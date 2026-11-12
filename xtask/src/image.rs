//! `cargo xtask image`: a complete card image for the Pi, made on this computer.
//!
//! The image is what the owner flashes once (`cargo xtask flash`) to put qberrypi alone on a card:
//! one FAT32 partition from sector 2048 in a 256 MiB image, holding the Pi 3's boot firmware, the
//! root `config.txt` that selects slot a, and the two slots `qberrypi-a/` and `qberrypi-b/`, both
//! filled with the build `cargo xtask build` left in `out/qberrypi/`. (The layout is in the design
//! of milestone 8, "Card layout".) It is made in pure Rust, with the `fatfs` crate and the
//! partition table of `sdimage`.
//!
//! The image holds the Wi-Fi passphrase and the API's key. It is refused for a configuration that
//! has a development switch on (as `deploy --permanent` refuses it) or no `[api]` section (a card
//! that cannot be updated over the network), and it is written the way the card backups are: in
//! `private/`, a git-ignored folder made with mode 0700, as a file of mode 0600, under a
//! temporary name that is renamed once the file is whole and on disk.
//!
//! [`card_files`] and [`stand_in_firmware`] are what the QEMU scenarios use to make slot images of
//! their own (with a slot's `qberrypi.toml` edited, a `tryboot.txt` or a marker added), since
//! QEMU never runs the boot firmware.

use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use qberrypi::config;
use qberrypi::slots::{SLOT_FILES, Slot};

use crate::card::{PRIVATE_DIR, absolute, make_private_dir, part_path, shell_word};
use crate::deploy;
use crate::sdimage::{self, CARD_IMAGE_BYTES};
use crate::slot::{self, BOOT_FOLDER, Build};
use crate::wifihint;

/// Where `cargo xtask fetch` leaves the boot firmware, under the repository root.
pub const FIRMWARE_FOLDER: &str = "vendor-cache/extracted/boot";

/// The boot firmware's files, which go into the root of the card: the Pi 3's first and second
/// stage bootloaders, the fixups for the second, and the licence they come under.
pub const FIRMWARE_FILES: [&str; 4] =
    ["bootcode.bin", "start.elf", "fixup.dat", "LICENCE.broadcom"];

/// The most bytes of one boot firmware file this reads; the largest, `start.elf`, is 3 MiB.
const FIRMWARE_FILE_CAP: u64 = 16 * 1024 * 1024;

/// The name of the image in `private/` when `--out` is not given.
const IMAGE_FILE: &str = "qberrypi-card.img";

/// The flags of `cargo xtask image`; each field's comment is that flag's help.
#[derive(clap::Args)]
pub struct ImageArgs {
    /// Where the image goes; it is replaced if it is there [default: private/qberrypi-card.img
    /// in the repository]
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
    /// The folder holding bootcode.bin, start.elf, fixup.dat and LICENCE.broadcom [default:
    /// vendor-cache/extracted/boot in the repository, which `cargo xtask fetch` fills]
    #[arg(long, value_name = "DIR")]
    pub firmware: Option<PathBuf>,
    /// The Pi's Wi-Fi channel, as the centre frequency in MHz of the 2.4 or 5 GHz band, for its first
    /// scan after a start to cover alone (`wifi.hint_mhz`); give it up to four times, at least one of
    /// them a 5 GHz channel (the Pi prefers 5 GHz, so a hint of 2.4 GHz alone is refused). It goes into
    /// the slots' copy of qberrypi.toml only, which then must have no `hint_mhz` of its own
    #[arg(long = "wifi-hint", value_name = "MHZ")]
    pub wifi_hint: Vec<u32>,
}

/// Reads the boot firmware's [`FIRMWARE_FILES`] from `dir`, in that order.
///
/// A file that is not there says to run `cargo xtask fetch` or to name the folder with
/// `--firmware`; a file that is empty, larger than 16 MiB or not a regular file is refused. The
/// errors name the file.
pub fn read_firmware(dir: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let mut files = Vec::new();
    for name in FIRMWARE_FILES {
        let path = dir.join(name);
        let file = File::open(&path).map_err(|error| match error.kind() {
            ErrorKind::NotFound => anyhow!(
                "cannot read {}; run `cargo xtask fetch` first, or name the folder that holds \
                 the boot firmware with --firmware",
                path.display()
            ),
            _ => anyhow::Error::new(error).context(format!("cannot read {}", path.display())),
        })?;
        if !file
            .metadata()
            .with_context(|| format!("cannot look at {}", path.display()))?
            .is_file()
        {
            bail!("{} is not a regular file", path.display());
        }
        let mut data = Vec::new();
        file.take(FIRMWARE_FILE_CAP + 1)
            .read_to_end(&mut data)
            .with_context(|| format!("cannot read {}", path.display()))?;
        if data.is_empty() {
            bail!("{} is empty", path.display());
        }
        if data.len() as u64 > FIRMWARE_FILE_CAP {
            bail!(
                "{} is larger than {FIRMWARE_FILE_CAP} bytes, which is more than a boot \
                 firmware file is",
                path.display()
            );
        }
        files.push((name.to_owned(), data));
    }
    Ok(files)
}

/// Files with the names of [`FIRMWARE_FILES`] whose bytes are only a sentence, for a card image
/// that QEMU boots: QEMU does not run the Pi's boot firmware, so nothing reads them.
pub fn stand_in_firmware() -> Vec<(String, Vec<u8>)> {
    FIRMWARE_FILES
        .into_iter()
        .map(|name| {
            let text = format!("A stand-in for {name}: QEMU does not run the boot firmware.\n");
            (name.to_owned(), text.into_bytes())
        })
        .collect()
}

/// Lays out a card: the boot firmware, the root `config.txt` that selects `selected`, and the two
/// slots' files in `qberrypi-a/` and `qberrypi-b/`, as the paths and bytes that
/// `sdimage::build_sized` takes.
///
/// The root `config.txt` is a copy of the selected slot's own, which is how
/// `slots::select` selects a slot. A caller may add a `tryboot.txt` or a marker to the result, or
/// replace a slot file first (see `slot::replace_file`).
///
/// It is an error for either slot not to hold exactly the files of `SLOT_FILES`, in that order.
pub fn card_files(
    firmware: &[(String, Vec<u8>)],
    slot_a: &[(String, Vec<u8>)],
    slot_b: &[(String, Vec<u8>)],
    selected: Slot,
) -> Result<Vec<(String, Vec<u8>)>> {
    let slots = [(Slot::A, slot_a), (Slot::B, slot_b)];
    for (slot, files) in slots {
        if files.iter().map(|(name, _)| name.as_str()).ne(SLOT_FILES) {
            bail!(
                "the files of slot {slot} are not the {} files of a slot",
                SLOT_FILES.len()
            );
        }
    }
    let selected_files = match selected {
        Slot::A => slot_a,
        Slot::B => slot_b,
    };
    let config = selected_files
        .iter()
        .find(|(name, _)| name == "config.txt")
        .map(|(_, bytes)| bytes.clone())
        .expect("a slot's files include config.txt");

    let mut files: Vec<(String, Vec<u8>)> = firmware.to_vec();
    files.push(("config.txt".to_owned(), config));
    for (slot, slot_files) in slots {
        for (name, bytes) in slot_files {
            files.push((format!("{}/{name}", slot.dir()), bytes.clone()));
        }
    }
    Ok(files)
}

/// Refuses a configuration that must not go on a card that stays, and gives it parsed otherwise:
/// one that does not parse, has a development switch on, or has no `[api]` section.
///
/// The development switches are `deploy::refuse_development_switches`'s, with `command` ("cargo
/// xtask image" or "cargo xtask update") named where the refusal speaks of the caller. Each
/// refusal ends with `nothing_done` ("no image was written", "nothing was uploaded"). None quotes
/// the file.
pub(crate) fn check_config(
    text: &str,
    command: &str,
    nothing_done: &str,
) -> Result<config::Config> {
    let parsed = config::parse(text).map_err(|error| {
        anyhow!(
            "{} is not a valid configuration: {error}; {nothing_done}",
            slot::CONFIG_FILE
        )
    })?;
    if let Err(refusal) = deploy::refuse_development_switches(&parsed.debug, command) {
        bail!("{refusal}; {nothing_done}");
    }
    if parsed.api.is_none() {
        bail!(
            "{} has no [api] section, so the Pi could not be updated over the network: add it \
             (qberrypi.example.toml shows how) and run `cargo xtask make-cert`; {nothing_done}",
            slot::CONFIG_FILE
        );
    }
    Ok(parsed)
}

/// Where the image goes, after checking that it can: the folder is there (or is `private/`, which
/// is made when the image is written), and a file already at the path is a regular file.
fn target_path(root: &Path, args: &ImageArgs) -> Result<PathBuf> {
    let target = match &args.out {
        Some(path) => absolute(path)?,
        None => root.join(PRIVATE_DIR).join(IMAGE_FILE),
    };
    let folder = target.parent().ok_or_else(|| {
        anyhow!(
            "{} has no folder to go in; no image was written",
            target.display()
        )
    })?;
    if folder != root.join(PRIVATE_DIR) && !folder.is_dir() {
        bail!(
            "the folder {} does not exist; no image was written",
            folder.display()
        );
    }
    match fs::symlink_metadata(&target) {
        Ok(meta) if !meta.is_file() => bail!(
            "{} is there and is not a regular file (an image is only ever written over an \
             earlier image); no image was written",
            target.display()
        ),
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("cannot look at {}", target.display()));
        }
    }
    Ok(target)
}

/// Writes `bytes` to `target`, a file of mode 0600, so that `target` is never half an image.
///
/// The bytes go to `<target>.part` (a leftover of an earlier run is replaced), are made durable,
/// and the part is renamed over `target`; the folder is made durable too. The folder `private/` of
/// the repository is made, with mode 0700, if it is the one `target` is in. A failure removes the
/// part.
fn write_private_file(root: &Path, target: &Path, bytes: &[u8]) -> Result<()> {
    let folder = target.parent().expect("the target has a folder");
    if folder == root.join(PRIVATE_DIR) {
        make_private_dir(folder).with_context(|| format!("cannot make {}", folder.display()))?;
    }
    let part = part_path(target);
    match fs::remove_file(&part) {
        Err(error) if error.kind() != ErrorKind::NotFound => {
            return Err(error).with_context(|| format!("cannot remove {}", part.display()));
        }
        _ => {}
    }
    let written = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&part)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&part, target)?;
        File::open(folder)?.sync_all()
    })();
    if let Err(error) = written {
        let _ = fs::remove_file(&part);
        return Err(error).with_context(|| format!("cannot write {}", target.display()));
    }
    Ok(())
}

/// Makes the card image, as `cargo xtask image` does, and says what it made to `out`.
///
/// In this order: the configuration (`root/qberrypi.toml`) is read and refused if it has a
/// development switch or no `[api]` section; with `--wifi-hint`, the copy that goes into the
/// slots is made from it ([`wifihint::hinted_config`], which proves that the hint is all that
/// differs) and the file is refused if it has a hint of its own; `qberrypi-tls.pem` is read; the boot firmware is
/// read from `--firmware` or `vendor-cache/extracted/boot`; the build in `out/qberrypi/` is read
/// and checked against its `SHA256SUMS`; where the image goes is checked. Only then is the image
/// put together, in memory, and written (see `write_private_file`). Any failure before the
/// write leaves nothing on disk. It prints the image's path, size and SHA-256, that it is
/// private, and the commands that come next.
pub fn run(root: &Path, args: &ImageArgs, out: &mut dyn Write) -> Result<()> {
    let config_text = slot::read_config(root)?;
    check_config(&config_text, "cargo xtask image", "no image was written")?;
    let slot_config = if args.wifi_hint.is_empty() {
        config_text.clone()
    } else {
        wifihint::hinted_config(&config_text, &args.wifi_hint)
            .map_err(|why| anyhow!("--wifi-hint: {why}; no image was written"))?
    };
    let tls_pem = slot::read_tls_pem(root)?;
    let firmware_dir = match &args.firmware {
        Some(dir) => absolute(dir)?,
        None => root.join(FIRMWARE_FOLDER),
    };
    let firmware = read_firmware(&firmware_dir)?;
    let build = Build::read(&root.join(BOOT_FOLDER))?;
    let target = target_path(root, args)?;

    let slot_a = build.slot_files(Slot::A, slot_config.as_bytes(), &tls_pem);
    let slot_b = build.slot_files(Slot::B, slot_config.as_bytes(), &tls_pem);
    let files = card_files(&firmware, &slot_a, &slot_b, Slot::A)?;
    let image = sdimage::make(CARD_IMAGE_BYTES, &files)?;
    write_private_file(root, &target, &image)?;

    writeln!(
        out,
        "image: wrote {} ({} bytes, {} MiB).",
        target.display(),
        image.len(),
        image.len() >> 20
    )?;
    writeln!(out, "image: its SHA-256 is {}.", slot::sha256_hex(&image))?;
    if !args.wifi_hint.is_empty() {
        let list: Vec<String> = args.wifi_hint.iter().map(u32::to_string).collect();
        writeln!(
            out,
            "image: the slots' copy of {} has wifi.hint_mhz = [{}], so that the Pi's first scan \
             covers only that channel; {} here is unchanged and nothing else differs in the copy.",
            slot::CONFIG_FILE,
            list.join(", "),
            slot::CONFIG_FILE
        )?;
    }
    writeln!(
        out,
        "image: it holds the Wi-Fi passphrase and the API's key, so only its owner can read it \
         (mode 0600)."
    )?;
    writeln!(
        out,
        "image: slot a is selected and both slots hold this build. Next, with the card in a USB \
         reader (sdX is the card, whole, not a partition):"
    )?;
    writeln!(out, "  cargo xtask backup-card --device /dev/sdX --yes")?;
    writeln!(
        out,
        "  cargo xtask flash --image {} --device /dev/sdX --yes",
        shell_word(target.as_os_str())
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdimage::Image;
    use crate::slot::tests::{CONFIG, checkout};
    use qberrypi::slots::{self, SLOT_FILES};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use tempfile::TempDir;

    /// A password line of the shape the configuration reads. Nobody's password hashes to it.
    const PASSWORD_LINE: &str = "password_hash = \"$pbkdf2-sha256$i=100000$00000000000000000000000000000000$0000000000000000000000000000000000000000000000000000000000000000\"";

    /// The example configuration with an `[api]` section.
    fn api_config() -> String {
        format!("{CONFIG}\n[api]\n{PASSWORD_LINE}\n")
    }

    /// A checkout that `run` accepts: a fixture build, an `[api]` configuration, a made
    /// certificate and a boot firmware folder of fake files in `vendor-cache/extracted/boot`.
    fn ready() -> (TempDir, String) {
        let (root, pem) = checkout();
        fs::write(root.path().join(slot::CONFIG_FILE), api_config()).unwrap();
        let firmware = root.path().join(FIRMWARE_FOLDER);
        fs::create_dir_all(&firmware).unwrap();
        for name in FIRMWARE_FILES {
            fs::write(firmware.join(name), format!("firmware {name}")).unwrap();
        }
        (root, pem)
    }

    /// Runs the command for `args`; what it printed, or its error as text.
    fn image(root: &Path, args: &ImageArgs) -> Result<String, String> {
        let mut out = Vec::new();
        match run(root, args, &mut out) {
            Ok(()) => Ok(String::from_utf8(out).unwrap()),
            Err(error) => Err(format!("{error:#}")),
        }
    }

    fn default_args() -> ImageArgs {
        ImageArgs {
            out: None,
            firmware: None,
            wifi_hint: Vec::new(),
        }
    }

    /// The default image of a checkout.
    fn default_image(root: &TempDir) -> PathBuf {
        root.path().join("private/qberrypi-card.img")
    }

    #[test]
    fn the_image_holds_the_firmware_the_selecting_config_and_both_slots_byte_for_byte() {
        let (root, pem) = ready();

        image(root.path(), &default_args()).unwrap();

        let mut card = Image::open(&default_image(&root)).unwrap();
        for name in FIRMWARE_FILES {
            assert_eq!(
                card.read(name).unwrap(),
                format!("firmware {name}").as_bytes(),
                "{name}"
            );
        }
        for slot in [Slot::A, Slot::B] {
            let mut listed = card.files_in(slot.dir()).unwrap();
            listed.sort();
            let mut expected: Vec<&str> = SLOT_FILES.to_vec();
            expected.sort();
            assert_eq!(listed, expected, "{slot}");
            let read = |card: &mut Image, name: &str| {
                card.read(&format!("{}/{name}", slot.dir())).unwrap()
            };
            for name in [
                "kernel8.img",
                "initramfs8",
                "ov-README",
                "ov-qb-piscreen.dtbo",
                "ov-disable-bt.dtbo",
            ] {
                assert_eq!(read(&mut card, name), name.as_bytes(), "{slot} {name}");
            }
            assert_eq!(read(&mut card, "qberrypi.toml"), api_config().as_bytes());
            assert_eq!(read(&mut card, "tls.pem"), pem.as_bytes());
        }
        // Only the firmware, config.txt and the two slots are in the root.
        let mut root_files = card.files_in("").unwrap();
        root_files.sort();
        assert_eq!(
            root_files,
            [
                "LICENCE.broadcom",
                "bootcode.bin",
                "config.txt",
                "fixup.dat",
                "start.elf"
            ]
        );
    }

    #[test]
    fn the_root_config_selects_slot_a_and_each_slots_files_name_that_slot() {
        let (root, _) = ready();

        image(root.path(), &default_args()).unwrap();

        let mut card = Image::open(&default_image(&root)).unwrap();
        let root_config = card.read("config.txt").unwrap();
        assert_eq!(slots::selected_slot(&root_config), Ok(Slot::A));
        assert_eq!(root_config, card.read("qberrypi-a/config.txt").unwrap());
        for slot in [Slot::A, Slot::B] {
            let dir = slot.dir();
            let config = card.read(&format!("{dir}/config.txt")).unwrap();
            let cmdline = card.read(&format!("{dir}/cmdline.txt")).unwrap();
            assert_eq!(slots::check_slot_config(&config, slot), Ok(()), "{slot}");
            assert_eq!(slots::check_slot_cmdline(&cmdline, slot), Ok(()), "{slot}");
        }
        // No Raspberry Pi OS leftovers, no trial in progress.
        for name in ["config.pios.txt", "tryboot.txt", "qberrypi-trial.txt"] {
            assert_eq!(card.find(name).unwrap(), None, "{name}");
        }
    }

    #[test]
    fn both_slots_of_the_image_have_the_digest_the_build_packs_into_its_initramfs() {
        let (root, _) = ready();
        // The fixture's files hold their own names; this is what `build` packs for such files.
        let bytes = |name: &str| name.as_bytes().to_vec();
        let overlays: Vec<(&str, Vec<u8>)> = [
            "ov-README",
            "ov-overlay_map.dtb",
            "ov-qb-piscreen.dtbo",
            "ov-disable-bt.dtbo",
        ]
        .into_iter()
        .map(|name| (name, bytes(name)))
        .collect();
        let packed = crate::build::boot_files_digest(
            &bytes("kernel8.img"),
            &bytes("bcm2710-rpi-3-b-plus.dtb"),
            &overlays,
        )
        .unwrap();

        image(root.path(), &default_args()).unwrap();

        let mut card = Image::open(&default_image(&root)).unwrap();
        for slot in [Slot::A, Slot::B] {
            let files: Vec<(String, Vec<u8>)> = SLOT_FILES
                .iter()
                .map(|name| {
                    let bytes = card.read(&format!("{}/{name}", slot.dir())).unwrap();
                    (name.to_string(), bytes)
                })
                .collect();
            assert_eq!(slot::boot_files_digest(&files).unwrap(), packed, "{slot}");
        }
    }

    #[test]
    fn a_wifi_hint_goes_into_both_slots_copy_of_the_configuration_and_nowhere_else() {
        let (root, _) = ready();
        let args = ImageArgs {
            wifi_hint: vec![5180, 2437],
            ..default_args()
        };

        let said = image(root.path(), &args).unwrap();

        let mut card = Image::open(&default_image(&root)).unwrap();
        for slot in [Slot::A, Slot::B] {
            let copy = card.read(&format!("{}/qberrypi.toml", slot.dir())).unwrap();
            let copy = String::from_utf8(copy).unwrap();
            assert_eq!(
                config::parse(&copy).unwrap().wifi.hint_mhz,
                [5180, 2437],
                "{slot}"
            );
            assert_eq!(
                copy.replacen("hint_mhz = [5180, 2437]\n", "", 1),
                api_config(),
                "{slot}"
            );
        }
        // The file on this computer is as it was.
        let local = fs::read_to_string(root.path().join(slot::CONFIG_FILE)).unwrap();
        assert_eq!(local, api_config());
        assert!(
            said.contains(
                "wifi.hint_mhz = [5180, 2437], so that the Pi's first scan covers only that channel"
            ),
            "{said}"
        );
        assert!(!said.contains("example-passphrase"), "{said}");
    }

    #[test]
    fn without_a_wifi_hint_the_slots_copy_is_the_file() {
        let (root, _) = ready();
        let said = image(root.path(), &default_args()).unwrap();
        let mut card = Image::open(&default_image(&root)).unwrap();
        assert_eq!(
            card.read("qberrypi-a/qberrypi.toml").unwrap(),
            api_config().as_bytes()
        );
        assert!(!said.contains("hint_mhz"), "{said}");
    }

    #[test]
    fn a_wifi_hint_that_cannot_be_used_stops_the_image_before_it_is_written() {
        // A frequency that is no channel; four too many; and a file that has a hint of its own.
        for (hint, text, why) in [
            (vec![5181], api_config(), "wifi.hint_mhz"),
            (vec![5180; 2], api_config(), "wifi.hint_mhz"),
            // Channels of 2.4 GHz alone: the Pi prefers 5 GHz, and would not take such a hint.
            (vec![2437], api_config(), "no 5 GHz channel"),
            (vec![2412, 2462], api_config(), "no 5 GHz channel"),
            (
                vec![5180],
                api_config().replacen("[wifi]\n", "[wifi]\nhint_mhz = [2437]\n", 1),
                "already has wifi.hint_mhz",
            ),
        ] {
            let (root, _) = ready();
            fs::write(root.path().join(slot::CONFIG_FILE), text).unwrap();
            let args = ImageArgs {
                wifi_hint: hint,
                ..default_args()
            };

            let error = image(root.path(), &args).unwrap_err();

            assert!(error.contains("--wifi-hint"), "{error}");
            assert!(error.contains(why), "{error}");
            assert!(error.ends_with("no image was written"), "{error}");
            assert!(!error.contains("5181"), "{error}");
            assert!(!default_image(&root).exists());
        }
    }

    #[test]
    fn the_image_is_256_mib_private_and_written_whole() {
        let (root, _) = ready();

        let said = image(root.path(), &default_args()).unwrap();

        let path = default_image(&root);
        let meta = fs::metadata(&path).unwrap();
        assert_eq!(meta.len(), 256 * 1024 * 1024);
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let folder = fs::metadata(path.parent().unwrap()).unwrap();
        assert_eq!(folder.permissions().mode() & 0o777, 0o700);
        // Nothing is left beside it, and what it says is true of the file.
        let names: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["qberrypi-card.img"]);
        let sha = slot::sha256_hex(&fs::read(&path).unwrap());
        assert!(said.contains(&path.display().to_string()), "{said}");
        assert!(said.contains(&sha), "{said}");
        assert!(
            said.contains("268435456 bytes") && said.contains("256 MiB"),
            "{said}"
        );
        assert!(said.contains("only its owner can read it"), "{said}");
        assert!(
            said.contains("cargo xtask backup-card --device /dev/sdX --yes"),
            "{said}"
        );
        assert!(
            said.contains(&format!("cargo xtask flash --image {}", path.display())),
            "{said}"
        );
    }

    #[test]
    fn the_image_is_the_same_bytes_every_time() {
        let (root, _) = ready();
        let args = ImageArgs {
            out: Some(root.path().join("one.img")),
            firmware: None,
            wifi_hint: Vec::new(),
        };
        image(root.path(), &args).unwrap();
        let other = ImageArgs {
            out: Some(root.path().join("two.img")),
            firmware: None,
            wifi_hint: Vec::new(),
        };
        image(root.path(), &other).unwrap();

        assert!(
            fs::read(root.path().join("one.img")).unwrap()
                == fs::read(root.path().join("two.img")).unwrap()
        );
    }

    #[test]
    fn a_looser_private_folder_is_tightened_and_an_earlier_image_is_replaced() {
        let (root, _) = ready();
        let folder = root.path().join("private");
        fs::create_dir(&folder).unwrap();
        fs::set_permissions(&folder, fs::Permissions::from_mode(0o755)).unwrap();
        let path = default_image(&root);
        fs::write(&path, "an earlier image").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        // A leftover of a run that was cut off.
        fs::write(folder.join("qberrypi-card.img.part"), "half").unwrap();

        image(root.path(), &default_args()).unwrap();

        assert_eq!(
            fs::metadata(&folder).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let meta = fs::metadata(&path).unwrap();
        assert_eq!(meta.len(), 256 * 1024 * 1024);
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::read_dir(&folder).unwrap().count(), 1);
    }

    #[test]
    fn out_names_the_file_and_a_firmware_folder_can_be_given() {
        let (root, _) = ready();
        let elsewhere = tempfile::tempdir().unwrap();
        for name in FIRMWARE_FILES {
            fs::write(elsewhere.path().join(name), format!("other {name}")).unwrap();
        }
        fs::remove_dir_all(root.path().join(FIRMWARE_FOLDER)).unwrap();
        let target = elsewhere.path().join("card.img");
        let args = ImageArgs {
            out: Some(target.clone()),
            firmware: Some(elsewhere.path().to_path_buf()),
            wifi_hint: Vec::new(),
        };

        let said = image(root.path(), &args).unwrap();

        let mut card = Image::open(&target).unwrap();
        assert_eq!(card.read("start.elf").unwrap(), b"other start.elf");
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(said.contains(&target.display().to_string()), "{said}");
        // The default place was not touched.
        assert!(!root.path().join("private").exists());
    }

    #[test]
    fn a_configuration_with_a_development_switch_on_is_refused_and_nothing_is_written() {
        for (switch, from, to) in [
            ("one_shot", "one_shot = false", "one_shot = true"),
            ("log_to_sd", "log_to_sd = false", "log_to_sd = true"),
            (
                "return_after_secs",
                "return_after_secs = 0",
                "return_after_secs = 60",
            ),
            (
                "calibrate_touch",
                "calibrate_touch = false",
                "calibrate_touch = true",
            ),
            ("fault", "fault = \"none\"", "fault = \"crash-loop\""),
        ] {
            let (root, _) = ready();
            let text = api_config().replace(from, to);
            fs::write(root.path().join(slot::CONFIG_FILE), text).unwrap();

            let e = image(root.path(), &default_args()).unwrap_err();

            assert!(
                e.contains(switch) && e.contains("no image was written"),
                "{switch}: {e}"
            );
            assert!(!root.path().join("private").exists(), "{switch}");
        }
    }

    #[test]
    fn a_configuration_without_an_api_section_is_refused_and_nothing_is_written() {
        let (root, _) = ready();
        fs::write(root.path().join(slot::CONFIG_FILE), CONFIG).unwrap();

        let e = image(root.path(), &default_args()).unwrap_err();

        assert!(
            e.contains("[api]") && e.contains("updated over the network"),
            "{e}"
        );
        assert!(e.contains("no image was written"), "{e}");
        assert!(!root.path().join("private").exists());
    }

    #[test]
    fn a_configuration_that_does_not_parse_is_refused_without_quoting_it() {
        let (root, _) = ready();
        let text = api_config().replace("country = \"US\"", "country = \"canary-value-79\"");
        fs::write(root.path().join(slot::CONFIG_FILE), text).unwrap();

        let e = image(root.path(), &default_args()).unwrap_err();

        assert!(e.contains("qberrypi.toml") || e.contains("country"), "{e}");
        assert!(!e.contains("canary-value-79"), "{e}");
        assert!(!root.path().join("private").exists());
    }

    #[test]
    fn missing_inputs_are_refused_with_the_command_that_makes_them() {
        for (missing, expect) in [
            ("out", "cargo xtask build"),
            ("qberrypi-tls.pem", "cargo xtask make-cert"),
            ("vendor-cache", "cargo xtask fetch"),
            ("qberrypi.toml", "qberrypi.toml"),
        ] {
            let (root, _) = ready();
            let path = root.path().join(missing);
            if path.is_dir() {
                fs::remove_dir_all(path).unwrap();
            } else {
                fs::remove_file(path).unwrap();
            }

            let e = image(root.path(), &default_args()).unwrap_err();

            assert!(e.contains(expect), "{missing}: {e}");
            assert!(!root.path().join("private").exists(), "{missing}");
        }
    }

    #[test]
    fn a_firmware_file_that_is_empty_or_too_large_is_refused_by_name() {
        let (root, _) = ready();
        let firmware = root.path().join(FIRMWARE_FOLDER);
        fs::write(firmware.join("fixup.dat"), "").unwrap();

        let e = image(root.path(), &default_args()).unwrap_err();

        assert!(e.contains("fixup.dat") && e.contains("empty"), "{e}");
        fs::write(
            firmware.join("fixup.dat"),
            vec![1u8; FIRMWARE_FILE_CAP as usize + 1],
        )
        .unwrap();
        let e = image(root.path(), &default_args()).unwrap_err();
        assert!(e.contains("fixup.dat") && e.contains("larger"), "{e}");
        assert!(!root.path().join("private").exists());
    }

    #[test]
    fn a_firmware_folder_given_with_the_flag_that_lacks_a_file_says_which() {
        let (root, _) = ready();
        let empty = tempfile::tempdir().unwrap();
        let args = ImageArgs {
            out: None,
            firmware: Some(empty.path().to_path_buf()),
            wifi_hint: Vec::new(),
        };

        let e = image(root.path(), &args).unwrap_err();

        assert!(
            e.contains("bootcode.bin") && e.contains("--firmware"),
            "{e}"
        );
    }

    #[test]
    fn a_target_that_cannot_be_written_over_is_refused_before_the_image_is_made() {
        let (root, _) = ready();
        let elsewhere = tempfile::tempdir().unwrap();
        let link = elsewhere.path().join("link.img");
        std::os::unix::fs::symlink("/dev/null", &link).unwrap();
        for (what, out) in [
            ("a folder is there", elsewhere.path().to_path_buf()),
            ("a link is there", link),
            ("no folder", elsewhere.path().join("absent/card.img")),
        ] {
            let args = ImageArgs {
                out: Some(out),
                firmware: None,
                wifi_hint: Vec::new(),
            };

            let e = image(root.path(), &args).unwrap_err();

            assert!(e.contains("no image was written"), "{what}: {e}");
        }
        assert!(!root.path().join("private").exists());
    }

    #[test]
    fn the_image_is_never_written_over_through_a_link() {
        let (root, _) = ready();
        let elsewhere = tempfile::tempdir().unwrap();
        let victim = elsewhere.path().join("victim");
        fs::write(&victim, "precious").unwrap();
        let link = elsewhere.path().join("card.img");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        let args = ImageArgs {
            out: Some(link),
            firmware: None,
            wifi_hint: Vec::new(),
        };

        image(root.path(), &args).unwrap_err();

        assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
        assert_eq!(fs::metadata(&victim).unwrap().nlink(), 1);
    }

    #[test]
    fn the_card_is_laid_out_from_any_two_slots_and_any_firmware() {
        let firmware = stand_in_firmware();
        let slot = |tag: u8, config: &[u8]| -> Vec<(String, Vec<u8>)> {
            SLOT_FILES
                .iter()
                .map(|name| {
                    let bytes = if *name == "config.txt" {
                        config.to_vec()
                    } else {
                        vec![tag; 3]
                    };
                    (name.to_string(), bytes)
                })
                .collect()
        };
        let (a, b) = (slot(b'a', b"config of a"), slot(b'b', b"config of b"));

        let files = card_files(&firmware, &a, &b, Slot::B).unwrap();

        let get = |name: &str| {
            files
                .iter()
                .find(|(have, _)| have == name)
                .map(|(_, bytes)| bytes.clone())
        };
        assert_eq!(get("config.txt"), Some(b"config of b".to_vec()));
        assert_eq!(get("qberrypi-a/config.txt"), Some(b"config of a".to_vec()));
        assert_eq!(get("qberrypi-b/kernel8.img"), Some(vec![b'b'; 3]));
        assert!(get("start.elf").unwrap().starts_with(b"A stand-in"));
        assert_eq!(files.len(), FIRMWARE_FILES.len() + 1 + 2 * SLOT_FILES.len());
        // QEMU's smaller image takes such a card.
        let card = sdimage::make(sdimage::IMAGE_BYTES, &files);
        assert!(card.is_ok(), "{:?}", card.err());
    }

    #[test]
    fn a_slot_that_is_not_the_ten_files_of_a_slot_is_refused() {
        let (root, _) = ready();
        let build = Build::read(&root.path().join(BOOT_FOLDER)).unwrap();
        let good = build.slot_files(Slot::A, b"", b"");
        let mut short = good.clone();
        short.pop();
        let mut swapped = good.clone();
        swapped.swap(0, 1);

        for bad in [short, swapped] {
            let e = card_files(&stand_in_firmware(), &good, &bad, Slot::A).unwrap_err();
            assert!(format!("{e:#}").contains("slot b"), "{e:#}");
        }
    }
}
