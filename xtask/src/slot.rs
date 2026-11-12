//! The files of one slot of the card: what `cargo xtask image` puts in each of `qberrypi-a/` and
//! `qberrypi-b/`, and what `cargo xtask update` uploads for the slot that is not running.
//!
//! A slot holds the eleven files of [`SLOT_FILES`]. Seven of them are the build's, read from the boot
//! folder `cargo xtask build` left in `out/qberrypi/` after checking each against its
//! `SHA256SUMS`: the kernel, the device tree, the initramfs and the four overlay files. The
//! slot's `config.txt` and `cmdline.txt` are not the folder's (those are the old layout's) but
//! the texts that [`slot_config_txt`] and [`slot_cmdline_txt`] make, which name the slot; the
//! owner's `qberrypi.toml` and the API's `qberrypi-tls.pem`, kept as `tls.pem`, complete it.
//!
//! The digest that a build packs in its initramfs for the update to compare is the same for the
//! slot a and slot b forms of one build ([`boot_files_digest`] says so of a slot's files).
//!
//! Nothing here prints or quotes a file's bytes. `qberrypi.toml` holds the Wi-Fi passphrase and
//! `qberrypi-tls.pem` the API's key, so an error about either names the file and what is wrong
//! with it, never what it says.

use std::collections::BTreeMap;
use std::fs;
use std::io::{ErrorKind, Read};
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use qberrypi::api::tls;
use qberrypi::bootpart::TLS_FILE_CAP;
use qberrypi::config;
use qberrypi::slots::{self, SLOT_FILES, Slot};
use sha2::{Digest, Sha256};

use crate::build::{slot_cmdline_txt, slot_config_txt};
use crate::cert::CERT_FILE;

/// The boot folder of a build, under the repository root.
pub const BOOT_FOLDER: &str = "out/qberrypi";

/// The list of digests `cargo xtask build` writes in the boot folder.
const CHECKSUMS: &str = "SHA256SUMS";

/// The owner's configuration, in the top of the repository, and its name in a slot.
pub const CONFIG_FILE: &str = "qberrypi.toml";

/// The name of the API's key and certificate in a slot; `cargo xtask make-cert` makes them in the
/// top of the repository as [`CERT_FILE`].
pub const TLS_FILE: &str = "tls.pem";

/// The slot's files that are not the build's: its two text files, which name the slot, and the
/// owner's two.
const NOT_THE_BUILDS: [&str; 4] = ["cmdline.txt", "config.txt", CONFIG_FILE, TLS_FILE];

/// The files of a slot that are the build's own, in the order of [`SLOT_FILES`]: the kernel, the
/// device tree, the initramfs and the four overlay files.
pub fn build_file_names() -> impl Iterator<Item = &'static str> {
    SLOT_FILES
        .into_iter()
        .filter(|name| !NOT_THE_BUILDS.contains(name))
}

/// The files of a build that a slot takes as they are, read once from a boot folder.
///
/// It exists only for a boot folder that is complete and matches its `SHA256SUMS`, so a slot made
/// from it is never made from a half-written or a changed build. Both slots of an image are made
/// from one `Build`, and so are the slot files of an update.
pub struct Build {
    /// Each of [`build_file_names`] with its bytes.
    files: BTreeMap<&'static str, Vec<u8>>,
}

impl Build {
    /// Reads the build in `folder`, which is `out/qberrypi/` as `cargo xtask build` left it.
    ///
    /// Every file `SHA256SUMS` lists is read and must have its digest, and each of
    /// [`build_file_names`] must be listed. The error names the file at fault and says to run
    /// `cargo xtask build`; a name in the list that holds a `/` is refused, so a list cannot send
    /// the check outside the folder.
    pub fn read(folder: &Path) -> Result<Build> {
        const REBUILD: &str = "run `cargo xtask build` first";
        let sums_path = folder.join(CHECKSUMS);
        let sums = fs::read_to_string(&sums_path)
            .with_context(|| format!("cannot read {}; {REBUILD}", sums_path.display()))?;
        let mut files = BTreeMap::new();
        let mut listed = Vec::new();
        for line in sums.lines() {
            let (sum, name) = line.split_once("  ").with_context(|| {
                format!(
                    "{} is not a list of checksums; {REBUILD}",
                    sums_path.display()
                )
            })?;
            if name.is_empty() || name.contains('/') {
                bail!(
                    "{} lists a name that is not a file of the folder; {REBUILD}",
                    sums_path.display()
                );
            }
            let path = folder.join(name);
            let data = fs::read(&path).with_context(|| {
                format!(
                    "cannot read {}, which {CHECKSUMS} lists; {REBUILD}",
                    path.display()
                )
            })?;
            if sha256_hex(&data) != sum {
                bail!("{} does not match {CHECKSUMS}; {REBUILD}", path.display());
            }
            listed.push(name);
            if let Some(wanted) = build_file_names().find(|wanted| *wanted == name) {
                files.insert(wanted, data);
            }
        }
        for wanted in build_file_names() {
            if !listed.contains(&wanted) {
                bail!("{} does not list {wanted}; {REBUILD}", sums_path.display());
            }
        }
        Ok(Build { files })
    }

    /// The eleven files of `slot`, in the order of [`SLOT_FILES`]: the build's seven, the slot's
    /// `config.txt` and `cmdline.txt`, then `config` as `qberrypi.toml` and `tls_pem` as
    /// `tls.pem`.
    ///
    /// Nothing is checked about `config` and `tls_pem`: [`read_config`] and [`read_tls_pem`]
    /// check what the owner's files must be, and a caller that makes its own (a test, or the
    /// rollback drill's edited copy) is trusted to have done the same.
    pub fn slot_files(&self, slot: Slot, config: &[u8], tls_pem: &[u8]) -> Vec<(String, Vec<u8>)> {
        SLOT_FILES
            .into_iter()
            .map(|name| {
                let bytes = match name {
                    "cmdline.txt" => slot_cmdline_txt(slot).into_bytes(),
                    "config.txt" => slot_config_txt(slot).into_bytes(),
                    CONFIG_FILE => config.to_vec(),
                    TLS_FILE => tls_pem.to_vec(),
                    _ => self.files[name].clone(),
                };
                (name.to_owned(), bytes)
            })
            .collect()
    }
}

/// The eleven files of `slot` from the build in `root`'s `out/qberrypi/` and the owner's
/// `qberrypi.toml` and `qberrypi-tls.pem` in the top of `root`, in the order of [`SLOT_FILES`].
///
/// The slot's `config.txt` and `cmdline.txt` name it; the other nine do not depend on the slot.
/// The errors are those of [`Build::read`], [`read_config`] and [`read_tls_pem`]: they say what
/// to run, and none quotes `qberrypi.toml` or the key.
#[allow(
    dead_code,
    reason = "the tests make a slot's files from a checkout; `image` and `update` read their inputs once and use `Build::slot_files`"
)]
pub fn slot_files(root: &Path, slot: Slot) -> Result<Vec<(String, Vec<u8>)>> {
    let build = Build::read(&root.join(BOOT_FOLDER))?;
    let config = read_config(root)?;
    let tls_pem = read_tls_pem(root)?;
    Ok(build.slot_files(slot, config.as_bytes(), &tls_pem))
}

/// Replaces the bytes of one of a slot's files, such as the `qberrypi.toml` of the rollback
/// drill; the file keeps its place.
///
/// It is an error for `files` not to hold a file called `name`, so a misspelt name cannot add an
/// eleventh file that the receiver would refuse.
pub fn replace_file(files: &mut [(String, Vec<u8>)], name: &str, bytes: Vec<u8>) -> Result<()> {
    match files.iter_mut().find(|(have, _)| have == name) {
        Some((_, old)) => {
            *old = bytes;
            Ok(())
        }
        None => bail!("the slot has no file called {name}"),
    }
}

/// The digest of the boot files of a slot's files, as `slots::boot_files_digest` takes it: the
/// same for the a and the b form of one build, and the one the build's initramfs packs.
///
/// It is an error for `files` to lack a boot file or to hold a `config.txt` or `cmdline.txt` that
/// names no slot; the error names the file.
pub fn boot_files_digest(files: &[(String, Vec<u8>)]) -> Result<String> {
    slots::boot_files_digest(
        files
            .iter()
            .map(|(name, bytes)| (name.as_str(), &bytes[..])),
    )
    .map_err(|reason| anyhow!("the digest of the boot files: {reason}"))
}

/// Reads the owner's `qberrypi.toml` from the top of `root` and checks that qberrypi parses it.
///
/// The error names the key at fault and never quotes the file; for a file that cannot be read it
/// names the file and says why.
pub fn read_config(root: &Path) -> Result<String> {
    let path = root.join(CONFIG_FILE);
    let text =
        fs::read_to_string(&path).with_context(|| format!("cannot read {}", path.display()))?;
    config::parse(&text)
        .map_err(|error| anyhow!("{CONFIG_FILE} is not a valid configuration: {error}"))?;
    Ok(text)
}

/// Reads `qberrypi-tls.pem` from the top of `root`, the API's key and certificate, and checks
/// that qberrypi could serve it: that it is no larger than the Pi reads
/// (`bootpart::TLS_FILE_CAP`), and that the API's TLS setup takes it and finds a certificate.
///
/// A file that is not there says to run `cargo xtask make-cert`. No error holds a byte of the
/// file.
pub fn read_tls_pem(root: &Path) -> Result<Vec<u8>> {
    let path = root.join(CERT_FILE);
    let file = match fs::File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            bail!("there is no {CERT_FILE}: run `cargo xtask make-cert` first")
        }
        Err(error) => return Err(error).with_context(|| format!("cannot read {}", path.display())),
    };
    let mut pem = Vec::new();
    file.take(TLS_FILE_CAP + 1)
        .read_to_end(&mut pem)
        .with_context(|| format!("cannot read {}", path.display()))?;
    if pem.len() as u64 > TLS_FILE_CAP {
        bail!(
            "{CERT_FILE} is larger than {TLS_FILE_CAP} bytes, which is as much of it as qberrypi \
             reads; the API would stay off"
        );
    }
    tls::server_config(&pem).map_err(|reason| anyhow!("{CERT_FILE} cannot be served: {reason}"))?;
    if tls::leaf_sha256(&pem).is_none() {
        bail!("{CERT_FILE} holds no certificate");
    }
    Ok(pem)
}

/// The SHA-256 of some bytes, as lower-case hexadecimal.
pub fn sha256_hex(data: &[u8]) -> String {
    use std::fmt::Write;
    Sha256::digest(data)
        .iter()
        .fold(String::new(), |mut text, byte| {
            // Writing to a `String` cannot fail.
            let _ = write!(text, "{byte:02x}");
            text
        })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::build::sha256sums;
    use std::net::Ipv4Addr;

    /// The name and bytes of each file of a fixture build, which hold their own name so that a
    /// mix-up shows.
    const BUILT: [&str; 9] = [
        "kernel8.img",
        "bcm2710-rpi-3-b-plus.dtb",
        "initramfs8",
        "cmdline.txt",
        "config.txt",
        "ov-README",
        "ov-overlay_map.dtb",
        "ov-qb-piscreen.dtbo",
        "ov-disable-bt.dtbo",
    ];

    /// The configuration the repository ships as its example, for a Pi at 192.0.2.53.
    pub(crate) const CONFIG: &str = include_str!("../../qberrypi.example.toml");

    /// A boot folder as `cargo xtask build` writes it: each file holds its own name, and
    /// `SHA256SUMS` lists them all.
    pub(crate) fn write_build(folder: &Path) {
        fs::create_dir_all(folder).unwrap();
        let files: Vec<(&str, &[u8])> = BUILT.iter().map(|n| (*n, n.as_bytes())).collect();
        for (name, data) in &files {
            fs::write(folder.join(name), data).unwrap();
        }
        fs::write(folder.join(CHECKSUMS), sha256sums(&files)).unwrap();
    }

    /// A made certificate and key, for the Pi of the example configuration.
    pub(crate) fn made_pem() -> String {
        crate::cert::make("qberrypi", Ipv4Addr::new(192, 0, 2, 53), 1_800_000_000).unwrap()
    }

    /// A checkout with a fixture build, the example configuration and a made certificate.
    pub(crate) fn checkout() -> (tempfile::TempDir, String) {
        let root = tempfile::tempdir().unwrap();
        write_build(&root.path().join(BOOT_FOLDER));
        fs::write(root.path().join(CONFIG_FILE), CONFIG).unwrap();
        let pem = made_pem();
        fs::write(root.path().join(CERT_FILE), &pem).unwrap();
        (root, pem)
    }

    fn names(files: &[(String, Vec<u8>)]) -> Vec<&str> {
        files.iter().map(|(name, _)| name.as_str()).collect()
    }

    fn bytes<'a>(files: &'a [(String, Vec<u8>)], name: &str) -> &'a [u8] {
        &files.iter().find(|(have, _)| have == name).unwrap().1
    }

    #[test]
    fn a_slot_has_the_eleven_files_in_the_order_the_layout_lists_them() {
        let (root, pem) = checkout();

        let files = slot_files(root.path(), Slot::A).unwrap();

        assert_eq!(names(&files), SLOT_FILES);
        for name in [
            "kernel8.img",
            "initramfs8",
            "ov-README",
            "ov-qb-piscreen.dtbo",
            "ov-disable-bt.dtbo",
        ] {
            assert_eq!(bytes(&files, name), name.as_bytes(), "{name}");
        }
        assert_eq!(bytes(&files, "qberrypi.toml"), CONFIG.as_bytes());
        assert_eq!(bytes(&files, "tls.pem"), pem.as_bytes());
    }

    #[test]
    fn a_slots_text_files_name_the_slot_and_are_not_the_old_layouts() {
        let (root, _) = checkout();
        for slot in [Slot::A, Slot::B] {
            let files = slot_files(root.path(), slot).unwrap();

            assert_eq!(
                bytes(&files, "config.txt"),
                slot_config_txt(slot).as_bytes()
            );
            assert_eq!(
                bytes(&files, "cmdline.txt"),
                slot_cmdline_txt(slot).as_bytes()
            );
            assert_eq!(
                slots::check_slot_config(bytes(&files, "config.txt"), slot),
                Ok(())
            );
            assert_eq!(
                slots::check_slot_cmdline(bytes(&files, "cmdline.txt"), slot),
                Ok(())
            );
            // The fixture folder's own config.txt and cmdline.txt hold their names, not the text.
            assert_ne!(bytes(&files, "config.txt"), b"config.txt");
        }
    }

    #[test]
    fn the_two_slots_differ_only_in_the_files_that_name_them() {
        let (root, _) = checkout();
        let a = slot_files(root.path(), Slot::A).unwrap();
        let b = slot_files(root.path(), Slot::B).unwrap();

        let differing: Vec<&str> = a
            .iter()
            .zip(&b)
            .filter(|(x, y)| x != y)
            .map(|(x, _)| x.0.as_str())
            .collect();

        assert_eq!(differing, ["cmdline.txt", "config.txt"]);
    }

    #[test]
    fn both_slots_of_a_build_have_the_digest_the_build_packs() {
        let (root, _) = checkout();
        let name_bytes = |name: &str| name.as_bytes().to_vec();
        let overlays: Vec<(&str, Vec<u8>)> = [
            "ov-README",
            "ov-overlay_map.dtb",
            "ov-qb-piscreen.dtbo",
            "ov-disable-bt.dtbo",
        ]
        .into_iter()
        .map(|name| (name, name_bytes(name)))
        .collect();
        let packed = crate::build::boot_files_digest(
            &name_bytes("kernel8.img"),
            &name_bytes("bcm2710-rpi-3-b-plus.dtb"),
            &overlays,
        )
        .unwrap();

        for slot in [Slot::A, Slot::B] {
            let files = slot_files(root.path(), slot).unwrap();
            assert_eq!(boot_files_digest(&files).unwrap(), packed, "{slot}");
        }
    }

    #[test]
    fn the_digest_changes_with_a_boot_file_and_not_with_the_initramfs_or_the_owners_files() {
        let (root, _) = checkout();
        let files = slot_files(root.path(), Slot::A).unwrap();
        let digest = boot_files_digest(&files).unwrap();
        let changed = |name: &str| {
            let mut edited = files.clone();
            replace_file(&mut edited, name, b"another".to_vec()).unwrap();
            boot_files_digest(&edited).unwrap()
        };

        for name in ["initramfs8", "qberrypi.toml", "tls.pem"] {
            assert_eq!(changed(name), digest, "{name}");
        }
        for name in ["kernel8.img", "bcm2710-rpi-3-b-plus.dtb", "ov-README"] {
            assert_ne!(changed(name), digest, "{name}");
        }
    }

    #[test]
    fn a_digest_of_files_without_a_boot_file_names_it() {
        let (root, _) = checkout();
        let mut files = slot_files(root.path(), Slot::A).unwrap();
        files.retain(|(name, _)| name != "kernel8.img");

        let e = boot_files_digest(&files).unwrap_err();

        assert!(format!("{e:#}").contains("kernel8.img"), "{e:#}");
    }

    #[test]
    fn replacing_a_file_keeps_its_place_and_an_unknown_name_is_refused() {
        let (root, _) = checkout();
        let mut files = slot_files(root.path(), Slot::B).unwrap();

        replace_file(&mut files, "qberrypi.toml", b"edited".to_vec()).unwrap();

        assert_eq!(names(&files), SLOT_FILES);
        assert_eq!(bytes(&files, "qberrypi.toml"), b"edited");
        let e = replace_file(&mut files, "qberrypi.tom", Vec::new()).unwrap_err();
        assert!(format!("{e:#}").contains("qberrypi.tom"), "{e:#}");
        assert_eq!(files.len(), 11);
    }

    #[test]
    fn a_build_made_slots_for_a_caller_with_its_own_configuration() {
        let (root, _) = checkout();
        let build = Build::read(&root.path().join(BOOT_FOLDER)).unwrap();

        let files = build.slot_files(Slot::B, b"[a]\n", b"pem");

        assert_eq!(names(&files), SLOT_FILES);
        assert_eq!(bytes(&files, "qberrypi.toml"), b"[a]\n");
        assert_eq!(bytes(&files, "tls.pem"), b"pem");
    }

    #[test]
    fn a_boot_folder_that_does_not_match_its_checksums_is_refused() {
        let (root, _) = checkout();
        let folder = root.path().join(BOOT_FOLDER);
        fs::write(folder.join("kernel8.img"), "tampered").unwrap();

        let e = slot_files(root.path(), Slot::A).unwrap_err();

        let e = format!("{e:#}");
        assert!(
            e.contains("kernel8.img") && e.contains("cargo xtask build"),
            "{e}"
        );
    }

    #[test]
    fn a_boot_folder_with_a_file_missing_or_unlisted_is_refused_and_says_to_build() {
        for (what, edit) in [
            (
                "a listed file is gone",
                Box::new(|f: &Path| fs::remove_file(f.join("initramfs8")).unwrap())
                    as Box<dyn Fn(&Path)>,
            ),
            (
                "there are no checksums",
                Box::new(|f| fs::remove_file(f.join(CHECKSUMS)).unwrap()),
            ),
            (
                "the checksums are not a list",
                Box::new(|f| fs::write(f.join(CHECKSUMS), "not checksums\n").unwrap()),
            ),
            (
                "a wanted file is not listed",
                Box::new(|f| {
                    let files: Vec<(&str, &[u8])> = vec![
                        ("kernel8.img", b"kernel8.img"),
                        ("initramfs8", b"initramfs8"),
                    ];
                    fs::write(f.join(CHECKSUMS), sha256sums(&files)).unwrap()
                }),
            ),
            (
                "a name leads out of the folder",
                Box::new(|f| {
                    let sums = fs::read_to_string(f.join(CHECKSUMS)).unwrap();
                    fs::write(
                        f.join(CHECKSUMS),
                        format!("{sums}{}  ../qberrypi.toml\n", "0".repeat(64)),
                    )
                    .unwrap()
                }),
            ),
        ] {
            let (root, _) = checkout();
            edit(&root.path().join(BOOT_FOLDER));

            let e = slot_files(root.path(), Slot::A).unwrap_err();

            let e = format!("{e:#}");
            assert!(e.contains("cargo xtask build"), "{what}: {e}");
        }
    }

    #[test]
    fn a_checkout_without_a_build_certificate_or_configuration_says_what_is_missing() {
        for (missing, expect) in [
            (BOOT_FOLDER, "cargo xtask build"),
            (CERT_FILE, "cargo xtask make-cert"),
            (CONFIG_FILE, "qberrypi.toml"),
        ] {
            let (root, _) = checkout();
            let path = root.path().join(missing);
            if path.is_dir() {
                fs::remove_dir_all(path).unwrap();
            } else {
                fs::remove_file(path).unwrap();
            }

            let e = slot_files(root.path(), Slot::A).unwrap_err();

            assert!(format!("{e:#}").contains(expect), "{missing}: {e:#}");
        }
    }

    #[test]
    fn a_configuration_that_does_not_parse_is_refused_without_quoting_it() {
        let (root, _) = checkout();
        let bad = CONFIG.replace("country = \"US\"", "country = \"canary-value-77\"");
        fs::write(root.path().join(CONFIG_FILE), &bad).unwrap();

        let e = slot_files(root.path(), Slot::A).unwrap_err();

        let e = format!("{e:#}");
        assert!(e.contains("qberrypi.toml"), "{e}");
        assert!(!e.contains("canary-value-77"), "{e}");
    }

    #[test]
    fn a_certificate_the_pi_would_not_serve_is_refused_without_quoting_it() {
        let (root, pem) = checkout();
        let key_line = pem.lines().nth(1).unwrap().to_owned();
        for (what, text) in [
            ("not a certificate", "canary-value-78\n".to_owned()),
            (
                "too large",
                format!("{pem}{}", "#".repeat(TLS_FILE_CAP as usize)),
            ),
            (
                "no certificate",
                pem.split("-----BEGIN CERTIFICATE-----")
                    .next()
                    .unwrap()
                    .to_owned(),
            ),
        ] {
            fs::write(root.path().join(CERT_FILE), &text).unwrap();

            let e = slot_files(root.path(), Slot::A).unwrap_err();

            let e = format!("{e:#}");
            assert!(e.contains(CERT_FILE), "{what}: {e}");
            assert!(
                !e.contains("canary-value-78") && !e.contains(&key_line),
                "{what}: {e}"
            );
        }
    }

    #[test]
    fn the_build_files_are_the_slot_files_that_are_not_the_owners_or_the_slots() {
        assert_eq!(
            build_file_names().collect::<Vec<_>>(),
            [
                "kernel8.img",
                "bcm2710-rpi-3-b-plus.dtb",
                "initramfs8",
                "ov-README",
                "ov-overlay_map.dtb",
                "ov-qb-piscreen.dtbo",
                "ov-disable-bt.dtbo"
            ]
        );
    }
}
