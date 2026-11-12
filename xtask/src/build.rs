//! `cargo xtask build`: cross-compiles qberrypi, packs the initramfs and
//! writes `out/qberrypi/`, the folder that goes onto the Pi's boot partition.
//!
//! The folder holds the kernel and device tree exactly as fetched, the
//! initramfs, the two text files the Pi's boot firmware reads, the four
//! overlay files that go with them, and the checksums of those nine. The
//! same inputs always give the same bytes.
//!
//! The initramfs also holds the block lists that `cargo xtask fetch-lists` cached, as one
//! compressed snapshot, so that the Pi can block before it has a network.
//!
//! Bluetooth is absent by design: the device-tree node is disabled (`dtoverlay=disable-bt`), the
//! initramfs holds no Bluetooth module and no Bluetooth firmware, and the build refuses to pack
//! either ([`refuse_bluetooth`]).

use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use qberrypi::lists::snapshot::{Header, SNAPSHOT_PATH};
use qberrypi::modules::{DEFAULT_TABLE, MODULE_DIR, MODULE_LIST, ModuleTable};
use qberrypi::slots::{self, Slot};
use qberrypi::update::BOOT_FILES_PATH;
use sha2::{Digest, Sha256};

use crate::cpio::{CpioWriter, Node};
use crate::lists::{self, STALE_AFTER_DAYS};

/// The kernel command line, as `cmdline.txt` holds it.
pub const CMDLINE_TXT: &str = "console=tty1 panic=5 loglevel=4\n";

/// The `config.txt` that makes the Pi's boot firmware start qberrypi from its folder.
///
/// The last four lines are the hardware's: the SPI bus, the prefix the
/// firmware puts before an overlay's file name, the overlay that describes
/// the touchscreen on the bus, with `rotate=270` for the way up the screen is
/// mounted, and the overlay that disables the Bluetooth device-tree node
/// (`disable-bt`: on a Pi 3 B+ it also gives UART0 back to GPIO 14 and 15, which nothing here
/// uses). With `os_prefix=qberrypi/` the firmware reads `qberrypi/ov-README`,
/// `qberrypi/ov-qb-piscreen.dtbo` and `qberrypi/ov-disable-bt.dtbo`: qberrypi's
/// own copies of the overlays, which an upgrade of Raspberry Pi OS cannot take
/// away or change.
pub const CONFIG_TXT: &str = "\
# qberrypi. Copy config.pios.txt over this file to return to Raspberry Pi OS.
arm_64bit=1
os_prefix=qberrypi/
kernel=kernel8.img
initramfs initramfs8 followkernel
disable_overscan=1
dtparam=spi=on
overlay_prefix=ov-
dtoverlay=qb-piscreen,speed=16000000,rotate=270
dtoverlay=disable-bt
";

/// The lines that only a slot's `config.txt` has, for a faster boot. Each is in the official
/// documentation of the Pi's firmware (`docs/bring-up/m8-only-os.md` has the source of each):
///
/// - `disable_splash=1` leaves out the rainbow splash screen;
/// - `initial_turbo=60` runs the processor in turbo from the start of the firmware until the kernel's
///   `cpufreq` driver takes over (60 s is the most the firmware takes, and init sets the
///   `performance` governor within a second of its start anyway);
/// - `camera_auto_detect=0` and `display_auto_detect=0` keep the firmware from probing for a CSI
///   camera and a DSI display, which the board does not have (the screen is on the SPI bus);
/// - `dtparam=audio=off` keeps the onboard audio interface off, which is the base device tree's
///   default and is stated so that it holds whatever the default is.
///
/// Nothing here touches the console, the Wi-Fi, the watchdog or the screen.
const SLOT_BOOT_LINES: &str = "\
disable_splash=1
initial_turbo=60
camera_auto_detect=0
display_auto_detect=0
dtparam=audio=off
";

/// The first line of a slot's `config.txt`: how slots are selected. It does not name the slot, so
/// that the two slots' files differ in their `os_prefix=` value alone, as the digest of the boot
/// files (`slots::slot_a_form`) takes them to.
const SLOT_COMMENT: &str = "# qberrypi, two slots. A slot is selected by copying its config.txt over the root config.txt (tryboot.txt for one trial boot).";

/// The `config.txt` of a slot on a card with two slots: [`CONFIG_TXT`] with the slot's own
/// `os_prefix=` and a first comment line about how slots are selected in place of the one about
/// returning to Raspberry Pi OS, which is not on such a card.
///
/// The firmware reads only the root `config.txt`, which is a copy of the selected slot's file
/// (`slots::select`); this one is the record of the slot, which init checks before it copies it
/// (`slots::check_slot_config`). Its overlay lines are [`CONFIG_TXT`]'s, so with `os_prefix` the
/// firmware reads the slot's own `ov-` files. After [`CONFIG_TXT`]'s lines come the boot-speed
/// lines that only a slot has ([`SLOT_BOOT_LINES`]); the old layout's text is left as it was.
pub fn slot_config_txt(slot: Slot) -> String {
    let (_comment, rest) = CONFIG_TXT
        .split_once('\n')
        .expect("CONFIG_TXT has a first line");
    let selects = format!("os_prefix={}", slot.os_prefix());
    let rest = rest.replacen("os_prefix=qberrypi/", &selects, 1);
    format!("{SLOT_COMMENT}\n{rest}{SLOT_BOOT_LINES}")
}

/// The `cmdline.txt` of a slot on a card with two slots: [`CMDLINE_TXT`]'s line and the
/// argument that names the slot, which is how the running build knows which slot it is
/// (`slots::Slot::from_cmdline`).
pub fn slot_cmdline_txt(slot: Slot) -> String {
    let line = CMDLINE_TXT.strip_suffix('\n').unwrap_or(CMDLINE_TXT);
    format!("{line} {}\n", slot.cmdline_arg())
}

/// The folder under the repository root that `cargo xtask fetch` extracts into.
const EXTRACTED_DIR: &str = "vendor-cache/extracted";

/// The boot folder, under the repository root.
const BOOT_FOLDER: &str = "out/qberrypi";

/// What the Pi's processor runs, as Rust names it.
const TARGET: &str = "aarch64-unknown-linux-musl";

// The three files of the boot folder that the Pi's boot firmware loads into memory.
const KERNEL: &str = "kernel8.img";
const DEVICE_TREE: &str = "bcm2710-rpi-3-b-plus.dtb";
const INITRAMFS: &str = "initramfs8";

/// The overlay files of the boot folder, as `cargo xtask fetch` leaves them under `vendor-cache/extracted/`.
///
/// `CONFIG_TXT`'s `overlay_prefix=ov-` is what makes the firmware ask for these names, in this
/// order: the README that says the overlays are here, the map, the screen's overlay and the one
/// that disables Bluetooth.
const OVERLAY_FILES: [&str; 4] = [
    "ov-README",
    "ov-overlay_map.dtb",
    "ov-qb-piscreen.dtbo",
    "ov-disable-bt.dtbo",
];

/// The kernel module files a module table names, in the table's order.
///
/// Those of `DEFAULT_TABLE` are what the initramfs holds: under `modules/`
/// when fetched, in `MODULE_DIR` in the initramfs. Taken from the table that
/// init reads, so the two cannot come apart.
fn module_files(table: &str) -> Result<Vec<String>> {
    let table = ModuleTable::parse(table).map_err(|e| anyhow!("the module table: {e}"))?;
    Ok(table.files().map(str::to_owned).collect())
}

/// The kernel modules of Bluetooth, by name; `-` and `_` are the same in a module's name.
const BLUETOOTH_MODULES: [&str; 10] = [
    "bluetooth",
    "btbcm",
    "hci_uart",
    "btsdio",
    "bnep",
    "rfcomm",
    "hidp",
    "btusb",
    "btintel",
    "btrtl",
];

/// Whether `module` (a module's name, or its file's name without `.ko` and what follows) is one of
/// Bluetooth's: those of [`BLUETOOTH_MODULES`], and any `hci_*`.
fn is_bluetooth_module(module: &str) -> bool {
    let name = module.to_ascii_lowercase().replace('-', "_");
    BLUETOOTH_MODULES.contains(&name.as_str()) || name.starts_with("hci_")
}

/// Why `path`, a name or a path in the initramfs or in the module table, is Bluetooth's: a module of
/// Bluetooth by its name, a file under the kernel's Bluetooth folders, or a firmware file of a
/// Bluetooth chip (`*.hcd`). `None` for anything else.
fn bluetooth_reason(path: &str) -> Option<&'static str> {
    let lower = path.to_ascii_lowercase();
    if lower.contains("kernel/net/bluetooth/") || lower.contains("kernel/drivers/bluetooth/") {
        return Some("a file of the kernel's Bluetooth folders");
    }
    if lower.ends_with(".hcd") {
        return Some("a Bluetooth firmware file (.hcd)");
    }
    let file = lower.rsplit('/').next().unwrap_or(&lower);
    let module = file.split(".ko").next().unwrap_or(file);
    if file.contains(".ko") && is_bluetooth_module(module) {
        return Some("a Bluetooth kernel module");
    }
    None
}

/// Refuses an initramfs that would hold any Bluetooth: a module of the table (its name, its file or a
/// module it needs), a firmware file, or any entry, whatever its path. Bluetooth is absent from
/// qberrypi by design: the device-tree node is disabled (`dtoverlay=disable-bt`), and with no module
/// and no firmware there is nothing that could start it. The error names each offender, and that
/// it is Bluetooth's.
pub fn refuse_bluetooth(table: &str, entries: &[(String, Node)]) -> Result<()> {
    let mut found: Vec<String> = Vec::new();
    let table = ModuleTable::parse(table).map_err(|e| anyhow!("the module table: {e}"))?;
    for entry in table.entries() {
        let named = [&entry.name, &entry.file]
            .into_iter()
            .chain(entry.deps.iter())
            .any(|name| is_bluetooth_module(name.trim_end_matches(".ko")));
        if named || bluetooth_reason(&entry.file).is_some() {
            found.push(format!(
                "module table entry {} (a Bluetooth kernel module)",
                entry.name
            ));
        }
    }
    for (path, node) in entries {
        let target = match node {
            Node::Symlink { target } => Some(*target),
            _ => None,
        };
        for text in std::iter::once(path.as_str()).chain(target) {
            if let Some(reason) = bluetooth_reason(text) {
                found.push(format!("{path} ({reason})"));
                break;
            }
        }
    }
    if found.is_empty() {
        return Ok(());
    }
    bail!(
        "the initramfs would hold Bluetooth: {}. qberrypi has no Bluetooth by design (no modules, no \
         firmware, the device-tree node disabled by dtoverlay=disable-bt): take it out of the module \
         table and the firmware list",
        found.join("; ")
    )
}

/// Where the build leaves the time it gave the executable as its build time.
///
/// Under the repository root, beside the boot folder and not in it: the
/// folder holds what goes onto the card, and nothing else.
const BUILD_EPOCH_FILE: &str = "out/build-epoch";

/// Reads the build time of the boot folder under `root`, as `cargo xtask build` recorded it.
///
/// It is the time in the header of the log that this build leaves on the card.
pub fn read_build_epoch(root: &Path) -> Result<u64> {
    let path = root.join(BUILD_EPOCH_FILE);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            bail!(
                "{} is missing: run `cargo xtask build` first",
                path.display()
            )
        }
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };
    let digits = text.strip_suffix('\n').unwrap_or(&text);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!(
            "{} is not as the build wrote it: run `cargo xtask build`",
            path.display()
        );
    }
    digits
        .parse()
        .map_err(|e| anyhow!("{}: {e}: run `cargo xtask build`", path.display()))
}

/// The directory in the initramfs where the kernel looks for firmware.
const FIRMWARE_DIR: &str = "lib/firmware";

/// The firmware files: under `firmware/` when fetched, in `FIRMWARE_DIR` in the initramfs.
const FIRMWARE: [&str; 5] = [
    "regulatory.db",
    "regulatory.db.p7s",
    "brcm/brcmfmac43455-sdio.bin",
    "brcm/brcmfmac43455-sdio.clm_blob",
    "brcm/brcmfmac43455-sdio.txt",
];

/// The names the Wi-Fi driver asks for first on this board, and the file beside each that it gets.
const BOARD_FIRMWARE: [(&str, &str); 3] = [
    (
        "lib/firmware/brcm/brcmfmac43455-sdio.raspberrypi,3-model-b-plus.bin",
        "brcmfmac43455-sdio.bin",
    ),
    (
        "lib/firmware/brcm/brcmfmac43455-sdio.raspberrypi,3-model-b-plus.clm_blob",
        "brcmfmac43455-sdio.clm_blob",
    ),
    (
        "lib/firmware/brcm/brcmfmac43455-sdio.raspberrypi,3-model-b-plus.txt",
        "brcmfmac43455-sdio.txt",
    ),
];

/// Where the initramfs holds the licence of the front panel's typefaces.
const TYPEFACE_LICENCE_PATH: &str = "licenses/JetBrainsMono-OFL.txt";

/// The licence of JetBrains Mono, the typeface that `qb-panel` builds into
/// the executable that draws with it: the SIL Open Font License 1.1.
///
/// The licence is to go wherever the typeface goes, so the image carries it.
/// These are the bytes of the crate's own copy, taken when xtask is compiled.
const TYPEFACE_LICENCE: &[u8] = include_bytes!("../../crates/qb-panel/fonts/OFL.txt");

/// The directories of the initramfs, each after the one it lies in.
const DIRS: [&str; 12] = [
    "dev",
    "proc",
    "sys",
    "run",
    "boot",
    "lib",
    "lib/modules",
    "lib/firmware",
    "lib/firmware/brcm",
    "licenses",
    "etc",
    "etc/qberrypi",
];

/// How hard zstd works on the initramfs. The kernel unpacks any level.
const ZSTD_LEVEL: i32 = 19;

/// The contents of the files `cargo xtask fetch` extracted.
pub struct ExtractedFiles {
    /// The kernel image.
    pub kernel: Vec<u8>,
    /// The device tree of the Pi 3 B+.
    pub dtb: Vec<u8>,
    /// Each of `OVERLAY_FILES` with its contents.
    overlays: Vec<(&'static str, Vec<u8>)>,
    /// Each module file of `DEFAULT_TABLE` with its contents.
    modules: Vec<(String, Vec<u8>)>,
    /// Each of `FIRMWARE` with its contents.
    firmware: Vec<(&'static str, Vec<u8>)>,
    /// The file the initramfs holds at `BOOT_FILES_PATH`: the digest of the boot files of this
    /// build (see [`boot_files_digest`]) and a line end.
    boot_files: String,
}

/// The digest of the boot files of a build, as the running build reports it and the update
/// receiver compares it (`slots::boot_files_digest`): the kernel, the device tree and the four
/// overlay files as they are, and `config.txt` and `cmdline.txt` in their slot a forms, which
/// `slot_config_txt` and `slot_cmdline_txt` make. The slot b forms give the same digest.
pub fn boot_files_digest(
    kernel: &[u8],
    dtb: &[u8],
    overlays: &[(&str, Vec<u8>)],
) -> Result<String> {
    let config = slot_config_txt(Slot::A);
    let cmdline = slot_cmdline_txt(Slot::A);
    let mut entries: Vec<(&str, &[u8])> = vec![
        (KERNEL, kernel),
        (DEVICE_TREE, dtb),
        ("cmdline.txt", cmdline.as_bytes()),
        ("config.txt", config.as_bytes()),
    ];
    entries.extend(overlays.iter().map(|(name, data)| (*name, &data[..])));
    slots::boot_files_digest(entries).map_err(|e| anyhow!("the digest of the boot files: {e}"))
}

impl ExtractedFiles {
    /// Reads every fetched file from `dir`, which is `vendor-cache/extracted/`.
    ///
    /// The error for a file that is not there says how to get it.
    pub fn read(dir: &Path) -> Result<Self> {
        let read = |name: &str| {
            let path = dir.join(name);
            fs::read(&path).map_err(|e| {
                let hint = match e.kind() {
                    ErrorKind::NotFound => "; run `cargo xtask fetch` first",
                    _ => "",
                };
                anyhow::Error::new(e).context(format!("cannot read {}{hint}", path.display()))
            })
        };
        let (kernel, dtb) = (read(KERNEL)?, read(DEVICE_TREE)?);
        let mut overlays = Vec::new();
        for name in OVERLAY_FILES {
            overlays.push((name, read(name)?));
        }
        let mut modules = Vec::new();
        for name in module_files(DEFAULT_TABLE)? {
            let data = read(&format!("modules/{name}"))?;
            modules.push((name, data));
        }
        let mut firmware = Vec::new();
        for name in FIRMWARE {
            firmware.push((name, read(&format!("firmware/{name}"))?));
        }
        let boot_files = format!("{}\n", boot_files_digest(&kernel, &dtb, &overlays)?);
        Ok(Self {
            kernel,
            dtb,
            overlays,
            modules,
            firmware,
            boot_files,
        })
    }
}

/// Lists everything the initramfs holds, in the order it is packed.
///
/// `init` is the cross-built executable, and the only member that can be executed. `snapshot`
/// is the block lists, compressed as `crate::lists::snapshot` makes them: the last entry.
pub fn initramfs_entries<'a>(
    extracted: &'a ExtractedFiles,
    init: &'a [u8],
    snapshot: &'a [u8],
) -> Vec<(String, Node<'a>)> {
    let file = |data| Node::File { data, mode: 0o644 };
    // The paths init uses start at the root; the archive's start below it.
    let module_dir = MODULE_DIR.trim_start_matches('/');
    let module_list = MODULE_LIST.trim_start_matches('/');

    let mut entries: Vec<(String, Node)> = Vec::new();
    for dir in DIRS {
        entries.push((dir.to_owned(), Node::Dir));
    }
    // The kernel opens this as init's input and output before it starts init.
    entries.push((
        "dev/console".to_owned(),
        Node::CharDev { major: 5, minor: 1 },
    ));
    // When the kernel has no console to open, init starts with nothing open,
    // and Rust's runtime opens this in its place before `main`. Without it
    // the runtime aborts there, where init can neither log nor restore.
    entries.push(("dev/null".to_owned(), Node::CharDev { major: 1, minor: 3 }));
    let init = Node::File {
        data: init,
        mode: 0o755,
    };
    entries.push(("init".to_owned(), init));
    entries.push((module_list.to_owned(), file(DEFAULT_TABLE.as_bytes())));
    for (name, data) in &extracted.modules {
        entries.push((format!("{module_dir}/{name}"), file(data)));
    }
    for (name, data) in &extracted.firmware {
        entries.push((format!("{FIRMWARE_DIR}/{name}"), file(data)));
    }
    for (path, target) in BOARD_FIRMWARE {
        entries.push((path.to_owned(), Node::Symlink { target }));
    }
    entries.push((TYPEFACE_LICENCE_PATH.to_owned(), file(TYPEFACE_LICENCE)));
    // What the build reports as its boot files: init reads it and `/api/v1/stats` tells it.
    entries.push((
        BOOT_FILES_PATH.trim_start_matches('/').to_owned(),
        file(extracted.boot_files.as_bytes()),
    ));
    entries.push((
        SNAPSHOT_PATH.trim_start_matches('/').to_owned(),
        file(snapshot),
    ));
    entries
}

/// Packs the entries into a cpio archive and compresses it, as the kernel unpacks an initramfs.
pub fn pack_initramfs(entries: &[(String, Node)]) -> Result<Vec<u8>> {
    let mut cpio = CpioWriter::new(Vec::new());
    for (path, node) in entries {
        cpio.add(path, *node)
            .with_context(|| format!("cannot add {path} to the initramfs"))?;
    }
    let archive = cpio.finish().context("cannot finish the initramfs")?;
    // One call with no worker threads: the same archive gives the same bytes.
    zstd::bulk::compress(&archive, ZSTD_LEVEL).context("cannot compress the initramfs")
}

/// Lists each file's SHA-256 and name, in the format `sha256sum --check` reads.
pub fn sha256sums(files: &[(&str, &[u8])]) -> String {
    let mut sums = String::new();
    for (name, data) in files {
        for byte in Sha256::digest(data) {
            sums.push_str(&format!("{byte:02x}"));
        }
        sums.push_str("  ");
        sums.push_str(name);
        sums.push('\n');
    }
    sums
}

/// What `build` says of the snapshot it packs: a line for what it holds and how old it is, and a
/// second when it is more than `STALE_AFTER_DAYS` days old. `epoch` is the Unix time of the build.
fn snapshot_report(header: &Header, bytes: usize, epoch: u64) -> Vec<String> {
    if header.lists == 0 {
        return vec![format!(
            "build: snapshot: no list is configured, {bytes} bytes"
        )];
    }
    let days = epoch.saturating_sub(header.fetched_unix_secs) / 86_400;
    let mut report = vec![format!(
        "build: snapshot: {} names from {} lists, fetched {days} days ago, {bytes} bytes",
        header.exact + header.suffix,
        header.lists
    )];
    if days > STALE_AFTER_DAYS {
        report.push(format!(
            "build: the snapshot is over {STALE_AFTER_DAYS} days old; cargo xtask fetch-lists renews it"
        ));
    }
    report
}

/// Cross-compiles qberrypi and writes the boot folder under `root`; returns the folder.
///
/// `epoch` is the Unix time the executable takes as the time of its build.
/// The folder of an earlier build is replaced, and only once the new
/// contents are complete. The block lists in the image are the ones
/// `cargo xtask fetch-lists` left in the cache, so the build fails before it
/// compiles anything when a list of the configuration was not fetched.
pub fn run(root: &Path, epoch: u64) -> Result<PathBuf> {
    let extracted = ExtractedFiles::read(&root.join(EXTRACTED_DIR))?;
    let (snapshot, header) = lists::snapshot(root, &lists::configured_lists(root)?)?;
    for line in snapshot_report(&header, snapshot.len(), epoch) {
        println!("{line}");
    }

    println!("build: cross-compiling qberrypi for {TARGET}");
    run_to_success(&mut cross_build_command(root, epoch))?;
    let executable = cross_built_executable(root);
    let init =
        fs::read(&executable).with_context(|| format!("cannot read {}", executable.display()))?;

    let out = write_boot_folder(root, &extracted, &init, &snapshot, epoch)?;
    let initramfs = out.join(INITRAMFS);
    let initramfs_len = fs::metadata(&initramfs)
        .with_context(|| format!("cannot look at {}", initramfs.display()))?
        .len();
    println!(
        "build: wrote {} (init is {} bytes, {INITRAMFS} is {initramfs_len} bytes)",
        out.display(),
        init.len()
    );
    Ok(out)
}

/// The cargo invocation that cross-compiles qberrypi with `epoch` as its build time.
///
/// The target directory is named outright, so the executable is at
/// `cross_built_executable` whatever the caller's cargo settings say.
fn cross_build_command(root: &Path, epoch: u64) -> Command {
    // Cargo names itself to the programs it runs; outside of cargo, find it on the path.
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = Command::new(cargo);
    command
        .current_dir(root)
        .args(["build", "-p", "qberrypi", "--release", "--target", TARGET])
        .arg("--target-dir")
        .arg(root.join("target"))
        .env("QBERRYPI_BUILD_EPOCH", epoch.to_string());
    command
}

/// Where `cross_build_command` leaves the executable.
fn cross_built_executable(root: &Path) -> PathBuf {
    root.join("target").join(TARGET).join("release/qberrypi")
}

/// Runs a command to its end; if it fails, the error shows everything it printed.
fn run_to_success(command: &mut Command) -> Result<()> {
    let program = command.get_program().to_string_lossy().into_owned();
    let output = command
        .output()
        .with_context(|| format!("cannot run {program}"))?;
    if !output.status.success() {
        bail!(
            "{program} failed ({}):\n{}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

/// Writes the boot folder under `root` from scratch and returns it.
///
/// `init` is the cross-built executable, `snapshot` the block lists for the initramfs, and
/// `epoch` the build time `init` was given, which is recorded beside the folder for
/// `read_build_epoch`. An earlier folder is removed only once everything that goes into the
/// new one is in memory. The record of its build time goes with it, and the new one is written
/// last: a record never stands for a folder of another build.
fn write_boot_folder(
    root: &Path,
    extracted: &ExtractedFiles,
    init: &[u8],
    snapshot: &[u8],
    epoch: u64,
) -> Result<PathBuf> {
    let entries = initramfs_entries(extracted, init, snapshot);
    refuse_bluetooth(DEFAULT_TABLE, &entries)?;
    let initramfs = pack_initramfs(&entries)?;
    let mut files: Vec<(&str, &[u8])> = vec![
        (KERNEL, &extracted.kernel),
        (DEVICE_TREE, &extracted.dtb),
        (INITRAMFS, &initramfs),
        ("cmdline.txt", CMDLINE_TXT.as_bytes()),
        ("config.txt", CONFIG_TXT.as_bytes()),
    ];
    files.extend(
        extracted
            .overlays
            .iter()
            .map(|(name, data)| (*name, &data[..])),
    );
    let sums = sha256sums(&files);

    let out = root.join(BOOT_FOLDER);
    let record = root.join(BUILD_EPOCH_FILE);
    remove_boot_folder(root, &out)?;
    match fs::remove_file(&record) {
        Err(e) if e.kind() != ErrorKind::NotFound => {
            return Err(e).with_context(|| format!("cannot remove {}", record.display()));
        }
        _ => {}
    }
    fs::create_dir_all(&out).with_context(|| format!("cannot create {}", out.display()))?;
    for (name, data) in files.into_iter().chain([("SHA256SUMS", sums.as_bytes())]) {
        let path = out.join(name);
        fs::write(&path, data).with_context(|| format!("cannot write {}", path.display()))?;
    }
    fs::write(&record, format!("{epoch}\n"))
        .with_context(|| format!("cannot write {}", record.display()))?;
    Ok(out)
}

/// Removes the boot folder of an earlier build, if there is one.
///
/// Nothing is removed unless `folder`, with every link in it followed, is
/// `out/qberrypi` inside `root`.
fn remove_boot_folder(root: &Path, folder: &Path) -> Result<()> {
    match fs::symlink_metadata(folder) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("cannot look at {}", folder.display())),
        Ok(_) => {}
    }
    let real_root =
        fs::canonicalize(root).with_context(|| format!("cannot resolve {}", root.display()))?;
    let real_folder =
        fs::canonicalize(folder).with_context(|| format!("cannot resolve {}", folder.display()))?;
    if real_folder != real_root.join(BOOT_FOLDER) {
        bail!(
            "refusing to remove {}: it is not {BOOT_FOLDER} inside {}",
            real_folder.display(),
            real_root.display()
        );
    }
    fs::remove_dir_all(&real_folder)
        .with_context(|| format!("cannot remove {}", real_folder.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpio::tests::system_cpio;
    use crate::deb::tests::files_under;
    use qberrypi::modules::{DEFAULT_TABLE, ModuleTable};
    use std::collections::BTreeSet;
    use std::ffi::OsStr;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    /// The twenty-one files `cargo xtask fetch` leaves under `vendor-cache/extracted/`.
    const FETCHED: [&str; 21] = [
        "kernel8.img",
        "bcm2710-rpi-3-b-plus.dtb",
        "modules/rfkill.ko",
        "modules/cfg80211.ko",
        "modules/brcmutil.ko",
        "modules/brcmfmac.ko",
        "modules/brcmfmac-cyw.ko",
        "modules/backlight.ko",
        "modules/fbtft.ko",
        "modules/fb_ili9486.ko",
        "modules/spi-bcm2835.ko",
        "modules/ads7846.ko",
        "firmware/regulatory.db",
        "firmware/regulatory.db.p7s",
        "firmware/brcm/brcmfmac43455-sdio.bin",
        "firmware/brcm/brcmfmac43455-sdio.clm_blob",
        "firmware/brcm/brcmfmac43455-sdio.txt",
        "ov-README",
        "ov-overlay_map.dtb",
        "ov-qb-piscreen.dtbo",
        "ov-disable-bt.dtbo",
    ];

    /// Every path of the initramfs in order, each after the letter `ls -l` shows for its kind.
    const INITRAMFS: [&str; 37] = [
        "d dev",
        "d proc",
        "d sys",
        "d run",
        "d boot",
        "d lib",
        "d lib/modules",
        "d lib/firmware",
        "d lib/firmware/brcm",
        "d licenses",
        "d etc",
        "d etc/qberrypi",
        "c dev/console",
        "c dev/null",
        "- init",
        "- lib/modules/modules.list",
        "- lib/modules/rfkill.ko",
        "- lib/modules/cfg80211.ko",
        "- lib/modules/brcmutil.ko",
        "- lib/modules/brcmfmac.ko",
        "- lib/modules/brcmfmac-cyw.ko",
        "- lib/modules/backlight.ko",
        "- lib/modules/fbtft.ko",
        "- lib/modules/fb_ili9486.ko",
        "- lib/modules/spi-bcm2835.ko",
        "- lib/modules/ads7846.ko",
        "- lib/firmware/regulatory.db",
        "- lib/firmware/regulatory.db.p7s",
        "- lib/firmware/brcm/brcmfmac43455-sdio.bin",
        "- lib/firmware/brcm/brcmfmac43455-sdio.clm_blob",
        "- lib/firmware/brcm/brcmfmac43455-sdio.txt",
        "l lib/firmware/brcm/brcmfmac43455-sdio.raspberrypi,3-model-b-plus.bin",
        "l lib/firmware/brcm/brcmfmac43455-sdio.raspberrypi,3-model-b-plus.clm_blob",
        "l lib/firmware/brcm/brcmfmac43455-sdio.raspberrypi,3-model-b-plus.txt",
        "- licenses/JetBrainsMono-OFL.txt",
        "- etc/qberrypi/boot-files",
        "- blocklist.zst",
    ];

    /// The build time the tests give a boot folder.
    const EPOCH: u64 = 1_700_000_123;

    /// A repository root whose `vendor-cache/extracted/` holds a stand-in for
    /// each fetched file. Each stand-in holds its own path, so a mix-up shows.
    fn fixture_root() -> TempDir {
        let root = tempfile::tempdir().unwrap();
        for name in FETCHED {
            let path = root.path().join("vendor-cache/extracted").join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, name).unwrap();
        }
        root
    }

    fn fixture_extracted() -> ExtractedFiles {
        let root = fixture_root();
        ExtractedFiles::read(&root.path().join("vendor-cache/extracted")).unwrap()
    }

    /// The data of the regular file at `path`.
    fn file_data<'a>(entries: &[(String, Node<'a>)], path: &str) -> &'a [u8] {
        match entries.iter().find(|(name, _)| name == path) {
            Some((_, Node::File { data, .. })) => data,
            _ => panic!("{path} is not a file in the initramfs"),
        }
    }

    #[test]
    fn initramfs_has_exactly_one_executable() {
        let extracted = fixture_extracted();
        let entries = initramfs_entries(&extracted, b"ELF", b"SNAPSHOT");

        let execs: Vec<_> = entries
            .iter()
            .filter(|(_, n)| matches!(n, Node::File { mode, .. } if mode & 0o111 != 0))
            .collect();

        assert_eq!(execs.len(), 1);
        assert_eq!(execs[0].0, "init");
        assert_eq!(
            execs[0].1,
            Node::File {
                data: b"ELF",
                mode: 0o755
            }
        );
    }

    #[test]
    fn the_typefaces_licence_is_shipped_as_the_panel_crate_has_it() {
        let extracted = fixture_extracted();
        let entries = initramfs_entries(&extracted, b"ELF", b"SNAPSHOT");
        let in_the_crate =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/qb-panel/fonts/OFL.txt");
        let licence = fs::read(in_the_crate).unwrap();

        let shipped = entries
            .iter()
            .find(|(path, _)| path == "licenses/JetBrainsMono-OFL.txt");

        assert_eq!(
            shipped.unwrap().1,
            Node::File {
                data: &licence,
                mode: 0o644
            }
        );
        // It is the licence the typefaces come under, and it names them.
        let text = String::from_utf8(licence).unwrap();
        assert!(text.contains("SIL OPEN FONT LICENSE Version 1.1"));
        assert!(text.contains("JetBrains Mono"));
        // A text to be read: init stays the one thing in the image that can be run.
        let executables: Vec<&str> = entries
            .iter()
            .filter(|(_, node)| matches!(node, Node::File { mode, .. } if mode & 0o111 != 0))
            .map(|(path, _)| path.as_str())
            .collect();
        assert_eq!(executables, ["init"]);
    }

    #[test]
    fn config_txt_selects_the_prefix_and_loads_the_initramfs() {
        assert!(CONFIG_TXT.lines().any(|l| l == "os_prefix=qberrypi/"));
        assert!(
            CONFIG_TXT
                .lines()
                .any(|l| l == "initramfs initramfs8 followkernel")
        );
    }

    #[test]
    fn config_txt_takes_overlays_from_qberrypis_own_folder() {
        assert_eq!(
            CONFIG_TXT.lines().rev().take(4).collect::<Vec<_>>(),
            [
                "dtoverlay=disable-bt",
                "dtoverlay=qb-piscreen,speed=16000000,rotate=270",
                "overlay_prefix=ov-",
                "dtparam=spi=on"
            ]
        );
        // Still no graphics overlay: the screen's, and the one that disables Bluetooth.
        assert_eq!(
            CONFIG_TXT
                .lines()
                .filter(|l| l.starts_with("dtoverlay="))
                .collect::<Vec<_>>(),
            [
                "dtoverlay=qb-piscreen,speed=16000000,rotate=270",
                "dtoverlay=disable-bt"
            ]
        );
        // Every overlay it asks for is one of the build's own files, by the prefix's name.
        for overlay in ["qb-piscreen", "disable-bt"] {
            assert!(
                OVERLAY_FILES.contains(&format!("ov-{overlay}.dtbo").as_str()),
                "{overlay}"
            );
        }
    }

    #[test]
    fn config_txt_and_cmdline_txt_are_the_agreed_text() {
        assert_eq!(
            CONFIG_TXT,
            "# qberrypi. Copy config.pios.txt over this file to return to Raspberry Pi OS.\n\
             arm_64bit=1\n\
             os_prefix=qberrypi/\n\
             kernel=kernel8.img\n\
             initramfs initramfs8 followkernel\n\
             disable_overscan=1\n\
             dtparam=spi=on\n\
             overlay_prefix=ov-\n\
             dtoverlay=qb-piscreen,speed=16000000,rotate=270\n\
             dtoverlay=disable-bt\n"
        );
        assert_eq!(CMDLINE_TXT, "console=tty1 panic=5 loglevel=4\n");
    }

    #[test]
    fn a_slots_config_txt_is_the_shipped_one_with_its_own_prefix_and_a_line_about_slots() {
        for slot in [Slot::A, Slot::B] {
            let text = slot_config_txt(slot);
            // It passes the check that init makes before it copies the file over the root one.
            assert_eq!(slots::check_slot_config(text.as_bytes(), slot), Ok(()));
            assert_eq!(slots::selected_slot(text.as_bytes()), Ok(slot));
            assert!(text.ends_with('\n'));
            // The first line is a comment about slots, and says nothing of Raspberry Pi OS.
            let first = text.lines().next().unwrap();
            assert!(first.starts_with('#') && first.contains("slot"), "{first}");
            assert!(!first.contains("Raspberry Pi OS"), "{first}");
            // Every other line is the shipped one, but the prefix, and then come the lines that
            // only a slot has.
            let others: Vec<&str> = text.lines().skip(1).collect();
            let shipped: Vec<&str> = CONFIG_TXT.lines().skip(1).collect();
            assert_eq!(
                others.len(),
                shipped.len() + SLOT_BOOT_LINES.lines().count()
            );
            assert_eq!(
                others[shipped.len()..],
                SLOT_BOOT_LINES.lines().collect::<Vec<_>>()
            );
            for (ours, theirs) in others.iter().zip(&shipped) {
                if theirs.starts_with("os_prefix=") {
                    assert_eq!(*ours, format!("os_prefix={}", slot.os_prefix()));
                } else {
                    assert_eq!(ours, theirs);
                }
            }
        }
        // The two slots' files differ in the value of the prefix alone.
        assert_eq!(
            slot_config_txt(Slot::A).replace("os_prefix=qberrypi-a/", "os_prefix=qberrypi-b/"),
            slot_config_txt(Slot::B)
        );
        // The shipped text of the old layout is untouched.
        assert!(CONFIG_TXT.lines().any(|l| l == "os_prefix=qberrypi/"));
    }

    #[test]
    fn a_slots_config_txt_has_the_boot_speed_lines_and_the_old_layouts_has_none_of_them() {
        // Each line is one the official documentation has (the sources are in m8-only-os.md).
        assert_eq!(
            SLOT_BOOT_LINES.lines().collect::<Vec<_>>(),
            [
                "disable_splash=1",
                "initial_turbo=60",
                "camera_auto_detect=0",
                "display_auto_detect=0",
                "dtparam=audio=off",
            ]
        );
        for slot in [Slot::A, Slot::B] {
            let text = slot_config_txt(slot);
            for line in SLOT_BOOT_LINES.lines() {
                assert_eq!(text.lines().filter(|l| *l == line).count(), 1, "{line}");
                assert!(!CONFIG_TXT.lines().any(|l| l == line), "{line}");
            }
            // What the slot must keep: the 64-bit kernel and its initramfs, the screen, the
            // Bluetooth overlay, and no line that moves the console, the Wi-Fi or the watchdog.
            for line in [
                "arm_64bit=1",
                "kernel=kernel8.img",
                "initramfs initramfs8 followkernel",
                "dtparam=spi=on",
                "dtoverlay=qb-piscreen,speed=16000000,rotate=270",
                "dtoverlay=disable-bt",
            ] {
                assert!(text.lines().any(|l| l == line), "{line}");
            }
            for key in [
                "boot_delay",
                "enable_uart",
                "dtoverlay=miniuart-bt",
                "dtparam=watchdog",
                "dtoverlay=disable-wifi",
                "dtparam=sd_",
                "force_turbo",
                "arm_freq",
                "over_voltage",
            ] {
                assert!(!text.contains(key), "{key}");
            }
        }
        // `initial_turbo` is the most the firmware takes, 60 seconds.
        assert!(SLOT_BOOT_LINES.contains("initial_turbo=60\n"));
    }

    #[test]
    fn a_slots_cmdline_txt_is_the_shipped_line_and_the_argument_that_names_the_slot() {
        assert_eq!(
            slot_cmdline_txt(Slot::A),
            "console=tty1 panic=5 loglevel=4 qberrypi.slot=a\n"
        );
        assert_eq!(
            slot_cmdline_txt(Slot::B),
            "console=tty1 panic=5 loglevel=4 qberrypi.slot=b\n"
        );
        for slot in [Slot::A, Slot::B] {
            let text = slot_cmdline_txt(slot);
            assert_eq!(slots::check_slot_cmdline(text.as_bytes(), slot), Ok(()));
            assert_eq!(Slot::from_cmdline(&text), Ok(Some(slot)));
        }
        // The old layout's command line names no slot.
        assert_eq!(Slot::from_cmdline(CMDLINE_TXT), Ok(None));
    }

    /// What the digest of the boot files of the fixture is, from the files of `slot` as a slot
    /// image holds them.
    fn digest_of_slot(extracted: &ExtractedFiles, slot: Slot) -> String {
        let (config, cmdline) = (slot_config_txt(slot), slot_cmdline_txt(slot));
        let mut entries: Vec<(&str, &[u8])> = vec![
            (KERNEL, &extracted.kernel),
            (DEVICE_TREE, &extracted.dtb),
            ("config.txt", config.as_bytes()),
            ("cmdline.txt", cmdline.as_bytes()),
            // Files that are not boot files are not in the digest.
            ("initramfs8", b"whatever"),
            ("qberrypi.toml", b"whatever"),
            ("tls.pem", b"whatever"),
        ];
        entries.extend(extracted.overlays.iter().map(|(n, d)| (*n, &d[..])));
        slots::boot_files_digest(entries).unwrap()
    }

    #[test]
    fn the_initramfs_packs_the_digest_of_the_boot_files_of_both_slots() {
        let extracted = fixture_extracted();
        let entries = initramfs_entries(&extracted, b"ELF", b"SNAPSHOT");
        let packed = file_data(&entries, "etc/qberrypi/boot-files");

        let text = std::str::from_utf8(packed).unwrap();
        let digest = text.strip_suffix('\n').expect("a line end");
        assert_eq!(digest.len(), 64);
        assert_eq!(digest, digest_of_slot(&extracted, Slot::A));
        assert_eq!(digest, digest_of_slot(&extracted, Slot::B));
        assert_eq!(digest, extracted.boot_files.trim_end());
        // The path is the one init reads, and init reads exactly this file.
        assert_eq!(BOOT_FILES_PATH, "/etc/qberrypi/boot-files");
        let tmp = tempfile::tempdir().unwrap();
        let on_disk = tmp.path().join("boot-files");
        fs::write(&on_disk, packed).unwrap();
        assert_eq!(
            qberrypi::update::read_boot_files(&on_disk).as_deref(),
            Some(digest)
        );
        // Not something to run.
        assert!(
            entries
                .iter()
                .any(|(path, node)| path == "etc/qberrypi/boot-files"
                    && matches!(node, Node::File { mode, .. } if mode & 0o111 == 0))
        );
    }

    #[test]
    fn the_packed_digest_changes_with_any_boot_file_and_not_with_the_initramfs_or_the_snapshot() {
        let packed = |extracted: &ExtractedFiles, init: &[u8], snapshot: &[u8]| {
            let entries = initramfs_entries(extracted, init, snapshot);
            file_data(&entries, "etc/qberrypi/boot-files").to_vec()
        };
        let base = fixture_extracted();
        let reference = packed(&base, b"ELF", b"SNAPSHOT");
        // The executable and the block lists make the build, not the boot files.
        assert_eq!(packed(&base, b"ANOTHER ELF", b"OTHER SNAPSHOT"), reference);
        let changed = |edit: &dyn Fn(&mut ExtractedFiles)| {
            let mut extracted = fixture_extracted();
            edit(&mut extracted);
            extracted.boot_files = format!(
                "{}\n",
                boot_files_digest(&extracted.kernel, &extracted.dtb, &extracted.overlays).unwrap()
            );
            packed(&extracted, b"ELF", b"SNAPSHOT")
        };
        assert_ne!(changed(&|e| e.kernel.push(1)), reference);
        assert_ne!(changed(&|e| e.dtb.push(1)), reference);
        for which in 0..3 {
            assert_ne!(
                changed(&|e| e.overlays[which].1.push(1)),
                reference,
                "{which}"
            );
        }
    }

    #[test]
    fn initramfs_holds_the_agreed_paths_in_the_agreed_order() {
        let extracted = fixture_extracted();
        let entries = initramfs_entries(&extracted, b"ELF", b"SNAPSHOT");

        let listing: Vec<String> = entries
            .iter()
            .map(|(path, node)| {
                let kind = match node {
                    Node::Dir => 'd',
                    Node::CharDev { .. } => 'c',
                    Node::File { .. } => '-',
                    Node::Symlink { .. } => 'l',
                };
                format!("{kind} {path}")
            })
            .collect();

        assert_eq!(listing, INITRAMFS);
        let console = entries.iter().find(|(path, _)| path == "dev/console");
        assert_eq!(console.unwrap().1, Node::CharDev { major: 5, minor: 1 });
    }

    #[test]
    fn the_snapshot_is_the_last_entry_and_is_not_executable() {
        let extracted = fixture_extracted();
        let entries = initramfs_entries(&extracted, b"ELF", b"SNAPSHOT");
        let (path, node) = entries.last().unwrap();
        assert_eq!(
            (path.as_str(), *node),
            (
                "blocklist.zst",
                Node::File {
                    data: b"SNAPSHOT",
                    mode: 0o644
                }
            )
        );
        assert_eq!(format!("/{path}"), qberrypi::lists::snapshot::SNAPSHOT_PATH);
    }

    #[test]
    fn the_boot_folder_packs_the_snapshot_it_is_given() {
        let root = fixture_root();
        let extracted = fixture_extracted();

        let out = write_boot_folder(root.path(), &extracted, b"ELF", b"ANOTHER", EPOCH).unwrap();

        assert_eq!(
            fs::read(out.join("initramfs8")).unwrap(),
            pack_initramfs(&initramfs_entries(&extracted, b"ELF", b"ANOTHER")).unwrap()
        );
        let first = pack_initramfs(&initramfs_entries(&extracted, b"ELF", b"SNAPSHOT")).unwrap();
        assert_ne!(fs::read(out.join("initramfs8")).unwrap(), first);
    }

    #[test]
    fn the_report_says_how_old_the_snapshot_is_and_when_to_renew_it() {
        let header = |fetched_unix_secs| Header {
            fetched_unix_secs,
            lists: 2,
            exact: 78_000,
            suffix: 224_001,
        };
        let epoch = 1_800_000_000 + 7 * 86_400 + 86_399;

        // Seven days and nearly a day more is still seven days.
        assert_eq!(
            snapshot_report(&header(1_800_000_000), 2_100_000, epoch),
            ["build: snapshot: 302001 names from 2 lists, fetched 7 days ago, 2100000 bytes"]
        );
        assert_eq!(
            snapshot_report(&header(1_800_000_000), 2_100_000, epoch + 1),
            [
                "build: snapshot: 302001 names from 2 lists, fetched 8 days ago, 2100000 bytes",
                "build: the snapshot is over 7 days old; cargo xtask fetch-lists renews it"
            ]
        );
        // A clock before the fetch makes no negative age.
        assert_eq!(
            snapshot_report(&header(epoch + 10), 1, epoch),
            ["build: snapshot: 302001 names from 2 lists, fetched 0 days ago, 1 bytes"]
        );
    }

    #[test]
    fn the_report_of_a_snapshot_of_no_list_has_no_age() {
        let header = Header {
            fetched_unix_secs: 0,
            lists: 0,
            exact: 1,
            suffix: 0,
        };
        assert_eq!(
            snapshot_report(&header, 30, 1_800_000_000),
            ["build: snapshot: no list is configured, 30 bytes"]
        );
    }

    #[test]
    fn dev_null_is_there_for_an_init_that_starts_with_nothing_open() {
        let extracted = fixture_extracted();
        let entries = initramfs_entries(&extracted, b"ELF", b"SNAPSHOT");

        let console = entries.iter().position(|(path, _)| path == "dev/console");
        let (path, node) = &entries[console.unwrap() + 1];

        assert_eq!(path, "dev/null");
        assert_eq!(*node, Node::CharDev { major: 1, minor: 3 });
    }

    #[test]
    fn modules_list_is_the_table_init_reads() {
        let extracted = fixture_extracted();
        let entries = initramfs_entries(&extracted, b"ELF", b"SNAPSHOT");

        let path = qberrypi::modules::MODULE_LIST.strip_prefix('/').unwrap();

        assert_eq!(file_data(&entries, path), DEFAULT_TABLE.as_bytes());
    }

    #[test]
    fn every_module_file_the_table_names_is_in_the_initramfs() {
        let extracted = fixture_extracted();
        let entries = initramfs_entries(&extracted, b"ELF", b"SNAPSHOT");
        let table = ModuleTable::parse(DEFAULT_TABLE).unwrap();
        let dir = qberrypi::modules::MODULE_DIR.strip_prefix('/').unwrap();

        let mut files = BTreeSet::new();
        for line in DEFAULT_TABLE.lines() {
            let name = line.split('\t').next().unwrap();
            for module in table.load_order(name).unwrap() {
                files.insert(module.file.clone());
            }
        }
        assert_eq!(files.len(), 10);
        for file in files {
            let fetched = format!("modules/{file}");
            assert_eq!(
                file_data(&entries, &format!("{dir}/{file}")),
                fetched.as_bytes()
            );
        }
    }

    #[test]
    fn every_fetched_file_lands_at_its_own_path() {
        let extracted = fixture_extracted();
        let entries = initramfs_entries(&extracted, b"ELF", b"SNAPSHOT");

        // The modules and the firmware go into the initramfs; the overlay files, last, do not.
        for fetched in &FETCHED[2..17] {
            let data = file_data(&entries, &format!("lib/{fetched}"));
            assert_eq!(data, fetched.as_bytes());
        }
        for overlay in &FETCHED[17..] {
            assert!(overlay.starts_with("ov-"), "{overlay}");
            assert!(entries.iter().all(|(path, _)| !path.contains(overlay)));
        }
        assert_eq!(extracted.kernel, b"kernel8.img");
        assert_eq!(extracted.dtb, b"bcm2710-rpi-3-b-plus.dtb");
    }

    #[test]
    fn board_firmware_names_link_to_the_file_beside_them() {
        let extracted = fixture_extracted();
        let entries = initramfs_entries(&extracted, b"ELF", b"SNAPSHOT");

        let mut links = 0;
        for (path, node) in &entries {
            let Node::Symlink { target } = node else {
                continue;
            };
            let (dir, name) = path.rsplit_once('/').unwrap();
            assert!(!target.contains('/'), "{target}");
            assert_eq!(
                name.replace(".raspberrypi,3-model-b-plus", ""),
                *target,
                "{path}"
            );
            file_data(&entries, &format!("{dir}/{target}"));
            links += 1;
        }
        assert_eq!(links, 3);
    }

    #[test]
    fn packing_the_same_entries_twice_gives_identical_bytes() {
        let extracted = fixture_extracted();
        let entries = initramfs_entries(&extracted, b"ELF", b"SNAPSHOT");

        let first = pack_initramfs(&entries).unwrap();
        let second = pack_initramfs(&entries).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn the_initramfs_is_a_zstd_frame_around_the_archive() {
        let extracted = fixture_extracted();
        let entries = initramfs_entries(&extracted, b"ELF", b"SNAPSHOT");
        let dir = tempfile::tempdir().unwrap();

        let packed = pack_initramfs(&entries).unwrap();

        assert_eq!(packed[..4], [0x28, 0xB5, 0x2F, 0xFD]);
        let archive = zstd::decode_all(&packed[..]).unwrap();
        let listing = system_cpio(&["-t"], &archive, dir.path());
        let listed: Vec<&str> = listing.lines().collect();
        let expected: Vec<&str> = INITRAMFS.iter().map(|line| &line[2..]).collect();
        assert_eq!(listed, expected);
    }

    #[test]
    fn checksums_are_written_the_way_sha256sum_reads_them() {
        let sums = sha256sums(&[("abc.txt", b"abc"), ("empty", b"")]);

        assert_eq!(
            sums,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  abc.txt\n\
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  empty\n"
        );
    }

    #[test]
    fn boot_folder_holds_the_nine_files_and_its_checksums_verify() {
        let root = fixture_root();
        let extracted = fixture_extracted();

        let out = write_boot_folder(root.path(), &extracted, b"ELF", b"SNAPSHOT", EPOCH).unwrap();

        assert_eq!(out, root.path().join("out/qberrypi"));
        assert_eq!(
            files_under(&out),
            [
                "SHA256SUMS",
                "bcm2710-rpi-3-b-plus.dtb",
                "cmdline.txt",
                "config.txt",
                "initramfs8",
                "kernel8.img",
                "ov-README",
                "ov-disable-bt.dtbo",
                "ov-overlay_map.dtb",
                "ov-qb-piscreen.dtbo",
            ]
        );
        assert_eq!(fs::read(out.join("kernel8.img")).unwrap(), b"kernel8.img");
        assert_eq!(
            fs::read(out.join("bcm2710-rpi-3-b-plus.dtb")).unwrap(),
            b"bcm2710-rpi-3-b-plus.dtb"
        );
        assert_eq!(
            fs::read(out.join("initramfs8")).unwrap(),
            pack_initramfs(&initramfs_entries(&extracted, b"ELF", b"SNAPSHOT")).unwrap()
        );
        assert_eq!(
            fs::read_to_string(out.join("cmdline.txt")).unwrap(),
            CMDLINE_TXT
        );
        assert_eq!(
            fs::read_to_string(out.join("config.txt")).unwrap(),
            CONFIG_TXT
        );

        let sums = fs::read_to_string(out.join("SHA256SUMS")).unwrap();
        let names: Vec<&str> = sums.lines().map(|line| &line[66..]).collect();
        assert_eq!(
            names,
            [
                "kernel8.img",
                "bcm2710-rpi-3-b-plus.dtb",
                "initramfs8",
                "cmdline.txt",
                "config.txt",
                "ov-README",
                "ov-overlay_map.dtb",
                "ov-qb-piscreen.dtbo",
                "ov-disable-bt.dtbo",
            ]
        );
        let check = Command::new("sha256sum")
            .args(["--check", "--strict", "SHA256SUMS"])
            .current_dir(&out)
            .output()
            .unwrap();
        assert!(check.status.success(), "{check:?}");
        assert_eq!(
            String::from_utf8_lossy(&check.stdout)
                .matches(": OK")
                .count(),
            9
        );
    }

    #[test]
    fn the_boot_folder_holds_the_four_overlay_files_and_their_checksums() {
        let root = fixture_root();
        let extracted = fixture_extracted();

        let out = write_boot_folder(root.path(), &extracted, b"ELF", b"SNAPSHOT", EPOCH).unwrap();

        let sums = fs::read_to_string(out.join("SHA256SUMS")).unwrap();
        for name in [
            "ov-README",
            "ov-overlay_map.dtb",
            "ov-qb-piscreen.dtbo",
            "ov-disable-bt.dtbo",
        ] {
            // Each is in the folder as the package had it, and listed with its own digest.
            assert_eq!(fs::read(out.join(name)).unwrap(), name.as_bytes(), "{name}");
            let line = sha256sums(&[(name, name.as_bytes())]);
            assert!(sums.lines().any(|l| l == line.trim_end()), "{name}: {sums}");
        }
        // The firmware finds them by their names beside the kernel; there is no folder of them.
        assert!(!out.join("overlays").exists());
        assert!(files_under(&out).iter().all(|path| !path.contains('/')));
    }

    #[test]
    fn the_build_time_is_recorded_beside_the_boot_folder_and_not_in_it() {
        let root = fixture_root();
        let extracted = fixture_extracted();

        let out = write_boot_folder(root.path(), &extracted, b"ELF", b"SNAPSHOT", EPOCH).unwrap();

        let record = root.path().join("out/build-epoch");
        assert_eq!(fs::read_to_string(record).unwrap(), "1700000123\n");
        assert_eq!(read_build_epoch(root.path()).unwrap(), EPOCH);
        // What goes onto the card, and what its checksums list, is as it was.
        assert_eq!(files_under(&out).len(), 10);
        let sums = fs::read_to_string(out.join("SHA256SUMS")).unwrap();
        assert_eq!(sums.lines().count(), 9);
        assert!(!sums.contains("build-epoch"));
    }

    #[test]
    fn a_later_build_replaces_the_record_of_the_build_time() {
        let root = fixture_root();
        let extracted = fixture_extracted();
        write_boot_folder(root.path(), &extracted, b"ELF", b"SNAPSHOT", EPOCH).unwrap();

        write_boot_folder(root.path(), &extracted, b"ELF", b"SNAPSHOT", EPOCH + 60).unwrap();

        assert_eq!(read_build_epoch(root.path()).unwrap(), EPOCH + 60);
    }

    #[test]
    fn a_build_time_that_is_missing_or_not_a_number_says_to_run_build() {
        let root = tempfile::tempdir().unwrap();
        let e = read_build_epoch(root.path()).unwrap_err();
        assert!(format!("{e:#}").contains("cargo xtask build"), "{e:#}");
        assert!(format!("{e:#}").contains("out/build-epoch"), "{e:#}");

        fs::create_dir(root.path().join("out")).unwrap();
        for text in [
            "",
            "\n",
            "soon\n",
            "-5\n",
            "17 00\n",
            "99999999999999999999999\n",
        ] {
            fs::write(root.path().join("out/build-epoch"), text).unwrap();
            let e = read_build_epoch(root.path()).unwrap_err();
            assert!(
                format!("{e:#}").contains("cargo xtask build"),
                "{text:?}: {e:#}"
            );
        }
    }

    #[test]
    fn the_packed_module_files_are_those_the_module_table_names() {
        // A module dropped from the table is not packed, and one added is.
        let table = "rfkill\trfkill.ko\t\nextra\textra-mod.ko\trfkill\n";
        assert_eq!(module_files(table).unwrap(), ["rfkill.ko", "extra-mod.ko"]);
        assert_eq!(
            module_files(DEFAULT_TABLE).unwrap(),
            [
                "rfkill.ko",
                "cfg80211.ko",
                "brcmutil.ko",
                "brcmfmac.ko",
                "brcmfmac-cyw.ko",
                "backlight.ko",
                "fbtft.ko",
                "fb_ili9486.ko",
                "spi-bcm2835.ko",
                "ads7846.ko"
            ]
        );
        let e = module_files("brcmfmac\tbrcmfmac.ko\tcfg80211\n").unwrap_err();
        assert!(format!("{e:#}").contains("cfg80211"), "{e:#}");
    }

    #[test]
    fn the_image_holds_no_bluetooth_module_and_no_bluetooth_firmware() {
        let extracted = fixture_extracted();
        let entries = initramfs_entries(&extracted, b"ELF", b"SNAPSHOT");
        refuse_bluetooth(DEFAULT_TABLE, &entries).unwrap();
        // What the image does hold is told from what it must not: none of its files is Bluetooth's.
        for (path, _) in &entries {
            assert_eq!(bluetooth_reason(path), None, "{path}");
        }
        for module in module_files(DEFAULT_TABLE).unwrap() {
            assert!(
                !is_bluetooth_module(module.trim_end_matches(".ko")),
                "{module}"
            );
        }
        for firmware in FIRMWARE {
            assert_eq!(bluetooth_reason(firmware), None, "{firmware}");
        }
    }

    #[test]
    fn a_bluetooth_module_in_the_module_table_stops_the_build() {
        let extracted = fixture_extracted();
        let entries = initramfs_entries(&extracted, b"ELF", b"SNAPSHOT");
        for module in [
            "bluetooth",
            "btbcm",
            "hci_uart",
            "btsdio",
            "bnep",
            "rfcomm",
            "hidp",
            "btusb",
            "btintel",
            "btrtl",
            "hci_vhci",
        ] {
            // As an entry of its own, and as something an entry needs.
            let own = format!("{DEFAULT_TABLE}{module}\t{module}.ko\t\n");
            let error = format!("{:#}", refuse_bluetooth(&own, &entries).unwrap_err());
            assert!(error.contains("would hold Bluetooth"), "{module}: {error}");
            assert!(
                error.contains(&format!("module table entry {module}")),
                "{module}: {error}"
            );
            assert!(error.contains("dtoverlay=disable-bt"), "{module}: {error}");
            let file_only = format!("{DEFAULT_TABLE}extra\t{module}.ko\t\n");
            let error = format!("{:#}", refuse_bluetooth(&file_only, &entries).unwrap_err());
            assert!(
                error.contains("module table entry extra"),
                "{module}: {error}"
            );
        }
        // A dash is an underscore, and capitals are small letters.
        let dashed = format!("{DEFAULT_TABLE}x\thci-uart.ko\t\n");
        assert!(refuse_bluetooth(&dashed, &entries).is_err());
        // A table that does not parse is its own error, and not a pass.
        let error = refuse_bluetooth("broken\n", &entries).unwrap_err();
        assert!(format!("{error:#}").contains("module table"), "{error:#}");
    }

    #[test]
    fn bluetooth_firmware_or_a_module_of_the_bluetooth_folders_in_the_image_stops_the_build() {
        let extracted = fixture_extracted();
        let mut entries = initramfs_entries(&extracted, b"ELF", b"SNAPSHOT");
        refuse_bluetooth(DEFAULT_TABLE, &entries).unwrap();
        for path in [
            "lib/firmware/brcm/BCM4345C0.hcd",
            "lib/firmware/brcm/bcm43xx.HCD",
            "lib/firmware/anything.hcd",
            "lib/modules/btbcm.ko",
            "lib/modules/hci_uart.ko",
            "lib/modules/kernel/net/bluetooth/rfcomm/rfcomm.ko",
            "lib/modules/kernel/drivers/bluetooth/other.ko",
            "lib/modules/btusb.ko.xz",
        ] {
            entries.push((
                path.to_owned(),
                Node::File {
                    data: b"x",
                    mode: 0o644,
                },
            ));
            let error = format!(
                "{:#}",
                refuse_bluetooth(DEFAULT_TABLE, &entries).unwrap_err()
            );
            assert!(error.contains(&format!("{path} (")), "{path}: {error}");
            entries.pop();
        }
        // A link to one is as much Bluetooth's as the file.
        entries.push((
            "lib/firmware/brcm/BCM4345C0-raspberrypi.hcd".to_owned(),
            Node::Symlink { target: "x" },
        ));
        assert!(refuse_bluetooth(DEFAULT_TABLE, &entries).is_err());
        entries.pop();
        entries.push((
            "lib/firmware/brcm/link".to_owned(),
            Node::Symlink {
                target: "BCM4345C0.hcd",
            },
        ));
        assert!(refuse_bluetooth(DEFAULT_TABLE, &entries).is_err());
    }

    #[test]
    fn the_boot_folder_is_not_written_for_an_initramfs_that_would_hold_bluetooth() {
        let root = fixture_root();
        let mut extracted = fixture_extracted();
        extracted
            .firmware
            .push(("brcm/BCM4345C0.hcd", b"patch".to_vec()));

        let error =
            write_boot_folder(root.path(), &extracted, b"ELF", b"SNAPSHOT", EPOCH).unwrap_err();

        assert!(format!("{error:#}").contains("BCM4345C0.hcd"), "{error:#}");
        assert!(!root.path().join(BOOT_FOLDER).exists());
    }

    #[test]
    fn the_fetched_modules_that_are_read_are_those_of_the_default_table() {
        let extracted = fixture_extracted();
        let read: Vec<&str> = extracted.modules.iter().map(|(name, _)| &**name).collect();
        assert_eq!(read, module_files(DEFAULT_TABLE).unwrap());
    }

    #[test]
    fn an_earlier_boot_folder_is_replaced_and_its_neighbours_are_kept() {
        let root = fixture_root();
        let extracted = fixture_extracted();
        let out = write_boot_folder(root.path(), &extracted, b"ELF", b"SNAPSHOT", EPOCH).unwrap();
        fs::write(out.join("log.txt"), "stale").unwrap();
        fs::create_dir(out.join("overlays")).unwrap();
        fs::write(out.join("overlays/stale.dtbo"), "stale").unwrap();
        fs::write(out.join("initramfs8"), "stale").unwrap();
        fs::write(root.path().join("out/notes.txt"), "kept").unwrap();

        write_boot_folder(root.path(), &extracted, b"ELF", b"SNAPSHOT", EPOCH).unwrap();

        assert_eq!(
            files_under(&root.path().join("out")),
            [
                "build-epoch",
                "notes.txt",
                "qberrypi/SHA256SUMS",
                "qberrypi/bcm2710-rpi-3-b-plus.dtb",
                "qberrypi/cmdline.txt",
                "qberrypi/config.txt",
                "qberrypi/initramfs8",
                "qberrypi/kernel8.img",
                "qberrypi/ov-README",
                "qberrypi/ov-disable-bt.dtbo",
                "qberrypi/ov-overlay_map.dtb",
                "qberrypi/ov-qb-piscreen.dtbo",
            ]
        );
        assert!(!out.join("overlays").exists());
        assert_ne!(fs::read(out.join("initramfs8")).unwrap(), b"stale");
    }

    #[test]
    fn a_missing_vendor_cache_says_to_run_fetch() {
        let root = tempfile::tempdir().unwrap();

        let e = run(root.path(), 0).unwrap_err();

        let e = format!("{e:#}");
        assert!(e.contains("cargo xtask fetch"), "{e}");
        assert!(e.contains("kernel8.img"), "{e}");
        assert!(!root.path().join("out").exists());
    }

    #[test]
    fn one_missing_fetched_file_is_named() {
        for missing in FETCHED {
            let root = fixture_root();
            let extracted = root.path().join("vendor-cache/extracted");
            fs::remove_file(extracted.join(missing)).unwrap();

            let Err(e) = ExtractedFiles::read(&extracted) else {
                panic!("read without {missing}");
            };

            let e = format!("{e:#}");
            assert!(
                e.contains(missing) && e.contains("cargo xtask fetch"),
                "{e}"
            );
        }
    }

    #[test]
    fn removes_out_qberrypi_inside_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().join("out/qberrypi");
        fs::create_dir_all(folder.join("deeper")).unwrap();
        fs::write(folder.join("deeper/file"), "x").unwrap();

        remove_boot_folder(dir.path(), &folder).unwrap();

        assert!(!folder.exists());
        assert!(dir.path().join("out").exists());
    }

    #[test]
    fn a_boot_folder_that_is_not_there_is_no_error() {
        let dir = tempfile::tempdir().unwrap();

        remove_boot_folder(dir.path(), &dir.path().join("out/qberrypi")).unwrap();
    }

    #[test]
    fn a_folder_with_another_name_is_never_removed() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "out/other",
            "out",
            "qberrypi",
            "elsewhere/qberrypi",
            "nested/out/qberrypi",
        ] {
            let folder = dir.path().join(name);
            fs::create_dir_all(&folder).unwrap();
            fs::write(folder.join("keep.txt"), "keep").unwrap();

            let e = remove_boot_folder(dir.path(), &folder).unwrap_err();

            assert!(e.to_string().contains("refusing"), "{e}");
            assert!(folder.join("keep.txt").exists(), "{name} was removed");
        }
    }

    #[test]
    fn a_folder_outside_the_root_is_never_removed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        fs::create_dir(&root).unwrap();
        let folder = dir.path().join("outside/out/qberrypi");
        fs::create_dir_all(&folder).unwrap();
        fs::write(folder.join("keep.txt"), "keep").unwrap();

        let e = remove_boot_folder(&root, &folder).unwrap_err();

        assert!(e.to_string().contains("refusing"), "{e}");
        assert!(folder.join("keep.txt").exists());
    }

    #[test]
    fn a_link_that_leads_out_of_the_root_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        fs::create_dir(&root).unwrap();
        let outside = dir.path().join("outside/out/qberrypi");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("keep.txt"), "keep").unwrap();
        symlink(dir.path().join("outside/out"), root.join("out")).unwrap();
        let extracted = fixture_extracted();

        let e = remove_boot_folder(&root, &root.join("out/qberrypi")).unwrap_err();
        assert!(e.to_string().contains("refusing"), "{e}");
        write_boot_folder(&root, &extracted, b"ELF", b"SNAPSHOT", EPOCH).unwrap_err();

        assert_eq!(
            files_under(&dir.path().join("outside")),
            ["out/qberrypi/keep.txt"]
        );
    }

    #[test]
    fn the_cross_build_gets_the_epoch_and_this_process_does_not() {
        let before = env::var_os("QBERRYPI_BUILD_EPOCH");

        let command = cross_build_command(Path::new("/repo"), 1_700_000_000);

        let args: Vec<&str> = command.get_args().map(|a| a.to_str().unwrap()).collect();
        assert_eq!(
            args,
            [
                "build",
                "-p",
                "qberrypi",
                "--release",
                "--target",
                "aarch64-unknown-linux-musl",
                "--target-dir",
                "/repo/target",
            ]
        );
        assert_eq!(command.get_current_dir(), Some(Path::new("/repo")));
        let envs: Vec<_> = command.get_envs().collect();
        assert_eq!(
            envs,
            [(
                OsStr::new("QBERRYPI_BUILD_EPOCH"),
                Some(OsStr::new("1700000000"))
            )]
        );
        assert_eq!(env::var_os("QBERRYPI_BUILD_EPOCH"), before);
        assert_eq!(
            cross_built_executable(Path::new("/repo")),
            Path::new("/repo/target/aarch64-unknown-linux-musl/release/qberrypi")
        );
    }

    #[test]
    fn a_command_that_fails_shows_what_it_printed() {
        let mut command = Command::new("sh");
        command.args([
            "-c",
            "echo compiling; echo 'error[E0425]: no' >&2; exit 101",
        ]);

        let e = run_to_success(&mut command).unwrap_err();

        let e = format!("{e:#}");
        assert!(
            e.contains("compiling") && e.contains("error[E0425]: no"),
            "{e}"
        );
        assert!(e.contains("101"), "{e}");
    }

    #[test]
    fn a_command_that_succeeds_is_no_error() {
        run_to_success(Command::new("sh").args(["-c", "echo fine; exit 0"])).unwrap();
    }
}
