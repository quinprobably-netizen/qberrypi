//! `cargo xtask build`: cross-compiles qberrypi, packs the initramfs and
//! writes `out/qberrypi/`, the folder that goes onto the Pi's boot partition.
//!
//! The folder holds the kernel and device tree exactly as fetched, the
//! initramfs, the two text files the Pi's boot firmware reads, and the
//! checksums of those five. The same inputs always give the same bytes.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use qberrypi::modules::{DEFAULT_TABLE, MODULE_DIR, MODULE_LIST, ModuleTable};
use sha2::{Digest, Sha256};

use crate::cpio::{CpioWriter, Node};

/// The kernel command line, as `cmdline.txt` holds it.
pub const CMDLINE_TXT: &str = "console=tty1 panic=5 loglevel=4\n";

/// The `config.txt` that makes the Pi's boot firmware start qberrypi from its folder.
pub const CONFIG_TXT: &str = "\
# qberrypi. Copy config.pios.txt over this file to return to Raspberry Pi OS.
arm_64bit=1
os_prefix=qberrypi/
kernel=kernel8.img
initramfs initramfs8 followkernel
disable_overscan=1
";

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

/// The kernel module files a module table names, in the table's order.
///
/// Those of `DEFAULT_TABLE` are what the initramfs holds: under `modules/`
/// when fetched, in `MODULE_DIR` in the initramfs. Taken from the table that
/// init reads, so the two cannot come apart.
fn module_files(table: &str) -> Result<Vec<String>> {
    let table = ModuleTable::parse(table).map_err(|e| anyhow!("the module table: {e}"))?;
    Ok(table.files().map(str::to_owned).collect())
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

/// The directories of the initramfs, each after the one it lies in.
const DIRS: [&str; 9] = [
    "dev",
    "proc",
    "sys",
    "run",
    "boot",
    "lib",
    "lib/modules",
    "lib/firmware",
    "lib/firmware/brcm",
];

/// How hard zstd works on the initramfs. The kernel unpacks any level.
const ZSTD_LEVEL: i32 = 19;

/// The contents of the files `cargo xtask fetch` extracted.
pub struct ExtractedFiles {
    /// The kernel image.
    pub kernel: Vec<u8>,
    /// The device tree of the Pi 3 B+.
    pub dtb: Vec<u8>,
    /// Each module file of `DEFAULT_TABLE` with its contents.
    modules: Vec<(String, Vec<u8>)>,
    /// Each of `FIRMWARE` with its contents.
    firmware: Vec<(&'static str, Vec<u8>)>,
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
        let mut modules = Vec::new();
        for name in module_files(DEFAULT_TABLE)? {
            let data = read(&format!("modules/{name}"))?;
            modules.push((name, data));
        }
        let mut firmware = Vec::new();
        for name in FIRMWARE {
            firmware.push((name, read(&format!("firmware/{name}"))?));
        }
        Ok(Self {
            kernel,
            dtb,
            modules,
            firmware,
        })
    }
}

/// Lists everything the initramfs holds, in the order it is packed.
///
/// `init` is the cross-built executable, and the only member that can be executed.
pub fn initramfs_entries<'a>(
    extracted: &'a ExtractedFiles,
    init: &'a [u8],
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

/// Cross-compiles qberrypi and writes the boot folder under `root`; returns the folder.
///
/// `epoch` is the Unix time the executable takes as the time of its build.
/// The folder of an earlier build is replaced, and only once the new
/// contents are complete.
pub fn run(root: &Path, epoch: u64) -> Result<PathBuf> {
    let extracted = ExtractedFiles::read(&root.join(EXTRACTED_DIR))?;

    println!("build: cross-compiling qberrypi for {TARGET}");
    run_to_success(&mut cross_build_command(root, epoch))?;
    let executable = cross_built_executable(root);
    let init =
        fs::read(&executable).with_context(|| format!("cannot read {}", executable.display()))?;

    let out = write_boot_folder(root, &extracted, &init, epoch)?;
    println!(
        "build: wrote {} (init is {} bytes)",
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
/// `init` is the cross-built executable, and `epoch` the build time it was
/// given, which is recorded beside the folder for `read_build_epoch`. An
/// earlier folder is removed only once everything that goes into the new one
/// is in memory. The record of its build time goes with it, and the new one
/// is written last: a record never stands for a folder of another build.
fn write_boot_folder(
    root: &Path,
    extracted: &ExtractedFiles,
    init: &[u8],
    epoch: u64,
) -> Result<PathBuf> {
    let initramfs = pack_initramfs(&initramfs_entries(extracted, init))?;
    let files: [(&str, &[u8]); 5] = [
        (KERNEL, &extracted.kernel),
        (DEVICE_TREE, &extracted.dtb),
        (INITRAMFS, &initramfs),
        ("cmdline.txt", CMDLINE_TXT.as_bytes()),
        ("config.txt", CONFIG_TXT.as_bytes()),
    ];
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

    /// The twelve files `cargo xtask fetch` leaves under `vendor-cache/extracted/`.
    const FETCHED: [&str; 12] = [
        "kernel8.img",
        "bcm2710-rpi-3-b-plus.dtb",
        "modules/rfkill.ko",
        "modules/cfg80211.ko",
        "modules/brcmutil.ko",
        "modules/brcmfmac.ko",
        "modules/brcmfmac-cyw.ko",
        "firmware/regulatory.db",
        "firmware/regulatory.db.p7s",
        "firmware/brcm/brcmfmac43455-sdio.bin",
        "firmware/brcm/brcmfmac43455-sdio.clm_blob",
        "firmware/brcm/brcmfmac43455-sdio.txt",
    ];

    /// Every path of the initramfs in order, each after the letter `ls -l` shows for its kind.
    const INITRAMFS: [&str; 26] = [
        "d dev",
        "d proc",
        "d sys",
        "d run",
        "d boot",
        "d lib",
        "d lib/modules",
        "d lib/firmware",
        "d lib/firmware/brcm",
        "c dev/console",
        "c dev/null",
        "- init",
        "- lib/modules/modules.list",
        "- lib/modules/rfkill.ko",
        "- lib/modules/cfg80211.ko",
        "- lib/modules/brcmutil.ko",
        "- lib/modules/brcmfmac.ko",
        "- lib/modules/brcmfmac-cyw.ko",
        "- lib/firmware/regulatory.db",
        "- lib/firmware/regulatory.db.p7s",
        "- lib/firmware/brcm/brcmfmac43455-sdio.bin",
        "- lib/firmware/brcm/brcmfmac43455-sdio.clm_blob",
        "- lib/firmware/brcm/brcmfmac43455-sdio.txt",
        "l lib/firmware/brcm/brcmfmac43455-sdio.raspberrypi,3-model-b-plus.bin",
        "l lib/firmware/brcm/brcmfmac43455-sdio.raspberrypi,3-model-b-plus.clm_blob",
        "l lib/firmware/brcm/brcmfmac43455-sdio.raspberrypi,3-model-b-plus.txt",
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
        let entries = initramfs_entries(&extracted, b"ELF");

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
    fn config_txt_selects_the_prefix_and_loads_the_initramfs() {
        assert!(CONFIG_TXT.lines().any(|l| l == "os_prefix=qberrypi/"));
        assert!(
            CONFIG_TXT
                .lines()
                .any(|l| l == "initramfs initramfs8 followkernel")
        );
        assert!(!CONFIG_TXT.contains("dtoverlay"));
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
             disable_overscan=1\n"
        );
        assert_eq!(CMDLINE_TXT, "console=tty1 panic=5 loglevel=4\n");
    }

    #[test]
    fn initramfs_holds_the_agreed_paths_in_the_agreed_order() {
        let extracted = fixture_extracted();
        let entries = initramfs_entries(&extracted, b"ELF");

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
    fn dev_null_is_there_for_an_init_that_starts_with_nothing_open() {
        let extracted = fixture_extracted();
        let entries = initramfs_entries(&extracted, b"ELF");

        let console = entries.iter().position(|(path, _)| path == "dev/console");
        let (path, node) = &entries[console.unwrap() + 1];

        assert_eq!(path, "dev/null");
        assert_eq!(*node, Node::CharDev { major: 1, minor: 3 });
    }

    #[test]
    fn modules_list_is_the_table_init_reads() {
        let extracted = fixture_extracted();
        let entries = initramfs_entries(&extracted, b"ELF");

        let path = qberrypi::modules::MODULE_LIST.strip_prefix('/').unwrap();

        assert_eq!(file_data(&entries, path), DEFAULT_TABLE.as_bytes());
    }

    #[test]
    fn every_module_file_the_table_names_is_in_the_initramfs() {
        let extracted = fixture_extracted();
        let entries = initramfs_entries(&extracted, b"ELF");
        let table = ModuleTable::parse(DEFAULT_TABLE).unwrap();
        let dir = qberrypi::modules::MODULE_DIR.strip_prefix('/').unwrap();

        let mut files = BTreeSet::new();
        for line in DEFAULT_TABLE.lines() {
            let name = line.split('\t').next().unwrap();
            for module in table.load_order(name).unwrap() {
                files.insert(module.file.clone());
            }
        }
        assert_eq!(files.len(), 5);
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
        let entries = initramfs_entries(&extracted, b"ELF");

        for fetched in &FETCHED[2..] {
            let data = file_data(&entries, &format!("lib/{fetched}"));
            assert_eq!(data, fetched.as_bytes());
        }
        assert_eq!(extracted.kernel, b"kernel8.img");
        assert_eq!(extracted.dtb, b"bcm2710-rpi-3-b-plus.dtb");
    }

    #[test]
    fn board_firmware_names_link_to_the_file_beside_them() {
        let extracted = fixture_extracted();
        let entries = initramfs_entries(&extracted, b"ELF");

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
        let entries = initramfs_entries(&extracted, b"ELF");

        let first = pack_initramfs(&entries).unwrap();
        let second = pack_initramfs(&entries).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn the_initramfs_is_a_zstd_frame_around_the_archive() {
        let extracted = fixture_extracted();
        let entries = initramfs_entries(&extracted, b"ELF");
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
    fn boot_folder_holds_the_six_files_and_its_checksums_verify() {
        let root = fixture_root();
        let extracted = fixture_extracted();

        let out = write_boot_folder(root.path(), &extracted, b"ELF", EPOCH).unwrap();

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
            ]
        );
        assert_eq!(fs::read(out.join("kernel8.img")).unwrap(), b"kernel8.img");
        assert_eq!(
            fs::read(out.join("bcm2710-rpi-3-b-plus.dtb")).unwrap(),
            b"bcm2710-rpi-3-b-plus.dtb"
        );
        assert_eq!(
            fs::read(out.join("initramfs8")).unwrap(),
            pack_initramfs(&initramfs_entries(&extracted, b"ELF")).unwrap()
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
            5
        );
    }

    #[test]
    fn the_build_time_is_recorded_beside_the_boot_folder_and_not_in_it() {
        let root = fixture_root();
        let extracted = fixture_extracted();

        let out = write_boot_folder(root.path(), &extracted, b"ELF", EPOCH).unwrap();

        let record = root.path().join("out/build-epoch");
        assert_eq!(fs::read_to_string(record).unwrap(), "1700000123\n");
        assert_eq!(read_build_epoch(root.path()).unwrap(), EPOCH);
        // What goes onto the card, and what its checksums list, is as it was.
        assert_eq!(files_under(&out).len(), 6);
        let sums = fs::read_to_string(out.join("SHA256SUMS")).unwrap();
        assert_eq!(sums.lines().count(), 5);
        assert!(!sums.contains("build-epoch"));
    }

    #[test]
    fn a_later_build_replaces_the_record_of_the_build_time() {
        let root = fixture_root();
        let extracted = fixture_extracted();
        write_boot_folder(root.path(), &extracted, b"ELF", EPOCH).unwrap();

        write_boot_folder(root.path(), &extracted, b"ELF", EPOCH + 60).unwrap();

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
                "brcmfmac-cyw.ko"
            ]
        );
        let e = module_files("brcmfmac\tbrcmfmac.ko\tcfg80211\n").unwrap_err();
        assert!(format!("{e:#}").contains("cfg80211"), "{e:#}");
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
        let out = write_boot_folder(root.path(), &extracted, b"ELF", EPOCH).unwrap();
        fs::write(out.join("log.txt"), "stale").unwrap();
        fs::create_dir(out.join("overlays")).unwrap();
        fs::write(out.join("overlays/stale.dtbo"), "stale").unwrap();
        fs::write(out.join("initramfs8"), "stale").unwrap();
        fs::write(root.path().join("out/notes.txt"), "kept").unwrap();

        write_boot_folder(root.path(), &extracted, b"ELF", EPOCH).unwrap();

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
        write_boot_folder(&root, &extracted, b"ELF", EPOCH).unwrap_err();

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
