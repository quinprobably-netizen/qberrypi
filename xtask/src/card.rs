//! `cargo xtask backup-card` and `cargo xtask flash`: copy a whole SD card into a file, and write
//! an image onto one, from this PC with the card in a USB reader.
//!
//! Both commands touch one kind of thing only: a whole `/dev/sd*` disk that the kernel calls
//! removable, whose sysfs path runs through a USB bus, that holds 1 to 512 GiB, and none of whose
//! partitions is mounted or used for swap. Anything else is refused before the device is opened,
//! and a command without `--yes` prints what it would do and does nothing. The checks read the
//! kernel's description of the disk (a sysfs tree, the text of `/proc/self/mountinfo` and of
//! `/proc/swaps`), which `main` takes from the running system and the tests from a fake one; the
//! device node is only opened after `--yes`, and then with `O_EXCL` and without following links,
//! so the kernel itself refuses a disk that something else has claimed since.
//!
//! A device node this user cannot open gets the exact `sudo` line to run, and nothing is run for
//! the owner. Under `sudo` the backup and its folder are handed to `SUDO_UID`/`SUDO_GID`.
//!
//! The tests run against a fake sysfs tree and regular files named like disks in a folder of
//! their own; none opens anything under `/dev`.

use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
use std::ops::RangeInclusive;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use rustix::fs::{Advice, Dev, OFlags, fadvise, major, minor};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

/// The smallest disk the commands accept: 1 GiB.
const MIN_BYTES: u64 = 1 << 30;
/// The largest disk the commands accept: 512 GiB.
const MAX_BYTES: u64 = 512 << 30;
/// The unit of the kernel's `size` files, whatever the disk's own sector size.
const SECTOR: u64 = 512;
/// The most that is read or written in one go.
const CHUNK: usize = 1 << 20;
/// The folder of the repository that holds what is private to the owner, git-ignored.
pub(crate) const PRIVATE_DIR: &str = "private";
/// The zstd compression level of a `.zst` backup.
const ZSTD_LEVEL: i32 = 3;
/// The least a progress report steps by.
const PROGRESS_STEP: u64 = 256 << 20;

/// The flags of `cargo xtask backup-card`; each field's comment is that flag's help.
#[derive(clap::Args)]
pub struct BackupArgs {
    /// The whole USB card reader disk to read, such as /dev/sdb (never a partition)
    #[arg(long, value_name = "/dev/sdX")]
    pub device: PathBuf,
    /// Where the backup goes; a name ending in .zst is compressed [default:
    /// private/card-backup-<UTC time>.img.zst in the repository]
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
    /// Do it; without this the command only says what it would do
    #[arg(long)]
    pub yes: bool,
}

/// The flags of `cargo xtask flash`; each field's comment is that flag's help.
#[derive(clap::Args)]
pub struct FlashArgs {
    /// The image to write; a name ending in .zst is decompressed on the way
    #[arg(long, value_name = "FILE")]
    pub image: PathBuf,
    /// The whole USB card reader disk to overwrite, such as /dev/sdb (never a partition)
    #[arg(long, value_name = "/dev/sdX")]
    pub device: PathBuf,
    /// Do it; without this the command only says what it would do
    #[arg(long)]
    pub yes: bool,
}

/// What the commands learn from the machine they run on: the real thing from `Host::real`, a
/// fake in the tests.
pub struct Host {
    /// The folder device nodes are in: `/dev`. A device is named by a path directly in it.
    pub dev: PathBuf,
    /// The root of sysfs: `/sys`.
    pub sys: PathBuf,
    /// The text of `/proc/self/mountinfo`.
    pub mountinfo: String,
    /// The text of `/proc/swaps`.
    pub swaps: String,
    /// The sizes a disk may have, in bytes.
    pub limits: RangeInclusive<u64>,
    /// Whether the opened device node must be a block device with the numbers sysfs gives; only
    /// the tests, which use regular files, turn this off.
    pub strict_node: bool,
    /// The absolute path of this executable, which the `sudo` line names.
    pub exe: PathBuf,
    /// The top of the repository, where `private/` is.
    pub root: PathBuf,
    /// The current time in seconds since 1970.
    pub now_unix: u64,
    /// The user and the group that ran `sudo`, when this runs under it.
    pub sudo_owner: Option<(u32, u32)>,
}

impl Host {
    /// The running machine: `/dev`, `/sys`, the mounts and swaps as they are now, and the
    /// environment of this process.
    ///
    /// Fails when the mounts or the swaps cannot be read, because then nothing can say that a
    /// disk is unused.
    pub fn real(root: &Path, now_unix: u64) -> Result<Host> {
        let read = |path: &str| {
            fs::read_to_string(path).with_context(|| {
                format!("cannot read {path}, so there is no telling whether the disk is in use")
            })
        };
        Ok(Host {
            dev: PathBuf::from("/dev"),
            sys: PathBuf::from("/sys"),
            mountinfo: read("/proc/self/mountinfo")?,
            swaps: read("/proc/swaps")?,
            limits: MIN_BYTES..=MAX_BYTES,
            strict_node: true,
            exe: env::current_exe().context("cannot tell where this program is")?,
            root: root.to_path_buf(),
            now_unix,
            sudo_owner: sudo_owner(
                env::var("SUDO_UID").ok().as_deref(),
                env::var("SUDO_GID").ok().as_deref(),
            ),
        })
    }
}

/// What the checks learned about a disk they accepted.
#[derive(Debug)]
pub struct Disk {
    /// Its device node, built from the folder of device nodes and the name.
    pub node: PathBuf,
    /// The vendor and model the device reports, or "an unnamed device".
    pub label: String,
    /// Its size in bytes.
    pub bytes: u64,
    /// Its device numbers as sysfs writes them: `8:16`.
    pub numbers: String,
    /// Its partitions' names and sizes in bytes, in partition order.
    pub partitions: Vec<(String, u64)>,
}

/// The error of a device node that this user may not open, which names the line to run instead.
#[derive(Debug)]
struct NeedsRoot {
    /// The device node that was refused.
    node: PathBuf,
    /// The whole `sudo` command line to run.
    line: String,
}

impl fmt::Display for NeedsRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} cannot be opened by this user, so nothing was done. This command line gives it \
             the access it needs; run it yourself:\n  {}",
            self.node.display(),
            self.line
        )
    }
}

impl std::error::Error for NeedsRoot {}

/// Whether the text is the name of a disk's partition's tail: one or more decimal digits.
fn is_number(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

/// The kernel's name for the disk that `device` names, or why it is not one this command takes.
///
/// It must be a path directly in `dev` named `sd` and one or more lowercase letters. A partition
/// (letters and then digits) is refused with the disk's name, anything else with the rule.
fn disk_name(dev: &Path, device: &Path) -> Result<String, String> {
    let shown = device.display();
    let not_a_disk = || {
        format!(
            "{shown} is not a whole /dev/sd* disk: this command takes a disk such as /dev/sdb, \
             nothing else"
        )
    };
    if device.parent() != Some(dev) {
        return Err(not_a_disk());
    }
    let name = device
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(not_a_disk)?;
    let rest = name.strip_prefix("sd").ok_or_else(not_a_disk)?;
    let letters = rest.trim_end_matches(|c: char| c.is_ascii_digit());
    if letters.is_empty() || !letters.bytes().all(|byte| byte.is_ascii_lowercase()) {
        return Err(not_a_disk());
    }
    if letters.len() < rest.len() {
        return Err(format!(
            "{shown} is a partition, not a whole disk: give the disk, {}",
            dev.join(format!("sd{letters}")).display()
        ));
    }
    Ok(name.to_owned())
}

/// Whether the `/dev` entry `rest` (the part after `/dev/`) is the disk `name` or one of its
/// partitions: `sdb` and `sdb1`, not `sdba1`.
fn names_disk(name: &str, rest: &str) -> bool {
    rest == name || rest.strip_prefix(name).is_some_and(is_number)
}

/// Whether a sysfs folder name is a USB bus: `usb` and a number.
fn is_usb_bus(name: &OsStr) -> bool {
    name.to_str()
        .and_then(|name| name.strip_prefix("usb"))
        .is_some_and(is_number)
}

/// One mounted file system.
struct Mount {
    /// The device numbers, `8:17`; a file system with no block device has `0:` and a number.
    numbers: String,
    /// Where it is mounted, as the kernel writes it.
    point: String,
    /// What it was mounted from.
    source: String,
}

/// The mounts in the text of `/proc/self/mountinfo`.
///
/// A line that does not have the fields the kernel documents is an error, not a mount to skip:
/// a mount that cannot be read could be the disk's.
fn parse_mountinfo(text: &str) -> Result<Vec<Mount>, String> {
    let mut mounts = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let fields: Vec<&str> = line.split(' ').collect();
        let dash = fields.iter().skip(6).position(|field| *field == "-");
        let (Some(dash), true) = (dash, fields.len() >= 7) else {
            return Err(
                "a line of /proc/self/mountinfo cannot be read, so there is no telling \
                        whether the disk is mounted"
                    .to_owned(),
            );
        };
        let Some(source) = fields.get(6 + dash + 2) else {
            return Err(
                "a line of /proc/self/mountinfo cannot be read, so there is no telling \
                        whether the disk is mounted"
                    .to_owned(),
            );
        };
        mounts.push(Mount {
            numbers: fields[2].to_owned(),
            point: fields[4].to_owned(),
            source: (*source).to_owned(),
        });
    }
    Ok(mounts)
}

/// What the text of `/proc/swaps` lists as swap, by the name it was given.
fn parse_swaps(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| *name != "Filename")
        .map(str::to_owned)
        .collect()
}

/// A kernel attribute file's text, trimmed, or the reason it cannot be read.
fn attribute(path: &Path) -> Result<String, String> {
    fs::read_to_string(path)
        .map(|text| text.trim().to_owned())
        .map_err(|error| format!("cannot read {}: {error}", path.display()))
}

/// A size in sectors from a kernel `size` file, in bytes.
fn sectors_to_bytes(path: &Path) -> Result<u64, String> {
    attribute(path)?
        .parse::<u64>()
        .ok()
        .and_then(|sectors| sectors.checked_mul(SECTOR))
        .ok_or_else(|| format!("{} does not hold a size", path.display()))
}

/// The text a device reports about itself, without anything a terminal would act on.
fn device_text(path: &Path) -> String {
    let text = fs::read_to_string(path).unwrap_or_default();
    text.chars().filter(|c| !c.is_control()).collect::<String>()
}

/// A size as a person reads it: `256 MiB`, `29.7 GiB`, `512 bytes`.
fn size_text(bytes: u64) -> String {
    for (unit, size) in [("GiB", 1u64 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)] {
        if bytes >= size {
            let text = format!("{:.1}", bytes as f64 / size as f64);
            let text = text.strip_suffix(".0").unwrap_or(&text);
            return format!("{text} {unit}");
        }
    }
    format!("{bytes} bytes")
}

/// Checks that `device` is a disk these commands may touch, and describes it.
///
/// `sys` is the root of sysfs, `dev` the folder of device nodes, `mountinfo` and `swaps` the texts
/// of `/proc/self/mountinfo` and `/proc/swaps`, and `limits` the sizes allowed in bytes. In this
/// order, stopping at the first failure: `device` is a path directly in `dev` named `sd` and
/// lowercase letters; the kernel has such a disk; its `removable` flag is 1; its sysfs path (below
/// `sys`) runs through a `usbN` bus; its size is within `limits` (a reader with no card says 0);
/// no partition (nor the disk itself) is mounted, by name or by device numbers, or listed as swap,
/// or held by another device (a mapper or a RAID on top). Nothing is opened but sysfs files.
pub fn check_device(
    sys: &Path,
    dev: &Path,
    mountinfo: &str,
    swaps: &str,
    limits: &RangeInclusive<u64>,
    device: &Path,
) -> Result<Disk, String> {
    let name = disk_name(dev, device)?;
    let shown = device.display();
    let link = sys.join("block").join(&name);
    let real = fs::canonicalize(&link).map_err(|error| match error.kind() {
        ErrorKind::NotFound => format!(
            "the kernel has no disk called {name} ({} does not exist): is the card in the reader?",
            link.display()
        ),
        _ => format!("cannot look at {}: {error}", link.display()),
    })?;
    let sys_real = fs::canonicalize(sys)
        .map_err(|error| format!("cannot look at {}: {error}", sys.display()))?;
    let below = real.strip_prefix(&sys_real).map_err(|_| {
        format!(
            "{} does not lead into {}: this is not sysfs",
            link.display(),
            sys.display()
        )
    })?;

    let removable = attribute(&real.join("removable"))?;
    if removable != "1" {
        return Err(format!(
            "{shown} is not a removable disk (the kernel's removable flag is {removable:?}, not \
             1): this command never touches a fixed disk"
        ));
    }
    if !below.components().any(|part| is_usb_bus(part.as_os_str())) {
        return Err(format!(
            "{shown} is not behind USB (its sysfs path is /sys/{}): this command only takes a \
             card in a USB reader",
            below.display()
        ));
    }
    let bytes = sectors_to_bytes(&real.join("size"))?;
    if bytes == 0 {
        return Err(format!("{shown} has no size: is a card in the reader?"));
    }
    if bytes < *limits.start() {
        return Err(format!(
            "{shown} holds {bytes} bytes ({}), less than the {} this command accepts",
            size_text(bytes),
            size_text(*limits.start())
        ));
    }
    if bytes > *limits.end() {
        return Err(format!(
            "{shown} holds {bytes} bytes ({}), more than the {} this command accepts",
            size_text(bytes),
            size_text(*limits.end())
        ));
    }

    let numbers = attribute(&real.join("dev"))?;
    let mut partitions = Vec::new();
    let mut every_numbers = vec![numbers.clone()];
    let mut holders = Vec::new();
    let entries =
        fs::read_dir(&real).map_err(|error| format!("cannot read {}: {error}", real.display()))?;
    let mut folders = vec![(name.clone(), real.clone())];
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot read {}: {error}", real.display()))?;
        let entry_name = entry.file_name().to_string_lossy().into_owned();
        let is_partition = entry_name.strip_prefix(&name).is_some_and(is_number);
        if is_partition && entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            folders.push((entry_name, entry.path()));
        }
    }
    folders.sort_by_key(|(entry_name, _)| {
        entry_name
            .strip_prefix(&name)
            .and_then(|digits| digits.parse::<u64>().ok())
            .unwrap_or(0)
    });
    for (entry_name, folder) in folders {
        if let Ok(list) = fs::read_dir(folder.join("holders")) {
            let by: Vec<String> = list
                .filter_map(|held| held.ok())
                .map(|held| held.file_name().to_string_lossy().into_owned())
                .collect();
            if !by.is_empty() {
                holders.push((entry_name.clone(), by));
            }
        }
        if entry_name != name {
            every_numbers.push(attribute(&folder.join("dev"))?);
            partitions.push((entry_name, sectors_to_bytes(&folder.join("size"))?));
        }
    }

    for mount in parse_mountinfo(mountinfo)? {
        let by_name = mount
            .source
            .strip_prefix("/dev/")
            .is_some_and(|rest| names_disk(&name, rest));
        if by_name || every_numbers.contains(&mount.numbers) {
            return Err(format!(
                "{} is mounted at {}: unmount it first (for a partition, `udisksctl unmount -b` \
                 and its device), then run this again",
                mount.source, mount.point
            ));
        }
    }
    for swap in parse_swaps(swaps) {
        if swap
            .strip_prefix("/dev/")
            .is_some_and(|rest| names_disk(&name, rest))
        {
            return Err(format!(
                "{swap} is in use as swap: turn it off first, then run this again"
            ));
        }
    }
    if let Some((part, by)) = holders.first() {
        return Err(format!(
            "{part} of {shown} is in use by {}: close that first, then run this again",
            by.join(", ")
        ));
    }

    let vendor = device_text(&real.join("device/vendor"));
    let model = device_text(&real.join("device/model"));
    let label = format!("{} {}", vendor.trim(), model.trim());
    let label = match label.trim() {
        "" => "an unnamed device".to_owned(),
        text => text.to_owned(),
    };
    Ok(Disk {
        node: dev.join(&name),
        label,
        bytes,
        numbers,
        partitions,
    })
}

/// Whether an opened device node is the block device whose sysfs `dev` file says `numbers`.
///
/// `is_block` is whether the node is a block device at all and `rdev` its device number. A node
/// that is a regular file, a character device, or another disk than the one that was checked
/// (a stale or planted `/dev/sdb`) is refused.
fn node_is(numbers: &str, is_block: bool, rdev: Dev) -> Result<(), String> {
    if !is_block {
        return Err("it is not a block device".to_owned());
    }
    let found = format!("{}:{}", major(rdev), minor(rdev));
    if found != numbers {
        return Err(format!(
            "it is the block device {found}, but the kernel's disk of that name is {numbers}"
        ));
    }
    Ok(())
}

/// Opens the disk's device node, with `O_EXCL` and without following a link, and read-only unless
/// `write` is set. Opened for writing it is also readable, so that what was written can be read
/// back. Nothing is created and nothing is truncated.
fn open_node(disk: &Disk, write: bool) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(write)
        .custom_flags((OFlags::EXCL | OFlags::NOFOLLOW).bits() as i32)
        .open(&disk.node)
}

/// Opens the device for the command, or says why not.
///
/// A node this user may not open is the `NeedsRoot` error carrying `sudo_line`; a disk the kernel
/// says is busy, a link, or any other failure is an error that names the node.
fn open_device(disk: &Disk, write: bool, sudo_line: impl FnOnce() -> String) -> Result<File> {
    match open_node(disk, write) {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == ErrorKind::PermissionDenied => Err(NeedsRoot {
            node: disk.node.clone(),
            line: sudo_line(),
        }
        .into()),
        Err(error) if error.kind() == ErrorKind::ResourceBusy => Err(anyhow!(
            "the kernel says {} is in use by something else, so it was not opened: let go of \
             the card, then run this again",
            disk.node.display()
        )),
        Err(error) => Err(error).with_context(|| format!("cannot open {}", disk.node.display())),
    }
}

/// Checks that the opened node is the disk that was described: a block device with the right
/// numbers (when the host is strict), and as long as sysfs says. The cursor is left at the start.
fn check_node(host: &Host, disk: &Disk, node: &mut File) -> Result<()> {
    if host.strict_node {
        let meta = node.metadata().context("cannot look at the device node")?;
        node_is(
            &disk.numbers,
            meta.file_type().is_block_device(),
            meta.rdev(),
        )
        .map_err(|why| {
            anyhow!(
                "{} is not the disk that was checked: {why}",
                disk.node.display()
            )
        })?;
    }
    let length = node
        .seek(SeekFrom::End(0))
        .with_context(|| format!("cannot find the size of {}", disk.node.display()))?;
    node.seek(SeekFrom::Start(0))
        .with_context(|| format!("cannot rewind {}", disk.node.display()))?;
    if length != disk.bytes {
        bail!(
            "{} holds {length} bytes but the kernel's size for the disk is {}: it is not the \
             disk that was checked",
            disk.node.display(),
            disk.bytes
        );
    }
    Ok(())
}

/// The user and group that ran `sudo`, from the values of `SUDO_UID` and `SUDO_GID`; `None` when
/// either is missing or not a number.
fn sudo_owner(uid: Option<&str>, gid: Option<&str>) -> Option<(u32, u32)> {
    Some((uid?.parse().ok()?, gid?.parse().ok()?))
}

/// A word that `sh` reads back as the same text: as it is when it holds only characters that
/// mean nothing to a shell, else in single quotes.
pub(crate) fn shell_word(text: &OsStr) -> String {
    let text = text.to_string_lossy();
    let plain = |c: char| c.is_ascii_alphanumeric() || "/._-:=+,@%".contains(c);
    if !text.is_empty() && text.chars().all(plain) {
        text.into_owned()
    } else {
        format!("'{}'", text.replace('\'', r"'\''"))
    }
}

/// The command line that runs this subcommand again as root: `sudo`, the absolute path of this
/// executable, the subcommand, each flag with its value, and `--yes`.
fn sudo_line(exe: &Path, subcommand: &str, flags: &[(&str, &Path)]) -> String {
    let mut line = format!("sudo {} {subcommand}", shell_word(exe.as_os_str()));
    for (flag, value) in flags {
        line.push_str(&format!(" {flag} {}", shell_word(value.as_os_str())));
    }
    line.push_str(" --yes");
    line
}

/// A path made absolute without resolving links, as the `sudo` line and the files need it.
pub(crate) fn absolute(path: &Path) -> Result<PathBuf> {
    std::path::absolute(path).with_context(|| format!("cannot make {} absolute", path.display()))
}

/// Whether the file name ends in `.zst`.
fn is_zst(path: &Path) -> bool {
    path.extension() == Some(OsStr::new("zst"))
}

/// The hexadecimal text of a digest.
fn hex(hash: Sha256) -> String {
    hash.finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// `yyyymmddThhmmssZ` for the moment `unix` seconds after 1970, in UTC.
fn stamp(unix: u64) -> Result<String> {
    let at = OffsetDateTime::from_unix_timestamp(i64::try_from(unix).unwrap_or(i64::MAX))
        .context("the clock of this machine is out of range")?;
    Ok(format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second()
    ))
}

/// Where a backup goes when `--out` is not given: `private/card-backup-<UTC time>.img.zst` under
/// the repository.
fn default_backup_path(root: &Path, now_unix: u64) -> Result<PathBuf> {
    Ok(root
        .join(PRIVATE_DIR)
        .join(format!("card-backup-{}.img.zst", stamp(now_unix)?)))
}

/// Makes the folder for private files, mode 0700, if it is not there; whether it was made.
///
/// A folder that is there is left alone but loses any access of its group and others: what is
/// kept in it is a Wi-Fi passphrase and a TLS key. Its parent must exist.
pub(crate) fn make_private_dir(dir: &Path) -> io::Result<bool> {
    match DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            let mode = fs::metadata(dir)?.permissions().mode();
            if !dir.is_dir() {
                return Err(io::Error::new(
                    ErrorKind::AlreadyExists,
                    format!("{} is there and is not a folder", dir.display()),
                ));
            }
            if mode & 0o077 != 0 {
                fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
            }
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

/// Gives `path` to the user and group that ran `sudo`, if there are any; a sentence for the owner
/// when that fails, which does not undo what was written.
fn give_to(path: &Path, owner: Option<(u32, u32)>) -> Option<String> {
    let (uid, gid) = owner?;
    match std::os::unix::fs::chown(path, Some(uid), Some(gid)) {
        Ok(()) => None,
        Err(error) => Some(format!(
            "{} could not be given to user {uid} ({error}); it stays as it is, readable by its \
             owner only",
            path.display()
        )),
    }
}

/// Reports how far a long copy has got, in at most about sixteen lines.
struct Progress<'a> {
    /// Where the lines go.
    out: &'a mut dyn Write,
    /// What is being done, in the past tense: "read", "written", "read back".
    done_text: &'static str,
    /// The whole length.
    total: u64,
    /// The distance between reports.
    step: u64,
    /// The next length at which to report.
    next: u64,
}

impl<'a> Progress<'a> {
    /// A report of a copy of `total` bytes.
    fn new(out: &'a mut dyn Write, done_text: &'static str, total: u64) -> Self {
        let step = (total / 16).max(PROGRESS_STEP);
        Progress {
            out,
            done_text,
            total,
            step,
            next: step,
        }
    }

    /// Says how much is done now, if a step has passed since the last line.
    fn at(&mut self, done: u64) {
        while done >= self.next && self.next < self.total {
            let _ = writeln!(
                self.out,
                "  {} {} of {}",
                self.done_text,
                size_text(self.next),
                size_text(self.total)
            );
            self.next += self.step;
        }
    }
}

/// Copies exactly `len` bytes from `from` to `to` in blocks, feeding each to `hash` and reporting.
///
/// A source that ends early is an `UnexpectedEof` error saying how far it got.
fn copy_hashed(
    from: &mut dyn Read,
    to: &mut dyn Write,
    len: u64,
    hash: &mut Sha256,
    progress: &mut Progress,
) -> io::Result<()> {
    let mut block = vec![0u8; CHUNK];
    let mut done = 0u64;
    while done < len {
        let want = usize::try_from(len - done).map_or(CHUNK, |left| left.min(CHUNK));
        let got = match from.read(&mut block[..want]) {
            Ok(0) => {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    format!("the source ended after {done} of {len} bytes"),
                ));
            }
            Ok(got) => got,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        hash.update(&block[..got]);
        to.write_all(&block[..got])?;
        done += got as u64;
        progress.at(done);
    }
    Ok(())
}

/// The length and SHA-256 of everything `image` yields, or `None` as soon as it yields more than
/// `limit` bytes (so that a small file that decompresses to a flood is not read to its end).
fn measure(mut image: impl Read, limit: u64) -> io::Result<Option<(u64, String)>> {
    let mut hash = Sha256::new();
    let mut block = vec![0u8; CHUNK];
    let mut total = 0u64;
    loop {
        let got = match image.read(&mut block) {
            Ok(0) => break,
            Ok(got) => got,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        total += got as u64;
        if total > limit {
            return Ok(None);
        }
        hash.update(&block[..got]);
    }
    Ok(Some((total, hex(hash))))
}

/// Opens an image for reading, decompressing it when its name ends in `.zst`.
fn open_image(path: &Path) -> io::Result<Box<dyn Read>> {
    let file = File::open(path)?;
    if is_zst(path) {
        Ok(Box::new(zstd::stream::read::Decoder::new(file)?))
    } else {
        Ok(Box::new(file))
    }
}

/// Where a file is written before it is complete: its name and `.part`.
pub(crate) fn part_path(target: &Path) -> PathBuf {
    let mut name: OsString = target.as_os_str().to_owned();
    name.push(".part");
    PathBuf::from(name)
}

/// What a backup is written through: the file as it is, or zstd's compression of it.
enum Sink {
    /// The raw bytes.
    Plain(File),
    /// The bytes compressed into a zstd frame with a checksum.
    Zstd(zstd::stream::write::Encoder<'static, File>),
}

impl Write for Sink {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        match self {
            Sink::Plain(file) => file.write(data),
            Sink::Zstd(encoder) => encoder.write(data),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Sink::Plain(file) => file.flush(),
            Sink::Zstd(encoder) => encoder.flush(),
        }
    }
}

impl Sink {
    /// Ends the compression, if any, and hands the file back.
    fn finish(self) -> io::Result<File> {
        match self {
            Sink::Plain(file) => Ok(file),
            Sink::Zstd(encoder) => encoder.finish(),
        }
    }
}

/// Writes the device's `bytes` bytes into a new file `part` (mode 0600, never an existing file),
/// compressed if asked, and makes it durable; the SHA-256 of the raw bytes.
fn write_backup(
    device: &mut File,
    bytes: u64,
    part: &Path,
    compressed: bool,
    progress: &mut Progress,
) -> Result<String> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(part)
        .with_context(|| {
            format!(
                "cannot create {} (if it is left from an earlier run, remove it)",
                part.display()
            )
        })?;
    let mut sink = if compressed {
        let mut encoder = zstd::stream::write::Encoder::new(file, ZSTD_LEVEL)
            .context("cannot start the compression")?;
        encoder
            .include_checksum(true)
            .context("cannot ask for a checksum")?;
        Sink::Zstd(encoder)
    } else {
        Sink::Plain(file)
    };
    let mut hash = Sha256::new();
    copy_hashed(device, &mut sink, bytes, &mut hash, progress)
        .context("cannot copy the device into the file")?;
    let file = sink.finish().context("cannot finish the file")?;
    file.sync_all()
        .with_context(|| format!("the file {} could not be made durable", part.display()))?;
    Ok(hex(hash))
}

/// Reads the whole disk into a file, as `cargo xtask backup-card` does.
///
/// In this order: the checks of `check_device`; the target (it must not exist, and its folder
/// must; the default folder is made private); the plan, written to `out`; and, only with `--yes`,
/// opening the device (a refusal by the system becomes the `sudo` line), checking that the node
/// is the disk that was described, reading it into `<target>.part` and, when that is complete and
/// durable, giving it to the user that ran `sudo` and moving it to its name. A failure removes the
/// part. Prints the size and the SHA-256 of the raw bytes.
pub fn backup(host: &Host, args: &BackupArgs, out: &mut dyn Write) -> Result<()> {
    let disk = check_device(
        &host.sys,
        &host.dev,
        &host.mountinfo,
        &host.swaps,
        &host.limits,
        &args.device,
    )
    .map_err(|why| anyhow!("{why}; nothing was read or written"))?;
    let target = match &args.out {
        Some(path) => absolute(path)?,
        None => default_backup_path(&host.root, host.now_unix)?,
    };
    match fs::symlink_metadata(&target) {
        Ok(_) => bail!(
            "{} is there already; nothing was read or written: choose another name with --out, \
             or remove it",
            target.display()
        ),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("cannot look at {}", target.display()));
        }
    }
    let folder = target
        .parent()
        .ok_or_else(|| anyhow!("{} has no folder to go in", target.display()))?
        .to_path_buf();
    let in_private = folder == host.root.join(PRIVATE_DIR);
    if !in_private && !folder.is_dir() {
        bail!(
            "the folder {} does not exist; nothing was read or written",
            folder.display()
        );
    }
    let compressed = is_zst(&target);

    writeln!(
        out,
        "backup-card will read the whole of {} ({}, {}, {} bytes; removable, behind USB) and \
         write it to {}{}.",
        disk.node.display(),
        disk.label,
        size_text(disk.bytes),
        disk.bytes,
        target.display(),
        if compressed {
            ", compressed with zstd"
        } else {
            ""
        }
    )?;
    if !disk.partitions.is_empty() {
        writeln!(out, "  It has these partitions: {}.", partition_list(&disk))?;
    }
    writeln!(
        out,
        "  The file will hold everything on the card, the Wi-Fi passphrase and the API's key \
         included, so it is made readable by its owner alone. Nothing is written to the card."
    )?;
    if !args.yes {
        bail!("nothing was done: run the same command with --yes to go ahead");
    }

    let mut flags: Vec<(&str, &Path)> = vec![("--device", args.device.as_path())];
    if args.out.is_some() {
        flags.push(("--out", target.as_path()));
    }
    let mut device = open_device(&disk, false, || sudo_line(&host.exe, "backup-card", &flags))?;
    check_node(host, &disk, &mut device)?;

    let made = in_private
        && make_private_dir(&folder)
            .with_context(|| format!("cannot make {}", folder.display()))?;
    if made && let Some(warning) = give_to(&folder, host.sudo_owner) {
        writeln!(out, "warning: {warning}")?;
    }
    let part = part_path(&target);
    let mut progress = Progress::new(out, "read", disk.bytes);
    let written = write_backup(&mut device, disk.bytes, &part, compressed, &mut progress);
    let sha = match written {
        Ok(sha) => sha,
        Err(error) => {
            let _ = fs::remove_file(&part);
            return Err(error);
        }
    };
    if let Some(warning) = give_to(&part, host.sudo_owner) {
        writeln!(out, "warning: {warning}")?;
    }
    // Never in place of a file that appeared meanwhile.
    if fs::symlink_metadata(&target).is_ok() {
        let _ = fs::remove_file(&part);
        bail!(
            "{} appeared while the card was read; it was not replaced",
            target.display()
        );
    }
    if let Err(error) = fs::rename(&part, &target) {
        let _ = fs::remove_file(&part);
        return Err(error)
            .with_context(|| format!("cannot move the backup to {}", target.display()));
    }
    File::open(&folder)
        .and_then(|dir| dir.sync_all())
        .with_context(|| format!("the folder {} could not be made durable", folder.display()))?;
    let size = fs::metadata(&target)
        .with_context(|| format!("cannot look at {}", target.display()))?
        .len();
    writeln!(
        out,
        "backup-card: read {} bytes ({}) from {}; the SHA-256 of those raw bytes is {sha}.",
        disk.bytes,
        size_text(disk.bytes),
        disk.node.display()
    )?;
    writeln!(
        out,
        "backup-card: wrote {} ({}, {size} bytes). It holds the Wi-Fi passphrase and the API's \
         key, and only its owner can read it.",
        target.display(),
        size_text(size)
    )?;
    writeln!(
        out,
        "To put it back: cargo xtask flash --image {} --device {} --yes",
        shell_word(target.as_os_str()),
        disk.node.display()
    )?;
    Ok(())
}

/// The partitions of a disk as a sentence part: `sdb1 (256 MiB), sdb2 (29.4 GiB)`.
fn partition_list(disk: &Disk) -> String {
    disk.partitions
        .iter()
        .map(|(name, bytes)| format!("{name} ({})", size_text(*bytes)))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Writes `len` bytes of `image` at the start of `device`, then proves the card holds them.
///
/// The image is read a second time, hashing as it goes, and the hash must be `expected` (an image
/// that changed since it was measured is not written on trust). After the last byte the device is
/// flushed (`fsync`) and the kernel's cached pages of it are dropped (`fadvise(DONTNEED)`);
/// `before_readback` is called then, which only the tests use, to damage the card. Then the first
/// `len` bytes are read back from the device and their SHA-256 must be `expected`. Returns that
/// hash. Progress goes to `out`.
fn write_and_verify(
    device: &mut File,
    image: &Path,
    len: u64,
    expected: &str,
    out: &mut dyn Write,
    before_readback: &mut dyn FnMut(),
) -> Result<String> {
    device
        .seek(SeekFrom::Start(0))
        .context("cannot rewind the device")?;
    let mut reader =
        open_image(image).with_context(|| format!("cannot read the image {}", image.display()))?;
    let mut written = Sha256::new();
    copy_hashed(
        &mut reader,
        device,
        len,
        &mut written,
        &mut Progress::new(out, "written", len),
    )
    .context("cannot write the image to the device")?;
    let written = hex(written);
    if written != expected {
        bail!(
            "the image changed while it was being written (its SHA-256 was {expected}, and it \
             was {written} as it was read again): the card does not hold a good copy; run \
             this again"
        );
    }
    device
        .flush()
        .and_then(|()| device.sync_all())
        .context("the device did not take the write")?;
    fadvise(&*device, 0, None, Advice::DontNeed)
        .context("cannot drop the kernel's cached pages of the device, so a read-back would not come from the card")?;
    before_readback();
    device
        .seek(SeekFrom::Start(0))
        .context("cannot rewind the device")?;
    let mut read = Sha256::new();
    copy_hashed(
        device,
        &mut io::sink(),
        len,
        &mut read,
        &mut Progress::new(out, "read back", len),
    )
    .context("cannot read the image back from the device")?;
    let found = hex(read);
    if found != expected {
        bail!(
            "the card does not hold the image: the SHA-256 of the image is {expected}, and of \
             the {len} bytes read back from the card it is {found}. Do not use this card; \
             write it again, and if that fails too, use another card or reader"
        );
    }
    Ok(found)
}

/// Writes an image onto a card, as `cargo xtask flash` does.
///
/// In this order: the image must be a non-empty regular file that fits the device (an image whose
/// name ends in `.zst` is decompressed twice, first to measure it, with a cap at the device's
/// size); the checks of `check_device`; the plan, written to `out`; and, only with `--yes`,
/// opening the device (a refusal by the system becomes the `sudo` line), checking that the node
/// is the disk that was described, and `write_and_verify`. Prints how to eject the card.
pub fn flash(host: &Host, args: &FlashArgs, out: &mut dyn Write) -> Result<()> {
    let image = absolute(&args.image)?;
    let meta = fs::metadata(&image)
        .with_context(|| format!("cannot look at the image {}", image.display()))?;
    if !meta.is_file() {
        bail!(
            "{} is not a regular file; nothing was written",
            image.display()
        );
    }
    let disk = check_device(
        &host.sys,
        &host.dev,
        &host.mountinfo,
        &host.swaps,
        &host.limits,
        &args.device,
    )
    .map_err(|why| anyhow!("{why}; nothing was written"))?;
    let compressed = is_zst(&image);
    if !compressed && meta.len() > disk.bytes {
        bail!(
            "the image {} is {} bytes ({}) and {} holds {} bytes ({}): the image does not fit; \
             nothing was written",
            image.display(),
            meta.len(),
            size_text(meta.len()),
            disk.node.display(),
            disk.bytes,
            size_text(disk.bytes)
        );
    }
    let reader =
        open_image(&image).with_context(|| format!("cannot read the image {}", image.display()))?;
    let Some((len, sha)) = measure(reader, disk.bytes)
        .with_context(|| format!("cannot read the image {}", image.display()))?
    else {
        bail!(
            "the image {} decompresses to more than the {} bytes ({}) that {} holds: the image \
             does not fit; nothing was written",
            image.display(),
            disk.bytes,
            size_text(disk.bytes),
            disk.node.display()
        );
    };
    if len == 0 {
        bail!(
            "the image {} is empty; nothing was written",
            image.display()
        );
    }

    writeln!(
        out,
        "flash will overwrite the start of {} ({}, {}, {} bytes; removable, behind USB) with {} \
         ({}, {len} bytes{}; SHA-256 {sha}).",
        disk.node.display(),
        disk.label,
        size_text(disk.bytes),
        disk.bytes,
        image.display(),
        size_text(len),
        if compressed { " once decompressed" } else { "" }
    )?;
    if disk.partitions.is_empty() {
        writeln!(out, "  Whatever is in those {} bytes is lost.", len)?;
    } else {
        writeln!(
            out,
            "  Whatever is in those {len} bytes is lost; the card now has these partitions: {}.",
            partition_list(&disk)
        )?;
    }
    writeln!(
        out,
        "  Afterwards it reads those {len} bytes back from the card, past the kernel's cache, and \
         compares their SHA-256."
    )?;
    if !args.yes {
        bail!("nothing was done: run the same command with --yes to go ahead");
    }

    let mut device = open_device(&disk, true, || {
        sudo_line(
            &host.exe,
            "flash",
            &[
                ("--image", image.as_path()),
                ("--device", args.device.as_path()),
            ],
        )
    })?;
    check_node(host, &disk, &mut device)?;
    write_and_verify(&mut device, &image, len, &sha, out, &mut || {})?;
    drop(device);
    writeln!(
        out,
        "flash: wrote {len} bytes ({}) to {}, then read them back from the card and their \
         SHA-256 is {sha}, the image's.",
        size_text(len),
        disk.node.display()
    )?;
    writeln!(
        out,
        "The card is ready. Eject it before taking it out: udisksctl power-off -b {}",
        disk.node.display()
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use tempfile::TempDir;

    use super::*;

    /// A tree standing for the machine: `sys/` as sysfs, `dev/` as the folder of device nodes
    /// (regular files here), and `repo/` as the top of the repository.
    struct Fake {
        /// The folder that holds all three.
        dir: TempDir,
    }

    /// What a fake disk looks like to the kernel.
    struct Spec {
        /// The disk's name.
        name: &'static str,
        /// What the `removable` file says.
        removable: &'static str,
        /// The `size` file, in sectors.
        sectors: u64,
        /// Whether the sysfs path runs through a USB bus.
        usb: bool,
        /// The partitions: name, sectors, held by.
        partitions: Vec<(&'static str, u64, Vec<&'static str>)>,
    }

    /// A removable USB disk of 3.5 MiB with two partitions, which the tests' small limits take.
    fn spec() -> Spec {
        Spec {
            name: "sdb",
            removable: "1",
            sectors: 7168,
            usb: true,
            partitions: vec![("sdb1", 2048, vec![]), ("sdb2", 4096, vec![])],
        }
    }

    /// The limits the small fake disks are checked against: 1 MiB to 64 MiB.
    fn small() -> RangeInclusive<u64> {
        (1 << 20)..=(64 << 20)
    }

    impl Fake {
        /// An empty machine.
        fn new() -> Fake {
            let dir = tempfile::tempdir().unwrap();
            for folder in ["sys/block", "dev", "repo"] {
                fs::create_dir_all(dir.path().join(folder)).unwrap();
            }
            Fake { dir }
        }

        /// A machine whose sysfs lives below a folder named like a USB bus, so that a check
        /// which looked at the whole path would be fooled.
        fn under_a_usb_looking_folder() -> Fake {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path().join("usb9");
            for folder in ["sys/block", "dev", "repo"] {
                fs::create_dir_all(base.join(folder)).unwrap();
            }
            Fake { dir }
        }

        /// The folder the machine is in.
        fn base(&self) -> PathBuf {
            let nested = self.dir.path().join("usb9");
            if nested.is_dir() {
                nested
            } else {
                self.dir.path().to_path_buf()
            }
        }

        /// The fake sysfs root.
        fn sys(&self) -> PathBuf {
            self.base().join("sys")
        }

        /// The fake folder of device nodes.
        fn dev(&self) -> PathBuf {
            self.base().join("dev")
        }

        /// The fake top of the repository.
        fn repo(&self) -> PathBuf {
            self.base().join("repo")
        }

        /// Adds a disk to sysfs the way the kernel lays it out: the real folder under
        /// `devices/`, and `block/<name>` a link to it.
        fn add(&self, spec: &Spec) {
            let bus = if spec.usb {
                "pci0000:00/0000:00:14.0/usb1/1-1/1-1:1.0/host6/target6:0:0/6:0:0:0"
            } else {
                "pci0000:00/0000:00:17.0/ata1/host0/target0:0:0/0:0:0:0"
            };
            let rel = format!("devices/{bus}/block/{}", spec.name);
            let folder = self.sys().join(&rel);
            fs::create_dir_all(folder.join("device")).unwrap();
            fs::write(folder.join("removable"), format!("{}\n", spec.removable)).unwrap();
            fs::write(folder.join("size"), format!("{}\n", spec.sectors)).unwrap();
            fs::write(folder.join("dev"), "8:16\n").unwrap();
            fs::write(folder.join("device/vendor"), "SanDisk \n").unwrap();
            fs::write(folder.join("device/model"), "Ultra           \n").unwrap();
            for (number, (part, sectors, held)) in spec.partitions.iter().enumerate() {
                let part_folder = folder.join(part);
                fs::create_dir_all(part_folder.join("holders")).unwrap();
                fs::write(part_folder.join("size"), format!("{sectors}\n")).unwrap();
                fs::write(part_folder.join("dev"), format!("8:{}\n", 17 + number)).unwrap();
                for holder in held {
                    fs::create_dir(part_folder.join("holders").join(holder)).unwrap();
                }
            }
            symlink(
                format!("../{rel}"),
                self.sys().join("block").join(spec.name),
            )
            .unwrap();
        }

        /// Checks the named device with the fake machine, the given texts and the small limits.
        fn check(&self, name: &str, mountinfo: &str, swaps: &str) -> Result<Disk, String> {
            check_device(
                &self.sys(),
                &self.dev(),
                mountinfo,
                swaps,
                &small(),
                &self.dev().join(name),
            )
        }

        /// A host over the fake machine, on a non-strict node (a regular file).
        fn host(&self) -> Host {
            Host {
                dev: self.dev(),
                sys: self.sys(),
                mountinfo: String::new(),
                swaps: String::new(),
                limits: small(),
                strict_node: false,
                exe: PathBuf::from("/opt/qb/target/debug/xtask"),
                root: self.repo(),
                now_unix: 1_700_000_000,
                sudo_owner: None,
            }
        }

        /// Makes the device node `sdb`: a regular file of the given bytes.
        fn node(&self, bytes: &[u8]) -> PathBuf {
            let node = self.dev().join("sdb");
            fs::write(&node, bytes).unwrap();
            node
        }
    }

    /// `len` bytes that differ from block to block, so that a misplaced block shows.
    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|at| (at as u8).wrapping_mul(31).wrapping_add((at >> 9) as u8) ^ seed)
            .collect()
    }

    /// The SHA-256 of a byte string.
    fn sha(bytes: &[u8]) -> String {
        let mut hash = Sha256::new();
        hash.update(bytes);
        hex(hash)
    }

    /// The disk size of `spec()`, in bytes: 3.5 MiB, so that the copies take four blocks.
    const DISK: usize = 7168 * 512;

    /// A mountinfo line of the kernel's documented shape.
    fn mount_line(numbers: &str, point: &str, source: &str) -> String {
        format!("36 25 {numbers} / {point} rw,relatime shared:1 - ext4 {source} rw\n")
    }

    /// The mode bits of a path.
    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// Whether this test runs as root, which opens any file whatever its mode.
    fn is_root(dir: &Path) -> bool {
        let probe = dir.join("root-probe");
        fs::write(&probe, b"x").unwrap();
        fs::set_permissions(&probe, fs::Permissions::from_mode(0o000)).unwrap();
        File::open(&probe).is_ok()
    }

    #[test]
    fn a_removable_usb_disk_of_a_sensible_size_is_accepted_and_described() {
        let fake = Fake::new();
        fake.add(&spec());
        let disk = fake.check("sdb", "", "").unwrap();
        assert_eq!(disk.node, fake.dev().join("sdb"));
        assert_eq!(disk.label, "SanDisk Ultra");
        assert_eq!(disk.bytes, DISK as u64);
        assert_eq!(disk.numbers, "8:16");
        assert_eq!(
            disk.partitions,
            vec![("sdb1".to_owned(), 1 << 20), ("sdb2".to_owned(), 2 << 20)]
        );
    }

    #[test]
    fn a_disk_that_reports_no_name_is_called_unnamed() {
        let fake = Fake::new();
        fake.add(&spec());
        let folder = fs::canonicalize(fake.sys().join("block/sdb")).unwrap();
        fs::remove_file(folder.join("device/vendor")).unwrap();
        fs::write(folder.join("device/model"), "\n").unwrap();
        assert_eq!(
            fake.check("sdb", "", "").unwrap().label,
            "an unnamed device"
        );
    }

    #[test]
    fn what_a_device_reports_about_itself_cannot_steer_the_terminal() {
        let fake = Fake::new();
        fake.add(&spec());
        let folder = fs::canonicalize(fake.sys().join("block/sdb")).unwrap();
        fs::write(folder.join("device/model"), "Ultra\x1b[2J\r\n").unwrap();
        assert_eq!(fake.check("sdb", "", "").unwrap().label, "SanDisk Ultra[2J");
    }

    #[test]
    fn a_path_that_is_not_directly_in_dev_or_not_named_sd_letters_is_refused() {
        let fake = Fake::new();
        fake.add(&spec());
        let dev = fake.dev();
        let elsewhere = fake.repo().join("sdb");
        let tricks = [
            dev.join("nvme0n1"),
            dev.join("mmcblk0"),
            dev.join("loop0"),
            dev.join("sd"),
            dev.join("sdB"),
            dev.join("hdb"),
            dev.join("sr0"),
            dev.join("sdb").join("sdb"),
            dev.join("..").join("repo").join("sdb"),
            elsewhere,
            PathBuf::from("sdb"),
            PathBuf::from("/dev/sdb"),
            dev,
        ];
        for path in tricks {
            let error =
                check_device(&fake.sys(), &fake.dev(), "", "", &small(), &path).unwrap_err();
            assert!(
                error.contains("is not a whole /dev/sd* disk"),
                "{path:?}: {error}"
            );
        }
    }

    #[test]
    fn a_partition_is_refused_and_the_disk_is_named() {
        let fake = Fake::new();
        fake.add(&spec());
        let error = fake.check("sdb1", "", "").unwrap_err();
        assert!(
            error.contains("is a partition, not a whole disk")
                && error.ends_with(&format!(
                    "give the disk, {}",
                    fake.dev().join("sdb").display()
                )),
            "{error}"
        );
        assert!(
            fake.check("sdb12", "", "")
                .unwrap_err()
                .contains("is a partition")
        );
    }

    #[test]
    fn a_disk_the_kernel_does_not_have_is_refused() {
        let fake = Fake::new();
        fake.add(&spec());
        let error = fake.check("sdc", "", "").unwrap_err();
        assert!(
            error.contains("the kernel has no disk called sdc"),
            "{error}"
        );
    }

    #[test]
    fn a_fixed_disk_is_refused() {
        for flag in ["0", "", "2", "yes"] {
            let fake = Fake::new();
            fake.add(&Spec {
                removable: flag,
                ..spec()
            });
            let error = fake.check("sdb", "", "").unwrap_err();
            assert!(
                error.contains("is not a removable disk")
                    && error.contains("never touches a fixed disk"),
                "{flag:?}: {error}"
            );
        }
    }

    #[test]
    fn a_removable_disk_that_is_not_behind_usb_is_refused() {
        let fake = Fake::new();
        fake.add(&Spec {
            usb: false,
            ..spec()
        });
        let error = fake.check("sdb", "", "").unwrap_err();
        assert!(error.contains("is not behind USB"), "{error}");
    }

    #[test]
    fn only_the_sysfs_path_below_the_root_counts_as_the_usb_check() {
        // The machine sits below a folder called usb9, and the disk is not on USB.
        let fake = Fake::under_a_usb_looking_folder();
        fake.add(&Spec {
            usb: false,
            ..spec()
        });
        assert!(
            fake.check("sdb", "", "")
                .unwrap_err()
                .contains("is not behind USB")
        );
        // And the same machine with the disk on USB is accepted.
        let fake = Fake::under_a_usb_looking_folder();
        fake.add(&spec());
        fake.check("sdb", "", "").unwrap();
    }

    #[test]
    fn the_sizes_are_one_gib_to_512_gib_inclusive_and_an_empty_reader_is_refused() {
        let whole = MIN_BYTES..=MAX_BYTES;
        let cases: [(u64, bool); 6] = [
            (0, false),
            (MIN_BYTES / 512 - 1, false),
            (MIN_BYTES / 512, true),
            (MAX_BYTES / 512, true),
            (MAX_BYTES / 512 + 1, false),
            (u64::MAX / 512, false),
        ];
        for (sectors, accepted) in cases {
            let fake = Fake::new();
            fake.add(&Spec {
                sectors,
                partitions: vec![],
                ..spec()
            });
            let result = check_device(
                &fake.sys(),
                &fake.dev(),
                "",
                "",
                &whole,
                &fake.dev().join("sdb"),
            );
            assert_eq!(result.is_ok(), accepted, "{sectors} sectors: {result:?}");
            if let Err(error) = result {
                let wanted = if sectors == 0 {
                    "has no size"
                } else if sectors < MIN_BYTES / 512 {
                    "less than the 1 GiB"
                } else {
                    "more than the 512 GiB"
                };
                assert!(error.contains(wanted), "{sectors}: {error}");
            }
        }
    }

    #[test]
    fn a_disk_with_a_mounted_partition_is_refused_by_name_or_by_numbers() {
        let fake = Fake::new();
        fake.add(&spec());
        // By the name of the source.
        let by_name = mount_line("0:51", "/run/media/q/CARD", "/dev/sdb1");
        let error = fake.check("sdb", &by_name, "").unwrap_err();
        assert!(
            error.contains("/dev/sdb1 is mounted at /run/media/q/CARD")
                && error.contains("unmount"),
            "{error}"
        );
        // By the device numbers of the second partition, under another name.
        let by_numbers = mount_line("8:18", "/mnt/card", "/dev/disk/by-label/CARD");
        assert!(
            fake.check("sdb", &by_numbers, "")
                .unwrap_err()
                .contains("is mounted at /mnt/card")
        );
        // The disk itself, mounted without a partition table.
        let whole = mount_line("0:52", "/mnt/raw", "/dev/sdb");
        assert!(
            fake.check("sdb", &whole, "")
                .unwrap_err()
                .contains("is mounted at /mnt/raw")
        );
        let whole_by_numbers = mount_line("8:16", "/mnt/raw", "/dev/disk/by-id/usb-X");
        assert!(fake.check("sdb", &whole_by_numbers, "").is_err());
    }

    #[test]
    fn a_disk_with_a_partition_used_for_swap_is_refused() {
        let fake = Fake::new();
        fake.add(&spec());
        let swaps = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n\
                     /dev/sdb2                               partition\t4194300\t\t0\t\t-2\n";
        let error = fake.check("sdb", "", swaps).unwrap_err();
        assert!(error.contains("/dev/sdb2 is in use as swap"), "{error}");
    }

    #[test]
    fn the_mounts_and_swaps_of_other_disks_do_not_count() {
        let fake = Fake::new();
        fake.add(&spec());
        let mounts = [
            mount_line("8:1", "/boot", "/dev/sda1"),
            mount_line("0:30", "/", "/dev/sdba1"),
            mount_line("259:1", "/home", "/dev/nvme0n1p2"),
            mount_line("0:5", "/proc", "proc"),
            mount_line("0:6", "/sys", "sysfs"),
            "\n".to_owned(),
        ]
        .concat();
        let swaps = "Filename Type Size Used Priority\n/dev/sda2 partition 100 0 -2\n/dev/sdbb1 partition 1 0 -3\n";
        fake.check("sdb", &mounts, swaps).unwrap();
    }

    #[test]
    fn a_partition_held_by_another_device_is_refused() {
        let fake = Fake::new();
        fake.add(&Spec {
            partitions: vec![("sdb1", 2048, vec!["dm-3"]), ("sdb2", 4096, vec![])],
            ..spec()
        });
        let error = fake.check("sdb", "", "").unwrap_err();
        assert!(
            error.contains("sdb1 of ") && error.contains("in use by dm-3"),
            "{error}"
        );
    }

    #[test]
    fn a_mountinfo_line_that_cannot_be_read_refuses_the_disk() {
        let fake = Fake::new();
        fake.add(&spec());
        for text in ["garbage\n", "1 2 3:4 / /x rw\n", "1 2 8:1 / /x rw - ext4\n"] {
            let error = fake.check("sdb", text, "").unwrap_err();
            assert!(error.contains("cannot be read"), "{text:?}: {error}");
        }
        // Optional fields before the separator are fine, and any number of them.
        let many = "36 25 0:51 / /mnt rw shared:1 master:2 propagate_from:3 - ext4 /dev/sda1 rw\n";
        fake.check("sdb", many, "").unwrap();
    }

    #[test]
    fn mountinfo_gives_the_numbers_the_point_and_the_source() {
        let mounts = parse_mountinfo(&mount_line("8:17", "/mnt/x", "/dev/sdb1")).unwrap();
        assert_eq!(mounts.len(), 1);
        assert_eq!(
            (
                mounts[0].numbers.as_str(),
                mounts[0].point.as_str(),
                mounts[0].source.as_str()
            ),
            ("8:17", "/mnt/x", "/dev/sdb1")
        );
    }

    #[test]
    fn an_opened_node_must_be_the_block_device_the_kernel_described() {
        let sdb = rustix::fs::makedev(8, 16);
        assert_eq!(node_is("8:16", true, sdb), Ok(()));
        assert!(
            node_is("8:16", false, sdb)
                .unwrap_err()
                .contains("not a block device")
        );
        let other = rustix::fs::makedev(8, 32);
        let error = node_is("8:16", true, other).unwrap_err();
        assert!(error.contains("8:32") && error.contains("8:16"), "{error}");
        // The numbers are decoded as the kernel encodes them, minor numbers above 255 included.
        assert_eq!(
            node_is("259:300", true, rustix::fs::makedev(259, 300)),
            Ok(())
        );
    }

    #[test]
    fn a_node_of_another_length_than_the_kernel_says_is_refused() {
        let fake = Fake::new();
        fake.add(&spec());
        let disk = fake.check("sdb", "", "").unwrap();
        let node = fake.node(&vec![0; DISK - 1]);
        let mut file = File::open(&node).unwrap();
        let error = check_node(&fake.host(), &disk, &mut file)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("it is not the disk that was checked"),
            "{error}"
        );
        let node = fake.node(&vec![0; DISK]);
        let mut file = File::open(&node).unwrap();
        check_node(&fake.host(), &disk, &mut file).unwrap();
        // A regular file is no disk to a strict host, which is what the real one is.
        let strict = Host {
            strict_node: true,
            ..fake.host()
        };
        let error = check_node(&strict, &disk, &mut file)
            .unwrap_err()
            .to_string();
        assert!(error.contains("not a block device"), "{error}");
    }

    #[test]
    fn sizes_read_as_a_person_writes_them() {
        assert_eq!(size_text(512), "512 bytes");
        assert_eq!(size_text(2048), "2 KiB");
        assert_eq!(size_text(256 << 20), "256 MiB");
        assert_eq!(size_text(3584 << 10), "3.5 MiB");
        assert_eq!(size_text(MIN_BYTES), "1 GiB");
        assert_eq!(size_text(MAX_BYTES), "512 GiB");
        assert_eq!(size_text(31_914_983_424), "29.7 GiB");
    }

    #[test]
    fn the_stamp_is_the_utc_time_without_separators() {
        assert_eq!(stamp(1_700_000_000).unwrap(), "20231114T221320Z");
        assert_eq!(stamp(0).unwrap(), "19700101T000000Z");
        assert_eq!(
            default_backup_path(Path::new("/repo"), 1_700_000_000).unwrap(),
            PathBuf::from("/repo/private/card-backup-20231114T221320Z.img.zst")
        );
    }

    #[test]
    fn the_sudo_ids_come_from_the_two_variables_or_not_at_all() {
        assert_eq!(sudo_owner(Some("1000"), Some("1001")), Some((1000, 1001)));
        assert_eq!(sudo_owner(Some("1000"), None), None);
        assert_eq!(sudo_owner(None, Some("1001")), None);
        assert_eq!(sudo_owner(Some("qqq"), Some("1001")), None);
        assert_eq!(sudo_owner(Some("-1"), Some("1001")), None);
    }

    #[test]
    fn the_sudo_line_quotes_what_a_shell_would_split() {
        let line = sudo_line(
            Path::new("/home/q/Work/qb repo/target/debug/xtask"),
            "flash",
            &[
                ("--image", Path::new("/home/q/it's.img")),
                ("--device", Path::new("/dev/sdb")),
            ],
        );
        assert_eq!(
            line,
            "sudo '/home/q/Work/qb repo/target/debug/xtask' flash --image '/home/q/it'\\''s.img' \
             --device /dev/sdb --yes"
        );
    }

    #[test]
    fn without_yes_the_backup_says_what_it_would_do_and_touches_nothing() {
        let fake = Fake::new();
        fake.add(&spec());
        // The device node does not even exist: it is not opened without --yes.
        let args = BackupArgs {
            device: fake.dev().join("sdb"),
            out: None,
            yes: false,
        };
        let mut said = Vec::new();
        let error = backup(&fake.host(), &args, &mut said)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "nothing was done: run the same command with --yes to go ahead"
        );
        let said = String::from_utf8(said).unwrap();
        let target = fake
            .repo()
            .join("private/card-backup-20231114T221320Z.img.zst");
        assert!(
            said.contains(&format!(
                "backup-card will read the whole of {} (SanDisk Ultra, 3.5 MiB, {DISK} bytes; removable, behind USB) and write it to {}, compressed with zstd.",
                fake.dev().join("sdb").display(),
                target.display()
            )) && said.contains("sdb1 (1 MiB), sdb2 (2 MiB)")
                && said.contains("Wi-Fi passphrase"),
            "{said}"
        );
        // Not even the private folder was made.
        assert!(!fake.repo().join("private").exists());
    }

    #[test]
    fn without_yes_the_flash_says_what_it_would_do_and_writes_nothing() {
        let fake = Fake::new();
        fake.add(&spec());
        let node = fake.node(&vec![0xAA; DISK]);
        let image = fake.repo().join("card.img");
        fs::write(&image, pattern(2 << 20, 1)).unwrap();
        let args = FlashArgs {
            image: image.clone(),
            device: node.clone(),
            yes: false,
        };
        let mut said = Vec::new();
        let error = flash(&fake.host(), &args, &mut said)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "nothing was done: run the same command with --yes to go ahead"
        );
        let said = String::from_utf8(said).unwrap();
        assert!(
            said.contains(&format!(
                "flash will overwrite the start of {} (SanDisk Ultra, 3.5 MiB, {DISK} bytes; removable, behind USB) with {} (2 MiB, 2097152 bytes; SHA-256 {})",
                node.display(),
                image.display(),
                sha(&pattern(2 << 20, 1))
            )) && said.contains("the card now has these partitions: sdb1 (1 MiB), sdb2 (2 MiB)"),
            "{said}"
        );
        assert_eq!(fs::read(&node).unwrap(), vec![0xAA; DISK]);
    }

    #[test]
    fn the_commands_refuse_a_disk_that_fails_a_check_before_anything_else() {
        let fake = Fake::new();
        fake.add(&spec());
        let mut host = fake.host();
        host.mountinfo = mount_line("8:17", "/mnt/card", "/dev/sdb1");
        let node = fake.node(&vec![0xAA; DISK]);
        let image = fake.repo().join("card.img");
        fs::write(&image, pattern(1 << 20, 2)).unwrap();
        let mut said = Vec::new();
        let error = backup(
            &host,
            &BackupArgs {
                device: node.clone(),
                out: None,
                yes: true,
            },
            &mut said,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("is mounted at /mnt/card")
                && error.ends_with("; nothing was read or written"),
            "{error}"
        );
        let error = flash(
            &host,
            &FlashArgs {
                image,
                device: node.clone(),
                yes: true,
            },
            &mut said,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("is mounted at /mnt/card") && error.ends_with("; nothing was written"),
            "{error}"
        );
        assert!(said.is_empty());
        assert!(!fake.repo().join("private").exists());
        assert_eq!(fs::read(&node).unwrap(), vec![0xAA; DISK]);
    }

    #[test]
    fn a_raw_backup_holds_the_device_bytes_and_is_private() {
        let fake = Fake::new();
        fake.add(&spec());
        let bytes = pattern(DISK, 3);
        let node = fake.node(&bytes);
        let out = fake.repo().join("mine.img");
        let args = BackupArgs {
            device: node.clone(),
            out: Some(out.clone()),
            yes: true,
        };
        let mut said = Vec::new();
        backup(&fake.host(), &args, &mut said).unwrap();
        assert_eq!(fs::read(&out).unwrap(), bytes);
        assert_eq!(mode(&out), 0o600);
        assert!(!part_path(&out).exists());
        let said = String::from_utf8(said).unwrap();
        assert!(
            said.contains(&format!(
                "backup-card: read {DISK} bytes (3.5 MiB) from {}; the SHA-256 of those raw bytes is {}.",
                node.display(),
                sha(&bytes)
            )) && said.contains(&format!("backup-card: wrote {} (3.5 MiB, {DISK} bytes).", out.display()))
                && said.contains(&format!(
                    "To put it back: cargo xtask flash --image {} --device {} --yes",
                    out.display(),
                    node.display()
                )),
            "{said}"
        );
        // The device was only read.
        assert_eq!(fs::read(&node).unwrap(), bytes);
    }

    #[test]
    fn a_zst_backup_decompresses_to_the_device_bytes_under_the_default_name() {
        let fake = Fake::new();
        fake.add(&spec());
        let bytes = pattern(DISK, 4);
        let node = fake.node(&bytes);
        let args = BackupArgs {
            device: node,
            out: None,
            yes: true,
        };
        let mut said = Vec::new();
        backup(&fake.host(), &args, &mut said).unwrap();
        let folder = fake.repo().join("private");
        assert_eq!(mode(&folder), 0o700);
        let target = folder.join("card-backup-20231114T221320Z.img.zst");
        assert_eq!(mode(&target), 0o600);
        let mut back = Vec::new();
        zstd::stream::read::Decoder::new(File::open(&target).unwrap())
            .unwrap()
            .read_to_end(&mut back)
            .unwrap();
        assert_eq!(back, bytes);
        assert!(String::from_utf8(said).unwrap().contains(&sha(&bytes)));
        let names: Vec<_> = fs::read_dir(&folder)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            names,
            vec![OsString::from("card-backup-20231114T221320Z.img.zst")]
        );
    }

    #[test]
    fn a_private_folder_that_was_open_to_others_is_closed() {
        let fake = Fake::new();
        fake.add(&spec());
        let node = fake.node(&pattern(DISK, 5));
        let folder = fake.repo().join("private");
        fs::create_dir(&folder).unwrap();
        fs::set_permissions(&folder, fs::Permissions::from_mode(0o755)).unwrap();
        let args = BackupArgs {
            device: node,
            out: None,
            yes: true,
        };
        backup(&fake.host(), &args, &mut Vec::new()).unwrap();
        assert_eq!(mode(&folder), 0o700);
    }

    #[test]
    fn a_backup_never_replaces_a_file_and_needs_a_folder_that_exists() {
        let fake = Fake::new();
        fake.add(&spec());
        let node = fake.node(&pattern(DISK, 6));
        let out = fake.repo().join("mine.img");
        fs::write(&out, b"precious").unwrap();
        let args = BackupArgs {
            device: node.clone(),
            out: Some(out.clone()),
            yes: true,
        };
        let error = backup(&fake.host(), &args, &mut Vec::new())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("is there already; nothing was read or written"),
            "{error}"
        );
        assert_eq!(fs::read(&out).unwrap(), b"precious");
        // A link is a file too, and is not followed.
        let link = fake.repo().join("link.img");
        symlink(&out, &link).unwrap();
        let args = BackupArgs {
            device: node.clone(),
            out: Some(link),
            yes: true,
        };
        assert!(backup(&fake.host(), &args, &mut Vec::new()).is_err());
        assert_eq!(fs::read(&out).unwrap(), b"precious");
        // A folder that is not there is not made for an explicit name.
        let args = BackupArgs {
            device: node,
            out: Some(fake.repo().join("missing/mine.img")),
            yes: true,
        };
        let error = backup(&fake.host(), &args, &mut Vec::new())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("does not exist; nothing was read or written"),
            "{error}"
        );
        assert!(!fake.repo().join("missing").exists());
    }

    #[test]
    fn a_part_left_from_an_earlier_run_is_not_written_through() {
        let fake = Fake::new();
        fake.add(&spec());
        let node = fake.node(&pattern(DISK, 7));
        let out = fake.repo().join("mine.img");
        let victim = fake.repo().join("victim");
        fs::write(&victim, b"keep").unwrap();
        symlink(&victim, part_path(&out)).unwrap();
        let args = BackupArgs {
            device: node,
            out: Some(out.clone()),
            yes: true,
        };
        let error = format!(
            "{:#}",
            backup(&fake.host(), &args, &mut Vec::new()).unwrap_err()
        );
        assert!(
            error.contains("if it is left from an earlier run, remove it"),
            "{error}"
        );
        assert_eq!(fs::read(&victim).unwrap(), b"keep");
        assert!(!out.exists());
    }

    #[test]
    fn a_device_shorter_than_the_kernel_says_is_refused_and_leaves_no_file() {
        let fake = Fake::new();
        fake.add(&spec());
        let node = fake.node(&pattern(DISK - 512, 8));
        let args = BackupArgs {
            device: node,
            out: None,
            yes: true,
        };
        let error = backup(&fake.host(), &args, &mut Vec::new())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("it is not the disk that was checked"),
            "{error}"
        );
        assert!(!fake.repo().join("private").exists());
    }

    #[test]
    fn a_failed_copy_leaves_no_part_behind() {
        // A source that gives out half way: the copy fails, and the part is removed by the caller.
        struct Breaks(u64);
        impl Read for Breaks {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.0 == 0 {
                    return Err(io::Error::other("the card went away"));
                }
                let n = buf.len().min(self.0 as usize);
                buf[..n].fill(7);
                self.0 -= n as u64;
                Ok(n)
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let part = dir.path().join("x.part");
        let file = File::create(&part).unwrap();
        let mut sink = Sink::Plain(file);
        let mut hash = Sha256::new();
        let error = copy_hashed(
            &mut Breaks(CHUNK as u64 + 5),
            &mut sink,
            3 * CHUNK as u64,
            &mut hash,
            &mut Progress::new(&mut io::sink(), "read", 3 * CHUNK as u64),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "the card went away");
        // A source that ends early says how far it got.
        let error = copy_hashed(
            &mut io::Cursor::new(vec![1u8; 10]),
            &mut io::sink(),
            20,
            &mut Sha256::new(),
            &mut Progress::new(&mut io::sink(), "read", 20),
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
        assert!(
            error.to_string().contains("after 10 of 20 bytes"),
            "{error}"
        );
    }

    #[test]
    fn under_sudo_the_backup_and_its_folder_go_to_the_user_that_ran_it() {
        let fake = Fake::new();
        fake.add(&spec());
        let node = fake.node(&pattern(DISK, 9));
        let mine = fs::metadata(fake.repo()).unwrap();
        let mut host = fake.host();
        host.sudo_owner = Some((mine.uid(), mine.gid()));
        let args = BackupArgs {
            device: node,
            out: None,
            yes: true,
        };
        let mut said = Vec::new();
        backup(&host, &args, &mut said).unwrap();
        let folder = fake.repo().join("private");
        let target = folder.join("card-backup-20231114T221320Z.img.zst");
        for path in [&folder, &target] {
            let meta = fs::metadata(path).unwrap();
            assert_eq!((meta.uid(), meta.gid()), (mine.uid(), mine.gid()));
        }
        assert!(!String::from_utf8(said).unwrap().contains("warning"));
    }

    #[test]
    fn a_failed_hand_over_is_said_and_does_not_undo_the_backup() {
        let fake = Fake::new();
        fake.add(&spec());
        if is_root(&fake.repo()) {
            return;
        }
        let node = fake.node(&pattern(DISK, 10));
        let mut host = fake.host();
        // A user that is not this one: only root may give files to it.
        host.sudo_owner = Some((0, 0));
        let out = fake.repo().join("mine.img");
        let args = BackupArgs {
            device: node,
            out: Some(out.clone()),
            yes: true,
        };
        let mut said = Vec::new();
        backup(&host, &args, &mut said).unwrap();
        let said = String::from_utf8(said).unwrap();
        assert!(
            said.contains("warning: ") && said.contains("could not be given to user 0"),
            "{said}"
        );
        assert_eq!(fs::read(&out).unwrap().len(), DISK);
    }

    #[test]
    fn a_device_this_user_cannot_open_gets_the_exact_sudo_line_and_nothing_happens() {
        let fake = Fake::new();
        fake.add(&spec());
        if is_root(&fake.repo()) {
            return;
        }
        let node = fake.node(&vec![0xAA; DISK]);
        fs::set_permissions(&node, fs::Permissions::from_mode(0o000)).unwrap();
        let host = fake.host();

        // The backup: its relative --out becomes absolute in the line.
        let relative = PathBuf::from("card-test-out.img");
        let args = BackupArgs {
            device: node.clone(),
            out: Some(relative.clone()),
            yes: true,
        };
        let error = backup(&host, &args, &mut Vec::new()).unwrap_err();
        let text = error.to_string();
        let wanted = format!(
            "sudo /opt/qb/target/debug/xtask backup-card --device {} --out {} --yes",
            node.display(),
            std::path::absolute(&relative).unwrap().display()
        );
        assert!(
            text.contains("cannot be opened by this user, so nothing was done")
                && text.lines().any(|line| line == format!("  {wanted}")),
            "{text}"
        );
        assert!(error.downcast_ref::<NeedsRoot>().is_some());
        assert!(!relative.exists() && !part_path(&relative).exists());
        assert!(!fake.repo().join("private").exists());

        // Without --out the line has none, and the private folder is not made.
        let args = BackupArgs {
            device: node.clone(),
            out: None,
            yes: true,
        };
        let text = backup(&host, &args, &mut Vec::new())
            .unwrap_err()
            .to_string();
        let wanted = format!(
            "sudo /opt/qb/target/debug/xtask backup-card --device {} --yes",
            node.display()
        );
        assert!(
            text.lines().any(|line| line == format!("  {wanted}")),
            "{text}"
        );
        assert!(!fake.repo().join("private").exists());

        // The flash.
        let image = fake.repo().join("card.img");
        fs::write(&image, pattern(1 << 20, 11)).unwrap();
        let args = FlashArgs {
            image: image.clone(),
            device: node.clone(),
            yes: true,
        };
        let text = flash(&host, &args, &mut Vec::new())
            .unwrap_err()
            .to_string();
        let wanted = format!(
            "sudo /opt/qb/target/debug/xtask flash --image {} --device {} --yes",
            image.display(),
            node.display()
        );
        assert!(
            text.lines().any(|line| line == format!("  {wanted}")),
            "{text}"
        );
        fs::set_permissions(&node, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(fs::read(&node).unwrap(), vec![0xAA; DISK]);
    }

    #[test]
    fn a_raw_image_is_written_at_the_start_and_the_rest_of_the_card_is_left() {
        let fake = Fake::new();
        fake.add(&spec());
        let node = fake.node(&vec![0xAA; DISK]);
        let image_bytes = pattern((2 << 20) + 100, 12);
        let image = fake.repo().join("card.img");
        fs::write(&image, &image_bytes).unwrap();
        let args = FlashArgs {
            image,
            device: node.clone(),
            yes: true,
        };
        let mut said = Vec::new();
        flash(&fake.host(), &args, &mut said).unwrap();
        let card = fs::read(&node).unwrap();
        assert_eq!(card.len(), DISK);
        assert_eq!(&card[..image_bytes.len()], &image_bytes[..]);
        assert!(card[image_bytes.len()..].iter().all(|byte| *byte == 0xAA));
        let said = String::from_utf8(said).unwrap();
        assert!(
            said.contains(&format!(
                "flash: wrote {} bytes (2 MiB) to {}, then read them back from the card and their SHA-256 is {}, the image's.",
                image_bytes.len(),
                node.display(),
                sha(&image_bytes)
            )) && said.ends_with(&format!(
                "Eject it before taking it out: udisksctl power-off -b {}\n",
                node.display()
            )),
            "{said}"
        );
    }

    #[test]
    fn a_zst_image_is_decompressed_on_the_way() {
        let fake = Fake::new();
        fake.add(&spec());
        let node = fake.node(&vec![0xAA; DISK]);
        let image_bytes = pattern(3 << 20, 13);
        let image = fake.repo().join("card.img.zst");
        fs::write(&image, zstd::encode_all(&image_bytes[..], 3).unwrap()).unwrap();
        let args = FlashArgs {
            image,
            device: node.clone(),
            yes: true,
        };
        let mut said = Vec::new();
        flash(&fake.host(), &args, &mut said).unwrap();
        let card = fs::read(&node).unwrap();
        assert_eq!(&card[..image_bytes.len()], &image_bytes[..]);
        assert!(card[image_bytes.len()..].iter().all(|byte| *byte == 0xAA));
        assert!(
            String::from_utf8(said)
                .unwrap()
                .contains("once decompressed")
        );
    }

    #[test]
    fn a_backup_flashes_back_to_the_same_bytes() {
        let fake = Fake::new();
        fake.add(&spec());
        let bytes = pattern(DISK, 14);
        let node = fake.node(&bytes);
        let out = fake.repo().join("round.img.zst");
        backup(
            &fake.host(),
            &BackupArgs {
                device: node.clone(),
                out: Some(out.clone()),
                yes: true,
            },
            &mut Vec::new(),
        )
        .unwrap();
        fs::write(&node, vec![0u8; DISK]).unwrap();
        flash(
            &fake.host(),
            &FlashArgs {
                image: out,
                device: node.clone(),
                yes: true,
            },
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(fs::read(&node).unwrap(), bytes);
    }

    #[test]
    fn an_image_larger_than_the_device_is_refused_and_the_card_is_untouched() {
        let fake = Fake::new();
        fake.add(&spec());
        let node = fake.node(&vec![0xAA; DISK]);
        // Raw: one byte too many.
        let raw = fake.repo().join("big.img");
        fs::write(&raw, vec![1u8; DISK + 1]).unwrap();
        let error = flash(
            &fake.host(),
            &FlashArgs {
                image: raw,
                device: node.clone(),
                yes: true,
            },
            &mut Vec::new(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains(&format!("is {} bytes", DISK + 1))
                && error.contains(&format!("holds {DISK} bytes"))
                && error.ends_with("the image does not fit; nothing was written"),
            "{error}"
        );
        // Compressed: tiny on disk, larger than the device once decompressed.
        let zst = fake.repo().join("big.img.zst");
        fs::write(&zst, zstd::encode_all(&vec![0u8; DISK + 1][..], 3).unwrap()).unwrap();
        let error = flash(
            &fake.host(),
            &FlashArgs {
                image: zst,
                device: node.clone(),
                yes: true,
            },
            &mut Vec::new(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("decompresses to more than the")
                && error.ends_with("the image does not fit; nothing was written"),
            "{error}"
        );
        // An image exactly as large as the device fits.
        let exact = fake.repo().join("exact.img");
        fs::write(&exact, pattern(DISK, 15)).unwrap();
        flash(
            &fake.host(),
            &FlashArgs {
                image: exact,
                device: node.clone(),
                yes: true,
            },
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(fs::read(&node).unwrap(), pattern(DISK, 15));
    }

    #[test]
    fn an_empty_image_a_folder_a_missing_file_and_a_broken_zst_are_refused_untouched() {
        let fake = Fake::new();
        fake.add(&spec());
        let node = fake.node(&vec![0xAA; DISK]);
        let empty = fake.repo().join("empty.img");
        fs::write(&empty, b"").unwrap();
        let broken = fake.repo().join("broken.img.zst");
        fs::write(&broken, b"this is not zstd").unwrap();
        let empty_zst = fake.repo().join("empty.img.zst");
        fs::write(&empty_zst, zstd::encode_all(&b""[..], 3).unwrap()).unwrap();
        let cases = [
            (empty, "is empty; nothing was written"),
            (empty_zst, "is empty; nothing was written"),
            (fake.repo(), "is not a regular file; nothing was written"),
            (fake.repo().join("nope.img"), "cannot look at the image"),
            (broken, "cannot read the image"),
        ];
        for (image, wanted) in cases {
            let error = format!(
                "{:#}",
                flash(
                    &fake.host(),
                    &FlashArgs {
                        image: image.clone(),
                        device: node.clone(),
                        yes: true,
                    },
                    &mut Vec::new(),
                )
                .unwrap_err()
            );
            assert!(error.contains(wanted), "{image:?}: {error}");
            assert_eq!(fs::read(&node).unwrap(), vec![0xAA; DISK]);
        }
    }

    #[test]
    fn the_read_back_catches_a_byte_the_card_got_wrong() {
        let dir = tempfile::tempdir().unwrap();
        let image_bytes = pattern(2 << 20, 16);
        let image = dir.path().join("card.img");
        fs::write(&image, &image_bytes).unwrap();
        let node = dir.path().join("card");
        fs::write(&node, vec![0xAA; 3 << 20]).unwrap();
        let mut device = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&node)
            .unwrap();
        let expected = sha(&image_bytes);

        // A card that keeps every byte passes.
        let found = write_and_verify(
            &mut device,
            &image,
            image_bytes.len() as u64,
            &expected,
            &mut io::sink(),
            &mut || {},
        )
        .unwrap();
        assert_eq!(found, expected);

        // A card that flips one byte after the sync is caught, and both hashes are shown.
        let mut flip = || {
            let mut card = fs::read(&node).unwrap();
            card[1_234_567] ^= 0x01;
            fs::write(&node, card).unwrap();
        };
        let error = write_and_verify(
            &mut device,
            &image,
            image_bytes.len() as u64,
            &expected,
            &mut io::sink(),
            &mut flip,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("the card does not hold the image")
                && error.contains(&expected)
                && error.contains("Do not use this card"),
            "{error}"
        );

        // A byte past the image's length is not part of the comparison.
        let mut flip_past_the_end = || {
            let mut card = fs::read(&node).unwrap();
            card[image_bytes.len() + 10] ^= 0x01;
            fs::write(&node, card).unwrap();
        };
        write_and_verify(
            &mut device,
            &image,
            image_bytes.len() as u64,
            &expected,
            &mut io::sink(),
            &mut flip_past_the_end,
        )
        .unwrap();
    }

    #[test]
    fn an_image_that_changed_since_it_was_measured_is_not_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("card.img");
        fs::write(&image, pattern(1 << 20, 17)).unwrap();
        let node = dir.path().join("card");
        fs::write(&node, vec![0xAA; 2 << 20]).unwrap();
        let mut device = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&node)
            .unwrap();
        let measured = sha(&pattern(1 << 20, 99));
        let error = write_and_verify(
            &mut device,
            &image,
            1 << 20,
            &measured,
            &mut io::sink(),
            &mut || panic!("no read-back of a bad copy"),
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("the image changed while it was being written"),
            "{error}"
        );
    }

    #[test]
    fn a_measure_stops_at_the_limit_and_counts_what_is_under_it() {
        let (len, hash) = measure(&b"abc"[..], 3).unwrap().unwrap();
        assert_eq!((len, hash), (3, sha(b"abc")));
        assert_eq!(measure(&b"abcd"[..], 3).unwrap(), None);
        let (len, hash) = measure(&b""[..], 3).unwrap().unwrap();
        assert_eq!((len, hash), (0, sha(b"")));
    }

    #[test]
    fn progress_reports_in_few_lines() {
        let mut said = Vec::new();
        {
            let total = 3u64 << 30;
            let mut progress = Progress::new(&mut said, "read", total);
            for done in (0..=total).step_by(1 << 20) {
                progress.at(done);
            }
        }
        let said = String::from_utf8(said).unwrap();
        assert_eq!(said.lines().count(), 11, "{said}");
        assert!(said.starts_with("  read 256 MiB of 3 GiB\n"), "{said}");
        // A small copy says nothing.
        let mut said = Vec::new();
        Progress::new(&mut said, "read", 3 << 20).at(3 << 20);
        assert!(said.is_empty());
    }
}
