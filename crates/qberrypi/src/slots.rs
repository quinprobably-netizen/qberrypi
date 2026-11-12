//! The card's two slots: which one runs, which one `config.txt` selects, the trial marker, and
//! the rules for what a boot does with them.
//!
//! A slot card holds qberrypi twice, in `qberrypi-a/` and `qberrypi-b/` on the boot partition.
//! The firmware starts the slot that the root `config.txt` selects with `os_prefix=`, and
//! applies that prefix to `cmdline.txt`, so each slot's command line names its own slot with
//! `qberrypi.slot=`. During an update's trial the file `qberrypi-trial.txt` (the marker)
//! records which slot is on trial, which slot it came from and how far the trial got.
//!
//! Everything here is a pure function or works on a directory where the boot partition is
//! already mounted. Nothing here mounts, restarts, logs or waits, and nothing here depends on
//! init, the services or the API: those call in. Which write is allowed when is for the
//! caller; each write here is one that the design's "Card writes, amended" lists.

use std::borrow::Cow;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, ErrorKind, Read, Write};
use std::ops::Range;
use std::os::unix::fs::FileExt;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::bootpart::{ACTIVE_CONFIG, overwrite_in_place};

/// The marker of a trial, in the root of the boot partition.
pub const MARKER_FILE: &str = "qberrypi-trial.txt";

/// The file the firmware reads instead of `config.txt` when it starts in `tryboot` mode.
pub const TRYBOOT_FILE: &str = "tryboot.txt";

/// The line that tells the marker its trial build has started; init appends it.
pub const STARTED: &str = "started";

/// The most bytes of the marker that are read; a marker takes well under 400.
pub const MARKER_CAP: u64 = 4096;

/// The most bytes of a `failed=` reason in the marker.
pub const FAILED_CAP: usize = 200;

/// The command line argument that names the running slot, without its value.
const CMDLINE_KEY: &[u8] = b"qberrypi.slot";

/// What a line of `config.txt` starts with when it selects a slot.
const OS_PREFIX_KEY: &[u8] = b"os_prefix=";

/// The files of a slot, in the order the update's body carries them.
///
/// The kernel, device tree and initramfs are what the firmware loads; the four `ov-` files are
/// the overlays': the README and map that the firmware reads first, the screen's overlay and the one
/// that disables Bluetooth; `cmdline.txt` and `config.txt` name the slot; the last two are
/// qberrypi's own.
pub const SLOT_FILES: [&str; 11] = [
    "kernel8.img",
    "bcm2710-rpi-3-b-plus.dtb",
    "initramfs8",
    "ov-README",
    "ov-overlay_map.dtb",
    "ov-qb-piscreen.dtbo",
    "ov-disable-bt.dtbo",
    "cmdline.txt",
    "config.txt",
    "qberrypi.toml",
    "tls.pem",
];

/// The files of a slot that the firmware and the kernel boot from, apart from the initramfs.
///
/// An update that changes none of them leaves the boot path exactly as it was; their digest
/// (`boot_files_digest`) says so. The initramfs, which holds the build, and the slot's own
/// configuration and key are left out.
pub const BOOT_FILES: [&str; 8] = [
    "kernel8.img",
    "bcm2710-rpi-3-b-plus.dtb",
    "ov-README",
    "ov-overlay_map.dtb",
    "ov-qb-piscreen.dtbo",
    "ov-disable-bt.dtbo",
    "cmdline.txt",
    "config.txt",
];

/// One of the card's two slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Slot {
    /// The first slot, in `qberrypi-a/`.
    A,
    /// The second slot, in `qberrypi-b/`.
    B,
}

impl Slot {
    /// The other slot.
    pub fn other(self) -> Slot {
        match self {
            Slot::A => Slot::B,
            Slot::B => Slot::A,
        }
    }

    /// The slot's letter, `"a"` or `"b"`: what the command line, the marker, the manifest and
    /// the statistics call it.
    pub fn letter(self) -> &'static str {
        match self {
            Slot::A => "a",
            Slot::B => "b",
        }
    }

    /// The slot's folder on the boot partition, `"qberrypi-a"` or `"qberrypi-b"`.
    pub fn dir(self) -> &'static str {
        match self {
            Slot::A => "qberrypi-a",
            Slot::B => "qberrypi-b",
        }
    }

    /// The `os_prefix=` value that selects the slot, `"qberrypi-a/"` or `"qberrypi-b/"`.
    pub fn os_prefix(self) -> &'static str {
        match self {
            Slot::A => "qberrypi-a/",
            Slot::B => "qberrypi-b/",
        }
    }

    /// The command line argument that names the slot, `"qberrypi.slot=a"` or `"qberrypi.slot=b"`.
    pub fn cmdline_arg(self) -> &'static str {
        match self {
            Slot::A => "qberrypi.slot=a",
            Slot::B => "qberrypi.slot=b",
        }
    }

    /// The slot a letter names: `"a"` and `"b"` exactly, nothing else.
    pub fn from_letter(letter: &str) -> Option<Slot> {
        match letter {
            "a" => Some(Slot::A),
            "b" => Some(Slot::B),
            _ => None,
        }
    }

    /// The slot a kernel command line names, or `None` if it has no `qberrypi.slot=` argument.
    ///
    /// The command line is split at ASCII whitespace; no quoting is interpreted. It is an error
    /// for the argument to be there twice (whatever the values), to have no value, or to have
    /// any value but `a` or `b`. The error says which and quotes nothing from the line.
    pub fn from_cmdline(cmdline: &str) -> Result<Option<Slot>, String> {
        match slot_arg(cmdline.as_bytes()) {
            Ok(found) => Ok(found.map(|(slot, _)| slot)),
            Err(reason) => Err(reason.to_string()),
        }
    }
}

impl fmt::Display for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.letter())
    }
}

/// Finds the `qberrypi.slot=` argument in a command line: the slot it names and where in the
/// text its value lies.
///
/// `None` if there is no such argument. An argument with no `=`, a value that is not `a` or `b`,
/// and a second argument are errors.
fn slot_arg(cmdline: &[u8]) -> Result<Option<(Slot, Range<usize>)>, &'static str> {
    let mut found = None;
    let mut at = 0;
    while at < cmdline.len() {
        if cmdline[at].is_ascii_whitespace() {
            at += 1;
            continue;
        }
        let start = at;
        while at < cmdline.len() && !cmdline[at].is_ascii_whitespace() {
            at += 1;
        }
        let token = &cmdline[start..at];
        let value_start = if token == CMDLINE_KEY {
            at
        } else if token.starts_with(CMDLINE_KEY) && token[CMDLINE_KEY.len()] == b'=' {
            start + CMDLINE_KEY.len() + 1
        } else {
            continue;
        };
        if found.is_some() {
            return Err("qberrypi.slot is given more than once");
        }
        let slot = match &cmdline[value_start..at] {
            b"a" => Slot::A,
            b"b" => Slot::B,
            _ => return Err("qberrypi.slot is neither a nor b"),
        };
        found = Some((slot, value_start..at));
    }
    Ok(found)
}

/// Finds the value of the one uncommented `os_prefix=` line of a `config.txt`, as a range of
/// the text.
///
/// The line may be indented and may end in whitespace (a carriage return among it); the range
/// is of what lies between. A commented line is not one, and nor is a line of another setting
/// whose name ends in `os_prefix`. No such line, or more than one, is an error.
fn os_prefix_value(config: &[u8]) -> Result<Range<usize>, &'static str> {
    let mut found = None;
    let mut offset = 0;
    for line in config.split_inclusive(|&byte| byte == b'\n') {
        let start = offset;
        offset += line.len();
        let trimmed = line.trim_ascii();
        if !trimmed.starts_with(OS_PREFIX_KEY) {
            continue;
        }
        if found.is_some() {
            return Err("config.txt has more than one os_prefix line");
        }
        let lead = line.len() - line.trim_ascii_start().len();
        found = Some(start + lead + OS_PREFIX_KEY.len()..start + lead + trimmed.len());
    }
    found.ok_or("config.txt has no os_prefix line")
}

/// The slot that a `config.txt` selects.
///
/// The text must have exactly one uncommented `os_prefix=` line, and it must name `qberrypi-a/`
/// or `qberrypi-b/` and nothing more. Anything else is an error, in words that name no value
/// from the file.
pub fn selected_slot(config: &[u8]) -> Result<Slot, &'static str> {
    let value = os_prefix_value(config)?;
    match &config[value] {
        b"qberrypi-a/" => Ok(Slot::A),
        b"qberrypi-b/" => Ok(Slot::B),
        _ => Err("config.txt's os_prefix names no slot"),
    }
}

/// Checks that a slot's `config.txt` is fit to be copied over the root one.
///
/// It must not be empty (whitespace alone is empty), must not contain a NUL byte (what an
/// interrupted write on FAT can leave), and must select `slot` as [`selected_slot`] reads it.
pub fn check_slot_config(text: &[u8], slot: Slot) -> Result<(), &'static str> {
    if text.trim_ascii().is_empty() {
        return Err("config.txt is empty");
    }
    if text.contains(&0) {
        return Err("config.txt is not text");
    }
    if selected_slot(text)? != slot {
        return Err("config.txt selects the other slot");
    }
    Ok(())
}

/// Checks that a slot's `cmdline.txt` names `slot`.
///
/// It must be one line (one line ending at its end is fine), without a NUL byte, with exactly
/// one `qberrypi.slot=` argument, and that argument must name `slot`.
pub fn check_slot_cmdline(text: &[u8], slot: Slot) -> Result<(), &'static str> {
    if text.trim_ascii().is_empty() {
        return Err("cmdline.txt is empty");
    }
    if text.contains(&0) {
        return Err("cmdline.txt is not text");
    }
    let body = text.strip_suffix(b"\n").unwrap_or(text);
    let body = body.strip_suffix(b"\r").unwrap_or(body);
    if body.iter().any(|&byte| byte == b'\n' || byte == b'\r') {
        return Err("cmdline.txt has more than one line");
    }
    match slot_arg(body)? {
        None => Err("cmdline.txt has no qberrypi.slot argument"),
        Some((named, _)) if named != slot => Err("cmdline.txt names the other slot"),
        Some(_) => Ok(()),
    }
}

/// What `select` or `stage_tryboot` did, or why it changed nothing.
#[derive(Debug, PartialEq)]
pub enum Select {
    /// The file now holds the slot's `config.txt`.
    Selected,
    /// The file already held it, so nothing was written.
    AlreadySelected,
    /// The slot's `config.txt` is not fit to be copied, for the reason given; nothing was written.
    Refused(String),
}

/// Selects `slot` by copying `qberrypi-X/config.txt` over `config.txt`, so the next start is
/// that slot.
///
/// The slot's file is read and judged in full before `config.txt` is touched, and is itself
/// never written. It is refused, with nothing changed, when it is missing or fails
/// [`check_slot_config`] for `slot`; the reason names the file. The copy is written in place by
/// [`overwrite_in_place`], as `bootpart::restore_pios_config` writes its own, and a `config.txt`
/// that is missing is made. When `config.txt` already holds the same bytes, nothing is written.
/// An error from reading either file or from the write is returned.
pub fn select(boot: &Path, slot: Slot) -> io::Result<Select> {
    copy_slot_config(boot, slot, ACTIVE_CONFIG)
}

/// Writes `tryboot.txt`, the file the firmware reads in `tryboot` mode, as a copy of
/// `qberrypi-X/config.txt`, so a start with `0 tryboot` is that slot.
///
/// Judged and written exactly as [`select`] does; `Selected` here means that `tryboot.txt` was
/// written. The file is never removed: the firmware reads it only after a `tryboot` restart.
pub fn stage_tryboot(boot: &Path, slot: Slot) -> io::Result<Select> {
    copy_slot_config(boot, slot, TRYBOOT_FILE)
}

/// The copy that `select` and `stage_tryboot` share.
fn copy_slot_config(boot: &Path, slot: Slot, target: &str) -> io::Result<Select> {
    let source = match fs::read(boot.join(slot.dir()).join(ACTIVE_CONFIG)) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Ok(Select::Refused(format!(
                "{}/{ACTIVE_CONFIG} is missing",
                slot.dir()
            )));
        }
        Err(error) => return Err(error),
    };
    if let Err(reason) = check_slot_config(&source, slot) {
        return Ok(Select::Refused(format!("{}/{reason}", slot.dir())));
    }

    let target = boot.join(target);
    match fs::read(&target) {
        Ok(current) if current == source => return Ok(Select::AlreadySelected),
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    overwrite_in_place(&target, &source)?;
    Ok(Select::Selected)
}

/// How an update's trial was started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// By the firmware's `tryboot`: `tryboot.txt` selected the trial slot for one boot.
    Tryboot,
    /// By the software trial: `config.txt` itself selects the trial slot until it is selected back.
    Software,
}

impl Mode {
    /// The mode's word in the marker, `"tryboot"` or `"software"`.
    pub fn word(self) -> &'static str {
        match self {
            Mode::Tryboot => "tryboot",
            Mode::Software => "software",
        }
    }

    /// The mode a word in the marker names: `"tryboot"` and `"software"` exactly.
    pub fn from_word(word: &str) -> Option<Mode> {
        match word {
            "tryboot" => Some(Mode::Tryboot),
            "software" => Some(Mode::Software),
            _ => None,
        }
    }
}

/// The record of a trial in `qberrypi-trial.txt`.
///
/// The file is lines of `key=value`: `slot`, `from`, `build` and `mode` in that order, as the
/// updater writes them, then lines that init appends, one at a time: a bare `started`, and
/// `failed=<reason>`. Lines it does not know are ignored when it is read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Marker {
    /// The slot on trial.
    pub slot: Slot,
    /// The slot the trial came from, and the one a rollback boots; never the same as `slot`.
    pub from: Slot,
    /// The build time of the build on trial, in Unix seconds.
    pub build: u64,
    /// How the trial was started.
    pub mode: Mode,
    /// Whether the trial build's init has started and found its marker.
    pub started: bool,
    /// Why the trial build gave up, if it did: one line, at most [`FAILED_CAP`] bytes.
    pub failed: Option<String>,
}

impl Marker {
    /// The marker's text as the updater writes it: the four keys, then `started` and `failed=`
    /// if set. A `failed` reason is made one line of at most [`FAILED_CAP`] bytes with its
    /// control characters dropped, as [`failed_line`] makes it.
    pub fn render(&self) -> String {
        let mut text = format!(
            "slot={}\nfrom={}\nbuild={}\nmode={}\n",
            self.slot.letter(),
            self.from.letter(),
            self.build,
            self.mode.word()
        );
        if self.started {
            text.push_str(STARTED);
            text.push('\n');
        }
        if let Some(reason) = &self.failed {
            text.push_str(&failed_line(reason));
            text.push('\n');
        }
        text
    }

    /// Reads a marker from its text.
    ///
    /// Lines of keys it does not know are ignored, and so is any line without an `=` but
    /// `started`. A missing `slot`, `from`, `build` or `mode`, a value that is not valid for
    /// its key (a slot is `a` or `b`, a build is digits only and fits a `u64`), a key given twice
    /// and `slot` equal to `from` are errors. Of several `failed=` lines the first is taken, and
    /// its reason is cleaned as [`failed_line`] cleans it. An error quotes nothing from the text.
    pub fn parse(text: &str) -> Result<Marker, String> {
        let (mut slot, mut from, mut build, mut mode) = (None, None, None, None);
        let (mut started, mut failed) = (false, None);
        for line in text.lines() {
            let line = line.trim_ascii();
            if line == STARTED {
                started = true;
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            match key {
                "slot" => once(&mut slot, Slot::from_letter(value), key)?,
                "from" => once(&mut from, Slot::from_letter(value), key)?,
                "build" => once(&mut build, parse_build(value), key)?,
                "mode" => once(&mut mode, Mode::from_word(value), key)?,
                "failed" if failed.is_none() => failed = Some(clean_reason(value)),
                _ => {}
            }
        }
        let slot = slot.ok_or("the marker has no slot line")?;
        let from = from.ok_or("the marker has no from line")?;
        if slot == from {
            return Err("the marker's slot and from are the same".to_string());
        }
        Ok(Marker {
            slot,
            from,
            build: build.ok_or("the marker has no build line")?,
            mode: mode.ok_or("the marker has no mode line")?,
            started,
            failed,
        })
    }

    /// What a rollback to this marker's `from` slot says happened, in the words
    /// `/api/v1/stats` and the log use.
    ///
    /// The reason the trial build gave up, if it wrote one; else `"the trial build never
    /// started"` if it never appended `started` (the firmware ignored the flag, or the kernel
    /// never reached init); else `"the trial build restarted before it confirmed"`.
    pub fn rollback_detail(&self) -> String {
        match (&self.failed, self.started) {
            (Some(reason), _) => reason.clone(),
            (None, false) => "the trial build never started".to_string(),
            (None, true) => "the trial build restarted before it confirmed".to_string(),
        }
    }
}

/// Stores a marker's value once: a missing or invalid value, or a key given twice, is an error.
fn once<T>(cell: &mut Option<T>, value: Option<T>, key: &str) -> Result<(), String> {
    if cell.is_some() {
        return Err(format!("the marker gives {key} twice"));
    }
    *cell = Some(value.ok_or_else(|| format!("the marker's {key} is not valid"))?);
    Ok(())
}

/// A build time as the marker holds it: digits only, which `parse` alone would not insist on.
fn parse_build(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

/// The `failed=` line (without its line ending) that tells the marker why a trial gave up.
///
/// The reason is made one line of at most [`FAILED_CAP`] bytes, cut at a character boundary,
/// with its control characters (a line ending among them) dropped and its ends trimmed. Pass
/// the result to [`append_line`].
pub fn failed_line(reason: &str) -> String {
    format!("failed={}", clean_reason(reason))
}

/// A reason as `failed_line` makes it, without the key.
fn clean_reason(reason: &str) -> String {
    let mut clean = String::new();
    for character in reason.chars().filter(|character| !character.is_control()) {
        if clean.len() + character.len_utf8() > FAILED_CAP {
            break;
        }
        clean.push(character);
    }
    clean.trim().to_string()
}

/// Reads the marker.
///
/// `Ok(None)` if there is none. `Ok(Some(Err(_)))` if there is one that cannot be parsed as a
/// marker: not text, longer than [`MARKER_CAP`] (no more than the cap and one byte of it is
/// read), or failing [`Marker::parse`]; the message is for the log. An error from opening or
/// reading it otherwise (a directory in its place, a card error) is returned as it is, and says
/// nothing of the content: a boot must not treat it as an unparsable marker (see
/// `init::apply_boot_rules`).
pub fn read_marker(boot: &Path) -> io::Result<Option<Result<Marker, String>>> {
    let file = match File::open(boot.join(MARKER_FILE)) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::new();
    file.take(MARKER_CAP + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MARKER_CAP {
        return Ok(Some(Err(format!(
            "{MARKER_FILE} is larger than {MARKER_CAP} bytes"
        ))));
    }
    Ok(Some(match String::from_utf8(bytes) {
        Ok(text) => Marker::parse(&text),
        Err(_) => Err(format!("{MARKER_FILE} is not text")),
    }))
}

/// Writes the marker as the updater leaves it, and waits until it is on the card, the entry of a
/// file that was just made included.
///
/// It is written in place by [`overwrite_in_place`]: a marker already there is overwritten and
/// the file made if missing. The updater writes it after the slot is written and proved, and
/// before the write that makes the next start boot the new slot (the selection in software mode),
/// so that a torn or missing marker never stands for a slot that was not completely written and a
/// selection of the new slot never has no marker. An error from any step is returned.
pub fn write_marker(boot: &Path, marker: &Marker) -> io::Result<()> {
    overwrite_in_place(&boot.join(MARKER_FILE), marker.render().as_bytes())?;
    File::open(boot)?.sync_all()
}

/// Adds one line to the end of the marker and waits until it is on the card.
///
/// The marker must exist: the file is never made here, and a missing one is a `NotFound`
/// error. A line that holds a line ending or a NUL byte is an `InvalidInput` error with
/// nothing written. If the marker's last byte is not a line ending (a write that was cut off),
/// one is added first, so the new line is never joined to the old.
pub fn append_line(boot: &Path, line: &str) -> io::Result<()> {
    if line
        .bytes()
        .any(|byte| byte == b'\n' || byte == b'\r' || byte == 0)
    {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "a marker line has a line ending or a NUL byte",
        ));
    }
    let mut file = File::options()
        .read(true)
        .append(true)
        .open(boot.join(MARKER_FILE))?;
    let length = file.metadata()?.len();
    let mut text = Vec::with_capacity(line.len() + 2);
    if length > 0 {
        let mut last = [0u8];
        file.read_exact_at(&mut last, length - 1)?;
        if last[0] != b'\n' {
            text.push(b'\n');
        }
    }
    text.extend_from_slice(line.as_bytes());
    text.push(b'\n');
    // One write, so that the line is not torn by anything of ours.
    file.write_all(&text)?;
    file.sync_all()
}

/// Deletes the marker and waits until the deletion is on the card.
///
/// A marker that is already gone is not an error, so the call can be repeated.
pub fn remove_marker(boot: &Path) -> io::Result<()> {
    match fs::remove_file(boot.join(MARKER_FILE)) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    File::open(boot)?.sync_all()
}

/// What a boot does, given the rules of the design's table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootAction {
    /// No marker, and this slot is the one selected: run, writing nothing.
    Normal,
    /// No marker, but another slot is selected, so the firmware started this one from a
    /// `tryboot.txt` that has no marker: run, and warn.
    NormalWarnTryboot,
    /// This slot is on its first boot of a trial: append `started` to the marker and run on
    /// trial. When `select_from_first` is set (a software trial, where `config.txt` selects
    /// this slot) select the marker's `from` slot first, so a restart boots that one.
    Trial {
        /// The marker as it was read, before `started` is appended.
        marker: Marker,
        /// Whether to select `marker.from` in `config.txt` before appending `started`.
        select_from_first: bool,
    },
    /// A confirm selected this slot but was cut off before it deleted the marker: delete the
    /// marker and run, confirmed.
    ConfirmInterrupted,
    /// The trial already started once and is starting again, `config.txt` still selecting the
    /// slot it came from (the firmware chose `tryboot.txt` again): overwrite `tryboot.txt` with
    /// the `config.txt` of the slot the trial came from (so that even a firmware that keeps
    /// choosing it boots that slot), then restart plainly, at once.
    SecondTrialBoot,
    /// A trial of the other slot failed and this slot, which it came from, is running again:
    /// report the rollback (see [`Marker::rollback_detail`]), delete the marker and run.
    RolledBack {
        /// The marker of the trial that failed.
        marker: Marker,
    },
    /// The marker was read but is unparsable (not text, over its cap, or not what the updater
    /// writes), for the reason given: log an error, delete the marker and run. A marker that
    /// could not be read at all (an I/O error) is no such thing, and never reaches [`decide`]: the
    /// boot rules leave it where it is.
    BadMarker(String),
}

/// Decides what a boot does.
///
/// `me` is the slot running (from the command line), `selected` the slot the root `config.txt`
/// selects, and `marker` what [`read_marker`] found inside its `Some`. The rows are the design's
/// table; the marker's `mode` does not enter into them, since `selected` already tells the two
/// kinds of trial apart:
///
/// | marker | selected | `started` | action |
/// |---|---|---|---|
/// | none | any | | `Normal` (`NormalWarnTryboot` if `selected` is not `me`) |
/// | names `me` | its `from` | no | `Trial`, `select_from_first: false` |
/// | names `me` | `me` | no | `Trial`, `select_from_first: true` |
/// | names `me` | `me` | yes | `ConfirmInterrupted` |
/// | names `me` | its `from` | yes | `SecondTrialBoot` |
/// | names the other slot | any | any | `RolledBack` |
/// | unparsable | any | | `BadMarker` |
pub fn decide(me: Slot, selected: Slot, marker: Option<Result<Marker, String>>) -> BootAction {
    let marker = match marker {
        None if selected == me => return BootAction::Normal,
        None => return BootAction::NormalWarnTryboot,
        Some(Err(reason)) => return BootAction::BadMarker(reason),
        Some(Ok(marker)) => marker,
    };
    if marker.slot != me {
        return BootAction::RolledBack { marker };
    }
    // A marker's `from` is never its `slot`, so `selected` is one of the two.
    match (selected == me, marker.started) {
        (false, false) => BootAction::Trial {
            marker,
            select_from_first: false,
        },
        (true, false) => BootAction::Trial {
            marker,
            select_from_first: true,
        },
        (true, true) => BootAction::ConfirmInterrupted,
        (false, true) => BootAction::SecondTrialBoot,
    }
}

/// The text of a boot file as the digest takes it: `config.txt` and `cmdline.txt` in the form
/// they have for slot a, the other files as they are.
///
/// In `config.txt` the value of the `os_prefix=` line is replaced by `qberrypi-a/`, and in
/// `cmdline.txt` the value of the `qberrypi.slot=` argument by `a`; nothing else changes, byte
/// for byte. A `config.txt` that does not select a slot, and a `cmdline.txt` without a slot
/// argument, are errors.
pub fn slot_a_form<'a>(name: &str, bytes: &'a [u8]) -> Result<Cow<'a, [u8]>, &'static str> {
    let (span, replacement): (Range<usize>, &[u8]) = match name {
        "config.txt" => {
            selected_slot(bytes)?;
            (os_prefix_value(bytes)?, Slot::A.os_prefix().as_bytes())
        }
        "cmdline.txt" => match slot_arg(bytes)? {
            Some((_, span)) => (span, Slot::A.letter().as_bytes()),
            None => return Err("cmdline.txt has no qberrypi.slot argument"),
        },
        _ => return Ok(Cow::Borrowed(bytes)),
    };
    let mut form = Vec::with_capacity(bytes.len() + replacement.len());
    form.extend_from_slice(&bytes[..span.start]);
    form.extend_from_slice(replacement);
    form.extend_from_slice(&bytes[span.end..]);
    Ok(Cow::Owned(form))
}

/// The digest of a build's boot files: the same for the a and the b form of one build, and
/// different when any boot file differs.
///
/// It is the SHA-256, in lower-case hex, of the lines `"<sha256 hex>  <name>\n"` for the names of
/// [`BOOT_FILES`] sorted by name, with `config.txt` and `cmdline.txt` taken in the form that
/// [`slot_a_form`] gives. Entries whose names are not in `BOOT_FILES` are ignored, in any order.
/// It is an error for a name of `BOOT_FILES` to be missing or to come twice, or for either of the
/// two slot files to be unfit for `slot_a_form`; the message names the file.
pub fn boot_files_digest<'a>(
    entries: impl IntoIterator<Item = (&'a str, &'a [u8])>,
) -> Result<String, String> {
    let mut hashes = Vec::new();
    for (name, bytes) in entries {
        if !BOOT_FILES.contains(&name) {
            continue;
        }
        let form = slot_a_form(name, bytes).map_err(|reason| format!("{name}: {reason}"))?;
        hashes.push((name, hex(&Sha256::digest(&form))));
    }
    digest_of_hashes(hashes)
}

/// The same digest as [`boot_files_digest`], from each boot file's SHA-256 instead of its bytes,
/// for a caller that hashes files as they stream past.
///
/// Each hash is 64 lower-case hex digits; for `config.txt` and `cmdline.txt` it must be the hash
/// of the file's [`slot_a_form`], not of the file. The same names are ignored, missing or
/// doubled, and a hash that is not 64 lower-case hex digits is an error naming the file.
pub fn boot_files_digest_of_hashes<'a>(
    entries: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<String, String> {
    let mut hashes = Vec::new();
    for (name, hash) in entries {
        if !BOOT_FILES.contains(&name) {
            continue;
        }
        let valid =
            hash.len() == 64 && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if !valid {
            return Err(format!("{name}: its hash is not 64 lower-case hex digits"));
        }
        hashes.push((name, hash.to_string()));
    }
    digest_of_hashes(hashes)
}

/// Combines the hashes of the boot files, which hold each name of `BOOT_FILES` once, into the digest.
fn digest_of_hashes(mut hashes: Vec<(&str, String)>) -> Result<String, String> {
    hashes.sort_by_key(|&(name, _)| name);
    if let Some(pair) = hashes.windows(2).find(|pair| pair[0].0 == pair[1].0) {
        return Err(format!("{} is given twice", pair[0].0));
    }
    if let Some(missing) = BOOT_FILES
        .iter()
        .copied()
        .find(|name| !hashes.iter().any(|(given, _)| given == name))
    {
        return Err(format!("{missing} is missing"));
    }
    let mut lines = String::new();
    for (name, hash) in &hashes {
        lines.push_str(&format!("{hash}  {name}\n"));
    }
    Ok(hex(&Sha256::digest(lines.as_bytes())))
}

/// Lower-case hex of bytes.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut text, byte| {
        // Writing to a `String` cannot fail.
        let _ = write!(text, "{byte:02x}");
        text
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::fs::MetadataExt;
    use std::time::{Duration, SystemTime};

    const SLOT_A_CONFIG: &str =
        "# a slot\narm_64bit=1\nos_prefix=qberrypi-a/\nkernel=kernel8.img\n";
    const SLOT_B_CONFIG: &str =
        "# a slot\narm_64bit=1\nos_prefix=qberrypi-b/\nkernel=kernel8.img\n";

    fn read(dir: &Path, name: &str) -> String {
        fs::read_to_string(dir.join(name)).unwrap()
    }

    fn write(dir: &Path, name: &str, bytes: impl AsRef<[u8]>) {
        fs::write(dir.join(name), bytes).unwrap();
    }

    /// Gives a file a modification time far in the past and returns that time.
    fn backdate(path: &Path) -> SystemTime {
        let long_ago = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        let file = File::options().write(true).open(path).unwrap();
        file.set_modified(long_ago).unwrap();
        long_ago
    }

    fn modified(path: &Path) -> SystemTime {
        fs::metadata(path).unwrap().modified().unwrap()
    }

    /// A boot partition with both slots' configurations and the root one selecting `a`.
    fn card() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        fs::create_dir(d.join("qberrypi-a")).unwrap();
        fs::create_dir(d.join("qberrypi-b")).unwrap();
        write(d, "qberrypi-a/config.txt", SLOT_A_CONFIG);
        write(d, "qberrypi-b/config.txt", SLOT_B_CONFIG);
        write(d, "config.txt", SLOT_A_CONFIG);
        tmp
    }

    fn marker(slot: Slot, started: bool) -> Marker {
        Marker {
            slot,
            from: slot.other(),
            build: 1_794_470_000,
            mode: Mode::Tryboot,
            started,
            failed: None,
        }
    }

    #[test]
    fn a_slot_knows_its_other_its_letter_its_folder_its_prefix_and_its_argument() {
        assert_eq!(Slot::A.other(), Slot::B);
        assert_eq!(Slot::B.other(), Slot::A);
        assert_eq!(Slot::A.letter(), "a");
        assert_eq!(Slot::B.letter(), "b");
        assert_eq!(Slot::A.dir(), "qberrypi-a");
        assert_eq!(Slot::B.dir(), "qberrypi-b");
        assert_eq!(Slot::A.os_prefix(), "qberrypi-a/");
        assert_eq!(Slot::B.os_prefix(), "qberrypi-b/");
        assert_eq!(Slot::A.cmdline_arg(), "qberrypi.slot=a");
        assert_eq!(Slot::B.cmdline_arg(), "qberrypi.slot=b");
        assert_eq!(Slot::B.to_string(), "b");
        assert_eq!(Slot::from_letter("a"), Some(Slot::A));
        assert_eq!(Slot::from_letter("b"), Some(Slot::B));
        for not_a_letter in ["", "A", "c", "ab", " a"] {
            assert_eq!(Slot::from_letter(not_a_letter), None, "{not_a_letter:?}");
        }
    }

    #[test]
    fn the_slot_files_are_the_eleven_of_the_layout_and_the_boot_files_are_eight_of_them() {
        let mut names = SLOT_FILES.to_vec();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 11);
        assert_eq!(SLOT_FILES[0], "kernel8.img");
        assert_eq!(SLOT_FILES[10], "tls.pem");
        for name in BOOT_FILES {
            assert!(SLOT_FILES.contains(&name), "{name}");
        }
        assert_eq!(BOOT_FILES.len(), 8);
        // The overlays are boot files, all four: the firmware reads them before the kernel starts.
        for overlay in [
            "ov-README",
            "ov-overlay_map.dtb",
            "ov-qb-piscreen.dtbo",
            "ov-disable-bt.dtbo",
        ] {
            assert!(BOOT_FILES.contains(&overlay), "{overlay}");
        }
        for left_out in ["initramfs8", "qberrypi.toml", "tls.pem"] {
            assert!(!BOOT_FILES.contains(&left_out), "{left_out}");
        }
        // The two slot files that name the slot are among those digested.
        assert!(BOOT_FILES.contains(&"config.txt") && BOOT_FILES.contains(&"cmdline.txt"));
    }

    #[test]
    fn a_command_line_names_its_slot_or_none() {
        assert_eq!(Slot::from_cmdline("console=tty1 panic=5"), Ok(None));
        assert_eq!(Slot::from_cmdline(""), Ok(None));
        assert_eq!(Slot::from_cmdline("qberrypi.slot=a"), Ok(Some(Slot::A)));
        assert_eq!(
            Slot::from_cmdline("console=tty1 panic=5 loglevel=4 qberrypi.slot=b\n"),
            Ok(Some(Slot::B))
        );
        assert_eq!(
            Slot::from_cmdline("qberrypi.slot=a\tconsole=tty1  panic=5\n"),
            Ok(Some(Slot::A))
        );
    }

    #[test]
    fn a_command_line_with_a_bad_or_a_second_slot_argument_is_an_error() {
        for bad in [
            "qberrypi.slot=c",
            "qberrypi.slot=",
            "qberrypi.slot",
            "qberrypi.slot=A",
            "qberrypi.slot=ab",
            "qberrypi.slot=a,b",
            "qberrypi.slot=a qberrypi.slot=a",
            "qberrypi.slot=a qberrypi.slot=b",
            "qberrypi.slot=b panic=5 qberrypi.slot=b",
        ] {
            assert!(Slot::from_cmdline(bad).is_err(), "{bad:?}");
        }
        // The message says which, and quotes nothing from the line.
        let error = Slot::from_cmdline("qberrypi.slot=zzz").unwrap_err();
        assert!(!error.contains("zzz"), "{error}");
        assert!(error.contains("neither a nor b"), "{error}");
        let error = Slot::from_cmdline("qberrypi.slot=a qberrypi.slot=b").unwrap_err();
        assert!(error.contains("more than once"), "{error}");
    }

    #[test]
    fn other_arguments_that_look_like_the_slot_argument_are_not_it() {
        for other in [
            "xqberrypi.slot=b",
            "qberrypi.slots=b",
            "qberrypi.slotted",
            "my.qberrypi.slot=b",
            "qberrypi_slot=b",
        ] {
            assert_eq!(Slot::from_cmdline(other), Ok(None), "{other:?}");
        }
    }

    #[test]
    fn a_config_selects_the_slot_its_one_os_prefix_names() {
        assert_eq!(selected_slot(SLOT_A_CONFIG.as_bytes()), Ok(Slot::A));
        assert_eq!(selected_slot(SLOT_B_CONFIG.as_bytes()), Ok(Slot::B));
        for (case, config) in [
            ("indented", "arm_64bit=1\n \tos_prefix=qberrypi-b/\n"),
            (
                "carriage returns",
                "arm_64bit=1\r\nos_prefix=qberrypi-b/\r\n",
            ),
            ("no line ending", "os_prefix=qberrypi-b/"),
            ("trailing blanks", "os_prefix=qberrypi-b/  \n"),
            (
                "commented lines are not counted",
                "#os_prefix=qberrypi-a/\n  # os_prefix=qberrypi-a/\nos_prefix=qberrypi-b/\n",
            ),
            (
                "other settings that end in the name are not counted",
                "x_os_prefix=qberrypi-a/\nos_prefix=qberrypi-b/\n",
            ),
        ] {
            assert_eq!(selected_slot(config.as_bytes()), Ok(Slot::B), "{case}");
        }
    }

    #[test]
    fn a_config_that_selects_no_slot_or_two_is_an_error() {
        for (config, reason) in [
            ("", "config.txt has no os_prefix line"),
            ("arm_64bit=1\n", "config.txt has no os_prefix line"),
            (
                "#os_prefix=qberrypi-a/\n",
                "config.txt has no os_prefix line",
            ),
            (
                "os_prefix = qberrypi-a/\n",
                "config.txt has no os_prefix line",
            ),
            (
                "os_prefix=qberrypi-a/\nos_prefix=qberrypi-a/\n",
                "config.txt has more than one os_prefix line",
            ),
            (
                "os_prefix=qberrypi-a/\n  os_prefix=qberrypi-b/\n",
                "config.txt has more than one os_prefix line",
            ),
            (
                "os_prefix=qberrypi/\n",
                "config.txt's os_prefix names no slot",
            ),
            (
                "os_prefix=qberrypi-c/\n",
                "config.txt's os_prefix names no slot",
            ),
            (
                "os_prefix=qberrypi-a\n",
                "config.txt's os_prefix names no slot",
            ),
            (
                "os_prefix=qberrypi-a/x\n",
                "config.txt's os_prefix names no slot",
            ),
            (
                "os_prefix= qberrypi-a/\n",
                "config.txt's os_prefix names no slot",
            ),
            ("os_prefix=\n", "config.txt's os_prefix names no slot"),
            (
                "os_prefix=qberrypi-a/ # a\n",
                "config.txt's os_prefix names no slot",
            ),
            (
                "os_prefix=QBERRYPI-A/\n",
                "config.txt's os_prefix names no slot",
            ),
        ] {
            assert_eq!(selected_slot(config.as_bytes()), Err(reason), "{config:?}");
        }
    }

    #[test]
    fn a_slot_config_must_select_its_own_slot_and_be_text() {
        assert_eq!(check_slot_config(SLOT_A_CONFIG.as_bytes(), Slot::A), Ok(()));
        assert_eq!(check_slot_config(SLOT_B_CONFIG.as_bytes(), Slot::B), Ok(()));
        for (case, config, reason) in [
            (
                "the other slot",
                SLOT_B_CONFIG.as_bytes(),
                "config.txt selects the other slot",
            ),
            ("empty", b"", "config.txt is empty"),
            ("blank", b" \t\r\n\n  \n", "config.txt is empty"),
            (
                "a NUL",
                b"os_prefix=qberrypi-a/\n\0",
                "config.txt is not text",
            ),
            ("all NULs", &[0u8; 512], "config.txt is not text"),
            (
                "no selection",
                b"arm_64bit=1\n",
                "config.txt has no os_prefix line",
            ),
            (
                "two selections",
                b"os_prefix=qberrypi-a/\nos_prefix=qberrypi-a/\n",
                "config.txt has more than one os_prefix line",
            ),
        ] {
            assert_eq!(check_slot_config(config, Slot::A), Err(reason), "{case}");
        }
    }

    #[test]
    fn a_slot_cmdline_must_be_one_line_that_names_its_own_slot() {
        let ok = b"console=tty1 panic=5 loglevel=4 qberrypi.slot=a\n";
        assert_eq!(check_slot_cmdline(ok, Slot::A), Ok(()));
        assert_eq!(check_slot_cmdline(b"qberrypi.slot=a", Slot::A), Ok(()));
        assert_eq!(
            check_slot_cmdline(b"x qberrypi.slot=b\r\n", Slot::B),
            Ok(())
        );
        for (case, text, reason) in [
            (
                "the other slot",
                &b"console=tty1 qberrypi.slot=b\n"[..],
                "cmdline.txt names the other slot",
            ),
            (
                "none",
                b"console=tty1\n",
                "cmdline.txt has no qberrypi.slot argument",
            ),
            ("empty", b"", "cmdline.txt is empty"),
            ("blank", b" \n", "cmdline.txt is empty"),
            (
                "two lines",
                b"console=tty1\nqberrypi.slot=a\n",
                "cmdline.txt has more than one line",
            ),
            (
                "a blank line after",
                b"qberrypi.slot=a\n\n",
                "cmdline.txt has more than one line",
            ),
            (
                "a carriage return inside",
                b"a\rqberrypi.slot=a\n",
                "cmdline.txt has more than one line",
            ),
            ("a NUL", b"qberrypi.slot=a\0\n", "cmdline.txt is not text"),
            (
                "twice",
                b"qberrypi.slot=a qberrypi.slot=a\n",
                "qberrypi.slot is given more than once",
            ),
            (
                "a bad value",
                b"qberrypi.slot=x\n",
                "qberrypi.slot is neither a nor b",
            ),
        ] {
            assert_eq!(check_slot_cmdline(text, Slot::A), Err(reason), "{case}");
        }
    }

    #[test]
    fn selecting_a_slot_copies_its_config_over_the_root_one_in_place() {
        let tmp = card();
        let d = tmp.path();
        // A longer root config than the slot's: the tail must be cut off, in the same file.
        write(d, "config.txt", format!("{SLOT_A_CONFIG}# a long tail\n"));
        let inode = fs::metadata(d.join("config.txt")).unwrap().ino();

        assert_eq!(select(d, Slot::B).unwrap(), Select::Selected);

        assert_eq!(read(d, "config.txt"), SLOT_B_CONFIG);
        assert_eq!(fs::metadata(d.join("config.txt")).unwrap().ino(), inode);
        assert_eq!(read(d, "qberrypi-b/config.txt"), SLOT_B_CONFIG);
        assert_eq!(read(d, "qberrypi-a/config.txt"), SLOT_A_CONFIG);
        // And back.
        assert_eq!(select(d, Slot::A).unwrap(), Select::Selected);
        assert_eq!(read(d, "config.txt"), SLOT_A_CONFIG);
    }

    #[test]
    fn selecting_the_slot_already_selected_writes_nothing() {
        let tmp = card();
        let d = tmp.path();
        let long_ago = backdate(&d.join("config.txt"));
        assert_eq!(select(d, Slot::A).unwrap(), Select::AlreadySelected);
        assert_eq!(modified(&d.join("config.txt")), long_ago);
        assert_eq!(read(d, "config.txt"), SLOT_A_CONFIG);
    }

    #[test]
    fn selecting_makes_a_missing_root_config() {
        let tmp = card();
        let d = tmp.path();
        fs::remove_file(d.join("config.txt")).unwrap();
        assert_eq!(select(d, Slot::B).unwrap(), Select::Selected);
        assert_eq!(read(d, "config.txt"), SLOT_B_CONFIG);
    }

    #[test]
    fn selecting_refuses_a_slot_config_that_is_not_fit_and_changes_nothing() {
        let cases: [(&str, Option<&[u8]>, &str); 7] = [
            ("missing", None, "qberrypi-b/config.txt is missing"),
            ("empty", Some(b""), "qberrypi-b/config.txt is empty"),
            (
                "a NUL",
                Some(b"os_prefix=qberrypi-b/\n\0"),
                "qberrypi-b/config.txt is not text",
            ),
            (
                "the other slot",
                Some(b"os_prefix=qberrypi-a/\n"),
                "qberrypi-b/config.txt selects the other slot",
            ),
            (
                "the old layout",
                Some(b"os_prefix=qberrypi/\n"),
                "qberrypi-b/config.txt's os_prefix names no slot",
            ),
            (
                "two selections",
                Some(b"os_prefix=qberrypi-b/\nos_prefix=qberrypi-b/\n"),
                "qberrypi-b/config.txt has more than one os_prefix line",
            ),
            (
                "no selection",
                Some(b"arm_64bit=1\n"),
                "qberrypi-b/config.txt has no os_prefix line",
            ),
        ];
        for (case, source, reason) in cases {
            let tmp = card();
            let d = tmp.path();
            match source {
                Some(bytes) => write(d, "qberrypi-b/config.txt", bytes),
                None => fs::remove_file(d.join("qberrypi-b/config.txt")).unwrap(),
            }
            let long_ago = backdate(&d.join("config.txt"));
            assert_eq!(
                select(d, Slot::B).unwrap(),
                Select::Refused(reason.to_string()),
                "{case}"
            );
            assert_eq!(read(d, "config.txt"), SLOT_A_CONFIG, "{case}");
            assert_eq!(modified(&d.join("config.txt")), long_ago, "{case}");
            assert!(!d.join("tryboot.txt").exists());
        }
    }

    #[test]
    fn selecting_with_an_unreadable_source_is_an_error_and_changes_nothing() {
        let tmp = card();
        let d = tmp.path();
        // A directory where the slot's config should be can be neither read nor copied.
        fs::remove_file(d.join("qberrypi-b/config.txt")).unwrap();
        fs::create_dir(d.join("qberrypi-b/config.txt")).unwrap();
        assert!(select(d, Slot::B).is_err());
        assert_eq!(read(d, "config.txt"), SLOT_A_CONFIG);
    }

    #[test]
    fn staging_tryboot_writes_tryboot_txt_and_leaves_config_alone() {
        let tmp = card();
        let d = tmp.path();
        let long_ago = backdate(&d.join("config.txt"));

        assert_eq!(stage_tryboot(d, Slot::B).unwrap(), Select::Selected);
        assert_eq!(read(d, "tryboot.txt"), SLOT_B_CONFIG);
        assert_eq!(read(d, "config.txt"), SLOT_A_CONFIG);
        assert_eq!(modified(&d.join("config.txt")), long_ago);

        // Again: nothing to write. A stale, longer file is overwritten in place and cut.
        assert_eq!(stage_tryboot(d, Slot::B).unwrap(), Select::AlreadySelected);
        write(d, "tryboot.txt", format!("{SLOT_A_CONFIG}# a long tail\n"));
        assert_eq!(stage_tryboot(d, Slot::B).unwrap(), Select::Selected);
        assert_eq!(read(d, "tryboot.txt"), SLOT_B_CONFIG);
    }

    #[test]
    fn staging_tryboot_refuses_what_selecting_refuses() {
        let tmp = card();
        let d = tmp.path();
        write(d, "qberrypi-b/config.txt", SLOT_A_CONFIG);
        assert_eq!(
            stage_tryboot(d, Slot::B).unwrap(),
            Select::Refused("qberrypi-b/config.txt selects the other slot".to_string())
        );
        assert!(!d.join("tryboot.txt").exists());
    }

    #[test]
    fn a_marker_renders_as_the_updater_writes_it_and_reads_back() {
        let mut m = marker(Slot::B, false);
        assert_eq!(
            m.render(),
            "slot=b\nfrom=a\nbuild=1794470000\nmode=tryboot\n"
        );
        assert_eq!(Marker::parse(&m.render()), Ok(m.clone()));

        m.mode = Mode::Software;
        m.started = true;
        m.failed = Some("the supervisor gave up".to_string());
        assert_eq!(
            m.render(),
            "slot=b\nfrom=a\nbuild=1794470000\nmode=software\nstarted\nfailed=the supervisor gave up\n"
        );
        assert_eq!(Marker::parse(&m.render()), Ok(m));

        let last = Marker {
            build: u64::MAX,
            ..marker(Slot::A, true)
        };
        assert_eq!(Marker::parse(&last.render()), Ok(last));
    }

    #[test]
    fn a_marker_ignores_lines_it_does_not_know_and_line_ending_styles() {
        let text = "# a note\r\nslot=a\r\nfrom=b\r\nextra=1\r\nbuild=7\r\nmode=software\r\nstart\r\nstarted\r\n\r\nstarted=1\r\n";
        assert_eq!(
            Marker::parse(text),
            Ok(Marker {
                slot: Slot::A,
                from: Slot::B,
                build: 7,
                mode: Mode::Software,
                started: true,
                failed: None,
            })
        );
        // A `started` that was cut off in writing is not one.
        let torn = "slot=a\nfrom=b\nbuild=7\nmode=tryboot\nstar";
        assert!(!Marker::parse(torn).unwrap().started);
        // Order does not matter.
        let shuffled = "mode=tryboot\nbuild=7\nfrom=b\nslot=a\n";
        assert_eq!(Marker::parse(shuffled).unwrap().slot, Slot::A);
    }

    #[test]
    fn a_marker_with_a_missing_key_a_bad_value_or_a_repeat_is_an_error() {
        let whole = ["slot=b", "from=a", "build=5", "mode=tryboot"];
        for dropped in 0..whole.len() {
            let text: Vec<_> = whole
                .iter()
                .enumerate()
                .filter(|&(i, _)| i != dropped)
                .map(|(_, line)| *line)
                .collect();
            assert!(
                Marker::parse(&text.join("\n")).is_err(),
                "no {}",
                whole[dropped]
            );
        }
        for bad in [
            "slot=c\nfrom=a\nbuild=5\nmode=tryboot\n",
            "slot=b\nfrom=\nbuild=5\nmode=tryboot\n",
            "slot=b\nfrom=a\nbuild=-5\nmode=tryboot\n",
            "slot=b\nfrom=a\nbuild=+5\nmode=tryboot\n",
            "slot=b\nfrom=a\nbuild=\nmode=tryboot\n",
            "slot=b\nfrom=a\nbuild=5x\nmode=tryboot\n",
            "slot=b\nfrom=a\nbuild=18446744073709551616\nmode=tryboot\n",
            "slot=b\nfrom=a\nbuild=5\nmode=reboot\n",
            "slot=b\nfrom=a\nbuild=5\nmode=\n",
            "slot=b\nslot=b\nfrom=a\nbuild=5\nmode=tryboot\n",
            "slot=b\nfrom=a\nbuild=5\nbuild=6\nmode=tryboot\n",
            "slot=b\nfrom=a\nbuild=5\nmode=tryboot\nmode=tryboot\n",
            "",
            "garbage",
        ] {
            assert!(Marker::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_marker_whose_slot_is_its_from_is_an_error() {
        for slot in ["a", "b"] {
            let text = format!("slot={slot}\nfrom={slot}\nbuild=5\nmode=tryboot\n");
            let error = Marker::parse(&text).unwrap_err();
            assert!(error.contains("the same"), "{error}");
        }
    }

    #[test]
    fn a_marker_error_quotes_nothing_from_the_text() {
        let error = Marker::parse("slot=zzz\nfrom=a\nbuild=5\nmode=tryboot\n").unwrap_err();
        assert!(!error.contains("zzz"), "{error}");
        let error = Marker::parse("slot=b\nfrom=a\nbuild=yyy\nmode=tryboot\n").unwrap_err();
        assert!(!error.contains("yyy"), "{error}");
    }

    #[test]
    fn a_failed_reason_is_one_line_of_at_most_two_hundred_bytes_without_control_characters() {
        assert_eq!(failed_line("gave up"), "failed=gave up");
        assert_eq!(failed_line(" gave\n up\r\n\0\t "), "failed=gave up");
        assert_eq!(failed_line(""), "failed=");
        assert_eq!(
            failed_line(&"x".repeat(200)),
            format!("failed={}", "x".repeat(200))
        );
        assert_eq!(
            failed_line(&"x".repeat(900)),
            format!("failed={}", "x".repeat(200))
        );
        // Cut at a character boundary: 67 three-byte characters are 201 bytes.
        let reason = failed_line(&"€".repeat(67));
        assert_eq!(reason, format!("failed={}", "€".repeat(66)));
        assert_eq!(reason.len() - "failed=".len(), 198);
        // Dropping control characters comes before the cut: the reason keeps its full length.
        assert_eq!(
            failed_line(&format!("{}{}", "\n".repeat(300), "y".repeat(200))),
            format!("failed={}", "y".repeat(200))
        );
    }

    #[test]
    fn a_failed_reason_is_made_clean_on_the_way_in_and_on_the_way_out() {
        let mut m = marker(Slot::B, true);
        m.failed = Some("one\ntwo\0three".to_string());
        // Rendered clean, so the text is still one marker.
        let text = m.render();
        assert!(text.ends_with("failed=onetwothree\n"), "{text}");
        assert_eq!(
            Marker::parse(&text).unwrap().failed.as_deref(),
            Some("onetwothree")
        );
        // Read clean, from a marker some other writer made.
        let wild = format!(
            "slot=b\nfrom=a\nbuild=5\nmode=tryboot\nfailed=\u{7}{}\nfailed=second\n",
            "z".repeat(500)
        );
        assert_eq!(
            Marker::parse(&wild).unwrap().failed,
            Some("z".repeat(200)),
            "the first failed line, cleaned"
        );
        // A reason that is nothing but control characters is an empty one, still a failure.
        let empty = "slot=b\nfrom=a\nbuild=5\nmode=tryboot\nfailed=\u{1}\u{2}\n";
        assert_eq!(Marker::parse(empty).unwrap().failed, Some(String::new()));
    }

    #[test]
    fn a_rollback_says_why_in_the_designs_words() {
        let mut m = marker(Slot::B, false);
        assert_eq!(m.rollback_detail(), "the trial build never started");
        m.started = true;
        assert_eq!(
            m.rollback_detail(),
            "the trial build restarted before it confirmed"
        );
        m.failed = Some("no upstream answered in 600 s".to_string());
        assert_eq!(m.rollback_detail(), "no upstream answered in 600 s");
    }

    #[test]
    fn the_marker_is_read_from_the_boot_partition() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        assert_eq!(read_marker(d).unwrap(), None);
        let m = marker(Slot::B, false);
        write(d, MARKER_FILE, m.render());
        assert_eq!(read_marker(d).unwrap(), Some(Ok(m)));
    }

    #[test]
    fn an_unreadable_marker_is_reported_not_raised() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        for (case, bytes) in [
            ("empty", b"".to_vec()),
            ("no keys", b"slot=b\n".to_vec()),
            ("all NULs", vec![0u8; 512]),
            (
                "not UTF-8",
                b"slot=b\nfrom=a\nbuild=5\nmode=tryboot\n\xff\xfe\n".to_vec(),
            ),
        ] {
            write(d, MARKER_FILE, &bytes);
            let read = read_marker(d).unwrap();
            assert!(matches!(read, Some(Err(_))), "{case}: {read:?}");
        }
        let error = {
            write(
                d,
                MARKER_FILE,
                b"slot=b\nfrom=a\nbuild=5\nmode=tryboot\n\xff\n",
            );
            read_marker(d).unwrap().unwrap().unwrap_err()
        };
        assert!(error.contains("not text"), "{error}");
    }

    #[test]
    fn a_marker_over_the_cap_is_unreadable_and_one_at_the_cap_is_read() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let m = marker(Slot::B, false);
        let mut text = m.render();
        text.push_str(&"#".repeat(MARKER_CAP as usize - text.len()));
        assert_eq!(text.len() as u64, MARKER_CAP);
        write(d, MARKER_FILE, &text);
        assert_eq!(read_marker(d).unwrap(), Some(Ok(m)));

        text.push('#');
        write(d, MARKER_FILE, &text);
        let error = read_marker(d).unwrap().unwrap().unwrap_err();
        assert!(error.contains("4096"), "{error}");
    }

    #[test]
    fn a_marker_that_cannot_be_read_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        fs::create_dir(d.join(MARKER_FILE)).unwrap();
        assert!(read_marker(d).is_err());
    }

    #[test]
    fn writing_a_marker_replaces_an_old_one_in_place() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let mut long = marker(Slot::B, true);
        long.failed = Some("x".repeat(150));
        write_marker(d, &long).unwrap();
        let inode = fs::metadata(d.join(MARKER_FILE)).unwrap().ino();

        let short = marker(Slot::A, false);
        write_marker(d, &short).unwrap();
        assert_eq!(read(d, MARKER_FILE), short.render());
        assert_eq!(fs::metadata(d.join(MARKER_FILE)).unwrap().ino(), inode);
        assert_eq!(read_marker(d).unwrap(), Some(Ok(short)));
    }

    #[test]
    fn a_line_is_appended_to_the_marker_and_read_back() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let m = marker(Slot::B, false);
        write_marker(d, &m).unwrap();

        append_line(d, STARTED).unwrap();
        let started = read_marker(d).unwrap().unwrap().unwrap();
        assert_eq!(
            started,
            Marker {
                started: true,
                ..m.clone()
            }
        );

        append_line(d, &failed_line("gave up\nagain")).unwrap();
        let failed = read_marker(d).unwrap().unwrap().unwrap();
        assert_eq!(failed.failed.as_deref(), Some("gave upagain"));
        assert!(failed.started);
        assert_eq!(
            read(d, MARKER_FILE),
            format!("{}started\nfailed=gave upagain\n", m.render())
        );
    }

    #[test]
    fn appending_to_a_marker_cut_off_mid_line_does_not_join_the_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        write(d, MARKER_FILE, "slot=b\nfrom=a\nbuild=5\nmode=tryboot");
        append_line(d, STARTED).unwrap();
        let m = read_marker(d).unwrap().unwrap().unwrap();
        assert_eq!(m.mode, Mode::Tryboot);
        assert!(m.started);
    }

    #[test]
    fn appending_never_makes_the_marker_and_refuses_a_line_that_is_not_one() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let error = append_line(d, STARTED).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotFound);
        assert!(!d.join(MARKER_FILE).exists());

        let m = marker(Slot::B, false);
        write_marker(d, &m).unwrap();
        let long_ago = backdate(&d.join(MARKER_FILE));
        for bad in ["a\nb", "a\r", "a\0", "\n"] {
            let error = append_line(d, bad).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidInput, "{bad:?}");
        }
        assert_eq!(read(d, MARKER_FILE), m.render());
        assert_eq!(modified(&d.join(MARKER_FILE)), long_ago);
    }

    #[test]
    fn removing_the_marker_deletes_it_and_can_be_repeated() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        write_marker(d, &marker(Slot::B, false)).unwrap();
        remove_marker(d).unwrap();
        assert!(!d.join(MARKER_FILE).exists());
        assert_eq!(read_marker(d).unwrap(), None);
        remove_marker(d).unwrap();
        // A missing boot partition is an error, not a marker that is gone.
        assert!(remove_marker(&d.join("absent")).is_err());
    }

    /// Every row of the design's table, as a trial on slot b that came from slot a sees it.
    #[test]
    fn the_boot_rules_are_the_designs_table_row_by_row() {
        let on_trial = |started| marker(Slot::B, started);

        // No marker: a plain boot; a warning if the firmware started this slot from tryboot.txt.
        assert_eq!(decide(Slot::A, Slot::A, None), BootAction::Normal);
        assert_eq!(decide(Slot::B, Slot::B, None), BootAction::Normal);
        assert_eq!(
            decide(Slot::B, Slot::A, None),
            BootAction::NormalWarnTryboot
        );
        assert_eq!(
            decide(Slot::A, Slot::B, None),
            BootAction::NormalWarnTryboot
        );

        // Names me, config selects its `from`, not started: a firmware trial.
        assert_eq!(
            decide(Slot::B, Slot::A, Some(Ok(on_trial(false)))),
            BootAction::Trial {
                marker: on_trial(false),
                select_from_first: false
            }
        );
        // Names me, config selects me, not started: a software trial, which selects `from` first.
        assert_eq!(
            decide(Slot::B, Slot::B, Some(Ok(on_trial(false)))),
            BootAction::Trial {
                marker: on_trial(false),
                select_from_first: true
            }
        );
        // Names me, config selects me, started: a confirm that was cut off.
        assert_eq!(
            decide(Slot::B, Slot::B, Some(Ok(on_trial(true)))),
            BootAction::ConfirmInterrupted
        );
        // Names me, config selects its `from`, started: the trial's second boot.
        assert_eq!(
            decide(Slot::B, Slot::A, Some(Ok(on_trial(true)))),
            BootAction::SecondTrialBoot
        );

        // Names the other slot: a rollback, whatever is selected and however far the trial got.
        for selected in [Slot::A, Slot::B] {
            for started in [false, true] {
                let m = on_trial(started);
                assert_eq!(
                    decide(Slot::A, selected, Some(Ok(m.clone()))),
                    BootAction::RolledBack { marker: m },
                    "selected {selected}, started {started}"
                );
            }
        }

        // Unreadable: an error to log, whatever is selected.
        for me in [Slot::A, Slot::B] {
            for selected in [Slot::A, Slot::B] {
                assert_eq!(
                    decide(me, selected, Some(Err("bad".to_string()))),
                    BootAction::BadMarker("bad".to_string())
                );
            }
        }
    }

    #[test]
    fn the_boot_rules_are_the_same_for_a_trial_on_slot_a_and_for_either_mode() {
        for mode in [Mode::Tryboot, Mode::Software] {
            let m = Marker {
                mode,
                ..marker(Slot::A, false)
            };
            assert_eq!(
                decide(Slot::A, Slot::B, Some(Ok(m.clone()))),
                BootAction::Trial {
                    marker: m.clone(),
                    select_from_first: false
                }
            );
            assert_eq!(
                decide(Slot::A, Slot::A, Some(Ok(m.clone()))),
                BootAction::Trial {
                    marker: m.clone(),
                    select_from_first: true
                }
            );
            assert_eq!(
                decide(Slot::B, Slot::B, Some(Ok(m.clone()))),
                BootAction::RolledBack { marker: m }
            );
        }
    }

    /// The boot files of a pretend build, slot a's form of the two that name the slot.
    fn build(slot: Slot) -> Vec<(String, Vec<u8>)> {
        let config = format!(
            "# qberrypi\narm_64bit=1\nos_prefix={}\nkernel=kernel8.img\n",
            slot.os_prefix()
        );
        let cmdline = format!("console=tty1 panic=5 loglevel=4 {}\n", slot.cmdline_arg());
        vec![
            ("kernel8.img".to_string(), b"kernel".to_vec()),
            ("bcm2710-rpi-3-b-plus.dtb".to_string(), b"tree".to_vec()),
            ("initramfs8".to_string(), b"the build itself".to_vec()),
            ("ov-README".to_string(), b"readme".to_vec()),
            ("ov-overlay_map.dtb".to_string(), b"map".to_vec()),
            ("ov-qb-piscreen.dtbo".to_string(), b"screen".to_vec()),
            ("ov-disable-bt.dtbo".to_string(), b"no bluetooth".to_vec()),
            ("cmdline.txt".to_string(), cmdline.into_bytes()),
            ("config.txt".to_string(), config.into_bytes()),
            ("qberrypi.toml".to_string(), b"secrets".to_vec()),
            ("tls.pem".to_string(), b"a key".to_vec()),
        ]
    }

    fn digest(files: &[(String, Vec<u8>)]) -> Result<String, String> {
        boot_files_digest(files.iter().map(|(n, b)| (n.as_str(), b.as_slice())))
    }

    #[test]
    fn the_digest_is_a_hash_of_the_sorted_hashes_with_the_slot_files_in_their_slot_a_form() {
        // The format is what the receiver and the build both compute: pin it with sha256sum's
        // own output for the pretend build, worked out outside this crate.
        let files = build(Slot::A);
        let sums = |name: &str| {
            let bytes = &files.iter().find(|(n, _)| n == name).unwrap().1;
            hex(&Sha256::digest(bytes))
        };
        let mut names = BOOT_FILES.to_vec();
        names.sort_unstable();
        let lines: String = names
            .iter()
            .map(|n| format!("{}  {n}\n", sums(n)))
            .collect();
        assert_eq!(
            digest(&files).unwrap(),
            hex(&Sha256::digest(lines.as_bytes()))
        );
        assert_eq!(digest(&files).unwrap(), PRETEND_BUILD_DIGEST);
        assert_eq!(digest(&files).unwrap().len(), 64);
    }

    /// `sha256sum` of the lines of the pretend build, computed by the shell.
    const PRETEND_BUILD_DIGEST: &str =
        "631d87e4419212f079a24a3bfcf15f9c3d25db931da2e452522137f99be67f59";

    #[test]
    fn the_digest_is_the_same_for_the_a_and_the_b_form_of_one_build() {
        assert_eq!(
            digest(&build(Slot::A)).unwrap(),
            digest(&build(Slot::B)).unwrap()
        );
    }

    #[test]
    fn the_digest_ignores_the_files_that_are_not_boot_files_and_the_order() {
        let files = build(Slot::A);
        let reference = digest(&files).unwrap();
        let mut changed = files.clone();
        for (name, bytes) in &mut changed {
            if ["initramfs8", "qberrypi.toml", "tls.pem"].contains(&name.as_str()) {
                bytes.push(b'!');
            }
        }
        changed.push(("extra".to_string(), b"more".to_vec()));
        changed.reverse();
        assert_eq!(digest(&changed).unwrap(), reference);
        // Nor does it need them.
        let only_boot: Vec<_> = files
            .iter()
            .filter(|(n, _)| BOOT_FILES.contains(&n.as_str()))
            .cloned()
            .collect();
        assert_eq!(digest(&only_boot).unwrap(), reference);
    }

    #[test]
    fn the_digest_differs_when_any_boot_file_differs() {
        let reference = digest(&build(Slot::A)).unwrap();
        for target in BOOT_FILES {
            let mut files = build(Slot::A);
            files
                .iter_mut()
                .find(|(n, _)| n == target)
                .unwrap()
                .1
                .push(b'#');
            assert_ne!(digest(&files).unwrap(), reference, "{target}");
        }
        // A change to the part of the slot files that is not the slot's name counts.
        let mut files = build(Slot::A);
        files
            .iter_mut()
            .find(|(n, _)| n == "cmdline.txt")
            .unwrap()
            .1 = b"console=ttyS0 qberrypi.slot=a\n".to_vec();
        assert_ne!(digest(&files).unwrap(), reference);
        let mut files = build(Slot::B);
        files.iter_mut().find(|(n, _)| n == "config.txt").unwrap().1 =
            b"arm_64bit=1\nos_prefix=qberrypi-b/\nkernel=other.img\n".to_vec();
        assert_ne!(digest(&files).unwrap(), reference);
        // One byte of a boot file's content moves between two files: the digest is not a
        // hash of the concatenation.
        let mut files = build(Slot::A);
        files.iter_mut().find(|(n, _)| n == "ov-README").unwrap().1 = b"readm".to_vec();
        files
            .iter_mut()
            .find(|(n, _)| n == "ov-overlay_map.dtb")
            .unwrap()
            .1 = b"emap".to_vec();
        assert_ne!(digest(&files).unwrap(), reference);
    }

    #[test]
    fn the_digest_is_an_error_naming_a_missing_or_doubled_boot_file() {
        for missing in BOOT_FILES {
            let files: Vec<_> = build(Slot::A)
                .into_iter()
                .filter(|(n, _)| n != missing)
                .collect();
            let error = digest(&files).unwrap_err();
            assert_eq!(error, format!("{missing} is missing"));
        }
        let mut files = build(Slot::A);
        files.push(("kernel8.img".to_string(), b"kernel".to_vec()));
        assert_eq!(digest(&files).unwrap_err(), "kernel8.img is given twice");
        assert_eq!(digest(&[]).unwrap_err(), "kernel8.img is missing");
    }

    #[test]
    fn the_digest_is_an_error_for_slot_files_that_name_no_slot() {
        let mut files = build(Slot::A);
        files.iter_mut().find(|(n, _)| n == "config.txt").unwrap().1 = b"arm_64bit=1\n".to_vec();
        assert_eq!(
            digest(&files).unwrap_err(),
            "config.txt: config.txt has no os_prefix line"
        );
        let mut files = build(Slot::A);
        files
            .iter_mut()
            .find(|(n, _)| n == "cmdline.txt")
            .unwrap()
            .1 = b"console=tty1\n".to_vec();
        assert_eq!(
            digest(&files).unwrap_err(),
            "cmdline.txt: cmdline.txt has no qberrypi.slot argument"
        );
        let mut files = build(Slot::A);
        files
            .iter_mut()
            .find(|(n, _)| n == "cmdline.txt")
            .unwrap()
            .1 = b"qberrypi.slot=a qberrypi.slot=b\n".to_vec();
        assert!(digest(&files).is_err());
    }

    #[test]
    fn the_slot_a_form_changes_only_the_slot_names_byte_for_byte() {
        let config = b"  os_prefix=qberrypi-b/ \r\nx=1\r\n";
        assert_eq!(
            slot_a_form("config.txt", config).unwrap().as_ref(),
            b"  os_prefix=qberrypi-a/ \r\nx=1\r\n"
        );
        let cmdline = b"qberrypi.slot=b\tconsole=tty1  panic=5\n";
        assert_eq!(
            slot_a_form("cmdline.txt", cmdline).unwrap().as_ref(),
            b"qberrypi.slot=a\tconsole=tty1  panic=5\n"
        );
        // Slot a's form of slot a's file is the file itself, and other files are untouched.
        let a = b"os_prefix=qberrypi-a/";
        assert_eq!(slot_a_form("config.txt", a).unwrap().as_ref(), a);
        assert!(matches!(
            slot_a_form("kernel8.img", b"\0x"),
            Ok(Cow::Borrowed(_))
        ));
        // A commented prefix in front of the real one is left as it is.
        let config = b"#os_prefix=qberrypi-b/\nos_prefix=qberrypi-b/\n";
        assert_eq!(
            slot_a_form("config.txt", config).unwrap().as_ref(),
            b"#os_prefix=qberrypi-b/\nos_prefix=qberrypi-a/\n"
        );
    }

    #[test]
    fn the_digest_from_hashes_is_the_digest_from_the_files() {
        let files = build(Slot::B);
        let hashes: Vec<(String, String)> = files
            .iter()
            .map(|(name, bytes)| {
                let form = slot_a_form(name, bytes).unwrap();
                (name.clone(), hex(&Sha256::digest(&form)))
            })
            .collect();
        let from_hashes =
            boot_files_digest_of_hashes(hashes.iter().map(|(n, h)| (n.as_str(), h.as_str())));
        assert_eq!(from_hashes, digest(&files));
        assert_eq!(from_hashes.unwrap(), PRETEND_BUILD_DIGEST);
    }

    #[test]
    fn the_digest_from_hashes_refuses_a_hash_that_is_not_lower_case_hex_and_missing_names() {
        let good = "ab".repeat(32);
        let all = |hash: &str| -> Vec<(String, String)> {
            BOOT_FILES
                .iter()
                .map(|n| (n.to_string(), hash.to_string()))
                .collect()
        };
        let run = |entries: &[(String, String)]| {
            boot_files_digest_of_hashes(entries.iter().map(|(n, h)| (n.as_str(), h.as_str())))
        };
        assert!(run(&all(&good)).is_ok());
        for bad in [
            "ab".repeat(31),
            "ab".repeat(33),
            "AB".repeat(32),
            "zz".repeat(32),
            String::new(),
        ] {
            let error = run(&all(&bad)).unwrap_err();
            assert!(error.contains("64 lower-case hex digits"), "{bad}: {error}");
        }
        let mut short = all(&good);
        short.pop();
        assert_eq!(run(&short).unwrap_err(), "config.txt is missing");
        let mut twice = all(&good);
        twice.push(("kernel8.img".to_string(), good));
        assert_eq!(run(&twice).unwrap_err(), "kernel8.img is given twice");
    }
}
