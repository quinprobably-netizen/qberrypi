//! `cargo xtask update`: sends this build to the Pi over the network and says whether the Pi kept
//! it.
//!
//! The Pi runs one slot of its card and the new build goes to the other. The command reads
//! `/api/v1/stats` (port 80, no login) for the running build, slot and boot-files digest, refuses
//! locally what the receiver would refuse, logs in over TLS pinned to `qberrypi-tls.pem`
//! ([`crate::pinned`]), uploads the slot's eleven files as one request, and then follows the stats
//! until the new build reports that it confirmed itself, or the old one reports the rollback.
//! The Pi's side is `qberrypi::update` (the design: milestone 8, "The update receiver" and "Trial
//! boot").
//!
//! # Where the command stops before anything is sent
//!
//! In this order, each with a sentence that ends "nothing was uploaded": the standard input is a
//! terminal (the password is piped in, as for `hash-password`); `qberrypi.toml` does not parse,
//! has a development switch on or has no `[api]` section; the build or the certificate is
//! missing; the Pi's statistics cannot be read; the Pi runs the old layout and has no slots; an
//! update or a trial is already under way on it; the new build is not newer than the running one
//! (`--force` takes it); the new build's boot files are not the running build's (`--allow-kernel`
//! takes them, and the sentence says what cannot be rolled back); the body is over the receiver's
//! 64 MiB. A password that could not log in (empty, not UTF-8, too long) and a Pi whose
//! certificate is not the pinned one are refused before the password is sent.
//!
//! # The rollback drill
//!
//! `--rollback-drill panic|stall` uploads this build with `debug.fault` set to `"trial_panic"` or
//! `"trial_stall"` in the uploaded copy of `qberrypi.toml` only: [`drill_config`] makes the copy and
//! proves with `qberrypi::config::parse` that it parses and differs from the original in that
//! one key. Both faults act only on a trial boot, so the build that comes back on the other slot
//! is the old one. `--force` is implied (the drill uploads the build the Pi may already run),
//! and the drill succeeds when the Pi rolls back; a trial that confirms is the failure.
//!
//! # The channel hint
//!
//! When the local `qberrypi.toml` has no `wifi.hint_mhz` and the Pi's statistics give the channel
//! it is joined on (`wifi.freq_mhz`), the copy of `qberrypi.toml` that is uploaded gets
//! `hint_mhz = [..]` under `[wifi]`, so that the new build's first scan covers only that channel.
//! [`with_running_channel`] makes the copy and, through [`crate::wifihint`], proves with
//! `qberrypi::config::parse` that it differs from the original in that one key; the command says so.
//! The file on this computer is not written. A Pi that does not say its channel, or a file that has
//! a hint (even an empty one), leaves the copy as it was, and a hint that cannot be added is said and
//! does not stop the update. Only a 5 GHz channel is added: the Pi prefers 5 GHz and does not take a
//! hinted scan whose best access point is on 2.4 GHz, so the hint is for the 5 GHz channel, and a
//! Pi that is on a 2.4 GHz one (it fell back to it) is said to have had none added.
//!
//! # What is printed
//!
//! Plain sentences, one for each stage: what is uploaded and how much, that the Pi is
//! restarting, that it is on trial, and how it ended: `build N is confirmed on slot X` or `the Pi
//! rolled back to build N on slot X: <why the Pi says>`. Never the password, the session id, the
//! Pi's address or a value of `qberrypi.toml`.
//!
//! After a rollback the command exits with an error, unless it was a drill. A trial that never
//! started under the firmware's `tryboot` ends with one more sentence: `--software-trial` is the
//! fallback, and the Pi check in the docs says how to tell.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};
use clap::{Args, ValueEnum};
use qberrypi::config::{self, Fault};
use qberrypi::slots::{Mode, Slot};
use qberrypi::update::receive::{BODY_ORDER, Manifest};
use serde_json::Value;

use crate::slot::{BOOT_FOLDER, Build, CONFIG_FILE};
use crate::{build, hashpw, image, pinned, probe, slot, wifihint};

/// What each refusal before the upload ends with.
const NOTHING_UPLOADED: &str = "nothing was uploaded";

/// The document of the Pi checks of milestone 8, which says how to tell whether the board's
/// firmware honours the `tryboot` flag.
const PI_CHECKS: &str = "docs/bring-up/m8-only-os.md";

/// The arguments of `cargo xtask update`.
#[derive(Args, Debug, PartialEq, Eq)]
pub struct UpdateArgs {
    /// The Pi's IPv4 address; without it, `net.address` of qberrypi.toml
    #[arg(long, value_name = "IPV4")]
    pub server: Option<Ipv4Addr>,
    /// Send a build whose boot files (kernel, device tree, overlays, command line, config.txt)
    /// differ from the running one's; a kernel that stops the board before init runs cannot be
    /// rolled back
    #[arg(long)]
    pub allow_kernel: bool,
    /// Send a build that is not newer than the one the Pi runs
    #[arg(long)]
    pub force: bool,
    /// Start the trial by selecting the new slot in config.txt instead of the firmware's tryboot
    /// flag; for a board whose firmware ignores the flag
    #[arg(long)]
    pub software_trial: bool,
    /// Send this build with a provoked failure on its trial boot (set in the uploaded copy of
    /// qberrypi.toml only; implies --force) and succeed only if the Pi rolls back
    #[arg(long, value_enum, value_name = "FAULT")]
    pub rollback_drill: Option<Drill>,
}

/// The failure that a rollback drill provokes on the trial boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Drill {
    /// `debug.fault = "trial_panic"`: a component panics, and the fatal error restarts the board.
    Panic,
    /// `debug.fault = "trial_stall"`: the supervisor stalls, and the watchdog restarts the board.
    Stall,
}

impl Drill {
    /// The value of `debug.fault` that provokes it.
    fn word(self) -> &'static str {
        match self {
            Drill::Panic => "trial_panic",
            Drill::Stall => "trial_stall",
        }
    }

    /// The fault that `qberrypi::config` reads that value as.
    fn fault(self) -> Fault {
        match self {
            Drill::Panic => Fault::TrialPanic,
            Drill::Stall => Fault::TrialStall,
        }
    }
}

/// The two servers of the Pi that the command talks to.
#[derive(Clone, Copy, Debug)]
pub struct Endpoints {
    /// The API, over TLS.
    pub https: SocketAddr,
    /// The status server, plain HTTP.
    pub status: SocketAddr,
}

impl Endpoints {
    /// The Pi's own ports, at `address`.
    fn of(address: Ipv4Addr) -> Self {
        let ip = IpAddr::V4(address);
        Self {
            https: SocketAddr::new(ip, qberrypi::api::PORT),
            status: SocketAddr::new(ip, qberrypi::status::PORT),
        }
    }
}

/// How long the command waits for each thing.
#[derive(Clone, Copy, Debug)]
pub struct Timing {
    /// One reading of the statistics.
    pub stats_wait: Duration,
    /// Connecting, the handshake and the login, together.
    pub login_wait: Duration,
    /// The upload and the Pi's answer to it: the receiver's own bound is ten minutes from the
    /// head of the request, and the answer is written after it.
    pub upload_wait: Duration,
    /// The pause between two readings of the statistics, once the update is staged.
    pub poll_every: Duration,
    /// How long after the update is staged the command waits for the end of the trial.
    pub follow_for: Duration,
}

impl Timing {
    /// The command's own: 5 s, 30 s, 11 min, 2 s, 15 min.
    const REAL: Timing = Timing {
        stats_wait: Duration::from_secs(5),
        login_wait: Duration::from_secs(30),
        upload_wait: Duration::from_secs(11 * 60),
        poll_every: Duration::from_secs(2),
        follow_for: Duration::from_secs(15 * 60),
    };
}

/// Where the Pi is and how long to wait for it: the real ones, or a test's.
pub struct Wiring {
    /// The servers, for the address that the Pi has.
    pub endpoints: Box<dyn Fn(Ipv4Addr) -> Endpoints>,
    /// The waits.
    pub timing: Timing,
}

impl Wiring {
    /// The Pi's own ports at its address, and the command's own waits.
    fn real() -> Self {
        Self {
            endpoints: Box::new(Endpoints::of),
            timing: Timing::REAL,
        }
    }
}

/// What one reading of `/api/v1/stats` says of the update, as this command needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Seen {
    /// The build time of the running build.
    build: u64,
    /// Seconds since init started, which only grows within one boot.
    uptime_secs: u64,
    /// The running slot; `None` on the old layout.
    slot: Option<Slot>,
    /// The digest of the running build's boot files, if it has one.
    boot_files: Option<String>,
    /// What the update machinery is doing; `None` on the old layout.
    phase: Option<Phase>,
    /// What a trial still waits for, if this boot is on trial.
    waiting_for: Vec<String>,
    /// How the last trial that this boot knows of ended.
    last: Option<Last>,
    /// The frequency in MHz of the channel the Pi is joined on (`wifi.freq_mhz`); `None` when it is
    /// not joined, or runs a build that does not tell.
    freq_mhz: Option<u32>,
}

/// What the update machinery of the Pi is doing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Nothing.
    Idle,
    /// An update is being received, or has been staged.
    Receiving,
    /// This boot is the trial of an update.
    Trial,
}

impl Phase {
    /// The word the statistics use for it.
    fn word(self) -> &'static str {
        match self {
            Phase::Idle => "idle",
            Phase::Receiving => "receiving",
            Phase::Trial => "trial",
        }
    }
}

/// How the last trial ended, as the statistics tell it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Last {
    /// `"confirmed"` or `"rolled_back"`.
    outcome: String,
    /// The build time of the trial build.
    build: u64,
    /// For a rollback, which case it was.
    detail: String,
}

impl Seen {
    /// Reads the statistics that the Pi answered. An error, in words that quote nothing from
    /// `stats`, if a key that must be there is not as it is told.
    fn from_stats(stats: &Value) -> Result<Seen, &'static str> {
        let build = stats
            .get("build")
            .and_then(Value::as_u64)
            .ok_or("no build time")?;
        let uptime_secs = stats
            .get("uptime_secs")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let slot = match stats.get("slot") {
            None | Some(Value::Null) => None,
            Some(Value::String(letter)) => {
                Some(Slot::from_letter(letter).ok_or("a slot that is not a or b")?)
            }
            Some(_) => return Err("a slot that is not a letter"),
        };
        let boot_files = stats
            .get("boot_files")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let (mut phase, mut waiting_for, mut last) = (None, Vec::new(), None);
        if let Some(update) = stats.get("update").filter(|update| !update.is_null()) {
            phase = Some(match update.get("state").and_then(Value::as_str) {
                Some("idle") => Phase::Idle,
                Some("receiving") => Phase::Receiving,
                Some("trial") => Phase::Trial,
                _ => return Err("an update state that is not idle, receiving or trial"),
            });
            if let Some(Value::Array(words)) = update.pointer("/trial/waiting_for") {
                waiting_for = words
                    .iter()
                    .filter_map(Value::as_str)
                    .map(pinned::printable)
                    .collect();
            }
            if let Some(found) = update.get("last").filter(|last| !last.is_null()) {
                last = Some(Last {
                    outcome: found
                        .get("outcome")
                        .and_then(Value::as_str)
                        .ok_or("a last trial with no outcome")?
                        .to_owned(),
                    build: found
                        .get("build")
                        .and_then(Value::as_u64)
                        .ok_or("a last trial with no build time")?,
                    detail: pinned::printable(
                        found.get("detail").and_then(Value::as_str).unwrap_or(""),
                    ),
                });
            }
        }
        let freq_mhz = stats
            .pointer("/wifi/freq_mhz")
            .and_then(Value::as_u64)
            .and_then(|mhz| u32::try_from(mhz).ok());
        Ok(Seen {
            build,
            uptime_secs,
            slot,
            boot_files,
            phase,
            waiting_for,
            last,
            freq_mhz,
        })
    }
}

/// The build that is to be sent, as far as the Pi's state is compared with it.
struct Candidate {
    /// The build time of `out/qberrypi/`.
    build: u64,
    /// The digest of its boot files.
    boot_files: String,
}

/// How the new build's boot files compare with the running build's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BootFiles {
    /// The same digest.
    Same,
    /// Another digest.
    Differ,
    /// The running build does not tell its digest.
    Unknown,
}

/// What the Pi's own state rules out: the old layout, which has no slots, and an update or a
/// trial that is already under way. Gives the slot that runs.
fn refuse_pi_state(seen: &Seen) -> Result<Slot> {
    let Some(running) = seen.slot else {
        bail!(
            "the Pi runs the old layout (Raspberry Pi OS beside qberrypi), which has no slots to \
             update: put a card made by `cargo xtask image` in it, or use `cargo xtask deploy`; \
             {NOTHING_UPLOADED}"
        );
    };
    match seen.phase {
        Some(Phase::Idle) | None => Ok(running),
        Some(busy) => bail!(
            "an update is already under way on the Pi (it is {}): wait until it ends and run this \
             again; {NOTHING_UPLOADED}",
            busy.word()
        ),
    }
}

/// What the new build's state against the Pi's rules out: a build that is not newer without
/// `--force` (a drill forces), and boot files that are not the running build's without
/// `--allow-kernel`. Says how the boot files compare.
fn refuse_build(seen: &Seen, new: &Candidate, args: &UpdateArgs) -> Result<BootFiles> {
    let forced = args.force || args.rollback_drill.is_some();
    if new.build <= seen.build && !forced {
        bail!(
            "build {} is not newer than the build the Pi runs ({}): run `cargo xtask build` for a \
             newer one, or pass --force; {NOTHING_UPLOADED}",
            new.build,
            seen.build
        );
    }
    let files = match seen.boot_files.as_deref() {
        Some(running) if running == new.boot_files => BootFiles::Same,
        Some(_) => BootFiles::Differ,
        None => BootFiles::Unknown,
    };
    if files != BootFiles::Same && !args.allow_kernel {
        let why = if files == BootFiles::Differ {
            "this build changes the boot files (kernel, device tree, overlays, command line or \
             config.txt), which a trial cannot roll back if the board stops before init runs"
        } else {
            "the running build does not tell its boot files, so this build cannot be shown to \
             leave them alone"
        };
        bail!("{why}: pass --allow-kernel to send it anyway; {NOTHING_UPLOADED}");
    }
    Ok(files)
}

/// Whether the Pi's reason for a rollback says that the trial build never started: the firmware
/// ignored the flag, or the kernel never reached init (see `Marker::rollback_detail`).
fn never_started(detail: &str) -> bool {
    detail.contains("never started")
}

/// `text`, the text of `qberrypi.toml`, with `fault = "<word>"` as `debug.fault`: the key's line
/// in the `[debug]` table is replaced (its comment goes with it), or added below the table's
/// header, or the table is added at the end. Nothing else is touched.
///
/// This is a text edit, since `xtask` has no TOML writer and a rewrite would lose the owner's
/// comments; [`drill_config`] proves the result.
fn with_fault(text: &str, word: &str) -> String {
    let wanted = format!("fault = \"{word}\"");
    let mut edited = String::with_capacity(text.len() + wanted.len() + 16);
    let (mut in_debug, mut replaced) = (false, false);
    let mut after_header = None;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if trimmed.starts_with('[') {
            in_debug = table_name(trimmed) == Some("debug");
            edited.push_str(line);
            if in_debug && after_header.is_none() {
                if !line.ends_with('\n') {
                    edited.push('\n');
                }
                after_header = Some(edited.len());
            }
        } else if in_debug && is_fault_key(trimmed) {
            let ending = if line.ends_with("\r\n") { "\r\n" } else { "\n" };
            edited.push_str(&wanted);
            edited.push_str(ending);
            replaced = true;
        } else {
            edited.push_str(line);
        }
    }
    if replaced {
        return edited;
    }
    match after_header {
        Some(at) => edited.insert_str(at, &format!("{wanted}\n")),
        None => {
            if !edited.is_empty() && !edited.ends_with('\n') {
                edited.push('\n');
            }
            edited.push_str(&format!("\n[debug]\n{wanted}\n"));
        }
    }
    edited
}

/// The name of the table that the header line `line` (already trimmed at its start) opens: `None`
/// for an array of tables or a line that is no header.
pub(crate) fn table_name(line: &str) -> Option<&str> {
    let inner = line.strip_prefix('[')?;
    if inner.starts_with('[') {
        return None;
    }
    let (name, _rest) = inner.split_once(']')?;
    Some(name.trim())
}

/// Whether `line` (already trimmed at its start) assigns the key `fault`.
fn is_fault_key(line: &str) -> bool {
    line.strip_prefix("fault")
        .is_some_and(|rest| rest.trim_start().starts_with('='))
}

/// The text of `qberrypi.toml` for a rollback drill: `text` with `debug.fault` set to the drill's
/// fault, and proved to differ from `text` in that and nothing else.
///
/// The proof reads both with `qberrypi::config::parse`: the copy must parse, must have the
/// drill's fault, and must be, with the original's fault put back, the same configuration as the
/// original (compared as `Debug` prints it, which hides the secrets, so the Wi-Fi key and the
/// API's password hash are compared on their own). An error says which of these failed and quotes
/// nothing of the file.
fn drill_config(text: &str, drill: Drill) -> Result<String> {
    let before = config::parse(text)
        .map_err(|error| anyhow!("{CONFIG_FILE} is not a valid configuration: {error}"))?;
    let edited = with_fault(text, drill.word());
    let mut after = config::parse(&edited).map_err(|error| {
        anyhow!(
            "the copy of {CONFIG_FILE} for the drill does not parse ({error}); debug.fault could \
             not be set in it, so nothing was uploaded"
        )
    })?;
    ensure!(
        after.debug.fault == drill.fault(),
        "the copy of {CONFIG_FILE} for the drill does not have debug.fault = \"{}\"; {NOTHING_UPLOADED}",
        drill.word()
    );
    after.debug.fault = before.debug.fault;
    ensure!(
        wifihint::same_configuration(&before, &after),
        "the copy of {CONFIG_FILE} for the drill differs from the original in more than \
         debug.fault; {NOTHING_UPLOADED}"
    );
    Ok(edited)
}

/// The text of `qberrypi.toml` to upload, and the sentence to say about its channel hint, if there is
/// one to say.
///
/// A file that has no `wifi.hint_mhz` of its own gains one, the channel `running` that the Pi reports
/// being joined on, so that the new build's first scan is short ([`wifihint::hinted_config`] proves
/// that only that key is added). A file that has a hint keeps it, and a Pi that does not say its
/// channel (not joined, or an old build) gives nothing to add, and neither says anything. A channel
/// that is not on the 5 GHz band is not added either, and the sentence says so: the Pi prefers 5 GHz
/// and does not take a hinted scan whose best access point is on 2.4 GHz, so the hint would only add
/// a scan. A hint that cannot be added (the frequency is no channel, or the file has no `[wifi]`
/// header) is not a reason to stop: the file goes as it is, and the sentence says so, with the reason
/// and no value of the file.
fn with_running_channel(text: &str, running: Option<u32>) -> (String, Option<String>) {
    let Some(mhz) = running else {
        return (text.to_owned(), None);
    };
    if wifihint::has_hint(text) {
        return (text.to_owned(), None);
    }
    if !wifihint::is_5ghz(mhz) {
        return (
            text.to_owned(),
            Some(format!(
                "no wifi.hint_mhz is added to the copy of {CONFIG_FILE} that is uploaded: the Pi is on \
                 {mhz} MHz, which is not on the 5 GHz band, and a hint is for the 5 GHz channel (the Pi \
                 prefers 5 GHz, so a hinted scan whose best access point is on another band is not taken \
                 and the scan covers every channel after all)"
            )),
        );
    }
    match wifihint::hinted_config(text, &[mhz]) {
        Ok(edited) => (
            edited,
            Some(format!(
                "the copy of {CONFIG_FILE} that is uploaded gains wifi.hint_mhz = [{mhz}], the channel \
                 the Pi is on, so that its first scan after a start is short; {CONFIG_FILE} here is \
                 unchanged and nothing else differs in the copy"
            )),
        ),
        Err(why) => (
            text.to_owned(),
            Some(format!(
                "no wifi.hint_mhz is added to the copy of {CONFIG_FILE} that is uploaded: {why}"
            )),
        ),
    }
}

/// How a trial ended, as the Pi's statistics say.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    /// The trial build confirmed itself: it is the build on this slot now.
    Confirmed { build: u64, slot: Slot },
    /// The trial failed: this build runs on this slot again, for the reason the Pi gave.
    RolledBack {
        build: u64,
        slot: Slot,
        detail: String,
    },
}

/// What a reading of the statistics adds to what the command knows, and says.
#[derive(Debug, Default, PartialEq, Eq)]
struct Observed {
    /// Sentences to print, in order.
    say: Vec<String>,
    /// How the trial ended, if this reading shows it.
    done: Option<Outcome>,
}

/// Where the command is in following an update: what it expects and what it has seen.
struct Follow {
    /// The slot that was running, which a rollback boots.
    from: Slot,
    /// The slot that was written, which the trial boots.
    to: Slot,
    /// The build that was sent.
    to_build: u64,
    /// Whether the board has been seen to restart since the upload.
    restarted: bool,
    /// Whether the last reading was an answer.
    up: bool,
    /// The uptime of the last answer.
    last_uptime: u64,
    /// Whether the trial build has been seen running.
    trial_seen: bool,
    /// What the trial was last seen waiting for.
    waiting: Vec<String>,
}

impl Follow {
    /// Follows an update of `to_build` to slot `to`, from a Pi that ran slot `from` and had been
    /// up for `uptime_secs` seconds.
    fn new(from: Slot, to: Slot, to_build: u64, uptime_secs: u64) -> Self {
        Self {
            from,
            to,
            to_build,
            restarted: false,
            up: true,
            last_uptime: uptime_secs,
            trial_seen: false,
            waiting: Vec::new(),
        }
    }

    /// Takes one reading of the Pi's statistics (`None` when it did not answer) and gives what it
    /// says and whether the trial has ended.
    ///
    /// The Pi has restarted once it did not answer, or its uptime went back, or it runs the new
    /// slot; nothing it says before that counts, since what it still holds of an earlier update
    /// would be taken for this one's end. After that: the new slot on trial is the trial, the
    /// new slot with no update under way is the confirm, and the old slot with a rollback of
    /// this build is the rollback.
    fn observe(&mut self, seen: Option<&Seen>) -> Observed {
        let mut observed = Observed::default();
        let Some(seen) = seen else {
            self.restarted = true;
            if std::mem::take(&mut self.up) {
                observed
                    .say
                    .push("the Pi is restarting and does not answer yet".to_owned());
            }
            return observed;
        };
        self.up = true;
        if seen.uptime_secs < self.last_uptime || seen.slot == Some(self.to) {
            self.restarted = true;
        }
        self.last_uptime = seen.uptime_secs;
        if !self.restarted {
            return observed;
        }
        if seen.slot == Some(self.to) {
            match seen.phase {
                Some(Phase::Trial) => {
                    if !self.trial_seen {
                        self.trial_seen = true;
                        observed.say.push(format!(
                            "build {} is running on slot {} as a trial; it confirms itself once it \
                             has proved itself",
                            seen.build, self.to
                        ));
                    }
                    if seen.waiting_for != self.waiting {
                        self.waiting.clone_from(&seen.waiting_for);
                        if !self.waiting.is_empty() {
                            observed.say.push(format!(
                                "the trial build is still waiting for: {}",
                                self.waiting.join(", ")
                            ));
                        }
                    }
                }
                Some(Phase::Idle) => {
                    if seen.build != self.to_build {
                        observed.say.push(format!(
                            "note: the Pi reports build {}, while the build that was sent is {}",
                            seen.build, self.to_build
                        ));
                    }
                    observed.done = Some(Outcome::Confirmed {
                        build: seen.build,
                        slot: self.to,
                    });
                }
                Some(Phase::Receiving) | None => {}
            }
        } else if seen.slot == Some(self.from)
            && let Some(last) = seen
                .last
                .as_ref()
                .filter(|last| last.outcome == "rolled_back" && last.build == self.to_build)
        {
            observed.done = Some(Outcome::RolledBack {
                build: seen.build,
                slot: self.from,
                detail: last.detail.clone(),
            });
        }
        observed
    }

    /// The sentence for a wait that ran out.
    fn gave_up(&self, waited: Duration) -> String {
        let minutes = waited.as_secs().div_ceil(60);
        if !self.restarted {
            format!(
                "the Pi did not restart within {minutes} minutes of the upload; the update is on \
                 its card, so a restart by hand (a power cycle) boots the trial"
            )
        } else if self.trial_seen {
            format!(
                "the trial build was still on trial after {minutes} minutes; it gives up by \
                 itself after 10 minutes, so the Pi may be stuck: look at it"
            )
        } else {
            format!(
                "the Pi restarted but did not tell how the trial ended within {minutes} minutes"
            )
        }
    }
}

/// Prints one line to `out` and flushes, so that a pipe shows the progress as it happens.
fn say(out: &mut dyn Write, text: impl AsRef<str>) -> Result<()> {
    writeln!(out, "{}", text.as_ref())?;
    out.flush()?;
    Ok(())
}

/// `bytes` as MiB with one decimal.
fn mib(bytes: u64) -> String {
    format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
}

/// Reads the Pi's statistics and what they say of the update.
fn read_stats(pi: &Endpoints, timing: &Timing) -> Result<Seen> {
    let stats = probe::get_stats(pi.status, timing.stats_wait).context(
        "cannot read the Pi's status (port 80): is it running, and is its address right? \
         (--server gives it)",
    )?;
    Seen::from_stats(&stats)
        .map_err(|why| anyhow!("the Pi's statistics are not as this xtask reads them: {why}"))
}

/// Follows the statistics every `poll_every` until the trial has ended or `follow_for` has gone.
fn follow(
    pi: &Endpoints,
    timing: &Timing,
    following: &mut Follow,
    out: &mut dyn Write,
) -> Result<Outcome> {
    let began = Instant::now();
    loop {
        let seen = probe::get_stats(pi.status, timing.stats_wait)
            .ok()
            .and_then(|stats| Seen::from_stats(&stats).ok());
        let observed = following.observe(seen.as_ref());
        for line in &observed.say {
            say(out, line)?;
        }
        if let Some(outcome) = observed.done {
            return Ok(outcome);
        }
        if began.elapsed() >= timing.follow_for {
            bail!("{}", following.gave_up(timing.follow_for));
        }
        thread::sleep(timing.poll_every);
    }
}

/// Runs `cargo xtask update`: reads the password from standard input (refusing a terminal) and
/// updates the Pi, saying to `out` what happens.
pub fn run(root: &Path, args: &UpdateArgs, out: &mut dyn Write) -> Result<()> {
    let password = hashpw::read_password_from_stdin()?;
    update(root, args, &password, &Wiring::real(), out)
}

/// The update, with the password, the Pi's servers and the waits given.
fn update(
    root: &Path,
    args: &UpdateArgs,
    password: &[u8],
    wiring: &Wiring,
    out: &mut dyn Write,
) -> Result<()> {
    let timing = &wiring.timing;

    // What is on this computer.
    let config_text = slot::read_config(root)?;
    let parsed = image::check_config(&config_text, "cargo xtask update", NOTHING_UPLOADED)?;
    let tls_pem = slot::read_tls_pem(root)?;
    let client = pinned::client_config(&tls_pem)?;
    let build = Build::read(&root.join(BOOT_FOLDER))?;
    let epoch = build::read_build_epoch(root)?;
    let pi = (wiring.endpoints)(args.server.unwrap_or(parsed.net.address.addr));

    // What the Pi is, and whether it takes this.
    let seen = read_stats(&pi, timing)?;
    let running = refuse_pi_state(&seen)?;
    let target = running.other();
    let (upload_config, hint_sentence) = with_running_channel(&config_text, seen.freq_mhz);
    let mut files = build.slot_files(target, upload_config.as_bytes(), &tls_pem);
    if let Some(drill) = args.rollback_drill {
        let edited = drill_config(&upload_config, drill)?;
        slot::replace_file(&mut files, CONFIG_FILE, edited.into_bytes())?;
    }
    let candidate = Candidate {
        build: epoch,
        boot_files: slot::boot_files_digest(&files)?,
    };
    let boot_files = refuse_build(&seen, &candidate, args)?;

    // What is sent.
    let mode = if args.software_trial {
        Mode::Software
    } else {
        Mode::Tryboot
    };
    let listed: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
        .collect();
    let mut manifest = Manifest::of_files(epoch, target, mode, &listed)
        .map_err(|why| anyhow!("the slot's files are not the eleven the receiver takes: {why}"))?;
    manifest.force = args.force || args.rollback_drill.is_some();
    manifest.allow_kernel = args.allow_kernel;
    let head = manifest
        .head()
        .map_err(|why| anyhow!("{why}; {NOTHING_UPLOADED}"))?;
    let length = manifest
        .content_length()
        .map_err(|why| anyhow!("{why}; {NOTHING_UPLOADED}"))?;
    let mut body: Vec<&[u8]> = vec![&head];
    for name in BODY_ORDER {
        let (_, bytes) = listed
            .iter()
            .find(|(have, _)| *have == name)
            .ok_or_else(|| anyhow!("the slot has no file called {name}"))?;
        body.push(bytes);
    }

    say(
        out,
        format!(
            "the Pi runs build {} on slot {running}; build {epoch} goes to slot {target}, started \
             by {}",
            seen.build,
            match mode {
                Mode::Tryboot => "the firmware's tryboot flag",
                Mode::Software => "the software trial",
            }
        ),
    )?;
    if epoch <= seen.build {
        say(
            out,
            "this build is not newer than the one the Pi runs, and is sent because of --force or \
             the drill",
        )?;
    }
    if let Some(sentence) = &hint_sentence {
        say(out, sentence)?;
    }
    if boot_files != BootFiles::Same {
        say(
            out,
            format!(
                "the boot files are not shown to be the running build's, and --allow-kernel sends \
                 them: a kernel that stops the board before init runs cannot be rolled back (under \
                 the firmware trial a power cycle still boots slot {running}; under the software \
                 trial the card must come out)"
            ),
        )?;
    }
    if let Some(drill) = args.rollback_drill {
        say(
            out,
            format!(
                "rollback drill: the copy of {CONFIG_FILE} that is uploaded has debug.fault = \
                 \"{}\", which acts only on a trial boot; the trial is expected to fail and the Pi \
                 to come back on slot {running}",
                drill.word()
            ),
        )?;
    }

    // The upload.
    let mut session = pinned::Session::login(pi.https, client, password, timing.login_wait)?;
    say(
        out,
        format!(
            "uploading build {epoch} to slot {target}: {} files, {} ({length} bytes)",
            manifest.files.len(),
            mib(length)
        ),
    )?;
    let answer = session.upload(&body, timing.upload_wait)?;
    let staged = answer.status == 200
        && answer
            .json()
            .is_some_and(|json| json.get("staged") == Some(&Value::Bool(true)));
    if !staged {
        let refusal = answer.refusal();
        session.logout(timing.login_wait);
        bail!("the Pi refused the update ({refusal})");
    }
    say(
        out,
        format!(
            "the Pi has written slot {target} and checked it from its card; the Pi is restarting \
             into the {} trial",
            match mode {
                Mode::Tryboot => "firmware",
                Mode::Software => "software",
            }
        ),
    )?;

    // The trial.
    let mut following = Follow::new(running, target, epoch, seen.uptime_secs);
    let outcome = follow(&pi, timing, &mut following, out)?;
    conclude(outcome, args, mode, out)
}

/// Says how the update ended, and whether that is what was wanted: a confirm is, unless it was a
/// drill; a rollback is only for a drill.
fn conclude(outcome: Outcome, args: &UpdateArgs, mode: Mode, out: &mut dyn Write) -> Result<()> {
    match outcome {
        Outcome::Confirmed { build, slot } => {
            say(out, format!("build {build} is confirmed on slot {slot}"))?;
            if args.rollback_drill.is_some() {
                bail!(
                    "the drill's trial build confirmed itself, so no rollback was shown: its \
                     provoked fault did not act"
                );
            }
            Ok(())
        }
        Outcome::RolledBack {
            build,
            slot,
            detail,
        } => {
            say(
                out,
                format!("the Pi rolled back to build {build} on slot {slot}: {detail}"),
            )?;
            if args.rollback_drill.is_some() {
                say(
                    out,
                    "the rollback drill worked: the trial failed and the Pi came back on the slot it \
                     came from",
                )?;
                return Ok(());
            }
            if mode == Mode::Tryboot && never_started(&detail) {
                say(
                    out,
                    format!(
                        "if the Pi's firmware ignores the tryboot flag, try again with \
                         --software-trial, and see the Pi check in {PI_CHECKS}"
                    ),
                )?;
            }
            bail!("the new build did not confirm, so the Pi is back on its old one")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::io;
    use std::path::PathBuf;
    use std::sync::Arc;

    use qberrypi::slots::{self, Marker};
    use qberrypi::update::receive::Receiver;
    use qberrypi::update::{BootCard, CardAccess, Restart, UpdateCtl};
    use serde_json::json;
    use tempfile::TempDir;

    use crate::cert::CERT_FILE;
    use crate::slot::tests::{CONFIG, checkout};
    use crate::standin::{PASSWORD, SID, StatusPi, Step, TlsPi};

    /// A refusal to try: what it is, how to spoil a checkout for it, the arguments, and what the
    /// error says.
    type Case = (&'static str, Box<dyn Fn(&Path)>, UpdateArgs, &'static str);

    /// The running Pi's build time in these tests, and the new build's (the fixture's).
    const RUNNING: u64 = 1_794_000_000;
    const NEW: u64 = 1_794_000_100;

    /// A password line of the shape the configuration reads. Nobody's password hashes to it.
    const PASSWORD_LINE: &str = "password_hash = \"$pbkdf2-sha256$i=100000$00000000000000000000000000000000$0000000000000000000000000000000000000000000000000000000000000000\"";

    /// The Wi-Fi passphrase of the example configuration, which no output may repeat.
    const PASSPHRASE: &str = "example-passphrase";

    /// The example configuration with an `[api]` section.
    fn api_config() -> String {
        format!("{CONFIG}\n[api]\n{PASSWORD_LINE}\n")
    }

    /// A checkout that `update` accepts: a fixture build with the time `NEW`, an `[api]`
    /// configuration and a made certificate.
    fn ready() -> (TempDir, String) {
        let (root, pem) = checkout();
        fs::write(root.path().join(CONFIG_FILE), api_config()).unwrap();
        fs::write(root.path().join("out/build-epoch"), format!("{NEW}\n")).unwrap();
        (root, pem)
    }

    fn args() -> UpdateArgs {
        UpdateArgs {
            server: None,
            allow_kernel: false,
            force: false,
            software_trial: false,
            rollback_drill: None,
        }
    }

    /// The digest of the boot files of the fixture build, which the running Pi reports.
    fn digest(root: &Path) -> String {
        let build = Build::read(&root.join(BOOT_FOLDER)).unwrap();
        slot::boot_files_digest(&build.slot_files(Slot::A, b"", b"")).unwrap()
    }

    /// The statistics of a Pi of `build` on `slot`, up for `uptime` seconds, with the update
    /// state `update` (a JSON value).
    fn stats(build: u64, slot: &str, digest: &str, uptime: u64, update: Value) -> Value {
        json!({
            "build": build,
            "uptime_secs": uptime,
            "slot": slot,
            "boot_files": digest,
            "update": update,
        })
    }

    fn idle() -> Value {
        json!({ "state": "idle", "trial": null, "last": null })
    }

    fn on_trial(waiting: &[&str]) -> Value {
        json!({ "state": "trial", "trial": { "build": NEW, "from": "a", "secs": 30, "waiting_for": waiting }, "last": null })
    }

    fn confirmed() -> Value {
        json!({ "state": "idle", "trial": null, "last": { "outcome": "confirmed", "build": NEW, "detail": "" } })
    }

    fn rolled_back(detail: &str) -> Value {
        json!({ "state": "idle", "trial": null, "last": { "outcome": "rolled_back", "build": NEW, "detail": detail } })
    }

    /// The card that the real receiver writes in these tests: a directory, where the boot
    /// partition's files are.
    struct DirCard(PathBuf);

    impl BootCard for DirCard {
        fn with_boot(&self, _: CardAccess, work: &mut dyn FnMut(&Path)) -> io::Result<()> {
            work(&self.0);
            Ok(())
        }
    }

    /// A Pi on slot a whose update route is the real receiver over a directory for a card, and
    /// whose statistics follow `script`.
    struct Pi {
        api: TlsPi,
        status: StatusPi,
        card: TempDir,
        ctl: Arc<UpdateCtl>,
    }

    impl Pi {
        fn new(pem: &str, running_build: u64, digest: Option<String>, script: Vec<Step>) -> Pi {
            let card = tempfile::tempdir().unwrap();
            fs::write(
                card.path().join("config.txt"),
                crate::build::slot_config_txt(Slot::A),
            )
            .unwrap();
            let ctl = UpdateCtl::new(
                Some(Slot::A),
                digest,
                Arc::new(DirCard(card.path().to_owned())),
            );
            let receiver = Arc::new(Receiver::new(ctl.clone(), running_build));
            let api = TlsPi::start(
                pem,
                Box::new(move |head, stream| {
                    let received = receiver.receive(head, stream);
                    let reply = qberrypi::api::http::Reply {
                        status: received.reply().status,
                        body: received.reply().body.clone(),
                    };
                    let _ = received.send_then_restart(|_| Ok(()));
                    reply
                }),
            );
            Pi {
                api,
                status: StatusPi::start(script),
                card,
                ctl,
            }
        }

        fn wiring(&self) -> Wiring {
            let endpoints = Endpoints {
                https: self.api.addr,
                status: self.status.addr,
            };
            Wiring {
                endpoints: Box::new(move |_| endpoints),
                timing: Timing {
                    stats_wait: Duration::from_secs(2),
                    login_wait: Duration::from_secs(10),
                    upload_wait: Duration::from_secs(20),
                    poll_every: Duration::from_millis(5),
                    follow_for: Duration::from_secs(3),
                },
            }
        }

        /// A file of the card, as text.
        fn card_file(&self, name: &str) -> String {
            fs::read_to_string(self.card.path().join(name)).unwrap_or_default()
        }
    }

    /// Runs the update against `pi`, and gives the result and what was printed.
    fn run_against(
        root: &Path,
        args: &UpdateArgs,
        password: &[u8],
        pi: &Pi,
    ) -> (Result<()>, String) {
        let mut out = Vec::new();
        let result = update(root, args, password, &pi.wiring(), &mut out);
        (result, String::from_utf8(out).unwrap())
    }

    /// The script of a Pi that confirms: running, down twice, on trial, confirmed.
    fn script_confirm(digest: &str) -> Vec<Step> {
        vec![
            Step::Stats(stats(RUNNING, "a", digest, 5_000, idle())),
            Step::Down,
            Step::Down,
            Step::Stats(stats(NEW, "b", digest, 20, on_trial(&["wifi", "clock"]))),
            Step::Stats(stats(NEW, "b", digest, 25, on_trial(&["clock"]))),
            Step::Stats(stats(NEW, "b", digest, 130, confirmed())),
        ]
    }

    /// The script of a Pi that runs `running` and rolls back to it, for the reason `detail`.
    fn script_rollback(digest: &str, running: u64, detail: &str) -> Vec<Step> {
        vec![
            Step::Stats(stats(running, "a", digest, 5_000, idle())),
            Step::Down,
            Step::Stats(stats(NEW, "b", digest, 10, on_trial(&["wifi"]))),
            Step::Down,
            Step::Stats(stats(running, "a", digest, 15, rolled_back(detail))),
        ]
    }

    // ---- the arguments, the statistics, the local refusals ----

    #[test]
    fn the_statistics_of_a_slot_pi_are_read_as_the_slot_the_digest_and_the_update() {
        let digest = "ab".repeat(32);
        let seen = Seen::from_stats(&stats(
            RUNNING,
            "b",
            &digest,
            77,
            json!({ "state": "trial", "trial": { "build": 1, "from": "a", "secs": 3, "waiting_for": ["wifi", "clock"] },
                    "last": { "outcome": "rolled_back", "build": 5, "detail": "the trial build\u{1b}[0m never started" } }),
        ))
        .unwrap();

        assert_eq!(seen.build, RUNNING);
        assert_eq!(seen.uptime_secs, 77);
        assert_eq!(seen.slot, Some(Slot::B));
        assert_eq!(seen.boot_files.as_deref(), Some(digest.as_str()));
        assert_eq!(seen.phase, Some(Phase::Trial));
        assert_eq!(seen.waiting_for, ["wifi", "clock"]);
        let last = seen.last.unwrap();
        assert_eq!((last.outcome.as_str(), last.build), ("rolled_back", 5));
        // A control character of the Pi's words is dropped before they are shown.
        assert_eq!(last.detail, "the trial build[0m never started");
    }

    #[test]
    fn the_statistics_of_the_old_layout_have_no_slot_and_no_update() {
        let seen = Seen::from_stats(
            &json!({ "build": RUNNING, "slot": null, "boot_files": null, "update": null }),
        )
        .unwrap();
        assert_eq!((seen.slot, seen.phase, seen.last), (None, None, None));
        // A build from before slots has no such keys at all.
        let seen = Seen::from_stats(&json!({ "build": RUNNING })).unwrap();
        assert_eq!(seen.slot, None);
        assert_eq!(seen.boot_files, None);
    }

    #[test]
    fn statistics_that_are_not_the_shape_are_an_error_that_quotes_nothing() {
        for bad in [
            json!({}),
            json!({ "build": "yesterday" }),
            json!({ "build": 1, "slot": "c" }),
            json!({ "build": 1, "slot": 3 }),
            json!({ "build": 1, "slot": "a", "update": { "state": "melting" } }),
            json!({ "build": 1, "slot": "a", "update": { "state": "idle", "last": { "outcome": "confirmed" } } }),
        ] {
            let error = Seen::from_stats(&bad).unwrap_err();
            assert!(
                !error.contains("yesterday") && !error.contains("melting"),
                "{error}"
            );
        }
    }

    #[test]
    fn a_pi_with_no_slots_or_with_an_update_under_way_is_refused_with_the_way_forward() {
        let digest = "00".repeat(32);
        let old = Seen::from_stats(&json!({ "build": RUNNING })).unwrap();
        let error = refuse_pi_state(&old).unwrap_err().to_string();
        assert!(
            error.contains("no slots") && error.contains("cargo xtask image"),
            "{error}"
        );
        assert!(error.ends_with("nothing was uploaded"), "{error}");

        for state in [on_trial(&[]), json!({ "state": "receiving" })] {
            let busy = Seen::from_stats(&stats(RUNNING, "a", &digest, 1, state)).unwrap();
            let error = refuse_pi_state(&busy).unwrap_err().to_string();
            assert!(
                error.contains("already under way") && error.ends_with("nothing was uploaded"),
                "{error}"
            );
        }
        let idle = Seen::from_stats(&stats(RUNNING, "b", &digest, 1, idle())).unwrap();
        assert_eq!(refuse_pi_state(&idle).unwrap(), Slot::B);
    }

    #[test]
    fn a_build_that_is_not_newer_is_refused_unless_forced_and_a_drill_forces() {
        let digest = "00".repeat(32);
        let seen = Seen::from_stats(&stats(RUNNING, "a", &digest, 1, idle())).unwrap();
        let candidate = |build| Candidate {
            build,
            boot_files: digest.clone(),
        };

        assert_eq!(
            refuse_build(&seen, &candidate(RUNNING + 1), &args()).unwrap(),
            BootFiles::Same
        );
        for build in [RUNNING, RUNNING - 1] {
            let error = refuse_build(&seen, &candidate(build), &args())
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("not newer") && error.contains("--force"),
                "{error}"
            );
            assert!(error.ends_with("nothing was uploaded"), "{error}");
            let forced = UpdateArgs {
                force: true,
                ..args()
            };
            assert!(refuse_build(&seen, &candidate(build), &forced).is_ok());
            let drill = UpdateArgs {
                rollback_drill: Some(Drill::Panic),
                ..args()
            };
            assert!(refuse_build(&seen, &candidate(build), &drill).is_ok());
        }
    }

    #[test]
    fn boot_files_that_are_not_the_running_builds_are_refused_unless_allowed() {
        let (running, other) = ("00".repeat(32), "11".repeat(32));
        let candidate = Candidate {
            build: RUNNING + 1,
            boot_files: other,
        };
        let allow = UpdateArgs {
            allow_kernel: true,
            ..args()
        };

        let seen = Seen::from_stats(&stats(RUNNING, "a", &running, 1, idle())).unwrap();
        let error = refuse_build(&seen, &candidate, &args())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("changes the boot files") && error.contains("--allow-kernel"),
            "{error}"
        );
        assert!(error.ends_with("nothing was uploaded"), "{error}");
        assert_eq!(
            refuse_build(&seen, &candidate, &allow).unwrap(),
            BootFiles::Differ
        );

        // A running build that cannot tell its boot files is no better: the receiver refuses too.
        let unknown = Seen::from_stats(
            &json!({ "build": RUNNING, "slot": "a", "update": { "state": "idle" } }),
        )
        .unwrap();
        let error = refuse_build(&unknown, &candidate, &args())
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not tell its boot files"), "{error}");
        assert_eq!(
            refuse_build(&unknown, &candidate, &allow).unwrap(),
            BootFiles::Unknown
        );
    }

    #[test]
    fn the_rollback_reason_that_means_the_firmware_ignored_the_flag_is_the_one_the_pi_gives() {
        let mut marker = Marker {
            slot: Slot::B,
            from: Slot::A,
            build: NEW,
            mode: Mode::Tryboot,
            started: false,
            failed: None,
        };
        assert!(never_started(&marker.rollback_detail()));
        marker.started = true;
        assert!(!never_started(&marker.rollback_detail()));
        marker.failed = Some("no upstream answered".to_owned());
        assert!(!never_started(&marker.rollback_detail()));
    }

    // ---- the drill's copy of qberrypi.toml ----

    #[test]
    fn the_drills_copy_has_the_fault_in_place_of_the_example_line_and_nothing_else_changes() {
        let text = api_config();

        let copy = drill_config(&text, Drill::Panic).unwrap();

        assert!(
            copy.contains("fault = \"trial_panic\"\n"),
            "the fault is set"
        );
        assert!(!copy.contains("fault = \"none\""), "the old value is gone");
        let (old_lines, new_lines): (Vec<&str>, Vec<&str>) =
            (text.lines().collect(), copy.lines().collect());
        assert_eq!(old_lines.len(), new_lines.len());
        let differing: Vec<_> = old_lines
            .iter()
            .zip(&new_lines)
            .filter(|(a, b)| a != b)
            .collect();
        assert_eq!(differing.len(), 1, "{differing:?}");
        let parsed = config::parse(&copy).unwrap();
        assert_eq!(parsed.debug.fault, Fault::TrialPanic);
        assert_eq!(config::parse(&text).unwrap().debug.fault, Fault::None);
        // The stall drill is the same edit with the other word.
        let stall = drill_config(&text, Drill::Stall).unwrap();
        assert_eq!(
            config::parse(&stall).unwrap().debug.fault,
            Fault::TrialStall
        );
    }

    #[test]
    fn a_configuration_with_no_fault_line_or_no_debug_table_gets_one_and_still_only_that() {
        for text in [
            // A debug table with no fault key.
            api_config().replace("fault = \"none\"", "# fault left out"),
            // No debug table at all.
            {
                let start = api_config().find("[debug]").unwrap();
                let end = api_config()
                    .find("# The touch screen's calibration")
                    .unwrap();
                format!("{}{}", &api_config()[..start], &api_config()[end..])
            },
            // Windows line endings, and a comment after the value.
            api_config()
                .replace('\n', "\r\n")
                .replace("fault = \"none\"", "fault = \"none\" # no failure"),
        ] {
            let before = config::parse(&text).unwrap();
            let copy = drill_config(&text, Drill::Stall).unwrap();
            let after = config::parse(&copy).unwrap();
            assert_eq!(after.debug.fault, Fault::TrialStall);
            assert_eq!(after.hostname, before.hostname);
            assert_eq!(after.debug.log_to_sd, before.debug.log_to_sd);
        }
    }

    #[test]
    fn a_debug_table_written_in_a_form_the_edit_cannot_handle_is_refused_without_quoting_the_file()
    {
        // `debug` as an inline table: the edit would add a second `[debug]` next to it, which
        // TOML refuses, and the proof catches that.
        let text = api_config();
        let start = text.find("[debug]").unwrap();
        let end = text.find("# The touch screen's calibration").unwrap();
        let inline = format!(
            "debug = {{ one_shot = false }}\n{}{}",
            &text[..start],
            &text[end..]
        );
        config::parse(&inline).expect("an inline debug table is a configuration");

        let error = drill_config(&inline, Drill::Panic).unwrap_err();

        let said = format!("{error:#}");
        assert!(
            said.contains("does not parse") && said.ends_with("nothing was uploaded"),
            "{said}"
        );
        assert!(!said.contains(PASSPHRASE), "{said}");
    }

    #[test]
    fn the_edit_leaves_every_line_alone_that_is_not_the_fault_key_of_the_debug_table() {
        let text = "[api]\nfault = \"keep me\"\n[debug]\n  fault   =  \"none\"  # c\nother = 1\n[x]\nfault = 2\n";
        assert_eq!(
            with_fault(text, "trial_panic"),
            "[api]\nfault = \"keep me\"\n[debug]\nfault = \"trial_panic\"\nother = 1\n[x]\nfault = 2\n"
        );
        assert_eq!(
            with_fault("[debug]\none_shot = false", "trial_stall"),
            "[debug]\nfault = \"trial_stall\"\none_shot = false"
        );
        assert_eq!(
            with_fault("a = 1", "trial_stall"),
            "a = 1\n\n[debug]\nfault = \"trial_stall\"\n"
        );
        assert_eq!(
            with_fault("", "trial_stall"),
            "\n[debug]\nfault = \"trial_stall\"\n"
        );
        assert_eq!(table_name("[ debug ] # c"), Some("debug"));
        assert_eq!(table_name("[[debug]]"), None);
        assert!(
            is_fault_key("fault=\"x\"")
                && !is_fault_key("fault_x = 1")
                && !is_fault_key("faulty = 1")
        );
    }

    // ---- following the Pi ----

    fn pi_seen(build: u64, slot: &str, uptime: u64, update: Value) -> Seen {
        Seen::from_stats(&stats(build, slot, &"00".repeat(32), uptime, update)).unwrap()
    }

    fn following() -> Follow {
        Follow::new(Slot::A, Slot::B, NEW, 5_000)
    }

    #[test]
    fn nothing_the_pi_says_before_it_restarts_counts_not_even_a_rollback_it_remembers() {
        let mut follow = following();
        // The Pi still holds the rollback of an earlier attempt of this very build.
        let stale = pi_seen(
            RUNNING,
            "a",
            5_002,
            rolled_back("the trial build never started"),
        );

        let observed = follow.observe(Some(&stale));

        assert_eq!(observed, Observed::default());
    }

    #[test]
    fn a_pi_that_goes_down_is_said_to_restart_once_and_a_confirm_follows_the_trial() {
        let mut follow = following();
        let mut said = Vec::new();
        let mut done = None;
        let readings = [
            None,
            None,
            Some(pi_seen(NEW, "b", 20, on_trial(&["wifi", "clock"]))),
            Some(pi_seen(NEW, "b", 21, on_trial(&["wifi", "clock"]))),
            Some(pi_seen(NEW, "b", 25, on_trial(&["clock"]))),
            Some(pi_seen(NEW, "b", 28, on_trial(&[]))),
            Some(pi_seen(NEW, "b", 130, confirmed())),
        ];
        for reading in &readings {
            let observed = follow.observe(reading.as_ref());
            said.extend(observed.say);
            done = observed.done.or(done);
        }

        assert_eq!(
            said,
            [
                "the Pi is restarting and does not answer yet",
                "build 1794000100 is running on slot b as a trial; it confirms itself once it has proved itself",
                "the trial build is still waiting for: wifi, clock",
                "the trial build is still waiting for: clock",
            ]
        );
        assert_eq!(
            done,
            Some(Outcome::Confirmed {
                build: NEW,
                slot: Slot::B
            })
        );
    }

    #[test]
    fn a_rollback_is_the_old_slot_reporting_the_trial_of_this_build_rolled_back() {
        let mut follow = following();
        follow.observe(None);

        let observed = follow.observe(Some(&pi_seen(
            RUNNING,
            "a",
            12,
            rolled_back("the trial build restarted before it confirmed"),
        )));

        assert_eq!(
            observed.done,
            Some(Outcome::RolledBack {
                build: RUNNING,
                slot: Slot::A,
                detail: "the trial build restarted before it confirmed".to_owned(),
            })
        );
        // Another build's rollback is not this one's, and the old slot with nothing to report is
        // no end yet.
        let mut other = following();
        other.observe(None);
        let mut elsewhere = rolled_back("x");
        elsewhere["last"]["build"] = json!(NEW + 5);
        assert_eq!(
            other
                .observe(Some(&pi_seen(RUNNING, "a", 12, elsewhere)))
                .done,
            None
        );
        assert_eq!(
            other.observe(Some(&pi_seen(RUNNING, "a", 13, idle()))).done,
            None
        );
    }

    #[test]
    fn a_restart_too_quick_to_catch_is_seen_in_the_uptime_going_back() {
        let mut follow = following();
        assert_eq!(
            follow.observe(Some(&pi_seen(RUNNING, "a", 5_002, idle()))),
            Observed::default()
        );

        let observed = follow.observe(Some(&pi_seen(
            RUNNING,
            "a",
            3,
            rolled_back("the trial build never started"),
        )));

        assert!(
            matches!(observed.done, Some(Outcome::RolledBack { .. })),
            "{observed:?}"
        );
    }

    #[test]
    fn a_new_slot_reporting_another_build_is_confirmed_with_a_note() {
        let mut follow = following();
        let observed = follow.observe(Some(&pi_seen(NEW + 9, "b", 200, idle())));

        assert_eq!(
            observed.done,
            Some(Outcome::Confirmed {
                build: NEW + 9,
                slot: Slot::B
            })
        );
        assert!(
            observed.say[0].contains("reports build 1794000109")
                && observed.say[0].contains("1794000100"),
            "{observed:?}"
        );
    }

    #[test]
    fn a_wait_that_runs_out_says_where_the_update_stood() {
        let mut follow = following();
        assert!(
            follow
                .gave_up(Duration::from_secs(900))
                .contains("did not restart within 15 minutes")
        );
        follow.observe(None);
        assert!(
            follow
                .gave_up(Duration::from_secs(900))
                .contains("did not tell how the trial ended")
        );
        follow.observe(Some(&pi_seen(NEW, "b", 9, on_trial(&["wifi"]))));
        assert!(
            follow
                .gave_up(Duration::from_secs(900))
                .contains("still on trial after 15 minutes")
        );
    }

    // ---- the whole command against stand-ins ----

    #[test]
    fn an_update_that_confirms_is_uploaded_staged_followed_and_reported() {
        let (root, pem) = ready();
        let digest = digest(root.path());
        let pi = Pi::new(&pem, RUNNING, Some(digest.clone()), script_confirm(&digest));

        let (result, said) = run_against(root.path(), &args(), PASSWORD, &pi);

        result.unwrap();
        // The real receiver took the client's bytes: slot b is on the card, staged for the firmware.
        for name in slots::SLOT_FILES {
            assert!(
                pi.card.path().join("qberrypi-b").join(name).is_file(),
                "{name}"
            );
        }
        assert_eq!(
            pi.card_file("tryboot.txt"),
            crate::build::slot_config_txt(Slot::B)
        );
        assert_eq!(
            pi.card_file("config.txt"),
            crate::build::slot_config_txt(Slot::A)
        );
        let marker = slots::read_marker(pi.card.path())
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            (marker.slot, marker.from, marker.build, marker.mode),
            (Slot::B, Slot::A, NEW, Mode::Tryboot)
        );
        assert_eq!(
            pi.ctl.restart_receiver().borrow().clone(),
            Some(Restart::Tryboot)
        );
        // The sentences, in order.
        let lines: Vec<&str> = said.lines().collect();
        assert!(
            lines[0].starts_with(
                "the Pi runs build 1794000000 on slot a; build 1794000100 goes to slot b"
            ),
            "{said}"
        );
        let at = |needle: &str| {
            lines
                .iter()
                .position(|line| line.contains(needle))
                .unwrap_or_else(|| panic!("{needle}: {said}"))
        };
        assert!(
            at("uploading build 1794000100 to slot b: 11 files")
                < at("restarting into the firmware trial")
        );
        assert!(at("restarting into the firmware trial") < at("is running on slot b as a trial"));
        assert_eq!(
            lines.last().unwrap(),
            &"build 1794000100 is confirmed on slot b"
        );
        // Nothing private is said.
        for private in [PASSWORD_LINE, PASSPHRASE, SID, "127.0.0.1", "192.0.2"] {
            assert!(!said.contains(private), "{private}: {said}");
        }
        assert!(!said.contains("example password"), "{said}");
    }

    #[test]
    fn a_rollback_is_reported_with_the_pis_reason_and_the_command_fails() {
        let (root, pem) = ready();
        let digest = digest(root.path());
        let detail = "the trial build restarted before it confirmed";
        let pi = Pi::new(
            &pem,
            RUNNING,
            Some(digest.clone()),
            script_rollback(&digest, RUNNING, detail),
        );

        let (result, said) = run_against(root.path(), &args(), PASSWORD, &pi);

        let error = result.unwrap_err();
        assert_eq!(
            error.to_string(),
            "the new build did not confirm, so the Pi is back on its old one"
        );
        assert_eq!(
            said.lines().last().unwrap(),
            format!("the Pi rolled back to build {RUNNING} on slot a: {detail}")
        );
        // A trial that started and failed is not the firmware ignoring the flag.
        assert!(!said.contains("--software-trial"), "{said}");
    }

    #[test]
    fn a_trial_that_never_started_under_the_firmware_suggests_the_software_trial_and_the_doc() {
        let (root, pem) = ready();
        let digest = digest(root.path());
        let detail = "the trial build never started";
        let pi = Pi::new(
            &pem,
            RUNNING,
            Some(digest.clone()),
            script_rollback(&digest, RUNNING, detail),
        );

        let (result, said) = run_against(root.path(), &args(), PASSWORD, &pi);

        assert!(result.is_err());
        let last = said.lines().last().unwrap();
        assert!(
            last.contains("--software-trial") && last.contains("docs/bring-up/m8-only-os.md"),
            "{said}"
        );
        assert!(
            said.lines().rev().nth(1).unwrap().ends_with(detail),
            "{said}"
        );
    }

    #[test]
    fn a_software_trial_selects_the_new_slot_on_the_card_and_says_so() {
        let (root, pem) = ready();
        let digest = digest(root.path());
        let pi = Pi::new(&pem, RUNNING, Some(digest.clone()), script_confirm(&digest));
        let software = UpdateArgs {
            software_trial: true,
            ..args()
        };

        let (result, said) = run_against(root.path(), &software, PASSWORD, &pi);

        result.unwrap();
        assert_eq!(
            pi.card_file("config.txt"),
            crate::build::slot_config_txt(Slot::B)
        );
        assert!(!pi.card.path().join("tryboot.txt").exists());
        let marker = slots::read_marker(pi.card.path())
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(marker.mode, Mode::Software);
        assert_eq!(
            pi.ctl.restart_receiver().borrow().clone(),
            Some(Restart::Plain(qberrypi::update::Cause::Update))
        );
        assert!(
            said.contains("started by the software trial")
                && said.contains("restarting into the software trial"),
            "{said}"
        );
    }

    #[test]
    fn a_rollback_drill_uploads_the_fault_in_the_copy_forces_the_build_and_wants_the_rollback() {
        for (drill, word) in [(Drill::Panic, "trial_panic"), (Drill::Stall, "trial_stall")] {
            let (root, pem) = ready();
            let digest = digest(root.path());
            // The Pi runs this very build: only a forced update would take it.
            let pi = Pi::new(
                &pem,
                NEW,
                Some(digest.clone()),
                script_rollback(
                    &digest,
                    NEW,
                    "the trial build restarted before it confirmed",
                ),
            );
            let drilling = UpdateArgs {
                rollback_drill: Some(drill),
                ..args()
            };

            let (result, said) = run_against(root.path(), &drilling, PASSWORD, &pi);

            result.unwrap();
            let uploaded = pi.card_file("qberrypi-b/qberrypi.toml");
            let sent = config::parse(&uploaded).unwrap();
            assert_eq!(sent.debug.fault, drill.fault(), "{word}");
            // The file on this computer is as it was.
            let local = fs::read_to_string(root.path().join(CONFIG_FILE)).unwrap();
            assert_eq!(local, api_config());
            assert_eq!(config::parse(&local).unwrap().debug.fault, Fault::None);
            assert!(said.contains(&format!("rollback drill: the copy of qberrypi.toml that is uploaded has debug.fault = \"{word}\"")), "{said}");
            assert!(said.contains("the rollback drill worked"), "{said}");
            assert!(said.contains("the Pi rolled back to build"), "{said}");
            assert!(!said.contains(PASSPHRASE), "{said}");
        }
    }

    /// `script`, whose first reading (the Pi before the update) says it is joined on `mhz`, if it says.
    fn on_channel(mut script: Vec<Step>, mhz: Option<u32>) -> Vec<Step> {
        if let Some(Step::Stats(first)) = script.first_mut() {
            first["wifi"] =
                json!({ "associated": true, "signal_dbm": -60, "ap": null, "freq_mhz": mhz });
        }
        script
    }

    /// The configuration of `ready()` with `hint_mhz = [..]` under `[wifi]`, as the owner may have it.
    fn api_config_with_hint(line: &str) -> String {
        api_config().replacen("[wifi]\n", &format!("[wifi]\n{line}\n"), 1)
    }

    #[test]
    fn the_channel_the_pi_is_on_goes_into_the_uploaded_copy_and_nowhere_else() {
        let (root, pem) = ready();
        let digest = digest(root.path());
        let script = on_channel(script_confirm(&digest), Some(5180));
        let pi = Pi::new(&pem, RUNNING, Some(digest), script);

        let (result, said) = run_against(root.path(), &args(), PASSWORD, &pi);

        result.unwrap();
        let uploaded = pi.card_file("qberrypi-b/qberrypi.toml");
        assert_eq!(config::parse(&uploaded).unwrap().wifi.hint_mhz, [5180]);
        // The one line, and nothing else: the copy is the file as it was, with that line taken out.
        assert_eq!(
            uploaded.replacen("hint_mhz = [5180]\n", "", 1),
            api_config()
        );
        // The file on this computer is as it was.
        assert_eq!(
            fs::read_to_string(root.path().join(CONFIG_FILE)).unwrap(),
            api_config()
        );
        assert!(
            said.contains("gains wifi.hint_mhz = [5180], the channel the Pi is on"),
            "{said}"
        );
        assert!(
            said.contains("unchanged and nothing else differs"),
            "{said}"
        );
        assert!(!said.contains(PASSPHRASE), "{said}");
    }

    #[test]
    fn a_hint_of_the_owners_stays_and_a_pi_that_does_not_say_its_channel_adds_none() {
        for (line, mhz) in [
            (Some("hint_mhz = [2437]"), Some(5180)),
            (Some("hint_mhz = []"), Some(5180)),
            (None, None),
        ] {
            let (root, pem) = ready();
            let text = line.map_or_else(api_config, api_config_with_hint);
            fs::write(root.path().join(CONFIG_FILE), &text).unwrap();
            let digest = digest(root.path());
            let script = on_channel(script_confirm(&digest), mhz);
            let pi = Pi::new(&pem, RUNNING, Some(digest), script);

            let (result, said) = run_against(root.path(), &args(), PASSWORD, &pi);

            result.unwrap();
            assert_eq!(pi.card_file("qberrypi-b/qberrypi.toml"), text, "{line:?}");
            assert!(!said.contains("hint_mhz"), "{line:?}: {said}");
        }
    }

    #[test]
    fn a_channel_that_cannot_be_a_hint_is_said_and_the_update_goes_on_without_it() {
        let (root, pem) = ready();
        let digest = digest(root.path());
        // The Pi reports a frequency that is no channel of the two bands.
        let script = on_channel(script_confirm(&digest), Some(5181));
        let pi = Pi::new(&pem, RUNNING, Some(digest), script);

        let (result, said) = run_against(root.path(), &args(), PASSWORD, &pi);

        result.unwrap();
        assert_eq!(pi.card_file("qberrypi-b/qberrypi.toml"), api_config());
        assert!(
            said.contains(
                "no wifi.hint_mhz is added to the copy of qberrypi.toml that is uploaded"
            ),
            "{said}"
        );
        assert!(said.contains("wifi.hint_mhz"), "{said}");
        assert!(!said.contains(PASSPHRASE), "{said}");
    }

    #[test]
    fn a_2_4_ghz_channel_is_not_added_as_a_hint_and_the_update_says_so() {
        // A hint of 2.4 GHz would not be taken by the Pi, which prefers 5 GHz: the copy is the file.
        for mhz in [2437, 2412, 2484] {
            let (root, pem) = ready();
            let digest = digest(root.path());
            let script = on_channel(script_confirm(&digest), Some(mhz));
            let pi = Pi::new(&pem, RUNNING, Some(digest), script);

            let (result, said) = run_against(root.path(), &args(), PASSWORD, &pi);

            result.unwrap();
            assert_eq!(
                pi.card_file("qberrypi-b/qberrypi.toml"),
                api_config(),
                "{mhz}"
            );
            assert!(
                said.contains(
                    "no wifi.hint_mhz is added to the copy of qberrypi.toml that is uploaded"
                ),
                "{said}"
            );
            assert!(
                said.contains(&format!("{mhz} MHz")) && said.contains("not on the 5 GHz band"),
                "{said}"
            );
            assert!(!said.contains(PASSPHRASE), "{said}");
        }
    }

    #[test]
    fn the_hint_and_the_drill_are_both_in_the_uploaded_copy() {
        let (root, pem) = ready();
        let digest = digest(root.path());
        let script = on_channel(
            script_rollback(
                &digest,
                RUNNING,
                "the trial build restarted before it confirmed",
            ),
            Some(5200),
        );
        let pi = Pi::new(&pem, RUNNING, Some(digest), script);
        let drilling = UpdateArgs {
            rollback_drill: Some(Drill::Panic),
            ..args()
        };

        let (result, _said) = run_against(root.path(), &drilling, PASSWORD, &pi);

        result.unwrap();
        let sent = config::parse(&pi.card_file("qberrypi-b/qberrypi.toml")).unwrap();
        assert_eq!(sent.wifi.hint_mhz, [5200]);
        assert_eq!(sent.debug.fault, Fault::TrialPanic);
    }

    #[test]
    fn the_stats_channel_is_read_when_it_is_a_number_and_is_none_otherwise() {
        let read = |wifi: Value| {
            let mut stats = stats(RUNNING, "a", &"00".repeat(32), 1, idle());
            stats["wifi"] = wifi;
            Seen::from_stats(&stats).unwrap().freq_mhz
        };
        assert_eq!(read(json!({ "freq_mhz": 5180 })), Some(5180));
        assert_eq!(read(json!({ "freq_mhz": null })), None);
        assert_eq!(read(json!({ "freq_mhz": "5180" })), None);
        assert_eq!(read(json!({ "freq_mhz": -1 })), None);
        assert_eq!(read(json!({ "freq_mhz": 99999999999u64 })), None);
        // An old build has no such key, and may have no object at all.
        assert_eq!(read(json!({ "associated": true })), None);
        assert_eq!(read(Value::Null), None);
    }

    #[test]
    fn a_drill_whose_trial_confirms_is_a_failure() {
        let (root, pem) = ready();
        let digest = digest(root.path());
        let pi = Pi::new(&pem, NEW, Some(digest.clone()), script_confirm(&digest));
        let drilling = UpdateArgs {
            rollback_drill: Some(Drill::Stall),
            ..args()
        };

        let (result, said) = run_against(root.path(), &drilling, PASSWORD, &pi);

        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("provoked fault did not act")
        );
        assert!(said.contains("is confirmed on slot b"), "{said}");
    }

    #[test]
    fn a_refusal_of_the_pi_is_reported_in_its_words_and_the_session_is_ended() {
        let (root, pem) = ready();
        let digest = digest(root.path());
        // The Pi believes it runs a newer build than the statistics say, so its receiver refuses.
        let pi = Pi::new(
            &pem,
            NEW + 50,
            Some(digest.clone()),
            script_confirm(&digest),
        );

        let (result, said) = run_against(root.path(), &args(), PASSWORD, &pi);

        let error = format!("{:#}", result.unwrap_err());
        assert!(
            error.starts_with("the Pi refused the update (not_newer: "),
            "{error}"
        );
        assert!(
            !pi.card.path().join("qberrypi-b").exists(),
            "nothing was written"
        );
        let seen = pi.api.seen();
        assert_eq!(seen.last().unwrap(), &format!("DELETE auth sid={}", SID));
        assert!(!said.contains("restarting"), "{said}");
    }

    #[test]
    fn nothing_is_sent_when_the_local_checks_refuse() {
        // Each case is a checkout and arguments that must be refused, and what the error says.
        let cases: Vec<Case> = vec![
            (
                "a development switch",
                Box::new(|root| {
                    let text = api_config().replace("log_to_sd = false", "log_to_sd = true");
                    fs::write(root.join(CONFIG_FILE), text).unwrap();
                }),
                args(),
                "log_to_sd",
            ),
            (
                "debug.one_shot, in the words for this command",
                Box::new(|root| {
                    let text = api_config().replace("one_shot = false", "one_shot = true");
                    fs::write(root.join(CONFIG_FILE), text).unwrap();
                }),
                args(),
                "cargo xtask update with debug.one_shot on",
            ),
            (
                "a provoked fault already in the file, even with a drill",
                Box::new(|root| {
                    let text = api_config().replace("fault = \"none\"", "fault = \"trial_panic\"");
                    fs::write(root.join(CONFIG_FILE), text).unwrap();
                }),
                UpdateArgs {
                    rollback_drill: Some(Drill::Panic),
                    ..args()
                },
                "debug.fault set",
            ),
            (
                "no api section",
                Box::new(|root| fs::write(root.join(CONFIG_FILE), CONFIG).unwrap()),
                args(),
                "no [api] section",
            ),
            (
                "no certificate",
                Box::new(|root| fs::remove_file(root.join(CERT_FILE)).unwrap()),
                args(),
                "cargo xtask make-cert",
            ),
            (
                "no build",
                Box::new(|root| fs::remove_file(root.join("out/build-epoch")).unwrap()),
                args(),
                "cargo xtask build",
            ),
        ];
        for (what, spoil, args, expect) in cases {
            let (root, pem) = ready();
            let digest = digest(root.path());
            let pi = Pi::new(&pem, RUNNING, Some(digest.clone()), script_confirm(&digest));
            spoil(root.path());

            let (result, said) = run_against(root.path(), &args, PASSWORD, &pi);

            let error = format!("{:#}", result.unwrap_err());
            assert!(error.contains(expect), "{what}: {error}");
            assert!(!error.contains("--permanent"), "{what}: {error}");
            assert!(
                !error.contains(PASSPHRASE) && !error.contains(PASSWORD_LINE),
                "{what}: {error}"
            );
            assert_eq!(
                (pi.api.connections(), pi.status.reads(), said.as_str()),
                (0, 0, ""),
                "{what}"
            );
        }
    }

    #[test]
    fn nothing_is_uploaded_when_the_pis_state_or_the_build_rules_it_out() {
        let (root, pem) = ready();
        let digest = digest(root.path());
        let other = "ff".repeat(32);
        let cases = [
            (
                "the old layout",
                vec![Step::Stats(json!({ "build": RUNNING }))],
                args(),
                "no slots",
            ),
            (
                "a trial under way",
                vec![Step::Stats(stats(
                    RUNNING,
                    "a",
                    &digest,
                    9,
                    on_trial(&["wifi"]),
                ))],
                args(),
                "already under way",
            ),
            (
                "a build that is not newer",
                vec![Step::Stats(stats(NEW, "a", &digest, 9, idle()))],
                args(),
                "not newer",
            ),
            (
                "other boot files",
                vec![Step::Stats(stats(RUNNING, "a", &other, 9, idle()))],
                args(),
                "changes the boot files",
            ),
        ];
        for (what, script, args, expect) in cases {
            let pi = Pi::new(&pem, RUNNING, Some(digest.clone()), script);

            let (result, said) = run_against(root.path(), &args, PASSWORD, &pi);

            let error = result.unwrap_err().to_string();
            assert!(
                error.contains(expect) && error.ends_with("nothing was uploaded"),
                "{what}: {error}"
            );
            assert_eq!((pi.api.connections(), said.as_str()), (0, ""), "{what}");
        }
    }

    #[test]
    fn a_new_kernel_goes_when_allowed_and_the_command_says_what_that_risks() {
        let (root, pem) = ready();
        let digest = digest(root.path());
        let other = "ff".repeat(32);
        let script = vec![
            Step::Stats(stats(RUNNING, "a", &other, 5_000, idle())),
            Step::Down,
            Step::Stats(stats(NEW, "b", &digest, 130, confirmed())),
        ];
        // The receiver is told the same digest as the statistics, so it too is for the other kernel.
        let pi = Pi::new(&pem, RUNNING, Some(other), script);
        let allow = UpdateArgs {
            allow_kernel: true,
            ..args()
        };

        let (result, said) = run_against(root.path(), &allow, PASSWORD, &pi);

        result.unwrap();
        assert!(said.contains("cannot be rolled back"), "{said}");
        assert!(pi.card.path().join("qberrypi-b/kernel8.img").is_file());
    }

    #[test]
    fn a_wrong_password_is_one_attempt_and_nothing_is_uploaded() {
        let (root, pem) = ready();
        let digest = digest(root.path());
        let pi = Pi::new(&pem, RUNNING, Some(digest.clone()), script_confirm(&digest));

        let (result, said) = run_against(root.path(), &args(), b"wrong password", &pi);

        assert_eq!(
            result.unwrap_err().to_string(),
            "the Pi refused the password"
        );
        assert_eq!(pi.api.seen(), ["POST auth"]);
        assert!(
            !said.contains("wrong password") && !said.contains("uploading"),
            "{said}"
        );
    }

    #[test]
    fn a_pi_that_never_restarts_is_given_up_on_after_the_wait_with_a_sentence_for_it() {
        let (root, pem) = ready();
        let digest = digest(root.path());
        // The statistics never change: the Pi took the update and nothing happened after it.
        let script = vec![Step::Stats(stats(RUNNING, "a", &digest, 5_000, idle()))];
        let pi = Pi::new(&pem, RUNNING, Some(digest), script);
        let mut wiring = pi.wiring();
        wiring.timing.follow_for = Duration::from_millis(150);
        let mut out = Vec::new();

        let error = update(root.path(), &args(), PASSWORD, &wiring, &mut out).unwrap_err();

        assert!(
            error.to_string().contains("did not restart within"),
            "{error}"
        );
        assert!(pi.status.reads() > 3, "the statistics were followed");
    }

    #[test]
    fn a_password_that_cannot_log_in_is_refused_before_the_pi_is_connected_to() {
        let (root, pem) = ready();
        let digest = digest(root.path());
        let pi = Pi::new(&pem, RUNNING, Some(digest.clone()), script_confirm(&digest));

        let (result, _) = run_against(root.path(), &args(), b"", &pi);

        assert_eq!(result.unwrap_err().to_string(), "the password is empty");
        assert_eq!(pi.api.connections(), 0);
    }

    #[test]
    fn the_body_the_receiver_takes_is_the_manifest_and_the_files_in_its_order() {
        // Not a stand-in: the receiver's own parser reads what `update` builds.
        let (root, _) = ready();
        let build = Build::read(&root.path().join(BOOT_FOLDER)).unwrap();
        let files = build.slot_files(Slot::B, b"[wifi]\n", b"pem");
        let listed: Vec<(&str, &[u8])> = files
            .iter()
            .map(|(n, b)| (n.as_str(), b.as_slice()))
            .collect();
        let mut manifest = Manifest::of_files(NEW, Slot::B, Mode::Software, &listed).unwrap();
        manifest.force = true;
        let head = manifest.head().unwrap();

        let json_len = u32::from_be_bytes(head[..4].try_into().unwrap()) as usize;
        let parsed = Manifest::parse(&head[4..]).unwrap();

        assert_eq!(json_len, head.len() - 4);
        assert_eq!(parsed, manifest);
        let total: u64 = head.len() as u64 + files.iter().map(|(_, b)| b.len() as u64).sum::<u64>();
        assert_eq!(manifest.content_length().unwrap(), total);
        let names: Vec<&str> = parsed.files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, BODY_ORDER);
    }
}
