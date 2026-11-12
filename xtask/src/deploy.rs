//! `cargo xtask deploy` and `collect`: one-shot boots on a card shared with Raspberry Pi OS.
//!
//! The Pi is running Raspberry Pi OS and is reached over SSH. `deploy` copies
//! the build into a fresh directory under `/tmp` there and hands a script to
//! `sudo sh -s`; that script alone writes the boot partition, in this order:
//!
//! 1. Checks: the stage directory and what is in it, the board, the mount, and
//!    that the mount is the partition and the filesystem that init mounts; and
//!    that Raspberry Pi OS's package manager is not running, whose upgrade would
//!    race the deploy. Then a note if the stage lacks `ov-README` or
//!    `ov-qb-piscreen.dtbo`, which the boot firmware reads from qberrypi's folder.
//! 2. Backup: `config.txt` is saved as `config.pios.txt`, unless a saved one
//!    is there already; that one is never written.
//! 3. Backup validation: the saved file must be one qberrypi's init will
//!    copy back, and `config.txt` must be either that file or qberrypi's.
//! 4. Deselect: if `config.txt` selects qberrypi from an earlier deploy, the
//!    saved file is copied back over it first.
//! 5. Copy: the staged files go into the `qberrypi` folder, and a `tls.pem` that an
//!    earlier deploy left there is removed unless this one brings one.
//! 6. Verify: the copies are read back against `SHA256SUMS`.
//! 7. The stage directory is removed.
//! 8. Select: qberrypi's `config.txt` is written over `config.txt`. If that
//!    fails, the saved file is put back.
//! 9. `sync`, then the restart.
//!
//! Up to step 8 the script only ever moves `config.txt` towards Raspberry Pi
//! OS, so a script that stops early leaves a Pi that starts Raspberry Pi OS.
//! Like init, it writes `config.txt` in place and then cuts it to length, so
//! the file is never empty on the way.
//!
//! When `qberrypi.toml` has an `[api]` section, `deploy` also reads the API's key and
//! certificate from `qberrypi-tls.pem` (made once by `cargo xtask make-cert`), refuses a file that
//! qberrypi could not serve, prints the certificate's pin, and stages the file as `tls.pem`, with
//! a line of its own in the staged checksums, so that the script copies it like any other file
//! and reads it back. It is staged in the private folder beside the checksums, which is removed
//! however the deploy ends; the key is never printed, and never enters `out/`. Without an `[api]`
//! section nothing of the kind is staged, and the script takes a `tls.pem` that an earlier deploy
//! left on the card off it (it tells the two cases apart by the staged checksums, which list a
//! `tls.pem` exactly when the section is there): the key has no use any more. It is the script
//! that does it, as root on Raspberry Pi OS, never qberrypi, which does not write the card.
//!
//! When the Pi answers again, `deploy` makes sure that it really went through
//! qberrypi and back. `config.txt` must be the saved one again: if the boot
//! firmware did not take qberrypi's folder, Raspberry Pi OS is running on
//! qberrypi's `config.txt`. And the last boot in the collected log must be of
//! the build that was deployed, by the build time that `cargo xtask build`
//! recorded: otherwise the log is one that an earlier run left. The log must
//! also hold neither the Wi-Fi passphrase nor the key derived from it, and one
//! that does is saved but not shown. While the Pi does not answer SSH, it is
//! pinged at its `net.address`, and the answers are counted: they say whether
//! qberrypi's network was up in the meantime.
//!
//! A permanent deploy (`--permanent`, with every development switch off) does not give
//! the Pi back. After the restart `deploy` waits for SSH to stop answering, and then asks
//! the status page at `net.address` every 2 s until `build` is the one that was deployed,
//! and says how to get the Pi back to Raspberry Pi OS: [`WAY_BACK`].
//!
//! Every external command is built as a program with its arguments by a
//! function of its own and run through a [`Runner`], so tests can read the
//! commands as data and no test reaches a real machine.

use std::ffi::OsString;
use std::fs::{self, OpenOptions, Permissions};
use std::io::{self, ErrorKind, Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Error, Result, anyhow, bail};
use qb_wpa2::pmk::Pmk;
use qberrypi::api::tls;
use qberrypi::bootpart::{self, BOOT_DEV, TLS_FILE_CAP};
use qberrypi::config;
use qberrypi::status;
use tempfile::TempDir;
use zeroize::Zeroizing;

use crate::build::{read_build_epoch, sha256sums};
use crate::cert::CERT_FILE;
use crate::probe::get_stats;

/// The environment variable that names the Pi when `--host` is not given.
pub const HOST_VARIABLE: &str = "QBERRYPI_HOST";

/// The configuration file, in the checkout and in the folder on the card.
const CONFIG_FILE: &str = "qberrypi.toml";
/// The API's key and certificate as the card holds them; `cargo xtask make-cert` makes them in the
/// checkout as `qberrypi-tls.pem`.
const TLS_FILE: &str = bootpart::TLS_FILE;
/// Where `cargo xtask build` leaves the boot folder.
const BUILD_FOLDER: &str = "out/qberrypi";
/// The list of digests that the build writes and the script checks.
const CHECKSUMS: &str = "SHA256SUMS";
/// Files of the folder on the card that are not the build's to list: the configuration and the
/// certificate are the owner's, the checksums are the stage's, and the log is the Pi's.
const NOT_THE_BUILDS: [&str; 4] = [CONFIG_FILE, CHECKSUMS, "log.txt", TLS_FILE];
/// The copy of the Pi's boot partition that the first deploy takes.
const BOOT_BACKUP: &str = "vendor-cache/bootpart-backup.tar";
/// Where `collect` keeps the logs.
const LOG_FOLDER: &str = "out/logs";

/// Where Raspberry Pi OS mounts the boot partition.
const REMOTE_BOOT: &str = "/boot/firmware";
/// The log qberrypi appends to when `debug.log_to_sd` is on.
const REMOTE_LOG: &str = "/boot/firmware/qberrypi/log.txt";
/// The configuration the Pi's boot firmware reads, and the saved one of Raspberry Pi OS.
const REMOTE_ACTIVE: &str = "/boot/firmware/config.txt";
const REMOTE_SAVED: &str = "/boot/firmware/config.pios.txt";
/// Where a Raspberry Pi says which board it is.
const REMOTE_MODEL: &str = "/proc/device-tree/model";
/// What `mktemp` on the Pi makes the stage directory from.
const STAGE_TEMPLATE: &str = "/tmp/qberrypi-stage.XXXXXX";
/// What a stage directory's name starts with; letters and digits follow.
const STAGE_PREFIX: &str = "/tmp/qberrypi-stage.";
/// How the script restarts the Pi.
const RESTART: &str = "systemctl reboot";

/// Given to every `ssh` and `scp`: never ask for a password, never wait long for a Pi that is off.
const SSH_OPTIONS: [&str; 4] = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10"];

/// How long the Pi is given to stop answering after the script restarted it.
const GONE_WITHIN: Duration = Duration::from_secs(30);
/// How long the Pi is given to answer again, at the least.
const BACK_WITHIN_AT_LEAST: Duration = Duration::from_secs(300);
/// What the Pi is given on top of a configured run: time to restart, start Raspberry Pi OS and answer.
const BACK_AFTER_RUN: Duration = Duration::from_secs(180);
/// The pause between two looks at whether the Pi answers.
const POLL: Duration = Duration::from_secs(5);

/// Script status: `config.txt` selects qberrypi and there is no saved configuration.
const ALREADY_SELECTED: i32 = 3;
/// Script status: init would refuse to restore from `config.pios.txt`.
const BACKUP_REFUSED: i32 = 4;
/// Script status: `config.txt` is Raspberry Pi OS's but not the one that was saved.
const CONFIG_CHANGED: i32 = 5;
/// Script status: the stage directory or what is in it is not what `deploy` puts there.
const BAD_STAGE: i32 = 6;
/// Script status: this is not a Raspberry Pi 3 B+ with a mounted boot partition.
const WRONG_MACHINE: i32 = 7;
/// Script status: a file on the card does not match its checksum.
const BAD_COPY: i32 = 8;
/// Script status: `config.txt` could not be written, to select qberrypi or to deselect it.
const CONFIG_NOT_WRITTEN: i32 = 9;
/// Script status: the boot partition is not the device, or not the filesystem, that init mounts.
const WRONG_DEVICE: i32 = 10;

/// Script status: Raspberry Pi OS's package manager is running.
const UPGRADING: i32 = 11;

/// How long a permanent build is given to answer after the restart.
const ANSWER_WITHIN: Duration = Duration::from_secs(180);
/// The pause between two looks at whether a permanent build answers.
const ASK_EVERY: Duration = Duration::from_secs(2);
/// How long one look at the status page of a permanent build may take.
const STATS_TIMEOUT: Duration = Duration::from_secs(2);
/// How to get the Pi back to Raspberry Pi OS once qberrypi stays.
const WAY_BACK: &str = "pull the Pi's power cord (safe for qberrypi), put its card in this computer, \
    run `cargo xtask return-to-pios --boot <where it is mounted>`, eject the card and put it back";

/// The line the script prints once `config.txt` selects qberrypi.
const SELECTED_MARKER: &str = "qberrypi-deploy: qberrypi is selected; restarting";

/// What to do about a Pi that stays away after a one-shot deploy; [`WAY_BACK`] follows it.
const RECOVERY: &str = "If qberrypi started with debug.one_shot on, it has already put Raspberry Pi \
    OS's config.txt back: switch the Pi off and on, and wait.";

/// Checks the local `qberrypi.toml` before anything is sent: it must parse, and it must be a
/// one-shot configuration unless `permanent` says otherwise.
///
/// A configuration that is to stay must have no development switch on: not `debug.one_shot`
/// (which would return the Pi to Raspberry Pi OS at the first restart), nor the log on the card,
/// a return time, the touch calibration or a provoked fault. The first of them in that order is
/// named, and every such error says that nothing was copied.
pub fn check_local(toml_text: &str, permanent: bool) -> Result<(), String> {
    let debug = debug_settings(toml_text)?;
    if permanent {
        return refuse_development_switches(&debug);
    }
    if debug.one_shot {
        return Ok(());
    }
    Err(format!(
        "{CONFIG_FILE} has debug.one_shot off: qberrypi would stay on the Pi and never return to \
         Raspberry Pi OS by itself. Turn debug.one_shot on, or pass --permanent if that is wanted"
    ))
}

/// Refuses a configuration with a development switch on, for a build that is to stay.
fn refuse_development_switches(debug: &config::DebugCfg) -> Result<(), String> {
    let refusal = if debug.one_shot {
        "--permanent with debug.one_shot on would return to Raspberry Pi OS at the first \
         restart: turn debug.one_shot off"
            .to_owned()
    } else if debug.log_to_sd {
        "a permanent qberrypi must not write its log to the card: turn debug.log_to_sd off"
            .to_owned()
    } else if debug.return_after_secs != 0 {
        "a permanent qberrypi with debug.return_after_secs set would restart for ever: set it \
         to 0"
            .to_owned()
    } else if debug.calibrate_touch {
        "debug.calibrate_touch is for one boot of calibration: turn it off".to_owned()
    } else if debug.fault != config::Fault::None {
        format!(
            "{CONFIG_FILE} has debug.fault set: a permanent qberrypi with a provoked failure \
             would restart for ever. Set debug.fault to \"none\""
        )
    } else {
        return Ok(());
    };
    Err(format!("{refusal}; nothing was copied"))
}

/// Reads the bring-up switches, which decide whether and when the Pi comes back.
///
/// The error names the key at fault and never quotes the file.
fn debug_settings(toml_text: &str) -> Result<config::DebugCfg, String> {
    match config::parse(toml_text) {
        Ok(parsed) => Ok(parsed.debug),
        Err(error) => Err(error.to_string()),
    }
}

/// Reads the address the Pi has once qberrypi runs on it.
///
/// The error names the key at fault and never quotes the file.
fn pi_address(toml_text: &str) -> Result<Ipv4Addr, String> {
    match config::parse(toml_text) {
        Ok(parsed) => Ok(parsed.net.address.addr),
        Err(error) => Err(error.to_string()),
    }
}

/// Whether the local `qberrypi.toml` has an `[api]` section, and so whether the Pi serves the API
/// and needs a certificate.
///
/// The error names the key at fault and never quotes the file.
fn has_api(toml_text: &str) -> Result<bool, String> {
    match config::parse(toml_text) {
        Ok(parsed) => Ok(parsed.api.is_some()),
        Err(error) => Err(error.to_string()),
    }
}

/// The API's key and certificate as they are staged, and the pin that qnet is to be given.
struct Certificate {
    /// The bytes of `qberrypi-tls.pem`, which hold the key.
    pem: Zeroizing<Vec<u8>>,
    /// The SHA-256 of the certificate, as `AB:CD:...`.
    pin: String,
}

/// Reads `qberrypi-tls.pem` from the top of the checkout and checks that qberrypi could serve it:
/// that it is no larger than the Pi reads, and that `server_config` takes it.
///
/// No error holds a byte of the file.
fn read_certificate(root: &Path) -> Result<Certificate> {
    let path = root.join(CERT_FILE);
    let file = match fs::File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            bail!("{CONFIG_FILE} has [api] but there is no {CERT_FILE}: run cargo xtask make-cert")
        }
        Err(error) => return Err(error).with_context(|| format!("cannot read {}", path.display())),
    };
    let mut pem = Zeroizing::new(Vec::new());
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
    let digest =
        tls::leaf_sha256(&pem).ok_or_else(|| anyhow!("{CERT_FILE} holds no certificate"))?;
    Ok(Certificate {
        pem,
        pin: tls::pin_text(&digest),
    })
}

/// The secrets of the Wi-Fi network, which no log may hold: the passphrase and
/// the key made from it and the network's name, or else the configured key.
///
/// Keys are in lower-case hex, as a log would show them. The error names the
/// key at fault and never quotes the file.
fn secrets_of(toml_text: &str) -> Result<Vec<String>, String> {
    let parsed = config::parse(toml_text).map_err(|error| error.to_string())?;
    Ok(match &parsed.wifi.key {
        config::WifiKey::Passphrase(passphrase) => {
            let mut secrets = vec![passphrase.expose().to_owned()];
            // The configuration's rules for a passphrase and a name are the derivation's. A file
            // that broke them was refused before this, so only the passphrase is left to look for.
            if let Ok(pmk) = Pmk::from_passphrase(passphrase.expose(), parsed.wifi.ssid.as_bytes())
            {
                secrets.push(
                    pmk.expose()
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect(),
                );
            }
            secrets
        }
        config::WifiKey::Pmk(key) => vec![key.expose().to_ascii_lowercase()],
    })
}

/// Refuses a host that `ssh` or `scp` could take for anything but a host.
fn validate_host(host: &str) -> Result<(), String> {
    let plain = |c: char| c.is_ascii_alphanumeric() || "._-@:".contains(c);
    if host.is_empty() {
        Err("the host is empty".to_owned())
    } else if host.starts_with('-') {
        Err("the host must not start with `-`".to_owned())
    } else if !host.chars().all(plain) {
        Err("the host may hold only letters, digits and . _ - @ :".to_owned())
    } else {
        Ok(())
    }
}

/// Picks the host from `--host` or else from the environment variable; there is no default.
pub fn resolve_host(flag: Option<String>, variable: Option<String>) -> Result<String> {
    let host = flag
        .or(variable.filter(|value| !value.is_empty()))
        .ok_or_else(|| anyhow!("no host: pass --host <ssh-alias> or set {HOST_VARIABLE}"))?;
    validate_host(&host).map_err(Error::msg)?;
    Ok(host)
}

/// Whether a name is the template of `mktemp` with only letters and digits in place of the `X`s.
fn is_stage_dir(name: &str) -> bool {
    name.strip_prefix(STAGE_PREFIX).is_some_and(|random| {
        !random.is_empty() && random.bytes().all(|byte| byte.is_ascii_alphanumeric())
    })
}

/// Reads the stage directory from what `mktemp` printed; anything else is used nowhere.
fn parse_stage_dir(answer: &[u8]) -> Result<String> {
    str::from_utf8(answer)
        .ok()
        .and_then(|text| text.strip_suffix('\n'))
        .filter(|name| is_stage_dir(name))
        .map(str::to_owned)
        .ok_or_else(|| {
            anyhow!(
                "mktemp on the Pi did not answer with a stage directory of its making but with \
                 {:?}; nothing was copied",
                String::from_utf8_lossy(answer)
            )
        })
}

/// One external command: a program and its arguments, never a line for a shell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Invocation {
    pub(crate) program: &'static str,
    pub(crate) args: Vec<OsString>,
}

/// How a command ended and what it wrote.
#[derive(Debug, Clone)]
pub(crate) struct Finished {
    /// The exit status; none when a signal ended the command.
    pub(crate) status: Option<i32>,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

/// Runs external commands. Tests put a recorder in its place.
pub(crate) trait Runner {
    /// Runs the command to its end, feeding it `stdin` if there is any.
    fn run(&mut self, invocation: &Invocation, stdin: Option<&[u8]>) -> io::Result<Finished>;

    /// Asks the status page of the Pi at `address` which build answers there.
    ///
    /// `None` when nothing answers, or what answers does not name a build.
    fn reported_build(&mut self, address: Ipv4Addr) -> Option<u64>;
}

/// Runs the commands for real.
pub(crate) struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&mut self, invocation: &Invocation, stdin: Option<&[u8]>) -> io::Result<Finished> {
        let mut child = Command::new(invocation.program)
            .args(&invocation.args)
            // Without input of its own, ssh would read this terminal.
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let pipe = child.stdin.take();
        let output = thread::scope(|scope| {
            // Fed from a thread of its own: the command may write before it has read it all.
            scope.spawn(move || {
                if let (Some(mut pipe), Some(input)) = (pipe, stdin) {
                    // A command that ends without reading everything says why in its status.
                    let _ = pipe.write_all(input);
                }
            });
            child.wait_with_output()
        })?;
        Ok(Finished {
            status: output.status.code(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    fn reported_build(&mut self, address: Ipv4Addr) -> Option<u64> {
        get_stats((address, status::PORT).into(), STATS_TIMEOUT)
            .ok()?
            .get("build")?
            .as_u64()
    }
}

/// A command for the Pi. `ssh` joins the words with spaces for the shell there,
/// so every word must be one that needs no quoting.
pub(crate) fn ssh(host: &str, remote: &[&str]) -> Invocation {
    let args = SSH_OPTIONS
        .iter()
        .chain(&["--", host])
        .chain(remote)
        .map(OsString::from)
        .collect();
    Invocation {
        program: "ssh",
        args,
    }
}

/// Asks whether the Pi answers over SSH.
fn probe(host: &str) -> Invocation {
    ssh(host, &["true"])
}

/// Sends one packet to the Pi and gives it one second to answer; no name lookup.
fn ping(address: Ipv4Addr) -> Invocation {
    Invocation {
        program: "ping",
        args: ["-n", "-c", "1", "-W", "1"]
            .into_iter()
            .map(OsString::from)
            .chain([address.to_string().into()])
            .collect(),
    }
}

/// How often the Pi was pinged while it did not answer SSH, and how often it answered.
#[derive(Debug, Default, PartialEq)]
struct PingTally {
    sent: u32,
    answered: u32,
}

/// Writes the Pi's whole boot partition to standard output as an archive.
fn save_boot_partition(host: &str) -> Invocation {
    ssh(host, &["tar", "-C", REMOTE_BOOT, "-cf", "-", "."])
}

/// Makes a stage directory that only the SSH user can enter, and prints its name.
fn make_stage(host: &str) -> Invocation {
    ssh(host, &["mktemp", "-d", STAGE_TEMPLATE])
}

/// Copies local files into the stage directory.
fn upload(host: &str, files: &[PathBuf], stage: &str) -> Invocation {
    let mut args: Vec<OsString> = SSH_OPTIONS.iter().map(OsString::from).collect();
    args.push("--".into());
    args.extend(files.iter().map(|file| file.clone().into_os_string()));
    args.push(scp_target(host, &format!("{stage}/")).into());
    Invocation {
        program: "scp",
        args,
    }
}

/// Names a path on the host the way `scp` reads it: an address with colons goes in brackets.
fn scp_target(host: &str, path: &str) -> String {
    let (user, machine) = match host.rsplit_once('@') {
        Some((user, machine)) => (format!("{user}@"), machine),
        None => (String::new(), host),
    };
    if machine.contains(':') {
        format!("{user}[{machine}]:{path}")
    } else {
        format!("{user}{machine}:{path}")
    }
}

/// Runs as root the script it is given on standard input.
fn run_script(host: &str) -> Invocation {
    ssh(host, &["sudo", "sh", "-s"])
}

/// Removes a stage directory; `stage` must have passed [`is_stage_dir`].
fn remove_stage(host: &str, stage: &str) -> Invocation {
    ssh(host, &["rm", "-rf", "--", stage])
}

/// Asks whether `config.txt` on the Pi is the saved configuration of Raspberry Pi OS.
///
/// Status 0 says that it is, status 1 that it is not. Nothing on the Pi is changed.
fn compare_configs(host: &str) -> Invocation {
    ssh(host, &["cmp", "-s", "--", REMOTE_ACTIVE, REMOTE_SAVED])
}

/// Asks whether qberrypi left a log on the card.
fn log_exists(host: &str) -> Invocation {
    ssh(host, &["test", "-f", REMOTE_LOG])
}

/// Writes the log to standard output.
fn fetch_log(host: &str) -> Invocation {
    ssh(host, &["cat", REMOTE_LOG])
}

/// Says how a command ended, for an error.
fn describe(status: Option<i32>) -> String {
    match status {
        Some(255) => "status 255: ssh could not reach the host, or lost it".to_owned(),
        Some(status) => format!("status {status}"),
        None => "ended by a signal".to_owned(),
    }
}

/// Runs a command that must succeed; `what` names it in the error, beside what it wrote.
fn run_to_success(
    runner: &mut dyn Runner,
    invocation: &Invocation,
    what: &str,
) -> Result<Finished> {
    run_fed_to_success(runner, invocation, None, what)
}

/// Runs a command that must succeed, feeding it `stdin` if there is any; `what`
/// names it in the error, beside what it wrote.
pub(crate) fn run_fed_to_success(
    runner: &mut dyn Runner,
    invocation: &Invocation,
    stdin: Option<&[u8]>,
    what: &str,
) -> Result<Finished> {
    let done = runner
        .run(invocation, stdin)
        .with_context(|| format!("cannot run {}", invocation.program))?;
    if done.status != Some(0) {
        bail!(
            "{what} failed ({}): {}",
            describe(done.status),
            String::from_utf8_lossy(&done.stderr).trim_end()
        );
    }
    Ok(done)
}

/// Reads the build's checksums and adds a line for the configuration, and after it one for the
/// certificate when there is one.
///
/// Returns the files the build lists, in its order, and the text for the
/// stage. The list is refused unless every line is a digest and a plain file
/// name, as `cargo xtask build` writes them, and `config.txt` is among them.
/// The configuration and the certificate are not the build's, so a build that
/// lists either is refused.
fn staged_checksums(
    build_sums: &str,
    toml: &[u8],
    certificate: Option<&[u8]>,
) -> Result<(Vec<String>, String)> {
    let not_the_builds = || {
        anyhow!("{BUILD_FOLDER}/{CHECKSUMS} is not as the build wrote it: run `cargo xtask build`")
    };
    let lines = build_sums.strip_suffix('\n').ok_or_else(not_the_builds)?;
    let mut names: Vec<String> = Vec::new();
    for line in lines.split('\n') {
        let (digest, name) = line.split_once("  ").ok_or_else(not_the_builds)?;
        let is_digest = digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        let is_plain_name = name.starts_with(|first: char| first.is_ascii_alphanumeric())
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c));
        let is_new = !NOT_THE_BUILDS.contains(&name) && !names.iter().any(|seen| seen == name);
        if !(is_digest && is_plain_name && is_new) {
            return Err(not_the_builds());
        }
        names.push(name.to_owned());
    }
    if !names.iter().any(|name| name == "config.txt") {
        return Err(not_the_builds());
    }
    let mut added = vec![(CONFIG_FILE, toml)];
    added.extend(certificate.map(|pem| (TLS_FILE, pem)));
    let staged = format!("{build_sums}{}", sha256sums(&added));
    Ok((names, staged))
}

/// Makes a temporary folder that only this user can enter; it is removed when dropped.
fn private_temp_dir() -> Result<TempDir> {
    tempfile::Builder::new()
        .prefix("qberrypi-deploy.")
        .permissions(Permissions::from_mode(0o700))
        .tempdir()
        .context("cannot make a temporary folder")
}

/// Writes a new file that only this user can read. A file that is already there is
/// an error and stays as it is.
pub(crate) fn write_private_new(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    if let Err(error) = file.write_all(data).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error).with_context(|| format!("cannot write {}", path.display()));
    }
    Ok(())
}

/// Saves the archive of the boot partition, which can hold the owner's credentials.
///
/// The file appears under its name only when it is complete, and never in place of another.
fn save_boot_backup(path: &Path, archive: &[u8]) -> Result<()> {
    if let Some(folder) = path.parent() {
        fs::create_dir_all(folder)
            .with_context(|| format!("cannot create {}", folder.display()))?;
    }
    let part = path.with_extension("tar.part");
    match fs::remove_file(&part) {
        Err(error) if error.kind() != ErrorKind::NotFound => {
            return Err(error).with_context(|| format!("cannot remove {}", part.display()));
        }
        _ => {}
    }
    write_private_new(&part, archive)?;
    // A link fails where a rename would replace.
    let linked = fs::hard_link(&part, path);
    let _ = fs::remove_file(&part);
    linked.with_context(|| format!("cannot create {}", path.display()))
}

/// The script that installs a staged build on the Pi's boot partition and selects it.
pub struct RemoteScript {
    /// Where the boot partition is mounted.
    pub boot_dir: String,
    /// The directory `mktemp` made, holding the build, the configuration and the checksums.
    pub stage_dir: String,
    /// The shell command that restarts the Pi.
    pub reboot_cmd: String,
    /// Whether to insist on a Raspberry Pi 3 B+ with `boot_dir` a mount point, and to
    /// read the copies back from the card rather than from memory.
    pub hardware_checks: bool,
    /// The file in which the machine says which board it is; read only for the hardware checks.
    pub model_file: String,
}

impl RemoteScript {
    /// Writes the script out: POSIX `sh`, to be run as root.
    pub fn render(&self) -> String {
        let boot = sh_quote(&self.boot_dir);
        let stage = sh_quote(&self.stage_dir);
        let model_file = sh_quote(&self.model_file);
        let boot_device = sh_quote(BOOT_DEV);
        let hardware_checks = if self.hardware_checks { "yes" } else { "no" };
        let restart = &self.reboot_cmd;
        format!(
            "{SCRIPT_HEAD}\n\
             boot={boot}\n\
             stage={stage}\n\
             hardware_checks={hardware_checks}\n\
             model_file={model_file}\n\
             boot_device={boot_device}\n\
             \n\
             already_selected={ALREADY_SELECTED}\n\
             backup_refused={BACKUP_REFUSED}\n\
             config_changed={CONFIG_CHANGED}\n\
             bad_stage={BAD_STAGE}\n\
             wrong_machine={WRONG_MACHINE}\n\
             bad_copy={BAD_COPY}\n\
             config_not_written={CONFIG_NOT_WRITTEN}\n\
             wrong_device={WRONG_DEVICE}\n\
             upgrading={UPGRADING}\n\
             \n\
             restart() {{\n    {restart}\n}}\n\
             {SCRIPT_BODY}"
        )
    }
}

/// Quotes a text so that `sh` reads it as one word, whatever it holds.
fn sh_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// The first lines of the script; the values of one deploy follow them.
const SCRIPT_HEAD: &str = r"#!/bin/sh
# Installs a staged qberrypi build on the boot partition that is shared with
# Raspberry Pi OS, and selects it for the next start. Written by
# `cargo xtask deploy`, which runs it as root: ssh <host> sudo sh -s
#
# In this order, stopping at the first thing that is not as expected:
#   1. Checks: the stage directory and its files, the board, the mount and
#      the device that is mounted there, and that Raspberry Pi OS's package
#      manager is not running. Then a note if the stage lacks ov-README or
#      ov-qb-piscreen.dtbo, which the boot firmware reads from qberrypi's folder.
#   2. Backup: config.txt is saved as config.pios.txt, unless a saved one is
#      there already. That one is never written.
#   3. Backup validation: init must be able to restore from config.pios.txt,
#      and config.txt must be either that file or qberrypi's.
#   4. Deselect: if config.txt selects qberrypi from an earlier deploy,
#      config.pios.txt is copied back over it.
#   5. Copy: the staged files go into the qberrypi folder, and a tls.pem that
#      an earlier deploy left there is removed unless this one brings one.
#   6. Verify: the copies are read back against SHA256SUMS.
#   7. The stage directory is removed.
#   8. Select: qberrypi's config.txt is written over config.txt. If that
#      fails, config.pios.txt is put back.
#   9. sync, then the restart.
# Before step 8, config.txt is only ever moved towards Raspberry Pi OS. It is
# always written in place and then cut to length, never emptied first.
#
# The work is done by main, which the last line calls: a script that arrives
# cut short does nothing.
set -eu
LC_ALL=C
export LC_ALL
";

/// The script proper. It takes everything it needs from the variables set before it.
const SCRIPT_BODY: &str = r##"
say() {
    printf 'qberrypi-deploy: %s\n' "$*"
}

# Stops the script with the status given first; the rest is the reason.
die() {
    status=$1
    shift
    printf 'qberrypi-deploy: stopped: %s\n' "$*" >&2
    exit "$status"
}

# Looks for an uncommented line that selects qberrypi, the way init does.
# Status 0: there is one. Status 1: there is none. Higher: the file cannot be read.
selects_qberrypi() {
    grep -q '^[[:space:]]*os_prefix=qberrypi/' "$1"
}

# Succeeds only when init would restore the configuration of Raspberry Pi OS
# from this file; otherwise fails and leaves the reason in $reason. The rules
# are those of restore_pios_config in crates/qberrypi/src/bootpart.rs.
restorable() {
    reason='is missing'
    [ -f "$1" ] || return 1
    reason='cannot be read'
    bytes=$(wc -c <"$1") || return 1
    bytes_not_nul=$(tr -d '\000' <"$1" | wc -c) || return 1
    bytes_not_blank=$(tr -d ' \t\n\f\r' <"$1" | wc -c) || return 1
    reason='is empty'
    [ "$bytes_not_blank" -gt 0 ] || return 1
    reason='is not text: it holds a NUL byte'
    [ "$bytes" -eq "$bytes_not_nul" ] || return 1
    found=0
    selects_qberrypi "$1" || found=$?
    reason='selects qberrypi'
    [ "$found" -ne 0 ] || return 1
    reason='cannot be read'
    [ "$found" -eq 1 ] || return 1
    reason=
}

# Makes config.txt hold what the file "$1" holds, the way init does it: the new
# bytes go over the old ones and only then is an old tail cut off. The file is
# at no moment empty and keeps its place on the card, which a copy that
# empties it first would not promise. Then the card is synced and the file
# read back. Fails if any of that does, or if "$1" is empty. dd is told not to
# print its count of records; what it says when it fails is let through.
write_config() {
    # Without the blanks that some versions of wc put before the number.
    new_size=$(wc -c <"$1" | tr -d ' \t')
    [ "$new_size" -gt 0 ] || return 1
    dd if="$1" of="$active" conv=notrunc status=none || return 1
    truncate -s "$new_size" "$active" || return 1
    sync || return 1
    cmp -s -- "$1" "$active"
}

# Whether the stage brings an API certificate: whether its checksums list a
# tls.pem, which they do exactly when qberrypi.toml has an [api] section.
# Status 0: it does. Status 1: it does not. Higher: the list cannot be read.
brings_certificate() {
    grep -q "^[0-9a-f]\{64\}  tls\.pem\$" "$stage/SHA256SUMS"
}

# Takes the API's key and certificate of an earlier deploy off the card. It is
# done when this deploy brings none: qberrypi would not serve the API without
# the section, and the file holds a private key that nothing uses any more. Says
# what it removes, by name, and never what is in it. Fails if the file is still
# there afterwards.
drop_stale_certificate() {
    [ -e "$own/tls.pem" ] || [ -L "$own/tls.pem" ] || return 0
    say "removing $own/tls.pem: this configuration has no [api] section, so qberrypi will not read it"
    rm -f -- "$own/tls.pem" || return 1
    [ ! -e "$own/tls.pem" ] && [ ! -L "$own/tls.pem" ]
}

# Copies the staged files into the folder on the card, takes off it the
# certificate of an earlier deploy if this one has none, and reads the copies
# back against the checksums. Fails if any step does.
copy_and_check() {
    mkdir -p -- "$own" || return 1
    cp -- "$stage"/* "$own/" || return 1
    certificate=0
    brings_certificate || certificate=$?
    # A list that cannot be read (status above 1) removes nothing; the check below fails on it.
    if [ "$certificate" -eq 1 ]; then
        drop_stale_certificate || return 1
    fi
    sync || return 1
    if [ "$hardware_checks" = yes ]; then
        # Otherwise the check would read what is still in memory, not what reached the card.
        echo 1 >/proc/sys/vm/drop_caches ||
            say "note: the page cache could not be emptied; the check may not read the card itself"
    fi
    (cd -- "$own" && sha256sum --check --strict SHA256SUMS)
}

main() {
    active="$boot/config.txt"
    backup="$boot/config.pios.txt"
    own="$boot/qberrypi"

    # 1. Checks. Until all of them have passed, nothing is written anywhere.
    case "$stage" in
        /tmp/qberrypi-stage.*) ;;
        *) die "$bad_stage" "the stage directory is not one that mktemp made for this; nothing was changed" ;;
    esac
    random_part=${stage#/tmp/qberrypi-stage.}
    case "$random_part" in
        '' | *[!A-Za-z0-9]*) die "$bad_stage" "the stage directory is not one that mktemp made for this; nothing was changed" ;;
    esac
    [ ! -L "$stage" ] || die "$bad_stage" "$stage is a link; nothing was changed"
    [ -d "$stage" ] || die "$bad_stage" "$stage is not a directory; nothing was changed"

    # The stage holds a copy of the Wi-Fi passphrase, and of the API's private key when there is
    # one: however this ends, it goes.
    trap 'rm -rf -- "$stage"' EXIT
    trap 'exit 129' HUP INT PIPE TERM

    [ -f "$stage/SHA256SUMS" ] || die "$bad_stage" "there is no SHA256SUMS in $stage; nothing was changed"
    [ -f "$stage/config.txt" ] || die "$bad_stage" "there is no config.txt in $stage; nothing was changed"
    for staged in "$stage"/*; do
        name=${staged##*/}
        [ -f "$staged" ] || die "$bad_stage" "$name in $stage is not a file; nothing was changed"
        case "$name" in
            *[!A-Za-z0-9._-]*) die "$bad_stage" "$name in $stage is not a name the build gives a file; nothing was changed" ;;
        esac
        if [ "$name" != SHA256SUMS ]; then
            grep -q "^[0-9a-f]\{64\}  $name\$" "$stage/SHA256SUMS" ||
                die "$bad_stage" "$name is not listed in SHA256SUMS, so its copy could not be checked; nothing was changed"
        fi
    done

    [ -d "$boot" ] || die "$wrong_machine" "$boot is not a directory; nothing was changed"
    if [ "$hardware_checks" = yes ]; then
        [ -r "$model_file" ] ||
            die "$wrong_machine" "this machine does not say which board it is; nothing was changed"
        model=$(tr -d '\000' <"$model_file")
        case "$model" in
            *'Raspberry Pi 3 Model B Plus'*) ;;
            *) die "$wrong_machine" "this is not a Raspberry Pi 3 Model B Plus but a $model; nothing was changed" ;;
        esac
        mountpoint -q "$boot" || die "$wrong_machine" "$boot is not a mount point; nothing was changed"
        # Init mounts $boot_device as vfat and looks nowhere else. Were $boot any
        # other partition, init would find neither its configuration nor the
        # saved config.txt there, and the Pi would start qberrypi for good.
        command -v findmnt >/dev/null 2>&1 ||
            die "$wrong_device" "there is no findmnt here to say which device $boot is; nothing was changed"
        mounted=$(findmnt -no SOURCE,FSTYPE "$boot") ||
            die "$wrong_device" "findmnt could not say which device $boot is; nothing was changed"
        [ "$mounted" = "$boot_device vfat" ] ||
            die "$wrong_device" "$boot is not $boot_device mounted as vfat, which is the one partition qberrypi reads and restores. Nothing was changed. findmnt found there: $mounted"
    fi

    # Raspberry Pi OS may be in the middle of replacing the kernel, the overlays
    # or config.txt: this deploy would race it. Nothing has been written yet.
    for p in apt apt-get dpkg; do
        if pgrep -x "$p" >/dev/null 2>&1; then
            die "$upgrading" "Raspberry Pi OS is installing updates ($p is running); try again when it has finished. Nothing was changed"
        fi
    done
    # The upgrade worker cannot be found by its name: it shares it with the
    # daemon that unattended-upgrades keeps running when nothing is being
    # upgraded, so a search by name would refuse every deploy. Its command
    # line tells them apart. The bracket keeps this line from matching the
    # command line of any shell that was given the script as text.
    if pgrep -f '/usr/bin/unattended-upgrad[e]( |$)' >/dev/null 2>&1; then
        die "$upgrading" "Raspberry Pi OS is installing updates (unattended-upgrade is running); try again when it has finished. Nothing was changed"
    fi

    # qberrypi's config.txt names the touchscreen's overlay by qberrypi's own
    # prefix, ov-: the boot firmware reads qberrypi/ov-README and
    # qberrypi/ov-qb-piscreen.dtbo, which this stage brings. Without them the
    # screen stays dark and everything else runs, so this stops nothing; the
    # build always has them, so it only catches a stage made by hand.
    if [ ! -f "$stage/ov-README" ] || [ ! -f "$stage/ov-qb-piscreen.dtbo" ]; then
        say "note: the build carries no overlay of its own: the front panel will stay dark"
    fi

    # 2. Backup. A saved configuration that is there is never written.
    if [ ! -s "$backup" ]; then
        if ! restorable "$active"; then
            if [ "$reason" = 'selects qberrypi' ]; then
                die "$already_selected" "config.txt already selects qberrypi and there is no config.pios.txt: the configuration of Raspberry Pi OS is not on the card to be saved. Put it back as $active and deploy again; nothing was changed"
            fi
            die "$backup_refused" "config.txt $reason, and init would refuse to restore a config.pios.txt made from it; nothing was changed"
        fi
        say "saving config.txt as config.pios.txt"
        cp -- "$active" "$backup.new"
        cmp -s -- "$active" "$backup.new" ||
            die "$backup_refused" "the copy of config.txt does not read back the same; config.txt was not changed"
        # The copy is on the card before it gets the name, so the name never
        # stands for bytes that were not written yet.
        sync
        mv -- "$backup.new" "$backup"
        sync
    fi

    # 3. Backup validation. Whether saved just now or long ago: init must be
    # able to restore from it.
    if ! restorable "$backup"; then
        refused="config.pios.txt $reason, so qberrypi could not hand the Pi back to Raspberry Pi OS"
        if selects_qberrypi "$active"; then
            die "$backup_refused" "$refused. And config.txt selects qberrypi since an earlier deploy: the next restart would start it for good. Before the Pi restarts, put the configuration of Raspberry Pi OS back as $active; nothing was changed"
        fi
        die "$backup_refused" "$refused. If $active is the configuration of Raspberry Pi OS, delete $backup and deploy again; nothing was changed"
    fi

    selected=0
    selects_qberrypi "$active" || selected=$?
    if [ "$selected" -ne 0 ]; then
        # A config.txt that does not select qberrypi is the one of Raspberry Pi
        # OS, and init will put the saved one in its place. Unless the two are
        # the same, that would lose what was changed since.
        cmp -s -- "$active" "$backup" ||
            die "$config_changed" "config.txt is not what config.pios.txt saved, and after its run qberrypi would put the saved one back. To keep the one in config.txt, run on the Pi: sudo rm $backup, then deploy again, which saves it afresh. To go back to the saved one, run on the Pi: sudo cp $backup $active, then deploy again. Nothing was changed"
    else
        # 4. Deselect. An earlier deploy selected qberrypi and the Pi has not
        # restarted since. Its folder is about to be replaced, so the saved
        # configuration goes back first: from here to step 8 a restart, or a
        # stop of this script, leaves Raspberry Pi OS.
        say "config.txt selects qberrypi from an earlier deploy; putting config.pios.txt back while the build is replaced"
        write_config "$backup" ||
            die "$config_not_written" "the saved configuration could not be put back: config.txt may still select qberrypi, or may be damaged. The folder $own was not touched. Before the Pi restarts, put the saved one back, on the Pi: sudo cp $backup $active"
    fi

    # 5 and 6. Copy and verify. The build goes beside whatever the folder holds
    # already (the log of earlier runs), and is read back before anything
    # depends on it.
    say "copying the build to $own"
    copy_and_check ||
        die "$bad_copy" "the build in $own is not complete or does not match SHA256SUMS. config.txt is the configuration of Raspberry Pi OS, so the next restart is Raspberry Pi OS"

    # 7. The stage is done with; no copy of the passphrase or the key stays in /tmp.
    rm -rf -- "$stage"

    # 8. Select. From here on the next start is qberrypi.
    say "selecting qberrypi"
    if ! write_config "$own/config.txt"; then
        if write_config "$backup"; then
            die "$config_not_written" "config.txt could not be made to select qberrypi. The saved configuration was put back and reads back the same, so the next restart is Raspberry Pi OS"
        fi
        die "$config_not_written" "config.txt could not be made to select qberrypi, and putting the saved configuration back failed too: config.txt may be damaged. Before the Pi restarts, put the saved one back, on the Pi: sudo cp $backup $active"
    fi
    say "qberrypi is selected; restarting"

    # 9. The restart.
    sync
    restart
} </dev/null

main
"##;

/// Judges the run of the script from its status and from whether it said that it selected qberrypi.
fn script_outcome(host: &str, ran: &Finished) -> Result<()> {
    let selected = String::from_utf8_lossy(&ran.stdout)
        .lines()
        .any(|line| line == SELECTED_MARKER);
    match (ran.status, selected) {
        // The restart can take the connection away before the script has ended.
        (Some(0 | 255), true) => Ok(()),
        (Some(status), true) => bail!(
            "qberrypi is selected on {host}, but the script then stopped with status {status} \
             and may not have restarted the Pi: it will start qberrypi the next time it restarts"
        ),
        (Some(0), false) => bail!(
            "the install script on {host} ended without saying that it selected qberrypi; \
             it cannot have run as written"
        ),
        (Some(255), false) => bail!(
            "ssh could not reach {host}, or lost it before the install script said that it \
             selected qberrypi. What the script said, if anything, is above; if it had begun, \
             config.txt may select qberrypi already. Deploy again when the Pi answers"
        ),
        (Some(status), false) => bail!(
            "the install script on {host} stopped with status {status}; what it said is above"
        ),
        (None, _) => bail!(
            "ssh to {host} was ended by a signal; how far the install script got is not known"
        ),
    }
}

/// Judges, from the comparison of `config.txt` with the saved one, whether the Pi is back as it should be.
///
/// Raspberry Pi OS answering is not enough. The boot firmware starts its
/// kernel whenever it cannot use qberrypi's folder, and then nothing has put
/// `config.txt` back.
fn check_returned(host: &str, compared: &Finished) -> Result<()> {
    match compared.status {
        Some(0) => Ok(()),
        Some(1) => bail!(
            "{host} is running Raspberry Pi OS on qberrypi's configuration: {REMOTE_ACTIVE} is \
             not the saved {REMOTE_SAVED}. Either the Pi did not restart, or its boot firmware \
             started Raspberry Pi OS's kernel in place of qberrypi's, or qberrypi could not put \
             the file back. No log was collected. To put the configuration of Raspberry Pi OS \
             back, run: ssh {host} sudo cp {REMOTE_SAVED} {REMOTE_ACTIVE}"
        ),
        status => bail!(
            "comparing {REMOTE_ACTIVE} with {REMOTE_SAVED} on {host} failed ({}), so it is not \
             known whether the Pi went through qberrypi and back: {}",
            describe(status),
            String::from_utf8_lossy(&compared.stderr).trim_end()
        ),
    }
}

/// Checks that the last boot in a collected log was one of the build that was deployed.
///
/// The log on the card is added to by every run, so one from an earlier run
/// is there to be fetched when this run saved none.
fn check_log_is_of(log: &str, build_epoch: u64) -> Result<()> {
    /// When qberrypi leaves a log at all.
    const WHEN: &str = "qberrypi saves its log with debug.log_to_sd on, and in one-shot mode \
                        also when it stops on an error";
    match bootpart::last_boot_build(log) {
        Some(build) if build == build_epoch => Ok(()),
        Some(build) => bail!(
            "the last boot in the log is of build {build}, and the build deployed is \
             {build_epoch}: this run left no log, and the one on the card is from an earlier \
             run. {WHEN}"
        ),
        None => bail!(
            "the log has no boot header (`==== boot, build N ====`), so it cannot be told \
             whether it is of this run, of build {build_epoch}. {WHEN}"
        ),
    }
}

/// Checks that a collected log holds none of the secrets.
///
/// A passphrase is looked for as it is. A key, which is hex, is looked for in
/// either case. The error never repeats a secret.
fn check_log_has_no_secret(log: &str, secrets: &[String]) -> Result<()> {
    let lowered = log.to_lowercase();
    let is_key = |secret: &str| secret.len() == 64 && secret.bytes().all(|b| b.is_ascii_hexdigit());
    let held = secrets.iter().any(|secret| {
        log.contains(secret.as_str())
            || (is_key(secret) && lowered.contains(&secret.to_ascii_lowercase()))
    });
    if held {
        bail!("the log holds the Wi-Fi passphrase or key");
    }
    Ok(())
}

/// Refuses a saved log that holds a secret, as `deploy` and `collect` both do.
///
/// The error names the file to delete and never repeats a secret.
fn refuse_secret(log: &str, secrets: &[String], saved: &Path) -> Result<()> {
    check_log_has_no_secret(log, secrets)
        .map_err(|refused| anyhow!("{refused}; delete {} and report this", saved.display()))
}

/// Tells the time and waits. Tests put a clock in its place that does not wait.
trait Clock {
    /// The time since some fixed moment.
    fn now(&self) -> Duration;
    /// Waits this long.
    fn sleep(&mut self, time: Duration);
    /// The time in seconds since 1970.
    fn unix_time(&self) -> Result<u64>;
}

/// The clock of this machine.
struct SystemClock {
    start: Instant,
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.start.elapsed()
    }

    fn sleep(&mut self, time: Duration) {
        thread::sleep(time);
    }

    fn unix_time(&self) -> Result<u64> {
        crate::unix_time()
    }
}

/// How the Pi came back after the script restarted it.
#[derive(Debug, PartialEq)]
enum Returned {
    /// It stopped answering and then answered again.
    AfterRestart,
    /// It was never seen to stop answering.
    WithoutGoingDown,
}

/// How long the Pi is given to answer again, for a run of `return_after_secs`.
///
/// The run is when qberrypi restarts the Pi by itself, counted from the start
/// of its boot, and 0 means it does not. The Pi is given the run and 180 s
/// after it, and in any case 300 s.
fn back_within(return_after_secs: u64) -> Duration {
    Duration::from_secs(return_after_secs)
        .saturating_add(BACK_AFTER_RUN)
        .max(BACK_WITHIN_AT_LEAST)
}

/// Waits for the Pi to stop answering and then to answer again.
///
/// `answering` asks the Pi once. A Pi that is not seen to go down within 30 s
/// is still waited for; one that does not answer again within `back_within`
/// is an error that says how to recover.
fn wait_for_return(
    answering: &mut dyn FnMut() -> bool,
    back_within: Duration,
    clock: &mut dyn Clock,
) -> Result<Returned> {
    let went_down = wait_until(false, GONE_WITHIN, answering, clock);
    if !wait_until(true, back_within, answering, clock) {
        bail!(
            "it did not answer again within {} s. {RECOVERY} If it still stays away: {WAY_BACK}",
            back_within.as_secs()
        );
    }
    Ok(if went_down {
        Returned::AfterRestart
    } else {
        Returned::WithoutGoingDown
    })
}

/// Waits for the permanent build to answer on its status page.
///
/// `build_seen` asks once and returns the `build` that the page reports; one that is another
/// number than `build_epoch` is another build, and the wait goes on. The question is asked
/// every 2 s, for up to 180 s. Returns how long the wait took. The error says what to do for a
/// Pi that did not answer.
fn wait_for_qberrypi(
    build_seen: &mut dyn FnMut() -> Option<u64>,
    build_epoch: u64,
    clock: &mut dyn Clock,
) -> Result<Duration> {
    let start = clock.now();
    let mut other = None;
    loop {
        let seen = build_seen();
        if seen == Some(build_epoch) {
            return Ok(clock.now().saturating_sub(start));
        }
        other = seen.or(other);
        if clock.now().saturating_sub(start) >= ANSWER_WITHIN {
            let last = match other {
                Some(build) => format!(" (the last build it reported was {build})"),
                None => String::new(),
            };
            bail!(
                "the Pi did not answer as qberrypi build {build_epoch} within {} s of the \
                 restart{last}. To return to Raspberry Pi OS: {WAY_BACK}",
                ANSWER_WITHIN.as_secs()
            );
        }
        clock.sleep(ASK_EVERY);
    }
}

/// Asks every 5 s until the answer is the wanted one; gives up, with `false`, after `limit`.
fn wait_until(
    wanted: bool,
    limit: Duration,
    answering: &mut dyn FnMut() -> bool,
    clock: &mut dyn Clock,
) -> bool {
    let start = clock.now();
    loop {
        if answering() == wanted {
            return true;
        }
        if clock.now().saturating_sub(start) >= limit {
            return false;
        }
        clock.sleep(POLL);
    }
}

/// Copies the build to the Pi, selects qberrypi for one boot, restarts the Pi,
/// waits for it to return to Raspberry Pi OS, checks that it did so through
/// qberrypi, and collects the log, which must be this build's and must hold
/// no Wi-Fi secret.
pub fn deploy(host: &str, permanent: bool, root: &Path) -> Result<()> {
    let mut clock = SystemClock {
        start: Instant::now(),
    };
    deploy_with(
        host,
        permanent,
        root,
        &mut SystemRunner,
        &mut clock,
        &mut io::stdout(),
    )
}

/// `deploy`, with the commands, the clock and the output in the caller's hands.
fn deploy_with(
    host: &str,
    permanent: bool,
    root: &Path,
    runner: &mut dyn Runner,
    clock: &mut dyn Clock,
    out: &mut dyn Write,
) -> Result<()> {
    validate_host(host).map_err(Error::msg)?;
    // scp takes a file name with a colon before its first slash for a host; absolute paths have none.
    let root =
        fs::canonicalize(root).with_context(|| format!("cannot resolve {}", root.display()))?;

    // The text of this file holds the Wi-Fi passphrase: it goes into no message.
    let toml_path = root.join(CONFIG_FILE);
    let toml = fs::read_to_string(&toml_path).with_context(|| {
        format!(
            "cannot read {} (qberrypi.example.toml is the template)",
            toml_path.display()
        )
    })?;
    check_local(&toml, permanent).map_err(Error::msg)?;
    let debug = debug_settings(&toml).map_err(Error::msg)?;
    let address = pi_address(&toml).map_err(Error::msg)?;
    let secrets = secrets_of(&toml).map_err(Error::msg)?;
    // The file holds the API's private key: nothing of it goes into a message.
    let certificate = if has_api(&toml).map_err(Error::msg)? {
        Some(read_certificate(&root)?)
    } else {
        None
    };
    if debug.one_shot && debug.return_after_secs == 0 {
        writeln!(
            out,
            "deploy: {host}: note: debug.return_after_secs is 0, so qberrypi will not restart by \
             itself. This command will stop waiting after {} s; the Pi returns to Raspberry Pi \
             OS when it is switched off and on",
            BACK_WITHIN_AT_LEAST.as_secs()
        )?;
    }

    let build = root.join(BUILD_FOLDER);
    let sums_path = build.join(CHECKSUMS);
    let build_sums = match fs::read_to_string(&sums_path) {
        Ok(text) => text,
        Err(error) if error.kind() == ErrorKind::NotFound => bail!(
            "{} is missing: run `cargo xtask build` first",
            sums_path.display()
        ),
        Err(error) => {
            return Err(error).with_context(|| format!("cannot read {}", sums_path.display()));
        }
    };
    let (names, staged_sums) = staged_checksums(
        &build_sums,
        toml.as_bytes(),
        certificate.as_ref().map(|found| found.pem.as_slice()),
    )?;
    // By this the log that comes back is told from one an earlier run left.
    let build_epoch = read_build_epoch(&root)?;
    let mut files = Vec::new();
    for name in &names {
        let file = build.join(name);
        if !file.is_file() {
            bail!(
                "{} is listed in {CHECKSUMS} but is not there: run `cargo xtask build` again",
                file.display()
            );
        }
        files.push(file);
    }

    // The checksums for the stage are a file of their own; the build's stay as they are.
    let scratch = private_temp_dir()?;
    let scratch_path = fs::canonicalize(scratch.path())
        .with_context(|| format!("cannot resolve {}", scratch.path().display()))?;
    let staged_sums_path = scratch_path.join(CHECKSUMS);
    fs::write(&staged_sums_path, staged_sums)
        .with_context(|| format!("cannot write {}", staged_sums_path.display()))?;
    files.push(staged_sums_path);
    files.push(toml_path);
    if let Some(found) = &certificate {
        // Beside the checksums, in the folder that only this user enters, and gone with it.
        let staged_pem = scratch_path.join(TLS_FILE);
        write_private_new(&staged_pem, &found.pem)?;
        files.push(staged_pem);
        writeln!(
            out,
            "deploy: {host}: the API's certificate pin (SHA-256): {}",
            found.pin
        )?;
    }

    let backup = root.join(BOOT_BACKUP);
    match fs::symlink_metadata(&backup) {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {
            writeln!(
                out,
                "deploy: {host}: saving its boot partition to {BOOT_BACKUP} (the first deploy from this checkout)"
            )?;
            let saved = run_to_success(
                runner,
                &save_boot_partition(host),
                "saving the boot partition",
            )?;
            if saved.stdout.is_empty() {
                bail!("saving the boot partition failed: {host} sent nothing");
            }
            save_boot_backup(&backup, &saved.stdout)?;
        }
        Err(error) => {
            return Err(error).with_context(|| format!("cannot look at {}", backup.display()));
        }
    }

    writeln!(out, "deploy: {host}: making a stage directory under /tmp")?;
    let made = run_to_success(runner, &make_stage(host), "making a stage directory")?;
    let stage = parse_stage_dir(&made.stdout)?;

    let installed = install(host, &stage, &files, runner, out);
    if installed.is_err() {
        // The stage holds the passphrase and the API's key. The script removes it, but may not
        // have run.
        let _ = writeln!(out, "deploy: {host}: removing the stage directory");
        let _ = runner.run(&remove_stage(host, &stage), None);
    }
    installed?;
    drop(scratch);

    if !debug.one_shot {
        return wait_for_permanent(host, address, build_epoch, runner, clock, out);
    }

    let back = back_within(debug.return_after_secs);
    writeln!(
        out,
        "deploy: {host}: waiting up to {} s for it to go down and then up to {} s for it to answer again",
        GONE_WITHIN.as_secs(),
        back.as_secs()
    )?;
    let mut pings = PingTally::default();
    let mut said_ping_failed = false;
    let mut answering = || {
        let up = runner
            .run(&probe(host), None)
            .is_ok_and(|done| done.status == Some(0));
        if !up {
            // A ping that cannot be run is no failure of the deploy either, and counts as sent.
            pings.sent += 1;
            match runner.run(&ping(address), None) {
                Ok(done) if done.status == Some(0) => pings.answered += 1,
                Ok(_) => {}
                // Once: it would be the same at every poll.
                Err(error) if !said_ping_failed => {
                    said_ping_failed = true;
                    let _ = writeln!(out, "deploy: {host}: ping could not be run: {error}");
                }
                Err(_) => {}
            }
        }
        up
    };
    let returned = match wait_for_return(&mut answering, back, clock) {
        Ok(returned) => returned,
        Err(error) => {
            // A Pi that did not come back is where the tally tells most.
            let _ = say_pings(out, host, address, &pings);
            return Err(error.context(format!("{host} did not come back")));
        }
    };
    match returned {
        Returned::AfterRestart => writeln!(out, "deploy: {host}: it is back")?,
        Returned::WithoutGoingDown => writeln!(
            out,
            "deploy: {host}: note: it never stopped answering; it may not have restarted, and \
             the log may be an older one"
        )?,
    }
    say_pings(out, host, address, &pings)?;

    writeln!(
        out,
        "deploy: {host}: checking that config.txt is the saved one of Raspberry Pi OS again"
    )?;
    let compared = runner
        .run(&compare_configs(host), None)
        .context("cannot run ssh")?;
    check_returned(host, &compared)?;

    let (saved, log) = save_log(host, &root, runner, clock, out)?;
    let of_this_build = check_log_is_of(&log, build_epoch);
    // A log with a secret in it is not shown, and that is what the error says first, whatever
    // else is wrong with it. That it is of an older build, too, says whether this run left a log.
    if let Err(refused) = refuse_secret(&log, &secrets, &saved) {
        return Err(match of_this_build {
            Ok(()) => refused,
            Err(also) => anyhow!("{refused}. Also, {also}"),
        });
    }
    // Any other log is shown, whatever else is wrong with it: it is what there is to read.
    show_log(&saved, &log, out)?;
    of_this_build
}

/// Waits for a permanent qberrypi to take over: for the Pi to stop answering SSH, and then for
/// its status page to report the build that was deployed.
///
/// A Pi that is never seen to stop answering SSH is still waited for, with a note: it may
/// already have restarted between two looks.
fn wait_for_permanent(
    host: &str,
    address: Ipv4Addr,
    build_epoch: u64,
    runner: &mut dyn Runner,
    clock: &mut dyn Clock,
    out: &mut dyn Write,
) -> Result<()> {
    writeln!(
        out,
        "deploy: {host}: qberrypi stays: waiting up to {} s for it to stop answering SSH and then \
         up to {} s for build {build_epoch} to answer at {address}",
        GONE_WITHIN.as_secs(),
        ANSWER_WITHIN.as_secs()
    )?;
    let restarted = clock.now();
    let mut ssh_answering = || {
        runner
            .run(&probe(host), None)
            .is_ok_and(|done| done.status == Some(0))
    };
    if !wait_until(false, GONE_WITHIN, &mut ssh_answering, clock) {
        writeln!(
            out,
            "deploy: {host}: note: it never stopped answering SSH; it may not have restarted. \
             Waiting for qberrypi all the same"
        )?;
    }
    let gone_for = clock.now().saturating_sub(restarted);
    let took = wait_for_qberrypi(&mut || runner.reported_build(address), build_epoch, clock)
        .map_err(|error| error.context(format!("{host} did not answer as qberrypi")))?;
    writeln!(
        out,
        "deploy: {host}: qberrypi build {build_epoch} answers at {address} {} s after the \
         restart; to return to Raspberry Pi OS later: {WAY_BACK}",
        (gone_for + took).as_secs()
    )?;
    Ok(())
}

/// Says how many of the pings sent while the Pi was away it answered.
fn say_pings(
    out: &mut dyn Write,
    host: &str,
    address: Ipv4Addr,
    pings: &PingTally,
) -> io::Result<()> {
    writeln!(
        out,
        "deploy: {host}: {address} answered {} of {} pings while the Pi was away",
        pings.answered, pings.sent
    )
}

/// Copies the files to the stage and runs the script there as root.
fn install(
    host: &str,
    stage: &str,
    files: &[PathBuf],
    runner: &mut dyn Runner,
    out: &mut dyn Write,
) -> Result<()> {
    writeln!(
        out,
        "deploy: {host}: copying {} files to {stage}",
        files.len()
    )?;
    run_to_success(runner, &upload(host, files, stage), "copying the files")?;

    writeln!(
        out,
        "deploy: {host}: installing as root; the script restarts the Pi when it is done"
    )?;
    let script = RemoteScript {
        boot_dir: REMOTE_BOOT.to_owned(),
        stage_dir: stage.to_owned(),
        reboot_cmd: RESTART.to_owned(),
        hardware_checks: true,
        model_file: REMOTE_MODEL.to_owned(),
    };
    let ran = runner
        .run(&run_script(host), Some(script.render().as_bytes()))
        .context("cannot run ssh")?;
    out.write_all(String::from_utf8_lossy(&ran.stdout).as_bytes())?;
    out.write_all(String::from_utf8_lossy(&ran.stderr).as_bytes())?;
    script_outcome(host, &ran)
}

/// Fetches the log qberrypi left on the Pi's boot partition, saves it under
/// `out/logs/`, prints it and returns where it was saved. A log that holds the
/// Wi-Fi passphrase or key is saved and not printed, and is an error.
pub fn collect(host: &str, root: &Path) -> Result<PathBuf> {
    let clock = SystemClock {
        start: Instant::now(),
    };
    collect_with(host, root, &mut SystemRunner, &clock, &mut io::stdout()).map(|(path, _)| path)
}

/// `collect`, with the commands, the clock and the output in the caller's hands.
///
/// Returns the text of the log as well as where it was saved. It is where a
/// deploy whose Pi did not come back is picked up, so it is a log nobody has
/// checked: with a `qberrypi.toml` in the checkout that parses, the log is
/// shown only if it holds none of the Wi-Fi secrets. Without one there is
/// nothing to check it against, and it is shown as it is.
fn collect_with(
    host: &str,
    root: &Path,
    runner: &mut dyn Runner,
    clock: &dyn Clock,
    out: &mut dyn Write,
) -> Result<(PathBuf, String)> {
    let (path, text) = save_log(host, root, runner, clock, out)?;
    if let Some(secrets) = fs::read_to_string(root.join(CONFIG_FILE))
        .ok()
        .and_then(|toml| secrets_of(&toml).ok())
    {
        refuse_secret(&text, &secrets, &path)?;
    }
    show_log(&path, &text, out)?;
    Ok((path, text))
}

/// Fetches the log and saves it under `out/logs/`, and shows none of it.
///
/// Returns where it was saved and its text, for the caller to check before
/// [`show_log`] prints it: a log may hold the Wi-Fi passphrase.
fn save_log(
    host: &str,
    root: &Path,
    runner: &mut dyn Runner,
    clock: &dyn Clock,
    out: &mut dyn Write,
) -> Result<(PathBuf, String)> {
    validate_host(host).map_err(Error::msg)?;

    writeln!(out, "collect: {host}: fetching {REMOTE_LOG}")?;
    let looked = runner
        .run(&log_exists(host), None)
        .context("cannot run ssh")?;
    match looked.status {
        Some(0) => {}
        Some(1) => bail!(
            "there is no log.txt in {REMOTE_BOOT}/qberrypi on {host}: qberrypi writes one only \
             with debug.log_to_sd on, and only once it has mounted the card"
        ),
        status => bail!(
            "looking for the log on {host} failed ({}): {}",
            describe(status),
            String::from_utf8_lossy(&looked.stderr).trim_end()
        ),
    }
    let fetched = run_to_success(runner, &fetch_log(host), "reading the log")?;

    let folder = root.join(LOG_FOLDER);
    fs::create_dir_all(&folder).with_context(|| format!("cannot create {}", folder.display()))?;
    let path = folder.join(format!("{}.log", clock.unix_time()?));
    // Private: later milestones log details of the network.
    write_private_new(&path, &fetched.stdout)?;

    Ok((path, String::from_utf8_lossy(&fetched.stdout).into_owned()))
}

/// Prints a saved log and where it was saved.
fn show_log(path: &Path, text: &str, out: &mut dyn Write) -> Result<()> {
    out.write_all(text.as_bytes())?;
    if !text.is_empty() && !text.ends_with('\n') {
        writeln!(out)?;
    }
    writeln!(out, "collect: wrote {}", path.display())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::Cell;
    use std::collections::{BTreeMap, VecDeque};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::process::{Command, Stdio};
    use std::rc::Rc;

    use qb_wpa2::pmk::Pmk;
    use tempfile::TempDir;

    use crate::build::sha256sums;

    const EXAMPLE: &str = include_str!("../../qberrypi.example.toml");

    // ---------------------------------------------------------------- local checks

    #[test]
    fn refuses_a_non_one_shot_config_without_permanent() {
        let permanent_cfg = EXAMPLE; // one_shot = false
        assert!(
            check_local(permanent_cfg, false)
                .unwrap_err()
                .contains("--permanent")
        );
        assert!(check_local(permanent_cfg, true).is_ok());
        assert!(
            check_local(
                &EXAMPLE.replace("one_shot = false", "one_shot = true"),
                false
            )
            .is_ok()
        );
        assert!(check_local("not toml", true).is_err());
    }

    #[test]
    fn a_provoked_failure_is_never_deployed_for_good() {
        // The example configuration has debug.one_shot off.
        let faulty = EXAMPLE.replace("fault = \"none\"", "fault = \"crash-loop\"");
        let error = check_local(&faulty, true).unwrap_err();
        assert!(error.contains("debug.fault"), "{error}");
        assert!(error.contains("restart for ever"), "{error}");
        assert!(
            check_local(
                &faulty.replace("one_shot = false", "one_shot = true"),
                false
            )
            .is_ok()
        );
        // Whatever the failure is, and whatever else is set: only a one-shot run may carry one.
        for word in [
            "stall",
            "crash-loop",
            "panic",
            "no-wifi",
            "drop-link",
            "mute-probe",
        ] {
            let text = EXAMPLE.replace("fault = \"none\"", &format!("fault = \"{word}\""));
            assert!(check_local(&text, true).is_err(), "{word}");
            let text = text.replace("one_shot = false", "one_shot = true");
            assert!(check_local(&text, true).is_err(), "{word}");
            assert!(check_local(&text, false).is_ok(), "{word}");
        }
        assert!(check_local(EXAMPLE, true).is_ok());
    }

    #[test]
    fn a_permanent_deploy_refuses_every_development_switch() {
        let base = EXAMPLE; // every switch off, fault "none"
        assert!(check_local(base, true).is_ok());
        let cases = [
            ("one_shot = false", "one_shot = true", "debug.one_shot"),
            ("log_to_sd = false", "log_to_sd = true", "debug.log_to_sd"),
            (
                "return_after_secs = 0",
                "return_after_secs = 40",
                "debug.return_after_secs",
            ),
            (
                "calibrate_touch = false",
                "calibrate_touch = true",
                "debug.calibrate_touch",
            ),
            ("fault = \"none\"", "fault = \"stall\"", "debug.fault"),
        ];
        for (from, to, key) in cases {
            let error = check_local(&base.replace(from, to), true).unwrap_err();
            assert!(
                error.contains(key) && error.ends_with("; nothing was copied"),
                "{error}"
            );
        }
        // One-shot deploys, which are not permanent, go through as before.
        assert!(check_local(&base.replace("one_shot = false", "one_shot = true"), false).is_ok());
    }

    #[test]
    fn a_permanent_deploy_names_the_first_switch_that_is_on_in_a_fixed_order() {
        // With every switch on, each refusal in turn is the one that is shown, in the plan's order.
        const KEYS: [&str; 5] = [
            "debug.one_shot",
            "debug.log_to_sd",
            "debug.return_after_secs",
            "debug.calibrate_touch",
            "debug.fault",
        ];
        let mut text = base_with_every_switch_on();
        for (at, key) in KEYS.iter().enumerate() {
            let error = check_local(&text, true).unwrap_err();
            for (other_at, other) in KEYS.iter().enumerate() {
                assert_eq!(error.contains(other), other_at == at, "{key}: {error}");
            }
            text = match *key {
                "debug.one_shot" => text.replace("one_shot = true", "one_shot = false"),
                "debug.log_to_sd" => text.replace("log_to_sd = true", "log_to_sd = false"),
                "debug.return_after_secs" => {
                    text.replace("return_after_secs = 40", "return_after_secs = 0")
                }
                "debug.calibrate_touch" => {
                    text.replace("calibrate_touch = true", "calibrate_touch = false")
                }
                _ => text.replace("fault = \"stall\"", "fault = \"none\""),
            };
        }
        assert!(check_local(&text, true).is_ok());
    }

    fn base_with_every_switch_on() -> String {
        EXAMPLE
            .replace("one_shot = false", "one_shot = true")
            .replace("log_to_sd = false", "log_to_sd = true")
            .replace("return_after_secs = 0", "return_after_secs = 40")
            .replace("calibrate_touch = false", "calibrate_touch = true")
            .replace("fault = \"none\"", "fault = \"stall\"")
    }

    #[test]
    fn a_config_error_never_quotes_the_file() {
        let text = EXAMPLE.replace("country = \"US\"", "country = \"canary-value-41\"");
        let error = check_local(&text, true).unwrap_err();
        assert!(!error.contains("canary-value-41"), "{error}");
        assert!(!error.contains("example-passphrase"), "{error}");
    }

    #[test]
    fn the_host_must_be_a_plain_ssh_name() {
        for good in [
            "pi",
            "pi.example",
            "user@pi-3_b.example",
            "192.0.2.53",
            "user@2001:db8::53",
        ] {
            assert_eq!(validate_host(good), Ok(()), "{good}");
        }
        for bad in [
            "",
            "-oProxyCommand=evil",
            "-pi",
            "pi host",
            "pi;reboot",
            "pi\n",
            "pi/x",
            "$(reboot)",
            "pi'",
            "pi\"",
            "pi`id`",
            "pï",
            "[2001:db8::53]",
        ] {
            assert!(validate_host(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_host_comes_from_the_flag_and_then_from_the_environment() {
        let some = |text: &str| Some(text.to_owned());
        assert_eq!(resolve_host(some("flag"), some("env")).unwrap(), "flag");
        assert_eq!(resolve_host(None, some("env")).unwrap(), "env");
        let error = resolve_host(None, None).unwrap_err().to_string();
        assert!(
            error.contains("--host") && error.contains("QBERRYPI_HOST"),
            "{error}"
        );
        // An empty variable is as good as none; there is no default host.
        assert!(resolve_host(None, some("")).is_err());
        assert!(resolve_host(some("-bad"), None).is_err());
    }

    #[test]
    fn only_a_name_mktemp_could_have_made_is_a_stage_directory() {
        for good in ["/tmp/qberrypi-stage.Ab12Cd", "/tmp/qberrypi-stage.x"] {
            assert!(is_stage_dir(good), "{good}");
        }
        for bad in [
            "/",
            "/tmp",
            "/tmp/",
            "/tmp/qberrypi-stage.x/../..",
            "/tmp/qberrypi-stage.a b",
            "/tmp/qberrypi-stage.a;b",
            "/tmp/qberrypi-stage.",
            "/tmp/qberrypi-stage.abc/",
            "/tmp/qberrypi-stage.abc\n",
            "/tmp/qberrypi-stage.ab-c",
            "/tmp/qberrypi-stage.ab.c",
            "/tmp/qberrypi-stage.abç",
            "/tmp/qberrypi-stageabc",
            "/var/tmp/qberrypi-stage.abc",
            "tmp/qberrypi-stage.abc",
            " /tmp/qberrypi-stage.abc",
            "",
        ] {
            assert!(!is_stage_dir(bad), "{bad:?}");
        }
    }

    #[test]
    fn the_answer_of_mktemp_is_one_line_naming_a_stage_directory() {
        assert_eq!(
            parse_stage_dir(b"/tmp/qberrypi-stage.Ab12Cd\n").unwrap(),
            "/tmp/qberrypi-stage.Ab12Cd"
        );
        for bad in [
            &b""[..],
            b"\n",
            b"/tmp\n",
            b"/\n",
            b"/tmp/qberrypi-stage.x/../..\n",
            b"/tmp/qberrypi-stage.a b\n",
            b"/tmp/qberrypi-stage.a;b\n",
            b"/tmp/qberrypi-stage.Ab12Cd\n/tmp\n",
            b"motd\n/tmp/qberrypi-stage.Ab12Cd\n",
            b"/tmp/qberrypi-stage.Ab12Cd\r\n",
            b"/tmp/qberrypi-stage.\xff\n",
        ] {
            assert!(
                parse_stage_dir(bad).is_err(),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    // ---------------------------------------------------------------- commands as data

    fn words(invocation: &Invocation) -> Vec<String> {
        invocation
            .args
            .iter()
            .map(|arg| arg.to_str().unwrap().to_owned())
            .collect()
    }

    /// The arguments every `ssh` to `host` starts with, followed by the remote command.
    fn ssh_args(host: &str, remote: &[&str]) -> Vec<String> {
        ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "--", host]
            .iter()
            .chain(remote)
            .map(|word| (*word).to_owned())
            .collect()
    }

    #[test]
    fn every_ssh_command_is_an_argument_list_with_batch_mode_and_a_timeout() {
        let stage = "/tmp/qberrypi-stage.Ab12Cd";
        let cases = [
            (probe("pi"), ssh_args("pi", &["true"])),
            (
                save_boot_partition("pi"),
                ssh_args("pi", &["tar", "-C", "/boot/firmware", "-cf", "-", "."]),
            ),
            (
                make_stage("pi"),
                ssh_args("pi", &["mktemp", "-d", "/tmp/qberrypi-stage.XXXXXX"]),
            ),
            (run_script("pi"), ssh_args("pi", &["sudo", "sh", "-s"])),
            (
                remove_stage("pi", stage),
                ssh_args("pi", &["rm", "-rf", "--", stage]),
            ),
            (
                compare_configs("pi"),
                ssh_args(
                    "pi",
                    &[
                        "cmp",
                        "-s",
                        "--",
                        "/boot/firmware/config.txt",
                        "/boot/firmware/config.pios.txt",
                    ],
                ),
            ),
            (
                log_exists("pi"),
                ssh_args("pi", &["test", "-f", "/boot/firmware/qberrypi/log.txt"]),
            ),
            (
                fetch_log("pi"),
                ssh_args("pi", &["cat", "/boot/firmware/qberrypi/log.txt"]),
            ),
        ];
        for (invocation, expected) in cases {
            assert_eq!(invocation.program, "ssh");
            assert_eq!(words(&invocation), expected);
        }
    }

    #[test]
    fn a_ping_is_one_packet_with_a_one_second_wait() {
        let invocation = ping(Ipv4Addr::new(192, 0, 2, 53));
        assert_eq!(invocation.program, "ping");
        // No name lookup, one packet, one second to answer.
        assert_eq!(
            words(&invocation),
            ["-n", "-c", "1", "-W", "1", "192.0.2.53"]
        );
    }

    #[test]
    fn the_upload_is_one_scp_of_named_files_into_the_stage() {
        let files = [
            PathBuf::from("/work/out/qberrypi/kernel8.img"),
            PathBuf::from("/work/qberrypi.toml"),
        ];
        let invocation = upload("user@pi", &files, "/tmp/qberrypi-stage.Ab12Cd");
        assert_eq!(invocation.program, "scp");
        assert_eq!(
            words(&invocation),
            [
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                "--",
                "/work/out/qberrypi/kernel8.img",
                "/work/qberrypi.toml",
                "user@pi:/tmp/qberrypi-stage.Ab12Cd/",
            ]
        );
    }

    #[test]
    fn scp_gets_an_address_with_colons_in_brackets() {
        assert_eq!(scp_target("pi", "/tmp/x/"), "pi:/tmp/x/");
        assert_eq!(scp_target("user@pi", "/tmp/x/"), "user@pi:/tmp/x/");
        // Without the brackets scp would take `2001` for the host.
        assert_eq!(
            scp_target("2001:db8::53", "/tmp/x/"),
            "[2001:db8::53]:/tmp/x/"
        );
        assert_eq!(
            scp_target("user@2001:db8::53", "/tmp/x/"),
            "user@[2001:db8::53]:/tmp/x/"
        );
    }

    #[test]
    fn the_runner_feeds_standard_input_and_reports_status_and_output() {
        let cat = Invocation {
            program: "cat",
            args: Vec::new(),
        };
        let done = SystemRunner.run(&cat, Some(b"through\n")).unwrap();
        assert_eq!(done.status, Some(0));
        assert_eq!(done.stdout, b"through\n");

        // With nothing to feed, the command reads an empty input rather than this terminal.
        let done = SystemRunner.run(&cat, None).unwrap();
        assert_eq!((done.status, done.stdout), (Some(0), Vec::new()));

        let failing = Invocation {
            program: "ls",
            args: vec!["/nonexistent-qberrypi-test".into()],
        };
        let done = SystemRunner.run(&failing, None).unwrap();
        assert_ne!(done.status, Some(0));
        assert!(!done.stderr.is_empty());

        // A command that ends without reading its input is no error of the runner.
        let deaf = Invocation {
            program: "true",
            args: Vec::new(),
        };
        let big = vec![b'x'; 1 << 20];
        assert_eq!(SystemRunner.run(&deaf, Some(&big)).unwrap().status, Some(0));

        let missing = Invocation {
            program: "qberrypi-no-such-program",
            args: Vec::new(),
        };
        assert!(SystemRunner.run(&missing, None).is_err());
    }

    // ---------------------------------------------------------------- checksums for the stage

    const DIGEST: &str = "6a5e53e2186a4ed916a7b41b7b73f1470ccf75f99d1a4d0b17580ed4c07d7f15";

    #[test]
    fn the_staged_checksums_gain_a_line_for_the_configuration() {
        let build = sha256sums(&[("kernel8.img", b"K"), ("config.txt", b"C")]);
        let (names, staged) = staged_checksums(&build, b"T", None).unwrap();
        assert_eq!(names, ["kernel8.img", "config.txt"]);
        let toml_line = sha256sums(&[("qberrypi.toml", b"T")]);
        assert_eq!(staged, format!("{build}{toml_line}"));
        assert_eq!(staged.lines().count(), 3);
    }

    #[test]
    fn the_overlay_files_names_are_plain_names_the_stage_takes() {
        let build = sha256sums(&[
            ("kernel8.img", b"K"),
            ("config.txt", b"C"),
            ("ov-README", b"R"),
            ("ov-overlay_map.dtb", b"M"),
            ("ov-qb-piscreen.dtbo", b"P"),
        ]);
        let (names, staged) = staged_checksums(&build, b"T", None).unwrap();
        assert_eq!(
            names,
            [
                "kernel8.img",
                "config.txt",
                "ov-README",
                "ov-overlay_map.dtb",
                "ov-qb-piscreen.dtbo"
            ]
        );
        assert_eq!(staged.lines().count(), 6);
    }

    #[test]
    fn the_staged_checksums_gain_a_line_for_the_certificate_after_the_configuration() {
        let build = sha256sums(&[("kernel8.img", b"K"), ("config.txt", b"C")]);
        let (names, staged) = staged_checksums(&build, b"T", Some(b"P")).unwrap();
        // The certificate is not one of the build's files.
        assert_eq!(names, ["kernel8.img", "config.txt"]);
        let added = sha256sums(&[("qberrypi.toml", b"T"), ("tls.pem", b"P")]);
        assert_eq!(staged, format!("{build}{added}"));
        assert_eq!(staged.lines().count(), 4);
    }

    #[test]
    fn checksums_that_are_not_a_plain_list_of_file_names_are_refused() {
        let line = |name: &str| format!("{DIGEST}  {name}\n");
        let config = line("config.txt");
        for (case, sums) in [
            ("empty", String::new()),
            ("no config.txt", line("kernel8.img")),
            ("a path", format!("{config}{}", line("../config.txt"))),
            ("a folder", format!("{config}{}", line("sub/file"))),
            ("an option", format!("{config}{}", line("-rf"))),
            ("a hidden file", format!("{config}{}", line(".hidden"))),
            ("a space", format!("{config}{}", line("a b"))),
            ("a glob", format!("{config}{}", line("*"))),
            (
                "the configuration",
                format!("{config}{}", line("qberrypi.toml")),
            ),
            ("the certificate", format!("{config}{}", line("tls.pem"))),
            ("the checksums", format!("{config}{}", line("SHA256SUMS"))),
            ("the log", format!("{config}{}", line("log.txt"))),
            ("listed twice", format!("{config}{config}")),
            ("a short digest", format!("{config}abc  kernel8.img\n")),
            ("binary mode", format!("{config}{DIGEST} *kernel8.img\n")),
            ("one space", format!("{config}{DIGEST} kernel8.img\n")),
            (
                "upper case",
                format!("{config}{}  x\n", DIGEST.to_uppercase()),
            ),
            ("a blank line", format!("{config}\n")),
        ] {
            assert!(staged_checksums(&sums, b"T", None).is_err(), "{case}");
            assert!(staged_checksums(&sums, b"T", Some(b"P")).is_err(), "{case}");
        }
    }

    // ---------------------------------------------------------------- the remote script

    const PIOS: &str = "PIOS\n";
    const OWN_CONFIG: &str = "os_prefix=qberrypi/\n";
    const STAGED: [(&str, &[u8]); 7] = [
        ("kernel8.img", b"KERNEL"),
        ("initramfs8", b"INITRAMFS"),
        ("config.txt", OWN_CONFIG.as_bytes()),
        ("ov-README", b"README"),
        ("ov-overlay_map.dtb", b"OVERLAY_MAP"),
        ("ov-qb-piscreen.dtbo", b"PISCREEN"),
        ("qberrypi.toml", b"[debug]\none_shot = true\n"),
    ];

    /// Replaces `sync` for the length of a test and records what `config.txt` held when it ran.
    const FAKE_SYNC: &str = "sync() { printf 'sync: %s\\n' \"$(cat \"$QBERRYPI_TEST_BOOT/config.txt\" 2>/dev/null)\" >>\"$QBERRYPI_TEST_TRACE\"; }\n";
    /// Replaces `rm`, so a script that is wrong about what to remove removes nothing.
    const FAKE_RM: &str = "rm() { printf 'rm %s\\n' \"$*\" >>\"$QBERRYPI_TEST_TRACE\"; }\n";
    /// Stands in for the restart and records what `config.txt` held when it was asked for.
    const FAKE_RESTART: &str = "printf 'restart: %s\\n' \"$(cat \"$QBERRYPI_TEST_BOOT/config.txt\")\" >>\"$QBERRYPI_TEST_TRACE\"";

    /// Stands in for `pgrep` on a Pi where no package manager runs: it finds nothing. Every run
    /// has it before its own stand-ins, so no test depends on what runs on the machine it is on.
    const NO_PACKAGE_MANAGER: &str = "pgrep() { return 1; }\n";

    /// Stands in for `pgrep` on a Pi where the process `name` runs: it finds that name and no other.
    fn package_manager_running(name: &str) -> String {
        format!("pgrep() {{ [ \"$*\" = \"-x {name}\" ]; }}\n")
    }

    /// What `unattended-upgrades.service` keeps running all the time on Raspberry Pi OS, however
    /// idle the machine: its shutdown script, waiting for a signal. The kernel names a script after
    /// its file, cut to 15 characters, so this process is called `unattended-upgr`.
    const IDLE_UPGRADES_DAEMON: (&str, &str) = (
        "unattended-upgr",
        "/usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal",
    );

    /// Stands in for `pgrep` on a Pi that runs the given processes, each as its name (what
    /// `pgrep -x` compares) and its whole command line (what `pgrep -f` searches with a regular
    /// expression). It answers those two questions and no other: given any other flags it finds
    /// nothing, so a script that asks differently is not refused by it.
    fn processes_running(processes: &[(&str, &str)]) -> String {
        let names: String = processes
            .iter()
            .map(|(name, _)| format!(" '{name}'"))
            .collect();
        let commands: String = processes
            .iter()
            .map(|(_, command)| format!(" '{command}'"))
            .collect();
        format!(
            "pgrep() {{\n\
             [ $# -eq 2 ] || return 2\n\
             case $1 in\n\
             -x) printf '%s\\n'{names} | grep -qxF -- \"$2\" ;;\n\
             -f) printf '%s\\n'{commands} | grep -qE -- \"$2\" ;;\n\
             *) return 2 ;;\n\
             esac\n\
             }}\n"
        )
    }

    /// The shells the script is tried under: `sh`, and `dash` (the Pi's `sh`) where there is one.
    fn shells() -> Vec<&'static str> {
        let has_dash = Command::new("dash")
            .args(["-c", "exit 0"])
            .status()
            .is_ok_and(|status| status.success());
        if has_dash {
            vec!["sh", "dash"]
        } else {
            vec!["sh"]
        }
    }

    struct Ran {
        status: Option<i32>,
        stdout: String,
        stderr: String,
    }

    /// A stand-in for the Pi: a folder for its boot partition and a stage directory.
    struct Card {
        tmp: TempDir,
        boot: PathBuf,
        stage: TempDir,
    }

    impl Card {
        fn new() -> Self {
            Self::with_boot_name("boot")
        }

        fn with_boot_name(name: &str) -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let boot = tmp.path().join(name);
            fs::create_dir(&boot).unwrap();
            // The script takes a stage directory nowhere else and under no other name.
            let stage = tempfile::Builder::new()
                .prefix("qberrypi-stage.")
                .rand_bytes(6)
                .tempdir_in("/tmp")
                .unwrap();
            let card = Card { tmp, boot, stage };
            card.stage_files(&STAGED);
            card
        }

        /// A card as Raspberry Pi OS left it, never deployed to.
        fn fresh() -> Self {
            let card = Self::new();
            card.write_boot("config.txt", PIOS);
            card
        }

        fn stage_path(&self) -> &str {
            self.stage.path().to_str().unwrap()
        }

        fn trace_path(&self) -> PathBuf {
            self.tmp.path().join("trace")
        }

        /// What the stand-ins for `sync`, `rm` and the restart recorded, in order.
        fn trace(&self) -> String {
            fs::read_to_string(self.trace_path()).unwrap_or_default()
        }

        /// Fills the stage with these files and the checksums that match them.
        fn stage_files(&self, files: &[(&str, &[u8])]) {
            if !self.stage.path().exists() {
                fs::create_dir(self.stage.path()).unwrap();
            }
            for (name, data) in files {
                fs::write(self.stage.path().join(name), data).unwrap();
            }
            fs::write(self.stage.path().join("SHA256SUMS"), sha256sums(files)).unwrap();
        }

        /// Takes these files out of the usual stage, and lists in `SHA256SUMS` only what is left.
        fn stage_all_but(&self, without: &[&str]) {
            for name in without {
                fs::remove_file(self.stage.path().join(name)).unwrap();
            }
            let left: Vec<(&str, &[u8])> = STAGED
                .iter()
                .copied()
                .filter(|(name, _)| !without.contains(name))
                .collect();
            self.stage_files(&left);
        }

        /// Puts one more file in the stage, whose checksums the caller writes.
        fn write_stage(&self, name: &str, data: &[u8]) {
            fs::write(self.stage.path().join(name), data).unwrap();
        }

        fn write_boot(&self, name: &str, data: impl AsRef<[u8]>) {
            let path = self.boot.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, data).unwrap();
        }

        fn read_boot(&self, name: &str) -> Vec<u8> {
            fs::read(self.boot.join(name)).unwrap()
        }

        fn has_boot(&self, name: &str) -> bool {
            self.boot.join(name).exists()
        }

        /// Every file of the boot partition with its contents.
        fn snapshot(&self) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
            fn walk(dir: &Path, into: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
                for entry in fs::read_dir(dir).unwrap() {
                    let path = entry.unwrap().path();
                    if path.is_dir() {
                        into.insert(path.clone(), None);
                        walk(&path, into);
                    } else {
                        let data = fs::read(&path).unwrap();
                        into.insert(path, Some(data));
                    }
                }
            }
            let mut files = BTreeMap::new();
            walk(&self.boot, &mut files);
            files
        }

        fn script(&self) -> RemoteScript {
            RemoteScript {
                boot_dir: self.boot.to_str().unwrap().to_owned(),
                stage_dir: self.stage_path().to_owned(),
                reboot_cmd: FAKE_RESTART.to_owned(),
                hardware_checks: false,
                model_file: "/proc/device-tree/model".to_owned(),
            }
        }

        /// The script with its hardware checks on, for a machine that says it is `model`.
        fn pi_script(&self, model: &str) -> RemoteScript {
            let model_file = self.tmp.path().join("model");
            // The device tree ends its texts with a NUL.
            fs::write(&model_file, format!("{model}\0")).unwrap();
            RemoteScript {
                hardware_checks: true,
                model_file: model_file.to_str().unwrap().to_owned(),
                ..self.script()
            }
        }

        /// Runs the script as `deploy` does, on the standard input of `sh -s`.
        fn run(&self, shell: &str) -> Ran {
            self.run_text(shell, &self.script().render(), FAKE_SYNC)
        }

        /// Runs a script text after the given stand-in commands.
        fn run_text(&self, shell: &str, script: &str, fakes: &str) -> Ran {
            self.run_on_path(shell, script, fakes, None)
        }

        /// The same, with the folder given as the whole `PATH`, if one is given.
        fn run_on_path(&self, shell: &str, script: &str, fakes: &str, path: Option<&Path>) -> Ran {
            let mut command = Command::new(shell);
            if let Some(path) = path {
                // The shell itself is looked for there too.
                command.env("PATH", path);
            }
            let mut child = command
                .arg("-s")
                .env("QBERRYPI_TEST_BOOT", &self.boot)
                .env("QBERRYPI_TEST_TRACE", self.trace_path())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let mut input = child.stdin.take().unwrap();
            // A shell that stops early may not read all of it.
            let _ = input.write_all(format!("{NO_PACKAGE_MANAGER}{fakes}{script}").as_bytes());
            drop(input);
            let output = child.wait_with_output().unwrap();
            Ran {
                status: output.status.code(),
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }
        }
    }

    #[test]
    fn first_deploy_backs_up_then_selects_qberrypi() {
        for shell in shells() {
            let card = Card::fresh();
            let ran = card.run(shell);
            assert_eq!(ran.status, Some(0), "{shell}: {}", ran.stderr);
            assert_eq!(card.read_boot("config.pios.txt"), PIOS.as_bytes());
            assert_eq!(card.read_boot("config.txt"), OWN_CONFIG.as_bytes());
            for (name, data) in STAGED {
                assert_eq!(card.read_boot(&format!("qberrypi/{name}")), data, "{name}");
            }
            assert_eq!(
                card.read_boot("qberrypi/SHA256SUMS"),
                sha256sums(&STAGED).as_bytes()
            );
            assert!(!card.stage.path().exists(), "the stage is still there");
            assert!(ran.stdout.contains(SELECTED_MARKER), "{}", ran.stdout);
            // A run that went well has nothing to say for itself on standard error:
            // dd, for one, keeps the count of what it wrote to itself.
            assert_eq!(ran.stderr, "", "{shell}");
            // Nothing but the backup, the selected configuration and the folder is on the card.
            assert_eq!(card.snapshot().len(), 3 + STAGED.len() + 1);
        }
    }

    #[test]
    fn second_deploy_keeps_the_original_backup() {
        for shell in shells() {
            let card = Card::fresh();
            assert_eq!(card.run(shell).status, Some(0));
            // Run again and a third time without restoring in between.
            for round in [2, 3] {
                card.stage_files(&STAGED);
                let ran = card.run(shell);
                assert_eq!(
                    ran.status,
                    Some(0),
                    "{shell}, deploy {round}: {}",
                    ran.stderr
                );
                assert_eq!(card.read_boot("config.pios.txt"), PIOS.as_bytes());
                assert_eq!(card.read_boot("config.txt"), OWN_CONFIG.as_bytes());
            }
        }
    }

    #[test]
    fn a_deploy_after_the_pi_returned_keeps_the_backup_too() {
        for shell in shells() {
            let card = Card::fresh();
            assert_eq!(card.run(shell).status, Some(0));
            // What init does on a one-shot boot.
            card.write_boot("config.txt", PIOS);
            card.stage_files(&STAGED);
            let ran = card.run(shell);
            assert_eq!(ran.status, Some(0), "{shell}: {}", ran.stderr);
            assert_eq!(card.read_boot("config.pios.txt"), PIOS.as_bytes());
            assert_eq!(card.read_boot("config.txt"), OWN_CONFIG.as_bytes());
        }
    }

    #[test]
    fn refuses_when_no_backup_exists_and_qberrypi_is_already_selected() {
        for shell in shells() {
            for selected in [OWN_CONFIG, "arm_64bit=1\n \tos_prefix=qberrypi/\n"] {
                let card = Card::new();
                card.write_boot("config.txt", selected);
                let ran = card.run(shell);
                assert_eq!(
                    ran.status,
                    Some(ALREADY_SELECTED),
                    "{shell}: {}",
                    ran.stderr
                );
                assert_eq!(ALREADY_SELECTED, 3);
                assert!(!card.has_boot("config.pios.txt"));
                assert!(!card.has_boot("qberrypi"));
                assert_eq!(card.read_boot("config.txt"), selected.as_bytes());
                assert_eq!(card.snapshot().len(), 1);
                assert!(ran.stderr.contains("config.pios.txt"), "{}", ran.stderr);
                assert!(!card.trace().contains("restart"));
            }
        }
    }

    #[test]
    fn a_corrupt_copy_never_selects_qberrypi() {
        for shell in shells() {
            for (corrupt, _) in STAGED {
                let card = Card::fresh();
                // The checksums list a digest that the staged file does not have.
                let listed: Vec<(&str, &[u8])> = STAGED
                    .iter()
                    .map(|&(name, data)| (name, if name == corrupt { &b"OTHER"[..] } else { data }))
                    .collect();
                fs::write(card.stage.path().join("SHA256SUMS"), sha256sums(&listed)).unwrap();

                let ran = card.run(shell);
                assert_eq!(
                    ran.status,
                    Some(BAD_COPY),
                    "{shell}, {corrupt}: {}",
                    ran.stderr
                );
                assert_eq!(card.read_boot("config.txt"), PIOS.as_bytes(), "{corrupt}");
                assert!(!card.trace().contains("restart"));
                assert!(!ran.stdout.contains(SELECTED_MARKER));
            }
        }
    }

    #[test]
    fn checksums_are_verified_before_config_txt_is_overwritten() {
        for shell in shells() {
            for (damaged, _) in STAGED {
                let card = Card::fresh();
                // The file changed on its way to the stage; the checksums are the build's.
                fs::write(card.stage.path().join(damaged), b"DAMAGED").unwrap();

                let ran = card.run(shell);
                assert_eq!(
                    ran.status,
                    Some(BAD_COPY),
                    "{shell}, {damaged}: {}",
                    ran.stderr
                );
                // The script got as far as copying: the failure is the verification itself.
                assert_eq!(card.read_boot("config.pios.txt"), PIOS.as_bytes());
                assert_eq!(
                    card.read_boot(&format!("qberrypi/{damaged}")),
                    b"DAMAGED",
                    "{damaged}"
                );
                // And config.txt is byte for byte what it was.
                assert_eq!(card.read_boot("config.txt"), PIOS.as_bytes(), "{damaged}");
                assert!(
                    ran.stderr.contains("the next restart is Raspberry Pi OS"),
                    "{}",
                    ran.stderr
                );
                assert!(!ran.stderr.contains("has selected qberrypi"));
                assert!(!card.trace().contains("restart"));
                assert!(
                    !card.stage.path().exists(),
                    "the stage outlived the failure"
                );
            }
        }
    }

    /// A card on which an earlier deploy selected qberrypi and the Pi has not restarted since.
    fn selected_card() -> Card {
        let card = Card::new();
        card.write_boot("config.txt", OWN_CONFIG);
        card.write_boot("config.pios.txt", PIOS);
        card.write_boot("qberrypi/kernel8.img", "OLD KERNEL");
        card.write_boot("qberrypi/config.txt", OWN_CONFIG);
        card
    }

    #[test]
    fn a_corrupt_copy_over_a_selected_qberrypi_leaves_raspberry_pi_os_selected() {
        // The folder config.txt pointed at is about to be replaced, so qberrypi is
        // deselected first: whatever happens to the copy, the next start is Raspberry Pi OS.
        for shell in shells() {
            for (damaged, _) in STAGED {
                let card = selected_card();
                fs::write(card.stage.path().join(damaged), b"DAMAGED").unwrap();

                let ran = card.run(shell);
                assert_eq!(
                    ran.status,
                    Some(BAD_COPY),
                    "{shell}, {damaged}: {}",
                    ran.stderr
                );
                assert_eq!(card.read_boot("config.txt"), PIOS.as_bytes(), "{damaged}");
                assert_eq!(card.read_boot("config.pios.txt"), PIOS.as_bytes());
                assert!(
                    ran.stderr.contains("the next restart is Raspberry Pi OS"),
                    "{}",
                    ran.stderr
                );
                assert!(!card.trace().contains("restart"));
            }
        }
    }

    #[test]
    fn a_copy_that_cannot_be_made_over_a_selected_qberrypi_leaves_raspberry_pi_os_selected() {
        for shell in shells() {
            let card = Card::new();
            card.write_boot("config.txt", OWN_CONFIG);
            card.write_boot("config.pios.txt", PIOS);
            // A file where the folder should be: nothing can be copied into it.
            card.write_boot("qberrypi", "not a folder");
            let ran = card.run(shell);
            assert_eq!(ran.status, Some(BAD_COPY), "{shell}: {}", ran.stderr);
            assert_eq!(card.read_boot("config.txt"), PIOS.as_bytes());
            assert_eq!(card.read_boot("config.pios.txt"), PIOS.as_bytes());
        }
    }

    #[test]
    fn a_good_deploy_over_a_selected_qberrypi_selects_it_again() {
        for shell in shells() {
            let card = selected_card();
            let ran = card.run(shell);
            assert_eq!(ran.status, Some(0), "{shell}: {}", ran.stderr);
            assert_eq!(card.read_boot("config.txt"), OWN_CONFIG.as_bytes());
            assert_eq!(card.read_boot("config.pios.txt"), PIOS.as_bytes());
            assert_eq!(card.read_boot("qberrypi/kernel8.img"), b"KERNEL");
            assert!(ran.stdout.contains(SELECTED_MARKER), "{}", ran.stdout);
        }
    }

    #[test]
    fn a_selected_qberrypi_is_deselected_before_its_folder_is_touched() {
        // This stand-in for sync also records which kernel the folder held at the time.
        let sync = "sync() { printf 'sync: %s / %s\\n' \
            \"$(cat \"$QBERRYPI_TEST_BOOT/config.txt\")\" \
            \"$(cat \"$QBERRYPI_TEST_BOOT/qberrypi/kernel8.img\")\" \
            >>\"$QBERRYPI_TEST_TRACE\"; }\n";
        for shell in shells() {
            let card = selected_card();
            let ran = card.run_text(shell, &card.script().render(), sync);
            assert_eq!(ran.status, Some(0), "{shell}: {}", ran.stderr);
            let trace = card.trace();
            let lines: Vec<&str> = trace.lines().collect();
            assert_eq!(
                lines,
                [
                    // Raspberry Pi OS is back and on the card while the old build is still whole.
                    "sync: PIOS / OLD KERNEL",
                    "sync: PIOS / KERNEL",
                    "sync: os_prefix=qberrypi/ / KERNEL",
                    "sync: os_prefix=qberrypi/ / KERNEL",
                    "restart: os_prefix=qberrypi/",
                ],
                "{shell}"
            );
        }
    }

    #[test]
    fn a_selected_qberrypi_without_a_backup_to_restore_is_refused_and_nothing_changes() {
        for shell in shells() {
            // The backup itself selects qberrypi, or is not one init would restore, or is not there.
            let backups: [Option<&[u8]>; 4] = [
                Some(OWN_CONFIG.as_bytes()),
                Some(b"arm_64bit=1\n  os_prefix=qberrypi/\n"),
                Some(b" \n"),
                None,
            ];
            for backup in backups {
                let card = selected_card();
                match backup {
                    Some(backup) => card.write_boot("config.pios.txt", backup),
                    None => fs::remove_file(card.boot.join("config.pios.txt")).unwrap(),
                }
                let before = card.snapshot();
                let ran = card.run(shell);
                let expected = if backup.is_some() {
                    BACKUP_REFUSED
                } else {
                    ALREADY_SELECTED
                };
                assert_eq!(ran.status, Some(expected), "{shell}: {}", ran.stderr);
                assert_eq!(card.snapshot(), before);
                assert_eq!(card.read_boot("config.txt"), OWN_CONFIG.as_bytes());
                assert_eq!(card.trace(), "");
            }
        }
    }

    #[test]
    fn a_copy_that_cannot_be_made_stops_the_deploy_like_a_corrupt_one() {
        for shell in shells() {
            let card = Card::fresh();
            // A file where the folder should be: nothing can be copied into it.
            card.write_boot("qberrypi", "not a folder");
            let ran = card.run(shell);
            assert_eq!(ran.status, Some(BAD_COPY), "{shell}: {}", ran.stderr);
            assert_eq!(card.read_boot("config.txt"), PIOS.as_bytes());
            assert!(
                ran.stderr.contains("the next restart is Raspberry Pi OS"),
                "{}",
                ran.stderr
            );
            assert!(!card.trace().contains("restart"));
        }
    }

    #[test]
    fn a_staged_file_the_checksums_do_not_list_stops_the_deploy() {
        for shell in shells() {
            let card = Card::fresh();
            fs::write(card.stage.path().join("extra.bin"), b"UNLISTED").unwrap();
            let before = card.snapshot();
            let ran = card.run(shell);
            assert_eq!(ran.status, Some(BAD_STAGE), "{shell}: {}", ran.stderr);
            assert!(ran.stderr.contains("extra.bin"), "{}", ran.stderr);
            assert_eq!(card.snapshot(), before);
        }
    }

    #[test]
    fn a_stage_without_checksums_or_config_stops_the_deploy() {
        for shell in shells() {
            for missing in ["SHA256SUMS", "config.txt"] {
                let card = Card::fresh();
                fs::remove_file(card.stage.path().join(missing)).unwrap();
                let before = card.snapshot();
                let ran = card.run(shell);
                assert_eq!(
                    ran.status,
                    Some(BAD_STAGE),
                    "{shell}, {missing}: {}",
                    ran.stderr
                );
                assert_eq!(card.snapshot(), before);
            }
            let card = Card::fresh();
            fs::remove_dir_all(card.stage.path()).unwrap();
            let before = card.snapshot();
            assert_eq!(card.run(shell).status, Some(BAD_STAGE));
            assert_eq!(card.snapshot(), before);
        }
    }

    /// Backups that `restore_pios_config` refuses, with the reason it gives.
    const REFUSED_BACKUPS: [(&str, &[u8], &str); 9] = [
        ("only whitespace", b" \t\r\n\x0c\n  \n", "is empty"),
        ("one newline", b"\n", "is empty"),
        (
            "a NUL in text",
            b"arm_64bit=1\ndtparam=au\0dio=on\n",
            "is not text",
        ),
        ("all NULs", &[0; 512], "is not text"),
        (
            "a NUL and the setting",
            b"os_prefix=qberrypi/\n\0",
            "is not text",
        ),
        (
            "the setting",
            b"arm_64bit=1\nos_prefix=qberrypi/\n",
            "selects qberrypi",
        ),
        (
            "the setting, indented",
            b"arm_64bit=1\n \tos_prefix=qberrypi/\n",
            "selects qberrypi",
        ),
        (
            "the setting, no newline",
            b"  os_prefix=qberrypi/",
            "selects qberrypi",
        ),
        (
            "the setting, not UTF-8",
            b"# \xff\xfe\r\nos_prefix=qberrypi/\r\n",
            "selects qberrypi",
        ),
    ];

    #[test]
    fn a_backup_init_would_refuse_stops_the_deploy() {
        for shell in shells() {
            for (case, backup, reason) in REFUSED_BACKUPS {
                // Whether Raspberry Pi OS or qberrypi is selected at the time makes no difference.
                for active in [PIOS, OWN_CONFIG] {
                    let card = Card::new();
                    card.write_boot("config.txt", active);
                    card.write_boot("config.pios.txt", backup);
                    let before = card.snapshot();

                    let ran = card.run(shell);
                    assert_eq!(
                        ran.status,
                        Some(BACKUP_REFUSED),
                        "{shell}, {case}: {}",
                        ran.stderr
                    );
                    assert!(
                        ran.stderr.contains("config.pios.txt"),
                        "{case}: {}",
                        ran.stderr
                    );
                    assert!(ran.stderr.contains(reason), "{case}: {}", ran.stderr);
                    assert_eq!(card.read_boot("config.txt"), active.as_bytes(), "{case}");
                    // With qberrypi selected, the next restart could not be undone: say so.
                    assert_eq!(
                        ran.stderr.contains("the next restart would start it"),
                        active == OWN_CONFIG,
                        "{case}: {}",
                        ran.stderr
                    );
                    assert_eq!(card.snapshot(), before, "{case}");
                    assert!(!card.trace().contains("restart"), "{case}");
                }
            }
        }
        assert!(![0, 1, 2, ALREADY_SELECTED].contains(&BACKUP_REFUSED));
    }

    #[test]
    fn a_config_txt_that_could_not_be_restored_is_not_saved_as_the_backup() {
        for shell in shells() {
            // With no backup yet, config.txt is what would be saved, so it is judged first.
            let cases = REFUSED_BACKUPS
                .iter()
                .filter(|(_, _, reason)| *reason != "selects qberrypi")
                .map(|&(case, data, reason)| (case, Some(data), reason))
                .chain([
                    ("empty", Some(&b""[..]), "is empty"),
                    ("missing", None, "is missing"),
                ]);
            for (case, active, reason) in cases {
                // The backup is either not there or an empty file, which counts the same.
                for empty_backup in [false, true] {
                    let card = Card::new();
                    if let Some(active) = active {
                        card.write_boot("config.txt", active);
                    }
                    if empty_backup {
                        card.write_boot("config.pios.txt", "");
                    }
                    let before = card.snapshot();

                    let ran = card.run(shell);
                    assert_eq!(
                        ran.status,
                        Some(BACKUP_REFUSED),
                        "{shell}, {case}: {}",
                        ran.stderr
                    );
                    assert!(ran.stderr.contains(reason), "{case}: {}", ran.stderr);
                    assert_eq!(card.snapshot(), before, "{case}");
                    assert!(!card.trace().contains("restart"), "{case}");
                }
            }
        }
    }

    #[test]
    fn a_backup_init_would_restore_is_accepted_and_kept_byte_for_byte() {
        let backups: [&[u8]; 4] = [
            b"#os_prefix=qberrypi/\n  # os_prefix=qberrypi/\narm_64bit=1\n",
            b"os_prefix=pios/\nx_os_prefix=qberrypi/\n",
            b"# caf\xe9 \xff\xfe\narm_64bit=1\n",
            b"arm_64bit=1\r\ndtparam=audio=on",
        ];
        for shell in shells() {
            for backup in backups {
                // Saved earlier, with qberrypi or Raspberry Pi OS selected now; or saved by this run.
                for (active, saved) in [
                    (OWN_CONFIG.as_bytes(), true),
                    (backup, true),
                    (backup, false),
                ] {
                    let card = Card::new();
                    card.write_boot("config.txt", active);
                    if saved {
                        card.write_boot("config.pios.txt", backup);
                    }
                    let ran = card.run(shell);
                    assert_eq!(ran.status, Some(0), "{shell}: {}", ran.stderr);
                    assert_eq!(card.read_boot("config.pios.txt"), backup);
                    assert_eq!(card.read_boot("config.txt"), OWN_CONFIG.as_bytes());
                }
            }
        }
    }

    #[test]
    fn a_config_txt_changed_since_the_backup_stops_the_deploy() {
        for shell in shells() {
            // Init would put the saved one back and the newer one would be lost.
            for newer in [Some("PIOS\ndtparam=audio=on\n"), Some("PIOS"), None] {
                let card = Card::new();
                card.write_boot("config.pios.txt", PIOS);
                if let Some(newer) = newer {
                    card.write_boot("config.txt", newer);
                }
                let before = card.snapshot();
                let ran = card.run(shell);
                assert_eq!(ran.status, Some(CONFIG_CHANGED), "{shell}: {}", ran.stderr);
                assert_eq!(card.snapshot(), before);
                // The message gives both ways on, as commands: keep the newer one or the saved one.
                let backup = card.boot.join("config.pios.txt");
                let active = card.boot.join("config.txt");
                let keep_newer = format!("rm {}", backup.display());
                let keep_saved = format!("cp {} {}", backup.display(), active.display());
                assert!(ran.stderr.contains(&keep_newer), "{}", ran.stderr);
                assert!(ran.stderr.contains(&keep_saved), "{}", ran.stderr);
                assert!(ran.stderr.contains("deploy again"), "{}", ran.stderr);
                assert!(!card.trace().contains("restart"));
            }
        }
    }

    /// A folder or link in `/tmp` that goes when the test ends, however it ends.
    struct RemovedOnDrop(String);

    impl Drop for RemovedOnDrop {
        fn drop(&mut self) {
            let path = Path::new(&self.0);
            if path.is_symlink() {
                let _ = fs::remove_file(path);
            } else {
                let _ = fs::remove_dir(path);
            }
        }
    }

    #[test]
    fn a_stage_directory_of_the_wrong_shape_is_refused_and_nothing_is_removed() {
        let both = format!("{FAKE_SYNC}{FAKE_RM}");
        for shell in shells() {
            // First make sure the stand-in for rm is the one that runs, and see what a
            // good run removes: the stage directory and nothing else.
            let card = Card::fresh();
            let ran = card.run_text(shell, &card.script().render(), &both);
            assert_eq!(ran.status, Some(0), "{shell}: {}", ran.stderr);
            let removals: Vec<String> = card
                .trace()
                .lines()
                .filter(|line| line.starts_with("rm "))
                .map(str::to_owned)
                .collect();
            assert!(!removals.is_empty());
            for removal in &removals {
                assert_eq!(removal, &format!("rm -rf -- {}", card.stage_path()));
            }
            assert!(card.stage.path().exists(), "the real rm ran");

            let victim = card.tmp.path().join("victim");
            fs::create_dir(&victim).unwrap();
            fs::write(victim.join("SHA256SUMS"), "").unwrap();
            // Both of these exist, so it is their names alone that get them refused.
            let spaced = RemovedOnDrop(format!("{} b", card.stage_path()));
            fs::create_dir(&spaced.0).unwrap();
            let link = RemovedOnDrop(format!("{}L", card.stage_path()));
            symlink(card.stage.path(), &link.0).unwrap();
            let hostile = [
                "/".to_owned(),
                "/tmp".to_owned(),
                "/tmp/".to_owned(),
                "/tmp/qberrypi-stage.x/../..".to_owned(),
                format!("{}/../..", card.stage_path()),
                format!("{}/", card.stage_path()),
                spaced.0.clone(),
                link.0.clone(),
                "/tmp/qberrypi-stage.a;b".to_owned(),
                "/tmp/qberrypi-stage.".to_owned(),
                "/tmp/qberrypi-stage.ab-c".to_owned(),
                "/tmp/qberrypi-stage.ab\ncd".to_owned(),
                "/tmp/qberrypi-stage.*".to_owned(),
                "/tmp/qberrypi-stageabc".to_owned(),
                "tmp/qberrypi-stage.abc".to_owned(),
                victim.to_str().unwrap().to_owned(),
                String::new(),
            ];
            for stage_dir in hostile {
                let card = Card::fresh();
                let before = card.snapshot();
                let script = RemoteScript {
                    stage_dir: stage_dir.clone(),
                    ..card.script()
                };
                let ran = card.run_text(shell, &script.render(), &both);
                assert_eq!(
                    ran.status,
                    Some(BAD_STAGE),
                    "{shell}, {stage_dir:?}: {}",
                    ran.stderr
                );
                assert_eq!(card.trace(), "", "{stage_dir:?}");
                assert_eq!(card.snapshot(), before, "{stage_dir:?}");
            }
        }
    }

    #[test]
    fn with_hardware_checks_a_machine_that_is_not_the_pi_is_refused() {
        // This holds on any machine: none has a temporary folder for a boot partition.
        for shell in shells() {
            let card = Card::fresh();
            let before = card.snapshot();
            let script = RemoteScript {
                hardware_checks: true,
                ..card.script()
            };
            let ran = card.run_text(shell, &script.render(), FAKE_SYNC);
            assert_eq!(ran.status, Some(WRONG_MACHINE), "{shell}: {}", ran.stderr);
            assert_eq!(card.snapshot(), before);
            assert_eq!(card.trace(), "");
        }
    }

    const PI_3_B_PLUS: &str = "Raspberry Pi 3 Model B Plus Rev 1.3";
    /// What `findmnt` says of the boot partition that init mounts.
    const INITS_PARTITION: &str = "/dev/mmcblk0p1 vfat";
    /// Stands in for `mountpoint`: the folder is one.
    const IS_A_MOUNT: &str = "mountpoint() { return 0; }\n";
    /// Stands in for `mountpoint`: the folder is none.
    const IS_NO_MOUNT: &str = "mountpoint() { return 1; }\n";
    /// Stands in for a `findmnt` that cannot say what is mounted there.
    const FINDMNT_FAILS: &str = "findmnt() { return 1; }\n";

    /// Stands in for `findmnt`: gives `answer` to the one question the script asks,
    /// and fails for any other.
    fn findmnt_says(answer: &str) -> String {
        format!(
            "findmnt() {{ [ \"$*\" = \"-no SOURCE,FSTYPE $QBERRYPI_TEST_BOOT\" ] || return 64; \
             printf '%s\\n' {}; }}\n",
            sh_quote(answer)
        )
    }

    /// Whether the tests run as root, for whom the kernel's switches are writable.
    fn is_root() -> bool {
        let probe = tempfile::NamedTempFile::new().unwrap();
        std::os::unix::fs::MetadataExt::uid(&probe.as_file().metadata().unwrap()) == 0
    }

    /// A folder to use as the whole `PATH`: links to the shells and to the tools the
    /// script runs, but for `sync`, `mountpoint` and `findmnt`.
    fn tools_without_findmnt() -> TempDir {
        const TOOLS: [&str; 12] = [
            "cat",
            "cmp",
            "cp",
            "dd",
            "grep",
            "mkdir",
            "mv",
            "rm",
            "sha256sum",
            "tr",
            "truncate",
            "wc",
        ];
        let dir = tempfile::tempdir().unwrap();
        let path = std::env::var_os("PATH").unwrap();
        for tool in TOOLS.iter().chain(&shells()) {
            let real = std::env::split_paths(&path)
                .map(|folder| folder.join(tool))
                .find(|candidate| candidate.is_file())
                .unwrap_or_else(|| panic!("{tool} is not on the PATH"));
            symlink(real, dir.path().join(tool)).unwrap();
        }
        dir
    }

    #[test]
    fn with_hardware_checks_the_boot_partition_that_init_mounts_is_accepted() {
        // The copies are then read back past the page cache, which root alone may empty;
        // as root this test would empty it on the machine it runs on.
        if is_root() {
            return;
        }
        for shell in shells() {
            let card = Card::fresh();
            let script = card.pi_script(PI_3_B_PLUS).render();
            let fakes = format!("{FAKE_SYNC}{IS_A_MOUNT}{}", findmnt_says(INITS_PARTITION));
            let ran = card.run_text(shell, &script, &fakes);
            assert_eq!(ran.status, Some(0), "{shell}: {}", ran.stderr);
            assert_eq!(card.read_boot("config.pios.txt"), PIOS.as_bytes());
            assert_eq!(card.read_boot("config.txt"), OWN_CONFIG.as_bytes());
            assert!(ran.stdout.contains(SELECTED_MARKER), "{}", ran.stdout);
            assert!(card.trace().contains("restart"));
        }
    }

    #[test]
    fn with_hardware_checks_a_boot_partition_that_init_does_not_mount_is_refused() {
        // Init mounts /dev/mmcblk0p1 as vfat, whatever is mounted here: on any other
        // partition it would find no configuration and no saved config.txt to put back.
        let found_instead = [
            "/dev/mmcblk0p2 vfat",
            "/dev/sda1 vfat",
            "/dev/mmcblk0p1 ext4",
            "/dev/mmcblk0p1",
            "systemd-1 autofs\n/dev/mmcblk0p1 vfat",
            "/dev/mmcblk0p1 vfat\n/dev/sda1 vfat",
        ];
        for shell in shells() {
            for found in found_instead {
                let card = Card::fresh();
                let before = card.snapshot();
                let script = card.pi_script(PI_3_B_PLUS).render();
                let fakes = format!("{FAKE_SYNC}{IS_A_MOUNT}{}", findmnt_says(found));
                let ran = card.run_text(shell, &script, &fakes);
                assert_eq!(
                    ran.status,
                    Some(WRONG_DEVICE),
                    "{shell}, {found:?}: {}",
                    ran.stderr
                );
                // The message names what init needs and what was found.
                assert!(ran.stderr.contains("/dev/mmcblk0p1"), "{}", ran.stderr);
                assert!(ran.stderr.contains(found), "{found:?}: {}", ran.stderr);
                assert!(ran.stderr.contains("othing was changed"), "{}", ran.stderr);
                assert_eq!(card.snapshot(), before, "{found:?}");
                assert_eq!(card.trace(), "", "{found:?}");
                assert!(!ran.stdout.contains(SELECTED_MARKER));
            }
        }
        assert_eq!(WRONG_DEVICE, 10);
        assert!(
            ![
                ALREADY_SELECTED,
                BACKUP_REFUSED,
                CONFIG_CHANGED,
                BAD_STAGE,
                WRONG_MACHINE,
                BAD_COPY,
                CONFIG_NOT_WRITTEN
            ]
            .contains(&WRONG_DEVICE)
        );
    }

    #[test]
    fn with_hardware_checks_a_findmnt_that_fails_or_is_not_there_is_refused() {
        let tools = tools_without_findmnt();
        for shell in shells() {
            // One that cannot answer, and none at all on the PATH.
            for (fakes, path) in [
                (format!("{FAKE_SYNC}{IS_A_MOUNT}{FINDMNT_FAILS}"), None),
                (format!("{FAKE_SYNC}{IS_A_MOUNT}"), Some(tools.path())),
            ] {
                let card = Card::fresh();
                let before = card.snapshot();
                let script = card.pi_script(PI_3_B_PLUS).render();
                let ran = card.run_on_path(shell, &script, &fakes, path);
                assert_eq!(ran.status, Some(WRONG_DEVICE), "{shell}: {}", ran.stderr);
                assert!(ran.stderr.contains("findmnt"), "{}", ran.stderr);
                assert!(ran.stderr.contains("othing was changed"), "{}", ran.stderr);
                assert_eq!(card.snapshot(), before);
                assert_eq!(card.trace(), "");
            }
        }
    }

    #[test]
    fn the_folder_of_tools_without_findmnt_lacks_nothing_else_the_script_needs() {
        // Or the test above would pass for a script that broke on something else.
        if is_root() {
            return;
        }
        let tools = tools_without_findmnt();
        for shell in shells() {
            let card = Card::fresh();
            let script = card.pi_script(PI_3_B_PLUS).render();
            let fakes = format!("{FAKE_SYNC}{IS_A_MOUNT}{}", findmnt_says(INITS_PARTITION));
            let ran = card.run_on_path(shell, &script, &fakes, Some(tools.path()));
            assert_eq!(ran.status, Some(0), "{shell}: {}", ran.stderr);
            assert_eq!(card.read_boot("config.txt"), OWN_CONFIG.as_bytes());
        }
    }

    #[test]
    fn with_hardware_checks_another_board_or_a_folder_that_is_no_mount_is_refused() {
        for shell in shells() {
            for (model, mount, said) in [
                (
                    "Raspberry Pi 4 Model B Rev 1.4",
                    IS_A_MOUNT,
                    "Raspberry Pi 4",
                ),
                (PI_3_B_PLUS, IS_NO_MOUNT, "is not a mount point"),
            ] {
                let card = Card::fresh();
                let before = card.snapshot();
                let script = card.pi_script(model).render();
                let fakes = format!("{FAKE_SYNC}{mount}{}", findmnt_says(INITS_PARTITION));
                let ran = card.run_text(shell, &script, &fakes);
                assert_eq!(ran.status, Some(WRONG_MACHINE), "{shell}: {}", ran.stderr);
                assert!(ran.stderr.contains(said), "{}", ran.stderr);
                assert_eq!(card.snapshot(), before);
                assert_eq!(card.trace(), "");
            }
        }
    }

    #[test]
    fn the_script_refuses_while_the_package_manager_runs() {
        for shell in shells() {
            for process in ["apt", "apt-get", "dpkg"] {
                let card = Card::fresh();
                let before = card.snapshot();
                let fakes = format!("{FAKE_SYNC}{}", package_manager_running(process));
                let ran = card.run_text(shell, &card.script().render(), &fakes);
                assert_eq!(
                    ran.status,
                    Some(UPGRADING),
                    "{shell}, {process}: {}",
                    ran.stderr
                );
                let named = format!("({process} is running)");
                assert!(ran.stderr.contains(&named), "{process}: {}", ran.stderr);
                assert!(ran.stderr.contains("try again"), "{}", ran.stderr);
                assert!(ran.stderr.contains("othing was changed"), "{}", ran.stderr);
                // Nothing was written, synced or restarted, and nothing was selected.
                assert_eq!(card.snapshot(), before, "{shell}, {process}");
                assert_eq!(card.trace(), "", "{shell}, {process}");
                assert!(!ran.stdout.contains(SELECTED_MARKER));
            }
            // With none of them running the deploy goes through, as it always did.
            let card = Card::fresh();
            let ran = card.run(shell);
            assert_eq!(ran.status, Some(0), "{shell}: {}", ran.stderr);
            assert_eq!(card.read_boot("config.txt"), OWN_CONFIG.as_bytes());
        }
        assert_eq!(UPGRADING, 11);
        assert!(
            ![
                ALREADY_SELECTED,
                BACKUP_REFUSED,
                CONFIG_CHANGED,
                BAD_STAGE,
                WRONG_MACHINE,
                BAD_COPY,
                CONFIG_NOT_WRITTEN,
                WRONG_DEVICE
            ]
            .contains(&UPGRADING)
        );
    }

    #[test]
    fn the_idle_unattended_upgrades_daemon_does_not_stop_a_deploy() {
        // Raspberry Pi OS keeps that daemon running all the time, so a name search that finds
        // it would refuse every deploy for ever.
        let table = [
            IDLE_UPGRADES_DAEMON,
            (
                "tail",
                "tail -f /var/log/unattended-upgrades/unattended-upgrades.log",
            ),
        ];
        for shell in shells() {
            let fakes = format!("{FAKE_SYNC}{}", processes_running(&table));
            // The stand-in would refuse a script that looks for the daemon by its name.
            let by_name = Command::new(shell)
                .args(["-c", &format!("{fakes}pgrep -x unattended-upgr")])
                .status()
                .unwrap();
            assert!(by_name.success(), "{shell}: the stand-in finds no daemon");

            let card = Card::fresh();
            let ran = card.run_text(shell, &card.script().render(), &fakes);
            assert_eq!(ran.status, Some(0), "{shell}: {}", ran.stderr);
            assert_eq!(card.read_boot("config.txt"), OWN_CONFIG.as_bytes());
            assert!(ran.stdout.contains(SELECTED_MARKER), "{}", ran.stdout);
            assert_eq!(ran.stderr, "", "{shell}");
        }
    }

    #[test]
    fn the_script_refuses_while_the_unattended_upgrade_worker_runs() {
        // The worker has the same process name as the idle daemon, so only its command line
        // tells them apart; with arguments or without, python3 runs it by its path.
        for shell in shells() {
            for command in [
                "/usr/bin/python3 /usr/bin/unattended-upgrade",
                "/usr/bin/python3 /usr/bin/unattended-upgrade -d",
                "/usr/bin/python3 /usr/bin/unattended-upgrade --download-only",
            ] {
                for beside_daemon in [false, true] {
                    let worker = ("unattended-upgr", command);
                    let table = if beside_daemon {
                        vec![IDLE_UPGRADES_DAEMON, worker]
                    } else {
                        vec![worker]
                    };
                    let card = Card::fresh();
                    let before = card.snapshot();
                    let fakes = format!("{FAKE_SYNC}{}", processes_running(&table));
                    let ran = card.run_text(shell, &card.script().render(), &fakes);
                    let what = format!("{shell}, {command}, with the daemon: {beside_daemon}");
                    assert_eq!(ran.status, Some(UPGRADING), "{what}: {}", ran.stderr);
                    assert!(
                        ran.stderr.contains("(unattended-upgrade is running)"),
                        "{what}: {}",
                        ran.stderr
                    );
                    assert!(ran.stderr.contains("try again"), "{}", ran.stderr);
                    assert!(ran.stderr.contains("othing was changed"), "{}", ran.stderr);
                    // Nothing was written, synced or restarted, and nothing was selected.
                    assert_eq!(card.snapshot(), before, "{what}");
                    assert_eq!(card.trace(), "", "{what}");
                    assert!(!ran.stdout.contains(SELECTED_MARKER), "{what}");
                }
            }
        }
    }

    #[test]
    fn the_package_manager_guard_comes_after_the_checks_of_the_stage() {
        // The guard sits after the checks of the stage and the board, so what is wrong with
        // those is still what is said first.
        for shell in shells() {
            let card = Card::fresh();
            fs::remove_file(card.stage.path().join("SHA256SUMS")).unwrap();
            let fakes = format!("{FAKE_SYNC}{}", package_manager_running("dpkg"));
            let ran = card.run_text(shell, &card.script().render(), &fakes);
            assert_eq!(ran.status, Some(BAD_STAGE), "{shell}: {}", ran.stderr);
        }
    }

    #[test]
    fn the_card_is_synced_after_selecting_and_before_the_restart() {
        // This stand-in for sync also records how far the saving of the backup has come.
        let sync = "sync() { printf 'sync: %s new=%s saved=%s\\n' \
            \"$(cat \"$QBERRYPI_TEST_BOOT/config.txt\")\" \
            \"$(test -e \"$QBERRYPI_TEST_BOOT/config.pios.txt.new\" && echo yes || echo no)\" \
            \"$(test -e \"$QBERRYPI_TEST_BOOT/config.pios.txt\" && echo yes || echo no)\" \
            >>\"$QBERRYPI_TEST_TRACE\"; }\n";
        for shell in shells() {
            let card = Card::fresh();
            let ran = card.run_text(shell, &card.script().render(), sync);
            assert_eq!(ran.status, Some(0), "{shell}: {}", ran.stderr);
            let trace = card.trace();
            let lines: Vec<&str> = trace.lines().collect();
            assert_eq!(
                lines,
                [
                    // The copy is on the card before it gets the name of the backup.
                    "sync: PIOS new=yes saved=no",
                    "sync: PIOS new=no saved=yes",
                    // Before the copies of the build are read back.
                    "sync: PIOS new=no saved=yes",
                    // The write of config.txt, and once more before the restart.
                    "sync: os_prefix=qberrypi/ new=no saved=yes",
                    "sync: os_prefix=qberrypi/ new=no saved=yes",
                    "restart: os_prefix=qberrypi/",
                ],
                "{shell}"
            );
        }
    }

    /// Makes every write of `config.txt` fail before it has written anything.
    const DD_FAILS: &str = "dd() { return 1; }\n";
    /// Makes every write of `config.txt` fail after it has ruined the file.
    const DD_RUINS: &str =
        "dd() { printf 'GARBAGE' >\"$QBERRYPI_TEST_BOOT/config.txt\"; return 1; }\n";
    /// The same, but only for the write that selects qberrypi; other writes work.
    const DD_RUINS_THE_SELECT: &str = "dd() { case \"$*\" in \
        *qberrypi/config.txt*) printf 'GARBAGE' >\"$QBERRYPI_TEST_BOOT/config.txt\"; return 1 ;; \
        *) command dd \"$@\" ;; esac; }\n";
    /// Makes every write of `config.txt` report success after writing something else.
    const DD_LIES: &str =
        "dd() { printf 'GARBAGE-GARBAGE-GARBAGE-GARBAGE' >\"$QBERRYPI_TEST_BOOT/config.txt\"; }\n";
    /// Lets the write through but not the cutting of the old tail.
    const TRUNCATE_FAILS: &str = "truncate() { return 1; }\n";

    /// What the script tells the owner to run when it leaves a `config.txt` it could not write.
    fn put_back_command(card: &Card) -> String {
        format!(
            "sudo cp {} {}",
            card.boot.join("config.pios.txt").display(),
            card.boot.join("config.txt").display()
        )
    }

    #[test]
    fn a_select_that_fails_puts_raspberry_pi_os_back_itself() {
        for shell in shells() {
            let card = Card::fresh();
            let fakes = format!("{FAKE_SYNC}{DD_RUINS_THE_SELECT}");
            let ran = card.run_text(shell, &card.script().render(), &fakes);
            assert_eq!(
                ran.status,
                Some(CONFIG_NOT_WRITTEN),
                "{shell}: {}",
                ran.stderr
            );
            assert_eq!(CONFIG_NOT_WRITTEN, 9);
            // The ruined file is whole again: the saved bytes and nothing after them.
            assert_eq!(card.read_boot("config.txt"), PIOS.as_bytes());
            assert_eq!(card.read_boot("config.pios.txt"), PIOS.as_bytes());
            assert!(
                ran.stderr.contains("the next restart is Raspberry Pi OS"),
                "{}",
                ran.stderr
            );
            assert!(!ran.stdout.contains(SELECTED_MARKER));
            assert!(!card.trace().contains("restart"));
        }
    }

    #[test]
    fn a_select_that_fails_and_cannot_be_undone_says_what_state_the_card_is_in() {
        for shell in shells() {
            for (fake, left) in [
                (DD_FAILS, Some(PIOS)),
                (DD_RUINS, Some("GARBAGE")),
                // Only reading the file back shows that these two went wrong.
                (DD_LIES, None),
                (TRUNCATE_FAILS, None),
            ] {
                let card = Card::fresh();
                let fakes = format!("{FAKE_SYNC}{fake}");
                let ran = card.run_text(shell, &card.script().render(), &fakes);
                assert_eq!(
                    ran.status,
                    Some(CONFIG_NOT_WRITTEN),
                    "{shell}: {}",
                    ran.stderr
                );
                if let Some(left) = left {
                    assert_eq!(card.read_boot("config.txt"), left.as_bytes());
                }
                assert_eq!(card.read_boot("config.pios.txt"), PIOS.as_bytes());
                assert!(ran.stderr.contains("may be damaged"), "{}", ran.stderr);
                assert!(
                    ran.stderr.contains(&put_back_command(&card)),
                    "{}",
                    ran.stderr
                );
                assert!(!ran.stdout.contains(SELECTED_MARKER));
                assert!(!card.trace().contains("restart"));
            }
        }
    }

    #[test]
    fn a_deselect_that_fails_stops_before_the_folder_is_touched() {
        for shell in shells() {
            for (fake, left) in [(DD_FAILS, OWN_CONFIG), (DD_RUINS, "GARBAGE")] {
                let card = selected_card();
                let fakes = format!("{FAKE_SYNC}{fake}");
                let ran = card.run_text(shell, &card.script().render(), &fakes);
                assert_eq!(
                    ran.status,
                    Some(CONFIG_NOT_WRITTEN),
                    "{shell}: {}",
                    ran.stderr
                );
                assert_eq!(card.read_boot("config.txt"), left.as_bytes());
                assert_eq!(card.read_boot("config.pios.txt"), PIOS.as_bytes());
                assert_eq!(card.read_boot("qberrypi/kernel8.img"), b"OLD KERNEL");
                assert!(ran.stderr.contains("may be damaged"), "{}", ran.stderr);
                assert!(
                    ran.stderr.contains(&put_back_command(&card)),
                    "{}",
                    ran.stderr
                );
                assert!(!card.trace().contains("restart"));
            }
        }
    }

    #[test]
    fn a_read_only_config_txt_ends_the_deploy_with_the_file_as_it_was() {
        // Nothing is faked here: the write itself is refused. Root would not be refused.
        let probe = tempfile::NamedTempFile::new().unwrap();
        if std::os::unix::fs::MetadataExt::uid(&probe.as_file().metadata().unwrap()) == 0 {
            return;
        }
        for shell in shells() {
            for (card, was) in [(Card::fresh(), PIOS), (selected_card(), OWN_CONFIG)] {
                let active = card.boot.join("config.txt");
                fs::set_permissions(&active, Permissions::from_mode(0o444)).unwrap();
                let ran = card.run(shell);
                assert_eq!(
                    ran.status,
                    Some(CONFIG_NOT_WRITTEN),
                    "{shell}: {}",
                    ran.stderr
                );
                assert_eq!(card.read_boot("config.txt"), was.as_bytes());
                assert_eq!(card.read_boot("config.pios.txt"), PIOS.as_bytes());
                assert!(!card.trace().contains("restart"));
                // Why the write failed is dd's to say, and it is let through:
                // on the Pi it is most likely a partition that went read-only.
                let dd_said = ran
                    .stderr
                    .lines()
                    .find(|line| line.starts_with("dd: "))
                    .unwrap_or_else(|| panic!("{shell}: dd said nothing in:\n{}", ran.stderr));
                assert!(dd_said.contains("config.txt"), "{dd_said}");
                assert!(dd_said.contains("Permission denied"), "{dd_said}");
            }
        }
    }

    #[test]
    fn dd_is_told_to_keep_its_count_to_itself_and_its_errors_are_not_thrown_away() {
        let script = production_script();
        let dd_lines: Vec<&str> = script
            .lines()
            .filter(|line| line.trim_start().starts_with("dd "))
            .collect();
        assert_eq!(
            dd_lines,
            [r#"    dd if="$1" of="$active" conv=notrunc status=none || return 1"#]
        );
    }

    #[test]
    fn config_txt_ends_with_exactly_the_bytes_written_whether_shorter_or_longer() {
        let padding = "# a line that makes this configuration longer\n".repeat(120);
        let long_pios = format!("{PIOS}{padding}");
        let long_own = format!("{OWN_CONFIG}{padding}");
        for shell in shells() {
            // Selecting: (what Raspberry Pi OS had, what qberrypi brings).
            for (pios, own) in [(long_pios.as_str(), OWN_CONFIG), (PIOS, long_own.as_str())] {
                let card = Card::new();
                card.write_boot("config.txt", pios);
                let staged: Vec<(&str, &[u8])> = STAGED
                    .iter()
                    .map(|&(name, data)| {
                        (
                            name,
                            if name == "config.txt" {
                                own.as_bytes()
                            } else {
                                data
                            },
                        )
                    })
                    .collect();
                card.stage_files(&staged);
                let ran = card.run(shell);
                assert_eq!(ran.status, Some(0), "{shell}: {}", ran.stderr);
                assert_eq!(card.read_boot("config.txt"), own.as_bytes());
                assert_eq!(card.read_boot("config.pios.txt"), pios.as_bytes());
            }
            // Deselecting: (what was selected, what was saved). The copy then fails,
            // so the deselected file is what stays.
            for (own, pios) in [(long_own.as_str(), PIOS), (OWN_CONFIG, long_pios.as_str())] {
                let card = selected_card();
                card.write_boot("config.txt", own);
                card.write_boot("config.pios.txt", pios);
                fs::write(card.stage.path().join("kernel8.img"), b"DAMAGED").unwrap();
                let ran = card.run(shell);
                assert_eq!(ran.status, Some(BAD_COPY), "{shell}: {}", ran.stderr);
                assert_eq!(card.read_boot("config.txt"), pios.as_bytes());
                assert_eq!(card.read_boot("config.pios.txt"), pios.as_bytes());
            }
        }
    }

    #[test]
    fn the_write_of_config_txt_creates_a_missing_file_and_refuses_an_empty_one() {
        for shell in shells() {
            let card = Card::new();
            card.write_boot("source", "arm_64bit=1\n");
            // The script's own definitions, with one call of the write in place of main.
            let script = card.script().render();
            let definitions = script.strip_suffix("main\n").unwrap();
            let call = "active=\"$QBERRYPI_TEST_BOOT/config.txt\"\n\
                        write_config \"$QBERRYPI_TEST_BOOT/source\"\n";
            let ran = card.run_text(shell, &format!("{definitions}{call}"), FAKE_SYNC);
            assert_eq!(ran.status, Some(0), "{shell}: {}", ran.stderr);
            assert_eq!(card.read_boot("config.txt"), b"arm_64bit=1\n");

            // An empty source is never written over a config.txt.
            card.write_boot("source", "");
            let ran = card.run_text(shell, &format!("{definitions}{call}"), FAKE_SYNC);
            assert_ne!(ran.status, Some(0), "{shell}");
            assert_eq!(card.read_boot("config.txt"), b"arm_64bit=1\n");
        }
    }

    #[test]
    fn a_script_cut_short_changes_nothing() {
        for shell in shells() {
            let card = Card::fresh();
            let before = card.snapshot();
            let script = card.script().render();
            let last_line = script.trim_end().rfind('\n').unwrap() + 1;
            // Cut after every line, and at every byte of the last line, which starts the work.
            let cuts = script[..last_line]
                .match_indices('\n')
                .map(|(at, _)| at + 1)
                .chain(last_line..script.trim_end().len());
            for cut in cuts {
                let ran = card.run_text(shell, &script[..cut], FAKE_SYNC);
                assert_eq!(card.snapshot(), before, "{shell}, cut at byte {cut}");
                assert!(card.stage.path().exists(), "{shell}, cut at byte {cut}");
                assert_eq!(card.trace(), "", "{shell}, cut at byte {cut}");
                assert!(!ran.stdout.contains(SELECTED_MARKER));
            }
            // The whole script does run; the cuts above were the only difference.
            assert_eq!(card.run(shell).status, Some(0));
        }
    }

    #[test]
    fn paths_with_spaces_and_quotes_are_quoted() {
        for shell in shells() {
            let card = Card::with_boot_name("boot dir's \"x\" $HOME `id`;*");
            card.write_boot("config.txt", PIOS);
            let ran = card.run(shell);
            assert_eq!(ran.status, Some(0), "{shell}: {}", ran.stderr);
            assert_eq!(card.read_boot("config.pios.txt"), PIOS.as_bytes());
            assert_eq!(card.read_boot("config.txt"), OWN_CONFIG.as_bytes());
            assert_eq!(card.read_boot("qberrypi/kernel8.img"), b"KERNEL");
            // Nothing landed beside the boot folder.
            assert_eq!(fs::read_dir(card.tmp.path()).unwrap().count(), 2);
        }
    }

    #[test]
    fn a_log_from_an_earlier_boot_survives_a_deploy() {
        for shell in shells() {
            let card = Card::fresh();
            card.write_boot("qberrypi/log.txt", "earlier boot\n");
            assert_eq!(card.run(shell).status, Some(0));
            assert_eq!(card.read_boot("qberrypi/log.txt"), b"earlier boot\n");
        }
    }

    #[test]
    fn the_overlay_files_land_flat_in_qberrypis_folder_for_the_firmware_to_find() {
        // The firmware reads `qberrypi/ov-README` and `qberrypi/ov-<overlay>.dtbo`; it never looks
        // in a folder of overlays, and the script makes none.
        for shell in shells() {
            let card = Card::fresh();
            let ran = card.run(shell);
            assert_eq!(ran.status, Some(0), "{shell}: {}", ran.stderr);
            for (name, data) in [
                ("ov-README", &b"README"[..]),
                ("ov-overlay_map.dtb", b"OVERLAY_MAP"),
                ("ov-qb-piscreen.dtbo", b"PISCREEN"),
            ] {
                assert_eq!(card.read_boot(&format!("qberrypi/{name}")), data, "{name}");
            }
            assert!(!card.has_boot("overlays"), "{shell}");
            assert!(!card.has_boot("qberrypi/overlays"), "{shell}");
        }
    }

    #[test]
    fn the_script_says_when_the_build_carries_no_overlay_of_its_own() {
        const NOTE: &str = "qberrypi-deploy: note: the build carries no overlay of its own: the \
                            front panel will stay dark";
        for shell in shells() {
            // The usual stage has them: nothing to say, and nothing but that.
            let card = Card::fresh();
            let ran = card.run(shell);
            assert_eq!(ran.status, Some(0), "{shell}: {}", ran.stderr);
            assert!(
                !ran.stdout.contains("note: the build carries no overlay"),
                "{shell}: {}",
                ran.stdout
            );
            assert!(!ran.stdout.contains("note:"), "{shell}: {}", ran.stdout);

            // A stage without the one file or the other, or without either, gets the note.
            for without in [
                &["ov-README"][..],
                &["ov-qb-piscreen.dtbo"],
                &["ov-README", "ov-overlay_map.dtb", "ov-qb-piscreen.dtbo"],
            ] {
                let card = Card::fresh();
                card.stage_all_but(without);
                let ran = card.run(shell);
                // It stops nothing.
                assert_eq!(ran.status, Some(0), "{shell}, {without:?}: {}", ran.stderr);
                assert_eq!(card.read_boot("config.txt"), OWN_CONFIG.as_bytes());
                assert!(ran.stdout.contains(SELECTED_MARKER), "{}", ran.stdout);
                assert_eq!(ran.stderr, "", "{shell}, {without:?}");
                // It is said once, and before the first thing that is written.
                let lines: Vec<&str> = ran.stdout.lines().collect();
                let notes: Vec<usize> = (0..lines.len()).filter(|&i| lines[i] == NOTE).collect();
                let first_write = lines
                    .iter()
                    .position(|line| line.contains("saving config.txt"));
                assert!(
                    notes.len() == 1 && Some(notes[0]) < first_write,
                    "{shell}, {without:?}: {}",
                    ran.stdout
                );
                // What the stage did bring was copied all the same.
                assert_eq!(card.read_boot("qberrypi/kernel8.img"), b"KERNEL");
            }

            // A map the firmware can do without is no reason for the note.
            let card = Card::fresh();
            card.stage_all_but(&["ov-overlay_map.dtb"]);
            let ran = card.run(shell);
            assert_eq!(ran.status, Some(0), "{shell}: {}", ran.stderr);
            assert!(!ran.stdout.contains("note:"), "{shell}: {}", ran.stdout);
        }
    }

    #[test]
    fn the_note_about_the_overlay_is_made_before_anything_is_written() {
        // A stage with no overlay that the script then refuses for another reason: the note was
        // said, and the card is as it was.
        for shell in shells() {
            let card = Card::new();
            card.write_boot("config.txt", "os_prefix=qberrypi/\n");
            card.stage_all_but(&["ov-README", "ov-qb-piscreen.dtbo"]);
            let before = card.snapshot();

            let ran = card.run(shell);

            assert_eq!(
                ran.status,
                Some(ALREADY_SELECTED),
                "{shell}: {}",
                ran.stderr
            );
            assert!(
                ran.stdout
                    .contains("note: the build carries no overlay of its own"),
                "{shell}: {}",
                ran.stdout
            );
            assert_eq!(card.snapshot(), before, "{shell}");
        }
    }

    /// A key and certificate left on the card by an earlier deploy: what no output may show.
    const STALE_PEM: &str =
        "-----BEGIN PRIVATE KEY-----\nSTALEKEYLINE\n-----END PRIVATE KEY-----\n";

    /// Stages the files as `deploy` does, with the checksums that `staged_checksums` makes: the
    /// build's files, the configuration, and `certificate` as `tls.pem` if there is one.
    fn stage_as_deploy_does(card: &Card, certificate: Option<&[u8]>) {
        let built: Vec<(&str, &[u8])> = STAGED
            .iter()
            .copied()
            .filter(|(name, _)| *name != "qberrypi.toml")
            .collect();
        let toml: &[u8] = STAGED
            .iter()
            .find(|(name, _)| *name == "qberrypi.toml")
            .unwrap()
            .1;
        let (_, sums) = staged_checksums(&sha256sums(&built), toml, certificate).unwrap();
        let mut staged = built;
        staged.push(("qberrypi.toml", toml));
        card.stage_files(&staged);
        if let Some(pem) = certificate {
            card.write_stage(TLS_FILE, pem);
        }
        fs::write(card.stage.path().join("SHA256SUMS"), sums).unwrap();
    }

    #[test]
    fn a_tls_pem_on_the_card_goes_when_the_deploy_brings_none() {
        for shell in shells() {
            let card = Card::fresh();
            card.write_boot("qberrypi/tls.pem", STALE_PEM);
            card.write_boot("qberrypi/log.txt", "LOG\n");
            stage_as_deploy_does(&card, None);

            let ran = card.run(shell);

            assert_eq!(ran.status, Some(0), "{shell}: {}", ran.stderr);
            assert!(!card.has_boot("qberrypi/tls.pem"), "{shell}");
            // Nothing else of the folder was touched, and the build went in as usual.
            assert_eq!(card.read_boot("qberrypi/log.txt"), b"LOG\n");
            for (name, data) in STAGED {
                assert_eq!(card.read_boot(&format!("qberrypi/{name}")), data, "{name}");
            }
            assert_eq!(card.read_boot("config.txt"), OWN_CONFIG.as_bytes());
            // It says which file it removes, before it selects qberrypi, and shows none of it.
            let removing = format!(
                "qberrypi-deploy: removing {}/qberrypi/tls.pem: ",
                card.boot.display()
            );
            let lines: Vec<&str> = ran.stdout.lines().collect();
            let said = lines.iter().position(|line| line.starts_with(&removing));
            let selecting = lines
                .iter()
                .position(|line| line.ends_with("selecting qberrypi"));
            assert!(
                said.is_some() && said < selecting,
                "{shell}: {}",
                ran.stdout
            );
            assert_eq!(ran.stderr, "", "{shell}");
            for text in [&ran.stdout, &ran.stderr, &card.trace()] {
                assert!(
                    !text.contains("STALEKEY") && !text.contains("PRIVATE"),
                    "{shell}: {text}"
                );
            }
        }
    }

    #[test]
    fn a_tls_pem_the_deploy_brings_replaces_the_one_on_the_card_and_is_not_removed() {
        for shell in shells() {
            let card = Card::fresh();
            card.write_boot("qberrypi/tls.pem", STALE_PEM);
            let new_pem = "-----BEGIN PRIVATE KEY-----\nNEWKEYLINE\n-----END PRIVATE KEY-----\n";
            stage_as_deploy_does(&card, Some(new_pem.as_bytes()));

            let ran = card.run(shell);

            assert_eq!(ran.status, Some(0), "{shell}: {}", ran.stderr);
            assert_eq!(card.read_boot("qberrypi/tls.pem"), new_pem.as_bytes());
            assert!(!ran.stdout.contains("removing"), "{shell}: {}", ran.stdout);
            assert_eq!(ran.stderr, "", "{shell}");
            for text in [&ran.stdout, &ran.stderr, &card.trace()] {
                assert!(!text.contains("KEYLINE"), "{shell}: {text}");
            }
        }
    }

    #[test]
    fn a_card_without_a_tls_pem_is_not_told_of_one() {
        for shell in shells() {
            let card = Card::fresh();
            stage_as_deploy_does(&card, None);
            let ran = card.run(shell);
            assert_eq!(ran.status, Some(0), "{shell}: {}", ran.stderr);
            assert!(!card.has_boot("qberrypi/tls.pem"), "{shell}");
            assert!(!ran.stdout.contains("tls.pem"), "{shell}: {}", ran.stdout);
        }
    }

    #[test]
    fn a_tls_pem_that_is_a_link_is_removed_and_what_it_pointed_at_is_not() {
        for shell in shells() {
            // A link that points at a file, and one that points at nothing.
            for target_exists in [true, false] {
                let card = Card::fresh();
                let target = card.tmp.path().join("elsewhere");
                if target_exists {
                    fs::write(&target, "ELSEWHERE").unwrap();
                }
                fs::create_dir(card.boot.join("qberrypi")).unwrap();
                std::os::unix::fs::symlink(&target, card.boot.join("qberrypi/tls.pem")).unwrap();
                stage_as_deploy_does(&card, None);

                let ran = card.run(shell);

                assert_eq!(ran.status, Some(0), "{shell}: {}", ran.stderr);
                let gone = fs::symlink_metadata(card.boot.join("qberrypi/tls.pem")).is_err();
                assert!(gone, "{shell}, target {target_exists}");
                assert_eq!(target.exists(), target_exists, "{shell}");
            }
        }
    }

    #[test]
    fn a_tls_pem_that_cannot_be_removed_stops_the_deploy_before_qberrypi_is_selected() {
        for shell in shells() {
            let card = Card::fresh();
            // A folder of that name, which `rm -f` does not take away.
            fs::create_dir_all(card.boot.join("qberrypi/tls.pem")).unwrap();
            fs::write(card.boot.join("qberrypi/tls.pem/inside"), "X").unwrap();
            stage_as_deploy_does(&card, None);

            let ran = card.run(shell);

            assert_eq!(ran.status, Some(BAD_COPY), "{shell}: {}", ran.stderr);
            assert!(card.has_boot("qberrypi/tls.pem/inside"), "{shell}");
            assert_eq!(card.read_boot("config.txt"), PIOS.as_bytes());
            assert!(!card.trace().contains("restart"), "{shell}");
            assert!(!ran.stdout.contains(SELECTED_MARKER), "{shell}");
            assert!(
                ran.stderr.contains("the next restart is Raspberry Pi OS"),
                "{shell}: {}",
                ran.stderr
            );
        }
    }

    #[test]
    fn a_stage_that_lists_a_certificate_it_does_not_hold_removes_nothing() {
        for shell in shells() {
            let card = Card::fresh();
            card.write_boot("qberrypi/tls.pem", STALE_PEM);
            stage_as_deploy_does(&card, Some(b"NEW"));
            // The file did not reach the stage; the checksums still list it.
            fs::remove_file(card.stage.path().join("tls.pem")).unwrap();

            let ran = card.run(shell);

            // The card's file is not the listed one: the copy fails its check and nothing is selected.
            assert_eq!(ran.status, Some(BAD_COPY), "{shell}: {}", ran.stderr);
            assert_eq!(card.read_boot("qberrypi/tls.pem"), STALE_PEM.as_bytes());
            assert_eq!(card.read_boot("config.txt"), PIOS.as_bytes());
            assert!(!ran.stdout.contains("removing"), "{shell}: {}", ran.stdout);
        }
    }

    fn production_script() -> String {
        RemoteScript {
            boot_dir: "/boot/firmware".to_owned(),
            stage_dir: "/tmp/qberrypi-stage.Ab12Cd".to_owned(),
            reboot_cmd: "systemctl reboot".to_owned(),
            hardware_checks: true,
            model_file: "/proc/device-tree/model".to_owned(),
        }
        .render()
    }

    #[test]
    fn the_production_script_names_the_real_paths() {
        let script = production_script();
        assert!(script.starts_with("#!/bin/sh\n"));
        assert!(script.contains("\nset -eu\n"));
        assert!(script.contains("\nboot='/boot/firmware'\n"));
        assert!(script.contains("\nstage='/tmp/qberrypi-stage.Ab12Cd'\n"));
        assert!(script.contains("\nhardware_checks=yes\n"));
        assert!(script.contains("\nupgrading=11\n"));
        // The certificate that it takes off the card is the one that init reads, by init's name.
        assert_eq!(TLS_FILE, "tls.pem");
        assert!(script.contains(r##"grep -q "^[0-9a-f]\{64\}  tls\.pem\$" "$stage/SHA256SUMS""##));
        assert!(script.contains(r#"rm -f -- "$own/tls.pem""#));
        assert!(script.contains("for p in apt apt-get dpkg; do"));
        assert!(script.contains(r#"if pgrep -x "$p" >/dev/null 2>&1; then"#));
        // The upgrade worker is found by its command line, not by the name it shares with the
        // idle daemon, and by a pattern that cannot match the line that holds it.
        assert!(
            script
                .contains("if pgrep -f '/usr/bin/unattended-upgrad[e]( |$)' >/dev/null 2>&1; then")
        );
        assert!(!script.contains("unattended-upgr;"));
        assert!(!script.contains("-x unattended-upgr"));
        assert!(script.contains("\n    systemctl reboot\n"));
        assert!(script.contains("Raspberry Pi 3 Model B Plus"));
        assert!(script.contains("\nmodel_file='/proc/device-tree/model'\n"));
        // The device is the one init mounts, by init's own constant.
        assert_eq!(qberrypi::bootpart::BOOT_DEV, "/dev/mmcblk0p1");
        assert!(script.contains("\nboot_device='/dev/mmcblk0p1'\n"));
        assert!(script.contains(r#"findmnt -no SOURCE,FSTYPE "$boot""#));
        assert!(script.contains(r#"[ "$mounted" = "$boot_device vfat" ]"#));
        assert!(script.ends_with("\nmain\n"));
    }

    #[test]
    fn the_worker_pattern_cannot_match_the_script_that_holds_it() {
        // `pgrep -f` searches the command lines of every process, the shell that runs this
        // script included. Written without the bracket, the pattern's own text would be a hit
        // on any command line that carries the script, so the worker's path must not occur in
        // the script as a word of its own.
        let script = production_script();
        assert!(script.contains("/usr/bin/unattended-upgrad[e]( |$)"));
        let worker = "/usr/bin/unattended-upgrade";
        for (at, _) in script.match_indices(worker) {
            let after = script[at + worker.len()..].chars().next();
            assert!(
                !matches!(after, None | Some(' ' | '\t' | '\n')),
                "the script holds the worker's path as it would be matched: {}",
                &script[at..(at + 60).min(script.len())]
            );
        }
    }

    #[test]
    fn the_script_keeps_to_posix_sh() {
        // No substitute for running it under dash, but it catches the usual slips.
        let script = production_script();
        for bashism in [
            "[[ ",
            " ]]",
            "local ",
            "function ",
            "<<<",
            "&>",
            "$'",
            "==",
            "source ",
            "${!",
            "=(",
            "echo -e",
            "echo -n",
            "pipefail",
            "$RANDOM",
            "+=",
        ] {
            assert!(!script.contains(bashism), "the script uses {bashism:?}");
        }
    }

    // ---------------------------------------------------------------- waiting for the Pi

    /// A clock that only moves when it is slept on, or when a test moves it.
    struct FakeClock {
        now: Rc<Cell<Duration>>,
        sleeps: Vec<Duration>,
    }

    impl FakeClock {
        fn new() -> Self {
            FakeClock {
                now: Rc::new(Cell::new(Duration::ZERO)),
                sleeps: Vec::new(),
            }
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Duration {
            self.now.get()
        }

        fn sleep(&mut self, time: Duration) {
            self.sleeps.push(time);
            self.now.set(self.now.get() + time);
        }

        fn unix_time(&self) -> Result<u64> {
            Ok(1_700_000_000)
        }
    }

    const SECOND: Duration = Duration::from_secs(1);

    #[test]
    fn waits_for_the_pi_to_go_down_and_come_back() {
        let mut clock = FakeClock::new();
        let mut answers = VecDeque::from([true, true, false, false, false, true]);
        let outcome = wait_for_return(
            &mut || answers.pop_front().unwrap(),
            back_within(0),
            &mut clock,
        )
        .unwrap();
        assert_eq!(outcome, Returned::AfterRestart);
        assert!(answers.is_empty());
        assert_eq!(clock.sleeps, [5 * SECOND; 4]);
    }

    #[test]
    fn a_pi_that_never_goes_down_is_waited_for_and_then_taken_as_back() {
        let mut clock = FakeClock::new();
        let mut probes = 0;
        let outcome = wait_for_return(
            &mut || {
                probes += 1;
                true
            },
            back_within(0),
            &mut clock,
        )
        .unwrap();
        assert_eq!(outcome, Returned::WithoutGoingDown);
        // 30 s of asking every 5 s whether it has gone, then the one answer that it is there.
        assert_eq!(clock.now(), 30 * SECOND);
        assert_eq!(probes, 8);
    }

    #[test]
    fn a_pi_that_never_comes_back_is_an_error_that_says_how_to_recover() {
        let mut clock = FakeClock::new();
        let mut answers = VecDeque::from([true]);
        let error = wait_for_return(
            &mut || answers.pop_front().unwrap_or(false),
            back_within(0),
            &mut clock,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("return-to-pios"), "{error}");
        assert!(error.contains("power cord"), "{error}");
        assert!(!error.contains("another computer"), "{error}");
        // Gone after 5 s, then 300 s of asking every 5 s.
        assert_eq!(clock.now(), 305 * SECOND);
    }

    #[test]
    fn slow_answers_do_not_stretch_the_wait() {
        // A Pi that is off takes the whole connection timeout to not answer.
        let mut clock = FakeClock::new();
        let now = Rc::clone(&clock.now);
        let result = wait_for_return(
            &mut || {
                now.set(now.get() + 10 * SECOND);
                false
            },
            back_within(0),
            &mut clock,
        );
        assert!(result.is_err());
        // Gone at the first answer; then 300 s, overrun by at most one answer and one pause.
        assert!(clock.now() >= 310 * SECOND, "{:?}", clock.now());
        assert!(clock.now() <= 325 * SECOND, "{:?}", clock.now());
    }

    #[test]
    fn the_wait_for_the_return_covers_the_configured_run() {
        let secs = Duration::from_secs;
        // At least 300 s, else the run and 180 s.
        assert_eq!(
            (back_within(0), back_within(40), back_within(400)),
            (secs(300), secs(300), secs(580))
        );
        // A run too long to count is still a limit, not an overflow.
        assert_eq!(back_within(u64::MAX), Duration::MAX);
    }

    #[test]
    fn a_pi_that_runs_longer_is_given_longer_to_come_back() {
        let mut clock = FakeClock::new();
        let mut answers = VecDeque::from([true]);
        let error = wait_for_return(
            &mut || answers.pop_front().unwrap_or(false),
            back_within(400),
            &mut clock,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("within 580 s"), "{error}");
        // Gone after 5 s, then 580 s of asking every 5 s.
        assert_eq!(clock.now(), 585 * SECOND);
    }

    #[test]
    fn the_permanent_build_is_waited_for_until_it_reports_itself() {
        let mut clock = FakeClock::new();
        // Nothing, nothing, another build, this build.
        let mut answers = VecDeque::from([None, None, Some(1), Some(7)]);
        let took = wait_for_qberrypi(&mut || answers.pop_front().unwrap(), 7, &mut clock).unwrap();
        assert_eq!(took, 3 * ASK_EVERY);
        assert_eq!(clock.sleeps, [ASK_EVERY; 3]);
        assert!(answers.is_empty());
    }

    #[test]
    fn a_build_that_answers_at_once_costs_no_waiting() {
        let mut clock = FakeClock::new();
        let took = wait_for_qberrypi(&mut || Some(7), 7, &mut clock).unwrap();
        assert_eq!(took, Duration::ZERO);
        assert!(clock.sleeps.is_empty());
    }

    #[test]
    fn a_build_that_never_answers_is_an_error_that_says_how_to_get_back() {
        let mut clock = FakeClock::new();
        let mut asked = 0;
        let error = wait_for_qberrypi(
            &mut || {
                asked += 1;
                None
            },
            7,
            &mut clock,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("return-to-pios") && error.contains("power cord"),
            "{error}"
        );
        assert!(error.contains("180 s"), "{error}");
        assert!(
            error.ends_with(&format!("To return to Raspberry Pi OS: {WAY_BACK}")),
            "{error}"
        );
        // Asked every 2 s up to 180 s, the last time at 180 s.
        assert_eq!(clock.now(), ANSWER_WITHIN);
        assert_eq!(asked, 91);
    }

    #[test]
    fn only_another_build_answering_is_still_not_this_build() {
        let mut clock = FakeClock::new();
        let error = wait_for_qberrypi(&mut || Some(1), 7, &mut clock)
            .unwrap_err()
            .to_string();
        // It says what answered, for a Pi that runs an older build.
        assert!(error.contains("build 7"), "{error}");
        assert!(error.contains("last build it reported was 1"), "{error}");
        assert_eq!(clock.now(), ANSWER_WITHIN);
    }

    #[test]
    fn slow_asks_do_not_stretch_the_wait_for_the_build() {
        // An ask that gets no answer takes its whole timeout.
        let mut clock = FakeClock::new();
        let now = Rc::clone(&clock.now);
        let result = wait_for_qberrypi(
            &mut || {
                now.set(now.get() + 2 * SECOND);
                None
            },
            7,
            &mut clock,
        );
        assert!(result.is_err());
        assert!(clock.now() >= ANSWER_WITHIN, "{:?}", clock.now());
        assert!(
            clock.now() <= ANSWER_WITHIN + 2 * (2 * SECOND + ASK_EVERY),
            "{:?}",
            clock.now()
        );
    }

    #[test]
    fn the_way_back_names_the_tool_and_the_power_cord() {
        assert!(WAY_BACK.contains("pull the Pi's power cord (safe for qberrypi)"));
        assert!(WAY_BACK.contains("cargo xtask return-to-pios --boot"));
        assert!(!WAY_BACK.contains("config.pios.txt over"));
        assert!(RECOVERY.contains("switch the Pi off and on"));
    }

    // ---------------------------------------------------------------- back from qberrypi

    #[test]
    fn a_pi_whose_config_txt_is_the_saved_one_is_back_as_it_should_be() {
        check_returned("pi", &finished(0, "", "")).unwrap();
    }

    #[test]
    fn a_pi_back_on_qberrypis_configuration_is_an_error_with_the_command_that_puts_it_right() {
        let error = check_returned("user@pi", &finished(1, "", ""))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("is running Raspberry Pi OS on qberrypi's configuration"),
            "{error}"
        );
        assert!(
            error.contains(
                "ssh user@pi sudo cp /boot/firmware/config.pios.txt /boot/firmware/config.txt"
            ),
            "{error}"
        );
    }

    #[test]
    fn a_comparison_that_could_not_be_made_is_an_error_of_its_own() {
        for (compared, said) in [
            (
                finished(2, "", "cmp: /boot/firmware/config.pios.txt: No such file\n"),
                "status 2",
            ),
            (
                finished(255, "", "ssh: connect to host pi: timed out\n"),
                "ssh could not reach",
            ),
            (
                Finished {
                    status: None,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                },
                "signal",
            ),
        ] {
            let error = check_returned("pi", &compared).unwrap_err().to_string();
            assert!(error.contains(said), "{error}");
            assert!(error.contains("config.pios.txt"), "{error}");
            // Not known to be on the wrong configuration, so not said to be.
            assert!(!error.contains("sudo cp"), "{error}");
        }
    }

    #[test]
    fn a_log_whose_last_boot_is_of_this_build_is_this_runs_log() {
        check_log_is_of(LOG, BUILD_EPOCH).unwrap();
        // Earlier boots, of earlier builds, are in the same file.
        let earlier = "==== boot, build 1600000000 ====\nqberrypi 0.1.0\n";
        check_log_is_of(&format!("{earlier}{LOG}"), BUILD_EPOCH).unwrap();
    }

    #[test]
    fn a_log_whose_last_boot_is_of_an_older_build_is_an_error_that_names_both() {
        let error = check_log_is_of(LOG, BUILD_EPOCH + 60)
            .unwrap_err()
            .to_string();
        assert!(error.contains("1699999000"), "{error}");
        assert!(error.contains("1699999060"), "{error}");
        assert!(error.contains("earlier"), "{error}");
        // The newest boot counts, not any boot.
        let later = "==== boot, build 1600000000 ====\nqberrypi 0.1.0\n";
        assert!(check_log_is_of(&format!("{LOG}{later}"), BUILD_EPOCH).is_err());
    }

    #[test]
    fn a_log_without_a_boot_header_is_an_error() {
        for log in [
            "",
            "qberrypi 0.1.0\nrestored config.txt\n",
            "==== boot, build x ====\n",
        ] {
            let error = check_log_is_of(log, BUILD_EPOCH).unwrap_err().to_string();
            assert!(error.contains("no boot header"), "{log:?}: {error}");
        }
    }

    // ---------------------------------------------------------------- secrets in the log

    /// What the key derived from the example's passphrase and network name is, in lower-case hex.
    fn example_key() -> String {
        let pmk = Pmk::from_passphrase("example-passphrase", b"example-network").unwrap();
        pmk.expose()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn a_log_with_the_passphrase_or_the_key_is_refused() {
        let key = example_key();
        assert_eq!(key.len(), 64);
        let secrets = secrets_of(EXAMPLE).unwrap();
        assert_eq!(secrets, ["example-passphrase", key.as_str()]);

        // The key is found in either case; the passphrase as it is.
        for leaked in ["example-passphrase", &key, &key.to_uppercase()] {
            let log = format!("{LOG}wifi: joined with {leaked}\n");
            let error = check_log_has_no_secret(&log, &secrets).unwrap_err();
            for shown in [
                error.to_string(),
                format!("{error:#}"),
                format!("{error:?}"),
            ] {
                assert!(!shown.contains("example-passphrase"), "{shown}");
                assert!(!shown.to_lowercase().contains(&key), "{shown}");
            }
        }
        check_log_has_no_secret(LOG, &secrets).unwrap();

        // A key in place of the passphrase is the whole list, in lower case.
        let upper = "AB12CD34".repeat(8);
        let text = EXAMPLE.replace(
            "passphrase = \"example-passphrase\"",
            &format!("pmk = \"{upper}\""),
        );
        assert_eq!(secrets_of(&text).unwrap(), [upper.to_lowercase()]);
        let log = format!("{LOG}pmk {upper}\n");
        assert!(check_log_has_no_secret(&log, &[upper.to_lowercase()]).is_err());
    }

    #[test]
    fn the_key_to_look_for_is_the_one_the_ieee_standard_derives() {
        // IEEE Std 802.11i-2004, Annex H.4.1: the passphrase "password" on the network "IEEE".
        let text = EXAMPLE
            .replace("example-passphrase", "password")
            .replace("example-network", "IEEE");
        assert_eq!(
            secrets_of(&text).unwrap(),
            [
                "password",
                "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"
            ]
        );
    }

    #[test]
    fn secrets_are_not_listed_for_a_configuration_that_does_not_parse() {
        let error = secrets_of(&format!("{CANARY} = [")).unwrap_err();
        assert!(!error.contains(CANARY), "{error}");
    }

    // ---------------------------------------------------------------- deploy and collect, end to end

    const STAGE: &str = "/tmp/qberrypi-stage.Ab12Cd";
    const CANARY: &str = "canary-passphrase-93871";
    const BOOT_TAR: &[u8] = b"TAR-OF-THE-BOOT-PARTITION-canary-firstboot-secret";
    /// The build time of the build in `checkout`, as the build recorded it.
    const BUILD_EPOCH: u64 = 1_699_999_000;
    /// The log of one boot of that build.
    const LOG: &str = "==== boot, build 1699999000 ====\nqberrypi 0.1.0\nrestored config.txt\n";

    fn finished(status: i32, stdout: impl AsRef<[u8]>, stderr: impl AsRef<[u8]>) -> Finished {
        Finished {
            status: Some(status),
            stdout: stdout.as_ref().to_vec(),
            stderr: stderr.as_ref().to_vec(),
        }
    }

    /// Stands in for `ssh` and `scp`: records every command and answers as a Pi would.
    struct FakePi {
        calls: Vec<(Invocation, Option<Vec<u8>>)>,
        /// Answers to "are you there", in order; when they run out, `answering_after`.
        answering: VecDeque<bool>,
        answering_after: bool,
        /// Answers to a ping, in order (true is a reply); when they run out, `pinging_after`.
        pings: VecDeque<bool>,
        pinging_after: bool,
        /// Whether there is a `ping` program on this machine to start.
        ping_installed: bool,
        /// What the status page says is the build that answers, in order (none is no answer);
        /// when they run out, `builds_after`.
        builds: VecDeque<Option<u64>>,
        builds_after: Option<u64>,
        tar: Finished,
        mktemp: Finished,
        scp: Finished,
        script: Finished,
        /// The answer to the comparison of `config.txt` with the saved one.
        compared: Finished,
        log: Option<Vec<u8>>,
        /// The staged checksums and the mode of the folder they were in, as scp found them.
        uploaded_sums: Option<(PathBuf, String, u32)>,
        /// The staged certificate, the mode of the file and the mode of its folder, as scp found
        /// them.
        uploaded_tls: Option<(PathBuf, Vec<u8>, u32, u32)>,
    }

    impl FakePi {
        fn new() -> Self {
            FakePi {
                calls: Vec::new(),
                answering: VecDeque::from([true, false, false]),
                answering_after: true,
                pings: VecDeque::new(),
                pinging_after: false,
                ping_installed: true,
                builds: VecDeque::new(),
                builds_after: Some(BUILD_EPOCH),
                tar: finished(0, BOOT_TAR, ""),
                mktemp: finished(0, format!("{STAGE}\n"), ""),
                scp: finished(0, "", ""),
                script: finished(
                    0,
                    format!("qberrypi-deploy: copying\n{SELECTED_MARKER}\n"),
                    "",
                ),
                compared: finished(0, "", ""),
                log: Some(LOG.as_bytes().to_vec()),
                uploaded_sums: None,
                uploaded_tls: None,
            }
        }

        /// The first word of each remote command, or `scp`, `ping` or `stats`, in the order they ran.
        fn summary(&self) -> Vec<String> {
            self.calls
                .iter()
                .map(|(invocation, _)| match invocation.program {
                    "ssh" => words(invocation)[6].clone(),
                    other => other.to_owned(),
                })
                .collect()
        }

        fn ran(&self, command: &str) -> bool {
            self.summary().iter().any(|word| word == command)
        }
    }

    impl Runner for FakePi {
        fn run(&mut self, invocation: &Invocation, stdin: Option<&[u8]>) -> io::Result<Finished> {
            self.calls
                .push((invocation.clone(), stdin.map(<[u8]>::to_vec)));
            let args = words(invocation);
            if invocation.program == "ping" {
                if !self.ping_installed {
                    return Err(io::Error::from(ErrorKind::NotFound));
                }
                let replied = self.pings.pop_front().unwrap_or(self.pinging_after);
                // ping ends with 1 when nothing answered.
                return Ok(finished(if replied { 0 } else { 1 }, "", ""));
            }
            if invocation.program == "scp" {
                let sums = args
                    .iter()
                    .map(PathBuf::from)
                    .find(|path| path.ends_with("SHA256SUMS"))
                    .unwrap();
                let folder = sums.parent().unwrap();
                let mode = fs::metadata(folder).unwrap().permissions().mode() & 0o7777;
                let text = fs::read_to_string(&sums).unwrap();
                self.uploaded_sums = Some((sums, text, mode));
                if let Some(tls) = args
                    .iter()
                    .map(PathBuf::from)
                    .find(|path| path.ends_with("tls.pem"))
                {
                    let bytes = fs::read(&tls).unwrap();
                    let file_mode = fs::metadata(&tls).unwrap().permissions().mode() & 0o7777;
                    self.uploaded_tls = Some((tls, bytes, file_mode, mode));
                }
                return Ok(self.scp.clone());
            }
            assert_eq!(invocation.program, "ssh");
            assert_eq!(args[..6], ssh_args("pi", &[])[..]);
            Ok(match args[6].as_str() {
                "true" => {
                    let answering = self.answering.pop_front().unwrap_or(self.answering_after);
                    finished(if answering { 0 } else { 255 }, "", "")
                }
                "tar" => self.tar.clone(),
                "mktemp" => self.mktemp.clone(),
                "sudo" => self.script.clone(),
                "rm" => finished(0, "", ""),
                "cmp" => self.compared.clone(),
                "test" => finished(if self.log.is_some() { 0 } else { 1 }, "", ""),
                "cat" => finished(0, self.log.clone().unwrap(), ""),
                other => panic!("unexpected remote command {other}"),
            })
        }

        fn reported_build(&mut self, address: Ipv4Addr) -> Option<u64> {
            // Written down with the commands, so that a test sees where in their order it came.
            let asked = Invocation {
                program: "stats",
                args: vec![address.to_string().into()],
            };
            self.calls.push((asked, None));
            self.builds.pop_front().unwrap_or(self.builds_after)
        }
    }

    const BUILT: [(&str, &[u8]); 6] = [
        ("kernel8.img", b"KERNEL"),
        ("initramfs8", b"INITRAMFS"),
        ("config.txt", b"os_prefix=qberrypi/\n"),
        ("ov-README", b"README"),
        ("ov-overlay_map.dtb", b"OVERLAY_MAP"),
        ("ov-qb-piscreen.dtbo", b"PISCREEN"),
    ];

    fn one_shot_toml() -> String {
        EXAMPLE
            .replace("one_shot = false", "one_shot = true")
            .replace("example-passphrase", CANARY)
    }

    /// A checkout with a build in `out/qberrypi` and a one-shot `qberrypi.toml`.
    fn checkout() -> TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let build = tmp.path().join("out/qberrypi");
        fs::create_dir_all(&build).unwrap();
        for (name, data) in BUILT {
            fs::write(build.join(name), data).unwrap();
        }
        fs::write(build.join("SHA256SUMS"), sha256sums(&BUILT)).unwrap();
        fs::write(
            tmp.path().join("out/build-epoch"),
            format!("{BUILD_EPOCH}\n"),
        )
        .unwrap();
        fs::write(tmp.path().join("qberrypi.toml"), one_shot_toml()).unwrap();
        tmp
    }

    struct Outcome {
        result: Result<()>,
        said: String,
    }

    impl Outcome {
        /// The whole error, causes included.
        fn error(&self) -> String {
            format!("{:#}", self.result.as_ref().unwrap_err())
        }
    }

    fn run_deploy(host: &str, permanent: bool, root: &Path, pi: &mut FakePi) -> Outcome {
        let mut said = Vec::new();
        let result = deploy_with(host, permanent, root, pi, &mut FakeClock::new(), &mut said);
        Outcome {
            result,
            said: String::from_utf8(said).unwrap(),
        }
    }

    /// Everything a deploy let out of the process: what it printed and what it ran.
    fn everything_shown(outcome: &Outcome, pi: &FakePi) -> String {
        let mut shown = outcome.said.clone();
        if let Err(error) = &outcome.result {
            shown.push_str(&format!("{error:#} {error:?}"));
        }
        for (invocation, stdin) in &pi.calls {
            shown.push_str(&format!("{invocation:?}"));
            shown.push_str(&String::from_utf8_lossy(
                stdin.as_deref().unwrap_or_default(),
            ));
        }
        shown
    }

    #[test]
    fn a_deploy_runs_these_commands_in_this_order() {
        let checkout = checkout();
        let root = fs::canonicalize(checkout.path()).unwrap();
        let mut pi = FakePi::new();
        let outcome = run_deploy("pi", false, checkout.path(), &mut pi);
        outcome.result.as_ref().unwrap();

        // Each probe that fails is followed by one ping, and no other is.
        assert_eq!(
            pi.summary(),
            [
                "tar", "mktemp", "scp", "sudo", "true", "true", "ping", "true", "ping", "true",
                "cmp", "test", "cat"
            ]
        );
        // Nothing goes through a local shell.
        for (invocation, _) in &pi.calls {
            assert!(["ssh", "scp", "ping"].contains(&invocation.program));
        }
        let call = |index: usize| &pi.calls[index];
        assert_eq!(call(0).0, save_boot_partition("pi"));
        assert_eq!(call(1).0, make_stage("pi"));

        let (scp, scp_input) = call(2);
        let (sums_path, sums_text, folder_mode) = pi.uploaded_sums.clone().unwrap();
        let mut files: Vec<PathBuf> = BUILT
            .iter()
            .map(|(name, _)| root.join("out/qberrypi").join(name))
            .collect();
        files.push(sums_path.clone());
        files.push(root.join("qberrypi.toml"));
        assert_eq!(scp, &upload("pi", &files, STAGE));
        assert_eq!(scp_input, &None);

        // The script reaches the Pi on standard input, with the production values.
        let (script, script_input) = call(3);
        assert_eq!(script, &run_script("pi"));
        let expected = RemoteScript {
            boot_dir: "/boot/firmware".to_owned(),
            stage_dir: STAGE.to_owned(),
            reboot_cmd: "systemctl reboot".to_owned(),
            hardware_checks: true,
            model_file: "/proc/device-tree/model".to_owned(),
        };
        assert_eq!(
            String::from_utf8(script_input.clone().unwrap()).unwrap(),
            expected.render()
        );
        for index in [0, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12] {
            assert_eq!(call(index).1, None, "call {index} was given input");
        }
        for index in [4, 5, 7, 9] {
            assert_eq!(call(index).0, probe("pi"));
        }
        // The Pi of the example configuration is pinged, and only when the probe before failed.
        for index in [6, 8] {
            assert_eq!(call(index).0, ping(Ipv4Addr::new(192, 0, 2, 53)));
        }
        // Once it answers again: is it back on its own configuration? Then the log.
        assert_eq!(call(10).0, compare_configs("pi"));
        assert_eq!(call(11).0, log_exists("pi"));
        assert_eq!(call(12).0, fetch_log("pi"));

        // The staged checksums: the build's and a line for the configuration, built in a
        // private folder outside the checkout that is gone afterwards.
        let toml_line = sha256sums(&[("qberrypi.toml", one_shot_toml().as_bytes())]);
        assert_eq!(sums_text, format!("{}{toml_line}", sha256sums(&BUILT)));
        assert_eq!(folder_mode, 0o700);
        assert!(sums_path.is_absolute() && !sums_path.starts_with(&root));
        assert!(!sums_path.parent().unwrap().exists());
        // The build's own list is as it was.
        assert_eq!(
            fs::read_to_string(root.join("out/qberrypi/SHA256SUMS")).unwrap(),
            sha256sums(&BUILT)
        );

        // The log was collected.
        let log = root.join("out/logs/1700000000.log");
        assert_eq!(fs::read_to_string(log).unwrap(), LOG);
        assert!(outcome.said.contains(LOG));
    }

    /// A password line of the shape the configuration reads. Nobody's password hashes to it.
    const PASSWORD_LINE: &str = "password_hash = \"$pbkdf2-sha256$i=100000$00000000000000000000000000000000$0000000000000000000000000000000000000000000000000000000000000000\"";

    fn api_toml() -> String {
        format!("{}\n[api]\n{PASSWORD_LINE}\n", one_shot_toml())
    }

    /// A made certificate, for a Pi at the address of the example configuration.
    fn made_certificate() -> String {
        crate::cert::make("qberrypi", Ipv4Addr::new(192, 0, 2, 53), 1_800_000_000).unwrap()
    }

    /// The base64 lines of the key in a certificate file: what no output may show.
    fn key_lines(pem: &str) -> Vec<String> {
        pem.split("-----BEGIN CERTIFICATE-----")
            .next()
            .unwrap()
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .map(str::to_owned)
            .collect()
    }

    /// The checkout with an `[api]` section in its configuration and `qberrypi-tls.pem` made.
    fn api_checkout() -> (TempDir, String) {
        let checkout = checkout();
        fs::write(checkout.path().join("qberrypi.toml"), api_toml()).unwrap();
        let pem = made_certificate();
        fs::write(checkout.path().join("qberrypi-tls.pem"), &pem).unwrap();
        (checkout, pem)
    }

    #[test]
    fn an_api_configuration_stages_the_certificate_and_none_does_not() {
        let (checkout, pem) = api_checkout();
        let root = fs::canonicalize(checkout.path()).unwrap();
        let mut pi = FakePi::new();
        let outcome = run_deploy("pi", false, checkout.path(), &mut pi);
        outcome.result.as_ref().unwrap();

        // The upload lists a file named tls.pem, beside the staged checksums in the private
        // scratch folder, whose bytes are those of qberrypi-tls.pem and that only this user reads.
        let (tls_path, tls_bytes, file_mode, folder_mode) = pi.uploaded_tls.clone().unwrap();
        let (sums_path, sums_text, _) = pi.uploaded_sums.clone().unwrap();
        assert_eq!(tls_bytes, pem.as_bytes());
        assert_eq!(tls_path.file_name().unwrap(), "tls.pem");
        assert_eq!(tls_path.parent(), sums_path.parent());
        assert_eq!((file_mode, folder_mode), (0o600, 0o700));
        assert!(tls_path.is_absolute() && !tls_path.starts_with(&root));
        let mut files: Vec<PathBuf> = BUILT
            .iter()
            .map(|(name, _)| root.join("out/qberrypi").join(name))
            .collect();
        files.extend([sums_path, root.join("qberrypi.toml"), tls_path.clone()]);
        let scp = pi
            .calls
            .iter()
            .find(|(call, _)| call.program == "scp")
            .unwrap();
        assert_eq!(scp.0, upload("pi", &files, STAGE));
        // The stage is gone with the deploy, key and all.
        assert!(!tls_path.exists());

        // The staged checksums have a line for it, after the configuration's.
        let added = sha256sums(&[
            ("qberrypi.toml", api_toml().as_bytes()),
            ("tls.pem", pem.as_bytes()),
        ]);
        assert_eq!(sums_text, format!("{}{added}", sha256sums(&BUILT)));

        // The pin is said before anything is installed.
        let pin =
            qberrypi::api::tls::pin_text(&qberrypi::api::tls::leaf_sha256(pem.as_bytes()).unwrap());
        assert_eq!(pin.len(), 95);
        let pin_line = format!("deploy: pi: the API's certificate pin (SHA-256): {pin}\n");
        let at = outcome.said.find(&pin_line).unwrap_or_else(|| {
            panic!("no pin line in:\n{}", outcome.said);
        });
        assert!(at < outcome.said.find("deploy: pi: installing").unwrap());
        // The build's files, the checksums, the configuration and the certificate.
        let copying = format!("deploy: pi: copying {} files", BUILT.len() + 3);
        assert!(outcome.said.contains(&copying), "{}", outcome.said);
        assert_eq!(outcome.said.matches("certificate pin").count(), 1);

        // The key is shown nowhere: not in what was printed, not in a command, not in an error.
        let shown = everything_shown(&outcome, &pi);
        assert!(!shown.contains("PRIVATE"), "{shown}");
        for line in key_lines(&pem) {
            assert!(!shown.contains(&line), "{shown}");
        }
        // Nor in out/, and the checkout's own file is as it was.
        for entry in fs::read_dir(root.join("out/qberrypi")).unwrap() {
            let name = entry.unwrap().file_name();
            assert!(name != "tls.pem" && name != "qberrypi-tls.pem", "{name:?}");
        }
        assert_eq!(
            fs::read_to_string(root.join("qberrypi-tls.pem")).unwrap(),
            pem
        );
    }

    #[test]
    fn a_configuration_without_an_api_stages_no_certificate_and_prints_no_pin() {
        // Even with a certificate file in the checkout.
        let checkout = checkout();
        fs::write(checkout.path().join("qberrypi-tls.pem"), made_certificate()).unwrap();
        let mut pi = FakePi::new();
        let outcome = run_deploy("pi", false, checkout.path(), &mut pi);
        outcome.result.as_ref().unwrap();
        assert!(pi.uploaded_tls.is_none());
        let (_, sums_text, _) = pi.uploaded_sums.clone().unwrap();
        assert!(!sums_text.contains("tls.pem"), "{sums_text}");
        // The build's lines and the configuration's, and no more.
        assert_eq!(sums_text.lines().count(), BUILT.len() + 1);
        assert!(
            !outcome.said.contains("certificate pin"),
            "{}",
            outcome.said
        );
        let copying = format!("deploy: pi: copying {} files", BUILT.len() + 2);
        assert!(outcome.said.contains(&copying), "{}", outcome.said);
    }

    #[test]
    fn an_api_without_a_certificate_file_stops_before_anything_runs_on_the_pi() {
        let checkout = checkout();
        fs::write(checkout.path().join("qberrypi.toml"), api_toml()).unwrap();
        let mut pi = FakePi::new();
        let outcome = run_deploy("pi", false, checkout.path(), &mut pi);
        assert_eq!(
            outcome.error(),
            "qberrypi.toml has [api] but there is no qberrypi-tls.pem: run cargo xtask make-cert"
        );
        assert!(pi.calls.is_empty());
        assert!(
            !outcome.said.contains("certificate pin"),
            "{}",
            outcome.said
        );
    }

    #[test]
    fn a_certificate_file_the_api_cannot_serve_stops_the_deploy_with_the_reason_and_not_the_file() {
        let (cert_only, key_only) = {
            let pem = made_certificate();
            let at = pem.find("-----BEGIN CERTIFICATE-----").unwrap();
            (pem[at..].to_owned(), pem[..at].to_owned())
        };
        let other = made_certificate();
        let mismatched = format!(
            "{}{}",
            &other[..other.find("-----BEGIN CERTIFICATE-----").unwrap()],
            cert_only
        );
        let too_big = format!("{}{}", made_certificate(), "#".repeat(16 * 1024));
        for (case, file, reason) in [
            ("no key", cert_only.clone(), "no private key"),
            ("no certificate", key_only.clone(), "no certificate"),
            ("another's key", mismatched, "does not fit"),
            ("not a PEM", "garbage".to_owned(), "no certificate"),
            ("too big", too_big, "larger than 16384 bytes"),
        ] {
            let checkout = checkout();
            fs::write(checkout.path().join("qberrypi.toml"), api_toml()).unwrap();
            fs::write(checkout.path().join("qberrypi-tls.pem"), &file).unwrap();
            let mut pi = FakePi::new();
            let outcome = run_deploy("pi", false, checkout.path(), &mut pi);
            let error = outcome.error();
            assert!(error.contains("qberrypi-tls.pem"), "{case}: {error}");
            assert!(error.contains(reason), "{case}: {error}");
            assert!(pi.calls.is_empty(), "{case}");
            assert!(pi.uploaded_tls.is_none(), "{case}");
            let shown = everything_shown(&outcome, &pi);
            assert!(
                !shown.contains("PRIVATE") && !shown.contains("BEGIN"),
                "{case}: {shown}"
            );
            for line in key_lines(&file) {
                assert!(!shown.contains(&line), "{case}: {shown}");
            }
        }
    }

    #[test]
    fn a_certificate_the_stage_could_not_take_is_removed_with_the_stage_however_the_deploy_ends() {
        let (checkout, _) = api_checkout();
        let mut pi = FakePi::new();
        pi.script = finished(7, "", "qberrypi-deploy: stopped: wrong board");
        let outcome = run_deploy("pi", false, checkout.path(), &mut pi);
        assert!(outcome.result.is_err());
        let (tls_path, ..) = pi.uploaded_tls.clone().unwrap();
        // The scratch folder with the key in it is gone, and so is the stage on the Pi.
        assert!(!tls_path.exists());
        assert!(pi.ran("rm"));
    }

    #[test]
    fn a_deploy_says_each_step_before_it_takes_it() {
        let checkout = checkout();
        let mut pi = FakePi::new();
        let outcome = run_deploy("pi", false, checkout.path(), &mut pi);
        outcome.result.as_ref().unwrap();
        let mut rest = outcome.said.as_str();
        for step in [
            "deploy: pi: saving its boot partition",
            "deploy: pi: making a stage directory",
            "deploy: pi: copying 8 files",
            "deploy: pi: installing",
            "qberrypi-deploy: copying",
            "deploy: pi: waiting",
            "deploy: pi: it is back",
            "deploy: pi: checking that config.txt",
            "collect: pi: fetching",
            "collect: wrote",
        ] {
            let at = rest.find(step).unwrap_or_else(|| {
                panic!("{step:?} is missing or out of order in:\n{}", outcome.said)
            });
            rest = &rest[at + step.len()..];
        }
    }

    #[test]
    fn the_passphrase_and_the_boot_partition_are_never_shown() {
        let checkout = checkout();
        let mut pi = FakePi::new();
        let outcome = run_deploy("pi", false, checkout.path(), &mut pi);
        outcome.result.as_ref().unwrap();
        let shown = everything_shown(&outcome, &pi);
        assert!(!shown.contains(CANARY));
        assert!(!shown.contains("canary-firstboot-secret"));
        // Nor the key derived from it, in the tally or in any command.
        for secret in secrets_of(&one_shot_toml()).unwrap() {
            assert!(!shown.contains(&secret));
            assert!(!shown.to_lowercase().contains(&secret));
        }
    }

    #[test]
    fn the_boot_partition_backup_is_private_and_made_only_once() {
        let checkout = checkout();
        let backup = checkout.path().join("vendor-cache/bootpart-backup.tar");
        let mut pi = FakePi::new();
        run_deploy("pi", false, checkout.path(), &mut pi)
            .result
            .unwrap();
        assert_eq!(fs::read(&backup).unwrap(), BOOT_TAR);
        let mode = fs::metadata(&backup).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o600);
        // Nothing else is left beside it.
        assert_eq!(fs::read_dir(backup.parent().unwrap()).unwrap().count(), 1);

        // The second deploy does not ask for it again, whatever the Pi would send now.
        fs::remove_dir_all(checkout.path().join("out/logs")).unwrap();
        let mut pi = FakePi::new();
        pi.tar = finished(0, "A LATER STATE", "");
        run_deploy("pi", false, checkout.path(), &mut pi)
            .result
            .unwrap();
        assert!(!pi.ran("tar"));
        assert_eq!(fs::read(&backup).unwrap(), BOOT_TAR);
    }

    #[test]
    fn a_boot_partition_backup_that_fails_stops_the_deploy_and_leaves_no_file() {
        for tar in [
            finished(2, "PARTIAL", "tar: cannot open"),
            finished(255, "", "ssh: connect to host pi: timed out"),
            finished(0, "", ""),
        ] {
            let checkout = checkout();
            let mut pi = FakePi::new();
            pi.tar = tar;
            let outcome = run_deploy("pi", false, checkout.path(), &mut pi);
            assert!(outcome.result.is_err());
            assert_eq!(pi.summary(), ["tar"]);
            let folder = checkout.path().join("vendor-cache");
            assert!(!folder.exists() || fs::read_dir(folder).unwrap().count() == 0);
        }
    }

    #[test]
    fn nothing_runs_when_a_local_check_fails() {
        type Spoil = fn(&Path);
        let cases: [(&str, &str, bool, Spoil, &str); 9] = [
            (
                "a host that is an option",
                "-oProxyCommand=x",
                false,
                |_| {},
                "host",
            ),
            ("no host", "", false, |_| {}, "host"),
            (
                "a permanent configuration",
                "pi",
                false,
                |root| {
                    let text = one_shot_toml().replace("one_shot = true", "one_shot = false");
                    fs::write(root.join("qberrypi.toml"), text).unwrap();
                },
                "--permanent",
            ),
            (
                "a one-shot configuration deployed for good",
                "pi",
                true,
                |_| {},
                "debug.one_shot",
            ),
            (
                "a configuration that does not parse",
                "pi",
                true,
                |root| fs::write(root.join("qberrypi.toml"), format!("{CANARY} = [")).unwrap(),
                "qberrypi.toml",
            ),
            (
                "no configuration",
                "pi",
                false,
                |root| fs::remove_file(root.join("qberrypi.toml")).unwrap(),
                "qberrypi.toml",
            ),
            (
                "no build",
                "pi",
                false,
                |root| fs::remove_file(root.join("out/qberrypi/SHA256SUMS")).unwrap(),
                "cargo xtask build",
            ),
            (
                "a build with a file missing",
                "pi",
                false,
                |root| fs::remove_file(root.join("out/qberrypi/initramfs8")).unwrap(),
                "initramfs8",
            ),
            (
                "a build without the record of its build time",
                "pi",
                false,
                |root| fs::remove_file(root.join("out/build-epoch")).unwrap(),
                "cargo xtask build",
            ),
        ];
        for (case, host, permanent, spoil, expected) in cases {
            let checkout = checkout();
            spoil(checkout.path());
            let mut pi = FakePi::new();
            let outcome = run_deploy(host, permanent, checkout.path(), &mut pi);
            assert!(outcome.result.is_err(), "{case}");
            assert!(pi.calls.is_empty(), "{case}: {:?}", pi.summary());
            assert!(
                outcome.error().contains(expected),
                "{case}: {}",
                outcome.error()
            );
            assert!(!everything_shown(&outcome, &pi).contains(CANARY), "{case}");
        }
    }

    #[test]
    fn a_stage_name_that_mktemp_would_not_give_ends_the_deploy_there() {
        for answer in [
            "/tmp\n",
            "/\n",
            "/tmp/qberrypi-stage.x/../..\n",
            "/tmp/qberrypi-stage.a b\n",
            "/tmp/qberrypi-stage.a;b\n",
            "",
        ] {
            let checkout = checkout();
            let mut pi = FakePi::new();
            pi.mktemp = finished(0, answer, "");
            let outcome = run_deploy("pi", false, checkout.path(), &mut pi);
            assert!(outcome.result.is_err(), "{answer:?}");
            // Not even a removal: the name is not used anywhere.
            assert_eq!(pi.summary(), ["tar", "mktemp"], "{answer:?}");
        }
    }

    #[test]
    fn a_failed_copy_removes_the_stage_and_runs_nothing_as_root() {
        let checkout = checkout();
        let mut pi = FakePi::new();
        pi.scp = finished(1, "", "scp: write failed: No space left on device");
        let outcome = run_deploy("pi", false, checkout.path(), &mut pi);
        assert!(
            outcome.error().contains("No space left"),
            "{}",
            outcome.error()
        );
        assert_eq!(pi.summary(), ["tar", "mktemp", "scp", "rm"]);
        assert_eq!(pi.calls[3].0, remove_stage("pi", STAGE));
    }

    #[test]
    fn a_script_that_stops_ends_the_deploy_without_waiting() {
        let checkout = checkout();
        let mut pi = FakePi::new();
        pi.script = finished(
            BACKUP_REFUSED,
            "qberrypi-deploy: checking\n",
            "qberrypi-deploy: stopped: config.pios.txt is empty\n",
        );
        let outcome = run_deploy("pi", false, checkout.path(), &mut pi);
        assert!(outcome.error().contains("status 4"), "{}", outcome.error());
        // What the script said is shown, on both of its streams.
        assert!(outcome.said.contains("qberrypi-deploy: checking"));
        assert!(outcome.said.contains("stopped: config.pios.txt is empty"));
        assert_eq!(pi.summary(), ["tar", "mktemp", "scp", "sudo", "rm"]);
    }

    #[test]
    fn a_connection_lost_at_the_restart_is_not_a_failure() {
        let checkout = checkout();
        let mut pi = FakePi::new();
        pi.script = finished(
            255,
            format!("{SELECTED_MARKER}\n"),
            "Connection to pi closed by remote host.\n",
        );
        let outcome = run_deploy("pi", false, checkout.path(), &mut pi);
        outcome.result.as_ref().unwrap();
        assert!(pi.ran("cat"));
        // The stage is the script's to remove, and it did before it selected anything.
        assert!(!pi.ran("rm"));
    }

    #[test]
    fn a_script_that_did_not_say_it_selected_qberrypi_is_a_failure() {
        for script in [
            finished(255, "qberrypi-deploy: copying\n", "Connection reset\n"),
            finished(0, "", ""),
            Finished {
                status: None,
                stdout: format!("{SELECTED_MARKER}\n").into_bytes(),
                stderr: Vec::new(),
            },
        ] {
            let checkout = checkout();
            let mut pi = FakePi::new();
            pi.script = script;
            let outcome = run_deploy("pi", false, checkout.path(), &mut pi);
            assert!(outcome.result.is_err());
            assert!(!pi.ran("true") && !pi.ran("cat"));
        }
    }

    #[test]
    fn a_script_that_selected_qberrypi_but_did_not_restart_says_so() {
        let checkout = checkout();
        let mut pi = FakePi::new();
        pi.script = finished(
            1,
            format!("{SELECTED_MARKER}\n"),
            "Failed to connect to bus\n",
        );
        let outcome = run_deploy("pi", false, checkout.path(), &mut pi);
        let error = outcome.error();
        assert!(error.contains("qberrypi is selected on pi"), "{error}");
        assert!(error.contains("status 1"), "{error}");
        assert!(!pi.ran("true") && !pi.ran("cat"));
    }

    /// A checkout whose `qberrypi.toml` is one that may be deployed for good.
    fn permanent_checkout() -> TempDir {
        let checkout = checkout();
        let text = one_shot_toml().replace("one_shot = true", "one_shot = false");
        fs::write(checkout.path().join("qberrypi.toml"), text).unwrap();
        checkout
    }

    #[test]
    fn a_permanent_deploy_waits_for_the_pi_to_go_and_then_for_the_build() {
        let checkout = permanent_checkout();
        let mut pi = FakePi::new();
        // Nothing, nothing, another build, this build.
        pi.builds = VecDeque::from([None, None, Some(BUILD_EPOCH - 1), Some(BUILD_EPOCH)]);
        let outcome = run_deploy("pi", true, checkout.path(), &mut pi);
        outcome.result.as_ref().unwrap();
        // SSH goes away first (the default Pi answers once and then not), then the status page is asked.
        assert_eq!(
            pi.summary(),
            [
                "tar", "mktemp", "scp", "sudo", "true", "true", "stats", "stats", "stats", "stats"
            ]
        );
        // The Pi of the example configuration, asked each time.
        for (call, _) in &pi.calls[6..] {
            assert_eq!(call.args, [OsString::from("192.0.2.53")]);
        }
        // 5 s for SSH to go, then 3 asks that were not answered, 2 s apart.
        let success = format!(
            "deploy: pi: qberrypi build {BUILD_EPOCH} answers at 192.0.2.53 11 s after the restart; \
             to return to Raspberry Pi OS later: {WAY_BACK}"
        );
        assert!(outcome.said.contains(&success), "{}", outcome.said);
        // No log is collected and no comparison is made: qberrypi stays and Raspberry Pi OS is not back.
        assert!(!pi.ran("cmp") && !pi.ran("test") && !pi.ran("cat"));
        // The old advice is gone.
        assert!(
            !outcome.said.contains("another computer"),
            "{}",
            outcome.said
        );
    }

    #[test]
    fn a_permanent_deploy_does_not_ask_for_the_build_before_ssh_has_gone() {
        let checkout = permanent_checkout();
        let mut pi = FakePi::new();
        // SSH answers four times, then goes; the build answers from the start.
        pi.answering = VecDeque::from([true, true, true, true, false]);
        run_deploy("pi", true, checkout.path(), &mut pi)
            .result
            .unwrap();
        assert_eq!(
            pi.summary(),
            [
                "tar", "mktemp", "scp", "sudo", "true", "true", "true", "true", "true", "stats"
            ]
        );
    }

    #[test]
    fn a_pi_that_never_stops_answering_ssh_is_noted_and_the_build_is_still_waited_for() {
        let checkout = permanent_checkout();
        let mut pi = FakePi::new();
        pi.answering = VecDeque::new(); // ssh answers for ever
        pi.builds = VecDeque::from([None, Some(BUILD_EPOCH)]);
        let outcome = run_deploy("pi", true, checkout.path(), &mut pi);
        outcome.result.as_ref().unwrap();
        assert!(
            outcome.said.contains("never stopped answering"),
            "{}",
            outcome.said
        );
        assert!(outcome.said.contains("qberrypi build"), "{}", outcome.said);
        assert_eq!(
            pi.summary().iter().filter(|word| *word == "stats").count(),
            2
        );
        // Asked every 5 s for 30 s, and it is no error that the Pi was never seen to go.
        assert_eq!(
            pi.summary().iter().filter(|word| *word == "true").count(),
            7
        );
    }

    #[test]
    fn a_permanent_build_that_never_answers_fails_the_deploy_with_the_way_back() {
        let checkout = permanent_checkout();
        let mut pi = FakePi::new();
        pi.builds_after = None;
        let outcome = run_deploy("pi", true, checkout.path(), &mut pi);
        let error = outcome.error();
        assert!(error.contains("pi"), "{error}");
        assert!(error.contains("return-to-pios"), "{error}");
        assert!(error.contains("power cord"), "{error}");
        assert!(error.contains("180 s"), "{error}");
        assert!(!error.contains("another computer"), "{error}");
        assert!(!outcome.said.contains("answers at"), "{}", outcome.said);
        assert!(!pi.ran("cmp") && !pi.ran("test") && !pi.ran("cat"));
    }

    #[test]
    fn a_permanent_deploy_names_the_pi_that_answers_not_the_host_alias() {
        let checkout = permanent_checkout();
        let text = fs::read_to_string(checkout.path().join("qberrypi.toml"))
            .unwrap()
            .replace("192.0.2.53", "192.0.2.77");
        fs::write(checkout.path().join("qberrypi.toml"), text).unwrap();
        let mut pi = FakePi::new();
        let outcome = run_deploy("pi", true, checkout.path(), &mut pi);
        outcome.result.as_ref().unwrap();
        let (asked, _) = pi
            .calls
            .iter()
            .find(|(call, _)| call.program == "stats")
            .unwrap();
        assert_eq!(asked.args, [OsString::from("192.0.2.77")]);
        assert!(
            outcome.said.contains("answers at 192.0.2.77"),
            "{}",
            outcome.said
        );
    }

    #[test]
    fn a_one_shot_configuration_deployed_with_permanent_is_refused_before_anything_runs() {
        let checkout = checkout(); // debug.one_shot is on
        let mut pi = FakePi::new();
        let outcome = run_deploy("pi", true, checkout.path(), &mut pi);
        let error = outcome.error();
        assert!(error.contains("debug.one_shot"), "{error}");
        assert!(error.ends_with("; nothing was copied"), "{error}");
        // Nothing was copied and nothing ran on the Pi, not even the save of its boot partition.
        assert!(pi.calls.is_empty(), "{:?}", pi.summary());
        assert!(!checkout.path().join("vendor-cache").exists());
    }

    #[test]
    fn a_permanent_deploy_does_not_wait_for_a_pi_that_could_not_be_installed_on() {
        let checkout = permanent_checkout();
        let mut pi = FakePi::new();
        pi.script = finished(
            UPGRADING,
            "",
            "qberrypi-deploy: stopped: Raspberry Pi OS is installing updates (dpkg is running); try again when it has finished. Nothing was changed\n",
        );
        let outcome = run_deploy("pi", true, checkout.path(), &mut pi);
        assert!(outcome.error().contains("status 11"), "{}", outcome.error());
        assert!(outcome.said.contains("try again when it has finished"));
        assert_eq!(pi.summary(), ["tar", "mktemp", "scp", "sudo", "rm"]);
    }

    #[test]
    fn a_configuration_that_never_restarts_by_itself_is_noted_at_the_start() {
        let note = "debug.return_after_secs is 0";
        let checkout = checkout();
        let mut pi = FakePi::new();
        let outcome = run_deploy("pi", false, checkout.path(), &mut pi);
        let noted = outcome.said.find(note).expect("the note is missing");
        assert!(noted < outcome.said.find("making a stage directory").unwrap());

        let text = one_shot_toml().replace("return_after_secs = 0", "return_after_secs = 90");
        fs::write(checkout.path().join("qberrypi.toml"), text).unwrap();
        fs::remove_dir_all(checkout.path().join("out/logs")).unwrap();
        let mut pi = FakePi::new();
        let outcome = run_deploy("pi", false, checkout.path(), &mut pi);
        outcome.result.as_ref().unwrap();
        assert!(!outcome.said.contains(note), "{}", outcome.said);
    }

    #[test]
    fn the_deploy_says_how_long_it_waits_for_the_return_of_a_configured_run() {
        let checkout = checkout();
        let text = one_shot_toml().replace("return_after_secs = 0", "return_after_secs = 400");
        fs::write(checkout.path().join("qberrypi.toml"), text).unwrap();
        let mut pi = FakePi::new();
        let outcome = run_deploy("pi", false, checkout.path(), &mut pi);
        outcome.result.as_ref().unwrap();
        assert!(
            outcome.said.contains(
                "waiting up to 30 s for it to go down and then up to 580 s for it to answer again"
            ),
            "{}",
            outcome.said
        );
    }

    #[test]
    fn a_pi_that_never_stops_answering_is_noted_and_its_log_collected() {
        let checkout = checkout();
        let mut pi = FakePi::new();
        pi.answering = VecDeque::new();
        let outcome = run_deploy("pi", false, checkout.path(), &mut pi);
        outcome.result.as_ref().unwrap();
        assert!(
            outcome.said.contains("never stopped answering"),
            "{}",
            outcome.said
        );
        // Nothing was pinged, and that is no error: a Pi that never left is not one that was lost.
        assert!(!pi.ran("ping"));
        assert!(
            outcome
                .said
                .contains("answered 0 of 0 pings while the Pi was away"),
            "{}",
            outcome.said
        );
        assert!(pi.ran("cat"));
    }

    #[test]
    fn a_pi_that_stays_away_ends_the_deploy_with_the_way_to_recover() {
        let checkout = checkout();
        let mut pi = FakePi::new();
        pi.answering_after = false;
        let outcome = run_deploy("pi", false, checkout.path(), &mut pi);
        let error = outcome.error();
        assert!(error.contains("pi"), "{error}");
        assert!(error.contains("return-to-pios"), "{error}");
        assert!(error.contains("power cord"), "{error}");
        assert!(!error.contains("another computer"), "{error}");
        assert!(!pi.ran("test") && !pi.ran("cat"));
    }

    // ---------------------------------------------------------------- pings while the Pi is away

    #[test]
    fn the_pi_is_pinged_only_while_it_does_not_answer_ssh() {
        let checkout = checkout();
        let mut pi = FakePi::new();
        pi.answering = VecDeque::from([true, false, false, false, true]);
        pi.pings = VecDeque::from([true, false, true]);
        let outcome = run_deploy("pi", false, checkout.path(), &mut pi);
        outcome.result.as_ref().unwrap();

        // Each of the three failed probes is followed by one ping, and nothing else is pinged.
        assert_eq!(
            pi.summary()[4..12],
            [
                "true", "true", "ping", "true", "ping", "true", "ping", "true"
            ]
        );
        for (invocation, input) in pi.calls.iter().filter(|(call, _)| call.program == "ping") {
            assert_eq!(invocation, &ping(Ipv4Addr::new(192, 0, 2, 53)));
            assert_eq!(input, &None);
        }
        // Said once the wait is over, before the check of config.txt.
        let tally = "deploy: pi: 192.0.2.53 answered 2 of 3 pings while the Pi was away";
        let said = &outcome.said;
        let at = said
            .find(tally)
            .unwrap_or_else(|| panic!("no tally in:\n{said}"));
        assert!(said.find("it is back").unwrap() < at);
        assert!(at < said.find("checking that config.txt").unwrap());
        assert_eq!(said.matches("pings while the Pi was away").count(), 1);
    }

    #[test]
    fn the_pi_pinged_is_the_one_at_net_address() {
        let checkout = checkout();
        let text = one_shot_toml().replace("192.0.2.53/24", "192.0.2.77/24");
        fs::write(checkout.path().join("qberrypi.toml"), text).unwrap();
        let mut pi = FakePi::new();
        pi.pings = VecDeque::from([true, true]);
        let outcome = run_deploy("pi", false, checkout.path(), &mut pi);
        outcome.result.as_ref().unwrap();
        assert!(pi.ran("ping"));
        for (invocation, _) in pi.calls.iter().filter(|(call, _)| call.program == "ping") {
            assert_eq!(invocation, &ping(Ipv4Addr::new(192, 0, 2, 77)));
        }
        assert!(
            outcome
                .said
                .contains("deploy: pi: 192.0.2.77 answered 2 of 2 pings"),
            "{}",
            outcome.said
        );
    }

    #[test]
    fn a_ping_that_is_not_answered_or_cannot_be_run_is_no_failure_of_the_deploy() {
        for installed in [true, false] {
            let checkout = checkout();
            let mut pi = FakePi::new();
            pi.ping_installed = installed;
            let outcome = run_deploy("pi", false, checkout.path(), &mut pi);
            outcome.result.as_ref().unwrap();
            // Two probes failed, so two pings were sent; neither was answered.
            assert!(
                outcome
                    .said
                    .contains("answered 0 of 2 pings while the Pi was away"),
                "{installed}: {}",
                outcome.said
            );
            assert!(pi.ran("cat"));
        }
    }

    #[test]
    fn a_ping_that_cannot_be_started_is_said_once_and_still_counts_as_sent() {
        let without_ping = checkout();
        let mut pi = FakePi::new();
        pi.ping_installed = false;
        pi.answering = VecDeque::from([true, false, false, false, true]);
        let outcome = run_deploy("pi", false, without_ping.path(), &mut pi);
        outcome.result.as_ref().unwrap();

        // Three pings were tried, and the reason is given once, not once for each.
        let cause = io::Error::from(ErrorKind::NotFound);
        let said = format!("deploy: pi: ping could not be run: {cause}\n");
        assert_eq!(outcome.said.matches(&said).count(), 1, "{}", outcome.said);
        assert_eq!(outcome.said.matches("could not be run").count(), 1);
        assert!(
            outcome
                .said
                .contains("answered 0 of 3 pings while the Pi was away"),
            "{}",
            outcome.said
        );
        // Said when it first happened: before the Pi is back, not with the tally.
        assert!(outcome.said.find(&said).unwrap() < outcome.said.find("it is back").unwrap());

        // A ping that did start, and was not answered, says nothing of the kind.
        let checkout = checkout();
        let mut pi = FakePi::new();
        let outcome = run_deploy("pi", false, checkout.path(), &mut pi);
        outcome.result.as_ref().unwrap();
        assert!(
            !outcome.said.contains("could not be run"),
            "{}",
            outcome.said
        );
    }

    #[test]
    fn the_pings_are_tallied_even_when_the_pi_does_not_come_back() {
        let checkout = checkout();
        let mut pi = FakePi::new();
        pi.answering_after = false;
        pi.pings = VecDeque::from([true, true]);
        let outcome = run_deploy("pi", false, checkout.path(), &mut pi);

        let error = outcome.error();
        assert!(error.contains("pi did not come back"), "{error}");
        assert!(error.contains("return-to-pios"), "{error}");
        let sent = pi
            .calls
            .iter()
            .filter(|(call, _)| call.program == "ping")
            .count();
        assert!(sent > 2, "{sent}");
        let tally =
            format!("deploy: pi: 192.0.2.53 answered 2 of {sent} pings while the Pi was away");
        assert!(outcome.said.contains(&tally), "{}", outcome.said);
        assert_eq!(
            outcome.said.matches("pings while the Pi was away").count(),
            1
        );
        // Nothing went on from the wait.
        assert!(!pi.ran("cmp") && !pi.ran("test") && !pi.ran("cat"));
        assert!(!outcome.said.contains("it is back"), "{}", outcome.said);
    }

    #[test]
    fn a_pi_back_on_qberrypis_configuration_fails_the_deploy_before_any_log_is_collected() {
        // The firmware did not take the folder and started Raspberry Pi OS's kernel on
        // qberrypi's config.txt. Whatever log is on the card is not of this run.
        let checkout = checkout();
        let mut pi = FakePi::new();
        pi.compared = finished(1, "", "");
        let outcome = run_deploy("pi", false, checkout.path(), &mut pi);
        let error = outcome.error();
        assert!(
            error.contains("pi is running Raspberry Pi OS on qberrypi's configuration"),
            "{error}"
        );
        assert!(
            error.contains(
                "ssh pi sudo cp /boot/firmware/config.pios.txt /boot/firmware/config.txt"
            ),
            "{error}"
        );
        assert_eq!(pi.summary().last().unwrap(), "cmp");
        assert!(!pi.ran("test") && !pi.ran("cat"));
        assert!(!outcome.said.contains(LOG));
        assert!(!checkout.path().join("out/logs").exists());
    }

    #[test]
    fn a_comparison_that_fails_ends_the_deploy_too() {
        let checkout = checkout();
        let mut pi = FakePi::new();
        pi.compared = finished(2, "", "cmp: /boot/firmware/config.pios.txt: No such file\n");
        let outcome = run_deploy("pi", false, checkout.path(), &mut pi);
        assert!(
            outcome.error().contains("No such file"),
            "{}",
            outcome.error()
        );
        assert!(!pi.ran("cat"));
    }

    #[test]
    fn a_log_of_an_older_build_is_collected_and_then_fails_the_deploy() {
        let checkout = checkout();
        let mut pi = FakePi::new();
        let old = "==== boot, build 1600000000 ====\nan earlier run\n";
        pi.log = Some(old.as_bytes().to_vec());
        let outcome = run_deploy("pi", false, checkout.path(), &mut pi);
        let error = outcome.error();
        assert!(error.contains("1600000000"), "{error}");
        assert!(error.contains("1699999000"), "{error}");
        // It is still shown and kept: it is what there is to read.
        assert!(outcome.said.contains(old), "{}", outcome.said);
        let saved = checkout.path().join("out/logs/1700000000.log");
        assert_eq!(fs::read_to_string(saved).unwrap(), old);
    }

    #[test]
    fn a_log_that_holds_the_passphrase_or_the_key_fails_the_deploy_and_says_which_file_to_delete() {
        let secrets = secrets_of(&one_shot_toml()).unwrap();
        assert_eq!(secrets.len(), 2);
        let leaks = [
            secrets[0].clone(),
            secrets[1].clone(),
            secrets[1].to_uppercase(),
        ];
        for leaked in leaks {
            let checkout = checkout();
            let saved = fs::canonicalize(checkout.path())
                .unwrap()
                .join("out/logs/1700000000.log");
            let mut pi = FakePi::new();
            pi.log = Some(format!("{LOG}wifi: joined with {leaked}\n").into_bytes());
            let outcome = run_deploy("pi", false, checkout.path(), &mut pi);
            let error = outcome.error();
            assert!(
                error.contains(&format!("delete {} and report this", saved.display())),
                "{error}"
            );
            assert!(error.contains("Wi-Fi passphrase or key"), "{error}");
            let debug = format!("{:?}", outcome.result.as_ref().unwrap_err());
            for secret in &secrets {
                assert!(!error.contains(secret), "{error}");
                assert!(!debug.contains(secret), "{debug}");
            }
            // Nothing of the log reaches the output, and nothing deploy shows holds a secret.
            assert!(!outcome.said.contains("==== boot"), "{}", outcome.said);
            let shown = everything_shown(&outcome, &pi).to_lowercase();
            for secret in &secrets {
                assert!(!shown.contains(&secret.to_lowercase()), "{shown}");
            }
            // The file is there, with the log in it, for the owner to delete.
            assert!(fs::read_to_string(&saved).unwrap().contains(&leaked));
            let mode = fs::metadata(&saved).unwrap().permissions().mode() & 0o7777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn a_log_of_an_older_build_that_holds_a_secret_is_refused_as_that_and_not_shown() {
        let secrets = secrets_of(&one_shot_toml()).unwrap();
        let checkout = checkout();
        let saved = fs::canonicalize(checkout.path())
            .unwrap()
            .join("out/logs/1700000000.log");
        let mut pi = FakePi::new();
        let old = format!("==== boot, build 1600000000 ====\n{CANARY}\n");
        pi.log = Some(old.into_bytes());
        let outcome = run_deploy("pi", false, checkout.path(), &mut pi);
        let error = outcome.error();

        // The refusal comes first, with the file to delete; the build is said too.
        assert!(error.contains("Wi-Fi passphrase or key"), "{error}");
        assert!(
            error.contains(&format!("delete {} and report this", saved.display())),
            "{error}"
        );
        assert!(error.contains("1600000000"), "{error}");
        // Nothing was shown, so nothing is above.
        assert!(!error.contains("above"), "{error}");
        assert!(!outcome.said.contains("==== boot"), "{}", outcome.said);
        let shown = everything_shown(&outcome, &pi);
        assert!(!shown.contains(CANARY));
        for secret in &secrets {
            assert!(!shown.to_lowercase().contains(&secret.to_lowercase()));
        }
        assert!(fs::read_to_string(&saved).unwrap().contains(CANARY));
    }

    #[test]
    fn the_error_for_a_log_of_an_older_build_does_not_point_above() {
        let checkout = checkout();
        let mut pi = FakePi::new();
        let old = "==== boot, build 1600000000 ====\nan earlier run\n";
        pi.log = Some(old.as_bytes().to_vec());
        let outcome = run_deploy("pi", false, checkout.path(), &mut pi);
        // The log is shown, and the error follows it.
        assert!(outcome.said.contains(old), "{}", outcome.said);
        assert!(
            outcome.error().contains("earlier run"),
            "{}",
            outcome.error()
        );
        assert!(!outcome.error().contains("above"), "{}", outcome.error());
    }

    #[test]
    fn a_log_without_a_boot_header_fails_the_deploy() {
        let checkout = checkout();
        let mut pi = FakePi::new();
        pi.log = Some(b"qberrypi 0.1.0\nrestored config.txt\n".to_vec());
        let outcome = run_deploy("pi", false, checkout.path(), &mut pi);
        assert!(
            outcome.error().contains("no boot header"),
            "{}",
            outcome.error()
        );
    }

    fn run_collect(host: &str, root: &Path, pi: &mut FakePi) -> (Result<PathBuf>, String) {
        let mut said = Vec::new();
        let result = collect_with(host, root, pi, &FakeClock::new(), &mut said);
        (
            result.map(|(path, _)| path),
            String::from_utf8(said).unwrap(),
        )
    }

    #[test]
    fn collect_writes_a_private_log_named_by_the_time_and_prints_it() {
        let checkout = checkout();
        let mut pi = FakePi::new();
        let (result, said) = run_collect("pi", checkout.path(), &mut pi);
        let path = result.unwrap();
        assert_eq!(path, checkout.path().join("out/logs/1700000000.log"));
        assert_eq!(fs::read_to_string(&path).unwrap(), LOG);
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o600);
        assert!(said.contains(LOG), "{said}");
        assert_eq!(pi.summary(), ["test", "cat"]);
        assert_eq!(pi.calls[0], (log_exists("pi"), None));
        assert_eq!(pi.calls[1], (fetch_log("pi"), None));
    }

    /// The error, causes included, and everything collect showed or ran.
    fn collect_shown(result: &Result<PathBuf>, said: &str, pi: &FakePi) -> String {
        let mut shown = said.to_owned();
        if let Err(error) = result {
            shown.push_str(&format!("{error:#} {error:?}"));
        }
        for (invocation, _) in &pi.calls {
            shown.push_str(&format!("{invocation:?}"));
        }
        shown
    }

    #[test]
    fn collect_shows_no_log_that_holds_the_passphrase_or_the_key() {
        let secrets = secrets_of(&one_shot_toml()).unwrap();
        let leaks = [
            secrets[0].clone(),
            secrets[1].clone(),
            secrets[1].to_uppercase(),
        ];
        for leaked in leaks {
            let checkout = checkout();
            let saved = checkout.path().join("out/logs/1700000000.log");
            let mut pi = FakePi::new();
            pi.log = Some(format!("{LOG}wifi: joined with {leaked}\n").into_bytes());
            let (result, said) = run_collect("pi", checkout.path(), &mut pi);

            let error = format!("{:#}", result.as_ref().unwrap_err());
            assert!(error.contains("Wi-Fi passphrase or key"), "{error}");
            assert!(
                error.contains(&format!("delete {} and report this", saved.display())),
                "{error}"
            );
            // The log is saved for the owner to delete, and none of it is shown.
            assert!(fs::read_to_string(&saved).unwrap().contains(&leaked));
            let mode = fs::metadata(&saved).unwrap().permissions().mode() & 0o7777;
            assert_eq!(mode, 0o600);
            assert!(!said.contains("==== boot"), "{said}");
            assert!(!said.contains("collect: wrote"), "{said}");
            let shown = collect_shown(&result, &said, &pi).to_lowercase();
            for secret in &secrets {
                assert!(!shown.contains(&secret.to_lowercase()), "{shown}");
            }
        }
    }

    #[test]
    fn collect_shows_a_log_that_holds_no_secret_of_the_configuration() {
        let checkout = checkout();
        let mut pi = FakePi::new();
        // Another passphrase than the checkout's is not what collect looks for.
        pi.log = Some(format!("{LOG}wifi: someone else's passphrase\n").into_bytes());
        let (result, said) = run_collect("pi", checkout.path(), &mut pi);
        let path = result.unwrap();
        assert!(said.contains("someone else's passphrase"), "{said}");
        assert!(said.contains(&format!("collect: wrote {}", path.display())));
    }

    #[test]
    fn collect_without_a_readable_configuration_shows_the_log_as_it_always_did() {
        let leaking = format!("{LOG}wifi: joined with {CANARY}\n");
        for text in [None, Some(format!("{CANARY} = [")), Some(String::new())] {
            let checkout = checkout();
            let toml = checkout.path().join("qberrypi.toml");
            match &text {
                None => fs::remove_file(&toml).unwrap(),
                Some(text) => fs::write(&toml, text).unwrap(),
            }
            let mut pi = FakePi::new();
            pi.log = Some(leaking.clone().into_bytes());
            let (result, said) = run_collect("pi", checkout.path(), &mut pi);

            result.unwrap();
            assert!(said.contains(&leaking), "{text:?}: {said}");
        }
    }

    #[test]
    fn collect_says_when_the_pi_has_no_log() {
        let checkout = checkout();
        let mut pi = FakePi::new();
        pi.log = None;
        let (result, _) = run_collect("pi", checkout.path(), &mut pi);
        let error = format!("{:#}", result.unwrap_err());
        assert!(error.contains("no log.txt"), "{error}");
        assert!(error.contains("pi"), "{error}");
        assert_eq!(pi.summary(), ["test"]);
        assert!(!checkout.path().join("out/logs").exists());
    }

    #[test]
    fn collect_refuses_a_bad_host_before_running_anything() {
        let checkout = checkout();
        let mut pi = FakePi::new();
        let (result, _) = run_collect("-oProxyCommand=x", checkout.path(), &mut pi);
        assert!(result.is_err());
        assert!(pi.calls.is_empty());
    }

    #[test]
    fn collect_does_not_overwrite_a_log_of_the_same_second() {
        let checkout = checkout();
        let mut pi = FakePi::new();
        run_collect("pi", checkout.path(), &mut pi).0.unwrap();
        pi.log = Some(b"ANOTHER\n".to_vec());
        let (result, _) = run_collect("pi", checkout.path(), &mut pi);
        assert!(result.is_err());
        let path = checkout.path().join("out/logs/1700000000.log");
        assert_eq!(fs::read_to_string(path).unwrap(), LOG);
    }

    #[test]
    fn the_checkout_keeps_what_deploy_writes_out_of_git() {
        let ignored = include_str!("../../.gitignore");
        for line in ["/out/", "/vendor-cache/", "qberrypi.toml"] {
            assert!(ignored.lines().any(|l| l == line), "{line} is not ignored");
        }
    }
}
