//! `cargo xtask deploy` and `collect`: one-shot boots on a card shared with Raspberry Pi OS.
//!
//! The Pi is running Raspberry Pi OS and is reached over SSH. `deploy` copies
//! the build into a fresh directory under `/tmp` there and hands a script to
//! `sudo sh -s`; that script alone writes the boot partition. It saves
//! `config.txt` as `config.pios.txt`, which qberrypi's init copies back, and
//! it stops before it touches `config.txt` whenever something is not as expected.
//!
//! Every external command is built as a program with its arguments by a
//! function of its own and run through a [`Runner`], so tests can read the
//! commands as data and no test reaches a real machine.

use std::ffi::OsString;
use std::fs::{self, OpenOptions, Permissions};
use std::io::{self, ErrorKind, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Error, Result, anyhow, bail};
use qberrypi::config;
use tempfile::TempDir;

use crate::build::sha256sums;

/// The environment variable that names the Pi when `--host` is not given.
pub const HOST_VARIABLE: &str = "QBERRYPI_HOST";

/// The configuration file, in the checkout and in the folder on the card.
const CONFIG_FILE: &str = "qberrypi.toml";
/// Where `cargo xtask build` leaves the boot folder.
const BUILD_FOLDER: &str = "out/qberrypi";
/// The list of digests that the build writes and the script checks.
const CHECKSUMS: &str = "SHA256SUMS";
/// Files of the folder on the card that are not the build's to list.
const NOT_THE_BUILDS: [&str; 3] = [CONFIG_FILE, CHECKSUMS, "log.txt"];
/// The copy of the Pi's boot partition that the first deploy takes.
const BOOT_BACKUP: &str = "vendor-cache/bootpart-backup.tar";
/// Where `collect` keeps the logs.
const LOG_FOLDER: &str = "out/logs";

/// Where Raspberry Pi OS mounts the boot partition.
const REMOTE_BOOT: &str = "/boot/firmware";
/// The log qberrypi appends to when `debug.log_to_sd` is on.
const REMOTE_LOG: &str = "/boot/firmware/qberrypi/log.txt";
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
/// How long the Pi is given to answer again.
const BACK_WITHIN: Duration = Duration::from_secs(300);
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
/// Script status: `config.txt` could not be written.
const SELECT_FAILED: i32 = 9;

/// The line the script prints once `config.txt` selects qberrypi.
const SELECTED_MARKER: &str = "qberrypi-deploy: qberrypi is selected; restarting";

/// What to do about a Pi that stays away after a deploy.
const RECOVERY: &str = "If qberrypi started with debug.one_shot on, it has already put Raspberry Pi \
    OS's config.txt back: switch the Pi off and on, and wait. If it still stays away, put the card \
    in another computer and copy config.pios.txt over config.txt.";

/// Checks the local `qberrypi.toml` before anything is sent: it must parse, and
/// it must be a one-shot configuration unless `permanent` says otherwise.
pub fn check_local(toml_text: &str, permanent: bool) -> Result<(), String> {
    if debug_settings(toml_text)?.one_shot || permanent {
        return Ok(());
    }
    Err(format!(
        "{CONFIG_FILE} has debug.one_shot off: qberrypi would stay on the Pi and never return to \
         Raspberry Pi OS by itself. Turn debug.one_shot on, or pass --permanent if that is wanted"
    ))
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
struct Invocation {
    program: &'static str,
    args: Vec<OsString>,
}

/// How a command ended and what it wrote.
#[derive(Debug, Clone)]
struct Finished {
    /// The exit status; none when a signal ended the command.
    status: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Runs external commands. Tests put a recorder in its place.
trait Runner {
    /// Runs the command to its end, feeding it `stdin` if there is any.
    fn run(&mut self, invocation: &Invocation, stdin: Option<&[u8]>) -> io::Result<Finished>;
}

/// Runs the commands for real.
struct SystemRunner;

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
}

/// A command for the Pi. `ssh` joins the words with spaces for the shell there,
/// so every word must be one that needs no quoting.
fn ssh(host: &str, remote: &[&str]) -> Invocation {
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
    let done = runner
        .run(invocation, None)
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

/// Reads the build's checksums and adds a line for the configuration.
///
/// Returns the files the build lists, in its order, and the text for the
/// stage. The list is refused unless every line is a digest and a plain file
/// name, as `cargo xtask build` writes them, and `config.txt` is among them.
fn staged_checksums(build_sums: &str, toml: &[u8]) -> Result<(Vec<String>, String)> {
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
    let staged = format!("{build_sums}{}", sha256sums(&[(CONFIG_FILE, toml)]));
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
fn write_private_new(path: &Path, data: &[u8]) -> Result<()> {
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
}

impl RemoteScript {
    /// Writes the script out: POSIX `sh`, to be run as root.
    pub fn render(&self) -> String {
        let boot = sh_quote(&self.boot_dir);
        let stage = sh_quote(&self.stage_dir);
        let hardware_checks = if self.hardware_checks { "yes" } else { "no" };
        let restart = &self.reboot_cmd;
        format!(
            "{SCRIPT_HEAD}\n\
             boot={boot}\n\
             stage={stage}\n\
             hardware_checks={hardware_checks}\n\
             \n\
             already_selected={ALREADY_SELECTED}\n\
             backup_refused={BACKUP_REFUSED}\n\
             config_changed={CONFIG_CHANGED}\n\
             bad_stage={BAD_STAGE}\n\
             wrong_machine={WRONG_MACHINE}\n\
             bad_copy={BAD_COPY}\n\
             select_failed={SELECT_FAILED}\n\
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

# Copies the staged files into the folder on the card and reads them back
# against the checksums. Fails if any step does.
copy_and_check() {
    mkdir -p -- "$own" || return 1
    cp -- "$stage"/* "$own/" || return 1
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

    # The stage holds a copy of the Wi-Fi passphrase: however this ends, it goes.
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
        [ -r /proc/device-tree/model ] ||
            die "$wrong_machine" "this machine does not say which board it is; nothing was changed"
        model=$(tr -d '\000' </proc/device-tree/model)
        case "$model" in
            *'Raspberry Pi 3 Model B Plus'*) ;;
            *) die "$wrong_machine" "this is not a Raspberry Pi 3 Model B Plus but a $model; nothing was changed" ;;
        esac
        mountpoint -q "$boot" || die "$wrong_machine" "$boot is not a mount point; nothing was changed"
    fi

    # 2. The saved configuration of Raspberry Pi OS. One that is there is never written.
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
        mv -- "$backup.new" "$backup"
        sync
    fi

    # Whether saved just now or long ago: init must be able to restore from it.
    if ! restorable "$backup"; then
        refused="config.pios.txt $reason, so qberrypi could not hand the Pi back to Raspberry Pi OS"
        if selects_qberrypi "$active"; then
            die "$backup_refused" "$refused. And config.txt selects qberrypi since an earlier deploy: the next restart would start it for good. Before the Pi restarts, put the configuration of Raspberry Pi OS back as $active; nothing was changed"
        fi
        die "$backup_refused" "$refused. If $active is the configuration of Raspberry Pi OS, delete $backup and deploy again; nothing was changed"
    fi

    # A config.txt that does not select qberrypi is the one of Raspberry Pi OS,
    # and init will put the saved one in its place. Unless the two are the
    # same, that would lose what was changed since.
    selected=0
    selects_qberrypi "$active" || selected=$?
    if [ "$selected" -ne 0 ]; then
        cmp -s -- "$active" "$backup" ||
            die "$config_changed" "config.txt is not what config.pios.txt saved, and after its run qberrypi would put the saved one back. To keep the one in config.txt, delete $backup and deploy again; config.txt was not changed"
    fi

    # 3 and 4. The build goes beside whatever the folder holds already (the log
    # of earlier runs), and is read back before anything depends on it.
    say "copying the build to $own"
    if ! copy_and_check; then
        if [ "$selected" -eq 0 ]; then
            die "$bad_copy" "the build in $own is not complete or does not match SHA256SUMS. config.txt was not changed, but it has selected qberrypi since an earlier deploy, so the next restart would start these files. Before the Pi restarts, deploy again, or put the saved configuration back: cp $backup $active"
        fi
        die "$bad_copy" "the build in $own is not complete or does not match SHA256SUMS; config.txt was not changed, so the next restart is Raspberry Pi OS"
    fi

    # 5. The stage is done with; no copy of the passphrase stays in /tmp.
    rm -rf -- "$stage"

    # 6. From here on the next start is qberrypi.
    say "selecting qberrypi"
    if ! cp -- "$own/config.txt" "$active" || ! cmp -s -- "$own/config.txt" "$active"; then
        die "$select_failed" "config.txt could not be written and may be damaged. Before the Pi restarts, put the saved one back: cp $backup $active"
    fi
    say "qberrypi is selected; restarting"

    # 7. The restart.
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

/// Waits for the Pi to stop answering and then to answer again.
///
/// `answering` asks the Pi once. A Pi that is not seen to go down within 30 s
/// is still waited for; one that does not answer again within 300 s is an
/// error that says how to recover.
fn wait_for_return(answering: &mut dyn FnMut() -> bool, clock: &mut dyn Clock) -> Result<Returned> {
    let went_down = wait_until(false, GONE_WITHIN, answering, clock);
    if !wait_until(true, BACK_WITHIN, answering, clock) {
        bail!(
            "it did not answer again within {} s. {RECOVERY}",
            BACK_WITHIN.as_secs()
        );
    }
    Ok(if went_down {
        Returned::AfterRestart
    } else {
        Returned::WithoutGoingDown
    })
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
/// waits for it to return to Raspberry Pi OS and collects the log.
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
    if debug.one_shot && debug.return_after_secs == 0 {
        writeln!(
            out,
            "deploy: {host}: note: debug.return_after_secs is 0, so qberrypi will not restart by \
             itself. This command will stop waiting after {} s; the Pi returns to Raspberry Pi \
             OS when it is switched off and on",
            BACK_WITHIN.as_secs()
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
    let (names, staged_sums) = staged_checksums(&build_sums, toml.as_bytes())?;
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
        // The stage holds the passphrase. The script removes it, but may not have run.
        let _ = writeln!(out, "deploy: {host}: removing the stage directory");
        let _ = runner.run(&remove_stage(host, &stage), None);
    }
    installed?;
    drop(scratch);

    if !debug.one_shot {
        writeln!(
            out,
            "deploy: {host}: debug.one_shot is off, so qberrypi stays: the Pi will not return to \
             Raspberry Pi OS by itself. To return it, put the card in another computer and copy \
             config.pios.txt over config.txt"
        )?;
        return Ok(());
    }

    writeln!(
        out,
        "deploy: {host}: waiting up to {} s for it to go down and then up to {} s for it to answer again",
        GONE_WITHIN.as_secs(),
        BACK_WITHIN.as_secs()
    )?;
    let mut answering = || {
        runner
            .run(&probe(host), None)
            .is_ok_and(|done| done.status == Some(0))
    };
    match wait_for_return(&mut answering, clock)
        .with_context(|| format!("{host} did not come back"))?
    {
        Returned::AfterRestart => writeln!(out, "deploy: {host}: it is back")?,
        Returned::WithoutGoingDown => writeln!(
            out,
            "deploy: {host}: note: it never stopped answering; it may not have restarted, and \
             the log may be an older one"
        )?,
    }

    collect_with(host, &root, runner, clock, out).map(drop)
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
    };
    let ran = runner
        .run(&run_script(host), Some(script.render().as_bytes()))
        .context("cannot run ssh")?;
    out.write_all(String::from_utf8_lossy(&ran.stdout).as_bytes())?;
    out.write_all(String::from_utf8_lossy(&ran.stderr).as_bytes())?;
    script_outcome(host, &ran)
}

/// Fetches the log qberrypi left on the Pi's boot partition, saves it under
/// `out/logs/`, prints it and returns where it was saved.
pub fn collect(host: &str, root: &Path) -> Result<PathBuf> {
    let clock = SystemClock {
        start: Instant::now(),
    };
    collect_with(host, root, &mut SystemRunner, &clock, &mut io::stdout())
}

/// `collect`, with the commands, the clock and the output in the caller's hands.
fn collect_with(
    host: &str,
    root: &Path,
    runner: &mut dyn Runner,
    clock: &dyn Clock,
    out: &mut dyn Write,
) -> Result<PathBuf> {
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

    let text = String::from_utf8_lossy(&fetched.stdout);
    out.write_all(text.as_bytes())?;
    if !text.is_empty() && !text.ends_with('\n') {
        writeln!(out)?;
    }
    writeln!(out, "collect: wrote {}", path.display())?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::Cell;
    use std::collections::{BTreeMap, VecDeque};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::process::{Command, Stdio};
    use std::rc::Rc;

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
        let (names, staged) = staged_checksums(&build, b"T").unwrap();
        assert_eq!(names, ["kernel8.img", "config.txt"]);
        let toml_line = sha256sums(&[("qberrypi.toml", b"T")]);
        assert_eq!(staged, format!("{build}{toml_line}"));
        assert_eq!(staged.lines().count(), 3);
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
            assert!(staged_checksums(&sums, b"T").is_err(), "{case}");
        }
    }

    // ---------------------------------------------------------------- the remote script

    const PIOS: &str = "PIOS\n";
    const OWN_CONFIG: &str = "os_prefix=qberrypi/\n";
    const STAGED: [(&str, &[u8]); 4] = [
        ("kernel8.img", b"KERNEL"),
        ("initramfs8", b"INITRAMFS"),
        ("config.txt", OWN_CONFIG.as_bytes()),
        ("qberrypi.toml", b"[debug]\none_shot = true\n"),
    ];

    /// Replaces `sync` for the length of a test and records what `config.txt` held when it ran.
    const FAKE_SYNC: &str = "sync() { printf 'sync: %s\\n' \"$(cat \"$QBERRYPI_TEST_BOOT/config.txt\" 2>/dev/null)\" >>\"$QBERRYPI_TEST_TRACE\"; }\n";
    /// Replaces `rm`, so a script that is wrong about what to remove removes nothing.
    const FAKE_RM: &str = "rm() { printf 'rm %s\\n' \"$*\" >>\"$QBERRYPI_TEST_TRACE\"; }\n";
    /// Stands in for the restart and records what `config.txt` held when it was asked for.
    const FAKE_RESTART: &str = "printf 'restart: %s\\n' \"$(cat \"$QBERRYPI_TEST_BOOT/config.txt\")\" >>\"$QBERRYPI_TEST_TRACE\"";

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
            }
        }

        /// Runs the script as `deploy` does, on the standard input of `sh -s`.
        fn run(&self, shell: &str) -> Ran {
            self.run_text(shell, &self.script().render(), FAKE_SYNC)
        }

        /// Runs a script text after the given stand-in commands.
        fn run_text(&self, shell: &str, script: &str, fakes: &str) -> Ran {
            let mut child = Command::new(shell)
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
            let _ = input.write_all(format!("{fakes}{script}").as_bytes());
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

    #[test]
    fn a_corrupt_copy_over_a_selected_qberrypi_says_what_to_do_before_a_restart() {
        // An earlier deploy selected qberrypi and the Pi has not restarted since. The
        // script still leaves config.txt alone, but the files it names are now bad.
        for shell in shells() {
            let card = Card::fresh();
            assert_eq!(card.run(shell).status, Some(0));
            card.stage_files(&STAGED);
            fs::write(card.stage.path().join("initramfs8"), b"DAMAGED").unwrap();

            let ran = card.run(shell);
            assert_eq!(ran.status, Some(BAD_COPY), "{shell}: {}", ran.stderr);
            assert_eq!(card.read_boot("config.txt"), OWN_CONFIG.as_bytes());
            assert_eq!(card.read_boot("config.pios.txt"), PIOS.as_bytes());
            let backup = card.boot.join("config.pios.txt");
            let active = card.boot.join("config.txt");
            let remedy = format!("cp {} {}", backup.display(), active.display());
            assert!(
                ran.stderr.contains("has selected qberrypi"),
                "{}",
                ran.stderr
            );
            assert!(ran.stderr.contains(&remedy), "{}", ran.stderr);
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

    #[test]
    fn the_card_is_synced_after_selecting_and_before_the_restart() {
        for shell in shells() {
            let card = Card::fresh();
            assert_eq!(card.run(shell).status, Some(0));
            let trace = card.trace();
            let lines: Vec<&str> = trace.lines().collect();
            let last_two = &lines[lines.len() - 2..];
            assert_eq!(
                last_two,
                ["sync: os_prefix=qberrypi/", "restart: os_prefix=qberrypi/"],
                "{trace}"
            );
            assert_eq!(trace.matches("restart").count(), 1, "{trace}");
            // Every earlier sync saw the configuration of Raspberry Pi OS.
            for line in &lines[..lines.len() - 2] {
                assert_eq!(*line, "sync: PIOS", "{trace}");
            }
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

    fn production_script() -> String {
        RemoteScript {
            boot_dir: "/boot/firmware".to_owned(),
            stage_dir: "/tmp/qberrypi-stage.Ab12Cd".to_owned(),
            reboot_cmd: "systemctl reboot".to_owned(),
            hardware_checks: true,
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
        assert!(script.contains("\n    systemctl reboot\n"));
        assert!(script.contains("Raspberry Pi 3 Model B Plus"));
        assert!(script.ends_with("\nmain\n"));
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
        let outcome = wait_for_return(&mut || answers.pop_front().unwrap(), &mut clock).unwrap();
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
        let error = wait_for_return(&mut || answers.pop_front().unwrap_or(false), &mut clock)
            .unwrap_err()
            .to_string();
        assert!(error.contains("another computer"), "{error}");
        assert!(error.contains("config.pios.txt over config.txt"), "{error}");
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
            &mut clock,
        );
        assert!(result.is_err());
        // Gone at the first answer; then 300 s, overrun by at most one answer and one pause.
        assert!(clock.now() >= 310 * SECOND, "{:?}", clock.now());
        assert!(clock.now() <= 325 * SECOND, "{:?}", clock.now());
    }

    // ---------------------------------------------------------------- deploy and collect, end to end

    const STAGE: &str = "/tmp/qberrypi-stage.Ab12Cd";
    const CANARY: &str = "canary-passphrase-93871";
    const BOOT_TAR: &[u8] = b"TAR-OF-THE-BOOT-PARTITION-canary-firstboot-secret";
    const LOG: &str = "qberrypi 0.1.0\nrestored config.txt\n";

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
        tar: Finished,
        mktemp: Finished,
        scp: Finished,
        script: Finished,
        log: Option<Vec<u8>>,
        /// The staged checksums and the mode of the folder they were in, as scp found them.
        uploaded_sums: Option<(PathBuf, String, u32)>,
    }

    impl FakePi {
        fn new() -> Self {
            FakePi {
                calls: Vec::new(),
                answering: VecDeque::from([true, false, false]),
                answering_after: true,
                tar: finished(0, BOOT_TAR, ""),
                mktemp: finished(0, format!("{STAGE}\n"), ""),
                scp: finished(0, "", ""),
                script: finished(
                    0,
                    format!("qberrypi-deploy: copying\n{SELECTED_MARKER}\n"),
                    "",
                ),
                log: Some(LOG.as_bytes().to_vec()),
                uploaded_sums: None,
            }
        }

        /// The first word of each remote command, or `scp`, in the order they ran.
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
                "test" => finished(if self.log.is_some() { 0 } else { 1 }, "", ""),
                "cat" => finished(0, self.log.clone().unwrap(), ""),
                other => panic!("unexpected remote command {other}"),
            })
        }
    }

    const BUILT: [(&str, &[u8]); 3] = [
        ("kernel8.img", b"KERNEL"),
        ("initramfs8", b"INITRAMFS"),
        ("config.txt", b"os_prefix=qberrypi/\n"),
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

        assert_eq!(
            pi.summary(),
            [
                "tar", "mktemp", "scp", "sudo", "true", "true", "true", "true", "test", "cat"
            ]
        );
        // Nothing goes through a local shell.
        for (invocation, _) in &pi.calls {
            assert!(["ssh", "scp"].contains(&invocation.program));
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
        };
        assert_eq!(
            String::from_utf8(script_input.clone().unwrap()).unwrap(),
            expected.render()
        );
        for index in [0, 1, 4, 5, 6, 7, 8, 9] {
            assert_eq!(call(index).1, None, "call {index} was given input");
        }
        for index in 4..8 {
            assert_eq!(call(index).0, probe("pi"));
        }
        assert_eq!(call(8).0, log_exists("pi"));
        assert_eq!(call(9).0, fetch_log("pi"));

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
            "deploy: pi: copying 5 files",
            "deploy: pi: installing",
            "qberrypi-deploy: copying",
            "deploy: pi: waiting",
            "deploy: pi: it is back",
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
        let cases: [(&str, &str, bool, Spoil, &str); 7] = [
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

    #[test]
    fn a_permanent_deploy_does_not_wait_for_the_pi() {
        let checkout = checkout();
        let text = one_shot_toml().replace("one_shot = true", "one_shot = false");
        fs::write(checkout.path().join("qberrypi.toml"), text).unwrap();
        let mut pi = FakePi::new();
        let outcome = run_deploy("pi", true, checkout.path(), &mut pi);
        outcome.result.as_ref().unwrap();
        assert_eq!(pi.summary(), ["tar", "mktemp", "scp", "sudo"]);
        assert!(
            outcome.said.contains("config.pios.txt over config.txt"),
            "{}",
            outcome.said
        );
    }

    #[test]
    fn a_one_shot_configuration_deployed_with_permanent_still_waits() {
        let checkout = checkout();
        let mut pi = FakePi::new();
        run_deploy("pi", true, checkout.path(), &mut pi)
            .result
            .unwrap();
        assert!(pi.ran("true") && pi.ran("cat"));
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
        assert!(error.contains("another computer"), "{error}");
        assert!(error.contains("config.pios.txt over config.txt"), "{error}");
        assert!(!pi.ran("test") && !pi.ran("cat"));
    }

    fn run_collect(host: &str, root: &Path, pi: &mut FakePi) -> (Result<PathBuf>, String) {
        let mut said = Vec::new();
        let result = collect_with(host, root, pi, &FakeClock::new(), &mut said);
        (result, String::from_utf8(said).unwrap())
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
