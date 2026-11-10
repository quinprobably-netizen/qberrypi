//! `cargo xtask qemu-test`: boots the built kernel and initramfs in QEMU's
//! Raspberry Pi 3 and checks what init did, on the serial console and on the
//! card.
//!
//! Each scenario gets a card image of its own and one boot. The guest has no
//! display, no network and no device of this machine; its console is a pipe
//! that is captured, and the card image is its only drive.

use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};

use crate::build::CONFIG_TXT;
use crate::sdimage;

const QEMU: &str = "qemu-system-aarch64";

/// The build that is booted, and where the scenarios keep their files; both under the repository root.
const BOOT_FOLDER: &str = "out/qberrypi";
const QEMU_FOLDER: &str = "out/qemu";

// The three files of the boot folder that QEMU loads, as the Pi's firmware would.
const KERNEL: &str = "kernel8.img";
const DEVICE_TREE: &str = "bcm2710-rpi-3-b-plus.dtb";
const INITRAMFS: &str = "initramfs8";
const CHECKSUMS: &str = "SHA256SUMS";

/// The kernel arguments of every boot.
///
/// - `console=ttyAMA1`: the serial port QEMU gives the guest is the PL011,
///   and this kernel's device tree names that one `serial1`.
/// - `initcall_blacklist=bcm2835_wdt_driver_init`: keeps the watchdog driver
///   out. QEMU's model of the board resets the machine the moment the
///   watchdog is armed, which init does before anything this test looks at.
///   See `RESTART_UNCHECKED` for what that costs.
/// - `qberrypi.selftest`: has init provoke one request to the module helper.
const KERNEL_ARGS: &str = "console=ttyAMA1,115200 panic=5 loglevel=7 qberrypi.selftest \
                           initcall_blacklist=bcm2835_wdt_driver_init";

/// The kernel arguments of the boot without a console: `KERNEL_ARGS` but for the console.
///
/// - `console=ttyAMA0`: a serial port this device tree does not have. The
///   kernel then has no console to open for init, and starts it with nothing
///   open, which is what a mistyped `console=` does on the Pi.
/// - `earlycon=pl011,0x3f201000`: lets the kernel's own messages through to
///   the serial port, so that the end of the boot can be seen. It is not a
///   console a program can open; nothing init writes goes there.
const KERNEL_ARGS_NO_CONSOLE: &str = "earlycon=pl011,0x3f201000 console=ttyAMA0,115200 panic=5 \
                                      loglevel=7 qberrypi.selftest \
                                      initcall_blacklist=bcm2835_wdt_driver_init";

/// The kernel arguments of the boot that keeps the watchdog driver: `KERNEL_ARGS` without
/// the blacklist. In QEMU that boot ends where init arms the watchdog.
const KERNEL_ARGS_WITH_WATCHDOG: &str =
    "console=ttyAMA1,115200 panic=5 loglevel=7 qberrypi.selftest";

/// How long one boot may take. The guest is emulated, not virtualised, so it is slow.
const BOOT_TIMEOUT: Duration = Duration::from_secs(300);
/// How often a running guest is looked at.
const POLL_EVERY: Duration = Duration::from_millis(100);

/// What the kernel prints when it is asked to restart the machine.
const RESTART_REQUESTED: &str = "reboot: Restarting system";
/// What the kernel prints when it has no way to restart the machine. Nothing follows it.
const GUEST_HALTED: &str = "Reboot failed -- System halted";

/// What the kernel prints when it starts init with no console open.
const NO_INITIAL_CONSOLE: &str = "Warning: unable to open an initial console.";

/// Printed with the scenario that boots without a console.
const JUDGED_BY_THE_CARD: &str = "init has no console in this boot, so nothing it does can show \
    on the serial port; what it did is judged from the card alone. The serial log holds only \
    the kernel's early console";

/// Printed with the scenario that keeps the watchdog driver.
const RESET_ON_ARMING: &str = "this boot keeps the watchdog driver, and QEMU's raspi3b resets \
    the machine the moment init arms the watchdog. It stands for a board that would do the \
    same: by then init must have put Raspberry Pi OS's config.txt back";

/// Why a guest that restarts does not end QEMU here, printed with every scenario it applies to.
const RESTART_UNCHECKED: &str = "QEMU's raspi3b resets the machine the moment the watchdog is \
    armed, so this test boots with the board's watchdog driver left out \
    (initcall_blacklist=bcm2835_wdt_driver_init). That driver is also what restarts the board: \
    without it the kernel takes the restart request and halts, and QEMU does not exit. On the \
    Pi the driver is there";

/// A `config.txt` that starts Raspberry Pi OS, which every image holds as `config.pios.txt`.
const PIOS: &str = "# raspberry pi os\narm_64bit=1\n";

// Where the files the scenarios look at are on the card.
const ACTIVE_CONFIG: &str = "config.txt";
const PIOS_CONFIG: &str = "config.pios.txt";
const SYSTEM_CONFIG: &str = "qberrypi/qberrypi.toml";
const SYSTEM_LOG: &str = "qberrypi/log.txt";

/// The template the scenarios make their `qberrypi.toml` from, under the repository root.
const EXAMPLE_CONFIG: &str = "qberrypi.example.toml";
/// The Wi-Fi passphrase of the template. No boot may show it anywhere.
const PASSPHRASE: &str = "example-passphrase";

/// How many lines of the serial console a failed scenario shows.
const SERIAL_TAIL_LINES: usize = 40;

/// How one boot in QEMU ended.
pub struct Outcome {
    /// Everything the guest wrote to its serial console, without carriage returns.
    pub serial: String,
    /// Whether QEMU ended by itself in time, which it does when the guest restarts the machine.
    pub exited: bool,
    /// The card image the guest booted from, as the guest left it.
    pub image: PathBuf,
}

/// Boots this repository's build (`out/qberrypi/`) in QEMU from a card image.
///
/// Returns when QEMU ends, when the guest's kernel has halted, or after
/// `timeout`, whichever is first. QEMU is not left running in any case.
pub fn boot(image: &Path, timeout: Duration) -> Result<Outcome> {
    boot_with(image, KERNEL_ARGS, timeout)
}

/// Like `boot`, with the kernel arguments given.
fn boot_with(image: &Path, kernel_args: &str, timeout: Duration) -> Result<Outcome> {
    let boot_folder = crate::workspace_root().join(BOOT_FOLDER);
    let command = qemu_command(&boot_folder, image, kernel_args);
    let (serial, exited) = run_guest(command, timeout)?;
    Ok(Outcome {
        serial,
        exited,
        image: image.to_owned(),
    })
}

/// The QEMU invocation that boots the build in `boot_folder` from a card image.
fn qemu_command(boot_folder: &Path, image: &Path, kernel_args: &str) -> Command {
    // A comma ends a value in QEMU's option lists; a doubled one stands for itself.
    let image = image.to_string_lossy().replace(',', ",,");
    let mut command = Command::new(QEMU);
    command
        .args(["-M", "raspi3b", "-display", "none", "-no-reboot"])
        .args(["-serial", "stdio", "-monitor", "none", "-nic", "none"])
        .arg("-kernel")
        .arg(boot_folder.join(KERNEL))
        .arg("-dtb")
        .arg(boot_folder.join(DEVICE_TREE))
        .arg("-initrd")
        .arg(boot_folder.join(INITRAMFS))
        .args(["-append", kernel_args])
        .arg("-drive")
        .arg(format!("file={image},if=sd,format=raw"));
    command
}

/// A guest that is running. It is killed when this goes away, however that happens.
struct Guest(Child);

impl Drop for Guest {
    fn drop(&mut self) {
        // Both fail only for a guest that has already ended and been collected.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Runs a guest to its end and returns what it wrote, and whether it ended by itself.
///
/// The guest is killed once it has printed `GUEST_HALTED`, or when `timeout`
/// has passed. One that ends by itself with a failure is an error, which
/// shows what the program said for itself.
fn run_guest(mut command: Command, timeout: Duration) -> Result<(String, bool)> {
    let program = command.get_program().to_string_lossy().into_owned();
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut guest = Guest(
        command
            .spawn()
            .with_context(|| format!("cannot run {program}"))?,
    );
    let (stdout, stderr) = (guest.0.stdout.take(), guest.0.stderr.take());
    let mut stdout = stdout.context("the guest has no output to capture")?;
    let mut stderr = stderr.context("the guest has no error output to capture")?;

    // Both are read as they come, so that the guest never waits for a full pipe.
    let serial = Arc::new(Mutex::new(Vec::new()));
    let serial_reader = {
        let serial = Arc::clone(&serial);
        thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            while let Ok(len @ 1..) = stdout.read(&mut chunk) {
                lock(&serial).extend_from_slice(&chunk[..len]);
            }
        })
    };
    let complaints_reader = thread::spawn(move || {
        let mut complaints = Vec::new();
        let _ = stderr.read_to_end(&mut complaints);
        complaints
    });

    let started = Instant::now();
    let ended = loop {
        if let Some(status) = guest.0.try_wait().context("cannot wait for the guest")? {
            break Some(status);
        }
        let halted = contains(&lock(&serial), GUEST_HALTED.as_bytes());
        if halted || started.elapsed() >= timeout {
            break None;
        }
        thread::sleep(POLL_EVERY);
    };
    // The readers end when the guest's side of the pipes is closed, so the guest goes first.
    drop(guest);
    let _ = serial_reader.join();
    let complaints = complaints_reader.join().unwrap_or_default();

    if let Some(status) = ended
        && !status.success()
    {
        bail!(
            "{program} failed ({status}):\n{}",
            String::from_utf8_lossy(&complaints)
        );
    }
    let serial = String::from_utf8_lossy(&lock(&serial)).replace('\r', "");
    Ok((serial, ended.is_some()))
}

/// Whether `needle` occurs in `haystack`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Takes a lock, whether or not a thread panicked while holding it.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The machine a scenario's guest finds itself on.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Machine {
    /// A serial console, and no watchdog driver: `KERNEL_ARGS`.
    Usual,
    /// No console that init can open: `KERNEL_ARGS_NO_CONSOLE`.
    NoConsole,
    /// The watchdog driver left in, which resets QEMU's machine when the
    /// watchdog is armed: `KERNEL_ARGS_WITH_WATCHDOG`.
    WithWatchdog,
}

/// One of the boots: what is on the card, and what must hold afterwards.
struct Scenario {
    /// As the result line names it.
    name: &'static str,
    machine: Machine,
    /// Printed under the result line, if the result needs a word of explanation.
    note: Option<&'static str>,
    /// The name of its image and its serial log in `out/qemu/`, without the ending.
    file_stem: &'static str,
    /// The text of `qberrypi/qberrypi.toml` on its card.
    system_config: String,
    /// Judges the boot; one entry per condition.
    conditions: fn(&Evidence) -> Vec<Condition>,
}

/// What a boot left behind for the conditions to judge.
struct Evidence {
    serial: String,
    exited: bool,
    /// `config.txt` on the card after the boot, or why it cannot be read.
    active_config: Result<Vec<u8>, String>,
    /// `qberrypi/log.txt` on the card after the boot, or why it cannot be read.
    system_log: Result<String, String>,
    /// The SHA-256 of the whole image before the boot and after it.
    image_before: String,
    image_after: String,
}

/// One thing that must hold after a boot, and whether it does.
struct Condition {
    what: String,
    verdict: Verdict,
}

#[derive(Debug, PartialEq)]
enum Verdict {
    Holds,
    /// With what was found instead.
    Fails(String),
    /// With the reason: one that is QEMU's and does not apply to the Pi.
    CannotBeCheckedInQemu(&'static str),
}

impl Condition {
    fn new(what: impl Into<String>, holds: bool, found: impl FnOnce() -> String) -> Self {
        let verdict = match holds {
            true => Verdict::Holds,
            false => Verdict::Fails(found()),
        };
        Self {
            what: what.into(),
            verdict,
        }
    }
}

impl Evidence {
    /// The brief's `exited`: the guest restarted the machine, which ends QEMU.
    ///
    /// Without the watchdog driver the last step cannot happen. A guest that
    /// got as far as the kernel taking its restart request is then reported
    /// as unchecked; one that never asked fails.
    fn exited(&self) -> Condition {
        let what = "QEMU exited by itself: the guest restarted the machine";
        let asked = self.serial.contains(RESTART_REQUESTED);
        let verdict = if self.exited {
            Verdict::Holds
        } else if asked && self.serial.contains(GUEST_HALTED) {
            Verdict::CannotBeCheckedInQemu(RESTART_UNCHECKED)
        } else if asked {
            Verdict::Fails(format!(
                "the guest asked for a restart, and then neither restarted nor printed `{GUEST_HALTED}`"
            ))
        } else {
            Verdict::Fails("QEMU had to be stopped, and the guest never asked for a restart".into())
        };
        Condition {
            what: what.into(),
            verdict,
        }
    }

    /// What goes with `exited` in every scenario: init asked the kernel for the restart.
    fn restart_requested(&self) -> Condition {
        Condition::new(
            format!("the serial console has the kernel's `{RESTART_REQUESTED}`"),
            self.serial.contains(RESTART_REQUESTED),
            || "it does not".into(),
        )
    }

    fn serial_has(&self, text: &str) -> Condition {
        Condition::new(
            format!("the serial console has `{text}`"),
            self.serial.contains(text),
            || "it does not".into(),
        )
    }

    fn serial_lacks(&self, text: &str) -> Condition {
        Condition::new(
            format!("the serial console does not have `{text}`"),
            !self.serial.contains(text),
            || "it does".into(),
        )
    }

    fn pios_config_is_active(&self) -> Condition {
        let what = "config.txt on the card equals config.pios.txt";
        match &self.active_config {
            Ok(config) => Condition::new(what, config == PIOS.as_bytes(), || {
                format!("it is {:?}", String::from_utf8_lossy(config))
            }),
            Err(error) => Condition::new(what, false, || error.clone()),
        }
    }

    fn log_has(&self, text: &str) -> Condition {
        let what = format!("qberrypi/log.txt on the card has `{text}`");
        match &self.system_log {
            Ok(log) => Condition::new(what, log.contains(text), || "it does not".into()),
            Err(error) => Condition::new(what, false, || error.clone()),
        }
    }

    fn log_lacks(&self, text: &str) -> Condition {
        let what = format!("qberrypi/log.txt on the card does not have `{text}`");
        match &self.system_log {
            Ok(log) => Condition::new(what, !log.contains(text), || "it does".into()),
            // A log that cannot be read is not shown to be free of it.
            Err(error) => Condition::new(what, false, || error.clone()),
        }
    }

    /// For the boot that keeps the watchdog driver: there QEMU does end when the machine is reset.
    fn machine_was_reset(&self) -> Condition {
        Condition::new(
            "QEMU exited by itself: the machine was reset",
            self.exited,
            || "QEMU had to be stopped".into(),
        )
    }

    fn image_is_unchanged(&self) -> Condition {
        Condition::new(
            "the card image has the SHA-256 it had before the boot",
            self.image_before == self.image_after,
            || format!("before {}, after {}", self.image_before, self.image_after),
        )
    }
}

/// The first words of init's banner, which go before the build time.
fn banner_start() -> String {
    format!("qberrypi {} (build ", qberrypi::VERSION)
}

fn one_shot_conditions(evidence: &Evidence) -> Vec<Condition> {
    vec![
        evidence.serial_has(&banner_start()),
        evidence.serial_has("qberrypi-modhelper: net-pf-10: not in table"),
        evidence.restart_requested(),
        evidence.exited(),
        evidence.pios_config_is_active(),
        evidence.log_has("==== boot"),
        evidence.log_has("kernel: "),
        evidence.log_has("wlan0: absent"),
        evidence.log_lacks(PASSPHRASE),
        evidence.serial_lacks(PASSPHRASE),
    ]
}

fn broken_config_conditions(evidence: &Evidence) -> Vec<Condition> {
    vec![
        evidence.restart_requested(),
        evidence.exited(),
        evidence.pios_config_is_active(),
        evidence.log_has("qberrypi.toml"),
        evidence.log_lacks(PASSPHRASE),
    ]
}

fn no_console_conditions(evidence: &Evidence) -> Vec<Condition> {
    vec![
        // What the scenario is about: without this it would be one-shot over again.
        evidence.serial_has(NO_INITIAL_CONSOLE),
        evidence.restart_requested(),
        evidence.exited(),
        evidence.pios_config_is_active(),
        evidence.log_has(&banner_start()),
        evidence.log_lacks(PASSPHRASE),
    ]
}

fn watchdog_conditions(evidence: &Evidence) -> Vec<Condition> {
    vec![
        evidence.serial_has("INFO  config.txt: Restored"),
        // What the scenario is about: the reset came where init arms the
        // watchdog, before the step after it. If init gets further, QEMU's
        // model has changed, and `exited` can be checked in every scenario.
        evidence.serial_lacks("INFO  modules: inserted"),
        evidence.machine_was_reset(),
        evidence.pios_config_is_active(),
    ]
}

fn permanent_conditions(evidence: &Evidence) -> Vec<Condition> {
    vec![
        // Without this the two below would hold for a guest that never started init.
        evidence.serial_has("INFO  returning"),
        evidence.restart_requested(),
        evidence.exited(),
        evidence.image_is_unchanged(),
    ]
}

/// Makes the five scenarios from the text of `qberrypi.example.toml`.
fn scenarios(example: &str) -> Result<[Scenario; 5]> {
    let returns = ("return_after_secs = 0", "return_after_secs = 5");
    let one_shot = edited(
        example,
        &[
            ("one_shot = false", "one_shot = true"),
            ("log_to_sd = false", "log_to_sd = true"),
            returns,
        ],
    )?;
    let permanent = edited(example, &[returns])?;
    let broken = "this is not toml".to_owned();

    // What the scenarios are about is in these switches, so they are read back.
    let switches = |text: &str| {
        qberrypi::config::parse(text)
            .map(|cfg| cfg.debug)
            .map(|debug| (debug.one_shot, debug.log_to_sd, debug.return_after_secs))
            .map_err(|error| anyhow!("{EXAMPLE_CONFIG}, edited for a scenario: {error}"))
    };
    if switches(&one_shot)? != (true, true, 5) || switches(&permanent)? != (false, false, 5) {
        bail!("{EXAMPLE_CONFIG} did not take the scenarios' debug settings");
    }
    if qberrypi::config::parse(&broken).is_ok() {
        bail!("the broken configuration is a valid one");
    }

    Ok([
        Scenario {
            name: "one-shot",
            machine: Machine::Usual,
            note: None,
            file_stem: "one-shot",
            system_config: one_shot.clone(),
            conditions: one_shot_conditions,
        },
        Scenario {
            name: "broken config",
            machine: Machine::Usual,
            note: None,
            file_stem: "broken-config",
            system_config: broken,
            conditions: broken_config_conditions,
        },
        Scenario {
            name: "permanent",
            machine: Machine::Usual,
            note: None,
            file_stem: "permanent",
            system_config: permanent,
            conditions: permanent_conditions,
        },
        Scenario {
            name: "no console",
            machine: Machine::NoConsole,
            note: Some(JUDGED_BY_THE_CARD),
            file_stem: "no-console",
            system_config: one_shot.clone(),
            conditions: no_console_conditions,
        },
        Scenario {
            name: "watchdog resets on arming",
            machine: Machine::WithWatchdog,
            note: Some(RESET_ON_ARMING),
            file_stem: "watchdog-resets-on-arming",
            system_config: one_shot,
            conditions: watchdog_conditions,
        },
    ])
}

/// Swaps pieces of the example configuration; each must be there exactly once.
fn edited(example: &str, edits: &[(&str, &str)]) -> Result<String> {
    let mut text = example.to_owned();
    for (find, replace) in edits {
        if text.matches(find).count() != 1 {
            bail!("{EXAMPLE_CONFIG} does not have `{find}` exactly once");
        }
        text = text.replace(find, replace);
    }
    Ok(text)
}

/// Boots the five scenarios and prints how each went; an error if one did not hold.
///
/// `root` is the repository root. The build in `out/qberrypi/` must be
/// complete; the images and the serial logs go to `out/qemu/`.
pub fn run_all(root: &Path) -> Result<()> {
    require_qemu(QEMU)?;
    verify_boot_folder(&root.join(BOOT_FOLDER))?;
    let example_path = root.join(EXAMPLE_CONFIG);
    let example = fs::read_to_string(&example_path)
        .with_context(|| format!("cannot read {}", example_path.display()))?;
    let scenarios = scenarios(&example)?;
    let folder = root.join(QEMU_FOLDER);
    fs::create_dir_all(&folder).with_context(|| format!("cannot create {}", folder.display()))?;

    let mut failed = Vec::new();
    for scenario in &scenarios {
        let started = Instant::now();
        let conditions = run_scenario(scenario, &folder)
            .with_context(|| format!("{}: could not be run", scenario.name))?;
        let (report, held) =
            scenario_report(scenario.name, scenario.note, &conditions, started.elapsed());
        print!("{report}");
        if !held {
            let log = folder.join(scenario.file_stem).with_extension("log");
            let serial = fs::read_to_string(&log).unwrap_or_default();
            println!(
                "  the last {SERIAL_TAIL_LINES} lines of the serial console ({}):",
                log.display()
            );
            for line in last_lines(&serial, SERIAL_TAIL_LINES) {
                println!("    {line}");
            }
            failed.push(scenario.name);
        }
    }
    if !failed.is_empty() {
        bail!("qemu-test: failed: {}", failed.join(", "));
    }
    Ok(())
}

/// Makes a scenario's card, boots it, saves the serial console and judges the boot.
fn run_scenario(scenario: &Scenario, folder: &Path) -> Result<Vec<Condition>> {
    let image = folder.join(scenario.file_stem).with_extension("img");
    let log = folder.join(scenario.file_stem).with_extension("log");
    sdimage::build(
        &image,
        &[
            (ACTIVE_CONFIG, CONFIG_TXT.as_bytes()),
            (PIOS_CONFIG, PIOS.as_bytes()),
            (SYSTEM_CONFIG, scenario.system_config.as_bytes()),
        ],
    )?;
    // Taken once the image is written whole and closed.
    let image_before = file_sha256(&image)?;

    let outcome = match scenario.machine {
        Machine::Usual => boot(&image, BOOT_TIMEOUT)?,
        Machine::NoConsole => boot_with(&image, KERNEL_ARGS_NO_CONSOLE, BOOT_TIMEOUT)?,
        Machine::WithWatchdog => boot_with(&image, KERNEL_ARGS_WITH_WATCHDOG, BOOT_TIMEOUT)?,
    };
    fs::write(&log, &outcome.serial).with_context(|| format!("cannot write {}", log.display()))?;

    let read =
        |name: &str| sdimage::read_file(&outcome.image, name).map_err(|error| format!("{error:#}"));
    let evidence = Evidence {
        active_config: read(ACTIVE_CONFIG),
        system_log: read(SYSTEM_LOG).map(|log| String::from_utf8_lossy(&log).into_owned()),
        image_after: file_sha256(&outcome.image)?,
        image_before,
        serial: outcome.serial,
        exited: outcome.exited,
    };
    Ok((scenario.conditions)(&evidence))
}

/// Lays out a scenario's result, and says whether every condition that can be checked held.
///
/// The first line is `{name}: ok` or `{name}: FAILED`. The scenario's note,
/// if it has one, and each condition that failed or could not be checked
/// follow on lines of their own.
fn scenario_report(
    name: &str,
    note: Option<&str>,
    conditions: &[Condition],
    took: Duration,
) -> (String, bool) {
    let count = |wanted: fn(&Verdict) -> bool| {
        conditions
            .iter()
            .filter(|condition| wanted(&condition.verdict))
            .count()
    };
    let failed = count(|verdict| matches!(verdict, Verdict::Fails(_)));
    let unchecked = count(|verdict| matches!(verdict, Verdict::CannotBeCheckedInQemu(_)));
    let held = conditions.len() - failed - unchecked;

    let mut report = format!(
        "{name}: {} ({} s; {held} of {} conditions hold",
        if failed == 0 { "ok" } else { "FAILED" },
        took.as_secs(),
        conditions.len()
    );
    if unchecked > 0 {
        report.push_str(&format!(", {unchecked} cannot be checked in QEMU"));
    }
    report.push_str(")\n");
    if let Some(note) = note {
        report.push_str(&format!("  note: {note}.\n"));
    }
    for condition in conditions {
        match &condition.verdict {
            Verdict::Holds => {}
            Verdict::Fails(found) => {
                report.push_str(&format!("  FAILED: {}: {found}\n", condition.what));
            }
            Verdict::CannotBeCheckedInQemu(reason) => {
                report.push_str(&format!(
                    "  cannot be checked in QEMU: {}. {reason}.\n",
                    condition.what
                ));
            }
        }
    }
    (report, failed == 0)
}

/// The last `count` lines of a text.
fn last_lines(text: &str, count: usize) -> Vec<&str> {
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(count)..].to_vec()
}

/// Makes sure QEMU, under the name given, can be run; the error says how to install it.
fn require_qemu(program: &str) -> Result<()> {
    match Command::new(program).arg("--version").output() {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            bail!("{program} is not installed; install it with `sudo pacman -S {QEMU}`")
        }
        Err(error) => Err(error).with_context(|| format!("cannot run {program}")),
    }
}

/// Makes sure the boot folder is a complete build: every file matches `SHA256SUMS`.
///
/// The error says to run `cargo xtask build`.
fn verify_boot_folder(folder: &Path) -> Result<()> {
    const REBUILD: &str = "run `cargo xtask build` first";
    let sums_path = folder.join(CHECKSUMS);
    let sums = fs::read_to_string(&sums_path)
        .with_context(|| format!("cannot read {}; {REBUILD}", sums_path.display()))?;
    let mut listed = Vec::new();
    for line in sums.lines() {
        let (sum, name) = line.split_once("  ").with_context(|| {
            format!(
                "{} is not a list of checksums; {REBUILD}",
                sums_path.display()
            )
        })?;
        let path = folder.join(name);
        let actual = file_sha256(&path)
            .with_context(|| format!("{name} is listed in {CHECKSUMS}; {REBUILD}"))?;
        if actual != sum {
            bail!("{} does not match {CHECKSUMS}; {REBUILD}", path.display());
        }
        listed.push(name);
    }
    for needed in [KERNEL, DEVICE_TREE, INITRAMFS] {
        if !listed.contains(&needed) {
            bail!("{} does not list {needed}; {REBUILD}", sums_path.display());
        }
    }
    Ok(())
}

/// The SHA-256 of a file's contents, as lowercase hex digits.
fn file_sha256(path: &Path) -> Result<String> {
    let data = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    Ok(Sha256::digest(&data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build::sha256sums;
    use std::ffi::OsStr;

    const EXAMPLE: &str = include_str!("../../qberrypi.example.toml");

    /// A stand-in for QEMU: a shell that runs `script`.
    fn shell(script: &str) -> Command {
        let mut command = Command::new("sh");
        command.args(["-c", script]);
        command
    }

    /// Whether a process with this id exists.
    fn is_running(pid: &str) -> bool {
        Path::new("/proc").join(pid).exists()
    }

    #[test]
    fn a_guest_that_ends_by_itself_has_exited_and_its_output_is_captured() {
        let (serial, exited) = run_guest(
            shell("printf 'one\\r\\ntwo\\r\\n'"),
            Duration::from_secs(30),
        )
        .unwrap();

        assert!(exited);
        assert_eq!(serial, "one\ntwo\n");
    }

    #[test]
    fn a_guest_that_runs_past_the_timeout_is_killed_and_has_not_exited() {
        let started = Instant::now();

        let (serial, exited) = run_guest(
            shell("echo $$; echo started; exec sleep 600"),
            Duration::from_millis(500),
        )
        .unwrap();

        assert!(!exited);
        assert!(started.elapsed() < Duration::from_secs(30));
        let (pid, rest) = serial.split_once('\n').unwrap();
        assert_eq!(rest, "started\n");
        assert!(!is_running(pid), "process {pid} was left running");
    }

    #[test]
    fn a_guest_whose_kernel_has_halted_is_stopped_without_waiting_for_the_timeout() {
        let started = Instant::now();

        let (serial, exited) = run_guest(
            shell("echo $$; echo 'Reboot failed -- System halted'; exec sleep 600"),
            Duration::from_secs(600),
        )
        .unwrap();

        assert!(!exited);
        assert!(started.elapsed() < Duration::from_secs(30));
        let (pid, rest) = serial.split_once('\n').unwrap();
        assert_eq!(rest, "Reboot failed -- System halted\n");
        assert!(!is_running(pid), "process {pid} was left running");
    }

    #[test]
    fn a_guest_that_fails_is_an_error_that_shows_what_it_said() {
        let e = run_guest(
            shell("echo 'could not open the image' >&2; exit 1"),
            Duration::from_secs(30),
        )
        .unwrap_err();

        let e = format!("{e:#}");
        assert!(e.contains("could not open the image"), "{e}");
    }

    #[test]
    fn a_guest_that_writes_more_than_a_pipe_holds_is_read_to_its_end() {
        let (serial, exited) = run_guest(
            shell("head -c 300000 /dev/zero | tr '\\0' x; head -c 300000 /dev/zero >&2"),
            Duration::from_secs(30),
        )
        .unwrap();

        assert!(exited);
        assert_eq!(serial.len(), 300_000);
    }

    #[test]
    fn a_program_that_is_not_there_is_an_error_that_names_it() {
        let e = run_guest(
            Command::new("/nonexistent/qemu-system-aarch64"),
            Duration::from_secs(1),
        )
        .unwrap_err();

        assert!(format!("{e:#}").contains("/nonexistent/qemu-system-aarch64"));
    }

    #[test]
    fn qemu_gets_the_build_the_card_and_nothing_of_this_machine() {
        let command = qemu_command(
            Path::new("/repo/out/qberrypi"),
            Path::new("/x/a,b.img"),
            KERNEL_ARGS,
        );

        assert_eq!(command.get_program(), OsStr::new("qemu-system-aarch64"));
        let args: Vec<&str> = command.get_args().map(|a| a.to_str().unwrap()).collect();
        assert_eq!(
            args,
            [
                "-M",
                "raspi3b",
                "-display",
                "none",
                "-no-reboot",
                "-serial",
                "stdio",
                "-monitor",
                "none",
                "-nic",
                "none",
                "-kernel",
                "/repo/out/qberrypi/kernel8.img",
                "-dtb",
                "/repo/out/qberrypi/bcm2710-rpi-3-b-plus.dtb",
                "-initrd",
                "/repo/out/qberrypi/initramfs8",
                "-append",
                "console=ttyAMA1,115200 panic=5 loglevel=7 qberrypi.selftest \
                 initcall_blacklist=bcm2835_wdt_driver_init",
                "-drive",
                "file=/x/a,,b.img,if=sd,format=raw",
            ]
        );
    }

    #[test]
    fn the_scenarios_differ_from_the_example_only_in_their_debug_settings() {
        let [one_shot, broken, permanent, no_console, watchdog] = scenarios(EXAMPLE).unwrap();

        assert_eq!(
            (one_shot.name, broken.name, permanent.name),
            ("one-shot", "broken config", "permanent")
        );
        assert_eq!(
            (no_console.name, watchdog.name),
            ("no console", "watchdog resets on arming")
        );
        assert_eq!(no_console.system_config, one_shot.system_config);
        assert_eq!(watchdog.system_config, one_shot.system_config);
        let changed = |text: &str| -> Vec<String> {
            let lines = text.lines().zip(EXAMPLE.lines());
            lines
                .filter(|(new, old)| new != old)
                .map(|(new, _)| new.split('#').next().unwrap().trim().to_owned())
                .collect()
        };
        assert_eq!(
            changed(&one_shot.system_config),
            [
                "one_shot = true",
                "log_to_sd = true",
                "return_after_secs = 5"
            ]
        );
        assert_eq!(changed(&permanent.system_config), ["return_after_secs = 5"]);
        assert_eq!(broken.system_config, "this is not toml");
        assert!(one_shot.system_config.contains(PASSPHRASE));
    }

    #[test]
    fn a_scenario_on_another_machine_than_the_usual_one_says_so() {
        let scenarios = scenarios(EXAMPLE).unwrap();

        let machines: Vec<Machine> = scenarios.iter().map(|s| s.machine).collect();
        assert_eq!(
            machines,
            [
                Machine::Usual,
                Machine::Usual,
                Machine::Usual,
                Machine::NoConsole,
                Machine::WithWatchdog
            ]
        );
        for scenario in &scenarios {
            assert_eq!(
                scenario.note.is_some(),
                scenario.machine != Machine::Usual,
                "{}",
                scenario.name
            );
        }
        let stems: Vec<&str> = scenarios.iter().map(|s| s.file_stem).collect();
        assert_eq!(
            stems,
            [
                "one-shot",
                "broken-config",
                "permanent",
                "no-console",
                "watchdog-resets-on-arming"
            ]
        );
    }

    #[test]
    fn the_boot_with_the_watchdog_differs_only_in_keeping_its_driver() {
        let usual: Vec<&str> = KERNEL_ARGS.split(' ').collect();
        let with_watchdog: Vec<&str> = KERNEL_ARGS_WITH_WATCHDOG.split(' ').collect();

        let kept: Vec<&str> = usual
            .iter()
            .copied()
            .filter(|arg| !arg.starts_with("initcall_blacklist="))
            .collect();
        assert_eq!(with_watchdog, kept);
        assert_eq!(usual.len(), kept.len() + 1);
        assert!(!KERNEL_ARGS_WITH_WATCHDOG.contains("blacklist"));
    }

    /// What the boot with the watchdog driver leaves behind when it went well, in QEMU.
    fn good_watchdog_evidence() -> Evidence {
        Evidence {
            serial: format!(
                "[    1.6] Run /init as init process\n\
                 [   0.001] INFO  qberrypi {} (build 1700000000)\n\
                 [   0.008] INFO  clock: set to the build time\n\
                 [   0.050] INFO  config.txt: Restored\n",
                qberrypi::VERSION
            ),
            exited: true,
            system_log: Err("cannot read qberrypi/log.txt".into()),
            ..good_evidence()
        }
    }

    #[test]
    fn a_reset_on_arming_after_the_restore_fails_no_condition() {
        let conditions = watchdog_conditions(&good_watchdog_evidence());

        assert_eq!(failures(&conditions), [""; 0]);
        assert_eq!(conditions.len(), 4);
        // Here QEMU does end by itself, so nothing is left unchecked.
        assert!(
            conditions
                .iter()
                .all(|condition| condition.verdict == Verdict::Holds)
        );
    }

    #[test]
    fn a_reset_on_arming_before_the_restore_leaves_the_card_starting_qberrypi() {
        // The watchdog opened before the configuration was read: the reset comes first.
        let mut evidence = good_watchdog_evidence();
        evidence.serial = evidence
            .serial
            .replace("[   0.050] INFO  config.txt: Restored\n", "");
        evidence.active_config = Ok(CONFIG_TXT.as_bytes().to_vec());

        let conditions = watchdog_conditions(&evidence);

        assert_eq!(
            failures(&conditions),
            [
                "the serial console has `INFO  config.txt: Restored`",
                "config.txt on the card equals config.pios.txt",
            ]
        );
    }

    #[test]
    fn a_boot_that_got_past_the_arming_is_not_the_watchdog_scenario() {
        let mut evidence = good_watchdog_evidence();
        evidence
            .serial
            .push_str("[   0.170] INFO  modules: inserted rfkill, cfg80211\n");

        let conditions = watchdog_conditions(&evidence);

        assert_eq!(
            failures(&conditions),
            ["the serial console does not have `INFO  modules: inserted`"]
        );
    }

    #[test]
    fn a_boot_with_the_watchdog_that_had_to_be_stopped_fails() {
        let mut evidence = good_watchdog_evidence();
        evidence.exited = false;

        let conditions = watchdog_conditions(&evidence);

        assert_eq!(
            failures(&conditions),
            ["QEMU exited by itself: the machine was reset"]
        );
    }

    #[test]
    fn the_boot_without_a_console_names_a_serial_port_that_is_not_there() {
        let with: Vec<&str> = KERNEL_ARGS.split(' ').collect();
        let without: Vec<&str> = KERNEL_ARGS_NO_CONSOLE.split(' ').collect();

        // The one port the guest has is ttyAMA1; an early console is not one init can open.
        assert!(with.contains(&"console=ttyAMA1,115200"));
        assert!(without.contains(&"console=ttyAMA0,115200"));
        assert!(without.contains(&"earlycon=pl011,0x3f201000"));
        // Everything else is the same in both.
        let rest = |args: &[&'static str]| -> Vec<&'static str> {
            let other = |arg: &&str| !arg.starts_with("console=") && !arg.starts_with("earlycon=");
            args.iter().copied().filter(other).collect()
        };
        assert_eq!(rest(&with), rest(&without));
    }

    /// What the boot without a console leaves behind when it went well, in QEMU.
    fn good_no_console_evidence() -> Evidence {
        Evidence {
            serial: "[    1.5] Warning: unable to open an initial console.\n\
                     [    1.6] Run /init as init process\n\
                     [   22.1] reboot: Restarting system\n\
                     [   22.2] Reboot failed -- System halted\n"
                .to_owned(),
            system_log: Ok(format!(
                "==== boot, build 1700000000 ====\n\
                 [   0.003] INFO  qberrypi {} (build 1700000000)\n\
                 [   0.005] WARN  /dev/console: No such device (os error 19)\n",
                qberrypi::VERSION
            )),
            ..good_evidence()
        }
    }

    #[test]
    fn a_good_boot_without_a_console_fails_no_condition() {
        let conditions = no_console_conditions(&good_no_console_evidence());

        assert_eq!(failures(&conditions), [""; 0]);
        assert_eq!(conditions.len(), 6);
    }

    #[test]
    fn a_boot_without_a_console_is_judged_by_the_card() {
        // Init died before it did anything: nothing restored, no log.
        let mut evidence = good_no_console_evidence();
        evidence.active_config = Ok(CONFIG_TXT.as_bytes().to_vec());
        evidence.system_log = Err("cannot read qberrypi/log.txt".into());
        evidence.serial = evidence.serial.replace("reboot: Restarting system\n", "");

        let conditions = no_console_conditions(&evidence);

        assert_eq!(
            failures(&conditions),
            [
                "the serial console has the kernel's `reboot: Restarting system`",
                "QEMU exited by itself: the guest restarted the machine",
                "config.txt on the card equals config.pios.txt",
                &format!(
                    "qberrypi/log.txt on the card has `qberrypi {} (build `",
                    qberrypi::VERSION
                ),
                "qberrypi/log.txt on the card does not have `example-passphrase`",
            ]
        );
    }

    #[test]
    fn a_boot_that_had_a_console_after_all_is_not_the_no_console_scenario() {
        let mut evidence = good_no_console_evidence();
        evidence.serial = good_serial();

        let conditions = no_console_conditions(&evidence);

        assert_eq!(
            failures(&conditions),
            ["the serial console has `Warning: unable to open an initial console.`"]
        );
    }

    #[test]
    fn an_example_without_the_settings_to_edit_is_refused() {
        let e = scenarios(&EXAMPLE.replace("one_shot = false", "one_shot = true"))
            .err()
            .unwrap();

        assert!(e.to_string().contains("one_shot = false"), "{e}");
    }

    /// The serial console of a one-shot boot that went well, in QEMU.
    fn good_serial() -> String {
        format!(
            "[    1.5] Run /init as init process\n\
             [   0.001] INFO  qberrypi {} (build 1700000000)\n\
             [   2.000] INFO  kernel: qberrypi-modhelper: net-pf-10: not in table\n\
             [  25.000] INFO  returning\n\
             [   27.1] reboot: Restarting system\n\
             [   27.2] Reboot failed -- System halted\n",
            qberrypi::VERSION
        )
    }

    /// What a one-shot boot that went well leaves behind, in QEMU.
    fn good_evidence() -> Evidence {
        Evidence {
            serial: good_serial(),
            exited: false,
            active_config: Ok(PIOS.as_bytes().to_vec()),
            system_log: Ok(
                "==== boot, build 1700000000 ====\n[  20.0] INFO  wlan0: absent\n\
                 [  20.1] INFO  kernel: Booting Linux\n"
                    .to_owned(),
            ),
            image_before: "aa".to_owned(),
            image_after: "bb".to_owned(),
        }
    }

    /// The conditions that fail, by what they are about.
    fn failures(conditions: &[Condition]) -> Vec<&str> {
        conditions
            .iter()
            .filter(|condition| matches!(condition.verdict, Verdict::Fails(_)))
            .map(|condition| condition.what.as_str())
            .collect()
    }

    #[test]
    fn a_good_one_shot_boot_fails_no_condition() {
        let conditions = one_shot_conditions(&good_evidence());

        assert_eq!(failures(&conditions), [""; 0]);
        assert_eq!(conditions.len(), 10);
    }

    #[test]
    fn each_thing_wrong_with_a_one_shot_boot_fails_its_condition() {
        /// What the failed condition is about, and what makes the evidence wrong.
        type Wrong = (&'static str, fn(&mut Evidence));
        let wrong: [Wrong; 9] = [
            ("has `qberrypi 0.", |e| {
                e.serial = e.serial.replace("INFO  qberrypi ", "INFO  qberrypi-")
            }),
            ("net-pf-10", |e| {
                e.serial = e.serial.replace("not in table", "loaded")
            }),
            ("Restarting system", |e| {
                e.serial = e.serial.replace("reboot: Restarting", "")
            }),
            ("config.txt", |e| {
                e.active_config = Ok(CONFIG_TXT.as_bytes().to_vec())
            }),
            ("has `==== boot`", |e| {
                e.system_log = Ok("wlan0: absent\nkernel: x\n".into())
            }),
            ("has `kernel: `", |e| {
                e.system_log = Ok("==== boot\nwlan0: absent\n".into())
            }),
            ("has `wlan0: absent`", |e| {
                e.system_log = Ok("==== boot\nkernel: x\nwlan0: present\n".into())
            }),
            (
                "log.txt on the card does not have `example-passphrase`",
                |e| e.system_log.as_mut().unwrap().push_str(PASSPHRASE),
            ),
            ("serial console does not have `example-passphrase`", |e| {
                e.serial.push_str(PASSPHRASE)
            }),
        ];
        for (about, spoil) in wrong {
            let mut evidence = good_evidence();
            spoil(&mut evidence);

            let conditions = one_shot_conditions(&evidence);

            let failed = failures(&conditions);
            assert!(
                failed.iter().any(|what| what.contains(about)),
                "{about}: {failed:?}"
            );
        }
    }

    #[test]
    fn a_log_that_cannot_be_read_fails_every_condition_about_it() {
        let mut evidence = good_evidence();
        evidence.system_log = Err("cannot read qberrypi/log.txt".into());

        let conditions = one_shot_conditions(&evidence);

        // Among them the one that the passphrase is not in it.
        assert_eq!(failures(&conditions).len(), 4);
    }

    #[test]
    fn a_guest_that_ends_qemu_by_restarting_has_exited() {
        let mut evidence = good_evidence();
        evidence.exited = true;

        assert_eq!(evidence.exited().verdict, Verdict::Holds);
    }

    #[test]
    fn a_guest_that_asked_for_the_restart_and_halted_is_reported_as_unchecked() {
        let verdict = good_evidence().exited().verdict;

        assert_eq!(verdict, Verdict::CannotBeCheckedInQemu(RESTART_UNCHECKED));
    }

    #[test]
    fn a_guest_that_never_asked_for_a_restart_has_not_exited() {
        let mut evidence = good_evidence();
        evidence.serial = "[   0.001] INFO  qberrypi 0.1.0 (build 1)\n".into();

        assert!(matches!(evidence.exited().verdict, Verdict::Fails(_)));
        assert!(matches!(
            evidence.restart_requested().verdict,
            Verdict::Fails(_)
        ));
    }

    #[test]
    fn a_broken_config_boot_must_restore_and_name_the_file_in_the_log() {
        let mut evidence = good_evidence();
        evidence.system_log = Ok("==== boot\nERROR qberrypi.toml: not valid\n".into());
        assert_eq!(failures(&broken_config_conditions(&evidence)), [""; 0]);

        evidence.system_log = Ok("==== boot\nERROR something else\n".into());
        evidence.active_config = Ok(CONFIG_TXT.as_bytes().to_vec());

        let conditions = broken_config_conditions(&evidence);
        assert_eq!(
            failures(&conditions),
            [
                "config.txt on the card equals config.pios.txt",
                "qberrypi/log.txt on the card has `qberrypi.toml`"
            ]
        );
    }

    #[test]
    fn a_permanent_boot_must_return_and_leave_the_image_as_it_was() {
        let mut evidence = good_evidence();
        evidence.image_after = evidence.image_before.clone();
        assert_eq!(failures(&permanent_conditions(&evidence)), [""; 0]);

        evidence.image_after = "cc".into();
        evidence.serial = evidence.serial.replace("INFO  returning", "");

        let conditions = permanent_conditions(&evidence);
        assert_eq!(
            failures(&conditions),
            [
                "the serial console has `INFO  returning`",
                "the card image has the SHA-256 it had before the boot"
            ]
        );
    }

    #[test]
    fn a_report_starts_with_the_name_and_ok_when_nothing_failed() {
        let conditions = one_shot_conditions(&good_evidence());

        let (report, held) =
            scenario_report("one-shot", None, &conditions, Duration::from_secs(42));

        assert!(held);
        let mut lines = report.lines();
        assert_eq!(
            lines.next().unwrap(),
            "one-shot: ok (42 s; 9 of 10 conditions hold, 1 cannot be checked in QEMU)"
        );
        let unchecked = lines.next().unwrap();
        assert!(
            unchecked.starts_with("  cannot be checked in QEMU: QEMU exited by itself"),
            "{unchecked}"
        );
        assert!(unchecked.contains("initcall_blacklist"), "{unchecked}");
        assert_eq!(lines.next(), None);
    }

    #[test]
    fn a_report_says_failed_and_names_each_failed_condition() {
        let mut evidence = good_evidence();
        evidence.exited = true;
        evidence.active_config = Ok(b"os_prefix=qberrypi/\n".to_vec());

        let conditions = one_shot_conditions(&evidence);
        let (report, held) = scenario_report("one-shot", None, &conditions, Duration::from_secs(7));

        assert!(!held);
        assert_eq!(
            report,
            "one-shot: FAILED (7 s; 9 of 10 conditions hold)\n  \
             FAILED: config.txt on the card equals config.pios.txt: \
             it is \"os_prefix=qberrypi/\\n\"\n"
        );
    }

    #[test]
    fn a_report_puts_the_scenarios_note_under_its_first_line() {
        let conditions = no_console_conditions(&good_no_console_evidence());

        let (report, held) = scenario_report(
            "no console",
            Some("judged by the card"),
            &conditions,
            Duration::from_secs(23),
        );

        assert!(held);
        let lines: Vec<&str> = report.lines().collect();
        assert_eq!(
            lines[0],
            "no console: ok (23 s; 5 of 6 conditions hold, 1 cannot be checked in QEMU)"
        );
        assert_eq!(lines[1], "  note: judged by the card.");
        assert!(lines[2].starts_with("  cannot be checked in QEMU: "));
        assert_eq!(lines.len(), 3);
    }

    #[test]
    fn the_last_lines_of_a_text_are_its_end() {
        assert_eq!(last_lines("a\nb\nc\n", 2), ["b", "c"]);
        assert_eq!(last_lines("a\nb\n", 40), ["a", "b"]);
        assert_eq!(last_lines("", 40), [""; 0]);
    }

    /// A boot folder with stand-ins for its files and checksums that match.
    fn boot_folder() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let files: [(&str, &[u8]); 3] = [
            (KERNEL, b"kernel"),
            (DEVICE_TREE, b"dtb"),
            (INITRAMFS, b"initramfs"),
        ];
        for (name, data) in files {
            fs::write(dir.path().join(name), data).unwrap();
        }
        fs::write(dir.path().join(CHECKSUMS), sha256sums(&files)).unwrap();
        dir
    }

    #[test]
    fn a_boot_folder_that_matches_its_checksums_is_accepted() {
        verify_boot_folder(boot_folder().path()).unwrap();
    }

    #[test]
    fn a_boot_folder_that_is_missing_or_stale_says_to_run_build() {
        /// What the error names, and what makes the folder wrong.
        type Spoil = (&'static str, fn(&Path));
        let spoils: [Spoil; 5] = [
            ("SHA256SUMS", |dir| {
                fs::remove_file(dir.join(CHECKSUMS)).unwrap()
            }),
            ("initramfs8", |dir| {
                fs::write(dir.join(INITRAMFS), "changed").unwrap()
            }),
            ("kernel8.img", |dir| {
                fs::remove_file(dir.join(KERNEL)).unwrap()
            }),
            ("bcm2710-rpi-3-b-plus.dtb", |dir| {
                let sums = sha256sums(&[(KERNEL, b"kernel"), (INITRAMFS, b"initramfs")]);
                fs::write(dir.join(CHECKSUMS), sums).unwrap()
            }),
            ("SHA256SUMS", |dir| {
                fs::write(dir.join(CHECKSUMS), "not checksums\n").unwrap()
            }),
        ];
        for (names, spoil) in spoils {
            let dir = boot_folder();
            spoil(dir.path());

            let e = verify_boot_folder(dir.path()).unwrap_err();

            let e = format!("{e:#}");
            assert!(e.contains(names), "{e}");
            assert!(e.contains("cargo xtask build"), "{e}");
        }
    }

    #[test]
    fn a_machine_without_qemu_is_told_how_to_install_it() {
        let e = require_qemu("qemu-system-that-is-not-installed").unwrap_err();

        let e = e.to_string();
        assert!(e.contains("not installed"), "{e}");
        assert!(e.contains("sudo pacman -S qemu-system-aarch64"), "{e}");
    }

    #[test]
    fn a_missing_boot_folder_says_to_run_build() {
        let dir = tempfile::tempdir().unwrap();

        let e = verify_boot_folder(&dir.path().join("out/qberrypi")).unwrap_err();

        assert!(format!("{e:#}").contains("cargo xtask build"), "{e:#}");
    }
}
