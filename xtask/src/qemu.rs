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

use qberrypi::bootpart;

use crate::build::{CMDLINE_TXT, CONFIG_TXT, read_build_epoch};
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
///   watchdog is armed, which init does once the one-shot restore is done
///   and before everything else this test looks at. See `RESTART_UNCHECKED`
///   for what that costs.
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

/// What the boot with the shipped command line adds to `cmdline.txt`, because QEMU needs it.
///
/// - the blacklist, as in `KERNEL_ARGS`;
/// - `earlycon=pl011,0x3f201000 keep_bootcon`: the shipped console is the
///   display, which this test does not have. The kernel's early console on
///   the serial port, kept on once the real console is there, shows the
///   restart request, which is how the end of the boot is seen.
const QEMU_NEEDS: &str =
    "initcall_blacklist=bcm2835_wdt_driver_init earlycon=pl011,0x3f201000 keep_bootcon";

/// How long one boot may take. The guest is emulated, not virtualised, so it is slow.
const BOOT_TIMEOUT: Duration = Duration::from_secs(300);
/// How often a running guest is looked at.
const POLL_EVERY: Duration = Duration::from_millis(100);

/// What the kernel prints when it is asked to restart the machine, at any log level.
const RESTART_REQUESTED: &str = "reboot: Restarting system";
/// How long a guest that was asked to restart is given to do it. At the
/// shipped log level the kernel does not print `GUEST_HALTED`.
const RESTART_GRACE: Duration = Duration::from_secs(3);
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

/// Printed with the scenario that boots with the shipped command line.
const SHIPPED_CONSOLE_UNSEEN: &str = "this boot has the kernel arguments of cmdline.txt, and \
    with them only the watchdog blacklist and the kernel's early console, which QEMU needs. \
    Init's console is tty1, the display, which this test cannot see; what init did is judged \
    from the card alone";

/// Why a guest that restarts does not end QEMU here, printed with every scenario it applies to.
const RESTART_UNCHECKED: &str = "QEMU's raspi3b resets the machine the moment the watchdog is \
    armed, so this test boots with the board's watchdog driver left out \
    (initcall_blacklist=bcm2835_wdt_driver_init). That driver is also what restarts the board: \
    without it the kernel takes the restart request and halts, and QEMU does not exit. On the \
    Pi the driver is there";

/// A `config.txt` that starts Raspberry Pi OS, which every image holds as `config.pios.txt`.
///
/// Made up for this test, and as long as the one a stock install has, which
/// is several times as long as qberrypi's own. The restore then has to make
/// `config.txt` grow on the card, as it has to on the Pi.
const PIOS: &str = "\
# A stand-in for the config.txt of Raspberry Pi OS, made up for qberrypi's
# tests: ordinary settings, each with a comment, as a stock install has them.

# Optional hardware interfaces. Remove the # in front of one to turn it on.
#dtparam=i2c_arm=on
#dtparam=i2s=on
#dtparam=spi=on

# Sound through the board's own output.
dtparam=audio=on

# Load the overlays for whatever camera and display are found.
camera_auto_detect=1
display_auto_detect=1

# Load the initramfs that belongs to the kernel, if there is one.
auto_initramfs=1

# The graphics driver, and how many framebuffers it may have.
dtoverlay=vc4-kms-v3d
max_framebuffers=2

# Leave the setting up of the display to the kernel.
disable_fw_kms_setup=1

# Run the kernel and everything above it in 64-bit mode.
arm_64bit=1

# Draw to the very edge of the screen.
disable_overscan=1

# Run as fast as the firmware and the board allow.
arm_boost=1

# How much memory the graphics processor keeps for itself, in megabytes.
#gpu_mem=64

# Settings for a display that the automatic detection gets wrong.
#hdmi_force_hotplug=1
#hdmi_group=1
#hdmi_mode=16

# Turn the picture for a display that is mounted on its side.
#display_rotate=1

# The remote control receiver, and the pin it is wired to.
#dtoverlay=gpio-ir,gpio_pin=17

[cm4]
# On the compute module, the USB controller is off unless it is asked for.
otg_mode=1

[cm5]
dtoverlay=dwc2,dr_mode=host

[all]
# What the owner adds goes below this line.
enable_uart=0
";

// Where the files the scenarios look at are on the card.
const ACTIVE_CONFIG: &str = "config.txt";
const PIOS_CONFIG: &str = "config.pios.txt";
const SYSTEM_CONFIG: &str = "qberrypi/qberrypi.toml";
const SYSTEM_LOG: &str = "qberrypi/log.txt";

/// The template the scenarios make their `qberrypi.toml` from, under the repository root.
const EXAMPLE_CONFIG: &str = "qberrypi.example.toml";
/// The Wi-Fi passphrase of the template. No boot may show it anywhere.
const PASSPHRASE: &str = "example-passphrase";

// The warnings init logs in QEMU for what the machine there lacks. A
// scenario allows only those it can meet; any other warning fails it.
/// The watchdog driver is left out of the boot (`initcall_blacklist`), so there is no `/dev/watchdog`.
const NO_WATCHDOG: &str = "watchdog: No such file or directory (os error 2)";
/// QEMU has no LEDs: one of the board's two hangs off the firmware's GPIO
/// expander, which QEMU does not answer for, and the kernel's LED driver
/// then gives up on both.
const NO_LED: &str = "activity LED: No such file or directory (os error 2)";
/// The kernel was given a console that does not exist, in the scenario that is about that.
const NO_CONSOLE: &str = "/dev/console: No such device (os error 19)";
/// How the one error begins that a scenario expects: the configuration is not TOML.
const SYNTAX_ERROR: &str = "qberrypi.toml: (syntax): not valid TOML at line ";

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

/// Boots the build in `boot_folder` in QEMU from a card image.
///
/// Returns when QEMU ends, when the guest's kernel has halted or has not
/// restarted a few seconds after it was asked to, or after `timeout`,
/// whichever is first. QEMU is not left running in any case.
///
/// The serial console is also saved beside the image, under the image's
/// name with the ending `.log`, whether the boot ends well or in an error.
/// The log of an earlier boot from that image is removed first.
pub fn boot(boot_folder: &Path, image: &Path, timeout: Duration) -> Result<Outcome> {
    boot_with(boot_folder, image, KERNEL_ARGS, timeout)
}

/// Like `boot`, with the kernel arguments given.
fn boot_with(
    boot_folder: &Path,
    image: &Path,
    kernel_args: &str,
    timeout: Duration,
) -> Result<Outcome> {
    let command = qemu_command(boot_folder, image, kernel_args);
    let (serial, exited) = run_guest(command, timeout, Some(&serial_log_of(image)))?;
    Ok(Outcome {
        serial,
        exited,
        image: image.to_owned(),
    })
}

/// Where the serial console of a boot from an image is saved.
fn serial_log_of(image: &Path) -> PathBuf {
    image.with_extension("log")
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
/// The guest is killed once it has printed `GUEST_HALTED`, when
/// `RESTART_GRACE` has passed since it printed `RESTART_REQUESTED`, or when
/// `timeout` has passed. One that ends by itself with a failure is an error,
/// which shows what the program said for itself.
///
/// What the guest wrote is saved to `serial_log`, if one is given, however
/// the run ends. A file already there is removed before the guest starts,
/// so that a log never belongs to an earlier run.
fn run_guest(
    mut command: Command,
    timeout: Duration,
    serial_log: Option<&Path>,
) -> Result<(String, bool)> {
    if let Some(log) = serial_log {
        match fs::remove_file(log) {
            Err(error) if error.kind() != ErrorKind::NotFound => {
                return Err(error).with_context(|| format!("cannot remove {}", log.display()));
            }
            _ => {}
        }
    }
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
    let mut asked_to_restart_at = None;
    // How the wait ended: with the guest's exit status, with none because it
    // had to be stopped, or with the reason it could not be waited for.
    let ended = loop {
        match guest.0.try_wait() {
            Ok(Some(status)) => break Ok(Some(status)),
            Ok(None) => {}
            Err(error) => break Err(error),
        }
        let (halted, asked) = {
            let serial = lock(&serial);
            (
                contains(&serial, GUEST_HALTED.as_bytes()),
                contains(&serial, RESTART_REQUESTED.as_bytes()),
            )
        };
        if asked && asked_to_restart_at.is_none() {
            asked_to_restart_at = Some(Instant::now());
        }
        let did_not_restart =
            asked_to_restart_at.is_some_and(|at: Instant| at.elapsed() >= RESTART_GRACE);
        if halted || did_not_restart || started.elapsed() >= timeout {
            break Ok(None);
        }
        thread::sleep(POLL_EVERY);
    };
    // The readers end when the guest's side of the pipes is closed, so the guest goes first.
    drop(guest);
    let _ = serial_reader.join();
    let complaints = complaints_reader.join().unwrap_or_default();
    let serial = String::from_utf8_lossy(&lock(&serial)).replace('\r', "");

    // Saved before anything below can fail: a boot that went wrong is the one to read.
    if let Some(log) = serial_log {
        fs::write(log, &serial).with_context(|| format!("cannot write {}", log.display()))?;
    }
    let ended = ended.context("cannot wait for the guest")?;
    if let Some(status) = ended
        && !status.success()
    {
        bail!(
            "{program} failed ({status}):\n{}",
            String::from_utf8_lossy(&complaints)
        );
    }
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
    /// The kernel arguments of `cmdline.txt`, and `QEMU_NEEDS`. The console is the display.
    Shipped,
}

impl Machine {
    /// The kernel arguments that make the machine.
    fn kernel_args(self) -> String {
        match self {
            Self::Usual => KERNEL_ARGS.to_owned(),
            Self::NoConsole => KERNEL_ARGS_NO_CONSOLE.to_owned(),
            Self::WithWatchdog => KERNEL_ARGS_WITH_WATCHDOG.to_owned(),
            Self::Shipped => format!("{} {QEMU_NEEDS}", CMDLINE_TXT.trim()),
        }
    }
}

/// What init may complain of in a scenario without failing it.
struct Allowed {
    /// How the message of an expected ERROR line begins.
    errors: &'static [&'static str],
    /// How the message of an expected WARN line begins.
    warnings: &'static [&'static str],
}

impl Allowed {
    const NOTHING: Self = Self {
        errors: &[],
        warnings: &[],
    };
    /// What a boot that gets through all its steps meets in QEMU.
    const NO_WATCHDOG_NO_LED: Self = Self {
        errors: &[],
        warnings: &[NO_WATCHDOG, NO_LED],
    };
}

/// Picks out the lines init logged, each as its level and its message.
///
/// An init line is `[{seconds, to the millisecond}] {LEVEL} {message}`; the
/// kernel's own lines give microseconds. On the serial port a kernel line
/// can land in the middle of the stream, so an init line is looked for
/// anywhere in a line, and its message runs to the line's end.
fn init_lines(text: &str) -> Vec<(&str, &str)> {
    const LEVELS: [&str; 5] = ["ERROR", "WARN", "INFO", "DEBUG", "TRACE"];
    let mut lines = Vec::new();
    for line in text.lines() {
        let init_line = line.match_indices('[').find_map(|(open, _)| {
            let (stamp, rest) = line[open + 1..].split_once("] ")?;
            let (seconds, millis) = stamp.trim_start().split_once('.')?;
            let digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
            if !digits(seconds) || !digits(millis) || millis.len() != 3 {
                return None;
            }
            // The level is padded to five characters, and a space follows it.
            LEVELS.into_iter().find_map(|level| {
                let message = rest.strip_prefix(&format!("{level:<5} "))?;
                Some((level, message))
            })
        });
        lines.extend(init_line);
    }
    lines
}

/// The ERROR and WARN lines init logged that the scenario does not expect, as `LEVEL message`.
fn unexpected_complaints(text: &str, allowed: &Allowed) -> Vec<String> {
    init_lines(text)
        .into_iter()
        .filter(|(level, message)| {
            let expected = match *level {
                "ERROR" => allowed.errors,
                "WARN" => allowed.warnings,
                _ => return false,
            };
            !expected.iter().any(|start| message.starts_with(start))
        })
        .map(|(level, message)| format!("{level:<5} {message}"))
        .collect()
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
    /// The build time of the build that was booted.
    build_epoch: u64,
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

    /// The log is of one boot, however many times that boot saved it, and names this build.
    ///
    /// It is also what `cargo xtask deploy` goes by to tell that a log is of the run it started.
    fn log_is_of_one_boot_of_this_build(&self) -> Condition {
        let what = "qberrypi/log.txt on the card has one boot header, which names this build";
        match &self.system_log {
            Ok(log) => {
                let headers = log.lines().filter(|l| l.starts_with("==== boot")).count();
                let build = bootpart::last_boot_build(log);
                let holds = headers == 1 && build == Some(self.build_epoch);
                Condition::new(what, holds, || {
                    let named = build.map_or("no build".to_owned(), |b| format!("build {b}"));
                    format!(
                        "it has {headers}; the last names {named}, and this is build {}",
                        self.build_epoch
                    )
                })
            }
            Err(error) => Condition::new(what, false, || error.clone()),
        }
    }

    /// Init complained of nothing on the serial console but what the scenario expects.
    fn serial_has_no_unexpected_complaint(&self, allowed: &Allowed) -> Condition {
        Self::no_unexpected_complaint("on the serial console", &self.serial, allowed)
    }

    /// The same for the log on the card, for a boot whose console cannot be seen.
    fn log_has_no_unexpected_complaint(&self, allowed: &Allowed) -> Condition {
        let place = "in qberrypi/log.txt on the card";
        match &self.system_log {
            Ok(log) => Self::no_unexpected_complaint(place, log, allowed),
            Err(error) => Condition::new(Self::no_complaint(place), false, || error.clone()),
        }
    }

    fn no_complaint(place: &str) -> String {
        format!("init logged no ERROR and no unexpected WARN {place}")
    }

    fn no_unexpected_complaint(place: &str, text: &str, allowed: &Allowed) -> Condition {
        let unexpected = unexpected_complaints(text, allowed);
        Condition::new(Self::no_complaint(place), unexpected.is_empty(), || {
            format!("it logged `{}`", unexpected.join("`, `"))
        })
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
        evidence.serial_has("INFO  modules: inserted rfkill, cfg80211, brcmutil, brcmfmac"),
        evidence.serial_has("INFO  returning"),
        evidence.restart_requested(),
        evidence.exited(),
        evidence.pios_config_is_active(),
        evidence.log_has("==== boot"),
        // Saved three times: with the restore, with the kernel's log, at the return.
        evidence.log_is_of_one_boot_of_this_build(),
        evidence.log_has(&banner_start()),
        evidence.log_has("INFO  config.txt: Restored"),
        evidence.log_has("kernel: "),
        evidence.log_has("wlan0: absent"),
        evidence.log_lacks(PASSPHRASE),
        evidence.serial_lacks(PASSPHRASE),
        evidence.serial_has_no_unexpected_complaint(&Allowed::NO_WATCHDOG_NO_LED),
    ]
}

fn broken_config_conditions(evidence: &Evidence) -> Vec<Condition> {
    // The boot ends in step 3, before the watchdog and the LED are reached.
    let allowed = Allowed {
        errors: &[SYNTAX_ERROR],
        warnings: &[],
    };
    vec![
        evidence.restart_requested(),
        evidence.exited(),
        evidence.pios_config_is_active(),
        evidence.log_has("qberrypi.toml"),
        evidence.log_is_of_one_boot_of_this_build(),
        // The card's configuration breaks on the line that holds the passphrase.
        evidence.log_lacks(PASSPHRASE),
        evidence.serial_lacks(PASSPHRASE),
        evidence.serial_has_no_unexpected_complaint(&allowed),
    ]
}

fn no_console_conditions(evidence: &Evidence) -> Vec<Condition> {
    let allowed = Allowed {
        errors: &[],
        warnings: &[NO_CONSOLE, NO_WATCHDOG, NO_LED],
    };
    vec![
        // What the scenario is about: without this it would be one-shot over again.
        evidence.serial_has(NO_INITIAL_CONSOLE),
        evidence.restart_requested(),
        evidence.exited(),
        evidence.pios_config_is_active(),
        evidence.log_has(&banner_start()),
        evidence.log_has("INFO  returning"),
        evidence.log_is_of_one_boot_of_this_build(),
        evidence.log_lacks(PASSPHRASE),
        evidence.log_has_no_unexpected_complaint(&allowed),
    ]
}

fn shipped_conditions(evidence: &Evidence) -> Vec<Condition> {
    vec![
        evidence.restart_requested(),
        // The shipped console is one the kernel can open for init.
        evidence.serial_lacks(NO_INITIAL_CONSOLE),
        evidence.pios_config_is_active(),
        evidence.log_has(&banner_start()),
        evidence.log_has("INFO  returning"),
        evidence.log_is_of_one_boot_of_this_build(),
        evidence.log_lacks(PASSPHRASE),
        evidence.log_has_no_unexpected_complaint(&Allowed::NO_WATCHDOG_NO_LED),
    ]
}

fn watchdog_conditions(evidence: &Evidence) -> Vec<Condition> {
    vec![
        evidence.serial_has("INFO  config.txt: Restored"),
        // What the scenario is about: the reset came where init arms the
        // watchdog, before the step after it. If init gets further, QEMU's
        // model has changed, and `exited` can be checked in every scenario.
        evidence.serial_lacks("INFO  modules: inserted"),
        // Nor was it init giving up, or being killed, that reset the machine.
        evidence.serial_lacks(RESTART_REQUESTED),
        evidence.serial_lacks("Kernel panic"),
        evidence.machine_was_reset(),
        evidence.pios_config_is_active(),
        // The log was saved with the restore, so the reset did not take it:
        // a boot that dies as soon as the watchdog runs, or in a driver, can
        // still be read afterwards.
        evidence.log_has(&banner_start()),
        evidence.log_has("INFO  config.txt: Restored"),
        evidence.log_is_of_one_boot_of_this_build(),
        evidence.log_lacks(PASSPHRASE),
        evidence.serial_has_no_unexpected_complaint(&Allowed::NOTHING),
    ]
}

fn permanent_conditions(evidence: &Evidence) -> Vec<Condition> {
    vec![
        // Without this the two below would hold for a guest that never started init.
        evidence.serial_has("INFO  returning"),
        evidence.restart_requested(),
        evidence.exited(),
        evidence.image_is_unchanged(),
        evidence.serial_has_no_unexpected_complaint(&Allowed::NO_WATCHDOG_NO_LED),
    ]
}

/// Makes the six scenarios from the text of `qberrypi.example.toml`.
fn scenarios(example: &str) -> Result<[Scenario; 6]> {
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
    // Without the quote that closes the passphrase: the file stops being
    // TOML on the very line that holds the secret, which no message may show.
    let closed = format!("\"{PASSPHRASE}\"");
    let broken = edited(example, &[(&closed, closed.trim_end_matches('"'))])?;

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
    match qberrypi::config::parse(&broken) {
        Err(error) if error.key == "(syntax)" => {}
        Err(error) => bail!("the broken configuration is refused for something else: {error}"),
        Ok(_) => bail!("the broken configuration is a valid one"),
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
            system_config: one_shot.clone(),
            conditions: watchdog_conditions,
        },
        Scenario {
            name: "shipped command line",
            machine: Machine::Shipped,
            note: Some(SHIPPED_CONSOLE_UNSEEN),
            file_stem: "shipped-command-line",
            system_config: one_shot,
            conditions: shipped_conditions,
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

/// Boots the six scenarios and prints how each went; an error if one did not hold.
///
/// `root` is the repository root. The build in its `out/qberrypi/` must be
/// complete, and is the one that is booted; the images and the serial logs
/// go to its `out/qemu/`.
pub fn run_all(root: &Path) -> Result<()> {
    require_qemu(QEMU)?;
    let build = Build {
        folder: root.join(BOOT_FOLDER),
        epoch: read_build_epoch(root)?,
    };
    verify_boot_folder(&build.folder)?;
    let example_path = root.join(EXAMPLE_CONFIG);
    let example = fs::read_to_string(&example_path)
        .with_context(|| format!("cannot read {}", example_path.display()))?;
    let scenarios = scenarios(&example)?;
    let folder = root.join(QEMU_FOLDER);
    fs::create_dir_all(&folder).with_context(|| format!("cannot create {}", folder.display()))?;

    let mut failed = Vec::new();
    for scenario in &scenarios {
        let started = Instant::now();
        let conditions = run_scenario(scenario, &build, &folder)
            .with_context(|| format!("{}: could not be run", scenario.name))?;
        let (report, held) =
            scenario_report(scenario.name, scenario.note, &conditions, started.elapsed());
        print!("{report}");
        if !held {
            let log = serial_log_of(&folder.join(scenario.file_stem).with_extension("img"));
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

/// The build the scenarios boot.
struct Build {
    /// Its boot folder.
    folder: PathBuf,
    /// The build time it was given, which the log of each of its boots names.
    epoch: u64,
}

/// Makes a scenario's card in `folder`, boots the build from it and judges the boot.
fn run_scenario(scenario: &Scenario, build: &Build, folder: &Path) -> Result<Vec<Condition>> {
    let image = folder.join(scenario.file_stem).with_extension("img");
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
        Machine::Usual => boot(&build.folder, &image, BOOT_TIMEOUT)?,
        other => boot_with(&build.folder, &image, &other.kernel_args(), BOOT_TIMEOUT)?,
    };

    let read =
        |name: &str| sdimage::read_file(&outcome.image, name).map_err(|error| format!("{error:#}"));
    let evidence = Evidence {
        active_config: read(ACTIVE_CONFIG),
        system_log: read(SYSTEM_LOG).map(|log| String::from_utf8_lossy(&log).into_owned()),
        image_after: file_sha256(&outcome.image)?,
        image_before,
        build_epoch: build.epoch,
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
    use crate::build::{CMDLINE_TXT, sha256sums};
    use qberrypi::bootpart::{Restore, restore_pios_config};
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
            None,
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
            None,
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
            None,
        )
        .unwrap();

        assert!(!exited);
        assert!(started.elapsed() < Duration::from_secs(30));
        let (pid, rest) = serial.split_once('\n').unwrap();
        assert_eq!(rest, "Reboot failed -- System halted\n");
        assert!(!is_running(pid), "process {pid} was left running");
    }

    #[test]
    fn a_guest_asked_to_restart_that_does_not_is_stopped_after_a_few_seconds() {
        // At the shipped log level the kernel does not say that it halted.
        let started = Instant::now();

        let (serial, exited) = run_guest(
            shell("echo $$; echo 'reboot: Restarting system'; exec sleep 600"),
            Duration::from_secs(600),
            None,
        )
        .unwrap();

        assert!(!exited);
        assert!(started.elapsed() >= RESTART_GRACE);
        assert!(started.elapsed() < Duration::from_secs(30));
        let (pid, rest) = serial.split_once('\n').unwrap();
        assert_eq!(rest, "reboot: Restarting system\n");
        assert!(!is_running(pid), "process {pid} was left running");
    }

    #[test]
    fn a_guest_asked_to_restart_that_does_has_exited() {
        let (_, exited) = run_guest(
            shell("echo 'reboot: Restarting system'; sleep 0.3"),
            Duration::from_secs(600),
            None,
        )
        .unwrap();

        assert!(exited);
    }

    #[test]
    fn a_guest_that_fails_is_an_error_that_shows_what_it_said() {
        let e = run_guest(
            shell("echo 'could not open the image' >&2; exit 1"),
            Duration::from_secs(30),
            None,
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
            None,
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
            None,
        )
        .unwrap_err();

        assert!(format!("{e:#}").contains("/nonexistent/qemu-system-aarch64"));
    }

    #[test]
    fn the_serial_log_of_a_boot_replaces_the_one_of_the_boot_before() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("scenario.log");
        fs::write(&log, "the boot before\n").unwrap();

        run_guest(
            shell("echo 'this boot'"),
            Duration::from_secs(30),
            Some(&log),
        )
        .unwrap();

        assert_eq!(fs::read_to_string(&log).unwrap(), "this boot\n");
    }

    #[test]
    fn the_serial_log_is_written_for_a_guest_that_fails_too() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("scenario.log");
        fs::write(&log, "the boot before\n").unwrap();

        run_guest(
            shell("echo 'got this far'; exit 1"),
            Duration::from_secs(30),
            Some(&log),
        )
        .unwrap_err();

        assert_eq!(fs::read_to_string(&log).unwrap(), "got this far\n");
    }

    #[test]
    fn a_guest_that_cannot_be_started_leaves_no_serial_log_of_the_boot_before() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("scenario.log");
        fs::write(&log, "the boot before\n").unwrap();

        run_guest(
            Command::new("/nonexistent/qemu-system-aarch64"),
            Duration::from_secs(1),
            Some(&log),
        )
        .unwrap_err();

        assert!(!log.exists());
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
    fn the_saved_configuration_is_as_long_as_a_stock_one_and_one_that_init_restores() {
        // Longer than qberrypi's own config.txt: the restore has to make the file grow.
        assert!(PIOS.len() > 1400, "{} bytes", PIOS.len());
        assert!(PIOS.len() > 4 * CONFIG_TXT.len());
        assert!(PIOS.is_ascii() && PIOS.ends_with('\n'));

        let card = tempfile::tempdir().unwrap();
        fs::write(card.path().join(ACTIVE_CONFIG), CONFIG_TXT).unwrap();
        fs::write(card.path().join(PIOS_CONFIG), PIOS).unwrap();
        assert_eq!(restore_pios_config(card.path()).unwrap(), Restore::Restored);
        assert_eq!(
            fs::read_to_string(card.path().join(ACTIVE_CONFIG)).unwrap(),
            PIOS
        );
    }

    /// The lines of a scenario's configuration that differ from the example's, without comments.
    fn changed(text: &str) -> Vec<String> {
        let lines = text.lines().zip(EXAMPLE.lines());
        lines
            .filter(|(new, old)| new != old)
            .map(|(new, _)| new.split('#').next().unwrap().trim().to_owned())
            .collect()
    }

    #[test]
    fn the_scenarios_differ_from_the_example_only_in_their_debug_settings() {
        let [one_shot, broken, permanent, no_console, watchdog, shipped] =
            scenarios(EXAMPLE).unwrap();

        assert_eq!(
            (one_shot.name, broken.name, permanent.name),
            ("one-shot", "broken config", "permanent")
        );
        assert_eq!(
            (no_console.name, watchdog.name, shipped.name),
            (
                "no console",
                "watchdog resets on arming",
                "shipped command line"
            )
        );
        assert_eq!(no_console.system_config, one_shot.system_config);
        assert_eq!(watchdog.system_config, one_shot.system_config);
        assert_eq!(shipped.system_config, one_shot.system_config);
        assert_eq!(
            changed(&one_shot.system_config),
            [
                "one_shot = true",
                "log_to_sd = true",
                "return_after_secs = 5"
            ]
        );
        assert_eq!(changed(&permanent.system_config), ["return_after_secs = 5"]);
        assert!(one_shot.system_config.contains(PASSPHRASE));
    }

    #[test]
    fn the_broken_configuration_breaks_on_the_line_that_holds_the_passphrase() {
        let [_, broken, ..] = scenarios(EXAMPLE).unwrap();

        // The example, but for the quote that closes the passphrase.
        assert_eq!(
            changed(&broken.system_config),
            ["passphrase = \"example-passphrase"]
        );
        assert_eq!(
            broken.system_config.len() + 1,
            EXAMPLE.len(),
            "one character is gone"
        );
        assert!(broken.system_config.contains(PASSPHRASE));
        let secret_line = broken
            .system_config
            .lines()
            .position(|line| line.contains(PASSPHRASE))
            .unwrap()
            + 1;
        let error = qberrypi::config::parse(&broken.system_config).unwrap_err();
        assert_eq!(error.key, "(syntax)");
        assert!(
            error
                .reason
                .contains(&format!("at line {secret_line}, column")),
            "{error}"
        );
        assert!(error.to_string().starts_with(SYNTAX_ERROR), "{error}");
        assert!(!error.to_string().contains(PASSPHRASE));
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
                Machine::WithWatchdog,
                Machine::Shipped
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
                "watchdog-resets-on-arming",
                "shipped-command-line"
            ]
        );
    }

    #[test]
    fn the_boot_with_the_watchdog_differs_only_in_keeping_its_driver() {
        let usual = Machine::Usual.kernel_args();
        let with_watchdog = Machine::WithWatchdog.kernel_args();
        let usual: Vec<&str> = usual.split(' ').collect();
        let with_watchdog: Vec<&str> = with_watchdog.split(' ').collect();

        let kept: Vec<&str> = usual
            .iter()
            .copied()
            .filter(|arg| !arg.starts_with("initcall_blacklist="))
            .collect();
        assert_eq!(with_watchdog, kept);
        assert_eq!(usual.len(), kept.len() + 1);
    }

    #[test]
    fn the_boot_without_a_console_names_a_serial_port_that_is_not_there() {
        let with = Machine::Usual.kernel_args();
        let without = Machine::NoConsole.kernel_args();
        let with: Vec<&str> = with.split(' ').collect();
        let without: Vec<&str> = without.split(' ').collect();

        // The one port the guest has is ttyAMA1; an early console is not one init can open.
        assert!(with.contains(&"console=ttyAMA1,115200"));
        assert!(without.contains(&"console=ttyAMA0,115200"));
        assert!(without.contains(&"earlycon=pl011,0x3f201000"));
        // Everything else is the same in both.
        let rest = |args: &[&str]| -> Vec<String> {
            args.iter()
                .filter(|arg| !arg.starts_with("console=") && !arg.starts_with("earlycon="))
                .map(|arg| arg.to_string())
                .collect()
        };
        assert_eq!(rest(&with), rest(&without));
    }

    #[test]
    fn the_shipped_command_line_is_cmdline_txt_and_only_what_qemu_needs() {
        let args = Machine::Shipped.kernel_args();

        assert_eq!(
            args,
            "console=tty1 panic=5 loglevel=4 \
             initcall_blacklist=bcm2835_wdt_driver_init earlycon=pl011,0x3f201000 keep_bootcon"
        );
        // Whatever cmdline.txt comes to hold, it goes first and whole.
        let shipped = CMDLINE_TXT.trim();
        assert_eq!(
            args.strip_prefix(shipped).unwrap(),
            format!(" {QEMU_NEEDS}")
        );
        assert!(!args.contains("qberrypi.selftest"));
    }

    #[test]
    fn the_lines_init_logged_are_told_from_the_kernels() {
        let text = "[    1.476157] reg-fixed-voltage cam1_regulator: error -EIO: can't get GPIO\n\
                    [   0.001] INFO  qberrypi 0.1.0 (build 1)\n\
                    [   0.009] WARN  watchdog: No such file or directory (os error 2)\n\
                    [  20.179] INFO  kernel: leds-gpio leds: probe failed with error -5\n\
                    [  12.345] ERROR loading brcmfmac: Exec format error\n\
                    [    1.5] Warning: unable to open an initial console.\n\
                    [    2.345678] ERROR is a word the kernel may begin a line with\n\
                    [12345.678] DEBUG late\n\
                    not a log line\n";

        assert_eq!(
            init_lines(text),
            [
                ("INFO", "qberrypi 0.1.0 (build 1)"),
                ("WARN", "watchdog: No such file or directory (os error 2)"),
                ("INFO", "kernel: leds-gpio leds: probe failed with error -5"),
                ("ERROR", "loading brcmfmac: Exec format error"),
                ("DEBUG", "late"),
            ]
        );
    }

    #[test]
    fn an_init_line_is_found_with_kernel_text_around_it() {
        // On the serial port a kernel line can land before an init line's newline.
        let text = "[   0.001] WARN  activity LED: No such file[    1.691794]  mmcblk0: p1\n\
                    [    1.7] usb 1-1: new device[   0.002] ERROR setting the hostname: denied\n";

        assert_eq!(
            init_lines(text),
            [
                (
                    "WARN",
                    "activity LED: No such file[    1.691794]  mmcblk0: p1"
                ),
                ("ERROR", "setting the hostname: denied"),
            ]
        );
    }

    #[test]
    fn only_complaints_that_are_not_expected_are_unexpected() {
        let allowed = Allowed {
            errors: &[SYNTAX_ERROR],
            warnings: &[NO_WATCHDOG, NO_LED],
        };
        let text = "[   0.009] WARN  watchdog: No such file or directory (os error 2)\n\
                    [   0.010] WARN  watchdog: the 15 s timeout was refused: Invalid argument\n\
                    [   0.020] ERROR qberrypi.toml: (syntax): not valid TOML at line 5, column 36\n\
                    [   0.021] ERROR qberrypi.toml: wifi.country: must be two letters\n\
                    [   0.182] WARN  activity LED: No such file or directory (os error 2)\n\
                    [   0.200] WARN  /dev/console: No such device (os error 19)\n\
                    [  20.179] INFO  kernel: ERROR and WARN  are only words here\n\
                    [  20.200] ERROR log.txt: No space left on device\n";

        assert_eq!(
            unexpected_complaints(text, &allowed),
            [
                "WARN  watchdog: the 15 s timeout was refused: Invalid argument",
                "ERROR qberrypi.toml: wifi.country: must be two letters",
                "WARN  /dev/console: No such device (os error 19)",
                "ERROR log.txt: No space left on device",
            ]
        );
        assert_eq!(unexpected_complaints("", &allowed), [""; 0]);
    }

    #[test]
    fn nothing_is_expected_unless_it_is_allowed() {
        let text = "[   0.009] WARN  watchdog: No such file or directory (os error 2)\n\
                    [   0.020] ERROR qberrypi.toml: (syntax): not valid TOML at line 5, column 36\n";

        assert_eq!(unexpected_complaints(text, &Allowed::NOTHING).len(), 2);
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
             [   0.050] INFO  config.txt: Restored\n\
             [   0.051] WARN  watchdog: No such file or directory (os error 2)\n\
             [   0.180] INFO  modules: inserted rfkill, cfg80211, brcmutil, brcmfmac\n\
             [   0.182] WARN  activity LED: No such file or directory (os error 2)\n\
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
            system_log: Ok(format!(
                "==== boot, build 1700000000 ====\n\
                 [   0.001] INFO  qberrypi {} (build 1700000000)\n\
                 [   0.050] INFO  config.txt: Restored\n\
                 [  20.000] INFO  wlan0: absent\n\
                 [  20.100] INFO  kernel: Booting Linux\n\
                 [  25.000] INFO  returning\n",
                qberrypi::VERSION
            )),
            image_before: "aa".to_owned(),
            image_after: "bb".to_owned(),
            build_epoch: 1_700_000_000,
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

    const NO_COMPLAINT_ON_SERIAL: &str =
        "init logged no ERROR and no unexpected WARN on the serial console";
    const NO_COMPLAINT_IN_LOG: &str =
        "init logged no ERROR and no unexpected WARN in qberrypi/log.txt on the card";
    const ONE_BOOT_OF_THIS_BUILD: &str =
        "qberrypi/log.txt on the card has one boot header, which names this build";

    #[test]
    fn a_good_one_shot_boot_fails_no_condition() {
        let conditions = one_shot_conditions(&good_evidence());

        assert_eq!(failures(&conditions), [""; 0]);
        assert_eq!(conditions.len(), 16);
    }

    #[test]
    fn each_thing_wrong_with_a_one_shot_boot_fails_its_condition() {
        /// What the failed condition is about, and what makes the evidence wrong.
        type Wrong = (&'static str, fn(&mut Evidence));
        let wrong: [Wrong; 20] = [
            ("has `qberrypi 0.", |e| {
                e.serial = e.serial.replace("INFO  qberrypi ", "INFO  qberrypi-")
            }),
            ("net-pf-10", |e| {
                e.serial = e.serial.replace("not in table", "loaded")
            }),
            (
                "has `INFO  modules: inserted rfkill, cfg80211, brcmutil, brcmfmac`",
                |e| e.serial = e.serial.replace("brcmutil, brcmfmac", "brcmutil"),
            ),
            ("has `INFO  returning`", |e| {
                e.serial = e.serial.replace("INFO  returning", "")
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
            // Each save of the boot wrote a header of its own.
            ("has one boot header", |e| {
                let log = e.system_log.as_mut().unwrap();
                *log = log.replace("[  25.", "==== boot, build 1700000000 ====\n[  25.");
            }),
            // The log on the card is one that an earlier build left.
            ("has one boot header", |e| {
                let log = e.system_log.as_mut().unwrap();
                *log = log.replace("==== boot, build 1700000000", "==== boot, build 1600000000");
            }),
            ("has one boot header", |e| {
                let log = e.system_log.as_mut().unwrap();
                *log = log.replace("==== boot, build 1700000000 ====\n", "");
            }),
            ("has one boot header", |e| e.build_epoch += 1),
            // Nothing was saved before the drivers were loaded.
            ("log.txt on the card has `qberrypi 0.", |e| {
                let log = e.system_log.as_mut().unwrap();
                *log = log.replace("INFO  qberrypi ", "INFO  qberrypi-");
            }),
            (
                "log.txt on the card has `INFO  config.txt: Restored`",
                |e| {
                    let log = e.system_log.as_mut().unwrap();
                    *log = log.replace("config.txt: Restored", "config.txt: AlreadyRestored");
                },
            ),
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
            // A boot that goes wrong after everything else was seen.
            (NO_COMPLAINT_ON_SERIAL, |e| {
                e.serial
                    .push_str("[  26.000] ERROR panic at init.rs:1:1: boom\n")
            }),
            (NO_COMPLAINT_ON_SERIAL, |e| {
                e.serial
                    .push_str("[  26.000] WARN  unmounting /dev/mmcblk0p1: busy\n")
            }),
            // No console is expected only where there is none.
            (NO_COMPLAINT_ON_SERIAL, |e| {
                e.serial
                    .push_str("[   0.002] WARN  /dev/console: No such device (os error 19)\n")
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
        assert_eq!(failures(&conditions).len(), 7);
    }

    #[test]
    fn a_log_of_one_boot_has_one_header_and_it_names_the_build_that_was_booted() {
        let header = "==== boot, build 1700000000 ====\n";
        let log_of = |text: String| Evidence {
            system_log: Ok(text),
            ..good_evidence()
        };
        let verdict = |text: String| log_of(text).log_is_of_one_boot_of_this_build().verdict;

        assert_eq!(verdict(format!("{header}a\nb\n")), Verdict::Holds);
        // One boot that reads as two, as when every save wrote a header.
        assert_eq!(
            verdict(format!("{header}a\n{header}b\n")),
            Verdict::Fails(
                "it has 2; the last names build 1700000000, and this is build 1700000000".into()
            )
        );
        assert_eq!(
            verdict("==== boot, build 1600000000 ====\na\n".into()),
            Verdict::Fails(
                "it has 1; the last names build 1600000000, and this is build 1700000000".into()
            )
        );
        assert_eq!(
            verdict("a\nb\n".into()),
            Verdict::Fails(
                "it has 0; the last names no build, and this is build 1700000000".into()
            )
        );
        let mut unread = good_evidence();
        unread.system_log = Err("cannot read qberrypi/log.txt".into());
        assert_eq!(
            unread.log_is_of_one_boot_of_this_build().verdict,
            Verdict::Fails("cannot read qberrypi/log.txt".into())
        );
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

    /// What the boot with the broken configuration leaves behind when it went well, in QEMU.
    fn good_broken_evidence() -> Evidence {
        let init = format!(
            "[   0.001] INFO  qberrypi {} (build 1700000000)\n\
             [   0.025] ERROR qberrypi.toml: (syntax): not valid TOML at line 5, column 36\n\
             [   0.041] INFO  config.txt: Restored\n",
            qberrypi::VERSION
        );
        Evidence {
            serial: format!(
                "[    1.5] Run /init as init process\n{init}\
                 [   11.8] reboot: Restarting system\n\
                 [   11.9] Reboot failed -- System halted\n"
            ),
            system_log: Ok(format!("==== boot, build 1700000000 ====\n{init}")),
            ..good_evidence()
        }
    }

    #[test]
    fn a_good_broken_config_boot_fails_no_condition() {
        let conditions = broken_config_conditions(&good_broken_evidence());

        assert_eq!(failures(&conditions), [""; 0]);
        assert_eq!(conditions.len(), 8);
    }

    #[test]
    fn a_broken_config_boot_must_restore_and_name_the_file_in_the_log() {
        let mut evidence = good_broken_evidence();
        evidence.system_log =
            Ok("==== boot, build 1700000000 ====\n[   0.025] ERROR something else\n".into());
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
    fn a_broken_config_boot_that_shows_the_offending_line_fails() {
        // An init that quoted the line it could not parse, on the console and in the log.
        let quoted = "[   0.025] ERROR qberrypi.toml: (syntax): not valid TOML at line 5: \
                      passphrase = \"example-passphrase   # or\n";
        let mut evidence = good_broken_evidence();
        evidence.serial.push_str(quoted);
        evidence.system_log.as_mut().unwrap().push_str(quoted);

        let conditions = broken_config_conditions(&evidence);

        assert_eq!(
            failures(&conditions),
            [
                "qberrypi/log.txt on the card does not have `example-passphrase`",
                "the serial console does not have `example-passphrase`",
            ]
        );
    }

    #[test]
    fn a_broken_config_boot_expects_its_one_error_and_no_other_complaint() {
        let mut evidence = good_broken_evidence();
        evidence
            .serial
            .push_str("[   0.050] ERROR log.txt: No space left on device\n");
        assert_eq!(
            failures(&broken_config_conditions(&evidence)),
            [NO_COMPLAINT_ON_SERIAL]
        );

        // It ends before the watchdog and the LED, so their warnings are not expected here.
        let mut evidence = good_broken_evidence();
        evidence
            .serial
            .push_str("[   0.050] WARN  watchdog: No such file or directory (os error 2)\n");
        assert_eq!(
            failures(&broken_config_conditions(&evidence)),
            [NO_COMPLAINT_ON_SERIAL]
        );
    }

    #[test]
    fn a_permanent_boot_must_return_and_leave_the_image_as_it_was() {
        let mut evidence = good_evidence();
        evidence.image_after = evidence.image_before.clone();
        let conditions = permanent_conditions(&evidence);
        assert_eq!(failures(&conditions), [""; 0]);
        assert_eq!(conditions.len(), 5);

        evidence.image_after = "cc".into();
        evidence.serial = evidence.serial.replace("INFO  returning", "");
        evidence
            .serial
            .push_str("[  26.000] ERROR log.txt: mounting /dev/mmcblk0p1: busy\n");

        let conditions = permanent_conditions(&evidence);
        assert_eq!(
            failures(&conditions),
            [
                "the serial console has `INFO  returning`",
                "the card image has the SHA-256 it had before the boot",
                NO_COMPLAINT_ON_SERIAL,
            ]
        );
    }

    /// What init logs in a one-shot boot without a console, as the card's log holds it.
    fn good_log_without_console() -> String {
        format!(
            "==== boot, build 1700000000 ====\n\
             [   0.003] INFO  qberrypi {} (build 1700000000)\n\
             [   0.005] WARN  /dev/console: No such device (os error 19)\n\
             [   0.050] INFO  config.txt: Restored\n\
             [   0.051] WARN  watchdog: No such file or directory (os error 2)\n\
             [   0.182] WARN  activity LED: No such file or directory (os error 2)\n\
             [  20.265] INFO  returning\n",
            qberrypi::VERSION
        )
    }

    /// What the boot without a console leaves behind when it went well, in QEMU.
    fn good_no_console_evidence() -> Evidence {
        Evidence {
            serial: "[    1.5] Warning: unable to open an initial console.\n\
                     [    1.6] Run /init as init process\n\
                     [   22.1] reboot: Restarting system\n\
                     [   22.2] Reboot failed -- System halted\n"
                .to_owned(),
            system_log: Ok(good_log_without_console()),
            ..good_evidence()
        }
    }

    #[test]
    fn a_good_boot_without_a_console_fails_no_condition() {
        let conditions = no_console_conditions(&good_no_console_evidence());

        assert_eq!(failures(&conditions), [""; 0]);
        assert_eq!(conditions.len(), 9);
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
                "qberrypi/log.txt on the card has `INFO  returning`",
                ONE_BOOT_OF_THIS_BUILD,
                "qberrypi/log.txt on the card does not have `example-passphrase`",
                NO_COMPLAINT_IN_LOG,
            ]
        );
    }

    #[test]
    fn an_init_that_takes_the_missing_console_for_fatal_fails() {
        // It restores and saves its log on the way out, as fatal does: only the log tells.
        let mut evidence = good_no_console_evidence();
        evidence.system_log = Ok(format!(
            "==== boot, build 1700000000 ====\n\
             [   0.003] INFO  qberrypi {} (build 1700000000)\n\
             [   0.005] ERROR /dev/console: No such device (os error 19)\n\
             [   0.050] INFO  config.txt: Restored\n",
            qberrypi::VERSION
        ));

        let conditions = no_console_conditions(&evidence);

        assert_eq!(
            failures(&conditions),
            [
                "qberrypi/log.txt on the card has `INFO  returning`",
                NO_COMPLAINT_IN_LOG,
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
            // Saved with the restore, before the watchdog was armed.
            system_log: Ok(format!(
                "==== boot, build 1700000000 ====\n\
                 [   0.001] INFO  qberrypi {} (build 1700000000)\n\
                 [   0.008] INFO  clock: set to the build time\n\
                 [   0.050] INFO  config.txt: Restored\n",
                qberrypi::VERSION
            )),
            ..good_evidence()
        }
    }

    #[test]
    fn a_reset_on_arming_after_the_restore_fails_no_condition() {
        let conditions = watchdog_conditions(&good_watchdog_evidence());

        assert_eq!(failures(&conditions), [""; 0]);
        assert_eq!(conditions.len(), 11);
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
        evidence.system_log = Err("cannot read qberrypi/log.txt".into());

        let conditions = watchdog_conditions(&evidence);

        assert_eq!(
            failures(&conditions),
            [
                "the serial console has `INFO  config.txt: Restored`",
                "config.txt on the card equals config.pios.txt",
                &format!(
                    "qberrypi/log.txt on the card has `qberrypi {} (build `",
                    qberrypi::VERSION
                ),
                "qberrypi/log.txt on the card has `INFO  config.txt: Restored`",
                ONE_BOOT_OF_THIS_BUILD,
                "qberrypi/log.txt on the card does not have `example-passphrase`",
            ]
        );
    }

    #[test]
    fn a_reset_on_arming_that_took_the_log_with_it_fails() {
        // The restore was done, but the log was to be saved only later: the
        // reset came first, and nothing of the boot can be read back.
        let mut evidence = good_watchdog_evidence();
        evidence.system_log = Err("cannot read qberrypi/log.txt".into());

        let conditions = watchdog_conditions(&evidence);

        assert_eq!(
            failures(&conditions),
            [
                &format!(
                    "qberrypi/log.txt on the card has `qberrypi {} (build `",
                    qberrypi::VERSION
                ),
                "qberrypi/log.txt on the card has `INFO  config.txt: Restored`",
                ONE_BOOT_OF_THIS_BUILD,
                "qberrypi/log.txt on the card does not have `example-passphrase`",
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
    fn an_init_that_dies_after_the_restore_is_not_a_reset_on_arming() {
        // A fatal error between the restore and the modules also ends in a reset here.
        let mut evidence = good_watchdog_evidence();
        evidence.serial.push_str(
            "[   0.060] ERROR setting the hostname: Operation not permitted\n\
             [    6.7] reboot: Restarting system\n",
        );
        assert_eq!(
            failures(&watchdog_conditions(&evidence)),
            [
                "the serial console does not have `reboot: Restarting system`",
                NO_COMPLAINT_ON_SERIAL,
            ]
        );

        // So does init being killed.
        let mut evidence = good_watchdog_evidence();
        evidence
            .serial
            .push_str("[    1.7] Kernel panic - not syncing: Attempted to kill init!\n");
        assert_eq!(
            failures(&watchdog_conditions(&evidence)),
            ["the serial console does not have `Kernel panic`"]
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

    /// What the boot with the shipped command line leaves behind when it went well, in QEMU.
    fn good_shipped_evidence() -> Evidence {
        Evidence {
            // The early console at the shipped log level: errors, and the restart.
            serial: "[    1.2] leds-gpio leds: probe with driver leds-gpio failed with error -5\n\
                     [   22.6] reboot: Restarting system\n"
                .to_owned(),
            system_log: Ok(good_log_without_console().replace(
                "[   0.005] WARN  /dev/console: No such device (os error 19)\n",
                "",
            )),
            ..good_evidence()
        }
    }

    #[test]
    fn a_good_boot_with_the_shipped_command_line_fails_no_condition() {
        let conditions = shipped_conditions(&good_shipped_evidence());

        assert_eq!(failures(&conditions), [""; 0]);
        assert_eq!(conditions.len(), 8);
        // It is judged from the card: nothing is left unchecked.
        assert!(
            conditions
                .iter()
                .all(|condition| condition.verdict == Verdict::Holds)
        );
    }

    #[test]
    fn the_shipped_console_must_be_one_init_can_open() {
        // The kernel says so on its early console, and init in its log.
        let mut evidence = good_shipped_evidence();
        evidence
            .serial
            .insert_str(0, "[    1.5] Warning: unable to open an initial console.\n");
        evidence.system_log = Ok(good_log_without_console());

        let conditions = shipped_conditions(&evidence);

        assert_eq!(
            failures(&conditions),
            [
                "the serial console does not have `Warning: unable to open an initial console.`",
                NO_COMPLAINT_IN_LOG,
            ]
        );
    }

    #[test]
    fn a_boot_with_the_shipped_command_line_is_judged_by_the_card() {
        let mut evidence = good_shipped_evidence();
        evidence.active_config = Ok(CONFIG_TXT.as_bytes().to_vec());
        evidence.system_log = Ok("==== boot, build 1700000000 ====\n".into());
        evidence.serial.clear();

        let conditions = shipped_conditions(&evidence);

        assert_eq!(
            failures(&conditions),
            [
                "the serial console has the kernel's `reboot: Restarting system`",
                "config.txt on the card equals config.pios.txt",
                &format!(
                    "qberrypi/log.txt on the card has `qberrypi {} (build `",
                    qberrypi::VERSION
                ),
                "qberrypi/log.txt on the card has `INFO  returning`",
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
            "one-shot: ok (42 s; 15 of 16 conditions hold, 1 cannot be checked in QEMU)"
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
        evidence
            .serial
            .push_str("[  26.000] ERROR log.txt: busy\n[  26.001] WARN  odd\n");

        let conditions = one_shot_conditions(&evidence);
        let (report, held) = scenario_report("one-shot", None, &conditions, Duration::from_secs(7));

        assert!(!held);
        assert_eq!(
            report,
            "one-shot: FAILED (7 s; 14 of 16 conditions hold)\n  \
             FAILED: config.txt on the card equals config.pios.txt: \
             it is \"os_prefix=qberrypi/\\n\"\n  \
             FAILED: init logged no ERROR and no unexpected WARN on the serial console: \
             it logged `ERROR log.txt: busy`, `WARN  odd`\n"
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
            "no console: ok (23 s; 8 of 9 conditions hold, 1 cannot be checked in QEMU)"
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
