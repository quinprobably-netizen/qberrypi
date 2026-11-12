//! What the executable does as PID 1: the boot sequence, and the way out when it fails.
//!
//! [`run`] is the sequence, one function per step. Whatever stops it goes
//! through `fatal`, which restarts the board. Any of init's threads may call
//! it: the first to do so carries the board out, and the others wait for it.
//! In one-shot mode, and whenever the configuration never got read, it first
//! puts Raspberry Pi OS's `config.txt` back, so a failure cannot leave the Pi
//! starting qberrypi over and over. It saves the log to the card then too, and
//! also on a permanent system that keeps its log there.
//!
//! A boot that keeps its log on the card saves it more than once: with the
//! first write to the card, before the watchdog runs or a driver is loaded,
//! again once the kernel's log has been copied, every 30 seconds while there is
//! anything new (not during a join), and at once on each join, and finally on
//! the way out. Each save adds only what is new, and only the first writes the
//! boot's header. Once the runtime runs, a save is a job of the pool, one at a
//! time and never waited for by the runtime's thread; only the way out saves on
//! the main thread, with the board about to restart.
//!
//! From step 10 on init runs one tokio runtime, on its main thread, and the
//! supervisor runs on it. Whatever the board does there waits on a timer or a
//! socket, so the tick that pets the watchdog is never held for long. The
//! components are the services (DNS, the zone's offset, the clock, status,
//! lists and, with an `[api]` section, the Pi-hole API on port 443:
//! `services::prepare` gives them, and the first of them to start makes
//! the state they share), the Wi-Fi with what follows a join, the front panel,
//! which blocks a thread of the pool for good, and, only when `debug.fault`
//! asks for one, a provoked failure; the supervisor starts them in that order,
//! starts a failed one again, and ends when the board has to restart. What else
//! must block runs on the pool of five threads, the log's saves to the card
//! among it, and a thread of it may fail as the main one may. The card is used
//! by one thread at a time (a claim on `BOARD`, which a fatal error's rescue goes by too); the
//! activity LED goes by the same board, so that nothing is written over what a fatal error
//! shows; the API adds no use of the card.

use std::cell::Cell;
use std::convert::Infallible;
use std::fs::File;
use std::future::Future;
use std::io::{self, Write};
use std::mem;
use std::net::{Ipv6Addr, UdpSocket};
use std::path::Path;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, TryLockError};
use std::thread::{self, ThreadId};
use std::time::{Duration, Instant};

use log::Level;
use tokio::sync::watch;

use crate::bootpart::{self, BOOT_DEV, MOUNT_POINT, Restore};
use crate::config::{self, Config, Fault};
use crate::cpu;
use crate::fault;
use crate::kmsg;
use crate::led::{self, LED_DIR, LedState};
use crate::logbuf::{self, LogBuf};
use crate::modules::{self, Insert, MODULE_LIST, ModuleTable};
use crate::net;
use crate::netlink::Route;
use crate::netlink::nl80211::Nl80211;
use crate::panel::{self, Deps, PanelEnd};
use crate::services::{self, Context};
use crate::supervisor::{self, Component, Ended, Hooks, Plan, Reason};
use crate::sys::{self, Watchdog};
use crate::wifi::kernel::KernelRadio;
use crate::wifi::{self, WifiStatus};
use crate::wiring::{SignalCache, Slot};
use crate::{BUILD_EPOCH, VERSION};

const CONSOLE: &str = "/dev/console";
const KERNEL_LOG: &str = "/dev/kmsg";
const SYSFS: &str = "/sys";
/// Where the initramfs has this executable, for the kernel to run as its module helper.
const MODULE_HELPER: &str = "/init";
/// The kernel argument that asks for a module request to be provoked.
const SELFTEST_ARG: &str = "qberrypi.selftest";
/// The Wi-Fi interface and the driver's vendor module, as `/sys` shows them.
const WLAN_IN_SYSFS: &str = "class/net/wlan0";
const CYW_IN_SYSFS: &str = "module/brcmfmac_cyw";
/// The CPU's frequency governor, relative to the sysfs root, and what it is set to.
const GOVERNOR_IN_SYSFS: &str = "devices/system/cpu/cpufreq/policy0/scaling_governor";
const GOVERNOR: &str = "performance";

/// How long the board may go without a pet before the watchdog restarts it.
const WATCHDOG_SECS: u32 = 15;
/// How often the watchdog is petted, at the least, while init waits.
const PET_EVERY: Duration = Duration::from_secs(5);
/// How many lines a long dump to the console logs between two pets.
const PET_EVERY_LINES: usize = 50;
/// How often a wait looks whether what it waits for has happened.
const POLL_EVERY: Duration = Duration::from_millis(50);
/// How long step 3 waits for the kernel to find the card.
///
/// Long, because giving up gains nothing: it is a fatal error whose way out
/// needs the card as well, and no watchdog runs yet that the wait could trip.
const BOOT_DEV_WAIT: Duration = Duration::from_secs(120);
/// How long a fatal error waits for the card before it restarts without it.
///
/// Bounded, so that a board with no card at all restarts and does not sit.
const RESCUE_DEV_WAIT: Duration = Duration::from_secs(30);
const WLAN_WAIT: Duration = Duration::from_secs(20);
/// How long the check of the regulatory domain waits for the configured country to apply.
const COUNTRY_WAIT: Duration = Duration::from_secs(5);
/// The Wi-Fi interface, as the kernel names it.
const WLAN: &str = "wlan0";
/// How long the address and the default route are given after a join.
///
/// The Wi-Fi component is waiting on netlink requests that can take up to 10 s each (a send
/// and a reply), three of them in a row. Their sends are made by a thread of the socket's own,
/// so the runtime's thread is not held, and the supervisor's tick pets the watchdog on its
/// own deadline either way. Ending the wait here keeps the join from sitting on a radio that
/// does not answer, and the wait itself under a pet's interval.
const CONFIGURE_WITHIN: Duration = Duration::from_secs(4);
/// How long after a save the tick saves the log again, if it holds lines not yet saved.
const LOG_SAVE_EVERY: Duration = Duration::from_secs(30);
/// How long the Wi-Fi waits to open its interface again after it could not.
const REOPEN_EVERY: Duration = Duration::from_secs(30);
/// The kernel's protocol counters, for the line about echo requests.
const SNMP: &str = "/proc/net/snmp";
/// What `brcmfmac` is loaded with: the firmware does not roam on its own.
const BRCMFMAC_PARAMS: &str = "roamoff=1";
/// How long a fatal message stays on the console before the restart.
const FATAL_PAUSE: Duration = Duration::from_secs(5);
/// How long `fatal` waits for the log's lock before it takes the lock to be stuck.
///
/// A thread that logs holds the lock for the length of one line, which on a
/// slow console is a few milliseconds; a lock held much longer than this is
/// held by whatever failed.
const LOG_LOCK_WAIT: Duration = Duration::from_millis(200);
/// How often a wait for a lock looks whether it has been let go of.
const LOCK_POLL: Duration = Duration::from_millis(5);

/// How long a claim on the card waits for another thread that has it before it gives up.
///
/// A save or a rescue mounts, writes, syncs and unmounts: a few seconds on a slow card. When the
/// wait runs out the fatal error's own thread goes on without the claim; every other thread
/// gives up.
const CARD_LOCK_WAIT: Duration = Duration::from_secs(5);

/// The log, from step 1 on. `fatal` saves it to the card.
static LOG: OnceLock<&'static Mutex<LogBuf>> = OnceLock::new();
/// The configuration, from step 3 on. `fatal` asks it whether to restore.
static CONFIG: OnceLock<Config> = OnceLock::new();
/// The TLS key and certificate that the card holds as `qberrypi/tls.pem`, from step 3 on: `None`
/// if there is no such file or it could not be read. It is the API's, and holds a secret.
static TLS_PEM: OnceLock<Option<Vec<u8>>> = OnceLock::new();
/// Who has the card and whose fatal error has begun, so that two threads never mount and unmount
/// the card under each other (the log's saves, the way out and a rescue on another thread) and
/// the LED shows what a fatal error put there. Held only for a change of that state and for the
/// LED's write, never across a use of the card.
static BOARD: Mutex<Board> = Mutex::new(Board::new());
/// The watchdog; a stand-in that does nothing until step 5 opens the real one.
static WATCHDOG: Mutex<Watchdog> = Mutex::new(Watchdog::absent());
/// The thread whose fatal error began first, once there is one.
///
/// Its failing again ends at once; another thread's fatal error waits for it;
/// and from then on only it pets the watchdog.
///
/// `BOARD` records the same thread, set in the same critical section; this one is for the readers
/// that must not wait for the board's mutex (`may_pet`).
static FATAL_THREAD: OnceLock<ThreadId> = OnceLock::new();

/// What the card and the LED go by, behind the mutex of `BOARD`.
///
/// The mutex makes each question and its answer one step: a thread that asks for the card is
/// refused or has it in the same critical section, and the LED is written, or not, in the same
/// critical section as the look at `fatal`.
struct Board {
    /// The thread that has claimed the card, if one has (`claim_card`).
    card: Option<ThreadId>,
    /// The thread whose fatal error began first, if one has (`begin_fatal`).
    fatal: Option<ThreadId>,
}

impl Board {
    /// A board that nobody has claimed the card of and that no fatal error has begun on.
    const fn new() -> Self {
        Self {
            card: None,
            fatal: None,
        }
    }
}

/// The thread whose fatal error began first, if one has, as `FATAL_THREAD` records it.
fn first_fatal() -> Option<ThreadId> {
    FATAL_THREAD.get().copied()
}

/// The first line of the log: which qberrypi this is.
pub fn banner() -> String {
    format!("qberrypi {VERSION} (build {BUILD_EPOCH})")
}

/// Whether a fatal error puts Raspberry Pi OS's `config.txt` back before the restart.
///
/// True in one-shot mode, and when the configuration never got read: a bad
/// file must not strand the Pi in qberrypi.
pub fn restore_on_fatal(cfg: Option<&Config>) -> bool {
    cfg.is_none_or(|cfg| cfg.debug.one_shot)
}

/// Boots the system and keeps it running. Only PID 1 may call this.
pub fn run() -> ! {
    let kernel_uptime = sys::uptime();
    let started = Instant::now();
    install_panic_hook();
    let log = start_logging(kernel_uptime); // 1
    raise_open_files(); // 1, once the log exists
    keep_clock_after_build(); // 2
    let cfg = read_config(); // 3
    restore_and_save_log(cfg, &mut SdCard, log); // 4
    open_watchdog(); // 5
    load_wifi_driver(cfg); // 6
    set_cpu_governor(); // 6, once the driver is in and before Wi-Fi starts
    show_joining(); // 7
    provoke_module_request(); // 7, under the self-test only
    let (kernel_log, wlan_present) = report_wifi(); // 8
    save_log_if_asked(cfg, &mut SdCard, log); // 9
    let runtime = start_runtime(cfg); // 10
    runtime.block_on(serve(cfg, log, started, kernel_log, wlan_present))
}

/// Step 1: mounts the kernel's filesystems and starts the log on the console.
///
/// The log opens with the banner and how long the kernel had run before init did.
fn start_logging(kernel_uptime: Duration) -> &'static Mutex<LogBuf> {
    let mounted = sys::mount_pseudo();
    let (console, console_error): (Box<dyn Write + Send>, _) =
        match File::options().write(true).open(CONSOLE) {
            Ok(console) => (Box::new(console), None),
            // Without a console the log still fills, for the card.
            Err(error) => (Box::new(io::sink()), Some(error)),
        };
    let log = *LOG.get_or_init(|| logbuf::install(console));
    log::info!("{}", banner());
    log::info!("{}", boot_line(kernel_uptime));
    if let Some(error) = console_error {
        log::warn!("{CONSOLE}: {error}");
    }
    if let Err(error) = mounted {
        fatal(&error.to_string());
    }
    log
}

/// The line that says how long the kernel had run before init started, to the millisecond.
fn boot_line(kernel_uptime: Duration) -> String {
    format!(
        "boot: init started {}.{:03} s after the kernel",
        kernel_uptime.as_secs(),
        kernel_uptime.subsec_millis()
    )
}

/// Step 1, once the log exists: raises the soft limit on open files to the hard one.
///
/// The kernel starts init at 1024, and the DNS service may hold more sockets than that while
/// it forwards a flood of questions. A failure is a warning: the limit stays as it was.
fn raise_open_files() {
    let (level, line) = open_files_report(&sys::raise_open_files().map_err(|e| e.to_string()));
    log::log!(level, "{line}");
}

/// The level and the line that the soft limit on open files, or why it was not raised, is
/// logged with.
fn open_files_report(raised: &Result<u64, String>) -> (Level, String) {
    match raised {
        Ok(limit) => (Level::Info, format!("init: open files: up to {limit}")),
        Err(error) => (
            Level::Warn,
            format!("init: open files: the limit could not be raised: {error}"),
        ),
    }
}

/// Step 2: makes sure the clock does not show a time before this build.
fn keep_clock_after_build() {
    match sys::clock_at_least(BUILD_EPOCH) {
        Ok(true) => log::info!("clock: set to the build time"),
        Ok(false) => {}
        Err(error) => fatal(&format!("setting the clock: {error}")),
    }
}

/// Step 3: waits for the card and reads the configuration from it, and the API's TLS file beside it.
fn read_config() -> &'static Config {
    if !wait_for_card(&SdCard, BOOT_DEV_WAIT, &mut pet_watchdog) {
        fatal(&format!("boot partition {BOOT_DEV} did not appear"));
    }
    match load_config(&mut SdCard) {
        Ok(cfg) => CONFIG.get_or_init(|| cfg),
        Err(message) => fatal(&message),
    }
}

/// Reads and checks `qberrypi.toml`, and keeps the TLS file that is beside it. The error is the
/// fatal message.
fn load_config(card: &mut dyn Card) -> Result<Config, String> {
    load_config_into(card, &TLS_PEM)
}

/// `load_config`, with the place that keeps the TLS file in the caller's hands.
///
/// Both files are read in the one read-only mount. The TLS file is kept whether or not the
/// configuration has an `[api]` section: what to do with it is the API's to decide. One that
/// cannot be read is logged, without a byte of it, and kept as none; the configuration still
/// loads, because the API is not what the system is for. A configuration that does not load
/// keeps nothing.
fn load_config_into(
    card: &mut dyn Card,
    tls: &OnceLock<Option<Vec<u8>>>,
) -> Result<Config, String> {
    let (text, pem) = with_card(card, Access::ReadOnly, |boot| {
        (bootpart::read_config_text(boot), bootpart::read_tls(boot))
    })
    .map_err(|error| format!("mounting {BOOT_DEV}: {error}"))?;
    let text = text.map_err(|error| format!("qberrypi.toml: {error}"))?;
    // The parser's errors name the file themselves.
    let cfg = config::parse(&text).map_err(|error| error.to_string())?;
    let pem = pem.unwrap_or_else(|error| {
        log::warn!("tls.pem: {error}; the API will stay off");
        None
    });
    // Whichever is first stays; there is only ever one load of the card.
    let _ = tls.set(pem);
    Ok(cfg)
}

/// The API's key and certificate as `load_config` found them, from step 3 on: `None` if the card
/// has none, or has one that could not be read.
pub fn tls_pem() -> Option<&'static [u8]> {
    tls_pem_of(&TLS_PEM)
}

/// What `slot` keeps of the TLS file.
fn tls_pem_of(slot: &OnceLock<Option<Vec<u8>>>) -> Option<&[u8]> {
    slot.get()?.as_deref()
}

/// Step 4: the first write to the card, before the watchdog runs or a driver is loaded.
///
/// In one-shot mode it makes the next start one of Raspberry Pi OS: from
/// here on, a restart for any reason leaves qberrypi. If the log is kept on
/// the card, what was logged so far is saved in the same mount, the outcome
/// of the restore included, so that a boot that dies in a driver has left its
/// first lines behind. With neither switch on, the card is not touched.
///
/// A restore that is refused or fails is logged as an error, and the boot
/// goes on. Stopping would not bring Raspberry Pi OS back: `fatal` restores
/// from the same backup, so it would fail the same way and only restart into
/// qberrypi sooner, over and over. Going on at least leaves a system to look at.
fn restore_and_save_log(cfg: &Config, card: &mut dyn Card, log: &Mutex<LogBuf>) {
    let (restore, save) = (cfg.debug.one_shot, cfg.debug.log_to_sd);
    if !restore && !save {
        return;
    }
    pet_watchdog();
    let written = with_card(card, Access::Writable, |boot| {
        if restore {
            log_restore(&bootpart::restore_pios_config(boot));
        }
        if save { save_log(boot, log) } else { Ok(()) }
    });
    match written {
        Ok(Ok(())) => {}
        Ok(Err(error)) => log::error!("log.txt: {error}"),
        Err(error) => {
            let what = if restore { "config.txt" } else { "log.txt" };
            log::error!("{what}: mounting {BOOT_DEV}: {error}");
        }
    }
}

/// Logs what came of a restore of `config.txt`.
fn log_restore(restored: &io::Result<Restore>) {
    let (level, line) = restore_report(restored);
    log::log!(level, "{line}");
}

/// The level and the line that what came of a restore of `config.txt` is logged with.
///
/// A restore that was refused, or that failed, is an error: the card still
/// starts qberrypi, and nothing else will say so.
fn restore_report(restored: &io::Result<Restore>) -> (Level, String) {
    match restored {
        Ok(outcome @ Restore::Refused(_)) => (Level::Error, format!("config.txt: {outcome:?}")),
        Ok(outcome) => (Level::Info, format!("config.txt: {outcome:?}")),
        Err(error) => (Level::Error, format!("config.txt: {error}")),
    }
}

/// Step 5: starts the hardware watchdog. The system runs without one if it must.
///
/// Only now, with the one-shot restore done: should a board ever restart on
/// the watchdog being started, it restarts into Raspberry Pi OS. Until here
/// the waits and `fatal` pet the stand-in, which does nothing.
fn open_watchdog() {
    match Watchdog::open(WATCHDOG_SECS) {
        Ok(watchdog) => *lock(&WATCHDOG) = watchdog,
        Err(error) => log::warn!("watchdog: {error}"),
    }
}

/// Step 6: names the system, becomes the kernel's module helper, loads the Wi-Fi driver.
fn load_wifi_driver(cfg: &Config) {
    pet_watchdog();
    if let Err(error) = sys::set_hostname(&cfg.hostname) {
        fatal(&format!("setting the hostname: {error}"));
    }
    if let Err(error) = sys::register_module_helper(MODULE_HELPER) {
        fatal(&format!("registering the module helper: {error}"));
    }
    let table = match std::fs::read_to_string(MODULE_LIST) {
        Ok(text) => ModuleTable::parse(&text)
            .unwrap_or_else(|error| fatal(&format!("{MODULE_LIST}: {error}"))),
        Err(error) => fatal(&format!("{MODULE_LIST}: {error}")),
    };
    match load_wifi_modules(&table, &cfg.wifi.country, &mut sys::insert_module) {
        Ok(inserted) => log::info!("modules: inserted {}", inserted.join(", ")),
        Err(message) => fatal(&message),
    }
}

/// Loads the Wi-Fi stack and returns the modules inserted. The error is the fatal message.
///
/// `cfg80211` goes first so that it gets the country; `brcmfmac` then finds it
/// loaded. The firmware is told not to roam on its own.
fn load_wifi_modules(
    table: &ModuleTable,
    country: &str,
    insert: Insert,
) -> Result<Vec<String>, String> {
    let regdom = format!("ieee80211_regdom={country}");
    let mut inserted = Vec::new();
    for (name, params) in [("cfg80211", regdom.as_str()), ("brcmfmac", BRCMFMAC_PARAMS)] {
        let loaded = modules::load(table, name, params, insert)
            .map_err(|error| format!("loading {name}: {error}"))?;
        inserted.extend(loaded);
    }
    Ok(inserted)
}

/// What the panel is given to work with: the configured touch calibration, and the slot that
/// stands for the resolver, for its numbers, for its switch, for the names its lane shows and for
/// the watchdog's alerts; the first service component to start fills it.
fn panel_deps(cfg: &Config, slot: &Arc<Slot>) -> Deps {
    Deps {
        source: slot.clone(),
        control: slot.clone(),
        calibration: cfg.panel.calibration(),
        calibrate: cfg.debug.calibrate_touch,
        lane: slot.lane(),
        alerts: slot.clone(),
    }
}

/// The front panel as a component: not essential, and it runs on a thread of the pool for good.
///
/// A board without the screen runs on without a panel, with the one warning the supervisor
/// logs for an absent component. The thread pets nothing and writes nothing but the log: a
/// calibration it measures is only logged.
fn panel_component(parts: &BoardParts) -> Option<Component> {
    let (cfg, slot) = (parts.cfg, parts.slot.clone());
    Some(Component::blocking("panel", false, move || {
        panel_ended(panel::run(panel_deps(cfg, &slot)))
    }))
}

/// How the supervisor takes the end of the panel's thread.
///
/// A board without the screen is only absent: the system runs on as it would have had the panel
/// never been planned, and the panel is not started again. A panel that was running and broke
/// has failed.
fn panel_ended(end: PanelEnd) -> Ended {
    match end {
        PanelEnd::NoScreen(why) => Ended::Absent(why),
        PanelEnd::Failed(why) => Ended::Failed(why),
    }
}

/// Step 6: sets the CPU frequency governor to `performance`, for the lowest latency.
///
/// With `performance` the CPU stays at its top frequency and does not have to
/// ramp up when a query arrives. This is never fatal: a board without the file
/// gets a warning, and the system runs on with the governor it has.
fn set_cpu_governor() {
    let (level, line) = governor_report(&set_governor(Path::new(SYSFS)));
    log::log!(level, "{line}");
}

/// Writes `performance` to the governor of the CPU's first frequency policy.
///
/// The file must already be there: it is the kernel's, and creating it would
/// only leave a file in a filesystem that has no such setting. The Pi 3 B+'s
/// four cores share the one policy.
fn set_governor(sysfs: &Path) -> io::Result<()> {
    // `truncate` is what a shell's `>` does: a sysfs file takes it as a no-op.
    let mut file = File::options()
        .write(true)
        .truncate(true)
        .open(sysfs.join(GOVERNOR_IN_SYSFS))?;
    file.write_all(GOVERNOR.as_bytes())
}

/// The level and the line that what came of setting the governor is logged with.
fn governor_report(result: &io::Result<()>) -> (Level, String) {
    match result {
        Ok(()) => (Level::Info, format!("cpu: governor {GOVERNOR}")),
        Err(error) => (Level::Warn, format!("cpu: governor: {error}")),
    }
}

/// Whether a boot has said already that the LED cannot be written.
static LED_WARNED: AtomicBool = AtomicBool::new(false);

/// Makes the LED in `dir` show `state`; gives the line that says it could not, the first time that
/// it could not, which is recorded in `warned`, and `None` every other time.
///
/// A board without the LED boots too, and a boot says so once: not at each change of the link.
fn change_led(dir: &Path, state: LedState, warned: &AtomicBool) -> Option<String> {
    led::set(dir, state)
        .err()
        .filter(|_| !warned.swap(true, Ordering::AcqRel))
        .map(|error| format!("activity LED: {error}"))
}

/// Makes the board's activity LED show `state`, unless a fatal error has begun; a failure is a
/// warning, once in a boot (`LED_WARNED`).
fn show_led(state: LedState) {
    if let Some(line) = show_led_in(&BOARD, Path::new(LED_DIR), state, &LED_WARNED) {
        log::warn!("{line}");
    }
}

/// `show_led`'s write, on the board `board` and the LED in `dir`; gives what `change_led` gives.
///
/// The look at the fatal error and the write are one step under the board's mutex, so that a
/// link state can never be written over the `Fatal` that `show_fatal` leaves: once a fatal error
/// has begun this writes nothing. This runs on the runtime's thread, and so the mutex is waited
/// for at most `LOG_LOCK_WAIT`; a mutex that is held for longer is held by something that has
/// failed, and then this gives up without a write.
fn show_led_in(
    board: &Mutex<Board>,
    dir: &Path,
    state: LedState,
    warned: &AtomicBool,
) -> Option<String> {
    let board = lock_within(board, LOG_LOCK_WAIT)?;
    if board.fatal.is_some() {
        return None;
    }
    change_led(dir, state, warned)
}

/// Makes the LED in `dir` show that the board has failed, under the board's mutex, so that no
/// link state is being written beside it.
///
/// The mutex is waited for at most `LOG_LOCK_WAIT`: if its holder is what failed, the LED is
/// written all the same.
fn show_fatal(board: &Mutex<Board>, dir: &Path) {
    let _held = lock_within(board, LOG_LOCK_WAIT);
    let _ = led::set(dir, LedState::Fatal);
}

/// Step 7: shows on the LED that the boot got this far: the system is up and has yet to join the network.
///
/// This is the LED's first state, long before the supervisor starts and takes the LED over, and the
/// first warning about a board that has none.
fn show_joining() {
    show_led(LedState::Joining);
}

/// Step 7, under the self-test: makes the kernel ask its module helper for a module.
///
/// Opening a socket of a family the kernel has no code for does that. The
/// module is not in the table, so nothing is loaded; the helper's line in
/// the kernel log shows that it was reached.
fn provoke_module_request() {
    if sys::kernel_arg(SELFTEST_ARG) {
        let _ = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0));
    }
}

/// Step 8: waits for the Wi-Fi interface and logs what came of the driver.
///
/// Returns the open kernel log, positioned after what step 8 has copied, and
/// whether the interface is there. A kernel log that cannot be opened is a
/// warning and `None`: the boot does not depend on it.
fn report_wifi() -> (Option<kmsg::Reader>, bool) {
    let sysfs = Path::new(SYSFS);
    let wlan_present = wait_for(WLAN_WAIT, || sysfs.join(WLAN_IN_SYSFS).exists());
    for line in wifi_report(sysfs) {
        log::info!("{line}");
    }
    let mut kernel_log = match kmsg::Reader::open(Path::new(KERNEL_LOG)) {
        Ok(reader) => Some(reader),
        Err(error) => {
            log::warn!("{KERNEL_LOG}: {error}");
            None
        }
    };
    log_kernel_news(&mut kernel_log);
    (kernel_log, wlan_present)
}

/// Says whether `/sys` shows the Wi-Fi interface and the driver's vendor module.
fn wifi_report(sysfs: &Path) -> [String; 2] {
    let wlan = sysfs.join(WLAN_IN_SYSFS).exists();
    let cyw = sysfs.join(CYW_IN_SYSFS).exists();
    [
        format!("wlan0: {}", if wlan { "present" } else { "absent" }),
        format!(
            "brcmfmac_cyw: {}",
            if cyw { "loaded" } else { "not loaded" }
        ),
    ]
}

/// Turns what the kernel has logged since the last look into lines for our own log.
fn kernel_lines(kernel_log: &mut kmsg::Reader) -> io::Result<Vec<String>> {
    let records = kernel_log.read_new()?;
    Ok(records
        .iter()
        .map(|record| format!("kernel: {}", record.text))
        .collect())
}

/// Logs what the kernel has logged since the last look, if its log is open.
///
/// A log that cannot be read is a warning, once, and is then let go of: the
/// same warning every second would only fill the log.
fn log_kernel_news(kernel_log: &mut Option<kmsg::Reader>) {
    let Some(reader) = kernel_log else { return };
    match kernel_lines(reader) {
        Ok(lines) => log_lines(&lines, &mut |line| log::info!("{line}"), &mut pet_watchdog),
        Err(error) => {
            log::warn!("{KERNEL_LOG}: {error}");
            *kernel_log = None;
        }
    }
}

/// Logs many lines, petting the watchdog before the first and then every `PET_EVERY_LINES`.
///
/// Each line is a write to the console that waits until it is out, and on a
/// serial console a full kernel log takes longer than the watchdog allows.
fn log_lines(lines: &[String], log_line: &mut dyn FnMut(&str), pet: &mut dyn FnMut()) {
    for batch in lines.chunks(PET_EVERY_LINES) {
        pet();
        for line in batch {
            log_line(line);
        }
    }
}

/// Step 9: if the configuration asks for it, appends the log to the card.
///
/// Only the lines not yet saved are written. Step 4 saved the first of them;
/// this is called again on the way out.
fn save_log_if_asked(cfg: &Config, card: &mut dyn Card, log: &Mutex<LogBuf>) {
    // Let go of at once: only the way out keeps its claim.
    drop(save_log_to(cfg, card, log, &BOARD, &first_fatal));
}

/// `save_log_if_asked`, on the board `board`, whose fatal error's thread `fatal_thread` also
/// tells; gives the claim on the card that the save made, still held, if it made one.
///
/// Once a fatal error has begun on another thread the card is the rescue's, and nothing is saved
/// from here: the claim refuses, in the same step in which it would have been made. Nor is it
/// saved while another thread has the card for longer than `CARD_LOCK_WAIT`. Either is only a
/// warning (`save_failure`), and the lines wait for the next save.
fn save_log_to<'b>(
    cfg: &Config,
    card: &mut dyn Card,
    log: &Mutex<LogBuf>,
    board: &'b Mutex<Board>,
    fatal_thread: &dyn Fn() -> Option<ThreadId>,
) -> Option<CardClaim<'b>> {
    if !cfg.debug.log_to_sd {
        return None;
    }
    pet_watchdog();
    let claim = match claim_card(board, CARD_LOCK_WAIT, fatal_thread) {
        Ok(claim) => claim,
        Err(error) => {
            let (level, line) = save_failure(&error);
            log::log!(level, "{line}");
            return None;
        }
    };
    match mounted(card, Access::Writable, |boot| save_log(boot, log)) {
        Ok((saved, unmounted)) => {
            log_unmount(unmounted);
            if let Err(error) = saved {
                log::error!("log.txt: {error}");
            }
        }
        Err(error) => {
            let (level, line) = save_failure(&error);
            log::log!(level, "{line}");
        }
    }
    Some(claim)
}

/// The level and the line for a save that did not get to write: the card was not given to it.
///
/// A card that is a fatal error's rescue's, or another thread's for longer than a claim waits, is
/// only a warning, and says so: the rescue saves the log itself, and the next save will. Anything
/// else is the mount that failed.
fn save_failure(error: &io::Error) -> (Level, String) {
    if refused_the_card(error) {
        (Level::Warn, format!("log.txt: not saved: {error}"))
    } else {
        (
            Level::Error,
            format!("log.txt: mounting {BOOT_DEV}: {error}"),
        )
    }
}

/// Appends the lines not yet saved to the log on the card, which is mounted at `boot`.
///
/// The lines are taken only here, with the card mounted, so that a card
/// that does not mount leaves them for the next save.
fn save_log(boot: &Path, log: &Mutex<LogBuf>) -> io::Result<()> {
    let entry = log_entry(&mut lock(log));
    bootpart::append_log(boot, &entry)
}

/// Takes the lines not yet saved and lays them out for the file on the card.
///
/// What a boot saves first goes under a header that names the build. What
/// it saves later only continues that, so the file shows one boot as one.
fn log_entry(buf: &mut LogBuf) -> String {
    let first_of_this_boot = !buf.taken();
    let unsaved = buf.take_unsaved();
    if first_of_this_boot {
        bootpart::boot_header(BUILD_EPOCH) + &unsaved
    } else {
        unsaved
    }
}

/// Step 10: builds the runtime that the rest of init's work runs on.
///
/// It has one thread, init's main one: nothing on it may hold the loop that
/// pets the watchdog for long. Work that blocks goes to the pool of
/// `services::BLOCKING_THREADS` behind it.
///
/// With `speed.runtime_cpu` set, the main thread is pinned to that core first, so that the
/// runtime and every pool thread that it creates start from a known place (`cpu: runtime pinned
/// to core N`). A core that cannot be taken is a warning, and the runtime goes on unpinned.
fn start_runtime(cfg: &Config) -> tokio::runtime::Runtime {
    let pin =
        cfg.speed.runtime_cpu.map(usize::from).and_then(|core| {
            match cpu::pin_current_thread(core) {
                Ok(()) => {
                    log::info!("cpu: runtime pinned to core {core}");
                    Some(core)
                }
                Err(error) => {
                    log::warn!("cpu: runtime not pinned to core {core}: {error}");
                    None
                }
            }
        });
    services::runtime(pin).unwrap_or_else(|error| fatal(&format!("starting the runtime: {error}")))
}

/// What the board's own components are made from, beside what the services have in their
/// [`Context`].
struct BoardParts {
    cfg: &'static Config,
    log: &'static Mutex<LogBuf>,
    /// Whether step 8 found the Wi-Fi interface.
    wlan_present: bool,
    /// The sender of the Wi-Fi's status, which the Wi-Fi component owns: it takes it out, once.
    status_sender: Cell<Option<watch::Sender<WifiStatus>>>,
    /// The saves of the log, which the Wi-Fi component starts after a join and the tick starts
    /// when one is due.
    saves: Arc<LogSaves>,
    /// The Wi-Fi's status, as the Wi-Fi task reports it.
    status: watch::Receiver<WifiStatus>,
    /// Where the `signal` component stores the Wi-Fi's signal.
    signal: Arc<SignalCache>,
    /// The front panel's slot, which the first service to start fills.
    slot: Arc<Slot>,
}

/// The board's own components, after the services and in the order that the board starts them:
/// the Wi-Fi, the one reader of the signal (the panel and the status page show what it stores) and
/// the front panel, and then a provoked failure, if one is asked for: that is started last, as the
/// rest of the board is up by then.
///
/// **This table is where a component of the board is added**: write its `fn <name>_component(parts:
/// &BoardParts) -> Option<Component>`, which gives `None` when the configuration has no such
/// component, and put it here. (A service of the shared state is added to `services::SERVICES`
/// instead.)
const BOARD_COMPONENTS: &[fn(&BoardParts) -> Option<Component>] = &[
    wifi_component,
    signal_component,
    panel_component,
    fault_component,
];

/// Every component of the board, in the order that the supervisor starts them: the services that
/// `ctx` makes (`services::prepare`) and then the board's own, made from `parts`
/// ([`BOARD_COMPONENTS`]). Nothing is started here.
fn components(ctx: Context, parts: &BoardParts) -> Vec<Component> {
    let mut components = services::prepare(ctx);
    components.extend(BOARD_COMPONENTS.iter().filter_map(|make| make(parts)));
    components
}

/// The `signal` component: the one reader of the signal, which `services` makes from the Wi-Fi's
/// status and the cache that the panel and the status page read.
fn signal_component(parts: &BoardParts) -> Option<Component> {
    Some(services::signal_component(
        parts.status.clone(),
        parts.signal.clone(),
    ))
}

/// The provoked failure that `debug.fault` asks for, if it is a component (`fault::component`).
fn fault_component(parts: &BoardParts) -> Option<Component> {
    fault::component(parts.cfg.debug.fault)
}

/// Step 10: brings the network up as far as `start_network` does, runs every component under the
/// supervisor, and restarts the board when the supervisor says so.
///
/// `services::prepare` gives the services as components: DNS, the zone's offset, the clock, status
/// and lists, the watchdog's and the API. The board's own components (`BOARD_COMPONENTS`) follow,
/// in this order: the Wi-Fi component, the signal component (the one reader of the Wi-Fi's signal,
/// which the panel and the status page show) and the front panel. The first service
/// to start makes what they share, which includes the snapshot load, and fills the slot that the
/// panel reads; the Wi-Fi joins and the panel looks for its screen beside that load, and until
/// the slot is filled the panel shows what it has no numbers for.
/// The supervisor's tick, once a `TICK`, pets the watchdog, collects the children that have
/// exited, copies the kernel's new log lines and, with the log kept on the card, starts a save
/// every `LOG_SAVE_EVERY`; the Wi-Fi component gives `wlan0` its address and a save of the log
/// after a join. The supervisor owns the LED, which follows the Wi-Fi's association, and ends when
/// a component that the board cannot do without has failed three times in a minute, when the
/// board has not been associated for 90 seconds, or when the configured time has passed.
/// With `debug.fault` set, a provoked failure is a component after the panel (for `drop-link` and
/// `mute-probe` a non-essential one, which provokes a loss of the link and no restart), or, for the
/// stall, a tick that never returns, or, for `no-wifi`, a link that never associates in place of
/// the real one. The last argument says whether step 8 found the Wi-Fi interface.
///
/// The supervisor keeps the tick's own deadline across every component, so that a component never
/// delays a pet or the restart for longer than it holds the thread.
async fn serve(
    cfg: &'static Config,
    log: &'static Mutex<LogBuf>,
    started: Instant,
    kernel_log: Option<kmsg::Reader>,
    wlan_present: bool,
) -> ! {
    let slot = Slot::new();
    let signal = SignalCache::new();
    // The services and the tick get a receiver of the Wi-Fi's status; the Wi-Fi component owns the sender.
    let (status_sender, status) = watch::channel(WifiStatus::Starting);
    // What follows waits on netlink replies, and starts with the watchdog's whole time ahead.
    pet_watchdog();
    start_network(cfg, &mut pet_watchdog).await;

    // The runtime thread's heartbeat, whose gaps `/api/v1/stats` reports (`stall`).
    drop(tokio::spawn(crate::stall::heartbeat()));

    // Nothing here waits: the services make what they share when the supervisor starts the first
    // of them, and the Wi-Fi and the panel start beside that.
    let saves = LogSaves::new();
    let components = components(
        Context {
            cfg,
            log,
            started,
            slot: slot.clone(),
            wifi: status.clone(),
            signal: signal.clone(),
            // The card's `tls.pem`, which `cfg.api` says whether to serve with.
            tls_pem: tls_pem(),
        },
        &BoardParts {
            cfg,
            log,
            wlan_present,
            status_sender: Cell::new(Some(status_sender)),
            saves: saves.clone(),
            status: status.clone(),
            signal,
            slot,
        },
    );

    let plan = Plan {
        components,
        return_after: return_after(cfg.debug.return_after_secs, started.elapsed()),
        // The Wi-Fi task's own statuses, or what the provoked fault puts in their place.
        link: Some(fault::link(cfg.debug.fault).unwrap_or_else(|| status.clone())),
    };
    let hooks = Hooks {
        // The stall fault counts from here, where the supervisor starts: the panel is up by then.
        tick: Box::new(tick(
            cfg,
            log,
            kernel_log,
            status,
            saves.clone(),
            Instant::now(),
        )),
        // The supervisor's: the LED follows the association.
        led: Box::new(show_led),
    };
    let reason = supervisor::run(plan, hooks).await;
    // On `Restart` the card stays claimed, from `leave` to the restart.
    match leave(cfg, &mut SdCard, log, &reason, &saves, &BOARD) {
        Leaving::Restart => sys::reboot(),
        Leaving::Park => loop {
            thread::park();
        },
    }
}

/// How long from now the board returns: `return_after_secs` counted from the start of the boot,
/// less what has passed since; `None` for 0, which means never.
fn return_after(return_after_secs: u64, elapsed: Duration) -> Option<Duration> {
    (return_after_secs != 0).then(|| Duration::from_secs(return_after_secs).saturating_sub(elapsed))
}

/// What the supervisor's tick does: pets the watchdog, collects the children that have exited,
/// copies the kernel's new log lines, and starts a save of the log if one is due.
///
/// Nothing here waits: the save runs on the pool. The one exception is the provoked stall
/// (`debug.fault = "stall"`): once `began`, when the supervisor started, is `fault::FAULT_AFTER`
/// ago, the tick does not pet and does not return (see `stall`).
fn tick(
    cfg: &'static Config,
    log: &'static Mutex<LogBuf>,
    mut kernel_log: Option<kmsg::Reader>,
    status: watch::Receiver<WifiStatus>,
    saves: Arc<LogSaves>,
    began: Instant,
) -> impl FnMut() {
    move || {
        // Before the pet: a stalled supervisor must leave the watchdog its whole time to run out.
        // The clock is read only for the one fault that asks for it.
        if cfg.debug.fault == Fault::Stall && fault::stall_due(Fault::Stall, began.elapsed()) {
            stall(cfg, log, &saves);
        }
        pet_watchdog();
        sys::reap_children();
        log_kernel_news(&mut kernel_log);
        // The status is copied out, so that no hold on the channel lasts through the rest.
        let now = status.borrow().clone();
        start_save_if_due(cfg, log, &saves, &now, Instant::now(), SdCard);
    }
}

/// How long a stalling supervisor waits for a save that runs on the pool before it saves itself.
///
/// Short, because the watchdog is running out; a save that takes longer is taken to be stuck.
const STALL_SAVE_WAIT: Duration = Duration::from_secs(3);

/// The provoked stall: says so, saves the log, and holds the supervisor's thread for ever.
///
/// What the supervisor's own thread must never do is the point here, so it is done on purpose:
/// the runtime is held, no tick comes, and nothing pets the watchdog, which restarts the board
/// within its 15 seconds. The line and what came before it are saved first (`stall_save`), so
/// that the log on the card shows that it happened; the save pets once as it begins, as every
/// save does, so the restart comes 15 seconds after that at the latest.
fn stall(cfg: &Config, log: &Mutex<LogBuf>, saves: &LogSaves) -> ! {
    stall_save(cfg, &mut SdCard, log, saves, STALL_SAVE_WAIT, &BOARD);
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

/// What the stall does before it sleeps: logs `fault::STALLING`, closes the saves, waits up to
/// `wait` for a save that has begun on the pool to end, and saves the log itself where it is kept
/// on the card.
///
/// On this thread, and not the pool's, so that the line is on the card before the watchdog
/// fires. The wait is for the card's sake, so that two saves do not use it at once, and pets
/// nothing. The save pets once as it begins, as every save does: that is the last pet. A save
/// that was queued behind other work on the pool and has not begun is not waited for and, the
/// saves being closed, ends when it begins without a pet or a touch of the card.
///
/// The card is claimed on `board` for the save and stays claimed, for the restart that the
/// watchdog is about to make: nothing of the pool mounts it under that. A save of the pool that
/// has the card for longer than the claim waits (`CARD_LOCK_WAIT`, after `wait`) is not used
/// beside: the claim gives up, and nothing is saved from here.
fn stall_save(
    cfg: &Config,
    card: &mut dyn Card,
    log: &Mutex<LogBuf>,
    saves: &LogSaves,
    wait: Duration,
    board: &Mutex<Board>,
) {
    log::warn!("{}", fault::STALLING);
    saves.close();
    saves.wait_idle(wait, &mut || {});
    if let Some(claim) = save_log_to(cfg, card, log, board, &first_fatal) {
        claim.keep();
    }
}

/// The tick's save: starts one on the pool when `saves` says it is due at `now`; says whether it did.
///
/// Never waits for the card, which is the pool thread's for as long as the save takes.
fn start_save_if_due<C: Card + Send + 'static>(
    cfg: &'static Config,
    log: &'static Mutex<LogBuf>,
    saves: &LogSaves,
    status: &WifiStatus,
    now: Instant,
    card: C,
) -> bool {
    let unsaved = lock(log).has_unsaved();
    saves.is_due_at(now, status, unsaved) && saves.start(cfg, log, card)
}

/// Whether the tick saves the log: lines are waiting, `LOG_SAVE_EVERY` has passed since the last save,
/// and no join is under way.
///
/// A save is a job of the pool and the handshake does not wait for it, but the card and the
/// radio's interrupts share the board's bus, and a join is short.
fn save_due(since_last_save: Duration, status: &WifiStatus, has_unsaved: bool) -> bool {
    has_unsaved
        && since_last_save >= LOG_SAVE_EVERY
        && !matches!(status, WifiStatus::Joining { .. })
}

/// How long until the Wi-Fi component tries again to give `wlan0` its address, or `None` when
/// there is nothing to try: it is not joined, or this join has its address.
///
/// The wait is what is left of `REOPEN_EVERY` since the last try.
fn configure_in(
    status: &WifiStatus,
    configured: bool,
    since_last_try: Duration,
) -> Option<Duration> {
    (matches!(status, WifiStatus::Joined { .. }) && !configured)
        .then(|| REOPEN_EVERY.saturating_sub(since_last_try))
}

/// The log's saves to the card once the runtime runs, as jobs of the blocking pool.
///
/// At most one is in flight: a save that is due while one runs is skipped, and the tick asks
/// again. None of them is waited for by the runtime's thread. The card is the pool thread's for
/// as long as the save takes, under a claim on `BOARD`.
///
/// A save that was started is on the pool in one of two ways: queued, when every thread of the
/// pool is busy and it has not begun, or started, once a thread has taken it. The way out tells
/// them apart: it waits for a started save, which holds the card, and not for a queued one, which
/// holds nothing and would otherwise make it wait for whatever the pool is busy with. Closing the
/// saves, which the way out does first, makes a queued save end as soon as it begins, without a
/// touch of the card, so that the card is never mounted by the pool while the board restarts. The
/// way out also keeps its own claim on the card through the restart, which is the board's side of
/// the same rule (`wind_down`); this type is about the pool's queue and the board is about the card.
struct LogSaves {
    /// Where the one save stands, and whether the way out has begun. One small mutex, so that a
    /// save's beginning and the way out's closing are in an order: a save that has begun is waited
    /// for, and one that has not will find the saves closed.
    state: Arc<Mutex<SaveState>>,
    /// When the last save began, or when the board began to serve: `LOG_SAVE_EVERY` counts from there.
    last: Mutex<Instant>,
}

/// Where the log's save stands, and whether the way out has begun.
struct SaveState {
    save: Save,
    /// Set by the way out, for good: no save starts, and one that has not begun never will.
    closing: bool,
}

/// Where the log's one save stands.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Save {
    /// None is on the pool.
    Idle,
    /// A job is on the pool and no thread has taken it yet.
    Queued,
    /// A thread of the pool has taken it: it may have the card, and ends by itself.
    Started,
}

/// Lets go of the claim on the pool when a save job ends, however it ends: begun and done, skipped
/// because the way out had begun, or dropped unbegun with the runtime.
struct Done(Arc<Mutex<SaveState>>);

impl Drop for Done {
    fn drop(&mut self) {
        lock(&self.0).save = Save::Idle;
    }
}

impl LogSaves {
    /// No save yet, from now.
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Arc::new(Mutex::new(SaveState {
                save: Save::Idle,
                closing: false,
            })),
            last: Mutex::new(Instant::now()),
        })
    }

    /// Whether a save is on the pool, queued or started.
    fn running(&self) -> bool {
        lock(&self.state).save != Save::Idle
    }

    /// Whether a thread of the pool has taken the save, which is then to be waited for.
    fn started(&self) -> bool {
        lock(&self.state).save == Save::Started
    }

    /// Marks the saves closed, for good: from now on none starts, and a queued one skips the card
    /// when it begins. The way out calls this before it waits for anything.
    fn close(&self) {
        lock(&self.state).closing = true;
    }

    /// Waits until no save has begun that has not ended, or `within` has passed, petting the
    /// watchdog meanwhile; says whether none has.
    ///
    /// For the way out, which saves on the main thread and must not use the card beside a save
    /// that holds it: a save that is still there when the time has passed is taken to be stuck.
    /// A save that is queued is not waited for. Close the saves first, or one that is queued can
    /// begin after this has returned.
    fn wait_idle(&self, within: Duration, pet: &mut dyn FnMut()) -> bool {
        wait_until(within, POLL_EVERY, PET_EVERY, pet, &mut || !self.started())
    }

    /// Whether the tick starts a save at `now`: `save_due`, counted from the last save's start, and
    /// none running.
    fn is_due_at(&self, now: Instant, status: &WifiStatus, has_unsaved: bool) -> bool {
        let since = now.saturating_duration_since(*lock(&self.last));
        !self.running() && save_due(since, status, has_unsaved)
    }

    /// Starts a save of the log on the pool, unless the log is not kept on the card, one is in
    /// flight or the way out has begun; says whether it did. Never waits for the card.
    ///
    /// Must be called on the runtime.
    fn start<C: Card + Send + 'static>(
        &self,
        cfg: &'static Config,
        log: &'static Mutex<LogBuf>,
        mut card: C,
    ) -> bool {
        if !cfg.debug.log_to_sd {
            return false;
        }
        {
            let mut state = lock(&self.state);
            if state.closing || state.save != Save::Idle {
                return false;
            }
            state.save = Save::Queued;
        }
        *lock(&self.last) = Instant::now();
        let done = Done(self.state.clone());
        // Not awaited: the job ends by itself, and the runtime goes on.
        drop(tokio::task::spawn_blocking(move || {
            let done = done;
            if begin(&done.0) {
                save_log_if_asked(cfg, &mut card, log);
            }
        }));
        true
    }
}

/// What a save does first, on its thread of the pool: marks itself started, unless the way out has
/// begun, and says whether it is to go on. A save that is told not to must not touch the card.
fn begin(state: &Mutex<SaveState>) -> bool {
    let mut state = lock(state);
    if state.closing {
        return false;
    }
    state.save = Save::Started;
    true
}

/// The Wi-Fi as a component, which is essential: the Wi-Fi task and what follows each join.
///
/// Each start builds the task afresh. When the link is joined it gives `wlan0` its address and
/// default route and starts a save of the log; a join that could not be given its address is
/// tried again every `REOPEN_EVERY` for as long as it holds. The LED is the supervisor's, not
/// this component's. It owns the sender of the status, so the panel and the status page read
/// what it reports. It never ends: without `wlan0` it waits for ever, as there is no radio to
/// supervise. `parts` says whether step 8 found the Wi-Fi interface, and gives the sender of the
/// status, which only one component can own: a second call finds it taken, and gives `None`.
fn wifi_component(parts: &BoardParts) -> Option<Component> {
    let (cfg, log, wlan_present) = (parts.cfg, parts.log, parts.wlan_present);
    let status = parts.status_sender.take()?;
    let saves = parts.saves.clone();
    Some(Component::task("wifi", true, move || {
        wifi_service(cfg, log, wlan_present, status.clone(), saves.clone())
    }))
}

/// The Wi-Fi component's task. It never ends: the Wi-Fi task does not return, and nothing else in the loop does.
async fn wifi_service(
    cfg: &'static Config,
    log: &'static Mutex<LogBuf>,
    wlan_present: bool,
    sender: watch::Sender<WifiStatus>,
    saves: Arc<LogSaves>,
) -> Ended {
    let mut status = sender.subscribe();
    let mut report = |next: WifiStatus| {
        sender.send_replace(next);
    };
    let mut joining = pin!(wifi_task(cfg, wlan_present, &mut report));
    // Opened when the first join needs it.
    let mut route: Option<Route> = None;
    // Whether the join that holds now was given its address, and when that was last tried.
    let mut configured = false;
    let mut last_try = tokio::time::Instant::now();
    loop {
        let retry = configure_in(&status.borrow(), configured, last_try.elapsed());
        // A change that is ready goes first, and a retry that waits behind it is not lost: each change
        // resets `configured`, and a join configures at once, and the wait is worked out again here.
        tokio::select! {
            biased;
            never = &mut joining => match never {},
            changed = status.changed() => {
                changed.expect("this component holds the sender of the Wi-Fi status");
                let now = status.borrow_and_update().clone();
                // A new status is a new join, or none: it has no address yet.
                configured = false;
                if matches!(now, WifiStatus::Joined { .. }) {
                    configured = settle_after_join(cfg, log, &mut route, &saves).await;
                    last_try = tokio::time::Instant::now();
                }
            }
            // A link that holds for hours must not stay without an address.
            () = tokio::time::sleep(retry.unwrap_or_default()), if retry.is_some() => {
                configured = configure_and_log(cfg, &mut route).await;
                last_try = tokio::time::Instant::now();
            }
        }
    }
}

/// The Wi-Fi: joins the configured network and holds the link for ever. It never returns.
///
/// Without `wlan0` there is nothing to join with, and with a key that cannot
/// be made there is nothing to join as: either is logged, and the task then
/// waits for ever. An interface that cannot be opened is tried again every
/// `REOPEN_EVERY`. Once `wifi::run` has the interface it never gives it back,
/// and `report` hears each change of status.
async fn wifi_task(
    cfg: &Config,
    wlan_present: bool,
    report: &mut (dyn FnMut(WifiStatus) + Send),
) -> Infallible {
    if !wlan_present {
        log::warn!("wifi: wlan0 is absent, not joining");
        return std::future::pending().await;
    }
    // Tens of milliseconds on the board, and the one stretch here that does not wait on a timer or a socket.
    let join = match wifi::join_cfg(&cfg.wifi) {
        Ok(join) => join,
        Err(error) => {
            log::error!("wifi: {error}");
            return std::future::pending().await;
        }
    };
    loop {
        match KernelRadio::open(WLAN).await {
            Ok(mut radio) => match wifi::run(&mut radio, &join, report).await {},
            Err(error) => {
                log::warn!("wifi: wlan0 could not be opened: {error}");
                tokio::time::sleep(REOPEN_EVERY).await;
            }
        }
    }
}

/// What follows a join: the address and the default route, then a save of the log if it is kept on the card.
///
/// The save is started at once so that what the join logged reaches the card, and the periodic
/// saves count their `LOG_SAVE_EVERY` from there; it runs on the pool, and one that is already
/// running leaves this one to the tick. Says whether the address was set; if not, the component
/// tries again while the join holds.
async fn settle_after_join(
    cfg: &'static Config,
    log: &'static Mutex<LogBuf>,
    route: &mut Option<Route>,
    saves: &LogSaves,
) -> bool {
    let configured = configure_and_log(cfg, route).await;
    saves.start(cfg, log, SdCard);
    configured
}

/// Gives `wlan0` its address and default route, and logs how it went; says whether it did.
///
/// Whatever goes wrong is only logged: the Wi-Fi component tries again while the join holds.
async fn configure_and_log(cfg: &Config, route: &mut Option<Route>) -> bool {
    // The supervisor's tick pets while the requests wait, and they are given `CONFIGURE_WITHIN`.
    match address_wlan(route, &cfg.net).await {
        Ok(()) => {
            log::info!("{}", net_line(&cfg.net));
            true
        }
        Err(error) => {
            log::warn!("net: {error}");
            false
        }
    }
}

/// Gives `wlan0` its address and default route over the route socket in `route`, within `CONFIGURE_WITHIN`.
///
/// Whatever goes wrong is only the error of this try: the Wi-Fi component tries again
/// while the join holds, and the next join does. The socket is let go of on an
/// error, so that the next try opens one with no request of this one left on it.
async fn address_wlan(route: &mut Option<Route>, net: &config::Net) -> Result<(), String> {
    let result = bounded(CONFIGURE_WITHIN, configure_over(route, net)).await;
    if result.is_err() {
        *route = None;
    }
    result
}

/// Sets the address and default route over the route socket in `route`, which is opened on first use.
///
/// The socket is an offloaded one: the driver of the radio's link runs its part of an address
/// inside the send, and that must not hold the runtime's thread, where DNS is answered.
async fn configure_over(route: &mut Option<Route>, net: &config::Net) -> Result<(), String> {
    let route = match route {
        Some(route) => route,
        None => route.insert(Route::open_offloaded().map_err(|error| error.to_string())?),
    };
    net::configure(route, WLAN, net)
        .await
        .map_err(|error| error.to_string())
}

/// Runs `work` for at most `within`; work that is not done by then is dropped, and that is its error.
async fn bounded(
    within: Duration,
    work: impl Future<Output = Result<(), String>>,
) -> Result<(), String> {
    tokio::time::timeout(within, work)
        .await
        .unwrap_or_else(|_| Err(format!("{WLAN} not configured within {}", length(within))))
}

/// A length of time for a message: whole seconds as `4 s`, anything else as `Duration` shows it.
///
/// Never `0 s` for a bound of less than a second.
fn length(time: Duration) -> String {
    if time.subsec_nanos() == 0 {
        format!("{} s", time.as_secs())
    } else {
        format!("{time:?}")
    }
}

/// The line that says what `wlan0` was given: its address, and the route out through the gateway.
fn net_line(net: &config::Net) -> String {
    format!(
        "net: {}/{} on {WLAN}, default route via {}",
        net.address.addr, net.address.prefix, net.gateway
    )
}

/// The way out of the supervisor: says why the board restarts, counts the echo requests
/// answered, saves the log if the configuration keeps it on the card, and says what follows.
///
/// Not when a fatal error has begun on another thread: that thread restarts
/// the board, and this one waits for it as `fatal` does for a second error. The
/// save is made here, on the calling thread, with the board about to restart.
///
/// The saves are closed first, so that none begins on the pool from here on, and a save that was
/// queued behind other work there ends when it begins without touching the card. One that has
/// begun is waited for, up to `CARD_LOCK_WAIT`, so that this one does not use the card beside it;
/// one that has not is not waited for. The card is claimed on `board` and, when the answer is
/// `Restart`, the claim is not let go of: the restart follows at once, and no save of the pool
/// may mount the card under it.
fn leave(
    cfg: &Config,
    card: &mut dyn Card,
    log: &Mutex<LogBuf>,
    reason: &Reason,
    saves: &LogSaves,
    board: &Mutex<Board>,
) -> Leaving {
    wind_down(cfg, card, log, reason, saves, board, &first_fatal)
}

/// What the main thread does once the supervisor has ended.
#[derive(Debug, PartialEq)]
enum Leaving {
    Restart,
    /// A fatal error on another thread is carrying the board out, and ends in a restart of its own.
    Park,
}

/// The level and the line that `reason` is logged with when the board leaves.
///
/// The configured time passing is the board's plan and the line the QEMU scenarios look for;
/// anything else is an error that restarts the board.
fn leaving_line(reason: &Reason) -> (Level, String) {
    match reason {
        Reason::ReturnAfter => (Level::Info, "returning".to_owned()),
        other => (Level::Error, format!("supervisor: restarting: {other}")),
    }
}

/// The work of `leave`: says why, counts the echo requests, saves the log if asked, and says what follows.
///
/// `fatal_thread` tells which thread's fatal error began first, if one has. It
/// is looked at again after each step, because one can begin at any moment.
///
/// The claim on the card that the save makes is kept, never let go of, when the answer is
/// `Restart`: the caller restarts the board next, and a save of the pool that began late, or
/// one that was stuck before it took the card, must not mount it under the restart. When the
/// answer is `Park` the claim is let go of, for the rescue of the fatal error that has the board.
fn wind_down(
    cfg: &Config,
    card: &mut dyn Card,
    log: &Mutex<LogBuf>,
    reason: &Reason,
    saves: &LogSaves,
    board: &Mutex<Board>,
    fatal_thread: &dyn Fn() -> Option<ThreadId>,
) -> Leaving {
    // First: a save that is queued behind the pool's other work must not begin and mount the card
    // while this one, or the restart, has it. Whoever's board this is, nothing more is saved from
    // the pool.
    saves.close();
    let me = thread::current().id();
    let ours = || board_is_ours(fatal_thread(), me);
    if !ours() {
        return Leaving::Park;
    }
    let (level, line) = leaving_line(reason);
    log::log!(level, "{line}");
    log_echo_counters();
    saves.wait_idle(CARD_LOCK_WAIT, &mut pet_watchdog);
    let claim = save_log_to(cfg, card, log, board, fatal_thread);
    if ours() {
        if let Some(claim) = claim {
            claim.keep();
        }
        Leaving::Restart
    } else {
        Leaving::Park
    }
}

/// Logs how many echo requests the kernel has answered, when `/proc/net/snmp` tells.
fn log_echo_counters() {
    let line = std::fs::read_to_string(SNMP)
        .ok()
        .and_then(|snmp| net::icmp_echo_line(&snmp));
    if let Some(line) = line {
        log::info!("{line}");
    }
}

/// Brings `lo` up and checks the regulatory domain. Neither is fatal.
///
/// Each step is bounded by the netlink replies' own timeout, and the country
/// check by `COUNTRY_WAIT` plus the last reply it asks for, so `pet` is called
/// after every step and no gap between two pets is longer than 10 s.
async fn start_network(cfg: &Config, pet: &mut dyn FnMut()) {
    let lo = match Route::open() {
        Ok(mut route) => net::loopback_up(&mut route)
            .await
            .map_err(|error| error.to_string()),
        Err(error) => Err(error.to_string()),
    };
    match lo {
        Ok(()) => log::info!("net: lo is up"),
        Err(error) => log::warn!("net: lo: {error}"),
    }
    pet();

    // `config::parse` has checked that the country is two letters.
    let want = <[u8; 2]>::try_from(cfg.wifi.country.as_bytes())
        .expect("the configured country is two letters");
    let opened = Nl80211::open().await;
    // Opening can have taken a whole reply timeout, and the check that follows can take two.
    pet();
    let country = match opened {
        Ok(mut nl80211) => nl80211
            .wait_for_country(want, COUNTRY_WAIT)
            .await
            .map_err(|error| error.to_string()),
        Err(error) => Err(error.to_string()),
    };
    let (level, line) = regulatory_report(&cfg.wifi.country, &country);
    log::log!(level, "{line}");
    // What the main loop does next starts with the watchdog's whole time ahead.
    pet();
}

/// The level and the line that what the kernel holds as its regulatory domain is logged with.
///
/// Anything but the configured country is a warning: the radio then works
/// under rules that are not the ones the owner asked for.
fn regulatory_report(want: &str, got: &Result<[u8; 2], String>) -> (Level, String) {
    match got {
        Ok(country) if country == want.as_bytes() => (
            Level::Info,
            format!("regulatory: country {want}, as configured"),
        ),
        Ok(country) => (
            Level::Warn,
            format!(
                "regulatory: country is {}, not the configured {want}",
                String::from_utf8_lossy(country)
            ),
        ),
        Err(error) => (
            Level::Warn,
            format!("regulatory: could not be read: {error}"),
        ),
    }
}

/// What a call of `fatal` finds when it comes.
#[derive(Debug, PartialEq)]
enum FatalEntry {
    /// No fatal error had begun: this one carries the board out.
    First,
    /// The thread that is carrying the board out failed again, or a panic came from inside it.
    Again,
    /// Another thread is carrying the board out.
    Elsewhere,
}

/// Which way a call of `fatal` on thread `me` goes, given the thread whose fatal error began first.
fn fatal_entry(begun_by: Option<ThreadId>, me: ThreadId) -> FatalEntry {
    match begun_by {
        None => FatalEntry::First,
        Some(first) if first == me => FatalEntry::Again,
        Some(_) => FatalEntry::Elsewhere,
    }
}

/// Whether thread `me` may pet the watchdog, given the thread whose fatal error began first.
///
/// Anyone may until a fatal error has begun; after that only its thread, so
/// that a rescue that hangs is ended by the watchdog, and is not kept alive by
/// a loop on another thread.
fn may_pet(fatal_thread: Option<ThreadId>, me: ThreadId) -> bool {
    fatal_thread.is_none_or(|first| first == me)
}

/// Whether thread `me` may write the card and restart the board: no fatal error has begun on another thread.
///
/// The rescue of a fatal error unmounts and mounts the card and ends in a
/// restart; a save or a restart from the main loop in the middle of that would
/// break it. This is `may_pet`'s question, asked for the card and the restart.
fn board_is_ours(fatal_thread: Option<ThreadId>, me: ThreadId) -> bool {
    may_pet(fatal_thread, me)
}

/// Takes the fatal error for thread `me` if none has begun; otherwise says which thread has it.
fn begin_fatal(me: ThreadId) -> Option<ThreadId> {
    begin_fatal_in(&BOARD, &FATAL_THREAD, me)
}

/// `begin_fatal`, on the board `board` and the lock-free record `first`.
///
/// Both records are set in the one critical section, so that a claim on the card or a write of
/// the LED sees either neither or both. The board's mutex is waited for at most `LOG_LOCK_WAIT`:
/// a fatal error must begin whatever holds it, and then `first` alone says whose it is.
fn begin_fatal_in(
    board: &Mutex<Board>,
    first: &OnceLock<ThreadId>,
    me: ThreadId,
) -> Option<ThreadId> {
    let held = lock_within(board, LOG_LOCK_WAIT);
    let begun = match first.set(me) {
        Ok(()) => None,
        Err(_) => first.get().copied(),
    };
    if let Some(mut board) = held {
        board.fatal = first.get().copied();
    }
    begun
}

/// Stops the system: message, LED, the card put right and the log saved, a pause to read, restart.
///
/// Any thread may call it. The first call carries the board out; a call from
/// another thread waits for ever, for the first one restarts the board.
fn fatal(message: &str) -> ! {
    let me = thread::current().id();
    match fatal_entry(begin_fatal(me), me) {
        FatalEntry::First => {}
        // The rescue failed, or a panic came from inside it. Nothing more is tried.
        FatalEntry::Again => sys::reboot(),
        FatalEntry::Elsewhere => loop {
            thread::park();
        },
    }
    // What follows writes to the card. It must not start on whatever time
    // the failed step left, or the watchdog could cut the writes short.
    pet_watchdog();
    // A log that stays locked was being written when the failure came. Using
    // it again from here would wait for ever, so it is left alone. A lock
    // that another thread holds for the length of one line is let go of soon.
    let log = LOG.get().copied();
    let log_in_use = log.is_some_and(|log| lock_within(log, LOG_LOCK_WAIT).is_none());
    if log_in_use {
        if let Ok(mut console) = File::options().write(true).open(CONSOLE) {
            let _ = writeln!(console, "{message}");
        }
    } else {
        log::error!("{message}");
    }
    show_fatal(&BOARD, Path::new(LED_DIR));
    rescue(
        CONFIG.get(),
        &mut SdCard,
        log.filter(|_| !log_in_use),
        RESCUE_DEV_WAIT,
        &mut pet_watchdog,
    );
    pause(FATAL_PAUSE);
    sys::reboot()
}

/// What a fatal error does to the card before the restart.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Rescue {
    /// Put Raspberry Pi OS's `config.txt` back.
    restore_config: bool,
    /// Append the log to `qberrypi/log.txt`.
    save_log: bool,
}

/// Decides what a fatal error does to the card, from the configuration if there is one.
///
/// `config.txt` is restored when `restore_on_fatal` says so. The log is
/// saved then too, and also whenever the configuration keeps the log on the
/// card: that switch is there so that a boot that failed can be read back.
fn rescue_plan(cfg: Option<&Config>) -> Rescue {
    let restore_config = restore_on_fatal(cfg);
    Rescue {
        restore_config,
        save_log: restore_config || cfg.is_some_and(|cfg| cfg.debug.log_to_sd),
    }
}

/// What `fatal` does to the card: whatever `rescue_plan` says, and no more.
///
/// The card is waited for and mounted only if there is something to do on
/// it. Errors are ignored: the restart comes whatever happens. `log` is the
/// log to save, and `None` if it must not be used; this logs only when it has
/// one. `wait` is how long the card is waited for. `pet` is called during
/// that wait, and between the restore and the saving of the log.
fn rescue(
    cfg: Option<&Config>,
    card: &mut dyn Card,
    log: Option<&Mutex<LogBuf>>,
    wait: Duration,
    pet: &mut dyn FnMut(),
) {
    let plan = rescue_plan(cfg);
    let log_to_save = log.filter(|_| plan.save_log);
    if !plan.restore_config && log_to_save.is_none() {
        return;
    }
    // Init starts before the kernel has read the card's partitions, so a
    // failure in the first steps comes when there is nothing to mount yet.
    // The mount is tried even when the wait ran out: nothing is lost by it.
    wait_for_card(card, wait, pet);
    let _ = on_card(card, Access::Writable, |boot| {
        if plan.restore_config {
            let restored = bootpart::restore_pios_config(boot);
            if log.is_some() {
                log_restore(&restored);
            }
        }
        // The restore and the log are each a write that waits for the card.
        pet();
        // Another thread may be logging at this moment: a line's length is waited for.
        if let Some(mut buf) = log_to_save.and_then(|log| lock_within(log, LOG_LOCK_WAIT)) {
            let entry = log_entry(&mut buf);
            drop(buf);
            let _ = bootpart::append_log(boot, &entry);
        }
    });
}

/// Reports a panic as a fatal error.
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|panic| {
        let what = panic.payload_as_str().unwrap_or("no message");
        match panic.location() {
            Some(place) => fatal(&format!("panic at {place}: {what}")),
            None => fatal(&format!("panic: {what}")),
        }
    }));
}

/// The boot partition of the SD card, as the boot sequence uses it.
trait Card {
    /// Whether the kernel has found the partition yet.
    fn present(&self) -> bool;
    /// Where the partition's files are while it is mounted.
    fn dir(&self) -> &Path;
    fn mount(&mut self, access: Access) -> io::Result<()>;
    /// Waits until everything written is on the card.
    fn sync(&mut self);
    fn unmount(&mut self) -> io::Result<()>;
}

/// What a mount of the boot partition allows.
#[derive(Clone, Copy, PartialEq)]
enum Access {
    ReadOnly,
    Writable,
}

/// The real card.
struct SdCard;

impl Card for SdCard {
    fn present(&self) -> bool {
        Path::new(BOOT_DEV).exists()
    }

    fn dir(&self) -> &Path {
        Path::new(MOUNT_POINT)
    }

    fn mount(&mut self, access: Access) -> io::Result<()> {
        sys::mount_vfat(BOOT_DEV, MOUNT_POINT, access == Access::ReadOnly)
    }

    fn sync(&mut self) {
        sys::sync();
    }

    fn unmount(&mut self) -> io::Result<()> {
        sys::unmount(MOUNT_POINT)
    }
}

/// Mounts the boot partition, runs `work` on its files, and unmounts it.
///
/// After a writable mount, everything is first synced to the card. Returns
/// what `work` returned, with how the unmount went. If the mount fails, that
/// is the error, and `work` is not run.
///
/// The partition is unmounted before it is mounted, too. A failure can come
/// while it is mounted, and an unmount can fail; a mount on top of that
/// would be refused as busy, and a restore skipped. Most often nothing is
/// mounted, and the error that says so is ignored.
///
/// Only one thread has the card at a time: see `claim_card`.
fn on_card<T>(
    card: &mut dyn Card,
    access: Access,
    work: impl FnOnce(&Path) -> T,
) -> io::Result<(T, io::Result<()>)> {
    on_card_within(card, access, &BOARD, CARD_LOCK_WAIT, &first_fatal, work)
}

/// `on_card`, on the board `board` that the card goes by, waiting up to `lock_wait` for another
/// thread that has the card; `fatal_thread` is `claim_card`'s.
///
/// The card is claimed for as long as this runs and let go of when it returns, and `board`'s
/// mutex is not held across the use of the card.
fn on_card_within<T>(
    card: &mut dyn Card,
    access: Access,
    board: &Mutex<Board>,
    lock_wait: Duration,
    fatal_thread: &dyn Fn() -> Option<ThreadId>,
    work: impl FnOnce(&Path) -> T,
) -> io::Result<(T, io::Result<()>)> {
    let _claim = claim_card(board, lock_wait, fatal_thread)?;
    mounted(card, access, work)
}

/// The use of the card that `on_card` is: unmount what is left, mount, `work`, sync, unmount. The
/// caller has claimed the card.
fn mounted<T>(
    card: &mut dyn Card,
    access: Access,
    work: impl FnOnce(&Path) -> T,
) -> io::Result<(T, io::Result<()>)> {
    let _ = card.unmount();
    card.mount(access)?;
    let done = work(card.dir());
    if access == Access::Writable {
        card.sync();
    }
    Ok((done, card.unmount()))
}

/// A thread's claim on the card, which `Drop` lets go of.
///
/// While it lasts, `claim_card` gives the card to no other thread. The way out `keep`s its claim.
#[must_use = "the card is claimed for as long as this lives"]
struct CardClaim<'a> {
    board: &'a Mutex<Board>,
    me: ThreadId,
    /// Whether the board records this claim. Not when the fatal error's own thread went on
    /// without one, because the holder of the card was taken to be what failed.
    recorded: bool,
}

impl CardClaim<'_> {
    /// Keeps the claim for good: it is never let go of. For the way out, which restarts the board
    /// next, so that nothing mounts the card under the restart.
    fn keep(self) {
        mem::forget(self);
    }
}

impl Drop for CardClaim<'_> {
    fn drop(&mut self) {
        if !self.recorded {
            return;
        }
        // Bounded, like every wait on the board's mutex: if it is never free the card stays
        // claimed, and the next claims give up when their wait is over.
        if let Some(mut board) = lock_within(self.board, LOG_LOCK_WAIT)
            && board.card == Some(self.me)
        {
            board.card = None;
        }
    }
}

/// What one look at the board says to a thread that wants the card.
enum Look {
    /// The card is this thread's.
    Claimed,
    /// A fatal error has begun on another thread: the card is the rescue's.
    Refused,
    /// Another thread has the card, or the board's mutex was held at this moment.
    Held,
}

/// One look at `board` for the thread `me`: the fatal error and the card are asked about, and the
/// card is taken, under the one hold of the mutex, so that no fatal error can begin between the
/// question and the claim. Never waits.
fn look_for_card(board: &Mutex<Board>, me: ThreadId) -> Look {
    let Some(mut board) = lock_if_free(board) else {
        return Look::Held;
    };
    if !board_is_ours(board.fatal, me) {
        Look::Refused
    } else if board.card.is_some() {
        Look::Held
    } else {
        board.card = Some(me);
        Look::Claimed
    }
}

/// Claims the card for the calling thread on `board`, waiting up to `wait` while another thread has it.
///
/// This is the only way to the card, and the question whether a fatal error has begun on another
/// thread is part of it, not a step before it: one that has refuses the claim at once
/// (`card_under_rescue`), and the rescue is then alone with the card. A card that is held is
/// polled for. When the wait runs out the holder is taken to be what failed, as with the log's
/// lock, and the fatal error's own thread goes on without a claim, because a rescue that waited
/// for ever would never restart the board. Which thread that is, `fatal_thread` says, a read
/// that needs no mutex and is made only then. Every other thread gives up: `card_under_rescue`
/// if a fatal error has begun, and `card_busy` if none has. A thread must not use a card it was
/// not given, however long it has waited.
fn claim_card<'a>(
    board: &'a Mutex<Board>,
    wait: Duration,
    fatal_thread: &dyn Fn() -> Option<ThreadId>,
) -> io::Result<CardClaim<'a>> {
    let me = thread::current().id();
    let mut looked = Look::Held;
    wait_until(wait, LOCK_POLL, PET_EVERY, &mut || {}, &mut || {
        looked = look_for_card(board, me);
        !matches!(looked, Look::Held)
    });
    match looked {
        Look::Claimed => Ok(CardClaim {
            board,
            me,
            recorded: true,
        }),
        Look::Refused => Err(card_under_rescue()),
        Look::Held => match fatal_thread() {
            Some(first) if first == me => Ok(CardClaim {
                board,
                me,
                recorded: false,
            }),
            Some(_) => Err(card_under_rescue()),
            None => Err(card_busy()),
        },
    }
}

/// Why a thread that is not the fatal error's own was not given the card.
#[derive(Debug)]
struct CardUnderRescue;

impl std::fmt::Display for CardUnderRescue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the card is in use by the rescue of a fatal error")
    }
}

impl std::error::Error for CardUnderRescue {}

/// The error of a use of the card that gave up because a fatal error's rescue has it.
fn card_under_rescue() -> io::Error {
    io::Error::other(CardUnderRescue)
}

/// Whether `error` is `card_under_rescue`'s.
fn held_by_rescue(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<CardUnderRescue>())
}

/// Why a thread was not given the card that another thread kept for longer than the claim waits.
#[derive(Debug)]
struct CardBusy;

impl std::fmt::Display for CardBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the card is in use by another thread")
    }
}

impl std::error::Error for CardBusy {}

/// The error of a use of the card that gave up because another thread has had it for too long.
fn card_busy() -> io::Error {
    io::Error::other(CardBusy)
}

/// Whether `error` says that the card was not given: `card_under_rescue` or `card_busy`, and not
/// a mount that failed.
fn refused_the_card(error: &io::Error) -> bool {
    held_by_rescue(error) || error.get_ref().is_some_and(|inner| inner.is::<CardBusy>())
}

/// Logs how an unmount went, if it failed: the card was used, and is not needed any more.
fn log_unmount(unmounted: io::Result<()>) {
    if let Err(error) = unmounted {
        log::warn!("unmounting {BOOT_DEV}: {error}");
    }
}

/// Like `on_card`, for the boot sequence: a failed unmount is logged and otherwise ignored.
fn with_card<T>(
    card: &mut dyn Card,
    access: Access,
    work: impl FnOnce(&Path) -> T,
) -> io::Result<T> {
    let (done, unmounted) = on_card(card, access, work)?;
    log_unmount(unmounted);
    Ok(done)
}

/// Waits until the kernel has found the card or `timeout` has passed, calling `pet` meanwhile; says which.
fn wait_for_card(card: &dyn Card, timeout: Duration, pet: &mut dyn FnMut()) -> bool {
    wait_until(timeout, POLL_EVERY, PET_EVERY, pet, &mut || card.present())
}

/// Waits until `ready` holds or the timeout has passed, petting the watchdog meanwhile.
fn wait_for(timeout: Duration, mut ready: impl FnMut() -> bool) -> bool {
    wait_until(
        timeout,
        POLL_EVERY,
        PET_EVERY,
        &mut pet_watchdog,
        &mut ready,
    )
}

/// Sleeps, petting the watchdog meanwhile.
fn pause(length: Duration) {
    wait_until(length, length, PET_EVERY, &mut pet_watchdog, &mut || false);
}

/// The one wait in init: until `ready` holds or `timeout` has passed; says which.
///
/// `ready` is asked at once, then every `poll_every`, and a last time when
/// the timeout has passed. `pet` is called at once and then every
/// `pet_every`, however rarely `ready` is asked, and once more on the way
/// out unless it was called just then: what comes after a wait starts with
/// the watchdog's whole time ahead of it.
fn wait_until(
    timeout: Duration,
    poll_every: Duration,
    pet_every: Duration,
    pet: &mut dyn FnMut(),
    ready: &mut dyn FnMut() -> bool,
) -> bool {
    let start = Instant::now();
    let mut next_pet = start;
    loop {
        let now = Instant::now();
        let pet_due = now >= next_pet;
        if pet_due {
            pet();
            next_pet = now + pet_every;
        }
        let held = ready();
        let left = timeout.saturating_sub(start.elapsed());
        if held || left.is_zero() {
            if !pet_due {
                pet();
            }
            return held;
        }
        let until_pet = next_pet.saturating_duration_since(Instant::now());
        thread::sleep(left.min(poll_every).min(until_pet));
    }
}

/// Pets the watchdog, unless a fatal error has begun on another thread.
///
/// Also not when the watchdog's lock is held. Either the other thread was
/// petting at that moment, and missing one pet of three is harmless, or the
/// holder is what failed.
fn pet_watchdog() {
    if !may_pet(FATAL_THREAD.get().copied(), thread::current().id()) {
        return;
    }
    if let Some(mut watchdog) = lock_if_free(&WATCHDOG) {
        watchdog.pet();
    }
}

/// Takes a lock, whether or not a thread panicked while holding it.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Takes a lock if nothing holds it, and never waits for it.
fn lock_if_free<T>(mutex: &Mutex<T>) -> Option<MutexGuard<'_, T>> {
    match mutex.try_lock() {
        Ok(guard) => Some(guard),
        Err(TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
        Err(TryLockError::WouldBlock) => None,
    }
}

/// Takes a lock, waiting up to `within` for whatever holds it to let go.
///
/// Gives `None` when the lock was held throughout, which is taken to mean
/// that its holder is stuck. The lock is asked for at once, so that none
/// that is free costs any time.
fn lock_within<T>(mutex: &Mutex<T>, within: Duration) -> Option<MutexGuard<'_, T>> {
    let mut guard = None;
    wait_until(within, LOCK_POLL, PET_EVERY, &mut || {}, &mut || {
        guard = lock_if_free(mutex);
        guard.is_some()
    });
    guard
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::{Cell, RefCell};
    use std::fs;
    use std::io::ErrorKind;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, mpsc};

    use qb_panel::Calibration;
    use tempfile::TempDir;

    use crate::live::Snapshot;
    use crate::modules::DEFAULT_TABLE;
    use crate::services::testutil::Jam;

    const EXAMPLE: &str = include_str!("../../../qberrypi.example.toml");
    /// A `config.txt` that starts Raspberry Pi OS.
    const PIOS: &str = "# raspberry pi os\narm_64bit=1\n";
    /// A `config.txt` that starts qberrypi.
    const QBERRYPI: &str = "arm_64bit=1\nos_prefix=qberrypi/\n";

    /// The example configuration with one piece of text swapped.
    fn cfg_with(find: &str, replace: &str) -> Config {
        assert!(EXAMPLE.contains(find), "the example has no {find:?}");
        config::parse(&EXAMPLE.replace(find, replace)).unwrap()
    }

    fn cfg_with_one_shot(on: bool) -> Config {
        cfg_with("one_shot = false", &format!("one_shot = {on}"))
    }

    fn cfg_with_log_to_sd(on: bool) -> Config {
        cfg_with("log_to_sd = false", &format!("log_to_sd = {on}"))
    }

    /// The example configuration with its two card-writing switches set.
    fn cfg_debug(one_shot: bool, log_to_sd: bool) -> Config {
        let text = EXAMPLE
            .replace("one_shot = false", &format!("one_shot = {one_shot}"))
            .replace("log_to_sd = false", &format!("log_to_sd = {log_to_sd}"));
        let cfg = config::parse(&text).unwrap();
        assert_eq!(
            (cfg.debug.one_shot, cfg.debug.log_to_sd),
            (one_shot, log_to_sd)
        );
        cfg
    }

    fn log_holding(lines: &[&str]) -> Mutex<LogBuf> {
        let mut buf = LogBuf::new(4096);
        for line in lines {
            buf.push(line);
        }
        Mutex::new(buf)
    }

    fn header() -> String {
        format!("==== boot, build {} ====\n", crate::BUILD_EPOCH)
    }

    /// A boot partition that is a temporary directory and records what is done to it.
    struct FakeCard {
        dir: TempDir,
        ops: Vec<&'static str>,
        mounted: bool,
        mount_fails: bool,
        unmount_fails: bool,
        /// How many more times the card is asked for before the kernel has found it.
        absent_for: Cell<usize>,
    }

    impl FakeCard {
        /// A card that starts qberrypi and holds Raspberry Pi OS's saved configuration.
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            fs::write(dir.path().join("config.txt"), QBERRYPI).unwrap();
            fs::write(dir.path().join("config.pios.txt"), PIOS).unwrap();
            fs::create_dir(dir.path().join("qberrypi")).unwrap();
            fs::write(dir.path().join("qberrypi/qberrypi.toml"), EXAMPLE).unwrap();
            Self {
                dir,
                ops: Vec::new(),
                mounted: false,
                mount_fails: false,
                unmount_fails: false,
                absent_for: Cell::new(0),
            }
        }

        /// A card the kernel finds only after it was asked for this many times.
        fn found_after(asks: usize) -> Self {
            let card = Self::new();
            card.absent_for.set(asks);
            card
        }

        fn read(&self, name: &str) -> String {
            fs::read_to_string(self.dir.path().join(name)).unwrap()
        }

        fn has(&self, name: &str) -> bool {
            self.dir.path().join(name).exists()
        }

        fn write(&self, name: &str, text: &str) {
            fs::write(self.dir.path().join(name), text).unwrap();
        }

        fn remove(&self, name: &str) {
            fs::remove_file(self.dir.path().join(name)).unwrap();
        }
    }

    impl Card for FakeCard {
        fn present(&self) -> bool {
            let left = self.absent_for.get();
            self.absent_for.set(left.saturating_sub(1));
            left == 0
        }

        fn dir(&self) -> &Path {
            self.dir.path()
        }

        fn mount(&mut self, access: Access) -> io::Result<()> {
            self.ops.push(match access {
                Access::ReadOnly => "mount read-only",
                Access::Writable => "mount writable",
            });
            if self.absent_for.get() > 0 {
                return Err(ErrorKind::NotFound.into());
            }
            if self.mount_fails || self.mounted {
                return Err(ErrorKind::ResourceBusy.into());
            }
            self.mounted = true;
            Ok(())
        }

        fn sync(&mut self) {
            self.ops.push("sync");
        }

        fn unmount(&mut self) -> io::Result<()> {
            self.ops.push("unmount");
            if self.unmount_fails || !self.mounted {
                return Err(ErrorKind::InvalidInput.into());
            }
            self.mounted = false;
            Ok(())
        }
    }

    /// What a read of the card does: it first unmounts whatever was left mounted.
    const READ_OPS: [&str; 3] = ["unmount", "mount read-only", "unmount"];
    /// What a write to the card does: the same, with a sync before the last unmount.
    const WRITE_OPS: [&str; 4] = ["unmount", "mount writable", "sync", "unmount"];

    #[test]
    fn banner_names_version_and_build() {
        assert_eq!(
            banner(),
            format!("qberrypi {} (build {})", crate::VERSION, crate::BUILD_EPOCH)
        );
    }

    #[test]
    fn fatal_restores_unless_a_parsed_config_says_permanent() {
        assert!(restore_on_fatal(None));
        assert!(restore_on_fatal(Some(&cfg_with_one_shot(true))));
        assert!(!restore_on_fatal(Some(&cfg_with_one_shot(false))));
    }

    // The wait that every pause in init goes through.

    const MS: Duration = Duration::from_millis(1);
    const LONG: Duration = Duration::from_secs(60);

    #[test]
    fn waiting_pets_the_watchdog_until_the_timeout() {
        let mut pets = 0;
        let start = Instant::now();
        let held = wait_until(200 * MS, 5 * MS, 20 * MS, &mut || pets += 1, &mut || false);
        assert!(!held);
        assert!(start.elapsed() >= 200 * MS);
        // One at once and one every 20 ms after it: eleven if none is late.
        assert!((4..=11).contains(&pets), "{pets} pets");
    }

    #[test]
    fn a_slow_poll_does_not_delay_the_pets() {
        let mut pets = 0;
        let mut asks = 0;
        let held = wait_until(150 * MS, LONG, 20 * MS, &mut || pets += 1, &mut || {
            asks += 1;
            false
        });
        assert!(!held);
        assert!(pets >= 3, "{pets} pets");
        assert!(asks >= 2, "{asks} asks");
    }

    #[test]
    fn waiting_ends_as_soon_as_the_condition_holds() {
        let mut asks = 0;
        let start = Instant::now();
        let held = wait_until(LONG, 5 * MS, LONG, &mut || {}, &mut || {
            asks += 1;
            asks == 3
        });
        assert!(held);
        assert_eq!(asks, 3);
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_condition_that_already_holds_is_seen_at_once_and_the_watchdog_is_still_petted() {
        let mut pets = 0;
        let mut asks = 0;
        let start = Instant::now();
        let held = wait_until(LONG, LONG, LONG, &mut || pets += 1, &mut || {
            asks += 1;
            true
        });
        assert!(held);
        assert_eq!((pets, asks), (1, 1));
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn with_no_time_to_wait_the_condition_is_asked_once() {
        let mut pets = 0;
        let mut asks = 0;
        let held = wait_until(Duration::ZERO, LONG, LONG, &mut || pets += 1, &mut || {
            asks += 1;
            false
        });
        assert!(!held);
        assert_eq!((pets, asks), (1, 1));
    }

    #[test]
    fn the_condition_gets_a_last_look_when_the_timeout_has_passed() {
        let mut asks = 0;
        let start = Instant::now();
        let held = wait_until(50 * MS, LONG, LONG, &mut || {}, &mut || {
            asks += 1;
            asks == 2
        });
        assert!(held);
        assert!(start.elapsed() >= 50 * MS);
    }

    /// Runs a wait and returns its pets and asks in the order they came.
    fn wait_events(
        timeout: Duration,
        poll_every: Duration,
        mut ready: impl FnMut(usize) -> bool,
    ) -> (bool, Vec<&'static str>) {
        let events = RefCell::new(Vec::new());
        let mut asks = 0;
        let held = wait_until(
            timeout,
            poll_every,
            LONG,
            &mut || events.borrow_mut().push("pet"),
            &mut || {
                events.borrow_mut().push("ask");
                asks += 1;
                ready(asks)
            },
        );
        (held, events.into_inner())
    }

    #[test]
    fn a_wait_that_times_out_ends_with_a_pet() {
        // Long after the first pet and long before the next is due: whatever
        // comes after the wait must not start on a budget that is half spent.
        let (held, events) = wait_events(50 * MS, LONG, |_| false);
        assert!(!held);
        assert_eq!(events, ["pet", "ask", "ask", "pet"]);
    }

    #[test]
    fn a_wait_that_the_condition_ends_later_ends_with_a_pet() {
        let (held, events) = wait_events(LONG, 10 * MS, |asks| asks == 3);
        assert!(held);
        assert_eq!(events, ["pet", "ask", "ask", "ask", "pet"]);
    }

    #[test]
    fn a_wait_that_ends_at_once_pets_only_once() {
        let (held, events) = wait_events(LONG, LONG, |_| true);
        assert!(held);
        assert_eq!(events, ["pet", "ask"]);
        let (held, events) = wait_events(Duration::ZERO, LONG, |_| false);
        assert!(!held);
        assert_eq!(events, ["pet", "ask"]);
    }

    #[test]
    fn a_wait_sees_a_path_that_appears_late_and_times_out_on_one_that_never_does() {
        let tmp = tempfile::tempdir().unwrap();
        let late = tmp.path().join("late");
        let start = Instant::now();
        let creator = thread::spawn({
            let late = late.clone();
            move || {
                thread::sleep(150 * MS);
                File::create(late).unwrap();
            }
        });
        let found = wait_until(2000 * MS, 5 * MS, LONG, &mut || {}, &mut || late.exists());
        let waited = start.elapsed();
        assert!(found);
        assert!(waited >= 150 * MS && waited < 2000 * MS, "{waited:?}");
        creator.join().unwrap();

        let never = tmp.path().join("never");
        let start = Instant::now();
        let found = wait_until(200 * MS, 5 * MS, LONG, &mut || {}, &mut || never.exists());
        assert!(!found);
        assert!(start.elapsed() >= 200 * MS);
    }

    #[test]
    fn the_card_is_waited_for_two_minutes_at_boot_and_half_a_minute_on_the_way_out() {
        // Giving up at boot is a fatal error, and the way out of that needs
        // the card as well. No watchdog runs yet, so a long wait costs
        // nothing. The way out gives up sooner: a board with no card at all
        // still restarts.
        assert_eq!(BOOT_DEV_WAIT, Duration::from_secs(120));
        assert_eq!(RESCUE_DEV_WAIT, Duration::from_secs(30));
    }

    #[test]
    fn a_card_the_kernel_finds_late_is_waited_for_and_the_watchdog_petted_meanwhile() {
        let card = FakeCard::found_after(3);
        let mut pets = 0;
        assert!(wait_for_card(&card, LONG, &mut || pets += 1));
        assert_eq!(card.absent_for.get(), 0);
        assert!(pets >= 1, "{pets} pets");
    }

    #[test]
    fn a_card_that_never_appears_is_given_up_on_when_the_time_has_passed() {
        let card = FakeCard::found_after(usize::MAX);
        let start = Instant::now();
        assert!(!wait_for_card(&card, 120 * MS, &mut || {}));
        assert!(start.elapsed() >= 120 * MS);
    }

    #[test]
    fn a_lock_that_is_held_is_not_waited_for() {
        let mutex = Mutex::new(7);
        {
            let _held = mutex.lock().unwrap();
            assert!(lock_if_free(&mutex).is_none());
        }
        assert_eq!(lock_if_free(&mutex).as_deref(), Some(&7));
    }

    #[test]
    fn a_lock_that_another_thread_lets_go_of_in_time_is_obtained() {
        let mutex = Mutex::new(7);
        let (held, ready) = mpsc::channel();
        thread::scope(|scope| {
            scope.spawn(|| {
                let guard = mutex.lock().unwrap();
                held.send(()).unwrap();
                thread::sleep(50 * MS);
                drop(guard);
            });
            ready.recv().unwrap();
            assert!(lock_if_free(&mutex).is_none());
            assert_eq!(lock_within(&mutex, LONG).as_deref(), Some(&7));
        });
    }

    #[test]
    fn a_lock_held_throughout_gives_nothing_after_about_the_time_asked() {
        let mutex = Mutex::new(7);
        let _held = mutex.lock().unwrap();
        let start = Instant::now();
        assert!(lock_within(&mutex, 100 * MS).is_none());
        assert!(start.elapsed() >= 100 * MS);
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_lock_nothing_holds_is_obtained_without_waiting() {
        let mutex = Mutex::new(7);
        assert_eq!(lock_within(&mutex, Duration::ZERO).as_deref(), Some(&7));
    }

    // The card, from two threads.

    #[test]
    fn two_threads_never_have_the_card_at_once() {
        static INSIDE: AtomicUsize = AtomicUsize::new(0);
        // The test's own board, so that no other test's hold on the global one can come between.
        let board = own_board();
        let user = || {
            (0..50).all(|_| {
                let mut card = FakeCard::new();
                on_card_within(&mut card, Access::Writable, &board, LONG, &|| None, |_| {
                    let others = INSIDE.fetch_add(1, Ordering::SeqCst);
                    thread::yield_now();
                    INSIDE.fetch_sub(1, Ordering::SeqCst);
                    others == 0
                })
                .unwrap()
                .0
            })
        };
        thread::scope(|scope| {
            let (a, b) = (scope.spawn(user), scope.spawn(user));
            assert!(a.join().unwrap() && b.join().unwrap());
        });
    }

    /// A board of a test's own, with nobody's claim on the card and no fatal error.
    fn own_board() -> Mutex<Board> {
        Mutex::new(Board::new())
    }

    /// A board of a test's own on which `holder` has the card and a fatal error of `fatal` has begun.
    fn board_of(holder: Option<ThreadId>, fatal: Option<ThreadId>) -> Mutex<Board> {
        Mutex::new(Board {
            card: holder,
            fatal,
        })
    }

    #[test]
    fn a_card_that_is_never_let_go_of_is_given_up_on_by_every_thread_but_the_fatal_errors_own() {
        // Another thread's claim, which it never lets go of.
        let board = board_of(Some(another_thread()), None);
        // No fatal error, and one that is the thread's own: only the second goes on.
        for own_fatal_error in [false, true] {
            let (result, ops, waited) = thread::scope(|scope| {
                scope
                    .spawn(|| {
                        let mut card = FakeCard::new();
                        let fatal_thread = own_fatal_error.then(|| thread::current().id());
                        let start = Instant::now();
                        let result = on_card_within(
                            &mut card,
                            Access::Writable,
                            &board,
                            50 * MS,
                            &|| fatal_thread,
                            |boot| bootpart::restore_pios_config(boot).is_ok(),
                        );
                        (result, card.ops, start.elapsed())
                    })
                    .join()
                    .unwrap()
            });
            // The wait was made in both cases.
            assert!(waited >= 50 * MS);
            if own_fatal_error {
                // The rescue goes on without the claim, because the holder is taken to be stuck.
                assert!(result.unwrap().0);
                assert_eq!(ops, WRITE_OPS);
            } else {
                // Any other thread gives up, and does not touch the card.
                let error = result.unwrap_err();
                assert!(!held_by_rescue(&error), "{error}");
                assert!(refused_the_card(&error), "{error}");
                assert_eq!(error.to_string(), "the card is in use by another thread");
                assert!(ops.is_empty());
            }
        }
    }

    #[test]
    fn a_card_that_a_rescue_holds_is_refused_to_another_thread_at_once_and_not_after_a_wait() {
        let rescue_thread = another_thread();
        let board = board_of(Some(rescue_thread), Some(rescue_thread));
        let mut card = FakeCard::new();
        let mut ran = false;

        let began = Instant::now();
        let result = on_card_within(
            &mut card,
            Access::Writable,
            &board,
            LONG,
            &|| Some(rescue_thread),
            |_| {
                ran = true;
            },
        );

        // Not an unmount, a mount or a write: the rescue has the card. And no wait: a fatal error
        // that has begun is the answer, whether or not the card is held.
        let error = result.unwrap_err();
        assert!(held_by_rescue(&error), "{error}");
        assert!(
            began.elapsed() < Duration::from_secs(5),
            "{:?}",
            began.elapsed()
        );
        assert!(card.ops.is_empty());
        assert!(!ran);
    }

    #[test]
    fn a_card_that_is_free_is_refused_to_every_thread_but_the_fatal_errors_own_once_one_has_begun()
    {
        let rescue_thread = another_thread();
        // Nothing holds the card, and a fatal error has begun on another thread: not this one's.
        let board = board_of(None, Some(rescue_thread));
        let mut card = FakeCard::new();
        let error = on_card_within(
            &mut card,
            Access::Writable,
            &board,
            50 * MS,
            &|| Some(rescue_thread),
            |_| 7,
        )
        .unwrap_err();
        assert!(held_by_rescue(&error), "{error}");
        assert!(card.ops.is_empty());
        assert_eq!(lock(&board).card, None);

        // The fatal error's own thread is given it, and with no fatal error at all so is any.
        let me = thread::current().id();
        for fatal in [Some(me), None] {
            let board = board_of(None, fatal);
            let mut card = FakeCard::new();
            let done = on_card_within(
                &mut card,
                Access::Writable,
                &board,
                50 * MS,
                &|| fatal,
                |_| 7,
            );
            assert_eq!(done.unwrap().0, 7);
            assert_eq!(card.ops, WRITE_OPS);
        }
    }

    #[test]
    fn the_claim_is_the_one_step_that_asks_whether_a_fatal_error_has_begun_and_takes_the_card() {
        // There is no other way to the card than `claim_card`, which takes no thread's word that
        // the check was made before: the fatal error and the holder are looked at, and the card is
        // taken, in one hold of the board's mutex (`look_for_card`). What that guarantees is
        // that no claim succeeds once a fatal error has begun: threads that claim and let go
        // as fast as they can, while another begins one, are all refused from then on.
        let board = own_board();
        let first = OnceLock::new();
        let begun = AtomicBool::new(false);
        let threads = 4;
        let (claims_after, refused_after) = thread::scope(|scope| {
            let claimants: Vec<_> = (0..threads)
                .map(|_| {
                    scope.spawn(|| {
                        let (mut after, mut refused) = (0, 0);
                        // Read first: a claim that is attempted after the fatal error has begun
                        // must be refused.
                        while !begun.load(Ordering::SeqCst) || after < 20 {
                            let was_begun = begun.load(Ordering::SeqCst);
                            // A wait that is long for a card that is held for a moment.
                            match claim_card(&board, Duration::from_secs(5), &|| None) {
                                Ok(_claim) if was_begun => after += 1,
                                Err(error) if was_begun => {
                                    assert!(held_by_rescue(&error), "{error}");
                                    after += 1;
                                    refused += 1;
                                }
                                _ => {}
                            }
                            // Not a spin that keeps the board's mutex from the fatal error.
                            thread::sleep(Duration::from_micros(100));
                        }
                        (after, refused)
                    })
                })
                .collect();
            thread::sleep(20 * MS);
            let rescue = another_thread();
            assert_eq!(begin_fatal_in(&board, &first, rescue), None);
            begun.store(true, Ordering::SeqCst);
            claimants
                .into_iter()
                .map(|claimant| claimant.join().unwrap())
                .fold((0, 0), |(a, b), (c, d)| (a + c, b + d))
        });
        // Every attempt that came after the fatal error began was refused.
        assert_eq!(claims_after, refused_after);
        assert!(refused_after > 0);
    }

    #[test]
    fn a_claim_is_let_go_of_when_it_is_dropped_and_a_later_one_succeeds() {
        let board = own_board();
        let me = thread::current().id();

        let claim = claim_card(&board, Duration::ZERO, &|| None).unwrap();
        assert_eq!(lock(&board).card, Some(me));
        drop(claim);
        assert_eq!(lock(&board).card, None);

        // The use of the card is a claim for its length.
        let mut card = FakeCard::new();
        let (_, unmounted) = on_card_within(
            &mut card,
            Access::Writable,
            &board,
            50 * MS,
            &|| None,
            |_| {
                assert_eq!(lock(&board).card, Some(me));
            },
        )
        .unwrap();
        unmounted.unwrap();
        assert_eq!(lock(&board).card, None);
        assert!(claim_card(&board, Duration::ZERO, &|| None).is_ok());
    }

    #[test]
    fn a_card_that_a_save_keeps_for_longer_than_the_wait_is_not_used_beside_it_except_by_the_rescue()
     {
        let board = own_board();
        let (held, holding) = mpsc::channel();
        let (let_go, letting_go) = mpsc::channel::<()>();
        thread::scope(|scope| {
            // A save of the pool, which has the card for as long as the test says.
            let holder = scope.spawn({
                let board = &board;
                move || {
                    let claim = claim_card(board, LONG, &|| None).unwrap();
                    held.send(thread::current().id()).unwrap();
                    letting_go.recv().unwrap();
                    drop(claim);
                }
            });
            let holder_id = holding.recv().unwrap();

            // The stall's save or the way out's, which are not the fatal error's: they give up
            // when the wait is over, with the card busy, and no operation on the card.
            let mut card = FakeCard::new();
            let mut ran = false;
            let began = Instant::now();
            let error = on_card_within(
                &mut card,
                Access::Writable,
                &board,
                100 * MS,
                &|| None,
                |_| ran = true,
            )
            .unwrap_err();
            assert!(began.elapsed() >= 100 * MS);
            assert!(
                !held_by_rescue(&error) && refused_the_card(&error),
                "{error}"
            );
            assert!(card.ops.is_empty() && !ran);
            let (level, line) = save_failure(&error);
            assert_eq!(level, Level::Warn);
            assert_eq!(
                line,
                "log.txt: not saved: the card is in use by another thread"
            );

            // The fatal error's own thread goes on, when the same wait is over.
            let rescue = scope.spawn(|| {
                let me = thread::current().id();
                let mut card = FakeCard::new();
                let done = on_card_within(
                    &mut card,
                    Access::Writable,
                    &board,
                    100 * MS,
                    &|| Some(me),
                    |_| 7,
                );
                (done.unwrap().0, card.ops)
            });
            assert_eq!(rescue.join().unwrap(), (7, WRITE_OPS.to_vec()));
            // Its going on did not take the holder's claim away or end it.
            assert_eq!(lock(&board).card, Some(holder_id));

            let_go.send(()).unwrap();
            holder.join().unwrap();
            assert_eq!(lock(&board).card, None);
        });
    }

    #[test]
    fn a_board_whose_mutex_is_stuck_gives_the_card_to_no_one_but_the_fatal_errors_own_thread() {
        let board = own_board();
        // Held throughout, as by a thread that failed in the middle of the LED's write.
        let _stuck = lock(&board);
        let (rescue_thread, own) = (another_thread(), thread::current().id());

        let error = claim_card(&board, 50 * MS, &|| None).err().unwrap();
        assert!(
            refused_the_card(&error) && !held_by_rescue(&error),
            "{error}"
        );
        let error = claim_card(&board, 50 * MS, &|| Some(rescue_thread))
            .err()
            .unwrap();
        assert!(held_by_rescue(&error), "{error}");
        // The rescue's own thread, whatever the mutex's state: its claim is not recorded.
        let claim = claim_card(&board, 50 * MS, &|| Some(own)).unwrap();
        assert!(!claim.recorded);
    }

    #[test]
    fn a_save_that_the_rescue_forbids_is_said_so_and_not_as_a_failed_mount() {
        let rescue = card_under_rescue();
        assert!(held_by_rescue(&rescue));
        assert_eq!(
            save_failure(&rescue),
            (
                Level::Warn,
                "log.txt: not saved: the card is in use by the rescue of a fatal error".to_owned()
            )
        );
        let mount = io::Error::from(ErrorKind::ResourceBusy);
        assert_eq!(
            save_failure(&mount),
            (
                Level::Error,
                format!("log.txt: mounting {BOOT_DEV}: {mount}")
            )
        );
    }

    // The main loop.

    #[test]
    fn the_board_returns_the_configured_time_after_it_started_or_never() {
        let secs = Duration::from_secs;
        // 0 means never.
        assert_eq!(return_after(0, secs(0)), None);
        assert_eq!(return_after(0, secs(1_000_000)), None);
        // What is left of the time, counted from the start of the boot.
        assert_eq!(return_after(60, secs(0)), Some(secs(60)));
        assert_eq!(return_after(60, secs(54)), Some(secs(6)));
        assert_eq!(
            return_after(60, Duration::from_millis(59_900)),
            Some(Duration::from_millis(100))
        );
        // Time that has passed already is no time at all, and no more.
        assert_eq!(return_after(60, secs(60)), Some(Duration::ZERO));
        assert_eq!(return_after(5, secs(600)), Some(Duration::ZERO));
        assert_eq!(
            return_after(u64::MAX, secs(600)).map(|left| left > secs(1)),
            Some(true)
        );
    }

    // The main loop and a fatal error on another thread.

    /// The id of a thread that has ended, so that it is no one's but its own.
    fn another_thread() -> ThreadId {
        thread::spawn(|| thread::current().id()).join().unwrap()
    }

    #[test]
    fn the_board_is_the_main_loops_unless_a_fatal_error_began_on_another_thread() {
        let me = thread::current().id();
        assert!(board_is_ours(None, me));
        assert!(board_is_ours(Some(me), me));
        assert!(!board_is_ours(Some(another_thread()), me));
    }

    #[test]
    fn the_log_is_not_saved_to_the_card_while_a_fatal_error_is_under_way_on_another_thread() {
        let cfg = cfg_with_log_to_sd(true);
        let log = log_holding(&["first"]);
        let mut card = FakeCard::new();
        let rescue = another_thread();

        let board = board_of(None, Some(rescue));

        let claim = save_log_to(&cfg, &mut card, &log, &board, &|| Some(rescue));

        // The rescue is using the card: nothing of ours is mounted, and the line waits.
        assert!(claim.is_none());
        assert!(card.ops.is_empty());
        assert!(!card.has("qberrypi/log.txt"));
        assert!(lock(&log).has_unsaved());
        // Nobody else's fatal error, or its own: the save goes ahead.
        let me = thread::current().id();
        for fatal_thread in [None, Some(me)] {
            let mut card = FakeCard::new();
            let log = log_holding(&["first"]);
            let board = board_of(None, fatal_thread);
            let claim = save_log_to(&cfg, &mut card, &log, &board, &|| fatal_thread);
            assert_eq!(card.read("qberrypi/log.txt"), header() + "first\n");
            // The claim that made it is still held, for the caller to keep or to let go of.
            assert_eq!(lock(&board).card, Some(me));
            drop(claim);
            assert_eq!(lock(&board).card, None);
        }
    }

    #[test]
    fn the_main_loop_restarts_when_it_is_done_and_leaves_the_restart_to_a_fatal_error_elsewhere() {
        let cfg = cfg_with_log_to_sd(true);
        let other = another_thread();

        // Nothing wrong: it saves the log and restarts.
        let mut card = FakeCard::new();
        let log = log_holding(&["first"]);
        let left = wind_down(
            &cfg,
            &mut card,
            &log,
            &Reason::ReturnAfter,
            &LogSaves::new(),
            &own_board(),
            &|| None,
        );
        assert_eq!(left, Leaving::Restart);
        assert_eq!(card.read("qberrypi/log.txt"), header() + "first\n");

        // A fatal error that began first is carrying the board out: no save, no restart.
        let mut card = FakeCard::new();
        let log = log_holding(&["first"]);
        let left = wind_down(
            &cfg,
            &mut card,
            &log,
            &Reason::ReturnAfter,
            &LogSaves::new(),
            &own_board(),
            &|| Some(other),
        );
        assert_eq!(left, Leaving::Park);
        assert!(card.ops.is_empty());

        // One that begins while the log is being saved is not restarted under either.
        let mut card = FakeCard::new();
        let log = log_holding(&["first"]);
        let looks = Cell::new(0);
        let left = wind_down(
            &cfg,
            &mut card,
            &log,
            &Reason::ReturnAfter,
            &LogSaves::new(),
            &own_board(),
            &|| {
                looks.set(looks.get() + 1);
                // The look before it starts finds none, and the save, which claims the card in
                // one step on the board and does not look here, takes none: the one after it does.
                (looks.get() > 1).then_some(other)
            },
        );
        assert_eq!(left, Leaving::Park);
        assert_eq!(card.ops, WRITE_OPS);
    }

    /// A save of the pool that begins on its own thread, on `board`, and finds the card claimed:
    /// says what the card was told to do.
    fn a_late_save_on(board: &Mutex<Board>) -> (io::Error, Vec<&'static str>) {
        thread::scope(|scope| {
            scope
                .spawn(|| {
                    let mut late = FakeCard::new();
                    let error = on_card_within(
                        &mut late,
                        Access::Writable,
                        board,
                        50 * MS,
                        &|| None,
                        |_| (),
                    )
                    .unwrap_err();
                    (error, late.ops)
                })
                .join()
                .unwrap()
        })
    }

    #[test]
    fn the_way_outs_claim_on_the_card_outlives_its_save_so_that_no_save_can_begin_under_the_restart()
     {
        let cfg = cfg_with_log_to_sd(true);
        let board = own_board();
        let mut card = FakeCard::new();
        let log = log_holding(&["first"]);

        let left = wind_down(
            &cfg,
            &mut card,
            &log,
            &Reason::ReturnAfter,
            &LogSaves::new(),
            &board,
            &|| None,
        );

        // The save is over and the board restarts next: the card is still this thread's.
        assert_eq!(left, Leaving::Restart);
        assert_eq!(card.ops, WRITE_OPS);
        assert_eq!(lock(&board).card, Some(thread::current().id()));
        // A save of the pool that begins now finds the card claimed, gives up, and does not
        // touch it.
        let (error, ops) = a_late_save_on(&board);
        assert!(refused_the_card(&error), "{error}");
        assert!(ops.is_empty());
    }

    #[test]
    fn the_way_out_lets_go_of_the_card_when_a_fatal_error_has_the_board_after_all() {
        let cfg = cfg_with_log_to_sd(true);
        let other = another_thread();

        // One that begins while the log is being saved: the save had the card, and the answer is
        // to park, so that the rescue of that fatal error can have the card.
        let board = own_board();
        let mut card = FakeCard::new();
        let log = log_holding(&["first"]);
        let looks = Cell::new(0);
        let left = wind_down(
            &cfg,
            &mut card,
            &log,
            &Reason::ReturnAfter,
            &LogSaves::new(),
            &board,
            &|| {
                looks.set(looks.get() + 1);
                (looks.get() > 1).then_some(other)
            },
        );
        assert_eq!(left, Leaving::Park);
        assert_eq!(card.ops, WRITE_OPS);
        assert_eq!(lock(&board).card, None);

        // One that had begun already: not a claim at all.
        let board = board_of(None, Some(other));
        let mut card = FakeCard::new();
        let left = wind_down(
            &cfg,
            &mut card,
            &log_holding(&["first"]),
            &Reason::ReturnAfter,
            &LogSaves::new(),
            &board,
            &|| Some(other),
        );
        assert_eq!(left, Leaving::Park);
        assert!(card.ops.is_empty());
        assert_eq!(lock(&board).card, None);
    }

    #[test]
    fn the_way_out_keeps_no_claim_on_a_card_that_it_has_no_use_for() {
        let board = own_board();
        let mut card = FakeCard::new();
        let left = wind_down(
            &cfg_debug(false, false),
            &mut card,
            &log_holding(&["banner"]),
            &Reason::ReturnAfter,
            &LogSaves::new(),
            &board,
            &|| None,
        );
        assert_eq!(left, Leaving::Restart);
        assert!(card.ops.is_empty());
        assert_eq!(lock(&board).card, None);
    }

    #[test]
    fn leaving_saves_the_reason_only_where_the_log_is_kept_on_the_card() {
        let mut card = FakeCard::new();
        let left = leave(
            &cfg_debug(false, false),
            &mut card,
            &log_holding(&["banner"]),
            &Reason::ComponentFailed("dns"),
            &LogSaves::new(),
            &own_board(),
        );
        assert_eq!(left, Leaving::Restart);
        assert!(card.ops.is_empty());

        let mut card = FakeCard::new();
        let log = log_holding(&["banner"]);
        let left = leave(
            &cfg_debug(true, true),
            &mut card,
            &log,
            &Reason::ReturnAfter,
            &LogSaves::new(),
            &own_board(),
        );
        assert_eq!(left, Leaving::Restart);
        assert_eq!(card.ops, WRITE_OPS);
        assert!(card.read("qberrypi/log.txt").starts_with(&header()));
    }

    #[test]
    fn the_log_of_a_restart_says_why_and_a_return_says_returning() {
        assert_eq!(
            leaving_line(&Reason::ReturnAfter),
            (Level::Info, "returning".to_owned())
        );
        assert_eq!(
            leaving_line(&Reason::ComponentFailed("dns")),
            (
                Level::Error,
                "supervisor: restarting: component dns failed 3 times in a minute".to_owned()
            )
        );
        assert_eq!(
            leaving_line(&Reason::NoAssociation),
            (
                Level::Error,
                "supervisor: restarting: no Wi-Fi association for 90 s".to_owned()
            )
        );
    }

    // The Wi-Fi beside the main loop.

    fn joined() -> WifiStatus {
        WifiStatus::Joined {
            bssid: [0; 6],
            freq_mhz: 5180,
            signal_mbm: -5600,
        }
    }

    /// Every status but the joined one.
    fn not_joined() -> [WifiStatus; 4] {
        [
            WifiStatus::Starting,
            WifiStatus::Scanning,
            WifiStatus::Joining {
                bssid: [0; 6],
                freq_mhz: 5180,
            },
            WifiStatus::Waiting { secs: 4 },
        ]
    }

    #[test]
    fn a_board_without_the_led_is_told_of_it_once_whatever_the_state_asked_for() {
        let tmp = tempfile::tempdir().unwrap();
        let absent = tmp.path().join("absent");
        let warned = AtomicBool::new(false);

        assert_eq!(
            change_led(&absent, LedState::Joining, &warned).as_deref(),
            Some("activity LED: No such file or directory (os error 2)")
        );
        for state in [LedState::Serving, LedState::Joining, LedState::Fatal] {
            assert_eq!(change_led(&absent, state, &warned), None, "{state:?}");
        }
    }

    #[test]
    fn a_led_that_works_is_set_and_never_complained_of() {
        let tmp = tempfile::tempdir().unwrap();
        let warned = AtomicBool::new(false);

        assert_eq!(change_led(tmp.path(), LedState::Serving, &warned), None);
        let trigger = || fs::read_to_string(tmp.path().join("trigger")).unwrap();
        assert_eq!(trigger(), "heartbeat");
        assert_eq!(change_led(tmp.path(), LedState::Joining, &warned), None);
        assert_eq!(trigger(), "timer");
        // An LED that breaks later is complained of once, and not again.
        let absent = tmp.path().join("absent");
        assert!(change_led(&absent, LedState::Serving, &warned).is_some());
        assert_eq!(change_led(&absent, LedState::Joining, &warned), None);
    }

    /// What the LED in `dir` was last told: its trigger, if anything was written.
    fn trigger(dir: &Path) -> Option<String> {
        fs::read_to_string(dir.join("trigger")).ok()
    }

    #[test]
    fn the_led_follows_the_link_until_a_fatal_error_begins_and_then_shows_only_that() {
        let tmp = tempfile::tempdir().unwrap();
        let warned = AtomicBool::new(false);
        let board = own_board();
        let first = OnceLock::new();

        // Before a fatal error the supervisor's hook writes the link's state.
        assert_eq!(
            show_led_in(&board, tmp.path(), LedState::Joining, &warned),
            None
        );
        assert_eq!(trigger(tmp.path()).as_deref(), Some("timer"));

        // The fatal error begins on another thread, and then writes its own state.
        assert_eq!(begin_fatal_in(&board, &first, another_thread()), None);
        show_fatal(&board, tmp.path());
        assert_eq!(trigger(tmp.path()).as_deref(), Some("default-on"));

        // The supervisor's hook, still running on the runtime's thread, writes nothing now: not
        // the link's state, and not a complaint about the LED either.
        for state in [LedState::Serving, LedState::Joining] {
            assert_eq!(show_led_in(&board, tmp.path(), state, &warned), None);
            assert_eq!(
                trigger(tmp.path()).as_deref(),
                Some("default-on"),
                "{state:?}"
            );
        }
        // Not a complaint about an LED that is not there either: nothing was tried.
        let absent = tmp.path().join("absent");
        assert_eq!(
            show_led_in(&board, &absent, LedState::Serving, &warned),
            None
        );
        assert!(!warned.load(Ordering::SeqCst));
    }

    #[test]
    fn a_led_whose_board_is_held_by_something_stuck_is_not_written_by_the_link_but_is_by_a_fatal_error()
     {
        let tmp = tempfile::tempdir().unwrap();
        let warned = AtomicBool::new(false);
        let board = own_board();
        // Held throughout, as by a thread that failed while it had the board.
        let _stuck = lock(&board);

        // The supervisor's hook gives up after `LOG_LOCK_WAIT`, without a write, and says nothing.
        let began = Instant::now();
        assert_eq!(
            show_led_in(&board, tmp.path(), LedState::Serving, &warned),
            None
        );
        assert!(began.elapsed() >= LOG_LOCK_WAIT, "{:?}", began.elapsed());
        assert!(
            began.elapsed() < Duration::from_secs(5),
            "{:?}",
            began.elapsed()
        );
        assert_eq!(trigger(tmp.path()), None);

        // The fatal error writes all the same, after the same wait at most.
        let began = Instant::now();
        show_fatal(&board, tmp.path());
        assert!(
            began.elapsed() < Duration::from_secs(5),
            "{:?}",
            began.elapsed()
        );
        assert_eq!(trigger(tmp.path()).as_deref(), Some("default-on"));
    }

    #[test]
    fn a_fatal_error_records_its_thread_on_the_board_and_in_the_lock_free_record_together() {
        let board = own_board();
        let first = OnceLock::new();
        let (one, two) = (another_thread(), another_thread());

        assert_eq!(begin_fatal_in(&board, &first, one), None);
        assert_eq!(first.get(), Some(&one));
        assert_eq!(lock(&board).fatal, Some(one));
        // A second one finds the first, and does not take its place.
        assert_eq!(begin_fatal_in(&board, &first, two), Some(one));
        assert_eq!(lock(&board).fatal, Some(one));
        assert_eq!(begin_fatal_in(&board, &first, one), Some(one));
    }

    #[test]
    fn a_fatal_error_begins_all_the_same_when_the_board_is_held_by_something_stuck() {
        let board = own_board();
        let first = OnceLock::new();
        let rescue = another_thread();
        let _stuck = lock(&board);

        let began = Instant::now();
        assert_eq!(begin_fatal_in(&board, &first, rescue), None);

        // Bounded, and the lock-free record has it, which the claim's last word goes by.
        assert!(
            began.elapsed() < Duration::from_secs(5),
            "{:?}",
            began.elapsed()
        );
        assert_eq!(first.get(), Some(&rescue));
    }

    #[test]
    fn the_log_is_saved_every_thirty_seconds_but_not_during_a_join() {
        let secs = Duration::from_secs;
        assert!(save_due(secs(30), &joined(), true));
        assert!(save_due(secs(31), &WifiStatus::Waiting { secs: 8 }, true));
        assert!(!save_due(secs(29), &joined(), true));
        assert!(!save_due(secs(300), &joined(), false));
        let joining = WifiStatus::Joining {
            bssid: [0; 6],
            freq_mhz: 5180,
        };
        assert!(!save_due(secs(300), &joining, true));
    }

    #[test]
    fn a_join_without_an_address_is_tried_again_every_thirty_seconds() {
        let secs = Duration::from_secs;
        assert_eq!(REOPEN_EVERY, secs(30));
        // The wait is what is left of the thirty seconds since the last try.
        assert_eq!(
            configure_in(&joined(), false, Duration::ZERO),
            Some(secs(30))
        );
        assert_eq!(configure_in(&joined(), false, secs(29)), Some(secs(1)));
        assert_eq!(
            configure_in(&joined(), false, secs(30)),
            Some(Duration::ZERO)
        );
        assert_eq!(
            configure_in(&joined(), false, secs(3_600)),
            Some(Duration::ZERO)
        );
        // A join that has its address is left alone, however long it holds.
        assert_eq!(configure_in(&joined(), true, secs(3_600)), None);
        // Without a join there is nothing to address: the next join does it.
        for status in not_joined() {
            assert_eq!(
                configure_in(&status, false, secs(3_600)),
                None,
                "{status:?}"
            );
        }
    }

    #[test]
    fn the_address_is_logged_as_it_was_configured() {
        let cfg = config::parse(EXAMPLE).unwrap();

        assert_eq!(
            net_line(&cfg.net),
            "net: 192.0.2.53/24 on wlan0, default route via 192.0.2.1"
        );
    }

    #[test]
    fn the_wifi_components_route_socket_is_an_offloaded_one() {
        crate::testns::run_inside("init::tests::ns_wlan_route_socket");
    }

    #[tokio::test]
    #[ignore = "run by the_wifi_components_route_socket_is_an_offloaded_one, inside a namespace"]
    async fn ns_wlan_route_socket() {
        if !crate::testns::inside() {
            return;
        }
        let cfg = config::parse(EXAMPLE).unwrap();
        // A new namespace has no `wlan0`, so this refuses, but the socket is opened first, on first use.
        let mut route = None;
        let refused = configure_over(&mut route, &cfg.net).await;
        assert!(refused.is_err());
        assert!(route.expect("the socket was opened").is_offloaded());
    }

    #[tokio::test(start_paused = true)]
    async fn an_address_that_is_not_set_in_time_is_an_error_and_ends_the_wait() {
        // The main loop pets between its arms, and the watchdog needs a pet every 5 s.
        assert!(CONFIGURE_WITHIN < PET_EVERY);
        let began = tokio::time::Instant::now();

        let late = bounded(CONFIGURE_WITHIN, std::future::pending()).await;

        assert_eq!(late, Err("wlan0 not configured within 4 s".to_owned()));
        assert_eq!(began.elapsed(), CONFIGURE_WITHIN);
        // What is done in time is the work's own result, success or refusal.
        assert_eq!(bounded(CONFIGURE_WITHIN, async { Ok(()) }).await, Ok(()));
        let refused = bounded(CONFIGURE_WITHIN, async { Err("refused".to_owned()) }).await;
        assert_eq!(refused, Err("refused".to_owned()));
    }

    #[tokio::test(start_paused = true)]
    async fn a_bound_of_less_than_a_second_is_not_given_as_zero_seconds() {
        for (within, said) in [
            (
                Duration::from_millis(500),
                "wlan0 not configured within 500ms",
            ),
            (
                Duration::from_millis(1_500),
                "wlan0 not configured within 1.5s",
            ),
            (Duration::from_secs(4), "wlan0 not configured within 4 s"),
        ] {
            let late = bounded(within, std::future::pending()).await;
            assert_eq!(late, Err(said.to_owned()));
        }
    }

    // The log's saves while the board serves.

    /// A card whose mount takes a while, and that counts its mounts.
    struct SlowCard {
        card: FakeCard,
        mount_takes: Duration,
        mounts: Arc<AtomicUsize>,
    }

    impl SlowCard {
        fn new(mount_takes: Duration) -> (Self, Arc<AtomicUsize>) {
            let mounts = Arc::new(AtomicUsize::new(0));
            let card = Self {
                card: FakeCard::new(),
                mount_takes,
                mounts: mounts.clone(),
            };
            (card, mounts)
        }
    }

    impl Card for SlowCard {
        fn present(&self) -> bool {
            self.card.present()
        }

        fn dir(&self) -> &Path {
            self.card.dir()
        }

        fn mount(&mut self, access: Access) -> io::Result<()> {
            self.mounts.fetch_add(1, Ordering::SeqCst);
            thread::sleep(self.mount_takes);
            self.card.mount(access)
        }

        fn sync(&mut self) {
            self.card.sync();
        }

        fn unmount(&mut self) -> io::Result<()> {
            self.card.unmount()
        }
    }

    /// A configuration and a log that live as long as the process, as a boot's do.
    fn kept(log_to_sd: bool, lines: &[&str]) -> (&'static Config, &'static Mutex<LogBuf>) {
        let cfg = Box::leak(Box::new(cfg_with_log_to_sd(log_to_sd)));
        let log = Box::leak(Box::new(log_holding(lines)));
        (cfg, log)
    }

    /// Waits until the save that runs on the blocking pool has ended.
    async fn until_saved(saves: &LogSaves) {
        let waited = Instant::now();
        while saves.running() {
            assert!(
                waited.elapsed() < Duration::from_secs(5),
                "the save never ended"
            );
            tokio::time::sleep(10 * MS).await;
        }
    }

    /// Waits until a thread of the pool has taken the save that was started: from then on the way
    /// out waits for it.
    async fn until_started(saves: &LogSaves) {
        let waited = Instant::now();
        while !saves.started() {
            assert!(
                waited.elapsed() < Duration::from_secs(5),
                "the save never began"
            );
            tokio::time::sleep(MS).await;
        }
    }

    #[tokio::test]
    async fn a_save_from_the_tick_does_not_wait_for_the_card() {
        let (cfg, log) = kept(true, &["first"]);
        let saves = LogSaves::new();
        let (card, mounts) = SlowCard::new(300 * MS);

        let began = Instant::now();
        let started = saves.start(cfg, log, card);

        // The mount takes 300 ms, and the runtime thread was never asked to wait for it.
        assert!(started);
        assert!(began.elapsed() < 100 * MS, "{:?}", began.elapsed());
        assert!(saves.running());
        // It was saved all the same, on the pool.
        until_saved(&saves).await;
        assert_eq!(mounts.load(Ordering::SeqCst), 1);
        assert!(!lock(log).has_unsaved());
    }

    #[tokio::test]
    async fn only_one_save_runs_at_a_time_and_the_next_one_is_skipped() {
        let (cfg, log) = kept(true, &["first"]);
        let saves = LogSaves::new();
        let (slow, mounts) = SlowCard::new(200 * MS);
        let (second, second_mounts) = SlowCard::new(MS);

        assert!(saves.start(cfg, log, slow));
        // One is on its way: this one is left for the next tick, and never touches the card.
        assert!(!saves.start(cfg, log, second));
        until_saved(&saves).await;
        assert_eq!(mounts.load(Ordering::SeqCst), 1);
        assert_eq!(second_mounts.load(Ordering::SeqCst), 0);
        // Once it has ended another may start.
        let (third, third_mounts) = SlowCard::new(MS);
        assert!(saves.start(cfg, log, third));
        until_saved(&saves).await;
        assert_eq!(third_mounts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_boot_that_keeps_no_log_on_the_card_starts_no_save() {
        let (cfg, log) = kept(false, &["first"]);
        let saves = LogSaves::new();
        let (card, mounts) = SlowCard::new(MS);

        assert!(!saves.start(cfg, log, card));
        assert!(!saves.running());
        assert_eq!(mounts.load(Ordering::SeqCst), 0);
        assert!(lock(log).has_unsaved());
    }

    #[tokio::test]
    async fn a_save_is_due_thirty_seconds_after_the_last_one_began_and_not_while_one_runs() {
        let secs = Duration::from_secs;
        let (cfg, log) = kept(true, &["first"]);
        let saves = LogSaves::new();
        let (slow, _) = SlowCard::new(100 * MS);
        // The thirty seconds are counted from when the board began to serve.
        assert!(!saves.is_due_at(Instant::now() + secs(29), &joined(), true));
        assert!(saves.is_due_at(Instant::now() + secs(31), &joined(), true));

        let began = Instant::now();
        assert!(saves.start(cfg, log, slow));
        // From the start of this one, and not while it runs.
        assert!(!saves.is_due_at(began + secs(29), &joined(), true));
        assert!(!saves.is_due_at(Instant::now() + secs(60), &joined(), true));
        until_saved(&saves).await;
        assert!(!saves.is_due_at(began + secs(29), &joined(), true));
        assert!(saves.is_due_at(Instant::now() + secs(31), &joined(), true));
        // And only if there is something new to save, and no join under way.
        assert!(!saves.is_due_at(Instant::now() + secs(31), &joined(), false));
        assert!(!saves.is_due_at(Instant::now() + secs(31), &not_joined()[2], true));
    }

    #[tokio::test]
    async fn the_ticks_save_step_starts_a_due_save_and_does_not_wait_for_the_card() {
        let (cfg, log) = kept(true, &["first"]);
        let saves = LogSaves::new();
        let (idle, idle_mounts) = SlowCard::new(MS);
        // Nothing is due for thirty seconds: nothing is started, and the card is not touched.
        assert!(!start_save_if_due(
            cfg,
            log,
            &saves,
            &joined(),
            Instant::now(),
            idle
        ));
        assert_eq!(idle_mounts.load(Ordering::SeqCst), 0);

        let (card, mounts) = SlowCard::new(300 * MS);
        let began = Instant::now();
        let started = start_save_if_due(
            cfg,
            log,
            &saves,
            &joined(),
            Instant::now() + LOG_SAVE_EVERY,
            card,
        );

        // The mount takes 300 ms, and the runtime thread was never asked to wait for it.
        assert!(started);
        assert!(began.elapsed() < 100 * MS, "{:?}", began.elapsed());
        until_saved(&saves).await;
        assert_eq!(mounts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_wait_for_the_saves_ends_at_once_when_none_runs_and_pets_while_one_does() {
        let (cfg, log) = kept(true, &["first"]);
        let saves = LogSaves::new();
        let pets = Cell::new(0);
        let began = Instant::now();
        assert!(saves.wait_idle(LONG, &mut || pets.set(pets.get() + 1)));
        assert!(began.elapsed() < 100 * MS);

        // One that runs for 300 ms: the wait lasts as long, and the watchdog is petted.
        let (slow, _) = SlowCard::new(300 * MS);
        assert!(saves.start(cfg, log, slow));
        until_started(&saves).await;
        let before = pets.get();
        let began = Instant::now();
        assert!(saves.wait_idle(LONG, &mut || pets.set(pets.get() + 1)));
        assert!(began.elapsed() >= 200 * MS, "{:?}", began.elapsed());
        assert!(!saves.running());
        assert!(pets.get() >= before + 2);
    }

    #[tokio::test]
    async fn a_wait_for_a_save_that_does_not_end_gives_up_when_the_time_has_passed() {
        let (cfg, log) = kept(true, &["first"]);
        let saves = LogSaves::new();
        let (slow, _) = SlowCard::new(400 * MS);
        assert!(saves.start(cfg, log, slow));
        until_started(&saves).await;

        assert!(!saves.wait_idle(100 * MS, &mut || {}));
        assert!(saves.running());
        until_saved(&saves).await;
    }

    #[test]
    fn a_save_queued_behind_a_full_pool_is_not_waited_for_and_never_mounts_the_card() {
        let rt = services::runtime(None).unwrap();
        rt.block_on(async {
            let (cfg, log) = kept(true, &["first", "second"]);
            let saves = LogSaves::new();
            let jam = Jam::fill().await;
            let (queued, mounts) = SlowCard::new(MS);
            // Due and started, and queued: no thread of the pool is free to begin it.
            assert!(saves.start(cfg, log, queued));
            let mut card = FakeCard::new();

            let began = Instant::now();
            let board = own_board();
            let left = wind_down(
                cfg,
                &mut card,
                log,
                &Reason::ReturnAfter,
                &saves,
                &board,
                &|| None,
            );

            // It did not wait, as it would for a save that holds the card, for `CARD_LOCK_WAIT`
            // of 5 s. Whatever else holds the card meanwhile, as the tests that run beside this
            // one do, is allowed for.
            assert!(
                began.elapsed() < Duration::from_secs(3),
                "{:?}",
                began.elapsed()
            );
            assert_eq!(left, Leaving::Restart);
            // It saved the log itself, in the one mount that there was.
            assert!(card.has("qberrypi/log.txt"));
            assert_eq!(card.ops, WRITE_OPS);
            // The save that was queued begins once the pool frees up, and finds the board leaving.
            jam.release();
            until_saved(&saves).await;
            assert_eq!(mounts.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn a_stalling_supervisor_does_not_wait_for_a_queued_save_and_it_never_mounts_the_card() {
        let rt = services::runtime(None).unwrap();
        rt.block_on(async {
            let (cfg, log) = kept(true, &["first", "second"]);
            let saves = LogSaves::new();
            let jam = Jam::fill().await;
            let (queued, mounts) = SlowCard::new(MS);
            assert!(saves.start(cfg, log, queued));
            let mut card = FakeCard::new();

            let began = Instant::now();
            stall_save(
                cfg,
                &mut card,
                log,
                &saves,
                Duration::from_secs(10),
                &own_board(),
            );

            // The watchdog is running out: a save that has not begun is not worth waiting for,
            // and the wait that was given is 10 s. Time for the card, which the tests that run
            // beside this one may hold, is allowed for.
            assert!(
                began.elapsed() < Duration::from_secs(5),
                "{:?}",
                began.elapsed()
            );
            assert!(card.has("qberrypi/log.txt"));
            jam.release();
            until_saved(&saves).await;
            assert_eq!(mounts.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn no_save_starts_once_the_way_out_has_begun() {
        let rt = services::runtime(None).unwrap();
        rt.block_on(async {
            let (cfg, log) = kept(true, &["first"]);
            let saves = LogSaves::new();
            let mut card = FakeCard::new();
            wind_down(
                cfg,
                &mut card,
                log,
                &Reason::ReturnAfter,
                &saves,
                &own_board(),
                &|| None,
            );

            // The Wi-Fi's save after a join, or the tick's, which come while the board leaves.
            let (late, mounts) = SlowCard::new(MS);
            assert!(!saves.start(cfg, log, late));
            assert!(!saves.running());
            tokio::time::sleep(50 * MS).await;
            assert_eq!(mounts.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn a_save_that_has_begun_when_the_way_out_does_is_still_waited_for_and_finishes() {
        let rt = services::runtime(None).unwrap();
        rt.block_on(async {
            let (cfg, log) = kept(true, &["first", "second"]);
            let saves = LogSaves::new();
            let (slow, mounts) = SlowCard::new(300 * MS);
            assert!(saves.start(cfg, log, slow));
            // Let it begin: it is on a free thread of the pool, and is in its mount.
            until_started(&saves).await;
            let mut card = ProbeCard {
                card: FakeCard::new(),
                saves: saves.clone(),
                running_when_touched: None,
            };

            let began = Instant::now();
            let left = wind_down(
                cfg,
                &mut card,
                log,
                &Reason::ReturnAfter,
                &saves,
                &own_board(),
                &|| None,
            );

            assert_eq!(left, Leaving::Restart);
            // It waited for the save that holds the card, and only then used the card itself.
            assert!(began.elapsed() >= 100 * MS, "{:?}", began.elapsed());
            assert_eq!(card.running_when_touched, Some(false));
            assert_eq!(mounts.load(Ordering::SeqCst), 1);
        });
    }

    /// A card that says, when it is first touched, whether a save was still running.
    struct ProbeCard {
        card: FakeCard,
        saves: Arc<LogSaves>,
        running_when_touched: Option<bool>,
    }

    impl ProbeCard {
        fn touched(&mut self) {
            self.running_when_touched
                .get_or_insert_with(|| self.saves.running());
        }
    }

    impl Card for ProbeCard {
        fn present(&self) -> bool {
            self.card.present()
        }

        fn dir(&self) -> &Path {
            self.card.dir()
        }

        fn mount(&mut self, access: Access) -> io::Result<()> {
            self.touched();
            self.card.mount(access)
        }

        fn sync(&mut self) {
            self.card.sync();
        }

        fn unmount(&mut self) -> io::Result<()> {
            self.touched();
            self.card.unmount()
        }
    }

    #[tokio::test]
    async fn the_way_out_waits_for_a_save_that_runs_before_it_uses_the_card() {
        let (cfg, log) = kept(true, &["first", "second"]);
        let saves = LogSaves::new();
        let (slow, _) = SlowCard::new(300 * MS);
        assert!(saves.start(cfg, log, slow));
        until_started(&saves).await;
        let mut card = ProbeCard {
            card: FakeCard::new(),
            saves: saves.clone(),
            running_when_touched: None,
        };

        let left = wind_down(
            cfg,
            &mut card,
            log,
            &Reason::ReturnAfter,
            &saves,
            &own_board(),
            &|| None,
        );

        assert_eq!(left, Leaving::Restart);
        // The save on the pool had let go of the card, and of its claim, before this one began.
        assert_eq!(card.running_when_touched, Some(false));
        assert!(!saves.running());
    }

    #[tokio::test]
    async fn a_stalling_supervisor_lets_a_running_save_end_and_then_saves_the_log_itself() {
        let (cfg, log) = kept(true, &["first", "second"]);
        let saves = LogSaves::new();
        let (slow, _) = SlowCard::new(300 * MS);
        assert!(saves.start(cfg, log, slow));
        until_started(&saves).await;
        let mut card = ProbeCard {
            card: FakeCard::new(),
            saves: saves.clone(),
            running_when_touched: None,
        };

        let began = Instant::now();
        stall_save(cfg, &mut card, log, &saves, LONG, &own_board());

        // It waited for the save on the pool, and only then touched the card.
        assert!(began.elapsed() >= 200 * MS, "{:?}", began.elapsed());
        assert_eq!(card.running_when_touched, Some(false));
        assert!(!saves.running());
        assert!(card.card.has("qberrypi/log.txt"));
    }

    #[test]
    fn a_stalling_supervisor_gives_up_waiting_for_a_save_that_does_not_end() {
        let (cfg, log) = kept(true, &["first"]);
        let saves = LogSaves::new();
        // A save that holds its claim for good, without touching the card.
        lock(&saves.state).save = Save::Started;
        let mut card = FakeCard::new();

        // The watchdog is running out, so the wait is bounded; the save goes ahead after it.
        let began = Instant::now();
        stall_save(cfg, &mut card, log, &saves, 100 * MS, &own_board());

        assert!(began.elapsed() >= 100 * MS, "{:?}", began.elapsed());
        assert!(saves.running());
        assert!(card.has("qberrypi/log.txt"));
    }

    #[test]
    fn a_stalling_supervisors_claim_on_the_card_outlives_its_save_until_the_watchdog_restarts_the_board()
     {
        let (cfg, log) = kept(true, &["first"]);
        let saves = LogSaves::new();
        let board = own_board();
        let mut card = FakeCard::new();

        stall_save(cfg, &mut card, log, &saves, LONG, &board);

        assert!(card.has("qberrypi/log.txt"));
        assert_eq!(lock(&board).card, Some(thread::current().id()));
        // The save of the pool that was in the queue, or that is started late, finds it claimed.
        let (error, ops) = a_late_save_on(&board);
        assert!(refused_the_card(&error), "{error}");
        assert!(ops.is_empty());
    }

    #[test]
    fn a_stalling_supervisor_leaves_the_card_alone_when_the_log_is_not_kept_there() {
        let (cfg, log) = kept(false, &["first"]);
        let saves = LogSaves::new();
        let mut card = FakeCard::new();

        stall_save(cfg, &mut card, log, &saves, LONG, &own_board());

        assert_eq!(card.ops, [""; 0]);
        assert!(!card.has("qberrypi/log.txt"));
        assert!(lock(log).has_unsaved());
    }

    #[tokio::test]
    async fn a_permanent_system_never_mounts_the_card_writable_from_boot_to_restart() {
        // Neither card switch is on: a system that is installed for good.
        let cfg: &'static Config = Box::leak(Box::new(cfg_debug(false, false)));
        let log: &'static Mutex<LogBuf> = Box::leak(Box::new(log_holding(&["banner"])));
        let saves = LogSaves::new();
        let mut card = FakeCard::new();

        // The boot: step 4, and step 9 as it is called again on the way out.
        restore_and_save_log(cfg, &mut card, log);
        save_log_if_asked(cfg, &mut card, log);
        // The tick's save and the one after each join, both of the pool. The tick's is due in every way
        // but the switch (lines are waiting, the link is joined, the thirty seconds have passed), so
        // that nothing but the switch can be what keeps it from the card.
        let later = Instant::now() + LOG_SAVE_EVERY;
        assert!(saves.is_due_at(later, &joined(), lock(log).has_unsaved()));
        let (ticked, tick_mounts) = SlowCard::new(MS);
        assert!(!start_save_if_due(
            cfg,
            log,
            &saves,
            &joined(),
            later,
            ticked
        ));
        let (after_a_join, join_mounts) = SlowCard::new(MS);
        assert!(!saves.start(cfg, log, after_a_join));
        // The provoked stall's own save, on the supervisor's thread.
        let board = own_board();
        stall_save(cfg, &mut card, log, &saves, LONG, &board);
        // The way out, for every reason the supervisor ends for.
        for reason in [
            Reason::ComponentFailed("dns"),
            Reason::NoAssociation,
            Reason::ReturnAfter,
        ] {
            leave(cfg, &mut card, log, &reason, &saves, &board);
        }
        // A fatal error once the configuration has been read: a panic, or the board giving up.
        rescue(Some(cfg), &mut card, Some(log), Duration::ZERO, &mut || {});

        // Not a mount, read-only or writable, and the lines are still waiting in memory.
        assert!(card.ops.is_empty(), "{:?}", card.ops);
        assert_eq!(
            (
                tick_mounts.load(Ordering::SeqCst),
                join_mounts.load(Ordering::SeqCst)
            ),
            (0, 0)
        );
        assert!(!saves.running());
        assert_eq!(card.read("config.txt"), QBERRYPI);
        assert!(!card.has("qberrypi/log.txt"));
        assert!(lock(log).has_unsaved());
        // Nor was the card claimed, so that a boot with no use for it never holds it either.
        assert_eq!(lock(&board).card, None);
    }

    /// A logger that keeps what is logged, for the one test that installs it.
    struct Capture(Mutex<Vec<String>>);

    impl Capture {
        fn lines(&self) -> Vec<String> {
            lock(&self.0).clone()
        }
    }

    impl log::Log for Capture {
        fn enabled(&self, _: &log::Metadata<'_>) -> bool {
            true
        }

        fn log(&self, record: &log::Record<'_>) {
            lock(&self.0).push(format!("{} {}", record.level(), record.args()));
        }

        fn flush(&self) {}
    }

    #[test]
    fn the_wifi_task_waits_without_the_interface_and_again_when_it_cannot_open_it() {
        crate::testns::run_inside("init::tests::ns_wifi_task");
    }

    #[tokio::test]
    #[ignore = "run by the_wifi_task_waits_without_the_interface_and_again_when_it_cannot_open_it, inside a namespace"]
    async fn ns_wifi_task() {
        use tokio::time::timeout;

        if !crate::testns::inside() {
            return;
        }
        // This process runs this one test, so the logger is its own to set.
        static CAPTURE: Capture = Capture(Mutex::new(Vec::new()));
        log::set_logger(&CAPTURE).unwrap();
        log::set_max_level(log::LevelFilter::Trace);
        let cfg = config::parse(EXAMPLE).unwrap();
        let mut reported = Vec::new();
        let mut report = |status: WifiStatus| reported.push(status);

        // A board without the interface says so, and never joins.
        let task = wifi_task(&cfg, false, &mut report);
        assert!(timeout(Duration::from_millis(300), task).await.is_err());
        assert_eq!(CAPTURE.lines(), ["WARN wifi: wlan0 is absent, not joining"]);

        // An interface that cannot be opened is said so, and left to be opened again later.
        let task = wifi_task(&cfg, true, &mut report);
        assert!(timeout(Duration::from_secs(1), task).await.is_err());
        assert_eq!(
            CAPTURE.lines()[1..],
            ["WARN wifi: wlan0 could not be opened: the wireless interface is gone"]
        );
        assert!(reported.is_empty());
    }

    #[test]
    fn a_tick_of_a_stall_fault_that_is_due_says_so_and_never_returns() {
        crate::testns::run_inside("init::tests::ns_stalled_tick");
    }

    #[test]
    #[ignore = "run by a_tick_of_a_stall_fault_that_is_due_says_so_and_never_returns, in a process of its own"]
    fn ns_stalled_tick() {
        if !crate::testns::inside() {
            return;
        }
        // This process runs this one test, so the logger is its own to set, and the tick's
        // collecting of children takes no other test's.
        static CAPTURE: Capture = Capture(Mutex::new(Vec::new()));
        log::set_logger(&CAPTURE).unwrap();
        log::set_max_level(log::LevelFilter::Trace);
        let ago = |secs| {
            Instant::now()
                .checked_sub(Duration::from_secs(secs))
                .expect("the machine has been up that long")
        };
        let ticking = |fault: &str, began: Instant| {
            let text = EXAMPLE.replace("fault = \"none\"", &format!("fault = \"{fault}\""));
            let cfg: &'static Config = Box::leak(Box::new(config::parse(&text).unwrap()));
            let log: &'static Mutex<LogBuf> = Box::leak(Box::new(log_holding(&[])));
            let (_sender, status) = watch::channel(WifiStatus::Starting);
            tick(cfg, log, None, status, LogSaves::new(), began)
        };

        // A stall that is not due yet, and any other fault however late: the tick comes back.
        ticking("stall", ago(9))();
        ticking("crash-loop", ago(3600))();
        ticking("none", ago(3600))();
        assert_eq!(CAPTURE.lines(), [""; 0]);

        // One that is due says so, and the supervisor's thread is held for good.
        let stalled = thread::spawn(move || ticking("stall", ago(11))());
        thread::sleep(Duration::from_millis(400));
        assert!(!stalled.is_finished());
        assert_eq!(
            CAPTURE.lines(),
            [
                "WARN fault: stalling the supervisor; the watchdog must restart the board within 15 s"
            ]
        );
    }

    #[test]
    fn the_network_start_pets_after_each_step_that_waits_on_netlink() {
        crate::testns::run_inside("init::tests::ns_start_network");
    }

    #[tokio::test]
    #[ignore = "run by the_network_start_pets_after_each_step_that_waits_on_netlink, inside a namespace"]
    async fn ns_start_network() {
        if !crate::testns::inside() {
            return;
        }
        // This process runs this one test, so the logger is its own to set.
        static CAPTURE: Capture = Capture(Mutex::new(Vec::new()));
        log::set_logger(&CAPTURE).unwrap();
        log::set_max_level(log::LevelFilter::Trace);
        let cfg = config::parse(EXAMPLE).unwrap();
        // Each pet, with the number of lines logged by then.
        let mut pets = Vec::new();

        start_network(&cfg, &mut || pets.push(CAPTURE.lines().len())).await;

        let lines = CAPTURE.lines();
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert_eq!(lines[0], "INFO net: lo is up");
        assert!(lines[1].contains("regulatory:"), "{lines:?}");
        // One pet after `lo`, one once nl80211 has been opened (which can take
        // 5 s) and before the country check (which can take 10), and one at the
        // end, so that what the main loop does next starts with a whole watchdog.
        assert_eq!(pets, [1, 1, 2]);
    }

    // Step 3: the configuration.

    #[test]
    fn the_config_is_read_from_a_read_only_mount() {
        let mut card = FakeCard::new();
        let cfg = load_config(&mut card).unwrap();
        assert_eq!(cfg.hostname, "qberrypi");
        assert_eq!(card.ops, READ_OPS);
    }

    #[test]
    fn a_missing_config_file_is_fatal_by_name() {
        let mut card = FakeCard::new();
        card.remove("qberrypi/qberrypi.toml");
        let not_found = io::Error::from_raw_os_error(libc::ENOENT);
        assert_eq!(
            load_config(&mut card).unwrap_err(),
            format!("qberrypi.toml: {not_found}")
        );
        assert_eq!(card.ops, READ_OPS);
    }

    #[test]
    fn a_config_that_does_not_parse_is_fatal_with_the_parser_error() {
        let mut card = FakeCard::new();
        card.write("qberrypi/qberrypi.toml", "this is not toml");
        let expected = config::parse("this is not toml").unwrap_err().to_string();
        assert!(expected.starts_with("qberrypi.toml: "));
        assert_eq!(load_config(&mut card).unwrap_err(), expected);
        assert_eq!(card.ops, READ_OPS);
    }

    #[test]
    fn a_config_error_never_repeats_a_value_from_the_file() {
        let mut card = FakeCard::new();
        card.write(
            "qberrypi/qberrypi.toml",
            &EXAMPLE.replace("example-passphrase", "short"),
        );
        let error = load_config(&mut card).unwrap_err();
        assert!(error.starts_with("qberrypi.toml: wifi.passphrase: "));
        assert!(!error.contains("short"));
    }

    #[test]
    fn a_card_that_does_not_mount_is_fatal_and_is_left_alone() {
        let mut card = FakeCard::new();
        card.mount_fails = true;
        let busy = io::Error::from(ErrorKind::ResourceBusy);
        assert_eq!(
            load_config(&mut card).unwrap_err(),
            format!("mounting /dev/mmcblk0p1: {busy}")
        );
        assert_eq!(card.ops, ["unmount", "mount read-only"]);
    }

    #[test]
    fn a_failed_unmount_does_not_lose_the_config() {
        let mut card = FakeCard::new();
        card.unmount_fails = true;
        assert_eq!(load_config(&mut card).unwrap().hostname, "qberrypi");
    }

    #[test]
    fn the_tls_file_is_read_in_the_same_read_only_mount_as_the_config() {
        let mut card = FakeCard::new();
        // Not a PEM: init keeps the bytes and leaves the judging of them to the API.
        fs::write(
            card.dir().join("qberrypi/tls.pem"),
            b"the bytes of the file",
        )
        .unwrap();
        let slot = OnceLock::new();
        let cfg = load_config_into(&mut card, &slot).unwrap();
        assert_eq!(cfg.hostname, "qberrypi");
        assert_eq!(slot.get(), Some(&Some(b"the bytes of the file".to_vec())));
        // One mount for both files, as before.
        assert_eq!(card.ops, READ_OPS);
    }

    #[test]
    fn a_card_without_a_tls_file_leaves_none_and_still_loads_the_config() {
        let mut card = FakeCard::new();
        let slot = OnceLock::new();
        assert!(load_config_into(&mut card, &slot).is_ok());
        assert_eq!(slot.get(), Some(&None));
        assert_eq!(card.ops, READ_OPS);
    }

    #[test]
    fn the_tls_file_is_read_whether_or_not_the_config_has_an_api_section() {
        // The example configuration has none (its [api] is commented out).
        let mut card = FakeCard::new();
        assert!(config::parse(EXAMPLE).unwrap().api.is_none());
        fs::write(card.dir().join("qberrypi/tls.pem"), b"pem").unwrap();
        let slot = OnceLock::new();
        load_config_into(&mut card, &slot).unwrap();
        assert_eq!(slot.get(), Some(&Some(b"pem".to_vec())));
    }

    #[test]
    fn a_config_that_does_not_load_leaves_the_tls_slot_unset() {
        let mut card = FakeCard::new();
        fs::write(card.dir().join("qberrypi/tls.pem"), b"pem").unwrap();
        card.write("qberrypi/qberrypi.toml", "this is not toml");
        let slot = OnceLock::new();
        assert!(load_config_into(&mut card, &slot).is_err());
        assert_eq!(slot.get(), None);
    }

    #[test]
    fn the_first_tls_file_stays_and_the_accessor_gives_its_bytes() {
        let slot = OnceLock::new();
        assert_eq!(tls_pem_of(&slot), None);
        slot.set(Some(b"first".to_vec())).unwrap();
        assert_eq!(tls_pem_of(&slot), Some(&b"first"[..]));
        let empty: OnceLock<Option<Vec<u8>>> = OnceLock::new();
        empty.set(None).unwrap();
        assert_eq!(tls_pem_of(&empty), None);
    }

    #[test]
    fn a_tls_file_that_cannot_be_read_is_logged_and_the_config_still_loads() {
        crate::testns::run_inside("init::tests::ns_tls_file_log");
    }

    #[test]
    #[ignore = "run by a_tls_file_that_cannot_be_read_is_logged_and_the_config_still_loads, in a process of its own"]
    fn ns_tls_file_log() {
        if !crate::testns::inside() {
            return;
        }
        // This process runs this one test, so the logger is its own to set.
        static CAPTURE: Capture = Capture(Mutex::new(Vec::new()));
        log::set_logger(&CAPTURE).unwrap();
        log::set_max_level(log::LevelFilter::Trace);

        // A file that is there, and one that is not: neither is a thing to log.
        let mut card = FakeCard::new();
        load_config_into(&mut card, &OnceLock::new()).unwrap();
        fs::write(card.dir().join("qberrypi/tls.pem"), b"pem").unwrap();
        load_config_into(&mut card, &OnceLock::new()).unwrap();
        assert_eq!(CAPTURE.lines(), [""; 0]);

        // One over the cap is, once, without a byte of it, and the API's stays off.
        let mut card = FakeCard::new();
        let canary = vec![b'k'; bootpart::TLS_FILE_CAP as usize + 1];
        fs::write(card.dir().join("qberrypi/tls.pem"), canary).unwrap();
        let slot = OnceLock::new();
        let cfg = load_config_into(&mut card, &slot).unwrap();
        assert_eq!(cfg.hostname, "qberrypi");
        assert_eq!(slot.get(), Some(&None));
        assert_eq!(
            CAPTURE.lines(),
            ["WARN tls.pem: larger than 16384 bytes; the API will stay off"]
        );
        assert_eq!(card.ops, READ_OPS);
    }

    // Step 4: the first write to the card.

    #[test]
    fn one_shot_restores_config_txt_then_syncs_and_unmounts() {
        let mut card = FakeCard::new();
        let log = log_holding(&["banner"]);
        restore_and_save_log(&cfg_debug(true, false), &mut card, &log);
        assert_eq!(card.read("config.txt"), PIOS);
        assert_eq!(card.ops, WRITE_OPS);
        // The log is not asked for on the card, and stays in memory.
        assert!(!card.has("qberrypi/log.txt"));
        assert_eq!(log.lock().unwrap().take_unsaved(), "banner\n");
    }

    #[test]
    fn without_one_shot_or_the_log_the_card_is_not_touched() {
        let mut card = FakeCard::new();
        let log = log_holding(&["banner"]);
        restore_and_save_log(&cfg_debug(false, false), &mut card, &log);
        assert!(card.ops.is_empty());
        assert_eq!(card.read("config.txt"), QBERRYPI);
        assert!(!card.has("qberrypi/log.txt"));
        assert_eq!(log.lock().unwrap().take_unsaved(), "banner\n");
    }

    #[test]
    fn one_shot_with_the_log_on_saves_it_in_the_same_mount_as_the_restore() {
        // The watchdog is not running yet and no driver is loaded: a boot
        // that dies in either has already left these lines on the card.
        let mut card = FakeCard::new();
        let log = log_holding(&["banner", "clock: set to the build time"]);
        restore_and_save_log(&cfg_debug(true, true), &mut card, &log);
        assert_eq!(card.read("config.txt"), PIOS);
        assert_eq!(
            card.read("qberrypi/log.txt"),
            header() + "banner\nclock: set to the build time\n"
        );
        // One mount for both.
        assert_eq!(card.ops, WRITE_OPS);
        assert_eq!(log.lock().unwrap().take_unsaved(), "");
    }

    #[test]
    fn a_permanent_system_with_the_log_on_saves_it_at_the_same_point_and_leaves_config_txt() {
        let mut card = FakeCard::new();
        let log = log_holding(&["banner"]);
        restore_and_save_log(&cfg_debug(false, true), &mut card, &log);
        assert_eq!(card.read("config.txt"), QBERRYPI);
        assert_eq!(card.read("config.pios.txt"), PIOS);
        assert_eq!(card.read("qberrypi/log.txt"), header() + "banner\n");
        assert_eq!(card.ops, WRITE_OPS);
    }

    #[test]
    fn a_backup_that_is_refused_still_ends_in_sync_and_unmount_and_the_log_is_saved() {
        let mut card = FakeCard::new();
        card.remove("config.pios.txt");
        let log = log_holding(&["banner"]);
        restore_and_save_log(&cfg_debug(true, true), &mut card, &log);
        assert_eq!(card.read("config.txt"), QBERRYPI);
        assert_eq!(card.read("qberrypi/log.txt"), header() + "banner\n");
        assert_eq!(card.ops, WRITE_OPS);
    }

    #[test]
    fn a_restore_that_fails_still_ends_in_sync_and_unmount() {
        let mut card = FakeCard::new();
        // A directory where the backup should be can be neither read nor restored.
        card.remove("config.pios.txt");
        fs::create_dir(card.dir().join("config.pios.txt")).unwrap();
        restore_and_save_log(&cfg_debug(true, false), &mut card, &log_holding(&[]));
        assert_eq!(card.read("config.txt"), QBERRYPI);
        assert_eq!(card.ops, WRITE_OPS);
    }

    #[test]
    fn a_partition_left_mounted_is_unmounted_before_the_restore() {
        // The unmount after the configuration was read has failed.
        let mut card = FakeCard::new();
        card.mount(Access::ReadOnly).unwrap();
        card.ops.clear();
        restore_and_save_log(&cfg_debug(true, false), &mut card, &log_holding(&[]));
        assert_eq!(card.read("config.txt"), PIOS);
        assert_eq!(card.ops, WRITE_OPS);
        assert!(!card.mounted);
    }

    #[test]
    fn a_card_that_does_not_mount_for_the_first_write_keeps_the_log_for_the_next_save() {
        let mut card = FakeCard::new();
        let log = log_holding(&["banner"]);
        let cfg = cfg_debug(true, true);

        card.mount_fails = true;
        restore_and_save_log(&cfg, &mut card, &log);
        assert_eq!(card.read("config.txt"), QBERRYPI);
        assert!(!card.has("qberrypi/log.txt"));

        card.mount_fails = false;
        save_log_if_asked(&cfg, &mut card, &log);
        assert_eq!(card.read("qberrypi/log.txt"), header() + "banner\n");
    }

    #[test]
    fn a_restore_that_was_refused_or_that_failed_is_logged_as_an_error() {
        let line = |text: &str| text.to_owned();
        assert_eq!(
            restore_report(&Ok(Restore::Restored)),
            (Level::Info, line("config.txt: Restored"))
        );
        assert_eq!(
            restore_report(&Ok(Restore::AlreadyRestored)),
            (Level::Info, line("config.txt: AlreadyRestored"))
        );
        // The card still starts qberrypi: nothing less than an error.
        assert_eq!(
            restore_report(&Ok(Restore::Refused("config.pios.txt is missing"))),
            (
                Level::Error,
                line("config.txt: Refused(\"config.pios.txt is missing\")")
            )
        );
        assert_eq!(
            restore_report(&Err(io::Error::other("the card went away"))),
            (Level::Error, line("config.txt: the card went away"))
        );
    }

    // Step 6: the Wi-Fi driver.

    #[test]
    fn the_wifi_modules_are_loaded_in_order_and_cfg80211_gets_the_country() {
        let table = ModuleTable::parse(DEFAULT_TABLE).unwrap();
        let mut calls: Vec<(String, String)> = Vec::new();
        // Like the kernel: a module that was inserted once is there from then on.
        let mut insert = |file: &Path, params: &str| {
            let file = file.to_str().unwrap().to_owned();
            let already = calls.iter().any(|(seen, _)| *seen == file);
            calls.push((file, params.to_owned()));
            if already {
                Err(ErrorKind::AlreadyExists.into())
            } else {
                Ok(())
            }
        };
        let inserted = load_wifi_modules(&table, "DE", &mut insert).unwrap();
        assert_eq!(inserted, ["rfkill", "cfg80211", "brcmutil", "brcmfmac"]);
        let calls: Vec<_> = calls
            .iter()
            .map(|(f, p)| (f.as_str(), p.as_str()))
            .collect();
        assert_eq!(
            calls,
            [
                ("/lib/modules/rfkill.ko", ""),
                ("/lib/modules/cfg80211.ko", "ieee80211_regdom=DE"),
                ("/lib/modules/brcmutil.ko", ""),
                ("/lib/modules/rfkill.ko", ""),
                ("/lib/modules/cfg80211.ko", ""),
                ("/lib/modules/brcmfmac.ko", "roamoff=1"),
            ]
        );
    }

    #[test]
    fn a_module_that_does_not_load_is_fatal_by_name() {
        let table = ModuleTable::parse(DEFAULT_TABLE).unwrap();
        let mut insert = |file: &Path, _: &str| {
            if file.ends_with("brcmutil.ko") {
                Err(io::Error::other("bad signature"))
            } else {
                Ok(())
            }
        };
        assert_eq!(
            load_wifi_modules(&table, "US", &mut insert).unwrap_err(),
            "loading brcmfmac: bad signature"
        );

        let empty = ModuleTable::parse("").unwrap();
        let error = load_wifi_modules(&empty, "US", &mut |_, _| Ok(())).unwrap_err();
        assert!(error.starts_with("loading cfg80211: "), "{error}");
    }

    // Step 6: the CPU frequency governor.

    const GOVERNOR_FILE: &str = "devices/system/cpu/cpufreq/policy0/scaling_governor";

    #[test]
    fn the_governor_is_set_to_performance() {
        let sysfs = tempfile::tempdir().unwrap();
        let file = sysfs.path().join(GOVERNOR_FILE);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, "schedutil\n").unwrap();

        set_governor(sysfs.path()).unwrap();
        assert_eq!(fs::read_to_string(&file).unwrap(), "performance");
    }

    #[test]
    fn a_governor_file_that_is_not_there_is_an_error_and_is_not_created() {
        let sysfs = tempfile::tempdir().unwrap();
        let error = set_governor(sysfs.path()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotFound);
        assert!(!sysfs.path().join(GOVERNOR_FILE).exists());
        // Not even the directories on the way to it.
        assert_eq!(fs::read_dir(sysfs.path()).unwrap().count(), 0);
    }

    #[test]
    fn the_governor_report_is_info_on_success_and_a_warning_otherwise() {
        assert_eq!(
            governor_report(&Ok(())),
            (Level::Info, "cpu: governor performance".into())
        );
        let error = io::Error::from(ErrorKind::NotFound);
        let line = format!("cpu: governor: {error}");
        assert_eq!(governor_report(&Err(error)), (Level::Warn, line));
    }

    // Step 8: what came of the driver.

    #[test]
    fn the_wifi_report_says_what_sysfs_shows() {
        let sysfs = tempfile::tempdir().unwrap();
        assert_eq!(
            wifi_report(sysfs.path()),
            ["wlan0: absent", "brcmfmac_cyw: not loaded"]
        );
        fs::create_dir_all(sysfs.path().join("module/brcmfmac_cyw")).unwrap();
        assert_eq!(
            wifi_report(sysfs.path()),
            ["wlan0: absent", "brcmfmac_cyw: loaded"]
        );
        fs::create_dir_all(sysfs.path().join("class/net/wlan0")).unwrap();
        assert_eq!(
            wifi_report(sysfs.path()),
            ["wlan0: present", "brcmfmac_cyw: loaded"]
        );
    }

    #[test]
    fn kernel_messages_become_log_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("kmsg");
        fs::write(
            &path,
            "4,7,100,-;qberrypi-modhelper: net-pf-10: not in table\n",
        )
        .unwrap();
        let mut reader = kmsg::Reader::open(&path).unwrap();
        assert_eq!(
            kernel_lines(&mut reader).unwrap(),
            ["kernel: qberrypi-modhelper: net-pf-10: not in table"]
        );
    }

    #[test]
    fn each_look_at_the_kernel_log_gives_what_came_after_the_last() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("kmsg");
        fs::write(&path, "6,1,100,-;first\n").unwrap();
        let mut reader = kmsg::Reader::open(&path).unwrap();
        assert_eq!(kernel_lines(&mut reader).unwrap(), ["kernel: first"]);
        assert_eq!(kernel_lines(&mut reader).unwrap(), [""; 0]);

        let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"6,2,200,-;second\n").unwrap();
        assert_eq!(kernel_lines(&mut reader).unwrap(), ["kernel: second"]);
    }

    #[test]
    fn a_long_dump_pets_the_watchdog_before_the_first_line_and_every_fifty_lines() {
        let lines: Vec<String> = (0..120).map(|n| format!("kernel: line {n}")).collect();
        let events = RefCell::new(Vec::new());
        log_lines(
            &lines,
            &mut |line| events.borrow_mut().push(line.to_owned()),
            &mut || events.borrow_mut().push("pet".to_owned()),
        );
        let events = events.into_inner();

        assert_eq!(events[0], "pet");
        let pets = events.iter().filter(|event| *event == "pet").count();
        assert!(pets >= 3, "{pets} pets");
        // Between two pets there are never more than fifty lines.
        for run in events.split(|event| event == "pet") {
            assert!(run.len() <= 50, "{} lines without a pet", run.len());
        }
        // Every line is logged, once and in order.
        let logged: Vec<_> = events.into_iter().filter(|event| event != "pet").collect();
        assert_eq!(logged, lines);
    }

    #[test]
    fn a_short_dump_is_logged_whole_after_one_pet() {
        let lines = ["kernel: one".to_owned(), "kernel: two".to_owned()];
        let events = RefCell::new(Vec::new());
        log_lines(
            &lines,
            &mut |line| events.borrow_mut().push(line.to_owned()),
            &mut || events.borrow_mut().push("pet".to_owned()),
        );
        assert_eq!(events.into_inner(), ["pet", "kernel: one", "kernel: two"]);
    }

    #[test]
    fn a_kernel_log_that_cannot_be_read_is_an_error_to_report() {
        // A directory opens, and every read of it fails.
        let tmp = tempfile::tempdir().unwrap();
        let mut reader = kmsg::Reader::open(tmp.path()).unwrap();
        let error = kernel_lines(&mut reader).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::IsADirectory);
    }

    // The boot line and the country check.

    #[test]
    fn the_boot_line_gives_the_kernels_uptime_to_the_millisecond() {
        assert_eq!(
            boot_line(Duration::from_millis(1234)),
            "boot: init started 1.234 s after the kernel"
        );
        assert_eq!(
            boot_line(Duration::from_micros(2_000_999)),
            "boot: init started 2.000 s after the kernel"
        );
        assert_eq!(
            boot_line(Duration::from_secs(61)),
            "boot: init started 61.000 s after the kernel"
        );
    }

    #[test]
    fn the_open_files_report_gives_the_limit_or_a_warning_with_the_error() {
        assert_eq!(
            open_files_report(&Ok(4096)),
            (Level::Info, "init: open files: up to 4096".into())
        );
        assert_eq!(
            open_files_report(&Err("Operation not permitted (os error 1)".into())),
            (
                Level::Warn,
                "init: open files: the limit could not be raised: Operation not permitted (os error 1)"
                    .into()
            )
        );
    }

    #[test]
    fn the_country_report_says_applied_or_what_is_there_instead() {
        assert_eq!(
            regulatory_report("US", &Ok(*b"US")),
            (Level::Info, "regulatory: country US, as configured".into())
        );
        assert_eq!(
            regulatory_report("US", &Ok(*b"00")),
            (
                Level::Warn,
                "regulatory: country is 00, not the configured US".into()
            )
        );
        assert_eq!(
            regulatory_report("US", &Err("no such file".into())),
            (
                Level::Warn,
                "regulatory: could not be read: no such file".into()
            )
        );
    }

    // Step 9: the log on the card.

    #[test]
    fn only_the_first_entry_of_a_boot_starts_with_the_build_header() {
        let mut buf = LogBuf::new(4096);
        buf.push("a");
        buf.push("b");
        assert_eq!(
            log_entry(&mut buf),
            format!("==== boot, build {} ====\na\nb\n", crate::BUILD_EPOCH)
        );
        buf.push("c");
        assert_eq!(log_entry(&mut buf), "c\n");
        assert_eq!(log_entry(&mut buf), "");
    }

    #[test]
    fn the_log_is_saved_when_asked_and_each_line_once() {
        let mut card = FakeCard::new();
        let log = log_holding(&["first"]);
        let cfg = cfg_with_log_to_sd(true);

        save_log_if_asked(&cfg, &mut card, &log);
        assert_eq!(card.read("qberrypi/log.txt"), header() + "first\n");
        assert_eq!(card.ops, WRITE_OPS);

        // What is saved later goes under the header the boot already has.
        log.lock().unwrap().push("second");
        save_log_if_asked(&cfg, &mut card, &log);
        assert_eq!(card.read("qberrypi/log.txt"), header() + "first\nsecond\n");
        assert_eq!(card.ops, [WRITE_OPS, WRITE_OPS].concat());
    }

    #[test]
    fn a_boot_that_saves_its_log_three_times_reads_as_one_boot() {
        // A one-shot boot that keeps its log: with the restore, after the
        // kernel's log was copied, and at the return.
        let mut card = FakeCard::new();
        let log = log_holding(&["banner"]);
        let cfg = cfg_debug(true, true);

        restore_and_save_log(&cfg, &mut card, &log);
        log.lock().unwrap().push("kernel: one");
        save_log_if_asked(&cfg, &mut card, &log);
        log.lock().unwrap().push("returning");
        save_log_if_asked(&cfg, &mut card, &log);

        assert_eq!(
            card.read("qberrypi/log.txt"),
            header() + "banner\nkernel: one\nreturning\n"
        );
        assert_eq!(card.ops, [WRITE_OPS, WRITE_OPS, WRITE_OPS].concat());
    }

    #[test]
    fn a_failure_after_the_log_was_first_saved_adds_its_lines_under_the_same_header() {
        let mut card = FakeCard::new();
        let log = log_holding(&["banner"]);
        let cfg = cfg_debug(true, true);

        restore_and_save_log(&cfg, &mut card, &log);
        log.lock().unwrap().push("loading brcmfmac: bad signature");
        rescue(Some(&cfg), &mut card, Some(&log), LONG, &mut || {});

        assert_eq!(
            card.read("qberrypi/log.txt"),
            header() + "banner\nloading brcmfmac: bad signature\n"
        );
    }

    #[test]
    fn without_log_to_sd_the_card_is_not_touched_and_the_log_is_kept() {
        let mut card = FakeCard::new();
        let log = log_holding(&["first"]);
        save_log_if_asked(&cfg_with_log_to_sd(false), &mut card, &log);
        assert!(card.ops.is_empty());
        assert!(!card.has("qberrypi/log.txt"));
        assert_eq!(log.lock().unwrap().take_unsaved(), "first\n");
    }

    #[test]
    fn a_card_that_does_not_mount_leaves_the_log_for_the_next_save() {
        let mut card = FakeCard::new();
        let log = log_holding(&["first"]);
        let cfg = cfg_with_log_to_sd(true);

        card.mount_fails = true;
        save_log_if_asked(&cfg, &mut card, &log);
        assert!(!card.has("qberrypi/log.txt"));

        card.mount_fails = false;
        save_log_if_asked(&cfg, &mut card, &log);
        assert!(card.read("qberrypi/log.txt").contains("first\n"));
    }

    // The way out.

    const BOTH: Rescue = Rescue {
        restore_config: true,
        save_log: true,
    };
    const LOG_ONLY: Rescue = Rescue {
        restore_config: false,
        save_log: true,
    };
    const NEITHER: Rescue = Rescue {
        restore_config: false,
        save_log: false,
    };

    #[test]
    fn with_no_config_a_failure_restores_config_txt_and_saves_the_log() {
        assert_eq!(rescue_plan(None), BOTH);
    }

    #[test]
    fn in_one_shot_mode_a_failure_restores_config_txt_and_saves_the_log() {
        assert_eq!(rescue_plan(Some(&cfg_debug(true, false))), BOTH);
        assert_eq!(rescue_plan(Some(&cfg_debug(true, true))), BOTH);
    }

    #[test]
    fn on_a_permanent_system_a_failure_only_saves_the_log_and_only_if_it_is_on() {
        assert_eq!(rescue_plan(Some(&cfg_debug(false, true))), LOG_ONLY);
        assert_eq!(rescue_plan(Some(&cfg_debug(false, false))), NEITHER);
    }

    #[test]
    fn the_rescue_restores_exactly_when_restore_on_fatal_says_so() {
        for cfg in [
            None,
            Some(cfg_debug(false, false)),
            Some(cfg_debug(false, true)),
            Some(cfg_debug(true, false)),
            Some(cfg_debug(true, true)),
        ] {
            let cfg = cfg.as_ref();
            assert_eq!(rescue_plan(cfg).restore_config, restore_on_fatal(cfg));
        }
    }

    #[test]
    fn a_failure_before_the_config_is_known_restores_config_txt_and_saves_the_log() {
        let mut card = FakeCard::new();
        let log = log_holding(&["qberrypi.toml: (syntax): not valid TOML"]);
        rescue(None, &mut card, Some(&log), LONG, &mut || {});
        assert_eq!(card.read("config.txt"), PIOS);
        assert_eq!(
            card.read("qberrypi/log.txt"),
            header() + "qberrypi.toml: (syntax): not valid TOML\n"
        );
        assert_eq!(card.ops, WRITE_OPS);
        assert!(!card.mounted);
    }

    #[test]
    fn a_failure_in_one_shot_mode_restores_config_txt_and_saves_the_log() {
        // The log is saved whether or not the configuration asks for it.
        for log_to_sd in [false, true] {
            let mut card = FakeCard::new();
            let log = log_holding(&["loading brcmfmac: bad signature"]);
            rescue(
                Some(&cfg_debug(true, log_to_sd)),
                &mut card,
                Some(&log),
                LONG,
                &mut || {},
            );
            assert_eq!(card.read("config.txt"), PIOS);
            assert_eq!(
                card.read("qberrypi/log.txt"),
                header() + "loading brcmfmac: bad signature\n"
            );
            assert_eq!(card.ops, WRITE_OPS);
            assert!(!card.mounted);
        }
    }

    #[test]
    fn a_failure_of_a_permanent_system_with_the_log_on_saves_it_and_leaves_config_txt() {
        let mut card = FakeCard::new();
        let log = log_holding(&["loading brcmfmac: bad signature"]);
        rescue(
            Some(&cfg_debug(false, true)),
            &mut card,
            Some(&log),
            LONG,
            &mut || {},
        );
        assert_eq!(card.read("config.txt"), QBERRYPI);
        assert_eq!(card.read("config.pios.txt"), PIOS);
        assert_eq!(
            card.read("qberrypi/log.txt"),
            header() + "loading brcmfmac: bad signature\n"
        );
        assert_eq!(card.ops, WRITE_OPS);
        assert!(!card.mounted);
    }

    #[test]
    fn a_failure_of_a_permanent_system_that_keeps_no_log_never_mounts_the_card() {
        let mut card = FakeCard::new();
        let log = log_holding(&["loading brcmfmac: bad signature"]);
        rescue(
            Some(&cfg_debug(false, false)),
            &mut card,
            Some(&log),
            LONG,
            &mut || {},
        );
        assert!(card.ops.is_empty());
        assert_eq!(card.read("config.txt"), QBERRYPI);
        assert!(!card.has("qberrypi/log.txt"));
        assert_eq!(
            log.lock().unwrap().take_unsaved(),
            "loading brcmfmac: bad signature\n"
        );
    }

    #[test]
    fn with_only_the_log_to_save_and_no_log_to_use_the_card_is_never_mounted() {
        let mut card = FakeCard::new();
        rescue(
            Some(&cfg_debug(false, true)),
            &mut card,
            None,
            LONG,
            &mut || {},
        );
        assert!(card.ops.is_empty());
        assert_eq!(card.read("config.txt"), QBERRYPI);
        assert!(!card.has("qberrypi/log.txt"));
    }

    #[test]
    fn the_rescue_pets_the_watchdog_between_the_restore_and_the_log() {
        let mut card = FakeCard::new();
        let dir = card.dir().to_owned();
        let log = log_holding(&["first"]);
        // What the card held each time the watchdog was petted.
        let mut seen = Vec::new();
        rescue(None, &mut card, Some(&log), LONG, &mut || {
            let restored = fs::read_to_string(dir.join("config.txt")).unwrap() == PIOS;
            seen.push((restored, dir.join("qberrypi/log.txt").exists()));
        });
        // Once as the wait for the card begins, once between the two writes.
        assert_eq!(seen, [(false, false), (true, false)]);
        assert_eq!(card.read("qberrypi/log.txt"), header() + "first\n");
    }

    #[test]
    fn the_rescue_pets_the_watchdog_before_it_saves_the_log_of_a_permanent_system() {
        let mut card = FakeCard::new();
        let dir = card.dir().to_owned();
        let log = log_holding(&["first"]);
        let mut seen = Vec::new();
        let cfg = cfg_debug(false, true);
        rescue(Some(&cfg), &mut card, Some(&log), LONG, &mut || {
            seen.push(dir.join("qberrypi/log.txt").exists());
        });
        assert_eq!(seen, [false, false]);
        assert_eq!(card.read("qberrypi/log.txt"), header() + "first\n");
    }

    #[test]
    fn a_failure_before_the_kernel_has_found_the_card_waits_for_it_and_then_restores() {
        // Init runs before the kernel has read the card's partitions, so a
        // failure in the first steps comes when there is no device to mount.
        let mut card = FakeCard::found_after(3);
        let log = log_holding(&["setting the clock: Operation not permitted"]);
        let mut pets = 0;
        rescue(None, &mut card, Some(&log), LONG, &mut || pets += 1);
        assert_eq!(card.read("config.txt"), PIOS);
        assert_eq!(
            card.read("qberrypi/log.txt"),
            header() + "setting the clock: Operation not permitted\n"
        );
        assert_eq!(card.ops, WRITE_OPS);
        // While it waited, and between the restore and the log.
        assert!(pets >= 2, "{pets} pets");
    }

    #[test]
    fn a_card_that_never_appears_does_not_keep_the_rescue_from_ending() {
        let mut card = FakeCard::found_after(usize::MAX);
        let log = log_holding(&["first"]);
        let start = Instant::now();
        rescue(None, &mut card, Some(&log), 100 * MS, &mut || {});
        let took = start.elapsed();
        assert!(
            took >= 100 * MS && took < Duration::from_secs(5),
            "{took:?}"
        );
        assert_eq!(card.read("config.txt"), QBERRYPI);
        assert_eq!(log.lock().unwrap().take_unsaved(), "first\n");
    }

    #[test]
    fn with_nothing_to_do_on_the_card_the_rescue_does_not_wait_for_it() {
        let mut card = FakeCard::found_after(usize::MAX);
        let log = log_holding(&["first"]);
        let start = Instant::now();
        rescue(
            Some(&cfg_debug(false, false)),
            &mut card,
            Some(&log),
            LONG,
            &mut || panic!("the watchdog was petted for a wait"),
        );
        assert!(start.elapsed() < Duration::from_secs(5));
        assert!(card.ops.is_empty());
        // The card was not so much as asked for.
        assert_eq!(card.absent_for.get(), usize::MAX);
    }

    #[test]
    fn a_failure_while_the_card_was_mounted_still_restores() {
        let mut card = FakeCard::new();
        card.mount(Access::ReadOnly).unwrap();
        card.ops.clear();
        rescue(None, &mut card, None, LONG, &mut || {});
        assert_eq!(card.read("config.txt"), PIOS);
        assert_eq!(card.ops, WRITE_OPS);
        assert!(!card.mounted);
    }

    #[test]
    fn a_log_that_is_locked_is_skipped_and_config_txt_is_still_restored() {
        let log = Arc::new(log_holding(&["first"]));
        let held = log.lock().unwrap();
        // On a thread of its own, so that a rescue that waits for the log
        // fails this test and does not hang it.
        let (done, outcome) = mpsc::channel();
        thread::spawn({
            let log = Arc::clone(&log);
            move || {
                let mut card = FakeCard::new();
                rescue(None, &mut card, Some(&log), LONG, &mut || {});
                done.send(card)
            }
        });
        let card = outcome
            .recv_timeout(Duration::from_secs(5))
            .expect("rescue waited for the log");
        drop(held);
        assert_eq!(card.read("config.txt"), PIOS);
        assert!(!card.has("qberrypi/log.txt"));
        assert_eq!(card.ops, WRITE_OPS);
    }

    #[test]
    fn a_backup_that_cannot_be_restored_does_not_stop_the_log_being_saved() {
        let mut card = FakeCard::new();
        card.remove("config.pios.txt");
        let log = log_holding(&["first"]);
        rescue(None, &mut card, Some(&log), LONG, &mut || {});
        assert_eq!(card.read("config.txt"), QBERRYPI);
        assert_eq!(card.read("qberrypi/log.txt"), header() + "first\n");
        assert_eq!(card.ops, WRITE_OPS);
    }

    #[test]
    fn a_card_that_does_not_mount_ends_the_rescue_and_keeps_the_log() {
        let mut card = FakeCard::new();
        card.mount_fails = true;
        let log = log_holding(&["first"]);
        rescue(None, &mut card, Some(&log), LONG, &mut || {});
        assert_eq!(card.ops, ["unmount", "mount writable"]);
        assert_eq!(card.read("config.txt"), QBERRYPI);
        assert_eq!(log.lock().unwrap().take_unsaved(), "first\n");
    }

    #[test]
    fn a_log_that_another_thread_holds_for_a_moment_is_still_saved_by_the_rescue() {
        let log = Arc::new(log_holding(&["first"]));
        let (held, ready) = mpsc::channel();
        let holder = thread::spawn({
            let log = Arc::clone(&log);
            move || {
                let guard = log.lock().unwrap();
                held.send(()).unwrap();
                thread::sleep(50 * MS);
                drop(guard);
            }
        });
        ready.recv().unwrap();
        let mut card = FakeCard::new();
        rescue(None, &mut card, Some(&log), LONG, &mut || {});
        holder.join().unwrap();
        assert_eq!(card.read("qberrypi/log.txt"), header() + "first\n");
    }

    // More than one thread.

    #[test]
    fn a_second_fatal_error_waits_for_the_first_unless_it_is_the_first_failing_again() {
        let (a, b) = (
            thread::current().id(),
            thread::spawn(|| thread::current().id()).join().unwrap(),
        );
        assert_eq!(fatal_entry(None, a), FatalEntry::First);
        assert_eq!(fatal_entry(Some(a), a), FatalEntry::Again);
        assert_eq!(fatal_entry(Some(a), b), FatalEntry::Elsewhere);
        assert!(may_pet(None, a) && may_pet(Some(a), a) && !may_pet(Some(a), b));
    }

    // The panel's component.

    #[test]
    fn a_panel_without_a_screen_is_absent_and_one_that_broke_is_a_failure() {
        assert_eq!(
            panel_ended(PanelEnd::NoScreen("no fb_ili9486 framebuffer".into())),
            Ended::Absent("no fb_ili9486 framebuffer".into())
        );
        assert_eq!(
            panel_ended(PanelEnd::Failed("writing the screen: gone".into())),
            Ended::Failed("writing the screen: gone".into())
        );
    }

    #[test]
    fn the_panel_is_given_the_configured_calibration_and_whether_to_measure_it() {
        let plain = panel_deps(&config::parse(EXAMPLE).unwrap(), &Slot::new());
        assert_eq!(plain.calibration, Calibration::NOMINAL);
        assert!(!plain.calibrate);

        let text = format!("{EXAMPLE}\n[panel]\ntouch_left = 3890\ntouch_swap_xy = true\n");
        let text = text.replace("calibrate_touch = false", "calibrate_touch = true");
        let set = panel_deps(&config::parse(&text).unwrap(), &Slot::new());
        assert_eq!(
            set.calibration,
            Calibration {
                swap_xy: true,
                left: 3890,
                right: 3900,
                top: 200,
                bottom: 3900
            }
        );
        assert!(set.calibrate);
    }

    // The panel's lane is the slot's own, which the resolver offers its names to; there is no alert
    // until the watchdog's store is in the slot.
    #[test]
    fn the_panel_is_given_the_slots_lane_and_no_alert_until_the_store_is_in_the_slot() {
        let slot = Slot::new();
        let deps = panel_deps(&config::parse(EXAMPLE).unwrap(), &slot);
        assert!(Arc::ptr_eq(&deps.lane, &slot.lane()));
        assert!(deps.alerts.top().is_none());
        deps.alerts.ack(1);
    }

    // What the panel is given answers as nothing until the resolver is in the slot.
    #[test]
    fn the_panels_switch_does_nothing_until_the_resolver_is_in_the_slot() {
        let slot = Slot::new();
        let deps = panel_deps(&config::parse(EXAMPLE).unwrap(), &slot);
        deps.control.pause_for(300);
        assert_eq!(deps.control.paused_left_secs(), None);
        assert_eq!(deps.source.snapshot(), Snapshot::default());
        assert!(deps.source.recent(5).is_empty());
    }

    /// The `[api]` section whose password is `right`.
    fn api_section() -> String {
        let hash = crate::api::password::PasswordHash::new(b"right", [0; 16]);
        format!("[api]\npassword_hash = \"{}\"\n", hash.to_text())
    }

    /// The names and the essential flags of every component of the board, in the order that the
    /// supervisor starts them, for the example configuration with `extra` added and `fault` as the
    /// debug fault. Nothing in it starts.
    fn components_started(extra: &str, fault: &str) -> Vec<(&'static str, bool)> {
        let text = EXAMPLE.replace("fault = \"none\"", &format!("fault = \"{fault}\""));
        let cfg: &'static Config = Box::leak(Box::new(
            config::parse(&format!("{text}\n{extra}")).unwrap(),
        ));
        let log: &'static Mutex<LogBuf> = Box::leak(Box::new(log_holding(&[])));
        let slot = Slot::new();
        let signal = SignalCache::new();
        let (status_sender, status) = watch::channel(WifiStatus::Starting);
        let components = components(
            Context {
                cfg,
                log,
                started: Instant::now(),
                slot: slot.clone(),
                wifi: status.clone(),
                signal: signal.clone(),
                tls_pem: None,
            },
            &BoardParts {
                cfg,
                log,
                wlan_present: true,
                status_sender: Cell::new(Some(status_sender)),
                saves: LogSaves::new(),
                status,
                signal,
                slot,
            },
        );
        components.iter().map(|c| (c.name, c.essential)).collect()
    }

    // Every feature adds its component to one of two tables (`services::SERVICES` and
    // `BOARD_COMPONENTS`), and this is the one test that says what the whole board starts, in
    // order: the services, then the Wi-Fi, the signal reader, the panel, and the provoked fault
    // last.
    #[tokio::test]
    async fn the_board_starts_the_services_then_its_own_components_in_one_fixed_order() {
        assert_eq!(
            components_started("", "none"),
            [
                ("dns", true),
                ("utc offset", true),
                ("clock", true),
                ("status", true),
                ("lists", true),
                ("analysis", false),
                ("devices", false),
                ("wifi", true),
                ("signal", true),
                ("panel", false),
            ]
        );
        // With an `[api]` section the API follows the watchdog, and a fault that fails the board
        // comes last of all.
        assert_eq!(
            components_started(&api_section(), "crash-loop"),
            [
                ("dns", true),
                ("utc offset", true),
                ("clock", true),
                ("status", true),
                ("lists", true),
                ("analysis", false),
                ("devices", false),
                ("api", false),
                ("wifi", true),
                ("signal", true),
                ("panel", false),
                ("fault", true),
            ]
        );
    }
}
