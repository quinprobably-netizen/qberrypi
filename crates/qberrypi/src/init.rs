//! What the executable does as PID 1: the boot sequence, and the way out when it fails.
//!
//! [`run`] is the sequence, one function per step. Whatever stops it goes
//! through `fatal`, which restarts the board. In one-shot mode, and whenever
//! the configuration never got read, it first puts Raspberry Pi OS's
//! `config.txt` back, so a failure cannot leave the Pi starting qberrypi
//! over and over.

use std::fs::File;
use std::io::{self, Write};
use std::net::{Ipv6Addr, UdpSocket};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError, TryLockError};
use std::thread;
use std::time::{Duration, Instant};

use crate::bootpart::{self, BOOT_DEV, MOUNT_POINT};
use crate::config::{self, Config};
use crate::kmsg;
use crate::led::{self, LED_DIR, LedState};
use crate::logbuf::{self, LogBuf};
use crate::modules::{self, Insert, MODULE_LIST, ModuleTable};
use crate::sys::{self, Watchdog};
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

/// How long the board may go without a pet before the watchdog restarts it.
const WATCHDOG_SECS: u32 = 15;
/// How often the watchdog is petted, at the least, while init waits.
const PET_EVERY: Duration = Duration::from_secs(5);
/// How often a wait looks whether what it waits for has happened.
const POLL_EVERY: Duration = Duration::from_millis(50);
const BOOT_DEV_WAIT: Duration = Duration::from_secs(10);
const WLAN_WAIT: Duration = Duration::from_secs(20);
/// How long a fatal message stays on the console before the restart.
const FATAL_PAUSE: Duration = Duration::from_secs(5);

/// The log, from step 1 on. `fatal` saves it to the card.
static LOG: OnceLock<&'static Mutex<LogBuf>> = OnceLock::new();
/// The configuration, from step 4 on. `fatal` asks it whether to restore.
static CONFIG: OnceLock<Config> = OnceLock::new();
/// The watchdog; a stand-in that does nothing until step 3 opens the real one.
static WATCHDOG: Mutex<Watchdog> = Mutex::new(Watchdog::absent());
/// Set once `fatal` has begun, so that a failure inside it ends at once.
static FATAL_BEGUN: AtomicBool = AtomicBool::new(false);

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
    let started = Instant::now();
    install_panic_hook();
    let log = start_logging(); // 1
    keep_clock_after_build(); // 2
    open_watchdog(); // 3
    let cfg = read_config(); // 4
    restore_if_one_shot(cfg, &mut SdCard); // 5
    load_wifi_driver(cfg); // 6
    show_serving(); // 7
    provoke_module_request(); // 7, under the self-test only
    report_wifi(); // 8
    save_log_if_asked(cfg, &mut SdCard, log); // 9
    serve(cfg, log, started) // 10
}

/// Step 1: mounts the kernel's filesystems and starts the log on the console.
fn start_logging() -> &'static Mutex<LogBuf> {
    let mounted = sys::mount_pseudo();
    let (console, console_error): (Box<dyn Write + Send>, _) =
        match File::options().write(true).open(CONSOLE) {
            Ok(console) => (Box::new(console), None),
            // Without a console the log still fills, for the card.
            Err(error) => (Box::new(io::sink()), Some(error)),
        };
    let log = *LOG.get_or_init(|| logbuf::install(console));
    log::info!("{}", banner());
    if let Some(error) = console_error {
        log::warn!("{CONSOLE}: {error}");
    }
    if let Err(error) = mounted {
        fatal(&error.to_string());
    }
    log
}

/// Step 2: makes sure the clock does not show a time before this build.
fn keep_clock_after_build() {
    match sys::clock_at_least(BUILD_EPOCH) {
        Ok(true) => log::info!("clock: set to the build time"),
        Ok(false) => {}
        Err(error) => fatal(&format!("setting the clock: {error}")),
    }
}

/// Step 3: starts the hardware watchdog. The system runs without one if it must.
fn open_watchdog() {
    match Watchdog::open(WATCHDOG_SECS) {
        Ok(watchdog) => *lock(&WATCHDOG) = watchdog,
        Err(error) => log::warn!("watchdog: {error}"),
    }
}

/// Step 4: waits for the card and reads the configuration from it.
fn read_config() -> &'static Config {
    if !wait_for(BOOT_DEV_WAIT, || Path::new(BOOT_DEV).exists()) {
        fatal(&format!("boot partition {BOOT_DEV} did not appear"));
    }
    match load_config(&mut SdCard) {
        Ok(cfg) => CONFIG.get_or_init(|| cfg),
        Err(message) => fatal(&message),
    }
}

/// Reads and checks `qberrypi.toml`. The error is the fatal message.
fn load_config(card: &mut dyn Card) -> Result<Config, String> {
    let text = with_card(card, Access::ReadOnly, bootpart::read_config_text)
        .map_err(|error| format!("mounting {BOOT_DEV}: {error}"))?
        .map_err(|error| format!("qberrypi.toml: {error}"))?;
    // The parser's errors name the file themselves.
    config::parse(&text).map_err(|error| error.to_string())
}

/// Step 5: in one-shot mode, makes the next start one of Raspberry Pi OS.
///
/// From here on, a restart for any reason leaves qberrypi. A restore that
/// cannot be done is logged and the boot goes on: stopping would not bring
/// Raspberry Pi OS back either.
fn restore_if_one_shot(cfg: &Config, card: &mut dyn Card) {
    if !cfg.debug.one_shot {
        return;
    }
    pet_watchdog();
    match with_card(card, Access::Writable, bootpart::restore_pios_config) {
        Ok(Ok(outcome)) => log::info!("config.txt: {outcome:?}"),
        Ok(Err(error)) => log::error!("config.txt: {error}"),
        Err(error) => log::error!("config.txt: mounting {BOOT_DEV}: {error}"),
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
/// `cfg80211` goes first so that it gets the country; `brcmfmac` then finds it loaded.
fn load_wifi_modules(
    table: &ModuleTable,
    country: &str,
    insert: Insert,
) -> Result<Vec<String>, String> {
    let regdom = format!("ieee80211_regdom={country}");
    let mut inserted = Vec::new();
    for (name, params) in [("cfg80211", regdom.as_str()), ("brcmfmac", "")] {
        let loaded = modules::load(table, name, params, insert)
            .map_err(|error| format!("loading {name}: {error}"))?;
        inserted.extend(loaded);
    }
    Ok(inserted)
}

/// Step 7: shows on the LED that the boot got this far. A board without the LED boots too.
fn show_serving() {
    if let Err(error) = led::set(Path::new(LED_DIR), LedState::Serving) {
        log::warn!("activity LED: {error}");
    }
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
fn report_wifi() {
    let sysfs = Path::new(SYSFS);
    wait_for(WLAN_WAIT, || sysfs.join(WLAN_IN_SYSFS).exists());
    for line in wifi_report(sysfs) {
        log::info!("{line}");
    }
    match kernel_lines(Path::new(KERNEL_LOG)) {
        Ok(lines) => lines.iter().for_each(|line| log::info!("{line}")),
        // The kernel log is for diagnosis; the boot does not depend on it.
        Err(error) => log::warn!("{KERNEL_LOG}: {error}"),
    }
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

/// Turns everything the kernel has logged so far into lines for our own log.
fn kernel_lines(kernel_log: &Path) -> io::Result<Vec<String>> {
    let records = kmsg::read_all(kernel_log)?;
    Ok(records
        .iter()
        .map(|record| format!("kernel: {}", record.text))
        .collect())
}

/// Step 9: if the configuration asks for it, appends the log to the card.
///
/// Only the lines not yet saved are written, under a header of their own.
fn save_log_if_asked(cfg: &Config, card: &mut dyn Card, log: &Mutex<LogBuf>) {
    if !cfg.debug.log_to_sd {
        return;
    }
    pet_watchdog();
    // The lines are taken only once the card is mounted, so that a card
    // that does not mount leaves them for the next save.
    let saved = with_card(card, Access::Writable, |boot| {
        let unsaved = lock(log).take_unsaved();
        bootpart::append_log(boot, &log_entry(&unsaved))
    });
    match saved {
        Ok(Ok(())) => {}
        Ok(Err(error)) => log::error!("log.txt: {error}"),
        Err(error) => log::error!("log.txt: mounting {BOOT_DEV}: {error}"),
    }
}

/// Lays out log lines for the file on the card, under a header that names the build.
fn log_entry(unsaved: &str) -> String {
    format!("==== boot, build {BUILD_EPOCH} ====\n{unsaved}")
}

/// Step 10: keeps the watchdog petted, and restarts when the configured time has passed.
fn serve(cfg: &Config, log: &Mutex<LogBuf>, started: Instant) -> ! {
    loop {
        sys::reap_children();
        match next_tick(cfg.debug.return_after_secs, started.elapsed()) {
            Some(tick) => pause(tick),
            None => {
                log::info!("returning");
                save_log_if_asked(cfg, &mut SdCard, log);
                sys::reboot();
            }
        }
    }
}

/// How long the main loop sleeps before it looks again, or `None` when it is time to restart.
///
/// `return_after_secs` is counted from the start of the boot; 0 means never.
fn next_tick(return_after_secs: u64, elapsed: Duration) -> Option<Duration> {
    if return_after_secs == 0 {
        return Some(PET_EVERY);
    }
    let left = Duration::from_secs(return_after_secs).saturating_sub(elapsed);
    (!left.is_zero()).then(|| left.min(PET_EVERY))
}

/// Stops the system: message, LED, the card put right, a pause to read, restart.
fn fatal(message: &str) -> ! {
    // A second call means the first one failed, or a panic came from inside
    // it. Nothing more is tried.
    if FATAL_BEGUN.swap(true, Ordering::SeqCst) {
        sys::reboot();
    }
    // A log that is locked was being written when the failure came. Using it
    // again from here would wait for ever, so it is left alone.
    let log = LOG.get().copied();
    let log_in_use = log.is_some_and(|log| lock_if_free(log).is_none());
    if log_in_use {
        if let Ok(mut console) = File::options().write(true).open(CONSOLE) {
            let _ = writeln!(console, "{message}");
        }
    } else {
        log::error!("{message}");
    }
    let _ = led::set(Path::new(LED_DIR), LedState::Fatal);
    rescue(CONFIG.get(), &mut SdCard, log.filter(|_| !log_in_use));
    pause(FATAL_PAUSE);
    sys::reboot()
}

/// What `fatal` does to the card: restores `config.txt` and saves the log.
///
/// Nothing is done if `restore_on_fatal` says the system is here to stay.
/// Errors are ignored: the restart comes whatever happens. `log` is the log
/// to save, and `None` if it must not be used; this logs only when it has one.
fn rescue(cfg: Option<&Config>, card: &mut dyn Card, log: Option<&Mutex<LogBuf>>) {
    if !restore_on_fatal(cfg) {
        return;
    }
    // The failure may have come while the partition was mounted.
    let _ = card.unmount();
    let _ = on_card(card, Access::Writable, |boot| {
        let restored = bootpart::restore_pios_config(boot);
        let Some(log) = log else { return };
        match restored {
            Ok(outcome) => log::info!("config.txt: {outcome:?}"),
            Err(error) => log::error!("config.txt: {error}"),
        }
        if let Some(mut buf) = lock_if_free(log) {
            let unsaved = buf.take_unsaved();
            drop(buf);
            let _ = bootpart::append_log(boot, &log_entry(&unsaved));
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
fn on_card<T>(
    card: &mut dyn Card,
    access: Access,
    work: impl FnOnce(&Path) -> T,
) -> io::Result<(T, io::Result<()>)> {
    card.mount(access)?;
    let done = work(card.dir());
    if access == Access::Writable {
        card.sync();
    }
    Ok((done, card.unmount()))
}

/// Like `on_card`, for the boot sequence: a failed unmount is logged and otherwise ignored.
fn with_card<T>(
    card: &mut dyn Card,
    access: Access,
    work: impl FnOnce(&Path) -> T,
) -> io::Result<T> {
    let (done, unmounted) = on_card(card, access, work)?;
    if let Err(error) = unmounted {
        log::warn!("unmounting {BOOT_DEV}: {error}");
    }
    Ok(done)
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
/// `pet_every`, however rarely `ready` is asked.
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
        if now >= next_pet {
            pet();
            next_pet = now + pet_every;
        }
        if ready() {
            return true;
        }
        let left = timeout.saturating_sub(start.elapsed());
        if left.is_zero() {
            return false;
        }
        let until_pet = next_pet.saturating_duration_since(Instant::now());
        thread::sleep(left.min(poll_every).min(until_pet));
    }
}

/// Pets the watchdog, unless its lock is held: then the holder is what failed.
fn pet_watchdog() {
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::io::ErrorKind;
    use std::sync::{Arc, mpsc};

    use tempfile::TempDir;

    use crate::modules::DEFAULT_TABLE;

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
            }
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
        fn dir(&self) -> &Path {
            self.dir.path()
        }

        fn mount(&mut self, access: Access) -> io::Result<()> {
            self.ops.push(match access {
                Access::ReadOnly => "mount read-only",
                Access::Writable => "mount writable",
            });
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

    const WRITE_OPS: [&str; 3] = ["mount writable", "sync", "unmount"];
    /// What `rescue` does: it first unmounts whatever the failure left mounted.
    const RESCUE_OPS: [&str; 4] = ["unmount", "mount writable", "sync", "unmount"];

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

    #[test]
    fn a_lock_that_is_held_is_not_waited_for() {
        let mutex = Mutex::new(7);
        {
            let _held = mutex.lock().unwrap();
            assert!(lock_if_free(&mutex).is_none());
        }
        assert_eq!(lock_if_free(&mutex).as_deref(), Some(&7));
    }

    // The main loop.

    #[test]
    fn the_main_loop_looks_again_within_the_pet_interval() {
        let secs = Duration::from_secs;
        // Never returning: a tick is one pet interval.
        assert_eq!(next_tick(0, secs(0)), Some(PET_EVERY));
        assert_eq!(next_tick(0, secs(1_000_000)), Some(PET_EVERY));
        // Returning after a minute: no tick goes past the minute.
        assert_eq!(next_tick(60, secs(0)), Some(PET_EVERY));
        assert_eq!(next_tick(60, secs(54)), Some(PET_EVERY));
        assert_eq!(next_tick(60, secs(58)), Some(secs(2)));
        assert_eq!(
            next_tick(60, Duration::from_millis(59_900)),
            Some(Duration::from_millis(100))
        );
    }

    #[test]
    fn the_main_loop_returns_once_the_time_has_passed() {
        let secs = Duration::from_secs;
        assert_eq!(next_tick(60, secs(60)), None);
        assert_eq!(next_tick(60, secs(600)), None);
        assert_eq!(next_tick(5, Duration::from_millis(4_999)), Some(MS));
        assert_eq!(next_tick(u64::MAX, secs(600)), Some(PET_EVERY));
    }

    // Step 4: the configuration.

    #[test]
    fn the_config_is_read_from_a_read_only_mount() {
        let mut card = FakeCard::new();
        let cfg = load_config(&mut card).unwrap();
        assert_eq!(cfg.hostname, "qberrypi");
        assert_eq!(card.ops, ["mount read-only", "unmount"]);
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
        assert_eq!(card.ops, ["mount read-only", "unmount"]);
    }

    #[test]
    fn a_config_that_does_not_parse_is_fatal_with_the_parser_error() {
        let mut card = FakeCard::new();
        card.write("qberrypi/qberrypi.toml", "this is not toml");
        let expected = config::parse("this is not toml").unwrap_err().to_string();
        assert!(expected.starts_with("qberrypi.toml: "));
        assert_eq!(load_config(&mut card).unwrap_err(), expected);
        assert_eq!(card.ops, ["mount read-only", "unmount"]);
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
        assert_eq!(card.ops, ["mount read-only"]);
    }

    #[test]
    fn a_failed_unmount_does_not_lose_the_config() {
        let mut card = FakeCard::new();
        card.unmount_fails = true;
        assert_eq!(load_config(&mut card).unwrap().hostname, "qberrypi");
    }

    // Step 5: one-shot mode.

    #[test]
    fn one_shot_restores_config_txt_then_syncs_and_unmounts() {
        let mut card = FakeCard::new();
        restore_if_one_shot(&cfg_with_one_shot(true), &mut card);
        assert_eq!(card.read("config.txt"), PIOS);
        assert_eq!(card.ops, WRITE_OPS);
    }

    #[test]
    fn without_one_shot_the_card_is_not_touched() {
        let mut card = FakeCard::new();
        restore_if_one_shot(&cfg_with_one_shot(false), &mut card);
        assert!(card.ops.is_empty());
        assert_eq!(card.read("config.txt"), QBERRYPI);
    }

    #[test]
    fn a_backup_that_is_refused_still_ends_in_sync_and_unmount() {
        let mut card = FakeCard::new();
        card.remove("config.pios.txt");
        restore_if_one_shot(&cfg_with_one_shot(true), &mut card);
        assert_eq!(card.read("config.txt"), QBERRYPI);
        assert_eq!(card.ops, WRITE_OPS);
    }

    #[test]
    fn a_restore_that_fails_still_ends_in_sync_and_unmount() {
        let mut card = FakeCard::new();
        // A directory where the backup should be can be neither read nor restored.
        card.remove("config.pios.txt");
        fs::create_dir(card.dir().join("config.pios.txt")).unwrap();
        restore_if_one_shot(&cfg_with_one_shot(true), &mut card);
        assert_eq!(card.read("config.txt"), QBERRYPI);
        assert_eq!(card.ops, WRITE_OPS);
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
                ("/lib/modules/brcmfmac.ko", ""),
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
        assert_eq!(
            kernel_lines(&path).unwrap(),
            ["kernel: qberrypi-modhelper: net-pf-10: not in table"]
        );
    }

    #[test]
    fn a_kernel_log_that_cannot_be_read_is_an_error_to_report() {
        let tmp = tempfile::tempdir().unwrap();
        let error = kernel_lines(&tmp.path().join("absent")).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotFound);
    }

    // Step 9: the log on the card.

    #[test]
    fn a_saved_log_starts_with_the_build_header() {
        assert_eq!(
            log_entry("a\nb\n"),
            format!("==== boot, build {} ====\na\nb\n", crate::BUILD_EPOCH)
        );
    }

    #[test]
    fn the_log_is_saved_when_asked_and_each_line_once() {
        let mut card = FakeCard::new();
        let log = log_holding(&["first"]);
        let cfg = cfg_with_log_to_sd(true);

        save_log_if_asked(&cfg, &mut card, &log);
        assert_eq!(card.read("qberrypi/log.txt"), header() + "first\n");
        assert_eq!(card.ops, WRITE_OPS);

        log.lock().unwrap().push("second");
        save_log_if_asked(&cfg, &mut card, &log);
        assert_eq!(
            card.read("qberrypi/log.txt"),
            header() + "first\n" + &header() + "second\n"
        );
        assert_eq!(card.ops, [WRITE_OPS, WRITE_OPS].concat());
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

    #[test]
    fn a_failure_before_the_config_is_known_restores_config_txt_and_saves_the_log() {
        let mut card = FakeCard::new();
        let log = log_holding(&["qberrypi.toml: (syntax): not valid TOML"]);
        rescue(None, &mut card, Some(&log));
        assert_eq!(card.read("config.txt"), PIOS);
        assert_eq!(
            card.read("qberrypi/log.txt"),
            header() + "qberrypi.toml: (syntax): not valid TOML\n"
        );
        assert_eq!(card.ops, RESCUE_OPS);
    }

    #[test]
    fn a_failure_in_one_shot_mode_restores_config_txt_and_saves_the_log() {
        let mut card = FakeCard::new();
        let log = log_holding(&["loading brcmfmac: bad signature"]);
        rescue(Some(&cfg_with_one_shot(true)), &mut card, Some(&log));
        assert_eq!(card.read("config.txt"), PIOS);
        assert!(card.read("qberrypi/log.txt").ends_with("bad signature\n"));
        assert_eq!(card.ops, RESCUE_OPS);
    }

    #[test]
    fn a_failure_of_a_permanent_system_leaves_the_card_alone() {
        let mut card = FakeCard::new();
        let log = log_holding(&["loading brcmfmac: bad signature"]);
        rescue(Some(&cfg_with_one_shot(false)), &mut card, Some(&log));
        // Not even with the log switched on: only one-shot mode writes on the way out.
        rescue(Some(&cfg_with_log_to_sd(true)), &mut card, Some(&log));
        assert!(card.ops.is_empty());
        assert_eq!(card.read("config.txt"), QBERRYPI);
        assert!(!card.has("qberrypi/log.txt"));
    }

    #[test]
    fn a_failure_while_the_card_was_mounted_still_restores() {
        let mut card = FakeCard::new();
        card.mount(Access::ReadOnly).unwrap();
        card.ops.clear();
        rescue(None, &mut card, None);
        assert_eq!(card.read("config.txt"), PIOS);
        assert_eq!(card.ops, RESCUE_OPS);
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
                rescue(None, &mut card, Some(&log));
                done.send(card)
            }
        });
        let card = outcome
            .recv_timeout(Duration::from_secs(5))
            .expect("rescue waited for the log");
        drop(held);
        assert_eq!(card.read("config.txt"), PIOS);
        assert!(!card.has("qberrypi/log.txt"));
        assert_eq!(card.ops, RESCUE_OPS);
    }

    #[test]
    fn a_backup_that_cannot_be_restored_does_not_stop_the_log_being_saved() {
        let mut card = FakeCard::new();
        card.remove("config.pios.txt");
        let log = log_holding(&["first"]);
        rescue(None, &mut card, Some(&log));
        assert_eq!(card.read("config.txt"), QBERRYPI);
        assert_eq!(card.read("qberrypi/log.txt"), header() + "first\n");
        assert_eq!(card.ops, RESCUE_OPS);
    }

    #[test]
    fn a_card_that_does_not_mount_ends_the_rescue_and_keeps_the_log() {
        let mut card = FakeCard::new();
        card.mount_fails = true;
        let log = log_holding(&["first"]);
        rescue(None, &mut card, Some(&log));
        assert_eq!(card.ops, ["unmount", "mount writable"]);
        assert_eq!(card.read("config.txt"), QBERRYPI);
        assert_eq!(log.lock().unwrap().take_unsaved(), "first\n");
    }
}
