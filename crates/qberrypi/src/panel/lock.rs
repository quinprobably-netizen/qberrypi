//! The panel's lock and its night hours: what the owner sets on SYSTEM, and what the strong actions ask
//! before they are done (spec `2026-11-12-qberrypi-panel-os-design.md` §7 and §5.4).
//!
//! **The lock.** [`Lock`] holds at most one PIN, as a salted PBKDF2-HMAC-SHA256 hash of its four digits
//! ([`PasswordHash`], 10,000 rounds: `cargo xtask hash-pin` makes the line), and says where the PIN came
//! from ([`Source`]): the slot's `qberrypi.toml` (it survives a restart), the desktop's
//! `PUT /api/qbp/panel`, or the panel itself (these two last as long as the card keeps the state, else for
//! the boot). The latest set wins. It is off until a PIN is set. The hash is never given out: [`Lock::view`]
//! says whether the lock is on and where the PIN came from, and nothing else, and no `Debug` here prints a
//! digit or a hash.
//!
//! **Checking.** The panel's four digits come as a `Zeroizing<[u8; 4]>` (`qb_panel::os::PinDigits::
//! into_zeroizing`); [`Lock::verify`] turns them into the four ASCII digits that `hash-pin` hashed, in a
//! holder that is wiped as well, and compares with [`PasswordHash::verify`], in constant time. It runs
//! on the panel's thread (10,000 rounds; the Drain is not shown meanwhile) and holds the lock's own mutex
//! for it, so that two checks can never be made at once and the backoff cannot be raced.
//!
//! **Backoff** (spec §7.3), on a clock that is given to the lock: three wrong PINs in a row make it
//! wait [`WAIT_FIRST_SECS`] (30 s); each wrong one after that doubles the wait, up to [`WAIT_MAX_SECS`]
//! (15 min); a right PIN starts the count again. While it waits, no check is made at all: [`Lock::verify`]
//! answers [`Check::Wait`] with what is left, whatever the digits are. A wrong PIN logs, at WARN,
//! `panel: wrong PIN (n in a row)`: the count and nothing else. The counter lives in memory and is not
//! kept, so a power cycle resets it (spec §7.3: accepted for a household's lock). Setting, changing or clearing the PIN
//! starts the count again too.
//!
//! **Night hours** are one small value, [`PanelState::night`], that the panel and the API edit: from the
//! configuration's `[panel] night` (default `23-07`), `HH-HH` as hours of the day, or none.
//!
//! **What outlasts a restart.** With the card keeping the state ([`PanelState::with_kept`]), a PIN that
//! the desktop or the panel set and the night hours are given by [`PanelState::kept_state`] and taken back
//! at the start by [`PanelState::restore`], each only if the configuration still says what it said when it
//! was saved: the PIN under the same `pin_hash` (compared as a fingerprint), the night under the same
//! `[panel] night`, so that an owner who changes the file and updates gets the file's. A PIN from the
//! configuration, a lock that was turned off, and the count of wrong PINs are never kept: the lock starts
//! as the configuration has it, with the count at 0. Neither logs a hash or a digit, and a restore logs
//! nothing.
//!
//! **Wiring.** [`PanelState`] is the one object: the API edits it (`PUT /api/qbp/panel`) and
//! `wiring::Slot` hands the panel [`LockControl`] over it once the first service has made it
//! (`Slot::fill_lock`), as for the devices and the names. Until then the panel finds no night, and a lock that
//! fails closed: it reads as on, so that the strong keys ask, and it refuses every check (`Check::Wait`,
//! nothing counted wrong), so that no strong action can pass before the real lock is there.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use zeroize::Zeroizing;

use crate::api::password::{PIN_ROUNDS, PasswordHash};
use crate::state::{SavedPanel, SavedPin, pin_fingerprint};

/// How many wrong PINs in a row the lock lets pass before it makes the owner wait.
pub const WRONG_BEFORE_WAIT: u32 = 3;

/// How long the first wait is, in seconds: after the third wrong PIN in a row.
pub const WAIT_FIRST_SECS: u32 = 30;

/// The longest wait there is, in seconds: 15 minutes.
pub const WAIT_MAX_SECS: u32 = 15 * 60;

/// The hours that a configuration without `[panel] night` has: dark from 23:00 until 07:00.
pub const DEFAULT_NIGHT: (u8, u8) = (23, 7);

/// The seconds that a clock of the lock counts, from any fixed start (a monotonic clock).
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Where the PIN came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// `[panel] pin_hash` in the slot's configuration: it survives a restart.
    Config,
    /// `PUT /api/qbp/panel`: for this boot, and further when the card keeps the state.
    Api,
    /// Set on the panel itself: for this boot, and further when the card keeps the state.
    Panel,
}

impl Source {
    /// The word `GET /api/qbp/panel` says: `config`, `api` or `panel`.
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Config => "config",
            Source::Api => "api",
            Source::Panel => "panel",
        }
    }
}

/// What a check of four digits came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    /// The PIN is right (or none is set, so that nothing is guarded).
    Right,
    /// It is wrong.
    Wrong,
    /// The lock is making the owner wait this many more seconds, and checked nothing.
    Wait(u32),
}

/// Whether the lock is on, and where its PIN came from; never the PIN or its hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockView {
    /// A PIN is set.
    pub on: bool,
    /// Where it came from; `None` while the lock is off.
    pub source: Option<Source>,
    /// Whether the card keeps the state, so that a PIN from the desktop or the panel and the night
    /// hours outlast a restart: true whatever the source, and false from [`Lock::view`], which does
    /// not know (the state does: [`PanelState::lock_view`]).
    pub kept: bool,
}

/// What the panel asks of the lock and of the night hours, and does to them: the control the panel is
/// given, in the way [`super::devices::DeviceControl`] is the devices' and
/// [`super::names::NamesControl`] the names'.
pub trait LockControl: Send + Sync {
    /// Checks the four digits typed on the pad (each 0 to 9) against the PIN, and counts a wrong one
    /// (the backoff). It runs 10,000 rounds of PBKDF2 on the calling thread, which is the panel's.
    /// Right when no PIN is set.
    fn verify(&self, digits: Zeroizing<[u8; 4]>) -> Check;

    /// How many seconds the lock still makes the owner wait before it takes a PIN, 0 when it does not:
    /// what the loop puts in `World::pin_wait_secs` while the pad shows.
    fn wait_left(&self) -> u32;

    /// Sets the PIN from the panel (source [`Source::Panel`]): the hash is made here, on
    /// the panel's thread, with 10,000 rounds. Whether the lock took it (`false` when there is no
    /// lock, or the kernel gave no salt).
    fn set_pin(&self, digits: Zeroizing<[u8; 4]>) -> bool;

    /// Turns the lock off.
    fn clear_pin(&self);

    /// Whether the lock is on, and where its PIN came from.
    fn lock_view(&self) -> LockView;

    /// The night hours `(from, to)` as hours of the day, or `None` for no night: what `GET
    /// /api/qbp/panel` says.
    fn night(&self) -> Option<(u8, u8)>;

    /// Sets the night hours; `None`, or the two hours equal, is no night.
    fn set_night(&self, night: Option<(u8, u8)>);
}

/// A control with no lock and no night, for as long as nothing is set: what the panel's own tests give it.
pub struct NoLock;

impl LockControl for NoLock {
    fn verify(&self, _digits: Zeroizing<[u8; 4]>) -> Check {
        Check::Right
    }

    fn wait_left(&self) -> u32 {
        0
    }

    fn set_pin(&self, _digits: Zeroizing<[u8; 4]>) -> bool {
        false
    }

    fn clear_pin(&self) {}

    fn lock_view(&self) -> LockView {
        LockView {
            on: false,
            source: None,
            kept: false,
        }
    }

    fn night(&self) -> Option<(u8, u8)> {
        None
    }

    fn set_night(&self, _night: Option<(u8, u8)>) {}
}

/// The PIN, its source and the count of wrong tries, behind the lock's own mutex.
struct Inner {
    /// The PIN's hash, while the lock is on.
    hash: Option<PasswordHash>,
    /// Where it came from, while the lock is on.
    source: Option<Source>,
    /// Wrong PINs in a row, since the last right one (or the last change of the PIN).
    wrong: u32,
    /// The second of the lock's clock at which the wait ends; before it, nothing is checked.
    wait_until: u64,
}

/// The lock: at most one PIN, as a hash, with the backoff that guards it.
pub struct Lock {
    inner: Mutex<Inner>,
    clock: Clock,
}

impl Lock {
    /// A lock whose PIN is `config_hash`, from the configuration (source [`Source::Config`]), or off
    /// with none; it waits by `clock`.
    pub fn new(config_hash: Option<PasswordHash>, clock: Clock) -> Self {
        let source = config_hash.as_ref().map(|_| Source::Config);
        Self {
            inner: Mutex::new(Inner {
                hash: config_hash,
                source,
                wrong: 0,
                wait_until: 0,
            }),
            clock,
        }
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        // The state holds no half-made change: every mutation below is a few plain assignments.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Checks `digits`, each 0 to 9 as the pad gives them, against the PIN: [`Check::Right`] (and the
    /// count starts again) or [`Check::Wrong`] (counted, and the third in a row starts the wait), or
    /// [`Check::Wait`] with the seconds left, without a check, while the lock waits. Right with no PIN set.
    pub fn verify(&self, digits: Zeroizing<[u8; 4]>) -> Check {
        let now = (self.clock)();
        let mut inner = self.inner();
        let Some(hash) = inner.hash.as_ref() else {
            return Check::Right;
        };
        if now < inner.wait_until {
            return Check::Wait(secs_left(inner.wait_until, now));
        }
        let ascii = ascii_digits(&digits);
        if hash.verify(&*ascii) {
            inner.wrong = 0;
            inner.wait_until = 0;
            return Check::Right;
        }
        inner.wrong = inner.wrong.saturating_add(1);
        // The count and nothing else: no digit, and no hash.
        log::warn!("panel: wrong PIN ({} in a row)", inner.wrong);
        let wait = backoff_secs(inner.wrong);
        if wait > 0 {
            inner.wait_until = now.saturating_add(u64::from(wait));
        }
        Check::Wrong
    }

    /// The seconds that the lock still waits before it checks a PIN; 0 when it is not waiting.
    pub fn wait_left(&self) -> u32 {
        let now = (self.clock)();
        let inner = self.inner();
        secs_left(inner.wait_until, now)
    }

    /// Sets the PIN to `digits` (each 0 to 9) from the panel, for this boot: the hash is made here with
    /// [`PIN_ROUNDS`] rounds and a salt from the kernel, so it is the caller's thread that pays for it.
    /// `false`, and the lock as it was, when the kernel gave no salt.
    pub fn set_from_panel(&self, digits: Zeroizing<[u8; 4]>) -> bool {
        let mut salt = [0_u8; 16];
        if crate::sys::random_bytes(&mut salt).is_err() {
            return false;
        }
        let ascii = ascii_digits(&digits);
        // Made before the mutex is taken: the others wait for nothing.
        let hash = PasswordHash::with_rounds(&*ascii, salt, PIN_ROUNDS);
        self.install(Some(hash), Some(Source::Panel));
        log::info!("panel: the PIN was set on the panel");
        true
    }

    /// Puts `hash` in place of the PIN, from `source` (the desktop's push), or turns the lock off with
    /// `None`. Starts the count of wrong PINs again, unless `hash` is the one in force already: qnet
    /// pushes its hash again after every start, and that must not clear a wait that is running (nor
    /// change where the PIN is said to live: a hash that the configuration holds goes on outliving a
    /// restart).
    pub fn set_hash(&self, hash: Option<PasswordHash>, source: Source) {
        let on = hash.is_some();
        let unchanged = {
            let mut inner = self.inner();
            // Two hashes are the same PIN when their lines are: the rounds, the salt and the hash.
            let same = matches!(
                (&inner.hash, &hash),
                (Some(held), Some(new)) if held.to_text() == new.to_text()
            );
            if !same {
                inner.hash = hash;
                inner.source = on.then_some(source);
                inner.wrong = 0;
                inner.wait_until = 0;
            }
            same
        };
        if unchanged {
            log::info!("panel: the PIN was pushed again, unchanged");
            return;
        }
        match (on, source) {
            (true, Source::Api) => log::info!("panel: the PIN was pushed from the desktop"),
            (true, _) => log::info!("panel: the PIN was set"),
            (false, _) => log::info!("panel: the lock was turned off"),
        }
    }

    /// Turns the lock off, for this boot.
    pub fn clear(&self) {
        self.install(None, None);
        log::info!("panel: the lock was turned off");
    }

    fn install(&self, hash: Option<PasswordHash>, source: Option<Source>) {
        let mut inner = self.inner();
        inner.hash = hash;
        inner.source = source;
        inner.wrong = 0;
        inner.wait_until = 0;
    }

    /// Whether the lock is on and where its PIN came from. `kept` is false: whether the card keeps
    /// the state is the [`PanelState`]'s to say.
    pub fn view(&self) -> LockView {
        let inner = self.inner();
        LockView {
            on: inner.hash.is_some(),
            source: inner.source,
            kept: false,
        }
    }

    /// The PIN as it is kept: a copy of its hash and its source, when the lock is on and the PIN came
    /// from the desktop or the panel. `None` for the configuration's PIN (it is in the file) and for
    /// a lock that is off.
    fn kept_pin(&self) -> Option<SavedPin> {
        let inner = self.inner();
        match (&inner.hash, inner.source) {
            (Some(hash), Some(source @ (Source::Api | Source::Panel))) => Some(SavedPin {
                source,
                hash: hash.clone(),
            }),
            _ => None,
        }
    }

    /// Puts a kept PIN in force, with the source it had and the count of wrong PINs and the wait at
    /// nothing, as for any new PIN. It logs nothing.
    fn restore_pin(&self, pin: SavedPin) {
        self.install(Some(pin.hash), Some(pin.source));
    }
}

impl fmt::Debug for Lock {
    /// Whether the lock is on and its source: never the hash, and no digit is held here.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let view = self.view();
        f.debug_struct("Lock")
            .field("on", &view.on)
            .field("source", &view.source)
            .finish_non_exhaustive()
    }
}

/// The four ASCII digits that `cargo xtask hash-pin` hashes for the digits 0 to 9 the pad gives (a value over
/// 9 is kept as 9, as the pad's own type keeps it), in a holder that is wiped when it is dropped.
fn ascii_digits(digits: &[u8; 4]) -> Zeroizing<[u8; 4]> {
    let mut ascii = Zeroizing::new([0_u8; 4]);
    for (out, digit) in ascii.iter_mut().zip(digits) {
        *out = b'0' + (*digit).min(9);
    }
    ascii
}

/// The seconds from `now` until `until`, 0 once it has passed.
fn secs_left(until: u64, now: u64) -> u32 {
    u32::try_from(until.saturating_sub(now)).unwrap_or(u32::MAX)
}

/// How long the lock waits after the `wrong`th wrong PIN in a row: 0 up to the second one, then 30 s, and
/// double each one after, to [`WAIT_MAX_SECS`].
pub fn backoff_secs(wrong: u32) -> u32 {
    if wrong < WRONG_BEFORE_WAIT {
        return 0;
    }
    let doublings = (wrong - WRONG_BEFORE_WAIT).min(16);
    (WAIT_FIRST_SECS << doublings).min(WAIT_MAX_SECS)
}

/// The lock and the night hours, which the panel and the API share.
pub struct PanelState {
    lock: Lock,
    night: Mutex<Option<(u8, u8)>>,
    /// The fingerprint of the configuration's PIN hash ([`pin_fingerprint`]), zeros for none: what a
    /// kept PIN was set under.
    pin_config: [u8; 32],
    /// The configuration's night hours: what a kept night was set under.
    night_config: Option<(u8, u8)>,
    /// Whether the card keeps the state ([`PanelState::with_kept`]): true while saving is on, and
    /// false from the moment it is off for the boot ([`PanelState::stop_keeping`]).
    kept: AtomicBool,
}

impl PanelState {
    /// The state of a boot that starts with `config_hash` as its PIN (or none) and `night` as its night
    /// hours (`None` for no night; two equal hours are none as well, as for [`LockControl::set_night`]),
    /// waiting by `clock`. The configuration's PIN and night are what a kept state is taken back
    /// under. The card does not keep the state until [`PanelState::with_kept`] says so.
    pub fn new(config_hash: Option<PasswordHash>, night: Option<(u8, u8)>, clock: Clock) -> Self {
        let night = night.filter(|&(from, to)| from != to);
        Self {
            pin_config: pin_fingerprint(config_hash.as_ref()),
            night_config: night,
            lock: Lock::new(config_hash, clock),
            night: Mutex::new(night),
            kept: AtomicBool::new(false),
        }
    }

    /// Says whether the card keeps the state: what [`LockView::kept`] tells, and so what the LOCK
    /// screen says of how long a PIN lasts. It is true only when persistence is on and saving is
    /// working for this boot, so a start whose read of the card found trouble says false. It
    /// changes nothing else here; whoever keeps the state calls [`PanelState::kept_state`] and
    /// [`PanelState::restore`].
    pub fn with_kept(self, kept: bool) -> Self {
        self.kept.store(kept, Ordering::Relaxed);
        self
    }

    /// Says that the card no longer keeps the state, because saving went off for this boot (a failed
    /// write, a card that cannot be written in place, a refused creation): the LOCK screen stops
    /// saying that a PIN outlasts a restart. It is never turned on again for the boot.
    pub fn stop_keeping(&self) {
        self.kept.store(false, Ordering::Relaxed);
    }

    /// What is kept of the lock and the night ([`SavedPanel`]): the PIN, when the desktop or the panel
    /// set it (never the configuration's, and nothing for a lock turned off), the night hours as they
    /// are now (none included, and two equal hours are never one), and the configuration's PIN
    /// fingerprint and night they stand against. A copy under two small locks; no hash is logged.
    pub fn kept_state(&self) -> SavedPanel {
        SavedPanel {
            pin: self.lock.kept_pin(),
            pin_config: self.pin_config,
            night: self.night(),
            night_config: self.night_config,
        }
    }

    /// Takes back what [`PanelState::kept_state`] gave, at the start, and logs nothing.
    ///
    /// A saved PIN is put back, with its source, only if the configuration's PIN is still the one it
    /// was saved under (the same fingerprint, none included) and the source is the desktop's or the
    /// panel's; the count of wrong PINs and any wait start from nothing, as for any new PIN. Otherwise
    /// the lock is left as the configuration has it. A saved night, none included, is put back only
    /// if the configuration's night is still the one it was saved under; otherwise the
    /// configuration's stays. Each is judged alone. Nothing is touched when there is nothing to put back,
    /// so that a restore cannot clear a wait that is running (it is made before anything serves).
    pub fn restore(&self, saved: SavedPanel) {
        if let Some(pin) = saved.pin
            && saved.pin_config == self.pin_config
            && matches!(pin.source, Source::Api | Source::Panel)
        {
            self.lock.restore_pin(pin);
        }
        if saved.night_config == self.night_config {
            *self.night_slot() = saved.night.filter(|&(from, to)| from != to);
        }
    }

    /// The lock, for the API's edits (`PUT /api/qbp/panel`).
    pub fn lock(&self) -> &Lock {
        &self.lock
    }

    fn night_slot(&self) -> MutexGuard<'_, Option<(u8, u8)>> {
        self.night.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl fmt::Debug for PanelState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PanelState")
            .field("lock", &self.lock)
            .field("night", &self.night())
            .finish()
    }
}

impl LockControl for PanelState {
    fn verify(&self, digits: Zeroizing<[u8; 4]>) -> Check {
        self.lock.verify(digits)
    }

    fn wait_left(&self) -> u32 {
        self.lock.wait_left()
    }

    fn set_pin(&self, digits: Zeroizing<[u8; 4]>) -> bool {
        self.lock.set_from_panel(digits)
    }

    fn clear_pin(&self) {
        self.lock.clear();
    }

    fn lock_view(&self) -> LockView {
        LockView {
            kept: self.kept.load(Ordering::Relaxed),
            ..self.lock.view()
        }
    }

    fn night(&self) -> Option<(u8, u8)> {
        *self.night_slot()
    }

    fn set_night(&self, night: Option<(u8, u8)>) {
        // Equal hours are no night, as the screens read them: keep one way to say it.
        *self.night_slot() = night.filter(|&(from, to)| from != to);
    }
}

/// `HH-HH`: two hours of the day (two digits each, 00 to 23), different: `Some((from, to))`; `None`
/// for any other text (including `off`, which is [`parse_night`]'s).
pub fn parse_hours(text: &str) -> Option<(u8, u8)> {
    let (from, to) = text.split_once('-')?;
    let hour = |text: &str| {
        let digits = text.as_bytes();
        match digits {
            [tens @ b'0'..=b'9', ones @ b'0'..=b'9'] => {
                Some((tens - b'0') * 10 + (ones - b'0')).filter(|&hour| hour <= 23)
            }
            _ => None,
        }
    };
    let (from, to) = (hour(from)?, hour(to)?);
    (from != to).then_some((from, to))
}

/// The configuration's `[panel] night`: `HH-HH` ([`parse_hours`]), or `off` for no night. The outer
/// `None` is a text that is neither.
pub fn parse_night(text: &str) -> Option<Option<(u8, u8)>> {
    if text == "off" {
        return Some(None);
    }
    parse_hours(text).map(Some)
}

/// The night hours as `HH-HH`, as `GET /api/qbp/panel` says them.
pub fn hours_text((from, to): (u8, u8)) -> String {
    format!("{from:02}-{to:02}")
}

/// A PIN's hash as the configuration's `pin_hash` holds it: the [`PasswordHash`] text that
/// `cargo xtask hash-pin` puts between the quotes of the line it prints, with exactly the rounds of a
/// PIN ([`PIN_ROUNDS`], 10,000: a check, which the panel's thread makes, then costs what the panel was
/// measured on, whatever a push or a file says). Nothing before or after it. `None` for any other text.
pub fn parse_pin_hash(text: &str) -> Option<PasswordHash> {
    PasswordHash::parse(text).filter(|hash| hash.rounds() == PIN_ROUNDS)
}

/// A PIN's hash as the desktop pushes it (`PUT /api/qbp/panel`): the text of [`parse_pin_hash`], or
/// the whole line that `cargo xtask hash-pin` prints, `pin_hash = "<hash>"` with the quotes and one
/// space each side of the `=`, which may have the line ending or other white space around it. A
/// wrapper that is not that line, or holds anything but a hash of a PIN, is `None`, as is any other
/// text (the bare hash is taken as it is, with no white space around it). The configuration reads its
/// value with [`parse_pin_hash`] alone.
pub fn parse_pushed_pin_hash(text: &str) -> Option<PasswordHash> {
    match text.trim().strip_prefix("pin_hash = \"") {
        Some(rest) => parse_pin_hash(rest.strip_suffix('"')?),
        None => parse_pin_hash(text),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Instant;

    /// A clock that the test moves.
    fn fake() -> (Clock, Arc<AtomicU64>) {
        let time = Arc::new(AtomicU64::new(1_000));
        let clock = time.clone();
        (Arc::new(move || clock.load(Ordering::Relaxed)), time)
    }

    /// The hash that `cargo xtask hash-pin` makes of `1234`, with a salt that no one else has.
    fn pin_1234() -> PasswordHash {
        PasswordHash::with_rounds(b"1234", [9; 16], PIN_ROUNDS)
    }

    fn digits(d: [u8; 4]) -> Zeroizing<[u8; 4]> {
        Zeroizing::new(d)
    }

    const RIGHT: [u8; 4] = [1, 2, 3, 4];
    const WRONG: [u8; 4] = [4, 3, 2, 1];

    #[test]
    fn the_backoff_is_thirty_seconds_after_three_wrong_and_doubles_to_fifteen_minutes() {
        let seen: Vec<u32> = (0..12).map(backoff_secs).collect();
        assert_eq!(seen, [0, 0, 0, 30, 60, 120, 240, 480, 900, 900, 900, 900]);
        assert_eq!(backoff_secs(u32::MAX), 900);
    }

    #[test]
    fn the_lock_waits_as_the_spec_says_on_a_clock_that_is_injected() {
        let (clock, time) = fake();
        let lock = Lock::new(Some(pin_1234()), clock);
        assert_eq!(lock.view().source, Some(Source::Config));
        // Two wrong PINs cost nothing.
        assert_eq!(lock.verify(digits(WRONG)), Check::Wrong);
        assert_eq!(lock.verify(digits(WRONG)), Check::Wrong);
        assert_eq!(lock.wait_left(), 0);
        // The third starts the wait of 30 s, and nothing is checked while it lasts: not even the right PIN.
        assert_eq!(lock.verify(digits(WRONG)), Check::Wrong);
        assert_eq!(lock.wait_left(), 30);
        assert_eq!(lock.verify(digits(RIGHT)), Check::Wait(30));
        time.fetch_add(10, Ordering::Relaxed);
        assert_eq!(lock.verify(digits(RIGHT)), Check::Wait(20));
        assert_eq!(lock.wait_left(), 20);
        time.fetch_add(19, Ordering::Relaxed);
        assert_eq!(lock.verify(digits(WRONG)), Check::Wait(1));
        // A try that is made while it waits is not a wrong PIN: the count stays at three.
        time.fetch_add(1, Ordering::Relaxed);
        assert_eq!(lock.wait_left(), 0);
        // The fourth wrong one doubles it.
        assert_eq!(lock.verify(digits(WRONG)), Check::Wrong);
        assert_eq!(lock.wait_left(), 60);
        time.fetch_add(60, Ordering::Relaxed);
        for expect in [120, 240, 480, 900, 900] {
            assert_eq!(lock.verify(digits(WRONG)), Check::Wrong);
            assert_eq!(lock.wait_left(), expect);
            time.fetch_add(u64::from(expect), Ordering::Relaxed);
        }
        // A right PIN, once the wait is over, resets the whole count.
        assert_eq!(lock.verify(digits(RIGHT)), Check::Right);
        assert_eq!(lock.wait_left(), 0);
        assert_eq!(lock.verify(digits(WRONG)), Check::Wrong);
        assert_eq!(lock.verify(digits(WRONG)), Check::Wrong);
        assert_eq!(lock.wait_left(), 0, "two wrong in a row again: no wait");
        assert_eq!(lock.verify(digits(WRONG)), Check::Wrong);
        assert_eq!(lock.wait_left(), 30, "and the third waits 30 s, not more");
    }

    #[test]
    fn a_new_pin_or_none_starts_the_count_again() {
        let (clock, _time) = fake();
        let lock = Lock::new(Some(pin_1234()), clock);
        for _ in 0..3 {
            lock.verify(digits(WRONG));
        }
        assert_eq!(lock.wait_left(), 30);
        // The desktop pushes another hash (of the same digits, with a salt of its own): the old
        // count is of no use against it.
        let other = PasswordHash::with_rounds(b"1234", [8; 16], PIN_ROUNDS);
        lock.set_hash(Some(other), Source::Api);
        assert_eq!(lock.wait_left(), 0);
        assert_eq!(lock.view().source, Some(Source::Api));
        assert_eq!(lock.verify(digits(RIGHT)), Check::Right);
        for _ in 0..3 {
            lock.verify(digits(WRONG));
        }
        lock.clear();
        assert_eq!(lock.wait_left(), 0);
        assert_eq!(
            lock.view(),
            LockView {
                on: false,
                source: None,
                kept: false
            }
        );
        // With none set nothing is guarded: any four digits are right, and nothing is counted.
        assert_eq!(lock.verify(digits(WRONG)), Check::Right);
    }

    #[test]
    fn pushing_the_same_hash_again_keeps_the_wrong_count_and_the_wait() {
        let (clock, time) = fake();
        let lock = Lock::new(None, clock);
        lock.set_hash(Some(pin_1234()), Source::Api);
        for _ in 0..3 {
            assert_eq!(lock.verify(digits(WRONG)), Check::Wrong);
        }
        assert_eq!(lock.wait_left(), WAIT_FIRST_SECS);
        time.fetch_add(10, Ordering::Relaxed);
        // qnet pushes its hash again after a start: the same hash, a copy of it.
        lock.set_hash(Some(pin_1234()), Source::Api);
        assert_eq!(lock.wait_left(), WAIT_FIRST_SECS - 10, "still waiting");
        assert_eq!(
            lock.verify(digits(RIGHT)),
            Check::Wait(WAIT_FIRST_SECS - 10)
        );
        // The count is kept as well as the wait: the next wrong one after the wait doubles it.
        time.fetch_add(u64::from(WAIT_FIRST_SECS), Ordering::Relaxed);
        assert_eq!(lock.verify(digits(WRONG)), Check::Wrong);
        assert_eq!(lock.wait_left(), 2 * WAIT_FIRST_SECS);

        // Another hash, even of the same digits with another salt, is a new PIN: the count starts
        // again, as does the wait.
        lock.set_hash(
            Some(PasswordHash::with_rounds(b"1234", [8; 16], PIN_ROUNDS)),
            Source::Api,
        );
        assert_eq!(lock.wait_left(), 0);
        assert_eq!(lock.verify(digits(WRONG)), Check::Wrong);
        assert_eq!(lock.wait_left(), 0, "one wrong in a row, not four");
        // Turning the lock off clears it, whatever was waiting.
        lock.set_hash(None, Source::Api);
        assert!(!lock.view().on);
    }

    #[test]
    fn the_same_hash_pushed_over_the_configurations_keeps_its_source() {
        let (clock, _time) = fake();
        let lock = Lock::new(Some(pin_1234()), clock);
        assert_eq!(lock.view().source, Some(Source::Config));
        lock.set_hash(Some(pin_1234()), Source::Api);
        // It is still the configuration's PIN, which a restart keeps.
        assert_eq!(lock.view().source, Some(Source::Config));
        // A different one is the desktop's.
        lock.set_hash(
            Some(PasswordHash::with_rounds(b"4321", [7; 16], PIN_ROUNDS)),
            Source::Api,
        );
        assert_eq!(lock.view().source, Some(Source::Api));
    }

    #[test]
    fn a_pin_set_on_the_panel_checks_as_the_digits_typed_and_says_where_it_lives() {
        let (clock, _time) = fake();
        let lock = Lock::new(None, clock);
        assert_eq!(
            lock.view(),
            LockView {
                on: false,
                source: None,
                kept: false
            }
        );
        assert!(lock.set_from_panel(digits([0, 7, 0, 9])));
        assert_eq!(
            lock.view(),
            LockView {
                on: true,
                source: Some(Source::Panel),
                kept: false
            }
        );
        assert_eq!(lock.verify(digits([0, 7, 0, 9])), Check::Right);
        assert_eq!(lock.verify(digits([0, 7, 0, 8])), Check::Wrong);
        // The latest set wins: the desktop's hash takes the place of the panel's.
        lock.set_hash(Some(pin_1234()), Source::Api);
        assert_eq!(lock.verify(digits([0, 7, 0, 9])), Check::Wrong);
        assert_eq!(lock.verify(digits(RIGHT)), Check::Right);
    }

    #[test]
    fn the_digits_are_the_ascii_digits_that_hash_pin_hashes() {
        // `cargo xtask hash-pin` reads "0000", "1234", ... as four ASCII characters.
        let (clock, _time) = fake();
        let lock = Lock::new(
            Some(PasswordHash::with_rounds(b"0509", [1; 16], PIN_ROUNDS)),
            clock,
        );
        assert_eq!(lock.verify(digits([0, 5, 0, 9])), Check::Right);
        // A value that is no digit is kept as 9, as the pad's own type keeps it.
        assert_eq!(lock.verify(digits([0, 5, 0, 200])), Check::Right);
        assert_eq!(lock.verify(digits([0, 5, 0, 8])), Check::Wrong);
    }

    #[test]
    fn the_control_over_the_state_is_the_lock_and_the_night_hours() {
        let (clock, _time) = fake();
        let state = PanelState::new(Some(pin_1234()), Some(DEFAULT_NIGHT), clock);
        let control: &dyn LockControl = &state;
        assert_eq!(control.night(), Some((23, 7)));
        control.set_night(Some((22, 6)));
        assert_eq!(control.night(), Some((22, 6)));
        control.set_night(Some((5, 5)));
        assert_eq!(control.night(), None, "equal hours are no night");
        control.set_night(None);
        assert_eq!(control.night(), None);
        assert!(control.lock_view().on);
        assert_eq!(control.verify(digits(RIGHT)), Check::Right);
        assert_eq!(control.verify(digits(WRONG)), Check::Wrong);
        control.clear_pin();
        assert!(!control.lock_view().on);
        assert!(control.set_pin(digits(WRONG)));
        assert_eq!(control.lock_view().source, Some(Source::Panel));
        assert_eq!(control.verify(digits(WRONG)), Check::Right);
    }

    /// Another PIN's hash, for a configuration that changed its `pin_hash`.
    fn pin_4321() -> PasswordHash {
        PasswordHash::with_rounds(b"4321", [7; 16], PIN_ROUNDS)
    }

    /// A state with `config` as the configuration's PIN and `night` as its night.
    fn state_of(config: Option<PasswordHash>, night: Option<(u8, u8)>) -> PanelState {
        let (clock, _time) = fake();
        PanelState::new(config, night, clock)
    }

    #[test]
    fn a_pin_from_the_desktop_and_one_from_the_panel_are_kept_with_their_sources_and_taken_back() {
        for (source, hash) in [(Source::Api, pin_1234()), (Source::Panel, pin_4321())] {
            let before = state_of(None, Some(DEFAULT_NIGHT));
            before.lock().set_hash(Some(hash.clone()), source);
            let kept = before.kept_state();
            let pin = kept.pin.as_ref().expect("the PIN is kept");
            assert_eq!(pin.source, source);
            assert_eq!(pin.hash.to_text(), hash.to_text());

            let after = state_of(None, Some(DEFAULT_NIGHT));
            assert!(!after.lock_view().on);
            after.restore(kept.clone());
            assert_eq!(after.lock_view().source, Some(source));
            assert_eq!(after.kept_state(), kept);
            // It checks as the PIN of the digits it was made of.
            let right = if source == Source::Api {
                RIGHT
            } else {
                [4, 3, 2, 1]
            };
            assert_eq!(after.verify(digits(right)), Check::Right);
            assert_eq!(after.verify(digits([9, 9, 9, 9])), Check::Wrong);
        }
        // One set on the panel itself, with its own salt.
        let before = state_of(None, None);
        assert!(before.set_pin(digits([0, 7, 0, 9])));
        let after = state_of(None, None);
        after.restore(before.kept_state());
        assert_eq!(after.lock_view().source, Some(Source::Panel));
        assert_eq!(after.verify(digits([0, 7, 0, 9])), Check::Right);
    }

    #[test]
    fn a_pin_from_the_configuration_and_a_lock_turned_off_are_not_kept() {
        let configured = state_of(Some(pin_1234()), Some(DEFAULT_NIGHT));
        let kept = configured.kept_state();
        assert!(kept.pin.is_none());
        // What it stands against is still there, so that a later PIN can be told from the file's.
        assert_eq!(kept.pin_config, pin_fingerprint(Some(&pin_1234())));
        // The same hash pushed from the desktop is still the configuration's.
        configured.lock().set_hash(Some(pin_1234()), Source::Api);
        assert!(configured.kept_state().pin.is_none());
        // Turned off, it is nothing to keep: the file's PIN is back at the next start.
        configured.clear_pin();
        assert!(!configured.lock_view().on);
        assert!(configured.kept_state().pin.is_none());
        // No PIN anywhere: the fingerprint of none is zeros.
        assert_eq!(state_of(None, None).kept_state().pin_config, [0; 32]);

        // A restore of a state with no PIN leaves the configuration's in force.
        let next = state_of(Some(pin_1234()), Some(DEFAULT_NIGHT));
        next.restore(configured.kept_state());
        assert_eq!(next.lock_view().source, Some(Source::Config));
        assert_eq!(next.verify(digits(RIGHT)), Check::Right);
    }

    #[test]
    fn a_pin_set_over_the_configurations_is_kept_and_comes_back_over_the_same_configuration() {
        let before = state_of(Some(pin_1234()), None);
        before.lock().set_hash(Some(pin_4321()), Source::Panel);
        let kept = before.kept_state();
        assert_eq!(kept.pin.as_ref().map(|pin| pin.source), Some(Source::Panel));

        let after = state_of(Some(pin_1234()), None);
        assert_eq!(after.lock_view().source, Some(Source::Config));
        after.restore(kept);
        assert_eq!(after.lock_view().source, Some(Source::Panel));
        assert_eq!(after.verify(digits([4, 3, 2, 1])), Check::Right);
    }

    #[test]
    fn a_saved_pin_under_another_configuration_pin_is_not_put_back() {
        let before = state_of(Some(pin_1234()), None);
        before.lock().set_hash(Some(pin_4321()), Source::Api);
        let kept = before.kept_state();
        // The owner changed the file's `pin_hash` and updated: the file's PIN is in force.
        let other = PasswordHash::with_rounds(b"0000", [3; 16], PIN_ROUNDS);
        let changed = state_of(Some(other), None);
        changed.restore(kept.clone());
        assert_eq!(changed.lock_view().source, Some(Source::Config));
        assert_eq!(changed.verify(digits([0, 0, 0, 0])), Check::Right);
        assert_eq!(changed.verify(digits([4, 3, 2, 1])), Check::Wrong);
        // The file lost its PIN: none is in force, not the saved one.
        let dropped = state_of(None, None);
        dropped.restore(kept.clone());
        assert!(!dropped.lock_view().on);
        // A PIN saved under no file PIN is not put back under one.
        let none_before = state_of(None, None);
        none_before.lock().set_hash(Some(pin_4321()), Source::Panel);
        let added = state_of(Some(pin_1234()), None);
        added.restore(none_before.kept_state());
        assert_eq!(added.lock_view().source, Some(Source::Config));
    }

    #[test]
    fn the_night_is_kept_as_it_is_and_comes_back_over_the_same_configuration_night() {
        let before = state_of(None, Some(DEFAULT_NIGHT));
        before.set_night(Some((22, 6)));
        let kept = before.kept_state();
        assert_eq!(kept.night, Some((22, 6)));
        assert_eq!(kept.night_config, Some(DEFAULT_NIGHT));
        let after = state_of(None, Some(DEFAULT_NIGHT));
        after.restore(kept);
        assert_eq!(after.night(), Some((22, 6)));
        // No night is a night to keep as well, over a configuration that has one.
        before.set_night(None);
        let off = state_of(None, Some(DEFAULT_NIGHT));
        off.restore(before.kept_state());
        assert_eq!(off.night(), None);
        // Equal hours are no night, here and in what is kept.
        let equal = state_of(None, Some((5, 5)));
        assert_eq!(equal.night(), None);
        assert_eq!(equal.kept_state().night_config, None);
        equal.set_night(Some((7, 7)));
        assert_eq!(equal.kept_state().night, None);
    }

    #[test]
    fn a_saved_night_under_another_configuration_night_is_not_put_back() {
        let before = state_of(None, Some(DEFAULT_NIGHT));
        before.set_night(Some((22, 6)));
        let kept = before.kept_state();
        // The file's `[panel] night` changed: the file's hours are in force.
        let changed = state_of(None, Some((0, 5)));
        changed.restore(kept.clone());
        assert_eq!(changed.night(), Some((0, 5)));
        // The file turned the night off.
        let off = state_of(None, None);
        off.restore(kept);
        assert_eq!(off.night(), None);
        // A saved night of "none" under a configuration that had none is not put over a new one.
        let none_before = state_of(None, None);
        none_before.set_night(None);
        let now_has = state_of(None, Some(DEFAULT_NIGHT));
        now_has.restore(none_before.kept_state());
        assert_eq!(now_has.night(), Some(DEFAULT_NIGHT));
    }

    #[test]
    fn the_pin_and_the_night_are_judged_apart() {
        let before = state_of(Some(pin_1234()), Some(DEFAULT_NIGHT));
        before.lock().set_hash(Some(pin_4321()), Source::Panel);
        before.set_night(Some((21, 5)));
        let kept = before.kept_state();
        // The PIN in the file changed, the night did not: the night comes back, the PIN does not.
        let other = PasswordHash::with_rounds(b"0000", [3; 16], PIN_ROUNDS);
        let after = state_of(Some(other), Some(DEFAULT_NIGHT));
        after.restore(kept);
        assert_eq!(after.lock_view().source, Some(Source::Config));
        assert_eq!(after.night(), Some((21, 5)));
    }

    #[test]
    fn the_wrong_pin_count_starts_at_nothing_after_a_restore_that_puts_a_pin_back() {
        let (clock, time) = fake();
        let state = PanelState::new(None, None, clock);
        state.lock().set_hash(Some(pin_1234()), Source::Api);
        for _ in 0..3 {
            assert_eq!(state.verify(digits(WRONG)), Check::Wrong);
        }
        assert_eq!(state.wait_left(), WAIT_FIRST_SECS);
        let kept = state.kept_state();
        // The same PIN, with the count that a start has: nothing.
        let (clock, _) = fake();
        let fresh = PanelState::new(None, None, clock);
        fresh.restore(kept.clone());
        assert_eq!(fresh.wait_left(), 0);
        assert_eq!(fresh.verify(digits(WRONG)), Check::Wrong);
        assert_eq!(fresh.verify(digits(WRONG)), Check::Wrong);
        assert_eq!(fresh.wait_left(), 0, "two wrong in a row, not five");
        // A restore that puts nothing back does not clear a wait that is running.
        let none = SavedPanel::default();
        state.restore(none);
        assert_eq!(state.wait_left(), WAIT_FIRST_SECS);
        time.fetch_add(1, Ordering::Relaxed);
        assert_eq!(state.wait_left(), WAIT_FIRST_SECS - 1);
    }

    #[test]
    fn the_lock_view_says_the_card_keeps_the_state_whatever_the_source() {
        for kept in [false, true] {
            let config = state_of(Some(pin_1234()), None).with_kept(kept);
            assert_eq!(config.lock_view().source, Some(Source::Config));
            assert_eq!(config.lock_view().kept, kept);
            let api = state_of(None, None).with_kept(kept);
            api.lock().set_hash(Some(pin_1234()), Source::Api);
            assert_eq!(api.lock_view().kept, kept);
            let panel = state_of(None, None).with_kept(kept);
            assert!(panel.set_pin(digits(RIGHT)));
            assert_eq!(panel.lock_view().kept, kept);
            let off = state_of(None, None).with_kept(kept);
            assert!(!off.lock_view().on);
            assert_eq!(off.lock_view().kept, kept);
        }
        // Not kept until it is said so.
        assert!(!state_of(None, None).lock_view().kept);
    }

    #[test]
    fn once_saving_is_off_the_lock_view_says_the_card_no_longer_keeps_the_state() {
        let state = Arc::new(state_of(None, None).with_kept(true));
        state.lock().set_hash(Some(pin_1234()), Source::Api);
        assert!(state.lock_view().kept);
        // Another thread says it (the saver's), through the shared state.
        let saver = state.clone();
        std::thread::spawn(move || saver.stop_keeping())
            .join()
            .unwrap();
        let view = state.lock_view();
        assert!(!view.kept);
        assert!(view.on, "the PIN itself is still in force");
        assert_eq!(view.source, Some(Source::Api));
        // It is never turned on again for the boot, and saying it twice is no harm.
        state.stop_keeping();
        assert!(!state.lock_view().kept);
        // A state that was not kept to begin with stays so.
        let never = state_of(None, None);
        never.stop_keeping();
        assert!(!never.lock_view().kept);
    }

    #[test]
    fn what_the_state_keeps_of_the_lock_prints_no_hash() {
        let state = state_of(Some(pin_1234()), Some(DEFAULT_NIGHT));
        state.lock().set_hash(Some(pin_4321()), Source::Panel);
        let text = format!("{:?} {:?}", state.kept_state(), state);
        for secret in ["pbkdf2", "$i=", "0707070707", "1234", "4321"] {
            assert!(!text.contains(secret), "{secret} in {text}");
        }
        assert!(text.contains("Panel"), "{text}");
    }

    #[test]
    fn the_stand_in_has_no_lock_and_no_night() {
        let control: &dyn LockControl = &NoLock;
        assert_eq!(control.verify(digits(WRONG)), Check::Right);
        assert_eq!(control.wait_left(), 0);
        assert!(!control.set_pin(digits(WRONG)));
        control.clear_pin();
        control.set_night(Some((1, 2)));
        assert_eq!(control.night(), None);
        assert_eq!(control.lock_view().source, None);
    }

    #[test]
    fn nothing_here_prints_a_digit_or_the_hash() {
        let (clock, _time) = fake();
        let state = PanelState::new(Some(pin_1234()), Some(DEFAULT_NIGHT), clock);
        for shown in [format!("{state:?}"), format!("{state:#?}")] {
            assert!(
                shown.contains("on: true") && shown.contains("Config"),
                "{shown}"
            );
            assert!(
                !shown.contains("pbkdf2") && !shown.contains("1234"),
                "{shown}"
            );
        }
        let hash = pin_1234();
        assert_eq!(format!("{hash:?}"), "<redacted>");
    }

    #[test]
    fn night_hours_are_two_hours_of_the_day_that_differ() {
        for (text, hours) in [
            ("23-07", (23, 7)),
            ("00-23", (0, 23)),
            ("07-23", (7, 23)),
            ("01-02", (1, 2)),
        ] {
            assert_eq!(parse_hours(text), Some(hours), "{text}");
            assert_eq!(hours_text(hours), text);
            assert_eq!(parse_night(text), Some(Some(hours)));
        }
        assert_eq!(parse_night("off"), Some(None));
        assert_eq!(parse_hours("off"), None, "off is the configuration's word");
        for bad in [
            "",
            "-",
            "7-23",
            "23-7",
            "07-07",
            "24-07",
            "07-24",
            "ab-cd",
            "23-07 ",
            " 23-07",
            "23_07",
            "23-07-08",
            "2307",
            "+7-23",
            "07--3",
            "Off",
            "OFF",
            "none",
            "\u{663}7-23",
        ] {
            assert_eq!(parse_hours(bad), None, "{bad:?}");
            assert_eq!(parse_night(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn only_a_line_with_the_rounds_of_a_pin_is_a_pin_hash() {
        let text = pin_1234().to_text();
        assert!(parse_pin_hash(&text).is_some());
        let salt = "09".repeat(16);
        let hash = "ab".repeat(32);
        let line = |rounds: &str| format!("$pbkdf2-sha256$i={rounds}${salt}${hash}");
        assert!(parse_pin_hash(&line("10000")).is_some());
        // Exactly the rounds of a PIN, so that a push cannot stall the panel's thread, and a
        // file cannot either.
        assert!(parse_pin_hash(&line("10001")).is_none());
        assert!(parse_pin_hash(&line("20000")).is_none());
        assert!(parse_pin_hash(&line("100000")).is_none());
        assert!(parse_pin_hash(&line("100001")).is_none());
        assert!(parse_pin_hash(&line("10000000")).is_none());
        assert!(parse_pin_hash(&line("9999")).is_none());
        assert!(parse_pin_hash("not a hash").is_none());
        assert!(parse_pin_hash("").is_none());
    }

    #[test]
    fn a_push_takes_the_line_that_hash_pin_prints_as_well_as_the_bare_hash() {
        let text = pin_1234().to_text();
        let printed = format!("pin_hash = \"{text}\"");
        // The bare hash, and the line as `hash-pin` prints it, with or without its line ending.
        for accepted in [
            text.clone(),
            printed.clone(),
            format!("{printed}\n"),
            format!("  {printed}\r\n"),
        ] {
            let hash = parse_pushed_pin_hash(&accepted).expect(&accepted);
            assert_eq!(hash.to_text(), text);
        }
        let salt = "09".repeat(16);
        let other = "ab".repeat(32);
        let slow = format!("$pbkdf2-sha256$i=100000${salt}${other}");
        for refused in [
            // A wrapper that is not the line `hash-pin` prints.
            format!("pin_hash = \"{text}"),
            format!("pin_hash = {text}"),
            format!("pin_hash=\"{text}\""),
            format!("pin_hash  = \"{text}\""),
            format!("pin_hash = '{text}'"),
            format!("pin_hash = \"{text}\" # note"),
            format!("pin_hash = \"{text}\"\npin_hash = \"{text}\""),
            format!("pin_hash = \"\"{text}\"\""),
            format!("pin_hash = \" {text}\""),
            format!("pin_hash = \"{text} \""),
            format!("password_hash = \"{text}\""),
            "pin_hash = \"\"".to_owned(),
            "pin_hash = \"".to_owned(),
            "pin_hash = ".to_owned(),
            // A wrapper around a hash of another kind.
            format!("pin_hash = \"{slow}\""),
            "pin_hash = \"not a hash\"".to_owned(),
            // The bare hash is exact: no white space.
            format!("{text} "),
            format!(" {text}"),
            format!("{text}\n"),
            "".to_owned(),
            "   ".to_owned(),
        ] {
            assert!(parse_pushed_pin_hash(&refused).is_none(), "{refused:?}");
        }
        // The configuration's value is the bare hash only: a whole line is no value.
        assert!(parse_pin_hash(&printed).is_none());
    }

    #[test]
    fn what_one_check_of_a_pin_costs_on_this_host() {
        let hash = pin_1234();
        let began = Instant::now();
        assert!(hash.verify(b"1234"));
        let took = began.elapsed();
        // Printed for the commit message; `cargo test -- --nocapture` shows it. The Pi's budget is 100 ms.
        println!(
            "host verify time of a {}-round hash: {:.2} ms",
            hash.rounds(),
            took.as_secs_f64() * 1_000.0
        );
        assert!(took.as_secs() < 30, "{took:?}");
    }

    #[test]
    fn a_wrong_pin_logs_its_count_and_nothing_else() {
        crate::testns::run_inside("panel::lock::tests::ns_a_wrong_pin_logs_its_count");
    }

    /// A logger that keeps what is logged, for the one test that installs it.
    struct Capture(Mutex<Vec<String>>);

    impl log::Log for Capture {
        fn enabled(&self, _: &log::Metadata<'_>) -> bool {
            true
        }

        fn log(&self, record: &log::Record<'_>) {
            self.0
                .lock()
                .unwrap()
                .push(format!("{} {}", record.level(), record.args()));
        }

        fn flush(&self) {}
    }

    #[test]
    #[ignore = "run by a_wrong_pin_logs_its_count_and_nothing_else, in a process of its own"]
    fn ns_a_wrong_pin_logs_its_count() {
        if !crate::testns::inside() {
            return;
        }
        // This process runs this one test, so the logger is its own to set.
        static CAPTURE: Capture = Capture(Mutex::new(Vec::new()));
        log::set_logger(&CAPTURE).unwrap();
        log::set_max_level(log::LevelFilter::Trace);

        let (clock, time) = fake();
        let lock = Lock::new(Some(pin_1234()), clock);
        lock.verify(digits([4, 3, 2, 1]));
        lock.verify(digits([9, 9, 9, 9]));
        lock.verify(digits([0, 0, 0, 0]));
        time.fetch_add(31, Ordering::Relaxed);
        lock.verify(digits([5, 5, 5, 5]));
        lock.verify(digits(RIGHT));
        assert!(lock.set_from_panel(digits([7, 7, 7, 7])));
        lock.set_hash(Some(pin_1234()), Source::Api);
        lock.clear();

        let lines = CAPTURE.0.lock().unwrap().clone();
        let wrong: Vec<&String> = lines.iter().filter(|line| line.contains("wrong")).collect();
        assert_eq!(
            wrong,
            [
                "WARN panel: wrong PIN (1 in a row)",
                "WARN panel: wrong PIN (2 in a row)",
                "WARN panel: wrong PIN (3 in a row)",
                "WARN panel: wrong PIN (4 in a row)",
            ]
        );
        // No line carries a digit of any PIN tried or set, or any part of a hash.
        for line in &lines {
            assert!(
                !line.contains("pbkdf2")
                    && !line.contains("1234")
                    && !line.contains("4321")
                    && !line.contains("7777")
                    && !line.contains("9999")
                    && !line.contains("5555")
                    && !line.contains("0000"),
                "{line}"
            );
        }
        assert!(lines.len() >= 7, "{lines:?}");
    }
}
