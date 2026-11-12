//! What the rest of the system knows, as the panel and the status page ask for it.
//!
//! Everything the front end shows comes through the `Source` trait, and a
//! value that nothing has measured is `None`. `wiring` has the source that
//! reads the running system; `Counts`, `Outcome`, `LogEntry` and `LastBlocked`
//! are those of `qb_dns`.

use std::sync::{Mutex, PoisonError};

use qb_panel::{Blocking, Switch};

pub use qb_dns::{Counts, LastBlocked, LogEntry, Outcome};

/// The state of the Wi-Fi link.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WifiStatus {
    /// Whether the board is associated with its access point.
    pub associated: bool,
    /// The signal strength in dBm, if it has been measured.
    pub signal_dbm: Option<i8>,
    /// The name of the access point, if it is known.
    pub ap: Option<String>,
    /// The frequency, in MHz, of the channel the access point is joined on, if it is known: what the
    /// join found when it scanned. It is what `wifi.hint_mhz` takes.
    pub freq_mhz: Option<u32>,
}

/// Everything known at one moment.
///
/// Every field is `None` until the component that measures it exists and has measured it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// The Wi-Fi link.
    pub wifi: Option<WifiStatus>,
    /// The queries since midnight.
    pub today: Option<Counts>,
    /// The queries since the board started.
    pub total: Option<Counts>,
    /// The name blocked most recently.
    pub last_blocked: Option<LastBlocked>,
    /// How long the upstream resolver takes to answer, in milliseconds.
    pub upstream_ms: Option<u16>,
    /// The local time's distance from UTC, in seconds.
    pub utc_offset_secs: i32,
    /// Whether the clock has been set to the real time.
    pub clock_set: bool,
    /// How many names the blocklists hold.
    pub list_names: Option<usize>,
    /// When the blocklists were last fetched, in Unix seconds.
    pub list_fetched_unix: Option<u64>,
}

/// Where the panel and the status page get what they show.
pub trait Source: Send + Sync {
    /// What is known now.
    fn snapshot(&self) -> Snapshot;

    /// The `n` most recent queries, newest first.
    fn recent(&self, n: usize) -> Vec<LogEntry>;
}

/// A source that knows nothing, for as long as nothing measures anything.
pub struct Nothing;

impl Source for Nothing {
    fn snapshot(&self) -> Snapshot {
        Snapshot::default()
    }

    fn recent(&self, _n: usize) -> Vec<LogEntry> {
        Vec::new()
    }
}

/// What the panel's switch controls.
///
/// Times are relative, so the implementor's own clock decides: the panel never
/// puts a deadline on a clock the resolver does not use.
pub trait BlockingControl: Send + Sync {
    /// The seconds of a pause that are left, rounded up; `None` while blocking is on.
    fn paused_left_secs(&self) -> Option<u16>;

    /// Pauses blocking for `secs` seconds from now; a pause that is running is replaced.
    fn pause_for(&self, secs: u16);

    /// Turns blocking on again, ending a pause that is running.
    fn resume(&self);
}

/// The control of blocking until the resolver exists: a pause that lives in memory, on a clock it is given.
///
/// The pause is never written anywhere, so it never outlives a reboot.
pub struct StandIn {
    /// The switch: on, or paused until a time on `mono_ms`.
    switch: Mutex<Switch>,
    /// A clock that does not jump, in milliseconds from any starting point.
    mono_ms: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl StandIn {
    /// A stand-in with blocking on, that counts a pause on `mono_ms`.
    pub fn new(mono_ms: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        Self {
            switch: Mutex::new(Switch::On),
            mono_ms: Box::new(mono_ms),
        }
    }
}

impl BlockingControl for StandIn {
    fn paused_left_secs(&self) -> Option<u16> {
        // The switch is `Copy` and always whole, so a lock that was poisoned is as good as any.
        let switch = *self.switch.lock().unwrap_or_else(PoisonError::into_inner);
        match switch.blocking((self.mono_ms)()) {
            Blocking::On => None,
            Blocking::Paused { left_secs } => Some(left_secs),
        }
    }

    fn pause_for(&self, secs: u16) {
        let until = (self.mono_ms)().saturating_add(u64::from(secs) * 1000);
        *self.switch.lock().unwrap_or_else(PoisonError::into_inner) = Switch::PausedUntil(until);
    }

    fn resume(&self) {
        *self.switch.lock().unwrap_or_else(PoisonError::into_inner) = Switch::On;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn nothing_is_known_before_the_other_components_exist() {
        assert_eq!(Nothing.snapshot(), Snapshot::default());
        assert!(Nothing.recent(10).is_empty());
    }

    #[test]
    fn the_stand_in_pauses_for_the_time_asked_and_ends_by_itself() {
        let now = Arc::new(AtomicU64::new(10_000));
        let stand_in = StandIn::new({
            let now = now.clone();
            move || now.load(Ordering::SeqCst)
        });
        assert_eq!(stand_in.paused_left_secs(), None);
        stand_in.pause_for(300);
        assert_eq!(stand_in.paused_left_secs(), Some(300));
        now.store(309_999, Ordering::SeqCst);
        assert_eq!(stand_in.paused_left_secs(), Some(1));
        now.store(310_000, Ordering::SeqCst);
        assert_eq!(stand_in.paused_left_secs(), None);
        stand_in.pause_for(300);
        stand_in.resume();
        assert_eq!(stand_in.paused_left_secs(), None);
    }
}
