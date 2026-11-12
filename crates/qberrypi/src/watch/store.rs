//! The alert store: a bounded ring in RAM that the detectors raise into and the API reads.
//!
//! Alerts that agree in kind, client and subject merge into one. Each kind may add only so many new
//! alerts in a rolling hour. Every change bumps a revision, so a reader asks for what changed after
//! the revision it last saw and a step of the clock can never hide an alert from it. Acknowledged
//! keys that a desktop sends back after a boot make the alerts they name start out acknowledged. A
//! repeat of an acknowledged alert leaves it acknowledged, unless the alert is a High one: the
//! store shows that again.

use std::collections::{HashSet, VecDeque};
use std::fmt::{self, Write as _};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::alerts::{Alert, AlertSink, Severity};
use crate::panel::alerts::{PanelAlert, PendingAlerts};

/// How many alerts the ring holds.
pub const CAPACITY: usize = 256;

/// How many acknowledged keys are remembered for alerts that have not been raised yet.
pub const MAX_RESTORED: usize = 1024;

/// How many new alerts one kind may add in a rolling hour.
pub const NEW_PER_HOUR: usize = 20;

/// How many new alerts the kind `beacon` may add in a rolling hour.
pub const BEACON_PER_HOUR: usize = 10;

/// The longest subject kept, in bytes.
pub const SUBJECT_MAX: usize = 255;

/// How many kinds have their rate limit tracked at once.
const MAX_KINDS: usize = 32;

/// The kind that has the lower limit.
const BEACON_KIND: &str = "beacon";

/// The length of the window that the rate limit counts in, in seconds.
const HOUR_SECS: u64 = 3600;

/// One alert as a reader sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertView {
    /// The number the API names the alert by; it is unique for as long as the board is up.
    pub id: u64,
    /// The merge key, which is the same for the same alert after a boot; see `key_of`.
    pub key: u64,
    /// The revision of the alert's last change.
    pub rev: u64,
    /// The kind of alert.
    pub kind: &'static str,
    /// The severity as text: `info`, `warn` or `high`.
    pub severity: &'static str,
    /// The client that the alert is about, if it is about one.
    pub client: Option<IpAddr>,
    /// What the alert is about, cut to at most 255 bytes.
    pub subject: String,
    /// The unix time when the alert was first raised.
    pub first_unix: u64,
    /// The unix time when the alert was last raised.
    pub last_unix: u64,
    /// How many times the alert was raised.
    pub count: u64,
    /// Whether the alert has been acknowledged. A High alert that is raised again is not, until it
    /// is acknowledged again.
    pub acked: bool,
}

/// What `AlertStore::list` returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertList {
    /// The store's revision now; a reader passes it back as `since` next time.
    pub rev: u64,
    /// How many new alerts were dropped by a rate limit since the board started.
    pub suppressed: u64,
    /// The alerts that changed after the revision asked for, the oldest change first.
    pub alerts: Vec<AlertView>,
}

/// The alert store.
pub struct AlertStore {
    /// Gives the monotonic seconds and the unix seconds, in that order.
    clock: Arc<dyn Fn() -> (u64, u64) + Send + Sync>,
    /// Everything that changes.
    inner: Mutex<Inner>,
}

impl AlertStore {
    /// Makes an empty store that reads time from `clock`, which gives (monotonic seconds, unix seconds).
    pub fn new(clock: Arc<dyn Fn() -> (u64, u64) + Send + Sync>) -> Self {
        Self {
            clock,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Lists the alerts that changed after revision `since`, the oldest change first.
    ///
    /// Asking with 0 lists every alert there is.
    pub fn list(&self, since: u64) -> AlertList {
        let inner = self.lock();
        let mut changed: Vec<&Entry> = inner.alerts.iter().filter(|a| a.rev > since).collect();
        changed.sort_by_key(|a| a.rev);
        AlertList {
            rev: inner.rev,
            suppressed: inner.suppressed,
            alerts: changed.into_iter().map(Entry::view).collect(),
        }
    }

    /// Acknowledges the alert with this id.
    ///
    /// Returns whether there is such an alert; one that was acknowledged already is not changed.
    pub fn ack(&self, id: u64) -> bool {
        let mut inner = self.lock();
        let Some(pos) = inner.alerts.iter().position(|a| a.id == id) else {
            return false;
        };
        if !inner.alerts[pos].acked {
            let rev = inner.bump();
            let alert = &mut inner.alerts[pos];
            alert.acked = true;
            alert.rev = rev;
        }
        true
    }

    /// Takes acknowledged keys, as `key_of` makes them, from an earlier boot.
    ///
    /// The alerts that are there are acknowledged now, and an alert raised later with one of the keys
    /// starts out acknowledged. That covers the first raise only: a High alert that is raised again
    /// after it is shown again, as one that was acknowledged here is. Only the newest `MAX_RESTORED`
    /// keys are kept, and a key sent again counts as newest. Returns how many different keys of `keys`
    /// are kept.
    pub fn restore_acked(&self, keys: &[u64]) -> usize {
        let mut guard = self.lock();
        let inner = &mut *guard;
        for &key in keys {
            if let Some(pos) = inner.restored.iter().position(|&k| k == key) {
                inner.restored.remove(pos);
            }
            inner.restored.push_back(key);
            if inner.restored.len() > MAX_RESTORED {
                inner.restored.pop_front();
            }
        }
        for pos in 0..inner.alerts.len() {
            let alert = &inner.alerts[pos];
            if !alert.acked && inner.restored.contains(&alert.key) {
                let rev = inner.bump();
                let alert = &mut inner.alerts[pos];
                alert.acked = true;
                alert.rev = rev;
            }
        }
        let mut seen = HashSet::new();
        keys.iter()
            .filter(|key| inner.restored.contains(key) && seen.insert(**key))
            .count()
    }

    /// Locks the state; a lock that was poisoned still holds a whole ring, so it is used as it is.
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// What the front panel reads of the store: the alert that it takes over its screen for, and the
/// tap that acknowledges it.
///
/// Both take the store's own lock, as `list` and `ack` do, and hold it for one pass over the ring
/// (at most `CAPACITY` alerts) and one copy. Neither takes any other lock or waits for anything,
/// so the panel never holds up the resolver's answer path, which raises into this store.
impl PendingAlerts for AlertStore {
    /// The newest alert of the highest severity among those not acknowledged: the one raised
    /// last, which is the one with the highest id, and not the one that repeated last.
    fn top(&self) -> Option<PanelAlert> {
        let inner = self.lock();
        let top = inner
            .alerts
            .iter()
            .filter(|alert| !alert.acked)
            .max_by_key(|alert| (alert.severity, alert.id))?;
        Some(PanelAlert {
            id: top.id,
            kind: top.kind.to_owned(),
            severity: top.severity.into(),
            client: top.client,
            subject: top.subject.clone(),
        })
    }

    fn ack(&self, id: u64) {
        // An id that is not in the ring is not an error: the alert may have been pushed out.
        AlertStore::ack(self, id);
    }
}

impl AlertSink for AlertStore {
    fn raise(&self, alert: Alert) {
        let (mono, unix) = (self.clock)();
        let mut subject = alert.subject;
        cut_subject(&mut subject);
        let kind = alert.kind;
        let severity = alert.severity;
        let entry = Entry {
            id: 0,
            key: key_of(kind, alert.client, &subject),
            rev: 0,
            kind,
            severity,
            client: alert.client,
            subject,
            first_unix: unix,
            last_unix: unix,
            count: 1,
            acked: false,
        };
        let created = self.lock().record(entry, mono);
        if created {
            log::info!("watch: alert {kind} ({})", severity_text(&severity));
        }
    }
}

/// The merge key of an alert: 16 hex digits of FNV-1a 64 over kind, client and subject.
///
/// The three are joined by a zero byte and the client, if there is one, is its usual text. The key
/// is the same on every boot, so a desktop can send back the keys it has seen acknowledged.
pub fn key_of(kind: &str, client: Option<IpAddr>, subject: &str) -> u64 {
    let mut hash = Fnv::new();
    hash.bytes(kind.as_bytes());
    hash.byte(0);
    if let Some(client) = client {
        // The hash never fails to take text.
        let _ = write!(hash, "{client}");
    }
    hash.byte(0);
    hash.bytes(subject.as_bytes());
    hash.0
}

/// A key as the API shows it: 16 lowercase hex digits.
pub fn key_hex(key: u64) -> String {
    format!("{key:016x}")
}

/// The severity as text.
fn severity_text(severity: &Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Warn => "warn",
        Severity::High => "high",
    }
}

/// Cuts `subject` to at most `SUBJECT_MAX` bytes without splitting a character.
fn cut_subject(subject: &mut String) {
    if subject.len() <= SUBJECT_MAX {
        return;
    }
    let mut end = SUBJECT_MAX;
    while !subject.is_char_boundary(end) {
        end -= 1;
    }
    subject.truncate(end);
}

/// FNV-1a with 64 bits, fed byte by byte or as formatted text.
struct Fnv(u64);

impl Fnv {
    /// Starts a hash.
    fn new() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }

    /// Takes one byte.
    fn byte(&mut self, byte: u8) {
        self.0 ^= u64::from(byte);
        self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
    }

    /// Takes the bytes in turn.
    fn bytes(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.byte(byte);
        }
    }
}

impl fmt::Write for Fnv {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.bytes(text.as_bytes());
        Ok(())
    }
}

/// One alert as the ring holds it.
struct Entry {
    /// See `AlertView::id`.
    id: u64,
    /// See `AlertView::key`.
    key: u64,
    /// See `AlertView::rev`.
    rev: u64,
    /// See `AlertView::kind`.
    kind: &'static str,
    /// How much it matters; `AlertView::severity` has it as text.
    severity: Severity,
    /// See `AlertView::client`.
    client: Option<IpAddr>,
    /// See `AlertView::subject`.
    subject: String,
    /// See `AlertView::first_unix`.
    first_unix: u64,
    /// See `AlertView::last_unix`.
    last_unix: u64,
    /// See `AlertView::count`.
    count: u64,
    /// See `AlertView::acked`.
    acked: bool,
}

impl Entry {
    /// Whether `other` is the same alert: the same kind, client and subject.
    fn same_as(&self, other: &Entry) -> bool {
        self.key == other.key
            && self.kind == other.kind
            && self.client == other.client
            && self.subject == other.subject
    }

    /// Copies the alert out for a reader.
    fn view(&self) -> AlertView {
        AlertView {
            id: self.id,
            key: self.key,
            rev: self.rev,
            kind: self.kind,
            severity: severity_text(&self.severity),
            client: self.client,
            subject: self.subject.clone(),
            first_unix: self.first_unix,
            last_unix: self.last_unix,
            count: self.count,
            acked: self.acked,
        }
    }
}

/// When the new alerts of one kind were added in the last hour.
struct KindWindow {
    /// The kind.
    kind: &'static str,
    /// The monotonic seconds of the new alerts that are still inside the hour, oldest first.
    recent: VecDeque<u64>,
}

/// The state behind the store's lock.
#[derive(Default)]
struct Inner {
    /// The revision, bumped by every change.
    rev: u64,
    /// The id the next new alert gets.
    next_id: u64,
    /// How many new alerts a rate limit dropped.
    suppressed: u64,
    /// The alerts, in the order they were added.
    alerts: VecDeque<Entry>,
    /// The keys that were restored, the oldest first.
    restored: VecDeque<u64>,
    /// The rate limit of each kind seen lately, at most `MAX_KINDS`.
    windows: Vec<KindWindow>,
}

impl Inner {
    /// Takes the next revision.
    fn bump(&mut self) -> u64 {
        self.rev += 1;
        self.rev
    }

    /// Merges the alert into the one it repeats, or adds it. Returns whether a new alert was added.
    ///
    /// A repeat counts and takes a new revision, so a reader that polls sees it. If the alert it
    /// merges into was acknowledged, it stays so, except for a High one: that recurrence is news
    /// again, so the alert is not acknowledged any more (it keeps its id, so the order in which the
    /// panel offers alerts does not change, and its count and last time say that it came back).
    fn record(&mut self, mut entry: Entry, mono: u64) -> bool {
        if let Some(pos) = self.alerts.iter().position(|a| a.same_as(&entry)) {
            let rev = self.bump();
            let alert = &mut self.alerts[pos];
            alert.count = alert.count.saturating_add(1);
            alert.last_unix = entry.last_unix;
            alert.rev = rev;
            if alert.severity == Severity::High {
                alert.acked = false;
            }
            return false;
        }
        if !self.admit(entry.kind, mono) {
            self.suppressed = self.suppressed.saturating_add(1);
            return false;
        }
        if self.alerts.len() >= CAPACITY {
            // The oldest acknowledged alert goes first, and with none acknowledged, the oldest.
            let pos = self.alerts.iter().position(|a| a.acked).unwrap_or(0);
            self.alerts.remove(pos);
        }
        self.next_id += 1;
        entry.id = self.next_id;
        entry.rev = self.bump();
        entry.acked = self.restored.contains(&entry.key);
        self.alerts.push_back(entry);
        true
    }

    /// Counts a new alert of `kind` against its limit. Returns whether it is within the limit.
    fn admit(&mut self, kind: &'static str, mono: u64) -> bool {
        let limit = if kind == BEACON_KIND {
            BEACON_PER_HOUR
        } else {
            NEW_PER_HOUR
        };
        let pos = match self.windows.iter().position(|w| w.kind == kind) {
            Some(pos) => pos,
            None => {
                if self.windows.len() >= MAX_KINDS {
                    // Kinds with nothing inside the hour have nothing to remember.
                    self.windows
                        .retain(|w| w.recent.back().is_some_and(|&t| inside_hour(t, mono)));
                }
                if self.windows.len() >= MAX_KINDS {
                    return false;
                }
                self.windows.push(KindWindow {
                    kind,
                    recent: VecDeque::new(),
                });
                self.windows.len() - 1
            }
        };
        let recent = &mut self.windows[pos].recent;
        while recent.front().is_some_and(|&t| !inside_hour(t, mono)) {
            recent.pop_front();
        }
        if recent.len() >= limit {
            return false;
        }
        recent.push_back(mono);
        true
    }
}

/// Whether something at monotonic second `then` still counts at second `now`.
fn inside_hour(then: u64, now: u64) -> bool {
    now.saturating_sub(then) < HOUR_SECS
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use super::*;
    use crate::panel::alerts::Severity as PanelSeverity;

    /// A store with a clock that the test sets, and the two numbers the clock reads.
    fn store() -> (AlertStore, Arc<AtomicU64>, Arc<AtomicU64>) {
        let mono = Arc::new(AtomicU64::new(1000));
        let unix = Arc::new(AtomicU64::new(1_700_000_000));
        let clock: Arc<dyn Fn() -> (u64, u64) + Send + Sync> = {
            let (mono, unix) = (mono.clone(), unix.clone());
            Arc::new(move || (mono.load(Ordering::SeqCst), unix.load(Ordering::SeqCst)))
        };
        (AlertStore::new(clock), mono, unix)
    }

    /// An alert of the given kind and subject about the client 192.0.2.10.
    fn alert(kind: &'static str, subject: &str) -> Alert {
        Alert {
            kind,
            severity: Severity::Warn,
            client: Some(client()),
            subject: subject.to_string(),
        }
    }

    /// The client of the test alerts.
    fn client() -> IpAddr {
        "192.0.2.10".parse().unwrap()
    }

    /// The subjects of the alerts in a list, in the order listed.
    fn subjects(list: &AlertList) -> Vec<&str> {
        list.alerts.iter().map(|a| a.subject.as_str()).collect()
    }

    #[test]
    fn a_repeat_merges_into_one_alert() {
        let (store, _, unix) = store();
        store.raise(alert("beacon", "example.org"));
        unix.store(1_700_000_050, Ordering::SeqCst);
        store.raise(alert("beacon", "example.org"));
        store.raise(alert("beacon", "example.org"));

        let list = store.list(0);
        assert_eq!(list.alerts.len(), 1);
        let a = &list.alerts[0];
        assert_eq!(a.count, 3);
        assert_eq!(a.first_unix, 1_700_000_000);
        assert_eq!(a.last_unix, 1_700_000_050);
        assert_eq!(a.kind, "beacon");
        assert_eq!(a.severity, "warn");
        assert_eq!(a.client, Some(client()));
        assert_eq!(a.subject, "example.org");
        assert!(!a.acked);
        assert_eq!(list.rev, 3);
        assert_eq!(a.rev, 3);
        assert_eq!(list.suppressed, 0);
    }

    #[test]
    fn alerts_that_differ_in_kind_client_or_subject_stay_apart() {
        let (store, _, _) = store();
        store.raise(alert("beacon", "example.org"));
        store.raise(alert("beacon", "example.com"));
        store.raise(alert("tunnel", "example.org"));
        let mut other_client = alert("beacon", "example.org");
        other_client.client = Some("192.0.2.11".parse().unwrap());
        store.raise(other_client);
        let mut no_client = alert("beacon", "example.org");
        no_client.client = None;
        store.raise(no_client);

        let list = store.list(0);
        assert_eq!(list.alerts.len(), 5);
        let ids: HashSet<u64> = list.alerts.iter().map(|a| a.id).collect();
        assert_eq!(ids.len(), 5);
        assert!(list.alerts.iter().all(|a| a.count == 1));
    }

    #[test]
    fn a_repeat_of_an_acknowledged_info_or_warn_alert_stays_acknowledged_but_counts() {
        for severity in [Severity::Info, Severity::Warn] {
            let (store, _, _) = store();
            store.raise(weighed(severity, "random NXDOMAIN names"));
            let id = store.list(0).alerts[0].id;
            assert!(store.ack(id));
            store.raise(weighed(severity, "random NXDOMAIN names"));

            let list = store.list(0);
            assert_eq!(list.alerts.len(), 1);
            assert!(list.alerts[0].acked);
            assert_eq!(list.alerts[0].count, 2);
            assert_eq!(list.alerts[0].rev, 3);
        }
    }

    #[test]
    fn a_repeat_of_an_acknowledged_high_alert_is_shown_again_and_counts() {
        let (store, _, unix) = store();
        store.raise(weighed(Severity::High, "random NXDOMAIN names"));
        let first = store.list(0).alerts[0].clone();
        assert!(store.ack(first.id));
        unix.store(1_700_000_090, Ordering::SeqCst);
        let before = store.list(0).rev;
        store.raise(weighed(Severity::High, "random NXDOMAIN names"));

        // One alert still, the same one, not acknowledged, and a repeat that a desktop polling
        // after the acknowledgement sees as a change.
        let list = store.list(before - 1);
        assert_eq!(list.alerts.len(), 1);
        let again = &list.alerts[0];
        assert_eq!(
            (again.id, again.key, again.severity),
            (first.id, first.key, "high")
        );
        assert!(!again.acked);
        assert_eq!(again.count, 2);
        assert_eq!(again.first_unix, 1_700_000_000);
        assert_eq!(again.last_unix, 1_700_000_090);
        assert_eq!((again.rev, list.rev), (before + 1, before + 1));
        assert_eq!(store.list(0).alerts.len(), 1);

        // It is acknowledged again like any other, and the next recurrence shows it once more.
        assert!(store.ack(first.id));
        assert!(store.list(0).alerts[0].acked);
        store.raise(weighed(Severity::High, "random NXDOMAIN names"));
        let list = store.list(0);
        assert_eq!((list.alerts[0].acked, list.alerts[0].count), (false, 3));

        // A repeat of one that is not acknowledged only counts.
        store.raise(weighed(Severity::High, "random NXDOMAIN names"));
        let list = store.list(0);
        assert_eq!((list.alerts[0].acked, list.alerts[0].count), (false, 4));
    }

    #[test]
    fn a_kind_may_add_twenty_new_alerts_in_a_rolling_hour() {
        let (store, mono, _) = store();
        for i in 0..NEW_PER_HOUR {
            mono.store(1000 + 100 * i as u64, Ordering::SeqCst);
            store.raise(alert("dga", &format!("n{i}.example.org")));
        }
        assert_eq!(store.list(0).alerts.len(), 20);
        assert_eq!(store.list(0).suppressed, 0);

        // The 21st new alert is dropped and counted; the window began at 1000 and ends at 4600.
        mono.store(2900, Ordering::SeqCst);
        store.raise(alert("dga", "over.example.org"));
        let list = store.list(0);
        assert_eq!(list.alerts.len(), 20);
        assert_eq!(list.suppressed, 1);
        assert!(!subjects(&list).contains(&"over.example.org"));

        // A repeat is a merge, not a new alert, so the limit does not touch it.
        store.raise(alert("dga", "n3.example.org"));
        assert_eq!(store.list(0).suppressed, 1);
        assert_eq!(
            store
                .list(0)
                .alerts
                .iter()
                .find(|a| a.subject == "n3.example.org")
                .map(|a| a.count),
            Some(2)
        );

        // The first of the 20 left the hour at 4600; the second is still inside it until 4700.
        mono.store(4599, Ordering::SeqCst);
        store.raise(alert("dga", "late.example.org"));
        assert_eq!(store.list(0).suppressed, 2);
        mono.store(4600, Ordering::SeqCst);
        store.raise(alert("dga", "late.example.org"));
        assert_eq!(store.list(0).suppressed, 2);
        assert!(subjects(&store.list(0)).contains(&"late.example.org"));
        store.raise(alert("dga", "later.example.org"));
        assert_eq!(store.list(0).suppressed, 3);
    }

    #[test]
    fn the_limit_counts_in_the_hour_that_just_passed_not_in_fixed_hours() {
        let (store, mono, _) = store();
        // Twenty at the very end of one hour and one at the start of the next: still over.
        for i in 0..NEW_PER_HOUR {
            mono.store(3500 + i as u64, Ordering::SeqCst);
            store.raise(alert("tunnel", &format!("n{i}.example.org")));
        }
        mono.store(3700, Ordering::SeqCst);
        store.raise(alert("tunnel", "next.example.org"));
        assert_eq!(store.list(0).suppressed, 1);
    }

    #[test]
    fn beacons_are_limited_to_ten_and_the_other_kinds_to_twenty() {
        let (store, _, _) = store();
        for i in 0..15 {
            store.raise(alert("beacon", &format!("n{i}.example.org")));
        }
        let beacons = store.list(0).alerts.len();
        assert_eq!(beacons, BEACON_PER_HOUR);
        assert_eq!(store.list(0).suppressed, 5);

        // Another kind is not held back by the beacons' window.
        for i in 0..25 {
            store.raise(alert("burst", &format!("n{i}.example.org")));
        }
        let list = store.list(0);
        assert_eq!(list.alerts.len(), 10 + 20);
        assert_eq!(list.suppressed, 10);
    }

    #[test]
    fn more_kinds_than_the_table_holds_are_dropped_until_one_leaves_the_hour() {
        let (store, mono, _) = store();
        let kinds: Vec<&'static str> = (0..MAX_KINDS + 1)
            .map(|i| &*Box::leak(format!("kind{i}").into_boxed_str()))
            .collect();
        for kind in &kinds[..MAX_KINDS] {
            store.raise(alert(kind, "example.org"));
        }
        assert_eq!(store.list(0).alerts.len(), MAX_KINDS);

        store.raise(alert(kinds[MAX_KINDS], "example.org"));
        assert_eq!(store.list(0).alerts.len(), MAX_KINDS);
        assert_eq!(store.list(0).suppressed, 1);

        // After the hour the old kinds have nothing to remember and the new one gets in.
        mono.store(1000 + HOUR_SECS, Ordering::SeqCst);
        store.raise(alert(kinds[MAX_KINDS], "example.org"));
        assert_eq!(store.list(0).alerts.len(), MAX_KINDS + 1);
        assert_eq!(store.list(0).suppressed, 1);
        assert!(store.lock().windows.len() <= MAX_KINDS);
    }

    #[test]
    fn a_full_ring_drops_the_oldest_acknowledged_alert_and_then_the_oldest() {
        let (store, mono, _) = store();
        // An hour apart, so that no rate limit is in the way.
        let raise = |i: usize| {
            mono.store(1000 + HOUR_SECS * i as u64, Ordering::SeqCst);
            store.raise(alert("dga", &format!("n{i}.example.org")));
        };
        for i in 0..CAPACITY {
            raise(i);
        }
        let list = store.list(0);
        assert_eq!(list.alerts.len(), CAPACITY);
        let id_of = |name: &str| {
            list.alerts
                .iter()
                .find(|a| a.subject == name)
                .map(|a| a.id)
                .unwrap()
        };
        assert!(store.ack(id_of("n3.example.org")));
        assert!(store.ack(id_of("n7.example.org")));

        raise(CAPACITY);
        let names = |l: &AlertList| -> HashSet<String> {
            l.alerts.iter().map(|a| a.subject.clone()).collect()
        };
        let list = store.list(0);
        assert_eq!(list.alerts.len(), CAPACITY);
        assert!(!names(&list).contains("n3.example.org"));
        assert!(names(&list).contains("n7.example.org"));
        assert!(names(&list).contains("n0.example.org"));

        raise(CAPACITY + 1);
        let list = store.list(0);
        assert!(!names(&list).contains("n7.example.org"));
        assert!(names(&list).contains("n0.example.org"));

        // None is acknowledged now (the two that were are gone): the oldest goes.
        raise(CAPACITY + 2);
        let list = store.list(0);
        assert_eq!(list.alerts.len(), CAPACITY);
        assert!(!names(&list).contains("n0.example.org"));
        assert!(names(&list).contains("n1.example.org"));
        raise(CAPACITY + 3);
        assert!(!names(&store.list(0)).contains("n1.example.org"));
        assert!(names(&store.list(0)).contains("n2.example.org"));
        assert_eq!(store.list(0).suppressed, 0);
        // The ack of an alert that is gone finds nothing.
        assert!(!store.ack(id_of("n3.example.org")));
    }

    #[test]
    fn an_alert_that_left_the_ring_and_comes_back_is_a_new_one() {
        let (store, mono, _) = store();
        store.raise(alert("dga", "first.example.org"));
        let first = store.list(0).alerts[0].id;
        for i in 0..CAPACITY {
            mono.store(1000 + HOUR_SECS * (i as u64 + 1), Ordering::SeqCst);
            store.raise(alert("dga", &format!("n{i}.example.org")));
        }
        assert!(!subjects(&store.list(0)).contains(&"first.example.org"));
        mono.store(1000 + HOUR_SECS * 300, Ordering::SeqCst);
        store.raise(alert("dga", "first.example.org"));
        let list = store.list(0);
        let back = list
            .alerts
            .iter()
            .find(|a| a.subject == "first.example.org")
            .unwrap();
        assert_ne!(back.id, first);
        assert_eq!(back.count, 1);
    }

    #[test]
    fn an_alert_is_acknowledged_by_its_id() {
        let (store, _, _) = store();
        store.raise(alert("dga", "random NXDOMAIN names"));
        store.raise(alert("burst", "question rate"));
        let list = store.list(0);
        let (dga, burst) = (list.alerts[0].id, list.alerts[1].id);
        let before = list.rev;

        assert!(store.ack(burst));
        let list = store.list(0);
        assert_eq!(list.rev, before + 1);
        assert!(!list.alerts.iter().find(|a| a.id == dga).unwrap().acked);
        let b = list.alerts.iter().find(|a| a.id == burst).unwrap();
        assert!(b.acked);
        assert_eq!(b.rev, before + 1);

        // Twice is the same as once and changes nothing; an unknown id is not found.
        assert!(store.ack(burst));
        assert_eq!(store.list(0).rev, before + 1);
        assert!(!store.ack(9999));
        assert!(!store.ack(0));
        assert_eq!(store.list(0).rev, before + 1);
    }

    #[test]
    fn restored_keys_acknowledge_the_alerts_there_and_the_ones_to_come() {
        let (store, _, _) = store();
        store.raise(alert("dga", "random NXDOMAIN names"));
        let there = key_of("dga", Some(client()), "random NXDOMAIN names");
        let to_come = key_of("beacon", Some(client()), "example.org");
        let never = key_of("beacon", Some(client()), "example.com");
        let rev = store.list(0).rev;

        assert_eq!(store.restore_acked(&[there, to_come, never]), 3);
        let list = store.list(rev);
        assert_eq!(list.alerts.len(), 1);
        assert!(list.alerts[0].acked);
        assert_eq!(list.alerts[0].kind, "dga");
        assert_eq!(list.rev, rev + 1);

        store.raise(alert("beacon", "example.org"));
        store.raise(alert("beacon", "example.net"));
        let list = store.list(0);
        let acked = |subject: &str| {
            list.alerts
                .iter()
                .find(|a| a.subject == subject)
                .map(|a| a.acked)
        };
        assert_eq!(acked("example.org"), Some(true));
        assert_eq!(acked("example.net"), Some(false));

        // Sent again, the same keys change nothing that is there.
        let rev = store.list(0).rev;
        assert_eq!(store.restore_acked(&[there, to_come]), 2);
        assert_eq!(store.list(0).rev, rev);
        assert_eq!(store.restore_acked(&[]), 0);
    }

    #[test]
    fn a_restored_key_covers_the_first_raise_and_a_high_recurrence_shows_the_alert() {
        let (store, _, _) = store();
        let high = key_of("dga", Some(client()), "example.org");
        let warn = key_of("burst", Some(client()), "example.net");
        assert_eq!(store.restore_acked(&[high, warn]), 2);

        // The first raise of each starts acknowledged, as the desktop asked.
        store.raise(weighed(Severity::High, "example.org"));
        let mut burst = weighed(Severity::Warn, "example.net");
        burst.kind = "burst";
        store.raise(burst);
        let list = store.list(0);
        assert!(list.alerts.iter().all(|a| a.acked && a.count == 1));
        let rev = list.rev;

        // A recurrence after that is news for the High one, and nothing new for the light one.
        let mut burst = weighed(Severity::Warn, "example.net");
        burst.kind = "burst";
        store.raise(burst);
        store.raise(weighed(Severity::High, "example.org"));
        let list = store.list(rev);
        assert_eq!(list.alerts.len(), 2);
        let acked = |kind: &str| {
            list.alerts
                .iter()
                .find(|a| a.kind == kind)
                .map(|a| (a.acked, a.count))
        };
        assert_eq!(acked("dga"), Some((false, 2)));
        assert_eq!(acked("burst"), Some((true, 2)));

        // The key was restored from an earlier boot and is still there: sent again, it
        // acknowledges the alert that is in the ring, as `restore_acked` says.
        assert_eq!(store.restore_acked(&[high]), 1);
        assert!(store.list(0).alerts.iter().all(|a| a.acked));
    }

    #[test]
    fn a_high_alert_that_was_acknowledged_in_the_ring_comes_back_in_the_old_order() {
        let (store, _, _) = store();
        let panel: &dyn PendingAlerts = &store;
        store.raise(weighed(Severity::High, "older"));
        store.raise(weighed(Severity::High, "newer"));
        assert_eq!(on_offer(panel).as_deref(), Some("newer"));
        panel.ack(2);
        panel.ack(1);
        assert!(panel.top().is_none());

        // The older one recurs first: it is the one on offer, as the only one not acknowledged.
        store.raise(weighed(Severity::High, "older"));
        assert_eq!(on_offer(panel).as_deref(), Some("older"));
        // Then the newer one: a repeat does not make an alert newer, so the newer is still first.
        store.raise(weighed(Severity::High, "newer"));
        assert_eq!(on_offer(panel).as_deref(), Some("newer"));
        panel.ack(2);
        assert_eq!(on_offer(panel).as_deref(), Some("older"));
        panel.ack(1);
        assert!(panel.top().is_none());
        // Neither took a new id.
        let mut ids: Vec<u64> = store.list(0).alerts.iter().map(|a| a.id).collect();
        ids.sort_unstable();
        assert_eq!(ids, [1, 2]);
    }

    #[test]
    fn restored_keys_are_capped_the_oldest_leave_and_a_key_sent_again_is_newest() {
        let (store, _, _) = store();
        let keys: Vec<u64> = (0..1100).collect();
        // Of 1100 keys only the newest 1024 are kept, and the count says so.
        assert_eq!(store.restore_acked(&keys), MAX_RESTORED);
        assert_eq!(store.lock().restored.len(), MAX_RESTORED);
        assert_eq!(store.lock().restored.front(), Some(&76));
        assert_eq!(store.lock().restored.back(), Some(&1099));

        // The key 76 is sent again, so it is the newest and key 77 is the oldest now.
        assert_eq!(store.restore_acked(&[76]), 1);
        assert_eq!(store.lock().restored.len(), MAX_RESTORED);
        assert_eq!(store.lock().restored.front(), Some(&77));
        assert_eq!(store.lock().restored.back(), Some(&76));

        // A new key pushes the oldest out.
        assert_eq!(store.restore_acked(&[5000]), 1);
        assert_eq!(store.lock().restored.front(), Some(&78));

        // The same key twice in one body is counted once.
        assert_eq!(store.restore_acked(&[6000, 6000]), 1);
    }

    #[test]
    fn the_revision_cursor_lists_what_changed_since_the_oldest_change_first() {
        let (store, _, _) = store();
        store.raise(alert("dga", "random NXDOMAIN names")); // rev 1
        store.raise(alert("burst", "question rate")); // rev 2
        store.raise(alert("tunnel", "example.org")); // rev 3
        let list = store.list(0);
        assert_eq!(list.rev, 3);
        assert_eq!(
            subjects(&list),
            ["random NXDOMAIN names", "question rate", "example.org"]
        );
        assert_eq!(
            list.alerts.iter().map(|a| a.rev).collect::<Vec<_>>(),
            [1, 2, 3]
        );

        // Nothing changed: nothing listed, and the revision is the same.
        let list = store.list(3);
        assert!(list.alerts.is_empty());
        assert_eq!(list.rev, 3);

        // A merge moves an alert to the end, an ack as well.
        store.raise(alert("dga", "random NXDOMAIN names")); // rev 4
        let burst = store
            .list(0)
            .alerts
            .iter()
            .find(|a| a.kind == "burst")
            .unwrap()
            .id;
        assert!(store.ack(burst)); // rev 5
        let list = store.list(3);
        assert_eq!(list.rev, 5);
        assert_eq!(subjects(&list), ["random NXDOMAIN names", "question rate"]);
        let list = store.list(4);
        assert_eq!(subjects(&list), ["question rate"]);
        assert_eq!(
            store
                .list(0)
                .alerts
                .iter()
                .map(|a| a.kind)
                .collect::<Vec<_>>(),
            ["tunnel", "dga", "burst"]
        );

        // A revision from the future lists nothing.
        assert!(store.list(99).alerts.is_empty());
    }

    #[test]
    fn a_step_of_the_clock_never_hides_an_alert_from_the_cursor() {
        let (store, _, unix) = store();
        store.raise(alert("dga", "random NXDOMAIN names"));
        let seen = store.list(0).rev;
        // The wall clock jumps back by a year and the monotonic one is not touched.
        unix.store(1_670_000_000, Ordering::SeqCst);
        store.raise(alert("burst", "question rate"));
        let list = store.list(seen);
        assert_eq!(subjects(&list), ["question rate"]);
        assert_eq!(list.alerts[0].first_unix, 1_670_000_000);
    }

    #[test]
    fn the_key_is_the_same_on_every_boot() {
        // FNV-1a 64 of "beacon\0192.0.2.10\0example.org", worked out outside this program.
        let key = key_of("beacon", Some(client()), "example.org");
        assert_eq!(key_hex(key), "1d398bff8473c1a8");
        // No client leaves the middle part empty.
        assert_eq!(
            key_hex(key_of("dga", None, "random NXDOMAIN names")),
            "4754ee16ce859fca"
        );
        assert_eq!(
            key_hex(key_of("rebind", Some("2001:db8::1".parse().unwrap()), "x")),
            "93cb236a7d8bc487"
        );

        // The key shown by a stored alert is the one `key_of` gives.
        let (store, _, _) = store();
        store.raise(alert("beacon", "example.org"));
        assert_eq!(store.list(0).alerts[0].key, key);
    }

    #[test]
    fn a_key_is_sixteen_lowercase_hex_digits_and_the_parts_cannot_slide() {
        assert_eq!(key_hex(0), "0000000000000000");
        assert_eq!(key_hex(0xab), "00000000000000ab");
        assert_eq!(key_hex(u64::MAX), "ffffffffffffffff");
        assert_ne!(key_of("a", None, "bc"), key_of("ab", None, "c"));
        assert_ne!(
            key_of("a", Some(client()), ""),
            key_of("a", None, "192.0.2.10")
        );
        assert_ne!(key_of("a", None, ""), key_of("a", Some(client()), ""));
    }

    #[test]
    fn the_hash_is_fnv_1a_with_the_standard_numbers() {
        let hash = |text: &str| {
            let mut fnv = Fnv::new();
            fnv.bytes(text.as_bytes());
            fnv.0
        };
        assert_eq!(hash(""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(hash("a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(hash("foobar"), 0x8594_4171_f739_67e8);
    }

    #[test]
    fn a_long_subject_is_cut_at_a_character_boundary() {
        let (store, _, _) = store();
        // Plain letters are cut at 255 bytes.
        store.raise(alert("tunnel", &"a".repeat(300)));
        // Two-byte letters: 255 is the middle of one, so the cut is at 254.
        store.raise(alert("tunnel", &"é".repeat(200)));
        // Exactly 255 bytes stays whole; a short one is untouched.
        store.raise(alert("tunnel", &"b".repeat(255)));
        store.raise(alert("tunnel", "example.org"));
        let list = store.list(0);
        assert_eq!(list.alerts[0].subject, "a".repeat(255));
        assert_eq!(list.alerts[1].subject, "é".repeat(127));
        assert_eq!(list.alerts[1].subject.len(), 254);
        assert_eq!(list.alerts[2].subject, "b".repeat(255));
        assert_eq!(list.alerts[3].subject, "example.org");
    }

    #[test]
    fn subjects_that_agree_up_to_the_cut_are_one_alert_with_the_key_of_the_cut() {
        let (store, _, _) = store();
        let head = "c".repeat(255);
        store.raise(alert("tunnel", &format!("{head}one")));
        store.raise(alert("tunnel", &format!("{head}two")));
        let list = store.list(0);
        assert_eq!(list.alerts.len(), 1);
        assert_eq!(list.alerts[0].count, 2);
        assert_eq!(list.alerts[0].key, key_of("tunnel", Some(client()), &head));
    }

    #[test]
    fn the_severity_reads_as_info_warn_or_high() {
        let (store, _, _) = store();
        for (subject, severity) in [
            ("a", Severity::Info),
            ("b", Severity::Warn),
            ("c", Severity::High),
        ] {
            store.raise(Alert {
                kind: "dga",
                severity,
                client: None,
                subject: subject.to_string(),
            });
        }
        let list = store.list(0);
        let texts: Vec<&str> = list.alerts.iter().map(|a| a.severity).collect();
        assert_eq!(texts, ["info", "warn", "high"]);
    }

    /// An alert of the kind `dga` and this severity, about the test client and `subject`.
    fn weighed(severity: Severity, subject: &str) -> Alert {
        Alert {
            kind: "dga",
            severity,
            client: Some(client()),
            subject: subject.to_string(),
        }
    }

    /// The subject of the alert that the panel is offered, or `None` for no alert.
    fn on_offer(panel: &dyn PendingAlerts) -> Option<String> {
        panel.top().map(|alert| alert.subject)
    }

    #[test]
    fn the_panel_is_offered_no_alert_by_an_empty_store() {
        let (store, _, _) = store();
        let panel: &dyn PendingAlerts = &store;
        assert!(panel.top().is_none());
        panel.ack(1);
        assert!(panel.top().is_none());
    }

    #[test]
    fn the_panel_is_offered_the_highest_severity_and_of_those_the_newest() {
        let (store, _, _) = store();
        let panel: &dyn PendingAlerts = &store;
        for (severity, subject) in [
            (Severity::Info, "a"),
            (Severity::High, "b"),
            (Severity::Warn, "c"),
            (Severity::High, "d"),
            (Severity::Info, "e"),
        ] {
            store.raise(weighed(severity, subject));
        }
        // The newest high one, and not the newest alert there is.
        let top = panel.top().unwrap();
        assert_eq!(
            (top.id, top.kind.as_str(), top.subject.as_str()),
            (4, "dga", "d")
        );
        assert_eq!(top.severity, PanelSeverity::High);
        assert_eq!(top.client, Some(client()));
        // Each one that is acknowledged leaves the next: the other high one, then warn, then info,
        // the newer of the two before the older.
        let mut offered = Vec::new();
        for _ in 0..8 {
            let Some(alert) = panel.top() else { break };
            offered.push(alert.subject);
            panel.ack(alert.id);
        }
        assert_eq!(offered, ["d", "b", "c", "e", "a"]);
    }

    #[test]
    fn a_repeat_does_not_make_an_alert_newer() {
        let (store, _, _) = store();
        let panel: &dyn PendingAlerts = &store;
        store.raise(weighed(Severity::Warn, "first"));
        store.raise(weighed(Severity::Warn, "second"));
        store.raise(weighed(Severity::Warn, "first"));
        assert_eq!(on_offer(panel).as_deref(), Some("second"));
    }

    #[test]
    fn the_panels_ack_takes_the_alert_off_offer_and_is_the_stores_own() {
        let (store, _, _) = store();
        let panel: &dyn PendingAlerts = &store;
        store.raise(weighed(Severity::Warn, "older"));
        store.raise(weighed(Severity::Warn, "newer"));
        let revision = store.list(0).rev;

        panel.ack(2);
        assert_eq!(on_offer(panel).as_deref(), Some("older"));
        // The desktop that reads the list sees the acknowledgement as a change.
        let changed = store.list(revision);
        assert_eq!(subjects(&changed), ["newer"]);
        assert!(changed.alerts[0].acked);

        // An id that is not known changes nothing; neither does asking twice.
        let revision = store.list(0).rev;
        panel.ack(99);
        panel.ack(2);
        assert_eq!(store.list(revision).alerts.len(), 0);
        assert_eq!(on_offer(panel).as_deref(), Some("older"));

        panel.ack(1);
        assert!(panel.top().is_none());
    }

    #[test]
    fn an_acknowledged_warn_alert_does_not_come_back() {
        let (store, _, _) = store();
        let panel: &dyn PendingAlerts = &store;
        store.raise(weighed(Severity::Warn, "seen"));
        store.raise(weighed(Severity::Info, "other"));
        panel.ack(1);
        assert_eq!(on_offer(panel).as_deref(), Some("other"));

        // It is raised again, as a repeat of it is: it merges, and stays acknowledged, and the
        // lighter alert that is not acknowledged is still the one on offer.
        store.raise(weighed(Severity::Warn, "seen"));
        let list = store.list(0);
        let seen = list.alerts.iter().find(|a| a.subject == "seen").unwrap();
        assert_eq!((seen.count, seen.acked), (2, true));
        assert_eq!(on_offer(panel).as_deref(), Some("other"));

        panel.ack(2);
        store.raise(weighed(Severity::Warn, "seen"));
        assert!(panel.top().is_none());

        // A new alert is another matter, even about the same client.
        store.raise(weighed(Severity::Warn, "unseen"));
        assert_eq!(on_offer(panel).as_deref(), Some("unseen"));
    }

    #[test]
    fn an_acknowledged_high_alert_comes_back_on_a_repeat_before_lighter_ones() {
        let (store, _, _) = store();
        let panel: &dyn PendingAlerts = &store;
        store.raise(weighed(Severity::High, "seen"));
        store.raise(weighed(Severity::Info, "other"));
        panel.ack(1);
        assert_eq!(on_offer(panel).as_deref(), Some("other"));

        // The repeat merges, shows the alert again, and it outranks the lighter one on offer.
        store.raise(weighed(Severity::High, "seen"));
        let list = store.list(0);
        let seen = list.alerts.iter().find(|a| a.subject == "seen").unwrap();
        assert_eq!((seen.count, seen.acked), (2, false));
        assert_eq!(on_offer(panel).as_deref(), Some("seen"));

        panel.ack(1);
        assert_eq!(on_offer(panel).as_deref(), Some("other"));
    }

    #[test]
    fn the_panels_severity_is_the_stores() {
        assert_eq!(PanelSeverity::from(Severity::Info), PanelSeverity::Info);
        assert_eq!(PanelSeverity::from(Severity::Warn), PanelSeverity::Warn);
        assert_eq!(PanelSeverity::from(Severity::High), PanelSeverity::High);
        assert!(Severity::Info < Severity::Warn && Severity::Warn < Severity::High);
    }

    /// The kinds that `filled` spreads its alerts over: sixteen, so that no kind passes its rate limit.
    const KINDS: [&str; 16] = [
        "k00", "k01", "k02", "k03", "k04", "k05", "k06", "k07", "k08", "k09", "k10", "k11", "k12",
        "k13", "k14", "k15",
    ];

    /// The alerts that `filled` raises, in the order it raises them: one per slot of the ring.
    fn ring_of(severity: Severity) -> Vec<Alert> {
        (0..CAPACITY)
            .map(|n| Alert {
                kind: KINDS[n % KINDS.len()],
                severity,
                client: Some(client()),
                subject: format!("example{n}.org"),
            })
            .collect()
    }

    /// A store whose ring is full of alerts of this severity, none of them acknowledged.
    fn filled(severity: Severity) -> AlertStore {
        let (store, _, _) = store();
        for alert in ring_of(severity) {
            store.raise(alert);
        }
        assert_eq!(store.list(0).alerts.len(), CAPACITY);
        store
    }

    /// Prints what `raise` costs when it merges into an alert of a full ring (the path a repeat of a
    /// threat takes, from a task of its own after the answer is sent): into one not acknowledged,
    /// into an acknowledged one of a light kind, and into an acknowledged one of a High kind.
    /// Each round raises once into every one of the 256 alerts, so the scan averages half the ring.
    #[test]
    #[ignore = "prints a timing; run: cargo test --release -p qberrypi raise_merge_timing -- --ignored --nocapture"]
    fn raise_merge_timing() {
        const ROUNDS: u32 = 4000;
        for (name, severity, acked_first) in [
            (
                "into an alert not acknowledged (warn)",
                Severity::Warn,
                false,
            ),
            ("into an acknowledged alert (warn)", Severity::Warn, true),
            ("into an acknowledged alert (high)", Severity::High, true),
        ] {
            let store = filled(severity);
            let ids: Vec<u64> = store.list(0).alerts.iter().map(|a| a.id).collect();
            let mut spent = Duration::ZERO;
            let mut best = Duration::MAX;
            for _ in 0..ROUNDS {
                if acked_first {
                    // Untimed: the ring is made ready for the round.
                    for &id in &ids {
                        store.ack(id);
                    }
                }
                let round = ring_of(severity);
                let started = Instant::now();
                for alert in round {
                    store.raise(alert);
                }
                let round = started.elapsed();
                spent += round;
                best = best.min(round);
            }
            let each = |total: Duration, raises: usize| total.as_secs_f64() * 1e9 / raises as f64;
            println!(
                "store raise {name}: {:.0} ns each on average, {:.0} ns in the best round ({} raises)",
                each(spent, ROUNDS as usize * CAPACITY),
                each(best, CAPACITY),
                ROUNDS as usize * CAPACITY
            );
        }
    }

    #[test]
    fn the_store_works_as_a_sink_that_many_threads_raise_into() {
        let (store, _, _) = store();
        let store = Arc::new(store);
        let sink: Arc<dyn AlertSink> = store.clone();
        std::thread::scope(|scope| {
            for t in 0..4 {
                let sink = sink.clone();
                scope.spawn(move || {
                    for _ in 0..50 {
                        // The same alert from four threads merges into one.
                        sink.raise(alert("burst", "question rate"));
                        sink.raise(alert("dga", &format!("thread{t}")));
                    }
                });
            }
        });
        let list = store.list(0);
        assert_eq!(list.alerts.len(), 5);
        let count = |subject: &str| {
            list.alerts
                .iter()
                .find(|a| a.subject == subject)
                .map(|a| a.count)
        };
        assert_eq!(count("question rate"), Some(200));
        for t in 0..4 {
            assert_eq!(count(&format!("thread{t}")), Some(50));
        }
        assert_eq!(list.rev, 400);
    }
}
