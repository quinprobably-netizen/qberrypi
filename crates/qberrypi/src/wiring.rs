//! Where the panel and the status page meet the running system: the real source of their numbers
//! and the real switch of blocking.
//!
//! The panel is given a [`Slot`] that answers as if nothing were measured until the first service
//! to start (`services`) fills it with the [`Live`] that reads the resolver the DNS task answers
//! from. The supervisor starts the panel beside the snapshot load that comes first, so the panel
//! may read the slot before it is filled, and shows no numbers until it is. Nothing here runs per
//! DNS query: the resolver is locked once per call, only to copy numbers out, and never across an
//! `.await`.
//!
//! The slot holds the watchdog's alert store the same way: the same service fills it, and until
//! then the panel has no alert to show. The store is read through its own lock and no other.

use std::sync::atomic::{AtomicI16, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use qb_dns::{LogEntry, Now, Resolver};
use tokio::sync::watch;

use crate::dns::Dns;
use crate::lane::LaneFeed;
use crate::lists::Lists;
use crate::live::{self, BlockingControl, Snapshot, Source};
use crate::panel::alerts::{PanelAlert, PendingAlerts};
use crate::wifi;

/// The file in which the kernel lists the wireless interfaces' signal.
pub const PROC_WIRELESS: &str = "/proc/net/wireless";

/// The Wi-Fi interface: the one whose line of [`PROC_WIRELESS`] is read, and the one that the
/// device watch listens on.
pub const INTERFACE: &str = "wlan0";

/// The resolver the DNS task answers from, and that task's own clock.
#[derive(Clone)]
pub struct SharedResolver {
    /// The resolver, which every holder locks for a copy or a change and for no longer.
    pub resolver: Arc<Mutex<Resolver>>,
    /// The time of this moment as the DNS task counts it: its monotonic seconds, and the system clock.
    pub now: Arc<dyn Fn() -> Now + Send + Sync>,
}

impl SharedResolver {
    /// The resolver of `dns` and its clock.
    pub fn of(dns: &Arc<Dns>) -> Self {
        let clock = dns.clone();
        Self {
            resolver: dns.shared(),
            now: Arc::new(move || clock.now()),
        }
    }

    /// The resolver, locked, whether or not a holder panicked: it keeps its bounds whatever a
    /// call left half done. Never hold the guard across an `.await`.
    fn lock(&self) -> crate::stall::Held<'_, Resolver> {
        crate::stall::lock_resolver(&self.resolver)
    }
}

/// The pause is counted on the DNS task's monotonic seconds, the clock the resolver itself uses,
/// so the wall clock stepping to the real time in the middle of a pause does not touch it.
impl BlockingControl for SharedResolver {
    fn paused_left_secs(&self) -> Option<u16> {
        let now = (self.now)();
        let until = self.lock().paused_until(now)?;
        Some(u16::try_from(until.saturating_sub(now.mono_secs)).unwrap_or(u16::MAX))
    }

    fn pause_for(&self, secs: u16) {
        let until = (self.now)().mono_secs.saturating_add(u64::from(secs));
        self.lock().pause_until(until);
    }

    fn resume(&self) {
        self.lock().resume();
    }
}

/// What the resolver does not know and the panel shows all the same.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Extras {
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

impl Extras {
    /// What `dns`, `lists` and the clock's `synced` say now.
    pub fn read(dns: &Dns, lists: &Lists, synced: &watch::Receiver<bool>) -> Self {
        let lists = lists.get();
        Self {
            upstream_ms: dns.upstreams().latency_ms(),
            utc_offset_secs: dns.utc_offset(),
            clock_set: *synced.borrow(),
            list_names: Some(lists.names),
            list_fetched_unix: lists.fetched_unix_secs,
        }
    }
}

/// The real source of what the panel shows: the resolver's own counts and log, the radio's link,
/// and the extras.
pub struct Live {
    /// The resolver, and its clock.
    pub resolver: SharedResolver,
    /// The state of the Wi-Fi link, read when asked.
    pub link: Arc<dyn Fn() -> live::WifiStatus + Send + Sync>,
    /// What else is known, read when asked.
    pub extras: Arc<dyn Fn() -> Extras + Send + Sync>,
}

impl Source for Live {
    fn snapshot(&self) -> Snapshot {
        let now = (self.resolver.now)();
        // The resolver is locked only to copy a few numbers out.
        let (today, total, last_blocked) = {
            let resolver = self.resolver.lock();
            let stats = resolver.stats();
            (stats.today(now), stats.total(), stats.last_blocked(now))
        };
        let extras = (self.extras)();
        Snapshot {
            wifi: Some((self.link)()),
            today: Some(today),
            total: Some(total),
            last_blocked,
            upstream_ms: extras.upstream_ms,
            utc_offset_secs: extras.utc_offset_secs,
            clock_set: extras.clock_set,
            list_names: extras.list_names,
            list_fetched_unix: extras.list_fetched_unix,
        }
    }

    fn recent(&self, n: usize) -> Vec<LogEntry> {
        self.resolver.lock().stats().recent(n).cloned().collect()
    }
}

/// What the panel is given, in the place of the [`Live`] that is made beside it.
///
/// Until it is filled it answers as [`live::Nothing`] does, and the switch does nothing, with a
/// line in the log. The panel's thread reads it, and the first service to start fills it, once.
///
/// It is the panel's source of alerts too ([`PendingAlerts`]): there is none until
/// [`Slot::fill_alerts`] puts the watchdog's store in, and an acknowledgement before that is
/// dropped without a line, since it names an alert that cannot have been shown.
pub struct Slot {
    live: OnceLock<Live>,
    /// The watchdog's alerts, as the panel reads them; filled by the same service as `live`.
    alerts: OnceLock<Arc<dyn PendingAlerts>>,
    /// The names that the DNS service offers the panel. It is the slot's, not the live source's:
    /// the panel holds it from the start, before the resolver that fills it exists.
    lane: Arc<LaneFeed>,
}

impl Slot {
    /// An empty slot.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            live: OnceLock::new(),
            alerts: OnceLock::new(),
            lane: LaneFeed::new(),
        })
    }

    /// The feed of the names that clients ask for, which the DNS service fills and the panel
    /// empties.
    pub fn lane(&self) -> Arc<LaneFeed> {
        self.lane.clone()
    }

    /// Puts `live` in the slot; a slot that is filled already keeps what it has.
    pub fn fill(&self, live: Live) {
        // The second value is of no use to anyone: the first stays.
        let _ = self.live.set(live);
    }

    /// Puts the source of the panel's alerts in the slot; a slot that has one keeps it.
    pub fn fill_alerts(&self, alerts: Arc<dyn PendingAlerts>) {
        // As in `fill`: the first stays.
        let _ = self.alerts.set(alerts);
    }
}

impl PendingAlerts for Slot {
    fn top(&self) -> Option<PanelAlert> {
        self.alerts.get()?.top()
    }

    fn ack(&self, id: u64) {
        if let Some(alerts) = self.alerts.get() {
            alerts.ack(id);
        }
    }
}

impl Source for Slot {
    fn snapshot(&self) -> Snapshot {
        self.live
            .get()
            .map_or_else(Snapshot::default, Live::snapshot)
    }

    fn recent(&self, n: usize) -> Vec<LogEntry> {
        self.live.get().map_or_else(Vec::new, |live| live.recent(n))
    }
}

impl BlockingControl for Slot {
    fn paused_left_secs(&self) -> Option<u16> {
        self.live.get()?.resolver.paused_left_secs()
    }

    fn pause_for(&self, secs: u16) {
        match self.live.get() {
            Some(live) => live.resolver.pause_for(secs),
            None => log::warn!("{NOT_RUNNING}"),
        }
    }

    fn resume(&self) {
        match self.live.get() {
            Some(live) => live.resolver.resume(),
            None => log::warn!("{NOT_RUNNING}"),
        }
    }
}

/// What the log says when the switch is worked before the resolver exists.
const NOT_RUNNING: &str = "switch: the resolver is not running yet; blocking stays on";

/// The signal in dBm of `wlan0` in the text of [`PROC_WIRELESS`]: the third number on the line
/// that starts with `wlan0:` (`-61.` is -61); `None` without that line or a number there.
///
/// The numbers of the line are the status, the link quality and the level, then the noise; the
/// dot after a number says that the driver updated it.
pub fn proc_signal(text: &str) -> Option<i8> {
    let line = text
        .lines()
        .find_map(|line| line.trim_start().strip_prefix(INTERFACE)?.strip_prefix(':'))?;
    let level = line.split_whitespace().nth(2)?;
    let dbm: i32 = level.trim_end_matches('.').parse().ok()?;
    Some(held(dbm))
}

/// The Wi-Fi signal as the `signal` component last read it, for whoever shows it.
///
/// Reading [`PROC_WIRELESS`] makes the driver ask the firmware, which takes milliseconds and now
/// and then seconds, and holds the kernel's network locks meanwhile. So that is done in one place,
/// off the runtime thread, and the front panel and the status page read this instead, which is
/// one load and never waits.
pub struct SignalCache(AtomicI16);

/// What [`SignalCache`] holds for no signal: below every `i8`, so that no signal can be taken for it.
const NO_SIGNAL: i16 = i16::MIN;

impl SignalCache {
    /// A cache with no signal in it.
    pub fn new() -> Arc<Self> {
        Arc::new(Self(AtomicI16::new(NO_SIGNAL)))
    }

    /// The signal in dBm that was stored last, or `None` if none was or the last was `None`.
    pub fn get(&self) -> Option<i8> {
        // The one value stands alone: nothing else is published with it.
        i8::try_from(self.0.load(Ordering::Relaxed)).ok()
    }

    /// Stores `signal` for the readers to find.
    pub fn set(&self, signal: Option<i8>) {
        self.0
            .store(signal.map_or(NO_SIGNAL, i16::from), Ordering::Relaxed);
    }
}

/// What the panel and the status page show of the Wi-Fi for the Wi-Fi task's `status`.
///
/// Only a joined link has a signal, an access point and a channel. The signal is the live one, which
/// `signal` reads, and when that is unknown it is the one the join measured. `signal` is called
/// only when joined. The access point is its address in the form the log shows. The channel's frequency
/// is the one the join found, copied out of the status: nothing is asked of the radio for it.
pub fn link_status(
    status: &wifi::WifiStatus,
    signal: impl FnOnce() -> Option<i8>,
) -> live::WifiStatus {
    match status {
        wifi::WifiStatus::Joined {
            bssid,
            freq_mhz,
            signal_mbm,
        } => live::WifiStatus {
            associated: true,
            signal_dbm: signal().or_else(|| Some(held(wifi::dbm(*signal_mbm)))),
            ap: Some(wifi::mac(bssid)),
            freq_mhz: Some(*freq_mhz),
        },
        _ => live::WifiStatus::default(),
    }
}

/// `dbm` held to what an `i8` can say.
fn held(dbm: i32) -> i8 {
    dbm.clamp(i8::MIN.into(), i8::MAX.into()) as i8
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicU64, Ordering};

    use qb_dns::{Action, BlockSetBuilder, Counts, Resolver, Transport};
    use tokio::sync::watch;

    use crate::alerts::{Alert, AlertSink, Severity};
    use crate::dns::testutil::FixedOffset;
    use crate::dns::upstream::Upstreams;
    use crate::lists::{ListState, Source as ListSource};
    use crate::live::Snapshot;
    use crate::watch::store::AlertStore;

    /// A resolver that blocks `ads.example.com`.
    fn resolver() -> Resolver {
        let mut builder = BlockSetBuilder::new();
        builder.add_list(b"0.0.0.0 ads.example.com\n");
        Resolver::new(builder.build())
    }

    /// A resolver that is shared with a clock that the test moves: `mono` seconds on the DNS
    /// task's own clock, and a wall clock that is 1_800_000_000 seconds ahead of it.
    fn shared(mono: u64) -> (SharedResolver, Arc<AtomicU64>) {
        let clock = Arc::new(AtomicU64::new(mono));
        let shared = SharedResolver {
            resolver: Arc::new(Mutex::new(resolver())),
            now: {
                let clock = clock.clone();
                Arc::new(move || {
                    let mono_secs = clock.load(Ordering::SeqCst);
                    Now {
                        mono_secs,
                        unix_secs: 1_800_000_000 + mono_secs,
                    }
                })
            },
        };
        (shared, clock)
    }

    /// A query for `name`: ID 7, recursion desired, one question, type A, class IN.
    fn query(name: &str) -> Vec<u8> {
        let mut packet = vec![0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.extend_from_slice(&[0, 0, 1, 0, 1]);
        packet
    }

    /// What the resolver decides for a query for `name` at the clock's time.
    fn ask(shared: &SharedResolver, name: &str) -> Action {
        let now = (shared.now)();
        shared
            .resolver
            .lock()
            .unwrap()
            .handle_query(&query(name), Transport::Udp, now)
    }

    /// A Wi-Fi link as the front end shows it.
    fn status(associated: bool, signal_dbm: Option<i8>) -> live::WifiStatus {
        live::WifiStatus {
            associated,
            signal_dbm,
            ap: None,
            freq_mhz: None,
        }
    }

    /// A `Live` over `shared`, whose link is `link` and whose extras are `extras`.
    fn live(shared: SharedResolver, link: live::WifiStatus, extras: Extras) -> Live {
        Live {
            resolver: shared,
            link: Arc::new(move || link.clone()),
            extras: Arc::new(move || extras.clone()),
        }
    }

    #[test]
    fn a_tap_pauses_the_very_resolver_the_dns_task_answers_from() {
        let (shared, clock) = shared(100);
        assert!(matches!(ask(&shared, "ads.example.com"), Action::Reply(_))); // blocked
        shared.pause_for(300);
        assert_eq!(shared.paused_left_secs(), Some(300));
        assert!(matches!(
            ask(&shared, "ads.example.com"),
            Action::Forward(_)
        )); // let through
        clock.store(399, Ordering::SeqCst);
        assert_eq!(shared.paused_left_secs(), Some(1));
        clock.store(400, Ordering::SeqCst);
        assert_eq!(shared.paused_left_secs(), None);
        assert!(matches!(ask(&shared, "ads.example.com"), Action::Reply(_))); // blocked again, by itself
        shared.pause_for(300);
        shared.resume();
        assert_eq!(shared.paused_left_secs(), None);
    }

    // Review Focus 4
    #[test]
    fn the_pause_runs_on_the_dns_tasks_seconds_whatever_the_wall_clock_does() {
        // The wall clock starts at the image's build time and steps a year ahead in the middle of
        // the pause; the monotonic seconds are the ones that count.
        let mono = Arc::new(AtomicU64::new(40));
        let wall = Arc::new(AtomicU64::new(crate::BUILD_EPOCH));
        let shared = SharedResolver {
            resolver: Arc::new(Mutex::new(resolver())),
            now: {
                let (mono, wall) = (mono.clone(), wall.clone());
                Arc::new(move || Now {
                    mono_secs: mono.load(Ordering::SeqCst),
                    unix_secs: wall.load(Ordering::SeqCst),
                })
            },
        };
        shared.pause_for(300);
        wall.store(crate::BUILD_EPOCH + 365 * 86_400, Ordering::SeqCst);
        assert_eq!(shared.paused_left_secs(), Some(300));
        mono.store(40 + 299, Ordering::SeqCst);
        assert_eq!(shared.paused_left_secs(), Some(1));
        mono.store(40 + 300, Ordering::SeqCst);
        assert_eq!(shared.paused_left_secs(), None);
    }

    #[test]
    fn the_snapshot_is_what_the_resolver_counted() {
        let (shared, _) = shared(100);
        ask(&shared, "ads.example.com");
        ask(&shared, "example.org");
        let live = live(
            shared,
            status(true, Some(-61)),
            Extras {
                upstream_ms: Some(8),
                clock_set: true,
                list_names: Some(1),
                ..Extras::default()
            },
        );
        let s = live.snapshot();
        assert_eq!(
            s.today,
            Some(Counts {
                queries: 2,
                blocked: 1,
                blocked_threat: 0,
                cache_hits: 0,
                forwarded: 1
            })
        );
        assert_eq!(s.total, s.today);
        assert_eq!(s.last_blocked.unwrap().name, "ads.example.com");
        assert_eq!(
            (
                s.upstream_ms,
                s.wifi.unwrap().signal_dbm,
                s.clock_set,
                s.list_names
            ),
            (Some(8), Some(-61), true, Some(1))
        );
        assert_eq!(live.recent(1)[0].name.as_ref(), "example.org");
    }

    #[test]
    fn the_slot_hands_out_one_lane_from_the_start() {
        let slot = Slot::new();
        assert!(Arc::ptr_eq(&slot.lane(), &slot.lane()));
        let mut names = Vec::new();
        slot.lane().take(&mut names);
        assert!(names.is_empty());
    }

    #[test]
    fn the_slot_knows_nothing_until_the_resolver_is_up() {
        let slot = Slot::new();
        assert_eq!(slot.snapshot(), Snapshot::default());
        assert!(slot.recent(5).is_empty());
        slot.pause_for(300);
        assert_eq!(slot.paused_left_secs(), None);
        slot.resume();

        let (first, _) = shared(100);
        slot.fill(live(first.clone(), status(true, None), Extras::default()));
        slot.pause_for(300);
        assert_eq!(slot.paused_left_secs(), Some(300));
        assert_eq!(first.paused_left_secs(), Some(300));
        assert_eq!(slot.snapshot().today, Some(Counts::default()));

        // A second fill is ignored: the slot still answers from the first resolver.
        let (second, _) = shared(500);
        slot.fill(live(second.clone(), status(false, None), Extras::default()));
        slot.resume();
        assert_eq!(first.paused_left_secs(), None);
        slot.pause_for(60);
        assert_eq!(first.paused_left_secs(), Some(60));
        assert_eq!(second.paused_left_secs(), None);
        assert!(slot.snapshot().wifi.unwrap().associated);
    }

    /// An empty alert store, with a clock that stands still.
    fn alert_store() -> Arc<AlertStore> {
        Arc::new(AlertStore::new(Arc::new(|| (1000, 1_800_000_000))))
    }

    /// Raises a high alert about `subject` into `store`.
    fn raise_high(store: &AlertStore, subject: &str) {
        store.raise(Alert {
            kind: "threat",
            severity: Severity::High,
            client: None,
            subject: subject.to_string(),
        });
    }

    #[test]
    fn the_slot_has_no_alert_and_drops_an_ack_until_the_store_is_in_it() {
        let slot = Slot::new();
        assert!(slot.top().is_none());
        slot.ack(1);
        assert!(slot.top().is_none());

        // The store was raised into before it was put in the slot, and after: both are shown.
        let store = alert_store();
        raise_high(&store, "before.example");
        slot.fill_alerts(store.clone());
        assert_eq!(slot.top().unwrap().subject, "before.example");
        raise_high(&store, "after.example");
        assert_eq!(slot.top().unwrap().subject, "after.example");

        // An ack through the slot is the store's: the desktop's list shows it acknowledged.
        slot.ack(2);
        assert_eq!(slot.top().unwrap().subject, "before.example");
        assert!(store.list(0).alerts[1].acked);
        slot.ack(1);
        assert!(slot.top().is_none());
    }

    #[test]
    fn a_second_store_does_not_replace_the_slots_and_the_alerts_do_not_touch_the_resolver_slot() {
        let slot = Slot::new();
        let (first, second) = (alert_store(), alert_store());
        raise_high(&first, "first.example");
        raise_high(&second, "second.example");
        slot.fill_alerts(first);
        slot.fill_alerts(second);
        assert_eq!(slot.top().unwrap().subject, "first.example");
        // The resolver's half of the slot is still empty.
        assert_eq!(slot.snapshot(), Snapshot::default());
    }

    #[test]
    fn the_extras_are_what_the_dns_service_the_lists_and_the_clock_say() {
        let dns = Dns::new(
            BlockSetBuilder::new().build(),
            Upstreams::new(&[Ipv4Addr::LOCALHOST]),
            Box::new(FixedOffset(3600)),
        );
        let lists = Lists::new(ListState {
            source: ListSource::Snapshot,
            names: 1,
            fetched_unix_secs: None,
            last_error: None,
        });
        let (clock_set, synced) = watch::channel(false);
        assert_eq!(
            Extras::read(&dns, &lists, &synced),
            Extras {
                upstream_ms: None,
                utc_offset_secs: 3600,
                clock_set: false,
                list_names: Some(1),
                list_fetched_unix: None,
            }
        );
        lists.fetched(302_176, 1_800_000_000);
        clock_set.send_replace(true);
        assert_eq!(
            Extras::read(&dns, &lists, &synced),
            Extras {
                upstream_ms: None,
                utc_offset_secs: 3600,
                clock_set: true,
                list_names: Some(302_176),
                list_fetched_unix: Some(1_800_000_000),
            }
        );
    }

    #[test]
    fn the_signal_is_the_third_number_on_wlan0s_line() {
        let header = "Inter-| sta-|   Quality        |   Discarded packets               | Missed | WE\n \
                      face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22\n";
        let wlan0 =
            " wlan0: 0000   49.  -61.  -256        0      0      0      0      0        0\n";
        assert_eq!(proc_signal(&format!("{header}{wlan0}")), Some(-61));
        assert_eq!(proc_signal(header), None);
        let wlan1 = wlan0.replace("wlan0", "wlan1");
        assert_eq!(proc_signal(&format!("{header}{wlan1}")), None);
        // A line that is cut short, or a level that is no number, is no signal.
        assert_eq!(proc_signal("wlan0: 0000   49.\n"), None);
        assert_eq!(proc_signal("wlan0: 0000   49.  none.  -256\n"), None);
    }

    #[test]
    fn the_signal_cache_hands_back_what_was_stored_and_none_when_nothing_was() {
        let cache = SignalCache::new();
        assert_eq!(cache.get(), None, "a cache that was never filled");
        // Every figure an `i8` can say, the ends and zero among them, comes back as it went in.
        for dbm in [-61, 0, i8::MIN, i8::MAX, -1, 1] {
            cache.set(Some(dbm));
            assert_eq!(cache.get(), Some(dbm));
        }
        cache.set(None);
        assert_eq!(cache.get(), None);
        // The ends are signals, not the stand-in for none.
        cache.set(Some(i8::MIN));
        assert_eq!(cache.get(), Some(i8::MIN));
        // A clone of the handle sees the same value, as the component and its readers do.
        let reader = cache.clone();
        cache.set(Some(-42));
        assert_eq!(reader.get(), Some(-42));
    }

    #[test]
    fn the_link_shows_a_signal_and_an_access_point_only_while_joined() {
        let joined = wifi::WifiStatus::Joined {
            bssid: [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01],
            freq_mhz: 5180,
            signal_mbm: -5600,
        };
        assert_eq!(
            link_status(&joined, || Some(-55)),
            live::WifiStatus {
                associated: true,
                signal_dbm: Some(-55),
                ap: Some("00:00:5e:00:53:01".to_owned()),
                freq_mhz: Some(5180),
            }
        );
        // Without a live figure, the join's own is shown.
        assert_eq!(link_status(&joined, || None).signal_dbm, Some(-56));
        for not_joined in [
            wifi::WifiStatus::Scanning,
            wifi::WifiStatus::Joining {
                bssid: [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01],
                freq_mhz: 5180,
            },
            wifi::WifiStatus::Waiting { secs: 4 },
            wifi::WifiStatus::Starting,
        ] {
            let shown = link_status(&not_joined, || {
                panic!("the signal is read only when joined")
            });
            assert_eq!(shown, live::WifiStatus::default(), "{not_joined:?}");
        }
    }
}
