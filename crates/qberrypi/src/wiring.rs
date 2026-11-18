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
//! then the panel has no alert to show. The store is read through its own lock and no other. The
//! device inventory is held the same way ([`LiveDevices`]): its own lock, never the resolver's. The
//! owner's names are held the same way ([`LiveNames`]): the list's own lock, and the resolver's only for
//! a swap of the names or a copy of the top of the day.
//!
//! The board itself (the update machinery, the Wi-Fi's rejoin, the readings of SYSTEM) is the panel's through
//! [`LiveSystem`], which init puts in the slot as soon as it is made: it needs no resolver.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicI16, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use qb_dns::{ListClass, LogEntry, Now, OwnerSide, Resolver, TopName};
use tokio::sync::watch;
use zeroize::Zeroizing;

use crate::alerts::AlertSink;
use crate::dns::Dns;
use crate::dns::clients::MAX_CLIENTS;
use crate::lane::LaneFeed;
use crate::lists::Lists;
use crate::live::{self, BlockingControl, Snapshot, Source};
use crate::names::{DenyList, NamesError, OwnerEntry, OwnerHold, OwnerList};
use crate::panel::alerts::{PanelAlert, PendingAlerts};
use crate::panel::devices::{DeviceControl, Mac as PanelMac};
use crate::panel::lock::{Check, LockControl, LockView};
use crate::panel::names::{NameClass, NamesControl};
use crate::panel::system::{REJOIN_EVERY_SECS, RejoinWait, RestartRefused, SystemControl};
use crate::sys;
use crate::update::{self, UpdateCtl};
use crate::usage::Readings;
use crate::watch::devices::{Devices, EditError, WallCopy, with_devices};
use crate::watch::frames::Mac;
use crate::wifi::{self, RejoinSignal};

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
    pub(crate) fn lock(&self) -> crate::stall::Held<'_, Resolver> {
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

/// The device inventory as the panel uses it: its own lock, the resolver's table of who asked lately,
/// and the lane feed's watch of one client.
///
/// Nothing here takes the resolver's lock. Reads copy out and let go; an edit takes the inventory's
/// lock for the call, as the API's do, and raises the alerts it made after the lock is released.
pub struct LiveDevices {
    /// The inventory.
    pub devices: Arc<Mutex<Devices>>,
    /// Where the alerts an edit makes go.
    pub alerts: Arc<dyn AlertSink>,
    /// Who asked lately: `Dns::clients`, whose lock the query path already takes for one insert.
    pub dns: Arc<Dns>,
    /// The lane feed, which keeps the names of the one device that is watched.
    pub lane: Arc<LaneFeed>,
}

impl DeviceControl for LiveDevices {
    fn wall(&self, recent: &dyn Fn(u64) -> bool, out: &mut WallCopy) -> bool {
        // The inventory's lock is the one `devwatch` takes for each packet, on the thread that
        // answers DNS: it is held for the copy and no longer.
        self.devices
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .wall_copy(recent, out);
        true
    }

    fn asking(&self, window_secs: u64, out: &mut Vec<Ipv4Addr>) {
        let mono = self.dns.now().mono_secs;
        // The room for every client the table can hold is made before the lock is taken (it is made
        // once: `out` keeps it), so that the lock the question path takes for each query is held for
        // a walk over the few that asked within the window and a copy of their addresses: no
        // allocation, and no list of all 256.
        out.clear();
        out.reserve(MAX_CLIENTS);
        self.dns.clients().asking_within(mono, window_secs, out);
    }

    fn set_ads_pass(&self, mac: PanelMac, pass: bool) -> Result<(), EditError> {
        with_devices(&self.devices, &*self.alerts, |devices| {
            devices.set_ads_pass(Mac(mac), pass)
        })
    }

    fn device_gate(&self, mac: PanelMac, secs: u16) -> Result<(), EditError> {
        with_devices(&self.devices, &*self.alerts, |devices| {
            devices.open_gate(Mac(mac), secs)
        })
    }

    fn watch_client(&self, client: Option<Ipv4Addr>) {
        self.lane.watch_client(client);
    }

    fn watched_names(&self, out: &mut Vec<crate::lane::WatchedName>) {
        self.lane.watched_names(out);
    }
}

/// The owner's names as the panel uses them: the owner's list, which the API edits too, and the
/// resolver the list is swapped into.
///
/// Reads copy out and let go; `top_today` and `class` take the resolver's lock for one copy or one
/// lookup, and the rest is the list's own lock. An edit builds the new names off the resolver's lock and
/// swaps them in under it (`OwnerList`), and moves the list's revision, as the API's edit does.
pub struct LiveNames {
    /// The owner's list.
    pub list: Arc<OwnerList>,
    /// The resolver, for the top of the day and for the block set.
    pub resolver: SharedResolver,
    /// The configuration's `dns.deny`, which the block set cannot tell from an ads list.
    pub deny: DenyList,
    /// Whether the clock has been set to the real time: an entry keeps the day it was set on only
    /// then.
    pub clock_set: Arc<dyn Fn() -> bool + Send + Sync>,
}

impl NamesControl for LiveNames {
    fn top_today(&self) -> Vec<TopName> {
        self.list.top_today()
    }

    fn owner_len(&self) -> usize {
        self.list.len()
    }

    fn owner_newest(&self, n: usize) -> Vec<OwnerEntry> {
        self.list.newest(n)
    }

    fn owner_hold(&self, name: &str) -> Option<OwnerHold> {
        self.list.hold(name)
    }

    fn class(&self, name: &str) -> NameClass {
        // The guard is gone at the end of the statement.
        let class = self.resolver.lock().list_class(name);
        match class {
            Some(ListClass::Threat) => NameClass::Threat,
            // The block set holds a `deny` entry as an ad; the configuration says which it is.
            Some(ListClass::Ads) if self.deny.covers(name) => NameClass::Deny,
            Some(ListClass::Ads) => NameClass::Ads,
            None => NameClass::None,
        }
    }

    fn set(&self, name: &str, verdict: OwnerSide) -> Result<(), NamesError> {
        // The resolver would not let such a name through, so the list does not pretend it does.
        if verdict == OwnerSide::Allow && self.class(name) == NameClass::Threat {
            return Err(NamesError::Threat);
        }
        let day = (self.clock_set)().then(|| (self.resolver.now)().unix_secs);
        self.list.set(name, verdict, day)
    }

    fn forget(&self, name: &str) -> Result<bool, NamesError> {
        self.list.forget(name)
    }
}

/// The board itself as the panel uses it: the update machinery, which a restart and the update screens ask,
/// and the Wi-Fi's rejoin, with its refusal of a second within a minute.
///
/// Nothing here takes the resolver's lock or any lock of the answer path: the update machinery's own small
/// lock is taken for a copy or a look, and a rejoin is a notify and a count.
pub struct LiveSystem {
    /// The update machinery: its view, and the owner's restart.
    update: Arc<UpdateCtl>,
    /// What `wifi::run` is given: asked to end the link that is held and join again, and saying whether one was.
    rejoin: Arc<RejoinSignal>,
    /// When the last rejoin that let a held link go was asked for, on `clock`.
    last_rejoin: Mutex<Option<Duration>>,
    /// A clock that does not jump, from any starting point: the kernel's, or a test's own.
    clock: Box<dyn Fn() -> Duration + Send + Sync>,
}

impl LiveSystem {
    /// The control of the board over `update` and the signal `rejoin` that the Wi-Fi component listens to, on
    /// the kernel's monotonic clock.
    pub fn new(update: Arc<UpdateCtl>, rejoin: Arc<RejoinSignal>) -> Self {
        Self::with_clock(update, rejoin, sys::uptime)
    }

    /// As `new`, with the time of `clock`, so that a test moves it.
    pub fn with_clock(
        update: Arc<UpdateCtl>,
        rejoin: Arc<RejoinSignal>,
        clock: impl Fn() -> Duration + Send + Sync + 'static,
    ) -> Self {
        Self {
            update,
            rejoin,
            last_rejoin: Mutex::new(None),
            clock: Box::new(clock),
        }
    }
}

impl LiveSystem {
    /// The rejoin of [`SystemControl::rejoin`] that the update machinery has let through: the limit of
    /// one a minute, the Wi-Fi's wake, and the second it was asked at when it let a held link go.
    ///
    /// Only a rejoin that let a link go starts the minute. One that finds no link held ends nothing (a join is
    /// under way or about to be, and is not repeated), so it is charged nothing and the next is let through.
    fn rejoin_now(&self) -> Result<(), RejoinWait> {
        let now = (self.clock)();
        let mut last = self
            .last_rejoin
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(at) = *last {
            let wait = Duration::from_secs(u64::from(REJOIN_EVERY_SECS))
                .saturating_sub(now.saturating_sub(at));
            if !wait.is_zero() {
                // At most the minute, so a `u16` holds it; counted up, so that 0 is never what is left.
                let left = wait.as_secs() + u64::from(wait.subsec_nanos() > 0);
                return Err(RejoinWait(u16::try_from(left).unwrap_or(REJOIN_EVERY_SECS)));
            }
        }
        // Only a loop that is holding a link hears it: a join that is under way is not repeated. The lock is
        // kept over the ask, so that the minute is charged in the same step as the link is let go.
        if self.rejoin.ask() {
            *last = Some(now);
        }
        Ok(())
    }
}

impl SystemControl for LiveSystem {
    /// Refused as a wait of the whole minute, and charged to nobody, while an update is received or staged
    /// or this boot is on trial, as a restart is: the link that carries the update is not let go of. The
    /// look at the update machinery and the wake are one step. (The panel's key is inert then, but the
    /// refusal is here, in the one place that knows.)
    fn rejoin(&self) -> Result<(), RejoinWait> {
        self.update
            .when_idle(|| self.rejoin_now())
            .unwrap_or(Err(RejoinWait(REJOIN_EVERY_SECS)))
    }

    fn restart(&self) -> Result<(), RestartRefused> {
        self.update.request_owner_restart().map_err(Into::into)
    }

    fn update_view(&self) -> update::View {
        self.update.view()
    }

    fn readings(&self) -> Readings {
        Readings::read()
    }
}

/// What the panel is given, in the place of the [`Live`] that is made beside it.
///
/// Until it is filled it answers as [`live::Nothing`] does, and the switch does nothing, with a
/// line in the log. The panel's thread reads it, and the first service to start fills it, once.
///
/// It is the panel's source of alerts too ([`PendingAlerts`]): there is none until
/// [`Slot::fill_alerts`] puts the watchdog's store in, and an acknowledgement before that is
/// dropped without a line, since it names an alert that cannot have been shown. And it is the
/// panel's control of the devices ([`DeviceControl`]): no inventory until [`Slot::fill_devices`], but
/// the watch of one device's names is the lane feed's, which the slot holds from the start. And it is
/// the panel's control of the owner's names ([`NamesControl`]): none is on any list, the top of the day is
/// empty and an edit is refused until [`Slot::fill_names`]. And it is the panel's control of the board itself
/// ([`SystemControl`]): the Wi-Fi's rejoin signal is the slot's own, from the start; until
/// [`Slot::fill_system`] a restart is refused, a rejoin must wait, and the update machinery looks idle.
/// And the panel's lock and night hours ([`LockControl`]): no night, and until [`Slot::fill_lock`] a lock that
/// fails closed (the strong keys ask for a PIN that nothing accepts).
pub struct Slot {
    live: OnceLock<Live>,
    /// The watchdog's alerts, as the panel reads them; filled by the same service as `live`.
    alerts: OnceLock<Arc<dyn PendingAlerts>>,
    /// The device inventory, as the panel reads and edits it; filled by the same service.
    devices: OnceLock<Arc<dyn DeviceControl>>,
    /// The owner's names, as the panel reads and edits them; filled by the same service.
    names: OnceLock<Arc<dyn NamesControl>>,
    /// The board itself, as the panel reads and acts on it; filled by init.
    system: OnceLock<Arc<dyn SystemControl>>,
    /// What the Wi-Fi component waits on for the owner's rejoin. It is the slot's, not the control's: the
    /// component holds it from its start, before the control is made.
    rejoin: Arc<RejoinSignal>,
    /// The lock and the night hours, as the panel reads and edits them; filled by the same service.
    lock: OnceLock<Arc<dyn LockControl>>,
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
            devices: OnceLock::new(),
            names: OnceLock::new(),
            system: OnceLock::new(),
            rejoin: Arc::new(RejoinSignal::new()),
            lock: OnceLock::new(),
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

    /// Puts the panel's control of the devices in the slot; a slot that has one keeps it.
    pub fn fill_devices(&self, devices: Arc<dyn DeviceControl>) {
        // As in `fill`: the first stays.
        let _ = self.devices.set(devices);
    }

    /// Puts the panel's control of the owner's names in the slot; a slot that has one keeps it.
    pub fn fill_names(&self, names: Arc<dyn NamesControl>) {
        // As in `fill`: the first stays.
        let _ = self.names.set(names);
    }

    /// Puts the panel's control of the board itself in the slot; a slot that has one keeps it.
    pub fn fill_system(&self, system: Arc<dyn SystemControl>) {
        // As in `fill`: the first stays.
        let _ = self.system.set(system);
    }

    /// What the Wi-Fi component gives `wifi::run`, and the panel's rejoin asks.
    pub fn rejoin_signal(&self) -> Arc<RejoinSignal> {
        self.rejoin.clone()
    }

    /// Puts the panel's control of the lock and the night hours in the slot; a slot that has one keeps it.
    pub fn fill_lock(&self, lock: Arc<dyn LockControl>) {
        // As in `fill`: the first stays.
        let _ = self.lock.set(lock);
    }
}

impl DeviceControl for Slot {
    fn wall(&self, recent: &dyn Fn(u64) -> bool, out: &mut WallCopy) -> bool {
        self.devices
            .get()
            .is_some_and(|devices| devices.wall(recent, out))
    }

    fn asking(&self, window_secs: u64, out: &mut Vec<Ipv4Addr>) {
        match self.devices.get() {
            Some(devices) => devices.asking(window_secs, out),
            None => out.clear(),
        }
    }

    fn set_ads_pass(&self, mac: PanelMac, pass: bool) -> Result<(), EditError> {
        self.devices
            .get()
            .map_or(Err(EditError::Unknown), |devices| {
                devices.set_ads_pass(mac, pass)
            })
    }

    fn device_gate(&self, mac: PanelMac, secs: u16) -> Result<(), EditError> {
        self.devices
            .get()
            .map_or(Err(EditError::Unknown), |devices| {
                devices.device_gate(mac, secs)
            })
    }

    // The watch is the lane feed's own, which the slot holds from the start: a device whose screen
    // opens before the inventory exists is watched all the same.
    fn watch_client(&self, client: Option<Ipv4Addr>) {
        self.lane.watch_client(client);
    }

    fn watched_names(&self, out: &mut Vec<crate::lane::WatchedName>) {
        self.lane.watched_names(out);
    }
}

impl PendingAlerts for Slot {
    fn top(&self) -> Option<PanelAlert> {
        self.alerts.get()?.top()
    }

    fn waiting_count(&self) -> u32 {
        self.alerts.get().map_or(0, |alerts| alerts.waiting_count())
    }

    fn waiting(&self, n: usize) -> Vec<PanelAlert> {
        self.alerts
            .get()
            .map_or_else(Vec::new, |alerts| alerts.waiting(n))
    }

    fn last_alert_unix(&self) -> Option<u64> {
        self.alerts.get()?.last_alert_unix()
    }

    fn ack(&self, id: u64) {
        if let Some(alerts) = self.alerts.get() {
            alerts.ack(id);
        }
    }
}

impl NamesControl for Slot {
    fn top_today(&self) -> Vec<TopName> {
        self.names
            .get()
            .map_or_else(Vec::new, |names| names.top_today())
    }

    fn owner_len(&self) -> usize {
        self.names.get().map_or(0, |names| names.owner_len())
    }

    fn owner_newest(&self, n: usize) -> Vec<OwnerEntry> {
        self.names
            .get()
            .map_or_else(Vec::new, |names| names.owner_newest(n))
    }

    fn owner_hold(&self, name: &str) -> Option<OwnerHold> {
        self.names.get()?.owner_hold(name)
    }

    fn class(&self, name: &str) -> NameClass {
        self.names
            .get()
            .map_or(NameClass::None, |names| names.class(name))
    }

    fn set(&self, name: &str, verdict: OwnerSide) -> Result<(), NamesError> {
        self.names
            .get()
            .map_or(Err(NamesError::Unavailable), |names| {
                names.set(name, verdict)
            })
    }

    fn forget(&self, name: &str) -> Result<bool, NamesError> {
        self.names
            .get()
            .map_or(Err(NamesError::Unavailable), |names| names.forget(name))
    }
}

impl SystemControl for Slot {
    fn rejoin(&self) -> Result<(), RejoinWait> {
        self.system
            .get()
            .map_or(Err(RejoinWait(1)), |system| system.rejoin())
    }

    fn restart(&self) -> Result<(), RestartRefused> {
        self.system
            .get()
            .map_or(Err(RestartRefused::NotReady), |system| system.restart())
    }

    fn update_view(&self) -> update::View {
        self.system
            .get()
            .map_or_else(|| UpdateCtl::off().view(), |system| system.update_view())
    }

    fn readings(&self) -> Readings {
        self.system
            .get()
            .map_or_else(Readings::read, |system| system.readings())
    }
}

// Until the lock is filled the slot fails closed: whether a PIN guards the strong keys is not known, so they
// ask as if one did, and nothing passes (`verify` makes the pad wait, counting nothing). The services fill
// the lock as they make the resolver's half of the slot, before DNS answers and so before STARTING ends; the
// state in between is only a board whose services never came up. No night is set.
impl LockControl for Slot {
    fn verify(&self, digits: Zeroizing<[u8; 4]>) -> Check {
        self.lock
            .get()
            .map_or(Check::Wait(UNFILLED_WAIT_SECS), |lock| lock.verify(digits))
    }

    fn wait_left(&self) -> u32 {
        self.lock
            .get()
            .map_or(UNFILLED_WAIT_SECS, |lock| lock.wait_left())
    }

    fn set_pin(&self, digits: Zeroizing<[u8; 4]>) -> bool {
        self.lock.get().is_some_and(|lock| lock.set_pin(digits))
    }

    fn clear_pin(&self) {
        if let Some(lock) = self.lock.get() {
            lock.clear_pin();
        }
    }

    fn lock_view(&self) -> LockView {
        self.lock.get().map_or(
            LockView {
                on: true,
                source: None,
                kept: false,
            },
            |lock| lock.lock_view(),
        )
    }

    fn night(&self) -> Option<(u8, u8)> {
        self.lock.get()?.night()
    }

    fn set_night(&self, night: Option<(u8, u8)>) {
        if let Some(lock) = self.lock.get() {
            lock.set_night(night);
        }
    }
}

/// The seconds that the pad waits while the lock is not filled yet: a check that is refused for a second, again
const UNFILLED_WAIT_SECS: u32 = 1;

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
/// is the one the join found, copied out of the status: nothing is asked of the radio for it. So is the
/// monotonic second the link came up on, which a link that is down has none of.
pub fn link_status(
    status: &wifi::WifiStatus,
    signal: impl FnOnce() -> Option<i8>,
) -> live::WifiStatus {
    match status {
        wifi::WifiStatus::Joined {
            bssid,
            freq_mhz,
            signal_mbm,
            since_secs,
        } => live::WifiStatus {
            associated: true,
            signal_dbm: signal().or_else(|| Some(held(wifi::dbm(*signal_mbm)))),
            ap: Some(wifi::mac(bssid)),
            freq_mhz: Some(*freq_mhz),
            joined_secs: Some(*since_secs),
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

    use std::net::IpAddr;
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
            joined_secs: None,
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
        assert!(slot.waiting(3).is_empty());
        assert_eq!(slot.last_alert_unix(), None);

        // The store was raised into before it was put in the slot, and after: both are shown.
        let store = alert_store();
        raise_high(&store, "before.example");
        slot.fill_alerts(store.clone());
        assert_eq!(slot.top().unwrap().subject, "before.example");
        raise_high(&store, "after.example");
        assert_eq!(slot.top().unwrap().subject, "after.example");

        // An ack through the slot is the store's: the desktop's list shows it acknowledged.
        assert_eq!(slot.waiting_count(), 2);
        let waiting = slot.waiting(5);
        assert_eq!(
            waiting
                .iter()
                .map(|a| a.subject.as_str())
                .collect::<Vec<_>>(),
            ["after.example", "before.example"]
        );
        assert_eq!(slot.last_alert_unix(), Some(1_800_000_000));
        slot.ack(2);
        assert_eq!(slot.top().unwrap().subject, "before.example");
        assert_eq!(slot.waiting_count(), 1);
        assert!(store.list(0).alerts[1].acked);
        slot.ack(1);
        assert!(slot.top().is_none());
        assert_eq!(slot.waiting_count(), 0);
    }

    /// A device inventory with one device, `192.0.2.5` at `02:00:00:00:00:05`, behind a router at
    /// `192.0.2.1`, on a clock that stands still at monotonic second 1,000; the resolver's own clients
    /// table and the lane's feed beside it.
    fn live_devices() -> (LiveDevices, Arc<Dns>) {
        use crate::watch::frames::{ARP_REQUEST, Arp};
        let dns = Dns::new(
            BlockSetBuilder::new().build(),
            Upstreams::new(&[Ipv4Addr::LOCALHOST]),
            Box::new(FixedOffset(0)),
        );
        let clock: Arc<dyn Fn() -> (u64, u64) + Send + Sync> = Arc::new(|| (1_000, 1_800_000_000));
        let mut devices = Devices::new(None, Ipv4Addr::new(192, 0, 2, 1), clock);
        devices.on_arp(&Arp {
            op: ARP_REQUEST,
            sender_mac: Mac([2, 0, 0, 0, 0, 5]),
            sender_ip: Ipv4Addr::new(192, 0, 2, 5),
            target_ip: Ipv4Addr::new(192, 0, 2, 5),
        });
        (
            LiveDevices {
                devices: Arc::new(Mutex::new(devices)),
                alerts: alert_store(),
                dns: dns.clone(),
                lane: LaneFeed::new(),
            },
            dns,
        )
    }

    /// What the panel copies of the inventory behind `devices`: its one device, as `(exempt, gate)`.
    fn wall_row(devices: &dyn DeviceControl) -> (bool, Option<u16>) {
        let mut copy = WallCopy::new();
        assert!(devices.wall(&|_| true, &mut copy), "the inventory");
        assert_eq!(copy.rows.len(), 1);
        (copy.rows[0].exempt, copy.rows[0].gate_left_secs)
    }

    #[test]
    fn the_panels_devices_are_the_inventory_read_and_edited_under_its_own_lock() {
        let (devices, _) = live_devices();
        let mac = [2, 0, 0, 0, 0, 5];
        let rev = || devices.devices.lock().unwrap().rev();
        assert_eq!(wall_row(&devices), (false, None));
        let first = rev();

        // Ads pass for the device, for good; and the revision moves, as it does for the API's edit.
        devices.set_ads_pass(mac, true).unwrap();
        assert_eq!(wall_row(&devices), (true, None));
        assert!(rev() > first);
        devices.set_ads_pass(mac, false).unwrap();
        assert_eq!(wall_row(&devices), (false, None));

        // Its own gate: open for five minutes, then shut.
        devices.device_gate(mac, 300).unwrap();
        assert_eq!(wall_row(&devices), (true, Some(300)));
        devices.device_gate(mac, 0).unwrap();
        assert_eq!(wall_row(&devices), (false, None));

        // A gate for a device the inventory does not hold, and one longer than an hour, are refused.
        assert_eq!(
            devices.device_gate([2, 0, 0, 0, 0, 9], 300),
            Err(EditError::Unknown)
        );
        assert_eq!(devices.device_gate(mac, 3_601), Err(EditError::Invalid));
        // An address that is no device's is refused.
        assert_eq!(devices.set_ads_pass([0; 6], true), Err(EditError::Invalid));
    }

    #[test]
    fn the_panel_asks_who_asked_lately_of_the_resolvers_clients_table() {
        let (devices, dns) = live_devices();
        let mut asking = vec![Ipv4Addr::LOCALHOST];
        devices.asking(2, &mut asking);
        assert!(asking.is_empty(), "nobody asked yet: {asking:?}");
        dns.note_client(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)));
        // The Pi's own queries are no device's.
        dns.note_client(IpAddr::V4(Ipv4Addr::LOCALHOST));
        devices.asking(2, &mut asking);
        assert_eq!(asking, [Ipv4Addr::new(192, 0, 2, 5)]);
        // A window of nothing holds nobody.
        devices.asking(0, &mut asking);
        assert!(asking.is_empty());
        // The room for the whole table was made once, outside the table's lock, and is kept: the
        // next ask allocates nothing.
        let room = asking.capacity();
        assert!(room >= MAX_CLIENTS);
        devices.asking(2, &mut asking);
        assert_eq!((asking.len(), asking.capacity()), (1, room));
    }

    #[test]
    fn the_slot_has_no_devices_until_the_inventory_is_in_it_but_watches_a_device_all_the_same() {
        let slot = Slot::new();
        let mac = [2, 0, 0, 0, 0, 5];
        let mut copy = WallCopy::new();
        assert!(!slot.wall(&|_| true, &mut copy));
        assert_eq!(slot.set_ads_pass(mac, true), Err(EditError::Unknown));
        assert_eq!(slot.device_gate(mac, 300), Err(EditError::Unknown));
        let mut asking = vec![Ipv4Addr::LOCALHOST];
        slot.asking(2, &mut asking);
        assert!(asking.is_empty());
        // The watch is the lane feed's own, which the slot holds from the start.
        slot.watch_client(Some(Ipv4Addr::new(192, 0, 2, 5)));
        let mut names = Vec::new();
        slot.watched_names(&mut names);
        assert!(names.is_empty());
        slot.watch_client(None);

        let (devices, _) = live_devices();
        let devices: Arc<dyn DeviceControl> = Arc::new(devices);
        slot.fill_devices(devices.clone());
        assert!(slot.wall(&|_| true, &mut copy));
        assert_eq!(copy.rows.len(), 1);
        slot.set_ads_pass(mac, true).unwrap();
        assert!(wall_row(&*devices).0);
        slot.device_gate(mac, 60).unwrap();
        assert_eq!(wall_row(&*devices).1, Some(60));
        // A second inventory does not replace the first.
        let (other, _) = live_devices();
        slot.fill_devices(Arc::new(other));
        assert!(wall_row(&*slot).0);
    }

    /// The names the tests of the owner's names use: a resolver that blocks `ads.example.com`, the
    /// configuration's `denied.example.org` and the threat `evil.example.net`, on a clock that stands
    /// still at second 100 of the wall time 1,800,000,100.
    fn names_resolver() -> SharedResolver {
        let mut builder = BlockSetBuilder::new();
        builder.add_list(b"0.0.0.0 ads.example.com\n");
        builder.deny("denied.example.org").unwrap();
        builder.add_list_as(b"0.0.0.0 evil.example.net\n", qb_dns::ListClass::Threat);
        SharedResolver {
            resolver: Arc::new(Mutex::new(Resolver::new(builder.build()))),
            now: Arc::new(|| Now {
                mono_secs: 100,
                unix_secs: 1_800_000_100,
            }),
        }
    }

    /// The panel's control of the owner's names over `resolver`, with the clock set or not.
    fn live_names(resolver: &SharedResolver, clock_set: bool) -> LiveNames {
        LiveNames {
            list: Arc::new(OwnerList::new(resolver.clone()).starting_at(0)),
            resolver: resolver.clone(),
            deny: DenyList::new(&["Denied.Example.org".to_owned()]),
            clock_set: Arc::new(move || clock_set),
        }
    }

    #[test]
    fn the_panel_tells_which_list_blocks_a_name_and_a_deny_entry_from_an_ad() {
        let resolver = names_resolver();
        let names = live_names(&resolver, true);
        for (name, class) in [
            ("ads.example.com", NameClass::Ads),
            ("sub.ads.example.com", NameClass::None),
            ("denied.example.org", NameClass::Deny),
            ("deep.Denied.Example.org.", NameClass::Deny),
            ("evil.example.net", NameClass::Threat),
            ("clean.example.org", NameClass::None),
            ("not a name", NameClass::None),
        ] {
            assert_eq!(names.class(name), class, "{name:?}");
        }
        // The owner's entries are no class: what the lists say is what they say.
        names.set("ads.example.com", OwnerSide::Allow).unwrap();
        names.set("clean.example.org", OwnerSide::Refuse).unwrap();
        assert_eq!(names.class("ads.example.com"), NameClass::Ads);
        assert_eq!(names.class("clean.example.org"), NameClass::None);
    }

    #[test]
    fn the_panel_edits_the_list_the_resolver_decides_from_and_keeps_the_day_of_the_tap() {
        let resolver = names_resolver();
        let names = live_names(&resolver, true);
        assert_eq!(
            (names.owner_len(), names.owner_hold("a.example.org")),
            (0, None)
        );

        names.set("New.Example.org", OwnerSide::Refuse).unwrap();
        names.set("ads.example.com", OwnerSide::Allow).unwrap();
        assert_eq!(names.owner_len(), 2);
        assert_eq!(names.list.rev(), 2);
        // In force at once, in the resolver the DNS task answers from.
        assert!(matches!(
            ask(&resolver, "new.example.org"),
            Action::Reply(_)
        ));
        assert!(matches!(
            ask(&resolver, "ads.example.com"),
            Action::Forward(_)
        ));
        let newest = names.owner_newest(3);
        assert_eq!(
            newest
                .iter()
                .map(|entry| (&*entry.name, entry.side, entry.set_unix))
                .collect::<Vec<_>>(),
            [
                ("ads.example.com", OwnerSide::Allow, Some(1_800_000_100)),
                ("new.example.org", OwnerSide::Refuse, Some(1_800_000_100)),
            ]
        );
        let hold = names.owner_hold("sub.new.example.org").unwrap();
        assert_eq!((hold.side, hold.exact), (OwnerSide::Refuse, false));
        let hold = names.owner_hold("new.example.org").unwrap();
        assert_eq!((hold.side, hold.exact), (OwnerSide::Refuse, true));

        // `ANSWER AGAIN` and `REFUSE AGAIN` take the entry back.
        assert_eq!(names.forget("new.example.org"), Ok(true));
        assert_eq!(names.forget("new.example.org"), Ok(false));
        assert_eq!(names.forget("ads.example.com"), Ok(true));
        assert!(matches!(
            ask(&resolver, "new.example.org"),
            Action::Forward(_)
        ));
        assert!(matches!(
            ask(&resolver, "ads.example.com"),
            Action::Reply(_)
        ));
        assert_eq!(names.owner_len(), 0);
        assert_eq!(
            names.set("not a name", OwnerSide::Refuse),
            Err(NamesError::Invalid)
        );
    }

    #[test]
    fn the_panel_never_allows_a_threat_and_keeps_no_day_before_the_clock_is_set() {
        let resolver = names_resolver();
        let names = live_names(&resolver, false);
        assert_eq!(
            names.set("evil.example.net", OwnerSide::Allow),
            Err(NamesError::Threat)
        );
        assert_eq!((names.owner_len(), names.list.rev()), (0, 0));
        assert!(matches!(
            ask(&resolver, "evil.example.net"),
            Action::Reply(_)
        ));
        // Refusing a threat is no harm, and an entry set before the clock was has no day.
        names.set("evil.example.net", OwnerSide::Refuse).unwrap();
        names.set("ads.example.com", OwnerSide::Allow).unwrap();
        assert!(
            names
                .owner_newest(2)
                .iter()
                .all(|entry| entry.set_unix.is_none())
        );
    }

    #[test]
    fn the_top_of_the_day_is_the_resolvers_and_a_copy() {
        let resolver = names_resolver();
        let names = live_names(&resolver, true);
        assert!(names.top_today().is_empty());
        for name in ["ads.example.com", "denied.example.org", "ads.example.com"] {
            assert!(matches!(ask(&resolver, name), Action::Reply(_)));
        }
        let top = names.top_today();
        assert_eq!(
            top.iter().map(|t| (&*t.name, t.count)).collect::<Vec<_>>(),
            [("ads.example.com", 2), ("denied.example.org", 1)]
        );
    }

    #[test]
    fn the_slot_has_no_names_until_they_are_in_it_and_keeps_the_first() {
        let slot = Slot::new();
        assert!(slot.top_today().is_empty());
        assert_eq!(
            (slot.owner_len(), slot.owner_hold("a.example.org")),
            (0, None)
        );
        assert!(slot.owner_newest(3).is_empty());
        assert_eq!(slot.class("ads.example.com"), NameClass::None);
        assert_eq!(
            slot.set("a.example.org", OwnerSide::Refuse),
            Err(NamesError::Unavailable)
        );
        assert_eq!(slot.forget("a.example.org"), Err(NamesError::Unavailable));

        let resolver = names_resolver();
        slot.fill_names(Arc::new(live_names(&resolver, true)));
        slot.set("a.example.org", OwnerSide::Refuse).unwrap();
        assert_eq!(slot.owner_len(), 1);
        assert_eq!(slot.class("ads.example.com"), NameClass::Ads);
        assert!(matches!(ask(&resolver, "a.example.org"), Action::Reply(_)));

        // A second control does not replace the slot's.
        slot.fill_names(Arc::new(live_names(&names_resolver(), true)));
        assert_eq!(slot.owner_len(), 1);
        assert_eq!(slot.forget("a.example.org"), Ok(true));
    }

    #[test]
    fn the_slot_fails_closed_and_has_no_night_until_the_state_is_in_it_and_keeps_the_first() {
        use crate::panel::lock::{PanelState, Source as PinSource};

        let pin = |digits: &[u8; 4]| {
            crate::api::password::PasswordHash::with_rounds(
                digits,
                [2; 16],
                crate::api::password::PIN_ROUNDS,
            )
        };
        let slot = Slot::new();
        // Nothing is filled: the lock fails closed. The strong keys ask (the lock reads as on), no PIN passes and
        // none is counted wrong, no night is on, and an edit goes nowhere.
        assert_eq!(slot.verify(Zeroizing::new([1, 2, 3, 4])), Check::Wait(1));
        assert_eq!(slot.verify(Zeroizing::new([4, 3, 2, 1])), Check::Wait(1));
        assert_eq!(
            slot.lock_view(),
            LockView {
                on: true,
                source: None,
                kept: false
            }
        );
        assert_eq!((slot.night(), slot.wait_left()), (None, 1));
        assert!(!slot.set_pin(Zeroizing::new([1, 2, 3, 4])));
        slot.set_night(Some((22, 6)));
        slot.clear_pin();
        assert_eq!(slot.night(), None);

        let state = Arc::new(PanelState::new(
            Some(pin(b"1234")),
            Some((23, 7)),
            Arc::new(|| 0),
        ));
        slot.fill_lock(state.clone());
        assert_eq!(slot.night(), Some((23, 7)));
        assert_eq!(slot.lock_view().source, Some(PinSource::Config));
        assert_eq!(slot.verify(Zeroizing::new([1, 2, 3, 4])), Check::Right);
        assert_eq!(slot.verify(Zeroizing::new([4, 3, 2, 1])), Check::Wrong);
        // The edits of the panel and of the API are the one state's.
        slot.set_night(Some((22, 6)));
        assert_eq!(state.night(), Some((22, 6)));
        state.lock().set_hash(None, PinSource::Api);
        assert!(!slot.lock_view().on);
        assert!(slot.set_pin(Zeroizing::new([5, 6, 7, 8])));
        assert_eq!(slot.lock_view().source, Some(PinSource::Panel));
        assert_eq!(state.verify(Zeroizing::new([5, 6, 7, 8])), Check::Right);

        // A second state does not replace the slot's.
        slot.fill_lock(Arc::new(PanelState::new(None, None, Arc::new(|| 0))));
        assert!(slot.lock_view().on);
        assert_eq!(slot.night(), Some((22, 6)));
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
            since_secs: 4_000,
        };
        assert_eq!(
            link_status(&joined, || Some(-55)),
            live::WifiStatus {
                associated: true,
                signal_dbm: Some(-55),
                ap: Some("00:00:5e:00:53:01".to_owned()),
                freq_mhz: Some(5180),
                joined_secs: Some(4_000),
            }
        );
        // How long it has held is counted from the second it came up on, and never below nothing.
        let shown = link_status(&joined, || None);
        assert_eq!(shown.linked_secs(4_000 + 12 * 86_400), Some(12 * 86_400));
        assert_eq!(shown.linked_secs(3_999), Some(0));
        assert_eq!(live::WifiStatus::default().linked_secs(5_000), None);
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
    /// A control of the board whose clock is `ms` milliseconds on a counter that the test moves, over
    /// `ctl`, with the Wi-Fi's signal.
    fn system_on(ctl: &Arc<UpdateCtl>, ms: &Arc<AtomicU64>) -> (LiveSystem, Arc<RejoinSignal>) {
        let notify = Arc::new(RejoinSignal::new());
        let clock = {
            let ms = ms.clone();
            move || Duration::from_millis(ms.load(Ordering::SeqCst))
        };
        (
            LiveSystem::with_clock(ctl.clone(), notify.clone(), clock),
            notify,
        )
    }

    /// Whether a hold that listens hears the owner within a moment: one that listened before the call under
    /// test hears it.
    async fn heard(waiting: &mut wifi::join::Listening<'_>) -> bool {
        tokio::time::timeout(Duration::from_millis(50), waiting)
            .await
            .is_ok()
    }

    #[tokio::test(start_paused = true)]
    async fn a_rejoin_wakes_the_wifi_and_a_second_within_a_minute_is_refused_with_the_time_left() {
        let ms = Arc::new(AtomicU64::new(1_000_000));
        let (system, notify) = system_on(&UpdateCtl::off(), &ms);

        let mut waiting = notify.listen();
        assert_eq!(system.rejoin(), Ok(()));
        assert!(
            heard(&mut waiting).await,
            "the Wi-Fi did not hear the rejoin"
        );

        // At once, the whole minute is left; the refusal wakes nobody.
        let mut waiting = notify.listen();
        assert_eq!(system.rejoin(), Err(RejoinWait(60)));
        // 1.5 s later 58.5 s are left, counted up; the last second of the minute says 1.
        ms.fetch_add(1_500, Ordering::SeqCst);
        assert_eq!(system.rejoin(), Err(RejoinWait(59)));
        ms.fetch_add(58_499, Ordering::SeqCst);
        assert_eq!(system.rejoin(), Err(RejoinWait(1)));
        assert!(
            !heard(&mut waiting).await,
            "a refused rejoin woke the Wi-Fi"
        );

        // A minute after the one that was let through, the next is.
        ms.fetch_add(1, Ordering::SeqCst);
        let mut waiting = notify.listen();
        assert_eq!(system.rejoin(), Ok(()));
        assert!(heard(&mut waiting).await);
        // And the minute counts from that one.
        assert_eq!(system.rejoin(), Err(RejoinWait(60)));
    }

    #[tokio::test(start_paused = true)]
    async fn a_rejoin_is_refused_while_an_update_is_received_or_on_trial_and_is_not_charged() {
        let ms = Arc::new(AtomicU64::new(1_000_000));
        let ctl = UpdateCtl::new(Some(crate::slots::Slot::A), None, Arc::new(update::NoCard));
        let (system, notify) = system_on(&ctl, &ms);

        // While an update is received the whole minute is the answer, and the Wi-Fi hears nothing.
        let mut waiting = notify.listen();
        let receiving = ctl.begin_receive().unwrap();
        assert_eq!(system.rejoin(), Err(RejoinWait(REJOIN_EVERY_SECS)));
        ms.fetch_add(120_000, Ordering::SeqCst);
        assert_eq!(system.rejoin(), Err(RejoinWait(REJOIN_EVERY_SECS)));
        assert!(
            !heard(&mut waiting).await,
            "a refused rejoin woke the Wi-Fi"
        );
        // A staged update still waits for its restart.
        receiving.staged();
        assert_eq!(system.rejoin(), Err(RejoinWait(REJOIN_EVERY_SECS)));

        // The refusals charged no minute: the first rejoin after the update is let through at once.
        let idle = UpdateCtl::new(Some(crate::slots::Slot::A), None, Arc::new(update::NoCard));
        let (system, notify) = system_on(&idle, &ms);
        let receiving = idle.begin_receive().unwrap();
        assert_eq!(system.rejoin(), Err(RejoinWait(REJOIN_EVERY_SECS)));
        drop(receiving);
        let mut waiting = notify.listen();
        assert_eq!(system.rejoin(), Ok(()));
        assert!(heard(&mut waiting).await);

        // A boot on trial refuses too.
        let trial = UpdateCtl::new(
            Some(crate::slots::Slot::B),
            None,
            Arc::new(crate::update::NoCard),
        );
        trial.begin_trial(
            crate::slots::Marker {
                slot: crate::slots::Slot::B,
                from: crate::slots::Slot::A,
                build: 1,
                mode: crate::slots::Mode::Tryboot,
                started: true,
                failed: None,
            },
            tokio::time::Instant::now(),
        );
        let (system, notify) = system_on(&trial, &ms);
        let mut waiting = notify.listen();
        assert_eq!(system.rejoin(), Err(RejoinWait(REJOIN_EVERY_SECS)));
        assert!(!heard(&mut waiting).await);
    }

    #[tokio::test(start_paused = true)]
    async fn a_rejoin_nobody_is_there_to_hear_leaves_nothing_for_a_later_join() {
        let ms = Arc::new(AtomicU64::new(0));
        let (system, notify) = system_on(&UpdateCtl::off(), &ms);
        // No link is held, so no loop waits: the signal keeps no permit (`notify_waiters`).
        assert_eq!(system.rejoin(), Ok(()));
        let mut waiting = notify.listen();
        assert!(!heard(&mut waiting).await);
    }

    #[tokio::test(start_paused = true)]
    async fn a_rejoin_that_finds_no_link_held_is_not_charged_its_minute() {
        let ms = Arc::new(AtomicU64::new(1_000_000));
        let (system, notify) = system_on(&UpdateCtl::off(), &ms);
        // The link is down or being joined: nothing is let go, and the next ask, at once, is let through too.
        assert_eq!(system.rejoin(), Ok(()));
        ms.fetch_add(1_000, Ordering::SeqCst);
        assert_eq!(system.rejoin(), Ok(()));

        // Then a link is held: the ask lets it go, and that one starts the minute.
        let mut waiting = notify.listen();
        assert_eq!(system.rejoin(), Ok(()));
        assert!(
            heard(&mut waiting).await,
            "the Wi-Fi did not hear the rejoin"
        );
        drop(waiting);
        assert_eq!(system.rejoin(), Err(RejoinWait(60)));
    }

    #[test]
    fn the_owner_restarts_the_board_unless_an_update_is_received_or_on_trial() {
        use crate::update::Cause;
        let ms = Arc::new(AtomicU64::new(0));
        let slot_a = crate::slots::Slot::A;
        let ctl = UpdateCtl::new(Some(slot_a), None, Arc::new(crate::update::NoCard));
        let (system, _) = system_on(&ctl, &ms);
        let mut asked = ctl.restart_receiver();

        // While an update is received: refused, nothing asked.
        let receiving = ctl.begin_receive().unwrap();
        assert_eq!(system.restart(), Err(RestartRefused::Updating));
        assert_eq!(*asked.borrow_and_update(), None);
        drop(receiving);
        // Otherwise it is asked for with the owner's cause.
        assert_eq!(system.restart(), Ok(()));
        assert_eq!(
            *asked.borrow_and_update(),
            Some(update::Restart::Plain(Cause::Owner))
        );

        // A boot on trial refuses.
        let trial = UpdateCtl::new(
            Some(crate::slots::Slot::B),
            None,
            Arc::new(crate::update::NoCard),
        );
        trial.begin_trial(
            crate::slots::Marker {
                slot: crate::slots::Slot::B,
                from: crate::slots::Slot::A,
                build: 1,
                mode: crate::slots::Mode::Tryboot,
                started: true,
                failed: None,
            },
            tokio::time::Instant::now(),
        );
        let (system, _) = system_on(&trial, &ms);
        assert_eq!(system.restart(), Err(RestartRefused::Updating));
        assert_eq!(*trial.restart_receiver().borrow(), None);
    }

    #[test]
    fn the_control_shows_the_update_machinerys_view_and_the_boards_readings() {
        let ctl = UpdateCtl::new(Some(crate::slots::Slot::A), None, Arc::new(update::NoCard));
        let (system, _) = system_on(&ctl, &Arc::new(AtomicU64::new(0)));
        assert_eq!(system.update_view().state, "idle");
        let receiving = ctl.begin_receive().unwrap();
        receiving.length_is(200);
        receiving.arrived(50);
        let view = system.update_view();
        assert_eq!(
            (view.state, view.received, view.length),
            ("receiving", 50, 200)
        );
        // The readings are the running board's, read on this thread.
        assert!(system.readings().uptime_secs.is_some_and(|secs| secs > 0));
    }

    #[test]
    fn a_slot_with_no_control_yet_refuses_and_shows_an_idle_machinery_and_the_first_control_stays()
    {
        let slot = Slot::new();
        assert_eq!(slot.rejoin(), Err(RejoinWait(1)));
        assert_eq!(slot.restart(), Err(RestartRefused::NotReady));
        let view = slot.update_view();
        assert_eq!((view.state, view.slot, view.received), ("idle", None, 0));
        // The readings are the board's all the same: they need nothing filled.
        assert!(slot.readings().uptime_secs.is_some());

        let ms = Arc::new(AtomicU64::new(0));
        let ctl = UpdateCtl::new(Some(crate::slots::Slot::A), None, Arc::new(update::NoCard));
        let (system, signal) = system_on(&ctl, &ms);
        slot.fill_system(Arc::new(system));
        // A link is held, so the first rejoin lets it go and the second must wait.
        let holding = signal.listen();
        assert_eq!(slot.rejoin(), Ok(()));
        assert_eq!(slot.rejoin(), Err(RejoinWait(60)));
        assert_eq!(slot.update_view().slot, Some(crate::slots::Slot::A));
        assert_eq!(slot.restart(), Ok(()));
        // A second control is not taken: the first stays.
        slot.fill_system(Arc::new(crate::panel::system::NoSystem));
        assert_eq!(slot.rejoin(), Err(RejoinWait(60)));
        drop(holding);
        // The signal the Wi-Fi component is given is the slot's own, the same on every call.
        assert!(Arc::ptr_eq(&slot.rejoin_signal(), &slot.rejoin_signal()));
    }
}
