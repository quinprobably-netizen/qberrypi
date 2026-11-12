//! The DNS service: the sockets around `qb-dns`, which decides every query.
//!
//! [`Dns`] is what every listener and every lookup of our own goes through: one resolver, one
//! set of upstreams, and one bound on the questions that are out with an upstream at once.
//!
//! A query that is blocked as a threat raises an alert, through the sink of the watch that is set
//! ([`Dns::set_watch`]), at most once an hour for each client and name ([`threat`]).
//!
//! A client that is exempt ([`Dns::exempt`], which the device watch keeps) is held to the threat
//! lists alone: its ads are let through, and its threats are blocked as anyone's. In the list mode
//! that is a client whose address is in the exempt set; in the exempt-by-default mode it is every
//! client but one whose address is fully blocked.
//!
//! Nothing here logs a name that is asked for, or an address that asks.

pub mod client;
pub mod clients;
pub mod dot;
pub mod exempt;
pub mod listen;
pub mod threat;
pub mod upstream;

#[cfg(test)]
pub(crate) mod testutil;

use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use qb_dns::{
    Action, BlockSet, Filter, Now, Pending, Resolver, ThreatHit, Transport, UpstreamOutcome,
};
use tokio::sync::Semaphore;

use crate::alerts::{Alert, Severity};
use crate::lane::LaneFeed;
use crate::watch::{Watch, rebind};
use clients::Clients;
use exempt::Exemption;
use threat::{THREAT_KIND, ThreatThrottle};
use upstream::Upstreams;

/// The port that DNS is served on, over UDP and TCP.
pub const DNS_PORT: u16 = 53;
/// The most questions that are out with an upstream at once: one that would be the next gets
/// SERVFAIL, and a renewal of a stale answer is not made.
pub const MAX_FORWARDS: usize = 256;

/// The most prefetches that are sent in a second, and the most that may be sent at once after a
/// quiet while: the bucket's refill rate and its size.
pub const PREFETCH_PER_SEC: u32 = 4;
/// A prefetch is sent only while fewer than this many questions are out with the upstreams.
pub const PREFETCH_BUSY: usize = 4;

/// The type number of an A record.
const TYPE_A: u16 = 1;
/// The ID of the queries that [`Dns::lookup_v4`] makes: only `answer` sees it, as the upstreams
/// are asked under IDs of their own.
const OWN_QUERY_ID: u16 = 1;

/// A time zone, as far as the statistics need it.
pub trait UtcOffset: Send + Sync {
    /// Local time minus UTC, in seconds, at `unix_secs`.
    fn offset_at(&self, unix_secs: u64) -> i32;
}

/// A token bucket that holds [`PREFETCH_PER_SEC`] tokens at most and earns one every
/// `1 s / PREFETCH_PER_SEC`: what limits the prefetches that are sent.
///
/// It reads no clock: the caller says what time it is, on the runtime's clock, so that a paused
/// clock in a test moves it too.
struct Bucket {
    /// The tokens that are in the bucket.
    tokens: u32,
    /// The moment up to which earned tokens have been counted; the part of an interval after it
    /// is not lost when a token is taken.
    counted: tokio::time::Instant,
}

impl Bucket {
    /// How long it takes to earn one token.
    const INTERVAL: Duration = Duration::from_nanos(1_000_000_000 / PREFETCH_PER_SEC as u64);

    /// A full bucket at `now`.
    fn new(now: tokio::time::Instant) -> Self {
        Self {
            tokens: PREFETCH_PER_SEC,
            counted: now,
        }
    }

    /// Takes one token if there is one, after the tokens that were earned up to `now` are added:
    /// whether it did. A `now` before the last one earns nothing. A bucket that is full does not
    /// count the time that passes, so a long idle banks the burst and no more.
    fn take(&mut self, now: tokio::time::Instant) -> bool {
        let passed = now.saturating_duration_since(self.counted);
        let earned =
            u32::try_from(passed.as_nanos() / Self::INTERVAL.as_nanos()).unwrap_or(u32::MAX);
        let tokens = self.tokens.saturating_add(earned);
        if tokens >= PREFETCH_PER_SEC {
            self.tokens = PREFETCH_PER_SEC;
            self.counted = now.max(self.counted);
        } else {
            self.tokens = tokens;
            // Fewer than `PREFETCH_PER_SEC` intervals were earned, so this cannot overflow.
            self.counted += Self::INTERVAL * earned;
        }
        let taken = self.tokens > 0;
        self.tokens = self.tokens.saturating_sub(1);
        taken
    }
}

/// The DNS service's one resolver and its upstreams.
pub struct Dns {
    resolver: Arc<Mutex<Resolver>>,
    upstreams: Upstreams,
    /// One permit for each question that may be out with an upstream.
    forwards: Arc<Semaphore>,
    /// How many permits `forwards` was made with: the most questions that may be out.
    forward_limit: usize,
    /// What limits the prefetches that are sent, apart from how many questions are out. Never
    /// held across an `.await`.
    prefetch_bucket: Mutex<Bucket>,
    /// The prefetches that were sent.
    prefetched: AtomicU64,
    /// The prefetches that were not sent, for the budget: too many questions out, or no token.
    prefetches_skipped: AtomicU64,
    /// Which pairs of client and name were alerted on lately. Locked only for a threat hit, and
    /// never across an `.await`.
    threats: Mutex<ThreatThrottle>,
    /// When this was made: the zero of the monotonic seconds that the resolver is given.
    started: Instant,
    zone: Box<dyn UtcOffset>,
    /// What the resolver was last given as its offset from UTC.
    utc_offset: AtomicI32,
    /// The watchdog's hook on the answer path; empty until [`Dns::set_watch`].
    watch: OnceLock<Watch>,
    /// The devices that asked. Locked for one insert or one copy out, never across an `.await`.
    clients: Mutex<Clients>,
    /// Whether an answer has been sent to a device that the table would count.
    first_answer: AtomicBool,
    /// Where the names that the front panel shows are offered, once there is a panel.
    lane: OnceLock<Arc<LaneFeed>>,
    /// Whose questions are held to the threat lists alone: the mode and the sets of addresses
    /// that the device watch keeps; read before the resolver is locked.
    exempt: Arc<Exemption>,
}

impl Dns {
    /// A service that blocks the names of `blockset`, asks `upstreams`, and counts a day in
    /// `zone`, with [`MAX_FORWARDS`] questions out at most. Its alerts, of threat hits and of
    /// rebinding answers, go to the sink of the watch, once one is set ([`Dns::set_watch`]).
    pub fn new(blockset: BlockSet, upstreams: Upstreams, zone: Box<dyn UtcOffset>) -> Arc<Self> {
        Self::build(blockset, upstreams, zone, MAX_FORWARDS)
    }

    /// [`Dns::new`] with `forwards` questions out at most. Tests only: nothing else limits the
    /// forwards to fewer than [`MAX_FORWARDS`].
    #[cfg(test)]
    pub(crate) fn with_forward_limit(
        blockset: BlockSet,
        upstreams: Upstreams,
        zone: Box<dyn UtcOffset>,
        forwards: usize,
    ) -> Arc<Self> {
        Self::build(blockset, upstreams, zone, forwards)
    }

    /// The service that the others are made by: `forwards` questions out at most.
    fn build(
        blockset: BlockSet,
        upstreams: Upstreams,
        zone: Box<dyn UtcOffset>,
        forwards: usize,
    ) -> Arc<Self> {
        let dns = Arc::new(Self {
            resolver: Arc::new(Mutex::new(Resolver::new(blockset))),
            upstreams,
            forwards: Arc::new(Semaphore::new(forwards)),
            forward_limit: forwards,
            prefetch_bucket: Mutex::new(Bucket::new(tokio::time::Instant::now())),
            prefetched: AtomicU64::new(0),
            prefetches_skipped: AtomicU64::new(0),
            threats: Mutex::new(ThreatThrottle::new()),
            started: Instant::now(),
            zone,
            utc_offset: AtomicI32::new(0),
            watch: OnceLock::new(),
            clients: Mutex::default(),
            first_answer: AtomicBool::new(false),
            lane: OnceLock::new(),
            exempt: Arc::default(),
        });
        dns.sync_utc_offset();
        dns
    }

    /// The time of this moment: the monotonic seconds since [`Dns::new`], and the system clock.
    pub fn now(&self) -> Now {
        let since_epoch = SystemTime::now().duration_since(UNIX_EPOCH);
        Now {
            mono_secs: self.started.elapsed().as_secs(),
            unix_secs: since_epoch.map_or(0, |since| since.as_secs()),
        }
    }

    /// The resolver, locked. It is taken whether or not a holder panicked: the resolver keeps
    /// its bounds whatever a call left half done. Never hold the guard across an `.await`.
    pub fn resolver(&self) -> crate::stall::Held<'_, Resolver> {
        crate::stall::lock_resolver(&self.resolver)
    }

    /// The devices that asked, locked. It is taken whether or not a holder panicked, and the same
    /// rules apply: copy what is needed out, and never hold the guard across an `.await`.
    pub fn clients(&self) -> MutexGuard<'_, Clients> {
        self.clients.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Notes that the device at `addr` has asked, at this moment. An address that is no device
    /// (see [`clients::counted`]) is not kept. No address is logged.
    pub fn note_client(&self, addr: IpAddr) {
        let now = self.now().mono_secs;
        self.clients().record(addr, now);
    }

    /// Notes that an answer was sent to `peer`. The first one that goes to a device that the table
    /// would count is logged, with the time since the kernel started, which is how long the
    /// household waited for qberrypi: the answers to the self-test, over loopback, are not it.
    pub(crate) fn note_answered(&self, peer: IpAddr) {
        if clients::counted(peer).is_some() && !self.first_answer.swap(true, Ordering::Relaxed) {
            log::info!(
                "dns: first answer to a client {} ms after the kernel started",
                crate::sys::uptime().as_millis()
            );
        }
    }

    /// The same resolver, for whoever must lock it from elsewhere; the same rules apply.
    pub fn shared(&self) -> Arc<Mutex<Resolver>> {
        self.resolver.clone()
    }

    /// The upstreams, and how they are doing.
    pub fn upstreams(&self) -> &Upstreams {
        &self.upstreams
    }

    /// Gives the resolver the zone's offset from UTC at this moment, which moves where a day
    /// starts. Daylight saving time is why it is to be called again and again.
    pub fn sync_utc_offset(&self) {
        let offset = self.zone.offset_at(self.now().unix_secs);
        self.resolver().set_utc_offset(offset);
        self.utc_offset.store(offset, Ordering::Relaxed);
    }

    /// The offset from UTC, in seconds, that the resolver was last given.
    pub fn utc_offset(&self) -> i32 {
        self.utc_offset.load(Ordering::Relaxed)
    }

    /// Hangs `watch` on the answer path: from now on the listeners offer it each answer they send.
    /// It is set once. A second call is ignored, as the first watch stays, so that the feed that
    /// the listeners fill is never swapped from under the analysis that drains it.
    pub fn set_watch(&self, watch: Watch) {
        let _ = self.watch.set(watch);
    }

    /// Offers the watchdog `reply`, an answer that was sent to `client`. The listeners call it
    /// for every answer they send; our own lookups do not. With no watch set it is one atomic
    /// load, and with one it never waits.
    pub fn observe(&self, client: IpAddr, reply: &[u8]) {
        if let Some(watch) = self.watch.get() {
            watch.feed.offer(client, reply);
        }
    }

    /// How many answers the watchdog's feed has dropped, for lack of room; 0 with no watch set.
    pub fn watch_events_dropped(&self) -> u64 {
        self.watch.get().map_or(0, |watch| watch.feed.dropped())
    }

    /// Who is exempt from the ads lists now: the device watch writes the mode and the addresses,
    /// and every question of a client is checked against them before the resolver is locked.
    pub fn exempt(&self) -> &Arc<Exemption> {
        &self.exempt
    }

    /// Which lists a question of `client` is held to: the threat lists alone for a client that is
    /// exempt ([`Exemption::is_exempt`]), and every list for any other, and for this program's own
    /// (`None`) in either mode. In the list mode with the exempt set empty it costs two relaxed
    /// atomic loads; in the exempt-by-default mode, one load and a look in the blocked set.
    fn filter_for(&self, client: Option<IpAddr>) -> Filter {
        match client {
            Some(client) if self.exempt.is_exempt(client) => Filter::ThreatsOnly,
            _ => Filter::All,
        }
    }

    /// Offers the names that clients ask for to `lane` from now on. Set once: a second feed is
    /// ignored, and the first stays.
    pub fn set_lane(&self, lane: Arc<LaneFeed>) {
        // The second value is of no use to anyone: the first stays.
        let _ = self.lane.set(lane);
    }

    /// The reply to one client's packet, if there is one; `None` for a packet that gets none.
    /// `client` is who asked, `None` if it is this program.
    ///
    /// The resolver decides, and what it decides is carried out here. Waiting for an upstream is
    /// the only wait, and it is bounded by the upstreams' own timeouts.
    pub async fn answer(self: &Arc<Self>, packet: &[u8], transport: Transport) -> Option<Vec<u8>> {
        self.answer_for(packet, transport, None).await
    }

    /// [`Dns::answer`] for a packet that came from `client`, which the watchdog's alerts name;
    /// `None` where it is not known.
    pub async fn answer_for(
        self: &Arc<Self>,
        packet: &[u8],
        transport: Transport,
        client: Option<IpAddr>,
    ) -> Option<Vec<u8>> {
        self.carry_for(self.decide_from(packet, transport, client), client)
            .await
    }

    /// [`Dns::decide_from`] with no client: what the resolver decides for one packet. Tests only:
    /// the listeners know their clients.
    #[cfg(test)]
    pub(crate) fn decide(&self, packet: &[u8], transport: Transport) -> Action {
        self.decide_from(packet, transport, None)
    }

    /// What the resolver decides for the packet that `client` sent; `None` if it is this program.
    /// The resolver is locked for this call only, and the call does not wait: the listener
    /// decides on its receive loop. The query that this counts is offered to the lane, if there
    /// is one, which does not wait either.
    ///
    /// The client's address is checked against the exemption first, before the resolver is
    /// locked: an exempt client is held to the threat lists alone ([`Filter::ThreatsOnly`]).
    /// The check is one relaxed load of the mode and one look in a set of addresses: with the
    /// set empty, one relaxed atomic load more; with addresses in it, one read lock that only a
    /// change of the set waits on, and a binary search. Neither allocates.
    ///
    /// A query that is blocked as a threat may raise an alert on the watch's sink, after the
    /// resolver is unlocked ([`Dns::threat_hit`]). Every other answer costs that check and one
    /// test of an `Option` more than the resolver's own decision: no other lock, no allocation.
    pub(crate) fn decide_from(
        &self,
        packet: &[u8],
        transport: Transport,
        client: Option<IpAddr>,
    ) -> Action {
        let filter = self.filter_for(client);
        let now = self.now();
        let mut resolver = self.resolver();
        let lane = self
            .lane
            .get()
            .map(|lane| (lane, resolver.stats().total().queries));
        let (action, hit) = resolver.handle_query_filtered(packet, transport, now, filter);
        if let Some((lane, before)) = lane {
            lane.offer_latest(&resolver, before, now);
        }
        drop(resolver);
        if let Some(hit) = hit {
            self.threat_hit(hit, client, now.mono_secs);
        }
        action
    }

    /// Raises the alert for a threat that `client` asked for, unless one was raised for the same
    /// client and name within [`THREAT_ALERT_EVERY_SECS`](threat::THREAT_ALERT_EVERY_SECS), or the
    /// throttle has no room for the pair. With no watch set no alert is raised, but the throttle
    /// counts the pair all the same, so that it stays bounded.
    ///
    /// The sink is not called here, where the answer is being made, as with [`Dns::raise_rebind`]:
    /// a small task raises it, after the reply has been sent, as the runtime gets to it. Off the
    /// runtime (a test that decides by itself) the sink is called at once. The throttle is
    /// unlocked before either.
    fn threat_hit(&self, hit: ThreatHit, client: Option<IpAddr>, mono_secs: u64) {
        let raise = self
            .threats
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .should_raise(client, &hit.name, mono_secs);
        if !raise {
            return;
        }
        let Some(sink) = self.watch.get().map(|watch| watch.sink.clone()) else {
            return;
        };
        let alert = Alert {
            kind: THREAT_KIND,
            severity: Severity::High,
            client,
            subject: hit.name.into_string(),
        };
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(async move { sink.raise(alert) });
            }
            Err(_) => sink.raise(alert),
        }
    }

    /// How many threat alerts were dropped since this was made, because the throttle held
    /// [`THREAT_PAIRS`](threat::THREAT_PAIRS) pairs that were not yet quiet again.
    pub fn threat_alerts_dropped(&self) -> u64 {
        self.threats
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .dropped()
    }

    /// Carries out what [`Dns::decide_from`] decided: a reply is given, a drop gives `None`, a forward
    /// is exchanged with the upstreams under a permit, or answered with SERVFAIL if none is
    /// free, and a stale answer is given at once, its renewal made in a task if a permit is free.
    // The listeners know their clients and call `carry_for`; this is for a test that decides alone.
    #[cfg(test)]
    pub(crate) async fn carry(self: &Arc<Self>, action: Action) -> Option<Vec<u8>> {
        self.carry_for(action, None).await
    }

    /// `Dns::carry` (which only the tests use) for an action that was decided for `client`, which
    /// the watchdog's alerts name; `None` where it is not known.
    pub(crate) async fn carry_for(
        self: &Arc<Self>,
        action: Action,
        client: Option<IpAddr>,
    ) -> Option<Vec<u8>> {
        match action {
            Action::Reply(bytes) => Some(bytes),
            Action::Drop => None,
            Action::Forward(pending) => {
                let Ok(_permit) = self.forwards.try_acquire() else {
                    return pending.servfail();
                };
                match self.exchange(&pending, client).await {
                    Some(UpstreamOutcome::Reply(bytes)) => Some(bytes),
                    _ => pending.servfail(),
                }
            }
            Action::ReplyAndRefresh(bytes, pending) => {
                self.refresh(pending);
                Some(bytes)
            }
        }
    }

    /// Renews the answer that `pending` stands for: the exchange is made in a task, if a forward
    /// is free. Without one the answer stays as it is, and is renewed another time. It does not
    /// wait, so the listener may call it on its receive loop.
    ///
    /// A stale answer's renewal is made whenever a forward is free. A [prefetch](Pending::is_prefetch)
    /// is made only while fewer than [`PREFETCH_BUSY`] questions are out with the upstreams, and
    /// at most [`PREFETCH_PER_SEC`] in a second: otherwise it is skipped and counted, and the
    /// entry goes stale, which a stale hit renews. No client waits for either.
    pub(crate) fn refresh(self: &Arc<Self>, pending: Pending) {
        let prefetch = pending.is_prefetch();
        if prefetch && !self.prefetch_allowed() {
            self.prefetches_skipped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if let Ok(permit) = self.forwards.clone().try_acquire_owned() {
            if prefetch {
                self.prefetched.fetch_add(1, Ordering::Relaxed);
            }
            let dns = self.clone();
            crate::stall::spawn("dns refresh", async move {
                let _permit = permit;
                dns.exchange(&pending, None).await;
            });
        } else if prefetch {
            self.prefetches_skipped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Whether a prefetch may be sent now: fewer than [`PREFETCH_BUSY`] questions are out, and
    /// the bucket has a token, which is then taken. The bucket's lock is held for one call of
    /// [`Bucket::take`].
    fn prefetch_allowed(&self) -> bool {
        let out = self
            .forward_limit
            .saturating_sub(self.forwards.available_permits());
        out < PREFETCH_BUSY
            && self
                .prefetch_bucket
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take(tokio::time::Instant::now())
    }

    /// How many prefetches were sent since this was made.
    pub fn prefetched(&self) -> u64 {
        self.prefetched.load(Ordering::Relaxed)
    }

    /// How many prefetches were skipped since this was made, because [`PREFETCH_BUSY`] questions
    /// were out or the bucket was empty.
    pub fn prefetches_skipped(&self) -> u64 {
        self.prefetches_skipped.load(Ordering::Relaxed)
    }

    /// The IPv4 addresses of `name`, asked for through the resolver as any client would: its
    /// block set, its cache and its statistics apply. An IPv4 literal is returned as it is.
    ///
    /// `ErrorKind::NotFound` if the name has no address: no answer, an answer that is not
    /// NOERROR, no A record, or `0.0.0.0`, which a blocked name gets.
    pub async fn lookup_v4(self: &Arc<Self>, name: &str) -> io::Result<Vec<Ipv4Addr>> {
        if let Ok(literal) = name.parse::<Ipv4Addr>() {
            return Ok(vec![literal]);
        }
        // The error says nothing of the name: the callers log it.
        let not_found = || io::Error::new(ErrorKind::NotFound, "the name has no address");
        let packet = client::query(OWN_QUERY_ID, name, TYPE_A)?;
        let reply = self
            .answer(&packet, Transport::Tcp)
            .await
            .ok_or_else(not_found)?;
        let answer = client::read_answer(&reply, OWN_QUERY_ID)
            .filter(|answer| answer.rcode == 0)
            .ok_or_else(not_found)?;
        let addrs = answer.v4();
        if addrs.is_empty() || addrs.contains(&Ipv4Addr::UNSPECIFIED) {
            return Err(not_found());
        }
        Ok(addrs)
    }

    /// One exchange with the upstreams for `pending`, whose packets the resolver takes in. They
    /// are screened for rebinding first, on behalf of `client`, who is `None` for a renewal.
    async fn exchange(&self, pending: &Pending, client: Option<IpAddr>) -> Option<UpstreamOutcome> {
        let mut take = |packet: &[u8], via: Transport| {
            let screened = self
                .rebinding(pending, packet)
                .then(|| rebind::zero_addresses(packet));
            let outcome = self.resolver().handle_upstream(
                pending,
                screened.as_deref().unwrap_or(packet),
                via,
                self.now(),
            );
            // Only a packet that the resolver took is an answer that would have been given.
            if screened.is_some()
                && matches!(
                    outcome,
                    UpstreamOutcome::Reply(_) | UpstreamOutcome::Refreshed
                )
            {
                self.raise_rebind(pending, client);
            }
            outcome
        };
        self.upstreams.exchange(pending, &mut take).await
    }

    /// Whether `packet`, an upstream's answer to `pending`, is one that holds a private address
    /// for a name that the watch screens. It is never so with no watch set.
    fn rebinding(&self, pending: &Pending, packet: &[u8]) -> bool {
        self.watch
            .get()
            .is_some_and(|watch| watch.rebind.screens(pending.name()))
            && rebind::private_answer(packet)
    }

    /// Raises the alert for a rebinding answer to `pending` that was blocked.
    ///
    /// The sink is not called here, where the answer is being made: what it does is its own
    /// business (the store takes a lock, makes a key and may log), and no answer waits for that. A
    /// small task raises it instead, after the reply has been sent, as the runtime gets to it. It
    /// is made only on a match, a rare event, so the allocation is not on the hot path. Must be
    /// called on the runtime, as the exchange is.
    fn raise_rebind(&self, pending: &Pending, client: Option<IpAddr>) {
        if let Some(watch) = self.watch.get() {
            let sink = watch.sink.clone();
            let subject = pending.name().to_owned();
            tokio::spawn(async move {
                sink.raise(Alert {
                    kind: "rebind",
                    severity: Severity::High,
                    client,
                    subject,
                });
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::{
        FakeUpstream, FixedOffset, NOW, RecordingSink, Reply, closed_port, ip, ms, threat_set,
    };
    use super::*;

    use std::hint::black_box;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use crate::alerts::NullSink;
    use crate::watch::{self, Watch};

    use qb_panel::drain::NameKind;
    use tokio::time::sleep;

    use crate::lists;

    /// Seconds a stale answer is sent with, as `qb-dns` has it.
    const STALE_TTL: u32 = 30;

    /// The monotonic second at which [`due_prefetches`] asks: its answers live 60 seconds, so the
    /// prefetch window (a tenth of that, 6 seconds) is open from second 54, and no answer was
    /// stored later than second 2 of a test that does not stall.
    const WINDOW_OPEN: u64 = 57;

    /// A `Dns` over one fake upstream, with one forward at most, that has been asked for
    /// `example.com` once and is 100 seconds later: the answer it keeps, which lives 60, is stale.
    async fn stale() -> (Arc<Dns>, FakeUpstream, Vec<u8>) {
        let up = FakeUpstream::start(Reply::Answer(ip("192.0.2.10"))).await;
        let dns = Dns::with_forward_limit(
            BlockSet::default(),
            Upstreams::with(vec![up.addr], ms(300), ms(600)),
            Box::new(FixedOffset(0)),
            1,
        );
        let packet = client::query(5, "example.com", TYPE_A).unwrap();
        assert!(dns.answer(&packet, Transport::Udp).await.is_some());
        assert_eq!(up.udp_queries(), 1);
        let mut dns = Arc::try_unwrap(dns).ok().expect("nothing else holds it");
        dns.started -= Duration::from_secs(100);
        (Arc::new(dns), up, packet)
    }

    /// The lowest TTL of the answer in `reply`.
    fn ttl(reply: Option<Vec<u8>>) -> Option<u32> {
        client::read_answer(&reply.unwrap(), 5).unwrap().min_ttl
    }

    /// A `Dns` over one fake upstream that answers at once, with `forwards` questions out at
    /// most and prefetch on, which has been asked for `n` names once, and then for each of them
    /// twice more as the window of its answer opens: the `n` prefetches that those third
    /// questions asked for, none of them made.
    async fn due_prefetches(n: usize, forwards: usize) -> (Arc<Dns>, FakeUpstream, Vec<Pending>) {
        let up = FakeUpstream::start(Reply::Answer(ip("192.0.2.10"))).await;
        let dns = Dns::with_forward_limit(
            BlockSet::default(),
            Upstreams::with(vec![up.addr], ms(300), ms(600)),
            Box::new(FixedOffset(0)),
            forwards,
        );
        dns.resolver().set_prefetch(true);
        let mut pending = Vec::new();
        for i in 0..n {
            let packet = client::query(5, &format!("n{i}.example.com"), TYPE_A).unwrap();
            assert!(dns.answer(&packet, Transport::Udp).await.is_some());
            let at = Now {
                mono_secs: WINDOW_OPEN,
                ..NOW
            };
            for _ in 0..2 {
                let hit = dns.resolver().handle_query(&packet, Transport::Udp, at);
                assert!(matches!(hit, Action::Reply(_)), "{hit:?}");
            }
            match dns.resolver().handle_query(&packet, Transport::Udp, at) {
                Action::ReplyAndRefresh(_, p) if p.is_prefetch() => pending.push(p),
                other => panic!("not a prefetch: {other:?}"),
            }
        }
        assert_eq!(up.udp_queries(), n);
        (dns, up, pending)
    }

    /// Waits until no question is out with the upstreams of `dns`, for at most 2 s.
    async fn until_idle(dns: &Dns) {
        for _ in 0..200 {
            if dns.forwards.available_permits() == dns.forward_limit {
                return;
            }
            sleep(ms(10)).await;
        }
        panic!("questions stayed out");
    }

    /// A client of the household.
    fn client(last: u8) -> Option<IpAddr> {
        Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)))
    }

    /// A `Dns` that blocks [`threat_set`] and raises its alerts on `sink`, the sink of a watch
    /// whose events nobody takes, with an upstream that nothing listens at.
    fn threat_dns(sink: &Arc<RecordingSink>) -> Arc<Dns> {
        let dns = Dns::new(
            threat_set(),
            Upstreams::with(vec![closed_port()], ms(300), ms(300)),
            Box::new(FixedOffset(0)),
        );
        let (feed, _events) = watch::feed();
        dns.set_watch(Watch::for_test(feed, sink.clone()));
        dns
    }

    /// What a client of `dns` gets for `name` A over UDP, decided at once.
    fn blocked_reply(dns: &Dns, name: &str, from: Option<IpAddr>) -> Vec<u8> {
        let packet = client::query(5, name, TYPE_A).unwrap();
        match dns.decide_from(&packet, Transport::Udp, from) {
            Action::Reply(reply) => reply,
            other => panic!("not answered at once: {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_threat_hit_raises_one_high_alert_for_its_client() {
        let sink = Arc::new(RecordingSink::default());
        let dns = threat_dns(&sink);
        let name = "x.bad.example.net";
        // The same client asks again and again: one alert, and every answer is the blocked one.
        for _ in 0..3 {
            let reply = blocked_reply(&dns, name, client(10));
            assert_eq!(
                client::read_answer(&reply, 5).unwrap().v4(),
                [Ipv4Addr::UNSPECIFIED]
            );
        }
        // The alert is raised by a task that follows the reply.
        assert_eq!(sink.raised(), []);
        assert_eq!(
            sink.raised_after(1).await,
            [("threat", "high", client(10), name.to_owned())]
        );
        // Another client asking for it is another alert; the name is the one the resolver
        // records, whatever the client's spelling.
        blocked_reply(&dns, "X.Bad.EXAMPLE.net", client(11));
        assert_eq!(
            sink.raised_after(2).await,
            [
                ("threat", "high", client(10), name.to_owned()),
                ("threat", "high", client(11), name.to_owned()),
            ]
        );
        assert_eq!(dns.threat_alerts_dropped(), 0);
    }

    #[tokio::test]
    async fn ads_blocks_and_own_lookups_raise_nothing_unexpected() {
        let up = FakeUpstream::start(Reply::Answer(ip("192.0.2.10"))).await;
        let sink = Arc::new(RecordingSink::default());
        let dns = Dns::new(
            threat_set(),
            Upstreams::with(vec![up.addr], ms(300), ms(600)),
            Box::new(FixedOffset(0)),
        );
        let (feed, _events) = watch::feed();
        dns.set_watch(Watch::for_test(feed, sink.clone()));
        // An ads block, an answer from an upstream and one from the cache: no alert.
        blocked_reply(&dns, "ads.example.com", client(10));
        let packet = client::query(5, "example.org", TYPE_A).unwrap();
        for _ in 0..2 {
            let reply = dns.answer_for(&packet, Transport::Udp, client(10)).await;
            assert!(reply.is_some());
        }
        assert_eq!(up.udp_queries(), 1);
        assert_eq!(sink.raised_after(0).await, []);
        // A lookup of our own for a threat name raises one, for no client, and a repeat none.
        for _ in 0..2 {
            let found = dns.lookup_v4("x.bad.example.net").await;
            assert_eq!(found.unwrap_err().kind(), ErrorKind::NotFound);
        }
        assert_eq!(
            sink.raised_after(1).await,
            [("threat", "high", None, "x.bad.example.net".to_owned())]
        );
        // `answer` is the same question asked for no client.
        let packet = client::query(5, "y.bad.example.net", TYPE_A).unwrap();
        assert!(dns.answer(&packet, Transport::Tcp).await.is_some());
        let raised = sink.raised_after(2).await;
        assert_eq!(raised.len(), 2);
        assert_eq!(raised[1].2, None);
    }

    /// The addresses that a client of `dns` gets for `name` A over UDP: through the upstream, the
    /// cache or the block, as the resolver decides for `from`.
    async fn addresses_for(dns: &Arc<Dns>, name: &str, from: Option<IpAddr>) -> Vec<Ipv4Addr> {
        let packet = client::query(5, name, TYPE_A).unwrap();
        let reply = dns.answer_for(&packet, Transport::Udp, from).await.unwrap();
        client::read_answer(&reply, 5).unwrap().v4()
    }

    #[tokio::test]
    async fn an_exempt_client_gets_its_ads_and_keeps_its_threats_blocked() {
        let up = FakeUpstream::start(Reply::Answer(ip("192.0.2.10"))).await;
        let sink = Arc::new(RecordingSink::default());
        let dns = Dns::new(
            threat_set(),
            Upstreams::with(vec![up.addr], ms(300), ms(600)),
            Box::new(FixedOffset(0)),
        );
        let (feed, _events) = watch::feed();
        dns.set_watch(Watch::for_test(feed, sink.clone()));
        dns.exempt()
            .listed()
            .replace(&[Ipv4Addr::new(192, 0, 2, 20)]);
        let mapped = Some(IpAddr::V6(Ipv4Addr::new(192, 0, 2, 20).to_ipv6_mapped()));
        let blocked = [Ipv4Addr::UNSPECIFIED];

        // The exempt client gets the ad from the upstream, and then from the cache, in either
        // form of its address.
        let ad = "ads.example.com";
        assert_eq!(
            addresses_for(&dns, ad, client(20)).await,
            [ip("192.0.2.10")]
        );
        assert_eq!(addresses_for(&dns, ad, mapped).await, [ip("192.0.2.10")]);
        assert_eq!(up.udp_queries(), 1);
        // Another client, and a lookup of our own, are blocked all the same.
        assert_eq!(addresses_for(&dns, ad, client(21)).await, blocked);
        assert_eq!(addresses_for(&dns, ad, None).await, blocked);
        // A threat is blocked for the exempt client too, and raises its alert.
        let threat = "x.bad.example.net";
        assert_eq!(addresses_for(&dns, threat, client(20)).await, blocked);
        assert_eq!(
            sink.raised_after(1).await,
            [("threat", "high", client(20), threat.to_owned())]
        );
        let total = dns.resolver().stats().total();
        assert_eq!(
            (
                total.queries,
                total.forwarded,
                total.cache_hits,
                total.blocked
            ),
            (5, 1, 1, 3)
        );
        assert_eq!(total.blocked_threat, 1);

        // Once the set is empty again, the client is blocked like any other.
        dns.exempt().listed().replace(&[]);
        assert_eq!(addresses_for(&dns, ad, client(20)).await, blocked);
        assert_eq!(up.udp_queries(), 1);
    }

    #[tokio::test]
    async fn exempt_by_default_lets_ads_through_for_all_but_the_blocked_and_never_threats() {
        let up = FakeUpstream::start(Reply::Answer(ip("192.0.2.10"))).await;
        let sink = Arc::new(RecordingSink::default());
        let dns = Dns::new(
            threat_set(),
            Upstreams::with(vec![up.addr], ms(300), ms(600)),
            Box::new(FixedOffset(0)),
        );
        let (feed, _events) = watch::feed();
        dns.set_watch(Watch::for_test(feed, sink.clone()));
        // 192.0.2.1 is the router and .30 a device on the block list; .20 is on the exempt list,
        // which this mode does not read.
        dns.exempt()
            .blocked()
            .replace(&[Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 30)]);
        dns.exempt()
            .listed()
            .replace(&[Ipv4Addr::new(192, 0, 2, 20)]);
        dns.exempt().set_by_default(true);
        let v6 = Some(IpAddr::V6("2001:db8::7".parse().unwrap()));
        let blocked_mapped = Some(IpAddr::V6(Ipv4Addr::new(192, 0, 2, 30).to_ipv6_mapped()));
        let blocked = [Ipv4Addr::UNSPECIFIED];
        let ad = "ads.example.com";

        // A client nobody named, and one that asks over IPv6, get the ad.
        assert_eq!(
            addresses_for(&dns, ad, client(21)).await,
            [ip("192.0.2.10")]
        );
        assert_eq!(addresses_for(&dns, ad, v6).await, [ip("192.0.2.10")]);
        assert_eq!(
            addresses_for(&dns, ad, client(20)).await,
            [ip("192.0.2.10")]
        );
        // The blocked device in either form, the router and our own lookups are blocked.
        for from in [client(30), blocked_mapped, client(1), None] {
            assert_eq!(addresses_for(&dns, ad, from).await, blocked, "{from:?}");
        }
        // A threat is blocked for an exempt client too, and raises its alert.
        let threat = "x.bad.example.net";
        assert_eq!(addresses_for(&dns, threat, client(21)).await, blocked);
        assert_eq!(
            sink.raised_after(1).await,
            [("threat", "high", client(21), threat.to_owned())]
        );
        // The mode flips at once: back in the list mode only .20 is exempt.
        dns.exempt().set_by_default(false);
        assert_eq!(addresses_for(&dns, ad, client(21)).await, blocked);
        assert_eq!(
            addresses_for(&dns, ad, client(20)).await,
            [ip("192.0.2.10")]
        );
        dns.exempt().set_by_default(true);
        assert_eq!(
            addresses_for(&dns, ad, client(22)).await,
            [ip("192.0.2.10")]
        );
        assert_eq!(addresses_for(&dns, ad, client(30)).await, blocked);
        assert_eq!(up.udp_queries(), 1);
    }

    #[tokio::test]
    async fn a_flood_of_threat_names_is_bounded_and_counted() {
        let sink = Arc::new(RecordingSink::default());
        let dns = threat_dns(&sink);
        let names = threat::THREAT_PAIRS + 10;
        for i in 0..names {
            blocked_reply(&dns, &format!("n{i}.bad.example.net"), client(10));
        }
        assert_eq!(
            sink.raised_after(threat::THREAT_PAIRS).await.len(),
            threat::THREAT_PAIRS
        );
        assert_eq!(dns.threat_alerts_dropped(), 10);
        // Every one of them was blocked all the same.
        assert_eq!(
            dns.resolver().stats().total().blocked_threat,
            u64::try_from(names).unwrap()
        );
    }

    /// What `decide_from` costs for names that are blocked, which is all that the receive loop
    /// pays for them: 100,000 calls for each kind, and the old body of `decide` for comparison.
    /// The figures are the best of several rounds, which are interleaved so that a busy machine
    /// does not favour one kind. Run in release:
    /// `cargo test -p qberrypi --release decide_cost -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore = "a timing measurement: run it in release, on its own"]
    async fn decide_cost_for_blocked_and_threat_names() {
        const CALLS: usize = 100_000;
        const ROUNDS: usize = 10;
        // A watch is set, so that a fresh threat pays for the task that raises its alert.
        let new_dns = || {
            let dns = Dns::new(
                threat_set(),
                Upstreams::with(vec![closed_port()], ms(300), ms(300)),
                Box::new(FixedOffset(0)),
            );
            let (feed, _events) = watch::feed();
            dns.set_watch(Watch::for_test(feed, Arc::new(NullSink)));
            dns
        };
        let ask = |name: &str| client::query(5, name, TYPE_A).unwrap();
        let ads = ask("ads.example.com");
        let repeated = ask("x.bad.example.net");
        let fresh: Vec<Vec<u8>> = (0..CALLS)
            .map(|i| ask(&format!("n{i}.bad.example.net")))
            .collect();
        let who = client(10);
        // Nanoseconds per call of `work` over `packets`.
        let per_call = |packets: &[&Vec<u8>], work: &dyn Fn(&[u8])| {
            let started = std::time::Instant::now();
            for packet in packets {
                work(packet);
            }
            started.elapsed().as_nanos() / u128::try_from(packets.len()).unwrap()
        };

        // The body that `decide` had before threats: the resolver and nothing else, whose hit
        // is dropped at once, for an ads name and for a threat name.
        let dns = new_dns();
        let old_body = |packet: &[u8]| {
            let now = dns.now();
            std::hint::black_box(dns.resolver().handle_query(packet, Transport::Udp, now));
        };
        let new_body = |packet: &[u8]| {
            std::hint::black_box(dns.decide_from(packet, Transport::Udp, who));
        };
        let (mut ads_old, mut ads_new) = (u128::MAX, u128::MAX);
        let (mut threat_old, mut threat_new) = (u128::MAX, u128::MAX);
        let ads_calls = vec![&ads; CALLS / ROUNDS];
        let threat_calls = vec![&repeated; CALLS / ROUNDS];
        for _ in 0..ROUNDS {
            ads_old = ads_old.min(per_call(&ads_calls, &old_body));
            ads_new = ads_new.min(per_call(&ads_calls, &new_body));
            threat_old = threat_old.min(per_call(&threat_calls, &old_body));
            // The first of these raises the alert; every one after it is throttled.
            threat_new = threat_new.min(per_call(&threat_calls, &new_body));
        }

        // The repeated name holds one pair in `dns`; so does a `Dns` of its own here, so that
        // the next `THREAT_PAIRS - 1` fresh names are new pairs, which are remembered and raise
        // an alert, and the rest find the throttle full, and are dropped and counted.
        let (mut raised, mut dropped) = (u128::MAX, u128::MAX);
        for _ in 0..3 {
            let dns = new_dns();
            let new_body = |packet: &[u8]| {
                std::hint::black_box(dns.decide_from(packet, Transport::Udp, who));
            };
            new_body(&repeated);
            let (new, full) = fresh.split_at(threat::THREAT_PAIRS - 1);
            let (new, full): (Vec<_>, Vec<_>) = (new.iter().collect(), full.iter().collect());
            raised = raised.min(per_call(&new, &new_body));
            dropped = dropped.min(per_call(&full, &new_body));
            assert_eq!(
                dns.threat_alerts_dropped(),
                u64::try_from(full.len()).unwrap()
            );
        }

        println!(
            "ads blocked: {ads_new} ns per decide (the resolver alone: {ads_old} ns); \
             threat, throttled: {threat_new} ns (the resolver alone: {threat_old} ns); \
             fresh threat, alert raised: {raised} ns; fresh threat, throttle full: {dropped} ns"
        );
        // Generous: this catches a sweep for every call, not a few hundred nanoseconds.
        assert!(ads_new < 20_000 && threat_new < 20_000 && dropped < 20_000);
    }

    #[test]
    fn prefetch_bucket_refills_at_its_rate() {
        let t0 = tokio::time::Instant::now();
        let mut bucket = Bucket::new(t0);
        // A full bucket gives its burst at once, and not a token more.
        for _ in 0..PREFETCH_PER_SEC {
            assert!(bucket.take(t0));
        }
        assert!(!bucket.take(t0));
        // One token every 250 ms.
        assert!(!bucket.take(t0 + ms(249)));
        assert!(bucket.take(t0 + ms(250)));
        assert!(!bucket.take(t0 + ms(250)));
        // The part of an interval that has passed is not lost when a token is taken: 300 ms
        // after the start the token that is taken is the one earned at 250 ms, and the next is
        // due at 500 ms.
        let mut bucket = Bucket::new(t0);
        for _ in 0..PREFETCH_PER_SEC {
            assert!(bucket.take(t0));
        }
        assert!(bucket.take(t0 + ms(300)));
        assert!(!bucket.take(t0 + ms(499)));
        assert!(bucket.take(t0 + ms(500)));
        // Half a second earns two.
        assert!(!bucket.take(t0 + ms(749)));
        assert!(bucket.take(t0 + ms(1000)));
        assert!(bucket.take(t0 + ms(1000)));
        assert!(!bucket.take(t0 + ms(1000)));
        // A long idle banks the burst and no more.
        let later = t0 + Duration::from_secs(3600);
        for _ in 0..PREFETCH_PER_SEC {
            assert!(bucket.take(later));
        }
        assert!(!bucket.take(later));
        assert!(bucket.take(later + ms(250)));
        // A clock that reads earlier than the last take earns nothing, and does not panic.
        assert!(!bucket.take(t0));
    }

    // Review Focus 5
    #[tokio::test]
    async fn prefetch_budget_caps_a_burst() {
        let (dns, up, mut prefetches) = due_prefetches(11, MAX_FORWARDS).await;
        let last = prefetches.pop().unwrap();
        let asked = up.udp_queries();

        // Ten popular names expire in the same second: back to back, four are made.
        for pending in prefetches {
            dns.refresh(pending);
        }
        assert_eq!((dns.prefetched(), dns.prefetches_skipped()), (4, 6));
        until_idle(&dns).await;
        assert_eq!(up.udp_queries(), asked + 4);

        // With nothing out, the bucket alone refuses the next one: it is a fraction of a second
        // since it was emptied.
        dns.refresh(last);
        assert_eq!((dns.prefetched(), dns.prefetches_skipped()), (4, 7));
        sleep(ms(100)).await;
        assert_eq!(up.udp_queries(), asked + 4);
    }

    #[tokio::test]
    async fn no_prefetch_while_questions_are_out() {
        let (dns, up, mut prefetches) = due_prefetches(2, MAX_FORWARDS).await;
        let asked = up.udp_queries();
        // Four questions are out with the upstreams.
        let mut out: Vec<_> = (0..PREFETCH_BUSY)
            .map(|_| dns.forwards.clone().try_acquire_owned().unwrap())
            .collect();
        dns.refresh(prefetches.remove(0));
        assert_eq!((dns.prefetched(), dns.prefetches_skipped()), (0, 1));
        sleep(ms(100)).await;
        assert_eq!(up.udp_queries(), asked);

        // One fewer is out: the next goes, and the skip took no token from the bucket.
        out.pop();
        dns.refresh(prefetches.remove(0));
        assert_eq!((dns.prefetched(), dns.prefetches_skipped()), (1, 1));
        for _ in 0..100 {
            if up.udp_queries() == asked + 1 {
                break;
            }
            sleep(ms(10)).await;
        }
        assert_eq!(up.udp_queries(), asked + 1);
        drop(out);
    }

    #[tokio::test]
    async fn a_stale_refresh_ignores_the_prefetch_budget() {
        let (dns, up, packet) = stale().await;
        // The bucket is empty, as after a burst.
        let now = tokio::time::Instant::now();
        while dns.prefetch_bucket.lock().unwrap().take(now) {}
        assert_eq!(
            ttl(dns.answer(&packet, Transport::Udp).await),
            Some(STALE_TTL)
        );
        for _ in 0..100 {
            if up.udp_queries() == 2 {
                break;
            }
            sleep(ms(10)).await;
        }
        assert_eq!(up.udp_queries(), 2);
        assert_eq!((dns.prefetched(), dns.prefetches_skipped()), (0, 0));
    }

    /// What a prefetch that is skipped costs, which is all that the receive loop pays for it
    /// when the budget is spent: `refresh` of one with an empty bucket, 100,000 times. Run in
    /// release: `cargo test -p qberrypi --release refresh_cost -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore = "a timing measurement: run it in release, on its own"]
    async fn refresh_cost_for_a_skipped_prefetch() {
        const CALLS: u32 = 100_000;
        let (dns, _up, mut prefetches) = due_prefetches(1, MAX_FORWARDS).await;
        let prefetch_pending = prefetches.pop().unwrap();
        let now = tokio::time::Instant::now();
        while dns.prefetch_bucket.lock().unwrap().take(now) {}

        let started = std::time::Instant::now();
        for _ in 0..CALLS {
            dns.refresh(prefetch_pending.clone());
        }
        let per_call = started.elapsed().as_nanos() / u128::from(CALLS);
        // The copy of the question that each call made, which is not the budget's cost.
        let started = std::time::Instant::now();
        for _ in 0..CALLS {
            std::hint::black_box(prefetch_pending.clone());
        }
        let per_clone = started.elapsed().as_nanos() / u128::from(CALLS);
        println!(
            "a skipped prefetch: {per_call} ns per refresh, of which {per_clone} ns the clone"
        );
        // The bucket may earn one token if the run stalls for a quarter of a second.
        assert_eq!(
            dns.prefetched() + dns.prefetches_skipped(),
            u64::from(CALLS)
        );
        assert!(per_call < 5_000, "{per_call} ns");
    }

    /// A client of the documentation range.
    const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));

    /// A service that never asks anything, for the tests of what is offered and what it costs.
    fn quiet() -> Arc<Dns> {
        Dns::new(
            BlockSet::default(),
            Upstreams::with(vec![closed_port()], ms(1), ms(1)),
            Box::new(FixedOffset(0)),
        )
    }

    /// A reply of 60 bytes, as one for `cdn.example.com` with one A record and an OPT record is.
    fn reply_of_sixty_bytes() -> Vec<u8> {
        let mut reply = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 1];
        reply.extend_from_slice(&crate::watch::wire_of("cdn.example.com"));
        reply.extend_from_slice(&[0, 1, 0, 1]);
        // The answer: a pointer to the question, A, IN, a TTL of 300, and an address.
        reply.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 192, 0, 2, 1]);
        // The OPT record: the root, OPT, a payload of 1232, no flags, and no data.
        reply.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
        assert_eq!(reply.len(), 60);
        reply
    }

    #[test]
    fn with_no_watch_set_nothing_is_offered_and_nothing_is_dropped() {
        let dns = quiet();
        dns.observe(CLIENT, &reply_of_sixty_bytes());
        assert_eq!(dns.watch_events_dropped(), 0);
    }

    #[test]
    fn the_first_watch_stays_and_a_second_is_ignored() {
        let dns = quiet();
        let (first, first_events) = watch::feed();
        let (second, second_events) = watch::feed();
        dns.set_watch(Watch::for_test(first, Arc::new(NullSink)));
        dns.set_watch(Watch::for_test(second, Arc::new(NullSink)));
        dns.observe(CLIENT, &reply_of_sixty_bytes());
        assert_eq!(first_events.try_iter().count(), 1);
        assert_eq!(second_events.try_iter().count(), 0);
        // The count that is told is the first feed's: with its receiver gone, offers are drops.
        drop(first_events);
        dns.observe(CLIENT, &reply_of_sixty_bytes());
        assert_eq!(dns.watch_events_dropped(), 1);
    }

    /// The nanoseconds that one call of `observe` took, on average, over `calls` calls with `reply`.
    fn ns_per_observe(dns: &Dns, reply: &[u8], calls: u32) -> f64 {
        let started = std::time::Instant::now();
        for _ in 0..calls {
            dns.observe(black_box(CLIENT), black_box(reply));
        }
        started.elapsed().as_secs_f64() * 1e9 / f64::from(calls)
    }

    /// How many calls the timing tests make.
    const TIMED_CALLS: u32 = 100_000;

    /// Prints the cost of `observe` on a reply of 60 bytes: with no watch, with a feed that a
    /// thread empties as it fills, and with a feed that is full and drops everything. Run it with
    /// `cargo test -p qberrypi --release -- --ignored --nocapture observe_costs_little`.
    #[test]
    #[ignore = "a timing, for reading"]
    fn observe_costs_little() {
        let reply = reply_of_sixty_bytes();

        let unset = quiet();
        // Once to warm up, then the timed run.
        ns_per_observe(&unset, &reply, TIMED_CALLS);
        println!(
            "observe, no watch:        {:8.1} ns per call",
            ns_per_observe(&unset, &reply, TIMED_CALLS)
        );

        let drained = quiet();
        let (feed, events) = watch::feed();
        drained.set_watch(Watch::for_test(feed, Arc::new(NullSink)));
        let drain = std::thread::spawn(move || events.iter().count());
        ns_per_observe(&drained, &reply, TIMED_CALLS);
        let per_call = ns_per_observe(&drained, &reply, TIMED_CALLS);
        println!("observe, drained feed:    {per_call:8.1} ns per call");
        let dropped = drained.watch_events_dropped();
        drop(drained);
        let taken = drain.join().unwrap();
        println!(
            "  (taken {taken} of {} offered, dropped {dropped})",
            2 * TIMED_CALLS
        );

        let full = quiet();
        let (feed, _events) = watch::feed();
        full.set_watch(Watch::for_test(feed, Arc::new(NullSink)));
        ns_per_observe(&full, &reply, TIMED_CALLS);
        println!(
            "observe, full feed:       {:8.1} ns per call",
            ns_per_observe(&full, &reply, TIMED_CALLS)
        );
    }

    // Hot path: every cached, blocked and forwarded answer is offered, and none may wait on it.
    #[test]
    fn observing_an_answer_costs_microseconds_at_most_with_a_watch_or_without() {
        let reply = reply_of_sixty_bytes();
        // The bound is for a debug build on a busy machine: a release build takes well under a
        // microsecond, and the board's cores are a few times slower.
        const MEAN_LIMIT_NS: f64 = 20_000.0;

        let unset = quiet();
        let per_call = ns_per_observe(&unset, &reply, TIMED_CALLS);
        assert!(per_call < MEAN_LIMIT_NS, "{per_call} ns with no watch");

        // Nobody takes the events: the feed fills after 1024 and drops the rest.
        let full = quiet();
        let (feed, events) = watch::feed();
        full.set_watch(Watch::for_test(feed, Arc::new(NullSink)));
        let per_call = ns_per_observe(&full, &reply, TIMED_CALLS);
        assert!(per_call < MEAN_LIMIT_NS, "{per_call} ns with a full feed");
        assert_eq!(
            full.watch_events_dropped(),
            u64::from(TIMED_CALLS) - watch::FEED_CAPACITY as u64
        );
        assert_eq!(events.try_iter().count(), watch::FEED_CAPACITY);
    }

    #[tokio::test]
    async fn a_stale_answer_is_sent_at_once_and_renewed_only_if_a_forward_is_free() {
        // A forward is free: the renewal is made, and the permit comes back.
        let (dns, up, packet) = stale().await;
        assert_eq!(
            ttl(dns.answer(&packet, Transport::Udp).await),
            Some(STALE_TTL)
        );
        for _ in 0..100 {
            if up.udp_queries() == 2 && dns.forwards.available_permits() == 1 {
                break;
            }
            sleep(ms(10)).await;
        }
        assert_eq!(up.udp_queries(), 2);
        // The renewed answer is a fresh one.
        assert!(ttl(dns.answer(&packet, Transport::Udp).await) > Some(STALE_TTL));
        assert_eq!(up.udp_queries(), 2);

        // Every forward is out: the stale answer is sent all the same, and not renewed.
        let (dns, up, packet) = stale().await;
        let _out = dns.forwards.try_acquire().unwrap();
        assert_eq!(
            ttl(dns.answer(&packet, Transport::Udp).await),
            Some(STALE_TTL)
        );
        sleep(ms(100)).await;
        assert_eq!(up.udp_queries(), 1);
    }

    /// The alert for a rebinding answer for `name`, as the sink was given it.
    fn rebind_alert(name: &str, client: Option<IpAddr>) -> super::testutil::Raised {
        ("rebind", "high", client, name.to_owned())
    }

    #[tokio::test]
    async fn the_alert_names_the_client_that_asked_and_none_where_it_is_not_known() {
        let up = FakeUpstream::start(Reply::Answer(ip("10.0.0.1"))).await;
        let dns = Dns::new(
            BlockSet::default(),
            Upstreams::with(vec![up.addr], ms(300), ms(600)),
            Box::new(FixedOffset(0)),
        );
        let sink = Arc::new(RecordingSink::default());
        let (feed, _events) = watch::feed();
        dns.set_watch(Watch::for_test(feed, sink.clone()));
        let asked = |name| client::query(5, name, TYPE_A).unwrap();
        for (name, client) in [("a.example.com", None), ("b.example.com", Some(CLIENT))] {
            let reply = dns
                .answer_for(&asked(name), Transport::Udp, client)
                .await
                .unwrap();
            assert_eq!(
                client::read_answer(&reply, 5).unwrap().summary(),
                "NOERROR 0.0.0.0"
            );
        }
        // `answer` is `answer_for` of no client.
        let reply = dns
            .answer(&asked("c.example.com"), Transport::Tcp)
            .await
            .unwrap();
        assert_eq!(
            client::read_answer(&reply, 5).unwrap().summary(),
            "NOERROR 0.0.0.0"
        );
        // The alerts are raised by tasks that follow the replies.
        tokio::task::yield_now().await;
        assert_eq!(
            sink.raised(),
            [
                rebind_alert("a.example.com", None),
                rebind_alert("b.example.com", Some(CLIENT)),
                rebind_alert("c.example.com", None),
            ]
        );
    }

    #[tokio::test]
    async fn the_rebind_alert_is_raised_by_a_task_after_the_reply_is_made_and_not_before() {
        let up = FakeUpstream::start(Reply::Answer(ip("10.0.0.1"))).await;
        let dns = Dns::new(
            BlockSet::default(),
            Upstreams::with(vec![up.addr], ms(300), ms(600)),
            Box::new(FixedOffset(0)),
        );
        let sink = Arc::new(RecordingSink::default());
        let (feed, _events) = watch::feed();
        dns.set_watch(Watch::for_test(feed, sink.clone()));
        let packet = client::query(5, "a.example.com", TYPE_A).unwrap();
        let reply = dns
            .answer_for(&packet, Transport::Udp, Some(CLIENT))
            .await
            .unwrap();
        assert_eq!(
            client::read_answer(&reply, 5).unwrap().summary(),
            "NOERROR 0.0.0.0"
        );
        // On the runtime's one thread the task has not had its turn: the reply came first.
        assert_eq!(sink.raised(), []);
        tokio::task::yield_now().await;
        assert_eq!(sink.raised(), [rebind_alert("a.example.com", Some(CLIENT))]);
    }

    #[tokio::test]
    async fn a_renewal_that_holds_a_private_address_raises_the_alert_without_a_client() {
        // The answer that is kept came before the watch was set, so it is as the upstream sent it.
        let up = FakeUpstream::start(Reply::Answer(ip("10.0.0.1"))).await;
        let dns = Dns::with_forward_limit(
            BlockSet::default(),
            Upstreams::with(vec![up.addr], ms(300), ms(600)),
            Box::new(FixedOffset(0)),
            2,
        );
        let packet = client::query(5, "example.com", TYPE_A).unwrap();
        assert!(dns.answer(&packet, Transport::Udp).await.is_some());
        let mut dns = Arc::try_unwrap(dns).ok().expect("nothing else holds it");
        dns.started -= Duration::from_secs(100);
        let sink = Arc::new(RecordingSink::default());
        let (feed, _events) = watch::feed();
        dns.set_watch(Watch::for_test(feed, sink.clone()));
        let dns = Arc::new(dns);

        // The stale answer is given at once, and the renewal that it starts is screened.
        let stale = dns
            .answer_for(&packet, Transport::Udp, Some(CLIENT))
            .await
            .unwrap();
        assert_eq!(
            client::read_answer(&stale, 5).unwrap().v4(),
            [ip("10.0.0.1")]
        );
        for _ in 0..100 {
            if !sink.raised().is_empty() {
                break;
            }
            sleep(ms(10)).await;
        }
        assert_eq!(sink.raised(), [rebind_alert("example.com", None)]);
        assert_eq!(up.udp_queries(), 2);
        // What the renewal stored is the zeros.
        let renewed = dns.answer(&packet, Transport::Udp).await.unwrap();
        assert_eq!(
            client::read_answer(&renewed, 5).unwrap().summary(),
            "NOERROR 0.0.0.0"
        );
        assert_eq!(up.udp_queries(), 2);
    }

    /// A `Dns` that denies `deny` and allows `allow`, whose upstream nothing listens at: only
    /// `decide` is called on it. Its lane is set if `lane` is.
    fn offline(deny: &[&str], allow: &[&str], lane: Option<&Arc<LaneFeed>>) -> Arc<Dns> {
        let own = |names: &[&str]| {
            names
                .iter()
                .map(|&name| name.to_owned())
                .collect::<Vec<_>>()
        };
        let dns = Dns::new(
            lists::from_config(&own(deny), &own(allow)).build(),
            Upstreams::with(vec![closed_port()], ms(300), ms(600)),
            Box::new(FixedOffset(0)),
        );
        if let Some(lane) = lane {
            dns.set_lane(lane.clone());
        }
        dns
    }

    /// What `dns` decides for `name` A, as a client asks over UDP.
    fn ask(dns: &Dns, name: &str) -> Action {
        dns.decide(&client::query(1, name, TYPE_A).unwrap(), Transport::Udp)
    }

    /// The names and kinds that `lane` holds, which empties it.
    fn taken(lane: &LaneFeed) -> Vec<(String, NameKind)> {
        let mut out = Vec::new();
        lane.take(&mut out);
        out.into_iter().map(|n| (n.name, n.kind)).collect()
    }

    /// What the lane holds after a `Dns` that denies `deny` and allows `allow` was asked for
    /// `names` in turn, all within one second of its monotonic clock, which is how a name is
    /// sampled. `setup` runs on the `Dns` first. The run is made again if a second ended in it.
    fn lane_after(
        deny: &[&str],
        allow: &[&str],
        setup: impl Fn(&Dns),
        names: &[&str],
    ) -> Vec<(String, NameKind)> {
        loop {
            let lane = LaneFeed::new();
            let dns = offline(deny, allow, Some(&lane));
            setup(&dns);
            let second = dns.now().mono_secs;
            for name in names {
                ask(&dns, name);
            }
            if dns.now().mono_secs == second {
                return taken(&lane);
            }
        }
    }

    /// The pause of 300 seconds, as the panel's key sets it.
    fn pause(dns: &Dns) {
        let until = dns.now().mono_secs + 300;
        dns.resolver().pause_until(until);
    }

    fn named(name: &str, kind: NameKind) -> (String, NameKind) {
        (name.to_owned(), kind)
    }

    #[test]
    fn decide_offers_blocked_and_sampled_names_to_the_lane() {
        // Two asks of each in the same second: the blocked name is offered both times, and the
        // plain one once, at the first ask.
        assert_eq!(
            lane_after(
                &["ads.example.org"],
                &[],
                |_| {},
                &[
                    "ads.example.org",
                    "news.example.org",
                    "ads.example.org",
                    "news.example.org",
                ],
            ),
            [
                named("ads.example.org", NameKind::Refused),
                named("news.example.org", NameKind::Plain),
                named("ads.example.org", NameKind::Refused),
            ]
        );

        // What the resolver does not count is not offered, and the query before it is not
        // offered again for it.
        let lane = LaneFeed::new();
        let dns = offline(&["ads.example.org"], &[], Some(&lane));
        ask(&dns, "ads.example.org");
        assert_eq!(taken(&lane), [named("ads.example.org", NameKind::Refused)]);
        for packet in [&[1, 2, 3][..], &[0; 12][..]] {
            dns.decide(packet, Transport::Udp);
        }
        assert_eq!(dns.resolver().stats().total().queries, 1);
        assert_eq!(taken(&lane), []);
        assert_eq!(lane.dropped(), 0);
    }

    #[test]
    fn a_paused_listed_name_comes_out_listed() {
        let ads = "ads.example.org";
        let (news, ok) = ("news.example.org", "ok.ads.example.org");
        // Blocking on: the listed name is refused.
        assert_eq!(
            lane_after(&[ads], &[ok], |_| {}, &[ads]),
            [named(ads, NameKind::Refused)]
        );
        // Paused, it is let through and the lane says it is on the lists.
        assert_eq!(
            lane_after(&[ads], &[ok], pause, &[ads]),
            [named(ads, NameKind::Listed)]
        );
        // The same for a name under it, and for the name in another spelling than it is listed in.
        assert_eq!(
            lane_after(&[ads], &[ok], pause, &["Sub.ADS.Example.org."]),
            [named("sub.ads.example.org", NameKind::Listed)]
        );
        // A name that is not on the lists, or that the allow rules exempt, is plain.
        assert_eq!(
            lane_after(&[ads], &[ok], pause, &[news]),
            [named(news, NameKind::Plain)]
        );
        assert_eq!(
            lane_after(&[ads], &[ok], pause, &[ok]),
            [named(ok, NameKind::Plain)]
        );
        // A pause that ends: the name is refused again.
        assert_eq!(
            lane_after(
                &[ads],
                &[ok],
                |dns| {
                    pause(dns);
                    dns.resolver().resume();
                },
                &[ads]
            ),
            [named(ads, NameKind::Refused)]
        );
    }

    #[test]
    fn no_lane_no_offer() {
        // A `Dns` with no lane answers as ever; a feed that it was not given stays empty.
        let lane = LaneFeed::new();
        let dns = offline(&["ads.example.org"], &[], None);
        assert!(matches!(ask(&dns, "ads.example.org"), Action::Reply(_)));
        assert!(matches!(ask(&dns, "news.example.org"), Action::Forward(_)));
        assert_eq!(taken(&lane), []);
        assert_eq!(lane.dropped(), 0);

        // The first lane that is set stays.
        let (first, second) = (LaneFeed::new(), LaneFeed::new());
        let dns = offline(&["ads.example.org"], &[], Some(&first));
        dns.set_lane(second.clone());
        ask(&dns, "ads.example.org");
        assert_eq!(taken(&second), []);
        assert_eq!(taken(&first), [named("ads.example.org", NameKind::Refused)]);
    }

    /// Calls of `decide` in one timed batch of [`decide_cost_with_and_without_the_lane`].
    const BATCH: usize = 2_000;
    /// Timed batches on each side: 200,000 calls of `decide` on a `Dns`.
    const BATCHES: usize = 100;

    /// The ns per call of `decide` on `packet` over one batch. With `room`, the lane is emptied
    /// every eight calls, so that a refused name finds room in it; without, it is full for most
    /// of the run, and the names are dropped.
    fn batch_ns(dns: &Dns, packet: &[u8], room: Option<&LaneFeed>) -> f64 {
        let started = Instant::now();
        for call in 0..BATCH {
            if let Some(lane) = room.filter(|_| call % 8 == 0) {
                lane.clear();
            }
            black_box(dns.decide(black_box(packet), Transport::Udp));
        }
        started.elapsed().as_nanos() as f64 / BATCH as f64
    }

    /// The median of `times`.
    fn median(mut times: Vec<f64>) -> f64 {
        times.sort_by(f64::total_cmp);
        times[times.len() / 2]
    }

    /// Run in release: `cargo test -p qberrypi --release decide_cost -- --ignored --nocapture`.
    ///
    /// The cost that the lane adds to `decide`, which runs on the listener's receive loop: for a
    /// cached, a blocked and a forwarded name, on a `Dns` that has no lane and on one that has.
    /// The two take turns in batches of 2,000 calls, the one that goes first changing every time,
    /// and each is given by the median of its batches, so that what drifts on the host drifts for
    /// both and a spike counts for little.
    #[ignore = "a timing, for release builds"]
    #[tokio::test]
    async fn decide_cost_with_and_without_the_lane() {
        const ALLOWED_NS: f64 = 200.0;

        let up = FakeUpstream::start(Reply::Answer(ip("192.0.2.10"))).await;
        let upstreams = || Upstreams::with(vec![up.addr], ms(300), ms(600));
        let denied = || lists::from_config(&["ads.example.org".to_owned()], &[]).build();
        let bare = Dns::new(denied(), upstreams(), Box::new(FixedOffset(0)));
        let lane = LaneFeed::new();
        let fed = Dns::new(denied(), upstreams(), Box::new(FixedOffset(0)));
        fed.set_lane(lane.clone());

        // The cached name is asked once, so that the upstream's answer is in the cache.
        let cached = client::query(5, "cached.example.org", TYPE_A).unwrap();
        for dns in [&bare, &fed] {
            assert!(dns.answer(&cached, Transport::Udp).await.is_some());
        }
        let blocked = client::query(6, "ads.example.org", TYPE_A).unwrap();
        let forwarded = client::query(7, "elsewhere.example.org", TYPE_A).unwrap();
        for dns in [&bare, &fed] {
            assert!(matches!(
                dns.decide(&cached, Transport::Udp),
                Action::Reply(_)
            ));
            assert!(matches!(
                dns.decide(&blocked, Transport::Udp),
                Action::Reply(_)
            ));
            assert!(matches!(
                dns.decide(&forwarded, Transport::Udp),
                Action::Forward(_)
            ));
        }

        println!("decide, median ns per query over {BATCHES} batches of {BATCH} on each side:");
        println!("{:<28}{:>10}{:>10}{:>9}", "", "no lane", "lane", "adds");
        let cases: [(&str, &[u8], Option<&LaneFeed>); 4] = [
            ("cached", &cached, None),
            ("blocked, lane full", &blocked, None),
            ("blocked, room in the lane", &blocked, Some(&*lane)),
            ("forwarded", &forwarded, None),
        ];
        for (label, packet, room) in cases {
            let (mut without, mut with) = (Vec::new(), Vec::new());
            for batch in 0..BATCHES {
                if batch % 2 == 0 {
                    without.push(batch_ns(&bare, packet, None));
                    with.push(batch_ns(&fed, packet, room));
                } else {
                    with.push(batch_ns(&fed, packet, room));
                    without.push(batch_ns(&bare, packet, None));
                }
            }
            let (without, with) = (median(without), median(with));
            let adds = with - without;
            println!("{label:<28}{without:>10.0}{with:>10.0}{adds:>+9.0}");
            assert!(
                adds < ALLOWED_NS,
                "{label}: the lane adds {adds:.0} ns a query, which is over {ALLOWED_NS}"
            );
        }

        // The hook by itself, for a blocked name that finds room: what `decide` does after the
        // resolver has decided, with the ring emptied every eight calls.
        fed.decide(&blocked, Transport::Udp);
        let started = Instant::now();
        let now = fed.now();
        let resolver = fed.resolver();
        let queries = resolver.stats().total().queries;
        for call in 0..BATCH * BATCHES {
            if call % 8 == 0 {
                lane.clear();
            }
            // One query fewer than counted: a new one is there to offer.
            lane.offer_latest(&resolver, black_box(queries - 1), now);
        }
        let hook = started.elapsed().as_nanos() as f64 / (BATCH * BATCHES) as f64;
        println!("the hook alone, blocked, room in the lane: {hook:.0} ns");
    }

    /// The ns per call of `decide_from` on `packet`, asked by `client`, over one batch.
    fn batch_ns_from(dns: &Dns, packet: &[u8], client: Option<IpAddr>) -> f64 {
        let started = Instant::now();
        for _ in 0..BATCH {
            black_box(dns.decide_from(black_box(packet), Transport::Udp, black_box(client)));
        }
        started.elapsed().as_nanos() as f64 / BATCH as f64
    }

    /// Run in release:
    /// `cargo test -p qberrypi --release -- --ignored decide_cost_with_an_exempt_set --nocapture`.
    ///
    /// The cost that the exemption adds to `decide`, which runs on the listener's receive loop:
    /// for a cached, a blocked and a forwarded name, asked by this program (no client, so no
    /// check); in the list mode by a client with the set empty, and with 64 addresses in the set
    /// by a client that is not one of them and by one that is; and in the exempt-by-default mode
    /// by a client with the blocked set empty, and with 64 addresses in it by one of them and by
    /// one that is not. An exempt client's "blocked" name is an ad, so it is let through and
    /// forwarded. The seven take turns in batches of 2,000 calls, the one that goes first
    /// changing every time, and each is the median of its batches.
    #[ignore = "a timing, for release builds"]
    #[tokio::test]
    async fn decide_cost_with_an_exempt_set() {
        const ALLOWED_NS: f64 = 200.0;

        let up = FakeUpstream::start(Reply::Answer(ip("192.0.2.10"))).await;
        let upstreams = || Upstreams::with(vec![up.addr], ms(300), ms(600));
        let denied = || lists::from_config(&["ads.example.org".to_owned()], &[]).build();
        let make = || Dns::new(denied(), upstreams(), Box::new(FixedOffset(0)));
        let (empty, full, open, guarded) = (make(), make(), make(), make());
        let set: Vec<Ipv4Addr> = (1..=64)
            .map(|host| Ipv4Addr::new(192, 0, 2, host))
            .collect();
        full.exempt().listed().replace(&set);
        assert_eq!(full.exempt().listed().len(), 64);
        open.exempt().set_by_default(true);
        guarded.exempt().blocked().replace(&set);
        guarded.exempt().set_by_default(true);
        let (other, exempt) = (client(200), client(33));

        let cached = client::query(5, "cached.example.org", TYPE_A).unwrap();
        for dns in [&empty, &full, &open, &guarded] {
            assert!(dns.answer(&cached, Transport::Udp).await.is_some());
        }
        let blocked = client::query(6, "ads.example.org", TYPE_A).unwrap();
        let forwarded = client::query(7, "elsewhere.example.org", TYPE_A).unwrap();
        for (dns, from, forwards) in [
            (&full, other, false),
            (&full, exempt, true),
            (&open, other, true),
            (&guarded, exempt, false),
            (&guarded, other, true),
        ] {
            let action = dns.decide_from(&blocked, Transport::Udp, from);
            assert_eq!(matches!(action, Action::Forward(_)), forwards, "{from:?}");
        }

        println!("decide, median ns per query over {BATCHES} batches of {BATCH}:");
        println!(
            "{:<11}{:>11}{:>11}{:>11}{:>11}{:>11}{:>11}{:>11}",
            "",
            "no client",
            "list empty",
            "64, other",
            "64, exempt",
            "dflt empty",
            "64, block",
            "64, other"
        );
        let columns: [(&Dns, Option<IpAddr>); 7] = [
            (&empty, None),
            (&empty, other),
            (&full, other),
            (&full, exempt),
            (&open, other),
            (&guarded, exempt),
            (&guarded, other),
        ];
        let rows: [(&str, &[u8]); 3] = [
            ("cached", &cached),
            ("blocked", &blocked),
            ("forwarded", &forwarded),
        ];
        for (label, packet) in rows {
            let mut times: [Vec<f64>; 7] = Default::default();
            for batch in 0..BATCHES {
                for turn in 0..columns.len() {
                    let column = (batch + turn) % columns.len();
                    let (dns, from) = columns[column];
                    times[column].push(batch_ns_from(dns, packet, from));
                }
            }
            let [none, empty_set, miss, hit, open_ns, held, free] = times.map(median);
            println!(
                "{label:<11}{none:>11.0}{empty_set:>11.0}{miss:>11.0}{hit:>11.0}{open_ns:>11.0}{held:>11.0}{free:>11.0}"
            );
            // A check that leaves the client held to every list may add little: the list mode's
            // empty set and its miss, and the blocked client of the exempt-by-default mode.
            for (adds, what) in [
                (empty_set - none, "list empty"),
                (miss - none, "64, other"),
                (held - none, "default, 64, blocked"),
            ] {
                assert!(
                    adds < ALLOWED_NS,
                    "{label}, {what}: the check adds {adds:.0} ns a query, which is over {ALLOWED_NS}"
                );
            }
        }

        // The check by itself: `is_exempt` in the list mode on an empty set, and on the set of
        // 64 for an address that is not in it and one that is; and in the exempt-by-default mode
        // on an empty blocked set, and on the set of 64 for an address in it and one that is not.
        let calls = BATCH * BATCHES;
        let check_ns = |exemption: &Exemption, addr: IpAddr| {
            let started = Instant::now();
            for _ in 0..calls {
                black_box(exemption.is_exempt(black_box(addr)));
            }
            started.elapsed().as_nanos() as f64 / calls as f64
        };
        let (other, exempt) = (other.unwrap(), exempt.unwrap());
        println!(
            "is_exempt alone, list mode: set empty {:.1} ns, 64 and not in it {:.1} ns, 64 and in it {:.1} ns",
            check_ns(empty.exempt(), other),
            check_ns(full.exempt(), other),
            check_ns(full.exempt(), exempt),
        );
        println!(
            "is_exempt alone, exempt by default: set empty {:.1} ns, 64 and in it {:.1} ns, 64 and not in it {:.1} ns",
            check_ns(open.exempt(), other),
            check_ns(guarded.exempt(), exempt),
            check_ns(guarded.exempt(), other),
        );
    }
}
