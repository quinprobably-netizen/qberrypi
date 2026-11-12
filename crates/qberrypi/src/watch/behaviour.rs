//! The behaviour detectors: what a client's questions say about the client.
//!
//! Four detectors watch each client: random-looking names that do not exist (`dga`), data
//! smuggled in names or in TXT and NULL questions (`tunnel`), one name asked at a steady pace for
//! hours (`beacon`) and a minute with far more questions than usual (`burst`). The questions come
//! in one by one with the time that the analysis gave them; nothing here reads a clock, does I/O
//! or logs, so a name or a client never reaches a log line from this file.
//!
//! The state is bounded however much is asked: at most [`MAX_CLIENTS`] clients, the least
//! recently seen leaving first, and for each client at most [`DGA_NAMES`] name hashes for the
//! random-name count, [`TUNNEL_DOMAINS`] domains of [`TUNNEL_HASHES`] name hashes each for the
//! long names, ten minute buckets for the TXT share, [`BEACON_SLOTS`] names for the beaconing and
//! one record of counts for the bursts. Names are kept as 64-bit hashes (FNV-1a), never as text.
//!
//! A name with a byte that no host name has, as a tunnel's Base64 or Base128 labels have, is read
//! leniently (see [`names::decode_lenient`]): it counts for the bursts, for the TXT and NULL
//! share and for the long names, and the random-name count and the beaconing skip it.
//!
//! A detector that has raised an alert keeps quiet for the same client and the same subject until
//! its window has passed, so a flood of questions over a threshold is one call to `raise` and not
//! one per question. The store merges repeats as well, but it should not have to.

use std::net::IpAddr;

use super::{Event, names};
use crate::alerts::{Alert, Severity};

/// How many clients are tracked; the one seen longest ago leaves for the next.
pub const MAX_CLIENTS: usize = 128;

/// The kind of alert for random-looking names that do not exist.
const KIND_DGA: &str = "dga";
/// The kind of alert for data in names or in TXT and NULL questions.
const KIND_TUNNEL: &str = "tunnel";
/// The kind of alert for one name asked at a steady pace.
const KIND_BEACON: &str = "beacon";
/// The kind of alert for a minute of far more questions than usual.
const KIND_BURST: &str = "burst";

/// What a `dga` alert is about: there is no one name.
const DGA_SUBJECT: &str = "random NXDOMAIN names";
/// What a `tunnel` alert for the TXT and NULL share is about.
const SHARE_SUBJECT: &str = "TXT/NULL share";
/// What a `burst` alert is about.
const BURST_SUBJECT: &str = "question rate";

/// The response code of a name that does not exist.
const RCODE_NXDOMAIN: u8 = 3;
/// The type of a NULL question.
const QTYPE_NULL: u16 = 10;
/// The type of a TXT question.
const QTYPE_TXT: u16 = 16;

/// The length of a minute, in milliseconds.
const MINUTE_MS: u64 = 60_000;
/// The length of an hour, in milliseconds.
const HOUR_MS: u64 = 3_600_000;

/// How long the window of the random-name count is, in milliseconds.
pub const DGA_WINDOW_MS: u64 = 300_000;
/// How many different random-looking names that do not exist, in one window, raise `dga`. It is
/// also how many hashes are kept for the count.
pub const DGA_NAMES: usize = 25;

/// How long the window of the long-name and the TXT count is, in milliseconds.
pub const TUNNEL_WINDOW_MS: u64 = 600_000;
/// How many different names under one registrable domain, in one window, raise `tunnel` when each
/// of them has [`TUNNEL_LEFT_MIN`] bytes or more left of the domain.
pub const TUNNEL_NAMES: usize = 40;
/// How many bytes of a name left of its registrable domain make it a long name.
pub const TUNNEL_LEFT_MIN: usize = 40;
/// How many bytes of a name left of its registrable domain make it a long name when a label of it
/// has a byte that no host name has: text that is not text is a tunnel's mark, and a shorter part
/// is enough.
pub const TUNNEL_ODD_LEFT_MIN: usize = 20;
/// How many registrable domains of long names are tracked for a client.
pub const TUNNEL_DOMAINS: usize = 8;
/// How many name hashes are kept for one registrable domain.
pub const TUNNEL_HASHES: usize = 64;
/// How many TXT and NULL questions, in one window, raise `tunnel` when they are at least half of
/// the client's questions.
pub const TUNNEL_TXT_MIN: u32 = 100;
/// How many minute buckets the window of the TXT and NULL count is made of.
const SHARE_MINUTES: usize = 10;
// The buckets make the window of the long names too.
const _: () = assert!(SHARE_MINUTES as u64 * MINUTE_MS == TUNNEL_WINDOW_MS);
// A domain that is kept holds more hashes than it takes to raise.
const _: () = assert!(TUNNEL_HASHES > TUNNEL_NAMES);

/// How many names are tracked for beaconing for a client.
pub const BEACON_SLOTS: usize = 32;
/// How many times a name is asked, at the least, to raise `beacon`.
pub const BEACON_MIN_ASKS: u32 = 30;
/// How long a name has been asked, at the least, to raise `beacon`: three hours, in milliseconds.
pub const BEACON_MIN_SPAN_MS: u64 = 3 * HOUR_MS;
/// The shortest mean interval of a beacon, in seconds.
pub const BEACON_MEAN_MIN_SECS: f64 = 30.0;
/// The longest mean interval of a beacon, in seconds: an hour.
pub const BEACON_MEAN_MAX_SECS: f64 = 3600.0;
/// The largest coefficient of variation of the intervals of a beacon: how steady the pace is.
pub const BEACON_CV_MAX: f64 = 0.1;
/// An interval from this many times the TTL that the asker was given is the asker's cache running
/// out, not a beacon.
pub const BEACON_TTL_LOW: f64 = 0.8;
/// An interval up to this many times the TTL that the asker was given is the asker's cache running
/// out, not a beacon.
pub const BEACON_TTL_HIGH: f64 = 1.25;
/// A question this soon after the last one counted for the name is the same ask: the A and the
/// AAAA of one lookup. In milliseconds.
pub const BEACON_REPEAT_MS: u64 = 2000;
/// An interval this many times the mean, or one that is this many times shorter, breaks the
/// pace: the statistics of the name start over.
const BEACON_BREAK: f64 = 3.0;
/// A name that was asked this many times in a regular pace is kept in its slot against new names
/// until it has not been seen for twice its mean interval.
const BEACON_KEEP_ASKS: u32 = 10;
/// How steady a pace is for a name to be kept in its slot: an earlier estimate than the limit of
/// a beacon, and so wider.
const BEACON_KEEP_CV: f64 = 0.25;
/// How many mean intervals a kept name may not be seen for before a new name takes its slot.
const BEACON_KEEP_INTERVALS: f64 = 2.0;
/// The names whose steady asking is no beacon: time servers, checks that a network has an
/// Internet, and push services. A name is skipped when it is one of these or below one.
const BEACON_SKIP: [&str; 17] = [
    "pool.ntp.org",
    "ntp.org",
    "time.apple.com",
    "time.windows.com",
    "time.google.com",
    "time.cloudflare.com",
    "connectivitycheck.gstatic.com",
    "connectivitycheck.android.com",
    "clients3.google.com",
    "captive.apple.com",
    "msftconnecttest.com",
    "msftncsi.com",
    "detectportal.firefox.com",
    "nmcheck.gnome.org",
    "mtalk.google.com",
    "push.apple.com",
    "courier.push.apple.com",
];

/// How many questions a minute needs, at the least, to be a burst.
pub const BURST_FLOOR: u32 = 300;
/// How many times its usual rate a minute needs to be a burst.
pub const BURST_TIMES: f64 = 10.0;
/// How long a client has been seen before its bursts count: ten minutes, in milliseconds.
pub const BURST_ARM_MS: u64 = 10 * MINUTE_MS;
/// The share of the new minute in the usual rate: one in this many.
const BURST_EWMA_DIVISOR: f64 = 8.0;
/// How many minutes that nothing was asked in are counted, at the most, when a minute begins.
const BURST_CATCH_UP: u64 = 60;

/// The behaviour detectors for all clients.
pub struct Behaviour {
    /// The names whose questions are not looked at: a question for one of these, or for a name
    /// below one, is skipped by every detector.
    quiet: Vec<String>,
    /// The clients that are tracked, at most [`MAX_CLIENTS`], in no order.
    clients: Vec<Client>,
}

impl Behaviour {
    /// Detectors that skip the questions under the names of `quiet`: the owner's "marked as fine".
    ///
    /// Each name is made lower-case and loses a trailing dot; an empty one is dropped.
    pub fn new(quiet: Vec<String>) -> Self {
        let quiet = quiet
            .into_iter()
            .map(|name| name.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|name| !name.is_empty())
            .collect();
        Self {
            quiet,
            clients: Vec::new(),
        }
    }

    /// Takes one question's answer, as the analysis sees it at `now_ms`, which is monotonic
    /// milliseconds, and calls `raise` for each alert that it makes.
    ///
    /// An event whose name has no shape of a name, or that is under a quiet name, is skipped. The
    /// names of the household's own, those that [`names::is_local`] says, count for the bursts of
    /// questions and for nothing else.
    ///
    /// A name with a byte that no host name has, such as the labels of a tunnel in Base64 or
    /// Base128, counts for the bursts, for the share of TXT and NULL questions and for the long
    /// names, which is what it is made for; the random-name count and the beaconing skip it.
    pub fn observe(&mut self, event: &Event, now_ms: u64, raise: &mut impl FnMut(Alert)) {
        let mut buf = [0u8; names::NAME_TEXT_MAX];
        let wire = event.name_wire();
        if let Some(name) = names::decode(wire, &mut buf) {
            if self.is_quiet(name) {
                return;
            }
            let at = self.client_at(event.client, now_ms);
            self.clients[at].observe(name, event, now_ms, raise);
            return;
        }
        let Some(odd) = names::decode_lenient(wire, &mut buf) else {
            return;
        };
        if self.is_quiet(odd.text) {
            return;
        }
        let at = self.client_at(event.client, now_ms);
        self.clients[at].observe_odd(&odd, event, now_ms, raise);
    }

    /// Whether `name`, as text, is one of the quiet names or below one.
    fn is_quiet(&self, name: &str) -> bool {
        self.quiet.iter().any(|quiet| names::under(name, quiet))
    }

    /// Where the record of `addr` is in the table, which it enters if it was not there: at the end
    /// while there is room, and in place of the client seen longest ago when there is not.
    fn client_at(&mut self, addr: IpAddr, now_ms: u64) -> usize {
        if let Some(at) = self.clients.iter().position(|client| client.addr == addr) {
            return at;
        }
        if self.clients.len() < MAX_CLIENTS {
            self.clients.push(Client::new(addr, now_ms));
            return self.clients.len() - 1;
        }
        let oldest = self
            .clients
            .iter()
            .enumerate()
            .min_by_key(|(_, client)| client.last_ms)
            .map_or(0, |(at, _)| at);
        self.clients[oldest] = Client::new(addr, now_ms);
        oldest
    }
}

/// What is known of one client.
struct Client {
    /// The client's address.
    addr: IpAddr,
    /// When a question of the client was seen last.
    last_ms: u64,
    /// The different random-looking names that do not exist, lately.
    dga: Recent,
    /// Until when `dga` is not raised again for this client.
    dga_quiet_until_ms: u64,
    /// The registrable domains of long names, at most [`TUNNEL_DOMAINS`].
    domains: Vec<Domain>,
    /// How many of the questions lately were TXT or NULL.
    share: Share,
    /// The names that are tracked for beaconing, at most [`BEACON_SLOTS`].
    slots: Vec<Slot>,
    /// The counts of questions by the minute.
    burst: Burst,
}

impl Client {
    /// A client that is seen for the first time at `now_ms`.
    fn new(addr: IpAddr, now_ms: u64) -> Self {
        Self {
            addr,
            last_ms: now_ms,
            dga: Recent::default(),
            dga_quiet_until_ms: 0,
            domains: Vec::new(),
            share: Share::default(),
            slots: Vec::new(),
            burst: Burst::new(now_ms),
        }
    }

    /// Takes one question of the client, whose name is `name`, to each of the detectors.
    fn observe(&mut self, name: &str, event: &Event, now_ms: u64, raise: &mut impl FnMut(Alert)) {
        self.last_ms = self.last_ms.max(now_ms);
        let addr = self.addr;
        if self.burst.ask(now_ms) {
            raise(alert(KIND_BURST, Severity::Warn, addr, BURST_SUBJECT));
        }
        if names::is_local(name) {
            return;
        }
        let registrable = names::registrable(name);
        if event.rcode == RCODE_NXDOMAIN && self.random_name(registrable, now_ms) {
            raise(alert(KIND_DGA, Severity::High, addr, DGA_SUBJECT));
        }
        // The dot that joins the part left of the domain to the domain is not part of it.
        let left = name.len().saturating_sub(registrable.len() + 1);
        if left >= TUNNEL_LEFT_MIN && self.long_name(registrable, fnv(name.as_bytes()), now_ms) {
            raise(alert(KIND_TUNNEL, Severity::High, addr, registrable));
        }
        if self.share.ask(event.qtype, now_ms) {
            raise(alert(KIND_TUNNEL, Severity::High, addr, SHARE_SUBJECT));
        }
        if !BEACON_SKIP.iter().any(|skip| names::under(name, skip))
            && self.beacon(name, event.ttl, now_ms)
        {
            raise(alert(KIND_BEACON, Severity::Info, addr, name));
        }
    }

    /// Notes a name that does not exist, of the registrable domain `registrable`, and says whether
    /// there are enough of them now to raise `dga`.
    ///
    /// Only a domain whose own label looks random counts, and each domain counts once: a program
    /// that makes up names makes up domains, not hosts below one.
    fn random_name(&mut self, registrable: &str, now_ms: u64) -> bool {
        let label = registrable.split('.').next().unwrap_or(registrable);
        if !names::looks_random(label) {
            return false;
        }
        let count = self.dga.note(
            fnv(registrable.as_bytes()),
            now_ms,
            DGA_WINDOW_MS,
            DGA_NAMES,
        );
        if count >= DGA_NAMES && now_ms >= self.dga_quiet_until_ms {
            self.dga_quiet_until_ms = now_ms.saturating_add(DGA_WINDOW_MS);
            return true;
        }
        false
    }

    /// Takes one question of the client whose name has a byte that no host name has, which
    /// [`names::decode_lenient`] read: to the bursts, the share of TXT and NULL questions and the
    /// long names. Random names and beacons are about names that one can read, and are skipped.
    fn observe_odd(
        &mut self,
        odd: &names::Lenient<'_, '_>,
        event: &Event,
        now_ms: u64,
        raise: &mut impl FnMut(Alert),
    ) {
        self.last_ms = self.last_ms.max(now_ms);
        let addr = self.addr;
        if self.burst.ask(now_ms) {
            raise(alert(KIND_BURST, Severity::Warn, addr, BURST_SUBJECT));
        }
        if names::is_local(odd.text) {
            return;
        }
        // The names are told apart by the bytes of the part left of the domain, as they came.
        let long = odd.left_len() >= TUNNEL_LEFT_MIN
            || (odd.left_odd && odd.left_len() >= TUNNEL_ODD_LEFT_MIN);
        if let Some(registrable) = odd.registrable
            && long
            && self.long_name(registrable, fnv(odd.left), now_ms)
        {
            raise(alert(KIND_TUNNEL, Severity::High, addr, registrable));
        }
        if self.share.ask(event.qtype, now_ms) {
            raise(alert(KIND_TUNNEL, Severity::High, addr, SHARE_SUBJECT));
        }
    }

    /// Notes a long name, whose registrable domain is `registrable` and which `name` tells from
    /// others (a hash of what is left of the domain), and says whether there are enough long names
    /// under the domain now to raise `tunnel`.
    fn long_name(&mut self, registrable: &str, name: u64, now_ms: u64) -> bool {
        let domain = fnv(registrable.as_bytes());
        let at = match self.domains.iter().position(|d| d.hash == domain) {
            Some(at) => at,
            None if self.domains.len() < TUNNEL_DOMAINS => {
                self.domains.push(Domain::new(domain));
                self.domains.len() - 1
            }
            None => {
                let oldest = self
                    .domains
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, d)| d.last_ms)
                    .map_or(0, |(at, _)| at);
                self.domains[oldest] = Domain::new(domain);
                oldest
            }
        };
        let entry = &mut self.domains[at];
        entry.last_ms = now_ms;
        let count = entry
            .names
            .note(name, now_ms, TUNNEL_WINDOW_MS, TUNNEL_HASHES);
        if count >= TUNNEL_NAMES && now_ms >= entry.quiet_until_ms {
            entry.quiet_until_ms = now_ms.saturating_add(TUNNEL_WINDOW_MS);
            return true;
        }
        false
    }

    /// Notes one more ask for `name`, with the TTL `ttl` of its answer, and says whether the name
    /// is a beacon now.
    fn beacon(&mut self, name: &str, ttl: u32, now_ms: u64) -> bool {
        let hash = fnv(name.as_bytes());
        if let Some(slot) = self.slots.iter_mut().find(|slot| slot.name == hash) {
            return slot.ask(ttl, now_ms);
        }
        let slot = Slot::new(hash, ttl, now_ms);
        if self.slots.len() < BEACON_SLOTS {
            self.slots.push(slot);
            return false;
        }
        // The slot that was seen longest ago, among those that may be taken.
        let taken = self
            .slots
            .iter()
            .enumerate()
            .filter(|(_, slot)| !slot.is_kept(now_ms))
            .min_by_key(|(_, slot)| slot.seen_ms)
            .map(|(at, _)| at);
        if let Some(at) = taken {
            self.slots[at] = slot;
        }
        false
    }
}

/// The alert of `kind` and `severity` for `client` about `subject`.
fn alert(kind: &'static str, severity: Severity, client: IpAddr, subject: &str) -> Alert {
    Alert {
        kind,
        severity,
        client: Some(client),
        subject: subject.to_owned(),
    }
}

/// Whether an interval of `interval` seconds is from 0.8 to 1.25 times `ttl`: the asker came back
/// when its cache ran out. A TTL of 0 is never that: nothing was to be kept.
fn within_ttl(interval: f64, ttl: u32) -> bool {
    ttl > 0
        && interval >= BEACON_TTL_LOW * f64::from(ttl)
        && interval <= BEACON_TTL_HIGH * f64::from(ttl)
}

/// FNV-1a with 64 bits over `bytes`.
fn fnv(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// How long `ms` milliseconds are, in seconds. A span of more than 49 days counts as 49 days.
fn secs(ms: u64) -> f64 {
    f64::from(u32::try_from(ms).unwrap_or(u32::MAX)) / 1000.0
}

/// The hashes of the different things that were seen lately, each with when it was seen last.
#[derive(Default)]
struct Recent {
    /// The hashes and the milliseconds that they were seen at, in no order.
    seen: Vec<(u64, u64)>,
}

impl Recent {
    /// Notes that `hash` was seen at `now_ms`, forgets what was seen `window_ms` ago or longer,
    /// and gives how many different hashes are held. At most `cap` are held: with a new one and no
    /// room, the one seen longest ago leaves.
    fn note(&mut self, hash: u64, now_ms: u64, window_ms: u64, cap: usize) -> usize {
        self.seen
            .retain(|&(_, at)| now_ms.saturating_sub(at) < window_ms);
        if let Some(entry) = self.seen.iter_mut().find(|(seen, _)| *seen == hash) {
            entry.1 = now_ms;
        } else {
            if self.seen.len() >= cap {
                let oldest = self
                    .seen
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, (_, at))| *at)
                    .map_or(0, |(at, _)| at);
                self.seen.swap_remove(oldest);
            }
            self.seen.push((hash, now_ms));
        }
        self.seen.len()
    }
}

/// The long names that were asked under one registrable domain.
struct Domain {
    /// The hash of the registrable domain.
    hash: u64,
    /// When a long name under the domain was asked last.
    last_ms: u64,
    /// Until when `tunnel` is not raised again for the domain.
    quiet_until_ms: u64,
    /// The different long names asked lately, at most [`TUNNEL_HASHES`].
    names: Recent,
}

impl Domain {
    /// A domain with no names yet.
    fn new(hash: u64) -> Self {
        Self {
            hash,
            last_ms: 0,
            quiet_until_ms: 0,
            names: Recent::default(),
        }
    }
}

/// The questions of one client in the last ten minutes, counted by the minute.
#[derive(Default)]
struct Share {
    /// The buckets, one for each minute of the window: minute `m` is in bucket `m % 10`.
    minutes: [Minute; SHARE_MINUTES],
    /// Until when the share is not raised again.
    quiet_until_ms: u64,
}

/// The counts of one minute.
#[derive(Default, Clone, Copy)]
struct Minute {
    /// Which minute: the monotonic milliseconds divided by 60 000.
    minute: u64,
    /// How many questions were asked in it.
    asked: u32,
    /// How many of them were TXT or NULL.
    odd: u32,
}

impl Share {
    /// Counts one question of the type `qtype` at `now_ms`, and says whether the TXT and NULL
    /// questions of the window are now [`TUNNEL_TXT_MIN`] or more and at least half of all.
    ///
    /// The window is the ten minutes up to and with the minute of `now_ms`: between 9 and 10
    /// minutes long.
    fn ask(&mut self, qtype: u16, now_ms: u64) -> bool {
        let minute = now_ms / MINUTE_MS;
        let odd = qtype == QTYPE_TXT || qtype == QTYPE_NULL;
        let bucket = usize::try_from(minute % SHARE_MINUTES as u64).unwrap_or(0);
        let slot = &mut self.minutes[bucket];
        if slot.minute != minute {
            *slot = Minute {
                minute,
                asked: 0,
                odd: 0,
            };
        }
        slot.asked = slot.asked.saturating_add(1);
        if odd {
            slot.odd = slot.odd.saturating_add(1);
        }
        if !odd {
            return false;
        }
        let (mut asked, mut odds) = (0u32, 0u32);
        for held in &self.minutes {
            if held.minute <= minute && minute - held.minute < SHARE_MINUTES as u64 {
                asked = asked.saturating_add(held.asked);
                odds = odds.saturating_add(held.odd);
            }
        }
        if odds >= TUNNEL_TXT_MIN
            && odds.saturating_mul(2) >= asked
            && now_ms >= self.quiet_until_ms
        {
            self.quiet_until_ms = now_ms.saturating_add(TUNNEL_WINDOW_MS);
            return true;
        }
        false
    }
}

/// One name that is tracked for beaconing: when it was asked and how steady the pace is.
struct Slot {
    /// The hash of the name.
    name: u64,
    /// When the pace that is measured now began.
    first_ms: u64,
    /// When the name was last asked, not counting a repeat.
    last_ms: u64,
    /// When a question for the name was seen last, repeats included.
    seen_ms: u64,
    /// How many times the name was asked in the pace that is measured now.
    asks: u32,
    /// The mean interval between the asks, in seconds (Welford's).
    mean: f64,
    /// The sum of the squares of the differences of the intervals from their mean (Welford's).
    m2: f64,
    /// The TTL that the answer to the previous ask had, and 0 for none: what the asker was told
    /// about how long it may keep the answer. Of the A and the AAAA of one lookup, the larger.
    last_ttl: u32,
    /// How many intervals of the pace that is measured now were counted.
    intervals: u32,
    /// How many of those intervals were from 0.8 to 1.25 times the TTL that the asker was given
    /// before: it asked again as its cache ran out.
    cache_intervals: u32,
    /// Until when the name is not raised again.
    quiet_until_ms: u64,
}

impl Slot {
    /// A slot for the name with the hash `name`, asked for the first time at `now_ms`.
    fn new(name: u64, ttl: u32, now_ms: u64) -> Self {
        Self {
            name,
            first_ms: now_ms,
            last_ms: now_ms,
            seen_ms: now_ms,
            asks: 1,
            mean: 0.0,
            m2: 0.0,
            last_ttl: ttl,
            intervals: 0,
            cache_intervals: 0,
            quiet_until_ms: 0,
        }
    }

    /// Begins the pace again, with this ask as its first.
    fn restart(&mut self, ttl: u32, now_ms: u64) {
        let quiet_until_ms = self.quiet_until_ms;
        *self = Slot::new(self.name, ttl, now_ms);
        self.quiet_until_ms = quiet_until_ms;
    }

    /// Takes one more question for the name, at `now_ms` and with the answer's TTL `ttl`, and says
    /// whether the name is a beacon now.
    fn ask(&mut self, ttl: u32, now_ms: u64) -> bool {
        self.seen_ms = now_ms;
        let gap = now_ms.saturating_sub(self.last_ms);
        if gap < BEACON_REPEAT_MS {
            // The other half of one lookup: an answer with no TTL, which has no record or an empty
            // one, does not take back what the first half told the asker.
            self.last_ttl = self.last_ttl.max(ttl);
            return false;
        }
        let interval = secs(gap);
        if self.asks >= 2
            && (interval > BEACON_BREAK * self.mean || interval * BEACON_BREAK < self.mean)
        {
            self.restart(ttl, now_ms);
            return false;
        }
        self.intervals = self.intervals.saturating_add(1);
        if within_ttl(interval, self.last_ttl) {
            self.cache_intervals = self.cache_intervals.saturating_add(1);
        }
        self.last_ttl = ttl;
        self.asks = self.asks.saturating_add(1);
        let delta = interval - self.mean;
        self.mean += delta / f64::from(self.asks - 1);
        self.m2 += delta * (interval - self.mean);
        self.last_ms = now_ms;
        if self.is_beacon(now_ms) {
            self.quiet_until_ms = now_ms.saturating_add(BEACON_MIN_SPAN_MS);
            return true;
        }
        false
    }

    /// The coefficient of variation of the intervals: their standard deviation over their mean.
    /// Infinite when there are too few intervals for one.
    fn cv(&self) -> f64 {
        if self.asks < 3 || self.mean <= 0.0 {
            return f64::INFINITY;
        }
        (self.m2 / f64::from(self.asks - 2)).sqrt() / self.mean
    }

    /// Whether the asker is a cache running out: at least half of the intervals were from 0.8 to
    /// 1.25 times the TTL of the answer before. The TTL that the resolver gives is the time left
    /// of the record (and 30 s of a stale one), so the band follows the answers that the asker
    /// was really given, not one TTL of the name.
    fn cache_bound(&self) -> bool {
        self.intervals > 0 && self.cache_intervals.saturating_mul(2) >= self.intervals
    }

    /// Whether the name is a beacon at `now_ms`: asked often enough for long enough, at a pace
    /// that is steady, that is not an hour or more nor under half a minute, and that is not the
    /// asker's cache running out, and not raised already.
    fn is_beacon(&self, now_ms: u64) -> bool {
        self.asks >= BEACON_MIN_ASKS
            && self.last_ms.saturating_sub(self.first_ms) >= BEACON_MIN_SPAN_MS
            && (BEACON_MEAN_MIN_SECS..=BEACON_MEAN_MAX_SECS).contains(&self.mean)
            && self.cv() <= BEACON_CV_MAX
            && !self.cache_bound()
            && now_ms >= self.quiet_until_ms
    }

    /// Whether the slot may not be taken by a new name at `now_ms`: the name was asked 10 times
    /// or more at a regular pace and was seen within twice its mean interval.
    fn is_kept(&self, now_ms: u64) -> bool {
        self.asks >= BEACON_KEEP_ASKS
            && self.cv() <= BEACON_KEEP_CV
            && secs(now_ms.saturating_sub(self.seen_ms)) <= BEACON_KEEP_INTERVALS * self.mean
    }
}

/// The questions of one client by the minute, and the usual rate that they make.
struct Burst {
    /// When the client was first seen.
    first_ms: u64,
    /// The minute that is counted now: the monotonic milliseconds divided by 60 000.
    minute: u64,
    /// How many questions there were in that minute so far.
    count: u32,
    /// The usual number of questions in a minute: an average where each minute weighs one eighth
    /// more than the average of the minutes before it.
    baseline: f64,
    /// The minute in which the burst was raised last.
    raised_minute: Option<u64>,
}

impl Burst {
    /// The counts of a client first seen at `now_ms`.
    fn new(now_ms: u64) -> Self {
        Self {
            first_ms: now_ms,
            minute: now_ms / MINUTE_MS,
            count: 0,
            baseline: 0.0,
            raised_minute: None,
        }
    }

    /// Counts one question at `now_ms`, and says whether this minute is a burst now: the client
    /// has been seen for 10 minutes, the minute has 300 questions or more, and 10 times the usual
    /// number or more. A minute raises once.
    fn ask(&mut self, now_ms: u64) -> bool {
        let minute = now_ms / MINUTE_MS;
        if minute > self.minute {
            self.roll(minute);
        }
        self.count = self.count.saturating_add(1);
        if now_ms.saturating_sub(self.first_ms) < BURST_ARM_MS
            || self.raised_minute == Some(self.minute)
        {
            return false;
        }
        if f64::from(self.count) >= f64::from(BURST_FLOOR).max(BURST_TIMES * self.baseline) {
            self.raised_minute = Some(self.minute);
            return true;
        }
        false
    }

    /// Ends the minute that was counted and begins `minute`: the usual rate takes the count of the
    /// minute that ended, then 0 for each minute after it that nothing was asked in. At most 60 of
    /// those are counted, which is long enough for the rate to be as good as 0.
    fn roll(&mut self, minute: u64) {
        self.baseline += (f64::from(self.count) - self.baseline) / BURST_EWMA_DIVISOR;
        let empty = (minute - self.minute - 1).min(BURST_CATCH_UP);
        for _ in 0..empty {
            self.baseline -= self.baseline / BURST_EWMA_DIVISOR;
        }
        self.minute = minute;
        self.count = 0;
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::super::wire_of;
    use super::*;

    /// The type of an A question.
    const A: u16 = 1;
    /// The type of an AAAA question.
    const AAAA: u16 = 28;
    /// The type of an SRV question.
    const SRV: u16 = 33;
    /// The response code of an answer.
    const NOERROR: u8 = 0;
    /// A second, in milliseconds.
    const SECOND: u64 = 1000;
    /// A minute, in milliseconds.
    const MINUTE: u64 = MINUTE_MS;
    /// An hour, in milliseconds.
    const HOUR: u64 = HOUR_MS;
    /// The monotonic time at the start of every trace, a whole number of minutes.
    const START: u64 = HOUR;

    /// A client of the documentation range `192.0.2.0/24`.
    fn client(host: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, host))
    }

    /// One question of a trace: when it was asked, and the answer that it got.
    type Ask = (u64, Event);

    /// An ask of `client` for `name` of type `qtype`, answered with `rcode` and `ttl` at `at`.
    fn ask(at: u64, client: IpAddr, name: &str, qtype: u16, rcode: u8, ttl: u32) -> Ask {
        (at, Event::for_test(client, name, qtype, rcode, ttl))
    }

    /// An alert as the tests see it: the severity as text.
    #[derive(Debug, PartialEq)]
    struct Seen {
        /// The kind.
        kind: &'static str,
        /// The severity as `info`, `warn` or `high`.
        severity: &'static str,
        /// The client.
        client: Option<IpAddr>,
        /// The subject.
        subject: String,
    }

    /// The alert that a test expects.
    fn seen(kind: &'static str, severity: &'static str, client: IpAddr, subject: &str) -> Seen {
        Seen {
            kind,
            severity,
            client: Some(client),
            subject: subject.to_owned(),
        }
    }

    /// The detectors and the alerts that they raised.
    struct Rig {
        /// What is under test.
        behaviour: Behaviour,
        /// The alerts that were raised, in order.
        alerts: Vec<Seen>,
    }

    impl Rig {
        /// A rig with the quiet names `quiet`.
        fn new(quiet: &[&str]) -> Self {
            Self {
                behaviour: Behaviour::new(quiet.iter().map(|name| (*name).to_owned()).collect()),
                alerts: Vec::new(),
            }
        }

        /// Gives the detectors one event at `at`.
        fn feed(&mut self, at: u64, event: &Event) {
            let alerts = &mut self.alerts;
            self.behaviour.observe(event, at, &mut |alert: Alert| {
                alerts.push(Seen {
                    kind: alert.kind,
                    severity: match alert.severity {
                        Severity::Info => "info",
                        Severity::Warn => "warn",
                        Severity::High => "high",
                    },
                    client: alert.client,
                    subject: alert.subject,
                });
            });
        }

        /// Gives the detectors a trace, in the order it is in.
        fn run(&mut self, trace: &[Ask]) {
            for (at, event) in trace {
                self.feed(*at, event);
            }
        }

        /// The kinds of the alerts so far, in order.
        fn kinds(&self) -> Vec<&'static str> {
            self.alerts.iter().map(|seen| seen.kind).collect()
        }

        /// The record of `client` in the detectors.
        fn record(&self, client: IpAddr) -> &Client {
            self.behaviour
                .clients
                .iter()
                .find(|record| record.addr == client)
                .expect("a client that was seen")
        }
    }

    /// A xorshift generator with a fixed seed, for traces that are the same on every run.
    struct Rng(u64);

    impl Rng {
        /// The generator that every test starts from.
        fn new() -> Self {
            Self(0x9E37_79B9_7F4A_7C15)
        }

        /// The next number.
        fn draw(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        /// A number below `n`.
        fn below(&mut self, n: u64) -> u64 {
            self.draw() % n
        }

        /// A number from `low` to `high`, both included.
        fn between(&mut self, low: u64, high: u64) -> u64 {
            low + self.below(high - low + 1)
        }

        /// `base` milliseconds, moved by at most `spread` milliseconds up or down.
        fn around(&mut self, base: u64, spread: u64) -> u64 {
            base - spread + self.below(2 * spread + 1)
        }

        /// A string of `len` characters of `alphabet`.
        fn token(&mut self, len: usize, alphabet: &[u8]) -> String {
            let size = u64::try_from(alphabet.len()).unwrap();
            (0..len)
                .map(|_| char::from(alphabet[usize::try_from(self.below(size)).unwrap()]))
                .collect()
        }

        /// A label of 12 characters that looks random, as a program would make one up.
        fn random_label(&mut self) -> String {
            loop {
                let label = self.token(12, ALNUM);
                if names::looks_random(&label) {
                    return label;
                }
            }
        }
    }

    /// The characters of `a-z` and `0-9`.
    const ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    /// The characters of `a-z`.
    const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    /// The hexadecimal digits.
    const HEX: &[u8] = b"0123456789abcdef";

    /// A trace of `count` random-looking names under `.com` that do not exist, `spacing` ms apart.
    fn random_names(client: IpAddr, rng: &mut Rng, count: usize, spacing: u64) -> Vec<Ask> {
        (0..count)
            .map(|n| {
                let name = format!("{}.com", rng.random_label());
                ask(START + n as u64 * spacing, client, &name, A, 3, 0)
            })
            .collect()
    }

    /// A trace of `count` names under `example.com` whose part left of it is `left` bytes, `spacing`
    /// ms apart.
    fn long_names(
        client: IpAddr,
        rng: &mut Rng,
        count: usize,
        spacing: u64,
        left: usize,
    ) -> Vec<Ask> {
        (0..count)
            .map(|n| {
                let name = format!("{}.example.com", rng.token(left, HEX));
                ask(START + n as u64 * spacing, client, &name, A, NOERROR, 60)
            })
            .collect()
    }

    /// A trace where `name` is asked at intervals of `interval_s` seconds, each moved by at most
    /// `jitter_s` seconds, for `hours` hours; every answer has the TTL `ttl`.
    fn periodic(
        client: IpAddr,
        name: &str,
        ttl: u32,
        interval_s: u64,
        jitter_s: u64,
        hours: f64,
    ) -> Vec<Ask> {
        periodic_as(client, name, A, ttl, interval_s, jitter_s, hours)
    }

    /// [`periodic`] for questions of the type `qtype`.
    fn periodic_as(
        client: IpAddr,
        name: &str,
        qtype: u16,
        ttl: u32,
        interval_s: u64,
        jitter_s: u64,
        hours: f64,
    ) -> Vec<Ask> {
        let mut rng = Rng::new();
        let end = START + (hours * HOUR as f64) as u64;
        let mut trace = Vec::new();
        let mut nominal = START + 10 * SECOND;
        while nominal < end {
            let at = rng.around(nominal, jitter_s * SECOND);
            trace.push(ask(at, client, name, qtype, NOERROR, ttl));
            nominal += interval_s * SECOND;
        }
        trace
    }

    /// A trace where `name` is asked every `interval_s` seconds, each moved by at most `jitter_s`
    /// seconds, for `hours` hours, through a resolver's cache: the first answer has the TTL `ttl`
    /// and the ones after it the time that is left of the record, until it ran out and the
    /// resolver asks upstream again for a new one.
    fn through_the_cache(
        client: IpAddr,
        name: &str,
        ttl: u32,
        interval_s: u64,
        jitter_s: u64,
        hours: f64,
    ) -> Vec<Ask> {
        let mut rng = Rng::new();
        let end = START + (hours * HOUR as f64) as u64;
        let mut trace = Vec::new();
        let mut nominal = START + 10 * SECOND;
        let mut expires = 0;
        while nominal < end {
            let at = rng.around(nominal, jitter_s * SECOND);
            if at >= expires {
                expires = at + u64::from(ttl) * SECOND;
            }
            let left = u32::try_from((expires - at).div_ceil(SECOND)).unwrap();
            trace.push(ask(at, client, name, A, NOERROR, left));
            nominal += interval_s * SECOND;
        }
        trace
    }

    /// A trace for the burst detector: 20 questions a minute for `quiet_minutes` minutes, then
    /// `burst` questions in the minute after, for names under `example.org`.
    fn busy_minute(client: IpAddr, quiet_minutes: u64, burst: u64) -> Vec<Ask> {
        let host = |n: u64| format!("h{n}.example.org");
        let mut trace: Vec<Ask> = (0..quiet_minutes * 20)
            .map(|n| ask(START + n * 3 * SECOND, client, &host(n), A, NOERROR, 60))
            .collect();
        let begin = START + quiet_minutes * MINUTE;
        trace.extend((0..burst).map(|n| {
            ask(
                begin + n * (MINUTE / burst),
                client,
                &host(100_000 + n),
                A,
                NOERROR,
                60,
            )
        }));
        trace
    }

    /// The TXT trace: `txt` TXT questions, of type 16, and `other` A questions, 2 s apart,
    /// the A ones first.
    fn txt_trace(client: IpAddr, txt: u64, other: u64, qtype: u16) -> Vec<Ask> {
        let mut at = START;
        let mut trace = Vec::new();
        for n in 0..other {
            trace.push(ask(
                at,
                client,
                &format!("w{n}.example.org"),
                A,
                NOERROR,
                60,
            ));
            at += 2 * SECOND;
        }
        for n in 0..txt {
            trace.push(ask(
                at,
                client,
                &format!("t{n}.example.org"),
                qtype,
                NOERROR,
                60,
            ));
            at += 2 * SECOND;
        }
        trace
    }

    #[test]
    fn twenty_five_random_names_that_do_not_exist_raise_dga_once() {
        let mut rng = Rng::new();
        let mut rig = Rig::new(&[]);
        let trace = random_names(client(7), &mut rng, 25, 10 * SECOND);
        rig.run(&trace[..24]);
        assert!(rig.alerts.is_empty());
        rig.run(&trace[24..]);
        assert_eq!(
            rig.alerts,
            vec![seen("dga", "high", client(7), "random NXDOMAIN names")]
        );
    }

    #[test]
    fn dga_with_one_name_fewer_or_names_too_far_apart_raises_nothing() {
        let mut rng = Rng::new();
        // 24 names.
        let mut rig = Rig::new(&[]);
        rig.run(&random_names(client(7), &mut rng, 24, SECOND));
        assert!(rig.alerts.is_empty());
        // 25 names 13 s apart: the 25th comes 312 s after the first, so a window of 300 s holds
        // 24 of them at the most.
        let mut rig = Rig::new(&[]);
        rig.run(&random_names(client(7), &mut rng, 25, 13 * SECOND));
        assert!(rig.alerts.is_empty());
        // 12 s apart they are all inside 300 s.
        let mut rig = Rig::new(&[]);
        rig.run(&random_names(client(7), &mut rng, 25, 12 * SECOND));
        assert_eq!(rig.kinds(), ["dga"]);
    }

    #[test]
    fn dga_raises_again_only_when_its_window_has_passed() {
        let mut rng = Rng::new();
        let trace = random_names(client(7), &mut rng, 55, 10 * SECOND);
        let mut rig = Rig::new(&[]);
        // The first alert is at the 25th name, 240 s in; 300 s later it may come again.
        rig.run(&trace[..54]);
        assert_eq!(rig.kinds(), ["dga"]);
        rig.run(&trace[54..]);
        assert_eq!(rig.kinds(), ["dga", "dga"]);
    }

    #[test]
    fn dga_does_not_count_names_that_are_not_random_not_missing_or_not_a_domain() {
        let mut rng = Rng::new();
        let me = client(7);
        let mut trace = Vec::new();
        let mut at = START;
        let mut push = |name: String, rcode: u8| {
            at += SECOND;
            trace.push(ask(at, me, &name, A, rcode, 0));
        };
        for _ in 0..60 {
            // Chrome's probes: one label, and so no domain.
            push(rng.token(10, LOWER), 3);
            // Random names under the household's own suffixes, and a reverse lookup.
            push(format!("{}.lan", rng.random_label()), 3);
            push(format!("{}.local", rng.random_label()), 3);
            push(format!("{}.in-addr.arpa", rng.random_label()), 3);
            // Random names that exist.
            push(format!("{}.com", rng.random_label()), 0);
            // Random hosts under a domain that is a word: the domain is what counts.
            push(format!("{}.example.org", rng.random_label()), 3);
        }
        // Words and typos, different every time, under 25 domains that look made by people.
        for word in [
            "download",
            "facebook",
            "wikipedia",
            "microsoft",
            "cloudflare",
            "instagram",
            "youtube",
            "netflix",
            "twitter",
            "linkedin",
            "pinterest",
            "dropbox",
            "spotify",
            "whatsapp",
            "telegram",
            "wordpress",
            "bloomberg",
            "reuters",
            "guardian",
            "economist",
            "weather",
            "calendar",
            "bookmarks",
            "keyboard",
            "pictures",
        ] {
            push(format!("{word}.com"), 3);
        }
        let mut rig = Rig::new(&[]);
        rig.run(&trace);
        assert!(rig.alerts.is_empty(), "{:?}", rig.alerts);
        // The same name asked 100 times counts once.
        let mut rig = Rig::new(&[]);
        let name = format!("{}.com", rng.random_label());
        for n in 0..100 {
            rig.feed(START + n * SECOND, &Event::for_test(me, &name, A, 3, 0));
        }
        assert!(rig.alerts.is_empty());
    }

    #[test]
    fn forty_long_names_under_one_domain_in_ten_minutes_raise_tunnel_with_the_domain() {
        let mut rng = Rng::new();
        let me = client(8);
        let trace = long_names(me, &mut rng, 40, 10 * SECOND, 60);
        let mut rig = Rig::new(&[]);
        rig.run(&trace[..39]);
        assert!(rig.alerts.is_empty());
        rig.run(&trace[39..]);
        assert_eq!(rig.alerts, vec![seen("tunnel", "high", me, "example.com")]);
    }

    #[test]
    fn long_names_just_under_the_threshold_in_number_in_length_or_in_time_raise_nothing() {
        let mut rng = Rng::new();
        let me = client(8);
        // 39 names.
        let mut rig = Rig::new(&[]);
        rig.run(&long_names(me, &mut rng, 39, SECOND, 60));
        assert!(rig.alerts.is_empty());
        // 100 names with 39 bytes left of the domain: one byte too short.
        let mut rig = Rig::new(&[]);
        rig.run(&long_names(me, &mut rng, 100, SECOND, 39));
        assert!(rig.alerts.is_empty());
        // 40 names 16 s apart span 624 s: a window of 600 s holds 38 or 39 of them.
        let mut rig = Rig::new(&[]);
        rig.run(&long_names(me, &mut rng, 40, 16 * SECOND, 60));
        assert!(rig.alerts.is_empty());
        // 40 bytes is long enough.
        let mut rig = Rig::new(&[]);
        rig.run(&long_names(me, &mut rng, 40, SECOND, 40));
        assert_eq!(rig.kinds(), ["tunnel"]);
    }

    #[test]
    fn long_names_count_per_domain_and_the_domain_of_a_country_second_level_is_three_labels() {
        let mut rng = Rng::new();
        let me = client(8);
        // 20 under each of two domains is not 40 under one.
        let mut rig = Rig::new(&[]);
        for n in 0..40u64 {
            let domain = if n % 2 == 0 {
                "example.org"
            } else {
                "example.net"
            };
            let name = format!("{}.{domain}", rng.token(50, HEX));
            rig.feed(START + n * SECOND, &Event::for_test(me, &name, A, 0, 60));
        }
        assert!(rig.alerts.is_empty());
        // Names under a second-level domain of a country, with a host label in between.
        let mut rig = Rig::new(&[]);
        for n in 0..40u64 {
            let name = format!("{}.www.example.co.uk", rng.token(50, HEX));
            rig.feed(START + n * SECOND, &Event::for_test(me, &name, A, 0, 60));
        }
        assert_eq!(
            rig.alerts,
            vec![seen("tunnel", "high", me, "example.co.uk")]
        );
    }

    #[test]
    fn a_hundred_txt_and_null_questions_that_are_half_of_all_raise_tunnel_with_a_subject_of_the_share()
     {
        let me = client(9);
        // 100 TXT questions and nothing else.
        let mut rig = Rig::new(&[]);
        let trace = txt_trace(me, 100, 0, 16);
        rig.run(&trace[..99]);
        assert!(rig.alerts.is_empty());
        rig.run(&trace[99..]);
        assert_eq!(
            rig.alerts,
            vec![seen("tunnel", "high", me, "TXT/NULL share")]
        );
        // NULL questions count the same, and so does a mix.
        let mut rig = Rig::new(&[]);
        let mut trace = txt_trace(me, 60, 0, 16);
        trace.extend(
            txt_trace(me, 40, 0, 10)
                .into_iter()
                .map(|(at, event)| (at + 3 * MINUTE, event)),
        );
        rig.run(&trace);
        assert_eq!(rig.kinds(), ["tunnel"]);
        // 100 TXT and 100 others is half: it raises.
        let mut rig = Rig::new(&[]);
        rig.run(&txt_trace(me, 100, 100, 16));
        assert_eq!(rig.kinds(), ["tunnel"]);
    }

    #[test]
    fn txt_questions_just_under_the_count_or_the_half_raise_nothing() {
        let me = client(9);
        // 99 of 99.
        let mut rig = Rig::new(&[]);
        rig.run(&txt_trace(me, 99, 0, 16));
        assert!(rig.alerts.is_empty());
        // 100 of 201 is under a half: 99 are 49.3 %, 100 are 49.8 %.
        let mut rig = Rig::new(&[]);
        rig.run(&txt_trace(me, 100, 101, 16));
        assert!(rig.alerts.is_empty());
        // 100 TXT questions an hour apart are never 100 in ten minutes.
        let mut rig = Rig::new(&[]);
        for n in 0..100u64 {
            let name = format!("t{n}.example.org");
            rig.feed(START + n * HOUR, &Event::for_test(me, &name, 16, 0, 60));
        }
        assert!(rig.alerts.is_empty());
        // Other types do not count, whatever the number.
        let mut rig = Rig::new(&[]);
        rig.run(&txt_trace(me, 300, 0, 15));
        assert!(rig.alerts.is_empty());
    }

    #[test]
    fn a_name_asked_every_300_s_with_a_jitter_of_5_s_for_3_5_hours_and_a_ttl_of_60_is_a_beacon() {
        let me = client(10);
        let mut rig = Rig::new(&[]);
        rig.run(&periodic(me, "telemetry.example.org", 60, 300, 5, 3.5));
        assert_eq!(
            rig.alerts,
            vec![seen("beacon", "info", me, "telemetry.example.org")]
        );
    }

    #[test]
    fn the_same_asking_with_a_ttl_of_300_a_jitter_of_100_s_or_a_skipped_name_is_no_beacon() {
        let me = client(10);
        // The asker's cache runs out every 300 s.
        let mut rig = Rig::new(&[]);
        rig.run(&periodic(me, "telemetry.example.org", 300, 300, 5, 3.5));
        assert!(rig.alerts.is_empty());
        // A pace that is not steady.
        let mut rig = Rig::new(&[]);
        rig.run(&periodic(me, "telemetry.example.org", 60, 300, 100, 3.5));
        assert!(rig.alerts.is_empty());
        // Names that are asked at a steady pace by design.
        for name in [
            "pool.ntp.org",
            "0.pool.ntp.org",
            "time.apple.com",
            "connectivitycheck.gstatic.com",
            "www.msftconnecttest.com",
            "mtalk.google.com",
            "courier.push.apple.com",
            "17-courier.push.apple.com",
        ] {
            let mut rig = Rig::new(&[]);
            rig.run(&periodic(me, name, 60, 300, 5, 3.5));
            assert!(rig.alerts.is_empty(), "{name}");
        }
        // A name that only looks like one of them is not skipped.
        let mut rig = Rig::new(&[]);
        rig.run(&periodic(
            me,
            "notpush.apple.com.example.org",
            60,
            300,
            5,
            3.5,
        ));
        assert_eq!(rig.kinds(), ["beacon"]);
    }

    #[test]
    fn a_client_asking_every_120_s_that_is_given_the_time_left_of_a_300_s_record_is_a_beacon() {
        let me = client(10);
        let trace = through_the_cache(me, "telemetry.example.org", 300, 120, 3, 3.5);
        // The answers fall from 300 to the time left, and the pace is not that of any of them.
        let ttls: Vec<u32> = trace.iter().map(|(_, event)| event.ttl).collect();
        assert!(
            ttls.contains(&300) && ttls.iter().any(|&ttl| ttl < 100),
            "{ttls:?}"
        );
        let mut rig = Rig::new(&[]);
        rig.run(&trace);
        assert_eq!(
            rig.alerts,
            vec![seen("beacon", "info", me, "telemetry.example.org")]
        );
        // The same with a record of an hour: the answers fall for much longer.
        let mut rig = Rig::new(&[]);
        rig.run(&through_the_cache(
            me,
            "telemetry.example.org",
            3600,
            120,
            3,
            3.5,
        ));
        assert_eq!(rig.kinds(), ["beacon"]);
    }

    #[test]
    fn a_client_asking_again_exactly_when_the_ttl_it_was_given_runs_out_is_no_beacon() {
        let me = client(10);
        // Given 300, it asks 300 s later, each time.
        let mut rig = Rig::new(&[]);
        rig.run(&periodic(me, "telemetry.example.org", 300, 300, 5, 3.5));
        assert!(rig.alerts.is_empty(), "{:?}", rig.alerts);
        // Through a resolver's cache the answer is the time that is left, and the client still
        // asks again when that has passed: 300 s, then what is left of the record.
        let mut rig = Rig::new(&[]);
        let name = "telemetry.example.org";
        let mut at = START;
        let mut left = 300u32;
        for _ in 0..80 {
            rig.feed(at, &Event::for_test(me, name, A, NOERROR, left));
            at += u64::from(left) * SECOND;
            // A resolver that refreshed meanwhile gives 300 again, one that did not gives less.
            left = if left == 300 { 280 } else { 300 };
        }
        assert!(rig.alerts.is_empty(), "{:?}", rig.alerts);
    }

    #[test]
    fn a_beacon_needs_thirty_asks_three_hours_and_a_mean_between_half_a_minute_and_an_hour() {
        let me = client(10);
        let name = "telemetry.example.org";
        let run = |interval_s: u64, asks: u64| {
            let mut rig = Rig::new(&[]);
            for n in 0..asks {
                let at = START + n * interval_s * SECOND;
                rig.feed(at, &Event::for_test(me, name, A, NOERROR, 60));
            }
            rig.alerts.len()
        };
        // Every 400 s: 29 asks span 3.1 hours, and the 30th is the one that counts.
        assert_eq!(run(400, 29), 0);
        assert_eq!(run(400, 30), 1);
        // Every 350 s: 30 asks span 2.8 hours, and 32 span 3.01.
        assert_eq!(run(350, 30), 0);
        assert_eq!(run(350, 31), 0);
        assert_eq!(run(350, 32), 1);
        // A mean of 25 s is too quick, one of 30 s is not; one of 4000 s is too slow.
        assert_eq!(run(25, 1000), 0);
        assert_eq!(run(30, 400), 1);
        assert_eq!(run(3500, 30), 1);
        assert_eq!(run(4000, 40), 0);
    }

    #[test]
    fn a_beacon_is_raised_again_only_after_the_hours_that_the_pace_has_to_last() {
        let me = client(10);
        let mut rig = Rig::new(&[]);
        // Every 300 s for 6.5 hours: the first alert is after 3 hours and the second after 6.
        rig.run(&periodic(me, "telemetry.example.org", 60, 300, 2, 6.5));
        assert_eq!(rig.kinds(), ["beacon", "beacon"]);
    }

    #[test]
    fn the_a_and_the_aaaa_of_one_lookup_count_as_one_ask() {
        let me = client(10);
        let name = "telemetry.example.org";
        let mut rig = Rig::new(&[]);
        for n in 0..43u64 {
            let at = START + n * 300 * SECOND;
            rig.feed(at, &Event::for_test(me, name, A, NOERROR, 60));
            rig.feed(at + 100, &Event::for_test(me, name, AAAA, NOERROR, 60));
            rig.feed(at + 1500, &Event::for_test(me, name, A, NOERROR, 60));
        }
        assert_eq!(rig.kinds(), ["beacon"]);
        let slot = &rig.record(me).slots[0];
        assert_eq!(slot.asks, 43);
    }

    #[test]
    fn answers_without_a_ttl_do_not_hide_a_cache_and_a_name_that_never_exists_is_a_beacon() {
        let me = client(10);
        let name = "telemetry.example.org";
        // An A with a TTL of 300 and an AAAA with none, every 300 s: the cache runs out.
        let mut rig = Rig::new(&[]);
        for n in 0..43u64 {
            let at = START + n * 300 * SECOND;
            rig.feed(at, &Event::for_test(me, name, A, NOERROR, 300));
            rig.feed(at + 80, &Event::for_test(me, name, AAAA, NOERROR, 0));
        }
        assert!(rig.alerts.is_empty());
        // An A with a TTL of 60 and an AAAA with 300: the asker keeps the one that is longest.
        let mut rig = Rig::new(&[]);
        for n in 0..43u64 {
            let at = START + n * 300 * SECOND;
            rig.feed(at, &Event::for_test(me, name, A, NOERROR, 60));
            rig.feed(at + 80, &Event::for_test(me, name, AAAA, NOERROR, 300));
        }
        assert!(rig.alerts.is_empty());
        // A name with no answer at all, asked on a steady pace, has no cache to blame.
        let mut rig = Rig::new(&[]);
        for n in 0..43u64 {
            let at = START + n * 300 * SECOND;
            rig.feed(at, &Event::for_test(me, "dead.example.org", A, 3, 0));
        }
        assert_eq!(rig.kinds(), ["beacon"]);
    }

    #[test]
    fn an_interval_is_cache_bound_from_four_fifths_to_five_fourths_of_the_ttl_before_it() {
        for (secs, bound) in [
            (79, false),
            (81, true),
            (100, true),
            (124, true),
            (126, false),
        ] {
            let mut slot = Slot::new(1, 100, START);
            slot.ask(100, START + secs * SECOND);
            assert_eq!(
                (slot.intervals, slot.cache_intervals),
                (1, u32::from(bound)),
                "{secs}"
            );
        }
        // No TTL given, no cache: an answer without one is no reason for the next ask.
        let mut slot = Slot::new(1, 0, START);
        slot.ask(0, START + 300 * SECOND);
        assert_eq!((slot.intervals, slot.cache_intervals), (1, 0));
        // It is the TTL of the answer before, not the one that comes with the ask.
        let mut slot = Slot::new(1, 300, START);
        slot.ask(60, START + 300 * SECOND);
        assert_eq!((slot.intervals, slot.cache_intervals), (1, 1));
        slot.ask(300, START + 600 * SECOND);
        assert_eq!((slot.intervals, slot.cache_intervals), (2, 1));
    }

    #[test]
    fn a_slot_is_cache_bound_when_half_of_its_intervals_were_and_not_when_fewer_were() {
        let mut slot = Slot::new(1, 300, START);
        assert!(!slot.cache_bound(), "no interval yet");
        let mut at = START;
        let mut states = Vec::new();
        // Given 300, then 60 each time, asking every 300 s: the first interval is the cache's.
        for ttl in [60, 60, 60, 60] {
            at += 300 * SECOND;
            slot.ask(ttl, at);
            states.push(slot.cache_bound());
        }
        assert_eq!(states, [true, true, false, false]);
    }

    #[test]
    fn the_other_half_of_a_lookup_adds_to_the_ttl_given_and_never_takes_from_it() {
        // An A of 300 and an AAAA without a TTL, in either order, then asked again at 300 s.
        for (first, second) in [(300, 0), (0, 300), (60, 300), (300, 60)] {
            let mut slot = Slot::new(1, first, START);
            slot.ask(second, START + 100);
            assert_eq!(slot.asks, 1, "a repeat is one ask");
            slot.ask(60, START + 300 * SECOND);
            assert_eq!(
                (slot.intervals, slot.cache_intervals),
                (1, 1),
                "{first} {second}"
            );
        }
    }

    #[test]
    fn the_mean_and_the_spread_of_the_intervals_are_those_of_a_direct_computation() {
        let mut slot = Slot::new(1, 60, START);
        let intervals = [300.0, 310.0, 290.0, 305.0, 295.0, 300.0];
        let mut at = START;
        for interval in intervals {
            at += (interval * 1000.0) as u64;
            slot.ask(60, at);
        }
        let n = intervals.len() as f64;
        let mean = intervals.iter().sum::<f64>() / n;
        let variance = intervals.iter().map(|i| (i - mean).powi(2)).sum::<f64>() / (n - 1.0);
        assert!((slot.mean - mean).abs() < 1e-9, "{} {mean}", slot.mean);
        assert!(
            (slot.cv() - variance.sqrt() / mean).abs() < 1e-9,
            "{} {}",
            slot.cv(),
            variance.sqrt() / mean
        );
        assert_eq!(slot.asks, 7);
    }

    #[test]
    fn an_interval_that_breaks_the_pace_starts_the_statistics_of_the_name_over() {
        let me = client(10);
        let name = "telemetry.example.org";
        let mut rig = Rig::new(&[]);
        // 1.6 hours at 300 s, then 1 hour of silence, then 2 hours at 300 s: neither run is 3 hours.
        let mut at = START;
        for _ in 0..20 {
            rig.feed(at, &Event::for_test(me, name, A, NOERROR, 60));
            at += 300 * SECOND;
        }
        at += HOUR;
        for _ in 0..24 {
            rig.feed(at, &Event::for_test(me, name, A, NOERROR, 60));
            at += 300 * SECOND;
        }
        assert!(rig.alerts.is_empty());
        assert_eq!(rig.record(me).slots[0].asks, 24);
        // It keeps going, and the second run is a beacon once it is 3 hours old.
        for _ in 0..13 {
            rig.feed(at, &Event::for_test(me, name, A, NOERROR, 60));
            at += 300 * SECOND;
        }
        assert_eq!(rig.kinds(), ["beacon"]);
        // A hiccup of a quarter of the pace starts it over too, in the other direction.
        let mut rig = Rig::new(&[]);
        let mut at = START;
        for n in 0..20 {
            rig.feed(at, &Event::for_test(me, name, A, NOERROR, 60));
            at += if n == 10 { 60 * SECOND } else { 300 * SECOND };
        }
        assert_eq!(rig.record(me).slots[0].asks, 9);
    }

    #[test]
    fn a_slot_of_a_name_that_was_asked_once_goes_to_the_new_name_that_finds_the_table_full() {
        let me = client(10);
        let mut rig = Rig::new(&[]);
        for n in 0..BEACON_SLOTS as u64 {
            let name = format!("n{n}.example.org");
            rig.feed(
                START + n * SECOND,
                &Event::for_test(me, &name, A, NOERROR, 60),
            );
        }
        assert_eq!(rig.record(me).slots.len(), BEACON_SLOTS);
        rig.feed(
            START + MINUTE,
            &Event::for_test(me, "new.example.org", A, NOERROR, 60),
        );
        let record = rig.record(me);
        assert_eq!(record.slots.len(), BEACON_SLOTS);
        let has = |name: &str| {
            record
                .slots
                .iter()
                .any(|slot| slot.name == fnv(name.as_bytes()))
        };
        // The one seen longest ago is out, the next is in, and so is the new one.
        assert!(!has("n0.example.org"));
        assert!(has("n1.example.org"));
        assert!(has("new.example.org"));
    }

    #[test]
    fn a_slot_with_ten_regular_asks_is_kept_until_it_was_not_seen_for_twice_its_mean() {
        let me = client(10);
        let mut rig = Rig::new(&[]);
        // 32 names, each asked 12 times every 300 s, one second after the one before.
        let mut trace = Vec::new();
        for round in 0..12u64 {
            for n in 0..BEACON_SLOTS as u64 {
                let at = START + round * 300 * SECOND + n * SECOND;
                trace.push(ask(at, me, &format!("n{n}.example.org"), A, NOERROR, 60));
            }
        }
        rig.run(&trace);
        let last = START + 11 * 300 * SECOND;
        // A 33rd name finds no slot that it may take.
        rig.feed(
            last + 40 * SECOND,
            &Event::for_test(me, "new.example.org", A, NOERROR, 60),
        );
        let has = |rig: &Rig, name: &str| {
            rig.record(me)
                .slots
                .iter()
                .any(|slot| slot.name == fnv(name.as_bytes()))
        };
        assert_eq!(rig.record(me).slots.len(), BEACON_SLOTS);
        assert!(!has(&rig, "new.example.org"));
        // 601 s after the first name was seen last, it has been away for over twice its mean, and
        // the second has not.
        rig.feed(
            last + 601 * SECOND,
            &Event::for_test(me, "new.example.org", A, NOERROR, 60),
        );
        assert_eq!(rig.record(me).slots.len(), BEACON_SLOTS);
        assert!(has(&rig, "new.example.org"));
        assert!(!has(&rig, "n0.example.org"));
        assert!(has(&rig, "n1.example.org"));
    }

    #[test]
    fn a_burst_of_400_questions_in_a_minute_after_20_minutes_of_20_a_minute_raises_warn() {
        let me = client(11);
        let mut rig = Rig::new(&[]);
        rig.run(&busy_minute(me, 20, 400));
        assert_eq!(rig.alerts, vec![seen("burst", "warn", me, "question rate")]);
    }

    #[test]
    fn a_minute_of_250_questions_or_a_burst_before_ten_minutes_raises_nothing() {
        let me = client(11);
        let mut rig = Rig::new(&[]);
        rig.run(&busy_minute(me, 20, 250));
        assert!(rig.alerts.is_empty());
        // 299 and 300 questions: the floor.
        let mut rig = Rig::new(&[]);
        rig.run(&busy_minute(me, 20, 299));
        assert!(rig.alerts.is_empty());
        let mut rig = Rig::new(&[]);
        rig.run(&busy_minute(me, 20, 300));
        assert_eq!(rig.kinds(), ["burst"]);
        // The detector is armed 10 minutes after the client was first seen: 9 are too few.
        let mut rig = Rig::new(&[]);
        rig.run(&busy_minute(me, 9, 400));
        assert!(rig.alerts.is_empty());
        let mut rig = Rig::new(&[]);
        rig.run(&busy_minute(me, 10, 400));
        assert_eq!(rig.kinds(), ["burst"]);
    }

    #[test]
    fn a_burst_over_ten_times_a_busy_baseline_raises_and_one_under_does_not() {
        let me = client(11);
        // 100 a minute for 30 minutes: the baseline is about 98, so 10 times it is about 980.
        let run = |burst: u64| {
            let mut rig = Rig::new(&[]);
            let mut trace: Vec<Ask> = (0..3000u64)
                .map(|n| ask(START + n * 600, me, &format!("h{n}.example.org"), A, 0, 60))
                .collect();
            trace.extend((0..burst).map(|n| {
                ask(
                    START + 30 * MINUTE + n * (MINUTE / burst),
                    me,
                    &format!("b{n}.example.org"),
                    A,
                    0,
                    60,
                )
            }));
            rig.run(&trace);
            rig.alerts.len()
        };
        assert_eq!(run(900), 0);
        assert_eq!(run(1000), 1);
    }

    #[test]
    fn a_burst_raises_once_a_minute_and_a_longer_one_raises_again_only_while_it_outgrows_the_baseline()
     {
        let me = client(11);
        let mut rig = Rig::new(&[]);
        let mut trace = busy_minute(me, 20, 400);
        // 400 more in the same minute are no new alert.
        let begin = START + 20 * MINUTE;
        trace.extend((0..400u64).map(|n| {
            ask(
                begin + 100 + n * 100,
                me,
                &format!("x{n}.example.org"),
                A,
                0,
                60,
            )
        }));
        trace.sort_by_key(|(at, _)| *at);
        rig.run(&trace);
        assert_eq!(rig.kinds(), ["burst"]);
        // The next minute of 400 is no burst: the baseline has risen to a tenth of it.
        rig.run(
            &(0..400u64)
                .map(|n| {
                    ask(
                        begin + MINUTE + n * 100,
                        me,
                        &format!("y{n}.example.org"),
                        A,
                        0,
                        60,
                    )
                })
                .collect::<Vec<_>>(),
        );
        assert_eq!(rig.kinds(), ["burst"]);
    }

    #[test]
    fn minutes_with_no_question_pull_the_baseline_down_and_the_catch_up_is_capped() {
        let mut burst = Burst::new(START);
        burst.baseline = 100.0;
        burst.count = 8;
        // The minute that ended counted 8: 100 + (8 - 100) / 8 = 88.5; one empty minute follows.
        burst.roll(START / MINUTE + 2);
        let want = (100.0 + (8.0 - 100.0) / 8.0) * 7.0 / 8.0;
        assert!((burst.baseline - want).abs() < 1e-9, "{}", burst.baseline);
        assert_eq!((burst.minute, burst.count), (START / MINUTE + 2, 0));
        // A day of silence costs 60 steps of an eighth, and the one for the minute that ended, not
        // 1440: 61 steps leave 0.03 % of the baseline, which is as good as nothing and is not 0.
        let mut burst = Burst::new(START);
        burst.baseline = 1000.0;
        burst.roll(START / MINUTE + 1440);
        let want = 1000.0 * (7.0f64 / 8.0).powi(61);
        assert!((burst.baseline - want).abs() < 1e-9, "{}", burst.baseline);
        assert!(burst.baseline > 0.1 && burst.baseline < 0.5);
    }

    #[test]
    fn quiet_names_are_skipped_by_every_detector_and_only_at_a_label_boundary() {
        let me = client(12);
        let mut rng = Rng::new();
        // Each trace that raises on its own, with its own quiet name.
        let cases: Vec<(Vec<Ask>, &str)> = vec![
            (random_names(me, &mut rng, 25, SECOND), "com"),
            (long_names(me, &mut rng, 40, SECOND, 60), "example.com"),
            (txt_trace(me, 100, 0, 16), "example.org"),
            (
                periodic(me, "telemetry.example.org", 60, 300, 5, 3.5),
                "example.org",
            ),
            (busy_minute(me, 20, 400), "example.org"),
        ];
        for (trace, quiet) in cases {
            let mut rig = Rig::new(&[]);
            rig.run(&trace);
            assert!(!rig.alerts.is_empty(), "{quiet} raises nothing without it");
            // With a quiet name, nothing is raised, and nothing of the client is even kept.
            let mut rig = Rig::new(&[quiet]);
            rig.run(&trace);
            assert!(rig.alerts.is_empty(), "{quiet}: {:?}", rig.alerts);
            assert!(rig.behaviour.clients.is_empty(), "{quiet}");
        }
        // The upper case, a trailing dot and a blank entry are taken as they should be.
        let mut rig = Rig::new(&["Example.COM.", "  ", ""]);
        rig.run(&long_names(me, &mut rng, 40, SECOND, 60));
        assert!(rig.alerts.is_empty());
        // A name that only ends in the same letters is not under it.
        let mut rig = Rig::new(&["ample.com"]);
        rig.run(&long_names(me, &mut rng, 40, SECOND, 60));
        assert_eq!(rig.kinds(), ["tunnel"]);
    }

    /// The bytes that iodine's Base128 makes labels of: letters, digits and the bytes from 0xBC up.
    fn base128() -> Vec<u8> {
        let mut alphabet = ALNUM.to_vec();
        alphabet.extend(b'A'..=b'Z');
        alphabet.extend(0xbcu8..=0xff);
        alphabet
    }

    /// The bytes that iodine's Base64 makes labels of: letters, digits, `+` and `_`.
    fn base64() -> Vec<u8> {
        let mut alphabet = ALNUM.to_vec();
        alphabet.extend(b'A'..=b'Z');
        alphabet.extend(*b"+_");
        alphabet
    }

    /// The wire form of a name of `labels` labels of `len` bytes drawn from `alphabet`, under
    /// `tail` (text).
    fn tunnel_wire(
        rng: &mut Rng,
        alphabet: &[u8],
        labels: usize,
        len: usize,
        tail: &str,
    ) -> Vec<u8> {
        let mut wire = Vec::new();
        for _ in 0..labels {
            wire.push(u8::try_from(len).unwrap());
            for _ in 0..len {
                let at = usize::try_from(rng.below(alphabet.len() as u64)).unwrap();
                wire.push(alphabet[at]);
            }
        }
        wire.extend_from_slice(&wire_of(tail));
        wire
    }

    /// A trace of `count` questions of type `qtype`, `spacing` ms apart, whose names are made by
    /// `name`, which is given the number of the question.
    fn trace_of(
        client: IpAddr,
        count: u64,
        spacing: u64,
        qtype: u16,
        mut name: impl FnMut(u64) -> Vec<u8>,
    ) -> Vec<Ask> {
        (0..count)
            .map(|n| {
                let event = Event::for_test_wire(client, &name(n), qtype, NOERROR, 60);
                (START + n * spacing, event)
            })
            .collect()
    }

    #[test]
    fn an_iodine_null_flood_with_base128_labels_under_one_domain_raises_tunnel() {
        let me = client(12);
        let mut rng = Rng::new();
        let alphabet = base128();
        let trace = trace_of(me, 150, 2 * SECOND, 10, |_| {
            tunnel_wire(&mut rng, &alphabet, 3, 57, "t.example.com")
        });
        // None of those names is text that a host has.
        let mut buf = [0u8; names::NAME_TEXT_MAX];
        assert!(
            trace
                .iter()
                .all(|(_, e)| names::decode(e.name_wire(), &mut buf).is_none())
        );
        let mut rig = Rig::new(&[]);
        rig.run(&trace[..39]);
        assert!(rig.alerts.is_empty());
        // The fortieth distinct long name raises for the domain, and the hundredth NULL question,
        // all of them half of the questions, for the share.
        rig.run(&trace[39..]);
        assert_eq!(
            rig.alerts,
            vec![
                seen("tunnel", "high", me, "example.com"),
                seen("tunnel", "high", me, "TXT/NULL share"),
            ]
        );
    }

    #[test]
    fn a_base64_tunnel_with_a_plus_in_its_labels_raises_tunnel_for_its_domain() {
        let me = client(12);
        let mut rng = Rng::new();
        let alphabet = base64();
        let trace = trace_of(me, 40, 5 * SECOND, 16, |_| {
            tunnel_wire(&mut rng, &alphabet, 2, 60, "t.example.co.uk")
        });
        let mut rig = Rig::new(&[]);
        rig.run(&trace);
        assert_eq!(
            rig.alerts,
            vec![seen("tunnel", "high", me, "example.co.uk")]
        );
    }

    #[test]
    fn a_name_with_odd_bytes_is_long_from_twenty_bytes_and_a_name_without_from_forty() {
        let me = client(12);
        let run = |label: &dyn Fn(u64) -> Vec<u8>, count: u64| {
            let mut rig = Rig::new(&[]);
            rig.run(&trace_of(me, count, 5 * SECOND, A, |n| {
                let mut wire = label(n);
                wire.extend_from_slice(&wire_of("example.org"));
                wire
            }));
            rig.alerts.len()
        };
        // A label of `len` bytes: a plus, then the number of the name in digits, then letters.
        let odd = |len: usize| {
            move |n: u64| {
                let mut label = format!("+{n:06}").into_bytes();
                label.resize(len, b'x');
                let mut wire = vec![u8::try_from(len).unwrap()];
                wire.extend_from_slice(&label);
                wire
            }
        };
        assert_eq!(run(&odd(20), 40), 1);
        assert_eq!(run(&odd(20), 39), 0);
        assert_eq!(run(&odd(19), 40), 0);
        assert_eq!(run(&odd(19), 400), 0);
        // Without odd bytes the name is the old 40, and it decodes as a name.
        let plain = |len: usize| {
            move |n: u64| {
                let mut label = format!("p{n:06}").into_bytes();
                label.resize(len, b'x');
                let mut wire = vec![u8::try_from(len).unwrap()];
                wire.extend_from_slice(&label);
                wire
            }
        };
        assert_eq!(run(&plain(39), 40), 0);
        assert_eq!(run(&plain(40), 40), 1);
    }

    #[test]
    fn odd_bytes_in_the_registrable_domain_itself_raise_no_tunnel_but_the_client_is_kept() {
        let me = client(12);
        let mut rig = Rig::new(&[]);
        let mut rng = Rng::new();
        let alphabet = base64();
        rig.run(&trace_of(me, 100, SECOND, A, |_| {
            tunnel_wire(&mut rng, &alphabet, 2, 60, "exa\u{ff}mple.org")
        }));
        assert!(rig.alerts.is_empty(), "{:?}", rig.alerts);
        assert_eq!(rig.behaviour.clients.len(), 1);
    }

    #[test]
    fn names_with_odd_bytes_count_for_the_burst_and_for_the_txt_share() {
        let me = client(12);
        let odd = |n: u64| {
            let mut wire = vec![7, b'h', 0xff];
            wire.extend_from_slice(format!("{n:05}").as_bytes());
            wire.extend_from_slice(&wire_of("example.org"));
            wire
        };
        // 20 questions a minute for 20 minutes, then 400 in one minute.
        let mut trace = trace_of(me, 400, 3 * SECOND, A, odd);
        trace.extend(
            trace_of(me, 400, MINUTE / 400, A, |n| odd(1000 + n))
                .into_iter()
                .map(|(at, event)| (at + 20 * MINUTE, event)),
        );
        let mut rig = Rig::new(&[]);
        rig.run(&trace);
        assert_eq!(rig.kinds(), ["burst"]);
        // A hundred TXT questions that are all of them.
        let mut rig = Rig::new(&[]);
        rig.run(&trace_of(me, 100, 2 * SECOND, 16, odd));
        assert_eq!(
            rig.alerts,
            vec![seen("tunnel", "high", me, "TXT/NULL share")]
        );
    }

    #[test]
    fn names_with_odd_bytes_are_no_dga_and_no_beacon() {
        let me = client(12);
        let mut rng = Rng::new();
        // Names that do not exist and look made up, each with an odd byte.
        let mut rig = Rig::new(&[]);
        rig.run(
            &trace_of(me, 60, SECOND, A, |_| {
                let mut wire = vec![13];
                wire.extend_from_slice(rng.random_label().as_bytes());
                wire.push(0xff);
                wire.extend_from_slice(&wire_of("com"));
                wire
            })
            .into_iter()
            .map(|(at, mut event)| {
                event.rcode = 3;
                (at, event)
            })
            .collect::<Vec<_>>(),
        );
        assert!(rig.alerts.is_empty(), "{:?}", rig.alerts);
        // One such name asked every 300 s for 3.5 hours.
        let mut rig = Rig::new(&[]);
        let mut wire = vec![9];
        wire.extend_from_slice(b"beacon+ab");
        wire.extend_from_slice(&wire_of("example.org"));
        for n in 0..42u64 {
            let event = Event::for_test_wire(me, &wire, A, NOERROR, 60);
            rig.feed(START + n * 300 * SECOND, &event);
        }
        assert!(rig.alerts.is_empty(), "{:?}", rig.alerts);
    }

    #[test]
    fn quiet_names_skip_the_questions_with_odd_bytes_too() {
        let me = client(12);
        let mut rng = Rng::new();
        let alphabet = base128();
        let trace = trace_of(me, 150, 2 * SECOND, 10, |_| {
            tunnel_wire(&mut rng, &alphabet, 3, 57, "t.example.com")
        });
        let mut rig = Rig::new(&["example.com"]);
        rig.run(&trace);
        assert!(rig.alerts.is_empty());
        assert!(rig.behaviour.clients.is_empty());
        let mut rig = Rig::new(&["t.example.com"]);
        rig.run(&trace);
        assert!(rig.alerts.is_empty());
        // Only at a label boundary.
        let mut rig = Rig::new(&["ample.com"]);
        rig.run(&trace);
        assert_eq!(rig.kinds(), ["tunnel", "tunnel"]);
    }

    #[test]
    fn an_event_whose_name_has_no_shape_of_a_name_is_skipped_and_its_client_is_not_kept() {
        let me = client(12);
        let mut long = vec![64];
        long.extend_from_slice(&[b'a'; 64]);
        long.push(0);
        let mut rig = Rig::new(&[]);
        for n in 0..500u64 {
            // The root, a pointer, a label past the end, a name that is not ended, a label over 63.
            for wire in [
                &[0u8][..],
                &[0xC0, 12],
                &[5, b'a', b'b', 0],
                &[3, b'w', b'w', b'w'],
                &long,
            ] {
                rig.feed(
                    START + n * SECOND,
                    &Event::for_test_wire(me, wire, 16, 0, 60),
                );
            }
        }
        assert!(rig.alerts.is_empty());
        assert!(rig.behaviour.clients.is_empty());
    }

    #[test]
    fn a_129th_client_takes_the_place_of_the_one_seen_longest_ago() {
        let mut rig = Rig::new(&[]);
        let host = |n: u64| IpAddr::V4(Ipv4Addr::new(198, 51, 100, u8::try_from(n % 256).unwrap()));
        let event = |n: u64| Event::for_test(host(n), "www.example.org", A, NOERROR, 60);
        for n in 0..128u64 {
            rig.feed(START + n * SECOND, &event(n));
        }
        assert_eq!(rig.behaviour.clients.len(), MAX_CLIENTS);
        // The first client asks again, so the second is the one seen longest ago.
        rig.feed(START + 128 * SECOND, &event(0));
        let other = Event::for_test(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            "www.example.org",
            A,
            NOERROR,
            60,
        );
        rig.feed(START + 129 * SECOND, &other);
        let addrs: Vec<IpAddr> = rig.behaviour.clients.iter().map(|c| c.addr).collect();
        assert_eq!(addrs.len(), MAX_CLIENTS);
        assert!(addrs.contains(&host(0)));
        assert!(!addrs.contains(&host(1)));
        assert!(addrs.contains(&other.client));
        // The client that came back has none of its old state: it is seen for the first time.
        let first = rig.record(other.client);
        assert_eq!(first.burst.first_ms, START + 129 * SECOND);
        // The table never grows past its size, whoever asks.
        for n in 0..1000u64 {
            let addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, u8::try_from(n % 250).unwrap()));
            let event = Event::for_test(addr, "www.example.org", A, NOERROR, 60);
            rig.feed(START + 200 * SECOND + n * SECOND, &event);
        }
        assert_eq!(rig.behaviour.clients.len(), MAX_CLIENTS);
    }

    #[test]
    fn a_flood_of_a_hundred_thousand_random_names_leaves_the_tables_of_a_client_at_their_caps() {
        let me = client(13);
        let mut rng = Rng::new();
        let mut rig = Rig::new(&[]);
        for n in 0..100_000u64 {
            let at = START + n * 100;
            let (name, qtype, rcode) = match n % 4 {
                // Random names that do not exist: the DGA table.
                0 => (format!("{}.com", rng.random_label()), A, 3),
                // Long names under one domain: the hashes of one domain.
                1 => (format!("{}.example.com", rng.token(50, HEX)), A, NOERROR),
                // Long names under a new domain each: the table of domains.
                2 => (
                    format!("{}.{}.net", rng.token(50, HEX), rng.token(9, LOWER)),
                    A,
                    NOERROR,
                ),
                // Many names, some TXT: the slots and the share.
                _ => (format!("{}.example.org", rng.token(10, ALNUM)), 16, NOERROR),
            };
            rig.feed(at, &Event::for_test(me, &name, qtype, rcode, 60));
        }
        let record = rig.record(me);
        assert_eq!(rig.behaviour.clients.len(), 1);
        assert_eq!(record.dga.seen.len(), DGA_NAMES);
        assert_eq!(record.domains.len(), TUNNEL_DOMAINS);
        let most = record.domains.iter().map(|d| d.names.seen.len()).max();
        assert_eq!(most, Some(TUNNEL_HASHES));
        assert!(
            record
                .domains
                .iter()
                .all(|d| d.names.seen.len() <= TUNNEL_HASHES)
        );
        assert_eq!(record.slots.len(), BEACON_SLOTS);
        // The vectors never held more than their caps, so they never grew past them.
        assert!(record.dga.seen.capacity() <= 2 * DGA_NAMES);
        assert!(record.domains.capacity() <= 2 * TUNNEL_DOMAINS);
        assert!(record.slots.capacity() <= 2 * BEACON_SLOTS);
        assert!(
            record
                .domains
                .iter()
                .all(|d| d.names.seen.capacity() <= 2 * TUNNEL_HASHES)
        );
        // And it raised what a flood raises, over and over, and nothing else.
        assert!(rig.alerts.len() > 3);
        assert!(
            rig.kinds()
                .iter()
                .all(|kind| ["dga", "tunnel", "burst"].contains(kind))
        );
    }

    /// The six clients of the household trace.
    const LAPTOP: u8 = 11;
    /// The phone.
    const PHONE: u8 = 12;
    /// The TV.
    const TV: u8 = 13;
    /// The mail client.
    const MAIL: u8 = 14;
    /// The device of the Internet of things.
    const IOT: u8 = 15;
    /// The tablet.
    const TABLET: u8 = 16;
    /// How long the household trace is, in hours.
    const HOURS: u64 = 6;

    /// A name of a content network, with a made-up part that is under 40 bytes.
    fn cdn_name(rng: &mut Rng) -> String {
        match rng.below(6) {
            0 => format!("d{}.cloudfront.net", rng.token(13, ALNUM)),
            1 => format!("e{}.dscb.akamaiedge.net", rng.below(9000) + 1000),
            2 => format!(
                "rr{}---sn-{}.googlevideo.com",
                rng.between(1, 9),
                rng.token(8, ALNUM)
            ),
            3 => format!(
                "{}.{}.example.com",
                rng.token(20, ALNUM),
                rng.token(18, ALNUM)
            ),
            4 => format!("{}.cdn.example.net", rng.token(32, HEX)),
            _ => format!("www.{}.example.org", rng.token(9, LOWER)),
        }
    }

    /// The browsing of a client over the six hours: a session of 30 to 150 different names in one
    /// minute every 15 to 40 minutes, with a few typos and some names that come back.
    fn browsing(client: IpAddr, rng: &mut Rng, trace: &mut Vec<Ask>) {
        let typos = [
            "faceboook.com",
            "gogle.com",
            "wikipedai.org",
            "yutube.com",
            "redit.com",
        ];
        let popular = ["www.example.org", "api.example.com", "static.example.net"];
        let end = START + HOURS * HOUR;
        let mut at = START + rng.between(1, 20) * MINUTE;
        while at < end {
            let minute = at / MINUTE * MINUTE;
            for _ in 0..rng.between(30, 150) {
                let name = cdn_name(rng);
                let qtype = if rng.below(2) == 0 { A } else { AAAA };
                let ttl = u32::try_from(rng.between(20, 3600)).unwrap();
                trace.push(ask(
                    minute + rng.below(MINUTE),
                    client,
                    &name,
                    qtype,
                    NOERROR,
                    ttl,
                ));
            }
            for _ in 0..rng.below(3) {
                let typo = typos[usize::try_from(rng.below(5)).unwrap()];
                trace.push(ask(minute + rng.below(MINUTE), client, typo, A, 3, 0));
            }
            for name in popular {
                if rng.below(2) == 0 {
                    trace.push(ask(
                        minute + rng.below(MINUTE),
                        client,
                        name,
                        A,
                        NOERROR,
                        300,
                    ));
                }
            }
            at += rng.between(15, 40) * MINUTE;
        }
    }

    /// The household of six clients over six hours, as one trace in the order of time. The TV asks
    /// its names `tv_ttls` at the end of their TTLs when it is (300, 60).
    fn household(tv_ttls: (u32, u32)) -> Vec<Ask> {
        let mut rng = Rng::new();
        let mut trace = Vec::new();
        let end = START + HOURS * HOUR;
        let hours = HOURS as f64;
        // Two browsing clients.
        browsing(client(LAPTOP), &mut rng, &mut trace);
        browsing(client(TABLET), &mut rng, &mut trace);
        // The laptop: Chrome asks three random single-label names, three times an hour.
        for hour in 0..HOURS {
            let at = START + hour * HOUR + rng.below(HOUR - SECOND);
            for n in 0..3 {
                let name = rng.token(10, LOWER);
                trace.push(ask(at + n * 10, client(LAPTOP), &name, A, 3, 0));
            }
        }
        // The TV: three names, asked when their TTLs run out, all day.
        trace.extend(periodic(
            client(TV),
            "api.tv.example.com",
            tv_ttls.0,
            300,
            0,
            hours,
        ));
        trace.extend(periodic(
            client(TV),
            "ota.tv.example.com",
            tv_ttls.1,
            60,
            0,
            hours,
        ));
        trace.extend(periodic(
            client(TV),
            "time.tv.example.org",
            tv_ttls.0,
            300,
            1,
            hours,
        ));
        // The phone: push and connectivity checks, which are skipped by name, with a TTL that
        // would not hide them; and a cloud name that it asks A and AAAA for, the AAAA with none.
        trace.extend(periodic(
            client(PHONE),
            "mtalk.google.com",
            30,
            240,
            2,
            hours,
        ));
        trace.extend(periodic(
            client(PHONE),
            "connectivitycheck.gstatic.com",
            30,
            300,
            3,
            hours,
        ));
        trace.extend(periodic(
            client(PHONE),
            "courier.push.apple.com",
            20,
            600,
            1,
            hours,
        ));
        let cloud = periodic(client(PHONE), "cloud.example.com", 300, 300, 1, hours);
        for (at, _) in &cloud {
            trace.push(ask(
                at + 50,
                client(PHONE),
                "cloud.example.com",
                AAAA,
                NOERROR,
                0,
            ));
        }
        trace.extend(cloud);
        // The mail client: its server at the end of the TTL, and a TXT question now and then.
        trace.extend(periodic(
            client(MAIL),
            "imap.example.org",
            600,
            600,
            1,
            hours,
        ));
        for hour in 0..HOURS {
            for _ in 0..rng.between(1, 4) {
                let at = START + hour * HOUR + rng.below(HOUR);
                trace.push(ask(at, client(MAIL), "example.org", 16, NOERROR, 3600));
            }
        }
        // The device of the Internet of things: a service name that starts with an underscore.
        trace.extend(periodic_as(
            client(IOT),
            "_hap._tcp.example.org",
            SRV,
            600,
            600,
            2,
            hours,
        ));
        trace.retain(|(at, _)| *at < end);
        trace.sort_by_key(|(at, _)| *at);
        trace
    }

    #[test]
    fn a_normal_household_over_six_hours_raises_nothing() {
        let trace = household((300, 60));
        assert!(trace.len() > 2500, "{}", trace.len());
        let mut rig = Rig::new(&[]);
        rig.run(&trace);
        assert!(rig.alerts.is_empty(), "{:?}", rig.alerts);
        // Every client was looked at.
        assert_eq!(rig.behaviour.clients.len(), 6);
    }

    #[test]
    fn the_household_trace_does_see_a_tv_that_does_not_ask_at_the_end_of_the_ttl() {
        // The same trace where the answers say an hour, and the TV asks every 300 s and 60 s: the
        // three names of the TV are beacons, and nothing else is.
        let trace = household((3600, 3600));
        let mut rig = Rig::new(&[]);
        rig.run(&trace);
        let mut subjects: Vec<&str> = rig.alerts.iter().map(|a| a.subject.as_str()).collect();
        subjects.sort_unstable();
        assert_eq!(
            subjects,
            [
                "api.tv.example.com",
                "ota.tv.example.com",
                "time.tv.example.org"
            ]
        );
        assert!(
            rig.alerts.iter().all(|a| a.kind == "beacon"
                && a.severity == "info"
                && a.client == Some(client(TV)))
        );
    }
}
