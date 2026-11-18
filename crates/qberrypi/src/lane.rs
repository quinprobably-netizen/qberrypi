//! The lane feed: the names that the DNS service lets the front panel see, a few at a time.
//!
//! The panel's lane shows names going by, and the gate stops the refused ones. The resolver offers
//! each name it decides to [`LaneFeed::observe`], which keeps the ones worth showing in a small
//! ring, and the panel's thread takes them out with [`LaneFeed::take`]. A refused name is always
//! kept, and a plain one at most once a second, so a busy network shows a trickle of names and
//! every refusal.
//!
//! `observe` runs inside `Dns::decide`, on the listener's receive loop, so it never waits and
//! never allocates: the ring is taken with `try_lock` and a name that finds it busy is dropped, and
//! the bytes of a name are copied into a slot of a fixed size. When the panel is behind, names are
//! dropped, and the drops are counted.
//!
//! A device's own names: while the panel shows one device's screen it asks for that device's
//! addresses to be watched ([`LaneFeed::watch_client`]), and `offer_latest` then keeps the last two
//! names that address asked in a ring of two fixed slots, for [`LaneFeed::watched_names`]. When no
//! device is watched, which is always but while that screen is open, the cost on the answer path
//! is one relaxed load and nothing is kept per client. A matching name is put in by `try_lock`
//! as the lane's are, in a slot of fixed size, so nothing waits and nothing allocates.
//!
//! A name reaches the physical screen and nothing else. These types implement no `Debug` and no
//! `Serialize`, nothing here logs, and no `Source`, API or status page hands the feed out.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, TryLockError};

use qb_dns::{Now, Outcome, Resolver};
use qb_panel::drain::NameKind;

/// The names the ring holds before it drops one.
pub const LANE_SLOTS: usize = 8;

/// The bytes of a name that the ring keeps; the panel shows 20 characters of them.
pub const LANE_NAME_BYTES: usize = 32;

/// The names of the watched device that the feed keeps: the last two it asked.
pub const WATCH_SLOTS: usize = 2;

/// The bytes of a name of the watched device that its slot keeps: the longest a DNS name is, so that the
/// device's screen has the whole name to open NAME with. Its row shows it cut as the lane's names are.
pub const WATCH_NAME_BYTES: usize = qb_panel::os::world::NAME_BYTES_MAX;

/// What `last_plain` holds before any plain name was sampled: no second a clock gives.
const NO_SECOND: u64 = u64::MAX;

/// A name taken from the feed, for the panel's thread to show. Made only on the panel's side.
pub struct LaneName {
    /// The name as the resolver recorded it: lower case, no trailing dot. Cut to its first
    /// [`LANE_NAME_BYTES`] bytes at a character boundary; a name cut short to fewer than that many
    /// characters, which only a name of wide characters is, ends with a `~`.
    pub name: String,
    /// How the lane treats it: a refused name stops at the gate, and a plain one passes.
    pub kind: NameKind,
}

/// One name in the ring: its bytes, in a slot of a fixed size.
#[derive(Clone, Copy)]
struct Entry {
    bytes: [u8; LANE_NAME_BYTES],
    /// How many of `bytes` are the name's.
    len: u8,
    /// Whether the name was longer than the slot.
    cut: bool,
    kind: NameKind,
}

impl Entry {
    const EMPTY: Self = Self {
        bytes: [0; LANE_NAME_BYTES],
        len: 0,
        cut: false,
        kind: NameKind::Plain,
    };

    /// The first [`LANE_NAME_BYTES`] bytes of `name`, less any part of a character at the end.
    fn of(name: &str, kind: NameKind) -> Self {
        let mut end = name.len().min(LANE_NAME_BYTES);
        while !name.is_char_boundary(end) {
            end -= 1;
        }
        let mut entry = Self::EMPTY;
        if let (Some(slot), Some(kept)) = (entry.bytes.get_mut(..end), name.as_bytes().get(..end)) {
            slot.copy_from_slice(kept);
        }
        // At most `LANE_NAME_BYTES`, which is 32.
        entry.len = u8::try_from(end).unwrap_or(u8::MAX);
        entry.cut = end < name.len();
        entry.kind = kind;
        entry
    }

    /// The name for the panel's thread, which may allocate.
    fn into_name(self) -> LaneName {
        let kept = self.bytes.get(..usize::from(self.len)).unwrap_or_default();
        let mut name = String::from_utf8_lossy(kept).into_owned();
        // A cut name of 32 characters reads as cut once it is fitted to the lane. One of wide
        // characters may be too short for that, so it says so itself.
        if self.cut && name.chars().count() < LANE_NAME_BYTES {
            name.push('~');
        }
        LaneName {
            name,
            kind: self.kind,
        }
    }
}

/// The names that wait for the panel, oldest first.
struct Ring {
    entries: [Entry; LANE_SLOTS],
    /// How many of `entries`, from the first, are in use.
    len: usize,
}

/// What came of offering a name to the ring.
enum Pushed {
    /// It is in the ring.
    Kept,
    /// It is in the ring, and a plain name that was there is not.
    Displaced,
    /// It is not in the ring.
    Dropped,
}

impl Ring {
    /// Keeps `entry` if there is room, or if it is a refused name and a name that is not refused
    /// can make room: the oldest such name is dropped, and the rest keep their order.
    fn push(&mut self, entry: Entry) -> Pushed {
        if let Some(free) = self.entries.get_mut(self.len) {
            *free = entry;
            self.len += 1;
            return Pushed::Kept;
        }
        if entry.kind != NameKind::Refused {
            return Pushed::Dropped;
        }
        let held = self.entries.get_mut(..self.len).unwrap_or_default();
        let Some(oldest_plain) = held.iter().position(|e| e.kind != NameKind::Refused) else {
            return Pushed::Dropped;
        };
        held.copy_within(oldest_plain + 1.., oldest_plain);
        if let Some(last) = held.last_mut() {
            *last = entry;
        }
        Pushed::Displaced
    }
}

/// How a watched device's name was answered, as its screen says it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchedOutcome {
    /// The name is on the lists and was refused.
    Refused,
    /// The name is on the lists and was let through: the device is exempt, or blocking is paused.
    Passed,
    /// The name is not on the lists, and was answered.
    Answered,
}

/// A name that the watched device asked, taken from the feed for the panel's thread to show. Made
/// only on the panel's side. It has no `Debug`: the name is the device's own business.
pub struct WatchedName {
    /// The name as the resolver recorded it, cut as a [`LaneName`] is: what its row shows.
    pub name: String,
    /// The name as the resolver recorded it, whole: what its row opens NAME with. `None` for a name longer
    /// than [`WATCH_NAME_BYTES`], which is no DNS name and was not kept whole.
    pub whole: Option<String>,
    /// How it was answered.
    pub outcome: WatchedOutcome,
}

/// One name of the watched device in the ring: its bytes, in a slot of a fixed size.
#[derive(Clone, Copy)]
struct WatchSlot {
    bytes: [u8; WATCH_NAME_BYTES],
    /// How many of `bytes` are the name's.
    len: u8,
    /// Whether the name was longer than the slot.
    cut: bool,
    outcome: WatchedOutcome,
}

impl WatchSlot {
    const EMPTY: Self = Self {
        bytes: [0; WATCH_NAME_BYTES],
        len: 0,
        cut: false,
        outcome: WatchedOutcome::Answered,
    };

    /// The first [`WATCH_NAME_BYTES`] bytes of `name`, less any part of a character at the end: a DNS name
    /// whole.
    fn of(name: &str, outcome: WatchedOutcome) -> Self {
        let mut end = name.len().min(WATCH_NAME_BYTES);
        while !name.is_char_boundary(end) {
            end -= 1;
        }
        let mut slot = Self::EMPTY;
        if let (Some(room), Some(kept)) = (slot.bytes.get_mut(..end), name.as_bytes().get(..end)) {
            room.copy_from_slice(kept);
        }
        // At most `WATCH_NAME_BYTES`, which is 253.
        slot.len = u8::try_from(end).unwrap_or(u8::MAX);
        slot.cut = end < name.len();
        slot.outcome = outcome;
        slot
    }

    /// The bytes of the name.
    fn kept(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or_default()
    }

    /// The name for the panel's thread, which may allocate: whole, and cut for its row as a [`LaneName`] is
    /// (its first [`LANE_NAME_BYTES`] bytes at a character boundary, and a `~` after a name of wide characters
    /// that this leaves shorter than that many characters).
    fn into_name(self) -> WatchedName {
        let kept = String::from_utf8_lossy(self.kept()).into_owned();
        let mut end = kept.len().min(LANE_NAME_BYTES);
        while !kept.is_char_boundary(end) {
            end -= 1;
        }
        let mut name = kept.get(..end).unwrap_or_default().to_owned();
        if (self.cut || end < kept.len()) && name.chars().count() < LANE_NAME_BYTES {
            name.push('~');
        }
        WatchedName {
            name,
            whole: (!self.cut).then_some(kept),
            outcome: self.outcome,
        }
    }
}

/// The last names of the watched device, newest first, and whose they are.
struct WatchRing {
    /// The IPv4 address (as a number) the names belong to; 0 for none. Set under the lock together
    /// with `watched`, so a name that was offered for the device before this one never lands in
    /// the ring of this one.
    client: u32,
    slots: [WatchSlot; WATCH_SLOTS],
    /// How many of `slots`, from the first, are in use.
    len: usize,
}

impl WatchRing {
    /// Puts `slot` first. The name that is first already, or second, is that name again (a device
    /// asks A and AAAA of one name): it moves to the front with the new outcome and nothing else
    /// is pushed out, so the two places hold two different names.
    fn push(&mut self, slot: WatchSlot) {
        let held = self.slots.get(..self.len).unwrap_or_default();
        let at = held
            .iter()
            .position(|old| old.kept() == slot.kept() && old.cut == slot.cut);
        let from = at.unwrap_or_else(|| self.len.min(WATCH_SLOTS - 1));
        // The names before `from` move back one place; the one at `from` is overwritten.
        self.slots.copy_within(..from, 1);
        if let Some(first) = self.slots.first_mut() {
            *first = slot;
        }
        if at.is_none() {
            self.len = (self.len + 1).min(WATCH_SLOTS);
        }
    }
}

/// The IPv4 address of `client` as a number: an IPv4 address, or an IPv4 address mapped into
/// IPv6. 0 for any other, and for none, which no watched address is.
fn client_key(client: Option<IpAddr>) -> u32 {
    match client {
        Some(IpAddr::V4(v4)) => u32::from(v4),
        Some(IpAddr::V6(v6)) => v6.to_ipv4_mapped().map_or(0, u32::from),
        None => 0,
    }
}

/// The feed from the DNS service to the front panel: a ring of the names to show.
pub struct LaneFeed {
    /// Taken with `try_lock` by the resolver's side, and with `lock` by the panel's, which holds
    /// it for a copy.
    ring: Mutex<Ring>,
    /// The monotonic second of the plain name that was last let through; [`NO_SECOND`] for none.
    last_plain: AtomicU64,
    /// The names that were lost: dropped by `observe`, or displaced from the ring.
    dropped: AtomicU64,
    /// The IPv4 address whose names are kept, as a number; 0 while none is. The one thing the
    /// answer path reads when no device is watched.
    watched: AtomicU32,
    /// The names of the watched device. Taken with `try_lock` by the resolver's side, and with
    /// `lock` by the panel's, which holds it for a copy.
    watch: Mutex<WatchRing>,
}

impl LaneFeed {
    /// An empty feed, watching nobody.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            ring: Mutex::new(Ring {
                entries: [Entry::EMPTY; LANE_SLOTS],
                len: 0,
            }),
            last_plain: AtomicU64::new(NO_SECOND),
            dropped: AtomicU64::new(0),
            watched: AtomicU32::new(0),
            watch: Mutex::new(WatchRing {
                client: 0,
                slots: [WatchSlot::EMPTY; WATCH_SLOTS],
                len: 0,
            }),
        })
    }

    /// Offers one name that the resolver decided, at `mono_secs` on its monotonic clock. It does
    /// not wait and does not allocate.
    ///
    /// A `refused` name is always kept. Any other is kept only if no other has been since
    /// `mono_secs` last changed, so the plain names are sampled at one a second; `listed` is
    /// asked about those, and no others, and says whether the name is on the lists though it was
    /// let through (a pause), which makes it [`NameKind::Listed`]. An empty name is not shown.
    ///
    /// A name is dropped, and counted, if the ring is in use by the panel's thread, or is full
    /// and has no plain name for a refused one to take the place of.
    pub fn observe(
        &self,
        name: &str,
        refused: bool,
        mono_secs: u64,
        listed: impl FnOnce(&str) -> bool,
    ) {
        if name.is_empty() {
            return;
        }
        let kind = if refused {
            NameKind::Refused
        } else {
            // The same second again is the common case, and it only reads.
            let last = self.last_plain.load(Ordering::Relaxed);
            if last == mono_secs
                || self
                    .last_plain
                    .compare_exchange(last, mono_secs, Ordering::Relaxed, Ordering::Relaxed)
                    .is_err()
            {
                return;
            }
            if listed(name) {
                NameKind::Listed
            } else {
                NameKind::Plain
            }
        };
        let entry = Entry::of(name, kind);
        let pushed = match self.ring.try_lock() {
            Ok(mut ring) => ring.push(entry),
            // The panel's thread holds it for a copy, and a holder that panicked left it poisoned.
            Err(TryLockError::WouldBlock | TryLockError::Poisoned(_)) => Pushed::Dropped,
        };
        if !matches!(pushed, Pushed::Kept) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Offers `resolver`'s latest logged query, if it logged one since it had counted
    /// `queries_before` queries: a refused one if it was blocked. Called with the resolver that
    /// just decided a query, as [`LaneFeed::observe`] allows: it does not wait. `client` is who
    /// asked; it matters only while that address is watched ([`LaneFeed::watch_client`]), and
    /// then the name is kept for that device's screen too.
    ///
    /// With nobody watched the watch costs one relaxed load, after the lane's own work.
    pub(crate) fn offer_latest(
        &self,
        resolver: &Resolver,
        queries_before: u64,
        now: Now,
        client: Option<IpAddr>,
    ) {
        let stats = resolver.stats();
        if stats.total().queries == queries_before {
            return;
        }
        let Some(latest) = stats.recent(1).next() else {
            return;
        };
        self.observe(
            &latest.name,
            latest.outcome == Outcome::Blocked,
            now.mono_secs,
            // A name is on the lists but let through only while blocking is paused.
            |name| resolver.paused_until(now).is_some() && resolver.lists(name),
        );
        let watched = self.watched.load(Ordering::Relaxed);
        if watched != 0 {
            self.offer_watched(watched, client, resolver, &latest.name, latest.outcome);
        }
    }

    /// Keeps `name`, which `client` asked and the resolver answered with `outcome`, if `client` is
    /// the `watched` address. It does not wait and does not allocate: whether the name is on the
    /// lists is looked up in a buffer on the stack, and the ring is taken with `try_lock`.
    #[inline(never)]
    fn offer_watched(
        &self,
        watched: u32,
        client: Option<IpAddr>,
        resolver: &Resolver,
        name: &str,
        outcome: Outcome,
    ) {
        if name.is_empty() || client_key(client) != watched {
            return;
        }
        let outcome = if outcome == Outcome::Blocked {
            WatchedOutcome::Refused
        } else if resolver.lists(name) {
            WatchedOutcome::Passed
        } else {
            WatchedOutcome::Answered
        };
        let slot = WatchSlot::of(name, outcome);
        // The panel's thread holds the ring for a copy: a name that finds it busy is dropped.
        if let Ok(mut ring) = self.watch.try_lock()
            && ring.client == watched
        {
            ring.push(slot);
        }
    }

    /// Keeps the names that the device at `client` asks from now on, for
    /// [`LaneFeed::watched_names`], and forgets the names of the one that was watched before. With
    /// `None` nothing is kept, and what was kept is gone: nothing is remembered of a device that
    /// nobody is looking at. An unspecified address (0.0.0.0) is no device and watches nobody.
    ///
    /// For the panel's thread, when a device's screen opens or closes. It takes the ring's lock,
    /// which the resolver's side never waits for.
    pub fn watch_client(&self, client: Option<Ipv4Addr>) {
        let key = client.map_or(0, u32::from);
        let mut ring = self.watch.lock().unwrap_or_else(PoisonError::into_inner);
        // A holder that panicked left it poisoned, and the resolver's side drops names for ever
        // after; the ring is a whole one whatever the holder did, so it is made good again.
        self.watch.clear_poison();
        ring.client = key;
        ring.len = 0;
        // What was kept is gone, not just out of reach.
        ring.slots = [WatchSlot::EMPTY; WATCH_SLOTS];
        self.watched.store(key, Ordering::Relaxed);
    }

    /// The names of the watched device, the newest first, at most [`WATCH_SLOTS`]: into `out`,
    /// whose contents they replace. Nothing is taken: the names stay for the next copy, as a screen
    /// that is on shows them all the while. Empty while nobody is watched, and until the device
    /// asks. For the panel's thread: the ring's lock is held only for the copy, and the names are
    /// made once it is let go.
    pub fn watched_names(&self, out: &mut Vec<WatchedName>) {
        let (slots, len) = {
            let ring = self.watch.lock().unwrap_or_else(PoisonError::into_inner);
            (ring.slots, ring.len)
        };
        out.clear();
        let held = slots.get(..len).unwrap_or_default();
        out.extend(held.iter().map(|slot| slot.into_name()));
    }

    /// Moves the names that wait into `out`, oldest first, and empties the ring. For the panel's
    /// thread: it takes the ring's lock, which the resolver's side never waits for, and holds it
    /// only to copy the entries out and empty the ring. The names are made once it is let go.
    pub fn take(&self, out: &mut Vec<LaneName>) {
        let (entries, len) = {
            let mut ring = self.ring.lock().unwrap_or_else(PoisonError::into_inner);
            let copied = (ring.entries, ring.len);
            ring.len = 0;
            copied
        };
        let held = entries.get(..len).unwrap_or_default();
        out.extend(held.iter().map(|entry| entry.into_name()));
    }

    /// How many names were lost since the start: the ones `observe` dropped because the panel was
    /// behind or the ring was in use, and the plain ones that a refused name took the place of.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Empties the ring, as `take` does, for a benchmark that keeps room in it.
    #[cfg(test)]
    pub(crate) fn clear(&self) {
        self.ring.lock().unwrap_or_else(PoisonError::into_inner).len = 0;
    }

    /// Holds the ring of the watched device's names, as the panel's thread does for a copy, until
    /// what it returns is dropped.
    #[cfg(test)]
    pub(crate) fn busy_watch(&self) -> impl Drop + '_ {
        self.watch.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::Cell;

    use qb_dns::BlockSet;

    /// The names and kinds that `take` gives, which empties the feed.
    fn taken(feed: &LaneFeed) -> Vec<(String, NameKind)> {
        let mut out = Vec::new();
        feed.take(&mut out);
        out.into_iter().map(|n| (n.name, n.kind)).collect()
    }

    fn not_listed(_: &str) -> bool {
        false
    }

    fn plain(name: &str) -> (String, NameKind) {
        (name.to_owned(), NameKind::Plain)
    }

    fn refused(name: &str) -> (String, NameKind) {
        (name.to_owned(), NameKind::Refused)
    }

    #[test]
    fn plain_names_are_sampled_once_a_second_refused_always() {
        let feed = LaneFeed::new();
        // Second 0 is a second like any other.
        feed.observe("a.example.org", false, 0, not_listed);
        feed.observe("b.example.org", false, 0, not_listed);
        feed.observe("c.example.org", false, 1, not_listed);
        feed.observe("d.example.org", false, 1, not_listed);
        feed.observe("ads.example.org", true, 1, not_listed);
        feed.observe("ads.example.org", true, 1, not_listed);
        feed.observe("e.example.org", false, 1, not_listed);
        assert_eq!(
            taken(&feed),
            [
                plain("a.example.org"),
                plain("c.example.org"),
                refused("ads.example.org"),
                refused("ads.example.org"),
            ]
        );
        assert_eq!(feed.dropped(), 0);
        // The gate is per second, not per call: the next second lets one through again.
        feed.observe("f.example.org", false, 2, not_listed);
        assert_eq!(taken(&feed), [plain("f.example.org")]);
        // A refused name does not use up the second's plain name.
        feed.observe("ads.example.org", true, 3, not_listed);
        feed.observe("g.example.org", false, 3, not_listed);
        assert_eq!(taken(&feed).len(), 2);
    }

    #[test]
    fn a_full_feed_drops_and_counts() {
        let feed = LaneFeed::new();
        for i in 0..LANE_SLOTS {
            feed.observe(&format!("ads{i}.example.org"), true, 5, not_listed);
        }
        assert_eq!(feed.dropped(), 0);
        // The ninth refused name finds every place held by a refused one, and a plain name finds
        // it full.
        feed.observe("ads8.example.org", true, 5, not_listed);
        feed.observe("a.example.org", false, 6, not_listed);
        assert_eq!(feed.dropped(), 2);
        let names = taken(&feed);
        assert_eq!(names.len(), LANE_SLOTS);
        assert_eq!(names.first(), Some(&refused("ads0.example.org")));
        assert_eq!(names.last(), Some(&refused("ads7.example.org")));
        // Emptied, it takes names again.
        feed.observe("ads9.example.org", true, 7, not_listed);
        assert_eq!(taken(&feed), [refused("ads9.example.org")]);
        assert_eq!(feed.dropped(), 2);
    }

    #[test]
    fn a_refused_name_displaces_a_plain_one() {
        let feed = LaneFeed::new();
        feed.observe("a.example.org", false, 1, not_listed);
        for i in 0..LANE_SLOTS - 1 {
            feed.observe(&format!("ads{i}.example.org"), true, 1, not_listed);
        }
        // Full, with the plain name first. The newcomer takes its place, at the end.
        feed.observe("ads7.example.org", true, 1, not_listed);
        // The plain name was lost, and that is counted like any other.
        assert_eq!(feed.dropped(), 1);
        let names = taken(&feed);
        assert_eq!(names.len(), LANE_SLOTS);
        assert!(names.iter().all(|(_, kind)| *kind == NameKind::Refused));
        assert_eq!(names.first(), Some(&refused("ads0.example.org")));
        assert_eq!(names.last(), Some(&refused("ads7.example.org")));

        // It takes the oldest plain name, wherever it is, and keeps the order of the rest.
        let feed = LaneFeed::new();
        feed.observe("ads0.example.org", true, 1, not_listed);
        feed.observe("a.example.org", false, 1, not_listed);
        for i in 1..LANE_SLOTS - 1 {
            feed.observe(&format!("ads{i}.example.org"), true, 1, not_listed);
        }
        feed.observe("new.example.org", true, 1, not_listed);
        let names: Vec<String> = taken(&feed).into_iter().map(|(name, _)| name).collect();
        assert_eq!(
            names,
            [
                "ads0.example.org",
                "ads1.example.org",
                "ads2.example.org",
                "ads3.example.org",
                "ads4.example.org",
                "ads5.example.org",
                "ads6.example.org",
                "new.example.org",
            ]
        );
    }

    #[test]
    fn listed_is_asked_only_for_sampled_plain_names() {
        let feed = LaneFeed::new();
        let asked = Cell::new(0);
        let on_the_lists = |_: &str| {
            asked.set(asked.get() + 1);
            true
        };
        // A refused name is not asked about.
        feed.observe("ads.example.org", true, 1, on_the_lists);
        assert_eq!(asked.get(), 0);
        // The first plain name of a second is, and the rest of that second are not.
        feed.observe("a.example.org", false, 1, on_the_lists);
        feed.observe("b.example.org", false, 1, on_the_lists);
        feed.observe("c.example.org", false, 1, on_the_lists);
        assert_eq!(asked.get(), 1);
        feed.observe("d.example.org", false, 2, on_the_lists);
        assert_eq!(asked.get(), 2);
        // What it answers is the name's kind.
        feed.observe("e.example.org", false, 3, not_listed);
        assert_eq!(
            taken(&feed),
            [
                refused("ads.example.org"),
                ("a.example.org".to_owned(), NameKind::Listed),
                ("d.example.org".to_owned(), NameKind::Listed),
                plain("e.example.org"),
            ]
        );
        // A name that is dropped because the ring is full was asked about, as it was sampled.
        let feed = LaneFeed::new();
        for i in 0..LANE_SLOTS {
            feed.observe(&format!("ads{i}.example.org"), true, 1, not_listed);
        }
        feed.observe("a.example.org", false, 2, on_the_lists);
        assert_eq!(asked.get(), 3);
        assert_eq!(feed.dropped(), 1);
    }

    #[test]
    fn names_are_cut_to_32_bytes_at_a_char_boundary() {
        let feed = LaneFeed::new();
        // 32 bytes fit; 33 do not, and the panel's own `~` shows it.
        let fits = format!("{}.example.org", "a".repeat(20));
        assert_eq!(fits.len(), LANE_NAME_BYTES);
        feed.observe(&fits, true, 1, not_listed);
        let cut = "b".repeat(LANE_NAME_BYTES + 1);
        feed.observe(&cut, true, 1, not_listed);
        feed.observe(&"c".repeat(253), true, 1, not_listed);
        assert_eq!(
            taken(&feed),
            [
                refused(&fits),
                refused(&"b".repeat(LANE_NAME_BYTES)),
                refused(&"c".repeat(LANE_NAME_BYTES)),
            ]
        );
        // A cut that falls inside a character backs up to the one before, and the name says it
        // was cut: three bytes a character, 36 bytes, 32 is inside the eleventh.
        feed.observe(&"\u{20ac}".repeat(12), true, 1, not_listed);
        // Two bytes a character: 32 bytes is 16 whole characters, and 20 characters are 40 bytes.
        feed.observe(&"\u{e9}".repeat(20), true, 1, not_listed);
        // Exactly 32 bytes of wide characters are not cut.
        feed.observe(&"\u{e9}".repeat(16), true, 1, not_listed);
        assert_eq!(
            taken(&feed),
            [
                refused(&format!("{}~", "\u{20ac}".repeat(10))),
                refused(&format!("{}~", "\u{e9}".repeat(16))),
                refused(&"\u{e9}".repeat(16)),
            ]
        );
        // The empty name is no name.
        feed.observe("", true, 2, not_listed);
        feed.observe("", false, 3, not_listed);
        assert!(taken(&feed).is_empty());
        assert_eq!(feed.dropped(), 0);
        // It did not use up the second's plain name either.
        feed.observe("a.example.org", false, 3, not_listed);
        assert_eq!(taken(&feed), [plain("a.example.org")]);
    }

    #[test]
    fn a_busy_ring_drops_instead_of_waiting() {
        let feed = LaneFeed::new();
        feed.observe("ads.example.org", true, 1, not_listed);
        {
            // The panel's thread holds the ring, and this thread would wait for ever if it
            // waited at all.
            let _held = feed.ring.lock().unwrap();
            feed.observe("ads2.example.org", true, 1, not_listed);
            feed.observe("a.example.org", false, 2, not_listed);
        }
        assert_eq!(feed.dropped(), 2);
        assert_eq!(taken(&feed), [refused("ads.example.org")]);

        // A holder that panicked left the ring poisoned: names are dropped, and counted, and the
        // panel's thread still takes what is there.
        let feed = LaneFeed::new();
        feed.observe("ads.example.org", true, 1, not_listed);
        let poisoner = feed.clone();
        let _ = std::thread::spawn(move || {
            let _held = poisoner.ring.lock().unwrap();
            panic!("a holder panics");
        })
        .join();
        feed.observe("ads2.example.org", true, 1, not_listed);
        assert_eq!(feed.dropped(), 1);
        assert_eq!(taken(&feed), [refused("ads.example.org")]);
        assert!(taken(&feed).is_empty());
    }

    /// The names (as their rows show them) and outcomes of the watched device that the feed holds, newest first.
    fn watched(feed: &LaneFeed) -> Vec<(String, WatchedOutcome)> {
        let mut out = Vec::new();
        feed.watched_names(&mut out);
        out.into_iter().map(|n| (n.name, n.outcome)).collect()
    }

    /// Puts `name` in the ring of the watched device's names as an answered one, and says what the
    /// ring holds.
    fn pushed(feed: &LaneFeed, name: &str) -> Vec<String> {
        feed.watch
            .lock()
            .unwrap()
            .push(WatchSlot::of(name, WatchedOutcome::Answered));
        watched(feed).into_iter().map(|(name, _)| name).collect()
    }

    #[test]
    fn the_ring_of_the_watched_device_holds_two_names_newest_first_and_a_repeat_moves_up() {
        let feed = LaneFeed::new();
        assert_eq!(watched(&feed), []);
        assert_eq!(pushed(&feed, "a.example.org"), ["a.example.org"]);
        assert_eq!(
            pushed(&feed, "b.example.org"),
            ["b.example.org", "a.example.org"]
        );
        assert_eq!(
            pushed(&feed, "c.example.org"),
            ["c.example.org", "b.example.org"]
        );
        // The name that is first again is one name; the one before it comes up.
        assert_eq!(
            pushed(&feed, "c.example.org"),
            ["c.example.org", "b.example.org"]
        );
        assert_eq!(
            pushed(&feed, "b.example.org"),
            ["b.example.org", "c.example.org"]
        );
        // A repeat takes the outcome it has now.
        feed.watch
            .lock()
            .unwrap()
            .push(WatchSlot::of("b.example.org", WatchedOutcome::Passed));
        assert_eq!(
            watched(&feed),
            [
                ("b.example.org".to_owned(), WatchedOutcome::Passed),
                ("c.example.org".to_owned(), WatchedOutcome::Answered),
            ]
        );
        let mut out = Vec::new();
        feed.watched_names(&mut out);
        feed.watched_names(&mut out);
        assert_eq!(out.len(), WATCH_SLOTS, "the copy replaces what `out` held");
    }

    #[test]
    fn watching_a_client_clears_the_ring_and_says_whose_names_it_holds() {
        let feed = LaneFeed::new();
        // Names that nobody asked for are not kept by the ring of nobody.
        assert_eq!(feed.watched.load(Ordering::Relaxed), 0);
        feed.watch_client(Some(Ipv4Addr::new(192, 0, 2, 7)));
        assert_eq!(feed.watched.load(Ordering::Relaxed), 0xC000_0207);
        assert_eq!(pushed(&feed, "a.example.org").len(), 1);
        feed.watch_client(Some(Ipv4Addr::new(192, 0, 2, 8)));
        assert_eq!(watched(&feed), []);
        assert_eq!(feed.watch.lock().unwrap().client, 0xC000_0208);
        feed.watch_client(None);
        assert_eq!(feed.watched.load(Ordering::Relaxed), 0);
        assert_eq!(feed.watch.lock().unwrap().client, 0);
        feed.watch_client(Some(Ipv4Addr::UNSPECIFIED));
        assert_eq!(feed.watched.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_name_that_was_on_its_way_when_the_watch_moved_is_not_taken_in_by_the_new_ring() {
        let feed = LaneFeed::new();
        let resolver = Resolver::new(BlockSet::default());
        let (old, new) = (Ipv4Addr::new(192, 0, 2, 7), Ipv4Addr::new(192, 0, 2, 8));
        feed.watch_client(Some(new));
        // The resolver's side read the address 7 as watched, and the panel moved the watch to 8
        // before the ring was taken: the name of 7 is dropped, and the one of 8 is kept.
        let offer = |watched: Ipv4Addr, client: Ipv4Addr, name: &str| {
            feed.offer_watched(
                u32::from(watched),
                Some(IpAddr::V4(client)),
                &resolver,
                name,
                Outcome::Forwarded,
            );
        };
        offer(old, old, "late.example.org");
        assert_eq!(watched(&feed), []);
        offer(new, new, "now.example.org");
        assert_eq!(
            watched(&feed),
            [("now.example.org".to_owned(), WatchedOutcome::Answered)]
        );
        // A name of another client than the watched one is not kept either.
        offer(new, old, "other.example.org");
        assert_eq!(watched(&feed).len(), 1);
    }

    #[test]
    fn a_client_is_an_ipv4_address_or_an_ipv4_address_mapped_into_ipv6_and_nothing_else() {
        let v4 = Ipv4Addr::new(192, 0, 2, 7);
        assert_eq!(client_key(Some(IpAddr::V4(v4))), u32::from(v4));
        assert_eq!(
            client_key(Some(IpAddr::V6(v4.to_ipv6_mapped()))),
            u32::from(v4)
        );
        assert_eq!(client_key(Some("2001:db8::7".parse().unwrap())), 0);
        assert_eq!(client_key(Some(IpAddr::V6(v4.to_ipv6_compatible()))), 0);
        assert_eq!(client_key(None), 0);
    }

    #[test]
    fn a_watched_name_is_cut_at_32_bytes_at_a_char_boundary() {
        let feed = LaneFeed::new();
        let out = |feed: &LaneFeed, name: &str| {
            feed.watch_client(Some(Ipv4Addr::new(192, 0, 2, 7)));
            pushed(feed, name).remove(0)
        };
        assert_eq!(out(&feed, &"b".repeat(33)), "b".repeat(LANE_NAME_BYTES));
        assert_eq!(
            out(&feed, &"\u{20ac}".repeat(12)),
            format!("{}~", "\u{20ac}".repeat(10))
        );
        assert_eq!(out(&feed, &"\u{e9}".repeat(16)), "\u{e9}".repeat(16));
    }

    #[test]
    fn a_watched_name_is_kept_whole_for_name_beside_what_its_row_shows() {
        let feed = LaneFeed::new();
        let whole = |feed: &LaneFeed, name: &str| -> (String, Option<String>) {
            feed.watch_client(Some(Ipv4Addr::new(192, 0, 2, 7)));
            feed.watch
                .lock()
                .unwrap()
                .push(WatchSlot::of(name, WatchedOutcome::Refused));
            let mut out = Vec::new();
            feed.watched_names(&mut out);
            let first = out.remove(0);
            (first.name, first.whole)
        };
        // A short name is shown and kept as it is.
        assert_eq!(
            whole(&feed, "ads.example.org"),
            (
                "ads.example.org".to_owned(),
                Some("ads.example.org".to_owned())
            )
        );
        // A long one is shown cut at 32 bytes, as before, and kept whole: the longest DNS name too.
        let long = format!("{}.example.org", "a".repeat(40));
        assert_eq!(
            whole(&feed, &long),
            ("a".repeat(LANE_NAME_BYTES), Some(long.clone()))
        );
        let longest = "b".repeat(WATCH_NAME_BYTES);
        assert_eq!(whole(&feed, &longest).1, Some(longest));
        // One longer than any DNS name is shown cut and is not kept whole.
        assert_eq!(
            whole(&feed, &"c".repeat(WATCH_NAME_BYTES + 1)),
            ("c".repeat(LANE_NAME_BYTES), None)
        );
        // Wide characters are cut at a boundary with their `~`, as the lane's are, and kept whole.
        let wide = "\u{20ac}".repeat(12);
        assert_eq!(
            whole(&feed, &wide),
            (format!("{}~", "\u{20ac}".repeat(10)), Some(wide.clone()))
        );
    }

    #[test]
    fn take_returns_oldest_first_and_empties() {
        let feed = LaneFeed::new();
        let mut out = Vec::new();
        feed.take(&mut out);
        assert!(out.is_empty());

        feed.observe("a.example.org", false, 1, not_listed);
        feed.observe("ads.example.org", true, 1, not_listed);
        feed.observe("b.example.org", false, 2, not_listed);
        feed.take(&mut out);
        let names: Vec<_> = out.iter().map(|n| (n.name.as_str(), n.kind)).collect();
        assert_eq!(
            names,
            [
                ("a.example.org", NameKind::Plain),
                ("ads.example.org", NameKind::Refused),
                ("b.example.org", NameKind::Plain),
            ]
        );
        // `take` adds to what `out` holds, and leaves nothing in the feed.
        feed.take(&mut out);
        assert_eq!(out.len(), 3);
        feed.observe("c.example.org", false, 3, not_listed);
        feed.take(&mut out);
        assert_eq!(out.len(), 4);
        assert_eq!(out.last().map(|n| n.name.as_str()), Some("c.example.org"));
    }
}
