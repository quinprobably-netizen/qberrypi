//! The sessions behind `X-FTL-SID` and the limit on failed logins.
//!
//! Both are plain data. Nothing here reads a clock, takes a random number or does any I/O: the
//! caller passes the time as `mono_secs`, a reading of the monotonic clock in seconds, and the 16
//! random bytes of a new session. All arithmetic on times is saturating, so no time, not even one
//! near `u64::MAX`, makes a call panic or wrap. Nothing here logs, and nothing here prints a
//! session id or an address.
//!
//! # Sessions
//!
//! A session id (a sid) is 16 random bytes, written as 32 lower-case hex digits. A session is
//! valid for [`SESSION_SECS`] after its last use, and at most [`MAX_SESSIONS`] are held; a login
//! beyond that ends the least recently used one. [`Sessions::touch`] and [`Sessions::close`] are
//! called with text that any device on the network chose. That text is first decoded, which
//! depends only on the caller's own input, and then compared with every stored sid in constant
//! time, so that the time taken says nothing about how much of a stored sid a guess matched.
//!
//! # The limit on failed logins
//!
//! Failures are counted per address and overall, each over a window of [`FAILURE_WINDOW_SECS`].
//! A failure that finds [`FAILURES_PER_ADDRESS`] failures from its address in the window (itself
//! among them) holds that address back for [`HOLD_BACK_SECS`]; one that finds [`FAILURES_OVERALL`]
//! in the window holds every address back. A failure that arrives while such a hold is on, which
//! a caller that checks [`Limiter::allowed`] first only meets when two requests race, counts like
//! any other and so renews the hold from its own time.
//!
//! The table holds at most [`MAX_ADDRESSES`] addresses; to make room, the address whose last
//! failure is oldest goes. That never frees a held-back address early: to be the oldest of 64, a
//! held address must have 64 others fail after it, all within the minute that it is held, and so
//! the overall limit already holds everyone back for longer than it would have been.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::net::Ipv4Addr;

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use super::hex;

/// The seconds a session lasts after its last use.
pub const SESSION_SECS: u64 = 1_800;
/// The most sessions held at once; a login beyond that ends the least recently used one.
pub const MAX_SESSIONS: usize = 16;
/// The failures from one address, within [`FAILURE_WINDOW_SECS`], that hold that address back.
pub const FAILURES_PER_ADDRESS: usize = 5;
/// The failures from all addresses together, within [`FAILURE_WINDOW_SECS`], that hold every
/// address back.
pub const FAILURES_OVERALL: usize = 30;
/// The seconds a failure counts for.
pub const FAILURE_WINDOW_SECS: u64 = 60;
/// The seconds a hold-back lasts from the failure that starts it.
pub const HOLD_BACK_SECS: u64 = 60;
/// The most addresses the limiter keeps a record of.
pub const MAX_ADDRESSES: usize = 64;

/// The length of a sid, in bytes.
const SID_LEN: usize = 16;

/// Which hold-back a failed login starts, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldBack {
    /// None: logins are still allowed.
    None,
    /// The failing address is held back, and no other.
    ThisAddress,
    /// Every address is held back.
    Everyone,
}

/// One session: its id and when it was last used.
struct Held {
    sid: [u8; SID_LEN],
    last_used: u64,
}

impl Held {
    /// Whether the session is no longer valid at `now`: it was last used `SESSION_SECS` ago or
    /// longer.
    fn expired(&self, now: u64) -> bool {
        now.saturating_sub(self.last_used) >= SESSION_SECS
    }
}

/// The open sessions, at most [`MAX_SESSIONS`]. `Debug` shows how many, never a sid.
#[derive(Default)]
pub struct Sessions {
    held: Vec<Held>,
}

impl Sessions {
    /// Opens a session with the sid `random` as 32 lower-case hex digits, last used at
    /// `mono_secs`, and returns the sid.
    ///
    /// Expired sessions are dropped first. If [`MAX_SESSIONS`] are still held, the least recently
    /// used one is ended to make room. If `random` is the sid of a session already held, which
    /// random bytes do not do, that session is renewed instead of a second one held.
    pub fn open(&mut self, random: [u8; SID_LEN], mono_secs: u64) -> String {
        self.held.retain(|held| !held.expired(mono_secs));
        if let Some(held) = self.find(&random).and_then(|at| self.held.get_mut(at)) {
            held.last_used = mono_secs;
        } else {
            if self.held.len() >= MAX_SESSIONS {
                let oldest = self
                    .held
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, held)| held.last_used)
                    .map(|(at, _)| at);
                if let Some(at) = oldest {
                    self.held.remove(at);
                }
            }
            self.held.push(Held {
                sid: random,
                last_used: mono_secs,
            });
        }
        hex::encode(&random)
    }

    /// Uses the session `sid` at `mono_secs`: if it is valid, its last use becomes `mono_secs`
    /// and the result is `Some(SESSION_SECS)`, the seconds it now lasts. `None` if `sid` is not
    /// 32 lower-case hex digits, names no session, or names one that has expired, which is
    /// dropped.
    pub fn touch(&mut self, sid: &str, mono_secs: u64) -> Option<u64> {
        let at = self.find(&hex::decode(sid)?)?;
        let held = self.held.get_mut(at)?;
        if held.expired(mono_secs) {
            self.held.remove(at);
            return None;
        }
        held.last_used = mono_secs;
        Some(SESSION_SECS)
    }

    /// Ends the session `sid`; true only if it was valid at `mono_secs`. An expired session is
    /// dropped, and answers false like one that was never there.
    pub fn close(&mut self, sid: &str, mono_secs: u64) -> bool {
        let Some(at) = hex::decode(sid).and_then(|sid| self.find(&sid)) else {
            return false;
        };
        let valid = self
            .held
            .get(at)
            .is_some_and(|held| !held.expired(mono_secs));
        self.held.remove(at);
        valid
    }

    /// The number of sessions held. That includes expired ones that no `open`, `touch` or
    /// `close` has dropped yet.
    pub fn len(&self) -> usize {
        self.held.len()
    }

    /// Whether no session is held, expired ones not yet dropped counted as held.
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// The index of the session whose sid is `sid`.
    ///
    /// `sid` is compared with every stored sid, all 16 bytes of each, and the matches are
    /// accumulated without a branch on them; only when every comparison is done is the result
    /// acted on.
    fn find(&self, sid: &[u8; SID_LEN]) -> Option<usize> {
        let mut found = Choice::from(0);
        let mut index = 0u64;
        for (at, held) in (0u64..).zip(&self.held) {
            let hit = held.sid.as_slice().ct_eq(sid.as_slice());
            index.conditional_assign(&at, hit);
            found |= hit;
        }
        if bool::from(found) {
            usize::try_from(index).ok()
        } else {
            None
        }
    }
}

impl fmt::Debug for Sessions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sessions")
            .field("count", &self.held.len())
            .finish()
    }
}

/// Failures that count towards one limit: their times, at most as many as the limit, and the
/// time until which that limit holds logins back.
#[derive(Default)]
struct Strikes {
    times: VecDeque<u64>,
    held_until: u64,
}

impl Strikes {
    /// Records a failure at `now` against `limit` failures per [`FAILURE_WINDOW_SECS`]; true if
    /// that many are now in the window, which holds logins back from `now` for
    /// [`HOLD_BACK_SECS`].
    fn record(&mut self, now: u64, limit: usize) -> bool {
        self.times
            .retain(|&at| now.saturating_sub(at) < FAILURE_WINDOW_SECS);
        while self.times.len() >= limit {
            self.times.pop_front();
        }
        self.times.push_back(now);
        if self.times.len() < limit {
            return false;
        }
        self.held_until = self.held_until.max(now.saturating_add(HOLD_BACK_SECS));
        true
    }

    /// Whether a hold is on at `now`.
    fn holds(&self, now: u64) -> bool {
        now < self.held_until
    }

    /// The time of the latest failure recorded.
    fn last_failure(&self) -> u64 {
        self.times.iter().copied().max().unwrap_or(0)
    }
}

/// The limit on failed logins, per address and overall.
///
/// A caller asks [`Limiter::allowed`] before it checks a password at all, and reports the result
/// with [`Limiter::failed`] or [`Limiter::succeeded`]. `Debug` shows only how many addresses are
/// recorded, never one.
#[derive(Default)]
pub struct Limiter {
    addresses: BTreeMap<Ipv4Addr, Strikes>,
    overall: Strikes,
}

impl Limiter {
    /// Whether a login from `addr` may be tried at `mono_secs`: false while that address is held
    /// back, and while everyone is.
    pub fn allowed(&self, addr: Ipv4Addr, mono_secs: u64) -> bool {
        !self.overall.holds(mono_secs)
            && !self
                .addresses
                .get(&addr)
                .is_some_and(|strikes| strikes.holds(mono_secs))
    }

    /// Records a failed login from `addr` at `mono_secs`, and says which hold-back it starts:
    /// [`HoldBack::Everyone`] if it is the [`FAILURES_OVERALL`]th overall in the window, even if
    /// it is also the [`FAILURES_PER_ADDRESS`]th from `addr`; else [`HoldBack::ThisAddress`] if
    /// it is the latter; else [`HoldBack::None`].
    ///
    /// If the table is full and `addr` is new, the address whose last failure is oldest is
    /// dropped to make room.
    pub fn failed(&mut self, addr: Ipv4Addr, mono_secs: u64) -> HoldBack {
        let everyone = self.overall.record(mono_secs, FAILURES_OVERALL);
        if self.addresses.len() >= MAX_ADDRESSES && !self.addresses.contains_key(&addr) {
            self.drop_oldest();
        }
        let this_address = self
            .addresses
            .entry(addr)
            .or_default()
            .record(mono_secs, FAILURES_PER_ADDRESS);
        if everyone {
            HoldBack::Everyone
        } else if this_address {
            HoldBack::ThisAddress
        } else {
            HoldBack::None
        }
    }

    /// Records a correct login from `addr`: its failures, and any hold-back on it, are forgotten.
    /// The overall count of failures stands.
    pub fn succeeded(&mut self, addr: Ipv4Addr) {
        self.addresses.remove(&addr);
    }

    /// The number of addresses recorded.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.addresses.len()
    }

    /// Drops the address whose last failure is oldest; the lowest address among equals.
    fn drop_oldest(&mut self) {
        let oldest = self
            .addresses
            .iter()
            .min_by_key(|(addr, strikes)| (strikes.last_failure(), **addr))
            .map(|(addr, _)| *addr);
        if let Some(addr) = oldest {
            self.addresses.remove(&addr);
        }
    }
}

impl fmt::Debug for Limiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Limiter")
            .field("addresses", &self.addresses.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_lasts_thirty_minutes_from_its_last_use() {
        let mut s = Sessions::default();
        let sid = s.open([0xab; 16], 100);
        assert_eq!(sid, "ab".repeat(16));
        assert_eq!(s.touch(&sid, 1_000), Some(1_800));
        assert_eq!(s.touch(&sid, 2_799), Some(1_800));
        assert_eq!(s.touch(&sid, 2_799 + 1_800), None);
    }

    #[test]
    fn only_the_exact_sid_opens_the_session() {
        // Review Focus 3
        let mut s = Sessions::default();
        // The last byte makes the sid hold letters, so that its upper-case form differs from it.
        let mut random = [1; 16];
        random[15] = 0xab;
        let sid = s.open(random, 0);
        for wrong in [
            &sid[..31],
            &format!("{sid}0"),
            &sid.to_uppercase(),
            &sid.replace("01", "02"),
            "",
            "sid=x",
        ] {
            assert_eq!(s.touch(wrong, 1), None, "{wrong}");
        }
        assert!(s.close(&sid, 1) && s.touch(&sid, 2).is_none() && !s.close(&sid, 3));
    }

    #[test]
    fn the_seventeenth_login_ends_the_least_recently_used() {
        let mut s = Sessions::default();
        let sids: Vec<String> = (0..16u8).map(|n| s.open([n; 16], u64::from(n))).collect();
        s.touch(&sids[0], 20); // the oldest is used again
        s.open([99; 16], 21);
        assert_eq!(s.len(), MAX_SESSIONS);
        assert!(s.touch(&sids[0], 22).is_some() && s.touch(&sids[1], 22).is_none());
    }

    #[test]
    fn five_failures_in_a_minute_hold_that_address_back_and_no_other() {
        // Review Focus 1
        let (a, b) = (Ipv4Addr::new(192, 0, 2, 7), Ipv4Addr::new(192, 0, 2, 8));
        let mut l = Limiter::default();
        for t in 0..4 {
            assert_eq!(l.failed(a, t), HoldBack::None);
        }
        assert_eq!(l.failed(a, 10), HoldBack::ThisAddress);
        assert!(!l.allowed(a, 11) && l.allowed(b, 11));
        assert!(!l.allowed(a, 69) && l.allowed(a, 70));
        let mut l = Limiter::default();
        for t in [0, 61, 122, 183, 244] {
            l.failed(a, t);
        } // a minute apart: never five in one window
        assert!(l.allowed(a, 245));
        l.failed(a, 300);
        l.succeeded(a);
        assert!(l.allowed(a, 301));
    }

    #[test]
    fn thirty_failures_from_anywhere_hold_everyone_back() {
        // Review Focus 1
        let mut l = Limiter::default();
        let starts: Vec<HoldBack> = (0..30u32)
            .map(|n| l.failed(Ipv4Addr::from(0xc633_6400 + n), 5))
            .collect(); // 198.51.100.n
        assert_eq!(starts.last(), Some(&HoldBack::Everyone));
        assert!(
            !l.allowed(Ipv4Addr::new(192, 0, 2, 7), 6)
                && l.allowed(Ipv4Addr::new(192, 0, 2, 7), 65)
        );
    }

    #[test]
    fn a_sweep_of_addresses_keeps_the_table_bounded() {
        let mut l = Limiter::default();
        for n in 0..1_000u32 {
            l.failed(Ipv4Addr::from(0xc612_0000 + n), u64::from(n) * 120);
        } // 198.18.0.0/15, the benchmarking range; far apart in time: no overall hold
        assert!(l.len() <= MAX_ADDRESSES);
    }

    /// The address `192.0.2.n`.
    fn doc(n: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, n)
    }

    /// The address `198.51.100.n`, for `n` up to 255 and beyond into the next numbers.
    fn other(n: u32) -> Ipv4Addr {
        Ipv4Addr::from(0xc633_6400 + n)
    }

    #[test]
    fn a_sid_is_found_among_several_and_only_that_one_answers() {
        let mut s = Sessions::default();
        let sids: Vec<String> = (0..8u8).map(|n| s.open([n * 17; 16], 0)).collect();
        for sid in &sids {
            assert_eq!(s.touch(sid, 1), Some(SESSION_SECS));
        }
        // A sid one digit off, in any place, is none of them.
        for sid in &sids {
            for at in 0..sid.len() {
                let mut wrong = sid.clone().into_bytes();
                wrong[at] = if wrong[at] == b'f' { b'e' } else { b'f' };
                let wrong = String::from_utf8(wrong).unwrap();
                assert_eq!(s.touch(&wrong, 2), None, "{wrong}");
                assert!(!s.close(&wrong, 2), "{wrong}");
            }
        }
        assert_eq!(s.len(), 8);
        // Closing one leaves the others, whatever their place.
        assert!(s.close(&sids[3], 3));
        for (n, sid) in sids.iter().enumerate() {
            assert_eq!(s.touch(sid, 4).is_some(), n != 3, "{n}");
        }
        assert_eq!(s.len(), 7);
    }

    #[test]
    fn only_32_lower_case_hex_digits_are_a_sid() {
        let mut s = Sessions::default();
        let sid = s.open([0xab; 16], 0); // "abab..."
        let wide = "\u{e9}".repeat(16); // 32 bytes, but not digits
        let wrong = [
            sid[..31].to_owned(),
            format!("{sid}a"),
            format!("a{sid}"),
            sid.repeat(2),
            sid.to_uppercase(),
            format!("A{}", &sid[1..]),
            format!("{}B", &sid[..31]),
            format!("{}g", &sid[..31]),
            format!("{}0x", &sid[..30]),
            format!("{}\n", &sid[..31]),
            format!(" {}", &sid[1..]),
            format!("{sid}\0"),
            format!("{} {}", &sid[..16], &sid[17..]),
            sid.replace('a', "\u{ff41}"),
            wide,
            "0".repeat(32),
            "-".repeat(32),
            String::new(),
        ];
        for text in &wrong {
            assert_eq!(s.touch(text, 1), None, "{text:?}");
            assert!(!s.close(text, 1), "{text:?}");
        }
        // Nothing was closed by any of them.
        assert_eq!(s.len(), 1);
        assert_eq!(s.touch(&sid, 2), Some(SESSION_SECS));
    }

    #[test]
    fn a_session_exactly_thirty_minutes_old_is_expired_and_dropped() {
        let mut s = Sessions::default();
        let sid = s.open([2; 16], 10);
        assert_eq!(s.touch(&sid, 10 + SESSION_SECS - 1), Some(SESSION_SECS)); // last used at 1,809
        assert_eq!(s.touch(&sid, 1_809 + SESSION_SECS), None);
        // It is gone, not merely refused.
        assert!(s.is_empty());
        // The same for close: one second short of the end it works, at the end it does not.
        let sid = s.open([2; 16], 10);
        assert!(!s.close(&sid, 10 + SESSION_SECS));
        assert!(s.is_empty());
        let sid = s.open([2; 16], 10);
        assert!(s.close(&sid, 10 + SESSION_SECS - 1));
        assert!(s.is_empty());
    }

    #[test]
    fn opening_drops_the_expired_before_it_ends_a_live_one() {
        let mut s = Sessions::default();
        let stale = s.open([200; 16], 0);
        let live: Vec<String> = (0..15u8).map(|n| s.open([n; 16], 1_000)).collect();
        assert_eq!(s.len(), MAX_SESSIONS);
        // The first is exactly SESSION_SECS old, so it goes and no live one has to.
        s.open([99; 16], SESSION_SECS);
        assert_eq!(s.len(), MAX_SESSIONS);
        assert_eq!(s.touch(&stale, SESSION_SECS), None);
        for sid in &live {
            assert!(s.touch(sid, SESSION_SECS).is_some(), "{sid}");
        }
    }

    #[test]
    fn the_same_random_bytes_renew_the_session_instead_of_holding_two() {
        let mut s = Sessions::default();
        let sid = s.open([5; 16], 0);
        assert_eq!(s.open([5; 16], 10), sid);
        assert_eq!(s.len(), 1);
        assert_eq!(s.touch(&sid, 10 + SESSION_SECS - 1), Some(SESSION_SECS));
        // With the table full, it ends nobody.
        let mut s = Sessions::default();
        let sids: Vec<String> = (0..16u8).map(|n| s.open([n; 16], 0)).collect();
        s.open([7; 16], 1);
        assert_eq!(s.len(), MAX_SESSIONS);
        assert!(sids.iter().all(|sid| s.touch(sid, 2).is_some()));
    }

    #[test]
    fn the_debug_text_of_the_sessions_is_their_count() {
        let mut s = Sessions::default();
        assert_eq!(format!("{s:?}"), "Sessions { count: 0 }");
        let sids: Vec<String> = (1..4u8).map(|n| s.open([n; 16], 0)).collect();
        assert_eq!(format!("{s:?}"), "Sessions { count: 3 }");
        let pretty = format!("{s:#?}");
        for sid in &sids {
            assert!(!pretty.contains(&sid[..8]) && !pretty.contains(&sid[..8].to_uppercase()));
        }
    }

    #[test]
    fn times_near_the_end_of_the_clock_do_not_overflow() {
        let end = u64::MAX;
        let mut s = Sessions::default();
        let sid = s.open([9; 16], end - 5);
        assert_eq!(s.touch(&sid, end), Some(SESSION_SECS));
        assert_eq!(s.touch(&sid, 0), Some(SESSION_SECS)); // an earlier time is no age at all
        assert!(s.close(&sid, 0));
        for n in 0..=u8::try_from(MAX_SESSIONS).unwrap() {
            s.open([n; 16], end);
        }
        assert_eq!(s.len(), MAX_SESSIONS);

        let a = doc(7);
        let mut l = Limiter::default();
        for _ in 0..FAILURES_PER_ADDRESS {
            l.failed(a, end - 100);
        }
        assert!(!l.allowed(a, end - 50) && l.allowed(a, end - 100 + HOLD_BACK_SECS));
        // A hold that would run past the end of the clock ends at it.
        let mut l = Limiter::default();
        for _ in 1..FAILURES_PER_ADDRESS {
            assert_eq!(l.failed(a, end), HoldBack::None);
        }
        assert_eq!(l.failed(a, end), HoldBack::ThisAddress);
        assert!(!l.allowed(a, end - 1) && l.allowed(a, end));
        for n in 0..FAILURES_OVERALL as u32 {
            l.failed(other(n), end);
        }
        assert!(!l.allowed(doc(9), end - 1));
        // And a time before every failure is no age at all: they all count, and nothing wraps.
        l.failed(a, 0);
        l.succeeded(a);
    }

    #[test]
    fn the_overall_hold_back_ends_a_minute_after_the_thirtieth_failure() {
        let mut l = Limiter::default();
        let starts: Vec<HoldBack> = (0..30).map(|n| l.failed(other(n), 100)).collect();
        assert!(starts[..29].iter().all(|h| *h == HoldBack::None));
        assert_eq!(starts[29], HoldBack::Everyone);
        for addr in [doc(1), other(0), other(29)] {
            assert!(!l.allowed(addr, 100) && !l.allowed(addr, 159), "{addr}");
            assert!(l.allowed(addr, 160), "{addr}");
        }
        // The thirty are out of the window by then: the next one starts nothing.
        assert_eq!(l.failed(doc(1), 160), HoldBack::None);
        assert!(l.allowed(doc(1), 161));
    }

    #[test]
    fn thirty_failures_spread_over_more_than_a_minute_hold_nobody() {
        let mut l = Limiter::default();
        // 29 at time 0, the thirtieth a full window later: at that time the 29 are 60 s old.
        for n in 0..29 {
            assert_eq!(l.failed(other(n), 0), HoldBack::None);
        }
        assert_eq!(l.failed(other(29), FAILURE_WINDOW_SECS), HoldBack::None);
        assert!(l.allowed(doc(1), FAILURE_WINDOW_SECS));
        // One second sooner, they all count.
        let mut l = Limiter::default();
        for n in 0..29 {
            l.failed(other(n), 0);
        }
        assert_eq!(
            l.failed(other(29), FAILURE_WINDOW_SECS - 1),
            HoldBack::Everyone
        );
    }

    #[test]
    fn a_failure_that_starts_both_hold_backs_reports_everyone() {
        let a = doc(7);
        let mut l = Limiter::default();
        for t in 0..4 {
            assert_eq!(l.failed(a, t), HoldBack::None);
        }
        for n in 0..25 {
            assert_eq!(l.failed(other(n), 4), HoldBack::None); // 29 overall, none held
        }
        assert_eq!(l.failed(a, 5), HoldBack::Everyone);
        // Both are on: a's own hold ends at 65, as does the overall one.
        assert!(!l.allowed(a, 64) && !l.allowed(doc(8), 64));
        assert!(l.allowed(a, 65) && l.allowed(doc(8), 65));
    }

    #[test]
    fn a_failure_that_finds_the_limit_reached_renews_the_hold() {
        let a = doc(7);
        let mut l = Limiter::default();
        for t in 0..5 {
            l.failed(a, t);
        } // held until 64
        assert_eq!(l.failed(a, 30), HoldBack::ThisAddress); // 1, 2, 3, 4, 30
        assert!(!l.allowed(a, 89) && l.allowed(a, 90));
        // The hold never gets shorter: an earlier reading of the clock does not shorten it.
        l.failed(a, 20);
        assert!(!l.allowed(a, 89));
    }

    #[test]
    fn a_success_forgets_that_address_only_and_the_overall_count_stands() {
        let (a, b) = (doc(7), doc(8));
        let mut l = Limiter::default();
        for t in 0..4 {
            l.failed(a, t);
            l.failed(b, t);
        }
        l.succeeded(a);
        assert_eq!(l.failed(b, 5), HoldBack::ThisAddress);
        // Four more from a, as if from none: its earlier four are forgotten.
        for t in 6..10 {
            assert_eq!(l.failed(a, t), HoldBack::None, "{t}");
        }
        assert!(l.allowed(a, 10));
        // Overall, 29 failures from 29 addresses, each then logging in: the next one still
        // completes the thirty.
        let mut l = Limiter::default();
        for n in 0..29 {
            l.failed(other(n), 0);
            l.succeeded(other(n));
        }
        assert_eq!(l.len(), 0);
        assert_eq!(l.failed(doc(1), 1), HoldBack::Everyone);
    }

    #[test]
    fn a_full_table_drops_the_address_whose_last_failure_is_oldest() {
        let mut l = Limiter::default();
        for n in 0..MAX_ADDRESSES as u32 {
            l.failed(other(n), u64::from(n) * 100);
        }
        assert_eq!(l.len(), MAX_ADDRESSES);
        // A new address makes room by dropping other(0), whose failure is the oldest.
        l.failed(doc(1), 10_000);
        assert_eq!(l.len(), MAX_ADDRESSES);
        assert!(!l.addresses.contains_key(&other(0)) && l.addresses.contains_key(&other(1)));
        // An address already in the table needs no room.
        l.failed(other(1), 10_001);
        assert_eq!(l.len(), MAX_ADDRESSES);
        assert!(l.addresses.contains_key(&doc(1)) && l.addresses.contains_key(&other(2)));
        // other(1) failed again, so it is no longer the oldest: other(2) is.
        l.failed(doc(2), 10_002);
        assert!(!l.addresses.contains_key(&other(2)) && l.addresses.contains_key(&other(1)));
    }

    #[test]
    fn a_held_back_address_stays_held_until_64_others_have_failed_after_it() {
        let a = doc(7);
        let mut l = Limiter::default();
        for t in 0..5 {
            l.failed(a, t);
        } // held until 64, and the oldest last failure from now on
        // 63 others fill the table together with a; nothing is dropped, and a stays held.
        for n in 0..63 {
            l.failed(other(n), 10);
            assert!(l.addresses.contains_key(&a), "{n}");
            assert!(!l.allowed(a, 63), "{n}");
        }
        assert_eq!(l.len(), MAX_ADDRESSES);
        assert_eq!(l.addresses[&a].held_until, 64);
        // The 64th other makes a the one dropped. By then 69 failures within a minute have held
        // everyone back, for as long as a's own hold would have lasted and longer: a is still
        // held at 63 and 64, and is let in again no sooner than it would have been.
        l.failed(other(63), 10);
        assert!(!l.addresses.contains_key(&a));
        assert_eq!(l.len(), MAX_ADDRESSES);
        assert!(!l.allowed(a, 63) && !l.allowed(a, 64));
        assert!(l.allowed(a, 70));
    }
}
