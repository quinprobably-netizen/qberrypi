//! The throttle in front of threat alerts: one alert per client per name per hour.
//!
//! A device that is infected asks for the same threat name again and again, or for thousands of
//! names in turn. The throttle keeps what that does to the alerts bounded: both in how many are
//! raised and in how much memory it takes to know that they are.
//!
//! Nothing here logs.

use std::collections::HashMap;
use std::net::IpAddr;

/// The kind of the alert that a threat hit raises.
pub const THREAT_KIND: &str = "threat";
/// How long a pair of client and name, once alerted on, is quiet.
pub const THREAT_ALERT_EVERY_SECS: u64 = 3_600;
/// The most pairs the throttle remembers at once.
pub const THREAT_PAIRS: usize = 4_096;

/// Which pairs of client and name were alerted on, and when.
///
/// It reads no clock: the caller says what time it is, in monotonic seconds. It holds at most
/// [`THREAT_PAIRS`] pairs.
pub(crate) struct ThreatThrottle {
    /// For each client (`None` is our own lookups) the names that were alerted on, with the
    /// second of the last alert. Two levels, so that a name is looked up as a `&str` and a
    /// repeat allocates nothing. No client is kept without a name.
    pairs: HashMap<Option<IpAddr>, HashMap<Box<str>, u64>>,
    /// The pairs in `pairs`.
    len: usize,
    /// No pair is quiet before this second: a sweep for expired pairs is made no earlier, which
    /// keeps a flood of new names, once the throttle is full, from sweeping for each one. It may
    /// be earlier than the first pair to expire, never later.
    expiry_after: u64,
    /// The alerts that were dropped for want of room.
    dropped: u64,
}

impl ThreatThrottle {
    /// A throttle that remembers no pair.
    pub(crate) fn new() -> Self {
        Self {
            pairs: HashMap::new(),
            len: 0,
            expiry_after: u64::MAX,
            dropped: 0,
        }
    }

    /// Whether to raise an alert for `name` asked for by `client` at `mono_secs`, which is then
    /// remembered.
    ///
    /// A pair that was alerted on less than [`THREAT_ALERT_EVERY_SECS`] ago gets none. A new pair
    /// that finds the throttle full first replaces the pairs that are quiet again; if none is, it
    /// gets none, and the alert is counted in [`dropped`](Self::dropped). So the memory is
    /// bounded whatever is asked for, and a pair that is already known is never dropped.
    ///
    /// A pair that is already known allocates nothing; a new one allocates its name.
    pub(crate) fn should_raise(
        &mut self,
        client: Option<IpAddr>,
        name: &str,
        mono_secs: u64,
    ) -> bool {
        let known = self
            .pairs
            .get_mut(&client)
            .and_then(|names| names.get_mut(name));
        if let Some(last) = known {
            if mono_secs.saturating_sub(*last) < THREAT_ALERT_EVERY_SECS {
                return false;
            }
            // `expiry_after` stays a lower bound: this pair only got later.
            *last = mono_secs;
            return true;
        }
        if self.len >= THREAT_PAIRS {
            if mono_secs >= self.expiry_after {
                self.sweep(mono_secs);
            }
            if self.len >= THREAT_PAIRS {
                self.dropped += 1;
                return false;
            }
        }
        self.pairs
            .entry(client)
            .or_default()
            .insert(name.into(), mono_secs);
        self.len += 1;
        self.expiry_after = self
            .expiry_after
            .min(mono_secs.saturating_add(THREAT_ALERT_EVERY_SECS));
        true
    }

    /// How many alerts were dropped, because a new pair found the throttle full of pairs that
    /// were not yet quiet again.
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Forgets the pairs that are quiet again at `mono_secs`, and works out when the next is.
    fn sweep(&mut self, mono_secs: u64) {
        let mut oldest = u64::MAX;
        self.pairs.retain(|_, names| {
            names.retain(|_, last| {
                let quiet = mono_secs.saturating_sub(*last) >= THREAT_ALERT_EVERY_SECS;
                if !quiet {
                    oldest = oldest.min(*last);
                }
                !quiet
            });
            !names.is_empty()
        });
        self.len = self.pairs.values().map(HashMap::len).sum();
        self.expiry_after = oldest.saturating_add(THREAT_ALERT_EVERY_SECS);
    }

    /// The pairs that are remembered.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;

    /// A client of the household.
    fn client(last: u8) -> Option<IpAddr> {
        Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)))
    }

    /// A throttle that holds `THREAT_PAIRS` pairs, all alerted on at second `at`.
    fn full(at: u64) -> ThreatThrottle {
        let mut throttle = ThreatThrottle::new();
        for i in 0..THREAT_PAIRS {
            assert!(throttle.should_raise(client(10), &format!("n{i}.example.net"), at));
        }
        assert_eq!(throttle.len(), THREAT_PAIRS);
        throttle
    }

    // Review Focus 4
    #[test]
    fn one_alert_per_client_and_name_per_hour() {
        let mut throttle = ThreatThrottle::new();
        let ask = |throttle: &mut ThreatThrottle, at| {
            throttle.should_raise(client(10), "x.bad.example.net", at)
        };
        assert!(ask(&mut throttle, 0));
        assert!(!ask(&mut throttle, 10));
        assert!(!ask(&mut throttle, 3_599));
        assert!(ask(&mut throttle, 3_600));
        // The hour starts again from the alert, and a repeat does not move it.
        assert!(!ask(&mut throttle, 3_601));
        assert!(!ask(&mut throttle, 7_199));
        assert!(ask(&mut throttle, 7_200));
        assert_eq!((throttle.len(), throttle.dropped()), (1, 0));
    }

    #[test]
    fn other_clients_and_names_are_separate() {
        let mut throttle = ThreatThrottle::new();
        let pairs = [
            (client(10), "x.bad.example.net"),
            (client(11), "x.bad.example.net"),
            (client(10), "y.bad.example.net"),
            (None, "x.bad.example.net"),
        ];
        for (who, name) in pairs {
            assert!(throttle.should_raise(who, name, 5), "{who:?} {name}");
        }
        for (who, name) in pairs {
            assert!(!throttle.should_raise(who, name, 6), "{who:?} {name}");
        }
        assert_eq!((throttle.len(), throttle.dropped()), (4, 0));
    }

    // Review Focus 4
    #[test]
    fn a_full_throttle_drops_expired_pairs_first() {
        let mut throttle = full(0);
        assert!(throttle.should_raise(client(11), "new.example.net", THREAT_ALERT_EVERY_SECS));
        // Every pair of second 0 was quiet again, and is gone.
        assert_eq!((throttle.len(), throttle.dropped()), (1, 0));
    }

    // Review Focus 4
    #[test]
    fn a_full_throttle_of_fresh_pairs_drops_the_alert() {
        let mut throttle = full(0);
        assert!(!throttle.should_raise(client(11), "new.example.net", 1));
        assert_eq!((throttle.len(), throttle.dropped()), (THREAT_PAIRS, 1));
        // Again, and for a name that was dropped before: it is a new pair each time.
        assert!(!throttle.should_raise(client(11), "new.example.net", 2));
        assert!(!throttle.should_raise(client(12), "other.example.net", 3));
        assert_eq!((throttle.len(), throttle.dropped()), (THREAT_PAIRS, 3));
        // A pair that is known is still throttled, and still alerts once its hour is over, with
        // the throttle full: it needs no room.
        assert!(!throttle.should_raise(client(10), "n0.example.net", 4));
        assert!(throttle.should_raise(client(10), "n0.example.net", THREAT_ALERT_EVERY_SECS));
        assert_eq!(throttle.dropped(), 3);
    }

    #[test]
    fn only_the_pairs_that_are_quiet_again_are_replaced() {
        // Half the pairs are of second 0, half of second 100.
        let mut throttle = ThreatThrottle::new();
        for i in 0..THREAT_PAIRS {
            let at = if i % 2 == 0 { 0 } else { 100 };
            assert!(throttle.should_raise(client(10), &format!("n{i}.example.net"), at));
        }
        // Nothing is quiet at 3,599: the new pair is dropped, and no later sweep is skipped.
        assert!(!throttle.should_raise(client(11), "a.example.net", 3_599));
        assert_eq!(throttle.dropped(), 1);
        // At 3,600 those of second 0 are quiet again, those of second 100 are not.
        assert!(throttle.should_raise(client(11), "b.example.net", 3_600));
        assert_eq!(throttle.len(), THREAT_PAIRS / 2 + 1);
        assert!(!throttle.should_raise(client(10), "n1.example.net", 3_600));
        // The room that was made takes more than one new pair.
        assert!(throttle.should_raise(client(11), "c.example.net", 3_600));
        // At 3,700 the rest is quiet again.
        let mut throttle = full(100);
        assert!(throttle.should_raise(client(11), "d.example.net", 3_700));
        assert_eq!(throttle.len(), 1);
    }
}
