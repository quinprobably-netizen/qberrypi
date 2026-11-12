//! The devices that ask: how many, and how recently, kept for the status page and the API.
//!
//! The table holds at most [`MAX_CLIENTS`] IPv4 addresses and forgets the one that was seen
//! least recently when another comes, so that a scan or a busy network cannot grow it. The Pi's
//! own queries (`127.0.0.0/8`) and anything that is not IPv4 are no device and are not kept.
//!
//! An address is shown only behind the API's login, never in a log line and never on port 80;
//! port 80 gets the counts of [`Clients::seen_within`] alone.

use std::net::{IpAddr, Ipv4Addr};

/// The most addresses the table holds.
pub const MAX_CLIENTS: usize = 256;

/// One device that asked, as the API lists it.
///
/// Its `Debug` shows the address: it must never reach a log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    /// The device's address.
    pub addr: Ipv4Addr,
    /// The queries it asked, since it was last taken into the table.
    pub queries: u64,
    /// The seconds since its last query.
    pub last_seen_secs_ago: u64,
}

/// The IPv4 address of `addr` if the table counts it as a device that asks: any IPv4 address
/// but those of `127.0.0.0/8`, which are the Pi's own (the self-test asks over loopback).
/// Anything that is not IPv4 is none.
///
/// This is the one rule of who counts: [`Clients::record`] keeps what it passes, and the listener
/// asks it before it calls the first answer to a client the first.
pub fn counted(addr: IpAddr) -> Option<Ipv4Addr> {
    match addr {
        IpAddr::V4(v4) if !v4.is_loopback() => Some(v4),
        _ => None,
    }
}

/// One device's entry in the table.
struct Entry {
    addr: Ipv4Addr,
    queries: u64,
    /// The monotonic second of its last query.
    last_seen: u64,
}

/// The devices that asked: [`MAX_CLIENTS`] at most, the least recently seen forgotten first.
///
/// It has no `Debug`, as its addresses must not reach a log line.
#[derive(Default)]
pub struct Clients {
    /// Ordered by when each was last seen, the least recent first: one that is seen again moves
    /// to the end, so that of those seen in the same second the one that came first goes first.
    entries: Vec<Entry>,
}

impl Clients {
    /// Notes a query from `addr` at `mono_secs`, the monotonic seconds. An address that
    /// [`counted`] says is no device is ignored. A new one that finds the table full takes the
    /// place of the one that was seen least recently.
    pub fn record(&mut self, addr: IpAddr, mono_secs: u64) {
        let Some(addr) = counted(addr) else {
            return;
        };
        // At most 256 comparisons, far under a microsecond: no index is worth its upkeep.
        let mut entry = match self.entries.iter().position(|e| e.addr == addr) {
            Some(at) => self.entries.remove(at),
            None => {
                if self.entries.len() == MAX_CLIENTS {
                    self.entries.remove(0);
                }
                Entry {
                    addr,
                    queries: 0,
                    last_seen: mono_secs,
                }
            }
        };
        entry.queries = entry.queries.saturating_add(1);
        entry.last_seen = mono_secs;
        self.entries.push(entry);
    }

    /// How many devices were last seen at or after `mono_secs - window_secs`.
    pub fn seen_within(&self, mono_secs: u64, window_secs: u64) -> usize {
        let since = mono_secs.saturating_sub(window_secs);
        self.entries.iter().filter(|e| e.last_seen >= since).count()
    }

    /// Every device, the most recently seen first, with the seconds since each was seen at
    /// `mono_secs`.
    pub fn list(&self, mono_secs: u64) -> Vec<Client> {
        self.entries
            .iter()
            .rev()
            .map(|e| Client {
                addr: e.addr,
                queries: e.queries,
                last_seen_secs_ago: mono_secs.saturating_sub(e.last_seen),
            })
            .collect()
    }

    /// How many devices the table holds.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table holds none.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 192.0.2.n and on.
    fn v4(n: u32) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(0xc000_0200 + n))
    }

    #[test]
    fn each_address_is_counted_and_listed_most_recent_first() {
        let mut c = Clients::default();
        c.record(v4(1), 10);
        c.record(v4(2), 20);
        c.record(v4(1), 30);
        assert_eq!(
            c.list(40),
            [
                Client {
                    addr: Ipv4Addr::new(192, 0, 2, 1),
                    queries: 2,
                    last_seen_secs_ago: 10
                },
                Client {
                    addr: Ipv4Addr::new(192, 0, 2, 2),
                    queries: 1,
                    last_seen_secs_ago: 20
                }
            ]
        );
        assert_eq!((c.seen_within(40, 15), c.seen_within(40, 3_600)), (1, 2));
    }

    #[test]
    fn the_pis_own_address_space_and_ipv6_are_not_clients() {
        let mut c = Clients::default();
        c.record("127.0.0.1".parse().unwrap(), 1);
        c.record("127.9.9.9".parse().unwrap(), 1);
        c.record("::1".parse().unwrap(), 1);
        c.record("2001:db8::1".parse().unwrap(), 1);
        assert_eq!(c.len(), 0);
        assert!(c.is_empty());
        // The rule is one function, which the listener asks as well.
        assert_eq!(counted("127.0.0.1".parse().unwrap()), None);
        assert_eq!(counted("::1".parse().unwrap()), None);
        assert_eq!(
            counted("198.51.100.4".parse().unwrap()),
            Some(Ipv4Addr::new(198, 51, 100, 4))
        );
    }

    // Review Focus 5
    #[test]
    fn the_table_holds_256_and_forgets_the_least_recently_seen() {
        let mut c = Clients::default();
        for n in 0..300 {
            c.record(v4(n), u64::from(n));
        }
        assert_eq!(c.len(), MAX_CLIENTS);
        // 0..43 were dropped.
        assert!(
            c.list(300)
                .iter()
                .all(|e| e.addr >= Ipv4Addr::from(0xc000_0200 + 44))
        );
        // An old one seen again moves to the front.
        c.record(v4(44), 301);
        assert_eq!(c.list(301)[0].addr, Ipv4Addr::from(0xc000_0200 + 44));
    }

    #[test]
    fn addresses_seen_in_the_same_second_are_dropped_in_the_order_they_came() {
        let mut c = Clients::default();
        for n in 0..300 {
            c.record(v4(n), 5);
        }
        assert_eq!(c.len(), MAX_CLIENTS);
        let oldest = c.list(5).last().map(|e| e.addr);
        assert_eq!(oldest, Some(Ipv4Addr::from(0xc000_0200 + 44)));
    }

    #[test]
    fn a_window_is_counted_back_from_now_and_never_before_the_start() {
        let mut c = Clients::default();
        c.record(v4(1), 0);
        c.record(v4(2), 100);
        // The window reaches back past the start of the clock.
        assert_eq!(c.seen_within(100, 86_400), 2);
        // The edge of the window is in it.
        assert_eq!((c.seen_within(100, 100), c.seen_within(101, 100)), (2, 1));
        assert_eq!(c.seen_within(100, 0), 1);
    }
}
