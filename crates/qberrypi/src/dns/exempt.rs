//! Who is held to the threat lists alone, as the DNS service reads it for every question: the
//! mode, and two small sets of addresses that the device watch keeps.
//!
//! In the list mode (the default) an address is exempt from the ads lists while it is in the
//! listed set: the addresses of the devices that the owner exempted. In the exempt-by-default mode
//! every client is exempt but for an address in the blocked set: the addresses of the devices on
//! the block list, the router's and the Pi's own; and a loopback address, which only the Pi itself
//! asks from, is never exempt in that mode either. A client that is no IPv4 address, or an IPv4
//! address mapped into IPv6, is in neither set.
//!
//! The DNS service reads this before it locks the resolver, so a read is cheap: one relaxed load
//! of the mode, then one set. A set with no address in it is one relaxed atomic load more and
//! nothing else; with some, one read lock that only a change of the set waits on, and a binary
//! search of a sorted array: no allocation either way. The device watch writes it, and seldom:
//! when a list or the mode changes or a listed device's address does. A write builds the new array
//! before it takes the lock, and drops the old one after letting it go. The watch keeps both sets
//! up to date in either mode, so that a change of the mode finds the set it reads ready.
//!
//! An address is a number here and never reaches a log line.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{PoisonError, RwLock};

/// The most addresses a set holds; a longer list is cut to its first ones. The device watch
/// gives no more than this: two lists of 64 devices, each with four addresses at most, and the
/// router's and the Pi's own.
pub const MAX_ADDRS: usize = 2 * 64 * 4 + 2;

/// Who is exempt from the ads lists right now: the mode and the two sets that it reads.
#[derive(Default)]
pub struct Exemption {
    /// Whether every client is exempt but those in `blocked`; otherwise only those in `listed`.
    by_default: AtomicBool,
    /// The addresses of the exempt devices, which the list mode reads.
    listed: AddrSet,
    /// The addresses that stay fully blocked, which the exempt-by-default mode reads.
    blocked: AddrSet,
    /// How many IPv4 addresses that the device watch knows are not in `blocked`, for the stats.
    unblocked: AtomicUsize,
}

impl Exemption {
    /// The list mode, with both sets empty: nobody is exempt.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a question of `client` is held to the threat lists alone. In the list mode it is
    /// while `client` is in the listed set; in the exempt-by-default mode it is unless `client` is
    /// in the blocked set or a loopback address, which only the Pi itself asks from. One relaxed
    /// load of the mode, and then one [`AddrSet::contains`].
    #[inline]
    pub fn is_exempt(&self, client: IpAddr) -> bool {
        if self.by_default.load(Ordering::Relaxed) {
            !client.is_loopback() && !self.blocked.contains(client)
        } else {
            self.listed.contains(client)
        }
    }

    /// Whether the exempt-by-default mode is on.
    pub fn by_default(&self) -> bool {
        self.by_default.load(Ordering::Relaxed)
    }

    /// Turns the exempt-by-default mode on or off. The device watch calls it, after the blocked
    /// set is up to date.
    pub fn set_by_default(&self, on: bool) {
        self.by_default.store(on, Ordering::Relaxed);
    }

    /// The addresses of the exempt devices, which the list mode reads.
    pub fn listed(&self) -> &AddrSet {
        &self.listed
    }

    /// The addresses that stay fully blocked, which the exempt-by-default mode reads.
    pub fn blocked(&self) -> &AddrSet {
        &self.blocked
    }

    /// Notes how many IPv4 addresses that the device watch knows are not in the blocked set.
    pub fn set_unblocked(&self, count: usize) {
        self.unblocked.store(count, Ordering::Relaxed);
    }

    /// How many clients are exempt right now, as the stats tell it: in the list mode the
    /// addresses in the listed set; in the exempt-by-default mode the IPv4 addresses that the
    /// device watch knows (each as the device that claimed it last) and that are not fully
    /// blocked. A client that the watch has not heard is exempt in that mode, but not counted.
    pub fn exempt_clients(&self) -> usize {
        if self.by_default() {
            self.unblocked.load(Ordering::Relaxed)
        } else {
            self.listed.len()
        }
    }
}

/// A small set of IPv4 addresses that is cheap to read: the listed or the blocked ones.
#[derive(Default)]
pub struct AddrSet {
    /// How many addresses `addrs` holds, beside it, so that an empty set is read without the lock.
    /// It is a hint only: a reader that finds it out of date by one change asks the lock, or
    /// treats one question as the set was a moment before.
    len: AtomicUsize,
    /// The addresses as numbers, sorted, each once.
    addrs: RwLock<Vec<u32>>,
}

impl AddrSet {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `client` is in the set: an IPv4 address, or an IPv4 address mapped into IPv6, that
    /// is. With the set empty this is one relaxed load, and no lock is taken.
    pub fn contains(&self, client: IpAddr) -> bool {
        if self.len.load(Ordering::Relaxed) == 0 {
            return false;
        }
        let v4 = match client {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => v4,
                None => return false,
            },
        };
        self.addrs
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .binary_search(&u32::from(v4))
            .is_ok()
    }

    /// Replaces the set with `addrs`, of which the first [`MAX_ADDRS`] are kept. A lock that a
    /// panic poisoned still guards a whole array, so it is taken as it is.
    pub fn replace(&self, addrs: &[Ipv4Addr]) {
        let mut sorted: Vec<u32> = addrs
            .iter()
            .take(MAX_ADDRS)
            .map(|&a| u32::from(a))
            .collect();
        sorted.sort_unstable();
        sorted.dedup();
        let old = {
            let mut held = self.addrs.write().unwrap_or_else(PoisonError::into_inner);
            self.len.store(sorted.len(), Ordering::Relaxed);
            std::mem::replace(&mut *held, sorted)
        };
        drop(old);
    }

    /// How many addresses the set holds.
    pub fn len(&self) -> usize {
        self.len.load(Ordering::Relaxed)
    }

    /// Whether the set holds no address.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv6Addr;

    /// The address 192.0.2.`host`.
    fn ip(host: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, host)
    }

    #[test]
    fn an_empty_set_holds_nobody() {
        let set = AddrSet::new();
        assert!(set.is_empty());
        assert!(!set.contains(IpAddr::V4(ip(1))));
        assert!(!set.contains(IpAddr::V6(ip(1).to_ipv6_mapped())));
    }

    #[test]
    fn a_set_holds_its_addresses_in_either_form_and_nothing_else() {
        let set = AddrSet::new();
        set.replace(&[ip(9), ip(3), ip(9), ip(200)]);
        assert_eq!(set.len(), 3);
        for host in [3, 9, 200] {
            assert!(set.contains(IpAddr::V4(ip(host))), "{host}");
            assert!(
                set.contains(IpAddr::V6(ip(host).to_ipv6_mapped())),
                "{host}"
            );
        }
        for host in [0, 1, 4, 8, 10, 199, 201, 255] {
            assert!(!set.contains(IpAddr::V4(ip(host))), "{host}");
        }
        // An IPv6 address that is no mapped IPv4 one is never in it, nor is the compatible form.
        assert!(!set.contains(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0xc000, 0x0203
        ))));
        assert!(!set.contains(IpAddr::V6(ip(3).to_ipv6_compatible())));
    }

    #[test]
    fn a_replace_takes_the_place_of_the_old_set_and_an_empty_one_empties_it() {
        let set = AddrSet::new();
        set.replace(&[ip(1), ip(2)]);
        set.replace(&[ip(2), ip(3)]);
        assert!(!set.contains(IpAddr::V4(ip(1))));
        assert!(set.contains(IpAddr::V4(ip(2))) && set.contains(IpAddr::V4(ip(3))));
        set.replace(&[]);
        assert!(set.is_empty());
        assert!(!set.contains(IpAddr::V4(ip(2))));
    }

    #[test]
    fn the_set_keeps_the_first_514_addresses_it_is_given() {
        let set = AddrSet::new();
        // 514 entries that name 128 addresses four times over and two more, then 88 that are new.
        let mut many: Vec<Ipv4Addr> = (0..MAX_ADDRS).map(|n| ip((n % 128) as u8)).collect();
        many.extend((128..216).map(ip));
        set.replace(&many);
        assert_eq!(set.len(), 128);
        assert!(set.contains(IpAddr::V4(ip(127))));
        assert!(!set.contains(IpAddr::V4(ip(128))));
    }

    #[test]
    fn a_poisoned_lock_still_answers() {
        let set = std::sync::Arc::new(AddrSet::new());
        set.replace(&[ip(5)]);
        let poisoner = set.clone();
        let _ = std::thread::spawn(move || {
            let _held = poisoner.addrs.write().unwrap();
            panic!("a holder of the lock panicked");
        })
        .join();
        assert!(set.addrs.is_poisoned());
        assert!(set.contains(IpAddr::V4(ip(5))));
        set.replace(&[ip(6)]);
        assert!(set.contains(IpAddr::V4(ip(6))) && !set.contains(IpAddr::V4(ip(5))));
    }

    #[test]
    fn in_the_list_mode_only_the_listed_addresses_are_exempt() {
        let exemption = Exemption::new();
        assert!(!exemption.by_default());
        assert!(!exemption.is_exempt(IpAddr::V4(ip(5))));
        exemption.listed().replace(&[ip(5)]);
        // The blocked set has no say in this mode.
        exemption.blocked().replace(&[ip(6)]);
        assert!(exemption.is_exempt(IpAddr::V4(ip(5))));
        assert!(exemption.is_exempt(IpAddr::V6(ip(5).to_ipv6_mapped())));
        assert!(!exemption.is_exempt(IpAddr::V4(ip(6))));
        assert!(!exemption.is_exempt(IpAddr::V4(ip(7))));
        assert!(!exemption.is_exempt(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))));
        exemption.set_unblocked(9);
        assert_eq!(exemption.exempt_clients(), 1);
    }

    #[test]
    fn exempt_by_default_exempts_everyone_but_the_blocked_addresses() {
        let exemption = Exemption::new();
        exemption.listed().replace(&[ip(5)]);
        exemption.blocked().replace(&[ip(1), ip(6)]);
        exemption.set_unblocked(3);
        exemption.set_by_default(true);
        assert!(exemption.by_default());
        // A blocked address, in either form, is held to every list.
        assert!(!exemption.is_exempt(IpAddr::V4(ip(6))));
        assert!(!exemption.is_exempt(IpAddr::V6(ip(6).to_ipv6_mapped())));
        assert!(!exemption.is_exempt(IpAddr::V4(ip(1))));
        // So is the Pi itself, asking over loopback.
        assert!(!exemption.is_exempt(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!exemption.is_exempt(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        // Any other is exempt: a listed one, one nobody named, and an IPv6 one.
        for client in [
            IpAddr::V4(ip(5)),
            IpAddr::V4(ip(200)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(ip(6).to_ipv6_compatible()),
        ] {
            assert!(exemption.is_exempt(client), "{client}");
        }
        assert_eq!(exemption.exempt_clients(), 3);
        // Off again, the listed set rules as before.
        exemption.set_by_default(false);
        assert!(!exemption.is_exempt(IpAddr::V4(ip(200))));
        assert!(exemption.is_exempt(IpAddr::V4(ip(5))));
        assert_eq!(exemption.exempt_clients(), 1);
    }
}
