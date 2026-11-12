//! A map with a fixed capacity that evicts the least recently used key.
//!
//! Entries live in a `Vec` of slots; a `HashMap` gives each key's slot index. The slots in use
//! form a doubly linked list in use order, and the slots given up form a singly linked free list,
//! both linked by index.
//!
//! Invariants, which hold between calls:
//! - every index in `map`, `oldest`, `newest`, `free`, `prev` and `next` is either `NIL` or was a
//!   valid index when it was stored, and stays one because `slots` never shrinks;
//! - a slot is on exactly one list: the use list if it holds an entry, the free list if not, so
//!   `slots.len()` is `map.len()` plus the length of the free list;
//! - `map.len()` and `slots.len()` never exceed `capacity`.
//!
//! No method panics even if a link were wrong: every slot access goes through `get` or `get_mut`,
//! which also turn `NIL` into `None`, and no arithmetic is done on an index.

use std::collections::HashMap;
use std::hash::Hash;

/// "No slot": the end of a list. Never a valid index, since a `Vec` of slots, which are not
/// zero-sized, holds at most `isize::MAX` bytes.
const NIL: usize = usize::MAX;

/// One place in the slot `Vec`.
struct Slot<K, V> {
    /// The key and value, or `None` while the slot is on the free list.
    entry: Option<(K, V)>,
    /// The slot used just before this one, or `NIL` for the oldest. Unused on the free list.
    prev: usize,
    /// The slot used just after this one, or `NIL` for the newest; on the free list, the next
    /// free slot.
    next: usize,
}

/// A map of at most `capacity` entries; inserting into a full one evicts the least recently
/// used key.
pub(crate) struct Lru<K, V> {
    capacity: usize,
    map: HashMap<K, usize>,
    slots: Vec<Slot<K, V>>,
    /// The least recently used slot, or `NIL` when empty.
    oldest: usize,
    /// The most recently used slot, or `NIL` when empty.
    newest: usize,
    /// The first slot of the free list, or `NIL`.
    free: usize,
}

impl<K: Hash + Eq + Clone, V> Lru<K, V> {
    /// An empty map holding at most `capacity` entries; 0 is treated as 1. Nothing is reserved:
    /// storage grows with the entries, up to the capacity.
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            map: HashMap::new(),
            slots: Vec::new(),
            oldest: NIL,
            newest: NIL,
            free: NIL,
        }
    }

    /// The value of `key`, which becomes the most recently used.
    pub(crate) fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        let at = *self.map.get(key)?;
        self.unlink(at);
        self.link_newest(at);
        let (_, value) = self.slots.get_mut(at)?.entry.as_mut()?;
        Some(value)
    }

    /// The value of `key`, without counting as a use.
    pub(crate) fn peek(&self, key: &K) -> Option<&V> {
        let at = *self.map.get(key)?;
        let (_, value) = self.slots.get(at)?.entry.as_ref()?;
        Some(value)
    }

    /// Stores `value` under `key` as the most recently used. A present key has its value
    /// replaced; a new key in a full map evicts the least recently used entry, which is returned.
    pub(crate) fn insert(&mut self, key: K, value: V) -> Option<(K, V)> {
        if let Some(present) = self.get_mut(&key) {
            *present = value;
            return None;
        }
        // Evicting before storing keeps both the map and the slots within the capacity: the
        // evicted slot goes on the free list and `store` takes it straight back.
        let evicted = if self.map.len() >= self.capacity {
            self.evict_oldest()
        } else {
            None
        };
        let at = self.store((key.clone(), value));
        self.map.insert(key, at);
        self.link_newest(at);
        evicted
    }

    /// Takes `key` out and returns its value.
    pub(crate) fn remove(&mut self, key: &K) -> Option<V> {
        let at = self.map.remove(key)?;
        self.unlink(at);
        let (_, value) = self.release(at)?;
        Some(value)
    }

    /// How many entries are held.
    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }

    /// Takes the least recently used entry out of the map and the use list.
    fn evict_oldest(&mut self) -> Option<(K, V)> {
        let at = self.oldest;
        self.unlink(at);
        let entry = self.release(at)?;
        self.map.remove(&entry.0);
        Some(entry)
    }

    /// Puts `entry` in a free slot, or in a new one when none is free, and returns its index.
    /// The slot is on neither list afterwards.
    fn store(&mut self, entry: (K, V)) -> usize {
        let at = self.free;
        if let Some(slot) = self.slots.get_mut(at) {
            self.free = slot.next;
            slot.entry = Some(entry);
            return at;
        }
        let at = self.slots.len();
        self.slots.push(Slot {
            entry: Some(entry),
            prev: NIL,
            next: NIL,
        });
        at
    }

    /// Empties slot `at`, which must be off the use list, and puts it on the free list.
    fn release(&mut self, at: usize) -> Option<(K, V)> {
        let slot = self.slots.get_mut(at)?;
        slot.next = self.free;
        self.free = at;
        slot.entry.take()
    }

    /// Takes slot `at` out of the use list, joining its neighbours to each other.
    fn unlink(&mut self, at: usize) {
        let Some(slot) = self.slots.get(at) else {
            return;
        };
        let (prev, next) = (slot.prev, slot.next);
        // A neighbour of `NIL` means `at` was at that end of the list.
        match self.slots.get_mut(prev) {
            Some(before) => before.next = next,
            None => self.oldest = next,
        }
        match self.slots.get_mut(next) {
            Some(after) => after.prev = prev,
            None => self.newest = prev,
        }
    }

    /// Puts slot `at`, which must be off the use list, at its most recently used end.
    fn link_newest(&mut self, at: usize) {
        let before = self.newest;
        let Some(slot) = self.slots.get_mut(at) else {
            return;
        };
        (slot.prev, slot.next) = (before, NIL);
        match self.slots.get_mut(before) {
            Some(previous) => previous.next = at,
            None => self.oldest = at,
        }
        self.newest = at;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Rng;

    impl<K: Hash + Eq + Clone, V> Lru<K, V> {
        /// Panics unless the structure invariants hold and nothing has outgrown the capacity.
        fn check(&self) {
            assert!(self.slots.len() <= self.capacity && self.map.len() <= self.capacity);
            let (mut used, mut before, mut at) = (0, NIL, self.oldest);
            while at != NIL {
                let slot = &self.slots[at];
                let (key, _) = slot.entry.as_ref().expect("a linked slot holds an entry");
                assert_eq!((self.map.get(key), slot.prev), (Some(&at), before));
                used += 1;
                assert!(used <= self.slots.len(), "the use order loops");
                (before, at) = (at, slot.next);
            }
            assert_eq!((before, used), (self.newest, self.map.len()));
            let (mut free, mut at) = (0, self.free);
            while at != NIL {
                assert!(self.slots[at].entry.is_none());
                free += 1;
                assert!(free <= self.slots.len(), "the free list loops");
                at = self.slots[at].next;
            }
            assert_eq!(used + free, self.slots.len());
        }
    }

    #[test]
    fn least_recently_used_is_evicted() {
        let mut l = Lru::new(2);
        assert!(l.insert("a", 1).is_none() && l.insert("b", 2).is_none());
        *l.get_mut(&"a").unwrap() += 10;
        assert_eq!(l.insert("c", 3), Some(("b", 2)));
        assert_eq!(
            (l.peek(&"a"), l.peek(&"b"), l.peek(&"c"), l.len()),
            (Some(&11), None, Some(&3), 2)
        );
    }

    #[test]
    fn peek_does_not_refresh() {
        let mut l = Lru::new(2);
        l.insert("a", 1);
        l.insert("b", 2);
        l.peek(&"a");
        assert_eq!(l.insert("c", 3), Some(("a", 1)));
    }

    #[test]
    fn inserting_a_present_key_replaces_and_refreshes() {
        let mut l = Lru::new(2);
        l.insert("a", 1);
        l.insert("b", 2);
        assert_eq!(l.insert("a", 9), None);
        assert_eq!(l.insert("c", 3), Some(("b", 2)));
        assert_eq!(l.peek(&"a"), Some(&9));
    }

    #[test]
    fn remove_frees_a_slot() {
        let mut l = Lru::new(2);
        l.insert("a", 1);
        l.insert("b", 2);
        assert_eq!(
            (l.remove(&"a"), l.remove(&"a"), l.len()),
            (Some(1), None, 1)
        );
        assert!(l.insert("c", 3).is_none());
        assert_eq!(Lru::<u8, u8>::new(0).insert(1, 1), None);
    }

    #[test]
    fn capacity_zero_holds_one_entry() {
        let mut l = Lru::new(0);
        assert_eq!((l.insert(1, 1), l.insert(2, 2)), (None, Some((1, 1))));
        assert_eq!((l.peek(&1), l.peek(&2), l.len()), (None, Some(&2), 1));
        l.check();
    }

    #[test]
    fn a_huge_capacity_reserves_nothing_up_front() {
        let mut l = Lru::new(usize::MAX);
        assert_eq!((l.slots.capacity(), l.map.capacity()), (0, 0));
        assert_eq!((l.insert(1, 1), l.insert(2, 2), l.len()), (None, None, 2));
        l.check();
    }

    #[test]
    fn matches_a_simple_model() {
        const CAPACITY: usize = 8;
        let mut rng = Rng::new(7);
        let mut lru: Lru<usize, u64> = Lru::new(CAPACITY);
        // In use order: the least recently used first, the most recently used last.
        let mut model: Vec<(usize, u64)> = Vec::new();
        let (mut evictions, mut removals) = (0, 0);
        for _ in 0..50_000 {
            let key = rng.below(16);
            let at = model.iter().position(|&(k, _)| k == key);
            match rng.below(5) {
                0 => {
                    let expected = at.map(|at| {
                        let (key, value) = model.remove(at);
                        model.push((key, value.wrapping_add(1)));
                        value.wrapping_add(1)
                    });
                    let got = lru.get_mut(&key).map(|value| {
                        *value = value.wrapping_add(1);
                        *value
                    });
                    assert_eq!(got, expected);
                }
                1 => assert_eq!(lru.peek(&key), at.map(|at| &model[at].1)),
                2 => {
                    let expected = at.map(|at| model.remove(at).1);
                    removals += usize::from(expected.is_some());
                    assert_eq!(lru.remove(&key), expected);
                }
                _ => {
                    let value = rng.next();
                    let expected = match at {
                        Some(at) => {
                            model.remove(at);
                            None
                        }
                        None if model.len() == CAPACITY => Some(model.remove(0)),
                        None => None,
                    };
                    model.push((key, value));
                    evictions += usize::from(expected.is_some());
                    assert_eq!(lru.insert(key, value), expected);
                }
            }
            assert_eq!(lru.len(), model.len());
            lru.check();
        }
        // The run must have exercised both ways a slot is given up.
        assert!(
            evictions > 1_000 && removals > 1_000,
            "{evictions} evictions, {removals} removals"
        );
        for key in 0..16 {
            let expected = model
                .iter()
                .find(|&&(k, _)| k == key)
                .map(|(_, value)| value);
            assert_eq!(lru.peek(&key), expected);
        }
    }
}
