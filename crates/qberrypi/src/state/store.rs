//! The two copies: which of them a start reads, which of them a save writes, and what happens to
//! the pair when a write fails or is cut short by a power cut.
//!
//! A [`Store`] remembers, for each copy, the sequence it holds if it is whole and nothing if it is
//! not. At a start [`Store::load`] reads the two copies' bytes and picks the whole one with the
//! highest sequence in serial-number order ([`newer`]); two whole copies of the same sequence, or
//! half the counter's range apart, are not ordered and copy `a` wins. A save ([`Store::save`])
//! writes the copy that is not the newest whole one (`a` when neither is) with a sequence one past
//! the newest's, wrapping from `u64::MAX` to 0, and only then is that copy the newest. A write
//! that fails marks its copy not whole, so the other stays the newest and the next save aims at the
//! same copy again; a write that is cut short by a power cut leaves a copy that fails its checksum
//! (see [`format`]) for the same effect, and the copy that was not being written still holds the
//! state before.
//!
//! What the copies are made of is the [`Medium`]'s business: this file only hands it a whole frame
//! for a copy, and reads nothing but the bytes it is given. The state a loaded copy holds is as
//! private as the file: [`Found`] prints counts only.

use std::fmt;
use std::io;

use super::Saved;
use super::format::{self, MAX_PAYLOAD, decode_payload, newer, read_frame};

/// One of the two copies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Which {
    /// The first copy, `a.bin`.
    A,
    /// The second copy, `b.bin`.
    B,
}

impl Which {
    /// The other copy.
    pub fn other(self) -> Which {
        match self {
            Which::A => Which::B,
            Which::B => Which::A,
        }
    }

    /// The letter a log line names the copy by: `a` or `b`.
    pub fn letter(self) -> char {
        match self {
            Which::A => 'a',
            Which::B => 'b',
        }
    }
}

/// Where the two copies are kept: a card, or in a test, memory.
pub trait Medium {
    /// The whole of copy `which`, as it is now (its file, not just its frame).
    fn read(&self, which: Which) -> io::Result<Vec<u8>>;

    /// Writes `frame` (a whole frame, from [`format::frame`]) at the start of copy `which`, leaving
    /// the rest of the copy as it was, and returns when it is as durable as the medium makes it. A
    /// write that fails, or is cut short, may leave the copy's frame torn: that copy is then not
    /// whole, and the other is untouched.
    fn write(&self, which: Which, frame: &[u8]) -> io::Result<()>;
}

/// Why a save wrote nothing, or may have written a copy that is not whole.
#[derive(Debug)]
pub enum SaveError {
    /// The payload is not one a copy may hold: it is longer than [`MAX_PAYLOAD`], or it is not one
    /// that [`format::encode_payload`] writes (it does not decode). Nothing was written.
    Refused,
    /// The medium failed the write. The copy is marked not whole; the other copy is untouched.
    Write(io::Error),
}

impl fmt::Display for SaveError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SaveError::Refused => out.write_str("the settings are not a payload a copy may hold"),
            SaveError::Write(error) => write!(out, "the write failed: {error}"),
        }
    }
}

impl std::error::Error for SaveError {}

/// Why a start found no copy to restore from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoCopy {
    /// Neither copy was there to read: a card that has never saved.
    Absent,
    /// At least one copy was there and no copy was whole.
    NotWhole,
}

/// The copy a start restores from.
#[derive(Clone, PartialEq, Eq)]
pub struct Found {
    /// Which copy it is.
    pub which: Which,
    /// Its sequence.
    pub seq: u64,
    /// The state it holds.
    pub saved: Saved,
    /// The bytes of its payload, which are [`format::encode_payload`] of `saved`: what a later
    /// encoding is compared with to tell whether anything changed.
    pub payload: Vec<u8>,
}

impl fmt::Debug for Found {
    /// The copy, the sequence, the counts of the state and the length of the payload: never its
    /// bytes, which are the owner's.
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("Found")
            .field("which", &self.which)
            .field("seq", &self.seq)
            .field("saved", &self.saved)
            .field("payload", &self.payload.len())
            .finish()
    }
}

/// What a start found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Loaded {
    /// A whole copy: the newest of the whole ones.
    Found(Box<Found>),
    /// No whole copy, and why.
    Empty(NoCopy),
}

/// The pair of copies as the board knows it: the sequence of each that is whole.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Store {
    /// Copy `a`'s sequence, if it is whole.
    a: Option<u64>,
    /// Copy `b`'s sequence, if it is whole.
    b: Option<u64>,
}

/// A copy that is whole: its sequence, its payload and the state in it.
struct Whole<'a> {
    seq: u64,
    payload: &'a [u8],
    saved: Saved,
}

/// The copy in `bytes`, if there is a frame in them whose payload decodes.
fn whole(bytes: Option<&[u8]>) -> Option<Whole<'_>> {
    let (seq, payload) = read_frame(bytes?)?;
    let saved = decode_payload(payload)?;
    Some(Whole {
        seq,
        payload,
        saved,
    })
}

impl Store {
    /// Reads the two copies' bytes (`None` for a copy that is not there), and says which is the
    /// newest whole one, if any, with the store that knows the sequence of each whole copy.
    pub fn load(bytes_a: Option<&[u8]>, bytes_b: Option<&[u8]>) -> (Store, Loaded) {
        let (a, b) = (whole(bytes_a), whole(bytes_b));
        let store = Store {
            a: a.as_ref().map(|copy| copy.seq),
            b: b.as_ref().map(|copy| copy.seq),
        };
        let found = |which, copy: Whole<'_>| {
            Loaded::Found(Box::new(Found {
                which,
                seq: copy.seq,
                payload: copy.payload.to_vec(),
                saved: copy.saved,
            }))
        };
        let loaded = match (a, b) {
            (Some(a), Some(b)) if newer(b.seq, a.seq) => found(Which::B, b),
            (Some(a), _) => found(Which::A, a),
            (None, Some(b)) => found(Which::B, b),
            (None, None) if bytes_a.is_none() && bytes_b.is_none() => Loaded::Empty(NoCopy::Absent),
            (None, None) => Loaded::Empty(NoCopy::NotWhole),
        };
        (store, loaded)
    }

    /// Sets what is known of copy `which`.
    fn set(&mut self, which: Which, seq: Option<u64>) {
        match which {
            Which::A => self.a = seq,
            Which::B => self.b = seq,
        }
    }

    /// The newest whole copy and its sequence, if any copy is whole: the one that is ahead in
    /// serial order, and `a` when neither is.
    pub fn newest(&self) -> Option<(Which, u64)> {
        match (self.a, self.b) {
            (Some(a), Some(b)) if newer(b, a) => Some((Which::B, b)),
            (Some(a), _) => Some((Which::A, a)),
            (None, Some(b)) => Some((Which::B, b)),
            (None, None) => None,
        }
    }

    /// The copy the next save writes and the sequence it gets: the copy that is not the newest
    /// whole one, one past the newest's sequence (wrapping), and `a` with 1 when no copy is whole.
    fn target(&self) -> (Which, u64) {
        match self.newest() {
            Some((which, seq)) => (which.other(), seq.wrapping_add(1)),
            None => (Which::A, 1),
        }
    }

    /// Saves `payload` (from [`format::encode_payload`]) into the copy that is not the newest
    /// whole one, with the sequence one past the newest's, and returns which copy and which
    /// sequence. On success that copy is the newest; when the medium fails the write it is marked
    /// not whole, the newest stays the newest, and the next save aims at the same copy again.
    ///
    /// A payload longer than [`MAX_PAYLOAD`], or one that does not decode, is refused before
    /// anything is written, so that a save never makes a copy that a start would not take.
    pub fn save(&mut self, medium: &dyn Medium, payload: &[u8]) -> Result<(Which, u64), SaveError> {
        if payload.len() > MAX_PAYLOAD || decode_payload(payload).is_none() {
            return Err(SaveError::Refused);
        }
        let (which, seq) = self.target();
        match medium.write(which, &format::frame(seq, payload)) {
            Ok(()) => {
                self.set(which, Some(seq));
                Ok((which, seq))
            }
            Err(error) => {
                self.set(which, None);
                Err(SaveError::Write(error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use qb_dns::OwnerSide;

    use super::super::format::{FILE_SIZE, encode_payload, frame};
    use super::super::{SavedDevices, SavedName};
    use super::*;
    use crate::watch::devices::Label;
    use crate::watch::frames::Mac;

    /// Copies held in memory, each exactly [`FILE_SIZE`] bytes of what a card holds before a first
    /// save (a fill that is no frame), with a switch that makes writes fail.
    struct Mem {
        files: RefCell<[Vec<u8>; 2]>,
        fail: Cell<bool>,
    }

    impl Mem {
        fn new() -> Self {
            let fill = |salt: u8| -> Vec<u8> {
                (0..FILE_SIZE)
                    .map(|n| (n as u8).wrapping_mul(31).wrapping_add(salt) | 1)
                    .collect()
            };
            Mem {
                files: RefCell::new([fill(3), fill(9)]),
                fail: Cell::new(false),
            }
        }

        fn index(which: Which) -> usize {
            match which {
                Which::A => 0,
                Which::B => 1,
            }
        }

        /// The medium's two files as a start would read them.
        fn load(&self) -> (Store, Loaded) {
            let files = self.files.borrow();
            Store::load(Some(&files[0]), Some(&files[1]))
        }
    }

    impl Medium for Mem {
        fn read(&self, which: Which) -> io::Result<Vec<u8>> {
            Ok(self.files.borrow()[Self::index(which)].clone())
        }

        fn write(&self, which: Which, frame: &[u8]) -> io::Result<()> {
            if self.fail.get() {
                return Err(io::Error::other("the card said no"));
            }
            self.files.borrow_mut()[Self::index(which)][..frame.len()].copy_from_slice(frame);
            Ok(())
        }
    }

    /// A state that differs from every other `n`.
    fn state(n: u8) -> Saved {
        Saved {
            devices: SavedDevices {
                exempt: vec![Mac([2, 0, 0, 0, 0, n])],
                labels: vec![(
                    Mac([2, 0, 0, 0, 1, n]),
                    Label::new(&format!("device {n}")).unwrap(),
                )],
                known: (0..n).map(|k| Mac([2, 0, 0, 0, 2, k])).collect(),
                ..SavedDevices::default()
            },
            names: vec![SavedName {
                name: format!("host-{n}.example.org").into(),
                side: OwnerSide::Refuse,
                set_unix: Some(u64::from(n)),
            }],
            ..Saved::default()
        }
    }

    fn payload(n: u8) -> Vec<u8> {
        encode_payload(&state(n)).unwrap()
    }

    /// What a start finds on `medium`: the state and the copy and sequence, or `None`.
    fn found(medium: &Mem) -> Option<(Saved, Which, u64)> {
        match medium.load().1 {
            Loaded::Found(copy) => Some((copy.saved, copy.which, copy.seq)),
            Loaded::Empty(_) => None,
        }
    }

    #[test]
    fn a_state_saved_is_the_state_loaded() {
        let medium = Mem::new();
        let (mut store, loaded) = medium.load();
        assert_eq!(loaded, Loaded::Empty(NoCopy::NotWhole), "a fill is no copy");
        assert_eq!(store.save(&medium, &payload(1)).unwrap(), (Which::A, 1));
        let (loaded_store, loaded) = medium.load();
        assert_eq!(loaded_store, store, "what is saved is what a start knows");
        let Loaded::Found(copy) = loaded else {
            panic!("nothing found");
        };
        assert_eq!((copy.which, copy.seq), (Which::A, 1));
        assert_eq!(copy.saved, state(1));
        assert_eq!(
            copy.payload,
            payload(1),
            "the payload is the one that was saved"
        );
    }

    #[test]
    fn no_copy_at_all_and_no_whole_copy_are_told_apart() {
        let (store, loaded) = Store::load(None, None);
        assert_eq!(loaded, Loaded::Empty(NoCopy::Absent));
        assert_eq!(store.newest(), None);
        let junk = vec![0x55; FILE_SIZE];
        assert_eq!(
            Store::load(Some(&junk), None).1,
            Loaded::Empty(NoCopy::NotWhole)
        );
        assert_eq!(
            Store::load(None, Some(&junk)).1,
            Loaded::Empty(NoCopy::NotWhole)
        );
        let (store, loaded) = Store::load(Some(&junk), Some(&junk));
        assert_eq!(loaded, Loaded::Empty(NoCopy::NotWhole));
        assert_eq!(store, Store::default());
    }

    #[test]
    fn both_copies_invalid_start_empty_and_the_next_save_makes_copy_a_the_first() {
        let medium = Mem::new();
        let (mut store, loaded) = medium.load();
        assert_eq!(loaded, Loaded::Empty(NoCopy::NotWhole));
        assert_eq!(store.save(&medium, &payload(4)).unwrap(), (Which::A, 1));
        assert_eq!(found(&medium).unwrap().0, state(4));
    }

    #[test]
    fn saves_alternate_between_the_copies_and_count_up() {
        let medium = Mem::new();
        let mut store = medium.load().0;
        for (n, (which, seq)) in [
            (Which::A, 1),
            (Which::B, 2),
            (Which::A, 3),
            (Which::B, 4),
            (Which::A, 5),
        ]
        .into_iter()
        .enumerate()
        {
            let n = u8::try_from(n).unwrap() + 1;
            assert_eq!(store.save(&medium, &payload(n)).unwrap(), (which, seq));
            assert_eq!(store.newest(), Some((which, seq)));
            assert_eq!(found(&medium), Some((state(n), which, seq)));
        }
    }

    #[test]
    fn a_start_goes_on_from_the_copy_it_found() {
        let medium = Mem::new();
        let mut store = medium.load().0;
        store.save(&medium, &payload(1)).unwrap();
        store.save(&medium, &payload(2)).unwrap();
        // A new boot: the store is made again from the bytes, and the next save goes on from them.
        let mut again = medium.load().0;
        assert_eq!(again, store);
        assert_eq!(again.save(&medium, &payload(3)).unwrap(), (Which::A, 3));
    }

    #[test]
    fn the_highest_sequence_wins_and_equal_sequences_prefer_a() {
        let a = frame(7, &payload(1));
        let b = frame(8, &payload(2));
        let (store, loaded) = Store::load(Some(&a), Some(&b));
        assert_eq!(store.newest(), Some((Which::B, 8)));
        let Loaded::Found(copy) = loaded else {
            panic!("nothing found");
        };
        assert_eq!((copy.which, copy.saved), (Which::B, state(2)));
        // And the other way round.
        let Loaded::Found(copy) = Store::load(Some(&b), Some(&a)).1 else {
            panic!("nothing found");
        };
        assert_eq!((copy.which, copy.saved), (Which::A, state(2)));
        // The same sequence in both: copy a, whatever the states.
        let same_b = frame(8, &payload(3));
        let (store, loaded) = Store::load(Some(&b), Some(&same_b));
        assert_eq!(store.newest(), Some((Which::A, 8)));
        let Loaded::Found(copy) = loaded else {
            panic!("nothing found");
        };
        assert_eq!((copy.which, copy.saved), (Which::A, state(2)));
        // And the next save goes to b, one past.
        let medium = Mem::new();
        medium.files.borrow_mut()[0][..b.len()].copy_from_slice(&b);
        medium.files.borrow_mut()[1][..same_b.len()].copy_from_slice(&same_b);
        let mut store = medium.load().0;
        assert_eq!(store.save(&medium, &payload(4)).unwrap(), (Which::B, 9));
    }

    #[test]
    fn the_sequence_wraps_and_the_copy_after_the_wrap_is_the_newest() {
        let medium = Mem::new();
        let at_max = frame(u64::MAX, &payload(1));
        medium.files.borrow_mut()[0][..at_max.len()].copy_from_slice(&at_max);
        let before = frame(u64::MAX - 1, &payload(9));
        medium.files.borrow_mut()[1][..before.len()].copy_from_slice(&before);
        let (mut store, loaded) = medium.load();
        let Loaded::Found(copy) = loaded else {
            panic!("nothing found");
        };
        assert_eq!((copy.which, copy.seq), (Which::A, u64::MAX));
        assert_eq!(store.save(&medium, &payload(2)).unwrap(), (Which::B, 0));
        assert_eq!(found(&medium), Some((state(2), Which::B, 0)));
        assert_eq!(store.save(&medium, &payload(3)).unwrap(), (Which::A, 1));
        assert_eq!(found(&medium), Some((state(3), Which::A, 1)));
    }

    #[test]
    fn a_failed_write_leaves_the_other_copy_newest_and_the_next_save_aims_at_the_same_copy() {
        let medium = Mem::new();
        let mut store = medium.load().0;
        store.save(&medium, &payload(1)).unwrap();
        store.save(&medium, &payload(2)).unwrap();
        assert_eq!(store.newest(), Some((Which::B, 2)));

        medium.fail.set(true);
        let error = store.save(&medium, &payload(3)).unwrap_err();
        assert!(matches!(error, SaveError::Write(_)), "{error}");
        assert_eq!(
            store.newest(),
            Some((Which::B, 2)),
            "the other copy stays the newest"
        );
        medium.fail.set(false);
        assert_eq!(found(&medium), Some((state(2), Which::B, 2)));

        // The copy that failed is aimed at again, with the sequence one past the newest's.
        assert_eq!(store.save(&medium, &payload(4)).unwrap(), (Which::A, 3));
        assert_eq!(found(&medium), Some((state(4), Which::A, 3)));
    }

    #[test]
    fn a_failed_first_save_leaves_the_store_empty_and_aims_at_copy_a_again() {
        let medium = Mem::new();
        let mut store = medium.load().0;
        medium.fail.set(true);
        assert!(store.save(&medium, &payload(1)).is_err());
        assert_eq!(store.newest(), None);
        medium.fail.set(false);
        assert_eq!(store.save(&medium, &payload(1)).unwrap(), (Which::A, 1));
    }

    #[test]
    fn a_payload_a_copy_may_not_hold_is_refused_and_nothing_is_written() {
        let medium = Mem::new();
        let mut store = medium.load().0;
        let before = medium.files.borrow().clone();
        for bad in [
            vec![],
            vec![0; 3],
            vec![0; MAX_PAYLOAD + 1],
            [payload(1), vec![0]].concat(),
        ] {
            assert!(matches!(store.save(&medium, &bad), Err(SaveError::Refused)));
        }
        assert_eq!(*medium.files.borrow(), before);
        assert_eq!(store.newest(), None);
    }

    /// The other copy's state must win over a copy that was torn while it was being written. `torn`
    /// is the copy the save that is cut aims at, `torn_bytes` makes the torn copies from its old
    /// bytes and the frame it was writing. Gives how many copies were tried, and the frame's length.
    fn tear(torn: Which, torn_bytes: impl Fn(&[u8], &[u8]) -> Vec<Vec<u8>>) -> (usize, usize) {
        // Copy A gets saves 1, 3, 5; copy B gets 2, 4: before the cut save, `before` saves are
        // made, and the next one is aimed at `torn`.
        let before: u8 = if torn == Which::A { 2 } else { 3 };
        let medium = Mem::new();
        let mut store = medium.load().0;
        for n in 1..=before {
            store.save(&medium, &payload(n)).unwrap();
        }
        let other = torn.other();
        assert_eq!(store.newest().map(|(which, _)| which), Some(other));
        let (target, seq) = store.target();
        assert_eq!(target, torn);
        let new_frame = frame(seq, &payload(before + 1));
        let old_bytes = medium.read(torn).unwrap();
        let kept = Mem::index(other);
        let mut tried = 0;
        for bytes in torn_bytes(&old_bytes, &new_frame) {
            let mut files = [Vec::new(), Vec::new()];
            files[kept] = medium.read(other).unwrap();
            files[Mem::index(torn)] = bytes;
            let (_, loaded) = Store::load(Some(&files[0]), Some(&files[1]));
            let Loaded::Found(copy) = loaded else {
                panic!("neither copy was taken after a tear of {torn:?}");
            };
            assert_eq!(copy.which, other, "the other copy wins (tear #{tried})");
            assert_eq!(copy.saved, state(before), "tear #{tried}");
            tried += 1;
        }
        (tried, new_frame.len())
    }

    #[test]
    fn a_write_cut_short_at_any_byte_leaves_the_other_copy_to_win() {
        for torn in [Which::A, Which::B] {
            let (tried, len) = tear(torn, |old, new_frame| {
                // The cut at every offset of the frame, the new frame's start over the old bytes
                // (the whole frame is a write that was not cut: every shorter cut is).
                (0..new_frame.len())
                    .map(|cut| {
                        let mut bytes = old.to_vec();
                        bytes[..cut].copy_from_slice(&new_frame[..cut]);
                        bytes
                    })
                    .collect()
            });
            assert_eq!(tried, len, "a cut at every offset of the frame of {torn:?}");
            assert!(len > 150, "a frame of {len} bytes has a payload to cut");
        }
    }

    #[test]
    fn a_write_with_one_byte_wrong_leaves_the_other_copy_to_win() {
        for torn in [Which::A, Which::B] {
            let (tried, len) = tear(torn, |old, new_frame| {
                // The whole frame over the old bytes, with each byte of it, in turn, flipped: the
                // header (magic, version, length, sequence), the payload's start, middle and end,
                // and the checksum.
                let mut all = Vec::new();
                for offset in 0..new_frame.len() {
                    for mask in [0x01, 0xff] {
                        let mut bytes = old.to_vec();
                        bytes[..new_frame.len()].copy_from_slice(new_frame);
                        bytes[offset] ^= mask;
                        all.push(bytes);
                    }
                }
                all
            });
            assert_eq!(
                tried,
                2 * len,
                "two flips at every offset of the frame of {torn:?}"
            );
        }
    }

    /// A state of `n` that holds a thousand known devices, so that its frame is a dozen sectors
    /// long and differs from every other `n` in nearly every sector.
    fn bulky(n: u8) -> Saved {
        Saved {
            devices: SavedDevices {
                known: (0..900u16)
                    .map(|k| {
                        let [high, low] = k.to_be_bytes();
                        Mac([2, 0, n, n.wrapping_mul(7), high, low])
                    })
                    .collect(),
                ..SavedDevices::default()
            },
            ..state(n)
        }
    }

    /// The order in which a device that writes a frame's sectors as it likes may put them: as they
    /// come, back to front, and one fixed shuffle (a stride that is coprime with the number of
    /// sectors, so that every sector is written once and the order is neither of the others).
    fn sector_orders(sectors: usize) -> [(&'static str, Vec<usize>); 3] {
        let gcd = |mut a: usize, mut b: usize| {
            while b != 0 {
                (a, b) = (b, a % b);
            }
            a
        };
        let stride = (sectors / 2..)
            .find(|&s| s > 1 && gcd(s, sectors) == 1)
            .unwrap();
        [
            ("forward", (0..sectors).collect()),
            ("reverse", (0..sectors).rev().collect()),
            (
                "shuffled",
                (0..sectors).map(|i| (i * stride + 3) % sectors).collect(),
            ),
        ]
    }

    #[test]
    fn a_frame_whose_sectors_reach_the_card_in_any_order_and_stop_after_any_of_them_leaves_one_copy_whole()
     {
        const SECTOR: usize = 512;
        for torn in [Which::A, Which::B] {
            let before: u8 = if torn == Which::A { 2 } else { 3 };
            let medium = Mem::new();
            let mut store = medium.load().0;
            for n in 1..=before {
                store
                    .save(&medium, &encode_payload(&bulky(n)).unwrap())
                    .unwrap();
            }
            let other = torn.other();
            assert_eq!(store.newest().map(|(which, _)| which), Some(other));
            let (target, seq) = store.target();
            assert_eq!(target, torn);
            let new_frame = frame(seq, &encode_payload(&bulky(before + 1)).unwrap());
            let sectors = new_frame.len().div_ceil(SECTOR);
            assert!(
                sectors >= 10,
                "a frame of {sectors} sectors has an order to speak of"
            );
            // The card writes whole sectors: the frame, padded with zeros to the sector.
            let mut padded = new_frame.clone();
            padded.resize(sectors * SECTOR, 0);
            let old = medium.read(torn).unwrap();
            let kept = medium.read(other).unwrap();

            let mut cases = 0;
            for (name, order) in sector_orders(sectors) {
                let mut seen = order.clone();
                seen.sort_unstable();
                assert_eq!(seen, (0..sectors).collect::<Vec<_>>(), "{name} is an order");
                for written in 0..=sectors {
                    let mut bytes = old.clone();
                    for &sector in &order[..written] {
                        let range = sector * SECTOR..(sector + 1) * SECTOR;
                        bytes[range.clone()].copy_from_slice(&padded[range]);
                    }
                    let mut files = [Vec::new(), Vec::new()];
                    files[Mem::index(other)] = kept.clone();
                    files[Mem::index(torn)] = bytes;
                    let (_, loaded) = Store::load(Some(&files[0]), Some(&files[1]));
                    let Loaded::Found(copy) = loaded else {
                        panic!("{name}, {written} of {sectors}: neither copy was taken");
                    };
                    if written == sectors {
                        // Every sector made it: the save is complete, and it is the newest.
                        assert_eq!((copy.which, copy.seq), (torn, seq), "{name}, all");
                        assert_eq!(copy.saved, bulky(before + 1), "{name}, all");
                    } else {
                        // Some did not: the other copy is whole and wins, with the state before.
                        assert_eq!(copy.which, other, "{name}, {written} of {sectors} sectors");
                        assert_eq!(copy.saved, bulky(before), "{name}, {written} of {sectors}");
                    }
                    cases += 1;
                }
            }
            assert_eq!(
                cases,
                3 * (sectors + 1),
                "every order and every stop, for {torn:?}"
            );
        }
    }

    #[test]
    fn the_sector_orders_are_three_different_orders_of_the_same_sectors() {
        for sectors in [10, 11, 12, 13, 16] {
            let [(_, forward), (_, reverse), (_, shuffled)] = sector_orders(sectors);
            assert_ne!(forward, reverse);
            assert_ne!(forward, shuffled);
            assert_ne!(reverse, shuffled);
            let mut sorted = shuffled.clone();
            sorted.sort_unstable();
            assert_eq!(sorted, forward);
        }
    }

    #[test]
    fn a_write_that_finished_is_the_newest_and_a_tear_before_its_last_byte_is_not() {
        // The two ends of the cut: the whole frame is a completed save and wins, one byte short is
        // a tear and loses.
        let medium = Mem::new();
        let mut store = medium.load().0;
        store.save(&medium, &payload(1)).unwrap();
        let (target, seq) = store.target();
        let new_frame = frame(seq, &payload(2));
        let old = medium.read(target).unwrap();
        let mut done = old.clone();
        done[..new_frame.len()].copy_from_slice(&new_frame);
        let mut short = old;
        short[..new_frame.len() - 1].copy_from_slice(&new_frame[..new_frame.len() - 1]);
        let other = medium.read(target.other()).unwrap();
        let load = |copy: &[u8]| {
            let (a, b) = match target {
                Which::A => (copy, &other[..]),
                Which::B => (&other[..], copy),
            };
            match Store::load(Some(a), Some(b)).1 {
                Loaded::Found(found) => found.saved,
                Loaded::Empty(_) => panic!("nothing found"),
            }
        };
        assert_eq!(load(&done), state(2));
        assert_eq!(load(&short), state(1));
    }
}
