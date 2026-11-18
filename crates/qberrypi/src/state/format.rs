//! The frame a copy starts with and the payload inside it.
//!
//! A copy is exactly [`FILE_SIZE`] bytes, and its frame is at its start:
//!
//! ```text
//! 0..8    magic  b"QBPSTATE"
//! 8..12   format version, u32 LE (1)
//! 12..16  payload length, u32 LE (at most MAX_PAYLOAD)
//! 16..24  sequence, u64 LE
//! 24..    payload (length bytes)
//! then    SHA-256 of bytes 0 .. 24+length (32 bytes)
//! ```
//!
//! The rest of the file is whatever was there: the fill it was made with, or the tail of an older,
//! longer frame. [`read_frame`] never looks at it.
//!
//! The payload is [`encode_payload`]'s deterministic encoding of a [`Saved`], the sections in this
//! order: the exempt list, the block list, the mode, the labels, the known set, the names, the
//! PIN, the configuration's PIN fingerprint, the night and the configuration's night. Counts are
//! `u16` LE, a MAC is its 6 bytes, a string is a `u8` length and its bytes, an `Option<u64>` is a
//! flag byte (0 or 1) and 8 bytes (zeros for none), the hours are a flag byte and two bytes (zeros
//! for none), the mode is 0 for none, 1 for the list mode and 2 for the exempt-by-default mode. A
//! name is its string, its side (0 allowed, 1 refused) and its day. The PIN is a flag byte (0 for
//! none, 1 from the desktop, 2 from the panel) and, for a PIN, the line of its hash as a string.
//!
//! The decoding is as strict as the encoding is exact, so that what [`decode_payload`] accepts is
//! always what [`encode_payload`] would write again: every count is checked against its cap (and
//! the names against their cap on each side), a MAC set must be strictly ascending, every label
//! must pass [`Label::new`], every name must already be normal for [`normalize`], every PIN line
//! must pass [`parse_pin_hash`] (which takes only the rounds of a PIN), every hour must be 0 to 23
//! with the two of a night different, every flag must be one of its values, every filler must be
//! zero, and nothing may be left over. Any failure makes the whole payload, and so the copy,
//! invalid: there is no partial restore.

use qb_dns::OWNER_NAMES_MAX;
use qb_dns::OwnerSide;
use qb_dns::name::{MAX_NAME_LEN, normalize};
use sha2::{Digest, Sha256};

use super::{Saved, SavedDevices, SavedName, SavedPanel, SavedPin};
use crate::api::password::PIN_ROUNDS;
use crate::panel::lock::{Source, parse_pin_hash};
use crate::watch::devices::{LABEL_MAX, Label, MAX_BLOCK, MAX_EXEMPT, MAX_KNOWN, MAX_LABELS};
use crate::watch::frames::Mac;

/// What every copy starts with.
const MAGIC: [u8; 8] = *b"QBPSTATE";

/// The version of the frame and the payload this file writes and reads.
pub const VERSION: u32 = 1;

/// The bytes before the payload: the magic, the version, the length and the sequence.
const HEADER_LEN: usize = 24;

/// The bytes of the checksum after the payload.
const CHECKSUM_LEN: usize = 32;

/// The bytes of a count.
const COUNT_LEN: usize = 2;

/// The bytes of a MAC.
const MAC_LEN: usize = 6;

/// The bytes of an `Option<u64>`: a flag and the number.
const OPTION_LEN: usize = 1 + 8;

/// The bytes of an `Option<(u8, u8)>`: a flag and the two hours.
const HOURS_LEN: usize = 1 + 2;

/// The longest line of a PIN's hash that can be kept, in bytes: `parse_pin_hash` takes only the
/// 10,000 rounds of a PIN, so the line is `$pbkdf2-sha256$i=10000$`, a salt of 32 hex digits, `$`
/// and a hash of 64 hex digits.
const PIN_LINE_MAX: usize = "$pbkdf2-sha256$i=10000$".len() + 32 + 1 + 64;

/// How many names the list holds: [`OWNER_NAMES_MAX`] on each side.
const MAX_NAMES: usize = 2 * OWNER_NAMES_MAX;

/// The bytes of the longest name entry: the length, the name, the side and the day.
const NAME_ENTRY_MAX: usize = 1 + MAX_NAME_LEN + 1 + OPTION_LEN;

/// The bytes of the longest label entry: the MAC, the length and the label.
const LABEL_ENTRY_MAX: usize = MAC_LEN + 1 + LABEL_MAX;

/// The most bytes a payload has: every section at its cap, every name and label at its longest,
/// a PIN of the longest line, from the caps of the structures that give the state. A payload
/// that would be longer is [`Oversize`], never cut.
pub const MAX_PAYLOAD: usize = (COUNT_LEN + MAX_EXEMPT * MAC_LEN)
    + (COUNT_LEN + MAX_BLOCK * MAC_LEN)
    + 1
    + (COUNT_LEN + MAX_LABELS * LABEL_ENTRY_MAX)
    + (COUNT_LEN + MAX_KNOWN * MAC_LEN)
    + (COUNT_LEN + MAX_NAMES * NAME_ENTRY_MAX)
    + (1 + 1 + PIN_LINE_MAX)
    + 32
    + HOURS_LEN
    + HOURS_LEN;

/// The size of each copy on the card: the longest frame, rounded up to 4096 bytes (the block of the
/// card's file system, so that a copy is whole blocks).
///
/// **This size is frozen for this layout.** A card keeps its two files at exactly this size for as
/// long as it lives, and a file of another size is not a copy: the creation makes it again, with a
/// fill, which would destroy what a later build had kept in a larger one. So a later [`VERSION`]
/// must fit inside this size (a longer payload needs another way to keep it, not a larger file),
/// and this build, which finds a frame of a version it does not know, leaves that copy alone
/// ([`foreign_version`]).
pub const FILE_SIZE: usize = (HEADER_LEN + MAX_PAYLOAD + CHECKSUM_LEN).next_multiple_of(4096);

// The file holds the longest frame and has no whole block to spare; every length and count the
// encoding writes in one byte or two fits them, and the length is a number a `u32` holds.
const _: () = {
    let longest = HEADER_LEN + MAX_PAYLOAD + CHECKSUM_LEN;
    assert!(FILE_SIZE >= longest);
    assert!(FILE_SIZE - longest < 4096);
    assert!(FILE_SIZE.is_multiple_of(4096));
    assert!(MAX_PAYLOAD <= u32::MAX as usize);
    assert!(MAX_NAME_LEN <= u8::MAX as usize);
    assert!(LABEL_MAX <= u8::MAX as usize);
    assert!(PIN_LINE_MAX <= u8::MAX as usize);
    assert!(MAX_EXEMPT <= u16::MAX as usize);
    assert!(MAX_BLOCK <= u16::MAX as usize);
    assert!(MAX_LABELS <= u16::MAX as usize);
    assert!(MAX_KNOWN <= u16::MAX as usize);
    assert!(MAX_NAMES <= u16::MAX as usize);
};

/// The state is more than a payload holds, or holds something that no payload may: a section
/// past its cap, a name longer than a name can be, a PIN that is not a PIN of the panel's (the
/// configuration's, or one of another number of rounds, or a line of another length), or hours
/// that are not the hours of a night. Nothing was written; it says nothing of what was too much.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Oversize;

impl std::fmt::Display for Oversize {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str("the settings are more than a saved copy holds")
    }
}

impl std::error::Error for Oversize {}

/// The payload of `saved`: the same state is always the same bytes, whatever order the MAC sets
/// come in (they are sorted, and each MAC is kept once, before they are written). At most
/// [`MAX_PAYLOAD`] bytes.
///
/// [`Oversize`] for a state that no payload holds (see there). A name or a label that the
/// structures made is never what fails here; one that is not normal, or a salt or hash that is
/// not hex, is the decoder's to refuse, so a caller that makes such a state by hand must not
/// expect it back.
pub fn encode_payload(saved: &Saved) -> Result<Vec<u8>, Oversize> {
    let devices = &saved.devices;
    let mut out = Vec::with_capacity(estimate(saved));
    put_macs(&mut out, &devices.exempt, MAX_EXEMPT)?;
    put_macs(&mut out, &devices.block, MAX_BLOCK)?;
    out.push(match devices.exempt_default {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    });
    put_count(&mut out, devices.labels.len(), MAX_LABELS)?;
    for (mac, label) in &devices.labels {
        out.extend_from_slice(&mac.0);
        put_text(&mut out, label, LABEL_MAX)?;
    }
    put_macs(&mut out, &devices.known, MAX_KNOWN)?;
    put_names(&mut out, &saved.names)?;
    let panel = &saved.panel;
    match &panel.pin {
        None => out.push(0),
        Some(pin) => {
            out.push(match pin.source {
                Source::Api => 1,
                Source::Panel => 2,
                Source::Config => return Err(Oversize),
            });
            if pin.hash.rounds() != PIN_ROUNDS {
                return Err(Oversize);
            }
            put_text(&mut out, &pin.hash.to_text(), PIN_LINE_MAX)?;
        }
    }
    out.extend_from_slice(&panel.pin_config);
    put_hours(&mut out, panel.night)?;
    put_hours(&mut out, panel.night_config)?;
    debug_assert!(out.len() <= MAX_PAYLOAD);
    Ok(out)
}

/// About how many bytes the payload of `saved` has, so that it is written into one allocation.
fn estimate(saved: &Saved) -> usize {
    let devices = &saved.devices;
    let macs = devices.exempt.len() + devices.block.len() + devices.known.len();
    macs * MAC_LEN
        + devices.labels.len() * (MAC_LEN + 1 + LABEL_MAX / 2)
        + saved.names.len() * (NAME_ENTRY_MAX / 4)
        + 64
        + 6 * COUNT_LEN
        + PIN_LINE_MAX
}

/// Writes `count` as a `u16`, or `Oversize` if it is more than `cap`.
fn put_count(out: &mut Vec<u8>, count: usize, cap: usize) -> Result<(), Oversize> {
    if count > cap {
        return Err(Oversize);
    }
    let count = u16::try_from(count).map_err(|_| Oversize)?;
    out.extend_from_slice(&count.to_le_bytes());
    Ok(())
}

/// Writes `text` as a length and its bytes, or `Oversize` if it is longer than `cap` bytes.
fn put_text(out: &mut Vec<u8>, text: &str, cap: usize) -> Result<(), Oversize> {
    if text.len() > cap {
        return Err(Oversize);
    }
    out.push(u8::try_from(text.len()).map_err(|_| Oversize)?);
    out.extend_from_slice(text.as_bytes());
    Ok(())
}

/// Writes a set of MACs, sorted and each once: the set as it comes when it is so already, which
/// it is when the structures made it, else a sorted copy.
fn put_macs(out: &mut Vec<u8>, macs: &[Mac], cap: usize) -> Result<(), Oversize> {
    let mut sorted;
    let macs = if macs.windows(2).all(|pair| pair[0] < pair[1]) {
        macs
    } else {
        sorted = macs.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        &sorted
    };
    put_count(out, macs.len(), cap)?;
    for mac in macs {
        out.extend_from_slice(&mac.0);
    }
    Ok(())
}

/// Writes the names in their order, after checking each side against [`OWNER_NAMES_MAX`].
fn put_names(out: &mut Vec<u8>, names: &[SavedName]) -> Result<(), Oversize> {
    let allowed = names
        .iter()
        .filter(|name| name.side == OwnerSide::Allow)
        .count();
    if allowed > OWNER_NAMES_MAX || names.len() - allowed > OWNER_NAMES_MAX {
        return Err(Oversize);
    }
    put_count(out, names.len(), MAX_NAMES)?;
    for name in names {
        put_text(out, &name.name, MAX_NAME_LEN)?;
        out.push(match name.side {
            OwnerSide::Allow => 0,
            OwnerSide::Refuse => 1,
        });
        match name.set_unix {
            None => out.extend_from_slice(&[0; OPTION_LEN]),
            Some(day) => {
                out.push(1);
                out.extend_from_slice(&day.to_le_bytes());
            }
        }
    }
    Ok(())
}

/// Writes a night as a flag and two hours, or `Oversize` for hours that no night has.
fn put_hours(out: &mut Vec<u8>, hours: Option<(u8, u8)>) -> Result<(), Oversize> {
    match hours {
        None => out.extend_from_slice(&[0; HOURS_LEN]),
        Some((from, to)) => {
            if from > 23 || to > 23 || from == to {
                return Err(Oversize);
            }
            out.extend_from_slice(&[1, from, to]);
        }
    }
    Ok(())
}

/// The payload is not one that [`encode_payload`] writes. It says nothing of where.
struct Malformed;

/// What a read of the payload gives, or that it is malformed.
type Read<T> = Result<T, Malformed>;

/// The payload being read, from its start.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    /// The next `n` bytes, or malformed if the payload ends before them.
    fn take(&mut self, n: usize) -> Read<&'a [u8]> {
        let (head, rest) = self.rest.split_at_checked(n).ok_or(Malformed)?;
        self.rest = rest;
        Ok(head)
    }

    /// The next `N` bytes as an array.
    fn array<const N: usize>(&mut self) -> Read<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Malformed)
    }

    fn u8(&mut self) -> Read<u8> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Read<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Read<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    /// A count, which must be at most `cap`.
    fn count(&mut self, cap: usize) -> Read<usize> {
        let count = usize::from(self.u16()?);
        if count > cap {
            return Err(Malformed);
        }
        Ok(count)
    }

    /// A string of at most `cap` bytes, as its length says.
    fn text(&mut self) -> Read<&'a str> {
        let len = usize::from(self.u8()?);
        std::str::from_utf8(self.take(len)?).map_err(|_| Malformed)
    }

    /// A set of MACs: at most `cap`, strictly ascending.
    fn macs(&mut self, cap: usize) -> Read<Vec<Mac>> {
        let count = self.count(cap)?;
        let mut macs: Vec<Mac> = Vec::with_capacity(count);
        for _ in 0..count {
            let mac = Mac(self.array()?);
            if macs.last().is_some_and(|last| *last >= mac) {
                return Err(Malformed);
            }
            macs.push(mac);
        }
        Ok(macs)
    }

    /// The labels, each a valid one.
    fn labels(&mut self) -> Read<Vec<(Mac, Label)>> {
        let count = self.count(MAX_LABELS)?;
        let mut labels = Vec::with_capacity(count);
        for _ in 0..count {
            let mac = Mac(self.array()?);
            labels.push((mac, Label::new(self.text()?).ok_or(Malformed)?));
        }
        Ok(labels)
    }

    /// The names, each already normal, at most [`OWNER_NAMES_MAX`] on each side.
    fn names(&mut self) -> Read<Vec<SavedName>> {
        let count = self.count(MAX_NAMES)?;
        let mut names = Vec::with_capacity(count);
        let (mut allowed, mut refused) = (0, 0);
        let mut buf = [0; MAX_NAME_LEN];
        for _ in 0..count {
            let text = self.text()?;
            if normalize(text.as_bytes(), &mut buf) != Some(text) {
                return Err(Malformed);
            }
            let side = match self.u8()? {
                0 => {
                    allowed += 1;
                    OwnerSide::Allow
                }
                1 => {
                    refused += 1;
                    OwnerSide::Refuse
                }
                _ => return Err(Malformed),
            };
            if allowed > OWNER_NAMES_MAX || refused > OWNER_NAMES_MAX {
                return Err(Malformed);
            }
            let set_unix = match self.u8()? {
                0 if self.u64()? == 0 => None,
                1 => Some(self.u64()?),
                _ => return Err(Malformed),
            };
            names.push(SavedName {
                name: text.into(),
                side,
                set_unix,
            });
        }
        Ok(names)
    }

    /// The PIN: none, or a source and the line of a PIN's hash.
    fn pin(&mut self) -> Read<Option<SavedPin>> {
        let source = match self.u8()? {
            0 => return Ok(None),
            1 => Source::Api,
            2 => Source::Panel,
            _ => return Err(Malformed),
        };
        let hash = parse_pin_hash(self.text()?).ok_or(Malformed)?;
        Ok(Some(SavedPin { source, hash }))
    }

    /// A night: none, or two hours of the day that differ.
    fn hours(&mut self) -> Read<Option<(u8, u8)>> {
        let [flag, from, to] = self.array()?;
        match flag {
            0 if from == 0 && to == 0 => Ok(None),
            1 if from <= 23 && to <= 23 && from != to => Ok(Some((from, to))),
            _ => Err(Malformed),
        }
    }
}

/// The state that `payload` holds, or `None` if it is not one that [`encode_payload`] writes
/// (see the module's rules): never a partial state, and never a panic, whatever the bytes.
pub fn decode_payload(payload: &[u8]) -> Option<Saved> {
    read_saved(payload).ok()
}

/// [`decode_payload`] with the way it fails left out.
fn read_saved(payload: &[u8]) -> Read<Saved> {
    let mut reader = Reader { rest: payload };
    let exempt = reader.macs(MAX_EXEMPT)?;
    let block = reader.macs(MAX_BLOCK)?;
    let exempt_default = match reader.u8()? {
        0 => None,
        1 => Some(false),
        2 => Some(true),
        _ => return Err(Malformed),
    };
    let labels = reader.labels()?;
    let known = reader.macs(MAX_KNOWN)?;
    let names = reader.names()?;
    let pin = reader.pin()?;
    let pin_config = reader.array()?;
    let night = reader.hours()?;
    let night_config = reader.hours()?;
    if !reader.rest.is_empty() {
        return Err(Malformed);
    }
    Ok(Saved {
        devices: SavedDevices {
            exempt,
            block,
            exempt_default,
            labels,
            known,
        },
        names,
        panel: SavedPanel {
            pin,
            pin_config,
            night,
            night_config,
        },
    })
}

/// The frame of `payload` with the sequence `seq`: the header, the payload and the checksum. The
/// payload is at most [`MAX_PAYLOAD`] bytes; a longer one makes a frame that [`read_frame`]
/// refuses (`Store::save` never makes one).
///
/// [`Store::save`]: super::store::Store::save
pub fn frame(seq: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len() + CHECKSUM_LEN);
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(
        &u32::try_from(payload.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(payload);
    let checksum = Sha256::digest(&out);
    out.extend_from_slice(checksum.as_slice());
    out
}

/// The sequence and the payload of the frame at the start of `bytes` (a whole copy, or the frame
/// alone), if its magic, version, length bound and checksum all pass; whatever follows the frame
/// is not looked at. Whether the payload itself decodes is [`decode_payload`]'s to say.
pub fn read_frame(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let (magic, rest) = bytes.split_first_chunk::<8>()?;
    let (version, rest) = rest.split_first_chunk::<4>()?;
    let (length, rest) = rest.split_first_chunk::<4>()?;
    let (seq, rest) = rest.split_first_chunk::<8>()?;
    if *magic != MAGIC || u32::from_le_bytes(*version) != VERSION {
        return None;
    }
    let length = usize::try_from(u32::from_le_bytes(*length))
        .ok()
        .filter(|&length| length <= MAX_PAYLOAD)?;
    let (payload, rest) = rest.split_at_checked(length)?;
    let checksum = rest.get(..CHECKSUM_LEN)?;
    let covered = bytes.get(..HEADER_LEN + length)?;
    (Sha256::digest(covered).as_slice() == checksum).then(|| (u64::from_le_bytes(*seq), payload))
}

/// The version of a frame that starts with this format's magic but is of a version this build does
/// not know, in the first bytes of `bytes` (a whole copy, or the frame alone); `None` for anything
/// else, whatever the rest of the bytes hold, and for a frame of [`VERSION`] itself.
///
/// It is what tells a copy that a newer build wrote (the board was rolled back) from a copy that is
/// merely torn or never written: the first must never be written over, the second may. The
/// checksum is not looked at, since a later version may checksum otherwise.
pub fn foreign_version(bytes: &[u8]) -> Option<u32> {
    let (magic, rest) = bytes.split_first_chunk::<8>()?;
    let (version, _) = rest.split_first_chunk::<4>()?;
    let version = u32::from_le_bytes(*version);
    (*magic == MAGIC && version != VERSION).then_some(version)
}

/// Whether the sequence `a` is newer than `b`, in serial-number order: `a` is ahead of `b` by less
/// than half the counter's range, so that the counter may wrap past `u64::MAX` to 0 and the copy
/// that was written after the wrap is still the newer. Equal sequences are neither newer; two
/// exactly half the range apart are neither either, and a loader prefers copy `a` then.
pub fn newer(a: u64, b: u64) -> bool {
    a.wrapping_sub(b) as i64 > 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::password::PasswordHash;

    /// A well-formed line of a PIN's hash (10,000 rounds) that costs no derivation.
    const PIN_LINE: &str = "$pbkdf2-sha256$i=10000$0123456789abcdef0123456789abcdef$fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    /// The same with the 100,000 rounds of a login password, which a PIN's line never has.
    const LOGIN_LINE: &str = "$pbkdf2-sha256$i=100000$0123456789abcdef0123456789abcdef$fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    fn mac(n: u16) -> Mac {
        let [high, low] = n.to_be_bytes();
        Mac([0x02, 0, 0, 0, high, low])
    }

    fn pin(source: Source, line: &str) -> SavedPin {
        SavedPin {
            source,
            hash: PasswordHash::parse(line).unwrap(),
        }
    }

    /// A state with a little of everything.
    fn some() -> Saved {
        Saved {
            devices: SavedDevices {
                exempt: vec![mac(1), mac(7)],
                block: vec![mac(3)],
                exempt_default: Some(false),
                labels: vec![
                    (mac(9), Label::new("TV").unwrap()),
                    (mac(2), Label::new("Back door cam").unwrap()),
                ],
                known: vec![mac(1), mac(2), mac(3), mac(300)],
            },
            names: vec![
                SavedName {
                    name: "ads.example.org".into(),
                    side: OwnerSide::Refuse,
                    set_unix: Some(1_700_000_000),
                },
                SavedName {
                    name: "ok.example.net".into(),
                    side: OwnerSide::Allow,
                    set_unix: None,
                },
            ],
            panel: SavedPanel {
                pin: Some(pin(Source::Panel, PIN_LINE)),
                pin_config: [7; 32],
                night: Some((22, 6)),
                night_config: Some((23, 7)),
            },
        }
    }

    /// A state with every section at its cap and every name and label at its longest.
    fn full() -> Saved {
        let name = |side: OwnerSide, n: usize| {
            // 253 bytes: three labels of 63 and one of 61, the first one different for each name.
            let first = format!(
                "{}{n:03}{}",
                if side == OwnerSide::Allow { 'a' } else { 'r' },
                "x".repeat(59)
            );
            SavedName {
                name: format!(
                    "{first}.{}.{}.{}",
                    "b".repeat(63),
                    "c".repeat(63),
                    "d".repeat(61)
                )
                .into(),
                side,
                set_unix: Some(u64::MAX - n as u64),
            }
        };
        let names = (0..OWNER_NAMES_MAX)
            .flat_map(|n| [name(OwnerSide::Allow, n), name(OwnerSide::Refuse, n)])
            .collect::<Vec<_>>();
        assert!(names.iter().all(|n| n.name.len() == MAX_NAME_LEN));
        Saved {
            devices: SavedDevices {
                exempt: (0..MAX_EXEMPT as u16).map(mac).collect(),
                block: (100..100 + MAX_BLOCK as u16).map(mac).collect(),
                exempt_default: Some(true),
                labels: (0..MAX_LABELS as u16)
                    .rev()
                    .map(|n| {
                        (
                            mac(n),
                            Label::new(&format!("{n:02}{}", "L".repeat(22))).unwrap(),
                        )
                    })
                    .collect(),
                known: (0..MAX_KNOWN as u16).map(mac).collect(),
            },
            names,
            panel: SavedPanel {
                pin: Some(pin(Source::Api, PIN_LINE)),
                pin_config: [0xff; 32],
                night: Some((23, 0)),
                night_config: Some((0, 23)),
            },
        }
    }

    /// A payload byte by byte, from the bytes of each section, so that a test can say what no
    /// encoder would write. The defaults are the empty state's.
    struct Raw {
        exempt: Vec<u8>,
        block: Vec<u8>,
        mode: u8,
        labels: Vec<u8>,
        known: Vec<u8>,
        names: Vec<u8>,
        panel: Vec<u8>,
    }

    impl Raw {
        fn empty() -> Self {
            let none = vec![0, 0];
            let mut panel = vec![0];
            panel.extend_from_slice(&[0; 32]);
            panel.extend_from_slice(&[0; 6]);
            Raw {
                exempt: none.clone(),
                block: none.clone(),
                mode: 0,
                labels: none.clone(),
                known: none.clone(),
                names: none,
                panel,
            }
        }

        fn bytes(&self) -> Vec<u8> {
            [
                &self.exempt[..],
                &self.block,
                &[self.mode],
                &self.labels,
                &self.known,
                &self.names,
                &self.panel,
            ]
            .concat()
        }
    }

    /// A section of `count` MACs as a section says them, in ascending order.
    fn macs_section(count: u16) -> Vec<u8> {
        let mut section = count.to_le_bytes().to_vec();
        for n in 0..count {
            section.extend_from_slice(&mac(n).0);
        }
        section
    }

    /// One name entry: its text, its side byte, its day flag and its day.
    fn name_entry(text: &str, side: u8, flag: u8, day: u64) -> Vec<u8> {
        let mut entry = vec![u8::try_from(text.len()).unwrap()];
        entry.extend_from_slice(text.as_bytes());
        entry.push(side);
        entry.push(flag);
        entry.extend_from_slice(&day.to_le_bytes());
        entry
    }

    /// A names section of the entries, with their count.
    fn names_section(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut section = u16::try_from(entries.len()).unwrap().to_le_bytes().to_vec();
        section.extend(entries.iter().flatten());
        section
    }

    #[test]
    fn the_bound_and_the_file_are_what_the_caps_say() {
        // The longest line a PIN can have is the line of a PIN of 10,000 rounds, and the line of
        // a login password (100,000 rounds, a digit more) is longer, which the decoder refuses.
        assert_eq!(PIN_LINE_MAX, PIN_LINE.len());
        assert!(PasswordHash::parse(LOGIN_LINE).unwrap().to_text().len() > PIN_LINE_MAX);
        let longest = HEADER_LEN + MAX_PAYLOAD + CHECKSUM_LEN;
        assert_eq!(FILE_SIZE, longest.div_ceil(4096) * 4096);
    }

    #[test]
    fn the_empty_state_round_trips_and_is_what_the_raw_empty_payload_says() {
        let payload = encode_payload(&Saved::default()).unwrap();
        assert_eq!(payload, Raw::empty().bytes());
        assert_eq!(decode_payload(&payload), Some(Saved::default()));
    }

    #[test]
    fn a_state_with_a_little_of_everything_round_trips() {
        let saved = some();
        let payload = encode_payload(&saved).unwrap();
        let back = decode_payload(&payload).unwrap();
        // The sets come back sorted, which they were; the labels and the names in their order.
        assert_eq!(back, saved);
        assert_eq!(encode_payload(&back).unwrap(), payload);
    }

    #[test]
    fn the_fullest_state_round_trips_and_is_exactly_the_bound_and_fits_the_file() {
        let saved = full();
        let payload = encode_payload(&saved).unwrap();
        assert_eq!(
            payload.len(),
            MAX_PAYLOAD,
            "the bound is what the largest state needs"
        );
        assert_eq!(decode_payload(&payload), Some(saved));
        let frame = frame(u64::MAX, &payload);
        assert_eq!(frame.len(), HEADER_LEN + MAX_PAYLOAD + CHECKSUM_LEN);
        assert!(frame.len().next_multiple_of(512) <= FILE_SIZE);
        let mut file = vec![0x5a; FILE_SIZE];
        file[..frame.len()].copy_from_slice(&frame);
        let (seq, body) = read_frame(&file).unwrap();
        assert_eq!((seq, body), (u64::MAX, &payload[..]));
    }

    #[test]
    fn the_layout_is_the_documented_one() {
        let saved = Saved {
            devices: SavedDevices {
                exempt: vec![Mac([2, 0, 0, 0, 0, 1])],
                block: vec![],
                exempt_default: Some(true),
                labels: vec![(Mac([2, 0, 0, 0, 0, 2]), Label::new("tv").unwrap())],
                known: vec![],
            },
            names: vec![SavedName {
                name: "a.example.org".into(),
                side: OwnerSide::Refuse,
                set_unix: Some(7),
            }],
            panel: SavedPanel {
                pin: None,
                pin_config: [9; 32],
                night: Some((23, 7)),
                night_config: None,
            },
        };
        let mut want: Vec<u8> = vec![1, 0, 2, 0, 0, 0, 0, 1];
        want.extend([0, 0]); // no block list
        want.push(2); // the exempt-by-default mode
        want.extend([1, 0, 2, 0, 0, 0, 0, 2, 2, b't', b'v']);
        want.extend([0, 0]); // no known set
        want.extend([1, 0, 13]);
        want.extend(b"a.example.org");
        want.extend([1, 1, 7, 0, 0, 0, 0, 0, 0, 0]);
        want.push(0); // no PIN
        want.extend([9; 32]);
        want.extend([1, 23, 7]);
        want.extend([0, 0, 0]);
        assert_eq!(encode_payload(&saved).unwrap(), want);
        assert_eq!(decode_payload(&want), Some(saved));
    }

    #[test]
    fn the_same_state_is_the_same_bytes_whatever_order_the_sets_come_in() {
        let saved = some();
        let mut shuffled = saved.clone();
        shuffled.devices.exempt.reverse();
        shuffled.devices.known = vec![mac(300), mac(2), mac(3), mac(1), mac(2)];
        assert_eq!(encode_payload(&shuffled), encode_payload(&saved));
        assert_eq!(encode_payload(&saved), encode_payload(&saved.clone()));
        // The labels and the names are in their own order, which is part of the state.
        let mut reordered = saved.clone();
        reordered.devices.labels.reverse();
        assert_ne!(encode_payload(&reordered), encode_payload(&saved));
        let mut reordered = saved.clone();
        reordered.names.reverse();
        assert_ne!(encode_payload(&reordered), encode_payload(&saved));
    }

    #[test]
    fn a_state_past_a_cap_is_oversize_and_never_cut() {
        let ok = full();
        assert!(encode_payload(&ok).is_ok());

        let mut bad = ok.clone();
        bad.names.push(SavedName {
            name: "one-more.example.org".into(),
            side: OwnerSide::Allow,
            set_unix: None,
        });
        assert_eq!(encode_payload(&bad), Err(Oversize));

        let mut bad = ok.clone();
        bad.devices.exempt.push(mac(5_000));
        assert_eq!(encode_payload(&bad), Err(Oversize));
        let mut bad = ok.clone();
        bad.devices.block.push(mac(5_000));
        assert_eq!(encode_payload(&bad), Err(Oversize));
        let mut bad = ok.clone();
        bad.devices.known.push(mac(5_000));
        assert_eq!(encode_payload(&bad), Err(Oversize));
        let mut bad = ok.clone();
        bad.devices
            .labels
            .push((mac(5_000), Label::new("one more").unwrap()));
        assert_eq!(encode_payload(&bad), Err(Oversize));

        let mut bad = ok.clone();
        bad.names[0].name = "x".repeat(MAX_NAME_LEN + 1).into();
        assert_eq!(encode_payload(&bad), Err(Oversize));
    }

    #[test]
    fn a_state_that_no_payload_may_hold_is_refused_too() {
        let mut bad = some();
        bad.panel.pin = Some(pin(Source::Config, PIN_LINE));
        assert_eq!(encode_payload(&bad), Err(Oversize));
        bad.panel.pin = Some(pin(Source::Api, LOGIN_LINE));
        assert_eq!(encode_payload(&bad), Err(Oversize));
        for hours in [(24, 1), (1, 24), (5, 5)] {
            let mut bad = some();
            bad.panel.night = Some(hours);
            assert_eq!(encode_payload(&bad), Err(Oversize), "{hours:?}");
            let mut bad = some();
            bad.panel.night_config = Some(hours);
            assert_eq!(encode_payload(&bad), Err(Oversize), "{hours:?}");
        }
    }

    #[test]
    fn a_frame_carries_its_sequence_and_payload_and_a_tail_is_not_looked_at() {
        let payload = encode_payload(&some()).unwrap();
        let framed = frame(12, &payload);
        assert_eq!(&framed[..8], b"QBPSTATE");
        assert_eq!(framed[8..12], 1u32.to_le_bytes());
        assert_eq!(
            framed[12..16],
            u32::try_from(payload.len()).unwrap().to_le_bytes()
        );
        assert_eq!(framed[16..24], 12u64.to_le_bytes());
        assert_eq!(&framed[24..24 + payload.len()], &payload[..]);
        assert_eq!(
            &framed[24 + payload.len()..],
            Sha256::digest(&framed[..24 + payload.len()]).as_slice()
        );
        assert_eq!(read_frame(&framed), Some((12, &payload[..])));
        let mut file = framed.clone();
        file.resize(FILE_SIZE, 0xa5);
        assert_eq!(read_frame(&file), Some((12, &payload[..])));
    }

    #[test]
    fn every_single_byte_corruption_of_a_frame_is_refused() {
        let payload = encode_payload(&some()).unwrap();
        let good = frame(41, &payload);
        assert!(read_frame(&good).is_some());
        for offset in 0..good.len() {
            for mask in [0x01, 0x80, 0xff] {
                let mut bad = good.clone();
                bad[offset] ^= mask;
                assert!(read_frame(&bad).is_none(), "byte {offset} ^ {mask:#x}");
            }
        }
        // The fullest frame too, at a spread of offsets (each one hashes 77 KB).
        let big = frame(1, &encode_payload(&full()).unwrap());
        for offset in (0..big.len())
            .step_by(997)
            .chain([0, 23, 24, big.len() - 1])
        {
            let mut bad = big.clone();
            bad[offset] ^= 0x10;
            assert!(read_frame(&bad).is_none(), "byte {offset}");
        }
    }

    #[test]
    fn a_frame_cut_short_is_refused_at_every_length() {
        let good = frame(3, &encode_payload(&some()).unwrap());
        for len in 0..good.len() {
            assert!(read_frame(&good[..len]).is_none(), "{len} bytes");
        }
    }

    /// A frame with a header of the test's own making and a checksum that is right for it, so that
    /// only the rule that is being tested can refuse it.
    fn forged(magic: &[u8; 8], version: u32, length: u32, seq: u64, payload: &[u8]) -> Vec<u8> {
        let mut out = magic.to_vec();
        out.extend_from_slice(&version.to_le_bytes());
        out.extend_from_slice(&length.to_le_bytes());
        out.extend_from_slice(&seq.to_le_bytes());
        out.extend_from_slice(payload);
        let checksum = Sha256::digest(&out);
        out.extend_from_slice(checksum.as_slice());
        out
    }

    #[test]
    fn the_magic_the_version_and_the_length_bound_are_checked_beside_the_checksum() {
        let payload = encode_payload(&some()).unwrap();
        let len = u32::try_from(payload.len()).unwrap();
        assert!(read_frame(&forged(b"QBPSTATE", 1, len, 9, &payload)).is_some());
        assert!(read_frame(&forged(b"QBPSTATF", 1, len, 9, &payload)).is_none());
        assert!(read_frame(&forged(b"QBPSTATE", 0, len, 9, &payload)).is_none());
        assert!(read_frame(&forged(b"QBPSTATE", 2, len, 9, &payload)).is_none());
        // A length that is not the payload's has the checksum in the wrong place.
        assert!(read_frame(&forged(b"QBPSTATE", 1, len - 1, 9, &payload)).is_none());
        // One past the bound, whole and with a good checksum, is still refused.
        let long = vec![0; MAX_PAYLOAD + 1];
        let over = u32::try_from(long.len()).unwrap();
        assert!(read_frame(&forged(b"QBPSTATE", 1, over, 9, &long)).is_none());
        let longest = vec![0; MAX_PAYLOAD];
        let at = u32::try_from(longest.len()).unwrap();
        assert!(read_frame(&forged(b"QBPSTATE", 1, at, 9, &longest)).is_some());
        assert!(read_frame(&forged(b"QBPSTATE", 1, u32::MAX, 9, &payload)).is_none());
    }

    #[test]
    fn a_frame_of_a_version_this_build_does_not_know_is_told_from_one_that_is_merely_not_whole() {
        let payload = encode_payload(&some()).unwrap();
        let len = u32::try_from(payload.len()).unwrap();
        // The right magic with another version, whatever the rest holds (a later build may checksum
        // or lay out as it likes): that is a later build's copy.
        for version in [0, 2, 3, u32::MAX] {
            let frame = forged(b"QBPSTATE", version, len, 9, &payload);
            assert_eq!(foreign_version(&frame), Some(version), "version {version}");
            assert!(read_frame(&frame).is_none(), "this build does not read it");
            let mut cut = frame[..12].to_vec();
            cut.extend_from_slice(b"junk");
            assert_eq!(
                foreign_version(&cut),
                Some(version),
                "no checksum is needed"
            );
            assert_eq!(
                foreign_version(&frame[..12]),
                Some(version),
                "just the header"
            );
        }
        // This build's own frames, torn frames of its own version, other magics, the fills, short
        // and empty bytes are not.
        assert_eq!(
            foreign_version(&forged(b"QBPSTATE", 1, len, 9, &payload)),
            None
        );
        assert_eq!(
            foreign_version(&forged(b"QBPSTATE", 1, 7, 9, b"torn")),
            None
        );
        assert_eq!(
            foreign_version(&forged(b"QBPSTATF", 2, len, 9, &payload)),
            None
        );
        assert_eq!(foreign_version(&vec![0; FILE_SIZE]), None);
        assert_eq!(foreign_version(&vec![0xff; FILE_SIZE]), None);
        assert_eq!(
            foreign_version(&b"QBPSTATE\x02\x00\x00"[..]),
            None,
            "11 bytes"
        );
        assert_eq!(foreign_version(&[]), None);
        // The frames of this build are never taken for a foreign one.
        assert_eq!(foreign_version(&frame(5, &payload)), None);
    }

    #[test]
    fn a_frame_is_never_valid_when_it_is_all_zeros_or_all_ones() {
        assert!(read_frame(&vec![0; FILE_SIZE]).is_none());
        assert!(read_frame(&vec![0xff; FILE_SIZE]).is_none());
        assert!(read_frame(&[]).is_none());
    }

    #[test]
    fn a_payload_with_trailing_bytes_or_cut_short_is_refused() {
        let payload = encode_payload(&some()).unwrap();
        let mut long = payload.clone();
        long.push(0);
        assert_eq!(decode_payload(&long), None);
        for len in 0..payload.len() {
            assert_eq!(decode_payload(&payload[..len]), None, "{len} bytes");
        }
        assert!(decode_payload(&payload).is_some());
    }

    #[test]
    fn a_count_over_its_cap_is_refused() {
        fn cap(put: impl Fn(&mut Raw, Vec<u8>), cap: usize) {
            let mut ok = Raw::empty();
            put(&mut ok, macs_section(u16::try_from(cap).unwrap()));
            assert!(decode_payload(&ok.bytes()).is_some(), "{cap} fits");
            let mut over = Raw::empty();
            put(&mut over, macs_section(u16::try_from(cap + 1).unwrap()));
            assert_eq!(decode_payload(&over.bytes()), None, "{} does not", cap + 1);
        }
        cap(|raw, section| raw.exempt = section, MAX_EXEMPT);
        cap(|raw, section| raw.block = section, MAX_BLOCK);
        cap(|raw, section| raw.known = section, MAX_KNOWN);

        // Labels and names, with their counts claiming more than there are bytes for.
        let mut raw = Raw::empty();
        raw.labels = u16::try_from(MAX_LABELS + 1)
            .unwrap()
            .to_le_bytes()
            .to_vec();
        assert_eq!(decode_payload(&raw.bytes()), None);
        let mut raw = Raw::empty();
        raw.names = u16::try_from(MAX_NAMES + 1).unwrap().to_le_bytes().to_vec();
        assert_eq!(decode_payload(&raw.bytes()), None);

        // One side may hold 128 names, not 129, though the two together are within 256.
        let entries = |allow: usize, refuse: usize| {
            let mut entries = Vec::new();
            for n in 0..allow {
                entries.push(name_entry(&format!("a{n}.example.org"), 0, 0, 0));
            }
            for n in 0..refuse {
                entries.push(name_entry(&format!("r{n}.example.org"), 1, 0, 0));
            }
            names_section(&entries)
        };
        let mut raw = Raw::empty();
        raw.names = entries(OWNER_NAMES_MAX, OWNER_NAMES_MAX);
        assert!(decode_payload(&raw.bytes()).is_some());
        raw.names = entries(OWNER_NAMES_MAX + 1, 1);
        assert_eq!(decode_payload(&raw.bytes()), None);
        raw.names = entries(1, OWNER_NAMES_MAX + 1);
        assert_eq!(decode_payload(&raw.bytes()), None);
    }

    #[test]
    fn a_mac_set_must_be_strictly_ascending() {
        let set = |macs: &[Mac]| {
            let mut section = u16::try_from(macs.len()).unwrap().to_le_bytes().to_vec();
            for mac in macs {
                section.extend_from_slice(&mac.0);
            }
            let mut raw = Raw::empty();
            raw.known = section;
            decode_payload(&raw.bytes())
        };
        assert!(set(&[mac(1), mac(2)]).is_some());
        assert!(set(&[mac(2), mac(1)]).is_none());
        assert!(set(&[mac(1), mac(1)]).is_none());
    }

    #[test]
    fn a_bad_label_is_refused() {
        let label = |text: &[u8]| {
            let mut section = vec![1, 0];
            section.extend_from_slice(&mac(1).0);
            section.push(u8::try_from(text.len()).unwrap());
            section.extend_from_slice(text);
            let mut raw = Raw::empty();
            raw.labels = section;
            decode_payload(&raw.bytes())
        };
        assert!(label(b"Kitchen TV").is_some());
        assert!(label(&[b'x'; LABEL_MAX]).is_some());
        assert!(label(b"").is_none());
        assert!(label(&[b'x'; LABEL_MAX + 1]).is_none());
        assert!(label(b"tab\there").is_none());
        assert!(label("caf\u{e9}".as_bytes()).is_none());
        assert!(label(&[0xff, 0xfe]).is_none());
    }

    #[test]
    fn a_name_that_is_not_normal_is_refused() {
        let name = |text: &str, side: u8, flag: u8, day: u64| {
            let mut raw = Raw::empty();
            raw.names = names_section(&[name_entry(text, side, flag, day)]);
            decode_payload(&raw.bytes())
        };
        assert!(name("ads.example.org", 1, 1, 5).is_some());
        assert!(name("ads.example.org", 0, 0, 0).is_some());
        assert!(name("Ads.Example.org", 1, 0, 0).is_none(), "upper case");
        assert!(
            name("ads.example.org.", 1, 0, 0).is_none(),
            "a trailing dot"
        );
        assert!(name("", 1, 0, 0).is_none(), "empty");
        assert!(name("a..b", 1, 0, 0).is_none());
        assert!(name("192.0.2.1", 1, 0, 0).is_none(), "an address");
        assert!(name("exa mple.org", 1, 0, 0).is_none());
        assert!(name(&"a".repeat(MAX_NAME_LEN + 1), 1, 0, 0).is_none());
        // Side, flag and filler: each in its own set of values only.
        assert!(name("ads.example.org", 2, 0, 0).is_none(), "side 2");
        assert!(name("ads.example.org", 1, 2, 0).is_none(), "flag 2");
        assert!(
            name("ads.example.org", 1, 0, 9).is_none(),
            "a day under no flag"
        );
    }

    #[test]
    fn a_pin_line_of_other_rounds_or_of_no_hash_is_refused() {
        let pin_section = |flag: u8, line: &[u8]| {
            let mut raw = Raw::empty();
            let mut panel = vec![flag];
            if flag != 0 {
                panel.push(u8::try_from(line.len()).unwrap());
                panel.extend_from_slice(line);
            }
            panel.extend_from_slice(&[0; 32 + 6]);
            raw.panel = panel;
            decode_payload(&raw.bytes())
        };
        let got = pin_section(1, PIN_LINE.as_bytes()).unwrap();
        assert_eq!(got.panel.pin, Some(pin(Source::Api, PIN_LINE)));
        assert_eq!(
            pin_section(2, PIN_LINE.as_bytes()).unwrap().panel.pin,
            Some(pin(Source::Panel, PIN_LINE))
        );
        assert!(pin_section(0, b"").unwrap().panel.pin.is_none());
        assert!(
            pin_section(1, LOGIN_LINE.as_bytes()).is_none(),
            "100,000 rounds"
        );
        assert!(pin_section(3, PIN_LINE.as_bytes()).is_none(), "source 3");
        assert!(pin_section(1, b"").is_none());
        assert!(pin_section(1, b"not a hash").is_none());
        assert!(pin_section(1, PIN_LINE.to_uppercase().as_bytes()).is_none());
        assert!(pin_section(1, &PIN_LINE.as_bytes()[1..]).is_none());
    }

    #[test]
    fn hours_must_be_hours_of_the_day_that_differ() {
        let hours = |flag: u8, from: u8, to: u8| {
            let mut raw = Raw::empty();
            let mut panel = vec![0];
            panel.extend_from_slice(&[0; 32]);
            panel.extend_from_slice(&[flag, from, to, 0, 0, 0]);
            raw.panel = panel;
            let night = decode_payload(&raw.bytes());
            // The configuration's night is held to the same rule.
            let mut panel = vec![0];
            panel.extend_from_slice(&[0; 32]);
            panel.extend_from_slice(&[0, 0, 0, flag, from, to]);
            raw.panel = panel;
            assert_eq!(night.is_some(), decode_payload(&raw.bytes()).is_some());
            night
        };
        assert_eq!(hours(1, 23, 7).unwrap().panel.night, Some((23, 7)));
        assert_eq!(hours(1, 0, 23).unwrap().panel.night, Some((0, 23)));
        assert!(hours(0, 0, 0).unwrap().panel.night.is_none());
        assert!(hours(1, 24, 7).is_none(), "hour 24");
        assert!(hours(1, 7, 24).is_none(), "hour 24");
        assert!(hours(1, 6, 6).is_none(), "equal hours");
        assert!(hours(2, 1, 2).is_none(), "flag 2");
        assert!(hours(0, 1, 0).is_none(), "an hour under no flag");
    }

    #[test]
    fn the_mode_flag_has_three_values() {
        for (flag, want) in [
            (0, Some(None)),
            (1, Some(Some(false))),
            (2, Some(Some(true))),
            (3, None),
        ] {
            let mut raw = Raw::empty();
            raw.mode = flag;
            assert_eq!(
                decode_payload(&raw.bytes()).map(|saved| saved.devices.exempt_default),
                want,
                "flag {flag}"
            );
        }
    }

    #[test]
    fn no_bytes_make_the_decoder_panic_and_whatever_it_takes_it_writes_again() {
        // A small deterministic generator: bytes made of valid payloads with one byte changed, and
        // of noise, which is never a whole state but must never panic either.
        let seeds = [
            encode_payload(&some()).unwrap(),
            encode_payload(&Saved::default()).unwrap(),
        ];
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut accepted = 0;
        for round in 0..4_000 {
            let mut bytes = seeds[round % 2].clone();
            let at = usize::try_from(next() % bytes.len() as u64).unwrap();
            bytes[at] = next().to_le_bytes()[0];
            if round % 5 == 0 {
                bytes.truncate(usize::try_from(next() % 40).unwrap());
            }
            if let Some(saved) = decode_payload(&bytes) {
                assert_eq!(encode_payload(&saved).unwrap(), bytes, "canonical");
                accepted += 1;
            }
        }
        assert!(
            accepted > 0,
            "no mutation was ever accepted: the check ran on nothing"
        );
    }

    #[test]
    fn the_serial_order_of_sequences_wraps() {
        assert!(newer(1, 0));
        assert!(!newer(0, 1));
        assert!(!newer(5, 5));
        assert!(newer(0, u64::MAX), "after the wrap");
        assert!(!newer(u64::MAX, 0));
        assert!(newer(3, u64::MAX - 3));
        let half = 1u64 << 63;
        assert!(newer(half - 1, 0));
        assert!(
            !newer(half, 0) && !newer(0, half),
            "half the range apart is neither"
        );
        assert!(newer(u64::MAX, u64::MAX - 1));
    }
}
