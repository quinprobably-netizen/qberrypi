//! The owner's settings that outlast a restart: what is kept, the frame it is written in, the two
//! copies it lives in and the timing of a save. Nothing here reads a card, a socket or a clock of
//! its own: the card and the saver that use it come after, and this is the part that can be proved
//! on a host.
//!
//! **What is kept** is [`Saved`]: the pushed exempt and block lists, the pushed mode, the labels and
//! the known set of the device inventory, the owner's names, the PIN when the owner set it (from
//! the desktop or the panel) and the night hours. With the PIN and the night go what the
//! configuration said when they were saved, as a fingerprint of its `pin_hash` ([`pin_fingerprint`])
//! and its night, so that a start whose configuration has changed since can tell, and take the
//! file's word over the card's. **Never kept**: the main pause, the per-device gates, the staged
//! chunks of a push, alerts and acknowledgements, counters, the devices heard, anything about
//! lookups.
//!
//! **The frame** ([`format`]) is a magic, a version, a payload length, a sequence number, the
//! payload and a SHA-256 of all of them. The payload is a hand-made, deterministic encoding: the
//! same state is always the same bytes, so "did it change" is a byte comparison. A frame is whole
//! when its magic, version, length bound, checksum and the payload's own decoding all pass; the
//! decoder checks every count against its cap and every item against the rule of its owner (a
//! label as [`Label::new`](crate::watch::devices::Label::new), a name as
//! [`qb_dns::name::normalize`], a PIN as [`parse_pin_hash`](crate::panel::lock::parse_pin_hash)).
//! [`format::MAX_PAYLOAD`] is computed from the caps, so a state that fits its caps always fits
//! [`format::FILE_SIZE`], and an encoder that would exceed it says so ([`format::Oversize`]) rather
//! than truncate.
//!
//! **The two copies** ([`store`]) are written one at a time, always the one that is not the newest
//! whole one, with a sequence one past the newest's. A power cut tears at most the copy being
//! written, which then fails its checksum, and the other holds the state before it. At a start the
//! whole copy with the highest sequence (in serial-number order, so that the counter may wrap)
//! wins.
//!
//! **The timing** ([`debounce`]) is when a changed state is worth a write: after it has been
//! unchanged for 30 seconds, and not more than once a minute.
//!
//! **The card** ([`card`]) is where the two copies lie: two files in a folder of their own on the
//! boot partition, made once through a writable mount and from then on only ever written in
//! place, through the raw partition device, never through a mount. **The saver** ([`saver`])
//! looks at the state every few seconds and, when the timing says so, hands the encoding to the
//! card.
//!
//! The kept state is the owner's, so nothing here logs or prints a MAC, a label, a name or a hash:
//! every `Debug` says how many, and the log lines of whoever uses this say counts and copy letters
//! only.

use std::fmt;

use qb_dns::OwnerSide;
use sha2::{Digest, Sha256};

use crate::api::password::PasswordHash;
use crate::panel::lock::Source;
use crate::watch::devices::Label;
use crate::watch::frames::Mac;

pub mod card;
pub mod debounce;
pub mod format;
pub mod saver;
pub mod store;

/// Everything that is kept, as the structures give it and take it back.
///
/// `Default` is the empty state, the one of a card that has never been written: no lists, no
/// names, no PIN, no night, and a configuration fingerprint of zeros. It prints counts only.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Saved {
    /// The device inventory's share.
    pub devices: SavedDevices,
    /// The owner's names, in the order they were set.
    pub names: Vec<SavedName>,
    /// The lock and the night hours.
    pub panel: SavedPanel,
}

impl fmt::Debug for Saved {
    /// The counts only: everything in here is the owner's.
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("Saved")
            .field("devices", &self.devices)
            .field("names", &self.names.len())
            .field("panel", &self.panel)
            .finish()
    }
}

/// What the device inventory keeps: the lists the desktop or the panel pushed, the pushed mode,
/// the labels and the known set.
///
/// The three sets are sorted and each MAC is in them once ([`format::encode_payload`] makes them
/// so before it writes, whatever order they come in). It prints counts only.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SavedDevices {
    /// The pushed exempt list, at most [`MAX_EXEMPT`](crate::watch::devices::MAX_EXEMPT).
    pub exempt: Vec<Mac>,
    /// The pushed block list, at most [`MAX_BLOCK`](crate::watch::devices::MAX_BLOCK).
    pub block: Vec<Mac>,
    /// The pushed mode: `None` while no policy has been pushed, else whether the exempt-by-default
    /// mode is in force.
    pub exempt_default: Option<bool>,
    /// The labels, in the desktop's order, at most
    /// [`MAX_LABELS`](crate::watch::devices::MAX_LABELS).
    pub labels: Vec<(Mac, Label)>,
    /// The known set, at most [`MAX_KNOWN`](crate::watch::devices::MAX_KNOWN).
    pub known: Vec<Mac>,
}

impl fmt::Debug for SavedDevices {
    /// The counts and the mode: the addresses and the labels are the owner's.
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("SavedDevices")
            .field("exempt", &self.exempt.len())
            .field("block", &self.block.len())
            .field("exempt_default", &self.exempt_default)
            .field("labels", &self.labels.len())
            .field("known", &self.known.len())
            .finish()
    }
}

/// One of the owner's names, with the side it is on and the day it was set from the panel.
#[derive(Clone, PartialEq, Eq)]
pub struct SavedName {
    /// The name, already normal (lower case, no trailing dot).
    pub name: Box<str>,
    /// The list the name is on.
    pub side: OwnerSide,
    /// The Unix time at which the owner set it from the panel; `None` for one that was pushed.
    pub set_unix: Option<u64>,
}

impl fmt::Debug for SavedName {
    /// The side and the day only: the name is the owner's.
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("SavedName")
            .field("side", &self.side)
            .field("set_unix", &self.set_unix)
            .finish_non_exhaustive()
    }
}

/// What the panel's state keeps: the PIN the owner set, the night hours, and what the
/// configuration said of both when they were saved.
///
/// At a start a saved PIN is put back only if the configuration's `pin_hash` is still the one it
/// was saved under (`pin_config`, from [`pin_fingerprint`]), and the saved night only if the
/// configuration's night is still `night_config`: an owner who changes the file and updates gets
/// the file's. A PIN from the configuration, a lock turned off and the count of wrong PINs are not
/// kept. `Default` has no PIN, no night, no configuration PIN (zeros) and no configuration night.
/// It prints no hash.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SavedPanel {
    /// The PIN the owner set from the desktop or the panel, if the lock was on with one.
    pub pin: Option<SavedPin>,
    /// The fingerprint of the configuration's `pin_hash` at the time ([`pin_fingerprint`]): zeros
    /// when it had none.
    pub pin_config: [u8; 32],
    /// The night hours `(from, to)` in force, or `None` for no night. Hours of the day, 0 to 23,
    /// and different.
    pub night: Option<(u8, u8)>,
    /// The configuration's night at the time, as `night` is.
    pub night_config: Option<(u8, u8)>,
}

impl fmt::Debug for SavedPanel {
    /// Where the PIN came from, if there is one, and the hours: never a hash or a fingerprint.
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("SavedPanel")
            .field("pin", &self.pin.as_ref().map(|pin| pin.source))
            .field("night", &self.night)
            .field("night_config", &self.night_config)
            .finish_non_exhaustive()
    }
}

/// A PIN the owner set, with where it came from.
///
/// The hash is the panel's own: [`format::encode_payload`] writes only a PIN whose source is
/// [`Source::Api`] or [`Source::Panel`] and whose rounds are the PIN's, and refuses any other. Its
/// `Debug` shows the source and no hash.
#[derive(Clone)]
pub struct SavedPin {
    /// Where the PIN came from: `Api` or `Panel`, never `Config`.
    pub source: Source,
    /// The PIN's hash.
    pub hash: PasswordHash,
}

impl PartialEq for SavedPin {
    /// The same source and the same line of text. Not constant-time: it compares what a copy of the
    /// state holds, never what someone typed.
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source && self.hash.to_text() == other.hash.to_text()
    }
}

impl Eq for SavedPin {}

impl fmt::Debug for SavedPin {
    /// The source only: the hash is a secret.
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("SavedPin")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

/// What a copy holds of the configuration's PIN: the SHA-256 of the text of its hash
/// ([`PasswordHash::to_text`]), or 32 zero bytes for none. The same hash always gives the same
/// fingerprint, and a different one a different fingerprint, so that a start can tell whether the
/// configuration's PIN is the one a saved PIN was set under without keeping that hash twice.
pub fn pin_fingerprint(hash: Option<&PasswordHash>) -> [u8; 32] {
    hash.map_or([0; 32], |hash| {
        Sha256::digest(hash.to_text().as_bytes()).into()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-formed line of a PIN's hash (10,000 rounds) that costs no derivation.
    const PIN_LINE: &str = "$pbkdf2-sha256$i=10000$0123456789abcdef0123456789abcdef$fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    /// Another one, with another salt and hash.
    const OTHER_LINE: &str = "$pbkdf2-sha256$i=10000$00112233445566778899aabbccddeeff$ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

    fn pin(line: &str) -> PasswordHash {
        PasswordHash::parse(line).unwrap()
    }

    #[test]
    fn the_fingerprint_of_no_pin_is_zeros_and_of_a_pin_is_the_hash_of_its_text() {
        assert_eq!(pin_fingerprint(None), [0; 32]);
        let one = pin_fingerprint(Some(&pin(PIN_LINE)));
        assert_eq!(one, <[u8; 32]>::from(Sha256::digest(PIN_LINE.as_bytes())));
        assert_ne!(one, [0; 32]);
        assert_eq!(one, pin_fingerprint(Some(&pin(PIN_LINE))));
        assert_ne!(one, pin_fingerprint(Some(&pin(OTHER_LINE))));
    }

    #[test]
    fn the_default_state_is_empty_and_has_no_configuration_pin() {
        let empty = Saved::default();
        assert!(empty.devices.exempt.is_empty() && empty.devices.block.is_empty());
        assert!(empty.devices.labels.is_empty() && empty.devices.known.is_empty());
        assert_eq!(empty.devices.exempt_default, None);
        assert!(empty.names.is_empty());
        assert!(empty.panel.pin.is_none() && empty.panel.night.is_none());
        assert_eq!(empty.panel.pin_config, pin_fingerprint(None));
        assert_eq!(empty.panel.night_config, None);
    }

    #[test]
    fn a_pin_is_equal_to_another_of_the_same_source_and_hash_only() {
        let api = SavedPin {
            source: Source::Api,
            hash: pin(PIN_LINE),
        };
        assert_eq!(api, api.clone());
        let panel = SavedPin {
            source: Source::Panel,
            hash: pin(PIN_LINE),
        };
        assert_ne!(api, panel);
        let other = SavedPin {
            source: Source::Api,
            hash: pin(OTHER_LINE),
        };
        assert_ne!(api, other);
    }

    #[test]
    fn nothing_that_is_kept_prints_a_mac_a_label_a_name_or_a_hash() {
        let mac = Mac([0x02, 0, 0, 0, 0x5a, 0x7c]);
        let saved = Saved {
            devices: SavedDevices {
                exempt: vec![mac],
                block: vec![mac],
                exempt_default: Some(true),
                labels: vec![(mac, Label::new("Kitchen Tablet").unwrap())],
                known: vec![mac, Mac([0x02, 0, 0, 0, 0, 1])],
            },
            names: vec![SavedName {
                name: "secret-host.example.org".into(),
                side: OwnerSide::Refuse,
                set_unix: Some(1_700_000_000),
            }],
            panel: SavedPanel {
                pin: Some(SavedPin {
                    source: Source::Panel,
                    hash: pin(PIN_LINE),
                }),
                pin_config: pin_fingerprint(Some(&pin(OTHER_LINE))),
                night: Some((22, 6)),
                night_config: Some((23, 7)),
            },
        };
        let text = format!("{saved:?} {:?} {:?}", saved.names[0], saved.panel.pin);
        for secret in [
            "Kitchen",
            "Tablet",
            "secret-host",
            "example.org",
            "5a",
            "7c",
            "0123456789abcdef",
            "pbkdf2",
            "fedcba",
        ] {
            assert!(!text.contains(secret), "{secret} in {text}");
        }
        assert!(
            text.contains("exempt: 1") && text.contains("known: 2"),
            "{text}"
        );
        assert!(
            text.contains("names: 1") && text.contains("labels: 1"),
            "{text}"
        );
    }
}
