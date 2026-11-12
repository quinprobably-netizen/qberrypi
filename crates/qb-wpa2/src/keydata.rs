//! Key data: the field of message 3 and of group message 1 that carries the
//! group key and the access point's RSN element (IEEE Std 802.11-2016 12.7.2),
//! wrapped under the KEK with the AES key wrap of RFC 3394.
//!
//! The wrapped bytes come from any radio in range and the unwrapped ones from
//! whoever holds the KEK. Neither function here panics on any input, and no
//! error repeats a byte of what it refused.

use std::fmt;

use aes_kw::{KeyInit, KwAes128};
use zeroize::Zeroizing;

use crate::secret::SecretBytes;

/// The length in bytes of the key encryption key.
const KEK_LEN: usize = 16;

/// The length in bytes of a CCMP group key.
const GTK_LEN: usize = 16;

/// The unit of the AES key wrap, half an AES block: wrapping lengthens its input by one, the integrity check value.
const SEMIBLOCK_LEN: usize = 8;

/// The shortest plaintext RFC 3394 defines the key wrap for: two semiblocks.
const MIN_PLAIN_LEN: usize = 2 * SEMIBLOCK_LEN;

/// The length in bytes of the header of an element: its id and the length of its data.
const ELEMENT_HEADER_LEN: usize = 2;

/// The element id of the RSN element.
const ID_RSNE: u8 = 0x30;

/// The element id of the RSN extension element (RSNXE).
const ID_RSNXE: u8 = 0xf4;

/// The element id of vendor-specific elements, which the key data encapsulations (KDEs) and the padding share.
const ID_VENDOR: u8 = 0xdd;

/// What the data of a GTK KDE starts with: the OUI 00-0F-AC and data type 1 (IEEE Std 802.11-2016 Table 12-6).
const GTK_KDE_SELECTOR: [u8; 4] = [0x00, 0x0f, 0xac, 0x01];

/// The bits of the flags byte of a GTK KDE that hold the key id.
const GTK_KEY_ID_MASK: u8 = 0x03;

/// The bit of the flags byte of a GTK KDE that says the station may also send under the key.
const GTK_TX_BIT: u8 = 0x04;

/// Unwraps key data with the AES key unwrap of RFC 3394 and its default initial value; the result is wiped on drop.
pub fn unwrap_key_data(
    kek: &[u8; KEK_LEN],
    wrapped: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KeyDataError> {
    // Nothing is subtracted or allocated for a length the key wrap is not defined for. The lower bound is not
    // left to `aes-kw`, which takes a single semiblock as an empty key: the initial value alone would then
    // unwrap to nothing under any KEK.
    let plain_len = wrapped
        .len()
        .checked_sub(SEMIBLOCK_LEN)
        .filter(|len| *len >= MIN_PLAIN_LEN && len.is_multiple_of(SEMIBLOCK_LEN))
        .ok_or(KeyDataError::WrappedLength)?;
    // Wiped on drop from here on, on the failure path too. It is allocated at its final length and never grows,
    // so the bytes are not moved to a second allocation.
    let mut plain = Zeroizing::new(vec![0u8; plain_len]);
    // The KEK is not copied: the only state made from it is the key schedule in `cipher`, which `aes` (built
    // with its `zeroize` feature) wipes when the value drops. The working copies `aes` and `aes-kw` make on
    // the stack while they decrypt are not wiped by either crate.
    let cipher = KwAes128::new(kek.into());
    // The lengths were checked above, so the one failure left is the integrity check.
    cipher
        .unwrap_key(wrapped, &mut plain)
        .map_err(|_| KeyDataError::Unwrap)?;
    Ok(plain)
}

/// The group key as a GTK KDE delivers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GtkKde {
    /// The key id, 0 to 3: the index the key is installed under and that group-addressed frames name.
    pub key_id: u8,
    /// The Tx bit: whether the station may send under the key as well as receive.
    pub tx: bool,
    /// The group temporal key.
    pub key: SecretBytes<GTK_LEN>,
}

/// What a key data field holds of the three things the handshakes read from it.
#[derive(Debug, Default)]
pub struct KeyData {
    /// The RSN element: the whole element, its two header bytes included.
    pub rsne: Option<Vec<u8>>,
    /// The RSN extension element: the whole element, its two header bytes included.
    pub rsnxe: Option<Vec<u8>>,
    /// The group key.
    pub gtk: Option<GtkKde>,
}

/// Reads the elements of unwrapped key data, by the rules `wpa_supplicant` applies to padding and unknown elements.
pub fn parse_key_data(plain: &[u8]) -> Result<KeyData, KeyDataError> {
    let mut found = KeyData::default();
    let mut rest = plain;
    // Fewer than two bytes are no element: the walk ends, and a single left-over byte is ignored.
    while let &[id, len, ..] = rest {
        // Padding: `dd` and a zero length, whatever follows.
        if id == ID_VENDOR && len == 0 {
            break;
        }
        let (element, after) = rest
            .split_at_checked(ELEMENT_HEADER_LEN + usize::from(len))
            .ok_or(KeyDataError::Truncated)?;
        // Cannot fail: `element` is at least its header long.
        let (_header, data) = element
            .split_at_checked(ELEMENT_HEADER_LEN)
            .ok_or(KeyDataError::Truncated)?;
        match id {
            ID_RSNE => keep_once(&mut found.rsne, element)?,
            ID_RSNXE => keep_once(&mut found.rsnxe, element)?,
            ID_VENDOR => {
                if let Some(fields) = data.strip_prefix(&GTK_KDE_SELECTOR) {
                    if found.gtk.is_some() {
                        return Err(KeyDataError::Duplicate);
                    }
                    found.gtk = Some(gtk_kde(fields)?);
                }
            }
            _ => {}
        }
        rest = after;
    }
    Ok(found)
}

/// Keeps a copy of `element` in `slot`, unless an earlier element of the same kind already filled it.
fn keep_once(slot: &mut Option<Vec<u8>>, element: &[u8]) -> Result<(), KeyDataError> {
    if slot.is_some() {
        return Err(KeyDataError::Duplicate);
    }
    *slot = Some(element.to_vec());
    Ok(())
}

/// Reads what follows the selector in a GTK KDE: the flags byte, a reserved byte and a key of exactly 16 bytes.
fn gtk_kde(fields: &[u8]) -> Result<GtkKde, KeyDataError> {
    let [flags, _reserved, key @ ..]: &[u8; 2 + GTK_LEN] =
        fields.try_into().map_err(|_| KeyDataError::GtkLength)?;
    Ok(GtkKde {
        key_id: flags & GTK_KEY_ID_MASK,
        tx: flags & GTK_TX_BIT != 0,
        // Copied from the caller's buffer straight into the argument that `SecretBytes::new` wipes.
        key: SecretBytes::new(*key),
    })
}

/// Why key data could not be unwrapped or read; it names the rule broken and carries no byte of the key data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyDataError {
    /// The wrapped key data is shorter than 24 bytes or not a multiple of 8 bytes long.
    WrappedLength,
    /// The integrity check of the key unwrap failed: the key data was altered or wrapped under another KEK.
    Unwrap,
    /// An element declares more data than the key data holds.
    Truncated,
    /// The key data holds a second RSN element, RSNXE or GTK KDE.
    Duplicate,
    /// The key of a GTK KDE is not 16 bytes long.
    GtkLength,
}

impl fmt::Display for KeyDataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WrappedLength => {
                "wrapped key data is shorter than 24 bytes or not a multiple of 8 bytes long"
            }
            Self::Unwrap => "key data failed the integrity check of the key unwrap",
            Self::Truncated => "key data element runs past the end of the key data",
            Self::Duplicate => "key data holds a second RSN element, RSNXE or GTK",
            Self::GtkLength => "group key in the key data is not 16 bytes long",
        })
    }
}

impl std::error::Error for KeyDataError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference::{GTK1, KEK, M3, RSNE};
    use hex_literal::hex;

    /// A GTK KDE: `dd`, the length, `00 0f ac 01`, the flags byte, a reserved byte, the key.
    fn kde(flags: u8, key: &[u8]) -> Vec<u8> {
        let len = u8::try_from(6 + key.len()).unwrap();
        [&[0xdd, len][..], &hex!("000fac01"), &[flags, 0x00], key].concat()
    }

    /// Whether `shown` holds `bytes` as a list of decimal numbers, the way `{:?}` prints a `Vec<u8>` (on one line
    /// or on many), or as hex digits in either case.
    fn shows(shown: &str, bytes: &[u8]) -> bool {
        let numbers: Vec<u8> = shown
            .split(|c: char| !c.is_ascii_digit())
            .filter_map(|number| number.parse().ok())
            .collect();
        let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        numbers.windows(bytes.len()).any(|window| window == bytes)
            || shown.contains(&hex)
            || shown.contains(&hex.to_uppercase())
    }

    // RFC 3394 section 4.1: 128 bits of key data under a 128-bit KEK.
    #[test]
    fn rfc3394_vector_unwraps() {
        let secret = hex!("00112233445566778899aabbccddeeff");
        let result = unwrap_key_data(
            &hex!("000102030405060708090a0b0c0d0e0f"),
            &hex!("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"),
        );
        // The unwrapped key data holds the GTK, so its `Debug` must stay redacted. That is the doing of `zeroize`
        // (from 1.9.1 `Zeroizing` prints `Zeroizing { .. }`), not of this crate: this pins it, in case a dependency
        // change stops redacting. The control makes sure `shows` would flag a plain `Vec` of the same bytes.
        assert!(shows(&format!("{:?}", secret.to_vec()), &secret));
        assert!(shows(&format!("{:#?}", secret.to_vec()), &secret));
        assert!(!shows(&format!("{result:?}"), &secret));
        let plain = result.unwrap();
        assert!(!shows(&format!("{plain:?}"), &secret));
        assert!(!shows(&format!("{plain:#?}"), &secret));
        assert_eq!(plain.as_slice(), secret);
    }

    // Wrapped by `openssl enc -id-aes128-wrap` in reference_handshake.py: a 48-byte plaintext.
    #[test]
    fn reference_message_3_key_data_unwraps() {
        let plain = unwrap_key_data(&KEK, &M3[99..]).unwrap();
        assert_eq!(
            plain.as_slice(),
            [&RSNE[..], &hex!("dd16000fac010100"), &GTK1, &hex!("dd00")].concat()
        );
    }

    #[test]
    fn damaged_or_misrouted_key_data_is_refused() {
        let mut damaged = M3[99..].to_vec();
        damaged[9] ^= 1;
        assert_eq!(
            unwrap_key_data(&KEK, &damaged).unwrap_err(),
            KeyDataError::Unwrap
        );
        assert_eq!(
            unwrap_key_data(&[0x22; 16], &M3[99..]).unwrap_err(),
            KeyDataError::Unwrap
        );
        for len in [0, 7, 8, 16, 23, 25] {
            assert_eq!(
                unwrap_key_data(&KEK, &vec![0; len]).unwrap_err(),
                KeyDataError::WrappedLength
            );
        }
        // The initial value alone, wrapping nothing: it would pass the integrity check under any key.
        assert_eq!(
            unwrap_key_data(&KEK, &hex!("a6a6a6a6a6a6a6a6")).unwrap_err(),
            KeyDataError::WrappedLength
        );
    }

    #[test]
    fn parses_rsne_and_gtk() {
        let d = parse_key_data(&unwrap_key_data(&KEK, &M3[99..]).unwrap()).unwrap();
        assert_eq!(d.rsne.as_deref(), Some(&RSNE[..]));
        assert_eq!(
            d.gtk,
            Some(GtkKde {
                key_id: 1,
                tx: false,
                key: SecretBytes::new(GTK1)
            })
        );
        assert!(d.rsnxe.is_none());
        let empty = parse_key_data(&[]).unwrap();
        assert!(empty.rsne.is_none() && empty.rsnxe.is_none() && empty.gtk.is_none());
    }

    // Review Focus 3. The padding forms seen from real access points: `dd 00`; `dd` and five zeros; two zero
    // bytes, which the standard does not define; a lone `dd`, the standard's shortest padding.
    #[test]
    fn padding_forms_seen_in_real_captures_are_accepted() {
        for padding in [
            &[][..],
            &hex!("dd"),
            &hex!("dd00"),
            &hex!("dd0000000000"),
            &hex!("0000"),
        ] {
            let d = parse_key_data(&[&RSNE[..], &kde(1, &GTK1), padding].concat()).unwrap();
            assert_eq!(d.gtk.unwrap().key.expose(), &GTK1);
        }
    }

    #[test]
    fn key_id_and_tx_bit_are_read() {
        for (flags, key_id, tx) in [(0x01, 1, false), (0x06, 2, true), (0xff, 3, true)] {
            let gtk = parse_key_data(&kde(flags, &GTK1)).unwrap().gtk.unwrap();
            assert_eq!((gtk.key_id, gtk.tx), (key_id, tx));
        }
    }

    #[test]
    fn unknown_elements_are_skipped() {
        let d = parse_key_data(
            &[
                &hex!("dd050050f20200")[..], // a vendor element
                &hex!("dd1c000fac09"),       // an IGTK KDE …
                &[0; 24],                    // … and its 24 bytes
                &hex!("7f03010203"),
                &hex!("f40120"),
                &RSNE,
                &kde(1, &GTK1),
            ]
            .concat(),
        )
        .unwrap();
        assert_eq!(d.rsne.as_deref(), Some(&RSNE[..]));
        assert_eq!(d.rsnxe.as_deref(), Some(&hex!("f40120")[..]));
        assert_eq!(d.gtk.unwrap().key.expose(), &GTK1);
    }

    #[test]
    fn malformed_key_data_is_refused() {
        let refused = |input: &[u8]| parse_key_data(input).unwrap_err();
        let gtk = kde(1, &GTK1);

        assert_eq!(refused(&hex!("30140100")), KeyDataError::Truncated);
        assert_eq!(
            refused(&[&RSNE[..], &hex!("dd16000fac01")].concat()),
            KeyDataError::Truncated
        );

        assert_eq!(refused(&[&gtk[..], &gtk].concat()), KeyDataError::Duplicate);
        assert_eq!(refused(&[RSNE, RSNE].concat()), KeyDataError::Duplicate);
        assert_eq!(refused(&hex!("f40120f40120")), KeyDataError::Duplicate);

        assert_eq!(refused(&kde(1, &[0x11; 32])), KeyDataError::GtkLength);
        assert_eq!(refused(&kde(1, &[0x11; 5])), KeyDataError::GtkLength);
        assert_eq!(refused(&hex!("dd05000fac0101")), KeyDataError::GtkLength);
    }

    #[test]
    fn gtk_is_redacted() {
        let text = format!("{:?}", parse_key_data(&kde(1, &GTK1)).unwrap());
        assert!(text.contains("<redacted>") && !text.contains("17, 34") && !text.contains("1122"));
    }
}
