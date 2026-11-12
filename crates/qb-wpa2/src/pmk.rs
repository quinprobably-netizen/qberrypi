//! The pairwise master key (PMK): the 256-bit secret a station and an access
//! point share before the handshake, stretched from the passphrase and the
//! network name or given directly as 64 hex digits.
//!
//! No error repeats what it rejected, so a mistyped passphrase or key cannot
//! end up in a log.

use std::fmt;

use sha1::Sha1;
use zeroize::{Zeroize, Zeroizing};

use crate::secret::SecretBytes;

/// The length of a PMK in bytes.
const PMK_LEN: usize = 32;

/// The PBKDF2 iteration count of IEEE Std 802.11-2016 Annex J.4.1.
const PBKDF2_ROUNDS: u32 = 4096;

/// A pairwise master key, wiped on drop and redacted in `Debug`.
#[derive(Clone, Debug)]
pub struct Pmk(SecretBytes<PMK_LEN>);

impl Pmk {
    /// Stretches a passphrase of 8 to 63 printable ASCII characters and a network name of 1 to 32 bytes into the PMK.
    pub fn from_passphrase(passphrase: &str, ssid: &[u8]) -> Result<Self, PmkError> {
        let printable = passphrase.bytes().all(|b| (0x20..=0x7e).contains(&b));
        if !printable || !(8..=63).contains(&passphrase.len()) {
            return Err(PmkError::Passphrase);
        }
        if !(1..=32).contains(&ssid.len()) {
            return Err(PmkError::Ssid);
        }
        let mut key = Zeroizing::new([0u8; PMK_LEN]);
        pbkdf2::pbkdf2_hmac::<Sha1>(
            passphrase.as_bytes(),
            ssid,
            PBKDF2_ROUNDS,
            key.as_mut_slice(),
        );
        Ok(Self(SecretBytes::new(*key)))
    }

    /// Reads a PMK written as exactly 64 hex digits, in either case.
    pub fn from_hex(hex: &str) -> Result<Self, PmkError> {
        let digits = hex.as_bytes();
        if digits.len() != 2 * PMK_LEN {
            return Err(PmkError::Hex);
        }
        let mut key = Zeroizing::new([0u8; PMK_LEN]);
        let (pairs, _) = digits.as_chunks::<2>();
        for (byte, &[high, low]) in key.iter_mut().zip(pairs) {
            *byte = hex_digit(high)? << 4 | hex_digit(low)?;
        }
        Ok(Self(SecretBytes::new(*key)))
    }

    /// Takes a ready-made PMK and wipes the argument; any other copy the caller holds is the caller's to wipe.
    pub fn from_bytes(mut bytes: [u8; PMK_LEN]) -> Self {
        let pmk = Self(SecretBytes::new(bytes));
        bytes.zeroize();
        pmk
    }

    /// The key itself, for the derivation that needs it.
    pub fn expose(&self) -> &[u8; PMK_LEN] {
        self.0.expose()
    }
}

/// The value of one hex digit, in either case.
fn hex_digit(digit: u8) -> Result<u8, PmkError> {
    match digit {
        b'0'..=b'9' => Ok(digit - b'0'),
        b'a'..=b'f' => Ok(digit - b'a' + 10),
        b'A'..=b'F' => Ok(digit - b'A' + 10),
        _ => Err(PmkError::Hex),
    }
}

/// Why a PMK could not be made; it names the rule broken and never the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmkError {
    /// The passphrase is not 8 to 63 printable ASCII characters.
    Passphrase,
    /// The network name is not 1 to 32 bytes long.
    Ssid,
    /// The text is not exactly 64 hex digits.
    Hex,
}

impl fmt::Display for PmkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Passphrase => "passphrase must be 8 to 63 printable ASCII characters",
            Self::Ssid => "network name must be 1 to 32 bytes long",
            Self::Hex => "PMK must be exactly 64 hex digits",
        })
    }
}

impl std::error::Error for PmkError {}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    /// Test case 1 of Annex J.4.2 as the 64 hex digits `wpa_passphrase` prints.
    const PSK_TEXT: &str = "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e";

    /// Asserts that neither rendering of `error` repeats `rejected`.
    fn assert_no_echo(error: PmkError, rejected: &str) {
        assert!(!rejected.is_empty());
        assert!(!error.to_string().contains(rejected), "{error}");
        assert!(!format!("{error:?}").contains(rejected), "{error:?}");
    }

    // IEEE Std 802.11-2016 Annex J.4.2, test cases 1 to 3. `wpa_passphrase <ssid> <passphrase>` prints the same values.
    #[test]
    fn annex_j4_passphrase_vectors() {
        for (passphrase, ssid, psk) in [
            (
                "password",
                "IEEE",
                hex!("f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"),
            ),
            (
                "ThisIsAPassword",
                "ThisIsASSID",
                hex!("0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af"),
            ),
            (
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
                hex!("becb93866bb8c3832cb777c2f559807c8c59afcb6eae734885001300a981cc62"),
            ),
        ] {
            assert_eq!(
                Pmk::from_passphrase(passphrase, ssid.as_bytes())
                    .unwrap()
                    .expose(),
                &psk
            );
        }
    }

    #[test]
    fn pmk_given_directly() {
        let text = PSK_TEXT;
        let bytes = hex!("f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e");
        assert_eq!(Pmk::from_hex(text).unwrap().expose(), &bytes);
        assert_eq!(
            Pmk::from_hex(&text.to_uppercase()).unwrap().expose(),
            &bytes
        );
        assert_eq!(Pmk::from_bytes(bytes).expose(), &bytes);
    }

    #[test]
    fn invalid_input_is_refused_without_echo() {
        let too_long = "p".repeat(64);
        for passphrase in [
            "short77",
            too_long.as_str(),
            "caf\u{e9}-au-lait",
            "tab\tseparated",
        ] {
            let error = Pmk::from_passphrase(passphrase, b"IEEE").unwrap_err();
            assert_eq!(error, PmkError::Passphrase);
            assert_no_echo(error, passphrase);
        }

        // An empty network name has no text an error could repeat; the passphrase must not appear either.
        let error = Pmk::from_passphrase("password", b"").unwrap_err();
        assert_eq!(error, PmkError::Ssid);
        assert_no_echo(error, "password");
        let error = Pmk::from_passphrase("password", &[b's'; 33]).unwrap_err();
        assert_eq!(error, PmkError::Ssid);
        assert_no_echo(error, &"s".repeat(33));
        assert_no_echo(error, "password");

        let short = &PSK_TEXT[..63];
        let long = format!("{PSK_TEXT}0");
        let not_hex = format!("zz{}", &PSK_TEXT[2..]);
        // 64 bytes, but the two-byte letter is one character: the length alone does not make it hex.
        let not_ascii = format!("\u{e9}{}", &PSK_TEXT[2..]);
        // A sign is not a digit, though Rust's integer parsers accept one.
        let signed = format!("+{}", &PSK_TEXT[1..]);
        assert_eq!((not_hex.len(), not_ascii.len(), signed.len()), (64, 64, 64));
        for text in [short, &long, &not_hex, &not_ascii, &signed, ""] {
            let error = Pmk::from_hex(text).unwrap_err();
            assert_eq!(error, PmkError::Hex);
            if !text.is_empty() {
                assert_no_echo(error, text);
            }
        }

        let longest = "p".repeat(63);
        assert_eq!(("password".len(), longest.len()), (8, 63));
        assert!(Pmk::from_passphrase("password", b"IEEE").is_ok());
        assert!(Pmk::from_passphrase(&longest, b"IEEE").is_ok());
        assert!(Pmk::from_passphrase("password", &[b's'; 32]).is_ok());
        assert!(Pmk::from_passphrase("password", &[0xff, 0x00, 0x80]).is_ok());
    }

    #[test]
    fn pmk_is_redacted() {
        let text = format!("{:?}", Pmk::from_bytes([0xab; 32]));
        assert!(
            text.contains("<redacted>")
                && !text.contains("171")
                && !text.to_lowercase().contains("abab")
        );
    }
}
