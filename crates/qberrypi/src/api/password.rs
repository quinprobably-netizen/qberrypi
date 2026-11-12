//! The login password as it is kept: a salted PBKDF2-HMAC-SHA256 hash, written as one line of
//! text, `$pbkdf2-sha256$i=<rounds>$<salt as 32 hex digits>$<hash as 64 hex digits>`.
//!
//! `cargo xtask hash-password` makes the line and `qberrypi.toml` holds it. The hash is a secret:
//! `Debug` shows `<redacted>`, and nothing here puts a salt, a hash or a password into an error.

use std::fmt;

use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::hex;

/// The rounds of PBKDF2 that a new hash takes.
pub const ROUNDS: u32 = 100_000;

/// The fewest rounds a line may name.
const MIN_ROUNDS: u32 = 10_000;

/// The most rounds a line may name.
const MAX_ROUNDS: u32 = 10_000_000;

/// What every line starts with, up to the rounds.
const PREFIX: &str = "$pbkdf2-sha256$i=";

/// The length of a salt, in bytes.
const SALT_LEN: usize = 16;

/// The length of a hash, in bytes.
const HASH_LEN: usize = 32;

/// A password's PBKDF2-HMAC-SHA256 hash, with the salt and the rounds that made it.
///
/// A copy is as secret as the original, and its `Debug` shows `<redacted>` as well.
#[derive(Clone)]
pub struct PasswordHash {
    rounds: u32,
    salt: [u8; SALT_LEN],
    hash: [u8; HASH_LEN],
}

impl PasswordHash {
    /// Hashes `password` with `salt` and [`ROUNDS`] rounds.
    pub fn new(password: &[u8], salt: [u8; SALT_LEN]) -> Self {
        Self {
            rounds: ROUNDS,
            salt,
            hash: derive(password, &salt, ROUNDS),
        }
    }

    /// Reads a line as [`PasswordHash::to_text`] writes it, with the rounds it names; `None` for
    /// any other text.
    ///
    /// The rounds are decimal digits only, 10,000 to 10,000,000 and without leading zeros, so
    /// that a later change of [`ROUNDS`] keeps old lines valid. The salt and the hash are lower-case
    /// hex. Nothing may come before or after the line.
    pub fn parse(text: &str) -> Option<Self> {
        let mut fields = text.strip_prefix(PREFIX)?.split('$');
        let (rounds, salt, hash) = (fields.next()?, fields.next()?, fields.next()?);
        if fields.next().is_some() || !rounds.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let rounds: u32 = rounds.parse().ok()?;
        if !(MIN_ROUNDS..=MAX_ROUNDS).contains(&rounds) {
            return None;
        }
        let parsed = Self {
            rounds,
            salt: hex::decode(salt)?,
            hash: hex::decode(hash)?,
        };
        // Whatever else is wrong with the text, such as a leading zero, makes it differ from the
        // line that these fields make.
        (parsed.to_text() == text).then_some(parsed)
    }

    /// The line that holds this hash: `$pbkdf2-sha256$i=<rounds>$<salt hex>$<hash hex>`.
    pub fn to_text(&self) -> String {
        format!(
            "{PREFIX}{}${}${}",
            self.rounds,
            hex::encode(&self.salt),
            hex::encode(&self.hash)
        )
    }

    /// Whether `password` is the one that made this hash: derives with the stored rounds and
    /// salt and compares in constant time.
    pub fn verify(&self, password: &[u8]) -> bool {
        let candidate = Zeroizing::new(derive(password, &self.salt, self.rounds));
        bool::from(candidate.as_slice().ct_eq(self.hash.as_slice()))
    }
}

impl fmt::Debug for PasswordHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// PBKDF2-HMAC-SHA256 of `password` and `salt`, `rounds` rounds, the first 32 bytes.
pub(crate) fn derive(password: &[u8], salt: &[u8], rounds: u32) -> [u8; HASH_LEN] {
    let mut out = [0; HASH_LEN];
    pbkdf2_hmac::<Sha256>(password, salt, rounds, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_derivation_is_pbkdf2_hmac_sha256() {
        // RFC 7914 section 11: P "passwd", S "salt", c 1; the first 32 bytes of its 64
        assert_eq!(
            hex::encode(&derive(b"passwd", b"salt", 1)),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        );
    }

    #[test]
    fn a_hash_round_trips_through_its_text_and_checks_only_its_password() {
        let h = PasswordHash::new(b"correct horse", [7; 16]);
        let text = h.to_text();
        assert!(
            text.starts_with("$pbkdf2-sha256$i=100000$07070707070707070707070707070707$")
                && text.len() == 15 + 9 + 32 + 1 + 64
        );
        let back = PasswordHash::parse(&text).unwrap();
        assert!(
            back.verify(b"correct horse") && !back.verify(b"correct horsf") && !back.verify(b"")
        );
        assert_eq!(format!("{back:?}"), "<redacted>");
    }

    #[test]
    fn only_the_one_shape_parses() {
        let good = PasswordHash::new(b"x", [0; 16]).to_text();
        for bad in [
            "",
            "$pbkdf2-sha256$i=100000$00$00",
            &good.replace("sha256", "sha1"),
            &good.replace("i=100000", "i=9999"),
            &good.replace("i=100000", "i=10000001"),
            &good.to_uppercase(),
            &format!("{good}0"),
            &good[1..],
        ] {
            assert!(PasswordHash::parse(bad).is_none(), "{bad}");
        }
        assert!(PasswordHash::parse(&good.replace("i=100000", "i=10000")).is_some());
    }

    /// A well-formed line that costs no derivation: a salt and a hash that nothing was derived
    /// from.
    const LINE: &str = "$pbkdf2-sha256$i=100000$0123456789abcdef0123456789abcdef$fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    #[test]
    fn a_line_is_read_back_exactly_as_written() {
        let h = PasswordHash::parse(LINE).unwrap();
        assert_eq!(h.to_text(), LINE);
        for rounds in ["10000", "10000000", "123456"] {
            let line = LINE.replace("i=100000", &format!("i={rounds}"));
            assert_eq!(PasswordHash::parse(&line).unwrap().to_text(), line);
        }
    }

    #[test]
    fn nothing_but_the_one_shape_is_a_line() {
        let salt = "0123456789abcdef0123456789abcdef";
        let hash = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        for bad in [
            // the rounds: out of range, padded, signed, spelled otherwise, or missing
            LINE.replace("i=100000", "i=9999"),
            LINE.replace("i=100000", "i=10000001"),
            LINE.replace("i=100000", "i=99999999999999999999"),
            LINE.replace("i=100000", "i=0"),
            LINE.replace("i=100000", "i=010000"),
            LINE.replace("i=100000", "i=+100000"),
            LINE.replace("i=100000", "i=-100000"),
            LINE.replace("i=100000", "i=1e5"),
            LINE.replace("i=100000", "i= 100000"),
            LINE.replace("i=100000", "i="),
            LINE.replace("i=100000", "r=100000"),
            LINE.replace("i=100000", "i=\u{663}\u{660}\u{660}\u{660}\u{660}"),
            // the algorithm
            LINE.replace("pbkdf2-sha256", "pbkdf2-sha512"),
            LINE.replace("pbkdf2-sha256", "PBKDF2-SHA256"),
            // the salt and the hash: length, case, characters
            LINE.replace(salt, &salt[1..]),
            LINE.replace(salt, &format!("{salt}0")),
            LINE.replace(hash, &hash[1..]),
            LINE.replace(hash, &format!("{hash}0")),
            LINE.replace(salt, &salt.to_uppercase()),
            LINE.replace(hash, &hash.to_uppercase()),
            LINE.replace(salt, &salt.replace('0', "g")),
            LINE.replace(hash, &hash.replace('f', "\u{ff46}")),
            // what comes before, after and between
            format!(" {LINE}"),
            format!("{LINE} "),
            format!("{LINE}\n"),
            format!("{LINE}$"),
            format!("{LINE}$x"),
            format!("x{LINE}"),
            LINE.replace("$i=", "$$i="),
            LINE.replace(&format!("{salt}$"), &format!("{salt}$$")),
            LINE.replacen('$', "", 1),
            LINE.replacen('$', "", 4),
            LINE.replace('$', "#"),
            "$".to_owned(),
            "$$$$$".to_owned(),
            "\0".to_owned(),
        ] {
            assert!(PasswordHash::parse(&bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn text_of_any_kind_is_refused_without_a_panic() {
        // Every prefix and every suffix of a good line, cut wherever a character starts.
        for (at, _) in LINE.char_indices() {
            assert!(PasswordHash::parse(&LINE[..at]).is_none(), "{at}");
            if at > 0 {
                assert!(PasswordHash::parse(&LINE[at..]).is_none(), "{at}");
            }
        }
        // A multi-byte character in each place, and in place of each digit and each separator.
        for (at, c) in LINE.char_indices() {
            for wide in ['\u{e9}', '\u{663}', '\u{20ac}', '\u{1f511}'] {
                let mut text = String::with_capacity(LINE.len() + 4);
                text.push_str(&LINE[..at]);
                text.push(wide);
                text.push_str(&LINE[at + c.len_utf8()..]);
                assert!(PasswordHash::parse(&text).is_none(), "{text:?}");
                text.insert(at, wide);
                assert!(PasswordHash::parse(&text).is_none(), "{text:?}");
            }
        }
        // And bytes that are not even a line of text.
        for junk in [
            "\u{feff}",
            "\u{202e}$pbkdf2-sha256$",
            "\u{1f511}\u{1f511}\u{1f511}",
        ] {
            assert!(PasswordHash::parse(junk).is_none());
        }
    }

    #[test]
    fn a_hash_shows_nothing_of_itself() {
        let h = PasswordHash::parse(LINE).unwrap();
        assert_eq!(format!("{h:?}"), "<redacted>");
        assert_eq!(format!("{h:#?}"), "<redacted>");
        assert_eq!(format!("{:?}", Some(&h)), "Some(<redacted>)");
    }
}
