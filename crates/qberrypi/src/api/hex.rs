//! Lower-case hex, as the password line and the session id write bytes.
//!
//! [`decode`] reads text that a file or a device on the network chose, so it takes exactly the one
//! shape that [`encode`] writes and nothing else, whatever the bytes of the text.

use std::fmt::Write as _;

/// `bytes` as lower-case hex digits, two for each byte.
pub(super) fn encode(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        // Writing to a `String` cannot fail.
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// The `N` bytes that `text` writes: exactly `2 * N` bytes of text, each `0` to `9` or `a` to
/// `f`; `None` for anything else, whatever its bytes. That depends only on `text`, which the
/// caller chose.
pub(super) fn decode<const N: usize>(text: &str) -> Option<[u8; N]> {
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if !rest.is_empty() || pairs.len() != N {
        return None;
    }
    let mut bytes = [0; N];
    for (byte, &[high, low]) in bytes.iter_mut().zip(pairs) {
        *byte = nibble(high)? << 4 | nibble(low)?;
    }
    Some(bytes)
}

/// The value of one lower-case hex digit.
fn nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_are_written_in_lower_case_and_read_back() {
        let bytes: [u8; 4] = [0x00, 0x0f, 0xab, 0xff];
        assert_eq!(encode(&bytes), "000fabff");
        assert_eq!(decode::<4>("000fabff"), Some(bytes));
        assert_eq!(encode(&[]), "");
        assert_eq!(decode::<0>(""), Some([]));
    }

    #[test]
    fn upper_case_digits_are_refused() {
        assert_eq!(decode::<4>("000FABFF"), None);
        assert_eq!(decode::<4>("000fabfF"), None);
    }

    #[test]
    fn any_length_but_twice_the_bytes_is_refused() {
        assert_eq!(decode::<4>("000fabf"), None);
        assert_eq!(decode::<4>("000fabff0"), None);
        assert_eq!(decode::<4>("000fabff00"), None);
        assert_eq!(decode::<4>(""), None);
        assert_eq!(decode::<0>("00"), None);
    }

    #[test]
    fn what_is_not_a_digit_is_refused_without_a_panic() {
        // 8 bytes of text each time, so that only the characters can be what is wrong.
        for text in [
            "000fabfg",
            "000fab f",
            "000fab-f",
            "000fab+f",
            "000fab0x",
            "000fab\n\n",
            "000fab\0\0",
            // multi-byte characters that fill 8 bytes of text, or that cut a pair in two
            "\u{e9}\u{e9}\u{e9}\u{e9}",
            "000fab\u{e9}",
            "0\u{e9}0fabf",
            "\u{ff41}\u{ff42}00",
            "\u{1f511}\u{1f511}",
            "\u{663}\u{660}\u{660}\u{660}",
        ] {
            assert_eq!(text.len(), 8, "{text:?}");
            assert_eq!(decode::<4>(text), None, "{text:?}");
        }
    }
}
