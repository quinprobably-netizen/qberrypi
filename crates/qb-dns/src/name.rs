//! Validate and normalise a domain name from a list or the configuration.

/// The longest valid name in bytes, written with dots and without the trailing one.
pub const MAX_NAME_LEN: usize = 253;

/// The longest label of a name, in bytes.
const MAX_LABEL_LEN: usize = 63;

/// Lower-cases `raw` into `buf` and drops one trailing dot; `None` if it is not a valid name.
///
/// Valid: 1 to 253 bytes, in labels of 1 to 63 bytes from `a-z 0-9 - _`, the last label not all
/// digits (which rules out IPv4 addresses). Never panics, whatever the bytes.
pub fn normalize<'b>(raw: &[u8], buf: &'b mut [u8; MAX_NAME_LEN]) -> Option<&'b str> {
    let raw = raw.strip_suffix(b".").unwrap_or(raw);
    // An empty name fails the last-label check below; a name over 253 bytes fails here.
    let out = buf.get_mut(..raw.len())?;
    let mut label_len = 0;
    let mut all_digits = true;
    for (dst, &byte) in out.iter_mut().zip(raw) {
        let byte = byte.to_ascii_lowercase();
        match byte {
            b'.' if label_len == 0 => return None,
            b'.' => {
                label_len = 0;
                all_digits = true;
            }
            b'0'..=b'9' => label_len += 1,
            b'a'..=b'z' | b'-' | b'_' => {
                label_len += 1;
                all_digits = false;
            }
            _ => return None,
        }
        if label_len > MAX_LABEL_LEN {
            return None;
        }
        *dst = byte;
    }
    if label_len == 0 || all_digits {
        return None;
    }
    // Only ASCII was copied, so this cannot fail.
    core::str::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Rng;

    fn norm(s: &[u8]) -> Option<String> {
        let mut buf = [0; MAX_NAME_LEN];
        normalize(s, &mut buf).map(str::to_owned)
    }

    #[test]
    fn names_are_lowercased_and_lose_one_trailing_dot() {
        for (raw, want) in [
            ("Example.COM.", "example.com"),
            ("xn--bcher-kva.example", "xn--bcher-kva.example"),
            (
                "_dmarc.under_score.example.com",
                "_dmarc.under_score.example.com",
            ),
            ("localhost", "localhost"),
            // Only the last label may not be all digits, and a label may start or end with `-`.
            ("123.example.com", "123.example.com"),
            ("1.2.3.example.com", "1.2.3.example.com"),
            ("-ads.example.com", "-ads.example.com"),
            ("ads-.example.com", "ads-.example.com"),
            ("-.example.com", "-.example.com"),
            ("example.c-", "example.c-"),
            ("example.-1", "example.-1"),
        ] {
            assert_eq!(norm(raw.as_bytes()).as_deref(), Some(want), "{raw}");
        }
    }

    #[test]
    fn invalid_names_are_rejected() {
        for bad in [
            "",
            ".",
            "example.com..",
            "a..b",
            ".example.com",
            "exa mple.com",
            "*.example.com",
            "example.com/path",
            "b\u{fc}cher.example",
            "0.0.0.0",
            "192.0.2.1",
            "example.123",
            "a\0b.example",
        ] {
            assert_eq!(norm(bad.as_bytes()), None, "{bad:?}");
        }
    }

    #[test]
    fn length_limits_are_exact() {
        let l63 = "a".repeat(63);
        assert!(norm(format!("{l63}.example").as_bytes()).is_some());
        assert!(norm(format!("{l63}a.example").as_bytes()).is_none());
        let n253 = format!("{l63}.{l63}.{l63}.{}", "b".repeat(61)); // 253 bytes
        assert!(norm(n253.as_bytes()).is_some() && norm(format!("{n253}.").as_bytes()).is_some());
        assert!(norm(format!("{n253}b").as_bytes()).is_none());
    }

    #[test]
    fn normalize_never_panics_and_is_idempotent() {
        let mut rng = Rng::new(1);
        let mut accepted = 0;
        for i in 0..100_000 {
            let input = if i % 2 == 0 {
                rng.bytes(300)
            } else {
                rng.mutate(b"Sub.Example-1.TEST.")
            };
            if let Some(n) = norm(&input) {
                assert!((1..=MAX_NAME_LEN).contains(&n.len()), "{input:?}");
                assert_eq!(norm(n.as_bytes()).as_deref(), Some(n.as_str()), "{input:?}");
                accepted += 1;
            }
        }
        // Both branches must be exercised, or the properties above were checked on nothing.
        assert!(0 < accepted && accepted < 100_000, "{accepted} accepted");
    }
}
