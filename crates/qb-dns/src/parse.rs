//! List text to rules and counts: hosts files and adblock-style `||domain^` lines.

use crate::name::{MAX_NAME_LEN, normalize};
use core::net::IpAddr;

/// A UTF-8 byte-order mark, which some servers put before the first line.
const BYTE_ORDER_MARK: &[u8] = b"\xef\xbb\xbf";

/// The hosts-file addresses that mean "block this name".
const BLOCKING_ADDRESSES: [&[u8]; 3] = [b"0.0.0.0", b"127.0.0.1", b"::"];

/// How much a rule covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleKind {
    /// The name only.
    Exact,
    /// The name and every subdomain.
    Suffix,
}

/// What the lines of one list came to; a list with no `exact` and no `suffix` holds no rule.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ListStats {
    /// Names emitted as `Exact` rules, from hosts lines; a repeated name counts each time.
    pub exact: usize,
    /// Names emitted as `Suffix` rules, from `||name^` lines; a repeated name counts each time.
    pub suffix: usize,
    /// Hosts names left alone: the address is not a blocking one, or the name is a local one.
    pub non_blocking: usize,
    /// Names in a readable line that are not valid domain names.
    pub invalid: usize,
    /// Lines in a shape that is not read: exceptions, options, wildcards, bare names.
    pub unsupported: usize,
}

/// Reads hosts and `||name^` lines from `text`, calls `emit` with each normalised name, and
/// counts every line that is not blank or a comment. A hosts line is counted once for each name
/// on it, or once if it has none; any other line once. Never panics, whatever the bytes.
pub fn parse_list(text: &[u8], mut emit: impl FnMut(RuleKind, &str)) -> ListStats {
    let text = text.strip_prefix(BYTE_ORDER_MARK).unwrap_or(text);
    let mut stats = ListStats::default();
    let mut buf = [0; MAX_NAME_LEN];
    for line in text.split(|&byte| byte == b'\n') {
        // The trailing `\r` of a CRLF line is ASCII whitespace, so it goes here too.
        match line.trim_ascii() {
            [] | [b'#' | b'!' | b'[', ..] => {}
            [b'@', b'@', ..] => stats.unsupported += 1,
            [b'|', b'|', rest @ ..] => match rest.strip_suffix(b"^") {
                Some(raw) => match normalize(raw, &mut buf) {
                    Some(name) => {
                        emit(RuleKind::Suffix, name);
                        stats.suffix += 1;
                    }
                    // Filter syntax this parser does not read, rather than a misspelt name.
                    None if raw.iter().any(|byte| b"*^$/|".contains(byte)) => {
                        stats.unsupported += 1;
                    }
                    None => stats.invalid += 1,
                },
                // Options after the `^`, or no `^` at all.
                None => stats.unsupported += 1,
            },
            line => hosts_line(line, &mut buf, &mut stats, &mut emit),
        }
    }
    stats
}

/// Counts one line that is neither a comment nor a `||` rule: an address, then names.
fn hosts_line(
    line: &[u8],
    buf: &mut [u8; MAX_NAME_LEN],
    stats: &mut ListStats,
    emit: &mut impl FnMut(RuleKind, &str),
) {
    let mut tokens = line
        .split(u8::is_ascii_whitespace)
        .filter(|token| !token.is_empty())
        .take_while(|token| !token.starts_with(b"#"));
    // The caller's line is trimmed, not empty and not a comment, so it has a first token.
    let Some(address) = tokens.next() else { return };
    let blocking = BLOCKING_ADDRESSES.contains(&address);
    let mut named = false;
    for raw in tokens {
        named = true;
        if !blocking || is_local_or_address(raw) {
            stats.non_blocking += 1;
        } else if let Some(name) = normalize(raw, buf) {
            emit(RuleKind::Exact, name);
            stats.exact += 1;
        } else {
            stats.invalid += 1;
        }
    }
    if !named {
        // One token: a bare name, a filter pattern, a line of some other format.
        stats.unsupported += 1;
    }
}

/// Whether a hosts name is one that system hosts files carry and that must not be blocked:
/// an IP address, a single label such as `localhost`, or `localhost.localdomain`.
fn is_local_or_address(raw: &[u8]) -> bool {
    let name = raw.strip_suffix(b".").unwrap_or(raw);
    let one_label = !name.is_empty() && !name.contains(&b'.');
    one_label
        || name.eq_ignore_ascii_case(b"localhost.localdomain")
        || core::str::from_utf8(name).is_ok_and(|name| name.parse::<IpAddr>().is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Rng;

    const HOSTS: &[u8] = include_bytes!("../tests/fixtures/hosts-sample.txt");
    const ADBLOCK: &[u8] = include_bytes!("../tests/fixtures/adblock-sample.txt");

    fn rules(text: &[u8]) -> (Vec<(RuleKind, String)>, ListStats) {
        let mut emitted = Vec::new();
        let stats = parse_list(text, |kind, name| emitted.push((kind, name.to_owned())));
        (emitted, stats)
    }

    #[test]
    fn hosts_sample_counts() {
        let (v, s) = rules(HOSTS);
        assert_eq!(
            s,
            ListStats {
                exact: 13,
                suffix: 0,
                non_blocking: 10,
                invalid: 2,
                unsupported: 1
            }
        );
        let names: Vec<&str> = v.iter().map(|(_, n)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "ads.example.com",
                "tracker.example.net",
                "metrics.example.org",
                "pixel.example.com",
                "under_score.example.com",
                "xn--bcher-kva.example",
                "loopback-style.example.net",
                "v6-style.example.net",
                "one.example.org",
                "two.example.org",
                "trailing-dot.example.com",
                "ads.example.com",
                "tabbed.example.com"
            ]
        );
        assert!(v.iter().all(|(k, _)| *k == RuleKind::Exact));
    }

    #[test]
    fn adblock_sample_counts() {
        let (v, s) = rules(ADBLOCK);
        assert_eq!(
            s,
            ListStats {
                exact: 0,
                suffix: 6,
                non_blocking: 0,
                invalid: 2,
                unsupported: 8
            }
        );
        let names: Vec<&str> = v.iter().map(|(_, n)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "ads.example.com",
                "tracker.example.net",
                "xn--bcher-kva.example",
                "example.org",
                "ads.example.com",
                "test"
            ]
        );
        assert!(v.iter().all(|(k, _)| *k == RuleKind::Suffix));
    }

    /// A byte-order mark, CRLF, NUL, bytes that are not UTF-8, no final newline.
    #[test]
    fn odd_bytes_do_not_confuse_lines() {
        let (v, s) = rules(b"\xef\xbb\xbf0.0.0.0 bom.example.com\r\n||crlf.example.net^\r\n0.0.0.0 nul\0.example.com\n0.0.0.0 \xff\xfe.example.com\n0.0.0.0 last.example.org");
        assert_eq!(
            s,
            ListStats {
                exact: 2,
                suffix: 1,
                non_blocking: 0,
                invalid: 2,
                unsupported: 0
            }
        );
        assert_eq!(
            (v[0].1.as_str(), v[1].1.as_str(), v[2].1.as_str()),
            ("bom.example.com", "crlf.example.net", "last.example.org")
        );
        assert_eq!(rules(b"").1, ListStats::default());
    }

    /// Only the start of the text is stripped of a byte-order mark: one anywhere else is part of
    /// the line, and a second one after the first is too.
    #[test]
    fn a_byte_order_mark_is_stripped_only_at_the_start() {
        const BOM: &str = "\u{feff}";
        let line = |text: &str| rules(text.as_bytes());
        let (v, s) = line(&format!("{BOM}0.0.0.0 a.example.com"));
        assert_eq!((v.len(), s.exact, s.non_blocking), (1, 1, 0));

        // The first token of the line is no blocking address, so its names are not blocked.
        for text in [
            format!("{BOM}{BOM}0.0.0.0 a.example.com"),
            format!("0.0.0.0 a.example.com\n{BOM}0.0.0.0 b.example.com"),
        ] {
            let (v, s) = line(&text);
            assert_eq!(s.non_blocking, 1, "{text:?}");
            assert!(v.iter().all(|(_, name)| name != "b.example.com"), "{v:?}");
        }
        let (v, s) = line(&format!("||a.example.com^\n{BOM}||b.example.com^"));
        assert_eq!((v.len(), s.suffix, s.unsupported), (1, 1, 1));
    }

    /// Review Focus 1: an error page or a cosmetic filter list yields no rule at all.
    #[test]
    fn text_that_is_not_a_list_blocks_nothing() {
        let html = b"<!DOCTYPE html>\n<html><head><title>404 Not Found</title></head>\n<body>\n<h1>Not Found</h1>\n<p>example.com</p>\n</body></html>\n";
        let cosmetic = b"example.com##.ad-banner\nexample.org,example.net##div.ad > a\n&ad_box_\n-advert-\nads.example.com\n/ads/*$script\n";
        for text in [&html[..], &cosmetic[..]] {
            let (v, s) = rules(text);
            assert!(v.is_empty() && s.exact == 0 && s.suffix == 0, "{v:?}");
            assert!(s.unsupported + s.non_blocking + s.invalid > 0);
        }
    }

    /// The table rows the two samples do not reach, one line each.
    #[test]
    fn edge_lines_follow_the_table() {
        let none = ListStats::default();
        let (non_blocking, invalid, unsupported) = (
            ListStats {
                non_blocking: 1,
                ..none
            },
            ListStats { invalid: 1, ..none },
            ListStats {
                unsupported: 1,
                ..none
            },
        );
        for (line, want) in [
            // One label is judged after the trailing dot is dropped.
            ("0.0.0.0 local.", non_blocking),
            ("0.0.0.0 LocalHost.LocalDomain.", non_blocking),
            ("0.0.0.0 192.0.2.1", non_blocking),
            ("0.0.0.0 192.0.2.1.", non_blocking),
            ("0.0.0.0 ::ffff:192.0.2.1", non_blocking),
            ("0.0.0.0 2001:db8::1", non_blocking),
            // Only the three blocking addresses, spelled exactly so, block.
            ("0 a.example.com", non_blocking),
            ("::1 a.example.com", non_blocking),
            ("0.0.0.0 .", invalid),
            ("0.0.0.0 # a comment and no name", unsupported),
            ("0.0.0.0 #a.example.com", unsupported),
            ("@@", unsupported),
            ("||", unsupported),
            ("||^", invalid),
            ("||a$b.example.com^", unsupported),
            ("||example.com/path^", unsupported),
            ("||a|b.example.com^", unsupported),
            ("||a.example.com^^", unsupported),
            ("||a.example.com^ $important", unsupported),
        ] {
            let (v, s) = rules(line.as_bytes());
            assert!(v.is_empty(), "{line:?} emitted {v:?}");
            assert_eq!(s, want, "{line:?}");
        }

        // Each name of a line is counted on its own, and a `#` token ends the line.
        let (v, s) = rules(b"0.0.0.0 A.Example.Com b..example.com local #c.example.com");
        assert_eq!(v, [(RuleKind::Exact, "a.example.com".to_owned())]);
        assert_eq!(
            s,
            ListStats {
                exact: 1,
                non_blocking: 1,
                invalid: 1,
                ..none
            }
        );
        // A trailing dot on a suffix rule is dropped like any other.
        let (v, s) = rules(b"  ||Example.Com.^  ");
        assert_eq!(v, [(RuleKind::Suffix, "example.com".to_owned())]);
        assert_eq!(s, ListStats { suffix: 1, ..none });
    }

    #[test]
    fn parse_list_never_panics() {
        let mut rng = Rng::new(2);
        let (mut exact, mut suffix) = (0, 0);
        for i in 0..20_000 {
            let text = match i % 3 {
                0 => rng.bytes(400),
                1 => rng.mutate(HOSTS),
                _ => rng.mutate(ADBLOCK),
            };
            let mut emitted = [0; 2];
            let stats = parse_list(&text, |kind, name| {
                let mut buf = [0; MAX_NAME_LEN];
                assert_eq!(normalize(name.as_bytes(), &mut buf), Some(name));
                emitted[kind as usize] += 1;
            });
            // The counts are the caller's only word on what was emitted.
            assert_eq!([stats.exact, stats.suffix], emitted, "{text:?}");
            exact += stats.exact;
            suffix += stats.suffix;
        }
        // Rules of both kinds must have come out, or the property was checked on nothing.
        assert!(exact > 0 && suffix > 0, "{exact} exact, {suffix} suffix");

        let (v, s) = rules(&vec![b'a'; 2_000_000]);
        assert!(v.is_empty());
        assert_eq!(
            s,
            ListStats {
                unsupported: 1,
                ..ListStats::default()
            }
        );
    }
}
