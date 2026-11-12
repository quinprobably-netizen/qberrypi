//! Names as the watchdog reads them: decoded from the wire into a caller's buffer, cut to the
//! registrable domain, tested for a local suffix, and judged for looking random.
//!
//! Nothing here allocates, and nothing logs: a name that is asked for never reaches a log line.

/// The longest a name is as text, with no trailing dot: the 255 bytes of the wire form, less the
/// length byte of the first label and the zero of the root.
pub const NAME_TEXT_MAX: usize = 253;

/// The longest label, in bytes.
const LABEL_MAX: usize = 63;

/// The suffixes whose names are the household's own and not the Internet's.
const LOCAL_SUFFIXES: [&str; 7] = [
    "local",
    "lan",
    "home",
    "internal",
    "localdomain",
    "home.arpa",
    "arpa",
];

/// The fewest characters a label has to look random: a short label says too little.
const RANDOM_MIN_LEN: usize = 8;
/// A consonant run of this many letters looks random.
const RANDOM_CONSONANT_RUN: usize = 5;
/// A label where the vowels are a smaller share than one in this many letters looks random.
const RANDOM_VOWEL_ONE_IN: usize = 5;
/// This many switches between a letter and a digit look random.
const RANDOM_SWITCHES: usize = 3;
/// A label of this many characters is also tested for its entropy.
const RANDOM_ENTROPY_MIN_LEN: usize = 12;
/// A label whose entropy is this share of the most that its length allows looks random.
const RANDOM_ENTROPY_SHARE: f64 = 0.9;
/// The entropy of a long label counts only where its vowels are under this many percent of its
/// letters, or where it has a digit: a compound of words (`stackoverflow`) is high in entropy and
/// has the vowels of a language.
const RANDOM_ENTROPY_VOWEL_PERCENT: usize = 30;

/// The name that `wire` holds, as lower-case text with dots and no trailing dot, written into
/// `buf`.
///
/// `wire` is a name as labels, each led by its length, and ended by the zero of the root, as it
/// stands at the start of a question; bytes after the root are ignored. `None` for anything that
/// is not a host name's shape: a compression pointer, a label over 63 bytes, a name that is not
/// ended, the root itself, or a byte other than `a-z`, `A-Z`, `0-9`, `-` and `_`.
pub fn decode<'a>(wire: &[u8], buf: &'a mut [u8; NAME_TEXT_MAX]) -> Option<&'a str> {
    let (mut at, mut out) = (0, 0);
    loop {
        let len = usize::from(*wire.get(at)?);
        at += 1;
        if len == 0 {
            break;
        }
        if len > LABEL_MAX {
            return None;
        }
        let label = wire.get(at..at + len)?;
        at += len;
        if out > 0 {
            *buf.get_mut(out)? = b'.';
            out += 1;
        }
        for &byte in label {
            let byte = byte.to_ascii_lowercase();
            if !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_')
            {
                return None;
            }
            *buf.get_mut(out)? = byte;
            out += 1;
        }
    }
    std::str::from_utf8(buf.get(..out)?)
        .ok()
        .filter(|text| !text.is_empty())
}

/// A name that [`decode`] does not take, read as far as it goes: a tunnel's labels, which may
/// hold any byte (iodine's Base64 has `+`, its Base128 has bytes from 0x80 up), under a domain
/// that is plain text.
pub struct Lenient<'b, 'w> {
    /// The whole name as lower-case text with dots, each byte that no host name has written as
    /// `?`. It is for the tests of a suffix, such as [`under`] and [`is_local`], and is no name.
    pub text: &'b str,
    /// The registrable domain, if its labels are plain host-name text: [`registrable`] of `text`,
    /// and `None` when one of its bytes is odd, as a domain with such a byte is none that the
    /// household could have asked for.
    pub registrable: Option<&'b str>,
    /// The wire form of the labels left of the registrable domain, each led by its length, as they
    /// came: their bytes are what tells one name from another. Empty when the name is no more than
    /// its domain.
    pub left: &'w [u8],
    /// Whether `left` holds a byte that a host name has not: other than `a-z`, `A-Z`, `0-9`, `-`
    /// and `_`.
    pub left_odd: bool,
}

impl Lenient<'_, '_> {
    /// How many bytes the part left of the registrable domain has as text: its labels and the dots
    /// between them, which is the wire form less the length byte of its first label.
    pub fn left_len(&self) -> usize {
        self.left.len().saturating_sub(1)
    }
}

/// The name that `wire` holds, like [`decode`] but taking any byte in a label.
///
/// `None` for what has no shape of a name: a compression pointer, a label over 63 bytes, a name
/// that is not ended, the root itself, or text too long for `buf`. Anything else is read, and
/// [`Lenient`] says what could not be read as text.
pub fn decode_lenient<'b, 'w>(
    wire: &'w [u8],
    buf: &'b mut [u8; NAME_TEXT_MAX],
) -> Option<Lenient<'b, 'w>> {
    let (mut at, mut out) = (0, 0);
    loop {
        let len = usize::from(*wire.get(at)?);
        at += 1;
        if len == 0 {
            break;
        }
        if len > LABEL_MAX {
            return None;
        }
        let label = wire.get(at..at + len)?;
        at += len;
        if out > 0 {
            *buf.get_mut(out)? = b'.';
            out += 1;
        }
        for &byte in label {
            *buf.get_mut(out)? = if is_host_byte(byte) {
                byte.to_ascii_lowercase()
            } else {
                b'?'
            };
            out += 1;
        }
    }
    let text = std::str::from_utf8(buf.get(..out)?)
        .ok()
        .filter(|text| !text.is_empty())?;
    let domain = registrable(text);
    // Each byte of the text is one of the wire form, and the first label has its length byte too.
    let left = match text.len().checked_sub(domain.len() + 1) {
        Some(left_text) => wire.get(..left_text + 1)?,
        None => &[],
    };
    Some(Lenient {
        text,
        registrable: (!domain.contains('?')).then_some(domain),
        left,
        left_odd: has_odd_byte(left),
    })
}

/// Whether a label of `labels`, which are in wire form and all there, holds a byte that a host
/// name has not. The length bytes are not looked at.
fn has_odd_byte(labels: &[u8]) -> bool {
    let mut at = 0;
    while let Some(&len) = labels.get(at) {
        let end = at + 1 + usize::from(len);
        let Some(label) = labels.get(at + 1..end) else {
            return false;
        };
        if label.iter().any(|&byte| !is_host_byte(byte)) {
            return true;
        }
        at = end;
    }
    false
}

/// Whether `byte` may be in a host name's label: `a-z`, `A-Z`, `0-9`, `-` and `_`.
fn is_host_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

/// The registrable domain of `name`, lower-case and without a trailing dot: its last two labels,
/// or its last three where the second to last is of 2 or 3 characters and the last of 2 (`co.uk`).
/// A name of fewer labels is returned as it is.
///
/// This is an approximation, as there is no list of public suffixes on the board.
pub fn registrable(name: &str) -> &str {
    let mut dots = name.rmatch_indices('.').map(|(at, _)| at);
    let (Some(last), Some(second)) = (dots.next(), dots.next()) else {
        return name;
    };
    let top = &name[last + 1..];
    let middle = &name[second + 1..last];
    if top.len() == 2 && (2..=3).contains(&middle.len()) {
        return dots.next().map_or(name, |third| &name[third + 1..]);
    }
    &name[second + 1..]
}

/// Whether `name` is the household's own: it has no dot, or it ends in `local`, `lan`, `home`,
/// `internal`, `localdomain`, `home.arpa` or `arpa`, at a label boundary (`notlocal.com` is not
/// local and `printer.local` is).
pub fn is_local(name: &str) -> bool {
    !name.contains('.') || LOCAL_SUFFIXES.iter().any(|suffix| under(name, suffix))
}

/// Whether `name` is `suffix` or a name below it, at a label boundary. Both are lower-case, as
/// [`decode`] gives them.
pub fn under(name: &str, suffix: &str) -> bool {
    name.strip_suffix(suffix)
        .is_some_and(|rest| rest.is_empty() || rest.ends_with('.'))
}

/// Whether `label`, one label of a name, looks like one that a program made up.
///
/// It must be of 8 characters or more, all of `a-z` and `0-9`, and then one of these is enough: a
/// run of 5 consonants; vowels that are fewer than one in 5 of the letters; 3 switches between a
/// letter and a digit; or, for 12 characters or more, an entropy of at least 0.9 of the log2 of
/// its length together with either a digit or vowels that are under 30 % of the letters (a
/// compound of real words such as `stackoverflow` has a high entropy and the vowels of a language).
/// `y` counts as a vowel, so that `crystals` is a word and not a run.
pub fn looks_random(label: &str) -> bool {
    let bytes = label.as_bytes();
    if bytes.len() < RANDOM_MIN_LEN
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return false;
    }
    longest_consonant_run(bytes) >= RANDOM_CONSONANT_RUN
        || few_vowels(bytes)
        || switches(bytes) >= RANDOM_SWITCHES
        || (bytes.len() >= RANDOM_ENTROPY_MIN_LEN
            && entropy_is_high(bytes)
            && (has_digit(bytes) || vowels_under_entropy_share(bytes)))
}

/// Whether `byte`, which is `a-z`, is a vowel.
fn is_vowel(byte: u8) -> bool {
    matches!(byte, b'a' | b'e' | b'i' | b'o' | b'u' | b'y')
}

/// The most letters in a row of `bytes` that are no vowels: a digit ends a run.
fn longest_consonant_run(bytes: &[u8]) -> usize {
    let (mut longest, mut run) = (0, 0);
    for &byte in bytes {
        if byte.is_ascii_lowercase() && !is_vowel(byte) {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    longest
}

/// Whether `bytes` holds a digit.
fn has_digit(bytes: &[u8]) -> bool {
    bytes.iter().any(u8::is_ascii_digit)
}

/// Whether the vowels of `bytes` are under [`RANDOM_ENTROPY_VOWEL_PERCENT`] percent of its
/// letters. A label of no letter has no share of vowels, and is not under it.
fn vowels_under_entropy_share(bytes: &[u8]) -> bool {
    let letters = bytes
        .iter()
        .filter(|byte| byte.is_ascii_lowercase())
        .count();
    let vowels = bytes.iter().filter(|&&byte| is_vowel(byte)).count();
    letters > 0 && vowels * 100 < letters * RANDOM_ENTROPY_VOWEL_PERCENT
}

/// Whether the vowels of `bytes` are fewer than one in [`RANDOM_VOWEL_ONE_IN`] of its letters. A
/// label of no letter has no share of vowels, and is not few.
fn few_vowels(bytes: &[u8]) -> bool {
    let letters = bytes
        .iter()
        .filter(|byte| byte.is_ascii_lowercase())
        .count();
    let vowels = bytes.iter().filter(|&&byte| is_vowel(byte)).count();
    letters > 0 && vowels * RANDOM_VOWEL_ONE_IN < letters
}

/// How many times the bytes of `bytes` change from a letter to a digit or from a digit to a letter.
fn switches(bytes: &[u8]) -> usize {
    bytes
        .windows(2)
        .filter(|pair| pair[0].is_ascii_digit() != pair[1].is_ascii_digit())
        .count()
}

/// Whether the Shannon entropy of the characters of `bytes`, which are `a-z` and `0-9`, is at
/// least [`RANDOM_ENTROPY_SHARE`] of the log2 of their number.
fn entropy_is_high(bytes: &[u8]) -> bool {
    let mut counts = [0u32; 36];
    for &byte in bytes {
        let slot = if byte.is_ascii_digit() {
            26 + usize::from(byte - b'0')
        } else {
            usize::from(byte - b'a')
        };
        if let Some(count) = counts.get_mut(slot) {
            *count += 1;
        }
    }
    let total = f64::from(u32::try_from(bytes.len()).unwrap_or(u32::MAX));
    let entropy: f64 = counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let share = f64::from(count) / total;
            -share * share.log2()
        })
        .sum();
    entropy >= RANDOM_ENTROPY_SHARE * total.log2()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire form of `name`, with the length of each label ahead of it and the root at the end.
    fn wire(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.').filter(|label| !label.is_empty()) {
            out.push(u8::try_from(label.len()).unwrap());
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    /// What `decode` gives for `bytes`.
    fn decoded(bytes: &[u8]) -> Option<String> {
        let mut buf = [0u8; NAME_TEXT_MAX];
        decode(bytes, &mut buf).map(str::to_owned)
    }

    #[test]
    fn a_name_on_the_wire_is_decoded_to_lower_case_text_without_a_trailing_dot() {
        assert_eq!(
            decoded(&wire("www.example.org")).as_deref(),
            Some("www.example.org")
        );
        assert_eq!(
            decoded(&wire("WwW.ExAmPlE.OrG")).as_deref(),
            Some("www.example.org")
        );
        assert_eq!(decoded(&wire("printer")).as_deref(), Some("printer"));
        assert_eq!(
            decoded(&wire("_dmarc.xn--e1afmkfd.example-1.org")).as_deref(),
            Some("_dmarc.xn--e1afmkfd.example-1.org")
        );
        // Bytes after the root are not part of the name.
        let mut bytes = wire("example.org");
        bytes.extend_from_slice(&[0, 1, 0, 1]);
        assert_eq!(decoded(&bytes).as_deref(), Some("example.org"));
    }

    #[test]
    fn a_name_that_is_not_a_host_name_is_not_decoded() {
        // The root has no name.
        assert_eq!(decoded(&[0]), None);
        assert_eq!(decoded(&[]), None);
        // Not ended, a label that runs past the end, a pointer, and a label over 63 bytes.
        assert_eq!(decoded(&[3, b'w', b'w', b'w']), None);
        assert_eq!(decoded(&[5, b'a', b'b', 0]), None);
        assert_eq!(decoded(&[0xC0, 12]), None);
        let mut long = vec![64];
        long.extend_from_slice(&[b'a'; 64]);
        long.push(0);
        assert_eq!(decoded(&long), None);
        // Bytes that no host name has: a space, a dot inside a label, a star, a high byte.
        for bad in [&b"a b"[..], b"a.b", b"a*b", b"caf\xc3\xa9"] {
            let mut bytes = vec![u8::try_from(bad.len()).unwrap()];
            bytes.extend_from_slice(bad);
            bytes.push(0);
            assert_eq!(decoded(&bytes), None, "{bad:?}");
        }
    }

    /// What `decode_lenient` gives for `bytes`, as the parts that a test looks at.
    fn lenient(bytes: &[u8]) -> Option<(String, Option<String>, Vec<u8>, bool)> {
        let mut buf = [0u8; NAME_TEXT_MAX];
        decode_lenient(bytes, &mut buf).map(|name| {
            (
                name.text.to_owned(),
                name.registrable.map(str::to_owned),
                name.left.to_vec(),
                name.left_odd,
            )
        })
    }

    /// A name's wire form made of the labels `labels`, each as bytes, and the root.
    fn wire_of_labels(labels: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for label in labels {
            out.push(u8::try_from(label.len()).unwrap());
            out.extend_from_slice(label);
        }
        out.push(0);
        out
    }

    #[test]
    fn a_name_with_odd_bytes_is_read_with_its_domain_and_the_wire_form_of_the_rest() {
        let bytes = wire_of_labels(&[b"Ab+c", b"\xbc\xff", b"t", b"Example", b"com"]);
        let (text, domain, left, odd) = lenient(&bytes).unwrap();
        assert_eq!(text, "ab?c.??.t.example.com");
        assert_eq!(domain.as_deref(), Some("example.com"));
        assert_eq!(
            left,
            bytes[..bytes.len() - 13],
            "up to the length byte of the domain"
        );
        assert_eq!(
            left,
            [&[4u8][..], b"Ab+c", &[2, 0xbc, 0xff], &[1, b't']].concat()
        );
        assert!(odd);
        // The same names, `?` apart, read as one.
        assert_eq!(decoded(&bytes), None);
    }

    #[test]
    fn the_length_bytes_of_the_labels_are_not_odd_bytes_and_a_clean_name_has_none() {
        // A label of 10 bytes has the length byte 10, which is no byte of a host name.
        let bytes = wire_of_labels(&[b"abcdefghij", b"example", b"org"]);
        let (text, domain, left, odd) = lenient(&bytes).unwrap();
        assert_eq!(text, "abcdefghij.example.org");
        assert_eq!(domain.as_deref(), Some("example.org"));
        assert_eq!(left, [&[10u8][..], b"abcdefghij"].concat());
        assert!(!odd);
        // The odd byte is in the domain: it has no registrable domain, and what is left is clean.
        let bytes = wire_of_labels(&[b"abcdefghij", b"exa+mple", b"org"]);
        let (text, domain, left, odd) = lenient(&bytes).unwrap();
        assert_eq!(text, "abcdefghij.exa?mple.org");
        assert_eq!(domain, None);
        assert_eq!(left, [&[10u8][..], b"abcdefghij"].concat());
        assert!(!odd);
    }

    #[test]
    fn a_name_that_is_no_more_than_its_domain_has_nothing_left_of_it() {
        for labels in [&[&b"a+b"[..]][..], &[b"a+b", b"com"], &[b"co", b"uk"]] {
            let (_, _, left, odd) = lenient(&wire_of_labels(labels)).unwrap();
            assert!(left.is_empty());
            assert!(!odd);
        }
        // Under a country's second level the domain has three labels.
        let bytes = wire_of_labels(&[b"x+y", b"example", b"co", b"uk"]);
        let (_, domain, left, odd) = lenient(&bytes).unwrap();
        assert_eq!(domain.as_deref(), Some("example.co.uk"));
        assert_eq!(left, [3, b'x', b'+', b'y']);
        assert!(odd);
        let mut buf = [0u8; NAME_TEXT_MAX];
        let name = decode_lenient(&bytes, &mut buf).unwrap();
        assert_eq!(name.left_len(), 3);
    }

    #[test]
    fn a_name_without_the_shape_of_a_name_is_not_read_even_leniently() {
        assert_eq!(lenient(&[0]), None);
        assert_eq!(lenient(&[]), None);
        assert_eq!(lenient(&[3, b'w', b'w', b'w']), None);
        assert_eq!(lenient(&[5, b'a', b'b', 0]), None);
        assert_eq!(lenient(&[0xC0, 12]), None);
        let mut long = vec![64];
        long.extend_from_slice(&[b'a'; 64]);
        long.push(0);
        assert_eq!(lenient(&long), None);
        // Too long as text for the buffer: 127 labels of one byte are 253, one more is not.
        let labels: Vec<&[u8]> = vec![b"\xff"; 127];
        assert!(lenient(&wire_of_labels(&labels)).is_some());
        let labels: Vec<&[u8]> = vec![b"\xff"; 128];
        assert_eq!(lenient(&wire_of_labels(&labels)), None);
    }

    #[test]
    fn the_longest_name_is_decoded_and_one_more_byte_is_not() {
        // 127 labels of one character is 254 bytes of wire form without the root: too long.
        let full = ["a"; 127].join(".");
        assert_eq!(wire(&full).len(), 255);
        assert_eq!(decoded(&wire(&full)).as_deref(), Some(full.as_str()));
        assert_eq!(full.len(), NAME_TEXT_MAX);
        let mut too_long = wire(&full);
        too_long.pop();
        too_long.extend_from_slice(&[1, b'a', 0]);
        assert_eq!(decoded(&too_long), None);
    }

    #[test]
    fn the_registrable_domain_is_the_last_two_labels_or_three_under_a_country_second_level() {
        for (name, want) in [
            ("example.org", "example.org"),
            ("www.example.org", "example.org"),
            ("a.b.c.example.com", "example.com"),
            ("co.uk", "co.uk"),
            ("example.co.uk", "example.co.uk"),
            ("www.example.co.uk", "example.co.uk"),
            ("a.b.example.com.au", "example.com.au"),
            ("www.example.de", "example.de"),
            ("t.me", "t.me"),
            ("foo.t.me", "t.me"),
            ("printer", "printer"),
            ("", ""),
        ] {
            assert_eq!(registrable(name), want, "{name}");
        }
    }

    #[test]
    fn local_names_are_those_without_a_dot_or_under_a_local_suffix_at_a_label_boundary() {
        for local in [
            "printer",
            "local",
            "printer.local",
            "a.b.lan",
            "nas.home",
            "db.internal",
            "pc.localdomain",
            "router.home.arpa",
            "4.3.2.1.in-addr.arpa",
            "arpa",
            "home.arpa",
        ] {
            assert!(is_local(local), "{local}");
        }
        for public in [
            "example.org",
            "notlocal.com",
            "foo.notlocal",
            "mylan.net",
            "foo.mylan",
            "local.example.org",
            "foo.homearpa",
            "internal.example.com",
            "xhome.arpa.example.org",
        ] {
            assert!(!is_local(public), "{public}");
        }
    }

    #[test]
    fn a_name_is_under_a_suffix_if_it_is_the_suffix_or_ends_in_a_dot_and_the_suffix() {
        assert!(under("example.org", "example.org"));
        assert!(under("www.example.org", "example.org"));
        assert!(under("a.b.example.org", "example.org"));
        assert!(!under("notexample.org", "example.org"));
        assert!(!under("example.org", "www.example.org"));
        assert!(!under("example.org.evil.net", "example.org"));
        assert!(!under("", "example.org"));
        assert!(under("plex.direct", "plex.direct"));
        assert!(under("abc.plex.direct", "plex.direct"));
    }

    #[test]
    fn words_and_names_that_people_made_do_not_look_random() {
        for word in [
            "download",
            "facebook",
            "googleapis",
            "cloudfront",
            "wikipedia",
            "microsoft",
            "amazonaws",
            "cloudflare",
            "akamaiedge",
            "doubleclick",
            "googleusercontent",
            "githubusercontent",
            "microsoftonline",
            "scorecardresearch",
            "googlevideo",
            "stackoverflow",
            "windowsupdate",
            "safebrowsing",
            "instagram",
            "crystals",
            "ipv6test",
            "example-site",
            // Under 8 characters, whatever they are.
            "xkqzvbw",
            "a1b2c3",
            "",
        ] {
            assert!(!looks_random(word), "{word}");
        }
    }

    #[test]
    fn strings_that_a_program_made_up_look_random() {
        for made_up in [
            "xkqzvbwtrp",
            "a1b2c3d4e5",
            "q8z0x7v3k2m9",
            "bcdfghjk",
            "5d41402abc4b2a76b9719d911017c592",
            "kjhgfdsapoiu",
        ] {
            assert!(looks_random(made_up), "{made_up}");
        }
    }

    #[test]
    fn each_rule_of_looking_random_is_tested_by_itself() {
        // A run of five consonants, with vowels enough and no digit.
        assert!(looks_random("aeiobcdfg"));
        assert!(!looks_random("aeiobcdf"));
        // Vowels under a fifth of the letters, in runs of at most four: one in nine is under,
        // two in nine is not.
        assert_eq!(longest_consonant_run(b"bcdfaghjk"), 4);
        assert!(looks_random("bcdfaghjk"));
        assert!(!looks_random("bcdfaghja"));
        // No letter, no share of vowels: eight digits are no vowel-poor label.
        assert!(!looks_random("20240101"));
        // Three switches between a letter and a digit, and two.
        assert!(looks_random("abcdefg1h2"));
        assert!(!looks_random("abcdefg1hi"));
        // Only the entropy of a long label of all-different characters tells: no run, enough
        // vowels, no digit.
        assert!(looks_random("abcdefghijkl"));
        assert!(!looks_random("abcdefghijk"));
        assert!(!looks_random("microsoftonline"));
    }

    #[test]
    fn a_high_entropy_alone_needs_few_vowels_or_a_digit_to_look_random() {
        // Vowels at a quarter of the letters, no digit: 3 in 12 is under 30 %.
        assert!(looks_random("abcdefghijkl"));
        // Vowels at a half, no digit, no run, no switch: a compound of words, not random.
        assert!(!looks_random("abecidofugah"));
        assert!(!looks_random("stackoverflow"));
        // The same label with a digit in it is random: 5 in 11 letters are vowels, 2 switches.
        assert_eq!(switches(b"abecidofug1h"), 2);
        assert!(looks_random("abecidofug1h"));
        // 4 vowels in 13 letters is 30.8 %: not under 30 %. 3 in 12 is, and 4 in 14 (28.6 %) is.
        assert!(!vowels_under_entropy_share(b"stackoverflow"));
        assert!(vowels_under_entropy_share(b"abcdefghijkl"));
        assert!(vowels_under_entropy_share(b"abcdefghijklmo"));
        // A label of no letter has no share of vowels.
        assert!(!vowels_under_entropy_share(b"012345678901"));
    }
}
