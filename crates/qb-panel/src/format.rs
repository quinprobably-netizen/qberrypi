//! The strings the panel shows, made from its values. An unknown value is a
//! dash, never a zero, and no string can outgrow its place.

use std::net::IpAddr;

use crate::drain::AlertCard;
use crate::drain::look::{ALERT_SUBJECT_CELLS, ALERT_TITLE_CELLS, ALERT_WHO_CELLS};
use crate::touch::PAUSE_MS;

/// An unknown value: an em dash alone, with no unit.
pub const DASH: &str = "\u{2014}";

/// A counter in at most 7 characters: `10,818`, then `1.9M` and `4.2B` (cut, not rounded).
pub fn count(n: u32) -> String {
    match n {
        0..1_000 => n.to_string(),
        1_000..1_000_000 => format!("{},{:03}", n / 1_000, n % 1_000),
        1_000_000..1_000_000_000 => format!("{}.{}M", n / 1_000_000, n / 100_000 % 10),
        _ => format!("{}.{}B", n / 1_000_000_000, n / 100_000_000 % 10),
    }
}

/// What is left of a pause as `m:ss`, never more than `9:59`.
pub fn countdown(left_secs: u16) -> String {
    let secs = left_secs.min(599);
    format!("{}:{:02}", secs / 60, secs % 60)
}

/// How many steps the paused gate refills in.
const GATE_FILL_STEPS: u32 = 19;

/// The most steps the refill shows: the last one is the gate full, and a pause that is still running is never that.
const GATE_FILL_MAX: u32 = GATE_FILL_STEPS - 1;

/// How full the paused gate is, as steps of 12 pixels from the floor, 0 to 18, when `left_secs` of the pause are left.
///
/// The gate is hollow when the pause starts and refills from the floor as it runs out:
/// `floor((300 - left) * 19 / 300)`. It is 0 for a full pause or more and stops at 18 for none left.
pub fn gate_fill(left_secs: u16) -> u8 {
    let pause = u32::try_from(PAUSE_MS / 1_000).unwrap_or(u32::MAX).max(1);
    let gone = pause.saturating_sub(u32::from(left_secs));
    let steps = (u64::from(gone) * u64::from(GATE_FILL_STEPS) / u64::from(pause))
        .min(u64::from(GATE_FILL_MAX));
    u8::try_from(steps).unwrap_or(u8::MAX)
}

/// A DNS name in `cells` cells, as the lane and the alert card show it.
///
/// It is lower-case, with one trailing dot off, and every character that is
/// not printable ASCII is a `?`. A name longer than `cells` is cut so that a
/// `~` is the last cell. Only the first `cells + 1` characters are read, so a
/// name of any length costs the same.
pub fn fit_name(name: &str, cells: usize) -> String {
    let name = name.strip_suffix('.').unwrap_or(name);
    cut(
        name.chars().map(|c| printable(c.to_ascii_lowercase())),
        cells,
    )
}

/// The character itself if it is printable ASCII and not a space, else `?`.
fn printable(c: char) -> char {
    if ('!'..='~').contains(&c) { c } else { '?' }
}

/// The first `cells` characters, or fewer with a `~` last if there are more.
fn cut(chars: impl Iterator<Item = char>, cells: usize) -> String {
    let mut kept: Vec<char> = chars.take(cells.saturating_add(1)).collect();
    if kept.len() > cells {
        kept.truncate(cells.saturating_sub(1));
        if cells > 0 {
            kept.push('~');
        }
    }
    kept.into_iter().collect()
}

/// How many characters of a name `fit_site` and `wrap_name` look at, counted from its end. A DNS name is at
/// most 253, so a longer one is not a name, and the end of it is what says whose it is.
const READ_CHARS: usize = 256;

/// The last `limit` characters of a name, with the one trailing dot off, in the lane's alphabet:
/// lower-case, and a `?` for every character that is not printable ASCII.
fn tail_of(name: &str, limit: usize) -> Vec<char> {
    let name = name.strip_suffix('.').unwrap_or(name);
    let mut chars: Vec<char> = name
        .chars()
        .rev()
        .take(limit)
        .map(|c| printable(c.to_ascii_lowercase()))
        .collect();
    chars.reverse();
    chars
}

/// How many labels make the site of a name, whose labels are `labels`: three when the name ends in a
/// two-letter suffix under a short second level (`example.co.uk`), else two.
fn site_labels(labels: &[&[char]]) -> usize {
    match labels {
        [.., second, last] if labels.len() >= 3 && last.len() == 2 && second.len() <= 3 => 3,
        _ => 2,
    }
}

/// A name in at most `cells` cells, with its site kept whole where it can be.
///
/// The end of a DNS name says whose it is, so host labels go first, whole, from the left, until the
/// name fits or only the site is left: its last two labels, or three under a suffix like `co.uk`.
/// A site that is still too long is cut at its end, with a `~` last. The name is first made as
/// `fit_name` makes it: lower-case, with one trailing dot off and a `?` for every character that is
/// not printable ASCII. Only its last 256 characters are read, so a name of any length costs the same.
pub fn fit_site(name: &str, cells: usize) -> String {
    let chars = tail_of(name, READ_CHARS);
    let labels: Vec<&[char]> = chars.split(|&c| c == '.').collect();
    // The length of the labels from `first` on, joined by dots.
    let mut joined = chars.len();
    let mut first = 0;
    loop {
        let rest = labels.get(first..).unwrap_or_default();
        let Some(leading) = rest.first() else { break };
        if joined <= cells || rest.len() <= site_labels(rest) {
            break;
        }
        joined = joined.saturating_sub(leading.len() + 1);
        first += 1;
    }
    let kept: Vec<char> = labels.get(first..).unwrap_or_default().join(&'.');
    cut(kept.into_iter(), cells)
}

/// A subject on one or two lines of `cells` cells, broken after a dot.
///
/// A name that fits is one line, and the second is empty. A longer one, to twice the room, breaks
/// after the last dot at or before the end of the first line that leaves room on the second, or at
/// the end of the first line when there is no such dot. Past twice the room the start goes and a `~`
/// leads. The name is made as `fit_name` makes it; only its last `2 * cells + 1` characters are read.
pub fn wrap_name(name: &str, cells: usize) -> [String; 2] {
    if cells == 0 {
        return [String::new(), String::new()];
    }
    let whole = cells.saturating_mul(2);
    let mut chars = tail_of(name, whole.saturating_add(1));
    if chars.len() <= cells {
        return [chars.into_iter().collect(), String::new()];
    }
    if chars.len() > whole {
        // One character too many was read: the name is longer than the card's two lines.
        let from = chars.len() - (whole - 1);
        chars = std::iter::once('~')
            .chain(chars.into_iter().skip(from))
            .collect();
    }
    // The first break after a dot that leaves the second line no more than `cells`, looking back from the end of the first line.
    let least = chars.len() - cells;
    let at = (least..=cells)
        .rev()
        .find(|&at| chars.get(at.wrapping_sub(1)) == Some(&'.'))
        .unwrap_or(cells);
    let (head, tail) = chars.split_at(at.min(chars.len()));
    [head.iter().collect(), tail.iter().collect()]
}

/// The card of an alert: two title lines, the subject on one or two, and who it concerns.
///
/// The title comes from the kind: `threat` is `THREAT` over `BLOCKED`, and a
/// kind that has no title of its own is upper-cased and split at its first
/// `_`. `who` says `at <ip>` for a device that appeared (`new_device`,
/// `arp_spoof`) and `asked by <ip>` for anything else, and is empty without a
/// client. Every line is cut to the room it has on the card, and the subject is wrapped by `wrap_name`.
pub fn alert_card(kind: &str, high: bool, subject: &str, client: Option<IpAddr>) -> AlertCard {
    let line = |text: &str| {
        cut(
            text.chars().map(|c| printable(c.to_ascii_uppercase())),
            ALERT_TITLE_CELLS,
        )
    };
    let title = match kind {
        "threat" => ["THREAT", "BLOCKED"].map(line),
        "rebind" => ["REBIND", "BLOCKED"].map(line),
        "dga" => ["RANDOM", "NAMES"].map(line),
        "tunnel" => ["DNS", "TUNNEL"].map(line),
        "beacon" => ["BEACON", "SEEN"].map(line),
        "burst" => ["QUERY", "BURST"].map(line),
        "new_device" => ["NEW", "DEVICE"].map(line),
        "arp_spoof" => ["ARP", "SPOOF"].map(line),
        other => {
            let (first, rest) = other.split_once('_').unwrap_or((other, ""));
            [first, rest].map(line)
        }
    };
    let who = client.map_or_else(String::new, |ip| {
        let who = match kind {
            "new_device" | "arp_spoof" => format!("at {ip}"),
            _ => format!("asked by {ip}"),
        };
        cut(who.chars(), ALERT_WHO_CELLS)
    });
    AlertCard {
        high,
        title,
        subject: wrap_name(subject, ALERT_SUBJECT_CELLS),
        who,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_get_separators_then_a_unit() {
        for (n, s) in [
            (0, "0"),
            (999, "999"),
            (1000, "1,000"),
            (4780, "4,780"),
            (999_999, "999,999"),
            (1_000_000, "1.0M"),
            (1_949_999, "1.9M"),
            (999_999_999, "999.9M"),
            (1_000_000_000, "1.0B"),
            (u32::MAX, "4.2B"),
        ] {
            assert_eq!(count(n), s);
        }
    }

    #[test]
    fn a_count_never_outgrows_seven_characters() {
        // Every decade boundary of a `u32` and its two neighbours, and the largest value.
        let mut edges = vec![u32::MAX];
        for power in 0..=9 {
            let decade = 10_u32.pow(power);
            edges.extend([decade - 1, decade, decade + 1]);
        }
        for n in edges {
            assert!(count(n).chars().count() <= 7, "{n}: {}", count(n));
        }
    }

    #[test]
    fn a_countdown_is_minutes_and_seconds_and_stops_at_nine_fifty_nine() {
        for (s, t) in [
            (299, "4:59"),
            (300, "5:00"),
            (277, "4:37"),
            (60, "1:00"),
            (1, "0:01"),
            (0, "0:00"),
            (u16::MAX, "9:59"),
        ] {
            assert_eq!(countdown(s), t);
        }
    }

    #[test]
    fn gate_fill_steps() {
        // A full pause is an empty gate, and each step is a nineteenth of it.
        assert_eq!(gate_fill(300), 0);
        assert_eq!(
            gate_fill(u16::MAX),
            0,
            "more than a pause is none of it gone"
        );
        assert_eq!(gate_fill(299), 0);
        assert_eq!(gate_fill(285), 0, "15 s gone is 0.95 of a step");
        assert_eq!(gate_fill(284), 1);
        assert_eq!(gate_fill(277), 1, "the mockup's 4:37");
        assert_eq!(gate_fill(150), 9);
        assert_eq!(gate_fill(1), 18);
        assert_eq!(gate_fill(0), 18, "the last step is as full as it shows");
        // Never more than 18, never backwards: the steps only go up as the time runs out.
        let mut last = 0;
        for left in (0..=300).rev() {
            let fill = gate_fill(left);
            assert!(fill >= last && fill <= 18, "{left}: {fill}");
            last = fill;
        }
        assert_eq!(last, 18);
        assert_eq!(
            (0..=300).map(gate_fill).filter(|&f| f == 0).count(),
            16,
            "left 285..=300 is the first step"
        );
    }

    #[test]
    fn fit_site_drops_host_labels_then_cuts() {
        // The mockup's examples, at the 15 cells a refused name stops in.
        assert_eq!(
            fit_site("pagead2.googlesyndication.com", 15),
            "googlesyndicat~"
        );
        assert_eq!(fit_site("rubiconproject.com", 15), "rubiconproject~");
        assert_eq!(fit_site("doubleclick.net", 15), "doubleclick.net");
        assert_eq!(fit_site("scorecardresearch.com", 15), "scorecardresea~");
        // Host labels go whole, from the left, and the site is what is read.
        assert_eq!(
            fit_site("a.very.long.tracker.example.org", 20),
            "tracker.example.org"
        );
        assert_eq!(
            fit_site("a.very.long.tracker.example.org", 15),
            "example.org"
        );
        assert_eq!(fit_site("one.example.org", 20), "one.example.org");
        assert_eq!(fit_site("one.example.org", 15), "one.example.org");
        assert_eq!(fit_site("one.example.org", 11), "example.org");
        // A name that fits is left alone, one cell over it is not.
        assert_eq!(fit_site("abcdefghij.example.c", 20), "abcdefghij.example.c");
        assert_eq!(
            fit_site("abcdefghij.example.co", 20),
            "example.co",
            "21 cells: the host goes"
        );
        // Under a two-letter suffix with a short second level the site is three labels.
        assert_eq!(fit_site("a.b.example.co.uk", 13), "example.co.uk");
        assert_eq!(fit_site("a.b.example.co.uk", 15), "b.example.co.uk");
        assert_eq!(fit_site("a.b.example.co.uk", 20), "a.b.example.co.uk");
        assert_eq!(fit_site("a.b.c.example.co.uk", 15), "c.example.co.uk");
        assert_eq!(
            fit_site("a.b.example.co.uk", 10),
            "example.c~",
            "the site is cut at its end"
        );
        assert_eq!(fit_site("a.b.shop.co.uk", 8), "shop.co~");
        // A suffix of more than two letters, or a second level of four or more under one of two, is
        // not three labels: only the last two are the site.
        assert_eq!(fit_site("a.b.example.com", 11), "example.com");
        assert_eq!(fit_site("a.b.example.de", 10), "example.de");
        assert_eq!(
            fit_site("a.b.exam.co.uk", 5),
            "exam~",
            "exam.co.uk is the site, and is cut"
        );
        assert_eq!(fit_site("a.b.c.d.example.com.au", 14), "example.com.au");
        // The name is made as `fit_name` makes it first: lower-case, one trailing dot off, `?` for the odd.
        assert_eq!(fit_site("WWW.Example.ORG.", 11), "example.org");
        assert_eq!(
            fit_site("b\u{fc}cher.example.org", 20),
            "b?cher.example.org"
        );
        assert_eq!(fit_site("a\u{7}b c\u{1F4A9}d", 20), "a?b?c?d");
        assert_eq!(fit_site("a.b..", 20), "a.b.", "a second trailing dot stays");
        // Names with no dots, or only dots, have no host labels to drop.
        assert_eq!(fit_site("localhost", 15), "localhost");
        assert_eq!(
            fit_site(&"a".repeat(253), 15),
            format!("{}~", "a".repeat(14))
        );
        assert_eq!(fit_site("..", 15), ".", "one trailing dot goes");
        assert_eq!(fit_site("", 15), "");
        assert_eq!(
            fit_site(".", 15),
            "",
            "a lone dot is the root: nothing to show"
        );
        // The extremes of the cell count.
        assert_eq!(fit_site("abc.example", 0), "");
        assert_eq!(fit_site("abc.example", 1), "~");
        assert_eq!(fit_site("a", 1), "a");
    }

    #[test]
    fn fit_site_never_exceeds_its_cells_and_costs_a_bounded_amount() {
        // A DNS name at its longest, in labels of every length, in odd alphabets, and at every width.
        let mut names = vec![
            "a".repeat(253),
            "a.".repeat(126) + "b",
            format!(
                "{}.{}.{}.{}",
                "x".repeat(63),
                "y".repeat(63),
                "z".repeat(63),
                "w".repeat(61)
            ),
            format!("{}.co.uk", "q".repeat(250)),
            "\u{1F4A9}".repeat(253),
            format!("{}.example.co.uk", "h.".repeat(120)),
            ".".repeat(300),
            "a.b.c.example.co.uk".to_string(),
            "co.uk".to_string(),
            "x.co.uk".to_string(),
            "x.y.co.uk".to_string(),
        ];
        // Names with no site worth the name at all, and a megabyte of them.
        names.push("é".repeat(1 << 20));
        names.push(format!("{}.example.org", "m".repeat(1 << 20)));
        for cells in [0, 1, 2, 5, 14, 15, 16, 20, 26] {
            for name in &names {
                let fitted = fit_site(name, cells);
                assert!(
                    fitted.chars().count() <= cells,
                    "{cells} cells: {}",
                    fitted.len()
                );
                assert!(fitted.chars().all(|c| ('!'..='~').contains(&c)));
            }
        }
        // The end of a name is what is read, even when the name is longer than any name can be.
        assert_eq!(
            fit_site(&format!("{}.example.org", "m".repeat(1 << 20)), 15),
            "example.org"
        );
        // Every prefix of a long, dotted name, at both widths.
        let long = "ab.cde.fg.hijk.example.co.uk";
        for len in 0..=long.len() {
            for cells in [15, 20] {
                assert!(fit_site(&long[..len], cells).chars().count() <= cells);
            }
        }
    }

    #[test]
    fn wrap_name_breaks_after_a_dot_and_costs_a_bounded_amount() {
        let wrap = |name: &str| wrap_name(name, 26);
        assert_eq!(
            wrap("secure-login-verify.top"),
            ["secure-login-verify.top", ""]
        );
        assert_eq!(
            wrap("secure-login-verify.example.org"),
            ["secure-login-verify.", "example.org"]
        );
        // A name of any length costs the same, and keeps its end.
        let huge = format!("{}.example.org", "x".repeat(1 << 20));
        let [first, second] = wrap(&huge);
        assert_eq!(first, format!("~{}", "x".repeat(25)));
        assert_eq!(second, format!("{}.example.org", "x".repeat(14)));
        // 52 cells is two full lines; 53 loses its start.
        assert_eq!(wrap(&"y".repeat(52)), ["y".repeat(26), "y".repeat(26)]);
        assert_eq!(
            wrap(&"y".repeat(53)),
            [format!("~{}", "y".repeat(25)), "y".repeat(26)]
        );
        assert_eq!(wrap("a.b..").concat(), "a.b.", "one trailing dot goes");
        assert_eq!(wrap("W\u{fc}.EXAMPLE.org"), ["w?.example.org", ""]);
        assert_eq!(wrap_name("abc", 0), [String::new(), String::new()]);
        assert_eq!(wrap_name("abc", 1), ["~", "c"]);
    }
}
