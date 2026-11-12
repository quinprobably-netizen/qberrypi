//! The set of blocked and allowed names: sorted name tables, their builder and the lookup.

use crate::name::{MAX_NAME_LEN, normalize};
use crate::parse::{ListStats, RuleKind, parse_list};
use core::cmp::Ordering;

/// A `deny` or `allow` entry of the configuration that is not a valid domain name.
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidName(
    /// The entry as given.
    pub String,
);

/// What kind of list a rule came from. A threat is a name from a list of malware, phishing and
/// scam names, which a caller may want to tell apart from an ordinary ad or tracker. The class
/// costs one bit per stored name and one bit test per entry a lookup finds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListClass {
    /// An ad, tracker or other nuisance; also every `deny` entry of the configuration.
    Ads,
    /// A malware, phishing or scam name. It wins over [`ListClass::Ads`] wherever both match.
    Threat,
}

/// Collects rules from lists and from the configuration, then builds the [`BlockSet`].
#[derive(Default)]
pub struct BlockSetBuilder {
    /// Names blocked on their own, from hosts lines.
    exact: PendingNames,
    /// Names blocked with their subdomains, from `||name^` lines and `deny`.
    suffix: PendingNames,
    /// Names never blocked, nor their subdomains, from `allow`.
    allow: PendingNames,
}

impl BlockSetBuilder {
    /// A builder with no rules.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds the rules of a whole list of ads, or of a chunk of one that ends at a line break,
    /// and returns what its lines came to: [`add_list_as`](Self::add_list_as) with
    /// [`ListClass::Ads`]. Never panics, whatever the bytes.
    pub fn add_list(&mut self, text: &[u8]) -> ListStats {
        self.add_list_as(text, ListClass::Ads)
    }

    /// Adds the rules of a whole list of the given class, or of a chunk of one that ends at a
    /// line break, and returns what its lines came to. A name that is on lists of both classes
    /// is stored once, as a threat. Never panics, whatever the bytes.
    ///
    /// A name that would start past 4 GiB of names already stored is dropped all the same, and
    /// still counted in the result.
    pub fn add_list_as(&mut self, text: &[u8], class: ListClass) -> ListStats {
        let threat = class == ListClass::Threat;
        parse_list(text, |kind, name| match kind {
            RuleKind::Exact => self.exact.push(name, threat),
            RuleKind::Suffix => self.suffix.push(name, threat),
        })
    }

    /// Blocks `name` and its subdomains as an ad; the name is normalised first. A name that
    /// would start past 4 GiB of names already stored is dropped, and `Ok` is returned all the
    /// same.
    pub fn deny(&mut self, name: &str) -> Result<(), InvalidName> {
        self.suffix.push_entry(name)
    }

    /// Exempts `name` and its subdomains from every list and from `deny`; the name is
    /// normalised first. A name that would start past 4 GiB of names already stored is dropped,
    /// and `Ok` is returned all the same.
    pub fn allow(&mut self, name: &str) -> Result<(), InvalidName> {
        self.allow.push_entry(name)
    }

    /// The capacity of the builder's buffers, in bytes.
    pub fn heap_bytes(&self) -> usize {
        self.exact.heap_bytes() + self.suffix.heap_bytes() + self.allow.heap_bytes()
    }

    /// Sorts the names, drops the duplicates and packs each table into buffers of exact size.
    pub fn build(self) -> BlockSet {
        // One table at a time, so that each unsorted buffer is freed before the next is packed.
        BlockSet {
            exact: self.exact.build(),
            suffix: self.suffix.build(),
            allow: self.allow.build(),
        }
    }
}

/// The blocked and the allowed names, each kind in a sorted table of its own.
#[derive(Default)]
pub struct BlockSet {
    /// Names blocked on their own.
    exact: NameTable,
    /// Names blocked with their subdomains.
    suffix: NameTable,
    /// Names never blocked, nor their subdomains.
    allow: NameTable,
}

impl BlockSet {
    /// Whether `name`, already normalised (lower case, no trailing dot), is to be blocked: it or
    /// a parent is listed, and neither it nor a parent is allowed. Allocates nothing.
    ///
    /// This is [`verdict`](Self::verdict) with the class dropped.
    pub fn is_blocked(&self, name: &str) -> bool {
        self.verdict(name).is_some()
    }

    /// The class of the block that applies to `name`, already normalised (lower case, no
    /// trailing dot), or `None` if the name is not blocked: neither it nor a parent is listed,
    /// or it or a parent is allowed. Allocates nothing.
    ///
    /// Where several entries match (the name on an exact entry, a parent on a suffix entry, a
    /// grandparent on another), a threat among them makes the verdict a threat. The class costs
    /// one bit test for each entry found. A name that hits an ad, in a set that also holds threat
    /// suffix entries, is looked up under each of its parents too, as a name that misses always
    /// is, because a threat could still be among them; with no such entries, or once a threat is
    /// found, the walk looks only for an allowed parent, as it did before there were classes.
    pub fn verdict(&self, name: &str) -> Option<ListClass> {
        let mut class = self.exact.class_of(name);
        // The name itself, then each parent: one label shorter every time round.
        let mut covering = name;
        loop {
            if self.allow.find(covering).is_some() {
                return None;
            }
            // A threat cannot be outranked, and an ad cannot be while no suffix entry is a
            // threat: either way the other suffix searches of the walk would find nothing new.
            let settled =
                class == Some(ListClass::Threat) || (class.is_some() && self.suffix.threats == 0);
            if !settled {
                class = stronger(class, self.suffix.class_of(covering));
            }
            match covering.split_once('.') {
                Some((_, parent)) => covering = parent,
                None => return class,
            }
        }
    }

    /// How many distinct names are blocked on their own.
    pub fn exact_len(&self) -> usize {
        self.exact.len()
    }

    /// How many distinct names are blocked with their subdomains.
    pub fn suffix_len(&self) -> usize {
        self.suffix.len()
    }

    /// How many distinct names are allowed with their subdomains.
    pub fn allow_len(&self) -> usize {
        self.allow.len()
    }

    /// How many of the distinct names blocked on their own or with their subdomains are
    /// threats; a name counts once however many lists it is on.
    pub fn threat_len(&self) -> usize {
        self.exact.threats + self.suffix.threats
    }

    /// The capacity of the set's buffers, in bytes: the bytes of every name, 4 more per name for
    /// where it ends, and 1 bit more per name for its class, rounded up to whole 8-byte words
    /// for each table.
    pub fn heap_bytes(&self) -> usize {
        self.exact.heap_bytes() + self.suffix.heap_bytes() + self.allow.heap_bytes()
    }
}

/// The stronger of two classes found for one name: a threat outranks an ad, and an ad outranks
/// no class at all.
fn stronger(a: Option<ListClass>, b: Option<ListClass>) -> Option<ListClass> {
    match (a, b) {
        (Some(ListClass::Threat), _) | (_, Some(ListClass::Threat)) => Some(ListClass::Threat),
        (Some(ListClass::Ads), _) | (_, Some(ListClass::Ads)) => Some(ListClass::Ads),
        (None, None) => None,
    }
}

/// Where one name lies in the buffer of a [`PendingNames`].
#[derive(Clone, Copy)]
struct Span {
    /// The offset of the name's first byte.
    start: u32,
    /// The name's length; a valid name has at most 253 bytes.
    len: u8,
    /// Whether the name came from a threat list. Fits in the padding: a span stays 8 bytes.
    threat: bool,
}

/// Normalised names in the order they were added, duplicates and all.
#[derive(Default)]
struct PendingNames {
    /// The names, one after another with nothing between them.
    bytes: Vec<u8>,
    /// Where each name lies in `bytes`.
    index: Vec<Span>,
}

impl PendingNames {
    /// Adds a normalised name, from a threat list or not. One that would start past what a `u32`
    /// offset can reach (4 GiB of names) is left out.
    fn push(&mut self, name: &str, threat: bool) {
        let (Ok(start), Ok(len)) = (u32::try_from(self.bytes.len()), u8::try_from(name.len()))
        else {
            return;
        };
        self.bytes.extend_from_slice(name.as_bytes());
        self.index.push(Span { start, len, threat });
    }

    /// Normalises an entry of the configuration and adds it as an ordinary name, or reports it
    /// as invalid.
    fn push_entry(&mut self, entry: &str) -> Result<(), InvalidName> {
        let mut buf = [0; MAX_NAME_LEN];
        let name =
            normalize(entry.as_bytes(), &mut buf).ok_or_else(|| InvalidName(entry.to_owned()))?;
        self.push(name, false);
        Ok(())
    }

    /// The capacity of the two buffers, in bytes.
    fn heap_bytes(&self) -> usize {
        self.bytes.capacity() + self.index.capacity() * size_of::<Span>()
    }

    /// Sorts the names bytewise, drops the duplicates (a name that is a threat on any of its
    /// copies stays one) and packs the rest, with a bit for each name that is a threat.
    fn build(self) -> NameTable {
        let Self {
            bytes: unsorted,
            mut index,
        } = self;
        let name = |span: &Span| {
            let start = span.start as usize;
            unsorted
                .get(start..start + usize::from(span.len))
                .unwrap_or_default()
        };
        index.sort_unstable_by(|a, b| name(a).cmp(name(b)));
        // `later` is the copy that follows `kept`, which stays.
        index.dedup_by(|later, kept| {
            let same = name(later) == name(kept);
            if same {
                kept.threat |= later.threat;
            }
            same
        });

        let mut ends = Vec::with_capacity(index.len());
        let mut end = 0_u32;
        for span in &index {
            // Names past what a `u32` end offset can reach (4 GiB of them) are left out.
            let Some(next) = end.checked_add(u32::from(span.len)) else {
                break;
            };
            end = next;
            ends.push(end);
        }
        let mut bytes = Vec::with_capacity(end as usize);
        for span in index.iter().take(ends.len()) {
            bytes.extend_from_slice(name(span));
        }
        let mut threat = vec![0_u64; ends.len().div_ceil(64)];
        let mut threats = 0;
        for (i, span) in index.iter().take(ends.len()).enumerate() {
            if let (true, Some(word)) = (span.threat, threat.get_mut(i / 64)) {
                *word |= 1 << (i % 64);
                threats += 1;
            }
        }
        NameTable {
            bytes,
            ends,
            threat,
            threats,
        }
    }
}

/// Distinct names in bytewise order, packed end to end, and one class bit for each.
#[derive(Default)]
struct NameTable {
    /// The names, one after another with nothing between them.
    bytes: Vec<u8>,
    /// `ends[i]` is where name `i` ends in `bytes`; it starts where the name before it ends.
    ends: Vec<u32>,
    /// Bit `i % 64` of word `i / 64` is set if name `i` is a threat; one word holds 64 names.
    threat: Vec<u64>,
    /// How many bits of `threat` are set.
    threats: usize,
}

impl NameTable {
    /// How many names the table holds.
    fn len(&self) -> usize {
        self.ends.len()
    }

    /// The capacity of the three buffers, in bytes.
    fn heap_bytes(&self) -> usize {
        self.bytes.capacity()
            + self.ends.capacity() * size_of::<u32>()
            + self.threat.capacity() * size_of::<u64>()
    }

    /// Whether name `i` is a threat; `false` if there is no such name.
    fn is_threat(&self, i: usize) -> bool {
        self.threat
            .get(i / 64)
            .is_some_and(|word| (word >> (i % 64)) & 1 == 1)
    }

    /// Name `i`, or the empty name if there is none.
    fn name(&self, i: usize) -> &[u8] {
        let start = i
            .checked_sub(1)
            .and_then(|before| self.ends.get(before))
            .map_or(0, |&end| end as usize);
        let end = self.ends.get(i).map_or(start, |&end| end as usize);
        self.bytes.get(start..end).unwrap_or_default()
    }

    /// Where `name` is in the table, if it is: a binary search, which allocates nothing.
    fn find(&self, name: &str) -> Option<usize> {
        let (mut low, mut high) = (0, self.ends.len());
        while low < high {
            let mid = low + (high - low) / 2;
            match self.name(mid).cmp(name.as_bytes()) {
                Ordering::Less => low = mid + 1,
                Ordering::Greater => high = mid,
                Ordering::Equal => return Some(mid),
            }
        }
        None
    }

    /// The class of `name` if it is in the table. The allow table has no threats, so it is not
    /// asked.
    fn class_of(&self, name: &str) -> Option<ListClass> {
        self.find(name).map(|i| {
            if self.is_threat(i) {
                ListClass::Threat
            } else {
                ListClass::Ads
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Rng;

    const HOSTS: &[u8] = include_bytes!("../tests/fixtures/hosts-sample.txt");
    const ADBLOCK: &[u8] = include_bytes!("../tests/fixtures/adblock-sample.txt");

    fn set() -> BlockSet {
        let mut b = BlockSetBuilder::new();
        b.add_list(b"0.0.0.0 exact.example.com\n||suffix.example.net^\n||test^\n0.0.0.0 exact.example.com\n");
        b.deny("Denied.Example.ORG.").unwrap();
        b.deny("ads.allowed.example.org").unwrap();
        b.allow("ok.suffix.example.net").unwrap();
        b.allow("allowed.example.org").unwrap();
        b.build()
    }

    /// The names and end offsets of the three tables, to compare two sets.
    fn tables(s: &BlockSet) -> [(&[u8], &[u32]); 3] {
        [&s.exact, &s.suffix, &s.allow].map(|t| (t.bytes.as_slice(), t.ends.as_slice()))
    }

    #[test]
    fn exact_rules_match_only_the_name() {
        let s = set();
        assert!(s.is_blocked("exact.example.com"));
        assert!(
            !s.is_blocked("sub.exact.example.com")
                && !s.is_blocked("example.com")
                && !s.is_blocked("xexact.example.com")
        );
    }

    #[test]
    fn suffix_rules_cover_subdomains_at_label_boundaries() {
        let s = set();
        assert!(s.is_blocked("suffix.example.net") && s.is_blocked("a.b.suffix.example.net"));
        assert!(!s.is_blocked("notsuffix.example.net") && !s.is_blocked("example.net"));
        assert!(s.is_blocked("test") && s.is_blocked("anything.test") && !s.is_blocked("contest"));
    }

    #[test]
    fn deny_and_allow_cover_subdomains_and_allow_wins() {
        let s = set();
        assert!(s.is_blocked("denied.example.org") && s.is_blocked("x.denied.example.org"));
        assert!(
            !s.is_blocked("ok.suffix.example.net") && !s.is_blocked("deep.ok.suffix.example.net")
        );
        assert!(s.is_blocked("other.suffix.example.net"));
        assert!(!s.is_blocked("ads.allowed.example.org"));
    }

    #[test]
    fn invalid_config_names_are_reported() {
        let mut b = BlockSetBuilder::new();
        assert_eq!(b.deny("not a name"), Err(InvalidName("not a name".into())));
        assert_eq!(b.allow(""), Err(InvalidName(String::new())));
        assert_eq!(b.build().suffix_len(), 0);
    }

    #[test]
    fn duplicates_are_stored_once_and_the_heap_is_what_the_layout_says() {
        let s = set();
        assert_eq!((s.exact_len(), s.suffix_len(), s.allow_len()), (1, 4, 2));
        // Name bytes, 4 bytes per name, then one 8-byte word of class bits per table (none has
        // more than 64 names).
        assert_eq!(
            s.heap_bytes(),
            (17 + (18 + 4 + 18 + 23) + (21 + 19)) + 4 * 7 + 3 * 8
        );
        // Sorted bytewise, whatever the order they were added in.
        assert_eq!(
            tables(&s)[1],
            (
                &b"ads.allowed.example.orgdenied.example.orgsuffix.example.nettest"[..],
                &[23, 41, 59, 63][..]
            )
        );
        let empty = BlockSet::default();
        assert!(
            !empty.is_blocked("example.com") && !empty.is_blocked("") && empty.heap_bytes() == 0
        );
        assert_eq!(BlockSetBuilder::new().heap_bytes(), 0);
    }

    #[test]
    fn threat_entries_carry_their_class() {
        let mut b = BlockSetBuilder::new();
        b.add_list(b"0.0.0.0 ad.example.com\n");
        b.add_list_as(
            b"||bad.example.net^\n0.0.0.0 phish.example.org\n",
            ListClass::Threat,
        );
        let s = b.build();
        assert_eq!(s.verdict("ad.example.com"), Some(ListClass::Ads));
        assert_eq!(s.verdict("x.bad.example.net"), Some(ListClass::Threat));
        assert_eq!(s.verdict("phish.example.org"), Some(ListClass::Threat));
        assert_eq!(s.verdict("example.org"), None);
        assert_eq!(s.threat_len(), 2);
        assert!(s.is_blocked("ad.example.com") && !s.is_blocked("example.org"));
    }

    #[test]
    fn a_name_on_both_classes_is_a_threat() {
        for ads_first in [true, false] {
            for (text, exact) in [
                (&b"0.0.0.0 dual.example.com\n"[..], true),
                (&b"||dual.example.com^\n"[..], false),
            ] {
                let mut b = BlockSetBuilder::new();
                if ads_first {
                    b.add_list_as(text, ListClass::Ads);
                    b.add_list_as(text, ListClass::Threat);
                } else {
                    b.add_list_as(text, ListClass::Threat);
                    b.add_list_as(text, ListClass::Ads);
                }
                let s = b.build();
                assert_eq!(s.verdict("dual.example.com"), Some(ListClass::Threat));
                assert_eq!(
                    (s.exact_len(), s.suffix_len(), s.threat_len()),
                    if exact { (1, 0, 1) } else { (0, 1, 1) },
                    "ads first: {ads_first}"
                );
            }
        }
    }

    #[test]
    fn an_ads_exact_entry_under_a_threat_suffix_is_a_threat() {
        let mut b = BlockSetBuilder::new();
        b.add_list_as(b"0.0.0.0 a.bad.example.net\n", ListClass::Ads);
        b.add_list_as(b"||bad.example.net^\n", ListClass::Threat);
        let s = b.build();
        assert_eq!(s.verdict("a.bad.example.net"), Some(ListClass::Threat));
        assert_eq!(s.verdict("bad.example.net"), Some(ListClass::Threat));

        let mut b = BlockSetBuilder::new();
        b.add_list_as(b"||example.net^\n", ListClass::Ads);
        b.add_list_as(b"0.0.0.0 bad.example.net\n", ListClass::Threat);
        let s = b.build();
        assert_eq!(s.verdict("bad.example.net"), Some(ListClass::Threat));
        assert_eq!(s.verdict("other.example.net"), Some(ListClass::Ads));
        // The threat entry is exact, so it does not reach a subdomain.
        assert_eq!(s.verdict("x.bad.example.net"), Some(ListClass::Ads));
    }

    #[test]
    fn allow_beats_a_threat() {
        let mut b = BlockSetBuilder::new();
        b.add_list_as(b"||bad.example.net^\n", ListClass::Threat);
        b.add_list_as(b"0.0.0.0 ok.bad.example.net\n", ListClass::Threat);
        b.allow("ok.bad.example.net").unwrap();
        let s = b.build();
        assert_eq!(s.verdict("ok.bad.example.net"), None);
        assert_eq!(s.verdict("x.ok.bad.example.net"), None);
        assert_eq!(s.verdict("bad.example.net"), Some(ListClass::Threat));
        assert_eq!(s.verdict("y.bad.example.net"), Some(ListClass::Threat));
        assert!(!s.is_blocked("ok.bad.example.net"));
    }

    #[test]
    fn class_bits_hold_past_64_entries() {
        let (mut ads, mut threat) = (String::new(), String::new());
        for i in 0..200 {
            // Parity gives the class and the next bit gives the table, so both tables have both.
            let line = if (i / 2) % 2 == 0 {
                format!("0.0.0.0 n{i}.example.com\n")
            } else {
                format!("||n{i}.example.com^\n")
            };
            if i % 2 == 0 { &mut threat } else { &mut ads }.push_str(&line);
        }
        let mut b = BlockSetBuilder::new();
        b.add_list_as(ads.as_bytes(), ListClass::Ads);
        b.add_list_as(threat.as_bytes(), ListClass::Threat);
        let s = b.build();
        assert_eq!(
            (s.exact_len(), s.suffix_len(), s.threat_len()),
            (100, 100, 100)
        );
        for i in 0..200 {
            let want = if i % 2 == 0 {
                ListClass::Threat
            } else {
                ListClass::Ads
            };
            assert_eq!(s.verdict(&format!("n{i}.example.com")), Some(want), "n{i}");
            if (i / 2) % 2 == 1 {
                assert_eq!(
                    s.verdict(&format!("sub.n{i}.example.com")),
                    Some(want),
                    "n{i}"
                );
            }
        }
    }

    #[test]
    fn span_is_still_8_bytes() {
        assert_eq!(size_of::<Span>(), 8);
    }

    #[test]
    fn verdict_matches_a_naive_model_with_classes() {
        let mut rng = Rng::new(5);
        let (mut ads, mut threats, mut allowed, mut untouched) = (0, 0, 0, 0);
        for _ in 0..300 {
            let mut builder = BlockSetBuilder::new();
            // Each rule: its name, whether it covers subdomains, and whether it is a threat.
            let mut rules: Vec<(String, bool, bool)> = Vec::new();
            let mut allow = Vec::new();
            for _ in 0..rng.below(12) {
                let rule = model_name(&mut rng);
                let threat = rng.below(2) == 0;
                let class = if threat {
                    ListClass::Threat
                } else {
                    ListClass::Ads
                };
                match rng.below(4) {
                    0 => {
                        builder.add_list_as(format!("0.0.0.0 {rule}\n").as_bytes(), class);
                        // The parser leaves a hosts name of one label alone.
                        if rule.contains('.') {
                            rules.push((rule, false, threat));
                        }
                    }
                    1 => {
                        builder.add_list_as(format!("||{rule}^\n").as_bytes(), class);
                        rules.push((rule, true, threat));
                    }
                    2 => {
                        builder.deny(&rule).unwrap();
                        rules.push((rule, true, false));
                    }
                    _ => {
                        builder.allow(&rule).unwrap();
                        allow.push(rule);
                    }
                }
            }
            let set = builder.build();
            for _ in 0..50 {
                let q = model_name(&mut rng);
                let covers = |rule: &String| q == *rule || q.ends_with(&format!(".{rule}"));
                let matching: Vec<bool> = rules
                    .iter()
                    .filter(|(rule, suffix, _)| if *suffix { covers(rule) } else { q == *rule })
                    .map(|&(_, _, threat)| threat)
                    .collect();
                let allowed_name = allow.iter().any(covers);
                let want = match (
                    allowed_name,
                    matching.iter().any(|&t| t),
                    matching.is_empty(),
                ) {
                    (true, ..) | (false, _, true) => None,
                    (false, true, false) => Some(ListClass::Threat),
                    (false, false, false) => Some(ListClass::Ads),
                };
                assert_eq!(
                    set.verdict(&q),
                    want,
                    "{q:?} with rules {rules:?}, allow {allow:?}"
                );
                assert_eq!(set.is_blocked(&q), want.is_some());
                match (want, allowed_name) {
                    (Some(ListClass::Ads), _) => ads += 1,
                    (Some(ListClass::Threat), _) => threats += 1,
                    (None, true) if !matching.is_empty() => allowed += 1,
                    (None, _) => untouched += 1,
                }
            }
        }
        // Every outcome must have come up, or the model was compared on nothing.
        assert!(
            ads > 500 && threats > 500 && allowed > 50 && untouched > 1_000,
            "{ads} ads, {threats} threats, {allowed} allowed, {untouched} untouched"
        );
    }

    /// A name of one to four labels out of a small alphabet, so that rules and queries meet.
    fn model_name(rng: &mut Rng) -> String {
        const LABELS: [&str; 5] = ["a", "b", "c", "example", "test"];
        let labels: Vec<&str> = (0..1 + rng.below(4))
            .map(|_| LABELS[rng.below(LABELS.len())])
            .collect();
        labels.join(".")
    }

    #[test]
    fn matches_a_naive_model() {
        fn distinct(names: &[String]) -> usize {
            let mut names = names.to_vec();
            names.sort();
            names.dedup();
            names.len()
        }

        let mut rng = Rng::new(3);
        let (mut blocked, mut allowed, mut untouched) = (0, 0, 0);
        for _ in 0..300 {
            let mut builder = BlockSetBuilder::new();
            let (mut exact, mut suffix, mut allow) = (Vec::new(), Vec::new(), Vec::new());
            for _ in 0..rng.below(12) {
                let rule = model_name(&mut rng);
                match rng.below(4) {
                    0 => {
                        builder.add_list(format!("0.0.0.0 {rule}\n").as_bytes());
                        // The parser leaves a hosts name of one label alone.
                        if rule.contains('.') {
                            exact.push(rule);
                        }
                    }
                    1 => {
                        builder.add_list(format!("||{rule}^\n").as_bytes());
                        suffix.push(rule);
                    }
                    2 => {
                        builder.deny(&rule).unwrap();
                        suffix.push(rule);
                    }
                    _ => {
                        builder.allow(&rule).unwrap();
                        allow.push(rule);
                    }
                }
            }
            let pending = builder.heap_bytes();
            assert_eq!(pending == 0, exact.len() + suffix.len() + allow.len() == 0);
            let set = builder.build();
            assert_eq!(
                (set.exact_len(), set.suffix_len(), set.allow_len()),
                (distinct(&exact), distinct(&suffix), distinct(&allow))
            );
            for _ in 0..50 {
                let q = model_name(&mut rng);
                let covers = |rule: &String| q == *rule || q.ends_with(&format!(".{rule}"));
                let listed = exact.contains(&q) || suffix.iter().any(covers);
                let want = !allow.iter().any(covers) && listed;
                assert_eq!(
                    set.is_blocked(&q),
                    want,
                    "{q:?} with exact {exact:?}, suffix {suffix:?}, allow {allow:?}"
                );
                match (listed, want) {
                    (true, true) => blocked += 1,
                    (true, false) => allowed += 1,
                    (false, _) => untouched += 1,
                }
            }
        }
        // All three outcomes must have come up, or the model was compared on nothing.
        assert!(
            blocked > 1_000 && allowed > 100 && untouched > 1_000,
            "{blocked} blocked, {allowed} allowed, {untouched} untouched"
        );
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut rng = Rng::new(4);
        let (mut rules, mut entries) = (0, 0);
        for i in 0..20_000 {
            let text = match i % 3 {
                0 => rng.bytes(400),
                1 => rng.mutate(HOSTS),
                _ => rng.mutate(ADBLOCK),
            };
            let mut emitted = Vec::new();
            let stats = parse_list(&text, |_, name| emitted.push(name.to_owned()));
            let mut builder = BlockSetBuilder::new();
            assert_eq!(builder.add_list(&text), stats, "{text:?}");
            let whole = builder.build();
            assert!(whole.exact_len() <= stats.exact && whole.suffix_len() <= stats.suffix);
            // Nothing is allowed here, so every rule of the list blocks its own name.
            assert!(
                emitted.iter().all(|name| whole.is_blocked(name)),
                "{text:?}"
            );
            rules += emitted.len();

            // A list may arrive in chunks that end at a line break.
            let line_breaks: Vec<usize> = (0..text.len()).filter(|&at| text[at] == b'\n').collect();
            if !line_breaks.is_empty() {
                let cut = line_breaks[rng.below(line_breaks.len())] + 1;
                let mut builder = BlockSetBuilder::new();
                builder.add_list(&text[..cut]);
                builder.add_list(&text[cut..]);
                assert_eq!(
                    tables(&builder.build()),
                    tables(&whole),
                    "{text:?} cut at {cut}"
                );
            }

            // A query name and a configuration entry may be any string at all.
            let any = String::from_utf8_lossy(&match i % 2 {
                0 => rng.bytes(300),
                _ => rng.mutate(b"Sub.Example-1.COM."),
            })
            .into_owned();
            whole.is_blocked(&any);
            let mut buf = [0; MAX_NAME_LEN];
            let valid = normalize(any.as_bytes(), &mut buf).map(str::to_owned);
            let mut builder = BlockSetBuilder::new();
            let want = match valid {
                Some(_) => Ok(()),
                None => Err(InvalidName(any.clone())),
            };
            assert_eq!(builder.deny(&any), want);
            assert_eq!(builder.allow(&any), want);
            let config = builder.build();
            let stored = usize::from(valid.is_some());
            assert_eq!(
                (config.exact_len(), config.suffix_len(), config.allow_len()),
                (0, stored, stored)
            );
            // Allow wins over the deny of the same name.
            assert!(valid.is_none_or(|name| !config.is_blocked(&name)));
            entries += stored;
        }
        // Rules and valid entries must have come up, or the properties were checked on nothing.
        assert!(
            rules > 1_000 && entries > 100,
            "{rules} rules, {entries} entries"
        );
    }
}
