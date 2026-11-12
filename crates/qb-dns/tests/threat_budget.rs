//! The lookup cost of the block set with the threat feeds loaded, against the budget of the
//! `qb-dns` lookup (5 µs) and against the same lookups on the ads alone.
//!
//! The sets are built from generated names, so no list has to be fetched. Run the test with
//!
//! ```text
//! cargo test -p qb-dns --release --test threat_budget -- --ignored --nocapture
//! ```
//!
//! The budget holds for a release build on the host; the timing is not meaningful in a debug build.

use qb_dns::{BlockSet, BlockSetBuilder, ListClass};
use std::hint::black_box;
use std::time::{Duration, Instant};

/// How many names the ads lists hold.
const ADS_NAMES: usize = 300_000;
/// How many names the threat feeds hold.
const THREAT_NAMES: usize = 1_000_000;
/// How many lookups are timed in a pass.
const LOOKUPS: usize = 1_000_000;
/// How many times the lookups are timed; the fastest pass is the one held to the budget, since a
/// busy host only ever makes a pass slower.
const PASSES: usize = 3;
/// The mean cost of one lookup the test allows, in nanoseconds.
const BUDGET_NS: u128 = 5_000;
/// The top-level domains the generated names sit under.
const TLDS: [&str; 3] = ["com", "net", "org"];
/// The characters of a generated label.
const LABEL_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

/// A 64-bit linear congruential generator: the same seed gives the same sequence.
struct Lcg(u64);

impl Lcg {
    /// The next 31 bits, the high ones, which are the well-mixed ones of this generator.
    fn next(&mut self) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) as usize
    }

    /// A number in `0..n`; `n` must be above 0.
    fn below(&mut self, n: usize) -> usize {
        self.next() % n
    }

    /// A name of two to four labels of 6 to 14 characters, under one of the three domains.
    fn name(&mut self) -> String {
        let mut name = String::new();
        for _ in 0..2 + self.below(3) {
            for _ in 0..6 + self.below(9) {
                name.push(char::from(LABEL_CHARS[self.below(LABEL_CHARS.len())]));
            }
            name.push('.');
        }
        name.push_str(TLDS[self.below(TLDS.len())]);
        name
    }
}

/// One list: its text, with every second name as a hosts line and the others as `||name^`
/// lines, and its names.
struct Feed {
    /// The list, as the parser reads it.
    text: Vec<u8>,
    /// The names, in the order of the lines.
    names: Vec<String>,
}

impl Feed {
    /// A list of `count` generated names from the sequence that starts at `seed`.
    fn generate(seed: u64, count: usize) -> Self {
        let mut rng = Lcg(seed);
        let mut text = Vec::new();
        let mut names = Vec::with_capacity(count);
        for i in 0..count {
            let name = rng.name();
            let line = if i % 2 == 0 {
                format!("0.0.0.0 {name}\n")
            } else {
                format!("||{name}^\n")
            };
            text.extend_from_slice(line.as_bytes());
            names.push(name);
        }
        Self { text, names }
    }

    /// A name of the list to ask for and the verdict it has: any name of a line `||name^` or a
    /// subdomain of it, and only the name itself of a hosts line.
    fn hit(&self, rng: &mut Lcg) -> String {
        let i = rng.below(self.names.len());
        let name = &self.names[i];
        if i % 2 == 1 && rng.below(2) == 0 {
            format!("www.{name}")
        } else {
            name.clone()
        }
    }
}

/// A number for each verdict, to add up what the timed loop saw.
fn code(verdict: Option<ListClass>) -> u64 {
    match verdict {
        None => 0,
        Some(ListClass::Ads) => 1,
        Some(ListClass::Threat) => 1 << 20,
    }
}

/// The mean cost of one call of `ask` over `queries`, in nanoseconds, for the fastest of
/// [`PASSES`] passes, and what each pass came to when the verdicts are added up with [`code`].
fn time(queries: &[String], ask: impl Fn(&str) -> u64) -> (u128, u64) {
    let mut fastest = Duration::MAX;
    let mut seen = 0;
    for _ in 0..PASSES {
        let start = Instant::now();
        seen = 0;
        for query in queries {
            seen += ask(black_box(query));
        }
        fastest = fastest.min(start.elapsed());
    }
    (fastest.as_nanos() / queries.len() as u128, seen)
}

#[test]
#[ignore = "a timing test for release builds; see the comment at the top of this file"]
fn lookup_cost_with_the_threat_feeds() {
    let ads = Feed::generate(1, ADS_NAMES);
    let threats = Feed::generate(2, THREAT_NAMES);

    let mut combined = BlockSetBuilder::new();
    combined.add_list_as(&ads.text, ListClass::Ads);
    combined.add_list_as(&threats.text, ListClass::Threat);
    let combined = combined.build();
    let mut ads_only = BlockSetBuilder::new();
    ads_only.add_list(&ads.text);
    let ads_only: BlockSet = ads_only.build();
    assert_eq!(combined.threat_len(), THREAT_NAMES);
    assert_eq!(ads_only.threat_len(), 0);

    // A third of the lookups hit an ads name, a third a threat name, a third miss: a random name
    // asked for as it is, and the same under `www.` in turn.
    let mut rng = Lcg(3);
    let mut queries = Vec::with_capacity(LOOKUPS);
    let mut expected = Vec::with_capacity(LOOKUPS);
    for i in 0..LOOKUPS {
        match i % 3 {
            0 => {
                queries.push(ads.hit(&mut rng));
                expected.push(Some(ListClass::Ads));
            }
            1 => {
                queries.push(threats.hit(&mut rng));
                expected.push(Some(ListClass::Threat));
            }
            _ if i % 2 == 0 => {
                queries.push(rng.name());
                expected.push(None);
            }
            _ => {
                queries.push(format!("www.{}", rng.name()));
                expected.push(None);
            }
        }
    }

    // Every verdict is checked first, which also warms the caches the timed loops run in.
    for (query, want) in queries.iter().zip(&expected) {
        assert_eq!(combined.verdict(query), *want, "{query}");
        assert_eq!(combined.is_blocked(query), want.is_some(), "{query}");
        assert_eq!(
            ads_only.is_blocked(query),
            *want == Some(ListClass::Ads),
            "{query}"
        );
    }
    let want_seen: u64 = expected.iter().map(|&want| code(want)).sum();
    let want_ads = expected
        .iter()
        .filter(|&&want| want == Some(ListClass::Ads))
        .count() as u64;

    let (with_feeds_ns, seen) = time(&queries, |query| code(black_box(&combined).verdict(query)));
    assert_eq!(seen, want_seen);
    let (ads_only_ns, seen) = time(&queries, |query| {
        u64::from(black_box(&ads_only).is_blocked(query))
    });
    assert_eq!(seen, want_ads);

    println!(
        "{LOOKUPS} lookups, fastest of {PASSES} passes: a third ads hits, a third threat hits, a \
         third misses (half of them subdomains)"
    );
    println!(
        "combined set, {ADS_NAMES} ads + {THREAT_NAMES} threat names, verdict: \
         {with_feeds_ns} ns per lookup (budget {BUDGET_NS})"
    );
    println!(
        "ads-only set, {ADS_NAMES} names, is_blocked: {ads_only_ns} ns per lookup (budget \
         {BUDGET_NS}); the threat hits are misses there"
    );
    println!(
        "block set heap: {} bytes combined, {} bytes ads only",
        combined.heap_bytes(),
        ads_only.heap_bytes()
    );
    assert!(with_feeds_ns < BUDGET_NS, "{with_feeds_ns} ns per lookup");
    assert!(ads_only_ns < BUDGET_NS, "{ads_only_ns} ns per lookup");
}
