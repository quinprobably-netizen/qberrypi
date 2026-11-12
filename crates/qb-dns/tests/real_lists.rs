//! The two real blocklists of the example configuration, checked against the entry counts in
//! their own headers and against the memory and time budgets of the block set.
//!
//! The lists change daily and are not committed. From the repository root, fetch them with
//!
//! ```text
//! mkdir -p vendor-cache/lists
//! curl -fsSL -o vendor-cache/lists/steven-hosts.txt https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
//! curl -fsSL -o vendor-cache/lists/hagezi-pro.txt https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt
//! ```
//!
//! and run the test with
//!
//! ```text
//! cargo test -p qb-dns --release --test real_lists -- --ignored --nocapture
//! ```
//!
//! The two time budgets hold for a release build; a debug build checks everything else.

use qb_dns::parse::parse_list;
use qb_dns::{BlockSet, BlockSetBuilder};
use std::fs;
use std::hint::black_box;
use std::path::Path;
use std::time::{Duration, Instant};

const HEAP_BUDGET: usize = 12 * 1024 * 1024;
const PEAK_BUDGET_KB: u64 = 24 * 1024;
const HOST_BUILD_BUDGET_MS: u128 = 150; // stands for 2 s on the Pi 3 B+
const HOST_LOOKUP_BUDGET_NS: u128 = 5_000;

/// How often both lists are built; the fastest build is the one held to the budget.
const BUILDS: usize = 5;
/// How many lookups are timed.
const LOOKUPS: usize = 1_000_000;
/// How many lines a failure shows at most.
const SHOWN_LINES: usize = 20;

/// The bytes of one downloaded list.
fn read_list(file: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vendor-cache/lists")
        .join(file);
    fs::read(&path).unwrap_or_else(|err| {
        panic!(
            "cannot read {}: {err}; fetch the lists with the commands in the comment at the \
             top of crates/qb-dns/tests/real_lists.rs",
            path.display()
        )
    })
}

/// The most memory this process has had resident at one time, in kB.
fn peak_resident_kb() -> u64 {
    let status = fs::read_to_string("/proc/self/status").expect("/proc/self/status is readable");
    status
        .lines()
        .find_map(|line| {
            let kb = line.strip_prefix("VmHWM:")?.trim().strip_suffix("kB")?;
            kb.trim().parse().ok()
        })
        .expect("/proc/self/status has a VmHWM line in kB")
}

/// One block set from both lists, and how long parsing and building took.
fn timed_build(lists: [&[u8]; 2]) -> (BlockSet, Duration) {
    let start = Instant::now();
    let mut builder = BlockSetBuilder::new();
    for text in lists {
        builder.add_list(text);
    }
    let set = builder.build();
    (set, start.elapsed())
}

/// The entry count a list states in the header line that starts with `prefix`.
fn header_count(file: &str, text: &[u8], prefix: &str) -> usize {
    text.split(|&byte| byte == b'\n')
        .find_map(|line| line.strip_prefix(prefix.as_bytes()))
        .and_then(|count| {
            let digits: String = String::from_utf8_lossy(count)
                .chars()
                .filter(|&c| c != ',')
                .collect();
            digits.trim().parse().ok()
        })
        .unwrap_or_else(|| panic!("{file} has no `{prefix} <count>` line"))
}

/// The first lines of `text` that the parser counts as invalid or unsupported, one per line.
fn offending_lines(text: &[u8]) -> String {
    text.split(|&byte| byte == b'\n')
        .filter(|line| {
            let stats = parse_list(line, |_, _| {});
            stats.invalid + stats.unsupported > 0
        })
        .take(SHOWN_LINES)
        .map(|line| format!("  {}\n", line.escape_ascii()))
        .collect()
}

/// Builds one list alone and checks it against its own header: `stored` names, as many as the
/// line that starts with `prefix` states, and no line the parser could not read.
fn check_against_header(file: &str, text: &[u8], prefix: &str, stored: fn(&BlockSet) -> usize) {
    let mut builder = BlockSetBuilder::new();
    let stats = builder.add_list(text);
    let set = builder.build();
    assert!(
        stats.invalid == 0 && stats.unsupported == 0,
        "{file}: {stats:?}; the first lines that were not read:\n{}",
        offending_lines(text)
    );
    assert_eq!(
        stored(&set),
        header_count(file, text, prefix),
        "{file}: distinct names stored, against the count in its header; {stats:?}"
    );
}

#[test]
#[ignore = "needs the lists in vendor-cache/lists; see the comment at the top of this file"]
fn real_lists_fit_the_budgets() {
    let hosts = read_list("steven-hosts.txt");
    let adblock = read_list("hagezi-pro.txt");
    let baseline_kb = peak_resident_kb();

    let (set, first_build) = timed_build([&hosts, &adblock]);
    let peak_growth_kb = peak_resident_kb() - baseline_kb;
    let fastest_build = (1..BUILDS)
        .map(|_| timed_build([&hosts, &adblock]).1)
        .fold(first_build, Duration::min);

    let heap_bytes = set.heap_bytes();
    assert!(heap_bytes <= HEAP_BUDGET, "block set of {heap_bytes} bytes");
    assert!(
        peak_growth_kb <= PEAK_BUDGET_KB,
        "peak resident memory grew by {peak_growth_kb} kB while building"
    );
    if !cfg!(debug_assertions) {
        assert!(
            fastest_build.as_nanos() <= HOST_BUILD_BUDGET_MS * 1_000_000,
            "fastest of {BUILDS} builds took {fastest_build:?}"
        );
    }

    check_against_header(
        "steven-hosts.txt",
        &hosts,
        "# Number of unique domains:",
        BlockSet::exact_len,
    );
    check_against_header(
        "hagezi-pro.txt",
        &adblock,
        "! Number of entries:",
        BlockSet::suffix_len,
    );

    let mut first_exact = None;
    let mut not_blocked = None;
    parse_list(&hosts, |_, name| {
        first_exact.get_or_insert_with(|| name.to_owned());
        if !set.is_blocked(name) {
            not_blocked.get_or_insert_with(|| name.to_owned());
        }
    });
    assert_eq!(not_blocked, None, "a name of the hosts list is not blocked");
    assert!(!set.is_blocked("example.com") && !set.is_blocked("www.example.org"));
    let mut first_suffix = None;
    parse_list(&adblock, |_, name| {
        first_suffix.get_or_insert_with(|| name.to_owned());
    });
    let exact = first_exact.expect("the hosts list emits a name");
    let subdomain = format!(
        "qb-dns-test.{}",
        first_suffix.expect("the adblock list emits a name")
    );
    assert!(set.is_blocked(&subdomain));

    // Two blocked names and three that are not, the last of them six labels deep.
    let rotation = [
        exact.as_str(),
        "example.com",
        subdomain.as_str(),
        "www.example.org",
        "a.b.c.d.example.net",
    ];
    let start = Instant::now();
    let blocked = rotation
        .iter()
        .cycle()
        .take(LOOKUPS)
        .filter(|name| black_box(&set).is_blocked(black_box(name)))
        .count();
    let lookups = start.elapsed();
    assert_eq!(blocked, LOOKUPS / rotation.len() * 2);
    if !cfg!(debug_assertions) {
        assert!(
            lookups.as_nanos() <= HOST_LOOKUP_BUDGET_NS * LOOKUPS as u128,
            "{LOOKUPS} lookups took {lookups:?}"
        );
    }

    let (exact_len, suffix_len) = (set.exact_len(), set.suffix_len());
    println!(
        "names: {exact_len} exact + {suffix_len} suffix = {}",
        exact_len + suffix_len
    );
    println!("block set: {heap_bytes} bytes (budget {HEAP_BUDGET})");
    println!("peak growth while building: {peak_growth_kb} kB (budget {PEAK_BUDGET_KB})");
    println!(
        "parse and build, fastest of {BUILDS}: {:.1} ms (budget {HOST_BUILD_BUDGET_MS}, release only)",
        fastest_build.as_secs_f64() * 1e3
    );
    println!(
        "lookup, mean of {LOOKUPS}: {} ns (budget {HOST_LOOKUP_BUDGET_NS}, release only)",
        lookups.as_nanos() / LOOKUPS as u128
    );
}
