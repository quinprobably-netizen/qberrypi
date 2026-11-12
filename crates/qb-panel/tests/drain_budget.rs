//! The Drain's budgets: the rows each screen write changes, and the time a frame takes to paint.
//!
//! The screen's driver sends one span, from the first changed row to the last, for each write, so
//! `changed_rows` measures a write. A write must fit a quarter of the screen's rows, 80, whatever the
//! traffic, and the average per frame, a motion write and a still write together, 15 %, 48 rows.
//! The panel's schedule is replayed here: each frame offers the names, ticks the Drain and paints a
//! motion write, then one still field is brought up to date and painted as a write of its own.
//! Four runs: steady traffic, a pause, a flood of refused names, and a cold boot, from a Drain with an
//! empty funnel and Wi-Fi not joined, through the join and `LISTENING`, to traffic filling the funnel.

use std::time::Instant;

use qb_panel::drain::{Drain, NameKind, QUEUE_MAX, Stills};
use qb_panel::rows::changed_rows;
use qb_panel::{Blocking, LaneWords, Painter, Share, TimeOfDay};

/// The bytes in a row of the RGB565 frame.
const ROW_BYTES: usize = 960;
/// The most rows a write may change.
const WRITE_ROWS_MAX: usize = 80;
/// The most rows a frame may change on average, with its motion write and its still write together.
const FRAME_ROWS_AVG_MAX: f64 = 48.0;
/// Frames in a second.
const FPS: usize = 8;
/// How long the traffic runs, in seconds.
const SECONDS: usize = 150;
/// The share of queries that are ads, as the mockup's traffic has them.
const AD_SHARE: f64 = 0.44;
/// When Wi-Fi joins in the boot run, in seconds, as the mockup's `boot()` has it.
const JOIN_SECS: usize = 4;
/// When the first query of the boot run comes, in seconds from the start, as the mockup's `boot()` has it.
const FIRST_QUERY_SECS: f64 = 6.5;

/// The public ad names of the mockup's traffic.
const ADS: [&str; 16] = [
    "doubleclick.net",
    "googlesyndication.com",
    "adnxs.com",
    "criteo.com",
    "taboola.com",
    "outbrain.com",
    "moatads.com",
    "adsrvr.org",
    "pubmatic.com",
    "scorecardresearch.com",
    "amazon-adsystem.com",
    "rubiconproject.com",
    "app-measurement.com",
    "ads.yahoo.com",
    "casalemedia.com",
    "openx.net",
];

/// Ordinary sites, all under example.org.
const SITES: [&str; 16] = [
    "www", "mail", "api", "cdn", "static", "login", "video", "images", "docs", "files", "news",
    "music", "maps", "shop", "chat", "time",
];

/// The mulberry32 generator, as the mockup's `rng`.
struct Rng(u32);

impl Rng {
    /// The next number in 0 to 1, 1 not included.
    fn next(&mut self) -> f64 {
        self.0 = self.0.wrapping_add(0x6D2B_79F5);
        let mut t = self.0;
        t = (t ^ (t >> 15)).wrapping_mul(t | 1);
        t ^= t.wrapping_add((t ^ (t >> 7)).wrapping_mul(t | 61));
        f64::from(t ^ (t >> 14)) / 4_294_967_296.0
    }
}

/// A query of the traffic.
struct Query {
    /// The name asked for.
    name: String,
    /// Whether it is an ad, one the lists have.
    ad: bool,
}

/// The mockup's fake traffic: bursty Poisson arrivals, from `common.js` `Sim`.
struct Sim {
    /// The random numbers.
    rng: Rng,
    /// The time of day, in seconds.
    clock: f64,
    /// Whether blocking is paused: ads are answered then.
    paused: bool,
    /// Queries so far today.
    queries: u32,
    /// Queries blocked among them.
    blocked: u32,
    /// Seconds until the next query.
    next: f64,
    /// Queries left in the burst under way.
    burst: u32,
}

impl Sim {
    /// The traffic of a seed, starting at 10:21 with the day's figures of the mockup's stills.
    fn new(seed: u32, paused: bool) -> Self {
        Self {
            rng: Rng(seed),
            clock: f64::from(10 * 3600 + 21 * 60),
            paused,
            queries: 10_818,
            blocked: 4_780,
            next: 0.4,
            burst: 0,
        }
    }

    /// One query.
    fn generate(&mut self) -> Query {
        let ad = self.rng.next() < AD_SHARE;
        let pick = (self.rng.next() * 16.0) as usize;
        let name = if ad {
            ADS[pick % 16].to_string()
        } else {
            format!("{}.example.org", SITES[pick % 16])
        };
        // The mockup also picks a client and an answer time; the generator keeps them in step.
        self.rng.next();
        if !ad {
            self.rng.next();
        }
        Query { name, ad }
    }

    /// Moves `dt` seconds on and gives the queries that arrived.
    fn step(&mut self, dt: f64) -> Vec<Query> {
        self.clock += dt;
        let mut out = vec![];
        self.next -= dt;
        while self.next <= 0.0 {
            let query = self.generate();
            self.queries += 1;
            self.blocked += u32::from(query.ad && !self.paused);
            out.push(query);
            if self.burst > 0 {
                self.burst -= 1;
                self.next += 0.2 + self.rng.next() * 0.4;
            } else {
                if self.rng.next() < 0.18 {
                    self.burst = 1 + (self.rng.next() * 3.0) as u32;
                }
                self.next += 0.6 - (1.0 - self.rng.next()).ln() * 1.6;
            }
        }
        out
    }

    /// The share of today's queries that were blocked.
    fn percent(&self) -> Option<Share> {
        Share::of(u64::from(self.blocked), u64::from(self.queries))
    }

    /// The time of day.
    fn time(&self) -> TimeOfDay {
        let minutes = (self.clock / 60.0) as u32;
        TimeOfDay {
            hour: u8::try_from(minutes / 60 % 24).unwrap_or(0),
            minute: u8::try_from(minutes % 60).unwrap_or(0),
        }
    }
}

/// What a run measured.
struct Measured {
    /// The rows of each write.
    writes: Vec<usize>,
    /// The rows of each frame, its writes together.
    frames: Vec<usize>,
    /// How many refusals ran to their last step.
    refusals: usize,
    /// The rows of each write in the second after Wi-Fi joined, in the boot run: the words, the clock and the count.
    join_writes: Vec<usize>,
    /// How many of the funnel's dots are lit at the end.
    funnel_lit: usize,
    /// Whether the lane's words were gone at the end.
    words_gone: bool,
    /// How many frames began with the queue at its cap of `QUEUE_MAX` names, after the offers.
    queue_full: usize,
}

/// What a run does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scenario {
    /// Traffic with blocking on, from a full funnel.
    Steady,
    /// Traffic while blocking is paused: ads are let through.
    Paused,
    /// Two refused names every frame, from the start.
    Flood,
    /// A cold boot: Wi-Fi not joined and an empty funnel, the join, `LISTENING`, then the traffic.
    Boot,
}

/// The mean, the 95th percentile and the peak of some row counts.
fn summary(rows: &[usize]) -> (f64, usize, usize) {
    let mut sorted = rows.to_vec();
    sorted.sort_unstable();
    let mean = rows.iter().sum::<usize>() as f64 / rows.len().max(1) as f64;
    let p95 = sorted.get(sorted.len() * 95 / 100).copied().unwrap_or(0);
    (mean, p95, sorted.last().copied().unwrap_or(0))
}

/// Runs the panel's schedule over the traffic and measures every write after the first.
fn run(scenario: Scenario) -> Measured {
    let paused = scenario == Scenario::Paused;
    let flood = scenario == Scenario::Flood;
    let boot = scenario == Scenario::Boot;
    let mut sim = Sim::new(7, paused);
    if boot {
        // Nothing is known: no queries today, and the first one a while after Wi-Fi joins.
        sim.queries = 0;
        sim.blocked = 0;
        sim.next = FIRST_QUERY_SECS;
    }
    let mut drain = Drain::new(7);
    drain.set_paused(paused);
    let blocking = |left: f64| {
        if paused {
            Blocking::Paused {
                left_secs: left as u16,
            }
        } else {
            Blocking::On
        }
    };
    let mut pause_left = 299.0_f64;
    // A cold boot knows nothing: the lane says `JOINING WI-FI`, and the figures are dashes.
    let mut joined = !boot;
    let mut shown = if boot {
        Stills {
            blocking: Blocking::On,
            words: Some(LaneWords::Joining),
            ..Stills::default()
        }
    } else {
        drain.set_blocked_today(Some(sim.blocked));
        Stills {
            percent: sim.percent(),
            clock: Some(sim.time()),
            blocking: blocking(pause_left),
            count: drain.count(),
            ..Stills::default()
        }
    };
    let mut wanted = shown.clone();
    let mut painter = Painter::new();
    // The first write is not measured.
    let mut last = painter.paint(&drain, &shown).to_vec();
    let mut measured = Measured {
        writes: vec![],
        frames: vec![],
        refusals: 0,
        join_writes: vec![],
        funnel_lit: 0,
        words_gone: false,
        queue_full: 0,
    };
    let rows_of = |last: &mut Vec<u8>, frame: &[u8]| {
        let rows = changed_rows(last, frame, ROW_BYTES).map_or(0, |rows| rows.len());
        last.clear();
        last.extend_from_slice(frame);
        rows
    };
    let mut flooded = 0_u32;
    let mut door_was_shut = false;
    for tick in 0..SECONDS * FPS {
        let mut frame_rows = 0;
        let writes_before = measured.writes.len();
        if boot && tick == JOIN_SECS * FPS {
            // Wi-Fi joins: the clock is set, today's figure is known (0), and the lane listens.
            joined = true;
            drain.set_blocked_today(Some(sim.blocked));
            wanted.clock = Some(sim.time());
            wanted.words = Some(LaneWords::Listening);
        }
        if flood {
            // A page load that fires blocked queries without a pause: two new names every frame.
            for _ in 0..2 {
                flooded += 1;
                // Each is its own site after fitting to the 15 cells a refused name stops in: two labels
                // of 15 cells in all, so that `fit_site` keeps them whole and none is a duplicate.
                drain.offer(&format!("ad{flooded:05}.example"), NameKind::Refused);
                sim.blocked += 1;
                sim.queries += 1;
            }
        }
        for query in sim.step(1.0 / FPS as f64) {
            let kind = match (query.ad, paused) {
                (true, false) => NameKind::Refused,
                (true, true) => NameKind::Listed,
                (false, _) => NameKind::Plain,
            };
            drain.offer(&query.name, kind);
        }
        if joined && tick % FPS == 0 {
            // The once-a-second snapshot.
            drain.set_blocked_today(Some(sim.blocked));
            pause_left = (pause_left - 1.0).max(0.0);
            wanted.percent = sim.percent();
            wanted.clock = Some(sim.time());
            wanted.blocking = blocking(pause_left);
        }
        if joined && sim.queries > 0 {
            // Today has queries, and the last came less than 2 minutes ago: no words.
            wanted.words = None;
        }
        measured.queue_full += usize::from(drain.queued() == QUEUE_MAX);
        if drain.moving() {
            drain.tick(paused);
            // A refusal ends when its door reopens.
            measured.refusals += usize::from(door_was_shut && !drain.door_shut());
            door_was_shut = drain.door_shut();
            if joined {
                wanted.count = drain.count();
            }
            let rows = rows_of(&mut last, painter.paint(&drain, &shown));
            // The real panel skips a paint that changes nothing, so that is no write.
            if rows > 0 {
                measured.writes.push(rows);
            }
            frame_rows += rows;
        } else if joined {
            wanted.count = drain.count();
        }
        // Half a frame later: one still field.
        if shown.step_toward(&wanted) {
            let rows = rows_of(&mut last, painter.paint(&drain, &shown));
            // The real panel skips a paint that changes nothing, so that is no write.
            if rows > 0 {
                measured.writes.push(rows);
            }
            frame_rows += rows;
        }
        if boot && (JOIN_SECS * FPS..(JOIN_SECS + 1) * FPS).contains(&tick) {
            measured
                .join_writes
                .extend_from_slice(&measured.writes[writes_before..]);
        }
        measured.frames.push(frame_rows);
    }
    measured.funnel_lit = drain
        .funnel()
        .iter()
        .filter(|cell| cell.shade.is_some())
        .count();
    measured.words_gone = shown.words.is_none();
    measured
}

/// Reports a run and checks it against the budgets.
fn check(name: &str, measured: &Measured, frame_average: bool) {
    let (write_mean, write_p95, write_peak) = summary(&measured.writes);
    let (frame_mean, frame_p95, frame_peak) = summary(&measured.frames);
    println!(
        "{name}: per write avg {write_mean:.1} p95 {write_p95} peak {write_peak} rows of 320 over {} writes; \
         per frame avg {frame_mean:.1} ({:.1} %) p95 {frame_p95} peak {frame_peak}; {} refusals; \
         the queue was full in {} of {} frames",
        measured.writes.len(),
        frame_mean / 3.2,
        measured.refusals,
        measured.queue_full,
        measured.frames.len()
    );
    if !measured.join_writes.is_empty() {
        println!(
            "{name}: the Wi-Fi join wrote {} times, {:?} rows",
            measured.join_writes.len(),
            measured.join_writes
        );
    }
    assert!(
        write_peak <= WRITE_ROWS_MAX,
        "{name}: a write changed {write_peak} rows, over {WRITE_ROWS_MAX}"
    );
    assert!(
        !frame_average || frame_mean <= FRAME_ROWS_AVG_MAX,
        "{name}: a frame changed {frame_mean:.1} rows on average, over {FRAME_ROWS_AVG_MAX}"
    );
}

#[test]
fn budget_steady_traffic_every_write_fits_80_rows() {
    let measured = run(Scenario::Steady);
    assert!(measured.refusals >= 20, "the traffic refused some names");
    check("steady traffic", &measured, true);
}

#[test]
fn budget_paused_every_write_fits_80_rows() {
    let measured = run(Scenario::Paused);
    assert_eq!(measured.refusals, 0, "nothing is refused while paused");
    check("paused", &measured, true);
}

/// Two refused names every frame, from the start: one refusal after another with no gap. Every write
/// still fits; only the average over frames is not held to a bound, since the lane is never idle.
#[test]
fn budget_a_flood_of_refused_names_every_write_fits_80_rows() {
    let measured = run(Scenario::Flood);
    // The flood is real: the names are all different after fitting, so the queue is full nearly all the
    // time (a few frames to fill it at the start) and each name that leaves it is shed or taken. If
    // the names collapsed into one site, the queue would hold one or none.
    assert!(
        measured.queue_full * 10 >= SECONDS * FPS * 9,
        "the queue was full in {} of {} frames",
        measured.queue_full,
        SECONDS * FPS
    );
    // The lane is saturated: a refusal of a 15-letter name is 15 frames to the gate, 17 steps and one to
    // leave, 33 frames in all, so 36 fit in the run whatever the names offered while it goes on.
    assert!(measured.refusals >= 30, "refusals ran one after another");
    check("flood of refused names", &measured, false);
}

/// A cold boot: `JOINING WI-FI` over an empty funnel and dashes, then Wi-Fi joins (the clock, the count and
/// `LISTENING` come in writes of their own), then traffic fills the funnel from its tip, and the words go.
/// Every write fits, the join's included: it is three still writes, one field each.
#[test]
fn budget_a_cold_boot_every_write_fits_80_rows() {
    let measured = run(Scenario::Boot);
    assert!(measured.refusals >= 10, "the traffic refused some names");
    assert!(
        !measured.join_writes.is_empty(),
        "the join wrote its figures"
    );
    assert!(
        measured.funnel_lit > 0,
        "the funnel filled from empty as names landed"
    );
    assert!(measured.words_gone, "the words went once traffic came");
    check("cold boot", &measured, true);
}

/// The mean, the median, the 99th percentile and the largest of some times, in microseconds.
fn micros(times: &[std::time::Duration]) -> (f64, f64, f64, f64) {
    let mut all: Vec<f64> = times.iter().map(|t| t.as_secs_f64() * 1e6).collect();
    all.sort_by(f64::total_cmp);
    let mean = all.iter().sum::<f64>() / all.len().max(1) as f64;
    let at = |share: usize| all.get(all.len() * share / 100).copied().unwrap_or(0.0);
    (mean, at(50), at(99), all.last().copied().unwrap_or(0.0))
}

#[test]
#[ignore = "timing; run with --release"]
fn render_time_per_frame() {
    let stills = Stills {
        percent: Some(Share::Percent(44)),
        clock: Some(TimeOfDay {
            hour: 10,
            minute: 21,
        }),
        blocking: Blocking::On,
        count: Some(4780),
        ..Stills::default()
    };

    // A steady motion frame: plain and refused names moving, the glyphs already rendered.
    let mut drain = Drain::new(7);
    drain.set_blocked_today(Some(4780));
    let mut painter = Painter::new();
    painter.paint(&drain, &stills);
    let mut motion = vec![];
    for i in 0..4000_u32 {
        if i % 7 == 0 {
            drain.offer(&format!("site{}.example.org", i % 23), NameKind::Plain);
        }
        if i % 31 == 0 {
            drain.offer(ADS[(i / 31) as usize % 16], NameKind::Refused);
        }
        if drain.moving() {
            drain.tick(false);
            let start = Instant::now();
            std::hint::black_box(painter.paint(&drain, &stills));
            // The first rounds render the glyphs.
            if i > 500 {
                motion.push(start.elapsed());
            }
        }
    }

    // A still write: the percentage changing, then the clock, then the count.
    let mut still = vec![];
    let mut shown = stills.clone();
    for i in 0..600_u32 {
        match i % 3 {
            0 => shown.percent = Some(Share::Percent(40 + u8::try_from(i % 20).unwrap_or(0))),
            1 => {
                shown.clock = Some(TimeOfDay {
                    hour: 10,
                    minute: u8::try_from(i % 60).unwrap_or(0),
                })
            }
            _ => shown.count = Some(4780 + i),
        }
        let start = Instant::now();
        std::hint::black_box(painter.paint(&drain, &shown));
        still.push(start.elapsed());
    }

    // A full repaint: a new painter and one paint, glyphs and all.
    let mut full = vec![];
    for _ in 0..200 {
        let start = Instant::now();
        let mut fresh = Painter::new();
        std::hint::black_box(fresh.paint(&drain, &stills));
        full.push(start.elapsed());
    }

    let (motion_mean, motion_p50, motion_p99, motion_max) = micros(&motion);
    let (still_mean, still_p50, still_p99, still_max) = micros(&still);
    let (full_mean, full_p50, full_p99, full_max) = micros(&full);
    println!(
        "steady motion frame: mean {motion_mean:.0} us, median {motion_p50:.0} us, p99 {motion_p99:.0} us, max {motion_max:.0} us over {} frames",
        motion.len()
    );
    println!(
        "still write: mean {still_mean:.0} us, median {still_p50:.0} us, p99 {still_p99:.0} us, max {still_max:.0} us over {} writes",
        still.len()
    );
    println!(
        "full repaint: mean {full_mean:.0} us, median {full_p50:.0} us, p99 {full_p99:.0} us, max {full_max:.0} us over {} paints",
        full.len()
    );
    assert!(
        motion_mean < 1000.0,
        "a steady motion frame took {motion_mean:.0} us"
    );
    assert!(full_mean < 5000.0, "a full repaint took {full_mean:.0} us");
}
