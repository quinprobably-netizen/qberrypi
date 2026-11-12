# Front panel "Drain" Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (lean: one fresh implementer per task, one whole-branch review at the end). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the approved design 8 on the 3.5" panel with the owner's pick from round 5, "Drain": a lane of name tiles along the top, a gate that stops refused names, and a melt that drips them into a funnel of dots above the refused count. It also adds a paused look, an alert takeover, and the % and clock column.

**Architecture:**
- `qb-panel` stays pure, with no I/O. It gains:
  - a deterministic scene model (`Drain`), advanced one frame per `tick`;
  - the slow figures (`Stills`), which change one region per write;
  - a painter that keeps one persistent frame and repaints only what changed;
  - `changed_rows`, moved here from `fb.rs`.
- `qberrypi` gains:
  - a bounded, never-waiting lane feed that the DNS service offers sampled names to;
  - a panel loop at 8 fps on the panel's existing pool thread (`Component::blocking`);
  - a read-side alert trait with a stand-in.

**Tech Stack:** Rust, tiny-skia 0.12, ab_glyph 0.2 with the crate's JetBrains Mono, std threads and atomics. Nothing new is added to the dependencies.

**Spec (design source of truth):** `~/Work/qberrypi-mockups/round5/`, meaning `r5-d1.html`, `src/d1.js`, `src/common.js`, `README.md` and the stills `r5-d1-{normal,paused,alert}.png`. Implementers read `src/d1.js` and `src/common.js` for every coordinate. The watchdog spec `docs/superpowers/specs/2026-11-11-qberrypi-watchdog-design.md` §5 covers the panel alert.

## Global Constraints

- **Process:**
  - Follow `target/tmp/wd-common.md` in the main checkout (`~/Work/qberrypi/target/tmp/wd-common.md`).
  - `export TMPDIR=~/Work/qberrypi-drain/target/tmp`.
  - Never read or touch `~/Work/qberrypi/qberrypi.toml`, and never contact the Pi.
- **Gates before every commit:**
  - `cargo test --workspace`
  - `cargo clippy --workspace --all-targets`, with 0 warnings
  - `cargo fmt --all --check`
  - `cargo build -p qberrypi --release --target aarch64-unknown-linux-musl`
  - `grep -rln unsafe crates/qberrypi/src crates/qberrypi/tests` prints only `crates/qberrypi/src/sys.rs`
  - a commit that touches `init.rs` or `xtask` also needs `cargo xtask build && cargo xtask qemu-test`, with every scenario ok.
- **Commits:** stage files by name, end each commit with `Co-Authored-By: Claude Sonnet <noreply@anthropic.com>` (the implementer's model), and never push.
- **The look:**
  - Screen: 480×320, on a black ground (`#000000`).
  - Colours: only the round 5 palette, which is blue `#4a72ff`, blueLt `#a4b6ff`, blueMd `#3152c4`, blueDk `#1f3383`, blueDeep `#121b44`, blueNight `#0c1230`, white, and g1 `#d0d0d0`, g2 `#8e8e8e`, g3 `#5e5e5e`, g4 `#2e2e2e`, g5 `#181818`.
  - Fonts: JetBrains Mono Regular and Bold from `crates/qb-panel/fonts` only. A canvas `px` is the em size, as `draw_text`'s `size` is.
- **Privacy:**
  - A query name reaches only the physical screen.
  - A name is never logged, never `Debug`-printed (feed types implement no `Debug`, or a redacting one), and never reachable from `api/`, `status.rs` or any `Source` method.
- **Public repo:** tests use example.org names and 192.0.2.x addresses only, or the public ad names from the mockup's `ADS` list.
- **Hot path (latency ruling 17):**
  - Nothing added to `Dns::decide` may wait, lock blockingly or allocate.
  - When the panel is behind, a name is dropped.
- **Panel thread:** rendering and animation run on the panel's thread, which is a pool thread (`init.rs::panel_component`, `Component::blocking`). Nothing is rendered on the runtime.
- **Motion budget:**
  - Every write to the screen must fit about 25% of the rows, which is at most 80 rows as `changed_rows` measures it, with each refusal step in a frame of its own.
  - There are two exceptions: a pause toggle, and an alert appearing, changing or being dismissed. Each costs one discrete large write.
  - The kernel driver (fbtft deferred io) sends one span from the first to the last touched row per flush. That is why `changed_rows` (first..last span) is the measure, not a count of the rows that changed.
- **Owner's open question:** the owner was asked about the 44% and clock sizes and has not answered. Build them as in the mockup (40 px and 26 px bold), as named constants `PERCENT_PX` and `CLOCK_PX`.

## Review Focus

1. **A burst of refused names**, such as a page load that fires 30 blocked queries in a second. The lane queue stays at 4 (plain names go first, then the oldest), the feed drops the rest, and nothing grows. Test: Task 1, `a_burst_keeps_the_queue_at_four_refused_first`. Test: Task 3, `a_full_feed_drops_and_counts`.
2. **A name longer than the lane or with odd bytes** (253 chars, a trailing dot, non-ASCII, upper case). It is cut to 20 cells with `~`, lower-cased, and `?` replaces what has no glyph. Test: Task 1, `long_and_odd_names_fit_twenty_cells`.
3. **The count around midnight and before the resolver exists.** With no snapshot, the count is a dash. A day rollover drops the count to the new value, and it never runs ahead of the snapshot. Test: Task 1, `the_count_follows_the_day_and_holds_back_names_in_flight`.
4. **A still change in the same tick as motion**, such as the clock minute rolling while names move. These go out as two separate writes, and each fits 80 rows. Test: Task 2, `budget_steady_traffic_every_write_fits_80_rows`.
5. **Taps while an alert is up.** A tap on the alert acknowledges that id and nothing else, and a tap on the key still works. An alert that disappears from the store between frames clears the takeover. Test: Task 4, `a_tap_on_the_alert_acks_it_and_the_key_still_pauses`.

---

### Task 1: The Drain model (pure) and `changed_rows` in qb-panel

**Files:**
- Create: `crates/qb-panel/src/drain/mod.rs`, with the model: lane, melt, funnel, count and `Stills`.
- Create: `crates/qb-panel/src/drain/look.rs`, with every Drain coordinate, size and colour as named `pub const`.
- Create: `crates/qb-panel/src/rows.rs`, with `changed_rows` moved verbatim (with its tests) from `crates/qberrypi/src/panel/fb.rs`.
- Modify: `crates/qb-panel/src/lib.rs`, `crates/qb-panel/src/format.rs` (`fit_name`, `alert_card`), `crates/qberrypi/src/panel/fb.rs` (use `qb_panel::rows::changed_rows`).

**Interfaces (Produces):**

```rust
// qb_panel::rows
pub fn changed_rows(old: &[u8], new: &[u8], stride: usize) -> Option<Range<usize>>;

// qb_panel::drain
pub enum NameKind { Plain, Refused, Listed }   // Listed: on the lists, let through while paused
pub struct Drain { /* private */ }
impl Drain {
    pub fn new(seed: u32) -> Self;                  // funnel prefilled from seed (runs of 6..18 cells, alternating shade)
    pub fn offer(&mut self, name: &str, kind: NameKind);
    pub fn tick(&mut self, paused: bool);           // one frame (125 ms)
    pub fn moving(&self) -> bool;                   // names on the lane, a refusal in progress, or a flip settling
    pub fn set_blocked_today(&mut self, blocked: Option<u32>);
    pub fn count(&self) -> Option<u32>;             // what the panel shows as the refused count
    pub fn refusal_step(&self) -> Option<u8>;       // the stopped name's step, 1-based; for goldens and tests
    // read accessors the painter needs: lane tiles (cell, char, style, melt stage, drip length), door shut,
    // funnel cells (shade, flip). Names and shape of these are the implementer's choice; Task 2 consumes them.
}
pub struct AlertCard { pub high: bool, pub title: [String; 2], pub subject: String, pub who: String }
#[derive(Clone, PartialEq)]
pub struct Stills {
    pub percent: Option<u8>, pub clock: Option<TimeOfDay>, pub blocking: Blocking,
    pub count: Option<u32>, pub alert: Option<AlertCard>,
}
impl Stills { pub fn step_toward(&mut self, wanted: &Stills) -> bool; }

// qb_panel::format
pub fn fit_name(name: &str, cells: usize) -> String;     // lower-case, one trailing dot off, non-printable-ASCII → '?', cut to `cells` with '~' last
pub fn alert_card(kind: &str, high: bool, subject: &str, client: Option<std::net::IpAddr>) -> AlertCard;
```

**Behaviour, from `d1.js` (`makeDrain`), with the changes the budget forces:**
- **Lane geometry:**
  - Model cells: `CW=24`, `LY=16`, `LH=40`, `GATE=15` and 20 cells, with `sx(cell) = (19 - cell) * 24`.
  - A name enters at `head = -1` and advances one cell per tick.
  - There is one empty cell between names, and a new name enters when the last name's tail is ≥ 1.
  - While any name is stopped, all names halt.
  - Names are cut with `fit_name(name, 20)`.
- **Refusal steps:** a `Refused` name stops when `head == GATE - 1`, and the door shuts. Each step below is one tick, and no step changes both the lane band and the funnel:
  1. stop: the tiles turn blue and the door shuts.
  2. hold.
  3. sag (`m=1`).
  4. puddle and drips (`m=2`).
  5. `m=3`.
  6. `m=4`, the drop.
  7. `m=5`, the drop lower.
  8. **puddle and drops vanish** (a new step, split from the mockup's step 8).
  9. **land**: `min(len, head+1)` funnel cells take the next shade, with `flip=2`.
  10. `flip=1`.
  11. `flip=0`.
  12. **count +1**.
  13. the door reopens and the name is done.
- **Landing:** if a landing run would wrap past the last funnel cell, it starts at cell 0 instead, so one landing never spans the spout and the top row.
- **Funnel:** 10 rows of `28 - 2r` cells, plus 2 rows of 4 cells (198 cells in all), at a 12 px pitch.
  - Origin: `CX=304`, `TOP=80`.
  - The cell order and the head start at 47, as in `d1.js`.
  - The seeded generator is mulberry32 (as in `common.js` `rng`). It is deterministic and has no `rand` dependency.
- **Queue:**
  - `offer` drops a name equal to one already queued or on the lane.
  - The queue holds 4: on overflow it sheds the oldest `Plain`, then the oldest `Listed`, then the oldest `Refused`.
  - A `Refused` name offered while `paused` is shown as `Listed`.
  - A `Listed` name is drawn as a white outline only while paused. Otherwise it is drawn as plain.
- **Count:**
  - `count()` is `blocked_today - refused_in_flight`, where in-flight means queued or on the lane and not yet past step 12.
  - It never decreases unless the new `blocked_today` is below what is shown, as at a day rollover. Then it is the new value.
  - It is `None` until `set_blocked_today(Some(_))`.
- **`Stills::step_toward`:** copies **one** differing field from `wanted` and returns `true`, or returns `false` if they are equal.
  - Order: `blocking`, then `alert`, then `count`, then `percent`, then `clock`.
  - This keeps every still region in a write of its own.
- **`alert_card`:**
  - Titles by kind:
    - `threat` → `THREAT`/`BLOCKED`
    - `rebind` → `REBIND`/`BLOCKED`
    - `dga` → `RANDOM`/`NAMES`
    - `tunnel` → `DNS`/`TUNNEL`
    - `beacon` → `BEACON`/`SEEN`
    - `burst` → `QUERY`/`BURST`
    - `new_device` → `NEW`/`DEVICE`
    - `arp_spoof` → `ARP`/`SPOOF`
    - any other kind: upper-cased and split at the first `_`, giving `[first, rest]`.
  - `who`:
    - `new_device` and `arp_spoof`: `at <ip>`
    - any other kind: `asked by <ip>`
    - no client: `""`.
  - The subject is cut with `fit_name(subject, 26)`.
  - The card is white when `high` is true and blue otherwise.

- [ ] **Step 1: Move `changed_rows`.** Move it and its unit tests into `qb_panel::rows` unchanged, and make `fb.rs` import it. `cargo test -p qberrypi panel::fb` passes.
- [ ] **Step 2: Write the failing tests** in `drain/mod.rs`:
  - `a_refused_name_stops_at_the_gate_and_takes_thirteen_steps`: offer `"doubleclick.net"` (Refused) to `Drain::new(7)` and tick until `refusal_step() == Some(1)`. Its head is at cell 14, and the step then counts 1..=13 one per tick, then `None`. The funnel changes only at steps 9–11.
  - `plain_names_pass_the_gate`: `"example.org"` (Plain) crosses cells 0..19 and leaves. `moving()` turns false after the tail leaves.
  - `a_burst_keeps_the_queue_at_four_refused_first`: offer 30 Refused and 5 Plain while the lane is halted. The queue length is ≤ 4, and no Plain is kept while a Refused was shed.
  - `duplicates_are_not_queued_twice`.
  - `long_and_odd_names_fit_twenty_cells`, for `fit_name`:
    - a 253-char name gives 20 chars ending `~`;
    - `"Ads.Example.ORG."` gives `"ads.example.org"`;
    - `"bücher.example"` gives `"b?cher.example"`.
  - `the_count_follows_the_day_and_holds_back_names_in_flight`:
    - `None` before set;
    - set 4780 with one Refused in flight gives 4779;
    - after step 12 it gives 4780;
    - set 12 (a new day) gives 12.
  - `a_landing_never_wraps`.
  - `step_toward_moves_one_field_in_order`.
  - `alert_cards_for_every_kind`, including `who` for `None`, v4 and v6 clients.
- [ ] **Step 3: Run the tests** and see them fail to compile or fail.
- [ ] **Step 4: Implement** `look.rs`, `drain/mod.rs` and the `format.rs` additions. No rendering.
- [ ] **Step 5: Run the gates** and see them pass.
- [ ] **Step 6: Commit** with "qb-panel: the Drain scene model, and changed_rows moves here".

### Task 2: The Drain painter, goldens, render timing and the rows budget

**Files:**
- Create: `crates/qb-panel/src/drain/paint.rs`.
- Create: `crates/qb-panel/tests/drain_golden.rs`, `crates/qb-panel/tests/drain_budget.rs`, and `crates/qb-panel/tests/reference/drain-{normal,paused,alert}.png`.
- Modify: `crates/qb-panel/src/lib.rs`, and `crates/qb-panel/src/text.rs` if a glyph-coverage cache is added.
- Design 8's `draw.rs`, `golden.rs` and `budget.rs` stay until Task 5.

**Interfaces:**
- Consumes: Task 1's `Drain`, its read accessors, `Stills`, `AlertCard`, `changed_rows` and `look.rs`.
- Produces:

  ```rust
  pub struct Painter { /* persistent RGBA + RGB565 frames, what was last painted */ }
  impl Painter {
      pub fn new() -> Self;
      pub fn paint(&mut self, drain: &Drain, stills: &Stills) -> &[u8];  // whole RGB565 frame, 307,200 bytes
      pub fn rgba(&self) -> &[u8];                                        // the same frame as RGBA, for tests/preview
  }
  pub fn drain_fixture(which: Fixture) -> (Drain, Stills);   // pub enum Fixture { Normal, Paused, Alert }
  ```

**Drawing (every number from `d1.js` `draw()` and `common.js`):**
- **Order:** left column, funnel, count, rails and gate, lane tiles and melt, then the alert takeover on top.
- **Left column:**
  - `percent%` (or `—%`) at (6,120), `PERCENT_PX=40` bold white;
  - `REFUSED` at (8,144), 14 px bold g2;
  - `HH:MM` (or `--:--`) at (6,190), `CLOCK_PX=26` bold g1;
  - the key at (8,220,80,84), as in `drawKey` with px 24:
    - on: a blue fill, `GATE` 16 bold blueNight at y+24, and `SHUT` 24 bold white at y+h−14;
    - paused: a black fill, a 4 px white inset stroke, `GATE` in g1, and `format::countdown(left)` in white.
- **Count:** `format::count(n)` (or `—`), 64 px bold white, centred at (304,306).
- **Rails and gate:**
  - Rails: g4 rects (0,6,480,4) and (0,62,480,4).
  - Gate when not paused: blue (96,0,24,6) and (96,66,24,246); the door (96,6,24,60) while shut.
  - Gate when paused: a hollow white 4 px stroke rect at (98,68,20,242).
- **Funnel dots:**
  - r 5, in blue (shade 2) or blueDk (shade 4);
  - flip 1: r 6, white;
  - flip 2: a white ellipse with rx 2, ry 6.
- **Tiles:** as in `laneTile`, 22×40 at `sx(cell)+1`.
  - ok: a blueDeep fill with a g1 letter;
  - ref: a blue fill with a white letter;
  - pass: a white 2 px stroke with a white letter;
  - letter: 24 px bold, centred, baseline y+29.
  - The melt stages m1–m5 are exactly the `d1.js` rects and arcs, with the drip length `4 + (i % 3) * 4`.
  - The tile in the gate cell is hidden while the door is shut.
- **Alert takeover:** `drawAlertTakeover` at (128,76,352,244), with the card colour as the ground and black ink.
- **Speed:** keep the frame between calls.
  - Repaint only the bands whose content changed: clear the band, then redraw the layers that meet it, clipped with a `tiny_skia::Mask` or by drawing band-local.
  - Convert to RGB565 only the repainted rows.
  - Cache glyph coverage per (char, size, weight).
  - Target, release on this host: ≤ 1 ms for a steady motion frame, and ≤ 5 ms for a full repaint.
  - Repainting the full frame every time is acceptable only if it still meets 1 ms.

- [ ] **Step 1: Write `drain_fixture`** with fixed states that mimic the mockup stills, at percent 44, clock 10:21 and count 4780:
  - **Normal:** `Drain::new(7)` with `"googlesyndication.com"` Refused, ticked until `refusal_step() == Some(4)` (`m=2`, puddle with drips, as in the still), plus a Plain `"example.org"` behind it.
  - **Paused:** blocking `Paused { left_secs: 277 }` (`4:37`), with `"amazon-adsystem.com"` Listed and `"openx.net"` Listed passing beyond the gate, and `"example.org"` Plain entering at the right.
  - **Alert:** Normal plus `alert_card("threat", true, "secure-login-verify.example.org", Some(192.0.2.23))`.
- [ ] **Step 2: Write the failing tests** in `drain_golden.rs`. Copy the three-part metric (`diff`, `close`, the alteration helpers) from `tests/golden.rs`.
  - `drain_{normal,paused,alert}_render_as_the_reference`: each compares the painter's RGBA against `tests/reference/drain-*.png`. On failure it saves the actual PNG to `CARGO_TARGET_TMPDIR`.
  - `the_metric_rejects_altered_drain_frames`: these 6 alterations of the normal frame must fail `close`:
    - the count 2 px down;
    - the key missing;
    - the gate missing;
    - the accent replaced by `#5b6cf0`;
    - `REFUSED` in white;
    - the ground at `[3,3,3]`.
  - `the_painter_draws_the_same_frame_whether_built_up_or_fresh`: paint 40 ticks of traffic, then compare with a fresh `Painter` that paints the final state once. The two frames are byte-equal, which proves the band repaint leaves no stale pixels.
  - `#[ignore] drain_matches_the_mockup`: when `QBP_MOCKUP_DIR` is set, it compares these regions with the mockup stills and prints the metric per region:
    - the left column (0,64,96,256);
    - the count (128,240,352,80);
    - the gate column (96,0,24,320);
    - for the alert, the card minus its subject and who lines.
- [ ] **Step 3: Implement `paint.rs`.**
  - Generate the three reference PNGs once with a throwaway `#[ignore]` writer (or the xtask in Task 5). Inspect them by eye beside the mockup stills before committing.
  - Run `drain_matches_the_mockup` and record its numbers in the ledger.
- [ ] **Step 4: Write `drain_budget.rs`**, which has a deterministic traffic generator: a port of `common.js` `Sim.step`, with 44% Refused and bursty arrivals, from seed 7.
  - It runs the panel's write schedule: per tick, `offer`, then `tick`, then paint with the shown stills, then measure. Then, if `shown.step_toward(&wanted)`, it paints again and measures again.
  - `budget_steady_traffic_every_write_fits_80_rows` (not ignored): 150 s of normal traffic. The clock advances each minute, `blocked_today` rises with the traffic, and the percent is recomputed each second.
    - The first write and the pause toggles are excluded.
    - Every write is ≤ 80 rows by `changed_rows` on RGB565 frames.
    - The average per tick (motion + still) is ≤ 48 rows (15%).
    - It prints avg, peak and p95.
  - `budget_paused_every_write_fits_80_rows`: the same, while paused, with the countdown ticking each second.
  - `#[ignore] render_time_per_frame`, run in release: it prints the mean and max µs for a steady motion frame, a still write, and a full repaint (`Painter::new` plus one `paint`). It asserts the steady frame is < 1 ms and the full repaint is < 5 ms.
- [ ] **Step 5: Run the gates** and see them pass. Run `cargo test -p qb-panel --release --test drain_budget -- --ignored --nocapture` and record the numbers in the ledger.
- [ ] **Step 6: Commit** with "qb-panel: the Drain painter, its goldens, render time and rows budget".

### Task 3: The lane feed and the DNS hook

**Files:**
- Create: `crates/qberrypi/src/lane.rs`.
- Modify: `crates/qberrypi/src/lib.rs` (`pub mod lane;`), `crates/qberrypi/src/dns/mod.rs` (a `lane: OnceLock<Arc<LaneFeed>>` field, `set_lane`, and the hook in `decide`), and `crates/qb-dns/src/decide.rs` (`pub fn lists(&self, name: &str) -> bool`, which says whether the block set blocks the lower-case `name`, whatever the pause).
- Modify: `crates/qberrypi/src/wiring.rs`: `Slot` owns `lane: Arc<LaneFeed>` (made in `Slot::new`) and gains `pub fn lane(&self) -> Arc<LaneFeed>`.
- Modify: `crates/qberrypi/src/services.rs`: one line where the slot is filled, `dns.set_lane(slot.lane())`.

**Interfaces (Produces):**

```rust
// crate::lane — no Debug, no Serialize, nothing here logs.
pub const LANE_SLOTS: usize = 8;
pub const LANE_NAME_BYTES: usize = 32;   // first 32 bytes kept, plus a `cut` flag; the panel shows 20
pub struct LaneFeed { /* Mutex<Ring> taken only with try_lock; AtomicU64 last plain second; AtomicU64 dropped */ }
pub struct LaneName { pub name: String, pub kind: qb_panel::drain::NameKind }  // built on the panel side only
impl LaneFeed {
    pub fn new() -> Arc<Self>;
    pub fn observe(&self, name: &str, refused: bool, mono_secs: u64, listed: impl FnOnce(&str) -> bool);
    pub fn take(&self, out: &mut Vec<LaneName>);   // panel thread; drains the ring, oldest first
    pub fn dropped(&self) -> u64;
}
impl Dns { pub fn set_lane(&self, lane: Arc<LaneFeed>); }
```

**Hot-path rules for `observe`:**
- A plain name passes the gate only when `mono_secs` differs from the last plain second, which is decided with one `compare_exchange`. A refused name always passes.
- `listed` is called only for a plain name that passed the gate, which is at most one per second. `Dns::decide` passes `|n| resolver.lists(n)` only while the resolver is paused, and otherwise `|_| false`. It lower-cases into a `[u8; 253]` on the stack.
- The ring is taken with `try_lock`. If it is busy or poisoned, the name is dropped and counted.
- In a full ring, a refused name replaces the oldest non-refused entry. Otherwise it is dropped and counted.
- There is no allocation: the bytes are copied into the slot's `[u8; 32]`.
- **In `Dns::decide`:**
  1. Read `stats().total().queries` before `handle_query` and after it.
  2. Only if they differ and a lane is set, take `stats().recent(1).next()` and call `observe(&entry.name, entry.outcome == Outcome::Blocked, now.mono_secs, …)` while the resolver guard is still held.
  3. The query log is 50,000 entries, so `recent(1)` is the query just recorded.

- [ ] **Step 1: Write the failing tests** in `lane.rs`:
  - `plain_names_are_sampled_once_a_second_refused_always`;
  - `a_full_feed_drops_and_counts`: a ring of 8 refused, then a 9th refused and a plain. Both are dropped, and `dropped()==2`;
  - `a_refused_name_displaces_a_plain_one`;
  - `listed_is_asked_only_for_sampled_plain_names`;
  - `names_are_cut_to_32_bytes_at_a_char_boundary`;
  - `a_busy_ring_drops_instead_of_waiting`: hold the lock from the test and call `observe`;
  - `take_returns_oldest_first_and_empties`.
- [ ] **Step 2: Write the DNS tests** in `dns/mod.rs`:
  - `decide_offers_blocked_and_sampled_names_to_the_lane`: a block set with `ads.example.org`, two asks of each of a blocked name and a plain name in the same second. The feed holds the blocked name twice and the plain name once.
  - `a_paused_listed_name_comes_out_listed`.
  - `no_lane_no_offer`.
- [ ] **Step 3: Write `#[ignore] decide_cost_with_and_without_the_lane`.** It times 200,000 `decide` calls on a cached name, a blocked name and a forwarded name, with the lane unset and set, and prints the ns per query for each. Assert that the lane adds < 200 ns per query in release.
- [ ] **Step 4: Implement**, and run the tests until they pass.
- [ ] **Step 5: Run the gates.** Run the cost test with `--release -- --ignored --nocapture` and record the numbers in the ledger.
- [ ] **Step 6: Commit** with "lane: a never-waiting feed of sampled names from the resolver to the panel".

### Task 4: The panel loop at 8 fps, alerts and touch

**Files:**
- Create: `crates/qberrypi/src/panel/alerts.rs`.
- Modify: `crates/qberrypi/src/panel/mod.rs` (the loop, `Deps`, and the tests), `crates/qberrypi/src/panel/view.rs` (snapshot → wanted `Stills`), and `crates/qb-panel/src/touch.rs` (the regions).
- Modify: `crates/qberrypi/src/init.rs::panel_deps` (two fields).
- Also modify `crates/qberrypi/src/thermal.rs` callers only if the board temperature is no longer read by the panel. The board temperature is no longer shown, so drop that read from the panel.

**Interfaces:**
- Consumes: `Drain`, `Stills`, `Painter`, `alert_card` (Tasks 1–2), and `LaneFeed::take` and `Slot::lane()` (Task 3).
- Produces:

  ```rust
  // crate::panel::alerts — the read side the session lead wires to wd-b's AlertStore at merge.
  #[derive(Clone)] pub enum Severity { Info, Warn, High }   // same variants as wd-b's alerts::Severity
  #[derive(Clone)] pub struct PanelAlert { pub id: u64, pub kind: String, pub severity: Severity,
                                           pub client: Option<std::net::IpAddr>, pub subject: String }
  pub trait PendingAlerts: Send + Sync {
      fn top(&self) -> Option<PanelAlert>;   // the alert to show: unacknowledged, highest severity, newest
      fn ack(&self, id: u64);
  }
  pub struct NoAlerts;                       // stand-in: top() is None, ack does nothing
  // Deps gains: pub lane: Arc<LaneFeed>, pub alerts: Arc<dyn PendingAlerts>
  // qb_panel::touch
  pub enum Control { BlockingSwitch, DismissAlert }
  pub fn hit(x: u16, y: u16, alert_shown: bool) -> Option<Control>;
  // TapTracker::feed(&mut self, at_ms: u64, event: TouchEvent, alert_shown: bool) -> Option<Control>
  pub fn wanted_stills(snapshot: &Snapshot, paused_left: Option<u16>, now_unix: u64,
                       alert: Option<&PanelAlert>) -> Stills;   // in panel/view.rs
  ```

**Behaviour:**
- **Frame:** `FRAME_MS = 125` (8 fps), and `STILL_OFFSET_MS = 62`. A still write goes half a frame after a motion write, so the fbtft deferred io (a flush delay of 50 ms or less) sends the two as separate spans.
- **Each frame:**
  1. `lane.take` → `drain.offer`.
  2. `paused_left_secs()` from the control.
  3. Every `SNAPSHOT_MS = 1000`: `source.snapshot()` and `alerts.top()`, then `wanted = wanted_stills(..)` and `drain.set_blocked_today(..)`. `wanted.count` is always `drain.count()`.
  4. If `drain.moving()`: `drain.tick(paused)`, then `paint(&drain, &shown)` and `show`.
  5. At +62 ms: if `shown.step_toward(&wanted)`, then `paint` and `show`.
  6. When neither happens, nothing is painted. The loop still waits on the touch device for at most a frame.
- **`wanted_stills`:**
  - percent: `(blocked*100 + total/2) / total`, with `None` when the total is 0 or unknown.
  - clock: from `now_unix + utc_offset_secs`, only when `snapshot.clock_set`, using `view::time_of_day`. `now_unix` comes from `SystemTime` in the loop.
  - alert: `alert_card(kind, severity == High, subject, client)`.
- **Touch:**
  - The key's hit region is (0,212,96,108).
  - The alert's region (128,76,352,244) is live only while `shown.alert` is set, and a tap there gives `DismissAlert`. It calls `alerts.ack(id)`, clears the alert in both `shown` and `wanted` (one discrete write), and does not touch blocking.
  - A tap on the key behaves exactly as now: it pauses for 300 s or resumes, it logs `panel: switch: …`, and the next frame draws.
  - `Decoded::Lost`, calibration and the tap rules are unchanged.
- **Stale alert:** if `top()` returns `None` or another id, the takeover follows it at the next snapshot.
- **Logging:** nothing in the loop logs a name or an alert subject.

- [ ] **Step 1: Write the failing tests** in `qb-panel/src/touch.rs`:
  - `the_key_is_tapped_at_its_region_and_the_alert_only_when_shown`;
  - the existing TapTracker tests, ported to the new signature.
- [ ] **Step 2: Write the failing tests** in `panel/mod.rs`, using the existing `Recorder`, `Fixed` and `FakeControl` helpers plus a `FakeAlerts`:
  - `names_from_the_lane_move_at_eight_frames_a_second`: offer a refused name to the feed and turn the panel at 0, 62, 125, … ms. The frames shown are motion frames 125 ms apart, and each is ≤ 80 rows by `changed_rows` against the previous frame.
  - `an_idle_panel_paints_nothing`: no names and fixed stills give no new frame for 10 s after the first.
  - `a_tap_on_the_key_pauses_and_the_countdown_steps`: the port of the existing switch tests.
  - `a_tap_on_the_alert_acks_it_and_the_key_still_pauses`: the alert is shown, a tap acks id 7, and the takeover is gone in the next frame. Then a tap on the key pauses.
  - `wanted_stills_from_the_reference_snapshot`: the result is 44%, 10:20 with the clock set, `--:--` without it, and the count is the drain's.
  - `the_panel_never_logs_a_name`: use a `log` capture if the crate has one, else assert by review.
- [ ] **Step 3: Implement.** Add the two fields to `init.rs::panel_deps`: `lane: slot.lane()` and `alerts: Arc::new(NoAlerts)`.
- [ ] **Step 4: Run the gates**, plus `cargo xtask build && cargo xtask qemu-test`, because `init.rs` is touched.
- [ ] **Step 5: Commit** with "panel: Drain at 8 fps on the panel's thread, with the alert takeover and its tap".

### Task 5: Design 8 goes; the preview draws Drain

**Files:**
- Delete:
  - `crates/qb-panel/src/draw.rs`;
  - `crates/qb-panel/tests/golden.rs` and `crates/qb-panel/tests/budget.rs`;
  - `crates/qb-panel/tests/reference/design-8-reference.{png,svg}` (they stay in git history);
  - the design-8-only items in `geometry.rs`, `format.rs` and `state.rs`: `PanelState`, `LatestBlocked`, the dial, meter and window constants, `name_lines`, `footer`, `latency`, `signal`, `temperature`, `time_line` and `day_line`.
- Keep: `TimeOfDay`, `Blocking`, `Switch`, `Calibration`, `Weight`, `Anchor`, `TextSlot`, `Rgb`, `WHITE`, `MUTED` (`calibrate.rs` uses it), `rgba_to_rgb565`, `text.rs`, `WIDTH` and `HEIGHT`.
- Modify: `crates/qb-panel/src/lib.rs` and its crate doc, `crates/qb-panel/Cargo.toml` (the `description`), and `xtask/src/panel.rs`.
- Modify `README.md` and `docs/` only where they describe the panel's look; plans are history and are not edited.

**`xtask panel-preview`:** add `--state normal|paused|alert` (default normal), which renders `drain_fixture(..)` through `Painter` into the PNG. `--push` is unchanged. Remove the design-8 value flags, and update its tests to match.

- [ ] **Step 1: Delete design 8** and fix what fails to compile.
- [ ] **Step 2: Port the xtask tests:**
  - `each_state_renders_its_fixture`;
  - the PNG-writing tests use `drain_fixture(Fixture::Normal)`;
  - the push tests are unchanged.
- [ ] **Step 3: Generate the preview.** `cargo xtask panel-preview --state alert --out target/tmp/p.png` gives the same pixels as `tests/reference/drain-alert.png`.
- [ ] **Step 4: Run the gates**, plus the qemu gate, because `xtask` is touched.
- [ ] **Step 5: Commit** with "qb-panel: design 8 goes; panel-preview draws Drain".

## Seams for the session lead (merge notes)

- **Alert store:**
  - Implement `panel::alerts::PendingAlerts` for wd-b's `AlertStore`:
    - `top()` is the newest unacknowledged alert of the highest severity, mapped to `PanelAlert`, whose `id` is `AlertView.id`.
    - `ack(id)` calls the store's `ack(id)`.
  - Then replace `Arc::new(NoAlerts)` in `init.rs::panel_deps`.
  - wd-b's `Severity` has the same variants, so a `From` impl is enough.
- **`dns/mod.rs`:** wd-b adds a `watch` field and `observe` in the listener. This track adds a `lane` field and four lines in `decide`. Keep both.
- **`services.rs`:** one line, `dns.set_lane(slot.lane())`, next to `slot.fill(..)`.
