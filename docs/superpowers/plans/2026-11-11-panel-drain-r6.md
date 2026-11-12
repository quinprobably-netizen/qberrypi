# Front panel "Drain", round 6 port: Implementation Plan

> **For agentic workers:** lean subagent-driven development: one fresh implementer per task, no per-task review, one whole-branch review at the end. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Port the owner-approved round 6 design pass of the Drain into the real renderer. Build all of it: the new grid, the left-column sizes, the bowl-neck-spout funnel that starts empty and fills from the tip, the spout drop, the melt that runs away from the gate, the count's comma slot, the `OPEN m:ss` key and the refilling gate, the new alert card, the boot / listening / quiet lane words, the `%` forms, and the refused-name fitting rule.

**Source of truth:** `~/Work/qberrypi-mockups/round6/`.
- `README.md`: the changes 1–35, and the "Numbers for building it" table (round 5 → round 6).
- `src/d6.js`: the new Drain (`makeDrain6`, `drawAlert6`, `tx`, `drawCount`, `fitSite`, `wrapName`, `count6`).
- `src/common.js`: the palette and the traffic `Sim`. `src/scenes.js`: how each still is made.
- Stills `r6-after-<state>@2x.png` (960×640, a nearest-neighbour 2× of the 480×320 canvas: pixel (x, y) of the panel is pixel (2x, 2y) of the still). `r6-after-refusal-strip.png` is one refusal frame by frame, at 1×.

Where this plan and `d6.js` disagree on a coordinate, `d6.js` wins; report it.

**What exists (round 5, built):** `crates/qb-panel/src/drain/{mod.rs,look.rs,paint.rs,fixture.rs}`, `crates/qb-panel/src/{format.rs,touch.rs,rows.rs}`, the tests `crates/qb-panel/tests/{drain_golden.rs,drain_budget.rs}` with goldens in `tests/reference/drain-*.png`, and the loop in `crates/qberrypi/src/panel/{mod.rs,view.rs,alerts.rs}`. Read the round 5 plan `docs/superpowers/plans/2026-11-11-panel-drain.md` for the conventions; they all still hold.

## Global constraints

- **Process:** follow `~/Work/qberrypi/target/tmp/wd-common.md`. `export TMPDIR=~/Work/qberrypi-drain2/target/tmp`. Never read or touch `~/Work/qberrypi/qberrypi.toml`; never contact the Pi; no `git reset --hard`, no `git clean`.
- **Gates before every commit:** `cargo test --workspace`; `cargo clippy --workspace --all-targets` with 0 warnings; `cargo fmt --all --check`; `cargo build -p qberrypi --release --target aarch64-unknown-linux-musl`; `grep -rln unsafe crates/qberrypi/src crates/qberrypi/tests` prints only `crates/qberrypi/src/sys.rs`. No task here touches `init.rs` or `xtask`; if one must, it also runs `cargo xtask build && cargo xtask qemu-test`.
- **Commits:** stage files by name, end with `Co-Authored-By: Claude Sonnet <noreply@anthropic.com>` (the implementer's model), never push.
- **Look:** 480×320 on black; the round 5 palette only (`look.rs` already has it, including `BLUE_MD`); JetBrains Mono from `crates/qb-panel/fonts`; flat rects, circles, triangles and text.
- **Budget:** every write is at most 80 rows as `changed_rows` (first..last changed row) measures it. Allowed one-off large writes: a pause toggle, an alert appearing / changing / going, and Wi-Fi joining. Each refusal step is a frame of its own, and a motion write never carries a still figure (they stay separate writes, as now).
- **Privacy:** no name in a log; no `Debug` that prints a name (keep the redacting `Debug` on `Tile` and `AlertCard`; any new type that holds a name gets none or a redacting one).
- **Hot path:** `crates/qberrypi/src/lane.rs`, `dns/` and the `LaneFeed` hook are not touched. All name fitting happens in `Drain::offer`, on the panel thread.
- **Rendering stays off the runtime thread** (the panel's pool thread, as now).
- **Public repo:** tests use example.org / example.com names, 192.0.2.x, or the public ad names of the mockup's `ADS` list.

## Rulings (track lead)

1. **The funnel starts empty** on the real panel: `Drain::new` makes 146 empty sockets. Fixtures that show a full funnel use a prefill that is the mockup's `fill(N)`: mulberry32 seeded 7, **one draw discarded** (the mockup's `Sim` constructor draws once in `stats()`), then runs of `6 + floor(r * 10)` dots in the three shades in turn from `BLUE`; after a full prefill the next landing starts at dot 61.
2. **Name fitting:** every name goes through `fit_site(name, cells)` (the mockup's `fitSite`, after `fit_name`'s lower-casing, trailing-dot removal and `?` replacement): 15 cells for a `Refused` name, 20 for `Plain` and `Listed`. A `Refused` name offered while paused becomes `Listed` and gets 20.
3. **Wi-Fi:** joined means `snapshot.wifi` is `Some` with `associated == true`. While not joined the lane says `JOINING WI-FI` (also after a later drop; `NO WI-FI` is deferred), and the `%` and the count are dashes; the clock follows `clock_set` as now.
4. **`LISTENING`:** joined and `today` is `None` or has 0 queries. **`QUIET n MIN`:** joined, queries today > 0, and 2 minutes or more since the panel loop last took a lane name (the loop starts its timer at its first frame). `n` is whole minutes below 120, then `n H` (whole hours) below 48 h, then `n D`.
5. **The `%`:** `—` (dim) for no queries; `0%` only when nothing was blocked; `ALL` when everything was; `<1%` when the rounded share is 0 but something was blocked; otherwise the rounded share, at most `99%`.
6. **The gate's refill** is a still of its own (`Stills::gate_fill`, 0–18 steps of 12 px), computed from the seconds left as `floor((300 − left) * 19 / 300)`, so it is never in the same write as the key's countdown.
7. **Still order** (`Stills::step_toward`): `blocking`, `gate_fill`, `alert`, `count`, `percent`, `clock`, `words`. The mockup's "no still on a refusal step" (change 35) is not needed: stills already go out in writes of their own, half a frame after the motion write.
8. **Refusal timing** is `d6.js`'s exactly, with `w = floor((len − 1) / 5)` and `G = 8 + w`; the door shuts at step 1 and reopens at `G + 7`, which is the last step; the name leaves on the next tick.

## Review focus

1. A refusal of a 15-letter name: 17 steps, each changing one place (lane, funnel, spout drop, count), each write ≤ 80 rows. Tests in Tasks 1 and 3.
2. A burst of refused names (the round 5 flood test) still holds every write ≤ 80 rows, with the new melt band (tiles from y 16 down to the low teardrop at about y 90).
3. A name of 253 characters, with odd bytes, under a two-letter TLD with a short second level (`a.b.c.example.co.uk`), or with no dots: `fit_site` never panics and never exceeds its cells.
4. Taps while the alert is up: a tap anywhere on the new card (128, 80, 344×224) dismisses it and acks the store's alert; the key still works.
5. The `QUIET` timer across the panel's first frame, a long idle (days), and a name arriving while the words are up (the words go in the same frame the name is queued).

---

### Task 1: The model and the formats (qb-panel, pure)

**Files:** `crates/qb-panel/src/drain/mod.rs`, `crates/qb-panel/src/drain/look.rs` (funnel and lane constants only), `crates/qb-panel/src/format.rs`, `crates/qb-panel/src/state.rs` (or a new small module for `Share` / `LaneWords`), `crates/qb-panel/src/lib.rs` (re-exports). Update every existing test these break, in the same files. The painter, fixtures and goldens (Task 2) may stop compiling or fail; make them compile with the least change (for example a `todo`-free stub drawing of the new states), and mark golden tests `#[ignore = "refreshed in task 2"]` if they fail, so the gates pass.

**Funnel (`look.rs` + model):**
- `FUNNEL_ROWS: [u16; 12] = [29, 25, 21, 17, 13, 11, 9, 7, 5, 3, 3, 3]`, `FUNNEL_CELLS = 146`, `FUNNEL_CX = 300`, `FUNNEL_TOP = 80`, pitch 12. Row `r`'s centre y is `80 + 12r + 6`; a dot's x is `300 + 12·(c − (n−1)/2)`.
- `FUNNEL_CENTRES` are in **landing order**: from the last row (the spout's tip) upward, and to and fro: the tip row left to right, the row above it right to left, and so on (`d6.js` `XY`). Keep the compile-time assert that the count is 146.
- `FunnelCell` gains an empty state (for example `shade: Option<Shade>`); `Shade` has three values, `Blue`, `Mid` (`BLUE_MD`) and `Dark` (`BLUE_DK`), in turn per run.
- `Drain::new(seed)` starts with every dot empty and the landing at dot 0. Add `pub fn prefill(&mut self, seed: u32)` (Ruling 1), used by fixtures and tests.
- `land(n)`: if the landing index is at 146, it goes back to 0; `n` is cut to the dots left before 146 (the run is cut at the rim, never wraps); the dots become the current shade with `Flip::Edge`; the shade moves on.

**Refusal (Ruling 8), per stopped name of `len` letters:**
- Steps: 1 tiles blue, door shuts · 2 hold · tile `k` (letters from the gate, `k = 0` is the first letter, next to the gate) has melt stage `s = step − 2 − floor(k / 5)`: `s ≤ 0` whole, 1 sag, 2 puddle, 3 slump, 4 pool and teardrop, 5 teardrop lower (no pool), `≥ 6` gone. `G = 8 + floor((len−1)/5)`: the lane is clear. `G+1` land `len` dots (Edge) · `G+2` Face · `G+3` Rest · `G+4` the spout drop is shown · `G+5` it is gone · `G+6` the count ticks · `G+7` the door reopens, last step; the name leaves on the next tick.
- `Melt` gets the stages above (rename as fits: `Whole, Sag, Puddle, Slump, Drop, Fall`), per tile.
- `Tile::drip = 4 + ((ch as u32 * 7 + k * 5) % 3) * 4` (the letter's code point, `k` as above).
- `pub fn spout_drop(&self) -> bool`. `refusal_step()` stays. `in_flight` uses each name's own count step (`G+6`).
- `pub fn idle(&self) -> bool`: no name on the lane and none queued (the lane words show only then).

**Names:** `pub fn fit_site(name: &str, cells: usize) -> String` in `format.rs`, as `d6.js` `fitSite`: first as `fit_name` does (lower-case, one trailing dot off, `?` for non-printable), but without cutting; split at `.`; the site is 3 labels if there are ≥ 3 labels, the last has 2 characters and the one before it ≤ 3, else 2; drop leading labels whole while the joined length is over `cells` and more labels than the site are left; then if still over, the first `cells − 1` characters and `~`. It must cost a bounded amount for a name of any length (cap the input at, say, 256 characters first). `offer` uses it with 15 cells for `Refused` (after the paused → `Listed` change) and 20 otherwise.

**Formats and stills:**
- `pub enum Share { Zero, UnderOne, Percent(u8), All }` with `Share::of(blocked: u64, total: u64) -> Option<Share>` (Ruling 5; `None` for total 0; overflow-safe) and its text (`0%`, `<1%`, `44%`, `ALL`).
- `pub enum LaneWords { Joining, Listening, Quiet { minutes: u32 } }` with its text (`JOINING WI-FI`, `LISTENING`, `QUIET 47 MIN` / `QUIET 3 H` / `QUIET 2 D`, Ruling 4) and whether it is white (`Joining`) or `G2`.
- `pub fn gate_fill(left_secs: u16) -> u8` (Ruling 6; uses `touch::PAUSE_MS / 1000` as the pause length; saturates at 18 for 0 left and 0 for ≥ 300).
- `Stills`: `percent: Option<Share>`, add `gate_fill: u8` and `words: Option<LaneWords>`; `step_toward` in the order of Ruling 7.
- `AlertCard`: the subject becomes up to two lines (`d6.js` `wrapName` with 26 cells: one line if it fits; else, past 52, `~` and the last 51 characters; then cut after the last `.` at or before cell 26 that leaves ≤ 26 for line two, else at 26). Keep the redacting `Debug`. Title lines stay as now (13 cells). `alert_card` fills it.

**Tests (in `drain/mod.rs` and `format.rs`), at least:**
- `a_refusal_takes_fifteen_to_seventeen_steps_by_length` (len 1..=5 → 15, 6..=10 → 16, 11..=15 → 17) and each step's state (door, melt stages per tile, landing, flips, drop, count) changes one place only.
- `the_melt_runs_away_from_the_gate_five_tiles_a_frame`.
- `the_funnel_is_the_mockups_bowl_neck_and_spout` (146 centres, first is the tip row's left dot at (288, 218), x on 132 + 12n, all odd rows centred on 300) and `it_starts_empty_and_fills_from_the_tip`.
- `a_landing_run_is_cut_at_the_rim_and_the_next_starts_at_the_tip`, `three_shades_in_turn`.
- `prefill_is_the_mockups_fill` (compare the first runs with values worked out from `d6.js`; write them down in the test).
- `fit_site_drops_host_labels_then_cuts` (the mockup's examples: `pagead2.googlesyndication.com` → `googlesyndicat~`; `rubiconproject.com` → `rubiconproject~`; `a.b.example.co.uk` keeps `example.co.uk`; 253 chars; no dots; a lone `.`), `refused_names_fit_fifteen_cells_and_passing_ones_twenty`.
- `share_forms` (0/q → `0%`; 1/1000 → `<1%`; 999/1000 → `99%`; q/q → `ALL`; 0/0 → None; `u64::MAX`), `lane_words_text`, `gate_fill_steps`, `step_toward_moves_one_field_in_order`, `alert_subject_wraps_after_a_dot`, and the existing burst, duplicate, count-around-midnight, no-panic and no-name-in-`Debug` tests kept passing.

**Acceptance:** gates pass; commit `panel: the round 6 Drain model: funnel, melt, fitting and the new figures`.

---

### Task 2: The painter, the look, the fixtures and the goldens (qb-panel)

**Files:** `crates/qb-panel/src/drain/look.rs`, `crates/qb-panel/src/drain/paint.rs`, `crates/qb-panel/src/drain/fixture.rs`, `crates/qb-panel/src/touch.rs` (`ALERT_TARGET` = the new card), `crates/qb-panel/tests/drain_golden.rs`, `crates/qb-panel/tests/reference/drain-*.png`, and `crates/qb-panel/src/text.rs` only if a helper is needed.

**Look (`look.rs`), every number from the README table and `d6.js`; replace the round 5 values, delete what is no longer drawn:**
- Rails y 4 and 64, 4 px, full width, `G4`. Gate x 96, 24 wide: blue y 0–4 and 68–304; door 4–68 while shut. Paused: white 96..120 × 68..304 with black inside 100..116 × 72..300 (a 4 px outline); the refill is blue at x 100..116, height `gate_fill × 12`, its foot at y 300.
- Tiles: letter baseline `LANE_Y + 28`, letter centre at the tile's left + 11. Lane words: 24 px bold, one character per cell, centred at x `132 + 24i`, baseline 45, white for `Joining`, `G2` otherwise; drawn only while `drain.idle()`.
- Melt (`d6.js` `drawMelt`, `x` = the tile's left edge, `mid = x + 11`, `bot = 56`): sag = blue `(x, 26, 22, 30)` + the letter white at baseline 50; puddle = `(x, 40, 22, 16)` + drip; slump = `(x, 50, 22, 6)` + drip of `drip + 6`; drop = `(x, 52, 22, 4)` + teardrop at `cy = bot + drip + 10`; fall = teardrop at `bot + drip + 18`. A drip is a rect `(mid − 3, bot, 6, len)` with a round tip, a circle r 3 at `(mid, bot + len)`. A teardrop is a circle r 4 at `(mid, cy)` and a triangle `(mid, cy − 11)`, `(mid + 3.5, cy − 2)`, `(mid − 3.5, cy − 2)`. Puddles keep the tiles' 22 px width (no more 24 px pools).
- Funnel: a lit dot is r 5 in its shade; an empty socket is r 2.5 `BLUE_DEEP`; Edge is a white ellipse 2 × 6; Face a white r 6 dot. The spout drop is white r 5 at (300, 234).
- Left column (`d6.js` `tx`: each glyph centred at `x + i·(0.6·px + ls) + 0.3·px`): `%` 46 px bold at x 5.2, baseline 114, white (a lone `—` in `G3` when unknown); `REFUSED` 16 px bold `G2` tracked 2.5 at x 6.4, baseline 138; clock 27.6 px bold `G1` at x 6.3, baseline 192 (`--:--` in `G3` when not set).
- Key 8, 224, 80×80. On: blue, `GATE` 16 px bold `BLUE_NIGHT` tracked 2 centred at baseline 254, `SHUT` 24 px bold white centred at baseline 286. Paused: a 4 px white outline on black, `OPEN` in `G1` tracked 2, the `m:ss` countdown in white, same places.
- Count: 64 px bold, centred on 300, baseline 304; digits in 0.6 em slots and `,` / `.` in a 20 px slot (`d6.js` `drawCount`), each glyph centred in its slot; white, or a dim `—` in `G3` when unknown. `format::count` stays as the text.
- Alert (`d6.js` `drawAlert6`): clear black x 120..480 × y 80..320; card 128, 80, 344×224 in white (high) or blue; the stub is the card's last 44 px, black inside with a 4 px rim (black rect `(132, 260, 336, 40)`); title lines 40 px bold black at x 142, baselines 125 and 167; subject lines 20 px bold black at x 143, 23 px apart, the last one at baseline 245 − 24 if there is a who line (else 245); who 18 px regular black at x 143, baseline 245; `TAP TO DISMISS` 20 px bold white tracked 2 centred at x 300, baseline 287.
- `touch::ALERT_TARGET` becomes (128, 80, 344, 224); keep its test that it equals `look::ALERT`.

**Painter (`paint.rs`):** keep the design (persistent frame, dirty rows, band-independent stamps and glyph cache). Add:
- a tracked / slotted text helper that draws glyph by glyph (centred in each slot) so the left column, the key, the count and the alert set as `tx` / `drawCount` do;
- stamps for r 2.5 and r 3, and a teardrop mask (circle + triangle) made once (tiny-skia into a coverage mask is fine), stamped band-independently;
- dirty rows for: `gate_fill` (the refill band), `words` and the lane's idle state (the words' rows), the spout drop (rows 228..240), the count's and the `%`'s new rows, the alert's cleared field (rows 80..320), and the tile band now reaching the low teardrop (about y 90; work it out from the constants).

**Fixtures (`fixture.rs`):** keep `Normal`, `Paused`, `Alert`, and add `AlertLow`, `AlertLong`, `Boot`, `Listening`, `Quiet`, `Long`, `Five`, `Six`, `Pct0`, `Pct100`. Each reproduces the mockup still of that name (`scenes.js`, with the shot defaults in `common.js` `mount`: clock 10:21, count 4,780, 44 %, pause 4:37 left). Names in the mockup that are not public ad names become example.org / example.com names of the **same length** (so the lane and card geometry match; the compare test skips those text rows). Where the mockup's lane is deterministic, place the names exactly as the still shows them:
- `Normal` and `Alert`: a 15-letter refused name at step 5 (the still shows `rubiconproject~`; `rubiconproject.com` is on the public `ADS` list) and a plain name whose last three letters `com` stand in cells 17–19; prefilled funnel (its later landings in the mockup come from random traffic and are not reproduced; say so in the doc comment).
- `Paused`: as the still (`rg` plain left of the gate; `amazon-adsystem.com` listed, outlined, crossing), gate_fill 1.
- `Long`: `pagead2.googlesyndication.com` refused, at step 2, prefilled funnel.
- `Quiet`: idle lane, `Quiet { minutes: 47 }`, prefilled funnel. `Boot`: empty funnel, `Joining`, dashes. `Listening`: empty funnel, `Listening`, count 0, `%` unknown, clock 10:21.
- `Five` (28,364 / 12,480 → count 12,480, 44 %) and `Six` (286,300 / 104,780 → count 104,780, 37 %): the normal scene with those figures.
- `Pct0`: empty funnel, no refusals, `0%`, count 0, and plain names passing as the still shows. `Pct100`: `adnxs.com`, `doubleclick.net`, `criteo.com` refused and landed (runs of 9, 15, 10 from the tip, in the three shades), lane idle with no words, `ALL`, count 3.

**Goldens (`tests/drain_golden.rs`):** regenerate `drain-normal.png`, `drain-paused.png`, `drain-alert.png` and add `drain-boot.png`, `drain-listening.png`, `drain-quiet.png`, `drain-long.png`, `drain-six.png` (the existing bless path or a documented env var). Look at each beside the mockup still before committing it. Keep `the_painter_draws_the_same_frame_whether_built_up_or_fresh` (extend its random scenes to the new states, including the spout drop, the refill, the words and two-line alerts) and `the_metric_rejects_altered_drain_frames`.

**Acceptance:** gates pass; the goldens look like the stills; commit `panel: paint the round 6 Drain, with goldens for every state`.

---

### Task 3: Proof against the mockup and the budget (qb-panel tests)

**Files:** `crates/qb-panel/tests/drain_golden.rs` (the mockup test), `crates/qb-panel/tests/drain_budget.rs`; painter or look fixes this finds, in `crates/qb-panel/src/drain/`.

- **Mockup comparison** (`#[ignore]`, run with `QBP_MOCKUP_DIR=~/Work/qberrypi-mockups/round6`): read `r6-after-<state>@2x.png`, take every second pixel, and compare each fixture region by region. Exact (0 difference) for regions of shapes only where the mockup is deterministic: the gate column, the rails, the key's fill and outline, the funnel in `Boot`, `Listening`, `Quiet`, `Long`, `Pct100`, the melting tiles' band in `Normal` (puddles, drips, teardrops; not the letters), the card's slab and stub outside text rows, the refill. Text regions: the round 5 tolerances (mean_abs ≤ 4, outliers ≤ 0.035, worst tile ≤ 70). Skip the rows of names that were replaced. Print every region's figures. Where an exact region cannot be exact, find why (tiny-skia vs Chrome antialiasing on the teardrop's triangle is a likely one), fix what is a mistake, and loosen only what is a rasteriser difference, with the reason in a comment.
- **The refusal strip:** a test that drives one refusal of `doubleclick.net` (15 letters, the strip's name) frame by frame through the painter and checks: 17 steps; each frame's changed rows lie in one place only (the lane band 0..100, the funnel 80..224, the spout drop 228..240, or the count 236..320, door rows counted with the lane); every write ≤ 80 rows. Optionally compare each frame's lane band with the strip image's frames (4 to a row, 8 px gaps, 1×; the strip starts at the frame before the stop).
- **Budget:** keep the steady, paused and flood runs and add a boot run (`Joining` → join → `Listening` → traffic, the funnel filling from empty). Every write ≤ 80 rows except the Wi-Fi join. Print per-write mean / p95 / peak and the per-frame average, as now.
- **Timing:** run the `#[ignore]` `render_time_per_frame` test in `--release` and record the numbers (steady motion, still write, full repaint).

**Acceptance:** gates pass; the ignored tests pass when run; commit `panel: check the round 6 Drain against the mockup and the budget`. Put the printed figures in the commit message body.

---

### Task 4: The panel loop (qberrypi) and the spec

**Files:** `crates/qberrypi/src/panel/view.rs`, `crates/qberrypi/src/panel/mod.rs`, `docs/superpowers/specs/2026-11-10-qberrypi-design.md` (the Front panel section only).

- `wanted_stills` gains what it needs for the new figures (for example `idle_secs: u64`): `percent = Share::of(..)` and `count` only while joined (Ruling 3); `gate_fill` from the seconds left; `words` by Rulings 3 and 4. Keep it free of names.
- `Panel` keeps the time (`now_ms`) of the last lane name it took (set whenever `deps.lane.take` gives at least one name; initialised at the first frame), and passes the idle time in at each refresh. The words change once a minute at most, as a still write.
- The alert takeover stays fed by the real store (`Slot::fill_alerts`, `PendingAlerts`): keep `a_tap_on_the_alert_acks_it_and_the_key_still_pauses` and `an_alert_that_leaves_the_store_clears_the_takeover` passing with the new card target.
- **Tests:** `boot_shows_joining_then_listening_then_the_count` (wifi `None` → associated with 0 queries → queries), `quiet_after_two_minutes_without_a_lane_name_and_gone_when_one_comes`, `the_percent_forms_reach_the_screen` (via `wanted_stills`), `the_gate_refills_as_the_pause_runs_out_in_writes_of_its_own`, and the loop's `steady_traffic_writes_at_most_eighty_rows_at_a_time` and one-refusal test updated to the new step count, with their figures printed. `the_panel_never_logs_a_name` stays.
- **Spec:** rewrite the Front panel section's look paragraphs for round 6 (funnel from empty, the new states and words, the `%` forms, the refill, the new card and its 344×224 target, the refused-name fitting) and the key's size (80×80). Keep it short.

**Acceptance:** gates pass; commit `panel: the loop drives the round 6 states: joining, listening, quiet, the % forms and the refill`.

---

### Review and fixes

One Opus whole-branch review against this plan, the README and `d6.js`; one fix wave for Critical and Important findings; Minors listed and deferred.
