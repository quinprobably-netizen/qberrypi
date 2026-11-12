//! The Drain painter: the scene as pixels, on a frame it keeps between calls.
//!
//! A `Painter` holds the last frame it painted, as RGBA for tests and the
//! preview and as RGB565 for the screen. A call compares the scene it is given
//! with the one the frame shows, finds the rows that can have changed, clears
//! those rows and draws every layer that meets them again, then converts only
//! those rows to RGB565. A fresh painter has nothing to compare with and
//! paints all the rows, so a frame is the same whichever way it was built up.
//!
//! Shapes that are round are stamped from the mockup's coverage masks (`stamps`), and text
//! comes from a cache of rendered glyphs, so that no pixel depends on where a
//! band of rows starts. Text is set glyph by glyph, each glyph centred in its
//! slot, as the mockup's `tx` and `drawCount` do. Nothing here panics,
//! whatever the scene.

use crate::drain::look::{
    ADVANCE_EM, ALERT, ALERT_FIELD, ALERT_INK, ALERT_LAST_DY, ALERT_STUB_H, ALERT_STUB_PX,
    ALERT_STUB_RIM, ALERT_STUB_TEXT, ALERT_STUB_TEXT_DY, ALERT_STUB_TRACKING,
    ALERT_SUBJECT_LEADING, ALERT_SUBJECT_PX, ALERT_TEXT_DX, ALERT_TITLE_DX, ALERT_TITLE_DY,
    ALERT_TITLE_PX, ALERT_WHO_LIFT, ALERT_WHO_PX, Area, BLUE, BLUE_DEEP, BLUE_DK, BLUE_MD,
    BLUE_NIGHT, CLOCK_BASELINE, CLOCK_PX, CLOCK_X, COUNT_BASELINE, COUNT_PX, COUNT_SEPARATOR_EM,
    COUNT_X, DOOR, DRIP_DX, DRIP_TIP_R, DRIP_W, DROP_DX, DROP_DY, DROP_FALL, FLIP_EDGE_RY,
    FLIP_FACE_R, FUNNEL_CELLS, FUNNEL_CENTRES, G1, G2, G3, G4, GATE_BOTTOM, GATE_FILL_FOOT,
    GATE_FILL_STEP, GATE_PAUSED, GATE_PAUSED_STROKE, GATE_TOP, GROUND, KEY, KEY_BIG_DY, KEY_BIG_ON,
    KEY_BIG_PX, KEY_LABEL, KEY_LABEL_DY, KEY_LABEL_OPEN, KEY_LABEL_PX, KEY_LABEL_TRACKING,
    KEY_STROKE, LABEL, LABEL_BASELINE, LABEL_PX, LABEL_TRACKING, LABEL_X, LANE_CELLS, LANE_H,
    LANE_Y, LETTER_BASELINE_DY, LETTER_DX, LETTER_PX, OUTLINE_PX, PERCENT_BASELINE, PERCENT_PX,
    PERCENT_X, POOL_H, PUDDLE_H, RAIL_BOTTOM, RAIL_TOP, SAG_DY, SAG_LETTER_BASELINE_DY,
    SLUMP_DRIP_EXTRA, SLUMP_H, SPOUT_DROP, SPOUT_DROP_R, TEAR_R, TILE_DX, TILE_W, WHITE,
    WORDS_BASELINE, WORDS_PITCH, WORDS_PX, WORDS_X, cell_x,
};
use crate::drain::stamps;
use crate::drain::{AlertCard, Drain, Flip, FunnelCell, Melt, Shade, Stills, Tile, TileStyle};
use crate::format::{self, DASH};
use crate::geometry::{Anchor, HEIGHT, Rgb, TextSlot, WIDTH, Weight};
use crate::rgb565::convert_into;
use crate::state::{Blocking, LaneWords, Share, TimeOfDay};
use crate::text::{ASCENT_EM, DESCENT_EM, GlyphCache};

/// How many bytes a row of the RGBA frame holds.
const RGBA_ROW: usize = WIDTH * 4;

/// How many bytes a row of the RGB565 frame holds.
const RGB565_ROW: usize = WIDTH * 2;

/// How many cells the lane has, as an index.
const CELLS: usize = LANE_CELLS as usize;

/// How far a stamped shape's mask reaches past its radius, for the soft edge.
const STAMP_MARGIN: i32 = 1;

/// How many rows above and below a text's line box are repainted with it, for the soft edges.
const TEXT_MARGIN: f32 = 2.0;

/// The most steps the gate's refill can show: the gate is full, from the foot to the top of its hollow.
const GATE_FILL_LIMIT: u8 = 19;

/// A row of the RGBA frame in the ground's colour.
const GROUND_ROW: [u8; RGBA_ROW] = {
    let mut row = [u8::MAX; RGBA_ROW];
    let mut at = 0;
    while at < RGBA_ROW {
        row[at] = GROUND[0];
        row[at + 1] = GROUND[1];
        row[at + 2] = GROUND[2];
        at += 4;
    }
    row
};

/// The coverage of a round shape, as a mask of whole pixels around the shape's centre, which is on a
/// pixel corner: the same pixels wherever it is stamped. The masks are the mockup's own (see `stamps`).
struct Stamp {
    /// How far the mask's left column is left of the centre, in pixels.
    left: i32,
    /// How far the mask's top row is above the centre, in pixels.
    top: i32,
    /// How many pixels a row of the mask has.
    width: usize,
    /// How much of each pixel is covered, 0 to 255, rows from the top.
    coverage: Vec<u8>,
}

impl Stamp {
    /// The stamp of a table of rows, whose first pixel is `left` and `top` from the centre.
    fn new<const W: usize, const H: usize>(left: i32, top: i32, rows: &[[u8; W]; H]) -> Self {
        Self {
            left,
            top,
            width: W,
            coverage: rows.iter().flatten().copied().collect(),
        }
    }
}

/// One channel of a pixel, a shape's colour over it with `coverage` of it covered, as the mockup's
/// browser blends: the colour by `coverage + 1` of 256, and what is under by `256 - coverage` of 256,
/// each cut to whole numbers on its own.
fn blend_channel(under: u8, color: u8, coverage: u8) -> u8 {
    let (under, color, coverage) = (u32::from(under), u32::from(color), u32::from(coverage));
    let mixed = ((color * (coverage + 1)) >> 8) + ((under * (256 - coverage)) >> 8);
    u8::try_from(mixed).unwrap_or(u8::MAX)
}

/// Everything a painter draws with that does not change: the round shapes and the glyphs.
struct Tools {
    /// The funnel's dots at rest.
    dot: Stamp,
    /// A landed dot turning face-on.
    face: Stamp,
    /// A landed dot edge-on.
    edge: Stamp,
    /// A socket nothing has landed in.
    socket: Stamp,
    /// The round tip of a drip.
    tip: Stamp,
    /// The round end of a teardrop leaving a puddle.
    tear_round: Stamp,
    /// The point of a teardrop, drawn over its round end.
    tear_point: Stamp,
    /// The rendered letters.
    glyphs: GlyphCache,
}

/// A run of whole rows of the frame to draw into.
struct Canvas<'a> {
    /// The rows' RGBA bytes.
    rows: &'a mut [u8],
    /// The frame's row of the first of them.
    top: i32,
    /// How many rows there are.
    height: i32,
}

impl Canvas<'_> {
    /// Whether any of the frame's rows `from` to `to`, `to` not included, are among this canvas's.
    fn meets(&self, from: i32, to: i32) -> bool {
        from < self.top + self.height && to > self.top
    }

    /// Fills a rectangle of whole pixels, clipped to the canvas.
    fn fill(&mut self, area: Area, color: Rgb) {
        let (x0, y0) = (area.x.round() as i32, area.y.round() as i32);
        let (x1, y1) = (
            (area.x + area.w).round() as i32,
            (area.y + area.h).round() as i32,
        );
        let (Ok(from), Ok(to)) = (
            usize::try_from(x0.max(0)),
            usize::try_from(x1.min(WIDTH as i32)),
        ) else {
            return;
        };
        if to <= from {
            return;
        }
        // The first row is written pixel by pixel, and the others are copies of it.
        let mut first: Option<usize> = None;
        for y in y0.max(self.top)..y1.min(self.top + self.height) {
            let Ok(row) = usize::try_from(y - self.top) else {
                continue;
            };
            let at = row * RGBA_ROW + from * 4;
            let len = (to - from) * 4;
            match first {
                None => {
                    let Some(span) = self.rows.get_mut(at..at + len) else {
                        continue;
                    };
                    for pixel in span.as_chunks_mut::<4>().0 {
                        pixel[..3].copy_from_slice(&color);
                        pixel[3] = u8::MAX;
                    }
                    first = Some(at);
                }
                Some(start) => {
                    if at + len <= self.rows.len() {
                        self.rows.copy_within(start..start + len, at);
                    }
                }
            }
        }
    }

    /// Draws a frame `width` thick inside an area, as a stroke of that width along a path inset by half of it.
    fn frame(&mut self, area: Area, width: f32, color: Rgb) {
        let Area { x, y, w, h } = area;
        let inner_h = (h - 2.0 * width).max(0.0);
        self.fill(Area::new(x, y, w, width), color);
        self.fill(Area::new(x, y + h - width, w, width), color);
        self.fill(Area::new(x, y + width, width, inner_h), color);
        self.fill(Area::new(x + w - width, y + width, width, inner_h), color);
    }

    /// Stamps a round shape with its centre on a pixel corner, in a colour, blended as the mockup's
    /// browser does.
    fn stamp(&mut self, stamp: &Stamp, (cx, cy): (i32, i32), color: Rgb) {
        for (dy, line) in stamp.coverage.chunks_exact(stamp.width.max(1)).enumerate() {
            let y = cy + stamp.top + i32::try_from(dy).unwrap_or(i32::MAX);
            let Some(row) = y
                .checked_sub(self.top)
                .filter(|&row| row < self.height)
                .and_then(|row| usize::try_from(row).ok())
            else {
                continue;
            };
            for (dx, &covered) in line.iter().enumerate() {
                let x = cx + stamp.left + i32::try_from(dx).unwrap_or(i32::MAX);
                let Ok(column) = usize::try_from(x) else {
                    continue;
                };
                if covered == 0 || column >= WIDTH {
                    continue;
                }
                let at = row * RGBA_ROW + column * 4;
                let Some(pixel) = self.rows.get_mut(at..at + 3) else {
                    continue;
                };
                for (under, channel) in pixel.iter_mut().zip(color) {
                    *under = blend_channel(*under, channel, covered);
                }
            }
        }
    }

    /// Whether a line of text standing on `baseline` can touch the canvas.
    fn sees_text(&self, baseline: f32, size: f32) -> bool {
        let (from, to) = text_rows(baseline, size);
        self.meets(from, to)
    }

    /// Sets one line of text; it is skipped when its line box is out of the canvas.
    fn text(&mut self, glyphs: &mut GlyphCache, slot: &TextSlot, text: &str) {
        if !text.is_empty() && self.sees_text(slot.baseline, slot.size) {
            glyphs.draw(self.rows, self.top, slot, text);
        }
    }

    /// Sets one line of text glyph by glyph, as the mockup's `tx` does: each glyph is centred in a
    /// slot of the font's advance plus `tracking`, and the slot's centre is a fixed distance from the
    /// run's `x`, whatever the glyph. A `Middle` run is centred on `x` with the tracking after its last
    /// glyph taken off; an `End` run ends there.
    fn tracked(&mut self, glyphs: &mut GlyphCache, slot: &TextSlot, tracking: f32, text: &str) {
        if text.is_empty() || !self.sees_text(slot.baseline, slot.size) {
            return;
        }
        let advance = slot.size * ADVANCE_EM + tracking;
        let glyph_count = text.chars().count() as f32;
        let width = glyph_count * advance - tracking;
        let left = match slot.anchor {
            Anchor::Start => slot.x,
            Anchor::Middle => slot.x - width / 2.0,
            Anchor::End => slot.x - width,
        };
        let mut utf8 = [0; 4];
        for (i, c) in text.chars().enumerate() {
            let centre = left + i as f32 * advance + slot.size * ADVANCE_EM / 2.0;
            let one = TextSlot {
                x: centre,
                anchor: Anchor::Middle,
                ..*slot
            };
            glyphs.draw(self.rows, self.top, &one, c.encode_utf8(&mut utf8));
        }
    }

    /// Sets the count: every glyph of its own slot, a `,` or a `.` in a narrow one, so that the
    /// separator does not open a hole in the number, and the run centred on `x`.
    fn slotted(&mut self, glyphs: &mut GlyphCache, slot: &TextSlot, text: &str) {
        if text.is_empty() || !self.sees_text(slot.baseline, slot.size) {
            return;
        }
        let slot_of = |c: char| {
            if matches!(c, ',' | '.') {
                slot.size * COUNT_SEPARATOR_EM
            } else {
                slot.size * ADVANCE_EM
            }
        };
        let width: f32 = text.chars().map(slot_of).sum();
        let mut left = slot.x - width / 2.0;
        let mut utf8 = [0; 4];
        for c in text.chars() {
            let one = TextSlot {
                x: left + slot_of(c) / 2.0,
                anchor: Anchor::Middle,
                ..*slot
            };
            glyphs.draw(self.rows, self.top, &one, c.encode_utf8(&mut utf8));
            left += slot_of(c);
        }
    }
}

/// The frame's rows a line of text can touch: its line box, with a margin.
///
/// Every glyph the panel sets lies between the font's ascent and descent lines.
fn text_rows(baseline: f32, size: f32) -> (i32, i32) {
    (
        (baseline - size * ASCENT_EM - TEXT_MARGIN).floor() as i32,
        (baseline + size * DESCENT_EM + TEXT_MARGIN).ceil() as i32,
    )
}

/// A text slot at an anchor, in bold unless it says otherwise.
const fn slot(x: f32, baseline: f32, anchor: Anchor, size: f32, color: Rgb) -> TextSlot {
    TextSlot {
        x,
        baseline,
        anchor,
        size,
        weight: Weight::Bold,
        color,
    }
}

/// The words the lane says, if it has nothing else to carry: the stills' words while the Drain is idle.
fn lane_words(stills: &Stills, idle: bool) -> Option<LaneWords> {
    stills.words.filter(|_| idle)
}

/// The scene as the painter reads it: the figures, the lane by cell, the door, the funnel and the drop.
struct Scene<'a> {
    /// The slow figures.
    stills: &'a Stills,
    /// The tile in each lane cell.
    lane: [Option<Tile>; CELLS],
    /// Whether the door across the lane is shut.
    door: bool,
    /// Whether the lane has no name to carry, which is when its words show.
    idle: bool,
    /// The funnel's dots.
    funnel: &'a [FunnelCell; FUNNEL_CELLS],
    /// Whether the drop at the spout is showing.
    drop: bool,
}

impl<'a> Scene<'a> {
    /// The scene of a Drain and the figures that go with it.
    fn of(drain: &'a Drain, stills: &'a Stills) -> Self {
        let mut lane = [None; CELLS];
        for tile in drain.lane() {
            if let Some(place) = lane.get_mut(usize::from(tile.cell)) {
                *place = Some(tile);
            }
        }
        Self {
            stills,
            lane,
            door: drain.door_shut(),
            idle: drain.idle(),
            funnel: drain.funnel(),
            drop: drain.spout_drop(),
        }
    }

    /// Whether blocking is paused as the key shows it.
    fn paused(&self) -> bool {
        matches!(self.stills.blocking, Blocking::Paused { .. })
    }
}

/// What the painter's frame shows: a scene it owns.
struct Shown {
    /// The slow figures.
    stills: Stills,
    /// The tile in each lane cell.
    lane: [Option<Tile>; CELLS],
    /// Whether the door across the lane is shut.
    door: bool,
    /// Whether the lane has no name to carry.
    idle: bool,
    /// The funnel's dots.
    funnel: [FunnelCell; FUNNEL_CELLS],
    /// Whether the drop at the spout is showing.
    drop: bool,
}

impl Shown {
    /// A copy of a scene.
    fn of(scene: &Scene<'_>) -> Self {
        Self {
            stills: scene.stills.clone(),
            lane: scene.lane,
            door: scene.door,
            idle: scene.idle,
            funnel: *scene.funnel,
            drop: scene.drop,
        }
    }

    /// Becomes the scene; the figures are copied only if they differ, so a steady frame allocates nothing.
    fn follow(&mut self, scene: &Scene<'_>) {
        if self.stills != *scene.stills {
            self.stills.clone_from(scene.stills);
        }
        self.lane = scene.lane;
        self.door = scene.door;
        self.idle = scene.idle;
        self.funnel = *scene.funnel;
        self.drop = scene.drop;
    }
}

/// The rows of the frame that must be painted again, one flag for each.
struct Dirty([bool; HEIGHT]);

impl Dirty {
    /// No row.
    fn none() -> Self {
        Self([false; HEIGHT])
    }

    /// Every row.
    fn all() -> Self {
        Self([true; HEIGHT])
    }

    /// Flags the frame's rows `from` to `to`, `to` not included.
    fn mark(&mut self, from: i32, to: i32) {
        let from = usize::try_from(from.max(0)).unwrap_or(0);
        let to = usize::try_from(to.max(0)).unwrap_or(0).min(HEIGHT);
        for row in self.0.iter_mut().take(to).skip(from) {
            *row = true;
        }
    }

    /// Flags the rows of an area.
    fn mark_area(&mut self, area: Area) {
        self.mark(area.y.floor() as i32, (area.y + area.h).ceil() as i32);
    }

    /// Flags the rows of a line of text.
    fn mark_text(&mut self, baseline: f32, size: f32) {
        let (from, to) = text_rows(baseline, size);
        self.mark(from, to);
    }

    /// The runs of flagged rows, as first row and one past the last.
    fn runs(&self) -> impl Iterator<Item = (usize, usize)> + '_ {
        let mut at = 0;
        std::iter::from_fn(move || {
            while at < HEIGHT && !self.0.get(at).copied().unwrap_or(false) {
                at += 1;
            }
            if at >= HEIGHT {
                return None;
            }
            let from = at;
            while at < HEIGHT && self.0.get(at).copied().unwrap_or(false) {
                at += 1;
            }
            Some((from, at))
        })
    }
}

/// The rows a tile can touch: its top, a sagging letter's tail, the longest drip it can have, and the
/// lowest teardrop, which is the one that has fallen free of its pool.
fn tile_rows(tile: &Tile) -> (i32, i32) {
    let base = LANE_Y + LANE_H;
    let drip = f32::from(tile.drip);
    let letter_tail = SAG_LETTER_BASELINE_DY + LETTER_PX * DESCENT_EM - LANE_H;
    let slump_tip = drip + SLUMP_DRIP_EXTRA + DRIP_TIP_R;
    let fallen = DROP_DY + drip + DROP_FALL + TEAR_R;
    let reach = slump_tip.max(fallen).max(letter_tail) + STAMP_MARGIN as f32;
    (
        (LANE_Y - TEXT_MARGIN).floor() as i32,
        (base + reach + TEXT_MARGIN).ceil() as i32,
    )
}

/// The rows of the gate's refill when it is `steps` high.
fn refill_top(steps: u8) -> f32 {
    GATE_FILL_FOOT - f32::from(steps.min(GATE_FILL_LIMIT)) * GATE_FILL_STEP
}

/// Finds the rows of the frame that must be painted again to go from `old` to `now`.
fn dirty_rows(old: &Shown, now: &Scene<'_>) -> Dirty {
    let mut dirty = Dirty::none();
    if old.stills.blocking != now.stills.blocking {
        let was_paused = matches!(old.stills.blocking, Blocking::Paused { .. });
        dirty.mark_area(KEY);
        if was_paused != now.paused() {
            // The gate's look changes from one end of the screen to the other.
            dirty.mark(0, (GATE_BOTTOM.y + GATE_BOTTOM.h).ceil() as i32);
        }
    }
    if old.stills.gate_fill != now.stills.gate_fill {
        let top = refill_top(old.stills.gate_fill.max(now.stills.gate_fill));
        dirty.mark(top.floor() as i32, GATE_FILL_FOOT.ceil() as i32);
    }
    if old.stills.alert != now.stills.alert {
        dirty.mark_area(ALERT_FIELD);
    }
    if old.stills.count != now.stills.count {
        dirty.mark_text(COUNT_BASELINE, COUNT_PX);
    }
    if old.stills.percent != now.stills.percent {
        dirty.mark_text(PERCENT_BASELINE, PERCENT_PX);
    }
    if old.stills.clock != now.stills.clock {
        dirty.mark_text(CLOCK_BASELINE, CLOCK_PX);
    }
    if lane_words(&old.stills, old.idle) != lane_words(now.stills, now.idle) {
        dirty.mark_text(WORDS_BASELINE, WORDS_PX);
    }
    if old.door != now.door {
        dirty.mark_area(DOOR);
    }
    if old.drop != now.drop {
        let reach = SPOUT_DROP_R.ceil() as i32 + STAMP_MARGIN;
        dirty.mark(SPOUT_DROP.1 - reach, SPOUT_DROP.1 + reach);
    }
    for (was, is) in old.lane.iter().zip(&now.lane) {
        if was != is {
            for tile in was.iter().chain(is) {
                let (from, to) = tile_rows(tile);
                dirty.mark(from, to);
            }
        }
    }
    for (i, (was, is)) in old.funnel.iter().zip(now.funnel).enumerate() {
        if was != is
            && let Some(&(_, cy)) = FUNNEL_CENTRES.get(i)
        {
            let reach = FLIP_FACE_R.max(FLIP_EDGE_RY).ceil() as i32 + STAMP_MARGIN;
            dirty.mark(i32::from(cy) - reach, i32::from(cy) + reach);
        }
    }
    dirty
}

/// The percentage as the left column sets it: `44%`, `ALL`, or a lone dash while it is not known.
fn percent_text(percent: Option<Share>) -> String {
    percent.map_or_else(|| DASH.to_string(), Share::text)
}

/// The time of day as the left column sets it: `10:21`, or `--:--` where it is not set or not a time.
fn clock_text(clock: Option<TimeOfDay>) -> String {
    match clock {
        Some(TimeOfDay { hour, minute }) if hour < 24 && minute < 60 => {
            format!("{hour:02}:{minute:02}")
        }
        _ => "--:--".to_string(),
    }
}

/// The left column: the percentage, its label, the clock and the key.
fn draw_left_column(canvas: &mut Canvas<'_>, glyphs: &mut GlyphCache, stills: &Stills) {
    let percent = slot(
        PERCENT_X,
        PERCENT_BASELINE,
        Anchor::Start,
        PERCENT_PX,
        if stills.percent.is_some() { WHITE } else { G3 },
    );
    canvas.tracked(glyphs, &percent, 0.0, &percent_text(stills.percent));
    let label = slot(LABEL_X, LABEL_BASELINE, Anchor::Start, LABEL_PX, G2);
    canvas.tracked(glyphs, &label, LABEL_TRACKING, LABEL);
    let clock = clock_text(stills.clock);
    let clock_ink = if clock.starts_with('-') { G3 } else { G1 };
    let clock_slot = slot(CLOCK_X, CLOCK_BASELINE, Anchor::Start, CLOCK_PX, clock_ink);
    canvas.tracked(glyphs, &clock_slot, 0.0, &clock);
    draw_key(canvas, glyphs, stills.blocking);
}

/// The key: lit and saying `GATE SHUT` while blocking is on; outlined and saying `OPEN` and the time left while paused.
fn draw_key(canvas: &mut Canvas<'_>, glyphs: &mut GlyphCache, blocking: Blocking) {
    if !canvas.meets(KEY.y.floor() as i32, (KEY.y + KEY.h).ceil() as i32) {
        return;
    }
    let (x, label_y, big_y) = (
        KEY.x + KEY.w / 2.0,
        KEY.y + KEY_LABEL_DY,
        KEY.y + KEY_BIG_DY,
    );
    match blocking {
        Blocking::On => {
            canvas.fill(KEY, BLUE);
            let label = slot(x, label_y, Anchor::Middle, KEY_LABEL_PX, BLUE_NIGHT);
            canvas.tracked(glyphs, &label, KEY_LABEL_TRACKING, KEY_LABEL);
            let big = slot(x, big_y, Anchor::Middle, KEY_BIG_PX, WHITE);
            canvas.tracked(glyphs, &big, 0.0, KEY_BIG_ON);
        }
        Blocking::Paused { left_secs } => {
            canvas.frame(KEY, KEY_STROKE, WHITE);
            let label = slot(x, label_y, Anchor::Middle, KEY_LABEL_PX, G1);
            canvas.tracked(glyphs, &label, KEY_LABEL_TRACKING, KEY_LABEL_OPEN);
            let big = slot(x, big_y, Anchor::Middle, KEY_BIG_PX, WHITE);
            canvas.tracked(glyphs, &big, 0.0, &format::countdown(left_secs));
        }
    }
}

/// The funnel's dots: a socket where nothing has landed, a dot in its run's shade, and a landing one white.
fn draw_funnel(canvas: &mut Canvas<'_>, tools: &Tools, funnel: &[FunnelCell; FUNNEL_CELLS]) {
    let reach = FLIP_FACE_R.max(FLIP_EDGE_RY).ceil() as i32 + STAMP_MARGIN;
    for (cell, &(cx, cy)) in funnel.iter().zip(FUNNEL_CENTRES.iter()) {
        let (cx, cy) = (i32::from(cx), i32::from(cy));
        if !canvas.meets(cy - reach, cy + reach) {
            continue;
        }
        let Some(shade) = cell.shade else {
            canvas.stamp(&tools.socket, (cx, cy), BLUE_DEEP);
            continue;
        };
        let rest = match shade {
            Shade::Blue => BLUE,
            Shade::Mid => BLUE_MD,
            Shade::Dark => BLUE_DK,
        };
        match cell.flip {
            Flip::Rest => canvas.stamp(&tools.dot, (cx, cy), rest),
            Flip::Face => canvas.stamp(&tools.face, (cx, cy), WHITE),
            Flip::Edge => canvas.stamp(&tools.edge, (cx, cy), WHITE),
        }
    }
}

/// The rails the lane runs between, and the gate across them; a paused gate is hollow and refills in blue from the floor.
fn draw_rails_and_gate(canvas: &mut Canvas<'_>, paused: bool, door: bool, gate_fill: u8) {
    canvas.fill(RAIL_TOP, G4);
    canvas.fill(RAIL_BOTTOM, G4);
    if paused {
        canvas.frame(GATE_PAUSED, GATE_PAUSED_STROKE, WHITE);
        let top = refill_top(gate_fill);
        if top < GATE_FILL_FOOT {
            canvas.fill(
                Area::new(
                    GATE_PAUSED.x + GATE_PAUSED_STROKE,
                    top,
                    GATE_PAUSED.w - 2.0 * GATE_PAUSED_STROKE,
                    GATE_FILL_FOOT - top,
                ),
                BLUE,
            );
        }
    } else {
        canvas.fill(GATE_TOP, BLUE);
        canvas.fill(GATE_BOTTOM, BLUE);
        if door {
            canvas.fill(DOOR, BLUE);
        }
    }
}

/// A drip: a rect hanging from the foot of the tile's place, with a round tip.
fn draw_drip(canvas: &mut Canvas<'_>, tools: &Tools, (x, base, mid): (f32, f32, i32), length: f32) {
    canvas.fill(Area::new(x + DRIP_DX, base, DRIP_W, length), BLUE);
    canvas.stamp(&tools.tip, (mid, (base + length).round() as i32), BLUE);
}

/// One tile of the lane: whole, or melted as far as it has.
fn draw_tile(canvas: &mut Canvas<'_>, tools: &mut Tools, tile: &Tile) {
    let x = cell_x(tile.cell) + TILE_DX;
    let base = LANE_Y + LANE_H;
    let mid = (x + DROP_DX).round() as i32;
    let drip = f32::from(tile.drip);
    let letter = |baseline, color| slot(x + LETTER_DX, baseline, Anchor::Middle, LETTER_PX, color);
    let tear = |canvas: &mut Canvas<'_>, tools: &Tools, lower: f32| {
        let centre = (mid, (base + DROP_DY + drip + lower).round() as i32);
        canvas.stamp(&tools.tear_round, centre, BLUE);
        canvas.stamp(&tools.tear_point, centre, BLUE);
    };
    let mut utf8 = [0; 4];
    let ch: &str = tile.ch.encode_utf8(&mut utf8);
    match tile.melt {
        Melt::Whole => {
            let body = Area::new(x, LANE_Y, TILE_W, LANE_H);
            let ink = match tile.style {
                TileStyle::Plain => {
                    canvas.fill(body, BLUE_DEEP);
                    G1
                }
                TileStyle::Refused => {
                    canvas.fill(body, BLUE);
                    WHITE
                }
                TileStyle::Listed => {
                    canvas.frame(body, OUTLINE_PX, WHITE);
                    WHITE
                }
            };
            canvas.text(
                &mut tools.glyphs,
                &letter(LANE_Y + LETTER_BASELINE_DY, ink),
                ch,
            );
        }
        Melt::Sag => {
            canvas.fill(Area::new(x, LANE_Y + SAG_DY, TILE_W, LANE_H - SAG_DY), BLUE);
            canvas.text(
                &mut tools.glyphs,
                &letter(LANE_Y + SAG_LETTER_BASELINE_DY, WHITE),
                ch,
            );
        }
        Melt::Puddle => {
            canvas.fill(Area::new(x, base - PUDDLE_H, TILE_W, PUDDLE_H), BLUE);
            draw_drip(canvas, tools, (x, base, mid), drip);
        }
        Melt::Slump => {
            canvas.fill(Area::new(x, base - SLUMP_H, TILE_W, SLUMP_H), BLUE);
            draw_drip(canvas, tools, (x, base, mid), drip + SLUMP_DRIP_EXTRA);
        }
        Melt::Drop => {
            canvas.fill(Area::new(x, base - POOL_H, TILE_W, POOL_H), BLUE);
            tear(canvas, tools, 0.0);
        }
        Melt::Fall => tear(canvas, tools, DROP_FALL),
    }
}

/// The lane's words, one capital to a cell: white while Wi-Fi is not joined, grey otherwise.
fn draw_words(canvas: &mut Canvas<'_>, glyphs: &mut GlyphCache, words: LaneWords) {
    if !canvas.sees_text(WORDS_BASELINE, WORDS_PX) {
        return;
    }
    let ink = if words.is_white() { WHITE } else { G2 };
    let mut utf8 = [0; 4];
    for (i, c) in words.text().chars().enumerate() {
        let x = WORDS_X + i as f32 * WORDS_PITCH;
        let one = slot(x, WORDS_BASELINE, Anchor::Middle, WORDS_PX, ink);
        canvas.text(glyphs, &one, c.encode_utf8(&mut utf8));
    }
}

/// The alert's takeover: the field cleared, the card in its colour, its title, subject and who in ink,
/// and the stub at its foot, hollow, with `TAP TO DISMISS`.
fn draw_alert(canvas: &mut Canvas<'_>, glyphs: &mut GlyphCache, card: &AlertCard) {
    let Area { x, y, w, h } = ALERT;
    if !canvas.meets(
        ALERT_FIELD.y.floor() as i32,
        (ALERT_FIELD.y + ALERT_FIELD.h).ceil() as i32,
    ) {
        return;
    }
    canvas.fill(ALERT_FIELD, GROUND);
    let ground = if card.high { WHITE } else { BLUE };
    canvas.fill(ALERT, ground);
    let stub_top = y + h - ALERT_STUB_H;
    canvas.fill(
        Area::new(
            x + ALERT_STUB_RIM,
            stub_top,
            w - 2.0 * ALERT_STUB_RIM,
            ALERT_STUB_H - ALERT_STUB_RIM,
        ),
        GROUND,
    );
    for (line, dy) in card.title.iter().zip(ALERT_TITLE_DY) {
        let title = slot(
            x + ALERT_TITLE_DX,
            y + dy,
            Anchor::Start,
            ALERT_TITLE_PX,
            ALERT_INK,
        );
        canvas.tracked(glyphs, &title, 0.0, line);
    }
    // The last line stands on a fixed baseline, and the lines above it stand one leading higher each.
    let who_lift = if card.who.is_empty() {
        0.0
    } else {
        ALERT_WHO_LIFT
    };
    let lines = card.subject_lines().count();
    let mut baseline =
        y + ALERT_LAST_DY - who_lift - lines.saturating_sub(1) as f32 * ALERT_SUBJECT_LEADING;
    for line in card.subject_lines() {
        let subject = slot(
            x + ALERT_TEXT_DX,
            baseline,
            Anchor::Start,
            ALERT_SUBJECT_PX,
            ALERT_INK,
        );
        canvas.tracked(glyphs, &subject, 0.0, line);
        baseline += ALERT_SUBJECT_LEADING;
    }
    let who = TextSlot {
        weight: Weight::Regular,
        ..slot(
            x + ALERT_TEXT_DX,
            y + ALERT_LAST_DY,
            Anchor::Start,
            ALERT_WHO_PX,
            ALERT_INK,
        )
    };
    canvas.tracked(glyphs, &who, 0.0, &card.who);
    let stub = slot(
        x + w / 2.0,
        y + ALERT_STUB_TEXT_DY,
        Anchor::Middle,
        ALERT_STUB_PX,
        WHITE,
    );
    canvas.tracked(glyphs, &stub, ALERT_STUB_TRACKING, ALERT_STUB_TEXT);
}

/// Draws every layer of the scene that meets the canvas, in order: the left column, the funnel, the
/// spout's drop, the count, the rails and the gate, the lane's tiles and words, and the alert on top.
fn draw_scene(canvas: &mut Canvas<'_>, tools: &mut Tools, scene: &Scene<'_>) {
    draw_left_column(canvas, &mut tools.glyphs, scene.stills);
    draw_funnel(canvas, tools, scene.funnel);
    if scene.drop {
        canvas.stamp(&tools.dot, SPOUT_DROP, WHITE);
    }
    let (count, ink) = match scene.stills.count {
        Some(count) => (format::count(count), WHITE),
        None => (DASH.to_string(), G3),
    };
    let count_slot = slot(COUNT_X, COUNT_BASELINE, Anchor::Middle, COUNT_PX, ink);
    canvas.slotted(&mut tools.glyphs, &count_slot, &count);
    draw_rails_and_gate(canvas, scene.paused(), scene.door, scene.stills.gate_fill);
    for tile in scene.lane.iter().flatten() {
        draw_tile(canvas, tools, tile);
    }
    if let Some(words) = lane_words(scene.stills, scene.idle) {
        draw_words(canvas, &mut tools.glyphs, words);
    }
    if let Some(card) = &scene.stills.alert {
        draw_alert(canvas, &mut tools.glyphs, card);
    }
}

/// Paints the Drain on a frame it keeps, and says what changed by what it hands back.
///
/// Each call to `paint` gives the whole frame as the screen takes it. Only the rows that can differ
/// from the last call are painted and converted again.
pub struct Painter {
    /// The frame as RGBA, rows from the top.
    rgba: Vec<u8>,
    /// The frame as RGB565, little-endian, rows from the top.
    rgb565: Vec<u8>,
    /// The scene the frame shows; `None` before the first `paint`.
    shown: Option<Shown>,
    /// Whether the last `paint` changed a pixel of the RGB565 frame.
    changed: bool,
    /// The rows of the RGB565 frame as they were before they were painted again, kept for the comparison.
    before: Vec<u8>,
    /// The shapes and glyphs.
    tools: Tools,
}

impl Default for Painter {
    fn default() -> Self {
        Self::new()
    }
}

impl Painter {
    /// A painter with a black frame that has painted nothing yet.
    pub fn new() -> Self {
        Self {
            rgba: [GROUND[0], GROUND[1], GROUND[2], u8::MAX].repeat(WIDTH * HEIGHT),
            rgb565: vec![0; WIDTH * HEIGHT * 2],
            shown: None,
            changed: false,
            before: Vec::new(),
            tools: Tools {
                dot: Stamp::new(-6, -6, &stamps::DOT),
                face: Stamp::new(-6, -6, &stamps::FACE),
                edge: Stamp::new(-2, -6, &stamps::EDGE),
                socket: Stamp::new(-4, -4, &stamps::SOCKET),
                tip: Stamp::new(-4, -4, &stamps::TIP),
                tear_round: Stamp::new(-4, -4, &stamps::TEAR_ROUND),
                tear_point: Stamp::new(-4, -11, &stamps::TEAR_POINT),
                glyphs: GlyphCache::new(),
            },
        }
    }

    /// Paints the scene and the figures, and returns the whole frame: 307,200 bytes of RGB565,
    /// little-endian, rows from the top.
    ///
    /// The first call paints every row. Each later one paints the rows that differ from what the last
    /// call painted, and nothing at all if the scene is the same.
    pub fn paint(&mut self, drain: &Drain, stills: &Stills) -> &[u8] {
        let scene = Scene::of(drain, stills);
        let dirty = match &self.shown {
            Some(shown) => dirty_rows(shown, &scene),
            None => Dirty::all(),
        };
        // The first frame is new whatever it holds: nothing is known of what the screen shows.
        self.changed = self.shown.is_none();
        for (from, to) in dirty.runs() {
            let (Some(rgba), Some(rgb565)) = (
                self.rgba.get_mut(from * RGBA_ROW..to * RGBA_ROW),
                self.rgb565.get_mut(from * RGB565_ROW..to * RGB565_ROW),
            ) else {
                continue;
            };
            for row in rgba.as_chunks_mut::<RGBA_ROW>().0 {
                row.copy_from_slice(&GROUND_ROW);
            }
            let mut canvas = Canvas {
                rows: rgba,
                top: i32::try_from(from).unwrap_or(0),
                height: i32::try_from(to - from).unwrap_or(0),
            };
            draw_scene(&mut canvas, &mut self.tools, &scene);
            if !self.changed {
                self.before.clear();
                self.before.extend_from_slice(rgb565);
            }
            convert_into(canvas.rows, rgb565);
            if !self.changed && self.before.as_slice() != &*rgb565 {
                self.changed = true;
            }
        }
        match &mut self.shown {
            Some(shown) => shown.follow(&scene),
            None => self.shown = Some(Shown::of(&scene)),
        }
        &self.rgb565
    }

    /// Paints as `paint` does, and gives the frame only if it differs from the one before: `None`
    /// when no pixel changed, so that a caller that writes the screen has nothing to write.
    pub fn paint_changed(&mut self, drain: &Drain, stills: &Stills) -> Option<&[u8]> {
        self.paint(drain, stills);
        // `paint` has set `changed` by the time it returns.
        self.changed.then_some(self.rgb565.as_slice())
    }

    /// Whether the last `paint` changed any pixel of the frame it gave. The first `paint` always did.
    ///
    /// A scene can differ from the last one and look the same: a step of the model that moves
    /// nothing on the screen. The caller that writes the screen can skip such a frame.
    pub fn changed(&self) -> bool {
        self.changed
    }

    /// The frame as RGBA, 614,400 bytes, rows from the top, every alpha 255: the same pixels as the
    /// last `paint` gave, for tests and the preview.
    pub fn rgba(&self) -> &[u8] {
        &self.rgba
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drain::look::{BLUE, G2, GROUND, WHITE};
    use crate::drain::{Fixture, NameKind, drain_fixture};
    use crate::format::alert_card;
    use crate::rgb565::rgba_to_rgb565;
    use crate::state::LaneWords;

    /// The rows that differ between two RGBA frames, as the first and one past the last.
    fn rows_differing(a: &[u8], b: &[u8]) -> Option<(usize, usize)> {
        let rows =
            |frame: &[u8]| -> Vec<Vec<u8>> { frame.chunks(RGBA_ROW).map(<[u8]>::to_vec).collect() };
        let (a, b) = (rows(a), rows(b));
        let first = a.iter().zip(&b).position(|(x, y)| x != y)?;
        let last = a.iter().zip(&b).rposition(|(x, y)| x != y)?;
        Some((first, last + 1))
    }

    /// A painter that has painted a fixture, and the fixture.
    fn painted(which: Fixture) -> (Painter, Drain, Stills) {
        let (drain, stills) = drain_fixture(which);
        let mut painter = Painter::new();
        painter.paint(&drain, &stills);
        (painter, drain, stills)
    }

    #[test]
    fn a_painter_can_move_to_the_panels_thread() {
        fn send<T: Send>() {}
        send::<Painter>();
    }

    #[test]
    fn the_frames_have_the_screens_size_and_are_opaque() {
        let (painter, _, _) = painted(Fixture::Normal);
        assert_eq!(painter.rgba().len(), 614_400);
        assert_eq!(painter.rgb565.len(), 307_200);
        assert!(
            painter
                .rgba()
                .as_chunks::<4>()
                .0
                .iter()
                .all(|p| p[3] == 255)
        );
    }

    #[test]
    fn the_rgb565_frame_is_the_rgba_frame_converted() {
        for which in Fixture::ALL {
            let (painter, _, _) = painted(which);
            assert!(rgba_to_rgb565(painter.rgba()) == painter.rgb565);
        }
    }

    #[test]
    fn a_scene_that_has_not_changed_repaints_nothing() {
        let (mut painter, drain, stills) = painted(Fixture::Alert);
        let shown = painter.shown.as_ref().expect("it has painted");
        assert_eq!(
            dirty_rows(shown, &Scene::of(&drain, &stills))
                .runs()
                .count(),
            0
        );
        let before = painter.rgba().to_vec();
        painter.paint(&drain, &stills);
        assert!(painter.rgba() == before);
    }

    #[test]
    fn changed_says_whether_the_last_paint_changed_a_pixel() {
        let (mut painter, mut drain, mut stills) = painted(Fixture::Normal);
        // The first paint is a change, whatever it holds.
        assert!(painter.changed());
        painter.paint(&drain, &stills);
        assert!(!painter.changed());
        stills.percent = Some(Share::Percent(45));
        painter.paint(&drain, &stills);
        assert!(painter.changed());
        // The count's step is a frame of the model that moves nothing on the lane.
        drain.set_blocked_today(Some(4_780));
        let mut quiet = 0;
        for _ in 0..80 {
            drain.tick(false);
            let step = drain.refusal_step();
            painter.paint(&drain, &stills);
            // The count's step of a 15-letter name: `G + 6`, with `G` of 10.
            if step == Some(16) {
                assert!(!painter.changed());
                quiet += 1;
            }
        }
        assert_eq!(quiet, 1);
    }

    #[test]
    fn the_first_paint_covers_every_row() {
        assert_eq!(Dirty::all().runs().collect::<Vec<_>>(), [(0, HEIGHT)]);
        assert_eq!(Dirty::none().runs().count(), 0);
        let (painter, _, _) = painted(Fixture::Normal);
        // Every band of the frame has something in it but the black between the figures.
        assert!(
            painter
                .rgba()
                .as_chunks::<4>()
                .0
                .iter()
                .any(|p| p[..3] == BLUE)
        );
    }

    #[test]
    fn a_still_changes_only_the_rows_of_its_own_region() {
        let (mut painter, drain, stills) = painted(Fixture::Normal);
        let cases: [(&str, Stills, (usize, usize)); 4] = [
            (
                "the percentage",
                Stills {
                    percent: Some(Share::Percent(45)),
                    ..stills.clone()
                },
                (65, 130),
            ),
            (
                "the clock",
                Stills {
                    clock: Some(TimeOfDay {
                        hour: 10,
                        minute: 22,
                    }),
                    ..stills.clone()
                },
                (160, 204),
            ),
            (
                "the count",
                Stills {
                    count: Some(4781),
                    ..stills.clone()
                },
                (236, HEIGHT),
            ),
            (
                "the countdown",
                Stills {
                    blocking: Blocking::Paused { left_secs: 299 },
                    ..stills.clone()
                },
                (0, 304),
            ),
        ];
        for (what, wanted, (top, bottom)) in cases {
            let before = painter.rgba().to_vec();
            painter.paint(&drain, &wanted);
            let (first, last) = rows_differing(&before, painter.rgba())
                .unwrap_or_else(|| panic!("{what} changed nothing"));
            assert!(
                first >= top && last <= bottom,
                "{what} changed rows {first} to {last}, outside {top} to {bottom}"
            );
            // Back to where it was.
            painter.paint(&drain, &stills);
            assert!(painter.rgba() == before, "{what} did not go back");
        }
    }

    /// The rows of the frame in which two RGBA frames differ, or `None`.
    fn changed_between(
        painter: &mut Painter,
        drain: &Drain,
        stills: &Stills,
    ) -> Option<(usize, usize)> {
        let before = painter.rgba().to_vec();
        painter.paint(drain, stills);
        rows_differing(&before, painter.rgba())
    }

    /// The colour of one pixel of the painter's frame.
    fn pixel(painter: &Painter, x: usize, y: usize) -> Rgb {
        let at = (y * WIDTH + x) * 4;
        let rgba = painter.rgba();
        [rgba[at], rgba[at + 1], rgba[at + 2]]
    }

    #[test]
    fn the_gate_refills_in_its_own_rows_and_the_words_in_theirs() {
        let (mut painter, drain, stills) = painted(Fixture::Paused);
        // One step more of the refill is 12 px of the hollow, from the 12 that are there.
        let more = Stills {
            gate_fill: 2,
            ..stills.clone()
        };
        let (first, last) = changed_between(&mut painter, &drain, &more).expect("the refill rose");
        assert!(
            (276..288).contains(&first) && last == 288,
            "{first} to {last}"
        );
        assert_eq!(pixel(&painter, 108, 280), BLUE);
        // And it falls back, where a pause starts over without the key changing.
        let (first, last) = changed_between(&mut painter, &drain, &stills).expect("it fell");
        assert!(
            (276..288).contains(&first) && last == 288,
            "{first} to {last}"
        );
        let (mut painter, drain, stills) = painted(Fixture::Boot);
        let none = Stills {
            words: None,
            ..stills.clone()
        };
        let (first, last) = changed_between(&mut painter, &drain, &none).expect("the words went");
        assert!(first >= 16 && last <= 58, "{first} to {last}");
        let (first, last) = changed_between(&mut painter, &drain, &stills).expect("and came back");
        assert!(first >= 16 && last <= 58, "{first} to {last}");
    }

    #[test]
    fn the_words_show_only_while_the_lane_is_idle() {
        let (mut painter, mut drain, stills) = painted(Fixture::Quiet);
        let words = painter.rgba().to_vec();
        assert!(
            words.iter().any(|&byte| byte == G2[0]),
            "grey words are drawn"
        );
        // A name is queued: the words go in the same frame, whatever the stills say.
        drain.offer("example.org", NameKind::Plain);
        painter.paint(&drain, &stills);
        assert!(painter.rgba() != words);
        let (fresh, _, _) = painted(Fixture::Quiet);
        let rows = |frame: &[u8]| frame[18 * RGBA_ROW..56 * RGBA_ROW].to_vec();
        assert!(rows(painter.rgba()) != rows(fresh.rgba()));
        // And the words are drawn again once the name is gone.
        for _ in 0..80 {
            drain.tick(false);
        }
        assert!(drain.idle());
        painter.paint(&drain, &stills);
        assert!(painter.rgba() == words);
    }

    #[test]
    fn the_spout_drop_is_one_white_dot_on_the_axis_in_its_own_rows() {
        let (mut painter, mut drain, stills) = painted(Fixture::Normal);
        let mut shown = 0;
        for _ in 0..30 {
            drain.tick(false);
            let rows = changed_between(&mut painter, &drain, &stills);
            if drain.spout_drop() {
                shown += 1;
                assert_eq!(pixel(&painter, 300, 234), WHITE);
                let (first, last) = rows.expect("the drop appeared");
                assert!(first >= 228 && last <= 240, "{first} to {last}");
            } else {
                assert!(pixel(&painter, 300, 234) != WHITE);
            }
        }
        assert_eq!(shown, 1, "the drop shows for one frame");
    }

    #[test]
    fn the_alert_clears_its_field_and_stands_on_the_floor() {
        for (which, ground) in [(Fixture::Alert, WHITE), (Fixture::AlertLow, BLUE)] {
            let (painter, _, _) = painted(which);
            // The field round the card is black, and the funnel's dots do not show in it.
            for (x, y) in [(120, 80), (124, 200), (479, 319), (300, 310), (476, 90)] {
                assert_eq!(pixel(&painter, x, y), GROUND, "{x}, {y}");
            }
            // The card: its corners, and the rim round the black stub.
            for (x, y) in [
                (128, 80),
                (471, 80),
                (128, 303),
                (471, 303),
                (130, 280),
                (300, 302),
            ] {
                assert_eq!(pixel(&painter, x, y), ground, "{x}, {y}");
            }
            // The stub is hollow, and the slab over it is solid.
            assert_eq!(pixel(&painter, 140, 270), GROUND);
            assert_eq!(pixel(&painter, 300, 259), ground);
            assert_eq!(pixel(&painter, 300, 260), GROUND);
        }
    }

    #[test]
    fn a_refusal_of_any_length_writes_at_most_eighty_rows_a_step() {
        for letters in 1..=15_usize {
            let name = format!("{}.example.org", "x".repeat(letters.saturating_sub(1)));
            let mut drain = Drain::new(1);
            drain.set_blocked_today(Some(10));
            drain.offer(&name, NameKind::Refused);
            let stills = Stills {
                count: Some(10),
                ..Stills::default()
            };
            let mut painter = Painter::new();
            painter.paint(&drain, &stills);
            for step in 0..60 {
                drain.tick(false);
                drain.set_blocked_today(Some(10 + u32::from(step > 5)));
                let moved = Stills {
                    count: drain.count(),
                    ..stills.clone()
                };
                if let Some((first, last)) = changed_between(&mut painter, &drain, &moved) {
                    assert!(
                        last - first <= 80,
                        "{letters} letters, step {step}: rows {first} to {last}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_tick_of_the_lane_repaints_only_the_lanes_rows() {
        let (mut painter, mut drain, stills) = painted(Fixture::Paused);
        drain.tick(true);
        let before = painter.rgba().to_vec();
        painter.paint(&drain, &stills);
        let (first, last) = rows_differing(&before, painter.rgba()).expect("the names moved");
        assert!(first >= 14 && last <= 90, "{first} to {last}");
    }

    #[test]
    fn a_landing_repaints_only_funnel_rows() {
        let (mut painter, mut drain, stills) = painted(Fixture::Normal);
        // Run the refusal on to its landing, painting each step.
        let mut landed = None;
        for _ in 0..20 {
            drain.tick(false);
            let before = painter.rgba().to_vec();
            painter.paint(&drain, &stills);
            // The dots land at `G + 1`: step 11 for a 15-letter name.
            if drain.refusal_step() == Some(11) {
                landed = rows_differing(&before, painter.rgba());
            }
        }
        let (first, last) = landed.expect("the funnel changed when the dots landed");
        assert!(first >= 80 && last <= 226, "{first} to {last}");
    }

    #[test]
    fn extreme_scenes_paint_a_whole_opaque_frame() {
        let mut drain = Drain::new(u32::MAX);
        drain.set_paused(true);
        for name in [
            "",
            ".",
            "\u{fc}ber.example.org",
            &"x".repeat(253),
            "a\0b\u{301}\u{10ffff}",
        ] {
            drain.offer(name, NameKind::Refused);
            drain.offer(name, NameKind::Listed);
        }
        drain.set_blocked_today(Some(u32::MAX));
        let longest = "a".repeat(253);
        let stills = [
            Stills::default(),
            Stills {
                percent: Some(Share::All),
                clock: Some(TimeOfDay {
                    hour: u8::MAX,
                    minute: u8::MAX,
                }),
                blocking: Blocking::Paused {
                    left_secs: u16::MAX,
                },
                gate_fill: u8::MAX,
                count: Some(u32::MAX),
                alert: Some(alert_card(&longest, true, &longest, None)),
                words: Some(LaneWords::Quiet { minutes: u32::MAX }),
            },
            Stills {
                clock: Some(TimeOfDay {
                    hour: 24,
                    minute: 0,
                }),
                count: None,
                alert: Some(alert_card("", false, "", None)),
                ..Stills::default()
            },
        ];
        let mut painter = Painter::new();
        for _ in 0..40 {
            drain.tick(true);
            for stills in &stills {
                assert_eq!(painter.paint(&drain, stills).len(), 307_200);
                assert!(
                    painter
                        .rgba()
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .all(|p| p[3] == 255)
                );
            }
        }
    }

    #[test]
    fn the_clock_and_percent_texts_are_dashes_where_unknown_or_not_a_time() {
        assert_eq!(clock_text(None), "--:--");
        assert_eq!(
            clock_text(Some(TimeOfDay {
                hour: 24,
                minute: 0
            })),
            "--:--"
        );
        assert_eq!(
            clock_text(Some(TimeOfDay {
                hour: 9,
                minute: 60
            })),
            "--:--"
        );
        assert_eq!(clock_text(Some(TimeOfDay { hour: 9, minute: 5 })), "09:05");
        assert_eq!(percent_text(None), "\u{2014}");
        assert_eq!(percent_text(Some(Share::All)), "ALL");
        assert_eq!(percent_text(Some(Share::UnderOne)), "<1%");
        assert_eq!(percent_text(Some(Share::Percent(44))), "44%");
    }

    #[test]
    fn a_stamp_is_a_round_mask_with_a_soft_edge() {
        let dot = Stamp::new(-6, -6, &stamps::DOT);
        assert_eq!((dot.width, dot.coverage.len()), (12, 144));
        let at = |x: usize, y: usize| dot.coverage[y * dot.width + x];
        assert_eq!((at(5, 5), at(6, 6)), (255, 255));
        assert_eq!((at(0, 0), at(11, 11)), (0, 0));
        assert!(dot.coverage.iter().any(|&v| v > 0 && v < 255));
    }

    #[test]
    fn a_stamp_blends_as_the_mockups_browser_does() {
        // Over the ground: the colour by `coverage + 1` of 256.
        assert_eq!(blend_channel(0, 0x72, 239), 0x6a);
        assert_eq!(blend_channel(0, 0xff, 73), 73);
        assert_eq!(blend_channel(0, 0x72, 255), 0x72);
        // Over its own colour a soft edge can lose a step, as the mockup's tips do.
        assert_eq!(blend_channel(0x72, 0x72, 200), 0x71);
        // Over a rail.
        assert_eq!(blend_channel(0x2e, 0xff, 144), 164);
    }

    #[test]
    fn a_stamp_is_clipped_to_the_canvas_and_the_frame() {
        let mut rows = vec![0_u8; RGBA_ROW * 4];
        let mut canvas = Canvas {
            rows: &mut rows,
            top: 10,
            height: 4,
        };
        let dot = Stamp::new(-6, -6, &stamps::DOT);
        // Centres above, below, left of and right of the canvas, and one in it.
        for centre in [(5, 0), (5, 40), (-20, 12), (WIDTH as i32 + 20, 12), (2, 12)] {
            canvas.stamp(&dot, centre, WHITE);
        }
        let lit = |x: usize, y: usize| rows[y * RGBA_ROW + x * 4];
        // Rows 10 to 13 of the frame are rows 0 to 3 here; the dot at (2, 12) lights its right side only.
        assert_eq!(lit(0, 2), 255);
        assert_eq!(lit(5, 2), 255);
        assert_eq!(lit(8, 2), 0);
    }
}
