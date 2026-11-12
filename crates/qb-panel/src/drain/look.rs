//! The Drain's look as numbers: every coordinate, size and colour of the
//! scene, taken from the round 6 mockup (`d6.js` and `common.js`) and the "Numbers for building it"
//! table of its README.
//!
//! Coordinates are screen pixels on the 480 by 320 frame, y pointing down.
//! A text's `x` and baseline are as the mockup's `text()` takes them. Nothing
//! here is drawn from; the painter reads these and the model's accessors.

use crate::geometry::Rgb;

/// A rectangle in screen pixels.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Area {
    /// The left edge.
    pub x: f32,
    /// The top edge.
    pub y: f32,
    /// The width.
    pub w: f32,
    /// The height.
    pub h: f32,
}

impl Area {
    /// The area at `x`, `y` that is `w` wide and `h` high.
    pub const fn new(x: f32, y: f32, w: f32, h: f32) -> Self {
        Self { x, y, w, h }
    }
}

// Colours: the round 5 palette, and nothing else.

/// The ground of the screen.
pub const GROUND: Rgb = [0x00, 0x00, 0x00];
/// The accent: refused tiles, the funnel's first shade, the key, the gate.
pub const BLUE: Rgb = [0x4a, 0x72, 0xff];
/// The light blue.
pub const BLUE_LT: Rgb = [0xa4, 0xb6, 0xff];
/// The mid blue.
pub const BLUE_MD: Rgb = [0x31, 0x52, 0xc4];
/// The funnel's second shade.
pub const BLUE_DK: Rgb = [0x1f, 0x33, 0x83];
/// The fill of a plain tile.
pub const BLUE_DEEP: Rgb = [0x12, 0x1b, 0x44];
/// The ink on the lit key.
pub const BLUE_NIGHT: Rgb = [0x0c, 0x12, 0x30];
/// Values, outlines and the paused key.
pub const WHITE: Rgb = [0xff, 0xff, 0xff];
/// The brightest grey: a plain tile's letter, the clock and the paused key's label.
pub const G1: Rgb = [0xd0, 0xd0, 0xd0];
/// The `REFUSED` label.
pub const G2: Rgb = [0x8e, 0x8e, 0x8e];
/// The third grey.
pub const G3: Rgb = [0x5e, 0x5e, 0x5e];
/// The rails the lane runs between.
pub const G4: Rgb = [0x2e, 0x2e, 0x2e];
/// The darkest grey.
pub const G5: Rgb = [0x18, 0x18, 0x18];

// The lane. A model cell is a letter's place; cell 0 is at the right edge, where names enter, and cell 19 at the left.

/// How many cells the lane has, across the whole screen.
pub const LANE_CELLS: u8 = 20;
/// The cell that holds the gate. A refused name stops in the cell before it.
pub const GATE_CELL: u8 = 15;
/// The width of a cell.
pub const CELL_W: f32 = 24.0;
/// The top of the tiles.
pub const LANE_Y: f32 = 16.0;
/// The height of a tile.
pub const LANE_H: f32 = 40.0;

/// The left edge of a lane cell, mirrored: cell 0 is at the right, so names read from the left edge outwards.
///
/// A cell past the lane is left of the screen's edge, at 0.
pub const fn cell_x(cell: u8) -> f32 {
    LANE_CELLS.saturating_sub(1).saturating_sub(cell) as f32 * CELL_W
}

/// How far a tile's left edge is inside its cell.
pub const TILE_DX: f32 = 1.0;
/// The width of a tile.
pub const TILE_W: f32 = CELL_W - 2.0;
/// The size of a letter on a tile, in bold.
pub const LETTER_PX: f32 = 24.0;
/// A letter's `x` from the tile's left edge; it is centred there.
pub const LETTER_DX: f32 = TILE_W / 2.0;
/// A letter's baseline from `LANE_Y`: 1 px higher than in round 5, so lower-case letters sit centred on the tile.
pub const LETTER_BASELINE_DY: f32 = 28.0;
/// The width of a listed tile's white outline, which is drawn inset by half of it.
pub const OUTLINE_PX: f32 = 2.0;

// The words the lane says while it has no names: bare capitals, one to a cell, with no tiles.

/// The first letter's centre: the middle of the first cell right of the gate.
pub const WORDS_X: f32 = 132.0;
/// The distance between two letters' centres: one cell.
pub const WORDS_PITCH: f32 = CELL_W;
/// The words' baseline.
pub const WORDS_BASELINE: f32 = 45.0;
/// The size of the words, in bold.
pub const WORDS_PX: f32 = 24.0;

// The melt of a stopped name, tile by tile. Rects are from the tile's left edge `x` (cell_x + TILE_DX);
// a tile is `TILE_W` wide at every stage, so the puddles keep the tiles' 2 px gaps.

/// A sagging tile: its top, from `LANE_Y`.
pub const SAG_DY: f32 = 10.0;
/// A sagging tile's letter baseline, from `LANE_Y`; the letter is white and centred at `LETTER_DX`.
pub const SAG_LETTER_BASELINE_DY: f32 = 34.0;
/// A puddle's height, flush with the bottom of the tile's place.
pub const PUDDLE_H: f32 = 16.0;
/// A slumped puddle's height.
pub const SLUMP_H: f32 = 6.0;
/// A pool's height while a drop falls from it.
pub const POOL_H: f32 = 4.0;
/// A drip's left edge from the tile's: the drip is centred on the tile.
pub const DRIP_DX: f32 = 8.0;
/// A drip's width.
pub const DRIP_W: f32 = 6.0;
/// The radius of a drip's round tip, a circle centred on the end of the drip's rect.
pub const DRIP_TIP_R: f32 = 3.0;
/// A slumped puddle's drips are this much longer than a puddle's.
pub const SLUMP_DRIP_EXTRA: f32 = 6.0;
/// A drip's shortest length, in pixels.
pub const DRIP_BASE: u8 = 4;
/// How much longer each next drip length is.
pub const DRIP_STEP: u8 = 4;
/// How many drip lengths there are: they come from the letter and its place in the name.
pub const DRIP_KINDS: u32 = 3;
/// A drop's and a drip's centre line from the tile's left edge: the middle of the tile.
pub const DROP_DX: f32 = 11.0;
/// A teardrop's centre, from the bottom of the tile's place (`LANE_Y + LANE_H`), before the drip's length is added.
pub const DROP_DY: f32 = 10.0;
/// How much lower the falling teardrop, with no pool, is than the one that has just left the pool.
pub const DROP_FALL: f32 = 8.0;
/// The radius of a teardrop's round end.
pub const TEAR_R: f32 = 4.0;
/// The tip of a teardrop's triangle, above its centre.
pub const TEAR_TIP: f32 = 11.0;
/// The base of a teardrop's triangle, above its centre.
pub const TEAR_BASE: f32 = 2.0;
/// Half the width of a teardrop's triangle at its base.
pub const TEAR_HALF: f32 = 3.5;

// Rails and the gate.

/// The rail above the lane.
pub const RAIL_TOP: Area = Area::new(0.0, 4.0, 480.0, 4.0);
/// The rail below the lane.
pub const RAIL_BOTTOM: Area = Area::new(0.0, 64.0, 480.0, 4.0);
/// The floor: where the gate, the key and the count end.
pub const FLOOR: f32 = 304.0;
/// The gate above the lane, when blocking is on.
pub const GATE_TOP: Area = Area::new(96.0, 0.0, CELL_W, 4.0);
/// The gate below the lane, when blocking is on; it runs to the floor.
pub const GATE_BOTTOM: Area = Area::new(96.0, 68.0, CELL_W, FLOOR - 68.0);
/// The door across the lane, drawn while it is shut and blocking is on.
pub const DOOR: Area = Area::new(96.0, 4.0, CELL_W, 64.0);
/// The gate while blocking is paused: a white slab below the lane, hollowed out to a `GATE_PAUSED_STROKE` outline.
pub const GATE_PAUSED: Area = Area::new(96.0, 68.0, CELL_W, FLOOR - 68.0);
/// The width of the paused gate's outline.
pub const GATE_PAUSED_STROKE: f32 = 4.0;
/// The paused gate refills from the floor in blue, in steps of this height, as the pause runs out.
pub const GATE_FILL_STEP: f32 = 12.0;
/// The foot of the refill: the floor less the outline.
pub const GATE_FILL_FOOT: f32 = FLOOR - GATE_PAUSED_STROKE;

// The funnel of dots: a bowl, a neck and a spout, every row of an odd number of dots so that each has one on the axis.

/// The funnel's centre line, which is the axis of the 15 cells right of the gate.
pub const FUNNEL_CX: u16 = 300;
/// The funnel's top.
pub const FUNNEL_TOP: u16 = 80;
/// The distance between two dots' centres, across and down.
pub const FUNNEL_PITCH: u16 = 12;
/// The dots in each row, top to bottom.
pub const FUNNEL_ROWS: [u16; 12] = [29, 25, 21, 17, 13, 11, 9, 7, 5, 3, 3, 3];
/// How many dots the funnel has in all.
pub const FUNNEL_CELLS: usize = 146;
/// The radius of a lit dot at rest.
pub const DOT_R: f32 = 5.0;
/// The radius of an empty socket, which is dim.
pub const SOCKET_R: f32 = 2.5;
/// The radius of a landed dot that is turning face-on: white.
pub const FLIP_FACE_R: f32 = 6.0;
/// The half width of a landed dot that is edge-on: a white ellipse.
pub const FLIP_EDGE_RX: f32 = 2.0;
/// The half height of a landed dot that is edge-on.
pub const FLIP_EDGE_RY: f32 = 6.0;
/// The drop that leaves the spout before the count ticks: a white dot, for one frame, on the axis.
pub const SPOUT_DROP: (i32, i32) = (FUNNEL_CX as i32, 234);
/// The radius of the spout's drop.
pub const SPOUT_DROP_R: f32 = 5.0;

/// The dots' centres in the funnel's landing order: from the spout's tip upward, and to and fro, so
/// that the tip row runs left to right, the row above it right to left, and so on. A name's run of
/// dots then stays in one piece where it turns up a row, and an empty funnel fills as a real one does.
pub const FUNNEL_CENTRES: [(u16, u16); FUNNEL_CELLS] = funnel_centres();

/// Works out `FUNNEL_CENTRES`. Refuses to compile if `FUNNEL_CELLS` is not the number of dots it makes.
const fn funnel_centres() -> [(u16, u16); FUNNEL_CELLS] {
    let mut out = [(0, 0); FUNNEL_CELLS];
    let mut at = 0;
    let mut row = FUNNEL_ROWS.len();
    let mut back = false;
    while row > 0 {
        row -= 1;
        let width = FUNNEL_ROWS[row] as i32;
        let y = FUNNEL_TOP as i32 + row as i32 * FUNNEL_PITCH as i32 + FUNNEL_PITCH as i32 / 2;
        let mut col = 0;
        while col < width {
            // Every row is odd, so its middle dot is on the axis; a row that runs back starts at its right end.
            let from_middle = col - (width - 1) / 2;
            let side = if back { -from_middle } else { from_middle };
            out[at] = (
                (FUNNEL_CX as i32 + side * FUNNEL_PITCH as i32) as u16,
                y as u16,
            );
            at += 1;
            col += 1;
        }
        back = !back;
    }
    assert!(at == FUNNEL_CELLS, "FUNNEL_CELLS is the number of dots");
    out
}

// Text is set glyph by glyph, as the mockup's `tx` does: JetBrains Mono's advance is 0.6 em, each glyph is
// centred in its slot of that advance plus the tracking, and a run's `x` is the left edge of its first slot.

/// JetBrains Mono's advance, as a share of the size.
pub const ADVANCE_EM: f32 = 0.6;

// The count.

/// The count's centre.
pub const COUNT_X: f32 = FUNNEL_CX as f32;
/// The count's baseline: the floor.
pub const COUNT_BASELINE: f32 = FLOOR;
/// The size of the count, in bold white. Every count has this size, a six-digit one included.
pub const COUNT_PX: f32 = 64.0;
/// The width of the slot of a `,` or a `.` in the count, as a share of the size: a monospace comma would open a hole.
pub const COUNT_SEPARATOR_EM: f32 = 0.3125;

// The left column: one 80 px measure, from x 8 to x 88, the key's edges.

/// The percentage's first slot's left edge, left of 8 by the glyphs' side bearing.
pub const PERCENT_X: f32 = 5.2;
/// The percentage's baseline.
pub const PERCENT_BASELINE: f32 = 114.0;
/// The size of the percentage, in bold white, or a dim dash while it is not known.
pub const PERCENT_PX: f32 = 46.0;
/// The `REFUSED` label's left edge.
pub const LABEL_X: f32 = 6.4;
/// The `REFUSED` label's baseline.
pub const LABEL_BASELINE: f32 = 138.0;
/// The size of the `REFUSED` label, in bold grey 2.
pub const LABEL_PX: f32 = 16.0;
/// The extra space after each letter of the label.
pub const LABEL_TRACKING: f32 = 2.5;
/// The label's text.
pub const LABEL: &str = "REFUSED";
/// The clock's left edge.
pub const CLOCK_X: f32 = 6.3;
/// The clock's baseline.
pub const CLOCK_BASELINE: f32 = 192.0;
/// The size of the clock, in bold grey 1, or `--:--` in grey 3 while it is not set.
pub const CLOCK_PX: f32 = 27.6;

// The key.

/// The key, a square: 80 by 80, from x 8 to 88 and ending on the floor.
pub const KEY: Area = Area::new(8.0, 224.0, 80.0, 80.0);
/// The key's top label, drawn centred, from the key's top to its baseline.
pub const KEY_LABEL_DY: f32 = 30.0;
/// The size of the key's top label, in bold.
pub const KEY_LABEL_PX: f32 = 16.0;
/// The extra space after each letter of the key's top label.
pub const KEY_LABEL_TRACKING: f32 = 2.0;
/// The key's top label while blocking is on.
pub const KEY_LABEL: &str = "GATE";
/// The key's top label while blocking is paused: it says which way the gate is.
pub const KEY_LABEL_OPEN: &str = "OPEN";
/// The key's big text, drawn centred, from the key's top to its baseline.
pub const KEY_BIG_DY: f32 = 62.0;
/// The size of the key's big text, in bold white.
pub const KEY_BIG_PX: f32 = 24.0;
/// The key's big text while blocking is on.
pub const KEY_BIG_ON: &str = "SHUT";
/// The width of the paused key's white outline, which is drawn inside the key.
pub const KEY_STROKE: f32 = 4.0;

// The alert takeover: one card claims this region until it is tapped.

/// The card: inset 8 px from the gate and from the right edge, and standing on the floor. A tap anywhere on it dismisses the alert.
pub const ALERT: Area = Area::new(128.0, 80.0, 344.0, 224.0);
/// The field the takeover clears to black before the card is drawn, so that nothing of the funnel or the count shows around it.
pub const ALERT_FIELD: Area = Area::new(120.0, 80.0, 360.0, 240.0);
/// The height of the stub at the card's foot, which holds `TAP TO DISMISS`: the paused key's outline.
pub const ALERT_STUB_H: f32 = 44.0;
/// The width of the stub's rim, in the card's colour.
pub const ALERT_STUB_RIM: f32 = 4.0;
/// The left edge of the title lines, from the card's left.
pub const ALERT_TITLE_DX: f32 = 14.0;
/// The baselines of the two title lines, from the card's top.
pub const ALERT_TITLE_DY: [f32; 2] = [45.0, 87.0];
/// The size of the title lines, in bold ink.
pub const ALERT_TITLE_PX: f32 = 40.0;
/// The left edge of the subject and who lines, from the card's left.
pub const ALERT_TEXT_DX: f32 = 15.0;
/// The baseline of the card's last line, from the card's top: 15 px above the slab's foot.
pub const ALERT_LAST_DY: f32 = ALERT.h - ALERT_STUB_H - 15.0;
/// The size of the subject, in bold ink.
pub const ALERT_SUBJECT_PX: f32 = 20.0;
/// The distance between the baselines of the subject's two lines.
pub const ALERT_SUBJECT_LEADING: f32 = 23.0;
/// The size of the who line, in regular ink, on the card's last baseline.
pub const ALERT_WHO_PX: f32 = 18.0;
/// How much higher the subject's last line stands when there is a who line.
pub const ALERT_WHO_LIFT: f32 = 24.0;
/// The stub's text, centred, in bold white.
pub const ALERT_STUB_TEXT: &str = "TAP TO DISMISS";
/// The stub text's baseline, from the card's top.
pub const ALERT_STUB_TEXT_DY: f32 = ALERT.h - ALERT_STUB_H + 27.0;
/// The size of the stub's text.
pub const ALERT_STUB_PX: f32 = 20.0;
/// The extra space after each letter of the stub's text.
pub const ALERT_STUB_TRACKING: f32 = 2.0;
/// The ink of everything on the card that is not in its colour.
pub const ALERT_INK: Rgb = GROUND;
/// How many cells a title line has before it is cut: the room right of the card's margin at 40 px, 24 px a letter.
pub const ALERT_TITLE_CELLS: usize = 13;
/// How many cells a line of the subject has: the card's width less its margins at 20 px, 12 px a letter. A longer subject wraps onto a second line, and past two lines its start goes.
pub const ALERT_SUBJECT_CELLS: usize = 26;
/// How many cells the who line has before it is cut: the same room at 18 px, 10.8 px a letter.
pub const ALERT_WHO_CELLS: usize = 29;
