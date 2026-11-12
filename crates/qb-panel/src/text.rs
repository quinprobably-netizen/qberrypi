//! One line of text in JetBrains Mono, drawn into an RGBA buffer.
//!
//! The fonts are JetBrains Mono 2.304, Regular and Bold, embedded unchanged from
//! <https://github.com/JetBrains/JetBrainsMono/releases/download/v2.304/JetBrainsMono-2.304.zip>.
//! They are under the SIL Open Font License 1.1, whose text is `fonts/OFL.txt`;
//! `fonts/SHA256SUMS` holds the digests of the three files.
//!
//! Nothing here panics, whatever the text, the size, the position or the
//! buffer: what cannot be drawn is left out.

use std::collections::HashMap;

use ab_glyph::{Font, FontRef, PxScale, ScaleFont, point};

use crate::geometry::{Anchor, HEIGHT, Rgb, TextSlot, WIDTH, Weight};

/// The embedded font of a weight. Reading it parses only the table directory.
fn font(weight: Weight) -> Option<FontRef<'static>> {
    let bytes: &[u8] = match weight {
        Weight::Regular => include_bytes!("../fonts/JetBrainsMono-Regular.ttf"),
        Weight::Bold => include_bytes!("../fonts/JetBrainsMono-Bold.ttf"),
    };
    FontRef::try_from_slice(bytes).ok()
}

/// The `ab_glyph` scale of a font size, or `None` for a size that is not above 0.
///
/// `PxScale` is the line height, ascent to descent, where the size is the em:
/// 1.32 times the size for this font.
fn scale(font: &FontRef<'_>, size: f32) -> Option<PxScale> {
    let em = font.units_per_em()?;
    // False for a size that is not a number, too.
    (size > 0.0).then(|| PxScale::from(size * font.height_unscaled() / em))
}

/// One channel of a pixel, `coverage` of the way from what is there to the colour.
fn blend(under: u8, color: u8, coverage: f32) -> u8 {
    let (under, color) = (f32::from(under), f32::from(color));
    (under + (color - under) * coverage.clamp(0.0, 1.0)).round() as u8
}

/// Whether the font of this weight has a glyph of its own for the character.
pub fn has_glyph(weight: Weight, c: char) -> bool {
    font(weight).is_some_and(|font| font.glyph_id(c).0 != 0)
}

/// How wide a text is at a font size: the sum of its glyphs' advances, with no kerning.
///
/// A character the font lacks advances like the font's missing-glyph box. A
/// size that is not above 0, or not a number, has no width.
pub fn text_width(text: &str, weight: Weight, size: f32) -> f32 {
    let Some(font) = font(weight) else { return 0.0 };
    let Some(scale) = scale(&font, size) else {
        return 0.0;
    };
    let font = font.as_scaled(scale);
    text.chars().map(|c| font.h_advance(font.glyph_id(c))).sum()
}

/// Draws one line into a 480 × 320 RGBA buffer (614,400 bytes).
///
/// The letters are blended over what is there and every alpha is left as it
/// is. Each glyph stands at its fractional pen position: no rounding, no
/// kerning, no shaping. A character the font lacks is drawn as the font's
/// missing-glyph box. What falls outside the frame, or outside a buffer that
/// is shorter than the frame, is left out, and so is a glyph larger than the
/// frame. A size that is not above 0, or not a number, draws nothing.
pub fn draw_text(rgba: &mut [u8], slot: &TextSlot, text: &str) {
    let Some(font) = font(slot.weight) else {
        return;
    };
    let Some(scale) = scale(&font, slot.size) else {
        return;
    };
    let width = text_width(text, slot.weight, slot.size);
    let mut pen = match slot.anchor {
        Anchor::Start => slot.x,
        Anchor::Middle => slot.x - width / 2.0,
        Anchor::End => slot.x - width,
    };
    let (frame_w, frame_h) = (WIDTH as f32, HEIGHT as f32);
    let font = font.as_scaled(scale);
    for c in text.chars() {
        let id = font.glyph_id(c);
        let glyph = id.with_scale_and_position(scale, point(pen, slot.baseline));
        pen += font.h_advance(id);
        // A glyph with no outline, a space, draws nothing.
        let Some(outline) = font.outline_glyph(glyph) else {
            continue;
        };
        // The glyph's box in whole pixels. Each comparison is false for a box
        // that is not a number, so past this point the box is finite, no larger
        // than the frame and overlapping it: the rasteriser's grid is at most
        // one frame, and the sums below cannot overflow.
        let ink = outline.px_bounds();
        let fits = ink.width() <= frame_w && ink.height() <= frame_h;
        let overlaps =
            ink.max.x > 0.0 && ink.min.x < frame_w && ink.max.y > 0.0 && ink.min.y < frame_h;
        if !(fits && overlaps) {
            continue;
        }
        let (left, top) = (ink.min.x as i64, ink.min.y as i64);
        outline.draw(|dx, dy, coverage| {
            // A pixel left of the frame or above it has no `usize`.
            let (Ok(x), Ok(y)) = (
                usize::try_from(left + i64::from(dx)),
                usize::try_from(top + i64::from(dy)),
            ) else {
                return;
            };
            if x >= WIDTH || y >= HEIGHT {
                return;
            }
            let at = (y * WIDTH + x) * 4;
            // A pixel the buffer does not wholly hold is skipped.
            let Some(pixel) = rgba.get_mut(at..at + 4) else {
                return;
            };
            for (under, color) in pixel.iter_mut().zip(slot.color) {
                *under = blend(*under, color, coverage);
            }
        });
    }
}

/// How far above the baseline any glyph of the font reaches, as a share of the size.
///
/// The font's ascent line is 1.02 of the em; a glyph does not rise past it.
pub const ASCENT_EM: f32 = 1.02;

/// How far below the baseline any glyph of the font reaches, as a share of the size.
pub const DESCENT_EM: f32 = 0.30;

/// How many rendered glyphs the cache keeps before it starts over, so that it cannot grow without bound.
const CACHE_MAX: usize = 2048;

/// What a rendered glyph is looked up by: the character, the size, the weight and the fractional
/// part of where its pen stands, which all change what its pixels look like.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct GlyphKey {
    /// The character.
    c: char,
    /// The bits of the font size.
    size: u32,
    /// Whether the weight is bold.
    bold: bool,
    /// The bits of the pen's x less its whole pixels.
    fx: u32,
    /// The bits of the baseline's y less its whole pixels.
    fy: u32,
}

/// The coverage of a glyph's pixels, as it falls from a pen at a whole pixel plus the key's fraction.
struct Glyph {
    /// The column of the box's left edge, from the pen's whole pixel.
    left: i32,
    /// The row of the box's top edge, from the baseline's whole pixel.
    top: i32,
    /// The box's width in pixels.
    width: usize,
    /// How much of each pixel the glyph covers, 0 to 255, rows from the top.
    coverage: Vec<u8>,
}

/// One channel of a pixel, `coverage` out of 255 of the way from what is there to the colour.
pub fn mix_channel(under: u8, color: u8, coverage: u8) -> u8 {
    let (under, color, coverage) = (i32::from(under), i32::from(color), i32::from(coverage));
    let delta = (color - under) * coverage;
    // Halves go away from the under colour; the result is between the two, so it is a byte.
    let half = if delta >= 0 { 127 } else { -127 };
    u8::try_from(under + (delta + half) / 255).unwrap_or(u8::MAX)
}

/// Draws text like `draw_text`, from glyphs it has rendered before.
///
/// A glyph is rendered once for each size, weight and fractional pen position it is drawn at, and
/// every later one is a copy of its coverage over the pixels. The cache holds at most
/// `CACHE_MAX` glyphs and starts over when it is full. Nothing here panics, whatever the text, the
/// size, the position or the buffer.
pub struct GlyphCache {
    /// The regular font, or `None` if it did not parse.
    regular: Option<FontRef<'static>>,
    /// The bold font, or `None` if it did not parse.
    bold: Option<FontRef<'static>>,
    /// Each glyph asked for, or `None` for one that has no outline, a space.
    glyphs: HashMap<GlyphKey, Option<Glyph>>,
}

impl Default for GlyphCache {
    fn default() -> Self {
        Self::new()
    }
}

impl GlyphCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self {
            regular: font(Weight::Regular),
            bold: font(Weight::Bold),
            glyphs: HashMap::new(),
        }
    }

    /// Renders one glyph at a pen of the fraction `(fx, fy)` of a pixel; `None` for one with no outline or no size that fits the frame.
    fn render(
        font: &FontRef<'static>,
        scale: PxScale,
        c: char,
        (fx, fy): (f32, f32),
    ) -> Option<Glyph> {
        let glyph = font
            .glyph_id(c)
            .with_scale_and_position(scale, point(fx, fy));
        let outline = font.outline_glyph(glyph)?;
        let ink = outline.px_bounds();
        // A box that is not a number, or larger than the frame, is not drawn.
        let fits = ink.width() <= WIDTH as f32 && ink.height() <= HEIGHT as f32;
        if !fits {
            return None;
        }
        let (width, height) = (ink.width() as usize, ink.height() as usize);
        let mut coverage = vec![0_u8; width.checked_mul(height)?];
        outline.draw(|x, y, covered| {
            let at = (y as usize)
                .saturating_mul(width)
                .saturating_add(x as usize);
            if let Some(pixel) = coverage.get_mut(at) {
                *pixel = (covered.clamp(0.0, 1.0) * 255.0).round() as u8;
            }
        });
        Some(Glyph {
            left: ink.min.x as i32,
            top: ink.min.y as i32,
            width,
            coverage,
        })
    }

    /// Draws one line of text, blending its letters over what is in `rows`.
    ///
    /// `rows` holds whole rows of the 480-pixel-wide RGBA frame, the first of them the frame's row
    /// `top`. What falls outside them is left out, and so is a size that is not above 0, a position
    /// that is not a number, and a character with no outline. Alphas are left as they are.
    pub fn draw(&mut self, rows: &mut [u8], top: i32, slot: &TextSlot, text: &str) {
        let Self {
            regular,
            bold,
            glyphs,
        } = self;
        let font = match slot.weight {
            Weight::Regular => regular,
            Weight::Bold => bold,
        };
        let Some(font) = font.as_ref() else { return };
        let Some(scale) = scale(font, slot.size) else {
            return;
        };
        let scaled = font.as_scaled(scale);
        let width: f32 = text
            .chars()
            .map(|c| scaled.h_advance(scaled.glyph_id(c)))
            .sum();
        let mut pen = match slot.anchor {
            Anchor::Start => slot.x,
            Anchor::Middle => slot.x - width / 2.0,
            Anchor::End => slot.x - width,
        };
        if !(pen.is_finite() && slot.baseline.is_finite()) {
            return;
        }
        let base_row = slot.baseline.floor();
        let base_fraction = slot.baseline - base_row;
        // Saturating casts: a baseline far outside the frame draws nothing below.
        let base_row = base_row as i32;
        for c in text.chars() {
            let advance = scaled.h_advance(scaled.glyph_id(c));
            let pen_column = pen.floor();
            let fraction = pen - pen_column;
            pen += advance;
            let key = GlyphKey {
                c,
                size: slot.size.to_bits(),
                bold: slot.weight == Weight::Bold,
                fx: fraction.to_bits(),
                fy: base_fraction.to_bits(),
            };
            if glyphs.len() >= CACHE_MAX && !glyphs.contains_key(&key) {
                glyphs.clear();
            }
            let glyph = glyphs
                .entry(key)
                .or_insert_with(|| Self::render(font, scale, c, (fraction, base_fraction)));
            let Some(glyph) = glyph else { continue };
            let column = (pen_column as i32).saturating_add(glyph.left);
            let row = base_row.saturating_add(glyph.top).saturating_sub(top);
            blit_mask(rows, row, column, glyph.width, &glyph.coverage, slot.color);
        }
    }
}

/// Blends a mask of coverage into whole rows of the 480-pixel-wide RGBA frame, in a colour.
///
/// The mask is `width` pixels across, its pixels from 0 to 255 and its rows from the top; its top-left
/// pixel is at (`column`, `row`) of `rows`. What falls outside is left out, and so is a mask with no
/// width. Alphas are left as they are.
pub fn blit_mask(
    rows: &mut [u8],
    row: i32,
    column: i32,
    width: usize,
    coverage: &[u8],
    color: Rgb,
) {
    if width == 0 {
        return;
    }
    let row_count = i64::try_from(rows.len() / (WIDTH * 4)).unwrap_or(0);
    let (across, columns) = (i64::try_from(width).unwrap_or(0), WIDTH as i64);
    // The mask's columns that are in the frame.
    let first = (-i64::from(column)).clamp(0, across);
    let last = (columns - i64::from(column)).clamp(0, across);
    if first >= last {
        return;
    }
    let (first, last) = (first as usize, last as usize);
    let left = usize::try_from(i64::from(column) + first as i64).unwrap_or(0);
    for (dy, line) in coverage.chunks_exact(width).enumerate() {
        let y = i64::from(row).saturating_add(i64::try_from(dy).unwrap_or(0));
        if !(0..row_count).contains(&y) {
            continue;
        }
        let at = (y as usize * WIDTH + left) * 4;
        let Some(span) = rows.get_mut(at..at + (last - first) * 4) else {
            continue;
        };
        for (&covered, pixel) in line[first..last]
            .iter()
            .zip(span.as_chunks_mut::<4>().0.iter_mut())
        {
            if covered == 0 {
                continue;
            }
            for (under, channel) in pixel.iter_mut().zip(color) {
                *under = mix_channel(*under, channel, covered);
            }
        }
    }
}

#[cfg(test)]
mod fixtures {
    //! The colours and the slots the text tests draw with.

    use crate::geometry::{Anchor, Rgb, TextSlot, WHITE, Weight};

    /// The ground.
    pub(super) const BLACK: Rgb = [0x00, 0x00, 0x00];
    /// A lit blue to blend text into.
    pub(super) const ACCENT: Rgb = [0x4a, 0x72, 0xff];
    /// How far every JetBrains Mono glyph advances, in ems.
    pub(super) const ADVANCE: f32 = 0.6;
    /// A short bold word in black, centred on x = 79 and standing on y = 301.
    pub(super) const KNOB_ON_TEXT: TextSlot = TextSlot {
        x: 79.0,
        baseline: 301.0,
        anchor: Anchor::Middle,
        size: 18.0,
        weight: Weight::Bold,
        color: BLACK,
    };
    /// A large bold figure in white, centred on x = 104 and standing on y = 124.
    pub(super) const PERCENT: TextSlot = TextSlot {
        x: 104.0,
        baseline: 124.0,
        anchor: Anchor::Middle,
        size: 50.0,
        weight: Weight::Bold,
        color: WHITE,
    };
}

#[cfg(test)]
mod tests {
    use super::fixtures::{ACCENT, ADVANCE, BLACK, KNOB_ON_TEXT, PERCENT};
    use super::*;
    use crate::geometry::{Rgb, WHITE};

    /// A frame of one colour, alpha 255.
    fn blank(color: Rgb) -> Vec<u8> {
        [color[0], color[1], color[2], 255].repeat(WIDTH * HEIGHT)
    }

    /// The box `(left, top, right, bottom)` of the pixels that differ from the background, ends included.
    fn ink(buf: &[u8], background: Rgb) -> (usize, usize, usize, usize) {
        let mut found = None;
        for (i, pixel) in buf.as_chunks::<4>().0.iter().enumerate() {
            if pixel[..3] != background {
                let (x, y) = (i % WIDTH, i / WIDTH);
                let (l, t, r, b) = found.unwrap_or((x, y, x, y));
                found = Some((l.min(x), t.min(y), r.max(x), b.max(y)));
            }
        }
        found.expect("something was drawn")
    }

    #[test]
    fn every_character_the_panel_can_show_has_a_glyph() {
        for w in [Weight::Regular, Weight::Bold] {
            for c in ('!'..='~').chain(['°', '—', '…']) {
                assert!(has_glyph(w, c), "{c:?}");
            }
        }
    }

    #[test]
    fn a_glyph_advances_six_tenths_of_the_size() {
        assert!((text_width("44%", Weight::Bold, 50.0) - 90.0).abs() < 0.01);
        assert!((text_width("blocked", Weight::Regular, 17.0) - 71.4).abs() < 0.01);
    }

    #[test]
    fn the_anchor_places_the_text() {
        // "H", bold, 50 px, x = 200, baseline = 200
        let slot = |anchor| TextSlot {
            x: 200.0,
            baseline: 200.0,
            anchor,
            size: 50.0,
            weight: Weight::Bold,
            color: WHITE,
        };
        for (anchor, left, right) in [
            (Anchor::Start, 203, 226),
            (Anchor::Middle, 188, 211),
            (Anchor::End, 173, 196),
        ] {
            let mut buf = blank(BLACK);
            draw_text(&mut buf, &slot(anchor), "H");
            let (l, t, r, b) = ink(&buf, BLACK);
            assert!(
                l.abs_diff(left) <= 1
                    && r.abs_diff(right) <= 1
                    && t.abs_diff(163) <= 1
                    && b.abs_diff(199) <= 1,
                "{anchor:?}: {l} {t} {r} {b}"
            );
        }
    }

    #[test]
    #[expect(
        clippy::chunks_exact_to_as_chunks,
        reason = "the plan's test as written"
    )]
    fn text_blends_into_what_is_there_and_stays_opaque() {
        let mut buf = blank(ACCENT);
        draw_text(&mut buf, &KNOB_ON_TEXT, "on");
        assert!(buf.chunks_exact(4).all(|p| p[3] == 255));
        assert!(buf.chunks_exact(4).any(|p| p[..3] == BLACK)); // a stem's inside is the full colour
        let (l, t, r, b) = ink(&buf, ACCENT);
        assert!(
            l >= 66 && r <= 92 && t >= 288 && b <= 302,
            "{l} {t} {r} {b}"
        ); // centred on x = 79, sitting on y = 301
    }

    #[test]
    fn text_past_an_edge_is_clipped() {
        let mut buf = blank(BLACK);
        for (x, baseline) in [(470.0, 20.0), (-40.0, 160.0), (240.0, 340.0), (240.0, -5.0)] {
            draw_text(
                &mut buf,
                &TextSlot {
                    x,
                    baseline,
                    ..PERCENT
                },
                "100%",
            ); // must not panic
        }
        assert_eq!(buf.len(), 614_400);
        // Not in the plan: what is cut off at one edge does not come back in at the other.
        let lit = |x: usize, y: usize| buf[(y * WIDTH + x) * 4..][..3] != BLACK;
        // The text at x = 470 reaches the right edge and stops there ...
        assert!((0..40).any(|y| (470..480).any(|x| lit(x, y))));
        // ... instead of going on from the left edge,
        assert!(!(0..40).any(|y| (0..=20).any(|x| lit(x, y))));
        // and the text at x = -40 does not go on from the right edge of the row above.
        assert!(!(120..170).any(|y| (460..480).any(|x| lit(x, y))));
    }

    // Not in the plan: each channel goes to the nearest level, and coverage past 1 is full coverage.
    #[test]
    fn a_channel_is_blended_to_the_nearest_level() {
        assert_eq!(
            [
                blend(0, 255, 0.5),
                blend(255, 0, 0.5),
                blend(200, 100, 0.25)
            ],
            [128, 128, 175]
        );
        assert_eq!([blend(74, 0, 0.0), blend(74, 0, 1.0)], [74, 0]);
        assert_eq!([blend(250, 10, 1.5), blend(10, 250, 1.5)], [10, 250]);
    }

    // Not in the plan: the layout counts characters, so every one of them advances alike.
    #[test]
    fn every_character_the_panel_can_show_advances_alike() {
        for w in [Weight::Regular, Weight::Bold] {
            assert!(has_glyph(w, ' '));
            for c in (' '..='~').chain(['°', '—', '…']) {
                let width = text_width(c.encode_utf8(&mut [0; 4]), w, 10.0);
                assert!((width - 10.0 * ADVANCE).abs() < 0.001, "{c:?}: {width}");
            }
        }
        assert_eq!(text_width("", Weight::Bold, 50.0), 0.0);
    }

    // Not in the plan: a character the font lacks is the font's own missing-glyph box, one advance wide.
    #[test]
    fn a_character_the_font_lacks_is_drawn_as_the_missing_glyph() {
        for w in [Weight::Regular, Weight::Bold] {
            assert!(!has_glyph(w, '漢'));
            assert!((text_width("漢", w, 50.0) - 30.0).abs() < 0.01);
            assert_eq!(text_width("4漢%", w, 50.0), text_width("44%", w, 50.0));
        }
        let mut buf = blank(BLACK);
        draw_text(&mut buf, &PERCENT, "漢"); // centred on x = 104, standing on y = 124
        let (l, t, r, b) = ink(&buf, BLACK);
        assert!(
            l >= 89 && r <= 119 && t >= 74 && b <= 134,
            "{l} {t} {r} {b}"
        );
    }

    // Not in the plan: a size nothing can be set at has no width and draws nothing.
    #[test]
    fn a_size_that_is_not_above_zero_sets_nothing() {
        for size in [0.0, -0.0, -50.0, f32::NEG_INFINITY, f32::NAN] {
            assert_eq!(text_width("100%", Weight::Bold, size), 0.0, "{size}");
            let mut buf = blank(BLACK);
            draw_text(&mut buf, &TextSlot { size, ..PERCENT }, "100%");
            assert!(buf == blank(BLACK), "{size}");
        }
    }

    // Not in the plan: text that is nowhere near the frame, or larger than it, draws nothing.
    #[test]
    fn text_that_cannot_be_seen_draws_nothing() {
        let far = [
            -1e9,
            1e9,
            f32::MIN,
            f32::MAX,
            f32::NEG_INFINITY,
            f32::INFINITY,
            f32::NAN,
        ];
        let mut buf = blank(BLACK);
        for at in far {
            for anchor in [Anchor::Start, Anchor::Middle, Anchor::End] {
                let slot = TextSlot { anchor, ..PERCENT };
                draw_text(&mut buf, &TextSlot { x: at, ..slot }, "100%");
                draw_text(
                    &mut buf,
                    &TextSlot {
                        baseline: at,
                        ..slot
                    },
                    "100%",
                );
                draw_text(
                    &mut buf,
                    &TextSlot {
                        x: at,
                        baseline: at,
                        ..slot
                    },
                    "100%",
                );
            }
        }
        for size in [2000.0, 1e9, f32::MAX, f32::INFINITY] {
            for anchor in [Anchor::Start, Anchor::Middle, Anchor::End] {
                let slot = TextSlot {
                    x: 240.0,
                    baseline: 160.0,
                    anchor,
                    size,
                    ..PERCENT
                };
                draw_text(&mut buf, &slot, "100%");
                assert!(!text_width("100%", Weight::Bold, size).is_nan());
            }
        }
        assert!(buf == blank(BLACK));
    }

    // Not in the plan: no text, size, position or buffer makes either function panic.
    #[test]
    fn no_input_panics() {
        let sizes = [
            0.0,
            -18.0,
            f32::MIN_POSITIVE,
            1e-3,
            18.0,
            400.0,
            1e4,
            f32::MAX,
            f32::INFINITY,
            f32::NAN,
        ];
        let places = [
            0.0,
            160.5,
            -1e5,
            1e5,
            f32::MIN,
            f32::MAX,
            f32::INFINITY,
            f32::NAN,
        ];
        let texts = ["", "漢", "\0\n\t\u{301}\u{e000}\u{10ffff}", "100%"];
        let mut buffers = [0, 1, 3, 4, 7, 4 * WIDTH * 7 + 2, 4 * WIDTH * (HEIGHT + 9)]
            .map(|len| vec![0u8; len])
            .to_vec();
        buffers.push(blank(BLACK));
        for buf in &mut buffers {
            let len = buf.len();
            for &size in &sizes {
                for &x in &places {
                    for &baseline in &places {
                        for (text, anchor) in texts.iter().zip([
                            Anchor::Start,
                            Anchor::Middle,
                            Anchor::End,
                            Anchor::End,
                        ]) {
                            let slot = TextSlot {
                                x,
                                baseline,
                                anchor,
                                size,
                                ..PERCENT
                            };
                            draw_text(buf, &slot, text);
                            let _ = text_width(text, Weight::Regular, size);
                        }
                    }
                }
            }
            assert_eq!(buf.len(), len);
        }
    }

    // Not in the plan: a buffer that is not one frame long takes the part of the text that falls in it.
    #[test]
    fn a_buffer_of_another_length_takes_what_fits() {
        // 100 rows and half a pixel: "44%" standing on y = 110 is cut at the last whole row.
        let mut short = blank(BLACK);
        short.truncate(4 * WIDTH * 100 + 2);
        draw_text(
            &mut short,
            &TextSlot {
                baseline: 110.0,
                ..PERCENT
            },
            "44%",
        );
        let (_, t, _, b) = ink(&short, BLACK);
        assert!(t.abs_diff(73) <= 1 && b == 99, "{t} {b}");
        assert_eq!(short[4 * WIDTH * 100..], [0, 0]);

        // 40 rows too many: the frame ends at row 320 all the same.
        let mut long = blank(BLACK);
        long.resize(4 * WIDTH * (HEIGHT + 40), 7);
        draw_text(
            &mut long,
            &TextSlot {
                baseline: 340.0,
                ..PERCENT
            },
            "44%",
        );
        let (_, t, _, b) = ink(&long[..4 * WIDTH * HEIGHT], BLACK);
        assert!(t.abs_diff(303) <= 1 && b == 319, "{t} {b}");
        assert!(long[4 * WIDTH * HEIGHT..].iter().all(|&byte| byte == 7));
    }
}

#[cfg(test)]
mod cache_tests {
    use super::fixtures::{BLACK, PERCENT};
    use super::*;
    use crate::geometry::{Rgb, WHITE};

    /// A frame of one colour, alpha 255.
    fn blank(color: Rgb) -> Vec<u8> {
        [color[0], color[1], color[2], 255].repeat(WIDTH * HEIGHT)
    }

    /// A slot for tests: bold, white, at a place.
    fn at(x: f32, baseline: f32, size: f32, anchor: Anchor) -> TextSlot {
        TextSlot {
            x,
            baseline,
            anchor,
            size,
            ..PERCENT
        }
    }

    #[test]
    fn glyphs_stay_between_the_ascent_and_descent_lines() {
        // The painter repaints the rows between these lines, so no glyph may reach past them.
        for weight in [Weight::Regular, Weight::Bold] {
            let font = font(weight).expect("the font parses");
            let scale = scale(&font, 100.0).expect("100 px is a size");
            for c in (' '..='~').chain(['°', '—', '…', '漢']) {
                let glyph = font
                    .glyph_id(c)
                    .with_scale_and_position(scale, point(0.0, 0.0));
                if let Some(outline) = font.outline_glyph(glyph) {
                    let ink = outline.px_bounds();
                    assert!(
                        ink.min.y >= -100.0 * ASCENT_EM,
                        "{c:?} rises to {}",
                        ink.min.y
                    );
                    assert!(
                        ink.max.y <= 100.0 * DESCENT_EM,
                        "{c:?} sinks to {}",
                        ink.max.y
                    );
                }
            }
        }
    }

    #[test]
    fn the_cache_draws_what_draw_text_draws_to_within_rounding() {
        for (slot, text) in [
            (at(240.0, 160.0, 64.0, Anchor::Middle), "4,780"),
            (at(6.0, 120.5, 40.0, Anchor::Start), "44%"),
            (at(300.3, 90.7, 18.0, Anchor::End), "asked by 192.0.2.23"),
        ] {
            let (mut direct, mut cached) = (blank(BLACK), blank(BLACK));
            draw_text(&mut direct, &slot, text);
            GlyphCache::new().draw(&mut cached, 0, &slot, text);
            let worst = direct
                .iter()
                .zip(&cached)
                .map(|(a, b)| a.abs_diff(*b))
                .max()
                .unwrap_or(0);
            assert!(direct != blank(BLACK), "{text}: something was drawn");
            assert!(worst <= 4, "{text}: the cache differs by {worst} levels");
        }
    }

    #[test]
    fn a_band_of_rows_gets_exactly_the_rows_of_the_whole_frame() {
        let slot = at(240.0, 200.4, 64.0, Anchor::Middle);
        let mut cache = GlyphCache::new();
        let mut whole = blank(BLACK);
        cache.draw(&mut whole, 0, &slot, "4,780");
        for (from, to) in [(0, 320), (150, 175), (176, 177), (230, 320), (100, 202)] {
            let mut band = blank(BLACK)[from * WIDTH * 4..to * WIDTH * 4].to_vec();
            cache.draw(&mut band, i32::try_from(from).unwrap_or(0), &slot, "4,780");
            assert!(
                band == whole[from * WIDTH * 4..to * WIDTH * 4],
                "rows {from} to {to} differ"
            );
        }
    }

    #[test]
    fn text_blends_over_the_colour_under_it_and_keeps_the_alpha() {
        let mut frame = blank([0x4a, 0x72, 0xff]);
        frame[3] = 200;
        GlyphCache::new().draw(&mut frame, 0, &at(240.0, 160.0, 64.0, Anchor::Middle), "8");
        assert_eq!(frame[3], 200);
        assert!(frame.as_chunks::<4>().0.iter().any(|p| p[..3] == WHITE));
        assert!(
            frame
                .as_chunks::<4>()
                .0
                .iter()
                .any(|p| p[..3] == [0x4a, 0x72, 0xff])
        );
    }

    #[test]
    fn odd_input_draws_nothing_and_does_not_panic() {
        let mut cache = GlyphCache::new();
        let mut frame = blank(BLACK);
        let nowhere = [
            f32::NAN,
            f32::INFINITY,
            f32::NEG_INFINITY,
            f32::MAX,
            f32::MIN,
            1e9,
        ];
        for &place in &nowhere {
            for anchor in [Anchor::Start, Anchor::Middle, Anchor::End] {
                for size in [0.0, -3.0, f32::NAN, f32::INFINITY, 2000.0, 24.0] {
                    for slot in [
                        at(place, 100.0, size, anchor),
                        at(100.0, place, size, anchor),
                    ] {
                        cache.draw(&mut frame, 0, &slot, "a漢 \0!");
                        cache.draw(&mut frame[..7], 3, &slot, "a");
                        cache.draw(&mut [], -5, &slot, "a");
                    }
                }
            }
        }
        assert!(frame == blank(BLACK));
        // A band whose first row is above or below the frame.
        let mut band = blank(BLACK)[..4 * WIDTH * 10].to_vec();
        cache.draw(
            &mut band,
            i32::MIN,
            &at(10.0, 5.0, 24.0, Anchor::Start),
            "a",
        );
        cache.draw(
            &mut band,
            i32::MAX,
            &at(10.0, 5.0, 24.0, Anchor::Start),
            "a",
        );
        assert!(band == blank(BLACK)[..4 * WIDTH * 10]);
    }

    #[test]
    fn the_cache_does_not_grow_without_bound() {
        let mut cache = GlyphCache::new();
        let mut frame = blank(BLACK);
        // A different fractional position for every call is a different glyph.
        for i in 0..CACHE_MAX * 2 {
            let x = 100.0 + (i as f32) * 0.001;
            cache.draw(&mut frame, 0, &at(x, 100.0, 20.0, Anchor::Start), "x");
            assert!(cache.glyphs.len() <= CACHE_MAX);
        }
    }

    #[test]
    fn a_channel_goes_to_the_nearest_level_and_full_coverage_is_the_colour() {
        assert_eq!(
            [
                mix_channel(0, 255, 128),
                mix_channel(255, 0, 128),
                mix_channel(200, 100, 64)
            ],
            [128, 127, 175]
        );
        for under in [0, 1, 127, 200, 255] {
            for color in [0, 1, 99, 254, 255] {
                assert_eq!(mix_channel(under, color, 255), color);
                assert_eq!(mix_channel(under, color, 0), under);
            }
        }
    }

    #[test]
    fn a_space_advances_the_pen_like_any_other_character() {
        let mut cache = GlyphCache::new();
        let (mut together, mut apart) = (blank(BLACK), blank(BLACK));
        cache.draw(
            &mut together,
            0,
            &at(10.0, 100.0, 20.0, Anchor::Start),
            "a b",
        );
        cache.draw(&mut apart, 0, &at(10.0, 100.0, 20.0, Anchor::Start), "a");
        cache.draw(&mut apart, 0, &at(34.0, 100.0, 20.0, Anchor::Start), "b");
        let worst = together
            .iter()
            .zip(&apart)
            .map(|(a, b)| a.abs_diff(*b))
            .max()
            .unwrap_or(0);
        assert!(worst <= 2, "{worst}");
    }
}
