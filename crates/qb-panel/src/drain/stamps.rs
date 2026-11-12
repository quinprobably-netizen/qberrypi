//! The Drain's round shapes as coverage masks, read off the round 6 mockup.
//!
//! The mockup is drawn by a browser, and a browser's anti-aliasing of a circle is neither the exact
//! area of the circle in each pixel nor symmetric: in a radius 5 dot the middle of the top row is
//! covered 239/255 and the middle of the bottom row 224/255, where the exact share is 247/255 for
//! both. No supersampling gets there: the exact area is off by up to 39/255 (at the bottom of a
//! dot), and `tiny-skia`'s anti-aliasing, which these masks replace, by up to 36/255. So the masks
//! are the browser's own, one for each shape. Every shape stands on a whole pixel, since the grid puts
//! every centre on one, and then its mask is one table.
//!
//! Each table is the coverage, 0 to 255, of the pixels around the shape's centre, rows from the top.
//! They were read off the mockup's stills and its refusal strip (`r6-after-*.png`) by solving, pixel
//! by pixel, the browser's blend, `(colour * (a + 1) >> 8) + (under * (256 - a) >> 8)`, for the
//! coverage `a` that gives the pixels seen: over every instance of the shape, on the ground, on the
//! rail, on the funnel's dots, or on the drip a tip is drawn over. White shapes (a landed dot, the
//! drop) and the lit blue dot give `a` directly in the red or blue channel. Where several coverages
//! give the pixels seen, the one nearest the exact area is kept. The teardrop is two masks, a
//! circle and then a triangle drawn over it, as the mockup fills them; where its two soft edges
//! meet, a pair of coverages that gives the pixels seen is kept.
//!
//! The browser's rasteriser is not quite the same at every place on the screen: 28 of the 146 dots
//! of a full funnel, those in five columns (x 156, 240, 324, 336 and 420), have two pixels (4 left of
//! the centre, 2 and 3 below it) that are 2 to 8 in 255 off the masks here, which are those of the
//! other 118. That is all that is left between the stills and the painter in a round shape, and
//! `drain_matches_the_mockup` counts it.
//!
//! The masks are only right for the radii they were read at: the tests below check each one's area
//! and centre against the radius `look` gives the shape.

/// A lit dot at rest, and the drop at the spout: a circle of radius 5. Pixels `-6..6` across and down from the centre.
pub(super) const DOT: [[u8; 12]; 12] = [
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 73, 205, 239, 239, 205, 73, 0, 0, 0],
    [0, 3, 134, 254, 255, 255, 255, 255, 254, 131, 3, 0],
    [0, 65, 255, 255, 255, 255, 255, 255, 255, 253, 68, 0],
    [0, 184, 255, 255, 255, 255, 255, 255, 255, 255, 184, 0],
    [0, 232, 255, 255, 255, 255, 255, 255, 255, 255, 232, 0],
    [0, 232, 255, 255, 255, 255, 255, 255, 255, 255, 232, 0],
    [0, 184, 255, 255, 255, 255, 255, 255, 255, 255, 184, 0],
    [0, 68, 255, 255, 255, 255, 255, 255, 255, 253, 65, 0],
    [0, 0, 144, 255, 255, 255, 255, 255, 255, 128, 0, 0],
    [0, 0, 0, 42, 156, 224, 224, 156, 42, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
];

/// A landed dot turning face-on: a circle of radius 6. Pixels `-6..6` across and down.
pub(super) const FACE: [[u8; 12]; 12] = [
    [0, 0, 0, 93, 173, 229, 229, 173, 93, 0, 0, 0],
    [0, 31, 185, 255, 255, 255, 255, 255, 255, 185, 31, 0],
    [0, 196, 255, 255, 255, 255, 255, 255, 255, 255, 195, 0],
    [97, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 97],
    [184, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 184],
    [232, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 232],
    [232, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 232],
    [184, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 184],
    [80, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 80],
    [0, 184, 255, 255, 255, 255, 255, 255, 255, 255, 176, 0],
    [0, 40, 248, 255, 255, 255, 255, 255, 255, 243, 28, 0],
    [0, 0, 0, 93, 173, 229, 229, 173, 93, 0, 0, 0],
];

/// A landed dot edge-on: an ellipse 2 across and 6 high (half widths). Pixels `-2..2` across and `-6..6` down.
pub(super) const EDGE: [[u8; 4]; 12] = [
    [0, 161, 160, 0],
    [80, 255, 255, 72],
    [152, 255, 255, 152],
    [205, 255, 255, 205],
    [232, 255, 255, 232],
    [248, 255, 255, 248],
    [248, 255, 255, 248],
    [232, 255, 255, 232],
    [200, 255, 255, 200],
    [152, 255, 255, 144],
    [96, 255, 255, 88],
    [1, 160, 160, 0],
];

/// An empty socket: a circle of radius 2.5. Pixels `-4..4` across and down.
pub(super) const SOCKET: [[u8; 8]; 8] = [
    [0, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 20, 100, 100, 20, 0, 0],
    [0, 20, 229, 255, 255, 229, 20, 0],
    [0, 104, 255, 255, 255, 255, 112, 0],
    [0, 104, 255, 255, 255, 255, 112, 0],
    [0, 26, 248, 255, 255, 248, 37, 0],
    [0, 0, 30, 100, 100, 30, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 0],
];

/// The round tip of a drip: a circle of radius 3. Pixels `-4..4` across and down. Its upper half is drawn over the drip, so only the way it rounds blue on blue is known there.
pub(super) const TIP: [[u8; 8]; 8] = [
    [0, 0, 0, 0, 0, 0, 0, 0],
    [0, 6, 155, 241, 241, 155, 6, 0],
    [0, 147, 255, 255, 255, 255, 147, 0],
    [0, 240, 255, 255, 255, 255, 240, 0],
    [0, 240, 255, 255, 255, 255, 240, 0],
    [0, 167, 255, 255, 255, 255, 167, 0],
    [0, 24, 162, 232, 232, 162, 24, 0],
    [0, 0, 0, 0, 0, 0, 0, 0],
];

/// The round end of a teardrop: a circle of radius 4. Pixels `-4..4` across and down. Drawn first.
pub(super) const TEAR_ROUND: [[u8; 8]; 8] = [
    [0, 21, 177, 244, 244, 177, 21, 0],
    [80, 240, 255, 255, 255, 255, 240, 80],
    [199, 255, 255, 255, 255, 255, 255, 199],
    [240, 255, 255, 255, 255, 255, 255, 240],
    [240, 255, 255, 255, 255, 255, 255, 240],
    [199, 255, 255, 255, 255, 255, 255, 199],
    [80, 255, 255, 255, 255, 255, 255, 80],
    [0, 76, 196, 239, 239, 196, 76, 0],
];

/// The point of a teardrop: a triangle from 11 above the centre to 2 above it, 3.5 each way at its base. Pixels `-4..4` across and `-11..-2` down. Drawn over the round end.
pub(super) const TEAR_POINT: [[u8; 8]; 9] = [
    [0, 0, 0, 48, 48, 0, 0, 0],
    [0, 0, 0, 144, 144, 0, 0, 0],
    [0, 0, 11, 235, 235, 11, 0, 0],
    [0, 0, 96, 255, 255, 96, 0, 0],
    [0, 0, 192, 255, 255, 192, 0, 0],
    [0, 32, 254, 255, 255, 254, 32, 0],
    [0, 136, 255, 255, 255, 255, 136, 0],
    [5, 240, 255, 255, 255, 255, 240, 5],
    [80, 255, 255, 255, 255, 255, 255, 80],
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drain::look::{
        DOT_R, DRIP_TIP_R, FLIP_EDGE_RX, FLIP_EDGE_RY, FLIP_FACE_R, SOCKET_R, SPOUT_DROP_R,
        TEAR_BASE, TEAR_HALF, TEAR_R, TEAR_TIP,
    };
    use std::f32::consts::PI;

    /// The coverage of a mask, in pixels, and where its weight sits from the mask's first pixel.
    fn weight<const W: usize, const H: usize>(mask: &[[u8; W]; H]) -> (f32, f32, f32) {
        let (mut sum, mut cx, mut cy) = (0.0, 0.0, 0.0);
        for (y, row) in mask.iter().enumerate() {
            for (x, &a) in row.iter().enumerate() {
                let a = f32::from(a) / 255.0;
                sum += a;
                cx += a * (x as f32 + 0.5);
                cy += a * (y as f32 + 0.5);
            }
        }
        (sum, cx / sum, cy / sum)
    }

    /// Checks that a mask covers about the area of its shape and is centred where it should be:
    /// `(left, top)` is where its first pixel lies from the shape's centre.
    fn is_about<const W: usize, const H: usize>(
        mask: &[[u8; W]; H],
        (left, top): (f32, f32),
        area: f32,
        centre: (f32, f32),
    ) {
        let (sum, x, y) = weight(mask);
        assert!(
            (sum - area).abs() <= area * 0.04,
            "covers {sum} pixels, not {area}"
        );
        assert!(
            (x + left - centre.0).abs() < 0.3 && (y + top - centre.1).abs() < 0.3,
            "centred at ({}, {}), not at {centre:?}",
            x + left,
            y + top
        );
    }

    #[test]
    fn the_masks_have_the_area_of_their_shapes_and_stand_on_their_centres() {
        is_about(&DOT, (-6.0, -6.0), PI * DOT_R * DOT_R, (0.0, 0.0));
        assert!(
            (DOT_R - SPOUT_DROP_R).abs() < f32::EPSILON,
            "the drop is a dot"
        );
        is_about(
            &FACE,
            (-6.0, -6.0),
            PI * FLIP_FACE_R * FLIP_FACE_R,
            (0.0, 0.0),
        );
        is_about(
            &EDGE,
            (-2.0, -6.0),
            PI * FLIP_EDGE_RX * FLIP_EDGE_RY,
            (0.0, 0.0),
        );
        is_about(&SOCKET, (-4.0, -4.0), PI * SOCKET_R * SOCKET_R, (0.0, 0.0));
        is_about(&TIP, (-4.0, -4.0), PI * DRIP_TIP_R * DRIP_TIP_R, (0.0, 0.0));
        is_about(&TEAR_ROUND, (-4.0, -4.0), PI * TEAR_R * TEAR_R, (0.0, 0.0));
        // The point is a triangle: its centre is a third of the way up from its base.
        let height = TEAR_TIP - TEAR_BASE;
        is_about(
            &TEAR_POINT,
            (-4.0, -11.0),
            TEAR_HALF * height,
            (0.0, -TEAR_BASE - height / 3.0),
        );
    }

    #[test]
    fn a_dot_is_covered_as_the_browser_covers_it() {
        // The rows the browser gives a dot of radius 5 are not the mirror of each other.
        assert_eq!((DOT[1][5], DOT[10][5]), (239, 224));
        // And a full row is full.
        assert!(DOT[5][2..10].iter().all(|&a| a == 255));
    }
}
