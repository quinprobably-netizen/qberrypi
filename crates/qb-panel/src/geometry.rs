//! What every drawing on the panel shares: the frame's size, the colour type,
//! how a text is set, and the pixel rectangle a tap is tested against. The
//! Drain's own coordinates and palette are in `drain::look`.

/// A colour as red, green and blue.
pub type Rgb = [u8; 3];

/// How heavy a text is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Weight {
    /// The 400 weight.
    Regular,
    /// The 700 weight.
    Bold,
}

/// Where a text's `x` sits in the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Anchor {
    /// `x` is the text's left edge.
    Start,
    /// `x` is the text's centre.
    Middle,
    /// `x` is the text's right edge.
    End,
}

/// Where and how one text is set.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TextSlot {
    /// The x of the anchor point.
    pub x: f32,
    /// The y of the line the letters stand on.
    pub baseline: f32,
    /// Where `x` sits in the text.
    pub anchor: Anchor,
    /// The font size in pixels.
    pub size: f32,
    /// The font weight.
    pub weight: Weight,
    /// The colour of the letters.
    pub color: Rgb,
}

/// A rectangle of whole pixels, for hit-testing taps.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rect {
    /// The leftmost column.
    pub x: u16,
    /// The topmost row.
    pub y: u16,
    /// The width in pixels.
    pub w: u16,
    /// The height in pixels.
    pub h: u16,
}

impl Rect {
    /// Whether the pixel is inside: columns `x..x + w`, rows `y..y + h`, ends excluded.
    pub const fn contains(&self, x: u16, y: u16) -> bool {
        // Subtracting first cannot overflow, where `self.x + self.w` could.
        x >= self.x && x - self.x < self.w && y >= self.y && y - self.y < self.h
    }
}

// The frame.

/// The width of the frame in pixels.
pub const WIDTH: usize = 480;
/// The height of the frame in pixels.
pub const HEIGHT: usize = 320;

// Colours.

/// Values and the lit text.
pub const WHITE: Rgb = [0xff, 0xff, 0xff];
/// Labels and secondary text; the calibration screen's hint.
pub const MUTED: Rgb = [0xa8, 0xb1, 0xc9];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rect_holds_its_first_pixel_and_not_the_one_past_its_end() {
        let r = Rect {
            x: 10,
            y: 20,
            w: 5,
            h: 3,
        };
        for (x, y) in [(10, 20), (14, 22)] {
            assert!(r.contains(x, y), "({x}, {y})");
        }
        for (x, y) in [(9, 20), (10, 19), (15, 20), (10, 23)] {
            assert!(!r.contains(x, y), "({x}, {y})");
        }
    }

    #[test]
    fn a_rect_at_the_corner_of_the_integers_does_not_overflow() {
        let corner = Rect {
            x: u16::MAX - 1,
            y: u16::MAX - 1,
            w: 9,
            h: 9,
        };
        assert!(corner.contains(u16::MAX, u16::MAX) && !corner.contains(0, 0));
        let empty = Rect {
            w: 0,
            h: 0,
            ..corner
        };
        assert!(!empty.contains(corner.x, corner.y));
    }
}
