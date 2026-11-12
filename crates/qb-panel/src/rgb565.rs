//! RGBA to RGB565, the screen's pixel format: 2 bytes a pixel, low byte first.
//!
//! Each channel goes to its nearest level, with no dithering: the panel is
//! flat colour and text. The painter and the callers that draw a frame of
//! their own (the calibration screen, the preview's push) share this one
//! conversion.

/// The levels an 8-bit channel goes to in RGB565, as the channel's bits in
/// place: the nearest of `max + 1` levels, moved up by `shift` bits.
const fn levels(max: u32, shift: u32) -> [u16; 256] {
    let mut table = [0; 256];
    let mut channel = 0;
    while channel < 256 {
        // 255 * 63 + 127 is within `u32`, and the result is within `u16`.
        table[channel as usize] = (((channel * max + 127) / 255) << shift) as u16;
        channel += 1;
    }
    table
}

/// Red in RGB565.
const RED: [u16; 256] = levels(31, 11);
/// Green in RGB565.
const GREEN: [u16; 256] = levels(63, 5);
/// Blue in RGB565.
const BLUE: [u16; 256] = levels(31, 0);

/// Converts RGBA pixels into `out`, 2 bytes a pixel, low byte first.
///
/// It stops at the end of the shorter of the two: a trailing partial pixel in
/// `rgba` is ignored, and so is any room in `out` that has no pixel for it.
pub(crate) fn convert_into(rgba: &[u8], out: &mut [u8]) {
    let pixels = rgba.as_chunks::<4>().0;
    for (pixel, packed) in pixels.iter().zip(out.as_chunks_mut::<2>().0.iter_mut()) {
        let value =
            RED[usize::from(pixel[0])] | GREEN[usize::from(pixel[1])] | BLUE[usize::from(pixel[2])];
        *packed = value.to_le_bytes();
    }
}

/// Converts RGBA to RGB565, 2 bytes per pixel, low byte first; a trailing partial pixel is ignored.
///
/// Each channel goes to its nearest level. There is no dithering: the panel
/// is flat colour and text.
#[must_use]
pub fn rgba_to_rgb565(rgba: &[u8]) -> Vec<u8> {
    let mut rgb565 = vec![0; rgba.len() / 4 * 2];
    convert_into(rgba, &mut rgb565);
    rgb565
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rgb565_is_little_endian_and_rounds_to_the_nearest_level() {
        let one = |r, g, b| rgba_to_rgb565(&[r, g, b, 255]);
        assert_eq!(one(0x4a, 0x72, 0xff), [0x9f, 0x4b]); // the accent blue = 0x4b9f
        assert_eq!(one(0xa8, 0xb1, 0xc9), [0x98, 0xa5]); // the muted grey = 0xa598
        assert_eq!(one(255, 255, 255), [0xff, 0xff]);
        assert_eq!(one(0, 0, 0), [0, 0]);
        assert_eq!(one(255, 0, 0), [0x00, 0xf8]);
    }

    #[test]
    fn every_level_is_the_nearest_one() {
        for channel in 0..=255_u16 {
            let nearest = |max: u16| (channel * max + 127) / 255;
            let got = rgba_to_rgb565(&[channel as u8, channel as u8, channel as u8, 255]);
            let got = u16::from_le_bytes([got[0], got[1]]);
            assert_eq!(
                (got >> 11, got >> 5 & 0x3f, got & 0x1f),
                (nearest(31), nearest(63), nearest(31)),
                "{channel}"
            );
        }
    }

    #[test]
    fn rgb565_ignores_a_trailing_partial_pixel() {
        assert!(rgba_to_rgb565(&[]).is_empty());
        assert!(rgba_to_rgb565(&[0xff; 3]).is_empty());
        assert_eq!(rgba_to_rgb565(&[0xff; 7]), [0xff, 0xff]);
        assert_eq!(rgba_to_rgb565(&[0; 9]), [0, 0, 0, 0]);
    }

    #[test]
    fn convert_into_fills_only_what_both_sides_have() {
        let mut out = [0xaa; 6];
        convert_into(&[0xff; 8], &mut out);
        assert_eq!(out, [0xff, 0xff, 0xff, 0xff, 0xaa, 0xaa]);
    }
}
