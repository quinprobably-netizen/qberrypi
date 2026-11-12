//! Which rows of a frame differ from another: the measure of what a screen
//! write costs, because the screen's driver sends one span from the first
//! touched row to the last.

use std::ops::Range;

/// The rows in which `new` differs from `old`, as the first and one past the last, or `None` if it does not.
///
/// The rows between the two may be equal. Slices of different lengths differ in all of `new`'s rows.
/// `old` may be memory that something else writes to while it is read: the range that comes back
/// is then one of rows that existed, never empty or turned round.
///
/// # Panics
///
/// If `stride`, the bytes in a row, is zero.
pub fn changed_rows(old: &[u8], new: &[u8], stride: usize) -> Option<Range<usize>> {
    if old.len() != new.len() {
        return Some(0..new.len().div_ceil(stride));
    }
    let mut rows = old.chunks(stride).zip(new.chunks(stride));
    let first = rows.clone().position(|(was, is)| was != is)?;
    // A last row that differs, as there is a first, unless `old` has changed in between.
    let last = rows
        .rposition(|(was, is)| was != is)
        .map_or(first, |last| last.max(first));
    Some(first..last + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::geometry::{HEIGHT, WIDTH};

    /// How many bytes a frame holds: two for each pixel.
    const FRAME_BYTES: usize = WIDTH * HEIGHT * 2;

    /// How many bytes a row holds.
    const ROW_BYTES: usize = WIDTH * 2;

    #[test]
    fn equal_frames_have_no_rows_that_changed() {
        let frame = vec![0x5a; FRAME_BYTES];
        assert_eq!(changed_rows(&frame, &frame, ROW_BYTES), None);
        assert_eq!(changed_rows(&[], &[], ROW_BYTES), None);
    }

    #[test]
    fn the_rows_that_changed_run_from_the_first_to_the_last_that_differ() {
        let old = vec![0; FRAME_BYTES];
        let with = |bytes: &[usize]| {
            let mut new = old.clone();
            for &at in bytes {
                new[at] = 1;
            }
            changed_rows(&old, &new, ROW_BYTES)
        };
        // One pixel of row 10.
        assert_eq!(with(&[10 * ROW_BYTES + 400]), Some(10..11));
        // Rows 3 and 200, and nothing between them.
        assert_eq!(with(&[3 * ROW_BYTES, 200 * ROW_BYTES + 959]), Some(3..201));
        // The first byte and the last byte of the frame.
        assert_eq!(with(&[0]), Some(0..1));
        assert_eq!(with(&[FRAME_BYTES - 1]), Some(319..320));
        assert_eq!(with(&[0, FRAME_BYTES - 1]), Some(0..320));
    }

    #[test]
    fn rows_of_different_lengths_all_count_as_changed() {
        assert_eq!(changed_rows(&[0; 960], &[0; 1920], ROW_BYTES), Some(0..2));
        assert_eq!(changed_rows(&[0; 1920], &[0; 960], ROW_BYTES), Some(0..1));
        assert_eq!(changed_rows(&[0; 960], &[0; 1000], ROW_BYTES), Some(0..2));
        assert_eq!(changed_rows(&[], &[0; 10], ROW_BYTES), Some(0..1));
    }
}
