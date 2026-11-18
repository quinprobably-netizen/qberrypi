//! Touch: which presses count as taps, the pause switch, and the mapping from raw touch readings to
//! pixels.
//!
//! Times are milliseconds on any clock that does not jump; the caller owns
//! it. Nothing here panics or overflows, whatever the input. What is under a point of the screen is the
//! caller's to say (`os::nav::decide` for the panel OS): the tracker only decides which presses are taps.

use crate::geometry::{HEIGHT, WIDTH};
use crate::state::Blocking;

/// One report of the touch screen, in screen coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchEvent {
    /// A finger came down.
    Down {
        /// The column it came down on.
        x: u16,
        /// The row it came down on.
        y: u16,
    },
    /// The finger moved without lifting.
    Move {
        /// The column it moved to.
        x: u16,
        /// The row it moved to.
        y: u16,
    },
    /// The finger lifted.
    Up,
}

/// The shortest press that counts as a tap, in milliseconds, unless the configuration says another
/// (`[panel] touch_min_press_ms`); anything shorter is noise.
///
/// The driver reads a pen that stays down every few milliseconds, so a press of 20 ms is several
/// of its readings; a stray reading alone is over sooner.
pub const DEFAULT_MIN_PRESS_MS: u64 = 20;

/// A press that would work a target if it were released now or later.
#[derive(Debug, Clone)]
struct Press<T> {
    /// What the press began on and has not left.
    target: T,
    /// Where the finger came down.
    at: (u16, u16),
    /// When the finger came down.
    began_ms: u64,
}

/// Turns touch events into taps: a press that begins on a target, stays on it and lasts the tracker's
/// shortest press (`DEFAULT_MIN_PRESS_MS` unless it is made with another).
///
/// A target is whatever the caller says is under a point: any value that can be compared (the OS's `Tap`
/// of `nav::decide`). Two points are on the same target when the caller's function gives equal targets for
/// them.
#[derive(Debug, Clone)]
pub struct TapTracker<T> {
    /// The press a release would turn into a tap. `None` while no finger is
    /// down, and also during a press that began on nothing or was spoilt:
    /// none of the three can fire before the next `Down`.
    press: Option<Press<T>>,
    /// The shortest press that is a tap, in milliseconds.
    min_press_ms: u64,
}

impl<T> Default for TapTracker<T> {
    /// A tracker whose shortest tap is `DEFAULT_MIN_PRESS_MS`.
    fn default() -> Self {
        Self::new(DEFAULT_MIN_PRESS_MS)
    }
}

impl<T> TapTracker<T> {
    /// A tracker with no press under way whose shortest tap is `min_press_ms` milliseconds.
    #[must_use]
    pub const fn new(min_press_ms: u64) -> Self {
        Self {
            press: None,
            min_press_ms,
        }
    }

    /// Forgets the press under way, if there is one: its release, whenever it comes, taps nothing.
    pub fn cancel(&mut self) {
        self.press = None;
    }
}

impl<T: Clone + PartialEq> TapTracker<T> {
    /// Takes the event that happened at `at_ms`; `target` says what is under a point, `None` for nothing.
    /// On the `Up` that completes a tap it gives the target the press began on and the point it came
    /// down at, which the caller hands to `nav::tap`.
    ///
    /// A press that began on nothing is not tracked. One that moves off its target is spoilt for good:
    /// coming back does not restore it. A press shorter than the tracker's shortest tap is noise. The target is
    /// decided at the press; `target` is asked again at every move, so a target that goes away while
    /// the finger is down (the gate ask, once it has closed) spoils the press at its next move.
    #[must_use]
    pub fn feed_with(
        &mut self,
        at_ms: u64,
        event: TouchEvent,
        target: impl Fn(u16, u16) -> Option<T>,
    ) -> Option<(T, (u16, u16))> {
        match event {
            TouchEvent::Down { x, y } => {
                // Whatever press was under way is dropped: its release was lost.
                self.press = target(x, y).map(|target| Press {
                    target,
                    at: (x, y),
                    began_ms: at_ms,
                });
                None
            }
            TouchEvent::Move { x, y } => {
                // Off its target the press is spoilt for good: coming back does not restore it.
                self.press = self
                    .press
                    .take()
                    .filter(|press| target(x, y).as_ref() == Some(&press.target));
                None
            }
            TouchEvent::Up => {
                let press = self.press.take()?;
                // A clock that went backwards counts as no time at all.
                let held_ms = at_ms.saturating_sub(press.began_ms);
                (held_ms >= self.min_press_ms).then_some((press.target, press.at))
            }
        }
    }
}

/// How long one tap pauses blocking, in milliseconds: five minutes.
pub const PAUSE_MS: u64 = 300_000;

/// The milliseconds in a second.
const MS_PER_SECOND: u64 = 1000;

/// The pause switch. It lives in memory only, so a pause never outlives a reboot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Switch {
    /// Blocking is on.
    #[default]
    On,
    /// Blocking is paused until this time in milliseconds; from then on it is on again.
    PausedUntil(u64),
}

impl Switch {
    /// The milliseconds of pause still to run at `now_ms`; `None` when blocking is on, a pause that is over included.
    fn pause_left_ms(self, now_ms: u64) -> Option<u64> {
        match self {
            Switch::On => None,
            Switch::PausedUntil(until) => until.checked_sub(now_ms).filter(|&left| left != 0),
        }
    }

    /// The switch after a tap at `now_ms`: a running pause ends, anything else starts a pause of `PAUSE_MS`.
    #[must_use = "the switch after the tap is the return value"]
    pub fn tapped(self, now_ms: u64) -> Switch {
        match self.pause_left_ms(now_ms) {
            Some(_) => Switch::On,
            None => Switch::PausedUntil(now_ms.saturating_add(PAUSE_MS)),
        }
    }

    /// What the panel shows at `now_ms`: on, or paused with the time left rounded up to whole seconds, `u16::MAX` at most.
    #[must_use]
    pub fn blocking(self, now_ms: u64) -> Blocking {
        match self.pause_left_ms(now_ms) {
            None => Blocking::On,
            Some(left_ms) => Blocking::Paused {
                left_secs: u16::try_from(left_ms.div_ceil(MS_PER_SECOND)).unwrap_or(u16::MAX),
            },
        }
    }
}

/// How the raw readings of the touch controller lie on the screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Calibration {
    /// Whether the two raw readings are exchanged before anything else.
    pub swap_xy: bool,
    /// The horizontal reading at the screen's left edge.
    pub left: u16,
    /// The horizontal reading at the screen's right edge; less than `left` on an axis that runs backwards.
    pub right: u16,
    /// The vertical reading at the screen's top edge.
    pub top: u16,
    /// The vertical reading at the screen's bottom edge; less than `top` on an axis that runs backwards.
    pub bottom: u16,
}

impl Calibration {
    /// A typical panel, unmeasured: the four readings are to be replaced by ones taken at the corners of the real screen.
    ///
    /// `swap_xy` is `false` by this reasoning: the `piscreen` overlay marks
    /// the touch axes as swapped, which lines `ABS_X` up with the panel's long
    /// side, and with `rotate=90` or `rotate=270` the display driver only exchanges rows and
    /// columns, so on this screen `ABS_X` runs along the 480-pixel side.
    /// Which way each axis counts depends on the individual panel, so the
    /// four readings are unmeasured until taken on the real screen.
    pub const NOMINAL: Calibration = Calibration {
        swap_xy: false,
        left: 200,
        right: 3900,
        top: 200,
        bottom: 3900,
    };
}

/// The last pixel along a side of the frame; a side that is empty or too long for a `u16` does not compile.
const fn last_pixel(side: usize) -> u16 {
    assert!(side >= 1 && side - 1 <= u16::MAX as usize);
    (side - 1) as u16
}

/// The rightmost column of the screen.
const LAST_X: u16 = last_pixel(WIDTH);
/// The bottom row of the screen.
const LAST_Y: u16 = last_pixel(HEIGHT);

/// The pixel under a raw reading: `raw_x` and `raw_y` are the `ABS_X` and `ABS_Y` of the `ads7846` driver; off the screen is clamped onto it.
///
/// A reading outside the calibrated range is clamped onto the screen's edge,
/// so every reading lands on some pixel, and the bottom-left corner is
/// inside the switch's target: with `Calibration::NOMINAL` the raw readings
/// (0, 4095) and (0, 65535) both give (0, 319). Nothing here can tell such a
/// reading from a touch: the caller must drop pen-up and low-pressure
/// samples before calling.
#[must_use]
pub fn to_screen(cal: &Calibration, raw_x: u16, raw_y: u16) -> (u16, u16) {
    let (h, v) = if cal.swap_xy {
        (raw_y, raw_x)
    } else {
        (raw_x, raw_y)
    };
    (
        axis(h, cal.left, cal.right, LAST_X),
        axis(v, cal.top, cal.bottom, LAST_Y),
    )
}

/// One axis: the pixel of `raw` where the reading `first` is pixel 0 and the reading `end` is pixel `last`; equal ends give 0.
fn axis(raw: u16, first: u16, end: u16, last: u16) -> u16 {
    let span = i64::from(end) - i64::from(first);
    if span == 0 {
        return 0;
    }
    // Every term below stays under 2^34 in size, whatever four `u16`s come in: an `i64` cannot overflow.
    let offset = (i64::from(raw) - i64::from(first)) * i64::from(last);
    // The same quotient over a positive divisor, so that the dividend alone carries the sign.
    let (offset, span) = (offset * span.signum(), span.abs());
    // To the nearest pixel, halves away from zero: half the divisor is added on the dividend's side of zero
    // (both doubled, so that an odd divisor has an exact half) and the division truncates towards zero.
    let pixel = (2 * offset + offset.signum() * span) / (2 * span);
    // Clamped onto the screen, the pixel fits a `u16`; the conversion cannot fail.
    u16::try_from(pixel.clamp(0, i64::from(last))).unwrap_or(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use TouchEvent::{Down, Move, Up};

    use crate::geometry::Rect;

    const IN: (u16, u16) = (40, 290);

    /// A target for these tests: one key in the screen's lower left corner, the place of the Drain's key
    /// and its margin, `(0, 212, 96, 108)`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Control {
        BlockingSwitch,
    }

    /// The key's place.
    const KEY_TARGET: Rect = Rect {
        x: 0,
        y: 212,
        w: 96,
        h: 108,
    };

    /// The target at a point; `None` where a tap does nothing.
    fn hit(x: u16, y: u16) -> Option<Control> {
        KEY_TARGET.contains(x, y).then_some(Control::BlockingSwitch)
    }

    /// The press point of a tap is not what these tests look at: only whether, and on what, a tap landed.
    fn run(events: &[(u64, TouchEvent)]) -> Vec<Option<Control>> {
        let mut t = TapTracker::default();
        events
            .iter()
            .map(|&(at, e)| t.feed_with(at, e, hit).map(|(control, _)| control))
            .collect()
    }

    #[test]
    fn the_key_is_tapped_at_its_region() {
        // The key and its margin: its region is (0, 212, 96, 108).
        for (x, y) in [(0, 212), (8, 220), (50, 260), (95, 319), (0, 319)] {
            assert_eq!(hit(x, y), Some(Control::BlockingSwitch));
        }
        for (x, y) in [(96, 290), (50, 211), (127, 250), (240, 40), (300, 200)] {
            assert_eq!(hit(x, y), None, "{x},{y}");
        }
    }

    /// What a tracker whose shortest tap is `min_press_ms` gives for `events`, as `run` says it.
    fn run_with(min_press_ms: u64, events: &[(u64, TouchEvent)]) -> Vec<Option<Control>> {
        let mut t = TapTracker::new(min_press_ms);
        events
            .iter()
            .map(|&(at, e)| t.feed_with(at, e, hit).map(|(control, _)| control))
            .collect()
    }

    #[test]
    fn a_press_of_twenty_milliseconds_inside_counts_on_release() {
        assert_eq!(DEFAULT_MIN_PRESS_MS, 20);
        assert_eq!(
            run(&[(1000, Down { x: 40, y: 290 }), (1020, Up)]),
            [None, Some(Control::BlockingSwitch)]
        );
        assert_eq!(
            run(&[(1000, Down { x: 40, y: 290 }), (1019, Up)]),
            [None, None]
        );
        assert_eq!(
            run(&[
                (0, Down { x: 40, y: 290 }),
                (10, Move { x: 90, y: 300 }),
                (30, Up)
            ])
            .last(),
            Some(&Some(Control::BlockingSwitch))
        );
    }

    #[test]
    fn a_tracker_made_with_another_shortest_tap_holds_to_it() {
        let press = |held| [(1000, Down { x: 40, y: 290 }), (1000 + held, Up)];
        for min in [0, 5, 50, 500] {
            assert_eq!(
                run_with(min, &press(min)),
                [None, Some(Control::BlockingSwitch)],
                "{min}"
            );
            if min > 0 {
                assert_eq!(run_with(min, &press(min - 1)), [None, None], "{min}");
            }
        }
        // The default tracker is the one made with the default.
        assert_eq!(run_with(DEFAULT_MIN_PRESS_MS, &press(19)), run(&press(19)));
        assert_eq!(run_with(DEFAULT_MIN_PRESS_MS, &press(20)), run(&press(20)));
        // Whatever its shortest tap, a press that left its target stays spoilt.
        assert_eq!(
            run_with(
                5,
                &[
                    (0, Down { x: IN.0, y: IN.1 }),
                    (10, Move { x: 300, y: 290 }),
                    (20, Move { x: IN.0, y: IN.1 }),
                    (900, Up)
                ]
            ),
            [None; 4]
        );
    }

    #[test]
    fn a_cancelled_press_taps_nothing_and_the_next_press_is_whole() {
        let mut t = TapTracker::new(DEFAULT_MIN_PRESS_MS);
        assert_eq!(t.feed_with(0, Down { x: IN.0, y: IN.1 }, hit), None);
        t.cancel();
        assert_eq!(t.feed_with(500, Up, hit), None);
        assert_eq!(t.feed_with(600, Down { x: IN.0, y: IN.1 }, hit), None);
        assert_eq!(
            t.feed_with(620, Up, hit).map(|(control, _)| control),
            Some(Control::BlockingSwitch)
        );
    }

    #[test]
    fn a_brushed_edge_does_nothing() {
        let out = Move { x: 300, y: 290 };
        let back = Move { x: IN.0, y: IN.1 };
        assert_eq!(
            run(&[
                (0, Down { x: IN.0, y: IN.1 }),
                (20, out),
                (40, back),
                (200, Up)
            ]),
            [None; 4]
        ); // left and returned
        assert_eq!(
            run(&[(0, Down { x: 300, y: 100 }), (10, back), (200, Up)]),
            [None; 3]
        ); // slid in from outside
    }

    #[test]
    fn a_lost_release_and_a_stray_one_do_nothing() {
        assert_eq!(run(&[(5, Up), (6, Move { x: IN.0, y: IN.1 })]), [None; 2]);
        assert_eq!(
            run(&[
                (0, Down { x: IN.0, y: IN.1 }),
                (100, Down { x: IN.0, y: IN.1 }),
                (119, Up)
            ]),
            [None; 3]
        ); // 19 ms since the second Down
        assert_eq!(
            run(&[(500, Down { x: IN.0, y: IN.1 }), (100, Up)]),
            [None; 2]
        ); // the clock went backwards
    }

    #[test]
    fn a_tap_pauses_for_five_minutes_and_the_pause_ends_by_itself() {
        let s = Switch::On.tapped(10_000);
        assert_eq!(s, Switch::PausedUntil(310_000));
        for (now, left) in [(10_000, 300), (10_001, 300), (11_000, 299), (309_999, 1)] {
            assert_eq!(s.blocking(now), Blocking::Paused { left_secs: left });
        }
        assert_eq!(
            (
                s.blocking(310_000),
                s.blocking(999_999),
                Switch::On.blocking(0)
            ),
            (Blocking::On, Blocking::On, Blocking::On)
        );
    }

    #[test]
    fn a_tap_while_paused_resumes_and_a_tap_after_the_end_pauses_again() {
        assert_eq!(Switch::PausedUntil(310_000).tapped(20_000), Switch::On);
        assert_eq!(
            Switch::PausedUntil(310_000).tapped(310_000),
            Switch::PausedUntil(610_000)
        );
        assert_eq!(Switch::default(), Switch::On);
    }

    #[test]
    fn calibration_maps_raw_readings_onto_the_rotated_screen() {
        let n = Calibration::NOMINAL;
        assert_eq!(
            (
                to_screen(&n, 200, 200),
                to_screen(&n, 3900, 3900),
                to_screen(&n, 1125, 2975)
            ),
            ((0, 0), (479, 319), (120, 239))
        );
        assert_eq!(
            (to_screen(&n, 0, 4095), to_screen(&n, 4095, 0)),
            ((0, 319), (479, 0))
        ); // clamped
        let backwards = Calibration {
            swap_xy: false,
            left: 3900,
            right: 200,
            top: 3900,
            bottom: 200,
        };
        assert_eq!(
            (
                to_screen(&backwards, 3900, 3900),
                to_screen(&backwards, 200, 200),
                to_screen(&backwards, 1125, 2975)
            ),
            ((0, 0), (479, 319), (359, 80))
        );
        let swapped = Calibration {
            swap_xy: true,
            ..Calibration::NOMINAL
        };
        assert_eq!(to_screen(&swapped, 2975, 1125), (120, 239));
        let flat = Calibration {
            left: 500,
            right: 500,
            top: 500,
            bottom: 500,
            swap_xy: false,
        };
        assert_eq!(to_screen(&flat, 2000, 2000), (0, 0));
    }

    // Not in the plan: a press that begins off the switch and slides onto it never fires,
    // however long it then rests there.
    #[test]
    fn a_press_that_starts_outside_and_slides_in_never_fires() {
        let inside = Move { x: IN.0, y: IN.1 };
        assert_eq!(
            run(&[
                (0, Down { x: 300, y: 100 }),
                (10, inside),
                (5_000, inside),
                (60_000, Up)
            ]),
            [None; 4]
        );
        // One pixel right of the key's region, then one pixel in.
        assert_eq!(
            run(&[
                (0, Down { x: 96, y: 290 }),
                (10, Move { x: 95, y: 290 }),
                (200, Up)
            ]),
            [None; 3]
        );
    }

    // Not in the plan: a spoilt press stays spoilt until the next Down, and the next press is whole again.
    #[test]
    fn a_press_that_leaves_and_returns_is_spoilt_until_the_next_down() {
        let down = Down { x: IN.0, y: IN.1 };
        let out = Move { x: 96, y: 290 };
        let back = Move { x: 95, y: 290 };
        assert_eq!(
            run(&[
                (0, down),
                (20, out),
                (40, back),
                (60, out),
                (80, back),
                (200, Up),    // the spoilt press ends without a tap
                (210, back),  // idle: a Move starts nothing
                (400, Up),    // and a second release has nothing to fire
                (1000, down), // a new press is whole again
                (1050, Up)
            ]),
            [
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(Control::BlockingSwitch)
            ]
        );
    }

    // Not in the plan: a press whose release never arrives is dropped by the next Down, wherever that lands.
    #[test]
    fn a_press_whose_release_never_arrives_never_fires() {
        let down = Down { x: IN.0, y: IN.1 };
        // The second press lands off the switch: its release fires nothing, though the first began 2 s earlier.
        assert_eq!(
            run(&[(0, down), (1000, Down { x: 300, y: 100 }), (2000, Up)]),
            [None; 3]
        );
        // The second press lands on the switch: it is timed from its own Down and fires once.
        assert_eq!(run(&[(0, down), (1000, down), (1019, Up)]), [None; 3]);
        assert_eq!(
            run(&[(0, down), (1000, down), (1020, Up), (1200, Up)]),
            [None, None, Some(Control::BlockingSwitch), None]
        );
    }

    // Not in the plan: the pause is over at `until` itself, so a tap in that millisecond pauses anew.
    #[test]
    fn a_tap_at_the_millisecond_the_pause_ends_starts_a_new_pause() {
        let s = Switch::On.tapped(0);
        assert_eq!(s, Switch::PausedUntil(PAUSE_MS));
        assert_eq!(
            (s.blocking(PAUSE_MS - 1), s.tapped(PAUSE_MS - 1)),
            (Blocking::Paused { left_secs: 1 }, Switch::On)
        );
        assert_eq!(
            (s.blocking(PAUSE_MS), s.tapped(PAUSE_MS)),
            (Blocking::On, Switch::PausedUntil(2 * PAUSE_MS))
        );
        assert_eq!(
            s.tapped(PAUSE_MS).blocking(PAUSE_MS),
            Blocking::Paused { left_secs: 300 }
        );
    }

    // Not in the plan: halves round away from zero, on an axis that runs either way.
    #[test]
    fn a_reading_halfway_between_two_pixels_rounds_up() {
        // 958 readings over 479 pixels: every odd reading is a half.
        let forwards = Calibration {
            swap_xy: false,
            left: 0,
            right: 958,
            top: 0,
            bottom: 638,
        };
        assert_eq!(
            [0, 1, 2, 3, 957, 958].map(|raw| to_screen(&forwards, raw, raw).0),
            [0, 1, 1, 2, 479, 479]
        );
        assert_eq!(
            [0, 1, 2, 3, 637, 638].map(|raw| to_screen(&forwards, raw, raw).1),
            [0, 1, 1, 2, 319, 319]
        );
        let backwards = Calibration {
            swap_xy: false,
            left: 958,
            right: 0,
            top: 638,
            bottom: 0,
        };
        assert_eq!(
            [958, 957, 956, 955, 1, 0].map(|raw| to_screen(&backwards, raw, raw).0),
            [0, 1, 1, 2, 479, 479]
        );
        assert_eq!(
            [638, 637, 636, 635, 1, 0].map(|raw| to_screen(&backwards, raw, raw).1),
            [0, 1, 1, 2, 319, 319]
        );
    }

    // Not in the plan: no input panics or overflows, and each extreme has the result the rules give it.
    #[test]
    fn every_input_has_a_defined_result() {
        let max = u64::MAX;
        let down = Down { x: IN.0, y: IN.1 };

        // The tracker: no upper limit on a press, a clock at its end, a clock that fell back to 0.
        assert_eq!(
            run(&[(0, down), (max, Up)]),
            [None, Some(Control::BlockingSwitch)]
        );
        assert_eq!(
            run(&[(max - DEFAULT_MIN_PRESS_MS, down), (max, Up)]),
            [None, Some(Control::BlockingSwitch)]
        );
        assert_eq!(run(&[(max, down), (max, Up)]), [None; 2]);
        assert_eq!(run(&[(max, down), (0, Up)]), [None; 2]);
        let corner = Down {
            x: u16::MAX,
            y: u16::MAX,
        };
        assert_eq!(hit(u16::MAX, u16::MAX), None);
        assert_eq!(
            run(&[
                (0, corner),
                (
                    1,
                    Move {
                        x: u16::MAX,
                        y: u16::MAX
                    }
                ),
                (max, Up)
            ]),
            [None; 3]
        );

        // The switch: the end of a pause saturates instead of wrapping round to the past.
        assert_eq!(Switch::On.tapped(max), Switch::PausedUntil(max));
        assert_eq!(Switch::On.tapped(max - 1), Switch::PausedUntil(max));
        assert_eq!(Switch::On.tapped(max - PAUSE_MS), Switch::PausedUntil(max));
        assert_eq!(
            Switch::PausedUntil(max).blocking(max - 1),
            Blocking::Paused { left_secs: 1 }
        );
        assert_eq!(
            (
                Switch::PausedUntil(max).blocking(max),
                Switch::PausedUntil(max).tapped(max)
            ),
            (Blocking::On, Switch::PausedUntil(max))
        );
        assert_eq!(
            (
                Switch::PausedUntil(0).blocking(0),
                Switch::PausedUntil(0).tapped(0)
            ),
            (Blocking::On, Switch::PausedUntil(PAUSE_MS))
        );
        // A pause far in the future: the seconds left stop at `u16::MAX`, and a tap still resumes.
        assert_eq!(
            Switch::PausedUntil(max).blocking(0),
            Blocking::Paused {
                left_secs: u16::MAX
            }
        );
        assert_eq!(Switch::PausedUntil(max).tapped(0), Switch::On);
        let secs = |until| match Switch::PausedUntil(until).blocking(0) {
            Blocking::Paused { left_secs } => Some(left_secs),
            Blocking::On => None,
        };
        assert_eq!(
            [
                1, 65_534_000, 65_534_001, 65_535_000, 65_535_001, 65_536_000
            ]
            .map(secs),
            [
                Some(1),
                Some(65_534),
                Some(65_535),
                Some(65_535),
                Some(65_535),
                Some(65_535)
            ]
        );

        // Calibration: the widest span, both ways, and the narrowest.
        let cal = |left, right| Calibration {
            swap_xy: false,
            left,
            right,
            top: left,
            bottom: right,
        };
        let ends =
            |c: Calibration| [0, 1, u16::MAX - 1, u16::MAX].map(|raw| to_screen(&c, raw, raw));
        assert_eq!(
            ends(cal(0, u16::MAX)),
            [(0, 0), (0, 0), (479, 319), (479, 319)]
        );
        assert_eq!(
            ends(cal(u16::MAX, 0)),
            [(479, 319), (479, 319), (0, 0), (0, 0)]
        );
        assert_eq!(
            ends(cal(0, 1)),
            [(0, 0), (479, 319), (479, 319), (479, 319)]
        );
        assert_eq!(ends(cal(1, 0)), [(479, 319), (0, 0), (0, 0), (0, 0)]);
        assert_eq!(
            ends(cal(u16::MAX - 1, u16::MAX)),
            [(0, 0), (0, 0), (0, 0), (479, 319)]
        );
        for flat in [0, 1, u16::MAX] {
            assert_eq!(ends(cal(flat, flat)), [(0, 0); 4]);
        }
        // Every result is on the screen, whatever the four ends and the reading.
        let edge = [
            0,
            1,
            200,
            3900,
            4095,
            32_767,
            32_768,
            u16::MAX - 1,
            u16::MAX,
        ];
        for swap_xy in [false, true] {
            for left in edge {
                for right in edge {
                    let c = Calibration {
                        swap_xy,
                        left,
                        right,
                        top: right,
                        bottom: left,
                    };
                    for raw_x in edge {
                        for raw_y in edge {
                            let (x, y) = to_screen(&c, raw_x, raw_y);
                            assert!(usize::from(x) < WIDTH && usize::from(y) < HEIGHT);
                        }
                    }
                }
            }
        }
    }

    // The tracker is generic: any target a caller can compare, and the press point comes back with it.
    #[test]
    fn a_tracker_of_any_target_yields_the_target_and_where_the_finger_came_down() {
        // Two halves of the screen are the targets 1 and 2; a strip at the top is nothing.
        let target = |x: u16, y: u16| (y >= 20).then_some(if x < 240 { 1_u8 } else { 2 });
        let mut tracker: TapTracker<u8> = TapTracker::default();
        let mut feed = |at, event| tracker.feed_with(at, event, target);
        assert_eq!(feed(0, Down { x: 10, y: 100 }), None);
        assert_eq!(feed(60, Move { x: 200, y: 300 }), None);
        assert_eq!(
            feed(80, Up),
            Some((1, (10, 100))),
            "the point of the press, not of the release"
        );
        // Sliding onto the other target spoils it; so does a press that begins on nothing.
        assert_eq!(feed(100, Down { x: 10, y: 100 }), None);
        assert_eq!(feed(110, Move { x: 300, y: 100 }), None);
        assert_eq!(feed(200, Up), None);
        assert_eq!(feed(300, Down { x: 10, y: 5 }), None);
        assert_eq!(feed(400, Up), None);
        // Twenty milliseconds, as for the Drain's key.
        assert_eq!(feed(500, Down { x: 300, y: 100 }), None);
        assert_eq!(feed(519, Up), None);
        assert_eq!(feed(600, Down { x: 300, y: 100 }), None);
        assert_eq!(feed(620, Up), Some((2, (300, 100))));
        // A lost release: the next press begins again, from its own time.
        assert_eq!(feed(700, Down { x: 300, y: 100 }), None);
        assert_eq!(feed(1_000, Down { x: 10, y: 100 }), None);
        assert_eq!(feed(1_019, Up), None);
    }
}
