//! Touch: which control a screen point belongs to, which presses count as
//! taps, the pause switch, and the mapping from raw touch readings to pixels.
//!
//! Times are milliseconds on any clock that does not jump; the caller owns
//! it. Nothing here panics or overflows, whatever the input.

use crate::geometry::{HEIGHT, Rect, WIDTH};
use crate::state::Blocking;

/// Something on the panel that a tap works.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    /// The key that pauses blocking and turns it on again.
    BlockingSwitch,
    /// The alert that covers part of the screen: a tap acknowledges it.
    DismissAlert,
}

/// Where a tap works the key: the key and a margin around it, a little more than the finger needs.
pub const KEY_TARGET: Rect = Rect {
    x: 0,
    y: 212,
    w: 96,
    h: 108,
};

/// Where a tap dismisses the alert: the whole of its card, 344 by 224, standing on the floor. It is live only while the card is shown.
pub const ALERT_TARGET: Rect = Rect {
    x: 128,
    y: 80,
    w: 344,
    h: 224,
};

/// The control at a point of the screen, in pixels from the top left; `None` where a tap does nothing.
///
/// `alert_shown` is whether the alert's card is on the screen: only then does its region count.
/// The two regions do not meet, so no point belongs to both.
#[must_use]
pub fn hit(x: u16, y: u16, alert_shown: bool) -> Option<Control> {
    if KEY_TARGET.contains(x, y) {
        Some(Control::BlockingSwitch)
    } else if alert_shown && ALERT_TARGET.contains(x, y) {
        Some(Control::DismissAlert)
    } else {
        None
    }
}

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

/// The shortest press that counts as a tap, in milliseconds; anything shorter is noise.
pub const MIN_PRESS_MS: u64 = 50;

/// A press that would work a control if it were released now or later.
#[derive(Debug, Clone, Copy)]
struct Press {
    /// The control the press began on and has not left.
    control: Control,
    /// When the finger came down.
    began_ms: u64,
}

/// Turns touch events into taps: a press that begins on a control, stays on it and lasts `MIN_PRESS_MS`.
#[derive(Debug, Clone, Default)]
pub struct TapTracker {
    /// The press a release would turn into a tap. `None` while no finger is
    /// down, and also during a press that began on nothing or was spoilt:
    /// none of the three can fire before the next `Down`.
    press: Option<Press>,
}

impl TapTracker {
    /// Takes the event that happened at `at_ms`; returns the control that was tapped, on the `Up` that completes a tap.
    ///
    /// `alert_shown` is whether the alert's card is on the screen as the event is taken. A press on
    /// the card that is still down when the card goes is spoilt by its next move, as a press that
    /// leaves its control is; the caller drops a tap on a card that is gone.
    #[must_use]
    pub fn feed(&mut self, at_ms: u64, event: TouchEvent, alert_shown: bool) -> Option<Control> {
        match event {
            TouchEvent::Down { x, y } => {
                // Whatever press was under way is dropped: its release was lost.
                self.press = hit(x, y, alert_shown).map(|control| Press {
                    control,
                    began_ms: at_ms,
                });
                None
            }
            TouchEvent::Move { x, y } => {
                // Off its control the press is spoilt for good: coming back does not restore it.
                self.press = self
                    .press
                    .filter(|press| hit(x, y, alert_shown) == Some(press.control));
                None
            }
            TouchEvent::Up => {
                let press = self.press.take()?;
                // A clock that went backwards counts as no time at all.
                let held_ms = at_ms.saturating_sub(press.began_ms);
                (held_ms >= MIN_PRESS_MS).then_some(press.control)
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

    const IN: (u16, u16) = (40, 290);

    fn run(events: &[(u64, TouchEvent)]) -> Vec<Option<Control>> {
        run_with(false, events)
    }

    fn run_with(alert_shown: bool, events: &[(u64, TouchEvent)]) -> Vec<Option<Control>> {
        let mut t = TapTracker::default();
        events
            .iter()
            .map(|&(at, e)| t.feed(at, e, alert_shown))
            .collect()
    }

    #[test]
    fn the_key_is_tapped_at_its_region_and_the_alert_only_when_shown() {
        // The key and its margin, shown or not: its region is (0, 212, 96, 108).
        for alert_shown in [false, true] {
            for (x, y) in [(0, 212), (8, 220), (50, 260), (95, 319), (0, 319)] {
                assert_eq!(hit(x, y, alert_shown), Some(Control::BlockingSwitch));
            }
            for (x, y) in [(96, 290), (50, 211), (127, 250), (240, 40)] {
                assert_eq!(hit(x, y, alert_shown), None, "{x},{y}");
            }
        }
        // The alert's card, (128, 80, 344, 224), counts only while it is on the screen.
        for (x, y) in [(128, 80), (300, 200), (471, 303), (128, 303), (471, 80)] {
            assert_eq!(hit(x, y, true), Some(Control::DismissAlert), "{x},{y}");
            assert_eq!(hit(x, y, false), None, "{x},{y}");
        }
        // Not the cleared field round the card, nor the floor under it.
        for (x, y) in [(127, 80), (128, 79), (472, 200), (300, 304), (124, 200)] {
            assert_eq!(hit(x, y, true), None, "{x},{y}");
        }
        // The two regions share no pixel.
        for x in 0..=u16::try_from(WIDTH).unwrap() {
            for y in 0..=u16::try_from(HEIGHT).unwrap() {
                assert!(!(KEY_TARGET.contains(x, y) && ALERT_TARGET.contains(x, y)));
            }
        }
    }

    #[test]
    fn the_alert_region_is_the_takeovers_area() {
        use crate::drain::look::ALERT;
        let area = (ALERT.x, ALERT.y, ALERT.w, ALERT.h);
        let region = (
            f32::from(ALERT_TARGET.x),
            f32::from(ALERT_TARGET.y),
            f32::from(ALERT_TARGET.w),
            f32::from(ALERT_TARGET.h),
        );
        assert_eq!(area, region);
    }

    #[test]
    fn a_tap_on_the_alert_fires_once_and_only_while_it_is_shown() {
        let down = Down { x: 300, y: 200 };
        assert_eq!(
            run_with(true, &[(1000, down), (1050, Up)]),
            [None, Some(Control::DismissAlert)]
        );
        assert_eq!(run_with(false, &[(1000, down), (1050, Up)]), [None; 2]);
        // Too short to count, as on the key.
        assert_eq!(run_with(true, &[(1000, down), (1049, Up)]), [None; 2]);
        // A press that slides off the card is spoilt.
        assert_eq!(
            run_with(true, &[(0, down), (10, Move { x: 50, y: 200 }), (200, Up)]),
            [None; 3]
        );
        // The card goes while the finger is down: the next move spoils the press.
        let mut tracker = TapTracker::default();
        assert_eq!(tracker.feed(0, down, true), None);
        assert_eq!(tracker.feed(20, Move { x: 301, y: 200 }, false), None);
        assert_eq!(tracker.feed(200, Up, false), None);
    }

    #[test]
    fn a_press_of_fifty_milliseconds_inside_counts_on_release() {
        assert_eq!(
            run(&[(1000, Down { x: 40, y: 290 }), (1050, Up)]),
            [None, Some(Control::BlockingSwitch)]
        );
        assert_eq!(
            run(&[(1000, Down { x: 40, y: 290 }), (1049, Up)]),
            [None, None]
        );
        assert_eq!(
            run(&[
                (0, Down { x: 40, y: 290 }),
                (30, Move { x: 90, y: 300 }),
                (80, Up)
            ])
            .last(),
            Some(&Some(Control::BlockingSwitch))
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
                (120, Up)
            ]),
            [None; 3]
        ); // 20 ms since the second Down
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
        assert_eq!(run(&[(0, down), (1000, down), (1049, Up)]), [None; 3]);
        assert_eq!(
            run(&[(0, down), (1000, down), (1050, Up), (1200, Up)]),
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
            run(&[(max - MIN_PRESS_MS, down), (max, Up)]),
            [None, Some(Control::BlockingSwitch)]
        );
        assert_eq!(run(&[(max, down), (max, Up)]), [None; 2]);
        assert_eq!(run(&[(max, down), (0, Up)]), [None; 2]);
        let corner = Down {
            x: u16::MAX,
            y: u16::MAX,
        };
        assert_eq!(hit(u16::MAX, u16::MAX, false), None);
        assert_eq!(hit(u16::MAX, u16::MAX, true), None);
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
}
