//! Measuring the touch screen: four crosses to tap, and the calibration the taps give.
//!
//! [`calibrate`] shows a cross at each of the four [`TARGETS`] and waits for a
//! tap on it. A [`Collector`] turns the touch device's events into one
//! [`Reading`] for each tap, [`solve`] turns the four readings into a
//! [`Calibration`], and [`toml_lines`] writes it as the `[panel]` table of
//! `qberrypi.toml`. Nothing is written anywhere: the result is logged, for
//! its owner to put into the file.

use std::io;
use std::ops::RangeInclusive;

use qb_panel::geometry::{Anchor, MUTED, TextSlot, WHITE, Weight};
use qb_panel::text::draw_text;
use qb_panel::{Calibration, HEIGHT, WIDTH, rgba_to_rgb565};

use super::Surface;
use super::touch::{
    ABS_PRESSURE, ABS_X, ABS_Y, BTN_TOUCH, EV_ABS, EV_KEY, EV_SYN, MIN_PRESSURE, RawEvent,
    SYN_DROPPED, SYN_REPORT, hold,
};

/// Where the four crosses are, in screen pixels, in the order they are tapped.
///
/// They are the corners of a rectangle that lies `MARGIN` pixels inside the screen's edges.
pub const TARGETS: [(u16, u16); 4] = [(40, 40), (439, 40), (439, 279), (40, 279)];

/// How long a cross is waited for, in milliseconds, before the calibration is given up.
pub const TARGET_WAIT_MS: u64 = 60_000;

/// How long one wait for the touch device lasts, in milliseconds, before the clock is looked at.
const POLL_MS: u64 = 100;

/// How far the targets lie inside the screen's edges, in pixels.
const MARGIN: i32 = 40;
/// The distance between the two columns of targets, in pixels.
const SPAN_X: i32 = 399;
/// The distance between the two rows of targets, in pixels.
const SPAN_Y: i32 = 239;

/// How many reports a press needs to be a reading: fewer is a brush, or a pen that bounced.
const MIN_REPORTS: usize = 3;

/// The least distance between the two sides of targets, in the controller's units.
///
/// Less is a screen that was not tapped at the crosses: a calibration made
/// from it would spread a few units over the whole screen.
const MIN_SPAN: i32 = 1_000;

/// How far a cross reaches from its middle, in pixels.
const CROSS_ARM: usize = 14;

/// The first line of the cue, in the middle of the screen.
const CUE: TextSlot = TextSlot {
    x: 240.0,
    baseline: 156.0,
    anchor: Anchor::Middle,
    size: 22.0,
    weight: Weight::Bold,
    color: WHITE,
};

/// The second line of the cue: which of the crosses this is.
const COUNT: TextSlot = TextSlot {
    x: 240.0,
    baseline: 186.0,
    anchor: Anchor::Middle,
    size: 17.0,
    weight: Weight::Regular,
    color: MUTED,
};

/// Paints the pixels in `columns` and `rows` white; all of them must be on the screen.
fn paint(rgba: &mut [u8], columns: RangeInclusive<usize>, rows: RangeInclusive<usize>) {
    for row in rows {
        for column in columns.clone() {
            let at = (row * WIDTH + column) * 4;
            rgba[at..at + 4].copy_from_slice(&[0xff; 4]);
        }
    }
}

/// The screen that asks for a tap on target `index`, as RGB565: 307,200 bytes.
///
/// It is black, with a white cross at the target, two pixels thick, and the
/// words `Tap the cross` and `{index + 1} of 4` in the middle.
///
/// # Panics
///
/// If `index` is not one of the four targets.
#[must_use]
pub fn target_frame(index: usize) -> Vec<u8> {
    let (x, y) = TARGETS[index];
    let (x, y) = (usize::from(x), usize::from(y));
    let mut rgba = [0, 0, 0, 0xff].repeat(WIDTH * HEIGHT);
    // The cross is a block of two by two pixels with an arm of `CROSS_ARM` pixels on each side.
    let (left, top) = (
        x.saturating_sub(CROSS_ARM + 1),
        y.saturating_sub(CROSS_ARM + 1),
    );
    paint(&mut rgba, left..=x + CROSS_ARM, y.saturating_sub(1)..=y);
    paint(&mut rgba, x.saturating_sub(1)..=x, top..=y + CROSS_ARM);
    draw_text(&mut rgba, &CUE, "Tap the cross");
    draw_text(&mut rgba, &COUNT, &format!("{} of 4", index + 1));
    rgba_to_rgb565(&rgba)
}

/// One tap as the touch controller read it, before any calibration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading {
    /// The `ABS_X` reading.
    pub raw_x: u16,
    /// The `ABS_Y` reading.
    pub raw_y: u16,
}

/// Turns the touch device's events into one [`Reading`] for each press.
///
/// It follows `BTN_TOUCH`, `ABS_X`, `ABS_Y` and `ABS_PRESSURE` as the
/// touch decoder does, but in the controller's own units. Each report with
/// the glass touched is a sample unless a pressure was reported and the last
/// one is under `MIN_PRESSURE`: the pen on its way up or down reads a point
/// that is not where the finger is. The report that releases ends the press,
/// and the press is the median of its samples, each axis on its own, so that
/// a stray sample moves nothing.
#[derive(Debug, Default)]
pub struct Collector {
    /// The last horizontal reading.
    raw_x: u16,
    /// The last vertical reading.
    raw_y: u16,
    /// The last pressure reading, if there ever was one.
    pressure: Option<i32>,
    /// Whether `BTN_TOUCH` is pressed as of the last event.
    button: bool,
    /// The samples of the press that is under way.
    samples: Vec<Reading>,
}

impl Collector {
    /// Takes the next event; returns the reading of the press that it ends.
    ///
    /// A press of fewer than three samples is no reading. Lost events cancel
    /// the press, and a finger that rests on the glass makes no press until it
    /// lifts and presses again.
    pub fn feed(&mut self, event: RawEvent) -> Option<Reading> {
        match (event.kind, event.code) {
            (EV_ABS, ABS_X) => self.raw_x = hold(event.value),
            (EV_ABS, ABS_Y) => self.raw_y = hold(event.value),
            (EV_ABS, ABS_PRESSURE) => self.pressure = Some(event.value),
            (EV_KEY, BTN_TOUCH) => self.button = event.value != 0,
            (EV_SYN, SYN_REPORT) => return self.report(),
            (EV_SYN, SYN_DROPPED) => {
                self.button = false;
                self.samples.clear();
            }
            _ => {}
        }
        None
    }

    /// What the end of a report gives out: a sample while the glass is touched, the reading when it is not.
    fn report(&mut self) -> Option<Reading> {
        if self.button {
            if self
                .pressure
                .is_none_or(|pressure| pressure >= MIN_PRESSURE)
            {
                self.samples.push(Reading {
                    raw_x: self.raw_x,
                    raw_y: self.raw_y,
                });
            }
            return None;
        }
        median(&std::mem::take(&mut self.samples))
    }
}

/// The middle of each axis of `samples`, taken apart; `None` for fewer than three samples.
fn median(samples: &[Reading]) -> Option<Reading> {
    if samples.len() < MIN_REPORTS {
        return None;
    }
    let middle = |axis: fn(&Reading) -> u16| {
        let mut values: Vec<u16> = samples.iter().map(axis).collect();
        values.sort_unstable();
        values[values.len() / 2]
    };
    Some(Reading {
        raw_x: middle(|sample| sample.raw_x),
        raw_y: middle(|sample| sample.raw_y),
    })
}

/// `numerator / divisor` to the nearest whole number, halves away from zero; `divisor` is above 0.
fn div_round(numerator: i32, divisor: i32) -> i32 {
    (2 * numerator + numerator.signum() * divisor) / (2 * divisor)
}

/// The calibration that makes the four readings, taken at `TARGETS` in order, the four targets.
///
/// The axes are exchanged when the reading that moves between targets 0 and 1,
/// which differ only in screen x, is `ABS_Y`. The readings of each side are
/// averaged, and the edges of the screen lie `MARGIN` pixels beyond them, so
/// the edges are the sides extended in proportion.
///
/// Refused, with the reason, when the taps cannot have been the four crosses:
/// when two sides of them lie less than `MIN_SPAN` apart, and when the two
/// readings of a side differ by more than a quarter of the distance between
/// the sides.
pub fn solve(readings: &[Reading; 4]) -> Result<Calibration, &'static str> {
    let x = readings.map(|reading| i32::from(reading.raw_x));
    let y = readings.map(|reading| i32::from(reading.raw_y));
    let swap_xy = (x[1] - x[0]).abs() < (y[1] - y[0]).abs();
    // `h` runs along the screen's x, `v` along its y.
    let (h, v) = if swap_xy { (y, x) } else { (x, y) };
    let (h_l, h_r) = ((h[0] + h[3]) / 2, (h[1] + h[2]) / 2);
    let (v_t, v_b) = ((v[0] + v[1]) / 2, (v[2] + v[3]) / 2);
    let (h_span, v_span) = (h_r - h_l, v_b - v_t);
    if h_span.abs() < MIN_SPAN || v_span.abs() < MIN_SPAN {
        return Err("the four readings are too close together");
    }
    let straight = |a: i32, b: i32, span: i32| (a - b).abs() * 4 <= span.abs();
    if !(straight(h[0], h[3], h_span)
        && straight(h[1], h[2], h_span)
        && straight(v[0], v[1], v_span)
        && straight(v[2], v[3], v_span))
    {
        return Err("the readings do not form a rectangle");
    }
    let beyond_h = div_round(MARGIN * h_span, SPAN_X);
    let beyond_v = div_round(MARGIN * v_span, SPAN_Y);
    Ok(Calibration {
        swap_xy,
        left: hold(h_l - beyond_h),
        right: hold(h_r + beyond_h),
        top: hold(v_t - beyond_v),
        bottom: hold(v_b + beyond_v),
    })
}

/// The `[panel]` table of `qberrypi.toml` that says `calibration`, a line each.
#[must_use]
pub fn toml_lines(calibration: &Calibration) -> [String; 6] {
    [
        "[panel]".to_owned(),
        format!("touch_left = {}", calibration.left),
        format!("touch_right = {}", calibration.right),
        format!("touch_top = {}", calibration.top),
        format!("touch_bottom = {}", calibration.bottom),
        format!("touch_swap_xy = {}", calibration.swap_xy),
    ]
}

/// Waits for one tap on the cross that is on the screen, for up to `TARGET_WAIT_MS` on `now_ms`.
///
/// `None` is a cross nobody tapped in time. A tap that completes in the last
/// read counts, whatever the clock says. What the read holds after the tap is
/// fed to `collector` too, so that it knows each axis's last reading, which
/// the kernel does not send again until it changes; a second tap in it is
/// not wanted, and the first reading is the one given.
fn await_tap(
    collector: &mut Collector,
    wait: &mut dyn FnMut(u64) -> io::Result<Vec<RawEvent>>,
    now_ms: &dyn Fn() -> u64,
) -> io::Result<Option<Reading>> {
    let shown_ms = now_ms();
    loop {
        let mut tap = None;
        for event in wait(POLL_MS)? {
            let reading = collector.feed(event);
            tap = tap.or(reading);
        }
        if tap.is_some() {
            return Ok(tap);
        }
        if now_ms().saturating_sub(shown_ms) >= TARGET_WAIT_MS {
            return Ok(None);
        }
    }
}

/// Shows the four crosses one after the other, waits for a tap on each, and logs the calibration the taps give.
///
/// `wait` reads the touch device for up to the milliseconds it is given and
/// returns the events it had; `now_ms` is a clock in milliseconds that does not
/// jump. Returns the calibration, which is also logged as the lines to paste into
/// `qberrypi.toml`; `None` when a cross was not tapped within `TARGET_WAIT_MS`
/// or the taps were not the crosses, which is logged and leaves the configured
/// calibration as it is. Only a screen or a device that fails is an error.
pub fn calibrate(
    surface: &mut dyn Surface,
    wait: &mut dyn FnMut(u64) -> io::Result<Vec<RawEvent>>,
    now_ms: &dyn Fn() -> u64,
) -> io::Result<Option<Calibration>> {
    let mut readings = [Reading { raw_x: 0, raw_y: 0 }; 4];
    // One collector for all four taps: the kernel sends an axis only when its value changes, and
    // two crosses in a row share a screen x or y.
    let mut collector = Collector::default();
    for (index, (reading, (x, y))) in readings.iter_mut().zip(TARGETS).enumerate() {
        let n = index + 1;
        surface.show(&target_frame(index))?;
        let Some(tap) = await_tap(&mut collector, wait, now_ms)? else {
            log::warn!(
                "panel: calibration: no tap on target {n} of 4; keeping the configured calibration"
            );
            return Ok(None);
        };
        log::info!(
            "panel: calibration: target {n} of 4 at ({x}, {y}): raw ({}, {})",
            tap.raw_x,
            tap.raw_y
        );
        *reading = tap;
    }
    match solve(&readings) {
        Ok(calibration) => {
            for line in toml_lines(&calibration) {
                log::info!("panel: calibration: {line}");
            }
            Ok(Some(calibration))
        }
        Err(error) => {
            log::warn!("panel: calibration: {error}; keeping the configured calibration");
            Ok(None)
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::cell::Cell;
    use std::io;

    use qb_panel::{Calibration, to_screen};

    use crate::panel::tests::recorder;
    use crate::panel::touch::tests::{abs_x, abs_y, dropped, key, pressure, syn};
    use crate::panel::touch::{MIN_PRESSURE, RawEvent};

    /// The reading a panel with `calibration` gives at the screen point (`x`, `y`).
    pub(crate) fn raw_at(calibration: &Calibration, x: u16, y: u16) -> Reading {
        let along = |from: u16, to: u16, at: u16, last: f64| {
            let reading =
                f64::from(from) + (f64::from(to) - f64::from(from)) * f64::from(at) / last;
            reading.round() as u16
        };
        let h = along(calibration.left, calibration.right, x, 479.0);
        let v = along(calibration.top, calibration.bottom, y, 319.0);
        let (raw_x, raw_y) = if calibration.swap_xy { (v, h) } else { (h, v) };
        Reading { raw_x, raw_y }
    }

    /// The events of one press at `raw`: `reports` reports 20 ms apart from `at` on, then the release.
    pub(crate) fn press(at: u64, raw: Reading, reports: u64) -> Vec<RawEvent> {
        let mut events = vec![
            key(at, 1),
            abs_x(at, i32::from(raw.raw_x)),
            abs_y(at, i32::from(raw.raw_y)),
        ];
        events.extend((0..reports).map(|n| syn(at + 20 * n)));
        let lifted = at + 20 * reports;
        events.extend([key(lifted, 0), syn(lifted)]);
        events
    }

    /// The events of one press at `raw` as the kernel sends them: an axis only when its value is
    /// not the one it sent last, which `sent` holds and the press updates.
    pub(crate) fn kernel_press(
        at: u64,
        sent: &mut Reading,
        raw: Reading,
        reports: u64,
    ) -> Vec<RawEvent> {
        let mut events = vec![key(at, 1)];
        if raw.raw_x != sent.raw_x {
            events.push(abs_x(at, i32::from(raw.raw_x)));
        }
        if raw.raw_y != sent.raw_y {
            events.push(abs_y(at, i32::from(raw.raw_y)));
        }
        *sent = raw;
        events.extend((0..reports).map(|n| syn(at + 20 * n)));
        let lifted = at + 20 * reports;
        events.extend([key(lifted, 0), syn(lifted)]);
        events
    }

    /// One report of the touch screen: the readings `x` and `y`, then the end of the report.
    fn report(at: u64, x: i32, y: i32) -> [RawEvent; 3] {
        [abs_x(at, x), abs_y(at, y), syn(at)]
    }

    /// The readings a new collector gives out for `events`, in order.
    fn collect(events: &[RawEvent]) -> Vec<Reading> {
        let mut collector = Collector::default();
        events
            .iter()
            .filter_map(|&event| collector.feed(event))
            .collect()
    }

    /// The calibration `got` is within a few raw units of `want`, and exchanges the axes as it does.
    pub(crate) fn assert_close(got: &Calibration, want: &Calibration) {
        assert_eq!(got.swap_xy, want.swap_xy);
        for (got, want) in [
            (got.left, want.left),
            (got.right, want.right),
            (got.top, want.top),
            (got.bottom, want.bottom),
        ] {
            assert!(got.abs_diff(want) <= 4, "{got} for {want}");
        }
    }

    /// A touch screen with `calibration` whose owner taps the first `taps` crosses as each appears.
    fn owner(
        calibration: Calibration,
        taps: usize,
    ) -> impl FnMut(u64) -> io::Result<Vec<RawEvent>> {
        let mut calls = 0;
        move |_| {
            let call = calls;
            calls += 1;
            Ok(match TARGETS.get(call).filter(|_| call < taps) {
                Some(&(x, y)) => press(1_000, raw_at(&calibration, x, y), 5),
                None => Vec::new(),
            })
        }
    }

    /// A touch screen with `calibration` like `owner`, but its kernel sends an axis only when it
    /// changed. With `bounce` the pen also bounces onto where the second cross will be read, in the
    /// read that has the end of the first tap.
    fn kernel_owner(
        calibration: Calibration,
        bounce: bool,
    ) -> impl FnMut(u64) -> io::Result<Vec<RawEvent>> {
        let mut calls = 0;
        let mut sent = Reading { raw_x: 0, raw_y: 0 };
        move |_| {
            let call = calls;
            calls += 1;
            let Some(&(x, y)) = TARGETS.get(call) else {
                return Ok(Vec::new());
            };
            let mut events = kernel_press(1_000, &mut sent, raw_at(&calibration, x, y), 5);
            if bounce && call == 0 {
                let (next_x, next_y) = TARGETS[1];
                let next = raw_at(&calibration, next_x, next_y);
                events.extend(kernel_press(1_200, &mut sent, next, 1));
            }
            Ok(events)
        }
    }

    #[test]
    fn a_press_that_leaves_out_an_axis_that_did_not_change_keeps_its_last_reading() {
        let (a, b) = (
            Reading {
                raw_x: 600,
                raw_y: 3500,
            },
            Reading {
                raw_x: 2100,
                raw_y: 3500,
            },
        );
        let mut sent = Reading { raw_x: 0, raw_y: 0 };
        let mut events = kernel_press(0, &mut sent, a, 5);
        events.extend(kernel_press(1_000, &mut sent, b, 5));
        assert!(!events[8..].contains(&abs_y(1_000, 3500)), "y is left out");
        assert_eq!(collect(&events), [a, b]);
    }

    #[test]
    fn the_axis_a_cross_shares_with_the_one_before_is_not_sent_again_and_still_counts() {
        for cal in [
            Calibration {
                swap_xy: false,
                left: 3890,
                right: 210,
                top: 300,
                bottom: 3800,
            },
            Calibration {
                swap_xy: true,
                left: 250,
                right: 3850,
                top: 3900,
                bottom: 180,
            },
        ] {
            let (mut surface, _) = recorder();
            let now = || 0;
            let solved = calibrate(&mut surface, &mut kernel_owner(cal, false), &now)
                .unwrap()
                .expect("a calibration");
            assert_close(&solved, &cal);
        }
    }

    #[test]
    fn what_the_kernel_sends_in_the_read_after_a_tap_is_not_lost() {
        let cal = Calibration {
            swap_xy: false,
            left: 3890,
            right: 210,
            top: 300,
            bottom: 3800,
        };
        let (mut surface, _) = recorder();
        let now = || 0;
        let solved = calibrate(&mut surface, &mut kernel_owner(cal, true), &now)
            .unwrap()
            .expect("a calibration");
        assert_close(&solved, &cal);
    }

    #[test]
    fn four_taps_give_back_the_calibration_that_made_them() {
        for cal in [
            Calibration::NOMINAL,
            Calibration {
                swap_xy: false,
                left: 3890,
                right: 210,
                top: 300,
                bottom: 3800,
            },
            Calibration {
                swap_xy: true,
                left: 250,
                right: 3850,
                top: 3900,
                bottom: 180,
            },
            // Both axes inverted: what a half turn of the screen reads on the nominal panel.
            Calibration {
                swap_xy: false,
                left: 3900,
                right: 200,
                top: 3900,
                bottom: 200,
            },
            // The same half turn on a panel whose axes are swapped.
            Calibration {
                swap_xy: true,
                left: 3850,
                right: 250,
                top: 3900,
                bottom: 180,
            },
        ] {
            let solved = solve(&TARGETS.map(|(x, y)| raw_at(&cal, x, y))).unwrap();
            assert_close(&solved, &cal);
            for (x, y) in TARGETS {
                let r = raw_at(&cal, x, y);
                let (sx, sy) = to_screen(&solved, r.raw_x, r.raw_y);
                assert!(
                    sx.abs_diff(x) <= 1 && sy.abs_diff(y) <= 1,
                    "({sx}, {sy}) for ({x}, {y})"
                );
            }
        }
    }

    #[test]
    fn taps_that_cannot_be_the_four_targets_are_refused() {
        assert_eq!(
            solve(
                &[Reading {
                    raw_x: 2000,
                    raw_y: 2000
                }; 4]
            )
            .unwrap_err(),
            "the four readings are too close together"
        );
        let mut r = TARGETS.map(|(x, y)| raw_at(&Calibration::NOMINAL, x, y));
        r[3] = r[2]; // the fourth cross was not the one tapped
        assert_eq!(
            solve(&r).unwrap_err(),
            "the readings do not form a rectangle"
        );
    }

    #[test]
    fn a_reading_is_the_median_of_a_press_and_a_short_touch_is_none() {
        let mut events = vec![key(0, 1)];
        for (n, (x, y)) in [
            (600, 3500),
            (640, 3480),
            (2000, 100),
            (620, 3490),
            (610, 3495),
        ]
        .into_iter()
        .enumerate()
        {
            events.extend(report(20 * n as u64, x, y));
        }
        events.extend([key(100, 0), syn(100)]);
        assert_eq!(
            collect(&events),
            [Reading {
                raw_x: 620,
                raw_y: 3490
            }]
        );
        let tap = Reading {
            raw_x: 600,
            raw_y: 3500,
        };
        assert_eq!(collect(&press(0, tap, 2)), []);
        assert_eq!(collect(&press(0, tap, 3)), [tap]);
    }

    #[test]
    fn a_press_cut_by_lost_events_gives_nothing_and_the_next_press_is_read_whole() {
        let cut = Reading {
            raw_x: 600,
            raw_y: 3500,
        };
        let next = Reading {
            raw_x: 2100,
            raw_y: 1900,
        };
        let mut events = press(0, cut, 4);
        let release = events.split_off(events.len() - 2);
        events.push(dropped(70));
        // The finger rests on: reports with the button up are no part of any press.
        events.extend(report(90, 100, 100));
        events.extend(release);
        events.extend(press(1_000, next, 5));
        assert_eq!(collect(&events), [next]);
    }

    #[test]
    fn two_presses_are_two_readings() {
        let (a, b) = (
            Reading {
                raw_x: 600,
                raw_y: 3500,
            },
            Reading {
                raw_x: 2100,
                raw_y: 1900,
            },
        );
        let mut events = press(0, a, 5);
        events.extend(press(1_000, b, 5));
        assert_eq!(collect(&events), [a, b]);
    }

    #[test]
    fn reports_too_light_to_be_a_touch_are_not_part_of_a_reading() {
        let light = MIN_PRESSURE - 1;
        let mut events = vec![key(0, 1), pressure(0, 180)];
        events.extend(report(0, 600, 3500));
        // A pen on its way down: the readings are corners.
        for (n, (x, y)) in [(200, 200), (4000, 4000), (100, 3900)]
            .into_iter()
            .enumerate()
        {
            let at = 20 * (n as u64 + 1);
            events.push(pressure(at, light));
            events.extend(report(at, x, y));
        }
        events.push(pressure(80, 180));
        events.extend(report(80, 640, 3480));
        events.extend([key(100, 0), syn(100)]);
        // Five reports, three of them too light: two are not enough.
        assert_eq!(collect(&events), []);

        // A third firm report, at exactly the least pressure, makes the reading from the firm ones alone.
        let mut events = events[..events.len() - 2].to_vec();
        events.push(pressure(100, MIN_PRESSURE));
        events.extend(report(100, 620, 3490));
        events.extend([key(120, 0), syn(120)]);
        assert_eq!(
            collect(&events),
            [Reading {
                raw_x: 620,
                raw_y: 3490
            }]
        );
    }

    #[test]
    fn the_targets_are_the_corners_of_a_rectangle_forty_pixels_inside_the_screen() {
        let (last_x, last_y) = (WIDTH as i32 - 1, HEIGHT as i32 - 1);
        let at = |(x, y): (u16, u16)| (i32::from(x), i32::from(y));
        assert_eq!(
            TARGETS.map(at),
            [
                (MARGIN, MARGIN),
                (last_x - MARGIN, MARGIN),
                (last_x - MARGIN, last_y - MARGIN),
                (MARGIN, last_y - MARGIN)
            ]
        );
        assert_eq!((SPAN_X, SPAN_Y), (last_x - 2 * MARGIN, last_y - 2 * MARGIN));
    }

    #[test]
    fn each_cue_marks_its_own_target_in_white_on_black() {
        for (i, (x, y)) in TARGETS.into_iter().enumerate() {
            let frame = target_frame(i);
            assert_eq!(frame.len(), 307_200);
            let px = |x: u16, y: u16| {
                let at = (usize::from(y) * 480 + usize::from(x)) * 2;
                [frame[at], frame[at + 1]]
            };
            assert_eq!(px(x, y), [0xff, 0xff]);
            for other in TARGETS {
                if other != (x, y) {
                    assert_eq!(px(other.0, other.1), [0, 0]);
                }
            }
        }
    }

    #[test]
    fn the_result_is_the_lines_to_paste_into_the_configuration() {
        assert_eq!(
            toml_lines(&Calibration {
                swap_xy: false,
                left: 3890,
                right: 210,
                top: 300,
                bottom: 3800
            }),
            [
                "[panel]",
                "touch_left = 3890",
                "touch_right = 210",
                "touch_top = 300",
                "touch_bottom = 3800",
                "touch_swap_xy = false"
            ]
        );
    }

    #[test]
    fn the_four_cues_come_in_order_and_the_taps_become_the_calibration() {
        for cal in [
            Calibration {
                swap_xy: false,
                left: 3890,
                right: 210,
                top: 300,
                bottom: 3800,
            },
            Calibration {
                swap_xy: true,
                left: 250,
                right: 3850,
                top: 3900,
                bottom: 180,
            },
        ] {
            let (mut surface, frames) = recorder();
            let clock = Cell::new(0);
            let now = || {
                clock.set(clock.get() + 100);
                clock.get()
            };
            let solved = calibrate(&mut surface, &mut owner(cal, 4), &now)
                .unwrap()
                .unwrap();
            assert_close(&solved, &cal);
            assert_eq!(
                frames.all(),
                (0..4).map(target_frame).collect::<Vec<_>>(),
                "one cue for each target, in order, and nothing after the fourth tap"
            );
        }
    }

    #[test]
    fn a_cue_nobody_taps_ends_the_calibration_after_a_minute() {
        let (mut surface, frames) = recorder();
        let clock = Cell::new(0);
        let now = || {
            clock.set(clock.get() + 100);
            clock.get()
        };
        assert_eq!(
            calibrate(&mut surface, &mut |_| Ok(Vec::new()), &now).unwrap(),
            None
        );
        assert!(clock.get() >= TARGET_WAIT_MS, "{}", clock.get());
        assert!(clock.get() < 2 * TARGET_WAIT_MS, "{}", clock.get());
        assert_eq!(frames.all(), [target_frame(0)]);
    }

    #[test]
    fn the_minute_is_counted_from_each_cue_and_a_later_cue_nobody_taps_ends_it_too() {
        let (mut surface, frames) = recorder();
        let clock = Cell::new(0);
        let now = || {
            clock.set(clock.get() + 100);
            clock.get()
        };
        let mut hand = owner(Calibration::NOMINAL, 2);
        assert_eq!(calibrate(&mut surface, &mut hand, &now).unwrap(), None);
        assert_eq!(
            frames.all(),
            (0..3).map(target_frame).collect::<Vec<_>>(),
            "the third cue was shown and then waited for"
        );
        assert!(clock.get() >= TARGET_WAIT_MS, "{}", clock.get());
    }

    #[test]
    fn four_taps_that_are_not_the_four_crosses_keep_the_configured_calibration() {
        let (mut surface, frames) = recorder();
        let same_place = Reading {
            raw_x: 2000,
            raw_y: 2000,
        };
        let outcome = calibrate(
            &mut surface,
            &mut |_| Ok(press(1_000, same_place, 5)),
            &|| 0,
        );
        assert_eq!(outcome.unwrap(), None);
        assert_eq!(frames.all().len(), 4);
    }

    #[test]
    fn a_touch_device_that_fails_ends_the_calibration_with_its_error() {
        let (mut surface, _) = recorder();
        let error = calibrate(
            &mut surface,
            &mut |_| Err(io::Error::other("the touch device is gone")),
            &|| 0,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "the touch device is gone");
    }
}
