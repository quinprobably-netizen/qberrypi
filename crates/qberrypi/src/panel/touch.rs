//! The touch screen: finding its input device, reading the device, and turning what it reports into touches on the screen.
//!
//! The device is the `ads7846` driver's input device. [`find_touch`] finds
//! it by name, [`read_events`] reads what the kernel reports, and a
//! [`Decoder`] turns those reports into [`TouchEvent`]s in screen pixels.
//! Nothing here opens a file for writing, and none of it needs an unchecked block.

use std::fs;
use std::io::{self, ErrorKind, Read};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use qb_panel::{Calibration, TouchEvent, to_screen};
use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::io::Errno;

/// The name the `ads7846` driver gives the touch screen's input device.
pub const TOUCH_NAME: &str = "ADS7846 Touchscreen";

/// Where the kernel lists its input devices.
pub const SYS_INPUT: &str = "/sys/class/input";

/// How many bytes the kernel sends for one input event: a 16-byte time, a 2-byte type,
/// a 2-byte code and a 4-byte value, as on every 64-bit system.
pub const EVENT_BYTES: usize = 24;

/// How many events one read asks for.
const READ_EVENTS: usize = 64;

/// The type of the events that end a report or say that events were lost.
pub(crate) const EV_SYN: u16 = 0;
/// The type of the events that say a button changed.
pub(crate) const EV_KEY: u16 = 1;
/// The type of the events that say an axis changed.
pub(crate) const EV_ABS: u16 = 3;

/// The code, among `EV_SYN` events, that ends a report: everything before it happened at once.
pub(crate) const SYN_REPORT: u16 = 0;
/// The code, among `EV_SYN` events, that says the kernel lost events because nobody read them in time.
pub(crate) const SYN_DROPPED: u16 = 3;

/// The axis of the horizontal reading.
pub(crate) const ABS_X: u16 = 0;
/// The axis of the vertical reading.
pub(crate) const ABS_Y: u16 = 1;
/// The axis of the pressure of the pen on the glass.
pub(crate) const ABS_PRESSURE: u16 = 0x18;

/// The button that is pressed while the glass is touched.
pub(crate) const BTN_TOUCH: u16 = 0x14a;

/// The largest reading of the touch controller's two axes: they have 12 bits.
pub const RAW_MAX: u16 = 4095;

/// The least pressure at which a report is a touch, of the driver's 0 to 255.
///
/// A report with less is a pen on its way up or down, whose readings are
/// not where the finger is. The value is a guess: it is not measured on the
/// real panel, and is to be adjusted after the first taps on it.
pub const MIN_PRESSURE: i32 = 16;

/// Finds the touch screen's input device among those in `sys_input` and names its device file in `dev_input`.
///
/// The device is the `event*` directory whose `device/name` is `TOUCH_NAME`,
/// whatever its number: the numbers depend on what else is plugged in.
#[must_use]
pub fn find_touch(sys_input: &Path, dev_input: &Path) -> Option<PathBuf> {
    fs::read_dir(sys_input)
        .ok()?
        .filter_map(|entry| {
            let dir = entry.ok()?.file_name().into_string().ok()?;
            // A directory like `mouse0` is not a device file the touch screen could be read from.
            let number = dir.strip_prefix("event")?;
            if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            let name = fs::read_to_string(sys_input.join(&dir).join("device").join("name")).ok()?;
            (name.trim() == TOUCH_NAME).then_some(dir)
        })
        .min()
        .map(|dir| dev_input.join(dir))
}

/// One event of the kernel's input system, as read from a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawEvent {
    /// When the kernel made it, in milliseconds on the wall clock.
    pub at_ms: u64,
    /// What sort of event it is: a report's end, a button, an axis.
    pub kind: u16,
    /// Which button, axis or sort of report end it is about.
    pub code: u16,
    /// The new state of the button or axis.
    pub value: i32,
}

/// The `N` bytes of an event's fields that begin at `at`.
fn field<const N: usize>(bytes: &[u8; EVENT_BYTES], at: usize) -> [u8; N] {
    let mut field = [0u8; N];
    field.copy_from_slice(&bytes[at..at + N]);
    field
}

/// Reads the event the kernel sent in `bytes`, in native byte order.
///
/// The time is in whole milliseconds; a part of it that is negative counts as 0.
/// The kernel stamps events with the wall clock, which steps when the clock is
/// set, so the times of two events may run backwards.
#[must_use]
pub fn parse_event(bytes: &[u8; EVENT_BYTES]) -> RawEvent {
    let seconds = u64::try_from(i64::from_ne_bytes(field(bytes, 0))).unwrap_or(0);
    let micros = u64::try_from(i64::from_ne_bytes(field(bytes, 8))).unwrap_or(0);
    RawEvent {
        at_ms: seconds.saturating_mul(1000).saturating_add(micros / 1000),
        kind: u16::from_ne_bytes(field(bytes, 16)),
        code: u16::from_ne_bytes(field(bytes, 18)),
        value: i32::from_ne_bytes(field(bytes, 20)),
    }
}

/// A duration as the `timespec` that `poll` takes; one too long for it is as long as it can be.
fn timespec(duration: Duration) -> Timespec {
    Timespec::try_from(duration).unwrap_or(Timespec {
        tv_sec: i64::MAX,
        tv_nsec: 0,
    })
}

/// Reads the events a device has for us, waiting at most `timeout` for it to have any.
///
/// Waits with `poll` until the device is readable, then makes one `read` of up to
/// 64 events. Nothing readable in time is an empty list. A signal that
/// interrupts the wait is nothing readable yet: the wait goes on for what is left
/// of the timeout. A read that does not end on an event is `ErrorKind::InvalidData`,
/// and a device with nothing more to give, as when it is unplugged, is `ErrorKind::UnexpectedEof`.
pub fn read_events(
    device: &mut (impl Read + AsFd),
    timeout: Duration,
) -> io::Result<Vec<RawEvent>> {
    read_events_with_poll(device, timeout, rustix::event::poll)
}

/// `read_events` with the `poll` it waits with given, so that a test can make it fail.
fn read_events_with_poll(
    device: &mut (impl Read + AsFd),
    timeout: Duration,
    mut poll: impl FnMut(&mut [PollFd<'_>], Option<&Timespec>) -> Result<usize, Errno>,
) -> io::Result<Vec<RawEvent>> {
    let started = Instant::now();
    let mut left = timeout;
    loop {
        let mut fds = [PollFd::new(&*device, PollFlags::IN)];
        match poll(&mut fds, Some(&timespec(left))) {
            Ok(0) | Err(Errno::INTR) => {}
            Ok(_) => break,
            Err(errno) => return Err(errno.into()),
        }
        left = timeout.saturating_sub(started.elapsed());
        if left.is_zero() {
            return Ok(Vec::new());
        }
    }
    let mut buffer = [0u8; READ_EVENTS * EVENT_BYTES];
    let read = match device.read(&mut buffer) {
        Ok(0) => {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "the touch device gave nothing more",
            ));
        }
        Ok(read) => read,
        // Another reader took what poll saw, or a signal came: nothing yet.
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {
            return Ok(Vec::new());
        }
        Err(e) => return Err(e),
    };
    let (events, rest) = buffer[..read].as_chunks::<EVENT_BYTES>();
    if !rest.is_empty() {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("a read of {read} bytes does not end on an event of {EVENT_BYTES}"),
        ));
    }
    Ok(events.iter().map(parse_event).collect())
}

/// What a report of the touch screen turned into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decoded {
    /// A touch on the screen.
    Touch(TouchEvent),
    /// The kernel lost events while a finger was down: the press is over, and nothing is known about how it ended.
    Lost,
}

/// Turns the events of the touch screen into touches on the screen.
///
/// The kernel sends an axis only when its value changes and tells a new
/// reader none of them, so the decoder keeps the last reading of each
/// and a press may begin without a new one. Events are given to it in
/// the order they were read.
///
/// A report is a *touch sample* while the glass is touched and either
/// no pressure was ever reported or the last one is at least `MIN_PRESSURE`.
/// Only a touch sample is turned into a point: the pen on its way up or down
/// reads a point that is not where the finger is, and `to_screen` cannot tell.
#[derive(Debug, Default)]
pub struct Decoder {
    /// The last horizontal reading.
    raw_x: u16,
    /// The last vertical reading.
    raw_y: u16,
    /// The last pressure reading, if there ever was one.
    pressure: Option<i32>,
    /// Whether `BTN_TOUCH` is pressed as of the last event, a report that is not over included.
    button: bool,
    /// Whether `BTN_TOUCH` was pressed as of the last report.
    down: bool,
    /// The screen point last given out in this press; `None` before the press's `Down` is given.
    given: Option<(u16, u16)>,
}

/// A reading held to the 12 bits of the controller.
pub(crate) fn hold(value: i32) -> u16 {
    u16::try_from(value.clamp(0, i32::from(RAW_MAX))).unwrap_or(RAW_MAX)
}

impl Decoder {
    /// Takes the next event; returns the touch it completes, with the time of the report that completed it.
    ///
    /// - An axis, a pressure or a `BTN_TOUCH` event is only stored.
    /// - A report with the button up gives `Up` if the press's `Down` was given out, else nothing.
    /// - A report with the button down gives nothing unless it is a touch sample.
    ///   The first touch sample of a press gives `Down`, which may be a later report than
    ///   the one in which the button went down; the next ones give `Move` when the screen
    ///   point differs from the one last given out.
    /// - Lost events cancel the press and give `Lost` if the button was down. A finger that
    ///   rests on the glass sends no new `BTN_TOUCH`, so it makes no touch until it lifts
    ///   and presses again.
    pub fn feed(&mut self, event: RawEvent, calibration: &Calibration) -> Option<(u64, Decoded)> {
        let decoded = match (event.kind, event.code) {
            (EV_ABS, ABS_X) => {
                self.raw_x = hold(event.value);
                None
            }
            (EV_ABS, ABS_Y) => {
                self.raw_y = hold(event.value);
                None
            }
            (EV_ABS, ABS_PRESSURE) => {
                self.pressure = Some(event.value);
                None
            }
            (EV_KEY, BTN_TOUCH) => {
                self.button = event.value != 0;
                None
            }
            (EV_SYN, SYN_REPORT) => self.report(calibration),
            (EV_SYN, SYN_DROPPED) => self.lose(),
            _ => None,
        };
        decoded.map(|decoded| (event.at_ms, decoded))
    }

    /// The last `ABS_X` and `ABS_Y` readings, held to 0 to 4095.
    #[must_use]
    pub fn raw(&self) -> (u16, u16) {
        (self.raw_x, self.raw_y)
    }

    /// Whether the glass was touched as of the last report, whatever the pressure.
    #[must_use]
    pub fn down(&self) -> bool {
        self.down
    }

    /// Whether the glass is touched firmly enough for a report taken now to be a touch sample.
    fn is_sample(&self) -> bool {
        self.pressure
            .is_none_or(|pressure| pressure >= MIN_PRESSURE)
    }

    /// What the end of a report gives out.
    fn report(&mut self, calibration: &Calibration) -> Option<Decoded> {
        self.down = self.button;
        if !self.button {
            return self.given.take().map(|_| Decoded::Touch(TouchEvent::Up));
        }
        if !self.is_sample() {
            return None;
        }
        let point = to_screen(calibration, self.raw_x, self.raw_y);
        let (x, y) = point;
        match self.given.replace(point) {
            None => Some(Decoded::Touch(TouchEvent::Down { x, y })),
            Some(last) if last != point => Some(Decoded::Touch(TouchEvent::Move { x, y })),
            Some(_) => None,
        }
    }

    /// What lost events give out: the press, if there was one, is over.
    fn lose(&mut self) -> Option<Decoded> {
        self.button = false;
        self.given = None;
        std::mem::take(&mut self.down).then_some(Decoded::Lost)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::collections::VecDeque;
    use std::fs;
    use std::io::{self, ErrorKind, PipeReader, PipeWriter, Read, Write};
    use std::os::fd::{AsFd, BorrowedFd};
    use std::path::Path;
    use std::time::{Duration, Instant};

    use qb_panel::{Calibration, TouchEvent};
    use rustix::event::{PollFd, Timespec};
    use rustix::io::Errno;
    use tempfile::TempDir;

    use Decoded::{Lost, Touch};
    use TouchEvent::{Down, Move, Up};

    /// An event of the kernel's input system, made at `at_ms`.
    pub(crate) fn ev(at_ms: u64, kind: u16, code: u16, value: i32) -> RawEvent {
        RawEvent {
            at_ms,
            kind,
            code,
            value,
        }
    }

    /// `BTN_TOUCH` becomes `value`: 1 is pressed, 0 is released.
    pub(crate) fn key(at_ms: u64, value: i32) -> RawEvent {
        ev(at_ms, 1, 0x14a, value)
    }

    /// The horizontal reading becomes `value`.
    pub(crate) fn abs_x(at_ms: u64, value: i32) -> RawEvent {
        ev(at_ms, 3, 0, value)
    }

    /// The vertical reading becomes `value`.
    pub(crate) fn abs_y(at_ms: u64, value: i32) -> RawEvent {
        ev(at_ms, 3, 1, value)
    }

    /// The pressure becomes `value`.
    pub(crate) fn pressure(at_ms: u64, value: i32) -> RawEvent {
        ev(at_ms, 3, 0x18, value)
    }

    /// The end of a report.
    pub(crate) fn syn(at_ms: u64) -> RawEvent {
        ev(at_ms, 0, 0, 0)
    }

    /// The kernel says it lost events.
    pub(crate) fn dropped(at_ms: u64) -> RawEvent {
        ev(at_ms, 0, 3, 0)
    }

    /// The bytes the kernel sends for `event`: the inverse of `parse_event`.
    pub(crate) fn bytes_of(event: RawEvent) -> [u8; EVENT_BYTES] {
        let mut bytes = [0u8; EVENT_BYTES];
        bytes[..8].copy_from_slice(&i64::try_from(event.at_ms / 1000).unwrap().to_ne_bytes());
        bytes[8..16].copy_from_slice(
            &i64::try_from(event.at_ms % 1000 * 1000)
                .unwrap()
                .to_ne_bytes(),
        );
        bytes[16..18].copy_from_slice(&event.kind.to_ne_bytes());
        bytes[18..20].copy_from_slice(&event.code.to_ne_bytes());
        bytes[20..].copy_from_slice(&event.value.to_ne_bytes());
        bytes
    }

    /// What a new decoder with the nominal calibration gives out for `events`, in order.
    pub(crate) fn decode(events: &[RawEvent]) -> Vec<(u64, Decoded)> {
        let mut decoder = Decoder::default();
        events
            .iter()
            .filter_map(|&event| decoder.feed(event, &Calibration::NOMINAL))
            .collect()
    }

    /// A temporary `/sys/class/input` holding the given directories, each with the name of its
    /// device if it has one, the name ending in a newline as sysfs writes it.
    fn input(entries: &[(&str, Option<&str>)]) -> TempDir {
        let sys = tempfile::tempdir().unwrap();
        for (dir, name) in entries {
            let dir = sys.path().join(dir);
            fs::create_dir(&dir).unwrap();
            if let Some(name) = name {
                fs::create_dir(dir.join("device")).unwrap();
                fs::write(dir.join("device").join("name"), format!("{name}\n")).unwrap();
            }
        }
        sys
    }

    #[test]
    fn an_event_is_24_bytes_seconds_microseconds_type_code_value() {
        let mut b = [0u8; 24];
        b[..8].copy_from_slice(&3i64.to_ne_bytes());
        b[8..16].copy_from_slice(&250_000i64.to_ne_bytes());
        b[16..18].copy_from_slice(&3u16.to_ne_bytes());
        b[18..20].copy_from_slice(&1u16.to_ne_bytes());
        b[20..].copy_from_slice(&(-7i32).to_ne_bytes());
        assert_eq!(
            parse_event(&b),
            RawEvent {
                at_ms: 3_250,
                kind: 3,
                code: 1,
                value: -7
            }
        );
    }

    #[test]
    fn a_negative_time_counts_as_zero() {
        let mut b = bytes_of(syn(0));
        b[..8].copy_from_slice(&(-2i64).to_ne_bytes());
        b[8..16].copy_from_slice(&(-1i64).to_ne_bytes());
        assert_eq!(parse_event(&b).at_ms, 0);
        b[..8].copy_from_slice(&2i64.to_ne_bytes());
        assert_eq!(parse_event(&b).at_ms, 2_000);
    }

    #[test]
    fn a_press_a_drag_and_a_release_become_down_move_up() {
        let out = decode(&[
            key(1000, 1),
            abs_x(1000, 1125),
            abs_y(1000, 2975),
            pressure(1000, 180),
            syn(1000),
            abs_x(1040, 200),
            syn(1040),
            pressure(1060, 150),
            syn(1060),
            key(1100, 0),
            pressure(1100, 0),
            syn(1100),
        ]);
        assert_eq!(
            out,
            [
                (1000, Touch(Down { x: 120, y: 239 })),
                (1040, Touch(Move { x: 0, y: 239 })),
                (1100, Touch(Up))
            ]
        );
    }

    #[test]
    fn a_second_press_on_the_same_spot_reuses_the_last_reading() {
        // the kernel sends an axis only when its value changes
        let out = decode(&[
            key(0, 1),
            abs_x(0, 1125),
            abs_y(0, 2975),
            syn(0),
            key(80, 0),
            syn(80),
            key(500, 1),
            syn(500),
            key(580, 0),
            syn(580),
        ]);
        assert_eq!(out[2], (500, Touch(Down { x: 120, y: 239 })));
        assert_eq!(out.len(), 4);
    }

    #[test]
    fn lost_events_cancel_the_press() {
        let out = decode(&[
            key(0, 1),
            abs_x(0, 1125),
            abs_y(0, 2975),
            syn(0),
            dropped(40),
            key(90, 0),
            syn(90),
            dropped(95),
        ]);
        assert_eq!(out, [(0, Touch(Down { x: 120, y: 239 })), (40, Lost)]);
    }

    #[test]
    fn a_press_cut_by_lost_events_does_not_begin_again_while_the_finger_rests() {
        // the kernel sends `BTN_TOUCH` only when it changes, so a finger that never lifted sends none
        let out = decode(&[
            key(0, 1),
            abs_x(0, 1125),
            abs_y(0, 2975),
            syn(0),
            dropped(40),
            abs_x(50, 200),
            syn(50),
            abs_x(100, 1125),
            syn(100),
            key(150, 0),
            syn(150),
            key(900, 1),
            syn(900),
        ]);
        assert_eq!(
            out,
            [
                (0, Touch(Down { x: 120, y: 239 })),
                (40, Lost),
                (900, Touch(Down { x: 120, y: 239 }))
            ]
        );
    }

    #[test]
    fn readings_outside_twelve_bits_are_held_to_the_range() {
        let mut d = Decoder::default();
        for e in [abs_x(0, -5), abs_y(0, 70_000)] {
            d.feed(e, &Calibration::NOMINAL);
        }
        assert_eq!((d.raw(), d.down()), ((0, 4095), false));
    }

    #[test]
    fn down_follows_the_button_as_of_the_last_report_whatever_the_pressure() {
        let mut d = Decoder::default();
        let cal = Calibration::NOMINAL;
        d.feed(pressure(0, 3), &cal);
        d.feed(key(0, 1), &cal);
        assert!(!d.down(), "the report is not over");
        d.feed(syn(0), &cal);
        assert!(d.down());
        d.feed(key(20, 0), &cal);
        assert!(d.down(), "the report is not over");
        d.feed(syn(20), &cal);
        assert!(!d.down());
    }

    #[test]
    fn a_press_under_the_least_pressure_begins_at_the_first_report_that_reaches_it() {
        let out = decode(&[
            key(0, 1),
            abs_x(0, 1125),
            abs_y(0, 2975),
            pressure(0, MIN_PRESSURE - 1),
            syn(0),
            pressure(30, 1),
            syn(30),
            abs_x(60, 200),
            pressure(60, 100),
            syn(60),
            key(100, 0),
            pressure(100, 0),
            syn(100),
        ]);
        assert_eq!(out, [(60, Touch(Down { x: 0, y: 239 })), (100, Touch(Up))]);
    }

    #[test]
    fn a_weak_report_in_mid_press_gives_nothing_and_changes_nothing() {
        let out = decode(&[
            key(0, 1),
            abs_x(0, 1125),
            abs_y(0, 2975),
            pressure(0, 180),
            syn(0),
            // the pen is lifting: the readings run to the corner while the pressure falls
            abs_x(20, 0),
            abs_y(20, 4095),
            pressure(20, MIN_PRESSURE - 1),
            syn(20),
            // back at the place it was given out at
            abs_x(40, 1125),
            abs_y(40, 2975),
            pressure(40, 180),
            syn(40),
            abs_x(60, 200),
            syn(60),
            key(80, 0),
            pressure(80, 0),
            syn(80),
        ]);
        assert_eq!(
            out,
            [
                (0, Touch(Down { x: 120, y: 239 })),
                (60, Touch(Move { x: 0, y: 239 })),
                (80, Touch(Up))
            ]
        );
    }

    #[test]
    fn a_press_that_never_reaches_the_least_pressure_gives_neither_down_nor_up() {
        let out = decode(&[
            key(0, 1),
            abs_x(0, 1125),
            abs_y(0, 2975),
            pressure(0, 10),
            syn(0),
            abs_x(40, 0),
            abs_y(40, 4095),
            pressure(40, MIN_PRESSURE - 1),
            syn(40),
            key(80, 0),
            pressure(80, 0),
            syn(80),
        ]);
        assert_eq!(out, []);
    }

    #[test]
    fn the_least_pressure_itself_counts_and_one_below_does_not() {
        let press = |value| {
            decode(&[
                key(0, 1),
                abs_x(0, 1125),
                abs_y(0, 2975),
                pressure(0, value),
                syn(0),
            ])
        };
        assert_eq!(press(MIN_PRESSURE - 1), []);
        assert_eq!(press(MIN_PRESSURE), [(0, Touch(Down { x: 120, y: 239 }))]);
    }

    #[test]
    fn the_touch_device_is_found_by_name_not_number() {
        let dev = Path::new("/dev/input");
        let sys = input(&[
            ("event0", Some("vc4-hdmi")),
            ("event1", Some(TOUCH_NAME)),
            ("mouse0", None),
        ]);
        assert_eq!(
            find_touch(sys.path(), dev),
            Some("/dev/input/event1".into())
        );
        let sys = input(&[
            ("event0", Some(TOUCH_NAME)),
            ("event1", Some("vc4-hdmi")),
            ("mouse0", None),
        ]);
        assert_eq!(
            find_touch(sys.path(), dev),
            Some("/dev/input/event0".into())
        );
        let sys = input(&[
            ("event0", Some("vc4-hdmi")),
            ("event1", None),
            ("mouse0", None),
        ]);
        assert_eq!(find_touch(sys.path(), dev), None);
    }

    #[test]
    fn only_an_event_directory_can_be_the_touch_device() {
        let dev = Path::new("/dev/input");
        let sys = input(&[("mouse0", Some(TOUCH_NAME)), ("input3", Some(TOUCH_NAME))]);
        assert_eq!(find_touch(sys.path(), dev), None);
        let gone = sys.path().join("not-there");
        assert_eq!(find_touch(&gone, dev), None);
    }

    #[test]
    fn events_are_read_whole_and_a_quiet_device_gives_none() {
        let (mut reader, mut writer) = std::io::pipe().unwrap();
        assert!(
            read_events(&mut reader, Duration::from_millis(20))
                .unwrap()
                .is_empty()
        );
        writer
            .write_all(&[bytes_of(key(1, 1)), bytes_of(syn(1))].concat())
            .unwrap();
        assert_eq!(
            read_events(&mut reader, Duration::from_secs(5)).unwrap(),
            [key(1, 1), syn(1)]
        );
        writer.write_all(&[0; 10]).unwrap();
        assert_eq!(
            read_events(&mut reader, Duration::from_secs(5))
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );
    }

    #[test]
    fn one_read_takes_at_most_64_events() {
        let (mut reader, mut writer) = std::io::pipe().unwrap();
        let all: Vec<RawEvent> = (0..70).map(syn).collect();
        let bytes: Vec<u8> = all.iter().flat_map(|&e| bytes_of(e)).collect();
        writer.write_all(&bytes).unwrap();
        let first = read_events(&mut reader, Duration::from_secs(5)).unwrap();
        assert_eq!(first, all[..64]);
        let second = read_events(&mut reader, Duration::from_secs(5)).unwrap();
        assert_eq!(second, all[64..]);
    }

    #[test]
    fn a_device_that_is_gone_is_an_error_and_not_a_quiet_one() {
        let (mut reader, writer) = std::io::pipe().unwrap();
        drop(writer);
        assert_eq!(
            read_events(&mut reader, Duration::from_secs(5))
                .unwrap_err()
                .kind(),
            ErrorKind::UnexpectedEof
        );
    }

    /// A device that gives the scripted answers to its reads and counts them; the descriptor
    /// it offers to `poll` is a pipe's, the writing end of which is never used.
    struct Scripted {
        fd: PipeReader,
        _writer: PipeWriter,
        answers: VecDeque<io::Result<Vec<u8>>>,
        reads: usize,
    }

    impl Scripted {
        fn new(answers: Vec<io::Result<Vec<u8>>>) -> Self {
            let (fd, _writer) = std::io::pipe().unwrap();
            Self {
                fd,
                _writer,
                answers: answers.into(),
                reads: 0,
            }
        }
    }

    impl Read for Scripted {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            let bytes = self.answers.pop_front().expect("a read nobody scripted")?;
            buf[..bytes.len()].copy_from_slice(&bytes);
            Ok(bytes.len())
        }
    }

    impl AsFd for Scripted {
        fn as_fd(&self) -> BorrowedFd<'_> {
            self.fd.as_fd()
        }
    }

    #[test]
    fn a_wait_cut_short_by_a_signal_goes_on_for_the_rest_of_the_timeout() {
        let mut device = Scripted::new(vec![Ok(bytes_of(syn(7)).to_vec())]);
        let mut timeouts = Vec::new();
        let events = read_events_with_poll(&mut device, Duration::from_secs(5), |_, timeout| {
            timeouts.push(Duration::try_from(*timeout.unwrap()).unwrap());
            if timeouts.len() == 1 {
                std::thread::sleep(Duration::from_millis(10));
                Err(Errno::INTR)
            } else {
                Ok(1)
            }
        })
        .unwrap();
        assert_eq!(events, [syn(7)]);
        assert_eq!(device.reads, 1);
        assert_eq!(timeouts.len(), 2);
        assert_eq!(timeouts[0], Duration::from_secs(5));
        assert!(timeouts[1] <= Duration::from_millis(4_990), "{timeouts:?}");
    }

    #[test]
    fn signals_all_through_the_timeout_end_it_with_nothing_and_no_read() {
        let mut device = Scripted::new(vec![]);
        let started = Instant::now();
        let events = read_events_with_poll(&mut device, Duration::from_millis(30), |_, _| {
            Err(Errno::INTR)
        })
        .unwrap();
        assert!(events.is_empty());
        assert_eq!(device.reads, 0);
        assert!(started.elapsed() >= Duration::from_millis(30));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_poll_that_times_out_gives_nothing_and_no_read() {
        let mut device = Scripted::new(vec![]);
        let mut polls = 0;
        let events = read_events_with_poll(&mut device, Duration::ZERO, |_, _| {
            polls += 1;
            Ok(0)
        })
        .unwrap();
        assert!(events.is_empty());
        assert_eq!((polls, device.reads), (1, 0));
    }

    #[test]
    fn a_poll_that_fails_is_an_error() {
        let mut device = Scripted::new(vec![]);
        let err =
            read_events_with_poll(&mut device, Duration::from_secs(5), |_, _| Err(Errno::BADF))
                .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(Errno::BADF.raw_os_error()));
        assert_eq!(device.reads, 0);
    }

    #[test]
    fn a_read_that_finds_nothing_after_all_is_a_quiet_device() {
        for kind in [ErrorKind::WouldBlock, ErrorKind::Interrupted] {
            let mut device = Scripted::new(vec![Err(kind.into())]);
            let events =
                read_events_with_poll(&mut device, Duration::from_secs(5), |_, _| Ok(1)).unwrap();
            assert!(events.is_empty(), "{kind:?}");
            assert_eq!(device.reads, 1);
        }
    }

    #[test]
    fn the_timeout_reaches_poll_as_seconds_and_nanoseconds() {
        let mut device = Scripted::new(vec![Ok(bytes_of(syn(1)).to_vec())]);
        let mut seen = None;
        let events = read_events_with_poll(
            &mut device,
            Duration::new(2, 500_000_000),
            |fds: &mut [PollFd<'_>], timeout| {
                assert_eq!(fds.len(), 1);
                seen = timeout.copied();
                Ok(1)
            },
        )
        .unwrap();
        assert_eq!(events, [syn(1)]);
        let expected = Timespec {
            tv_sec: 2,
            tv_nsec: 500_000_000,
        };
        assert_eq!(seen, Some(expected));
    }
}
