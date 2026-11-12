//! The front panel's side of the system: finding the screen, what to show on it, and what a tap does.
//!
//! [`run`] is the panel's thread. It loads the screen's drivers, finds the
//! framebuffer, and draws the Drain on it: names go by on the lane eight times
//! a second, and the slow figures (the percentage, the clock, the count, the
//! key, the gate's refill, the lane's words and the alert) are written one region at a time between
//! those frames.
//! The thread reads the touch screen between draws. A tap on the key pauses
//! blocking or turns it on again, and a tap on an alert's card acknowledges
//! it. A boot that asks for it first shows four crosses to tap and measures
//! the touch screen from the taps. A board without the screen is
//! [`PanelEnd::NoScreen`], which is no reason for the rest of the system to
//! stop. The thread only logs and reads `/sys` and `/dev`: it never touches
//! the card, the watchdog or the LED, and it never logs a name.

use std::fs::File;
use std::io::{self, Read};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use qb_panel::drain::{Drain, Stills};
use qb_panel::touch::PAUSE_MS;
use qb_panel::{Calibration, Control, HEIGHT, Painter, TapTracker, WIDTH};

use crate::lane::{LaneFeed, LaneName};
use crate::live::{BlockingControl, Source};
use crate::modules::{self, Insert, MODULE_LIST, ModuleTable, PANEL_MODULES};
use crate::sys;
use alerts::PendingAlerts;
use fb::{Framebuffer, SCREEN_DRIVER, SYS_GRAPHICS, SYS_VTCONSOLE, Screen, ScreenError};
use touch::{Decoded, Decoder, RawEvent, SYS_INPUT, find_touch, read_events};
use view::{blocking, refill, wanted_stills};

pub mod alerts;
pub mod calibrate;
pub mod fb;
pub mod touch;
pub mod view;

/// How long a frame of the Drain lasts, in milliseconds: eight frames a second.
///
/// The Drain moves one step each frame while anything on the lane is moving. A panel with nothing
/// moving writes nothing, and looks at the lane's feed and the control of blocking once a frame.
pub const FRAME_MS: u64 = 125;

/// How long after a frame the slow figures may be written, in milliseconds.
///
/// The screen's driver (fbtft, with deferred io) sends the span from the first to the last row
/// touched since its last flush, and flushes [`FLUSH_GUARD_MS`] or less after a write. A figure
/// written half a frame after the lane's frame goes out in a flush of its own, so that the two
/// spans are not one.
pub const STILL_OFFSET_MS: u64 = 62;

/// How often the panel asks for the system's numbers and for the alert to show, in milliseconds.
pub const SNAPSHOT_MS: u64 = 1_000;

/// How long the screen's driver may wait before it sends what was written, in milliseconds.
///
/// A figure is written only while at least this long is left before the next frame's write. One
/// that is written later is in the same flush window as that write, and the driver merges the two
/// into one span of rows, about 300 of them. A figure that is late waits for the next frame's slot.
pub const FLUSH_GUARD_MS: u64 = 50;

// A figure's slot falls inside its frame, outside the flush window of the frame's own write and
// of the next one's.
const _: () =
    assert!(STILL_OFFSET_MS > FLUSH_GUARD_MS && STILL_OFFSET_MS + FLUSH_GUARD_MS < FRAME_MS);

/// What the funnel's first dots are made from; any number gives a funnel of its own.
const DRAIN_SEED: u32 = 7;

/// How long the screen's framebuffer is waited for once its drivers are loaded.
///
/// The framebuffer appears a little after the module that makes it is inserted.
pub const SCREEN_WAIT: Duration = Duration::from_secs(2);

/// How long one tap on the switch pauses blocking, in seconds.
pub const PAUSE_SECS: u16 = 300;

/// The seconds and the milliseconds of the pause are one length of time.
const _: () = assert!(PAUSE_MS == PAUSE_SECS as u64 * 1_000);

/// How often a wait for the screen, or for the touch screen, looks whether it is there.
const SCREEN_POLL: Duration = Duration::from_millis(50);

/// Where the kernel makes the device files of the framebuffers.
const DEV: &str = "/dev";

/// Where the kernel makes the device files of the input devices.
const DEV_INPUT: &str = "/dev/input";

/// Where a frame goes to be seen.
pub trait Surface {
    /// Replaces the picture with `frame`, which holds the panel as RGB565.
    fn show(&mut self, frame: &[u8]) -> io::Result<()>;
}

impl Surface for Framebuffer {
    fn show(&mut self, frame: &[u8]) -> io::Result<()> {
        Framebuffer::show(self, frame)
    }
}

/// What the panel is given to work with besides the screen.
pub struct Deps {
    /// Where what the panel shows comes from.
    pub source: Arc<dyn Source>,
    /// What the switch on the panel controls.
    pub control: Arc<dyn BlockingControl>,
    /// How the touch screen's readings lie on the screen.
    pub calibration: Calibration,
    /// Whether to measure `calibration` before the panel is drawn: four crosses to tap, logged and used for this boot only.
    pub calibrate: bool,
    /// The names that the resolver lets the lane show.
    pub lane: Arc<LaneFeed>,
    /// Where the alert to show comes from, and where a tap on it is told.
    pub alerts: Arc<dyn PendingAlerts>,
}

/// How the panel's thread ended; it ends only when the panel cannot go on.
#[derive(Debug, PartialEq)]
pub enum PanelEnd {
    /// There is no usable screen; says why. The rest of the system runs without a panel.
    NoScreen(String),
    /// The panel was running and broke; says how.
    Failed(String),
}

/// The places the panel looks in, so that tests can look elsewhere.
pub struct Roots {
    /// The table of the kernel modules that can be loaded.
    pub module_list: PathBuf,
    /// The directory in which the kernel lists its framebuffers.
    pub sys_graphics: PathBuf,
    /// The directory in which the kernel lists its text consoles.
    pub sys_vtconsole: PathBuf,
    /// The directory of the device files.
    pub dev: PathBuf,
}

impl Roots {
    /// The places on a running system.
    pub fn real() -> Self {
        Self {
            module_list: MODULE_LIST.into(),
            sys_graphics: SYS_GRAPHICS.into(),
            sys_vtconsole: SYS_VTCONSOLE.into(),
            dev: DEV.into(),
        }
    }
}

/// Loads the drivers of the screen and the touch controller, and finds the screen.
///
/// The framebuffer is looked for at least once, and then every 50 ms until it
/// is there or `wait` has passed. When the screen is the only framebuffer the
/// kernel has put its text console on it, so the console is taken off.
pub fn bring_up(roots: &Roots, insert: Insert, wait: Duration) -> Result<Screen, PanelEnd> {
    let table = std::fs::read_to_string(&roots.module_list)
        .map_err(|error| error.to_string())
        .and_then(|text| ModuleTable::parse(&text))
        .map_err(|error| PanelEnd::NoScreen(format!("{}: {error}", roots.module_list.display())))?;
    let mut inserted = Vec::new();
    for name in PANEL_MODULES {
        let loaded = modules::load(&table, name, "", &mut *insert)
            .map_err(|error| PanelEnd::NoScreen(format!("loading {name}: {error}")))?;
        inserted.extend(loaded);
    }
    log::info!("panel: modules: inserted {}", inserted.join(", "));

    let asked = Instant::now();
    let found = loop {
        match fb::find_screen(&roots.sys_graphics, &roots.dev) {
            Err(ScreenError::Absent) if asked.elapsed() < wait => {
                thread::sleep(SCREEN_POLL.min(wait.saturating_sub(asked.elapsed())));
            }
            other => break other,
        }
    };
    let screen = found.map_err(|error| {
        PanelEnd::NoScreen(match error {
            ScreenError::Absent => format!("no {SCREEN_DRIVER} framebuffer"),
            ScreenError::Wrong(found) => {
                format!("{SCREEN_DRIVER} is {found}, not {WIDTH},{HEIGHT} at 16 bpp")
            }
        })
    })?;
    if screen.sole {
        match fb::detach_console(&roots.sys_vtconsole) {
            Ok(true) => log::info!("panel: the text console was on the screen; detached"),
            Ok(false) => {}
            // The panel is drawn anyway; the console's lines will scroll over it.
            Err(error) => log::warn!("panel: taking the text console off the screen: {error}"),
        }
    }
    log::info!(
        "panel: {SCREEN_DRIVER} is {}, {WIDTH} x {HEIGHT}, 16 bpp",
        screen.device.display()
    );
    Ok(screen)
}

/// The panel on its screen: what to draw and when, and what a tap does.
///
/// The Drain is the scene: names on a lane, refused ones melting into a funnel. The `Stills` are
/// the figures that change slowly. What the screen shows of them is `shown`, and what it is to
/// come to show is `wanted`; the panel copies one field at a time from `wanted` to `shown`, each
/// in a write of its own, half a frame after the lane's frame.
pub struct Panel<S: Surface> {
    surface: S,
    deps: Deps,
    /// Turns the touch screen's events into touches on the screen.
    decoder: Decoder,
    /// Turns touches into taps on the key and the alert.
    tracker: TapTracker,
    /// The scene.
    drain: Drain,
    /// Draws the scene and the figures on a frame it keeps.
    painter: Painter,
    /// The figures that the screen shows.
    shown: Stills,
    /// The figures that the screen is to show, as of the last turn.
    wanted: Stills,
    /// The store's id of the alert on the screen, if one is.
    shown_alert: Option<u64>,
    /// The store's id of the alert that is to be on the screen, if there is one.
    wanted_alert: Option<u64>,
    /// The names taken from the lane's feed at a frame. Kept between frames so that it is not made again.
    arrivals: Vec<LaneName>,
    /// Whether the first frame has been drawn.
    begun: bool,
    /// The time, in milliseconds since the panel began, at which the next frame is due.
    next_frame_ms: u64,
    /// The time at which the last frame was made.
    last_frame_ms: u64,
    /// The time, in milliseconds since the panel began, at which the panel last took a name from the
    /// lane's feed; the first frame's time until it takes one. It times the lane's `QUIET` words.
    last_name_ms: u64,
    /// Whether the figures' write of the frame that was last made has been done.
    still_done: bool,
    /// The time from which the next snapshot of the system is due.
    next_snapshot_ms: u64,
    /// The seconds of a pause that the control last said were left; `None` when it said blocking is on.
    left: Option<u16>,
    /// Whether a tap on the key asked for a draw that has not been made.
    tapped: bool,
    /// Whether a tap on the alert took it off the screen, and the screen has not been drawn since.
    dismissed: bool,
}

impl<S: Surface> Panel<S> {
    /// A panel that draws on `surface`.
    pub fn new(surface: S, deps: Deps) -> Self {
        Self {
            surface,
            deps,
            decoder: Decoder::default(),
            tracker: TapTracker::default(),
            drain: Drain::new(DRAIN_SEED),
            painter: Painter::new(),
            shown: Stills::default(),
            wanted: Stills::default(),
            shown_alert: None,
            wanted_alert: None,
            arrivals: Vec::new(),
            begun: false,
            next_frame_ms: 0,
            last_frame_ms: 0,
            last_name_ms: 0,
            still_done: false,
            next_snapshot_ms: 0,
            left: None,
            tapped: false,
            dismissed: false,
        }
    }

    /// Takes the events the touch screen reported, in the order they were read.
    ///
    /// A tap on the key pauses blocking for five minutes, or ends the pause
    /// that is running, and the next turn draws whatever the time. A tap on
    /// the alert's card, which counts only while the card is shown, tells the
    /// store that the alert was seen and takes the card off the screen at the
    /// next turn. A tap is timed by the events that make it, not by when they
    /// were read.
    pub fn touch(&mut self, events: &[RawEvent]) {
        for &event in events {
            let Some((at_ms, decoded)) = self.decoder.feed(event, &self.deps.calibration) else {
                continue;
            };
            match decoded {
                Decoded::Touch(touch) => {
                    let alert_shown = self.shown.alert.is_some();
                    match self.tracker.feed(at_ms, touch, alert_shown) {
                        Some(Control::BlockingSwitch) => self.switch(),
                        Some(Control::DismissAlert) => self.dismiss(),
                        None => {}
                    }
                }
                // Whatever was known of the press is not to be trusted, nor is it needed:
                // the press may be one whose `Down` was never given out.
                Decoded::Lost => self.tracker = TapTracker::default(),
            }
        }
    }

    /// Works the key: pauses blocking, or ends the pause that is running.
    fn switch(&mut self) {
        let control = &self.deps.control;
        if control.paused_left_secs().is_some() {
            control.resume();
            log::info!("panel: switch: resumed");
        } else {
            control.pause_for(PAUSE_SECS);
            log::info!("panel: switch: paused for {PAUSE_SECS} s");
        }
        self.tapped = true;
    }

    /// Works the alert: tells the store the alert on the screen was seen, and takes its card away.
    ///
    /// A card that is already gone, because the press began on it and the store dropped it before
    /// the finger lifted, is nothing to dismiss.
    fn dismiss(&mut self) {
        if self.shown.alert.is_none() {
            return;
        }
        if let Some(id) = self.shown_alert.take() {
            self.deps.alerts.ack(id);
        }
        self.shown.alert = None;
        self.wanted.alert = None;
        self.wanted_alert = None;
        self.dismissed = true;
    }

    /// Makes the id of the alert on the screen the one of the alert that is to be, once they are the same card.
    fn follow_alert(&mut self) {
        if self.shown.alert == self.wanted.alert {
            self.shown_alert = self.wanted_alert;
        }
    }

    /// Does what is due at `now_ms`, and returns how many milliseconds may pass before the next call.
    ///
    /// `now_ms` is the time since the panel began and `now_unix` is the clock, in Unix seconds.
    /// A frame is due every `FRAME_MS`: it takes the names the feed holds, asks the control of
    /// blocking, asks the system for its numbers every `SNAPSHOT_MS`, and, while anything is
    /// moving, advances the Drain one step and draws it. Half a frame later, if the figures on
    /// the screen are not those that are wanted, one of them is drawn: a figure to a write, and
    /// only until `FLUSH_GUARD_MS` before the next frame, since a figure written later would
    /// share its flush with that frame's write; a figure that is late waits for the next frame's
    /// slot. A tap draws at once. The first turn draws everything. A panel with nothing to move and
    /// nothing to change draws nothing, whatever the time. A turn that comes late makes one
    /// frame, and the frames are counted from it.
    pub fn turn(&mut self, now_ms: u64, now_unix: u64) -> io::Result<u64> {
        let tapped = std::mem::take(&mut self.tapped);
        let dismissed = std::mem::take(&mut self.dismissed);
        let urgent = tapped || dismissed;
        let left = self.deps.control.paused_left_secs();
        if left.is_none() && self.left.is_some() && !tapped {
            log::info!("panel: switch: the pause ended");
        }
        let toggled = left.is_some() != self.left.is_some();
        self.left = left;
        // The key's countdown and the gate's refill follow the control at every turn, and go out in
        // writes of their own, the countdown first.
        self.wanted.blocking = blocking(left);
        self.wanted.gate_fill = refill(left);
        // The Drain knows of a pause as soon as it changes, so that the listed names on the lane are
        // restyled in the key's own write, which is a large one by right, and not in a motion write
        // that may share a step of the funnel.
        let early = toggled && tapped && self.begun && now_ms >= self.next_frame_ms;
        if toggled {
            self.drain.set_paused(left.is_some());
        }
        if early {
            // A tap that comes in the turn of a frame: the key's write goes ahead of the frame's.
            self.still(true)?;
        }
        if !self.begun || now_ms >= self.next_frame_ms {
            self.frame(now_ms, now_unix)?;
        }
        if (urgent && !early) || self.still_is_due(now_ms) {
            self.still(urgent)?;
        }
        let mut next_ms = self.next_frame_ms;
        if !self.still_done && self.still_window_open(now_ms) && self.shown != self.wanted {
            next_ms = next_ms.min(self.last_frame_ms.saturating_add(STILL_OFFSET_MS));
        }
        Ok(next_ms.saturating_sub(now_ms))
    }

    /// Whether a figure may still be written in this frame: `FLUSH_GUARD_MS` or more is left before the next frame.
    fn still_window_open(&self, now_ms: u64) -> bool {
        now_ms < self.last_frame_ms.saturating_add(FRAME_MS - FLUSH_GUARD_MS)
    }

    /// Whether a figure is to be drawn now: this frame's write is not done, there is one to make, half a frame has passed, and it is not late in the frame.
    fn still_is_due(&self, now_ms: u64) -> bool {
        !self.still_done
            && now_ms >= self.last_frame_ms.saturating_add(STILL_OFFSET_MS)
            && self.still_window_open(now_ms)
            && self.shown != self.wanted
    }

    /// Makes a frame: takes the names, asks for the numbers when they are due, and moves and draws the Drain.
    fn frame(&mut self, now_ms: u64, now_unix: u64) -> io::Result<()> {
        let first = !self.begun;
        self.begun = true;
        if first {
            // The lane's quiet is counted from the panel's first frame, not from the thread's start.
            self.last_name_ms = now_ms;
        }
        self.last_frame_ms = now_ms;
        self.still_done = false;
        // The frames keep their beat, unless the thread was held up for a frame or more.
        self.next_frame_ms = match self.next_frame_ms.saturating_add(FRAME_MS) {
            next if next > now_ms => next,
            _ => now_ms.saturating_add(FRAME_MS),
        };

        // The pause is known first, so that a refused name that arrives during one is shown as listed.
        let paused = self.left.is_some();
        self.drain.set_paused(paused);
        self.arrivals.clear();
        self.deps.lane.take(&mut self.arrivals);
        if !self.arrivals.is_empty() {
            self.last_name_ms = now_ms;
        }
        for arrival in self.arrivals.drain(..) {
            self.drain.offer(&arrival.name, arrival.kind);
        }
        if first || now_ms >= self.next_snapshot_ms {
            self.refresh(now_ms, now_unix);
            self.next_snapshot_ms = now_ms.saturating_add(SNAPSHOT_MS);
        }
        let moving = self.drain.moving();
        if moving {
            self.drain.tick(paused);
        }
        // The count is the Drain's: it holds back the refused names that have not melted yet. It is a
        // dash while the Wi-Fi is not joined: `refresh` gave the Drain no figure then, and a Drain
        // with no figure has no count, whatever names it carries.
        self.wanted.count = self.drain.count();
        if first {
            // The screen has nothing yet: it gets everything known at once.
            self.shown.clone_from(&self.wanted);
            self.shown_alert = self.wanted_alert;
            return self.draw();
        }
        if moving { self.draw() } else { Ok(()) }
    }

    /// Asks the system for its numbers and the store for the alert to show, and works out the figures that are wanted.
    ///
    /// `now_ms` times how long the lane has been without a name, for its `QUIET` words.
    fn refresh(&mut self, now_ms: u64, now_unix: u64) {
        let snapshot = self.deps.source.snapshot();
        let top = self.deps.alerts.top();
        let idle_secs = now_ms.saturating_sub(self.last_name_ms) / 1_000;
        self.wanted = wanted_stills(&snapshot, self.left, now_unix, idle_secs, top.as_ref());
        self.wanted_alert = top.map(|alert| alert.id);
        self.drain.set_blocked_today(self.wanted.count);
        self.follow_alert();
    }

    /// Draws one figure that is not as wanted, or, when a tap asked for a draw, whatever there is.
    fn still(&mut self, urgent: bool) -> io::Result<()> {
        self.still_done = true;
        let stepped = self.shown.step_toward(&self.wanted);
        self.follow_alert();
        if stepped || urgent {
            self.draw()?;
        }
        Ok(())
    }

    /// Paints the scene with the figures that are shown, and writes the frame if it differs from the one on the screen.
    fn draw(&mut self) -> io::Result<()> {
        match self.painter.paint_changed(&self.drain, &self.shown) {
            Some(frame) => self.surface.show(frame),
            None => Ok(()),
        }
    }
}

/// Finds the touch screen's device file, waiting up to `wait` for its driver to make it.
///
/// The device is looked for at least once, and then every 50 ms until it is there or `wait` has passed.
fn await_touch(sys_input: &Path, dev_input: &Path, wait: Duration) -> Option<PathBuf> {
    let asked = Instant::now();
    loop {
        match find_touch(sys_input, dev_input) {
            None if asked.elapsed() < wait => {
                thread::sleep(SCREEN_POLL.min(wait.saturating_sub(asked.elapsed())));
            }
            found => return found,
        }
    }
}

/// Measures the touch screen if the boot asks for it, and goes on with what was measured.
///
/// Without a touch device there is nothing to tap with, and nothing is asked
/// of the screen. A calibration that is not made, because a cross was not
/// tapped or the taps do not fit the crosses, leaves the configured one in
/// place; the result is logged and written nowhere. Fails only when the screen
/// or the device does.
fn measure_touch<S: Surface, D: Read + AsFd>(
    panel: &mut Panel<S>,
    device: Option<&mut D>,
) -> Result<(), PanelEnd> {
    let Some(device) = device.filter(|_| panel.deps.calibrate) else {
        return Ok(());
    };
    let began = Instant::now();
    let (calibration, decoder) = (panel.deps.calibration, &mut panel.decoder);
    let measured = calibrate::calibrate(
        &mut panel.surface,
        &mut |wait_ms| {
            let events = read_events(&mut *device, Duration::from_millis(wait_ms))?;
            // The decoder is told what the calibration reads too, though nothing it says is taken:
            // the kernel sends an axis only when its value changes, so the panel's first tap can
            // depend on a reading that only a tap of the calibration carried. A tap of the
            // calibration is no tap on the switch, so the tracker is not told.
            for &event in &events {
                decoder.feed(event, &calibration);
            }
            Ok(events)
        },
        &|| u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX),
    )
    .map_err(|error| PanelEnd::Failed(format!("calibrating the touch screen: {error}")))?;
    if let Some(calibration) = measured {
        panel.deps.calibration = calibration;
    }
    Ok(())
}

/// The clock in Unix seconds; 0 if it is before 1970.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Draws the panel and works its key for as long as the screen and the touch device allow.
///
/// Each round gives the panel what the touch device said, lets it draw if a
/// draw is due, and then waits for the touch device for as long as the panel
/// can go without a turn: never longer than a frame. Without a device it only
/// waits. Returns only when the screen or the device breaks.
fn serve<S: Surface, D: Read + AsFd>(
    panel: &mut Panel<S>,
    mut device: Option<D>,
    began: Instant,
) -> PanelEnd {
    let mut events = Vec::new();
    loop {
        panel.touch(&events);
        let now_ms = u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX);
        let wait = match panel.turn(now_ms, unix_now()) {
            Ok(wait_ms) => Duration::from_millis(wait_ms),
            Err(error) => return PanelEnd::Failed(format!("writing the screen: {error}")),
        };
        match device.as_mut() {
            Some(device) => match read_events(device, wait) {
                Ok(read) => events = read,
                Err(error) => {
                    return PanelEnd::Failed(format!("reading the touch device: {error}"));
                }
            },
            None => thread::sleep(wait),
        }
    }
}

/// The panel's thread: brings the screen up, draws on it for ever and works its key.
///
/// Returns only when the panel cannot go on, and says why. A board whose
/// touch screen is not found keeps its panel, with one warning: it is only
/// the switch that does not work.
pub fn run(deps: Deps) -> PanelEnd {
    let screen = match bring_up(&Roots::real(), &mut sys::insert_module, SCREEN_WAIT) {
        Ok(screen) => screen,
        Err(end) => return end,
    };
    let framebuffer = match Framebuffer::open(&screen.device) {
        Ok(framebuffer) => framebuffer,
        Err(error) => {
            return PanelEnd::Failed(format!("opening {}: {error}", screen.device.display()));
        }
    };
    let mut device = match await_touch(Path::new(SYS_INPUT), Path::new(DEV_INPUT), SCREEN_WAIT) {
        None => {
            log::warn!("panel: no ADS7846 touch device; the switch will not work");
            None
        }
        Some(path) => File::open(&path)
            .inspect_err(|error| {
                log::warn!(
                    "panel: opening {}: {error}; the switch will not work",
                    path.display()
                );
            })
            .ok(),
    };
    let mut panel = Panel::new(framebuffer, deps);
    if let Err(end) = measure_touch(&mut panel, device.as_mut()) {
        return end;
    }
    serve(&mut panel, device, Instant::now())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::io::{self, Write};
    use std::ops::Deref;
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    use qb_panel::drain::{QUEUE_MAX, TileStyle};
    use qb_panel::rows::changed_rows;
    use qb_panel::{Blocking, Calibration, LaneWords, Share, TimeOfDay};
    use tempfile::TempDir;

    use crate::live::{BlockingControl, Counts, LogEntry, Nothing, Snapshot, Source, WifiStatus};
    use crate::modules::DEFAULT_TABLE;
    use alerts::{NoAlerts, PanelAlert, Severity};
    use calibrate::Reading;
    use calibrate::tests::{assert_close, kernel_press, press, raw_at};
    use fb::tests::{Graphics, HDMI, graphics};
    use touch::tests::{abs_x, abs_y, bytes_of, dropped, key, pressure, syn};
    use view::tests::{TEN_TWENTY_UTC, reference_snapshot};

    /// Every frame a `Recorder` was shown, readable from where the `Recorder` was handed over.
    #[derive(Clone, Default)]
    pub(crate) struct Frames(Arc<Mutex<Vec<Vec<u8>>>>);

    impl Frames {
        pub(crate) fn count(&self) -> usize {
            self.0.lock().unwrap().len()
        }

        pub(crate) fn last(&self) -> Vec<u8> {
            self.0.lock().unwrap().last().unwrap().clone()
        }

        /// Every frame shown so far, the first first.
        pub(crate) fn all(&self) -> Vec<Vec<u8>> {
            self.0.lock().unwrap().clone()
        }
    }

    /// A surface that keeps every frame it is shown.
    pub(crate) struct Recorder(Frames);

    impl Surface for Recorder {
        fn show(&mut self, frame: &[u8]) -> io::Result<()> {
            (self.0).0.lock().unwrap().push(frame.to_vec());
            Ok(())
        }
    }

    pub(crate) fn recorder() -> (Recorder, Frames) {
        let frames = Frames::default();
        (Recorder(frames.clone()), frames)
    }

    /// A surface that cannot be written to.
    struct Broken;

    impl Surface for Broken {
        fn show(&mut self, _frame: &[u8]) -> io::Result<()> {
            Err(io::Error::other("the screen is gone"))
        }
    }

    /// A source that knows one snapshot.
    struct Fixed(Snapshot);

    impl Source for Fixed {
        fn snapshot(&self) -> Snapshot {
            self.0.clone()
        }

        fn recent(&self, _n: usize) -> Vec<LogEntry> {
            Vec::new()
        }
    }

    /// What the panel's switch controls, as a test sees it: the calls it was given, and the time it says is left.
    #[derive(Clone, Default)]
    struct FakeControl(Arc<Mutex<FakeControlState>>);

    #[derive(Default)]
    struct FakeControlState {
        calls: Vec<String>,
        left: Option<u16>,
    }

    impl FakeControl {
        fn calls(&self) -> Vec<String> {
            self.0.lock().unwrap().calls.clone()
        }

        /// Makes the control say that `left` seconds of a pause are left.
        fn set_left(&self, left: Option<u16>) {
            self.0.lock().unwrap().left = left;
        }
    }

    impl BlockingControl for FakeControl {
        fn paused_left_secs(&self) -> Option<u16> {
            self.0.lock().unwrap().left
        }

        fn pause_for(&self, secs: u16) {
            let mut state = self.0.lock().unwrap();
            state.calls.push(format!("pause {secs}"));
            state.left = Some(secs);
        }

        fn resume(&self) {
            let mut state = self.0.lock().unwrap();
            state.calls.push("resume".to_owned());
            state.left = None;
        }
    }

    /// The clock in these tests, in Unix seconds: 10:20 at UTC.
    const UNIX: u64 = TEN_TWENTY_UTC;

    /// What the panel reads of the alerts, as a test sees it: the alert on offer, and the acks it was told of.
    #[derive(Clone, Default)]
    struct FakeAlerts(Arc<Mutex<FakeAlertsState>>);

    #[derive(Default)]
    struct FakeAlertsState {
        alert: Option<PanelAlert>,
        acks: Vec<u64>,
    }

    impl FakeAlerts {
        /// Puts `alert` on offer, or takes the one there is away.
        fn set(&self, alert: Option<PanelAlert>) {
            self.0.lock().unwrap().alert = alert;
        }

        fn acks(&self) -> Vec<u64> {
            self.0.lock().unwrap().acks.clone()
        }
    }

    impl alerts::PendingAlerts for FakeAlerts {
        fn top(&self) -> Option<PanelAlert> {
            self.0.lock().unwrap().alert.clone()
        }

        /// As a store does: an acknowledged alert is no longer on offer.
        fn ack(&self, id: u64) {
            let mut state = self.0.lock().unwrap();
            state.acks.push(id);
            if state.alert.as_ref().is_some_and(|alert| alert.id == id) {
                state.alert = None;
            }
        }
    }

    /// A high alert about a name, for the device at 192.0.2.23.
    fn threat(id: u64) -> PanelAlert {
        PanelAlert {
            id,
            kind: "threat".into(),
            severity: Severity::High,
            client: Some("192.0.2.23".parse().unwrap()),
            subject: "secure-login-verify.example.org".into(),
        }
    }

    /// The panel's dependencies with a control nobody looks at, the nominal calibration, a lane nobody feeds and no alerts.
    fn deps(source: Arc<dyn Source>) -> Deps {
        Deps {
            source,
            control: Arc::new(FakeControl::default()),
            calibration: Calibration::NOMINAL,
            calibrate: false,
            lane: LaneFeed::new(),
            alerts: Arc::new(NoAlerts),
        }
    }

    /// A panel that knows nothing, the frames it writes, and the control its key works.
    fn panel() -> (Panel<Recorder>, Frames, FakeControl) {
        let (surface, frames) = recorder();
        let control = FakeControl::default();
        let panel = Panel::new(
            surface,
            Deps {
                control: Arc::new(control.clone()),
                ..deps(Arc::new(Nothing))
            },
        );
        (panel, frames, control)
    }

    /// A panel with every hand a test reaches it by: what it is shown, what its key controls,
    /// the feed of names and the alerts.
    struct Rig {
        panel: Panel<Recorder>,
        frames: Frames,
        control: FakeControl,
        lane: Arc<LaneFeed>,
        alerts: FakeAlerts,
    }

    impl Rig {
        fn new(source: Arc<dyn Source>) -> Self {
            let (surface, frames) = recorder();
            let (control, lane, alerts) = (
                FakeControl::default(),
                LaneFeed::new(),
                FakeAlerts::default(),
            );
            let panel = Panel::new(
                surface,
                Deps {
                    source,
                    control: Arc::new(control.clone()),
                    calibration: Calibration::NOMINAL,
                    calibrate: false,
                    lane: lane.clone(),
                    alerts: Arc::new(alerts.clone()),
                },
            );
            Self {
                panel,
                frames,
                control,
                lane,
                alerts,
            }
        }

        /// Turns the panel at `now_ms`, with the clock at 10:20, and returns how long it may wait.
        fn turn(&mut self, now_ms: u64) -> u64 {
            self.panel.turn(now_ms, UNIX).unwrap()
        }

        /// The resolver refuses `name`.
        fn refuse(&self, name: &str) {
            self.lane.observe(name, true, 0, |_| false);
        }

        /// Turns the panel as its own waits ask, from `*now` up to `until`; returns what was written.
        fn drive(&mut self, now: &mut u64, until: u64) -> Vec<Written> {
            let before = self.frames.count();
            let mut times = Vec::new();
            let mut seen = before;
            while *now <= until {
                let wait = self.turn(*now);
                assert!(wait <= FRAME_MS, "waits {wait} ms at {now}");
                for _ in seen..self.frames.count() {
                    times.push(*now);
                }
                seen = self.frames.count();
                *now += wait.max(1);
            }
            let all = self.frames.all();
            times
                .into_iter()
                .enumerate()
                .map(|(n, at)| {
                    let index = before + n;
                    let rows = index.checked_sub(1).map(|previous| {
                        changed_rows(&all[previous], &all[index], WIDTH * 2)
                            .map_or(0, |rows| rows.len())
                    });
                    Written { at, rows }
                })
                .collect()
        }
    }

    /// A frame that was written: when, and how many rows from the first changed to the last it differs
    /// from the frame before by; `None` for the very first.
    #[derive(Debug)]
    struct Written {
        at: u64,
        rows: Option<usize>,
    }

    /// The panel as it draws an empty lane, with the Wi-Fi not joined and nothing known but blocking
    /// `blocking`, and the gate refilled `gate_fill` steps.
    fn frame_with_fill(blocking: Blocking, gate_fill: u8) -> Vec<u8> {
        let stills = Stills {
            blocking,
            gate_fill,
            words: Some(LaneWords::Joining),
            ..Stills::default()
        };
        Painter::new()
            .paint(&Drain::new(DRAIN_SEED), &stills)
            .to_vec()
    }

    /// The panel as it draws an empty lane and nothing known but blocking `blocking`, and the gate not refilled.
    fn frame_of(blocking: Blocking) -> Vec<u8> {
        frame_with_fill(blocking, 0)
    }

    /// The events of one press at the raw reading `raw`: down at `at`, lifted `held_ms` later.
    fn tap(at: u64, held_ms: u64, raw: (i32, i32)) -> Vec<RawEvent> {
        vec![
            key(at, 1),
            abs_x(at, raw.0),
            abs_y(at, raw.1),
            syn(at),
            key(at + held_ms, 0),
            syn(at + held_ms),
        ]
    }

    /// The raw reading that `Calibration::NOMINAL` maps onto the switch, to (40, 290).
    const ON_SWITCH: (i32, i32) = (509, 3564);
    /// The raw reading that `Calibration::NOMINAL` maps onto the middle of the screen, to (240, 100).
    const ELSEWHERE: (i32, i32) = (2054, 1360);

    /// Temporary `Roots` and the directories that hold them, which go when this does.
    struct Fixture {
        roots: Roots,
        _dirs: Vec<TempDir>,
    }

    impl Deref for Fixture {
        type Target = Roots;

        fn deref(&self) -> &Roots {
            &self.roots
        }
    }

    /// Roots of a board with the given framebuffers: the image's module table, an empty `/dev`,
    /// and a text console on a framebuffer that is bound.
    fn roots(framebuffers: &[Graphics]) -> Fixture {
        let graphics = graphics(framebuffers);
        let files = tempfile::tempdir().unwrap();
        let module_list = files.path().join("modules.list");
        fs::write(&module_list, DEFAULT_TABLE).unwrap();
        let vtconsole = tempfile::tempdir().unwrap();
        for (dir, name, bind) in [
            ("vtcon0", "(S) dummy device\n", "0\n"),
            ("vtcon1", "(M) frame buffer device\n", "1\n"),
        ] {
            fs::create_dir(vtconsole.path().join(dir)).unwrap();
            fs::write(vtconsole.path().join(dir).join("name"), name).unwrap();
            fs::write(vtconsole.path().join(dir).join("bind"), bind).unwrap();
        }
        let dev = tempfile::tempdir().unwrap();
        Fixture {
            roots: Roots {
                module_list,
                sys_graphics: graphics.path().to_owned(),
                sys_vtconsole: vtconsole.path().to_owned(),
                dev: dev.path().to_owned(),
            },
            _dirs: vec![graphics, files, vtconsole, dev],
        }
    }

    /// The screen as the kernel lists it.
    const SCREEN: Graphics = ("fb1", "fb_ili9486", "480,320", "16");

    #[test]
    fn names_from_the_lane_move_at_eight_frames_a_second() {
        let mut rig = Rig::new(Arc::new(Nothing));
        rig.refuse("doubleclick.net");
        let mut now = 0;
        let writes = rig.drive(&mut now, 8_000);
        // The panel is turned at 0, 125, 250, ...: nothing else is due, for no figure changes.
        assert_eq!(writes[0].at, 0);
        for write in &writes {
            assert_eq!(write.at % FRAME_MS, 0, "{write:?}");
            // Each write fits a quarter of the screen, as the budget has it.
            assert!(write.rows.is_none_or(|rows| rows <= 80), "{write:?}");
        }
        // The name is in motion for some forty frames: the lane, then seventeen steps of the refusal.
        assert!(writes.len() >= 25, "{} writes", writes.len());
        let gaps: Vec<u64> = writes
            .windows(2)
            .map(|pair| pair[1].at - pair[0].at)
            .collect();
        assert!(gaps.iter().all(|gap| gap % FRAME_MS == 0), "{gaps:?}");
        // Steps of the refusal that move nothing on the screen write nothing, and leave a gap of two
        // frames: the hold, and the count (the figure is not on the screen here). The drop at the
        // spout is painted, so it writes.
        assert_eq!(
            gaps.iter().filter(|&&gap| gap == 2 * FRAME_MS).count(),
            2,
            "{gaps:?}"
        );
        assert!(gaps.iter().all(|&gap| gap <= 2 * FRAME_MS), "{gaps:?}");
        // When the name is done the panel is idle: no write for the last seconds.
        let last = writes.last().unwrap().at;
        assert!(last < 6_000, "{last}");
        let rows: Vec<usize> = writes.iter().filter_map(|write| write.rows).collect();
        eprintln!(
            "rows per write, one refused name: max {}, mean {:.1} over {} writes: {rows:?}",
            rows.iter().max().unwrap(),
            rows.iter().sum::<usize>() as f64 / rows.len() as f64,
            rows.len()
        );
    }

    #[test]
    fn an_idle_panel_paints_nothing() {
        let mut rig = Rig::new(Arc::new(Fixed(reference_snapshot())));
        let mut now = 0;
        let writes = rig.drive(&mut now, 10_000);
        assert_eq!(writes.len(), 1, "{writes:?}");
        assert_eq!(writes[0].at, 0);
        // The panel did look: it was turned every frame for ten seconds.
        assert!(now > 10_000);
    }

    #[test]
    fn a_turn_that_comes_late_makes_one_frame_and_counts_the_beat_from_it() {
        let mut rig = Rig::new(Arc::new(Nothing));
        rig.refuse("doubleclick.net");
        assert_eq!(rig.turn(0), FRAME_MS);
        assert_eq!(rig.turn(124), 1);
        assert_eq!(rig.frames.count(), 1);
        // The thread was held up for half a minute: one frame, not two hundred and forty.
        assert_eq!(rig.turn(30_000), FRAME_MS);
        assert_eq!(rig.frames.count(), 2);
        assert_eq!(rig.turn(30_124), 1);
        assert_eq!(rig.frames.count(), 2);
    }

    #[test]
    fn the_first_frame_is_the_panel_of_what_is_known_now() {
        let (mut panel, frames, _) = panel();
        panel.turn(0, UNIX).unwrap();
        assert_eq!(frames.count(), 1);
        assert!(frames.last() == frame_of(Blocking::On));

        let mut rig = Rig::new(Arc::new(Fixed(reference_snapshot())));
        rig.turn(0);
        let mut drain = Drain::new(DRAIN_SEED);
        drain.set_blocked_today(Some(4_780));
        let stills = Stills {
            percent: Some(Share::Percent(44)),
            clock: Some(TimeOfDay {
                hour: 10,
                minute: 20,
            }),
            blocking: Blocking::On,
            gate_fill: 0,
            count: Some(4_780),
            alert: None,
            words: None,
        };
        assert_eq!(rig.frames.count(), 1);
        assert!(rig.frames.last() == Painter::new().paint(&drain, &stills));
    }

    #[test]
    fn wanted_stills_from_the_reference_snapshot() {
        let mut rig = Rig::new(Arc::new(Fixed(reference_snapshot())));
        // A refused name is on its way: the count is the Drain's, and holds it back.
        rig.refuse("doubleclick.net");
        rig.turn(0);
        let shown = rig.panel.shown.clone();
        assert_eq!(shown.percent, Some(Share::Percent(44)));
        assert_eq!(
            shown.clock,
            Some(TimeOfDay {
                hour: 10,
                minute: 20
            })
        );
        assert_eq!(
            (shown.count, rig.panel.drain.count()),
            (Some(4_779), Some(4_779))
        );
        assert_eq!(rig.panel.wanted, shown);

        // Without the clock set there is no time of day.
        let unset = Snapshot {
            clock_set: false,
            ..reference_snapshot()
        };
        let mut rig = Rig::new(Arc::new(Fixed(unset)));
        rig.turn(0);
        assert_eq!(rig.panel.shown.clock, None);
        assert_eq!(rig.panel.shown.percent, Some(Share::Percent(44)));
    }

    #[test]
    fn a_count_that_rises_is_written_on_its_own_half_a_frame_after_the_lane() {
        let mut rig = Rig::new(Arc::new(Fixed(reference_snapshot())));
        rig.refuse("doubleclick.net");
        let mut now = 0;
        let writes = rig.drive(&mut now, 6_000);
        let late: Vec<&Written> = writes
            .iter()
            .filter(|write| write.at % FRAME_MS == STILL_OFFSET_MS)
            .collect();
        // One figure changed: the count, 4,779 to 4,780, when the name melted away.
        assert_eq!(late.len(), 1, "{writes:?}");
        assert!(late[0].rows.is_some_and(|rows| rows <= 80), "{late:?}");
        assert!(
            writes
                .iter()
                .all(|write| write.at % FRAME_MS == 0 || write.at % FRAME_MS == STILL_OFFSET_MS),
            "{writes:?}"
        );
        assert!(
            writes
                .iter()
                .all(|write| write.rows.is_none_or(|rows| rows <= 80)),
            "{writes:?}"
        );
        assert_eq!(rig.panel.shown.count, Some(4_780));
    }

    #[test]
    fn a_screen_that_cannot_be_written_ends_the_turn_with_its_error() {
        let error = Panel::new(Broken, deps(Arc::new(Nothing)))
            .turn(0, UNIX)
            .unwrap_err();
        assert_eq!(error.to_string(), "the screen is gone");
    }

    #[test]
    fn a_board_without_the_screen_is_no_screen_not_a_failure() {
        let r = roots(&[HDMI]);
        assert_eq!(
            bring_up(&r, &mut |_, _| Ok(()), Duration::ZERO),
            Err(PanelEnd::NoScreen("no fb_ili9486 framebuffer".into()))
        );
    }

    #[test]
    fn a_driver_that_does_not_load_is_no_screen_and_names_the_module() {
        let r = roots(&[HDMI, SCREEN]);
        let mut insert = |file: &Path, _: &str| {
            if file.ends_with("fbtft.ko") {
                Err(io::Error::other("bad signature"))
            } else {
                Ok(())
            }
        };
        assert_eq!(
            bring_up(&r, &mut insert, Duration::ZERO),
            Err(PanelEnd::NoScreen(
                "loading fb_ili9486: bad signature".into()
            ))
        );
    }

    #[test]
    fn a_module_list_that_cannot_be_read_is_no_screen_and_names_the_file() {
        let r = roots(&[HDMI, SCREEN]);
        fs::remove_file(&r.module_list).unwrap();
        match bring_up(&r, &mut |_, _| Ok(()), Duration::ZERO) {
            Err(PanelEnd::NoScreen(why)) => assert!(why.contains("modules.list"), "{why}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_modules_of_the_screen_and_the_touch_controller_are_loaded_in_order() {
        let r = roots(&[HDMI, SCREEN]);
        let mut files = Vec::new();
        let mut insert = |file: &Path, _: &str| {
            files.push(file.file_name().unwrap().to_str().unwrap().to_owned());
            Ok(())
        };
        bring_up(&r, &mut insert, Duration::ZERO).unwrap();
        assert_eq!(
            files,
            [
                "spi-bcm2835.ko",
                "backlight.ko",
                "fbtft.ko",
                "fb_ili9486.ko",
                "ads7846.ko"
            ]
        );
    }

    #[test]
    fn a_screen_in_another_rotation_is_refused() {
        let r = roots(&[HDMI, ("fb1", "fb_ili9486", "320,480", "16")]);
        assert!(matches!(
            bring_up(&r, &mut |_, _| Ok(()), Duration::ZERO),
            Err(PanelEnd::NoScreen(why)) if why.contains("320,480")
        ));
    }

    #[test]
    fn the_console_is_taken_off_the_screen_only_when_it_is_the_only_framebuffer() {
        let alone = roots(&[("fb0", "fb_ili9486", "480,320", "16")]);
        assert_eq!(
            bring_up(&alone, &mut |_, _| Ok(()), Duration::ZERO)
                .unwrap()
                .device,
            alone.dev.join("fb0")
        );
        assert_eq!(
            fs::read_to_string(alone.sys_vtconsole.join("vtcon1/bind")).unwrap(),
            "0"
        );
        let beside_hdmi = roots(&[HDMI, SCREEN]);
        bring_up(&beside_hdmi, &mut |_, _| Ok(()), Duration::ZERO).unwrap();
        assert_eq!(
            fs::read_to_string(beside_hdmi.sys_vtconsole.join("vtcon1/bind")).unwrap(),
            "1\n"
        );
    }

    #[test]
    fn a_screen_that_appears_while_its_driver_comes_up_is_waited_for() {
        let r = roots(&[HDMI]);
        let appearing = graphics(&[SCREEN]);
        thread::scope(|scope| {
            scope.spawn(|| {
                thread::sleep(Duration::from_millis(150));
                // Whole, so that it is never seen half made.
                fs::rename(appearing.path().join("fb1"), r.sys_graphics.join("fb1")).unwrap();
            });
            let screen = bring_up(&r, &mut |_, _| Ok(()), Duration::from_secs(30)).unwrap();
            assert_eq!(screen.device, r.dev.join("fb1"));
        });
    }

    #[test]
    fn a_screen_that_never_appears_is_waited_for_as_long_as_asked_and_no_longer() {
        let r = roots(&[HDMI]);
        let began = Instant::now();
        let outcome = bring_up(&r, &mut |_, _| Ok(()), Duration::from_millis(200));
        assert_eq!(
            outcome,
            Err(PanelEnd::NoScreen("no fb_ili9486 framebuffer".into()))
        );
        assert!(began.elapsed() >= Duration::from_millis(200));
        assert!(began.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn a_tap_on_the_key_pauses_and_the_countdown_steps() {
        let (mut panel, frames, control) = panel();
        panel.turn(0, UNIX).unwrap();
        // Both halves in one read: timed by the events, not by the read.
        panel.touch(&tap(1_000, 60, ON_SWITCH));
        assert_eq!(control.calls(), ["pause 300"]);
        // Drawn now, between the beats, and the control is asked again within a frame.
        assert!(panel.turn(1_010, UNIX).unwrap() <= FRAME_MS);
        assert_eq!(frames.count(), 2);
        assert!(frames.last() == frame_of(Blocking::Paused { left_secs: 300 }));
        // The control's seconds step, on its own clock: the next frame notices, and half a frame
        // later the new figure is written, and nothing else.
        control.set_left(Some(299));
        assert_eq!(panel.turn(1_135, UNIX).unwrap(), STILL_OFFSET_MS);
        assert_eq!(frames.count(), 2);
        assert_eq!(
            panel.turn(1_135 + STILL_OFFSET_MS, UNIX).unwrap(),
            FRAME_MS - STILL_OFFSET_MS
        );
        assert_eq!(frames.count(), 3);
        assert!(frames.last() == frame_of(Blocking::Paused { left_secs: 299 }));
        // The same seconds again: nothing to write.
        for at in [1_260, 1_322, 1_385, 1_447] {
            panel.turn(at, UNIX).unwrap();
        }
        assert_eq!(frames.count(), 3);
    }

    #[test]
    fn a_tap_while_paused_resumes() {
        let (mut panel, frames, control) = panel();
        control.set_left(Some(120));
        panel.touch(&tap(1_000, 60, ON_SWITCH));
        assert_eq!(control.calls(), ["resume"]);
        assert_eq!(panel.turn(1_100, UNIX).unwrap(), FRAME_MS);
        assert!(frames.last() == frame_of(Blocking::On));
    }

    #[test]
    fn a_brush_and_a_tap_elsewhere_change_nothing() {
        let (mut panel, frames, control) = panel();
        panel.turn(0, UNIX).unwrap();
        panel.touch(&tap(1_000, 30, ON_SWITCH));
        // Where the alert's card would be, there is no card: a tap there does nothing.
        panel.touch(&tap(2_000, 200, ELSEWHERE));
        panel.turn(2_500, UNIX).unwrap();
        assert!(control.calls().is_empty());
        assert_eq!(frames.count(), 1);
    }

    #[test]
    fn a_finger_left_on_the_switch_toggles_once_when_it_lifts() {
        let (mut panel, _, control) = panel();
        panel.touch(&tap(1_000, 240_000, ON_SWITCH));
        assert_eq!(control.calls(), ["pause 300"]);
    }

    #[test]
    fn a_press_cut_off_by_lost_events_does_not_toggle() {
        let (mut panel, _, control) = panel();
        let press = tap(1_000, 200, ON_SWITCH);
        // `tap` is four events down, two up.
        let (down, up) = press.split_at(4);
        panel.touch(down);
        panel.touch(&[dropped(1_100)]);
        panel.touch(up);
        assert!(control.calls().is_empty());
    }

    #[test]
    fn a_press_whose_first_sample_was_lost_does_not_toggle_either() {
        let (mut panel, _, control) = panel();
        // A touch too light to count: the glass is down, but no touch was ever given out.
        panel.touch(&[
            key(1_000, 1),
            abs_x(1_000, ON_SWITCH.0),
            abs_y(1_000, ON_SWITCH.1),
            pressure(1_000, 5),
            syn(1_000),
        ]);
        // Then the kernel loses events, which is `Lost` for a press that never had a `Down`.
        panel.touch(&[dropped(1_040), key(1_300, 0), syn(1_300)]);
        assert!(control.calls().is_empty());
        // The next press is whole again.
        panel.touch(&[pressure(1_900, 180)]);
        panel.touch(&tap(2_000, 60, ON_SWITCH));
        assert_eq!(control.calls(), ["pause 300"]);
    }

    #[test]
    fn a_pause_that_ends_by_itself_is_drawn_within_a_beat_and_a_half() {
        let (mut panel, frames, control) = panel();
        control.set_left(Some(1));
        assert_eq!(panel.turn(0, UNIX).unwrap(), FRAME_MS);
        // Everything known is on the first frame, the gate nearly refilled.
        assert!(frames.last() == frame_with_fill(Blocking::Paused { left_secs: 1 }, 18));
        control.set_left(None);
        // The next frame notices, and half a frame later the key is on again.
        assert_eq!(panel.turn(FRAME_MS, UNIX).unwrap(), STILL_OFFSET_MS);
        assert_eq!(frames.count(), 1);
        assert_eq!(
            panel.turn(FRAME_MS + STILL_OFFSET_MS, UNIX).unwrap(),
            FRAME_MS - STILL_OFFSET_MS
        );
        assert_eq!(frames.count(), 2);
        assert!(frames.last() == frame_of(Blocking::On));
        // The refill is its own figure and goes back to nothing in the next slot, which changes
        // nothing a shut gate shows: no write. Then the panel is calm again.
        assert_eq!(panel.turn(2 * FRAME_MS, UNIX).unwrap(), STILL_OFFSET_MS);
        assert_eq!(
            panel.turn(2 * FRAME_MS + STILL_OFFSET_MS, UNIX).unwrap(),
            FRAME_MS - STILL_OFFSET_MS
        );
        assert_eq!(panel.turn(3 * FRAME_MS, UNIX).unwrap(), FRAME_MS);
        assert_eq!(frames.count(), 2);
    }

    #[test]
    fn a_pause_that_began_without_a_tap_is_drawn_in_the_figures_slot() {
        let (mut panel, frames, control) = panel();
        assert_eq!(panel.turn(0, UNIX).unwrap(), FRAME_MS);
        control.set_left(Some(120));
        // Half a frame after the frame, when the figures are written, and not before.
        assert_eq!(panel.turn(10, UNIX).unwrap(), STILL_OFFSET_MS - 10);
        assert_eq!(frames.count(), 1);
        assert_eq!(
            panel.turn(STILL_OFFSET_MS, UNIX).unwrap(),
            FRAME_MS - STILL_OFFSET_MS
        );
        assert_eq!(frames.count(), 2);
        assert!(frames.last() == frame_of(Blocking::Paused { left_secs: 120 }));
    }

    #[test]
    fn a_figure_that_is_late_in_the_frame_waits_for_the_next_frames_slot() {
        let (mut panel, frames, control) = panel();
        assert_eq!(panel.turn(0, UNIX).unwrap(), FRAME_MS);
        control.set_left(Some(120));
        // Touch events that are no tap wake the loop at +120 ms: past the figures' slot, and in
        // the flush window of the next frame's write. The figure is not written, and the next
        // frame is the next thing to wait for.
        panel.touch(&tap(100, 10, ELSEWHERE));
        assert_eq!(panel.turn(120, UNIX).unwrap(), FRAME_MS - 120);
        assert_eq!(frames.count(), 1);
        // The frame has nothing to write either, and its slot comes half a frame later.
        assert_eq!(panel.turn(FRAME_MS, UNIX).unwrap(), STILL_OFFSET_MS);
        assert_eq!(frames.count(), 1);
        assert_eq!(
            panel.turn(FRAME_MS + STILL_OFFSET_MS, UNIX).unwrap(),
            FRAME_MS - STILL_OFFSET_MS
        );
        assert_eq!(frames.count(), 2);
        assert!(frames.last() == frame_of(Blocking::Paused { left_secs: 120 }));
    }

    #[test]
    fn a_tap_on_the_alert_acks_it_and_the_key_still_pauses() {
        let mut rig = Rig::new(Arc::new(Fixed(reference_snapshot())));
        rig.alerts.set(Some(threat(7)));
        rig.turn(0);
        assert!(rig.panel.shown.alert.is_some());
        assert_eq!(rig.frames.count(), 1);

        // A tap on the card acknowledges that alert, and nothing else.
        rig.panel.touch(&tap(1_000, 60, ELSEWHERE));
        assert_eq!(rig.alerts.acks(), [7]);
        assert!(rig.control.calls().is_empty());
        // The takeover is gone in the next frame, in a write of its own.
        rig.turn(1_000);
        assert!(rig.panel.shown.alert.is_none());
        assert_eq!(rig.frames.count(), 2);
        let mut drain = Drain::new(DRAIN_SEED);
        drain.set_blocked_today(Some(4_780));
        let clear = Stills {
            percent: Some(Share::Percent(44)),
            clock: Some(TimeOfDay {
                hour: 10,
                minute: 20,
            }),
            blocking: Blocking::On,
            gate_fill: 0,
            count: Some(4_780),
            alert: None,
            words: None,
        };
        assert!(rig.frames.last() == Painter::new().paint(&drain, &clear));

        // The next alert is the store's to offer: it takes the screen at the next snapshot.
        rig.alerts.set(Some(threat(8)));
        let mut now = 1_125;
        rig.drive(&mut now, 2_500);
        assert!(rig.panel.shown.alert.is_some());
        assert_eq!(rig.panel.shown_alert, Some(8));

        // The key works with the card up, and leaves the card where it is.
        rig.panel.touch(&tap(3_000, 60, ON_SWITCH));
        assert_eq!(rig.control.calls(), ["pause 300"]);
        assert!(rig.alerts.acks() == [7]);
        rig.turn(3_010);
        assert!(rig.panel.shown.alert.is_some());
        assert_eq!(
            rig.panel.shown.blocking,
            Blocking::Paused { left_secs: 300 }
        );

        // And the card, tapped again, is acknowledged by its own id. A tap on the key in the same
        // read is worked too, and each asks for its draw once.
        let mut both = tap(4_000, 60, ELSEWHERE);
        both.extend(tap(4_200, 60, ON_SWITCH));
        rig.panel.touch(&both);
        assert_eq!(rig.alerts.acks(), [7, 8]);
        assert_eq!(rig.control.calls(), ["pause 300", "resume"]);
        rig.turn(4_210);
        assert!(!rig.panel.tapped && !rig.panel.dismissed);
        assert!(rig.panel.shown.alert.is_none());
        assert_eq!(rig.panel.shown.blocking, Blocking::On);
    }

    #[test]
    fn an_alert_that_leaves_the_store_clears_the_takeover() {
        let mut rig = Rig::new(Arc::new(Fixed(reference_snapshot())));
        rig.alerts.set(Some(threat(7)));
        rig.turn(0);
        rig.alerts.set(None);
        let mut now = FRAME_MS;
        rig.drive(&mut now, 2_000);
        assert!(rig.panel.shown.alert.is_none());
        assert_eq!(rig.frames.count(), 2);
        // A tap where the card was does nothing now, and acknowledges nothing.
        rig.panel.touch(&tap(3_000, 60, ELSEWHERE));
        assert!(rig.alerts.acks().is_empty());
        // A tap that began on the card and lifts after the card has gone acknowledges nothing either.
        let mut rig = Rig::new(Arc::new(Fixed(reference_snapshot())));
        rig.alerts.set(Some(threat(7)));
        rig.turn(0);
        let press = tap(1_000, 200, ELSEWHERE);
        let (down, up) = press.split_at(4);
        rig.panel.touch(down);
        rig.alerts.set(None);
        let mut now = FRAME_MS;
        rig.drive(&mut now, 2_000);
        rig.panel.touch(up);
        assert!(rig.alerts.acks().is_empty());
    }

    /// A Wi-Fi link that is up.
    fn joined() -> WifiStatus {
        WifiStatus {
            associated: true,
            signal_dbm: Some(-63),
            ap: None,
        }
    }

    /// A source whose figures rise at every look, as a resolver's do under traffic.
    struct Counting(Mutex<(u64, u64)>);

    impl Source for Counting {
        fn snapshot(&self) -> Snapshot {
            let mut counts = self.0.lock().unwrap();
            counts.0 += 7;
            counts.1 += 3;
            Snapshot {
                wifi: Some(joined()),
                today: Some(Counts {
                    queries: counts.0,
                    blocked: counts.1,
                    blocked_threat: 0,
                    cache_hits: 0,
                    forwarded: 0,
                }),
                clock_set: true,
                ..Snapshot::default()
            }
        }

        fn recent(&self, _n: usize) -> Vec<LogEntry> {
            Vec::new()
        }
    }

    /// A surface that measures each frame against the one before, in rows from the first changed to
    /// the last, and keeps only the numbers.
    struct Measure {
        previous: Vec<u8>,
        rows: Arc<Mutex<Vec<usize>>>,
    }

    impl Surface for Measure {
        fn show(&mut self, frame: &[u8]) -> io::Result<()> {
            if !self.previous.is_empty() {
                let rows =
                    changed_rows(&self.previous, frame, WIDTH * 2).map_or(0, |rows| rows.len());
                self.rows.lock().unwrap().push(rows);
            }
            self.previous.clear();
            self.previous.extend_from_slice(frame);
            Ok(())
        }
    }

    #[test]
    fn steady_traffic_writes_at_most_eighty_rows_at_a_time() {
        let rows = Arc::new(Mutex::new(Vec::new()));
        let lane = LaneFeed::new();
        let mut panel = Panel::new(
            Measure {
                previous: Vec::new(),
                rows: rows.clone(),
            },
            Deps {
                lane: lane.clone(),
                ..deps(Arc::new(Counting(Mutex::new((0, 0)))))
            },
        );
        // Half a minute before the minute turns, so that the clock's figure changes during the run.
        let start = TEN_TWENTY_UTC + 30;
        let mut asked = 0;
        // How many frames the Drain's queue was full at, and how many refusals ran to the door reopening.
        let (mut full, mut refusals, mut door_was_shut) = (0, 0, false);
        for frame in 0..400_u64 {
            let at = frame * FRAME_MS;
            // A page load that never ends: a dozen refused names and a plain one in every frame, all
            // different, which is more than the feed holds. Each stays different after fitting to the
            // 15 cells of a refused name and the 20 of a plain one: `fit_site` drops host labels, so a
            // name made of a host in front of one site would be the same site for all of them.
            for n in 0..12 {
                lane.observe(&format!("a{frame:03}{n:02}.example"), true, frame, |_| {
                    false
                });
            }
            lane.observe(&format!("site{frame}.example.org"), false, frame, |_| false);
            asked += 13;
            for at in [at, at + STILL_OFFSET_MS] {
                panel.turn(at, start + at / 1_000).unwrap();
                refusals += usize::from(door_was_shut && !panel.drain.door_shut());
                door_was_shut = panel.drain.door_shut();
            }
            full += usize::from(panel.drain.queued() == QUEUE_MAX);
        }
        let rows = rows.lock().unwrap().clone();
        let (peak, total) = (rows.iter().max().unwrap(), rows.iter().sum::<usize>());
        let mut sorted = rows.clone();
        sorted.sort_unstable();
        eprintln!(
            "rows per write, 50 s of heavy traffic: {} writes, peak {peak}, p95 {}, mean {:.1}",
            rows.len(),
            sorted[sorted.len() * 95 / 100],
            total as f64 / rows.len() as f64
        );
        assert!(*peak <= 80, "peak {peak}");
        assert!(rows.len() > 300, "{} writes", rows.len());
        // The flood floods: the Drain's queue was full in nearly every frame, and refusal after refusal
        // ran at the lane's own pace, 15 frames to the gate, 17 steps and one to leave.
        eprintln!("the queue was full in {full} of 400 frames, {refusals} refusals ran");
        assert!(full >= 360, "the queue was full in {full} of 400 frames");
        assert!(refusals >= 10, "{refusals} refusals ran");
        // The lane took what it could and the rest were dropped, not queued.
        assert!(lane.dropped() > 0 && asked > 5_000);
        // The clock's minute turned (10:20 to 10:21) while the lane ran.
        assert_eq!(
            panel.shown.clock,
            Some(TimeOfDay {
                hour: 10,
                minute: 21
            })
        );
    }

    /// A refusal that is landing when the key is tapped, with a listed name on the lane: the lane's
    /// restyle goes out in the key's own write, and no motion write after it is over 80 rows. `early`
    /// has the tap come in the very turn of a frame.
    fn toggle_while_a_refusal_lands(early: bool) {
        let mut rig = Rig::new(Arc::new(Fixed(reference_snapshot())));
        // A listed name goes ahead of a refused one of 11 letters: the refused one stops at the gate and
        // melts while the listed one stands on the lane past it. The refusal's dots land at step 11,
        // which is a motion write to itself.
        rig.lane.observe("listed.example", false, 1, |_| true);
        rig.refuse("ads.example");
        let (mut now, land) = (0, 11);
        loop {
            let wait = rig.turn(now);
            if rig.panel.drain.refusal_step() == Some(land - 1) {
                break;
            }
            assert!(now < 20_000, "the refusal never got near its landing");
            now += wait.max(1);
        }
        assert!(
            rig.panel
                .drain
                .lane()
                .all(|tile| tile.style != TileStyle::Listed),
            "nothing is outlined while blocking is on"
        );
        // The tap comes half a frame after the frame, or in the turn of the next one.
        let at = if early { now + FRAME_MS } else { now + 30 };
        rig.panel.touch(&tap(at - 100, 60, ON_SWITCH));
        let before = rig.frames.count();
        rig.turn(at);
        let outlined = rig
            .panel
            .drain
            .lane()
            .any(|tile| tile.style == TileStyle::Listed);
        let mut now = at;
        while rig.panel.drain.moving() || now < at + 4 * FRAME_MS {
            now += rig.turn(now).max(1);
            assert!(now < 30_000, "the refusal never ended");
        }
        let all = rig.frames.all();
        let rows: Vec<usize> = (before..all.len())
            .map(|n| changed_rows(&all[n - 1], &all[n], WIDTH * 2).map_or(0, |rows| rows.len()))
            .collect();
        eprintln!("rows of the writes from a pause toggle on, a refusal landing: {rows:?}");
        // Every write but the key's own is a motion write or a figure, and fits. The landing is one of them.
        assert!(rows.iter().skip(1).all(|&rows| rows <= 80), "{rows:?}");
        // The first write is the key's: the gate and the key flip, and the lane's restyle is in it.
        assert!(
            rows[0] > 80,
            "the toggle's own write is a large one: {rows:?}"
        );
        assert!(
            outlined,
            "a listed name is on the lane, outlined now that blocking is paused"
        );
        assert!(
            rig.panel
                .drain
                .funnel()
                .iter()
                .filter(|cell| cell.shade.is_some())
                .count()
                >= 11,
            "the refusal landed its dots after the toggle"
        );
    }

    #[test]
    fn a_pause_toggle_restyles_the_lane_in_its_own_write_not_a_motion_write() {
        toggle_while_a_refusal_lands(false);
    }

    #[test]
    fn a_tap_in_the_turn_of_a_frame_puts_the_key_ahead_of_the_motion_write() {
        toggle_while_a_refusal_lands(true);
    }

    /// A source whose snapshot a test changes while the panel runs.
    #[derive(Clone, Default)]
    struct Changing(Arc<Mutex<Snapshot>>);

    impl Changing {
        fn set(&self, snapshot: Snapshot) {
            *self.0.lock().unwrap() = snapshot;
        }
    }

    impl Source for Changing {
        fn snapshot(&self) -> Snapshot {
            self.0.lock().unwrap().clone()
        }

        fn recent(&self, _n: usize) -> Vec<LogEntry> {
            Vec::new()
        }
    }

    /// The counters of a joined board that has answered `queries` today and refused `blocked` of them,
    /// with the clock set.
    fn counted(blocked: u64, queries: u64) -> Snapshot {
        Snapshot {
            today: Some(Counts {
                queries,
                blocked,
                ..Counts::default()
            }),
            ..reference_snapshot()
        }
    }

    /// The panel as it draws a Drain with no names, a funnel that is empty, and `stills`; `blocked` is
    /// the day's figure the Drain is given.
    fn screen_of(blocked: Option<u32>, stills: &Stills) -> Vec<u8> {
        let mut drain = Drain::new(DRAIN_SEED);
        drain.set_blocked_today(blocked);
        Painter::new().paint(&drain, stills).to_vec()
    }

    /// The clock the reference snapshot shows.
    const TEN_TWENTY: Option<TimeOfDay> = Some(TimeOfDay {
        hour: 10,
        minute: 20,
    });

    #[test]
    fn boot_shows_joining_then_listening_then_the_count() {
        let source = Changing::default();
        source.set(Snapshot {
            clock_set: true,
            ..Snapshot::default()
        });
        let mut rig = Rig::new(Arc::new(source.clone()));
        // The Wi-Fi is not joined: the lane says so, and the percentage and the count are dashes.
        rig.turn(0);
        let joining = Stills {
            clock: TEN_TWENTY,
            words: Some(LaneWords::Joining),
            ..Stills::default()
        };
        assert_eq!(rig.panel.shown, joining);
        assert!(rig.frames.last() == screen_of(None, &joining));
        assert_eq!(rig.frames.count(), 1);

        // Joined, and no query has come: `LISTENING` and a true zero. The two figures go in writes of
        // their own.
        source.set(Snapshot {
            wifi: Some(joined()),
            today: Some(Counts::default()),
            clock_set: true,
            ..Snapshot::default()
        });
        let mut now = FRAME_MS;
        let writes = rig.drive(&mut now, 2_500);
        let listening = Stills {
            clock: TEN_TWENTY,
            count: Some(0),
            words: Some(LaneWords::Listening),
            ..Stills::default()
        };
        assert_eq!(rig.panel.shown, listening);
        assert!(rig.frames.last() == screen_of(Some(0), &listening));
        assert_eq!(writes.len(), 2, "{writes:?}");

        // Queries come, some refused: the words go and the figures are the resolver's.
        source.set(counted(5, 12));
        let writes = rig.drive(&mut now, 5_000);
        let counting = Stills {
            percent: Some(Share::Percent(42)),
            clock: TEN_TWENTY,
            count: Some(5),
            ..Stills::default()
        };
        assert_eq!(rig.panel.shown, counting);
        assert!(rig.frames.last() == screen_of(Some(5), &counting));
        assert_eq!(
            writes.len(),
            3,
            "the count, the share, the words: {writes:?}"
        );
        assert!(
            writes
                .iter()
                .all(|write| write.rows.is_none_or(|rows| rows <= 80)),
            "{writes:?}"
        );
    }

    #[test]
    fn a_count_stays_a_dash_while_the_wifi_is_not_joined() {
        let source = Changing::default();
        source.set(reference_snapshot());
        let mut rig = Rig::new(Arc::new(source.clone()));
        let mut now = 0;
        rig.drive(&mut now, 1_500);
        assert_eq!(rig.panel.shown.count, Some(4_780));

        // The link drops. Within a snapshot the count and the share are dashes and the lane says why.
        source.set(Snapshot {
            wifi: Some(WifiStatus::default()),
            ..reference_snapshot()
        });
        rig.drive(&mut now, 3_000);
        let shown = rig.panel.shown.clone();
        assert_eq!(
            (shown.count, shown.percent, shown.words),
            (None, None, Some(LaneWords::Joining))
        );

        // Names go on being offered (the resolver is the LAN's, whatever the link). Whole refusals
        // pass: the Drain's own count, which counts a name when it melts, is never shown.
        for name in ["example.org", "example.com", "ads"] {
            rig.refuse(name);
        }
        let mut done = 0;
        while now < 40_000 {
            let wait = rig.turn(now);
            now += wait.max(1);
            assert_eq!(rig.panel.shown.count, None, "at {now}");
            assert_eq!(rig.panel.wanted.count, None, "at {now}");
            assert_eq!(rig.panel.drain.count(), None, "at {now}");
            done += usize::from(rig.panel.drain.refusal_step().is_some());
        }
        assert!(done > 30, "the names were on their way: {done} frames");

        // The link is back: the count is the figure again, and the names that melted are in it.
        source.set(counted(4_783, 10_821));
        rig.drive(&mut now, 42_000);
        assert_eq!(rig.panel.shown.count, Some(4_783));
        assert_eq!(rig.panel.shown.percent, Some(Share::Percent(44)));
        assert_eq!(rig.panel.shown.words, None);
    }

    #[test]
    fn quiet_after_two_minutes_without_a_lane_name_and_gone_when_one_comes() {
        let mut rig = Rig::new(Arc::new(Fixed(reference_snapshot())));
        // The panel's thread may be running a good while before its first frame: the quiet is counted
        // from that frame, not from the thread's start.
        let first = 40_000;
        let mut now = first;
        rig.drive(&mut now, first + 119_000);
        assert_eq!(rig.panel.shown.words, None, "two minutes have not passed");
        rig.drive(&mut now, first + 122_000);
        let quiet = |minutes| Stills {
            percent: Some(Share::Percent(44)),
            clock: TEN_TWENTY,
            count: Some(4_780),
            words: Some(LaneWords::Quiet { minutes }),
            ..Stills::default()
        };
        assert_eq!(rig.panel.shown, quiet(2));
        assert!(rig.frames.last() == screen_of(Some(4_780), &quiet(2)));
        // The words change once a minute at most, each in a write of its own.
        let before = rig.frames.count();
        let writes = rig.drive(&mut now, first + 175_000);
        assert!(writes.is_empty(), "{writes:?}");
        let writes = rig.drive(&mut now, first + 185_000);
        assert_eq!(rig.panel.shown.words, Some(LaneWords::Quiet { minutes: 3 }));
        assert_eq!(writes.len(), 1, "{writes:?}");
        assert_eq!(rig.frames.count(), before + 1);

        // A name comes. The words go in the frame that takes it: the lane is not idle, so they
        // are not drawn, though the figure for them is still on its way out.
        let mut rest = rig.panel.shown.clone();
        rest.words = None;
        rig.refuse("ads.example.org");
        let taken = now;
        let until = now + FRAME_MS;
        rig.drive(&mut now, until);
        assert!(!rig.panel.drain.idle());
        assert!(rig.frames.last() == Painter::new().paint(&rig.panel.drain, &rest));
        rig.drive(&mut now, taken + 2_000);
        assert_eq!(rig.panel.shown.words, None);

        // And the quiet is counted again from that name.
        rig.drive(&mut now, taken + 118_000);
        assert_eq!(rig.panel.shown.words, None);
        rig.drive(&mut now, taken + 123_000);
        assert_eq!(rig.panel.shown.words, Some(LaneWords::Quiet { minutes: 2 }));
        // The count is the figure again, with the refused name in it.
        assert_eq!(rig.panel.shown.count, Some(4_780));

        // Days of nothing, in one late turn: a frame, the new words, and no overflow.
        let days = now + 3 * 86_400_000;
        rig.turn(days);
        rig.turn(days + STILL_OFFSET_MS);
        assert_eq!(
            rig.panel.shown.words.map(LaneWords::text).as_deref(),
            Some("QUIET 3 D")
        );
    }

    #[test]
    fn the_percent_forms_reach_the_screen() {
        let source = Changing::default();
        source.set(reference_snapshot());
        let mut rig = Rig::new(Arc::new(source.clone()));
        let mut now = 0;
        rig.drive(&mut now, 500);
        for (blocked, queries, share, text) in [
            (0, 3, Share::Zero, "0%"),
            (1, 1_000, Share::UnderOne, "<1%"),
            (4_780, 10_818, Share::Percent(44), "44%"),
            (999, 1_000, Share::Percent(99), "99%"),
            (5, 5, Share::All, "ALL"),
        ] {
            source.set(counted(blocked, queries));
            let until = now + 2_500;
            rig.drive(&mut now, until);
            assert_eq!(rig.panel.shown.percent, Some(share));
            assert_eq!(share.text(), text);
            let stills = Stills {
                percent: Some(share),
                clock: TEN_TWENTY,
                count: u32::try_from(blocked).ok(),
                ..Stills::default()
            };
            assert!(
                rig.frames.last() == screen_of(u32::try_from(blocked).ok(), &stills),
                "{text}"
            );
        }
    }

    #[test]
    fn the_gate_refills_as_the_pause_runs_out_in_writes_of_its_own() {
        let mut rig = Rig::new(Arc::new(Fixed(reference_snapshot())));
        let mut now = 0;
        // Each write's rows and which figure it carried: the countdown, the refill or the words.
        let mut writes = Vec::new();
        let mut previous = Vec::new();
        let (mut countdown_writes, mut refill_writes, mut words_writes) = (0, 0, 0);
        let mut fills = Vec::new();
        // A pause of 300 s on the control's clock, from the panel's first frame to the last second.
        while now < 299_000 {
            rig.control
                .set_left(Some(300 - u16::try_from(now / 1_000).unwrap()));
            let (blocking, fill, words) = (
                rig.panel.shown.blocking,
                rig.panel.shown.gate_fill,
                rig.panel.shown.words,
            );
            let wrote = rig.frames.count();
            let wait = rig.turn(now);
            let moved = (
                rig.panel.shown.blocking != blocking,
                rig.panel.shown.gate_fill != fill,
                rig.panel.shown.words != words,
            );
            assert!(
                usize::from(moved.0) + usize::from(moved.1) + usize::from(moved.2) <= 1,
                "two figures changed in the write at {now}"
            );
            countdown_writes += usize::from(moved.0);
            words_writes += usize::from(moved.2);
            if moved.1 {
                refill_writes += 1;
                fills.push(rig.panel.shown.gate_fill);
            }
            if rig.frames.count() > wrote {
                let frame = rig.frames.last();
                let rows = (!previous.is_empty()).then(|| {
                    changed_rows(&previous, &frame, WIDTH * 2).map_or(0, |rows| rows.len())
                });
                previous = frame;
                writes.push((rows, moved));
            }
            now += wait.max(1);
        }
        // 18 steps of 12 pixels, one to a write, each after the countdown's write of its second.
        assert_eq!(fills, (1..=18).collect::<Vec<u8>>());
        assert_eq!(refill_writes, 18);
        // The countdown: the first frame's, and one write for every second that passed after it.
        assert_eq!(countdown_writes, 1 + 298);
        let rows: Vec<usize> = writes.iter().filter_map(|(rows, _)| *rows).collect();
        let refill_rows: Vec<usize> = writes
            .iter()
            .filter(|(_, moved)| moved.1)
            .filter_map(|(rows, _)| *rows)
            .collect();
        eprintln!(
            "rows per write, a pause running out: {} writes, peak {}, the countdown's peak {}, the refill's {:?}",
            rows.len(),
            rows.iter().max().unwrap(),
            writes
                .iter()
                .filter(|(_, moved)| moved.0)
                .filter_map(|(rows, _)| *rows)
                .max()
                .unwrap(),
            refill_rows
        );
        assert!(rows.iter().all(|&rows| rows <= 80), "{rows:?}");
        assert_eq!(refill_rows.len(), 18);
        // The lane's quiet words came at two, three and four minutes, each in a write of its own.
        assert_eq!(words_writes, 3);
        // Every write was one figure's: nothing else moved.
        assert_eq!(
            writes.len(),
            countdown_writes + refill_writes + words_writes
        );
    }

    /// A logger that keeps what is logged, for the one test that installs it.
    struct Capture(Mutex<Vec<String>>);

    impl log::Log for Capture {
        fn enabled(&self, _: &log::Metadata<'_>) -> bool {
            true
        }

        fn log(&self, record: &log::Record<'_>) {
            self.0
                .lock()
                .unwrap()
                .push(format!("{} {}", record.level(), record.args()));
        }

        fn flush(&self) {}
    }

    #[test]
    fn the_panel_never_logs_a_name() {
        crate::testns::run_inside("panel::tests::ns_the_panel_never_logs_a_name");
    }

    #[test]
    #[ignore = "run by the_panel_never_logs_a_name, in a process of its own"]
    fn ns_the_panel_never_logs_a_name() {
        if !crate::testns::inside() {
            return;
        }
        // This process runs this one test, so the logger is its own to set.
        static CAPTURE: Capture = Capture(Mutex::new(Vec::new()));
        log::set_logger(&CAPTURE).unwrap();
        log::set_max_level(log::LevelFilter::Trace);

        let mut rig = Rig::new(Arc::new(Fixed(reference_snapshot())));
        rig.alerts.set(Some(threat(7)));
        // Refused names, plain names, a name too long for the lane, a pause, an alert and its dismissal.
        // The names stay different after fitting to the lane, so that all of them really go through it:
        // `fit_site` drops host labels whole, so a long host in front of `example.org` would be
        // `example.org` like the plain one.
        let long = format!("{}.example", "x".repeat(200));
        let names = [
            ("ads.example.org", 15),
            ("example.org", 20),
            (long.as_str(), 15),
            ("tracker.example", 15),
        ];
        let fitted: std::collections::HashSet<String> = names
            .iter()
            .map(|&(name, cells)| qb_panel::format::fit_site(name, cells))
            .collect();
        assert_eq!(
            fitted.len(),
            names.len(),
            "the names are different on the lane"
        );
        rig.refuse("ads.example.org");
        rig.lane.observe("example.org", false, 5, |_| false);
        rig.refuse(&long);
        let mut now = 0;
        rig.drive(&mut now, 1_000);
        rig.panel.touch(&tap(now, 60, ON_SWITCH));
        rig.refuse("tracker.example");
        rig.drive(&mut now, 3_000);
        rig.panel.touch(&tap(now, 60, ELSEWHERE));
        rig.drive(&mut now, 5_000);
        rig.control.set_left(None);
        rig.drive(&mut now, 6_000);
        assert_eq!(rig.alerts.acks(), [7]);
        // The first refusal ran to the funnel: its 15 dots are lit, and the others were on their way.
        let lit = rig
            .panel
            .drain
            .funnel()
            .iter()
            .filter(|cell| cell.shade.is_some());
        assert!(lit.count() >= 15);

        let lines = CAPTURE.0.lock().unwrap().clone();
        assert!(
            lines
                .iter()
                .any(|line| line == "INFO panel: switch: paused for 300 s"),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line == "INFO panel: switch: the pause ended"),
            "{lines:?}"
        );
        for line in &lines {
            for secret in [
                "example.org",
                ".example",
                "tracker",
                "xxxx",
                "192.0.2.23",
                "secure-login",
            ] {
                assert!(!line.contains(secret), "{line}");
            }
        }
    }

    /// The bytes of `events` as a device sends them.
    fn wire(events: &[RawEvent]) -> Vec<u8> {
        events.iter().flat_map(|&event| bytes_of(event)).collect()
    }

    #[test]
    fn the_events_of_a_device_work_the_switch_until_the_device_goes() {
        let (mut panel, frames, control) = panel();
        let (reader, mut writer) = std::io::pipe().unwrap();
        writer.write_all(&wire(&tap(1_000, 60, ON_SWITCH))).unwrap();
        drop(writer);
        assert_eq!(
            serve(&mut panel, Some(reader), Instant::now()),
            PanelEnd::Failed("reading the touch device: the touch device gave nothing more".into())
        );
        assert_eq!(control.calls(), ["pause 300"]);
        assert!(frames.last() == frame_of(Blocking::Paused { left_secs: 300 }));
    }

    #[test]
    fn a_screen_that_breaks_ends_the_loop_with_no_touch_device_too() {
        let mut panel = Panel::new(Broken, deps(Arc::new(Nothing)));
        assert_eq!(
            serve(&mut panel, None::<std::io::PipeReader>, Instant::now()),
            PanelEnd::Failed("writing the screen: the screen is gone".into())
        );
    }

    #[test]
    fn a_calibration_boot_shows_the_crosses_and_goes_on_with_what_the_taps_measured() {
        let measured = Calibration {
            swap_xy: false,
            left: 3890,
            right: 210,
            top: 300,
            bottom: 3800,
        };
        let (mut panel, frames, control) = panel();
        panel.deps.calibrate = true;
        let (reader, mut writer) = std::io::pipe().unwrap();
        let mut device = Some(reader);
        thread::scope(|scope| {
            scope.spawn(|| {
                for (n, (x, y)) in calibrate::TARGETS.into_iter().enumerate() {
                    // The owner taps a cross once it is on the screen.
                    while frames.count() <= n {
                        thread::sleep(Duration::from_millis(5));
                    }
                    let tap = press(1_000, raw_at(&measured, x, y), 5);
                    writer.write_all(&wire(&tap)).unwrap();
                }
            });
            assert_eq!(measure_touch(&mut panel, device.as_mut()), Ok(()));
        });
        assert_eq!(
            frames.all(),
            (0..4).map(calibrate::target_frame).collect::<Vec<_>>()
        );
        assert_close(&panel.deps.calibration, &measured);
        // The panel reads the touch screen as it was measured from now on.
        let on_switch = raw_at(&measured, 40, 290);
        panel.touch(&tap(
            2_000,
            60,
            (i32::from(on_switch.raw_x), i32::from(on_switch.raw_y)),
        ));
        assert_eq!(control.calls(), ["pause 300"]);
    }

    #[test]
    fn the_first_tap_after_a_calibration_boot_works_though_the_kernel_leaves_out_an_axis() {
        let measured = Calibration {
            swap_xy: false,
            left: 3890,
            right: 210,
            top: 300,
            bottom: 3800,
        };
        let (mut panel, frames, control) = panel();
        panel.deps.calibrate = true;
        let (reader, mut writer) = std::io::pipe().unwrap();
        let mut device = Some(reader);
        let mut sent = Reading { raw_x: 0, raw_y: 0 };
        thread::scope(|scope| {
            let owner = scope.spawn(|| {
                for (n, (x, y)) in calibrate::TARGETS.into_iter().enumerate() {
                    while frames.count() <= n {
                        thread::sleep(Duration::from_millis(5));
                    }
                    let tap = kernel_press(1_000, &mut sent, raw_at(&measured, x, y), 5);
                    writer.write_all(&wire(&tap)).unwrap();
                }
            });
            assert_eq!(measure_touch(&mut panel, device.as_mut()), Ok(()));
            owner.join().unwrap();
        });
        assert_close(&panel.deps.calibration, &measured);
        // The switch is at the screen's left edge, as the last cross is: the kernel does not send x again.
        let on_switch = raw_at(&measured, 40, 290);
        assert_eq!(on_switch.raw_x, sent.raw_x);
        writer
            .write_all(&wire(&kernel_press(2_000, &mut sent, on_switch, 3)))
            .unwrap();
        drop(writer);
        assert_eq!(
            serve(&mut panel, device.take(), Instant::now()),
            PanelEnd::Failed("reading the touch device: the touch device gave nothing more".into())
        );
        assert_eq!(control.calls(), ["pause 300"]);
    }

    #[test]
    fn a_boot_that_does_not_ask_for_a_calibration_shows_no_crosses() {
        let (mut panel, frames, _) = panel();
        let (mut reader, _writer) = std::io::pipe().unwrap();
        assert_eq!(measure_touch(&mut panel, Some(&mut reader)), Ok(()));
        assert_eq!(frames.count(), 0);
        assert_eq!(panel.deps.calibration, Calibration::NOMINAL);
    }

    #[test]
    fn a_calibration_boot_without_a_touch_device_has_nothing_to_tap_with() {
        let (mut panel, frames, _) = panel();
        panel.deps.calibrate = true;
        let outcome = measure_touch(&mut panel, None::<&mut std::io::PipeReader>);
        assert_eq!(outcome, Ok(()));
        assert_eq!(frames.count(), 0);
        assert_eq!(panel.deps.calibration, Calibration::NOMINAL);
    }

    #[test]
    fn a_touch_device_that_goes_during_a_calibration_ends_the_panel() {
        let (mut panel, frames, _) = panel();
        panel.deps.calibrate = true;
        let (mut reader, writer) = std::io::pipe().unwrap();
        drop(writer);
        assert_eq!(
            measure_touch(&mut panel, Some(&mut reader)),
            Err(PanelEnd::Failed(
                "calibrating the touch screen: the touch device gave nothing more".into()
            ))
        );
        assert_eq!(frames.all(), [calibrate::target_frame(0)]);
    }

    /// A `/sys/class/input` holding the touch screen as `event2`, in a directory of its own, so that it can be moved into place whole.
    fn touch_input() -> TempDir {
        let sys = tempfile::tempdir().unwrap();
        fs::create_dir_all(sys.path().join("event2/device")).unwrap();
        fs::write(
            sys.path().join("event2/device/name"),
            format!("{}\n", touch::TOUCH_NAME),
        )
        .unwrap();
        sys
    }

    #[test]
    fn a_touch_device_that_never_comes_is_waited_for_as_long_as_asked_and_no_longer() {
        let sys = touch_input();
        let dev = Path::new("/dev/input");
        assert_eq!(
            await_touch(sys.path(), dev, Duration::ZERO),
            Some(dev.join("event2"))
        );
        let empty = tempfile::tempdir().unwrap();
        let began = Instant::now();
        assert_eq!(
            await_touch(empty.path(), dev, Duration::from_millis(200)),
            None
        );
        assert!(began.elapsed() >= Duration::from_millis(200));
        assert!(began.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn a_touch_device_that_appears_while_its_driver_comes_up_is_waited_for() {
        let sys = tempfile::tempdir().unwrap();
        let appearing = touch_input();
        let dev = Path::new("/dev/input");
        thread::scope(|scope| {
            scope.spawn(|| {
                thread::sleep(Duration::from_millis(150));
                // Whole, so that it is never seen half made.
                fs::rename(appearing.path().join("event2"), sys.path().join("event2")).unwrap();
            });
            assert_eq!(
                await_touch(sys.path(), dev, Duration::from_secs(30)),
                Some(dev.join("event2"))
            );
        });
    }
}
