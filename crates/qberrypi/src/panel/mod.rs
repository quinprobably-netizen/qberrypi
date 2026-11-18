//! The front panel's side of the system: finding the screen, what to show on it, and what a tap does.
//!
//! [`run`] is the panel's thread. It loads the screen's drivers, finds the framebuffer, and shows the
//! panel OS on it (spec `2026-11-12-qberrypi-panel-os-design.md`): HOME and its five sections, which
//! [`Panel`] shows with the painters of `qb_panel`, and LIVE, the Drain, whose names go by on the lane
//! eight times a second and whose slow figures (the percentage, the clock, the count, the key, the
//! gate's refill and the lane's words) are written one region at a time between those frames.
//!
//! The thread reads the touch screen between draws; a tap is decided by `qb_panel::os::nav`, which says
//! what the panel does next and, for a tap that is an action, what the system must do (an `Intent`):
//! the gate, one device's ads or its own gate, a dismissed alert, the owner's word on a name, the night hours,
//! sleeping at once, a rejoin of the Wi-Fi, a restart, the PIN. A boot that
//! asks for it first shows four crosses to tap and measures the touch screen from the taps. A board without
//! the screen is [`PanelEnd::NoScreen`], which is no reason for the rest of the system to stop. The thread
//! only logs and reads `/sys` and `/dev`: it never touches the card, the watchdog or the LED, and it never
//! logs a name, a label or an address; what it logs of an action is what kind it was.
//!
//! What the screens read is copied into a `World` on the cadences of spec §5.2: the snapshot every
//! second; the control of blocking every turn; the lane's names every frame; the device inventory every
//! two seconds and who asks every second, only while HOME, DEVICES, DEVICE, CONFIRM or ITS GATE shows
//! (the first, DEVICE, also the watched device's names every frame), and the inventory while ALERTS or an
//! ALERT shows, which name their devices; the newest three waiting alerts every second; the day's most
//! refused names and the owner's own list every five seconds, only while NAMES, YOUR LIST or NAME shows.
//! The resolver's lock is taken only for the copies of the snapshot and of the control, as before, and for
//! the copy of at most eight names and the one lookup of a NAME's list, once in five seconds on those screens.
//! A new waiting alert opens its slip from any screen but a state of the whole system (`nav::arrive`, spec §5.3).
//!
//! **SYSTEM and the states** (phase 3). The board's load, memory and heat are read from `/proc` and `/sys` on this
//! thread every five seconds, only while SYSTEM, UP or WI-FI shows; where the update machinery stands, once a second,
//! whatever shows; the link's figures come with the snapshot, and the lock's state and the night hours with it.
//! The states of the whole system are the loop's to enter and leave (`Panel::drive_states`): STARTING from the first
//! frame (`Panel::boot`) until the panel is on, the Wi-Fi joined, the clock set, the lists loaded and DNS
//! answering, and 3 s after the last, or 90 s; then HOME, or UPDATE on a trial boot. UPDATE covers the screen
//! while an update is received or on trial, and shows once how a trial ended until a tap or 30 s. NIGHT is the dark
//! clock after a minute alone in the night hours (a touch wakes HOME, the next minute alone sleeps again; an
//! arriving alert does not light it) and after `SLEEP NOW` until a touch; it is drawing only.
//!
//! **The lock.** A strong intent with the lock on is asked for by the nav: the PIN pad opens holding it, and its
//! fourth digit is an `Intent::Verify`, which this thread checks against the lock (PBKDF2, constant time, on the
//! panel's thread: the screen is not drawn meanwhile) and answers with `nav::verified`; a right PIN hands the held
//! action back, and it is carried out as if it had just been tapped. The digits live in a `Zeroizing` from the pad
//! to the check; nothing here logs one, nor the hash. What the panel logs of any action is its kind.
//!
//! **Writes.** The surface takes a whole frame and writes the rows that differ from what the glass shows.
//! LIVE keeps the Drain's painter and its schedule: a frame's motion, and half a frame later one figure.
//! Every other screen is painted whole from its view into the `ScreenPainter`; a switch of screens, a
//! whole-system change and the gate's toggle are one full write, and inside a screen each band of changed
//! rows (`ScreenPainter::paint_bands`) is a write of its own, at most 80 rows, one to a slot, so that no
//! two share the driver's flush window.

use std::fs::File;
use std::io::{self, Read};
use std::net::Ipv4Addr;
use std::ops::Range;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use qb_panel::drain::{Drain, Stills};
use qb_panel::os::nav::{self, Arrivals, Nav, Screen as Opened, Section, Tap, Verified};
use qb_panel::os::screens::{self, View};
use qb_panel::os::world::{
    AlertRow, BUILT_CELLS, LockSource, MAX_ALERT_ROWS, MAX_OWNER_ROWS, Machine, Moment, Outcome,
    Pause, RESTART_CAUSE_CELLS, Rejoin, UpdateRead, WatchedName, World,
};
use qb_panel::os::{GateMove, Intent, Verdict, Whole};
use qb_panel::rows::BAND_GAP;
use qb_panel::ui::ScreenPainter;
use qb_panel::{Calibration, HEIGHT, Painter, TapTracker, WIDTH};

use crate::lane::{LaneFeed, LaneName, WatchedName as LaneWatched, WatchedOutcome};
use crate::live::{BlockingControl, Source};
use crate::modules::{self, Insert, MODULE_LIST, ModuleTable, PANEL_MODULES};
use crate::sys;
use crate::update::OutcomeKind;
use crate::watch::devices::WallCopy;
use alerts::{PanelAlert, PendingAlerts};
use devices::DeviceControl;
use fb::{Framebuffer, SCREEN_DRIVER, SYS_GRAPHICS, SYS_VTCONSOLE, Screen, ScreenError};
use lock::{Check, LockControl, Source as PinSource};
use names::{NamesControl, OwnerSide};
use system::{RejoinWait, RestartRefused, SystemControl};
use touch::{Decoded, Decoder, RawEvent, SYS_INPUT, Sensitivity, find_touch, read_events};
use view::{WallEntry, blocking, gate_total, refill, wanted_stills};

pub mod alerts;
pub mod calibrate;
pub mod devices;
pub mod fb;
pub mod lock;
pub mod names;
pub mod system;
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

/// How often the panel asks for the system's numbers, in milliseconds.
pub const SNAPSHOT_MS: u64 = 1_000;

/// How often the panel copies the device inventory, in milliseconds, while a screen that shows devices is up.
pub const DEVICES_MS: u64 = 2_000;

/// How often the panel asks who asked something lately, in milliseconds, while HOME or DEVICES shows.
pub const ACTIVITY_MS: u64 = 1_000;

/// How often the panel asks for the waiting alerts, in milliseconds.
pub const ALERTS_MS: u64 = 1_000;

/// How often the panel asks for the day's most refused names and the owner's own list, in milliseconds, while
/// NAMES, YOUR LIST or NAME shows.
pub const NAMES_MS: u64 = 5_000;

/// How often the panel asks where the update machinery stands, in milliseconds, whatever screen shows (spec §5.2):
/// UPDATE is a state of the whole system, and a trial's countdown steps every second.
pub const UPDATE_MS: u64 = 1_000;

/// How often the panel reads the board's load, memory and heat, in milliseconds, while SYSTEM, UP or WI-FI shows
/// (spec §5.2, §6.5).
pub const SYSTEM_MS: u64 = 5_000;

/// How long STARTING lasts at most, in milliseconds: 90 s from the panel's first frame (spec §5.4).
pub const STARTING_MAX_MS: u64 = 90_000;

/// How long STARTING stays once its five lines are all done, in milliseconds: 3 s (spec §5.4).
pub const STARTING_HOLD_MS: u64 = 3_000;

/// How long a REJOIN shows `JOINING` at most, in milliseconds, if the link does not come back by itself (it
/// should in about 15 s; the control refuses another rejoin for 60 s, and then the key says `WAIT`).
pub const REJOIN_SHOWN_MS: u64 = 45_000;

/// How many frames the log's cursor is on, and then off: 4 and 4 at 8 frames a second (spec §12.4).
pub const CURSOR_FRAMES: u8 = 4;

/// How many frames the LIVE tile's lamp stays white after a name went by in the lane.
pub const BEAT_FRAMES: u8 = 3;

/// The most rows one write of a band holds: the budget of a write inside a screen.
pub const BAND_ROWS_MAX: usize = 80;

/// How many bytes a row of the frame holds.
const ROW_BYTES: usize = WIDTH * 2;

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
    /// How light a touch counts: the least pressure of a touch sample, which the calibration takes too,
    /// and the shortest press that is a tap.
    pub sensitivity: Sensitivity,
    /// The names that the resolver lets the lane show.
    pub lane: Arc<LaneFeed>,
    /// Where the panel's alerts come from, and where a dismissal is told: the ALERT screen shows the top one.
    pub alerts: Arc<dyn PendingAlerts>,
    /// The devices: what the wall and DEVICE read of them, and the edits a tap makes to them.
    pub devices: Arc<dyn DeviceControl>,
    /// The owner's names: what NAMES, YOUR LIST and NAME read of them, and the edits a tap makes to them.
    pub names: Arc<dyn NamesControl>,
    /// The board itself: the update machinery's view, the readings of SYSTEM, and the two actions on it, a
    /// rejoin of the Wi-Fi and a restart.
    pub system: Arc<dyn SystemControl>,
    /// The lock and the night hours: what the PIN pad checks the digits against (on the panel's thread), the
    /// PIN the panel sets or clears, and the hours the night screen keeps.
    pub lock: Arc<dyn LockControl>,
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

/// Where the panel is, as far as what is on the glass goes: a change of it is a switch of screens, which
/// is one full write. The gate ask over LIVE is no place of its own: the Drain draws it.
#[derive(Clone, PartialEq, Eq)]
struct Place {
    root: Section,
    stack: Vec<Opened>,
    whole: Option<Whole>,
    page: usize,
}

impl Place {
    fn of(nav: &Nav) -> Self {
        Self {
            root: nav.root(),
            stack: nav.stack().to_vec(),
            whole: nav.whole(),
            page: nav.devices_page(),
        }
    }
}

/// Whether LIVE, the Drain, is what shows: the root, with nothing opened over it.
fn is_live(nav: &Nav) -> bool {
    nav.root() == Section::Live && nav.stack().is_empty() && nav.whole().is_none()
}

/// Whether ALERTS, the log, is what shows: the root, with nothing opened over it. It is where the cursor blinks.
fn is_log(nav: &Nav) -> bool {
    nav.root() == Section::Alerts && nav.stack().is_empty() && nav.whole().is_none()
}

/// What the screen that shows needs read (spec §5.2): the device inventory while HOME, DEVICES, DEVICE,
/// CONFIRM or ITS GATE shows, and while ALERTS or an ALERT does, which name their devices; who asked lately
/// only while HOME or DEVICES shows; the watched device's names only while DEVICE shows; the day's most
/// refused and the owner's list only while NAMES, YOUR LIST or NAME shows; the board's load, memory and heat
/// only while SYSTEM, UP or WI-FI shows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Reads {
    devices: bool,
    activity: bool,
    watched: bool,
    names: bool,
    system: bool,
}

impl Reads {
    fn of(nav: &Nav) -> Self {
        if nav.whole().is_some() {
            return Self::default();
        }
        let wall = Self {
            devices: true,
            ..Self::default()
        };
        match nav.top() {
            None if matches!(nav.root(), Section::Home | Section::Devices) => Self {
                activity: true,
                ..wall
            },
            None if nav.root() == Section::Alerts => wall,
            Some(Opened::Device(_)) => Self {
                watched: true,
                ..wall
            },
            Some(Opened::Alert(_) | Opened::Confirm { .. } | Opened::ItsGate(_)) => wall,
            Some(Opened::Uptime | Opened::Wifi) => Self {
                system: true,
                ..Self::default()
            },
            None if nav.root() == Section::System => Self {
                system: true,
                ..Self::default()
            },
            _ => Self {
                names: nav.shows_names(),
                ..Self::default()
            },
        }
    }
}

/// Puts `value` in `slot` and notes it in `changed` when it is not what the slot holds.
fn put<T: PartialEq>(slot: &mut T, value: T, changed: &mut bool) {
    if *slot != value {
        *slot = value;
        *changed = true;
    }
}

/// The panel on its screen: what to draw and when, and what a tap does.
///
/// The `World` is what the OS screens read and `Nav` is where the panel is. LIVE is the Drain: names on a
/// lane, refused ones melting into a funnel, and the `Stills`, the figures that change slowly. What the
/// screen shows of them is `shown`, and what it is to come to show is `wanted`; the panel copies one
/// field at a time from `wanted` to `shown`, each in a write of its own, half a frame after the lane's
/// frame. Every other screen is a `View` of the world, painted whole by the `ScreenPainter`; `glass` is
/// what the glass shows when one of those is up, so that a band of it is written alone.
pub struct Panel<S: Surface> {
    surface: S,
    deps: Deps,
    /// Turns the touch screen's events into touches on the screen.
    decoder: Decoder,
    /// Turns touches into taps; its target is what `nav::decide` says a press would do.
    tracker: TapTracker<Tap>,
    /// Where the panel is.
    nav: Nav,
    /// What the screens read.
    world: World,
    /// The inventory as the panel copies it for the wall: its own buffer, which `Devices::wall_copy` fills every time
    /// it is read, so that the read allocates nothing under the inventory's lock.
    inventory: WallCopy,
    /// The wall as the inventory gave it last, with each place's addresses: what a device is looked up by.
    wall: Vec<WallEntry>,
    /// The addresses that asked in the last second or two, as the last read said.
    asking: Vec<Ipv4Addr>,
    /// The names of the watched device, taken from the lane feed. Kept between frames so that it is not made again.
    watched_buf: Vec<LaneWatched>,
    /// The address whose names the lane feed keeps for DEVICE; `None` while DEVICE does not show, or shows a
    /// device with no address yet.
    watching: Option<Ipv4Addr>,
    /// The scene.
    drain: Drain,
    /// Draws the scene and the figures on a frame it keeps.
    painter: Painter,
    /// The figures that the screen shows.
    shown: Stills,
    /// The figures that the screen is to show, as of the last turn.
    wanted: Stills,
    /// The names taken from the lane's feed at a frame. Kept between frames so that it is not made again.
    arrivals: Vec<LaneName>,
    /// Paints the screens that are not LIVE, whole, from a view.
    screens: ScreenPainter<View>,
    /// The frame the glass shows while a screen of `screens` is up: what is written band by band.
    glass: Vec<u8>,
    /// Bands of `screens`' frame that are not on the glass yet, one is written to a slot.
    pending: Vec<Range<usize>>,
    /// Where the panel was when the glass was last written whole; `None` before the first frame.
    drawn: Option<Place>,
    /// Whether the world changed since a screen of `screens` last looked at it.
    world_changed: bool,
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
    /// The total of the gate that is open: what the panel opened it for, or what a pause that came from
    /// elsewhere is taken to be (`view::gate_total`); `None` while blocking is on.
    gate_total: Option<u16>,
    /// Whether a tap asked for a draw that has not been made.
    tapped: bool,
    /// Whether the touch screen was touched since the last turn.
    touched: bool,
    /// The time at which the touch screen was last touched.
    last_touch_ms: u64,
    /// How long without a touch takes the panel HOME, in milliseconds.
    idle_after_ms: u64,
    /// The clock, in Unix seconds, as the last turn had it.
    unix: u64,
    /// The local time's distance from UTC, in seconds, as the last snapshot said.
    utc_offset_secs: i32,
    /// Whether the clock was set, as the last snapshot said.
    clock_set: bool,
    /// How many frames the LIVE tile's lamp is still to stay white.
    beat_left: u8,
    /// What the last frame needed read.
    reads: Reads,
    /// The times from which the next reads are due.
    next_devices_ms: u64,
    next_activity_ms: u64,
    next_alerts_ms: u64,
    next_names_ms: u64,
    /// Whether an edit asked for the inventory, or for the names, to be read at once.
    force_devices: bool,
    force_names: bool,
    /// The newest waiting alerts as the store last gave them, newest first: the world's rows are made from them
    /// and the wall, so that they are made again when the wall is read. They have no `Debug`.
    alerts_raw: Vec<PanelAlert>,
    /// How many alerts the store said were waiting, and when it last filed one.
    alerts_count: u32,
    alerts_last_unix: Option<u64>,
    /// The arrival rule's memory (spec §5.3): the alerts the panel has shown or passed over.
    alert_arrivals: Arrivals,
    /// Counts the frames of the log's cursor, which is on for the first `CURSOR_FRAMES` of every two times that.
    cursor_frames: u8,
    /// How long the board had been up when the panel began, in milliseconds: the panel's own time starts later.
    boot_ms: u64,
    /// The Unix second the board started, taken once the clock is set (`WATCH OPENED`, spec §12.3).
    opened_unix: Option<u64>,
    /// The panel's own time, in milliseconds since it began, at its last turn: what a tap's effects are dated by.
    now_ms: u64,
    /// STARTING, while it shows (spec §5.4): when it began and when its five lines were first all done.
    starting: Option<Starting>,
    /// The time from which the update machinery is next asked where it stands.
    next_update_ms: u64,
    /// The time from which the board's load, memory and heat are next read.
    next_system_ms: u64,
    /// The update that is under way, as UPDATE draws it, as the update machinery last said; `None` while none is.
    update_live: Option<UpdateRead>,
    /// The trial this boot knows of that has ended, as the update machinery last said: the finished update UPDATE
    /// shows once, and which outcome it is.
    update_ended: Option<(UpdateRead, (OutcomeKind, u64))>,
    /// The outcome the panel has shown, or passed over, so that it shows each once (spec §12.3).
    update_seen: Option<(OutcomeKind, u64)>,
    /// The finished update UPDATE is showing, until a tap or 30 s goes HOME.
    update_done: Option<UpdateRead>,
    /// Whether the night screen was asked for by `SLEEP NOW`: it then stays after the night hours, until a touch.
    sleep_now: bool,
    /// Where the owner's rejoin of the Wi-Fi stands: the link's join second when it was asked and when (the link is
    /// back once it has a newer one), and until when the control refuses another.
    rejoining: Option<(Option<u64>, u64)>,
    rejoin_wait_until_ms: Option<u64>,
    /// The monotonic second the link joined on, as the last snapshot said; `None` while it is down.
    joined_secs: Option<u64>,
}

/// STARTING's clock (spec §5.4): from the panel's first frame, until every line is done and 3 s have passed, or 90 s.
#[derive(Clone, Copy, Default)]
struct Starting {
    /// The panel's time at its first frame.
    began_ms: Option<u64>,
    /// The panel's time at which the five lines were first all done, and have been since.
    done_ms: Option<u64>,
}

impl<S: Surface> Panel<S> {
    /// A panel that draws on `surface`, at HOME.
    pub fn new(surface: S, deps: Deps) -> Self {
        // A panel that failed, or was restarted, may have left the lane feed keeping the names of one
        // device (spec §6.2: names only while that device's screen is open). This one has no screen open.
        deps.devices.watch_client(None);
        let sensitivity = deps.sensitivity;
        Self {
            surface,
            deps,
            decoder: Decoder::new(sensitivity.min_pressure),
            tracker: TapTracker::new(sensitivity.min_press_ms),
            nav: Nav::new(),
            world: World {
                version: qb_panel::format::fit_text(
                    crate::VERSION,
                    qb_panel::os::world::VERSION_CELLS,
                ),
                machine: Machine {
                    built: qb_panel::format::fit_text(
                        &view::date_of(crate::BUILD_EPOCH),
                        BUILT_CELLS,
                    ),
                    ..Machine::default()
                },
                ..World::default()
            },
            inventory: WallCopy::new(),
            wall: Vec::new(),
            asking: Vec::new(),
            watched_buf: Vec::new(),
            watching: None,
            drain: Drain::new(DRAIN_SEED),
            painter: Painter::new(),
            shown: Stills::default(),
            wanted: Stills::default(),
            arrivals: Vec::new(),
            screens: ScreenPainter::new(),
            glass: vec![0; ROW_BYTES * HEIGHT],
            pending: Vec::new(),
            drawn: None,
            world_changed: false,
            begun: false,
            next_frame_ms: 0,
            last_frame_ms: 0,
            last_name_ms: 0,
            still_done: false,
            next_snapshot_ms: 0,
            left: None,
            gate_total: None,
            tapped: false,
            touched: false,
            last_touch_ms: 0,
            idle_after_ms: nav::IDLE_MS,
            unix: 0,
            utc_offset_secs: 0,
            clock_set: false,
            beat_left: 0,
            reads: Reads::default(),
            next_devices_ms: 0,
            next_activity_ms: 0,
            next_alerts_ms: 0,
            next_names_ms: 0,
            force_devices: false,
            force_names: false,
            alerts_raw: Vec::new(),
            alerts_count: 0,
            alerts_last_unix: None,
            alert_arrivals: Arrivals::new(),
            cursor_frames: 0,
            boot_ms: u64::try_from(sys::uptime().as_millis()).unwrap_or(u64::MAX),
            opened_unix: None,
            now_ms: 0,
            starting: None,
            next_update_ms: 0,
            next_system_ms: 0,
            update_live: None,
            update_ended: None,
            update_seen: None,
            update_done: None,
            sleep_now: false,
            rejoining: None,
            rejoin_wait_until_ms: None,
            joined_secs: None,
        }
    }

    /// A panel as it comes up with the board: STARTING first (spec §5.4), then HOME, or the trial's UPDATE on a trial
    /// boot. [`Panel::new`] is the panel without that beginning, at HOME.
    pub fn boot(surface: S, deps: Deps) -> Self {
        let mut panel = Self::new(surface, deps);
        panel.starting = Some(Starting::default());
        panel.nav.set_whole(Some(Whole::Starting));
        panel
    }

    /// Takes the events the touch screen reported, in the order they were read.
    ///
    /// A press that begins on something a tap works, stays on it and lasts the shortest press of the
    /// `sensitivity` (20 ms unless the configuration says another) is a tap; it is decided by
    /// `nav::tap`, which moves the panel and may give back what the system must do, which is done here.
    /// The next turn draws whatever it changed. A tap is timed by the events that make it, not by when
    /// they were read.
    pub fn touch(&mut self, events: &[RawEvent]) {
        for &event in events {
            let Some((at_ms, decoded)) = self.decoder.feed(event, &self.deps.calibration) else {
                continue;
            };
            match decoded {
                Decoded::Touch(touch) => {
                    self.touched = true;
                    let (nav, world) = (&self.nav, &self.world);
                    let tapped = self.tracker.feed_with(at_ms, touch, |x, y| {
                        match nav::decide(nav, world, x, y) {
                            Tap::None => None,
                            tap => Some(tap),
                        }
                    });
                    if let Some((_, (x, y))) = tapped {
                        self.on_tap(x, y);
                    }
                }
                // Whatever was known of the press is not to be trusted, nor is it needed:
                // the press may be one whose `Down` was never given out.
                Decoded::Lost => self.tracker.cancel(),
            }
        }
    }

    /// Does a tap at `(x, y)`: the panel moves, and the system does what the tap asked of it.
    fn on_tap(&mut self, x: u16, y: u16) {
        // The lock may have changed since the last second's read (the desktop pushed a PIN, or took it away): a tap
        // is decided by what the lock is now.
        self.read_lock();
        if let Some(intent) = nav::tap(&mut self.nav, &self.world, x, y) {
            self.carry_out(intent);
        }
        self.tapped = true;
        self.sync_watch();
    }

    /// Does what an intent asks of the system, and logs which kind it was: never whom it was about, and never a
    /// PIN digit or hash. A strong action reaches here only once the nav has asked for the PIN, when the lock is on:
    /// the pad's right answer hands it back through `nav::verified` and it is carried out from `Intent::Verify`.
    fn carry_out(&mut self, intent: Intent) {
        match intent {
            Intent::Gate(GateMove::Open(secs)) => {
                self.deps.control.pause_for(secs);
                self.gate_total = Some(secs);
                log::info!("panel: gate opened for {secs} s");
            }
            Intent::Gate(GateMove::Shut) => {
                self.deps.control.resume();
                self.gate_total = None;
                log::info!("panel: gate shut");
            }
            Intent::DeviceAds { mac, pass } => {
                match self.deps.devices.set_ads_pass(mac, pass) {
                    Ok(()) if pass => log::info!("panel: device ads pass set"),
                    Ok(()) => log::info!("panel: device ads blocked"),
                    Err(error) => {
                        log::warn!("panel: device ads edit refused: {}", error.as_str());
                    }
                }
                self.force_devices = true;
            }
            Intent::DeviceGate { mac, secs } => {
                match self.deps.devices.device_gate(mac, secs) {
                    Ok(()) if secs == 0 => log::info!("panel: device gate shut"),
                    Ok(()) => log::info!("panel: device gate opened for {secs} s"),
                    Err(error) => {
                        log::warn!("panel: device gate edit refused: {}", error.as_str());
                    }
                }
                self.force_devices = true;
            }
            Intent::Ack(id) => {
                self.deps.alerts.ack(id);
                log::info!("panel: alert dismissed");
                // The log the panel goes back to is of what waits now: the next frame is too late to be the
                // first it draws.
                self.read_alerts();
            }
            Intent::Name { name, verdict } => {
                self.carry_out_name(&name, verdict);
                self.force_names = true;
            }
            Intent::NightHours { from, to } => {
                // The two hours equal are no night, as the lock keeps them.
                self.deps.lock.set_night((from != to).then_some((from, to)));
                let night = self.deps.lock.night();
                put(&mut self.world.night, night, &mut self.world_changed);
                log::info!("panel: night hours set");
            }
            Intent::SleepNow => {
                self.sleep_now = true;
                self.nav.set_whole(Some(Whole::Night));
                log::info!("panel: sleeping until a touch");
            }
            Intent::Rejoin => {
                match self.deps.system.rejoin() {
                    Ok(()) => {
                        // The link says JOINING (and the key WAIT) until it has joined again: until it has a
                        // newer join second than the one it has now.
                        self.rejoining = Some((self.joined_secs, self.now_ms));
                        log::info!("panel: Wi-Fi rejoin asked");
                    }
                    Err(RejoinWait(secs)) => {
                        let until = self.now_ms.saturating_add(u64::from(secs) * 1_000);
                        self.rejoin_wait_until_ms = Some(until);
                        log::info!("panel: Wi-Fi rejoin refused for now");
                    }
                }
                self.update_rejoin(self.now_ms);
            }
            Intent::Restart => match self.deps.system.restart() {
                Ok(()) => log::info!("panel: restart asked"),
                Err(RestartRefused::Updating) => {
                    log::info!("panel: restart refused: an update is under way");
                }
                Err(RestartRefused::NotReady) => log::warn!("panel: restart refused: not ready"),
            },
            // The lock logs a PIN that was set or taken away (`panel: the PIN was set on the panel`,
            // `panel: the lock was turned off`): there is nothing the panel adds, and nothing it may.
            Intent::SetPin(digits) => {
                if !self.deps.lock.set_pin(digits.into_zeroizing()) {
                    log::warn!("panel: the PIN was not set");
                }
                self.read_lock();
            }
            Intent::ClearPin => {
                self.deps.lock.clear_pin();
                self.read_lock();
            }
            // The four digits of the pad go to the lock, on this thread, and the pad is told what it said.
            Intent::Verify(digits) => {
                let answer = match self.deps.lock.verify(digits.into_zeroizing()) {
                    Check::Right => {
                        log::info!("panel: PIN accepted");
                        Verified::Right
                    }
                    // The lock logs a wrong PIN, with its count.
                    Check::Wrong => Verified::Wrong,
                    Check::Wait(secs) => {
                        log::info!("panel: PIN not checked: the lock is waiting");
                        Verified::Wait(secs)
                    }
                };
                let wait = self.deps.lock.wait_left();
                put(&mut self.world.pin_wait_secs, wait, &mut self.world_changed);
                // A right PIN gives back the action it was asked for, which is done as if it had just been tapped.
                if let Some(held) = nav::verified(&mut self.nav, answer) {
                    self.carry_out(held);
                }
            }
        }
    }

    /// Does what the owner decided for a name: puts it on the owner's list, or takes the entry back. Logs which kind
    /// of decision it was, never the name.
    fn carry_out_name(&self, name: &str, verdict: Verdict) {
        let names = &self.deps.names;
        let done = match verdict {
            Verdict::Allow => names.set(name, OwnerSide::Allow).map(|()| true),
            Verdict::Refuse => names.set(name, OwnerSide::Refuse).map(|()| true),
            Verdict::ClearAllow | Verdict::ClearRefuse => names.forget(name),
        };
        match (done, verdict) {
            (Ok(true), Verdict::Allow) => log::info!("panel: name allowed"),
            (Ok(true), Verdict::Refuse) => log::info!("panel: name refused"),
            (Ok(true), Verdict::ClearAllow) => log::info!("panel: allow taken back"),
            (Ok(true), Verdict::ClearRefuse) => log::info!("panel: refusal taken back"),
            // A name that only a parent covers has no entry of its own to take back.
            (Ok(false), _) => log::info!("panel: no entry of its own to take back"),
            (Err(error), _) => log::warn!("panel: name edit refused: {}", error.as_str()),
        }
    }

    /// Does what is due at `now_ms`, and returns how many milliseconds may pass before the next call.
    ///
    /// `now_ms` is the time since the panel began and `now_unix` is the clock, in Unix seconds.
    /// A frame is due every `FRAME_MS`: it takes the names the feed holds, asks the system for its numbers
    /// and the screen's reads when they are due, and, while anything is moving, advances the Drain one step
    /// and, when LIVE shows, draws it; any other screen draws what changed in the world, one band of rows.
    /// Half a frame later, if the figures on the screen are not those that are wanted (on LIVE), or a band
    /// is still to be written (elsewhere), one is drawn: a write to a slot, and only until `FLUSH_GUARD_MS`
    /// before the next frame, since a write later would share its flush with that frame's; one that is
    /// late waits for the next frame's slot. A tap draws at once, and so does a switch of screens, which
    /// is one full write, as is the gate's toggle. The first turn draws everything. A panel with nothing
    /// to move and nothing to change draws nothing, whatever the time. A turn that comes late makes one
    /// frame, and the frames are counted from it. A minute without a touch takes the panel HOME.
    pub fn turn(&mut self, now_ms: u64, now_unix: u64) -> io::Result<u64> {
        self.unix = now_unix;
        self.now_ms = now_ms;
        if std::mem::take(&mut self.touched) {
            self.last_touch_ms = now_ms;
        }
        let tapped = std::mem::take(&mut self.tapped);

        // The gate: the control is asked at every turn. The total of a pause is what the panel opened it
        // for, or taken from what is left of one that came from elsewhere.
        let left = self.deps.control.paused_left_secs();
        if left.is_none() && self.left.is_some() && !tapped {
            log::info!("panel: gate: the pause ended");
        }
        let toggled = left.is_some() != self.left.is_some();
        self.left = left;
        self.gate_total = left.map(|left| gate_total(self.gate_total, left));
        self.wanted.blocking = blocking(left);
        self.wanted.gate_fill = refill(left, self.gate_total.unwrap_or(0));
        let pause = left
            .zip(self.gate_total)
            .map(|(left_secs, total_secs)| Pause {
                left_secs,
                total_secs,
            });
        put(&mut self.world.blocking, pause, &mut self.world_changed);
        // The Drain knows of a pause as soon as it changes, so that the listed names on the lane are
        // restyled in the key's own write, which is a large one by right, and not in a motion write
        // that may share a step of the funnel.
        if toggled {
            self.drain.set_paused(left.is_some());
        }

        // A minute without a touch takes the panel HOME.
        let quiet_ms = now_ms.saturating_sub(self.last_touch_ms);
        if self.begun && quiet_ms >= self.idle_after_ms {
            let on_the_pad = self.nav.whole() == Some(Whole::Pin);
            nav::idle(&mut self.nav, quiet_ms);
            if on_the_pad {
                // The pad timed out, back to the screen it came from with the action not done (spec §4): that screen
                // has a minute of its own before the panel goes home, as if it had just been touched.
                self.last_touch_ms = now_ms;
            } else {
                // In the night hours the panel that has been left alone for that minute sleeps (spec §12.6).
                self.sleep_if_night();
            }
        }
        self.sync_watch();
        self.sync_ask();

        // A switch of screens is one full write, now.
        let mut wrote = false;
        if self.begun && self.drawn.as_ref() != Some(&Place::of(&self.nav)) {
            self.arrive(now_ms)?;
            wrote = true;
        }
        let live = is_live(&self.nav);
        if !live && toggled && self.begun && !wrote {
            // The gate's toggle changes HOME's lane and tile at once: one full write.
            self.present_toggle()?;
            wrote = true;
        }
        let early =
            live && toggled && tapped && self.begun && !wrote && now_ms >= self.next_frame_ms;
        if early {
            // A tap that comes in the turn of a frame: the key's write goes ahead of the frame's.
            self.still(true)?;
        }
        if !self.begun || now_ms >= self.next_frame_ms {
            self.frame(now_ms, now_unix)?;
        }
        if is_live(&self.nav) {
            if (tapped && !early && !wrote) || self.still_is_due(now_ms) {
                self.still(tapped)?;
            }
        } else if self.still_is_due(now_ms) {
            self.still_done = true;
            self.draw_screen()?;
        }
        let mut next_ms = self.next_frame_ms;
        if !self.still_done && self.still_window_open(now_ms) && self.has_still() {
            next_ms = next_ms.min(self.last_frame_ms.saturating_add(STILL_OFFSET_MS));
        }
        Ok(next_ms.saturating_sub(now_ms))
    }

    /// Whether a figure may still be written in this frame: `FLUSH_GUARD_MS` or more is left before the next frame.
    fn still_window_open(&self, now_ms: u64) -> bool {
        now_ms < self.last_frame_ms.saturating_add(FRAME_MS - FLUSH_GUARD_MS)
    }

    /// Whether there is a write to make in the frame's second slot: on LIVE a figure that is not as wanted,
    /// elsewhere a change of the world, or a band that is not written yet.
    fn has_still(&self) -> bool {
        if is_live(&self.nav) {
            self.shown != self.wanted
        } else {
            self.world_changed || !self.pending.is_empty()
        }
    }

    /// Whether a write is to be made now: this frame's second slot is not used, there is one to make, half a frame has passed, and it is not late in the frame.
    fn still_is_due(&self, now_ms: u64) -> bool {
        !self.still_done
            && now_ms >= self.last_frame_ms.saturating_add(STILL_OFFSET_MS)
            && self.still_window_open(now_ms)
            && self.has_still()
    }

    /// Makes a frame: takes the names, asks for the numbers and the screen's reads when they are due, moves
    /// the Drain, and draws what the screen that shows needs.
    fn frame(&mut self, now_ms: u64, now_unix: u64) -> io::Result<()> {
        let first = !self.begun;
        self.begun = true;
        if first {
            // The lane's quiet is counted from the panel's first frame, not from the thread's start; the
            // minute without a touch too, and STARTING's 90 s.
            self.last_name_ms = now_ms;
            self.last_touch_ms = now_ms;
            if let Some(starting) = self.starting.as_mut() {
                starting.began_ms = Some(now_ms);
            }
        }
        let elapsed_ms = now_ms.saturating_sub(self.last_frame_ms);
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
            self.beat_left = BEAT_FRAMES;
        }
        for arrival in self.arrivals.drain(..) {
            self.drain.offer(&arrival.name, arrival.kind);
        }
        // The LIVE tile's lamp is white for a few frames after a name.
        let beat = self.beat_left > 0;
        self.beat_left = self.beat_left.saturating_sub(1);
        put(&mut self.world.beat, beat, &mut self.world_changed);
        // The log's cursor: on for 4 frames and off for 4, only while the log shows (spec §12.4).
        self.cursor_frames = (self.cursor_frames + 1) % (2 * CURSOR_FRAMES);
        if is_log(&self.nav) {
            let on = self.cursor_frames < CURSOR_FRAMES;
            put(&mut self.world.cursor_on, on, &mut self.world_changed);
        } else {
            // No other screen draws it: nothing to repaint.
            self.world.cursor_on = false;
        }

        if first || now_ms >= self.next_snapshot_ms {
            self.refresh(now_ms, now_unix);
            self.next_snapshot_ms = now_ms.saturating_add(SNAPSHOT_MS);
        }
        self.read_cadences(now_ms);
        self.tick_gates(now_ms);
        // The board's uptime, from the clock the board's readings rebase: whole days, and the hours into the day.
        let uptime_ms = self.boot_ms.saturating_add(now_ms);
        let days = u32::try_from(uptime_ms / 86_400_000).unwrap_or(u32::MAX);
        let hours = u8::try_from(uptime_ms / 3_600_000 % 24).unwrap_or(0);
        put(
            &mut self.world.uptime_days,
            Some(days),
            &mut self.world_changed,
        );
        put(
            &mut self.world.machine.uptime_hours,
            Some(hours),
            &mut self.world_changed,
        );
        // The pad's wait is the lock's own, set before the nav looks at the world: `refresh` lets go of the figure
        // the lock's last answer gave the pad, for this one.
        let wait = if self.nav.pin().is_some() {
            self.deps.lock.wait_left()
        } else {
            0
        };
        put(&mut self.world.pin_wait_secs, wait, &mut self.world_changed);
        // STARTING, then UPDATE and the night, which cover everything else (spec §5.4). A screen that comes up
        // when one of them lets go is drawn from what it reads, as a screen that a tap opens is.
        let whole = self.nav.whole();
        self.drive_states(now_ms);
        nav::age_update(&mut self.nav, &self.world, elapsed_ms);
        if self.nav.whole() != whole {
            self.read_cadences(now_ms);
        }
        let popped = nav::refresh(&mut self.nav, &self.world);
        // A new waiting alert opens its slip, from wherever the panel is but a state of the whole system.
        let arrived = nav::arrive(&mut self.nav, &mut self.alert_arrivals, &self.world);
        if popped || arrived {
            self.sync_watch();
        }
        if arrived {
            // The slip is a screen of its own, and its device is named from the wall: read what it needs
            // before it is drawn. It was not asked for by a touch, but it is a screen to look at for a minute.
            self.last_touch_ms = now_ms;
            self.read_cadences(now_ms);
        }

        let moving = self.drain.moving();
        if moving {
            self.drain.tick(paused);
        }
        // The count is the Drain's: it holds back the refused names that have not melted yet. It is a
        // dash while the Wi-Fi is not joined: `refresh` gave the Drain no figure then, and a Drain
        // with no figure has no count, whatever names it carries. HOME's tile shows the same figure.
        self.wanted.count = self.drain.count();
        put(
            &mut self.world.refused_today,
            self.wanted.count,
            &mut self.world_changed,
        );
        if is_live(&self.nav) {
            nav::age_ask(&mut self.nav, elapsed_ms);
        }
        self.sync_ask();
        if first || self.drawn.as_ref() != Some(&Place::of(&self.nav)) {
            // The screen has nothing yet, or a pop moved the panel: it gets everything known at once.
            return self.present_full();
        }
        if is_live(&self.nav) {
            if moving { self.draw() } else { Ok(()) }
        } else {
            self.draw_screen()
        }
    }

    /// Asks the system for its numbers and works out the figures that are wanted, and what of them the
    /// world holds.
    ///
    /// `now_ms` times how long the lane has been without a name, for its `QUIET` words.
    fn refresh(&mut self, now_ms: u64, now_unix: u64) {
        let snapshot = self.deps.source.snapshot();
        let idle_secs = now_ms.saturating_sub(self.last_name_ms) / 1_000;
        self.wanted = wanted_stills(
            &snapshot,
            self.left,
            self.gate_total.unwrap_or(0),
            now_unix,
            idle_secs,
        );
        self.drain.set_blocked_today(self.wanted.count);
        self.sync_ask();

        self.utc_offset_secs = snapshot.utc_offset_secs;
        self.clock_set = snapshot.clock_set;
        // The watch opened when the board started: the clock less the uptime, taken once when the clock is
        // first set, so that the minute it shows cannot flip between two reads that round differently.
        if self.clock_set && self.opened_unix.is_none() {
            let uptime_secs = self.boot_ms.saturating_add(now_ms) / 1_000;
            self.opened_unix = Some(now_unix.saturating_sub(uptime_secs));
        }
        let opened: Option<Moment> = self
            .opened_unix
            .and_then(|unix| view::moment_of(unix, snapshot.utc_offset_secs));
        put(
            &mut self.world.watch_opened,
            opened,
            &mut self.world_changed,
        );
        let joined = view::joined(&snapshot);
        let today = snapshot.today.filter(|_| joined);
        let time = snapshot
            .clock_set
            .then(|| view::time_of_day(now_unix, snapshot.utc_offset_secs));
        let names = snapshot
            .list_names
            .map(|names| view::held(u64::try_from(names).unwrap_or(u64::MAX)));
        let changed = &mut self.world_changed;
        put(&mut self.world.time, time, changed);
        put(&mut self.world.wifi_joined, joined, changed);
        put(
            &mut self.world.queries_today,
            today.map(|today| view::held(today.queries)),
            changed,
        );
        put(&mut self.world.share, self.wanted.percent, changed);
        put(&mut self.world.list_names, names, changed);
        // DNS answers once the slot is filled and a query has been answered today, or an upstream has answered one
        // (spec §5.4): a quiet house asks nothing for minutes, and that is no reason to wait the 90 s out.
        let answering = snapshot
            .today
            .is_some_and(|today| today.queries > 0 || snapshot.upstream_ms.is_some());
        put(&mut self.world.dns_answering, answering, changed);

        // SYSTEM's and WI-FI's link, from the same snapshot: the monotonic second is the uptime's.
        self.joined_secs = snapshot.wifi.as_ref().and_then(|wifi| wifi.joined_secs);
        let now_secs = self.boot_ms.saturating_add(now_ms) / 1_000;
        let link = view::link_of(snapshot.wifi.as_ref(), snapshot.upstream_ms, now_secs);
        put(&mut self.world.link, link, &mut self.world_changed);
        self.update_rejoin(now_ms);

        // The lock and the night hours: small reads, under the lock's own mutex.
        self.read_lock();
        let night = self.deps.lock.night();
        put(&mut self.world.night, night, &mut self.world_changed);
    }

    /// Where the owner's rejoin of the Wi-Fi stands (spec §6.6, §12.4): `Joining` from the moment it was asked until
    /// the link has joined again (a newer join second than the one it had), or `REJOIN_SHOWN_MS` have passed;
    /// `Wait` while the control refuses another; else `Idle`.
    fn update_rejoin(&mut self, now_ms: u64) {
        if let Some((from, asked_ms)) = self.rejoining {
            let back =
                self.world.wifi_joined && self.joined_secs.is_some() && self.joined_secs != from;
            if back || now_ms.saturating_sub(asked_ms) >= REJOIN_SHOWN_MS {
                self.rejoining = None;
            }
        }
        let rejoin = if self.rejoining.is_some() {
            Rejoin::Joining
        } else {
            match self.rejoin_wait_until_ms {
                Some(until) if now_ms < until => {
                    let secs = (until - now_ms).div_ceil(1_000);
                    Rejoin::Wait(u16::try_from(secs).unwrap_or(u16::MAX))
                }
                _ => {
                    self.rejoin_wait_until_ms = None;
                    Rejoin::Idle
                }
            }
        };
        put(&mut self.world.rejoin, rejoin, &mut self.world_changed);
    }

    /// Reads whether the lock is on, where its PIN came from and whether the card keeps it: what makes a strong key
    /// ask, and what the LOCK screen says. A mutex and a copy.
    fn read_lock(&mut self) {
        let view = self.deps.lock.lock_view();
        let source = match view.source {
            Some(PinSource::Api) => LockSource::Api,
            Some(PinSource::Panel) => LockSource::Panel,
            Some(PinSource::Config) | None => LockSource::Config,
        };
        let changed = &mut self.world_changed;
        put(&mut self.world.lock_on, view.on, changed);
        put(&mut self.world.lock_source, source, changed);
        put(&mut self.world.lock_kept, view.kept, changed);
    }

    /// Asks the update machinery where it stands (every `UPDATE_MS`, whatever shows: UPDATE covers every screen): the
    /// slot that runs, how the last update ended and what the board last restarted for (SYSTEM, VERSION, UP), whether
    /// an update is received or on trial (`REJOIN` and `RESTART` are inert then), and the update that is under way,
    /// or the one that just ended, which UPDATE shows once. One small lock.
    fn read_update(&mut self, now_ms: u64) {
        let update = self.deps.system.update_view();
        self.next_update_ms = now_ms.saturating_add(UPDATE_MS);
        let cause = qb_panel::format::fit_text(view::restart_cause(&update), RESTART_CAUSE_CELLS);
        let changed = &mut self.world_changed;
        put(
            &mut self.world.machine.slot,
            update.slot.map(view::slot_of),
            changed,
        );
        put(
            &mut self.world.machine.last_update,
            view::last_update_of(&update),
            changed,
        );
        put(&mut self.world.machine.last_restart, cause, changed);
        put(&mut self.world.update_busy, update.state != "idle", changed);
        self.update_live = view::update_read(&update);
        self.update_ended = view::finished_update(&update);
    }

    /// Reads the board's load, memory and heat, on this thread: `/proc` and `/sys`, four small files. The kernel's
    /// uptime is the one the days and hours of UP count from, so it sets the panel's base for them.
    fn read_system(&mut self, now_ms: u64) {
        let readings = self.deps.system.readings();
        self.next_system_ms = now_ms.saturating_add(SYSTEM_MS);
        if let Some(secs) = readings.uptime_secs {
            self.boot_ms = secs.saturating_mul(1_000).saturating_sub(now_ms);
        }
        let changed = &mut self.world_changed;
        let machine = &mut self.world.machine;
        put(
            &mut machine.load_hundredths,
            readings.load_hundredths,
            changed,
        );
        put(&mut machine.memory_pct, readings.memory_pct, changed);
        put(&mut machine.temp_c, readings.temp_c.map(i16::from), changed);
    }

    /// Does the reads the screen that shows needs, when they are due (spec §5.2): the inventory every
    /// two seconds, who asked every second, the watched device's names every frame, and the waiting
    /// alerts every second. A read whose screen has just come up is made at once.
    fn read_cadences(&mut self, now_ms: u64) {
        let reads = Reads::of(&self.nav);
        if reads.activity && (!self.reads.activity || now_ms >= self.next_activity_ms) {
            self.deps
                .devices
                .asking(view::ASKING_SECS, &mut self.asking);
            self.next_activity_ms = now_ms.saturating_add(ACTIVITY_MS);
            for entry in &mut self.wall {
                entry.row.asking = view::is_asking(&entry.ipv4, &self.asking);
            }
            self.publish_wall();
        }
        if reads.devices
            && (!self.reads.devices || self.force_devices || now_ms >= self.next_devices_ms)
        {
            let unix = self.clock_set.then_some(self.unix);
            // The copy is made under the inventory's lock and is short; the wall's own work (its order,
            // its names, their fitting) is done here, after the lock is let go.
            if self
                .deps
                .devices
                .wall(&|last| view::recent(last, unix), &mut self.inventory)
            {
                let mut wall = view::wall(&self.inventory, &self.asking, now_ms, unix);
                view::keep_countdowns(&self.wall, &mut wall, now_ms);
                self.wall = wall;
                let before = self.world.newcomer;
                put(
                    &mut self.world.newcomer,
                    view::newcomer_of(&self.inventory),
                    &mut self.world_changed,
                );
                if self.world.newcomer != before {
                    self.map_alerts();
                }
            }
            self.force_devices = false;
            self.next_devices_ms = now_ms.saturating_add(DEVICES_MS);
            self.publish_wall();
            self.sync_watch();
        }
        if reads.watched {
            self.deps.devices.watched_names(&mut self.watched_buf);
            let names = self
                .watched_buf
                .iter()
                .map(|name| {
                    // The row shows the name as the feed cut it, and opens NAME with it whole.
                    WatchedName::shown_as(
                        &name.name,
                        name.whole.as_deref(),
                        outcome_of(name.outcome),
                    )
                })
                .collect();
            put(&mut self.world.watched, names, &mut self.world_changed);
        }
        if now_ms >= self.next_alerts_ms {
            self.read_alerts();
            self.next_alerts_ms = now_ms.saturating_add(ALERTS_MS);
        }
        if now_ms >= self.next_update_ms {
            self.read_update(now_ms);
        }
        // The board's load, memory and heat: only while SYSTEM, UP or WI-FI shows, every five seconds, and at once
        // when one of them comes up; what was read goes with them.
        if reads.system && (!self.reads.system || now_ms >= self.next_system_ms) {
            self.read_system(now_ms);
        }
        if !reads.system && self.reads.system {
            let changed = &mut self.world_changed;
            let machine = &mut self.world.machine;
            put(&mut machine.load_hundredths, None, changed);
            put(&mut machine.memory_pct, None, changed);
            put(&mut machine.temp_c, None, changed);
        }
        // The names: at once on arriving, after an edit, and when NAME is about another name than the one the
        // world holds the facts of; else every five seconds.
        let shown = self.nav.shown_name();
        let facts_for = self
            .world
            .name_facts
            .as_ref()
            .map(|facts| facts.name.as_str());
        if reads.names
            && (!self.reads.names
                || self.force_names
                || now_ms >= self.next_names_ms
                || facts_for != shown)
        {
            self.read_names();
            self.force_names = false;
            self.next_names_ms = now_ms.saturating_add(NAMES_MS);
        }
        if !reads.names && self.reads.names {
            // What was read goes with the screens that showed it: the next ones read afresh.
            let changed = &mut self.world_changed;
            put(&mut self.world.top_names, Vec::new(), changed);
            put(&mut self.world.owner_total, 0, changed);
            put(&mut self.world.owner_newest, Vec::new(), changed);
            put(&mut self.world.name_facts, None, changed);
        }
        self.reads = reads;
    }

    /// Reads the waiting alerts: the newest three, how many wait in all, and when the store last filed one. One
    /// pass over the store each, under its own lock.
    fn read_alerts(&mut self) {
        self.alerts_raw = self.deps.alerts.waiting(MAX_ALERT_ROWS);
        self.alerts_count = self.deps.alerts.waiting_count();
        self.alerts_last_unix = self.deps.alerts.last_alert_unix();
        self.map_alerts();
    }

    /// Makes the world's alerts from what was read and the wall: the log's lines and the slips they open, with the
    /// lines made from what the store carries and the names of the wall. Done again when the wall is read, since
    /// it names their devices.
    fn map_alerts(&mut self) {
        let (offset, now) = (self.utc_offset_secs, self.unix);
        let rows: Vec<AlertRow> = self
            .alerts_raw
            .iter()
            .map(|alert| view::alert_row(alert, &self.wall, self.world.newcomer, offset, now))
            .collect();
        let held = u32::try_from(rows.len()).unwrap_or(u32::MAX);
        let waiting = self.alerts_count.max(held);
        let newest = self
            .alerts_raw
            .first()
            .and_then(|alert| view::today_clock(alert.last_unix, now, offset));
        let last = self
            .alerts_last_unix
            .and_then(|unix| view::moment_of(unix, offset));
        let changed = &mut self.world_changed;
        put(&mut self.world.alerts_waiting, waiting, changed);
        put(&mut self.world.alert_newest, newest, changed);
        put(&mut self.world.last_entry, last, changed);
        put(&mut self.world.alerts, rows, changed);
    }

    /// Reads the day's most refused names, the owner's own list and, while NAME shows, what the lists and the
    /// owner say of its name. Copies, taken one after another: the resolver's lock is held for the copy of at
    /// most eight names and for one lookup, and let go between them.
    fn read_names(&mut self) {
        let (offset, now) = (self.utc_offset_secs, self.unix);
        let names = &self.deps.names;
        let top = names.top_today();
        let newest = names.owner_newest(MAX_OWNER_ROWS);
        let total = u32::try_from(names.owner_len()).unwrap_or(u32::MAX);
        let top_names = view::top_rows(&top, &|name| names.owner_hold(name));
        let owner_newest = view::owner_rows(&newest, now, offset);
        let facts = self.nav.shown_name().map(|name| {
            view::name_facts(
                name,
                names.class(name),
                names.owner_hold(name),
                &top,
                now,
                offset,
            )
        });
        let changed = &mut self.world_changed;
        put(&mut self.world.top_names, top_names, changed);
        put(&mut self.world.owner_total, total, changed);
        put(&mut self.world.owner_newest, owner_newest, changed);
        put(&mut self.world.name_facts, facts, changed);
    }

    /// Makes the world's wall what the panel's copy of it is, if it is not.
    fn publish_wall(&mut self) {
        let same = self.world.devices.len() == self.wall.len()
            && self
                .world
                .devices
                .iter()
                .zip(&self.wall)
                .all(|(row, entry)| *row == entry.row);
        if !same {
            self.world.devices = self.wall.iter().map(|entry| entry.row.clone()).collect();
            self.world_changed = true;
            // The alerts name their devices from the wall.
            self.map_alerts();
        }
    }

    /// Steps the open gates' countdowns to `now_ms`: the inventory is read every two seconds, and a
    /// countdown is to step every second.
    fn tick_gates(&mut self, now_ms: u64) {
        let mut stepped = false;
        for entry in &mut self.wall {
            let before = entry.row.state;
            entry.tick(now_ms);
            stepped |= entry.row.state != before;
        }
        if stepped {
            self.publish_wall();
        }
    }

    /// Keeps the lane feed's watch on the device whose screen shows, and on nothing else: the watch opens
    /// when DEVICE does, with the device's newest address, and is cleared as soon as DEVICE is left, by a
    /// tap, the idle minute or the device going. What was kept of its names goes with it. A screen over
    /// DEVICE (CONFIRM, ITS GATE) is no DEVICE: the watch is let go while it shows.
    fn sync_watch(&mut self) {
        let shown = self.nav.watched_mac();
        let address = shown.and_then(|mac| {
            self.wall
                .iter()
                .find(|entry| entry.row.mac == mac)
                .and_then(|entry| entry.ipv4.first().copied())
        });
        if address != self.watching {
            self.deps.devices.watch_client(address);
            self.watching = address;
        }
        if shown.is_none() {
            self.watched_buf.clear();
            put(&mut self.world.watched, Vec::new(), &mut self.world_changed);
        }
    }

    /// The gate ask over LIVE is the nav's; the Drain is to be drawn with it.
    fn sync_ask(&mut self) {
        self.wanted.gate_ask = self.nav.gate_ask();
    }

    /// The states of the whole system (spec §5.4), which cover every screen: STARTING from the first frame, then
    /// UPDATE for an update that is received or on trial (a trial boot shows it once STARTING is done) and, once, for
    /// how a trial ended, and the end of the night in the morning. The PIN pad is the nav's own.
    fn drive_states(&mut self, now_ms: u64) {
        if self.drive_starting(now_ms) {
            return;
        }
        self.drive_update();
        self.lift_night();
    }

    /// STARTING (spec §5.4): from the panel's first frame until the panel is on, the Wi-Fi joined, the clock set, the
    /// lists loaded (even when they hold no name: none may be configured) and DNS answering (the slot is filled and a
    /// query or an upstream has answered), and 3 s after the last of them, or 90 s; then HOME. Says whether it still
    /// shows.
    fn drive_starting(&mut self, now_ms: u64) -> bool {
        let Some(mut starting) = self.starting else {
            return false;
        };
        if self.nav.whole() != Some(Whole::Starting) {
            // The panel was moved from outside the loop: the beginning is over.
            self.starting = None;
            return false;
        }
        let began_ms = *starting.began_ms.get_or_insert(now_ms);
        let world = &self.world;
        let done = world.wifi_joined
            && world.time.is_some()
            && world.list_names.is_some()
            && world.dns_answering;
        match (done, starting.done_ms) {
            (true, None) => starting.done_ms = Some(now_ms),
            (false, Some(_)) => starting.done_ms = None,
            _ => {}
        }
        let held = starting
            .done_ms
            .is_some_and(|at| now_ms.saturating_sub(at) >= STARTING_HOLD_MS);
        let late = now_ms.saturating_sub(began_ms) >= STARTING_MAX_MS;
        if held || late {
            self.starting = None;
            self.nav.set_whole(None);
            if held {
                log::info!("panel: started");
            } else {
                log::warn!("panel: STARTING ended at its longest with a line not done");
            }
            return false;
        }
        self.starting = Some(starting);
        true
    }

    /// UPDATE (spec §5.4, §12.3): an update that is received or on trial takes the screen for as long as it lasts; how
    /// a trial ended (confirmed, rolled back) is shown once, until a tap or 30 s (`nav::age_update`); an update that
    /// came to nothing lets go. A PIN pad is not covered: it times out by itself, and the update is shown after it.
    /// Neither is the night screen: it stays dark (spec §5.4, as for an alert), and what is waiting, an update that
    /// is received or on trial or an outcome not yet shown, is held until the screen wakes, and shown then.
    fn drive_update(&mut self) {
        let whole = self.nav.whole();
        if !matches!(whole, None | Some(Whole::Update)) {
            return;
        }
        if let Some(live) = self.update_live {
            self.update_done = None;
            put(&mut self.world.update, Some(live), &mut self.world_changed);
            if whole != Some(Whole::Update) {
                self.nav.set_whole(Some(Whole::Update));
            }
            return;
        }
        match self.update_ended {
            Some((done, outcome)) if self.update_seen != Some(outcome) => {
                self.update_seen = Some(outcome);
                self.update_done = Some(done);
                // Its 30 s start now, whatever the update screen showed before.
                self.nav.set_whole(Some(Whole::Update));
            }
            _ if whole == Some(Whole::Update) && self.update_done.is_none() => {
                // The update that was under way is no more, and left nothing to show.
                self.nav.set_whole(None);
            }
            _ => {}
        }
        let showing = self.nav.whole() == Some(Whole::Update);
        if !showing {
            self.update_done = None;
        }
        let shown = self.update_done.filter(|_| showing);
        put(&mut self.world.update, shown, &mut self.world_changed);
    }

    /// The night screen after a minute alone, in the night hours (spec §5.4, §12.6): the panel that nobody touched
    /// sleeps; a touch wakes it to HOME, and the next minute alone puts it to sleep again. Called when the idle minute
    /// is up. Drawing only: the backlight is not switched.
    fn sleep_if_night(&mut self) {
        if self.nav.whole().is_none() && view::in_night(self.world.night, self.world.time) {
            self.nav.set_whole(Some(Whole::Night));
            self.sleep_now = false;
        }
    }

    /// The end of the night (spec §12.6): the dark screen of the night hours lifts to HOME in the morning; one that
    /// `SLEEP NOW` asked for stays until a touch. A night screen that is gone (a touch woke it) forgets the ask.
    fn lift_night(&mut self) {
        if self.nav.whole() != Some(Whole::Night) {
            self.sleep_now = false;
            return;
        }
        if !self.sleep_now && !view::in_night(self.world.night, self.world.time) {
            self.nav.set_whole(None);
            log::info!("panel: the night is over");
        }
    }

    /// Moves to a screen that is not the one on the glass: reads what it needs, lets the nav pop what is
    /// gone, and writes it whole.
    fn arrive(&mut self, now_ms: u64) -> io::Result<()> {
        self.read_cadences(now_ms);
        if nav::refresh(&mut self.nav, &self.world) {
            self.sync_watch();
            self.read_cadences(now_ms);
        }
        self.sync_ask();
        self.present_full()
    }

    /// Writes the screen that shows, whole: the surface writes the rows that differ from the glass. A
    /// screen switch, the gate's toggle and the first frame are the only callers.
    fn present_full(&mut self) -> io::Result<()> {
        self.pending.clear();
        self.world_changed = false;
        self.drawn = Some(Place::of(&self.nav));
        if is_live(&self.nav) {
            // The Drain was run all the while: it paints what changed since it was last painted.
            self.shown.clone_from(&self.wanted);
            let frame = self.painter.paint(&self.drain, &self.shown);
            return self.surface.show(frame);
        }
        self.screens.invalidate();
        let Some(view) = screens::view_of(&self.nav, &self.world) else {
            return Ok(());
        };
        self.screens.paint(view, screens::draw);
        self.glass.copy_from_slice(self.screens.frame());
        self.surface.show(&self.glass)
    }

    /// Writes what the gate's toggle changed on the screen that shows as one write, the span of rows that
    /// differ from the glass, and with it every band that was waiting; nothing when it changed nothing (the
    /// wall of devices does not show the gate). Not LIVE: the Drain's toggle is its own.
    fn present_toggle(&mut self) -> io::Result<()> {
        self.world_changed = false;
        let Some(view) = screens::view_of(&self.nav, &self.world) else {
            return Ok(());
        };
        let changed = self.screens.paint(view, screens::draw).is_some();
        if !changed && self.pending.is_empty() {
            return Ok(());
        }
        self.pending.clear();
        self.glass.copy_from_slice(self.screens.frame());
        self.surface.show(&self.glass)
    }

    /// Paints what changed in the world on the screen that shows, and writes one band of it.
    fn draw_screen(&mut self) -> io::Result<()> {
        if std::mem::take(&mut self.world_changed)
            && let Some(view) = screens::view_of(&self.nav, &self.world)
        {
            let bands = self.screens.paint_bands(view, screens::draw);
            self.queue(bands);
        }
        self.write_band()
    }

    /// Adds bands of rows to those that are to be written, joining those that are near.
    fn queue(&mut self, bands: Vec<Range<usize>>) {
        self.pending.extend(bands);
        self.pending.sort_by_key(|band| band.start);
        let mut joined: Vec<Range<usize>> = Vec::with_capacity(self.pending.len());
        for band in self.pending.drain(..) {
            match joined.last_mut() {
                Some(last) if band.start <= last.end + BAND_GAP => {
                    last.end = last.end.max(band.end)
                }
                _ => joined.push(band),
            }
        }
        self.pending = joined;
    }

    /// Writes the first of the bands that wait, at most `BAND_ROWS_MAX` rows of it: rows of the screen's
    /// frame put on the glass's, as a write of their own.
    fn write_band(&mut self) -> io::Result<()> {
        let Some(first) = self.pending.first().cloned() else {
            return Ok(());
        };
        let end = first.end.min(first.start + BAND_ROWS_MAX);
        if end >= first.end {
            self.pending.remove(0);
        } else if let Some(band) = self.pending.first_mut() {
            band.start = end;
        }
        let rows = first.start * ROW_BYTES..end * ROW_BYTES;
        self.glass[rows.clone()].copy_from_slice(&self.screens.frame()[rows]);
        self.surface.show(&self.glass)
    }

    /// Draws one figure that is not as wanted, or, when a tap asked for a draw, whatever there is. LIVE only.
    fn still(&mut self, urgent: bool) -> io::Result<()> {
        self.still_done = true;
        if urgent {
            // The ask folds, or unfolds, in the write of the tap that did it.
            self.shown.gate_ask = self.wanted.gate_ask;
        }
        let stepped = self.shown.step_toward(&self.wanted);
        if stepped || urgent {
            self.draw()?;
        }
        Ok(())
    }

    /// Paints the scene with the figures that are shown, and writes the frame if it differs from the one on the screen. LIVE only.
    fn draw(&mut self) -> io::Result<()> {
        match self.painter.paint_changed(&self.drain, &self.shown) {
            Some(frame) => self.surface.show(frame),
            None => Ok(()),
        }
    }
}

/// What a name of the watched device came to, as its screen says it.
fn outcome_of(outcome: WatchedOutcome) -> Outcome {
    match outcome {
        WatchedOutcome::Refused => Outcome::Refused,
        WatchedOutcome::Passed => Outcome::Passed,
        WatchedOutcome::Answered => Outcome::Answered,
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
    let min_pressure = panel.deps.sensitivity.min_pressure;
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
        min_pressure,
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
    device: Option<D>,
    began: Instant,
) -> PanelEnd {
    let end = serve_until_broken(panel, device, began);
    // However the loop ended, no screen of this panel is open any more: the lane feed stops keeping the names
    // of the device whose screen was (spec §6.2).
    panel.deps.devices.watch_client(None);
    end
}

/// [`serve`]'s loop, which ends only when the screen or the touch device breaks.
fn serve_until_broken<S: Surface, D: Read + AsFd>(
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
    let devices = deps.devices.clone();
    let end = run_panel(deps);
    // Any end, an early one too: the lane feed keeps the names of no device (spec §6.2).
    devices.watch_client(None);
    end
}

/// [`run`], which clears the watch of a device's names when it returns.
fn run_panel(deps: Deps) -> PanelEnd {
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
    let mut panel = Panel::boot(framebuffer, deps);
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

    use std::net::IpAddr;

    use qb_panel::drain::{QUEUE_MAX, TileStyle};
    use qb_panel::os::world::{
        AlertStamp, DeviceState, LastUpdate, Newcomer, Slot as WorldSlot, UpdatePhase,
        Waiting as WorldWaiting, When,
    };
    use qb_panel::rows::changed_rows;
    use qb_panel::{Blocking, Calibration, LaneWords, Share, TimeOfDay};
    use tempfile::TempDir;

    use crate::live::{BlockingControl, Counts, LogEntry, Nothing, Snapshot, Source, WifiStatus};
    use crate::modules::DEFAULT_TABLE;
    use crate::names::{NamesError, OwnerEntry as OwnedEntry, OwnerHold};
    use crate::slots::Slot as CardSlot;
    use crate::update;
    use crate::usage::Readings;
    use crate::watch::devices::{DeviceView, DevicesView, EditError, KnownList, Label};
    use crate::watch::frames::Mac;
    use alerts::{NoAlerts, PanelAlert, Severity};
    use calibrate::Reading;
    use calibrate::tests::{assert_close, kernel_press, press, raw_at};
    use devices::NoDevices;
    use fb::tests::{Graphics, HDMI, graphics};
    use lock::{NoLock, PanelState};
    use names::{NameClass, NoNames, TopName};
    use system::NoSystem;
    use touch::tests::{abs_x, abs_y, bytes_of, dropped, key, pressure, syn};
    use view::tests::{TEN_TWENTY_UTC, reference_snapshot};
    use zeroize::Zeroizing;

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

    /// The panel's dependencies with a control nobody looks at, the nominal calibration, a lane nobody
    /// feeds, no alerts and no devices.
    fn deps(source: Arc<dyn Source>) -> Deps {
        Deps {
            source,
            control: Arc::new(FakeControl::default()),
            calibration: Calibration::NOMINAL,
            calibrate: false,
            sensitivity: Sensitivity::DEFAULT,
            lane: LaneFeed::new(),
            alerts: Arc::new(NoAlerts),
            devices: Arc::new(NoDevices),
            names: Arc::new(NoNames),
            system: Arc::new(NoSystem),
            lock: Arc::new(NoLock),
        }
    }

    /// A panel that is on LIVE, the Drain, and stays there however long nobody touches it: most of
    /// these tests are about the Drain's own writes.
    fn on_live<S: Surface>(mut panel: Panel<S>) -> Panel<S> {
        panel.nav.go(Section::Live);
        panel.idle_after_ms = u64::MAX;
        panel
    }

    /// A panel on LIVE that knows nothing, the frames it writes, and the control its key works.
    fn panel() -> (Panel<Recorder>, Frames, FakeControl) {
        let (surface, frames) = recorder();
        let control = FakeControl::default();
        let panel = on_live(Panel::new(
            surface,
            Deps {
                control: Arc::new(control.clone()),
                ..deps(Arc::new(Nothing))
            },
        ));
        (panel, frames, control)
    }

    /// The house as the panel's own tests have it: the owner's labels in the label order, then a device with
    /// a hostname and one with no name, then the router. Addresses are `192.0.2.n`, hardware addresses
    /// `02:00:00:00:00:n`, `n` the octet.
    fn house() -> DevicesView {
        let device = |octet: u8, label: Option<(&str, usize)>, host: Option<&str>, exempt: bool| {
            DeviceView {
                mac: Mac([2, 0, 0, 0, 0, octet]),
                ipv4: vec![Ipv4Addr::new(192, 0, 2, octet)],
                hostname: host.map(str::to_owned),
                first_unix: 1_799_000_000 + u64::from(octet),
                last_unix: UNIX,
                known: true,
                exempt,
                blocked: !exempt,
                label: label.and_then(|(text, _)| Label::new(text)),
                label_rank: label.map(|(_, rank)| rank),
                gate_left_secs: None,
                fixed: false,
                always: false,
            }
        };
        let mut router = device(1, None, None, false);
        router.always = true;
        router.blocked = false;
        DevicesView {
            rev: 1,
            known_list: KnownList::Received,
            devices: vec![
                device(12, Some(("Desk PC", 0)), None, true),
                device(23, Some(("Sam's phone", 1)), None, true),
                device(31, Some(("Living room TV", 2)), None, false),
                device(57, None, Some("printer"), true),
                device(143, None, None, true),
                router,
            ],
            exempt_macs: Vec::new(),
            exempt_pushed: Vec::new(),
            exempt_default: false,
            block_macs: Vec::new(),
            block_pushed: Vec::new(),
            own_mac: None,
            own_ip: None,
        }
    }

    /// The hardware address of the house's device with octet `octet`.
    fn hw(octet: u8) -> [u8; 6] {
        [2, 0, 0, 0, 0, octet]
    }

    /// What a fake inventory has been asked, and what it holds.
    #[derive(Default)]
    struct FakeDevicesState {
        view: Option<DevicesView>,
        asking: Vec<Ipv4Addr>,
        watched: Vec<LaneWatched>,
        /// How many times each was read.
        views: usize,
        askings: usize,
        watched_reads: usize,
        /// The addresses `watch_client` was given, in order.
        watches: Vec<Option<Ipv4Addr>>,
        /// Whose names the lane feed keeps now: the last address `watch_client` was given.
        watching: Option<Ipv4Addr>,
        /// The edits, as `ads 31 true`, `gate 31 300`: the octet of the device and what was asked.
        edits: Vec<String>,
    }

    /// An inventory that counts the calls it is made, keeps the edits, and applies them to its view as the
    /// real one does.
    #[derive(Clone, Default)]
    struct FakeDevices(Arc<Mutex<FakeDevicesState>>);

    impl FakeDevices {
        fn with(view: DevicesView) -> Self {
            let fake = Self::default();
            fake.0.lock().unwrap().view = Some(view);
            fake
        }

        fn state(&self) -> std::sync::MutexGuard<'_, FakeDevicesState> {
            self.0.lock().unwrap()
        }

        /// Changes the inventory a read gives.
        fn edit(&self, change: impl FnOnce(&mut DevicesView)) {
            change(self.state().view.as_mut().unwrap());
        }

        /// (inventory reads, activity reads, watched-names reads) so far.
        fn reads(&self) -> (usize, usize, usize) {
            let state = self.state();
            (state.views, state.askings, state.watched_reads)
        }
    }

    impl DeviceControl for FakeDevices {
        fn wall(&self, _recent: &dyn Fn(u64) -> bool, out: &mut WallCopy) -> bool {
            let mut state = self.state();
            state.views += 1;
            // Every device of the view: `view::wall` cuts it to the wall, as it does the real copy.
            match &state.view {
                Some(view) => {
                    *out = WallCopy::of_view(view);
                    true
                }
                None => false,
            }
        }

        fn asking(&self, _window_secs: u64, out: &mut Vec<Ipv4Addr>) {
            let mut state = self.state();
            state.askings += 1;
            out.clone_from(&state.asking);
        }

        fn set_ads_pass(&self, mac: [u8; 6], pass: bool) -> Result<(), EditError> {
            let mut state = self.state();
            let device = state
                .view
                .as_mut()
                .and_then(|view| view.devices.iter_mut().find(|device| device.mac.0 == mac))
                .ok_or(EditError::Unknown)?;
            if device.fixed {
                return Err(EditError::Fixed);
            }
            device.exempt = pass;
            state.edits.push(format!("ads {} {pass}", mac[5]));
            Ok(())
        }

        fn device_gate(&self, mac: [u8; 6], secs: u16) -> Result<(), EditError> {
            let mut state = self.state();
            let device = state
                .view
                .as_mut()
                .and_then(|view| view.devices.iter_mut().find(|device| device.mac.0 == mac))
                .ok_or(EditError::Unknown)?;
            device.gate_left_secs = (secs > 0).then_some(secs);
            state.edits.push(format!("gate {} {secs}", mac[5]));
            Ok(())
        }

        fn watch_client(&self, client: Option<Ipv4Addr>) {
            let mut state = self.state();
            state.watches.push(client);
            state.watching = client;
        }

        fn watched_names(&self, out: &mut Vec<LaneWatched>) {
            let mut state = self.state();
            state.watched_reads += 1;
            out.clear();
            out.extend(state.watched.iter().map(|name| LaneWatched {
                name: name.name.clone(),
                whole: name.whole.clone(),
                outcome: name.outcome,
            }));
        }
    }

    /// Alerts that the store would hold: those not acknowledged, and how often the panel asked.
    #[derive(Clone, Default)]
    struct FakeAlerts(Arc<Mutex<FakeAlertsState>>);

    #[derive(Default)]
    struct FakeAlertsState {
        alerts: Vec<(PanelAlert, bool)>,
        asked: usize,
        acks: Vec<u64>,
    }

    impl FakeAlerts {
        fn raise(&self, alert: PanelAlert) {
            self.0.lock().unwrap().alerts.push((alert, false));
        }

        /// Acknowledges as the API does: not by the panel.
        fn api_ack(&self, id: u64) {
            for (alert, acked) in &mut self.0.lock().unwrap().alerts {
                *acked |= alert.id == id;
            }
        }

        fn asked(&self) -> usize {
            self.0.lock().unwrap().asked
        }

        fn acks(&self) -> Vec<u64> {
            self.0.lock().unwrap().acks.clone()
        }
    }

    impl PendingAlerts for FakeAlerts {
        fn top(&self) -> Option<PanelAlert> {
            let state = self.0.lock().unwrap();
            state
                .alerts
                .iter()
                .filter(|(_, acked)| !acked)
                .max_by_key(|(alert, _)| (alert.severity == Severity::High, alert.id))
                .map(|(alert, _)| alert.clone())
        }

        fn waiting_count(&self) -> u32 {
            let state = self.0.lock().unwrap();
            u32::try_from(state.alerts.iter().filter(|(_, acked)| !acked).count()).unwrap()
        }

        fn waiting(&self, n: usize) -> Vec<PanelAlert> {
            let mut state = self.0.lock().unwrap();
            state.asked += 1;
            let mut waiting: Vec<PanelAlert> = state
                .alerts
                .iter()
                .filter(|(_, acked)| !acked)
                .map(|(alert, _)| alert.clone())
                .collect();
            waiting.sort_by_key(|alert| std::cmp::Reverse(alert.id));
            waiting.truncate(n);
            waiting
        }

        fn last_alert_unix(&self) -> Option<u64> {
            let state = self.0.lock().unwrap();
            state.alerts.iter().map(|(alert, _)| alert.last_unix).max()
        }

        fn ack(&self, id: u64) {
            let mut state = self.0.lock().unwrap();
            state.acks.push(id);
            for (alert, acked) in &mut state.alerts {
                *acked |= alert.id == id;
            }
        }
    }

    /// A threat alert about the device at `192.0.2.23`, as the store would carry it.
    fn threat_alert(id: u64) -> PanelAlert {
        PanelAlert {
            id,
            kind: "threat".to_owned(),
            severity: Severity::High,
            client: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 23))),
            subject: "secure-login-verify.example".to_owned(),
            count: 3,
            first_unix: UNIX - 1_000,
            last_unix: UNIX - 60,
        }
    }

    /// What a fake of the owner's names holds and has been asked.
    #[derive(Default)]
    struct FakeNamesState {
        /// The day's most refused, as the resolver counted them.
        top: Vec<TopName>,
        /// The owner's entries, the oldest first, with the day each was set.
        owner: Vec<(String, OwnerSide, Option<u64>)>,
        /// The names a list of the house blocks, and which.
        lists: Vec<(String, NameClass)>,
        /// How many times each read was made: the top, the newest entries, the length, a hold, a class.
        reads: [usize; 5],
        /// The edits, as `allow <name>`, `refuse <name>`, `forget <name>`.
        edits: Vec<String>,
    }

    /// The owner's names as a test sees them: a list that counts the reads it is made and keeps the edits, and
    /// applies them as the real one does.
    #[derive(Clone, Default)]
    struct FakeNames(Arc<Mutex<FakeNamesState>>);

    impl FakeNames {
        fn state(&self) -> std::sync::MutexGuard<'_, FakeNamesState> {
            self.0.lock().unwrap()
        }

        /// The house's day: three names most refused first, one of which an ads list holds and one a threat.
        fn with_day() -> Self {
            let fake = Self::default();
            {
                let mut state = fake.state();
                state.top = [
                    ("ads.example.net", 1_204),
                    ("tracker.example.com", 612),
                    ("metrics.example.org", 31),
                ]
                .map(|(name, count)| TopName {
                    name: name.into(),
                    count,
                })
                .to_vec();
                state.lists = vec![
                    ("ads.example.net".to_owned(), NameClass::Ads),
                    ("tracker.example.com".to_owned(), NameClass::Ads),
                    ("metrics.example.org".to_owned(), NameClass::Deny),
                    ("secure-login-verify.example".to_owned(), NameClass::Threat),
                ];
            }
            fake
        }

        /// How many reads of any kind were made.
        fn reads(&self) -> usize {
            self.state().reads.iter().sum()
        }

        fn edits(&self) -> Vec<String> {
            self.state().edits.clone()
        }
    }

    impl NamesControl for FakeNames {
        fn top_today(&self) -> Vec<TopName> {
            let mut state = self.state();
            state.reads[0] += 1;
            state.top.clone()
        }

        fn owner_len(&self) -> usize {
            let mut state = self.state();
            state.reads[2] += 1;
            state.owner.len()
        }

        fn owner_newest(&self, n: usize) -> Vec<OwnedEntry> {
            let mut state = self.state();
            state.reads[1] += 1;
            state
                .owner
                .iter()
                .rev()
                .take(n)
                .map(|(name, side, set_unix)| OwnedEntry {
                    name: name.as_str().into(),
                    side: *side,
                    set_unix: *set_unix,
                })
                .collect()
        }

        fn owner_hold(&self, name: &str) -> Option<OwnerHold> {
            let mut state = self.state();
            state.reads[3] += 1;
            let entry = state.owner.iter().find(|(held, _, _)| held == name)?;
            Some(OwnerHold {
                side: entry.1,
                exact: true,
                set_unix: entry.2,
            })
        }

        fn class(&self, name: &str) -> NameClass {
            let mut state = self.state();
            state.reads[4] += 1;
            state
                .lists
                .iter()
                .find(|(held, _)| held == name)
                .map_or(NameClass::None, |(_, class)| *class)
        }

        fn set(&self, name: &str, verdict: OwnerSide) -> Result<(), NamesError> {
            let on_threat = self
                .state()
                .lists
                .iter()
                .any(|(held, class)| held == name && *class == NameClass::Threat);
            if verdict == OwnerSide::Allow && on_threat {
                return Err(NamesError::Threat);
            }
            let mut state = self.state();
            state.owner.retain(|(held, _, _)| held != name);
            state.owner.push((name.to_owned(), verdict, Some(UNIX)));
            let word = if verdict == OwnerSide::Allow {
                "allow"
            } else {
                "refuse"
            };
            state.edits.push(format!("{word} {name}"));
            Ok(())
        }

        fn forget(&self, name: &str) -> Result<bool, NamesError> {
            let mut state = self.state();
            let before = state.owner.len();
            state.owner.retain(|(held, _, _)| held != name);
            let gone = state.owner.len() < before;
            if gone {
                state.edits.push(format!("forget {name}"));
            }
            Ok(gone)
        }
    }

    /// What a fake of the board itself holds, says and has been asked.
    struct FakeSystemState {
        /// Where the update machinery stands, as it says.
        update: update::View,
        /// What the rejoin and the restart answer.
        rejoin: Result<(), RejoinWait>,
        restart: Result<(), RestartRefused>,
        /// What the board's files read.
        readings: Readings,
        /// The actions it was asked for, in order: `rejoin`, `restart`.
        acts: Vec<&'static str>,
        /// How many times the update view and the readings were read.
        reads: (usize, usize),
    }

    /// The board itself as a test sees it: scripted answers and a count of the reads and the actions.
    #[derive(Clone)]
    struct FakeSystem(Arc<Mutex<FakeSystemState>>);

    impl Default for FakeSystem {
        fn default() -> Self {
            Self(Arc::new(Mutex::new(FakeSystemState {
                update: idle_update(),
                rejoin: Ok(()),
                restart: Ok(()),
                readings: Readings {
                    uptime_secs: Some(12 * 86_400 + 4 * 3_600),
                    load_hundredths: Some(21),
                    memory_pct: Some(38),
                    temp_c: Some(47),
                },
                acts: Vec::new(),
                reads: (0, 0),
            })))
        }
    }

    impl FakeSystem {
        fn state(&self) -> std::sync::MutexGuard<'_, FakeSystemState> {
            self.0.lock().unwrap()
        }

        /// Says where the update machinery stands from now on.
        fn set_update(&self, update: update::View) {
            self.state().update = update;
        }

        fn acts(&self) -> Vec<&'static str> {
            self.state().acts.clone()
        }

        /// (update views, readings) read so far.
        fn reads(&self) -> (usize, usize) {
            self.state().reads
        }
    }

    impl SystemControl for FakeSystem {
        fn rejoin(&self) -> Result<(), RejoinWait> {
            let mut state = self.state();
            state.acts.push("rejoin");
            state.rejoin
        }

        fn restart(&self) -> Result<(), RestartRefused> {
            let mut state = self.state();
            state.acts.push("restart");
            state.restart
        }

        fn update_view(&self) -> update::View {
            let mut state = self.state();
            state.reads.0 += 1;
            state.update.clone()
        }

        fn readings(&self) -> Readings {
            let mut state = self.state();
            state.reads.1 += 1;
            state.readings
        }
    }

    /// The update machinery of a board on slot A with nothing going on and nothing to say.
    fn idle_update() -> update::View {
        update::View {
            slot: Some(CardSlot::A),
            boot_files: None,
            state: "idle",
            received: 0,
            length: 0,
            trial: None,
            last: None,
        }
    }

    /// An update being received on a board that runs slot A: `received` of `length` bytes.
    fn receiving_update(received: u64, length: u64) -> update::View {
        update::View {
            state: "receiving",
            received,
            length,
            ..idle_update()
        }
    }

    /// The trial of a build on slot B, which a rollback would leave for slot A, with `min_left` seconds to its
    /// minimum time and these things still waited for.
    fn trial_update(min_left: u64, waiting_for: Vec<update::Waiting>) -> update::View {
        update::View {
            slot: Some(CardSlot::B),
            state: "trial",
            trial: Some(update::TrialView {
                build: 1_794_480_000,
                from: CardSlot::A,
                secs: 10,
                min_left_secs: min_left,
                waiting_for,
            }),
            ..idle_update()
        }
    }

    /// A board on `slot` whose last trial ended this way.
    fn ended_update(slot: CardSlot, kind: update::OutcomeKind) -> update::View {
        let build = 1_794_480_000;
        update::View {
            slot: Some(slot),
            last: Some(match kind {
                update::OutcomeKind::Confirmed => update::Outcome::confirmed(build),
                update::OutcomeKind::RolledBack => update::Outcome::rolled_back(build, "no clock"),
            }),
            ..idle_update()
        }
    }

    /// A source whose snapshot a test changes while the panel runs.
    #[derive(Clone)]
    struct Scripted(Arc<Mutex<Snapshot>>);

    impl Scripted {
        fn new(snapshot: Snapshot) -> Self {
            Self(Arc::new(Mutex::new(snapshot)))
        }

        fn set(&self, change: impl FnOnce(&mut Snapshot)) {
            change(&mut self.0.lock().unwrap());
        }
    }

    impl Source for Scripted {
        fn snapshot(&self) -> Snapshot {
            self.0.lock().unwrap().clone()
        }

        fn recent(&self, _n: usize) -> Vec<LogEntry> {
            Vec::new()
        }
    }

    /// A panel with every hand a test reaches it by: what it is shown, what its key controls, the feed
    /// of names, the devices, the alerts and the owner's names.
    struct Rig {
        panel: Panel<Recorder>,
        frames: Frames,
        control: FakeControl,
        lane: Arc<LaneFeed>,
        devices: FakeDevices,
        alerts: FakeAlerts,
        names: FakeNames,
        system: FakeSystem,
        /// The real lock and night hours, on a clock the test moves (`clock`, in seconds).
        lock: Arc<PanelState>,
        clock: Arc<std::sync::atomic::AtomicU64>,
    }

    impl Rig {
        /// A rig whose panel is on LIVE.
        fn new(source: Arc<dyn Source>) -> Self {
            let mut rig = Self::home(source);
            rig.panel = on_live(rig.panel);
            rig
        }

        /// A rig whose panel is at HOME with the house for its devices, without the boot's beginning.
        fn home(source: Arc<dyn Source>) -> Self {
            Self::built(source, false)
        }

        /// A rig whose panel comes up as the board's does, with STARTING first (`Panel::boot`).
        fn booting(source: Arc<dyn Source>) -> Self {
            Self::built(source, true)
        }

        fn built(source: Arc<dyn Source>, boot: bool) -> Self {
            let (surface, frames) = recorder();
            let (control, lane) = (FakeControl::default(), LaneFeed::new());
            let (devices, alerts) = (FakeDevices::with(house()), FakeAlerts::default());
            let names = FakeNames::with_day();
            let system = FakeSystem::default();
            let clock = Arc::new(std::sync::atomic::AtomicU64::new(1_000));
            let lock = Arc::new(PanelState::new(None, None, {
                let clock = clock.clone();
                Arc::new(move || clock.load(std::sync::atomic::Ordering::Relaxed))
            }));
            let deps = Deps {
                source,
                control: Arc::new(control.clone()),
                calibration: Calibration::NOMINAL,
                calibrate: false,
                sensitivity: Sensitivity::DEFAULT,
                lane: lane.clone(),
                alerts: Arc::new(alerts.clone()),
                devices: Arc::new(devices.clone()),
                names: Arc::new(names.clone()),
                system: Arc::new(system.clone()),
                lock: lock.clone(),
            };
            let mut panel = if boot {
                Panel::boot(surface, deps)
            } else {
                Panel::new(surface, deps)
            };
            // The board's uptime when the panel began is the host's, which no test can know: say it is none.
            panel.boot_ms = 0;
            // What the new panel did to the watch is the tests' own (`a_new_panel_lets_go_...`).
            devices.state().watches.clear();
            Self {
                panel,
                frames,
                control,
                lane,
                devices,
                alerts,
                names,
                system,
                lock,
                clock,
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

        /// Taps the screen at a pixel at `*now`, lets the panel draw what it changed, and moves on: the
        /// press lasts 60 ms and the draw is the turn after it.
        fn tap_at(&mut self, now: &mut u64, x: u16, y: u16) {
            self.panel.touch(&tap(*now, 60, raw_of(x, y)));
            *now += 100;
            self.turn(*now);
            *now += FRAME_MS;
        }

        /// Turns the panel as its own waits ask, for `ms` milliseconds from `*now`; returns what was written.
        fn run_for(&mut self, now: &mut u64, ms: u64) -> Vec<Written> {
            let until = *now + ms;
            self.drive(now, until)
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

    /// The raw reading that `Calibration::NOMINAL` maps onto the pixel `(x, y)`.
    fn raw_of(x: u16, y: u16) -> (i32, i32) {
        let find = |pixel: u16, span: i32, at: &dyn Fn(u16) -> u16| -> i32 {
            let near = 200 + i32::from(pixel) * 3_700 / span;
            (near - 12..=near + 12)
                .find(|&raw| at(u16::try_from(raw).unwrap()) == pixel)
                .expect("a reading on the pixel")
        };
        (
            find(x, 479, &|raw| {
                qb_panel::to_screen(&Calibration::NOMINAL, raw, 200).0
            }),
            find(y, 319, &|raw| {
                qb_panel::to_screen(&Calibration::NOMINAL, 200, raw).1
            }),
        )
    }

    /// The events of a tap on the pixel `(x, y)`: 60 ms down, from `at`.
    fn tap_on(at: u64, x: u16, y: u16) -> Vec<RawEvent> {
        tap(at, 60, raw_of(x, y))
    }

    /// Where a tap works the Drain's key, and the keys of the gate ask that it unfolds.
    const KEY: (u16, u16) = (40, 290);
    const ASK_5_MIN: (u16, u16) = (180, 270);
    const ASK_30_MIN: (u16, u16) = (300, 270);

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
            gate_ask: false,
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

    /// The panel as it draws an empty lane and nothing known but the gate's choices unfolded.
    fn frame_asking() -> Vec<u8> {
        let stills = Stills {
            gate_ask: true,
            words: Some(LaneWords::Joining),
            ..Stills::default()
        };
        Painter::new()
            .paint(&Drain::new(DRAIN_SEED), &stills)
            .to_vec()
    }

    #[test]
    fn a_tap_on_the_key_unfolds_the_choices_a_choice_opens_the_gate_and_the_countdown_steps() {
        let (mut panel, frames, control) = panel();
        panel.turn(0, UNIX).unwrap();
        // Both halves in one read: timed by the events, not by the read. With the gate shut the key unfolds
        // its choices in place, and nothing is paused yet.
        panel.touch(&tap_on(1_000, KEY.0, KEY.1));
        assert!(control.calls().is_empty());
        assert!(panel.turn(1_010, UNIX).unwrap() <= FRAME_MS);
        assert_eq!(frames.count(), 2);
        assert!(frames.last() == frame_asking());
        // A choice opens the gate for its time, and folds the choices in the same write.
        panel.touch(&tap_on(2_000, ASK_5_MIN.0, ASK_5_MIN.1));
        assert_eq!(control.calls(), ["pause 300"]);
        assert!(panel.turn(2_010, UNIX).unwrap() <= FRAME_MS);
        assert_eq!(frames.count(), 3);
        assert!(frames.last() == frame_of(Blocking::Paused { left_secs: 300 }));
        // The control's seconds step, on its own clock: the next frame notices, and half a frame
        // later the new figure is written, and nothing else.
        control.set_left(Some(299));
        assert_eq!(panel.turn(2_135, UNIX).unwrap(), STILL_OFFSET_MS);
        assert_eq!(frames.count(), 3);
        assert_eq!(
            panel.turn(2_135 + STILL_OFFSET_MS, UNIX).unwrap(),
            FRAME_MS - STILL_OFFSET_MS
        );
        assert_eq!(frames.count(), 4);
        assert!(frames.last() == frame_of(Blocking::Paused { left_secs: 299 }));
        // The same seconds again: nothing to write.
        for at in [2_260, 2_322, 2_385, 2_447] {
            panel.turn(at, UNIX).unwrap();
        }
        assert_eq!(frames.count(), 4);
    }

    #[test]
    fn the_choices_open_the_gate_for_half_an_hour_and_an_hour_and_a_tap_elsewhere_only_folds_them()
    {
        let (mut panel, _, control) = panel();
        panel.turn(0, UNIX).unwrap();
        for (secs, (x, y)) in [(1_800, ASK_30_MIN), (3_600, (420, 270))] {
            control.resume();
            panel.turn(500, UNIX).unwrap();
            panel.touch(&tap_on(1_000, KEY.0, KEY.1));
            panel.turn(1_100, UNIX).unwrap();
            assert!(panel.nav.gate_ask());
            panel.touch(&tap_on(2_000, x, y));
            assert!(!panel.nav.gate_ask());
            assert_eq!(control.calls().last().unwrap(), &format!("pause {secs}"));
            panel.turn(2_100, UNIX).unwrap();
        }
        // Anywhere else on the screen only folds the choices.
        control.resume();
        panel.turn(3_000, UNIX).unwrap();
        panel.touch(&tap_on(4_000, KEY.0, KEY.1));
        panel.turn(4_100, UNIX).unwrap();
        let calls = control.calls().len();
        panel.touch(&tap_on(5_000, 300, 150));
        assert!(!panel.nav.gate_ask());
        assert_eq!(control.calls().len(), calls);
    }

    #[test]
    fn a_tap_while_paused_resumes() {
        let (mut panel, frames, control) = panel();
        // Five minutes left of a pause of five minutes: the gate is open and not yet refilled.
        control.set_left(Some(300));
        panel.turn(0, UNIX).unwrap();
        panel.touch(&tap_on(1_000, KEY.0, KEY.1));
        assert_eq!(control.calls(), ["resume"]);
        assert!(!panel.nav.gate_ask());
        assert_eq!(panel.turn(1_100, UNIX).unwrap(), FRAME_MS);
        assert!(frames.last() == frame_of(Blocking::On));
    }

    #[test]
    fn a_brush_and_a_tap_elsewhere_change_nothing() {
        let (mut panel, frames, control) = panel();
        panel.turn(0, UNIX).unwrap();
        panel.touch(&tap(1_000, 30, ON_SWITCH));
        // Away from the key a tap does nothing: the Drain's lane of names is no door (the field is NAMES').
        panel.touch(&tap_on(2_000, 300, 40));
        panel.turn(2_500, UNIX).unwrap();
        assert!(control.calls().is_empty());
        assert_eq!(frames.count(), 1);
    }

    #[test]
    fn a_finger_left_on_the_key_unfolds_the_choices_once_when_it_lifts() {
        let (mut panel, _, control) = panel();
        panel.touch(&tap(1_000, 240_000, ON_SWITCH));
        assert!(panel.nav.gate_ask());
        assert!(control.calls().is_empty());
    }

    #[test]
    fn a_press_cut_off_by_lost_events_does_nothing() {
        let (mut panel, _, control) = panel();
        let press = tap(1_000, 200, ON_SWITCH);
        // `tap` is four events down, two up.
        let (down, up) = press.split_at(4);
        panel.touch(down);
        panel.touch(&[dropped(1_100)]);
        panel.touch(up);
        assert!(control.calls().is_empty());
        assert!(!panel.nav.gate_ask());
    }

    #[test]
    fn a_press_whose_first_sample_was_lost_does_nothing_either() {
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
        assert!(!panel.nav.gate_ask());
        // The next press is whole again.
        panel.touch(&[pressure(1_900, 180)]);
        panel.touch(&tap(2_000, 60, ON_SWITCH));
        assert!(panel.nav.gate_ask());
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

    /// A Wi-Fi link that is up.
    fn joined() -> WifiStatus {
        WifiStatus {
            associated: true,
            signal_dbm: Some(-63),
            ap: None,
            freq_mhz: None,
            joined_secs: None,
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
        let mut panel = on_live(Panel::new(
            Measure {
                previous: Vec::new(),
                rows: rows.clone(),
            },
            Deps {
                lane: lane.clone(),
                ..deps(Arc::new(Counting(Mutex::new((0, 0)))))
            },
        ));
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
        // A listed name follows a refused one of 11 letters: the refused one stops at the gate and melts
        // while the listed one waits on the lane behind it. (One ahead of it would have left the lane, which
        // ends at the gate's cell now that `HOME` takes the cells left of it.) The refusal's dots land at
        // step 11, which is a motion write to itself.
        rig.refuse("ads.example");
        rig.lane.observe("listed.example", false, 1, |_| true);
        // The gate's choices are unfolded first, over the field and the funnel (the refusal runs on
        // under them); the toggle is the tap on a choice.
        rig.turn(0);
        rig.panel.touch(&tap_on(10, KEY.0, KEY.1));
        let (mut now, land) = (20, 11);
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
        rig.panel.touch(&tap_on(at - 100, ASK_5_MIN.0, ASK_5_MIN.1));
        assert_eq!(rig.control.calls(), ["pause 300"]);
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

    /// Where a tap works HOME's tiles and the lane's `HOME`.
    const HOME_DEVICES: (u16, u16) = (237, 130);
    const HOME_ALERTS: (u16, u16) = (394, 130);
    const HOME_GATE: (u16, u16) = (80, 246);
    const HOME_NAMES: (u16, u16) = (237, 246);
    const LANE_HOME: (u16, u16) = (50, 30);
    /// The first place of the wall of devices, and the third.
    const WALL_FIRST: (u16, u16) = (63, 115);
    const WALL_THIRD: (u16, u16) = (300, 115);
    /// The floor's left key, and its right one; and the four keys of the gate's choices (the first keeps).
    const FLOOR_LEFT: (u16, u16) = (100, 280);
    const FLOOR_RIGHT: (u16, u16) = (360, 280);
    const CHOICE_5_MIN: (u16, u16) = (180, 280);
    const CHOICE_30_MIN: (u16, u16) = (300, 280);

    /// What screen the panel shows, for a test to say where a tap took it.
    fn at_screen(rig: &Rig) -> (Section, Option<&Opened>) {
        (rig.panel.nav.root(), rig.panel.nav.top())
    }

    /// The first pipe of NAMES and of YOUR LIST, the second, and NAMES' door to YOUR LIST.
    const PIPE_FIRST: (u16, u16) = (100, 150);
    const PIPE_SECOND: (u16, u16) = (100, 200);
    const LIST_DOOR: (u16, u16) = (300, 100);
    /// The name line of an alert's slip, which opens NAME for a threat.
    const SLIP_NAME: (u16, u16) = (200, 190);

    /// Taps through the screens until every kind of intent has been carried out: the gate opened and shut,
    /// a device's ads blocked, let through, and an edit that is refused, a device's own gate opened and shut,
    /// an alert dismissed, a name allowed, refused and both taken back. An alert arrives on the way, from the
    /// device's screen. The rig is at HOME with `house()`, the day's names, and the panel's thread at `*now`.
    fn walk_through_every_intent(rig: &mut Rig, now: &mut u64) {
        let desk = hw(12);
        let until = *now + 300;
        rig.drive(now, until);
        assert_eq!(at_screen(rig), (Section::Home, None));
        // The main gate: HOME's key, the choices, a half hour; then the key again, which shuts it.
        rig.tap_at(now, HOME_GATE.0, HOME_GATE.1);
        assert_eq!(rig.panel.nav.root(), Section::Gate);
        rig.tap_at(now, CHOICE_30_MIN.0, CHOICE_30_MIN.1);
        assert_eq!(at_screen(rig), (Section::Home, None));
        assert_eq!(rig.control.calls(), ["pause 1800"]);
        assert_eq!(
            rig.panel.world.blocking,
            Some(Pause {
                left_secs: 1_800,
                total_secs: 1_800
            })
        );
        rig.tap_at(now, HOME_GATE.0, HOME_GATE.1);
        assert_eq!(rig.control.calls(), ["pause 1800", "resume"]);

        // The wall, the desk PC (ads pass), and the device's own screen.
        rig.tap_at(now, HOME_DEVICES.0, HOME_DEVICES.1);
        assert_eq!(at_screen(rig), (Section::Devices, None));
        rig.tap_at(now, WALL_FIRST.0, WALL_FIRST.1);
        assert_eq!(
            at_screen(rig),
            (Section::Devices, Some(&Opened::Device(desk)))
        );
        // Block its ads: the key, the question, its answer.
        rig.tap_at(now, FLOOR_LEFT.0, FLOOR_LEFT.1);
        assert_eq!(
            at_screen(rig),
            (
                Section::Devices,
                Some(&Opened::Confirm {
                    mac: desk,
                    pass: false
                })
            )
        );
        rig.tap_at(now, FLOOR_RIGHT.0, FLOOR_RIGHT.1);
        assert_eq!(rig.devices.state().edits, ["ads 12 false"]);
        // The inventory is read again at once, and the question that was answered is not asked again.
        let until = *now + FRAME_MS;
        rig.drive(now, until);
        assert_eq!(
            at_screen(rig),
            (Section::Devices, Some(&Opened::Device(desk)))
        );
        // Its own gate: the key, five minutes; then the key again, which shuts it.
        rig.tap_at(now, FLOOR_RIGHT.0, FLOOR_RIGHT.1);
        assert_eq!(
            at_screen(rig),
            (Section::Devices, Some(&Opened::ItsGate(desk)))
        );
        rig.tap_at(now, CHOICE_5_MIN.0, CHOICE_5_MIN.1);
        assert_eq!(rig.devices.state().edits, ["ads 12 false", "gate 12 300"]);
        let until = *now + FRAME_MS;
        rig.drive(now, until);
        assert_eq!(
            at_screen(rig),
            (Section::Devices, Some(&Opened::Device(desk)))
        );
        rig.tap_at(now, FLOOR_RIGHT.0, FLOOR_RIGHT.1);
        assert_eq!(
            rig.devices.state().edits,
            ["ads 12 false", "gate 12 300", "gate 12 0"]
        );
        let until = *now + FRAME_MS;
        rig.drive(now, until);
        // Let its ads pass again: the key, the question, its answer.
        rig.tap_at(now, FLOOR_LEFT.0, FLOOR_LEFT.1);
        assert_eq!(
            at_screen(rig),
            (
                Section::Devices,
                Some(&Opened::Confirm {
                    mac: desk,
                    pass: true
                })
            )
        );
        rig.tap_at(now, FLOOR_RIGHT.0, FLOOR_RIGHT.1);
        assert_eq!(rig.devices.state().edits.last().unwrap(), "ads 12 true");
        let until = *now + FRAME_MS;
        rig.drive(now, until);

        // An alert comes while the desk's screen shows: its slip opens by itself over whatever shows, and its
        // device, which the wall holds, is what SEE DEVICE opens (over the slip).
        let sam = Ipv4Addr::new(192, 0, 2, 23);
        rig.alerts.raise(threat_alert(7));
        let until = *now + 1_300;
        rig.drive(now, until);
        assert_eq!(at_screen(rig), (Section::Alerts, Some(&Opened::Alert(7))));
        assert_eq!(
            rig.panel.world.top_alert().and_then(|row| row.device),
            Some(hw(23))
        );
        rig.tap_at(now, FLOOR_RIGHT.0, FLOOR_RIGHT.1);
        assert_eq!(
            at_screen(rig),
            (Section::Alerts, Some(&Opened::Device(hw(23))))
        );
        assert_eq!(
            rig.devices.state().watching,
            Some(sam),
            "its names are watched"
        );
        rig.tap_at(now, LANE_HOME.0, LANE_HOME.1);
        assert_eq!(at_screen(rig), (Section::Home, None));
        // The alert waits: HOME's tile opens the log and its entry the slip, whose name line opens NAME. A
        // threat has no key to allow it. DISMISS acks the alert and goes back to the log.
        rig.tap_at(now, HOME_ALERTS.0, HOME_ALERTS.1);
        assert_eq!(at_screen(rig), (Section::Alerts, None), "the log");
        rig.tap_at(now, LOG_NEWEST.0, LOG_NEWEST.1);
        assert_eq!(at_screen(rig), (Section::Alerts, Some(&Opened::Alert(7))));
        rig.tap_at(now, SLIP_NAME.0, SLIP_NAME.1);
        let threat = Opened::Name("secure-login-verify.example".to_owned());
        assert_eq!(at_screen(rig), (Section::Alerts, Some(&threat)));
        rig.tap_at(now, FLOOR_RIGHT.0, FLOOR_RIGHT.1);
        assert_eq!(
            at_screen(rig),
            (Section::Alerts, Some(&threat)),
            "never allowed"
        );
        rig.tap_at(now, FLOOR_LEFT.0, FLOOR_LEFT.1);
        assert_eq!(at_screen(rig), (Section::Alerts, Some(&Opened::Alert(7))));
        rig.tap_at(now, FLOOR_LEFT.0, FLOOR_LEFT.1);
        assert_eq!(
            at_screen(rig),
            (Section::Alerts, None),
            "DISMISS goes back to the log"
        );
        rig.tap_at(now, LANE_HOME.0, LANE_HOME.1);
        assert_eq!(at_screen(rig), (Section::Home, None));
        assert_eq!(rig.alerts.acks(), [7]);
        assert!(rig.names.edits().is_empty());

        // NAMES: the day's most refused. ALLOW NAME on the first; REFUSE NAME on the second, which no list
        // holds; then YOUR LIST takes both back, the newest first.
        rig.names
            .state()
            .lists
            .retain(|(name, _)| name != "tracker.example.com");
        rig.tap_at(now, HOME_NAMES.0, HOME_NAMES.1);
        assert_eq!(at_screen(rig), (Section::Names, None));
        rig.tap_at(now, PIPE_FIRST.0, PIPE_FIRST.1);
        assert_eq!(
            at_screen(rig),
            (
                Section::Names,
                Some(&Opened::Name("ads.example.net".to_owned()))
            )
        );
        rig.tap_at(now, FLOOR_RIGHT.0, FLOOR_RIGHT.1);
        assert_eq!(rig.names.edits(), ["allow ads.example.net"]);
        assert_eq!(at_screen(rig), (Section::Names, None));
        rig.tap_at(now, PIPE_SECOND.0, PIPE_SECOND.1);
        rig.tap_at(now, FLOOR_RIGHT.0, FLOOR_RIGHT.1);
        assert_eq!(
            rig.names.edits(),
            ["allow ads.example.net", "refuse tracker.example.com"]
        );
        // What was edited is read at once: the valve of the first pipe is open now.
        assert!(rig.panel.world.top_names[0].open);
        assert!(!rig.panel.world.top_names[1].open);
        rig.tap_at(now, LIST_DOOR.0, LIST_DOOR.1);
        assert_eq!(at_screen(rig), (Section::Names, Some(&Opened::Yours)));
        assert_eq!(rig.panel.world.owner_total, 2);
        rig.tap_at(now, PIPE_FIRST.0, PIPE_FIRST.1);
        rig.tap_at(now, FLOOR_RIGHT.0, FLOOR_RIGHT.1);
        assert_eq!(
            rig.names.edits().last().unwrap(),
            "forget tracker.example.com"
        );
        assert_eq!(at_screen(rig), (Section::Names, Some(&Opened::Yours)));
        rig.tap_at(now, PIPE_FIRST.0, PIPE_FIRST.1);
        rig.tap_at(now, FLOOR_RIGHT.0, FLOOR_RIGHT.1);
        assert_eq!(rig.names.edits().last().unwrap(), "forget ads.example.net");
        assert_eq!(rig.panel.world.owner_total, 0);
        rig.tap_at(now, LANE_HOME.0, LANE_HOME.1);
        assert_eq!(at_screen(rig), (Section::Home, None));

        // An edit that the inventory refuses, because the device is gone from it between the panel's last
        // look and the tap: nothing changes, and the panel says so without saying whom.
        rig.tap_at(now, HOME_DEVICES.0, HOME_DEVICES.1);
        rig.tap_at(now, WALL_THIRD.0, WALL_THIRD.1);
        let tv = hw(31);
        assert_eq!(
            at_screen(rig),
            (Section::Devices, Some(&Opened::Device(tv)))
        );
        rig.devices
            .edit(|view| view.devices.retain(|device| device.mac.0 != tv));
        rig.tap_at(now, FLOOR_LEFT.0, FLOOR_LEFT.1);
        let edits = rig.devices.state().edits.len();
        rig.panel.touch(&tap_on(*now, FLOOR_RIGHT.0, FLOOR_RIGHT.1));
        assert_eq!(
            rig.devices.state().edits.len(),
            edits,
            "nothing was changed"
        );
    }

    /// HOME's LIVE tile, and the lane's words between `HOME` and the clock.
    const HOME_LIVE: (u16, u16) = (80, 130);
    const LANE_WORDS: (u16, u16) = (200, 30);
    /// The log's newest entry, which it prints last, at the bottom.
    const LOG_NEWEST: (u16, u16) = (200, 240);

    /// The frame that `screens` paints for where the panel is and what its world holds.
    fn painted(panel: &Panel<Recorder>) -> Vec<u8> {
        let view = screens::view_of(&panel.nav, &panel.world).expect("a screen with a view");
        let mut painter = ScreenPainter::new();
        painter.paint(view, screens::draw);
        painter.frame().to_vec()
    }

    /// The rows of the frames that were written, each from the one before it; the first has none.
    fn rows_of(frames: &Frames) -> Vec<usize> {
        let all = frames.all();
        all.windows(2)
            .map(|pair| changed_rows(&pair[0], &pair[1], WIDTH * 2).map_or(0, |rows| rows.len()))
            .collect()
    }

    #[test]
    fn a_boot_begins_at_home_which_is_written_whole_in_its_first_frame() {
        let mut rig = Rig::home(Arc::new(Fixed(reference_snapshot())));
        rig.turn(0);
        assert_eq!(at_screen(&rig), (Section::Home, None));
        assert_eq!(rig.frames.count(), 1);
        assert!(rig.frames.last() == painted(&rig.panel));
        // It is what the world says: 44% of 10,818 refused, 10:20, 212K names are not known to the
        // snapshot of these tests, the house's six places and a lamp on none.
        let world = &rig.panel.world;
        assert_eq!(world.share, Some(Share::Percent(44)));
        assert_eq!(world.queries_today, Some(10_818));
        assert_eq!(
            world.time,
            Some(TimeOfDay {
                hour: 10,
                minute: 20
            })
        );
        assert!(world.wifi_joined);
        assert_eq!(world.refused_today, Some(4_780));
        assert_eq!(world.devices.len(), 6);
        assert_eq!(world.version, crate::VERSION);
        assert_eq!(world.uptime_days, Some(0));
        assert_eq!(world.newcomer, Newcomer::Blocked);
        assert_eq!(world.blocking, None);
        assert_eq!(
            (world.alerts_waiting, world.top_alert().is_none()),
            (0, true)
        );
        // The wall is the labelled devices in their order, then the others, then the router.
        let names: Vec<&str> = world.devices.iter().map(|row| row.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "Desk PC",
                "Sam's phone",
                "Living room TV",
                "printer",
                "\u{b7}143",
                "\u{b7}1"
            ]
        );
    }

    #[test]
    fn a_home_with_nothing_to_move_paints_nothing_after_its_first_frame() {
        let mut rig = Rig::home(Arc::new(Fixed(reference_snapshot())));
        let mut now = 0;
        let writes = rig.drive(&mut now, 20_000);
        assert_eq!(writes.len(), 1, "{writes:?}");
        assert!(now > 20_000);
    }

    #[test]
    fn the_wall_and_the_device_are_read_only_while_their_screens_show() {
        let mut rig = Rig::new(Arc::new(Fixed(reference_snapshot())));
        let mut now = 0;
        // LIVE: no device is read at all, and the alerts are asked for once a second.
        rig.drive(&mut now, 10_000);
        assert_eq!(rig.devices.reads(), (0, 0, 0));
        let asked = rig.alerts.asked();
        assert!((10..=11).contains(&asked), "{asked}");

        // HOME: the inventory every two seconds, who asked every second.
        rig.tap_at(&mut now, LANE_HOME.0, LANE_HOME.1);
        assert_eq!(at_screen(&rig), (Section::Home, None));
        let (views, askings, watched) = rig.devices.reads();
        assert_eq!(
            (views, askings, watched),
            (1, 1, 0),
            "read at once on arriving"
        );
        let from = now;
        rig.drive(&mut now, from + 10_000 - 1);
        let (views, askings, watched) = rig.devices.reads();
        assert_eq!(
            (views, askings, watched),
            (6, 11, 0),
            "five more reads in ten seconds, ten more of who asked"
        );

        // DEVICES: the same cadences; no more at once, as HOME read them.
        rig.tap_at(&mut now, HOME_DEVICES.0, HOME_DEVICES.1);
        assert_eq!(at_screen(&rig), (Section::Devices, None));
        let before = rig.devices.reads();
        rig.run_for(&mut now, 10_000);
        let after = rig.devices.reads();
        assert!(
            (5..=6).contains(&(after.0 - before.0)),
            "{before:?} {after:?}"
        );
        assert!(
            (10..=11).contains(&(after.1 - before.1)),
            "{before:?} {after:?}"
        );
        assert_eq!(after.2, 0);

        // DEVICE: the inventory, never who asked, and the device's names every frame.
        rig.tap_at(&mut now, WALL_FIRST.0, WALL_FIRST.1);
        assert_eq!(
            at_screen(&rig)
                .1
                .map(|screen| matches!(screen, Opened::Device(_))),
            Some(true)
        );
        let before = rig.devices.reads();
        rig.run_for(&mut now, 10_000);
        let after = rig.devices.reads();
        assert!(
            (5..=6).contains(&(after.0 - before.0)),
            "{before:?} {after:?}"
        );
        assert_eq!(after.1, before.1, "nobody is asked who asked on DEVICE");
        assert!(
            (79..=81).contains(&(after.2 - before.2)),
            "{before:?} {after:?}"
        );

        // CONFIRM and ITS GATE over it read the inventory and nothing else.
        rig.tap_at(&mut now, FLOOR_LEFT.0, FLOOR_LEFT.1);
        assert!(matches!(at_screen(&rig).1, Some(Opened::Confirm { .. })));
        let before = rig.devices.reads();
        rig.run_for(&mut now, 6_000);
        let after = rig.devices.reads();
        assert!(
            (3..=4).contains(&(after.0 - before.0)),
            "{before:?} {after:?}"
        );
        assert_eq!((after.1, after.2), (before.1, before.2));

        // ALERTS and an ALERT name their devices: the inventory every two seconds, never who asked and never a
        // device's names. An alert that arrives opens its slip.
        rig.tap_at(&mut now, LANE_HOME.0, LANE_HOME.1);
        rig.alerts.raise(threat_alert(3));
        rig.run_for(&mut now, 1_500);
        assert!(matches!(at_screen(&rig).1, Some(Opened::Alert(3))));
        let before = rig.devices.reads();
        rig.run_for(&mut now, 10_000);
        let after = rig.devices.reads();
        assert!(
            (5..=6).contains(&(after.0 - before.0)),
            "{before:?} {after:?}"
        );
        assert_eq!((after.1, after.2), (before.1, before.2));
        // DISMISS goes back to the log: the same.
        rig.tap_at(&mut now, FLOOR_LEFT.0, FLOOR_LEFT.1);
        assert_eq!(at_screen(&rig), (Section::Alerts, None));
        let before = rig.devices.reads();
        rig.run_for(&mut now, 6_000);
        let after = rig.devices.reads();
        assert!(
            (3..=4).contains(&(after.0 - before.0)),
            "{before:?} {after:?}"
        );
        assert_eq!((after.1, after.2), (before.1, before.2));
        // GATE and SYSTEM read no device at all.
        rig.tap_at(&mut now, LANE_HOME.0, LANE_HOME.1);
        rig.tap_at(&mut now, HOME_GATE.0, HOME_GATE.1);
        assert_eq!(rig.panel.nav.root(), Section::Gate);
        let before = rig.devices.reads();
        rig.run_for(&mut now, 6_000);
        assert_eq!(rig.devices.reads(), before);
        rig.tap_at(&mut now, LANE_HOME.0, LANE_HOME.1);
        rig.tap_at(&mut now, 394, 246);
        assert_eq!(rig.panel.nav.root(), Section::System);
        let before = rig.devices.reads();
        rig.run_for(&mut now, 6_000);
        assert_eq!(rig.devices.reads(), before);
        assert_eq!(rig.names.reads(), 0, "no screen of these reads a name");
    }

    #[test]
    fn the_names_are_read_only_while_their_screens_show_and_every_five_seconds() {
        let mut rig = Rig::home(Arc::new(Fixed(reference_snapshot())));
        let mut now = 0;
        // HOME, LIVE, the wall, the log and SYSTEM read no name at all.
        rig.drive(&mut now, 300);
        for door in [HOME_DEVICES, HOME_ALERTS] {
            rig.tap_at(&mut now, door.0, door.1);
            rig.run_for(&mut now, 3_000);
            rig.tap_at(&mut now, LANE_HOME.0, LANE_HOME.1);
        }
        rig.tap_at(&mut now, 80, 130);
        assert_eq!(rig.panel.nav.root(), Section::Live);
        rig.run_for(&mut now, 3_000);
        rig.tap_at(&mut now, LANE_HOME.0, LANE_HOME.1);
        assert_eq!(rig.names.reads(), 0);
        assert!(rig.panel.world.top_names.is_empty());

        // NAMES: read at once, then every five seconds; the pipes and the list's length are the world's.
        let tops = |rig: &Rig| rig.names.state().reads[0];
        rig.tap_at(&mut now, HOME_NAMES.0, HOME_NAMES.1);
        assert_eq!(at_screen(&rig), (Section::Names, None));
        assert_eq!(tops(&rig), 1, "read at once on arriving");
        let names: Vec<(&str, u32)> = rig
            .panel
            .world
            .top_names
            .iter()
            .map(|row| (row.name.as_str(), row.count))
            .collect();
        assert_eq!(
            names,
            [
                ("ads.example.net", 1_204),
                ("tracker.example.com", 612),
                ("metrics.example.org", 31)
            ]
        );
        assert_eq!(rig.panel.world.owner_total, 0);
        let from = now;
        rig.drive(&mut now, from + 10_000 - 1);
        assert_eq!(tops(&rig), 3, "two more in ten seconds");
        // The facts of a name are read for NAME alone: the lists and the owner's entry, at once.
        assert_eq!(rig.names.state().reads[4], 0);
        rig.tap_at(&mut now, PIPE_FIRST.0, PIPE_FIRST.1);
        assert_eq!(rig.names.state().reads[4], 1);
        let facts = rig.panel.world.name_facts.clone().unwrap();
        assert_eq!(facts.name, "ads.example.net");
        assert_eq!(
            (facts.class, facts.owner, facts.count),
            (qb_panel::os::world::NameClass::Ads, None, Some(1_204))
        );
        // Back to NAMES: the name's facts are gone from the world; YOUR LIST reads nothing extra at once.
        rig.tap_at(&mut now, FLOOR_LEFT.0, FLOOR_LEFT.1);
        assert_eq!(at_screen(&rig), (Section::Names, None));
        assert!(rig.panel.world.name_facts.is_none());
        let reads = rig.names.reads();
        rig.tap_at(&mut now, LIST_DOOR.0, LIST_DOOR.1);
        assert_eq!(at_screen(&rig), (Section::Names, Some(&Opened::Yours)));
        assert_eq!(rig.names.reads(), reads, "the same screens' read serves");
        // HOME: reads stop, and what was read goes.
        rig.tap_at(&mut now, LANE_HOME.0, LANE_HOME.1);
        let reads = rig.names.reads();
        rig.run_for(&mut now, 12_000);
        assert_eq!(rig.names.reads(), reads);
        assert!(rig.panel.world.top_names.is_empty());
        assert_eq!(rig.panel.world.owner_total, 0);
    }

    #[test]
    fn the_idle_log_has_when_the_last_entry_was_filed_and_when_the_watch_opened() {
        let word = |moment: Option<Moment>| moment.map(Moment::word);
        let mut rig = Rig::home(Arc::new(Fixed(reference_snapshot())));
        // The board had been up an hour when the panel began.
        rig.panel.boot_ms = 3_600_000;
        let mut now = 0;
        rig.drive(&mut now, 300);
        assert_eq!(
            word(rig.panel.world.last_entry),
            None,
            "none was ever filed"
        );
        assert_eq!(
            word(rig.panel.world.watch_opened).as_deref(),
            Some("FRI 09:20"),
            "the clock less the uptime"
        );
        // An alert that was filed and dismissed is still the last entry: when it last happened.
        rig.alerts.raise(threat_alert(7));
        rig.alerts.api_ack(7);
        let until = now + 1_300;
        rig.drive(&mut now, until);
        assert_eq!(
            word(rig.panel.world.last_entry).as_deref(),
            Some("FRI 10:19")
        );
        // The opening is taken once: the clock running on (or being stepped) does not move it.
        rig.panel.turn(now + 5_000, UNIX + 3_600).unwrap();
        assert_eq!(
            word(rig.panel.world.watch_opened).as_deref(),
            Some("FRI 09:20")
        );
        // The local day and hour are the zone's: an hour behind UTC the opening is 08:20.
        let mut zoned = Rig::home(Arc::new(Fixed(Snapshot {
            utc_offset_secs: -3_600,
            ..reference_snapshot()
        })));
        zoned.panel.boot_ms = 3_600_000;
        let mut at = 0;
        zoned.drive(&mut at, 300);
        assert_eq!(
            word(zoned.panel.world.watch_opened).as_deref(),
            Some("FRI 08:20")
        );
        // With the clock not set the watch has no opening, and nothing is made up.
        let mut rig = Rig::home(Arc::new(Nothing));
        let mut now = 0;
        rig.drive(&mut now, 300);
        assert_eq!(rig.panel.world.watch_opened, None);
    }

    #[test]
    fn the_logs_cursor_blinks_four_frames_on_and_four_off_and_is_the_only_thing_written() {
        let mut rig = Rig::home(Arc::new(Fixed(reference_snapshot())));
        let mut now = 0;
        rig.drive(&mut now, 300);
        assert!(!rig.panel.world.cursor_on, "HOME has no cursor");
        rig.tap_at(&mut now, HOME_ALERTS.0, HOME_ALERTS.1);
        assert_eq!(at_screen(&rig), (Section::Alerts, None));
        let mut states = Vec::new();
        for _ in 0..40 {
            rig.turn(now);
            states.push(rig.panel.world.cursor_on);
            now += FRAME_MS;
        }
        // Runs of four, whichever the first one is (the counter was running before the log came).
        let mut runs: Vec<usize> = Vec::new();
        for (n, state) in states.iter().enumerate() {
            if n > 0 && states[n - 1] == *state {
                *runs.last_mut().unwrap() += 1;
            } else {
                runs.push(1);
            }
        }
        assert!(
            runs[1..runs.len() - 1].iter().all(|&run| run == 4),
            "{states:?}"
        );
        // At rest nothing else moves: every write is the cursor's few rows, one every four frames.
        let writes = rig.run_for(&mut now, 20_000);
        assert!(
            writes
                .iter()
                .all(|write| write.rows.is_some_and(|rows| rows <= 20)),
            "{writes:?}"
        );
        assert!((38..=42).contains(&writes.len()), "{} writes", writes.len());
        // Leaving the log takes the cursor with it, and no other screen has one.
        rig.tap_at(&mut now, LANE_HOME.0, LANE_HOME.1);
        let until = now + 2_000;
        let after = rig.drive(&mut now, until);
        assert!(!rig.panel.world.cursor_on);
        assert!(after.is_empty(), "{after:?}");
    }

    #[test]
    fn a_device_screen_watches_its_device_from_when_it_opens_until_it_closes() {
        let mut rig = Rig::home(Arc::new(Fixed(reference_snapshot())));
        let desk = Some(Ipv4Addr::new(192, 0, 2, 12));
        let mut now = 0;
        rig.drive(&mut now, 300);
        assert!(rig.devices.state().watches.is_empty());
        rig.tap_at(&mut now, HOME_DEVICES.0, HOME_DEVICES.1);
        assert!(
            rig.devices.state().watches.is_empty(),
            "the wall watches nobody"
        );
        rig.tap_at(&mut now, WALL_FIRST.0, WALL_FIRST.1);
        assert_eq!(rig.devices.state().watches, [desk]);
        // The names it asks come to its screen, newest first, fitted.
        rig.devices.state().watched = vec![
            LaneWatched {
                name: "ads.example".to_owned(),
                whole: Some("ads.example".to_owned()),
                outcome: WatchedOutcome::Refused,
            },
            LaneWatched {
                name: "example.org".to_owned(),
                whole: Some("example.org".to_owned()),
                outcome: WatchedOutcome::Answered,
            },
        ];
        let until = now + FRAME_MS * 2;
        rig.drive(&mut now, until);
        let names: Vec<(&str, Outcome)> = rig
            .panel
            .world
            .watched
            .iter()
            .map(|name| (name.name.as_str(), name.outcome))
            .collect();
        assert_eq!(
            names,
            [
                ("ads.example", Outcome::Refused),
                ("example.org", Outcome::Answered)
            ]
        );
        // Nothing but the watch of the same device has been asked for since.
        assert_eq!(rig.devices.state().watches, [desk]);

        // A question over the device's screen stops the watch, and the screen back starts it again.
        rig.tap_at(&mut now, FLOOR_LEFT.0, FLOOR_LEFT.1);
        assert!(matches!(at_screen(&rig).1, Some(Opened::Confirm { .. })));
        assert_eq!(rig.devices.state().watches, [desk, None]);
        assert!(
            rig.panel.world.watched.is_empty(),
            "what was kept goes with the watch"
        );
        rig.tap_at(&mut now, FLOOR_LEFT.0, FLOOR_LEFT.1);
        assert!(matches!(at_screen(&rig).1, Some(Opened::Device(_))));
        assert_eq!(rig.devices.state().watches, [desk, None, desk]);

        // The lane's HOME closes it.
        rig.tap_at(&mut now, LANE_HOME.0, LANE_HOME.1);
        assert_eq!(at_screen(&rig), (Section::Home, None));
        assert_eq!(rig.devices.state().watches, [desk, None, desk, None]);
    }

    #[test]
    fn a_name_row_of_a_device_opens_name_with_the_whole_name_and_back_watches_again() {
        let mut rig = Rig::home(Arc::new(Fixed(reference_snapshot())));
        let desk = Some(Ipv4Addr::new(192, 0, 2, 12));
        let mut now = 0;
        rig.drive(&mut now, 300);
        rig.tap_at(&mut now, HOME_DEVICES.0, HOME_DEVICES.1);
        rig.tap_at(&mut now, WALL_FIRST.0, WALL_FIRST.1);
        // A name longer than the lane shows: its row has the feed's cut, and NAME is opened with the whole.
        let long = format!("{}.tracker.example.org", "a".repeat(40));
        rig.devices.state().watched = vec![LaneWatched {
            name: long.get(..32).unwrap().to_owned(),
            whole: Some(long.clone()),
            outcome: WatchedOutcome::Refused,
        }];
        let until = now + FRAME_MS * 2;
        rig.drive(&mut now, until);
        let shown = rig
            .panel
            .world
            .watched
            .first()
            .map(|name| name.name.clone());
        assert!(
            shown.is_some_and(|text| text.starts_with("aaaa") && !text.contains("example")),
            "the row shows the feed's cut"
        );
        rig.tap_at(&mut now, 100, 150);
        assert_eq!(rig.panel.nav.shown_name(), Some(long.as_str()));
        assert_eq!(
            rig.devices.state().watches,
            [desk, None],
            "NAME stops the watch"
        );
        // NAME reads the facts of the whole name.
        let until = now + 1_000;
        rig.drive(&mut now, until);
        assert_eq!(
            rig.panel
                .world
                .name_facts
                .as_ref()
                .map(|facts| facts.name.as_str()),
            Some(long.as_str())
        );
        // Its BACK (the floor's left key, KEEP …) is DEVICE again, which watches again.
        rig.tap_at(&mut now, FLOOR_LEFT.0, FLOOR_LEFT.1);
        assert!(matches!(at_screen(&rig).1, Some(Opened::Device(_))));
        assert_eq!(rig.devices.state().watches, [desk, None, desk]);
    }

    /// A panel on a surface that can be broken from outside, with a device that is watched.
    struct Switch(Arc<std::sync::atomic::AtomicBool>);

    impl Surface for Switch {
        fn show(&mut self, _frame: &[u8]) -> io::Result<()> {
            if self.0.load(std::sync::atomic::Ordering::Relaxed) {
                Err(io::Error::other("the screen is gone"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn a_new_panel_lets_go_of_a_watch_that_a_panel_before_it_left_on() {
        let desk = Ipv4Addr::new(192, 0, 2, 12);
        let devices = FakeDevices::with(house());
        // The panel before this one failed with DEVICE open, and the lane feed went on keeping the names
        // of the desk.
        devices.watch_client(Some(desk));
        assert_eq!(devices.state().watching, Some(desk));
        let _panel = Panel::new(
            recorder().0,
            Deps {
                devices: Arc::new(devices.clone()),
                ..deps(Arc::new(Nothing))
            },
        );
        assert_eq!(devices.state().watching, None);
        assert_eq!(devices.state().watches, [Some(desk), None]);
    }

    #[test]
    fn a_panel_that_ends_lets_go_of_the_watch_whatever_its_end() {
        let broken = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let devices = FakeDevices::with(house());
        let mut panel = Panel::new(
            Switch(broken.clone()),
            Deps {
                devices: Arc::new(devices.clone()),
                ..deps(Arc::new(Fixed(reference_snapshot())))
            },
        );
        // DEVICE of the desk opens: its names are watched.
        let tap_at = |panel: &mut Panel<Switch>, now: u64, x: u16, y: u16| {
            panel.touch(&tap(now, 60, raw_of(x, y)));
            panel.turn(now + 100, UNIX).unwrap();
        };
        panel.turn(0, UNIX).unwrap();
        tap_at(&mut panel, 300, HOME_DEVICES.0, HOME_DEVICES.1);
        tap_at(&mut panel, 600, WALL_FIRST.0, WALL_FIRST.1);
        let desk = Some(Ipv4Addr::new(192, 0, 2, 12));
        assert_eq!(devices.state().watching, desk);

        // The screen breaks: `serve` returns the failure, and the watch is let go with it.
        broken.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(matches!(
            serve(&mut panel, None::<std::io::PipeReader>, Instant::now()),
            PanelEnd::Failed(_)
        ));
        assert_eq!(devices.state().watching, None);
        assert_eq!(devices.state().watches.last(), Some(&None));
    }

    #[test]
    fn the_watch_is_cleared_when_the_idle_minute_takes_the_panel_home_and_when_the_device_goes() {
        let mut rig = Rig::home(Arc::new(Fixed(reference_snapshot())));
        let (desk, tv) = (
            Some(Ipv4Addr::new(192, 0, 2, 12)),
            Some(Ipv4Addr::new(192, 0, 2, 31)),
        );
        let mut now = 0;
        rig.drive(&mut now, 300);
        rig.tap_at(&mut now, HOME_DEVICES.0, HOME_DEVICES.1);
        rig.tap_at(&mut now, WALL_FIRST.0, WALL_FIRST.1);
        assert_eq!(rig.devices.state().watches, [desk]);
        // A minute without a touch: HOME, and the watch is let go in the same turn.
        let touched = now;
        rig.drive(&mut now, touched + 59_000);
        assert!(matches!(at_screen(&rig).1, Some(Opened::Device(_))));
        rig.drive(&mut now, touched + 61_000);
        assert_eq!(at_screen(&rig), (Section::Home, None));
        assert_eq!(rig.devices.state().watches, [desk, None]);

        // The living room TV: it goes from the inventory while its screen shows.
        rig.tap_at(&mut now, HOME_DEVICES.0, HOME_DEVICES.1);
        rig.tap_at(&mut now, WALL_THIRD.0, WALL_THIRD.1);
        assert_eq!(rig.devices.state().watches, [desk, None, tv]);
        rig.devices
            .edit(|view| view.devices.retain(|device| device.mac.0 != hw(31)));
        let until = now + 2_500;
        rig.drive(&mut now, until);
        // The next read finds it gone, and the screen goes back to the wall, which shows no such place.
        assert_eq!(at_screen(&rig), (Section::Devices, None));
        assert_eq!(rig.devices.state().watches, [desk, None, tv, None]);
        assert!(rig.panel.world.device(&hw(31)).is_none());
        assert_eq!(rig.panel.world.devices.len(), 5);
    }

    #[test]
    fn a_confirm_that_is_done_or_no_longer_true_is_popped_to_the_device_under_it() {
        let mut rig = Rig::home(Arc::new(Fixed(reference_snapshot())));
        let mut now = 0;
        rig.drive(&mut now, 300);
        rig.tap_at(&mut now, HOME_DEVICES.0, HOME_DEVICES.1);
        rig.tap_at(&mut now, WALL_FIRST.0, WALL_FIRST.1);
        rig.tap_at(&mut now, FLOOR_LEFT.0, FLOOR_LEFT.1);
        let desk = hw(12);
        assert_eq!(
            at_screen(&rig).1,
            Some(&Opened::Confirm {
                mac: desk,
                pass: false
            })
        );
        // The desktop blocked its ads in the meantime: the question has no answer to give.
        rig.devices.edit(|view| view.devices[0].exempt = false);
        let until = now + 2_500;
        rig.drive(&mut now, until);
        assert_eq!(at_screen(&rig).1, Some(&Opened::Device(desk)));
    }

    #[test]
    fn a_minute_without_a_touch_takes_the_panel_home_in_one_write_and_a_touch_starts_the_minute_again()
     {
        let mut rig = Rig::home(Arc::new(Fixed(reference_snapshot())));
        let mut now = 0;
        rig.drive(&mut now, 300);
        rig.tap_at(&mut now, HOME_DEVICES.0, HOME_DEVICES.1);
        let touched = now;
        // A press that is no tap is a touch all the same: it starts the minute again at 50 s.
        rig.drive(&mut now, touched + 50_000);
        rig.panel.touch(&tap(1, 10, ELSEWHERE));
        let until = touched + 100_000;
        rig.drive(&mut now, until);
        assert_eq!(at_screen(&rig), (Section::Devices, None), "{now} ms");
        let writes = rig.frames.count();
        let until = touched + 112_000;
        rig.drive(&mut now, until);
        assert_eq!(at_screen(&rig), (Section::Home, None));
        // HOME was written whole once, and nothing else was written.
        assert_eq!(rig.frames.count(), writes + 1);
        assert!(rig.frames.last() == painted(&rig.panel));
        // At HOME it stays, writing nothing, for as long as nobody touches.
        let until = touched + 400_000;
        let more = rig.drive(&mut now, until);
        assert!(more.is_empty(), "{more:?}");
    }

    #[test]
    fn a_switch_of_screens_is_one_full_write_of_the_screen_and_leaving_live_and_coming_back_is_too()
    {
        let mut rig = Rig::new(Arc::new(Fixed(reference_snapshot())));
        rig.refuse("ads.example.org");
        let mut now = 0;
        rig.drive(&mut now, 1_000);
        let live = rig.frames.count();
        // LIVE to HOME: one write, which is the whole of HOME.
        rig.tap_at(&mut now, LANE_HOME.0, LANE_HOME.1);
        assert_eq!(rig.frames.count(), live + 1);
        assert!(rig.frames.last() == painted(&rig.panel));
        let rows = rows_of(&rig.frames);
        assert!(*rows.last().unwrap() > 200, "{rows:?}");
        // The Drain ran on behind it: names still go through it and the figures follow the snapshot.
        rig.refuse("tracker.example");
        let until = now + 3_000;
        rig.drive(&mut now, until);
        // HOME to LIVE: the Drain as it is now, written whole, and it is what a Drain painted from this
        // state gives.
        rig.tap_at(&mut now, HOME_LIVE.0, HOME_LIVE.1);
        assert_eq!(at_screen(&rig), (Section::Live, None));
        let shown = rig.panel.shown.clone();
        assert_eq!(shown, rig.panel.wanted);
        assert!(rig.frames.last() == Painter::new().paint(&rig.panel.drain, &shown));
        // And from there it goes on in motion writes of its own, each within the budget.
        let until = now + 6_000;
        let writes = rig.drive(&mut now, until);
        assert!(writes.len() > 10);
        assert!(
            writes
                .iter()
                .all(|write| write.rows.is_none_or(|rows| rows <= 80)),
            "{writes:?}"
        );
    }

    #[test]
    fn the_gates_toggle_is_one_full_write_and_its_countdown_after_it_is_one_band_a_second() {
        let mut rig = Rig::home(Arc::new(Fixed(reference_snapshot())));
        let mut now = 0;
        rig.drive(&mut now, 1_000);
        let before = rig.frames.count();
        // Someone opens the gate for half an hour from the desktop.
        rig.control.set_left(Some(1_800));
        let until = now + 500;
        rig.drive(&mut now, until);
        assert_eq!(rig.frames.count(), before + 1);
        assert!(rig.frames.last() == painted(&rig.panel));
        assert_eq!(
            rig.panel.world.blocking,
            Some(Pause {
                left_secs: 1_800,
                total_secs: 1_800
            })
        );
        // The lane and the gate's tile changed together: over a hundred rows, written at once.
        assert!(*rows_of(&rig.frames).last().unwrap() > 80);
        // Every second after it, the figure of the tile: one write of its own.
        let mark = rig.frames.count();
        for left in (1_790..1_800).rev() {
            rig.control.set_left(Some(left));
            let until = now + 1_000;
            rig.drive(&mut now, until);
        }
        let rows: Vec<usize> = rows_of(&rig.frames).split_off(mark - 1);
        assert_eq!(rows.len(), 10, "{rows:?}");
        assert!(
            rows.iter().all(|&rows| (1..=80).contains(&rows)),
            "{rows:?}"
        );
        // The pause ends by itself: the toggle back is one full write again.
        let before = rig.frames.count();
        rig.control.set_left(None);
        let until = now + 500;
        rig.drive(&mut now, until);
        assert_eq!(rig.frames.count(), before + 1);
        assert_eq!(rig.panel.world.blocking, None);
        assert!(rig.frames.last() == painted(&rig.panel));
    }

    #[test]
    fn the_gates_total_is_what_it_was_opened_for_and_a_pause_from_elsewhere_is_taken_for_its_length()
     {
        let mut rig = Rig::new(Arc::new(Fixed(reference_snapshot())));
        let mut now = 0;
        rig.drive(&mut now, 300);
        // Opened on the panel for half an hour: 900 s left is half of it.
        rig.panel.touch(&tap_on(now, KEY.0, KEY.1));
        let until = now + 300;
        rig.drive(&mut now, until);
        rig.panel.touch(&tap_on(now, ASK_30_MIN.0, ASK_30_MIN.1));
        assert_eq!(rig.control.calls(), ["pause 1800"]);
        for (left, fill) in [(1_800, 0), (900, 9), (180, 17), (1, 18)] {
            rig.control.set_left(Some(left));
            let until = now + 300;
            rig.drive(&mut now, until);
            assert_eq!(rig.panel.wanted.gate_fill, fill, "{left} s left");
            assert_eq!(rig.panel.gate_total, Some(1_800));
        }
        // It ends, and what is remembered goes with it.
        rig.control.set_left(None);
        let until = now + 300;
        rig.drive(&mut now, until);
        assert_eq!(rig.panel.gate_total, None);
        // A pause the API made, with 1,000 s left, is taken for half an hour; as it runs down the total
        // holds, so the gate does not jump.
        rig.control.set_left(Some(1_000));
        let until = now + 300;
        rig.drive(&mut now, until);
        assert_eq!(
            (rig.panel.gate_total, rig.panel.wanted.gate_fill),
            (Some(1_800), 8)
        );
        rig.control.set_left(Some(250));
        let until = now + 300;
        rig.drive(&mut now, until);
        assert_eq!(
            (rig.panel.gate_total, rig.panel.wanted.gate_fill),
            (Some(1_800), 16)
        );
        rig.control.set_left(None);
        let until = now + 300;
        rig.drive(&mut now, until);
        // A short one, which came from elsewhere, is five minutes.
        rig.control.set_left(Some(250));
        let until = now + 300;
        rig.drive(&mut now, until);
        assert_eq!(
            (rig.panel.gate_total, rig.panel.wanted.gate_fill),
            (Some(300), 3)
        );
    }

    #[test]
    fn homes_newest_is_when_the_alert_last_happened_not_when_it_first_did() {
        let mut rig = Rig::home(Arc::new(Fixed(reference_snapshot())));
        let mut now = 0;
        rig.drive(&mut now, 300);
        assert_eq!(rig.panel.world.alert_newest, None);
        // The threat first came at 10:03 and came again at 10:19; the clock says 10:20.
        rig.alerts.raise(threat_alert(7));
        let until = now + 1_300;
        rig.drive(&mut now, until);
        assert_eq!(
            rig.panel.world.alert_newest,
            Some(TimeOfDay {
                hour: 10,
                minute: 19
            })
        );
        // An alert that last happened before today is no time of day, however fresh its first sighting.
        rig.alerts.api_ack(7);
        rig.alerts.raise(PanelAlert {
            first_unix: UNIX - 90_000,
            last_unix: UNIX - 86_400,
            ..threat_alert(9)
        });
        let until = now + 1_300;
        rig.drive(&mut now, until);
        assert_eq!(rig.panel.world.alert_newest, None);
        assert_eq!(rig.panel.world.alerts_waiting, 1);
    }

    #[test]
    fn a_new_alert_opens_its_slip_by_itself_waits_once_left_and_dismiss_acks_it() {
        let mut rig = Rig::home(Arc::new(Fixed(reference_snapshot())));
        let mut now = 0;
        rig.drive(&mut now, 300);
        // With none waiting the tile opens the log, which says so.
        rig.tap_at(&mut now, HOME_ALERTS.0, HOME_ALERTS.1);
        assert_eq!(at_screen(&rig), (Section::Alerts, None));
        assert_eq!(rig.panel.world.alerts_waiting, 0);
        rig.tap_at(&mut now, LANE_HOME.0, LANE_HOME.1);
        assert_eq!(at_screen(&rig), (Section::Home, None));

        // Two come in one second: the high one opens, and the newer, lesser one waits in the log.
        rig.alerts.raise(threat_alert(7));
        rig.alerts.raise(PanelAlert {
            severity: Severity::Info,
            ..threat_alert(8)
        });
        let until = now + 1_300;
        rig.drive(&mut now, until);
        assert_eq!(at_screen(&rig), (Section::Alerts, Some(&Opened::Alert(7))));
        let world = &rig.panel.world;
        assert_eq!(world.alerts_waiting, 2);
        let ids: Vec<u64> = world.alerts.iter().map(|row| row.id).collect();
        assert_eq!(ids, [8, 7], "the log holds the newest first");
        assert!(world.alert_newest.is_some());
        // The slip is made of what the store carries and what the wall names.
        let row = world.alert(7).cloned().unwrap();
        assert_eq!(row.title, "THREAT BLOCKED");
        assert_eq!(row.lines[0], "secure-login-verify.example");
        assert_eq!(row.lines[1], "Sam's phone asked 3 times by 10:19");
        assert!(row.high);
        assert_eq!(
            (row.stamp, row.who.as_str(), row.device),
            (AlertStamp::Refused, "Sam's phone", Some(hw(23)))
        );
        assert_eq!(row.name.as_deref(), Some("secure-login-verify.example"));
        assert_eq!(row.at.map(When::word).as_deref(), Some("10:19"));
        assert!(rig.frames.last() == painted(&rig.panel));
        // It is shown once: going back leaves both waiting, with the tile and the lane to say so.
        rig.tap_at(&mut now, LANE_HOME.0, LANE_HOME.1);
        let until = now + 2_000;
        rig.drive(&mut now, until);
        assert_eq!(at_screen(&rig), (Section::Home, None));
        assert_eq!(rig.panel.world.alerts_waiting, 2);
        assert_eq!(rig.panel.world.top_alert().map(|alert| alert.id), Some(8));

        // The lane's words open the log, and the newest entry, which it prints last, the slip.
        rig.tap_at(&mut now, LANE_WORDS.0, LANE_WORDS.1);
        assert_eq!(at_screen(&rig), (Section::Alerts, None));
        rig.tap_at(&mut now, LOG_NEWEST.0, LOG_NEWEST.1);
        assert_eq!(at_screen(&rig), (Section::Alerts, Some(&Opened::Alert(8))));
        // Dismissed: acked in the store, back at the log, which is of what waits now.
        rig.tap_at(&mut now, FLOOR_LEFT.0, FLOOR_LEFT.1);
        assert_eq!(rig.alerts.acks(), [8]);
        assert_eq!(at_screen(&rig), (Section::Alerts, None));
        assert_eq!(rig.panel.world.alerts_waiting, 1);
        assert_eq!(rig.panel.world.top_alert().map(|alert| alert.id), Some(7));
        assert!(rig.frames.last() == painted(&rig.panel));
    }

    #[test]
    fn an_alert_screen_goes_back_to_the_log_when_the_desktop_acks_its_alert_and_a_newer_one_opens_over_it()
     {
        let mut rig = Rig::home(Arc::new(Fixed(reference_snapshot())));
        let mut now = 0;
        rig.alerts.raise(threat_alert(7));
        rig.drive(&mut now, 1_300);
        assert_eq!(at_screen(&rig), (Section::Alerts, Some(&Opened::Alert(7))));
        // The desktop acked it: within a second the screen is gone, and the log is where the panel is.
        rig.alerts.api_ack(7);
        let until = now + 1_300;
        rig.drive(&mut now, until);
        assert_eq!(at_screen(&rig), (Section::Alerts, None));
        assert_eq!(rig.panel.world.alerts_waiting, 0);
        assert!(rig.frames.last() == painted(&rig.panel));
        assert!(rig.alerts.acks().is_empty(), "the panel acked nothing");

        // A newer alert comes while a slip is open: it is a new one, and its slip opens.
        rig.alerts.raise(threat_alert(9));
        let until = now + 1_300;
        rig.drive(&mut now, until);
        assert_eq!(at_screen(&rig), (Section::Alerts, Some(&Opened::Alert(9))));
        rig.alerts.raise(threat_alert(10));
        let until = now + 1_300;
        rig.drive(&mut now, until);
        assert_eq!(at_screen(&rig), (Section::Alerts, Some(&Opened::Alert(10))));
        assert_eq!(rig.panel.world.alerts_waiting, 2);
        // The one that was opened is acked on the desktop: back at the log, with the other one in it.
        rig.alerts.api_ack(10);
        let until = now + 1_300;
        rig.drive(&mut now, until);
        assert_eq!(at_screen(&rig), (Section::Alerts, None));
        let ids: Vec<u64> = rig.panel.world.alerts.iter().map(|row| row.id).collect();
        assert_eq!(ids, [9]);
        assert!(rig.alerts.acks().is_empty());
    }

    #[test]
    fn an_alert_that_arrives_opens_its_slip_from_every_screen_but_not_over_a_state_of_the_whole_system()
     {
        // From LIVE, HOME, the wall and NAMES alike; the minute without a touch starts over.
        let mut rig = Rig::new(Arc::new(Fixed(reference_snapshot())));
        let mut now = 0;
        rig.drive(&mut now, 300);
        assert_eq!(rig.panel.nav.root(), Section::Live);
        rig.alerts.raise(threat_alert(3));
        let until = now + 1_300;
        rig.drive(&mut now, until);
        assert_eq!(at_screen(&rig), (Section::Alerts, Some(&Opened::Alert(3))));
        // It was drawn whole, with its device named from the wall, which LIVE had not read.
        assert_eq!(rig.panel.world.alert(3).unwrap().who, "Sam's phone");
        assert!(rig.frames.last() == painted(&rig.panel));
        rig.tap_at(&mut now, LANE_HOME.0, LANE_HOME.1);
        rig.tap_at(&mut now, HOME_NAMES.0, HOME_NAMES.1);
        assert_eq!(at_screen(&rig), (Section::Names, None));
        rig.alerts.raise(threat_alert(4));
        let until = now + 1_300;
        rig.drive(&mut now, until);
        assert_eq!(at_screen(&rig), (Section::Alerts, Some(&Opened::Alert(4))));
        // Not over the PIN pad, a state of the whole system: the alert is new when it ends.
        rig.panel.nav.set_whole(Some(Whole::Pin));
        rig.alerts.raise(threat_alert(5));
        let until = now + 1_300;
        rig.drive(&mut now, until);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Pin));
        assert_eq!(rig.panel.nav.top(), Some(&Opened::Alert(4)));
        rig.panel.nav.set_whole(None);
        let until = now + 1_300;
        rig.drive(&mut now, until);
        assert_eq!(at_screen(&rig), (Section::Alerts, Some(&Opened::Alert(5))));
    }

    #[test]
    fn open_gates_count_down_every_second_between_two_reads_of_the_inventory() {
        let mut rig = Rig::home(Arc::new(Fixed(reference_snapshot())));
        rig.devices
            .edit(|view| view.devices[2].gate_left_secs = Some(60));
        let mut now = 0;
        rig.drive(&mut now, 300);
        rig.tap_at(&mut now, HOME_DEVICES.0, HOME_DEVICES.1);
        let tv = |rig: &Rig| rig.panel.world.device(&hw(31)).unwrap().state;
        assert_eq!(tv(&rig), DeviceState::Open { left_secs: 60 });
        let (reads, from) = (rig.devices.reads().0, now);
        // The inventory's own gate runs down in whole seconds, as the real one does; the panel reads it
        // every two seconds and counts down by itself in between.
        let mut seen = Vec::new();
        while now < from + 9_000 {
            let left = 60 - u16::try_from((now - from) / 1_000).unwrap();
            rig.devices
                .edit(|view| view.devices[2].gate_left_secs = Some(left));
            rig.turn(now);
            if let DeviceState::Open { left_secs } = tv(&rig)
                && seen.last() != Some(&left_secs)
            {
                seen.push(left_secs);
            }
            now += FRAME_MS;
        }
        // Every second a step, though the inventory was read only four or five times in nine seconds, and
        // never a step back up.
        assert!(seen.len() >= 9, "{seen:?}");
        assert!(seen.windows(2).all(|pair| pair[1] < pair[0]), "{seen:?}");
        assert!(rig.devices.reads().0 - reads <= 5);
    }

    #[test]
    fn home_and_the_wall_write_at_most_eighty_rows_at_a_time_over_two_and_a_half_minutes_of_traffic()
     {
        for wall in [false, true] {
            let mut rig = Rig::home(Arc::new(Fixed(reference_snapshot())));
            // The idle minute is another test's: here the panel stays where it is.
            rig.panel.idle_after_ms = u64::MAX;
            let mut now = 0;
            rig.drive(&mut now, 300);
            if wall {
                rig.tap_at(&mut now, HOME_DEVICES.0, HOME_DEVICES.1);
            }
            // Lamps, a device's gate counting down, the clock's minute turning, the lane's beat, and a
            // gate that the desktop opens for a minute and shuts.
            rig.devices
                .edit(|view| view.devices[1].gate_left_secs = Some(300));
            let begin = now;
            let (mut toggles, mut turns) = (0, Vec::new());
            while now < begin + 150_000 {
                let second = (now - begin) / 1_000;
                rig.devices.state().asking = [12, 23, 31, 57, 143]
                    .into_iter()
                    .filter(|octet| (second + u64::from(*octet)) % 3 == 0)
                    .map(|octet| Ipv4Addr::new(192, 0, 2, octet))
                    .collect();
                let left = (60..120)
                    .contains(&second)
                    .then(|| u16::try_from(120 - second).unwrap());
                toggles += usize::from(rig.control.paused_left_secs().is_some() != left.is_some());
                rig.control.set_left(left);
                if (now - begin) % 1_000 < FRAME_MS {
                    rig.lane.observe("ads.example", true, second, |_| false);
                }
                let before = rig.frames.count();
                let wait = rig
                    .panel
                    .turn(now, UNIX + 20 + (now - begin) / 1_000)
                    .unwrap();
                turns.push((now - begin, before, rig.frames.count()));
                now += wait.max(1);
            }
            // Every write, from the frame before it: the rows from the first that differs to the last.
            let all = rig.frames.all();
            let mut rows: Vec<(u64, usize)> = Vec::new();
            for &(at, from, to) in &turns {
                for index in from.max(1)..to {
                    let changed = changed_rows(&all[index - 1], &all[index], WIDTH * 2);
                    rows.push((at, changed.map_or(0, |rows| rows.len())));
                }
            }
            // The gate's two toggles are two full writes; every other write fits.
            let big: Vec<&(u64, usize)> = rows.iter().filter(|(_, rows)| *rows > 80).collect();
            let name = if wall { "DEVICES" } else { "HOME" };
            eprintln!(
                "{name}: {} writes, peak {}, {} over 80 ({toggles} toggles): {big:?}",
                rows.len(),
                rows.iter().map(|(_, rows)| *rows).max().unwrap(),
                big.len()
            );
            assert_eq!(toggles, 2);
            if wall {
                // The wall shows nothing of the gate: its toggle writes nothing.
                assert!(big.is_empty(), "{name}: {big:?}");
            } else {
                // HOME's lane words and its gate tile change together, once opening and once shutting.
                assert_eq!(big.len(), 2, "{name}: {big:?}");
                assert!(big.iter().all(|(at, _)| {
                    [60_000, 120_000]
                        .iter()
                        .any(|toggle| at.abs_diff(*toggle) < 200)
                }));
            }
            assert!(rows.len() > 100, "{name}: {} writes", rows.len());
        }
    }

    #[test]
    fn the_lamp_of_the_live_tile_is_white_for_three_frames_after_a_name_goes_by() {
        let mut rig = Rig::home(Arc::new(Fixed(reference_snapshot())));
        let mut now = 0;
        rig.drive(&mut now, 300);
        assert!(!rig.panel.world.beat);
        rig.refuse("ads.example.org");
        let mut beats = Vec::new();
        for _ in 0..6 {
            rig.turn(now);
            beats.push(rig.panel.world.beat);
            now += FRAME_MS;
        }
        assert_eq!(beats, [true, true, true, false, false, false]);
    }

    #[test]
    fn the_wall_has_the_devices_that_ask_lit_and_the_lamps_follow_who_asked_every_second() {
        let mut rig = Rig::home(Arc::new(Fixed(reference_snapshot())));
        let mut now = 0;
        rig.drive(&mut now, 300);
        assert!(!rig.panel.world.any_asking());
        rig.devices.state().asking =
            vec![Ipv4Addr::new(192, 0, 2, 23), Ipv4Addr::new(192, 0, 2, 57)];
        let until = now + 1_300;
        rig.drive(&mut now, until);
        let lamps: Vec<bool> = rig
            .panel
            .world
            .devices
            .iter()
            .map(|row| row.asking)
            .collect();
        assert_eq!(lamps, [false, true, false, true, false, false]);
        rig.devices.state().asking.clear();
        let until = now + 1_300;
        rig.drive(&mut now, until);
        assert!(!rig.panel.world.any_asking());
    }

    // ------------------------------------------------------------------------------------------ phase 3

    /// The PIN the tests set, and a wrong one.
    const PIN: [u8; 4] = [2, 4, 6, 8];
    const WRONG_PIN: [u8; 4] = [1, 3, 5, 7];

    /// The hash of `digits` as `cargo xtask hash-pin` makes it: the four ASCII digits, 10,000 rounds.
    fn pin_hash(digits: [u8; 4]) -> crate::api::password::PasswordHash {
        crate::api::password::PasswordHash::with_rounds(
            &digits.map(|digit| b'0' + digit),
            [5; 16],
            crate::api::password::PIN_ROUNDS,
        )
    }

    /// The middle of the PIN pad's key for `digit`.
    fn pad_digit(digit: u8) -> (u16, u16) {
        let index = if digit == 0 {
            10
        } else {
            usize::from(digit) - 1
        };
        let key = qb_panel::os::screens::whole::pad_rect(index);
        (key.x + key.w / 2, key.y + key.h / 2)
    }

    /// A Wi-Fi link that is joined, on 5 GHz at -54 dBm, up since the monotonic second `joined`.
    fn linked(joined: u64) -> Option<WifiStatus> {
        Some(WifiStatus {
            associated: true,
            signal_dbm: Some(-54),
            ap: None,
            freq_mhz: Some(5_180),
            joined_secs: Some(joined),
        })
    }

    /// Everything STARTING waits for, known: the link, the clock, 212K names and a query answered.
    fn started() -> Snapshot {
        Snapshot {
            wifi: linked(0),
            list_names: Some(212_000),
            ..reference_snapshot()
        }
    }

    impl Rig {
        /// Turns the lock on with `PIN`, as the configuration's `pin_hash` does.
        fn set_pin(&self) {
            self.lock
                .lock()
                .set_hash(Some(pin_hash(PIN)), PinSource::Config);
        }

        /// Types four digits on the pad, a tap each.
        fn type_pin(&mut self, now: &mut u64, digits: [u8; 4]) {
            for digit in digits {
                let (x, y) = pad_digit(digit);
                self.tap_at(now, x, y);
            }
        }

        /// Lets `secs` seconds pass on the lock's clock.
        fn lock_clock_ahead(&self, secs: u64) {
            self.clock
                .fetch_add(secs, std::sync::atomic::Ordering::Relaxed);
        }

        /// Puts the panel on SYSTEM with `screen` opened over it.
        fn on_system(&mut self, screen: Opened) {
            self.panel.nav.go(Section::System);
            self.panel.nav.open(screen);
        }
    }

    #[test]
    fn a_boot_runs_starting_ticking_its_lines_and_goes_home_three_seconds_after_the_last() {
        use qb_panel::os::screens::whole::{StartingView, Step};

        let source = Scripted::new(Snapshot::default());
        let mut rig = Rig::booting(Arc::new(source.clone()));
        let mut now = 0;
        rig.turn(0);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Starting));
        assert_eq!(rig.frames.count(), 1);
        assert!(rig.frames.last() == painted(&rig.panel));
        let steps = |rig: &Rig| StartingView::of(&rig.panel.world).steps;
        // The panel is on; the Wi-Fi is what it waits for.
        assert_eq!(
            steps(&rig),
            [
                Step::Done,
                Step::Now,
                Step::Waiting,
                Step::Waiting,
                Step::Waiting
            ]
        );
        // A tap is no key of STARTING's.
        rig.tap_at(&mut now, HOME_DEVICES.0, HOME_DEVICES.1);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Starting));

        source.set(|snapshot| snapshot.wifi = linked(0));
        rig.drive(&mut now, 5_000);
        assert_eq!(
            steps(&rig),
            [
                Step::Done,
                Step::Done,
                Step::Now,
                Step::Waiting,
                Step::Waiting
            ]
        );
        // The clock and the lists are in, and DNS has not answered yet.
        source.set(|snapshot| {
            snapshot.clock_set = true;
            snapshot.list_names = Some(212_000);
        });
        rig.drive(&mut now, 8_000);
        assert_eq!(
            steps(&rig),
            [Step::Done, Step::Done, Step::Done, Step::Done, Step::Now]
        );
        // The slot is filled and a query was answered: all five are done at 10 s, and HOME comes 3 s later.
        rig.drive(&mut now, 9_875);
        assert_eq!(now, 10_000);
        source.set(|snapshot| *snapshot = started());
        rig.drive(&mut now, 12_875);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Starting));
        assert_eq!(steps(&rig), [Step::Done; 5]);
        let writes = rig.drive(&mut now, 13_125);
        assert!(rig.panel.nav.is_home());
        // The change is one write of the whole screen, at the frame 3 s after the last line, drawn from what HOME
        // reads: the wall is there already.
        assert_eq!(writes.iter().map(|w| w.at).collect::<Vec<_>>(), [13_000]);
        assert_eq!(rig.panel.world.devices.len(), 6);
        rig.drive(&mut now, 15_000);
        assert!(rig.frames.last() == painted(&rig.panel));
        // It stays at HOME.
        rig.drive(&mut now, 40_000);
        assert!(rig.panel.nav.is_home());
    }

    #[test]
    fn a_quiet_boot_with_empty_lists_leaves_starting_without_the_cap() {
        use qb_panel::os::screens::whole::{StartingView, Step};

        // No list is configured and no client has asked anything yet: the lists hold no name, and no query was
        // answered. The slot is filled, and an upstream has answered once.
        let quiet = Snapshot {
            wifi: linked(0),
            clock_set: true,
            list_names: Some(0),
            upstream_ms: Some(12),
            today: Some(qb_dns::Counts::default()),
            ..Snapshot::default()
        };
        let mut rig = Rig::booting(Arc::new(Fixed(quiet.clone())));
        let mut now = 0;
        rig.drive(&mut now, 2_875);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Starting));
        assert_eq!(StartingView::of(&rig.panel.world).steps, [Step::Done; 5]);
        // Done at the first frame, HOME 3 s later: nowhere near 90 s.
        rig.drive(&mut now, 3_125);
        assert!(rig.panel.nav.is_home());

        // Without an answer from any upstream it is still waiting, and the 90 s are the cap.
        let mut rig = Rig::booting(Arc::new(Fixed(Snapshot {
            upstream_ms: None,
            ..quiet.clone()
        })));
        let mut now = 0;
        rig.drive(&mut now, 10_000);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Starting));
        assert_eq!(
            StartingView::of(&rig.panel.world).steps,
            [Step::Done, Step::Done, Step::Done, Step::Done, Step::Now]
        );
        // An upstream that answers ends it, with the lists still empty and no query asked.
        let source = Scripted::new(Snapshot {
            upstream_ms: None,
            ..quiet
        });
        let mut rig = Rig::booting(Arc::new(source.clone()));
        let mut now = 0;
        rig.drive(&mut now, 20_000);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Starting));
        source.set(|snapshot| snapshot.upstream_ms = Some(9));
        rig.drive(&mut now, 24_000);
        assert!(rig.panel.nav.is_home());

        // A slot that is not filled has no `today`: an upstream's answer is not DNS answering.
        let mut rig = Rig::booting(Arc::new(Fixed(Snapshot {
            today: None,
            upstream_ms: Some(9),
            wifi: linked(0),
            clock_set: true,
            list_names: Some(0),
            ..Snapshot::default()
        })));
        let mut now = 0;
        rig.drive(&mut now, 10_000);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Starting));
        assert!(!rig.panel.world.dns_answering);
    }

    #[test]
    fn starting_ends_at_ninety_seconds_with_a_line_not_done() {
        let mut rig = Rig::booting(Arc::new(Nothing));
        let mut now = 0;
        rig.drive(&mut now, 89_875);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Starting));
        rig.drive(&mut now, 90_125);
        assert!(rig.panel.nav.is_home());
        assert!(!rig.panel.world.dns_answering);
    }

    #[test]
    fn a_panel_made_without_the_boot_begins_at_home() {
        let mut rig = Rig::home(Arc::new(Nothing));
        rig.turn(0);
        assert!(rig.panel.nav.is_home());
        assert!(rig.frames.last() == painted(&rig.panel));
    }

    #[test]
    fn a_trial_boot_shows_the_trial_once_starting_is_done_and_the_confirm_once() {
        let mut rig = Rig::booting(Arc::new(Fixed(started())));
        let trial = |left| trial_update(left, vec![update::Waiting::Wifi, update::Waiting::Time]);
        rig.system.set_update(trial(107));
        let mut now = 0;
        rig.drive(&mut now, 2_875);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Starting));
        // STARTING is done at the frame 3 s in, and the trial is what comes after it, not HOME.
        rig.drive(&mut now, 3_125);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Update));
        let trial_read = |left_secs, waiting_for| UpdateRead {
            phase: UpdatePhase::Trial {
                left_secs,
                waiting_for,
            },
            before: WorldSlot::A,
            after: WorldSlot::B,
        };
        assert_eq!(
            rig.panel.world.update,
            Some(trial_read(107, Some(WorldWaiting::Wifi)))
        );
        assert!(rig.panel.world.update_busy);
        assert!(rig.frames.last() == painted(&rig.panel));

        // The countdown steps with the machinery's own view, and each step is a small write.
        rig.system.set_update(trial(106));
        let writes = rig.drive(&mut now, 4_875);
        assert_eq!(
            rig.panel.world.update,
            Some(trial_read(106, Some(WorldWaiting::Wifi)))
        );
        assert!(!writes.is_empty());
        assert!(
            writes
                .iter()
                .all(|write| write.rows.is_some_and(|rows| rows <= BAND_ROWS_MAX)),
            "{writes:?}"
        );
        // The minimum time is up and the trial waits for the clock: its word.
        rig.system
            .set_update(trial_update(0, vec![update::Waiting::Clock]));
        rig.drive(&mut now, 6_000);
        assert_eq!(
            rig.panel.world.update,
            Some(trial_read(0, Some(WorldWaiting::Clock)))
        );

        // The build confirms: the machinery is idle again and says so. It shows once; a tap goes HOME.
        rig.system
            .set_update(ended_update(CardSlot::B, update::OutcomeKind::Confirmed));
        rig.drive(&mut now, 7_500);
        let confirmed = UpdateRead {
            phase: UpdatePhase::Confirmed,
            before: WorldSlot::A,
            after: WorldSlot::B,
        };
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Update));
        assert_eq!(rig.panel.world.update, Some(confirmed));
        assert!(!rig.panel.world.update_busy);
        assert_eq!(rig.panel.world.machine.last_update, LastUpdate::Confirmed);
        rig.tap_at(&mut now, 240, 160);
        assert!(rig.panel.nav.is_home());
        rig.drive(&mut now, 120_000);
        assert!(rig.panel.nav.is_home(), "it is not shown twice");
        assert_eq!(rig.panel.world.update, None);
    }

    #[test]
    fn a_finished_update_that_nobody_taps_goes_home_after_thirty_seconds() {
        let mut rig = Rig::home(Arc::new(Fixed(started())));
        rig.system
            .set_update(ended_update(CardSlot::A, update::OutcomeKind::RolledBack));
        let mut now = 0;
        rig.drive(&mut now, 2_000);
        // A rollback: the slot that runs is the one the update left, and the right box is the one that failed.
        assert_eq!(
            rig.panel.world.update,
            Some(UpdateRead {
                phase: UpdatePhase::RolledBack,
                before: WorldSlot::A,
                after: WorldSlot::B,
            })
        );
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Update));
        assert_eq!(rig.panel.world.machine.last_update, LastUpdate::RolledBack);
        assert_eq!(
            rig.panel.world.machine.last_restart,
            "an update that rolled back"
        );
        // It was first read in the first frame, and it goes at the frame 30 s on.
        rig.drive(&mut now, 29_875);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Update));
        rig.drive(&mut now, 30_125);
        assert!(rig.panel.nav.is_home());
        rig.drive(&mut now, 90_000);
        assert!(rig.panel.nav.is_home());
    }

    #[test]
    fn an_update_being_received_covers_the_screen_and_lets_go_when_it_comes_to_nothing() {
        let mut rig = Rig::home(Arc::new(Fixed(started())));
        let mut now = 0;
        rig.drive(&mut now, 1_000);
        assert!(rig.panel.nav.is_home());
        rig.system.set_update(receiving_update(50, 100));
        rig.drive(&mut now, 2_875);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Update));
        assert_eq!(
            rig.panel.world.update.map(|update| update.phase.received()),
            Some((50, 0.5))
        );
        assert!(rig.panel.world.update_busy);
        // The number moves and the screen follows, in writes inside a screen.
        rig.system.set_update(receiving_update(75, 100));
        let writes = rig.drive(&mut now, 4_000);
        assert!(!writes.is_empty());
        assert!(
            writes
                .iter()
                .all(|write| write.rows.unwrap() <= BAND_ROWS_MAX)
        );
        // The receiver gave up: nothing is going on and nothing ended, so HOME is back.
        rig.system.set_update(idle_update());
        rig.drive(&mut now, 5_500);
        assert!(rig.panel.nav.is_home());
        assert!(!rig.panel.world.update_busy);
    }

    #[test]
    fn the_pin_pad_asks_for_a_strong_key_with_the_lock_on_and_a_right_pin_carries_it_out() {
        let mut rig = Rig::home(Arc::new(Fixed(started())));
        rig.set_pin();
        let mut now = 0;
        rig.drive(&mut now, 1_000);
        assert!(rig.panel.world.lock_on);
        assert_eq!(rig.panel.world.lock_source, LockSource::Config);
        // The living room TV (blocked): its state key, the question, `ALLOW ADS`, which is strong.
        rig.tap_at(&mut now, HOME_DEVICES.0, HOME_DEVICES.1);
        rig.tap_at(&mut now, WALL_THIRD.0, WALL_THIRD.1);
        rig.tap_at(&mut now, FLOOR_LEFT.0, FLOOR_LEFT.1);
        rig.tap_at(&mut now, FLOOR_RIGHT.0, FLOOR_RIGHT.1);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Pin));
        assert!(rig.devices.state().edits.is_empty());
        assert!(rig.frames.last() == painted(&rig.panel));

        // Two wrong PINs: `WRONG PIN` each time, the digits gone, nothing done.
        for _ in 0..2 {
            rig.type_pin(&mut now, WRONG_PIN);
            assert_eq!(rig.panel.nav.whole(), Some(Whole::Pin));
            let pad = rig.panel.nav.pin().unwrap();
            assert!(pad.wrong() && pad.is_empty());
            assert_eq!(rig.panel.world.pin_wait_secs, 0);
        }
        // The third makes it wait half a minute, and the pad takes no digit while it does.
        rig.type_pin(&mut now, WRONG_PIN);
        assert_eq!(rig.panel.world.pin_wait_secs, 30);
        assert_eq!(rig.panel.nav.pin().unwrap().wait_secs(&rig.panel.world), 30);
        let (x, y) = pad_digit(2);
        rig.tap_at(&mut now, x, y);
        assert!(rig.panel.nav.pin().unwrap().is_empty());
        // Even the right PIN is not checked in the wait: no digit is taken.
        rig.lock_clock_ahead(29);
        rig.run_for(&mut now, 500);
        assert_eq!(rig.panel.world.pin_wait_secs, 1);
        rig.type_pin(&mut now, PIN);
        assert!(rig.devices.state().edits.is_empty());
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Pin));
        // After the wait the right PIN closes the pad, goes back from the question, and the action is done.
        rig.lock_clock_ahead(2);
        rig.run_for(&mut now, 500);
        assert_eq!(rig.panel.world.pin_wait_secs, 0);
        rig.type_pin(&mut now, PIN);
        assert_eq!(rig.panel.nav.whole(), None);
        assert_eq!(rig.devices.state().edits, ["ads 31 true"]);
        assert_eq!(
            at_screen(&rig),
            (Section::Devices, Some(&Opened::Device(hw(31))))
        );
        // The count started again: one wrong PIN is not a wait. (`RESTART` is the next strong key.)
        rig.on_system(Opened::Uptime);
        rig.tap_at(&mut now, FLOOR_RIGHT.0, FLOOR_RIGHT.1);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Pin));
        rig.type_pin(&mut now, WRONG_PIN);
        assert_eq!(rig.panel.world.pin_wait_secs, 0);
        assert!(rig.panel.nav.pin().unwrap().wrong());
        // `CANCEL` goes back with the action not done.
        let cancel = qb_panel::os::screens::whole::pad_rect(9);
        rig.tap_at(&mut now, cancel.x + 10, cancel.y + 10);
        assert_eq!(rig.panel.nav.whole(), None);
        assert_eq!(rig.devices.state().edits, ["ads 31 true"]);
        assert!(rig.system.acts().is_empty());
    }

    #[test]
    fn name_goes_home_after_the_idle_minute_as_every_other_screen_does() {
        let mut rig = Rig::home(Arc::new(Fixed(reference_snapshot())));
        let mut now = 0;
        rig.drive(&mut now, 300);
        rig.tap_at(&mut now, HOME_NAMES.0, HOME_NAMES.1);
        rig.tap_at(&mut now, PIPE_FIRST.0, PIPE_FIRST.1);
        assert_eq!(rig.panel.nav.shown_name(), Some("ads.example.net"));
        let touched = now;
        rig.drive(&mut now, touched + 59_000);
        assert_eq!(rig.panel.nav.shown_name(), Some("ads.example.net"));
        rig.drive(&mut now, touched + 61_000);
        assert_eq!(at_screen(&rig), (Section::Home, None));
        assert!(rig.panel.world.name_facts.is_none());

        // A threat's NAME, from the slip of an alert that arrived by itself, goes HOME the same.
        rig.alerts.raise(threat_alert(7));
        let until = now + 1_300;
        rig.drive(&mut now, until);
        assert_eq!(at_screen(&rig), (Section::Alerts, Some(&Opened::Alert(7))));
        rig.tap_at(&mut now, SLIP_NAME.0, SLIP_NAME.1);
        assert_eq!(
            rig.panel.nav.shown_name(),
            Some("secure-login-verify.example")
        );
        let touched = now;
        rig.drive(&mut now, touched + 59_000);
        assert!(rig.panel.nav.shown_name().is_some());
        rig.drive(&mut now, touched + 61_000);
        assert_eq!(at_screen(&rig), (Section::Home, None));

        // NAME from YOUR LIST, with the lock on: the pad over it goes back to NAME after its minute, and NAME
        // goes HOME after its own.
        rig.set_pin();
        rig.names
            .state()
            .owner
            .push(("ads.example.net".to_owned(), OwnerSide::Refuse, Some(UNIX)));
        rig.tap_at(&mut now, HOME_NAMES.0, HOME_NAMES.1);
        rig.tap_at(&mut now, LIST_DOOR.0, LIST_DOOR.1);
        rig.tap_at(&mut now, PIPE_FIRST.0, PIPE_FIRST.1);
        assert_eq!(rig.panel.nav.shown_name(), Some("ads.example.net"));
        rig.tap_at(&mut now, FLOOR_RIGHT.0, FLOOR_RIGHT.1);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Pin), "ANSWER AGAIN asks");
        let touched = now;
        rig.drive(&mut now, touched + 60_500);
        assert_eq!(rig.panel.nav.whole(), None);
        assert_eq!(rig.panel.nav.shown_name(), Some("ads.example.net"));
        rig.drive(&mut now, touched + 60_000 + 59_000);
        assert!(rig.panel.nav.shown_name().is_some());
        rig.drive(&mut now, touched + 60_000 + 61_000);
        assert_eq!(at_screen(&rig), (Section::Home, None));
        assert!(rig.names.edits().is_empty());
    }

    #[test]
    fn a_pin_pad_left_alone_goes_back_with_the_action_not_done() {
        let mut rig = Rig::home(Arc::new(Fixed(started())));
        rig.set_pin();
        let mut now = 0;
        rig.drive(&mut now, 1_000);
        rig.tap_at(&mut now, HOME_DEVICES.0, HOME_DEVICES.1);
        rig.tap_at(&mut now, WALL_THIRD.0, WALL_THIRD.1);
        rig.tap_at(&mut now, FLOOR_LEFT.0, FLOOR_LEFT.1);
        rig.tap_at(&mut now, FLOOR_RIGHT.0, FLOOR_RIGHT.1);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Pin));
        let (x, y) = pad_digit(2);
        rig.tap_at(&mut now, x, y);
        let until = now + nav::IDLE_MS + 1_000;
        rig.drive(&mut now, until);
        // The pad is gone and the screen it came from is back, with the action not done and a minute of its own.
        assert_eq!(rig.panel.nav.whole(), None);
        assert_eq!(
            rig.panel.nav.top(),
            Some(&Opened::Confirm {
                mac: hw(31),
                pass: true
            })
        );
        assert!(rig.devices.state().edits.is_empty());
        let until = now + nav::IDLE_MS - 5_000;
        rig.drive(&mut now, until);
        assert!(!rig.panel.nav.is_home());
        let until = now + 10_000;
        rig.drive(&mut now, until);
        assert!(rig.panel.nav.is_home());
        assert!(rig.devices.state().edits.is_empty());
    }

    #[test]
    fn a_pin_set_on_the_panel_guards_the_strong_keys_and_the_lock_can_be_turned_off_with_it() {
        let mut rig = Rig::home(Arc::new(Fixed(started())));
        let mut now = 0;
        rig.drive(&mut now, 1_000);
        assert!(!rig.panel.world.lock_on);
        // SET A PIN, four digits: the pad closes, the lock is on and says it was set here.
        rig.on_system(Opened::Lock);
        rig.tap_at(&mut now, FLOOR_RIGHT.0, FLOOR_RIGHT.1);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Pin));
        rig.type_pin(&mut now, PIN);
        assert_eq!(rig.panel.nav.whole(), None);
        assert_eq!(
            rig.lock.lock_view(),
            lock::LockView {
                on: true,
                source: Some(PinSource::Panel),
                kept: false
            }
        );
        assert!(rig.panel.world.lock_on);
        assert_eq!(rig.panel.world.lock_source, LockSource::Panel);
        assert_eq!(rig.lock.verify(Zeroizing::new(PIN)), Check::Right);
        // `TURN OFF` is strong: a wrong PIN leaves the lock on, the right one turns it off.
        rig.tap_at(&mut now, FLOOR_RIGHT.0, FLOOR_RIGHT.1);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Pin));
        rig.type_pin(&mut now, WRONG_PIN);
        assert!(rig.lock.lock_view().on);
        rig.type_pin(&mut now, PIN);
        assert!(!rig.lock.lock_view().on);
        assert!(!rig.panel.world.lock_on);
        // Off, the strong keys do not ask: the restart goes straight out.
        rig.on_system(Opened::Uptime);
        rig.tap_at(&mut now, FLOOR_RIGHT.0, FLOOR_RIGHT.1);
        assert_eq!(rig.system.acts(), ["restart"]);
        assert_eq!(rig.panel.nav.whole(), None);
    }

    #[test]
    fn restart_and_rejoin_reach_the_board_and_a_restart_asks_for_the_pin_when_the_lock_is_on() {
        let mut rig = Rig::home(Arc::new(Fixed(started())));
        let mut now = 0;
        rig.drive(&mut now, 1_000);
        rig.on_system(Opened::Uptime);
        rig.tap_at(&mut now, FLOOR_RIGHT.0, FLOOR_RIGHT.1);
        assert_eq!(rig.system.acts(), ["restart"]);

        // With the lock on, the restart waits for a right PIN.
        rig.set_pin();
        rig.run_for(&mut now, 1_000);
        rig.tap_at(&mut now, FLOOR_RIGHT.0, FLOOR_RIGHT.1);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Pin));
        assert_eq!(rig.system.acts(), ["restart"]);
        rig.type_pin(&mut now, PIN);
        assert_eq!(rig.system.acts(), ["restart", "restart"]);
        assert_eq!(rig.panel.nav.whole(), None);

        // The rejoin never asks: it is asked of the board, and the link says JOINING until it is back.
        rig.system.state().acts.clear();
        rig.on_system(Opened::Wifi);
        rig.tap_at(&mut now, FLOOR_RIGHT.0, FLOOR_RIGHT.1);
        assert_eq!(rig.system.acts(), ["rejoin"]);
        assert_eq!(rig.panel.world.rejoin, Rejoin::Joining);
        // Still joining while the old link is what the snapshot says, and while it is down.
        rig.run_for(&mut now, 2_000);
        assert_eq!(rig.panel.world.rejoin, Rejoin::Joining);
        rig.tap_at(&mut now, FLOOR_RIGHT.0, FLOOR_RIGHT.1);
        assert_eq!(
            rig.system.acts(),
            ["rejoin"],
            "the key is inert while joining"
        );
    }

    #[test]
    fn a_rejoin_is_over_when_the_link_has_joined_again_and_a_second_one_must_wait() {
        let source = Scripted::new(Snapshot {
            wifi: linked(100),
            ..started()
        });
        let mut rig = Rig::home(Arc::new(source.clone()));
        let mut now = 0;
        rig.drive(&mut now, 1_000);
        rig.on_system(Opened::Wifi);
        rig.tap_at(&mut now, FLOOR_RIGHT.0, FLOOR_RIGHT.1);
        assert_eq!(rig.panel.world.rejoin, Rejoin::Joining);
        // The link goes down: no dash is lit, and the word says so.
        source.set(|snapshot| snapshot.wifi = None);
        rig.run_for(&mut now, 2_000);
        assert_eq!(rig.panel.world.rejoin, Rejoin::Joining);
        // It comes back with a newer join second.
        source.set(|snapshot| snapshot.wifi = linked(130));
        rig.run_for(&mut now, 1_000);
        assert_eq!(rig.panel.world.rejoin, Rejoin::Idle);
        // The control refuses another so soon: the key says WAIT, for as long as it said, then it is a key again.
        rig.system.state().rejoin = Err(RejoinWait(45));
        rig.tap_at(&mut now, FLOOR_RIGHT.0, FLOOR_RIGHT.1);
        assert_eq!(rig.system.acts(), ["rejoin", "rejoin"]);
        assert!(matches!(rig.panel.world.rejoin, Rejoin::Wait(secs) if (44..=45).contains(&secs)));
        rig.tap_at(&mut now, FLOOR_RIGHT.0, FLOOR_RIGHT.1);
        assert_eq!(rig.system.acts().len(), 2, "inert while it waits");
        rig.run_for(&mut now, 46_000);
        assert_eq!(rig.panel.world.rejoin, Rejoin::Idle);
    }

    #[test]
    fn a_rejoin_whose_link_never_changes_stops_saying_joining() {
        let mut rig = Rig::home(Arc::new(Fixed(Snapshot {
            wifi: linked(100),
            ..started()
        })));
        let mut now = 0;
        rig.drive(&mut now, 1_000);
        rig.on_system(Opened::Wifi);
        rig.tap_at(&mut now, FLOOR_RIGHT.0, FLOOR_RIGHT.1);
        assert_eq!(rig.panel.world.rejoin, Rejoin::Joining);
        let until = now + REJOIN_SHOWN_MS - 2_000;
        rig.drive(&mut now, until);
        assert_eq!(rig.panel.world.rejoin, Rejoin::Joining);
        let until = now + 4_000;
        rig.drive(&mut now, until);
        assert_eq!(rig.panel.world.rejoin, Rejoin::Idle);
    }

    #[test]
    fn the_boards_readings_are_read_every_five_seconds_only_while_system_up_or_wifi_show() {
        let mut rig = Rig::home(Arc::new(Fixed(started())));
        let mut now = 0;
        // HOME, DEVICES and NAMES never read them; the update view is asked every second whatever shows.
        rig.drive(&mut now, 6_000);
        let (updates, readings) = rig.system.reads();
        assert_eq!(readings, 0);
        assert!((6..=8).contains(&updates), "{updates}");
        rig.tap_at(&mut now, HOME_DEVICES.0, HOME_DEVICES.1);
        rig.tap_at(&mut now, LANE_HOME.0, LANE_HOME.1);
        rig.tap_at(&mut now, HOME_NAMES.0, HOME_NAMES.1);
        assert_eq!(rig.system.reads().1, 0);

        // SYSTEM reads at once, and then every five seconds.
        rig.panel.nav.go(Section::System);
        let start = now;
        rig.drive(&mut now, start + 100);
        assert_eq!(rig.system.reads().1, 1);
        let machine = rig.panel.world.machine.clone();
        assert_eq!(
            (
                machine.load_hundredths,
                machine.memory_pct,
                machine.temp_c,
                machine.uptime_hours
            ),
            (Some(21), Some(38), Some(47), Some(4))
        );
        assert_eq!(rig.panel.world.uptime_days, Some(12));
        assert_eq!(machine.slot, Some(WorldSlot::A));
        rig.drive(&mut now, start + 4_500);
        assert_eq!(rig.system.reads().1, 1);
        rig.drive(&mut now, start + 5_300);
        assert_eq!(rig.system.reads().1, 2);
        // UP and WI-FI are the same reading: one that is up goes on with SYSTEM's cadence, and one that comes up
        // after a screen that reads nothing reads at once.
        rig.panel.nav.open(Opened::Uptime);
        rig.drive(&mut now, start + 5_800);
        assert_eq!(rig.system.reads().1, 2);
        rig.panel.nav.go(Section::System);
        rig.panel.nav.open(Opened::Version);
        rig.drive(&mut now, start + 6_300);
        assert_eq!(rig.panel.world.machine.load_hundredths, None);
        rig.drive(&mut now, start + 20_000);
        assert_eq!(rig.system.reads().1, 2);
        rig.panel.nav.go(Section::System);
        rig.panel.nav.open(Opened::Wifi);
        rig.drive(&mut now, start + 20_300);
        assert_eq!(rig.system.reads().1, 3);
        assert_eq!(rig.panel.world.machine.load_hundredths, Some(21));
        // The lock and ABOUT read nothing.
        for screen in [Opened::Lock, Opened::About, Opened::NightHours] {
            rig.panel.nav.go(Section::System);
            rig.panel.nav.open(screen);
            rig.drive(&mut now, start + 30_000);
        }
        assert_eq!(rig.system.reads().1, 3);
    }

    #[test]
    fn the_reads_of_the_screens_that_show_the_board_are_those_and_no_others() {
        let reads = |nav: &Nav| Reads::of(nav).system;
        let mut nav = Nav::at(Section::System);
        assert!(reads(&nav));
        for (screen, expected) in [
            (Opened::Uptime, true),
            (Opened::Wifi, true),
            (Opened::Version, false),
            (Opened::NightHours, false),
            (Opened::Lock, false),
            (Opened::About, false),
        ] {
            nav.go(Section::System);
            nav.open(screen.clone());
            assert_eq!(reads(&nav), expected, "{screen:?}");
        }
        for section in [
            Section::Home,
            Section::Live,
            Section::Devices,
            Section::Alerts,
            Section::Names,
            Section::Gate,
        ] {
            assert!(!reads(&Nav::at(section)), "{section:?}");
        }
        // A state of the whole system reads nothing of its screens.
        let mut nav = Nav::at(Section::System);
        nav.set_whole(Some(Whole::Update));
        assert_eq!(Reads::of(&nav), Reads::default());
    }

    #[test]
    fn the_world_says_what_the_link_and_the_build_and_the_machine_are() {
        let source = Scripted::new(Snapshot {
            wifi: linked(8 * 86_400),
            upstream_ms: Some(9),
            ..started()
        });
        let mut rig = Rig::home(Arc::new(source.clone()));
        // The board has run twenty days: the link joined on the eighth.
        rig.panel.boot_ms = 20 * 86_400_000;
        rig.turn(0);
        let world = &rig.panel.world;
        assert_eq!(world.link.band, Some(qb_panel::os::world::Band::Ghz5));
        assert_eq!(world.link.signal_dbm, Some(-54));
        assert_eq!(world.link.linked_days, Some(12));
        assert_eq!(world.link.upstream_ms, Some(9));
        assert_eq!(world.machine.built, view::date_of(crate::BUILD_EPOCH));
        assert_eq!(world.machine.slot, Some(WorldSlot::A));
        assert_eq!(world.machine.last_update, LastUpdate::None);
        assert_eq!(world.machine.last_restart, "");
        assert!(world.dns_answering);
        assert!(!world.update_busy);
        assert_eq!(world.update, None);
        // A link that is down has no band, no signal and no days.
        source.set(|snapshot| snapshot.wifi = None);
        let mut now = 125;
        rig.drive(&mut now, 1_200);
        assert_eq!(rig.panel.world.link, qb_panel::os::world::Link::default());
    }

    #[test]
    fn the_lock_and_the_night_hours_are_read_from_the_lock_each_second_and_a_tap_sees_its_latest() {
        let mut rig = Rig::home(Arc::new(Fixed(started())));
        rig.lock.set_night(Some((23, 7)));
        let mut now = 0;
        rig.drive(&mut now, 1_000);
        assert_eq!(rig.panel.world.night, Some((23, 7)));
        assert!(!rig.panel.world.lock_on);
        // The desktop pushes a PIN between two reads: the next tap is decided by it.
        rig.lock
            .lock()
            .set_hash(Some(pin_hash(PIN)), PinSource::Api);
        rig.on_system(Opened::Uptime);
        rig.tap_at(&mut now, FLOOR_RIGHT.0, FLOOR_RIGHT.1);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Pin));
        assert!(rig.system.acts().is_empty());
        assert_eq!(rig.panel.world.lock_source, LockSource::Api);
    }

    #[test]
    fn the_world_knows_whether_the_card_keeps_the_pin_whatever_its_source() {
        let mut rig = Rig::home(Arc::new(Fixed(started())));
        let mut now = 0;
        rig.drive(&mut now, 1_000);
        assert!(!rig.panel.world.lock_kept);
        // The state is kept on the card: the world says so with the lock off, and with a PIN from each source.
        let state = Arc::new(PanelState::new(None, None, Arc::new(|| 1_000)).with_kept(true));
        rig.panel.deps.lock = state.clone();
        rig.lock = state;
        rig.drive(&mut now, 2_000);
        assert!(rig.panel.world.lock_kept && !rig.panel.world.lock_on);
        rig.lock
            .lock()
            .set_hash(Some(pin_hash(PIN)), PinSource::Api);
        rig.drive(&mut now, 3_000);
        assert!(rig.panel.world.lock_kept && rig.panel.world.lock_on);
        assert_eq!(rig.panel.world.lock_source, LockSource::Api);
        rig.lock.set_pin(Zeroizing::new(PIN));
        rig.drive(&mut now, 4_000);
        assert!(rig.panel.world.lock_kept);
        assert_eq!(rig.panel.world.lock_source, LockSource::Panel);
    }

    /// A rig at HOME whose night is 10:00 to 11:00, in which the clock of these tests (10:20) is.
    fn night_rig() -> Rig {
        let rig = Rig::home(Arc::new(Fixed(started())));
        rig.lock.set_night(Some((10, 11)));
        rig
    }

    #[test]
    fn in_the_night_hours_a_minute_alone_puts_the_panel_to_sleep_and_a_touch_wakes_it_to_home() {
        let mut rig = night_rig();
        let mut now = 0;
        rig.drive(&mut now, 59_875);
        assert!(rig.panel.nav.is_home());
        // The minute without a touch is up at 60 s: the dark clock is one write of the whole screen.
        let writes = rig.drive(&mut now, 60_125);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Night));
        assert_eq!(writes.iter().map(|w| w.at).collect::<Vec<_>>(), [60_000]);
        assert!(rig.frames.last() == painted(&rig.panel));
        // A touch wakes it: HOME, whole.
        rig.tap_at(&mut now, 240, 160);
        assert!(rig.panel.nav.is_home());
        assert!(rig.frames.last() == painted(&rig.panel));
        // A minute after the touch it sleeps again, not before.
        let woke = now;
        rig.drive(&mut now, woke + 55_000);
        assert!(rig.panel.nav.is_home());
        rig.drive(&mut now, woke + 62_000);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Night));
    }

    #[test]
    fn an_alert_does_not_wake_the_night_screen_and_waits_for_the_touch_that_does() {
        let mut rig = night_rig();
        let mut now = 0;
        rig.drive(&mut now, 61_000);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Night));
        let before = rig.frames.count();
        rig.alerts.raise(threat_alert(30));
        let until = now + 3_000;
        rig.drive(&mut now, until);
        // It is counted (the caption says `1 ON THE LOG`), and the screen was not touched.
        assert_eq!(rig.panel.world.alerts_waiting, 1);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Night));
        assert_eq!(rig.panel.nav.top(), None);
        assert!(rig.frames.count() >= before);
        // A touch wakes the panel, and the slip of the alert that came in the night is what it opens.
        rig.tap_at(&mut now, 240, 160);
        let until = now + 500;
        rig.drive(&mut now, until);
        assert_eq!(rig.panel.nav.whole(), None);
        assert_eq!(rig.panel.nav.top(), Some(&Opened::Alert(30)));
    }

    #[test]
    fn the_night_lifts_in_the_morning_and_sleep_now_stays_until_a_touch() {
        let mut rig = night_rig();
        let mut now = 0;
        rig.drive(&mut now, 61_000);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Night));
        // 11:10: the hours are over. The next second's reading of the clock lifts it to HOME.
        let morning = UNIX + 3_000;
        for _ in 0..16 {
            rig.panel.turn(now, morning).unwrap();
            now += FRAME_MS;
        }
        assert!(rig.panel.nav.is_home());
        // `SLEEP NOW` outside the hours (NIGHT HOURS' left key): asleep until a touch, and a minute later still
        // awake, since it is no night.
        rig.on_system(Opened::NightHours);
        rig.tap_at(&mut now, FLOOR_LEFT.0, FLOOR_LEFT.1);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Night));
        for _ in 0..16 {
            rig.panel.turn(now, morning).unwrap();
            now += FRAME_MS;
        }
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Night));
        let late = now + 70_000;
        while now < late {
            rig.panel.turn(now, morning).unwrap();
            now += FRAME_MS;
        }
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Night));
        rig.tap_at(&mut now, 240, 160);
        assert!(rig.panel.nav.is_home());
        let late = now + 70_000;
        while now < late {
            rig.panel.turn(now, morning).unwrap();
            now += FRAME_MS;
        }
        assert!(
            rig.panel.nav.is_home(),
            "outside the hours it sleeps no more"
        );
    }

    #[test]
    fn the_night_hours_the_owner_sets_go_to_the_lock_and_equal_hours_are_no_night() {
        let mut rig = Rig::home(Arc::new(Fixed(started())));
        rig.turn(0);
        rig.panel.carry_out(Intent::NightHours { from: 22, to: 6 });
        assert_eq!(rig.lock.night(), Some((22, 6)));
        assert_eq!(rig.panel.world.night, Some((22, 6)));
        rig.panel.carry_out(Intent::NightHours { from: 5, to: 5 });
        assert_eq!(rig.lock.night(), None);
        assert_eq!(rig.panel.world.night, None);
    }

    #[test]
    fn an_update_does_not_light_the_night_screen_and_shows_when_the_panel_wakes() {
        let mut rig = night_rig();
        let mut now = 0;
        rig.drive(&mut now, 61_000);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Night));
        let before = rig.frames.count();
        // An update that is received, and one that ends: the night screen stays dark through both.
        rig.system.set_update(receiving_update(1, 100));
        let until = now + 2_000;
        rig.drive(&mut now, until);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Night));
        assert_eq!(rig.frames.count(), before, "nothing was drawn");
        rig.system.set_update(idle_update());
        let until = now + 2_000;
        rig.drive(&mut now, until);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Night));
        rig.system
            .set_update(ended_update(CardSlot::B, update::OutcomeKind::Confirmed));
        let until = now + 2_000;
        rig.drive(&mut now, until);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Night));
        assert_eq!(rig.frames.count(), before, "nothing was drawn");
        // A touch wakes the panel, and the outcome that came in the night is what it shows, once.
        rig.tap_at(&mut now, 240, 160);
        let until = now + 500;
        rig.drive(&mut now, until);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Update));
        assert!(rig.panel.world.update.is_some());

        // An update that is still received when the panel wakes is shown the same way.
        let mut rig = night_rig();
        let mut now = 0;
        rig.drive(&mut now, 61_000);
        rig.system.set_update(receiving_update(1, 100));
        let until = now + 2_000;
        rig.drive(&mut now, until);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Night));
        rig.tap_at(&mut now, 240, 160);
        let until = now + 500;
        rig.drive(&mut now, until);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Update));
    }

    #[test]
    fn an_update_waits_for_a_pad_which_is_the_owners_for_a_minute() {
        // A pad is the owner's, for a minute: an update waits for it.
        let mut rig = Rig::home(Arc::new(Fixed(started())));
        rig.set_pin();
        let mut now = 0;
        rig.drive(&mut now, 1_000);
        rig.on_system(Opened::Uptime);
        rig.tap_at(&mut now, FLOOR_RIGHT.0, FLOOR_RIGHT.1);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Pin));
        rig.system.set_update(receiving_update(1, 100));
        let until = now + 2_000;
        rig.drive(&mut now, until);
        assert_eq!(rig.panel.nav.whole(), Some(Whole::Pin));
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
    fn taps_reach_the_fakes_for_every_kind_of_intent() {
        let mut rig = Rig::home(Arc::new(Fixed(reference_snapshot())));
        let mut now = 0;
        walk_through_every_intent(&mut rig, &mut now);
        // The names' edits are the owner's list's, and each says what kind it was in the log (see
        // `the_panel_never_logs_a_name`).
        assert_eq!(
            rig.names.edits(),
            [
                "allow ads.example.net",
                "refuse tracker.example.com",
                "forget tracker.example.com",
                "forget ads.example.net"
            ]
        );
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

        let mut rig = Rig::home(Arc::new(Fixed(reference_snapshot())));
        // Refused names, plain names, a name too long for the lane, and a pause.
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
        // Devices with labels, hostnames and addresses, one that asks, one whose names are watched; the walk
        // brings an alert about a name and a device, and the owner's names.
        rig.devices.state().asking = vec![Ipv4Addr::new(192, 0, 2, 23)];
        rig.devices.state().watched = vec![LaneWatched {
            name: "tracker.example".to_owned(),
            whole: Some("tracker.example".to_owned()),
            outcome: WatchedOutcome::Refused,
        }];
        let mut now = 0;
        rig.drive(&mut now, 1_000);
        rig.refuse("tracker.example");
        walk_through_every_intent(&mut rig, &mut now);
        let until = now + 3_000;
        rig.drive(&mut now, until);
        // A gate that someone opens, and that ends by itself.
        rig.control.set_left(Some(1));
        let until = now + 1_000;
        rig.drive(&mut now, until);
        rig.control.set_left(None);
        let until = now + 1_000;
        rig.drive(&mut now, until);
        // Alerts about a device, by its hardware address, and a pattern: their slips and their log are
        // drawn, and no line says what they carry. The owner's edits that the list refuses, or that have
        // nothing to take back, say why or that, and not for which name.
        for (id, kind, subject) in [
            (20, "new_device", "02:00:00:00:00:d8"),
            (21, "arp_spoof", "02:00:00:00:00:17"),
            (22, "dga", "x7k2q9.example.org"),
        ] {
            rig.alerts.raise(PanelAlert {
                kind: kind.to_owned(),
                subject: subject.to_owned(),
                ..threat_alert(id)
            });
            let until = now + 1_300;
            rig.drive(&mut now, until);
        }
        assert_eq!(rig.panel.world.alerts_waiting, 3);
        rig.panel.carry_out(Intent::Name {
            name: "secure-login-verify.example".to_owned(),
            verdict: Verdict::Allow,
        });
        rig.panel.carry_out(Intent::Name {
            name: "nothing.example.org".to_owned(),
            verdict: Verdict::ClearAllow,
        });

        // The lock, with a PIN from the configuration: `RESTART` asks, three wrong PINs and a wait, the right PIN
        // after it; then the PIN set on the panel, the lock turned off, the night hours, sleep, and the rejoin
        // that is done and the one that is refused. None says a digit or the hash.
        rig.set_pin();
        rig.panel.nav.go(Section::System);
        rig.panel.nav.open(Opened::Uptime);
        rig.tap_at(&mut now, FLOOR_RIGHT.0, FLOOR_RIGHT.1);
        for _ in 0..3 {
            rig.type_pin(&mut now, WRONG_PIN);
        }
        // A digit typed in the wait is not taken, and a check asked for in it is not made.
        rig.panel
            .carry_out(Intent::Verify(qb_panel::os::PinDigits::new(PIN)));
        rig.lock_clock_ahead(31);
        let until = now + 300;
        rig.drive(&mut now, until);
        rig.type_pin(&mut now, PIN);
        rig.panel
            .carry_out(Intent::SetPin(qb_panel::os::PinDigits::new([9, 1, 6, 3])));
        rig.panel.carry_out(Intent::ClearPin);
        rig.panel.carry_out(Intent::NightHours { from: 22, to: 6 });
        rig.panel.carry_out(Intent::SleepNow);
        rig.panel.carry_out(Intent::Rejoin);
        rig.system.state().rejoin = Err(RejoinWait(45));
        rig.panel.carry_out(Intent::Rejoin);
        rig.system.state().restart = Err(RestartRefused::Updating);
        rig.panel.carry_out(Intent::Restart);
        rig.system.state().restart = Err(RestartRefused::NotReady);
        rig.panel.carry_out(Intent::Restart);

        let lines = CAPTURE.0.lock().unwrap().clone();
        for line in [
            "WARN panel: wrong PIN (1 in a row)",
            "WARN panel: wrong PIN (3 in a row)",
            "INFO panel: PIN not checked: the lock is waiting",
            "INFO panel: PIN accepted",
            "INFO panel: restart asked",
            "INFO panel: restart refused: an update is under way",
            "WARN panel: restart refused: not ready",
            "INFO panel: the PIN was set on the panel",
            "INFO panel: the lock was turned off",
            "INFO panel: night hours set",
            "INFO panel: sleeping until a touch",
            "INFO panel: Wi-Fi rejoin asked",
            "INFO panel: Wi-Fi rejoin refused for now",
        ] {
            assert!(lines.iter().any(|seen| seen == line), "{line}: {lines:?}");
        }
        // Not one of the PINs the test typed or set, and no piece of the hash that holds one.
        let hash = pin_hash(PIN).to_text();
        let pieces: Vec<&str> = hash.split('$').filter(|piece| piece.len() >= 6).collect();
        assert!(!pieces.is_empty());
        for line in &lines {
            for secret in ["2468", "1357", "9163", "pbkdf2"]
                .into_iter()
                .chain(pieces.iter().copied())
            {
                assert!(!line.contains(secret), "{line}");
            }
        }
        for line in [
            "INFO panel: gate opened for 1800 s",
            "INFO panel: gate shut",
            "INFO panel: device ads blocked",
            "INFO panel: device gate opened for 300 s",
            "INFO panel: device gate shut",
            "INFO panel: device ads pass set",
            "INFO panel: alert dismissed",
            "WARN panel: device ads edit refused: unknown",
            "INFO panel: gate: the pause ended",
            "INFO panel: name allowed",
            "INFO panel: name refused",
            "INFO panel: refusal taken back",
            "INFO panel: allow taken back",
            "WARN panel: name edit refused: threat",
            "INFO panel: no entry of its own to take back",
        ] {
            assert!(lines.iter().any(|seen| seen == line), "{line}: {lines:?}");
        }
        for line in &lines {
            for secret in [
                "example.org",
                ".example",
                "tracker",
                "xxxx",
                "192.0.2.",
                "02:00:00",
                "2:0:0",
                "Desk PC",
                "Sam",
                "Living",
                "printer",
                "secure-login",
                "doubleclick",
                "metrics",
                "x7k2",
                "nothing",
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
    fn the_events_of_a_device_work_the_key_until_the_device_goes() {
        let (mut panel, frames, control) = panel();
        let (reader, mut writer) = std::io::pipe().unwrap();
        // The key, then a choice of the gate's, which the first tap unfolded.
        writer
            .write_all(&wire(&tap_on(1_000, KEY.0, KEY.1)))
            .unwrap();
        writer
            .write_all(&wire(&tap_on(2_000, ASK_5_MIN.0, ASK_5_MIN.1)))
            .unwrap();
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
        assert!(panel.nav.gate_ask(), "the key unfolds the gate's choices");
        assert!(control.calls().is_empty());
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
        assert!(panel.nav.gate_ask(), "the key unfolds the gate's choices");
        assert!(control.calls().is_empty());
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

    /// The panel's memory (spec 6.7): what its painters, the glass's kept frame and the world hold, summed
    /// after everything Phase 1 draws has been drawn through the panel's own painters, so that the glyph
    /// caches hold what a day of use puts in them. The ceiling is 5 MB more resident than the Drain
    /// alone; the sum here counts the Drain's painter as well, which is stricter.
    #[test]
    fn the_panels_buffers_and_caches_stay_within_the_memory_budget() {
        use qb_panel::drain::{Fixture, drain_fixture};
        use qb_panel::os::Change;
        use qb_panel::os::fixture::{Still, live_scene, mac_of, world as still_world};
        use qb_panel::os::world::{DeviceRow, MAX_DEVICES, WatchedName as Watched, display_name};

        // The spec's figures, in bytes: 1.2 MB a painter's frames, 2 MB of glyph caches in all, 64 KB of world.
        const FRAMES: usize = 614_400 + 307_200 + 307_200;
        const GLYPHS: usize = 2 * 1024 * 1024;
        const WORLD: usize = 64 * 1024;
        const CEILING: usize = 5 * 1000 * 1000;

        let (mut panel, _frames, _control) = panel();

        // Everything P1 draws: the Drain's stills, LIVE's two, every screen of the OS.
        for fixture in Fixture::ALL {
            let (drain, stills) = drain_fixture(fixture);
            panel.painter.paint(&drain, &stills);
        }
        for still in Still::ALL {
            if let Some((drain, stills)) = live_scene(still) {
                panel.painter.paint(&drain, &stills);
                continue;
            }
            let world = still_world(still);
            if let Some(view) = screens::view_of(&still.nav(&world), &world) {
                panel.screens.paint(view, screens::draw);
            }
        }
        // A crowded house with the longest names and the widest words, every page of the wall, DEVICE with
        // its two watched names, ALERT with its fullest lines.
        let mut crowd = still_world(Still::Devices);
        let widest = "W".repeat(qb_panel::os::world::DEVICE_NAME_CELLS);
        for octet in 0..MAX_DEVICES as u8 {
            let (name, named) = if octet % 2 == 0 {
                (widest.clone(), true)
            } else {
                display_name(None, None, octet)
            };
            let _ = crowd.push_device(DeviceRow {
                mac: mac_of(100 + octet),
                name,
                named,
                octet,
                state: qb_panel::os::world::DeviceState::Blocked,
                fixed: false,
                asking: octet % 5 == 0,
            });
        }
        crowd.watched = vec![
            Watched::new("a.very-long-and-busy-site.example.com", Outcome::Refused),
            Watched::new("www.example.org", Outcome::Passed),
        ];
        let mut fullest = still_world(Still::Alert);
        let long = "M".repeat(40);
        fullest.alerts = vec![qb_panel::os::world::AlertRow::new(
            9,
            true,
            &"W".repeat(24),
            &[&long, &long, &long],
        )];
        for page in 0..3 {
            let mut nav = Nav::at(Section::Devices);
            nav.apply(Change::DevicesPage(page));
            if let Some(view) = screens::view_of(&nav, &crowd) {
                panel.screens.paint(view, screens::draw);
            }
        }
        let mut nav = Nav::at(Section::Devices);
        nav.open(Opened::Device(crowd.devices[0].mac));
        if let Some(view) = screens::view_of(&nav, &crowd) {
            panel.screens.paint(view, screens::draw);
        }
        let mut nav = Nav::at(Section::Alerts);
        nav.open(Opened::Alert(9));
        if let Some(view) = screens::view_of(&nav, &fullest) {
            panel.screens.paint(view, screens::draw);
        }

        let ((drain_frames, drain_glyphs), (screen_frames, screen_glyphs)) =
            (panel.painter.bytes(), panel.screens.bytes());
        let glass = panel.glass.capacity();
        let world = World::bound_bytes().max(crowd.bytes()).max(fullest.bytes());
        let total = drain_frames + drain_glyphs + screen_frames + screen_glyphs + glass + world;
        println!(
            "panel memory: Drain painter {drain_frames} B of frames + {drain_glyphs} B of glyphs, \
             ScreenPainter {screen_frames} B + {screen_glyphs} B, glass {glass} B, \
             World bound {world} B: {total} B in all ({:.2} MB)",
            total as f64 / 1e6
        );

        // The frames are the spec's 1.2 MB each (RGBA, RGB565, and the one it is compared with).
        assert!(
            drain_frames <= FRAMES,
            "Drain painter frames {drain_frames} B"
        );
        assert!(
            screen_frames <= FRAMES,
            "ScreenPainter frames {screen_frames} B"
        );
        // Both glyph caches together stay inside the spec's 2 MB.
        assert!(
            drain_glyphs + screen_glyphs <= GLYPHS,
            "glyph caches {} B",
            drain_glyphs + screen_glyphs
        );
        // The glass keeps one RGB565 frame; the world is under its 64 KB.
        assert_eq!(glass, WIDTH * HEIGHT * 2);
        assert!(world <= WORLD, "world {world} B");
        assert!(total <= CEILING, "{total} B is over the 5 MB ceiling");
    }
}
