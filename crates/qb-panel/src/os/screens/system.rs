//! SYSTEM (spec §3.8, drawn as round 9's concept C for the overview and WI-FI, spec §12, and as round 8's plain
//! readings for the rest).
//!
//! - **SYSTEM** is a one-line mimic: the router, the Wi-Fi link as five dashes with its word, and the box with its
//!   two slots and what it feels, with `NIGHT`, `LOCK` and `ABOUT` as keys under it. The link is a door to WI-FI,
//!   the box's top (the slots) to VERSION, its lower half (the readings) to UP. Under ROUTER stands the band, not
//!   the router's answer time, and the spare slot says `KEPT` (spec §12.3): the Pi knows no more of either.
//! - **WI-FI** draws the link large: ten dashes lit by the signal (`clamp(round((dBm + 100) / 5), 0, 10)`), its
//!   word, two lines and `REJOIN`. While the link is joined again it says `JOINING` with every dash dark; nothing
//!   moves (spec §12.4). The key says `WAIT` during the control's refusal and is inert while an update runs.
//! - **VERSION**, **UP**, **LOCK**, **NIGHT HOURS** and **ABOUT** are round 8's plain readings (`reading()`): a
//!   label at baseline 104, a figure of 64 px at 170, lines of 18 px at 202 and 225, and the floor. VERSION has
//!   `BACK` only (no `CHECK NOW`, spec §11.1); UP's `RESTART` and LOCK's `TURN OFF` are strong and wear the
//!   padlock while the lock is on; NIGHT HOURS sets the two hours with `-` and `+` and `DONE`.
//!
//! A figure the Pi does not know is a dash in `G3`, never a zero. The strong keys give their intents as they are:
//! `nav::tap` holds them in the PIN pad (`screens::whole`) while the lock is on.

use crate::format::{self, DASH};
use crate::geometry::{Anchor, Rect};
use crate::os::intent::Intent;
use crate::os::nav::{Change, Screen, Section, Tap};
use crate::os::screens::lane::{self, LaneView};
use crate::os::screens::parts::{self, Dress, Right, node};
use crate::os::world::{BUILT_CELLS, LastUpdate, LockSource, Rejoin, Slot, VERSION_CELLS, World};
use crate::ui::canvas::{Canvas, Face};
use crate::ui::look::{
    ADVANCE_EM, BLUE, BLUE_DEEP, BLUE_LT, BLUE_MD, BLUE_NIGHT, FLOOR_SPLIT_X, FLOOR_Y, G1, G2, G3,
    G4, GROUND, WHITE,
};

/// The version's cells in ABOUT's second line: the line has 28 other letters, and 480 px hold 43 of 10.8 px.
const ABOUT_VERSION_CELLS: usize = 7;

/// The version's cells in the running slot's box: 24 px letters of 14.4 px in a box 130 wide, from x + 7.
const SLOT_VERSION_CELLS: usize = 8;

/// The hours NIGHT HOURS starts from when there are none: the two equal, which is no night.
const NO_NIGHT: (u8, u8) = (23, 23);

/// The first row of SYSTEM's doors: the rows between the lane and the mimic are nothing, as HOME's are.
const DOORS_Y0: u16 = 76;

/// The row where the box's slots end and its readings begin: the version door above, the uptime door below.
const BOX_SPLIT_Y: u16 = 174;

/// The column the link's door ends at; the box begins there.
const LINK_DOOR_X: u16 = 180;

/// The three keys under the mimic: 150 wide on a pitch of 157 from x 8, and a press counts from x 4.
const KEY_PITCH: u16 = 157;

/// The most the hours of the day count.
const HOURS: u8 = 24;

// ---------------------------------------------------------------------------------------------
// Lines with figures the Pi may not know.

/// A piece of a line: its letters, and whether it is a figure that is known. An unknown figure is the dash,
/// drawn in `G3` where the rest of the line is in its own ink.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Run {
    /// The letters.
    text: String,
    /// False for the dash standing for a figure the Pi does not know.
    known: bool,
}

/// A line of words and figures, set in one face with the unknown figures dimmed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Line(Vec<Run>);

impl Line {
    /// A line with nothing in it yet.
    fn new() -> Self {
        Self::default()
    }

    /// Adds words.
    fn say(mut self, text: impl Into<String>) -> Self {
        self.0.push(Run {
            text: text.into(),
            known: true,
        });
        self
    }

    /// Adds a figure made by `show` from its value, or the dash while there is none.
    fn figure<T>(mut self, value: Option<T>, show: impl FnOnce(T) -> String) -> Self {
        self.0.push(match value {
            Some(value) => Run {
                text: show(value),
                known: true,
            },
            None => Run {
                text: DASH.to_string(),
                known: false,
            },
        });
        self
    }

    /// How many letters the line has.
    fn letters(&self) -> usize {
        self.0.iter().map(|run| run.text.chars().count()).sum()
    }

    /// The line's words as one string, for tests and for what a screen says in plain words.
    #[cfg(test)]
    fn text(&self) -> String {
        self.0.iter().map(|run| run.text.as_str()).collect()
    }
}

/// Sets a line at `x` (by `face.anchor`) on `baseline`: each run in the face's ink, the dashes in `G3`.
fn draw_line(canvas: &mut Canvas, line: &Line, x: f32, baseline: f32, face: Face) {
    let advance = face.px * ADVANCE_EM + face.tracking;
    let width = face.width(line.letters());
    let left = match face.anchor {
        Anchor::Start => x,
        Anchor::Middle => x - width / 2.0,
        Anchor::End => x - width,
    };
    let mut before = 0_usize;
    for run in &line.0 {
        let ink = if run.known { face.color } else { G3 };
        let run_face = Face {
            color: ink,
            anchor: Anchor::Start,
            ..face
        };
        canvas.text(
            &run.text,
            left + before as f32 * advance,
            baseline,
            run_face,
        );
        before += run.text.chars().count();
    }
}

/// The version fitted to `cells`, or no figure while the world has none.
fn version_of(world: &World, cells: usize) -> Option<String> {
    let version = world.version.trim();
    (!version.is_empty()).then(|| format::fit_text(version, cells))
}

/// The load in hundredths as it is read in full, `0.21`.
fn load_full(hundredths: u32) -> String {
    format!("{}.{:02}", hundredths / 100, hundredths % 100)
}

/// The load as the mimic's line has it, without the leading zero: `.21`, and `1.05` past one.
fn load_short(hundredths: u32) -> String {
    if hundredths < 100 {
        format!(".{:02}", hundredths % 100)
    } else {
        load_full(hundredths)
    }
}

/// `n days` as the WI-FI line says it: `today`, `1 day`, `12 days`.
fn days_word(days: u32) -> String {
    match days {
        0 => "today".to_string(),
        1 => "1 day".to_string(),
        n => format!("{n} days"),
    }
}

/// The night hours as the key says them: `23\u{2013}07`, or `OFF`.
fn night_word(world: &World) -> String {
    world.night_hours().map_or_else(
        || "OFF".to_string(),
        |(from, to)| format!("{from:02}\u{2013}{to:02}"),
    )
}

// ---------------------------------------------------------------------------------------------
// SYSTEM: the mimic.

/// One slot's box on the mimic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotBox {
    /// Its letter.
    pub letter: char,
    /// Whether it is the slot that runs, and so drawn solid; `None` while the world does not say which runs.
    pub runs: Option<bool>,
    /// What stands in it at 24 px: the running slot's version, the spare's `KEPT`, a dash for either unknown.
    pub figure: Line,
}

impl SlotBox {
    /// The box of `slot`, for a world.
    fn of(world: &World, slot: Slot) -> Self {
        let runs = world.machine.slot.map(|running| running == slot);
        let figure = match runs {
            Some(true) => Line::new().figure(version_of(world, SLOT_VERSION_CELLS), |v| v),
            Some(false) => Line::new().say("KEPT"),
            None => Line::new().figure(None::<String>, |v| v),
        };
        Self {
            letter: slot.letter(),
            runs,
            figure,
        }
    }

    /// The label: `A · RUNS`, `B · SPARE`, or the letter alone when it is not known which slot runs.
    fn label(&self) -> String {
        match self.runs {
            Some(true) => format!("{} \u{b7} RUNS", self.letter),
            Some(false) => format!("{} \u{b7} SPARE", self.letter),
            None => self.letter.to_string(),
        }
    }
}

/// What SYSTEM puts on the glass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemView {
    /// The lane, which says `SYSTEM`.
    pub lane: LaneView,
    /// The band, under ROUTER: `5 GHZ` (spec §12.3).
    pub band: Line,
    /// How many of the link's five dashes are lit: half the WI-FI screen's ten, rounded up.
    pub dashes: u8,
    /// The link's word under its dashes.
    pub word: Line,
    /// `UP 12 D`, at the box's top right.
    pub up: Line,
    /// The two slots, A then B.
    pub slots: [SlotBox; 2],
    /// How the last update ended, as the box says it (spec §12.3).
    pub updated: &'static str,
    /// `LOAD .21 · MEM 38% · 47 °C`.
    pub readings: Line,
    /// The `NIGHT` key's figure: `23–07` or `OFF`.
    pub night: String,
    /// The `LOCK` key's figure: `ON` or `OFF`.
    pub lock: &'static str,
}

impl SystemView {
    /// What SYSTEM shows for a world.
    pub fn of(world: &World) -> Self {
        let machine = &world.machine;
        Self {
            lane: LaneView::of(Section::System, world),
            band: Line::new().figure(world.link.band, |band| band.word().to_string()),
            dashes: world.link_dashes().div_ceil(2),
            word: Line::new().figure(world.link_word(), str::to_string),
            up: Line::new()
                .say("UP ")
                .figure(world.uptime_days, |days| format!("{days} D")),
            slots: [SlotBox::of(world, Slot::A), SlotBox::of(world, Slot::B)],
            updated: match machine.last_update {
                LastUpdate::Confirmed => "LAST UPDATE CONFIRMED",
                LastUpdate::RolledBack => "LAST UPDATE ROLLED BACK",
                LastUpdate::None => "NO UPDATE SINCE START",
            },
            readings: Line::new()
                .say("LOAD ")
                .figure(machine.load_hundredths, load_short)
                .say(" \u{b7} MEM ")
                .figure(machine.memory_pct, |pct| format!("{pct}%"))
                .say(" \u{b7} ")
                .figure(machine.temp_c, |c| format!("{c} \u{b0}C")),
            night: night_word(world),
            lock: if world.lock_on { "ON" } else { "OFF" },
        }
    }
}

/// SYSTEM's taps: the link opens WI-FI, the box's slots VERSION, its readings UP, and the three keys under it
/// NIGHT HOURS, LOCK and ABOUT.
pub fn system_tap(x: u16, y: u16) -> Tap {
    if y < DOORS_Y0 {
        return Tap::None;
    }
    let door = if y >= FLOOR_Y {
        match (x.saturating_sub(4) / KEY_PITCH).min(2) {
            0 => Screen::NightHours,
            1 => Screen::Lock,
            _ => Screen::About,
        }
    } else if x < LINK_DOOR_X {
        Screen::Wifi
    } else if y < BOX_SPLIT_Y {
        Screen::Version
    } else {
        Screen::Uptime
    };
    Tap::Nav(Change::Open(door))
}

/// Draws SYSTEM (`system`).
pub fn draw_system(canvas: &mut Canvas, view: &SystemView) {
    lane::draw(canvas, &view.lane);
    // The router, its band under it, and the link between: five dashes, its caption and its word.
    node(canvas, Rect::new(8, 124, 78, 56), "ROUTER", G1, G1);
    draw_line(canvas, &view.band, 47.0, 202.0, Face::bold(16.0, G2).mid());
    canvas.text("WI-FI", 135.0, 140.0, Face::bold(16.0, G2).track(1.0).mid());
    for i in 0..5_u16 {
        let lit = i < u16::from(view.dashes);
        canvas.rect(
            Rect::new(92 + i * 18, 149, 12, 6),
            if lit { WHITE } else { G4 },
        );
    }
    draw_line(
        canvas,
        &view.word,
        135.0,
        178.0,
        Face::bold(16.0, WHITE).track(1.0).mid(),
    );
    // The box.
    canvas.hollow(Rect::new(180, 80, 292, 152), BLUE_MD, 2, GROUND);
    canvas.text(
        "QBERRYPI",
        192.0,
        102.0,
        Face::bold(16.0, BLUE_LT).track(2.0),
    );
    draw_line(canvas, &view.up, 460.0, 102.0, Face::bold(16.0, G1).end());
    for (slot, x) in view.slots.iter().zip([192_u16, 330]) {
        let rect = Rect::new(x, 112, 130, 56);
        let (label_ink, figure_ink) = match slot.runs {
            Some(true) => {
                canvas.rect(rect, BLUE);
                (BLUE_NIGHT, WHITE)
            }
            _ => {
                canvas.hollow(rect, G3, 2, GROUND);
                (G3, G2)
            }
        };
        canvas.text(
            &slot.label(),
            f32::from(x) + 8.0,
            133.0,
            Face::bold(16.0, label_ink).track(1.0),
        );
        draw_line(
            canvas,
            &slot.figure,
            f32::from(x) + 7.0,
            159.0,
            Face::bold(24.0, figure_ink),
        );
    }
    canvas.text(view.updated, 192.0, 190.0, Face::bold(16.0, G1));
    canvas.rect(Rect::new(192, 198, 268, 2), BLUE_DEEP);
    draw_line(canvas, &view.readings, 192.0, 220.0, Face::bold(16.0, G2));
    // The three keys under it.
    for (k, (caption, value)) in [
        ("NIGHT", view.night.as_str()),
        ("LOCK", view.lock),
        ("ABOUT", "PI 3B+"),
    ]
    .into_iter()
    .enumerate()
    {
        let x = 8.0 + 157.0 * k as f32;
        canvas.hollow(Rect::new(8 + 157 * k as u16, 240, 150, 64), G3, 2, GROUND);
        canvas.text(caption, x + 10.0, 263.0, Face::bold(16.0, G2).track(2.0));
        canvas.text(value, x + 9.0, 292.0, Face::bold(24.0, WHITE));
    }
}

// ---------------------------------------------------------------------------------------------
// The floor's right key of a reading.

/// What the floor's right key of a reading is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RightKey {
    /// No key: the half stays black.
    None,
    /// A key that changes things: solid white. A strong one wears the padlock while the lock is on (`locked`).
    Key {
        /// The word.
        word: &'static str,
        /// Whether it wears the padlock: it is strong and the lock is on.
        locked: bool,
    },
    /// A key that is not offered now (`WAIT`, or the word of a key an update has made inert): a dim outline.
    Inert(&'static str),
}

impl RightKey {
    /// A solid key, with the padlock when `locked`.
    const fn key(word: &'static str, locked: bool) -> Self {
        Self::Key { word, locked }
    }

    /// As the dressed floor (`keys9`) says it.
    fn right(self) -> Right<'static> {
        match self {
            Self::None => Right::Nothing,
            Self::Key { word, .. } => Right::Key(word),
            Self::Inert(word) => Right::Inert(word),
        }
    }

    /// Whether the key wears the padlock.
    const fn locked(self) -> bool {
        matches!(self, Self::Key { locked: true, .. })
    }
}

/// Where the floor's right key of a reading is a key: its intent, when it is offered.
const fn offered(right: RightKey) -> bool {
    matches!(right, RightKey::Key { .. })
}

// ---------------------------------------------------------------------------------------------
// WI-FI: the link, large.

/// What WI-FI puts on the glass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifiView {
    /// The lane, which says `SYSTEM`.
    pub lane: LaneView,
    /// `WI-FI · 5 GHZ`, above the dashes.
    pub caption: Line,
    /// How many of the ten dashes are lit.
    pub dashes: u8,
    /// The link's word under them (24 px).
    pub word: Line,
    /// The two lines under the word: the signal and how long it has held, then the upstream's answer time.
    pub lines: [Line; 2],
    /// The floor's right key: `REJOIN`, `WAIT` while the control refuses, `REJOIN` inert while an update runs.
    pub right: RightKey,
}

/// The key `REJOIN` is, from the world: a refusal says `WAIT` first, an update running leaves it inert.
fn rejoin_key(world: &World) -> RightKey {
    match world.rejoin {
        Rejoin::Wait(_) | Rejoin::Joining => RightKey::Inert("WAIT"),
        Rejoin::Idle if world.update_busy => RightKey::Inert("REJOIN"),
        Rejoin::Idle => RightKey::key("REJOIN", false),
    }
}

impl WifiView {
    /// What WI-FI shows for a world.
    pub fn of(world: &World) -> Self {
        let signal = if world.link_joining() {
            Line::new().say("letting go and taking hold again")
        } else {
            Line::new()
                .say("signal ")
                .figure(world.link.signal_dbm, |dbm| dbm.to_string())
                .say(" dBm \u{b7} linked ")
                .figure(world.link.linked_days, days_word)
        };
        Self {
            lane: LaneView::of(Section::System, world),
            caption: Line::new()
                .say("WI-FI \u{b7} ")
                .figure(world.link.band, |band| band.word().to_string()),
            dashes: world.link_dashes(),
            word: Line::new().figure(world.link_word(), str::to_string),
            lines: [
                signal,
                Line::new()
                    .say("upstream answers in ")
                    .figure(world.link.upstream_ms, |ms| format!("{ms} ms")),
            ],
            right: rejoin_key(world),
        }
    }
}

/// WI-FI's taps: `BACK` goes back to SYSTEM; `REJOIN` asks the system to join again, when it is offered.
pub fn wifi_tap(world: &World, floor: bool, left: bool) -> Tap {
    if !floor {
        return Tap::None;
    }
    if left {
        return Tap::Nav(Change::Back);
    }
    if offered(rejoin_key(world)) {
        Tap::Act(Intent::Rejoin, None)
    } else {
        Tap::None
    }
}

/// Draws WI-FI (`wifi`).
pub fn draw_wifi(canvas: &mut Canvas, view: &WifiView) {
    lane::draw(canvas, &view.lane);
    node(canvas, Rect::new(8, 92, 110, 64), "ROUTER", G1, G1);
    canvas.rect(Rect::new(362, 92, 110, 64), BLUE);
    canvas.text("QBERRYPI", 417.0, 130.0, Face::bold(16.0, WHITE).mid());
    for i in 0..10_u16 {
        let lit = i < u16::from(view.dashes);
        canvas.rect(
            Rect::new(132 + i * 22, 119, 16, 10),
            if lit { WHITE } else { G4 },
        );
    }
    draw_line(
        canvas,
        &view.caption,
        240.0,
        108.0,
        Face::bold(16.0, G2).track(1.0).mid(),
    );
    draw_line(
        canvas,
        &view.word,
        240.0,
        160.0,
        Face::bold(24.0, WHITE).mid(),
    );
    for (line, baseline) in view.lines.iter().zip([198.0, 222.0]) {
        draw_line(canvas, line, 8.0, baseline, Face::regular(18.0, G1));
    }
    parts::keys9(
        canvas,
        Dress::C,
        Some("BACK"),
        view.right.right(),
        view.right.locked(),
    );
}

// ---------------------------------------------------------------------------------------------
// VERSION, UP and LOCK: the plain readings.

/// What a plain reading (`reading()`) puts on the glass: VERSION, UP or LOCK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadingView {
    /// The lane, which says `SYSTEM`.
    pub lane: LaneView,
    /// The label, 16 px at baseline 104.
    pub label: &'static str,
    /// The figure, 64 px at baseline 170.
    pub figure: Line,
    /// The lines, 18 px at 202 and 225.
    pub lines: Vec<Line>,
    /// The floor's left key.
    pub left: &'static str,
    /// The floor's right key.
    pub right: RightKey,
}

impl ReadingView {
    /// VERSION: the running version, the build and the slot, and how the last update ended. `BACK` only.
    pub fn version(world: &World) -> Self {
        let machine = &world.machine;
        let ended = match machine.last_update {
            LastUpdate::Confirmed => "confirmed",
            LastUpdate::RolledBack => "rolled back",
            LastUpdate::None => "none since start",
        };
        Self {
            lane: LaneView::of(Section::System, world),
            label: "VERSION",
            figure: Line::new().figure(version_of(world, VERSION_CELLS), |v| v),
            lines: vec![
                Line::new()
                    .say("built ")
                    .figure(
                        Some(machine.built.trim()).filter(|built| !built.is_empty()),
                        |built| format::fit_text(built, BUILT_CELLS),
                    )
                    .say(" \u{b7} slot ")
                    .figure(machine.slot, |slot| slot.letter().to_string()),
                Line::new().say(format!("last update: {ended}")),
            ],
            left: "BACK",
            right: RightKey::None,
        }
    }

    /// UP: the uptime, what the board feels, and what it last restarted for; `RESTART` is strong, and inert while
    /// an update is received or on trial.
    pub fn uptime(world: &World) -> Self {
        let machine = &world.machine;
        let cause = Some(machine.last_restart.trim()).filter(|cause| !cause.is_empty());
        let mut figure = Line::new().figure(world.uptime_days, |days| format!("{days} D"));
        if let (Some(_), Some(hours)) = (world.uptime_days, machine.uptime_hours) {
            figure = figure.say(format!(" {hours} H"));
        }
        Self {
            lane: LaneView::of(Section::System, world),
            label: "UP",
            figure,
            lines: vec![
                Line::new()
                    .say("load ")
                    .figure(machine.load_hundredths, load_full)
                    .say(" \u{b7} memory ")
                    .figure(machine.memory_pct, |pct| format!("{pct}%"))
                    .say(" \u{b7} ")
                    .figure(machine.temp_c, |c| format!("{c} \u{b0}C")),
                Line::new().say("last restart: ").figure(cause, |cause| {
                    format::fit_text(cause, crate::os::world::RESTART_CAUSE_CELLS)
                }),
            ],
            left: "BACK",
            right: if world.update_busy {
                RightKey::Inert("RESTART")
            } else {
                RightKey::key("RESTART", world.lock_on)
            },
        }
    }

    /// LOCK: `ON` or `OFF`, the strong actions a PIN guards, and where the PIN lives (spec §7.2).
    pub fn lock(world: &World) -> Self {
        let on = world.lock_on;
        // With the card keeping the state a PIN from the desktop or the panel outlasts a restart too.
        let home = match (on, world.lock_source, world.lock_kept) {
            (true, LockSource::Config, _) => "kept in the config: it outlasts a restart",
            (true, LockSource::Api, true) => "from the desktop: it outlasts a restart",
            (true, LockSource::Api, false) => "from the desktop: until the next restart",
            (true, LockSource::Panel, true) => "set here: it outlasts a restart",
            (true, LockSource::Panel, false) => "set here: until the next restart",
            (false, _, true) => "a PIN set here outlasts a restart",
            (false, _, false) => "a PIN set here lasts until a restart",
        };
        Self {
            lane: LaneView::of(Section::System, world),
            label: "LOCK",
            figure: Line::new().say(if on { "ON" } else { "OFF" }),
            lines: vec![
                Line::new().say(if on {
                    "PIN first: allow ads, name, restart, unlock"
                } else {
                    "PIN would guard: allow ads, name, restart"
                }),
                Line::new().say(home),
            ],
            left: if on { "KEEP ON" } else { "KEEP OFF" },
            // Turning the lock off is strong, so with the lock on its key wears the padlock; a PIN is set while it is off.
            right: RightKey::key(if on { "TURN OFF" } else { "SET A PIN" }, on),
        }
    }
}

/// Draws a plain reading: its label, figure, lines and the floor.
pub fn draw_reading(canvas: &mut Canvas, view: &ReadingView) {
    lane::draw(canvas, &view.lane);
    canvas.text(view.label, 6.4, 104.0, Face::bold(16.0, G2).track(2.5));
    draw_line(canvas, &view.figure, 3.0, 170.0, Face::bold(64.0, WHITE));
    for (k, line) in view.lines.iter().enumerate() {
        draw_line(
            canvas,
            line,
            7.0,
            202.0 + 23.0 * k as f32,
            Face::regular(18.0, G1),
        );
    }
    match view.right {
        RightKey::None => parts::keys(canvas, Some(view.left), None, false),
        RightKey::Key { word, locked } => {
            parts::keys(canvas, Some(view.left), Some(word), locked);
        }
        RightKey::Inert(word) => {
            parts::keys(canvas, Some(view.left), None, false);
            parts::inert_key(canvas, word);
        }
    }
}

/// The taps of a reading with only `BACK`: VERSION and ABOUT. The floor's left key goes back to SYSTEM.
pub fn back_tap(floor: bool, left: bool) -> Tap {
    if floor && left {
        Tap::Nav(Change::Back)
    } else {
        Tap::None
    }
}

/// UP's taps: `BACK`, and `RESTART` (strong), which asks the system to restart when it is offered.
pub fn uptime_tap(world: &World, floor: bool, left: bool) -> Tap {
    if !floor {
        return Tap::None;
    }
    if left {
        return Tap::Nav(Change::Back);
    }
    if world.update_busy {
        Tap::None
    } else {
        Tap::Act(Intent::Restart, None)
    }
}

/// LOCK's taps: `KEEP ON` and `KEEP OFF` go back; `TURN OFF` (strong) asks the system to clear the PIN, and
/// `SET A PIN` opens the pad to choose one.
pub fn lock_tap(world: &World, floor: bool, left: bool) -> Tap {
    if !floor {
        return Tap::None;
    }
    if left {
        Tap::Nav(Change::Back)
    } else if world.lock_on {
        Tap::Act(Intent::ClearPin, None)
    } else {
        Tap::Nav(Change::ChoosePin)
    }
}

// ---------------------------------------------------------------------------------------------
// NIGHT HOURS.

/// The hours the screen starts from and `DONE` compares with: the world's, or the two equal, which is no night.
fn world_hours(world: &World) -> (u8, u8) {
    world.night_hours().unwrap_or(NO_NIGHT)
}

/// The hours NIGHT HOURS shows: the draft the `-` and `+` keys made, else the world's.
fn shown_hours(draft: Option<(u8, u8)>, world: &World) -> (u8, u8) {
    draft.unwrap_or_else(|| world_hours(world))
}

/// What NIGHT HOURS puts on the glass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NightView {
    /// The lane, which says `SYSTEM`.
    pub lane: LaneView,
    /// The hour the dark begins, 0 to 23.
    pub from: u8,
    /// The hour it ends, 0 to 23; equal to `from` is no night.
    pub to: u8,
}

impl NightView {
    /// What NIGHT HOURS shows for a world and the draft the nav holds.
    pub fn of(world: &World, draft: Option<(u8, u8)>) -> Self {
        let (from, to) = shown_hours(draft, world);
        Self {
            lane: LaneView::of(Section::System, world),
            from,
            to,
        }
    }
}

/// NIGHT HOURS' taps: the `-` and `+` keys (from x 292: `-` under x 386) of the first row (above y 160) and
/// the second change one hour of the draft; `SLEEP NOW` asks for the night clock at once; `DONE` sets the hours
/// when they changed and goes back.
pub fn night_tap(draft: Option<(u8, u8)>, world: &World, x: u16, y: u16) -> Tap {
    let (from, to) = shown_hours(draft, world);
    if y >= FLOOR_Y {
        return if x < FLOOR_SPLIT_X {
            Tap::Act(Intent::SleepNow, None)
        } else if (from, to) == world_hours(world) {
            Tap::Nav(Change::Back)
        } else {
            Tap::Act(Intent::NightHours { from, to }, Some(Change::Back))
        };
    }
    if x < 292 {
        return Tap::None;
    }
    let step = if x < 386 { HOURS - 1 } else { 1 };
    let moved = |hour: u8| (hour + step) % HOURS;
    Tap::Nav(if y < 160 {
        Change::Hours(moved(from), to)
    } else {
        Change::Hours(from, moved(to))
    })
}

/// Draws NIGHT HOURS (`nightHoursScreen`): two rows of a label, the hour in 40 px, and a `-` and a `+` key.
pub fn draw_night(canvas: &mut Canvas, view: &NightView) {
    lane::draw(canvas, &view.lane);
    // The two hours equal is no night: the second label says so.
    let until = if view.from == view.to {
        "UNTIL \u{b7} NEVER DARK"
    } else {
        "UNTIL"
    };
    for (k, (label, hour)) in [("DARK FROM", view.from), (until, view.to)]
        .into_iter()
        .enumerate()
    {
        let y = 80.0 + 80.0 * k as f32;
        canvas.text(label, 6.4, y + 22.0, Face::bold(16.0, G2).track(2.5));
        canvas.text(
            &format!("{hour:02}:00"),
            6.0,
            y + 64.0,
            Face::bold(40.0, WHITE),
        );
        for (glyph, x) in [("-", 300_u16), ("+", 392)] {
            canvas.hollow(Rect::new(x, y as u16 + 4, 80, 64), WHITE, 4, GROUND);
            canvas.text(
                glyph,
                f32::from(x) + 40.0,
                y + 50.0,
                Face::bold(40.0, WHITE).mid(),
            );
        }
    }
    parts::keys(canvas, Some("SLEEP NOW"), Some("DONE"), false);
}

// ---------------------------------------------------------------------------------------------
// ABOUT.

/// What ABOUT puts on the glass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AboutView {
    /// The lane, which says `SYSTEM`.
    pub lane: LaneView,
    /// The reading's second line, with the running version in it.
    pub line: String,
}

impl AboutView {
    /// What ABOUT shows for a world.
    pub fn of(world: &World) -> Self {
        let version = version_of(world, ABOUT_VERSION_CELLS).unwrap_or_else(|| DASH.to_string());
        Self {
            lane: LaneView::of(Section::System, world),
            line: format!("version {version} on a Pi 3B+ \u{b7} panel 480\u{d7}320"),
        }
    }
}

/// Draws ABOUT.
pub fn draw_about(canvas: &mut Canvas, view: &AboutView) {
    lane::draw(canvas, &view.lane);
    parts::reading(
        canvas,
        "ABOUT",
        "QBERRYPI",
        &["a DNS gate and watchdog for the house", &view.line],
        Some("BACK"),
        None,
        false,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geometry::{Rgb, Weight};
    use crate::os::fixture::{Still, world};
    use crate::os::nav::{Nav, decide, refresh, tap};
    use crate::os::world::Band;
    use crate::text::has_glyph;
    use crate::ui::look::BLUE;

    fn is(canvas: &Canvas, x: usize, y: usize, color: Rgb) -> bool {
        canvas.pixel(x, y) == Some(color)
    }

    /// The nav of a still, and its world.
    fn at(still: Still) -> (Nav, World) {
        let world = world(still);
        (still.nav(&world), world)
    }

    /// Whether any pixel of the rectangle is the colour.
    fn any(canvas: &Canvas, (x0, y0, w, h): (usize, usize, usize, usize), color: Rgb) -> bool {
        (y0..y0 + h).any(|y| (x0..x0 + w).any(|x| is(canvas, x, y, color)))
    }

    // ---- SYSTEM ----

    #[test]
    fn the_mimic_says_the_band_the_link_the_slots_and_the_box_as_the_pi_knows_them() {
        let view = SystemView::of(&world(Still::System));
        assert_eq!(view.lane.words, "SYSTEM");
        // Spec §12.3: the band under ROUTER, not the router's answer time.
        assert_eq!(view.band.text(), "5 GHZ");
        // -54 dBm is nine dashes of ten, five of five rounded up, and GOOD.
        assert_eq!((view.dashes, view.word.text().as_str()), (5, "GOOD"));
        assert_eq!(view.up.text(), "UP 12 D");
        assert_eq!(view.slots[0].label(), "A \u{b7} RUNS");
        assert_eq!(view.slots[0].figure.text(), "0.4.1");
        assert_eq!(view.slots[1].label(), "B \u{b7} SPARE");
        assert_eq!(
            view.slots[1].figure.text(),
            "KEPT",
            "the spare's version is not known"
        );
        assert_eq!(view.updated, "LAST UPDATE CONFIRMED");
        assert_eq!(
            view.readings.text(),
            "LOAD .21 \u{b7} MEM 38% \u{b7} 47 \u{b0}C"
        );
        assert_eq!((view.night.as_str(), view.lock), ("23\u{2013}07", "OFF"));
        // The en dash is in the font.
        assert!(has_glyph(Weight::Bold, '\u{2013}') && has_glyph(Weight::Bold, '\u{b0}'));
    }

    #[test]
    fn the_box_says_how_the_last_update_ended_which_slot_runs_and_what_it_is_not_told() {
        let mut w = world(Still::System);
        w.machine.last_update = LastUpdate::RolledBack;
        w.machine.slot = Some(Slot::B);
        w.night = None;
        w.lock_on = true;
        let view = SystemView::of(&w);
        assert_eq!(view.updated, "LAST UPDATE ROLLED BACK");
        assert_eq!(view.slots[0].label(), "A \u{b7} SPARE");
        assert_eq!(view.slots[0].figure.text(), "KEPT");
        assert_eq!(view.slots[1].label(), "B \u{b7} RUNS");
        assert_eq!(view.slots[1].figure.text(), "0.4.1");
        assert_eq!((view.night.as_str(), view.lock), ("OFF", "ON"));
        w.machine.last_update = LastUpdate::None;
        assert_eq!(SystemView::of(&w).updated, "NO UPDATE SINCE START");
        // Two equal hours are no night either.
        w.night = Some((7, 7));
        assert_eq!(SystemView::of(&w).night, "OFF");
        // Nothing known: a dash for every figure, never a zero.
        let blank = SystemView::of(&World::default());
        assert_eq!(blank.band.text(), DASH);
        assert_eq!(blank.up.text(), format!("UP {DASH}"));
        assert_eq!(
            blank.readings.text(),
            format!("LOAD {DASH} \u{b7} MEM {DASH} \u{b7} {DASH}")
        );
        assert_eq!(blank.slots[0].label(), "A");
        assert_eq!(blank.slots[0].figure.text(), DASH);
        assert_eq!(blank.slots[1].figure.text(), DASH);
        // Not joined: DOWN with every dash dark.
        assert_eq!((blank.dashes, blank.word.text().as_str()), (0, "DOWN"));
        // The running version is cut to its box: eight cells of 14.4 px in 130.
        let mut long = world(Still::System);
        long.version = "0.4.1-release-candidate".into();
        let said = SystemView::of(&long).slots[0].figure.text();
        assert_eq!(said.chars().count(), SLOT_VERSION_CELLS, "{said}");
        assert!(said.ends_with('~'));
    }

    #[test]
    fn the_mimic_is_drawn_as_cc_js_has_it() {
        let mut canvas = Canvas::new();
        draw_system(&mut canvas, &SystemView::of(&world(Still::System)));
        // ROUTER's node: a 2 px G1 frame at (8, 124), 78 by 56.
        assert!(
            is(&canvas, 8, 124, G1) && is(&canvas, 85, 179, G1) && is(&canvas, 20, 140, GROUND)
        );
        // Five dashes 18 apart from x 92, 12 by 6 on y 149, all lit at -54 dBm.
        for i in 0..5 {
            assert!(is(&canvas, 92 + 18 * i, 149, WHITE), "dash {i}");
            assert!(is(&canvas, 103 + 18 * i, 154, WHITE), "dash {i}");
            assert!(
                is(&canvas, 104 + 18 * i, 150, GROUND),
                "the gap after dash {i}"
            );
        }
        // The box: a 2 px BLUE_MD frame (180, 80), 292 by 152; slot A solid blue, slot B a G3 outline.
        assert!(is(&canvas, 180, 80, BLUE_MD) && is(&canvas, 471, 231, BLUE_MD));
        assert!(is(&canvas, 192, 112, BLUE) && is(&canvas, 321, 167, BLUE));
        assert!(is(&canvas, 330, 112, G3) && is(&canvas, 459, 167, G3));
        assert!(is(&canvas, 400, 140, GROUND), "the spare is hollow");
        // The rule under the line, the three keys at y 240, 150 wide on a pitch of 157.
        assert!(is(&canvas, 192, 198, BLUE_DEEP) && is(&canvas, 459, 199, BLUE_DEEP));
        for k in 0..3 {
            assert!(is(&canvas, 8 + 157 * k, 240, G3), "key {k}");
            assert!(is(&canvas, 157 + 157 * k, 303, G3), "key {k}");
            assert!(is(&canvas, 20 + 157 * k, 250, GROUND), "key {k}");
        }
    }

    #[test]
    fn the_links_five_dashes_are_half_of_wi_fis_ten_rounded_up() {
        // (dBm, ten dashes on WI-FI, five on SYSTEM)
        for (dbm, ten, five) in [
            (-54, 9, 5),
            (-63, 7, 4),
            (-80, 4, 2),
            (-95, 1, 1),
            (-100, 0, 0),
        ] {
            let mut w = world(Still::System);
            w.link.signal_dbm = Some(dbm);
            assert_eq!(WifiView::of(&w).dashes, ten, "{dbm}");
            assert_eq!(SystemView::of(&w).dashes, five, "{dbm}");
        }
        // Rejoining: all dark on both, and no timer is in the view.
        let mut w = world(Still::Wifi);
        w.rejoin = Rejoin::Joining;
        assert_eq!((WifiView::of(&w).dashes, SystemView::of(&w).dashes), (0, 0));
    }

    #[test]
    fn the_mimics_doors_lead_where_the_map_says() {
        let (nav, world) = at(Still::System);
        // The link, from x 0 to 180 and y 76 to 236: WI-FI. The box's slots, y 76 to 174: VERSION; its readings: UP.
        let open = |screen| Tap::Nav(Change::Open(screen));
        for (x, y, door) in [
            (47, 150, Screen::Wifi),
            (0, 76, Screen::Wifi),
            (179, 235, Screen::Wifi),
            (180, 76, Screen::Version),
            (470, 173, Screen::Version),
            (300, 120, Screen::Version),
            (180, 174, Screen::Uptime),
            (470, 235, Screen::Uptime),
            // The keys under it: NIGHT, LOCK, ABOUT; a press counts from x 4, the last key to the edge.
            (80, 270, Screen::NightHours),
            (4, 236, Screen::NightHours),
            (160, 300, Screen::NightHours),
            (161, 300, Screen::Lock),
            (240, 270, Screen::Lock),
            (317, 270, Screen::Lock),
            (318, 270, Screen::About),
            (479, 319, Screen::About),
        ] {
            assert_eq!(decide(&nav, &world, x, y), open(door.clone()), "({x}, {y})");
        }
        // The rows between the lane and the mimic are nothing, and so is the lane's own row.
        for (x, y) in [(100, 72), (100, 75), (300, 75)] {
            assert_eq!(decide(&nav, &world, x, y), Tap::None, "({x}, {y})");
        }
        // Each door opens the screen above the root.
        let mut nav = nav;
        assert_eq!(tap(&mut nav, &world, 47, 150), None);
        assert_eq!(nav.stack(), [Screen::Wifi]);
    }

    #[test]
    fn home_and_the_clock_open_the_mimic_and_a_reading_is_over_it() {
        use crate::os::screens::{View, view_of};
        let w = world(Still::Home);
        for (x, y) in [(400, 250), (400, 40)] {
            let mut nav = Still::Home.nav(&w);
            assert_eq!(tap(&mut nav, &w, x, y), None);
            assert_eq!((nav.root(), nav.stack().len()), (Section::System, 0));
            assert!(matches!(view_of(&nav, &w), Some(View::System(_))));
        }
        // From a reading, the clock goes to the mimic as well, and its lane word does.
        let (mut nav, w) = at(Still::Uptime);
        assert_eq!(tap(&mut nav, &w, 400, 40), None);
        assert_eq!((nav.root(), nav.stack().len()), (Section::System, 0));
        let (mut nav, w) = at(Still::Lock);
        assert_eq!(tap(&mut nav, &w, 200, 40), None);
        assert_eq!((nav.root(), nav.stack().len()), (Section::System, 0));
    }

    // ---- WI-FI ----

    #[test]
    fn wi_fi_says_the_link_in_words_and_lines() {
        let view = WifiView::of(&world(Still::Wifi));
        assert_eq!(view.caption.text(), "WI-FI \u{b7} 5 GHZ");
        assert_eq!((view.dashes, view.word.text().as_str()), (9, "GOOD"));
        assert_eq!(view.lines[0].text(), "signal -54 dBm \u{b7} linked 12 days");
        assert_eq!(view.lines[1].text(), "upstream answers in 9 ms");
        assert_eq!(view.right, RightKey::key("REJOIN", false));
        // How long it has held, in words.
        for (days, said) in [(0, "today"), (1, "1 day"), (2, "2 days")] {
            let mut w = world(Still::Wifi);
            w.link.linked_days = Some(days);
            assert!(WifiView::of(&w).lines[0].text().ends_with(said), "{days}");
        }
        // The Pi may know none of it: dashes in G3, no zero.
        let mut w = world(Still::Wifi);
        w.link = crate::os::world::Link::default();
        let view = WifiView::of(&w);
        assert_eq!(view.caption.text(), format!("WI-FI \u{b7} {DASH}"));
        assert_eq!(view.word.text(), "GOOD".replace("GOOD", DASH));
        assert_eq!(
            view.lines[0].text(),
            format!("signal {DASH} dBm \u{b7} linked {DASH}")
        );
        assert_eq!(view.lines[1].text(), format!("upstream answers in {DASH}"));
        assert_eq!(view.dashes, 0);
        let mut canvas = Canvas::new();
        draw_wifi(&mut canvas, &view);
        // The unknown band is a dash in G3 in the caption: `WI-FI · ` is G2.
        assert!(any(&canvas, (150, 96, 180, 16), G3));
        assert!(any(&canvas, (150, 96, 180, 16), G2));
        assert!(
            any(&canvas, (190, 142, 100, 24), G3),
            "the word's dash is G3"
        );
    }

    #[test]
    fn wi_fi_is_joining_with_every_dash_dark_and_no_motion() {
        let mut w = world(Still::Wifi);
        w.rejoin = Rejoin::Joining;
        w.wifi_joined = false;
        let view = WifiView::of(&w);
        assert_eq!((view.dashes, view.word.text().as_str()), (0, "JOINING"));
        assert_eq!(view.lines[0].text(), "letting go and taking hold again");
        assert_eq!(view.right, RightKey::Inert("WAIT"));
        let mut canvas = Canvas::new();
        draw_wifi(&mut canvas, &view);
        for i in 0..10 {
            assert!(is(&canvas, 132 + 22 * i, 119, G4), "dash {i} is dark");
        }
        // The same world draws the same, frame after frame: nothing in it moves.
        let mut again = Canvas::new();
        draw_wifi(&mut again, &WifiView::of(&w));
        assert_eq!(canvas.rgba(), again.rgba());
        // The link back, the refusal still on: `WAIT`, the dashes lit again.
        w.rejoin = Rejoin::Wait(40);
        w.wifi_joined = true;
        let back = WifiView::of(&w);
        assert_eq!((back.dashes, back.word.text().as_str()), (9, "GOOD"));
        assert_eq!(back.right, RightKey::Inert("WAIT"));
    }

    #[test]
    fn rejoin_is_a_key_wait_during_the_refusal_and_inert_while_an_update_runs() {
        let (nav, mut w) = at(Still::Wifi);
        // BACK goes back to the mimic; REJOIN asks for it and the panel stays.
        assert_eq!(decide(&nav, &w, 100, 280), Tap::Nav(Change::Back));
        assert_eq!(decide(&nav, &w, 400, 280), Tap::Act(Intent::Rejoin, None));
        assert!(!Intent::Rejoin.is_strong(), "REJOIN never asks for the PIN");
        // Above the floor there is nothing to press.
        assert_eq!(decide(&nav, &w, 400, 150), Tap::None);
        // The control's refusal: `WAIT`, G3 and inert.
        w.rejoin = Rejoin::Wait(30);
        assert_eq!(WifiView::of(&w).right, RightKey::Inert("WAIT"));
        assert_eq!(decide(&nav, &w, 400, 280), Tap::None);
        assert_eq!(decide(&nav, &w, 100, 280), Tap::Nav(Change::Back));
        // An update received or on trial: the key is inert, its word kept.
        w.rejoin = Rejoin::Idle;
        w.update_busy = true;
        assert_eq!(WifiView::of(&w).right, RightKey::Inert("REJOIN"));
        assert_eq!(decide(&nav, &w, 400, 280), Tap::None);
        // An inert key is a dim outline, not a white key.
        let mut canvas = Canvas::new();
        draw_wifi(&mut canvas, &WifiView::of(&w));
        assert!(is(&canvas, 300, 240, G4) && !any(&canvas, (250, 242, 220, 60), WHITE));
        assert!(any(&canvas, (250, 262, 220, 22), G3));
        // The refusal outranks the update in what the key says.
        w.rejoin = Rejoin::Wait(5);
        assert_eq!(WifiView::of(&w).right, RightKey::Inert("WAIT"));
    }

    // ---- the plain readings ----

    #[test]
    fn version_says_what_runs_and_how_the_last_update_ended_and_has_back_only() {
        let view = ReadingView::version(&world(Still::Version));
        assert_eq!(
            (view.label, view.figure.text().as_str()),
            ("VERSION", "0.4.1")
        );
        assert_eq!(view.lines[0].text(), "built 2026-11-12 \u{b7} slot A");
        assert_eq!(view.lines[1].text(), "last update: confirmed");
        assert_eq!((view.left, view.right), ("BACK", RightKey::None));
        let mut w = world(Still::Version);
        w.machine.last_update = LastUpdate::RolledBack;
        assert_eq!(
            ReadingView::version(&w).lines[1].text(),
            "last update: rolled back"
        );
        w.machine.last_update = LastUpdate::None;
        assert_eq!(
            ReadingView::version(&w).lines[1].text(),
            "last update: none since start"
        );
        // No CHECK NOW: the right half of the floor is black and no press there does anything.
        let mut canvas = Canvas::new();
        draw_reading(&mut canvas, &ReadingView::version(&world(Still::Version)));
        assert!((244..472).all(|x| (237..304).all(|y| is(&canvas, x, y, GROUND))));
        let (nav, world) = at(Still::Version);
        assert_eq!(decide(&nav, &world, 400, 280), Tap::None);
        assert_eq!(decide(&nav, &world, 100, 280), Tap::Nav(Change::Back));
        // Nothing known: dashes.
        let blank = ReadingView::version(&World::default());
        assert_eq!(blank.figure.text(), DASH);
        assert_eq!(
            blank.lines[0].text(),
            format!("built {DASH} \u{b7} slot {DASH}")
        );
    }

    #[test]
    fn up_says_the_uptime_the_load_and_the_last_restart_with_a_strong_restart() {
        let view = ReadingView::uptime(&world(Still::Uptime));
        assert_eq!(
            (view.label, view.figure.text().as_str()),
            ("UP", "12 D 4 H")
        );
        assert_eq!(
            view.lines[0].text(),
            "load 0.21 \u{b7} memory 38% \u{b7} 47 \u{b0}C"
        );
        assert_eq!(view.lines[1].text(), "last restart: the update to 0.4.1");
        assert_eq!(view.right, RightKey::key("RESTART", false));
        let (nav, mut w) = at(Still::Uptime);
        assert_eq!(decide(&nav, &w, 400, 280), Tap::Act(Intent::Restart, None));
        assert!(Intent::Restart.is_strong());
        assert_eq!(decide(&nav, &w, 100, 280), Tap::Nav(Change::Back));
        // Without hours the figure is the days alone; without days it is a dash.
        w.machine.uptime_hours = None;
        assert_eq!(ReadingView::uptime(&w).figure.text(), "12 D");
        w.uptime_days = None;
        w.machine.uptime_hours = Some(4);
        assert_eq!(ReadingView::uptime(&w).figure.text(), DASH);
        // An update received or on trial: RESTART is inert, its word kept.
        let mut busy = world(Still::Uptime);
        busy.update_busy = true;
        assert_eq!(ReadingView::uptime(&busy).right, RightKey::Inert("RESTART"));
        assert_eq!(decide(&nav, &busy, 400, 280), Tap::None);
        // The cause is cut to its place and a missing one is a dash.
        let mut long = world(Still::Uptime);
        long.machine.last_restart = "x".repeat(60);
        let line = ReadingView::uptime(&long).lines[1].text();
        assert_eq!(
            line.chars().count(),
            "last restart: ".len() + crate::os::world::RESTART_CAUSE_CELLS
        );
        assert!(7.0 + 10.8 * line.chars().count() as f32 <= 480.0, "{line}");
        long.machine.last_restart.clear();
        assert_eq!(
            ReadingView::uptime(&long).lines[1].text(),
            format!("last restart: {DASH}")
        );
        let blank = ReadingView::uptime(&World::default());
        assert_eq!(
            blank.lines[0].text(),
            format!("load {DASH} \u{b7} memory {DASH} \u{b7} {DASH}")
        );
    }

    #[test]
    fn lock_says_on_or_off_where_the_pin_lives_and_offers_the_right_key() {
        let off = ReadingView::lock(&world(Still::Lock));
        assert_eq!((off.label, off.figure.text().as_str()), ("LOCK", "OFF"));
        assert_eq!(
            (off.left, off.right),
            ("KEEP OFF", RightKey::key("SET A PIN", false))
        );
        let (nav, mut w) = at(Still::Lock);
        assert_eq!(decide(&nav, &w, 100, 280), Tap::Nav(Change::Back));
        assert_eq!(decide(&nav, &w, 400, 280), Tap::Nav(Change::ChoosePin));
        // With the lock on: KEEP ON and TURN OFF, strong, with the padlock.
        w.lock_on = true;
        let on = ReadingView::lock(&w);
        assert_eq!((on.label, on.figure.text().as_str()), ("LOCK", "ON"));
        assert_eq!(
            (on.left, on.right),
            ("KEEP ON", RightKey::key("TURN OFF", true))
        );
        assert_eq!(decide(&nav, &w, 400, 280), Tap::Act(Intent::ClearPin, None));
        assert!(Intent::ClearPin.is_strong());
        // Where the PIN lives is the second line (spec §7.2), and whether the card keeps it.
        for (kept, expected) in [
            (
                false,
                [
                    (
                        LockSource::Config,
                        "kept in the config: it outlasts a restart",
                    ),
                    (LockSource::Api, "from the desktop: until the next restart"),
                    (LockSource::Panel, "set here: until the next restart"),
                ],
            ),
            (
                true,
                [
                    (
                        LockSource::Config,
                        "kept in the config: it outlasts a restart",
                    ),
                    (LockSource::Api, "from the desktop: it outlasts a restart"),
                    (LockSource::Panel, "set here: it outlasts a restart"),
                ],
            ),
        ] {
            w.lock_kept = kept;
            for (source, said) in expected {
                w.lock_source = source;
                let view = ReadingView::lock(&w);
                assert_eq!(view.lines[1].text(), said);
                assert!(said.chars().count() <= 43, "{said}");
                assert!(view.lines[0].text().chars().count() <= 43);
            }
        }
        // With the lock off the second line says how long a PIN set here would last.
        w.lock_on = false;
        for (kept, said) in [
            (false, "a PIN set here lasts until a restart"),
            (true, "a PIN set here outlasts a restart"),
        ] {
            w.lock_kept = kept;
            let view = ReadingView::lock(&w);
            assert_eq!(view.lines[1].text(), said);
            assert!(said.chars().count() <= 43, "{said}");
            assert!(view.lines[0].text().chars().count() <= 43);
        }
    }

    #[test]
    fn a_strong_key_wears_the_padlock_only_while_the_lock_is_on() {
        let draw = |view: &ReadingView| {
            let mut canvas = Canvas::new();
            draw_reading(&mut canvas, view);
            canvas
        };
        // The same key with and without the padlock: the lock stands left of the word, 16 wide from x 293.6 for
        // `RESTART`, and the word moves 12 px right.
        let lock_ink = |canvas: &Canvas| {
            (294..307)
                .flat_map(|x| (262..281).map(move |y| (x, y)))
                .filter(|&(x, y)| is(canvas, x, y, GROUND))
                .count()
        };
        let plain = draw(&ReadingView::uptime(&world(Still::Uptime)));
        let mut w = world(Still::Uptime);
        w.lock_on = true;
        let locked = draw(&ReadingView::uptime(&w));
        assert_eq!(lock_ink(&plain), 0);
        assert!(lock_ink(&locked) > 120, "{}", lock_ink(&locked));
        // TURN OFF is strong: with the lock on (and it is only offered then) it wears the padlock.
        let off = ReadingView::lock(&w);
        assert!(off.right.locked());
        let mut bare = off.clone();
        bare.right = RightKey::key("TURN OFF", false);
        assert_ne!(draw(&off).rgba(), draw(&bare).rgba());
        // SET A PIN is offered while the lock is off, and wears none.
        let set = ReadingView::lock(&world(Still::Lock));
        assert!(!set.right.locked());
        // An inert RESTART wears none, with the lock on: a dim outline and its word in G3.
        w.update_busy = true;
        let inert = draw(&ReadingView::uptime(&w));
        assert!(any(&inert, (250, 262, 220, 22), G3), "its word in G3");
        assert!(is(&inert, 300, 240, G4) && !any(&inert, (250, 242, 220, 60), WHITE));
        // VERSION has no key to wear one.
        assert_eq!(ReadingView::version(&w).right, RightKey::None);
        // Only the intents that are strong are keys that may wear it: RESTART and TURN OFF.
        assert!(Intent::Restart.is_strong() && Intent::ClearPin.is_strong());
        assert!(!Intent::Rejoin.is_strong() && !Intent::SleepNow.is_strong());
    }

    #[test]
    fn about_keeps_its_second_line_and_the_version_fits() {
        let about = AboutView::of(&world(Still::About));
        assert_eq!(
            about.line,
            "version 0.4.1 on a Pi 3B+ \u{b7} panel 480\u{d7}320"
        );
        assert_eq!(about.lane.words, "SYSTEM");
        let mut long = world(Still::About);
        long.version = "0.4.1-release-candidate".to_string();
        let line = AboutView::of(&long).line;
        assert!(line.contains("0.4.1-~"), "{line}");
        // 18 px letters are 10.8 px wide, from x 7: the line ends inside the 480.
        assert!(7.0 + 10.8 * line.chars().count() as f32 <= 480.0, "{line}");
        assert_eq!(
            AboutView::of(&World::default()).line,
            format!("version {DASH} on a Pi 3B+ \u{b7} panel 480\u{d7}320")
        );
    }

    #[test]
    fn about_has_its_label_its_figure_its_two_lines_and_back() {
        let mut canvas = Canvas::new();
        draw_about(&mut canvas, &AboutView::of(&world(Still::About)));
        let brightest = |x0, x1, y0, y1| {
            (y0..y1)
                .flat_map(|y| (x0..x1).map(move |x| (x, y)))
                .filter_map(|(x, y)| canvas.pixel(x, y))
                .map(|p| p[0])
                .max()
                .unwrap_or(0)
        };
        assert_eq!(brightest(0, 480, 120, 172), 255, "the figure, white");
        assert_eq!(brightest(0, 480, 190, 206), G1[0], "the first line, G1");
        assert_eq!(canvas.pixel(8, 240), Some(WHITE), "BACK's frame");
        assert_eq!(brightest(244, 472, 240, 304), 0, "no right key");
    }

    // ---- NIGHT HOURS ----

    #[test]
    fn night_hours_shows_the_two_hours_and_a_draft_over_them() {
        let (nav, w) = at(Still::NightHours);
        let view = NightView::of(&w, nav.night_draft());
        assert_eq!((view.from, view.to), (23, 7));
        let draft = NightView::of(&w, Some((22, 6)));
        assert_eq!((draft.from, draft.to), (22, 6));
        // No night: both hours equal, and the second label says so.
        let mut none = w.clone();
        none.night = None;
        let view = NightView::of(&none, None);
        assert_eq!(view.from, view.to);
        let mut canvas = Canvas::new();
        draw_night(&mut canvas, &view);
        let mut plain = Canvas::new();
        draw_night(&mut plain, &NightView::of(&w, None));
        assert_ne!(canvas.rgba(), plain.rgba());
        // `UNTIL · NEVER DARK` is longer than `UNTIL`: ink right of where `UNTIL` ends (6.4 + 5 * 12.1 = 67).
        assert!(any(&canvas, (80, 166, 150, 16), G2));
        assert!(!any(&plain, (80, 166, 150, 16), G2));
    }

    #[test]
    fn the_minus_and_plus_keys_change_one_hour_of_the_draft_and_done_sets_it() {
        let (mut nav, w) = at(Still::NightHours);
        // `-` of FROM (x 292 to 385, above y 160): 22. `+` of FROM: 0 (past 23). `-` of TO: 6. `+` of TO: 8.
        assert_eq!(tap(&mut nav, &w, 340, 116), None);
        assert_eq!(nav.night_draft(), Some((22, 7)));
        assert_eq!(tap(&mut nav, &w, 430, 116), None);
        assert_eq!(nav.night_draft(), Some((23, 7)));
        assert_eq!(tap(&mut nav, &w, 430, 116), None);
        assert_eq!(nav.night_draft(), Some((0, 7)), "23 + 1 is midnight");
        assert_eq!(tap(&mut nav, &w, 340, 196), None);
        assert_eq!(nav.night_draft(), Some((0, 6)));
        assert_eq!(tap(&mut nav, &w, 430, 196), None);
        assert_eq!(tap(&mut nav, &w, 430, 196), None);
        assert_eq!(nav.night_draft(), Some((0, 8)));
        // Nothing is set until DONE, which sets it and goes back to the mimic.
        let view = NightView::of(&w, nav.night_draft());
        assert_eq!((view.from, view.to), (0, 8));
        assert_eq!(
            tap(&mut nav, &w, 400, 280),
            Some(Intent::NightHours { from: 0, to: 8 })
        );
        assert_eq!((nav.root(), nav.stack().len()), (Section::System, 0));
        assert_eq!(nav.night_draft(), None);
        assert!(!Intent::NightHours { from: 0, to: 8 }.is_strong());
        // `-` below 0 wraps to 23; the first press of `-` on the hour 0 starts there.
        let mut w0 = world(Still::NightHours);
        w0.night = Some((0, 8));
        let mut nav = Still::NightHours.nav(&w0);
        assert_eq!(tap(&mut nav, &w0, 340, 116), None);
        assert_eq!(nav.night_draft(), Some((23, 8)));
        // Left of x 292 and between the rows' keys is nothing; the lane is the lane.
        assert_eq!(decide(&nav, &w0, 100, 116), Tap::None);
        assert_eq!(decide(&nav, &w0, 291, 116), Tap::None);
    }

    #[test]
    fn done_with_nothing_changed_only_goes_back_and_a_draft_dies_with_the_screen() {
        let (mut nav, w) = at(Still::NightHours);
        assert_eq!(tap(&mut nav, &w, 400, 280), None, "no change, no intent");
        assert_eq!((nav.root(), nav.stack().len()), (Section::System, 0));
        // A change that is put back is no change.
        let (mut nav, w) = at(Still::NightHours);
        tap(&mut nav, &w, 340, 116);
        tap(&mut nav, &w, 430, 116);
        assert_eq!(nav.night_draft(), Some((23, 7)));
        assert_eq!(tap(&mut nav, &w, 400, 280), None);
        // The lane's HOME and the idle minute throw the draft away; so does a fresh opening.
        let (mut nav, w) = at(Still::NightHours);
        tap(&mut nav, &w, 340, 116);
        assert_eq!(tap(&mut nav, &w, 10, 40), None);
        assert!(nav.is_home() && nav.night_draft().is_none());
        let (mut nav, w) = at(Still::NightHours);
        tap(&mut nav, &w, 340, 116);
        assert!(crate::os::nav::idle(&mut nav, crate::os::nav::IDLE_MS));
        assert!(nav.night_draft().is_none());
        let (mut nav, w) = at(Still::System);
        nav.open(Screen::NightHours);
        assert_eq!(tap(&mut nav, &w, 340, 116), None);
        nav.back();
        nav.open(Screen::NightHours);
        assert_eq!(
            nav.night_draft(),
            None,
            "a screen opened again starts from the world's hours"
        );
        // A `Change::Hours` while another screen shows is ignored.
        let (mut nav, _) = at(Still::Lock);
        nav.apply(Change::Hours(1, 2));
        assert_eq!(nav.night_draft(), None);
        // Equal hours are no night, and DONE sets them: from == to is how the panel says OFF.
        let (mut nav, w) = at(Still::NightHours);
        for _ in 0..16 {
            tap(&mut nav, &w, 430, 196);
        }
        assert_eq!(nav.night_draft(), Some((23, 23)));
        assert_eq!(
            tap(&mut nav, &w, 400, 280),
            Some(Intent::NightHours { from: 23, to: 23 })
        );
    }

    #[test]
    fn sleep_now_is_an_intent_that_changes_nothing_on_the_panel() {
        let (mut nav, w) = at(Still::NightHours);
        assert_eq!(tap(&mut nav, &w, 100, 280), Some(Intent::SleepNow));
        assert_eq!(nav.stack(), [Screen::NightHours]);
        assert!(!Intent::SleepNow.is_strong());
    }

    #[test]
    fn set_a_pin_opens_the_pad_over_lock_to_choose_one_and_cancel_goes_back_to_it() {
        use crate::os::nav::{PinGoal, Whole};
        let (mut nav, w) = at(Still::Lock);
        assert_eq!(tap(&mut nav, &w, 400, 280), None);
        assert_eq!(nav.whole(), Some(Whole::Pin));
        assert!(matches!(
            nav.pin().map(|pad| pad.goal()),
            Some(PinGoal::Choose)
        ));
        assert_eq!(nav.stack(), [Screen::Lock], "LOCK is under the pad");
        // CANCEL leaves the pad, and LOCK is as it was.
        let cancel = crate::os::screens::whole::pad_rect(9);
        assert_eq!(tap(&mut nav, &w, cancel.x + 45, cancel.y + 25), None);
        assert_eq!((nav.whole(), nav.stack()), (None, &[Screen::Lock][..]));
    }

    #[test]
    fn every_reading_goes_back_to_the_mimic_by_its_left_key_and_none_pops_by_itself() {
        for still in [
            Still::Version,
            Still::Wifi,
            Still::Uptime,
            Still::NightHours,
            Still::Lock,
            Still::About,
        ] {
            let (mut nav, w) = at(still);
            assert!(!refresh(&mut nav, &w), "{still:?}: a reading is never gone");
            assert_eq!(nav.stack().len(), 1);
            // NIGHT HOURS' left key is SLEEP NOW; the rest is BACK.
            if still != Still::NightHours {
                assert_eq!(tap(&mut nav, &w, 100, 280), None, "{still:?}");
                assert_eq!(
                    (nav.root(), nav.stack().len()),
                    (Section::System, 0),
                    "{still:?}"
                );
            }
            // The slab area above the floor is nothing, on every one of them but the keys of NIGHT HOURS.
            let (nav, w) = at(still);
            assert_eq!(decide(&nav, &w, 100, 150), Tap::None, "{still:?}");
        }
    }

    #[test]
    fn debug_says_no_figure_that_is_private() {
        // Nothing here is a name or an address, but the screens keep to the rule: a Screen says its kind.
        let said = format!("{:?}", [Screen::Version, Screen::Wifi, Screen::NightHours]);
        assert!(said.contains("Version") && said.contains("NightHours"));
        assert!(Band::Ghz5.word().is_ascii());
    }
}
