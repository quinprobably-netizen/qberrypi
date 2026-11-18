//! DEVICES (spec §3.4, `devicesScreen`, `deviceScreen`, `flipScreen`, `pauseScreen`): the wall of the house's
//! devices, one device's screen, the confirm before its ads change, and the choices for its own gate.
//!
//! - **The wall** is twelve places, 110 by 70, four across and three down. A device is a tile: blue when its
//!   ads are blocked (and for the router and the Pi, which always are), a hollow `G3` frame when ads pass,
//!   a hollow white one while its own gate is open (`OPEN m:ss`). The name stands in up to two 16 px lines,
//!   or as `·octet` in 24 px for a device with no name, over its state's word, with a lamp at the top
//!   right. The first empty place says `NEW ONES` and what a newcomer gets. With more than twelve devices
//!   the wall pages: eleven to a page and a twelfth place, `MORE · n`, that turns the page.
//! - **DEVICE** is its name, the last two names it asked (while the screen is open, spec §6.2), its state as
//!   the floor's left key and its own gate as the right one. A name row opens NAME, by the name's whole text.
//! - **CONFIRM** is the slab drawn as the state the device would take, over `KEEP …` and the change.
//! - **ITS GATE** is the slab `OPEN ITS GATE` over GATE's four keys.
//!
//! Every screen is a view, a small value of exactly what it draws with its words fitted; the views hold
//! names and print none of them in `Debug`. The taps are here too, as the functions `nav::decide` calls.

use crate::format;
use crate::geometry::Rect;
use crate::os::intent::Intent;
use crate::os::nav::{Change, Screen, Section, Tap};
use crate::os::screens::gate;
use crate::os::screens::lane::{self, LaneView};
use crate::os::screens::parts::{self, SlabLine};
use crate::os::world::{DeviceRow, DeviceState, MAX_WATCHED, Mac, Newcomer, Outcome, World};
use crate::ui::canvas::{Canvas, Face};
use crate::ui::look::{
    BLUE, BLUE_DEEP, BLUE_DK, BLUE_LT, BLUE_MD, BLUE_NIGHT, FLOOR_SPLIT_X, FLOOR_Y, G1, G2, G3, G4,
    GROUND, KEY_H, KEY_W2, KEY_X2, KEY_Y, WALL_COLUMNS, WALL_H, WALL_HIT_X0, WALL_HIT_Y0,
    WALL_PITCH_X, WALL_PITCH_Y, WALL_PLACES, WALL_W, WALL_X0, WALL_Y0, WHITE,
};

/// How many devices a page of the wall holds when it pages: the twelfth place is the page turner.
pub const PAGE_DEVICES: usize = WALL_PLACES - 1;

/// How many rows of places the wall has.
const WALL_ROWS: usize = WALL_PLACES / WALL_COLUMNS;

/// A tile's name breaks into two lines at a space within this many cells (`wrapWords(…, 10)`).
const WRAP_CELLS: usize = 10;

/// A device's name on its own screen is set smaller past this many letters: 30 px instead of 40.
const BIG_NAME_LETTERS: usize = 15;

/// The rows of the watched names: the first row's top, and the distance between two.
const NAME_ROW_Y0: u16 = 132;
/// See `NAME_ROW_Y0`.
const NAME_ROW_PITCH: u16 = 52;

// ---------------------------------------------------------------------------------------------
// What a device looks like in miniature, shared with HOME's mini wall.

/// One place of a miniature wall of devices (HOME's DEVICES tile).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    /// No device here: a small dot.
    Empty,
    /// A device that is asking now: white.
    Asking,
    /// Ads pass on it, or its gate is open: a hollow `G2` place.
    Pass,
    /// Ads are blocked for it (and the router and the Pi, which always are): blue.
    Blocked,
}

/// How many places a miniature wall has.
pub const MINI_PLACES: usize = 12;

impl Place {
    /// What a device is in miniature: white while it asks, else by its state, as its tile on the wall is.
    pub const fn of(row: &DeviceRow) -> Self {
        if row.asking {
            Self::Asking
        } else {
            match row.state {
                DeviceState::AdsPass | DeviceState::Open { .. } => Self::Pass,
                DeviceState::Blocked | DeviceState::Always => Self::Blocked,
            }
        }
    }
}

/// The miniature wall of a list of devices: the first twelve, in the wall's order.
pub fn mini_places(rows: &[DeviceRow]) -> [Place; MINI_PLACES] {
    let mut places = [Place::Empty; MINI_PLACES];
    for (place, row) in places.iter_mut().zip(rows) {
        *place = Place::of(row);
    }
    places
}

// ---------------------------------------------------------------------------------------------
// The wall.

/// What stands in a place of the wall, before it is made into a view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    /// The device at this index of the world's list.
    Device(usize),
    /// `NEW ONES`: where a newcomer will land.
    NewOnes,
    /// The page turner, with how many devices are not on this page.
    More(usize),
    /// Nothing: a small dot.
    Empty,
}

/// How many pages the wall has for this many devices: one while they fit its twelve places, else pages of eleven.
pub const fn pages(devices: usize) -> usize {
    if devices <= WALL_PLACES {
        1
    } else {
        devices.div_ceil(PAGE_DEVICES)
    }
}

/// A page number that exists for this many devices: a wall that shrank under a page that was open has
/// its last page.
pub const fn clamp_page(page: usize, devices: usize) -> usize {
    let last = pages(devices) - 1;
    if page > last { last } else { page }
}

/// The twelve places of a page of the wall for this many devices.
///
/// They are the devices in the world's order, which is stable so that a tile never moves while the screen
/// shows. The first empty place says `NEW ONES`. When the devices do not fit twelve places they page: eleven
/// to a page, and the twelfth place on every page is `MORE · n`, `n` being the devices that are not on this
/// page; it turns to the next page, and from the last back to the first.
pub fn layout(devices: usize, page: usize) -> [Slot; WALL_PLACES] {
    let mut slots = [Slot::Empty; WALL_PLACES];
    if devices <= WALL_PLACES {
        for (i, slot) in slots.iter_mut().enumerate() {
            *slot = match i.cmp(&devices) {
                std::cmp::Ordering::Less => Slot::Device(i),
                std::cmp::Ordering::Equal => Slot::NewOnes,
                std::cmp::Ordering::Greater => Slot::Empty,
            };
        }
        return slots;
    }
    let start = clamp_page(page, devices) * PAGE_DEVICES;
    let shown = PAGE_DEVICES.min(devices - start);
    for (i, slot) in slots.iter_mut().take(PAGE_DEVICES).enumerate() {
        *slot = match i.cmp(&shown) {
            std::cmp::Ordering::Less => Slot::Device(start + i),
            std::cmp::Ordering::Equal => Slot::NewOnes,
            std::cmp::Ordering::Greater => Slot::Empty,
        };
    }
    slots[WALL_PLACES - 1] = Slot::More(devices - shown);
    slots
}

/// A name on at most two lines of `max` cells, broken at the last space within them (`wrapWords`): a name
/// that fits is one line; one with no space to break at is cut with a `~`; the second line is cut too.
fn wrap_words(name: &str, max: usize) -> [String; 2] {
    let chars: Vec<char> = name.chars().collect();
    if chars.len() <= max {
        return [name.to_string(), String::new()];
    }
    match chars.iter().take(max + 1).rposition(|&c| c == ' ') {
        Some(cut) if cut >= 1 => [
            chars[..cut].iter().collect(),
            format::fit_text(&chars[cut + 1..].iter().collect::<String>(), max),
        ],
        _ => [format::fit_text(name, max), String::new()],
    }
}

/// One device's tile as it is on the glass.
#[derive(Clone, PartialEq, Eq)]
pub struct TileView {
    /// Where ads stand on the device; an open gate carries the seconds it has left, which the tile counts.
    pub state: DeviceState,
    /// The name in up to two lines; a device with no name has its `·octet` in the first.
    pub lines: [String; 2],
    /// Whether the name is the `·octet` of a device with none: 24 px, on one line.
    pub octet: bool,
    /// Whether the device is asking now: the lamp.
    pub asking: bool,
}

impl std::fmt::Debug for TileView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TileView")
            .field("state", &self.state)
            .field("asking", &self.asking)
            .finish_non_exhaustive()
    }
}

impl TileView {
    /// The tile of a device.
    pub fn of(row: &DeviceRow) -> Self {
        let (lines, octet) = if row.named {
            (wrap_words(&row.name, WRAP_CELLS), false)
        } else {
            ([row.name.clone(), String::new()], true)
        };
        Self {
            state: row.state,
            lines,
            octet,
            asking: row.asking,
        }
    }

    /// The tile's state word, in capitals: `ADS PASS`, `BLOCKED`, `ALWAYS`, `OPEN m:ss`.
    pub fn word(&self) -> String {
        match self.state {
            DeviceState::AdsPass => "ADS PASS".to_string(),
            DeviceState::Blocked => "BLOCKED".to_string(),
            DeviceState::Always => "ALWAYS".to_string(),
            DeviceState::Open { left_secs } => format!("OPEN {}", format::mss(left_secs)),
        }
    }
}

/// What a place of the wall holds, as it is drawn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seat {
    /// A device.
    Device(TileView),
    /// `NEW ONES`, and what a newcomer gets.
    NewOnes(Newcomer),
    /// `MORE · n`.
    More(usize),
    /// Nothing.
    Empty,
}

/// What DEVICES puts on the glass.
#[derive(Clone, PartialEq, Eq)]
pub struct WallView {
    /// The lane, which says `DEVICES`.
    pub lane: LaneView,
    /// The twelve places, row by row.
    pub seats: Vec<Seat>,
}

impl std::fmt::Debug for WallView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WallView")
            .field("seats", &self.seats.len())
            .finish_non_exhaustive()
    }
}

impl WallView {
    /// What a page of the wall shows for a world.
    pub fn of(world: &World, page: usize) -> Self {
        let seats = layout(world.devices.len(), page)
            .iter()
            .map(|slot| match *slot {
                Slot::Device(i) => world
                    .devices
                    .get(i)
                    .map_or(Seat::Empty, |row| Seat::Device(TileView::of(row))),
                Slot::NewOnes => Seat::NewOnes(world.newcomer),
                Slot::More(n) => Seat::More(n),
                Slot::Empty => Seat::Empty,
            })
            .collect();
        Self {
            lane: LaneView::of(Section::Devices, world),
            seats,
        }
    }
}

/// The place `i` of the wall (`DVT`): 110 by 70 at `x 8 + 118·col, y 80 + 77·row`.
pub fn place_rect(i: usize) -> Rect {
    let (col, row) = (i % WALL_COLUMNS, i / WALL_COLUMNS);
    Rect::new(
        WALL_X0 + u16::try_from(col).unwrap_or(0) * WALL_PITCH_X,
        WALL_Y0 + u16::try_from(row).unwrap_or(0) * WALL_PITCH_Y,
        WALL_W,
        WALL_H,
    )
}

/// The place a press at `(x, y)` is on: the mockup's `floor((y - 76) / 77) * 4 + floor((x - 4) / 118)`, with
/// the last column and the last row going on to the screen's edge as HOME's tiles do (the mockup's last
/// column wraps to the next row's first place). `None` above y 76.
pub fn place_hit(x: u16, y: u16) -> Option<usize> {
    if y < WALL_HIT_Y0 {
        return None;
    }
    let row = usize::from((y - WALL_HIT_Y0) / WALL_PITCH_Y).min(WALL_ROWS - 1);
    let col = usize::from(x.saturating_sub(WALL_HIT_X0) / WALL_PITCH_X).min(WALL_COLUMNS - 1);
    Some(row * WALL_COLUMNS + col)
}

/// The wall's taps (`tapOS`, the `devices` branch): a device's tile opens DEVICE; the page turner turns the
/// page; `NEW ONES` and the empty places are nothing.
pub fn wall_tap(page: usize, world: &World, x: u16, y: u16) -> Tap {
    let Some(place) = place_hit(x, y) else {
        return Tap::None;
    };
    let devices = world.devices.len();
    match layout(devices, page)[place] {
        Slot::Device(i) => world.devices.get(i).map_or(Tap::None, |row| {
            Tap::Nav(Change::Open(Screen::Device(row.mac)))
        }),
        Slot::More(_) => Tap::Nav(Change::DevicesPage(
            (clamp_page(page, devices) + 1) % pages(devices),
        )),
        Slot::NewOnes | Slot::Empty => Tap::None,
    }
}

/// Draws the wall: the lane and the twelve places.
pub fn draw_wall(canvas: &mut Canvas, view: &WallView) {
    lane::draw(canvas, &view.lane);
    for (i, seat) in view.seats.iter().enumerate() {
        let r = place_rect(i);
        let (x, y) = (f32::from(r.x), f32::from(r.y));
        match seat {
            Seat::Device(tile) => draw_tile(canvas, r, tile),
            Seat::NewOnes(newcomer) => {
                // The default, where a newcomer will land.
                canvas.text("NEW ONES", x + 7.0, y + 22.0, Face::bold(16.0, G3));
                canvas.text(newcomer.word(), x + 7.0, y + 40.0, Face::bold(16.0, G3));
            }
            Seat::More(n) => {
                canvas.rect(r, G4);
                canvas.text(
                    &format!("MORE \u{b7} {n}"),
                    x + f32::from(r.w) / 2.0,
                    y + 41.0,
                    Face::bold(16.0, G1).mid(),
                );
            }
            Seat::Empty => canvas.dot(x + 55.0, y + 35.0, 2.5, BLUE_DEEP),
        }
    }
}

/// Draws one device's tile (`deviceTile`).
fn draw_tile(canvas: &mut Canvas, r: Rect, tile: &TileView) {
    let gate_open = matches!(tile.state, DeviceState::Open { .. });
    let open = gate_open || tile.state == DeviceState::AdsPass;
    if gate_open {
        canvas.hollow(r, WHITE, 2, GROUND);
    } else if open {
        canvas.hollow(r, G3, 2, GROUND);
    } else {
        canvas.rect(r, BLUE);
    }
    let ink = if open { G1 } else { WHITE };
    let (x, y) = (f32::from(r.x), f32::from(r.y));
    if tile.octet {
        canvas.text(&tile.lines[0], x + 4.0, y + 30.0, Face::bold(24.0, ink));
    } else {
        for (k, line) in tile.lines.iter().enumerate() {
            canvas.text(
                line,
                x + 7.0,
                y + 22.0 + 18.0 * k as f32,
                Face::bold(16.0, ink),
            );
        }
    }
    let word = tile.word();
    let word_ink = if gate_open {
        WHITE
    } else if open {
        G2
    } else {
        BLUE_NIGHT
    };
    // `OPEN 30:00` is ten letters, and with the mockup's one pixel of tracking it would run onto the frame.
    let tracking = if word.chars().count() > 9 { 0.0 } else { 1.0 };
    canvas.text(
        &word,
        x + 7.0,
        y + 61.0,
        Face::bold(16.0, word_ink).track(tracking),
    );
    // The lamp: white while the device asks (the mockup's r 6 is the first quarter second of an ask, which a
    // reading once a second cannot show), else a small dot.
    let (lx, ly) = (x + f32::from(r.w) - 13.0, y + 13.0);
    if tile.asking {
        canvas.dot(lx, ly, 5.0, WHITE);
    } else {
        canvas.dot(lx, ly, 2.5, if open { BLUE_DEEP } else { BLUE_MD });
    }
}

// ---------------------------------------------------------------------------------------------
// What may be done to a device, and when a screen about one is no longer true.

/// The state a device would take if its key were pressed: `Some(true)` to let ads pass, `Some(false)` to block
/// them; `None` when the owner does not decide it, because the configuration does (`fixed`) or it is the router
/// or the Pi. A device whose own gate is open is blocked underneath, so its key lets ads pass.
pub fn flip_target(row: &DeviceRow) -> Option<bool> {
    if row.fixed {
        return None;
    }
    match row.state {
        DeviceState::Always => None,
        DeviceState::AdsPass => Some(false),
        DeviceState::Blocked | DeviceState::Open { .. } => Some(true),
    }
}

/// Whether a CONFIRM for `pass` is still true of this device: the owner decides it, and ads are not already
/// in that state. A screen that is not true is popped (`nav::refresh`).
pub fn confirm_valid(world: &World, mac: &Mac, pass: bool) -> bool {
    world
        .device(mac)
        .is_some_and(|row| flip_target(row) == Some(pass))
}

/// Whether ITS GATE is still true of this device: it is on the wall, its ads are blocked and the configuration
/// does not decide that (`fixed`), so its own gate can be opened (an open gate, or ads that pass, leave nothing to
/// open, and the Pi refuses every gate edit of a device the configuration decides: `Devices::open_gate`).
pub fn gate_valid(world: &World, mac: &Mac) -> bool {
    world
        .device(mac)
        .is_some_and(|row| row.state == DeviceState::Blocked && !row.fixed)
}

// ---------------------------------------------------------------------------------------------
// DEVICE.

/// What DEVICE puts on the glass.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceView {
    /// The lane, which says `DEVICES`.
    pub lane: LaneView,
    /// The device's name, 40 px (30 px past 15 letters).
    pub name: String,
    /// Its `·octet` at the right, for a device that has a name; one with none already has it as its name.
    pub octet: Option<String>,
    /// The last names it asked, newest first, at most two, each with what came of it.
    pub names: Vec<(String, Outcome)>,
    /// Where ads stand on it: the state key and the gate key are drawn from this.
    pub state: DeviceState,
    /// Whether the configuration decides its state: the state key says `SET IN CONFIG`.
    pub fixed: bool,
}

impl std::fmt::Debug for DeviceView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceView")
            .field("state", &self.state)
            .field("names", &self.names.len())
            .finish_non_exhaustive()
    }
}

impl DeviceView {
    /// What DEVICE shows for the device with this address: `None` when the world does not hold it, because it
    /// is gone (the nav pops the screen at its next refresh).
    pub fn of(world: &World, mac: &Mac) -> Option<Self> {
        let row = world.device(mac)?;
        Some(Self {
            lane: LaneView::of(Section::Devices, world),
            name: row.name.clone(),
            octet: row.named.then(|| format!("\u{b7}{}", row.octet)),
            names: world
                .watched
                .iter()
                .take(MAX_WATCHED)
                .map(|watched| (watched.name.clone(), watched.outcome))
                .collect(),
            state: row.state,
            fixed: row.fixed,
        })
    }
}

/// The watched name a press at row `y` is on: the rows from `NAME_ROW_Y0`, `NAME_ROW_PITCH` apart, over the
/// floor; `None` above them, on the floor, or on a row that holds no name.
fn name_row_hit(held: usize, y: u16) -> Option<usize> {
    if y >= FLOOR_Y {
        return None;
    }
    let k = usize::from(y.checked_sub(NAME_ROW_Y0)? / NAME_ROW_PITCH);
    (k < MAX_WATCHED && k < held).then_some(k)
}

/// DEVICE's taps: the floor's left key, the device's state, opens CONFIRM (inert for a device the
/// configuration decides and for the router and the Pi); the right key, its own gate, opens ITS GATE when
/// ads are blocked and shuts the gate when it is open; it is inert for what the left key is inert for, as the
/// Pi refuses every gate edit of those. A name row opens NAME with the name's whole text, as a pipe of NAMES
/// does; a row whose whole name is not known, and the waiting line, are no door.
pub fn device_tap(world: &World, mac: Mac, x: u16, y: u16) -> Tap {
    let Some(row) = world.device(&mac) else {
        return Tap::None;
    };
    if y < FLOOR_Y {
        return name_row_hit(world.watched.len(), y)
            .and_then(|k| world.watched.get(k)?.whole.clone())
            .map_or(Tap::None, |name| Tap::Nav(Change::Open(Screen::Name(name))));
    }
    if x < FLOOR_SPLIT_X {
        return flip_target(row).map_or(Tap::None, |pass| {
            Tap::Nav(Change::Open(Screen::Confirm { mac, pass }))
        });
    }
    match row.state {
        // A device the configuration decides has nothing to open: the Pi would refuse it.
        DeviceState::Blocked if !row.fixed => Tap::Nav(Change::Open(Screen::ItsGate(mac))),
        DeviceState::Open { .. } => Tap::Act(Intent::DeviceGate { mac, secs: 0 }, None),
        DeviceState::Blocked | DeviceState::AdsPass | DeviceState::Always => Tap::None,
    }
}

/// Draws DEVICE.
pub fn draw_device(canvas: &mut Canvas, view: &DeviceView) {
    lane::draw(canvas, &view.lane);
    let px = if view.name.chars().count() > BIG_NAME_LETTERS {
        30.0
    } else {
        40.0
    };
    canvas.text(&view.name, 6.0, 116.0, Face::bold(px, WHITE));
    if let Some(octet) = &view.octet {
        canvas.text(octet, 472.0, 116.0, Face::regular(24.0, G2).end());
    }
    for (k, (name, outcome)) in view.names.iter().enumerate() {
        let y = NAME_ROW_Y0 + NAME_ROW_PITCH * u16::try_from(k).unwrap_or(0);
        let square = Rect::new(8, y + 16, 16, 16);
        match outcome {
            Outcome::Refused => canvas.rect(square, BLUE),
            Outcome::Passed => canvas.hollow(square, WHITE, 2, GROUND),
            Outcome::Answered => canvas.rect(square, BLUE_DEEP),
        }
        let ink = if *outcome == Outcome::Answered {
            G1
        } else {
            WHITE
        };
        canvas.text(name, 33.0, f32::from(y) + 32.0, Face::bold(24.0, ink));
        canvas.text(
            outcome.word(),
            472.0,
            f32::from(y) + 30.0,
            Face::bold(16.0, G2).track(2.0).end(),
        );
    }
    if view.names.len() < MAX_WATCHED {
        // Nothing is kept of what it asked before the screen opened: its next name comes in this row.
        let y = NAME_ROW_Y0 + NAME_ROW_PITCH * u16::try_from(view.names.len()).unwrap_or(0);
        canvas.text(
            "waiting for its next name",
            33.0,
            f32::from(y) + 32.0,
            Face::regular(18.0, G3),
        );
    }
    state_key(canvas, view.state, view.fixed);
    gate_key(canvas, view.state, view.fixed);
}

/// The floor's left key (`deviceScreen`): where ads stand on the device. Solid blue when they are blocked,
/// a white frame when they pass, the router's and the Pi's `ALWAYS BLOCKED` in the dark blue, and for a device the
/// configuration decides the same in dimmer inks with `SET IN CONFIG` for its word: it is inert.
fn state_key(canvas: &mut Canvas, state: DeviceState, fixed: bool) {
    let r = Rect::new(8, KEY_Y, KEY_W2, KEY_H);
    // (the frame: solid ground or a hollow frame, the label's ink, the value's ink, the label, the value)
    let (solid, frame, label_ink, value_ink, label, value) = match (state, fixed) {
        (DeviceState::AdsPass, false) => (None, WHITE, G1, WHITE, "ON THIS DEVICE", "ADS PASS"),
        (DeviceState::AdsPass, true) => (None, G3, G2, G1, "ADS PASS", "SET IN CONFIG"),
        (DeviceState::Blocked | DeviceState::Open { .. }, false) => (
            Some(BLUE),
            BLUE,
            BLUE_NIGHT,
            WHITE,
            "ON THIS DEVICE",
            "ADS BLOCKED",
        ),
        (DeviceState::Blocked | DeviceState::Open { .. }, true) => (
            Some(BLUE_DK),
            BLUE_DK,
            BLUE_LT,
            BLUE_LT,
            "ADS BLOCKED",
            "SET IN CONFIG",
        ),
        (DeviceState::Always, _) => (
            Some(BLUE_DK),
            BLUE_DK,
            BLUE_LT,
            BLUE_LT,
            "ON THIS DEVICE",
            "ALWAYS BLOCKED",
        ),
    };
    match solid {
        Some(color) => canvas.rect(r, color),
        None => canvas.hollow(r, frame, 4, GROUND),
    }
    canvas.text(
        label,
        122.0,
        264.0,
        Face::bold(16.0, label_ink).track(2.0).mid(),
    );
    canvas.text(value, 122.0, 292.0, Face::bold(24.0, value_ink).mid());
}

/// The floor's right key (`deviceScreen`): the device's own gate. `OPEN A WHILE` while it is blocked, the open
/// key with its countdown while the gate is open, and `ALREADY OPEN` or `NEVER OPENS` in `G3` when there is
/// nothing to open: ads that pass, the router and the Pi, and a blocked device the configuration decides
/// (`fixed`), whose gate the Pi refuses.
fn gate_key(canvas: &mut Canvas, state: DeviceState, fixed: bool) {
    let r = Rect::new(KEY_X2, KEY_Y, KEY_W2, KEY_H);
    let cx = f32::from(KEY_X2) + f32::from(KEY_W2) / 2.0;
    match state {
        DeviceState::Open { left_secs } => parts::open_key(canvas, r, &format::mss(left_secs)),
        DeviceState::Blocked if !fixed => {
            canvas.hollow(r, G2, 4, GROUND);
            canvas.text(
                "ITS OWN GATE",
                cx,
                264.0,
                Face::bold(16.0, G2).track(2.0).mid(),
            );
            canvas.text("OPEN A WHILE", cx, 292.0, Face::bold(24.0, WHITE).mid());
        }
        DeviceState::Blocked | DeviceState::AdsPass | DeviceState::Always => {
            let word = if state == DeviceState::AdsPass {
                "ALREADY OPEN"
            } else {
                "NEVER OPENS"
            };
            canvas.text(
                "ITS OWN GATE",
                cx,
                264.0,
                Face::bold(16.0, G3).track(2.0).mid(),
            );
            canvas.text(word, cx, 292.0, Face::bold(24.0, G3).mid());
        }
    }
}

// ---------------------------------------------------------------------------------------------
// CONFIRM.

/// What CONFIRM puts on the glass: the slab drawn as the state the device would take.
#[derive(Clone, PartialEq, Eq)]
pub struct ConfirmView {
    /// The lane, which says `DEVICES`.
    pub lane: LaneView,
    /// The state it would take: `true` lets ads pass (`LET ADS PASS?`, a hollow slab), `false` blocks them
    /// (`BLOCK ADS?`, a blue one).
    pub pass: bool,
    /// The slab's first line: the device, and its `·octet` after two spaces when it has a name.
    pub who: String,
    /// How ads stand on the device now, as the slab's second line begins.
    pub now: &'static str,
    /// Whether `ALLOW ADS` wears the padlock: the action is strong and the lock is on.
    pub locked: bool,
}

impl std::fmt::Debug for ConfirmView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfirmView")
            .field("pass", &self.pass)
            .field("locked", &self.locked)
            .finish_non_exhaustive()
    }
}

impl ConfirmView {
    /// What CONFIRM shows for the device with this address and the state it would take: `None` when that is
    /// no longer true of the device (it is gone, or fixed, or already in that state); the nav pops the screen.
    pub fn of(world: &World, mac: &Mac, pass: bool) -> Option<Self> {
        if !confirm_valid(world, mac, pass) {
            return None;
        }
        let row = world.device(mac)?;
        let who = if row.named {
            format!("{}  \u{b7}{}", row.name, row.octet)
        } else {
            row.name.clone()
        };
        let now = match (pass, row.state) {
            (false, _) => "Ads pass now.",
            // Blocked underneath, but its own gate is open and ads are passing for a while.
            (true, DeviceState::Open { .. }) => "Ads pass for now.",
            (true, _) => "Ads are blocked now.",
        };
        Some(Self {
            lane: LaneView::of(Section::Devices, world),
            pass,
            who,
            now,
            locked: pass && world.lock_on,
        })
    }
}

/// CONFIRM's taps: the floor's left key keeps things as they are and goes back; the right key makes the change
/// and goes back to DEVICE. `ALLOW ADS` is strong, and in P1 nothing asks for a PIN (ruling R3).
pub fn confirm_tap(world: &World, mac: Mac, pass: bool, x: u16, y: u16) -> Tap {
    if y < FLOOR_Y || !confirm_valid(world, &mac, pass) {
        return Tap::None;
    }
    if x < FLOOR_SPLIT_X {
        Tap::Nav(Change::Back)
    } else {
        Tap::Act(Intent::DeviceAds { mac, pass }, Some(Change::Back))
    }
}

/// Draws CONFIRM (`flipScreen`).
pub fn draw_confirm(canvas: &mut Canvas, view: &ConfirmView) {
    lane::draw(canvas, &view.lane);
    let (ground, title) = if view.pass {
        (None, "LET ADS PASS?")
    } else {
        (Some(BLUE), "BLOCK ADS?")
    };
    let line = format!("{} Threats stay blocked.", view.now);
    parts::slab(
        canvas,
        ground,
        title,
        &[
            SlabLine::bold(&view.who, 24.0),
            SlabLine::plain(&line, 18.0),
        ],
    );
    let (keep, change) = if view.pass {
        ("KEEP BLOCKED", "ALLOW ADS")
    } else {
        ("KEEP ADS PASS", "BLOCK ADS")
    };
    parts::keys(canvas, Some(keep), Some(change), view.locked);
}

// ---------------------------------------------------------------------------------------------
// ITS GATE.

/// What ITS GATE puts on the glass: the device's name over the slab and GATE's four keys.
#[derive(Clone, PartialEq, Eq)]
pub struct ItsGateView {
    /// The lane, which says `DEVICES`.
    pub lane: LaneView,
    /// The device, as the slab's first line.
    pub name: String,
}

impl std::fmt::Debug for ItsGateView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ItsGateView").finish_non_exhaustive()
    }
}

impl ItsGateView {
    /// What ITS GATE shows for the device with this address: `None` when its gate cannot be opened any more
    /// (it is gone, its ads pass, or its gate is open already); the nav pops the screen.
    pub fn of(world: &World, mac: &Mac) -> Option<Self> {
        gate_valid(world, mac).then_some(())?;
        let row = world.device(mac)?;
        Some(Self {
            lane: LaneView::of(Section::Devices, world),
            name: row.name.clone(),
        })
    }
}

/// ITS GATE's taps, GATE's own four keys: `KEEP SHUT` goes back; 5 MIN, 30 MIN and 1 HOUR open the device's
/// gate for that long and go back to DEVICE. Nothing above the floor is a key.
pub fn its_gate_tap(world: &World, mac: Mac, x: u16, y: u16) -> Tap {
    if y < FLOOR_Y || !gate_valid(world, &mac) {
        return Tap::None;
    }
    match gate::key_secs(x) {
        Some(secs) => Tap::Act(Intent::DeviceGate { mac, secs }, Some(Change::Back)),
        None => Tap::Nav(Change::Back),
    }
}

/// Draws ITS GATE (`pauseScreen`).
pub fn draw_its_gate(canvas: &mut Canvas, view: &ItsGateView) {
    lane::draw(canvas, &view.lane);
    parts::slab(
        canvas,
        None,
        "OPEN ITS GATE",
        &[
            SlabLine::bold(&view.name, 24.0),
            SlabLine::plain("Ads pass on this device for a while.", 18.0),
        ],
    );
    parts::four_keys(canvas, "KEEP");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::os::fixture::{HOUSE, Still, house_devices, mac_of, world};
    use crate::os::intent::GateMove;
    use crate::os::nav::Nav;
    use crate::os::world::{WatchedName, display_name};

    /// A device row for the tests: `02:00:00:00:00:xx`, named or not.
    fn row(octet: u8, name: Option<&str>, state: DeviceState) -> DeviceRow {
        let (name, named) = display_name(name, None, octet);
        DeviceRow {
            mac: mac_of(octet),
            name,
            named,
            octet,
            state,
            fixed: false,
            asking: false,
        }
    }

    /// A world of `n` devices, `·1` to `·n`, ads passing.
    fn crowd(n: u8) -> World {
        let mut w = world(Still::Devices);
        w.devices = (1..=n)
            .map(|octet| row(octet, None, DeviceState::AdsPass))
            .collect();
        w
    }

    /// The living room TV, Sam's phone, the router: the house's third, second and ninth device.
    const TV: usize = 2;
    const SAM: usize = 1;
    const ROUTER: usize = 8;

    #[test]
    fn the_places_are_where_the_numbers_put_them() {
        let at: Vec<(u16, u16)> = (0..WALL_PLACES)
            .map(|i| (place_rect(i).x, place_rect(i).y))
            .collect();
        assert_eq!(
            at,
            [
                (8, 80),
                (126, 80),
                (244, 80),
                (362, 80),
                (8, 157),
                (126, 157),
                (244, 157),
                (362, 157),
                (8, 234),
                (126, 234),
                (244, 234),
                (362, 234)
            ]
        );
        assert!((0..WALL_PLACES).all(|i| (place_rect(i).w, place_rect(i).h) == (110, 70)));
    }

    #[test]
    fn the_wall_of_the_house_is_ten_devices_new_ones_and_an_empty_place() {
        let slots = layout(10, 0);
        assert_eq!(
            slots
                .iter()
                .filter(|s| matches!(s, Slot::Device(_)))
                .count(),
            10
        );
        assert_eq!(slots[10], Slot::NewOnes);
        assert_eq!(slots[11], Slot::Empty);
        // Twelve fit the twelve places with no `NEW ONES`, and the wall is one page.
        let twelve = layout(12, 0);
        assert!(
            twelve
                .iter()
                .enumerate()
                .all(|(i, s)| *s == Slot::Device(i))
        );
        assert_eq!((pages(0), pages(12), pages(13)), (1, 1, 2));
        assert_eq!(layout(0, 0)[0], Slot::NewOnes, "an empty house");
    }

    #[test]
    fn thirty_devices_page_by_eleven_with_more_in_the_twelfth_place() {
        assert_eq!(pages(30), 3);
        assert_eq!(pages(33), 3);
        let first = layout(30, 0);
        assert!(
            first[..11]
                .iter()
                .enumerate()
                .all(|(i, s)| *s == Slot::Device(i))
        );
        assert_eq!(first[11], Slot::More(19), "19 are not on this page");
        let second = layout(30, 1);
        assert!(
            second[..11]
                .iter()
                .enumerate()
                .all(|(i, s)| *s == Slot::Device(11 + i))
        );
        assert_eq!(second[11], Slot::More(19));
        // The last page has what is left (8), `NEW ONES` after them, and still the turner.
        let last = layout(30, 2);
        assert!(
            last[..8]
                .iter()
                .enumerate()
                .all(|(i, s)| *s == Slot::Device(22 + i))
        );
        assert_eq!(last[8], Slot::NewOnes);
        assert_eq!((last[9], last[10]), (Slot::Empty, Slot::Empty));
        assert_eq!(last[11], Slot::More(22));
        // A page that does not exist is the last; a full last page has no `NEW ONES`.
        assert_eq!(layout(30, 9), last);
        let full = layout(33, 2);
        assert!(full[..11].iter().all(|s| matches!(s, Slot::Device(_))));
        assert_eq!(full[11], Slot::More(22));
        assert_eq!(clamp_page(7, 30), 2);
        assert_eq!(clamp_page(7, 5), 0);
        // Every device is on exactly one page.
        let mut seen = vec![0; 30];
        for page in 0..3 {
            for slot in layout(30, page) {
                if let Slot::Device(i) = slot {
                    seen[i] += 1;
                }
            }
        }
        assert!(seen.iter().all(|&n| n == 1), "{seen:?}");
    }

    #[test]
    fn the_page_turner_goes_to_the_next_page_and_from_the_last_to_the_first() {
        let w = crowd(30);
        let turner = (
            WALL_X0 + 3 * WALL_PITCH_X + 10,
            WALL_Y0 + 2 * WALL_PITCH_Y + 10,
        );
        for (page, next) in [(0, 1), (1, 2), (2, 0)] {
            assert_eq!(
                wall_tap(page, &w, turner.0, turner.1),
                Tap::Nav(Change::DevicesPage(next)),
                "from page {page}"
            );
        }
        // A page that is past the end turns from the last.
        assert_eq!(
            wall_tap(9, &w, turner.0, turner.1),
            Tap::Nav(Change::DevicesPage(0))
        );
        // On the second page the first place is the twelfth device.
        assert_eq!(
            wall_tap(1, &w, 20, 100),
            Tap::Nav(Change::Open(Screen::Device(mac_of(12))))
        );
        // Taps in the wall's places on the last page: its eighth device, `NEW ONES` and the empty ones.
        let place = |i: usize| {
            let r = place_rect(i);
            (r.x + 55, r.y + 35)
        };
        assert_eq!(
            wall_tap(2, &w, place(7).0, place(7).1),
            Tap::Nav(Change::Open(Screen::Device(mac_of(30))))
        );
        for i in [8, 9, 10] {
            assert_eq!(wall_tap(2, &w, place(i).0, place(i).1), Tap::None, "{i}");
        }
    }

    #[test]
    fn the_wall_view_paging_shows_the_pages_devices() {
        let w = crowd(30);
        let page = |n| WallView::of(&w, n);
        assert_eq!(page(0).seats.len(), WALL_PLACES);
        let names = |view: &WallView| -> Vec<String> {
            view.seats
                .iter()
                .filter_map(|seat| match seat {
                    Seat::Device(tile) => Some(tile.lines[0].clone()),
                    _ => None,
                })
                .collect()
        };
        assert_eq!(names(&page(0)).first().map(String::as_str), Some("\u{b7}1"));
        assert_eq!(
            names(&page(1)).first().map(String::as_str),
            Some("\u{b7}12")
        );
        assert_eq!(names(&page(2)).len(), 8);
        assert_eq!(page(1).seats[11], Seat::More(19));
        assert_eq!(page(2).seats[8], Seat::NewOnes(Newcomer::AdsPass));
        assert_ne!(page(0), page(1));
        // The lane says DEVICES.
        assert_eq!(page(0).lane.words, "DEVICES");
    }

    #[test]
    fn a_tile_wraps_its_name_at_a_space_within_ten_cells() {
        let w = world(Still::Devices);
        let lines = |i: usize| TileView::of(&w.devices[i]).lines;
        // The mockup's `wrapWords(name, 10)`.
        assert_eq!(lines(0), ["Desk PC".to_string(), String::new()]);
        assert_eq!(lines(SAM), ["Sam's".to_string(), "phone".to_string()]);
        assert_eq!(lines(TV), ["Living".to_string(), "room TV".to_string()]);
        assert_eq!(lines(3), ["Kid's".to_string(), "tablet".to_string()]);
        assert_eq!(lines(4), ["printer".to_string(), String::new()]);
        // No space to break at: one line, cut. A second line that is too long is cut.
        assert_eq!(
            wrap_words("Basement furnace sensor", 10),
            ["Basement".to_string(), "furnace s~".to_string()]
        );
        assert_eq!(
            wrap_words("Thermostat9000x", 10),
            ["Thermosta~".to_string(), String::new()]
        );
        assert_eq!(
            wrap_words("a b", 10),
            ["a b".to_string(), String::new()],
            "short names are not broken"
        );
        // A device with no name is its octet, in 24 px.
        let unnamed = TileView::of(&w.devices[6]);
        assert!(unnamed.octet);
        assert_eq!(unnamed.lines[0], "\u{b7}143");
        assert!(!TileView::of(&w.devices[0]).octet);
    }

    #[test]
    fn the_state_words_are_the_ads_pass_ones() {
        let w = world(Still::Devices);
        let words: Vec<String> = w.devices.iter().map(|d| TileView::of(d).word()).collect();
        assert_eq!(
            words,
            [
                "ADS PASS", "ADS PASS", "BLOCKED", "BLOCKED", "ADS PASS", "ADS PASS", "ADS PASS",
                "ADS PASS", "ALWAYS", "ALWAYS"
            ]
        );
        let open = TileView::of(&row(
            5,
            Some("Lamp"),
            DeviceState::Open { left_secs: 1_777 },
        ));
        assert_eq!(open.word(), "OPEN 29:37");
    }

    fn drawn(still: Still) -> Canvas {
        let w = world(still);
        let nav = still.nav(&w);
        let view = crate::os::screens::view_of(&nav, &w).expect("a view");
        let mut canvas = Canvas::new();
        crate::os::screens::draw(&mut canvas, &view);
        canvas
    }

    #[test]
    fn a_tile_is_blue_when_blocked_and_a_frame_when_ads_pass() {
        let canvas = drawn(Still::Devices);
        let px = |x, y| canvas.pixel(x, y);
        // Desk PC (ads pass): a 2 px G3 frame round black. The TV (blocked): solid blue. The router: blue.
        assert_eq!(px(8, 80), Some(G3));
        assert_eq!(px(9, 81), Some(G3));
        assert_eq!(px(10, 82), Some(GROUND));
        assert_eq!(px(117, 149), Some(G3));
        assert_eq!(px(244, 80), Some(BLUE));
        assert_eq!(px(353, 149), Some(BLUE));
        assert_eq!(px(8, 234), Some(BLUE));
        assert_eq!(px(117, 303), Some(BLUE));
        // The gaps between places are black, and the place after the router's row says `NEW ONES` on black.
        assert_eq!(px(118, 100), Some(GROUND));
        assert_eq!(px(100, 150), Some(GROUND));
        assert_eq!(px(250, 240), Some(GROUND));
    }

    #[test]
    fn a_tile_whose_own_gate_is_open_is_a_white_frame_with_a_countdown() {
        let mut w = world(Still::Devices);
        w.devices[TV].state = DeviceState::Open { left_secs: 1_790 };
        let view = WallView::of(&w, 0);
        let mut canvas = Canvas::new();
        draw_wall(&mut canvas, &view);
        let r = place_rect(TV);
        assert_eq!(canvas.pixel(r.x.into(), r.y.into()), Some(WHITE));
        assert_eq!(
            canvas.pixel(usize::from(r.x) + 2, usize::from(r.y) + 2),
            Some(GROUND)
        );
        match &view.seats[TV] {
            Seat::Device(tile) => assert_eq!(tile.word(), "OPEN 29:50"),
            other => panic!("{other:?}"),
        }
        // Ten letters go untracked so the word stays inside the frame: its ink never reaches the frame's column.
        let word_rows = usize::from(r.y) + 49..usize::from(r.y) + 63;
        let right_ink = |x: usize| word_rows.clone().any(|y| canvas.pixel(x, y) == Some(WHITE));
        assert!(
            !right_ink(usize::from(r.x) + 106),
            "the word runs onto the frame"
        );
        // The countdown is a view change of a few rows.
        let mut later = w.clone();
        later.devices[TV].state = DeviceState::Open { left_secs: 1_789 };
        assert_ne!(WallView::of(&later, 0), view);
    }

    #[test]
    fn the_lamp_is_white_while_a_device_asks_and_a_dot_otherwise() {
        let canvas = drawn(Still::Devices);
        // Sam's phone (place 1) and the printer (place 4) ask: a white disc of r 5 at (tile + 97, tile + 13).
        let lamp = |i: usize| {
            let r = place_rect(i);
            (usize::from(r.x) + 97, usize::from(r.y) + 13)
        };
        for i in [1, 4] {
            let (x, y) = lamp(i);
            assert_eq!(canvas.pixel(x, y), Some(WHITE), "place {i}");
            assert_eq!(canvas.pixel(x + 4, y), Some(WHITE), "r 5 reaches 4 px");
            assert_eq!(canvas.pixel(x + 7, y), Some(GROUND), "and not 7");
        }
        // The others are r 2.5 dots: `BLUE_DEEP` on a black tile, `BLUE_MD` on a blue one.
        let (x, y) = lamp(0);
        assert_eq!(canvas.pixel(x, y), Some(BLUE_DEEP));
        let (x, y) = lamp(TV);
        assert_eq!(canvas.pixel(x, y), Some(BLUE_MD));
        let (x, y) = lamp(ROUTER);
        assert_eq!(canvas.pixel(x, y), Some(BLUE_MD));
    }

    #[test]
    fn the_first_empty_place_says_new_ones_and_the_default_in_the_mode_in_force() {
        let mut w = world(Still::Devices);
        let ink_in = |canvas: &Canvas, r: Rect| {
            (usize::from(r.y)..usize::from(r.y + r.h)).any(|y| {
                (usize::from(r.x)..usize::from(r.x + r.w)).any(|x| canvas.pixel(x, y) == Some(G3))
            })
        };
        let canvas = drawn(Still::Devices);
        assert!(ink_in(&canvas, place_rect(10)), "NEW ONES / ADS PASS in G3");
        assert!(!ink_in(&canvas, place_rect(11)), "the next place is a dot");
        let blocked = {
            w.newcomer = Newcomer::Blocked;
            WallView::of(&w, 0)
        };
        assert_eq!(blocked.seats[10], Seat::NewOnes(Newcomer::Blocked));
        assert_ne!(blocked, WallView::of(&world(Still::Devices), 0));
    }

    #[test]
    fn the_page_turner_is_a_dark_tile_with_more_and_how_many() {
        let w = crowd(30);
        let mut canvas = Canvas::new();
        draw_wall(&mut canvas, &WallView::of(&w, 0));
        let r = place_rect(11);
        assert_eq!(canvas.pixel(r.x.into(), r.y.into()), Some(G4));
        assert_eq!(
            canvas.pixel(usize::from(r.x) + 109, usize::from(r.y) + 69),
            Some(G4)
        );
        // Its words are in G1, centred.
        let ink: Vec<usize> = (usize::from(r.x)..usize::from(r.x + r.w))
            .filter(|&x| {
                (usize::from(r.y)..usize::from(r.y + r.h)).any(|y| canvas.pixel(x, y) == Some(G1))
            })
            .collect();
        let (first, last) = (ink[0], ink[ink.len() - 1]);
        let middle = usize::from(r.x) + 55;
        assert!(first.abs_diff(middle) < 55 && last.abs_diff(middle) < 55);
        assert!(
            first.abs_diff(middle).abs_diff(last.abs_diff(middle)) <= 8,
            "{first} {last}"
        );
    }

    // ---- DEVICE ----

    fn device_view(still: Still, index: usize) -> DeviceView {
        let w = world(still);
        DeviceView::of(&w, &mac_of(HOUSE[index].octet)).expect("a device on the wall")
    }

    #[test]
    fn the_device_view_is_its_name_octet_names_and_state() {
        let view = device_view(Still::Device, TV);
        assert_eq!(view.name, "Living room TV");
        assert_eq!(view.octet.as_deref(), Some("\u{b7}31"));
        assert_eq!(
            view.names,
            [
                ("googlesyndication.com".to_string(), Outcome::Refused),
                ("i.ytimg.com".to_string(), Outcome::Answered)
            ]
        );
        assert_eq!((view.state, view.fixed), (DeviceState::Blocked, false));
        // A device with no name is its octet, once.
        let w = world(Still::Devices);
        let bare = DeviceView::of(&w, &mac_of(143)).expect("the device");
        assert_eq!((bare.name.as_str(), bare.octet), ("\u{b7}143", None));
        assert!(bare.names.is_empty());
        // A device that is not on the wall has no screen.
        assert_eq!(DeviceView::of(&w, &mac_of(99)), None);
    }

    #[test]
    fn a_long_name_is_30_px_and_a_short_one_40() {
        let height = |name: &str| {
            let mut w = world(Still::Devices);
            w.devices[0].name = name.to_string();
            let mut canvas = Canvas::new();
            draw_device(
                &mut canvas,
                &DeviceView::of(&w, &w.devices[0].mac).expect("a device"),
            );
            let ink: Vec<usize> = (80..125)
                .filter(|&y| (6..400).any(|x| canvas.pixel(x, y) == Some(WHITE)))
                .collect();
            ink.last().copied().unwrap_or(0) - ink.first().copied().unwrap_or(0)
        };
        let (big, small) = (height(&"H".repeat(15)), height(&"H".repeat(16)));
        assert!(big > small + 4, "{big} against {small}");
    }

    #[test]
    fn the_names_it_asked_are_rows_with_a_square_and_what_came_of_them() {
        let canvas = drawn(Still::Device);
        let px = |x, y| canvas.pixel(x, y);
        // Row 0, refused: a solid blue square at (8, 148); row 1, answered: a deep blue one at (8, 200).
        assert_eq!(px(8, 148), Some(BLUE));
        assert_eq!(px(23, 163), Some(BLUE));
        assert_eq!(px(8, 200), Some(BLUE_DEEP));
        // A passed name is a white frame round black.
        let mut w = world(Still::Device);
        w.watched[0] = WatchedName::new("doubleclick.net", Outcome::Passed);
        let mut canvas = Canvas::new();
        draw_device(
            &mut canvas,
            &DeviceView::of(&w, &mac_of(31)).expect("the TV"),
        );
        assert_eq!(canvas.pixel(8, 148), Some(WHITE));
        assert_eq!(canvas.pixel(9, 149), Some(WHITE));
        assert_eq!(canvas.pixel(10, 150), Some(GROUND));
    }

    #[test]
    fn with_no_names_it_waits_for_the_next_one_and_with_one_it_still_does_below_it() {
        let mut w = world(Still::Device);
        let mac = mac_of(31);
        // The waiting line is on the left of a row, 270 px of it from x 33; a name row has its outcome's word
        // at the right edge.
        let ink =
            |canvas: &Canvas, rows: std::ops::Range<usize>, columns: std::ops::Range<usize>| {
                rows.clone()
                    .any(|y| columns.clone().any(|x| canvas.pixel(x, y) != Some(GROUND)))
            };
        let (left, right) = (30..330, 360..470);
        w.watched.clear();
        let view = DeviceView::of(&w, &mac).expect("the TV");
        assert!(view.names.is_empty());
        let mut canvas = Canvas::new();
        draw_device(&mut canvas, &view);
        assert!(ink(&canvas, 146..170, left.clone()), "the first row waits");
        assert!(!ink(&canvas, 146..170, right.clone()));
        assert!(!ink(&canvas, 198..222, 0..480));
        // One name, in the first row, and the next one awaited in the second.
        w.watched
            .push(WatchedName::new("one.example.org", Outcome::Answered));
        let mut canvas = Canvas::new();
        draw_device(&mut canvas, &DeviceView::of(&w, &mac).expect("the TV"));
        assert!(ink(&canvas, 146..170, right.clone()), "a name's outcome");
        assert!(ink(&canvas, 198..222, left.clone()), "the second waits");
        assert!(!ink(&canvas, 198..222, right.clone()), "and is no name");
        // Two names: nothing waits, and both rows carry their outcome.
        w.watched
            .push(WatchedName::new("two.example.org", Outcome::Refused));
        let mut canvas = Canvas::new();
        draw_device(&mut canvas, &DeviceView::of(&w, &mac).expect("the TV"));
        assert!(ink(&canvas, 146..170, right.clone()) && ink(&canvas, 198..222, right));
    }

    #[test]
    fn the_floors_keys_say_where_ads_stand_and_what_its_gate_can_do() {
        let keys = |state: DeviceState, fixed: bool| {
            let mut w = world(Still::Devices);
            w.devices[0].state = state;
            w.devices[0].fixed = fixed;
            let mut canvas = Canvas::new();
            draw_device(
                &mut canvas,
                &DeviceView::of(&w, &w.devices[0].mac).expect("a device"),
            );
            canvas
        };
        let px = |c: &Canvas, x, y| c.pixel(x, y);
        // Blocked: a solid blue state key and a G2 frame for the gate to open.
        let blocked = keys(DeviceState::Blocked, false);
        assert_eq!(px(&blocked, 8, 240), Some(BLUE));
        assert_eq!(px(&blocked, 244, 240), Some(G2));
        assert_eq!(px(&blocked, 250, 250), Some(GROUND));
        // Ads pass: a white frame, and nothing to open (no frame, G3 words).
        let pass = keys(DeviceState::AdsPass, false);
        assert_eq!(
            (px(&pass, 8, 240), px(&pass, 20, 250)),
            (Some(WHITE), Some(GROUND))
        );
        assert_eq!(px(&pass, 244, 240), Some(GROUND));
        assert!((250..470).any(|x| (280..296).any(|y| px(&pass, x, y) == Some(G3))));
        // The router: the dark blue key, and a gate that never opens.
        let always = keys(DeviceState::Always, false);
        assert_eq!(px(&always, 8, 240), Some(BLUE_DK));
        assert_eq!(px(&always, 244, 240), Some(GROUND));
        // The gate open: the open key's white frame, the state key still blue.
        let open = keys(DeviceState::Open { left_secs: 90 }, false);
        assert_eq!(
            (px(&open, 8, 240), px(&open, 244, 240)),
            (Some(BLUE), Some(WHITE))
        );
        // The configuration decides: dimmer keys, the same shape.
        let fixed = keys(DeviceState::AdsPass, true);
        assert_eq!(px(&fixed, 8, 240), Some(G3));
        let fixed_blocked = keys(DeviceState::Blocked, true);
        assert_eq!(px(&fixed_blocked, 8, 240), Some(BLUE_DK));
        // Its own gate never opens (the Pi refuses it): no frame, G3 words, as for the router.
        assert_eq!(
            (px(&fixed_blocked, 244, 240), px(&fixed_blocked, 250, 250)),
            (Some(GROUND), Some(GROUND)),
            "its own gate is inert"
        );
        assert!(
            (250..470).any(|x| (280..296).any(|y| px(&fixed_blocked, x, y) == Some(G3))),
            "and says so in G3"
        );
    }

    #[test]
    fn a_fixed_device_says_set_in_config_where_the_state_word_was() {
        let word_ink = |fixed: bool| {
            let mut w = world(Still::Devices);
            w.devices[0].fixed = fixed;
            let mut canvas = Canvas::new();
            draw_device(
                &mut canvas,
                &DeviceView::of(&w, &w.devices[0].mac).expect("a device"),
            );
            // The value stands on 292: 24 px of ink between rows 274 and 293, left key.
            (14..230)
                .filter(|&x| (274..293).any(|y| canvas.pixel(x, y) != Some(GROUND)))
                .count()
        };
        // `ADS PASS` is 8 letters of 14.4 px; `SET IN CONFIG` is 13.
        let (plain, fixed) = (word_ink(false), word_ink(true));
        assert!(fixed > plain + 40, "{fixed} against {plain}");
    }

    // ---- CONFIRM and ITS GATE ----

    #[test]
    fn confirm_is_the_slab_drawn_as_the_state_it_would_take() {
        let w = world(Still::Confirm);
        let sam = mac_of(23);
        // Sam's phone passes ads: the question is whether to block them, a blue slab.
        let block = ConfirmView::of(&w, &sam, false).expect("a screen");
        assert_eq!(block.who, "Sam's phone  \u{b7}23");
        assert_eq!(
            (block.pass, block.now, block.locked),
            (false, "Ads pass now.", false)
        );
        let mut canvas = Canvas::new();
        draw_confirm(&mut canvas, &block);
        assert_eq!(canvas.pixel(8, 80), Some(BLUE));
        assert_eq!(canvas.pixel(300, 200), Some(BLUE));
        // The floor: `KEEP ADS PASS` hollow on the left, `BLOCK ADS` solid white on the right.
        assert_eq!(
            (canvas.pixel(8, 240), canvas.pixel(20, 250)),
            (Some(WHITE), Some(GROUND))
        );
        assert_eq!(canvas.pixel(244, 240), Some(WHITE));
        // The TV is blocked: the question is whether to let ads pass, a hollow slab.
        let tv = mac_of(31);
        let pass = ConfirmView::of(&w, &tv, true).expect("a screen");
        assert_eq!(
            (pass.now, pass.who.as_str()),
            ("Ads are blocked now.", "Living room TV  \u{b7}31")
        );
        let mut canvas = Canvas::new();
        draw_confirm(&mut canvas, &pass);
        assert_eq!(
            (canvas.pixel(8, 80), canvas.pixel(300, 200)),
            (Some(WHITE), Some(GROUND))
        );
        // A device with no name is its octet alone.
        let bare = ConfirmView::of(&w, &mac_of(143), false).expect("a screen");
        assert_eq!(bare.who, "\u{b7}143");
    }

    #[test]
    fn confirm_for_a_device_with_its_gate_open_says_ads_pass_for_now() {
        let mut w = world(Still::Confirm);
        w.devices[TV].state = DeviceState::Open { left_secs: 60 };
        let view = ConfirmView::of(&w, &mac_of(31), true).expect("a screen");
        assert_eq!(view.now, "Ads pass for now.");
        assert_eq!(
            ConfirmView::of(&w, &mac_of(31), false),
            None,
            "it does not pass for good"
        );
    }

    #[test]
    fn allow_ads_wears_the_padlock_only_while_the_lock_is_on() {
        let mut w = world(Still::Confirm);
        let tv = mac_of(31);
        assert!(!ConfirmView::of(&w, &tv, true).expect("a screen").locked);
        w.lock_on = true;
        assert!(ConfirmView::of(&w, &tv, true).expect("a screen").locked);
        // Blocking is never strong.
        assert!(
            !ConfirmView::of(&w, &mac_of(23), false)
                .expect("a screen")
                .locked
        );
        let plain = world(Still::Confirm);
        let mut a = Canvas::new();
        draw_confirm(
            &mut a,
            &ConfirmView::of(&plain, &tv, true).expect("a screen"),
        );
        let mut b = Canvas::new();
        draw_confirm(&mut b, &ConfirmView::of(&w, &tv, true).expect("a screen"));
        assert_ne!(a.rgba(), b.rgba(), "the padlock is drawn");
    }

    #[test]
    fn confirm_is_only_true_while_the_device_can_take_that_state() {
        let mut w = world(Still::Confirm);
        let (sam, tv, router) = (mac_of(23), mac_of(31), mac_of(1));
        assert!(confirm_valid(&w, &sam, false) && confirm_valid(&w, &tv, true));
        assert!(!confirm_valid(&w, &sam, true), "ads already pass");
        assert!(!confirm_valid(&w, &tv, false), "ads are already blocked");
        assert!(!confirm_valid(&w, &router, true) && !confirm_valid(&w, &router, false));
        assert!(!confirm_valid(&w, &mac_of(99), true), "not on the wall");
        w.devices[SAM].fixed = true;
        assert!(!confirm_valid(&w, &sam, false), "the configuration decides");
        assert_eq!(flip_target(&w.devices[TV]), Some(true));
        assert_eq!(flip_target(&w.devices[SAM]), None);
    }

    #[test]
    fn its_gate_is_the_slab_with_the_devices_name_and_gates_four_keys() {
        let w = world(Still::Pause);
        let view = ItsGateView::of(&w, &mac_of(31)).expect("a screen");
        assert_eq!(view.name, "Living room TV");
        let mut canvas = Canvas::new();
        draw_its_gate(&mut canvas, &view);
        assert_eq!(canvas.pixel(8, 80), Some(WHITE), "a hollow slab");
        assert_eq!(canvas.pixel(300, 150), Some(GROUND));
        assert_eq!(canvas.pixel(8, 240), Some(BLUE), "KEEP SHUT");
        assert_eq!(canvas.pixel(126, 240), Some(WHITE));
        // Ads that pass leave no gate to open.
        assert_eq!(ItsGateView::of(&w, &mac_of(23)), None);
        assert_eq!(ItsGateView::of(&w, &mac_of(1)), None);
        let mut open = w.clone();
        open.devices[TV].state = DeviceState::Open { left_secs: 5 };
        assert_eq!(ItsGateView::of(&open, &mac_of(31)), None);
    }

    // ---- the taps ----

    /// The tap of a press on a screen of a still.
    fn press(still: Still, x: u16, y: u16) -> Tap {
        let w = world(still);
        crate::os::nav::decide(&still.nav(&w), &w, x, y)
    }

    #[test]
    fn the_walls_places_open_their_devices_and_the_rest_is_nothing() {
        let want = |i: usize| Tap::Nav(Change::Open(Screen::Device(mac_of(HOUSE[i].octet))));
        for i in 0..10 {
            let r = place_rect(i);
            for (dx, dy) in [(0, 0), (55, 35), (109, 69)] {
                assert_eq!(
                    press(Still::Devices, r.x + dx, r.y + dy),
                    want(i),
                    "place {i}"
                );
            }
        }
        // `NEW ONES` and the dot after it are nothing.
        for i in [10, 11] {
            let r = place_rect(i);
            assert_eq!(
                press(Still::Devices, r.x + 55, r.y + 35),
                Tap::None,
                "place {i}"
            );
        }
    }

    #[test]
    fn the_wall_hit_is_the_mockups_with_the_edges_going_on() {
        // `floor((y - 76) / 77) * 4 + floor((x - 4) / 118)`.
        assert_eq!(place_hit(0, 75), None);
        assert_eq!(place_hit(0, 76), Some(0));
        assert_eq!(place_hit(121, 152), Some(0));
        assert_eq!(place_hit(122, 152), Some(1));
        assert_eq!(place_hit(4, 153), Some(4));
        assert_eq!(place_hit(358, 76), Some(3));
        assert_eq!(place_hit(357, 229), Some(6));
        assert_eq!(place_hit(358, 230), Some(11));
        // The mockup's x >= 476 runs on to the next row's first place and y >= 307 is no row; here both
        // are the last column and the last row.
        assert_eq!(place_hit(479, 100), Some(3));
        assert_eq!(place_hit(479, 319), Some(11));
        assert_eq!(place_hit(u16::MAX, u16::MAX), Some(11));
        // The rows between the lane and the wall are nothing.
        assert_eq!(press(Still::Devices, 100, 74), Tap::None);
    }

    #[test]
    fn device_has_two_keys_the_state_and_its_own_gate() {
        let open = |screen| Tap::Nav(Change::Open(screen));
        // The TV (blocked): the left key asks to let ads pass, the right opens its gate's choices.
        let tv = mac_of(31);
        assert_eq!(
            press(Still::Device, 100, 280),
            open(Screen::Confirm {
                mac: tv,
                pass: true
            })
        );
        assert_eq!(
            press(Still::Device, 100, 236),
            press(Still::Device, 239, 319)
        );
        assert_eq!(press(Still::Device, 400, 280), open(Screen::ItsGate(tv)));
        assert_eq!(press(Still::Device, 240, 236), open(Screen::ItsGate(tv)));
        // Above the floor are the rows of the names it asked, which open NAME: see their own test.
        assert_eq!(
            press(Still::Device, 100, 100),
            Tap::None,
            "its own name is no door"
        );
    }

    #[test]
    fn a_name_row_opens_name_with_the_whole_name_and_the_waiting_line_is_no_door() {
        // The TV's screen has two names: rows 132 to 183 and 184 to 235, each the whole width.
        let name = |text: &str| Tap::Nav(Change::Open(Screen::Name(text.to_owned())));
        for (x, y) in [(0, 132), (100, 150), (479, 183)] {
            assert_eq!(
                press(Still::Device, x, y),
                name("googlesyndication.com"),
                "{x},{y}"
            );
        }
        for (x, y) in [(0, 184), (300, 210), (479, 235)] {
            assert_eq!(press(Still::Device, x, y), name("i.ytimg.com"), "{x},{y}");
        }
        assert_eq!(press(Still::Device, 100, 131), Tap::None, "above the rows");

        // The row opens NAME with the whole name, not the one fitted to the row.
        let mut w = world(Still::Device);
        let long = "a.very.long.host.name.of.a.tracker.example.org";
        w.watched[0] = WatchedName::new(long, Outcome::Refused);
        assert_eq!(w.watched[0].name, "a.tracker.example.org");
        let nav = Still::Device.nav(&w);
        assert_eq!(crate::os::nav::decide(&nav, &w, 100, 150), name(long));
        // A row whose whole name is not known is no door.
        w.watched[0].whole = None;
        assert_eq!(crate::os::nav::decide(&nav, &w, 100, 150), Tap::None);

        // One name: its row is a door, and the waiting line under it is not.
        w.watched.truncate(1);
        w.watched[0] = WatchedName::new("one.example.org", Outcome::Answered);
        assert_eq!(
            crate::os::nav::decide(&nav, &w, 100, 150),
            name("one.example.org")
        );
        assert_eq!(crate::os::nav::decide(&nav, &w, 100, 200), Tap::None);
        // No names: nothing above the floor is a door.
        w.watched.clear();
        for y in [132, 150, 200, 235] {
            assert_eq!(crate::os::nav::decide(&nav, &w, 100, y), Tap::None, "y {y}");
        }
    }

    #[test]
    fn device_keys_by_state() {
        let tap = |state: DeviceState, fixed: bool, x: u16| {
            let mut w = world(Still::Devices);
            w.devices[SAM].state = state;
            w.devices[SAM].fixed = fixed;
            let mut nav = Nav::at(Section::Devices);
            nav.open(Screen::Device(mac_of(23)));
            crate::os::nav::decide(&nav, &w, x, 280)
        };
        let sam = mac_of(23);
        let confirm = |pass| Tap::Nav(Change::Open(Screen::Confirm { mac: sam, pass }));
        // Ads pass: the left key asks to block; the right is nothing (`ALREADY OPEN`).
        assert_eq!(tap(DeviceState::AdsPass, false, 100), confirm(false));
        assert_eq!(tap(DeviceState::AdsPass, false, 400), Tap::None);
        // Blocked: ask to let ads pass; the gate opens.
        assert_eq!(tap(DeviceState::Blocked, false, 100), confirm(true));
        assert_eq!(
            tap(DeviceState::Blocked, false, 400),
            Tap::Nav(Change::Open(Screen::ItsGate(sam)))
        );
        // The gate open: the left key still asks to let ads pass for good; the right shuts the gate and stays.
        let open = DeviceState::Open { left_secs: 100 };
        assert_eq!(tap(open, false, 100), confirm(true));
        assert_eq!(
            tap(open, false, 400),
            Tap::Act(Intent::DeviceGate { mac: sam, secs: 0 }, None)
        );
        // The router and the Pi: neither key does anything. The configuration decides: the state key is inert.
        assert_eq!(tap(DeviceState::Always, false, 100), Tap::None);
        assert_eq!(tap(DeviceState::Always, false, 400), Tap::None);
        assert_eq!(tap(DeviceState::AdsPass, true, 100), Tap::None);
        assert_eq!(tap(DeviceState::Blocked, true, 100), Tap::None);
        // The Pi refuses every gate edit of such a device (`Devices::open_gate`: `Fixed`), so its gate
        // key is like the router's: nothing to open, and no screen to ask for it.
        assert_eq!(
            tap(DeviceState::Blocked, true, 400),
            Tap::None,
            "a fixed device's own gate never opens"
        );
        // Its ads pass for good in the list mode (`ALREADY OPEN`): nothing there either.
        assert_eq!(tap(DeviceState::AdsPass, true, 400), Tap::None);
    }

    #[test]
    fn its_gate_is_no_screen_for_a_device_the_configuration_decides() {
        let tv = mac_of(31);
        let mut w = world(Still::Devices);
        assert_eq!(w.devices[TV].state, DeviceState::Blocked);
        assert!(
            gate_valid(&w, &tv),
            "the TV's gate opens, as the stills show"
        );
        assert!(ItsGateView::of(&w, &tv).is_some());
        assert_ne!(its_gate_tap(&w, tv, 180, 290), Tap::None);
        // Config-blocked: the gate would be refused, so the screen is not valid, and its keys are inert.
        w.devices[TV].fixed = true;
        assert!(!gate_valid(&w, &tv));
        assert_eq!(ItsGateView::of(&w, &tv), None);
        for x in [60, 180, 300, 420] {
            assert_eq!(its_gate_tap(&w, tv, x, 290), Tap::None, "x {x}");
        }
    }

    #[test]
    fn confirm_keeps_or_changes_and_either_way_goes_back() {
        // Sam's phone, ads pass, asking whether to block them.
        let sam = mac_of(23);
        assert_eq!(press(Still::Confirm, 100, 280), Tap::Nav(Change::Back));
        assert_eq!(press(Still::Confirm, 239, 236), Tap::Nav(Change::Back));
        let block = Tap::Act(
            Intent::DeviceAds {
                mac: sam,
                pass: false,
            },
            Some(Change::Back),
        );
        assert_eq!(press(Still::Confirm, 240, 236), block);
        assert_eq!(press(Still::Confirm, 400, 300), block);
        for (x, y) in [(100, 150), (400, 235), (300, 100)] {
            assert_eq!(press(Still::Confirm, x, y), Tap::None, "({x}, {y})");
        }
        // The change to let ads pass is the strong one, which P1 sends straight through.
        let w = world(Still::Devices);
        let mut nav = Nav::at(Section::Devices);
        nav.open(Screen::Device(mac_of(31)));
        nav.open(Screen::Confirm {
            mac: mac_of(31),
            pass: true,
        });
        let allow = crate::os::nav::decide(&nav, &w, 400, 280);
        assert_eq!(
            allow,
            Tap::Act(
                Intent::DeviceAds {
                    mac: mac_of(31),
                    pass: true
                },
                Some(Change::Back)
            )
        );
        if let Tap::Act(intent, _) = allow {
            assert!(intent.is_strong(), "ALLOW ADS is strong");
        }
        // The screen's own target is what it sends, whatever the device has become since.
        let mut now_pass = w.clone();
        now_pass.devices[TV].state = DeviceState::AdsPass;
        assert_eq!(crate::os::nav::decide(&nav, &now_pass, 400, 280), Tap::None);
    }

    #[test]
    fn its_gate_keys_are_gates_and_go_back_to_the_device() {
        let tv = mac_of(31);
        let open = |secs| Tap::Act(Intent::DeviceGate { mac: tv, secs }, Some(Change::Back));
        assert_eq!(press(Still::Pause, 60, 280), Tap::Nav(Change::Back));
        assert_eq!(press(Still::Pause, 121, 240), Tap::Nav(Change::Back));
        assert_eq!(press(Still::Pause, 122, 240), open(300));
        assert_eq!(press(Still::Pause, 300, 280), open(1_800));
        assert_eq!(press(Still::Pause, 479, 319), open(3_600));
        assert_eq!(press(Still::Pause, 300, 235), Tap::None);
        assert_eq!(press(Still::Pause, 300, 120), Tap::None);
        // The device-gate intent is not the main gate's.
        assert!(!matches!(
            open(300),
            Tap::Act(Intent::Gate(GateMove::Open(_)), _)
        ));
    }

    #[test]
    fn the_lane_on_every_device_screen_is_the_lane_of_devices() {
        for still in [Still::Devices, Still::Device, Still::Confirm, Still::Pause] {
            let w = world(still);
            let nav = still.nav(&w);
            let decide = |x| crate::os::nav::decide(&nav, &w, x, 40);
            assert_eq!(decide(10), Tap::Nav(Change::Go(Section::Home)), "{still:?}");
            assert_eq!(
                decide(200),
                Tap::Nav(Change::Go(Section::Devices)),
                "{still:?}"
            );
            assert_eq!(
                decide(400),
                Tap::Nav(Change::Go(Section::System)),
                "{still:?}"
            );
        }
    }

    // ---- the views never print a name ----

    #[test]
    fn debug_never_prints_a_name_a_label_or_a_word_of_a_screen() {
        let w = world(Still::Device);
        let tv = mac_of(31);
        let said = format!(
            "{:?} {:?} {:?} {:?} {:?} {:?}",
            WallView::of(&w, 0),
            TileView::of(&w.devices[SAM]),
            DeviceView::of(&w, &tv),
            ConfirmView::of(&w, &tv, true),
            ItsGateView::of(&w, &tv),
            Screen::Confirm {
                mac: tv,
                pass: true
            },
        );
        for secret in [
            "Sam",
            "phone",
            "Living",
            "room",
            "googlesyndication",
            "i.ytimg",
            "\u{b7}",
            "02:00",
            "[2, 0",
        ] {
            assert!(!said.contains(secret), "{said} holds {secret}");
        }
    }

    #[test]
    fn the_miniature_and_the_tile_agree_on_every_state() {
        // HOME's mini wall and the wall's tiles are made from the same rows: one place for each state.
        let states = [
            (DeviceState::Blocked, false, Place::Blocked),
            (DeviceState::AdsPass, false, Place::Pass),
            (DeviceState::Open { left_secs: 9 }, false, Place::Pass),
            (DeviceState::Always, false, Place::Blocked),
            (DeviceState::Blocked, true, Place::Asking),
            (DeviceState::AdsPass, true, Place::Asking),
        ];
        for (state, asking, place) in states {
            let mut device = row(3, Some("x"), state);
            device.asking = asking;
            assert_eq!(Place::of(&device), place, "{state:?} asking {asking}");
            assert_eq!(TileView::of(&device).asking, asking);
            assert_eq!(TileView::of(&device).state, state);
        }
        let rows = house_devices(&[1, 4]);
        let mini = mini_places(&rows);
        assert_eq!(mini[1], Place::Asking);
        assert_eq!(mini[2], Place::Blocked);
        assert_eq!(mini[10], Place::Empty);
        assert_eq!(mini_places(&crowd(30).devices).len(), MINI_PLACES);
    }
}
