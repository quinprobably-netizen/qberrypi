//! Where the panel is, and what a tap does (spec §4).
//!
//! The panel is at a root, one of the sections (or the gate), with a stack of screens opened above it
//! (`stage.js`: `go` replaces the stack, `open` pushes, `back` pops). A screen carries its argument by
//! identity (an alert by the store's id), never by index, so a screen whose thing is gone can tell, and
//! `refresh` pops it.
//!
//! A tap is decided by `decide`, which looks and changes nothing: it is the `Tap` of the spec, what the
//! press would do. `tap` decides and does it to the `Nav`, and gives back the `Intent` the system must
//! carry out, if the tap is one. The touch tracker decides at the press (`touch::TapTracker::feed_with`
//! takes `|x, y| target(...)`) so that a finger that leaves its key is not a tap, and the caller then
//! calls `tap` with the press point.
//!
//! Phase 1 (rulings R1 to R3 of the track lead): SYSTEM was the ABOUT reading, as the root of the section;
//! no strong action asks for a PIN, since there is no lock. Phase 3 makes SYSTEM's root the mimic (spec §12,
//! concept C): its doors open WI-FI, VERSION, UP, NIGHT HOURS, LOCK and ABOUT above it, and their `BACK` goes
//! back to the mimic.
//!
//! The lock (spec §7): a strong intent (`Intent::is_strong`, the list of §7.1) that a tap asks for while
//! `World::lock_on` does not go out. `tap` opens the PIN pad over the screen it came from, holding the intent and the
//! move that was to go with it; the fourth digit gives `Intent::Verify`, which the caller checks (on the panel
//! thread, against the lock) and answers with `verified`: right returns the held intent, to be carried out
//! as if it had just been tapped, and closes the pad; wrong clears it and says `WRONG PIN`; a wait says `WAIT m:ss`
//! and takes no digits. `SET A PIN` opens the pad to choose a PIN (and, with a PIN already set, to check the current
//! one first): the fourth digit gives `Intent::SetPin` and the pad closes. A pad that was opened to choose with the
//! lock off, and has not asked for a PIN, gives nothing if the lock is on by its fourth digit (the desktop pushed a PIN
//! meanwhile): it closes, the PIN in force stays, and the owner starts again, which asks for the current one.
//! `CANCEL` and a minute without a touch close the pad too, the action not done. With the lock off a strong intent
//! goes straight out, as before.
//!
//! The states of the whole system (STARTING, UPDATE, NIGHT) are entered and left by the caller (`set_whole`); they
//! answer only their own keys: NIGHT wakes to HOME on a touch, and a finished UPDATE goes HOME on a touch or, by
//! `age_update`, after 30 s.
//!
//! Phase 2 (spec §3.6, §3.7, §5.3, §12) adds ALERTS and NAMES. ALERTS is the log: its entries open ALERT (by
//! the store's id), whose `DISMISS` acks and goes back to the log and whose `SEE DEVICE` opens DEVICE over it,
//! and whose name line, for an alert about a name, opens NAME. NAMES is the manifold: a pipe opens NAME (by the
//! name's text), `YOUR OWN` opens YOUR LIST, whose pipes open NAME too; a NAME's keys give `Intent::Name`
//! (the strong ones are marked by `Intent::is_strong`) and go back. HOME's ALERTS and NAMES tiles, the lane's
//! `n ALERT(S)` and LIVE's share, funnel and count are doors to the roots. `arrive` is the arrival rule: a
//! new waiting alert opens its slip. A screen about a name is never gone, only not yet read (`NAME` draws the
//! bare lane until the loop has the name's facts); a slip whose alert is gone pops to the log.
//!
//! DEVICES is the wall of places (`screens::devices::wall_tap`: a tile opens DEVICE, `MORE · n` turns the
//! wall's page, which the `Nav` keeps while a screen is open over it and forgets at `go`), DEVICE, CONFIRM
//! and ITS GATE, each carrying its device by hardware address. CONFIRM carries the state it would take as
//! well, so what the screen asked is what a tap does whatever the device has become since. A name row of
//! DEVICE opens NAME, as a pipe of NAMES does: the world holds each watched name whole beside the text fitted
//! to its row (`WatchedName::whole`), and NAME is about a name by its whole text. DEVICE is the screen whose
//! device's names the loop watches (`Nav::watched_mac`): NAME over it stops the watch, as CONFIRM does, and
//! its `BACK` starts it again. `refresh` pops a screen whose device is gone or no longer fits it.
//!
//! LIVE is the Drain, which draws itself; its taps (the key, the gate ask over its field, the lane's
//! `HOME`, the clock column) are `screens::live::decide`, called from `decide`, and the gate ask's state, open
//! or shut with the time it has left, is the `Nav`'s own (`Nav::gate_ask`), where the routing and the caller
//! that draws the Drain both read it.

use std::fmt;

use crate::os::intent::{Digit, GateMove, Intent, PinDigits};
use crate::os::screens::lane::Says;
use crate::os::screens::{alerts, devices, gate, home, live, names, system, whole};
use crate::os::world::{Mac, World};
use crate::ui::look::{FLOOR_SPLIT_X, FLOOR_Y, LANE_CLOCK_X, LANE_HOME_X, LANE_TARGET_Y};

/// The most screens above the root: the deepest path is ALERTS, ALERT, DEVICE, CONFIRM, PIN (spec §4).
pub const MAX_STACK: usize = 6;

/// How long without a touch before the panel goes HOME by itself: a minute.
pub const IDLE_MS: u64 = 60_000;

/// How long the gate ask stays over LIVE's field before it folds away by itself: 8 s (the mockup's 64 frames at 8 a second).
pub const GATE_ASK_MS: u64 = 8_000;

/// How long a finished update (confirmed or rolled back) shows before the panel goes HOME by itself: 30 s (spec §5.4).
pub const UPDATE_DONE_MS: u64 = 30_000;

/// The root of the screen the panel shows: HOME, one of the five sections, or the gate, which
/// opens from HOME and is a root of its own (the lane says `GATE` and its word goes back HOME).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    /// HOME: the six tiles.
    Home,
    /// LIVE: the Drain.
    Live,
    /// DEVICES: the wall.
    Devices,
    /// ALERTS.
    Alerts,
    /// NAMES.
    Names,
    /// SYSTEM.
    System,
    /// The gate's choices, from HOME.
    Gate,
}

impl Section {
    /// The word the lane says for the section, in capitals: `HOME` for HOME.
    pub const fn word(self) -> &'static str {
        match self {
            Self::Home => "HOME",
            Self::Live => "LIVE",
            Self::Devices => "DEVICES",
            Self::Alerts => "ALERTS",
            Self::Names => "NAMES",
            Self::System => "SYSTEM",
            Self::Gate => "GATE",
        }
    }
}

/// A screen opened above a root. Its argument is the identity of the thing it is about.
///
/// ALERT (by the store's id), the three screens over a device (by hardware address), YOUR LIST and NAME (by its
/// text), and SYSTEM's six readings, which are about the board and carry nothing (NIGHT HOURS' draft is the
/// `Nav`'s). A screen that holds a device's address or a name must not print it in its `Debug`, which is written
/// by hand for that.
#[derive(Clone, PartialEq, Eq)]
pub enum Screen {
    /// ALERT: one alert, by the store's id.
    Alert(u64),
    /// YOUR LIST: the owner's own list of names, over NAMES.
    Yours,
    /// NAME: one name, by its whole text.
    Name(String),
    /// DEVICE: one device.
    Device(Mac),
    /// CONFIRM: before one device's ads change, with the state they would take: `pass` lets them pass,
    /// otherwise they are blocked.
    Confirm {
        /// The device.
        mac: Mac,
        /// Whether the change lets ads pass (`ALLOW ADS`, strong) rather than blocks them.
        pass: bool,
    },
    /// ITS GATE: the choices for opening one device's own gate.
    ItsGate(Mac),
    /// VERSION: what runs, in the plain reading, over SYSTEM.
    Version,
    /// WI-FI: the link drawn large, with `REJOIN`, over SYSTEM.
    Wifi,
    /// UP: the uptime and what the board feels, with `RESTART`, over SYSTEM.
    Uptime,
    /// NIGHT HOURS: the two hours, edited with `-` and `+` (the draft is `Nav::night_draft`), over SYSTEM.
    NightHours,
    /// LOCK: whether a PIN guards the strong keys, over SYSTEM.
    Lock,
    /// ABOUT: the board and the panel, over SYSTEM.
    About,
}

impl std::fmt::Debug for Screen {
    /// The screen's name and nothing it is about but what is no secret (which way a confirm goes).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Alert(_) => f.write_str("Alert"),
            Self::Yours => f.write_str("Yours"),
            Self::Name(_) => f.write_str("Name"),
            Self::Device(_) => f.write_str("Device"),
            Self::Confirm { pass, .. } => f
                .debug_struct("Confirm")
                .field("pass", pass)
                .finish_non_exhaustive(),
            Self::ItsGate(_) => f.write_str("ItsGate"),
            Self::Version => f.write_str("Version"),
            Self::Wifi => f.write_str("Wifi"),
            Self::Uptime => f.write_str("Uptime"),
            Self::NightHours => f.write_str("NightHours"),
            Self::Lock => f.write_str("Lock"),
            Self::About => f.write_str("About"),
        }
    }
}

/// A state of the whole system (spec §5.4): it takes the whole screen, draws its own lane and offers no
/// HOME. The caller enters and leaves them (`Nav::set_whole`); the nav knows that the first three are not timed out
/// of and answer no taps but their own, and that the PIN pad is timed out, back to where it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Whole {
    /// STARTING: the checklist while the panel comes up.
    Starting,
    /// UPDATE: receiving, on trial, confirmed or rolled back.
    Update,
    /// NIGHT: the dark clock. A touch wakes it.
    Night,
    /// The PIN pad: it is over the screen the action came from, and goes back to it.
    Pin,
}

/// What a tap does to where the panel is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// Go to the section's root: the stack is replaced (`go`).
    Go(Section),
    /// Go to the section's root and open a screen on it at once (the arrival of an alert opens its slip over ALERTS).
    GoOpen(Section, Screen),
    /// Open a screen above the one that shows (`open`).
    Open(Screen),
    /// Go back one screen (`back`).
    Back,
    /// Unfold the gate's choices over LIVE's field, for `GATE_ASK_MS` (the Drain's key, shut).
    OpenGateAsk,
    /// Fold the gate's choices away.
    CloseGateAsk,
    /// Show this page of the wall of devices (the `MORE · n` place turns it).
    DevicesPage(usize),
    /// NIGHT HOURS' `-` and `+`: the draft hours are now `(from, to)`; nothing is set until `DONE`.
    Hours(u8, u8),
    /// LOCK's `SET A PIN`: the pad opens to choose a PIN (`tap` makes it ask the current PIN first when the lock is on).
    ChoosePin,
    /// The PIN pad's digit key: this digit is typed. The digit prints in no `Debug`.
    PinDigit(Digit),
    /// The PIN pad's `<`: the last digit is taken back.
    PinErase,
}

/// What the PIN pad is for (spec §7).
#[derive(Clone, PartialEq, Eq)]
pub enum PinGoal {
    /// Ask for the PIN, and then carry out the strong intent held here, and make the move that went with it.
    Do {
        /// The intent the tap asked for, which waits for the PIN.
        intent: Intent,
        /// The move the tap made along with it, made when the PIN is right (`Back` out of a confirm).
        then: Option<Change>,
    },
    /// Ask for the current PIN, and then let the owner choose a new one: setting a PIN while one is set is strong.
    Change,
    /// Choose a PIN: the four digits typed are it (`Intent::SetPin`).
    Choose,
}

impl fmt::Debug for PinGoal {
    /// Which it is, and nothing of the intent held.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Do { .. } => "Do",
            Self::Change => "Change",
            Self::Choose => "Choose",
        })
    }
}

/// The PIN pad: what it is for, the digits typed so far, whether the last try was wrong, and how long it was told to
/// wait. The digits are held wiped-on-drop and no `Debug` prints them (spec §7.3).
#[derive(Clone, PartialEq, Eq)]
pub struct PinPad {
    /// What the pad is for.
    goal: PinGoal,
    /// The digits typed, the first `typed` of them.
    digits: PinDigits,
    /// How many digits are typed, 0 to 4.
    typed: u8,
    /// Whether the last try was wrong: `WRONG PIN`, until the next digit.
    wrong: bool,
    /// The seconds the lock's last answer said to wait, which show until the next world says what is left.
    wait_hint: Option<u32>,
    /// How many screens were open above the root when the pad opened: the pad is dropped if fewer are left (the
    /// screen the action came from is gone).
    depth: usize,
    /// Whether the current PIN was asked for and was right: the pad that chooses a PIN after `PinGoal::Change` has
    /// it, and the one opened to choose with the lock off has not.
    proved: bool,
}

impl fmt::Debug for PinPad {
    /// The goal's kind and how many digits are typed; never which.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinPad")
            .field("goal", &self.goal)
            .field("typed", &self.typed)
            .field("wrong", &self.wrong)
            .finish_non_exhaustive()
    }
}

impl PinPad {
    /// A pad for `goal`, opened over `depth` screens.
    fn new(goal: PinGoal, depth: usize) -> Self {
        Self {
            goal,
            digits: PinDigits::new([0; 4]),
            typed: 0,
            wrong: false,
            wait_hint: None,
            depth,
            proved: false,
        }
    }

    /// What the pad is for.
    pub fn goal(&self) -> &PinGoal {
        &self.goal
    }

    /// How many digits are typed, 0 to 4.
    pub fn len(&self) -> usize {
        usize::from(self.typed)
    }

    /// Whether no digit is typed.
    pub fn is_empty(&self) -> bool {
        self.typed == 0
    }

    /// Whether the last try was wrong (`WRONG PIN`).
    pub fn wrong(&self) -> bool {
        self.wrong
    }

    /// The seconds the pad must wait before it takes digits: what the world says is left of the lock's wait; until the
    /// first world after the lock's answer, the answer's own figure.
    pub fn wait_secs(&self, world: &World) -> u32 {
        if world.pin_wait_secs > 0 {
            world.pin_wait_secs
        } else {
            self.wait_hint.unwrap_or(0)
        }
    }

    /// The digits typed with `digit` as the next: the fourth completes the PIN.
    pub fn digits_with(&self, digit: Digit) -> PinDigits {
        let mut digits = self.digits.clone();
        digits.put(self.len(), digit);
        digits
    }

    /// Types a digit, if there is room; any digit clears `WRONG PIN`.
    fn type_digit(&mut self, digit: Digit) {
        if self.typed < 4 {
            self.digits.put(self.len(), digit);
            self.typed += 1;
            self.wrong = false;
        }
    }

    /// Takes the last digit back.
    fn erase(&mut self) {
        if self.typed > 0 {
            self.typed -= 1;
            self.digits.put(self.len(), Digit::new(0));
        }
    }

    /// Takes every digit back and wipes them.
    fn clear(&mut self) {
        self.digits.wipe();
        self.typed = 0;
    }
}

/// The lock's answer to the digits the pad gave (`Intent::Verify`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verified {
    /// The PIN is right.
    Right,
    /// It is wrong: `WRONG PIN`, and the digits are cleared.
    Wrong,
    /// The lock makes the owner wait this many seconds: `WAIT m:ss`, no digits are taken. The loop puts what is left
    /// in `World::pin_wait_secs` each time it makes a world while the pad shows.
    Wait(u32),
}

/// What a press would do (spec §4's `Tap`).
///
/// The spec has `None`, `Nav(change)` and `Act(Intent)`; an act can also move the panel (a gate key
/// opens the gate and goes back, `DISMISS` acks and goes HOME), so `Act` carries the move too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tap {
    /// Nothing: a press on nothing, or on a key that is inert.
    None,
    /// The panel moves.
    Nav(Change),
    /// The system must do something, and the panel may move as well.
    Act(Intent, Option<Change>),
}

/// Where the panel is: a root, the screens above it, and the state of the whole system over it, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nav {
    /// The section the panel is under.
    root: Section,
    /// The screens opened above the root, the last on top; at most `MAX_STACK`.
    stack: Vec<Screen>,
    /// A state of the whole system, which covers all of it.
    whole: Option<Whole>,
    /// The gate ask over LIVE's field: the milliseconds it has left, `None` while it is folded away. It is
    /// part of where the panel is, so that a tap is decided by it and the Drain is drawn from it.
    gate_ask: Option<u64>,
    /// The page of the wall of devices that DEVICES shows, from 0. A screen opened over the wall leaves it as
    /// it is, so that back is the page it came from; going to a root starts the wall over at its first page.
    devices_page: usize,
    /// The night hours NIGHT HOURS is editing, `(from, to)`, once a `-` or `+` has changed them; `None` while the
    /// screen shows the hours the world has. It belongs to the screen, and goes with it.
    night: Option<(u8, u8)>,
    /// The PIN pad, while it covers the screen (`whole` is `Pin`): what it is for and the digits typed.
    pin: Option<PinPad>,
    /// How long a finished update has shown, in milliseconds (`age_update`).
    update_done_ms: u64,
}

impl Default for Nav {
    fn default() -> Self {
        Self::new()
    }
}

impl Nav {
    /// The panel at HOME.
    pub fn new() -> Self {
        Self::at(Section::Home)
    }

    /// The panel at a section's root.
    pub fn at(root: Section) -> Self {
        Self {
            root,
            stack: Vec::with_capacity(MAX_STACK),
            whole: None,
            gate_ask: None,
            devices_page: 0,
            night: None,
            pin: None,
            update_done_ms: 0,
        }
    }

    /// The section the panel is under.
    pub fn root(&self) -> Section {
        self.root
    }

    /// The screens above the root, the one that shows last.
    pub fn stack(&self) -> &[Screen] {
        &self.stack
    }

    /// The screen that shows, if one is open above the root.
    pub fn top(&self) -> Option<&Screen> {
        self.stack.last()
    }

    /// The state of the whole system that covers the screen, if there is one.
    pub fn whole(&self) -> Option<Whole> {
        self.whole
    }

    /// Whether the gate ask is unfolded over LIVE's field: the Drain is drawn with it (`Stills::gate_ask`) and
    /// any press folds it away or picks a choice (`screens::live::decide`).
    pub fn gate_ask(&self) -> bool {
        self.gate_ask.is_some()
    }

    /// How many milliseconds the gate ask has left before it folds away; `None` while it is folded away.
    pub fn gate_ask_left_ms(&self) -> Option<u64> {
        self.gate_ask
    }

    /// Whether the panel is at HOME itself, with nothing open and nothing over it.
    pub fn is_home(&self) -> bool {
        self.root == Section::Home && self.stack.is_empty() && self.whole.is_none()
    }

    /// The hours NIGHT HOURS shows when they were changed on it and not yet set by `DONE`; `None` otherwise,
    /// and always when another screen shows.
    pub fn night_draft(&self) -> Option<(u8, u8)> {
        self.night
            .filter(|_| matches!(self.stack.last(), Some(Screen::NightHours)))
    }

    /// The page of the wall of devices DEVICES shows, from 0; the screen clamps it to the pages there are.
    pub fn devices_page(&self) -> usize {
        self.devices_page
    }

    /// The device whose names the loop is to watch: the one DEVICE shows, while it is the screen that shows
    /// (spec §6.2: names stream only while that device's screen is open; CONFIRM, ITS GATE and a state of
    /// the whole system over it stop the watch, and its ring with it). The loop turns this into the lane
    /// feed's `watch_client` on each change, `None` clearing it.
    pub fn watched_mac(&self) -> Option<Mac> {
        match (self.whole, self.stack.last()) {
            (None, Some(&Screen::Device(mac))) => Some(mac),
            _ => None,
        }
    }

    /// Whether a screen about names shows (NAMES, YOUR LIST or NAME): the loop reads the day's most refused
    /// and the owner's list (every 5 s) only then, and never under a state of the whole system (spec §5.2).
    pub fn shows_names(&self) -> bool {
        self.whole.is_none()
            && match self.stack.last() {
                Some(Screen::Yours | Screen::Name(_)) => true,
                Some(_) => false,
                None => self.root == Section::Names,
            }
    }

    /// The name NAME shows, while it is the screen that shows: the loop reads its facts (`World::name_facts`) for it.
    pub fn shown_name(&self) -> Option<&str> {
        match (self.whole, self.stack.last()) {
            (None, Some(Screen::Name(name))) => Some(name),
            _ => None,
        }
    }

    /// Goes to a section's root: the stack is emptied, no state of the whole system covers it, the gate ask
    /// is folded away (it belongs to LIVE) and the wall of devices is back at its first page.
    pub fn go(&mut self, section: Section) {
        self.root = section;
        self.stack.clear();
        self.whole = None;
        self.pin = None;
        self.update_done_ms = 0;
        self.gate_ask = None;
        self.devices_page = 0;
        self.night = None;
    }

    /// Opens a screen above the one that shows (which folds the gate ask away: it is LIVE's own). A stack that
    /// is full has its top replaced.
    pub fn open(&mut self, screen: Screen) {
        self.gate_ask = None;
        self.night = None;
        if self.stack.len() >= MAX_STACK {
            self.stack.pop();
        }
        self.stack.push(screen);
    }

    /// Goes back one screen. At a root there is none to go back to: the panel goes HOME, which is where
    /// the `BACK` of a section's only screen and of the gate lead.
    pub fn back(&mut self) {
        self.night = None;
        if self.whole == Some(Whole::Pin) {
            self.close_pin();
        } else if self.stack.pop().is_none() {
            self.go(Section::Home);
        }
    }

    /// The PIN pad, while it covers the screen.
    pub fn pin(&self) -> Option<&PinPad> {
        self.pin.as_ref()
    }

    /// Opens the PIN pad over the screen that shows, for `goal`. The screens under it stay as they are, and come back
    /// when the pad closes.
    pub fn open_pin(&mut self, goal: PinGoal) {
        self.gate_ask = None;
        self.update_done_ms = 0;
        self.pin = Some(PinPad::new(goal, self.stack.len()));
        self.whole = Some(Whole::Pin);
    }

    /// Closes the PIN pad, wherever it came from, and drops what it held.
    fn close_pin(&mut self) {
        self.pin = None;
        if self.whole == Some(Whole::Pin) {
            self.whole = None;
        }
    }

    /// Covers the screen with a state of the whole system, or lifts it. A PIN pad covers what it came
    /// from and goes back to it; the others leave to HOME.
    pub fn set_whole(&mut self, whole: Option<Whole>) {
        if whole.is_none() && self.whole.is_some_and(|was| was != Whole::Pin) {
            self.go(Section::Home);
        }
        if whole.is_some() {
            self.gate_ask = None;
        }
        self.update_done_ms = 0;
        // A pad lives only as the state it is: one entered through here, rather than `open_pin`, is the pad that
        // chooses a PIN; any other state, or none, has no pad.
        self.pin = match whole {
            Some(Whole::Pin) => Some(
                self.pin
                    .take()
                    .unwrap_or_else(|| PinPad::new(PinGoal::Choose, self.stack.len())),
            ),
            _ => None,
        };
        self.whole = whole;
    }

    /// Does what a tap decided.
    pub fn apply(&mut self, change: Change) {
        match change {
            Change::Go(section) => self.go(section),
            Change::GoOpen(section, screen) => {
                self.go(section);
                self.open(screen);
            }
            Change::Open(screen) => self.open(screen),
            Change::Back => self.back(),
            // The ask is LIVE's: nowhere else is there a field to unfold it over.
            Change::OpenGateAsk => {
                self.gate_ask = (self.is_live() && self.stack.is_empty() && self.whole.is_none())
                    .then_some(GATE_ASK_MS);
            }
            Change::CloseGateAsk => self.gate_ask = None,
            Change::DevicesPage(page) => self.devices_page = page,
            Change::Hours(from, to) => {
                if self.night_screen() {
                    self.night = Some((from, to));
                }
            }
            // The lock is off, or the caller is `tap`, which asks the current PIN first when it is on.
            Change::ChoosePin => self.open_pin(PinGoal::Choose),
            Change::PinDigit(digit) => {
                if let Some(pad) = self.pin.as_mut() {
                    pad.type_digit(digit);
                }
            }
            Change::PinErase => {
                if let Some(pad) = self.pin.as_mut() {
                    pad.erase();
                }
            }
        }
    }

    /// Whether NIGHT HOURS is the screen that shows.
    fn night_screen(&self) -> bool {
        matches!(self.stack.last(), Some(Screen::NightHours))
    }

    /// Whether LIVE is the root.
    fn is_live(&self) -> bool {
        self.root == Section::Live
    }
}

/// What a press at `(x, y)` would do on the screen that shows; nothing is changed. It is also the
/// press's target: two presses with equal results are on the same key, so a finger that slides to
/// another key is not a tap.
pub fn decide(nav: &Nav, world: &World, x: u16, y: u16) -> Tap {
    match nav.whole() {
        // The states of the whole system answer only their own keys: the pad's twelve, a touch on NIGHT (which wakes
        // to HOME), a touch on an update that has ended (HOME). STARTING has none.
        Some(Whole::Pin) => return whole::pin_tap(nav.pin(), world, x, y),
        Some(Whole::Night) => return Tap::Nav(Change::Go(Section::Home)),
        Some(Whole::Update) if world.update.is_some_and(|update| update.phase.is_done()) => {
            return Tap::Nav(Change::Go(Section::Home));
        }
        Some(Whole::Update | Whole::Starting) => return Tap::None,
        None => {}
    }
    if nav.is_live() && nav.stack().is_empty() {
        // The Drain's own screen: its taps are its own (the key, the ask, the readings that are doors).
        return live::decide(nav, world, x, y);
    }
    if y < LANE_TARGET_Y {
        return lane(nav, world, x);
    }
    let (floor, left) = (y >= FLOOR_Y, x < FLOOR_SPLIT_X);
    match (nav.root(), nav.top()) {
        (Section::Home, None) => home_door(world, x, y),
        (Section::Gate, None) => gate_key(x, floor),
        (Section::System, None) => system::system_tap(x, y),
        (Section::Alerts, None) => alerts::log_tap(world, x, y),
        (Section::Names, None) => names::names_tap(world, x, y),
        (Section::Devices, None) => devices::wall_tap(nav.devices_page(), world, x, y),
        // The screens over a root do not depend on how the panel came to them: a device's from the wall or
        // from an alert's `SEE DEVICE`, a name's from NAMES, YOUR LIST or a threat's slip.
        (_, Some(&Screen::Alert(id))) => alerts::alert_tap(world, id, x, y),
        (_, Some(Screen::Yours)) => names::yours_tap(world, x, y),
        (_, Some(Screen::Name(name))) => names::name_tap(world, name, x, y),
        (_, Some(&Screen::Device(mac))) => devices::device_tap(world, mac, x, y),
        (_, Some(&Screen::Confirm { mac, pass })) => devices::confirm_tap(world, mac, pass, x, y),
        (_, Some(&Screen::ItsGate(mac))) => devices::its_gate_tap(world, mac, x, y),
        (_, Some(Screen::Version | Screen::About)) => system::back_tap(floor, left),
        (_, Some(Screen::Wifi)) => system::wifi_tap(world, floor, left),
        (_, Some(Screen::Uptime)) => system::uptime_tap(world, floor, left),
        (_, Some(Screen::NightHours)) => system::night_tap(nav.night_draft(), world, x, y),
        (_, Some(Screen::Lock)) => system::lock_tap(world, floor, left),
        _ => Tap::None,
    }
}

/// Decides what a press at `(x, y)` does, does it to the panel, and gives back what the system must do.
///
/// A strong intent (spec §7.1) is not returned while `world.lock_on`: the PIN pad opens over the screen, holding
/// the intent and the move that went with it, and is left to `verified` to give them back. With the lock off it is
/// returned as it is. `SET A PIN` opens the pad to choose a PIN, which first asks the current one when the lock is
/// on (setting a new PIN while one is set is strong). The pad's own intents, `Verify` and the `SetPin` of a PIN
/// just chosen, come out as they are: they are the asking and its answer.
pub fn tap(nav: &mut Nav, world: &World, x: u16, y: u16) -> Option<Intent> {
    match decide(nav, world, x, y) {
        Tap::None => None,
        Tap::Nav(Change::ChoosePin) => {
            nav.open_pin(choose_goal(world));
            None
        }
        Tap::Nav(change) => {
            nav.apply(change);
            None
        }
        // A pad that was opened to choose a PIN while the lock was off, and has not asked for one: the lock came on
        // since (the desktop pushed a PIN), so its fourth digit would replace a PIN that was never asked for. The pad
        // closes and nothing is done; `SET A PIN` then asks for the current PIN first.
        Tap::Act(Intent::SetPin(_), _)
            if world.lock_on
                && nav
                    .pin()
                    .is_some_and(|pad| pad.goal == PinGoal::Choose && !pad.proved) =>
        {
            nav.close_pin();
            None
        }
        Tap::Act(intent, then) => {
            if world.lock_on && intent.is_strong() && nav.whole().is_none() {
                nav.open_pin(PinGoal::Do { intent, then });
                return None;
            }
            if let Some(change) = then {
                nav.apply(change);
            }
            Some(intent)
        }
    }
}

/// What the pad is for when the owner chooses a PIN: with none set, to choose; with one set, to check it first, since
/// setting a new PIN while one is set is a strong action (spec §7.1).
fn choose_goal(world: &World) -> PinGoal {
    if world.lock_on {
        PinGoal::Change
    } else {
        PinGoal::Choose
    }
}

/// Takes the lock's answer to the digits the pad gave (`Intent::Verify`). Right closes the pad and gives back the
/// intent it held, for the caller to carry out, after the move that went with it (the pad of a PIN change turns into
/// the pad that chooses the new one, and gives nothing yet); wrong clears the digits and says `WRONG PIN`; a wait
/// clears them and says `WAIT m:ss` (`World::pin_wait_secs` keeps the count from there). Nothing happens, and nothing is
/// given, when no pad covers the screen: the pad timed out or was cancelled while the lock checked.
pub fn verified(nav: &mut Nav, answer: Verified) -> Option<Intent> {
    if nav.whole != Some(Whole::Pin) {
        return None;
    }
    let pad = nav.pin.as_mut()?;
    match answer {
        Verified::Wrong => {
            pad.clear();
            pad.wrong = true;
            pad.wait_hint = None;
            None
        }
        Verified::Wait(secs) => {
            pad.clear();
            pad.wrong = false;
            pad.wait_hint = Some(secs);
            None
        }
        Verified::Right => match pad.goal.clone() {
            PinGoal::Do { intent, then } => {
                nav.close_pin();
                if let Some(change) = then {
                    nav.apply(change);
                }
                Some(intent)
            }
            PinGoal::Change => {
                pad.goal = PinGoal::Choose;
                pad.proved = true;
                pad.clear();
                pad.wrong = false;
                pad.wait_hint = None;
                None
            }
            // A pad that chooses a PIN asks nothing of the lock.
            PinGoal::Choose => None,
        },
    }
}

/// Lets `elapsed_ms` pass for a finished update (confirmed or rolled back), which goes HOME by itself after
/// `UPDATE_DONE_MS`. Says whether it went HOME now. The caller runs it each frame with the time since its last call;
/// the time counts only while UPDATE shows a finished update (it starts over for the next one), and a touch ends it
/// sooner, as the tap that goes HOME.
pub fn age_update(nav: &mut Nav, world: &World, elapsed_ms: u64) -> bool {
    let finished = nav.whole == Some(Whole::Update)
        && world.update.is_some_and(|update| update.phase.is_done());
    if !finished {
        nav.update_done_ms = 0;
        return false;
    }
    nav.update_done_ms = nav.update_done_ms.saturating_add(elapsed_ms);
    if nav.update_done_ms >= UPDATE_DONE_MS {
        nav.go(Section::Home);
        true
    } else {
        false
    }
}

/// Lets `elapsed_ms` pass for the gate ask, which folds away by itself once it has been open `GATE_ASK_MS`.
/// Says whether it folded away now (the Drain is to be drawn without it). The caller runs it each frame it
/// is on LIVE, with the time since its last call; a touch does not start it over, since any touch ends it.
pub fn age_ask(nav: &mut Nav, elapsed_ms: u64) -> bool {
    let Some(left) = nav.gate_ask else {
        return false;
    };
    if elapsed_ms >= left {
        nav.gate_ask = None;
        true
    } else {
        nav.gate_ask = Some(left - elapsed_ms);
        false
    }
}

/// Takes the panel HOME after a minute without a touch, from any screen but HOME and the states of the
/// whole system; a PIN pad that is left alone goes back to where it came from. `idle_ms` is how long it
/// has been since the last touch. Says whether the panel moved.
pub fn idle(nav: &mut Nav, idle_ms: u64) -> bool {
    if idle_ms < IDLE_MS {
        return false;
    }
    match nav.whole() {
        Some(Whole::Pin) => nav.set_whole(None),
        Some(Whole::Starting | Whole::Update | Whole::Night) => return false,
        None if nav.is_home() => return false,
        None => nav.go(Section::Home),
    }
    true
}

/// Whether the thing a screen is about is gone, or no longer fits the screen. A name is never gone: it is
/// about a text, and the world either has its facts yet or not (`screens::names::NameView::of`). SYSTEM's
/// readings are about the board, which is there.
fn gone(world: &World, screen: &Screen) -> bool {
    match *screen {
        Screen::Alert(id) => world.alert(id).is_none(),
        // None of these is about a thing that can go: SYSTEM's readings are about the board itself.
        Screen::Yours
        | Screen::Name(_)
        | Screen::Version
        | Screen::Wifi
        | Screen::Uptime
        | Screen::NightHours
        | Screen::Lock
        | Screen::About => false,
        Screen::Device(mac) => world.device(&mac).is_none(),
        Screen::Confirm { mac, pass } => !devices::confirm_valid(world, &mac, pass),
        Screen::ItsGate(mac) => !devices::gate_valid(world, &mac),
    }
}

/// Pops the screens whose thing is gone, and says whether the panel moved. The caller runs it each time it
/// has a new `World`.
///
/// - An ALERT whose alert is no longer in the log (it was dismissed on the desktop, or it has fallen out of the
///   newest three) goes back to the log, and so does everything opened over it.
/// - A DEVICE whose address left the world (the device was forgotten) goes back to the screen under it (the
///   wall, or the slip that named it), and so does everything opened over it.
/// - A CONFIRM that is not true any more (the desktop changed the device's ads, the configuration took
///   over, it went) and an ITS GATE with no gate to open (its ads pass, the gate is open) go back to the screen under
///   them, which shows the device as it is.
/// - The wall's page, if the wall shrank under it, moves to the last page there is.
pub fn refresh(nav: &mut Nav, world: &World) -> bool {
    let mut moved = false;
    if let Some(at) = nav.stack.iter().position(|screen| gone(world, screen)) {
        moved = true;
        nav.stack.truncate(at);
    }
    let page = devices::clamp_page(nav.devices_page, world.devices.len());
    if page != nav.devices_page {
        nav.devices_page = page;
        moved = true;
    }
    // A pad whose screen is gone has nowhere to go back to, and what it held was about a thing that is not there:
    // it closes, the action not done. A wait the lock last told stands only until a world says what is left of it.
    if let Some(pad) = nav.pin.as_mut() {
        pad.wait_hint = None;
        if nav.stack.len() < pad.depth {
            nav.close_pin();
            moved = true;
        }
    }
    moved
}

/// Which alerts the panel has shown: the arrival rule's memory (spec §5.3).
///
/// The store's ids only grow, so what the panel has shown or passed over is one number, the highest id.
/// `arrive` opens an alert whose id is above it, once. It lives in the caller beside the `Nav`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Arrivals {
    /// The highest id shown or passed over; 0 before any.
    shown: u64,
}

impl Arrivals {
    /// A panel that has shown nothing: every waiting alert is new to it.
    pub const fn new() -> Self {
        Self { shown: 0 }
    }
}

/// The arrival rule (spec §5.3): a new waiting alert, one the panel has not shown, opens ALERTS and its slip
/// from any screen but a state of the whole system. If several are new in one refresh, the newest high one
/// opens (else the newest), and the others are passed over: they wait in the log, where the tile and the
/// lane count them. An alert is shown once: going back, or the idle minute, leaves it waiting.
///
/// A state of the whole system (starting, update, night, the PIN) leaves the alerts new: the panel shows
/// them when the state ends and the next `World` comes, and an alert at night does not light the screen
/// (spec §5.4). Says whether the panel moved. The caller runs it each time it has a new `World`, after
/// `refresh`.
pub fn arrive(nav: &mut Nav, arrivals: &mut Arrivals, world: &World) -> bool {
    if nav.whole().is_some() {
        return false;
    }
    let new = || world.alerts.iter().filter(|row| row.id > arrivals.shown);
    let Some(pick) = new().find(|row| row.high).or_else(|| new().next()) else {
        return false;
    };
    let id = pick.id;
    arrivals.shown = world
        .alerts
        .iter()
        .map(|row| row.id)
        .max()
        .unwrap_or(id)
        .max(id);
    nav.apply(Change::GoOpen(Section::Alerts, Screen::Alert(id)));
    true
}

/// The lane (spec §3.1): HOME on the left, SYSTEM on the clock, and between them the section's word.
fn lane(nav: &Nav, world: &World, x: u16) -> Tap {
    if x < LANE_HOME_X {
        return Tap::Nav(Change::Go(Section::Home));
    }
    let root = nav.root();
    if x >= LANE_CLOCK_X {
        return Tap::Nav(Change::Go(Section::System));
    }
    match root {
        // The words say the system, and are the door to what they say.
        Section::Home => match Says::of(world) {
            Says::Alerts(_) => Tap::Nav(Change::Go(Section::Alerts)),
            Says::GateOpen => Tap::Act(Intent::Gate(GateMove::Shut), None),
            Says::AllWell => Tap::Nav(Change::Go(Section::Live)),
        },
        // The gate is a root of its own, from HOME, and its word goes back there.
        Section::Gate => Tap::Nav(Change::Go(Section::Home)),
        section => Tap::Nav(Change::Go(section)),
    }
}

/// HOME's six tiles (`wallHit`): LIVE, DEVICES, ALERTS; the gate key, NAMES, SYSTEM.
fn home_door(world: &World, x: u16, y: u16) -> Tap {
    match home::wall_hit(x, y) {
        Some(home::LIVE) => Tap::Nav(Change::Go(Section::Live)),
        Some(home::DEVICES) => Tap::Nav(Change::Go(Section::Devices)),
        Some(home::ALERTS) => Tap::Nav(Change::Go(Section::Alerts)),
        // The key: shut, it opens the gate's choices; open, it shuts the gate at once.
        Some(home::GATE) if world.gate_open() => Tap::Act(Intent::Gate(GateMove::Shut), None),
        Some(home::GATE) => Tap::Nav(Change::Go(Section::Gate)),
        Some(home::NAMES) => Tap::Nav(Change::Go(Section::Names)),
        Some(home::SYSTEM) => Tap::Nav(Change::Go(Section::System)),
        _ => Tap::None,
    }
}

/// GATE's four keys: `KEEP SHUT` goes back; 5 MIN, 30 MIN and 1 HOUR open the gate and go back.
fn gate_key(x: u16, floor: bool) -> Tap {
    if !floor {
        return Tap::None;
    }
    match gate::key_secs(x) {
        Some(secs) => Tap::Act(Intent::Gate(GateMove::Open(secs)), Some(Change::Back)),
        None => Tap::Nav(Change::Back),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::os::fixture::{Still, mac_of, world};
    use crate::os::intent::Verdict;
    use crate::os::world::{AlertRow, Pause, UpdatePhase, UpdateRead};

    /// Taps once at a point on a nav, and says what the system is asked to do.
    fn press(nav: &mut Nav, world: &World, x: u16, y: u16) -> Option<Intent> {
        tap(nav, world, x, y)
    }

    /// A nav at HOME that has gone to a root and opened what the fixture's still has open.
    fn at(still: Still) -> (Nav, World) {
        let world = world(still);
        (still.nav(&world), world)
    }

    #[test]
    fn the_words_fit_the_lane_between_home_and_the_clock() {
        for section in [
            Section::Home,
            Section::Live,
            Section::Devices,
            Section::Alerts,
            Section::Names,
            Section::System,
            Section::Gate,
        ] {
            // Cells 5 to 11 hold a section's word: seven letters at most.
            assert!(section.word().len() <= 7, "{section:?}");
            assert!(section.word().chars().all(|c| c.is_ascii_uppercase()));
        }
        assert_eq!(Section::Devices.word(), "DEVICES");
    }

    #[test]
    fn go_replaces_the_stack_open_pushes_and_back_pops() {
        let mut nav = Nav::new();
        assert!(nav.is_home() && nav.stack().is_empty());
        nav.go(Section::Alerts);
        nav.open(Screen::Alert(1));
        nav.open(Screen::Alert(2));
        assert_eq!(nav.root(), Section::Alerts);
        assert_eq!(nav.stack(), [Screen::Alert(1), Screen::Alert(2)]);
        assert_eq!(nav.top(), Some(&Screen::Alert(2)));
        nav.back();
        assert_eq!(nav.stack(), [Screen::Alert(1)]);
        nav.go(Section::Devices);
        assert_eq!((nav.root(), nav.stack().len()), (Section::Devices, 0));
        // At a root, back is HOME.
        nav.back();
        assert!(nav.is_home());
        nav.back();
        assert!(nav.is_home(), "HOME has nowhere to go back to");
    }

    #[test]
    fn a_push_past_the_bound_replaces_the_top() {
        let mut nav = Nav::at(Section::Alerts);
        for id in 0..MAX_STACK as u64 {
            nav.open(Screen::Alert(id));
        }
        assert_eq!(nav.stack().len(), MAX_STACK);
        nav.open(Screen::Alert(100));
        assert_eq!(nav.stack().len(), MAX_STACK, "no deeper");
        assert_eq!(nav.top(), Some(&Screen::Alert(100)));
        assert_eq!(
            nav.stack()[MAX_STACK - 2],
            Screen::Alert(MAX_STACK as u64 - 2)
        );
        for _ in 0..MAX_STACK {
            nav.back();
        }
        assert!(nav.stack().is_empty() && nav.root() == Section::Alerts);
    }

    #[test]
    fn a_screen_is_about_an_identity_and_debug_says_none_of_it() {
        let said = format!(
            "{:?} {:?}",
            Screen::Alert(987_654),
            Nav::at(Section::Alerts)
        );
        assert!(!said.contains("987654"), "{said}");
        let tap = Tap::Act(
            Intent::Ack(987_654),
            Some(Change::Open(Screen::Alert(987_654))),
        );
        assert!(
            format!("{tap:?}").contains("987654"),
            "an alert's id is no secret"
        );
    }

    // ---- the tap table ----

    /// Where the middle of HOME's tile `i` is.
    fn tile_centre(i: u16) -> (u16, u16) {
        (8 + (i % 3) * 157 + 75, 80 + (i / 3) * 116 + 54)
    }

    #[test]
    fn homes_six_doors_lead_where_the_map_says() {
        let (home, world) = at(Still::Home);
        let go = |tile: u16| {
            let mut nav = home.clone();
            let (x, y) = tile_centre(tile);
            let intent = press(&mut nav, &world, x, y);
            (nav.root(), nav.stack().len(), intent)
        };
        assert_eq!(go(0), (Section::Live, 0, None));
        assert_eq!(go(1), (Section::Devices, 0, None));
        assert_eq!(
            go(2),
            (Section::Alerts, 0, None),
            "ALERTS: the log, even with none waiting (it says so)"
        );
        assert_eq!(
            go(3),
            (Section::Gate, 0, None),
            "the gate key, shut: the choices"
        );
        assert_eq!(go(4), (Section::Names, 0, None));
        assert_eq!(go(5), (Section::System, 0, None));
        // None of them changed the nav they were cloned from.
        assert!(home.is_home());
    }

    #[test]
    fn the_alerts_tile_opens_the_log_and_an_entry_opens_its_slip() {
        let (mut nav, world) = at(Still::HomeAlert);
        let (x, y) = tile_centre(2);
        assert_eq!(press(&mut nav, &world, x, y), None);
        assert_eq!((nav.root(), nav.stack().len()), (Section::Alerts, 0));
        // The newest entry is the last printed, at the bottom: its slip, by the store's id.
        assert_eq!(press(&mut nav, &world, 200, 240), None);
        assert_eq!(
            nav.stack(),
            [Screen::Alert(4)],
            "the store's id, not the place"
        );
    }

    #[test]
    fn the_gate_key_opens_the_choices_when_shut_and_shuts_when_open() {
        let (mut nav, world) = at(Still::HomeOpen);
        let (x, y) = tile_centre(3);
        assert_eq!(
            press(&mut nav, &world, x, y),
            Some(Intent::Gate(GateMove::Shut))
        );
        assert!(nav.is_home(), "it shuts at once, and the panel stays");
        let (mut nav, world) = at(Still::Home);
        assert_eq!(press(&mut nav, &world, x, y), None);
        assert_eq!(nav.root(), Section::Gate);
    }

    #[test]
    fn a_door_is_its_tile_and_a_margin_and_the_gaps_are_nothing() {
        let (nav, world) = at(Still::Home);
        // `wallHit`: rows from y 76 (the second from 192), columns from x 4 (the second from 161, the third
        // from 318); the last row and column go on to the screen's edge.
        let live = Tap::Nav(Change::Go(Section::Live));
        let devices = Tap::Nav(Change::Go(Section::Devices));
        for (x, y) in [(8, 80), (157, 187), (4, 76), (160, 191), (0, 100)] {
            assert_eq!(decide(&nav, &world, x, y), live, "({x}, {y})");
        }
        for (x, y) in [(161, 100), (317, 191), (200, 76)] {
            assert_eq!(decide(&nav, &world, x, y), devices, "({x}, {y})");
        }
        // The rows between the lane and the tiles are nothing.
        assert_eq!(decide(&nav, &world, 100, 75), Tap::None);
        assert_eq!(decide(&nav, &world, 100, 72), Tap::None);
        assert_eq!(
            decide(&nav, &world, 479, 319),
            Tap::Nav(Change::Go(Section::System))
        );
        // The mockup's `wallHit` has x < 4 on the second row reach the third tile (column -1 plus 3); here
        // it is the first column, the gate key.
        assert_eq!(
            decide(&nav, &world, 0, 300),
            Tap::Nav(Change::Go(Section::Gate))
        );
    }

    #[test]
    fn the_lane_on_home_says_a_door_and_the_clock_is_system() {
        // ALL WELL goes to LIVE; GATE OPEN shuts the gate; n ALERTS opens the top alert.
        let (mut nav, world) = at(Still::Home);
        assert_eq!(press(&mut nav, &world, 200, 40), None);
        assert_eq!(nav.root(), Section::Live);
        let (mut nav, world) = at(Still::HomeOpen);
        assert_eq!(
            press(&mut nav, &world, 200, 40),
            Some(Intent::Gate(GateMove::Shut))
        );
        assert!(nav.is_home());
        let (mut nav, world) = at(Still::HomeAlert);
        assert_eq!(press(&mut nav, &world, 200, 40), None);
        assert_eq!((nav.root(), nav.stack().len()), (Section::Alerts, 0));
        // Alerts come before the gate, as the lane's words do.
        let (mut nav, mut world) = at(Still::HomeAlert);
        world.blocking = Some(Pause {
            left_secs: 100,
            total_secs: 300,
        });
        assert_eq!(press(&mut nav, &world, 200, 40), None);
        assert_eq!(nav.root(), Section::Alerts);
        // The clock opens SYSTEM, the first cells HOME (which is where it is).
        let (mut nav, world) = at(Still::Home);
        assert_eq!(press(&mut nav, &world, 400, 40), None);
        assert_eq!(nav.root(), Section::System);
        assert_eq!(press(&mut nav, &world, 50, 40), None);
        assert!(nav.is_home());
    }

    #[test]
    fn the_lanes_three_targets_are_where_the_spec_puts_them() {
        let (nav, world) = at(Still::Gate);
        let home = Tap::Nav(Change::Go(Section::Home));
        let system = Tap::Nav(Change::Go(Section::System));
        for (x, y, tap) in [
            (0, 0, &home),
            (107, 71, &home),
            (108, 71, &home), // the gate's own word goes HOME too
            (347, 0, &home),
            (348, 0, &system),
            (479, 71, &system),
        ] {
            assert_eq!(&decide(&nav, &world, x, y), tap, "({x}, {y})");
        }
        // Row 72 is no longer the lane.
        assert_eq!(decide(&nav, &world, 400, 72), Tap::None);
    }

    #[test]
    fn the_lane_on_every_p1_screen() {
        // (the screen, what its section's word does)
        let cases = [
            (Still::Gate, Tap::Nav(Change::Go(Section::Home))),
            // ALERT is over the log: its word goes to the log, its root.
            (Still::Alert, Tap::Nav(Change::Go(Section::Alerts))),
            (Still::Alerts, Tap::Nav(Change::Go(Section::Alerts))),
            (Still::AlertsNone, Tap::Nav(Change::Go(Section::Alerts))),
            (Still::Names, Tap::Nav(Change::Go(Section::Names))),
            (Still::Yours, Tap::Nav(Change::Go(Section::Names))),
            (Still::Name, Tap::Nav(Change::Go(Section::Names))),
            // A threat's NAME, opened from its slip, is under ALERTS: the word goes back to the log.
            (Still::NameThreat, Tap::Nav(Change::Go(Section::Alerts))),
            // SYSTEM's mimic is the root, and its readings are over it: the word is the mimic.
            (Still::System, Tap::Nav(Change::Go(Section::System))),
            (Still::About, Tap::Nav(Change::Go(Section::System))),
            (Still::Version, Tap::Nav(Change::Go(Section::System))),
            (Still::Wifi, Tap::Nav(Change::Go(Section::System))),
            (Still::Uptime, Tap::Nav(Change::Go(Section::System))),
            (Still::NightHours, Tap::Nav(Change::Go(Section::System))),
            (Still::Lock, Tap::Nav(Change::Go(Section::System))),
        ];
        for (still, word) in cases {
            let (nav, world) = at(still);
            assert_eq!(
                decide(&nav, &world, 10, 40),
                Tap::Nav(Change::Go(Section::Home)),
                "{still:?}: HOME"
            );
            assert_eq!(decide(&nav, &world, 200, 40), word, "{still:?}: the word");
            assert_eq!(
                decide(&nav, &world, 400, 40),
                Tap::Nav(Change::Go(Section::System)),
                "{still:?}: the clock"
            );
        }
    }

    #[test]
    fn the_lane_on_live_is_only_home_until_the_live_task() {
        let (nav, world) = at(Still::Live);
        assert_eq!(
            decide(&nav, &world, 10, 40),
            Tap::Nav(Change::Go(Section::Home))
        );
        assert_eq!(decide(&nav, &world, 200, 40), Tap::None);
        assert_eq!(decide(&nav, &world, 400, 40), Tap::None);
    }

    #[test]
    fn the_gates_four_keys() {
        // The floor is y >= 236; four keys, floor((x - 4) / 118).
        let (nav, world) = at(Still::Gate);
        let key = |x: u16, y: u16| decide(&nav, &world, x, y);
        let open = |secs| Tap::Act(Intent::Gate(GateMove::Open(secs)), Some(Change::Back));
        let keep = Tap::Nav(Change::Back);
        assert_eq!(key(8, 240), keep);
        assert_eq!(key(121, 300), keep);
        assert_eq!(key(122, 240), open(300));
        assert_eq!(key(239, 319), open(300));
        assert_eq!(key(240, 236), open(1800));
        assert_eq!(key(357, 300), open(1800));
        assert_eq!(key(358, 300), open(3600));
        assert_eq!(key(479, 319), open(3600));
        assert_eq!(key(0, 300), keep, "left of the first key's margin");
        // Above the floor there is the slab, which is nothing.
        assert_eq!(key(300, 235), Tap::None);
        assert_eq!(key(200, 100), Tap::None);
    }

    #[test]
    fn a_gate_key_opens_the_gate_and_goes_back() {
        for (x, secs) in [
            (60, None),
            (180, Some(300)),
            (300, Some(1800)),
            (420, Some(3600)),
        ] {
            let (mut nav, world) = at(Still::Home);
            let (gx, gy) = tile_centre(3);
            press(&mut nav, &world, gx, gy);
            assert_eq!(nav.root(), Section::Gate);
            let intent = press(&mut nav, &world, x, 280);
            assert_eq!(intent, secs.map(|secs| Intent::Gate(GateMove::Open(secs))));
            assert!(nav.is_home(), "back from the gate is HOME");
        }
    }

    #[test]
    fn about_is_a_door_of_the_mimic_and_its_one_key_goes_back_to_it() {
        let (mut nav, world) = at(Still::About);
        assert_eq!(
            (nav.root(), nav.stack()),
            (Section::System, &[Screen::About][..])
        );
        // The right half of the floor has no key; the slab area is nothing.
        assert_eq!(press(&mut nav, &world, 400, 280), None);
        assert_eq!(press(&mut nav, &world, 100, 150), None);
        assert_eq!(nav.stack(), [Screen::About]);
        assert_eq!(decide(&nav, &world, 239, 236), Tap::Nav(Change::Back));
        assert_eq!(decide(&nav, &world, 240, 236), Tap::None);
        // BACK is the mimic, SYSTEM's root, and the mimic's key is the door to ABOUT again.
        assert_eq!(press(&mut nav, &world, 100, 280), None);
        assert_eq!((nav.root(), nav.stack().len()), (Section::System, 0));
        assert_eq!(press(&mut nav, &world, 400, 280), None);
        assert_eq!(nav.stack(), [Screen::About]);
    }

    #[test]
    fn alert_has_dismiss_which_acks_and_goes_back_to_the_log_and_see_device_which_opens_the_device()
    {
        let (mut nav, world) = at(Still::Alert);
        assert_eq!(
            (nav.root(), nav.stack()),
            (Section::Alerts, &[Screen::Alert(4)][..])
        );
        // The slip's head and stamp are no door; the right half of the floor is SEE DEVICE.
        assert_eq!(
            press(&mut nav, &world, 100, 100),
            None,
            "the slip's head and stamp"
        );
        assert_eq!(nav.stack(), [Screen::Alert(4)]);
        // SEE DEVICE: Sam's phone, over the slip.
        assert_eq!(press(&mut nav, &world, 400, 280), None);
        assert_eq!(nav.stack(), [Screen::Alert(4), Screen::Device(mac_of(23))]);
        nav.back();
        // DISMISS acks and goes back to the log, which is where the slip came from.
        assert_eq!(press(&mut nav, &world, 100, 280), Some(Intent::Ack(4)));
        assert_eq!((nav.root(), nav.stack().len()), (Section::Alerts, 0));
        // A screen whose alert is not in the log has no key.
        let mut nav = Nav::at(Section::Alerts);
        nav.open(Screen::Alert(1));
        assert_eq!(press(&mut nav, &world, 100, 280), None);
        assert_eq!(press(&mut nav, &world, 400, 280), None);
    }

    #[test]
    fn the_idle_panel_goes_home_after_a_minute_from_every_screen_but_home() {
        for still in [
            Still::Gate,
            Still::Alert,
            Still::About,
            Still::System,
            Still::Version,
            Still::Wifi,
            Still::Uptime,
            Still::NightHours,
            Still::Lock,
            Still::Live,
            Still::Devices,
        ] {
            let (mut nav, world) = at(still);
            let _ = &world;
            assert!(!idle(&mut nav, 0), "{still:?}");
            assert!(!idle(&mut nav, IDLE_MS - 1), "{still:?}: 59.999 s");
            assert!(!nav.is_home());
            assert!(idle(&mut nav, IDLE_MS), "{still:?}: 60 s");
            assert!(nav.is_home() && nav.stack().is_empty());
        }
        let mut nav = Nav::new();
        assert!(!idle(&mut nav, u64::MAX), "HOME stays HOME");
    }

    #[test]
    fn the_states_of_the_whole_system_are_not_timed_out_of_and_answer_only_their_own_keys() {
        let world = world(Still::Home);
        // STARTING has no key, and an update that is still received or on trial has none: no tap does anything, the
        // lane's HOME and clock included, and no idle minute takes them away.
        let mut receiving = world.clone();
        receiving.update = Some(UpdateRead::default());
        let mut trial = world.clone();
        trial.update = Some(UpdateRead {
            phase: UpdatePhase::Trial {
                left_secs: 60,
                waiting_for: None,
            },
            ..UpdateRead::default()
        });
        for (whole, world) in [
            (Whole::Starting, &world),
            (Whole::Update, &world),
            (Whole::Update, &receiving),
            (Whole::Update, &trial),
        ] {
            let mut nav = Nav::at(Section::Live);
            nav.set_whole(Some(whole));
            assert!(!idle(&mut nav, u64::MAX), "{whole:?}");
            assert_eq!(nav.whole(), Some(whole));
            for (x, y) in [
                (10, 40),
                (400, 40),
                (240, 160),
                (400, 280),
                (0, 0),
                (479, 319),
            ] {
                assert_eq!(tap(&mut nav, world, x, y), None, "{whole:?} ({x}, {y})");
                assert_eq!(decide(&nav, world, x, y), Tap::None, "{whole:?} ({x}, {y})");
                assert_eq!(nav.whole(), Some(whole), "{whole:?}");
            }
            nav.set_whole(None);
            assert!(nav.is_home(), "{whole:?} ends at HOME");
        }
        // NIGHT is one key, the whole screen: a touch anywhere wakes to HOME, and no idle minute takes it away.
        let mut nav = Nav::at(Section::Names);
        nav.open(Screen::Yours);
        nav.set_whole(Some(Whole::Night));
        assert!(!idle(&mut nav, u64::MAX));
        for (x, y) in [(0, 0), (240, 160), (479, 319), (400, 280)] {
            assert_eq!(
                decide(&nav, &world, x, y),
                Tap::Nav(Change::Go(Section::Home)),
                "({x}, {y})"
            );
        }
        assert_eq!(tap(&mut nav, &world, 240, 160), None);
        assert!(
            nav.is_home(),
            "the touch woke it to HOME, not to where it was"
        );
        // An update that has ended is one key too: a touch goes HOME; the finished ones are the world's.
        for phase in [UpdatePhase::Confirmed, UpdatePhase::RolledBack] {
            let mut ended = world.clone();
            ended.update = Some(UpdateRead {
                phase,
                ..UpdateRead::default()
            });
            let mut nav = Nav::at(Section::Live);
            nav.set_whole(Some(Whole::Update));
            assert_eq!(tap(&mut nav, &ended, 240, 160), None);
            assert!(nav.is_home(), "{phase:?}");
        }
        // The pad is timed out, back to what it came from, and cancelling goes there too.
        let mut nav = Nav::at(Section::Gate);
        nav.set_whole(Some(Whole::Pin));
        assert!(idle(&mut nav, IDLE_MS));
        assert_eq!((nav.root(), nav.whole()), (Section::Gate, None));
        nav.set_whole(Some(Whole::Pin));
        nav.back();
        assert_eq!((nav.root(), nav.whole()), (Section::Gate, None));
    }

    #[test]
    fn a_screen_whose_alert_is_gone_pops_to_the_log() {
        let (mut nav, mut world) = at(Still::Alert);
        assert!(!refresh(&mut nav, &world));
        assert_eq!(nav.stack(), [Screen::Alert(4)]);
        // Dismissed on the desktop: the log no longer holds it.
        world.alerts.remove(0);
        world.alerts_waiting = 3;
        assert!(refresh(&mut nav, &world));
        assert_eq!(
            (nav.root(), nav.stack().len()),
            (Section::Alerts, 0),
            "the log, not HOME"
        );
        assert!(!refresh(&mut nav, &world));
        // Everything opened over the slip goes with it: DEVICE, and a threat's NAME.
        let (mut nav, mut world) = at(Still::NameThreat);
        assert_eq!(nav.stack().len(), 2);
        assert!(!refresh(&mut nav, &world));
        world.alerts.remove(0);
        assert!(refresh(&mut nav, &world));
        assert_eq!((nav.root(), nav.stack().len()), (Section::Alerts, 0));
        let (mut nav, mut world) = at(Still::Alert);
        nav.open(Screen::Device(mac_of(23)));
        world.alerts.clear();
        assert!(refresh(&mut nav, &world));
        assert!(nav.stack().is_empty());
        // HOME and the roots have nothing to pop.
        let (mut nav, world) = at(Still::Gate);
        assert!(!refresh(&mut nav, &world));
        assert_eq!(nav.root(), Section::Gate);
    }

    // ---- DEVICES: the wall, DEVICE, CONFIRM and ITS GATE ----

    /// The wall's tile `i` of the house, tapped at its middle, from the wall.
    fn tile_tap(i: usize) -> Tap {
        let (nav, world) = at(Still::Devices);
        let r = devices::place_rect(i);
        decide(&nav, &world, r.x + 55, r.y + 35)
    }

    #[test]
    fn a_device_screen_is_where_the_map_puts_it_and_each_key_is_a_door() {
        // The wall's tile → DEVICE; its two keys → CONFIRM and ITS GATE; their keys → back, or the change and back.
        let mut nav = Nav::at(Section::Devices);
        let world = world(Still::Devices);
        let sam = mac_of(23);
        assert_eq!(press(&mut nav, &world, 180, 110), None);
        assert_eq!(nav.stack(), [Screen::Device(sam)]);
        assert_eq!(press(&mut nav, &world, 100, 280), None);
        assert_eq!(
            nav.stack(),
            [
                Screen::Device(sam),
                Screen::Confirm {
                    mac: sam,
                    pass: false
                }
            ]
        );
        // KEEP: back to DEVICE, nothing asked of the system.
        assert_eq!(press(&mut nav, &world, 100, 280), None);
        assert_eq!(nav.stack(), [Screen::Device(sam)]);
        // The lane's HOME from anywhere is HOME, and its word the wall.
        assert_eq!(press(&mut nav, &world, 200, 40), None);
        assert_eq!((nav.root(), nav.stack().len()), (Section::Devices, 0));
        assert_eq!(press(&mut nav, &world, 180, 110), None);
        assert_eq!(press(&mut nav, &world, 10, 40), None);
        assert!(nav.is_home());
    }

    #[test]
    fn the_wall_taps_are_the_tile_table() {
        let want = |octet: u8| Tap::Nav(Change::Open(Screen::Device(mac_of(octet))));
        let octets = [12, 23, 31, 40, 57, 64, 143, 216, 1, 2];
        for (i, octet) in octets.into_iter().enumerate() {
            assert_eq!(tile_tap(i), want(octet), "place {i}");
        }
        assert_eq!(tile_tap(10), Tap::None, "NEW ONES");
        assert_eq!(tile_tap(11), Tap::None);
    }

    #[test]
    fn a_device_screens_lane_goes_home_the_wall_or_system() {
        for still in [Still::Device, Still::Confirm, Still::Pause] {
            let (nav, world) = at(still);
            assert_eq!(
                decide(&nav, &world, 10, 40),
                Tap::Nav(Change::Go(Section::Home))
            );
            assert_eq!(
                decide(&nav, &world, 200, 40),
                Tap::Nav(Change::Go(Section::Devices)),
                "{still:?}: DEVICES goes back to the wall"
            );
            assert_eq!(
                decide(&nav, &world, 400, 40),
                Tap::Nav(Change::Go(Section::System))
            );
        }
    }

    #[test]
    fn the_wall_keeps_its_page_under_a_screen_and_starts_over_at_a_root() {
        let mut crowd = world(Still::Devices);
        for octet in 100..120 {
            let (name, named) = crate::os::world::display_name(None, None, octet);
            crowd.push_device(crate::os::world::DeviceRow {
                mac: mac_of(octet),
                name,
                named,
                octet,
                state: crate::os::world::DeviceState::AdsPass,
                fixed: false,
                asking: false,
            });
        }
        let mut nav = Nav::at(Section::Devices);
        assert_eq!(nav.devices_page(), 0);
        // The twelfth place turns the page; again, and the third page's turner is back to the first.
        let turner = devices::place_rect(11);
        let (x, y) = (turner.x + 55, turner.y + 35);
        assert_eq!(press(&mut nav, &crowd, x, y), None);
        assert_eq!(nav.devices_page(), 1);
        // A device of the second page opens, and back is the second page.
        assert_eq!(press(&mut nav, &crowd, 20, 100), None);
        assert_eq!(nav.top(), Some(&Screen::Device(mac_of(101))));
        assert_eq!(nav.devices_page(), 1);
        nav.back();
        assert_eq!((nav.devices_page(), nav.stack().len()), (1, 0));
        assert_eq!(press(&mut nav, &crowd, x, y), None);
        assert_eq!(press(&mut nav, &crowd, x, y), None);
        assert_eq!(nav.devices_page(), 0, "the third page's turner goes round");
        // The lane's word, HOME and SYSTEM start the wall over.
        assert_eq!(press(&mut nav, &crowd, x, y), None);
        assert_eq!(nav.devices_page(), 1);
        nav.go(Section::Devices);
        assert_eq!(nav.devices_page(), 0);
        // The wall shrank under a page that was open: the last page there is, and the panel says it moved.
        nav.apply(Change::DevicesPage(2));
        assert!(!refresh(&mut nav, &crowd));
        assert_eq!(nav.devices_page(), 2);
        let small = world(Still::Devices);
        assert!(refresh(&mut nav, &small));
        assert_eq!(nav.devices_page(), 0);
        assert!(!refresh(&mut nav, &small));
    }

    #[test]
    fn only_the_device_screen_is_watched() {
        let sam = mac_of(23);
        let world = world(Still::Devices);
        let mut nav = Nav::at(Section::Devices);
        assert_eq!(nav.watched_mac(), None, "the wall watches nothing");
        press(&mut nav, &world, 180, 110);
        assert_eq!(nav.watched_mac(), Some(sam));
        // CONFIRM and ITS GATE are over the device: its names stop.
        press(&mut nav, &world, 100, 280);
        assert_eq!(nav.watched_mac(), None);
        nav.back();
        assert_eq!(nav.watched_mac(), Some(sam), "back to DEVICE watches again");
        // A state of the whole system over it covers it.
        nav.set_whole(Some(Whole::Pin));
        assert_eq!(nav.watched_mac(), None);
        nav.set_whole(None);
        assert_eq!(nav.watched_mac(), Some(sam));
        nav.go(Section::Home);
        assert_eq!(nav.watched_mac(), None);
        for still in [
            Still::Home,
            Still::Gate,
            Still::Alert,
            Still::Confirm,
            Still::Pause,
        ] {
            let (nav, _) = at(still);
            assert_eq!(nav.watched_mac(), None, "{still:?}");
        }
        assert_eq!(at(Still::Device).0.watched_mac(), Still::Device.device());
    }

    #[test]
    fn a_device_that_left_the_world_pops_its_screens_to_the_wall() {
        // DEVICE, and everything opened over it, goes with the device.
        for still in [Still::Device, Still::Confirm, Still::Pause] {
            let (mut nav, mut world) = at(still);
            assert!(!refresh(&mut nav, &world), "{still:?}: nothing moved yet");
            let mac = still.device().expect("a device");
            world.devices.retain(|row| row.mac != mac);
            assert!(refresh(&mut nav, &world), "{still:?}");
            assert_eq!(
                (nav.root(), nav.stack().len()),
                (Section::Devices, 0),
                "{still:?}"
            );
            assert!(!refresh(&mut nav, &world));
        }
        // Another device leaving changes nothing.
        let (mut nav, mut world) = at(Still::Device);
        world.devices.retain(|row| row.octet != 216);
        assert!(!refresh(&mut nav, &world));
        assert_eq!(nav.stack().len(), 1);
    }

    #[test]
    fn a_confirm_or_a_gate_that_is_not_true_any_more_goes_back_to_the_device() {
        use crate::os::world::DeviceState;
        // The desktop let Sam's phone's ads pass already: the question has no point.
        let (mut nav, mut world) = at(Still::Confirm);
        world.devices[1].state = DeviceState::Blocked;
        assert!(refresh(&mut nav, &world));
        assert_eq!(nav.stack(), [Screen::Device(mac_of(23))]);
        // The configuration took its state over.
        let (mut nav, mut world) = at(Still::Confirm);
        world.devices[1].fixed = true;
        assert!(refresh(&mut nav, &world));
        assert_eq!(nav.stack(), [Screen::Device(mac_of(23))]);
        // The living room TV's gate was opened elsewhere (or its ads were let pass): nothing to open.
        let (mut nav, mut world) = at(Still::Pause);
        world.devices[2].state = DeviceState::Open { left_secs: 100 };
        assert!(refresh(&mut nav, &world));
        assert_eq!(nav.stack(), [Screen::Device(mac_of(31))]);
        let (mut nav, mut world) = at(Still::Pause);
        world.devices[2].state = DeviceState::AdsPass;
        assert!(refresh(&mut nav, &world));
        assert_eq!(nav.stack(), [Screen::Device(mac_of(31))]);
        // DEVICE itself stays: it shows whatever the device is.
        let (mut nav, mut world) = at(Still::Device);
        world.devices[2].state = DeviceState::Open { left_secs: 100 };
        assert!(!refresh(&mut nav, &world));
        // And ALERT's own rule is untouched by the device screens.
        let (mut nav, world) = at(Still::Alert);
        assert!(!refresh(&mut nav, &world));
    }

    #[test]
    fn the_screens_confirm_target_is_what_a_tap_asks_for() {
        // The confirm asked to let ads pass for the TV (blocked). Had the desktop let them pass in between,
        // the tap on `ALLOW ADS` would ask for nothing, and `refresh` takes the screen away.
        let mut world = world(Still::Devices);
        let tv = mac_of(31);
        let mut nav = Nav::at(Section::Devices);
        nav.open(Screen::Device(tv));
        nav.open(Screen::Confirm {
            mac: tv,
            pass: true,
        });
        assert_eq!(
            decide(&nav, &world, 400, 280),
            Tap::Act(
                Intent::DeviceAds {
                    mac: tv,
                    pass: true
                },
                Some(Change::Back)
            )
        );
        world.devices[2].state = crate::os::world::DeviceState::AdsPass;
        assert_eq!(decide(&nav, &world, 400, 280), Tap::None);
        assert_eq!(decide(&nav, &world, 100, 280), Tap::None, "and KEEP too");
        assert!(refresh(&mut nav, &world));
        assert_eq!(nav.top(), Some(&Screen::Device(tv)));
    }

    #[test]
    fn a_device_screens_debug_says_no_address() {
        let said = format!(
            "{:?} {:?} {:?} {:?}",
            Screen::Device([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            Screen::ItsGate([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            Screen::Confirm {
                mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                pass: true
            },
            at(Still::Confirm).0
        );
        for secret in ["170", "187", "238", "255", "0xaa", "[2, 0", "aa"] {
            assert!(!said.contains(secret), "{said} holds {secret}");
        }
        assert!(said.contains("Confirm") && said.contains("pass: true"));
    }

    #[test]
    fn the_tracker_yields_the_press_point_and_a_finger_that_slides_off_its_key_taps_nothing() {
        use crate::touch::{
            TapTracker,
            TouchEvent::{Down, Move, Up},
        };
        let (nav, world) = at(Still::Home);
        let target = |x, y| match decide(&nav, &world, x, y) {
            Tap::None => None,
            tap => Some(tap),
        };
        let mut tracker: TapTracker<Tap> = TapTracker::default();
        let mut feed = |at_ms, event| tracker.feed_with(at_ms, event, target);
        // A press of 20 ms on SYSTEM's tile: the tap is where it came down, and `tap` takes it from there.
        assert_eq!(feed(0, Down { x: 400, y: 250 }), None);
        let (pressed, point) = feed(20, Up).expect("a tap");
        assert_eq!(point, (400, 250));
        assert_eq!(pressed, Tap::Nav(Change::Go(Section::System)));
        // Too short, or slid onto another tile, or begun on a gap: nothing.
        assert_eq!(feed(100, Down { x: 400, y: 250 }), None);
        assert_eq!(feed(119, Up), None);
        assert_eq!(feed(200, Down { x: 400, y: 250 }), None);
        assert_eq!(feed(210, Move { x: 250, y: 250 }), None);
        assert_eq!(feed(300, Up), None);
        assert_eq!(feed(400, Down { x: 100, y: 74 }), None);
        assert_eq!(feed(500, Up), None, "the gap under the lane is no target");
        // Moving inside the same key keeps the press, and the point is where it came down.
        assert_eq!(feed(600, Down { x: 340, y: 200 }), None);
        assert_eq!(feed(610, Move { x: 470, y: 300 }), None);
        let (_, point) = feed(700, Up).expect("still on its key");
        assert_eq!(point, (340, 200));
    }

    // ---- ALERTS, NAMES and the arrival rule (P2) ----

    #[test]
    fn a_devices_name_row_opens_name_over_it_and_back_watches_the_device_again() {
        let (mut nav, world) = at(Still::Device);
        let tv = nav.watched_mac().expect("DEVICE watches its device");
        assert_eq!(press(&mut nav, &world, 100, 150), None);
        assert_eq!(
            nav.stack(),
            [
                Screen::Device(tv),
                Screen::Name("googlesyndication.com".into())
            ]
        );
        assert_eq!(nav.shown_name(), Some("googlesyndication.com"));
        assert!(nav.shows_names(), "the loop reads the name's facts");
        assert_eq!(nav.watched_mac(), None, "NAME over DEVICE stops the watch");
        nav.back();
        assert_eq!(nav.stack(), [Screen::Device(tv)]);
        assert_eq!(nav.watched_mac(), Some(tv));
        // The second row is the older name.
        assert_eq!(press(&mut nav, &world, 100, 210), None);
        assert_eq!(nav.shown_name(), Some("i.ytimg.com"));
    }

    #[test]
    fn the_p2_doors_lead_where_the_map_says() {
        // ALERTS: an entry → ALERT; its name line, for a threat, → NAME; back → ALERT.
        let (mut nav, world) = at(Still::Alerts);
        assert_eq!(press(&mut nav, &world, 200, 110), None);
        assert_eq!(
            nav.stack(),
            [Screen::Alert(2)],
            "the oldest of the three, printed at the top"
        );
        nav.back();
        assert_eq!(press(&mut nav, &world, 200, 240), None);
        assert_eq!(nav.stack(), [Screen::Alert(4)]);
        let threat = Screen::Name("secure-login.example.org".into());
        assert_eq!(
            press(&mut nav, &world, 200, 190),
            None,
            "the slip's name line"
        );
        assert_eq!(nav.stack(), [Screen::Alert(4), threat]);
        assert_eq!(nav.shown_name(), Some("secure-login.example.org"));
        nav.back();
        assert_eq!(nav.stack(), [Screen::Alert(4)]);
        // NAMES: a pipe → NAME; YOUR OWN → YOUR LIST → a pipe → NAME; the door there → back.
        let (mut nav, world) = at(Still::Names);
        assert_eq!(press(&mut nav, &world, 100, 200), None);
        assert_eq!(nav.stack(), [Screen::Name("tracker.example.com".into())]);
        nav.back();
        assert_eq!(press(&mut nav, &world, 400, 100), None);
        assert_eq!(nav.stack(), [Screen::Yours]);
        assert_eq!(
            press(&mut nav, &world, 100, 260),
            None,
            "the third place of YOUR LIST holds nothing"
        );
        assert_eq!(press(&mut nav, &world, 100, 200), None);
        assert_eq!(
            nav.stack(),
            [Screen::Yours, Screen::Name("forum.example.com".into())]
        );
        nav.back();
        assert_eq!(
            press(&mut nav, &world, 400, 100),
            None,
            "REFUSED MOST goes back"
        );
        assert!(nav.stack().is_empty() && nav.root() == Section::Names);
        // The lane's word on YOUR LIST is the root: NAMES.
        nav.open(Screen::Yours);
        assert_eq!(press(&mut nav, &world, 200, 40), None);
        assert!(nav.stack().is_empty() && nav.root() == Section::Names);
    }

    #[test]
    fn the_lane_and_the_home_words_on_every_p2_screen_and_the_door_that_is_inert() {
        for still in [
            Still::Alerts,
            Still::AlertsNone,
            Still::Alert,
            Still::Names,
            Still::Yours,
            Still::Name,
            Still::NameLocked,
            Still::NameThreat,
        ] {
            let (nav, world) = at(still);
            assert_eq!(
                decide(&nav, &world, 107, 71),
                Tap::Nav(Change::Go(Section::Home)),
                "{still:?}: HOME"
            );
            assert_eq!(
                decide(&nav, &world, 348, 0),
                Tap::Nav(Change::Go(Section::System)),
                "{still:?}: the clock"
            );
            assert_eq!(
                decide(&nav, &world, 200, 40),
                Tap::Nav(Change::Go(still.section())),
                "{still:?}: the word"
            );
        }
        // The empty log has no door on its paper.
        let (nav, world) = at(Still::AlertsNone);
        for (x, y) in [(100, 124), (100, 206), (200, 240), (400, 300)] {
            assert_eq!(decide(&nav, &world, x, y), Tap::None, "({x}, {y})");
        }
    }

    #[test]
    fn name_has_keep_on_the_left_and_the_verdict_on_the_right_which_go_back() {
        // ALLOW NAME on a refused name: strong, marked so that the PIN can be asked (P3).
        let (mut nav, world) = at(Still::Name);
        let allow = Intent::Name {
            name: "ads.example.net".into(),
            verdict: Verdict::Allow,
        };
        assert_eq!(press(&mut nav, &world, 100, 280), None, "KEEP REFUSED");
        assert!(nav.stack().is_empty() && nav.root() == Section::Names);
        let (mut nav, world) = at(Still::Name);
        assert_eq!(press(&mut nav, &world, 400, 280), Some(allow.clone()));
        assert!(allow.is_strong());
        assert!(
            nav.stack().is_empty() && nav.root() == Section::Names,
            "back to NAMES"
        );
        // The lock on: the intent waits for the PIN, held in the pad over NAME.
        let (mut nav, world) = at(Still::NameLocked);
        assert_eq!(press(&mut nav, &world, 400, 280), None);
        assert_eq!(nav.whole(), Some(Whole::Pin));
        assert!(matches!(
            nav.pin().map(PinPad::goal),
            Some(PinGoal::Do { intent, .. }) if *intent == allow
        ));
        // A name the lists answer: REFUSE NAME, never asks.
        let (mut nav, mut world) = at(Still::Name);
        if let Some(facts) = world.name_facts.as_mut() {
            facts.class = crate::os::world::NameClass::None;
        }
        let Some(refuse) = press(&mut nav, &world, 400, 280) else {
            panic!("an intent");
        };
        assert_eq!(
            refuse,
            Intent::Name {
                name: "ads.example.net".into(),
                verdict: Verdict::Refuse
            }
        );
        assert!(!refuse.is_strong());
        // The owner's own entries over YOUR LIST: REFUSE AGAIN (stricter, never asks) and ANSWER AGAIN (strong).
        for (verdict, strong) in [
            (crate::os::world::OwnerVerdict::Allow, false),
            (crate::os::world::OwnerVerdict::Refuse, true),
        ] {
            let mut world = world.clone();
            if let Some(facts) = world.name_facts.as_mut() {
                facts.owner = Some(crate::os::world::OwnerEntry { verdict, day: None });
            }
            let mut nav = Nav::at(Section::Names);
            nav.open(Screen::Yours);
            nav.open(Screen::Name("ads.example.net".into()));
            let intent = press(&mut nav, &world, 400, 280).expect("an intent");
            assert_eq!(intent.is_strong(), strong, "{intent:?}");
            assert_eq!(nav.stack(), [Screen::Yours], "back to YOUR LIST");
        }
        // A threat: BACK, and nothing on the right.
        let (mut nav, world) = at(Still::NameThreat);
        assert_eq!(press(&mut nav, &world, 400, 280), None);
        assert_eq!(nav.stack().len(), 2);
        assert_eq!(press(&mut nav, &world, 100, 280), None);
        assert_eq!(nav.stack(), [Screen::Alert(4)], "BACK is to the slip");
    }

    /// How a test puts the nav somewhere.
    type Place = Box<dyn Fn(&mut Nav)>;

    /// A nav somewhere, with the world of the alert stills.
    fn somewhere(build: impl Fn(&mut Nav)) -> (Nav, World) {
        let mut nav = Nav::new();
        build(&mut nav);
        (nav, world(Still::HomeAlert))
    }

    #[test]
    fn a_new_alert_opens_its_slip_from_every_screen_but_the_states_of_the_whole_system() {
        let places: [(&str, Place); 9] = [
            ("HOME", Box::new(|_| {})),
            ("LIVE", Box::new(|nav| nav.go(Section::Live))),
            (
                "LIVE with the gate ask",
                Box::new(|nav| {
                    nav.go(Section::Live);
                    nav.apply(Change::OpenGateAsk);
                }),
            ),
            ("GATE", Box::new(|nav| nav.go(Section::Gate))),
            ("SYSTEM", Box::new(|nav| nav.go(Section::System))),
            (
                "DEVICE over the wall",
                Box::new(|nav| {
                    nav.go(Section::Devices);
                    nav.open(Screen::Device(mac_of(31)));
                    nav.open(Screen::ItsGate(mac_of(31)));
                }),
            ),
            ("NAMES", Box::new(|nav| nav.go(Section::Names))),
            (
                "NAME over YOUR LIST",
                Box::new(|nav| {
                    nav.go(Section::Names);
                    nav.open(Screen::Yours);
                    nav.open(Screen::Name("forum.example.com".into()));
                }),
            ),
            ("the log", Box::new(|nav| nav.go(Section::Alerts))),
        ];
        for (name, build) in places {
            let (mut nav, world) = somewhere(build);
            let mut arrivals = Arrivals::new();
            assert!(arrive(&mut nav, &mut arrivals, &world), "{name}");
            assert_eq!(
                (nav.root(), nav.stack(), nav.gate_ask()),
                (Section::Alerts, &[Screen::Alert(4)][..], false),
                "{name}: ALERTS, then the newest high one"
            );
            // Shown once: nothing arrives again, and back leaves it waiting in the log.
            assert!(!arrive(&mut nav, &mut arrivals, &world), "{name}");
            nav.back();
            assert!(
                !arrive(&mut nav, &mut arrivals, &world),
                "{name}: back leaves it waiting"
            );
            assert_eq!(
                (nav.root(), nav.stack().len()),
                (Section::Alerts, 0),
                "{name}"
            );
            assert_eq!(world.alerts_waiting, 4, "still waiting");
        }
    }

    #[test]
    fn of_several_new_alerts_the_newest_high_one_opens_and_the_others_wait_in_the_log() {
        let mut w = world(Still::Alerts);
        // 5 is routine and the newest; 4 and 2 are urgent; 3 is routine.
        let mut routine = AlertRow::new(5, false, "NEW DEVICE", &["x"]);
        routine.who = "x".into();
        w.alerts.insert(0, routine);
        w.alerts.truncate(3);
        assert_eq!(w.alerts.iter().map(|a| a.id).collect::<Vec<_>>(), [5, 4, 3]);
        let mut nav = Nav::new();
        let mut arrivals = Arrivals::new();
        assert!(arrive(&mut nav, &mut arrivals, &w));
        assert_eq!(
            nav.stack(),
            [Screen::Alert(4)],
            "the newest high one, not the newest"
        );
        // The others were passed over: they are not shown one after another.
        nav.back();
        assert!(!arrive(&mut nav, &mut arrivals, &w));
        // Nothing urgent among several: the newest.
        let mut quiet = world(Still::Alerts);
        for alert in &mut quiet.alerts {
            alert.high = false;
        }
        let (mut nav, mut arrivals) = (Nav::new(), Arrivals::new());
        assert!(arrive(&mut nav, &mut arrivals, &quiet));
        assert_eq!(nav.stack(), [Screen::Alert(4)]);
        // Then a later one arrives on its own.
        let mut later = quiet.clone();
        later.alerts.insert(0, AlertRow::new(6, false, "X", &[]));
        later.alerts.truncate(3);
        nav.go(Section::Live);
        assert!(arrive(&mut nav, &mut arrivals, &later));
        assert_eq!(
            (nav.root(), nav.stack()),
            (Section::Alerts, &[Screen::Alert(6)][..])
        );
        // Dismissed alerts that were passed over do not come back: ids only grow.
        let (mut nav, mut arrivals) = (Nav::new(), Arrivals::new());
        assert!(arrive(&mut nav, &mut arrivals, &w));
        let mut after = w.clone();
        after.alerts.retain(|a| a.id != 4);
        nav.go(Section::Devices);
        assert!(!arrive(&mut nav, &mut arrivals, &after));
        assert_eq!(nav.root(), Section::Devices);
    }

    #[test]
    fn an_alert_does_not_arrive_over_the_states_of_the_whole_system_and_arrives_when_they_end() {
        let w = world(Still::HomeAlert);
        for whole in [Whole::Starting, Whole::Update, Whole::Night, Whole::Pin] {
            let mut nav = Nav::at(Section::Names);
            nav.open(Screen::Yours);
            nav.set_whole(Some(whole));
            let mut arrivals = Arrivals::new();
            let before = nav.clone();
            assert!(!arrive(&mut nav, &mut arrivals, &w), "{whole:?}");
            assert_eq!(nav, before, "{whole:?}: the screen is not lit");
            // The state ends, and the alert, still new, opens: the PIN pad goes back to where it came from first.
            nav.set_whole(None);
            assert!(arrive(&mut nav, &mut arrivals, &w), "{whole:?}: after it");
            assert_eq!(
                (nav.root(), nav.stack()),
                (Section::Alerts, &[Screen::Alert(4)][..]),
                "{whole:?}"
            );
        }
    }

    #[test]
    fn no_alert_is_no_arrival_and_the_arrival_is_the_alerts_root_and_slip() {
        let (mut nav, mut arrivals) = (Nav::new(), Arrivals::new());
        assert!(!arrive(&mut nav, &mut arrivals, &world(Still::AlertsNone)));
        assert!(nav.is_home());
        assert_eq!(arrivals, Arrivals::default());
    }

    #[test]
    fn the_names_screens_are_read_while_they_show_and_a_name_is_never_gone() {
        let shows = |nav: &Nav| nav.shows_names();
        assert!(
            shows(&at(Still::Names).0) && shows(&at(Still::Yours).0) && shows(&at(Still::Name).0)
        );
        assert!(
            shows(&at(Still::NameThreat).0),
            "a threat's NAME, over a slip"
        );
        for still in [
            Still::Home,
            Still::Alerts,
            Still::Alert,
            Still::Devices,
            Still::Device,
            Still::Gate,
            Still::Live,
            Still::About,
        ] {
            assert!(!shows(&at(still).0), "{still:?}");
        }
        let mut nav = at(Still::Name).0;
        nav.set_whole(Some(Whole::Night));
        assert!(!nav.shows_names() && nav.shown_name().is_none());
        // The name NAME shows, for the loop's read; none on the other screens.
        assert_eq!(at(Still::Name).0.shown_name(), Some("ads.example.net"));
        assert_eq!(at(Still::Yours).0.shown_name(), None);
        // A NAME without its facts yet (the loop has not read them) is not popped: it is not gone, only unread.
        let (mut nav, mut world) = at(Still::Name);
        world.name_facts = None;
        assert!(!refresh(&mut nav, &world));
        assert_eq!(nav.stack().len(), 1);
        // The facts are of another name: the screen is the bare lane, still there.
        let mut other = world.clone();
        other.name_facts = Some(crate::os::world::NameFacts {
            name: "other.example.org".into(),
            class: crate::os::world::NameClass::Ads,
            owner: None,
            count: None,
        });
        assert!(!refresh(&mut nav, &other));
    }

    #[test]
    fn the_idle_panel_goes_home_from_every_p2_screen() {
        for still in [
            Still::Alerts,
            Still::AlertsNone,
            Still::Names,
            Still::Yours,
            Still::Name,
            Still::NameThreat,
        ] {
            let (mut nav, _world) = at(still);
            assert!(!idle(&mut nav, IDLE_MS - 1), "{still:?}");
            assert!(idle(&mut nav, IDLE_MS), "{still:?}");
            assert!(nav.is_home(), "{still:?}");
        }
    }

    #[test]
    fn a_name_screens_debug_says_no_name() {
        let said = format!(
            "{:?} {:?}",
            Screen::Name("secret-tracker.example.org".into()),
            at(Still::NameThreat).0
        );
        assert!(
            !said.contains("secret") && !said.contains("example"),
            "{said}"
        );
        assert!(said.contains("Name") && said.contains("Alert"));
    }

    // ---- the lock: strong intents, the PIN pad and its answers (spec §7), and the whole states' clocks ----

    /// Where the pad's key for a digit stands: its middle.
    fn digit_at(digit: u8) -> (u16, u16) {
        let key = whole::pad_rect(if digit == 0 {
            10
        } else {
            usize::from(digit) - 1
        });
        (key.x + 45, key.y + 25)
    }

    /// The middle of the pad's `CANCEL` and `<`.
    const CANCEL: usize = 9;
    const ERASE: usize = 11;

    /// Where the pad's key `i` has its middle.
    fn key_at(i: usize) -> (u16, u16) {
        let key = whole::pad_rect(i);
        (key.x + 45, key.y + 25)
    }

    /// Types digits on the pad; says what the last tap asked of the system.
    fn type_pin(nav: &mut Nav, world: &World, digits: &[u8]) -> Option<Intent> {
        let mut last = None;
        for &digit in digits {
            let (x, y) = digit_at(digit);
            last = tap(nav, world, x, y);
        }
        last
    }

    /// The pad over `ALLOW NAME` on the first of the day's names, with the lock on, nothing typed.
    fn name_pad() -> (Nav, World) {
        let (mut nav, world) = at(Still::NameLocked);
        assert_eq!(press(&mut nav, &world, 400, 280), None);
        (nav, world)
    }

    fn allow_ads_for(octet: u8) -> Intent {
        Intent::DeviceAds {
            mac: mac_of(octet),
            pass: true,
        }
    }

    #[test]
    fn a_strong_key_asks_for_the_pin_only_with_the_lock_on_and_the_never_asked_keys_never_do() {
        // Each key of §7.1, and each that never asks, on the screen that has it: the nav and the world it
        // lives in, where to press, what it asks of the system, and whether §7.1 calls it strong.
        let tv = mac_of(31);
        let mut over_tv = Nav::at(Section::Devices);
        over_tv.open(Screen::Device(tv));
        over_tv.open(Screen::Confirm {
            mac: tv,
            pass: true,
        });
        let mut owner_allowed = world(Still::Name);
        let mut owner_refused = world(Still::Name);
        if let Some(facts) = owner_allowed.name_facts.as_mut() {
            facts.owner = Some(crate::os::world::OwnerEntry {
                verdict: crate::os::world::OwnerVerdict::Allow,
                day: None,
            });
        }
        if let Some(facts) = owner_refused.name_facts.as_mut() {
            facts.owner = Some(crate::os::world::OwnerEntry {
                verdict: crate::os::world::OwnerVerdict::Refuse,
                day: None,
            });
        }
        let mut lists_answer = world(Still::Name);
        if let Some(facts) = lists_answer.name_facts.as_mut() {
            facts.class = crate::os::world::NameClass::None;
        }
        let over_name = || at(Still::Name).0;
        let over_yours = || {
            let mut nav = Nav::at(Section::Names);
            nav.open(Screen::Yours);
            nav.open(Screen::Name("ads.example.net".into()));
            nav
        };
        /// A key: what it is called, the screen it is on, where to press, whether §7.1 calls it strong.
        type Case = (&'static str, Nav, World, (u16, u16), bool);
        let cases: Vec<Case> = vec![
            (
                "ALLOW ADS",
                over_tv,
                world(Still::Devices),
                (400, 280),
                true,
            ),
            (
                "BLOCK ADS",
                at(Still::Confirm).0,
                world(Still::Confirm),
                (400, 280),
                false,
            ),
            (
                "ALLOW NAME",
                over_name(),
                world(Still::Name),
                (400, 280),
                true,
            ),
            ("REFUSE NAME", over_name(), lists_answer, (400, 280), false),
            (
                "ANSWER AGAIN",
                over_yours(),
                owner_refused,
                (400, 280),
                true,
            ),
            (
                "REFUSE AGAIN",
                over_yours(),
                owner_allowed,
                (400, 280),
                false,
            ),
            (
                "RESTART",
                at(Still::Uptime).0,
                world(Still::Uptime),
                (400, 280),
                true,
            ),
            (
                "TURN OFF",
                at(Still::Lock).0,
                {
                    let mut w = world(Still::Lock);
                    w.lock_on = true;
                    w
                },
                (400, 280),
                true,
            ),
            (
                "the main gate, opened",
                at(Still::Gate).0,
                world(Still::Gate),
                (180, 280),
                false,
            ),
            (
                "the main gate, shut",
                at(Still::HomeOpen).0,
                world(Still::HomeOpen),
                (83, 250),
                false,
            ),
            (
                "ITS GATE",
                at(Still::Pause).0,
                world(Still::Pause),
                (180, 280),
                false,
            ),
            (
                "DISMISS",
                at(Still::Alert).0,
                world(Still::Alert),
                (100, 280),
                false,
            ),
            (
                "SLEEP NOW",
                at(Still::NightHours).0,
                world(Still::NightHours),
                (100, 280),
                false,
            ),
            (
                "REJOIN",
                at(Still::Wifi).0,
                world(Still::Wifi),
                (400, 280),
                false,
            ),
        ];
        for (what, nav, world, (x, y), strong) in cases {
            // The lock off: every one goes straight out, and the panel never shows a pad. (`TURN OFF` is not on the
            // screen then: LOCK offers `SET A PIN`, which is the pad that chooses.)
            let (mut off_nav, mut off) = (nav.clone(), world.clone());
            off.lock_on = false;
            let asked = if what == "TURN OFF" {
                assert_eq!(press(&mut off_nav, &off, x, y), None);
                assert!(matches!(
                    off_nav.pin().map(PinPad::goal),
                    Some(PinGoal::Choose)
                ));
                Intent::ClearPin
            } else {
                let asked =
                    press(&mut off_nav, &off, x, y).unwrap_or_else(|| panic!("{what}: lock off"));
                assert_eq!(off_nav.whole(), None, "{what}: no lock, no pad");
                asked
            };
            assert_eq!(asked.is_strong(), strong, "{what}: {asked:?}");
            // The lock on: a strong key holds its intent in the pad; the others go out as they were.
            let (mut on_nav, mut on) = (nav, world);
            on.lock_on = true;
            let before = on_nav.stack().to_vec();
            let said = press(&mut on_nav, &on, x, y);
            if strong {
                assert_eq!(said, None, "{what}: held for the PIN");
                assert_eq!(on_nav.whole(), Some(Whole::Pin), "{what}");
                assert!(
                    matches!(on_nav.pin().map(PinPad::goal), Some(PinGoal::Do { intent, .. }) if *intent == asked),
                    "{what}: the pad holds the intent"
                );
                assert_eq!(
                    on_nav.stack(),
                    before,
                    "{what}: the screens under the pad are as they were"
                );
            } else {
                assert_eq!(said, Some(asked), "{what}: never asked");
                assert_eq!(on_nav.whole(), None, "{what}");
            }
        }
    }

    #[test]
    fn set_a_pin_asks_the_current_pin_first_when_one_is_set() {
        let mut w = world(Still::Lock);
        assert!(matches!(choose_goal(&w), PinGoal::Choose));
        w.lock_on = true;
        assert!(matches!(choose_goal(&w), PinGoal::Change));
        // And `Change::ChoosePin` applied bare is the pad that chooses.
        let mut nav = Nav::new();
        nav.apply(Change::ChoosePin);
        assert!(matches!(nav.pin().map(PinPad::goal), Some(PinGoal::Choose)));
    }

    #[test]
    fn the_fourth_digit_asks_to_verify_and_a_right_pin_gives_the_held_intent_and_its_move() {
        // ALLOW ADS on the TV, from CONFIRM: the move that went with it was `Back`, to DEVICE.
        let tv = mac_of(31);
        let mut world = world(Still::Devices);
        world.lock_on = true;
        let mut nav = Nav::at(Section::Devices);
        nav.open(Screen::Device(tv));
        nav.open(Screen::Confirm {
            mac: tv,
            pass: true,
        });
        assert_eq!(press(&mut nav, &world, 400, 280), None);
        assert_eq!(nav.pin().map(PinPad::len), Some(0));
        // Three digits are typed, and nothing is asked of the system; the fourth is to be checked.
        assert_eq!(type_pin(&mut nav, &world, &[4, 7, 1]), None);
        assert_eq!(nav.pin().map(PinPad::len), Some(3));
        let (x, y) = digit_at(3);
        let asked = tap(&mut nav, &world, x, y).expect("the fourth digit asks to verify");
        assert_eq!(asked, Intent::Verify(PinDigits::new([4, 7, 1, 3])));
        assert!(!asked.is_strong(), "the check is never asked for itself");
        assert_eq!(nav.pin().map(PinPad::len), Some(4));
        assert_eq!(
            nav.whole(),
            Some(Whole::Pin),
            "the pad waits for the answer"
        );
        // Right: the held intent comes out, the pad is closed, and the move was made (CONFIRM is popped).
        assert_eq!(verified(&mut nav, Verified::Right), Some(allow_ads_for(31)));
        assert_eq!((nav.whole(), nav.pin().is_none()), (None, true));
        assert_eq!(nav.stack(), [Screen::Device(tv)]);
        // Nothing is left to answer: a second answer gives nothing.
        assert_eq!(verified(&mut nav, Verified::Right), None);
    }

    #[test]
    fn a_wrong_pin_clears_the_digits_says_so_and_goes_on_asking_until_a_digit_clears_the_word() {
        let (mut nav, world) = name_pad();
        let asked = type_pin(&mut nav, &world, &[1, 2, 3, 4]);
        assert_eq!(asked, Some(Intent::Verify(PinDigits::new([1, 2, 3, 4]))));
        assert_eq!(verified(&mut nav, Verified::Wrong), None);
        let pad = nav.pin().expect("the pad stays");
        assert_eq!((pad.len(), pad.wrong()), (0, true));
        assert_eq!(nav.whole(), Some(Whole::Pin));
        // The view says WRONG PIN; the next digit takes it back.
        let Some(crate::os::screens::View::Pin(view)) = crate::os::screens::view_of(&nav, &world)
        else {
            panic!("the pad");
        };
        assert_eq!(view.ask, crate::os::screens::whole::Ask::Wrong);
        assert_eq!(type_pin(&mut nav, &world, &[9]), None);
        assert!(!nav.pin().expect("the pad").wrong());
        // And a try that is right after it gives the intent, which is still the one asked.
        type_pin(&mut nav, &world, &[8, 8, 8]);
        assert_eq!(
            verified(&mut nav, Verified::Right).map(|intent| intent.is_strong()),
            Some(true)
        );
    }

    #[test]
    fn a_wait_clears_the_digits_takes_no_more_and_ends_when_the_world_says_nothing_is_left() {
        let (mut nav, mut world) = name_pad();
        type_pin(&mut nav, &world, &[1, 2, 3, 4]);
        assert_eq!(verified(&mut nav, Verified::Wait(30)), None);
        let pad = nav.pin().expect("the pad stays");
        assert_eq!(
            (pad.len(), pad.wrong(), pad.wait_secs(&world)),
            (0, false, 30)
        );
        // No digit is taken, nor `<`; `CANCEL` is.
        for digit in 0..=9 {
            assert_eq!(type_pin(&mut nav, &world, &[digit]), None);
        }
        assert_eq!(nav.pin().map(PinPad::len), Some(0), "nothing was typed");
        let (ex, ey) = key_at(ERASE);
        assert_eq!(decide(&nav, &world, ex, ey), Tap::None);
        // The world's count, once it has one, is what shows; the world's refresh drops the answer's own figure.
        world.pin_wait_secs = 12;
        assert_eq!(nav.pin().map(|pad| pad.wait_secs(&world)), Some(12));
        assert!(!refresh(&mut nav, &world));
        world.pin_wait_secs = 0;
        assert_eq!(
            nav.pin().map(|pad| pad.wait_secs(&world)),
            Some(0),
            "the wait is over"
        );
        assert_eq!(type_pin(&mut nav, &world, &[5]), None);
        assert_eq!(
            nav.pin().map(PinPad::len),
            Some(1),
            "digits are taken again"
        );
        // A wait told again is told by the figure of the answer: until the world has one of its own.
        type_pin(&mut nav, &world, &[5, 5, 5]);
        verified(&mut nav, Verified::Wait(900));
        assert_eq!(nav.pin().map(|pad| pad.wait_secs(&world)), Some(900));
        let (cx, cy) = key_at(CANCEL);
        assert_eq!(tap(&mut nav, &world, cx, cy), None);
        assert_eq!(nav.whole(), None, "CANCEL leaves the wait too");
    }

    #[test]
    fn cancel_and_a_minute_without_a_touch_leave_the_pad_for_where_it_came_from_the_action_not_done()
     {
        let (cx, cy) = key_at(CANCEL);
        // CANCEL: the NAME screen is back under it, and the intent was never given out.
        let (mut nav, world) = name_pad();
        type_pin(&mut nav, &world, &[1, 2]);
        assert_eq!(tap(&mut nav, &world, cx, cy), None);
        assert_eq!((nav.whole(), nav.pin().is_none()), (None, true));
        assert_eq!(nav.stack(), [Screen::Name("ads.example.net".into())]);
        assert_eq!(
            verified(&mut nav, Verified::Right),
            None,
            "late answers give nothing"
        );
        // A minute idle: the same.
        let (mut nav, world) = name_pad();
        type_pin(&mut nav, &world, &[1, 2, 3]);
        assert!(!idle(&mut nav, IDLE_MS - 1));
        assert_eq!(nav.whole(), Some(Whole::Pin));
        assert!(idle(&mut nav, IDLE_MS));
        assert_eq!((nav.whole(), nav.pin().is_none()), (None, true));
        assert_eq!(
            nav.stack(),
            [Screen::Name("ads.example.net".into())],
            "not HOME"
        );
        assert_eq!(verified(&mut nav, Verified::Right), None);
        // The lane and the rest of the screen are no keys of the pad.
        let (nav, world) = name_pad();
        for (x, y) in [
            (10, 40),
            (400, 40),
            (50, 150),
            (176, 150),
            (478, 150),
            (300, 312),
        ] {
            assert_eq!(decide(&nav, &world, x, y), Tap::None, "({x}, {y})");
        }
    }

    #[test]
    fn the_erase_key_takes_the_last_digit_back_and_a_fifth_digit_is_not_taken() {
        let (mut nav, world) = name_pad();
        type_pin(&mut nav, &world, &[1, 2]);
        let (ex, ey) = key_at(ERASE);
        assert_eq!(tap(&mut nav, &world, ex, ey), None);
        assert_eq!(nav.pin().map(PinPad::len), Some(1));
        assert_eq!(tap(&mut nav, &world, ex, ey), None);
        assert_eq!(
            decide(&nav, &world, ex, ey),
            Tap::None,
            "nothing to take back"
        );
        type_pin(&mut nav, &world, &[3, 4, 5]);
        // The erased digits are gone for good: the fourth is what was typed after.
        let asked = type_pin(&mut nav, &world, &[6]);
        assert_eq!(asked, Some(Intent::Verify(PinDigits::new([3, 4, 5, 6]))));
        // Four are typed and the lock is checking: more taps are not digits.
        assert_eq!(type_pin(&mut nav, &world, &[7, 8]), None);
        assert_eq!(nav.pin().map(PinPad::len), Some(4));
        assert_eq!(
            decide(&nav, &world, ex, ey),
            Tap::Nav(Change::PinErase),
            "`<` still works"
        );
    }

    #[test]
    fn choosing_a_pin_gives_set_pin_at_the_fourth_digit_and_closes_the_pad_over_lock() {
        let (mut nav, world) = at(Still::Lock);
        assert_eq!(press(&mut nav, &world, 400, 280), None);
        assert!(matches!(nav.pin().map(PinPad::goal), Some(PinGoal::Choose)));
        assert_eq!(type_pin(&mut nav, &world, &[2, 0, 4]), None);
        let set = type_pin(&mut nav, &world, &[8]).expect("the fourth digit sets the PIN");
        assert_eq!(set, Intent::SetPin(PinDigits::new([2, 0, 4, 8])));
        assert!(set.is_strong());
        assert_eq!(
            (nav.whole(), nav.pin().is_none()),
            (None, true),
            "the pad is done"
        );
        assert_eq!(nav.stack(), [Screen::Lock], "back on LOCK");
        // With a PIN set the pad asks for the current one first, and turns into the one that chooses.
        let (mut nav, world) = at(Still::Lock);
        nav.open_pin(PinGoal::Change);
        let check = type_pin(&mut nav, &world, &[1, 2, 3, 4]);
        assert_eq!(check, Some(Intent::Verify(PinDigits::new([1, 2, 3, 4]))));
        assert_eq!(
            verified(&mut nav, Verified::Right),
            None,
            "no action yet: a new PIN is to be chosen"
        );
        let pad = nav.pin().expect("the pad stays");
        assert!(matches!(pad.goal(), PinGoal::Choose));
        assert_eq!((pad.len(), pad.wrong()), (0, false));
        let set = type_pin(&mut nav, &world, &[9, 9, 9, 0]);
        assert_eq!(set, Some(Intent::SetPin(PinDigits::new([9, 9, 9, 0]))));
        assert_eq!((nav.whole(), nav.stack()), (None, &[Screen::Lock][..]));
        // A wrong current PIN does not get to choose.
        let (mut nav, world) = at(Still::Lock);
        nav.open_pin(PinGoal::Change);
        type_pin(&mut nav, &world, &[1, 2, 3, 4]);
        verified(&mut nav, Verified::Wrong);
        assert!(matches!(nav.pin().map(PinPad::goal), Some(PinGoal::Change)));
    }

    #[test]
    fn a_pad_that_chooses_with_the_lock_off_does_not_set_a_pin_once_the_lock_is_on() {
        // The pad opens to choose a PIN with the lock off, three digits are typed, and the desktop pushes a PIN.
        let (mut nav, mut world) = at(Still::Lock);
        world.lock_on = false;
        assert_eq!(press(&mut nav, &world, 400, 280), None);
        assert!(matches!(nav.pin().map(PinPad::goal), Some(PinGoal::Choose)));
        assert_eq!(type_pin(&mut nav, &world, &[2, 0, 4]), None);
        world.lock_on = true;
        // The fourth digit gives nothing, and the pad is gone: the PIN in force was not replaced.
        assert_eq!(type_pin(&mut nav, &world, &[8]), None);
        assert_eq!((nav.whole(), nav.pin().is_none()), (None, true));
        assert_eq!(nav.stack(), [Screen::Lock], "back on LOCK");
        // With the lock on a new PIN asks for the current PIN first, and then the new one is taken.
        assert!(matches!(choose_goal(&world), PinGoal::Change));
        nav.open_pin(choose_goal(&world));
        let check = type_pin(&mut nav, &world, &[1, 2, 3, 4]);
        assert_eq!(check, Some(Intent::Verify(PinDigits::new([1, 2, 3, 4]))));
        assert_eq!(verified(&mut nav, Verified::Right), None);
        assert!(matches!(nav.pin().map(PinPad::goal), Some(PinGoal::Choose)));
        assert_eq!(type_pin(&mut nav, &world, &[2, 0, 4]), None);
        let set = type_pin(&mut nav, &world, &[8]);
        assert_eq!(
            set,
            Some(Intent::SetPin(PinDigits::new([2, 0, 4, 8]))),
            "the PIN that was asked for chooses the next"
        );
        assert_eq!((nav.whole(), nav.pin().is_none()), (None, true));
        // With the lock off all along the pad sets the PIN, as it did.
        world.lock_on = false;
        assert_eq!(press(&mut nav, &world, 400, 280), None);
        assert_eq!(type_pin(&mut nav, &world, &[1, 1, 1]), None);
        assert_eq!(
            type_pin(&mut nav, &world, &[1]),
            Some(Intent::SetPin(PinDigits::new([1, 1, 1, 1])))
        );
    }

    #[test]
    fn a_pad_whose_screen_is_gone_is_dropped_and_the_action_not_done() {
        let tv = mac_of(31);
        let mut world = world(Still::Devices);
        world.lock_on = true;
        let mut nav = Nav::at(Section::Devices);
        nav.open(Screen::Device(tv));
        nav.open(Screen::Confirm {
            mac: tv,
            pass: true,
        });
        assert_eq!(press(&mut nav, &world, 400, 280), None);
        type_pin(&mut nav, &world, &[1, 2]);
        assert!(!refresh(&mut nav, &world), "all is where it was");
        // The desktop forgot the TV: DEVICE and CONFIRM pop, and the pad with them.
        world.devices.retain(|row| row.mac != tv);
        assert!(refresh(&mut nav, &world));
        assert_eq!((nav.whole(), nav.pin().is_none()), (None, true));
        assert_eq!((nav.root(), nav.stack().len()), (Section::Devices, 0));
        assert_eq!(verified(&mut nav, Verified::Right), None);
        // A pad over a screen that is still there stays through any refresh.
        let (mut nav, world) = name_pad();
        assert!(!refresh(&mut nav, &world));
        assert_eq!(nav.whole(), Some(Whole::Pin));
    }

    #[test]
    fn the_pad_and_the_nav_that_holds_it_print_no_digit_name_or_device() {
        let (mut nav, world) = name_pad();
        type_pin(&mut nav, &world, &[8, 8, 8]);
        let said = format!("{nav:?} {:?}", nav.pin());
        for secret in ["888", "8, 8", "example", "ads", "[8"] {
            assert!(!said.contains(secret), "{said} holds {secret}");
        }
        assert!(said.contains("Pin") && said.contains("Do"), "{said}");
        let pad = nav.pin().expect("the pad").clone();
        assert_eq!(format!("{:?}", pad.goal()), "Do");
        // The tap that asks to verify carries digits in an intent that prints none.
        let (x, y) = digit_at(8);
        let said = format!("{:?}", decide(&nav, &world, x, y));
        assert!(!said.contains('8'), "{said}");
        // Nor does a key press that is not the fourth.
        let (x, y) = digit_at(5);
        let said = format!("{:?}", decide(&nav, &world, x, y));
        assert!(said.contains("PinDigit") && !said.contains('5'), "{said}");
    }

    #[test]
    fn a_finished_update_goes_home_after_thirty_seconds_and_nothing_else_does() {
        let mut ended = world(Still::Home);
        ended.update = Some(UpdateRead {
            phase: UpdatePhase::Confirmed,
            ..UpdateRead::default()
        });
        let mut nav = Nav::at(Section::Live);
        nav.set_whole(Some(Whole::Update));
        assert!(!age_update(&mut nav, &ended, UPDATE_DONE_MS - 1));
        assert_eq!(nav.whole(), Some(Whole::Update));
        assert!(age_update(&mut nav, &ended, 1));
        assert!(nav.is_home());
        // It counts only while a finished update shows: receiving and on trial it does not.
        let mut busy = ended.clone();
        busy.update = Some(UpdateRead::default());
        let mut nav = Nav::new();
        nav.set_whole(Some(Whole::Update));
        for _ in 0..10 {
            assert!(!age_update(&mut nav, &busy, 20_000));
        }
        assert_eq!(nav.whole(), Some(Whole::Update));
        // And it starts over for the next: the time before the result does not count towards it.
        assert!(!age_update(&mut nav, &ended, 20_000));
        assert!(!age_update(&mut nav, &busy, 20_000));
        assert!(
            !age_update(&mut nav, &ended, 20_000),
            "20 s since it ended, not 40"
        );
        assert!(age_update(&mut nav, &ended, 10_000));
        // Another state, or none, is not touched.
        let mut nav = Nav::at(Section::Names);
        assert!(!age_update(&mut nav, &ended, u64::MAX));
        nav.set_whole(Some(Whole::Night));
        assert!(!age_update(&mut nav, &ended, u64::MAX));
        assert_eq!(nav.whole(), Some(Whole::Night));
    }

    #[test]
    fn an_alert_does_not_arrive_over_the_pad_and_a_pad_over_it_leaves_the_slip_waiting() {
        let (mut nav, world) = name_pad();
        let mut arrivals = Arrivals::new();
        let before = nav.clone();
        assert!(!arrive(
            &mut nav,
            &mut arrivals,
            &self::world(Still::HomeAlert)
        ));
        assert_eq!(nav, before, "the pad is not lit over by a slip");
        assert_eq!(world.alerts_waiting, 0);
    }
}
