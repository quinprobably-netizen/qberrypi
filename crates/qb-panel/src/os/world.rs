//! What the screens read: the panel's view of the house, as plain data the caller fills in (spec §5.2).
//!
//! The caller (qberrypi's panel loop) copies it out of the resolver, the device inventory, the alert
//! store and the update controller on the cadences of the spec, and hands it to the screens; they
//! never read a lock. Everything a name rides in (a device's name, a watched name, an alert's lines)
//! is already fitted to its place, and none of those types prints a name: `Debug` shows counts and
//! states only.
//!
//! An `Option` is a figure the Pi may not know yet: the screens draw it as `—` (or `--:--`), never a zero.

use std::fmt;

use crate::format::{self, fit_site, fit_text};
use crate::state::{Share, TimeOfDay};

/// A device's hardware address.
pub type Mac = [u8; 6];

/// The most devices the world holds: three pages of eleven places (the twelfth is `MORE`).
pub const MAX_DEVICES: usize = 33;

/// The most names of the watched device the world holds: the last two it asked.
pub const MAX_WATCHED: usize = 2;

/// The most lines an alert's slip holds under its title.
pub const MAX_ALERT_LINES: usize = 3;

/// The most alerts the world holds, newest first: the log prints the newest three.
pub const MAX_ALERT_ROWS: usize = 3;

/// The most names of the day's most refused the world holds: the manifold's three pipes.
pub const MAX_TOP_NAMES: usize = 3;

/// The most entries of the owner's own list the world holds: the newest three.
pub const MAX_OWNER_ROWS: usize = 3;

/// The longest a DNS name is, in bytes: a name the world holds is whole, for a screen is about it by its text
/// (spec §4) and the intent that decides it carries it; the screens fit it to their places when they draw.
pub const NAME_BYTES_MAX: usize = 253;

/// How many cells a device's name has: the owner's labels are at most this, and the 30 px name on
/// its own screen still fits the width.
pub const DEVICE_NAME_CELLS: usize = 24;

/// How many cells the slip's title has: the 30 px title the slip sets past 16 letters, from x 38 to the slip's
/// right edge at 454; the log's 24 px title has more room.
pub const ALERT_TITLE_CELLS: usize = 22;

/// How many cells the alert slip's lines have: the subject (20 px bold, the first) and the others (16 px), from
/// x 40 to the slip's right edge.
pub const ALERT_LINE_CELLS: [usize; MAX_ALERT_LINES] = [33, 42, 42];

/// How many cells a watched name has: 24 px on the device's screen, as `fit_site` fits it.
pub const WATCHED_NAME_CELLS: usize = 22;

/// How many cells the version text has.
pub const VERSION_CELLS: usize = 12;

/// How many cells the build date has: `2026-11-12`.
pub const BUILT_CELLS: usize = 10;

/// How many cells the cause of the last restart has: UP's second line is `last restart: ` and the cause, in 18 px
/// letters from x 7, and holds 43 letters.
pub const RESTART_CAUSE_CELLS: usize = 28;

/// How the ad blocking stands on one device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceState {
    /// Ads are refused for it.
    Blocked,
    /// Ads pass: the device is let off the ads lists. Threats stay blocked.
    AdsPass,
    /// Its own gate is open for a while: ads pass until it shuts.
    Open {
        /// Seconds until the gate shuts.
        left_secs: u16,
    },
    /// The router and the Pi: they are never changed.
    Always,
}

/// One device on the wall.
///
/// `Debug` says its state and nothing else: not its name, its address or its place.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceRow {
    /// Its hardware address, which is how a screen knows which device it is about.
    pub mac: Mac,
    /// What the screens call it: the owner's label, else its hostname, else `·` and the last octet of
    /// its address, fitted to `DEVICE_NAME_CELLS`. See `display_name`.
    pub name: String,
    /// Whether `name` is a label or a hostname rather than the `·octet` made for a device with neither.
    pub named: bool,
    /// The last octet of its address.
    pub octet: u8,
    /// Where ad blocking stands on it.
    pub state: DeviceState,
    /// Whether the configuration, not the owner, decides its state: its key says `SET IN CONFIG` and is inert.
    pub fixed: bool,
    /// Whether it asked something in the last second or so: the lamp.
    pub asking: bool,
}

impl fmt::Debug for DeviceRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceRow")
            .field("state", &self.state)
            .field("fixed", &self.fixed)
            .field("asking", &self.asking)
            .finish_non_exhaustive()
    }
}

/// A device's name as the wall shows it, and whether it is a real name: the label the owner gave, else
/// the hostname, else `·` and the last octet. A label or hostname of nothing but spaces is none.
pub fn display_name(label: Option<&str>, hostname: Option<&str>, octet: u8) -> (String, bool) {
    [label, hostname]
        .into_iter()
        .flatten()
        .map(|text| fit_text(text, DEVICE_NAME_CELLS))
        .find(|text| !text.is_empty())
        .map_or_else(|| (format!("\u{b7}{octet}"), false), |text| (text, true))
}

/// What a watched device's name came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Blocked: no answer.
    Refused,
    /// An ad name that was answered, because the device's ads pass.
    Passed,
    /// Answered as any name is.
    Answered,
}

impl Outcome {
    /// The word on the device's screen, in capitals.
    pub const fn word(self) -> &'static str {
        match self {
            Self::Refused => "REFUSED",
            Self::Passed => "PASSED",
            Self::Answered => "ANSWERED",
        }
    }
}

/// A name the watched device asked, with what came of it.
///
/// It is held twice: fitted to its row, as DEVICE draws it, and whole, as the row opens NAME with it (NAME is
/// about a name by its whole text, spec §4). `Debug` shows the outcome only.
#[derive(Clone, PartialEq, Eq)]
pub struct WatchedName {
    /// The name, as `fit_site` fits it to `WATCHED_NAME_CELLS`.
    pub name: String,
    /// The name by its whole text, at most `NAME_BYTES_MAX` bytes: what the row opens NAME with. `None` when
    /// the whole of it is not known, and the row is then no door.
    pub whole: Option<String>,
    /// What came of it.
    pub outcome: Outcome,
}

impl WatchedName {
    /// A name and its outcome: the row shows it fitted, and opens NAME with it whole.
    pub fn new(name: &str, outcome: Outcome) -> Self {
        Self::shown_as(name, Some(name), outcome)
    }

    /// A name that the row shows as `shown` (which is fitted here) and opens NAME with as `whole`: for a source
    /// whose text to show is not the whole name (the board cuts what it shows as its lane does). A `whole` longer
    /// than a DNS name is not one, and is not held.
    pub fn shown_as(shown: &str, whole: Option<&str>, outcome: Outcome) -> Self {
        Self {
            name: fit_site(shown, WATCHED_NAME_CELLS),
            whole: whole
                .filter(|name| !name.is_empty() && name.len() <= NAME_BYTES_MAX)
                .map(str::to_owned),
            outcome,
        }
    }
}

impl fmt::Debug for WatchedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WatchedName")
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}

/// The Wi-Fi band the link is on, from its frequency (spec §12.3: the band stands under ROUTER, `5 GHZ`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Band {
    /// 2.4 GHz.
    Ghz24,
    /// 5 GHz.
    Ghz5,
}

impl Band {
    /// The band a frequency in MHz is in; `None` for one that is neither (the Pi 3B+ has these two).
    pub const fn from_mhz(mhz: u32) -> Option<Self> {
        match mhz {
            2_400..=2_500 => Some(Self::Ghz24),
            4_900..=5_900 => Some(Self::Ghz5),
            _ => None,
        }
    }

    /// The band in capitals: `5 GHZ`.
    pub const fn word(self) -> &'static str {
        match self {
            Self::Ghz24 => "2.4 GHZ",
            Self::Ghz5 => "5 GHZ",
        }
    }
}

/// What the panel reads of the Wi-Fi link besides whether it is joined (WI-FI, and SYSTEM's link). Each is a
/// figure the Pi may not know: `None` is a dash in `G3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Link {
    /// The band, from the link's frequency (`Band::from_mhz`).
    pub band: Option<Band>,
    /// The signal in dBm, as the driver reports it (`-54`).
    pub signal_dbm: Option<i16>,
    /// Whole days the link has held since it joined; 0 is `today`.
    pub linked_days: Option<u32>,
    /// How long the upstream resolver takes to answer, in milliseconds (spec §11.4).
    pub upstream_ms: Option<u32>,
}

/// How many dashes of ten the signal lights (WI-FI): `clamp(round((dBm + 100) / 5), 0, 10)`.
pub fn dashes_of(dbm: i16) -> u8 {
    let lit = ((f32::from(dbm) + 100.0) / 5.0).round().clamp(0.0, 10.0);
    // Between 0 and 10, so a byte holds it.
    lit as u8
}

/// Which slot of the card the board runs from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    /// Slot A.
    A,
    /// Slot B.
    B,
}

impl Slot {
    /// The slot's letter.
    pub const fn letter(self) -> char {
        match self {
            Self::A => 'A',
            Self::B => 'B',
        }
    }
}

/// How the last update ended (spec §12.3), as the box says it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LastUpdate {
    /// `LAST UPDATE CONFIRMED`.
    Confirmed,
    /// `LAST UPDATE ROLLED BACK`.
    RolledBack,
    /// `NO UPDATE SINCE START`.
    #[default]
    None,
}

/// What the panel reads of the board itself, on SYSTEM and its readings (every few seconds, only while they
/// show, spec §5.2). A figure the Pi does not know is `None` (or empty), and is drawn as a dash in `G3`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Machine {
    /// The slot that runs; the other holds the spare, which the Pi knows nothing of but that it is kept.
    pub slot: Option<Slot>,
    /// The build's date, `2026-11-12`, fitted to `BUILT_CELLS`; empty when it is not known.
    pub built: String,
    /// How the last update ended.
    pub last_update: LastUpdate,
    /// The hours since the board started, within the day (0 to 23): UP's `12 D 4 H` is `uptime_days` and these.
    pub uptime_hours: Option<u8>,
    /// The load over a minute in hundredths (`21` is `0.21`).
    pub load_hundredths: Option<u32>,
    /// The share of the memory in use, in percent.
    pub memory_pct: Option<u8>,
    /// The board's heat in whole degrees Celsius.
    pub temp_c: Option<i16>,
    /// What the board last restarted for, in a few words (`the owner`, `an update`), fitted to
    /// `RESTART_CAUSE_CELLS`; empty when it is not known.
    pub last_restart: String,
}

/// Where a rejoin of the Wi-Fi stands (spec §6.6, §12.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Rejoin {
    /// Nothing is going on: `REJOIN` is a key.
    #[default]
    Idle,
    /// The link was let go and is not back: `JOINING` and every dash dark, until it is (no timer).
    Joining,
    /// The control refuses another rejoin for this many seconds: the key says `WAIT`.
    Wait(u16),
}

/// Where the PIN lives while the lock is on (spec §7.2); the LOCK screen's second line says it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LockSource {
    /// `[panel] pin_hash` in the slot's configuration: it survives a restart.
    #[default]
    Config,
    /// Pushed from the desktop: until the next restart, or beyond it when the card keeps the state
    /// ([`World::lock_kept`]).
    Api,
    /// Set on the panel itself: until the next restart, or beyond it when the card keeps the state
    /// ([`World::lock_kept`]).
    Panel,
}

/// What a trial boot still waits for once its minimum time is up (spec §12.5): the figure then says it in a word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Waiting {
    /// The Wi-Fi link is not joined yet.
    Wifi,
    /// The clock is not set yet.
    Clock,
    /// The upstream resolver has not answered yet.
    Upstream,
}

impl Waiting {
    /// The word in the trial's figure, in capitals.
    pub const fn word(self) -> &'static str {
        match self {
            Self::Wifi => "WI-FI",
            Self::Clock => "CLOCK",
            Self::Upstream => "UPSTREAM",
        }
    }
}

/// Where an update stands (spec §5.4, §12.3, §12.5): the four states UPDATE draws.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdatePhase {
    /// The new build is being received; the old one answers all the while.
    Receiving {
        /// Bytes received so far.
        received: u64,
        /// The build's length in bytes, from the manifest; 0 while it is not known.
        length: u64,
    },
    /// The new build runs on trial and confirms itself when the trial is over.
    Trial {
        /// Seconds to the trial's minimum time; 0 once it is up.
        left_secs: u16,
        /// What the trial waits for past its minimum time; `None` while it does not wait for anything.
        waiting_for: Option<Waiting>,
    },
    /// The trial passed: the new build stays.
    Confirmed,
    /// The trial failed: the old build is back.
    RolledBack,
}

impl UpdatePhase {
    /// Whether the update has ended: a tap, or 30 s, goes HOME.
    pub const fn is_done(self) -> bool {
        matches!(self, Self::Confirmed | Self::RolledBack)
    }

    /// How much of the build has been received, from 0 to 100 (rounded down), and a ratio from 0 to 1 for the fill.
    /// Both are 0 while the length is not known, and never more than the whole.
    pub fn received(self) -> (u8, f32) {
        match self {
            Self::Receiving { received, length } if length > 0 => {
                let received = received.min(length);
                // The percentage is whole and cut, as the mockup's `Math.floor(pct)`.
                let pct = (u128::from(received) * 100 / u128::from(length)) as u8;
                (pct, received as f32 / length as f32)
            }
            _ => (0, 0.0),
        }
    }
}

/// What the panel reads of an update while UPDATE shows (spec §12.3): where it stands, the slot that served before it and the
/// slot the new build is in, by their real letters. It is `None` in the world when no update is going on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpdateRead {
    /// Where it stands.
    pub phase: UpdatePhase,
    /// The slot that served before the update: UPDATE's left box.
    pub before: Slot,
    /// The slot the new build is in: UPDATE's right box.
    pub after: Slot,
}

impl Default for UpdateRead {
    /// An update that has just begun: nothing received, slot A serving, slot B to fill.
    fn default() -> Self {
        Self {
            phase: UpdatePhase::Receiving {
                received: 0,
                length: 0,
            },
            before: Slot::A,
            after: Slot::B,
        }
    }
}

/// A day of the week, for the words that say when something was (`MON`, `Mon`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Weekday {
    /// Monday.
    Mon,
    /// Tuesday.
    Tue,
    /// Wednesday.
    Wed,
    /// Thursday.
    Thu,
    /// Friday.
    Fri,
    /// Saturday.
    Sat,
    /// Sunday.
    Sun,
}

impl Weekday {
    /// The day in capitals: `MON`.
    pub const fn caps(self) -> &'static str {
        match self {
            Self::Mon => "MON",
            Self::Tue => "TUE",
            Self::Wed => "WED",
            Self::Thu => "THU",
            Self::Fri => "FRI",
            Self::Sat => "SAT",
            Self::Sun => "SUN",
        }
    }

    /// The day with one capital: `Mon`, as a sentence says it (`refused by you since Mon`).
    pub const fn title(self) -> &'static str {
        match self {
            Self::Mon => "Mon",
            Self::Tue => "Tue",
            Self::Wed => "Wed",
            Self::Thu => "Thu",
            Self::Fri => "Fri",
            Self::Sat => "Sat",
            Self::Sun => "Sun",
        }
    }
}

/// When an alert happened, as the log says it: the time of day for today's, the weekday for an older one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum When {
    /// Today: `10:19`.
    Time(TimeOfDay),
    /// Before today: `MON`.
    Day(Weekday),
}

impl When {
    /// The word: `10:19`, or `MON`.
    pub fn word(self) -> String {
        match self {
            Self::Time(time) => format::clock(Some(time)),
            Self::Day(day) => day.caps().to_string(),
        }
    }
}

/// A weekday and a time of day, as the idle log says them (`MON 21:40`): when the last entry was filed, when
/// the watch opened (spec §12.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Moment {
    /// The day.
    pub day: Weekday,
    /// The time on it.
    pub time: TimeOfDay,
}

impl Moment {
    /// The words: `MON 21:40`.
    pub fn word(self) -> String {
        format!("{} {}", self.day.caps(), format::clock(Some(self.time)))
    }
}

/// What the Pi did about an alert, as the slip's stamp says it (spec §12.2). The caller maps it from the
/// alert's kind; the screens only draw the word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AlertStamp {
    /// The answer was blocked (`threat`, `rebind`).
    Refused,
    /// It joined and got the newcomer's default (`new_device`).
    Admitted,
    /// Nothing was blocked because of it (`arp_spoof`, `dga`, `tunnel`, `beacon`, `burst`, any other kind).
    #[default]
    Observed,
}

impl AlertStamp {
    /// The word on the stamp, in capitals.
    pub const fn word(self) -> &'static str {
        match self {
            Self::Refused => "REFUSED",
            Self::Admitted => "ADMITTED",
            Self::Observed => "OBSERVED",
        }
    }
}

/// One waiting alert: a line of the log, and the slip it opens.
///
/// The store's `top()` gave P1 the newest one; the log shows the newest three (`World::alerts`, newest
/// first). `Debug` shows the id and the severity only: not a title, a device or a name.
#[derive(Clone, PartialEq, Eq)]
pub struct AlertRow {
    /// The store's id: what `Intent::Ack` carries, and how the screen knows its alert is gone.
    pub id: u64,
    /// Whether the slip is white and the log says `URGENT` (high severity), rather than blue and `ROUTINE`.
    pub high: bool,
    /// The title, in capitals, fitted to `ALERT_TITLE_CELLS`.
    pub title: String,
    /// When it last happened; `None` while the clock was not set when it was taken.
    pub at: Option<When>,
    /// The device it is about, as the wall names it, fitted to `DEVICE_NAME_CELLS`; empty when none is known.
    pub who: String,
    /// What the Pi did about it: the slip's stamp.
    pub stamp: AlertStamp,
    /// Up to three lines under the title: the first is the subject (20 px bold), the others 16 px; each
    /// fitted to its place in `ALERT_LINE_CELLS`.
    pub lines: Vec<String>,
    /// The name on the slip, for an alert about a name (`threat`, `rebind`): the slip's name line is a door
    /// to NAME. The whole name, as the screen is about it by its text.
    pub name: Option<String>,
    /// The device the alert names, as the wall has it: `SEE DEVICE` opens it. It is no door when the device
    /// is not on the wall (`World::device`).
    pub device: Option<Mac>,
}

impl AlertRow {
    /// An alert row with what a bare loop knows: the title and the lines (fitted; lines past the third are
    /// dropped), no time, no device and no name, stamped `OBSERVED`. The loop fills the other fields in.
    pub fn new(id: u64, high: bool, title: &str, lines: &[&str]) -> Self {
        Self {
            id,
            high,
            title: fit_text(title, ALERT_TITLE_CELLS),
            at: None,
            who: String::new(),
            stamp: AlertStamp::default(),
            lines: lines
                .iter()
                .zip(ALERT_LINE_CELLS)
                .map(|(line, cells)| fit_text(line, cells))
                .collect(),
            name: None,
            device: None,
        }
    }

    /// The precedence the log and the slip print: `URGENT` for a high alert, `ROUTINE` otherwise.
    pub const fn precedence(&self) -> &'static str {
        if self.high { "URGENT" } else { "ROUTINE" }
    }
}

impl fmt::Debug for AlertRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AlertRow")
            .field("id", &self.id)
            .field("high", &self.high)
            .field("stamp", &self.stamp)
            .finish_non_exhaustive()
    }
}

/// What the owner decided for a name that is on their own list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerVerdict {
    /// Answered though the lists refuse it.
    Allow,
    /// Refused though the lists answer it.
    Refuse,
}

/// The day an entry of the owner's list was set, for the words YOUR LIST and NAME say (spec §12.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DayWord {
    /// Today: `TODAY`.
    Today,
    /// An earlier day: `MON`.
    On(Weekday),
}

impl DayWord {
    /// The right figure of a row of YOUR LIST: `TODAY`, or `MON`.
    pub const fn caps(self) -> &'static str {
        match self {
            Self::Today => "TODAY",
            Self::On(day) => day.caps(),
        }
    }

    /// How a sentence says it after `by you`: ` today`, or ` since Mon`.
    pub fn since(self) -> String {
        match self {
            Self::Today => " today".to_string(),
            Self::On(day) => format!(" since {}", day.title()),
        }
    }
}

/// A name of the day's most refused, one pipe of NAMES.
///
/// `Debug` shows the valve only: not the name or its count.
#[derive(Clone, PartialEq, Eq)]
pub struct NameRow {
    /// The name, whole.
    pub name: String,
    /// How many times it was refused today.
    pub count: u32,
    /// Whether the owner let it through (the valve is open) though it is in the day's most refused.
    pub open: bool,
}

impl fmt::Debug for NameRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NameRow")
            .field("open", &self.open)
            .finish_non_exhaustive()
    }
}

/// An entry of the owner's own list, one pipe of YOUR LIST.
///
/// `Debug` shows the verdict only.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnerRow {
    /// The name, whole.
    pub name: String,
    /// Allowed or refused.
    pub verdict: OwnerVerdict,
    /// The day it was set on the panel; `None` for an entry pushed from the desktop (spec §12.8).
    pub day: Option<DayWord>,
}

impl fmt::Debug for OwnerRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnerRow")
            .field("verdict", &self.verdict)
            .finish_non_exhaustive()
    }
}

/// Which list holds a name, as the block set says it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameClass {
    /// A threat list: refused for every device, and never to be allowed from the panel.
    Threat,
    /// An ads list.
    Ads,
    /// The configuration's own deny list.
    Deny,
    /// No list: answered as any name is.
    None,
}

/// The owner's entry on a name, if it has one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerEntry {
    /// Allowed or refused.
    pub verdict: OwnerVerdict,
    /// The day it was set on the panel; `None` for an entry pushed from the desktop.
    pub day: Option<DayWord>,
}

/// What NAME needs to know of the name it shows: the facts of one name, which the loop fills while that
/// screen is open (spec §5.2: names are read only on NAMES, YOUR LIST and NAME).
///
/// `Debug` shows the class and the owner's verdict only.
#[derive(Clone, PartialEq, Eq)]
pub struct NameFacts {
    /// The name, whole: a NAME screen is about it by this text, and shows these facts when it matches.
    pub name: String,
    /// Which list holds it.
    pub class: NameClass,
    /// The owner's entry on it, if they have one.
    pub owner: Option<OwnerEntry>,
    /// How many times it was refused (or answered) today, when the Pi counts it: only the day's most
    /// refused names are counted, so the line has no figure for the others.
    pub count: Option<u32>,
}

impl NameFacts {
    /// Whether the name is refused now: a threat always; the owner's entry decides over the lists; else a
    /// name on a list is refused and one on none is answered.
    pub fn shut(&self) -> bool {
        match (self.class, self.owner) {
            (NameClass::Threat, _) => true,
            (_, Some(entry)) => entry.verdict == OwnerVerdict::Refuse,
            (NameClass::Ads | NameClass::Deny, None) => true,
            (NameClass::None, None) => false,
        }
    }
}

impl fmt::Debug for NameFacts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NameFacts")
            .field("class", &self.class)
            .field("owner", &self.owner.map(|entry| entry.verdict))
            .finish_non_exhaustive()
    }
}

/// What a device that is new to the house gets in the mode in force: the word on the wall's first empty place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Newcomer {
    /// Ads pass until the owner blocks them.
    #[default]
    AdsPass,
    /// Ads are blocked until the owner lets them pass.
    Blocked,
}

impl Newcomer {
    /// The word, in capitals.
    pub const fn word(self) -> &'static str {
        match self {
            Self::AdsPass => "ADS PASS",
            Self::Blocked => "BLOCKED",
        }
    }
}

/// The main gate while it is open: blocking paused for the house.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pause {
    /// Seconds until blocking turns on again.
    pub left_secs: u16,
    /// How long the pause was for, as chosen: 300, 1,800 or 3,600. The gate refills by `left / total`.
    pub total_secs: u16,
}

/// Everything the OS screens read.
///
/// `Debug` shows counts, never a name.
#[derive(Clone, PartialEq)]
pub struct World {
    /// The time of day; `None` while the clock is not set.
    pub time: Option<TimeOfDay>,
    /// Whether Wi-Fi is joined.
    pub wifi_joined: bool,
    /// Queries answered since midnight; `None` while unknown.
    pub queries_today: Option<u32>,
    /// Queries refused since midnight; `None` while unknown.
    pub refused_today: Option<u32>,
    /// The share of today's queries that were refused; `None` while unknown or with no queries.
    pub share: Option<Share>,
    /// How many names the lists hold; `None` while unknown.
    pub list_names: Option<u32>,
    /// The running version, as `0.4.1`.
    pub version: String,
    /// Whole days since the board started; `None` while unknown.
    pub uptime_days: Option<u32>,
    /// The main gate: `None` while blocking is on (the gate is shut).
    pub blocking: Option<Pause>,
    /// The devices on the wall, in the wall's order, at most `MAX_DEVICES`.
    pub devices: Vec<DeviceRow>,
    /// What a newcomer gets, in the mode in force.
    pub newcomer: Newcomer,
    /// The LIVE tile's lamp: white for 3 frames after a name went by in the lane.
    pub beat: bool,
    /// The last names the watched device asked, newest first, at most `MAX_WATCHED`; empty unless DEVICE is open.
    pub watched: Vec<WatchedName>,
    /// How many alerts wait.
    pub alerts_waiting: u32,
    /// When the newest waiting alert last happened; `None` with none waiting, or when its time is not today's.
    pub alert_newest: Option<TimeOfDay>,
    /// The newest waiting alerts, newest first, at most `MAX_ALERT_ROWS`: the log's lines, and the slips they open.
    pub alerts: Vec<AlertRow>,
    /// When the store's last alert happened, for the idle log's `LAST ENTRY FILED`; `None` when the store
    /// never had one (spec §12.3).
    pub last_entry: Option<Moment>,
    /// When this boot's watch opened (the clock less the uptime), for `WATCH OPENED`; `None` while the clock
    /// is not set.
    pub watch_opened: Option<Moment>,
    /// The log's cursor: on for 4 frames and off for 4 at 8 frames a second. The one thing that moves on a
    /// screen at rest (spec §12.4).
    pub cursor_on: bool,
    /// The day's most refused names, most refused first, at most `MAX_TOP_NAMES`; read while NAMES shows.
    pub top_names: Vec<NameRow>,
    /// How many names the owner's own list holds (YOUR OWN's figure); read while NAMES shows.
    pub owner_total: u32,
    /// The newest of the owner's own list, newest first, at most `MAX_OWNER_ROWS`; read while NAMES or YOUR
    /// LIST shows.
    pub owner_newest: Vec<OwnerRow>,
    /// The facts of the name NAME shows; `None` unless a NAME screen is open and the loop has read them.
    pub name_facts: Option<NameFacts>,
    /// Whether the lock is on. It is not in P1, and stays `false`.
    pub lock_on: bool,
    /// Where the PIN lives; read only while `lock_on` (the LOCK screen's second line).
    pub lock_source: LockSource,
    /// Whether the card keeps what the owner sets, so that a PIN from the desktop or the panel outlasts a
    /// restart whatever `lock_source` says; `false` until the loop reads it (the LOCK screen's second line,
    /// whether the lock is on or not).
    pub lock_kept: bool,
    /// The Wi-Fi link's figures; read while SYSTEM or WI-FI shows.
    pub link: Link,
    /// The board's readings; read while SYSTEM or one of its readings shows.
    pub machine: Machine,
    /// The night hours `(from, to)` as hours of the day; `None`, or the two equal, is no night (`OFF`).
    pub night: Option<(u8, u8)>,
    /// Where a rejoin of the Wi-Fi stands.
    pub rejoin: Rejoin,
    /// Whether an update is being received or is on trial: `REJOIN` and `RESTART` are inert (spec §3.8).
    pub update_busy: bool,
    /// Whether DNS answers: STARTING's last line is done (the slot is filled, and a query has been answered or the self-test has passed).
    pub dns_answering: bool,
    /// The update UPDATE draws; `None` while none is going on.
    pub update: Option<UpdateRead>,
    /// The seconds the PIN pad must wait before it takes digits again (the lock's backoff, spec §7.3); 0 when it does not
    /// wait. The loop sets it every time it makes a world while the pad shows.
    pub pin_wait_secs: u32,
}

impl Default for World {
    /// A world that knows nothing: no time, no figures, blocking on, no devices, no alerts.
    fn default() -> Self {
        Self {
            time: None,
            wifi_joined: false,
            queries_today: None,
            refused_today: None,
            share: None,
            list_names: None,
            version: String::new(),
            uptime_days: None,
            blocking: None,
            devices: Vec::new(),
            newcomer: Newcomer::default(),
            beat: false,
            watched: Vec::new(),
            alerts_waiting: 0,
            alert_newest: None,
            alerts: Vec::new(),
            last_entry: None,
            watch_opened: None,
            cursor_on: false,
            top_names: Vec::new(),
            owner_total: 0,
            owner_newest: Vec::new(),
            name_facts: None,
            lock_on: false,
            lock_source: LockSource::default(),
            lock_kept: false,
            link: Link::default(),
            machine: Machine::default(),
            night: None,
            rejoin: Rejoin::default(),
            update_busy: false,
            dns_answering: false,
            update: None,
            pin_wait_secs: 0,
        }
    }
}

impl fmt::Debug for World {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("World")
            .field("devices", &self.devices.len())
            .field("alerts_waiting", &self.alerts_waiting)
            .field("alerts", &self.alerts.len())
            .field("top_names", &self.top_names.len())
            .field("owner_total", &self.owner_total)
            .field("gate_open", &self.blocking.is_some())
            .field("lock_on", &self.lock_on)
            .field("rejoin", &self.rejoin)
            .field("update_busy", &self.update_busy)
            .field("dns_answering", &self.dns_answering)
            .field("update", &self.update.map(|update| update.phase))
            .field("pin_wait_secs", &self.pin_wait_secs)
            .finish_non_exhaustive()
    }
}

impl World {
    /// Adds a device to the wall's end; `false`, and not added, when the wall already has `MAX_DEVICES`.
    pub fn push_device(&mut self, row: DeviceRow) -> bool {
        if self.devices.len() >= MAX_DEVICES {
            return false;
        }
        self.devices.push(row);
        true
    }

    /// The device with this address, if it is on the wall: a screen about a device that is gone finds none and pops.
    pub fn device(&self, mac: &Mac) -> Option<&DeviceRow> {
        self.devices.iter().find(|row| row.mac == *mac)
    }

    /// How many devices have ads blocked by their state: the figure under `DEVICES` on HOME. The router and
    /// the Pi are `Always` and not counted.
    pub fn blocked_count(&self) -> usize {
        self.devices
            .iter()
            .filter(|row| row.state == DeviceState::Blocked)
            .count()
    }

    /// Whether any device is asking now: DEVICES' lamp.
    pub fn any_asking(&self) -> bool {
        self.devices.iter().any(|row| row.asking)
    }

    /// Whether the main gate is open.
    pub fn gate_open(&self) -> bool {
        self.blocking.is_some()
    }

    /// Whether the link is being joined again: `JOINING`, every dash dark, until it is back (spec §12.4).
    pub fn link_joining(&self) -> bool {
        self.rejoin == Rejoin::Joining
    }

    /// How many dashes of ten the link lights: `clamp(round((dBm + 100) / 5), 0, 10)`; none while it is down,
    /// being joined again, or its signal is not known.
    pub fn link_dashes(&self) -> u8 {
        if self.link_joining() || !self.wifi_joined {
            return 0;
        }
        self.link.signal_dbm.map_or(0, dashes_of)
    }

    /// The word for the link: `JOINING` while it is rejoined, `DOWN` while it is not joined, else by the
    /// signal `GOOD` (-65 dBm and better), `FAIR` (to -75) or `WEAK`; `None` when it is joined and the signal is
    /// not known.
    pub fn link_word(&self) -> Option<&'static str> {
        if self.link_joining() {
            return Some("JOINING");
        }
        if !self.wifi_joined {
            return Some("DOWN");
        }
        self.link.signal_dbm.map(|dbm| match dbm {
            -65.. => "GOOD",
            -75..=-66 => "FAIR",
            _ => "WEAK",
        })
    }

    /// The night hours that are in force: `None` when there are none (`OFF`, or the two hours equal).
    pub fn night_hours(&self) -> Option<(u8, u8)> {
        self.night.filter(|&(from, to)| from != to)
    }

    /// The newest waiting alert: HOME's tile and the lane open the log, which lists it last, but the arrival
    /// rule and P1's loop read the newest one.
    pub fn top_alert(&self) -> Option<&AlertRow> {
        self.alerts.first()
    }

    /// The alert with this store id, if the log holds it: a slip about an alert that is gone finds none and pops.
    pub fn alert(&self, id: u64) -> Option<&AlertRow> {
        self.alerts.iter().find(|row| row.id == id)
    }

    /// The bytes of a world that holds the most the types above allow: the struct, every row and every
    /// string full (a name's cells at four bytes each, the widest a character is in UTF-8, and a DNS name
    /// at its 253 bytes). The spec's budget for a world (§6.7) is 64 KB.
    pub const fn bound_bytes() -> usize {
        use std::mem::size_of;
        const CHAR: usize = 4;
        let alert_lines = ALERT_LINE_CELLS[0] + ALERT_LINE_CELLS[1] + ALERT_LINE_CELLS[2];
        let alert_row = size_of::<AlertRow>()
            + (ALERT_TITLE_CELLS + DEVICE_NAME_CELLS + alert_lines) * CHAR
            + MAX_ALERT_LINES * size_of::<String>()
            + NAME_BYTES_MAX;
        size_of::<Self>()
            + (VERSION_CELLS + BUILT_CELLS + RESTART_CAUSE_CELLS) * CHAR
            + MAX_DEVICES * (size_of::<DeviceRow>() + DEVICE_NAME_CELLS * CHAR)
            + MAX_WATCHED * (size_of::<WatchedName>() + WATCHED_NAME_CELLS * CHAR + NAME_BYTES_MAX)
            + MAX_ALERT_ROWS * alert_row
            + MAX_TOP_NAMES * (size_of::<NameRow>() + NAME_BYTES_MAX)
            + MAX_OWNER_ROWS * (size_of::<OwnerRow>() + NAME_BYTES_MAX)
            + size_of::<NameFacts>()
            + NAME_BYTES_MAX
    }

    /// The bytes of memory this world holds now: the struct and what its vectors and strings have room for.
    pub fn bytes(&self) -> usize {
        use std::mem::size_of;
        size_of::<Self>()
            + self.version.capacity()
            + self.machine.built.capacity()
            + self.machine.last_restart.capacity()
            + self.devices.capacity() * size_of::<DeviceRow>()
            + self
                .devices
                .iter()
                .map(|d| d.name.capacity())
                .sum::<usize>()
            + self.watched.capacity() * size_of::<WatchedName>()
            + self
                .watched
                .iter()
                .map(|w| w.name.capacity() + w.whole.as_ref().map_or(0, String::capacity))
                .sum::<usize>()
            + self.alerts.capacity() * size_of::<AlertRow>()
            + self
                .alerts
                .iter()
                .map(|alert| {
                    alert.title.capacity()
                        + alert.who.capacity()
                        + alert.name.as_ref().map_or(0, String::capacity)
                        + alert.lines.capacity() * size_of::<String>()
                        + alert.lines.iter().map(String::capacity).sum::<usize>()
                })
                .sum::<usize>()
            + self.top_names.capacity() * size_of::<NameRow>()
            + self
                .top_names
                .iter()
                .map(|row| row.name.capacity())
                .sum::<usize>()
            + self.owner_newest.capacity() * size_of::<OwnerRow>()
            + self
                .owner_newest
                .iter()
                .map(|row| row.name.capacity())
                .sum::<usize>()
            + self
                .name_facts
                .as_ref()
                .map_or(0, |facts| facts.name.capacity())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(octet: u8, state: DeviceState) -> DeviceRow {
        let (name, named) = display_name(None, None, octet);
        DeviceRow {
            mac: [2, 0, 0, 0, 0, octet],
            name,
            named,
            octet,
            state,
            fixed: false,
            asking: false,
        }
    }

    #[test]
    fn a_world_holding_the_most_is_within_its_bound_and_the_bound_within_64_kb() {
        // The widest a name's cells are in bytes is four each; use that for every name.
        let cells = |n: usize| "\u{1F600}".repeat(n);
        let mut world = World {
            version: cells(VERSION_CELLS),
            machine: Machine {
                built: cells(BUILT_CELLS),
                last_restart: cells(RESTART_CAUSE_CELLS),
                ..Machine::default()
            },
            devices: Vec::with_capacity(MAX_DEVICES),
            watched: Vec::with_capacity(MAX_WATCHED),
            ..World::default()
        };
        for octet in 0..MAX_DEVICES as u8 {
            let mut full = row(octet, DeviceState::Blocked);
            full.name = cells(DEVICE_NAME_CELLS);
            assert!(world.push_device(full));
        }
        for _ in 0..MAX_WATCHED {
            world.watched.push(WatchedName {
                name: cells(WATCHED_NAME_CELLS),
                whole: Some("n".repeat(NAME_BYTES_MAX)),
                outcome: Outcome::Refused,
            });
        }
        let name = "n".repeat(NAME_BYTES_MAX);
        world.alerts = Vec::with_capacity(MAX_ALERT_ROWS);
        world.top_names = Vec::with_capacity(MAX_TOP_NAMES);
        world.owner_newest = Vec::with_capacity(MAX_OWNER_ROWS);
        for id in 0..MAX_ALERT_ROWS as u64 {
            world.alerts.push(AlertRow {
                id,
                high: true,
                title: cells(ALERT_TITLE_CELLS),
                at: Some(When::Day(Weekday::Mon)),
                who: cells(DEVICE_NAME_CELLS),
                stamp: AlertStamp::Refused,
                lines: ALERT_LINE_CELLS.iter().map(|&n| cells(n)).collect(),
                name: Some(name.clone()),
                device: Some([2, 0, 0, 0, 0, 1]),
            });
        }
        for _ in 0..MAX_TOP_NAMES {
            world.top_names.push(NameRow {
                name: name.clone(),
                count: u32::MAX,
                open: false,
            });
        }
        for _ in 0..MAX_OWNER_ROWS {
            world.owner_newest.push(OwnerRow {
                name: name.clone(),
                verdict: OwnerVerdict::Allow,
                day: Some(DayWord::Today),
            });
        }
        world.name_facts = Some(NameFacts {
            name: name.clone(),
            class: NameClass::Ads,
            owner: None,
            count: Some(1),
        });

        let bound = World::bound_bytes();
        assert!(world.bytes() <= bound, "{} B over {bound} B", world.bytes());
        assert!(bound <= 64 * 1024, "{bound} B");
        // The empty world is the struct and nothing else.
        assert_eq!(World::default().bytes(), std::mem::size_of::<World>());
    }

    #[test]
    fn a_device_is_called_by_its_label_then_its_hostname_then_its_octet() {
        assert_eq!(
            display_name(Some("Desk PC"), Some("pc"), 12),
            ("Desk PC".into(), true)
        );
        assert_eq!(
            display_name(None, Some("printer"), 57),
            ("printer".into(), true)
        );
        assert_eq!(display_name(None, None, 143), ("\u{b7}143".into(), false));
        // Nothing but spaces is no name at all.
        assert_eq!(
            display_name(Some("  "), Some(""), 7),
            ("\u{b7}7".into(), false)
        );
        assert_eq!(
            display_name(Some(""), Some("doorbell"), 64),
            ("doorbell".into(), true)
        );
        // A name is fitted to its place, with a tilde.
        let long = display_name(Some("A very long label for a very small tile"), None, 1).0;
        assert_eq!(long.chars().count(), DEVICE_NAME_CELLS);
        assert!(long.ends_with('~'));
    }

    #[test]
    fn a_watched_name_is_held_whole_for_name_beside_what_its_row_shows() {
        let long = "a.very.long.host.name.of.a.tracker.example.org";
        let name = WatchedName::new(long, Outcome::Refused);
        assert_eq!(name.name, "a.tracker.example.org");
        assert_eq!(name.whole.as_deref(), Some(long));
        // The board shows the text its lane cut, and keeps the whole name for the door.
        let cut = WatchedName::shown_as("a.very.long.host", Some(long), Outcome::Answered);
        assert_eq!(
            (cut.name.as_str(), cut.whole.as_deref()),
            ("a.very.long.host", Some(long))
        );
        // A name that is not known whole, or is longer than a DNS name, or is empty, is no door.
        assert_eq!(
            WatchedName::shown_as("cut~", None, Outcome::Answered).whole,
            None
        );
        let too_long = "n".repeat(NAME_BYTES_MAX + 1);
        assert_eq!(
            WatchedName::shown_as("n", Some(&too_long), Outcome::Answered).whole,
            None
        );
        assert_eq!(WatchedName::new("", Outcome::Answered).whole, None);
        // `Debug` prints neither.
        assert!(!format!("{name:?}").contains("tracker"));
    }

    #[test]
    fn a_watched_name_is_fitted_like_a_site_and_an_alert_to_its_lines() {
        let name = WatchedName::new(
            "a.very.long.host.name.of.a.tracker.example.org",
            Outcome::Refused,
        );
        assert_eq!(
            name.name, "a.tracker.example.org",
            "host labels go first, whole"
        );
        assert_eq!(
            WatchedName::new("i.ytimg.com", Outcome::Answered).name,
            "i.ytimg.com"
        );
        assert_eq!(Outcome::Passed.word(), "PASSED");
        let alert = AlertRow::new(
            7,
            true,
            "PHISHING BLOCKED",
            &[
                "secure-login-verify.top",
                "second",
                "third",
                "a fourth line is dropped",
            ],
        );
        assert_eq!(alert.lines.len(), MAX_ALERT_LINES);
        assert_eq!(alert.lines[0], "secure-login-verify.top");
        let tall = AlertRow::new(1, false, &"T".repeat(80), &[&"x".repeat(80)]);
        assert_eq!(tall.title.chars().count(), ALERT_TITLE_CELLS);
        assert_eq!(tall.lines[0].chars().count(), ALERT_LINE_CELLS[0]);
        assert!(AlertRow::new(1, false, "T", &[]).lines.is_empty());
        // What a bare loop knows leaves the rest neutral: no time, no device, no name, observed.
        assert_eq!(
            (alert.at, alert.stamp, alert.name.as_ref(), alert.device),
            (None, AlertStamp::Observed, None, None)
        );
        assert_eq!(
            (alert.precedence(), tall.precedence()),
            ("URGENT", "ROUTINE")
        );
    }

    #[test]
    fn the_words_of_a_day_a_moment_and_a_stamp() {
        let time = TimeOfDay {
            hour: 21,
            minute: 40,
        };
        assert_eq!(When::Time(time).word(), "21:40");
        assert_eq!(When::Day(Weekday::Mon).word(), "MON");
        assert_eq!(
            Moment {
                day: Weekday::Tue,
                time: TimeOfDay { hour: 0, minute: 0 }
            }
            .word(),
            "TUE 00:00"
        );
        assert_eq!((Weekday::Sun.caps(), Weekday::Sun.title()), ("SUN", "Sun"));
        assert_eq!(DayWord::Today.caps(), "TODAY");
        assert_eq!(DayWord::On(Weekday::Mon).caps(), "MON");
        assert_eq!(DayWord::Today.since(), " today");
        assert_eq!(DayWord::On(Weekday::Mon).since(), " since Mon");
        assert_eq!(
            [
                AlertStamp::Refused,
                AlertStamp::Admitted,
                AlertStamp::Observed
            ]
            .map(AlertStamp::word),
            ["REFUSED", "ADMITTED", "OBSERVED"]
        );
    }

    #[test]
    fn a_name_is_shut_by_its_list_unless_the_owner_decided_and_a_threat_is_always_shut() {
        let facts = |class, owner: Option<OwnerVerdict>| NameFacts {
            name: "x.example.org".into(),
            class,
            owner: owner.map(|verdict| OwnerEntry { verdict, day: None }),
            count: None,
        };
        use NameClass::{Ads, Deny, None as NoList, Threat};
        use OwnerVerdict::{Allow, Refuse};
        assert!(facts(Ads, None).shut() && facts(Deny, None).shut());
        assert!(!facts(NoList, None).shut());
        // The owner's entry decides over the lists, both ways.
        assert!(!facts(Ads, Some(Allow)).shut());
        assert!(facts(NoList, Some(Refuse)).shut());
        // A threat stays shut whatever an entry says.
        assert!(facts(Threat, None).shut());
        assert!(facts(Threat, Some(Allow)).shut());
    }

    #[test]
    fn the_log_finds_an_alert_by_its_id_and_the_top_is_the_newest() {
        let mut world = World::default();
        assert!(world.top_alert().is_none() && world.alert(3).is_none());
        world.alerts = vec![
            AlertRow::new(9, true, "A", &[]),
            AlertRow::new(8, false, "B", &[]),
        ];
        assert_eq!(world.top_alert().map(|row| row.id), Some(9));
        assert_eq!(world.alert(8).map(|row| row.title.as_str()), Some("B"));
        assert!(world.alert(7).is_none());
    }

    #[test]
    fn debug_never_prints_a_name_an_address_or_a_line() {
        let mut world = World::default();
        let mut sam = row(23, DeviceState::AdsPass);
        sam.name = "Sam's phone".into();
        world.push_device(sam.clone());
        world.watched.push(WatchedName::new(
            "secret-tracker.example.org",
            Outcome::Refused,
        ));
        let mut alert = AlertRow::new(9, true, "PHISHING BLOCKED", &["secure-login-verify.top"]);
        alert.who = "Sam's phone".into();
        alert.name = Some("secure-login-verify.top".into());
        alert.device = Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        world.alerts = vec![alert];
        world.top_names = vec![NameRow {
            name: "ads.example.net".into(),
            count: 1204,
            open: false,
        }];
        world.owner_newest = vec![OwnerRow {
            name: "forum.example.com".into(),
            verdict: OwnerVerdict::Refuse,
            day: Some(DayWord::On(Weekday::Sun)),
        }];
        world.name_facts = Some(NameFacts {
            name: "tracker.example.com".into(),
            class: NameClass::Ads,
            owner: None,
            count: Some(861),
        });
        let said = format!(
            "{world:?} {sam:?} {:?} {:?} {:?} {:?} {:?}",
            world.watched, world.alerts, world.top_names, world.owner_newest, world.name_facts
        );
        for secret in [
            "Sam",
            "phone",
            "secret-tracker",
            "example.org",
            "PHISHING",
            "secure-login",
            "02:00",
            "[2, 0",
            "170",
            "ads.example",
            "forum",
            "tracker",
            "1204",
            "861",
            "Sun",
        ] {
            assert!(!said.contains(secret), "{said} holds {secret}");
        }
        assert!(said.contains("Refused") && said.contains("AdsPass"));
    }

    #[test]
    fn the_wall_holds_33_devices_and_finds_one_by_its_address() {
        let mut world = World::default();
        for octet in 0..MAX_DEVICES as u8 {
            assert!(world.push_device(row(octet, DeviceState::AdsPass)));
        }
        assert!(
            !world.push_device(row(200, DeviceState::Blocked)),
            "the 34th is refused"
        );
        assert_eq!(world.devices.len(), MAX_DEVICES);
        assert_eq!(world.device(&[2, 0, 0, 0, 0, 5]).map(|d| d.octet), Some(5));
        assert_eq!(world.device(&[2, 0, 0, 0, 0, 200]), None);
    }

    #[test]
    fn the_counts_the_home_tiles_read() {
        let mut world = World::default();
        assert!(!world.gate_open() && !world.any_asking());
        assert_eq!(world.blocked_count(), 0);
        world.push_device(row(1, DeviceState::Blocked));
        world.push_device(row(2, DeviceState::AdsPass));
        world.push_device(row(3, DeviceState::Always));
        world.push_device(row(4, DeviceState::Open { left_secs: 30 }));
        world.push_device(row(5, DeviceState::Blocked));
        assert_eq!(
            world.blocked_count(),
            2,
            "only the ones whose ads are blocked"
        );
        world.devices[3].asking = true;
        assert!(world.any_asking());
        world.blocking = Some(Pause {
            left_secs: 277,
            total_secs: 300,
        });
        assert!(world.gate_open());
    }

    #[test]
    fn the_newcomer_words_are_ads_pass_and_blocked() {
        assert_eq!(Newcomer::default(), Newcomer::AdsPass);
        assert_eq!(Newcomer::AdsPass.word(), "ADS PASS");
        assert_eq!(Newcomer::Blocked.word(), "BLOCKED");
    }

    #[test]
    fn a_world_is_small() {
        // The spec's memory budget: a world is at most 64 KB. Thirty-three rows of the longest names, an
        // alert and two watched names are well inside it.
        let mut world = World::default();
        for octet in 0..MAX_DEVICES as u8 {
            let mut full = row(octet, DeviceState::Blocked);
            full.name = "n".repeat(DEVICE_NAME_CELLS);
            world.push_device(full);
        }
        let bytes = world.devices.len() * (size_of::<DeviceRow>() + DEVICE_NAME_CELLS)
            + size_of::<World>()
            + 2 * (size_of::<WatchedName>() + WATCHED_NAME_CELLS + NAME_BYTES_MAX)
            + size_of::<AlertRow>()
            + ALERT_TITLE_CELLS
            + ALERT_LINE_CELLS.iter().sum::<usize>();
        assert!(bytes < 64 * 1024, "{bytes} bytes");
    }
    #[test]
    fn the_link_lights_dashes_by_its_signal_and_names_it() {
        // clamp(round((dBm + 100) / 5), 0, 10).
        for (dbm, dashes) in [
            (-54, 9),
            (-58, 8),
            (-60, 8),
            (-62, 8),
            (-63, 7),
            (-75, 5),
            (-90, 2),
            (-100, 0),
            (-110, 0),
            (-40, 10),
            (-20, 10),
        ] {
            assert_eq!(dashes_of(dbm), dashes, "{dbm} dBm");
        }
        let mut world = World {
            wifi_joined: true,
            link: Link {
                signal_dbm: Some(-54),
                ..Link::default()
            },
            ..World::default()
        };
        assert_eq!((world.link_dashes(), world.link_word()), (9, Some("GOOD")));
        for (dbm, word) in [
            (-65, "GOOD"),
            (-66, "FAIR"),
            (-75, "FAIR"),
            (-76, "WEAK"),
            (-90, "WEAK"),
        ] {
            world.link.signal_dbm = Some(dbm);
            assert_eq!(world.link_word(), Some(word), "{dbm} dBm");
        }
        // Joined and no reading: no dash lit and no word (the screen draws a dash).
        world.link.signal_dbm = None;
        assert_eq!((world.link_dashes(), world.link_word()), (0, None));
        // Not joined: DOWN, dark. Being joined again: JOINING, dark, whatever the signal was.
        world.link.signal_dbm = Some(-54);
        world.wifi_joined = false;
        assert_eq!((world.link_dashes(), world.link_word()), (0, Some("DOWN")));
        world.wifi_joined = true;
        world.rejoin = Rejoin::Joining;
        assert_eq!(
            (world.link_dashes(), world.link_word()),
            (0, Some("JOINING"))
        );
        // A refusal to rejoin again does not touch the link's reading.
        world.rejoin = Rejoin::Wait(30);
        assert_eq!((world.link_dashes(), world.link_word()), (9, Some("GOOD")));
    }

    #[test]
    fn the_band_comes_from_the_frequency_and_night_hours_that_are_equal_are_none() {
        assert_eq!(Band::from_mhz(5_180), Some(Band::Ghz5));
        assert_eq!(Band::from_mhz(2_437), Some(Band::Ghz24));
        assert_eq!(Band::from_mhz(0), None);
        assert_eq!(Band::from_mhz(5_955), None);
        assert_eq!(
            (Band::Ghz5.word(), Band::Ghz24.word()),
            ("5 GHZ", "2.4 GHZ")
        );
        let mut world = World::default();
        assert_eq!(world.night_hours(), None);
        world.night = Some((23, 7));
        assert_eq!(world.night_hours(), Some((23, 7)));
        world.night = Some((23, 23));
        assert_eq!(world.night_hours(), None, "from = to is no night");
        assert_eq!((Slot::A.letter(), Slot::B.letter()), ('A', 'B'));
    }
}
