//! The Drain: the scene the panel draws, as a model that moves one frame per
//! `tick`.
//!
//! A lane of name tiles runs right to left along the top. A gate stands in it;
//! a refused name stops against the gate, melts away from it, and drips into a
//! funnel of dots above the refused count. The funnel starts empty and fills
//! from the tip of its spout upward, one run of dots a name. The model knows no
//! pixels: `look` holds every coordinate, and the accessors here give a painter
//! what stands where.
//!
//! The model is deterministic: the same seed and the same calls make the same
//! scene. Nothing here panics, whatever the names, counts or order of calls,
//! and no name is ever printed: the types that hold one have no `Debug`, or a
//! redacting one.

use std::collections::VecDeque;
use std::fmt;

use crate::format::fit_site;
use crate::state::{Blocking, LaneWords, Share, TimeOfDay};

mod fixture;
pub mod look;
mod paint;
mod stamps;

pub use fixture::{Fixture, drain_fixture};
pub use paint::Painter;

use look::{DRIP_BASE, DRIP_KINDS, DRIP_STEP, FUNNEL_CELLS, GATE_CELL, LANE_CELLS};

/// How many cells of the lane a name may fill as it passes: all of it.
const NAME_CELLS: usize = LANE_CELLS as usize;

/// How many cells a refused name may fill: the ones between the gate and the right edge, where it stops.
const REFUSED_CELLS: usize = GATE_CELL as usize;

/// How many names wait for the lane.
pub const QUEUE_MAX: usize = 4;

/// Where the next landing starts after the funnel was filled in one go with `prefill`, as in the mockup.
const PREFILL_LANDING: usize = 61;

/// The step in which the melt reaches the first tile: step 1 shuts the door and step 2 holds, so the
/// first tile sags in step 3.
const MELT_HOLD: usize = 2;

/// How many tiles the melt passes in a step, moving away from the gate.
const MELT_TILES_PER_STEP: usize = 5;

/// The step at which the lane is clear of a stopped name of up to `MELT_TILES_PER_STEP` letters; every
/// further five letters add a step, since the melt reaches the last of them that much later.
const STEP_CLEAR_BASE: usize = 8;

/// What happened to a name, which decides how the lane treats it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameKind {
    /// Answered as usual: it passes the gate.
    Plain,
    /// Refused: it stops at the gate and melts.
    Refused,
    /// On the lists, but let through because blocking is paused: it passes, and is outlined while the pause lasts.
    Listed,
}

/// How a tile is drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TileStyle {
    /// A `BLUE_DEEP` fill and a `G1` letter.
    Plain,
    /// A `BLUE` fill and a white letter: a name stopped at the gate.
    Refused,
    /// A white outline and a white letter: a listed name let through a pause.
    Listed,
}

/// How far a stopped name's tile has melted. Each stage is one frame; the tiles stand where they stood.
///
/// The melt starts at the tile next to the gate and runs away from it, five tiles a frame, so a
/// name's last letters are readable the longest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Melt {
    /// Not melting: the whole tile, in its style.
    Whole,
    /// The tile sags: a blue block from `SAG_DY` down, the letter still legible in white.
    Sag,
    /// A puddle of `PUDDLE_H` at the foot of the tile, and a drip below it.
    Puddle,
    /// A slumped puddle of `SLUMP_H`, and a longer drip.
    Slump,
    /// A pool of `POOL_H` and a teardrop that has left it.
    Drop,
    /// The teardrop alone, lower, with no pool: it is falling.
    Fall,
}

/// One letter of a name on the lane.
///
/// The letter is a character of a name: this type says nothing of it when it is printed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Tile {
    /// The lane cell, 0 to 19; `look::cell_x` gives its left edge.
    pub cell: u8,
    /// The letter: lower-case printable ASCII, a `?`, or the `~` that ends a cut name.
    pub ch: char,
    /// How to draw the whole tile; a melting tile is drawn as its `melt` says.
    pub style: TileStyle,
    /// How far the tile has melted.
    pub melt: Melt,
    /// How long this tile's drip is, in pixels: 4, 8 or 12, from its letter and its place in the name. A
    /// teardrop falls from the end of it.
    pub drip: u8,
}

impl fmt::Debug for Tile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tile")
            .field("cell", &self.cell)
            .field("style", &self.style)
            .field("melt", &self.melt)
            .field("drip", &self.drip)
            .finish_non_exhaustive()
    }
}

/// The colour of a lit funnel dot at rest: one per run, three in turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shade {
    /// `BLUE`.
    Blue,
    /// `BLUE_MD`.
    Mid,
    /// `BLUE_DK`: with the others, it tells one name's run of dots from the next.
    Dark,
}

impl Shade {
    /// The shade of the next run.
    fn next(self) -> Self {
        match self {
            Shade::Blue => Shade::Mid,
            Shade::Mid => Shade::Dark,
            Shade::Dark => Shade::Blue,
        }
    }
}

/// A funnel dot just landed: it is drawn in white, turning over for two frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flip {
    /// At rest: a dot of its shade, `DOT_R` in radius.
    Rest,
    /// Face-on: a white dot of `FLIP_FACE_R`.
    Face,
    /// Edge-on: a white ellipse, `FLIP_EDGE_RX` by `FLIP_EDGE_RY`.
    Edge,
}

/// One dot of the funnel; its place is `look::FUNNEL_CENTRES` at the same index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FunnelCell {
    /// The colour of the run it was lit in, and the colour it goes back to; `None` for a socket that no
    /// refused name has landed in yet.
    pub shade: Option<Shade>,
    /// Whether it is landing.
    pub flip: Flip,
}

impl FunnelCell {
    /// A dot nothing has landed in.
    const EMPTY: Self = Self {
        shade: None,
        flip: Flip::Rest,
    };
}

/// The mulberry32 generator, as in the mockup's `common.js`.
struct Mulberry32(u32);

impl Mulberry32 {
    /// A generator from a seed.
    fn new(seed: u32) -> Self {
        Self(seed)
    }

    /// The next 32 bits.
    fn next_u32(&mut self) -> u32 {
        self.0 = self.0.wrapping_add(0x6D2B_79F5);
        let mut t = self.0;
        t = (t ^ (t >> 15)).wrapping_mul(t | 1);
        t ^= t.wrapping_add((t ^ (t >> 7)).wrapping_mul(t | 61));
        t ^ (t >> 14)
    }

    /// The next number below `n` (0 for `n` of 0), as the mockup's `floor(r() * n)`.
    fn below(&mut self, n: u32) -> u32 {
        ((u64::from(self.next_u32()) * u64::from(n)) >> 32) as u32
    }
}

/// A name waiting for the lane.
struct Queued {
    /// The name as the lane shows it: at most `REFUSED_CELLS` characters if it is refused, else `NAME_CELLS`.
    text: Vec<char>,
    /// What happened to it.
    kind: NameKind,
}

/// A name on the lane.
struct OnLane {
    /// The name as the lane shows it: at most `REFUSED_CELLS` characters if it is refused, else `NAME_CELLS`.
    text: Vec<char>,
    /// What happened to it.
    kind: NameKind,
    /// The cell of its first letter, which leads; -1 when it has not yet come in.
    head: i32,
    /// How far its refusal has gone: 0 while it moves, then 1 to `done_step`.
    step: u8,
}

impl OnLane {
    /// How many cells the name fills.
    fn len(&self) -> i32 {
        i32::try_from(self.text.len()).unwrap_or(i32::MAX)
    }

    /// The cell of its last letter.
    fn tail(&self) -> i32 {
        self.head - self.len() + 1
    }

    /// The step of its refusal at which the lane is clear of it: `8 + floor((len - 1) / 5)`.
    ///
    /// The melt reaches the letter `k` places from the gate `k / 5` steps after the first, so the last
    /// letter is gone when the first has taken 6 stages and the last has waited its turn. Everything
    /// after that is counted from here.
    fn clear_step(&self) -> u8 {
        let wait = self.text.len().saturating_sub(1) / MELT_TILES_PER_STEP;
        u8::try_from(STEP_CLEAR_BASE + wait).unwrap_or(u8::MAX)
    }

    /// The step at which its dots land in the funnel, edge-on: the next after the lane is clear.
    fn land_step(&self) -> u8 {
        self.clear_step().saturating_add(1)
    }

    /// The step at which the drop shows at the spout; it is gone the step after.
    fn drop_step(&self) -> u8 {
        self.clear_step().saturating_add(4)
    }

    /// The step at which it is counted.
    fn count_step(&self) -> u8 {
        self.clear_step().saturating_add(6)
    }

    /// The last step of its refusal: the door reopens, and the name leaves on the next tick.
    fn done_step(&self) -> u8 {
        self.clear_step().saturating_add(7)
    }

    /// How far the tile `k` places from the gate has melted; `None` once nothing of it is left to draw.
    ///
    /// The first stage of a tile is `step - 2 - k / 5`: the melt starts next to the gate and runs
    /// away from it, five tiles a step. Up to stage 0 the tile is whole.
    fn melt(&self, k: usize) -> Option<Melt> {
        let stage = usize::from(self.step).saturating_sub(MELT_HOLD + k / MELT_TILES_PER_STEP);
        match stage {
            0 => Some(Melt::Whole),
            1 => Some(Melt::Sag),
            2 => Some(Melt::Puddle),
            3 => Some(Melt::Slump),
            4 => Some(Melt::Drop),
            5 => Some(Melt::Fall),
            _ => None,
        }
    }

    /// Its tiles that are on the lane, the last letter first.
    fn tiles(&self, paused: bool, door: bool) -> impl Iterator<Item = Tile> + '_ {
        let style = if self.step > 0 {
            TileStyle::Refused
        } else if paused && self.kind == NameKind::Listed {
            TileStyle::Listed
        } else {
            TileStyle::Plain
        };
        let first = self.tail();
        let last = self.text.len().saturating_sub(1);
        (0..self.text.len()).filter_map(move |i| {
            // The first letter leads, and is next to the gate when the name stops: `k` places from it.
            let k = last - i;
            let melt = self.melt(k)?;
            let at = first + i32::try_from(i).ok()?;
            let cell = u8::try_from(at).ok().filter(|&c| c < LANE_CELLS)?;
            // The door covers the gate's cell while it is shut.
            if door && cell == GATE_CELL {
                return None;
            }
            let ch = *self.text.get(k)?;
            Some(Tile {
                cell,
                ch,
                style,
                melt,
                drip: drip_of(ch, k),
            })
        })
    }
}

/// How long the drip of the tile `k` places from the gate is: 4, 8 or 12 pixels, from its letter, so that
/// the lengths do not make a pattern.
fn drip_of(ch: char, k: usize) -> u8 {
    let k = u32::try_from(k).unwrap_or(0);
    let kind = (u32::from(ch) * 7 + k * 5) % DRIP_KINDS;
    DRIP_BASE + DRIP_STEP * u8::try_from(kind).unwrap_or(0)
}

/// The Drain scene: the lane, the funnel and the count.
///
/// Feed it names with `offer` and the figure of the day with
/// `set_blocked_today`, then call `tick` once per frame while `moving`. Read
/// the scene back with `lane`, `door_shut`, `funnel`, `spout_drop`, `idle` and `count`.
///
/// It has no `Debug`: the lane holds names.
pub struct Drain {
    /// The names on the lane, the one furthest along first.
    names: Vec<OnLane>,
    /// The names waiting, the oldest first.
    queue: VecDeque<Queued>,
    /// The funnel's dots, in landing order.
    funnel: [FunnelCell; FUNNEL_CELLS],
    /// The dot at which the next landing run starts; `FUNNEL_CELLS` once the rim is reached.
    landing: usize,
    /// The shade of the next landing run.
    shade: Shade,
    /// Whether the door across the lane is shut.
    door: bool,
    /// Whether blocking was paused at the last `tick` or `set_paused`.
    paused: bool,
    /// What the resolver says was blocked today, as of its last snapshot.
    blocked: Option<u32>,
    /// What the count shows.
    shown: Option<u32>,
    /// The last count that was shown, kept while the figure is not known (the Wi-Fi is down), so that
    /// the count does not step back when it returns.
    floor: Option<u32>,
}

impl Drain {
    /// A Drain with an empty lane and an empty funnel: every dot is a socket until a refused name lands in
    /// it, from the tip of the spout upward.
    ///
    /// Nothing in the Drain is random, so the seed is not used; `prefill` takes its own. It stays so that
    /// a caller need not change.
    pub fn new(_seed: u32) -> Self {
        Self {
            names: Vec::new(),
            queue: VecDeque::new(),
            funnel: [FunnelCell::EMPTY; FUNNEL_CELLS],
            landing: 0,
            shade: Shade::Blue,
            door: false,
            paused: false,
            blocked: None,
            shown: None,
            floor: None,
        }
    }

    /// Fills the whole funnel at once, as the mockup's `fill`: runs of 6 to 15 dots in the three shades in
    /// turn, from the tip of the spout, the last one cut at the rim. For stills and tests; the panel's
    /// funnel fills as names land.
    ///
    /// The runs come from the mockup's generator seeded with `seed`, after the one draw that its traffic
    /// simulation makes first. The next landing starts at dot 61, and no dot is turning.
    pub fn prefill(&mut self, seed: u32) {
        let mut random = Mulberry32::new(seed);
        random.next_u32();
        self.funnel = [FunnelCell::EMPTY; FUNNEL_CELLS];
        let mut shade = Shade::Blue;
        let mut at = 0;
        while at < FUNNEL_CELLS {
            let run = 6 + random.below(10) as usize;
            for cell in self.funnel.iter_mut().skip(at).take(run) {
                cell.shade = Some(shade);
            }
            at += run;
            shade = shade.next();
        }
        self.landing = PREFILL_LANDING;
        self.shade = shade;
    }

    /// Tells the Drain whether blocking is paused, without a frame.
    ///
    /// `tick` does this too. Call it first when a name is offered while the lane is idle, so that a
    /// refused name offered during a pause is shown as the listed name it is.
    pub fn set_paused(&mut self, paused: bool) {
        self.paused = paused;
    }

    /// Offers a name to the lane.
    ///
    /// A refused name is fitted to the 15 cells it stops in and any other to the lane's 20, by
    /// `fit_site`: host labels go first, whole, and a site that is still too long is cut with a `~`. A
    /// name that is empty on the screen is dropped, and so is one that shows the same text and is of the
    /// same kind as one that is queued or on the lane: a plain `example.com` never holds back a refused
    /// `pixel.example.com`, which fits to the same text but has a melt to run and a count to raise. The
    /// queue holds 4: when it is over, the oldest plain name goes, then the oldest listed one, then the
    /// oldest refused one. A refused name offered while paused is a listed one, and gets 20 cells.
    pub fn offer(&mut self, name: &str, kind: NameKind) {
        let kind = match kind {
            NameKind::Refused if self.paused => NameKind::Listed,
            kind => kind,
        };
        let cells = if kind == NameKind::Refused {
            REFUSED_CELLS
        } else {
            NAME_CELLS
        };
        let text: Vec<char> = fit_site(name, cells).chars().collect();
        if text.is_empty()
            || self
                .queue
                .iter()
                .any(|queued| queued.kind == kind && queued.text == text)
            || self
                .names
                .iter()
                .any(|on_lane| on_lane.kind == kind && on_lane.text == text)
        {
            return;
        }
        self.queue.push_back(Queued { text, kind });
        while self.queue.len() > QUEUE_MAX {
            let oldest = |kind| self.queue.iter().position(|queued| queued.kind == kind);
            let shed = oldest(NameKind::Plain)
                .or_else(|| oldest(NameKind::Listed))
                .unwrap_or(0);
            self.queue.remove(shed);
        }
        self.refresh_count();
    }

    /// Whether the Drain needs a `tick`: a name is queued or on the lane, or a landed dot is still turning.
    pub fn moving(&self) -> bool {
        !self.idle() || self.funnel.iter().any(|cell| cell.flip != Flip::Rest)
    }

    /// Whether the lane has nothing to carry: no name is on it and none is queued. The lane's words show
    /// only then.
    pub fn idle(&self) -> bool {
        self.names.is_empty() && self.queue.is_empty()
    }

    /// How many names wait for the lane, at most `QUEUE_MAX`. For gauges and tests.
    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    /// Advances the scene one frame, 125 ms. `paused` is whether blocking is paused now.
    ///
    /// A refused name that reaches the cell before the gate stops, and every name on the lane waits for it.
    /// Its refusal takes 15 to 17 frames, `G + 7` of them with `G = 8 + floor((letters - 1) / 5)`, and each
    /// changes one place of the screen: the tiles turn blue and the door shuts (1), they hold (2), then the
    /// melt runs away from the gate five tiles a frame, each tile sagging, puddling, slumping, dropping and
    /// falling in a frame of its own until the lane is clear (`G`), the dots land in the funnel (`G + 1`),
    /// turn over (`G + 2`) and settle (`G + 3`), a drop shows at the spout (`G + 4`) and is gone (`G + 5`),
    /// the count rises (`G + 6`), and the door reopens (`G + 7`). The name leaves on the frame after.
    pub fn tick(&mut self, paused: bool) {
        self.paused = paused;
        for cell in &mut self.funnel {
            cell.flip = match cell.flip {
                Flip::Edge => Flip::Face,
                Flip::Face | Flip::Rest => Flip::Rest,
            };
        }
        // A name whose last step was shown leaves now.
        self.names.retain(|name| name.step < name.done_step());
        let halt = self.names.iter().any(|name| name.step > 0);
        let gate = i32::from(GATE_CELL);
        let mut shut = false;
        let mut landing = None;
        for k in 0..self.names.len() {
            let ahead_tail = k
                .checked_sub(1)
                .and_then(|ahead| self.names.get(ahead))
                .map(OnLane::tail);
            let Some(name) = self.names.get_mut(k) else {
                break;
            };
            if name.step > 0 {
                name.step = name.step.saturating_add(1);
                shut = name.step < name.done_step();
                if name.step == name.land_step() {
                    landing = Some(name.text.len());
                }
                continue;
            }
            if halt {
                continue;
            }
            if name.kind == NameKind::Refused && name.head == gate - 1 {
                name.step = 1;
                shut = true;
                continue;
            }
            // One empty cell stays between a name and the one ahead of it.
            if ahead_tail.is_none_or(|tail| name.head + 1 < tail - 1) {
                name.head += 1;
            }
        }
        if let Some(count) = landing {
            self.land(count);
        }
        let past = i32::from(LANE_CELLS);
        self.names.retain(|name| name.tail() < past);
        self.door = shut;
        let clear = self.names.last().is_none_or(|last| last.tail() >= 1);
        if !halt
            && clear
            && let Some(queued) = self.queue.pop_front()
        {
            self.names.push(OnLane {
                text: queued.text,
                kind: queued.kind,
                head: -1,
                step: 0,
            });
        }
        self.refresh_count();
    }

    /// Lands `count` dots in the funnel in the next shade, turning over.
    ///
    /// The funnel fills from the tip of the spout upward. A run is cut at the rim, never wrapped: it
    /// lights the dots that are left, and the next run starts at the tip again.
    fn land(&mut self, count: usize) {
        if self.landing >= FUNNEL_CELLS {
            self.landing = 0;
        }
        let count = count.min(FUNNEL_CELLS - self.landing);
        let landed = FunnelCell {
            shade: Some(self.shade),
            flip: Flip::Edge,
        };
        for cell in self.funnel.iter_mut().skip(self.landing).take(count) {
            *cell = landed;
        }
        self.landing += count;
        self.shade = self.shade.next();
    }

    /// Sets what the resolver says was blocked today; `None` while it does not know.
    ///
    /// The count follows it, held back by the refused names still on their way, so that the count rises
    /// as each melts and never runs ahead of the figure.
    pub fn set_blocked_today(&mut self, blocked: Option<u32>) {
        self.blocked = blocked;
        self.refresh_count();
    }

    /// The refused names that are queued or on the lane and not yet counted.
    fn in_flight(&self) -> u32 {
        let queued = self
            .queue
            .iter()
            .filter(|queued| queued.kind == NameKind::Refused)
            .count();
        let on_lane = self
            .names
            .iter()
            .filter(|name| name.kind == NameKind::Refused && name.step < name.count_step())
            .count();
        u32::try_from(queued + on_lane).unwrap_or(u32::MAX)
    }

    /// Works out what the count shows.
    ///
    /// The count never goes down while the figure goes on, and that holds across a dash too: the last
    /// count shown is a floor until the figure is known again.
    fn refresh_count(&mut self) {
        self.shown = self.blocked.map(|blocked| {
            let counted = blocked.saturating_sub(self.in_flight());
            match self.floor {
                None => counted,
                // A figure below what was shown is a new day.
                Some(floor) if blocked < floor => blocked,
                Some(floor) => floor.max(counted),
            }
        });
        if self.shown.is_some() {
            self.floor = self.shown;
        }
    }

    /// What the panel shows as the refused count: the day's figure less the refused names not yet counted. A dash (`None`) until the figure is known.
    pub fn count(&self) -> Option<u32> {
        self.shown
    }

    /// The step of the refusal in progress, 1 to 17 by the name's length; `None` when no name is stopped. For goldens and tests.
    pub fn refusal_step(&self) -> Option<u8> {
        self.names
            .iter()
            .find(|name| name.step > 0)
            .map(|name| name.step)
    }

    /// The tiles on the lane, each name's last letter first. A name that has melted away has none.
    ///
    /// Tiles off the lane are left out, and so is any tile in the gate's cell while the door is shut, so
    /// the painter draws every tile it gets.
    pub fn lane(&self) -> impl Iterator<Item = Tile> + '_ {
        let (paused, door) = (self.paused, self.door);
        self.names
            .iter()
            .flat_map(move |name| name.tiles(paused, door))
    }

    /// Whether the door across the lane is shut. It is drawn only while blocking is on; paused, the gate is hollow.
    pub fn door_shut(&self) -> bool {
        self.door
    }

    /// The funnel's dots, in the order of `look::FUNNEL_CENTRES`: landing order, from the tip of the spout.
    pub fn funnel(&self) -> &[FunnelCell; FUNNEL_CELLS] {
        &self.funnel
    }

    /// Whether the drop that leaves the spout before the count rises is showing: one white dot below the
    /// spout, for one frame. It is the step between the funnel and the number.
    pub fn spout_drop(&self) -> bool {
        self.names
            .iter()
            .any(|name| name.step > 0 && name.step == name.drop_step())
    }
}

/// An alert, as the takeover card shows it.
///
/// The subject is a DNS name: this type says nothing of it, or of who, when it is printed.
#[derive(Clone, PartialEq, Eq)]
pub struct AlertCard {
    /// Whether the card is white (high severity) rather than blue.
    pub high: bool,
    /// The two title lines.
    pub title: [String; 2],
    /// What the alert is about, as a name on one line of the card's width, or on two broken after a dot.
    /// The second line is empty when the first is enough.
    pub subject: [String; 2],
    /// Who it concerns: `asked by <ip>`, `at <ip>`, or empty.
    pub who: String,
}

impl AlertCard {
    /// The subject's lines that have something on them: one, or two.
    pub fn subject_lines(&self) -> impl Iterator<Item = &str> {
        self.subject
            .iter()
            .map(String::as_str)
            .filter(|line| !line.is_empty())
    }
}

impl fmt::Debug for AlertCard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AlertCard")
            .field("high", &self.high)
            .field("title", &self.title)
            .finish_non_exhaustive()
    }
}

/// The slow figures of the panel, which change one region per write.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Stills {
    /// The share of today's queries that were blocked; `None` while unknown or when there were none.
    pub percent: Option<Share>,
    /// The time of day; `None` while the clock is not set.
    pub clock: Option<TimeOfDay>,
    /// Whether blocking is on, or paused with how long is left.
    pub blocking: Blocking,
    /// How full the paused gate is, as steps of 12 pixels from the floor, 0 to 18; see `format::gate_fill`.
    /// It is its own still so that it never goes out with the key's countdown.
    pub gate_fill: u8,
    /// The refused count; `None` while unknown.
    pub count: Option<u32>,
    /// The alert that covers part of the screen, if any.
    pub alert: Option<AlertCard>,
    /// The words the lane says while it has no names, if any; the painter shows them only while the
    /// Drain is `idle`.
    pub words: Option<LaneWords>,
}

impl Stills {
    /// Copies one field that differs from `wanted`, and says whether there was one.
    ///
    /// The order is the blocking switch, the gate's refill, the alert, the count, the share, the clock
    /// and the lane's words. Calling it until it says `false` makes `self` equal `wanted`, and each call
    /// changes one region of the screen, so that every still region is written on its own.
    pub fn step_toward(&mut self, wanted: &Stills) -> bool {
        if self.blocking != wanted.blocking {
            self.blocking = wanted.blocking;
        } else if self.gate_fill != wanted.gate_fill {
            self.gate_fill = wanted.gate_fill;
        } else if self.alert != wanted.alert {
            self.alert.clone_from(&wanted.alert);
        } else if self.count != wanted.count {
            self.count = wanted.count;
        } else if self.percent != wanted.percent {
            self.percent = wanted.percent;
        } else if self.clock != wanted.clock {
            self.clock = wanted.clock;
        } else if self.words != wanted.words {
            self.words = wanted.words;
        } else {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::look::{FUNNEL_CENTRES, FUNNEL_ROWS};
    use super::*;
    use crate::format::{alert_card, fit_name};

    /// Ticks until the stopped name is at `step`; fails if it never gets there.
    fn tick_to_step(d: &mut Drain, step: u8) {
        for _ in 0..300 {
            if d.refusal_step() == Some(step) {
                return;
            }
            d.tick(false);
        }
        panic!("never reached step {step}");
    }

    /// The first `len` letters of the alphabet: a name with no dot, which fits any lane whole.
    fn letters(len: usize) -> String {
        "abcdefghijklmno".chars().take(len).collect()
    }

    /// The melt of the tiles of the stopped name `letters(len)`, one character each, the tile next to the
    /// gate first: `W`hole, `S`ag, `P`uddle, `L` (slump), `D`rop and `F`all, or `.` where it is gone.
    fn melt_string(d: &Drain, len: usize) -> String {
        (0..len)
            .map(|k| {
                // The first letter stops in the cell before the gate; each next one is a cell further back.
                let cell = GATE_CELL - 1 - u8::try_from(k).unwrap_or(0);
                match d
                    .lane()
                    .find(|tile| tile.cell == cell)
                    .map(|tile| tile.melt)
                {
                    Some(Melt::Whole) => 'W',
                    Some(Melt::Sag) => 'S',
                    Some(Melt::Puddle) => 'P',
                    Some(Melt::Slump) => 'L',
                    Some(Melt::Drop) => 'D',
                    Some(Melt::Fall) => 'F',
                    None => '.',
                }
            })
            .collect()
    }

    /// What the screen shows of a Drain in the four places a refusal's steps change one at a time.
    #[derive(PartialEq)]
    struct Places {
        /// The tiles and the door.
        lane: (Vec<Tile>, bool),
        /// The dots.
        funnel: [FunnelCell; FUNNEL_CELLS],
        /// The drop at the spout.
        drop: bool,
        /// The count.
        count: Option<u32>,
    }

    /// The four places of a Drain.
    fn places(d: &Drain) -> Places {
        Places {
            lane: (d.lane().collect(), d.door_shut()),
            funnel: *d.funnel(),
            drop: d.spout_drop(),
            count: d.count(),
        }
    }

    /// The names of the places that differ.
    fn changed(a: &Places, b: &Places) -> Vec<&'static str> {
        [
            ("lane", a.lane != b.lane),
            ("funnel", a.funnel != b.funnel),
            ("drop", a.drop != b.drop),
            ("count", a.count != b.count),
        ]
        .into_iter()
        .filter_map(|(name, differs)| differs.then_some(name))
        .collect()
    }

    /// Offers a refused name to an empty drain, runs it to its end, and returns the funnel cells that landed.
    fn refuse_to_the_end(d: &mut Drain, name: &str) -> Vec<usize> {
        d.offer(name, NameKind::Refused);
        let mut landed = Vec::new();
        for _ in 0..300 {
            d.tick(false);
            if landed.is_empty() {
                landed = (0..FUNNEL_CELLS)
                    .filter(|&i| d.funnel()[i].flip == Flip::Edge)
                    .collect();
            }
            if !d.moving() {
                return landed;
            }
        }
        panic!("a refusal never finished");
    }

    /// A refused name of 15 letters that is a different site for each `i`, so that none is a duplicate.
    fn site(i: usize) -> String {
        format!("ads{i}example.org")
    }

    #[test]
    fn a_refusal_takes_fifteen_to_seventeen_steps_by_length() {
        for len in 1..=15_usize {
            // G is the step at which the lane is clear; the door reopens seven steps later, the last.
            let g = 8 + (len - 1) / 5;
            let last = g + 7;
            let want = match len {
                1..=5 => 15,
                6..=10 => 16,
                _ => 17,
            };
            assert_eq!(last, want, "{len} letters");
            let mut d = Drain::new(7);
            d.offer(&letters(len), NameKind::Refused);
            d.set_blocked_today(Some(100));
            assert_eq!(
                d.count(),
                Some(99),
                "held back while the name is on its way"
            );
            tick_to_step(&mut d, 1);
            assert_eq!(d.names[0].head, 14, "it stops one cell before the gate");
            assert!(d.door_shut());
            assert!(d.lane().all(|t| t.style == TileStyle::Refused));
            assert_eq!(d.lane().count(), len);
            let mut before = places(&d);
            let mut steps = 1;
            loop {
                d.tick(false);
                let Some(step) = d.refusal_step() else { break };
                steps = usize::from(step);
                assert_eq!(steps, usize::from(step));
                let now = places(&d);
                // Each step changes one place only: the lane (and its door), the funnel, the drop or the count.
                let want: &[&str] = if steps == 2 {
                    &[]
                } else if steps <= g || steps == last {
                    &["lane"]
                } else if steps <= g + 3 {
                    &["funnel"]
                } else if steps <= g + 5 {
                    &["drop"]
                } else {
                    &["count"]
                };
                assert_eq!(changed(&before, &now), want, "{len} letters, step {steps}");
                assert_eq!(
                    d.door_shut(),
                    steps < last,
                    "the door reopens at step {last}"
                );
                assert_eq!(
                    d.spout_drop(),
                    steps == g + 4,
                    "the drop shows at step {}",
                    g + 4
                );
                assert_eq!(d.count(), Some(if steps < g + 6 { 99 } else { 100 }));
                // The dots land edge-on, turn face-on, and settle, in three steps of their own.
                let flips = |flip| d.funnel().iter().filter(|c| c.flip == flip).count();
                let (edge, face) = (flips(Flip::Edge), flips(Flip::Face));
                assert_eq!(
                    (edge, face),
                    match steps {
                        s if s == g + 1 => (len, 0),
                        s if s == g + 2 => (0, len),
                        _ => (0, 0),
                    },
                    "{len} letters, step {steps}"
                );
                before = now;
            }
            assert_eq!(steps, last, "{len} letters");
            assert!(!d.moving() || d.funnel().iter().any(|c| c.flip != Flip::Rest) || !d.idle());
            d.tick(false);
            assert!(!d.moving());
            assert!(d.idle());
            assert_eq!(d.lane().count(), 0);
            assert!(!d.door_shut());
            // The run landed at the tip: as many dots as the name has letters.
            assert_eq!(d.funnel().iter().filter(|c| c.shade.is_some()).count(), len);
            assert!(
                d.funnel()
                    .iter()
                    .take(len)
                    .all(|c| c.shade == Some(Shade::Blue))
            );
        }
    }

    #[test]
    fn the_melt_runs_away_from_the_gate_five_tiles_a_frame() {
        // Read back from what the mockup's d6.js draws for a refusal of this many letters, step by step, the
        // tile next to the gate first: the first stage of the tile `k` places from the gate is step `3 + k / 5`.
        let frames: [(usize, &[&str]); 3] = [
            (
                15,
                &[
                    "WWWWWWWWWWWWWWW",
                    "WWWWWWWWWWWWWWW",
                    "SSSSSWWWWWWWWWW",
                    "PPPPPSSSSSWWWWW",
                    "LLLLLPPPPPSSSSS",
                    "DDDDDLLLLLPPPPP",
                    "FFFFFDDDDDLLLLL",
                    ".....FFFFFDDDDD",
                    "..........FFFFF",
                    "...............",
                ],
            ),
            (
                11,
                &[
                    "WWWWWWWWWWW",
                    "WWWWWWWWWWW",
                    "SSSSSWWWWWW",
                    "PPPPPSSSSSW",
                    "LLLLLPPPPPS",
                    "DDDDDLLLLLP",
                    "FFFFFDDDDDL",
                    ".....FFFFFD",
                    "..........F",
                    "...........",
                ],
            ),
            (
                6,
                &[
                    "WWWWWW", "WWWWWW", "SSSSSW", "PPPPPS", "LLLLLP", "DDDDDL", "FFFFFD", ".....F",
                    "......",
                ],
            ),
        ];
        for (len, want) in frames {
            let mut d = Drain::new(7);
            d.offer(&letters(len), NameKind::Refused);
            tick_to_step(&mut d, 1);
            for (i, melts) in want.iter().enumerate() {
                assert_eq!(d.refusal_step(), Some(u8::try_from(i + 1).unwrap()));
                assert_eq!(
                    &melt_string(&d, len),
                    melts,
                    "{len} letters, step {}",
                    i + 1
                );
                d.tick(false);
            }
        }
        // The tiles keep their places while they melt, and a tile that melts is the same letter.
        let mut d = Drain::new(7);
        d.offer("doubleclick.net", NameKind::Refused);
        tick_to_step(&mut d, 3);
        let tiles: Vec<Tile> = d.lane().collect();
        assert_eq!(tiles.len(), 15);
        let name: Vec<char> = "doubleclick.net".chars().collect();
        for tile in &tiles {
            let k = usize::from(14 - tile.cell);
            assert_eq!(tile.ch, name[k], "the first letter is next to the gate");
            assert_eq!(tile.melt, if k < 5 { Melt::Sag } else { Melt::Whole });
        }
    }

    #[test]
    fn the_drip_comes_from_the_letter_and_its_place_not_a_cycle() {
        // `4 + ((code point * 7 + k * 5) % 3) * 4`, as the mockup draws it, for "doubleclick.net".
        let want = [8, 12, 8, 12, 12, 4, 4, 12, 8, 4, 8, 12, 12, 8, 4];
        let mut d = Drain::new(7);
        d.offer("doubleclick.net", NameKind::Refused);
        tick_to_step(&mut d, 3);
        let mut drips = [0; 15];
        for tile in d.lane() {
            drips[usize::from(14 - tile.cell)] = tile.drip;
        }
        assert_eq!(drips, want);
        assert_eq!(drip_of('a', 0), 8);
        assert_eq!(drip_of('b', 0), 12);
        assert_eq!(drip_of('c', 0), 4);
        assert_eq!(drip_of('~', 19), 4 + ((126 * 7 + 19 * 5) % 3) as u8 * 4);
        for ch in ['a', 'z', '~', '?', '\u{10ffff}'] {
            for k in 0..20 {
                assert!(matches!(drip_of(ch, k), 4 | 8 | 12));
            }
        }
    }

    #[test]
    fn the_lane_reads_the_first_letter_at_the_front() {
        let mut d = Drain::new(7);
        d.offer("example.org", NameKind::Plain);
        for _ in 0..4 {
            d.tick(false);
        }
        let mut tiles: Vec<Tile> = d.lane().collect();
        tiles.sort_by_key(|t| std::cmp::Reverse(t.cell));
        let word: String = tiles.iter().map(|t| t.ch).collect();
        assert_eq!(word, "exa");
        assert_eq!(tiles[0].cell, 2);
    }

    #[test]
    fn refused_names_fit_fifteen_cells_and_passing_ones_twenty() {
        let queued = |d: &Drain| -> Vec<String> {
            d.queue.iter().map(|q| q.text.iter().collect()).collect()
        };
        // The same long name, three ways: refused it stops in 15 cells, plain and listed it passes in 20.
        let long = "pagead2.googlesyndication.com";
        let mut d = Drain::new(7);
        d.offer(long, NameKind::Refused);
        assert_eq!(queued(&d), ["googlesyndicat~"]);
        let mut d = Drain::new(7);
        d.offer(long, NameKind::Plain);
        assert_eq!(queued(&d), ["googlesyndication.c~"]);
        let mut d = Drain::new(7);
        d.offer(long, NameKind::Listed);
        assert_eq!(queued(&d), ["googlesyndication.c~"]);
        // A name with host labels loses them first, and keeps more of them where there is room.
        let mut d = Drain::new(7);
        d.offer("a.very.long.tracker.example.org", NameKind::Refused);
        d.offer("a.very.long.tracker.example.org", NameKind::Plain);
        assert_eq!(queued(&d), ["example.org", "tracker.example.org"]);
        // A refused name offered while paused is a listed one, and gets 20.
        let mut d = Drain::new(7);
        d.set_paused(true);
        d.offer(long, NameKind::Refused);
        assert_eq!(queued(&d), ["googlesyndication.c~"]);
        assert_eq!(d.queue[0].kind, NameKind::Listed);
        // The edges: 15 stays whole as refused, 16 is cut; 20 stays as plain, 21 is cut.
        let mut d = Drain::new(7);
        d.offer("abcdefghijk.org", NameKind::Refused);
        d.offer("abcdefghijkl.org", NameKind::Refused);
        d.offer("abcdefghijklmnop.org", NameKind::Plain);
        d.offer("abcdefghijklmnopq.org", NameKind::Plain);
        assert_eq!(
            queued(&d),
            [
                "abcdefghijk.org",
                "abcdefghijkl.o~",
                "abcdefghijklmnop.org",
                "abcdefghijklmnopq.o~"
            ]
        );
        // Whatever the name, a refused one is never wider than the cells it stops in, and a plain one than the lane.
        let mut d = Drain::new(7);
        for name in [
            "a".repeat(253),
            format!("{}.co.uk", "q".repeat(200)),
            "a.b.c.example.co.uk".to_string(),
            "\u{1F4A9}".repeat(100),
            "x.".repeat(120),
        ] {
            d.offer(&name, NameKind::Refused);
            assert!(
                d.queue.back().is_some_and(|q| q.text.len() <= 15),
                "{}",
                name.len()
            );
            d.offer(&name, NameKind::Plain);
            assert!(d.queue.back().is_some_and(|q| q.text.len() <= 20));
        }
    }

    #[test]
    fn the_lane_is_idle_only_with_no_name_on_it_or_queued() {
        let mut d = Drain::new(7);
        assert!(d.idle());
        d.offer("example.org", NameKind::Plain);
        assert!(!d.idle(), "queued, and nothing on the lane yet");
        d.tick(false);
        assert!(!d.idle(), "on the lane");
        for _ in 0..80 {
            d.tick(false);
        }
        assert!(d.idle());
        // A name that is on the lane and a name that is queued behind it both hold the words back.
        d.offer("doubleclick.net", NameKind::Refused);
        d.offer("example.com", NameKind::Plain);
        let mut was_idle = false;
        for _ in 0..200 {
            was_idle |= d.idle() && d.moving() && d.refusal_step().is_some();
            d.tick(false);
        }
        assert!(!was_idle && d.idle());
        // Dots still turning do not count: the lane is what is idle.
        d.land(3);
        assert!(d.idle() && d.moving());
    }

    #[test]
    fn plain_names_pass_the_gate() {
        let mut d = Drain::new(7);
        let funnel = *d.funnel();
        d.offer("example.org", NameKind::Plain);
        assert!(d.moving());
        let mut seen = [false; 20];
        for _ in 0..100 {
            if !d.moving() {
                break;
            }
            d.tick(false);
            for t in d.lane() {
                seen[usize::from(t.cell)] = true;
                assert_eq!((t.style, t.melt), (TileStyle::Plain, Melt::Whole));
            }
            assert_eq!(d.refusal_step(), None);
            assert!(!d.door_shut());
        }
        assert!(seen.iter().all(|&cell| cell), "it crossed cells 0 to 19");
        assert!(!d.moving());
        assert_eq!(d.lane().count(), 0);
        assert_eq!(*d.funnel(), funnel, "a plain name leaves no trace");
    }

    #[test]
    fn names_follow_each_other_with_a_cell_between() {
        let mut d = Drain::new(7);
        d.offer("one.example.org", NameKind::Plain);
        d.offer("two.example.org", NameKind::Plain);
        let mut saw_two = false;
        for _ in 0..60 {
            d.tick(false);
            // Two names never touch: at least one cell is empty between them.
            if d.names.len() == 2 {
                saw_two = true;
                let (a, b) = (&d.names[0], &d.names[1]);
                assert!(b.head < a.tail() - 1, "{} {}", b.head, a.tail());
            }
        }
        assert!(saw_two);
        assert!(!d.moving());
    }

    #[test]
    fn a_burst_keeps_the_queue_at_four_refused_first() {
        let mut d = Drain::new(7);
        d.offer("doubleclick.net", NameKind::Refused);
        tick_to_step(&mut d, 1); // the lane is halted from here on
        for i in 0..30 {
            d.offer(&site(i), NameKind::Refused);
            if i % 6 == 0 {
                d.offer(&format!("web{i}.example.org"), NameKind::Plain);
            }
            assert!(d.queue.len() <= 4);
        }
        let kept: Vec<(String, NameKind)> = d
            .queue
            .iter()
            .map(|q| (q.text.iter().collect(), q.kind))
            .collect();
        let want: Vec<(String, NameKind)> = (26..30)
            .map(|i| (fit_site(&site(i), 15), NameKind::Refused))
            .collect();
        assert_eq!(kept, want, "the newest four refused, and no plain one");
    }

    #[test]
    fn the_queue_sheds_plain_then_listed_then_refused_and_oldest_first() {
        let mut d = Drain::new(7);
        d.offer("doubleclick.net", NameKind::Refused);
        tick_to_step(&mut d, 1);
        let queue = |d: &Drain| -> Vec<String> {
            d.queue.iter().map(|q| q.text.iter().collect()).collect()
        };
        for (n, kind) in [
            ("r1.example.org", NameKind::Refused),
            ("l1.example.org", NameKind::Listed),
            ("p1.example.org", NameKind::Plain),
            ("p2.example.org", NameKind::Plain),
        ] {
            d.offer(n, kind);
        }
        d.offer("r2.example.org", NameKind::Refused);
        assert_eq!(
            queue(&d),
            [
                "r1.example.org",
                "l1.example.org",
                "p2.example.org",
                "r2.example.org"
            ]
        );
        d.offer("r3.example.org", NameKind::Refused);
        assert_eq!(
            queue(&d),
            [
                "r1.example.org",
                "l1.example.org",
                "r2.example.org",
                "r3.example.org"
            ]
        );
        d.offer("r4.example.org", NameKind::Refused);
        assert_eq!(
            queue(&d),
            [
                "r1.example.org",
                "r2.example.org",
                "r3.example.org",
                "r4.example.org"
            ]
        );
        d.offer("r5.example.org", NameKind::Refused);
        assert_eq!(
            queue(&d),
            [
                "r2.example.org",
                "r3.example.org",
                "r4.example.org",
                "r5.example.org"
            ]
        );
    }

    #[test]
    fn duplicates_are_not_queued_twice() {
        let mut d = Drain::new(7);
        d.offer("doubleclick.net", NameKind::Refused);
        d.offer("doubleclick.net", NameKind::Refused);
        d.offer("Doubleclick.NET.", NameKind::Refused);
        assert_eq!(d.queue.len(), 1);
        tick_to_step(&mut d, 1);
        // The same name again while it melts on the lane.
        d.offer("doubleclick.net", NameKind::Refused);
        assert_eq!(d.queue.len(), 0);
        d.offer("example.org", NameKind::Plain);
        d.offer("example.org", NameKind::Plain);
        assert_eq!(d.queue.len(), 1);
        // A different name that is cut to the same twenty cells is the same on the screen.
        let long = "a".repeat(40);
        d.offer(&long, NameKind::Plain);
        d.offer(&format!("{long}b"), NameKind::Plain);
        assert_eq!(d.queue.len(), 2);
    }

    #[test]
    fn a_plain_name_does_not_hold_back_a_refused_one_of_the_same_site() {
        let mut d = Drain::new(7);
        d.set_blocked_today(Some(10));
        // A plain `example.com` is on the lane.
        d.offer("example.com", NameKind::Plain);
        d.tick(false);
        assert_eq!(d.names.len(), 1);
        assert!(d.queue.is_empty());
        // A refused name of that site fits to the same text, and is still its own name: it is queued,
        // and the figure that counts it is held back until it melts.
        d.offer("pixel.example.com", NameKind::Refused);
        assert_eq!(d.queue.len(), 1, "the refusal is queued");
        assert_eq!(d.queue[0].text.iter().collect::<String>(), "example.com");
        d.set_blocked_today(Some(11));
        assert_eq!(d.count(), Some(10), "not counted before it melts");
        // The same kind of the same text is still a duplicate, queued or on the lane.
        d.offer("example.com", NameKind::Plain);
        d.offer("pixels.example.com", NameKind::Refused);
        assert_eq!(d.queue.len(), 1);
        // And the other way round: a refused name that is queued or stopped does not hold back a plain one.
        d.offer("example.com", NameKind::Listed);
        assert_eq!(d.queue.len(), 2);
        // It runs: the tiles melt, the dots land, and the count is raised when it is counted.
        let mut melted = false;
        for _ in 0..300 {
            d.tick(false);
            melted |= d.lane().any(|tile| tile.melt == Melt::Puddle);
            if !d.moving() {
                break;
            }
        }
        assert!(melted, "the refused name melted");
        let lit = d.funnel().iter().filter(|cell| cell.shade.is_some());
        assert_eq!(lit.count(), "example.com".len());
        assert_eq!(d.count(), Some(11), "counted when it melted");
    }

    #[test]
    fn a_name_with_nothing_to_show_is_not_offered() {
        let mut d = Drain::new(7);
        for name in ["", "."] {
            d.offer(name, NameKind::Plain);
        }
        assert!(!d.moving());
    }

    #[test]
    fn long_and_odd_names_fit_twenty_cells() {
        let long = "a".repeat(253);
        assert_eq!(fit_name(&long, 20), format!("{}~", "a".repeat(19)));
        assert_eq!(fit_name(&long, 20).chars().count(), 20);
        assert_eq!(fit_name("Ads.Example.ORG.", 20), "ads.example.org");
        assert_eq!(fit_name("bücher.example", 20), "b?cher.example");
        // Exactly twenty is left alone, twenty-one is cut.
        assert_eq!(fit_name("abcdefghij.example.c", 20), "abcdefghij.example.c");
        assert_eq!(
            fit_name("abcdefghij.example.co", 20),
            "abcdefghij.example.~"
        );
        // One trailing dot goes, a second stays (and is a character like any other).
        assert_eq!(fit_name("a.b..", 20), "a.b.");
        // Anything without a glyph, however wide in bytes, is one `?`.
        assert_eq!(fit_name("a\u{7}b c\u{1F4A9}d", 20), "a?b?c?d");
        // The extremes of the cell count.
        assert_eq!(fit_name("abc", 0), "");
        assert_eq!(fit_name("abc", 1), "~");
        assert_eq!(fit_name("a", 1), "a");
        assert_eq!(fit_name("", 20), "");
        // And a name that is a megabyte is cut like any other.
        assert_eq!(
            fit_name(&"é".repeat(1 << 20), 20),
            format!("{}~", "?".repeat(19))
        );
        // On the lane, the same.
        let mut d = Drain::new(7);
        d.offer(&long, NameKind::Plain);
        assert_eq!(d.queue[0].text.len(), 20);
        assert_eq!(d.queue[0].text[19], '~');
    }

    #[test]
    fn the_count_follows_the_day_and_holds_back_names_in_flight() {
        let mut d = Drain::new(7);
        assert_eq!(d.count(), None);
        d.offer("doubleclick.net", NameKind::Refused);
        assert_eq!(d.count(), None, "no snapshot yet: a dash");
        d.set_blocked_today(Some(4780));
        assert_eq!(
            d.count(),
            Some(4779),
            "the name in flight is not counted yet"
        );
        // A 15-letter name is counted at step 16.
        for step in 1..=15 {
            tick_to_step(&mut d, step);
            assert_eq!(d.count(), Some(4779), "step {step}");
        }
        tick_to_step(&mut d, 16);
        assert_eq!(d.count(), Some(4780), "step 16 counts it");
        d.tick(false);
        d.tick(false);
        assert_eq!(d.count(), Some(4780));
        // A new day: the figure drops to the new value.
        d.set_blocked_today(Some(12));
        assert_eq!(d.count(), Some(12));
        // And an unknown figure is a dash again.
        d.set_blocked_today(None);
        assert_eq!(d.count(), None);
    }

    #[test]
    fn the_count_never_runs_backwards_while_a_snapshot_catches_up() {
        let mut d = Drain::new(7);
        d.set_blocked_today(Some(100));
        assert_eq!(d.count(), Some(100));
        // A refused name arrives before the next snapshot has counted it.
        d.offer("doubleclick.net", NameKind::Refused);
        assert_eq!(d.count(), Some(100), "held, not 99");
        d.set_blocked_today(Some(101));
        assert_eq!(
            d.count(),
            Some(100),
            "the snapshot has it, the screen is still showing it arrive"
        );
        tick_to_step(&mut d, 16);
        assert_eq!(d.count(), Some(101));
        // Names that were shed from the queue are in no flight: only the lane's and the queue's are held back.
        let mut d = Drain::new(7);
        d.offer("doubleclick.net", NameKind::Refused);
        tick_to_step(&mut d, 1);
        for i in 0..6 {
            d.offer(&site(i), NameKind::Refused);
        }
        d.set_blocked_today(Some(50));
        // One on the lane and four queued, so five in flight.
        assert_eq!(d.count(), Some(45));
        // Plain and listed names never hold the count back.
        let mut d = Drain::new(7);
        d.set_blocked_today(Some(50));
        d.offer("example.org", NameKind::Plain);
        d.offer("example.net", NameKind::Listed);
        assert_eq!(d.count(), Some(50));
    }

    #[test]
    fn the_count_does_not_step_back_across_a_dash() {
        let mut d = Drain::new(7);
        d.set_blocked_today(Some(100));
        assert_eq!(d.count(), Some(100));
        // The link drops: a dash. Three refused names arrive while it is down.
        d.set_blocked_today(None);
        assert_eq!(d.count(), None);
        for i in 0..3 {
            d.offer(&site(i), NameKind::Refused);
        }
        assert_eq!(d.count(), None, "a dash, whatever is on its way");
        // It rejoins with the figure it had: the three are in flight, but the count is not 97.
        d.set_blocked_today(Some(100));
        assert_eq!(d.count(), Some(100));
        // And goes on from there as the figure does.
        d.set_blocked_today(Some(103));
        assert_eq!(d.count(), Some(100), "the three have not melted yet");
        // A figure below what was last shown is a new day, whether or not there was a dash.
        d.set_blocked_today(None);
        d.set_blocked_today(Some(7));
        assert_eq!(d.count(), Some(7));
        d.set_blocked_today(Some(12));
        assert_eq!(
            d.count(),
            Some(9),
            "three of the figure are still on their way"
        );
    }

    #[test]
    fn a_landing_run_is_cut_at_the_rim_and_the_next_starts_at_the_tip() {
        // Forty refusals walk the landing head up the funnel, from the tip, more than once.
        let mut d = Drain::new(7);
        let mut cut_at_the_rim = false;
        for i in 0..40 {
            let before = d.landing;
            let name = format!("{}.example.org", "ads".repeat(1 + i % 5));
            let len = fit_site(&name, 15).chars().count();
            let landed = refuse_to_the_end(&mut d, &name);
            assert!(!landed.is_empty());
            let (first, last) = (landed[0], landed[landed.len() - 1]);
            assert_eq!(
                last - first + 1,
                landed.len(),
                "one run of neighbours: {landed:?}"
            );
            // It starts where the last one stopped, or at the tip when that was the rim.
            assert_eq!(first, if before >= FUNNEL_CELLS { 0 } else { before });
            cut_at_the_rim |= landed.len() < len;
            assert_eq!(landed.len(), len.min(FUNNEL_CELLS - first));
        }
        assert!(cut_at_the_rim, "a run met the rim at least once");
        // A run that does not fit is cut to the dots that are left, and the next one starts at the tip.
        let mut d = Drain::new(7);
        d.landing = FUNNEL_CELLS - 3;
        let shade = d.shade;
        d.land(5);
        assert_eq!(d.landing, FUNNEL_CELLS, "it did not wrap");
        assert!(
            (FUNNEL_CELLS - 3..FUNNEL_CELLS)
                .all(|i| d.funnel()[i].shade == Some(shade) && d.funnel()[i].flip == Flip::Edge)
        );
        assert!((0..FUNNEL_CELLS - 3).all(|i| d.funnel()[i].shade.is_none()));
        assert_ne!(d.shade, shade, "the shade moves on");
        d.land(4);
        assert_eq!(d.landing, 4);
        assert!(
            (0..4)
                .all(|i| d.funnel()[i].shade == Some(shade.next())
                    && d.funnel()[i].flip == Flip::Edge)
        );
        // A run that ends exactly on the last dot fills it, and the next starts at the tip too.
        let mut d = Drain::new(7);
        d.landing = FUNNEL_CELLS - 5;
        d.land(5);
        assert_eq!(d.landing, FUNNEL_CELLS);
        assert!((FUNNEL_CELLS - 5..FUNNEL_CELLS).all(|i| d.funnel()[i].flip == Flip::Edge));
        d.land(2);
        assert_eq!(d.landing, 2);
    }

    #[test]
    fn moving_covers_a_queued_name_and_a_settling_dot() {
        let mut d = Drain::new(7);
        assert!(!d.moving());
        d.offer("example.org", NameKind::Plain);
        assert!(d.moving(), "queued, and nothing on the lane yet");
        let mut d = Drain::new(7);
        d.land(3);
        assert!(d.moving(), "edge-on");
        d.tick(false);
        assert!(d.moving(), "face-on");
        d.tick(false);
        assert!(!d.moving(), "settled");
    }

    #[test]
    fn three_shades_in_turn() {
        let mut d = Drain::new(7);
        let first = refuse_to_the_end(&mut d, "doubleclick.net");
        assert_eq!(first.len(), 15, "a dot a letter");
        assert!(
            first
                .iter()
                .all(|&i| d.funnel()[i].shade == Some(Shade::Blue))
        );
        assert_eq!(d.landing, 15);
        let second = refuse_to_the_end(&mut d, "adnxs.com");
        assert_eq!(second.len(), 9);
        assert_eq!(second[0], 15, "the next run starts where the last stopped");
        assert!(
            second
                .iter()
                .all(|&i| d.funnel()[i].shade == Some(Shade::Mid))
        );
        let third = refuse_to_the_end(&mut d, "criteo.com");
        assert_eq!(third.len(), 10);
        assert!(
            third
                .iter()
                .all(|&i| d.funnel()[i].shade == Some(Shade::Dark))
        );
        let fourth = refuse_to_the_end(&mut d, "openx.net");
        assert!(
            fourth
                .iter()
                .all(|&i| d.funnel()[i].shade == Some(Shade::Blue))
        );
        assert_eq!(d.landing, 15 + 9 + 10 + 9);
        // The earlier runs keep their shades.
        assert!((0..15).all(|i| d.funnel()[i].shade == Some(Shade::Blue)));
        assert!((15..24).all(|i| d.funnel()[i].shade == Some(Shade::Mid)));
        assert!((24..34).all(|i| d.funnel()[i].shade == Some(Shade::Dark)));
        // Nothing lights above the landing.
        assert!(d.funnel()[43..].iter().all(|c| c.shade.is_none()));
    }

    #[test]
    fn the_funnel_is_the_mockups_bowl_neck_and_spout() {
        assert_eq!(FUNNEL_ROWS, [29, 25, 21, 17, 13, 11, 9, 7, 5, 3, 3, 3]);
        assert_eq!(
            FUNNEL_ROWS.iter().map(|&n| usize::from(n)).sum::<usize>(),
            146
        );
        assert_eq!(FUNNEL_CELLS, 146);
        assert_eq!(FUNNEL_CENTRES.len(), 146);
        // In landing order: the spout's tip first, left to right, and the row above it right to left.
        assert_eq!(FUNNEL_CENTRES[0], (288, 218), "the tip row's left dot");
        assert_eq!(FUNNEL_CENTRES[2], (312, 218), "and its right");
        assert_eq!(
            FUNNEL_CENTRES[3],
            (312, 206),
            "the next row up is walked right to left"
        );
        assert_eq!(FUNNEL_CENTRES[5], (288, 206));
        assert_eq!(
            FUNNEL_CENTRES[6],
            (288, 194),
            "and the next left to right again"
        );
        assert_eq!(
            FUNNEL_CENTRES[FUNNEL_CELLS - 1],
            (132, 86),
            "the bowl's top row ends at its left edge"
        );
        let mut at = 0;
        for (r, &n) in FUNNEL_ROWS.iter().enumerate().rev() {
            let row = &FUNNEL_CENTRES[at..at + usize::from(n)];
            at += usize::from(n);
            let y = 86 + 12 * u16::try_from(r).unwrap();
            assert!(
                row.iter().all(|&(_, row_y)| row_y == y),
                "row {r} is at y {y}"
            );
            let xs: Vec<u16> = row.iter().map(|&(x, _)| x).collect();
            let (least, most) = (xs.iter().min().unwrap(), xs.iter().max().unwrap());
            assert_eq!(
                least + most,
                600,
                "every row is odd, with a dot on the axis, x 300"
            );
            assert!(xs.iter().all(|&x| (x - 132) % 12 == 0), "x is 132 + 12 n");
            // To and fro: the rows from the tip go right, left, right...
            let leftwards = (FUNNEL_ROWS.len() - 1 - r) % 2 == 1;
            assert!(
                xs.windows(2).all(|w| if leftwards {
                    w[0] == w[1] + 12
                } else {
                    w[1] == w[0] + 12
                }),
                "row {r} is walked in one direction, a pitch at a time"
            );
        }
        assert_eq!(at, 146);
    }

    #[test]
    fn it_starts_empty_and_fills_from_the_tip() {
        let mut d = Drain::new(7);
        assert!(
            d.funnel()
                .iter()
                .all(|c| c.shade.is_none() && c.flip == Flip::Rest)
        );
        assert_eq!(d.landing, 0);
        assert!(!d.moving(), "an empty funnel is not moving");
        // The first refusal lights the dots at the tip of the spout.
        let landed = refuse_to_the_end(&mut d, "adnxs.com");
        assert_eq!(landed, (0..9).collect::<Vec<_>>());
        assert!(
            landed.iter().all(|&i| FUNNEL_CENTRES[i].1 >= 194),
            "the three spout rows hold the nine"
        );
        assert!(d.funnel()[9..].iter().all(|c| c.shade.is_none()));
    }

    #[test]
    fn prefill_is_the_mockups_fill() {
        // What the mockup's `fill(146)` lights with `Sim(7)`: its generator draws once in the `Sim`'s
        // constructor, then once a run, 6 + floor(r * 10) dots each, in the three shades in turn. Read back
        // from what d6.js draws.
        let runs = [
            (Shade::Blue, 6),
            (Shade::Mid, 15),
            (Shade::Dark, 12),
            (Shade::Blue, 11),
            (Shade::Mid, 10),
            (Shade::Dark, 10),
            (Shade::Blue, 8),
            (Shade::Mid, 11),
            (Shade::Dark, 13),
            (Shade::Blue, 8),
            (Shade::Mid, 7),
            (Shade::Dark, 13),
            (Shade::Blue, 11),
            (Shade::Mid, 7),
            (Shade::Dark, 4),
        ];
        let mut d = Drain::new(7);
        d.prefill(7);
        let want: Vec<Option<Shade>> = runs
            .iter()
            .flat_map(|&(shade, len)| std::iter::repeat_n(Some(shade), len))
            .collect();
        assert_eq!(want.len(), 146, "the last run is cut at the rim");
        let got: Vec<Option<Shade>> = d.funnel().iter().map(|c| c.shade).collect();
        assert_eq!(got, want);
        assert!(d.funnel().iter().all(|c| c.flip == Flip::Rest));
        assert_eq!(d.landing, 61, "the next landing starts at dot 61");
        assert_eq!(d.shade, Shade::Blue, "after a run of the third shade");
        assert!(!d.moving());
        // The same seed, the same funnel; another seed, another.
        let mut again = Drain::new(1);
        again.prefill(7);
        assert_eq!(again.funnel()[..], d.funnel()[..]);
        let mut other = Drain::new(7);
        other.prefill(8);
        assert_ne!(other.funnel()[..], d.funnel()[..]);
        // A prefill on a used funnel starts over.
        refuse_to_the_end(&mut d, "adnxs.com");
        d.prefill(7);
        assert_eq!(d.landing, 61);
        assert!(
            d.funnel()
                .iter()
                .all(|c| c.flip == Flip::Rest && c.shade.is_some())
        );
        // The generator is mulberry32, as in the mockup's `common.js`.
        let mut r = Mulberry32::new(7);
        let first: Vec<u32> = (0..6).map(|_| r.next_u32()).collect();
        assert_eq!(
            first,
            [
                50_271_532,
                266_108_690,
                4_195_786_334,
                3_002_305_430,
                2_239_590_375,
                1_741_702_388
            ]
        );
    }

    #[test]
    fn a_listed_name_is_outlined_only_while_paused_and_a_refused_one_offered_then_is_listed() {
        let mut d = Drain::new(7);
        d.offer("openx.net", NameKind::Listed);
        for _ in 0..4 {
            d.tick(false);
        }
        assert!(d.lane().count() > 0 && d.lane().all(|t| t.style == TileStyle::Plain));
        d.tick(true);
        assert!(d.lane().all(|t| t.style == TileStyle::Listed));
        d.tick(false);
        assert!(d.lane().all(|t| t.style == TileStyle::Plain));
        // Offered during a pause, a refused name is shown as listed: it is let through, and does not stop.
        let mut d = Drain::new(7);
        d.set_paused(true);
        d.offer("doubleclick.net", NameKind::Refused);
        assert_eq!(d.queue[0].kind, NameKind::Listed);
        for _ in 0..80 {
            d.tick(true);
            assert_eq!(d.refusal_step(), None);
        }
        assert!(!d.moving());
        d.set_blocked_today(Some(10));
        assert_eq!(d.count(), Some(10), "a listed name is never in flight");
    }

    #[test]
    fn step_toward_moves_one_field_in_order() {
        let wanted = Stills {
            percent: Some(Share::Percent(44)),
            clock: Some(TimeOfDay {
                hour: 10,
                minute: 21,
            }),
            blocking: Blocking::Paused { left_secs: 277 },
            gate_fill: 1,
            count: Some(4780),
            alert: Some(alert_card(
                "threat",
                true,
                "secure-login-verify.example.org",
                None,
            )),
            words: Some(LaneWords::Quiet { minutes: 47 }),
        };
        let mut shown = Stills::default();
        let mut now = shown.clone();
        let mut order = Vec::new();
        while shown.step_toward(&wanted) {
            let changed = [
                ("blocking", shown.blocking != now.blocking),
                ("gate_fill", shown.gate_fill != now.gate_fill),
                ("alert", shown.alert != now.alert),
                ("count", shown.count != now.count),
                ("percent", shown.percent != now.percent),
                ("clock", shown.clock != now.clock),
                ("words", shown.words != now.words),
            ];
            let changed: Vec<&str> = changed.iter().filter(|c| c.1).map(|c| c.0).collect();
            assert_eq!(changed.len(), 1, "one field at a time: {changed:?}");
            order.push(changed[0]);
            now = shown.clone();
            assert!(order.len() <= 7);
        }
        assert_eq!(
            order,
            [
                "blocking",
                "gate_fill",
                "alert",
                "count",
                "percent",
                "clock",
                "words"
            ]
        );
        assert!(shown == wanted);
        assert!(!shown.step_toward(&wanted), "equal: nothing to do");
        // A field going back to unknown is a change like any other.
        let mut unknown = wanted.clone();
        unknown.clock = None;
        unknown.count = None;
        unknown.words = None;
        assert!(shown.step_toward(&unknown));
        assert_eq!(shown.count, None, "the count comes before the clock");
        assert!(shown.clock.is_some() && shown.words.is_some());
        assert!(shown.step_toward(&unknown));
        assert_eq!(shown.clock, None, "and the clock before the words");
        assert!(shown.words.is_some());
        assert!(shown.step_toward(&unknown));
        assert!(shown == unknown);
        // The gate's refill goes out before anything else but the key, so never with the key's countdown.
        let mut refill = unknown.clone();
        refill.gate_fill = 2;
        refill.blocking = Blocking::Paused { left_secs: 276 };
        assert!(shown.step_toward(&refill));
        assert_eq!(shown.blocking, refill.blocking);
        assert_eq!(shown.gate_fill, 1);
        assert!(shown.step_toward(&refill));
        assert_eq!(shown.gate_fill, 2);
    }

    #[test]
    fn alert_cards_for_every_kind() {
        let v4 = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 23)));
        let v6 = Some(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x17,
        )));
        let titles = [
            ("threat", "THREAT", "BLOCKED"),
            ("rebind", "REBIND", "BLOCKED"),
            ("dga", "RANDOM", "NAMES"),
            ("tunnel", "DNS", "TUNNEL"),
            ("beacon", "BEACON", "SEEN"),
            ("burst", "QUERY", "BURST"),
            ("new_device", "NEW", "DEVICE"),
            ("arp_spoof", "ARP", "SPOOF"),
            ("odd_kind_of_thing", "ODD", "KIND_OF_THING"),
            ("solo", "SOLO", ""),
            ("", "", ""),
        ];
        for (kind, one, two) in titles {
            let card = alert_card(kind, true, "secure-login-verify.example.org", v4);
            assert_eq!(card.title, [one.to_string(), two.to_string()], "{kind}");
            assert!(card.high);
        }
        let card = alert_card("threat", false, "ads.example.org", v4);
        assert!(!card.high);
        assert_eq!(card.subject, ["ads.example.org", ""]);
        assert_eq!(card.who, "asked by 192.0.2.23");
        assert_eq!(
            alert_card("dga", true, "x", v6).who,
            "asked by 2001:db8::17"
        );
        assert_eq!(alert_card("dga", true, "x", None).who, "");
        // A device is "at" an address, it has asked nothing.
        assert_eq!(
            alert_card("new_device", false, "x", v4).who,
            "at 192.0.2.23"
        );
        assert_eq!(
            alert_card("arp_spoof", true, "x", v6).who,
            "at 2001:db8::17"
        );
        assert_eq!(alert_card("new_device", false, "x", None).who, "");
        // The subject is lower-cased and made safe like a lane name, and set on two lines of 26 cells.
        // Past 52 cells the start goes and a `~` leads.
        let long = format!("Secure-Login-Verify.{}.EXAMPLE.org.", "a".repeat(40));
        let card = alert_card("threat", true, &long, None);
        assert_eq!(
            card.subject,
            [
                format!("~{}", "a".repeat(25)),
                format!("{}.example.org", "a".repeat(14))
            ]
        );
        assert_eq!(
            alert_card("threat", true, "bücher.example", None).subject,
            ["b?cher.example", ""]
        );
        // Nothing is wider than its place, whatever the kind or the address.
        let wide = alert_card(&"x_".repeat(100), true, "", v6);
        assert!(wide.title.iter().all(|t| t.chars().count() <= 13));
        let widest = IpAddr::V6(Ipv6Addr::new(
            0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
        ));
        let wide = alert_card("dga", true, "", Some(widest));
        assert_eq!(wide.who.chars().count(), 29);
        assert!(wide.who.ends_with('~'));
        // The card is clone and equal, and says nothing of a name when it is printed.
        assert!(card.clone() == card);
        assert!(!format!("{card:?}").contains("secure"));
        assert!(!format!("{card:?}").contains("aaaa"));
    }

    #[test]
    fn alert_subject_wraps_after_a_dot() {
        let lines = |name: &str| alert_card("threat", true, name, None).subject;
        // One line when it fits, with nothing on the second.
        assert_eq!(
            lines("secure-login-verify.top"),
            ["secure-login-verify.top", ""]
        );
        assert_eq!(lines(&"x".repeat(26)), ["x".repeat(26), String::new()]);
        // Past 26 it breaks after the last dot that leaves the second line no more than 26.
        assert_eq!(
            lines("secure-login-verify.example.org"),
            ["secure-login-verify.", "example.org"]
        );
        assert_eq!(
            lines("secure-login-verify.accounts-billing.example"),
            ["secure-login-verify.", "accounts-billing.example"]
        );
        // The dot at cell 20 would leave 28 for the second line, so it breaks at 26.
        assert_eq!(
            lines("secure-login-verify.accounts-billing.example.org"),
            ["secure-login-verify.accoun", "ts-billing.example.org"]
        );
        // No such dot: break at 26.
        assert_eq!(lines(&"a".repeat(40)), ["a".repeat(26), "a".repeat(14)]);
        assert_eq!(
            lines(&format!("{}.org", "a".repeat(30))),
            ["a".repeat(26), "aaaa.org".to_string()]
        );
        assert_eq!(
            lines(&format!("ab.{}", "c".repeat(40))),
            [format!("ab.{}", "c".repeat(23)), "c".repeat(17)],
            "the dot at cell 3 would leave the second line 40 cells"
        );
        // 27 cells is the least that wraps.
        assert_eq!(lines(&"x".repeat(27)), ["x".repeat(26), "x".to_string()]);
        // Both lines are never more than 26, whatever the name.
        for len in 0..120 {
            for name in [
                "a".repeat(len),
                format!("{}.{}.org", "b".repeat(len / 3), "c".repeat(len / 2)),
                "d.".repeat(len),
            ] {
                let [first, second] = lines(&name);
                assert!(
                    first.chars().count() <= 26 && second.chars().count() <= 26,
                    "{len}"
                );
                assert!(second.is_empty() || first.chars().count() >= 1);
            }
        }
        // The card says what lines it has.
        let card = alert_card("threat", true, "secure-login-verify.example.org", None);
        assert_eq!(card.subject_lines().count(), 2);
        let card = alert_card("threat", true, "example.org", None);
        assert_eq!(card.subject_lines().collect::<Vec<_>>(), ["example.org"]);
        assert_eq!(
            alert_card("threat", true, "", None).subject_lines().count(),
            0
        );
    }

    #[test]
    fn stills_say_nothing_of_a_name_when_printed() {
        let stills = Stills {
            alert: Some(alert_card(
                "threat",
                true,
                "secure-login-verify.example.org",
                Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 23))),
            )),
            ..Stills::default()
        };
        let shown = format!("{stills:?}");
        assert!(
            !shown.contains("secure") && !shown.contains("192.0.2.23"),
            "{shown}"
        );
        // A tile is one letter of a name.
        let mut d = Drain::new(7);
        d.offer("zzz.example.org", NameKind::Plain);
        for _ in 0..3 {
            d.tick(false);
        }
        let tile = d.lane().next().unwrap();
        assert_eq!(tile.ch, 'z');
        assert!(!format!("{tile:?}").contains('z'));
    }

    /// The Drain survives any input: odd names, odd counts, any order.
    #[test]
    fn nothing_panics_on_any_input() {
        let mut r = Mulberry32::new(99);
        let alphabet: Vec<char> = "abc.-_ XYZ019\u{0}\u{7f}ü—\u{1F4A9}~?".chars().collect();
        let mut d = Drain::new(1);
        for step in 0..6000_u32 {
            match r.below(10) {
                0..=3 => {
                    let len = [0, 1, 2, 5, 19, 20, 21, 63, 253, 4000][r.below(10) as usize];
                    let name: String = (0..len)
                        .map(|_| alphabet[r.below(alphabet.len() as u32) as usize])
                        .collect();
                    let kind =
                        [NameKind::Plain, NameKind::Refused, NameKind::Listed][r.below(3) as usize];
                    d.offer(&name, kind);
                }
                4..=7 => d.tick(r.below(7) == 0),
                8 => d.set_blocked_today(
                    [None, Some(0), Some(u32::MAX), Some(step), Some(5)][r.below(5) as usize],
                ),
                _ if r.below(40) == 0 => d.prefill(step),
                _ => d.set_paused(r.below(2) == 0),
            }
            assert!(d.queue.len() <= 4);
            assert!(d.names.len() <= 21);
            assert!(d.lane().all(|t| t.cell < 20 && t.drip <= 12));
            assert!(d.landing <= FUNNEL_CELLS);
            if d.refusal_step().is_some() {
                assert!(d.moving());
            }
            if d.spout_drop() {
                assert!(d.refusal_step().is_some() && !d.idle());
            }
            assert!(d.idle() || d.moving());
            let _ = d.count();
        }
        // Whatever happened, the lane runs dry.
        d.set_paused(false);
        for _ in 0..4000 {
            d.tick(false);
        }
        assert!(!d.moving());
    }
}
