//! The device inventory: which devices the home network has, from the ARP, DHCP and mDNS that the
//! device watch hears, and the two alerts that come of it, a new device and a forged gateway.
//!
//! Nothing here reads a socket or a clock of its own: the device watch calls in with what it
//! heard, and time is read from the clock that `Devices::new` was given, which is the same
//! shape as the alert store's: (monotonic seconds, unix seconds). Everything is bounded: 512
//! devices, 4 addresses each, a known list of 1024, two exempt lists of 64 and two block lists of
//! 64, 64 open gates, 64 labels, 64 held alerts and 64
//! alerts waiting to be taken, so that a flood of forged frames fills a table that never grows past
//! that.
//!
//! The inventory never calls a sink. The alerts that a call makes wait inside it until
//! [`Devices::take_alerts`] takes them, and whoever called raises them after the lock of the
//! inventory is released: [`with_devices`] does exactly that, and is how the device watch and the
//! API reach the inventory. What a sink does (the store takes its own lock and makes a key) is
//! never done while a sighting is being noted or a list is being set.
//!
//! The rule for a new device: a MAC that is not on the known list is raised as `new_device`, with
//! no client: the MAC is the whole key of the alert, so that it is the same across boots and
//! address changes (the addresses are in the inventory the API lists). A device that stays unknown
//! is raised again, on a later sighting, at most once an hour: an alert that the store's rate limit
//! dropped is delivered later, and the repeats merge in the store. Until the desktop has sent a
//! known list the alerts are held, so that a boot does not raise a warning for every device the
//! owner has had for years. When the list comes, the held alerts for devices on it are dropped and
//! the others are raised; if no list has come ten minutes after the first device was seen, every
//! device seen so far is learned as known, silently. With nothing heard there is nothing to learn,
//! and the state stays as it is.
//!
//! The exempt devices are those whose MAC is on the configuration's exempt list or on the one the
//! desktop pushed: their questions are held to the threat lists alone. An IPv4 address is exempt
//! while the device that claimed it last, by ARP or DHCP, is an exempt one, and leaves the set at
//! once when another device claims it. The router's address and the Pi's own are never exempt,
//! whatever MAC claims them: an exempt device that claimed the router's would exempt every client
//! whose questions the router relays. The inventory publishes the exempt addresses to the set that
//! the DNS service reads ([`Exemption::listed`]) whenever they change: the DNS side touches that
//! small set alone, and never this inventory or its lock. Exemption has no part in the new-device or the
//! spoof alerts, and does not depend on the known list.
//!
//! A device's gate is the panel's way to let one device's ads pass for a while: while it is open
//! (at most an hour, from the monotonic clock) the device is exempt in either mode, as if its MAC
//! were on the exempt list in the list mode and off the block list in the exempt-by-default mode.
//! A gate is a deadline in a small map, and opening it or letting it expire republishes the two
//! sets exactly as a change of a list does: the DNS side reads the same two sets, and knows
//! nothing of gates. [`Devices::expire_gates`] lets them expire; the device watch calls it when
//! [`Devices::next_gate_deadline`] comes, and is woken by [`Devices::gate_wake`] when a gate is
//! opened. Gates are never pushed or read back by the desktop and die with the board's restart.
//!
//! The panel also edits the pushed lists of the mode in force ([`Devices::set_ads_pass`]): a device
//! that the configuration's list of that mode names is `fixed`, and the router and the Pi never
//! take part. Labels are what the desktop calls the devices ([`Devices::load_labels`]), in its
//! order, which the panel keeps. Every change of a pushed list, of the mode, of the labels or of a
//! gate, whoever makes it, moves [`Devices::rev`], which the API gives and a push can be made
//! conditional on, so that the desktop and the panel do not overwrite each other.
//!
//! In the exempt-by-default mode the exempt lists have no effect: every client is exempt but the
//! fully blocked ones, and an address is fully blocked while the device that claimed it last is on
//! the configuration's block list or the pushed one, and always when it is the router's or the
//! Pi's own. The inventory keeps the blocked addresses ([`Exemption::blocked`]) in step the same
//! way, in either mode, so that turning the mode on finds them ready. The mode in force is the
//! pushed one once a policy has been pushed since the start, and the configuration's until then.
//!
//! What the owner pushed outlasts a restart when it is kept on the card: [`Devices::kept`] gives
//! the pushed lists, the pushed mode, the labels and the known set, and [`Devices::restore`] takes
//! them back at the start, before anything is heard. A restored known set stands in for the
//! desktop's list when none comes: a device on it is known from the first sighting, and when the
//! ten minutes pass with no list the held newcomers are raised, not learned. The state stays
//! `Waiting` through a restore, so that the API still says so and the desktop pushes its lists
//! again as it does after any restart.
//!
//! Nothing here logs but counts and the mode: the devices on a known list that came, the devices
//! learned, the devices of a restored known set that stood in for a list that never came, the
//! devices on an exempt list that came, the labels that came, and the mode and number of blocked
//! devices of a policy that came and changed them. A MAC, an address, a host name or a label never
//! reaches a log line from this file.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::ops::Deref;
use std::sync::{Arc, Mutex, PoisonError};

use tokio::sync::Notify;

use super::frames::{Arp, DHCP_DISCOVER, DHCP_REQUEST, Dhcp, HOSTNAME_MAX, Mac};
use crate::alerts::{Alert, AlertSink, Severity};
use crate::dns::exempt::{self, Exemption};
use crate::state::SavedDevices;

/// How many devices the inventory holds; past that the one seen longest ago goes.
pub const MAX_DEVICES: usize = 512;

/// How many IPv4 addresses one device keeps; past that the oldest goes.
pub const MAX_IPV4: usize = 4;

/// How many MACs a known list keeps.
pub const MAX_KNOWN: usize = 1024;

/// How many new-device alerts are held while the known list has not come.
pub const MAX_HELD: usize = 64;

/// How many MACs each exempt list keeps: the configuration's, and the one the desktop pushes.
pub const MAX_EXEMPT: usize = 64;

/// How many MACs each block list keeps: the configuration's, and the one the desktop pushes.
pub const MAX_BLOCK: usize = 64;

/// How many device gates are open at most.
pub const MAX_GATES: usize = MAX_EXEMPT;

/// How many labels the inventory keeps.
pub const MAX_LABELS: usize = 64;

/// The longest label, in characters.
pub const LABEL_MAX: usize = 24;

/// The longest a gate stays open, in seconds.
pub const MAX_GATE_SECS: u16 = 3600;

// Every address of every device on both exempt lists and of every device with a gate fits the set
// that the DNS side reads, and so does every address of every device on both block lists with the
// router's and the Pi's own.
const _: () = assert!((2 * MAX_EXEMPT + MAX_GATES) * MAX_IPV4 <= exempt::MAX_ADDRS);
const _: () = assert!(2 * MAX_BLOCK * MAX_IPV4 + 2 <= exempt::MAX_ADDRS);

/// How long the watch waits for a known list before it learns every device it has seen, in
/// monotonic seconds from the first sighting of any device.
pub const LEARN_AFTER_SECS: u64 = 600;

/// How long a device that is still unknown is left alone after its alert, in monotonic seconds,
/// before a later sighting raises it again.
pub const REALERT_AFTER_SECS: u64 = 3600;

/// How many alerts wait inside the inventory to be taken; past that they are dropped and counted.
pub const MAX_PENDING: usize = 64;

/// The kind of the alert for a device that is not on the known list.
const NEW_DEVICE: &str = "new_device";

/// The kind of the alert for an ARP that claims the gateway's address from another MAC.
const ARP_SPOOF: &str = "arp_spoof";

/// Gives the monotonic seconds and the unix seconds, in that order.
type Clock = Arc<dyn Fn() -> (u64, u64) + Send + Sync>;

/// Whether a known list has come yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownList {
    /// No list has come, and the learning has not happened: new devices are held.
    Waiting,
    /// A list came from the desktop.
    Received,
    /// No list came in time, so the devices seen in the ten minutes after the first one were
    /// learned.
    Learned,
}

impl KnownList {
    /// The state as the API says it: `waiting`, `received` or `learned`.
    pub fn as_str(self) -> &'static str {
        match self {
            KnownList::Waiting => "waiting",
            KnownList::Received => "received",
            KnownList::Learned => "learned",
        }
    }
}

/// What the owner calls a device: 1 to [`LABEL_MAX`] printable ASCII characters. It reads as a
/// `str`, and its `Debug` says nothing of it: a label that ends up in a log line by accident would
/// say who lives in the house.
#[derive(Clone, PartialEq, Eq)]
pub struct Label(String);

impl Label {
    /// The label `text`, or `None` if it is empty, longer than [`LABEL_MAX`], or has a character
    /// that is not printable ASCII (a space is).
    pub fn new(text: &str) -> Option<Label> {
        let fits = (1..=LABEL_MAX).contains(&text.len());
        (fits && text.bytes().all(|byte| (0x20..=0x7e).contains(&byte))).then(|| Label(text.into()))
    }
}

impl Deref for Label {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Label {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("Label(..)")
    }
}

/// Why an edit of a device's exemption or gate was refused. It names no device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditError {
    /// The configuration's list of the mode in force names the device: only the configuration
    /// changes it.
    Fixed,
    /// The device is the router or the Pi itself, which are never exempt.
    Always,
    /// The pushed list or the gates are full.
    Full,
    /// The inventory has no such device (for a gate).
    Unknown,
    /// Not a device's address, or a gate for longer than [`MAX_GATE_SECS`].
    Invalid,
}

impl EditError {
    /// The word the API says: `fixed`, `always`, `full`, `unknown` or `invalid`.
    pub fn as_str(self) -> &'static str {
        match self {
            EditError::Fixed => "fixed",
            EditError::Always => "always",
            EditError::Full => "full",
            EditError::Unknown => "unknown",
            EditError::Invalid => "invalid",
        }
    }
}

/// One device as a reader sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceView {
    /// The device's hardware address.
    pub mac: Mac,
    /// The IPv4 addresses it has been seen with, the newest first, at most four.
    pub ipv4: Vec<Ipv4Addr>,
    /// The host name it gave by DHCP or mDNS, as the parsers sanitized it.
    pub hostname: Option<String>,
    /// The unix time when it was first seen.
    pub first_unix: u64,
    /// The unix time when it was last seen.
    pub last_unix: u64,
    /// Whether its MAC is on the known list, which is the learned one after the learning.
    pub known: bool,
    /// Whether it is exempt from the ads lists. In the list mode: its MAC is on an exempt list,
    /// the configuration's or the pushed one, or its gate is open. In the exempt-by-default mode:
    /// it is not on a block list (or its gate is open), and no address that it claimed last is the
    /// router's or the Pi's own.
    pub exempt: bool,
    /// Whether its MAC is on a block list, the configuration's or the pushed one, whatever the
    /// mode, and whether or not its gate is open.
    pub blocked: bool,
    /// What the owner calls it, from the desktop's labels.
    pub label: Option<Label>,
    /// The place of its label in the desktop's list, which is the order the panel shows labelled
    /// devices in; `None` for a device with no label.
    pub label_rank: Option<usize>,
    /// How many seconds its gate stays open, 1 to [`MAX_GATE_SECS`]; `None` while it is shut.
    pub gate_left_secs: Option<u16>,
    /// Whether the configuration's list of the mode in force names it, so that no edit of the
    /// panel or the desktop changes it: the exempt list in the list mode, the block list in the
    /// exempt-by-default mode.
    pub fixed: bool,
    /// Whether it is the router, or claims the router's or the Pi's address: never exempt.
    pub always: bool,
}

/// The inventory as a reader sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicesView {
    /// The revision of the pushed lists, the mode, the labels and the gates: it moves with every
    /// change of them, whoever made it.
    pub rev: u64,
    /// Whether a known list has come.
    pub known_list: KnownList,
    /// Every device in the inventory, the one seen last first.
    pub devices: Vec<DeviceView>,
    /// The MACs of both exempt lists, sorted and each once, those not heard yet included.
    pub exempt_macs: Vec<Mac>,
    /// The MACs of the pushed exempt list alone, sorted, those not heard yet included.
    pub exempt_pushed: Vec<Mac>,
    /// Whether the exempt-by-default mode is in force.
    pub exempt_default: bool,
    /// The MACs of both block lists, sorted and each once, those not heard yet included.
    pub block_macs: Vec<Mac>,
    /// The MACs of the pushed block list alone, sorted, those not heard yet included.
    pub block_pushed: Vec<Mac>,
    /// The Pi's own hardware address, once it is known: it is no device of the inventory, and is
    /// one of the two that are always blocked.
    pub own_mac: Option<Mac>,
    /// The Pi's own address, if it was given: the panel names the Pi's place on its wall by it.
    pub own_ip: Option<Ipv4Addr>,
}

/// How many places the panel's wall has: the most rows a [`WallCopy`] holds.
pub const WALL_ROWS: usize = qb_panel::os::world::MAX_DEVICES;

/// A text of at most `N` bytes kept in place, cut at a character boundary when it is longer; the
/// empty text is none. For what a copy under the inventory's lock holds without allocating.
#[derive(Clone, Copy)]
struct Inline<const N: usize> {
    len: u8,
    bytes: [u8; N],
}

impl<const N: usize> Inline<N> {
    /// No text.
    const EMPTY: Self = Self {
        len: 0,
        bytes: [0; N],
    };

    /// Keeps `text`, or its longest start that is whole characters and fits.
    fn set(&mut self, text: Option<&str>) {
        let text = text.unwrap_or("");
        let mut end = text.len().min(N);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        self.bytes[..end].copy_from_slice(&text.as_bytes()[..end]);
        self.len = u8::try_from(end).unwrap_or(u8::MAX);
    }

    /// The text, or `None` for none.
    fn get(&self) -> Option<&str> {
        let text = self.bytes.get(..usize::from(self.len))?;
        if text.is_empty() {
            return None;
        }
        std::str::from_utf8(text).ok()
    }
}

/// What the panel's wall needs of one device, held in place: no field allocates, so that
/// [`Devices::wall_copy`] fills a buffer that it never grows while the inventory is locked.
///
/// It has no `Debug`: it holds a host name and a label.
#[derive(Clone, Copy)]
pub struct WallDevice {
    /// The device's hardware address.
    pub mac: Mac,
    ipv4: [Ipv4Addr; MAX_IPV4],
    ipv4_len: u8,
    hostname: Inline<HOSTNAME_MAX>,
    label: Inline<LABEL_MAX>,
    /// The unix time when it was first seen.
    pub first_unix: u64,
    /// The unix time when it was last seen.
    pub last_unix: u64,
    /// The place of its label in the desktop's list; `None` for a device with no label.
    pub label_rank: Option<usize>,
    /// How many seconds its gate stays open; `None` while it is shut.
    pub gate_left_secs: Option<u16>,
    /// As [`DeviceView::exempt`].
    pub exempt: bool,
    /// As [`DeviceView::fixed`].
    pub fixed: bool,
    /// As [`DeviceView::always`].
    pub always: bool,
}

impl WallDevice {
    /// The IPv4 addresses it has been seen with, the newest first, at most four.
    pub fn ipv4(&self) -> &[Ipv4Addr] {
        self.ipv4.get(..usize::from(self.ipv4_len)).unwrap_or(&[])
    }

    /// The host name it gave, as the parsers sanitized it.
    pub fn hostname(&self) -> Option<&str> {
        self.hostname.get()
    }

    /// What the owner calls it.
    pub fn label(&self) -> Option<&str> {
        self.label.get()
    }

    /// The wall's fields of a device as a reader sees it, for tests that hold a [`DevicesView`].
    #[cfg(test)]
    pub fn of_view(device: &DeviceView) -> Self {
        let mut ipv4 = [Ipv4Addr::UNSPECIFIED; MAX_IPV4];
        let held = device.ipv4.len().min(MAX_IPV4);
        ipv4[..held].copy_from_slice(&device.ipv4[..held]);
        let mut wall = Self {
            mac: device.mac,
            ipv4,
            ipv4_len: u8::try_from(held).unwrap_or(0),
            hostname: Inline::EMPTY,
            label: Inline::EMPTY,
            first_unix: device.first_unix,
            last_unix: device.last_unix,
            label_rank: device.label_rank,
            gate_left_secs: device.gate_left_secs,
            exempt: device.exempt,
            fixed: device.fixed,
            always: device.always,
        };
        wall.hostname.set(device.hostname.as_deref());
        wall.label.set(device.label.as_deref());
        wall
    }
}

/// What the panel's wall reads of the inventory, in a buffer that the panel keeps: made once by
/// [`WallCopy::new`], filled by [`Devices::wall_copy`] every time, never grown.
///
/// It has no `Debug`: it holds the devices' names and addresses.
pub struct WallCopy {
    /// The devices the wall can show, in no order: at most [`WALL_ROWS`].
    pub rows: Vec<WallDevice>,
    /// Whether the exempt-by-default mode is in force.
    pub exempt_default: bool,
    /// The Pi's own hardware address, once it is known.
    pub own_mac: Option<Mac>,
    /// The Pi's own address, if it was given.
    pub own_ip: Option<Ipv4Addr>,
}

impl WallCopy {
    /// An empty copy, with room for every row it will ever hold.
    pub fn new() -> Self {
        Self {
            rows: Vec::with_capacity(WALL_ROWS),
            exempt_default: false,
            own_mac: None,
            own_ip: None,
        }
    }

    /// The copy of a [`DevicesView`], all of its devices, for tests of what is built from a copy.
    #[cfg(test)]
    pub fn of_view(view: &DevicesView) -> Self {
        Self {
            rows: view.devices.iter().map(WallDevice::of_view).collect(),
            exempt_default: view.exempt_default,
            own_mac: view.own_mac,
            own_ip: view.own_ip,
        }
    }
}

impl Default for WallCopy {
    fn default() -> Self {
        Self::new()
    }
}

/// How a device ranks for a place on the wall: labelled devices first by the place of the label (0,
/// rank), then the others by first sighting (1, unix time), the MAC deciding a tie. The router and
/// the Pi are ranked by first sighting among themselves.
type WallKey = (u8, u64, Mac);

/// The `N` devices with the smallest [`WallKey`]s of those offered, in order, on the stack: what
/// [`Devices::wall_copy`] picks from the inventory in one pass without sorting it or allocating.
struct Smallest<'a, const N: usize> {
    len: usize,
    keys: [WallKey; N],
    devices: [Option<&'a Device>; N],
}

impl<'a, const N: usize> Smallest<'a, N> {
    fn new() -> Self {
        Self {
            len: 0,
            keys: [(0, 0, Mac([0; 6])); N],
            devices: [None; N],
        }
    }

    /// Whether `key` would take a place now: there is one free, or it is smaller than the last.
    fn accepts(&self, key: WallKey) -> bool {
        self.len < N || self.keys.last().is_some_and(|worst| key < *worst)
    }

    /// Takes `device` in if its `key` is among the `N` smallest so far.
    fn offer(&mut self, key: WallKey, device: &'a Device) {
        // The common case once the places are full: it ranks after them all.
        if self.len == N && self.keys.last().is_some_and(|worst| key >= *worst) {
            return;
        }
        let at = self.keys[..self.len].partition_point(|held| *held < key);
        if at >= N {
            return;
        }
        // The last of the full places falls off the end.
        let end = self.len.min(N - 1);
        self.keys.copy_within(at..end, at + 1);
        self.devices.copy_within(at..end, at + 1);
        self.keys[at] = key;
        self.devices[at] = Some(device);
        self.len = (self.len + 1).min(N);
    }

    fn len(&self) -> usize {
        self.len
    }

    /// The first `n` devices, smallest key first.
    fn first(&self, n: usize) -> impl Iterator<Item = (Mac, &'a Device)> + '_ {
        self.keys
            .iter()
            .zip(&self.devices)
            .take(n.min(self.len))
            .filter_map(|(key, device)| Some((key.2, (*device)?)))
    }
}

/// What the inventory keeps of one device.
struct Device {
    /// Its addresses, the oldest first.
    ipv4: Vec<Ipv4Addr>,
    /// Its host name, if one was heard.
    hostname: Option<String>,
    /// The unix time when it was first seen.
    first_unix: u64,
    /// The unix time when it was last seen.
    last_unix: u64,
    /// The number of the sighting that last saw it: the order of sightings, which the seconds of
    /// a clock are too coarse to give.
    seen: u64,
    /// The monotonic second of the last `new_device` alert that was made for it since it came into
    /// the inventory.
    alerted_at: Option<u64>,
    /// Whether the held alerts were full when it would have been held, and this was counted.
    hold_dropped: bool,
}

/// The inventory of devices on the home network.
pub struct Devices {
    /// The Pi's own address on the wireless link, which is never a device; set once it is known.
    own_mac: Option<Mac>,
    /// The Pi's own IPv4 address, which is never exempt and always fully blocked; set once it is
    /// given.
    own_ip: Option<Ipv4Addr>,
    /// The router's address, whose MAC the first ARP that claims it fixes.
    gateway: Ipv4Addr,
    /// The MAC that the gateway was first heard from, fixed for the boot.
    gateway_mac: Option<Mac>,
    /// The alerts that calls have made and nobody has taken yet, at most [`MAX_PENDING`].
    pending: Vec<Alert>,
    /// How many alerts were dropped because [`MAX_PENDING`] waited already, since the start.
    dropped_alerts: u64,
    /// The monotonic seconds and the unix seconds.
    clock: Clock,
    /// The monotonic second of the first sighting of a device, which the learning counts from;
    /// `None` until a device is heard.
    first_seen: Option<u64>,
    /// Whether a known list has come.
    state: KnownList,
    /// The MACs that are not new.
    known: HashSet<Mac>,
    /// Whether `known` was restored from the card and is not empty, so that it stands in for the
    /// desktop's list if none comes ([`Devices::tick`]). Cleared when a list comes.
    restored: bool,
    /// The known list that is being sent in chunks and has not come whole, which replaces `known`
    /// with the last chunk; `None` when no list is on its way.
    staged: Option<HashSet<Mac>>,
    /// The devices, by MAC.
    devices: HashMap<Mac, Device>,
    /// The device that each address was last seen with, which is where an mDNS name goes.
    by_ip: HashMap<Ipv4Addr, Mac>,
    /// The MACs whose alert waits for a known list, in the order they came.
    held: Vec<Mac>,
    /// How many devices the held alerts could not take, since the start.
    dropped_holds: u64,
    /// How many sightings there have been.
    sightings: u64,
    /// The MACs that the configuration exempts from the ads lists, at most [`MAX_EXEMPT`].
    exempt_config: HashSet<Mac>,
    /// The MACs that the desktop last pushed as exempt, at most [`MAX_EXEMPT`].
    exempt_pushed: HashSet<Mac>,
    /// Whether a pushed exempt list has come since the start, which decides a log line.
    exempt_received: bool,
    /// Whether the configuration turns the exempt-by-default mode on.
    default_config: bool,
    /// The mode that the desktop last pushed; `None` until a policy has come since the start.
    default_pushed: Option<bool>,
    /// The MACs that the configuration keeps fully blocked, at most [`MAX_BLOCK`].
    block_config: HashSet<Mac>,
    /// The MACs that the desktop last pushed as fully blocked, at most [`MAX_BLOCK`].
    block_pushed: HashSet<Mac>,
    /// The mode and the number of blocked devices that the last policy line told, which decides
    /// the next one; `None` until one is logged.
    policy_logged: Option<(bool, usize)>,
    /// Where the mode and the addresses are published, for the DNS side.
    exemption: Arc<Exemption>,
    /// The exempt addresses that were published last, sorted, each once.
    exempt_published: Vec<Ipv4Addr>,
    /// The fully blocked addresses that were published last, sorted, each once.
    blocked_published: Vec<Ipv4Addr>,
    /// The revision of the pushed lists, the mode, the labels and the gates; it moves with every
    /// change of them. It starts from a number of its own on every boot ([`crate::sys::rev_seed`],
    /// never 0), so that a revision a desktop kept from the boot before is not the one now.
    rev: u64,
    /// The devices whose gate is open, by MAC, with the monotonic second at which it shuts, at
    /// most [`MAX_GATES`].
    gates: HashMap<Mac, u64>,
    /// Woken when a gate is opened, so that the device watch looks at the next deadline again.
    gate_wake: Arc<Notify>,
    /// The desktop's labels, in its order, at most [`MAX_LABELS`], each MAC once.
    labels: Vec<(Mac, Label)>,
    /// The labels that are being sent in chunks and have not come whole; `None` when no list is on
    /// its way.
    staged_labels: Option<Vec<(Mac, Label)>>,
}

impl Devices {
    /// Makes an empty inventory for a network whose router is `gateway`.
    ///
    /// `own_mac` is the Pi's own hardware address if it is known already; `set_own_mac` gives it
    /// later. `clock` gives (monotonic seconds, unix seconds); the learning counts from the
    /// monotonic seconds of the first device that is heard.
    pub fn new(own_mac: Option<Mac>, gateway: Ipv4Addr, clock: Clock) -> Self {
        Self {
            own_mac,
            own_ip: None,
            gateway,
            gateway_mac: None,
            pending: Vec::new(),
            dropped_alerts: 0,
            clock,
            first_seen: None,
            state: KnownList::Waiting,
            known: HashSet::new(),
            restored: false,
            staged: None,
            devices: HashMap::new(),
            by_ip: HashMap::new(),
            held: Vec::new(),
            dropped_holds: 0,
            sightings: 0,
            exempt_config: HashSet::new(),
            exempt_pushed: HashSet::new(),
            exempt_received: false,
            default_config: false,
            default_pushed: None,
            block_config: HashSet::new(),
            block_pushed: HashSet::new(),
            policy_logged: None,
            exemption: Arc::default(),
            exempt_published: Vec::new(),
            blocked_published: Vec::new(),
            rev: crate::sys::rev_seed(),
            gates: HashMap::new(),
            gate_wake: Arc::new(Notify::new()),
            labels: Vec::new(),
            staged_labels: None,
        }
    }

    /// Makes the inventory publish who is exempt to `exemption`, which the DNS service reads: it
    /// is given the mode and the addresses now at once, and kept in step from then on. Until this
    /// is called the inventory publishes to one of its own, which nobody reads.
    pub fn with_exemption(mut self, exemption: Arc<Exemption>) -> Self {
        self.exemption = exemption;
        self.exempt_published = self.exempt_now();
        self.exemption.listed().replace(&self.exempt_published);
        self.blocked_published = self.blocked_now();
        self.exemption.blocked().replace(&self.blocked_published);
        self.publish_unblocked();
        self.exemption.set_by_default(self.exempt_default());
        self
    }

    /// Gives the inventory the Pi's own IPv4 address, which, like the router's, is never in the
    /// exempt set and always in the blocked one, whatever MAC claims it.
    pub fn with_own_ip(mut self, ip: Ipv4Addr) -> Self {
        self.own_ip = Some(ip);
        self.refresh_exempt();
        self
    }

    /// Sets whether the configuration turns the exempt-by-default mode on. It is the mode in
    /// force until a policy is pushed.
    pub fn set_exempt_default_config(&mut self, on: bool) {
        self.default_config = on;
        self.publish_mode();
    }

    /// Replaces the configuration's block list with `macs` and says how many different ones it
    /// kept: the first [`MAX_BLOCK`] of them. The pushed list stays as it is, and the blocked
    /// addresses are worked out again.
    pub fn set_block_config(&mut self, macs: Vec<Mac>) -> usize {
        self.block_config = first_different(macs, MAX_BLOCK);
        self.refresh_exempt();
        self.block_config.len()
    }

    /// Replaces the pushed policy: the mode, which is the one in force from now on, and the pushed
    /// block list, of which the first [`MAX_BLOCK`] different MACs are kept; it says how many. The
    /// configuration's block list stays as it is. A MAC need not be in the inventory: one that has
    /// not been heard has no address, and its address is fully blocked from when it is heard.
    ///
    /// One line tells the mode, and in the exempt-by-default mode the number of different MACs of
    /// both block lists, when that is not what the line before told; no MAC or address is logged.
    pub fn set_policy(&mut self, exempt_default: bool, block: Vec<Mac>) -> usize {
        let block = first_different(block, MAX_BLOCK);
        if exempt_default != self.exempt_default() || block != self.block_pushed {
            self.rev += 1;
        }
        self.block_pushed = block;
        self.default_pushed = Some(exempt_default);
        // The blocked set is up to date before the mode that reads it is turned on.
        self.refresh_exempt();
        self.publish_mode();
        if let Some(line) = self.policy_news() {
            log::info!("{line}");
        }
        self.block_pushed.len()
    }

    /// The line that tells the policy in force, after one was pushed, if it is not what the line
    /// before told: the mode and, in the exempt-by-default mode, the number of different MACs of
    /// both block lists. It tells no MAC and no address.
    fn policy_news(&mut self) -> Option<String> {
        let on = self.exempt_default();
        let blocked = self.block_config.union(&self.block_pushed).count();
        let told = (on, if on { blocked } else { 0 });
        if self.policy_logged == Some(told) {
            return None;
        }
        self.policy_logged = Some(told);
        Some(if on {
            format!(
                "watch: exemption policy received: exempt by default, {blocked} blocked devices"
            )
        } else {
            "watch: exemption policy received: exempt list only".to_owned()
        })
    }

    /// Whether the exempt-by-default mode is in force: the pushed mode once a policy has come,
    /// and the configuration's until then.
    pub fn exempt_default(&self) -> bool {
        self.default_pushed.unwrap_or(self.default_config)
    }

    /// Replaces the configuration's exempt list with `macs` and says how many different ones it
    /// kept: the first [`MAX_EXEMPT`] of them. The pushed list stays as it is, and the exempt
    /// addresses are worked out again.
    pub fn set_exempt_config(&mut self, macs: Vec<Mac>) -> usize {
        self.exempt_config = first_different(macs, MAX_EXEMPT);
        self.refresh_exempt();
        self.exempt_config.len()
    }

    /// Replaces the pushed exempt list with `macs` and says how many different ones it kept: the
    /// first [`MAX_EXEMPT`] of them. The configuration's list stays as it is, and the exempt
    /// addresses are worked out again. A MAC need not be in the inventory: one that has not been
    /// heard has no address, and is exempt from when it is heard.
    ///
    /// One line says how many devices the list has, when it is the first since the start or that
    /// count changed; no MAC or address is logged.
    pub fn set_exempt(&mut self, macs: Vec<Mac>) -> usize {
        let pushed = first_different(macs, MAX_EXEMPT);
        let kept = pushed.len();
        let news = !self.exempt_received || self.exempt_pushed.len() != kept;
        if pushed != self.exempt_pushed {
            self.rev += 1;
        }
        self.exempt_pushed = pushed;
        self.exempt_received = true;
        self.refresh_exempt();
        if news {
            log::info!("watch: exempt list of {kept} devices received");
        }
        kept
    }

    /// The revision of the pushed lists, the mode, the labels and the gates: it moves with every
    /// change of them, from the API, the panel or a gate that expires, and with nothing else. A
    /// push that would change nothing does not move it. It goes up by one for a change, from a
    /// number that is different on every boot, so what the desktop kept from the last boot is not
    /// the revision now.
    pub fn rev(&self) -> u64 {
        self.rev
    }

    /// Makes the revision start from `rev` in place of this boot's own number, so that a test can
    /// say what each change makes it.
    #[cfg(test)]
    pub(crate) fn starting_at(mut self, rev: u64) -> Self {
        self.rev = rev;
        self
    }

    /// Whether a push that was made on the revision `if_rev` may go ahead: with `None` it always
    /// may, and with a revision only if that is the one now. When it may not, the revision that
    /// is now is the error.
    pub fn check_rev(&self, if_rev: Option<u64>) -> Result<(), u64> {
        match if_rev {
            Some(wanted) if wanted != self.rev => Err(self.rev),
            _ => Ok(()),
        }
    }

    /// Lets ads pass for the device `mac` for good (`pass`) or stops that: it edits the pushed
    /// list of the mode in force, the exempt list in the list mode and the block list in the
    /// exempt-by-default mode, and republishes the sets as any change of a list does. A device
    /// that is not in the inventory yet may be edited: the lists name MACs that have not been
    /// heard. Stopping it also shuts the device's gate, so that it is blocked from then on. Doing
    /// what is done already changes nothing, and moves no revision.
    ///
    /// Refused: the router and the Pi ([`EditError::Always`]), a device that the configuration's
    /// list of the mode in force names ([`EditError::Fixed`]), an address that is no device's
    /// ([`EditError::Invalid`]), and a pushed list that is full ([`EditError::Full`]).
    pub fn set_ads_pass(&mut self, mac: Mac, pass: bool) -> Result<(), EditError> {
        if !mac.can_be_a_device() {
            return Err(EditError::Invalid);
        }
        if self.is_always(mac) {
            return Err(EditError::Always);
        }
        if self.is_fixed(mac) {
            return Err(EditError::Fixed);
        }
        let by_default = self.exempt_default();
        // Whether the pushed list of the mode in force should hold the MAC.
        let (list, cap, listed) = if by_default {
            (&mut self.block_pushed, MAX_BLOCK, !pass)
        } else {
            (&mut self.exempt_pushed, MAX_EXEMPT, pass)
        };
        let mut changed = false;
        if listed && !list.contains(&mac) {
            if list.len() >= cap {
                return Err(EditError::Full);
            }
            list.insert(mac);
            changed = true;
        } else if !listed {
            changed = list.remove(&mac);
        }
        if !pass {
            changed |= self.gates.remove(&mac).is_some();
        }
        if changed {
            self.rev += 1;
            self.refresh_exempt();
        }
        Ok(())
    }

    /// Opens the gate of the device `mac` for `secs` seconds from now, or shuts it with 0; an
    /// open gate is given the new time. While it is open the device is exempt in either mode, and
    /// the sets are republished as for a change of a list.
    ///
    /// Any device that the inventory lists may have a gate: the ones that are exempt or blocked by
    /// a pushed list, or by neither. Refused: more than [`MAX_GATE_SECS`] or an address that is no
    /// device's ([`EditError::Invalid`]), the router and the Pi ([`EditError::Always`]), a device
    /// that the configuration's list of the mode in force names ([`EditError::Fixed`]), a device
    /// that is not in the inventory ([`EditError::Unknown`], but for shutting a gate that is
    /// open), and [`MAX_GATES`] gates already open for others ([`EditError::Full`]).
    pub fn open_gate(&mut self, mac: Mac, secs: u16) -> Result<(), EditError> {
        if !mac.can_be_a_device() || secs > MAX_GATE_SECS {
            return Err(EditError::Invalid);
        }
        if self.is_always(mac) {
            return Err(EditError::Always);
        }
        if self.is_fixed(mac) {
            return Err(EditError::Fixed);
        }
        if secs == 0 {
            if self.gates.remove(&mac).is_some() {
                self.rev += 1;
                self.refresh_exempt();
                return Ok(());
            }
            return if self.devices.contains_key(&mac) {
                Ok(())
            } else {
                Err(EditError::Unknown)
            };
        }
        if !self.devices.contains_key(&mac) {
            return Err(EditError::Unknown);
        }
        if !self.gates.contains_key(&mac) && self.gates.len() >= MAX_GATES {
            return Err(EditError::Full);
        }
        let (mono, _) = (self.clock)();
        self.gates.insert(mac, mono.saturating_add(u64::from(secs)));
        self.rev += 1;
        self.refresh_exempt();
        self.gate_wake.notify_one();
        Ok(())
    }

    /// Shuts the gate of `mac`: [`Devices::open_gate`] with 0.
    pub fn shut_gate(&mut self, mac: Mac) -> Result<(), EditError> {
        self.open_gate(mac, 0)
    }

    /// Shuts the gates whose time has come, at the monotonic second `now`, and republishes the
    /// sets if any did. It says how many it shut.
    pub fn expire_gates(&mut self, now: u64) -> usize {
        let before = self.gates.len();
        self.gates.retain(|_, shuts| *shuts > now);
        let shut = before - self.gates.len();
        if shut > 0 {
            self.rev += 1;
            self.refresh_exempt();
        }
        shut
    }

    /// The monotonic second at which the first open gate shuts; `None` with no gate open.
    pub fn next_gate_deadline(&self) -> Option<u64> {
        self.gates.values().min().copied()
    }

    /// The inventory's monotonic second, which is the clock that the gates' deadlines are on.
    pub fn mono_now(&self) -> u64 {
        (self.clock)().0
    }

    /// What the device watch waits on while no gate is due: woken when a gate is opened, so that it
    /// looks at the next deadline again.
    pub fn gate_wake(&self) -> Arc<Notify> {
        self.gate_wake.clone()
    }

    /// Takes a chunk of the labels, `labels`, and says how many the set that it belongs to holds
    /// now, at most [`MAX_LABELS`]: the list of the desktop's names for its devices, in its order,
    /// each MAC once (the first of a MAC that comes twice stays), is sent as the known list is.
    ///
    /// With `append` false the chunk starts a list that replaces the labels; with it true the
    /// chunk is added to the list that is being sent, or to the labels if none is. A list that is
    /// being sent is kept apart and takes the place of the labels only when its last chunk, the one
    /// with `complete` true, has come; the old labels stay in force until then. Whenever the labels
    /// in force change the revision moves. One line says how many labels the list has when it
    /// is complete and changed them; no MAC and no label is logged.
    pub fn load_labels(
        &mut self,
        labels: Vec<(Mac, Label)>,
        append: bool,
        complete: bool,
    ) -> usize {
        let (mut list, staged) = match (append, self.staged_labels.take()) {
            (false, _) => (Vec::new(), true),
            (true, Some(staged)) => (staged, true),
            (true, None) => (self.labels.clone(), false),
        };
        for (mac, label) in labels {
            if list.len() >= MAX_LABELS {
                break;
            }
            if !list.iter().any(|(held, _)| *held == mac) {
                list.push((mac, label));
            }
        }
        let kept = list.len();
        if staged && !complete {
            self.staged_labels = Some(list);
            return kept;
        }
        if list != self.labels {
            self.labels = list;
            self.rev += 1;
            if complete {
                log::info!("watch: labels of {kept} devices received");
            }
        }
        kept
    }

    /// What is kept of the inventory ([`SavedDevices`]): the pushed exempt and block lists, the
    /// pushed mode (`None` while no policy has been pushed), the labels in the desktop's order,
    /// and the known set. The three sets come sorted, each MAC once, so that the same state is
    /// always the same copy. The configuration's lists, the gates, the staged chunks of a push
    /// and the devices heard are not kept. It copies at most 64 + 64 + 64 + 1024 MACs and 64
    /// labels, and takes no lock of its own.
    pub fn kept(&self) -> SavedDevices {
        let sorted = |set: &HashSet<Mac>| {
            let mut macs: Vec<Mac> = set.iter().copied().collect();
            macs.sort_unstable();
            macs
        };
        SavedDevices {
            exempt: sorted(&self.exempt_pushed),
            block: sorted(&self.block_pushed),
            exempt_default: self.default_pushed,
            labels: self.labels.clone(),
            known: sorted(&self.known),
        }
    }

    /// Takes back what [`Devices::kept`] gave, at the start, before anything is heard or pushed:
    /// the pushed lists, the pushed mode, the labels and the known set replace what the inventory
    /// holds, capped as the setters cap (the first [`MAX_EXEMPT`] and [`MAX_BLOCK`] different
    /// MACs, the first [`MAX_LABELS`] labels with each MAC once, the first [`MAX_KNOWN`] different
    /// known MACs). The sets the DNS side reads and the mode are republished as a push does.
    ///
    /// It logs nothing, and leaves the known list `Waiting`: the API still says `waiting`, and the
    /// desktop, which treats a Pi that waits as one that restarted, pushes its lists again. A
    /// device on the restored known set is known from its first sighting. If the set is not empty
    /// it also stands in for the desktop's list: when [`LEARN_AFTER_SECS`] pass with none, the
    /// held newcomers are raised and not learned ([`Devices::tick`]). An empty set stands in for
    /// nothing, and the learning is as ever.
    ///
    /// The revision moves by one if the pushed lists, the mode or the labels end up other than
    /// they were, as any change of them does, and not otherwise: a restore of the same state
    /// changes nothing, and the known set has no part in the revision. At a start nobody has read
    /// the revision yet, and it is a number of this boot's own already.
    pub fn restore(&mut self, saved: SavedDevices) {
        let exempt = first_different(saved.exempt, MAX_EXEMPT);
        let block = first_different(saved.block, MAX_BLOCK);
        let mut labels: Vec<(Mac, Label)> = Vec::new();
        for (mac, label) in saved.labels {
            if labels.len() >= MAX_LABELS {
                break;
            }
            if !labels.iter().any(|(held, _)| *held == mac) {
                labels.push((mac, label));
            }
        }
        let changed = exempt != self.exempt_pushed
            || block != self.block_pushed
            || saved.exempt_default != self.default_pushed
            || labels != self.labels;
        if changed {
            self.rev += 1;
        }
        self.exempt_pushed = exempt;
        self.block_pushed = block;
        self.default_pushed = saved.exempt_default;
        self.labels = labels;
        self.known = first_different(saved.known, MAX_KNOWN);
        self.restored = !self.known.is_empty();
        // The blocked set is up to date before the mode that reads it is turned on.
        self.refresh_exempt();
        self.publish_mode();
    }

    /// Sets the Pi's own hardware address, which is never a device, and drops it from the
    /// inventory if it got in.
    pub fn set_own_mac(&mut self, mac: Mac) {
        self.own_mac = Some(mac);
        self.forget(mac);
        self.held.retain(|&held| held != mac);
    }

    /// Takes in an ARP message: its sender is a device with that address.
    ///
    /// A sender address of 0.0.0.0 is a probe, which says that the device has no address yet: the
    /// device is noted and no address goes to it. A message that claims the gateway's address is
    /// checked against the MAC that claimed it first.
    pub fn on_arp(&mut self, arp: &Arp) {
        self.check_gateway(arp);
        let ip = (!arp.sender_ip.is_unspecified()).then_some(arp.sender_ip);
        self.see(arp.sender_mac, ip, None);
    }

    /// Takes in a DHCP DISCOVER or REQUEST: its `chaddr` is a device, with the address that it
    /// asks for, or else the one it says it has, and the host name that it gives.
    ///
    /// A message of another type is no sign of a device with that address, and is ignored.
    pub fn on_dhcp(&mut self, dhcp: &Dhcp) {
        if !matches!(dhcp.msg_type, Some(DHCP_DISCOVER | DHCP_REQUEST)) {
            return;
        }
        let ip = dhcp
            .requested_ip
            .into_iter()
            .chain([dhcp.ciaddr])
            .find(|ip| !ip.is_unspecified());
        self.see(dhcp.chaddr, ip, dhcp.hostname.as_deref());
    }

    /// Takes in an mDNS host name for `addr`: it goes to the device that an ARP or a DHCP message
    /// gave that address, and is ignored when there is none.
    ///
    /// An announcement is nobody's proof that a device is there, so it does not count as a
    /// sighting. An empty name, or one longer than [`HOSTNAME_MAX`], is ignored.
    pub fn on_mdns(&mut self, addr: Ipv4Addr, host: &str) {
        if host.is_empty() || host.len() > HOSTNAME_MAX {
            return;
        }
        let Some(mac) = self.by_ip.get(&addr) else {
            return;
        };
        if let Some(device) = self.devices.get_mut(mac)
            && device.hostname.as_deref() != Some(host)
        {
            device.hostname = Some(host.to_owned());
        }
    }

    /// Replaces the known list with `macs` and says how many different ones it kept: the first
    /// [`MAX_KNOWN`] of them. It is [`Devices::load_known`] of a whole list.
    pub fn set_known(&mut self, macs: Vec<Mac>) -> usize {
        self.load_known(macs, false, true)
    }

    /// Takes a chunk of the known list, `macs`, and says how many different MACs the set that it
    /// belongs to holds now, at most [`MAX_KNOWN`]: a list longer than one request may be sent in
    /// several.
    ///
    /// With `append` false the chunk starts a list that replaces the known set; with it true the
    /// chunk is added to the list that is being sent, or to the known set if none is. A list that
    /// is being sent is kept apart and is the known set only when its last chunk, the one with
    /// `complete` true, has come, so that the devices of later chunks are not raised in the
    /// meantime; the old set stays in force until then, and a list whose last chunk never comes
    /// changes nothing. A chunk that adds to the known set directly, with `complete` false, makes
    /// no decision either.
    ///
    /// Only the chunk with `complete` true decides: the alerts that were held are decided now,
    /// those for MACs on the list dropped and the others raised. Then every device in the
    /// inventory that is not on the list and was never alerted is raised too. A list that comes
    /// after the learning, or after another list, is applied the same way, whatever the state
    /// was. One line says how many devices the list has, when it is the first or that count
    /// changed.
    pub fn load_known(&mut self, macs: Vec<Mac>, append: bool, complete: bool) -> usize {
        // Where the chunk goes: a list that is being sent, or the known set itself.
        let (mut set, staged) = match (append, self.staged.take()) {
            (false, _) => (HashSet::new(), true),
            (true, Some(staged)) => (staged, true),
            (true, None) => (self.known.clone(), false),
        };
        for mac in macs {
            if set.len() >= MAX_KNOWN {
                break;
            }
            set.insert(mac);
        }
        let kept = set.len();
        if !complete {
            if staged {
                self.staged = Some(set);
            } else {
                self.known = set;
            }
            return kept;
        }
        // A list that says what the one before did is not news for the log.
        let news = self.state != KnownList::Received || self.known.len() != kept;
        self.known = set;
        self.restored = false;
        self.state = KnownList::Received;
        self.raise_unknown();
        if news {
            log::info!("watch: known list of {kept} devices received");
        }
        kept
    }

    /// Does what is due by now: if no known list has come [`LEARN_AFTER_SECS`] after the first
    /// device was seen, every device seen so far joins the known set, silently, and the held
    /// alerts are dropped. With no device seen there is nothing to learn, and nothing happens.
    ///
    /// When the known set was restored from the card ([`Devices::restore`]) it stands in for the
    /// desktop's list instead: the devices that are not on it are raised, the held ones and any
    /// never alerted, as a list that came would raise them, none is learned, and the state becomes
    /// `Learned` all the same. One line says how many devices the restored set had.
    pub fn tick(&mut self) {
        let (mono, _) = (self.clock)();
        let Some(first) = self.first_seen else {
            return;
        };
        if self.state != KnownList::Waiting || mono < first.saturating_add(LEARN_AFTER_SECS) {
            return;
        }
        if self.restored {
            self.restored = false;
            self.state = KnownList::Learned;
            self.raise_unknown();
            log::info!(
                "watch: no known list came; the saved one of {} devices stands",
                self.known.len()
            );
            return;
        }
        // What chunks of a list have put in the set stays; the devices heard join it.
        for &mac in self.devices.keys() {
            if self.known.len() >= MAX_KNOWN {
                break;
            }
            self.known.insert(mac);
        }
        self.held.clear();
        self.state = KnownList::Learned;
        log::info!("watch: learned {} devices", self.devices.len());
    }

    /// Copies what the panel's wall reads into `out`, whose rows and fields it replaces: the devices
    /// that the wall can show, no more than [`WALL_ROWS`] of them, and the few fields of each that
    /// the wall uses. The panel asks every two seconds, and `devwatch` takes this lock for every ARP,
    /// DHCP and mDNS packet on the thread that also answers DNS, so this is made to be short:
    /// [`Devices::view`] builds up to 512 devices with clones, a map of the labels and a sort, and
    /// this builds none of that. It walks the inventory once, keeps the best few keys on the stack,
    /// and copies only those devices into `out`'s own room (made by [`WallCopy::new`] and never
    /// grown). The wall's own sorting, its names, and the fitting of its texts are done by the
    /// panel with the lock let go.
    ///
    /// Which devices: those the wall shows first, by its own order (spec §3.4): the router and the
    /// Pi (the `always` ones), then, with the places that are left, the labelled devices in the
    /// desktop's order and the others seen lately (`recent` says it of a device's last sighting, in
    /// unix time) by first sighting. What the wall's rule would drop from the full inventory is not
    /// copied, and the rest is: the wall built from this is the wall built from [`Devices::view`].
    pub fn wall_copy(&self, recent: &dyn Fn(u64) -> bool, out: &mut WallCopy) {
        let by_default = self.exempt_default();
        let (now, _) = (self.clock)();
        out.rows.clear();
        out.exempt_default = by_default;
        out.own_mac = self.own_mac;
        out.own_ip = self.own_ip;

        // The labels' places, by MAC, so that a device's is found by a search and not a scan.
        let labels = self.labels.get(..MAX_LABELS).unwrap_or(&self.labels);
        let mut ranked = [(Mac([0; 6]), 0u8); MAX_LABELS];
        for (slot, (rank, (mac, _))) in ranked.iter_mut().zip(labels.iter().enumerate()) {
            *slot = (*mac, u8::try_from(rank).unwrap_or(u8::MAX));
        }
        let ranked = &mut ranked[..labels.len()];
        ranked.sort_unstable();
        let rank_of = |mac: Mac| {
            ranked
                .binary_search_by_key(&mac, |&(held, _)| held)
                .ok()
                .map(|at| usize::from(ranked[at].1))
        };

        let mut front: Smallest<'_, WALL_ROWS> = Smallest::new();
        let mut always: Smallest<'_, WALL_ROWS> = Smallest::new();
        // The labelled devices are found from the labels, a few dozen lookups, and not by asking each of
        // the inventory's 512 devices whether it has one. The router and the Pi are left to the pass
        // below, which sees every device once.
        for (rank, (mac, _)) in labels.iter().enumerate() {
            if let Some(device) = self.devices.get(mac)
                && !self.is_always_device(*mac, device)
            {
                front.offer((0, rank as u64, *mac), device);
            }
        }
        for (&mac, device) in &self.devices {
            if self.is_always_device(mac, device) {
                always.offer((0, device.first_unix, mac), device);
                continue;
            }
            // An unlabelled device is checked against the labels only when its first sighting would
            // take a place: once the places are full of earlier ones that is rare.
            let key = (1, device.first_unix, mac);
            if front.accepts(key) && recent(device.last_unix) && rank_of(mac).is_none() {
                front.offer(key, device);
            }
        }

        // The wall puts the router and the Pi last, and the Pi's own place, if the inventory does
        // not hold it, among them; what is left of its places goes to the others.
        let pi_place = self
            .own_mac
            .is_some_and(|mac| !self.devices.contains_key(&mac));
        let tail = (always.len() + usize::from(pi_place)).min(WALL_ROWS);
        let room = WALL_ROWS - tail;
        for (mac, device) in always.first(tail).chain(front.first(room)) {
            let mut row = WallDevice {
                mac,
                ipv4: [Ipv4Addr::UNSPECIFIED; MAX_IPV4],
                ipv4_len: 0,
                hostname: Inline::EMPTY,
                label: Inline::EMPTY,
                first_unix: device.first_unix,
                last_unix: device.last_unix,
                label_rank: rank_of(mac),
                gate_left_secs: self
                    .gates
                    .get(&mac)
                    .and_then(|shuts| shuts.checked_sub(now))
                    .filter(|&left| left > 0)
                    .map(|left| u16::try_from(left).unwrap_or(MAX_GATE_SECS)),
                exempt: if by_default {
                    !self.held_blocked(mac) && !self.claims_router_or_pi(mac, device)
                } else {
                    self.is_exempt(mac) || self.gates.contains_key(&mac)
                },
                fixed: self.is_fixed(mac),
                always: self.is_always_device(mac, device),
            };
            // Newest first, as `view` has them.
            for (slot, ip) in row.ipv4.iter_mut().zip(device.ipv4.iter().rev()) {
                *slot = *ip;
                row.ipv4_len += 1;
            }
            row.hostname.set(device.hostname.as_deref());
            if let Some(rank) = row.label_rank {
                row.label
                    .set(self.labels.get(rank).map(|(_, label)| &**label));
            }
            out.rows.push(row);
        }
    }

    /// The inventory now, the device seen last first.
    pub fn view(&self) -> DevicesView {
        let by_default = self.exempt_default();
        let (now, _) = (self.clock)();
        let labels: HashMap<Mac, (usize, &Label)> = self
            .labels
            .iter()
            .enumerate()
            .map(|(rank, (mac, label))| (*mac, (rank, label)))
            .collect();
        let mut seen: Vec<(u64, DeviceView)> = self
            .devices
            .iter()
            .map(|(&mac, device)| {
                let gate_left = self
                    .gates
                    .get(&mac)
                    .and_then(|shuts| shuts.checked_sub(now))
                    .filter(|&left| left > 0)
                    .map(|left| u16::try_from(left).unwrap_or(MAX_GATE_SECS));
                let view = DeviceView {
                    mac,
                    ipv4: device.ipv4.iter().rev().copied().collect(),
                    hostname: device.hostname.clone(),
                    first_unix: device.first_unix,
                    last_unix: device.last_unix,
                    known: self.known.contains(&mac),
                    exempt: if by_default {
                        !self.held_blocked(mac) && !self.claims_router_or_pi(mac, device)
                    } else {
                        self.is_exempt(mac) || self.gates.contains_key(&mac)
                    },
                    blocked: self.is_blocked(mac),
                    label: labels.get(&mac).map(|&(_, label)| label.clone()),
                    label_rank: labels.get(&mac).map(|&(rank, _)| rank),
                    gate_left_secs: gate_left,
                    fixed: self.is_fixed(mac),
                    always: self.is_always(mac),
                };
                (device.seen, view)
            })
            .collect();
        seen.sort_unstable_by_key(|(seen, _)| std::cmp::Reverse(*seen));
        let mut exempt_macs: Vec<Mac> = self
            .exempt_config
            .union(&self.exempt_pushed)
            .copied()
            .collect();
        exempt_macs.sort_unstable();
        let mut block_macs: Vec<Mac> = self
            .block_config
            .union(&self.block_pushed)
            .copied()
            .collect();
        block_macs.sort_unstable();
        let sorted = |set: &HashSet<Mac>| {
            let mut macs: Vec<Mac> = set.iter().copied().collect();
            macs.sort_unstable();
            macs
        };
        DevicesView {
            rev: self.rev,
            known_list: self.state,
            devices: seen.into_iter().map(|(_, view)| view).collect(),
            exempt_macs,
            exempt_pushed: sorted(&self.exempt_pushed),
            exempt_default: by_default,
            block_macs,
            block_pushed: sorted(&self.block_pushed),
            own_mac: self.own_mac,
            own_ip: self.own_ip,
        }
    }

    /// How many new-device alerts were not held, because [`MAX_HELD`] were held already, since the
    /// start. The devices are not lost: a known list raises the ones in the inventory.
    pub fn dropped_holds(&self) -> u64 {
        self.dropped_holds
    }

    /// Takes the alerts that calls have made since the last time, oldest first. They are to be
    /// raised after the lock of the inventory is released, which [`with_devices`] does.
    pub fn take_alerts(&mut self) -> Vec<Alert> {
        std::mem::take(&mut self.pending)
    }

    /// How many alerts were dropped because [`MAX_PENDING`] waited already, since the start.
    pub fn dropped_alerts(&self) -> u64 {
        self.dropped_alerts
    }

    /// Lets `alert` wait to be taken, and says whether it will: with [`MAX_PENDING`] waiting
    /// already it is dropped and counted.
    fn queue(&mut self, alert: Alert) -> bool {
        if self.pending.len() >= MAX_PENDING {
            self.dropped_alerts += 1;
            return false;
        }
        self.pending.push(alert);
        true
    }

    /// Whether `mac` can be the address of a device: not all zeros, not a broadcast or multicast
    /// address, and not the Pi's own.
    fn is_device(&self, mac: Mac) -> bool {
        mac.can_be_a_device() && Some(mac) != self.own_mac
    }

    /// Whether `mac` is on an exempt list, the configuration's or the pushed one.
    fn is_exempt(&self, mac: Mac) -> bool {
        self.exempt_config.contains(&mac) || self.exempt_pushed.contains(&mac)
    }

    /// Whether `mac` is on a block list, the configuration's or the pushed one.
    fn is_blocked(&self, mac: Mac) -> bool {
        self.block_config.contains(&mac) || self.block_pushed.contains(&mac)
    }

    /// Whether `mac` is held fully blocked in the exempt-by-default mode: on the configuration's
    /// block list, or on the pushed one with no gate open.
    fn held_blocked(&self, mac: Mac) -> bool {
        self.block_config.contains(&mac)
            || (self.block_pushed.contains(&mac) && !self.gates.contains_key(&mac))
    }

    /// Whether the configuration's list of the mode in force names `mac`: the exempt list in the
    /// list mode, the block list in the exempt-by-default mode. Nothing but the configuration
    /// changes such a device.
    fn is_fixed(&self, mac: Mac) -> bool {
        if self.exempt_default() {
            self.block_config.contains(&mac)
        } else {
            self.exempt_config.contains(&mac)
        }
    }

    /// Whether `mac` is the Pi's own, or the router's, or a device in the inventory that claims
    /// the router's or the Pi's address: none of them is ever exempt.
    fn is_always(&self, mac: Mac) -> bool {
        Some(mac) == self.own_mac
            || Some(mac) == self.gateway_mac
            || self
                .devices
                .get(&mac)
                .is_some_and(|device| self.claims_router_or_pi(mac, device))
    }

    /// [`Devices::is_always`] for a device that is at hand, which saves its lookup.
    fn is_always_device(&self, mac: Mac, device: &Device) -> bool {
        Some(mac) == self.own_mac
            || Some(mac) == self.gateway_mac
            || self.claims_router_or_pi(mac, device)
    }

    /// Whether `mac` is on any of the four lists or has a gate open, so that an address it takes
    /// or leaves may change a published set.
    fn is_listed(&self, mac: Mac) -> bool {
        self.is_exempt(mac) || self.is_blocked(mac) || self.gates.contains_key(&mac)
    }

    /// Whether `ip` is the router's address or the Pi's own.
    fn is_router_or_pi(&self, ip: Ipv4Addr) -> bool {
        ip == self.gateway || Some(ip) == self.own_ip
    }

    /// Whether `device`, which is `mac`'s, claimed the router's address or the Pi's own last.
    fn claims_router_or_pi(&self, mac: Mac, device: &Device) -> bool {
        device
            .ipv4
            .iter()
            .any(|&ip| self.is_router_or_pi(ip) && self.by_ip.get(&ip) == Some(&mac))
    }

    /// The addresses that the devices of `macs` claimed last, as an iterator: each address of
    /// each of them that is in the inventory, and that no other device claimed after it.
    fn claimed_by<'a>(
        &'a self,
        macs: impl Iterator<Item = &'a Mac> + 'a,
    ) -> impl Iterator<Item = Ipv4Addr> + 'a {
        macs.filter_map(|mac| Some((mac, self.devices.get(mac)?)))
            .flat_map(move |(mac, device)| {
                device
                    .ipv4
                    .iter()
                    .copied()
                    .filter(move |ip| self.by_ip.get(ip) == Some(mac))
            })
    }

    /// The addresses that are exempt now, sorted, each once: each address of an exempt device in
    /// the inventory, or of one whose gate is open, that the device claimed last, but for the
    /// router's and the Pi's own, which are never exempt.
    fn exempt_now(&self) -> Vec<Ipv4Addr> {
        let mut addrs: Vec<Ipv4Addr> = self
            .claimed_by(
                self.exempt_config
                    .iter()
                    .chain(&self.exempt_pushed)
                    .chain(self.gates.keys()),
            )
            .filter(|&ip| !self.is_router_or_pi(ip))
            .collect();
        addrs.sort_unstable();
        addrs.dedup();
        addrs
    }

    /// The addresses that are fully blocked now, sorted, each once: the router's and the Pi's own,
    /// and each address of a device on a block list in the inventory that the device claimed
    /// last, but for a device of the pushed list whose gate is open. The router's and the Pi's
    /// come first, so that a cut of the set could never drop them.
    fn blocked_now(&self) -> Vec<Ipv4Addr> {
        let mut addrs: Vec<Ipv4Addr> = [Some(self.gateway), self.own_ip]
            .into_iter()
            .flatten()
            .chain(
                self.claimed_by(
                    self.block_config
                        .iter()
                        .chain(&self.block_pushed)
                        .filter(|&&mac| self.held_blocked(mac)),
                ),
            )
            .collect();
        addrs.sort_unstable();
        addrs.dedup();
        addrs
    }

    /// Works out the exempt and the fully blocked addresses again, and publishes each set that
    /// changed, and the count of the addresses that are not blocked. It looks at the devices of
    /// the four lists and the gates alone, at most 320 of four addresses each.
    fn refresh_exempt(&mut self) {
        let now = self.exempt_now();
        if now != self.exempt_published {
            self.exemption.listed().replace(&now);
            self.exempt_published = now;
        }
        let now = self.blocked_now();
        if now != self.blocked_published {
            self.exemption.blocked().replace(&now);
            self.blocked_published = now;
        }
        self.publish_unblocked();
    }

    /// Publishes how many addresses of the index are not fully blocked: each address that a
    /// device claimed last counts once. It looks up the blocked addresses alone, at most 514.
    fn publish_unblocked(&self) {
        let blocked = self
            .blocked_published
            .iter()
            .filter(|ip| self.by_ip.contains_key(ip))
            .count();
        self.exemption
            .set_unblocked(self.by_ip.len().saturating_sub(blocked));
    }

    /// Publishes the mode in force.
    fn publish_mode(&self) {
        self.exemption.set_by_default(self.exempt_default());
    }

    /// Fixes the gateway's MAC on the first ARP that claims its address from an address that can
    /// be a device's, and raises `arp_spoof` for each later one that claims it from another MAC,
    /// whatever that is, the Pi's own included. The fixed MAC is never replaced.
    fn check_gateway(&mut self, arp: &Arp) {
        if arp.sender_ip != self.gateway {
            return;
        }
        match self.gateway_mac {
            None => {
                if self.is_device(arp.sender_mac) {
                    self.gateway_mac = Some(arp.sender_mac);
                }
            }
            Some(fixed) if fixed != arp.sender_mac => {
                self.queue(Alert {
                    kind: ARP_SPOOF,
                    severity: Severity::High,
                    client: Some(IpAddr::V4(self.gateway)),
                    subject: arp.sender_mac.to_string(),
                });
            }
            Some(_) => {}
        }
    }

    /// Notes a sighting of the device `mac`, with an address and a host name if the message gave
    /// them: it is made if it is new, and then judged by the new-device rule.
    fn see(&mut self, mac: Mac, ip: Option<Ipv4Addr>, hostname: Option<&str>) {
        if !self.is_device(mac) {
            return;
        }
        // The published addresses change only if the address passes to this device from another,
        // and this one or the one before it is on a list, or a device that leaves the inventory is
        // (which `forget` sees to). An address that the device claimed last already is in its
        // list, so claiming it again changes nothing, which is the usual case. Any new claim may
        // change the count of the addresses that are not blocked.
        let (claimed, listed_touched) = match ip.map(|ip| self.by_ip.get(&ip)) {
            None => (false, false),
            Some(Some(&before)) if before == mac => (false, false),
            Some(before) => (
                true,
                self.is_listed(mac) || before.is_some_and(|&before| self.is_listed(before)),
            ),
        };
        let (mono, unix) = (self.clock)();
        self.first_seen.get_or_insert(mono);
        self.sightings += 1;
        if !self.devices.contains_key(&mac) && self.devices.len() >= MAX_DEVICES {
            self.evict_least_recent();
        }
        let device = self.devices.entry(mac).or_insert_with(|| Device {
            ipv4: Vec::new(),
            hostname: None,
            first_unix: unix,
            last_unix: unix,
            seen: 0,
            alerted_at: None,
            hold_dropped: false,
        });
        device.last_unix = unix;
        device.seen = self.sightings;
        if let Some(name) = hostname
            && !name.is_empty()
            && name.len() <= HOSTNAME_MAX
        {
            device.hostname = Some(name.to_owned());
        }
        if let Some(ip) = ip {
            // An address seen again becomes the newest; a fifth one pushes the oldest out.
            if let Some(at) = device.ipv4.iter().position(|&known| known == ip) {
                device.ipv4.remove(at);
            } else if device.ipv4.len() >= MAX_IPV4 {
                let oldest = device.ipv4.remove(0);
                if self.by_ip.get(&oldest) == Some(&mac) {
                    self.by_ip.remove(&oldest);
                }
            }
            device.ipv4.push(ip);
            self.by_ip.insert(ip, mac);
        }
        if listed_touched {
            self.refresh_exempt();
        } else if claimed {
            self.publish_unblocked();
        }
        self.judge(mac);
    }

    /// Applies the new-device rule to `mac`, which is in the inventory: a device that is known is
    /// left alone, and so is one that was alerted within [`REALERT_AFTER_SECS`]; one that is not
    /// is held while no known list has come, and raised otherwise.
    fn judge(&mut self, mac: Mac) {
        if self.known.contains(&mac) {
            return;
        }
        match self.state {
            KnownList::Waiting => {
                let Some(device) = self.devices.get_mut(&mac) else {
                    return;
                };
                if device.alerted_at.is_some() || device.hold_dropped || self.held.contains(&mac) {
                    return;
                }
                if self.held.len() < MAX_HELD {
                    self.held.push(mac);
                } else {
                    device.hold_dropped = true;
                    self.dropped_holds += 1;
                }
            }
            KnownList::Received | KnownList::Learned => {
                let (mono, _) = (self.clock)();
                let due = self.devices.get(&mac).is_some_and(|device| {
                    device
                        .alerted_at
                        .is_none_or(|at| mono >= at.saturating_add(REALERT_AFTER_SECS))
                });
                if due {
                    self.raise_new_device(mac);
                }
            }
        }
    }

    /// Decides the held alerts against the known set as it is now: those for MACs on it are
    /// dropped and the others raised, then every device in the inventory that is not on it and was
    /// never alerted is raised too, the one seen first first.
    fn raise_unknown(&mut self) {
        for mac in std::mem::take(&mut self.held) {
            if !self.known.contains(&mac) {
                self.raise_new_device(mac);
            }
        }
        let mut unlisted: Vec<(u64, Mac)> = self
            .devices
            .iter()
            .filter(|(mac, device)| device.alerted_at.is_none() && !self.known.contains(mac))
            .map(|(&mac, device)| (device.seen, mac))
            .collect();
        unlisted.sort_unstable();
        for (_, mac) in unlisted {
            self.raise_new_device(mac);
        }
    }

    /// Makes the `new_device` alert for `mac`, which has no client: the MAC alone is its key. It
    /// notes the time on the device if the alert is kept for the caller.
    fn raise_new_device(&mut self, mac: Mac) {
        let (mono, _) = (self.clock)();
        let kept = self.queue(Alert {
            kind: NEW_DEVICE,
            severity: Severity::Warn,
            client: None,
            subject: mac.to_string(),
        });
        // An alert that was dropped for lack of room is not one that was raised: the device is
        // judged again when it is next seen.
        if kept && let Some(device) = self.devices.get_mut(&mac) {
            device.alerted_at = Some(mono);
        }
    }

    /// Takes the device seen longest ago out of the inventory.
    fn evict_least_recent(&mut self) {
        let oldest = self
            .devices
            .iter()
            .min_by_key(|(_, device)| device.seen)
            .map(|(&mac, _)| mac);
        if let Some(mac) = oldest {
            self.forget(mac);
        }
    }

    /// Takes `mac` out of the inventory, and the addresses that lead to it out of the index and,
    /// if it is on a list, out of the published sets.
    fn forget(&mut self, mac: Mac) {
        if let Some(device) = self.devices.remove(&mac) {
            for ip in device.ipv4 {
                if self.by_ip.get(&ip) == Some(&mac) {
                    self.by_ip.remove(&ip);
                }
            }
            if self.is_listed(mac) {
                self.refresh_exempt();
            } else {
                self.publish_unblocked();
            }
        }
    }
}

/// The first `cap` different MACs of `macs`.
fn first_different(macs: Vec<Mac>, cap: usize) -> HashSet<Mac> {
    let mut set = HashSet::new();
    for mac in macs {
        if set.len() >= cap {
            break;
        }
        set.insert(mac);
    }
    set
}

/// Calls `call` with the inventory locked, then raises the alerts that it made through `sink`
/// after the lock is released, and gives what `call` gave.
///
/// A lock that a panic poisoned still guards an inventory whose bounds hold at every step, so it
/// is taken as it is. `call` is not to wait, and the sink is never called with the lock held.
pub fn with_devices<R>(
    devices: &Mutex<Devices>,
    sink: &dyn AlertSink,
    call: impl FnOnce(&mut Devices) -> R,
) -> R {
    let (result, alerts) = {
        let mut inventory = devices.lock().unwrap_or_else(PoisonError::into_inner);
        let result = call(&mut inventory);
        (result, inventory.take_alerts())
    };
    for alert in alerts {
        sink.raise(alert);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::dns::exempt::AddrSet;

    use std::ops::{Deref, DerefMut};
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::dns::testutil::Raised;

    /// The unix time of the fake clock's zero.
    const UNIX_START: u64 = 1_800_000_000;

    /// A clock that the test moves: the monotonic seconds, from 1000, and the unix seconds that
    /// go with them.
    #[derive(Clone)]
    struct FakeClock(Arc<AtomicU64>);

    impl FakeClock {
        fn new() -> Self {
            Self(Arc::new(AtomicU64::new(1000)))
        }

        fn advance(&self, secs: u64) {
            self.0.fetch_add(secs, Ordering::Relaxed);
        }

        fn as_clock(&self) -> Clock {
            let now = Arc::clone(&self.0);
            Arc::new(move || {
                let mono = now.load(Ordering::Relaxed);
                (mono, UNIX_START + (mono - 1000))
            })
        }
    }

    /// An inventory that also keeps what it was asked to raise, as the tests read it: `raised`
    /// takes the alerts that are waiting, and gives all that were taken so far.
    struct Rig {
        /// What is under test.
        inner: Devices,
        /// The alerts taken so far, as (kind, severity, client, subject).
        seen: Vec<Raised>,
    }

    impl Rig {
        /// A rig around `inner`.
        fn around(inner: Devices) -> Self {
            Rig {
                inner,
                seen: Vec::new(),
            }
        }

        /// Takes the alerts that wait, and gives every one taken so far, in order.
        fn raised(&mut self) -> Vec<Raised> {
            for alert in self.inner.take_alerts() {
                let severity = match alert.severity {
                    Severity::Info => "info",
                    Severity::Warn => "warn",
                    Severity::High => "high",
                };
                self.seen
                    .push((alert.kind, severity, alert.client, alert.subject));
            }
            self.seen.clone()
        }
    }

    impl Deref for Rig {
        type Target = Devices;

        fn deref(&self) -> &Devices {
            &self.inner
        }
    }

    impl DerefMut for Rig {
        fn deref_mut(&mut self) -> &mut Devices {
            &mut self.inner
        }
    }

    /// An inventory for a network whose router is 192.0.2.1, and the clock it uses.
    fn setup() -> (Rig, FakeClock) {
        let clock = FakeClock::new();
        let devices = Devices::new(Some(own()), ip(1), clock.as_clock());
        (Rig::around(devices), clock)
    }

    /// The MAC `02:00:00:00:00:<last>`.
    fn mac(last: u8) -> Mac {
        Mac([2, 0, 0, 0, 0, last])
    }

    /// The Pi's own MAC, which none of the `mac` and `mac2` ones is.
    fn own() -> Mac {
        Mac([2, 0, 0, 0xee, 0, 0xee])
    }

    /// The MAC `02:00:00:00:<high>:<low>`, for a test with many devices.
    fn mac2(n: u16) -> Mac {
        let [high, low] = n.to_be_bytes();
        Mac([2, 0, 0, 0, high, low])
    }

    /// The address 192.0.2.`host`.
    fn ip(host: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, host)
    }

    /// An ARP message from `mac` with the address `ip`.
    fn arp(mac: Mac, ip: Ipv4Addr) -> Arp {
        Arp {
            op: 1,
            sender_mac: mac,
            sender_ip: ip,
            target_ip: ip,
        }
    }

    /// A DHCP message of `msg_type` from `chaddr`.
    fn dhcp(
        msg_type: u8,
        chaddr: Mac,
        requested: Option<Ipv4Addr>,
        ciaddr: Ipv4Addr,
        hostname: Option<&str>,
    ) -> Dhcp {
        Dhcp {
            msg_type: Some(msg_type),
            chaddr,
            ciaddr,
            requested_ip: requested,
            hostname: hostname.map(str::to_owned),
        }
    }

    /// The alert a new device `mac` makes: it has no client, whatever address it has.
    fn new_device(mac: Mac) -> Raised {
        ("new_device", "warn", None, mac.to_string())
    }

    /// The alert a claim of the gateway's address from `mac` makes.
    fn spoof(mac: Mac) -> Raised {
        (
            "arp_spoof",
            "high",
            Some(IpAddr::V4(ip(1))),
            mac.to_string(),
        )
    }

    #[test]
    fn the_three_sources_make_one_device() {
        let (mut devices, clock) = setup();
        devices.on_arp(&arp(mac(5), ip(5)));
        clock.advance(7);
        devices.on_dhcp(&dhcp(
            DHCP_REQUEST,
            mac(5),
            Some(ip(6)),
            Ipv4Addr::UNSPECIFIED,
            Some("laptop"),
        ));
        clock.advance(3);
        devices.on_mdns(ip(5), "laptop-mdns");
        devices.on_arp(&arp(mac(9), ip(9)));
        let view = devices.view();
        assert_eq!(view.devices.len(), 2);
        let laptop = view.devices.iter().find(|d| d.mac == mac(5)).unwrap();
        assert_eq!(laptop.ipv4, [ip(6), ip(5)]);
        assert_eq!(laptop.hostname.as_deref(), Some("laptop-mdns"));
        assert_eq!(laptop.first_unix, UNIX_START);
        assert_eq!(laptop.last_unix, UNIX_START + 7);
        let other = view.devices.iter().find(|d| d.mac == mac(9)).unwrap();
        assert_eq!(other.ipv4, [ip(9)]);
        assert_eq!(other.hostname, None);
        assert_eq!(other.first_unix, UNIX_START + 10);
    }

    #[test]
    fn a_dhcp_message_uses_the_requested_address_or_else_the_one_it_has() {
        let (mut devices, _) = setup();
        let none = Ipv4Addr::UNSPECIFIED;
        devices.on_dhcp(&dhcp(DHCP_DISCOVER, mac(1), Some(ip(11)), none, None));
        devices.on_dhcp(&dhcp(DHCP_REQUEST, mac(2), None, ip(12), None));
        devices.on_dhcp(&dhcp(DHCP_REQUEST, mac(3), None, none, None));
        let view = devices.view();
        let of = |m: Mac| view.devices.iter().find(|d| d.mac == m).unwrap();
        assert_eq!(of(mac(1)).ipv4, [ip(11)]);
        assert_eq!(of(mac(2)).ipv4, [ip(12)]);
        assert_eq!(of(mac(3)).ipv4, Vec::<Ipv4Addr>::new());
    }

    #[test]
    fn a_dhcp_message_of_another_type_is_ignored() {
        let (mut devices, _) = setup();
        let mut offer = dhcp(2, mac(1), Some(ip(11)), Ipv4Addr::UNSPECIFIED, None);
        devices.on_dhcp(&offer);
        offer.msg_type = None;
        devices.on_dhcp(&offer);
        assert!(devices.view().devices.is_empty());
    }

    #[test]
    fn an_arp_probe_notes_the_device_and_gives_it_no_address() {
        let (mut devices, _) = setup();
        devices.on_arp(&arp(mac(5), Ipv4Addr::UNSPECIFIED));
        let view = devices.view();
        assert_eq!(view.devices.len(), 1);
        assert_eq!(view.devices[0].mac, mac(5));
        assert!(view.devices[0].ipv4.is_empty());
        // A later message with an address gives it one.
        devices.on_arp(&arp(mac(5), ip(5)));
        assert_eq!(devices.view().devices[0].ipv4, [ip(5)]);
    }

    #[test]
    fn an_mdns_name_for_an_address_that_no_device_has_is_ignored() {
        let (mut devices, _) = setup();
        devices.on_mdns(ip(5), "ghost");
        assert!(devices.view().devices.is_empty());
        devices.on_arp(&arp(mac(5), ip(5)));
        devices.on_mdns(ip(6), "ghost");
        assert_eq!(devices.view().devices[0].hostname, None);
        devices.on_mdns(ip(5), "printer");
        assert_eq!(
            devices.view().devices[0].hostname.as_deref(),
            Some("printer")
        );
        // An mDNS name does not count as a sighting.
        assert_eq!(devices.view().devices[0].last_unix, UNIX_START);
    }

    #[test]
    fn an_mdns_name_that_is_empty_or_too_long_is_ignored() {
        let (mut devices, _) = setup();
        devices.on_arp(&arp(mac(5), ip(5)));
        devices.on_mdns(ip(5), "");
        devices.on_mdns(ip(5), &"a".repeat(HOSTNAME_MAX + 1));
        assert_eq!(devices.view().devices[0].hostname, None);
        devices.on_mdns(ip(5), &"a".repeat(HOSTNAME_MAX));
        assert_eq!(
            devices.view().devices[0].hostname,
            Some("a".repeat(HOSTNAME_MAX))
        );
    }

    #[test]
    fn an_mdns_name_goes_to_the_device_that_has_the_address_now() {
        let (mut devices, _) = setup();
        devices.on_arp(&arp(mac(5), ip(5)));
        devices.on_arp(&arp(mac(6), ip(5)));
        devices.on_mdns(ip(5), "newer");
        let view = devices.view();
        let of = |m: Mac| view.devices.iter().find(|d| d.mac == m).unwrap();
        assert_eq!(of(mac(6)).hostname.as_deref(), Some("newer"));
        assert_eq!(of(mac(5)).hostname, None);
    }

    #[test]
    fn new_devices_are_held_until_a_known_list_and_then_raised_or_dropped() {
        let (mut devices, _) = setup();
        devices.on_arp(&arp(mac(5), ip(5)));
        devices.on_arp(&arp(mac(6), ip(6)));
        devices.on_arp(&arp(mac(7), ip(7)));
        assert_eq!(devices.view().known_list, KnownList::Waiting);
        assert_eq!(devices.raised(), []);

        // The list has the first device, and a MAC that has not been seen.
        assert_eq!(devices.set_known(vec![mac(5), mac(99)]), 2);
        assert_eq!(devices.view().known_list, KnownList::Received);
        assert_eq!(devices.raised(), [new_device(mac(6)), new_device(mac(7))]);
        let known: Vec<(u8, bool)> = devices
            .view()
            .devices
            .iter()
            .map(|d| (d.mac.0[5], d.known))
            .collect();
        assert_eq!(known, [(7, false), (6, false), (5, true)]);

        // Seen again: neither the known one nor the raised ones are raised again.
        devices.on_arp(&arp(mac(5), ip(5)));
        devices.on_arp(&arp(mac(6), ip(6)));
        assert_eq!(devices.raised().len(), 2);
        // A device that comes now is raised at once.
        devices.on_arp(&arp(mac(8), ip(8)));
        assert_eq!(devices.raised().len(), 3);
        assert_eq!(devices.raised()[2], new_device(mac(8)));
    }

    #[test]
    fn a_new_device_with_no_address_is_raised_like_any_other() {
        let (mut devices, _) = setup();
        devices.set_known(Vec::new());
        devices.on_arp(&arp(mac(5), Ipv4Addr::UNSPECIFIED));
        assert_eq!(devices.raised(), [new_device(mac(5))]);
    }

    #[test]
    fn a_held_device_is_raised_when_the_list_comes_without_a_client_whatever_addresses_it_had() {
        let (mut devices, _) = setup();
        devices.on_arp(&arp(mac(5), Ipv4Addr::UNSPECIFIED));
        devices.on_arp(&arp(mac(5), ip(5)));
        devices.on_arp(&arp(mac(5), ip(6)));
        assert_eq!(devices.raised(), []);
        devices.set_known(Vec::new());
        assert_eq!(devices.raised(), [new_device(mac(5))]);
    }

    #[test]
    fn an_empty_known_list_raises_every_device_that_was_seen() {
        let (mut devices, _) = setup();
        devices.on_arp(&arp(mac(5), ip(5)));
        devices.on_arp(&arp(mac(6), ip(6)));
        assert_eq!(devices.set_known(Vec::new()), 0);
        assert_eq!(devices.raised().len(), 2);
    }

    #[test]
    fn a_known_list_keeps_the_first_thousand_and_twenty_four_different_macs() {
        let (mut devices, _) = setup();
        let mut macs: Vec<Mac> = (0..2000).map(mac2).collect();
        macs.insert(5, mac2(0));
        assert_eq!(devices.set_known(macs), MAX_KNOWN);
        devices.on_arp(&arp(mac2(1023), ip(5)));
        devices.on_arp(&arp(mac2(1500), ip(6)));
        let view = devices.view();
        let known: Vec<bool> = view.devices.iter().map(|d| d.known).collect();
        // The one at 1500 came last, and is first in the view.
        assert_eq!(known, [false, true]);
    }

    #[test]
    fn the_inventory_learns_every_device_after_600_seconds_and_not_before() {
        let (mut devices, clock) = setup();
        devices.on_arp(&arp(mac(5), ip(5)));
        devices.on_arp(&arp(mac(6), ip(6)));
        clock.advance(599);
        devices.tick();
        assert_eq!(devices.view().known_list, KnownList::Waiting);
        clock.advance(1);
        devices.tick();
        let view = devices.view();
        assert_eq!(view.known_list, KnownList::Learned);
        assert_eq!(view.known_list.as_str(), "learned");
        assert!(view.devices.iter().all(|d| d.known));
        assert_eq!(devices.raised(), []);
        // The held alerts are gone: a late list that has the devices does not raise them.
        devices.set_known(vec![mac(5), mac(6)]);
        assert_eq!(devices.raised(), []);
        // A device that comes after the learning is raised at once.
        devices.on_arp(&arp(mac(7), ip(7)));
        assert_eq!(devices.raised(), [new_device(mac(7))]);
    }

    #[test]
    fn a_known_list_stops_the_learning() {
        let (mut devices, clock) = setup();
        devices.on_arp(&arp(mac(5), ip(5)));
        devices.set_known(vec![mac(5)]);
        clock.advance(10_000);
        devices.tick();
        let view = devices.view();
        assert_eq!(view.known_list, KnownList::Received);
        assert_eq!(view.known_list.as_str(), "received");
        assert_eq!(KnownList::Waiting.as_str(), "waiting");
        assert_eq!(devices.raised(), []);
    }

    #[test]
    fn a_late_list_raises_the_devices_it_does_not_list_that_were_never_alerted() {
        let (mut devices, clock) = setup();
        devices.on_arp(&arp(mac(5), ip(5)));
        devices.on_arp(&arp(mac(6), ip(6)));
        clock.advance(600);
        devices.tick();
        assert_eq!(devices.view().known_list, KnownList::Learned);
        // The owner's list has the first device only: the second was learned, and is now unlisted.
        devices.set_known(vec![mac(5)]);
        assert_eq!(devices.view().known_list, KnownList::Received);
        assert_eq!(devices.raised(), [new_device(mac(6))]);
        // Sending the list again raises nothing more.
        devices.set_known(vec![mac(5)]);
        assert_eq!(devices.raised().len(), 1);
    }

    #[test]
    fn a_device_is_raised_once_for_all_the_sightings_within_an_hour() {
        let (mut devices, _) = setup();
        devices.set_known(Vec::new());
        for _ in 0..5 {
            devices.on_arp(&arp(mac(5), ip(5)));
            devices.on_dhcp(&dhcp(
                DHCP_REQUEST,
                mac(5),
                Some(ip(5)),
                Ipv4Addr::UNSPECIFIED,
                None,
            ));
        }
        assert_eq!(devices.raised(), [new_device(mac(5))]);
        // Even if the same list is sent again, and even if it has other MACs.
        devices.set_known(vec![mac(9)]);
        assert_eq!(devices.raised().len(), 1);
    }

    #[test]
    fn a_device_that_left_the_inventory_may_be_raised_again_when_it_returns() {
        let (mut devices, _) = setup();
        devices.set_known(Vec::new());
        devices.on_arp(&arp(mac2(0), ip(5)));
        for n in 1..=MAX_DEVICES as u16 {
            devices.on_arp(&arp(mac2(n), ip(6)));
            // Taken as they come, as the callers take them: no more than 64 wait.
            devices.raised();
        }
        let before = devices.raised().len();
        assert_eq!(before, MAX_DEVICES + 1);
        devices.on_arp(&arp(mac2(0), ip(5)));
        assert_eq!(devices.raised().len(), before + 1);
    }

    #[test]
    fn an_arp_that_claims_the_gateway_from_another_mac_is_a_spoof() {
        let (mut devices, _) = setup();
        devices.set_known(vec![mac(2), mac(3)]);
        devices.on_arp(&arp(mac(2), ip(1)));
        devices.on_arp(&arp(mac(2), ip(1)));
        assert_eq!(devices.raised(), []);
        devices.on_arp(&arp(mac(3), ip(1)));
        assert_eq!(devices.raised(), [spoof(mac(3))]);
        // The same claim again is raised again: the store merges it.
        devices.on_arp(&arp(mac(3), ip(1)));
        assert_eq!(devices.raised(), [spoof(mac(3)), spoof(mac(3))]);
    }

    #[test]
    fn the_first_claim_of_the_gateway_fixes_its_mac_for_good() {
        let (mut devices, _) = setup();
        devices.set_known(vec![mac(2), mac(3), mac(4)]);
        devices.on_arp(&arp(mac(2), ip(1)));
        // A second MAC claims it: an alert, and the fixed MAC stays.
        devices.on_arp(&arp(mac(3), ip(1)));
        assert_eq!(devices.raised(), [spoof(mac(3))]);
        // The claimant does not become the gateway by being heard more, nor by being alone.
        devices.on_arp(&arp(mac(3), ip(1)));
        devices.on_arp(&arp(mac(4), ip(1)));
        assert_eq!(
            devices.raised(),
            [spoof(mac(3)), spoof(mac(3)), spoof(mac(4))]
        );
        // The original MAC is never raised.
        devices.on_arp(&arp(mac(2), ip(1)));
        assert_eq!(devices.raised().len(), 3);
    }

    #[test]
    fn a_claim_of_another_address_is_not_the_gateway() {
        let (mut devices, _) = setup();
        devices.set_known(vec![mac(2), mac(3)]);
        devices.on_arp(&arp(mac(2), ip(1)));
        devices.on_arp(&arp(mac(3), ip(2)));
        assert_eq!(devices.raised(), []);
    }

    #[test]
    fn a_spoof_is_raised_even_while_new_devices_are_held() {
        let (mut devices, _) = setup();
        devices.on_arp(&arp(mac(2), ip(1)));
        devices.on_arp(&arp(mac(3), ip(1)));
        assert_eq!(devices.raised(), [spoof(mac(3))]);
    }

    #[test]
    fn an_address_that_is_no_device_is_ignored() {
        let (mut devices, _) = setup();
        devices.set_known(Vec::new());
        // The Pi's own, all zeros, broadcast, and a multicast address.
        for bad in [
            own(),
            Mac([0; 6]),
            Mac([0xff; 6]),
            Mac([0x01, 0x00, 0x5e, 0, 0, 0xfb]),
        ] {
            devices.on_arp(&arp(bad, ip(5)));
            devices.on_dhcp(&dhcp(
                DHCP_REQUEST,
                bad,
                Some(ip(5)),
                Ipv4Addr::UNSPECIFIED,
                Some("x"),
            ));
        }
        assert!(devices.view().devices.is_empty());
        assert_eq!(devices.raised(), []);
        // None of them fixes the gateway either: the first good claim does.
        for bad in [own(), Mac([0; 6]), Mac([0xff; 6])] {
            devices.on_arp(&arp(bad, ip(1)));
        }
        devices.on_arp(&arp(mac(2), ip(1)));
        devices.on_arp(&arp(mac(3), ip(1)));
        let spoofs: Vec<Raised> = devices
            .raised()
            .into_iter()
            .filter(|a| a.0 == "arp_spoof")
            .collect();
        assert_eq!(spoofs, [spoof(mac(3))]);
    }

    #[test]
    fn the_own_mac_can_be_set_late_and_leaves_the_inventory() {
        let clock = FakeClock::new();
        let mut devices = Rig::around(Devices::new(None, ip(1), clock.as_clock()));
        devices.on_arp(&arp(own(), ip(5)));
        devices.on_arp(&arp(mac(6), ip(6)));
        assert_eq!(devices.view().devices.len(), 2);
        devices.set_own_mac(own());
        assert_eq!(devices.view().devices.len(), 1);
        devices.on_arp(&arp(own(), ip(5)));
        assert_eq!(devices.view().devices.len(), 1);
        // The held alert of the own MAC went with it.
        devices.set_known(Vec::new());
        assert_eq!(devices.raised(), [new_device(mac(6))]);
        // And its address is no longer there for an mDNS name.
        devices.on_mdns(ip(5), "pi");
        assert_eq!(devices.view().devices[0].hostname, None);
    }

    #[test]
    fn the_513th_device_pushes_out_the_one_seen_longest_ago() {
        let (mut devices, _) = setup();
        for n in 0..MAX_DEVICES as u16 {
            devices.on_arp(&arp(mac2(n), ip(5)));
        }
        // The first one is seen again, so the second is now the oldest.
        devices.on_arp(&arp(mac2(0), ip(5)));
        assert_eq!(devices.view().devices.len(), MAX_DEVICES);
        devices.on_arp(&arp(mac2(MAX_DEVICES as u16), ip(5)));
        let view = devices.view();
        assert_eq!(view.devices.len(), MAX_DEVICES);
        let macs: HashSet<Mac> = view.devices.iter().map(|d| d.mac).collect();
        assert!(!macs.contains(&mac2(1)));
        assert!(macs.contains(&mac2(0)));
        assert!(macs.contains(&mac2(2)));
        assert!(macs.contains(&mac2(MAX_DEVICES as u16)));
    }

    #[test]
    fn a_device_that_is_pushed_out_takes_its_addresses_from_the_index() {
        let (mut devices, _) = setup();
        devices.on_arp(&arp(mac2(0), ip(5)));
        for n in 1..=MAX_DEVICES as u16 {
            devices.on_arp(&arp(mac2(n), ip(6)));
        }
        devices.on_mdns(ip(5), "gone");
        assert!(devices.view().devices.iter().all(|d| d.hostname.is_none()));
    }

    #[test]
    fn a_device_keeps_four_addresses_and_the_fifth_pushes_out_the_oldest() {
        let (mut devices, _) = setup();
        for host in 10..=14 {
            devices.on_arp(&arp(mac(5), ip(host)));
        }
        assert_eq!(
            devices.view().devices[0].ipv4,
            [ip(14), ip(13), ip(12), ip(11)]
        );
        // An address seen again is the newest, and so the next one out is the one after it.
        devices.on_arp(&arp(mac(5), ip(11)));
        devices.on_arp(&arp(mac(5), ip(15)));
        assert_eq!(
            devices.view().devices[0].ipv4,
            [ip(15), ip(11), ip(14), ip(13)]
        );
        // The address that went is no way to an mDNS name any more.
        devices.on_mdns(ip(12), "old");
        assert_eq!(devices.view().devices[0].hostname, None);
        devices.on_mdns(ip(13), "kept");
        assert_eq!(devices.view().devices[0].hostname.as_deref(), Some("kept"));
    }

    #[test]
    fn the_65th_held_alert_is_dropped_and_counted_and_a_list_raises_the_device_anyway() {
        let (mut devices, _) = setup();
        for n in 0..65u16 {
            devices.on_arp(&arp(mac2(n), ip(5)));
        }
        // Seen again, it is counted once.
        devices.on_arp(&arp(mac2(64), ip(5)));
        assert_eq!(devices.dropped_holds(), 1);
        assert_eq!(devices.held.len(), MAX_HELD);
        assert_eq!(devices.raised(), []);
        devices.set_known(Vec::new());
        // The 64 that were held fill the room for alerts; the one that was not is in the inventory
        // and is not alerted yet.
        assert_eq!(devices.raised().len(), MAX_HELD);
        assert_eq!(devices.dropped_alerts(), 1);
        // The next list raises it, with room now.
        devices.set_known(Vec::new());
        let raised = devices.raised();
        assert_eq!(raised.len(), 65);
        assert_eq!(raised[64].3, mac2(64).to_string());
        devices.set_known(Vec::new());
        assert_eq!(devices.raised().len(), 65);
    }

    #[test]
    fn the_alerts_wait_inside_the_inventory_until_they_are_taken_oldest_first() {
        let (mut devices, _) = setup();
        devices.set_known(Vec::new());
        devices.on_arp(&arp(mac(5), ip(5)));
        devices.on_arp(&arp(mac(2), ip(1)));
        devices.on_arp(&arp(mac(3), ip(1)));
        devices.on_arp(&arp(mac(6), ip(6)));
        let taken: Vec<(&str, String)> = devices
            .take_alerts()
            .into_iter()
            .map(|alert| (alert.kind, alert.subject))
            .collect();
        let want = [
            ("new_device", mac(5)),
            ("new_device", mac(2)),
            ("arp_spoof", mac(3)),
            ("new_device", mac(3)),
            ("new_device", mac(6)),
        ]
        .map(|(kind, mac)| (kind, mac.to_string()));
        assert_eq!(taken, want);
        // Taken, they are gone.
        assert!(devices.take_alerts().is_empty());
    }

    #[test]
    fn the_65th_alert_that_waits_is_dropped_and_counted_and_its_device_is_judged_again() {
        let (mut devices, _) = setup();
        devices.set_known(Vec::new());
        for n in 0..70u16 {
            devices.on_arp(&arp(mac2(n), ip(5)));
        }
        assert_eq!(devices.pending.len(), MAX_PENDING);
        assert_eq!(devices.dropped_alerts(), 6);
        assert_eq!(devices.take_alerts().len(), MAX_PENDING);
        // The six that were dropped were not raised, so seeing them again raises them.
        for n in 0..70u16 {
            devices.on_arp(&arp(mac2(n), ip(5)));
        }
        let again: Vec<String> = devices
            .take_alerts()
            .into_iter()
            .map(|alert| alert.subject)
            .collect();
        let want: Vec<String> = (64..70u16).map(|n| mac2(n).to_string()).collect();
        assert_eq!(again, want);
        assert_eq!(devices.dropped_alerts(), 6);
    }

    #[test]
    fn the_sink_is_never_called_while_the_inventory_is_locked() {
        use std::sync::atomic::AtomicUsize;

        /// A sink that tries the lock of the inventory each time it is given an alert.
        struct Probe {
            devices: Arc<Mutex<Devices>>,
            given: AtomicUsize,
            while_locked: AtomicUsize,
        }

        impl AlertSink for Probe {
            fn raise(&self, _alert: Alert) {
                self.given.fetch_add(1, Ordering::Relaxed);
                if matches!(
                    self.devices.try_lock(),
                    Err(std::sync::TryLockError::WouldBlock)
                ) {
                    self.while_locked.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        let clock = FakeClock::new();
        let devices = Arc::new(Mutex::new(Devices::new(
            Some(own()),
            ip(1),
            clock.as_clock(),
        )));
        let probe = Probe {
            devices: devices.clone(),
            given: AtomicUsize::new(0),
            while_locked: AtomicUsize::new(0),
        };
        // Held alerts that a list raises, a device that is heard, and a spoof.
        for n in 5..8 {
            with_devices(&devices, &probe, |d| d.on_arp(&arp(mac(n), ip(n))));
        }
        assert_eq!(probe.given.load(Ordering::Relaxed), 0);
        let kept = with_devices(&devices, &probe, |d| d.set_known(vec![mac(5)]));
        assert_eq!(kept, 1);
        assert_eq!(probe.given.load(Ordering::Relaxed), 2);
        with_devices(&devices, &probe, |d| d.on_arp(&arp(mac(8), ip(8))));
        with_devices(&devices, &probe, |d| d.on_arp(&arp(mac(2), ip(1))));
        with_devices(&devices, &probe, |d| d.on_arp(&arp(mac(3), ip(1))));
        // The two on the first claim and the claim from another MAC, and the spoof.
        assert_eq!(probe.given.load(Ordering::Relaxed), 6);
        assert_eq!(probe.while_locked.load(Ordering::Relaxed), 0);
        // Nothing is left waiting inside, and a poisoned lock is taken as it is.
        assert!(devices.lock().unwrap().take_alerts().is_empty());
        let poisoner = devices.clone();
        let _ = std::thread::spawn(move || {
            let _held = poisoner.lock().unwrap();
            panic!("a holder of the lock panicked");
        })
        .join();
        assert!(devices.is_poisoned());
        with_devices(&devices, &probe, |d| d.on_arp(&arp(mac(9), ip(9))));
        assert_eq!(probe.given.load(Ordering::Relaxed), 7);
        assert_eq!(probe.while_locked.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn the_learning_counts_from_the_first_sighting_and_nothing_heard_is_nothing_learned() {
        let clock = FakeClock::new();
        let mut devices = Devices::new(None, ip(1), clock.as_clock());
        // An hour with nothing heard: nothing to learn, and the state stays as it is.
        clock.advance(3600);
        devices.tick();
        assert_eq!(devices.view().known_list, KnownList::Waiting);
        // A frame that is no device's does not start the window either.
        devices.on_arp(&arp(Mac([0; 6]), ip(5)));
        clock.advance(10_000);
        devices.tick();
        assert_eq!(devices.view().known_list, KnownList::Waiting);
        // The first device does: 600 s after it, and not before.
        devices.on_arp(&arp(mac(5), ip(5)));
        clock.advance(300);
        devices.on_arp(&arp(mac(6), ip(6)));
        clock.advance(299);
        devices.tick();
        assert_eq!(devices.view().known_list, KnownList::Waiting);
        clock.advance(1);
        devices.tick();
        let view = devices.view();
        assert_eq!(view.known_list, KnownList::Learned);
        assert!(view.devices.iter().all(|d| d.known));
        assert!(devices.take_alerts().is_empty());
    }

    #[test]
    fn a_new_device_alert_has_no_client_so_that_its_mac_is_its_whole_key() {
        let (mut devices, _) = setup();
        devices.set_known(Vec::new());
        // The same MAC at one address, then at another: one subject, and no client either time.
        devices.on_arp(&arp(mac(5), ip(5)));
        devices.on_arp(&arp(mac(6), ip(6)));
        devices.on_dhcp(&dhcp(
            DHCP_REQUEST,
            mac(5),
            Some(ip(7)),
            Ipv4Addr::UNSPECIFIED,
            None,
        ));
        let alerts = devices.take_alerts();
        assert_eq!(alerts.len(), 2);
        assert!(alerts.iter().all(|alert| alert.client.is_none()));
        // Held ones and ones a list raises are the same.
        let (mut held, _) = setup();
        held.on_arp(&arp(mac(5), ip(5)));
        held.set_known(Vec::new());
        assert!(
            held.take_alerts()
                .iter()
                .all(|alert| alert.client.is_none())
        );
    }

    #[test]
    fn a_device_that_stays_unknown_is_raised_again_once_an_hour_on_a_later_sighting() {
        let (mut devices, clock) = setup();
        devices.set_known(Vec::new());
        devices.on_arp(&arp(mac(5), ip(5)));
        assert_eq!(devices.take_alerts().len(), 1);
        // Seen as often as you like within the hour: nothing more.
        for _ in 0..10 {
            clock.advance(359);
            devices.on_arp(&arp(mac(5), ip(5)));
        }
        assert_eq!(devices.take_alerts().len(), 0);
        // At the hour, and with no sighting there is nothing to raise it on.
        clock.advance(10);
        assert_eq!(devices.take_alerts().len(), 0);
        devices.on_arp(&arp(mac(5), ip(5)));
        let again = devices.take_alerts();
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].subject, mac(5).to_string());
        // And the hour starts over from that raising.
        clock.advance(3599);
        devices.on_arp(&arp(mac(5), ip(5)));
        assert_eq!(devices.take_alerts().len(), 0);
        clock.advance(1);
        devices.on_arp(&arp(mac(5), ip(5)));
        assert_eq!(devices.take_alerts().len(), 1);
        // A device that came onto the list is not raised again.
        devices.set_known(vec![mac(5)]);
        clock.advance(7200);
        devices.on_arp(&arp(mac(5), ip(5)));
        assert_eq!(devices.take_alerts().len(), 0);
    }

    /// The MACs `02:00:00:00:00:<n>` for each `n` of `lasts`.
    fn macs(lasts: &[u8]) -> Vec<Mac> {
        lasts.iter().map(|&n| mac(n)).collect()
    }

    /// The MACs that the view calls known, as the last bytes, in order.
    fn known_lasts(devices: &Devices) -> Vec<u8> {
        let mut known: Vec<u8> = devices
            .view()
            .devices
            .iter()
            .filter(|d| d.known)
            .map(|d| d.mac.0[5])
            .collect();
        known.sort_unstable();
        known
    }

    #[test]
    fn a_known_list_in_chunks_decides_only_with_the_last_chunk() {
        let (mut devices, _) = setup();
        for n in 5..=9 {
            devices.on_arp(&arp(mac(n), ip(n)));
        }
        assert_eq!(devices.load_known(macs(&[5, 6]), false, false), 2);
        assert_eq!(devices.view().known_list, KnownList::Waiting);
        assert_eq!(devices.held.len(), 5);
        // The devices of an earlier chunk are heard again: nothing is raised, nothing decided.
        devices.on_arp(&arp(mac(5), ip(5)));
        assert_eq!(devices.load_known(macs(&[7]), true, false), 3);
        devices.on_arp(&arp(mac(6), ip(6)));
        assert_eq!(devices.view().known_list, KnownList::Waiting);
        assert_eq!(devices.raised(), []);
        // The last chunk decides: those that no chunk named are raised, and the rest are not.
        assert_eq!(devices.load_known(macs(&[8]), true, true), 4);
        assert_eq!(devices.view().known_list, KnownList::Received);
        assert_eq!(devices.raised(), [new_device(mac(9))]);
        assert_eq!(known_lasts(&devices), [5, 6, 7, 8]);
        // Heard again, none of them is raised.
        for n in 5..=9 {
            devices.on_arp(&arp(mac(n), ip(n)));
        }
        assert_eq!(devices.raised().len(), 1);
    }

    #[test]
    fn a_list_that_is_on_its_way_is_not_the_known_set_until_its_last_chunk_comes() {
        let (mut devices, _) = setup();
        for n in 5..=7 {
            devices.on_arp(&arp(mac(n), ip(n)));
        }
        devices.set_known(macs(&[5, 6, 7]));
        assert_eq!(devices.raised(), []);
        // A new list begins: the old set stays in force, and nobody it names is raised.
        assert_eq!(devices.load_known(macs(&[5]), false, false), 1);
        assert_eq!(known_lasts(&devices), [5, 6, 7]);
        for n in 5..=7 {
            devices.on_arp(&arp(mac(n), ip(n)));
        }
        assert_eq!(devices.raised(), []);
        // Another first chunk starts it over, and a list whose last chunk never comes is nothing.
        assert_eq!(devices.load_known(macs(&[6]), false, false), 1);
        assert_eq!(known_lasts(&devices), [5, 6, 7]);
        // A whole list comes after, and replaces both the set and what was on its way.
        assert_eq!(devices.set_known(macs(&[7])), 1);
        assert_eq!(known_lasts(&devices), [7]);
        assert_eq!(devices.raised().len(), 2);
        // What was on its way is gone: an adding chunk adds to the set that there is.
        assert_eq!(devices.load_known(macs(&[6]), true, true), 2);
        assert_eq!(known_lasts(&devices), [6, 7]);
    }

    #[test]
    fn the_last_chunk_replaces_the_set_with_the_whole_list_and_raises_what_it_leaves_out() {
        let (mut devices, _) = setup();
        for n in 5..=7 {
            devices.on_arp(&arp(mac(n), ip(n)));
        }
        devices.set_known(macs(&[5, 6, 7]));
        devices.load_known(macs(&[6]), false, false);
        assert_eq!(devices.load_known(macs(&[7]), true, true), 2);
        assert_eq!(known_lasts(&devices), [6, 7]);
        // The device that the whole list leaves out is new now.
        assert_eq!(devices.raised(), [new_device(mac(5))]);
    }

    #[test]
    fn a_chunk_that_adds_with_no_list_on_its_way_adds_to_the_known_set_and_decides_nothing_until_complete()
     {
        let (mut devices, _) = setup();
        devices.on_arp(&arp(mac(5), ip(5)));
        assert_eq!(devices.load_known(macs(&[1]), false, true), 1);
        assert_eq!(devices.view().known_list, KnownList::Received);
        devices.on_arp(&arp(mac(5), ip(5)));
        assert_eq!(devices.raised(), [new_device(mac(5))]);
        // Added at once, and not complete: the state is as it was, and 5 is not raised again.
        assert_eq!(devices.load_known(macs(&[2, 1]), true, false), 2);
        assert_eq!(devices.load_known(macs(&[3]), true, true), 3);
        assert_eq!(devices.raised().len(), 1);
        // Seen devices that the set has now are known.
        devices.on_arp(&arp(mac(3), ip(3)));
        assert_eq!(devices.raised().len(), 1);
    }

    #[test]
    fn the_cap_of_the_known_set_holds_across_chunks() {
        let (mut devices, _) = setup();
        let first: Vec<Mac> = (0..600).map(mac2).collect();
        let second: Vec<Mac> = (300..1300).map(mac2).collect();
        assert_eq!(devices.load_known(first, false, false), 600);
        assert_eq!(devices.load_known(second, true, false), MAX_KNOWN);
        assert_eq!(devices.load_known(vec![mac2(5000)], true, true), MAX_KNOWN);
        assert_eq!(devices.known.len(), MAX_KNOWN);
        assert!(!devices.known.contains(&mac2(5000)));
    }

    #[test]
    fn the_learning_keeps_what_chunks_of_a_list_already_put_in_the_set() {
        let (mut devices, clock) = setup();
        devices.on_arp(&arp(mac(5), ip(5)));
        // A chunk that adds, and no last chunk ever.
        devices.load_known(macs(&[9]), true, false);
        clock.advance(600);
        devices.tick();
        assert_eq!(devices.view().known_list, KnownList::Learned);
        assert!(devices.known.contains(&mac(5)));
        assert!(devices.known.contains(&mac(9)));
    }

    /// What the kept state of an inventory holds: pushed lists of 5 and 6 (exempt) and 7 (blocked),
    /// the exempt-by-default mode, two labels in an order that is not the MACs', and the known
    /// MACs 9 and 5.
    fn some_kept() -> SavedDevices {
        SavedDevices {
            exempt: macs(&[5, 6]),
            block: macs(&[7]),
            exempt_default: Some(true),
            labels: vec![(mac(6), label("Phone")), (mac(5), label("Desk PC"))],
            known: macs(&[5, 9]),
        }
    }

    #[test]
    fn what_is_kept_restores_into_another_inventory_and_is_kept_again_as_it_was() {
        let (mut first, _) = setup();
        first.set_exempt(macs(&[6, 5, 6]));
        first.set_policy(true, macs(&[7]));
        first.load_labels(
            vec![(mac(6), label("Phone")), (mac(5), label("Desk PC"))],
            false,
            true,
        );
        first.set_known(macs(&[9, 5]));
        let kept = first.kept();
        assert_eq!(kept, some_kept());

        let (mut second, _) = setup();
        second.restore(kept.clone());
        assert_eq!(second.kept(), kept);
        // A state with nothing pushed is kept as nothing, and the mode as none.
        let (empty, _) = setup();
        assert_eq!(empty.kept(), SavedDevices::default());
        assert_eq!(empty.kept().exempt_default, None);
        // The configuration's lists are not part of it.
        let (mut configured, _) = setup();
        configured.set_exempt_config(macs(&[5]));
        configured.set_block_config(macs(&[6]));
        configured.set_exempt_default_config(true);
        assert_eq!(configured.kept(), SavedDevices::default());
    }

    #[test]
    fn a_restored_state_is_what_a_push_would_have_made_of_the_view() {
        let (mut devices, _) = setup();
        devices.restore(some_kept());
        let view = devices.view();
        assert_eq!(view.exempt_pushed, macs(&[5, 6]));
        assert_eq!(view.block_pushed, macs(&[7]));
        assert!(view.exempt_default);
        hear_all(&mut devices, &[5, 6]);
        let view = devices.view();
        let label_of = |last: u8| {
            let device = view.devices.iter().find(|d| d.mac == mac(last)).unwrap();
            (
                device.label.as_deref().map(str::to_owned),
                device.label_rank,
            )
        };
        assert_eq!(label_of(6), (Some("Phone".into()), Some(0)));
        assert_eq!(label_of(5), (Some("Desk PC".into()), Some(1)));
    }

    #[test]
    fn a_restore_publishes_the_exempt_list_and_the_mode_to_the_dns_side() {
        let (mut devices, _, exemption) = exempt_setup();
        hear_all(&mut devices, &[5, 6, 7]);
        // The list mode: nothing pushed yet, nothing exempt.
        assert!(exempt_hosts(&exemption).is_empty() && !exemption.by_default());
        devices.restore(SavedDevices {
            exempt: macs(&[5, 6]),
            block: macs(&[7]),
            exempt_default: Some(false),
            ..SavedDevices::default()
        });
        assert_eq!(exempt_hosts(&exemption), [5, 6]);
        assert_eq!(blocked_hosts(&exemption), [1, 2, 7]);
        assert!(!exemption.by_default() && !devices.exempt_default());
        // The mode of a restored policy is the one in force, as a pushed one is.
        devices.restore(SavedDevices {
            exempt_default: Some(true),
            block: macs(&[7]),
            ..SavedDevices::default()
        });
        assert!(exemption.by_default() && devices.exempt_default());
        assert!(exempt_hosts(&exemption).is_empty());
        assert_eq!(blocked_hosts(&exemption), [1, 2, 7]);
        assert!(!exemption.is_exempt(IpAddr::V4(ip(7))));
        assert!(exemption.is_exempt(IpAddr::V4(ip(5))));
        // A restore of no policy gives the mode back to the configuration's.
        devices.restore(SavedDevices::default());
        assert!(!exemption.by_default());
        assert_eq!(blocked_hosts(&exemption), [1, 2]);
    }

    #[test]
    fn a_restore_leaves_the_known_list_waiting_and_raises_nothing() {
        let (mut devices, _) = setup();
        devices.restore(some_kept());
        let view = devices.view();
        assert_eq!(view.known_list, KnownList::Waiting);
        assert_eq!(view.known_list.as_str(), "waiting");
        // Nothing waits to be taken: a restore raises no alert.
        assert_eq!(devices.raised(), []);
        // The log lines that a push makes are still due for the first push.
        assert!(!devices.exempt_received && devices.policy_logged.is_none());
    }

    #[test]
    fn a_restored_known_device_is_never_held_or_raised() {
        let (mut devices, clock) = setup();
        devices.restore(SavedDevices {
            known: macs(&[5, 6]),
            ..SavedDevices::default()
        });
        devices.on_arp(&arp(mac(5), ip(5)));
        devices.on_arp(&arp(mac(6), ip(6)));
        assert!(devices.held.is_empty());
        assert!(devices.view().devices.iter().all(|d| d.known));
        // A newcomer is held, as before a list comes.
        devices.on_arp(&arp(mac(7), ip(7)));
        assert_eq!(devices.held, [mac(7)]);
        clock.advance(600);
        devices.tick();
        // Only the newcomer is raised.
        assert_eq!(devices.raised(), [new_device(mac(7))]);
    }

    #[test]
    fn with_a_restored_set_the_ten_minutes_raise_the_held_newcomers_and_do_not_learn_them() {
        let (mut devices, clock) = setup();
        devices.restore(SavedDevices {
            known: macs(&[5]),
            ..SavedDevices::default()
        });
        devices.on_arp(&arp(mac(5), ip(5)));
        devices.on_arp(&arp(mac(6), ip(6)));
        devices.on_arp(&arp(mac(7), ip(7)));
        clock.advance(599);
        devices.tick();
        assert_eq!(devices.view().known_list, KnownList::Waiting);
        assert_eq!(devices.raised(), []);
        clock.advance(1);
        devices.tick();
        assert_eq!(devices.view().known_list, KnownList::Learned);
        assert_eq!(devices.raised(), [new_device(mac(6)), new_device(mac(7))]);
        // They were not learned: the known set is the restored one.
        assert_eq!(devices.kept().known, macs(&[5]));
        let known: Vec<(u8, bool)> = {
            let mut list: Vec<_> = devices
                .view()
                .devices
                .iter()
                .map(|d| (d.mac.0[5], d.known))
                .collect();
            list.sort_unstable();
            list
        };
        assert_eq!(known, [(5, true), (6, false), (7, false)]);
        // The state is settled: later ticks do nothing, and a newcomer is raised at once.
        clock.advance(10_000);
        devices.tick();
        assert_eq!(devices.raised().len(), 2);
        devices.on_arp(&arp(mac(8), ip(8)));
        assert_eq!(devices.raised()[2], new_device(mac(8)));
    }

    #[test]
    fn with_no_restored_set_the_ten_minutes_learn_as_they_always_did() {
        // Nothing restored, and a restore that had no known set: the same.
        for restored in [false, true] {
            let (mut devices, clock) = setup();
            if restored {
                devices.restore(SavedDevices {
                    exempt: macs(&[5]),
                    labels: vec![(mac(5), label("Desk PC"))],
                    ..SavedDevices::default()
                });
            }
            devices.on_arp(&arp(mac(5), ip(5)));
            devices.on_arp(&arp(mac(6), ip(6)));
            clock.advance(600);
            devices.tick();
            assert_eq!(devices.view().known_list, KnownList::Learned);
            assert!(devices.view().devices.iter().all(|d| d.known));
            assert_eq!(devices.raised(), [], "restored: {restored}");
        }
    }

    #[test]
    fn a_list_from_the_desktop_after_a_restore_is_applied_as_any_list_is() {
        let (mut devices, clock) = setup();
        devices.restore(SavedDevices {
            known: macs(&[5]),
            ..SavedDevices::default()
        });
        devices.on_arp(&arp(mac(5), ip(5)));
        devices.on_arp(&arp(mac(6), ip(6)));
        // The desktop's list wins over the restored one, and stops the stand-in.
        assert_eq!(devices.set_known(macs(&[6])), 1);
        assert_eq!(devices.view().known_list, KnownList::Received);
        assert_eq!(devices.raised(), [new_device(mac(5))]);
        clock.advance(10_000);
        devices.tick();
        assert_eq!(devices.view().known_list, KnownList::Received);
        assert_eq!(devices.raised().len(), 1);
    }

    #[test]
    fn a_restore_is_capped_as_the_setters_cap() {
        let (mut devices, _) = setup();
        let mut exempt: Vec<Mac> = (0..100).map(mac2).collect();
        exempt.insert(3, mac2(0));
        devices.restore(SavedDevices {
            exempt,
            block: (0..100).map(mac2).collect(),
            labels: (0..100)
                .map(|n| (mac2(n % 70), label("x")))
                .collect::<Vec<_>>(),
            known: (0..2000).map(mac2).collect(),
            exempt_default: None,
        });
        let kept = devices.kept();
        assert_eq!(kept.exempt, (0..64).map(mac2).collect::<Vec<_>>());
        assert_eq!(kept.block, (0..64).map(mac2).collect::<Vec<_>>());
        assert_eq!(kept.labels.len(), MAX_LABELS);
        assert_eq!(kept.known.len(), MAX_KNOWN);
        // Each MAC of the labels is there once.
        let mut macs_of: Vec<Mac> = kept.labels.iter().map(|(mac, _)| *mac).collect();
        macs_of.sort_unstable();
        macs_of.dedup();
        assert_eq!(macs_of.len(), MAX_LABELS);
    }

    #[test]
    fn a_restore_moves_the_revision_only_when_it_changes_what_a_push_could_change() {
        let (mut devices, _) = setup();
        let start = devices.rev();
        // The known set alone is no part of the revision.
        devices.restore(SavedDevices {
            known: macs(&[5]),
            ..SavedDevices::default()
        });
        assert_eq!(devices.rev(), start);
        devices.restore(some_kept());
        assert_eq!(devices.rev(), start + 1);
        // The same again changes nothing.
        devices.restore(some_kept());
        assert_eq!(devices.rev(), start + 1);
        let mut other = some_kept();
        other.labels.reverse();
        devices.restore(other);
        assert_eq!(devices.rev(), start + 2);
    }

    /// An inventory for a network whose router is 192.0.2.1 and where the Pi is 192.0.2.2, the
    /// clock it uses, and the exempt set that it keeps for the DNS side.
    fn exempt_setup() -> (Rig, FakeClock, Arc<Exemption>) {
        let clock = FakeClock::new();
        let addrs = Arc::new(Exemption::new());
        let devices = Devices::new(Some(own()), ip(1), clock.as_clock())
            .with_exemption(addrs.clone())
            .with_own_ip(ip(2));
        (Rig::around(devices), clock, addrs)
    }

    /// The hosts `192.0.2.<host>` of the exempt set, in order, of those that can be in it here.
    fn exempt_hosts(exemption: &Exemption) -> Vec<u8> {
        hosts_of(exemption.listed())
    }

    /// The hosts `192.0.2.<host>` of `set`, in order.
    fn hosts_of(set: &AddrSet) -> Vec<u8> {
        (0..=255)
            .filter(|&host| set.contains(IpAddr::V4(ip(host))))
            .collect()
    }

    #[test]
    fn an_exempt_device_has_its_addresses_exempt_once_it_is_heard() {
        let (mut devices, _, addrs) = exempt_setup();
        // On the list but not heard yet: it has no address, and nothing is exempt.
        assert_eq!(devices.set_exempt(macs(&[5])), 1);
        assert!(addrs.listed().is_empty());
        devices.on_arp(&arp(mac(5), ip(5)));
        assert_eq!(exempt_hosts(&addrs), [5]);
        // A DHCP request for another address adds it; the first one is still the device's.
        devices.on_dhcp(&dhcp(
            DHCP_REQUEST,
            mac(5),
            Some(ip(6)),
            Ipv4Addr::UNSPECIFIED,
            None,
        ));
        assert_eq!(exempt_hosts(&addrs), [5, 6]);
        // A device that is not on the list is not exempt, and a probe adds no address.
        devices.on_arp(&arp(mac(7), ip(7)));
        devices.on_arp(&arp(mac(5), Ipv4Addr::UNSPECIFIED));
        assert_eq!(exempt_hosts(&addrs), [5, 6]);
    }

    #[test]
    fn an_address_that_another_device_claims_leaves_the_set_at_once() {
        let (mut devices, _, addrs) = exempt_setup();
        devices.set_exempt(macs(&[5]));
        devices.on_arp(&arp(mac(5), ip(5)));
        devices.on_arp(&arp(mac(6), ip(5)));
        assert!(addrs.listed().is_empty());
        // Claimed back, it is exempt again.
        devices.on_arp(&arp(mac(5), ip(5)));
        assert_eq!(exempt_hosts(&addrs), [5]);
        // A claim by DHCP counts as one by ARP does.
        devices.on_dhcp(&dhcp(
            DHCP_REQUEST,
            mac(6),
            Some(ip(5)),
            Ipv4Addr::UNSPECIFIED,
            None,
        ));
        assert!(addrs.listed().is_empty());
        // When the device that takes it over is exempt too, it stays in the set.
        devices.set_exempt_config(macs(&[6]));
        assert_eq!(exempt_hosts(&addrs), [5]);
        devices.on_arp(&arp(mac(5), ip(5)));
        assert_eq!(exempt_hosts(&addrs), [5]);
    }

    #[test]
    fn a_change_of_either_list_recomputes_the_set() {
        let (mut devices, _, addrs) = exempt_setup();
        for n in 5..=7 {
            devices.on_arp(&arp(mac(n), ip(n)));
        }
        assert!(addrs.listed().is_empty());
        devices.set_exempt(macs(&[5, 6]));
        assert_eq!(exempt_hosts(&addrs), [5, 6]);
        devices.set_exempt_config(macs(&[7]));
        assert_eq!(exempt_hosts(&addrs), [5, 6, 7]);
        // A pushed list replaces the pushed list and leaves the configuration's alone.
        devices.set_exempt(macs(&[6]));
        assert_eq!(exempt_hosts(&addrs), [6, 7]);
        assert_eq!(devices.set_exempt(Vec::new()), 0);
        assert_eq!(exempt_hosts(&addrs), [7]);
        devices.set_exempt_config(Vec::new());
        assert!(addrs.listed().is_empty());
    }

    #[test]
    fn the_view_tells_which_devices_are_exempt_and_lists_both_lists_sorted() {
        let (mut devices, _, _) = exempt_setup();
        devices.on_arp(&arp(mac(5), ip(5)));
        devices.on_arp(&arp(mac(6), ip(6)));
        devices.set_exempt_config(macs(&[9, 5]));
        // Duplicates collapse, and a MAC on both lists is listed once.
        assert_eq!(devices.set_exempt(macs(&[8, 5, 8])), 2);
        let view = devices.view();
        assert_eq!(view.exempt_macs, macs(&[5, 8, 9]));
        let exempt: Vec<(u8, bool)> = view
            .devices
            .iter()
            .map(|d| (d.mac.0[5], d.exempt))
            .collect();
        assert_eq!(exempt, [(6, false), (5, true)]);
        // Exemption says nothing about the known list.
        assert!(view.devices.iter().all(|d| !d.known));
    }

    #[test]
    fn each_list_keeps_its_first_64_different_macs() {
        let (mut devices, _, addrs) = exempt_setup();
        let many: Vec<Mac> = (0..70).map(mac2).collect();
        assert_eq!(devices.set_exempt(many.clone()), MAX_EXEMPT);
        devices.on_arp(&arp(mac2(63), ip(63)));
        devices.on_arp(&arp(mac2(64), ip(64)));
        assert_eq!(exempt_hosts(&addrs), [63]);
        // The configuration's list is held to the same, apart.
        let later: Vec<Mac> = (100..170).map(mac2).collect();
        assert_eq!(devices.set_exempt_config(later), MAX_EXEMPT);
        assert_eq!(devices.view().exempt_macs.len(), 2 * MAX_EXEMPT);
    }

    #[test]
    fn exemption_changes_no_alert() {
        let (mut devices, _, addrs) = exempt_setup();
        devices.set_exempt_config(macs(&[2, 3, 5]));
        devices.set_known(macs(&[2]));
        // An exempt device that is not known is new all the same.
        devices.on_arp(&arp(mac(5), ip(5)));
        assert_eq!(devices.raised(), [new_device(mac(5))]);
        // And an exempt device that claims the gateway is a spoof all the same.
        devices.on_arp(&arp(mac(2), ip(1)));
        devices.on_arp(&arp(mac(3), ip(1)));
        assert_eq!(
            devices.raised(),
            [new_device(mac(5)), spoof(mac(3)), new_device(mac(3))]
        );
        // The router's address is never exempt, whoever claims it.
        assert_eq!(exempt_hosts(&addrs), [5]);
    }

    #[test]
    fn the_routers_address_and_the_pis_own_are_never_exempt_whatever_mac_claims_them() {
        let (mut devices, _, addrs) = exempt_setup();
        devices.set_exempt(macs(&[5]));
        devices.on_arp(&arp(mac(5), ip(5)));
        // The exempt device claims the router's address, as a spoof would, and then the Pi's.
        devices.on_arp(&arp(mac(5), ip(1)));
        devices.on_dhcp(&dhcp(
            DHCP_REQUEST,
            mac(5),
            Some(ip(2)),
            Ipv4Addr::UNSPECIFIED,
            None,
        ));
        assert_eq!(devices.view().devices[0].ipv4, [ip(2), ip(1), ip(5)]);
        // Its own other address stays exempt, and the two never are.
        assert_eq!(exempt_hosts(&addrs), [5]);
        // A plain address that it claims later is added as ever.
        devices.on_arp(&arp(mac(5), ip(6)));
        assert_eq!(exempt_hosts(&addrs), [5, 6]);
        // A list that changes works the set out again the same way.
        devices.set_exempt(Vec::new());
        assert!(addrs.listed().is_empty());
        devices.set_exempt_config(macs(&[5]));
        assert_eq!(exempt_hosts(&addrs), [5, 6]);
        // An own address given after the device claimed it leaves the set at once.
        let clock = FakeClock::new();
        let late = Arc::new(Exemption::new());
        let mut devices =
            Devices::new(Some(own()), ip(1), clock.as_clock()).with_exemption(late.clone());
        devices.set_exempt(macs(&[5]));
        devices.on_arp(&arp(mac(5), ip(2)));
        devices.on_arp(&arp(mac(5), ip(5)));
        assert_eq!(exempt_hosts(&late), [2, 5]);
        let _devices = devices.with_own_ip(ip(2));
        assert_eq!(exempt_hosts(&late), [5]);
    }

    #[test]
    fn a_device_that_leaves_the_inventory_or_an_address_takes_it_out_of_the_set() {
        let (mut devices, _, addrs) = exempt_setup();
        devices.set_exempt(vec![mac2(0)]);
        // A fifth address pushes the oldest out of the device, and so out of the set.
        for host in 10..=14 {
            devices.on_arp(&arp(mac2(0), ip(host)));
        }
        assert_eq!(exempt_hosts(&addrs), [11, 12, 13, 14]);
        // Pushed out of the inventory by 512 later devices, it has no address at all.
        for n in 1..=MAX_DEVICES as u16 {
            devices.on_arp(&arp(mac2(n), ip(200)));
        }
        assert!(devices.view().devices.iter().all(|d| d.mac != mac2(0)));
        assert!(addrs.listed().is_empty());
        // Heard again, it is exempt again.
        devices.on_arp(&arp(mac2(0), ip(10)));
        assert_eq!(exempt_hosts(&addrs), [10]);
    }

    #[test]
    fn the_own_mac_and_addresses_that_are_no_device_are_never_exempt() {
        let (mut devices, _, addrs) = exempt_setup();
        devices.set_exempt(vec![own(), Mac([0xff; 6]), Mac([0; 6])]);
        devices.on_arp(&arp(own(), ip(5)));
        devices.on_arp(&arp(Mac([0xff; 6]), ip(6)));
        devices.on_arp(&arp(Mac([0; 6]), ip(7)));
        assert!(addrs.listed().is_empty());
    }

    #[test]
    fn the_set_is_read_while_the_inventory_is_locked() {
        let (mut devices, _, addrs) = exempt_setup();
        devices.set_exempt(macs(&[5]));
        devices.on_arp(&arp(mac(5), ip(5)));
        let inventory = Mutex::new(devices.inner);
        let _held = inventory.lock().unwrap();
        // The DNS side touches the set alone, never the inventory, so that lock holds nothing up.
        assert!(addrs.listed().contains(IpAddr::V4(ip(5))));
    }

    /// The hosts `192.0.2.<host>` of the fully blocked set, in order.
    fn blocked_hosts(exemption: &Exemption) -> Vec<u8> {
        hosts_of(exemption.blocked())
    }

    #[test]
    fn the_router_and_the_pi_are_fully_blocked_from_the_start_in_either_mode() {
        let (mut devices, _, exemption) = exempt_setup();
        assert!(!exemption.by_default());
        assert_eq!(blocked_hosts(&exemption), [1, 2]);
        devices.set_exempt_default_config(true);
        assert!(exemption.by_default() && devices.exempt_default());
        assert_eq!(blocked_hosts(&exemption), [1, 2]);
        // An own address given late joins the set at once, before any device is heard.
        let clock = FakeClock::new();
        let late = Arc::new(Exemption::new());
        let devices =
            Devices::new(Some(own()), ip(1), clock.as_clock()).with_exemption(late.clone());
        assert_eq!(blocked_hosts(&late), [1]);
        let _devices = devices.with_own_ip(ip(2));
        assert_eq!(blocked_hosts(&late), [1, 2]);
    }

    #[test]
    fn a_blocked_device_has_its_addresses_fully_blocked_once_heard_and_only_while_it_claims_them() {
        let (mut devices, _, exemption) = exempt_setup();
        devices.set_exempt_default_config(true);
        assert_eq!(devices.set_block_config(macs(&[5])), 1);
        // Not heard yet: no address of its own is blocked, so any client is exempt.
        assert!(exemption.is_exempt(IpAddr::V4(ip(5))));
        devices.on_arp(&arp(mac(5), ip(5)));
        assert_eq!(blocked_hosts(&exemption), [1, 2, 5]);
        assert!(!exemption.is_exempt(IpAddr::V4(ip(5))));
        assert!(!exemption.is_exempt(IpAddr::V6(ip(5).to_ipv6_mapped())));
        // Another device takes the address over: it is exempt at once, and back when reclaimed.
        devices.on_arp(&arp(mac(6), ip(5)));
        assert_eq!(blocked_hosts(&exemption), [1, 2]);
        assert!(exemption.is_exempt(IpAddr::V4(ip(5))));
        devices.on_dhcp(&dhcp(
            DHCP_REQUEST,
            mac(5),
            Some(ip(5)),
            Ipv4Addr::UNSPECIFIED,
            None,
        ));
        assert!(!exemption.is_exempt(IpAddr::V4(ip(5))));
        // A blocked device that moves to a new address takes the block with it; the old one,
        // still its own, stays blocked too.
        devices.on_arp(&arp(mac(5), ip(9)));
        assert_eq!(blocked_hosts(&exemption), [1, 2, 5, 9]);
        // Unknown devices, other addresses and IPv6 clients are exempt.
        devices.on_arp(&arp(mac(7), ip(7)));
        for client in [
            IpAddr::V4(ip(7)),
            IpAddr::V4(ip(100)),
            IpAddr::V6("2001:db8::5".parse().unwrap()),
        ] {
            assert!(exemption.is_exempt(client), "{client}");
        }
        // The router and the Pi are not, whoever claims them.
        devices.on_arp(&arp(mac(7), ip(2)));
        assert!(!exemption.is_exempt(IpAddr::V4(ip(1))));
        assert!(!exemption.is_exempt(IpAddr::V4(ip(2))));
        // Off the list, its addresses are exempt again.
        devices.set_block_config(Vec::new());
        assert_eq!(blocked_hosts(&exemption), [1, 2]);
    }

    #[test]
    fn a_pushed_policy_wins_over_the_configurations_mode_and_adds_to_its_block_list() {
        let (mut devices, _, exemption) = exempt_setup();
        for n in 5..=8 {
            devices.on_arp(&arp(mac(n), ip(n)));
        }
        devices.set_exempt_config(macs(&[5]));
        devices.set_block_config(macs(&[6]));
        // The list mode: only the exempt list counts, and the block list does nothing.
        assert!(exemption.is_exempt(IpAddr::V4(ip(5))));
        assert!(!exemption.is_exempt(IpAddr::V4(ip(7))));
        assert!(!exemption.is_exempt(IpAddr::V4(ip(6))));
        // A pushed policy turns the mode on at once; both block lists count, the exempt one not.
        assert_eq!(devices.set_policy(true, macs(&[7, 7, 9])), 2);
        assert!(exemption.by_default() && devices.exempt_default());
        assert_eq!(blocked_hosts(&exemption), [1, 2, 6, 7]);
        for (host, exempt) in [(5, true), (6, false), (7, false), (8, true), (9, true)] {
            assert_eq!(exemption.is_exempt(IpAddr::V4(ip(host))), exempt, "{host}");
        }
        // The pushed mode stays in force whatever the configuration's is set to later.
        devices.set_exempt_default_config(false);
        assert!(exemption.by_default());
        // A policy that turns it off goes back to the exempt list at once.
        assert_eq!(devices.set_policy(false, Vec::new()), 0);
        assert!(!exemption.by_default() && !devices.exempt_default());
        assert!(exemption.is_exempt(IpAddr::V4(ip(5))));
        assert!(!exemption.is_exempt(IpAddr::V4(ip(8))));
        // The pushed block list was replaced; the configuration's stays.
        assert_eq!(blocked_hosts(&exemption), [1, 2, 6]);
        assert_eq!(devices.view().block_macs, macs(&[6]));
    }

    #[test]
    fn the_view_tells_the_mode_the_block_lists_and_who_is_exempt_in_the_mode_in_force() {
        let (mut devices, _, _) = exempt_setup();
        devices.on_arp(&arp(mac(5), ip(5)));
        devices.on_arp(&arp(mac(6), ip(6)));
        devices.on_arp(&arp(mac(7), ip(1)));
        devices.set_exempt_config(macs(&[5]));
        devices.set_block_config(macs(&[9, 6]));
        devices.set_policy(false, macs(&[6, 8]));
        let flags = |view: &DevicesView| -> Vec<(u8, bool, bool)> {
            view.devices
                .iter()
                .map(|d| (d.mac.0[5], d.exempt, d.blocked))
                .collect()
        };
        // The list mode: exempt is the exempt list; blocked is the block list, all the same.
        let view = devices.view();
        assert!(!view.exempt_default);
        assert_eq!(view.block_macs, macs(&[6, 8, 9]));
        assert_eq!(view.exempt_macs, macs(&[5]));
        assert_eq!(
            flags(&view),
            [(7, false, false), (6, false, true), (5, true, false)]
        );
        // Exempt by default: all but the blocked device and the one that claims the router.
        devices.set_policy(true, macs(&[6, 8]));
        let view = devices.view();
        assert!(view.exempt_default);
        assert_eq!(
            flags(&view),
            [(7, false, false), (6, false, true), (5, true, false)]
        );
        devices.on_arp(&arp(mac(10), ip(10)));
        assert!(devices.view().devices[0].exempt);
        // The device that claimed the router's address loses it to another: it is exempt again.
        devices.on_arp(&arp(mac(11), ip(1)));
        let view = devices.view();
        let seven = view.devices.iter().find(|d| d.mac == mac(7)).unwrap();
        assert!(seven.exempt);
    }

    #[test]
    fn the_count_of_exempt_clients_follows_the_addresses_that_are_not_fully_blocked() {
        let (mut devices, _, exemption) = exempt_setup();
        devices.set_exempt_config(macs(&[5]));
        devices.set_block_config(macs(&[6]));
        for n in 5..=8 {
            devices.on_arp(&arp(mac(n), ip(n)));
        }
        // The list mode counts the exempt addresses.
        assert_eq!(exemption.exempt_clients(), 1);
        devices.set_exempt_default_config(true);
        // Exempt by default: .5, .7 and .8, not the blocked .6.
        assert_eq!(exemption.exempt_clients(), 3);
        // The router and the Pi, when heard, are not counted.
        devices.on_arp(&arp(mac(20), ip(1)));
        devices.on_arp(&arp(mac(21), ip(2)));
        assert_eq!(exemption.exempt_clients(), 3);
        // A new address counts, and one that passes to the blocked device stops counting.
        devices.on_arp(&arp(mac(7), ip(17)));
        assert_eq!(exemption.exempt_clients(), 4);
        devices.on_arp(&arp(mac(6), ip(17)));
        assert_eq!(exemption.exempt_clients(), 3);
        // A device pushed out of the inventory takes its addresses out of the count.
        for n in 100..100 + MAX_DEVICES as u16 {
            devices.on_arp(&arp(mac2(n), ip(250)));
        }
        assert_eq!(exemption.exempt_clients(), 1);
    }

    #[test]
    fn each_block_list_keeps_its_first_64_different_macs() {
        let (mut devices, _, exemption) = exempt_setup();
        let many: Vec<Mac> = (0..70).map(mac2).collect();
        assert_eq!(devices.set_policy(true, many.clone()), MAX_BLOCK);
        devices.on_arp(&arp(mac2(63), ip(63)));
        devices.on_arp(&arp(mac2(64), ip(64)));
        assert_eq!(blocked_hosts(&exemption), [1, 2, 63]);
        let later: Vec<Mac> = (100..170).map(mac2).collect();
        assert_eq!(devices.set_block_config(later), MAX_BLOCK);
        assert_eq!(devices.view().block_macs.len(), 2 * MAX_BLOCK);
        // Every address of every device on both lists fits the set, with the router and the Pi.
        let blocked: Vec<Mac> = (0..64).map(mac2).chain((100..164).map(mac2)).collect();
        for (n, &mac) in blocked.iter().enumerate() {
            for k in 0..MAX_IPV4 {
                let at = (n * MAX_IPV4 + k) as u16;
                devices.on_arp(&arp(mac, Ipv4Addr::new(198, 51, (at >> 8) as u8, at as u8)));
            }
        }
        assert_eq!(
            exemption.blocked().len(),
            2 * MAX_BLOCK * MAX_IPV4 + 2,
            "every blocked address is in the set"
        );
        assert!(!exemption.is_exempt(IpAddr::V4(ip(1))));
    }

    #[test]
    fn a_policy_is_logged_only_when_the_mode_or_the_number_of_blocked_devices_changes() {
        let (mut devices, _, _) = exempt_setup();
        devices.set_block_config(macs(&[6]));
        devices.set_policy(true, macs(&[5]));
        assert_eq!(devices.policy_logged, Some((true, 2)));
        // The same policy again tells nothing new.
        assert_eq!(devices.policy_news(), None);
        // In the list mode the number of blocked devices is not told, so a new list is no news.
        devices.set_policy(false, macs(&[5, 7]));
        assert_eq!(devices.policy_logged, Some((false, 0)));
        devices.set_policy(false, Vec::new());
        assert_eq!(devices.policy_news(), None);
        // The lines tell the mode and a count, and never a MAC.
        devices.policy_logged = None;
        assert_eq!(
            devices.policy_news().as_deref(),
            Some("watch: exemption policy received: exempt list only")
        );
        devices.set_policy(true, macs(&[5, 8]));
        devices.policy_logged = None;
        assert_eq!(
            devices.policy_news().as_deref(),
            Some("watch: exemption policy received: exempt by default, 3 blocked devices")
        );
    }

    #[test]
    fn the_view_lists_the_device_seen_last_first() {
        let (mut devices, clock) = setup();
        devices.on_arp(&arp(mac(1), ip(1 + 10)));
        devices.on_arp(&arp(mac(2), ip(2 + 10)));
        devices.on_arp(&arp(mac(3), ip(3 + 10)));
        let order =
            |d: &Devices| -> Vec<u8> { d.view().devices.iter().map(|v| v.mac.0[5]).collect() };
        assert_eq!(order(&devices), [3, 2, 1]);
        // In the same second, the order of sightings decides.
        devices.on_arp(&arp(mac(1), ip(11)));
        assert_eq!(order(&devices), [1, 3, 2]);
        clock.advance(5);
        devices.on_dhcp(&dhcp(DHCP_REQUEST, mac(2), None, ip(12), None));
        assert_eq!(order(&devices), [2, 1, 3]);
        assert_eq!(devices.view().devices[0].last_unix, UNIX_START + 5);
    }

    /// The label `text`.
    fn label(text: &str) -> Label {
        Label::new(text).unwrap()
    }

    /// The hosts `192.0.2.<host>` are devices `5..`: hears the devices `lasts`, each with the
    /// address `192.0.2.<last>`.
    fn hear_all(devices: &mut Devices, lasts: &[u8]) {
        for &last in lasts {
            devices.on_arp(&arp(mac(last), ip(last)));
        }
    }

    #[test]
    fn a_label_is_one_to_24_printable_ascii_characters_and_says_nothing_in_debug() {
        assert_eq!(Label::new("Desk PC").as_deref(), Some("Desk PC"));
        assert_eq!(Label::new(" a ").as_deref(), Some(" a "));
        assert!(Label::new("x").is_some());
        assert!(Label::new(&"x".repeat(LABEL_MAX)).is_some());
        for bad in [
            "",
            &"x".repeat(LABEL_MAX + 1),
            "caf\u{e9}",
            "tab\t",
            "line\nbreak",
            "bell\u{7}",
            "del\u{7f}",
            "\u{1f600}",
        ] {
            assert!(Label::new(bad).is_none(), "{bad:?}");
        }
        assert_eq!(format!("{:?}", label("Desk PC")), "Label(..)");
    }

    #[test]
    fn an_open_gate_makes_the_device_exempt_in_the_list_mode_until_it_expires() {
        let (mut devices, clock, addrs) = exempt_setup();
        hear_all(&mut devices, &[5, 6]);
        assert!(exempt_hosts(&addrs).is_empty());
        let rev = devices.rev();
        assert_eq!(devices.next_gate_deadline(), None);

        assert_eq!(devices.open_gate(mac(5), 300), Ok(()));
        // The sets are republished as for a list change: the device's address, and nobody else's.
        assert_eq!(exempt_hosts(&addrs), [5]);
        assert!(addrs.is_exempt(IpAddr::V4(ip(5))) && !addrs.is_exempt(IpAddr::V4(ip(6))));
        assert_eq!(devices.rev(), rev + 1);
        assert_eq!(devices.next_gate_deadline(), Some(1300));
        let view = devices.view();
        let of = |m: Mac| view.devices.iter().find(|d| d.mac == m).unwrap().clone();
        assert!(of(mac(5)).exempt && !of(mac(6)).exempt);
        assert_eq!(of(mac(5)).gate_left_secs, Some(300));
        assert_eq!(of(mac(6)).gate_left_secs, None);
        // It is on no list: a gate is no part of the lists the desktop sees.
        assert!(view.exempt_macs.is_empty() && view.exempt_pushed.is_empty());

        clock.advance(100);
        assert_eq!(devices.view().devices[1].gate_left_secs, Some(200));
        // Not due yet: nothing changes, and no revision moves.
        assert_eq!(devices.expire_gates(1299), 0);
        assert_eq!(exempt_hosts(&addrs), [5]);
        assert_eq!(devices.rev(), rev + 1);
        // Due: the gate shuts, the set is republished, and that is a change.
        assert_eq!(devices.expire_gates(1300), 1);
        assert!(exempt_hosts(&addrs).is_empty());
        assert_eq!(devices.rev(), rev + 2);
        assert_eq!(devices.next_gate_deadline(), None);
        let view = devices.view();
        assert!(
            view.devices
                .iter()
                .all(|d| !d.exempt && d.gate_left_secs.is_none())
        );
        assert_eq!(devices.expire_gates(5000), 0);
        assert_eq!(devices.rev(), rev + 2);
    }

    #[test]
    fn a_gate_on_a_device_that_is_exempt_already_shuts_without_taking_its_exemption() {
        let (mut devices, _, addrs) = exempt_setup();
        hear_all(&mut devices, &[5]);
        devices.set_exempt(macs(&[5]));
        assert_eq!(devices.open_gate(mac(5), 60), Ok(()));
        assert_eq!(devices.expire_gates(2000), 1);
        assert_eq!(exempt_hosts(&addrs), [5]);
        assert!(devices.view().devices[0].exempt);
    }

    #[test]
    fn an_open_gate_lifts_the_block_in_the_exempt_by_default_mode_and_shutting_it_puts_it_back() {
        let (mut devices, clock, addrs) = exempt_setup();
        hear_all(&mut devices, &[5, 6]);
        devices.set_policy(true, macs(&[5]));
        assert_eq!(blocked_hosts(&addrs), [1, 2, 5]);
        assert!(!addrs.is_exempt(IpAddr::V4(ip(5))));
        let view = devices.view();
        let five = view.devices.iter().find(|d| d.mac == mac(5)).unwrap();
        assert!(five.blocked && !five.exempt);

        let rev = devices.rev();
        assert_eq!(devices.open_gate(mac(5), 60), Ok(()));
        assert_eq!(blocked_hosts(&addrs), [1, 2]);
        assert!(addrs.is_exempt(IpAddr::V4(ip(5))));
        assert_eq!(devices.rev(), rev + 1);
        // It is still on the block list, and exempt for now.
        let view = devices.view();
        let five = view.devices.iter().find(|d| d.mac == mac(5)).unwrap();
        assert!(five.blocked && five.exempt);
        assert_eq!(five.gate_left_secs, Some(60));
        assert_eq!(view.block_pushed, [mac(5)]);

        // Shut by hand: blocked again at once, and shutting a shut gate changes nothing.
        assert_eq!(devices.shut_gate(mac(5)), Ok(()));
        assert_eq!(blocked_hosts(&addrs), [1, 2, 5]);
        assert_eq!(devices.rev(), rev + 2);
        assert_eq!(devices.shut_gate(mac(5)), Ok(()));
        assert_eq!(devices.rev(), rev + 2);

        // Shut by the clock: the same.
        assert_eq!(devices.open_gate(mac(5), 60), Ok(()));
        clock.advance(60);
        let now = devices.mono_now();
        assert_eq!(devices.expire_gates(now), 1);
        assert_eq!(blocked_hosts(&addrs), [1, 2, 5]);
        assert!(!addrs.is_exempt(IpAddr::V4(ip(5))));
        // The router and the Pi were blocked all the while.
        assert!(!addrs.is_exempt(IpAddr::V4(ip(1))) && !addrs.is_exempt(IpAddr::V4(ip(2))));
    }

    #[test]
    fn a_gate_is_refused_for_the_router_the_pi_a_fixed_device_and_what_is_not_listed() {
        let (mut devices, _, _) = exempt_setup();
        hear_all(&mut devices, &[1, 5, 6]);
        devices.set_exempt_config(macs(&[5]));
        let rev = devices.rev();
        // The MAC that claimed the router's address first is the router; the Pi is never listed.
        assert_eq!(devices.open_gate(mac(1), 60), Err(EditError::Always));
        assert_eq!(devices.open_gate(own(), 60), Err(EditError::Always));
        assert_eq!(devices.shut_gate(own()), Err(EditError::Always));
        // A device that claims the Pi's address is as little exempt.
        devices.on_arp(&arp(mac(6), ip(2)));
        assert_eq!(devices.open_gate(mac(6), 60), Err(EditError::Always));
        // The configuration's exempt list, in the list mode.
        assert_eq!(devices.open_gate(mac(5), 60), Err(EditError::Fixed));
        assert_eq!(devices.shut_gate(mac(5)), Err(EditError::Fixed));
        // Not in the inventory, shut or open.
        assert_eq!(devices.open_gate(mac(9), 60), Err(EditError::Unknown));
        assert_eq!(devices.shut_gate(mac(9)), Err(EditError::Unknown));
        // Too long, and no device's address.
        assert_eq!(devices.open_gate(mac(7), 3601), Err(EditError::Invalid));
        assert_eq!(
            devices.open_gate(Mac([3, 0, 0, 0, 0, 1]), 60),
            Err(EditError::Invalid)
        );
        assert_eq!(devices.open_gate(Mac([0; 6]), 60), Err(EditError::Invalid));
        assert_eq!(devices.rev(), rev);
        assert_eq!(devices.next_gate_deadline(), None);
        // An hour is the most.
        hear_all(&mut devices, &[7]);
        assert_eq!(devices.open_gate(mac(7), 3600), Ok(()));
        assert_eq!(devices.view().devices[0].gate_left_secs, Some(3600));
    }

    #[test]
    fn what_the_configuration_fixes_depends_on_the_mode_in_force() {
        let (mut devices, _, _) = exempt_setup();
        hear_all(&mut devices, &[5, 6]);
        devices.set_exempt_config(macs(&[5]));
        devices.set_block_config(macs(&[6]));
        let fixed = |d: &Devices| -> Vec<(u8, bool)> {
            let mut all: Vec<_> = d
                .view()
                .devices
                .iter()
                .map(|v| (v.mac.0[5], v.fixed))
                .collect();
            all.sort_unstable();
            all
        };
        // The list mode: the exempt list decides.
        assert_eq!(fixed(&devices), [(5, true), (6, false)]);
        assert_eq!(devices.open_gate(mac(6), 60), Ok(()));
        // The exempt-by-default mode: the block list decides.
        devices.set_policy(true, Vec::new());
        assert_eq!(fixed(&devices), [(5, false), (6, true)]);
        assert_eq!(devices.open_gate(mac(6), 60), Err(EditError::Fixed));
        assert_eq!(devices.open_gate(mac(5), 60), Ok(()));
    }

    #[test]
    fn at_most_64_gates_are_open_and_one_that_is_open_may_be_given_a_new_time() {
        let (mut devices, _, _) = exempt_setup();
        for n in 0..=MAX_GATES as u16 {
            devices.on_arp(&arp(mac2(n), ip(10 + n as u8)));
        }
        for n in 0..MAX_GATES as u16 {
            assert_eq!(devices.open_gate(mac2(n), 60), Ok(()), "{n}");
        }
        assert_eq!(
            devices.open_gate(mac2(MAX_GATES as u16), 60),
            Err(EditError::Full)
        );
        // A gate that is open takes a new time, and room is made by shutting one.
        assert_eq!(devices.open_gate(mac2(3), 600), Ok(()));
        assert_eq!(devices.shut_gate(mac2(0)), Ok(()));
        assert_eq!(devices.open_gate(mac2(MAX_GATES as u16), 60), Ok(()));
        assert_eq!(devices.next_gate_deadline(), Some(1060));
    }

    #[test]
    fn every_address_of_both_lists_and_of_all_the_gates_fits_the_set_the_dns_side_reads() {
        let (mut devices, _, addrs) = exempt_setup();
        // 192 devices, 4 addresses each: 64 on the configuration's list, 64 on the pushed one,
        // 64 with a gate open.
        for n in 0..192u16 {
            for k in 0..4u8 {
                let host = Ipv4Addr::new(10, 1, (n % 192) as u8, k);
                devices.on_arp(&arp(mac2(n), host));
            }
        }
        devices.set_exempt_config((0..64).map(mac2).collect());
        devices.set_exempt((64..128).map(mac2).collect());
        for n in 128..192 {
            assert_eq!(devices.open_gate(mac2(n), 60), Ok(()));
        }
        assert_eq!(addrs.listed().len(), 192 * 4);
        assert!(addrs.is_exempt(IpAddr::V4(Ipv4Addr::new(10, 1, 191, 3))));
        assert!(addrs.is_exempt(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0))));
    }

    #[test]
    fn ads_pass_edits_the_pushed_exempt_list_in_the_list_mode() {
        let (mut devices, _, addrs) = exempt_setup();
        hear_all(&mut devices, &[5, 6, 8]);
        devices.set_exempt(macs(&[6]));
        devices.set_exempt_config(macs(&[8]));
        let rev = devices.rev();

        assert_eq!(devices.set_ads_pass(mac(5), true), Ok(()));
        assert_eq!(exempt_hosts(&addrs), [5, 6, 8]);
        let view = devices.view();
        assert_eq!(view.exempt_pushed, [mac(5), mac(6)]);
        assert_eq!(view.exempt_macs, [mac(5), mac(6), mac(8)]);
        assert_eq!(devices.rev(), rev + 1);
        // The same again changes nothing and moves nothing.
        assert_eq!(devices.set_ads_pass(mac(5), true), Ok(()));
        assert_eq!(devices.rev(), rev + 1);

        assert_eq!(devices.set_ads_pass(mac(5), false), Ok(()));
        assert_eq!(exempt_hosts(&addrs), [6, 8]);
        assert_eq!(devices.view().exempt_pushed, [mac(6)]);
        assert_eq!(devices.rev(), rev + 2);
        assert_eq!(devices.set_ads_pass(mac(5), false), Ok(()));
        assert_eq!(devices.rev(), rev + 2);

        // The configuration's list fixes its devices, either way.
        assert_eq!(devices.set_ads_pass(mac(8), false), Err(EditError::Fixed));
        assert_eq!(devices.set_ads_pass(mac(8), true), Err(EditError::Fixed));
        assert_eq!(devices.rev(), rev + 2);
        // A MAC that has not been heard may be edited: the lists name such devices.
        assert_eq!(devices.set_ads_pass(mac(9), true), Ok(()));
        assert_eq!(devices.view().exempt_pushed, [mac(6), mac(9)]);
        // No device's address.
        assert_eq!(
            devices.set_ads_pass(Mac([0; 6]), true),
            Err(EditError::Invalid)
        );
        assert_eq!(
            devices.set_ads_pass(Mac([1, 0, 0, 0, 0, 1]), false),
            Err(EditError::Invalid)
        );
    }

    #[test]
    fn ads_pass_edits_the_pushed_block_list_in_the_exempt_by_default_mode() {
        let (mut devices, _, addrs) = exempt_setup();
        hear_all(&mut devices, &[5, 6, 7]);
        devices.set_block_config(macs(&[6]));
        devices.set_exempt_config(macs(&[7]));
        devices.set_policy(true, macs(&[5]));
        assert_eq!(blocked_hosts(&addrs), [1, 2, 5, 6]);
        let rev = devices.rev();

        // ADS PASS for a blocked device takes it off the pushed block list.
        assert_eq!(devices.set_ads_pass(mac(5), true), Ok(()));
        assert_eq!(blocked_hosts(&addrs), [1, 2, 6]);
        assert!(devices.view().block_pushed.is_empty());
        assert_eq!(devices.rev(), rev + 1);
        assert_eq!(devices.set_ads_pass(mac(5), true), Ok(()));
        assert_eq!(devices.rev(), rev + 1);
        // Stopping it puts it on the list again.
        assert_eq!(devices.set_ads_pass(mac(5), false), Ok(()));
        assert_eq!(blocked_hosts(&addrs), [1, 2, 5, 6]);
        assert_eq!(devices.view().block_pushed, [mac(5)]);
        assert_eq!(devices.rev(), rev + 2);
        // The configuration's block list fixes its device; its exempt list means nothing here.
        assert_eq!(devices.set_ads_pass(mac(6), true), Err(EditError::Fixed));
        assert_eq!(devices.set_ads_pass(mac(7), false), Ok(()));
        assert_eq!(blocked_hosts(&addrs), [1, 2, 5, 6, 7]);
        // The exempt list of the mode that is not in force is left alone.
        assert_eq!(devices.view().exempt_pushed, []);
    }

    #[test]
    fn stopping_ads_pass_also_shuts_the_devices_gate() {
        let (mut devices, _, addrs) = exempt_setup();
        hear_all(&mut devices, &[5]);
        devices.open_gate(mac(5), 600).unwrap();
        devices.set_ads_pass(mac(5), true).unwrap();
        // Letting ads pass for good leaves the gate as it is.
        assert_eq!(devices.view().devices[0].gate_left_secs, Some(600));
        let rev = devices.rev();
        devices.set_ads_pass(mac(5), false).unwrap();
        assert!(exempt_hosts(&addrs).is_empty());
        assert_eq!(devices.view().devices[0].gate_left_secs, None);
        assert_eq!(devices.rev(), rev + 1);
        // In the other mode too: blocked, and not open.
        devices.set_policy(true, Vec::new());
        devices.open_gate(mac(5), 600).unwrap();
        devices.set_ads_pass(mac(5), false).unwrap();
        assert_eq!(blocked_hosts(&addrs), [1, 2, 5]);
        assert_eq!(devices.next_gate_deadline(), None);
    }

    #[test]
    fn the_router_and_the_pi_take_no_ads_pass_in_either_mode() {
        let (mut devices, _, _) = exempt_setup();
        hear_all(&mut devices, &[1, 5]);
        let rev = devices.rev();
        for default in [false, true] {
            devices.set_policy(default, Vec::new());
            let rev = devices.rev();
            for pass in [true, false] {
                assert_eq!(devices.set_ads_pass(mac(1), pass), Err(EditError::Always));
                assert_eq!(devices.set_ads_pass(own(), pass), Err(EditError::Always));
            }
            assert_eq!(devices.rev(), rev);
        }
        assert!(devices.rev() > rev);
        // A device that claims the router's address is the router for this.
        devices.on_arp(&arp(mac(5), ip(1)));
        assert_eq!(devices.set_ads_pass(mac(5), true), Err(EditError::Always));
        let view = devices.view();
        assert!(view.devices.iter().all(|d| d.always));
        assert_eq!(view.own_mac, Some(own()));
    }

    #[test]
    fn a_full_pushed_list_refuses_one_more_but_still_edits_its_members() {
        let (mut devices, _, _) = exempt_setup();
        devices.set_exempt((0..64).map(mac2).collect());
        assert_eq!(devices.set_ads_pass(mac2(64), true), Err(EditError::Full));
        assert_eq!(devices.set_ads_pass(mac2(3), true), Ok(()));
        assert_eq!(devices.set_ads_pass(mac2(3), false), Ok(()));
        assert_eq!(devices.set_ads_pass(mac2(64), true), Ok(()));
        devices.set_policy(true, (0..64).map(mac2).collect());
        assert_eq!(devices.set_ads_pass(mac2(64), false), Err(EditError::Full));
        assert_eq!(devices.set_ads_pass(mac2(3), true), Ok(()));
        assert_eq!(devices.set_ads_pass(mac2(64), false), Ok(()));
    }

    #[test]
    fn the_revision_moves_with_every_change_of_a_pushed_list_the_mode_the_labels_or_a_gate() {
        let (mut devices, clock, _) = exempt_setup();
        // Each boot starts the count from a number of its own, which is never 0.
        let start = devices.rev();
        assert_ne!(start, 0);
        // What the watch hears, the known list, the configuration and the learning are no part.
        hear_all(&mut devices, &[5, 6]);
        devices.set_known(macs(&[5]));
        devices.set_exempt_config(macs(&[7]));
        devices.set_block_config(macs(&[7]));
        devices.set_exempt_default_config(false);
        clock.advance(1000);
        devices.tick();
        assert_eq!(devices.rev(), start);
        let expect = std::cell::Cell::new(start);
        let moved = |devices: &Rig, what: &str| {
            expect.set(expect.get() + 1);
            assert_eq!(devices.rev(), expect.get(), "{what}");
        };
        let still = |devices: &Rig, what: &str| assert_eq!(devices.rev(), expect.get(), "{what}");

        devices.set_exempt(macs(&[5]));
        moved(&devices, "an exempt list that differs");
        devices.set_exempt(macs(&[5]));
        still(&devices, "the same exempt list");
        // A mode that is the one in force and a block list that is the one there is.
        devices.set_policy(false, Vec::new());
        still(&devices, "a policy that changes nothing");
        devices.set_policy(true, Vec::new());
        moved(&devices, "the mode");
        devices.set_policy(true, macs(&[6]));
        moved(&devices, "a block list that differs");
        devices.set_policy(true, macs(&[6]));
        still(&devices, "the same policy");
        devices.load_labels(vec![(mac(5), label("Desk"))], false, true);
        moved(&devices, "a label");
        devices.load_labels(vec![(mac(5), label("Desk"))], false, true);
        still(&devices, "the same labels");
        devices.load_labels(vec![(mac(6), label("TV"))], false, false);
        still(&devices, "a chunk that is on its way");
        devices.load_labels(Vec::new(), true, true);
        moved(&devices, "the chunk that completes");
        devices.open_gate(mac(5), 60).unwrap();
        moved(&devices, "a gate opens");
        devices.shut_gate(mac(5)).unwrap();
        moved(&devices, "a gate shuts");
        devices.shut_gate(mac(5)).unwrap();
        still(&devices, "a gate that is shut");
        devices.open_gate(mac(5), 60).unwrap();
        moved(&devices, "a gate opens again");
        devices.expire_gates(1000 + 1000 + 60);
        moved(&devices, "a gate expires");
        // The exempt-by-default mode is in force, and device 5 is not on the block list.
        devices.set_ads_pass(mac(5), true).unwrap();
        still(&devices, "an edit that changes nothing");
        devices.set_ads_pass(mac(5), false).unwrap();
        moved(&devices, "an edit of the block list");
        devices.set_ads_pass(mac(5), false).unwrap();
        still(&devices, "the same edit again");
        devices.set_ads_pass(mac(5), true).unwrap();
        moved(&devices, "an edit the other way");
    }

    #[test]
    fn a_check_of_the_revision_lets_a_push_through_only_on_the_revision_there_is() {
        let (mut devices, _, _) = exempt_setup();
        let start = devices.rev();
        assert_eq!(devices.check_rev(None), Ok(()));
        assert_eq!(devices.check_rev(Some(start)), Ok(()));
        devices.set_exempt(macs(&[5]));
        assert_eq!(devices.check_rev(Some(start)), Err(start + 1));
        assert_eq!(devices.check_rev(Some(start + 2)), Err(start + 1));
        assert_eq!(devices.check_rev(Some(start + 1)), Ok(()));
        assert_eq!(devices.check_rev(None), Ok(()));
    }

    #[test]
    fn the_revision_starts_from_a_number_of_each_boot_and_a_stale_one_from_the_last_does_not_match()
    {
        // Two inventories stand for two boots. Each starts its count somewhere else and never at
        // 0, so a desktop's `if_rev` from the boot before, which it took from the count after a
        // few changes, is not the revision of a boot that has made none.
        let (mut before, _, _) = exempt_setup();
        before.set_exempt(macs(&[5]));
        before.set_exempt(macs(&[6]));
        let kept = before.rev();
        let (after, _, _) = exempt_setup();
        assert_ne!(after.rev(), 0);
        assert_ne!(after.rev(), before.rev());
        assert_eq!(after.check_rev(Some(kept)), Err(after.rev()));
    }

    #[test]
    fn labels_come_in_chunks_like_the_known_list_and_keep_the_desktops_order() {
        let (mut devices, _, _) = exempt_setup();
        hear_all(&mut devices, &[5, 6, 7, 8]);
        let pair = |last: u8, text: &str| (mac(last), label(text));
        let label_of = |d: &Devices, last: u8| {
            let view = d.view();
            let device = view
                .devices
                .iter()
                .find(|v| v.mac == mac(last))
                .unwrap()
                .clone();
            (
                device.label.as_deref().map(str::to_owned),
                device.label_rank,
            )
        };

        assert_eq!(
            devices.load_labels(vec![pair(7, "TV"), pair(5, "Desk PC")], false, false),
            2
        );
        // A list on its way is not in force.
        assert_eq!(label_of(&devices, 7), (None, None));
        // The chunk adds; a MAC that comes twice keeps its first label and place.
        assert_eq!(
            devices.load_labels(vec![pair(6, "Phone"), pair(7, "Again")], true, true),
            3
        );
        assert_eq!(label_of(&devices, 7), (Some("TV".into()), Some(0)));
        assert_eq!(label_of(&devices, 5), (Some("Desk PC".into()), Some(1)));
        assert_eq!(label_of(&devices, 6), (Some("Phone".into()), Some(2)));
        assert_eq!(label_of(&devices, 8), (None, None));
        // A list that starts again leaves the old labels in force until it completes.
        assert_eq!(
            devices.load_labels(vec![pair(8, "Kettle")], false, false),
            1
        );
        assert_eq!(label_of(&devices, 7).0.as_deref(), Some("TV"));
        assert_eq!(devices.load_labels(vec![pair(5, "PC")], true, true), 2);
        assert_eq!(label_of(&devices, 7), (None, None));
        assert_eq!(label_of(&devices, 8), (Some("Kettle".into()), Some(0)));
        assert_eq!(label_of(&devices, 5), (Some("PC".into()), Some(1)));
        // An adding chunk with no list on its way adds to the labels there are.
        assert_eq!(devices.load_labels(vec![pair(6, "Phone")], true, true), 3);
        assert_eq!(label_of(&devices, 6), (Some("Phone".into()), Some(2)));
        // An empty complete list clears them.
        assert_eq!(devices.load_labels(Vec::new(), false, true), 0);
        assert_eq!(label_of(&devices, 5), (None, None));
    }

    #[test]
    fn the_labels_keep_the_first_64_and_the_cap_holds_across_chunks() {
        let (mut devices, _, _) = exempt_setup();
        let many = |from: u16, to: u16| -> Vec<(Mac, Label)> {
            (from..to).map(|n| (mac2(n), label("x"))).collect()
        };
        assert_eq!(devices.load_labels(many(0, 40), false, false), 40);
        assert_eq!(devices.load_labels(many(30, 100), true, true), MAX_LABELS);
        assert_eq!(devices.load_labels(many(200, 210), true, true), MAX_LABELS);
    }

    #[test]
    fn the_debug_of_a_view_says_nothing_of_a_label() {
        let (mut devices, _, _) = exempt_setup();
        hear_all(&mut devices, &[5]);
        devices.load_labels(vec![(mac(5), label("Desk PC"))], false, true);
        let text = format!("{:?}", devices.view());
        assert!(!text.contains("Desk"), "{text}");
        assert!(text.contains("Label(..)"), "{text}");
    }

    // ---- the panel's copy for the wall ----

    /// A busy house on a clock that moves: 600 devices heard (the inventory keeps 512), two of
    /// them in each three at the same second, every fifth with a host name, the router and the
    /// Pi's address in use, 40 labels in an order of their own (one of them the router's), a few
    /// open gates, and the configuration's lists in both modes.
    fn busy_house() -> (Rig, FakeClock) {
        let (mut rig, clock, _) = exempt_setup();
        for n in 0..600u16 {
            if n % 3 != 0 {
                clock.advance(1);
            }
            let [high, low] = n.to_be_bytes();
            let host = Ipv4Addr::new(10, 1, high, low);
            rig.on_arp(&arp(mac2(n), host));
            if n % 5 == 0 {
                rig.on_dhcp(&dhcp(
                    DHCP_REQUEST,
                    mac2(n),
                    Some(host),
                    Ipv4Addr::UNSPECIFIED,
                    Some(&format!("host-{n}-with-a-name")),
                ));
            }
            // A second address for some, which comes first in the list of its device.
            if n % 7 == 0 {
                rig.on_arp(&arp(mac2(n), Ipv4Addr::new(10, 2, high, low)));
            }
        }
        // The router, heard last so that the inventory still holds it, and a device that claims the
        // Pi's address: neither is ever exempt.
        rig.on_arp(&arp(mac2(9_999), ip(1)));
        rig.on_arp(&arp(mac2(580), ip(2)));
        let labels: Vec<(Mac, Label)> = std::iter::once((mac2(9_999), label("Router")))
            .chain((0..39).map(|k| (mac2(100 + k * 3), label(&format!("Label {k}")))))
            .collect();
        rig.load_labels(labels, false, true);
        // Gates on labelled devices, which have their place on the wall, and on others.
        for n in [100, 103, 160, 595, 400] {
            rig.open_gate(mac2(n), 90 + n).unwrap();
        }
        rig.set_exempt_config(vec![mac2(597), mac2(300)]);
        rig.set_exempt(vec![mac2(598)]);
        rig.set_block_config(vec![mac2(596), mac2(501)]);
        (rig, clock)
    }

    /// The wall, as the panel builds it, in a form to compare: every field of every place.
    fn places(copy: &WallCopy, now: Option<u64>) -> Vec<String> {
        crate::panel::view::wall(copy, &[], 5_000, now)
            .iter()
            .map(|entry| {
                format!(
                    "{:?} {} {} {} {} {} {:?} {:?} {:?}",
                    entry.row.mac,
                    entry.row.name,
                    entry.row.named,
                    entry.row.octet,
                    entry.row.fixed,
                    entry.row.asking,
                    entry.row.state,
                    entry.ipv4,
                    entry.gate_ends_ms,
                )
            })
            .collect()
    }

    #[test]
    fn the_wall_built_from_the_panels_copy_is_the_wall_built_from_the_whole_view() {
        use crate::panel::view;
        let (mut rig, _) = busy_house();
        // At 24 hours and 300 seconds after the start, those last seen in the first 300 are too old: about
        // half the devices. And with no clock, none are.
        let late = UNIX_START + 86_400 + 300;
        // The 40 labels, then 10 of them (the places are not full of labelled devices), then none.
        let all = rig
            .view()
            .devices
            .iter()
            .filter(|d| d.label.is_some())
            .count();
        assert!(all >= 39, "{all}");
        for labels in [40usize, 10, 0] {
            let kept: Vec<(Mac, Label)> = (0..labels.min(39))
                .map(|k| (mac2(100 + k as u16 * 3), label(&format!("Label {k}"))))
                .collect();
            rig.load_labels(kept, false, true);
            for exempt_default in [false, true] {
                rig.set_policy(exempt_default, vec![mac2(590), mac2(160), mac2(2)]);
                for now in [None, Some(UNIX_START + 600), Some(late)] {
                    let mut copy = WallCopy::new();
                    rig.wall_copy(&|last| view::recent(last, now), &mut copy);
                    let whole = WallCopy::of_view(&rig.view());
                    assert!(whole.rows.len() > 500);
                    let (lean, full) = (places(&copy, now), places(&whole, now));
                    assert_eq!(lean.len(), WALL_ROWS, "{labels} {exempt_default} {now:?}");
                    assert_eq!(
                        lean, full,
                        "{labels} labels, default mode {exempt_default}, clock {now:?}"
                    );
                    assert_eq!(copy.exempt_default, exempt_default);
                    assert_eq!(
                        view::newcomer_of(&copy),
                        view::newcomer_of(&whole),
                        "the mode"
                    );
                }
            }
        }
    }

    #[test]
    fn the_copy_holds_what_the_wall_reads_of_each_device_as_the_view_says_it() {
        let (rig, _) = busy_house();
        let mut copy = WallCopy::new();
        rig.wall_copy(&|_| true, &mut copy);
        let view = rig.view();
        assert!(copy.rows.len() <= WALL_ROWS);
        let (mut gated, mut named, mut labelled, mut always) = (0, 0, 0, 0);
        for row in &copy.rows {
            let whole = view
                .devices
                .iter()
                .find(|device| device.mac == row.mac)
                .expect("a device of the inventory");
            assert_eq!(row.ipv4(), whole.ipv4.as_slice());
            assert_eq!(row.hostname(), whole.hostname.as_deref());
            assert_eq!(row.label(), whole.label.as_deref());
            assert_eq!(row.label_rank, whole.label_rank);
            assert_eq!(
                (row.first_unix, row.last_unix),
                (whole.first_unix, whole.last_unix)
            );
            assert_eq!(
                (row.gate_left_secs, row.exempt, row.fixed, row.always),
                (
                    whole.gate_left_secs,
                    whole.exempt,
                    whole.fixed,
                    whole.always
                )
            );
            gated += usize::from(row.gate_left_secs.is_some());
            named += usize::from(row.hostname().is_some());
            labelled += usize::from(row.label().is_some());
            always += usize::from(row.always);
        }
        // The things above were in the house, and so in the copy: it is a test of them.
        assert!(
            gated > 0 && named > 0 && labelled > 0 && always >= 2,
            "{gated} {named} {labelled} {always}"
        );
        assert_eq!(
            (copy.own_mac, copy.own_ip, copy.exempt_default),
            (view.own_mac, view.own_ip, view.exempt_default)
        );
    }

    #[test]
    fn the_copy_is_bounded_and_makes_no_allocation_when_the_buffer_is_used_again() {
        let (mut rig, clock) = busy_house();
        let mut copy = WallCopy::new();
        let room = copy.rows.capacity();
        assert!(room >= WALL_ROWS);
        rig.wall_copy(&|_| true, &mut copy);
        // The wall's 33 places are full, the Pi's own among them: it is no device of the inventory.
        assert_eq!(
            copy.rows.len(),
            WALL_ROWS - 1,
            "a house of 512 fills the wall"
        );
        assert_eq!(
            copy.rows.capacity(),
            room,
            "the room it was made with is all it uses"
        );
        // Again, after the inventory changed under it, and with a window that holds fewer: the same room,
        // never more rows than the wall has places.
        clock.advance(5);
        rig.on_arp(&arp(mac2(700), Ipv4Addr::new(10, 3, 0, 1)));
        rig.wall_copy(&|last| last > UNIX_START + 300, &mut copy);
        assert!(copy.rows.len() <= WALL_ROWS);
        rig.wall_copy(&|_| false, &mut copy);
        assert!(
            copy.rows
                .iter()
                .all(|row| row.label().is_some() || row.always),
            "the unlabelled are too old"
        );
        assert_eq!(copy.rows.capacity(), room);
        // An inventory with next to nothing in it leaves the buffer as big as it was.
        let (small, _) = setup();
        small.wall_copy(&|_| true, &mut copy);
        assert!(copy.rows.is_empty());
        assert_eq!(copy.rows.capacity(), room);
    }

    #[test]
    fn the_copy_of_a_long_name_is_cut_to_whole_characters_and_keeps_the_router_when_the_wall_is_full()
     {
        let mut text = Inline::<4>::EMPTY;
        assert_eq!(text.get(), None);
        text.set(Some("abcdef"));
        assert_eq!(text.get(), Some("abcd"));
        // `\u{e9}` is two bytes: the cut goes before the one that would not fit.
        text.set(Some("abc\u{e9}"));
        assert_eq!(text.get(), Some("abc"));
        text.set(Some("\u{20ac}\u{20ac}"));
        assert_eq!(text.get(), Some("\u{20ac}"));
        text.set(None);
        assert_eq!(text.get(), None);

        // Far more than 33 devices were seen first; the router, heard last, still has its place.
        let (mut rig, clock, _) = exempt_setup();
        for n in 0..100u16 {
            clock.advance(1);
            rig.on_arp(&arp(mac2(n), Ipv4Addr::new(10, 1, 0, n as u8)));
        }
        clock.advance(1);
        rig.on_arp(&arp(mac(250), ip(1)));
        let mut copy = WallCopy::new();
        rig.wall_copy(&|_| true, &mut copy);
        assert_eq!(copy.rows.len(), WALL_ROWS - 1, "and the Pi's own place");
        assert_eq!(copy.rows.iter().filter(|row| row.always).count(), 1);
        assert!(copy.rows.iter().any(|row| row.mac == mac(250)));
    }

    /// The panel's copy against the view that it replaced, for 512 devices: `view` builds every
    /// device with clones, a map of the labels and a sort; `wall_copy` walks the inventory and copies
    /// the few the wall can show.
    #[test]
    #[ignore = "prints timings; run it in release"]
    fn what_the_wall_copy_costs_against_the_view() {
        use std::hint::black_box;
        use std::time::Instant;
        let (rig, _) = busy_house();
        let mut copy = WallCopy::new();
        const ROUNDS: u32 = 2_000;
        let mut best = (u128::MAX, u128::MAX);
        for _ in 0..7 {
            let began = Instant::now();
            for _ in 0..ROUNDS {
                black_box(black_box(&*rig).view());
            }
            let before = began.elapsed().as_nanos() / u128::from(ROUNDS);
            let began = Instant::now();
            for _ in 0..ROUNDS {
                black_box(&*rig).wall_copy(&|last| last > 0, black_box(&mut copy));
                black_box(&copy);
            }
            let after = began.elapsed().as_nanos() / u128::from(ROUNDS);
            best = (best.0.min(before), best.1.min(after));
        }
        assert_eq!(copy.rows.len(), WALL_ROWS - 1);
        println!(
            "panel's read of the inventory, 512 devices, 40 labels, fastest of 7 runs of {ROUNDS}:\n  \
             view() (before): {} ns per call\n  wall_copy (after): {} ns per call",
            best.0, best.1
        );
    }
}
