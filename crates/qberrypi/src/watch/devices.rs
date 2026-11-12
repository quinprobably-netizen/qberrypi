//! The device inventory: which devices the home network has, from the ARP, DHCP and mDNS that the
//! device watch hears, and the two alerts that come of it, a new device and a forged gateway.
//!
//! Nothing here reads a socket or a clock of its own: the device watch calls in with what it
//! heard, and time is read from the clock that `Devices::new` was given, which is the same
//! shape as the alert store's: (monotonic seconds, unix seconds). Everything is bounded: 512
//! devices, 4 addresses each, a known list of 1024, two exempt lists of 64 and two block lists of
//! 64, 64 held alerts and 64
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
//! In the exempt-by-default mode the exempt lists have no effect: every client is exempt but the
//! fully blocked ones, and an address is fully blocked while the device that claimed it last is on
//! the configuration's block list or the pushed one, and always when it is the router's or the
//! Pi's own. The inventory keeps the blocked addresses ([`Exemption::blocked`]) in step the same
//! way, in either mode, so that turning the mode on finds them ready. The mode in force is the
//! pushed one once a policy has been pushed since the start, and the configuration's until then.
//!
//! Nothing here logs but counts and the mode: the devices on a known list that came, the devices
//! learned, the devices on an exempt list that came, and the mode and number of blocked devices of
//! a policy that came and changed them. A MAC, an address or a host name never reaches a log line
//! from this file.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex, PoisonError};

use super::frames::{Arp, DHCP_DISCOVER, DHCP_REQUEST, Dhcp, HOSTNAME_MAX, Mac};
use crate::alerts::{Alert, AlertSink, Severity};
use crate::dns::exempt::{self, Exemption};

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

// Every address of every device on both exempt lists fits the set that the DNS side reads, and
// so does every address of every device on both block lists with the router's and the Pi's own.
const _: () = assert!(2 * MAX_EXEMPT * MAX_IPV4 <= exempt::MAX_ADDRS);
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
    /// the configuration's or the pushed one. In the exempt-by-default mode: it is not on a block
    /// list, and no address that it claimed last is the router's or the Pi's own.
    pub exempt: bool,
    /// Whether its MAC is on a block list, the configuration's or the pushed one, whatever the
    /// mode.
    pub blocked: bool,
}

/// The inventory as a reader sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicesView {
    /// Whether a known list has come.
    pub known_list: KnownList,
    /// Every device in the inventory, the one seen last first.
    pub devices: Vec<DeviceView>,
    /// The MACs of both exempt lists, sorted and each once, those not heard yet included.
    pub exempt_macs: Vec<Mac>,
    /// Whether the exempt-by-default mode is in force.
    pub exempt_default: bool,
    /// The MACs of both block lists, sorted and each once, those not heard yet included.
    pub block_macs: Vec<Mac>,
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
        self.block_pushed = first_different(block, MAX_BLOCK);
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
        self.exempt_pushed = pushed;
        self.exempt_received = true;
        self.refresh_exempt();
        if news {
            log::info!("watch: exempt list of {kept} devices received");
        }
        kept
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
        self.state = KnownList::Received;
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
        if news {
            log::info!("watch: known list of {kept} devices received");
        }
        kept
    }

    /// Does what is due by now: if no known list has come [`LEARN_AFTER_SECS`] after the first
    /// device was seen, every device seen so far joins the known set, silently, and the held
    /// alerts are dropped. With no device seen there is nothing to learn, and nothing happens.
    pub fn tick(&mut self) {
        let (mono, _) = (self.clock)();
        let Some(first) = self.first_seen else {
            return;
        };
        if self.state != KnownList::Waiting || mono < first.saturating_add(LEARN_AFTER_SECS) {
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

    /// The inventory now, the device seen last first.
    pub fn view(&self) -> DevicesView {
        let by_default = self.exempt_default();
        let mut seen: Vec<(u64, DeviceView)> = self
            .devices
            .iter()
            .map(|(&mac, device)| {
                let view = DeviceView {
                    mac,
                    ipv4: device.ipv4.iter().rev().copied().collect(),
                    hostname: device.hostname.clone(),
                    first_unix: device.first_unix,
                    last_unix: device.last_unix,
                    known: self.known.contains(&mac),
                    exempt: if by_default {
                        !self.is_blocked(mac) && !self.claims_router_or_pi(mac, device)
                    } else {
                        self.is_exempt(mac)
                    },
                    blocked: self.is_blocked(mac),
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
        DevicesView {
            known_list: self.state,
            devices: seen.into_iter().map(|(_, view)| view).collect(),
            exempt_macs,
            exempt_default: by_default,
            block_macs,
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

    /// Whether `mac` is on any of the four lists, so that an address it takes or leaves may
    /// change a published set.
    fn is_listed(&self, mac: Mac) -> bool {
        self.is_exempt(mac) || self.is_blocked(mac)
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
    /// the inventory that the device claimed last, but for the router's and the Pi's own, which
    /// are never exempt.
    fn exempt_now(&self) -> Vec<Ipv4Addr> {
        let mut addrs: Vec<Ipv4Addr> = self
            .claimed_by(self.exempt_config.iter().chain(&self.exempt_pushed))
            .filter(|&ip| !self.is_router_or_pi(ip))
            .collect();
        addrs.sort_unstable();
        addrs.dedup();
        addrs
    }

    /// The addresses that are fully blocked now, sorted, each once: the router's and the Pi's own,
    /// and each address of a device on a block list in the inventory that the device claimed
    /// last. The router's and the Pi's come first, so that a cut of the set could never drop them.
    fn blocked_now(&self) -> Vec<Ipv4Addr> {
        let mut addrs: Vec<Ipv4Addr> = [Some(self.gateway), self.own_ip]
            .into_iter()
            .flatten()
            .chain(self.claimed_by(self.block_config.iter().chain(&self.block_pushed)))
            .collect();
        addrs.sort_unstable();
        addrs.dedup();
        addrs
    }

    /// Works out the exempt and the fully blocked addresses again, and publishes each set that
    /// changed, and the count of the addresses that are not blocked. It looks at the devices of
    /// the four lists alone, at most 256 of four addresses each.
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
}
