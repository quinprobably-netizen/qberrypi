//! nl80211: the commands that scan, connect and install keys on a Wi-Fi
//! interface, the readers for what the kernel sends back, and a client that
//! sends the one and reads the other.
//!
//! Every message starts with the 4-byte generic netlink header (command,
//! version, two zero bytes), and its attributes follow. The builders return
//! the request as a [`MsgBuilder`]; the parsers read the payload of one
//! message, header first.
//!
//! The two key commands put the key into the request and nowhere else: it is
//! never formatted, copied into a buffer of its own, or logged, and the
//! socket wipes the request once it is sent. Nothing here prints what the
//! kernel sent either.

use std::io;
use std::time::Duration;

use tokio::time::Instant;

use super::{
    MsgBuilder, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NlSocket, RequestError, find, messages,
};
use crate::sys::NetlinkProtocol;

/// The cipher suite CCMP-128 (00-0F-AC:4).
pub const CIPHER_CCMP: u32 = 0x000f_ac04;
/// The key management suite PSK (00-0F-AC:2).
pub const AKM_PSK: u32 = 0x000f_ac02;

/// Message type: the controller that knows the other families.
const GENL_ID_CTRL: u16 = 16;
/// Controller command: describe a family.
const CTRL_CMD_GETFAMILY: u8 = 3;
/// Controller attribute: the family's id.
const CTRL_ATTR_FAMILY_ID: u16 = 1;
/// Controller attribute: the family's name.
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
/// Controller attribute: the family's multicast groups.
const CTRL_ATTR_MCAST_GROUPS: u16 = 7;
/// Group attribute: the group's name.
const CTRL_ATTR_MCAST_GRP_NAME: u16 = 1;
/// Group attribute: the group's id.
const CTRL_ATTR_MCAST_GRP_ID: u16 = 2;

/// The name nl80211 is looked up by, the only family this client resolves.
const FAMILY_NAME: &str = "nl80211";
/// The group that announces scans ending.
const GROUP_SCAN: &str = "scan";
/// The group that announces connecting and disconnecting.
const GROUP_MLME: &str = "mlme";

/// Command: install a key.
const CMD_NEW_KEY: u8 = 11;
/// Command: read a station's state; the kernel answers with `CMD_NEW_STATION`.
const CMD_GET_STATION: u8 = 17;
/// Command: change a station's flags.
const CMD_SET_STATION: u8 = 18;
/// Reply: a station's state.
const CMD_NEW_STATION: u8 = 19;
/// Command: read the regulatory domain.
const CMD_GET_REG: u8 = 31;
/// Command: read the scan results.
const CMD_GET_SCAN: u8 = 32;
/// Command, and event: a scan was started.
const CMD_TRIGGER_SCAN: u8 = 33;
/// Event: a scan ended.
const CMD_NEW_SCAN_RESULTS: u8 = 34;
/// Event: a scan was aborted.
const CMD_SCAN_ABORTED: u8 = 35;
/// Command: set an interface's power save.
const CMD_SET_POWER_SAVE: u8 = 61;
/// Command, and event: connect to a network; or the outcome of the attempt.
const CMD_CONNECT: u8 = 46;
/// Event: the station moved to another access point.
const CMD_ROAM: u8 = 47;
/// Command, and event: leave the network; or the link went away.
const CMD_DISCONNECT: u8 = 48;

/// Attribute: the interface's index.
const ATTR_IFINDEX: u16 = 3;
/// Attribute: a hardware address.
const ATTR_MAC: u16 = 6;
/// Attribute: information elements.
const ATTR_IE: u16 = 42;
/// Attribute: the regulatory domain's country.
const ATTR_REG_ALPHA2: u16 = 33;
/// Attribute: the frequency in MHz.
const ATTR_WIPHY_FREQ: u16 = 38;
/// Attribute: the network's name.
const ATTR_SSID: u16 = 52;
/// Attribute: the nest that lists the frequencies a scan covers; left out, a scan covers every channel.
const ATTR_SCAN_FREQUENCIES: u16 = 44;
/// Attribute: the nest that names the networks a scan asks for.
const ATTR_SCAN_SSIDS: u16 = 45;
/// Attribute: how a scan is done.
const ATTR_SCAN_FLAGS: u16 = 158;
/// Attribute: the nest that describes a scan result.
const ATTR_BSS: u16 = 47;
/// Attribute: the reason a station left.
const ATTR_REASON_CODE: u16 = 54;
/// Attribute: the authentication algorithm.
const ATTR_AUTH_TYPE: u16 = 53;
/// Attribute: the station's flags and which of them to change.
const ATTR_STA_FLAGS2: u16 = 67;
/// Attribute, a flag: the control port is the supplicant's.
const ATTR_CONTROL_PORT: u16 = 68;
/// Attribute, a flag: the connection is protected.
const ATTR_PRIVACY: u16 = 70;
/// Attribute, a flag: the access point ended the connection.
const ATTR_DISCONNECTED_BY_AP: u16 = 71;
/// Attribute: the outcome of an attempt, as the access point said it.
const ATTR_STATUS_CODE: u16 = 72;
/// Attribute: the pairwise ciphers.
const ATTR_CIPHER_SUITES_PAIRWISE: u16 = 73;
/// Attribute: the group cipher.
const ATTR_CIPHER_SUITE_GROUP: u16 = 74;
/// Attribute: the WPA versions.
const ATTR_WPA_VERSIONS: u16 = 75;
/// Attribute: the key management suites.
const ATTR_AKM_SUITES: u16 = 76;
/// Attribute: the elements of the association request.
const ATTR_REQ_IE: u16 = 77;
/// Attribute, a flag: the attempt timed out.
const ATTR_TIMED_OUT: u16 = 65;
/// Attribute: the nest that describes a key.
const ATTR_KEY: u16 = 80;
/// Attribute: the interface's power save state.
const ATTR_PS_STATE: u16 = 93;

/// Key attribute: the key itself.
const KEY_DATA: u16 = 1;
/// Key attribute: the key's index.
const KEY_IDX: u16 = 2;
/// Key attribute: the cipher.
const KEY_CIPHER: u16 = 3;
/// Key attribute: the sequence number the key starts at.
const KEY_SEQ: u16 = 4;
/// Key attribute: group, pairwise or peer key.
const KEY_TYPE: u16 = 7;

/// Scan result attribute: the access point's address.
const BSS_BSSID: u16 = 1;
/// Scan result attribute: the frequency in MHz.
const BSS_FREQUENCY: u16 = 2;
/// Scan result attribute: the information elements of its beacon or reply.
const BSS_INFORMATION_ELEMENTS: u16 = 6;
/// Scan result attribute: the signal strength in 1/100 dBm.
const BSS_SIGNAL_MBM: u16 = 7;

/// A scan flag: the old results are dropped first.
const SCAN_FLAG_FLUSH: u32 = 1 << 1;
/// The power save state "off".
const PS_STATE_DISABLED: u32 = 0;
/// The open system authentication algorithm, which WPA2 uses before its handshake.
const AUTHTYPE_OPEN_SYSTEM: u32 = 0;
/// The WPA version bit for WPA2.
const WPA_VERSION_2: u32 = 1 << 1;
/// The key type of a group key.
const KEY_TYPE_GROUP: u32 = 0;
/// The key type of a pairwise key.
const KEY_TYPE_PAIRWISE: u32 = 1;
/// The station flag that lets its traffic through the control port.
const STA_FLAG_AUTHORIZED: u32 = 1 << 1;

/// The status code `parse_event` gives for a failed connection that came without one.
const STATUS_UNKNOWN: u16 = u16::MAX;

/// How often `wait_for_country` asks.
const COUNTRY_POLL: Duration = Duration::from_millis(250);

/// A request to a family, with its generic header.
fn command(family: u16, flags: u16, cmd: u8) -> MsgBuilder {
    MsgBuilder::new(family, flags).header(&[cmd, 0, 0, 0])
}

/// A request for `cmd` on interface `ifindex`, which the kernel acknowledges.
fn on_interface(family: u16, cmd: u8, ifindex: u32) -> MsgBuilder {
    command(family, NLM_F_REQUEST | NLM_F_ACK, cmd).attr_u32(ATTR_IFINDEX, ifindex)
}

/// What the controller says about a family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Family {
    /// The message type the family's messages have.
    pub id: u16,
    /// The multicast groups: each one's name and its id.
    pub groups: Vec<(String, u32)>,
}

impl Family {
    /// The id of the group called `name`.
    pub fn group(&self, name: &str) -> Option<u32> {
        self.groups
            .iter()
            .find(|(group, _)| group == name)
            .map(|&(_, id)| id)
    }
}

/// A request to the controller for the family called `name`.
pub fn get_family(name: &str) -> MsgBuilder {
    MsgBuilder::new(GENL_ID_CTRL, NLM_F_REQUEST | NLM_F_ACK)
        .header(&[CTRL_CMD_GETFAMILY, 1, 0, 0])
        .attr_str(CTRL_ATTR_FAMILY_NAME, name)
}

/// The attributes of a message: what follows its 4-byte generic header.
fn body(payload: &[u8]) -> Option<&[u8]> {
    payload.get(4..)
}

/// Reads the controller's description of a family.
///
/// `None` if the message holds no id. A group that lacks its name or its id
/// is left out.
pub fn parse_family(payload: &[u8]) -> Option<Family> {
    let body = body(payload)?;
    let id = find(body, CTRL_ATTR_FAMILY_ID)?.u16()?;
    let groups = find(body, CTRL_ATTR_MCAST_GROUPS)
        .into_iter()
        .flat_map(|groups| groups.nested())
        .filter_map(|group| {
            let inner = group.payload;
            let name = find(inner, CTRL_ATTR_MCAST_GRP_NAME)?.str()?;
            let id = find(inner, CTRL_ATTR_MCAST_GRP_ID)?.u32()?;
            Some((name.to_owned(), id))
        })
        .collect();
    Some(Family { id, groups })
}

/// A request for the regulatory domain that applies to the whole system.
pub fn get_reg(family: u16) -> MsgBuilder {
    command(family, NLM_F_REQUEST | NLM_F_ACK, CMD_GET_REG)
}

/// A request to turn power save off on an interface.
pub fn set_power_save_off(family: u16, ifindex: u32) -> MsgBuilder {
    on_interface(family, CMD_SET_POWER_SAVE, ifindex).attr_u32(ATTR_PS_STATE, PS_STATE_DISABLED)
}

/// A request to scan for the network called `ssid`, dropping the old results first.
///
/// The scan is a directed one: it probes for `ssid`. It covers every channel when `freqs_mhz` is empty, and
/// only the channels with these centre frequencies otherwise. The kernel refuses a request that names a
/// frequency its radio has no channel for, with `EINVAL`; the caller sees that as a failed scan.
pub fn trigger_scan(family: u16, ifindex: u32, ssid: &[u8], freqs_mhz: &[u32]) -> MsgBuilder {
    let message = on_interface(family, CMD_TRIGGER_SCAN, ifindex);
    let message = if freqs_mhz.is_empty() {
        message
    } else {
        // The attributes of the nest are the frequencies, numbered from 1 as `wpa_supplicant` numbers them.
        message.nest(ATTR_SCAN_FREQUENCIES, |freqs| {
            (1..)
                .zip(freqs_mhz)
                .fold(freqs, |freqs, (index, mhz)| freqs.attr_u32(index, *mhz))
        })
    };
    message
        .nest(ATTR_SCAN_SSIDS, |ssids| ssids.attr(1, ssid))
        .attr_u32(ATTR_SCAN_FLAGS, SCAN_FLAG_FLUSH)
}

/// A request for the scan results, which the kernel sends as a dump.
pub fn get_scan(family: u16, ifindex: u32) -> MsgBuilder {
    command(family, NLM_F_REQUEST | NLM_F_DUMP, CMD_GET_SCAN).attr_u32(ATTR_IFINDEX, ifindex)
}

/// The access point to connect to.
pub struct ConnectTarget<'a> {
    /// The network's name.
    pub ssid: &'a [u8],
    /// The access point's address.
    pub bssid: [u8; 6],
    /// The channel's frequency in MHz.
    pub freq_mhz: u32,
    /// The RSN element the access point advertised, which goes into the
    /// association request as it is.
    pub rsne: &'a [u8],
}

/// A request to associate with an access point: WPA2, PSK, CCMP.
///
/// The kernel authenticates and associates, and leaves the handshake and the
/// keys to the caller: the control port is the caller's.
pub fn connect(family: u16, ifindex: u32, target: &ConnectTarget<'_>) -> MsgBuilder {
    on_interface(family, CMD_CONNECT, ifindex)
        .attr(ATTR_SSID, target.ssid)
        .attr(ATTR_MAC, &target.bssid)
        .attr_u32(ATTR_WIPHY_FREQ, target.freq_mhz)
        .attr(ATTR_IE, target.rsne)
        .attr_u32(ATTR_AUTH_TYPE, AUTHTYPE_OPEN_SYSTEM)
        .attr_flag(ATTR_PRIVACY)
        .attr_u32(ATTR_WPA_VERSIONS, WPA_VERSION_2)
        .attr_u32(ATTR_CIPHER_SUITES_PAIRWISE, CIPHER_CCMP)
        .attr_u32(ATTR_CIPHER_SUITE_GROUP, CIPHER_CCMP)
        .attr_u32(ATTR_AKM_SUITES, AKM_PSK)
        .attr_flag(ATTR_CONTROL_PORT)
}

/// A request to leave the network, giving `reason`.
pub fn disconnect(family: u16, ifindex: u32, reason: u16) -> MsgBuilder {
    on_interface(family, CMD_DISCONNECT, ifindex).attr_u16(ATTR_REASON_CODE, reason)
}

/// A request to install the pairwise key `tk` for the access point `peer`.
///
/// The key goes into the request and nowhere else.
pub fn new_pairwise_key(family: u16, ifindex: u32, peer: [u8; 6], tk: &[u8; 16]) -> MsgBuilder {
    on_interface(family, CMD_NEW_KEY, ifindex)
        .attr(ATTR_MAC, &peer)
        .nest(ATTR_KEY, |key| {
            key.attr(KEY_DATA, tk)
                .attr_u32(KEY_CIPHER, CIPHER_CCMP)
                .attr_u8(KEY_IDX, 0)
                .attr_u32(KEY_TYPE, KEY_TYPE_PAIRWISE)
        })
}

/// A request to install the group key `gtk` as key `key_id`, whose packet
/// counter starts at `rsc`.
///
/// The key goes into the request and nowhere else.
pub fn new_group_key(
    family: u16,
    ifindex: u32,
    key_id: u8,
    gtk: &[u8; 16],
    rsc: &[u8; 6],
) -> MsgBuilder {
    on_interface(family, CMD_NEW_KEY, ifindex).nest(ATTR_KEY, |key| {
        key.attr(KEY_DATA, gtk)
            .attr_u32(KEY_CIPHER, CIPHER_CCMP)
            .attr_u8(KEY_IDX, key_id)
            .attr(KEY_SEQ, rsc)
            .attr_u32(KEY_TYPE, KEY_TYPE_GROUP)
    })
}

/// A request to let the access point `peer`'s traffic through the control port.
pub fn set_station_authorized(family: u16, ifindex: u32, peer: [u8; 6]) -> MsgBuilder {
    // The flags to change, then the flags' new values.
    let mut flags = [0; 8];
    flags[..4].copy_from_slice(&STA_FLAG_AUTHORIZED.to_ne_bytes());
    flags[4..].copy_from_slice(&STA_FLAG_AUTHORIZED.to_ne_bytes());
    on_interface(family, CMD_SET_STATION, ifindex)
        .attr(ATTR_MAC, &peer)
        .attr(ATTR_STA_FLAGS2, &flags)
}

/// A request for what the radio knows of the station `peer`, which the kernel answers with a station message
/// and then acknowledges.
///
/// It names the interface and the address and is no dump, so the kernel runs it as a single query (the
/// driver, or the firmware under it, fills in the answer): an access point the radio is no longer
/// associated with is `ENOENT`, and a radio that does not answer is no answer. [`parse_station`] reads
/// the station message that comes back.
pub fn get_station(family: u16, ifindex: u32, peer: [u8; 6]) -> MsgBuilder {
    on_interface(family, CMD_GET_STATION, ifindex).attr(ATTR_MAC, &peer)
}

/// The address of the station a station message describes.
///
/// `None` unless the message is the kernel's answer to [`get_station`] and holds an address.
pub fn parse_station(payload: &[u8]) -> Option<[u8; 6]> {
    if *payload.first()? != CMD_NEW_STATION {
        return None;
    }
    find(body(payload)?, ATTR_MAC)?.mac()
}

/// One access point, as a scan found it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bss {
    pub bssid: [u8; 6],
    pub freq_mhz: u32,
    /// The signal strength in 1/100 dBm; `i32::MIN` when the kernel gave none.
    pub signal_mbm: i32,
    /// The information elements of its beacon or probe response.
    pub ies: Vec<u8>,
}

/// Reads a message that describes one access point.
///
/// `None` unless it holds the access point's address and frequency.
pub fn parse_bss(payload: &[u8]) -> Option<Bss> {
    let bss = find(body(payload)?, ATTR_BSS)?;
    let inner = bss.payload;
    Some(Bss {
        bssid: find(inner, BSS_BSSID)?.mac()?,
        freq_mhz: find(inner, BSS_FREQUENCY)?.u32()?,
        signal_mbm: find(inner, BSS_SIGNAL_MBM)
            .and_then(|signal| signal.i32())
            .unwrap_or(i32::MIN),
        ies: find(inner, BSS_INFORMATION_ELEMENTS)
            .map(|ies| ies.payload.to_vec())
            .unwrap_or_default(),
    })
}

/// Something the kernel announced about an interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A scan finished, and its results can be read.
    ScanDone,
    /// A scan was cut short.
    ScanAborted,
    /// The association worked.
    Connected {
        bssid: [u8; 6],
        /// The elements the association request carried.
        req_ies: Vec<u8>,
    },
    /// The association did not work.
    ConnectFailed {
        /// The access point's status code; `u16::MAX` when the kernel gave none.
        status: u16,
        timed_out: bool,
    },
    /// The link went away.
    Disconnected {
        /// The reason code; zero when the kernel gave none.
        reason: u16,
        /// Whether the access point ended it.
        by_ap: bool,
    },
    /// The station moved to another access point of the network.
    Roamed { bssid: [u8; 6] },
    /// Any other command.
    Other(u8),
}

/// Reads an event message that concerns interface `ifindex`.
///
/// `None` if the message names another interface, or is too short to be one.
pub fn parse_event(payload: &[u8], ifindex: u32) -> Option<Event> {
    let cmd = *payload.first()?;
    let body = body(payload)?;
    // A message that names an interface it is not about, or one that cannot be read, is not ours.
    if let Some(named) = find(body, ATTR_IFINDEX)
        && named.u32() != Some(ifindex)
    {
        return None;
    }
    let bssid = || find(body, ATTR_MAC).and_then(|mac| mac.mac());
    let u16_of = |ty| find(body, ty).and_then(|attr| attr.u16());
    Some(match cmd {
        CMD_NEW_SCAN_RESULTS => Event::ScanDone,
        CMD_SCAN_ABORTED => Event::ScanAborted,
        CMD_CONNECT => match (u16_of(ATTR_STATUS_CODE), bssid()) {
            (Some(0), Some(bssid)) => Event::Connected {
                bssid,
                req_ies: find(body, ATTR_REQ_IE)
                    .map(|ies| ies.payload.to_vec())
                    .unwrap_or_default(),
            },
            (status, _) => Event::ConnectFailed {
                status: status.unwrap_or(STATUS_UNKNOWN),
                timed_out: find(body, ATTR_TIMED_OUT).is_some(),
            },
        },
        CMD_DISCONNECT => Event::Disconnected {
            reason: u16_of(ATTR_REASON_CODE).unwrap_or(0),
            by_ap: find(body, ATTR_DISCONNECTED_BY_AP).is_some(),
        },
        CMD_ROAM => Event::Roamed {
            bssid: bssid().unwrap_or([0; 6]),
        },
        other => Event::Other(other),
    })
}

/// The country of a regulatory domain reply: its first two bytes.
pub fn parse_reg_alpha2(payload: &[u8]) -> Option<[u8; 2]> {
    let country = find(body(payload)?, ATTR_REG_ALPHA2)?;
    country.payload.first_chunk().copied()
}

/// The events that interface `ifindex` has in a datagram of the family `family`.
fn events_in(datagram: &[u8], family: u16, ifindex: u32) -> Vec<Event> {
    messages(datagram)
        .filter(|message| message.msg_type == family)
        .filter_map(|message| parse_event(message.payload, ifindex))
        .collect()
}

/// A client of nl80211: one socket for requests and one for the events the
/// kernel announces on its own.
pub struct Nl80211 {
    commands: NlSocket,
    events: NlSocket,
    family: u16,
}

impl Nl80211 {
    /// Looks up nl80211 and listens to its `scan` and `mlme` groups.
    ///
    /// Fails with the kernel's error if the family is not there (no Wi-Fi
    /// driver is loaded), and with [`RequestError::Malformed`] if the kernel's
    /// description lacks either group.
    ///
    /// # Panics
    ///
    /// Outside a tokio runtime.
    pub async fn open() -> Result<Self, RequestError> {
        Self::open_with(NlSocket::open(NetlinkProtocol::Generic)?).await
    }

    /// `open`, with the command socket's requests sent by a thread of its own: a Wi-Fi driver runs
    /// a command's handler inside the send, and one that does not answer holds it for seconds. The
    /// events socket only reads, and stays as it is. See [`NlSocket::open_offloaded`].
    ///
    /// # Panics
    ///
    /// Outside a tokio runtime.
    pub async fn open_offloaded() -> Result<Self, RequestError> {
        Self::open_with(NlSocket::open_offloaded(NetlinkProtocol::Generic)?).await
    }

    /// Whether the command socket's requests are sent by a thread of its own.
    #[cfg(test)]
    pub(crate) fn is_offloaded(&self) -> bool {
        self.commands.is_offloaded()
    }

    /// Looks nl80211 up over `commands`, which then is the command socket.
    async fn open_with(mut commands: NlSocket) -> Result<Self, RequestError> {
        let replies = commands.request(get_family(FAMILY_NAME)).await?;
        let family = replies
            .iter()
            .find_map(|reply| parse_family(reply))
            .ok_or(RequestError::Malformed)?;
        let scan = family.group(GROUP_SCAN).ok_or(RequestError::Malformed)?;
        let mlme = family.group(GROUP_MLME).ok_or(RequestError::Malformed)?;
        let events = NlSocket::open(NetlinkProtocol::Generic)?;
        events.join_group(scan)?;
        events.join_group(mlme)?;
        Ok(Self {
            commands,
            events,
            family: family.id,
        })
    }

    /// The message type of nl80211's messages, for building requests.
    pub fn family(&self) -> u16 {
        self.family
    }

    /// Sends a request and returns the payloads of its reply.
    pub async fn request(&mut self, message: MsgBuilder) -> Result<Vec<Vec<u8>>, RequestError> {
        self.commands.request(message).await
    }

    /// Waits for a datagram of events and returns those about `ifindex`, in
    /// order. The list is empty when the datagram held none of them.
    ///
    /// Dropping the future loses nothing. An error of `ENOBUFS` means events
    /// were lost: the caller should read the state again.
    pub async fn events(&mut self, ifindex: u32) -> io::Result<Vec<Event>> {
        let datagram = self.events.recv().await?;
        Ok(events_in(&datagram, self.family, ifindex))
    }

    /// The country of the regulatory domain that applies to the whole system;
    /// `00` is the world's.
    pub async fn country(&mut self) -> Result<[u8; 2], RequestError> {
        let replies = self.request(get_reg(self.family)).await?;
        replies
            .iter()
            .find_map(|reply| parse_reg_alpha2(reply))
            .ok_or(RequestError::Malformed)
    }

    /// Asks for the country every 250 ms until it is `want` or `limit` has
    /// passed, and returns the last answer.
    pub async fn wait_for_country(
        &mut self,
        want: [u8; 2],
        limit: Duration,
    ) -> Result<[u8; 2], RequestError> {
        let deadline = Instant::now() + limit;
        loop {
            let answer = self.country().await?;
            let now = Instant::now();
            if answer == want || now >= deadline {
                return Ok(answer);
            }
            tokio::time::sleep_until((now + COUNTRY_POLL).min(deadline)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::netlink::messages;
    use hex_literal::hex;

    /// The nl80211 family's id, as the golden messages have it.
    const F: u16 = 28;
    /// The IEEE sample address of an access point.
    const AA: [u8; 6] = hex!("a0a1a1a3a4a5");
    /// An RSN element: WPA2, CCMP for the group and the pair, PSK.
    const RSNE: [u8; 22] = hex!("30140100000fac040100000fac040100000fac020000");
    const TK: [u8; 16] = hex!("b2360c79e9710fdd58bea93deaf06599");
    const GTK1: [u8; 16] = hex!("00112233445566778899aabbccddeeff");

    #[test]
    fn commands_match_the_kernels_layout() {
        assert_eq!(
            get_family("nl80211").finish(7),
            hex!("20000000100005000700000000000000030100000c0002006e6c383032313100")
        );
        assert_eq!(
            get_reg(F).finish(7),
            hex!("140000001c00050007000000000000001f000000")
        );
        assert_eq!(
            set_power_save_off(F, 3).finish(7),
            hex!("240000001c00050007000000000000003d000000080003000300000008005d0000000000")
        );
        assert_eq!(
            trigger_scan(F, 3, b"ThisIsASSID", &[]).finish(7),
            hex!(
                "380000001c000500070000000000000021000000080003000300000014002d800f00010054686973497341535349440008009e0002000000"
            )
        );
        // The same request for one channel: a nest of one frequency (5180 MHz) before the name.
        assert_eq!(
            trigger_scan(F, 3, b"ThisIsASSID", &[5180]).finish(7),
            hex!(
                "440000001c00050007000000000000002100000008000300030000000c002c8008000100 3c140000 14002d800f00010054686973497341535349440008009e0002000000"
            )
        );
        // And for two, numbered from 1 in the order given (5180 and 2437 MHz).
        assert_eq!(
            trigger_scan(F, 3, b"ThisIsASSID", &[5180, 2437]).finish(7),
            hex!(
                "4c0000001c00050007000000000000002100000008000300030000001400 2c80 08000100 3c140000 08000200 85090000 14002d800f00010054686973497341535349440008009e0002000000"
            )
        );
        assert_eq!(
            get_scan(F, 3).finish(7),
            hex!("1c0000001c0001030700000000000000200000000800030003000000")
        );
        assert_eq!(
            disconnect(F, 3, 3).finish(7),
            hex!("240000001c00050007000000000000003000000008000300030000000600360003000000")
        );
        // A single query, not a dump: the request and an acknowledgement, the interface and the address.
        assert_eq!(
            get_station(F, 3, AA).finish(7),
            hex!(
                "280000001c00050007000000000000001100000008000300030000000a000600a0a1a1a3a4a50000"
            )
        );
        assert_eq!(
            set_station_authorized(F, 3, AA).finish(7),
            hex!(
                "340000001c00050007000000000000001200000008000300030000000a000600a0a1a1a3a4a500000c0043000200000002000000"
            )
        );
    }

    #[test]
    fn connect_carries_the_bss_and_wpa2_psk_ccmp() {
        let target = ConnectTarget {
            ssid: b"ThisIsASSID",
            bssid: AA,
            freq_mhz: 5180,
            rsne: &RSNE,
        };
        assert_eq!(
            connect(F, 3, &target).finish(7),
            hex!(
                "8c0000001c00050007000000000000002e00000008000300030000000f0034005468697349734153534944000a000600a0a1a1a3a4a50000080026003c1400001a002a0030140100000fac040100000fac040100000fac020000000008003500000000000400460008004b00020000000800490004ac0f0008004a0004ac0f0008004c0002ac0f0004004400"
            )
        );
    }

    #[test]
    fn keys_are_laid_out_as_the_kernel_parses_them() {
        assert_eq!(
            new_pairwise_key(F, 3, AA, &TK).finish(7),
            hex!(
                "580000001c00050007000000000000000b00000008000300030000000a000600a0a1a1a3a4a500003000508014000100b2360c79e9710fdd58bea93deaf065990800030004ac0f0005000200000000000800070001000000"
            )
        );
        assert_eq!(
            new_group_key(F, 3, 1, &GTK1, &hex!("112233445566")).finish(7),
            hex!(
                "580000001c00050007000000000000000b00000008000300030000003c0050801400010000112233445566778899aabbccddeeff0800030004ac0f0005000200010000000a00040011223344556600000800070000000000"
            )
        );
    }

    /// The payload of a message of the family: the generic header with
    /// command `cmd`, then what `fill` adds.
    fn payload_of(cmd: u8, fill: impl FnOnce(MsgBuilder) -> MsgBuilder) -> Vec<u8> {
        let datagram = fill(MsgBuilder::new(F, 0).header(&[cmd, 1, 0, 0])).finish(0);
        messages(&datagram).next().unwrap().payload.to_vec()
    }

    /// The reply to a family lookup, as the kernel builds it.
    fn family_reply() -> Vec<u8> {
        payload_of(1, |reply| {
            reply
                .attr_u16(1, 28)
                .attr_str(2, "nl80211")
                .nest(7, |groups| {
                    groups
                        .nest(1, |g| g.attr_str(1, "scan").attr_u32(2, 25))
                        .nest(2, |g| g.attr_str(1, "mlme").attr_u32(2, 27))
                })
        })
    }

    #[test]
    fn a_family_reply_gives_the_id_and_the_groups() {
        let family = parse_family(&family_reply()).unwrap();
        assert_eq!(
            family,
            Family {
                id: 28,
                groups: vec![("scan".into(), 25), ("mlme".into(), 27)]
            }
        );
        assert_eq!(family.group("mlme"), Some(27));
        assert_eq!(family.group("scan"), Some(25));
        assert_eq!(family.group("nan"), None);

        // Without its id, it is not a family.
        let nameless = payload_of(1, |reply| reply.attr_str(2, "nl80211"));
        assert_eq!(parse_family(&nameless), None);
        // Without groups, it is a family that has none.
        let bare = payload_of(1, |reply| reply.attr_u16(1, 28));
        assert_eq!(
            parse_family(&bare),
            Some(Family {
                id: 28,
                groups: vec![]
            })
        );
        // A group that lacks its name or its id is left out; the others stay.
        let partial = payload_of(1, |reply| {
            reply.attr_u16(1, 28).nest(7, |groups| {
                groups
                    .nest(1, |g| g.attr_u32(2, 25))
                    .nest(2, |g| g.attr_str(1, "config"))
                    .nest(3, |g| g.attr_str(1, "mlme").attr_u32(2, 27))
            })
        });
        assert_eq!(
            parse_family(&partial).unwrap().groups,
            [("mlme".to_owned(), 27)]
        );
        // Too short to hold the generic header.
        assert_eq!(parse_family(&[]), None);
        assert_eq!(parse_family(&[1, 1, 0]), None);
    }

    #[test]
    fn a_station_reply_gives_the_address_it_describes() {
        // What the kernel sends for a station: the interface, the address, then its state in a nest.
        let station = |cmd| {
            payload_of(cmd, |reply| {
                reply
                    .attr_u32(3, 3)
                    .attr(6, &AA)
                    .nest(21, |info| info.attr_u32(1, 1000))
            })
        };
        assert_eq!(parse_station(&station(CMD_NEW_STATION)), Some(AA));

        // Another command is not a station message, whatever it holds.
        assert_eq!(parse_station(&station(CMD_NEW_SCAN_RESULTS)), None);
        // Without an address, or with one that is not six bytes, there is no station.
        let bare = payload_of(CMD_NEW_STATION, |reply| reply.attr_u32(3, 3));
        assert_eq!(parse_station(&bare), None);
        let short = payload_of(CMD_NEW_STATION, |reply| reply.attr(6, &AA[..4]));
        assert_eq!(parse_station(&short), None);
        // Too short to hold the generic header.
        assert_eq!(parse_station(&[]), None);
        assert_eq!(parse_station(&[CMD_NEW_STATION, 1, 0]), None);
    }

    /// The information elements a scan result carries: an SSID `abc`, then the RSN element.
    fn bss_ies() -> Vec<u8> {
        [&hex!("0003616263")[..], &RSNE[..]].concat()
    }

    /// A scan result, the way a dump of the scan list holds it.
    fn scan_reply() -> Vec<u8> {
        payload_of(34, |reply| {
            reply.attr_u32(3, 3).nest(47, |bss| {
                bss.attr(1, &AA)
                    .attr_u32(2, 5180)
                    .attr(7, &(-5600i32).to_ne_bytes())
                    .attr(6, &bss_ies())
            })
        })
    }

    #[test]
    fn a_scan_result_is_read() {
        assert_eq!(
            parse_bss(&scan_reply()),
            Some(Bss {
                bssid: AA,
                freq_mhz: 5180,
                signal_mbm: -5600,
                ies: bss_ies()
            })
        );

        // The signal and the elements may be absent; the address and the
        // frequency may not.
        let nest = |fill: fn(MsgBuilder) -> MsgBuilder| payload_of(34, |r| r.nest(47, fill));
        let no_signal = nest(|b| b.attr(1, &AA).attr_u32(2, 2412).attr(6, &[0, 0]));
        assert_eq!(
            parse_bss(&no_signal),
            Some(Bss {
                bssid: AA,
                freq_mhz: 2412,
                signal_mbm: i32::MIN,
                ies: vec![0, 0]
            })
        );
        let no_ies = nest(|b| b.attr(1, &AA).attr_u32(2, 2412).attr(7, &[0xff; 4]));
        assert_eq!(
            parse_bss(&no_ies),
            Some(Bss {
                bssid: AA,
                freq_mhz: 2412,
                signal_mbm: -1,
                ies: vec![]
            })
        );
        assert_eq!(parse_bss(&nest(|b| b.attr_u32(2, 2412))), None);
        assert_eq!(parse_bss(&nest(|b| b.attr(1, &AA))), None);
        assert_eq!(parse_bss(&nest(|b| b)), None);
        assert_eq!(parse_bss(&payload_of(34, |r| r.attr_u32(3, 3))), None);
        assert_eq!(parse_bss(&[]), None);
    }

    #[test]
    fn events_are_told_apart() {
        let ev = |payload: Vec<u8>| parse_event(&payload, 3);
        // 34 and 35: a scan ended, or was cut short.
        assert_eq!(
            ev(payload_of(34, |b| b.attr_u32(3, 3))),
            Some(Event::ScanDone)
        );
        assert_eq!(
            ev(payload_of(35, |b| b.attr_u32(3, 3))),
            Some(Event::ScanAborted)
        );
        // Another interface's event is not this one's.
        assert_eq!(ev(payload_of(34, |b| b.attr_u32(3, 4))), None);
        // 46: a connection attempt that worked, with and without its request elements.
        assert_eq!(
            ev(payload_of(46, |b| b
                .attr_u32(3, 3)
                .attr(6, &AA)
                .attr_u16(72, 0)
                .attr(77, &RSNE))),
            Some(Event::Connected {
                bssid: AA,
                req_ies: RSNE.to_vec()
            })
        );
        assert_eq!(
            ev(payload_of(46, |b| b
                .attr_u32(3, 3)
                .attr(6, &AA)
                .attr_u16(72, 0))),
            Some(Event::Connected {
                bssid: AA,
                req_ies: vec![]
            })
        );
        // 46: one that did not.
        assert_eq!(
            ev(payload_of(46, |b| b
                .attr_u32(3, 3)
                .attr_u16(72, 16)
                .attr_flag(65))),
            Some(Event::ConnectFailed {
                status: 16,
                timed_out: true
            })
        );
        assert_eq!(
            ev(payload_of(46, |b| b.attr_u32(3, 3))),
            Some(Event::ConnectFailed {
                status: 65535,
                timed_out: false
            })
        );
        // 48: the link went away, by the access point's doing or not.
        assert_eq!(
            ev(payload_of(48, |b| b
                .attr_u32(3, 3)
                .attr_u16(54, 15)
                .attr_flag(71))),
            Some(Event::Disconnected {
                reason: 15,
                by_ap: true
            })
        );
        assert_eq!(
            ev(payload_of(48, |b| b.attr_u32(3, 3))),
            Some(Event::Disconnected {
                reason: 0,
                by_ap: false
            })
        );
        // 47: the station moved to another access point of the same network.
        assert_eq!(
            ev(payload_of(47, |b| b.attr_u32(3, 3).attr(6, &AA))),
            Some(Event::Roamed { bssid: AA })
        );
        // Anything else, with no interface named, is passed on as it is.
        assert_eq!(ev(payload_of(36, |b| b)), Some(Event::Other(36)));

        // A success that does not say who it is with is not one.
        assert_eq!(
            ev(payload_of(46, |b| b.attr_u32(3, 3).attr_u16(72, 0))),
            Some(Event::ConnectFailed {
                status: 0,
                timed_out: false
            })
        );
        // An interface number that is not a number is not this interface.
        assert_eq!(ev(payload_of(34, |b| b.attr(3, &[3]))), None);
        // Too short to hold the generic header.
        assert_eq!(ev(vec![34]), None);
        assert_eq!(ev(vec![]), None);

        // A datagram's events are the family's own, for the interface, in order.
        let datagram = [
            MsgBuilder::new(F, 0)
                .header(&[34, 1, 0, 0])
                .attr_u32(3, 3)
                .finish(0),
            MsgBuilder::new(F, 0)
                .header(&[35, 1, 0, 0])
                .attr_u32(3, 4)
                .finish(0),
            // Not the family's: the kernel's own marker, which holds no event.
            MsgBuilder::new(crate::netlink::NLMSG_ERROR, 0)
                .header(&[48, 1, 0, 0])
                .finish(0),
            MsgBuilder::new(F, 0)
                .header(&[35, 1, 0, 0])
                .attr_u32(3, 3)
                .finish(0),
        ]
        .concat();
        assert_eq!(
            events_in(&datagram, F, 3),
            [Event::ScanDone, Event::ScanAborted]
        );
        assert_eq!(events_in(&datagram, F + 1, 3), []);
        assert_eq!(events_in(&[], F, 3), []);
    }

    #[test]
    fn the_regulatory_reply_gives_the_country() {
        let reg = |country: &[u8]| payload_of(31, |reply| reply.attr(33, country));
        assert_eq!(parse_reg_alpha2(&reg(b"US\0")), Some(*b"US"));
        assert_eq!(parse_reg_alpha2(&reg(b"00\0")), Some(*b"00"));
        assert_eq!(parse_reg_alpha2(&reg(b"U")), None);
        assert_eq!(parse_reg_alpha2(&reg(b"")), None);
        assert_eq!(parse_reg_alpha2(&payload_of(31, |reply| reply)), None);
        assert_eq!(parse_reg_alpha2(&[]), None);
    }

    /// Reads `payload` through all four parsers.
    fn parse_all(payload: &[u8]) {
        let _ = parse_family(payload);
        let _ = parse_bss(payload);
        let _ = parse_event(payload, 3);
        let _ = parse_reg_alpha2(payload);
    }

    #[test]
    fn malformed_replies_never_panic() {
        let connected = payload_of(46, |b| {
            b.attr_u32(3, 3)
                .attr(6, &AA)
                .attr_u16(72, 0)
                .attr(77, &RSNE)
        });
        let regulatory = payload_of(31, |reply| reply.attr(33, b"US\0"));
        // Each fixture is read as it is, so that the sweep is not reading nothing.
        assert!(parse_family(&family_reply()).is_some());
        assert!(parse_bss(&scan_reply()).is_some());
        assert!(matches!(
            parse_event(&connected, 3),
            Some(Event::Connected { .. })
        ));
        assert!(parse_reg_alpha2(&regulatory).is_some());

        for original in [family_reply(), scan_reply(), connected, regulatory] {
            parse_all(&original);
            // Every truncation...
            for end in 0..original.len() {
                parse_all(&original[..end]);
            }
            // ...and every byte changed in the ways the wire layer's sweep does.
            for at in 0..original.len() {
                let byte = original[at];
                for changed in [0x00, 0xff, byte ^ 0x01, byte ^ 0x80] {
                    let mut damaged = original.clone();
                    damaged[at] = changed;
                    parse_all(&damaged);
                }
            }
        }
    }

    #[test]
    fn the_kernel_answers_for_nl80211() {
        crate::testns::run_inside("netlink::nl80211::tests::ns_family");
    }

    #[tokio::test]
    #[ignore = "run by the_kernel_answers_for_nl80211, inside a namespace"]
    async fn ns_family() {
        if !crate::testns::inside() {
            return;
        }
        if !std::path::Path::new("/sys/module/cfg80211").exists() {
            println!("note: no cfg80211 on this machine, so no nl80211 to ask");
            return;
        }
        // Looking up the family and reading the global regulatory domain are
        // the only things asked of the kernel here.
        let mut wifi = Nl80211::open().await.unwrap();
        assert_ne!(wifi.family(), 0);
        let country = wifi.country().await.unwrap();
        assert!(
            country
                .iter()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()),
            "{country:?}"
        );
        // Already what is wanted: one answer, no wait.
        let started = std::time::Instant::now();
        let limit = Duration::from_secs(5);
        assert_eq!(
            wifi.wait_for_country(country, limit).await.unwrap(),
            country
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        // Never what is wanted: the last answer, once the limit has passed.
        let started = std::time::Instant::now();
        let never = *b"ZZ";
        let limit = Duration::from_millis(600);
        let last = wifi.wait_for_country(never, limit).await.unwrap();
        assert_eq!(last, country);
        assert!(started.elapsed() >= limit);
    }
}
