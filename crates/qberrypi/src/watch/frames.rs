//! Parsers for what the device watch reads off the home network: ARP frames, DHCP requests and
//! mDNS announcements.
//!
//! Each parser takes bytes that anybody on the network may have sent and gives back only what is
//! well formed: a length or a count that reaches past the end of the data, a name whose
//! compression pointers do not lead backwards, or a header that is not the one of IPv4 over
//! Ethernet makes the whole thing `None`, or, for mDNS, makes the walk stop. Nothing here panics
//! for any input, allocates but for the host name that is returned, reads a clock, does I/O or
//! logs: a MAC, an address or a host name never reaches a log line from this file, and the
//! address type prints as `Mac(..)` for the same reason.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use super::be16;

/// The longest host name that is kept, in bytes.
pub const HOSTNAME_MAX: usize = 63;

/// How many records of an mDNS message are looked at, the answers, the authority records and the
/// additional records together.
pub const MDNS_RECORDS_MAX: usize = 64;

/// How many compression pointers a name may be followed through.
pub const NAME_JUMPS_MAX: usize = 16;

/// The operation of an ARP request, "who has".
pub const ARP_REQUEST: u16 = 1;

/// The operation of an ARP reply, "is at".
pub const ARP_REPLY: u16 = 2;

/// The DHCP message type of a DISCOVER.
pub const DHCP_DISCOVER: u8 = 1;

/// The DHCP message type of a REQUEST.
pub const DHCP_REQUEST: u8 = 3;

/// The length of an Ethernet header: two addresses and the type.
const ETHERNET_HEADER: usize = 14;
/// The place of the Ethernet type in a frame.
const ETHERTYPE_AT: usize = 12;
/// The Ethernet type of ARP.
const ETHERTYPE_ARP: u16 = 0x0806;
/// The Ethernet type of an 802.1Q tag, which is followed by two bytes of tag and the real type.
const ETHERTYPE_VLAN: u16 = 0x8100;
/// The length of an ARP message for IPv4 over Ethernet.
const ARP_LEN: usize = 28;
/// The ARP hardware type of Ethernet.
const ARP_HTYPE_ETHERNET: u16 = 1;
/// The ARP protocol type of IPv4.
const ARP_PTYPE_IPV4: u16 = 0x0800;

/// The length of the fixed part of a BOOTP message, up to where the magic cookie is.
const BOOTP_FIXED: usize = 236;
/// The magic cookie that starts the options of a DHCP message.
const DHCP_COOKIE: [u8; 4] = [99, 130, 83, 99];
/// The BOOTP operation of a request from a client.
const BOOTREQUEST: u8 = 1;
/// The BOOTP hardware type of Ethernet.
const BOOTP_HTYPE_ETHERNET: u8 = 1;
/// The length of an Ethernet address, in a BOOTP message and in an ARP one.
const MAC_LEN: u8 = 6;
/// The DHCP option that pads.
const OPTION_PAD: u8 = 0;
/// The DHCP option that ends the options.
const OPTION_END: u8 = 255;
/// The DHCP option of the host name.
const OPTION_HOSTNAME: u8 = 12;
/// The DHCP option of the address that the client asks for.
const OPTION_REQUESTED_IP: u8 = 50;
/// The DHCP option of the message type.
const OPTION_MESSAGE_TYPE: u8 = 53;

/// The length of a DNS header.
const DNS_HEADER: usize = 12;
/// The place of the flags in a DNS header.
const DNS_FLAGS_AT: usize = 2;
/// The bit of the flags that says the message is a response.
const DNS_RESPONSE: u16 = 0x8000;
/// The most bytes that a name has on the wire, the zero of the root included.
const NAME_WIRE_MAX: usize = 255;
/// The top two bits of a length byte.
const LABEL_BITS: u8 = 0xC0;
/// The top two bits of a length byte that mark a compression pointer.
const POINTER_BITS: u8 = 0xC0;
/// The bytes of a record after its name and before its data: type, class, TTL and data length.
const RECORD_FIXED: usize = 10;
/// The DNS record type of an A record.
const TYPE_A: u16 = 1;
/// The DNS class of the Internet, with the cache-flush bit of mDNS taken off.
const CLASS_IN: u16 = 1;
/// The bit of the class that mDNS uses for "flush your cache"; it is not part of the class.
const CACHE_FLUSH: u16 = 0x8000;
/// The suffix of the names that mDNS answers for.
const LOCAL_SUFFIX: &[u8] = b".local";

/// The Ethernet address of a device.
///
/// It prints as `02:00:00:00:00:01`, and its `Debug` as `Mac(..)`: an address that ends up in a
/// log line by accident would say which device is on the network.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Mac(pub [u8; 6]);

impl Mac {
    /// Whether this can be the address of one device: not all zeros, and not a broadcast or
    /// multicast address (the low bit of the first byte clear).
    pub fn can_be_a_device(self) -> bool {
        self.0 != [0; 6] && self.0[0] & 1 == 0
    }
}

impl fmt::Display for Mac {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, f] = self.0;
        write!(out, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}")
    }
}

impl fmt::Debug for Mac {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("Mac(..)")
    }
}

/// The text is not six pairs of hexadecimal digits that one `:` or one `-` separates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseMacError;

impl fmt::Display for ParseMacError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("not an Ethernet address of six pairs of hexadecimal digits")
    }
}

impl std::error::Error for ParseMacError {}

impl FromStr for Mac {
    type Err = ParseMacError;

    /// Reads `02:00:00:00:00:01`, or the same with `-`, in lower or upper case. The separators
    /// must all be the same one.
    fn from_str(text: &str) -> Result<Self, ParseMacError> {
        let bytes = text.as_bytes();
        if bytes.len() != 17 {
            return Err(ParseMacError);
        }
        let separator = *bytes.get(2).ok_or(ParseMacError)?;
        if separator != b':' && separator != b'-' {
            return Err(ParseMacError);
        }
        let mut mac = [0u8; 6];
        for (n, octet) in mac.iter_mut().enumerate() {
            let at = n * 3;
            if n > 0 && bytes.get(at - 1) != Some(&separator) {
                return Err(ParseMacError);
            }
            let high = hex_digit(*bytes.get(at).ok_or(ParseMacError)?)?;
            let low = hex_digit(*bytes.get(at + 1).ok_or(ParseMacError)?)?;
            *octet = (high << 4) | low;
        }
        Ok(Mac(mac))
    }
}

/// The value of the hexadecimal digit `digit`, in either case.
fn hex_digit(digit: u8) -> Result<u8, ParseMacError> {
    char::from(digit)
        .to_digit(16)
        .and_then(|value| u8::try_from(value).ok())
        .ok_or(ParseMacError)
}

/// An ARP message for IPv4 over Ethernet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arp {
    /// What the message is: [`ARP_REQUEST`], [`ARP_REPLY`] or something else.
    pub op: u16,
    /// The hardware address of the sender, as the message says.
    pub sender_mac: Mac,
    /// The address of the sender, which a gratuitous ARP shares with `target_ip`.
    pub sender_ip: Ipv4Addr,
    /// The address that is asked about, or that the reply is for.
    pub target_ip: Ipv4Addr,
}

/// The ARP message in `frame`, a whole Ethernet frame: the header of 14 bytes, with or without
/// one 802.1Q tag, and the message of IPv4 over Ethernet. `None` for any other frame, for one
/// that is cut short, and for a hardware or protocol that is not Ethernet and IPv4. Bytes after
/// the message, as the padding of a short frame, are ignored.
pub fn parse_arp(frame: &[u8]) -> Option<Arp> {
    let mut start = ETHERNET_HEADER;
    let mut ethertype = be16(frame, ETHERTYPE_AT)?;
    if ethertype == ETHERTYPE_VLAN {
        // The tag is two bytes of priority and VLAN, then the type of what follows.
        ethertype = be16(frame, ETHERTYPE_AT + 4)?;
        start += 4;
    }
    if ethertype != ETHERTYPE_ARP {
        return None;
    }
    let arp = frame.get(start..start + ARP_LEN)?;
    if be16(arp, 0)? != ARP_HTYPE_ETHERNET
        || be16(arp, 2)? != ARP_PTYPE_IPV4
        || *arp.get(4)? != MAC_LEN
        || *arp.get(5)? != 4
    {
        return None;
    }
    Some(Arp {
        op: be16(arp, 6)?,
        sender_mac: mac_at(arp, 8)?,
        sender_ip: ipv4_at(arp, 14)?,
        // The target's hardware address, at 18, is not asked for.
        target_ip: ipv4_at(arp, 24)?,
    })
}

/// A DHCP request, as far as the device watch reads it.
#[derive(Clone, PartialEq, Eq)]
pub struct Dhcp {
    /// The DHCP message type of option 53: [`DHCP_DISCOVER`], [`DHCP_REQUEST`] or another.
    pub msg_type: Option<u8>,
    /// The hardware address of the client, `chaddr`.
    pub chaddr: Mac,
    /// The address that the client says it has, `ciaddr`; 0.0.0.0 for a client that has none.
    pub ciaddr: Ipv4Addr,
    /// The address that the client asks for, option 50.
    pub requested_ip: Option<Ipv4Addr>,
    /// The host name of option 12, as [`sanitize_hostname`] makes it.
    pub hostname: Option<String>,
}

/// A DHCP request shows its message type, and never what it says about the client: it may end up
/// in a log line.
impl fmt::Debug for Dhcp {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("Dhcp")
            .field("msg_type", &self.msg_type)
            .finish_non_exhaustive()
    }
}

/// The DHCP request in `payload`, the payload of a UDP datagram: a BOOTREQUEST for an Ethernet
/// client of 6 bytes of hardware address, with the magic cookie after the fixed part of 236
/// bytes. The options are walked with every length checked: pad and end are understood, a
/// length that reaches past the end of the data makes the message `None`, a second option of the
/// same kind does not replace the first, and an option overload (option 52) is not followed.
/// Options of the wrong size for their kind are skipped.
pub fn parse_dhcp(payload: &[u8]) -> Option<Dhcp> {
    let fixed = payload.get(..BOOTP_FIXED + DHCP_COOKIE.len())?;
    if *fixed.first()? != BOOTREQUEST
        || *fixed.get(1)? != BOOTP_HTYPE_ETHERNET
        || *fixed.get(2)? != MAC_LEN
        || fixed.get(BOOTP_FIXED..)? != DHCP_COOKIE
    {
        return None;
    }
    let mut request = Dhcp {
        msg_type: None,
        chaddr: mac_at(fixed, 28)?,
        ciaddr: ipv4_at(fixed, 12)?,
        requested_ip: None,
        hostname: None,
    };
    let mut at = fixed.len();
    while let Some(&code) = payload.get(at) {
        at += 1;
        match code {
            OPTION_PAD => continue,
            OPTION_END => break,
            _ => {}
        }
        let len = usize::from(*payload.get(at)?);
        let data = payload.get(at + 1..at + 1 + len)?;
        at += 1 + len;
        match (code, data) {
            (OPTION_MESSAGE_TYPE, &[kind]) => {
                request.msg_type.get_or_insert(kind);
            }
            (OPTION_REQUESTED_IP, &[a, b, c, d]) => {
                request
                    .requested_ip
                    .get_or_insert(Ipv4Addr::new(a, b, c, d));
            }
            (OPTION_HOSTNAME, raw) if request.hostname.is_none() => {
                request.hostname = sanitize_hostname(raw);
            }
            _ => {}
        }
    }
    Some(request)
}

/// Calls `found` with the address and the host name of each A record in `payload`, the payload
/// of an mDNS datagram, whose owner name ends in `.local`. The host name is the owner name
/// without that suffix, as [`sanitize_hostname`] makes it.
///
/// Only responses are read: the bit `QR` of the flags must be set. The answers, the authority
/// records and the additional records are walked together, at most [`MDNS_RECORDS_MAX`] of them,
/// and the walk stops at a record that is not all there. The class may carry the cache-flush
/// bit. A name is decoded through compression pointers that lead backwards only, at most
/// [`NAME_JUMPS_MAX`] of them, and into at most 255 bytes of wire form; an A record whose name is
/// not that is skipped.
pub fn parse_mdns(payload: &[u8], found: &mut impl FnMut(Ipv4Addr, &str)) {
    let (Some(flags), Some(questions), Some(answers), Some(authority), Some(additional)) = (
        be16(payload, DNS_FLAGS_AT),
        be16(payload, 4),
        be16(payload, 6),
        be16(payload, 8),
        be16(payload, 10),
    ) else {
        return;
    };
    // A query, or a message with many questions, is no announcement.
    if (flags & DNS_RESPONSE) == 0 || usize::from(questions) > MDNS_RECORDS_MAX {
        return;
    }
    let mut at = DNS_HEADER;
    for _ in 0..questions {
        let Some(end) = name_end(payload, at) else {
            return;
        };
        // The type and the class of the question.
        at = end + 4;
        if at > payload.len() {
            return;
        }
    }
    let records = usize::from(answers) + usize::from(authority) + usize::from(additional);
    for _ in 0..records.min(MDNS_RECORDS_MAX) {
        let Some(end) = name_end(payload, at) else {
            return;
        };
        let (Some(kind), Some(class), Some(len)) = (
            be16(payload, end),
            be16(payload, end + 2),
            be16(payload, end + 8),
        ) else {
            return;
        };
        let data_at = end + RECORD_FIXED;
        let Some(data) = payload.get(data_at..data_at + usize::from(len)) else {
            return;
        };
        if kind == TYPE_A
            && (class & !CACHE_FLUSH) == CLASS_IN
            && data.len() == 4
            && let (Some(addr), Some(host)) = (ipv4_at(data, 0), local_host(payload, at))
        {
            found(addr, &host);
        }
        at = data_at + usize::from(len);
    }
}

/// The host name of the owner name at `at` in `payload`, which is that name without `.local`,
/// sanitized; `None` for a name that does not decode or does not end so.
fn local_host(payload: &[u8], at: usize) -> Option<String> {
    let mut text = [0u8; NAME_WIRE_MAX];
    let len = decode_name(payload, at, &mut text)?;
    let name = text.get(..len)?;
    let host = name.get(..len.checked_sub(LOCAL_SUFFIX.len())?)?;
    let suffix = name.get(host.len()..)?;
    if host.is_empty() || !suffix.eq_ignore_ascii_case(LOCAL_SUFFIX) {
        return None;
    }
    sanitize_hostname(host)
}

/// Where the name that starts at `at` in `payload` ends: after its zero, or after the compression
/// pointer that ends it in place. `None` if it runs past the end of the data, has a label type
/// that no name has, or is longer than 255 bytes before a pointer.
fn name_end(payload: &[u8], mut at: usize) -> Option<usize> {
    let mut wire = 0;
    loop {
        let byte = *payload.get(at)?;
        match byte & LABEL_BITS {
            POINTER_BITS => {
                payload.get(at + 1)?;
                return Some(at + 2);
            }
            0 => {
                at += 1 + usize::from(byte);
                wire += 1 + usize::from(byte);
                if wire > NAME_WIRE_MAX {
                    return None;
                }
                if byte == 0 {
                    return Some(at);
                }
            }
            _ => return None,
        }
    }
}

/// Writes the name that starts at `start` in `payload` into `out` as text, its labels joined by
/// dots, and returns how long that is. The name may end in a compression pointer, which must lead
/// to a place before the pointer and not into the header; at most [`NAME_JUMPS_MAX`] pointers are
/// followed, so a chain that goes round cannot be followed for ever, and the name may be 255
/// bytes in wire form. `None` for anything else.
fn decode_name(payload: &[u8], start: usize, out: &mut [u8; NAME_WIRE_MAX]) -> Option<usize> {
    let (mut at, mut jumps, mut wire, mut len) = (start, 0, 1, 0);
    loop {
        let byte = *payload.get(at)?;
        match byte & LABEL_BITS {
            0 => {
                let label = usize::from(byte);
                if label == 0 {
                    return Some(len);
                }
                wire += 1 + label;
                if wire > NAME_WIRE_MAX {
                    return None;
                }
                let text = payload.get(at + 1..at + 1 + label)?;
                if len > 0 {
                    *out.get_mut(len)? = b'.';
                    len += 1;
                }
                out.get_mut(len..len + label)?.copy_from_slice(text);
                len += label;
                at += 1 + label;
            }
            POINTER_BITS => {
                let target =
                    (usize::from(byte & !LABEL_BITS) << 8) | usize::from(*payload.get(at + 1)?);
                jumps += 1;
                if jumps > NAME_JUMPS_MAX || target >= at || target < DNS_HEADER {
                    return None;
                }
                at = target;
            }
            _ => return None,
        }
    }
}

/// A host name that is safe to show and to keep, made of `raw`: the printable ASCII characters,
/// 0x21 to 0x7e, are kept, a space becomes `-`, every other byte is dropped, and the name is cut
/// to [`HOSTNAME_MAX`] bytes. `None` if nothing is left.
pub fn sanitize_hostname(raw: &[u8]) -> Option<String> {
    let mut name = String::with_capacity(raw.len().min(HOSTNAME_MAX));
    for &byte in raw {
        if name.len() == HOSTNAME_MAX {
            break;
        }
        match byte {
            0x21..=0x7e => name.push(char::from(byte)),
            b' ' => name.push('-'),
            _ => {}
        }
    }
    (!name.is_empty()).then_some(name)
}

/// The Ethernet address in the six bytes of `bytes` at `at`.
fn mac_at(bytes: &[u8], at: usize) -> Option<Mac> {
    Some(Mac(<[u8; 6]>::try_from(bytes.get(at..at + 6)?).ok()?))
}

/// The IPv4 address in the four bytes of `bytes` at `at`.
fn ipv4_at(bytes: &[u8], at: usize) -> Option<Ipv4Addr> {
    Some(Ipv4Addr::from(
        <[u8; 4]>::try_from(bytes.get(at..at + 4)?).ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashSet;

    /// A device of the locally administered range.
    const MAC_A: [u8; 6] = [2, 0, 0, 0, 0, 1];
    /// A second device.
    const MAC_B: [u8; 6] = [2, 0, 0, 0, 0, 2];
    /// The gateway of the documentation range.
    const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    /// A device of the documentation range.
    const DEVICE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
    /// Another device.
    const OTHER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 11);

    // ----- the address

    #[test]
    fn a_mac_prints_in_lower_case_pairs_with_colons() {
        assert_eq!(Mac(MAC_A).to_string(), "02:00:00:00:00:01");
        assert_eq!(
            Mac([0x0a, 0xBC, 0x00, 0xde, 0xf0, 0xff]).to_string(),
            "0a:bc:00:de:f0:ff"
        );
    }

    #[test]
    fn a_mac_is_read_with_colons_or_dashes_in_either_case() {
        for text in [
            "02:00:00:00:00:01",
            "02-00-00-00-00-01",
            "0A:bC:00:dE:F0:ff",
            "0a-BC-00-de-f0-FF",
        ] {
            let mac: Mac = text.parse().expect(text);
            assert_eq!(mac.to_string(), text.to_ascii_lowercase().replace('-', ":"));
        }
        assert_eq!("02:00:00:00:00:01".parse(), Ok(Mac(MAC_A)));
    }

    #[test]
    fn text_that_is_not_a_mac_is_not_read() {
        for text in [
            "",
            "02:00:00:00:00",
            "02:00:00:00:00:01:02",
            "02:00:00:00:00:0",
            "02:00:00:00:00:001",
            "02:00-00:00:00:01",
            "02-00:00-00-00-01",
            "02.00.00.00.00.01",
            "02 00 00 00 00 01",
            "0200:0000:0001",
            "02:00:00:00:00:0g",
            "02:00:00:00:00:+1",
            "02:00:00:00:00:\u{e9}",
            " 02:00:00:00:00:01",
            "02:00:00:00:00:01 ",
            "\u{e9}2:00:00:00:00:01",
        ] {
            assert_eq!(text.parse::<Mac>(), Err(ParseMacError), "{text:?}");
        }
        assert!(!ParseMacError.to_string().is_empty());
    }

    #[test]
    fn a_mac_shows_no_bytes_in_its_debug_form() {
        let shown = format!("{:?}", Mac([0x02, 0xAB, 0xCD, 0xEF, 0x12, 0x34]));
        assert_eq!(shown, "Mac(..)");
        // Nor does a message that holds one.
        let arp = parse_arp(&arp_frame(false, ARP_REPLY, MAC_A, DEVICE, MAC_B, OTHER)).unwrap();
        let shown = format!("{arp:?}");
        assert!(
            !shown.contains("[2, 0") && !shown.contains("02:00"),
            "{shown}"
        );
        assert!(shown.contains("Mac(..)"), "{shown}");
    }

    #[test]
    fn a_mac_is_a_value_that_is_copied_compared_ordered_and_hashed() {
        let (a, b) = (Mac(MAC_A), Mac(MAC_B));
        let copy = a;
        assert!(a == copy && a != b && a < b);
        let set: HashSet<Mac> = [a, b, copy].into_iter().collect();
        assert_eq!(set.len(), 2);
    }

    // ----- ARP

    /// An Ethernet frame with an ARP message, padded to the 60 bytes of the shortest frame; with
    /// an 802.1Q tag if `tag`.
    fn arp_frame(
        tag: bool,
        op: u16,
        sender: [u8; 6],
        sender_ip: Ipv4Addr,
        target: [u8; 6],
        target_ip: Ipv4Addr,
    ) -> Vec<u8> {
        let mut frame = vec![0xff; 6];
        frame.extend_from_slice(&sender);
        if tag {
            frame.extend_from_slice(&[0x81, 0x00, 0x20, 0x07]);
        }
        frame.extend_from_slice(&[0x08, 0x06, 0, 1, 8, 0, 6, 4]);
        frame.extend_from_slice(&op.to_be_bytes());
        frame.extend_from_slice(&sender);
        frame.extend_from_slice(&sender_ip.octets());
        frame.extend_from_slice(&target);
        frame.extend_from_slice(&target_ip.octets());
        frame.resize(60, 0);
        frame
    }

    /// The length of a frame of `arp_frame` without the padding.
    fn arp_len(tag: bool) -> usize {
        14 + if tag { 4 } else { 0 } + ARP_LEN
    }

    #[test]
    fn a_who_has_gives_its_operation_sender_and_target() {
        let frame = arp_frame(false, ARP_REQUEST, MAC_A, DEVICE, [0; 6], GATEWAY);
        assert_eq!(
            parse_arp(&frame),
            Some(Arp {
                op: 1,
                sender_mac: Mac(MAC_A),
                sender_ip: DEVICE,
                target_ip: GATEWAY
            })
        );
    }

    #[test]
    fn a_reply_gives_the_address_and_the_mac_that_it_claims() {
        let frame = arp_frame(false, ARP_REPLY, MAC_B, GATEWAY, MAC_A, DEVICE);
        let arp = parse_arp(&frame).unwrap();
        assert_eq!(
            (arp.op, arp.sender_mac, arp.sender_ip, arp.target_ip),
            (ARP_REPLY, Mac(MAC_B), GATEWAY, DEVICE)
        );
    }

    #[test]
    fn a_gratuitous_arp_has_the_same_sender_and_target_address() {
        for op in [ARP_REQUEST, ARP_REPLY] {
            let frame = arp_frame(false, op, MAC_A, DEVICE, [0; 6], DEVICE);
            let arp = parse_arp(&frame).unwrap();
            assert_eq!((arp.sender_ip, arp.target_ip), (DEVICE, DEVICE));
            assert_eq!(arp.sender_mac, Mac(MAC_A));
        }
    }

    #[test]
    fn a_frame_with_one_vlan_tag_is_read_like_one_without() {
        let plain = arp_frame(false, ARP_REPLY, MAC_A, DEVICE, MAC_B, OTHER);
        let tagged = arp_frame(true, ARP_REPLY, MAC_A, DEVICE, MAC_B, OTHER);
        assert_eq!(tagged.len(), 60);
        assert_eq!(parse_arp(&tagged), parse_arp(&plain));
        assert!(parse_arp(&tagged).is_some());
    }

    #[test]
    fn a_frame_longer_than_the_message_is_read_and_the_rest_is_ignored() {
        let mut frame = arp_frame(false, ARP_REQUEST, MAC_A, DEVICE, [0; 6], GATEWAY);
        frame.extend_from_slice(&[0xAA; 100]);
        assert_eq!(parse_arp(&frame).unwrap().target_ip, GATEWAY);
        // Exactly the message and nothing after it.
        frame.truncate(arp_len(false));
        assert!(parse_arp(&frame).is_some());
    }

    #[test]
    fn a_frame_that_is_not_arp_is_not_read() {
        let good = arp_frame(false, ARP_REQUEST, MAC_A, DEVICE, [0; 6], GATEWAY);
        // IPv4, IPv6, RARP, and a stacked or an 802.1ad tag: one tag only is accepted.
        for ethertype in [[0x08, 0x00], [0x86, 0xDD], [0x80, 0x35], [0x88, 0xA8]] {
            let mut frame = good.clone();
            frame[12..14].copy_from_slice(&ethertype);
            assert_eq!(parse_arp(&frame), None, "{ethertype:?}");
        }
        let mut stacked = arp_frame(true, ARP_REQUEST, MAC_A, DEVICE, [0; 6], GATEWAY);
        stacked[16..18].copy_from_slice(&[0x81, 0x00]);
        assert_eq!(parse_arp(&stacked), None);
        let mut tagged_ip = arp_frame(true, ARP_REQUEST, MAC_A, DEVICE, [0; 6], GATEWAY);
        tagged_ip[16..18].copy_from_slice(&[0x08, 0x00]);
        assert_eq!(parse_arp(&tagged_ip), None);
    }

    #[test]
    fn an_arp_message_that_is_not_ipv4_over_ethernet_is_not_read() {
        let good = arp_frame(false, ARP_REQUEST, MAC_A, DEVICE, [0; 6], GATEWAY);
        // Hardware type (14, 15), protocol type (16, 17), hardware length (18), protocol length (19).
        for (at, value) in [
            (15, 6),
            (14, 1),
            (17, 0x86),
            (16, 9),
            (18, 8),
            (18, 0),
            (19, 16),
            (19, 0),
        ] {
            let mut frame = good.clone();
            frame[at] = value;
            assert_eq!(parse_arp(&frame), None, "byte {at} = {value}");
        }
    }

    #[test]
    fn every_cut_of_an_arp_frame_is_not_read_and_does_not_panic() {
        for tag in [false, true] {
            let frame = arp_frame(tag, ARP_REPLY, MAC_A, DEVICE, MAC_B, OTHER);
            for cut in 0..arp_len(tag) {
                assert_eq!(parse_arp(&frame[..cut]), None, "tag {tag}, cut {cut}");
            }
            assert!(parse_arp(&frame[..arp_len(tag)]).is_some());
        }
        assert_eq!(parse_arp(&[]), None);
    }

    // ----- host names

    #[test]
    fn a_host_name_keeps_printable_ascii_turns_spaces_into_dashes_and_drops_the_rest() {
        assert_eq!(sanitize_hostname(b"laptop-01"), Some("laptop-01".into()));
        assert_eq!(
            sanitize_hostname(b"Sam's iPhone"),
            Some("Sam's-iPhone".into())
        );
        assert_eq!(
            sanitize_hostname(b"a\x00b\x1fc\x7fd\xffe\ttab\n"),
            Some("abcdetab".into())
        );
        // A multi-byte character goes byte by byte.
        assert_eq!(
            sanitize_hostname("caf\u{e9}".as_bytes()),
            Some("caf".into())
        );
        assert_eq!(sanitize_hostname(b"~!"), Some("~!".into()));
        // A name of only spaces is dashes, a name of nothing printable is nothing.
        assert_eq!(sanitize_hostname(b"  "), Some("--".into()));
        assert_eq!(sanitize_hostname(b""), None);
        assert_eq!(sanitize_hostname(b"\x00\x01\xff\x7f"), None);
    }

    #[test]
    fn a_host_name_is_cut_to_63_bytes_after_the_bytes_that_go_are_dropped() {
        assert_eq!(sanitize_hostname(&[b'a'; 63]).unwrap().len(), 63);
        assert_eq!(sanitize_hostname(&[b'a'; 64]).unwrap(), "a".repeat(63));
        assert_eq!(sanitize_hostname(&[b'a'; 500]).unwrap().len(), HOSTNAME_MAX);
        let mut raw = vec![0u8; 200];
        raw.extend_from_slice(b"abc");
        assert_eq!(sanitize_hostname(&raw), Some("abc".into()));
        let mut spaced = vec![b' '; 70];
        spaced.push(b'x');
        assert_eq!(sanitize_hostname(&spaced).unwrap(), "-".repeat(63));
    }

    // ----- DHCP

    /// One DHCP option: its code, its length and its data.
    fn option(code: u8, data: &[u8]) -> Vec<u8> {
        let mut out = vec![code, u8::try_from(data.len()).unwrap()];
        out.extend_from_slice(data);
        out
    }

    /// A BOOTP message of `op` for the client `MAC_A`, with ciaddr `ciaddr`, the cookie, and
    /// `options` after it.
    fn dhcp_message(op: u8, ciaddr: Ipv4Addr, options: &[u8]) -> Vec<u8> {
        let mut message = vec![0u8; BOOTP_FIXED];
        message[0] = op;
        message[1] = 1;
        message[2] = 6;
        message[4..8].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        message[12..16].copy_from_slice(&ciaddr.octets());
        message[28..34].copy_from_slice(&MAC_A);
        message.extend_from_slice(&DHCP_COOKIE);
        message.extend_from_slice(options);
        message
    }

    /// The options of a DHCPREQUEST from a client that has a name and asks for an address.
    fn request_options() -> Vec<u8> {
        let mut options = option(53, &[3]);
        options.extend(option(50, &DEVICE.octets()));
        options.extend(option(12, b"example-laptop"));
        options.extend(option(55, &[1, 3, 6, 15, 119]));
        options.push(255);
        options
    }

    #[test]
    fn a_dhcprequest_gives_its_type_client_requested_address_and_name() {
        let message = dhcp_message(1, Ipv4Addr::UNSPECIFIED, &request_options());
        let request = parse_dhcp(&message).unwrap();
        assert_eq!(request.msg_type, Some(DHCP_REQUEST));
        assert_eq!(request.chaddr, Mac(MAC_A));
        assert_eq!(request.ciaddr, Ipv4Addr::UNSPECIFIED);
        assert_eq!(request.requested_ip, Some(DEVICE));
        assert_eq!(request.hostname.as_deref(), Some("example-laptop"));
    }

    #[test]
    fn a_renewing_client_has_a_ciaddr_and_a_discover_has_neither_name_nor_address() {
        let renewing = dhcp_message(1, DEVICE, &request_options());
        assert_eq!(parse_dhcp(&renewing).unwrap().ciaddr, DEVICE);
        let mut options = option(53, &[1]);
        options.push(255);
        let discover = parse_dhcp(&dhcp_message(1, Ipv4Addr::UNSPECIFIED, &options)).unwrap();
        assert_eq!(discover.msg_type, Some(DHCP_DISCOVER));
        assert_eq!((discover.requested_ip, discover.hostname), (None, None));
    }

    #[test]
    fn a_message_with_a_cookie_and_no_options_is_read_with_nothing_in_it() {
        let request = parse_dhcp(&dhcp_message(1, Ipv4Addr::UNSPECIFIED, &[])).unwrap();
        assert_eq!(request.msg_type, None);
        assert_eq!(request.chaddr, Mac(MAC_A));
    }

    #[test]
    fn pads_are_skipped_the_end_stops_the_walk_and_a_missing_end_is_all_right() {
        let mut options = vec![0, 0];
        options.extend(option(53, &[1]));
        options.extend([0, 0, 0]);
        options.extend(option(12, b"padded"));
        let request = parse_dhcp(&dhcp_message(1, DEVICE, &options)).unwrap();
        assert_eq!(request.msg_type, Some(1));
        assert_eq!(request.hostname.as_deref(), Some("padded"));
        // Whatever comes after the end is not read, even a length that runs past the data.
        let mut options = option(53, &[3]);
        options.push(255);
        options.extend(option(12, b"after"));
        options.extend([50, 200]);
        let request = parse_dhcp(&dhcp_message(1, DEVICE, &options)).unwrap();
        assert_eq!((request.msg_type, request.hostname), (Some(3), None));
    }

    #[test]
    fn an_option_that_runs_past_the_end_makes_the_message_not_read() {
        let mut base = option(53, &[3]);
        base.extend(option(12, b"example-laptop"));
        // The length byte says 14 and one byte less is there.
        let mut cut = base.clone();
        cut.pop();
        assert!(parse_dhcp(&dhcp_message(1, DEVICE, &cut)).is_none());
        // A code with no length byte after it.
        let mut dangling = option(53, &[3]);
        dangling.push(12);
        assert!(parse_dhcp(&dhcp_message(1, DEVICE, &dangling)).is_none());
        // A length of 255 and nothing.
        assert!(parse_dhcp(&dhcp_message(1, DEVICE, &[12, 255])).is_none());
        // The same options whole are read.
        assert!(parse_dhcp(&dhcp_message(1, DEVICE, &base)).is_some());
    }

    #[test]
    fn a_bootreply_or_a_client_that_is_not_ethernet_or_a_missing_cookie_is_not_read() {
        let good = dhcp_message(1, DEVICE, &request_options());
        assert!(parse_dhcp(&good).is_some());
        // BOOTREPLY, and an operation that is neither.
        for op in [2, 0, 3] {
            assert!(parse_dhcp(&dhcp_message(op, DEVICE, &request_options())).is_none());
        }
        // htype and hlen.
        for (at, value) in [(1, 6), (1, 0), (2, 8), (2, 0)] {
            let mut message = good.clone();
            message[at] = value;
            assert!(parse_dhcp(&message).is_none(), "byte {at} = {value}");
        }
        // Each byte of the cookie.
        for at in BOOTP_FIXED..BOOTP_FIXED + 4 {
            let mut message = good.clone();
            message[at] ^= 1;
            assert!(parse_dhcp(&message).is_none(), "cookie byte {at}");
        }
        // A BOOTP message without options, and an empty one.
        assert!(parse_dhcp(&good[..BOOTP_FIXED]).is_none());
        assert!(parse_dhcp(&[]).is_none());
    }

    #[test]
    fn the_host_name_of_a_request_is_sanitized_and_cut() {
        let mut options = option(12, b"Sam's\x00 phone\xff\xfe");
        options.push(255);
        let request = parse_dhcp(&dhcp_message(1, DEVICE, &options)).unwrap();
        assert_eq!(request.hostname.as_deref(), Some("Sam's-phone"));
        let mut options = option(12, &[b'h'; 200]);
        options.push(255);
        let request = parse_dhcp(&dhcp_message(1, DEVICE, &options)).unwrap();
        assert_eq!(request.hostname, Some("h".repeat(63)));
        // A name of nothing printable is no name, and the message is still read.
        let mut options = option(12, &[0, 1, 2, 0xff]);
        options.extend(option(53, &[3]));
        let request = parse_dhcp(&dhcp_message(1, DEVICE, &options)).unwrap();
        assert_eq!((request.hostname, request.msg_type), (None, Some(3)));
    }

    #[test]
    fn options_of_the_wrong_size_are_skipped_and_the_first_of_a_kind_stays() {
        let mut options = option(53, &[3, 3]);
        options.extend(option(50, &[192, 0, 2]));
        options.extend(option(12, b"first"));
        options.extend(option(12, b"second"));
        options.extend(option(53, &[1]));
        options.extend(option(53, &[3]));
        options.extend(option(50, &OTHER.octets()));
        options.extend(option(50, &DEVICE.octets()));
        // Option overload and an option that is unknown are passed over.
        options.extend(option(52, &[3]));
        options.extend(option(224, b"vendor"));
        options.push(255);
        let request = parse_dhcp(&dhcp_message(1, DEVICE, &options)).unwrap();
        assert_eq!(request.msg_type, Some(1));
        assert_eq!(request.requested_ip, Some(OTHER));
        assert_eq!(request.hostname.as_deref(), Some("first"));
    }

    #[test]
    fn a_debug_print_of_a_dhcp_request_shows_no_name_or_address() {
        let message = dhcp_message(1, DEVICE, &request_options());
        let shown = format!("{:?}", parse_dhcp(&message).unwrap());
        assert!(
            !shown.contains("laptop") && !shown.contains("192.0.2") && !shown.contains("02:00"),
            "{shown}"
        );
        assert!(shown.contains("msg_type"), "{shown}");
    }

    #[test]
    fn every_cut_of_a_dhcp_message_does_not_panic_and_a_cut_inside_an_option_is_not_read() {
        let options = request_options();
        let message = dhcp_message(1, DEVICE, &options);
        // The offsets where an option ends, within the message.
        let mut boundaries = vec![BOOTP_FIXED + 4];
        let mut at = 0;
        while options[at] != 255 {
            at += 2 + usize::from(options[at + 1]);
            boundaries.push(BOOTP_FIXED + 4 + at);
        }
        for cut in 0..=message.len() {
            let parsed = parse_dhcp(&message[..cut]);
            let whole_options = cut >= BOOTP_FIXED + 4 && boundaries.contains(&cut);
            assert_eq!(
                parsed.is_some(),
                whole_options || cut == message.len(),
                "cut {cut}"
            );
        }
    }

    // ----- mDNS

    /// The wire form of a name of `labels`, with the zero of the root.
    fn labels(labels: &[&[u8]]) -> Vec<u8> {
        let mut name = Vec::new();
        for label in labels {
            name.push(u8::try_from(label.len()).unwrap());
            name.extend_from_slice(label);
        }
        name.push(0);
        name
    }

    /// A compression pointer to `target`.
    fn pointer(target: usize) -> Vec<u8> {
        let target = u16::try_from(target).unwrap() | 0xC000;
        target.to_be_bytes().to_vec()
    }

    /// A DNS header of `flags` and the four counts.
    fn dns_header(flags: u16, counts: [u16; 4]) -> Vec<u8> {
        let mut header = vec![0, 0];
        header.extend_from_slice(&flags.to_be_bytes());
        for count in counts {
            header.extend_from_slice(&count.to_be_bytes());
        }
        header
    }

    /// A record of `owner` (wire form, may be a pointer), `kind`, `class` and `data`.
    fn record(owner: &[u8], kind: u16, class: u16, data: &[u8]) -> Vec<u8> {
        let mut out = owner.to_vec();
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&class.to_be_bytes());
        out.extend_from_slice(&120u32.to_be_bytes());
        out.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    /// An A record with the cache-flush bit.
    fn a_record(owner: &[u8], addr: Ipv4Addr) -> Vec<u8> {
        record(owner, 1, 0x8001, &addr.octets())
    }

    /// What `parse_mdns` found in `payload`, in order.
    fn mdns(payload: &[u8]) -> Vec<(Ipv4Addr, String)> {
        let mut seen = Vec::new();
        parse_mdns(payload, &mut |addr, host| {
            seen.push((addr, host.to_owned()))
        });
        seen
    }

    /// An announcement: two answers, the first with its name spelled out and the second with
    /// its first label and a pointer to the `local` of the first.
    fn announcement() -> Vec<u8> {
        let mut message = dns_header(0x8400, [0, 2, 0, 0]);
        message.extend(a_record(&labels(&[b"example-tv", b"local"]), DEVICE));
        // The `local` label of the first name: 12 header bytes, 1 + 10 for the first label.
        let local = DNS_HEADER + 1 + 10;
        let mut owner = labels(&[b"example-pc"]);
        owner.pop();
        owner.extend(pointer(local));
        message.extend(a_record(&owner, OTHER));
        message
    }

    #[test]
    fn an_announcement_with_two_a_records_one_of_them_compressed_gives_both() {
        assert_eq!(
            mdns(&announcement()),
            vec![
                (DEVICE, "example-tv".to_owned()),
                (OTHER, "example-pc".to_owned())
            ]
        );
    }

    #[test]
    fn a_ptr_and_srv_mix_is_walked_over_and_an_a_record_in_the_additionals_is_found() {
        let service = labels(&[b"_http", b"_tcp", b"local"]);
        let instance = labels(&[b"Example TV", b"_http", b"_tcp", b"local"]);
        let mut srv = vec![0, 0, 0, 0, 0x1f, 0x90];
        srv.extend(labels(&[b"example-tv", b"local"]));
        let mut message = dns_header(0x8400, [0, 2, 1, 2]);
        message.extend(record(&service, 12, 1, &instance));
        message.extend(record(&instance, 33, 0x8001, &srv));
        // An authority record that is not an A record, and an AAAA, then the A record.
        message.extend(record(&instance, 16, 0x8001, &[3, b'a', b'=', b'b']));
        message.extend(record(
            &labels(&[b"example-tv", b"local"]),
            28,
            0x8001,
            &[0; 16],
        ));
        message.extend(a_record(&labels(&[b"example-tv", b"local"]), DEVICE));
        assert_eq!(mdns(&message), vec![(DEVICE, "example-tv".to_owned())]);
    }

    #[test]
    fn a_message_with_a_question_section_has_it_skipped() {
        let mut message = dns_header(0x8400, [1, 1, 0, 0]);
        message.extend(labels(&[b"example-tv", b"local"]));
        message.extend_from_slice(&[0, 1, 0x80, 1]);
        message.extend(a_record(&labels(&[b"example-tv", b"local"]), DEVICE));
        assert_eq!(mdns(&message), vec![(DEVICE, "example-tv".to_owned())]);
    }

    #[test]
    fn a_query_gives_nothing_even_with_records() {
        let mut message = announcement();
        message[2] = 0x00;
        assert!(mdns(&message).is_empty());
        message[2] = 0x84;
        assert_eq!(mdns(&message).len(), 2);
    }

    #[test]
    fn an_a_record_that_is_not_in_class_in_or_not_four_bytes_or_not_local_gives_nothing() {
        let local = labels(&[b"example-tv", b"local"]);
        let mut message = dns_header(0x8400, [0, 6, 0, 0]);
        message.extend(record(&local, 1, 3, &DEVICE.octets()));
        message.extend(record(&local, 1, 0x8003, &DEVICE.octets()));
        message.extend(record(&local, 1, 1, &[192, 0, 2]));
        message.extend(record(&local, 1, 1, &[192, 0, 2, 1, 0]));
        message.extend(a_record(&labels(&[b"example", b"org"]), DEVICE));
        message.extend(a_record(&labels(&[b"local"]), DEVICE));
        assert!(mdns(&message).is_empty());
        // The class with and without the cache-flush bit, and a name in capitals.
        let mut message = dns_header(0x8400, [0, 3, 0, 0]);
        message.extend(record(&local, 1, 1, &DEVICE.octets()));
        message.extend(record(&local, 1, 0x8001, &OTHER.octets()));
        message.extend(a_record(&labels(&[b"EXAMPLE-NAS", b"LOCAL"]), GATEWAY));
        assert_eq!(
            mdns(&message),
            vec![
                (DEVICE, "example-tv".to_owned()),
                (OTHER, "example-tv".to_owned()),
                (GATEWAY, "EXAMPLE-NAS".to_owned())
            ]
        );
    }

    #[test]
    fn a_name_with_more_labels_gives_what_is_left_of_local_and_a_host_is_sanitized() {
        let mut message = dns_header(0x8400, [0, 2, 0, 0]);
        message.extend(a_record(
            &labels(&[b"printer", b"floor-2", b"local"]),
            DEVICE,
        ));
        message.extend(a_record(
            &labels(&["Sam's Mac\u{e9}".as_bytes(), b"local"]),
            OTHER,
        ));
        assert_eq!(
            mdns(&message),
            vec![
                (DEVICE, "printer.floor-2".to_owned()),
                (OTHER, "Sam's-Mac".to_owned())
            ]
        );
        // A host of nothing printable has no name to give.
        let mut message = dns_header(0x8400, [0, 1, 0, 0]);
        message.extend(a_record(&labels(&[&[1, 2, 3], b"local"]), DEVICE));
        assert!(mdns(&message).is_empty());
    }

    #[test]
    fn a_pointer_to_itself_a_forward_pointer_and_a_pointer_into_the_header_give_nothing() {
        let first = DNS_HEADER;
        for target in [first, first + 2, first + 40, 0, 4, 11] {
            let mut message = dns_header(0x8400, [0, 1, 0, 0]);
            message.extend(a_record(&pointer(target), DEVICE));
            assert!(mdns(&message).is_empty(), "target {target}");
        }
        // A label and then a pointer that goes forward.
        let mut owner = vec![3, b'a', b'b', b'c'];
        owner.extend(pointer(DNS_HEADER + 20));
        let mut message = dns_header(0x8400, [0, 1, 0, 0]);
        message.extend(a_record(&owner, DEVICE));
        assert!(mdns(&message).is_empty());
    }

    #[test]
    fn a_pointer_to_a_place_that_holds_a_forward_pointer_gives_nothing() {
        // A record that is no A record, whose data is a pointer that leads forward, and an A record
        // whose owner points at that data.
        let mut message = dns_header(0x8400, [0, 2, 0, 0]);
        let data_at = message.len() + 1 + RECORD_FIXED;
        message.extend(record(&[0], 16, 1, &pointer(data_at + 2)));
        message.extend(a_record(&pointer(data_at), DEVICE));
        assert!(mdns(&message).is_empty());
        // The same with a pointer that leads back to itself.
        let mut message = dns_header(0x8400, [0, 2, 0, 0]);
        message.extend(record(&[0], 16, 1, &pointer(data_at)));
        message.extend(a_record(&pointer(data_at), DEVICE));
        assert!(mdns(&message).is_empty());
    }

    /// A message whose last answer is an A record whose owner is followed through `jumps` pointers
    /// to the name `example-tv.local`, which two records before it holds in its data. Each pointer
    /// leads to the one before it.
    fn through_pointers(jumps: usize) -> Vec<u8> {
        let mut message = dns_header(0x8400, [0, 3, 0, 0]);
        // The name, in the data of a record that is no A record: after the owner and the fixed part.
        let name_at = message.len() + 1 + RECORD_FIXED;
        message.extend(record(&[0], 16, 1, &labels(&[b"example-tv", b"local"])));
        // The pointers, in the data of another: the first leads to the name, each next to the one
        // before it, and the owner of the A record leads to the last.
        let chain_at = message.len() + 1 + RECORD_FIXED;
        let mut chain = Vec::new();
        for n in 0..jumps - 1 {
            chain.extend(pointer(if n == 0 {
                name_at
            } else {
                chain_at + 2 * (n - 1)
            }));
        }
        message.extend(record(&[0], 16, 1, &chain));
        let last = if jumps == 1 {
            name_at
        } else {
            chain_at + 2 * (jumps - 2)
        };
        message.extend(a_record(&pointer(last), DEVICE));
        message
    }

    #[test]
    fn a_chain_of_16_pointers_is_followed_and_one_of_17_is_not() {
        assert_eq!(
            mdns(&through_pointers(16)),
            vec![(DEVICE, "example-tv".to_owned())]
        );
        assert_eq!(
            mdns(&through_pointers(1)),
            vec![(DEVICE, "example-tv".to_owned())]
        );
        assert!(mdns(&through_pointers(17)).is_empty());
        assert!(mdns(&through_pointers(40)).is_empty());
    }

    #[test]
    fn a_name_of_255_bytes_is_decoded_and_one_of_256_is_not() {
        // 63 + 63 + 63 + 55 bytes of labels with their lengths, the 6 of `local` and the root.
        let long = |last: usize| {
            let (a, b, c, d) = (
                vec![b'a'; 63],
                vec![b'b'; 63],
                vec![b'c'; 63],
                vec![b'd'; last],
            );
            let mut message = dns_header(0x8400, [0, 1, 0, 0]);
            message.extend(a_record(&labels(&[&a, &b, &c, &d, b"local"]), DEVICE));
            message
        };
        let found = mdns(&long(55));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1.len(), HOSTNAME_MAX);
        assert!(mdns(&long(56)).is_empty());
        // Four labels of 63 cannot be a name either.
        let four = vec![b'x'; 63];
        let mut message = dns_header(0x8400, [0, 1, 0, 0]);
        message.extend(a_record(&labels(&[&four, &four, &four, &four]), DEVICE));
        assert!(mdns(&message).is_empty());
    }

    #[test]
    fn a_name_that_a_pointer_leads_to_is_held_to_255_bytes_as_well() {
        // The name is in the data of an earlier record, which no length check of the walk sees.
        let through = |last: usize| {
            let (a, b, c, d) = (
                vec![b'a'; 63],
                vec![b'b'; 63],
                vec![b'c'; 63],
                vec![b'd'; last],
            );
            let mut message = dns_header(0x8400, [0, 2, 0, 0]);
            let name_at = message.len() + 1 + RECORD_FIXED;
            message.extend(record(&[0], 16, 1, &labels(&[&a, &b, &c, &d, b"local"])));
            message.extend(a_record(&pointer(name_at), DEVICE));
            message
        };
        assert_eq!(mdns(&through(55)).len(), 1);
        assert!(mdns(&through(56)).is_empty());
        assert!(mdns(&through(60)).is_empty());
    }

    #[test]
    fn a_pointer_that_leads_forward_is_not_followed_even_to_a_good_name() {
        // An A record whose owner points at a name in the data of the record after it.
        let mut message = dns_header(0x8400, [0, 2, 0, 0]);
        let a_len = 2 + RECORD_FIXED + 4;
        let name_at = message.len() + a_len + 1 + RECORD_FIXED;
        message.extend(a_record(&pointer(name_at), DEVICE));
        message.extend(record(&[0], 16, 1, &labels(&[b"example-tv", b"local"])));
        assert_eq!(message[name_at], 10);
        assert!(mdns(&message).is_empty());
    }

    #[test]
    fn a_pointer_into_the_header_is_not_followed_even_to_bytes_that_make_a_name() {
        let mut buf = [0u8; NAME_WIRE_MAX];
        // Twelve bytes that start with a name of one label, `abc`, and a pointer to them.
        let mut payload = vec![3, b'a', b'b', b'c', 0, 0, 0, 0, 0, 0, 0, 0];
        payload.extend(pointer(0));
        assert_eq!(decode_name(&payload, 12, &mut buf), None);
        // The same name after the header, and a pointer to that.
        let mut payload = vec![0u8; DNS_HEADER];
        payload.extend(labels(&[b"abc"]));
        payload.extend(pointer(DNS_HEADER));
        assert_eq!(decode_name(&payload, 17, &mut buf), Some(3));
        assert_eq!(&buf[..3], b"abc");
    }

    #[test]
    fn a_record_whose_owner_is_longer_than_255_bytes_ends_the_walk() {
        let label = vec![b'x'; 63];
        let mut message = dns_header(0x8400, [0, 2, 0, 0]);
        message.extend(record(
            &labels(&[&label, &label, &label, &label]),
            16,
            1,
            b"\x01a",
        ));
        message.extend(a_record(&labels(&[b"example-tv", b"local"]), DEVICE));
        assert!(mdns(&message).is_empty());
        // With a name that is just long enough, the walk goes on to the second record.
        let mut message = dns_header(0x8400, [0, 2, 0, 0]);
        message.extend(record(
            &labels(&[&label, &label, &label, &[b'y'; 61]]),
            16,
            1,
            b"\x01a",
        ));
        message.extend(a_record(&labels(&[b"example-tv", b"local"]), DEVICE));
        assert_eq!(mdns(&message).len(), 1);
    }

    #[test]
    fn an_a_record_with_a_bad_name_is_skipped_and_the_walk_goes_on() {
        let mut message = dns_header(0x8400, [0, 2, 0, 0]);
        message.extend(a_record(&pointer(12), DEVICE));
        message.extend(a_record(&labels(&[b"example-pc", b"local"]), OTHER));
        assert_eq!(mdns(&message), vec![(OTHER, "example-pc".to_owned())]);
    }

    #[test]
    fn at_most_64_records_are_walked() {
        let mut message = dns_header(0x8400, [0, 70, 0, 0]);
        for n in 0..70u8 {
            message.extend(a_record(
                &labels(&[b"example-tv", b"local"]),
                Ipv4Addr::new(192, 0, 2, n),
            ));
        }
        let found = mdns(&message);
        assert_eq!(found.len(), MDNS_RECORDS_MAX);
        assert_eq!(found.last().unwrap().0, Ipv4Addr::new(192, 0, 2, 63));
        // Counts that add up from the three sections are one limit.
        message[7] = 30;
        message[9] = 30;
        message[11] = 30;
        assert_eq!(mdns(&message).len(), MDNS_RECORDS_MAX);
        // And a message of many questions is no announcement.
        message[5] = 65;
        assert!(mdns(&message).is_empty());
    }

    #[test]
    fn counts_that_run_past_the_data_stop_the_walk_after_the_records_that_are_there() {
        let mut message = dns_header(0x8400, [0, 500, 0, 0]);
        message.extend(a_record(&labels(&[b"example-tv", b"local"]), DEVICE));
        assert_eq!(mdns(&message), vec![(DEVICE, "example-tv".to_owned())]);
        // A data length that reaches past the end stops the walk before the record is used.
        let mut message = dns_header(0x8400, [0, 1, 0, 0]);
        let mut cut = a_record(&labels(&[b"example-tv", b"local"]), DEVICE);
        cut.truncate(cut.len() - 1);
        message.extend(cut);
        assert!(mdns(&message).is_empty());
    }

    #[test]
    fn every_cut_of_an_announcement_does_not_panic_and_finds_no_more_than_the_whole() {
        let mut messages = vec![announcement(), through_pointers(16)];
        let mut mixed = dns_header(0x8400, [1, 2, 0, 1]);
        mixed.extend(labels(&[b"example-tv", b"local"]));
        mixed.extend_from_slice(&[0, 1, 0, 1]);
        mixed.extend(record(
            &labels(&[b"_x", b"local"]),
            12,
            1,
            &labels(&[b"y", b"local"]),
        ));
        mixed.extend(record(&pointer(12), 33, 1, &[0; 6]));
        mixed.extend(a_record(&pointer(12), DEVICE));
        messages.push(mixed);
        for message in &messages {
            let whole = mdns(message).len();
            assert!(whole >= 1);
            for cut in 0..message.len() {
                assert!(mdns(&message[..cut]).len() <= whole, "cut {cut}");
            }
        }
        assert!(mdns(&[]).is_empty());
        assert!(mdns(&[0; 11]).is_empty());
    }

    #[test]
    fn bytes_of_every_value_in_a_message_do_not_panic_any_parser() {
        // A header that says there is plenty, over bytes that are all one value.
        for byte in [0x00, 0x01, 0x3f, 0x40, 0x80, 0xC0, 0xFF] {
            let mut payload = dns_header(0x8400, [1, 20, 20, 20]);
            payload.resize(300, byte);
            let _ = mdns(&payload);
            let _ = parse_dhcp(&payload);
            let _ = parse_arp(&payload);
            let mut dhcp = dhcp_message(1, DEVICE, &[]);
            dhcp.resize(400, byte);
            let _ = parse_dhcp(&dhcp);
        }
    }
}
