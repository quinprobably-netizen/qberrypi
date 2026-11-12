//! DNS rebinding: a public name that answers with an address inside the household.
//!
//! [`RebindPolicy`] says which names are screened, [`private_answer`] reads the wire form of an
//! answer for such an address, and [`zero_addresses`] makes the answer a blocked name gets. The
//! scan walks the answer section where it stands, allocates nothing, and follows no compression
//! pointer: a name is only skipped.
//!
//! Nothing here logs: a name that is asked for never reaches a log line.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Range;

use super::names;
use super::{HEADER_LEN, NAME_WIRE_MAX, POINTER_BITS, be16};

/// The type number of an A record.
const TYPE_A: u16 = 1;
/// The type number of an AAAA record.
const TYPE_AAAA: u16 = 28;
/// The class number of IN.
const CLASS_IN: u16 = 1;
/// The bytes of a record after its owner name: the type, the class, the TTL and the length of
/// the data.
const RECORD_FIXED_LEN: usize = 10;
/// The bytes of the data of an A record.
const A_LEN: usize = 4;
/// The bytes of the data of an AAAA record.
const AAAA_LEN: usize = 16;
/// The bytes of a question after its name: the type and the class.
const QUESTION_FIXED_LEN: usize = 4;
/// The low four bits of the header's second flag byte: the response code.
const RCODE_MASK: u8 = 0x0f;
/// The bits of a pointer's first byte that are not part of its target.
const POINTER_TARGET_MASK: u8 = 0x3F;

/// Which names are screened for a private address in their answers.
#[derive(Debug, Clone)]
pub struct RebindPolicy {
    /// The names that answer private addresses by design, lower-case and with no trailing dot: a
    /// name under one of them is not screened.
    allow: Vec<String>,
}

impl RebindPolicy {
    /// A policy that lets the names under `allow` answer private addresses. An entry is taken in
    /// lower case and without a trailing dot, so that one as it is written in the file serves.
    pub fn new(allow: Vec<String>) -> Self {
        let allow = allow
            .into_iter()
            .map(|entry| entry.trim_end_matches('.').to_ascii_lowercase())
            .filter(|entry| !entry.is_empty())
            .collect();
        Self { allow }
    }

    /// Whether answers for `name`, as the resolver spells it (lower case, no trailing dot), are
    /// screened: it is public, see [`is_public`], and is not under an allowed name.
    pub fn screens(&self, name: &str) -> bool {
        is_public(name) && !self.allow.iter().any(|entry| names::under(name, entry))
    }
}

/// Whether `name` is one of the Internet's: it has a dot and is not the household's own, see
/// [`names::is_local`].
pub fn is_public(name: &str) -> bool {
    name.contains('.') && !names::is_local(name)
}

/// Whether an A or AAAA record of the answer section of `packet`, a response with the code
/// NOERROR, holds an address that is private, loopback or link-local: 10/8, 172.16/12,
/// 192.168/16, 127/8, 169.254/16, `::1`, `fc00::/7` and `fe80::/10`, and an IPv4-mapped address of
/// those of IPv4. `0.0.0.0` and `::` are not, as an upstream that blocks a name sends them, and
/// nor is 100.64/10.
///
/// Only the answer section is read. Anything that is not the shape of a message, a length that
/// runs past the end for one, ends the scan, and what it found so far stands. Nothing is
/// allocated.
pub fn private_answer(packet: &[u8]) -> bool {
    let Some(mut records) = Records::new(packet) else {
        return false;
    };
    records.any(|record| record.is_private(packet))
}

/// A copy of `packet` with the data of each A and AAAA record of the answer section set to zeros:
/// `0.0.0.0` and `::`, the answer that a blocked name gets. The scan is that of
/// [`private_answer`], and a part of the packet that it cannot read is copied as it is.
pub fn zero_addresses(packet: &[u8]) -> Vec<u8> {
    let mut zeroed = packet.to_vec();
    if let Some(records) = Records::new(packet) {
        for record in records.filter(Record::is_address) {
            if let Some(data) = zeroed.get_mut(record.data) {
                data.fill(0);
            }
        }
    }
    zeroed
}

/// One record of the answer section: where its data lies, and what kind it is.
struct Record {
    /// The type of the record.
    rtype: u16,
    /// The class of the record.
    class: u16,
    /// The span of its data, which lies within the packet.
    data: Range<usize>,
}

impl Record {
    /// Whether this is an A record of 4 bytes or an AAAA record of 16, which holds an address.
    fn is_address(&self) -> bool {
        matches!(
            (self.rtype, self.data.len()),
            (TYPE_A, A_LEN) | (TYPE_AAAA, AAAA_LEN)
        )
    }

    /// Whether this is an address of class IN that is private, loopback or link-local; `packet`
    /// is what the record was read from.
    fn is_private(&self, packet: &[u8]) -> bool {
        if self.class != CLASS_IN {
            return false;
        }
        let Some(data) = packet.get(self.data.clone()) else {
            return false;
        };
        match self.rtype {
            TYPE_A => {
                <[u8; A_LEN]>::try_from(data).is_ok_and(|octets| private_v4(Ipv4Addr::from(octets)))
            }
            TYPE_AAAA => <[u8; AAAA_LEN]>::try_from(data)
                .is_ok_and(|octets| private_v6(Ipv6Addr::from(octets))),
            _ => false,
        }
    }
}

/// Whether `addr` is in 10/8, 172.16/12, 192.168/16, 127/8 or 169.254/16.
fn private_v4(addr: Ipv4Addr) -> bool {
    addr.is_private() || addr.is_loopback() || addr.is_link_local()
}

/// Whether `addr` is `::1`, in `fc00::/7` or `fe80::/10`, or an IPv4-mapped address that
/// [`private_v4`] holds.
fn private_v6(addr: Ipv6Addr) -> bool {
    let first = addr.segments()[0];
    addr.is_loopback()
        || first & 0xfe00 == 0xfc00
        || first & 0xffc0 == 0xfe80
        || addr.to_ipv4_mapped().is_some_and(private_v4)
}

/// The records of the answer section of a response, in order, up to the first that is not all
/// there. Each step reads one record and leaves the rest alone, and there are no more steps than
/// the header counts.
struct Records<'a> {
    packet: &'a [u8],
    /// Where the next record starts.
    at: usize,
    /// How many records the header counts and have not been read.
    left: u16,
}

impl<'a> Records<'a> {
    /// The records of `packet`; `None` for a packet that is no response with the code NOERROR,
    /// or whose questions are not all there.
    fn new(packet: &'a [u8]) -> Option<Self> {
        let header = packet.get(..HEADER_LEN)?;
        if header[3] & RCODE_MASK != 0 {
            return None;
        }
        let mut at = HEADER_LEN;
        for _ in 0..be16(header, 4)? {
            at = skip_name(packet, at)? + QUESTION_FIXED_LEN;
            if at > packet.len() {
                return None;
            }
        }
        Some(Self {
            packet,
            at,
            left: be16(header, 6)?,
        })
    }

    /// The record at `self.at`, and the start of the next.
    fn read(&self) -> Option<(Record, usize)> {
        let at = skip_name(self.packet, self.at)?;
        let rtype = be16(self.packet, at)?;
        let class = be16(self.packet, at + 2)?;
        let len = usize::from(be16(self.packet, at + RECORD_FIXED_LEN - 2)?);
        let start = at + RECORD_FIXED_LEN;
        let end = start.checked_add(len)?;
        if end > self.packet.len() {
            return None;
        }
        let data = start..end;
        Some((Record { rtype, class, data }, end))
    }
}

impl Iterator for Records<'_> {
    type Item = Record;

    fn next(&mut self) -> Option<Record> {
        if self.left == 0 {
            return None;
        }
        // One that cannot be read ends the answer section here.
        let Some((record, next)) = self.read() else {
            self.left = 0;
            return None;
        };
        self.left -= 1;
        self.at = next;
        Some(record)
    }
}

/// Where the name at `at` ends, which is where whatever follows it starts. The name is labels
/// that end at the root, or labels that end in a pointer, or only a pointer. A pointer is not
/// followed, but it must point back into the message past the header, as the first of a name
/// does. `None` for a name that is not all there, is over 255 bytes, has a label of a type that
/// is neither, or has a pointer that points at itself or forward: the steps are bounded by the
/// 255 bytes, and a pointer loop has no way in.
fn skip_name(packet: &[u8], mut at: usize) -> Option<usize> {
    let start = at;
    loop {
        let byte = *packet.get(at)?;
        match byte & POINTER_BITS {
            POINTER_BITS => {
                let target = usize::from(byte & POINTER_TARGET_MASK) << 8
                    | usize::from(*packet.get(at + 1)?);
                return (HEADER_LEN..at).contains(&target).then_some(at + 2);
            }
            0 => {
                at += 1 + usize::from(byte);
                if byte == 0 {
                    return Some(at);
                }
                // The labels, and then the root, are at most 255 bytes.
                if at - start >= NAME_WIRE_MAX {
                    return None;
                }
            }
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::hint::black_box;
    use std::time::Instant;

    use hickory_proto::op::{Message, OpCode, Query};
    use hickory_proto::rr::rdata::{A, AAAA, CNAME, TXT};
    use hickory_proto::rr::{Name, RData, Record as DnsRecord, RecordType};

    use crate::watch::wire_of;

    /// One record as bytes: the owner as given, the type, the class IN, a TTL of 60, the data.
    fn record(owner: &[u8], rtype: u16, class: u16, data: &[u8]) -> Vec<u8> {
        let mut out = owner.to_vec();
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&class.to_be_bytes());
        out.extend_from_slice(&60u32.to_be_bytes());
        out.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    /// The owner that is a pointer to the question's name.
    const TO_QUESTION: [u8; 2] = [0xC0, 12];

    /// An A record for the question, from a pointer, with the address in `text`.
    fn a(text: &str) -> Vec<u8> {
        let addr: Ipv4Addr = text.parse().unwrap();
        record(&TO_QUESTION, TYPE_A, CLASS_IN, &addr.octets())
    }

    /// An AAAA record for the question, from a pointer, with the address in `text`.
    fn aaaa(text: &str) -> Vec<u8> {
        let addr: Ipv6Addr = text.parse().unwrap();
        record(&TO_QUESTION, TYPE_AAAA, CLASS_IN, &addr.octets())
    }

    /// A response for `example.org` of type A with the response code `rcode`, and these records
    /// in its three sections.
    fn message(
        rcode: u8,
        answers: &[Vec<u8>],
        authority: &[Vec<u8>],
        additional: &[Vec<u8>],
    ) -> Vec<u8> {
        let count = |records: &[Vec<u8>]| u16::try_from(records.len()).unwrap().to_be_bytes();
        let mut out = vec![0x12, 0x34, 0x81, 0x80 | rcode, 0, 1];
        out.extend_from_slice(&count(answers));
        out.extend_from_slice(&count(authority));
        out.extend_from_slice(&count(additional));
        out.extend_from_slice(&wire_of("example.org"));
        out.extend_from_slice(&[0, 1, 0, 1]);
        for part in answers.iter().chain(authority).chain(additional) {
            out.extend_from_slice(part);
        }
        out
    }

    /// A NOERROR response whose answer section is `answers`.
    fn answering(answers: &[Vec<u8>]) -> Vec<u8> {
        message(0, answers, &[], &[])
    }

    /// Whether the answer of one A record with the address in `text` is private.
    fn private_a(text: &str) -> bool {
        private_answer(&answering(&[a(text)]))
    }

    /// Whether the answer of one AAAA record with the address in `text` is private.
    fn private_aaaa(text: &str) -> bool {
        private_answer(&answering(&[aaaa(text)]))
    }

    #[test]
    fn each_private_range_of_ipv4_ends_where_it_should() {
        for (inside, outside) in [
            ("10.0.0.0", "9.255.255.255"),
            ("10.255.255.255", "11.0.0.0"),
            ("172.16.0.0", "172.15.255.255"),
            ("172.31.255.255", "172.32.0.0"),
            ("192.168.0.0", "192.167.255.255"),
            ("192.168.255.255", "192.169.0.0"),
            ("127.0.0.0", "126.255.255.255"),
            ("127.255.255.255", "128.0.0.0"),
            ("169.254.0.0", "169.253.255.255"),
            ("169.254.255.255", "169.255.0.0"),
            ("10.0.0.1", "192.0.2.1"),
            ("127.0.0.1", "198.51.100.1"),
            ("192.168.1.1", "203.0.113.1"),
        ] {
            assert!(private_a(inside), "{inside}");
            assert!(!private_a(outside), "{outside}");
        }
    }

    #[test]
    fn the_unspecified_address_the_shared_range_and_the_broadcast_are_not_private() {
        for addr in [
            "0.0.0.0",
            "0.0.0.1",
            "100.64.0.1",
            "100.127.255.255",
            "255.255.255.255",
            "8.8.8.8",
        ] {
            assert!(!private_a(addr), "{addr}");
        }
    }

    #[test]
    fn each_private_range_of_ipv6_ends_where_it_should() {
        for (inside, outside) in [
            ("::1", "::2"),
            ("::1", "::"),
            ("fc00::", "fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            ("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fe00::"),
            ("fd00::1", "2001:db8::1"),
            ("fe80::", "fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            ("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fec0::"),
            ("fe80::1", "2001:db8:ffff::1"),
        ] {
            assert!(private_aaaa(inside), "{inside}");
            assert!(!private_aaaa(outside), "{outside}");
        }
        assert!(!private_aaaa("::"));
    }

    #[test]
    fn an_ipv4_mapped_address_is_private_as_the_ipv4_address_is() {
        for (inside, outside) in [
            ("::ffff:10.0.0.1", "::ffff:192.0.2.1"),
            ("::ffff:127.0.0.1", "::ffff:0.0.0.0"),
            ("::ffff:169.254.1.1", "::ffff:172.32.0.1"),
            ("::ffff:172.16.0.1", "::ffff:100.64.0.1"),
            ("::ffff:192.168.1.1", "::ffff:11.0.0.1"),
        ] {
            assert!(private_aaaa(inside), "{inside}");
            assert!(!private_aaaa(outside), "{outside}");
        }
        // The IPv4-compatible form is not the mapped one, and the NAT64 prefix is not read.
        assert!(!private_aaaa("::10.0.0.1"));
        assert!(!private_aaaa("64:ff9b::10.0.0.1"));
    }

    #[test]
    fn an_owner_name_may_be_a_pointer_labels_or_both() {
        let ten = [10, 0, 0, 1];
        let spelled = wire_of("cdn.example.org");
        let mut label_then_pointer = vec![3, b'c', b'd', b'n'];
        label_then_pointer.extend_from_slice(&TO_QUESTION);
        // Three labels of 63 and one of 61, with the root: the longest name there is.
        let longest = wire_of(&format!("{0}.{0}.{0}.{1}", "a".repeat(63), "b".repeat(61)));
        assert_eq!(longest.len(), 255);
        for owner in [&TO_QUESTION[..], &spelled, &label_then_pointer, &longest] {
            let packet = answering(&[record(owner, TYPE_A, CLASS_IN, &ten)]);
            assert!(private_answer(&packet), "{owner:?}");
        }
    }

    #[test]
    fn a_private_address_after_a_cname_chain_is_found_and_a_public_one_is_not() {
        // The first record's data is a name that ends in a pointer; the second's owner is a
        // pointer to that name inside the data.
        let mut target = vec![4, b'e', b'd', b'g', b'e'];
        target.extend_from_slice(&TO_QUESTION);
        let cname = record(&TO_QUESTION, 5, CLASS_IN, &target);
        // The data of the first record starts after its owner, type, class, TTL and length.
        let edge_at = HEADER_LEN + wire_of("example.org").len() + 4 + 12;
        let edge = [0xC0, u8::try_from(edge_at).unwrap()];
        let two_hops = record(&edge, 5, CLASS_IN, &wire_of("far.example.net"));
        let at_edge = |data: [u8; 4]| record(&edge, TYPE_A, CLASS_IN, &data);
        for (data, want) in [([10, 0, 0, 1], true), ([192, 0, 2, 1], false)] {
            let packet = answering(&[cname.clone(), two_hops.clone(), at_edge(data)]);
            assert_eq!(private_answer(&packet), want, "{data:?}");
        }
        // A private address before the chain is found too.
        let packet = answering(&[a("10.0.0.1"), cname]);
        assert!(private_answer(&packet));
    }

    #[test]
    fn any_record_of_the_answer_section_counts() {
        for addresses in [
            ["192.0.2.1", "10.0.0.1", "198.51.100.1"],
            ["10.0.0.1", "192.0.2.1", "198.51.100.1"],
            ["192.0.2.1", "198.51.100.1", "10.0.0.1"],
        ] {
            let records: Vec<Vec<u8>> = addresses.into_iter().map(a).collect();
            assert!(private_answer(&answering(&records)), "{addresses:?}");
        }
        let records = [a("192.0.2.1"), aaaa("2001:db8::1"), aaaa("fd00::1")];
        assert!(private_answer(&answering(&records)));
    }

    #[test]
    fn records_of_the_authority_and_additional_sections_are_not_read() {
        let packet = message(
            0,
            &[a("192.0.2.1")],
            &[a("10.0.0.1")],
            &[aaaa("fd00::1"), a("127.0.0.1")],
        );
        assert!(!private_answer(&packet));
        // The same records in the answer section are read.
        assert!(private_answer(&answering(&[a("10.0.0.1")])));
        // And zeroing leaves the other sections as they are.
        let zeroed = zero_addresses(&message(
            0,
            &[a("10.0.0.1")],
            &[a("10.0.0.2")],
            &[aaaa("fd00::1")],
        ));
        let parsed = Message::from_vec(&zeroed).unwrap();
        assert_eq!(addresses(&parsed.answers), ["0.0.0.0"]);
        assert_eq!(addresses(&parsed.authorities), ["10.0.0.2"]);
        assert_eq!(addresses(&parsed.additionals), ["fd00::1"]);
    }

    #[test]
    fn only_a_response_with_the_code_noerror_is_read() {
        for rcode in 0..16 {
            let packet = message(rcode, &[a("10.0.0.1")], &[], &[]);
            assert_eq!(private_answer(&packet), rcode == 0, "{rcode}");
            // And the copy of one that is not read is the packet.
            if rcode != 0 {
                assert_eq!(zero_addresses(&packet), packet);
            }
        }
        // The flags above the code are not part of it.
        let mut packet = answering(&[a("10.0.0.1")]);
        packet[3] = 0xF0;
        assert!(private_answer(&packet));
    }

    #[test]
    fn a_record_that_is_not_an_in_address_of_the_right_length_is_not_private() {
        let ten = [10, 0, 0, 1];
        let in_v6 = Ipv6Addr::LOCALHOST.octets();
        for (rtype, class, data) in [
            (TYPE_A, 3, &ten[..]),
            (TYPE_A, 255, &ten[..]),
            (TYPE_A, CLASS_IN, &[10, 0, 0, 1, 0][..]),
            (TYPE_A, CLASS_IN, &[10, 0, 0][..]),
            (TYPE_A, CLASS_IN, &[][..]),
            (TYPE_AAAA, CLASS_IN, &ten[..]),
            (TYPE_AAAA, CLASS_IN, &in_v6[..15]),
            (16, CLASS_IN, &ten[..]),
            (5, CLASS_IN, &ten[..]),
            (0, CLASS_IN, &ten[..]),
        ] {
            let packet = answering(&[record(&TO_QUESTION, rtype, class, data)]);
            assert!(!private_answer(&packet), "{rtype} {class} {data:?}");
        }
    }

    #[test]
    fn an_answer_cut_short_is_not_private_and_does_not_panic() {
        let packet = answering(&[a("10.0.0.1")]);
        for cut in 0..packet.len() {
            assert!(!private_answer(&packet[..cut]), "{cut}");
            assert_eq!(zero_addresses(&packet[..cut]), packet[..cut]);
        }
        assert!(private_answer(&packet));
        // A record cut short ends the scan, and a private one before it stands.
        let mut two = answering(&[a("10.0.0.1"), a("192.0.2.1")]);
        two.truncate(two.len() - 1);
        assert!(private_answer(&two));
        let mut two = answering(&[a("192.0.2.1"), a("10.0.0.1")]);
        two.truncate(two.len() - 1);
        assert!(!private_answer(&two));
    }

    #[test]
    fn a_data_length_past_the_end_is_not_private() {
        let mut packet = answering(&[a("10.0.0.1")]);
        let length_at = packet.len() - 4 - 2;
        for length in [5u16, 100, 0xFFFF] {
            packet[length_at..length_at + 2].copy_from_slice(&length.to_be_bytes());
            assert!(!private_answer(&packet), "{length}");
            assert_eq!(zero_addresses(&packet), packet, "{length}");
        }
    }

    #[test]
    fn counts_that_the_packet_cannot_hold_are_not_private_and_do_not_loop() {
        let mut packet = answering(&[a("192.0.2.1")]);
        // A thousand answers counted, one there: the one is read, and then the scan ends.
        packet[6..8].copy_from_slice(&1000u16.to_be_bytes());
        assert!(!private_answer(&packet));
        let mut packet = answering(&[a("10.0.0.1")]);
        packet[6..8].copy_from_slice(&0xFFFFu16.to_be_bytes());
        assert!(private_answer(&packet));
        // No answer counted: nothing is read, whatever follows.
        packet[6..8].copy_from_slice(&0u16.to_be_bytes());
        assert!(!private_answer(&packet));
        // Many questions counted, and no room for them.
        let mut packet = answering(&[a("10.0.0.1")]);
        packet[4..6].copy_from_slice(&0xFFFFu16.to_be_bytes());
        assert!(!private_answer(&packet));
        assert_eq!(zero_addresses(&packet), packet);
    }

    #[test]
    fn a_pointer_that_loops_or_points_ahead_is_not_private() {
        let ten = [10, 0, 0, 1];
        let name_at = HEADER_LEN + wire_of("example.org").len() + 4;
        let past_the_end = u8::try_from(name_at + 40).unwrap();
        for owner in [
            // To itself, to the start of the packet, into the header, and ahead.
            [0xC0, u8::try_from(name_at).unwrap()],
            [0xC0, 0],
            [0xC0, 11],
            [0xC0, u8::try_from(name_at + 2).unwrap()],
            [0xC0, past_the_end],
            [0xFF, 0xFF],
        ] {
            let packet = answering(&[record(&owner, TYPE_A, CLASS_IN, &ten)]);
            assert!(!private_answer(&packet), "{owner:?}");
            assert_eq!(zero_addresses(&packet), packet, "{owner:?}");
        }
        // The pointer of a question is held to the same rule.
        let mut packet = answering(&[a("10.0.0.1")]);
        packet[HEADER_LEN..HEADER_LEN + 2].copy_from_slice(&[0xC0, 12]);
        assert!(!private_answer(&packet));
        // A pointer cut after its first byte.
        let mut cut = answering(&[]);
        cut[7] = 1;
        cut.push(0xC0);
        assert!(!private_answer(&cut));
    }

    #[test]
    fn names_that_are_not_labels_or_pointers_are_not_private() {
        let ten = [10, 0, 0, 1];
        // The label types 01 and 10, a label that runs past the end, and a name of 256 bytes.
        let mut long = Vec::new();
        for _ in 0..4 {
            long.push(63);
            long.extend_from_slice(&[b'a'; 63]);
        }
        long.push(0);
        assert_eq!(long.len(), 257);
        for owner in [vec![0x40, 1], vec![0x80, 1], vec![50, 1, 2, 3], long] {
            let packet = answering(&[record(&owner, TYPE_A, CLASS_IN, &ten)]);
            assert!(!private_answer(&packet), "{owner:?}");
        }
    }

    #[test]
    fn a_packet_that_is_no_message_is_not_private() {
        assert!(!private_answer(&[]));
        assert!(!private_answer(&[0; 11]));
        assert!(!private_answer(&[0; 12]));
        assert!(!private_answer(&[0xFF; 600]));
        assert_eq!(zero_addresses(&[]), Vec::<u8>::new());
        assert_eq!(zero_addresses(&[0xFF; 600]), vec![0xFF; 600]);
    }

    /// A small deterministic stream of numbers, so that a failure repeats.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    #[test]
    fn packets_with_bytes_changed_never_panic_and_zeroing_keeps_their_length() {
        let seeds = [
            answering(&[a("10.0.0.1"), aaaa("fd00::1"), a("192.0.2.1")]),
            message(0, &[a("192.0.2.1")], &[a("10.0.0.1")], &[aaaa("::1")]),
            realistic_answer(),
        ];
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for _ in 0..50_000 {
            let mut packet = seeds[rng.next() as usize % seeds.len()].clone();
            for _ in 0..1 + rng.next() % 4 {
                let at = rng.next() as usize % packet.len();
                packet[at] = rng.next() as u8;
            }
            if rng.next().is_multiple_of(4) {
                packet.truncate(rng.next() as usize % packet.len());
            }
            let found = private_answer(&packet);
            let zeroed = zero_addresses(&packet);
            assert_eq!(zeroed.len(), packet.len());
            // What was found as private is gone in the copy.
            if found {
                assert!(!private_answer(&zeroed));
            }
        }
    }

    /// The addresses of `records` as text, in order, those that are A or AAAA.
    fn addresses(records: &[DnsRecord]) -> Vec<String> {
        records
            .iter()
            .filter_map(|record| match &record.data {
                RData::A(a) => Some(a.0.to_string()),
                RData::AAAA(aaaa) => Some(aaaa.0.to_string()),
                _ => None,
            })
            .collect()
    }

    /// A response for `cdn.example.com` as an upstream sends it: a CNAME to an edge name, and
    /// three A records for it, public ones, with the names compressed.
    fn realistic_answer() -> Vec<u8> {
        let name = |text: &str| Name::from_ascii(text).unwrap();
        let mut message = Message::response(0x4242, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.metadata.recursion_available = true;
        message.add_query(Query::query(name("cdn.example.com"), RecordType::A));
        message.add_answer(DnsRecord::from_rdata(
            name("cdn.example.com"),
            300,
            RData::CNAME(CNAME(name("edge-7.cdn.example.net"))),
        ));
        for octet in [10, 11, 12] {
            message.add_answer(DnsRecord::from_rdata(
                name("edge-7.cdn.example.net"),
                60,
                RData::A(A(Ipv4Addr::new(203, 0, 113, octet))),
            ));
        }
        message.to_vec().unwrap()
    }

    #[test]
    fn zeroed_addresses_read_back_as_zeros_and_the_rest_is_as_it_was() {
        let name = |text: &str| Name::from_ascii(text).unwrap();
        let mut message = Message::response(0x4242, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(name("www.example.org"), RecordType::A));
        let owner = name("www.example.org");
        let rdata = [
            RData::CNAME(CNAME(name("edge.example.net"))),
            RData::A(A(Ipv4Addr::new(10, 0, 0, 1))),
            RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
            RData::AAAA(AAAA("fd00::1".parse().unwrap())),
            RData::AAAA(AAAA("2001:db8::1".parse().unwrap())),
            RData::TXT(TXT::new(vec!["10.0.0.1".to_owned()])),
        ];
        for data in rdata {
            message.add_answer(DnsRecord::from_rdata(owner.clone(), 120, data));
        }
        let packet = message.to_vec().unwrap();
        assert!(private_answer(&packet));

        let zeroed = zero_addresses(&packet);
        assert_eq!(zeroed.len(), packet.len());
        let back = Message::from_vec(&zeroed).unwrap();
        assert_eq!(back.metadata.id, 0x4242);
        assert_eq!(addresses(&back.answers), ["0.0.0.0", "0.0.0.0", "::", "::"]);
        // The types, TTLs and names are as they were, and the records that hold no address are
        // the same ones.
        let original = Message::from_vec(&packet).unwrap();
        for (now, was) in back.answers.iter().zip(&original.answers) {
            assert_eq!(
                (&now.name, now.ttl, now.data.record_type()),
                (&was.name, was.ttl, was.data.record_type())
            );
        }
        assert_eq!(back.answers.len(), original.answers.len());
        assert_eq!(back.answers[0], original.answers[0]);
        assert_eq!(back.answers[5], original.answers[5]);
        assert_eq!(back.queries, original.queries);
        // What was private is not any more, and a copy of a copy is the same.
        assert!(!private_answer(&zeroed));
        assert_eq!(zero_addresses(&zeroed), zeroed);
    }

    #[test]
    fn the_names_that_are_screened_are_the_public_ones_that_are_not_allowed() {
        let policy = RebindPolicy::new(vec![
            "Router.Example.org.".to_owned(),
            "plex.direct".to_owned(),
            String::new(),
        ]);
        for name in [
            "example.com",
            "a.b.example.org",
            "notlocal.com",
            "xn--bcher-kva.example",
            "notplex.direct",
            "plex.direct.example.com",
        ] {
            assert!(policy.screens(name), "{name}");
        }
        for name in [
            // Allowed: the name and everything under it, at a label boundary.
            "router.example.org",
            "nas.router.example.org",
            "plex.direct",
            "0a0b.abc123.plex.direct",
            // Local, or not a name with a dot.
            "printer",
            "printer.lan",
            "nas.home",
            "host.local",
            "x.internal",
            "pc.localdomain",
            "pc.home.arpa",
            "1.0.0.10.in-addr.arpa",
            "localhost",
            "",
        ] {
            assert!(!policy.screens(name), "{name}");
        }
        // With no entries, every public name is screened, plex.direct too.
        let none = RebindPolicy::new(Vec::new());
        assert!(none.screens("plex.direct") && none.screens("router.example.org"));
        assert!(!none.screens("printer.lan"));
    }

    /// How many calls the timing tests make.
    const TIMED_CALLS: u32 = 1_000_000;

    /// The nanoseconds that one call of `private_answer` took on average over `calls` calls.
    fn ns_per_call(packet: &[u8], calls: u32) -> f64 {
        let started = Instant::now();
        for _ in 0..calls {
            black_box(private_answer(black_box(packet)));
        }
        started.elapsed().as_secs_f64() * 1e9 / f64::from(calls)
    }

    /// Prints the cost of `private_answer` on a CNAME and three A records of public addresses,
    /// which is the whole walk with no match, and on one that matches in the last record. Run it
    /// with `cargo test -p qberrypi --release -- --ignored --nocapture private_answer_costs`.
    #[test]
    #[ignore = "a timing, for reading"]
    fn private_answer_costs_little() {
        let packet = realistic_answer();
        assert!(!private_answer(&packet));
        // Once to warm up, then the timed run.
        ns_per_call(&packet, TIMED_CALLS);
        println!(
            "private_answer, 4 records, no match: {:7.1} ns per call ({} bytes)",
            ns_per_call(&packet, TIMED_CALLS),
            packet.len()
        );
        let mut matching = packet.clone();
        let last = matching.len() - 4;
        matching[last..].copy_from_slice(&[10, 0, 0, 1]);
        assert!(private_answer(&matching));
        println!(
            "private_answer, 4 records, last matches: {:5.1} ns per call",
            ns_per_call(&matching, TIMED_CALLS)
        );
        println!("zero_addresses, the same answer:     {:7.1} ns per call", {
            let started = Instant::now();
            for _ in 0..TIMED_CALLS / 10 {
                black_box(zero_addresses(black_box(&matching)));
            }
            started.elapsed().as_secs_f64() * 1e9 / f64::from(TIMED_CALLS / 10)
        });
    }

    // Hot path: every forwarded answer of a public name is scanned, and none may wait on it.
    #[test]
    fn scanning_an_answer_costs_microseconds_at_most() {
        // The bound is for a debug build on a busy machine: a release build takes well under a
        // microsecond, and the board's cores are a few times slower.
        const MEAN_LIMIT_NS: f64 = 20_000.0;
        let packet = realistic_answer();
        let per_call = ns_per_call(&packet, 100_000);
        assert!(per_call < MEAN_LIMIT_NS, "{per_call} ns per call");
    }
}
