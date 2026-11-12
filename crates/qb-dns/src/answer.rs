//! Reply bytes: blocked, answered here, error, and relayed from an upstream answer.

use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Edns, Message, OpCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};

use crate::Transport;
use crate::query::{Question, ResponseCode};

/// The UDP payload size announced in every OPT record sent, to a client or upstream, and the
/// most a UDP reply holds.
pub(crate) const UDP_PAYLOAD: u16 = 1232;
/// The seconds a blocked answer may be kept: few, so that a pause shows within seconds.
pub(crate) const BLOCK_TTL: u32 = 2;
/// The seconds an answer for `localhost` may be kept.
pub(crate) const LOCAL_TTL: u32 = 3600;

/// The most a UDP reply holds when the query had no OPT record, and the least an OPT record's
/// payload size counts as.
const UDP_WITHOUT_OPT: u16 = 512;

/// In the third header byte: set on a response.
const QR: u8 = 0x80;
/// In the fourth header byte: recursion available.
const RA: u8 = 0x80;
/// The rcode of the header-only reply.
const SERVFAIL: u8 = 2;

/// The reverse zones of private, link-local and loopback addresses (RFC 6303). A public
/// resolver has nothing to say about them, and asking it tells it which addresses are in use.
const PRIVATE_REVERSE: [&str; 25] = [
    "10.in-addr.arpa",
    "16.172.in-addr.arpa",
    "17.172.in-addr.arpa",
    "18.172.in-addr.arpa",
    "19.172.in-addr.arpa",
    "20.172.in-addr.arpa",
    "21.172.in-addr.arpa",
    "22.172.in-addr.arpa",
    "23.172.in-addr.arpa",
    "24.172.in-addr.arpa",
    "25.172.in-addr.arpa",
    "26.172.in-addr.arpa",
    "27.172.in-addr.arpa",
    "28.172.in-addr.arpa",
    "29.172.in-addr.arpa",
    "30.172.in-addr.arpa",
    "31.172.in-addr.arpa",
    "168.192.in-addr.arpa",
    "254.169.in-addr.arpa",
    "127.in-addr.arpa",
    "d.f.ip6.arpa",
    "8.e.f.ip6.arpa",
    "9.e.f.ip6.arpa",
    "a.e.f.ip6.arpa",
    "b.e.f.ip6.arpa",
];

/// The reply for a blocked name: `0.0.0.0` for A, `::` for AAAA, an empty success for any
/// other type.
pub(crate) fn blocked(q: &Question) -> Vec<u8> {
    address(q, Ipv4Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED, BLOCK_TTL)
}

/// The reply for a name that is answered here and never forwarded; `None` for any other name.
///
/// `localhost` gets the loopback address, whatever the type. Any other single-label name gets
/// NXDOMAIN for A and AAAA only, as with dnsmasq's `domain-needed`: no public resolver knows it,
/// and the other types stay with the upstream, for a validating client asks it `com. DS` and
/// `com. DNSKEY` and treats an unsigned NXDOMAIN as proof that every name is bogus. Every name at
/// or under a private reverse zone gets NXDOMAIN. The root is not answered here.
pub(crate) fn local(q: &Question) -> Option<Vec<u8>> {
    let mut labels = q.query().name.iter();
    match (labels.next(), labels.next()) {
        (Some(only), None) if only.eq_ignore_ascii_case(b"localhost") => Some(address(
            q,
            Ipv4Addr::LOCALHOST,
            Ipv6Addr::LOCALHOST,
            LOCAL_TTL,
        )),
        (Some(_), None) => matches!(q.query().query_type, RecordType::A | RecordType::AAAA)
            .then(|| error(q, ResponseCode::NXDomain)),
        _ => PRIVATE_REVERSE
            .iter()
            .any(|zone| at_or_under(q, zone))
            .then(|| error(q, ResponseCode::NXDomain)),
    }
}

/// The reply that holds `rcode` and no records.
///
/// An rcode above 15 keeps its high bits in the OPT record. If the query had none, the reply
/// has none either, and the low bits alone would read as another rcode: it is SERVFAIL then.
pub(crate) fn error(q: &Question, rcode: ResponseCode) -> Vec<u8> {
    reply(q, rcode, |_| {})
}

/// The reply that passes on an upstream answer: its rcode, its TC flag and its three record
/// sections, with every TTL set to `ttl` if one is given.
///
/// Nothing else of `upstream` reaches the client: not its ID, question, OPT record or other
/// flags. An upstream rcode above 15 is about the query this crate sent, not the client's, so
/// the client gets SERVFAIL with no records.
pub(crate) fn relay(q: &Question, upstream: &Message, ttl: Option<u32>) -> Vec<u8> {
    let rcode = upstream.metadata.response_code;
    if is_extended(rcode) {
        return error(q, ResponseCode::ServFail);
    }
    let section = |records: &[Record]| -> Vec<Record> {
        let mut records = records.to_vec();
        if let Some(ttl) = ttl {
            for record in &mut records {
                record.ttl = ttl;
            }
        }
        records
    };
    reply(q, rcode, |message| {
        message.metadata.truncation = upstream.metadata.truncation;
        message.answers = section(&upstream.answers);
        message.authorities = section(&upstream.authorities);
        message.additionals = section(&upstream.additionals);
    })
}

/// A success that holds the address of the family asked for under the question's name: `v4`
/// for A, `v6` for AAAA, and no record for any other type.
fn address(q: &Question, v4: Ipv4Addr, v6: Ipv6Addr, ttl: u32) -> Vec<u8> {
    let data = match q.query().query_type {
        RecordType::A => Some(RData::A(A(v4))),
        RecordType::AAAA => Some(RData::AAAA(AAAA(v6))),
        _ => None,
    };
    let answer = data.map(|data| Record::from_rdata(q.query().name.clone(), ttl, data));
    reply(q, ResponseCode::NoError, |message| {
        message.answers.extend(answer);
    })
}

/// Whether the name asked for is `zone` or under it, compared label by label as sent and
/// without regard to case. A label that holds a dot is one label, and never matches two.
fn at_or_under(q: &Question, zone: &str) -> bool {
    let mut labels = q.query().name.iter().rev();
    zone.rsplit('.').all(|part| {
        labels
            .next()
            .is_some_and(|label| label.eq_ignore_ascii_case(part.as_bytes()))
    })
}

/// Encodes one reply. What every reply shares is decided here:
///
/// - the client's ID and its question as it spelled it;
/// - the flags: RA set, RD copied, AA, AD and CD clear;
/// - an OPT record only if the query had one: payload 1232, version 0, DO echoed, no options;
/// - over UDP, a reply above the size limit gives way to its truncated form: TC set, the
///   question and the OPT record only. The limit is 512 bytes for a query without an OPT
///   record, and otherwise the size the client announced, held to 512–1232.
///
/// `fill` adds the records. If hickory cannot encode the result, the reply is a 12-byte
/// SERVFAIL header.
fn reply(q: &Question, rcode: ResponseCode, fill: impl FnOnce(&mut Message)) -> Vec<u8> {
    let has_opt = q.edns_payload().is_some();
    let mut message = Message::response(q.id(), OpCode::Query);
    message.metadata.recursion_desired = q.rd();
    message.metadata.recursion_available = true;
    message.metadata.response_code = if is_extended(rcode) && !has_opt {
        ResponseCode::ServFail
    } else {
        rcode
    };
    message.add_query(q.query().clone());
    if has_opt {
        let mut edns = Edns::new();
        edns.set_max_payload(UDP_PAYLOAD)
            .set_dnssec_ok(q.dnssec_ok());
        message.set_edns(edns);
    }
    fill(&mut message);

    // TCP has no limit of ours. hickory writes at most 65,535 bytes, all that a TCP frame
    // holds, and sets TC itself if it had to leave records out.
    // hickory 0.26 already reads an announced size under 512 as 512; the lower bound is kept
    // here so that the rule does not rest on that.
    let limit = match (q.transport(), q.edns_payload()) {
        (Transport::Tcp, _) => None,
        (Transport::Udp, None) => Some(UDP_WITHOUT_OPT),
        (Transport::Udp, Some(announced)) => Some(announced.clamp(UDP_WITHOUT_OPT, UDP_PAYLOAD)),
    };
    let encoded = message.to_vec().and_then(|bytes| {
        if limit.is_some_and(|limit| bytes.len() > usize::from(limit)) {
            message.truncate().to_vec()
        } else {
            Ok(bytes)
        }
    });
    encoded.unwrap_or_else(|_| {
        // The six fields of a header: ID, flags, and four counts of zero.
        let flags = [QR | u8::from(q.rd()), RA | SERVFAIL];
        [q.id().to_be_bytes(), flags, [0; 2], [0; 2], [0; 2], [0; 2]].concat()
    })
}

/// Whether `rcode` is above 15, the most the four bits in the header hold.
fn is_extended(rcode: ResponseCode) -> bool {
    u16::from(rcode) > 15
}

#[cfg(test)]
mod tests {
    use hickory_proto::rr::Name;
    use hickory_proto::rr::rdata::TXT;

    use super::*;
    use crate::query::{Parsed, parse_query};
    use crate::testutil::{
        Q_AAAA_EDNS, Q_DIG, Q_DO, Q_MIXED, Q_PLAIN, R_A, Rng, decode, query, question,
        question_tcp, unhex,
    };

    fn example_com() -> Name {
        Name::from_ascii("example.com.").unwrap()
    }

    /// A response holding `example.com` A `192.0.2.0` … `192.0.2.(n-1)`, TTL 60. With `Q_PLAIN`'s
    /// question, 40 of them encode to 669 bytes and 100 to 1,629.
    fn a_records(n: u8) -> Message {
        let mut message = Message::response(0x1234, OpCode::Query);
        message.add_answers((0..n).map(|i| {
            Record::from_rdata(example_com(), 60, RData::A(A(Ipv4Addr::new(192, 0, 2, i))))
        }));
        message
    }

    /// `Q_AAAA_EDNS` asking for A instead, with an OPT that announces `size` bytes.
    fn with_payload(size: u16) -> Vec<u8> {
        let mut packet = unhex(Q_AAAA_EDNS);
        packet[26] = 1;
        packet[32..34].copy_from_slice(&size.to_be_bytes());
        packet
    }

    /// Whether the TC flag is set.
    fn truncated(reply: &[u8]) -> bool {
        reply[2] & 0x02 != 0
    }

    #[test]
    fn blocked_a_is_the_hand_checked_packet() {
        // header: ID, QR RD RA, 1 question, 1 answer | question as the client spelled it
        // answer: pointer to offset 12, type A, class IN, TTL 2, 4 bytes 0.0.0.0
        // (RFC 1035 4.1.1 to 4.1.4)
        assert_eq!(
            blocked(&question(&unhex(Q_MIXED))),
            unhex(
                "1234 8180 0001 0001 0000 0000  07 4558616d706c65 03 636f4d 00 0001 0001 \
                 c00c 0001 0001 00000002 0004 00000000"
            )
        );
    }

    #[test]
    fn blocked_aaaa_echoes_edns() {
        assert_eq!(
            blocked(&question(&unhex(Q_AAAA_EDNS))),
            unhex(
                "3456 8180 0001 0001 0000 0001  07 6578616d706c65 03 636f6d 00 001c 0001 \
                 c00c 001c 0001 00000002 0010 00000000 00000000 00000000 00000000 \
                 00 0029 04d0 00000000 0000"
            )
        );
        assert!(blocked(&question(&unhex(Q_DO))).ends_with(&unhex("00 0029 04d0 00008000 0000")));
        // No cookie is echoed.
        assert!(blocked(&question(&unhex(Q_DIG))).ends_with(&unhex("00 0029 04d0 00000000 0000")));
    }

    #[test]
    fn blocked_other_type_is_empty_success() {
        let q = query(0x4567, "example.com", 16);
        let mut expected = q.clone();
        expected[2] = 0x81;
        expected[3] = 0x80;
        assert_eq!(blocked(&question(&q)), expected);
    }

    #[test]
    fn errors_carry_the_rcode() {
        let s = error(&question(&unhex(Q_PLAIN)), ResponseCode::ServFail);
        assert_eq!((s.len(), s[3]), (29, 0x82));
        let mut v1 = unhex(Q_AAAA_EDNS);
        let n = v1.len();
        v1[n - 5] = 1;
        let Parsed::Refuse(q, rcode) = parse_query(&v1, Transport::Udp) else {
            panic!()
        };
        let b = error(&q, rcode);
        // The low rcode bits; the 1 is in the OPT.
        assert_eq!(b[3] & 0x0f, 0);
        assert!(b.ends_with(&unhex("00 0029 04d0 01000000 0000")));
    }

    // Without an OPT there is nowhere to put the high bits, and the low ones alone would read as
    // another rcode: BADVERS as success, BADCOOKIE as YXDOMAIN.
    #[test]
    fn an_extended_rcode_without_an_opt_is_servfail() {
        for rcode in [ResponseCode::BADVERS, ResponseCode::BADCOOKIE] {
            let b = error(&question(&unhex(Q_PLAIN)), rcode);
            assert_eq!((b.len(), b[3]), (29, 0x82), "{rcode:?}");
        }
    }

    #[test]
    fn local_names() {
        let rcode =
            |name: &str, qtype: u16| local(&question(&query(1, name, qtype))).map(|b| b[3] & 0x0f);
        for (name, qtype) in [
            ("printer", 1),
            ("PRINTER", 28),
            ("1.0.168.192.in-addr.arpa", 12),
            ("7.0.0.10.in-addr.arpa", 12),
            ("1.0.16.172.in-addr.arpa", 12),
            ("1.0.31.172.in-addr.arpa", 12),
            ("16.172.in-addr.arpa", 2),
            ("1.0.254.169.in-addr.arpa", 12),
            ("1.0.0.127.in-addr.arpa", 12),
            ("1.0.d.f.ip6.arpa", 12),
            ("0.8.e.f.ip6.arpa", 12),
            ("0.b.e.f.ip6.arpa", 12),
        ] {
            assert_eq!(rcode(name, qtype), Some(3), "{name}");
        }
        for name in [
            "1.0.15.172.in-addr.arpa",
            "1.0.32.172.in-addr.arpa",
            "1.0.116.172.in-addr.arpa",
            "1.2.0.192.in-addr.arpa",
            "7.113.0.203.in-addr.arpa",
            "0.c.e.f.ip6.arpa",
            "example.com",
            "localhost.example.com",
        ] {
            assert_eq!(rcode(name, 12), None, "{name}");
        }
        // The root.
        assert!(local(&question(&unhex("1234010000010000000000000000020001"))).is_none());
        let a = decode(&local(&question(&query(1, "LocalHost", 1))).unwrap());
        assert_eq!(
            (
                a.answers.len(),
                a.answers[0].ttl,
                a.answers[0].data.to_string().as_str()
            ),
            (1, 3600, "127.0.0.1")
        );
        assert_eq!(
            decode(&local(&question(&query(1, "localhost", 28))).unwrap()).answers[0]
                .data
                .to_string(),
            "::1"
        );
        assert_eq!(rcode("localhost", 16), Some(0));
        assert!(
            decode(&local(&question(&query(1, "localhost", 16))).unwrap())
                .answers
                .is_empty()
        );
    }

    // The "Single-label names" row: a single-label name other than `localhost` is answered here
    // for A and AAAA only. A validating client asks `com. DS` and `com. DNSKEY`, and must get the
    // upstream's signed answer, not an unsigned NXDOMAIN.
    #[test]
    fn single_label_names_are_answered_here_for_address_types_only() {
        let rcode =
            |name: &str, qtype: u16| local(&question(&query(1, name, qtype))).map(|b| b[3] & 0x0f);
        for qtype in [1, 28] {
            assert_eq!(rcode("printer", qtype), Some(3), "printer {qtype}");
            assert_eq!(rcode("PRINTER", qtype), Some(3), "PRINTER {qtype}");
        }
        // DS, DNSKEY, NS, SOA, MX, TXT, ANY and an unknown type.
        for qtype in [43, 48, 2, 6, 15, 16, 255, 999] {
            for name in ["com", "example", "printer", "PRINTER"] {
                assert_eq!(rcode(name, qtype), None, "{name} {qtype}");
            }
        }
        // `localhost` is as it was for every type: the loopback address for A and AAAA, and an
        // empty success for the rest.
        for qtype in [2, 6, 15, 16, 43, 48, 255, 999] {
            let b = local(&question(&query(1, "localhost", qtype))).unwrap();
            assert_eq!(b[3] & 0x0f, 0, "localhost {qtype}");
            assert!(decode(&b).answers.is_empty(), "localhost {qtype}");
        }
        // The one label `a.b` is a single label whatever its text holds.
        let dotted =
            |qtype: &str| format!("0001 0100 0001 0000 0000 0000  03 612e62  00  {qtype} 0001");
        assert_eq!(
            local(&question(&unhex(&dotted("002b")))).map(|b| b[3] & 0x0f),
            None
        );
        assert_eq!(
            local(&question(&unhex(&dotted("001c")))).map(|b| b[3] & 0x0f),
            Some(3)
        );
    }

    // The "Private reverse zones" row, zone by zone, and the names next to each that it leaves
    // to the upstream.
    #[test]
    fn local_reverse_zones_are_those_of_the_table_and_no_others() {
        let nxdomain = |name: &str| local(&question(&query(1, name, 12))).map(|b| b[3] & 0x0f);
        for second in 0..=255 {
            let zone = format!("{second}.172.in-addr.arpa");
            let expected = (16..=31).contains(&second).then_some(3);
            assert_eq!(nxdomain(&zone), expected, "{zone}");
            assert_eq!(nxdomain(&format!("7.{zone}")), expected, "7.{zone}");
        }
        for zone in [
            "10.in-addr.arpa",
            "168.192.in-addr.arpa",
            "254.169.in-addr.arpa",
            "127.in-addr.arpa",
            "d.f.ip6.arpa",
            "8.e.f.ip6.arpa",
            "9.e.f.ip6.arpa",
            "a.e.f.ip6.arpa",
            "b.e.f.ip6.arpa",
            "A.E.F.IP6.ARPA",
            "1.0.168.192.IN-ADDR.Arpa",
        ] {
            assert_eq!(nxdomain(zone), Some(3), "{zone}");
        }
        for name in [
            "in-addr.arpa",
            "ip6.arpa",
            "11.in-addr.arpa",
            "192.in-addr.arpa",
            "172.in-addr.arpa",
            "169.192.in-addr.arpa",
            "168.193.in-addr.arpa",
            "254.168.in-addr.arpa",
            "10.ip6.arpa",
            "f.ip6.arpa",
            "e.f.ip6.arpa",
            "c.f.ip6.arpa",
            "7.e.f.ip6.arpa",
            "d.f.in-addr.arpa",
            "10.in-addr.arpa.example.com",
            "10.in-addr.test",
        ] {
            assert_eq!(nxdomain(name), None, "{name}");
        }
    }

    // `Question::name` writes a dot inside a label as `\.`, so text that ends in a zone's name
    // need not be under the zone.
    #[test]
    fn local_is_judged_on_the_labels_of_the_wire() {
        let rcode = |packet: &str| local(&question(&unhex(packet))).map(|b| b[3] & 0x0f);
        // `1`, then the one label `x.10`, then `in-addr`, `arpa`: not under `10.in-addr.arpa`.
        let dotted = "0001 0100 0001 0000 0000 0000 \
                      01 31  04 782e3130  07 696e2d61646472  04 61727061  00  000c 0001";
        assert_eq!(question(&unhex(dotted)).name(), r"1.x\.10.in-addr.arpa");
        assert_eq!(rcode(dotted), None);
        // The one label `a.b`: a single-label name, though its text holds a dot.
        assert_eq!(
            rcode("0001 0100 0001 0000 0000 0000  03 612e62  00  0001 0001"),
            Some(3)
        );
        // `a b` under `10.in-addr.arpa`: in the zone, whatever bytes the label holds.
        let odd = "0001 0100 0001 0000 0000 0000 \
                   03 612062  02 3130  07 696e2d61646472  04 61727061  00  000c 0001";
        assert_eq!(rcode(odd), Some(3));
    }

    #[test]
    fn relay_sets_ttls_and_clears_aa_and_ad() {
        let q = question(&unhex(Q_PLAIN));
        let mut flagged = unhex(R_A);
        flagged[2] |= 0x04;
        flagged[3] |= 0x20;
        assert_eq!(relay(&q, &decode(&flagged), None), unhex(R_A));
        assert!(
            decode(&relay(&q, &decode(&unhex(R_A)), Some(115)))
                .answers
                .iter()
                .all(|r| r.ttl == 115)
        );
    }

    #[test]
    fn relay_overwrites_the_ttl_in_every_section() {
        let mut upstream = a_records(2);
        upstream.add_authority(a_records(1).answers.remove(0));
        upstream.add_additional(a_records(1).answers.remove(0));
        let q = question(&unhex(Q_PLAIN));
        let kept = decode(&relay(&q, &upstream, None));
        assert_eq!(
            (
                kept.answers.len(),
                kept.authorities.len(),
                kept.additionals.len()
            ),
            (2, 1, 1)
        );
        assert!(kept.all_sections().all(|r| r.ttl == 60));
        let set = decode(&relay(&q, &upstream, Some(0)));
        assert_eq!(set.all_sections().count(), 4);
        assert!(set.all_sections().all(|r| r.ttl == 0));
    }

    #[test]
    fn rd_is_copied_and_cd_is_cleared() {
        let mut iterative = unhex(Q_PLAIN);
        iterative[2] = 0;
        let mut checking_disabled = unhex(R_A);
        checking_disabled[3] |= 0x10;
        let reply = relay(&question(&iterative), &decode(&checking_disabled), None);
        assert_eq!(reply[2..4], [0x80, 0x80]);
        assert_eq!(blocked(&question(&iterative))[2..4], [0x80, 0x80]);
    }

    // The upstream's ID is the caller's own, and its question may be spelled another way.
    #[test]
    fn relay_keeps_the_clients_id_and_question() {
        let mut upstream = decode(&unhex(R_A));
        upstream.metadata.id = 0xbeef;
        let reply = relay(&question(&unhex(Q_MIXED)), &upstream, None);
        assert_eq!(reply[..2], [0x12, 0x34]);
        assert_eq!(reply[4..6], [0, 1]);
        assert_eq!(reply[12..29], unhex(Q_MIXED)[12..]);
        assert_eq!(decode(&reply).answers, upstream.answers);

        // Not even another question, or none at all, reaches the client.
        upstream.queries = decode(&query(1, "example.net", 28)).queries;
        assert_eq!(relay(&question(&unhex(Q_MIXED)), &upstream, None), reply);
        upstream.queries.clear();
        assert_eq!(relay(&question(&unhex(Q_MIXED)), &upstream, None), reply);
    }

    // The upstream's own OPT stays behind: the client gets one only if it sent one.
    #[test]
    fn relay_does_not_pass_on_the_upstreams_opt() {
        let mut upstream = decode(&unhex(R_A));
        let mut edns = Edns::new();
        edns.set_max_payload(4096).set_dnssec_ok(true);
        upstream.set_edns(edns);
        assert_eq!(
            relay(&question(&unhex(Q_PLAIN)), &upstream, None),
            unhex(R_A)
        );
        let with_opt = relay(&question(&with_payload(1232)), &upstream, None);
        assert!(with_opt.ends_with(&unhex("00 0029 04d0 00000000 0000")));
    }

    // An answer the upstream cut short must not reach the client looking whole.
    #[test]
    fn relay_keeps_tc_from_the_upstream() {
        let mut cut = unhex(R_A);
        cut[2] |= 0x02;
        let reply = relay(&question_tcp(&unhex(Q_PLAIN)), &decode(&cut), None);
        assert_eq!(reply, cut);
    }

    #[test]
    fn udp_replies_over_the_limit_are_truncated() {
        let small = relay(&question(&unhex(Q_PLAIN)), &a_records(40), None);
        assert!(
            truncated(&small)
                && small.len() == 29
                && small[6..8] == [0, 0]
                && small[12..] == unhex(Q_PLAIN)[12..]
        );
        let tcp = relay(&question_tcp(&unhex(Q_PLAIN)), &a_records(40), None);
        assert!(!truncated(&tcp) && tcp.len() == 669);
        let edns = relay(&question(&with_payload(1232)), &a_records(40), None);
        assert!(!truncated(&edns) && edns.len() == 680);
        // Held up to 512.
        assert!(truncated(&relay(
            &question(&with_payload(100)),
            &a_records(40),
            None
        )));
        // Held down to 1232.
        assert!(truncated(&relay(
            &question(&with_payload(4096)),
            &a_records(100),
            None
        )));
        assert!(!truncated(&relay(
            &question_tcp(&with_payload(4096)),
            &a_records(100),
            None
        )));
    }

    // `n` records come to 29 + 16n bytes without an OPT and to 40 + 16n with one.
    #[test]
    fn the_limit_is_the_last_size_that_passes() {
        let plain = question(&unhex(Q_PLAIN));
        let fits = relay(&plain, &a_records(30), None);
        assert!(!truncated(&fits) && fits.len() == 509);
        assert!(truncated(&relay(&plain, &a_records(31), None)));

        // The size announced, the most records that fit, and the bytes they come to.
        for (announced, most, len) in [
            (0, 29, 504),
            (100, 29, 504),
            (512, 29, 504),
            (600, 35, 600),
            (1232, 74, 1224),
            (1233, 74, 1224),
            (4096, 74, 1224),
            (65535, 74, 1224),
        ] {
            let q = question(&with_payload(announced));
            let fits = relay(&q, &a_records(most), None);
            assert!(!truncated(&fits) && fits.len() == len, "{announced}");
            let cut = relay(&q, &a_records(most + 1), None);
            // The truncated reply keeps the OPT.
            assert!(
                truncated(&cut) && cut.len() == 40 && cut[10..12] == [0, 1],
                "{announced}"
            );
        }
    }

    // A TCP frame holds 65,535 bytes. hickory stops writing there, drops the records that do
    // not fit and sets TC, so the caller can always frame what it is given.
    #[test]
    fn a_tcp_reply_always_fits_a_frame() {
        let mut huge = a_records(0);
        for _ in 0..20 {
            huge.answers.extend(a_records(250).answers);
        }
        let reply = relay(&question_tcp(&unhex(Q_PLAIN)), &huge, None);
        assert!(truncated(&reply) && reply.len() <= 65_535 && reply.len() > 60_000);
        let sent = decode(&reply).answers.len();
        assert!(sent > 0 && sent < 5_000, "{sent} records");
        assert_eq!(relay(&question(&unhex(Q_PLAIN)), &huge, None).len(), 29);
    }

    #[test]
    fn extended_upstream_rcode_becomes_servfail() {
        let mut m = a_records(1);
        m.metadata.response_code = ResponseCode::BADCOOKIE;
        let b = relay(&question(&unhex(Q_PLAIN)), &m, None);
        assert_eq!((b[3] & 0x0f, b.len()), (2, 29));
        // With an OPT to hold the high bits it is still SERVFAIL, and still without records.
        let b = relay(&question(&with_payload(1232)), &m, None);
        assert_eq!((b[3] & 0x0f, b.len(), b[6..8] == [0, 0]), (2, 40, true));
        assert!(b.ends_with(&unhex("00 0029 04d0 00000000 0000")));
    }

    // A character string holds at most 255 bytes, and hickory refuses to write a longer one. No
    // decoded answer holds one; this stands for whatever else may fail to encode.
    #[test]
    fn an_answer_that_cannot_be_encoded_is_the_servfail_header() {
        let mut m = a_records(1);
        let too_long = TXT::from_bytes(vec![&[b'x'; 256]]);
        m.add_answer(Record::from_rdata(example_com(), 60, RData::TXT(too_long)));
        assert_eq!(
            relay(&question(&unhex(Q_PLAIN)), &m, None),
            unhex("1234 8182 0000 0000 0000 0000")
        );
        let mut iterative = with_payload(1232);
        iterative[2] = 0;
        assert_eq!(
            relay(&question_tcp(&iterative), &m, None),
            unhex("3456 8082 0000 0000 0000 0000")
        );
    }

    /// Checks what every reply to `q` owes the client, whatever else it holds.
    fn assert_owed(q: &Question, reply: &[u8]) {
        let message = decode(reply);
        let meta = &message.metadata;
        assert_eq!(reply[..2], q.id().to_be_bytes());
        assert_eq!(reply[2] & 0xf8, 0x80, "a response to a standard query");
        assert!(meta.recursion_available);
        assert_eq!(meta.recursion_desired, q.rd());
        assert!(!meta.authoritative && !meta.authentic_data && !meta.checking_disabled);

        let [asked] = message.queries.as_slice() else {
            panic!("{} questions", message.queries.len())
        };
        // `Name` compares without case; the labels are compared as bytes.
        assert!(asked.name.iter().eq(q.query().name.iter()));
        assert_eq!(asked.query_type, q.query().query_type);
        assert_eq!(asked.query_class, q.query().query_class);

        assert_eq!(message.edns.is_some(), q.edns_payload().is_some());
        if let Some(edns) = &message.edns {
            assert_eq!((edns.max_payload(), edns.version()), (1232, 0));
            assert_eq!(edns.flags().dnssec_ok, q.dnssec_ok());
            assert!(edns.options().as_ref().is_empty());
        }

        if q.transport() == Transport::Udp {
            let limit = q.edns_payload().map_or(512, |size| size.clamp(512, 1232));
            assert!(reply.len() <= usize::from(limit), "{} bytes", reply.len());
        }
    }

    #[test]
    fn every_reply_keeps_the_id_the_question_and_the_limit() {
        let queries = [
            unhex(Q_PLAIN),
            unhex(Q_MIXED),
            unhex(Q_DIG),
            unhex(Q_AAAA_EDNS),
            unhex(Q_DO),
            query(0x789a, "localhost", 28),
            query(0x89ab, "1.0.168.192.in-addr.arpa", 12),
        ];
        let answers = [
            unhex(R_A),
            a_records(40).to_vec().unwrap(),
            a_records(100).to_vec().unwrap(),
        ];
        let mut rng = Rng::new(6);
        let (mut refused, mut answered_here, mut relayed, mut cut) = (0, 0, 0, 0);
        for i in 0..60_000 {
            let packet = rng.mutate(&queries[i % queries.len()]);
            let transport = if i % 3 == 0 {
                Transport::Tcp
            } else {
                Transport::Udp
            };
            let (q, rcode) = match parse_query(&packet, transport) {
                Parsed::Ok(q) => (q, ResponseCode::ServFail),
                Parsed::Refuse(q, rcode) => {
                    refused += 1;
                    (q, rcode)
                }
                Parsed::HeaderOnly(_) | Parsed::Drop => continue,
            };
            assert_owed(&q, &blocked(&q));
            assert_owed(&q, &error(&q, rcode));
            if let Some(reply) = local(&q) {
                answered_here += 1;
                assert_owed(&q, &reply);
            }
            let upstream = rng.mutate(&answers[i % answers.len()]);
            if let Ok(upstream) = Message::from_vec(&upstream) {
                relayed += 1;
                for ttl in [None, Some(30)] {
                    let reply = relay(&q, &upstream, ttl);
                    assert_owed(&q, &reply);
                    cut += usize::from(truncated(&reply) && !upstream.metadata.truncation);
                }
            }
        }
        // Guards against a generator that only ever reaches one branch.
        assert!(
            refused > 1_000 && answered_here > 1_000 && relayed > 1_000 && cut > 1_000,
            "{refused} refused, {answered_here} answered here, {relayed} relayed, {cut} cut"
        );
    }
}
