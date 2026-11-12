//! A client's packet becomes a `Question` or a rejection; a `Question` builds the upstream query.

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_proto::rr::{DNSClass, Name};

pub(crate) use hickory_proto::op::ResponseCode;

use crate::Transport;
use crate::answer::UDP_PAYLOAD;

/// The length of a DNS header in bytes.
const HEADER_LEN: usize = 12;

/// The question count of the fifth and sixth header bytes that a query to decide has.
const QUESTION_COUNT: [u8; 2] = [0, 1];

/// In the third header byte: set on a response.
const QR: u8 = 0x80;
/// In the third header byte: the opcode, 0 for a standard query.
const OPCODE: u8 = 0x78;
/// In the third header byte: recursion desired.
const RD: u8 = 0x01;
/// In the fourth header byte: recursion available.
const RA: u8 = 0x80;

/// The rcode for a packet that cannot be read.
const FORMERR: u8 = 1;
/// The rcode for an opcode that is not served.
const NOTIMP: u8 = 4;

/// Incremental zone transfer: a query type that is refused.
const IXFR: u16 = 251;
/// Zone transfer: a query type that is refused.
const AXFR: u16 = 252;

/// One question from a client, checked and ready to be decided.
#[derive(Clone, Debug)]
pub(crate) struct Question {
    id: u16,
    query: Query,
    name: String,
    /// Whether every label of the name is made of `a-z 0-9 - _` only, as a listed name is.
    listable: bool,
    rd: bool,
    dnssec_ok: bool,
    edns_payload: Option<u16>,
    transport: Transport,
}

impl Question {
    /// The ID the client chose.
    pub(crate) fn id(&self) -> u16 {
        self.id
    }

    /// The name in lower case and presentation form, without the trailing dot; `""` for the root.
    ///
    /// Two names that differ on the wire, other than in case, never give the same text. A name
    /// that could be on a list reads as the list has it, in at most 253 bytes. Any other carries
    /// hickory's escapes, a dot inside a label being `\.`, and is up to 1,003 bytes long: 250
    /// label bytes that each become an escape such as `\001` of 4 bytes, and 3 dots.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// The query type as its number.
    pub(crate) fn qtype(&self) -> u16 {
        u16::from(self.query.query_type)
    }

    /// How many labels the name has; 0 for the root.
    #[cfg(test)]
    pub(crate) fn labels(&self) -> usize {
        self.query.name.iter().count()
    }

    /// Whether the client asked for recursion.
    pub(crate) fn rd(&self) -> bool {
        self.rd
    }

    /// Whether the client set the DO bit; false without an OPT record.
    pub(crate) fn dnssec_ok(&self) -> bool {
        self.dnssec_ok
    }

    /// The UDP payload size the client announced; `None` when the query had no OPT record.
    pub(crate) fn edns_payload(&self) -> Option<u16> {
        self.edns_payload
    }

    /// How the query arrived.
    pub(crate) fn transport(&self) -> Transport {
        self.transport
    }

    /// The question as the client spelled it.
    pub(crate) fn query(&self) -> &Query {
        &self.query
    }

    /// The name to look up in the block set: `name()`, if every label is made of `a-z 0-9 - _`
    /// only once lower-cased. Any other name cannot be on a list, however its text reads.
    pub(crate) fn block_key(&self) -> Option<&str> {
        self.listable.then_some(self.name.as_str())
    }

    /// The query to send upstream under `id`: the client's question unchanged, RD set, and an OPT
    /// record with payload 1232, version 0, the client's DO bit and no options.
    ///
    /// Empty if hickory cannot encode the question, which one it has decoded does not cause.
    pub(crate) fn upstream_query(&self, id: u16) -> Vec<u8> {
        let mut message = Message::new(id, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.add_query(self.query.clone());
        let mut edns = Edns::new();
        edns.set_max_payload(UDP_PAYLOAD)
            .set_dnssec_ok(self.dnssec_ok);
        message.set_edns(edns);
        message.to_vec().unwrap_or_default()
    }
}

/// What a client's packet turned out to be.
#[derive(Debug)]
pub(crate) enum Parsed {
    /// A question to decide.
    Ok(Question),
    /// A question to answer with this rcode, echoing the question.
    Refuse(Question, ResponseCode),
    /// A packet to answer with exactly these bytes.
    HeaderOnly([u8; HEADER_LEN]),
    /// A packet that gets no answer.
    Drop,
}

/// Checks one packet from a client. Never panics, whatever the bytes.
pub(crate) fn parse_query(packet: &[u8], transport: Transport) -> Parsed {
    let Some(&[id_high, id_low, flags, _, count_high, count_low, ..]) =
        packet.first_chunk::<HEADER_LEN>()
    else {
        return Parsed::Drop;
    };
    if flags & QR != 0 {
        return Parsed::Drop;
    }
    let header_only = |rcode: u8| {
        let flags = QR | flags & (OPCODE | RD);
        Parsed::HeaderOnly([id_high, id_low, flags, RA | rcode, 0, 0, 0, 0, 0, 0, 0, 0])
    };
    if flags & OPCODE != 0 {
        return header_only(NOTIMP);
    }
    // Judged before hickory reads anything: it reserves room for every question the header claims,
    // which is about 5.8 MB for the 65,535 that a packet of 12 bytes can claim.
    if [count_high, count_low] != QUESTION_COUNT {
        return header_only(FORMERR);
    }
    let Ok(message) = Message::from_vec(packet) else {
        return header_only(FORMERR);
    };
    let Ok([query]) = <[Query; 1]>::try_from(message.queries) else {
        return header_only(FORMERR);
    };
    let (name, listable) = presentation(&query.name);
    let question = Question {
        id: u16::from_be_bytes([id_high, id_low]),
        name,
        listable,
        rd: flags & RD != 0,
        dnssec_ok: message.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok),
        edns_payload: message.edns.as_ref().map(Edns::max_payload),
        transport,
        query,
    };
    if message.edns.is_some_and(|edns| edns.version() != 0) {
        return Parsed::Refuse(question, ResponseCode::BADVERS);
    }
    if question.query.query_class != DNSClass::IN || matches!(question.qtype(), IXFR | AXFR) {
        return Parsed::Refuse(question, ResponseCode::Refused);
    }
    Parsed::Ok(question)
}

/// The text of `name` for `Question::name`, and whether every label is made of `a-z 0-9 - _`
/// only once lower-cased.
fn presentation(name: &Name) -> (String, bool) {
    let mut lower = name.to_lowercase();
    // A name read from a packet always is; said here so that the dot removed below is the root's.
    lower.set_fqdn(true);
    let listable = lower.iter().all(|label| {
        label
            .iter()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'))
    });
    if !listable {
        // hickory escapes every byte that is not a letter, a digit, `-` or `_`, so the text
        // holds a `\` or a `*`, which no listable name does.
        let mut text = lower.to_ascii();
        text.pop();
        return (text, false);
    }
    // Written out here: hickory would escape a leading hyphen, and a list holds the name bare.
    let mut text = String::with_capacity(lower.len());
    for label in lower.iter() {
        if !text.is_empty() {
            text.push('.');
        }
        text.extend(label.iter().copied().map(char::from));
    }
    (text, true)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};

    use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};

    use super::*;
    use crate::BlockSetBuilder;
    use crate::testutil::{
        Q_AAAA_EDNS, Q_DIG, Q_DO, Q_MIXED, Q_PLAIN, Rng, decode, query, question, question_tcp,
        unhex,
    };

    fn parse(hex: &str) -> Parsed {
        parse_query(&unhex(hex), Transport::Udp)
    }

    /// The bytes of a `HeaderOnly` reply; panics on any other variant.
    fn header_only(parsed: Parsed) -> Vec<u8> {
        match parsed {
            Parsed::HeaderOnly(bytes) => bytes.to_vec(),
            other => panic!("not a header-only reply: {other:?}"),
        }
    }

    /// An A query whose name has exactly these labels, whatever bytes they hold.
    fn with_labels(labels: &[&[u8]]) -> Vec<u8> {
        let mut packet = query(1, "", 1);
        let name: Vec<u8> = labels
            .iter()
            .flat_map(|label| [&[label.len() as u8], *label].concat())
            .collect();
        packet.splice(12..12, name);
        packet
    }

    #[test]
    fn plain_query_is_accepted() {
        let q = question(&unhex(Q_PLAIN));
        assert_eq!(
            (q.id(), q.name(), q.qtype(), q.labels()),
            (0x1234, "example.com", 1, 2)
        );
        assert_eq!(
            (q.rd(), q.dnssec_ok(), q.edns_payload(), q.block_key()),
            (true, false, None, Some("example.com"))
        );
        assert_eq!(q.transport(), Transport::Udp);
        let m = question(&unhex(Q_MIXED));
        assert_eq!(
            (m.name(), m.block_key()),
            ("example.com", Some("example.com"))
        );
        let d = question(&unhex(Q_DIG));
        assert_eq!(
            (d.id(), d.edns_payload(), d.dnssec_ok()),
            (0xabcd, Some(1232), false)
        );
        assert!(question(&unhex(Q_DO)).dnssec_ok());
        assert_eq!(question_tcp(&unhex(Q_PLAIN)).transport(), Transport::Tcp);
    }

    #[test]
    fn rd_is_read_from_the_client() {
        let mut iterative = unhex(Q_PLAIN);
        iterative[2] = 0;
        assert!(!question(&iterative).rd());
    }

    #[test]
    fn upstream_query_is_the_packet_a_real_resolver_answered() {
        let plain =
            "beef01000001000000000001076578616d706c6503636f6d000001000100002904d0000000000000";
        assert_eq!(
            question(&unhex(Q_PLAIN)).upstream_query(0xbeef),
            unhex(plain)
        );
        // The cookie and the AD flag are not forwarded.
        assert_eq!(question(&unhex(Q_DIG)).upstream_query(0xbeef), unhex(plain));
        assert_eq!(question(&unhex(Q_DO)).upstream_query(0x6789), unhex(Q_DO));
        // The client's spelling of the name.
        assert_eq!(
            question(&unhex(Q_MIXED)).upstream_query(1)[12..25],
            unhex(Q_MIXED)[12..25]
        );
    }

    // The client's address is not passed on: the upstream's answer is the same for every client.
    #[test]
    fn upstream_query_strips_the_clients_ecs_option() {
        let mut client = Message::new(0x4321, MessageType::Query, OpCode::Query);
        client.metadata.recursion_desired = true;
        client.add_query(question(&unhex(Q_PLAIN)).query().clone());
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        let subnet = ClientSubnet::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24, 0);
        edns.options_mut().insert(EdnsOption::Subnet(subnet));
        client.set_edns(edns);
        let packet = client.to_vec().unwrap();
        // The packet does carry the option, or the test would prove nothing.
        assert!(
            decode(&packet)
                .edns
                .unwrap()
                .option(EdnsCode::Subnet)
                .is_some()
        );

        let upstream = question(&packet).upstream_query(0xbeef);
        let edns = decode(&upstream).edns.expect("an OPT record");
        assert!(edns.options().options.is_empty());
        assert_eq!(edns.max_payload(), UDP_PAYLOAD);
        // The packet is the one for a client that sent no option.
        assert_eq!(upstream, question(&unhex(Q_PLAIN)).upstream_query(0xbeef));
    }

    #[test]
    fn upstream_query_sets_rd_whatever_the_client_sent() {
        let mut iterative = unhex(Q_PLAIN);
        iterative[2] = 0;
        assert_eq!(question(&iterative).upstream_query(7)[2..4], [0x01, 0x00]);
    }

    // 255 bytes on the wire, the most RFC 1035 allows: 253 as text.
    #[test]
    fn the_longest_name_is_accepted_and_forwarded() {
        let labels: [&[u8]; 4] = [&[b'a'; 63], &[b'b'; 63], &[b'c'; 63], &[b'd'; 61]];
        let packet = with_labels(&labels);
        let q = question(&packet);
        assert_eq!((q.name().len(), q.labels()), (253, 4));
        assert_eq!(q.block_key(), Some(q.name()));
        assert_eq!(q.upstream_query(1)[12..packet.len()], packet[12..]);

        let too_long: [&[u8]; 4] = [&[b'a'; 63], &[b'b'; 63], &[b'c'; 63], &[b'd'; 62]];
        assert_eq!(
            header_only(parse_query(&with_labels(&too_long), Transport::Udp))[3],
            0x81
        );
    }

    // The same name with every byte escaped: the longest text `name()` has.
    #[test]
    fn the_longest_escaped_name_is_1003_bytes() {
        let labels: [&[u8]; 4] = [&[1; 63], &[1; 63], &[1; 63], &[1; 61]];
        let q = question(&with_labels(&labels));
        assert_eq!((q.name().len(), q.labels(), q.block_key()), (1003, 4, None));
    }

    #[test]
    fn short_packets_and_responses_are_dropped() {
        let plain = unhex(Q_PLAIN);
        for len in 0..12 {
            assert!(
                matches!(parse_query(&plain[..len], Transport::Udp), Parsed::Drop),
                "{len} bytes"
            );
        }
        let mut response = plain;
        response[2] |= 0x80;
        assert!(matches!(
            parse_query(&response, Transport::Udp),
            Parsed::Drop
        ));
    }

    #[test]
    fn unreadable_body_or_question_count_is_formerr() {
        assert_eq!(
            header_only(parse("123401000001000000000000")),
            unhex("123481810000000000000000")
        );
        assert_eq!(
            header_only(parse("000000000000000000000000")),
            unhex("000080810000000000000000")
        );
        let two = "123401000002000000000000076578616d706c6503636f6d0000010001076578616d706c6503636f6d00001c0001";
        assert_eq!(header_only(parse(two)), unhex("123481810000000000000000"));
    }

    // hickory reserves room for every question the header claims before it reads one: for 65,535
    // that is about 5.8 MB from a 12-byte packet. The count is judged first, so any count but 1
    // gets the same reply, whatever follows.
    #[test]
    fn a_question_count_other_than_1_is_formerr_whatever_follows() {
        let body = &Q_PLAIN[24..];
        for count in ["0000", "0002", "0100", "ffff", "fffe", "8000"] {
            for rest in ["", body, &body.repeat(3)] {
                let packet = format!("12340100{count}000000000000{rest}");
                assert_eq!(
                    header_only(parse(&packet)),
                    unhex("123481810000000000000000"),
                    "{count} questions, {} bytes",
                    packet.len() / 2
                );
            }
        }
    }

    #[test]
    fn other_opcodes_are_notimp() {
        let mut status = unhex(Q_PLAIN);
        status[2] = 0x10; // opcode 2, RD clear
        assert_eq!(
            header_only(parse_query(&status, Transport::Udp)),
            unhex("123490840000000000000000")
        );
        // The opcode is judged before the body: a NOTIFY header alone is still NOTIMP, with RD copied.
        assert_eq!(
            header_only(parse("567821000000000000000000")),
            unhex("5678a1840000000000000000")
        );
    }

    #[test]
    fn edns_version_1_is_badvers() {
        let mut v1 = unhex(Q_AAAA_EDNS);
        let n = v1.len();
        v1[n - 5] = 1;
        assert!(matches!(
            parse_query(&v1, Transport::Udp),
            Parsed::Refuse(q, ResponseCode::BADVERS) if q.id() == 0x3456
        ));
    }

    #[test]
    fn other_classes_and_zone_transfers_are_refused() {
        let mut chaos = unhex(Q_PLAIN);
        let n = chaos.len();
        chaos[n - 1] = 3;
        assert!(matches!(
            parse_query(&chaos, Transport::Udp),
            Parsed::Refuse(_, ResponseCode::Refused)
        ));
        for t in [251, 252] {
            assert!(matches!(
                parse_query(&query(1, "example.com", t), Transport::Udp),
                Parsed::Refuse(_, ResponseCode::Refused)
            ));
        }
    }

    #[test]
    fn a_bad_edns_version_is_reported_before_the_class() {
        let mut both = unhex(Q_AAAA_EDNS);
        let n = both.len();
        both[n - 5] = 1; // EDNS version 1
        both[n - 12] = 3; // class CHAOS
        assert!(matches!(
            parse_query(&both, Transport::Udp),
            Parsed::Refuse(_, ResponseCode::BADVERS)
        ));
    }

    #[test]
    fn unknown_types_any_and_the_root_are_accepted() {
        assert_eq!(question(&query(1, "example.com", 65434)).qtype(), 65434);
        assert_eq!(question(&query(1, "example.com", 255)).qtype(), 255);
        let root = question(&unhex("1234010000010000000000000000020001"));
        assert_eq!((root.name(), root.labels(), root.qtype()), ("", 0, 2));
    }

    // Review Focus 2: the first label is the 3 bytes `a.b`.
    #[test]
    fn a_label_with_a_dot_inside_is_not_a_listed_name() {
        let q = question(&unhex(
            "12340100000100000000000003612e62076578616d706c6503636f6d0000010001",
        ));
        assert_eq!(
            (q.name(), q.labels(), q.block_key()),
            (r"a\.b.example.com", 3, None)
        );
        assert_ne!(q.name(), question(&query(1, "a.b.example.com", 1)).name());
    }

    #[test]
    fn a_wildcard_label_still_counts_as_a_label() {
        let q = question(&query(1, "*.example.com", 1));
        assert_eq!(
            (q.name(), q.labels(), q.block_key()),
            ("*.example.com", 3, None)
        );
    }

    // hickory writes a leading hyphen as `\-`; a list holds the name bare, and it must still match.
    #[test]
    fn a_label_with_a_leading_hyphen_is_a_listed_name() {
        let q = question(&query(1, "-ads.Example.com", 1));
        assert_eq!(
            (q.name(), q.block_key()),
            ("-ads.example.com", Some("-ads.example.com"))
        );
        let mut builder = BlockSetBuilder::new();
        builder.deny("-ads.example.com").unwrap();
        assert!(builder.build().is_blocked(q.block_key().unwrap()));
    }

    #[test]
    fn names_that_differ_on_the_wire_differ_as_text() {
        let cases: [(&[&[u8]], &str); 12] = [
            (&[b"a", b"b"], "a.b"),
            (&[b"a.b"], r"a\.b"),
            (&[b"a\\", b"b"], r"a\\.b"),
            (&[b"a\\.b"], r"a\\\.b"),
            (&[b"a"], "a"),
            (&[b"a."], r"a\."),
            (&[b"\x01"], r"\001"),
            (&[b"\\001"], r"\\001"),
            (&[b"-a"], "-a"),
            (&[b"\\-a"], r"\\-a"),
            (&[b"-a", b"b.c"], r"\-a.b\.c"),
            (&[b"a b", b"\xc3\xa9"], r"a\040b.\303\251"),
        ];
        let mut seen = HashMap::new();
        for (labels, text) in cases {
            let q = question(&with_labels(labels));
            assert_eq!(q.name(), text, "{labels:?}");
            assert_eq!(q.labels(), labels.len(), "{labels:?}");
            assert_eq!(seen.insert(text, labels), None, "{text} twice");
        }
    }

    #[test]
    fn parse_query_never_panics() {
        let fixtures = [Q_PLAIN, Q_MIXED, Q_DIG, Q_AAAA_EDNS, Q_DO].map(unhex);
        let mut rng = Rng::new(5);
        // Every name seen, with the lower-cased labels it stands for.
        let mut names: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
        let (mut accepted, mut refused, mut header_only, mut dropped) = (0, 0, 0, 0);
        for i in 0..200_000 {
            let packet = if i % 4 == 0 {
                rng.bytes(64)
            } else {
                rng.mutate(&fixtures[i % fixtures.len()])
            };
            let q = match parse_query(&packet, Transport::Udp) {
                Parsed::Ok(q) => {
                    accepted += 1;
                    q
                }
                Parsed::Refuse(q, _) => {
                    refused += 1;
                    q
                }
                Parsed::HeaderOnly(reply) => {
                    header_only += 1;
                    assert_eq!(reply[..2], packet[..2]);
                    continue;
                }
                Parsed::Drop => {
                    dropped += 1;
                    continue;
                }
            };
            if let Some(key) = q.block_key() {
                assert_eq!(key, q.name());
                assert!(
                    key.bytes()
                        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.')),
                    "{key:?}"
                );
            }
            // The upstream query is one a resolver can read: the same question, compared without
            // regard to the case of the name's letters, and nothing else.
            let upstream = decode(&q.upstream_query(1));
            assert_eq!(upstream.queries, [q.query().clone()]);
            assert!(upstream.answers.is_empty() && upstream.additionals.is_empty());
            // One name never stands for two different sets of labels.
            let wire: Vec<Vec<u8>> = q
                .query()
                .name
                .iter()
                .map(|label| label.to_ascii_lowercase())
                .collect();
            assert_eq!(q.labels(), wire.len());
            let known = names
                .entry(q.name().to_owned())
                .or_insert_with(|| wire.clone());
            assert_eq!(*known, wire, "{:?}", q.name());
        }
        // Guards against a generator that only ever reaches one branch.
        assert!(
            accepted > 1_000 && refused > 1_000 && header_only > 1_000 && dropped > 1_000,
            "{accepted} accepted, {refused} refused, {header_only} header-only, {dropped} dropped"
        );
        assert!(names.len() > 1_000, "{} distinct names", names.len());
    }
}
