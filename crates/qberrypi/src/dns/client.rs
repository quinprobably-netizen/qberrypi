//! The packets of a query to an upstream, built and read with hickory.
//!
//! Nothing here logs: a name that is asked for stays out of every log line.

use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};

/// The bytes of a query for one question of class IN, with recursion desired and no OPT record.
///
/// An error for a name that cannot be encoded, such as one with a label over 63 bytes; it does
/// not hold the name.
pub fn query(id: u16, name: &str, qtype: u16) -> io::Result<Vec<u8>> {
    let cannot_encode = || io::Error::new(ErrorKind::InvalidInput, "name cannot be encoded");
    let name = Name::from_ascii(name).map_err(|_| cannot_encode())?;
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name, RecordType::from(qtype)));
    message.to_vec().map_err(|_| cannot_encode())
}

/// What an upstream's response says, in the parts that matter to whoever asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// The response code; a code above 255 shows as 255.
    pub rcode: u8,
    /// The A and AAAA records of the answer section, in order.
    pub addrs: Vec<IpAddr>,
    /// The lowest TTL of the answer section; `None` for an empty one.
    pub min_ttl: Option<u32>,
    /// Whether the truncation flag is set.
    pub truncated: bool,
}

/// Reads `reply` if it is a response carrying `id`; anything else, including bytes that are
/// no message, is `None`.
pub fn read_answer(reply: &[u8], id: u16) -> Option<Answer> {
    let message = Message::from_vec(reply).ok()?;
    let header = &message.metadata;
    if header.message_type != MessageType::Response || header.id != id {
        return None;
    }
    let addrs = message
        .answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            RData::AAAA(aaaa) => Some(IpAddr::V6(aaaa.0)),
            _ => None,
        })
        .collect();
    Some(Answer {
        rcode: u8::try_from(u16::from(header.response_code)).unwrap_or(u8::MAX),
        addrs,
        min_ttl: message.answers.iter().map(|record| record.ttl).min(),
        truncated: header.truncation,
    })
}

impl Answer {
    /// The IPv4 addresses among [`Answer::addrs`], in order.
    pub fn v4(&self) -> Vec<Ipv4Addr> {
        self.addrs
            .iter()
            .filter_map(|addr| match addr {
                IpAddr::V4(v4) => Some(*v4),
                IpAddr::V6(_) => None,
            })
            .collect()
    }

    /// The response code by name, and the first address if there is one: `NOERROR 0.0.0.0`,
    /// `NXDOMAIN`, `SERVFAIL`, or `RCODE n` for any other code.
    pub fn summary(&self) -> String {
        let code = match self.rcode {
            0 => "NOERROR".to_owned(),
            2 => "SERVFAIL".to_owned(),
            3 => "NXDOMAIN".to_owned(),
            other => format!("RCODE {other}"),
        };
        match self.addrs.first() {
            Some(addr) => format!("{code} {addr}"),
            None => code,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::testutil::{hex, unhex};

    use std::net::IpAddr;

    #[test]
    fn a_query_is_the_plain_packet() {
        assert_eq!(
            hex(&query(0x1234, "example.com", 1).unwrap()),
            "123401000001000000000000076578616d706c6503636f6d0000010001"
        );
        assert!(query(1, &"a".repeat(64), 1).is_err());
    }

    #[test]
    fn an_answer_is_read_only_under_its_own_id() {
        // The hand-checked blocked reply of the qb-dns plan's Task 6.
        let blocked = unhex(
            "12348180000100010000000007 4558616d706c65 03 636f4d 00 0001 0001 c00c 0001 0001 00000002 0004 00000000",
        );
        let a = read_answer(&blocked, 0x1234).unwrap();
        assert_eq!(
            a,
            Answer {
                rcode: 0,
                addrs: vec![IpAddr::from([0, 0, 0, 0])],
                min_ttl: Some(2),
                truncated: false
            }
        );
        assert_eq!(a.summary(), "NOERROR 0.0.0.0");
        assert_eq!(read_answer(&blocked, 0x1235), None);
        // A query, not a response.
        assert_eq!(
            read_answer(&query(0x1234, "example.com", 1).unwrap(), 0x1234),
            None
        );
        assert_eq!(
            read_answer(&unhex("123481830000000000000000"), 0x1234)
                .unwrap()
                .summary(),
            "NXDOMAIN"
        );
        assert_eq!(
            read_answer(&unhex("123481820000000000000000"), 0x1234)
                .unwrap()
                .summary(),
            "SERVFAIL"
        );
        assert_eq!(read_answer(&[1, 2, 3], 0x0102), None);
    }
}
