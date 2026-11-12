//! Test only: a seeded generator of arbitrary bytes, hex decoding, and packet fixtures.

use hickory_proto::op::Message;

use crate::Transport;
use crate::query::{Parsed, Question, parse_query};

// The queries are hand-assembled to RFC 1035 section 4.1 and RFC 6891 section 6.1.2.

/// `example.com` A, RD set, no OPT. Sent to a public resolver on 2026-11-10, which answered it.
pub(crate) const Q_PLAIN: &str = "123401000001000000000000076578616d706c6503636f6d0000010001";

/// `Q_PLAIN` with the name spelled `EXample.coM`.
pub(crate) const Q_MIXED: &str = "123401000001000000000000074558616d706c6503636f4d0000010001";

/// The layout `dig` sends by default: the AD flag, and an OPT with payload 1232 and one 8-byte
/// COOKIE option.
pub(crate) const Q_DIG: &str = "abcd01200001000000000001076578616d706c6503636f6d000001000100002904d000000000000c000a00080102030405060708";

/// `example.com` AAAA with an OPT of payload 1232. Sent to a public resolver on 2026-11-10,
/// which answered it.
pub(crate) const Q_AAAA_EDNS: &str =
    "345601000001000000000001076578616d706c6503636f6d00001c000100002904d0000000000000";

/// `example.com` A with the DO bit set. Sent to a public resolver on 2026-11-10, which answered it.
pub(crate) const Q_DO: &str =
    "678901000001000000000001076578616d706c6503636f6d000001000100002904d0000080000000";

/// The answer a public resolver gave to `Q_PLAIN` over UDP on 2026-11-10: two A records, TTL 215.
pub(crate) const R_A: &str = "123481800001000200000000076578616d706c6503636f6d0000010001c00c00010001000000d700046814179ac00c00010001000000d70004ac4293f3";

/// `does-not-exist.example.com` A with an OPT of payload 1232. Sent to a public resolver on
/// 2026-11-10, which answered it.
pub(crate) const Q_NODATA: &str = "2345010000010000000000010e646f65732d6e6f742d6578697374076578616d706c6503636f6d000001000100002904d0000000000000";

/// The answer a public resolver gave to `Q_NODATA` over UDP on 2026-11-10: NOERROR with no
/// answer, one SOA with TTL 1800 and MINIMUM 1800, and an OPT.
pub(crate) const R_NODATA: &str = "2345818000010000000100010e646f65732d6e6f742d6578697374076578616d706c6503636f6d0000010001c01b0006000100000708003207656c6c696f7474026e730a636c6f7564666c617265c02303646e73c043901fd090000027100000096000093a800000070800002904d0000000000000";

/// The answer a public resolver gave to `query(0x5678, "host.invalid", 1)` over UDP on
/// 2026-11-10: NXDOMAIN with AA set, one SOA with TTL 10800 and MINIMUM 10800.
pub(crate) const R_NXDOMAIN: &str = "56788583000100000001000004686f737407696e76616c69640000010001c0110006000100002a300028096c6f63616c686f737400066e6f626f6479c0110000000100000e10000004b000093a8000002a30";

/// A xorshift64 generator: the same seed gives the same sequence.
pub(crate) struct Rng(u64);

impl Rng {
    /// Starts a sequence. Seed 0 would leave xorshift stuck at 0, so it is replaced.
    pub(crate) fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    /// The next 64 bits; never 0.
    pub(crate) fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// A number in `0..n`; `n` must be above 0.
    pub(crate) fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    /// Random bytes of a random length in `0..=max_len`.
    pub(crate) fn bytes(&mut self, max_len: usize) -> Vec<u8> {
        let len = self.below(max_len + 1);
        (0..len).map(|_| self.byte()).collect()
    }

    /// A copy of `base` after one to three changes: overwrite a byte, flip a bit, truncate,
    /// insert a byte, or append up to 8 bytes.
    pub(crate) fn mutate(&mut self, base: &[u8]) -> Vec<u8> {
        let mut out = base.to_vec();
        for _ in 0..1 + self.below(3) {
            match self.below(5) {
                // The first three need a byte to act on; on an empty buffer they do nothing.
                0..=2 if out.is_empty() => {}
                0 => {
                    let at = self.below(out.len());
                    out[at] = self.byte();
                }
                1 => {
                    let at = self.below(out.len());
                    out[at] ^= 1 << self.below(8);
                }
                2 => {
                    let len = self.below(out.len());
                    out.truncate(len);
                }
                3 => {
                    let at = self.below(out.len() + 1);
                    let byte = self.byte();
                    out.insert(at, byte);
                }
                _ => {
                    for _ in 0..1 + self.below(8) {
                        let byte = self.byte();
                        out.push(byte);
                    }
                }
            }
        }
        out
    }

    /// One random byte.
    fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }
}

/// Decodes hex digits to bytes, ignoring whitespace. Panics on anything else.
pub(crate) fn unhex(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_digit(16).expect("a hex digit") as u8)
        .collect();
    assert!(
        digits.len().is_multiple_of(2),
        "an odd number of hex digits"
    );
    let (pairs, _) = digits.as_chunks::<2>();
    pairs.iter().map(|[high, low]| high << 4 | low).collect()
}

/// A query assembled by hand: flags `0x0100`, one question for `name` (labels split at each dot,
/// `""` for the root), class IN, no OPT.
pub(crate) fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut packet = id.to_be_bytes().to_vec();
    packet.extend([0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.').filter(|label| !label.is_empty()) {
        packet.push(u8::try_from(label.len()).expect("a label under 256 bytes"));
        packet.extend(label.bytes());
    }
    packet.push(0);
    packet.extend(qtype.to_be_bytes());
    packet.extend([0, 1]);
    packet
}

/// The question in `packet`, taken as arriving over UDP. Panics unless it is accepted.
pub(crate) fn question(packet: &[u8]) -> Question {
    accepted(packet, Transport::Udp)
}

/// The question in `packet`, taken as arriving over TCP. Panics unless it is accepted.
pub(crate) fn question_tcp(packet: &[u8]) -> Question {
    accepted(packet, Transport::Tcp)
}

fn accepted(packet: &[u8], transport: Transport) -> Question {
    match parse_query(packet, transport) {
        Parsed::Ok(question) => question,
        other => panic!("not an accepted query: {other:?}"),
    }
}

/// Decodes a whole message. Panics if hickory cannot read it.
pub(crate) fn decode(bytes: &[u8]) -> Message {
    Message::from_vec(bytes).unwrap()
}

mod tests {
    use super::*;

    #[test]
    fn the_same_seed_gives_the_same_sequence() {
        let (mut a, mut b, mut c) = (Rng::new(7), Rng::new(7), Rng::new(8));
        let seq = |r: &mut Rng| (0..16).map(|_| r.next()).collect::<Vec<_>>();
        let first = seq(&mut a);
        assert_eq!(first, seq(&mut b));
        assert_ne!(first, seq(&mut c));
    }

    #[test]
    fn a_zero_seed_is_not_stuck() {
        let mut rng = Rng::new(0);
        let (a, b) = (rng.next(), rng.next());
        assert!(a != 0 && b != 0 && a != b);
    }

    #[test]
    fn lengths_and_ranges_hold() {
        let mut rng = Rng::new(3);
        let mut longest = 0;
        for _ in 0..10_000 {
            assert!(rng.below(5) < 5);
            assert_eq!(rng.below(1), 0);
            assert!(rng.bytes(0).is_empty());
            longest = longest.max(rng.bytes(9).len());
            // Every mutation must cope with an empty base; at most three appends of 8 bytes.
            assert!(rng.mutate(b"").len() <= 24);
            assert!(rng.mutate(b"abcd").len() <= 28);
        }
        assert_eq!(longest, 9);
    }

    #[test]
    fn mutate_changes_the_base_most_of_the_time() {
        let mut rng = Rng::new(4);
        let base = b"Sub.Example-1.COM.";
        let changed = (0..1_000).filter(|_| rng.mutate(base) != base).count();
        assert!(changed > 900, "{changed} of 1000 changed");
    }
}
