//! The watchdog's analysis side: the alert store, the behaviour detectors and the device watch.
//!
//! Everything here lives in RAM; nothing is written to the card.

pub mod analysis;
pub mod behaviour;
pub mod devices;
pub mod devwatch;
pub mod frames;
pub mod names;
pub mod rebind;
pub mod store;

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};

use crate::alerts::AlertSink;
use rebind::RebindPolicy;

/// How many events the feed holds before it drops the next ones.
pub const FEED_CAPACITY: usize = 1024;

/// The length of a DNS header.
const HEADER_LEN: usize = 12;
/// The most bytes that a name has on the wire, the zero of the root included.
const NAME_WIRE_MAX: usize = 255;
/// The longest label, in bytes: a length byte above it is a compression pointer or a type of
/// label that no name of a question has.
const LABEL_MAX: usize = 63;
/// The top two bits of a length byte that mark a compression pointer.
const POINTER_BITS: u8 = 0xC0;

/// One answer that the listener sent, as the analysis sees it: who asked, what, and what the
/// answer said. It is a copy in a fixed array, so that making one needs no allocation, and it
/// carries no time: the analysis stamps it when it takes it from the feed.
#[derive(Clone)]
pub struct Event {
    /// The client that asked.
    pub client: IpAddr,
    /// The type of the record asked for.
    pub qtype: u16,
    /// The response code: the low four bits of the header's flags.
    pub rcode: u8,
    /// The TTL of the first record of the answer, and 0 for an answer without one.
    pub ttl: u32,
    /// How many bytes of `name` are the question's name.
    name_len: u8,
    /// The question's name in wire form, the zero of the root included, and zeros after it.
    name: [u8; NAME_WIRE_MAX],
}

impl Event {
    /// The event for `reply`, which was sent to `client`; `None` if `reply` has no single
    /// question that is plain labels and ends within 255 bytes, which is no reply of ours.
    ///
    /// The name is read at the start of the question, where no compression pointer can be. The
    /// TTL is that of the first record of the answer section, whose owner name is skipped, whether
    /// it is a pointer, as it mostly is, or labels. Nothing here allocates.
    pub fn from_reply(client: IpAddr, reply: &[u8]) -> Option<Event> {
        let header = reply.get(..HEADER_LEN)?;
        if be16(header, 4)? != 1 {
            return None;
        }
        let rcode = header[3] & 0x0f;
        let answers = be16(header, 6)?;
        let mut name = [0u8; NAME_WIRE_MAX];
        let (mut at, mut len) = (HEADER_LEN, 0);
        loop {
            let label = usize::from(*reply.get(at)?);
            if label > LABEL_MAX {
                return None;
            }
            // The length byte and the label, which is the root when it is of 0 bytes.
            let part = reply.get(at..=at + label)?;
            name.get_mut(len..len + part.len())?.copy_from_slice(part);
            len += part.len();
            at += part.len();
            if label == 0 {
                break;
            }
        }
        let qtype = be16(reply, at)?;
        // The type and the class end the question, which must be all there.
        at += 4;
        if reply.len() < at {
            return None;
        }
        let ttl = if answers >= 1 {
            first_ttl(reply, at).unwrap_or(0)
        } else {
            0
        };
        Some(Event {
            client,
            qtype,
            rcode,
            ttl,
            name_len: u8::try_from(len).ok()?,
            name,
        })
    }

    /// The question's name in wire form: each label led by its length, and the zero of the root.
    /// [`names::decode`] makes text of it.
    pub fn name_wire(&self) -> &[u8] {
        let len = usize::from(self.name_len);
        self.name.get(..len).unwrap_or(&[])
    }

    /// An event for `name`, as text, for the tests of whoever reads events.
    #[cfg(test)]
    pub(crate) fn for_test(client: IpAddr, name: &str, qtype: u16, rcode: u8, ttl: u32) -> Event {
        Event::for_test_wire(client, &wire_of(name), qtype, rcode, ttl)
    }

    /// An event for the name `wire`, as it stands on the wire: for names that no host has, with
    /// bytes that text cannot make, and for shapes that no question has.
    #[cfg(test)]
    pub(crate) fn for_test_wire(
        client: IpAddr,
        wire: &[u8],
        qtype: u16,
        rcode: u8,
        ttl: u32,
    ) -> Event {
        let mut bytes = [0u8; NAME_WIRE_MAX];
        bytes[..wire.len()].copy_from_slice(wire);
        Event {
            client,
            qtype,
            rcode,
            ttl,
            name_len: u8::try_from(wire.len()).expect("a name of at most 255 bytes"),
            name: bytes,
        }
    }
}

/// The wire form of `name`, as text with dots: each label led by its length, and the root. For
/// the tests.
#[cfg(test)]
pub(crate) fn wire_of(name: &str) -> Vec<u8> {
    let mut wire = Vec::new();
    for label in name.split('.').filter(|label| !label.is_empty()) {
        wire.push(u8::try_from(label.len()).expect("a label of at most 255 bytes"));
        wire.extend_from_slice(label.as_bytes());
    }
    wire.push(0);
    wire
}

/// An event shows what kind of answer it was, and never the name or the client: an event that
/// ends up in a log line must not tell who asked for what.
impl fmt::Debug for Event {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("Event")
            .field("qtype", &self.qtype)
            .field("rcode", &self.rcode)
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

/// The big-endian number of two bytes of `bytes` at `at`.
fn be16(bytes: &[u8], at: usize) -> Option<u16> {
    let pair = <[u8; 2]>::try_from(bytes.get(at..at + 2)?).ok()?;
    Some(u16::from_be_bytes(pair))
}

/// The big-endian number of four bytes of `bytes` at `at`.
fn be32(bytes: &[u8], at: usize) -> Option<u32> {
    let quad = <[u8; 4]>::try_from(bytes.get(at..at + 4)?).ok()?;
    Some(u32::from_be_bytes(quad))
}

/// The TTL of the record of `reply` that starts at `at`: past its owner name, which is a pointer
/// of two bytes or labels, and its type and class. `None` if the record is not all there.
fn first_ttl(reply: &[u8], mut at: usize) -> Option<u32> {
    loop {
        let byte = *reply.get(at)?;
        match byte & POINTER_BITS {
            POINTER_BITS => {
                at += 2;
                break;
            }
            0 => {
                at += 1 + usize::from(byte);
                if byte == 0 {
                    break;
                }
            }
            _ => return None,
        }
    }
    be32(reply, at + 4)
}

/// The sending end of the feed: the listener offers it each answer, and the analysis takes them
/// from the receiving end.
pub struct Feed {
    tx: SyncSender<Event>,
    /// How many answers were not taken in: the channel was full, or nobody receives any more.
    dropped: Arc<AtomicU64>,
}

/// A feed of [`FEED_CAPACITY`] events, and the end that the analysis receives from.
pub fn feed() -> (Feed, Receiver<Event>) {
    feed_with(FEED_CAPACITY)
}

/// A feed that holds `capacity` events.
fn feed_with(capacity: usize) -> (Feed, Receiver<Event>) {
    let (tx, rx) = sync_channel(capacity);
    let dropped = Arc::new(AtomicU64::new(0));
    (Feed { tx, dropped }, rx)
}

impl Feed {
    /// Offers the answer `reply`, which went to `client`. It never waits: with the channel full,
    /// or its receiver gone, the answer is counted as dropped and that is all. A reply that is no
    /// event, see [`Event::from_reply`], is not offered and not counted.
    pub fn offer(&self, client: IpAddr, reply: &[u8]) {
        let Some(event) = Event::from_reply(client, reply) else {
            return;
        };
        if self.tx.try_send(event).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// How many answers were dropped so far.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// What the watchdog hangs on the answer path: [`Dns::set_watch`] takes it.
///
/// [`Dns::set_watch`]: crate::dns::Dns::set_watch
pub struct Watch {
    /// Where the answers that the listener sends are offered.
    pub feed: Feed,
    /// Which names have their answers screened for private addresses.
    pub rebind: RebindPolicy,
    /// Where the alerts that the answer path raises go: a rebinding answer that was blocked.
    pub sink: Arc<dyn AlertSink>,
}

#[cfg(test)]
impl Watch {
    /// A watch of `feed` that screens every public name and raises its alerts into `sink`.
    pub(crate) fn for_test(feed: Feed, sink: Arc<dyn AlertSink>) -> Watch {
        Watch {
            feed,
            rebind: RebindPolicy::new(Vec::new()),
            sink,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;

    /// A client of the documentation range.
    const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));

    /// A reply for `name` and `qtype`, with the response code `rcode` and one answer of TTL
    /// `ttl` for each of `ttls`; the owner of an answer is a pointer to the question.
    fn reply(name: &str, qtype: u16, rcode: u8, ttls: &[u32]) -> Vec<u8> {
        let mut out = vec![0x12, 0x34, 0x81, 0x80 | rcode, 0, 1];
        out.extend_from_slice(&u16::try_from(ttls.len()).unwrap().to_be_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&wire_of(name));
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&[0, 1]);
        for ttl in ttls {
            out.extend_from_slice(&[0xC0, 12]);
            out.extend_from_slice(&qtype.to_be_bytes());
            out.extend_from_slice(&[0, 1]);
            out.extend_from_slice(&ttl.to_be_bytes());
            out.extend_from_slice(&[0, 4, 192, 0, 2, 1]);
        }
        out
    }

    /// The name of `event` as text.
    fn name(event: &Event) -> String {
        let mut buf = [0u8; names::NAME_TEXT_MAX];
        names::decode(event.name_wire(), &mut buf)
            .unwrap()
            .to_owned()
    }

    #[test]
    fn an_event_has_the_client_the_type_the_code_the_name_and_the_first_ttl() {
        let bytes = reply("Www.Example.org", 28, 0, &[300, 60]);
        let event = Event::from_reply(CLIENT, &bytes).unwrap();
        assert_eq!(
            (event.client, event.qtype, event.rcode, event.ttl),
            (CLIENT, 28, 0, 300)
        );
        assert_eq!(name(&event), "www.example.org");
        assert_eq!(event.name_wire(), &wire_of("Www.Example.org")[..]);
        // The clone is the same.
        assert_eq!(event.clone().name_wire(), event.name_wire());
    }

    #[test]
    fn the_response_code_is_the_low_four_bits_and_an_answer_less_reply_has_ttl_0() {
        let mut bytes = reply("printer", 1, 3, &[]);
        let event = Event::from_reply(CLIENT, &bytes).unwrap();
        assert_eq!(
            (event.rcode, event.ttl, name(&event)),
            (3, 0, "printer".to_owned())
        );
        // The flags above the response code are not part of it.
        bytes[3] = 0xF5;
        assert_eq!(Event::from_reply(CLIENT, &bytes).unwrap().rcode, 5);
    }

    #[test]
    fn the_ttl_is_that_of_the_first_answer_whose_owner_is_a_pointer_or_labels() {
        // An owner that is spelled out in labels.
        let mut bytes = reply("example.org", 1, 0, &[]);
        bytes[7] = 1;
        bytes.extend_from_slice(&wire_of("cdn.example.org"));
        bytes.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0x0E, 0x10, 0, 4, 192, 0, 2, 1]);
        assert_eq!(Event::from_reply(CLIENT, &bytes).unwrap().ttl, 3600);
        // A label then a pointer, as a name that is cut and compressed has it.
        let mut bytes = reply("example.org", 1, 0, &[]);
        bytes[7] = 1;
        bytes.extend_from_slice(&[3, b'c', b'd', b'n', 0xC0, 12]);
        bytes.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 42, 0, 4, 192, 0, 2, 1]);
        assert_eq!(Event::from_reply(CLIENT, &bytes).unwrap().ttl, 42);
        // An answer that is counted and not there, or cut, leaves the event with ttl 0.
        let mut bytes = reply("example.org", 1, 0, &[]);
        bytes[7] = 1;
        assert_eq!(Event::from_reply(CLIENT, &bytes).unwrap().ttl, 0);
        bytes.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0]);
        assert_eq!(Event::from_reply(CLIENT, &bytes).unwrap().ttl, 0);
    }

    #[test]
    fn a_reply_that_is_not_one_plain_question_is_no_event() {
        let good = reply("example.org", 1, 0, &[60]);
        assert!(Event::from_reply(CLIENT, &good).is_some());
        // No question, and two.
        for count in [0, 2] {
            let mut bytes = good.clone();
            bytes[5] = count;
            assert!(Event::from_reply(CLIENT, &bytes).is_none(), "{count}");
        }
        // A pointer for the name, and a label type that is neither.
        for first in [0xC0, 0x40, 0x80] {
            let mut bytes = good.clone();
            bytes[12] = first;
            assert!(Event::from_reply(CLIENT, &bytes).is_none(), "{first}");
        }
        // Cut anywhere before the end of the question: no event; after it, an event.
        let question_end = 12 + wire_of("example.org").len() + 4;
        for cut in 0..question_end {
            assert!(Event::from_reply(CLIENT, &good[..cut]).is_none(), "{cut}");
        }
        assert!(Event::from_reply(CLIENT, &good[..question_end]).is_some());
        assert!(Event::from_reply(CLIENT, &[]).is_none());
    }

    #[test]
    fn a_name_of_255_bytes_is_an_event_and_one_of_257_is_not() {
        // Three labels of 63 and one of 61: 64 * 3 + 62 + 1 = 255 bytes of wire form.
        let full = format!("{0}.{0}.{0}.{1}", "a".repeat(63), "b".repeat(61));
        assert_eq!(wire_of(&full).len(), 255);
        let event = Event::from_reply(CLIENT, &reply(&full, 1, 0, &[1])).unwrap();
        assert_eq!(event.name_wire().len(), 255);
        assert_eq!(event.ttl, 1);
        // One byte more in the last label is 256 bytes, and four labels of 63 are 257.
        let long = format!("{0}.{0}.{0}.{1}", "a".repeat(63), "b".repeat(62));
        assert!(Event::from_reply(CLIENT, &reply(&long, 1, 0, &[])).is_none());
        let longer = vec!["a".repeat(63); 4].join(".");
        assert!(Event::from_reply(CLIENT, &reply(&longer, 1, 0, &[])).is_none());
    }

    #[test]
    fn an_event_shows_neither_the_name_nor_the_client_when_it_is_printed() {
        let event = Event::for_test(CLIENT, "secret.example.org", 1, 0, 60);
        let shown = format!("{event:?}");
        assert!(
            !shown.contains("secret") && !shown.contains("192.0.2"),
            "{shown}"
        );
    }

    #[test]
    fn the_feed_gives_events_in_order_and_counts_those_it_cannot_hold() {
        let (feed, rx) = feed_with(2);
        for (n, host) in ["a", "b", "c", "d"].into_iter().enumerate() {
            feed.offer(
                CLIENT,
                &reply(&format!("{host}.example.org"), 1, 0, &[n as u32]),
            );
        }
        assert_eq!(feed.dropped(), 2);
        assert_eq!(name(&rx.try_recv().unwrap()), "a.example.org");
        assert_eq!(name(&rx.try_recv().unwrap()), "b.example.org");
        assert!(rx.try_recv().is_err());
        // With room again, an event is held.
        feed.offer(CLIENT, &reply("e.example.org", 1, 0, &[]));
        assert_eq!(
            (feed.dropped(), name(&rx.try_recv().unwrap())),
            (2, "e.example.org".to_owned())
        );
    }

    #[test]
    fn a_feed_whose_receiver_is_gone_counts_and_does_not_fail() {
        let (feed, rx) = feed_with(8);
        drop(rx);
        feed.offer(CLIENT, &reply("example.org", 1, 0, &[1]));
        feed.offer(CLIENT, &reply("example.org", 1, 0, &[1]));
        assert_eq!(feed.dropped(), 2);
    }

    #[test]
    fn a_reply_that_is_no_event_is_not_offered_and_not_counted() {
        let (feed, rx) = feed_with(1);
        feed.offer(CLIENT, &[1, 2, 3]);
        feed.offer(CLIENT, &[]);
        assert_eq!(feed.dropped(), 0);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn the_real_feed_holds_one_thousand_and_twenty_four_events() {
        let (feed, rx) = feed();
        let bytes = reply("example.org", 1, 0, &[1]);
        for _ in 0..FEED_CAPACITY + 5 {
            feed.offer(CLIENT, &bytes);
        }
        assert_eq!(feed.dropped(), 5);
        assert_eq!(rx.try_iter().count(), FEED_CAPACITY);
    }
}
