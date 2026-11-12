//! Test only: a fake upstream resolver on `127.0.0.1`, and the small helpers the DNS tests share.

use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener as StdTcpListener,
    TcpStream as StdTcpStream, UdpSocket as StdUdpSocket,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, ThreadId};
use std::time::{Duration, Instant as StdInstant};

use hickory_proto::op::{Edns, Message, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, NULL};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use qb_dns::{Action, BlockSet, BlockSetBuilder, ListClass, Now, Pending, Resolver, Transport};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, HandshakeKind, RootCertStore, ServerConfig,
    ServerConnection, SignatureScheme, StreamOwned, version,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, timeout};

use super::client::{Answer, query, read_answer};
use super::dot::TlsUpstream;
use super::listen::{UDP_TASKS, bind, serve_with};
use super::upstream::{UDP_BUFFER, Upstreams};
use super::{Dns, UtcOffset};
use crate::alerts::{Alert, AlertSink, Severity};
use crate::https::{client_config, provider};
use crate::lists;
use crate::watch::Watch;

/// The time of every call to the resolver.
pub(crate) const NOW: Now = Now {
    mono_secs: 1,
    unix_secs: 1_800_000_000,
};

/// The address in the answer of [`Reply::WrongIdFirst`] and [`Reply::TruncatedThenWrongIdOverTcp`]
/// that carries the wrong ID.
const WRONG_ID_ADDRESS: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 66);

/// How long [`Reply::FloodWrongId`] keeps sending at most: a flood ends with the test that began it.
const FLOOD_FOR: Duration = Duration::from_secs(2);

/// The RDATA of the records that [`Reply::Dnssec`] makes: bytes that no one parses.
const OPAQUE_RDATA: [u8; 12] = *b"opaque rdata";

/// How a fake upstream answers a query. Every answer holds one A record with a TTL of 60,
/// except those of [`Reply::AnswerV6`] and [`Reply::Dnssec`].
#[derive(Clone, Copy, Debug)]
pub(crate) enum Reply {
    /// With the address, at once.
    Answer(Ipv4Addr),
    /// With one AAAA record of the address instead of an A record, at once: for a client that
    /// asks for type AAAA.
    AnswerV6(Ipv6Addr),
    /// Not at all: the query is counted and no byte goes back.
    Silent,
    /// With the address, after a copy under the ID plus one that holds `203.0.113.66` instead,
    /// which whoever takes that copy for the answer shows.
    WrongIdFirst(Ipv4Addr),
    /// Only a copy of the answer under the ID plus one, which holds the address, and never the
    /// answer under the right ID: whoever takes that copy for the answer shows.
    WrongIdOnly(Ipv4Addr),
    /// Over UDP, copies under the ID plus one that hold `203.0.113.66`, one after the other as fast
    /// as the socket takes them, until the fake is dropped or two seconds have passed; never the
    /// answer. Over TCP, nothing.
    FloodWrongId,
    /// With the address, after an answer for `other.example.net` under the right ID.
    OtherQuestionFirst(Ipv4Addr),
    /// Over UDP with the truncation flag and no record; over TCP in full, with the address.
    TruncatedOverUdp(Ipv4Addr),
    /// Over UDP with the truncation flag and no record, as [`Reply::TruncatedOverUdp`]; over TCP
    /// one answer under the ID plus one that holds `203.0.113.66`, which whoever takes it for the
    /// answer shows.
    TruncatedThenWrongIdOverTcp,
    /// With the address, once the time has passed.
    After(Duration, Ipv4Addr),
    /// With one record of the type asked for and one RRSIG record for the same name, TTL 60, and
    /// an OPT record with the DO bit set if the query had the bit. The records carry
    /// [`OPAQUE_RDATA`], as hickory without its DNSSEC features has no types for them.
    Dnssec,
    /// Over UDP, three datagrams in this order: `forged` under the ID plus one; `forged` under the
    /// right ID and question from another socket, which sends to the address the query came from;
    /// and `real`, from the socket that was asked. Over TCP, `real`.
    Hostile { real: Ipv4Addr, forged: Ipv4Addr },
    /// REFUSED with the question and no record, at once, over UDP and over TCP: what a resolver
    /// that will not serve this client says.
    Refused,
    /// Over UDP, the first datagram is counted and not answered; every later one is answered with
    /// the address at once, which is what a lost datagram and a resend look like. Over TCP, as
    /// [`Reply::Answer`].
    DropFirst(Ipv4Addr),
    /// Over UDP, five bytes at once, which are no message, and never an answer. Over TCP, nothing.
    ShortPacket,
    /// Over UDP with the truncation flag and no record, at once; over TCP in full, with the
    /// address, once the time has passed.
    TruncatedOverUdpLateOverTcp(Duration, Ipv4Addr),
    /// Over UDP, the first datagram is counted and not answered; every later one is answered with
    /// the truncation flag and no record at once. Over TCP in full, with the address.
    DropFirstThenTruncated(Ipv4Addr),
    /// With SERVFAIL for `other.example.net` under the right ID, and then with the address: a
    /// failure that is not the answer to this question, before the answer.
    OtherQuestionRefusedFirst(Ipv4Addr),
    /// Only SERVFAIL for `other.example.net` under the right ID, at once, and never the answer.
    OtherQuestionRefusedOnly,
}

/// What a fake upstream has received.
#[derive(Default)]
struct Seen {
    udp: AtomicUsize,
    tcp: AtomicUsize,
    /// Of both kinds: the queries that had an OPT record with the DO bit set.
    with_do: AtomicUsize,
    /// Set when the fake is dropped: a flood that is still going stops.
    stopped: AtomicBool,
}

impl Seen {
    /// Counts one query that came over `via`, and gives its number among those that came over
    /// `via`: 1 for the first.
    fn note(&self, query: &[u8], via: Transport) -> usize {
        let by_transport = match via {
            Transport::Udp => &self.udp,
            Transport::Tcp => &self.tcp,
        };
        let number = by_transport.fetch_add(1, Ordering::SeqCst) + 1;
        if dnssec_ok(query) {
            self.with_do.fetch_add(1, Ordering::SeqCst);
        }
        number
    }
}

/// Whether `query` is a message with an OPT record that has the DO bit set.
fn dnssec_ok(query: &[u8]) -> bool {
    Message::from_vec(query)
        .is_ok_and(|message| message.edns.is_some_and(|edns| edns.flags().dnssec_ok))
}

/// A resolver that listens on UDP and TCP at one `127.0.0.1` port, and counts the queries.
///
/// Its listeners stop when it is dropped.
pub(crate) struct FakeUpstream {
    /// Where to ask it, over UDP or TCP.
    pub(crate) addr: SocketAddr,
    seen: Arc<Seen>,
    tasks: [JoinHandle<()>; 2],
}

impl FakeUpstream {
    /// Starts listening; the port is chosen by the system.
    pub(crate) async fn start(reply: Reply) -> Self {
        let (udp, tcp) = bind_both().await;
        let addr = udp.local_addr().unwrap();
        let seen = Arc::new(Seen::default());
        let tasks = [
            tokio::spawn(serve_udp(udp, reply, seen.clone())),
            tokio::spawn(serve_tcp(tcp, reply, seen.clone())),
        ];
        Self { addr, seen, tasks }
    }

    /// The datagrams received so far.
    pub(crate) fn udp_queries(&self) -> usize {
        self.seen.udp.load(Ordering::SeqCst)
    }

    /// The queries received over TCP so far, whole messages and not connections.
    pub(crate) fn tcp_queries(&self) -> usize {
        self.seen.tcp.load(Ordering::SeqCst)
    }

    /// The queries received so far, over UDP or TCP, with an OPT record that had the DO bit set.
    pub(crate) fn do_queries(&self) -> usize {
        self.seen.with_do.load(Ordering::SeqCst)
    }
}

impl Drop for FakeUpstream {
    fn drop(&mut self) {
        self.seen.stopped.store(true, Ordering::SeqCst);
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// A UDP socket and a TCP listener on one port of `127.0.0.1`.
async fn bind_both() -> (UdpSocket, TcpListener) {
    // The port that UDP gets may be one that another test already listens on over TCP.
    for _ in 0..100 {
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = udp.local_addr().unwrap().port();
        if let Ok(tcp) = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await {
            return (udp, tcp);
        }
    }
    panic!("no port is free for both UDP and TCP");
}

/// The datagrams sent back to each query, whoever's they are.
async fn serve_udp(socket: UdpSocket, reply: Reply, seen: Arc<Seen>) {
    let socket = Arc::new(socket);
    let mut buf = vec![0u8; 4096];
    while let Ok((len, from)) = socket.recv_from(&mut buf).await {
        let number = seen.note(&buf[..len], Transport::Udp);
        let (delay, packets) = match reply {
            // The one datagram that is lost; the ones after it find an upstream that answers.
            Reply::DropFirst(_) | Reply::DropFirstThenTruncated(_) if number == 1 => {
                (Duration::ZERO, Vec::new())
            }
            reply => replies(reply, &buf[..len], Transport::Udp),
        };
        let socket = socket.clone();
        let seen = seen.clone();
        let flood = matches!(reply, Reply::FloodWrongId);
        // Apart, so that a late answer does not hold up the next query.
        tokio::spawn(async move {
            sleep(delay).await;
            let stranger = if packets.iter().any(|out| out.from_stranger) {
                Some(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap())
            } else {
                None
            };
            let end = Instant::now() + FLOOD_FOR;
            loop {
                for out in &packets {
                    let sender = match (&stranger, out.from_stranger) {
                        (Some(stranger), true) => stranger,
                        _ => &socket,
                    };
                    let _ = sender.send_to(&out.bytes, from).await;
                }
                if !flood || seen.stopped.load(Ordering::SeqCst) || Instant::now() >= end {
                    break;
                }
            }
        });
    }
}

/// Takes each connection on its own, so that one that says nothing holds up no other.
async fn serve_tcp(listener: TcpListener, reply: Reply, seen: Arc<Seen>) {
    while let Ok((stream, _)) = listener.accept().await {
        tokio::spawn(serve_connection(stream, reply, seen.clone()));
    }
}

/// Reads one length-prefixed query and answers it, and then keeps the connection open until
/// the client closes it: a reply that never comes is a wait, not an end of the stream.
async fn serve_connection(mut stream: TcpStream, reply: Reply, seen: Arc<Seen>) {
    let Ok(query) = read_frame(&mut stream).await else {
        return;
    };
    seen.note(&query, Transport::Tcp);
    let (delay, packets) = replies(reply, &query, Transport::Tcp);
    sleep(delay).await;
    for out in packets {
        if write_frame(&mut stream, &out.bytes).await.is_err() {
            return;
        }
    }
    let _ = stream.read(&mut [0u8; 1]).await;
}

/// A message that a fake upstream sends.
struct Out {
    bytes: Vec<u8>,
    /// Whether it comes from a socket other than the one that was asked; over UDP only.
    from_stranger: bool,
}

/// How long to wait, and then the messages to send, in order, in answer to `query`.
fn replies(reply: Reply, query: &[u8], via: Transport) -> (Duration, Vec<Out>) {
    let Ok(query) = Message::from_vec(query) else {
        return (Duration::ZERO, Vec::new());
    };
    let (id, question) = (query.metadata.id, &query.queries[0]);
    let encoded = |message: Message| message.to_vec().unwrap();
    let right = |ip| encoded(response(id, question, ip));
    let from_asked = |packets: Vec<Vec<u8>>| {
        packets
            .into_iter()
            .map(|bytes| Out {
                bytes,
                from_stranger: false,
            })
            .collect()
    };
    match reply {
        Reply::Answer(ip) | Reply::DropFirst(ip) => (Duration::ZERO, from_asked(vec![right(ip)])),
        Reply::AnswerV6(ip) => {
            let answer = response_v6(id, question, ip);
            (Duration::ZERO, from_asked(vec![encoded(answer)]))
        }
        Reply::Silent => (Duration::ZERO, Vec::new()),
        Reply::WrongIdFirst(ip) => {
            let wrong = encoded(response(id.wrapping_add(1), question, WRONG_ID_ADDRESS));
            (Duration::ZERO, from_asked(vec![wrong, right(ip)]))
        }
        Reply::FloodWrongId => {
            let wrong = encoded(response(id.wrapping_add(1), question, WRONG_ID_ADDRESS));
            match via {
                Transport::Udp => (Duration::ZERO, from_asked(vec![wrong])),
                Transport::Tcp => (Duration::ZERO, Vec::new()),
            }
        }
        Reply::WrongIdOnly(ip) => {
            let wrong = encoded(response(id.wrapping_add(1), question, ip));
            (Duration::ZERO, from_asked(vec![wrong]))
        }
        Reply::OtherQuestionFirst(ip) => {
            let other = other_question();
            (
                Duration::ZERO,
                from_asked(vec![encoded(response(id, &other, ip)), right(ip)]),
            )
        }
        Reply::OtherQuestionRefusedFirst(ip) => {
            let failed = failure(id, &other_question(), ResponseCode::ServFail);
            (Duration::ZERO, from_asked(vec![encoded(failed), right(ip)]))
        }
        Reply::OtherQuestionRefusedOnly => {
            let failed = failure(id, &other_question(), ResponseCode::ServFail);
            (Duration::ZERO, from_asked(vec![encoded(failed)]))
        }
        Reply::TruncatedOverUdp(ip) | Reply::DropFirstThenTruncated(ip) => match via {
            Transport::Udp => {
                let mut cut = response(id, question, ip);
                cut.answers.clear();
                cut.metadata.truncation = true;
                (Duration::ZERO, from_asked(vec![encoded(cut)]))
            }
            Transport::Tcp => (Duration::ZERO, from_asked(vec![right(ip)])),
        },
        Reply::TruncatedOverUdpLateOverTcp(delay, ip) => match via {
            Transport::Udp => {
                let mut cut = response(id, question, ip);
                cut.answers.clear();
                cut.metadata.truncation = true;
                (Duration::ZERO, from_asked(vec![encoded(cut)]))
            }
            Transport::Tcp => (delay, from_asked(vec![right(ip)])),
        },
        Reply::TruncatedThenWrongIdOverTcp => match via {
            Transport::Udp => {
                let mut cut = response(id, question, WRONG_ID_ADDRESS);
                cut.answers.clear();
                cut.metadata.truncation = true;
                (Duration::ZERO, from_asked(vec![encoded(cut)]))
            }
            Transport::Tcp => {
                let wrong = encoded(response(id.wrapping_add(1), question, WRONG_ID_ADDRESS));
                (Duration::ZERO, from_asked(vec![wrong]))
            }
        },
        Reply::After(delay, ip) => (delay, from_asked(vec![right(ip)])),
        Reply::ShortPacket => match via {
            Transport::Udp => (Duration::ZERO, from_asked(vec![vec![0u8; 5]])),
            Transport::Tcp => (Duration::ZERO, Vec::new()),
        },
        Reply::Refused => {
            let refused = failure(id, question, ResponseCode::Refused);
            (Duration::ZERO, from_asked(vec![encoded(refused)]))
        }
        Reply::Dnssec => (
            Duration::ZERO,
            from_asked(vec![encoded(signed_response(id, question, &query))]),
        ),
        Reply::Hostile { real, forged } => match via {
            Transport::Udp => {
                let wrong_id = encoded(response(id.wrapping_add(1), question, forged));
                let planted = encoded(response(id, question, forged));
                (
                    Duration::ZERO,
                    vec![
                        Out {
                            bytes: wrong_id,
                            from_stranger: false,
                        },
                        Out {
                            bytes: planted,
                            from_stranger: true,
                        },
                        Out {
                            bytes: right(real),
                            from_stranger: false,
                        },
                    ],
                )
            }
            Transport::Tcp => (Duration::ZERO, from_asked(vec![right(real)])),
        },
    }
}

/// The answer of [`Reply::Dnssec`] to `query`, whose first question is `question`.
fn signed_response(id: u16, question: &Query, query: &Message) -> Message {
    let mut message = Message::response(id, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.metadata.recursion_available = true;
    message.add_query(question.clone());
    let record = |code| {
        let rdata = RData::Unknown {
            code,
            rdata: NULL::with(OPAQUE_RDATA.to_vec()),
        };
        Record::from_rdata(question.name.clone(), 60, rdata)
    };
    message.add_answer(record(question.query_type));
    message.add_answer(record(RecordType::RRSIG));
    if query
        .edns
        .as_ref()
        .is_some_and(|edns| edns.flags().dnssec_ok)
    {
        let mut edns = Edns::new();
        edns.set_max_payload(1232).set_dnssec_ok(true);
        message.set_edns(edns);
    }
    message
}

/// The question that the answers of [`Reply::OtherQuestionFirst`] and the like are for.
fn other_question() -> Query {
    Query::query(
        Name::from_ascii("other.example.net").unwrap(),
        RecordType::A,
    )
}

/// A response to `question` under `id` with the response code `code` and no record.
fn failure(id: u16, question: &Query, code: ResponseCode) -> Message {
    let mut message = response(id, question, WRONG_ID_ADDRESS);
    message.answers.clear();
    message.metadata.response_code = code;
    message
}

/// A response to `question` under `id` with one A record, TTL 60.
fn response(id: u16, question: &Query, ip: Ipv4Addr) -> Message {
    let mut message = Message::response(id, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.metadata.recursion_available = true;
    message.add_query(question.clone());
    message.add_answer(Record::from_rdata(
        question.name.clone(),
        60,
        RData::A(A(ip)),
    ));
    message
}

/// The bytes of a response under `id` to an A question for `name`, with one A record for `ip`.
pub(crate) fn response_bytes(id: u16, name: &str, ip: Ipv4Addr) -> Vec<u8> {
    let question = Query::query(Name::from_ascii(name).unwrap(), RecordType::A);
    response(id, &question, ip).to_vec().unwrap()
}

/// The name that the certificate of a [`TlsFakeUpstream`] is for.
pub(crate) const TLS_FAKE_NAME: &str = "dns.example.org";

/// How long a connection of a [`TlsFakeUpstream`] waits at a time for the client to say something
/// before it looks at its own business again (the answers that are due, and the end of the test).
const TLS_FAKE_TICK: Duration = Duration::from_millis(2);

/// How long a [`TlsFakeUpstream`] gives a client to complete its handshake.
const TLS_FAKE_HANDSHAKE: Duration = Duration::from_secs(5);

/// How a [`TlsFakeUpstream`] treats the queries of a connection, besides what its [`Reply`] says.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TlsMode {
    /// Holds the first query of every two until the second one has come, and answers the second
    /// one first: answers that come out of order.
    pub(crate) reverse_pairs: bool,
    /// Closes the connection, with the TLS close notice, once this many queries of it have been
    /// answered; `Some(0)` closes it as soon as the handshake is done. `None`: never.
    pub(crate) close_after: Option<usize>,
    /// Waits this long after accepting a connection before it takes the client's hello: a
    /// handshake that takes that long, whatever the crypto costs.
    pub(crate) handshake_delay: Duration,
    /// Reads the queries for this name (whatever the case, with or without the final dot) and
    /// never answers them, while it answers every other as its [`Reply`] says.
    pub(crate) never_answers: Option<&'static str>,
    /// Writes this many bytes of messages straight after the handshake, as fast as the client takes
    /// them: tiny ones under an ID that no question has, which a client reads and drops. It stops
    /// when the connection fails, as it does when the client has had enough. `0`: none.
    pub(crate) flood: usize,
    /// Closes a connection, with the TLS close notice, once it has read no query for this long
    /// and has no answer to give: a server's idle timeout. `None`: never.
    pub(crate) idle_close: Option<Duration>,
    /// Closes a connection, with the TLS close notice, as soon as it has read its `n`th query,
    /// which it does not answer: a question that met the server's close. `None`: never.
    pub(crate) close_on_query: Option<usize>,
    /// Advertises this idle timeout, in units of 100 ms, with the edns-tcp-keepalive option in
    /// the answers to the queries that carry the option. `None`: never.
    pub(crate) keepalive: Option<u16>,
}

/// What a [`TlsFakeUpstream`] has seen, from all of its connections.
#[derive(Default)]
struct TlsSeen {
    handshakes: AtomicUsize,
    resumed: AtomicUsize,
    queries: AtomicUsize,
    /// Of those, the ones that carried the edns-tcp-keepalive option.
    keepalive_asked: AtomicUsize,
    /// The connections that the fake closed itself, for [`TlsMode::idle_close`] or
    /// [`TlsMode::close_on_query`].
    closed: AtomicUsize,
    /// The bytes of [`TlsMode::flood`] written so far.
    flooded: AtomicUsize,
    /// Set when the fake is dropped: its connections end, and it takes no more.
    stopped: AtomicBool,
}

/// A DNS-over-TLS resolver on a `127.0.0.1` port, served by threads of its own, with a
/// certificate for [`TLS_FAKE_NAME`] that [`tls_for_fake`] gives a client the means to trust. It
/// answers every query it reads on a connection, the way a [`Reply`] says, over TLS 1.3 with the
/// default session cache, so that a client can resume.
///
/// Its threads end, and its connections with them, when it is dropped.
pub(crate) struct TlsFakeUpstream {
    /// Where to connect.
    pub(crate) addr: SocketAddr,
    cert: CertificateDer<'static>,
    seen: Arc<TlsSeen>,
}

impl TlsFakeUpstream {
    /// Starts listening, answering as `reply` says; the port is chosen by the system.
    pub(crate) fn start(reply: Reply) -> Self {
        Self::start_with(reply, TlsMode::default())
    }

    /// [`TlsFakeUpstream::start`], with a [`TlsMode`].
    pub(crate) fn start_with(reply: Reply, mode: TlsMode) -> Self {
        let made = rcgen::generate_simple_self_signed(vec![TLS_FAKE_NAME.to_owned()]).unwrap();
        let cert = made.cert.der().clone();
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(made.signing_key.serialize_der()));
        let config = ServerConfig::builder_with_provider(Arc::new(provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(TlsSeen::default());
        let (config, accepting) = (Arc::new(config), seen.clone());
        thread::spawn(move || accept_tls(&listener, &config, reply, mode, &accepting));
        Self { addr, cert, seen }
    }

    /// The TLS handshakes that were completed, on the server's side.
    pub(crate) fn handshakes(&self) -> usize {
        self.seen.handshakes.load(Ordering::SeqCst)
    }

    /// Of those, the ones that resumed a session.
    pub(crate) fn resumed(&self) -> usize {
        self.seen.resumed.load(Ordering::SeqCst)
    }

    /// The queries that were read, over all the connections.
    pub(crate) fn queries(&self) -> usize {
        self.seen.queries.load(Ordering::SeqCst)
    }

    /// Of [`TlsFakeUpstream::queries`], the ones that carried the edns-tcp-keepalive option.
    pub(crate) fn keepalive_asked(&self) -> usize {
        self.seen.keepalive_asked.load(Ordering::SeqCst)
    }

    /// The connections that the fake closed itself, for being idle or on a query.
    pub(crate) fn closed(&self) -> usize {
        self.seen.closed.load(Ordering::SeqCst)
    }

    /// The bytes of [`TlsMode::flood`] that were written to the clients so far (some of them may
    /// still be on their way: in the kernel's buffers).
    pub(crate) fn flooded(&self) -> usize {
        self.seen.flooded.load(Ordering::SeqCst)
    }
}

impl Drop for TlsFakeUpstream {
    fn drop(&mut self) {
        self.seen.stopped.store(true, Ordering::SeqCst);
    }
}

/// What a client needs to use `fake` under its own name, [`TLS_FAKE_NAME`]: a root store that holds
/// the fake's certificate alone.
pub(crate) fn tls_for_fake(fake: &TlsFakeUpstream) -> TlsUpstream {
    tls_for_fake_as(fake, TLS_FAKE_NAME)
}

/// [`tls_for_fake`] for a client that expects the server to be `name`: one that the fake's
/// certificate is not for never connects.
pub(crate) fn tls_for_fake_as(fake: &TlsFakeUpstream, name: &str) -> TlsUpstream {
    let mut roots = RootCertStore::empty();
    roots.add(fake.cert.clone()).unwrap();
    TlsUpstream {
        name: ServerName::try_from(name.to_owned()).unwrap(),
        config: client_config(roots),
    }
}

/// The thread that a client's certificate check ran on.
#[derive(Clone, Debug)]
pub(crate) struct CheckedOn {
    pub(crate) id: ThreadId,
    pub(crate) name: Option<String>,
    /// The cores that the thread could run on, lowest first.
    pub(crate) cores: Vec<usize>,
}

/// The threads that a client's certificate checks ran on, in order.
pub(crate) type CheckThreads = Arc<Mutex<Vec<CheckedOn>>>;

/// A certificate check that gives the verdict of the real one and notes the thread it ran on.
#[derive(Debug)]
struct Noting {
    real: Arc<WebPkiServerVerifier>,
    threads: CheckThreads,
}

impl ServerCertVerifier for Noting {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let thread = thread::current();
        let mask = rustix::thread::sched_getaffinity(None).unwrap();
        self.threads
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(CheckedOn {
                id: thread.id(),
                name: thread.name().map(str::to_owned),
                cores: (0..rustix::thread::CpuSet::MAX_CPU)
                    .filter(|core| mask.is_set(*core))
                    .collect(),
            });
        self.real
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.real.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.real.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.real.supported_verify_schemes()
    }
}

/// [`tls_for_fake`], and where the client's certificate checks ran: the checks are part of the
/// handshake, so a handshake that runs on a thread shows that thread there. A handshake that
/// resumes an earlier session checks nothing, so only the first handshake of the returned
/// client side is a sure sight.
pub(crate) fn tls_for_fake_noting_threads(fake: &TlsFakeUpstream) -> (TlsUpstream, CheckThreads) {
    let mut roots = RootCertStore::empty();
    roots.add(fake.cert.clone()).unwrap();
    let real = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::new(provider()))
        .build()
        .unwrap();
    let threads = CheckThreads::default();
    let config = ClientConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[&version::TLS13, &version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Noting {
            real,
            threads: threads.clone(),
        }))
        .with_no_client_auth();
    let tls = TlsUpstream {
        name: ServerName::try_from(TLS_FAKE_NAME.to_owned()).unwrap(),
        config: Arc::new(config),
    };
    (tls, threads)
}

/// [`tls_for_fake`] for several fakes at once: a root store that holds all their certificates, so
/// that one client side checks each of them as [`TLS_FAKE_NAME`].
pub(crate) fn tls_for_fakes(fakes: &[&TlsFakeUpstream]) -> TlsUpstream {
    let mut roots = RootCertStore::empty();
    for fake in fakes {
        roots.add(fake.cert.clone()).unwrap();
    }
    TlsUpstream {
        name: ServerName::try_from(TLS_FAKE_NAME.to_owned()).unwrap(),
        config: client_config(roots),
    }
}

/// Takes connections until the fake is dropped, a thread to each.
fn accept_tls(
    listener: &StdTcpListener,
    config: &Arc<ServerConfig>,
    reply: Reply,
    mode: TlsMode,
    seen: &Arc<TlsSeen>,
) {
    listener.set_nonblocking(true).unwrap();
    while !seen.stopped.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((tcp, _)) => {
                let (config, seen) = (config.clone(), seen.clone());
                thread::spawn(move || serve_tls(tcp, config, reply, mode, &seen));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(TLS_FAKE_TICK),
            Err(_) => return,
        }
    }
}

/// One connection of a [`TlsFakeUpstream`]: the handshake, and then the queries it carries, until
/// the client goes away, the mode ends it, or the fake is dropped.
fn serve_tls(
    tcp: StdTcpStream,
    config: Arc<ServerConfig>,
    reply: Reply,
    mode: TlsMode,
    seen: &TlsSeen,
) {
    let Ok(conn) = ServerConnection::new(config) else {
        return;
    };
    // An accepted socket is not blocking on Linux; say so, in case it is somewhere else.
    if tcp.set_nonblocking(false).is_err()
        || tcp.set_nodelay(true).is_err()
        || tcp.set_read_timeout(Some(TLS_FAKE_HANDSHAKE)).is_err()
    {
        return;
    }
    thread::sleep(mode.handshake_delay);
    let mut tls = StreamOwned::new(conn, tcp);
    while tls.conn.is_handshaking() {
        if tls.conn.complete_io(&mut tls.sock).is_err() {
            return;
        }
    }
    seen.handshakes.fetch_add(1, Ordering::SeqCst);
    if tls.conn.handshake_kind() == Some(HandshakeKind::Resumed) {
        seen.resumed.fetch_add(1, Ordering::SeqCst);
    }
    if tls.sock.set_read_timeout(Some(TLS_FAKE_TICK)).is_err() {
        return;
    }
    if mode.close_after == Some(0) {
        tls.conn.send_close_notify();
        let _ = tls.flush();
        return;
    }
    if flood(&mut tls, mode.flood, seen).is_err() {
        return;
    }

    // The answers that are waiting for their time, each as the frames to write; and the first
    // of a pair that is held while `reverse_pairs` waits for the second.
    let mut due: Vec<(StdInstant, Vec<Vec<u8>>)> = Vec::new();
    let mut held: Option<(StdInstant, Vec<Vec<u8>>)> = None;
    let mut plain: Vec<u8> = Vec::new();
    let mut answered = 0usize;
    let mut read_here = 0usize;
    let mut last_query = StdInstant::now();
    let mut buf = [0u8; 4096];
    let close = |tls: &mut StreamOwned<ServerConnection, StdTcpStream>| {
        tls.conn.send_close_notify();
        let _ = tls.flush();
        seen.closed.fetch_add(1, Ordering::SeqCst);
    };
    while !seen.stopped.load(Ordering::SeqCst) {
        let now = StdInstant::now();
        if mode
            .idle_close
            .is_some_and(|idle| due.is_empty() && held.is_none() && now >= last_query + idle)
        {
            close(&mut tls);
            return;
        }
        let (ready, later): (Vec<_>, Vec<_>) = due.into_iter().partition(|(at, _)| *at <= now);
        due = later;
        for (_, packets) in ready {
            for packet in packets {
                let len = u16::try_from(packet.len()).unwrap();
                let frame = [&len.to_be_bytes()[..], &packet].concat();
                if tls.write_all(&frame).and_then(|()| tls.flush()).is_err() {
                    return;
                }
            }
            answered += 1;
            if mode.close_after.is_some_and(|n| answered >= n) {
                tls.conn.send_close_notify();
                let _ = tls.flush();
                return;
            }
        }
        match tls.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => plain.extend_from_slice(&buf[..n]),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return,
        }
        while plain.len() >= 2 {
            let len = usize::from(u16::from_be_bytes([plain[0], plain[1]]));
            if plain.len() < 2 + len {
                break;
            }
            let query: Vec<u8> = plain.drain(..2 + len).skip(2).collect();
            seen.queries.fetch_add(1, Ordering::SeqCst);
            last_query = StdInstant::now();
            read_here += 1;
            let asks_keepalive = carries_keepalive(&query);
            if asks_keepalive {
                seen.keepalive_asked.fetch_add(1, Ordering::SeqCst);
            }
            if mode.close_on_query == Some(read_here) {
                close(&mut tls);
                return;
            }
            if mode
                .never_answers
                .is_some_and(|name| asks_for(&query, name))
            {
                continue;
            }
            let (delay, packets) = replies(reply, &query, Transport::Tcp);
            let advertised = mode.keepalive.filter(|_| asks_keepalive);
            let entry = (
                StdInstant::now() + delay,
                packets
                    .into_iter()
                    .map(|out| match advertised {
                        Some(timeout) => advertise_keepalive(&out.bytes, timeout),
                        None => out.bytes,
                    })
                    .collect::<Vec<_>>(),
            );
            match (mode.reverse_pairs, held.take()) {
                (true, None) => held = Some(entry),
                (true, Some(first)) => {
                    due.push(entry);
                    due.push(first);
                }
                (false, _) => due.push(entry),
            }
        }
    }
}

/// Writes at least `bytes` bytes of messages to `tls` that no one asked for: a header and nothing
/// else, each with its length, under the ID 0xFFFF. Counts what it wrote in `seen`.
fn flood(
    tls: &mut StreamOwned<ServerConnection, StdTcpStream>,
    bytes: usize,
    seen: &TlsSeen,
) -> io::Result<()> {
    let mut frame = [0u8; 14];
    frame[1] = 12;
    frame[2] = 0xFF;
    frame[3] = 0xFF;
    // Four thousand of them to a write: about 56 KB.
    let block = frame.repeat(4000);
    let mut written = 0;
    while written < bytes {
        tls.write_all(&block)?;
        written += block.len();
        seen.flooded.fetch_add(block.len(), Ordering::SeqCst);
    }
    tls.flush()
}

/// Whether `query` carries the edns-tcp-keepalive option (code 11) in its OPT record.
fn carries_keepalive(query: &[u8]) -> bool {
    Message::from_vec(query).is_ok_and(|message| {
        message.edns.is_some_and(|edns| {
            edns.options()
                .as_ref()
                .iter()
                .any(|(code, _)| u16::from(*code) == 11)
        })
    })
}

/// `packet` with the edns-tcp-keepalive option and `timeout` (in units of 100 ms) in its OPT
/// record, which it is given if it has none.
pub(crate) fn advertise_keepalive(packet: &[u8], timeout: u16) -> Vec<u8> {
    let mut message = Message::from_vec(packet).unwrap();
    let mut edns = message.edns.take().unwrap_or_else(|| {
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        edns
    });
    edns.options_mut()
        .insert(hickory_proto::rr::rdata::opt::EdnsOption::Unknown(
            11,
            timeout.to_be_bytes().to_vec(),
        ));
    message.set_edns(edns);
    message.to_vec().unwrap()
}

/// Whether the first question of `query` is for `name`, whatever the case and with or without the
/// final dot.
fn asks_for(query: &[u8], name: &str) -> bool {
    Message::from_vec(query).is_ok_and(|message| {
        message.queries.first().is_some_and(|question| {
            let asked = question.name.to_ascii();
            asked
                .trim_end_matches('.')
                .eq_ignore_ascii_case(name.trim_end_matches('.'))
        })
    })
}

/// A response to `question` under `id` with one AAAA record, TTL 60.
fn response_v6(id: u16, question: &Query, ip: Ipv6Addr) -> Message {
    let mut message = response(id, question, WRONG_ID_ADDRESS);
    message.answers.clear();
    message.add_answer(Record::from_rdata(
        question.name.clone(),
        60,
        RData::AAAA(AAAA(ip)),
    ));
    message
}

/// What a [`RecordingSink`] was given: the kind, the severity as a word, the client and the
/// subject.
pub(crate) type Raised = (&'static str, &'static str, Option<IpAddr>, String);

/// A sink that keeps the alerts that are raised into it, for the tests to read.
#[derive(Default)]
pub(crate) struct RecordingSink {
    alerts: Mutex<Vec<Raised>>,
}

impl RecordingSink {
    /// The alerts raised so far, in order.
    pub(crate) fn raised(&self) -> Vec<Raised> {
        let alerts = self.alerts.lock().unwrap_or_else(PoisonError::into_inner);
        alerts.clone()
    }

    /// The alerts raised so far, once there are `n` of them or 2 s have passed, and the runtime
    /// has had one more turn after that, so that a task that would raise one too many has run:
    /// the alerts of the answer path are raised by tasks that follow the replies.
    pub(crate) async fn raised_after(&self, n: usize) -> Vec<Raised> {
        for _ in 0..200 {
            if self.raised().len() >= n {
                break;
            }
            sleep(ms(10)).await;
        }
        sleep(ms(10)).await;
        self.raised()
    }
}

impl AlertSink for RecordingSink {
    fn raise(&self, alert: Alert) {
        let severity = match alert.severity {
            Severity::Info => "info",
            Severity::Warn => "warn",
            Severity::High => "high",
        };
        let mut alerts = self.alerts.lock().unwrap_or_else(PoisonError::into_inner);
        alerts.push((alert.kind, severity, alert.client, alert.subject));
    }
}

/// A time zone whose offset from UTC, in seconds, is the same all year.
pub(crate) struct FixedOffset(pub(crate) i32);

impl UtcOffset for FixedOffset {
    fn offset_at(&self, _unix_secs: u64) -> i32 {
        self.0
    }
}

/// A block set that has `ads.example.com` on an ads list, and `bad.example.net` with its
/// subdomains on a threat list.
pub(crate) fn threat_set() -> BlockSet {
    let mut builder = BlockSetBuilder::new();
    builder.add_list(b"0.0.0.0 ads.example.com\n");
    builder.add_list_as(b"||bad.example.net^\n", ListClass::Threat);
    builder.build()
}

/// A `Dns` over `upstreams` that denies `ads.example.com` and is in UTC, listening on a
/// `127.0.0.1` port with room for two TCP clients that may idle for 200 ms.
pub(crate) async fn service(upstreams: Upstreams) -> (Arc<Dns>, SocketAddr) {
    let deny = ["ads.example.com".to_owned()];
    let dns = Dns::new(
        lists::from_config(&deny, &[]).build(),
        upstreams,
        Box::new(FixedOffset(0)),
    );
    let addr = listen(dns.clone()).await;
    (dns, addr)
}

/// A `Dns` over `upstreams` that blocks [`threat_set`], raises its alerts on `alerts` (the sink
/// of a watch that screens no names, whose events nobody takes), and is in UTC, listening as
/// [`service`] does.
pub(crate) async fn service_with_alerts(
    upstreams: Upstreams,
    alerts: Arc<dyn AlertSink>,
) -> (Arc<Dns>, SocketAddr) {
    let dns = Dns::new(threat_set(), upstreams, Box::new(FixedOffset(0)));
    let (feed, _events) = crate::watch::feed();
    dns.set_watch(Watch::for_test(feed, alerts));
    let addr = listen(dns.clone()).await;
    (dns, addr)
}

/// [`service`] over one fake upstream that answers as `reply` says, and waits 300 ms for a
/// datagram and 600 ms for a stream.
pub(crate) async fn one(reply: Reply) -> (Arc<Dns>, SocketAddr, FakeUpstream) {
    let up = FakeUpstream::start(reply).await;
    let (dns, addr) = service(Upstreams::with(vec![up.addr], ms(300), ms(600))).await;
    (dns, addr, up)
}

/// A `Dns` with no listener and an upstream that nothing answers, that by its own clock was made
/// `secs` seconds ago.
pub(crate) fn aged(secs: u64) -> Arc<Dns> {
    let mut dns = Dns::new(
        BlockSet::default(),
        Upstreams::with(vec![closed_port()], ms(1), ms(1)),
        Box::new(FixedOffset(0)),
    );
    let ago = Duration::from_secs(secs);
    let started = Arc::get_mut(&mut dns).expect("nothing else holds it");
    started.started = started
        .started
        .checked_sub(ago)
        .expect("the machine has been up that long");
    dns
}

/// Serves `dns` on a `127.0.0.1` port, with room for two TCP clients that may idle for 200 ms,
/// until the test ends.
pub(crate) async fn listen(dns: Arc<Dns>) -> SocketAddr {
    let listeners = bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let addr = listeners.addr();
    tokio::spawn(serve_with(dns, listeners, 2, ms(200), UDP_TASKS));
    addr
}

/// What a client gets for `name` A under ID 9 over UDP within 2 s; `None` if nothing comes.
pub(crate) async fn ask_udp(addr: SocketAddr, name: &str) -> Option<Answer> {
    let packet = query(9, name, 1).unwrap();
    read_answer(&udp_exchange(addr, &packet, ms(2000)).await?, 9)
}

/// What a client gets for `name` AAAA under ID 9 over UDP within 2 s; `None` if nothing comes.
pub(crate) async fn ask_udp_aaaa(addr: SocketAddr, name: &str) -> Option<Answer> {
    let packet = query(9, name, 28).unwrap();
    read_answer(&udp_exchange(addr, &packet, ms(2000)).await?, 9)
}

/// What a client gets for `name` A under ID 9 over TCP within 2 s; `None` if nothing comes.
pub(crate) async fn ask_tcp(addr: SocketAddr, name: &str) -> Option<Answer> {
    let packet = query(9, name, 1).unwrap();
    read_answer(&tcp_exchange(addr, &packet, ms(2000)).await?, 9)
}

/// Sends `packet` from a new socket and returns the first datagram that comes back within
/// `wait`, which must be from `addr`.
pub(crate) async fn udp_exchange(
    addr: SocketAddr,
    packet: &[u8],
    wait: Duration,
) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    socket.send_to(packet, addr).await.unwrap();
    let mut buf = vec![0u8; UDP_BUFFER];
    let (len, from) = timeout(wait, socket.recv_from(&mut buf)).await.ok()?.ok()?;
    assert_eq!(from, addr);
    buf.truncate(len);
    Some(buf)
}

/// Sends `packet` over a new connection and returns the first message that comes back within
/// `wait`.
pub(crate) async fn tcp_exchange(
    addr: SocketAddr,
    packet: &[u8],
    wait: Duration,
) -> Option<Vec<u8>> {
    let exchange = async {
        let mut stream = TcpStream::connect(addr).await.ok()?;
        write_frame(&mut stream, packet).await.ok()?;
        read_frame(&mut stream).await.ok()
    };
    timeout(wait, exchange).await.ok().flatten()
}

/// Writes one message with its 2-byte length.
pub(crate) async fn write_frame(stream: &mut TcpStream, message: &[u8]) -> io::Result<()> {
    let len = u16::try_from(message.len()).unwrap();
    stream
        .write_all(&[&len.to_be_bytes()[..], message].concat())
        .await
}

/// Reads one message that has its 2-byte length.
pub(crate) async fn read_frame(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).await?;
    let mut message = vec![0u8; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut message).await?;
    Ok(message)
}

/// A `127.0.0.1` port on which nothing listens, over UDP or TCP.
pub(crate) fn closed_port() -> SocketAddr {
    loop {
        let udp = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = udp.local_addr().unwrap();
        // The listener is dropped at once, as is the socket when this returns.
        if StdTcpListener::bind(addr).is_ok() {
            return addr;
        }
    }
}

/// The question `name` A, as a client asks it over UDP at [`NOW`]. Panics unless the resolver
/// forwards it.
pub(crate) fn pending(resolver: &mut Resolver, name: &str) -> Pending {
    match resolver.handle_query(&query(7, name, 1).unwrap(), Transport::Udp, NOW) {
        Action::Forward(pending) => pending,
        other => panic!("not forwarded: {other:?}"),
    }
}

/// An IPv4 address from its text.
pub(crate) fn ip(text: &str) -> Ipv4Addr {
    text.parse().unwrap()
}

/// `n` milliseconds.
pub(crate) fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// The bytes as lower-case hexadecimal.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The bytes that hexadecimal text spells; whitespace is ignored.
pub(crate) fn unhex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    assert!(
        digits.len().is_multiple_of(2),
        "an odd number of hex digits"
    );
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
