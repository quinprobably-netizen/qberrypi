//! The listeners on port 53: datagrams and connections, each answered through [`Dns`].
//!
//! The lines logged here say where the service listens, and when the first device was answered.
//! A name that is asked for, and an address that asks, are never logged.

use std::io::{self, ErrorKind};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use qb_dns::{Action, Transport};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};

use super::upstream::UDP_BUFFER;
use super::{Dns, MAX_FORWARDS};
use crate::stall::timed;

/// The most TCP connections that are served at once; one more is closed as soon as it is taken.
pub const TCP_CLIENTS: usize = 32;
/// How long a TCP client may take to send what it is expected to send, or to take what it is
/// sent, before its connection is closed.
pub const TCP_IDLE: Duration = Duration::from_secs(10);
/// How long one TCP connection may last in all, counted from when it is taken: after this it is
/// closed, whatever the client is doing and however often it asks within [`TCP_IDLE`]. A client
/// that is served well within it, as RFC 7766 has one behave (a few queries, one after the
/// other or pipelined, and then it closes, or lets the idle limit close it), never meets it, and
/// one that does meets a closed connection, which RFC 7766 tells every client to take and to
/// answer with a new one. A minute is six idle limits, so that a client that asks, waits for what
/// it wants to know and asks again is not cut short, and no client that asks every few seconds
/// holds one of the [`TCP_CLIENTS`] places for longer.
pub const TCP_LIFETIME: Duration = Duration::from_secs(60);
/// The most datagrams that are in a task at once: those that wait for an upstream, and the rare
/// reply that waits for room in the socket. An answer that is known at once, a stale one too, is
/// sent from the receive loop and takes none. A packet that finds none free is dropped, as the
/// kernel drops what does not fit in its buffer: a flood is shed here and does not grow without
/// end. A forward that is shed for want of a slot has been counted by the resolver already, which
/// decides before a slot is sought. Those that wait for an upstream are at most [`MAX_FORWARDS`]:
/// the rest is room for those that are on their way.
pub const UDP_TASKS: usize = 2 * MAX_FORWARDS;

/// How long the TCP loop rests after a failed accept, so that a failure that lasts is not a spin.
const ACCEPT_PAUSE: Duration = Duration::from_millis(100);
/// How long the UDP loop rests after a failed receive, so that a failure that lasts is not a spin.
const RECV_PAUSE: Duration = Duration::from_millis(10);
/// How often a port of 0 is tried: the TCP port of the number that UDP was given may be taken.
const BIND_TRIES: usize = 100;

/// A UDP socket and a TCP listener on one address and port.
pub struct Listeners {
    pub udp: UdpSocket,
    pub tcp: TcpListener,
}

impl Listeners {
    /// The address that both are bound to.
    pub fn addr(&self) -> SocketAddr {
        // A bound socket always has an address: the fallback is never used.
        let unbound = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
        self.udp.local_addr().unwrap_or(unbound)
    }
}

/// Binds UDP at `addr`, and then TCP at the same address and the port that UDP got. A port of 0,
/// for which the system chooses the UDP port, is tried again if TCP cannot have that port.
pub async fn bind(addr: SocketAddr) -> io::Result<Listeners> {
    // Nothing here opens an IPv6 socket.
    debug_assert!(addr.is_ipv4());
    let mut tries = 1;
    loop {
        let udp = UdpSocket::bind(addr).await?;
        let tcp_addr = SocketAddr::new(addr.ip(), udp.local_addr()?.port());
        match TcpListener::bind(tcp_addr).await {
            Ok(tcp) => return Ok(Listeners { udp, tcp }),
            Err(_) if addr.port() == 0 && tries < BIND_TRIES => tries += 1,
            Err(err) => return Err(err),
        }
    }
}

/// The DNS component: binds `addr`, logs where it listens, and serves. It ends only with an
/// error, which includes a port that cannot be bound.
pub async fn run(dns: Arc<Dns>, addr: SocketAddr) -> io::Result<()> {
    let listeners = bind(addr).await?;
    log::info!("dns: listening on {}", listeners.addr());
    serve(dns, listeners).await
}

/// Answers every client of `listeners` through `dns`, with [`TCP_CLIENTS`] TCP connections at a
/// time that may idle for [`TCP_IDLE`] and last [`TCP_LIFETIME`]. A failed receive or accept is
/// waited out, not an end: there is no supervisor to start the service again, and the household
/// would have no DNS.
///
/// The tasks that this starts, one for each connection and one for each datagram that waits for
/// an upstream, belong to the future that is returned: when it is dropped they are aborted, and
/// the sockets that they hold are closed with it, so that a service that is started again can
/// bind the same port at once.
pub async fn serve(dns: Arc<Dns>, listeners: Listeners) -> io::Result<()> {
    serve_with(
        dns,
        listeners,
        TCP_CLIENTS,
        TCP_IDLE,
        TCP_LIFETIME,
        UDP_TASKS,
    )
    .await
}

/// [`serve`] with `tcp_clients` TCP connections at a time that may idle for `tcp_idle` and last
/// `tcp_life`, and `udp_tasks` datagrams at a time that are not answered on the receive loop.
pub(crate) async fn serve_with(
    dns: Arc<Dns>,
    listeners: Listeners,
    tcp_clients: usize,
    tcp_idle: Duration,
    tcp_life: Duration,
    udp_tasks: usize,
) -> io::Result<()> {
    let Listeners { udp, tcp } = listeners;
    tokio::try_join!(
        serve_udp(dns.clone(), udp, udp_tasks),
        serve_tcp(dns, tcp, tcp_clients, tcp_idle, tcp_life)
    )?;
    Ok(())
}

/// Decides each datagram on this loop, and sends what is known at once from here: an answer from
/// the cache (a stale one too, whose renewal is asked for at the same time), from the block set or
/// from the local names costs no task and no copy of the packet, and does not wait for a slot.
/// Only a datagram that must wait for an upstream is taken into a task of its own, so that nothing
/// in this loop waits for one. At most `udp_tasks` such tasks run at once, and a datagram that
/// finds none free is dropped: the resolver has counted it by then, as it decides before a slot is
/// sought.
///
/// A failed receive does not end the loop: it rests for [`RECV_PAUSE`] and goes on, and logs one
/// line for a run of failures, which the next datagram that is received ends.
///
/// The tasks are kept in a [`JoinSet`], which aborts them when the loop is dropped: a task that
/// went on without it would hold the socket open, and the port with it. The set is cleared of the
/// tasks that have ended only where a task is added, so that the answers that need no task
/// (the hot path) do not touch it.
async fn serve_udp(dns: Arc<Dns>, socket: UdpSocket, udp_tasks: usize) -> io::Result<()> {
    let socket = Arc::new(socket);
    let slots = Arc::new(Semaphore::new(udp_tasks));
    let mut tasks = JoinSet::new();
    let mut buf = vec![0u8; UDP_BUFFER];
    let mut failing = false;
    loop {
        let (len, client) = match socket.recv_from(&mut buf).await {
            Ok(received) => {
                failing = false;
                received
            }
            Err(error) => {
                if !failing {
                    log::warn!("dns: receiving a datagram failed, going on: {error}");
                    failing = true;
                }
                sleep(RECV_PAUSE).await;
                continue;
            }
        };
        // The table of clients and the resolver are locked for one call each, inside
        // `note_client` and `decide_from`, and never across an `.await`.
        dns.note_client(client.ip());
        match dns.decide_from(&buf[..len], Transport::Udp, Some(client.ip())) {
            Action::Reply(reply) => reply_now(&dns, &socket, &slots, &mut tasks, reply, client),
            Action::ReplyAndRefresh(reply, pending) => {
                dns.refresh(pending);
                reply_now(&dns, &socket, &slots, &mut tasks, reply, client);
            }
            Action::Drop => {}
            action @ Action::Forward(_) => {
                let Ok(slot) = slots.clone().try_acquire_owned() else {
                    continue;
                };
                let (dns, socket) = (dns.clone(), socket.clone());
                reap(&mut tasks);
                tasks.spawn(timed("dns forward", async move {
                    let _slot = slot;
                    if let Some(reply) = dns.carry_for(action, Some(client.ip())).await
                        && socket.send_to(&reply, client).await.is_ok()
                    {
                        dns.note_answered(client.ip());
                        dns.observe(client.ip(), &reply);
                    }
                }));
            }
        }
    }
}

/// Sends `reply` to `client` from the receive loop. Only if the socket's buffer is full does it
/// wait for room, in a task under a slot, and with none free the reply is dropped, as the kernel
/// would. Any other failure to send is ignored: a client that has gone is no concern of ours.
///
/// A reply that was sent is offered to the watchdog right after it, so that the answer goes out
/// first; one that was not sent is not offered. A task that is started is added to `tasks`.
fn reply_now(
    dns: &Arc<Dns>,
    socket: &Arc<UdpSocket>,
    slots: &Arc<Semaphore>,
    tasks: &mut JoinSet<()>,
    reply: Vec<u8>,
    client: SocketAddr,
) {
    let Err(error) = socket.try_send_to(&reply, client) else {
        dns.note_answered(client.ip());
        dns.observe(client.ip(), &reply);
        return;
    };
    if error.kind() != ErrorKind::WouldBlock {
        return;
    }
    if let Ok(slot) = slots.clone().try_acquire_owned() {
        let (dns, socket) = (dns.clone(), socket.clone());
        reap(tasks);
        tasks.spawn(timed("dns reply", async move {
            let _slot = slot;
            if socket.send_to(&reply, client).await.is_ok() {
                dns.note_answered(client.ip());
                dns.observe(client.ip(), &reply);
            }
        }));
    }
}

/// Takes the tasks of `tasks` that have ended out of it: a set keeps what a task returned until
/// it is asked for, so a set that is not cleared grows with every task that it has ever run.
/// Nothing waits here.
fn reap(tasks: &mut JoinSet<()>) {
    while tasks.try_join_next().is_some() {}
}

/// Takes each connection into a task of its own. At most `tcp_clients` run at once: one more is
/// accepted, which empties the queue of the kernel, and is closed at once by being dropped. Each
/// connection is served as [`serve_connection`] does, under `tcp_idle` and `tcp_life`.
///
/// The tasks are kept in a [`JoinSet`], which aborts them, and so closes their connections, when
/// this loop is dropped. The ones that have ended are taken out of it as each connection is
/// accepted.
async fn serve_tcp(
    dns: Arc<Dns>,
    listener: TcpListener,
    tcp_clients: usize,
    tcp_idle: Duration,
    tcp_life: Duration,
) -> io::Result<()> {
    let slots = Arc::new(Semaphore::new(tcp_clients));
    let mut connections = JoinSet::new();
    loop {
        // A failed accept is mostly one client's: it reset the connection before it was taken.
        let Ok((stream, peer)) = listener.accept().await else {
            sleep(ACCEPT_PAUSE).await;
            continue;
        };
        reap(&mut connections);
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let dns = dns.clone();
        connections.spawn(timed("dns tcp", async move {
            let _slot = slot;
            // However it ended, the connection is closed with it.
            let _ = serve_connection(&dns, stream, peer, tcp_idle, tcp_life).await;
        }));
    }
}

/// One connection of the client at `peer`, which [`talk`] serves, and which ends at the latest
/// `life` after this is called, whatever the client is doing: a client that asks again within
/// `idle`, every time, would otherwise hold its place for ever. The connection is closed with
/// the stream, which is dropped, and the answer that is being made at that moment is dropped
/// with it.
async fn serve_connection(
    dns: &Arc<Dns>,
    stream: impl AsyncRead + AsyncWrite + Unpin,
    peer: SocketAddr,
    idle: Duration,
    life: Duration,
) -> io::Result<()> {
    within(life, talk(dns, stream, peer, idle)).await
}

/// One connection of the client at `peer`: a message with its 2-byte length, its answer, and so on
/// in order. Each answer is offered to the watchdog as that client's, once it is written.
///
/// It ends, with an error or without one, at the end of the stream, at a length of 0, at any read
/// or write that takes longer than `idle`, and at a reply too long for the length. Nothing says
/// which: the caller closes the connection in every case. Each message that is read is noted as
/// asked by `peer`.
async fn talk(
    dns: &Arc<Dns>,
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    peer: SocketAddr,
    idle: Duration,
) -> io::Result<()> {
    loop {
        let mut len = [0u8; 2];
        within(idle, stream.read_exact(&mut len)).await?;
        let len = usize::from(u16::from_be_bytes(len));
        if len == 0 {
            return Ok(());
        }
        let mut message = vec![0u8; len];
        within(idle, stream.read_exact(&mut message)).await?;
        dns.note_client(peer.ip());
        let Some(reply) = dns
            .answer_for(&message, Transport::Tcp, Some(peer.ip()))
            .await
        else {
            continue;
        };
        let len = u16::try_from(reply.len()).map_err(|_| ErrorKind::InvalidData)?;
        let framed = [&len.to_be_bytes()[..], &reply[..]].concat();
        within(idle, stream.write_all(&framed)).await?;
        dns.note_answered(peer.ip());
        dns.observe(peer.ip(), &reply);
    }
}

/// What `work` gives, or `ErrorKind::TimedOut` if it takes longer than `limit`. The value that
/// a read gives is of no use here, so it is dropped.
async fn within<T>(limit: Duration, work: impl Future<Output = io::Result<T>>) -> io::Result<()> {
    match timeout(limit, work).await {
        Ok(done) => done.map(drop),
        Err(_) => Err(ErrorKind::TimedOut.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::{TCP_IDLE, TCP_LIFETIME, UDP_TASKS, bind, reply_now, serve_connection, serve_with};
    use crate::alerts::NullSink;
    use crate::config::{Ipv4Cidr, Net, TimeZoneRule};
    use crate::dns::Dns;
    use crate::dns::client::{query, read_answer};
    use crate::dns::testutil::{
        FakeUpstream, FixedOffset, RecordingSink, Reply, ask_tcp, ask_udp, ask_udp_aaaa,
        closed_port, ip, listen, ms, one, read_frame, service, service_with_alerts, tcp_exchange,
        udp_exchange, until, write_frame,
    };
    use crate::dns::upstream::Upstreams;
    use crate::net::{configure, loopback_up};
    use crate::netlink::Route;
    use crate::watch::rebind::RebindPolicy;
    use crate::watch::{self, Event, FEED_CAPACITY, Watch, names};
    use crate::{lists, sys};

    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::atomic::Ordering;
    use std::sync::mpsc::Receiver;
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::{Duration, Instant};

    use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{Name, RecordType};
    use qb_dns::{Action, BlockSet, Transport};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::{TcpSocket, TcpStream, UdpSocket};
    use tokio::sync::Semaphore;
    use tokio::task::JoinSet;
    use tokio::time::{sleep, timeout};

    /// The life that the tests of other things give a TCP connection: more than they take.
    const LIFE: Duration = Duration::from_secs(10);

    /// The bytes that a stream gives within `wait`: `Ok(0)` is the end of the stream, and an
    /// error, for a stream that was reset, or `Err(TimedOut)` for none within the wait.
    async fn read_some(stream: &mut TcpStream, wait: Duration) -> io::Result<usize> {
        match timeout(wait, stream.read(&mut [0u8; 16])).await {
            Ok(read) => read,
            Err(_) => Err(io::ErrorKind::TimedOut.into()),
        }
    }

    #[tokio::test]
    async fn a_forwarded_name_is_answered_and_its_repeat_comes_from_the_cache() {
        let (dns, addr, up) = one(Reply::Answer(ip("192.0.2.10"))).await;
        for _ in 0..2 {
            assert_eq!(
                ask_udp(addr, "example.com").await.unwrap().v4(),
                [ip("192.0.2.10")]
            );
        }
        assert_eq!(up.udp_queries(), 1);
        let total = dns.resolver().stats().total();
        assert_eq!(
            (total.queries, total.forwarded, total.cache_hits),
            (2, 1, 1)
        );
    }

    #[tokio::test]
    async fn a_tcp_client_is_answered_and_may_ask_again_on_its_connection() {
        let (_dns, addr, up) = one(Reply::Answer(ip("192.0.2.10"))).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        for name in ["example.com", "example.org"] {
            write_frame(&mut stream, &query(9, name, 1).unwrap())
                .await
                .unwrap();
            let reply = read_frame(&mut stream).await.unwrap();
            let answer = read_answer(&reply, 9).unwrap();
            assert_eq!(answer.v4(), [ip("192.0.2.10")]);
        }
        assert_eq!(up.udp_queries(), 2);
        // A length of 0 ends the connection.
        stream.write_all(&[0, 0]).await.unwrap();
        assert_eq!(read_some(&mut stream, ms(1000)).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn every_query_notes_its_sender_and_loopback_is_not_one() {
        let (dns, addr, _up) = one(Reply::Answer(ip("192.0.2.10"))).await;
        ask_udp(addr, "ads.example.com").await.unwrap();
        ask_tcp(addr, "ads.example.com").await.unwrap();
        // The test client is 127.0.0.1: it is no one's device, and its answer is no first one.
        assert_eq!(dns.clients().len(), 0);
        assert!(!dns.first_answer.load(Ordering::Relaxed));
        dns.note_client(ip("198.51.100.4").into());
        assert_eq!(dns.clients().list(dns.now().mono_secs)[0].queries, 1);
    }

    #[test]
    fn only_an_answer_to_a_device_the_table_would_count_is_the_first_to_a_client() {
        let dns = Dns::new(
            BlockSet::default(),
            Upstreams::with(vec![closed_port()], ms(1), ms(1)),
            Box::new(FixedOffset(0)),
        );
        for loopback in ["127.0.0.1", "127.8.8.8", "::1"] {
            dns.note_answered(loopback.parse().unwrap());
            assert!(!dns.first_answer.load(Ordering::Relaxed), "{loopback}");
        }
        dns.note_answered(ip("198.51.100.4").into());
        assert!(dns.first_answer.load(Ordering::Relaxed));
    }

    /// A logger that keeps what is logged, for the one test that installs it.
    struct Capture(Mutex<Vec<String>>);

    impl log::Log for Capture {
        fn enabled(&self, _: &log::Metadata<'_>) -> bool {
            true
        }

        fn log(&self, record: &log::Record<'_>) {
            let mut lines = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            lines.push(format!("{} {}", record.level(), record.args()));
        }

        fn flush(&self) {}
    }

    #[test]
    fn a_device_that_asks_is_counted_and_its_first_answer_is_logged_once() {
        crate::testns::run_inside("dns::listen::tests::ns_a_device_asks");
    }

    #[tokio::test]
    #[ignore = "run by a_device_that_asks_is_counted_and_its_first_answer_is_logged_once, inside a namespace"]
    async fn ns_a_device_asks() {
        if !crate::testns::inside() {
            return;
        }
        // This process runs this one test, so the logger is its own to set.
        static CAPTURE: Capture = Capture(Mutex::new(Vec::new()));
        log::set_logger(&CAPTURE).unwrap();
        log::set_max_level(log::LevelFilter::Trace);
        // The namespace's loopback has an address of a home network too, so that a client that is
        // bound to it is a device as far as the table is concerned, and one that is not is not.
        let mut route = Route::open().unwrap();
        loopback_up(&mut route).await.unwrap();
        let net = Net {
            address: Ipv4Cidr {
                addr: ip("192.0.2.53"),
                prefix: 24,
            },
            gateway: ip("192.0.2.1"),
            time_servers: Vec::new(),
        };
        configure(&mut route, "lo", &net).await.unwrap();
        let up = FakeUpstream::start(Reply::Answer(ip("192.0.2.10"))).await;
        let deny = ["ads.example.com".to_owned()];
        let dns = Dns::new(
            lists::from_config(&deny, &[]).build(),
            Upstreams::with(vec![up.addr], ms(300), ms(600)),
            Box::new(FixedOffset(0)),
        );
        let listeners = bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
            .await
            .unwrap();
        let port = listeners.addr().port();
        tokio::spawn(serve_with(
            dns.clone(),
            listeners,
            2,
            ms(200),
            LIFE,
            UDP_TASKS,
        ));
        let on_loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let from_device = ip("192.0.2.53");
        let first_answers = || -> Vec<String> {
            let lines = CAPTURE.0.lock().unwrap_or_else(PoisonError::into_inner);
            let first = |line: &&String| line.contains("first answer to a client");
            lines.iter().filter(first).cloned().collect()
        };

        // Asked from 127.0.0.1, over both transports, the answer comes and nothing is counted.
        assert!(ask_udp(on_loopback, "ads.example.com").await.is_some());
        assert!(ask_tcp(on_loopback, "ads.example.com").await.is_some());
        assert_eq!(dns.clients().len(), 0);
        assert!(first_answers().is_empty());

        let ask_over_udp = |name: &'static str| async move {
            let socket = UdpSocket::bind((from_device, 0)).await.unwrap();
            let packet = query(9, name, 1).unwrap();
            socket.send_to(&packet, (from_device, port)).await.unwrap();
            let mut buf = [0u8; 512];
            let (len, _) = timeout(ms(2000), socket.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            read_answer(&buf[..len], 9).unwrap().summary()
        };
        let asked = || dns.clients().list(dns.now().mono_secs)[0].queries;

        // A device asks over UDP, for a name that is answered on the receive loop: it is counted,
        // and the first answer to it is logged, with the kernel's uptime and no address.
        assert_eq!(ask_over_udp("ads.example.com").await, "NOERROR 0.0.0.0");
        let listed = dns.clients().list(dns.now().mono_secs);
        assert_eq!(
            listed
                .iter()
                .map(|c| (c.addr, c.queries))
                .collect::<Vec<_>>(),
            [(from_device, 1)]
        );
        let lines = first_answers();
        assert_eq!(lines.len(), 1, "{lines:?}");
        let ms_text = lines[0]
            .strip_prefix("INFO dns: first answer to a client ")
            .and_then(|rest| rest.strip_suffix(" ms after the kernel started"))
            .unwrap_or_else(|| panic!("{}", lines[0]));
        let logged_ms: u128 = ms_text.parse().unwrap();
        assert!(logged_ms > 0 && logged_ms <= sys::uptime().as_millis());
        assert!(!lines[0].contains("192.0.2"), "{}", lines[0]);
        // It is said once: the same device asks again.
        assert_eq!(ask_over_udp("ads.example.com").await, "NOERROR 0.0.0.0");
        assert_eq!((asked(), first_answers().len()), (2, 1));

        // Each way of answering has its own place that says it, so each is tried as the first.
        // A name that waits for the upstream is answered from a task of its own.
        dns.first_answer.store(false, Ordering::Relaxed);
        assert_eq!(ask_over_udp("example.com").await, "NOERROR 192.0.2.10");
        assert_eq!((asked(), first_answers().len()), (3, 2));

        // And over TCP: two messages on one connection are each counted, and say it once.
        dns.first_answer.store(false, Ordering::Relaxed);
        let tcp = TcpSocket::new_v4().unwrap();
        tcp.bind(SocketAddr::from((from_device, 0))).unwrap();
        let mut stream = tcp
            .connect(SocketAddr::from((from_device, port)))
            .await
            .unwrap();
        for _ in 0..2 {
            write_frame(&mut stream, &query(9, "example.com", 1).unwrap())
                .await
                .unwrap();
            let reply = read_frame(&mut stream).await.unwrap();
            assert_eq!(
                read_answer(&reply, 9).unwrap().summary(),
                "NOERROR 192.0.2.10"
            );
        }
        assert_eq!((asked(), first_answers().len()), (5, 3));
        // No line of the log, whatever its level, says an address.
        let lines = CAPTURE.0.lock().unwrap_or_else(PoisonError::into_inner);
        assert!(
            lines.iter().all(|line| !line.contains("192.0.2.53")),
            "{lines:?}"
        );
    }

    #[tokio::test]
    async fn a_denied_name_is_answered_here() {
        let (_dns, addr, up) = one(Reply::Answer(ip("192.0.2.10"))).await;
        assert_eq!(
            ask_udp(addr, "ads.example.com").await.unwrap().summary(),
            "NOERROR 0.0.0.0"
        );
        assert_eq!(
            ask_tcp(addr, "ADS.example.com").await.unwrap().summary(),
            "NOERROR 0.0.0.0"
        );
        assert_eq!(up.udp_queries(), 0);
    }

    // Review Focus 1
    #[tokio::test]
    async fn when_no_upstream_answers_the_client_gets_servfail_and_the_listener_lives() {
        let (_dns, addr) = service(Upstreams::with(vec![closed_port()], ms(300), ms(300))).await;
        for name in ["example.com", "example.org"] {
            assert_eq!(ask_udp(addr, name).await.unwrap().summary(), "SERVFAIL");
        }
        assert_eq!(
            ask_udp(addr, "printer").await.unwrap().summary(),
            "NXDOMAIN"
        );
    }

    // Review Focus 3
    #[tokio::test]
    async fn tcp_clients_that_stall_are_closed_and_hold_up_nobody() {
        let (_dns, addr, _up) = one(Reply::Answer(ip("192.0.2.10"))).await;
        // The limit of `service` is two clients, and they idle for 200 ms.
        let mut half = TcpStream::connect(addr).await.unwrap();
        half.write_all(&[0]).await.unwrap();
        let mut silent = TcpStream::connect(addr).await.unwrap();
        assert!(ask_udp(addr, "example.com").await.is_some());
        // A third is closed at once and not kept waiting.
        let mut third = TcpStream::connect(addr).await.unwrap();
        assert_eq!(read_some(&mut third, ms(100)).await.unwrap(), 0);
        tokio::time::sleep(ms(400)).await;
        assert_eq!(read_some(&mut half, ms(100)).await.unwrap(), 0);
        assert_eq!(read_some(&mut silent, ms(100)).await.unwrap(), 0);
        assert!(ask_tcp(addr, "example.com").await.is_some());
    }

    /// A resolver that answers `printer` itself and so needs no upstream.
    fn local() -> Arc<Dns> {
        Dns::new(
            BlockSet::default(),
            Upstreams::with(vec![closed_port()], ms(1), ms(1)),
            Box::new(FixedOffset(0)),
        )
    }

    /// What the resolver says to `printer`, asked over `stream` as a TCP client asks.
    async fn ask_printer(stream: &mut (impl AsyncRead + AsyncWrite + Unpin)) -> io::Result<String> {
        write_frame(stream, &query(9, "printer", 1).unwrap()).await?;
        let reply = read_frame(stream).await?;
        Ok(read_answer(&reply, 9).unwrap().summary())
    }

    /// Serves one end of an in-memory connection as the listener serves a client, from a task
    /// that gives how it ended and how long the connection lasted by the clock of the test.
    fn serve_in_memory(
        server: tokio::io::DuplexStream,
    ) -> tokio::task::JoinHandle<(io::Result<()>, Duration)> {
        let began = tokio::time::Instant::now();
        tokio::spawn(async move {
            let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 5353));
            let ended = serve_connection(&local(), server, peer, TCP_IDLE, TCP_LIFETIME).await;
            (ended, began.elapsed())
        })
    }

    // The clock is the test's: the connection is in memory, so that nothing but the timers
    // decides when time moves.
    #[tokio::test(start_paused = true)]
    async fn a_tcp_client_that_keeps_asking_within_the_idle_limit_is_closed_at_the_lifetime() {
        let (mut client, server) = tokio::io::duplex(4096);
        let served = serve_in_memory(server);
        // One question every 9 s, each inside the idle limit of 10 s, the last at 54 s: all are
        // answered, so that the idle limit alone never ends this connection.
        assert!(TCP_IDLE > Duration::from_secs(9));
        for turn in 0..=6 {
            assert_eq!(
                ask_printer(&mut client).await.unwrap(),
                "NXDOMAIN",
                "{turn}"
            );
            sleep(Duration::from_secs(9)).await;
        }
        // The next would be at 63 s: the connection ended at the lifetime, 60 s from its start.
        let (ended, lasted) = served.await.unwrap();
        assert_eq!(ended.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(
            (TCP_LIFETIME..TCP_LIFETIME + ms(10)).contains(&lasted),
            "{lasted:?}"
        );
        assert!(ask_printer(&mut client).await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn a_tcp_client_that_asks_a_few_times_and_goes_is_not_held_to_the_lifetime() {
        let secs = Duration::from_secs;
        // A client that closes with the zero length, as RFC 7766 has it, after three questions.
        let (mut client, server) = tokio::io::duplex(4096);
        let served = serve_in_memory(server);
        for turn in 0..3 {
            if turn > 0 {
                sleep(secs(1)).await;
            }
            assert_eq!(ask_printer(&mut client).await.unwrap(), "NXDOMAIN");
        }
        client.write_all(&[0, 0]).await.unwrap();
        let (ended, lasted) = served.await.unwrap();
        ended.unwrap();
        assert!((secs(2)..secs(3)).contains(&lasted), "{lasted:?}");

        // One that pipelines two questions, reads both answers and drops the connection.
        let (mut client, server) = tokio::io::duplex(4096);
        let served = serve_in_memory(server);
        for _ in 0..2 {
            write_frame(&mut client, &query(9, "printer", 1).unwrap())
                .await
                .unwrap();
        }
        for _ in 0..2 {
            read_frame(&mut client).await.unwrap();
        }
        drop(client);
        let (ended, lasted) = served.await.unwrap();
        assert_eq!(ended.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        assert!(lasted < secs(1), "{lasted:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_tcp_client_is_still_closed_at_the_idle_limit_and_not_at_the_lifetime() {
        let (mut client, server) = tokio::io::duplex(4096);
        let served = serve_in_memory(server);
        assert_eq!(ask_printer(&mut client).await.unwrap(), "NXDOMAIN");
        let (ended, lasted) = served.await.unwrap();
        assert_eq!(ended.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(
            (TCP_IDLE..TCP_IDLE + ms(10)).contains(&lasted),
            "{lasted:?}"
        );
    }

    #[tokio::test]
    async fn serve_closes_a_tcp_client_at_the_lifetime_and_its_place_goes_to_the_next() {
        let listeners = bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let addr = listeners.addr();
        // One place, an idle limit of 2 s and a lifetime of 600 ms.
        tokio::spawn(serve_with(
            local(),
            listeners,
            1,
            ms(2000),
            ms(600),
            UDP_TASKS,
        ));

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let began = Instant::now();
        let mut answered = 0;
        // Asks every 100 ms until its connection is closed, for 3 s at most.
        while answered < 30
            && timeout(ms(2000), ask_printer(&mut stream))
                .await
                .is_ok_and(|answer| answer.is_ok())
        {
            answered += 1;
            sleep(ms(100)).await;
        }
        let lasted = began.elapsed();
        assert!(answered >= 3, "{answered}");
        assert!((ms(600)..ms(1900)).contains(&lasted), "{lasted:?}");
        // The one place is free again.
        assert_eq!(
            ask_tcp(addr, "printer").await.unwrap().summary(),
            "NXDOMAIN"
        );
    }

    #[tokio::test]
    async fn dropping_serve_ends_its_connections_and_the_tasks_that_hold_its_socket() {
        let up = FakeUpstream::start(Reply::After(ms(1500), ip("192.0.2.10"))).await;
        let dns = Dns::new(
            BlockSet::default(),
            Upstreams::with(vec![up.addr], ms(3000), ms(3000)),
            Box::new(FixedOffset(0)),
        );
        let listeners = bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let addr = listeners.addr();
        let serving = tokio::spawn(serve_with(
            dns,
            listeners,
            2,
            ms(10_000),
            ms(10_000),
            UDP_TASKS,
        ));
        // A datagram whose answer waits for the upstream, in a task that holds the socket, and a
        // TCP client that is connected and quiet.
        let asker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        asker
            .send_to(&query(9, "example.com", 1).unwrap(), addr)
            .await
            .unwrap();
        let mut quiet = TcpStream::connect(addr).await.unwrap();
        // The client has been served, so that its connection is in a task, and then says nothing.
        assert_eq!(ask_printer(&mut quiet).await.unwrap(), "NXDOMAIN");
        for _ in 0..300 {
            if up.udp_queries() == 1 {
                break;
            }
            sleep(ms(10)).await;
        }
        assert_eq!(up.udp_queries(), 1);

        serving.abort();
        assert!(serving.await.unwrap_err().is_cancelled());
        sleep(ms(50)).await;
        // The connection is closed, and the port is free to bind again, 1.4 s before the
        // datagram's task would have ended by itself.
        assert_eq!(read_some(&mut quiet, ms(500)).await.unwrap(), 0);
        UdpSocket::bind(addr).await.unwrap();
    }

    #[tokio::test]
    async fn a_forward_beyond_the_limit_gets_servfail_at_once() {
        let up = FakeUpstream::start(Reply::After(ms(400), ip("192.0.2.10"))).await;
        let dns = Dns::with_forward_limit(
            BlockSet::default(),
            Upstreams::with(vec![up.addr], ms(2000), ms(2000)),
            Box::new(FixedOffset(0)),
            1,
        );
        let addr = listen(dns).await;
        let timed = |name| async move {
            let started = Instant::now();
            let summary = ask_udp(addr, name).await.unwrap().summary();
            (summary, started.elapsed())
        };
        let (first, second) = tokio::join!(timed("example.com"), timed("example.org"));
        // "NOERROR ..." sorts before "SERVFAIL".
        let mut results = [first, second];
        results.sort();
        assert_eq!(results[0].0, "NOERROR 192.0.2.10");
        assert!(results[0].1 >= ms(400), "{:?}", results[0].1);
        assert_eq!(results[1].0, "SERVFAIL");
        assert!(results[1].1 < ms(200), "{:?}", results[1].1);
    }

    // Task 3c: the hot path answers from the receive loop, which needs no slot.
    #[tokio::test]
    async fn a_cached_or_blocked_answer_is_sent_while_every_task_waits_for_an_upstream() {
        let up = FakeUpstream::start(Reply::After(ms(400), ip("192.0.2.10"))).await;
        let deny = ["ads.example.com".to_owned()];
        let dns = Dns::new(
            lists::from_config(&deny, &[]).build(),
            Upstreams::with(vec![up.addr], ms(2000), ms(2000)),
            Box::new(FixedOffset(0)),
        );
        let listeners = bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let addr = listeners.addr();
        // One slot for the datagrams that wait.
        tokio::spawn(serve_with(dns, listeners, 2, ms(200), LIFE, 1));

        // `example.net` is asked for once, so that it is cached.
        assert_eq!(
            ask_udp(addr, "example.net").await.unwrap().summary(),
            "NOERROR 192.0.2.10"
        );
        // `example.com` takes the one slot, and waits 400 ms for the upstream.
        let first = tokio::spawn(ask_udp(addr, "example.com"));
        sleep(ms(100)).await;
        assert!(!first.is_finished());
        for (name, summary) in [
            ("ads.example.com", "NOERROR 0.0.0.0"),
            ("example.net", "NOERROR 192.0.2.10"),
        ] {
            let asked = Instant::now();
            assert_eq!(ask_udp(addr, name).await.unwrap().summary(), summary);
            assert!(asked.elapsed() < ms(100), "{:?}", asked.elapsed());
        }
        assert!(!first.is_finished());
        assert_eq!(
            first.await.unwrap().unwrap().summary(),
            "NOERROR 192.0.2.10"
        );
    }

    // A stale answer is a cached answer to the client, and takes no slot either.
    #[tokio::test]
    async fn a_stale_answer_is_sent_while_every_task_waits_for_an_upstream_and_is_renewed() {
        /// Seconds a stale answer is sent with, as `qb-dns` has it.
        const STALE_TTL: u32 = 30;
        let up = FakeUpstream::start(Reply::After(ms(400), ip("192.0.2.10"))).await;
        // Two forwards: one for the question that waits, one for the renewal.
        let dns = Dns::with_forward_limit(
            BlockSet::default(),
            Upstreams::with(vec![up.addr], ms(2000), ms(2000)),
            Box::new(FixedOffset(0)),
            2,
        );
        // `example.com` is cached, and 100 seconds later the answer it keeps, which lives 60, is stale.
        let packet = query(9, "example.com", 1).unwrap();
        assert!(dns.answer(&packet, Transport::Udp).await.is_some());
        let mut dns = Arc::try_unwrap(dns).ok().expect("nothing else holds it");
        dns.started -= Duration::from_secs(100);
        let dns = Arc::new(dns);
        let listeners = bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let addr = listeners.addr();
        // One slot for the datagrams that wait.
        tokio::spawn(serve_with(dns.clone(), listeners, 2, ms(200), LIFE, 1));

        // `example.org` takes the one slot, and waits 400 ms for the upstream.
        let slow = tokio::spawn(ask_udp(addr, "example.org"));
        sleep(ms(100)).await;
        assert!(!slow.is_finished());
        let stale = ask_udp(addr, "example.com").await.unwrap();
        assert_eq!(stale.v4(), [ip("192.0.2.10")]);
        assert_eq!(stale.min_ttl, Some(STALE_TTL));
        // The stale answer came while the slot was still taken: it did not wait for it.
        assert!(!slow.is_finished());
        assert_eq!(slow.await.unwrap().unwrap().summary(), "NOERROR 192.0.2.10");

        // The renewal was asked for as well, once, and its permit comes back with the answer.
        until("the renewal to be asked and its permit returned", || {
            up.udp_queries() == 3 && dns.forwards.available_permits() == 2
        })
        .await;
        // The renewed answer is a fresh one, and comes from the cache.
        let fresh = ask_udp(addr, "example.com").await.unwrap();
        assert!(fresh.min_ttl > Some(STALE_TTL), "{:?}", fresh.min_ttl);
        assert_eq!(up.udp_queries(), 3);
    }

    #[tokio::test]
    async fn decide_and_carry_give_what_answer_gives() {
        let (dns, _addr, _up) = one(Reply::Answer(ip("192.0.2.10"))).await;
        let cached = query(7, "example.com", 1).unwrap();
        // The first asking is forwarded and fills the cache: the second is the cache's.
        assert!(dns.answer(&cached, Transport::Udp).await.is_some());
        let blocked = query(7, "ads.example.com", 1).unwrap();
        let garbage = [1, 2, 3, 4, 5];
        // A cached answer counts its TTL down by the second, so the answers are compared read.
        let read =
            |reply: Option<Vec<u8>>| reply.and_then(|r| read_answer(&r, 7)).map(|a| a.summary());
        for (packet, want) in [
            (&cached[..], Some("NOERROR 192.0.2.10")),
            (&blocked[..], Some("NOERROR 0.0.0.0")),
            (&garbage[..], None),
        ] {
            let carried = dns.carry(dns.decide(packet, Transport::Udp)).await;
            assert_eq!(read(carried).as_deref(), want);
            assert_eq!(
                read(dns.answer(packet, Transport::Udp).await).as_deref(),
                want
            );
        }
    }

    /// Hangs a feed on `dns`, and gives the end that the events come out of.
    fn watched(dns: &Dns) -> Receiver<Event> {
        let (feed, events) = watch::feed();
        dns.set_watch(Watch::for_test(feed, Arc::new(NullSink)));
        events
    }

    /// The events that are waiting in `events`, as client, name, type and code. An answer is
    /// offered right after it is sent, in the same turn of the runtime, and the tests run on its
    /// one thread, so those of the answers that a client has received are all there.
    fn waiting(events: &Receiver<Event>) -> Vec<(IpAddr, String, u16, u8)> {
        events
            .try_iter()
            .map(|event| {
                let mut buf = [0u8; names::NAME_TEXT_MAX];
                let name = names::decode(event.name_wire(), &mut buf)
                    .unwrap()
                    .to_owned();
                (event.client, name, event.qtype, event.rcode)
            })
            .collect()
    }

    /// One event of `rcode` for `name`, type A, from the loopback client.
    fn event_for(name: &str, rcode: u8) -> Vec<(IpAddr, String, u16, u8)> {
        vec![(IpAddr::V4(Ipv4Addr::LOCALHOST), name.to_owned(), 1, rcode)]
    }

    #[tokio::test]
    async fn an_answer_is_offered_once_it_is_sent_and_not_when_it_could_not_be() {
        let dns = Dns::new(
            BlockSet::default(),
            Upstreams::with(vec![closed_port()], ms(1), ms(1)),
            Box::new(FixedOffset(0)),
        );
        let events = watched(&dns);
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let slots = Arc::new(Semaphore::new(1));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let packet = query(3, "printer", 1).unwrap();
        let Action::Reply(reply) = dns.decide(&packet, Transport::Udp) else {
            panic!("a name without a dot is answered here");
        };

        // To a client that is there: sent, and offered.
        let mut tasks = JoinSet::new();
        reply_now(
            &dns,
            &socket,
            &slots,
            &mut tasks,
            reply.clone(),
            client.local_addr().unwrap(),
        );
        let mut got = [0u8; 512];
        let (len, _) = client.recv_from(&mut got).await.unwrap();
        assert_eq!(&got[..len], &reply[..]);
        assert_eq!(waiting(&events), event_for("printer", 3));
        // To an address that cannot be sent to (port 0): not sent, so not offered.
        reply_now(
            &dns,
            &socket,
            &slots,
            &mut tasks,
            reply,
            "127.0.0.1:0".parse().unwrap(),
        );
        assert_eq!(waiting(&events), []);
    }

    #[tokio::test]
    async fn each_answer_that_is_sent_is_offered_once_with_its_client_name_type_and_code() {
        let (dns, addr, _up) = one(Reply::Answer(ip("192.0.2.10"))).await;
        let events = watched(&dns);
        // Forwarded over UDP, and the same name from the cache.
        for _ in 0..2 {
            ask_udp(addr, "example.com").await.unwrap();
            assert_eq!(waiting(&events), event_for("example.com", 0));
        }
        // Denied here, over UDP and over TCP, and the name comes out in lower case.
        ask_udp(addr, "ads.example.com").await.unwrap();
        assert_eq!(waiting(&events), event_for("ads.example.com", 0));
        ask_tcp(addr, "ADS.example.com").await.unwrap();
        assert_eq!(waiting(&events), event_for("ads.example.com", 0));
        // Forwarded over TCP, and from the cache over TCP.
        for _ in 0..2 {
            ask_tcp(addr, "example.org").await.unwrap();
            assert_eq!(waiting(&events), event_for("example.org", 0));
        }
        // A name without a dot is answered here with NXDOMAIN, which is rcode 3.
        ask_udp(addr, "printer").await.unwrap();
        assert_eq!(waiting(&events), event_for("printer", 3));
        assert_eq!(dns.watch_events_dropped(), 0);
    }

    #[tokio::test]
    async fn the_events_carry_the_ttl_of_the_first_answer() {
        let (dns, addr, _up) = one(Reply::Answer(ip("192.0.2.10"))).await;
        let events = watched(&dns);
        ask_udp(addr, "example.com").await.unwrap();
        ask_udp(addr, "ads.example.com").await.unwrap();
        ask_udp(addr, "printer").await.unwrap();
        let ttls: Vec<u32> = events.try_iter().map(|event| event.ttl).collect();
        // The upstream's 60 seconds; the block set's answer, a TTL of its own; no answer.
        assert_eq!(ttls[0], 60);
        assert!(ttls[1] > 0, "{ttls:?}");
        assert_eq!(ttls[2], 0);
    }

    #[tokio::test]
    async fn a_stale_answer_and_a_servfail_are_offered_too() {
        let up = FakeUpstream::start(Reply::Answer(ip("192.0.2.10"))).await;
        let dns = Dns::with_forward_limit(
            BlockSet::default(),
            Upstreams::with(vec![up.addr], ms(300), ms(600)),
            Box::new(FixedOffset(0)),
            2,
        );
        let packet = query(9, "example.com", 1).unwrap();
        assert!(dns.answer(&packet, Transport::Udp).await.is_some());
        let mut dns = Arc::try_unwrap(dns).ok().expect("nothing else holds it");
        dns.started -= Duration::from_secs(100);
        let dns = Arc::new(dns);
        let events = watched(&dns);
        let addr = listen(dns.clone()).await;
        // Stale: answered from the cache and renewed, which is `ReplyAndRefresh`.
        ask_udp(addr, "example.com").await.unwrap();
        assert_eq!(waiting(&events), event_for("example.com", 0));

        // No upstream answers: SERVFAIL, which is rcode 2, from the task that waited.
        let (dns, addr) = service(Upstreams::with(vec![closed_port()], ms(300), ms(300))).await;
        let events = watched(&dns);
        ask_udp(addr, "example.com").await.unwrap();
        assert_eq!(waiting(&events), event_for("example.com", 2));
    }

    #[tokio::test]
    async fn our_own_lookups_and_packets_that_get_no_answer_offer_nothing() {
        let (dns, addr, _up) = one(Reply::Answer(ip("192.0.2.10"))).await;
        let events = watched(&dns);
        dns.lookup_v4("time.example.net").await.unwrap();
        dns.lookup_v4("time.example.net").await.unwrap();
        assert!(dns.lookup_v4("printer").await.is_err());
        assert_eq!(udp_exchange(addr, &[1, 2, 3, 4, 5], ms(200)).await, None);
        assert_eq!(waiting(&events), []);
        // The next answer from the listener is the first event.
        ask_udp(addr, "example.com").await.unwrap();
        assert_eq!(waiting(&events), event_for("example.com", 0));
    }

    #[tokio::test]
    async fn a_full_feed_counts_the_drops_and_the_answers_still_come_back_promptly() {
        let (dns, addr, up) = one(Reply::Answer(ip("192.0.2.10"))).await;
        // Nobody takes the events from this one.
        let events = watched(&dns);
        let asked = FEED_CAPACITY + 50;
        let started = Instant::now();
        let mut slowest = Duration::ZERO;
        for _ in 0..asked {
            let sent = Instant::now();
            assert_eq!(
                ask_udp(addr, "example.com").await.unwrap().v4(),
                [ip("192.0.2.10")]
            );
            slowest = slowest.max(sent.elapsed());
        }
        assert_eq!(dns.watch_events_dropped(), 50);
        assert_eq!(events.try_iter().count(), FEED_CAPACITY);
        assert_eq!(up.udp_queries(), 1);
        // A full feed makes no answer wait: the slowest took what a local round trip takes.
        assert!(slowest < ms(500), "{slowest:?} of {:?}", started.elapsed());
    }

    #[tokio::test]
    async fn garbage_gets_no_answer_and_the_next_query_does() {
        let (dns, addr, _up) = one(Reply::Answer(ip("192.0.2.10"))).await;
        assert_eq!(udp_exchange(addr, &[1, 2, 3, 4, 5], ms(200)).await, None);
        assert!(ask_udp(addr, "example.com").await.is_some());
        assert_eq!(dns.resolver().stats().total().queries, 1);
    }

    #[tokio::test]
    async fn own_lookups_go_through_the_same_resolver() {
        let (dns, _addr, up) = one(Reply::Answer(ip("192.0.2.10"))).await;
        assert_eq!(dns.lookup_v4("192.0.2.7").await.unwrap(), [ip("192.0.2.7")]);
        assert_eq!(up.udp_queries(), 0);
        for _ in 0..2 {
            assert_eq!(
                dns.lookup_v4("time.example.net").await.unwrap(),
                [ip("192.0.2.10")]
            );
        }
        assert_eq!(
            (up.udp_queries(), dns.resolver().stats().total().queries),
            (1, 2)
        );
        // 0.0.0.0 is no address.
        assert_eq!(
            dns.lookup_v4("ads.example.com").await.unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            dns.lookup_v4("printer").await.unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[tokio::test]
    async fn a_threat_asked_over_udp_and_tcp_names_the_asker() {
        let sink = Arc::new(RecordingSink::default());
        let upstreams = Upstreams::with(vec![closed_port()], ms(300), ms(300));
        let (_dns, addr) = service_with_alerts(upstreams, sink.clone()).await;
        let loopback = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(
            ask_udp(addr, "x.bad.example.net").await.unwrap().summary(),
            "NOERROR 0.0.0.0"
        );
        assert_eq!(
            ask_tcp(addr, "y.bad.example.net").await.unwrap().summary(),
            "NOERROR 0.0.0.0"
        );
        assert_eq!(
            sink.raised_after(2).await,
            [
                ("threat", "high", loopback, "x.bad.example.net".to_owned()),
                ("threat", "high", loopback, "y.bad.example.net".to_owned()),
            ]
        );
    }

    #[test]
    fn the_offset_given_to_the_resolver_is_the_zones() {
        let dns = Dns::new(
            BlockSet::default(),
            Upstreams::with(vec![closed_port()], ms(1), ms(1)),
            Box::new(TimeZoneRule::parse("<+0530>-5:30").unwrap()),
        );
        assert_eq!(dns.utc_offset(), 19_800);
    }

    /// A query for `name` of `qtype` as a validating client sends it: recursion desired, one
    /// question, and an OPT record with a payload of 1232 and the DO bit.
    fn validating_query(id: u16, name: &str, qtype: RecordType) -> Vec<u8> {
        let mut message = Message::new(id, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(Name::from_ascii(name).unwrap(), qtype));
        let mut edns = Edns::new();
        edns.set_max_payload(1232).set_dnssec_ok(true);
        message.set_edns(edns);
        message.to_vec().unwrap()
    }

    /// Checks that `reply` is the signed answer for `com.` of `qtype` to the query under `id`.
    fn assert_signed_answer(reply: &[u8], id: u16, qtype: RecordType) {
        let message = Message::from_vec(reply).unwrap();
        let header = &message.metadata;
        assert_eq!(
            (header.id, header.message_type, header.response_code),
            (id, MessageType::Response, ResponseCode::NoError)
        );
        let asked: Vec<_> = message
            .queries
            .iter()
            .map(|q| (q.name.to_ascii(), q.query_type))
            .collect();
        assert_eq!(asked, [("com.".to_owned(), qtype)]);
        let answers: Vec<_> = message
            .answers
            .iter()
            .map(|record| (record.name.to_ascii(), record.data.record_type()))
            .collect();
        assert_eq!(
            answers,
            [
                ("com.".to_owned(), qtype),
                ("com.".to_owned(), RecordType::RRSIG)
            ]
        );
        assert!(message.edns.is_some_and(|edns| edns.flags().dnssec_ok));
    }

    // Cross-plan ruling 13: a validating client asks the top-level domain for these two.
    #[tokio::test]
    async fn a_validating_client_gets_ds_and_dnskey_for_a_top_level_domain() {
        let (_dns, addr, up) = one(Reply::Dnssec).await;
        let ds = validating_query(0x4321, "com.", RecordType::DS);
        let reply = udp_exchange(addr, &ds, ms(2000)).await.unwrap();
        assert_signed_answer(&reply, 0x4321, RecordType::DS);
        let dnskey = validating_query(0x8765, "com.", RecordType::DNSKEY);
        let reply = tcp_exchange(addr, &dnskey, ms(2000)).await.unwrap();
        assert_signed_answer(&reply, 0x8765, RecordType::DNSKEY);
        assert_eq!(up.do_queries(), 2);
    }

    #[tokio::test]
    async fn a_hostile_upstream_cannot_plant_an_answer() {
        let (real, forged) = (ip("192.0.2.10"), ip("203.0.113.66"));
        let (dns, addr, up) = one(Reply::Hostile { real, forged }).await;
        for _ in 0..2 {
            let answer = ask_udp(addr, "example.com").await.unwrap();
            assert_eq!(answer.v4(), [real]);
        }
        assert_eq!(up.udp_queries(), 1);
        assert_eq!(dns.resolver().stats().total().cache_hits, 1);
    }

    /// Hangs a watch on `dns` that screens every public name but those under `allow`, and gives
    /// the sink that its alerts go into.
    fn screening(dns: &Dns, allow: &[&str]) -> Arc<RecordingSink> {
        let sink = Arc::new(RecordingSink::default());
        let (feed, _events) = watch::feed();
        let allow = allow.iter().map(|name| (*name).to_owned()).collect();
        dns.set_watch(Watch {
            feed,
            rebind: RebindPolicy::new(allow),
            sink: sink.clone(),
        });
        sink
    }

    /// The alert that a rebinding answer for `name` that went to the loopback client raises.
    fn rebind_alert(name: &str) -> (&'static str, &'static str, Option<IpAddr>, String) {
        let client = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        ("rebind", "high", client, name.to_owned())
    }

    #[tokio::test]
    async fn a_forwarded_public_address_passes_unchanged_and_raises_nothing() {
        let (dns, addr, up) = one(Reply::Answer(ip("192.0.2.10"))).await;
        let sink = screening(&dns, &[]);
        for _ in 0..2 {
            let answer = ask_udp(addr, "example.com").await.unwrap();
            assert_eq!(answer.v4(), [ip("192.0.2.10")]);
        }
        assert_eq!(
            ask_tcp(addr, "example.org").await.unwrap().summary(),
            "NOERROR 192.0.2.10"
        );
        assert_eq!(up.udp_queries(), 2);
        assert!(sink.raised().is_empty());
    }

    #[tokio::test]
    async fn a_private_address_is_answered_with_zeros_and_so_is_the_repeat_from_the_cache() {
        let (dns, addr, up) = one(Reply::Answer(ip("10.0.0.1"))).await;
        let sink = screening(&dns, &[]);
        for _ in 0..3 {
            let answer = ask_udp(addr, "example.com").await.unwrap();
            assert_eq!(answer.summary(), "NOERROR 0.0.0.0");
            assert_eq!(answer.addrs.len(), 1);
        }
        // Asked once, and over TCP too: the cache holds the answer that was given.
        assert_eq!(
            ask_tcp(addr, "example.com").await.unwrap().summary(),
            "NOERROR 0.0.0.0"
        );
        assert_eq!(up.udp_queries(), 1);
        assert_eq!(dns.resolver().stats().total().cache_hits, 3);
        // One alert, for the one answer that was screened, with the client that asked.
        assert_eq!(sink.raised(), [rebind_alert("example.com")]);

        // A name that is forwarded over TCP is screened as well, and alerts for its own name.
        assert_eq!(
            ask_tcp(addr, "Example.Org").await.unwrap().summary(),
            "NOERROR 0.0.0.0"
        );
        assert_eq!(
            sink.raised(),
            [rebind_alert("example.com"), rebind_alert("example.org")]
        );
    }

    #[tokio::test]
    async fn every_private_range_is_answered_with_zeros_whatever_its_family() {
        for text in [
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.168.1.1",
            "10.255.0.1",
        ] {
            let (dns, addr, up) = one(Reply::Answer(ip(text))).await;
            let sink = screening(&dns, &[]);
            for _ in 0..2 {
                let answer = ask_udp(addr, "example.com").await.unwrap();
                assert_eq!(answer.summary(), "NOERROR 0.0.0.0", "{text}");
            }
            assert_eq!((up.udp_queries(), sink.raised().len()), (1, 1), "{text}");
        }
        for text in ["fd00::1", "fe80::1", "::1", "::ffff:10.0.0.1", "fc00::8"] {
            let (dns, addr, up) = one(Reply::AnswerV6(text.parse().unwrap())).await;
            let sink = screening(&dns, &[]);
            for _ in 0..2 {
                let answer = ask_udp_aaaa(addr, "example.com").await.unwrap();
                assert_eq!(answer.addrs, [IpAddr::V6(Ipv6Addr::UNSPECIFIED)], "{text}");
            }
            assert_eq!((up.udp_queries(), sink.raised().len()), (1, 1), "{text}");
        }
        // A public address of the other family passes.
        let (dns, addr, _up) = one(Reply::AnswerV6("2001:db8::1".parse().unwrap())).await;
        let sink = screening(&dns, &[]);
        let answer = ask_udp_aaaa(addr, "example.com").await.unwrap();
        assert_eq!(answer.addrs, ["2001:db8::1".parse::<IpAddr>().unwrap()]);
        assert!(sink.raised().is_empty());
    }

    #[tokio::test]
    async fn an_allowed_name_and_a_local_name_may_answer_a_private_address() {
        let (dns, addr, up) = one(Reply::Answer(ip("10.0.0.1"))).await;
        let sink = screening(&dns, &["Router.Example.org."]);
        for name in [
            "router.example.org",
            "nas.router.example.org",
            "printer.lan",
            "host.local",
            "tv.home.arpa",
        ] {
            let answer = ask_udp(addr, name).await.unwrap();
            assert_eq!(answer.v4(), [ip("10.0.0.1")], "{name}");
        }
        assert_eq!(up.udp_queries(), 5);
        assert!(sink.raised().is_empty());
        // The policy is live: a name that is neither is blocked, in the same service.
        let answer = ask_udp(addr, "attacker.example.com").await.unwrap();
        assert_eq!(answer.summary(), "NOERROR 0.0.0.0");
        assert_eq!(sink.raised(), [rebind_alert("attacker.example.com")]);
    }

    #[tokio::test]
    async fn with_no_watch_set_a_private_address_is_answered_as_it_is() {
        let (_dns, addr, _up) = one(Reply::Answer(ip("10.0.0.1"))).await;
        assert_eq!(
            ask_udp(addr, "example.com").await.unwrap().v4(),
            [ip("10.0.0.1")]
        );
    }

    #[tokio::test]
    async fn a_packet_the_resolver_does_not_take_raises_nothing() {
        // Only a copy under another ID, which holds a private address: the client gets SERVFAIL.
        let (dns, addr, _up) = one(Reply::WrongIdOnly(ip("10.0.0.1"))).await;
        let sink = screening(&dns, &[]);
        assert_eq!(
            ask_udp(addr, "example.com").await.unwrap().summary(),
            "SERVFAIL"
        );
        assert!(sink.raised().is_empty());

        // Forgeries of private addresses, under another ID and from another socket, before the
        // answer: the answer is the real one, and public.
        let (real, forged) = (ip("192.0.2.10"), ip("10.0.0.1"));
        let (dns, addr, _up) = one(Reply::Hostile { real, forged }).await;
        let sink = screening(&dns, &[]);
        assert_eq!(ask_udp(addr, "example.com").await.unwrap().v4(), [real]);
        assert!(sink.raised().is_empty());

        // An answer for another question is not taken, and raises nothing; the answer to this one
        // is, and raises one alert.
        let (dns, addr, _up) = one(Reply::OtherQuestionFirst(ip("10.0.0.1"))).await;
        let sink = screening(&dns, &[]);
        assert_eq!(
            ask_udp(addr, "example.com").await.unwrap().summary(),
            "NOERROR 0.0.0.0"
        );
        assert_eq!(sink.raised(), [rebind_alert("example.com")]);
    }
}
