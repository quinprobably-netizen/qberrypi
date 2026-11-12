//! One exchange with the upstream resolvers: the question goes over UDP to the preferred upstream
//! first, and to the others (at most [`MAX_RACED`] in all) only when the preferred one has not
//! answered within a hedge delay of about twice its usual latency (the smoothed figure that all the
//! exchanges share), or has failed or refused at once; without a figure for that latency, at the
//! start, every upstream is asked at once. The first good answer is taken, and TCP is used when
//! that answer is truncated. A refusal or a failure (SERVFAIL, NOTIMP, REFUSED) is not a good
//! answer while another upstream may still give one.
//!
//! A question that is still open [`RESEND_AFTER`] after it was first sent is sent once more on each
//! socket that waits for an answer, which recovers a question or an answer lost on the way, if
//! the upstream answers at all; it does nothing for one that is down, whose wait runs out as
//! before, and it comes only when the wait is longer than that.
//!
//! The hedge, the resend and the end of the wait are points on tokio's clock, counted from the
//! first send. A runtime that was held up past one of them does not catch up on all of them: the
//! point that comes late is still acted on if the wait is not over, the points it passed over are
//! left out, and nothing is sent after the end of the wait.
//!
//! Over TLS (RFC 7858), once [`Upstreams::start_tls`] has switched it on, the exchange is the same
//! race on the connections (`Conn`, in `dot`): the preferred upstream alone, the others after the
//! same hedge delay or at once when it fails or refuses, the same wait, no resend (TCP is reliable)
//! and no retry over TCP (a stream is not truncated). After it there is no way back to UDP, so that
//! blocking port 853 cannot make a question go out in the clear. Before it, which is before the
//! clock is set and a certificate can be checked, only the names of
//! [`Upstreams::with_clear_names`] go over UDP as above (the time servers', which the clock itself
//! needs): any other question waits for the switch within its own wait, is asked over TLS if the
//! switch comes, and fails with nothing sent if it does not, so that keeping the clock from being
//! set cannot make a question go out in the clear either. A connection closes a session
//! that is idle, and opens the next when a question comes: an exchange wakes every connection it
//! may ask, and one whose preferred connection has no session up asks the others at once, so that
//! the first session that is up answers. A question that finds a connection opening its session
//! waits for it, and one that was open on a session that the server ended is sent again on the
//! next; neither is a failure. A question that finds every connection down (in its backoff) waits
//! for one within its own wait, and is not failed for the want of one before that.
//!
//! Nothing here logs a name that is asked for: the only lines are about the upstreams.

use std::future::{Future, poll_fn};
use std::io::{self, ErrorKind};
use std::iter;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::ops::Range;
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use qb_dns::{Pending, Transport, UpstreamOutcome};
use rustix::net::RecvFlags;
use tokio::io::{AsyncReadExt, AsyncWriteExt, Interest, Ready};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::time::{Instant, Sleep, sleep_until, timeout};

use super::dot::{Conn, ConnCounts, ConnOptions, Link, TlsUpstream};
use super::listen::TCP_CLIENTS;
use crate::{status, sys};

/// The port of a DNS server.
pub const UPSTREAM_PORT: u16 = 53;
/// How long the upstreams have to answer over UDP, all of them together, from the first send.
pub const UDP_WAIT: Duration = Duration::from_secs(2);
/// How long a retry over TCP has, from the connect to the end of the answer.
pub const TCP_WAIT: Duration = Duration::from_secs(4);
/// The room for one datagram from an upstream.
pub const UDP_BUFFER: usize = 4096;
/// How many failures in a row make an upstream "not answering" (logged once).
pub const SILENT_AFTER: u32 = 3;
/// The most exchanges whose losing sockets are read at once, as many as the questions that can be
/// out with an upstream: [`MAX_FORWARDS`](super::MAX_FORWARDS). A loser that finds no room is
/// dropped unread.
pub const MAX_DRAINS: usize = super::MAX_FORWARDS;

/// The most upstreams that one question is sent to: the preferred one and the next three after
/// it, in the order they were given, and the same for the retry over TCP. The sockets of a
/// question are bounded by it, and so are the descriptors of the questions that are out together.
pub const MAX_RACED: usize = 4;

/// The hedge delay as a multiple of the smoothed latency: the other upstreams are asked too once
/// the preferred one has had the question that long. Nearly all the answers of a healthy upstream
/// come within twice their usual time, so a question costs the upstreams about one query, and a
/// slow answer is rescued soon after.
pub const HEDGE_FACTOR: f32 = 2.0;
/// The shortest hedge delay: an upstream that answers in a millisecond is not hedged on every
/// question for a little jitter.
pub const HEDGE_MIN: Duration = Duration::from_millis(20);
/// The longest hedge delay: a *silent* preferred upstream costs one question this much (a closed
/// port fails at once, and hedges at once), and then the one that answered is the preferred.
pub const HEDGE_MAX: Duration = Duration::from_millis(250);

/// How long after the first send a question that is still open is sent once more, on every socket
/// that waits for it. It leaves 1.3 s of the 2 s wait, and of the 2 s that the latency tool gives
/// a client, for the answer to the second datagram. It comes before the 1 s after which some stub
/// resolvers (Windows's) ask again themselves, and well before glibc's 5 s. A wait that is no
/// longer than this never resends.
pub const RESEND_AFTER: Duration = Duration::from_millis(700);
const _: () = assert!(
    HEDGE_MAX.as_millis() < RESEND_AFTER.as_millis(),
    "the hedges must have gone out before the resend"
);

/// The descriptors that the services can hold at once, at the worst: a socket for each upstream
/// of each question that is out, one for each upstream but the winner of those that are read on
/// after a race, two for each TCP client (its connection, and the retry for it), the status
/// server's clients, and 64 for the fixed ones (netlink, log, watchdog, the listeners) and room.
const DESCRIPTORS: usize = super::MAX_FORWARDS * MAX_RACED
    + MAX_DRAINS * (MAX_RACED - 1)
    + TCP_CLIENTS * 2
    + status::MAX_CLIENTS
    + 64;
/// The hard limit on open files that the kernel gives init, and `sys::raise_open_files` raises the
/// soft limit to. Past it a socket fails to open, and with it the questions and the accepts.
const HARD_OPEN_FILES: usize = 4096;
const _: () = assert!(
    DESCRIPTORS < HARD_OPEN_FILES,
    "the services could hold more descriptors than init may have open"
);

/// The bytes of a DNS header: nothing shorter is a message.
const HEADER_LEN: usize = 12;
/// The most rounds, an arming and a poll each, that one poll of a socket goes through before the
/// task gives the runtime back. A socket needs two at most (a stale readiness, then the wait); a
/// loop that did not end would hold the runtime.
const STALE_READINESS_LIMIT: usize = 4;
/// The most often that "no upstream answers" is logged.
const NO_UPSTREAM_LOG_EVERY: Duration = Duration::from_secs(60);
/// The most often that a line is logged about one upstream's health.
const HEALTH_LOG_EVERY: Duration = Duration::from_secs(60);

/// What an exchange gives each packet to: `qb-dns` decides if it answers the question.
type Take<'a> = dyn FnMut(&[u8], Transport) -> UpstreamOutcome + Send + 'a;

/// The upstream resolvers, which one is asked first, and how they are doing.
///
/// Many exchanges run at once on one value. The state sits behind a lock that is never held
/// across an `.await`, and is shared with the tasks that read the losing sockets.
pub struct Upstreams {
    shared: Arc<Shared>,
    udp_wait: Duration,
    tcp_wait: Duration,
    /// One permit for each exchange whose losing sockets are being read.
    drains: Arc<Semaphore>,
    /// The way to the upstreams over TLS, if there is one: see [`Upstreams::with_tls`].
    tls: Option<TlsSwitch>,
}

/// The TLS way to the upstreams: where it goes and how it is checked, and the connections once
/// [`Upstreams::start_tls`] has opened them. Until then only the names of `clear` are asked, over
/// UDP, and every other question waits for the switch.
struct TlsSwitch {
    /// The name that the certificates must be valid for, and the client side that checks them.
    upstream: TlsUpstream,
    /// Where each connection goes: the first [`MAX_RACED`] upstreams, at their TLS port.
    servers: Vec<SocketAddr>,
    /// The connections, one to each of `servers`, in the same order. Set once, by the first
    /// [`Upstreams::start_tls`]; a value that is set is never changed.
    conns: OnceLock<Vec<Conn>>,
    /// The waits of each connection: the standard ones, except in tests.
    options: ConnOptions,
    /// Whether [`Upstreams::start_tls`] has run: a question that may not go in the clear waits
    /// for `true` here.
    started: watch::Sender<bool>,
    /// The names that are asked over UDP before the switch, as [`Pending::name`] gives a name:
    /// lower case, no trailing dot. See [`Upstreams::with_clear_names`].
    clear: Vec<String>,
}

/// Whether the upstreams are asked over TLS, as [`Upstreams::tls`] says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsState {
    /// There is no TLS way to the upstreams: every question goes over UDP.
    Off,
    /// There is one and it has not been switched on, because the clock is not set and no
    /// certificate can be checked: only the names of [`Upstreams::with_clear_names`] are asked,
    /// over UDP, and every other question waits for the switch or fails.
    WaitingForClock,
    /// Every question goes over TLS.
    On {
        /// The connections that have a session up now. A connection whose session was closed for
        /// being idle has none until the next question.
        up: usize,
        /// What the connections counted since the switch, all of them together.
        counts: ConnCounts,
    },
}

/// What the exchanges and their drains share.
struct Shared {
    servers: Vec<SocketAddr>,
    state: Mutex<State>,
    /// The datagrams sent to the upstreams over UDP.
    sent: AtomicU64,
}

/// What the exchanges learn.
struct State {
    /// The index in `servers` of the upstream that is asked first.
    preferred: usize,
    /// Milliseconds from a query to its answer, smoothed.
    latency_ms: Option<f32>,
    /// Times an upstream gave no usable answer.
    failures: u64,
    /// How each of `servers` is answering.
    health: Vec<Health>,
    /// When "no upstream answers" was last logged.
    no_upstream_logged: Option<Instant>,
}

/// How one upstream is answering.
#[derive(Default)]
struct Health {
    /// Failures since the last answer.
    misses: u32,
    /// Times the exchange used an answer of this upstream, over UDP or TCP, since the start. A late
    /// answer that is read and dropped after a race was lost is not one.
    answered: u64,
    /// Times this upstream gave no usable answer, since the start: the share of
    /// [`State::failures`] that is its own.
    failed: u64,
    /// Milliseconds from a query to this upstream's own answer, smoothed over the samples of the
    /// answers that were used; `None` before the first. Not the one that the hedge goes by:
    /// that is [`State::latency_ms`], over all the upstreams.
    latency_ms: Option<f32>,
    /// When the log last said something about this upstream, and whether it said that it was
    /// silent. `None` while it has said nothing, which is as good as "answering".
    said: Option<(Instant, bool)>,
}

/// A change in how an upstream is answering, which is logged.
#[derive(Debug, PartialEq, Eq)]
enum Change {
    /// It has failed [`SILENT_AFTER`] times in a row.
    Silent,
    /// It answered after it had gone silent.
    Answers,
}

/// Notes at `now` that an upstream answered, or did not, and what the log is to say about it, if
/// anything.
///
/// The state always changes; only the line is held back. The log says what it last said until
/// [`HEALTH_LOG_EVERY`] has passed since then, and the first note after that says what is the
/// case now, if that is not what the log last said. So an upstream that answers some of the time
/// costs a line a minute at most, and the last line never stays wrong for good.
fn note(health: &mut Health, answered: bool, now: Instant) -> Option<Change> {
    health.misses = if answered {
        0
    } else {
        health.misses.saturating_add(1)
    };
    let silent = health.misses >= SILENT_AFTER;
    let (said_at, said_silent) = match health.said {
        Some((at, silent)) => (Some(at), silent),
        None => (None, false),
    };
    let held_back = said_at.is_some_and(|at| now.duration_since(at) < HEALTH_LOG_EVERY);
    if silent == said_silent || held_back {
        return None;
    }
    health.said = Some((now, silent));
    Some(if silent {
        Change::Silent
    } else {
        Change::Answers
    })
}

/// One upstream's figures since the start: what the status page and the API show of it.
#[derive(Debug, Clone, PartialEq)]
pub struct ServerStats {
    /// The upstream's address and port.
    pub addr: SocketAddr,
    /// The answers of it that the exchanges used, over UDP or TCP. A late answer that was read and
    /// dropped after another upstream won is not counted.
    pub answered: u64,
    /// The times it gave no usable answer: the same events as [`Upstreams::failures`] counts, for
    /// this upstream alone.
    pub failed: u64,
    /// Its own smoothed round trip in milliseconds, from the answers that were used and whose time
    /// is known; `None` before the first. After a resend, or for the retry over TCP of another
    /// upstream's truncated answer, the time is not known and there is no sample.
    pub latency_ms: Option<f32>,
}

/// One upstream's socket, while its answer is waited for.
struct Leg {
    /// The index of the upstream in `servers`.
    index: usize,
    /// The ID its query went out under.
    id: u16,
    /// The datagram that went out, for the resend.
    query: Vec<u8>,
    /// When it went out: the answer's time is counted from here.
    sent: Instant,
    /// Connected to its upstream: the kernel drops what any other source sends to it. Shared with
    /// `armed`, so that the resend can use it while the leg is being waited on.
    socket: Arc<UdpSocket>,
    /// Waits until a datagram or an error is there. `None` while the socket is not waited on.
    armed: Option<Armed>,
}

/// What a [`Leg`] waits on until its socket has a datagram or an error.
type Armed = Pin<Box<dyn Future<Output = io::Result<Ready>> + Send>>;

// What the race below relies on in tokio 1.54.1, which no type checks:
// - readiness that is only ERROR (the ICMP message of a refused port) does not wake `poll_recv`,
//   so a leg waits on `ready` for READABLE and ERROR together;
// - `try_io` spends none of the task's coop budget, so `Legs::next` spends it itself with
//   `consume_budget`, which, once the budget is out, yields by deferring the wake-up;
// - the resend is a `try_send`, which tries the system call only while the WRITABLE readiness is
//   set, and relies on the first `send().await` having left it set (the send did not block, so it
//   is not cleared); if it were not, every resend would take the `WouldBlock` skip and send
//   nothing, with no error.
// On any upgrade of tokio, run `refused_ports_fail_at_once`,
// `a_dead_preferred_is_hedged_at_once_and_not_at_the_delay`,
// `a_flooding_upstream_neither_starves_the_others_nor_outlasts_the_wait`,
// `a_flooding_preferred_does_not_keep_the_hedge_from_going`, `a_flood_alone_ends_with_the_wait`,
// `a_question_that_was_lost_is_sent_again_at_the_resend_point` and
// `a_socket_that_cannot_be_sent_on_fails_its_resend_and_the_others_go_on` again.

/// Waits until `socket` has a datagram, or an error: the ICMP message that a refused port sends
/// back is one, and it wakes nothing that waits for a datagram alone.
async fn readiness(socket: Arc<UdpSocket>) -> io::Result<Ready> {
    socket.ready(Interest::READABLE | Interest::ERROR).await
}

/// One datagram from `socket` into `buf`, or the error that it holds, as `ready` says it is ready
/// for. `WouldBlock` if there is neither: the readiness was stale, and is cleared.
fn receive(socket: &UdpSocket, ready: Ready, buf: &mut [u8]) -> io::Result<usize> {
    // One interest at a time: tokio takes no readiness from a pair. Readiness that is nothing but
    // READ_CLOSED does not come to a UDP socket that is never shut down, and READABLE's mask
    // holds it all the same.
    let interest = if ready.is_error() {
        Interest::ERROR
    } else {
        Interest::READABLE
    };
    socket.try_io(interest, || {
        let (len, _) = rustix::net::recv(socket, buf, RecvFlags::empty())?;
        Ok(len)
    })
}

impl Leg {
    /// A leg for the upstream at `index`, whose `query` went out on `socket` under `id` at `sent`.
    fn new(index: usize, id: u16, query: Vec<u8>, sent: Instant, socket: UdpSocket) -> Self {
        Self {
            index,
            id,
            query,
            sent,
            socket: Arc::new(socket),
            armed: None,
        }
    }

    /// The length of the datagram that came into `buf`, or the error of the socket, which is no
    /// use after it. `Pending` until one of them is there.
    ///
    /// A socket that was read from is read again before it is waited on: a datagram that is
    /// already there costs no allocation, and one that is not clears the stale readiness.
    fn poll(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        for _ in 0..STALE_READINESS_LIMIT {
            let mut armed: Armed = match self.armed.take() {
                None => match receive(&self.socket, Ready::READABLE, buf) {
                    Ok(len) => return Poll::Ready(Ok(len)),
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        Box::pin(readiness(self.socket.clone()))
                    }
                    Err(error) => return Poll::Ready(Err(error)),
                },
                Some(armed) => armed,
            };
            let ready = match armed.as_mut().poll(cx) {
                Poll::Pending => {
                    self.armed = Some(armed);
                    return Poll::Pending;
                }
                Poll::Ready(ready) => ready,
            };
            match ready.and_then(|ready| receive(&self.socket, ready, buf)) {
                Ok(len) => return Poll::Ready(Ok(len)),
                // The readiness was no more: read again, and wait.
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// The sockets that are waited for, and the one buffer they receive into.
struct Legs {
    /// In the order the queries were sent.
    live: Vec<Leg>,
    buf: Vec<u8>,
    /// Where the next look at the sockets starts, modulo their number: after a packet, at the
    /// socket after its, so that one that is always ready does not keep the others from a turn.
    first: usize,
}

/// What became of the question that was sent once more on a leg's socket.
#[derive(Debug, PartialEq, Eq)]
enum Resend {
    /// The datagram went out.
    Sent,
    /// The socket would block: nothing went out, and the leg is as good as it was.
    Blocked,
    /// The socket cannot be sent on: the leg is no good.
    Failed,
}

/// What happens to the live sockets.
enum Event {
    /// The packet of `buf[..len]` came to the socket at that position.
    Packet(usize, usize),
    /// The socket at that position failed.
    Failed(usize),
    /// The clock ran out: the point of the phase that the race is in ([`Phase`]).
    Timer,
}

impl Legs {
    /// The next thing that happens to a live socket, or to the clock `timer`.
    async fn next(&mut self, timer: &mut Pin<&mut Sleep>) -> Event {
        // Waiting for readiness spends none of the task's budget: this gives the runtime back if
        // an upstream sends packets that are dropped faster than other tasks get their turn.
        tokio::task::consume_budget().await;
        poll_fn(|cx| {
            // The time first: a socket that always has something must not keep it from running out.
            if timer.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Event::Timer);
            }
            let count = self.live.len();
            for step in 0..count {
                let position = (self.first + step) % count;
                match self.live[position].poll(cx, &mut self.buf) {
                    Poll::Ready(Ok(len)) => {
                        self.first = position + 1;
                        return Poll::Ready(Event::Packet(position, len));
                    }
                    Poll::Ready(Err(_)) => return Poll::Ready(Event::Failed(position)),
                    Poll::Pending => {}
                }
            }
            Poll::Pending
        })
        .await
    }

    /// Counts every socket that is left as a failure: its time is up.
    fn expire(&mut self, shared: &Shared) {
        for leg in self.live.drain(..) {
            shared.note(leg.index, false);
        }
    }

    /// Sends the question again on each of the first `count` live sockets, the datagram that went
    /// out before, and drops, as a failure, one that it cannot be sent on. A socket that would
    /// block (`WouldBlock`: its buffer is full, which one datagram does not make it) has had the
    /// question once already, and stays and waits without a second send. Whether any datagram
    /// went out.
    fn resend(&mut self, shared: &Shared, count: usize) -> bool {
        let mut position = 0;
        let mut went_out = false;
        for _ in 0..count {
            match shared.resend(&self.live[position]) {
                Resend::Sent => {
                    went_out = true;
                    position += 1;
                }
                Resend::Blocked => position += 1,
                Resend::Failed => {
                    // The next one comes to this place.
                    let leg = self.live.remove(position);
                    shared.note(leg.index, false);
                }
            }
        }
        went_out
    }
}

/// How the race of the sockets ended.
enum Race {
    /// The upstream at that index gave this outcome, and the question was answered in that time
    /// from its send ([`Round::sample`]).
    Won(usize, Option<Duration>, UpstreamOutcome),
    /// The upstream at that index answered with a truncated message, and the datagram's own round
    /// trip, from its send to its arrival, was that ([`Round::sample`]): the sample of the latency
    /// for the retry over TCP, whose own time is not the upstream's usual latency.
    Truncated(usize, Option<Duration>),
    /// Nothing better than a refusal came: this is what the first refusal made. It is no
    /// upstream's answer time and no preference.
    Fallback(UpstreamOutcome),
    /// No answer: every socket failed, or the time ran out.
    Lost,
}

/// One upstream's connection, while its answer is waited for over TLS.
struct TlsLeg {
    /// The index of the upstream in `servers`, and of its connection.
    index: usize,
    /// When the question was asked: the answer's time is counted from here.
    sent: Instant,
    /// Whether its connection had no session up when it was asked: its answer waits for a
    /// handshake, and its time is not the upstream's.
    cold: bool,
    /// The answer, or why there is none. The question is queued already: this is only waited on.
    answer: Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send>>,
}

impl TlsLeg {
    /// Asks `query` on the connection `conns[index]`, now.
    fn ask(conns: &[Conn], index: usize, query: &[u8]) -> Self {
        Self {
            index,
            sent: Instant::now(),
            cold: !conns[index].is_up(),
            answer: Box::pin(conns[index].ask(query.to_vec())),
        }
    }
}

/// How a leg ended: its upstream's index, when it was asked, whether it was cold, and what it
/// gave.
type LegEnd = (usize, Instant, bool, io::Result<Vec<u8>>);

/// The next of `legs` to end. The leg is taken out of `legs` when it is ready and not before, so a
/// dropped call loses nothing.
async fn next_leg(legs: &mut Vec<TlsLeg>) -> LegEnd {
    poll_fn(|cx| {
        let ready = legs.iter_mut().enumerate().find_map(|(position, leg)| {
            match leg.answer.as_mut().poll(cx) {
                Poll::Ready(result) => Some((position, result)),
                Poll::Pending => None,
            }
        });
        match ready {
            Some((position, result)) => {
                let leg = legs.remove(position);
                Poll::Ready((leg.index, leg.sent, leg.cold, result))
            }
            None => Poll::Pending,
        }
    })
    .await
}

/// Ready when any of `conns` can be asked (is not down), which it may be at once. Never ready for
/// no connection at all.
async fn any_askable(conns: &[Conn]) {
    let mut waits: Vec<Pin<Box<dyn Future<Output = ()> + Send>>> = conns
        .iter()
        .map(|conn| Box::pin(conn.wait_askable()) as Pin<Box<dyn Future<Output = ()> + Send>>)
        .collect();
    poll_fn(|cx| {
        if waits
            .iter_mut()
            .any(|wait| wait.as_mut().poll(cx).is_ready())
        {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
}

/// The most rounds that an exchange over TLS makes for one question: the first, and a new one each
/// time every connection that was asked was down, or failed it for want of a session. It bounds
/// the work of a question; the end of the wait bounds the time.
const TLS_ROUNDS: usize = 3;

/// How a round of an exchange over TLS ended.
enum TlsRound {
    /// An answer ended the exchange.
    Done(UpstreamOutcome),
    /// No leg is left, or the wait is over.
    Over {
        /// Whether every leg of the round failed for want of a session (its connection was down
        /// when asked, or no session could be opened for it, or the one it was sent again on
        /// ended), and nothing else went wrong: a round that is worth making again once a
        /// connection can be asked.
        down: bool,
    },
}

/// A question that is being asked over the TLS connections, from one round to the next.
struct TlsAsk<'a> {
    shared: &'a Shared,
    /// One connection to each of the first upstreams, in the order of the upstreams.
    conns: &'a [Conn],
    /// The whole message, under an ID that each connection replaces.
    query: Vec<u8>,
    /// The connection that is asked first, which is the upstream that answered last.
    preferred: usize,
    /// How long the others are held back for, if they are.
    hedge: Option<Duration>,
    /// When the wait is up: nothing is asked after it.
    deadline: Instant,
    /// The first refusal that was set aside, which is all there is if nothing better comes.
    fallback: Option<Vec<u8>>,
    /// The upstreams, by index, that were counted as failures of this question: each is counted
    /// once, however many rounds it fails.
    failed: u64,
}

impl TlsAsk<'_> {
    /// Counts the upstream at `index` as a failure of this question, unless it was already.
    fn fail(&mut self, index: usize) {
        let bit = 1u64 << (index % 64);
        if self.failed & bit == 0 {
            self.failed |= bit;
            self.shared.note(index, false);
        }
    }

    /// One round: the preferred connection is asked, and the others after the hedge delay (counted
    /// from now, and only if that is before the end of the wait) or at once when no leg is live,
    /// when the preferred one had no session up when it was asked, or when its session goes away
    /// while the hedges wait; then the legs are waited for. `deadline_timer` runs to the end of the
    /// wait.
    async fn round(
        &mut self,
        deadline_timer: &mut Pin<&mut Sleep>,
        take: &mut Take<'_>,
    ) -> TlsRound {
        let (shared, conns) = (self.shared, self.conns);
        let start = Instant::now();
        let mut unsent = asked(self.preferred, conns.len()).peekable();
        let mut legs: Vec<TlsLeg> = Vec::with_capacity(MAX_RACED);
        let first = unsent.next();
        if let Some(first) = first {
            legs.push(TlsLeg::ask(conns, first, &self.query));
        }
        let cold = legs.first().is_some_and(|leg| leg.cold);
        let left = self.deadline.saturating_duration_since(start);
        // A delay that the wait does not outlast would never come: nothing is held back then. Nor
        // is anything held back for a preferred one that must open a session first.
        let hedge = self
            .hedge
            .filter(|&delay| delay < left && unsent.peek().is_some() && !cold);
        if hedge.is_none() {
            legs.extend(
                unsent
                    .by_ref()
                    .map(|index| TlsLeg::ask(conns, index, &self.query)),
            );
        }
        let mut hedge_due = hedge.is_some();
        let hedge_timer = sleep_until(start + hedge.unwrap_or(left));
        let mut hedge_timer = pin!(hedge_timer);
        let mut down = true;
        while !legs.is_empty() || unsent.peek().is_some() {
            if legs.is_empty() {
                // Nobody to wait for: the hedges go now, unless the wait is over.
                if Instant::now() >= self.deadline {
                    break;
                }
                legs.extend(
                    unsent
                        .by_ref()
                        .map(|index| TlsLeg::ask(conns, index, &self.query)),
                );
                hedge_due = false;
                continue;
            }
            tokio::select! {
                // The end of the wait first: a runtime that was held up does not send after it.
                biased;
                () = deadline_timer.as_mut() => {
                    let late: Vec<usize> = legs.drain(..).map(|leg| leg.index).collect();
                    for index in late {
                        self.fail(index);
                    }
                    down = false;
                    break;
                }
                () = hedge_timer.as_mut(), if hedge_due => {
                    hedge_due = false;
                    legs.extend(
                        unsent.by_ref().map(|index| TlsLeg::ask(conns, index, &self.query)),
                    );
                }
                // The preferred one's session went away (the server ended it, and its question
                // waits for the next): the others are asked now.
                () = conns[first.unwrap_or(0)].wait_not_up(), if hedge_due => {
                    hedge_due = false;
                    legs.extend(
                        unsent.by_ref().map(|index| TlsLeg::ask(conns, index, &self.query)),
                    );
                }
                (index, sent, cold, result) = next_leg(&mut legs) => {
                    let packet = match result {
                        Ok(packet) => packet,
                        Err(error) => {
                            self.fail(index);
                            down &= error.kind() == ErrorKind::NotConnected;
                            continue;
                        }
                    };
                    let others = !legs.is_empty() || unsent.peek().is_some();
                    if is_refusal(&packet) && (others || self.fallback.is_some()) {
                        down = false;
                        if asks_the_same(&self.query, &packet) {
                            shared.note(index, true);
                            self.fallback.get_or_insert(packet);
                        } else {
                            self.fail(index);
                        }
                        continue;
                    }
                    match take(&packet, Transport::Tcp) {
                        UpstreamOutcome::Mismatch | UpstreamOutcome::RetryOverTcp => {
                            down = false;
                            self.fail(index);
                        }
                        outcome => {
                            // A leg that waited for a handshake gives no sample: its time is not
                            // the upstream's.
                            shared.won(index, (!cold).then(|| sent.elapsed()));
                            return TlsRound::Done(outcome);
                        }
                    }
                }
            }
        }
        TlsRound::Over { down }
    }
}

/// The upstreams that a question has not been sent to yet, which are the hedges until they go:
/// the steps from the preferred upstream, in the order of [`order`], after the first.
struct Unsent {
    preferred: usize,
    count: usize,
    steps: Range<usize>,
}

impl Unsent {
    /// Every upstream that a question is sent to ([`asked`]) but the preferred one.
    fn new(preferred: usize, count: usize) -> Self {
        Self {
            preferred,
            count,
            steps: 1..count.min(MAX_RACED),
        }
    }

    fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Gives up the upstreams that are left: they are never sent the question.
    fn clear(&mut self) {
        self.steps = 0..0;
    }
}

impl Iterator for Unsent {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        let step = self.steps.next()?;
        Some((self.preferred + step) % self.count)
    }
}

/// What the one clock of a race is counting to, and so what it means when it runs out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// The hedge point: the upstreams that have not had the question yet get it now.
    Hedge,
    /// The resend point, [`RESEND_AFTER`] from the first send: the question goes out once more.
    Resend,
    /// The end of the wait: what is left is counted as failed.
    Deadline,
}

/// What the race needs besides its sockets and its clock.
struct Round<'a> {
    shared: &'a Shared,
    pending: &'a Pending,
    unsent: Unsent,
    /// When the first query went out.
    start: Instant,
    /// When the hedge point is. Only [`Phase::Hedge`] looks at it.
    hedge_at: Instant,
    /// When the wait over UDP is up, for every upstream together.
    deadline: Instant,
    phase: Phase,
    /// Whether the question was sent once more, so that an answer may be to either datagram.
    resent: bool,
}

impl<'a> Round<'a> {
    /// A round of a question that went out at `start` and that has `udp_wait` to be answered. With
    /// a `hedge` delay the unsent upstreams wait for it; without one, the caller sends them at
    /// once.
    fn new(
        shared: &'a Shared,
        pending: &'a Pending,
        unsent: Unsent,
        start: Instant,
        udp_wait: Duration,
        hedge: Option<Duration>,
    ) -> Self {
        let deadline = start + udp_wait;
        let mut round = Self {
            shared,
            pending,
            unsent,
            start,
            hedge_at: hedge.map_or(deadline, |delay| start + delay),
            deadline,
            phase: Phase::Hedge,
            resent: false,
        };
        if hedge.is_none() {
            round.phase = round.after_hedge();
        }
        round
    }

    /// When the clock runs out in the phase that the round is in.
    fn point(&self) -> Instant {
        match self.phase {
            Phase::Hedge => self.hedge_at,
            Phase::Resend => self.start + RESEND_AFTER,
            Phase::Deadline => self.deadline,
        }
    }

    /// The phase that follows the hedge point (or comes first without one): the resend point if
    /// it is before the deadline, and the deadline if not, as it is for a wait no longer than
    /// [`RESEND_AFTER`].
    fn after_hedge(&self) -> Phase {
        if self.start + RESEND_AFTER < self.deadline {
            Phase::Resend
        } else {
            Phase::Deadline
        }
    }

    /// The phase to go to once the hedge point has been dealt with at `now` ([`Round::after_hedge`]),
    /// or the one after that if the runtime was held up so long that the resend point is no longer
    /// ahead: a resend that is already late is not sent along with a hedge that has just gone.
    fn upcoming(&self, now: Instant) -> Phase {
        match self.after_hedge() {
            Phase::Resend if self.start + RESEND_AFTER <= now => Phase::Deadline,
            phase => phase,
        }
    }

    /// Moves to `phase`, and has the clock `timer` run to its point.
    fn go_to(&mut self, phase: Phase, timer: &mut Pin<&mut Sleep>) {
        self.phase = phase;
        timer.as_mut().reset(self.point());
    }

    /// The time that an answer taken now is a sample of the latency for, if it is one: from the
    /// send at `sent`. After the resend it is not known which datagram the answer is to (the
    /// time could be that of either), so there is none. This is the one place that says so.
    fn sample(&self, sent: Instant) -> Option<Duration> {
        (!self.resent).then(|| sent.elapsed())
    }

    /// Sends the question to every upstream that has not had it yet, each from a socket of its own
    /// under an ID of its own, and puts their legs on the end of `legs`. One that cannot be sent
    /// to is counted as a failure.
    async fn send_unsent(&mut self, legs: &mut Legs) {
        for index in self.unsent.by_ref() {
            let id = new_id();
            let query = self.pending.upstream_query(id);
            if let Some(leg) = self.shared.open(index, id, query, Instant::now()).await {
                legs.live.push(leg);
            }
        }
    }

    /// Sends the hedges, and has the clock `timer`, which was at the hedge point, run on to the
    /// next point that is still ahead.
    ///
    /// The runtime may have been held up, and the clock be past the points that this round counts
    /// to. Nothing is sent once the deadline has gone by: the hedges are given up (they were never
    /// asked, and are no failure), and the next look at the clock, which has run out, ends the
    /// race. Otherwise the hedges go, however late, and a resend point that is behind the clock
    /// as well is left out ([`Round::upcoming`]).
    async fn hedge(&mut self, legs: &mut Legs, timer: &mut Pin<&mut Sleep>) {
        debug_assert_eq!(self.phase, Phase::Hedge, "the hedges go in their own phase");
        if Instant::now() >= self.deadline {
            self.unsent.clear();
            self.go_to(Phase::Deadline, timer);
            return;
        }
        self.send_unsent(legs).await;
        self.go_to(self.upcoming(Instant::now()), timer);
    }

    /// Sends the question once more on every socket that is live and waits for it, and has the
    /// clock `timer` run to the deadline from now on. A socket that cannot be sent on fails. If
    /// the runtime was held up so long that the deadline has gone by, nothing is sent: the next
    /// look at the clock ends the race.
    ///
    /// No hedge is unsent here, so none is sent for the first time or resent: this phase comes only
    /// after the hedge point has been dealt with, which sends them all, or, when nothing is held
    /// back, after the caller sent them at the start ([`Round::new`]). That the hedge point is the
    /// earlier of the two is what the assertion on [`HEDGE_MAX`] keeps true.
    async fn resend(&mut self, legs: &mut Legs, timer: &mut Pin<&mut Sleep>) {
        debug_assert!(self.unsent.is_empty(), "the hedges have gone out by now");
        if Instant::now() < self.deadline {
            self.resent = legs.resend(self.shared, legs.live.len());
        }
        self.go_to(Phase::Deadline, timer);
    }
}

/// How long the preferred upstream is given before the others are asked too, for a smoothed
/// latency of `latency_ms`: [`HEDGE_FACTOR`] times it, between [`HEDGE_MIN`] and [`HEDGE_MAX`].
/// `None` without a figure: nothing is held back.
fn hedge_delay(latency_ms: Option<f32>) -> Option<Duration> {
    latency_ms.map(|ms| {
        // Microseconds, whole: a float that is not a time cannot panic, as the cast makes NaN and
        // negatives 0 and saturates the rest.
        let delay = Duration::from_micros((ms * HEDGE_FACTOR * 1000.0) as u64);
        delay.clamp(HEDGE_MIN, HEDGE_MAX)
    })
}

impl Upstreams {
    /// The servers on [`UPSTREAM_PORT`], with the standard waits; the first is asked first. A
    /// question goes to at most [`MAX_RACED`] of them, and more are warned about once. Panics if
    /// there is no server.
    pub fn new(servers: &[Ipv4Addr]) -> Self {
        let servers = servers
            .iter()
            .map(|&ip| SocketAddr::from((ip, UPSTREAM_PORT)))
            .collect();
        Self::with(servers, UDP_WAIT, TCP_WAIT)
    }

    /// The servers with their own waits; the first is asked first.
    ///
    /// The addresses are IPv4: nothing here opens an IPv6 socket. Panics if there is no server,
    /// or one that is not IPv4.
    pub fn with(servers: Vec<SocketAddr>, udp_wait: Duration, tcp_wait: Duration) -> Self {
        Self::with_drains(servers, udp_wait, tcp_wait, MAX_DRAINS)
    }

    /// [`Upstreams::with`], and at most `drains` exchanges' losing sockets read at once.
    pub(crate) fn with_drains(
        servers: Vec<SocketAddr>,
        udp_wait: Duration,
        tcp_wait: Duration,
        drains: usize,
    ) -> Self {
        assert!(!servers.is_empty(), "there must be an upstream to ask");
        assert!(
            servers.iter().all(SocketAddr::is_ipv4),
            "the upstreams must be IPv4"
        );
        if let Some(warning) = surplus_warning(servers.len()) {
            log::warn!("{warning}");
        }
        let health = servers.iter().map(|_| Health::default()).collect();
        Self {
            shared: Arc::new(Shared {
                servers,
                state: Mutex::new(State {
                    preferred: 0,
                    latency_ms: None,
                    failures: 0,
                    health,
                    no_upstream_logged: None,
                }),
                sent: AtomicU64::new(0),
            }),
            udp_wait,
            tcp_wait,
            drains: Arc::new(Semaphore::new(drains)),
            tls: None,
        }
    }

    /// These upstreams, given a way over TLS: their addresses at `port`, to be checked as `tls`
    /// says. Nothing is opened until [`Upstreams::start_tls`], and until then no question goes out
    /// but those for the names of [`Upstreams::with_clear_names`]. Only the first [`MAX_RACED`]
    /// upstreams get a connection.
    pub fn with_tls(self, tls: TlsUpstream, port: u16) -> Self {
        let servers = self
            .shared
            .servers
            .iter()
            .map(|server| SocketAddr::new(server.ip(), port))
            .collect();
        self.with_tls_at(tls, servers)
    }

    /// [`Upstreams::with_tls`], with the address of each upstream's TLS service spelt out, in the
    /// order of the upstreams (the first [`MAX_RACED`] are used). For tests, whose upstreams all
    /// share one address and differ by port.
    pub(crate) fn with_tls_at(mut self, tls: TlsUpstream, mut servers: Vec<SocketAddr>) -> Self {
        servers.truncate(MAX_RACED);
        self.tls = Some(TlsSwitch {
            upstream: tls,
            servers,
            conns: OnceLock::new(),
            options: ConnOptions::default(),
            started: watch::Sender::new(false),
            clear: Vec::new(),
        });
        self
    }

    /// These upstreams, with `names` as the only ones that are asked over UDP before
    /// [`Upstreams::start_tls`]: the time servers' names, which the clock needs before any
    /// certificate can be checked, and which say nothing of what a client asks for. A no-op
    /// without a way over TLS.
    pub fn with_clear_names(mut self, names: impl IntoIterator<Item = String>) -> Self {
        if let Some(tls) = &mut self.tls {
            tls.clear = names
                .into_iter()
                .map(|name| name.trim_end_matches('.').to_ascii_lowercase())
                .collect();
        }
        self
    }

    /// These upstreams, with the connections that [`Upstreams::start_tls`] opens given `options`
    /// instead of the standard waits. A no-op without a way over TLS. For tests, which shorten the
    /// waits of a connection.
    #[cfg(test)]
    pub(crate) fn with_conn_options(mut self, options: ConnOptions) -> Self {
        if let Some(tls) = &mut self.tls {
            tls.options = options;
        }
        self
    }

    /// Opens a connection to each upstream, and every exchange that starts from now on goes over
    /// them: call it once the clock is set, which a certificate check needs. A no-op without
    /// [`Upstreams::with_tls`], and when it was called before, so that no second set of
    /// connections is ever opened. Logs `upstreams over TLS from now on` once. It does not wait for
    /// a session: a question to a connection that is opening its session waits for it, and the
    /// exchange asks the other upstreams at once (see `Conn::ask` and [`Upstreams::exchange`]).
    ///
    /// Panics outside a runtime: each connection is a task on it.
    pub fn start_tls(&self) {
        let Some(tls) = &self.tls else {
            return;
        };
        let mut opened = false;
        tls.conns.get_or_init(|| {
            opened = true;
            tls.servers
                .iter()
                .map(|&server| Conn::spawn(server, tls.upstream.clone(), tls.options.clone()))
                .collect()
        });
        if opened {
            tls.started.send_replace(true);
            log::info!("dns: upstreams over TLS from now on");
        }
    }

    /// Whether the upstreams are asked over TLS, and how the connections are doing.
    pub fn tls(&self) -> TlsState {
        match self.tls.as_ref().map(|tls| tls.conns.get()) {
            None => TlsState::Off,
            Some(None) => TlsState::WaitingForClock,
            Some(Some(conns)) => TlsState::On {
                up: conns.iter().filter(|conn| conn.is_up()).count(),
                counts: conns
                    .iter()
                    .map(Conn::counts)
                    .fold(ConnCounts::default(), |all, one| ConnCounts {
                        connects: all.connects + one.connects,
                        resumed: all.resumed + one.resumed,
                        asked: all.asked + one.asked,
                        idle_closes: all.idle_closes + one.idle_closes,
                        server_closes: all.server_closes + one.server_closes,
                        retried: all.retried + one.retried,
                    }),
            },
        }
    }

    /// The connections, if [`Upstreams::start_tls`] has opened them.
    fn started_tls(&self) -> Option<&[Conn]> {
        self.tls.as_ref()?.conns.get().map(Vec::as_slice)
    }

    /// Asks the preferred upstream, then the others if it is slow or fails, and takes the first
    /// good answer: the preferred one and the next ones after it in the order they were given,
    /// [`MAX_RACED`] of them at most.
    ///
    /// Each upstream gets the query over UDP from a socket of its own, under an ID of its own. The
    /// preferred one gets it first; the others (the hedges) after the hedge delay, which is twice
    /// the smoothed latency, between [`HEDGE_MIN`] and [`HEDGE_MAX`], or at once when the
    /// preferred one cannot be sent to, its socket fails (the ICMP refusal of a closed port is
    /// that), or it answers with a refusal. An upstream that is never sent the question is not
    /// counted, good or bad. A packet that is not under the preferred upstream's ID, is shorter
    /// than a header, or that `take` calls a `Mismatch`, hedges nothing: whoever can send those
    /// must not be able to double the queries. Before the first answer there is no latency to go
    /// by, and every upstream gets the query at once; and so it is with a delay that the wait
    /// does not outlast, which would never come: nothing is held back then.
    ///
    /// A question that is still open [`RESEND_AFTER`] after the first send, with no winner and no
    /// truncated answer, is sent once more: the same datagram under the same ID, on the socket of
    /// every upstream that was asked and is still waited for. An answer to the first send that
    /// comes late is as good as one to the second. It happens once per exchange, only if that
    /// point is before the end of the wait (so never for a wait no longer than [`RESEND_AFTER`]),
    /// and never for the sockets that are read on after the race. A socket that cannot be sent on
    /// is a failure. An answer taken after the resend gives no latency sample, as it is not known
    /// which datagram it answers; its upstream still becomes the preferred one and counts as
    /// answered.
    ///
    /// The kernel drops what another source sends to those sockets, and only a packet that
    /// carries the ID of its upstream reaches `take`. `take` says what the packet is: the race goes
    /// on after a `Mismatch`, the same question is asked over TCP after a `RetryOverTcp` (the
    /// hedges are never sent if that comes before the hedge delay), and a `Reply` or `Refreshed`
    /// ends the exchange. The upstream that gave it is asked first from then on, and the time
    /// from its own send to its answer is the sample of the latency (after a `RetryOverTcp`, the
    /// round trip of the truncated datagram itself, from its send to its arrival, and not the time
    /// of the retry over TCP, which is not what that upstream usually takes): a hedge that wins is
    /// not counted from the start of the question.
    ///
    /// A packet whose response code is SERVFAIL, NOTIMP or REFUSED is not given to `take` while
    /// another upstream may still answer, or hedges are still unsent (they go at once): its
    /// upstream is set aside (it did answer, and counts as one), and the first such packet is
    /// kept. That holds only if the packet carries the question of that upstream's query (the
    /// name but for the case of its letters, the type and the class); a failure for another
    /// question is ignored like a `Mismatch`, and hedges nothing. When no upstream is left in the
    /// race, or the time is up, that packet goes to `take` and what `take` makes of it ends the
    /// exchange, without a latency sample or a new preferred upstream.
    ///
    /// The upstreams have [`Upstreams::with`]'s `udp_wait` together, from the first send; the
    /// hedges and the resend do not make it longer. Those that lose the race are read on in a
    /// task of their own, which gives nothing to `take`, so that a slow upstream is not counted
    /// as a failure for being slow. After a truncated answer the upstreams are asked over TCP in
    /// turn, that one first.
    ///
    /// An upstream that gives no usable answer, or whose socket fails, is counted in
    /// [`Upstreams::failures`]. `None` once every one has failed, and at once, with nothing sent,
    /// if the question cannot be encoded.
    ///
    /// Once [`Upstreams::start_tls`] has run, the question goes over the TLS connections instead,
    /// as the exchange over TLS says (see the module documentation), and the rest of this is not
    /// used. With a way over TLS that is not switched on yet, a question for any name but those of
    /// [`Upstreams::with_clear_names`] waits for the switch, for `udp_wait` at most, and is then
    /// asked over TLS; `None`, with nothing sent and nothing counted, if the switch does not come.
    pub async fn exchange(
        &self,
        pending: &Pending,
        take: &mut (dyn FnMut(&[u8], Transport) -> UpstreamOutcome + Send),
    ) -> Option<UpstreamOutcome> {
        if let Some(conns) = self.started_tls() {
            return self.exchange_tls(conns, pending, take).await;
        }
        if let Some(tls) = &self.tls
            && !tls.clear.iter().any(|name| name == pending.name())
        {
            let mut started = tls.started.subscribe();
            let switched = timeout(self.udp_wait, started.wait_for(|&on| on))
                .await
                .is_ok_and(|on| on.is_ok());
            if !switched {
                return None;
            }
            let conns = self.started_tls()?;
            return self.exchange_tls(conns, pending, take).await;
        }
        let shared = &*self.shared;
        let (preferred, hedge) = {
            let state = shared.state();
            (state.preferred, hedge_delay(state.latency_ms))
        };
        let count = shared.servers.len();
        let id = new_id();
        let query = pending.upstream_query(id);
        if query.is_empty() {
            return None;
        }
        let start = Instant::now();
        let unsent = Unsent::new(preferred, count);
        // A delay that the wait does not outlast would never come: nothing is held back then.
        let hedge = hedge.filter(|&delay| delay < self.udp_wait && !unsent.is_empty());
        let mut round = Round::new(shared, pending, unsent, start, self.udp_wait, hedge);
        let deadline = round.deadline;
        let mut legs = Legs {
            live: Vec::with_capacity(count.min(MAX_RACED)),
            buf: vec![0u8; UDP_BUFFER],
            first: 0,
        };
        if let Some(leg) = shared.open(preferred, id, query, start).await {
            legs.live.push(leg);
        }
        if hedge.is_none() {
            round.send_unsent(&mut legs).await;
        }
        let race = {
            let mut timer = pin!(sleep_until(round.point()));
            race(&mut round, &mut legs, &mut timer, take).await
        };
        let (index, sample, outcome) = match race {
            Race::Won(index, sample, outcome) => {
                self.drain(legs, deadline);
                (index, sample, outcome)
            }
            Race::Truncated(first, sample) => {
                self.drain(legs, deadline);
                match self.ask_tcp_in_turn(first, preferred, pending, take).await {
                    // The round trip is `first`'s: it is no sample for another upstream.
                    Some((index, outcome)) => (index, sample.filter(|_| index == first), outcome),
                    None => return self.none_answers(),
                }
            }
            // The sockets are all out of the race by now: every one failed, was set aside, or ran
            // out of time, and there is nothing to read on. The refusal is no upstream's answer
            // time, and no reason to ask that upstream first.
            Race::Fallback(outcome) => return Some(outcome),
            Race::Lost => return self.none_answers(),
        };
        shared.won(index, sample);
        Some(outcome)
    }

    /// The exchange over the TLS connections `conns`, one to each of the first upstreams.
    ///
    /// Every connection that may be asked is woken first ([`Conn::wake`]): one that closed its
    /// idle session opens one now. The preferred upstream is asked alone, and the others (the
    /// hedges) after the hedge delay ([`hedge_delay`]) or at once when no leg is left (the
    /// preferred one cannot be asked, as its connection is down or its queue is full, or it failed
    /// or refused), when the preferred connection had no session up when it was asked (its
    /// question waits for a handshake), or when its session goes away while the hedges wait (the
    /// server ended it, and its question waits to be sent again). Without a latency figure every
    /// upstream is asked at once. The wait is `udp_wait` in all, from the start, and nothing is
    /// asked after its end. There is no resend, as TCP loses nothing, and no retry over TCP.
    ///
    /// A question does not give up for want of a session. A connection that is opening a session
    /// holds the question until it is up; one that is down fails it at once. The exchange that
    /// finds every connection down waits for one that is not, within its own wait, and then asks
    /// as above. A round in which every leg that failed did so for want of a session, with no
    /// answer to go by, is made again in the same way, at most [`TLS_ROUNDS`] times in all. The
    /// wait ends, and the question with it, at the end of the wait; there is no way back to UDP.
    ///
    /// An upstream is counted as a failure of the question once at most, however many of its legs
    /// fail. A leg that ends in an error is a failure of its upstream. A refusal ([`is_refusal`]) for
    /// this question is set aside while another leg is live or unasked, or after an earlier one was
    /// kept, as the UDP race does, and the first is kept as the fallback; a refusal for another
    /// question is a failure. Any other answer goes to `take`, with [`Transport::Tcp`]: a `Reply`
    /// or `Refreshed` ends the exchange, and that upstream is the preferred one from then on, with
    /// the time from its own ask as the sample of the latency (none for a leg that waited for a
    /// handshake, whose time is not the upstream's); a `Mismatch` is a failure of the leg.
    /// When no leg is left or the time is up, what is still open counts as failed, and the
    /// fallback, if there is one, goes to `take`; without one the result is `None`. An upstream
    /// that had no session to the end of the wait is a failure too.
    ///
    /// The legs that lose are dropped, not counted: their answers are read and dropped by their
    /// connections, which close a session that a question has waited on for too long
    /// ([`STALL_AFTER`](super::dot::STALL_AFTER)).
    async fn exchange_tls(
        &self,
        conns: &[Conn],
        pending: &Pending,
        take: &mut Take<'_>,
    ) -> Option<UpstreamOutcome> {
        let shared = &*self.shared;
        let count = conns.len();
        let (preferred, hedge) = {
            let state = shared.state();
            // A preferred upstream that has no connection (more upstreams than a question is sent
            // to) was the preferred one over UDP: the first is asked first then.
            let preferred = if state.preferred < count {
                state.preferred
            } else {
                0
            };
            (preferred, hedge_delay(state.latency_ms))
        };
        // The ID is the connection's to choose: it gives the answer back under this one.
        let query = pending.upstream_query(0);
        if query.is_empty() {
            return None;
        }
        let deadline = Instant::now() + self.udp_wait;
        let deadline_timer = sleep_until(deadline);
        let mut deadline_timer = pin!(deadline_timer);
        // A connection that closed its idle session opens one now: the question may be hedged to
        // it, and the next questions find it up.
        for index in asked(preferred, count) {
            conns[index].wake();
        }
        let mut ask = TlsAsk {
            shared,
            conns,
            query,
            preferred,
            hedge,
            deadline,
            fallback: None,
            failed: 0,
        };
        for _ in 0..TLS_ROUNDS {
            if conns.iter().all(|conn| conn.link() == Link::Down) {
                // The wait for a connection that can be asked, which the end of the wait cuts
                // short: the upstreams that never had one are failures.
                tokio::select! {
                    biased;
                    () = deadline_timer.as_mut() => {
                        for index in asked(preferred, count) {
                            ask.fail(index);
                        }
                        break;
                    }
                    () = any_askable(conns) => {}
                }
            }
            match ask.round(&mut deadline_timer, take).await {
                TlsRound::Done(outcome) => return Some(outcome),
                // Every connection was down or had no session for it: another round, if there is
                // time and nothing to fall back to.
                TlsRound::Over { down: true }
                    if ask.fallback.is_none() && Instant::now() < deadline => {}
                TlsRound::Over { .. } => break,
            }
        }
        // Whatever is left is no better than the refusal that was set aside, if there was one.
        let outcome = ask.fallback.map(|packet| take(&packet, Transport::Tcp));
        match outcome {
            Some(UpstreamOutcome::Mismatch | UpstreamOutcome::RetryOverTcp) | None => {
                self.none_answers()
            }
            outcome => outcome,
        }
    }

    /// How many datagrams have been sent to the upstreams over UDP since the start: every query
    /// that went out, the hedges and the resends too. The tests count by it; the statistics show
    /// [`Upstreams::queries`], which counts the questions over TLS too.
    pub fn sent(&self) -> u64 {
        self.shared.sent.load(Ordering::Relaxed)
    }

    /// How many questions have gone to the upstreams since the start: the datagrams of
    /// [`Upstreams::sent`], and the questions written to the TLS sessions (one that is sent again
    /// on a new session counts again). The statistics show it as the upstream queries.
    pub fn queries(&self) -> u64 {
        let tls = match self.tls() {
            TlsState::On { counts, .. } => counts.asked,
            TlsState::Off | TlsState::WaitingForClock => 0,
        };
        self.sent() + tls
    }

    /// Milliseconds from a query to its answer, smoothed; `None` before the first answer.
    pub fn latency_ms(&self) -> Option<u16> {
        self.shared.state().latency_ms.map(|ms| ms.round() as u16)
    }

    /// How many times an upstream has given no usable answer.
    pub fn failures(&self) -> u64 {
        self.shared.state().failures
    }

    /// The figures of each upstream since the start, in the order they were given: the answers the
    /// exchanges used, the times it gave none, and its own smoothed round trip. Takes the lock
    /// once, and copies out.
    pub fn servers(&self) -> Vec<ServerStats> {
        let state = self.shared.state();
        self.shared
            .servers
            .iter()
            .zip(&state.health)
            .map(|(&addr, health)| ServerStats {
                addr,
                answered: health.answered,
                failed: health.failed,
                latency_ms: health.latency_ms,
            })
            .collect()
    }

    /// The upstream that is asked first.
    pub fn preferred(&self) -> SocketAddr {
        let shared = &self.shared;
        shared.servers[shared.state().preferred]
    }

    /// The upstreams that have failed [`SILENT_AFTER`] times in a row and not answered since, in
    /// the order they were given.
    pub fn not_answering(&self) -> Vec<SocketAddr> {
        let state = self.shared.state();
        let silent = state
            .health
            .iter()
            .map(|health| health.misses >= SILENT_AFTER);
        self.shared
            .servers
            .iter()
            .zip(silent)
            .filter_map(|(&server, silent)| silent.then_some(server))
            .collect()
    }

    /// Reads the sockets that lost the race in a task of their own, if there is room for one.
    /// Without room they are dropped unread, and nothing is counted for them.
    fn drain(&self, legs: Legs, deadline: Instant) {
        if legs.live.is_empty() {
            return;
        }
        if let Ok(permit) = self.drains.clone().try_acquire_owned() {
            tokio::spawn(drain(self.shared.clone(), legs, deadline, permit));
        }
    }

    /// Logs that every upstream failed, unless it was logged less than a minute ago. Gives `None`.
    fn none_answers(&self) -> Option<UpstreamOutcome> {
        let now = Instant::now();
        let mut state = self.shared.state();
        let due = state
            .no_upstream_logged
            .is_none_or(|last| now.duration_since(last) >= NO_UPSTREAM_LOG_EVERY);
        if due {
            state.no_upstream_logged = Some(now);
        }
        drop(state);
        if due {
            log::warn!("dns: no upstream answers");
        }
        None
    }

    /// The question over TCP: `first` is asked, then the others in the order of an exchange that
    /// started at `preferred`, each within its own `tcp_wait`, until one gives an outcome. The
    /// index of that upstream and the outcome; those that gave none are counted as failures.
    async fn ask_tcp_in_turn(
        &self,
        first: usize,
        preferred: usize,
        pending: &Pending,
        take: &mut Take<'_>,
    ) -> Option<(usize, UpstreamOutcome)> {
        let others = asked(preferred, self.shared.servers.len()).filter(|&index| index != first);
        for index in iter::once(first).chain(others) {
            let asked = timeout(
                self.tcp_wait,
                ask_tcp(self.shared.servers[index], pending, take),
            )
            .await;
            match asked {
                Ok(Ok(outcome)) => return Some((index, outcome)),
                Ok(Err(_)) | Err(_) => self.shared.note(index, false),
            }
        }
        None
    }
}

impl Shared {
    fn state(&self) -> MutexGuard<'_, State> {
        // The numbers stay valid whatever a panicking holder left half done.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Notes that the upstream `servers[index]` answered, or gave no usable answer, and logs what
    /// changed by it.
    fn note(&self, index: usize, answered: bool) {
        let mut state = self.state();
        if !answered {
            state.failures += 1;
            state.health[index].failed += 1;
        }
        let change = note(&mut state.health[index], answered, Instant::now());
        drop(state);
        self.log(index, change);
    }

    /// Sends `query`, which goes under `id`, to `servers[index]` from a socket of its own at `sent`,
    /// and gives the leg that waits for the answer. A failure to send is counted, and gives none.
    async fn open(&self, index: usize, id: u16, query: Vec<u8>, sent: Instant) -> Option<Leg> {
        match send_udp(self.servers[index], &query).await {
            Ok(socket) => {
                self.sent.fetch_add(1, Ordering::Relaxed);
                Some(Leg::new(index, id, query, sent, socket))
            }
            Err(_) => {
                self.note(index, false);
                None
            }
        }
    }

    /// Sends the query of `leg` once more on its socket, while the leg goes on being waited for.
    /// A leg that cannot be sent on is no good. A socket that would block (its buffer is full,
    /// which one datagram of a few dozen bytes does not make it) has had the question once
    /// already: nothing goes out, and the leg waits on.
    fn resend(&self, leg: &Leg) -> Resend {
        match leg.socket.try_send(&leg.query) {
            Ok(_) => {
                self.sent.fetch_add(1, Ordering::Relaxed);
                Resend::Sent
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => Resend::Blocked,
            Err(_) => Resend::Failed,
        }
    }

    /// Notes an answer from `servers[index]` that the exchange used, and that it is the upstream
    /// that is asked first from now on. `took` is the time from the send that it answers, the
    /// sample of the latency, for all the upstreams and for this one, when that is known: after a
    /// resend it is not.
    fn won(&self, index: usize, took: Option<Duration>) {
        let mut state = self.state();
        if let Some(took) = took {
            let sample_ms = took.as_secs_f32() * 1000.0;
            state.latency_ms = Some(smoothed(state.latency_ms, sample_ms));
            let health = &mut state.health[index];
            health.latency_ms = Some(smoothed(health.latency_ms, sample_ms));
        }
        state.preferred = index;
        state.health[index].answered += 1;
        let change = note(&mut state.health[index], true, Instant::now());
        drop(state);
        self.log(index, change);
    }

    fn log(&self, index: usize, change: Option<Change>) {
        match change {
            Some(Change::Silent) => {
                log::warn!("dns: upstream {} does not answer", self.servers[index]);
            }
            Some(Change::Answers) => {
                log::info!("dns: upstream {} answers again", self.servers[index]);
            }
            None => {}
        }
    }
}

/// A new socket connected to `server`, with `query` sent on it.
async fn send_udp(server: SocketAddr, query: &[u8]) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).await?;
    socket.connect(server).await?;
    socket.send(query).await?;
    Ok(socket)
}

/// Waits on the live sockets until the deadline of `round` runs out, one packet at a time. A packet
/// that is shorter than a header or not under its socket's ID is ignored, `take` calls the rest;
/// a socket that fails is counted and dropped. The winner's socket is taken out of `legs`; at the
/// end of the time what is left of them is counted as failures.
///
/// `timer` counts to the point of the phase of `round`: the hedge point if there are hedges to
/// send, then the resend point if that is before the deadline, then the deadline. The hedges go
/// when the hedge point comes, or when no socket is live (the preferred upstream could not be sent
/// to, failed, or was set aside as a refusal), and their sockets are put on the end of `legs`. At
/// the resend point, if the race is still on, the question is sent once more on every socket that
/// is live; the deadline ends the race.
///
/// A refusal ([`is_refusal`]) does not win while another socket is live, hedges are unsent, or
/// after an earlier refusal was kept: its socket is set aside, counted as an answer, and the first
/// such packet is kept as the fallback. It goes to `take`, and is the outcome, only once no socket
/// is left or the time is up. `take` sees the packet that is finally used and no other. A refusal
/// that carries another question than its socket's ([`asks_the_same`]) is ignored, and its socket
/// stays live. A stall of the runtime does not make the phases that it passed over come one after
/// the other ([`Round::hedge`], [`Round::resend`]).
async fn race(
    round: &mut Round<'_>,
    legs: &mut Legs,
    timer: &mut Pin<&mut Sleep>,
    take: &mut Take<'_>,
) -> Race {
    let shared = round.shared;
    // The first refusal that was set aside: the index of its upstream, the round trip of its
    // datagram if that is a sample ([`Round::sample`]), and the packet.
    let mut fallback: Option<(usize, Option<Duration>, Vec<u8>)> = None;
    loop {
        if legs.live.is_empty() {
            if round.unsent.is_empty() {
                break;
            }
            // Nobody to wait for: the hedges go now.
            round.hedge(legs, timer).await;
            continue;
        }
        match legs.next(timer).await {
            Event::Timer => match round.phase {
                Phase::Hedge => round.hedge(legs, timer).await,
                Phase::Resend => round.resend(legs, timer).await,
                Phase::Deadline => {
                    legs.expire(shared);
                    break;
                }
            },
            Event::Failed(position) => {
                let leg = legs.live.remove(position);
                shared.note(leg.index, false);
            }
            Event::Packet(position, len) => {
                let packet = &legs.buf[..len];
                if !has_id(packet, legs.live[position].id) {
                    continue;
                }
                let others = legs.live.len() > 1 || !round.unsent.is_empty();
                if is_refusal(packet) && (others || fallback.is_some()) {
                    // A failure for another question is not this upstream's answer: it is
                    // ignored, as a `Mismatch` is, and the leg stays live.
                    if !asks_the_same(&legs.live[position].query, packet) {
                        continue;
                    }
                    let leg = legs.live.remove(position);
                    shared.note(leg.index, true);
                    fallback.get_or_insert_with(|| {
                        (leg.index, round.sample(leg.sent), packet.to_vec())
                    });
                    continue;
                }
                match take(packet, Transport::Udp) {
                    UpstreamOutcome::Mismatch => {}
                    UpstreamOutcome::RetryOverTcp => {
                        let leg = legs.live.remove(position);
                        return Race::Truncated(leg.index, round.sample(leg.sent));
                    }
                    outcome => {
                        let leg = legs.live.remove(position);
                        return Race::Won(leg.index, round.sample(leg.sent), outcome);
                    }
                }
            }
        }
    }
    let Some((index, sample, packet)) = fallback else {
        return Race::Lost;
    };
    match take(&packet, Transport::Udp) {
        UpstreamOutcome::Mismatch => Race::Lost,
        UpstreamOutcome::RetryOverTcp => Race::Truncated(index, sample),
        outcome => Race::Fallback(outcome),
    }
}

/// Reads the sockets of the upstreams that lost the race, until each has given a packet under its
/// ID or failed, or `deadline` passes. The packets are dropped: the answer is already taken. One
/// under the right ID counts as an answer for its upstream, the rest as failures. Sends nothing,
/// and so resends nothing. Holds `permit` until it is done.
async fn drain(
    shared: Arc<Shared>,
    mut legs: Legs,
    deadline: Instant,
    permit: OwnedSemaphorePermit,
) {
    let _permit = permit;
    let mut clock = pin!(sleep_until(deadline));
    while !legs.live.is_empty() {
        match legs.next(&mut clock).await {
            Event::Timer => legs.expire(&shared),
            Event::Failed(position) => {
                let leg = legs.live.remove(position);
                shared.note(leg.index, false);
            }
            Event::Packet(position, len) => {
                if has_id(&legs.buf[..len], legs.live[position].id) {
                    let leg = legs.live.remove(position);
                    shared.note(leg.index, true);
                }
            }
        }
    }
}

/// The query over TCP under a new ID, and the one message that comes back. No wait of its own.
/// A message under another ID, or one that `take` calls a mismatch, is an error.
async fn ask_tcp(
    server: SocketAddr,
    pending: &Pending,
    take: &mut Take<'_>,
) -> io::Result<UpstreamOutcome> {
    let id = new_id();
    let query = pending.upstream_query(id);
    let len = u16::try_from(query.len()).map_err(|_| ErrorKind::InvalidInput)?;
    let mut stream = TcpStream::connect(server).await?;
    stream
        .write_all(&[&len.to_be_bytes()[..], &query[..]].concat())
        .await?;
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).await?;
    let mut message = vec![0u8; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut message).await?;
    if !has_id(&message, id) {
        return Err(ErrorKind::InvalidData.into());
    }
    match take(&message, Transport::Tcp) {
        UpstreamOutcome::Mismatch => Err(ErrorKind::InvalidData.into()),
        outcome => Ok(outcome),
    }
}

/// A query ID: the low 16 bits of a random number.
fn new_id() -> u16 {
    sys::random_u64() as u16
}

/// Whether `packet` is long enough to be a message and carries `id`.
fn has_id(packet: &[u8], id: u16) -> bool {
    packet.len() >= HEADER_LEN && packet[..2] == id.to_be_bytes()
}

/// The bytes of the one question that `message`, which a header precedes, starts with: the name's
/// labels with their lengths and its end, and the type and class. `None` if that is not a question
/// of that shape: no end to the name, a label that is a pointer or longer than 63 bytes, or no
/// room for a type and a class.
fn question_len(message: &[u8]) -> Option<usize> {
    let mut at = HEADER_LEN;
    loop {
        let label = usize::from(*message.get(at)?);
        if label > 63 {
            return None;
        }
        at += 1 + label;
        if label == 0 {
            // The type and the class: two bytes each.
            let end = at + 4;
            return (end <= message.len()).then_some(end - HEADER_LEN);
        }
    }
}

/// Whether `packet`, which is a header long at least, asks one question, and that of `query`,
/// which went out on its socket: the same name but for the case of its letters, the same type and
/// the same class. A packet whose question cannot be read, or that does not hold one, is another
/// question. Compares the bytes and allocates nothing; a name is spelt out in full here, since
/// the first one has nothing before it to point to.
fn asks_the_same(query: &[u8], packet: &[u8]) -> bool {
    let Some(len) = question_len(query) else {
        return false;
    };
    let end = HEADER_LEN + len;
    let (Some(asked), Some(echoed)) = (query.get(HEADER_LEN..end), packet.get(HEADER_LEN..end))
    else {
        return false;
    };
    // The name is all but the last four bytes, the type and the class, which are exact: two
    // that differ by the case bit of a letter are two. The counts of questions are alike too: one.
    let name = len - 4;
    packet[4..6] == query[4..6]
        && echoed[..name].eq_ignore_ascii_case(&asked[..name])
        && echoed[name..] == asked[name..]
}

/// Whether `packet`, which is a header long at least, is a response whose code says that the
/// upstream failed (SERVFAIL, 2), does not do what was asked (NOTIMP, 4) or will not (REFUSED, 5).
/// Another upstream may still give a real answer to the question, and the race waits for it.
fn is_refusal(packet: &[u8]) -> bool {
    matches!(packet, [_, _, flags, code, ..] if flags & 0x80 != 0 && matches!(code & 0x0f, 2 | 4 | 5))
}

/// The warning for `count` upstreams, if there are more than a question is sent to.
fn surplus_warning(count: usize) -> Option<String> {
    (count > MAX_RACED).then(|| {
        format!(
            "dns: {count} upstreams configured; each question asks the first {MAX_RACED} from the preferred one"
        )
    })
}

/// The upstreams that a question is sent to: the indexes `0..len` starting at `preferred` and
/// going round, at most [`MAX_RACED`] of them.
fn asked(preferred: usize, len: usize) -> impl Iterator<Item = usize> {
    order(preferred, len).take(MAX_RACED)
}

/// The indexes `0..len` starting at `preferred` and going round.
pub(crate) fn order(preferred: usize, len: usize) -> impl Iterator<Item = usize> {
    (0..len).map(move |step| (preferred + step) % len)
}

/// The latency after one more sample: the first as it is, then a move of an eighth of the way
/// towards each.
pub(crate) fn smoothed(old: Option<f32>, sample_ms: f32) -> f32 {
    match old {
        None => sample_ms,
        Some(old) => old + (sample_ms - old) / 8.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::client::{Answer, read_answer};
    use crate::dns::testutil::{
        FakeUpstream, NOW, Reply, TlsFakeUpstream, TlsMode, closed_port, ip, ms, pending,
        tls_for_fake, tls_for_fakes,
    };

    use std::time::Duration;

    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{DNSClass, Name, RecordType};
    use qb_dns::{BlockSet, Resolver, UpstreamOutcome};
    use tokio::time::sleep;

    /// One exchange for `name` A with a fresh resolver: the client's answer, if any, and how long
    /// the exchange took, on tokio's clock (which a test may pause).
    async fn run(ups: &Upstreams, name: &str) -> (Option<Answer>, Duration) {
        let mut r = Resolver::new(BlockSet::default());
        let p = pending(&mut r, name);
        let started = Instant::now();
        let outcome = ups
            .exchange(&p, &mut |packet, via| {
                r.handle_upstream(&p, packet, via, NOW)
            })
            .await;
        let took = started.elapsed();
        let answer = match outcome {
            Some(UpstreamOutcome::Reply(bytes)) => read_answer(&bytes, 7),
            _ => None,
        };
        (answer, took)
    }

    /// Two fakes, the slow one listed first: it answers `192.0.2.20` after 200 ms, the fast one
    /// `192.0.2.10` at once.
    async fn slow_and_fast() -> (FakeUpstream, FakeUpstream) {
        (
            FakeUpstream::start(Reply::After(ms(200), ip("192.0.2.20"))).await,
            FakeUpstream::start(Reply::Answer(ip("192.0.2.10"))).await,
        )
    }

    #[tokio::test]
    async fn an_answer_is_taken_and_its_latency_kept() {
        let up = FakeUpstream::start(Reply::Answer(ip("192.0.2.10"))).await;
        let ups = Upstreams::with(vec![up.addr], ms(300), ms(600));
        assert_eq!(ups.latency_ms(), None);
        assert_eq!(
            run(&ups, "example.com").await.0.unwrap().v4(),
            [ip("192.0.2.10")]
        );
        assert!(ups.latency_ms().is_some());
        assert_eq!(
            (ups.failures(), up.udp_queries(), up.tcp_queries()),
            (0, 1, 0)
        );
    }

    #[tokio::test]
    async fn the_faster_of_two_upstreams_is_taken_and_the_slower_is_not_waited_for() {
        let (slow, fast) = slow_and_fast().await;
        let ups = Upstreams::with(vec![slow.addr, fast.addr], ms(400), ms(600));
        let (answer, took) = run(&ups, "example.com").await;
        assert_eq!(answer.unwrap().v4(), [ip("192.0.2.10")]);
        assert!(took < ms(150), "took {took:?}");
        assert_eq!(ups.preferred(), fast.addr);
        assert!(ups.latency_ms().unwrap() < 150);
        // The slow one's late answer (at 200 ms) is read and dropped: it is no failure. Past the
        // wait (400 ms) a drain that had missed it would have counted one.
        sleep(ms(500)).await;
        assert_eq!((slow.udp_queries(), fast.udp_queries()), (1, 1));
        assert_eq!(ups.failures(), 0);
        assert!(ups.not_answering().is_empty());
    }

    // Review Focus 1. Changed with the hedge: the silent upstream is asked with the first question
    // only (there is no figure yet, so both are asked at once); the live one answers it and is
    // the preferred one from then on, and the silent one is not asked again while it does. It
    // collects one miss, not three; "reported after three misses" is in the next test, and in the
    // `note` tests. On the paused clock: with a figure of about nothing the hedge delay is 20 ms,
    // and the live one's answer, which is at once, must not ride a margin of real time.
    #[tokio::test(start_paused = true)]
    async fn a_silent_upstream_is_asked_once_and_no_more_while_another_answers() {
        let dead = FakeUpstream::start(Reply::Silent).await;
        let live = FakeUpstream::start(Reply::Answer(ip("192.0.2.10"))).await;
        let ups = Upstreams::with(vec![dead.addr, live.addr], ms(150), ms(300));
        for name in ["example.com", "example.org", "example.net"] {
            let (answer, took) = run(&ups, name).await;
            assert!(answer.is_some() && took < ms(100), "took {took:?}");
            // Past the wait: the dead one's miss is counted when its time is up.
            sleep(ms(200)).await;
        }
        assert_eq!(ups.failures(), 1);
        assert_eq!(dead.udp_queries(), 1);
        assert_eq!(live.udp_queries(), 3);
        assert!(ups.not_answering().is_empty());
    }

    // Review Focus 1: what the test above no longer shows, with the one upstream that is asked
    // every time
    #[tokio::test(start_paused = true)]
    async fn a_silent_upstream_that_is_asked_each_time_is_reported_after_three_misses() {
        let dead = FakeUpstream::start(Reply::Silent).await;
        let ups = Upstreams::with(vec![dead.addr], ms(150), ms(300));
        for (name, misses) in [("example.com", 1), ("example.org", 2), ("example.net", 3)] {
            let (answer, took) = run(&ups, name).await;
            assert!(answer.is_none() && took >= ms(150), "took {took:?}");
            assert_eq!(ups.failures(), misses);
        }
        assert_eq!(ups.not_answering(), [dead.addr]);
    }

    // Final review I1: a refusal is set aside while another upstream may still give an answer
    #[tokio::test]
    async fn a_refusal_does_not_win_the_race_over_a_good_answer() {
        for refuser_first in [true, false] {
            let refuser = FakeUpstream::start(Reply::Refused).await;
            let good = FakeUpstream::start(Reply::After(ms(50), ip("192.0.2.10"))).await;
            let servers = if refuser_first {
                vec![refuser.addr, good.addr]
            } else {
                vec![good.addr, refuser.addr]
            };
            let ups = Upstreams::with(servers, ms(400), ms(600));
            let (answer, took) = run(&ups, "example.com").await;
            let answer = answer.unwrap();
            assert_eq!((answer.rcode, answer.v4()), (0, vec![ip("192.0.2.10")]));
            assert!(took < ms(300), "took {took:?}");
            assert_eq!(ups.preferred(), good.addr);
            // The sample is the good answer's time, not the refusal's.
            assert!(ups.latency_ms().unwrap() >= 50, "{:?}", ups.latency_ms());
            // The refuser answered: it is no failure, and not silent.
            sleep(ms(500)).await;
            assert_eq!(ups.failures(), 0);
            assert!(ups.not_answering().is_empty());
        }
    }

    #[tokio::test]
    async fn a_refusal_is_delivered_at_the_deadline_when_no_better_answer_comes() {
        for refuser_first in [true, false] {
            let refuser = FakeUpstream::start(Reply::Refused).await;
            let silent = FakeUpstream::start(Reply::Silent).await;
            let servers = if refuser_first {
                vec![refuser.addr, silent.addr]
            } else {
                vec![silent.addr, refuser.addr]
            };
            let ups = Upstreams::with(servers.clone(), ms(300), ms(600));
            let (answer, took) = run(&ups, "example.com").await;
            assert_eq!(answer.unwrap().rcode, 5);
            assert!(took >= ms(300) && took < ms(500), "took {took:?}");
            // A refusal that is only a fallback is no upstream's answer time, and no preference.
            assert_eq!(ups.preferred(), servers[0]);
            assert_eq!(ups.latency_ms(), None);
            // Only the silent one failed.
            assert_eq!(ups.failures(), 1);
        }
    }

    #[tokio::test]
    async fn refusals_alone_are_delivered_at_once() {
        let (a, b) = (
            FakeUpstream::start(Reply::Refused).await,
            FakeUpstream::start(Reply::Refused).await,
        );
        let ups = Upstreams::with(vec![a.addr, b.addr], ms(2000), ms(2000));
        let (answer, took) = run(&ups, "example.com").await;
        assert_eq!(answer.unwrap().rcode, 5);
        assert!(took < ms(500), "took {took:?}");
        assert_eq!((ups.preferred(), ups.latency_ms()), (a.addr, None));
        assert_eq!(ups.failures(), 0);

        // The one that is left after the other failed has nothing to wait for either.
        let ups = Upstreams::with(vec![closed_port(), a.addr], ms(2000), ms(2000));
        let (answer, took) = run(&ups, "example.com").await;
        assert_eq!(answer.unwrap().rcode, 5);
        assert!(took < ms(500), "took {took:?}");
    }

    /// `n` fakes that all answer `192.0.2.10` at once, or all start a TCP exchange that fails.
    async fn many(n: usize, reply: Reply) -> Vec<FakeUpstream> {
        let mut fakes = Vec::new();
        for _ in 0..n {
            fakes.push(FakeUpstream::start(reply).await);
        }
        fakes
    }

    // Final review I2: the sockets that one question can open are bounded. Changed with the hedge:
    // the claim of four holds for a question that holds nothing back, which is one without a
    // figure for the latency; with a figure the preferred one is alone until it is slow. On the
    // paused clock, as the third question's figure is about nothing and its hedge delay 20 ms.
    #[tokio::test(start_paused = true)]
    async fn with_six_upstreams_a_question_is_sent_to_four() {
        let fakes = many(6, Reply::Answer(ip("192.0.2.10"))).await;
        let servers = fakes.iter().map(|fake| fake.addr).collect();
        let ups = Upstreams::with(servers, ms(300), ms(600));
        let sent = || {
            fakes
                .iter()
                .map(FakeUpstream::udp_queries)
                .collect::<Vec<_>>()
        };
        assert!(run(&ups, "example.com").await.0.is_some());
        // The fakes that lost count their datagram when their task gets to it: give them time.
        sleep(ms(100)).await;
        assert_eq!(sent(), [1, 1, 1, 1, 0, 0]);
        assert_eq!(ups.sent(), 4);

        // From the upstream that is preferred, the next three after it, wrapping round.
        ups.shared.state().preferred = 4;
        ups.shared.state().latency_ms = None;
        assert!(run(&ups, "example.net").await.0.is_some());
        sleep(ms(100)).await;
        assert_eq!(sent(), [2, 2, 1, 1, 1, 1]);
        assert_eq!(ups.sent(), 8);

        // With the figure that those answers gave, the preferred one that answers is the only one.
        ups.shared.state().preferred = 4;
        assert!(run(&ups, "example.org").await.0.is_some());
        sleep(ms(100)).await;
        assert_eq!(sent(), [2, 2, 1, 1, 2, 1]);
        assert_eq!(ups.sent(), 9);
    }

    #[tokio::test]
    async fn with_six_upstreams_the_tcp_retry_asks_four_as_well() {
        let fakes = many(6, Reply::TruncatedThenWrongIdOverTcp).await;
        let servers = fakes.iter().map(|fake| fake.addr).collect();
        let ups = Upstreams::with(servers, ms(300), ms(600));
        assert!(run(&ups, "example.com").await.0.is_none());
        sleep(ms(100)).await;
        let sent: Vec<_> = fakes
            .iter()
            .map(|fake| (fake.udp_queries(), fake.tcp_queries()))
            .collect();
        assert_eq!(sent, [(1, 1), (1, 1), (1, 1), (1, 1), (0, 0), (0, 0)]);
    }

    #[test]
    fn more_upstreams_than_are_asked_at_once_are_warned_about_once() {
        assert_eq!(surplus_warning(MAX_RACED), None);
        assert_eq!(surplus_warning(1), None);
        assert_eq!(
            surplus_warning(6).as_deref(),
            Some(
                "dns: 6 upstreams configured; each question asks the first 4 from the preferred one"
            )
        );
    }

    // Review Focus 2
    #[tokio::test]
    async fn a_packet_that_is_not_the_answer_is_ignored_and_the_wait_goes_on() {
        for reply in [
            Reply::WrongIdFirst(ip("192.0.2.10")),
            Reply::OtherQuestionFirst(ip("192.0.2.10")),
        ] {
            let up = FakeUpstream::start(reply).await;
            let ups = Upstreams::with(vec![up.addr], ms(300), ms(600));
            assert_eq!(
                run(&ups, "example.com").await.0.unwrap().v4(),
                [ip("192.0.2.10")]
            );
            assert_eq!((ups.failures(), up.udp_queries()), (0, 1));
        }
    }

    // Review Focus 2, ruling 13
    #[tokio::test]
    async fn a_hostile_upstream_never_wins() {
        // One that only ever sends the wrong ID loses to one that answers, and then misses.
        let wrong = FakeUpstream::start(Reply::WrongIdOnly(ip("203.0.113.66"))).await;
        let live = FakeUpstream::start(Reply::After(ms(50), ip("192.0.2.10"))).await;
        let ups = Upstreams::with(vec![wrong.addr, live.addr], ms(300), ms(600));
        assert_eq!(
            run(&ups, "example.com").await.0.unwrap().v4(),
            [ip("192.0.2.10")]
        );
        sleep(ms(400)).await;
        assert_eq!(ups.failures(), 1);

        // One that forges the answer from another socket and under another ID, beside one that
        // says nothing: the real answer is what comes out.
        let hostile = FakeUpstream::start(Reply::Hostile {
            real: ip("192.0.2.10"),
            forged: ip("203.0.113.99"),
        })
        .await;
        let silent = FakeUpstream::start(Reply::Silent).await;
        let ups = Upstreams::with(vec![silent.addr, hostile.addr], ms(300), ms(600));
        assert_eq!(
            run(&ups, "example.com").await.0.unwrap().v4(),
            [ip("192.0.2.10")]
        );
    }

    #[tokio::test]
    async fn a_truncated_answer_is_asked_for_again_over_tcp() {
        let up = FakeUpstream::start(Reply::TruncatedOverUdp(ip("192.0.2.10"))).await;
        let ups = Upstreams::with(vec![up.addr], ms(300), ms(600));
        assert_eq!(
            run(&ups, "example.com").await.0.unwrap().v4(),
            [ip("192.0.2.10")]
        );
        assert_eq!((up.udp_queries(), up.tcp_queries()), (1, 1));
    }

    // Review Focus 2, over TCP
    #[tokio::test]
    async fn a_tcp_answer_under_another_id_is_not_taken_and_the_next_upstream_is_asked() {
        let wrong = FakeUpstream::start(Reply::TruncatedThenWrongIdOverTcp).await;
        let live = FakeUpstream::start(Reply::After(ms(100), ip("192.0.2.10"))).await;
        let ups = Upstreams::with(vec![wrong.addr, live.addr], ms(300), ms(600));
        assert_eq!(
            run(&ups, "example.com").await.0.unwrap().v4(),
            [ip("192.0.2.10")]
        );
        assert_eq!((wrong.udp_queries(), wrong.tcp_queries()), (1, 1));
        assert_eq!(live.tcp_queries(), 1);
        assert_eq!(ups.preferred(), live.addr);
        assert!(ups.failures() >= 1);
    }

    #[tokio::test]
    async fn refused_ports_fail_at_once() {
        let live = FakeUpstream::start(Reply::Answer(ip("192.0.2.10"))).await;
        let ups = Upstreams::with(vec![closed_port(), live.addr], ms(2000), ms(2000));
        let (answer, took) = run(&ups, "example.com").await;
        assert!(answer.is_some() && took < ms(500), "took {took:?}");

        let ups = Upstreams::with(vec![closed_port(), closed_port()], ms(2000), ms(2000));
        let (answer, took) = run(&ups, "example.com").await;
        assert!(answer.is_none() && took < ms(500), "took {took:?}");
        assert_eq!(ups.failures(), 2);
    }

    #[tokio::test]
    async fn when_no_upstream_answers_there_is_no_outcome() {
        let (a, b) = (
            FakeUpstream::start(Reply::Silent).await,
            FakeUpstream::start(Reply::Silent).await,
        );
        let ups = Upstreams::with(vec![a.addr, b.addr], ms(100), ms(200));
        let (answer, took) = run(&ups, "example.com").await;
        // One wait for both, and not one each.
        assert!(
            answer.is_none() && took >= ms(100) && took < ms(190),
            "took {took:?}"
        );
        assert_eq!((ups.failures(), ups.latency_ms()), (2, None));
    }

    #[tokio::test]
    async fn losers_are_not_read_when_no_drain_is_free() {
        let silent = FakeUpstream::start(Reply::Silent).await;
        let fast = FakeUpstream::start(Reply::Answer(ip("192.0.2.10"))).await;

        // The control: with a drain free, the silent loser is counted when its time is up.
        let ups = Upstreams::with(vec![silent.addr, fast.addr], ms(200), ms(600));
        assert!(run(&ups, "example.com").await.0.is_some());
        sleep(ms(300)).await;
        assert_eq!(ups.failures(), 1);

        // With none free, the socket is dropped unread and nothing is counted for it.
        let ups = Upstreams::with_drains(vec![silent.addr, fast.addr], ms(200), ms(600), 0);
        assert_eq!(
            run(&ups, "example.com").await.0.unwrap().v4(),
            [ip("192.0.2.10")]
        );
        sleep(ms(300)).await;
        assert_eq!(ups.failures(), 0);
        assert!(ups.not_answering().is_empty());

        // The same for a loser that would have answered late.
        let (slow, fast) = slow_and_fast().await;
        let ups = Upstreams::with_drains(vec![slow.addr, fast.addr], ms(300), ms(600), 0);
        assert_eq!(
            run(&ups, "example.com").await.0.unwrap().v4(),
            [ip("192.0.2.10")]
        );
        sleep(ms(400)).await;
        assert_eq!(ups.failures(), 0);
    }

    // Review Focus 2: a socket that never stops receiving what is not the answer
    #[tokio::test]
    async fn a_flooding_upstream_neither_starves_the_others_nor_outlasts_the_wait() {
        let flood = FakeUpstream::start(Reply::FloodWrongId).await;
        let live = FakeUpstream::start(Reply::After(ms(50), ip("192.0.2.10"))).await;
        let ups = Upstreams::with(vec![flood.addr, live.addr], ms(400), ms(600));
        let (answer, took) = run(&ups, "example.com").await;
        assert_eq!(answer.unwrap().v4(), [ip("192.0.2.10")]);
        assert!(took < ms(300), "took {took:?}");
        // The drain that reads the flooded socket ends with the wait too, and gives its permit
        // back, though the flood goes on.
        sleep(ms(500)).await;
        assert_eq!(ups.failures(), 1);
        assert_eq!(ups.drains.available_permits(), MAX_DRAINS);
    }

    #[tokio::test]
    async fn a_flood_alone_ends_with_the_wait() {
        let flood = FakeUpstream::start(Reply::FloodWrongId).await;
        let ups = Upstreams::with(vec![flood.addr], ms(100), ms(200));
        let (answer, took) = run(&ups, "example.com").await;
        assert!(
            answer.is_none() && took >= ms(100) && took < ms(250),
            "took {took:?}"
        );
        assert_eq!(ups.failures(), 1);
    }

    /// The sum of what the servers' figures say about answers, and about failures.
    fn totals(ups: &Upstreams) -> (u64, u64) {
        ups.servers()
            .iter()
            .fold((0, 0), |(answered, failed), server| {
                (answered + server.answered, failed + server.failed)
            })
    }

    // The plan's test, adapted to the hedge: with no figure yet the first question asks both at
    // once, the live one answers it and is the preferred one from then on, so the second question
    // never reaches the silent one. Its one miss is the time of the first question running out.
    #[tokio::test(start_paused = true)]
    async fn each_server_counts_its_own_answers_failures_and_round_trips() {
        let dead = FakeUpstream::start(Reply::Silent).await;
        let live = FakeUpstream::start(Reply::Answer(ip("192.0.2.10"))).await;
        let ups = Upstreams::with(vec![dead.addr, live.addr], ms(150), ms(300));
        for name in ["example.com", "example.org"] {
            let (answer, took) = run(&ups, name).await;
            assert!(answer.is_some() && took < ms(100), "took {took:?}");
            // Past the wait: the silent one's miss is counted when its time is up.
            sleep(ms(200)).await;
        }
        let servers = ups.servers();
        // In the order they were given, whoever answers first.
        assert_eq!(
            servers.iter().map(|s| s.addr).collect::<Vec<_>>(),
            [dead.addr, live.addr]
        );
        let silent = (
            servers[0].answered,
            servers[0].failed,
            servers[0].latency_ms,
        );
        assert_eq!(silent, (0, 1, None));
        assert_eq!((servers[1].answered, servers[1].failed), (2, 0));
        assert!(
            servers[1].latency_ms.is_some_and(|ms| ms < 150.0),
            "{:?}",
            servers[1].latency_ms
        );
        assert_eq!(totals(&ups), (2, ups.failures()));
    }

    #[tokio::test(start_paused = true)]
    async fn the_server_that_wins_is_counted_answered_and_a_loser_that_answers_late_is_not() {
        let (slow, fast, ups) = hedged_pair(
            Reply::After(ms(200), ip("192.0.2.20")),
            Reply::Answer(ip("192.0.2.10")),
            10.0,
            ms(400),
        )
        .await;
        // The hedge goes at 20 ms, wins, and is the preferred one for the second question.
        for name in ["example.com", "example.org"] {
            let (answer, took) = run(&ups, name).await;
            assert_eq!(answer.unwrap().v4(), [ip("192.0.2.10")]);
            assert!(took < ms(40), "took {took:?}");
        }
        // The slow one's late answer, at 200 ms, was read and dropped by the drain: the exchange
        // used the other's, so it is no answer of the slow one's, and no failure either.
        sleep(ms(500)).await;
        assert_eq!((slow.udp_queries(), fast.udp_queries()), (1, 2));
        let servers = ups.servers();
        assert_eq!(
            (servers[0].addr, servers[0].answered, servers[0].failed),
            (slow.addr, 0, 0)
        );
        assert_eq!(servers[0].latency_ms, None);
        assert_eq!(
            (servers[1].addr, servers[1].answered, servers[1].failed),
            (fast.addr, 2, 0)
        );
        assert!(servers[1].latency_ms.is_some_and(|ms| ms < 20.0));
        // As many answers as exchanges that got one, and the failures are those of the total.
        assert_eq!(totals(&ups), (2, ups.failures()));
        assert_eq!(ups.failures(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn the_failures_of_each_server_add_up_to_the_total() {
        let silent = FakeUpstream::start(Reply::Silent).await;
        let live = FakeUpstream::start(Reply::Answer(ip("192.0.2.10"))).await;
        let closed = closed_port();
        let ups = Upstreams::with(vec![closed, silent.addr, live.addr], ms(150), ms(300));
        // No figure yet: all three are asked at once. The closed port is refused at once, the live
        // one answers, and the silent one's time runs out, each once, whether the race or the
        // drain after it sees it.
        assert!(run(&ups, "example.com").await.0.is_some());
        sleep(ms(200)).await;
        let servers = ups.servers();
        let counts = |i: usize| (servers[i].answered, servers[i].failed);
        assert_eq!((counts(0), counts(1), counts(2)), ((0, 1), (0, 1), (1, 0)));
        assert_eq!(totals(&ups), (1, 2));
        assert_eq!(ups.failures(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn an_answer_over_tcp_counts_for_the_upstream_that_gave_it() {
        // One upstream: its datagram is truncated, its stream answers. The sample of its latency
        // is the datagram's round trip, which is about nothing here.
        let up = FakeUpstream::start(Reply::TruncatedOverUdp(ip("192.0.2.10"))).await;
        let ups = Upstreams::with(vec![up.addr], ms(300), ms(600));
        assert_eq!(
            run(&ups, "example.com").await.0.unwrap().v4(),
            [ip("192.0.2.10")]
        );
        let servers = ups.servers();
        assert_eq!((servers[0].answered, servers[0].failed), (1, 0));
        assert!(servers[0].latency_ms.is_some_and(|ms| ms < 10.0));

        // Two: the first is truncated and then answers over TCP under another ID, which is no
        // answer and is its failure; the second's stream answers, and the answer is the second's.
        // The second's datagram, which the drain reads, is not counted as an answer, and the
        // round trip of the first's datagram is no sample for the second.
        let wrong = FakeUpstream::start(Reply::TruncatedThenWrongIdOverTcp).await;
        let live = FakeUpstream::start(Reply::After(ms(100), ip("192.0.2.10"))).await;
        let ups = Upstreams::with(vec![wrong.addr, live.addr], ms(300), ms(600));
        assert_eq!(
            run(&ups, "example.com").await.0.unwrap().v4(),
            [ip("192.0.2.10")]
        );
        sleep(ms(500)).await;
        let servers = ups.servers();
        let first = (
            servers[0].answered,
            servers[0].failed,
            servers[0].latency_ms,
        );
        assert_eq!(first, (0, 1, None));
        let second = (
            servers[1].answered,
            servers[1].failed,
            servers[1].latency_ms,
        );
        assert_eq!(second, (1, 0, None));
        assert_eq!(totals(&ups), (1, ups.failures()));
    }

    #[test]
    fn the_hedge_delay_is_twice_the_latency_between_the_bounds() {
        assert_eq!(hedge_delay(None), None);
        assert_eq!(hedge_delay(Some(1.0)), Some(ms(20)));
        assert_eq!(hedge_delay(Some(30.0)), Some(ms(60)));
        assert_eq!(hedge_delay(Some(200.0)), Some(ms(250)));
        // What is not a time is still no panic: it falls to a bound.
        assert_eq!(hedge_delay(Some(f32::NAN)), Some(HEDGE_MIN));
        assert_eq!(hedge_delay(Some(-5.0)), Some(HEDGE_MIN));
        assert_eq!(hedge_delay(Some(f32::INFINITY)), Some(HEDGE_MAX));
    }

    /// Two fakes, the first of them the preferred upstream, and an `Upstreams` over them that has a
    /// smoothed latency of `figure_ms`, so that the second is held back for the hedge delay.
    async fn hedged_pair(
        first: Reply,
        second: Reply,
        figure_ms: f32,
        udp_wait: Duration,
    ) -> (FakeUpstream, FakeUpstream, Upstreams) {
        let first = FakeUpstream::start(first).await;
        let second = FakeUpstream::start(second).await;
        let ups = Upstreams::with(vec![first.addr, second.addr], udp_wait, ms(600));
        ups.shared.state().latency_ms = Some(figure_ms);
        (first, second, ups)
    }

    #[tokio::test]
    async fn without_a_figure_every_asked_upstream_gets_the_question_at_once() {
        let first = FakeUpstream::start(Reply::Answer(ip("192.0.2.10"))).await;
        let second = FakeUpstream::start(Reply::Answer(ip("192.0.2.20"))).await;
        let ups = Upstreams::with(vec![first.addr, second.addr], ms(300), ms(600));
        assert_eq!(ups.latency_ms(), None);
        let answer = run(&ups, "example.com").await.0.unwrap();
        // The preferred one answered at once, and the other had the question all the same.
        assert_eq!(answer.v4(), [ip("192.0.2.10")]);
        sleep(ms(100)).await;
        assert_eq!((first.udp_queries(), second.udp_queries()), (1, 1));
        assert_eq!(ups.sent(), 2);
        assert_eq!(ups.failures(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_preferred_that_answers_within_the_hedge_delay_is_the_only_one_asked() {
        let (first, second, ups) = hedged_pair(
            Reply::Answer(ip("192.0.2.10")),
            Reply::Answer(ip("192.0.2.20")),
            10.0,
            ms(300),
        )
        .await;
        for name in ["example.com", "example.org", "example.net"] {
            let (answer, took) = run(&ups, name).await;
            assert_eq!(answer.unwrap().v4(), [ip("192.0.2.10")]);
            assert!(took < ms(20), "took {took:?}");
        }
        // Past the wait: a question that had gone out and was not read would show as a failure.
        sleep(ms(500)).await;
        assert_eq!((first.udp_queries(), second.udp_queries()), (3, 0));
        assert_eq!((ups.sent(), ups.failures()), (3, 0));
        assert!(ups.not_answering().is_empty());
        assert_eq!(ups.preferred(), first.addr);
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_preferred_is_hedged_at_the_delay_and_the_hedge_wins() {
        let (slow, fast, ups) = hedged_pair(
            Reply::After(ms(200), ip("192.0.2.20")),
            Reply::Answer(ip("192.0.2.10")),
            10.0,
            ms(400),
        )
        .await;
        let (answer, took) = run(&ups, "example.com").await;
        assert_eq!(answer.unwrap().v4(), [ip("192.0.2.10")]);
        // The delay is twice the figure: 20 ms.
        assert!(took >= ms(20) && took < ms(30), "took {took:?}");
        assert_eq!(ups.preferred(), fast.addr);
        // The sample is the hedge's own time, about nothing, and the figure moves from 10 towards
        // it. Counted from the start of the question it would be 20 ms, and the figure would rise.
        assert!(ups.latency_ms().unwrap() <= 10, "{:?}", ups.latency_ms());
        // The slow one's late answer (at 200 ms) is read and dropped: it is no failure.
        sleep(ms(500)).await;
        assert_eq!((slow.udp_queries(), fast.udp_queries()), (1, 1));
        assert_eq!((ups.sent(), ups.failures()), (2, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn a_dead_preferred_is_hedged_at_once_and_not_at_the_delay() {
        let live = FakeUpstream::start(Reply::Answer(ip("192.0.2.10"))).await;
        let ups = Upstreams::with(vec![closed_port(), live.addr], ms(2000), ms(2000));
        // The delay would be 200 ms.
        ups.shared.state().latency_ms = Some(100.0);
        let (answer, took) = run(&ups, "example.com").await;
        assert_eq!(answer.unwrap().v4(), [ip("192.0.2.10")]);
        assert!(took < ms(20), "took {took:?}");
        assert_eq!((ups.preferred(), ups.failures()), (live.addr, 1));
        // The dead one's datagram went out, and so did the live one's.
        assert_eq!(ups.sent(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_preferred_that_cannot_be_sent_to_is_hedged_at_once() {
        let live = FakeUpstream::start(Reply::Answer(ip("192.0.2.10"))).await;
        // The broadcast address: without SO_BROADCAST Linux refuses the `connect` (EACCES), so
        // nothing goes out.
        let nowhere = SocketAddr::from((Ipv4Addr::BROADCAST, UPSTREAM_PORT));
        let ups = Upstreams::with(vec![nowhere, live.addr], ms(2000), ms(2000));
        ups.shared.state().latency_ms = Some(100.0);
        let (answer, took) = run(&ups, "example.com").await;
        assert_eq!(answer.unwrap().v4(), [ip("192.0.2.10")]);
        assert!(took < ms(20), "took {took:?}");
        assert_eq!(
            (ups.preferred(), ups.failures(), ups.sent()),
            (live.addr, 1, 1)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_preferred_is_hedged_at_the_delay_and_then_not_asked() {
        let (silent, live, ups) = hedged_pair(
            Reply::Silent,
            Reply::Answer(ip("192.0.2.10")),
            10.0,
            ms(300),
        )
        .await;
        let (answer, took) = run(&ups, "example.com").await;
        assert!(answer.is_some());
        assert!(took >= ms(20) && took < ms(30), "took {took:?}");
        assert_eq!((ups.preferred(), ups.failures()), (live.addr, 0));

        // The answer made the other upstream the preferred one: the next question goes to it alone.
        let (answer, took) = run(&ups, "example.org").await;
        assert!(answer.is_some() && took < ms(20), "took {took:?}");
        sleep(ms(500)).await;
        assert_eq!((silent.udp_queries(), live.udp_queries()), (1, 2));
        // The silent one's time ran out once, and it is no one's preferred.
        assert_eq!((ups.sent(), ups.failures()), (3, 1));
    }

    #[tokio::test(start_paused = true)]
    async fn a_refusing_preferred_hedges_at_once_and_the_good_answer_wins() {
        let (refuser, good, ups) = hedged_pair(
            Reply::Refused,
            Reply::After(ms(50), ip("192.0.2.10")),
            100.0,
            ms(400),
        )
        .await;
        let (answer, took) = run(&ups, "example.com").await;
        let answer = answer.unwrap();
        assert_eq!((answer.rcode, answer.v4()), (0, vec![ip("192.0.2.10")]));
        // The delay would be 200 ms: the hedge went when the refusal came, and took its 50 ms.
        assert!(took >= ms(50) && took < ms(100), "took {took:?}");
        assert_eq!(ups.preferred(), good.addr);
        // The sample is the good answer's own time (50 ms), not the refusal's: 100 → 93.75.
        assert_eq!(ups.latency_ms(), Some(94));
        sleep(ms(500)).await;
        assert_eq!((refuser.udp_queries(), good.udp_queries()), (1, 1));
        assert_eq!((ups.sent(), ups.failures()), (2, 0));
        assert!(ups.not_answering().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_refusal_is_not_delivered_while_the_hedge_has_not_answered() {
        let (refuser, silent, ups) =
            hedged_pair(Reply::Refused, Reply::Silent, 100.0, ms(300)).await;
        let (answer, took) = run(&ups, "example.com").await;
        // The refusal came at once, but the hedge that it set off had the time up to the deadline.
        assert_eq!(answer.unwrap().rcode, 5);
        assert!(took >= ms(300) && took < ms(350), "took {took:?}");
        // No sample and no new preferred one: the refusal is only a fallback.
        assert_eq!(
            (ups.preferred(), ups.latency_ms()),
            (refuser.addr, Some(100))
        );
        assert_eq!(
            (silent.udp_queries(), ups.sent(), ups.failures()),
            (1, 2, 1)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_wrong_id_does_not_hedge_early_and_never_wins() {
        let (wrong, live, ups) = hedged_pair(
            Reply::WrongIdOnly(ip("203.0.113.66")),
            Reply::Answer(ip("192.0.2.10")),
            100.0,
            ms(1000),
        )
        .await;
        let (answer, took) = run(&ups, "example.com").await;
        // The packet with the wrong ID came at once; the other upstream was asked at the delay.
        assert_eq!(answer.unwrap().v4(), [ip("192.0.2.10")]);
        assert!(took >= ms(200) && took < ms(210), "took {took:?}");
        assert_eq!(ups.preferred(), live.addr);
        // The one that sent it had its wait, and no answer under its ID.
        sleep(ms(1500)).await;
        assert_eq!((wrong.udp_queries(), live.udp_queries()), (1, 1));
        assert_eq!(ups.failures(), 1);
    }

    #[tokio::test]
    async fn a_packet_for_another_question_does_not_hedge_early() {
        // The answer to another question under the right ID is a mismatch, and the right answer
        // follows at once: nothing was held up, and the other upstream was never asked.
        let (first, second, ups) = hedged_pair(
            Reply::OtherQuestionFirst(ip("192.0.2.10")),
            Reply::Answer(ip("192.0.2.20")),
            100.0,
            ms(400),
        )
        .await;
        let answer = run(&ups, "example.com").await.0.unwrap();
        assert_eq!(answer.v4(), [ip("192.0.2.10")]);
        sleep(ms(100)).await;
        assert_eq!((first.udp_queries(), second.udp_queries()), (1, 0));
        assert_eq!((ups.sent(), ups.failures()), (1, 0));
    }

    // Real time: the flood keeps the runtime busy, and a paused clock only moves when it is idle.
    #[tokio::test]
    async fn a_flooding_preferred_does_not_keep_the_hedge_from_going() {
        let (flood, live, ups) = hedged_pair(
            Reply::FloodWrongId,
            Reply::Answer(ip("192.0.2.10")),
            10.0,
            ms(400),
        )
        .await;
        let (answer, took) = run(&ups, "example.com").await;
        // The hedge goes at the delay (20 ms) though the preferred one never stops sending.
        assert_eq!(answer.unwrap().v4(), [ip("192.0.2.10")]);
        assert!(took >= ms(20) && took < ms(300), "took {took:?}");
        assert_eq!(ups.preferred(), live.addr);
        sleep(ms(500)).await;
        assert_eq!((flood.udp_queries(), live.udp_queries()), (1, 1));
        assert_eq!(ups.failures(), 1);
        assert_eq!(ups.drains.available_permits(), MAX_DRAINS);
    }

    #[tokio::test]
    async fn a_truncated_answer_before_the_hedge_delay_goes_to_tcp_and_hedges_nothing() {
        let (first, second, ups) = hedged_pair(
            Reply::TruncatedOverUdp(ip("192.0.2.10")),
            Reply::Answer(ip("192.0.2.20")),
            100.0,
            ms(400),
        )
        .await;
        let answer = run(&ups, "example.com").await.0.unwrap();
        assert_eq!(answer.v4(), [ip("192.0.2.10")]);
        sleep(ms(100)).await;
        assert_eq!(
            (first.udp_queries(), first.tcp_queries()),
            (1, 1),
            "the preferred one is asked again over TCP"
        );
        assert_eq!((second.udp_queries(), second.tcp_queries()), (0, 0));
        assert_eq!((ups.sent(), ups.failures()), (1, 0));
        assert_eq!(ups.preferred(), first.addr);
    }

    #[tokio::test(start_paused = true)]
    async fn a_delay_that_the_wait_does_not_outlast_holds_nothing_back() {
        // The figure would make the delay 200 ms, and the wait is 100 ms: the silent preferred one
        // would be waited out alone, and the live one never asked.
        let (silent, live, ups) = hedged_pair(
            Reply::Silent,
            Reply::Answer(ip("192.0.2.10")),
            100.0,
            ms(100),
        )
        .await;
        let (answer, took) = run(&ups, "example.com").await;
        assert!(answer.is_some() && took < ms(20), "took {took:?}");
        sleep(ms(200)).await;
        assert_eq!(
            (silent.udp_queries(), live.udp_queries(), ups.sent()),
            (1, 1, 2)
        );
    }

    #[tokio::test]
    async fn a_single_upstream_with_a_figure_is_asked_as_ever() {
        let up = FakeUpstream::start(Reply::Answer(ip("192.0.2.10"))).await;
        let ups = Upstreams::with(vec![up.addr], ms(300), ms(600));
        ups.shared.state().latency_ms = Some(10.0);
        assert_eq!(
            run(&ups, "example.com").await.0.unwrap().v4(),
            [ip("192.0.2.10")]
        );
        assert_eq!((ups.sent(), ups.failures(), up.udp_queries()), (1, 0, 1));
        assert_eq!(ups.preferred(), up.addr);
    }

    // Task 2 review M2: the wait of a hedged exchange is counted from the first send, not from
    // the hedge
    #[tokio::test(start_paused = true)]
    async fn the_deadline_of_a_hedged_exchange_counts_from_the_first_send() {
        let (_first, _second, ups) = hedged_pair(Reply::Silent, Reply::Silent, 10.0, ms(300)).await;
        let (answer, took) = run(&ups, "example.com").await;
        // The hedge went at 20 ms; the wait still ends at 300 ms, not at 320.
        assert!(answer.is_none(), "{answer:?}");
        assert!(took >= ms(300) && took < ms(310), "took {took:?}");
        assert_eq!((ups.failures(), ups.sent()), (2, 2));
    }

    // Task 2 review M3: a packet too short to be a message is ignored, and hedges nothing early
    #[tokio::test(start_paused = true)]
    async fn a_short_packet_does_not_hedge_early() {
        let (short, live, ups) = hedged_pair(
            Reply::ShortPacket,
            Reply::Answer(ip("192.0.2.10")),
            100.0,
            ms(1000),
        )
        .await;
        let (answer, took) = run(&ups, "example.com").await;
        // The delay is 200 ms, and the short packet that came at once did not shorten it.
        assert_eq!(answer.unwrap().v4(), [ip("192.0.2.10")]);
        assert!(took >= ms(200) && took < ms(210), "took {took:?}");
        assert_eq!(ups.preferred(), live.addr);
        // The one that sent it had its wait, and no answer under its ID.
        sleep(ms(1500)).await;
        assert_eq!((short.udp_queries(), live.udp_queries()), (1, 1));
        assert_eq!((ups.sent(), ups.failures()), (2, 1));
    }

    // Task 2 review M3: of six upstreams a silent preferred one is hedged to the next three after
    // it, wrapping round, and to no more
    #[tokio::test(start_paused = true)]
    async fn the_hedges_of_a_silent_preferred_go_to_the_next_three_and_wrap() {
        let mut fakes = Vec::new();
        for index in 0..6 {
            let reply = if index == 4 {
                Reply::Silent
            } else {
                Reply::Answer(ip("192.0.2.10"))
            };
            fakes.push(FakeUpstream::start(reply).await);
        }
        let servers = fakes.iter().map(|fake| fake.addr).collect();
        let ups = Upstreams::with(servers, ms(300), ms(600));
        {
            let mut state = ups.shared.state();
            state.preferred = 4;
            state.latency_ms = Some(10.0);
        }
        let (answer, took) = run(&ups, "example.com").await;
        assert!(answer.is_some());
        assert!(took >= ms(20) && took < ms(30), "took {took:?}");
        sleep(ms(500)).await;
        let sent: Vec<_> = fakes.iter().map(FakeUpstream::udp_queries).collect();
        assert_eq!(sent, [1, 1, 0, 0, 1, 1]);
        assert_eq!((ups.sent(), ups.failures()), (4, 1));
    }

    // Task 3. The fakes' answers are on tokio's clock, and the waits are the real ones.

    #[tokio::test(start_paused = true)]
    async fn a_question_that_was_lost_is_sent_again_at_the_resend_point() {
        let up = FakeUpstream::start(Reply::DropFirst(ip("192.0.2.10"))).await;
        let ups = Upstreams::with(vec![up.addr], UDP_WAIT, TCP_WAIT);
        let (answer, took) = run(&ups, "example.com").await;
        assert_eq!(answer.unwrap().v4(), [ip("192.0.2.10")]);
        assert!(took >= ms(700) && took < ms(750), "took {took:?}");
        assert_eq!((up.udp_queries(), ups.sent()), (2, 2));
        // Which datagram the answer is to is not known: no sample. The upstream still answered.
        assert_eq!(ups.latency_ms(), None);
        assert_eq!((ups.failures(), ups.preferred()), (0, up.addr));
        assert!(ups.not_answering().is_empty());
        // Once, and not again: nothing more goes out as the wait runs out.
        sleep(UDP_WAIT).await;
        assert_eq!((up.udp_queries(), ups.sent(), ups.failures()), (2, 2, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn a_late_answer_to_the_first_send_is_taken_when_it_comes() {
        let up = FakeUpstream::start(Reply::After(ms(800), ip("192.0.2.10"))).await;
        let ups = Upstreams::with(vec![up.addr], UDP_WAIT, TCP_WAIT);
        let (answer, took) = run(&ups, "example.com").await;
        // The resend went at 700 ms, and the answer to the first send came at 800: the leg's ID is
        // the same, so it is taken, and not the one at 1500 ms to the second.
        assert_eq!(answer.unwrap().v4(), [ip("192.0.2.10")]);
        assert!(took >= ms(800) && took < ms(850), "took {took:?}");
        assert_eq!((up.udp_queries(), ups.sent()), (2, 2));
        assert_eq!(ups.latency_ms(), None);
        sleep(UDP_WAIT).await;
        assert_eq!(ups.failures(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_question_answered_before_the_resend_point_is_not_sent_again() {
        let up = FakeUpstream::start(Reply::After(ms(300), ip("192.0.2.10"))).await;
        let ups = Upstreams::with(vec![up.addr], UDP_WAIT, TCP_WAIT);
        let (answer, took) = run(&ups, "example.com").await;
        assert!(answer.is_some());
        assert!(took >= ms(300) && took < ms(310), "took {took:?}");
        // The sample is there: nothing was sent twice.
        assert_eq!(ups.latency_ms(), Some(300));
        sleep(UDP_WAIT).await;
        assert_eq!((up.udp_queries(), ups.sent(), ups.failures()), (1, 1, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn a_wait_that_the_resend_point_is_not_before_is_never_resent_in() {
        for (wait, resent) in [(500, false), (700, false), (701, true)] {
            let silent = FakeUpstream::start(Reply::Silent).await;
            let ups = Upstreams::with(vec![silent.addr], ms(wait), ms(600));
            let (answer, took) = run(&ups, "example.com").await;
            assert!(answer.is_none(), "{wait} ms");
            assert!(
                took >= ms(wait) && took < ms(wait + 10),
                "{wait} ms: took {took:?}"
            );
            sleep(ms(1000)).await;
            let queries = if resent { 2 } else { 1 };
            assert_eq!(
                (silent.udp_queries(), ups.sent(), ups.failures()),
                (queries, queries as u64, 1),
                "{wait} ms"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn every_open_leg_is_resent_and_the_preferred_ones_second_answer_wins() {
        let (lossy, silent, ups) = hedged_pair(
            Reply::DropFirst(ip("192.0.2.10")),
            Reply::Silent,
            10.0,
            UDP_WAIT,
        )
        .await;
        let (answer, took) = run(&ups, "example.com").await;
        assert_eq!(answer.unwrap().v4(), [ip("192.0.2.10")]);
        assert!(took >= ms(700) && took < ms(750), "took {took:?}");
        // The hedge went at 20 ms to the silent one, and at 700 ms both were asked again.
        assert_eq!((lossy.udp_queries(), silent.udp_queries()), (2, 2));
        assert_eq!(ups.sent(), 4);
        assert_eq!((ups.preferred(), ups.latency_ms()), (lossy.addr, Some(10)));
        // The silent one's time is up with the wait, which was counted from the first send.
        sleep(UDP_WAIT).await;
        assert_eq!((ups.failures(), ups.sent()), (1, 4));
    }

    #[tokio::test(start_paused = true)]
    async fn a_leg_that_was_set_aside_by_a_refusal_is_not_resent() {
        let (refuser, lossy, ups) = hedged_pair(
            Reply::Refused,
            Reply::DropFirst(ip("192.0.2.10")),
            100.0,
            UDP_WAIT,
        )
        .await;
        let (answer, took) = run(&ups, "example.com").await;
        let answer = answer.unwrap();
        // The refusal sent the hedge at once, which was dropped, and was answered when it was
        // asked again.
        assert_eq!((answer.rcode, answer.v4()), (0, vec![ip("192.0.2.10")]));
        assert!(took >= ms(700) && took < ms(750), "took {took:?}");
        assert_eq!((refuser.udp_queries(), lossy.udp_queries()), (1, 2));
        assert_eq!(ups.sent(), 3);
        assert_eq!((ups.preferred(), ups.failures()), (lossy.addr, 0));
        // The answer came after the resend: no sample, and the figure is where it was.
        assert_eq!(ups.latency_ms(), Some(100));
    }

    #[tokio::test(start_paused = true)]
    async fn a_leg_that_failed_is_not_resent() {
        let silent = FakeUpstream::start(Reply::Silent).await;
        let ups = Upstreams::with(vec![closed_port(), silent.addr], UDP_WAIT, TCP_WAIT);
        ups.shared.state().latency_ms = Some(10.0);
        let (answer, took) = run(&ups, "example.com").await;
        assert!(answer.is_none());
        assert!(
            took >= UDP_WAIT && took < UDP_WAIT + ms(10),
            "took {took:?}"
        );
        // The closed port went out once and failed at once; the silent one twice.
        assert_eq!(silent.udp_queries(), 2);
        assert_eq!((ups.sent(), ups.failures()), (3, 2));
    }

    #[tokio::test(start_paused = true)]
    async fn a_wrong_id_only_upstream_is_resent_once_and_never_taken() {
        let wrong = FakeUpstream::start(Reply::WrongIdOnly(ip("203.0.113.66"))).await;
        let ups = Upstreams::with(vec![wrong.addr], UDP_WAIT, TCP_WAIT);
        let (answer, took) = run(&ups, "example.com").await;
        // Its packets are not under the leg's ID, and no resend changes that.
        assert!(answer.is_none(), "{answer:?}");
        assert!(
            took >= UDP_WAIT && took < UDP_WAIT + ms(10),
            "took {took:?}"
        );
        assert_eq!((wrong.udp_queries(), ups.sent()), (2, 2));
        assert_eq!((ups.failures(), ups.latency_ms()), (1, None));
    }

    // Real time: the error of a refused port is no part of tokio's clock.
    #[tokio::test]
    async fn a_socket_that_cannot_be_sent_on_fails_its_resend_and_the_others_go_on() {
        let (first, last) = (
            FakeUpstream::start(Reply::Silent).await,
            FakeUpstream::start(Reply::Silent).await,
        );
        let closed = closed_port();
        let ups = Upstreams::with(vec![first.addr, closed, last.addr], ms(300), ms(600));
        let mut legs = Legs {
            live: Vec::new(),
            buf: Vec::new(),
            first: 0,
        };
        let mut resolver = Resolver::new(BlockSet::default());
        let question = pending(&mut resolver, "example.com");
        for (index, server) in [first.addr, closed, last.addr].into_iter().enumerate() {
            let query = question.upstream_query(7);
            let socket = send_udp(server, &query).await.unwrap();
            legs.live
                .push(Leg::new(index, 7, query, Instant::now(), socket));
        }
        // The refused port has sent its ICMP message back by now: the socket holds the error, and
        // the next send on it is the one that reports it.
        sleep(ms(50)).await;
        assert!(legs.resend(&ups.shared, 3), "two datagrams went out");
        let kept: Vec<_> = legs.live.iter().map(|leg| leg.index).collect();
        assert_eq!(kept, [0, 2]);
        assert_eq!(ups.failures(), 1);
        assert_eq!(ups.sent(), 2);
        sleep(ms(50)).await;
        assert_eq!((first.udp_queries(), last.udp_queries()), (2, 2));
    }

    // Task 3 review m3: the sockets that are read on after the race never send
    #[tokio::test(start_paused = true)]
    async fn the_sockets_that_are_read_on_after_a_race_are_never_sent_to_again() {
        let answers = FakeUpstream::start(Reply::Answer(ip("192.0.2.10"))).await;
        let silent = FakeUpstream::start(Reply::Silent).await;
        let ups = Upstreams::with(vec![answers.addr, silent.addr], UDP_WAIT, TCP_WAIT);
        // No figure: both are asked at once, and the answer ends the race at once, long before the
        // resend point. The silent one's socket is read on until the end of the wait, which is
        // past that point.
        let (answer, took) = run(&ups, "example.com").await;
        assert!(answer.is_some() && took < ms(20), "took {took:?}");
        sleep(UDP_WAIT).await;
        assert_eq!((silent.udp_queries(), ups.sent()), (1, 2));
        sleep(ms(50)).await;
        assert_eq!(ups.failures(), 1);
        assert_eq!(ups.drains.available_permits(), MAX_DRAINS);
        assert_eq!((silent.udp_queries(), ups.sent()), (1, 2));
    }

    // Final review I1: the sample of a TCP retry is the datagram's own round trip
    #[tokio::test(start_paused = true)]
    async fn the_sample_of_a_tcp_retry_is_the_round_trip_of_the_truncated_datagram() {
        let up = FakeUpstream::start(Reply::TruncatedOverUdpLateOverTcp(
            ms(300),
            ip("192.0.2.10"),
        ))
        .await;
        let ups = Upstreams::with(vec![up.addr], ms(400), ms(600));
        ups.shared.state().latency_ms = Some(100.0);
        let (answer, took) = run(&ups, "example.com").await;
        assert_eq!(answer.unwrap().v4(), [ip("192.0.2.10")]);
        // The stream answered after 300 ms; the datagram, which was truncated at once, took
        // nothing: the figure moves from 100 to 87.5, and with the time of the stream it would
        // have risen to 125.
        assert!(took >= ms(300) && took < ms(310), "took {took:?}");
        assert_eq!(ups.latency_ms(), Some(88));
        assert_eq!((up.udp_queries(), up.tcp_queries()), (1, 1));
        assert_eq!((ups.preferred(), ups.failures()), (up.addr, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn a_tcp_retry_after_a_resend_gives_no_sample() {
        let up = FakeUpstream::start(Reply::DropFirstThenTruncated(ip("192.0.2.10"))).await;
        let ups = Upstreams::with(vec![up.addr], UDP_WAIT, TCP_WAIT);
        ups.shared.state().latency_ms = Some(100.0);
        let (answer, took) = run(&ups, "example.com").await;
        // The truncated answer is to the resend, at 700 ms; it is not known which datagram it
        // answers, so the figure stays.
        assert_eq!(answer.unwrap().v4(), [ip("192.0.2.10")]);
        assert!(took >= ms(700) && took < ms(750), "took {took:?}");
        assert_eq!((up.udp_queries(), up.tcp_queries(), ups.sent()), (2, 1, 2));
        assert_eq!(ups.latency_ms(), Some(100));
        assert_eq!((ups.preferred(), ups.failures()), (up.addr, 0));
    }

    // Final review M2: the failure of another question is no answer to set aside
    #[tokio::test(start_paused = true)]
    async fn a_failure_for_another_question_is_ignored_and_the_real_answer_is_taken() {
        let (first, second, ups) = hedged_pair(
            Reply::OtherQuestionRefusedFirst(ip("192.0.2.10")),
            Reply::Answer(ip("192.0.2.20")),
            100.0,
            ms(1000),
        )
        .await;
        let (answer, took) = run(&ups, "example.com").await;
        // SERVFAIL for another question came first, at once, and the real answer after it: the
        // hedge, which would have gone at once for a refusal, never went.
        assert_eq!(answer.unwrap().v4(), [ip("192.0.2.10")]);
        assert!(took < ms(20), "took {took:?}");
        sleep(ms(1500)).await;
        assert_eq!((first.udp_queries(), second.udp_queries()), (1, 0));
        assert_eq!((ups.sent(), ups.failures()), (1, 0));
        assert_eq!(ups.preferred(), first.addr);
    }

    #[tokio::test(start_paused = true)]
    async fn a_failure_for_another_question_does_not_hedge_early_and_never_wins() {
        let (other, live, ups) = hedged_pair(
            Reply::OtherQuestionRefusedOnly,
            Reply::Answer(ip("192.0.2.10")),
            100.0,
            ms(1000),
        )
        .await;
        let (answer, took) = run(&ups, "example.com").await;
        // The packet came at once; the other upstream was asked at the delay (200 ms).
        assert_eq!(answer.unwrap().v4(), [ip("192.0.2.10")]);
        assert!(took >= ms(200) && took < ms(210), "took {took:?}");
        assert_eq!(ups.preferred(), live.addr);
        // The one that sent it stayed in the race, had its wait, and gave no answer.
        sleep(ms(1500)).await;
        assert_eq!((other.udp_queries(), live.udp_queries()), (1, 1));
        assert_eq!((ups.sent(), ups.failures()), (2, 1));
    }

    /// [`run`], with the clock moved on by `stall` as soon as the first datagram is out, while the
    /// exchange is not polled: its timers then come when `stall` has gone by, as those of a
    /// runtime that was busy for that long.
    async fn run_after_a_stall(
        ups: &Upstreams,
        name: &str,
        stall: Duration,
    ) -> (Option<Answer>, Duration) {
        let stalled = async {
            while ups.sent() == 0 {
                tokio::task::yield_now().await;
            }
            tokio::time::advance(stall).await;
        };
        let (outcome, ()) = tokio::join!(run(ups, name), stalled);
        outcome
    }

    // Final review M5: after a stall the phases whose points have gone by are left out
    #[tokio::test(start_paused = true)]
    async fn a_hedge_that_comes_late_goes_and_skips_a_resend_point_that_has_gone_by() {
        let (first, second, ups) = hedged_pair(Reply::Silent, Reply::Silent, 10.0, UDP_WAIT).await;
        // The hedge point is at 20 ms and the resend point at 700 ms; the clock is at 1000 ms
        // when the exchange next runs.
        let (answer, took) = run_after_a_stall(&ups, "example.com", ms(1000)).await;
        assert!(answer.is_none(), "{answer:?}");
        assert!(
            took >= UDP_WAIT && took < UDP_WAIT + ms(10),
            "took {took:?}"
        );
        // The hedge went, late; the resend point was behind the clock, and nothing is sent twice.
        assert_eq!((first.udp_queries(), second.udp_queries()), (1, 1));
        assert_eq!((ups.sent(), ups.failures()), (2, 2));
    }

    #[tokio::test(start_paused = true)]
    async fn a_hedge_that_comes_after_the_deadline_sends_nothing() {
        let (first, second, ups) = hedged_pair(Reply::Silent, Reply::Silent, 10.0, UDP_WAIT).await;
        let (answer, took) = run_after_a_stall(&ups, "example.com", ms(2500)).await;
        // The wait was over when the exchange next ran: the question that had gone out is a miss,
        // and the one that had not is never sent.
        assert!(answer.is_none(), "{answer:?}");
        assert!(took >= ms(2500) && took < ms(2510), "took {took:?}");
        sleep(ms(100)).await;
        assert_eq!((first.udp_queries(), second.udp_queries()), (1, 0));
        assert_eq!((ups.sent(), ups.failures()), (1, 1));
    }

    #[tokio::test(start_paused = true)]
    async fn a_resend_that_comes_late_goes_and_one_after_the_deadline_does_not() {
        for (stall, resent) in [(1000, true), (2500, false)] {
            let (first, second, ups) =
                hedged_pair(Reply::Silent, Reply::Silent, 10.0, UDP_WAIT).await;
            // Without a figure nothing is held back, and the resend point is the first one.
            ups.shared.state().latency_ms = None;
            let (answer, took) = run_after_a_stall(&ups, "example.com", ms(stall)).await;
            assert!(answer.is_none(), "{stall} ms: {answer:?}");
            assert!(
                took >= ms(stall.max(2000)) && took < ms(stall.max(2000) + 10),
                "{stall} ms: took {took:?}"
            );
            sleep(ms(100)).await;
            let queries = if resent { 2 } else { 1 };
            assert_eq!(
                (first.udp_queries(), second.udp_queries()),
                (queries, queries),
                "{stall} ms"
            );
            assert_eq!(
                (ups.sent(), ups.failures()),
                (2 * queries as u64, 2),
                "{stall} ms"
            );
        }
    }

    // Task 3 review m6: nothing went out when the one socket cannot be sent on
    #[tokio::test]
    async fn a_resend_that_sends_nothing_says_so() {
        let closed = closed_port();
        let ups = Upstreams::with(vec![closed], ms(300), ms(600));
        let mut resolver = Resolver::new(BlockSet::default());
        let question = pending(&mut resolver, "example.com");
        let query = question.upstream_query(7);
        let socket = send_udp(closed, &query).await.unwrap();
        let mut legs = Legs {
            live: vec![Leg::new(0, 7, query, Instant::now(), socket)],
            buf: Vec::new(),
            first: 0,
        };
        // The refused port has sent its ICMP message back by now, and the socket holds the error.
        sleep(ms(50)).await;
        assert!(!legs.resend(&ups.shared, 1));
        assert!(legs.live.is_empty());
        assert_eq!((ups.failures(), ups.sent()), (1, 0));
    }

    /// A socket of ours connected to a peer, and the peer, which is connected to it.
    async fn connected_pair() -> (UdpSocket, std::net::UdpSocket) {
        let peer = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let ours = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        ours.connect(peer.local_addr().unwrap()).await.unwrap();
        peer.connect(ours.local_addr().unwrap()).unwrap();
        (ours, peer)
    }

    #[tokio::test]
    async fn a_socket_that_always_has_a_packet_does_not_keep_the_others_from_a_turn() {
        // The first socket has fifty packets queued, the second one.
        let (first, first_peer) = connected_pair().await;
        let (second, second_peer) = connected_pair().await;
        for _ in 0..50 {
            first_peer.send(&[0u8; HEADER_LEN]).unwrap();
        }
        second_peer.send(&[1u8; HEADER_LEN]).unwrap();
        let mut legs = Legs {
            live: vec![
                Leg::new(0, 0, Vec::new(), Instant::now(), first),
                Leg::new(1, 0, Vec::new(), Instant::now(), second),
            ],
            buf: vec![0u8; UDP_BUFFER],
            first: 0,
        };
        let mut clock = pin!(tokio::time::sleep(ms(5000)));
        let mut seen = Vec::new();
        for _ in 0..2 {
            match legs.next(&mut clock).await {
                Event::Packet(position, _) => seen.push(position),
                _ => panic!("a packet was there"),
            }
        }
        assert_eq!(seen, [0, 1]);
    }

    /// A clock for [`note`] that is a minute on at each reading: no rate limit is in the way.
    fn a_minute_apart() -> impl FnMut() -> tokio::time::Instant {
        let mut now = tokio::time::Instant::now();
        move || {
            now += HEALTH_LOG_EVERY;
            now
        }
    }

    #[test]
    fn three_misses_in_a_row_are_reported_once_and_the_next_answer_is_too() {
        let mut later = a_minute_apart();
        let mut health = Health::default();
        assert_eq!(note(&mut health, false, later()), None);
        assert_eq!(note(&mut health, false, later()), None);
        assert_eq!(note(&mut health, false, later()), Some(Change::Silent));
        assert_eq!(note(&mut health, false, later()), None);
        assert_eq!(note(&mut health, true, later()), Some(Change::Answers));
        assert_eq!(note(&mut health, true, later()), None);

        // An answer in between starts the count again, and says nothing.
        let mut health = Health::default();
        assert_eq!(note(&mut health, false, later()), None);
        assert_eq!(note(&mut health, false, later()), None);
        assert_eq!(note(&mut health, true, later()), None);
        assert_eq!(note(&mut health, false, later()), None);
        assert_eq!(note(&mut health, false, later()), None);
        assert_eq!(note(&mut health, false, later()), Some(Change::Silent));
    }

    // Final review M1
    #[test]
    fn an_upstream_that_answers_some_of_the_time_is_logged_once_a_minute_at_most() {
        let start = tokio::time::Instant::now();
        let at = |secs| start + Duration::from_secs(secs);
        let mut health = Health::default();

        // Silent: said at once.
        assert_eq!(note(&mut health, false, at(0)), None);
        assert_eq!(note(&mut health, false, at(1)), None);
        assert_eq!(note(&mut health, false, at(2)), Some(Change::Silent));
        // It answers, and is silent again within the minute: the state changes, the log says
        // nothing, and what it said last (silent) is still right.
        assert_eq!(note(&mut health, true, at(3)), None);
        assert_eq!(health.misses, 0);
        for secs in [4, 5, 6] {
            assert_eq!(note(&mut health, false, at(secs)), None);
        }
        assert_eq!(health.misses, 3);
        // It answers for good: said once the minute since the last line is over.
        assert_eq!(note(&mut health, true, at(30)), None);
        assert_eq!(note(&mut health, true, at(61)), None);
        assert_eq!(note(&mut health, true, at(62)), Some(Change::Answers));
        assert_eq!(note(&mut health, true, at(63)), None);

        // Silent for good, within a minute of that line: said with the first miss after it.
        for secs in [64, 65, 66, 100, 121] {
            assert_eq!(note(&mut health, false, at(secs)), None, "{secs} s");
        }
        assert_eq!(note(&mut health, false, at(122)), Some(Change::Silent));
        assert_eq!(note(&mut health, false, at(123)), None);
        assert_eq!(health.misses, 7);
    }

    #[test]
    #[should_panic(expected = "must be IPv4")]
    fn an_upstream_that_is_not_ipv4_is_refused() {
        let v6 = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, UPSTREAM_PORT));
        Upstreams::with(vec![v6], ms(300), ms(600));
    }

    #[test]
    fn only_a_response_that_failed_or_refused_is_a_refusal() {
        /// A header that holds `flags` and the response code `code` in its low nibble.
        fn header(flags: u8, code: u8) -> [u8; HEADER_LEN] {
            let mut header = [0u8; HEADER_LEN];
            header[2] = flags;
            header[3] = code;
            header
        }
        const RESPONSE: u8 = 0x80;
        // SERVFAIL, NOTIMP and REFUSED; the other bits of the byte do not matter.
        for code in [2, 4, 5, 0x82, 0x35] {
            assert!(is_refusal(&header(RESPONSE, code)), "code {code}");
        }
        // NOERROR, FORMERR, NXDOMAIN, YXDOMAIN, and a code of 16 or more, which has no bit here.
        for code in [0, 1, 3, 6, 9, 0x10] {
            assert!(!is_refusal(&header(RESPONSE, code)), "code {code}");
        }
        // A packet that does not say it is a response is nothing for the race to set aside.
        assert!(!is_refusal(&header(0, 5)));
        assert!(!is_refusal(&[0x80, 5]));
    }

    /// A query under `id`, or, if `response`, a SERVFAIL response, with these questions.
    fn message(id: u16, response: bool, questions: &[(&str, RecordType, DNSClass)]) -> Vec<u8> {
        let mut message = if response {
            let mut message = Message::response(id, OpCode::Query);
            message.metadata.response_code = ResponseCode::ServFail;
            message
        } else {
            Message::new(id, MessageType::Query, OpCode::Query)
        };
        for &(name, kind, class) in questions {
            let mut asked = Query::query(Name::from_ascii(name).unwrap(), kind);
            asked.query_class = class;
            message.add_query(asked);
        }
        message.to_vec().unwrap()
    }

    // Final review M2
    #[test]
    fn a_packet_is_for_the_question_of_the_query_when_the_name_the_type_and_the_class_are() {
        let mut resolver = Resolver::new(BlockSet::default());
        // The query as it goes out upstream, with its OPT record, for a name spelt in mixed case.
        let query = pending(&mut resolver, "Example.COM").upstream_query(0x1234);
        let failure = |name, kind, class| message(0x1234, true, &[(name, kind, class)]);
        let (a, aaaa, internet) = (RecordType::A, RecordType::AAAA, DNSClass::IN);
        // The same question, in any case.
        for name in ["Example.COM", "example.com", "EXAMPLE.COM", "eXaMpLe.CoM"] {
            assert!(asks_the_same(&query, &failure(name, a, internet)), "{name}");
        }
        // Another name, however near, another type, another class.
        for name in [
            "example.net",
            "www.example.com",
            "com",
            "xexample.com",
            "example.co",
            ".",
        ] {
            assert!(
                !asks_the_same(&query, &failure(name, a, internet)),
                "{name}"
            );
        }
        assert!(!asks_the_same(
            &query,
            &failure("example.com", aaaa, internet)
        ));
        assert!(!asks_the_same(
            &query,
            &failure("example.com", a, DNSClass::CH)
        ));
        // What cannot be read as that question: none, two (the first the right one), a name that
        // stops, a pointer where the name is, and a packet that is no more than its header.
        assert!(!asks_the_same(&query, &message(0x1234, true, &[])));
        let right = ("example.com", a, internet);
        assert!(!asks_the_same(
            &query,
            &message(0x1234, true, &[right, right])
        ));
        let whole = failure("example.com", a, internet);
        for cut in HEADER_LEN..HEADER_LEN + 17 {
            assert!(!asks_the_same(&query, &whole[..cut]), "cut at {cut}");
        }
        let mut pointer = whole.clone();
        pointer[HEADER_LEN..HEADER_LEN + 2].copy_from_slice(&[0xc0, 0x0c]);
        assert!(!asks_the_same(&query, &pointer));
        // A query that cannot be read is no question to compare with.
        assert!(!asks_the_same(&[0u8; HEADER_LEN], &whole));
        assert!(!asks_the_same(&[], &whole));
    }

    #[test]
    fn the_type_and_the_class_are_compared_exactly_and_not_by_letter() {
        // 65 and 97 differ by the case bit of an ASCII letter, which only the name ignores.
        let query = message(
            5,
            false,
            &[("example.com", RecordType::from(65), DNSClass::IN)],
        );
        let failure = |kind| message(5, true, &[("example.com", kind, DNSClass::IN)]);
        assert!(asks_the_same(&query, &failure(RecordType::from(65))));
        assert!(!asks_the_same(&query, &failure(RecordType::from(97))));
    }

    #[test]
    fn the_order_starts_at_the_preferred_and_wraps() {
        assert_eq!(order(1, 3).collect::<Vec<_>>(), [1, 2, 0]);
        assert_eq!(order(0, 1).collect::<Vec<_>>(), [0]);
    }

    #[test]
    fn latency_moves_an_eighth_of_the_way_to_each_sample() {
        assert_eq!(smoothed(None, 40.0), 40.0);
        assert_eq!(smoothed(Some(40.0), 8.0), 36.0);
    }

    // The exchange over TLS. The fakes are threads of real I/O, so none of these pauses the clock,
    // and the bounds are wide: a test that decides between "at once" and "after the hedge delay"
    // takes the quickest of several tries, which a slow machine cannot make slower than the
    // hedge delay for all of them.

    /// Waits until `ready` holds, for ten seconds at most, and panics with `what` if it does not.
    async fn until(what: &str, mut ready: impl FnMut() -> bool) {
        let end = Instant::now() + Duration::from_secs(10);
        while !ready() {
            assert!(Instant::now() < end, "timed out waiting for {what}");
            sleep(ms(5)).await;
        }
    }

    /// Waits until exactly `up` of the TLS connections of `ups` have a session.
    async fn until_up(ups: &Upstreams, up: usize) {
        until(
            &format!("{up} TLS sessions"),
            || matches!(ups.tls(), TlsState::On { up: now, .. } if now == up),
        )
        .await;
    }

    /// Two TLS fakes, the first the preferred, with two UDP fakes that answer `192.0.2.99`, and an
    /// `Upstreams` over them that has the way over TLS and has not switched it on.
    struct Rig {
        first: TlsFakeUpstream,
        second: TlsFakeUpstream,
        udp: [FakeUpstream; 2],
        ups: Upstreams,
    }

    impl Rig {
        async fn new(first: Reply, second: Reply, udp_wait: Duration) -> Self {
            let (first, second) = (
                TlsFakeUpstream::start(first),
                TlsFakeUpstream::start(second),
            );
            let udp = [
                FakeUpstream::start(Reply::Answer(ip("192.0.2.99"))).await,
                FakeUpstream::start(Reply::Answer(ip("192.0.2.99"))).await,
            ];
            let ups = Upstreams::with(vec![udp[0].addr, udp[1].addr], udp_wait, ms(600))
                .with_tls_at(
                    tls_for_fakes(&[&first, &second]),
                    vec![first.addr, second.addr],
                )
                .with_clear_names(["Time.Example.NET.".to_owned()]);
            Self {
                first,
                second,
                udp,
                ups,
            }
        }

        /// The switch is on and both sessions are up.
        async fn switched_on(self) -> Self {
            self.ups.start_tls();
            until_up(&self.ups, 2).await;
            self
        }
    }

    /// Sets the smoothed latency of `ups` to `figure_ms`, so that the hedge delay is twice that.
    fn figure(ups: &Upstreams, figure_ms: f32) {
        ups.shared.state().latency_ms = Some(figure_ms);
    }

    #[tokio::test]
    async fn before_start_tls_only_a_clear_name_goes_over_udp() {
        let rig = Rig::new(
            Reply::Answer(ip("192.0.2.10")),
            Reply::Answer(ip("192.0.2.20")),
            ms(2000),
        )
        .await;
        assert_eq!(rig.ups.tls(), TlsState::WaitingForClock);
        let (answer, _) = run(&rig.ups, "time.example.net").await;
        assert_eq!(answer.unwrap().v4(), [ip("192.0.2.99")]);
        sleep(ms(100)).await;
        assert_eq!((rig.first.queries(), rig.second.queries()), (0, 0));
        assert_eq!(rig.first.handshakes() + rig.second.handshakes(), 0);
        assert_eq!(rig.ups.sent(), 2);
    }

    #[tokio::test]
    async fn before_start_tls_any_other_name_is_sent_nowhere_and_fails_after_the_wait() {
        let rig = Rig::new(
            Reply::Answer(ip("192.0.2.10")),
            Reply::Answer(ip("192.0.2.20")),
            ms(300),
        )
        .await;
        let (answer, took) = run(&rig.ups, "example.com").await;
        assert!(answer.is_none());
        assert!(took >= ms(300) && took < ms(1500), "{took:?}");
        sleep(ms(100)).await;
        // Not over UDP, where it would be in the clear, and not over TLS, which is not on.
        assert_eq!(rig.ups.sent(), 0);
        assert_eq!((rig.first.queries(), rig.second.queries()), (0, 0));
        assert_eq!(rig.first.handshakes() + rig.second.handshakes(), 0);
        assert_eq!(rig.ups.failures(), 0);
        assert_eq!(rig.ups.tls(), TlsState::WaitingForClock);
    }

    #[tokio::test]
    async fn a_question_that_waits_for_the_switch_is_asked_over_tls_when_it_comes() {
        let rig = Rig::new(
            Reply::Answer(ip("192.0.2.10")),
            Reply::Answer(ip("192.0.2.20")),
            ms(5000),
        )
        .await;
        let ((answer, took), ()) = tokio::join!(run(&rig.ups, "example.com"), async {
            sleep(ms(150)).await;
            rig.ups.start_tls();
        });
        // The TLS fakes' answer, and not the UDP fakes' 192.0.2.99.
        let got = answer.unwrap().v4();
        assert!(
            got == [ip("192.0.2.10")] || got == [ip("192.0.2.20")],
            "{got:?}"
        );
        assert!(took >= ms(150) && took < ms(4000), "{took:?}");
        assert!(rig.first.queries() + rig.second.queries() >= 1);
    }

    #[tokio::test]
    async fn after_start_tls_a_question_goes_over_tls_only() {
        let rig = Rig::new(
            Reply::Answer(ip("192.0.2.10")),
            Reply::Answer(ip("192.0.2.20")),
            ms(2000),
        )
        .await
        .switched_on()
        .await;
        // The hedge is at 250 ms: the preferred is asked alone.
        figure(&rig.ups, 125.0);
        let (answer, _) = run(&rig.ups, "example.com").await;
        assert_eq!(answer.unwrap().v4(), [ip("192.0.2.10")]);
        until("the question to reach the fake", || {
            rig.first.queries() == 1
        })
        .await;
        sleep(ms(100)).await;
        assert_eq!(rig.second.queries(), 0);
        assert_eq!((rig.udp[0].udp_queries(), rig.udp[1].udp_queries()), (0, 0));
        assert_eq!((rig.ups.sent(), rig.ups.failures()), (0, 0));
        assert_eq!(rig.ups.preferred(), rig.udp[0].addr);
        // The statistics count the question that went over TLS.
        assert_eq!(rig.ups.queries(), 1);
    }

    #[tokio::test]
    async fn a_healthy_preferred_is_asked_alone() {
        // The second answers late: the first question, which has no figure to be held back by, is
        // asked of both, and the preferred one wins it.
        let rig = Rig::new(
            Reply::Answer(ip("192.0.2.10")),
            Reply::After(ms(300), ip("192.0.2.20")),
            ms(2000),
        )
        .await
        .switched_on()
        .await;
        let (answer, _) = run(&rig.ups, "example.com").await;
        assert_eq!(answer.unwrap().v4(), [ip("192.0.2.10")]);
        for _ in 0..20 {
            // Whatever a slow machine made of the figure, the hedge is at its longest.
            figure(&rig.ups, 125.0);
            let (answer, _) = run(&rig.ups, "example.org").await;
            assert_eq!(answer.unwrap().v4(), [ip("192.0.2.10")]);
        }
        until("the questions to reach the fake", || {
            rig.first.queries() == 21
        })
        .await;
        assert!(rig.second.queries() <= 1, "{}", rig.second.queries());
        assert_eq!(rig.ups.failures(), 0);
    }

    #[tokio::test]
    async fn a_slow_preferred_is_hedged_after_the_delay() {
        let rig = Rig::new(
            Reply::After(ms(1500), ip("192.0.2.10")),
            Reply::Answer(ip("192.0.2.20")),
            ms(2000),
        )
        .await
        .switched_on()
        .await;
        // The delay is 20 ms; the preferred would take 1.5 s.
        figure(&rig.ups, 10.0);
        let (answer, took) = run(&rig.ups, "example.com").await;
        assert_eq!(answer.unwrap().v4(), [ip("192.0.2.20")]);
        assert!(took < ms(1000), "took {took:?}");
        assert_eq!(rig.ups.preferred(), rig.udp[1].addr);
        // The sample is the hedge's own time, and no failure came of the slow one.
        assert!(
            rig.ups.latency_ms().unwrap() <= 10,
            "{:?}",
            rig.ups.latency_ms()
        );
        assert_eq!(rig.ups.failures(), 0);
    }

    #[tokio::test]
    async fn a_down_preferred_is_hedged_at_once() {
        let second = TlsFakeUpstream::start(Reply::Answer(ip("192.0.2.20")));
        let ups = Upstreams::with(vec![closed_port(), closed_port()], ms(2000), ms(2000))
            .with_tls_at(tls_for_fake(&second), vec![closed_port(), second.addr]);
        ups.start_tls();
        until_up(&ups, 1).await;
        // The hedge delay would be 250 ms. A machine that is slow makes one try slow; the quickest
        // of five is not slower than at once.
        let mut quickest = Duration::MAX;
        for _ in 0..5 {
            {
                let mut state = ups.shared.state();
                state.preferred = 0;
                state.latency_ms = Some(125.0);
            }
            let (answer, took) = run(&ups, "example.com").await;
            assert_eq!(answer.unwrap().v4(), [ip("192.0.2.20")]);
            quickest = quickest.min(took);
        }
        assert!(quickest < ms(200), "the quickest took {quickest:?}");
        // The down one failed each time, and the live one became the preferred one.
        assert_eq!((ups.failures(), ups.sent()), (5, 0));
        assert_eq!(ups.preferred(), ups.shared.servers[1]);
    }

    #[tokio::test]
    async fn a_refusal_waits_for_the_other_answer() {
        let rig = Rig::new(
            Reply::Refused,
            Reply::After(ms(100), ip("192.0.2.20")),
            ms(2000),
        )
        .await
        .switched_on()
        .await;
        let (answer, took) = run(&rig.ups, "example.com").await;
        let answer = answer.unwrap();
        assert_eq!((answer.rcode, answer.v4()), (0, vec![ip("192.0.2.20")]));
        assert!(took >= ms(90) && took < ms(1500), "took {took:?}");
        assert_eq!(rig.ups.preferred(), rig.udp[1].addr);
        // The refuser answered: it is no failure.
        assert_eq!(rig.ups.failures(), 0);
        assert!(rig.ups.not_answering().is_empty());
    }

    #[tokio::test]
    async fn refusals_alone_are_delivered_when_no_leg_is_left() {
        let rig = Rig::new(Reply::Refused, Reply::Refused, ms(2000))
            .await
            .switched_on()
            .await;
        let (answer, took) = run(&rig.ups, "example.com").await;
        assert_eq!(answer.unwrap().rcode, 5);
        assert!(took < ms(1500), "took {took:?}");
        // A refusal that is only a fallback is no upstream's answer time, and no preference.
        assert_eq!(
            (rig.ups.preferred(), rig.ups.latency_ms()),
            (rig.udp[0].addr, None)
        );
        assert_eq!(rig.ups.failures(), 0);
    }

    #[tokio::test]
    async fn an_answer_to_another_question_fails_its_leg_and_hedges_at_once() {
        let rig = Rig::new(
            Reply::OtherQuestionFirst(ip("192.0.2.10")),
            Reply::Answer(ip("192.0.2.20")),
            ms(2000),
        )
        .await
        .switched_on()
        .await;
        figure(&rig.ups, 125.0);
        let (answer, _) = run(&rig.ups, "example.com").await;
        assert_eq!(answer.unwrap().v4(), [ip("192.0.2.20")]);
        assert_eq!(rig.ups.failures(), 1);
        assert_eq!(rig.ups.preferred(), rig.udp[1].addr);
    }

    #[tokio::test]
    async fn all_down_still_gives_none_within_the_wait() {
        let ups = Upstreams::with(vec![closed_port(), closed_port()], ms(300), ms(300))
            .with_tls_at(tls_for_fakes(&[]), vec![closed_port(), closed_port()]);
        ups.start_tls();
        let (answer, took) = run(&ups, "example.com").await;
        assert!(answer.is_none());
        // The question waited for a session to the end of its wait, and not past it (the slack is
        // wide: this is no measure of the timer).
        assert!(took >= ms(250), "gave up after {took:?}");
        assert!(took < ms(300) + ms(1500), "took {took:?}");
        // Each upstream that had no session is a failure of this question, once, however many
        // rounds it took.
        assert_eq!(ups.failures(), 2);
        assert_eq!(ups.sent(), 0);
    }

    #[tokio::test]
    async fn a_question_right_after_start_tls_is_answered() {
        let rig = Rig::new(
            Reply::Answer(ip("192.0.2.10")),
            Reply::Answer(ip("192.0.2.20")),
            ms(5000),
        )
        .await;
        rig.ups.start_tls();
        // Not a handshake has run: no session is up, and the question must wait for one instead
        // of being given up on.
        assert!(matches!(
            rig.ups.tls(),
            TlsState::On {
                up: 0,
                counts: ConnCounts {
                    connects: 0,
                    resumed: 0,
                    ..
                }
            }
        ));
        let (answer, _) = run(&rig.ups, "example.com").await;
        let answer = answer.expect("a question that finds no session yet is answered, not failed");
        assert!(
            answer.v4() == [ip("192.0.2.10")] || answer.v4() == [ip("192.0.2.20")],
            "{:?}",
            answer.v4()
        );
        // Over TLS, and never over UDP.
        assert_eq!(rig.ups.sent(), 0);
        assert_eq!((rig.udp[0].udp_queries(), rig.udp[1].udp_queries()), (0, 0));
    }

    #[tokio::test]
    async fn a_question_while_both_sessions_reconnect_is_answered() {
        // Each fake closes a session after one answer, and the first question is asked of both
        // (there is no latency figure yet): both sessions end together.
        let mode = TlsMode {
            close_after: Some(1),
            ..TlsMode::default()
        };
        let first = TlsFakeUpstream::start_with(Reply::Answer(ip("192.0.2.10")), mode);
        let second = TlsFakeUpstream::start_with(Reply::Answer(ip("192.0.2.20")), mode);
        let options = ConnOptions {
            stall: ms(3000),
            backoff_min: ms(20),
            backoff_max: ms(100),
            min_lived: Duration::ZERO,
            idle: Duration::from_secs(60),
        };
        let ups = Upstreams::with(vec![closed_port(), closed_port()], ms(10_000), ms(10_000))
            .with_tls_at(
                tls_for_fakes(&[&first, &second]),
                vec![first.addr, second.addr],
            )
            .with_conn_options(options);
        ups.start_tls();
        until_up(&ups, 2).await;
        for name in ["example.com", "example.org", "example.net", "example.com"] {
            let (answer, _) = run(&ups, name).await;
            assert!(answer.is_some(), "{name} was not answered");
        }
        assert_eq!(ups.sent(), 0);
    }

    #[tokio::test]
    async fn tls_state_follows_the_switch() {
        let off = Upstreams::with(vec![closed_port()], ms(300), ms(300));
        assert_eq!(off.tls(), TlsState::Off);
        // Switching on what is not there does nothing, and does not panic.
        off.start_tls();
        assert_eq!(off.tls(), TlsState::Off);

        let rig = Rig::new(
            Reply::Answer(ip("192.0.2.10")),
            Reply::Answer(ip("192.0.2.20")),
            ms(300),
        )
        .await;
        assert_eq!(rig.ups.tls(), TlsState::WaitingForClock);
        rig.ups.start_tls();
        until_up(&rig.ups, 2).await;
        assert!(matches!(
            rig.ups.tls(),
            TlsState::On {
                up: 2,
                counts: ConnCounts {
                    connects: 2,
                    resumed: 0,
                    ..
                }
            }
        ));
    }

    #[tokio::test]
    async fn start_tls_twice_opens_one_set() {
        let rig = Rig::new(
            Reply::Answer(ip("192.0.2.10")),
            Reply::Answer(ip("192.0.2.20")),
            ms(300),
        )
        .await;
        rig.ups.start_tls();
        until_up(&rig.ups, 2).await;
        rig.ups.start_tls();
        rig.ups.start_tls();
        sleep(ms(200)).await;
        until("the servers to count both handshakes", || {
            rig.first.handshakes() + rig.second.handshakes() == 2
        })
        .await;
        assert!(matches!(
            rig.ups.tls(),
            TlsState::On {
                up: 2,
                counts: ConnCounts { connects: 2, .. },
            }
        ));
        assert_eq!(rig.first.handshakes() + rig.second.handshakes(), 2);
    }

    #[tokio::test]
    async fn the_upstreams_are_asked_on_the_tls_port_at_their_own_addresses() {
        let fake = TlsFakeUpstream::start(Reply::Answer(ip("192.0.2.10")));
        // The upstream's address is the fake's, at port 53; its TLS service is at the fake's port.
        let ups = Upstreams::with(
            vec![SocketAddr::from((Ipv4Addr::LOCALHOST, UPSTREAM_PORT))],
            ms(2000),
            ms(2000),
        )
        .with_tls(tls_for_fake(&fake), fake.addr.port());
        ups.start_tls();
        until_up(&ups, 1).await;
        let (answer, _) = run(&ups, "example.com").await;
        assert_eq!(answer.unwrap().v4(), [ip("192.0.2.10")]);
    }

    #[tokio::test]
    async fn only_the_first_upstreams_that_a_question_goes_to_have_a_connection() {
        let fakes: Vec<_> = (0..MAX_RACED + 2)
            .map(|_| TlsFakeUpstream::start(Reply::Silent))
            .collect();
        let refs: Vec<&TlsFakeUpstream> = fakes.iter().collect();
        let ups = Upstreams::with(
            fakes.iter().map(|_| closed_port()).collect(),
            ms(300),
            ms(300),
        )
        .with_tls_at(
            tls_for_fakes(&refs),
            fakes.iter().map(|fake| fake.addr).collect(),
        );
        // A preferred upstream past the connections, as the UDP exchange may have left it.
        ups.shared.state().preferred = MAX_RACED + 1;
        ups.start_tls();
        until_up(&ups, MAX_RACED).await;
        let (answer, _) = run(&ups, "example.com").await;
        assert!(answer.is_none());
        assert!(fakes[MAX_RACED..].iter().all(|fake| fake.handshakes() == 0));
    }

    /// The counts of the TLS connections of `ups`, which has switched TLS on.
    fn tls_counts(ups: &Upstreams) -> ConnCounts {
        match ups.tls() {
            TlsState::On { counts, .. } => counts,
            other => panic!("TLS is not on: {other:?}"),
        }
    }

    #[tokio::test]
    async fn after_an_idle_close_the_next_question_is_answered_and_nothing_failed() {
        let mut rig = Rig::new(
            Reply::Answer(ip("192.0.2.10")),
            Reply::Answer(ip("192.0.2.20")),
            ms(2000),
        )
        .await;
        rig.ups = rig.ups.with_conn_options(ConnOptions {
            idle: ms(200),
            ..ConnOptions::default()
        });
        rig.ups.start_tls();
        until_up(&rig.ups, 2).await;
        // The first sessions carried no question: they are closed for being idle, and none is
        // opened in their place.
        until("both idle closes", || tls_counts(&rig.ups).idle_closes == 2).await;
        until_up(&rig.ups, 0).await;
        figure(&rig.ups, 125.0);
        let (answer, took) = run(&rig.ups, "example.com").await;
        let answer = answer.expect("the question after the idle close was not answered");
        assert!(
            answer.v4() == [ip("192.0.2.10")] || answer.v4() == [ip("192.0.2.20")],
            "{:?}",
            answer.v4()
        );
        assert!(took < ms(1500), "took {took:?}");
        // No failure, nothing silent, and no sample of the handshake's time.
        assert_eq!(rig.ups.failures(), 0);
        assert!(rig.ups.not_answering().is_empty());
        assert_eq!(rig.ups.latency_ms(), Some(125));
        // Both connections were opened again: the question was hedged at once.
        until("both new sessions", || tls_counts(&rig.ups).connects == 4).await;
        assert_eq!((tls_counts(&rig.ups).server_closes, rig.ups.sent()), (0, 0));
    }

    #[tokio::test]
    async fn a_question_that_met_the_servers_close_is_sent_again_and_nothing_failed() {
        // The preferred one closes a session as it reads its second query, and answers that
        // query on the next session; the other never answers, so that only the question sent
        // again can answer it.
        let mode = TlsMode {
            close_on_query: Some(2),
            ..TlsMode::default()
        };
        let first = TlsFakeUpstream::start_with(Reply::Answer(ip("192.0.2.10")), mode);
        let second = TlsFakeUpstream::start(Reply::Silent);
        let ups = Upstreams::with(vec![closed_port(), closed_port()], ms(2000), ms(2000))
            .with_tls_at(
                tls_for_fakes(&[&first, &second]),
                vec![first.addr, second.addr],
            );
        ups.start_tls();
        until_up(&ups, 2).await;
        figure(&ups, 125.0);
        let (answer, _) = run(&ups, "example.com").await;
        assert_eq!(answer.unwrap().v4(), [ip("192.0.2.10")]);
        figure(&ups, 125.0);
        let (answer, took) = run(&ups, "example.org").await;
        assert_eq!(answer.unwrap().v4(), [ip("192.0.2.10")]);
        assert!(took < ms(1500), "took {took:?}");
        let counts = tls_counts(&ups);
        assert_eq!((counts.retried, counts.server_closes), (1, 1));
        // The session that ended is no failure, and the hedge that lost is not counted.
        assert_eq!(ups.failures(), 0);
        assert_eq!(ups.preferred(), ups.shared.servers[0]);
        // The close hedged the question at once: the other upstream had it too.
        until("the hedge", || second.queries() == 1).await;
        assert_eq!(ups.queries(), counts.asked);
    }

    #[tokio::test]
    async fn the_server_closing_every_idle_session_costs_no_failure_over_many_questions() {
        // A server that closes a session idle for 100 ms, and questions that come 150 ms apart:
        // each finds the session it was on closed, and reopened.
        let mode = TlsMode {
            idle_close: Some(ms(100)),
            ..TlsMode::default()
        };
        let first = TlsFakeUpstream::start_with(Reply::Answer(ip("192.0.2.10")), mode);
        let second = TlsFakeUpstream::start_with(Reply::Answer(ip("192.0.2.20")), mode);
        let options = ConnOptions {
            min_lived: ms(50),
            ..ConnOptions::default()
        };
        let ups = Upstreams::with(vec![closed_port(), closed_port()], ms(2000), ms(2000))
            .with_tls_at(
                tls_for_fakes(&[&first, &second]),
                vec![first.addr, second.addr],
            )
            .with_conn_options(options);
        ups.start_tls();
        until_up(&ups, 2).await;
        for _ in 0..10 {
            let (answer, _) = run(&ups, "example.com").await;
            assert!(answer.is_some());
            sleep(ms(150)).await;
        }
        assert!(
            tls_counts(&ups).server_closes >= 5,
            "{:?}",
            tls_counts(&ups)
        );
        assert_eq!(ups.failures(), 0);
        assert!(ups.not_answering().is_empty());
    }

    /// The time of a question that finds its connections idle, and so waits for a handshake,
    /// against a warm one, on the loopback: p50 and p95 of 30 each, in microseconds. Run it on its
    /// own in release: `cargo test -p qberrypi --release cold_and_warm -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore = "a timing measurement: run it in release, on its own"]
    async fn cold_and_warm_questions_over_tls_on_loopback() {
        const EXCHANGES: usize = 30;
        let fake = TlsFakeUpstream::start(Reply::Answer(ip("192.0.2.10")));
        let ups = Upstreams::with(vec![closed_port()], ms(2000), ms(2000))
            .with_tls_at(tls_for_fake(&fake), vec![fake.addr])
            .with_conn_options(ConnOptions {
                idle: ms(100),
                ..ConnOptions::default()
            });
        ups.start_tls();
        until_up(&ups, 1).await;
        let (mut warm, mut cold) = (Vec::new(), Vec::new());
        for _ in 0..EXCHANGES {
            // Warm: right after another question.
            assert!(run(&ups, "example.com").await.0.is_some());
            let (answer, took) = run(&ups, "example.com").await;
            assert!(answer.is_some());
            warm.push(took);
            // Cold: once the session and the one that replaced it have both idled out.
            until_up(&ups, 1).await;
            sleep(ms(150)).await;
            until_up(&ups, 0).await;
            sleep(ms(150)).await;
            until_up(&ups, 0).await;
            let (answer, took) = run(&ups, "example.com").await;
            assert!(answer.is_some());
            cold.push(took);
        }
        for (way, took) in [("warm", &mut warm), ("cold", &mut cold)] {
            took.sort();
            println!(
                "{way}: {EXCHANGES} exchanges on the loopback, p50 {} us, p95 {} us",
                percentile(took, 50),
                percentile(took, 95)
            );
        }
        println!("{:?}", tls_counts(&ups));
        assert_eq!(ups.failures(), 0);
    }

    /// The real Quad9 servers, through the real exchange: warm questions a few times a second,
    /// then questions after 20 s of silence, which find both connections idle. Polite: about 100
    /// questions over three minutes. `cargo test -p qberrypi --release quad9_through -- --ignored
    /// --nocapture`.
    #[tokio::test]
    #[ignore = "reaches the real Quad9"]
    async fn quad9_through_the_exchange_warm_and_cold() {
        let tls = TlsUpstream {
            name: rustls::pki_types::ServerName::try_from("dns.quad9.net").unwrap(),
            config: crate::https::client_config(crate::https::mozilla_roots()),
        };
        let ups = Upstreams::new(&[Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(149, 112, 112, 112)])
            .with_tls(tls, super::super::dot::DOT_PORT);
        ups.start_tls();
        until_up(&ups, 2).await;
        let names = ["example.com", "example.org", "example.net", "iana.org"];
        let mut warm = Vec::new();
        for round in 0..80 {
            let (answer, took) = run(&ups, names[round % names.len()]).await;
            assert!(answer.is_some());
            if round >= 8 {
                warm.push(took);
            }
            sleep(ms(250)).await;
        }
        let mut cold = Vec::new();
        for round in 0..6 {
            sleep(Duration::from_secs(20)).await;
            let idle = ups.tls();
            let (answer, took) = run(&ups, names[round % names.len()]).await;
            assert!(answer.is_some());
            println!("cold {round}: {took:?} (before it: {idle:?})");
            cold.push(took);
        }
        warm.sort();
        cold.sort();
        println!(
            "warm: {} exchanges, p50 {} us, p95 {} us; cold: {} exchanges, p50 {} us, max {} us",
            warm.len(),
            percentile(&warm, 50),
            percentile(&warm, 95),
            cold.len(),
            percentile(&cold, 50),
            percentile(&cold, 100),
        );
        println!(
            "failures {}, queries {}, {:?}",
            ups.failures(),
            ups.queries(),
            ups.tls()
        );
    }

    /// The `p`th percentile of `sorted`, which is sorted, in microseconds.
    fn percentile(sorted: &[Duration], p: usize) -> u128 {
        sorted[(sorted.len() * p / 100).min(sorted.len() - 1)].as_micros()
    }

    /// The round trip of an exchange over UDP and one over a warm TLS connection, both to a
    /// responder on a thread of its own on the loopback: p50 and p95 of 200 each, in microseconds.
    /// (The UDP fake of the other tests answers from a task that sleeps first, and tokio's timer
    /// ticks at a millisecond: its figure would be that tick and not the exchange.) Run it on its
    /// own in release: `cargo test -p qberrypi --release tls_and_udp_round_trips -- --ignored
    /// --nocapture`.
    #[tokio::test]
    #[ignore = "a timing measurement: run it in release, on its own"]
    async fn tls_and_udp_round_trips_on_loopback() {
        const EXCHANGES: usize = 200;
        // The UDP responder sends each query back as a response with no record: an answer.
        let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket.set_read_timeout(Some(ms(50))).unwrap();
        let udp_addr = socket.local_addr().unwrap();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopping = stop.clone();
        let responder = std::thread::spawn(move || {
            let mut buf = [0u8; UDP_BUFFER];
            while !stopping.load(Ordering::Relaxed) {
                if let Ok((len, from)) = socket.recv_from(&mut buf) {
                    buf[2] |= 0x80;
                    let _ = socket.send_to(&buf[..len], from);
                }
            }
        });
        let tls_fake = TlsFakeUpstream::start(Reply::Answer(ip("192.0.2.10")));
        let udp = Upstreams::with(vec![udp_addr], ms(2000), ms(2000));
        let tls = Upstreams::with(vec![udp_addr], ms(2000), ms(2000))
            .with_tls_at(tls_for_fake(&tls_fake), vec![tls_fake.addr]);
        tls.start_tls();
        until_up(&tls, 1).await;
        let mut figures = Vec::new();
        for (way, ups) in [("UDP", &udp), ("TLS", &tls)] {
            // Warm: the first exchanges pay for page faults and the first send.
            for _ in 0..20 {
                assert!(run(ups, "example.com").await.0.is_some());
            }
            let mut took = Vec::with_capacity(EXCHANGES);
            for _ in 0..EXCHANGES {
                let (answer, one) = run(ups, "example.com").await;
                assert!(answer.is_some());
                took.push(one);
            }
            took.sort();
            let (p50, p95) = (percentile(&took, 50), percentile(&took, 95));
            println!("{way}: {EXCHANGES} exchanges on the loopback, p50 {p50} us, p95 {p95} us");
            figures.push(p95);
            assert_eq!(ups.failures(), 0);
        }
        stop.store(true, Ordering::Relaxed);
        responder.join().unwrap();
        // Loopback, no crypto to speak of on a warm session: nowhere near a hedge delay.
        assert!(figures.iter().all(|&p95| p95 < 20_000), "{figures:?}");
        assert_eq!(tls.sent(), 0);
    }
}
