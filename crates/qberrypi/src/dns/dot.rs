//! One pipelined DNS-over-TLS connection to an upstream resolver (RFC 7858), kept up while it is
//! used.
//!
//! A [`Conn`] is a task on the runtime that owns at most one TLS session with one upstream. It
//! opens the first session as soon as it is spawned, so that the first question finds it up. Many
//! questions are out on a session at once, each under an ID of its own on that session, and an
//! answer finds its question by that ID, in whatever order the answers come.
//!
//! A session that has had no question open for its idle time is closed by the task itself, with
//! the TLS close notice: [`IDLE_CLOSE`], just under the 10 s after which Quad9 closes an idle
//! session (measured on 2026-11-11), or, when the server advertises its idle timeout with the
//! edns-tcp-keepalive option (RFC 7828, which every question carries), a little less than that
//! timeout. A server that advertises a timeout of 0 is drained: no new question goes out on the
//! session, and it is closed once its last answer has come. Closing first means that no question
//! is written into a session that the server is closing (Quad9 drops those), and that the
//! TIME-WAIT is ours (RFC 7766 §6.2.3). The next session is opened at once if the one that ended
//! carried a question, so that a household that asks every few seconds finds one up; otherwise it
//! is opened by the next question (or [`Conn::wake`]), and a quiet household opens none.
//!
//! A session that the server ends (with the close notice, the end of the stream, or a reset)
//! is no failure either. The questions that were open on it are sent once more on the next
//! session, which is opened at once (RFC 7766 §6.2.1 and RFC 7858 §3.4: a client is prepared to
//! reconnect and retry); one that was open on a second session that ended too fails with
//! `NotConnected`. The asker bounds how long that takes, as with any question.
//!
//! The expensive part of a session is its handshake (the certificate checks and the key
//! exchange, which a Cortex-A53 without AES instructions does in pure Rust): it runs on a thread
//! of its own, named `tls handshake`, started for each handshake and ended with it, never on the
//! runtime thread and never on the blocking pool. Not on the pool, because a handshake that
//! queued there behind a list parse or a snapshot load would leave every question without a
//! session to wait for it (the resolver does not go back to UDP once it has switched to TLS):
//! the time of the handshake is the same whatever else the board does. A connection has at most
//! one handshake at a time, so there are as many such threads as there are connections
//! ([`MAX_RACED`](super::upstream::MAX_RACED) at most), and the pool stays as wide as it is. The
//! thread leaves the runtime's core, if the runtime is pinned to one
//! ([`spawn_off_runtime_core`]). The records of an established session are small, and are sealed
//! and opened in the task. Every handshake offers a session ticket of an earlier session with the
//! same upstream, from a store that is this connection's own: the tickets of one address are
//! refused by the other (Quad9 resumes none across its two addresses), and a ticket is used once.
//!
//! Bounds, all of them fixed here or in [`MAX_FORWARDS`]:
//! - the TCP connect waits [`CONNECT_WAIT`], and the handshake [`HANDSHAKE_WAIT`] from its first
//!   byte to its last, however its peer trickles;
//! - the ask queue holds [`MAX_FORWARDS`] questions, and as many can be out on the session: one
//!   more is refused at once; so are the questions to be sent again;
//! - a question is at most [`MAX_QUERY`] bytes;
//! - what is held of the plaintext of the session is at most [`PLAIN_MAX`] bytes;
//! - a session whose oldest open question is `stall` old, and from which not a byte was read since
//!   that question was sent, is closed, which ends every question that is open on it with an
//!   error (a path that went silent without a close, a NAT that lost its state); on a session
//!   that is still being read, such a question alone ends, with a `TimedOut` for its asker, so
//!   that one name that the upstream never answers does not cost the answers of all the others
//!   their session;
//! - a reconnect waits [`BACKOFF_MIN`], doubling to [`BACKOFF_MAX`] (see [`backoff`]) for as long
//!   as the sessions end sooner than [`MIN_LIVED`] after they began, or cannot be opened at all:
//!   a handshake that completes is no reason to start over, a session that lived is.
//!
//! While the connection is down (the last attempt failed, and the backoff is being waited out),
//! [`Conn::ask`] fails at once, so whoever asks can turn to another upstream without waiting.
//! While a session is being opened, or none is wanted, a question waits in the queue for the
//! next session. [`Conn::link`] says which it is.
//!
//! Nothing here logs a name that is asked for. A failure to open a session is logged at most
//! once a minute for each connection, and the line names the upstream's address and the kind of
//! failure, and nothing the upstream sent. A session that ends as a server ends idle sessions
//! logs nothing.

use std::collections::HashMap;
use std::future::Future;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream as StdTcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rustls::client::Resumption;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, HandshakeKind};
use tokio::io::Interest;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, sleep_until, timeout};

use super::MAX_FORWARDS;
use super::upstream::UDP_WAIT;
use crate::cpu::spawn_off_runtime_core;
use crate::sys;

/// The port of a DNS-over-TLS server.
pub const DOT_PORT: u16 = 853;
/// How old the oldest open question of a session may be before the session is closed: as long as
/// the whole wait of an exchange over UDP.
pub const STALL_AFTER: Duration = UDP_WAIT;
/// How long a session must have lived for the waits of the reconnects to start over when it ends:
/// a server that closes a session after a while is not one that is failing, and one that closes
/// every session at once is.
pub const MIN_LIVED: Duration = Duration::from_secs(5);
/// The wait before the first reconnect after a failure, and after a session that was too short.
pub const BACKOFF_MIN: Duration = Duration::from_millis(250);
/// The longest wait between two reconnects.
pub const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// The longest a handshake takes, from the first byte it sends to the last it reads.
pub const HANDSHAKE_WAIT: Duration = Duration::from_secs(3);
/// The longest wait for the TCP connection.
pub const CONNECT_WAIT: Duration = Duration::from_secs(2);
/// How long a session with no question open is kept when its server advertises no idle timeout.
/// Quad9 ignores edns-tcp-keepalive and closes a session that was idle for 10 s (10.1 to 11.3 s
/// were measured), and the questions written to it in that last second get no answer.
pub const IDLE_CLOSE: Duration = Duration::from_secs(9);
/// How much sooner than the idle timeout that a server advertises its session is closed: as much
/// as this, and half the timeout at most.
pub const KEEPALIVE_MARGIN: Duration = Duration::from_secs(1);
/// The longest question that is taken. A question to an upstream is a header, one name and an
/// OPT record, which is under 300 bytes; a longer one is refused.
pub const MAX_QUERY: usize = 4096;
/// The most plaintext bytes of a session that are held at once: room for two of the longest
/// messages that the two-byte length of a frame allows, each with that length.
pub const PLAIN_MAX: usize = 2 * (2 + u16::MAX as usize);

/// The most often that a failure to open a session is logged, for one connection.
const WARN_EVERY: Duration = Duration::from_secs(60);
/// The bytes of a DNS header: nothing shorter is a message, and the ID is its first two.
const HEADER_LEN: usize = 12;
/// How much of the plaintext of a session is taken from the TLS layer at a time.
const CHUNK: usize = 4096;
/// A time so far off that no wait comes to it: for a timer that is not wanted.
const FAR: Duration = Duration::from_secs(3600);
/// The type of the OPT record.
const OPT: u16 = 41;
/// The code of the edns-tcp-keepalive option (RFC 7828), whose timeout counts 100 ms units.
const KEEPALIVE: u16 = 11;
/// The session tickets that a connection keeps: Quad9 gives two with each full handshake.
const TICKETS: usize = 8;

/// Who to speak to over TLS, and how to check it.
#[derive(Clone)]
pub struct TlsUpstream {
    /// The name that the upstream's certificate must be valid for.
    pub name: ServerName<'static>,
    /// The client side: its roots and its protocols. Each connection resumes from a ticket store
    /// of its own, whatever this one holds.
    pub config: Arc<ClientConfig>,
}

/// The waits of a [`Conn`], which tests shorten.
#[derive(Clone, Debug)]
pub(crate) struct ConnOptions {
    /// How old the oldest open question may be before the session is closed.
    pub(crate) stall: Duration,
    /// The wait before the first reconnect, doubled by each one that fails.
    pub(crate) backoff_min: Duration,
    /// The longest wait between two reconnects.
    pub(crate) backoff_max: Duration,
    /// How long a session must have lived for the waits of the reconnects to start over.
    pub(crate) min_lived: Duration,
    /// How long a session with no question open is kept, unless its server advertises its own
    /// idle timeout.
    pub(crate) idle: Duration,
}

impl Default for ConnOptions {
    /// [`STALL_AFTER`], [`BACKOFF_MIN`], [`BACKOFF_MAX`], [`MIN_LIVED`] and [`IDLE_CLOSE`].
    fn default() -> Self {
        Self {
            stall: STALL_AFTER,
            backoff_min: BACKOFF_MIN,
            backoff_max: BACKOFF_MAX,
            min_lived: MIN_LIVED,
            idle: IDLE_CLOSE,
        }
    }
}

/// The wait before the next reconnect, when the one before it waited `previous`: `backoff_min` for
/// the first, then double the last, and never more than `backoff_max`.
fn backoff(previous: Option<Duration>, options: &ConnOptions) -> Duration {
    previous
        .map_or(options.backoff_min, |last| last.saturating_mul(2))
        .min(options.backoff_max)
}

/// The idle time of a session whose server advertised `timeout`: [`KEEPALIVE_MARGIN`] less, and
/// half of it at the least.
fn idle_for(timeout: Duration) -> Duration {
    timeout.saturating_sub(KEEPALIVE_MARGIN).max(timeout / 2)
}

/// What a connection is doing about its session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Link {
    /// A session is being opened: a question waits for it.
    Opening,
    /// A session is up.
    Up,
    /// No session, and none is wanted until a question comes: a question opens one, and waits
    /// for it.
    Idle,
    /// The last attempt failed, and the backoff is being waited out: a question fails at once.
    Down,
}

/// What a [`Conn`] and its task both see.
struct Shared {
    /// What the connection is doing: set before the questions that are open on a session that
    /// ended are told. Watched, so that a question can wait for a change.
    link: watch::Sender<Link>,
    /// The handshakes that were completed.
    connects: AtomicU64,
    /// Of those, the ones that resumed a session.
    resumed: AtomicU64,
    /// The questions written to a session, each one sent again counted once more.
    asked: AtomicU64,
    /// The sessions that were closed here for being idle.
    idle_closes: AtomicU64,
    /// The sessions that the server ended: the close notice, the end of the stream, or a reset.
    server_closes: AtomicU64,
    /// The questions that were sent again on a new session, after the server ended theirs.
    retried: AtomicU64,
}

impl Shared {
    /// A connection that is opening its first session, and has completed no handshake.
    fn new() -> Self {
        Self {
            link: watch::Sender::new(Link::Opening),
            connects: AtomicU64::new(0),
            resumed: AtomicU64::new(0),
            asked: AtomicU64::new(0),
            idle_closes: AtomicU64::new(0),
            server_closes: AtomicU64::new(0),
            retried: AtomicU64::new(0),
        }
    }

    fn set(&self, link: Link) {
        self.link.send_if_modified(|now| {
            let changed = *now != link;
            *now = link;
            changed
        });
    }
}

/// What a connection has done since it was spawned.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConnCounts {
    /// The handshakes that were completed, resumed or not.
    pub connects: u64,
    /// Of those, the ones that resumed an earlier session.
    pub resumed: u64,
    /// The questions written to a session, each one sent again counted once more.
    pub asked: u64,
    /// The sessions closed here for being idle.
    pub idle_closes: u64,
    /// The sessions that the server ended.
    pub server_closes: u64,
    /// The questions sent again on a new session after the server ended theirs.
    pub retried: u64,
}

/// A question on its way to the task.
struct Request {
    /// The whole frame: the length in two bytes, and then the message, whose ID the task replaces.
    /// Empty for a wake ([`Conn::wake`]), which nothing is sent for.
    frame: Vec<u8>,
    /// Where the answer, or the failure, goes.
    reply: oneshot::Sender<io::Result<Vec<u8>>>,
    /// Whether it was open on a session that ended already: it is not sent a third time.
    again: bool,
}

/// One TLS connection to one upstream. See the module documentation.
///
/// The task that runs it is aborted when the `Conn` is dropped, and the questions that are open
/// end with an error. (A handshake that is running on its thread at that moment is not stopped; it
/// ends within [`HANDSHAKE_WAIT`], and its result is dropped.)
pub(crate) struct Conn {
    /// What the task shows: what it is doing, and the counts.
    shared: Arc<Shared>,
    /// The queue of questions to the task: [`MAX_FORWARDS`] at most.
    asks: mpsc::Sender<Request>,
    /// The task, which is aborted when the `Conn` is dropped.
    task: JoinHandle<()>,
}

impl Conn {
    /// Starts the task on the current runtime, which opens a session to `server` at once. Panics
    /// outside a runtime.
    pub(crate) fn spawn(server: SocketAddr, tls: TlsUpstream, options: ConnOptions) -> Conn {
        // A ticket store of this connection's own: see the module documentation.
        let mut config = (*tls.config).clone();
        config.resumption = Resumption::in_memory_sessions(TICKETS);
        let tls = TlsUpstream {
            name: tls.name,
            config: Arc::new(config),
        };
        let shared = Arc::new(Shared::new());
        let (asks, queue) = mpsc::channel(MAX_FORWARDS);
        let task = tokio::spawn(keep_up(server, tls, options, shared.clone(), queue));
        Conn { shared, asks, task }
    }

    /// Asks `query`, a whole DNS message, and gives the answer when it comes: the whole message,
    /// with the ID that `query` had (the session's own IDs are not shown). The question goes out
    /// with the edns-tcp-keepalive option added to its OPT record, if it has one.
    ///
    /// The question is queued when this is called, not when the future is first polled, and
    /// dropping the future does not recall it: its answer is read and dropped (a question whose
    /// asker is gone before it goes out is not sent). It waits for a session while one is being
    /// opened, and an idle connection opens one for it. The future fails with
    /// - `NotConnected` at once while the connection is down, and when no session could be opened
    ///   for it, or the session it was sent again on ended too;
    /// - `WouldBlock` at once, when [`MAX_FORWARDS`] questions are queued or out on the session;
    /// - `InvalidInput` at once, for a message under 12 or over [`MAX_QUERY`] bytes;
    /// - `TimedOut` when this question was open for the stall wait: the session was closed for it
    ///   if nothing was read from the session since the question was sent, and otherwise it alone
    ///   ended.
    ///
    /// There is no other wait here: the caller bounds one, as an exchange does.
    pub(crate) fn ask(
        &self,
        query: Vec<u8>,
    ) -> impl Future<Output = io::Result<Vec<u8>>> + Send + 'static {
        let queued = self.enqueue(query);
        async move {
            match queued {
                Ok(answer) => answer.await.unwrap_or_else(|_| Err(not_connected("ended"))),
                Err(error) => Err(error),
            }
        }
    }

    /// Puts `query` in the queue, if the connection is not down and there is room.
    fn enqueue(&self, query: Vec<u8>) -> io::Result<oneshot::Receiver<io::Result<Vec<u8>>>> {
        if !(HEADER_LEN..=MAX_QUERY).contains(&query.len()) {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "not a question this connection takes",
            ));
        }
        if self.link() == Link::Down {
            return Err(not_connected("no session"));
        }
        let query = with_keepalive(&query);
        let len = u16::try_from(query.len()).map_err(|_| ErrorKind::InvalidInput)?;
        let mut frame = Vec::with_capacity(2 + query.len());
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&query);
        let (reply, answer) = oneshot::channel();
        let request = Request {
            frame,
            reply,
            again: false,
        };
        match self.asks.try_send(request) {
            Ok(()) => Ok(answer),
            Err(mpsc::error::TrySendError::Full(_)) => {
                Err(io::Error::new(ErrorKind::WouldBlock, "queue full"))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err(not_connected("ended")),
        }
    }

    /// What the connection is doing about its session.
    pub(crate) fn link(&self) -> Link {
        *self.shared.link.borrow()
    }

    /// Whether a session is up.
    pub(crate) fn is_up(&self) -> bool {
        self.link() == Link::Up
    }

    /// Opens a session if the connection is idle, with no question: for a question that may be
    /// asked of it soon. Does nothing otherwise. The wake goes through the queue, where it takes
    /// a place until the task reads it (none if the queue is full, which needs no wake), and a
    /// session that finds it drops it: no wake is kept for later.
    pub(crate) fn wake(&self) {
        if self.link() == Link::Idle {
            let (reply, _) = oneshot::channel();
            let _ = self.asks.try_send(Request {
                frame: Vec::new(),
                reply,
                again: false,
            });
        }
    }

    /// Waits until the connection's link is one that `wanted` takes: ready at once if it is. It
    /// is a wait for the state and no more: it may have changed again by the time the caller acts.
    /// The caller bounds the wait, as there is none here. The future holds nothing of the `Conn`;
    /// if the `Conn` is dropped it never ends.
    fn wait_for(&self, wanted: fn(Link) -> bool) -> impl Future<Output = ()> + Send + 'static {
        let mut link = self.shared.link.subscribe();
        async move {
            // The guard that `wait_for` gives is dropped in this statement, before any other wait.
            let gone = link.wait_for(|&link| wanted(link)).await.is_err();
            if gone {
                // The connection and its task are gone: nothing changes any more.
                std::future::pending::<()>().await;
            }
        }
    }

    /// Waits until a question can be asked: until the connection is not down.
    pub(crate) fn wait_askable(&self) -> impl Future<Output = ()> + Send + 'static {
        self.wait_for(|link| link != Link::Down)
    }

    /// Waits until no session is up.
    pub(crate) fn wait_not_up(&self) -> impl Future<Output = ()> + Send + 'static {
        self.wait_for(|link| link != Link::Up)
    }

    /// Waits until a session is up.
    #[cfg(test)]
    pub(crate) fn wait_up(&self) -> impl Future<Output = ()> + Send + 'static {
        self.wait_for(|link| link == Link::Up)
    }

    /// The handshakes that were completed so far, resumed or not.
    #[cfg(test)]
    pub(crate) fn connects(&self) -> u64 {
        self.shared.connects.load(Ordering::Relaxed)
    }

    /// Of [`Conn::connects`], the handshakes that resumed an earlier session.
    #[cfg(test)]
    pub(crate) fn resumed(&self) -> u64 {
        self.shared.resumed.load(Ordering::Relaxed)
    }

    /// Everything that the connection counts.
    pub(crate) fn counts(&self) -> ConnCounts {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let shared = &*self.shared;
        ConnCounts {
            connects: load(&shared.connects),
            resumed: load(&shared.resumed),
            asked: load(&shared.asked),
            idle_closes: load(&shared.idle_closes),
            server_closes: load(&shared.server_closes),
            retried: load(&shared.retried),
        }
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The error of a question that finds no session.
fn not_connected(why: &'static str) -> io::Error {
    io::Error::new(ErrorKind::NotConnected, why)
}

/// The task: opens a session, serves it until it ends, and opens the next when it is wanted, for
/// as long as the `Conn` exists.
async fn keep_up(
    server: SocketAddr,
    tls: TlsUpstream,
    options: ConnOptions,
    shared: Arc<Shared>,
    mut queue: mpsc::Receiver<Request>,
) {
    // The wait before the last attempt or short session, since the last session that lived
    // `min_lived`: a handshake alone does not reset it.
    let mut waited: Option<Duration> = None;
    let mut warned: Option<Instant> = None;
    // The questions that go out first on the next session: those that were open on one that
    // the server ended, and the one that woke an idle connection.
    let mut first: Vec<Request> = Vec::new();
    // Whether a session is wanted now: the first one is.
    let mut wanted = true;
    loop {
        if !wanted {
            shared.set(Link::Idle);
            match queue.recv().await {
                // A wake asks nothing; a question goes out first.
                Some(request) if request.frame.is_empty() => {}
                Some(request) => first.push(request),
                None => return,
            }
        }
        shared.set(Link::Opening);
        let (tcp, conn) = match open(server, &tls).await {
            Ok(opened) => opened,
            Err(error) => {
                warn_limited(&mut warned, server, &why(&error));
                fail(&mut first, ErrorKind::NotConnected, "no session");
                down(&shared, &mut queue, &mut waited, &options).await;
                wanted = true;
                continue;
            }
        };
        let resumed = conn.handshake_kind() == Some(HandshakeKind::Resumed);
        shared.connects.fetch_add(1, Ordering::Relaxed);
        if resumed {
            shared.resumed.fetch_add(1, Ordering::Relaxed);
        }
        shared.set(Link::Up);
        let began = Instant::now();
        let mut session = Session::new(conn, tcp, options.idle);
        let end = session
            .serve(&mut queue, std::mem::take(&mut first), &options, &shared)
            .await;
        let lived = began.elapsed() >= options.min_lived;
        match end {
            End::Abandoned => return,
            End::Idle => {
                shared.idle_closes.fetch_add(1, Ordering::Relaxed);
                waited = None;
                // A session that was used is replaced at once: the household is awake. One that
                // was not waits for a question.
                wanted = session.carried;
                continue;
            }
            End::Closed | End::Failed => {
                shared.server_closes.fetch_add(1, Ordering::Relaxed);
                first = session.again();
                shared
                    .retried
                    .fetch_add(first.len() as u64, Ordering::Relaxed);
                if lived {
                    waited = None;
                    wanted = session.carried || !first.is_empty();
                    continue;
                }
            }
            End::Stalled => {
                warn_limited(&mut warned, server, "the session stalled");
                if lived {
                    waited = None;
                    wanted = true;
                    continue;
                }
            }
        }
        // A session that was too short: the server is failing. What is to be sent again waits
        // for the next session, within its asker's wait.
        down(&shared, &mut queue, &mut waited, &options).await;
        wanted = true;
    }
}

/// Marks the connection down, refuses what is queued, and waits out the backoff.
async fn down(
    shared: &Shared,
    queue: &mut mpsc::Receiver<Request>,
    waited: &mut Option<Duration>,
    options: &ConnOptions,
) {
    shared.set(Link::Down);
    refuse_queued(queue);
    let wait = backoff(*waited, options);
    *waited = Some(wait);
    sleep(wait).await;
}

/// Gives every question that is queued the error of there being no session.
fn refuse_queued(queue: &mut mpsc::Receiver<Request>) {
    while let Ok(request) = queue.try_recv() {
        let _ = request.reply.send(Err(not_connected("no session")));
    }
}

/// Gives every one of `requests` an error of `kind`.
fn fail(requests: &mut Vec<Request>, kind: ErrorKind, why: &'static str) {
    for request in requests.drain(..) {
        let _ = request.reply.send(Err(io::Error::new(kind, why)));
    }
}

/// Logs that no session could be opened with `server`, unless that was logged less than
/// [`WARN_EVERY`] ago. `why` holds no name that was asked for, and nothing the server sent.
fn warn_limited(warned: &mut Option<Instant>, server: SocketAddr, why: &str) {
    let now = Instant::now();
    if warned.is_some_and(|at| now.duration_since(at) < WARN_EVERY) {
        return;
    }
    *warned = Some(now);
    log::warn!("dns: no TLS session with upstream {server}: {why}");
}

/// The kind of failure that `error` is, in words that hold nothing the server sent: rustls words
/// a bad certificate with the names it holds.
fn why(error: &io::Error) -> String {
    let tls = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>());
    match tls {
        Some(rustls::Error::InvalidCertificate(_)) => "certificate rejected".to_owned(),
        Some(rustls::Error::AlertReceived(_)) => "alert received".to_owned(),
        Some(_) => "TLS error".to_owned(),
        None if error.kind() == ErrorKind::TimedOut => "timed out".to_owned(),
        None => error.kind().to_string(),
    }
}

/// Connects to `server` and completes the handshake with the upstream, which runs on a thread
/// of its own that this waits for through a oneshot channel.
///
/// A thread that cannot be started is the error of this open, which the reconnect's backoff
/// takes as any other. If this future is dropped (the `Conn` went) the thread goes on until its
/// handshake ends, within [`HANDSHAKE_WAIT`], and its result is dropped.
async fn open(server: SocketAddr, tls: &TlsUpstream) -> io::Result<(TcpStream, ClientConnection)> {
    let tcp = timeout(CONNECT_WAIT, TcpStream::connect(server))
        .await
        .map_err(|_| io::Error::from(ErrorKind::TimedOut))??;
    tcp.set_nodelay(true)?;
    let std = tcp.into_std()?;
    let (name, config) = (tls.name.clone(), tls.config.clone());
    let (done, result) = oneshot::channel();
    spawn_off_runtime_core("tls handshake", move || {
        // Nobody is told if the connection was dropped while this ran.
        drop(done.send(handshake(std, name, config)));
    })?;
    let (conn, std) = result
        .await
        .map_err(|_| io::Error::other("tls handshake: the thread ended without a result"))??;
    Ok((TcpStream::from_std(std)?, conn))
}

/// The handshake, in blocking mode, within [`HANDSHAKE_WAIT`] in all; the stream comes back in
/// non-blocking mode with a session that is ready for data. Runs on the handshake's own thread,
/// which counts the wait from its start.
fn handshake(
    tcp: StdTcpStream,
    name: ServerName<'static>,
    config: Arc<ClientConfig>,
) -> io::Result<(ClientConnection, StdTcpStream)> {
    tcp.set_nonblocking(false)?;
    let mut conn = ClientConnection::new(config, name).map_err(io::Error::other)?;
    let mut socket = Deadlined {
        tcp,
        deadline: std::time::Instant::now() + HANDSHAKE_WAIT,
    };
    while conn.is_handshaking() {
        conn.complete_io(&mut socket)?;
    }
    socket.tcp.set_nonblocking(true)?;
    Ok((conn, socket.tcp))
}

/// A blocking stream whose every read and write waits what is left to the deadline at most: a
/// peer that trickles bytes cannot hold a handshake past it.
struct Deadlined {
    /// The stream, in blocking mode.
    tcp: StdTcpStream,
    /// When every wait on it ends.
    deadline: std::time::Instant,
}

impl Deadlined {
    /// What is left to the deadline, or the error of there being none.
    fn left(&self) -> io::Result<Duration> {
        let left = self
            .deadline
            .saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err(ErrorKind::TimedOut.into());
        }
        Ok(left)
    }
}

impl Read for Deadlined {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.tcp.set_read_timeout(Some(self.left()?))?;
        self.tcp.read(buf)
    }
}

impl Write for Deadlined {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tcp.set_write_timeout(Some(self.left()?))?;
        self.tcp.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}

/// A tokio socket as the blocking `Read` and `Write` that rustls takes, never waiting: what the
/// socket cannot take or give now is `WouldBlock`, which the caller waits out with the socket's
/// readiness.
struct Raw<'a>(&'a TcpStream);

impl Read for Raw<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.try_read(buf)
    }
}

impl Write for Raw<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.try_write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Why a session ended.
enum End {
    /// The upstream closed it, with the TLS close notice or without.
    Closed,
    /// The socket or the TLS layer failed.
    Failed,
    /// The oldest open question was `stall` old, and nothing was read since it was sent.
    Stalled,
    /// It had no question open for its idle time, and was closed here.
    Idle,
    /// The `Conn` is gone: nothing can ask any more.
    Abandoned,
}

/// What happens next to the session loop.
enum Event {
    /// A question from the queue, or `None` when the `Conn` is gone.
    Request(Option<Request>),
    /// The socket is ready for what was asked of it.
    Ready(io::Result<tokio::io::Ready>),
    /// The stall timer ran out.
    Stall,
    /// The idle timer ran out.
    Idle,
}

/// A question that is out on the session.
struct Open {
    /// Where its answer goes.
    reply: oneshot::Sender<io::Result<Vec<u8>>>,
    /// The ID that the asker's message had, which the answer gets back.
    original: [u8; 2],
    /// When it was sent.
    sent: Instant,
    /// The frame as it went out, under the session's ID: what is sent again.
    frame: Vec<u8>,
    /// Whether it was sent on a session that ended before.
    again: bool,
}

/// An established session and the questions that are out on it.
struct Session {
    /// The TLS layer: what is sealed and opened, and what waits to be written.
    conn: ClientConnection,
    /// The socket under it, which is never waited on except through its readiness.
    tcp: TcpStream,
    /// The questions that are out, by the ID they went out under. At most [`MAX_FORWARDS`].
    open: HashMap<u16, Open>,
    /// Plaintext that has come and is not yet whole frames: under [`PLAIN_MAX`] bytes.
    plain: Vec<u8>,
    /// When bytes were last read from the socket: the handshake's last, to begin with.
    last_read: Instant,
    /// When a question was last sent, or the handshake's end.
    last_sent: Instant,
    /// How long it is kept with no question open: the options' idle time, or what the server
    /// advertises.
    idle: Duration,
    /// Whether the server advertised a timeout of 0: no new question goes out on the session.
    draining: bool,
    /// Whether a question was sent on it.
    carried: bool,
}

impl Session {
    /// A session that has no question out yet, kept for `idle` with no question open.
    fn new(conn: ClientConnection, tcp: TcpStream, idle: Duration) -> Self {
        let now = Instant::now();
        Self {
            conn,
            tcp,
            open: HashMap::new(),
            plain: Vec::new(),
            last_read: now,
            last_sent: now,
            idle,
            draining: false,
            carried: false,
        }
    }

    /// Sends `first`, then serves the session until it ends, and then tells the shared state that
    /// no session is up, before whoever has a question open on it is told anything. A session that
    /// stalled ends its open questions with `TimedOut`; one that the server ended keeps them for
    /// [`Session::again`].
    async fn serve(
        &mut self,
        queue: &mut mpsc::Receiver<Request>,
        first: Vec<Request>,
        options: &ConnOptions,
        shared: &Shared,
    ) -> End {
        let mut sent = Ok(());
        for request in first {
            if sent.is_ok() {
                sent = self.send(request, shared);
            } else {
                // The stream broke: what is left is sent again on the next one.
                self.keep(request);
            }
        }
        let end = match sent.and_then(|()| self.flush()) {
            Ok(()) => self.drive(queue, options.stall, shared).await,
            Err(_) => End::Failed,
        };
        // The state changes first: an exchange that waits on it hedges at once.
        shared.set(Link::Opening);
        if let End::Stalled = end {
            for (_, open) in self.open.drain() {
                let error =
                    io::Error::new(ErrorKind::TimedOut, "the upstream did not answer in time");
                let _ = open.reply.send(Err(error));
            }
        }
        end
    }

    /// Notes a question that was not written before the stream broke as one that is open, under
    /// no ID, so that it is sent again like the others.
    fn keep(&mut self, request: Request) {
        if request.frame.is_empty() {
            return;
        }
        let id = self.fresh_id();
        self.open.insert(
            id,
            Open {
                original: [request.frame[2], request.frame[3]],
                reply: request.reply,
                sent: Instant::now(),
                frame: request.frame,
                again: request.again,
            },
        );
    }

    /// The questions that were open when the server ended the session, to be sent once more on
    /// the next one, under the ID they were asked with; those that had been sent again already,
    /// and those whose askers are gone, end here.
    fn again(&mut self) -> Vec<Request> {
        let mut again = Vec::new();
        for (_, open) in self.open.drain() {
            if open.reply.is_closed() {
                continue;
            }
            if open.again {
                let _ = open.reply.send(Err(not_connected("the session ended")));
                continue;
            }
            let mut frame = open.frame;
            frame[2..4].copy_from_slice(&open.original);
            again.push(Request {
                frame,
                reply: open.reply,
                again: true,
            });
        }
        again
    }

    /// The session loop: takes questions, moves bytes, and watches the oldest question and the
    /// idle time.
    async fn drive(
        &mut self,
        queue: &mut mpsc::Receiver<Request>,
        stall: Duration,
        shared: &Shared,
    ) -> End {
        loop {
            // A socket that is readable every time (a peer that writes as fast as we read) never
            // makes this loop wait: readiness is not counted against the task's budget of tokio's
            // cooperative scheduling, so this counts one unit for each turn, and the task gives
            // the runtime back when its budget is spent.
            tokio::task::coop::consume_budget().await;
            let stall_at = self.oldest().map(|sent| sent + stall);
            // While output waits for the socket, no new question is taken: a peer that does not
            // read holds the queue (which then refuses) and not our memory. Nor is one taken on a
            // session that the server asked to be closed.
            let blocked = self.conn.wants_write();
            let taking = !blocked && !self.draining;
            let idle_at = (self.open.is_empty() && !blocked)
                .then(|| self.last_read.max(self.last_sent) + self.idle);
            let interest = if blocked {
                Interest::READABLE | Interest::WRITABLE
            } else {
                Interest::READABLE
            };
            let event = tokio::select! {
                request = queue.recv(), if taking => Event::Request(request),
                ready = self.tcp.ready(interest) => Event::Ready(ready),
                () = sleep_until(stall_at.unwrap_or_else(|| Instant::now() + FAR)),
                    if stall_at.is_some() => Event::Stall,
                () = sleep_until(idle_at.unwrap_or_else(|| Instant::now() + FAR)),
                    if idle_at.is_some() => Event::Idle,
            };
            let step = match event {
                Event::Request(None) => return End::Abandoned,
                Event::Request(Some(request)) => {
                    self.send(request, shared).and_then(|()| self.flush())
                }
                Event::Stall if self.stall_ran_out(stall) => return End::Stalled,
                Event::Stall => Ok(()),
                // A question that came at the last moment keeps the session.
                Event::Idle if !self.draining && !queue.is_empty() => Ok(()),
                Event::Idle => {
                    self.conn.send_close_notify();
                    let _ = self.flush();
                    return End::Idle;
                }
                Event::Ready(Err(_)) => return End::Failed,
                Event::Ready(Ok(ready)) => {
                    if ready.is_readable() {
                        match self.receive() {
                            Ok(true) => return End::Closed,
                            Ok(false) => {}
                            Err(_) => return End::Failed,
                        }
                    }
                    self.flush()
                }
            };
            if step.is_err() {
                return End::Failed;
            }
        }
    }

    /// When the oldest open question was sent. At most [`MAX_FORWARDS`] are looked at.
    fn oldest(&self) -> Option<Instant> {
        self.open.values().map(|open| open.sent).min()
    }

    /// Deals with the stall timer running out, which it does when the oldest open question is
    /// `stall` old. `true` when the session is to be closed: nothing was read from it since that
    /// question was sent, which is what a path that has gone silent looks like. Otherwise the
    /// session is alive, and only the questions that are `stall` old end, each with `TimedOut`:
    /// their entries are taken out of the table, which keeps it bounded, and an answer that comes
    /// later finds no question and is dropped.
    fn stall_ran_out(&mut self, stall: Duration) -> bool {
        let Some(oldest) = self.oldest() else {
            return false;
        };
        if self.last_read <= oldest {
            return true;
        }
        let now = Instant::now();
        let late: Vec<u16> = self
            .open
            .iter()
            .filter(|(_, open)| open.sent + stall <= now)
            .map(|(&id, _)| id)
            .collect();
        for id in late {
            if let Some(open) = self.open.remove(&id) {
                let error =
                    io::Error::new(ErrorKind::TimedOut, "the upstream did not answer in time");
                let _ = open.reply.send(Err(error));
            }
        }
        false
    }

    /// An ID that no open question on this session has.
    fn fresh_id(&self) -> u16 {
        loop {
            // Few of the 65,536 are taken, so this ends at once.
            let id = sys::random_u64() as u16;
            if !self.open.contains_key(&id) {
                return id;
            }
        }
    }

    /// Writes `request`'s frame to the TLS layer under a fresh ID, and notes it as open. A
    /// question whose asker is gone is not sent. A table that is full refuses it, which is no
    /// error of the session. An error here means that the stream cannot be trusted to be in step
    /// any more.
    fn send(&mut self, request: Request, shared: &Shared) -> io::Result<()> {
        let Request {
            mut frame,
            reply,
            again,
        } = request;
        // A wake, or a question whose asker is gone.
        if frame.is_empty() || reply.is_closed() {
            return Ok(());
        }
        if self.open.len() >= MAX_FORWARDS {
            let _ = reply.send(Err(io::Error::new(ErrorKind::WouldBlock, "table full")));
            return Ok(());
        }
        let id = self.fresh_id();
        let original = [frame[2], frame[3]];
        frame[2..4].copy_from_slice(&id.to_be_bytes());
        let written = self.conn.writer().write_all(&frame);
        let now = Instant::now();
        self.open.insert(
            id,
            Open {
                reply,
                original,
                sent: now,
                frame,
                again,
            },
        );
        self.last_sent = now;
        self.carried = true;
        shared.asked.fetch_add(1, Ordering::Relaxed);
        written
    }

    /// Writes the TLS layer's output to the socket as far as the socket takes it.
    fn flush(&mut self) -> io::Result<()> {
        while self.conn.wants_write() {
            match self.conn.write_tls(&mut Raw(&self.tcp)) {
                Ok(0) => return Err(ErrorKind::WriteZero.into()),
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Reads what the socket has into the TLS layer and takes the answers out of it. `true` when
    /// the upstream has closed the session; an error when the stream is broken.
    fn receive(&mut self) -> io::Result<bool> {
        match self.conn.read_tls(&mut Raw(&self.tcp)) {
            Ok(0) => return Ok(true),
            Ok(_) => self.last_read = Instant::now(),
            Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(error),
        }
        let state = self
            .conn
            .process_new_packets()
            .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
        self.drain()?;
        Ok(state.peer_has_closed())
    }

    /// Moves the plaintext that the TLS layer holds into `plain` and delivers the answers in it.
    fn drain(&mut self) -> io::Result<()> {
        let mut chunk = [0u8; CHUNK];
        loop {
            match self.conn.reader().read(&mut chunk) {
                // The upstream's close notice, or the end of the stream: nothing more comes.
                Ok(0) => return Ok(()),
                Ok(n) => {
                    self.plain.extend_from_slice(&chunk[..n]);
                    if self.plain.len() > PLAIN_MAX {
                        return Err(io::Error::new(ErrorKind::InvalidData, "too much plaintext"));
                    }
                    self.deliver();
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::WouldBlock | ErrorKind::UnexpectedEof
                    ) =>
                {
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Cuts the whole frames from the front of `plain` and gives each to the question whose ID it
    /// carries, with the ID that question was asked under. A frame that is no message, or whose
    /// ID no open question has (a duplicate, or an answer to nothing), is dropped. An answer that
    /// advertises the server's idle timeout sets the session's.
    fn deliver(&mut self) {
        let mut at = 0;
        while let Some(head) = self.plain.get(at..at + 2) {
            let len = usize::from(u16::from_be_bytes([head[0], head[1]]));
            let Some(frame) = self.plain.get(at + 2..at + 2 + len) else {
                break;
            };
            if len >= HEADER_LEN {
                let id = u16::from_be_bytes([frame[0], frame[1]]);
                if let Some(open) = self.open.remove(&id) {
                    if let Some(timeout) = keepalive(frame) {
                        self.idle = idle_for(timeout);
                        self.draining = timeout.is_zero();
                    }
                    let mut answer = frame.to_vec();
                    answer[..2].copy_from_slice(&open.original);
                    // The asker may have given up on it: then there is nobody to tell.
                    let _ = open.reply.send(Ok(answer));
                }
            }
            at += 2 + len;
        }
        self.plain.drain(..at);
    }
}

/// The two bytes at `at` of `message`, as a number.
fn u16_at(message: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *message.get(at)?,
        *message.get(at + 1)?,
    ]))
}

/// Where the name that starts at `at` of `message` ends: after its zero label, or after the
/// pointer that ends it. `None` past the end, or at a label of a kind that is not known.
fn skip_name(message: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let label = *message.get(at)?;
        match label & 0xC0 {
            0x00 if label == 0 => return Some(at + 1),
            0x00 => at += 1 + usize::from(label),
            0xC0 => return message.get(at + 1).map(|_| at + 2),
            _ => return None,
        }
    }
}

/// Where the OPT record of `message` is: the offset of its RDLENGTH, and the end of its RDATA.
/// `None` when it has none in its additional section, or cannot be read that far. Walks the
/// records and allocates nothing; each step moves on by a byte at least, so it ends.
fn find_opt(message: &[u8]) -> Option<(usize, usize)> {
    let count = |at| u16_at(message, at).map(usize::from);
    let (questions, answers, authority, additional) = (count(4)?, count(6)?, count(8)?, count(10)?);
    let mut at = HEADER_LEN;
    for _ in 0..questions {
        at = skip_name(message, at)? + 4;
    }
    let before = answers + authority;
    for record in 0..before + additional {
        at = skip_name(message, at)?;
        let kind = u16_at(message, at)?;
        let rdlen_at = at + 8;
        let end = rdlen_at + 2 + usize::from(u16_at(message, rdlen_at)?);
        if end > message.len() {
            return None;
        }
        if record >= before && kind == OPT {
            return Some((rdlen_at, end));
        }
        at = end;
    }
    None
}

/// The options in the RDATA of an OPT record, `rdata`: each one's code and data. Stops at one
/// that runs past the end.
fn options(rdata: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    let mut at = 0;
    std::iter::from_fn(move || {
        let code = u16_at(rdata, at)?;
        let len = usize::from(u16_at(rdata, at + 2)?);
        let data = rdata.get(at + 4..at + 4 + len)?;
        at += 4 + len;
        Some((code, data))
    })
}

/// The idle timeout that `answer` advertises with the edns-tcp-keepalive option, if it does:
/// the option with a two-byte timeout, in units of 100 ms (RFC 7828 §3.1).
fn keepalive(answer: &[u8]) -> Option<Duration> {
    let (rdlen_at, end) = find_opt(answer)?;
    options(&answer[rdlen_at + 2..end]).find_map(|(code, data)| match (code, data) {
        (KEEPALIVE, &[high, low]) => Some(Duration::from_millis(
            u64::from(u16::from_be_bytes([high, low])) * 100,
        )),
        _ => None,
    })
}

/// `query` with the edns-tcp-keepalive option, with no timeout as a question carries it (RFC 7828
/// §3.2.1), added to its OPT record; as it is when it has no OPT record or has the option already.
fn with_keepalive(query: &[u8]) -> Vec<u8> {
    let Some((rdlen_at, end)) = find_opt(query) else {
        return query.to_vec();
    };
    let rdata = &query[rdlen_at + 2..end];
    let Ok(len) = u16::try_from(rdata.len() + 4) else {
        return query.to_vec();
    };
    if options(rdata).any(|(code, _)| code == KEEPALIVE) {
        return query.to_vec();
    }
    let mut with = Vec::with_capacity(query.len() + 4);
    with.extend_from_slice(&query[..rdlen_at]);
    with.extend_from_slice(&len.to_be_bytes());
    with.extend_from_slice(rdata);
    with.extend_from_slice(&KEEPALIVE.to_be_bytes());
    with.extend_from_slice(&[0, 0]);
    with.extend_from_slice(&query[end..]);
    with
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::AtomicUsize;
    use std::time::Instant as StdInstant;

    use hickory_proto::op::Message;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    use crate::dns::client::{query, read_answer};
    use crate::dns::testutil::{
        Reply, TlsFakeUpstream, TlsMode, advertise_keepalive, closed_port, ip, ms, tls_for_fake,
        tls_for_fake_as, tls_for_fake_noting_threads,
    };
    use crate::services::testutil::{Jam, longest_gap};

    /// Waits until `ready` holds, for ten seconds at most, and panics with `what` if it does not.
    async fn until(what: &str, mut ready: impl FnMut() -> bool) {
        let end = Instant::now() + Duration::from_secs(10);
        while !ready() {
            assert!(Instant::now() < end, "timed out waiting for {what}");
            sleep(ms(5)).await;
        }
    }

    /// The waits of a test: quick ones, and a reconnect at once.
    fn quick() -> ConnOptions {
        ConnOptions {
            stall: ms(300),
            backoff_min: ms(50),
            backoff_max: ms(200),
            min_lived: Duration::ZERO,
            idle: Duration::from_secs(60),
        }
    }

    /// `name` A under ID 0 with an OPT record, as the exchange sends every question.
    fn question(name: &str) -> Vec<u8> {
        let mut message = Message::query();
        message.metadata.id = 0;
        message.metadata.recursion_desired = true;
        message.add_query(hickory_proto::op::Query::query(
            hickory_proto::rr::Name::from_ascii(name).unwrap(),
            hickory_proto::rr::RecordType::A,
        ));
        let mut edns = hickory_proto::op::Edns::new();
        edns.set_max_payload(1232);
        message.set_edns(edns);
        message.to_vec().unwrap()
    }

    /// The name that `answer` is the answer to.
    fn asked_name(answer: &[u8]) -> String {
        Message::from_vec(answer).unwrap().queries[0]
            .name
            .to_ascii()
    }

    /// A connection to a fake that answers `192.0.2.10`, which is up.
    async fn up(options: ConnOptions) -> (Conn, TlsFakeUpstream) {
        let fake = TlsFakeUpstream::start(Reply::Answer(ip("192.0.2.10")));
        let conn = Conn::spawn(fake.addr, tls_for_fake(&fake), options);
        until("the session", || conn.is_up()).await;
        (conn, fake)
    }

    #[tokio::test]
    async fn an_answer_comes_back_over_tls() {
        let (conn, fake) = up(quick()).await;
        let answer = conn.ask(query(0x1234, "example.com", 1).unwrap()).await;
        // Under the ID the question had.
        let answer = read_answer(&answer.unwrap(), 0x1234).unwrap();
        assert_eq!(answer.v4(), [ip("192.0.2.10")]);
        assert_eq!(conn.connects(), 1);
        assert_eq!((fake.handshakes(), fake.queries()), (1, 1));
    }

    #[tokio::test]
    async fn questions_are_pipelined_and_matched_by_id() {
        let mode = TlsMode {
            reverse_pairs: true,
            ..TlsMode::default()
        };
        let fake = TlsFakeUpstream::start_with(Reply::Answer(ip("192.0.2.10")), mode);
        let conn = Conn::spawn(fake.addr, tls_for_fake(&fake), quick());
        until("the session", || conn.is_up()).await;
        // Both under ID 0; the fake answers the second first, and each asker gets its own.
        let first = conn.ask(question("a.example.com"));
        let second = conn.ask(question("b.example.com"));
        let (first, second) = tokio::join!(first, second);
        let (first, second) = (first.unwrap(), second.unwrap());
        assert_eq!(asked_name(&first), "a.example.com.");
        assert_eq!(asked_name(&second), "b.example.com.");
        assert!(read_answer(&first, 0).is_some() && read_answer(&second, 0).is_some());
        assert_eq!((fake.handshakes(), fake.queries()), (1, 2));
        assert_eq!(conn.connects(), 1);
    }

    #[tokio::test]
    async fn the_connection_is_opened_before_the_first_question() {
        let fake = TlsFakeUpstream::start(Reply::Silent);
        let conn = Conn::spawn(fake.addr, tls_for_fake(&fake), quick());
        until("the session, with no question asked", || conn.is_up()).await;
        // The client is done with the handshake a moment before the server notes that it is.
        until("the server's handshake", || fake.handshakes() == 1).await;
        assert_eq!((conn.connects(), fake.queries()), (1, 0));
    }

    #[tokio::test]
    async fn a_closed_connection_is_reopened_and_resumed() {
        let mode = TlsMode {
            close_after: Some(1),
            ..TlsMode::default()
        };
        let fake = TlsFakeUpstream::start_with(Reply::Answer(ip("192.0.2.10")), mode);
        let conn = Conn::spawn(fake.addr, tls_for_fake(&fake), quick());
        until("the session", || conn.is_up()).await;
        conn.ask(question("example.com")).await.unwrap();
        // The fake closed the session after that answer; a new one is opened at once.
        until("the second handshake", || conn.connects() == 2).await;
        until("the second session", || conn.is_up()).await;
        let answer = conn.ask(question("example.com")).await.unwrap();
        assert!(read_answer(&answer, 0).is_some());
        assert!(conn.resumed() >= 1, "client resumed {}", conn.resumed());
        assert!(fake.resumed() >= 1, "server resumed {}", fake.resumed());
    }

    #[tokio::test]
    async fn a_session_that_was_short_waits_before_the_next() {
        let mode = TlsMode {
            close_after: Some(1),
            ..TlsMode::default()
        };
        let fake = TlsFakeUpstream::start_with(Reply::Answer(ip("192.0.2.10")), mode);
        let options = ConnOptions {
            backoff_min: ms(1500),
            backoff_max: ms(1500),
            min_lived: Duration::from_secs(60),
            ..quick()
        };
        let conn = Conn::spawn(fake.addr, tls_for_fake(&fake), options);
        until("the session", || conn.is_up()).await;
        conn.ask(question("example.com")).await.unwrap();
        until("the end of the session", || !conn.is_up()).await;
        sleep(ms(300)).await;
        // Not yet: the session lived far less than `min_lived`.
        assert_eq!(conn.connects(), 1);
        until("the second handshake", || conn.connects() == 2).await;
    }

    #[tokio::test]
    async fn a_server_that_closes_at_once_is_backed_off_from() {
        // The handshake completes, and the session ends at once: the wait must not start over
        // from its minimum with every handshake.
        let mode = TlsMode {
            close_after: Some(0),
            ..TlsMode::default()
        };
        let fake = TlsFakeUpstream::start_with(Reply::Silent, mode);
        let options = ConnOptions {
            backoff_min: ms(50),
            backoff_max: ms(400),
            min_lived: Duration::from_secs(5),
            ..quick()
        };
        let conn = Conn::spawn(fake.addr, tls_for_fake(&fake), options);
        sleep(ms(1500)).await;
        let n = conn.connects();
        // The waits between handshakes are 50, 100, 200, 400, 400 ms, so the sixth starts at
        // 1,150 ms and the seventh at 1,550 ms at the earliest, whatever a handshake takes; a
        // wait that stayed at 50 ms would give about 30.
        assert!(n <= 6, "{n} handshakes in 1.5 s");
        // Still reconnecting, only more and more slowly.
        until("a second handshake", || conn.connects() >= 2).await;
    }

    #[tokio::test]
    async fn ask_fails_at_once_while_down() {
        let fake = TlsFakeUpstream::start(Reply::Silent);
        let conn = Conn::spawn(closed_port(), tls_for_fake(&fake), quick());
        let began = StdInstant::now();
        let error = conn.ask(question("example.com")).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotConnected);
        // Nothing waited for the session: a trivial bound that is far under any wait here.
        assert!(began.elapsed() < ms(200), "took {:?}", began.elapsed());
        assert!(!conn.is_up());
    }

    #[tokio::test]
    async fn wait_up_follows_the_session() {
        let mode = TlsMode {
            close_after: Some(1),
            ..TlsMode::default()
        };
        let fake = TlsFakeUpstream::start_with(Reply::Answer(ip("192.0.2.10")), mode);
        let options = ConnOptions {
            backoff_min: ms(1500),
            backoff_max: ms(1500),
            min_lived: Duration::from_secs(60),
            ..quick()
        };
        let conn = Conn::spawn(fake.addr, tls_for_fake(&fake), options);
        // A wait that begins with no session ends when there is one.
        timeout(Duration::from_secs(10), conn.wait_up())
            .await
            .expect("no session came");
        assert!(conn.is_up());
        // With one up, it is ready at once.
        timeout(ms(1), conn.wait_up()).await.unwrap();
        conn.ask(question("example.com")).await.unwrap();
        until("the end of the session", || !conn.is_up()).await;
        // The next session is a backoff away: a wait that begins now is still open after a moment,
        // and ends with it.
        assert!(timeout(ms(300), conn.wait_up()).await.is_err());
        timeout(Duration::from_secs(10), conn.wait_up())
            .await
            .expect("no second session came");
        assert_eq!(conn.connects(), 2);
    }

    #[tokio::test]
    async fn a_wait_for_a_session_that_never_comes_is_the_callers_to_end() {
        let fake = TlsFakeUpstream::start(Reply::Silent);
        let conn = Conn::spawn(closed_port(), tls_for_fake(&fake), quick());
        assert!(timeout(ms(250), conn.wait_up()).await.is_err());
        assert!(!conn.is_up());
    }

    #[test]
    fn the_backoff_doubles_to_its_cap() {
        let options = ConnOptions::default();
        let mut previous = None;
        let mut waits = Vec::new();
        for _ in 0..10 {
            let next = backoff(previous, &options);
            waits.push(next.as_millis());
            previous = Some(next);
        }
        assert_eq!(
            waits,
            [250, 500, 1000, 2000, 4000, 8000, 16000, 30000, 30000, 30000]
        );
        // A first wait over the cap is held to it.
        let odd = ConnOptions {
            backoff_min: ms(900),
            backoff_max: ms(400),
            ..quick()
        };
        assert_eq!(backoff(None, &odd), ms(400));
    }

    #[tokio::test]
    async fn reconnects_back_off_boundedly() {
        // A server that takes every connection and drops it: the handshake fails each time.
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let counting = attempts.clone();
        let acceptor = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                counting.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
        let fake = TlsFakeUpstream::start(Reply::Silent);
        let options = ConnOptions {
            backoff_min: ms(50),
            backoff_max: ms(200),
            ..quick()
        };
        let conn = Conn::spawn(addr, tls_for_fake(&fake), options);
        sleep(Duration::from_secs(1)).await;
        let n = attempts.load(Ordering::SeqCst);
        // 50, 100, 200, 200, ... between attempts: about 7. Never a tight loop, never idle.
        assert!((3..=12).contains(&n), "{n} attempts in a second");
        assert!(!conn.is_up() && conn.connects() == 0);
        acceptor.abort();
    }

    #[tokio::test]
    async fn a_stalled_connection_is_closed_and_reopened() {
        let fake = TlsFakeUpstream::start(Reply::Silent);
        let conn = Conn::spawn(fake.addr, tls_for_fake(&fake), quick());
        until("the session", || conn.is_up()).await;
        // The tickets that the server sends after the handshake are read before the question
        // goes out: they are bytes read, and would keep the session.
        until("the server's handshake", || fake.handshakes() == 1).await;
        sleep(ms(100)).await;
        let began = StdInstant::now();
        let error = timeout(Duration::from_secs(5), conn.ask(question("example.com")))
            .await
            .expect("the question was left open for good")
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::TimedOut);
        // Not before the stall wait (300 ms), and long before anything else would end it.
        assert!(began.elapsed() >= ms(250), "took {:?}", began.elapsed());
        until("the second handshake", || conn.connects() == 2).await;
        until("the server's second handshake", || fake.handshakes() == 2).await;
    }

    #[tokio::test]
    async fn one_unanswered_question_beside_answered_ones_keeps_the_session() {
        let mode = TlsMode {
            never_answers: Some("slow.example.com"),
            ..TlsMode::default()
        };
        let fake = TlsFakeUpstream::start_with(Reply::Answer(ip("192.0.2.10")), mode);
        let options = ConnOptions {
            stall: ms(600),
            ..quick()
        };
        let conn = Conn::spawn(fake.addr, tls_for_fake(&fake), options);
        until("the session", || conn.is_up()).await;
        let slow = conn.ask(question("slow.example.com"));
        let began = StdInstant::now();
        // The others are answered, one after the other, for more than twice the stall wait: the
        // session is being read all the time, and only the one name is not answered.
        let mut answered = 0;
        while began.elapsed() < ms(1500) {
            let answer = conn.ask(question("fast.example.com")).await;
            assert!(answer.is_ok(), "an answered question failed: {answer:?}");
            answered += 1;
            sleep(ms(20)).await;
        }
        assert!(answered >= 5, "only {answered} questions were asked");
        // The one that was never answered ended alone, with the stall wait's error.
        let error = timeout(Duration::from_secs(5), slow)
            .await
            .expect("the question was left open for good")
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::TimedOut);
        assert!(conn.is_up());
        assert_eq!(conn.connects(), 1);
        // Its entry is gone: the table has room again, and the session still answers.
        assert!(conn.ask(question("fast.example.com")).await.is_ok());
    }

    #[tokio::test]
    async fn a_flood_from_the_server_does_not_hold_the_runtime() {
        // A server that writes as fast as the client reads keeps the socket readable for as long
        // as the flood lasts. A session loop that never gave the runtime back would hold it for all
        // of that, and with it the other connection, the listeners and the clock.
        //
        // How long a flood takes depends on the machine and the build (a build without
        // optimisation opens records at a few MB a second), so the bound is a share of the flood's
        // own duration: the loop yields every 128 reads, which is under a tenth of 16 MB, and
        // however loaded the machine is, that share holds. The part that is in the kernel's buffers
        // when the server has written the last of it is not counted: about as much as another
        // third.
        const FLOOD: usize = 16 << 20;
        let mode = TlsMode {
            flood: FLOOD,
            ..TlsMode::default()
        };
        let fake = TlsFakeUpstream::start_with(Reply::Silent, mode);
        let tls = tls_for_fake(&fake);
        let began = StdInstant::now();
        let (gap, conn) = longest_gap(async {
            let conn = Conn::spawn(fake.addr, tls, quick());
            until("the flood to be written", || fake.flooded() >= FLOOD).await;
            conn
        })
        .await;
        let took = began.elapsed();
        assert!(conn.is_up());
        assert!(
            gap * 2 < took,
            "the runtime was held for {gap:?} of the {took:?} that the flood took"
        );
    }

    #[tokio::test]
    async fn a_certificate_for_another_name_never_connects() {
        let fake = TlsFakeUpstream::start(Reply::Answer(ip("192.0.2.10")));
        let conn = Conn::spawn(
            fake.addr,
            tls_for_fake_as(&fake, "other.example.org"),
            quick(),
        );
        for _ in 0..20 {
            sleep(ms(50)).await;
            assert!(!conn.is_up());
        }
        assert_eq!((conn.connects(), fake.handshakes()), (0, 0));
        let error = conn.ask(question("example.com")).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotConnected);
    }

    #[tokio::test]
    async fn a_handshake_does_not_hold_the_runtime() {
        // The fake takes 300 ms to start its side of the handshake: a handshake that waited for
        // it on the runtime thread would hold the thread for that long, which no amount of
        // crypto speed hides. On a thread of its own, the ticker beside it runs on.
        let mode = TlsMode {
            handshake_delay: ms(300),
            ..TlsMode::default()
        };
        let fake = TlsFakeUpstream::start_with(Reply::Silent, mode);
        let tls = tls_for_fake(&fake);
        let began = StdInstant::now();
        let (gap, conn) = longest_gap(async {
            let conn = Conn::spawn(fake.addr, tls, quick());
            until("the session", || conn.is_up()).await;
            conn
        })
        .await;
        assert!(began.elapsed() >= ms(300), "the handshake did not wait");
        assert_eq!(conn.connects(), 1);
        assert!(gap < ms(150), "the runtime was held for {gap:?}");
    }

    #[tokio::test]
    async fn the_handshake_runs_on_a_thread_of_its_own() {
        // The certificate check is part of the handshake and runs where the handshake does. A
        // handshake on the runtime's thread is the test's own thread here; one on the blocking
        // pool is on a thread with the pool's name, which is not `tls handshake`.
        let fake = TlsFakeUpstream::start(Reply::Silent);
        let (tls, checked_on) = tls_for_fake_noting_threads(&fake);
        let conn = Conn::spawn(fake.addr, tls, quick());
        until("the session", || conn.is_up()).await;
        let checked_on = checked_on.lock().unwrap().clone();
        assert_eq!(checked_on.len(), 1, "{checked_on:?}");
        assert_ne!(
            checked_on[0].id,
            std::thread::current().id(),
            "the handshake ran on the runtime's thread"
        );
        assert_eq!(
            checked_on[0].name.as_deref(),
            Some("tls handshake"),
            "the handshake ran on a thread that is not its own"
        );
    }

    #[test]
    fn the_handshake_thread_leaves_the_core_the_runtime_is_pinned_to() {
        let allowed = rustix::thread::sched_getaffinity(None).unwrap();
        let allowed: Vec<usize> = (0..rustix::thread::CpuSet::MAX_CPU)
            .filter(|core| allowed.is_set(*core))
            .collect();
        if allowed.len() < 2 {
            println!(
                "skipped: the host allows {} CPU(s), the test needs 2",
                allowed.len()
            );
            return;
        }
        let core = allowed[0];
        // On a thread of its own, so that the pin does not outlast the test on a thread of the harness.
        let checked_on = std::thread::spawn(move || {
            crate::cpu::pin_current_thread(core).unwrap();
            let runtime = crate::services::runtime(Some(core)).unwrap();
            runtime.block_on(async {
                let fake = TlsFakeUpstream::start(Reply::Silent);
                let (tls, checked_on) = tls_for_fake_noting_threads(&fake);
                let conn = Conn::spawn(fake.addr, tls, quick());
                until("the session", || conn.is_up()).await;
                std::mem::take(&mut *checked_on.lock().unwrap())
            })
        })
        .join()
        .unwrap();
        assert_eq!(checked_on.len(), 1, "{checked_on:?}");
        assert_eq!(checked_on[0].cores, allowed[1..].to_vec());
    }

    #[test]
    fn a_session_comes_up_while_every_thread_of_the_pool_is_busy() {
        // Every thread of the pool is held, as by a list parse at boot, which is when no session
        // is up and the questions wait for one: the handshake must not wait for a place there.
        let runtime = crate::services::runtime(None).unwrap();
        let (took, connects) = runtime.block_on(async {
            let _jam = Jam::fill().await;
            let fake = TlsFakeUpstream::start(Reply::Silent);
            let began = StdInstant::now();
            let conn = Conn::spawn(fake.addr, tls_for_fake(&fake), quick());
            timeout(Duration::from_secs(3), conn.wait_up())
                .await
                .expect(
                    "no session in 3 s with the pool full: the handshake waits for a place in it",
                );
            (began.elapsed(), conn.connects())
        });
        println!("session up {took:?} after the start, with the pool full");
        assert_eq!(connects, 1);
        assert!(took < Duration::from_secs(2), "{took:?}");
    }

    /// How long a first session takes to come up, from the start of the connection, when every
    /// thread of the pool is held for `hold` from just before it.
    fn time_to_a_session_with_the_pool_held(hold: Duration) -> Duration {
        let runtime = crate::services::runtime(None).unwrap();
        runtime.block_on(async {
            let jam = Jam::fill().await;
            let releasing = tokio::spawn(async move {
                sleep(hold).await;
                jam.release();
            });
            let fake = TlsFakeUpstream::start(Reply::Silent);
            let began = StdInstant::now();
            let conn = Conn::spawn(fake.addr, tls_for_fake(&fake), quick());
            conn.wait_up().await;
            let took = began.elapsed();
            releasing.await.unwrap();
            took
        })
    }

    /// Prints the time to a first session with the pool free and with it held for 1.5 s, as the
    /// pool is behind a list parse at boot: on a pool that the handshake queued on, the second
    /// figure is the first plus the hold; run with `--ignored --nocapture`.
    #[test]
    #[ignore = "prints two figures"]
    fn print_the_time_to_a_session_with_the_pool_free_and_held() {
        let free = time_to_a_session_with_the_pool_held(Duration::ZERO);
        let held = time_to_a_session_with_the_pool_held(Duration::from_millis(1500));
        println!("first session: pool free {free:?}, pool held for 1.5 s {held:?}");
    }

    #[tokio::test]
    async fn a_server_that_never_speaks_is_given_up_on_at_the_handshake_wait() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let fake = TlsFakeUpstream::start(Reply::Silent);
        let options = ConnOptions {
            // No second attempt while the test looks.
            backoff_min: Duration::from_secs(60),
            backoff_max: Duration::from_secs(60),
            ..quick()
        };
        let conn = Conn::spawn(addr, tls_for_fake(&fake), options);
        let (mut stream, _) = listener.accept().await.unwrap();
        let began = StdInstant::now();
        // Reads what the client says (its hello) until the client closes.
        let mut buf = [0u8; 1024];
        while matches!(stream.read(&mut buf).await, Ok(n) if n > 0) {}
        let took = began.elapsed();
        assert!(
            took >= HANDSHAKE_WAIT - ms(100) && took < HANDSHAKE_WAIT + Duration::from_secs(10),
            "gave up after {took:?}"
        );
        assert!(!conn.is_up() && conn.connects() == 0);
    }

    #[tokio::test]
    async fn an_answer_under_an_id_that_is_not_open_is_ignored() {
        // The fake sends the answer under the ID plus one first, and then the right one.
        let fake = TlsFakeUpstream::start(Reply::WrongIdFirst(ip("192.0.2.10")));
        let conn = Conn::spawn(fake.addr, tls_for_fake(&fake), quick());
        until("the session", || conn.is_up()).await;
        let answer = conn.ask(question("example.com")).await.unwrap();
        let answer = read_answer(&answer, 0).unwrap();
        assert_eq!(answer.v4(), [ip("192.0.2.10")]);
        assert_eq!(conn.connects(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_failure_is_logged_at_most_once_a_minute() {
        let server = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, DOT_PORT));
        let mut warned = None;
        warn_limited(&mut warned, server, "x");
        let first = warned.expect("the first failure is logged");
        tokio::time::advance(WARN_EVERY - ms(1)).await;
        warn_limited(&mut warned, server, "x");
        assert_eq!(warned, Some(first), "logged again within a minute");
        tokio::time::advance(ms(2)).await;
        warn_limited(&mut warned, server, "x");
        assert!(warned > Some(first), "not logged after a minute");
    }

    #[test]
    fn a_failure_is_worded_without_what_the_server_sent() {
        let rejected = |certificate| {
            let tls = rustls::Error::InvalidCertificate(certificate);
            io::Error::new(ErrorKind::InvalidData, tls)
        };
        let mismatch = rustls::CertificateError::NotValidForNameContext {
            expected: ServerName::try_from("dns.example.org").unwrap(),
            presented: vec!["secret.example.net".to_owned()],
        };
        assert_eq!(why(&rejected(mismatch)), "certificate rejected");
        assert_eq!(why(&io::Error::from(ErrorKind::TimedOut)), "timed out");
        assert_eq!(
            why(&io::Error::from(ErrorKind::ConnectionRefused)),
            "connection refused"
        );
    }

    #[tokio::test]
    async fn a_question_that_is_no_message_or_too_long_is_refused() {
        let (conn, fake) = up(quick()).await;
        for bad in [vec![], vec![0u8; HEADER_LEN - 1], vec![0u8; MAX_QUERY + 1]] {
            let error = conn.ask(bad).await.unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidInput);
        }
        assert_eq!(fake.queries(), 0);
    }

    #[tokio::test]
    async fn the_queue_and_the_table_are_bounded() {
        let fake = TlsFakeUpstream::start(Reply::Silent);
        // A stall that is not reached: every question stays open.
        let options = ConnOptions {
            stall: Duration::from_secs(60),
            ..quick()
        };
        let conn = Conn::spawn(fake.addr, tls_for_fake(&fake), options);
        until("the session", || conn.is_up()).await;
        // The queue takes MAX_FORWARDS before the task has run at all, and refuses the next.
        let held: Vec<_> = (0..MAX_FORWARDS)
            .map(|_| conn.ask(question("example.com")))
            .collect();
        let error = conn.ask(question("example.com")).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::WouldBlock);
        // All of them go out; the table is then full, and the next is refused by the task.
        until("every question to go out", || {
            fake.queries() == MAX_FORWARDS
        })
        .await;
        let error = timeout(Duration::from_secs(5), conn.ask(question("example.com")))
            .await
            .expect("a question over the table was left open")
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::WouldBlock);
        assert_eq!(fake.queries(), MAX_FORWARDS);
        assert!(conn.is_up());
        drop(held);
    }

    #[tokio::test]
    async fn dropping_the_conn_ends_the_questions_that_are_open() {
        let fake = TlsFakeUpstream::start(Reply::Silent);
        let options = ConnOptions {
            stall: Duration::from_secs(60),
            ..quick()
        };
        let conn = Conn::spawn(fake.addr, tls_for_fake(&fake), options);
        until("the session", || conn.is_up()).await;
        let open = conn.ask(question("example.com"));
        until("the question to go out", || fake.queries() == 1).await;
        drop(conn);
        let error = timeout(Duration::from_secs(5), open)
            .await
            .expect("the question outlived its connection")
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotConnected);
    }
    /// [`quick`] with sessions that idle out after `idle`.
    fn idling(idle: Duration) -> ConnOptions {
        ConnOptions { idle, ..quick() }
    }

    #[tokio::test]
    async fn a_session_that_carried_no_question_idles_out_and_the_next_question_opens_one() {
        let fake = TlsFakeUpstream::start(Reply::Answer(ip("192.0.2.10")));
        let conn = Conn::spawn(fake.addr, tls_for_fake(&fake), idling(ms(200)));
        until("the session", || conn.is_up()).await;
        // Nobody asks: the session is closed here, and none is opened in its place.
        until("the idle close", || conn.link() == Link::Idle).await;
        sleep(ms(400)).await;
        assert_eq!(conn.link(), Link::Idle);
        assert_eq!((conn.connects(), conn.counts().idle_closes), (1, 1));
        until("the server to see the close", || fake.handshakes() == 1).await;
        // A question opens the next, waits for it, and is answered.
        let answer = timeout(Duration::from_secs(5), conn.ask(question("example.com")))
            .await
            .expect("the question was left waiting")
            .expect("a question to an idle connection failed");
        assert_eq!(read_answer(&answer, 0).unwrap().v4(), [ip("192.0.2.10")]);
        assert_eq!(conn.connects(), 2);
        assert_eq!(conn.counts().server_closes, 0);
    }

    #[tokio::test]
    async fn a_session_that_carried_a_question_is_replaced_at_once_when_it_idles_out() {
        let fake = TlsFakeUpstream::start(Reply::Answer(ip("192.0.2.10")));
        let conn = Conn::spawn(fake.addr, tls_for_fake(&fake), idling(ms(200)));
        until("the session", || conn.is_up()).await;
        conn.ask(question("example.com")).await.unwrap();
        // Replaced without a question; and that one, which carries none, is not.
        until("the replacement", || conn.connects() == 2).await;
        until("the second idle close", || conn.link() == Link::Idle).await;
        sleep(ms(400)).await;
        assert_eq!(conn.counts().idle_closes, 2);
        assert_eq!(conn.connects(), 2);
    }

    #[tokio::test]
    async fn wake_opens_a_session_for_an_idle_connection_only() {
        let fake = TlsFakeUpstream::start(Reply::Answer(ip("192.0.2.10")));
        let conn = Conn::spawn(fake.addr, tls_for_fake(&fake), idling(ms(200)));
        until("the session", || conn.is_up()).await;
        // Up: nothing to do.
        conn.wake();
        until("the idle close", || conn.link() == Link::Idle).await;
        assert_eq!(conn.connects(), 1);
        conn.wake();
        until("the woken session", || conn.connects() == 2).await;
        until("the session", || conn.is_up()).await;
        // A wake and a question together, as an exchange makes them, open one session between
        // them; that one carried a question and is replaced once, and no wake is left over to
        // open another.
        until("the second idle close", || conn.link() == Link::Idle).await;
        conn.wake();
        conn.ask(question("example.com")).await.unwrap();
        until("the replacement", || conn.connects() == 4).await;
        until("the last idle close", || conn.link() == Link::Idle).await;
        sleep(ms(600)).await;
        assert_eq!(conn.connects(), 4);
    }

    #[tokio::test]
    async fn an_idle_close_by_the_server_is_followed_by_an_answer_and_no_error() {
        let mode = TlsMode {
            idle_close: Some(ms(200)),
            ..TlsMode::default()
        };
        let fake = TlsFakeUpstream::start_with(Reply::Answer(ip("192.0.2.10")), mode);
        // Sessions that live for the backoff to start over: the server's close is no failure.
        let options = ConnOptions {
            min_lived: ms(100),
            backoff_min: Duration::from_secs(60),
            backoff_max: Duration::from_secs(60),
            ..quick()
        };
        let conn = Conn::spawn(fake.addr, tls_for_fake(&fake), options);
        until("the session", || conn.is_up()).await;
        conn.ask(question("example.com")).await.unwrap();
        // The server ends it; the session carried a question, and the next is opened at once.
        until("the server's idle close", || fake.closed() >= 1).await;
        until("the second session", || conn.connects() == 2).await;
        let answer = timeout(Duration::from_secs(5), conn.ask(question("example.org")))
            .await
            .expect("the question was left waiting")
            .expect("a question after the server's idle close failed");
        assert_eq!(asked_name(&answer), "example.org.");
        assert!(conn.counts().server_closes >= 1);
        assert_eq!(conn.counts().retried, 0);
        assert_ne!(conn.link(), Link::Down);
    }

    #[tokio::test]
    async fn a_question_open_when_the_server_closes_is_sent_again_on_the_next_session() {
        // The fake closes a session as it reads its second query, without answering it: that
        // question met the close.
        let mode = TlsMode {
            close_on_query: Some(2),
            ..TlsMode::default()
        };
        let fake = TlsFakeUpstream::start_with(Reply::Answer(ip("192.0.2.10")), mode);
        let conn = Conn::spawn(fake.addr, tls_for_fake(&fake), quick());
        until("the session", || conn.is_up()).await;
        conn.ask(question("first.example.com")).await.unwrap();
        let began = StdInstant::now();
        let answer = timeout(
            Duration::from_secs(5),
            conn.ask(query(0x4242, "second.example.com", 1).unwrap()),
        )
        .await
        .expect("the question was left open")
        .expect("the question that met the close failed");
        // On the second session, under the asker's own ID, well within a client's wait.
        assert_eq!(
            read_answer(&answer, 0x4242).unwrap().v4(),
            [ip("192.0.2.10")]
        );
        assert_eq!(asked_name(&answer), "second.example.com.");
        assert!(
            began.elapsed() < Duration::from_secs(2),
            "took {:?}",
            began.elapsed()
        );
        assert_eq!((conn.connects(), fake.handshakes()), (2, 2));
        assert_eq!(fake.queries(), 3);
        let counts = conn.counts();
        assert_eq!(
            (counts.retried, counts.server_closes, counts.asked),
            (1, 1, 3)
        );
    }

    #[tokio::test]
    async fn a_question_is_sent_again_once_and_not_twice() {
        // Every session is closed as it reads its first query.
        let mode = TlsMode {
            close_on_query: Some(1),
            ..TlsMode::default()
        };
        let fake = TlsFakeUpstream::start_with(Reply::Answer(ip("192.0.2.10")), mode);
        let conn = Conn::spawn(fake.addr, tls_for_fake(&fake), quick());
        until("the session", || conn.is_up()).await;
        let error = timeout(Duration::from_secs(5), conn.ask(question("example.com")))
            .await
            .expect("the question was left open")
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotConnected);
        assert_eq!(fake.queries(), 2);
        assert_eq!(conn.counts().retried, 1);
    }

    #[tokio::test]
    async fn the_idle_timeout_that_the_server_advertises_is_kept() {
        // 6 × 100 ms: the session is closed here half of that after the answer, the margin
        // being more than half.
        let mode = TlsMode {
            keepalive: Some(6),
            ..TlsMode::default()
        };
        let fake = TlsFakeUpstream::start_with(Reply::Answer(ip("192.0.2.10")), mode);
        let conn = Conn::spawn(fake.addr, tls_for_fake(&fake), quick());
        until("the session", || conn.is_up()).await;
        conn.ask(question("example.com")).await.unwrap();
        let answered = StdInstant::now();
        // The question carried the option, as every question does.
        assert_eq!(fake.keepalive_asked(), 1);
        until("the idle close", || conn.counts().idle_closes == 1).await;
        let took = answered.elapsed();
        assert!(
            took >= ms(250) && took < Duration::from_secs(5),
            "closed after {took:?}"
        );
        // It carried a question: the next session is opened at once, with the options' idle time
        // until the server says otherwise.
        until("the next session", || conn.connects() == 2 && conn.is_up()).await;
        sleep(ms(600)).await;
        assert!(conn.is_up());
    }

    #[tokio::test]
    async fn a_server_that_advertises_no_idle_time_is_left_once_the_answers_are_in() {
        let mode = TlsMode {
            keepalive: Some(0),
            ..TlsMode::default()
        };
        let fake = TlsFakeUpstream::start_with(Reply::Answer(ip("192.0.2.10")), mode);
        let conn = Conn::spawn(fake.addr, tls_for_fake(&fake), quick());
        until("the session", || conn.is_up()).await;
        let began = StdInstant::now();
        conn.ask(question("example.com")).await.unwrap();
        until("the close", || conn.counts().idle_closes == 1).await;
        assert!(began.elapsed() < Duration::from_secs(5));
        // And the next question still has a session to go out on.
        let answer = timeout(Duration::from_secs(5), conn.ask(question("example.org")))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(asked_name(&answer), "example.org.");
    }

    #[test]
    fn the_keepalive_option_is_added_to_a_question_once() {
        let plain = question("example.com");
        let with = with_keepalive(&plain);
        assert_eq!(with.len(), plain.len() + 4);
        let message = Message::from_vec(&with).unwrap();
        let edns = message.edns.unwrap();
        let codes: Vec<u16> = edns
            .options()
            .as_ref()
            .iter()
            .map(|(code, _)| u16::from(*code))
            .collect();
        assert_eq!(codes, [KEEPALIVE]);
        // The rest is as it was: the header, the question, the payload size.
        assert_eq!(message.queries[0].name.to_ascii(), "example.com.");
        assert_eq!(
            edns.max_payload(),
            Message::from_vec(&plain)
                .unwrap()
                .edns
                .unwrap()
                .max_payload()
        );
        // Not twice; and a message without an OPT record, or one that cannot be read, is left.
        assert_eq!(with_keepalive(&with), with);
        let mut bare = Message::query();
        bare.add_query(hickory_proto::op::Query::query(
            hickory_proto::rr::Name::from_ascii("example.com.").unwrap(),
            hickory_proto::rr::RecordType::A,
        ));
        let bare = bare.to_vec().unwrap();
        assert_eq!(with_keepalive(&bare), bare);
        assert_eq!(
            with_keepalive(&plain[..plain.len() - 3]),
            plain[..plain.len() - 3]
        );
    }

    #[test]
    fn the_keepalive_timeout_of_an_answer_is_read() {
        let answer = crate::dns::testutil::response_bytes(1, "example.com", ip("192.0.2.10"));
        assert_eq!(keepalive(&answer), None);
        let advertised = advertise_keepalive(&answer, 50);
        assert_eq!(keepalive(&advertised), Some(Duration::from_secs(5)));
        assert_eq!(
            keepalive(&advertise_keepalive(&answer, 0)),
            Some(Duration::ZERO)
        );
        // Cut anywhere, it is never read past its end, and never panics.
        for len in 0..advertised.len() {
            let _ = keepalive(&advertised[..len]);
        }
        // A pointer for a name, as an answer's records have, is stepped over.
        assert!(answer.windows(2).any(|pair| pair[0] & 0xC0 == 0xC0));
        // The idle time is a second less, and half the timeout at the least.
        assert_eq!(idle_for(Duration::from_secs(10)), Duration::from_secs(9));
        assert_eq!(idle_for(Duration::from_millis(600)), ms(300));
        assert_eq!(idle_for(Duration::ZERO), Duration::ZERO);
    }
}

/// Measurements against the real Quad9 servers, which this host must be able to reach. Polite: a
/// question every few seconds at most, two sessions at a time. Run in release (the handshakes are
/// pure Rust), one at a time:
///
/// `cargo test -p qberrypi --release dns::dot::live -- --ignored --nocapture --test-threads 1`
#[cfg(test)]
mod live {
    use super::*;

    use std::thread;
    use std::time::Instant as StdInstant;

    use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
    use hickory_proto::rr::{Name, RecordType};
    use rustls::StreamOwned;

    const SERVERS: [&str; 2] = ["9.9.9.9:853", "149.112.112.112:853"];

    fn quad9() -> TlsUpstream {
        TlsUpstream {
            name: ServerName::try_from("dns.quad9.net").unwrap(),
            config: crate::https::client_config(crate::https::mozilla_roots()),
        }
    }

    type Stream = StreamOwned<ClientConnection, StdTcpStream>;

    /// A session through the real handshake, and the times of the connect and of the handshake.
    fn session(server: &str, tls: &TlsUpstream) -> (Stream, Duration, Duration, bool) {
        let addr: SocketAddr = server.parse().unwrap();
        let began = StdInstant::now();
        let tcp = StdTcpStream::connect_timeout(&addr, CONNECT_WAIT).unwrap();
        tcp.set_nodelay(true).unwrap();
        let connected = began.elapsed();
        let (conn, tcp) = handshake(tcp, tls.name.clone(), tls.config.clone()).unwrap();
        let shaken = began.elapsed() - connected;
        tcp.set_nonblocking(false).unwrap();
        let resumed = conn.handshake_kind() == Some(HandshakeKind::Resumed);
        (StreamOwned::new(conn, tcp), connected, shaken, resumed)
    }

    fn question(id: u16, name: &str, keepalive: bool) -> Vec<u8> {
        let mut message = Message::new(id, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        if keepalive {
            edns.options_mut()
                .insert(EdnsOption::Unknown(11, Vec::new()));
        }
        message.set_edns(edns);
        message.to_vec().unwrap()
    }

    fn send(stream: &mut Stream, query: &[u8]) {
        let len = u16::try_from(query.len()).unwrap().to_be_bytes();
        stream.write_all(&[&len[..], query].concat()).unwrap();
        stream.flush().unwrap();
    }

    /// How a read ended.
    #[derive(Debug)]
    enum Got {
        Frame(Vec<u8>),
        CloseNotify,
        Error(#[allow(dead_code, reason = "shown by Debug")] ErrorKind),
        Nothing,
    }

    /// The next frame, or how the session ended, within `wait`.
    fn read_frame(stream: &mut Stream, wait: Duration) -> Got {
        stream.sock.set_read_timeout(Some(wait)).unwrap();
        let mut len = [0u8; 2];
        match stream.read_exact(&mut len) {
            Ok(()) => {}
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Got::Nothing;
            }
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => {
                // rustls says a close notice is EOF (Ok(0)), which read_exact makes this; tell
                // the two apart by asking the session.
                return if stream.conn.wants_read() {
                    Got::Error(ErrorKind::UnexpectedEof)
                } else {
                    Got::CloseNotify
                };
            }
            Err(error) => return Got::Error(error.kind()),
        }
        let mut frame = vec![0u8; usize::from(u16::from_be_bytes(len))];
        stream
            .sock
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        match stream.read_exact(&mut frame) {
            Ok(()) => Got::Frame(frame),
            Err(error) => Got::Error(error.kind()),
        }
    }

    /// What the answer's OPT says of the keepalive: `None` without the option, else its
    /// timeout in milliseconds, if it holds one.
    fn keepalive_of(answer: &[u8]) -> Option<Option<u64>> {
        let message = Message::from_vec(answer).unwrap();
        let edns = message.edns?;
        match edns.option(EdnsCode::Keepalive)? {
            EdnsOption::Unknown(_, data) if data.len() == 2 => Some(Some(
                u64::from(u16::from_be_bytes([data[0], data[1]])) * 100,
            )),
            _ => Some(None),
        }
    }

    /// Waits for the server to end an idle session, for `max` at most: how long it took and how.
    fn until_closed(stream: &mut Stream, max: Duration) -> (Duration, Got) {
        let began = StdInstant::now();
        loop {
            match read_frame(stream, Duration::from_secs(1)) {
                Got::Nothing if began.elapsed() < max => {}
                Got::Frame(frame) => println!("    unasked frame of {} bytes", frame.len()),
                end => return (began.elapsed(), end),
            }
        }
    }

    fn both(work: impl Fn(&'static str) + Send + Sync + Copy + 'static) {
        let threads: Vec<_> = SERVERS
            .iter()
            .map(|&server| thread::spawn(move || work(server)))
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
    }

    #[test]
    #[ignore = "reaches the real Quad9"]
    fn handshakes_full_and_resumed() {
        for server in SERVERS {
            for round in 0..3 {
                // A fresh client side: nothing to resume.
                let tls = quad9();
                let (mut first, connect, full, resumed) = session(server, &tls);
                assert!(!resumed);
                let version = first.conn.protocol_version();
                let suite = first.conn.negotiated_cipher_suite().map(|s| s.suite());
                // An answer, so that the tickets that came after the handshake are read.
                send(&mut first, &question(1, "example.com.", false));
                let _ = read_frame(&mut first, Duration::from_secs(3));
                println!("  {version:?} {suite:?}");
                first.conn.send_close_notify();
                let _ = first.flush();
                drop(first);
                thread::sleep(Duration::from_millis(500));
                let (mut second, connect2, again, resumed) = session(server, &tls);
                second.conn.send_close_notify();
                let _ = second.flush();
                println!(
                    "{server} #{round}: connect {connect:?} full {full:?} | connect {connect2:?} {} {again:?}",
                    if resumed { "resumed" } else { "NOT resumed" }
                );
                thread::sleep(Duration::from_secs(1));
            }
        }
    }

    /// Opens a session, reads one answer (and with it the tickets), and closes it: whether it
    /// resumed, and the handshake's time.
    fn one(server: &str, tls: &TlsUpstream) -> (bool, Duration) {
        let (mut stream, _, shaken, resumed) = session(server, tls);
        send(&mut stream, &question(1, "example.com.", false));
        let _ = read_frame(&mut stream, Duration::from_secs(3));
        stream.conn.send_close_notify();
        let _ = stream.flush();
        (resumed, shaken)
    }

    #[test]
    #[ignore = "reaches the real Quad9"]
    fn tickets_across_the_two_addresses() {
        let shared = quad9();
        let mut seen = Vec::new();
        for round in 0..8 {
            let server = SERVERS[round % 2];
            seen.push((server, one(server, &shared)));
            thread::sleep(Duration::from_millis(500));
        }
        println!("one store, alternating: {seen:?}");
        for server in SERVERS {
            let own = quad9();
            let mut seen = Vec::new();
            for _ in 0..4 {
                seen.push(one(server, &own));
                thread::sleep(Duration::from_millis(500));
            }
            println!("{server} with a store of its own: {seen:?}");
        }
    }

    #[test]
    #[ignore = "reaches the real Quad9"]
    fn idle_sessions_end() {
        both(|server| {
            let tls = quad9();
            // Idle from the handshake.
            let (mut stream, ..) = session(server, &tls);
            let (took, how) = until_closed(&mut stream, Duration::from_secs(150));
            println!("{server} no question: ended after {took:?}: {how:?}");
            // Idle after one question without the option.
            let (mut stream, ..) = session(server, &tls);
            send(&mut stream, &question(1, "example.com.", false));
            let Got::Frame(answer) = read_frame(&mut stream, Duration::from_secs(3)) else {
                panic!("no answer");
            };
            println!(
                "{server} plain answer keepalive: {:?}",
                keepalive_of(&answer)
            );
            let (took, how) = until_closed(&mut stream, Duration::from_secs(150));
            println!("{server} after a plain question: ended after {took:?}: {how:?}");
            // And with the option.
            let (mut stream, ..) = session(server, &tls);
            send(&mut stream, &question(2, "example.com.", true));
            let Got::Frame(answer) = read_frame(&mut stream, Duration::from_secs(3)) else {
                panic!("no answer");
            };
            let message = Message::from_vec(&answer).unwrap();
            println!(
                "{server} keepalive answer: {:?}; options {:?}; asked {:02x?}",
                keepalive_of(&answer),
                message.edns.as_ref().map(|edns| edns
                    .options()
                    .as_ref()
                    .iter()
                    .map(|(code, _)| *code)
                    .collect::<Vec<_>>()),
                &question(2, "example.com.", true)[28..],
            );
            let (took, how) = until_closed(&mut stream, Duration::from_secs(150));
            println!("{server} after a keepalive question: ended after {took:?}: {how:?}");
        });
    }

    /// A question every `PROBE_EVERY_MS` (default 2,000) for `PROBE_FOR_S` seconds (default 60):
    /// whether a session that is used lives on, and for how long.
    #[test]
    #[ignore = "reaches the real Quad9"]
    fn a_used_session_lives() {
        let every = std::env::var("PROBE_EVERY_MS").map_or(2000, |v| v.parse().unwrap());
        let total = std::env::var("PROBE_FOR_S").map_or(60, |v| v.parse().unwrap());
        both(move |server| {
            let tls = quad9();
            let (mut stream, ..) = session(server, &tls);
            let began = StdInstant::now();
            let mut asked = 0u16;
            while began.elapsed() < Duration::from_secs(total) {
                asked += 1;
                send(&mut stream, &question(asked, "example.com.", true));
                match read_frame(&mut stream, Duration::from_secs(3)) {
                    Got::Frame(_) => {}
                    other => {
                        println!(
                            "{server} question {asked} at {:?}: {other:?}",
                            began.elapsed()
                        );
                        return;
                    }
                }
                thread::sleep(Duration::from_millis(every));
            }
            println!(
                "{server}: {asked} questions every {every} ms, session alive after {:?}",
                began.elapsed()
            );
        });
    }

    /// Questions sent `PROBE_AT_MS` after the last answer (default 9,900), three pipelined:
    /// what comes of questions that meet the server's close.
    #[test]
    #[ignore = "reaches the real Quad9"]
    fn questions_at_the_close() {
        let at: u64 = std::env::var("PROBE_AT_MS").map_or(9900, |v| v.parse().unwrap());
        both(move |server| {
            let tls = quad9();
            let (mut stream, ..) = session(server, &tls);
            send(&mut stream, &question(1, "example.com.", false));
            let Got::Frame(_) = read_frame(&mut stream, Duration::from_secs(3)) else {
                panic!("no answer");
            };
            thread::sleep(Duration::from_millis(at));
            for id in 10..13 {
                let len = u16::try_from(question(id, "example.com.", false).len()).unwrap();
                let frame = [&len.to_be_bytes()[..], &question(id, "example.com.", false)].concat();
                if let Err(error) = stream.write_all(&frame).and_then(|()| stream.flush()) {
                    println!(
                        "{server} at {at} ms: write of {id} failed: {:?}",
                        error.kind()
                    );
                }
            }
            for _ in 0..4 {
                match read_frame(&mut stream, Duration::from_secs(3)) {
                    Got::Frame(frame) => {
                        println!(
                            "{server} at {at} ms: answer to {}",
                            u16::from_be_bytes([frame[0], frame[1]])
                        );
                    }
                    other => {
                        println!("{server} at {at} ms: {other:?}");
                        return;
                    }
                }
            }
        });
    }

    /// The real [`Conn`] left alone for `PROBE_FOR_S` (default 120) seconds: when its sessions
    /// come and go.
    #[tokio::test]
    #[ignore = "reaches the real Quad9"]
    async fn the_conn_left_alone() {
        let total: u64 = std::env::var("PROBE_FOR_S").map_or(120, |v| v.parse().unwrap());
        let tls = quad9();
        let conns: Vec<Conn> = SERVERS
            .iter()
            .map(|server| Conn::spawn(server.parse().unwrap(), tls.clone(), ConnOptions::default()))
            .collect();
        let began = StdInstant::now();
        let mut last: Vec<(bool, u64)> = vec![(false, 0); conns.len()];
        while began.elapsed() < Duration::from_secs(total) {
            for (index, conn) in conns.iter().enumerate() {
                let now = (conn.is_up(), conn.connects());
                if now != last[index] {
                    println!(
                        "{:>8.2?} {}: up {} connects {} resumed {}",
                        began.elapsed(),
                        SERVERS[index],
                        now.0,
                        now.1,
                        conn.resumed()
                    );
                    last[index] = now;
                }
            }
            sleep(Duration::from_millis(5)).await;
        }
    }
}
