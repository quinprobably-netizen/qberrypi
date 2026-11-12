//! The Pi-hole API subset that qberrypi serves over TLS on port 443: the login, the statistics
//! and the blocking switch that qnet and other Pi-hole clients use, and, under `/api/qbp/`, the
//! watchdog's alerts and devices ([`qbp`]).
//!
//! [`serve`] is the listener. It accepts on the runtime and does nothing else there: each
//! connection, from its TLS handshake to its close, is one job of the blocking pool
//! ([`crate::services::blocking`]), and at most [`CONNECTIONS`] of them are alive at once, so the
//! API never has more than that many threads of the pool and DNS, on the runtime thread, never
//! waits for it. The places that count them ([`places`]) belong to the caller and outlive any one
//! [`serve`]: a listener that is started again after a failure, while the connections of the last
//! one are still running, finds their places taken, and the bound holds across the restart.
//!
//! An `accept` that fails is, for the errors that the kernel gives for one connection that was
//! lost or for a passing shortage, retried after a pause ([`ACCEPT_PAUSE`], [`ACCEPT_SHORTAGE_PAUSE`])
//! and ends [`serve`] only after [`ACCEPT_FAILURES`] failures in a row.
//!
//! A connection is bounded by [`Limits`] from every side. The clock of a connection starts when
//! it is accepted. Every read and write of its socket goes through a [`Deadlined`], which sets
//! the socket's timeout before each call to the shorter of that call's wait and what is left
//! of the connection's deadline, and fails once the deadline has passed: the handshake, which a
//! client could drip bytes into for ever with a timeout per read, ends at [`HANDSHAKE_WAIT`] as a
//! whole, and the requests at [`CONNECTION_LIFE`]. Every request that cannot be read closes the
//! connection, and a refusal says why when the client is still owed an answer. No log line here
//! names a client, a session or a body: the log is open to the network.
//!
//! One request is read in another way. `POST /api/qbp/update`, which an API that has an update
//! receiver ([`routes::Api::with_update`]) takes, is recognised from its head: without a valid
//! session it is a 401 and no byte of its body is read; with one, its body is streamed to the
//! receiver on this same thread, bounded by [`Limits::upload`] for the whole request counted from
//! its head and by [`Limits::upload_idle`] for each read, in place of the connection's life and
//! idle wait. The reply is written under a fresh [`WRITE_WAIT`] and the connection closes after it,
//! whatever the client asked.

use std::future::Future;
use std::io::{self, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::{ServerConfig, ServerConnection, StreamOwned};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use zeroize::Zeroize;

use self::http::{
    Head, ReadError, Reply, Request, read_request_body, read_request_head, write_reply,
};
use self::routes::Api;
use crate::services::blocking;
use crate::update::receive::{self, Receiver};

mod hex;
pub mod http;
pub mod live;
pub mod password;
pub mod qbp;
pub mod routes;
pub mod seams;
pub mod session;
#[cfg(test)]
pub(crate) mod testutil;
pub mod tls;

/// The port that the API is served on, over TLS only.
pub const PORT: u16 = 443;
/// The most connections served at once: the API's share of the blocking pool.
pub const CONNECTIONS: usize = 2;
/// How many failures of `accept` in a row, with no connection accepted between, [`serve`] puts up
/// with. The failure that makes this many ends it with that failure's error, and the supervisor
/// sees a component that failed, as it did when any failure ended it, so an `accept` that never
/// recovers still reaches its rule of three failures in a row.
pub const ACCEPT_FAILURES: usize = 10;
/// How long [`serve`] waits after an `accept` that failed with the error of one connection that
/// the kernel had already lost or refused (`ECONNABORTED`, `EPROTO`, `EPERM` and the network
/// errors that accept(2) lists), before it tries again. Short, as the next connection in the
/// queue is a good one, and long enough that a failure that repeats does not spin the runtime.
pub const ACCEPT_PAUSE: Duration = Duration::from_millis(100);
/// How long [`serve`] waits after an `accept` that failed for want of a descriptor or memory
/// (`EMFILE`, `ENFILE`, `ENOBUFS`, `ENOMEM`), which only something else letting go can cure.
/// Ten of them in a row make nine of these pauses, nine seconds, before the failure is final.
pub const ACCEPT_SHORTAGE_PAUSE: Duration = Duration::from_secs(1);
/// How long after one run of failed accepts was logged the start of the next may be, so that
/// failures that come and go, with a connection accepted between, write a line a minute at most.
const ACCEPT_LOG_GAP: Duration = Duration::from_secs(60);
/// How long a client has for its TLS handshake, as a whole.
pub const HANDSHAKE_WAIT: Duration = Duration::from_secs(5);
/// How long a connection waits for the next bytes of a request, or for the next request.
pub const IDLE_WAIT: Duration = Duration::from_secs(5);
/// How long a write waits for a client that does not read.
pub const WRITE_WAIT: Duration = Duration::from_secs(5);
/// How long a connection lives, counted from when it was accepted.
pub const CONNECTION_LIFE: Duration = Duration::from_secs(60);
/// The most requests one connection answers.
pub const MAX_REQUESTS: usize = 100;
/// How long the update's request may take, counted from its head: ten minutes.
pub const UPLOAD_LIFE: Duration = Duration::from_secs(600);
/// How long the update's request waits for the next bytes of its body.
pub const UPLOAD_IDLE_WAIT: Duration = Duration::from_secs(30);

/// What bounds each connection: how long each of its waits and its life may be. How many are
/// alive at once is for the [`places`] to say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The whole TLS handshake.
    pub handshake: Duration,
    /// Each wait for bytes from the client once the handshake is done.
    pub idle: Duration,
    /// The life of a connection, from its accept.
    pub life: Duration,
    /// The whole of the update's request, from the moment its head was read, which takes the place
    /// of `life` for it.
    pub upload: Duration,
    /// Each wait for bytes of the update's body, which takes the place of `idle` for it.
    pub upload_idle: Duration,
}

impl Limits {
    /// The spec's limits.
    pub const DEFAULT: Limits = Limits {
        handshake: HANDSHAKE_WAIT,
        idle: IDLE_WAIT,
        life: CONNECTION_LIFE,
        upload: UPLOAD_LIFE,
        upload_idle: UPLOAD_IDLE_WAIT,
    };
}

/// The places for the API's connections: [`CONNECTIONS`] of them, which every [`serve`] that
/// shares them takes from. A connection holds its place until its job on the blocking pool ends,
/// whichever listener accepted it.
///
/// The caller makes them once and keeps them across every start of the listener: a start that
/// came after a failure, with the last one's connections still running, would otherwise have
/// places of its own, and the API would hold more threads of the pool than its share.
pub fn places() -> Arc<Semaphore> {
    Arc::new(Semaphore::new(CONNECTIONS))
}

/// Serves the API on `listener` for ever: a connection that is accepted becomes a job of the
/// blocking pool that runs its TLS handshake from `tls` and answers its requests from `api`.
///
/// A place is taken from `places` before `accept`, so that no more clients are ever served than
/// `places` has places for, and one that comes while they are is left in the kernel's queue and
/// accepted when a place is free. The place moves into the connection's job and goes back when the
/// job ends, however it ends. A peer that is not IPv4 is closed at once.
///
/// An `accept` that fails with the error of one lost connection or of a passing shortage is
/// retried after a pause ([`ACCEPT_PAUSE`], [`ACCEPT_SHORTAGE_PAUSE`]), and the first failure of a
/// run of them is logged once, and its end with the count. Returns the error when `accept` fails
/// [`ACCEPT_FAILURES`] times in a row, or at once with an error that no retry cures (a closed
/// or invalid listener, and any error that is not known to be passing).
///
/// The runtime thread does the accept, the change of the stream into a blocking one and the hand
/// off, which are a few system calls, and nothing else; the pause is a timer of the runtime.
pub async fn serve(
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    api: Arc<Api>,
    limits: Limits,
    places: Arc<Semaphore>,
) -> io::Result<()> {
    serve_accepting(|| listener.accept(), tls, api, limits, places).await
}

/// [`serve`] over any way of accepting, which is the seam that the tests use to make `accept`
/// fail: `accept` is called for the next connection, and gives it or the error.
async fn serve_accepting<A, F>(
    mut accept: A,
    tls: Arc<ServerConfig>,
    api: Arc<Api>,
    limits: Limits,
    places: Arc<Semaphore>,
) -> io::Result<()>
where
    A: FnMut() -> F,
    F: Future<Output = io::Result<(tokio::net::TcpStream, SocketAddr)>>,
{
    let mut run = AcceptRun::default();
    loop {
        let place = places
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| io::Error::other("the connection places are closed"))?;
        let (stream, peer) = match accept().await {
            Ok(accepted) => {
                if let Some(failures) = run.worked() {
                    log::info!("api: accepting again after {failures} failed accepts");
                }
                accepted
            }
            Err(error) => match run.failed(&error, Instant::now()) {
                Next::End => return Err(error),
                Next::Retry { pause, say } => {
                    if say {
                        log::warn!("api: accept failed, trying again: {error}");
                    }
                    // The place is free for the pause, as it was before the accept.
                    drop(place);
                    tokio::time::sleep(pause).await;
                    continue;
                }
            },
        };
        let accepted = Instant::now();
        // The listener is on `0.0.0.0`, so every peer is IPv4; the place goes back with the
        // stream that is dropped here.
        let SocketAddr::V4(peer) = peer else {
            continue;
        };
        let Ok(stream) = stream.into_std().and_then(|stream| {
            stream.set_nonblocking(false)?;
            stream.set_nodelay(true)?;
            Ok(stream)
        }) else {
            continue;
        };
        let (tls, api) = (tls.clone(), api.clone());
        tokio::spawn(async move {
            // The place is the job's, and goes back when the job ends, however it ends.
            let _ = blocking("api connection", move || {
                let _place = place;
                connection(stream, *peer.ip(), tls, &api, limits, accepted);
            })
            .await;
        });
    }
}

/// How an `accept` error is met.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Failure {
    /// The error of one connection that was lost or refused before it was accepted, or of the
    /// network under it: the next one is not touched by it. The errors that accept(2) says to
    /// treat as `EAGAIN` on Linux, which passes them on from the new socket (`ENETDOWN`, `EPROTO`,
    /// `ENOPROTOOPT`, `EHOSTDOWN`, `ENONET`, `EHOSTUNREACH`, `EOPNOTSUPP`, `ENETUNREACH`), and
    /// `ECONNABORTED`, `EPERM` (a firewall rule refused the connection), `EINTR` and `ETIMEDOUT`.
    Passing,
    /// No descriptor or memory to make the connection with (`EMFILE`, `ENFILE`, `ENOBUFS`,
    /// `ENOMEM`): it clears only when something else lets go, and a short pause would spin.
    Shortage,
    /// Anything else, which a retry on the same listener does not cure (`EBADF`, `EINVAL`,
    /// `ENOTSOCK`, `EFAULT`), and any error that has no number of the kernel's or is not known.
    Lasting,
}

impl Failure {
    /// How `error`, which `accept` gave, is met.
    fn of(error: &io::Error) -> Failure {
        match error.raw_os_error() {
            Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM) => Failure::Shortage,
            Some(
                libc::ECONNABORTED
                | libc::EPROTO
                | libc::EPERM
                | libc::ETIMEDOUT
                | libc::EINTR
                | libc::ENETDOWN
                | libc::ENOPROTOOPT
                | libc::EHOSTDOWN
                | libc::ENONET
                | libc::EHOSTUNREACH
                | libc::EOPNOTSUPP
                | libc::ENETUNREACH,
            ) => Failure::Passing,
            _ => Failure::Lasting,
        }
    }
}

/// What [`serve`] does after a failed `accept`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Next {
    /// Ends with the error.
    End,
    /// Waits `pause` and tries again, and logs the failure if `say`.
    Retry { pause: Duration, say: bool },
}

/// The failures of `accept` in a row that [`serve`] has met, and what it has said about them.
#[derive(Debug, Default)]
struct AcceptRun {
    /// Failures since the last accept that worked.
    failures: usize,
    /// Whether the start of this run was logged, and so its end is to be.
    said: bool,
    /// When the start of a run was last logged.
    last_said: Option<Instant>,
}

impl AcceptRun {
    /// A failure of `accept` with `error`, at `now`: whether to go on, after how long, and whether
    /// to log it. Only the first failure of a run is logged, and only if no run was logged in the
    /// last [`ACCEPT_LOG_GAP`]; a log that is open to the network cannot be filled by a burst.
    fn failed(&mut self, error: &io::Error, now: Instant) -> Next {
        let pause = match Failure::of(error) {
            Failure::Lasting => return Next::End,
            Failure::Passing => ACCEPT_PAUSE,
            Failure::Shortage => ACCEPT_SHORTAGE_PAUSE,
        };
        self.failures += 1;
        if self.failures >= ACCEPT_FAILURES {
            return Next::End;
        }
        let say = self.failures == 1
            && self
                .last_said
                .is_none_or(|at| now.saturating_duration_since(at) >= ACCEPT_LOG_GAP);
        if say {
            self.said = true;
            self.last_said = Some(now);
        }
        Next::Retry { pause, say }
    }

    /// An `accept` worked, which ends the run: `Some(failures)` if the run's start was logged, so
    /// that its end is.
    fn worked(&mut self) -> Option<usize> {
        let said = std::mem::take(&mut self.said).then_some(self.failures);
        self.failures = 0;
        said
    }
}

/// A socket whose every read and write is bounded by a deadline.
///
/// Before each read the socket's timeout is the shorter of `read_wait` and what is left until
/// `deadline`, and before each write the shorter of `write_wait` and what is left; once the
/// deadline has passed, a read or a write fails with `TimedOut` without touching the socket. So
/// no client can keep a call waiting past the deadline by sending a byte now and then. A timeout
/// of the socket is `TimedOut`, whatever the system calls it.
struct Deadlined {
    stream: TcpStream,
    deadline: Instant,
    read_wait: Duration,
    write_wait: Duration,
}

impl Deadlined {
    /// What is left until the deadline; `TimedOut` once it has passed.
    fn left(&self) -> io::Result<Duration> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            Err(io::ErrorKind::TimedOut.into())
        } else {
            Ok(left)
        }
    }

    /// Bounds what follows by `deadline`, and each of its reads and writes by the waits.
    fn bound(&mut self, deadline: Instant, read_wait: Duration, write_wait: Duration) {
        self.deadline = deadline;
        self.read_wait = read_wait;
        self.write_wait = write_wait;
    }
}

/// A socket's timeout as `TimedOut`: on Unix it is `WouldBlock`, which a TLS stream would take
/// for "no data yet".
fn timed_out<T>(result: io::Result<T>) -> io::Result<T> {
    result.map_err(|error| match error.kind() {
        io::ErrorKind::WouldBlock => io::ErrorKind::TimedOut.into(),
        _ => error,
    })
}

impl Read for Deadlined {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let wait = self.left()?.min(self.read_wait);
        self.stream.set_read_timeout(Some(wait))?;
        timed_out(self.stream.read(buf))
    }
}

impl Write for Deadlined {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let wait = self.left()?.min(self.write_wait);
        self.stream.set_write_timeout(Some(wait))?;
        timed_out(self.stream.write(buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

/// The TLS stream of a connection, as a request is read from it.
type Stream = BufReader<StreamOwned<ServerConnection, Deadlined>>;

/// One connection, accepted at `accepted`, from its handshake to its close. Runs on a thread of
/// the blocking pool, and ends when the client is done, asks to close, has been answered
/// [`MAX_REQUESTS`] times, runs out of the time of any limit or breaks the protocol.
fn connection(
    stream: TcpStream,
    peer: Ipv4Addr,
    tls: Arc<ServerConfig>,
    api: &Api,
    limits: Limits,
    accepted: Instant,
) {
    let life_end = accepted + limits.life;
    let mut socket = Deadlined {
        stream,
        deadline: life_end,
        read_wait: limits.handshake,
        write_wait: WRITE_WAIT,
    };
    let Ok(mut conn) = ServerConnection::new(tls) else {
        return;
    };
    // The handshake as a whole is bounded, and not each read of it.
    socket.bound(
        life_end.min(Instant::now() + limits.handshake),
        limits.handshake,
        WRITE_WAIT,
    );
    while conn.is_handshaking() {
        if conn.complete_io(&mut socket).is_err() {
            return;
        }
    }
    socket.bound(life_end, limits.idle, WRITE_WAIT);
    let mut stream: Stream = BufReader::new(StreamOwned::new(conn, socket));

    let mut served = 0;
    loop {
        let head = match read_request_head(&mut stream) {
            Ok(head) => head,
            Err(error) => {
                refuse_unreadable(&mut stream, error);
                break;
            }
        };
        if let Some(receiver) = api
            .receiver()
            .filter(|_| head.method == "POST" && head.target == receive::PATH)
        {
            upload(&mut stream, api, receiver, &head, limits);
            break;
        }
        let mut request = match read_request_body(&mut stream, head) {
            Ok(request) => request,
            Err(error) => {
                refuse_unreadable(&mut stream, error);
                break;
            }
        };
        served += 1;
        let reply = answer(api, &mut request, peer);
        // The last request that fits in the connection's life says so: another could not be read
        // within an idle wait.
        let last = request.close
            || served >= MAX_REQUESTS
            || life_end.saturating_duration_since(Instant::now()) < limits.idle;
        if write_reply(stream.get_mut(), &reply, last).is_err() || last {
            break;
        }
    }
    say_goodbye(&mut stream);
}

/// Answers a request that could not be read, if the client is still owed an answer: a head or a
/// body over the limits is a 413 and bytes that are no request a 400; a peer that is done, or
/// stalled, or out of time is owed nothing.
fn refuse_unreadable(stream: &mut Stream, error: ReadError) {
    let reply = match error {
        ReadError::TooLarge => routes::too_large(),
        ReadError::Malformed(_) => routes::malformed(),
        ReadError::Closed | ReadError::Io(_) => return,
    };
    let _ = write_reply(stream.get_mut(), &reply, true);
}

/// Serves `POST /api/qbp/update`, whose head has been read and whose body has not: a request
/// without a valid session is a 401 and nothing more is read; otherwise `receiver` takes the body
/// from the stream under the upload's bounds, and the reply is written under a fresh write wait.
/// The restart that a staged update asks for follows the reply ([`receive::Received`]).
fn upload(stream: &mut Stream, api: &Api, receiver: &Receiver, head: &Head, limits: Limits) {
    if !api.has_session(head.sid.as_deref()) {
        let _ = write_reply(stream.get_mut(), &routes::unauthorized(), true);
        return;
    }
    stream.get_mut().sock.bound(
        Instant::now() + limits.upload,
        limits.upload_idle,
        WRITE_WAIT,
    );
    let received = receiver.receive(head, stream);
    // The upload may have used its whole time: the answer to it still gets its own.
    stream
        .get_mut()
        .sock
        .bound(Instant::now() + WRITE_WAIT, limits.idle, WRITE_WAIT);
    let _ = received.send_then_restart(|reply| write_reply(stream.get_mut(), reply, true));
}

/// Answers `request`, which came from `peer`, and wipes its body, which may be a password, before
/// anything else is read.
///
/// What this does not reach: the copies that TLS and the reader hold, which are rustls's
/// plaintext buffer and the `BufReader`'s, and are overwritten by what follows or freed with the
/// connection. They are not wiped here, which is a known limit.
fn answer(api: &Api, request: &mut Request, peer: Ipv4Addr) -> Reply {
    let reply = api.handle(request, peer);
    request.body.zeroize();
    reply
}

/// Tells the client that the connection ends, if that can be done without waiting: the TLS close
/// notice, so that a client that reads to the end of a reply does not take the close for an
/// attack. The socket is closed by what follows.
fn say_goodbye(stream: &mut Stream) {
    let tls = stream.get_mut();
    tls.conn.send_close_notify();
    while tls.conn.wants_write() {
        if tls.conn.write_tls(&mut tls.sock).is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use rustls::pki_types::CertificateDer;
    use tokio::net::TcpListener;

    use super::http::Request;
    use super::live::LiveFacts;
    use super::password::PasswordHash;
    use super::routes::Api;
    use super::testutil::{Connection, certificate, https, pem, pinned_client};
    use super::tls::server_config;
    use super::*;
    use crate::dns::Dns;
    use crate::dns::testutil::{FakeUpstream, Reply, ask_udp, one};
    use crate::services::testutil::longest_gap;
    use crate::services::{self, blocking};
    use crate::wiring::Extras;

    const MS: Duration = Duration::from_millis(1);

    /// What `served` starts.
    struct Served {
        /// Where the API listens, on `127.0.0.1`.
        addr: SocketAddr,
        /// The resolver the API answers from, and where it answers queries over UDP.
        dns: Arc<Dns>,
        dns_addr: SocketAddr,
        /// The certificate the API serves.
        cert: CertificateDer<'static>,
        /// What the API serves from, for a test that starts a listener of its own beside it.
        tls: Arc<ServerConfig>,
        api: Arc<Api>,
        /// The listener's task, which ends with what [`serve`] returns.
        ended: tokio::task::JoinHandle<io::Result<()>>,
        /// The upstream the resolver asks, which must live as long as the test.
        _upstream: FakeUpstream,
    }

    /// The API over `Dns`, the password `right` and a certificate made now, serving on a
    /// `127.0.0.1` port under `limits` and the default places until the test ends.
    async fn served(limits: Limits) -> Served {
        served_by(move |listener, tls, api| serve(listener, tls, api, limits, places())).await
    }

    /// [`served`] with the listener's task made by `run` from the listener on a `127.0.0.1` port
    /// and what the API serves from.
    async fn served_by<F>(run: impl FnOnce(TcpListener, Arc<ServerConfig>, Arc<Api>) -> F) -> Served
    where
        F: Future<Output = io::Result<()>> + Send + 'static,
    {
        let (dns, dns_addr, upstream) = one(Reply::Answer("192.0.2.1".parse().unwrap())).await;
        let pem = pem();
        let cert = certificate(&pem);
        let tls = server_config(pem.as_bytes()).unwrap();
        let api = Arc::new(Api::new(
            PasswordHash::new(b"right", [0; 16]),
            Arc::new(LiveFacts {
                dns: dns.clone(),
                extras: Arc::new(Extras::default),
            }),
            {
                let dns = dns.clone();
                Arc::new(move || dns.now().mono_secs)
            },
            Arc::new(|| Some([7; 16])),
        ));
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let ended = tokio::spawn(run(listener, tls.clone(), api.clone()));
        Served {
            addr,
            dns,
            dns_addr,
            cert,
            tls,
            api,
            ended,
            _upstream: upstream,
        }
    }

    /// The default limits with the times that a test waits for shortened.
    fn small() -> Limits {
        Limits {
            handshake: 300 * MS,
            idle: 300 * MS,
            ..Limits::DEFAULT
        }
    }

    #[test]
    fn the_limits_are_the_specs() {
        assert_eq!((PORT, CONNECTIONS, MAX_REQUESTS), (443, 2, 100));
        let secs = Duration::from_secs;
        assert_eq!(
            (HANDSHAKE_WAIT, IDLE_WAIT, WRITE_WAIT, CONNECTION_LIFE),
            (secs(5), secs(5), secs(5), secs(60))
        );
        let limits = Limits::DEFAULT;
        assert_eq!(
            (limits.handshake, limits.idle, limits.life),
            (HANDSHAKE_WAIT, IDLE_WAIT, CONNECTION_LIFE)
        );
        // The update's request: ten minutes from its head, 30 s for each read.
        assert_eq!((UPLOAD_LIFE, UPLOAD_IDLE_WAIT), (secs(600), secs(30)));
        assert_eq!(
            (limits.upload, limits.upload_idle),
            (UPLOAD_LIFE, UPLOAD_IDLE_WAIT)
        );
        assert_eq!(places().available_permits(), CONNECTIONS);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn qnets_kind_of_client_logs_in_reads_and_pauses_the_resolver() {
        let served = served(Limits::DEFAULT).await;
        let (addr, dns, cert) = (served.addr, &served.dns, &served.cert);
        let login = https(
            addr,
            pinned_client(cert),
            &[r#"POST /api/auth|{"password":"right"}"#],
        )
        .await;
        assert_eq!(login[0].0, 200);
        let sid = login[0].1["session"]["sid"].as_str().unwrap().to_owned();

        let polled = https(
            addr,
            pinned_client(cert),
            &[
                &format!("GET /api/stats/summary|sid={sid}"),
                &format!("GET /api/dns/blocking|sid={sid}"),
                &format!("GET /api/history|sid={sid}"),
                &format!("GET /api/stats/upstreams|sid={sid}"),
            ],
        )
        .await;
        // Four requests, one kept-alive connection.
        assert!(
            polled.iter().all(|(status, _)| *status == 200),
            "{polled:?}"
        );
        assert_eq!(polled[1].1["blocking"], "enabled");
        assert_eq!(polled[2].1["history"].as_array().unwrap().len(), 144);
        assert_eq!(polled[3].1["upstreams"].as_array().unwrap().len(), 3);

        let paused = https(
            addr,
            pinned_client(cert),
            &[&format!(
                r#"POST /api/dns/blocking|sid={sid}|{{"blocking":false,"timer":300}}"#
            )],
        )
        .await;
        assert_eq!(paused[0].0, 200);
        assert!(dns.resolver().paused_until(dns.now()).is_some());
        // And the same pause is what the API reads back.
        let read = https(
            addr,
            pinned_client(cert),
            &[&format!("GET /api/dns/blocking|sid={sid}")],
        )
        .await;
        assert_eq!(read[0].1["blocking"], "disabled");
    }

    #[tokio::test]
    async fn a_client_pinned_to_another_certificate_is_refused_in_the_handshake() {
        let served = served(Limits::DEFAULT).await;
        let addr = served.addr;
        let other = certificate(&pem());

        let refused = tokio::task::spawn_blocking(move || {
            Connection::open(addr, pinned_client(&other)).is_err()
        })
        .await
        .unwrap();
        assert!(refused);

        // The server goes on: the next client, with the right pin, is served.
        let next = https(addr, pinned_client(&served.cert), &["GET /api/auth"]).await;
        assert_eq!(next[0].0, 401);
    }

    // Review Focus 2.
    #[tokio::test]
    async fn two_silent_connections_do_not_keep_a_third_out_for_long_and_dns_answers_meanwhile() {
        let served = served(small()).await;
        let addr = served.addr;
        let mut silent: Vec<TcpStream> =
            (0..2).map(|_| TcpStream::connect(addr).unwrap()).collect();

        // A third, as qnet's, while the two hold the API's two places.
        let began = Instant::now();
        let (third, dns_answer) = tokio::join!(
            https(addr, pinned_client(&served.cert), &["GET /api/auth"]),
            ask_udp(served.dns_addr, "example.com"),
        );

        assert_eq!(third[0].0, 401);
        assert!(
            began.elapsed() < Duration::from_secs(1),
            "{:?}",
            began.elapsed()
        );
        assert!(dns_answer.is_some(), "DNS answered while the API was held");
        // Both silent ones were cut off: each reads end of file by now.
        for stream in &mut silent {
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            assert!(closed_by_the_peer(stream.read(&mut [0u8; 1])));
        }
    }

    #[tokio::test]
    async fn a_connection_is_closed_after_its_idle_time_and_its_life() {
        let limits = Limits {
            handshake: Duration::from_secs(2),
            idle: 300 * MS,
            life: Duration::from_secs(1),
            ..Limits::DEFAULT
        };
        let served = served(limits).await;
        let (addr, client) = (served.addr, pinned_client(&served.cert));

        // One request, then nothing: closed after the idle time.
        let idle = {
            let client = client.clone();
            tokio::task::spawn_blocking(move || {
                let mut connection = Connection::open(addr, client).unwrap();
                connection.send("GET /api/auth").unwrap();
                let answer = connection.receive().unwrap();
                assert!(!answer.close, "the first request is no reason to close");
                connection.closed_within(Duration::from_secs(2))
            })
            .await
            .unwrap()
        };
        let idle = idle.expect("an idle connection is closed");
        assert!(
            (250 * MS..550 * MS).contains(&idle),
            "closed after {idle:?} of 300 ms"
        );

        // A request every 200 ms: never idle, but at the end of its life the reply says close.
        let (replies, took) = tokio::task::spawn_blocking(move || {
            let began = Instant::now();
            let mut connection = Connection::open(addr, client).unwrap();
            let mut replies = 0;
            loop {
                connection.send("GET /api/auth").unwrap();
                let answer = connection.receive().unwrap();
                replies += 1;
                if answer.close {
                    assert!(connection.closed_within(Duration::from_secs(1)).is_some());
                    return (replies, began.elapsed());
                }
                assert!(replies < 10, "a connection that never ends its life");
                std::thread::sleep(200 * MS);
            }
        })
        .await
        .unwrap();
        // It lived a while, and said close in time: before its life of one second was out.
        assert!(replies >= 2, "{replies} replies");
        assert!(took < Duration::from_millis(1300), "{took:?}");
    }

    #[tokio::test]
    async fn a_connection_serves_at_most_a_hundred_requests() {
        let served = served(Limits::DEFAULT).await;
        let (addr, client) = (served.addr, pinned_client(&served.cert));
        let (closes, closed) = tokio::task::spawn_blocking(move || {
            let mut connection = Connection::open(addr, client).unwrap();
            let mut closes = Vec::new();
            for _ in 0..MAX_REQUESTS {
                connection.send("GET /api/auth").unwrap();
                closes.push(connection.receive().unwrap().close);
            }
            (closes, connection.closed_within(Duration::from_secs(2)))
        })
        .await
        .unwrap();
        assert_eq!(closes.len(), 100);
        assert!(closes[..99].iter().all(|close| !close));
        assert!(closes[99], "the hundredth reply says close");
        assert!(closed.is_some());
    }

    #[tokio::test]
    async fn every_request_that_cannot_be_read_closes_the_connection() {
        let served = served(small()).await;
        let (addr, client) = (served.addr, pinned_client(&served.cert));
        let long_head = format!("GET /api/auth HTTP/1.1\r\nX-Long: {}", "a".repeat(9000));
        for (what, bytes, status) in [
            ("a head over 8 KiB", long_head, Some(413)),
            (
                "a body over 4 KiB",
                "POST /api/auth HTTP/1.1\r\nContent-Length: 5000\r\n\r\n".to_owned(),
                Some(413),
            ),
            ("no HTTP at all", "BAD\r\n\r\n".to_owned(), Some(400)),
            (
                "chunked bodies",
                "POST /api/auth HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".to_owned(),
                Some(400),
            ),
            // A body that stops short: the idle time runs out, and the close says nothing.
            (
                "a body cut short",
                "POST /api/auth HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc".to_owned(),
                None,
            ),
        ] {
            let client = client.clone();
            let (answer, closed) = tokio::task::spawn_blocking(move || {
                let mut connection = Connection::open(addr, client).unwrap();
                connection.send_raw(bytes.as_bytes()).unwrap();
                let answer = connection.receive().ok();
                (answer, connection.closed_within(Duration::from_secs(2)))
            })
            .await
            .unwrap();
            assert_eq!(answer.as_ref().map(|a| a.status), status, "{what}");
            if let Some(answer) = answer {
                assert!(answer.close, "{what}: the refusal says close");
                assert!(answer.json["error"]["key"].is_string(), "{what}");
            }
            assert!(closed.is_some(), "{what}: the connection is closed");
        }
    }

    #[tokio::test]
    async fn a_handshake_that_drips_is_cut_off_at_the_handshake_time_not_the_idle_time_of_each_byte()
     {
        // Each byte comes inside the 300 ms that a read may wait, so only a deadline over the whole
        // handshake can end it.
        let served = served(small()).await;
        let addr = served.addr;
        let cut_at = tokio::task::spawn_blocking(move || {
            let mut socket = TcpStream::connect(addr).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_millis(1)))
                .unwrap();
            // The start of a handshake record that claims 240 bytes, and then a byte at a time.
            let mut stream = vec![0x16, 0x03, 0x01, 0x00, 0xf0];
            stream.extend([0u8; 40]);
            let began = Instant::now();
            for byte in stream {
                if socket.write_all(&[byte]).is_err() {
                    return began.elapsed();
                }
                let mut seen = [0u8; 1];
                match socket.read(&mut seen) {
                    Ok(0) => return began.elapsed(),
                    Err(error)
                        if !matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        return began.elapsed();
                    }
                    _ => {}
                }
                std::thread::sleep(100 * MS);
            }
            Duration::MAX
        })
        .await
        .unwrap();
        assert!(
            (250 * MS..800 * MS).contains(&cut_at),
            "cut off after {cut_at:?} of 300 ms"
        );
    }

    #[tokio::test]
    async fn a_handshake_does_not_hold_the_runtime_thread() {
        let served = served(Limits::DEFAULT).await;
        let (addr, client) = (served.addr, pinned_client(&served.cert));
        let (gap, login) = longest_gap(https(
            addr,
            client,
            &[r#"POST /api/auth|{"password":"right"}"#],
        ))
        .await;
        assert_eq!(login[0].0, 200);
        assert!(gap < 100 * MS, "{gap:?}");
    }

    #[test]
    fn no_more_than_two_pool_threads_are_ever_the_apis() {
        // The runtime of the board: one thread and a pool of five.
        let rt = services::runtime(None).unwrap();
        rt.block_on(async {
            let served = served(Limits::DEFAULT).await;
            // Four clients that say nothing: two are taken, and hold a thread each for the 5 s of the
            // handshake; the other two wait for a place and hold nothing.
            let silent: Vec<TcpStream> = (0..4)
                .map(|_| TcpStream::connect(served.addr).unwrap())
                .collect();
            tokio::time::sleep(200 * MS).await;

            // The pool's other three threads are free: three jobs that can end only by all
            // being there at once.
            let here = Arc::new(AtomicUsize::new(0));
            let job = || {
                let here = here.clone();
                blocking("test", move || {
                    here.fetch_add(1, Ordering::SeqCst);
                    let began = Instant::now();
                    while here.load(Ordering::SeqCst) < 3
                        && began.elapsed() < Duration::from_secs(2)
                    {
                        std::thread::sleep(MS);
                    }
                    here.load(Ordering::SeqCst) == 3
                })
            };
            let (a, b, c) = tokio::join!(job(), job(), job());
            assert!(a.unwrap() && b.unwrap() && c.unwrap());
            // The clients go, so that the runtime's end does not wait out their handshakes.
            drop(silent);
            tokio::time::sleep(100 * MS).await;
        });
    }

    #[tokio::test]
    async fn a_peer_that_is_not_ipv4_is_closed_at_once() {
        let Ok(listener) = TcpListener::bind("[::1]:0").await else {
            // No IPv6 loopback on this machine: there is no such peer to test with.
            return;
        };
        let addr = listener.local_addr().unwrap();
        let (dns, ..) = one(Reply::Answer("192.0.2.1".parse().unwrap())).await;
        let pem = pem();
        let api = Arc::new(Api::new(
            PasswordHash::new(b"right", [0; 16]),
            Arc::new(LiveFacts {
                dns,
                extras: Arc::new(Extras::default),
            }),
            Arc::new(|| 0),
            Arc::new(|| None),
        ));
        tokio::spawn(serve(
            listener,
            server_config(pem.as_bytes()).unwrap(),
            api,
            Limits::DEFAULT,
            places(),
        ));

        let closed = tokio::task::spawn_blocking(move || {
            let mut socket = TcpStream::connect(addr).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            closed_by_the_peer(socket.read(&mut [0u8; 1]))
        })
        .await
        .unwrap();
        assert!(closed);
    }

    /// What `accept` does for a test, in the order of its script: each accept takes the next entry,
    /// which fails with that OS error number or, for `None`, is the listener's own accept. Once the
    /// script is spent every accept is the listener's own.
    struct Script {
        listener: TcpListener,
        steps: std::sync::Mutex<std::collections::VecDeque<Option<i32>>>,
        /// How many times `accept` was called.
        calls: Arc<AtomicUsize>,
    }

    impl Script {
        async fn accept(&self) -> io::Result<(tokio::net::TcpStream, SocketAddr)> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let step = self.steps.lock().unwrap().pop_front().flatten();
            match step {
                Some(errno) => Err(io::Error::from_raw_os_error(errno)),
                None => self.listener.accept().await,
            }
        }
    }

    /// [`served`] with default limits and places, whose accepts go by `steps` ([`Script`]); the
    /// second of what comes back counts the calls of `accept`.
    async fn served_scripted(steps: Vec<Option<i32>>) -> (Served, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let served = served_by({
            let calls = calls.clone();
            move |listener, tls, api| {
                let script = Arc::new(Script {
                    listener,
                    steps: std::sync::Mutex::new(steps.into()),
                    calls,
                });
                let accept = move || {
                    let script = script.clone();
                    async move { script.accept().await }
                };
                serve_accepting(accept, tls, api, Limits::DEFAULT, places())
            }
        })
        .await;
        (served, calls)
    }

    /// `steps` that fail `errno` `times` times.
    fn failing(errno: i32, times: usize) -> Vec<Option<i32>> {
        vec![Some(errno); times]
    }

    /// The status of the API's answer to a request, from a client that runs on a thread of its
    /// own and not on the blocking pool: a pool job in flight keeps a paused clock from advancing,
    /// and the pause that the server is in could not end while this client waits for it.
    async fn answered(served: &Served) -> u16 {
        let (addr, client) = (served.addr, pinned_client(&served.cert));
        let (sender, answer) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            let mut connection = Connection::open(addr, client).unwrap();
            connection.send("GET /api/auth").unwrap();
            let _ = sender.send(connection.receive().unwrap().status);
        });
        answer.await.unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn an_accept_that_fails_once_is_retried_after_a_pause_and_the_next_connection_is_served()
    {
        let (served, calls) = served_scripted(failing(libc::ECONNABORTED, 1)).await;
        let began = tokio::time::Instant::now();

        // The first accept failed: a lost connection, as the kernel reports one.
        assert_eq!(answered(&served).await, 401);

        assert!(!served.ended.is_finished(), "serve ended");
        // The pause was the runtime's timer: the paused clock moved by it.
        assert!(began.elapsed() >= ACCEPT_PAUSE, "{:?}", began.elapsed());
        assert!(calls.load(Ordering::SeqCst) >= 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_run_of_failures_one_short_of_the_bound_does_not_end_serve_and_a_connection_resets_it()
     {
        // Nine shortages, a connection, nine lost connections, a connection.
        let mut steps = failing(libc::EMFILE, ACCEPT_FAILURES - 1);
        steps.push(None);
        steps.extend(failing(libc::ECONNABORTED, ACCEPT_FAILURES - 1));
        steps.push(None);
        let (served, _) = served_scripted(steps).await;
        let began = tokio::time::Instant::now();

        assert_eq!(answered(&served).await, 401);
        assert_eq!(answered(&served).await, 401);

        assert!(!served.ended.is_finished(), "serve ended");
        // A shortage waits longer than a lost connection.
        let waited = ACCEPT_SHORTAGE_PAUSE * 9 + ACCEPT_PAUSE * 9;
        assert!(began.elapsed() >= waited, "{:?}", began.elapsed());
    }

    #[tokio::test(start_paused = true)]
    async fn accepts_that_fail_the_bound_in_a_row_end_serve_with_the_error() {
        for errno in [libc::ECONNABORTED, libc::EMFILE] {
            // More failures than the bound, so that a bound that is not kept shows as calls.
            let (served, calls) = served_scripted(failing(errno, ACCEPT_FAILURES + 5)).await;
            let began = tokio::time::Instant::now();

            let ended = tokio::time::timeout(Duration::from_secs(1000), served.ended)
                .await
                .expect("serve went on past the bound")
                .unwrap();

            let error = ended.unwrap_err();
            assert_eq!(error.raw_os_error(), Some(errno));
            assert_eq!(calls.load(Ordering::SeqCst), ACCEPT_FAILURES);
            // Nine pauses: the tenth failure ends it at once.
            let pause = if errno == libc::EMFILE {
                ACCEPT_SHORTAGE_PAUSE
            } else {
                ACCEPT_PAUSE
            };
            assert!(
                began.elapsed() >= pause * (ACCEPT_FAILURES as u32 - 1),
                "{:?}",
                began.elapsed()
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_accept_error_that_a_retry_does_not_cure_ends_serve_at_once() {
        let (served, calls) = served_scripted(failing(libc::EBADF, 3)).await;
        let began = tokio::time::Instant::now();

        let ended = served.ended.await.unwrap();

        assert_eq!(ended.unwrap_err().raw_os_error(), Some(libc::EBADF));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(began.elapsed() < ACCEPT_PAUSE, "{:?}", began.elapsed());
    }

    #[test]
    fn accept_errors_are_sorted_by_what_accept_man_page_says_of_them() {
        let of = |errno| Failure::of(&io::Error::from_raw_os_error(errno));
        for errno in [
            libc::ECONNABORTED,
            libc::EPROTO,
            libc::EPERM,
            libc::ETIMEDOUT,
            libc::EINTR,
            libc::ENETDOWN,
            libc::ENOPROTOOPT,
            libc::EHOSTDOWN,
            libc::ENONET,
            libc::EHOSTUNREACH,
            libc::EOPNOTSUPP,
            libc::ENETUNREACH,
        ] {
            assert_eq!(of(errno), Failure::Passing, "errno {errno}");
        }
        for errno in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
            assert_eq!(of(errno), Failure::Shortage, "errno {errno}");
        }
        for errno in [
            libc::EBADF,
            libc::EINVAL,
            libc::ENOTSOCK,
            libc::EFAULT,
            libc::ENOENT,
        ] {
            assert_eq!(of(errno), Failure::Lasting, "errno {errno}");
        }
        // No number of the kernel's: nothing says a retry would help.
        assert_eq!(
            Failure::of(&io::Error::other("a made-up failure")),
            Failure::Lasting
        );
    }

    #[test]
    fn a_run_of_failures_is_logged_at_its_start_and_its_end_and_no_oftener_than_the_gap() {
        let lost = io::Error::from_raw_os_error(libc::ECONNABORTED);
        let full = io::Error::from_raw_os_error(libc::EMFILE);
        let mut run = AcceptRun::default();
        let t0 = Instant::now();

        // The first failure of the run is logged, the others are not, and the tenth ends it.
        assert_eq!(
            run.failed(&lost, t0),
            Next::Retry {
                pause: ACCEPT_PAUSE,
                say: true
            }
        );
        for _ in 2..ACCEPT_FAILURES {
            assert_eq!(
                run.failed(&full, t0),
                Next::Retry {
                    pause: ACCEPT_SHORTAGE_PAUSE,
                    say: false
                }
            );
        }
        assert_eq!(run.failed(&lost, t0), Next::End);
        // A connection ends the run, and says how many failures it had; with no run, nothing.
        assert_eq!(run.worked(), Some(ACCEPT_FAILURES));
        assert_eq!(run.worked(), None);

        // The next run, too soon after the logged one, is not logged, and neither is its end.
        let soon = t0 + ACCEPT_LOG_GAP - Duration::from_secs(1);
        assert_eq!(
            run.failed(&lost, soon),
            Next::Retry {
                pause: ACCEPT_PAUSE,
                say: false
            }
        );
        assert_eq!(run.worked(), None);
        // After the gap it is, and the count starts again.
        assert_eq!(
            run.failed(&lost, t0 + ACCEPT_LOG_GAP),
            Next::Retry {
                pause: ACCEPT_PAUSE,
                say: true
            }
        );
        assert_eq!(run.worked(), Some(1));

        // An error that no retry cures ends it, and does not count.
        let bad = io::Error::from_raw_os_error(libc::EBADF);
        assert_eq!(run.failed(&bad, t0), Next::End);
    }

    #[tokio::test]
    async fn the_places_outlive_a_serve_so_a_listener_started_again_never_adds_threads() {
        let places = places();
        let limits = Limits {
            handshake: 800 * MS,
            ..Limits::DEFAULT
        };
        let first = served_by({
            let places = places.clone();
            move |listener, tls, api| serve(listener, tls, api, limits, places)
        })
        .await;
        // Two clients that say nothing hold both places, a thread of the pool each, for the
        // handshake's 800 ms.
        let silent: Vec<TcpStream> = (0..2)
            .map(|_| TcpStream::connect(first.addr).unwrap())
            .collect();
        tokio::time::sleep(100 * MS).await;
        // The listener ends, as it does when `accept` fails; the connections go on.
        first.ended.abort();
        let _ = first.ended.await;
        assert_eq!(
            places.available_permits(),
            0,
            "the connections hold the places"
        );

        // A listener that starts again, on the same places, is served after theirs go back.
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(
            listener,
            first.tls.clone(),
            first.api.clone(),
            limits,
            places.clone(),
        ));
        let began = Instant::now();
        let third = https(addr, pinned_client(&first.cert), &["GET /api/auth"]).await;

        assert_eq!(third[0].0, 401);
        // The silent ones were cut off at 800 ms, 100 ms before this began; with places of its
        // own, the new listener would have served the third at once.
        assert!(
            began.elapsed() >= 300 * MS,
            "served after {:?}, with both places taken",
            began.elapsed()
        );
        drop(silent);
    }

    /// Whether a read found the peer gone: end of file or a reset, and not the read's own timeout.
    fn closed_by_the_peer(read: std::io::Result<usize>) -> bool {
        match read {
            Ok(got) => got == 0,
            Err(error) => !matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
        }
    }

    /// The two ends of a connection on `127.0.0.1`.
    fn socket_pair() -> (TcpStream, TcpStream) {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        (client, listener.accept().unwrap().0)
    }

    #[test]
    fn a_read_waits_for_the_shorter_of_the_idle_wait_and_the_life_that_is_left() {
        let (_client, server) = socket_pair();
        let secs = Duration::from_secs;
        let mut socket = Deadlined {
            stream: server,
            deadline: Instant::now() + secs(10),
            read_wait: 100 * MS,
            write_wait: secs(5),
        };
        let timed = |socket: &mut Deadlined| {
            let began = Instant::now();
            let error = socket.read(&mut [0u8; 1]).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            began.elapsed()
        };

        // The idle wait is the shorter, with 10 s of life left.
        let waited = timed(&mut socket);
        assert!(
            (90 * MS..400 * MS).contains(&waited),
            "{waited:?} of 100 ms"
        );
        // The life is the shorter, with 10 s of idle wait.
        socket.bound(Instant::now() + 100 * MS, secs(10), secs(5));
        let waited = timed(&mut socket);
        assert!(
            (90 * MS..400 * MS).contains(&waited),
            "{waited:?} of 100 ms"
        );
        // The life is over: no wait at all, and the socket is not asked.
        let waited = timed(&mut socket);
        assert!(waited < 50 * MS, "{waited:?}");
        assert_eq!(
            socket.write(&[0u8]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn a_write_to_a_client_that_does_not_read_is_cut_at_the_write_wait_or_the_life_left() {
        let (_client, server) = socket_pair();
        let secs = Duration::from_secs;
        let mut socket = Deadlined {
            stream: server,
            deadline: Instant::now() + secs(30),
            read_wait: secs(5),
            write_wait: 200 * MS,
        };
        // Whatever the buffers take, a client that never reads fills them.
        let fill = |socket: &mut Deadlined| {
            let began = Instant::now();
            let chunk = [0u8; 64 * 1024];
            for _ in 0..4096 {
                if let Err(error) = socket.write(&chunk) {
                    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                    return began.elapsed();
                }
            }
            panic!("the write never blocked");
        };

        // The write wait is the shorter: the last, blocked write took 200 ms.
        let waited = fill(&mut socket);
        assert!(waited >= 190 * MS && waited < secs(5), "{waited:?}");
        // The life is the shorter: the buffers are already full, so the write waits the life out.
        socket.bound(Instant::now() + 100 * MS, secs(5), secs(10));
        let began = Instant::now();
        assert_eq!(
            socket.write(&[0u8; 64 * 1024]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        let waited = began.elapsed();
        assert!(
            (90 * MS..400 * MS).contains(&waited),
            "{waited:?} of 100 ms"
        );
    }

    #[tokio::test]
    async fn a_request_body_is_wiped_once_it_has_been_answered() {
        let (dns, ..) = one(Reply::Answer("192.0.2.1".parse().unwrap())).await;
        let api = Api::new(
            PasswordHash::new(b"right", [0; 16]),
            Arc::new(LiveFacts {
                dns,
                extras: Arc::new(Extras::default),
            }),
            Arc::new(|| 0),
            Arc::new(|| Some([1; 16])),
        );
        let mut request = Request {
            method: "POST".into(),
            target: "/api/auth".into(),
            sid: None,
            body: br#"{"password":"right"}"#.to_vec(),
            close: false,
        };

        let reply = answer(&api, &mut request, std::net::Ipv4Addr::new(192, 0, 2, 7));

        // The login was served from the body, and the body is gone.
        assert_eq!(reply.status, 200);
        assert!(request.body.is_empty());
    }
}
