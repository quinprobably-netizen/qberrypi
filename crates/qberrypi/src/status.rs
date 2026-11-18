//! The status server: read-only HTTP on port 80, for the status page and for whoever wants the
//! numbers or the log.
//!
//! Three paths answer, `/api/v1/stats`, `/api/v1/me` and `/log`; `/api/v1/queries` is a 403, as
//! the list of what was asked is behind the API's login; every other is a 404. Only the first line
//! of a request is read. The statistics hold counts, the state of the block lists, the Wi-Fi
//! link, the board's temperature, the busy share of its cores and the memory held
//! ([`crate::usage`]), the slot that runs and how an update stands, never a name that was asked
//! for or the address of a device that asked. `/api/v1/me` is the one answer that holds names,
//! and only those that the device which asks has asked itself, its reverse lookups (names under
//! `in-addr.arpa` and `ip6.arpa`, which are addresses) left out: it needs no login, because the
//! peer's address is the device, and a device that never calls it is never watched (see
//! [`crate::dns::watched`]). No address of a device is in any answer, and the one line logged here
//! says where the server listens.
//!
//! Nothing here holds a lock across an `.await`: the answer is made first, and then written. A
//! connection that has been answered is closed as [`crate::linger`] says, so that a client that
//! still has request bytes unread by the server, or a long `/log` to read, is not sent a reset
//! that costs it the end of the answer. That happens inside [`CLIENT_TIMEOUT`], which counts the
//! whole connection, and never beyond it.

use std::io::{self, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};

use crate::dns::upstream::TlsState;
use crate::dns::{Dns, clients};
use crate::linger;
use crate::lists::Lists;
use crate::live;
use crate::logbuf::LogBuf;
use crate::update::{self, UpdateCtl};

/// The port that the status is served on.
pub const PORT: u16 = 80;
/// The most connections that are served at once. A further one waits in the queue of the listener
/// until a place is free.
pub const MAX_CLIENTS: usize = 8;
/// How long a connection has, from the moment it is taken to the end of its close: the answer and
/// the lingering close ([`crate::linger`]) are both inside it.
pub const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);
/// The most bytes that are read from a client: a request line that is longer is answered with 400.
pub const MAX_REQUEST_LINE: usize = 1024;

/// The path of the statistics.
const STATS_PATH: &str = "/api/v1/stats";
/// The path of the log.
const LOG_PATH: &str = "/log";
/// The path of the list of queries, which is served on the API's port only.
const QUERIES_PATH: &str = "/api/v1/queries";
/// The path where a device asks about itself.
const ME_PATH: &str = "/api/v1/me";
/// The seconds in an hour and in a day: the windows that the devices that asked are counted in.
const HOUR_SECS: u64 = 3_600;
const DAY_SECS: u64 = 86_400;
/// The kinds of text that are answered with.
const JSON: &str = "application/json";
const PLAIN: &str = "text/plain; charset=utf-8";

/// What is sent back: a status code, the kind of its body, and the body.
#[derive(Debug, PartialEq)]
pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl Response {
    /// An answer that is one line of plain text.
    fn line(status: u16, text: &str) -> Self {
        Self {
            status,
            content_type: PLAIN,
            body: format!("{text}\n").into_bytes(),
        }
    }

    /// The reason phrase of the status.
    fn reason(&self) -> &'static str {
        match self.status {
            200 => "OK",
            400 => "Bad Request",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            _ => "Error",
        }
    }

    /// The bytes to send: the status line, the headers, a blank line and the body, in one piece
    /// so that they leave in one packet if they fit.
    fn to_bytes(&self) -> Vec<u8> {
        let head = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
            self.status,
            self.reason(),
            self.content_type,
            self.body.len()
        );
        [head.as_bytes(), &self.body].concat()
    }
}

/// What the server tells about the system.
#[derive(Clone)]
pub struct Status {
    pub dns: Arc<Dns>,
    /// Where the block set in force came from, and how the last refresh went.
    pub lists: Arc<Lists>,
    pub log: &'static Mutex<LogBuf>,
    /// Whether the clock has been set, which SNTP says.
    pub synced: watch::Receiver<bool>,
    /// When the system came up.
    pub started: Instant,
    /// The state of the Wi-Fi link, read for each request of the statistics.
    pub link: Arc<dyn Fn() -> live::WifiStatus + Send + Sync>,
    /// The board's temperature in whole degrees, read for each request of the statistics;
    /// `None` if it cannot be read.
    pub board_c: Arc<dyn Fn() -> Option<i8> + Send + Sync>,
    /// How many devices on the network are not on the known list, read for each request of
    /// `/api/v1/me`: a count, never a device. While no known list has come it is 0.
    pub unknown_devices: Arc<dyn Fn() -> usize + Send + Sync>,
    /// The slot this boot runs and how an update stands, copied out for each request of the
    /// statistics under the short lock of [`UpdateCtl`] and no longer than that takes.
    pub update: Arc<UpdateCtl>,
}

impl Status {
    /// The numbers of `/api/v1/stats`. A key whose value is not known yet has `null` for it.
    pub fn stats(&self) -> Value {
        let now = self.dns.now();
        // The resolver is locked only to copy a few numbers out.
        let (today, total, cache_entries, paused_until, block_set_bytes, cache_bytes) = {
            let resolver = self.dns.resolver();
            (
                resolver.stats().today(now),
                resolver.stats().total(),
                resolver.cache_len(),
                resolver.paused_until(now),
                resolver.block_set_bytes(),
                resolver.cache_bytes(),
            )
        };
        // What the supervisor's tick last read of the cores and the process.
        let (cpu, memory) = crate::usage::json(block_set_bytes, cache_bytes);
        // The table of clients is locked to count it: no address is copied out.
        let (clients_hour, clients_24h) = {
            let clients = self.dns.clients();
            (
                clients.seen_within(now.mono_secs, HOUR_SECS),
                clients.seen_within(now.mono_secs, DAY_SECS),
            )
        };
        let upstreams = self.dns.upstreams();
        let clock_set = *self.synced.borrow();
        let lists = self.lists.get();
        // Until the clock is set, the time it shows is no time to measure an age against; and a
        // fetch dated after now, because the clock stepped back, is of age 0.
        let list_age_secs = lists
            .fetched_unix_secs
            .filter(|_| clock_set)
            .map(|fetched| now.unix_secs.saturating_sub(fetched));
        // The signal is the one the `signal` component last stored, so there is no round trip to
        // the Wi-Fi firmware here, which would hold the runtime thread. The board's temperature,
        // below, is one read of the SoC's own sensor: microseconds.
        let link = (self.link)();
        let update = self.update.view();
        // The admission of forwards (`dns::admit`): those shed, those paced, and the most
        // questions out on one upstream session now (`null` before TLS). Set apart: the macro
        // takes no more keys.
        let admission = [
            ("forwards_shed", json!(self.dns.forwards_shed())),
            ("forwards_paced", json!(self.dns.forwards_paced())),
            ("upstream_cap", json!(upstreams.session_cap())),
        ];
        let mut stats = json!({
            "version": crate::VERSION,
            "build": crate::BUILD_EPOCH,
            "uptime_secs": self.started.elapsed().as_secs(),
            "clock_set": clock_set,
            "unix_secs": now.unix_secs,
            "utc_offset_secs": self.dns.utc_offset(),
            "queries_today": today.queries,
            "blocked_today": today.blocked,
            "blocked_threat_today": today.blocked_threat,
            "blocked_share": share(today.blocked, today.queries),
            "cache_hit_rate": share(today.cache_hits, today.queries),
            "queries_total": total.queries,
            "blocked_total": total.blocked,
            "blocked_threat_total": total.blocked_threat,
            "cache_hits_total": total.cache_hits,
            "forwarded_total": total.forwarded,
            "prefetched_total": self.dns.prefetched(),
            "cache_entries": cache_entries,
            "clients_hour": clients_hour,
            "clients_24h": clients_24h,
            "upstream_ms": upstreams.latency_ms(),
            "upstream_failures": upstreams.failures(),
            "upstream_queries": upstreams.queries(),
            "upstream_tls": tls_state(upstreams.tls()),
            "watch_events_dropped": self.dns.watch_events_dropped(),
            "exempt_default": self.dns.exempt().by_default(),
            "exempt_clients": self.dns.exempt().exempt_clients(),
            "blocking": blocking_word(paused_until),
            "pause_left_secs": paused_until.map(|until| until.saturating_sub(now.mono_secs)),
            "list_source": lists.source.as_str(),
            "list_names": lists.names,
            "list_age_secs": list_age_secs,
            "list_error": lists.last_error,
            "wifi": {
                "associated": link.associated,
                "signal_dbm": link.signal_dbm,
                "ap": link.ap,
                "freq_mhz": link.freq_mhz,
            },
            "board_c": (self.board_c)(),
            "stalls": crate::stall::json(),
            "cpu": cpu,
            "memory": memory,
            "slot": update.slot.map(|slot| slot.letter()),
            "boot_files": update.boot_files.as_deref(),
            "update": update_json(&update),
        });
        for (key, value) in admission {
            stats[key] = value;
        }
        stats
    }

    /// The answer of `/api/v1/me` to the device at `peer`: what the watch table keeps of that
    /// device alone, with the state of blocking and the count of unknown devices. The route is
    /// the opt-in: the device is watched from its first call, and refreshed by every later one.
    /// Its reverse lookups are not in the answer, nor in its counts: they name addresses.
    ///
    /// A `peer` that the table of clients does not count (loopback, or not IPv4) is 404 and is not
    /// watched. No address is in the answer, and nothing about the request or the device is logged.
    fn me(&self, peer: IpAddr) -> Response {
        let Some(device) = clients::counted(peer) else {
            return Response::line(404, "not found");
        };
        let now = self.dns.now();
        // Each lock is let go of at the end of its statement: the table of watched devices is never
        // held with the resolver, and no address is copied out of either.
        let mine = self
            .dns
            .watched()
            .touch(device, now.mono_secs, now.unix_secs);
        let paused_until = self.dns.resolver().paused_until(now);
        let recent: Vec<Value> = mine
            .recent
            .iter()
            .map(|seen| {
                json!({
                    "unix_secs": seen.unix_secs,
                    "name": &*seen.name,
                    "refused": seen.refused,
                    "threat": seen.threat,
                })
            })
            .collect();
        let body = json!({
            "unix_secs": now.unix_secs,
            "watching_since_unix": mine.watching_since_unix,
            "blocking": blocking_word(paused_until),
            "exempt": self.dns.exempt().is_exempt(peer),
            "asked_24h": mine.asked_24h,
            "refused_24h": mine.refused_24h,
            "threats_24h": mine.threats_24h,
            "unknown_devices": (self.unknown_devices)(),
            "recent": recent,
        });
        Response {
            status: 200,
            content_type: JSON,
            body: body.to_string().into_bytes(),
        }
    }

    /// The answer to a request whose first line, without its line end, is `request_line`, from the
    /// device at `peer`.
    ///
    /// `GET /api/v1/stats`, `GET /api/v1/me` and `GET /log`, with HTTP/1.0 or HTTP/1.1, are
    /// answered; any other path is 404, and so is any of these with a query string. `/api/v1/me`
    /// is also 404 for a `peer` that is no device, and is the one path that uses `peer`.
    /// `GET /api/v1/queries`, with a query string or without, is 403: the list is behind the
    /// API's login. Another method of the same shape is 405, and what is not of that shape is 400.
    pub fn respond(&self, request_line: &str, peer: IpAddr) -> Response {
        let mut parts = request_line.split(' ');
        let (Some(method), Some(path), Some(version), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Response::line(400, "bad request");
        };
        let is_method = !method.is_empty() && method.bytes().all(|byte| byte.is_ascii_uppercase());
        if !is_method || path.is_empty() || !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
            return Response::line(400, "bad request");
        }
        if method != "GET" {
            return Response::line(405, "method not allowed");
        }
        match path {
            ME_PATH => self.me(peer),
            STATS_PATH => Response {
                status: 200,
                content_type: JSON,
                body: self.stats().to_string().into_bytes(),
            },
            LOG_PATH => Response {
                status: 200,
                content_type: PLAIN,
                // The lock is let go of at the end of this statement.
                body: self
                    .log
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .text()
                    .into_bytes(),
            },
            _ if is_queries_path(path) => Response::line(403, "this needs the API login"),
            _ => Response::line(404, "not found"),
        }
    }

    /// The status component: binds `addr`, logs where it listens, and serves. It ends only with
    /// an error, which includes a port that cannot be bound.
    pub async fn run(self, addr: SocketAddr) -> io::Result<()> {
        // Nothing here opens an IPv6 socket.
        debug_assert!(addr.is_ipv4());
        let listener = TcpListener::bind(addr).await?;
        log::info!("status: listening on {}", listener.local_addr()?);
        self.serve(listener).await
    }

    /// Answers every client of `listener`, with [`MAX_CLIENTS`] connections at a time that may
    /// take [`CLIENT_TIMEOUT`]. Ends only with an error of `accept`.
    pub async fn serve(self, listener: TcpListener) -> io::Result<()> {
        self.serve_with(listener, MAX_CLIENTS, CLIENT_TIMEOUT).await
    }

    /// [`Status::serve`] with `clients` connections at a time that may take `timeout`.
    ///
    /// A place is taken before the next connection is accepted, so that when all are taken the
    /// further clients wait in the queue of the listener and no memory is spent on them.
    pub(crate) async fn serve_with(
        self,
        listener: TcpListener,
        clients: usize,
        timeout: Duration,
    ) -> io::Result<()> {
        let places = Arc::new(Semaphore::new(clients));
        loop {
            let place = places
                .clone()
                .acquire_owned()
                .await
                .map_err(io::Error::other)?;
            let (stream, peer) = match listener.accept().await {
                Ok((stream, peer)) => (stream, peer.ip()),
                // The client that was to be taken has gone: that ends its connection and no more.
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset
                    ) =>
                {
                    continue;
                }
                Err(err) => return Err(err),
            };
            let status = self.clone();
            tokio::spawn(async move {
                let _place = place;
                // However it ended, the connection is closed with it, and an error or a time out
                // is its own: there is no one to tell, and no other connection to harm.
                let _ = tokio::time::timeout(timeout, status.talk(stream, peer)).await;
            });
        }
    }

    /// One client's connection, from `peer`: its request line, the answer, and the end, which
    /// lingers ([`linger::close`]). A client that has gone before its request line was read is
    /// owed no answer and none is written.
    async fn talk(&self, mut stream: TcpStream, peer: IpAddr) -> io::Result<()> {
        let response = match read_request_line(&mut stream).await? {
            Some(line) => self.respond(&String::from_utf8_lossy(&line), peer),
            None => Response::line(400, "bad request"),
        };
        stream.write_all(&response.to_bytes()).await?;
        linger::close(stream).await;
        Ok(())
    }
}

/// The first line of a request, without its line end; `None` if [`MAX_REQUEST_LINE`] bytes came
/// and the line did not end. No more than those bytes are read, so the rest of the request, which
/// is of no interest, is left where it is.
async fn read_request_line(stream: &mut TcpStream) -> io::Result<Option<Vec<u8>>> {
    let mut buf = [0u8; MAX_REQUEST_LINE];
    let mut filled = 0;
    loop {
        let read = stream.read(&mut buf[filled..]).await?;
        if read == 0 {
            // The client has gone before it was done: nothing is to be said to it.
            return Err(ErrorKind::UnexpectedEof.into());
        }
        let new = filled..filled + read;
        if let Some(offset) = buf[new.clone()].iter().position(|&byte| byte == b'\n') {
            let line = &buf[..filled + offset];
            return Ok(Some(line.strip_suffix(b"\r").unwrap_or(line).to_vec()));
        }
        filled = new.end;
        if filled == buf.len() {
            return Ok(None);
        }
    }
}

/// The `blocking` entry of the statistics and of `/api/v1/me`: `"paused"` while a pause is in
/// force, which `paused_until` says, and `"on"` otherwise.
fn blocking_word(paused_until: Option<u64>) -> &'static str {
    if paused_until.is_some() {
        "paused"
    } else {
        "on"
    }
}

/// The `update` entry of the statistics: `null` on the old layout, which has no slots to update;
/// else the state (`"idle"`, `"receiving"` or `"trial"`), the trial this boot is on with its
/// build, the slot a rollback boots, the seconds since init started and what it still waits for
/// (`null` if there is none), and how the last trial that this boot knows of ended (`null` if
/// none): `"confirmed"` or `"rolled_back"`, the build, and for a rollback which case it was.
///
/// Only numbers, slot letters and the fixed words of the design are in it, and the reason a
/// trial build gave up with, which the trial itself wrote.
fn update_json(update: &update::View) -> Value {
    if update.slot.is_none() {
        return Value::Null;
    }
    json!({
        "state": update.state,
        "trial": update.trial.as_ref().map(|trial| json!({
            "build": trial.build,
            "from": trial.from.letter(),
            "secs": trial.secs,
            "waiting_for": trial.waiting_for.iter().map(|w| w.word()).collect::<Vec<_>>(),
        })),
        "last": update.last.as_ref().map(|last| json!({
            "outcome": last.kind.word(),
            "build": last.build,
            "detail": last.detail,
        })),
    })
}

/// The `upstream_tls` entry of the statistics: the text `"off"` or `"waiting for the clock"`, or,
/// once the questions go over TLS, an object with the connections that have a session (`up`: an
/// idle one has none until the next question), the handshakes completed (`connects`) and resumed
/// (`resumed`) since the switch, the sessions closed here for being idle (`idle_closes`) and
/// those that the servers ended (`server_closes`), and the questions sent again on a new session
/// after the server ended theirs (`retried`).
fn tls_state(state: TlsState) -> Value {
    match state {
        TlsState::Off => json!("off"),
        TlsState::WaitingForClock => json!("waiting for the clock"),
        TlsState::On { up, counts } => json!({
            "up": up,
            "connects": counts.connects,
            "resumed": counts.resumed,
            "idle_closes": counts.idle_closes,
            "server_closes": counts.server_closes,
            "retried": counts.retried,
        }),
    }
}

/// Whether `path` is the list of queries, with a query string or without.
fn is_queries_path(path: &str) -> bool {
    path.strip_prefix(QUERIES_PATH)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('?'))
}

/// `part` of `whole`, to four decimal places; `None` when there is no whole to be part of.
pub(crate) fn share(part: u64, whole: u64) -> Option<f64> {
    if whole == 0 {
        return None;
    }
    Some((part as f64 / whole as f64 * 10_000.0).round() / 10_000.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::dot::ConnCounts;

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use qb_dns::ListClass;
    use tokio::time::{sleep, timeout};

    use qb_dns::BlockSetBuilder;

    use crate::dns::testutil::{
        FixedOffset, Reply, TlsFakeUpstream, aged, ask_udp, ip, ms, one, tls_for_fake,
    };
    use crate::dns::upstream::Upstreams;
    use crate::lists::{self, ListState, Source};
    use crate::logbuf::LogBuf;

    /// A `Status` over a `Dns` whose one upstream answers as `reply` says, lists that came from the
    /// configuration with 1 name, and a log that holds the lines `one` and `two`, with its server on
    /// a `127.0.0.1` port: room for two clients, which may take 200 ms. Returns it with the
    /// addresses of its server and of the DNS service.
    async fn served(reply: Reply) -> (Status, SocketAddr, SocketAddr) {
        served_with(reply, ms(200), 4096).await
    }

    /// [`served`] with connections that may take `timeout`, and a log that holds `log_cap` bytes.
    async fn served_with(
        reply: Reply,
        timeout: Duration,
        log_cap: usize,
    ) -> (Status, SocketAddr, SocketAddr) {
        let (dns, dns_addr, upstream) = one(reply).await;
        // The upstream stops answering when it is dropped.
        std::mem::forget(upstream);
        let mut buf = LogBuf::new(log_cap);
        buf.push("one");
        buf.push("two");
        let log: &'static Mutex<LogBuf> = Box::leak(Box::new(Mutex::new(buf)));
        let (clock_set, synced) = watch::channel(false);
        // A receiver whose sender is gone says the same, but the real one is never dropped.
        std::mem::forget(clock_set);
        let lists = Lists::new(ListState {
            source: Source::Config,
            names: 1,
            fetched_unix_secs: None,
            last_error: None,
        });
        let status = Status {
            dns,
            lists,
            log,
            synced,
            started: Instant::now(),
            link: Arc::new(live::WifiStatus::default),
            board_c: Arc::new(|| None),
            unknown_devices: Arc::new(|| 0),
            update: UpdateCtl::off(),
        };
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(status.clone().serve_with(listener, 2, timeout));
        (status, addr, dns_addr)
    }

    /// Sends `request` and reads the answer to the end of the connection: the head, with its
    /// last header's line end and not the blank line, and the body.
    async fn get(addr: SocketAddr, request: &str) -> (String, Vec<u8>) {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut reply = Vec::new();
        let read = timeout(ms(2000), stream.read_to_end(&mut reply)).await;
        read.expect("the connection is closed").unwrap();
        let blank = reply
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("a head");
        let head = String::from_utf8(reply[..blank + 2].to_vec()).unwrap();
        (head, reply[blank + 4..].to_vec())
    }

    /// The bytes that a stream gives within `wait`: `Ok(0)` is the end of the stream, and an
    /// error, for a stream that was reset, or `Err(TimedOut)` for none within the wait.
    async fn read_some(stream: &mut TcpStream, wait: Duration) -> io::Result<usize> {
        match timeout(wait, stream.read(&mut [0u8; 16])).await {
            Ok(read) => read,
            Err(_) => Err(io::ErrorKind::TimedOut.into()),
        }
    }

    #[tokio::test]
    async fn requests_are_answered_by_method_and_path() {
        let (status, _http, _dns) = served(Reply::Silent).await;
        let code = |line: &str| status.respond(line, peer(4)).status;
        assert_eq!(
            (
                code("GET /api/v1/stats HTTP/1.1"),
                code("GET /log HTTP/1.0")
            ),
            (200, 200)
        );
        assert_eq!(
            (
                code("GET / HTTP/1.1"),
                code("GET /api/v1/stats?x=1 HTTP/1.1"),
                code("GET /log?n=5 HTTP/1.1")
            ),
            (404, 404, 404)
        );
        // The list of queries is behind the API's login, on the other port: here it is refused.
        assert_eq!(
            (
                code("GET /api/v1/queries HTTP/1.1"),
                code("GET /api/v1/queries?n=5 HTTP/1.0")
            ),
            (403, 403)
        );
        assert_eq!(
            (
                code("POST /api/v1/stats HTTP/1.1"),
                code("DELETE /log HTTP/1.1")
            ),
            (405, 405)
        );
        assert_eq!(
            (
                code("nonsense"),
                code(""),
                code("GET /log"),
                code("GET /log HTTP/2")
            ),
            (400, 400, 400, 400)
        );
        assert_eq!(
            status.respond("GET /log HTTP/1.1", peer(4)),
            Response {
                status: 200,
                content_type: "text/plain; charset=utf-8",
                body: b"one\ntwo\n".to_vec()
            }
        );
    }

    #[tokio::test]
    async fn the_statistics_are_served_as_json() {
        let (_status, http, dns) = served(Reply::Answer(ip("192.0.2.10"))).await;
        for name in ["example.com", "example.com", "ads.example.com"] {
            ask_udp(dns, name).await.unwrap();
        }
        let (head, body) = get(http, "GET /api/v1/stats HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
        for line in [
            "Content-Type: application/json\r\n",
            "Connection: close\r\n",
            "Cache-Control: no-store\r\n",
            &format!("Content-Length: {}\r\n", body.len()),
        ] {
            assert!(head.contains(line), "{line}");
        }
        // The counts are all that it says: no name that was asked for is in it.
        assert!(!String::from_utf8_lossy(&body).contains("example"));
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            (v["version"].as_str(), v["build"].as_u64()),
            (Some(crate::VERSION), Some(crate::BUILD_EPOCH))
        );
        assert_eq!(
            (
                v["queries_today"].as_u64(),
                v["blocked_today"].as_u64(),
                v["blocked_share"].as_f64(),
                v["cache_hit_rate"].as_f64()
            ),
            (Some(3), Some(1), Some(0.3333), Some(0.3333))
        );
        assert_eq!(
            (
                v["queries_total"].as_u64(),
                v["blocked_total"].as_u64(),
                v["cache_hits_total"].as_u64(),
                v["forwarded_total"].as_u64()
            ),
            (Some(3), Some(1), Some(1), Some(1))
        );
        // Nothing here is a threat, and nothing was prefetched.
        assert_eq!(
            (
                v["blocked_threat_today"].as_u64(),
                v["blocked_threat_total"].as_u64(),
                v["prefetched_total"].as_u64()
            ),
            (Some(0), Some(0), Some(0))
        );
        assert_eq!(
            (
                v["clock_set"].as_bool(),
                v["utc_offset_secs"].as_i64(),
                v["cache_entries"].as_u64(),
                v["upstream_failures"].as_u64()
            ),
            (Some(false), Some(0), Some(1), Some(0))
        );
        assert!(
            v["unix_secs"].as_u64().unwrap() > 1_700_000_000
                && v["uptime_secs"].is_u64()
                && v["upstream_ms"].is_u64()
        );
        // The one question that was forwarded went out to the one upstream once.
        assert_eq!(v["upstream_queries"].as_u64(), Some(1));
        assert_eq!(
            (v["blocking"].as_str(), v["pause_left_secs"].is_null()),
            (Some("on"), true)
        );
        assert_eq!(
            (
                v["list_source"].as_str(),
                v["list_names"].as_u64(),
                v["list_age_secs"].is_null(),
                v["list_error"].is_null()
            ),
            (Some("config"), Some(1), true, true)
        );
        // No way over TLS is configured here.
        assert_eq!(v["upstream_tls"], "off");
        // No watch is set on this service: nothing was dropped, and no device is exempt.
        assert_eq!(v["watch_events_dropped"].as_u64(), Some(0));
        assert_eq!(
            (v["forwards_shed"].as_u64(), v["forwards_paced"].as_u64()),
            (Some(0), Some(0))
        );
        assert!(v["upstream_cap"].is_null());
        assert_eq!(v["exempt_clients"].as_u64(), Some(0));
        assert_eq!(v["exempt_default"], false);
        // The stall marks, as `stall` keeps them.
        assert!(v["stalls"]["runtime_gap_max_ms"].is_u64());
        assert!(v["stalls"]["resolver_lock_hold_max_us"].is_u64());
        // The old layout has no slot, no digest and no update to tell of.
        assert!(v["slot"].is_null() && v["boot_files"].is_null() && v["update"].is_null());
        // The cores and the process, as the tick last read them (perhaps not yet: `null`), and the
        // memory, the block set's and the cache's own.
        assert!(v["cpu"].get("cores").is_some() && v["cpu"].get("process").is_some());
        assert!(
            v["memory"]["block_set_kib"]
                .as_u64()
                .is_some_and(|kib| kib > 0)
        );
        assert!(v["memory"]["cache_kib"].as_u64().is_some_and(|kib| kib > 0));
        assert!(v["memory"].get("rss_kib").is_some());
        assert_eq!(v.as_object().unwrap().len(), 44);
    }

    /// A status on slot `slot` whose update state is `ctl`.
    async fn on_slot(ctl: Arc<UpdateCtl>) -> Status {
        let (status, _http, _dns) = served(Reply::Silent).await;
        Status {
            update: ctl,
            ..status
        }
    }

    fn marker(slot: crate::slots::Slot) -> crate::slots::Marker {
        crate::slots::Marker {
            slot,
            from: slot.other(),
            build: 1_794_470_000,
            mode: crate::slots::Mode::Tryboot,
            started: true,
            failed: None,
        }
    }

    #[tokio::test]
    async fn the_stats_name_the_slot_and_the_digest_and_an_idle_update() {
        use crate::slots::Slot;
        let ctl = UpdateCtl::new(
            Some(Slot::B),
            Some("0123456789abcdef".repeat(4)),
            Arc::new(crate::update::NoCard),
        );
        let v = on_slot(ctl).await.stats();
        assert_eq!(v["slot"], "b");
        assert_eq!(v["boot_files"], "0123456789abcdef".repeat(4));
        assert_eq!(
            v["update"],
            json!({"state": "idle", "trial": null, "last": null})
        );
        assert_eq!(v.as_object().unwrap().len(), 44);
    }

    #[tokio::test]
    async fn a_slot_with_no_digest_says_null_for_it() {
        use crate::slots::Slot;
        let ctl = UpdateCtl::new(Some(Slot::A), None, Arc::new(crate::update::NoCard));
        let v = on_slot(ctl).await.stats();
        assert_eq!(
            (v["slot"].as_str(), v["boot_files"].is_null()),
            (Some("a"), true)
        );
        assert_eq!(v["update"]["state"], "idle");
    }

    #[tokio::test]
    async fn a_trial_shows_its_build_its_origin_its_seconds_and_what_it_waits_for() {
        use crate::slots::Slot;
        use crate::update::Waiting;
        let ctl = UpdateCtl::new(Some(Slot::B), None, Arc::new(crate::update::NoCard));
        ctl.begin_trial(marker(Slot::B), tokio::time::Instant::now());
        let status = on_slot(ctl.clone()).await;
        let v = status.stats();
        assert_eq!(v["update"]["state"], "trial");
        assert_eq!(v["update"]["last"], Value::Null);
        let trial = &v["update"]["trial"];
        assert_eq!(
            (trial["build"].as_u64(), trial["from"].as_str()),
            (Some(1_794_470_000), Some("a"))
        );
        assert!(trial["secs"].as_u64().unwrap() < 5);
        assert_eq!(
            trial["waiting_for"],
            json!(["wifi", "clock", "upstream", "time"])
        );
        // What is still waited for follows the trial's own account of it.
        ctl.set_waiting(vec![Waiting::Time]);
        assert_eq!(
            status.stats()["update"]["trial"]["waiting_for"],
            json!(["time"])
        );
        ctl.set_waiting(Vec::new());
        assert_eq!(status.stats()["update"]["trial"]["waiting_for"], json!([]));
    }

    #[tokio::test]
    async fn a_receive_shows_as_receiving_with_no_trial() {
        use crate::slots::Slot;
        let ctl = UpdateCtl::new(Some(Slot::A), None, Arc::new(crate::update::NoCard));
        let receiving = ctl.begin_receive().unwrap();
        let v = on_slot(ctl).await.stats();
        assert_eq!(v["update"]["state"], "receiving");
        assert_eq!(v["update"]["trial"], Value::Null);
        drop(receiving);
    }

    #[tokio::test]
    async fn the_last_outcome_shows_which_way_it_ended_and_for_a_rollback_which_case() {
        use crate::slots::Slot;
        use crate::update::Outcome;
        let ctl = UpdateCtl::new(Some(Slot::A), None, Arc::new(crate::update::NoCard));
        let status = on_slot(ctl.clone()).await;
        ctl.finish(Outcome::rolled_back(
            1_794_470_000,
            "the trial build restarted before it confirmed",
        ));
        assert_eq!(
            status.stats()["update"]["last"],
            json!({
                "outcome": "rolled_back",
                "build": 1_794_470_000u64,
                "detail": "the trial build restarted before it confirmed",
            })
        );
        ctl.finish(Outcome::confirmed(1_794_480_000));
        assert_eq!(
            status.stats()["update"]["last"],
            json!({"outcome": "confirmed", "build": 1_794_480_000u64, "detail": ""})
        );
        assert_eq!(status.stats()["update"]["state"], "idle");
    }

    #[tokio::test]
    async fn the_tls_state_of_the_upstreams_is_told() {
        let (status, _http, _dns) = served(Reply::Silent).await;
        let fake = TlsFakeUpstream::start(Reply::Answer(ip("192.0.2.10")));
        let upstreams = Upstreams::with(vec![fake.addr], ms(300), ms(300))
            .with_tls_at(tls_for_fake(&fake), vec![fake.addr]);
        let dns = Dns::new(
            BlockSetBuilder::new().build(),
            upstreams,
            Box::new(FixedOffset(0)),
        );
        let status = Status { dns, ..status };
        // Configured, and not switched on: the clock is awaited.
        assert_eq!(status.stats()["upstream_tls"], "waiting for the clock");
        // Switched on: the connections that are up, and the handshakes.
        status.dns.upstreams().start_tls();
        let end = Instant::now() + Duration::from_secs(10);
        while !matches!(
            status.dns.upstreams().tls(),
            TlsState::On {
                up: 1,
                counts: ConnCounts {
                    connects: 1,
                    resumed: 0,
                    ..
                }
            }
        ) {
            assert!(Instant::now() < end, "no session came up");
            tokio::time::sleep(ms(5)).await;
        }
        assert_eq!(
            status.stats()["upstream_tls"],
            json!({
                "up": 1,
                "connects": 1,
                "resumed": 0,
                "idle_closes": 0,
                "server_closes": 0,
                "retried": 0,
            })
        );
        // Neither a name that was asked for nor the certificate's is in the statistics.
        assert!(!status.stats().to_string().contains("example"));
    }

    #[tokio::test]
    async fn the_threat_hits_are_counted_apart_from_the_blocks() {
        let (status, _http, dns) = served(Reply::Answer(ip("192.0.2.10"))).await;
        let mut builder = lists::from_config(&["ads.example.com".to_owned()], &[]);
        builder.add_list_as(b"||bad.example.net^\n", ListClass::Threat);
        status.dns.resolver().set_blockset(builder.build());
        for name in ["ads.example.com", "x.bad.example.net", "bad.example.net"] {
            ask_udp(dns, name).await.unwrap();
        }
        let v = status.stats();
        assert_eq!(
            (
                v["blocked_today"].as_u64(),
                v["blocked_threat_today"].as_u64(),
                v["blocked_total"].as_u64(),
                v["blocked_threat_total"].as_u64()
            ),
            (Some(3), Some(2), Some(3), Some(2))
        );
    }

    // Review Focus 5
    #[tokio::test]
    async fn port_80_gives_counts_and_never_an_address_or_a_query() {
        let (status, http, _dns) = served(Reply::Silent).await;
        status.dns.note_client(ip("198.51.100.4").into());
        status.dns.note_client(ip("198.51.100.4").into());
        let v = status.stats();
        assert_eq!(
            (v["clients_hour"].as_u64(), v["clients_24h"].as_u64()),
            (Some(1), Some(1))
        );
        for line in [
            "GET /api/v1/queries HTTP/1.1",
            "GET /api/v1/queries?n=5 HTTP/1.1",
        ] {
            let r = status.respond(line, peer(4));
            assert_eq!(
                (r.status, r.content_type, r.body.as_slice()),
                (
                    403,
                    "text/plain; charset=utf-8",
                    &b"this needs the API login\n"[..]
                ),
                "{line}"
            );
        }
        // The same over a socket, with a reason phrase.
        let (head, body) = get(http, "GET /api/v1/queries?n=5 HTTP/1.1\r\n\r\n").await;
        assert!(head.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{head}");
        assert_eq!(body, b"this needs the API login\n");
        assert_eq!(
            status
                .respond("GET /api/v1/clients HTTP/1.1", peer(4))
                .status,
            404
        );
        for line in [
            "GET / HTTP/1.1",
            "GET /api/v1/stats HTTP/1.1",
            "GET /log HTTP/1.1",
            "GET /api/v1/queries HTTP/1.1",
            "GET /api/v1/clients HTTP/1.1",
        ] {
            let body = String::from_utf8_lossy(&status.respond(line, peer(4)).body).into_owned();
            assert!(!body.contains("198.51.100.4"), "{line}");
        }
    }

    #[tokio::test]
    async fn a_client_counts_for_the_hour_and_the_day_it_was_last_seen_in() {
        let (served, _http, _dns) = served(Reply::Silent).await;
        // A service that has been up for 26 hours.
        let status = Status {
            dns: aged(26 * 3600),
            ..served
        };
        let now = status.dns.now().mono_secs;
        {
            let mut clients = status.dns.clients();
            clients.record(ip("198.51.100.4").into(), now - 10);
            clients.record(ip("198.51.100.5").into(), now - 2 * 3600);
            clients.record(ip("198.51.100.6").into(), 0);
        }
        let v = status.stats();
        assert_eq!(
            (v["clients_hour"].as_u64(), v["clients_24h"].as_u64()),
            (Some(1), Some(2))
        );
    }

    #[tokio::test]
    async fn the_lists_age_is_known_only_with_a_fetch_time_and_a_set_clock() {
        let (served, _http, _dns) = served(Reply::Silent).await;
        let (clock_set, synced) = watch::channel(false);
        let lists = Lists::new(ListState {
            source: Source::Config,
            names: 1,
            fetched_unix_secs: None,
            last_error: None,
        });
        let status = Status {
            lists: lists.clone(),
            synced,
            ..served
        };
        let list = |v: &Value| {
            (
                v["list_source"].as_str().map(str::to_owned),
                v["list_names"].as_u64(),
                v["list_age_secs"].as_u64(),
                v["list_error"].as_str().map(str::to_owned),
            )
        };
        // Lists that were fetched an hour ago by the system's clock: until SNTP says that the clock
        // is set, their age is not known.
        lists.fetched(302_176, status.dns.now().unix_secs - 3600);
        assert_eq!(
            list(&status.stats()),
            (Some("fetched".to_owned()), Some(302_176), None, None)
        );
        assert!(status.stats()["list_age_secs"].is_null());
        clock_set.send_replace(true);
        let v = status.stats();
        let (source, names, age, error) = list(&v);
        assert_eq!(
            (source.as_deref(), names, error),
            (Some("fetched"), Some(302_176), None)
        );
        assert!(matches!(age, Some(3600 | 3601)), "{age:?}");
        // A failed refresh shows its error and changes nothing else.
        lists.failed("list 1 (lists.example.net): status 404".to_owned());
        let v = status.stats();
        let (source, names, age, error) = list(&v);
        assert_eq!(
            (source.as_deref(), names, error.as_deref()),
            (
                Some("fetched"),
                Some(302_176),
                Some("list 1 (lists.example.net): status 404")
            )
        );
        assert!(matches!(age, Some(3600 | 3601)), "{age:?}");
        // A fetch time that is ahead of the clock does not make a negative age.
        lists.fetched(10, status.dns.now().unix_secs + 3600);
        assert_eq!(status.stats()["list_age_secs"].as_u64(), Some(0));
    }

    #[tokio::test]
    async fn what_is_not_known_yet_is_null_and_a_pause_shows_its_seconds() {
        let (status, _http, _dns) = served(Reply::Silent).await;
        let v = status.stats();
        assert!(
            v["upstream_ms"].is_null()
                && v["blocked_share"].is_null()
                && v["cache_hit_rate"].is_null()
        );
        let until = status.dns.now().mono_secs + 300;
        status.dns.resolver().pause_until(until);
        let v = status.stats();
        assert_eq!(v["blocking"], "paused");
        assert!(matches!(v["pause_left_secs"].as_u64(), Some(299..=300)));
    }

    #[tokio::test]
    async fn the_stats_tell_the_link_and_the_board_temperature() {
        let (status, _http, _dns) = served(Reply::Silent).await;
        let status = Status {
            link: Arc::new(|| live::WifiStatus {
                associated: true,
                signal_dbm: Some(-61),
                ap: Some("00:00:5e:00:53:01".to_owned()),
                freq_mhz: Some(5180),
                joined_secs: None,
            }),
            board_c: Arc::new(|| Some(51)),
            ..status
        };
        let v = status.stats();
        assert_eq!(
            v["wifi"],
            json!({
                "associated": true,
                "signal_dbm": -61,
                "ap": "00:00:5e:00:53:01",
                "freq_mhz": 5180
            })
        );
        assert_eq!(v["board_c"], 51);
    }

    #[tokio::test]
    async fn the_stats_say_null_for_a_link_and_a_board_that_are_not_known() {
        let (status, _http, _dns) = served(Reply::Silent).await;
        let v = status.stats();
        assert_eq!(
            v["wifi"],
            json!({"associated": false, "signal_dbm": null, "ap": null, "freq_mhz": null})
        );
        assert!(v["board_c"].is_null());
    }

    #[test]
    fn a_share_has_four_decimal_places_and_none_of_nothing() {
        assert_eq!(
            (
                share(1, 3),
                share(4780, 10_818),
                share(0, 5),
                share(5, 5),
                share(0, 0)
            ),
            (Some(0.3333), Some(0.4419), Some(0.0), Some(1.0), None)
        );
    }

    #[tokio::test]
    async fn a_request_over_a_socket_gets_one_whole_answer_and_the_connection_closes() {
        let (_status, http, _dns) = served(Reply::Silent).await;
        let (head, body) = get(http, "GET /log HTTP/1.1\r\n\r\n").await;
        assert!(
            head.starts_with("HTTP/1.1 200 OK\r\n")
                && head.contains("Content-Type: text/plain; charset=utf-8\r\n")
        );
        assert_eq!(body, b"one\ntwo\n");
        assert!(
            get(http, "GET / HTTP/1.1\r\n\r\n")
                .await
                .0
                .starts_with("HTTP/1.1 404 ")
        );
        assert!(
            get(http, "DELETE /log HTTP/1.1\r\n\r\n")
                .await
                .0
                .starts_with("HTTP/1.1 405 ")
        );
        assert!(
            get(http, "nonsense\r\n\r\n")
                .await
                .0
                .starts_with("HTTP/1.1 400 ")
        );
    }

    // Review Focus 3
    #[tokio::test]
    async fn silent_clients_do_not_keep_the_next_from_being_served() {
        let (_status, http, _dns) = served(Reply::Silent).await;
        // The limit here is two clients, and each may take 200 ms: one sends half a line, the
        // other nothing.
        let mut half = TcpStream::connect(http).await.unwrap();
        half.write_all(b"GET /log HT").await.unwrap();
        let mut silent = TcpStream::connect(http).await.unwrap();
        // A third waits in the queue of the listener for a place, and is answered when one is
        // free.
        let started = Instant::now();
        let (head, body) = timeout(ms(1000), get(http, "GET /log HTTP/1.1\r\n\r\n"))
            .await
            .expect("it is answered within a second");
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
        assert_eq!(body, b"one\ntwo\n");
        assert!(started.elapsed() >= ms(100), "{:?}", started.elapsed());
        // The two that said too little are closed, with no reply.
        assert_eq!(read_some(&mut half, ms(500)).await.unwrap(), 0);
        assert_eq!(read_some(&mut silent, ms(500)).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn a_line_without_an_end_is_answered_400_after_1024_bytes() {
        let (_status, http, _dns) = served(Reply::Silent).await;
        assert!(
            get(http, &"a".repeat(1024))
                .await
                .0
                .starts_with("HTTP/1.1 400 ")
        );
    }

    /// What `stream` gives until the server ends the connection, within `wait`: an error if it
    /// was reset, which is what a lingering close is there to prevent.
    async fn read_to_the_end(stream: &mut TcpStream, wait: Duration) -> io::Result<Vec<u8>> {
        let mut reply = Vec::new();
        match timeout(wait, stream.read_to_end(&mut reply)).await {
            Ok(read) => read.map(|_| reply),
            Err(_) => Err(io::ErrorKind::TimedOut.into()),
        }
    }

    #[tokio::test]
    async fn a_large_log_is_read_whole_by_a_client_that_has_request_bytes_the_server_never_read() {
        // 3 MiB of log, more than the buffers of both sockets hold, so that the end of the answer
        // is still on the server's side when it has written the last of it.
        let (status, http, _dns) =
            served_with(Reply::Silent, Duration::from_secs(20), 4 << 20).await;
        let line = "x".repeat(80);
        {
            let mut log = status.log.lock().unwrap_or_else(PoisonError::into_inner);
            for n in 0..(3 << 20) / 90 + 100 {
                log.push(&format!("{n:08} {line}"));
            }
        }
        let expected = status
            .log
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .text();
        assert!(expected.len() > 3 << 20);

        let mut stream = TcpStream::connect(http).await.unwrap();
        // The server reads the request line and no more: these 8 KiB of header are left unread.
        let pad = "p".repeat(8000);
        let request = format!("GET /log HTTP/1.1\r\nHost: x\r\nX-Pad: {pad}\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        // The client reads nothing for a while, so that the answer waits in the buffers.
        sleep(ms(500)).await;
        let reply = read_to_the_end(&mut stream, Duration::from_secs(15))
            .await
            .expect("the answer is read to its end, with no reset");
        let blank = reply
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("a head");
        assert!(reply.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert_eq!(reply.len() - (blank + 4), expected.len());
        assert!(reply[blank + 4..] == *expected.as_bytes());
    }

    #[tokio::test]
    async fn a_client_that_goes_on_sending_after_a_400_still_reads_it_whole() {
        let (_status, http, _dns) = served_with(Reply::Silent, Duration::from_secs(5), 4096).await;
        let mut stream = TcpStream::connect(http).await.unwrap();
        // A line that does not end in 1,100 bytes: the server answers at 1,024, and what the
        // client goes on with, 16 KiB in pieces, is for it to read and throw away. With the
        // connection closed at once, which is a reset, a write would fail from there on.
        stream.write_all(&[b'a'; 1100]).await.unwrap();
        for piece in 0..16 {
            sleep(ms(10)).await;
            stream
                .write_all(&[b'a'; 1024])
                .await
                .unwrap_or_else(|error| panic!("write {piece}: {error}"));
        }
        let reply = read_to_the_end(&mut stream, Duration::from_secs(3))
            .await
            .expect("the answer is read to its end");
        assert!(reply.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
        assert!(reply.ends_with(b"bad request\n"));
    }

    #[tokio::test]
    async fn a_client_that_never_stops_sending_is_closed_at_the_time_bound() {
        // A byte every 100 ms, which no byte count would stop.
        let (_status, http, _dns) = served_with(Reply::Silent, Duration::from_secs(20), 4096).await;
        let mut stream = TcpStream::connect(http).await.unwrap();
        stream.write_all(&[b'a'; 1100]).await.unwrap();
        let began = Instant::now();
        // The client finds out when a write fails: a little after the close.
        while stream.write_all(b"a").await.is_ok() && began.elapsed() < Duration::from_secs(8) {
            sleep(ms(100)).await;
        }
        let closed = began.elapsed();
        assert!(
            (linger::TIME - ms(100)..linger::TIME + Duration::from_secs(2)).contains(&closed),
            "{closed:?}"
        );
    }

    #[tokio::test]
    async fn a_client_that_floods_is_closed_at_the_byte_bound_long_before_the_time_bound() {
        // 20 s of time bound, which the 64 KiB beat: the client sends 4 KiB every 5 ms, which no
        // buffer takes in, and finds out that the server has closed when a write fails.
        let (_status, http, _dns) = served_with(Reply::Silent, Duration::from_secs(20), 4096).await;
        let mut stream = TcpStream::connect(http).await.unwrap();
        // The server reads 1,024 bytes of these for the line, and drains the rest.
        stream.write_all(&[b'a'; 1100]).await.unwrap();
        let began = Instant::now();
        let mut sent = 0;
        while sent < 1 << 20 && stream.write_all(&[b'a'; 4096]).await.is_ok() {
            sent += 4096;
            sleep(ms(5)).await;
        }
        // A client that finds out a piece or two late has sent that much more than the bound.
        let drained = sent + 76;
        let bound = linger::BYTES;
        assert!(
            (bound - 4096..bound + 8 * 4096).contains(&drained),
            "{drained}"
        );
        assert!(
            began.elapsed() < Duration::from_secs(10),
            "{:?}",
            began.elapsed()
        );
    }

    #[tokio::test]
    async fn the_lingering_close_ends_with_the_connections_time_and_does_not_add_to_it() {
        // Each connection has 600 ms in all, and the linger is 2 s: it is cut at 600 ms.
        let (_status, http, _dns) = served_with(Reply::Silent, ms(600), 4096).await;
        let mut stream = TcpStream::connect(http).await.unwrap();
        stream.write_all(&[b'a'; 1100]).await.unwrap();
        let began = Instant::now();
        while stream.write_all(b"a").await.is_ok() && began.elapsed() < Duration::from_secs(8) {
            sleep(ms(50)).await;
        }
        let closed = began.elapsed();
        assert!((ms(550)..ms(1500)).contains(&closed), "{closed:?}");
    }

    #[tokio::test]
    async fn a_client_that_reads_its_answer_and_closes_does_not_hold_its_place_for_the_linger() {
        // One place for 5 s: a second client is served as soon as the first has gone.
        let (_status, http, _dns) = served_with(Reply::Silent, Duration::from_secs(5), 4096).await;
        let began = Instant::now();
        for _ in 0..5 {
            let (head, body) = get(http, "GET /log HTTP/1.1\r\n\r\n").await;
            assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
            assert_eq!(body, b"one\ntwo\n");
        }
        assert!(began.elapsed() < linger::TIME, "{:?}", began.elapsed());
    }

    #[tokio::test]
    async fn a_client_that_leaves_early_costs_the_next_nothing() {
        let (_status, http, _dns) = served(Reply::Silent).await;
        // Both places are taken by clients that go away at once, without a whole line, and the
        // next sends a line that ends in a bare newline.
        for _ in 0..2 {
            let mut gone = TcpStream::connect(http).await.unwrap();
            gone.write_all(b"GET /l").await.unwrap();
        }
        let (head, _body) = get(http, "GET /log HTTP/1.1\n").await;
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
    }

    /// The device 198.51.100.`n`, a documentation range: a peer that counts.
    fn peer(n: u8) -> IpAddr {
        Ipv4Addr::new(198, 51, 100, n).into()
    }

    /// The path of the one route that opts a device in.
    const ME: &str = "GET /api/v1/me HTTP/1.1";

    /// What `from` is answered when it asks [`ME`]: it must be a 200 of JSON, and is read as such.
    fn me(status: &Status, from: IpAddr) -> Value {
        let response = status.respond(ME, from);
        assert_eq!((response.status, response.content_type), (200, JSON));
        serde_json::from_slice(&response.body).unwrap()
    }

    /// The keys of the JSON object `v`, sorted.
    fn keys(v: &Value) -> Vec<&str> {
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        keys
    }

    /// Notes that `from` asked for `name`, as the resolver does for a device that is watched.
    fn asked(status: &Status, from: IpAddr, name: &str, refused: bool, threat: bool) {
        let IpAddr::V4(from) = from else {
            panic!("a device of these tests has an IPv4 address");
        };
        let now = status.dns.now();
        let mut watched = status.dns.watched();
        watched.note(from, now.mono_secs, now.unix_secs, name, refused, threat);
    }

    #[tokio::test]
    async fn me_answers_the_asking_device_with_the_specs_keys() {
        let (status, _http, _dns) = served(Reply::Silent).await;
        let device = peer(4);
        // The first call opts the device in: it is told so, and has nothing yet.
        let v = me(&status, device);
        assert_eq!(
            keys(&v),
            [
                "asked_24h",
                "blocking",
                "exempt",
                "recent",
                "refused_24h",
                "threats_24h",
                "unix_secs",
                "unknown_devices",
                "watching_since_unix"
            ]
        );
        assert!(v["unix_secs"].as_u64().unwrap() > 1_700_000_000);
        assert_eq!(v["watching_since_unix"], v["unix_secs"]);
        assert_eq!(
            (v["blocking"].as_str(), v["exempt"].as_bool()),
            (Some("on"), Some(false))
        );
        assert_eq!(
            (
                v["asked_24h"].as_u64(),
                v["refused_24h"].as_u64(),
                v["threats_24h"].as_u64(),
                v["unknown_devices"].as_u64()
            ),
            (Some(0), Some(0), Some(0), Some(0))
        );
        assert_eq!(v["recent"], json!([]));

        // From then on its queries are kept, and the answer lists them, newest first.
        let (t0, t1, t2) = {
            let now = status.dns.now().unix_secs;
            (now - 30, now - 20, now - 10)
        };
        let now = status.dns.now();
        {
            let mut watched = status.dns.watched();
            let addr = Ipv4Addr::new(198, 51, 100, 4);
            watched.note(addr, now.mono_secs, t0, "ads.example.com", true, false);
            watched.note(addr, now.mono_secs, t1, "x.bad.example.net", true, true);
            watched.note(addr, now.mono_secs, t2, "example.com", false, false);
        }
        let response = status.respond(ME, device);
        let text = String::from_utf8(response.body.clone()).unwrap();
        let v: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            (
                v["asked_24h"].as_u64(),
                v["refused_24h"].as_u64(),
                v["threats_24h"].as_u64()
            ),
            (Some(3), Some(2), Some(1))
        );
        assert_eq!(
            v["recent"],
            json!([
                {"unix_secs": t2, "name": "example.com", "refused": false, "threat": false},
                {"unix_secs": t1, "name": "x.bad.example.net", "refused": true, "threat": true},
                {"unix_secs": t0, "name": "ads.example.com", "refused": true, "threat": false},
            ])
        );
        // A refresh does not move where the watch began, and no address is in the answer.
        assert!(v["watching_since_unix"].as_u64().unwrap() <= now.unix_secs);
        assert!(!text.contains("198.51.100"), "{text}");
    }

    #[tokio::test]
    async fn me_shows_one_device_nothing_of_another() {
        let (status, _http, _dns) = served(Reply::Silent).await;
        let (one, other) = (peer(4), peer(5));
        me(&status, one);
        me(&status, other);
        asked(&status, one, "private.example.com", false, false);
        asked(&status, other, "theirs.example.org", true, false);
        let mine = me(&status, one);
        let theirs = me(&status, other);
        assert_eq!(
            mine["recent"].as_array().unwrap().len() + theirs["recent"].as_array().unwrap().len(),
            2
        );
        assert_eq!(mine["recent"][0]["name"], "private.example.com");
        assert_eq!(theirs["recent"][0]["name"], "theirs.example.org");
        assert_eq!(
            (mine["refused_24h"].as_u64(), theirs["refused_24h"].as_u64()),
            (Some(0), Some(1))
        );
        // A third device that calls for the first time is shown nothing of what the two asked.
        let third = status.respond(ME, peer(6));
        let text = String::from_utf8(third.body).unwrap();
        assert!(!text.contains("example"), "{text}");
        assert_eq!(status.dns.watched().len(), 3);
    }

    #[tokio::test]
    async fn me_leaves_out_reverse_lookups_so_that_no_address_is_in_it() {
        let (status, _http, _dns) = served(Reply::Silent).await;
        let device = peer(4);
        me(&status, device);
        asked(&status, device, "5.2.0.192.in-addr.arpa", false, false);
        asked(&status, device, "example.com", false, false);
        let response = status.respond(ME, device);
        let text = String::from_utf8(response.body).unwrap();
        let v: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["asked_24h"].as_u64(), Some(1));
        assert_eq!(
            v["recent"]
                .as_array()
                .unwrap()
                .iter()
                .map(|seen| seen["name"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["example.com"]
        );
        assert!(!text.contains("arpa"), "{text}");
    }

    #[tokio::test]
    async fn me_is_404_for_loopback_and_for_a_query_string() {
        let (status, _http, _dns) = served(Reply::Silent).await;
        let not_counted: [IpAddr; 5] = [
            Ipv4Addr::LOCALHOST.into(),
            Ipv4Addr::new(127, 0, 0, 2).into(),
            Ipv6Addr::LOCALHOST.into(),
            "2001:db8::4".parse().unwrap(),
            Ipv4Addr::new(198, 51, 100, 4).to_ipv6_mapped().into(),
        ];
        for from in not_counted {
            let response = status.respond(ME, from);
            assert_eq!(
                (response.status, response.body.as_slice()),
                (404, &b"not found\n"[..]),
                "{from}"
            );
        }
        // A query string is no more the route than it is for the other open paths.
        for line in [
            "GET /api/v1/me?x=1 HTTP/1.1",
            "GET /api/v1/me? HTTP/1.1",
            "GET /api/v1/me/ HTTP/1.1",
            "GET /api/v1/mine HTTP/1.1",
        ] {
            assert_eq!(status.respond(line, peer(4)).status, 404, "{line}");
        }
        // None of them watched anyone.
        assert!(status.dns.watched().is_empty());
    }

    #[tokio::test]
    async fn me_over_a_socket_from_loopback_is_404_and_watches_nobody() {
        let (status, http, _dns) = served(Reply::Silent).await;
        let (head, body) = get(http, "GET /api/v1/me HTTP/1.1\r\n\r\n").await;
        assert!(head.starts_with("HTTP/1.1 404 Not Found\r\n"), "{head}");
        assert_eq!(body, b"not found\n");
        assert!(status.dns.watched().is_empty());
    }

    #[tokio::test]
    async fn me_reports_exempt_and_unknown_devices() {
        let (status, _http, _dns) = served(Reply::Silent).await;
        let (exempt, other) = (peer(4), peer(5));
        status
            .dns
            .exempt()
            .listed()
            .replace(&[Ipv4Addr::new(198, 51, 100, 4)]);
        let status = Status {
            unknown_devices: Arc::new(|| 3),
            ..status
        };
        let (a, b) = (me(&status, exempt), me(&status, other));
        assert_eq!(
            (a["exempt"].as_bool(), b["exempt"].as_bool()),
            (Some(true), Some(false))
        );
        assert_eq!(
            (a["unknown_devices"].as_u64(), b["unknown_devices"].as_u64()),
            (Some(3), Some(3))
        );
        // In the exempt-by-default mode every device but a blocked one is exempt.
        status.dns.exempt().set_by_default(true);
        assert_eq!(me(&status, other)["exempt"], true);
    }

    #[tokio::test]
    async fn me_says_blocking_as_the_stats_do() {
        let (status, _http, _dns) = served(Reply::Silent).await;
        assert_eq!(me(&status, peer(4))["blocking"], "on");
        let until = status.dns.now().mono_secs + 300;
        status.dns.resolver().pause_until(until);
        assert_eq!(me(&status, peer(4))["blocking"], "paused");
        assert_eq!(status.stats()["blocking"], "paused");
    }

    #[tokio::test]
    async fn me_is_405_for_post_and_the_other_methods() {
        let (status, _http, _dns) = served(Reply::Silent).await;
        for line in [
            "POST /api/v1/me HTTP/1.1",
            "DELETE /api/v1/me HTTP/1.1",
            "HEAD /api/v1/me HTTP/1.1",
        ] {
            let response = status.respond(line, peer(4));
            assert_eq!(
                (response.status, response.body.as_slice()),
                (405, &b"method not allowed\n"[..]),
                "{line}"
            );
        }
        assert!(status.dns.watched().is_empty());
    }

    #[tokio::test]
    async fn nothing_but_me_opts_a_device_in() {
        let (status, _http, _dns) = served(Reply::Silent).await;
        for line in [
            "GET /api/v1/stats HTTP/1.1",
            "GET /log HTTP/1.1",
            "GET /api/v1/queries HTTP/1.1",
            "GET / HTTP/1.1",
        ] {
            status.respond(line, peer(4));
        }
        assert!(status.dns.watched().is_empty());
    }
}
