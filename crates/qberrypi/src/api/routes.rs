//! The endpoints of the Pi-hole API subset: [`Api::handle`] turns one [`Request`] into one
//! [`Reply`].
//!
//! Everything here is plain logic over [`Facts`], the figures and the switch that the rest of
//! qberrypi provides, a monotonic clock and a source of random bytes, so it is tested without a
//! socket. The connection, TLS and the pool thread that a call runs on are the caller's.
//!
//! The order of the checks is the security of the API:
//!
//! 1. A target outside `/api/` is 404 `not_found`, whatever else it carries.
//! 2. `POST /api/auth`, exactly that target, is the login, and the only request served without a
//!    session.
//! 3. Every other request needs a valid session in `X-FTL-SID` ([`Request::sid`]); without one it
//!    is 401 and changes nothing. For `/api/auth` the 401 is in the login's session shape, for
//!    everything else in Pi-hole's error shape. A sid in a cookie or in the query string is not
//!    looked at.
//! 4. A known path with another method is 405 `method_not_allowed`.
//! 5. Any other path is 404 `not_found`, and so is a query string on any path but
//!    `/api/v1/queries`, which takes `n` alone.
//!
//! The watchdog's endpoints, everything under `/api/qbp/`, are handed on to [`qbp`] once the
//! session is valid, and are 404 on an API that was given no watch ([`Api::with_watch`]).
//!
//! `POST /api/qbp/update` is the one request that is not answered here: its body is far over the
//! cap that every other request has, so the connection recognises it from the head, asks
//! [`Api::has_session`] before a byte of the body is read, and streams the body to the update
//! receiver ([`Api::with_update`]). What reaches [`Api::handle`] on that path is a request that was
//! read whole: 405 for any other method, 404 for a query string, and 404 on an API with no
//! receiver, and for a POST that a connection would have streamed, a 400 that says so.
//!
//! The login is held back by the [`Limiter`] before the password is checked at all, and checked
//! again once this call holds the verification lock, so a guess that queued behind another meets
//! the hold-back that the other started: the other records its failure before it lets go of the
//! lock. One password is verified at a time, and neither the sessions nor the limiter are locked
//! while it is.
//!
//! Every JSON object answered carries `"took"`, the seconds `handle` spent. The two arrays,
//! `/api/v1/queries` and `/api/v1/clients`, carry none, as an array has no place for it, and a
//! 204 has no body at all. Nothing here panics on any request, and the only log lines are the
//! five of the login, none of which names an address, a sid, a password or a body.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use qb_dns::stats::BUCKET_SECS;
use qb_dns::{Counts, HistoryBucket, LogEntry};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::http::{Reply, Request};
use super::password::PasswordHash;
use super::qbp::{self, QbpWatch};
use super::seams::{Client, MAX_QUERIES, ServerStats, query_json};
use super::session::{HoldBack, Limiter, SESSION_SECS, Sessions};
use crate::update::receive::{self, Receiver};

/// The queries `/api/v1/queries` lists when no `n` is given.
const DEFAULT_QUERIES: usize = 100;

/// The seconds in the 24 hours the summary covers.
const DAY_SECS: f64 = 86_400.0;

/// The longest pause, in seconds.
const MAX_PAUSE_SECS: u64 = 86_400;

/// The path of the login, the session check and the logout.
const AUTH: &str = "/api/auth";

/// The key and the message of an error object.
pub(super) type Error = (&'static str, &'static str);

/// No valid session.
const UNAUTHORIZED: Error = ("unauthorized", "Unauthorized");
/// No such endpoint.
pub(super) const NOT_FOUND: Error = ("not_found", "Not found");
/// A known endpoint, another method.
pub(super) const METHOD_NOT_ALLOWED: Error = ("method_not_allowed", "Method not allowed");
/// Logins are held back.
const RATE_LIMITING: Error = ("rate_limiting", "Rate-limiting login attempts");
/// A body that is not JSON, or a login body with no `password` string.
pub(super) const NO_VALID_JSON: Error =
    ("bad_request", "Invalid request body data (no valid JSON)");
/// A blocking body with no `blocking` boolean.
const NO_BLOCKING: Error = ("body_error", "No \"blocking\" boolean in body data");
/// A pause with no timer, or with one out of range.
const BAD_TIMER: Error = ("bad_request", "a pause needs a timer of 1 to 86400 seconds");
/// A query string on `/api/v1/queries` that is not `n` of 1 or more.
const BAD_COUNT: Error = ("bad_request", "n must be a whole number of 1 or more");
/// A right password, but no random bytes for the session id.
const NO_RANDOM: Error = ("internal", "no random source");
/// A request that is not one this server takes: the connection's reader refused it.
const MALFORMED: Error = ("bad_request", "Malformed request");
/// A request with a head or a body over the limits.
const TOO_LARGE: Error = ("payload_too_large", "Request too large");
/// The update, sent as a request that was read whole instead of streamed.
const NOT_STREAMED: Error = (
    "bad_request",
    "The update's body is streamed, not sent as one small request",
);

/// The figures and the blocking switch that the endpoints answer from, provided by the rest of
/// qberrypi.
pub trait Facts: Send + Sync {
    /// The queries of the last 24 hours, by outcome.
    fn last_24h(&self) -> Counts;
    /// The 144 ten-minute buckets of the last 24 hours, oldest first, ending with the current
    /// one.
    fn history(&self) -> Vec<HistoryBucket>;
    /// Each configured upstream server's figures since boot, in the configured order.
    fn upstreams(&self) -> Vec<ServerStats>;
    /// The devices seen in the last 24 hours, and the devices held in the table.
    fn clients(&self) -> (usize, usize);
    /// The devices held in the table, most recently seen first.
    fn client_list(&self) -> Vec<Client>;
    /// The `n` most recent queries, newest first.
    fn recent(&self, n: usize) -> Vec<LogEntry>;
    /// The names in the block set, and the Unix time of the last list fetch; each `None` while
    /// not known.
    fn list(&self) -> (Option<usize>, Option<u64>);
    /// The seconds left of the pause of blocking; `None` while blocking.
    fn paused_left_secs(&self) -> Option<u64>;
    /// Pauses blocking for `secs` seconds.
    fn pause_for(&self, secs: u64);
    /// Ends the pause of blocking, if there is one.
    fn resume(&self);
}

/// The API: the password, the facts it answers from, its clock and random source, and the
/// sessions and the limit on failed logins that it keeps.
///
/// It is shared by the connections, each of which calls [`Api::handle`] on its own thread.
pub struct Api {
    /// The hash of the one password that logs in.
    pub hash: PasswordHash,
    /// The figures and the switch the endpoints answer from.
    pub facts: Arc<dyn Facts>,
    /// The monotonic clock, in seconds.
    pub mono_secs: Arc<dyn Fn() -> u64 + Send + Sync>,
    /// 16 bytes from the kernel's random source, for the id of a new session; `None` when the
    /// source cannot be read, and then a login that was right gets a 500 and no session.
    ///
    /// The integration must build this from a fail-closed reading of the kernel's random source,
    /// such as `sys::random_bytes`, and never from a fallback: `sys::random_u64` falls back to
    /// clock noise, which is not secret, and a session id made from it could be guessed.
    pub random: Arc<dyn Fn() -> Option<[u8; 16]> + Send + Sync>,
    /// The open sessions.
    sessions: Mutex<Sessions>,
    /// The limit on failed logins.
    limiter: Mutex<Limiter>,
    /// Held while a password is verified and its result recorded, so that one is verified at a
    /// time.
    verifying: Mutex<()>,
    /// What the endpoints under `/api/qbp/` answer from; `None` until [`Api::with_watch`].
    qbp: Option<Arc<QbpWatch>>,
    /// The update receiver, which the connection hands the body of `POST /api/qbp/update` to;
    /// `None` until [`Api::with_update`].
    update: Option<Receiver>,
}

/// The endpoints, by path.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Endpoint {
    /// `/api/auth`: the login, the session check and the logout.
    Auth,
    /// `/api/stats/summary`.
    Summary,
    /// `/api/history`.
    History,
    /// `/api/stats/upstreams`.
    Upstreams,
    /// `/api/dns/blocking`.
    Blocking,
    /// `/api/v1/queries`.
    Queries,
    /// `/api/v1/clients`.
    Clients,
}

impl Endpoint {
    /// The endpoint at `path`, the target before any `?`.
    fn at(path: &str) -> Option<Endpoint> {
        Some(match path {
            AUTH => Endpoint::Auth,
            "/api/stats/summary" => Endpoint::Summary,
            "/api/history" => Endpoint::History,
            "/api/stats/upstreams" => Endpoint::Upstreams,
            "/api/dns/blocking" => Endpoint::Blocking,
            "/api/v1/queries" => Endpoint::Queries,
            "/api/v1/clients" => Endpoint::Clients,
            _ => return None,
        })
    }

    /// Whether the endpoint answers `method`.
    fn allows(self, method: &str) -> bool {
        match self {
            Endpoint::Auth => matches!(method, "POST" | "GET" | "DELETE"),
            Endpoint::Blocking => matches!(method, "GET" | "POST"),
            _ => method == "GET",
        }
    }
}

impl Api {
    /// An API that logs in with the password of `hash` and answers from `facts`, with no session
    /// open and no failed login recorded.
    pub fn new(
        hash: PasswordHash,
        facts: Arc<dyn Facts>,
        mono_secs: Arc<dyn Fn() -> u64 + Send + Sync>,
        random: Arc<dyn Fn() -> Option<[u8; 16]> + Send + Sync>,
    ) -> Self {
        Api {
            hash,
            facts,
            mono_secs,
            random,
            sessions: Mutex::default(),
            limiter: Mutex::default(),
            verifying: Mutex::default(),
            qbp: None,
            update: None,
        }
    }

    /// This API, with the endpoints under `/api/qbp/` answering from `watch`: the watchdog's alerts
    /// and devices. Without it they are 404.
    pub fn with_watch(mut self, watch: Arc<QbpWatch>) -> Self {
        self.qbp = Some(watch);
        self
    }

    /// This API, with `POST /api/qbp/update` taken by `receiver`: the connection streams the
    /// body of that request to it. Without it the path is 404.
    pub fn with_update(mut self, receiver: Receiver) -> Self {
        self.update = Some(receiver);
        self
    }

    /// The update receiver, if the API was given one.
    pub(super) fn receiver(&self) -> Option<&Receiver> {
        self.update.as_ref()
    }

    /// Whether `sid` is a valid session now, which uses it as any request that carries it does.
    /// For the connection, which must know before it reads a body that [`Api::handle`] never sees.
    pub(super) fn has_session(&self, sid: Option<&str>) -> bool {
        let now = (self.mono_secs)();
        sid.is_some_and(|sid| self.sessions().touch(sid, now).is_some())
    }

    /// Answers `request`, which came from `from`, in the order of checks the module describes.
    ///
    /// A login verifies a password, about 0.2 s of one core, and may first wait for another
    /// login's verification; the caller runs `handle` where that may block.
    pub fn handle(&self, request: &Request, from: Ipv4Addr) -> Reply {
        let started = Instant::now();
        let now = (self.mono_secs)();
        let (path, query) = match request.target.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (request.target.as_str(), None),
        };
        if !path.starts_with("/api/") {
            return error(404, NOT_FOUND, started);
        }
        if request.method == "POST" && request.target == AUTH {
            return self.login(&request.body, from, now, started);
        }
        let session = request
            .sid
            .as_deref()
            .and_then(|sid| Some((sid, self.sessions().touch(sid, now)?)));
        let Some((sid, validity)) = session else {
            return if path == AUTH {
                session_refused(401, None, started)
            } else {
                error(401, UNAUTHORIZED, started)
            };
        };
        if path == receive::PATH {
            return match (&self.update, request.method.as_str()) {
                _ if query.is_some() => error(404, NOT_FOUND, started),
                (None, _) => error(404, NOT_FOUND, started),
                (Some(_), "POST") => error(400, NOT_STREAMED, started),
                (Some(_), _) => error(405, METHOD_NOT_ALLOWED, started),
            };
        }
        if let Some(rest) = path.strip_prefix("/api/qbp/") {
            return match &self.qbp {
                Some(watch) => {
                    qbp::handle(watch, &request.method, rest, query, &request.body, started)
                }
                None => error(404, NOT_FOUND, started),
            };
        }
        let Some(endpoint) = Endpoint::at(path) else {
            return error(404, NOT_FOUND, started);
        };
        if !endpoint.allows(&request.method) {
            return error(405, METHOD_NOT_ALLOWED, started);
        }
        if query.is_some() && endpoint != Endpoint::Queries {
            return error(404, NOT_FOUND, started);
        }
        match (endpoint, request.method.as_str()) {
            (Endpoint::Auth, "DELETE") => {
                self.sessions().close(sid, now);
                Reply {
                    status: 204,
                    body: Vec::new(),
                }
            }
            (Endpoint::Auth, "GET") => session_valid(None, validity, None, started),
            // A POST to the exact target was the login above, and `allows` refused every other
            // method, so nothing reaches this arm; if one ever did, it is no session read.
            (Endpoint::Auth, _) => error(405, METHOD_NOT_ALLOWED, started),
            (Endpoint::Summary, _) => self.summary(started),
            (Endpoint::History, _) => self.history(started),
            (Endpoint::Upstreams, _) => self.upstreams(started),
            (Endpoint::Blocking, "POST") => self.set_blocking(&request.body, started),
            (Endpoint::Blocking, _) => self.blocking(started),
            (Endpoint::Queries, _) => self.queries(query, started),
            (Endpoint::Clients, _) => self.clients(),
        }
    }

    /// `POST /api/auth`: checks the password in `body` from `from`, unless logins from `from` are
    /// held back, and opens a session if it is right.
    fn login(&self, body: &[u8], from: Ipv4Addr, now: u64, started: Instant) -> Reply {
        if !self.limiter().allowed(from, now) {
            return error(429, RATE_LIMITING, started);
        }
        let Some(password) = password(body) else {
            return error(400, NO_VALID_JSON, started);
        };
        let verifying = self
            .verifying
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // A hold-back may have begun while this call waited for the lock (ruling R8).
        let now = (self.mono_secs)();
        if !self.limiter().allowed(from, now) {
            return error(429, RATE_LIMITING, started);
        }
        let right = self.hash.verify(password.as_bytes());
        drop(password);
        if right {
            self.limiter().succeeded(from);
            drop(verifying);
            let Some(random) = (self.random)() else {
                log::warn!("api: no random source for a session");
                return error(500, NO_RANDOM, started);
            };
            let sid = self.sessions().open(random, now);
            log::info!("api: login accepted");
            return session_valid(Some(sid), SESSION_SECS, Some("password correct"), started);
        }
        // Recorded before the lock is let go, so that the next guess in line meets its hold-back.
        let hold = self.limiter().failed(from, now);
        drop(verifying);
        log::warn!("api: login refused");
        match hold {
            HoldBack::None => {}
            HoldBack::ThisAddress => log::warn!("api: logins from one address held back for 60 s"),
            HoldBack::Everyone => log::warn!("api: all logins held back for 60 s"),
        }
        session_refused(401, Some("password incorrect"), started)
    }

    /// `GET /api/stats/summary`: the queries of the last 24 hours, the devices and the block set.
    fn summary(&self, started: Instant) -> Reply {
        let counts = self.facts.last_24h();
        let (active, total) = self.facts.clients();
        let (domains, fetched) = self.facts.list();
        let percent_blocked = if counts.queries == 0 {
            0.0
        } else {
            counts.blocked as f64 / counts.queries as f64 * 100.0
        };
        ok(
            json!({
                "queries": {
                    "total": counts.queries,
                    "blocked": counts.blocked,
                    "percent_blocked": percent_blocked,
                    "forwarded": counts.forwarded,
                    "cached": cached(&counts),
                    "frequency": counts.queries as f64 / DAY_SECS,
                },
                "clients": { "active": active, "total": total },
                "gravity": {
                    "domains_being_blocked": domains.unwrap_or(0),
                    "last_update": fetched.unwrap_or(0),
                },
            }),
            started,
        )
    }

    /// `GET /api/history`: the ten-minute buckets, oldest first, each labelled by its centre.
    fn history(&self, started: Instant) -> Reply {
        let history: Vec<Value> = self
            .facts
            .history()
            .iter()
            .map(|bucket| {
                json!({
                    "timestamp": bucket.start_unix.saturating_add(BUCKET_SECS / 2),
                    "total": bucket.counts.queries,
                    "cached": cached(&bucket.counts),
                    "blocked": bucket.counts.blocked,
                    "forwarded": bucket.counts.forwarded,
                })
            })
            .collect();
        ok(json!({ "history": history }), started)
    }

    /// `GET /api/stats/upstreams`: the block set and the cache as Pi-hole lists them, then each
    /// upstream server.
    fn upstreams(&self, started: Instant) -> Reply {
        let counts = self.facts.last_24h();
        let own = |name: &str, count: u64| {
            json!({
                "ip": name,
                "name": name,
                "port": -1,
                "count": count,
                "statistics": { "response": 0, "variance": 0 },
            })
        };
        let mut upstreams = vec![
            own("blocklist", counts.blocked),
            own("cache", cached(&counts)),
        ];
        upstreams.extend(self.facts.upstreams().iter().map(|server| {
            let ip = server.addr.ip().to_string();
            json!({
                "ip": ip,
                "name": ip,
                "port": server.addr.port(),
                "count": server.answered,
                "statistics": {
                    "response": server.latency_ms.map_or(0.0, |ms| f64::from(ms) / 1000.0),
                    "variance": 0,
                },
            })
        }));
        ok(
            json!({
                "upstreams": upstreams,
                "forwarded_queries": counts.forwarded,
                "total_queries": counts.queries,
            }),
            started,
        )
    }

    /// `GET /api/dns/blocking`, and the answer to a `POST`: whether blocking is on, and the
    /// seconds left of a pause.
    fn blocking(&self, started: Instant) -> Reply {
        let body = match self.facts.paused_left_secs() {
            None => json!({ "blocking": "enabled", "timer": null }),
            Some(left) => json!({ "blocking": "disabled", "timer": left }),
        };
        ok(body, started)
    }

    /// `POST /api/dns/blocking`: `{"blocking": true}` resumes, `{"blocking": false, "timer": n}`
    /// pauses for `n` seconds rounded up, and any other body changes nothing. Other fields are
    /// ignored. The answer is the GET's, read back after the change.
    fn set_blocking(&self, body: &[u8], started: Instant) -> Reply {
        let Ok(body) = serde_json::from_slice::<Value>(body) else {
            return error(400, NO_VALID_JSON, started);
        };
        match body.get("blocking").and_then(Value::as_bool) {
            None => return error(400, NO_BLOCKING, started),
            Some(true) => self.facts.resume(),
            Some(false) => {
                let Some(secs) = pause_secs(body.get("timer")) else {
                    return error(400, BAD_TIMER, started);
                };
                self.facts.pause_for(secs);
            }
        }
        self.blocking(started)
    }

    /// `GET /api/v1/queries?n=`: the `n` most recent queries, newest first, as an array, which
    /// carries no `took`.
    fn queries(&self, query: Option<&str>, started: Instant) -> Reply {
        let Some(n) = queries_wanted(query) else {
            return error(400, BAD_COUNT, started);
        };
        let queries: Vec<Value> = self
            .facts
            .recent(n)
            .iter()
            .take(n)
            .map(query_json)
            .collect();
        reply(200, Value::Array(queries), None)
    }

    /// `GET /api/v1/clients`: the devices, most recently seen first, as an array, which carries
    /// no `took`.
    fn clients(&self) -> Reply {
        let clients: Vec<Value> = self
            .facts
            .client_list()
            .iter()
            .map(|client| {
                json!({
                    "address": client.addr.to_string(),
                    "queries": client.queries,
                    "last_seen_secs": client.last_seen_secs_ago,
                })
            })
            .collect();
        reply(200, Value::Array(clients), None)
    }

    /// The sessions, locked.
    fn sessions(&self) -> MutexGuard<'_, Sessions> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The limit on failed logins, locked.
    fn limiter(&self) -> MutexGuard<'_, Limiter> {
        self.limiter.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The answer to bytes that were not a request this server takes: Pi-hole's error shape, 400.
pub fn malformed() -> Reply {
    error(400, MALFORMED, Instant::now())
}

/// The answer to a request whose head or body is over the limits: Pi-hole's error shape, 413.
pub fn too_large() -> Reply {
    error(413, TOO_LARGE, Instant::now())
}

/// The answer to a request that needs a session and has none: Pi-hole's error shape, 401.
pub fn unauthorized() -> Reply {
    error(401, UNAUTHORIZED, Instant::now())
}

/// The queries answered from the cache or here: the cache hits, and the queries that were
/// neither blocked, cached nor forwarded, as Pi-hole's "from cache or local configuration" counts
/// them.
fn cached(counts: &Counts) -> u64 {
    let local = counts
        .queries
        .saturating_sub(counts.blocked)
        .saturating_sub(counts.cache_hits)
        .saturating_sub(counts.forwarded);
    counts.cache_hits.saturating_add(local)
}

/// The password of a login body: a JSON object with `password` a string. Other fields, such as
/// `totp`, are ignored. The copy returned is wiped when it is dropped.
fn password(body: &[u8]) -> Option<Zeroizing<String>> {
    let Ok(Value::Object(mut fields)) = serde_json::from_slice::<Value>(body) else {
        return None;
    };
    match fields.remove("password") {
        Some(Value::String(password)) => Some(Zeroizing::new(password)),
        _ => None,
    }
}

/// The seconds of a pause from its `timer`: a finite JSON number, rounded up, of 1 to
/// [`MAX_PAUSE_SECS`]. `None` for anything else, `null` and a missing timer among them.
fn pause_secs(timer: Option<&Value>) -> Option<u64> {
    let secs = timer?.as_f64()?;
    if !secs.is_finite() {
        return None;
    }
    let secs = secs.ceil();
    if !(1.0..=MAX_PAUSE_SECS as f64).contains(&secs) {
        return None;
    }
    // In range, `secs` is a whole number of at most 86,400, which `as` converts exactly.
    Some(secs as u64)
}

/// The count the query string of `/api/v1/queries` asks for: [`DEFAULT_QUERIES`] with none, and
/// for exactly `n=` and one or more ASCII digits, that number, at most [`MAX_QUERIES`] (a number
/// too large for `usize` included). `None`, a 400, for 0 and for anything else.
fn queries_wanted(query: Option<&str>) -> Option<usize> {
    let Some(query) = query else {
        return Some(DEFAULT_QUERIES);
    };
    let digits = query.strip_prefix("n=")?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    // Only a number too large for `usize` fails to parse here.
    let n = digits.parse::<usize>().unwrap_or(MAX_QUERIES);
    (n >= 1).then(|| n.min(MAX_QUERIES))
}

/// A 200 with `body` and its `took`.
pub(crate) fn ok(body: Value, started: Instant) -> Reply {
    reply(200, body, Some(started))
}

/// Pi-hole's error object, with `status`.
pub(super) fn error(status: u16, (key, message): Error, started: Instant) -> Reply {
    error_with(status, key, message, started)
}

/// Pi-hole's error object, with `status` and a message that is made as it is needed instead of
/// being one of the constants: the update receiver's, which say which of the eleven files.
pub(crate) fn error_with(status: u16, key: &str, message: &str, started: Instant) -> Reply {
    reply(
        status,
        json!({ "error": { "key": key, "message": message, "hint": null } }),
        Some(started),
    )
}

/// The session object of a valid session, a 200: `sid` is given only for a new one.
fn session_valid(
    sid: Option<String>,
    validity: u64,
    message: Option<&str>,
    started: Instant,
) -> Reply {
    reply(
        200,
        json!({ "session": {
            "valid": true,
            "totp": false,
            "sid": sid,
            "csrf": null,
            "validity": validity,
            "message": message,
        } }),
        Some(started),
    )
}

/// The session object of no session, with `status`.
fn session_refused(status: u16, message: Option<&str>, started: Instant) -> Reply {
    reply(
        status,
        json!({ "session": {
            "valid": false,
            "totp": false,
            "sid": null,
            "csrf": null,
            "validity": -1,
            "message": message,
        } }),
        Some(started),
    )
}

/// A reply of `status` with `body` as JSON text. An object gets `took`, the seconds since
/// `started`, when that is given.
fn reply(status: u16, mut body: Value, started: Option<Instant>) -> Reply {
    if let (Value::Object(fields), Some(started)) = (&mut body, started) {
        fields.insert("took".into(), json!(started.elapsed().as_secs_f64()));
    }
    // Writing a `Value` into a `Vec` cannot fail: its keys are strings, and a non-finite float is
    // already `null` in it.
    Reply {
        status,
        body: serde_json::to_vec(&body).unwrap_or_default(),
    }
}

#[cfg(test)]
#[expect(
    clippy::field_reassign_with_default,
    reason = "the plan's tests set the fake's fields one by one, as written"
)]
mod tests {
    use std::cell::Cell;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::Duration;

    use qb_dns::{Counts, HistoryBucket, LogEntry, Outcome};
    use serde_json::{Value, json};

    use super::*;
    use crate::api::http::{Reply, Request};
    use crate::api::password::PasswordHash;
    use crate::api::seams::{Client, MAX_QUERIES, ServerStats};
    use crate::update::UpdateCtl;

    const ME: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 7);

    /// What the fake records and changes, shared between its clones.
    #[derive(Default)]
    struct Shared {
        calls: Vec<String>,
        asked: Vec<usize>,
        paused: Option<u64>,
    }

    /// A `Facts` that answers from its public fields and records `pause_for`, `resume` and the
    /// `n` of every `recent`. Clones share what they record.
    #[derive(Clone, Default)]
    struct Fake {
        last_24h: Counts,
        history: Vec<HistoryBucket>,
        upstreams: Vec<ServerStats>,
        clients: (usize, usize),
        client_list: Vec<Client>,
        recent: Vec<LogEntry>,
        list: (Option<usize>, Option<u64>),
        shared: Arc<Mutex<Shared>>,
    }

    impl Fake {
        fn shared(&self) -> std::sync::MutexGuard<'_, Shared> {
            self.shared.lock().unwrap_or_else(PoisonError::into_inner)
        }
        /// The `pause_for` and `resume` calls, in order.
        fn calls(&self) -> Vec<String> {
            self.shared().calls.clone()
        }
        /// The `n` of every `recent` call, in order.
        fn asked(&self) -> Vec<usize> {
            self.shared().asked.clone()
        }
    }

    impl Facts for Fake {
        fn last_24h(&self) -> Counts {
            self.last_24h
        }
        fn history(&self) -> Vec<HistoryBucket> {
            self.history.clone()
        }
        fn upstreams(&self) -> Vec<ServerStats> {
            self.upstreams.clone()
        }
        fn clients(&self) -> (usize, usize) {
            self.clients
        }
        fn client_list(&self) -> Vec<Client> {
            self.client_list.clone()
        }
        fn recent(&self, n: usize) -> Vec<LogEntry> {
            self.shared().asked.push(n);
            self.recent.iter().take(n).cloned().collect()
        }
        fn list(&self) -> (Option<usize>, Option<u64>) {
            self.list
        }
        fn paused_left_secs(&self) -> Option<u64> {
            self.shared().paused
        }
        fn pause_for(&self, secs: u64) {
            let mut shared = self.shared();
            shared.paused = Some(secs);
            shared.calls.push(format!("pause {secs}"));
        }
        fn resume(&self) {
            let mut shared = self.shared();
            shared.paused = None;
            shared.calls.push("resume".into());
        }
    }

    thread_local! {
        /// The monotonic clock of the test running on this thread.
        static NOW: Cell<u64> = const { Cell::new(1_000) };
    }

    /// An `Api` over `fake`, the password `right`, this thread's test clock and sids that count
    /// up from `[1; 16]`.
    fn api(fake: Fake) -> Api {
        let next = AtomicU8::new(1);
        Api::new(
            PasswordHash::new(b"right", [0; 16]),
            Arc::new(fake),
            Arc::new(|| NOW.with(Cell::get)),
            Arc::new(move || Some([next.fetch_add(1, Ordering::Relaxed); 16])),
        )
    }

    /// Moves the clock of the test on this thread, which is the clock of every `Api` it made.
    fn advance(_api: &Api, secs: u64) {
        NOW.with(|now| now.set(now.get() + secs));
    }

    fn req(method: &str, target: &str, sid: Option<&str>, body: &[u8]) -> Request {
        Request {
            method: method.into(),
            target: target.into(),
            sid: sid.map(Into::into),
            body: body.to_vec(),
            close: false,
        }
    }

    /// The reply's body as JSON; `Null` if it is not JSON.
    fn json(reply: &Reply) -> Value {
        serde_json::from_slice(&reply.body).unwrap_or(Value::Null)
    }

    /// Logs in from `ME` and returns the sid.
    fn login(api: &Api) -> String {
        let reply = api.handle(
            &req("POST", "/api/auth", None, br#"{"password":"right"}"#),
            ME,
        );
        assert_eq!(reply.status, 200);
        json(&reply)["session"]["sid"].as_str().unwrap().to_owned()
    }

    #[test]
    fn the_right_password_opens_a_session_and_the_wrong_one_is_refused_in_pi_holes_shape() {
        let api = api(Fake::default());
        let ok = api.handle(
            &req("POST", "/api/auth", None, br#"{"password":"right"}"#),
            ME,
        );
        let v = json(&ok);
        assert_eq!(
            (
                ok.status,
                v["session"]["valid"].as_bool(),
                v["session"]["validity"].as_u64()
            ),
            (200, Some(true), Some(1_800))
        );
        assert!(
            v["session"]["sid"].as_str().unwrap().len() == 32
                && v["session"]["csrf"].is_null()
                && v["took"].is_number()
        );
        let no = api.handle(
            &req("POST", "/api/auth", None, br#"{"password":"wrong"}"#),
            ME,
        );
        assert_eq!(
            (
                no.status,
                json(&no)["session"]["valid"].as_bool(),
                json(&no)["session"]["sid"].is_null()
            ),
            (401, Some(false), true)
        );
        for body in [&b"{}"[..], b"not json", b"{\"password\":5}", b""] {
            assert_eq!(
                api.handle(&req("POST", "/api/auth", None, body), ME).status,
                400
            );
        }
    }

    #[test]
    fn after_five_failures_even_the_right_password_waits() {
        // Review Focus 1
        let api = api(Fake::default());
        for _ in 0..5 {
            api.handle(
                &req("POST", "/api/auth", None, br#"{"password":"wrong"}"#),
                ME,
            );
        }
        let held = api.handle(
            &req("POST", "/api/auth", None, br#"{"password":"right"}"#),
            ME,
        );
        assert_eq!(
            (held.status, json(&held)["error"]["key"].as_str()),
            (429, Some("rate_limiting"))
        );
        assert_eq!(
            api.handle(
                &req("POST", "/api/auth", None, br#"{"password":"right"}"#),
                Ipv4Addr::new(192, 0, 2, 8)
            )
            .status,
            200
        );
    }

    #[test]
    fn nothing_but_the_login_answers_without_a_session_and_nothing_changes_or_shows() {
        // Review Focus 3
        let mut fake = Fake::default();
        fake.recent = vec![LogEntry {
            unix_secs: 1,
            name: "secret.example.com".into(),
            qtype: 1,
            outcome: Outcome::Forwarded,
        }];
        fake.client_list = vec![Client {
            addr: Ipv4Addr::new(198, 51, 100, 4),
            queries: 3,
            last_seen_secs_ago: 1,
        }];
        let api = api(fake.clone());
        let pause = br#"{"blocking":false,"timer":300}"#;
        for (method, target, body) in [
            ("GET", "/api/stats/summary", &b""[..]),
            ("GET", "/api/history", b""),
            ("GET", "/api/stats/upstreams", b""),
            ("GET", "/api/dns/blocking", b""),
            ("POST", "/api/dns/blocking", pause),
            ("GET", "/api/auth", b""),
            ("DELETE", "/api/auth", b""),
            ("GET", "/api/v1/queries", b""),
            ("GET", "/api/v1/clients", b""),
            ("GET", "/api/nope", b""),
        ] {
            for sid in [None, Some("0".repeat(32))] {
                let r = api.handle(&req(method, target, sid.as_deref(), body), ME);
                let v = json(&r);
                // /api/auth answers in its session shape, everything else with the error object
                let refused = v["error"]["key"] == "unauthorized" || v["session"]["valid"] == false;
                let text = String::from_utf8_lossy(&r.body);
                assert!(
                    r.status == 401
                        && refused
                        && !text.contains("secret.example.com")
                        && !text.contains("198.51.100.4"),
                    "{method} {target}"
                );
            }
        }
        assert!(fake.calls().is_empty());
        let sid = login(&api);
        advance(&api, 1_800);
        assert_eq!(
            api.handle(&req("GET", "/api/dns/blocking", Some(&sid), b""), ME)
                .status,
            401
        ); // expired
    }

    #[test]
    fn a_session_can_be_checked_and_ended() {
        let api = api(Fake::default());
        let sid = login(&api);
        let r = api.handle(&req("GET", "/api/auth", Some(&sid), b""), ME);
        assert_eq!(
            (
                r.status,
                json(&r)["session"]["valid"].as_bool(),
                json(&r)["session"]["sid"].is_null()
            ),
            (200, Some(true), true)
        );
        assert_eq!(
            api.handle(&req("DELETE", "/api/auth", Some(&sid), b""), ME)
                .status,
            204
        );
        assert_eq!(
            api.handle(&req("GET", "/api/auth", Some(&sid), b""), ME)
                .status,
            401
        );
    }

    #[test]
    fn the_summary_is_of_the_last_24_hours() {
        let mut fake = Fake::default();
        fake.last_24h = Counts {
            queries: 200,
            blocked: 50,
            blocked_threat: 0,
            cache_hits: 30,
            forwarded: 100,
        };
        fake.clients = (3, 5);
        fake.list = (Some(302_176), Some(1_800_000_000));
        let api = api(fake);
        let v = json(&api.handle(
            &req("GET", "/api/stats/summary", Some(&login(&api)), b""),
            ME,
        ));
        let q = &v["queries"];
        assert_eq!(
            (
                q["total"].as_u64(),
                q["blocked"].as_u64(),
                q["percent_blocked"].as_f64()
            ),
            (Some(200), Some(50), Some(25.0))
        );
        assert_eq!(
            (q["forwarded"].as_u64(), q["cached"].as_u64()),
            (Some(100), Some(50))
        ); // 30 from the cache, 20 answered here
        assert!((q["frequency"].as_f64().unwrap() - 200.0 / 86_400.0).abs() < 1e-9);
        assert_eq!(
            (
                v["clients"]["active"].as_u64(),
                v["clients"]["total"].as_u64()
            ),
            (Some(3), Some(5))
        );
        assert_eq!(
            (
                v["gravity"]["domains_being_blocked"].as_u64(),
                v["gravity"]["last_update"].as_u64()
            ),
            (Some(302_176), Some(1_800_000_000))
        );
        assert!(v["took"].is_number());
        // with no queries percent_blocked is 0, and with nothing known gravity's two values are 0
        let api = self::api(Fake::default());
        let v = json(&api.handle(
            &req("GET", "/api/stats/summary", Some(&login(&api)), b""),
            ME,
        ));
        assert_eq!(
            (
                v["queries"]["total"].as_u64(),
                v["queries"]["percent_blocked"].as_f64(),
                v["queries"]["frequency"].as_f64()
            ),
            (Some(0), Some(0.0), Some(0.0))
        );
        assert_eq!(
            (
                v["gravity"]["domains_being_blocked"].as_u64(),
                v["gravity"]["last_update"].as_u64()
            ),
            (Some(0), Some(0))
        );
    }

    #[test]
    fn the_history_is_144_buckets_by_their_centres_oldest_first() {
        const T: u64 = 1_800_000_000;
        let mut fake = Fake::default();
        fake.history = (0..144)
            .map(|i| HistoryBucket {
                start_unix: T - (143 - i) * 600,
                counts: Counts::default(),
            })
            .collect();
        fake.history[143].counts = Counts {
            queries: 9,
            blocked: 2,
            blocked_threat: 0,
            cache_hits: 3,
            forwarded: 4,
        };
        let api = api(fake);
        let r = api.handle(&req("GET", "/api/history", Some(&login(&api)), b""), ME);
        let v = json(&r);
        let history = v["history"].as_array().unwrap();
        assert_eq!((r.status, history.len()), (200, 144));
        assert_eq!(
            history[0],
            json!({"timestamp": T - 143 * 600 + 300, "total": 0, "cached": 0, "blocked": 0, "forwarded": 0})
        );
        assert_eq!(
            history[143],
            json!({"timestamp": T + 300, "total": 9, "cached": 3, "blocked": 2, "forwarded": 4})
        );
        assert!(v["took"].is_number());
    }

    #[test]
    fn upstreams_come_after_the_blocklist_and_the_cache() {
        let mut fake = Fake::default();
        fake.last_24h = Counts {
            queries: 200,
            blocked: 50,
            blocked_threat: 0,
            cache_hits: 30,
            forwarded: 100,
        };
        fake.upstreams = vec![
            ServerStats {
                addr: SocketAddr::from(([9, 9, 9, 9], 53)),
                answered: 287,
                failed: 3,
                latency_ms: Some(8.0),
            },
            ServerStats {
                addr: SocketAddr::from(([149, 112, 112, 112], 53)),
                answered: 0,
                failed: 0,
                latency_ms: None,
            },
        ];
        let api = api(fake);
        let r = api.handle(
            &req("GET", "/api/stats/upstreams", Some(&login(&api)), b""),
            ME,
        );
        let v = json(&r);
        let up = v["upstreams"].as_array().unwrap();
        assert_eq!((r.status, up.len()), (200, 4));
        assert_eq!(
            up[0],
            json!({"ip":"blocklist","name":"blocklist","port":-1,"count":50,"statistics":{"response":0,"variance":0}})
        );
        assert_eq!(
            up[1],
            json!({"ip":"cache","name":"cache","port":-1,"count":50,"statistics":{"response":0,"variance":0}})
        );
        assert_eq!(
            (
                up[2]["ip"].as_str(),
                up[2]["name"].as_str(),
                up[2]["port"].as_u64(),
                up[2]["count"].as_u64()
            ),
            (Some("9.9.9.9"), Some("9.9.9.9"), Some(53), Some(287))
        );
        assert!((up[2]["statistics"]["response"].as_f64().unwrap() - 0.008).abs() < 1e-12);
        assert_eq!(up[2]["statistics"]["variance"].as_f64(), Some(0.0));
        assert_eq!(
            (
                up[3]["ip"].as_str(),
                up[3]["count"].as_u64(),
                up[3]["statistics"]["response"].as_f64()
            ),
            (Some("149.112.112.112"), Some(0), Some(0.0))
        );
        assert_eq!(
            (v["forwarded_queries"].as_u64(), v["total_queries"].as_u64()),
            (Some(100), Some(200))
        );
        assert!(v["took"].is_number());
    }

    #[test]
    fn the_households_queries_and_devices_come_with_a_session() {
        let entry = |unix_secs, name: &str, outcome| LogEntry {
            unix_secs,
            name: name.into(),
            qtype: 1,
            outcome,
        };
        let mut fake = Fake::default();
        fake.recent = vec![
            entry(30, "a.example.com", Outcome::Blocked),
            entry(20, "b.example.com", Outcome::Cached),
            entry(10, "c.example.com", Outcome::Forwarded),
        ];
        fake.client_list = vec![
            Client {
                addr: Ipv4Addr::new(198, 51, 100, 4),
                queries: 3,
                last_seen_secs_ago: 1,
            },
            Client {
                addr: Ipv4Addr::new(198, 51, 100, 5),
                queries: 1,
                last_seen_secs_ago: 40,
            },
        ];
        let api = api(fake.clone());
        let sid = login(&api);
        let get = |target: &str| api.handle(&req("GET", target, Some(&sid), b""), ME);

        let r = get("/api/v1/queries?n=2");
        let v = json(&r);
        assert_eq!(r.status, 200);
        assert_eq!(
            v,
            json!([
                {"unix_secs": 30, "name": "a.example.com", "qtype": 1, "outcome": "blocked"},
                {"unix_secs": 20, "name": "b.example.com", "qtype": 1, "outcome": "cached"},
            ])
        );
        assert_eq!(get("/api/v1/queries").status, 200);
        assert_eq!(get("/api/v1/queries?n=999999").status, 200);
        assert_eq!(
            get("/api/v1/queries?n=99999999999999999999999999").status,
            200
        );
        assert_eq!(fake.asked(), [2, 100, MAX_QUERIES, MAX_QUERIES]);
        for bad in [
            "n=0", "n=abc", "m=3", "n=", "n=-1", "n=+5", "n=2&n=3", "n=2&x=1", "", "n=2 ", "n=٣",
        ] {
            let r = get(&format!("/api/v1/queries?{bad}"));
            assert_eq!(
                (r.status, json(&r)["error"]["key"].as_str()),
                (400, Some("bad_request")),
                "{bad}"
            );
        }
        assert_eq!(fake.asked().len(), 4);

        let r = get("/api/v1/clients");
        assert_eq!(r.status, 200);
        assert_eq!(
            json(&r),
            json!([
                {"address": "198.51.100.4", "queries": 3, "last_seen_secs": 1},
                {"address": "198.51.100.5", "queries": 1, "last_seen_secs": 40},
            ])
        );
        assert_eq!(get("/api/v1/clients?x=1").status, 404);
    }

    #[test]
    fn blocking_pauses_with_a_timer_and_resumes() {
        let fake = Fake::default();
        let api = api(fake.clone());
        let sid = login(&api);
        let post =
            |body: &[u8]| api.handle(&req("POST", "/api/dns/blocking", Some(&sid), body), ME);
        let r = post(br#"{"blocking":false,"timer":299.5}"#);
        assert_eq!(
            (
                r.status,
                json(&r)["blocking"].as_str(),
                json(&r)["timer"].as_u64()
            ),
            (200, Some("disabled"), Some(300))
        );
        assert_eq!(fake.calls(), ["pause 300"]);
        let r = post(br#"{"blocking":true,"timer":null}"#);
        assert_eq!(
            (json(&r)["blocking"].as_str(), json(&r)["timer"].is_null()),
            (Some("enabled"), true)
        );
        assert_eq!(fake.calls(), ["pause 300", "resume"]);
    }

    #[test]
    fn bodies_that_are_not_a_pause_or_a_resume_change_nothing() {
        // Review Focus 5
        let fake = Fake::default();
        let api = api(fake.clone());
        let sid = login(&api);
        for (body, key) in [
            (&br#"{"blocking":"no"}"#[..], "body_error"),
            (b"{}", "body_error"),
            (b"nope", "bad_request"),
            (b"", "bad_request"),
            (br#"{"blocking":false}"#, "bad_request"),
            (br#"{"blocking":false,"timer":null}"#, "bad_request"),
            (br#"{"blocking":false,"timer":0}"#, "bad_request"),
            (br#"{"blocking":false,"timer":-5}"#, "bad_request"),
            (br#"{"blocking":false,"timer":86401}"#, "bad_request"),
            (br#"{"blocking":false,"timer":1e300}"#, "bad_request"),
        ] {
            let r = api.handle(&req("POST", "/api/dns/blocking", Some(&sid), body), ME);
            assert_eq!(
                (r.status, json(&r)["error"]["key"].as_str()),
                (400, Some(key)),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
        assert!(fake.calls().is_empty());
        assert_eq!(
            api.handle(
                &req(
                    "POST",
                    "/api/dns/blocking",
                    Some(&sid),
                    br#"{"blocking":true,"extra":1}"#
                ),
                ME
            )
            .status,
            200
        );
    }

    #[test]
    fn other_paths_and_methods() {
        let api = api(Fake::default());
        let sid = login(&api);
        let status = |m: &str, t: &str| api.handle(&req(m, t, Some(&sid), b""), ME).status;
        assert_eq!(
            [
                status("PUT", "/api/dns/blocking"),
                status("POST", "/api/v1/queries"),
                status("GET", "/api/domains/deny/exact"),
                status("GET", "/api/stats/summary?x=1"),
                status("GET", "/admin/"),
                status("GET", "/")
            ],
            [405, 405, 404, 404, 404, 404]
        );
    }

    // The tests below are this task's own, beyond the plan's.

    #[test]
    fn the_update_path_is_404_without_a_receiver_and_401_without_a_session_either_way() {
        let without = api(Fake::default());
        let sid = login(&without);
        let status = |api: &Api, m: &str, t: &str, sid: Option<&str>| {
            api.handle(&req(m, t, sid, b""), ME).status
        };
        let path = crate::update::receive::PATH;
        assert_eq!(status(&without, "POST", path, Some(&sid)), 404);
        assert_eq!(status(&without, "GET", path, Some(&sid)), 404);
        assert_eq!(status(&without, "POST", path, None), 401);

        let with = api(Fake::default()).with_update(Receiver::new(UpdateCtl::off(), 1));
        let sid = login(&with);
        assert_eq!(status(&with, "POST", path, None), 401);
        assert_eq!(status(&with, "GET", path, None), 401);
        assert_eq!(status(&with, "POST", path, Some("0000")), 401);
        // Another method on the path is 405, a query string is 404 whatever the method.
        for method in ["GET", "PUT", "DELETE"] {
            assert_eq!(status(&with, method, path, Some(&sid)), 405, "{method}");
        }
        assert_eq!(
            status(&with, "POST", &format!("{path}?x=1"), Some(&sid)),
            404
        );
        assert_eq!(
            status(&with, "GET", &format!("{path}?x=1"), Some(&sid)),
            404
        );
        // A POST that was read whole is not an update: the connection streams those, and says so.
        let reply = with.handle(&req("POST", path, Some(&sid), b"{}"), ME);
        assert_eq!(reply.status, 400);
        assert_eq!(json(&reply)["error"]["key"], "bad_request");
    }

    #[test]
    fn a_session_is_checked_for_the_connection_and_used_as_any_request_that_carries_it_is() {
        let api = api(Fake::default());
        let sid = login(&api);
        assert!(api.has_session(Some(&sid)));
        assert!(!api.has_session(None));
        assert!(!api.has_session(Some("0123")));
        assert!(!api.has_session(Some(&"0".repeat(32))));
        // It expires as any session does: 30 minutes after its last use, which the check counts.
        advance(&api, SESSION_SECS - 1);
        assert!(api.has_session(Some(&sid)));
        advance(&api, SESSION_SECS - 1);
        assert!(api.has_session(Some(&sid)), "the last check was a use");
        advance(&api, SESSION_SECS);
        assert!(!api.has_session(Some(&sid)));
        let reply = unauthorized();
        assert_eq!(reply.status, 401);
        assert_eq!(json(&reply)["error"]["key"], "unauthorized");
    }

    #[test]
    fn a_pause_shows_in_the_get_and_its_timer_is_whole_seconds_up_to_a_day() {
        let fake = Fake::default();
        let api = api(fake.clone());
        let sid = login(&api);
        let get = || json(&api.handle(&req("GET", "/api/dns/blocking", Some(&sid), b""), ME));
        let post =
            |body: &[u8]| api.handle(&req("POST", "/api/dns/blocking", Some(&sid), body), ME);
        let v = get();
        assert_eq!(
            (
                v["blocking"].as_str(),
                v["timer"].is_null(),
                v["took"].is_number()
            ),
            (Some("enabled"), true, true)
        );
        post(br#"{"blocking":false,"timer":299.5}"#);
        let v = get();
        assert_eq!(
            (v["blocking"].as_str(), v["timer"].as_u64()),
            (Some("disabled"), Some(300))
        );
        // a fraction of a second rounds up to one, the most is a day, and a timer on a resume is
        // ignored
        assert_eq!(
            json(&post(br#"{"blocking":false,"timer":0.2}"#))["timer"].as_u64(),
            Some(1)
        );
        post(br#"{"blocking":false,"timer":86400}"#);
        post(br#"{"blocking":true,"timer":5}"#);
        assert_eq!(
            fake.calls(),
            ["pause 300", "pause 1", "pause 86400", "resume"]
        );
        for (body, key) in [
            (&br#"{"blocking":false,"timer":"300"}"#[..], "bad_request"),
            (br#"{"blocking":false,"timer":86400.5}"#, "bad_request"),
            (br#"{"blocking":false,"timer":1e400}"#, "bad_request"),
            (br#"{"blocking":null}"#, "body_error"),
            (br#"[true]"#, "body_error"),
            (b"true", "body_error"),
            (b"\xff\xfe", "bad_request"),
        ] {
            let r = post(body);
            assert_eq!(
                (r.status, json(&r)["error"]["key"].as_str()),
                (400, Some(key)),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
        let r = post(br#"{"blocking":false,"timer":0}"#);
        assert_eq!(
            json(&r)["error"]["message"].as_str(),
            Some("a pause needs a timer of 1 to 86400 seconds")
        );
        let r = post(br#"{"blocking":1}"#);
        assert_eq!(
            json(&r)["error"]["message"].as_str(),
            Some("No \"blocking\" boolean in body data")
        );
        assert_eq!(fake.calls().len(), 4);
    }

    #[test]
    fn the_refusals_are_in_pi_holes_shapes() {
        let api = api(Fake::default());
        let shape = |m: &str, t: &str, sid: Option<&str>| {
            let r = api.handle(&req(m, t, sid, b""), ME);
            let mut v = json(&r);
            assert!(v["took"].is_number(), "{m} {t}");
            v.as_object_mut().unwrap().remove("took");
            (r.status, v)
        };
        let error = |key: &str, message: &str| json!({"error": {"key": key, "message": message, "hint": null}});
        assert_eq!(
            shape("GET", "/api/history", None),
            (401, error("unauthorized", "Unauthorized"))
        );
        assert_eq!(
            shape("GET", "/api/auth", None),
            (
                401,
                json!({"session": {"valid": false, "totp": false, "sid": null, "csrf": null, "validity": -1, "message": null}})
            )
        );
        assert_eq!(
            shape("GET", "/", None),
            (404, error("not_found", "Not found"))
        );
        assert_eq!(
            shape("GET", "/api", None),
            (404, error("not_found", "Not found"))
        );
        let sid = login(&api);
        assert_eq!(
            shape("PATCH", "/api/auth", Some(&sid)),
            (405, error("method_not_allowed", "Method not allowed"))
        );
        assert_eq!(
            shape("GET", "/api/config", Some(&sid)),
            (404, error("not_found", "Not found"))
        );
        let ok = api.handle(
            &req(
                "POST",
                "/api/auth",
                None,
                br#"{"password":"right","totp":123456}"#,
            ),
            ME,
        );
        let mut v = json(&ok);
        let sid = v["session"]["sid"].take();
        assert_eq!(sid.as_str().map(str::len), Some(32));
        v.as_object_mut().unwrap().remove("took");
        assert_eq!(
            (ok.status, v),
            (
                200,
                json!({"session": {"valid": true, "totp": false, "sid": null, "csrf": null, "validity": 1800, "message": "password correct"}})
            )
        );
        let no = api.handle(
            &req("POST", "/api/auth", None, br#"{"password":"wrong"}"#),
            ME,
        );
        let mut v = json(&no);
        v.as_object_mut().unwrap().remove("took");
        assert_eq!(
            (no.status, v),
            (
                401,
                json!({"session": {"valid": false, "totp": false, "sid": null, "csrf": null, "validity": -1, "message": "password incorrect"}})
            )
        );
        let bad = api.handle(&req("POST", "/api/auth", None, b"{"), ME);
        let mut v = json(&bad);
        v.as_object_mut().unwrap().remove("took");
        assert_eq!(
            (bad.status, v),
            (
                400,
                error("bad_request", "Invalid request body data (no valid JSON)")
            )
        );
        let delete = api.handle(&req("DELETE", "/api/auth", Some(&login(&api)), b""), ME);
        assert_eq!((delete.status, delete.body.is_empty()), (204, true));
    }

    #[test]
    fn a_sid_anywhere_but_its_header_or_one_character_off_is_no_session() {
        // Review Focus 3
        let fake = Fake::default();
        let api = api(fake.clone());
        let sid = login(&api);
        let pause = br#"{"blocking":false,"timer":300}"#;
        let r = api.handle(
            &req("POST", &format!("/api/dns/blocking?sid={sid}"), None, pause),
            ME,
        );
        assert_eq!(r.status, 401);
        let mut off = sid.clone().into_bytes();
        off[31] = if off[31] == b'0' { b'1' } else { b'0' };
        let off = String::from_utf8(off).unwrap();
        assert_eq!(
            api.handle(&req("POST", "/api/dns/blocking", Some(&off), pause), ME)
                .status,
            401
        );
        assert_eq!(
            api.handle(
                &req("POST", "/api/dns/blocking", Some(&format!("{sid}0")), pause),
                ME
            )
            .status,
            401
        );
        assert!(fake.calls().is_empty());
        assert_eq!(
            api.handle(&req("POST", "/api/dns/blocking", Some(&sid), pause), ME)
                .status,
            200
        );
    }

    #[test]
    fn a_login_with_a_query_string_or_a_body_that_is_not_utf_8_is_no_login() {
        let api = api(Fake::default());
        let right = br#"{"password":"right"}"#;
        let r = api.handle(&req("POST", "/api/auth?x=1", None, right), ME);
        assert_eq!(
            (
                r.status,
                json(&r)["session"]["valid"].as_bool(),
                json(&r)["session"]["sid"].is_null()
            ),
            (401, Some(false), true)
        );
        let sid = login(&api);
        assert_eq!(
            api.handle(&req("POST", "/api/auth?x=1", Some(&sid), right), ME)
                .status,
            404
        );
        assert_eq!(api.sessions.lock().unwrap().len(), 1);
        let r = api.handle(
            &req("POST", "/api/auth", None, b"{\"password\":\"r\xffght\"}"),
            ME,
        );
        assert_eq!(
            (r.status, json(&r)["error"]["key"].as_str()),
            (400, Some("bad_request"))
        );
        let r = api.handle(&req("POST", "/api/auth", None, b"\xff\xfe"), ME);
        assert_eq!(r.status, 400);
        // a body of the wrong shape is no failed login
        for _ in 0..10 {
            api.handle(&req("POST", "/api/auth", None, br#"{"password":null}"#), ME);
        }
        assert!(api.limiter.lock().unwrap().allowed(ME, NOW.with(Cell::get)));
    }

    #[test]
    fn a_post_to_the_login_is_checked_as_a_password_even_with_a_valid_session() {
        let api = api(Fake::default());
        let sid = login(&api);
        let post = |body: &[u8]| api.handle(&req("POST", "/api/auth", Some(&sid), body), ME);
        // A wrong password is a failed login, not a read of the session that came with it.
        let r = post(br#"{"password":"wrong"}"#);
        assert_eq!(
            (
                r.status,
                json(&r)["session"]["valid"].as_bool(),
                json(&r)["session"]["message"].as_str()
            ),
            (401, Some(false), Some("password incorrect"))
        );
        // No password is a bad request, where a session read would be a 200.
        assert_eq!(post(b"").status, 400);
        // The right password opens a session of its own, not the one it came with.
        let r = post(br#"{"password":"right"}"#);
        let new = json(&r)["session"]["sid"].as_str().map(str::to_owned);
        assert!(r.status == 200 && new.as_deref().is_some_and(|new| new != sid));
        // And it counts as a login: the right one forgot the failure before it, and five wrong
        // ones in a minute hold the address back.
        for _ in 0..5 {
            post(br#"{"password":"wrong"}"#);
        }
        let r = post(br#"{"password":"right"}"#);
        assert_eq!(
            (r.status, json(&r)["error"]["key"].as_str()),
            (429, Some("rate_limiting"))
        );
    }

    #[test]
    fn a_login_whose_session_id_cannot_be_made_is_a_500_and_opens_no_session() {
        // Ruling R22: the random source can fail, and then there is no sid, not a guessable one.
        let api = Api::new(
            PasswordHash::new(b"right", [0; 16]),
            Arc::new(Fake::default()),
            Arc::new(|| NOW.with(Cell::get)),
            Arc::new(|| None),
        );
        let now = NOW.with(Cell::get);
        for _ in 0..4 {
            api.limiter.lock().unwrap().failed(ME, now);
        }
        let r = api.handle(
            &req("POST", "/api/auth", None, br#"{"password":"right"}"#),
            ME,
        );
        let v = json(&r);
        assert_eq!(r.status, 500);
        assert_eq!(
            v["error"],
            json!({ "key": "internal", "message": "no random source", "hint": null })
        );
        assert!(v["took"].is_number() && v.get("session").is_none());
        // No session is open, so no sid, not even the one that a zeroed buffer would give, is
        // usable.
        assert!(api.sessions.lock().unwrap().is_empty());
        for sid in ["0".repeat(32), "00".repeat(16)] {
            let r = api.handle(&req("GET", "/api/auth", Some(&sid), b""), ME);
            assert_eq!(r.status, 401, "{sid}");
        }
        // The password was right, so it still counts as a success: the four failures before it
        // are forgotten, and the next one is the first.
        assert_eq!(api.limiter.lock().unwrap().failed(ME, now), HoldBack::None);
    }

    #[test]
    fn a_guess_waiting_to_be_verified_meets_the_hold_back_that_began_meanwhile() {
        // Review Focus 1, ruling R8: the hold-back is checked again once the verification lock is
        // taken, so the right password from a held address is not checked even then.
        let reads = Arc::new(AtomicUsize::new(0));
        let clock = Arc::clone(&reads);
        let api = Arc::new(Api::new(
            PasswordHash::new(b"right", [0; 16]),
            Arc::new(Fake::default()),
            Arc::new(move || {
                clock.fetch_add(1, Ordering::SeqCst);
                1_000
            }),
            Arc::new(|| Some([7; 16])),
        ));
        let verifying = api.verifying.lock().unwrap();
        let guess = std::thread::spawn({
            let api = Arc::clone(&api);
            move || {
                api.handle(
                    &req("POST", "/api/auth", None, br#"{"password":"right"}"#),
                    ME,
                )
            }
        });
        while reads.load(Ordering::SeqCst) == 0 {
            std::thread::yield_now();
        }
        // let the guess pass its first check and queue on the lock
        std::thread::sleep(Duration::from_millis(100));
        {
            let mut limiter = api.limiter.lock().unwrap();
            for _ in 0..5 {
                limiter.failed(ME, 1_000);
            }
        }
        drop(verifying);
        let reply = guess.join().unwrap();
        assert_eq!(
            (reply.status, json(&reply)["error"]["key"].as_str()),
            (429, Some("rate_limiting"))
        );
        assert!(api.sessions.lock().unwrap().is_empty());
    }

    #[test]
    fn no_request_makes_it_panic() {
        let api = api(Fake::default());
        let sid = login(&api);
        let targets = [
            "",
            "?",
            "/",
            "/api",
            "/api/",
            "/api/?",
            "/api/auth?",
            "/api/v1/queries?",
            "/api/v1/queries??n=1",
            "/api/v1/queries?n=1?",
            "/api/v1/queries?n=1=2",
            "/api/é?n=é",
            "*",
            "/api/stats/summary/",
            "//api/history",
            "/API/history",
        ];
        let bodies = [
            &b""[..],
            b"\0",
            b"\xff",
            b"{",
            b"null",
            b"[]",
            br#"{"blocking":false,"timer":1e400}"#,
        ];
        for method in ["GET", "POST", "DELETE", "PUT", "", "get", "\u{1F600}"] {
            for target in targets {
                for body in bodies {
                    for sid in [None, Some(sid.as_str()), Some(""), Some("é")] {
                        let r = api.handle(&req(method, target, sid, body), ME);
                        let v = json(&r);
                        assert!(
                            r.status == 204 && r.body.is_empty() || v.is_object() || v.is_array(),
                            "{method} {target}"
                        );
                    }
                }
            }
        }
    }
}
