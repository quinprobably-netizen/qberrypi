//! `cargo xtask probe`: asks a running Pi's DNS and status servers what a client would, and
//! judges which of a milestone's checks hold.
//!
//! Plain std sockets and no runtime: the probe asks one question at a time and waits for it.
//! Nothing here prints the Pi's address.

use std::cell::RefCell;
use std::fs;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::path::Path;
use std::sync::atomic::{AtomicU16, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use qberrypi::dns::DNS_PORT;
use qberrypi::dns::client::{Answer, query, read_answer};
use qberrypi::lists::snapshot::MARKER;
use qberrypi::status;
use serde_json::Value;

/// The record types A and AAAA.
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
/// How often the first query is repeated while the Pi is not answering, and how long each waits.
const WAKE_EVERY: Duration = Duration::from_secs(2);
const WAKE_WAIT: Duration = Duration::from_secs(1);
/// How long one question of the checks, or one read of the statistics, may take.
const ASK_WAIT: Duration = Duration::from_secs(5);
/// How many times the second name is asked again, and so how many cache hits the Pi must count.
const REPEATS: usize = 5;
/// How long to wait for the Pi to say its clock is set, polling once a second.
const CLOCK_WAIT: Duration = Duration::from_secs(30);
/// The most the probe reads of an HTTP answer; the statistics are under a kilobyte.
const MAX_HTTP: usize = 64 * 1024;
/// How far the Pi's clock may be from this machine's, in seconds.
const CLOCK_SLACK_SECS: u64 = 5;
/// How long the blocker stage waits for the Pi to refresh its lists over HTTPS, once the
/// resolver's questions are asked: the clock is set by SNTP first, then each list is fetched.
pub const REFRESH_WAIT_SECS: u64 = 150;
/// How often the statistics are read while that wait lasts.
const REFRESH_POLL: Duration = Duration::from_secs(5);
/// The TTL of a blocked answer, which the snapshot's marker must come back with.
const BLOCKED_TTL: u32 = 2;
/// How many queries the Pi counts as blocked before the refresh: the marker, a listed name's A and
/// its AAAA.
const BLOCKED_BEFORE_REFRESH: u64 = 3;

/// Which half of the milestone's checks to run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Stage {
    /// The resolver: forwarding, the cache, TCP, single-label names, the clock.
    Resolver,
    /// The blocker, after the resolver: the snapshot blocks before any refresh, then the lists are
    /// refreshed over HTTPS and a listed name stays blocked. Start it with the deploy.
    Blocker,
}

/// One check: what it is about, whether it holds, and what was found.
#[derive(Debug, PartialEq, Eq)]
pub struct Check {
    pub what: &'static str,
    pub ok: bool,
    pub found: String,
}

/// An answer and how long it took to come back.
#[derive(Debug, Clone)]
pub struct Timed {
    pub answer: Answer,
    pub took: Duration,
}

/// What a probe of the resolver stage saw; a part that could not be seen is `None` or empty.
#[derive(Debug, Default)]
pub struct ResolverSeen {
    /// example.com, the first good answer, or the last answer seen when the wait ended with none
    /// good.
    pub forwarded: Option<Timed>,
    /// example.org, asked once.
    pub first: Option<Timed>,
    /// example.org, five more times.
    pub repeats: Vec<Timed>,
    /// example.net over TCP.
    pub tcp: Option<Timed>,
    /// printer.
    pub local: Option<Timed>,
    /// `/api/v1/stats` before `first`.
    pub before: Option<Value>,
    /// `/api/v1/stats` once `clock_set` is true, or after 30 s of waiting for that.
    pub after: Option<Value>,
    /// This machine's clock when `after` was read.
    pub pc_unix_secs: u64,
}

/// What a probe of the blocker stage saw, besides the resolver's; a part that could not be seen is
/// `None`.
#[derive(Debug, Default)]
pub struct BlockerSeen {
    /// `/api/v1/stats` as soon as the Pi answered.
    pub at_first: Option<Value>,
    /// The snapshot's marker, A, as soon as the Pi answered.
    pub marker_at_first: Option<Timed>,
    /// The listed name, A.
    pub listed_a: Option<Timed>,
    /// The listed name, AAAA.
    pub listed_aaaa: Option<Timed>,
    /// `/api/v1/stats` once `list_source` is "fetched"; `None` if that never came.
    pub refreshed: Option<Value>,
    /// The snapshot's marker, A, after the refresh.
    pub marker_after: Option<Timed>,
    /// The listed name, A, after the refresh.
    pub listed_after: Option<Timed>,
}

fn verdict(what: &'static str, found: Result<String, String>) -> Check {
    match found {
        Ok(found) => Check {
            what,
            ok: true,
            found,
        },
        Err(found) => Check {
            what,
            ok: false,
            found,
        },
    }
}

/// An answer that is NOERROR with at least one address, as a verdict.
fn with_address(seen: Option<&Timed>, missing: &str) -> Result<String, String> {
    let Some(timed) = seen else {
        return Err(missing.to_owned());
    };
    let answer = &timed.answer;
    if answer.rcode != 0 {
        Err(format!("the answer was {}", answer.summary()))
    } else if answer.addrs.is_empty() {
        Err("the answer held no address".to_owned())
    } else {
        Ok(answer.summary())
    }
}

/// A number from the statistics read before or after the queries.
fn counter(stats: Option<&Value>, when: &str, key: &str) -> Result<u64, String> {
    let stats = stats.ok_or_else(|| format!("no statistics were read {when} the queries"))?;
    stats
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{key} is missing from the statistics read {when} the queries"))
}

fn cache_hits(seen: &ResolverSeen) -> Result<String, String> {
    let before = counter(seen.before.as_ref(), "before", "cache_hits_total")?;
    let after = counter(seen.after.as_ref(), "after", "cache_hits_total")?;
    let Some(hits) = after.checked_sub(before) else {
        return Err(format!("the counter went from {before} down to {after}"));
    };
    if hits >= REPEATS as u64 {
        Ok(format!("{hits} more cache hits"))
    } else {
        Err(format!("{hits} more cache hits, {REPEATS} wanted"))
    }
}

fn repeat_is_faster(seen: &ResolverSeen) -> Result<String, String> {
    let first = seen
        .first
        .as_ref()
        .ok_or("the first query was not answered")?;
    let times: Vec<Duration> = seen.repeats.iter().map(|r| r.took).collect();
    let median = median(&times).ok_or("no repeat was answered")?;
    if median < first.took {
        Ok(format!("median {median:?} against {:?}", first.took))
    } else {
        Err(format!(
            "median {median:?} is not under the first answer's {:?}",
            first.took
        ))
    }
}

fn ttl_has_not_grown(seen: &ResolverSeen) -> Result<String, String> {
    let first = seen
        .first
        .as_ref()
        .ok_or("the first query was not answered")?;
    let limit = first
        .answer
        .min_ttl
        .ok_or("the first answer carried no TTL")?;
    if seen.repeats.is_empty() {
        return Err("no repeat was answered".to_owned());
    }
    for repeat in &seen.repeats {
        match repeat.answer.min_ttl {
            None => return Err("a repeat carried no TTL".to_owned()),
            Some(ttl) if ttl > limit => {
                return Err(format!("a repeat's TTL {ttl} is above the first's {limit}"));
            }
            Some(_) => {}
        }
    }
    Ok(format!("no repeat's TTL is above {limit}"))
}

fn single_label(seen: &ResolverSeen) -> Result<String, String> {
    let timed = seen
        .local
        .as_ref()
        .ok_or("the single-label name was not answered")?;
    if timed.answer.rcode == 3 {
        Ok(timed.answer.summary())
    } else {
        Err(format!("the answer was {}", timed.answer.summary()))
    }
}

fn clock_is_set(seen: &ResolverSeen) -> Result<String, String> {
    let after = seen
        .after
        .as_ref()
        .ok_or("no statistics were read after the queries")?;
    match after.get("clock_set").and_then(Value::as_bool) {
        Some(true) => {}
        Some(false) => return Err("clock_set is false".to_owned()),
        None => return Err("clock_set is missing from the statistics".to_owned()),
    }
    let unix = after
        .get("unix_secs")
        .and_then(Value::as_u64)
        .ok_or("unix_secs is missing from the statistics")?;
    let off = unix.abs_diff(seen.pc_unix_secs);
    if off <= CLOCK_SLACK_SECS {
        Ok(format!("{off} s from this machine's clock"))
    } else {
        Err(format!("{off} s from this machine's clock"))
    }
}

fn latency_is_known(seen: &ResolverSeen) -> Result<String, String> {
    let after = seen
        .after
        .as_ref()
        .ok_or("no statistics were read after the queries")?;
    match after.get("upstream_ms") {
        Some(ms) if ms.is_number() => Ok(format!("{ms} ms")),
        Some(_) => Err("upstream_ms is not a number yet".to_owned()),
        None => Err("upstream_ms is missing from the statistics".to_owned()),
    }
}

/// The resolver stage's eight checks, in order, each judged on its own evidence.
pub fn judge_resolver(seen: &ResolverSeen) -> Vec<Check> {
    vec![
        verdict(
            "a forwarded name is answered",
            with_address(seen.forwarded.as_ref(), "no answer was seen"),
        ),
        verdict("a repeat is answered from the cache", cache_hits(seen)),
        verdict("a cached repeat is faster", repeat_is_faster(seen)),
        verdict("a repeat's TTL has not grown", ttl_has_not_grown(seen)),
        verdict(
            "a query over TCP is answered",
            with_address(seen.tcp.as_ref(), "no answer was seen"),
        ),
        verdict(
            "a single-label name is answered by the Pi",
            single_label(seen),
        ),
        verdict("the clock is set", clock_is_set(seen)),
        verdict("the upstream latency is known", latency_is_known(seen)),
    ]
}

const UNSPECIFIED_V4: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
const UNSPECIFIED_V6: IpAddr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);

/// An answer that is NOERROR and carries `blocked` and nothing else, as a verdict.
fn blocked_with(seen: Option<&Timed>, blocked: IpAddr, missing: &str) -> Result<String, String> {
    let answer = &seen.ok_or_else(|| missing.to_owned())?.answer;
    if answer.rcode == 0 && !answer.addrs.is_empty() && answer.addrs.iter().all(|a| *a == blocked) {
        Ok(answer.summary())
    } else {
        Err(format!("the answer was {}", answer.summary()))
    }
}

/// A word of the statistics, which a Pi with a different build may not have.
fn stat_str<'a>(stats: &'a Value, key: &str) -> Result<&'a str, String> {
    stats
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{key} is missing from the statistics"))
}

/// A number of the statistics.
fn stat_u64(stats: &Value, key: &str) -> Result<u64, String> {
    stats
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{key} is missing from the statistics"))
}

fn snapshot_is_in_force(seen: &BlockerSeen) -> Result<String, String> {
    let stats = seen
        .at_first
        .as_ref()
        .ok_or("no statistics were read when the Pi first answered")?;
    match stat_str(stats, "list_source")? {
        "snapshot" => {}
        "fetched" => {
            return Err(
                "the lists were refreshed before the probe arrived; start it with the deploy"
                    .to_owned(),
            );
        }
        other => return Err(format!("list_source is {other}, snapshot wanted")),
    }
    match stat_u64(stats, "list_names")? {
        0 => Err("list_names is 0".to_owned()),
        names => Ok(format!("{names} names")),
    }
}

fn marker_is_blocked(seen: &BlockerSeen) -> Result<String, String> {
    let found = blocked_with(
        seen.marker_at_first.as_ref(),
        UNSPECIFIED_V4,
        "the marker was not answered",
    )?;
    match seen.marker_at_first.as_ref().and_then(|t| t.answer.min_ttl) {
        Some(BLOCKED_TTL) => Ok(format!("{found}, TTL {BLOCKED_TTL}")),
        Some(ttl) => Err(format!("{found} with TTL {ttl}, {BLOCKED_TTL} wanted")),
        None => Err(format!("{found} without a TTL")),
    }
}

fn lists_are_refreshed(seen: &BlockerSeen) -> Result<String, String> {
    let stats = seen
        .refreshed
        .as_ref()
        .ok_or("list_source did not become fetched within the wait")?;
    match stat_str(stats, "list_source")? {
        "fetched" => {}
        other => return Err(format!("list_source is {other}, fetched wanted")),
    }
    match stats.get("list_error") {
        Some(Value::Null) => {}
        Some(error) => return Err(format!("list_error is {error}")),
        None => return Err("list_error is missing from the statistics".to_owned()),
    }
    match stat_u64(stats, "list_names")? {
        0 => Err("list_names is 0".to_owned()),
        names => Ok(format!("{names} names")),
    }
}

fn marker_is_gone_and_the_listed_name_is_not(seen: &BlockerSeen) -> Result<String, String> {
    let marker = seen
        .marker_after
        .as_ref()
        .ok_or("the marker was not answered after the refresh")?;
    if marker.answer.addrs.contains(&UNSPECIFIED_V4) {
        return Err(format!(
            "the marker is still blocked: {}",
            marker.answer.summary()
        ));
    }
    let listed = blocked_with(
        seen.listed_after.as_ref(),
        UNSPECIFIED_V4,
        "the listed name was not answered after the refresh",
    )
    .map_err(|why| format!("the listed name is no longer blocked: {why}"))?;
    Ok(format!(
        "the marker got {}, the listed name {listed}",
        marker.answer.summary()
    ))
}

fn blocked_queries_are_counted(seen: &BlockerSeen) -> Result<String, String> {
    let stats = seen
        .refreshed
        .as_ref()
        .ok_or("no statistics were read once the lists were refreshed")?;
    match stat_u64(stats, "blocked_total")? {
        n if n >= BLOCKED_BEFORE_REFRESH => Ok(format!("{n} blocked")),
        n => Err(format!("{n} blocked, {BLOCKED_BEFORE_REFRESH} wanted")),
    }
}

/// The blocker stage's seven checks, in order, each judged on its own evidence.
pub fn judge_blocker(seen: &BlockerSeen) -> Vec<Check> {
    vec![
        verdict(
            "the snapshot is in force before any refresh",
            snapshot_is_in_force(seen),
        ),
        verdict("the snapshot's marker is blocked", marker_is_blocked(seen)),
        verdict(
            "a listed name gets 0.0.0.0",
            blocked_with(
                seen.listed_a.as_ref(),
                UNSPECIFIED_V4,
                "the listed name was not answered",
            ),
        ),
        verdict(
            "a listed name gets :: for AAAA",
            blocked_with(
                seen.listed_aaaa.as_ref(),
                UNSPECIFIED_V6,
                "the listed name was not answered for AAAA",
            ),
        ),
        verdict(
            "the lists are refreshed over HTTPS",
            lists_are_refreshed(seen),
        ),
        verdict(
            "after the refresh the marker is gone and the listed name is still blocked",
            marker_is_gone_and_the_listed_name_is_not(seen),
        ),
        verdict(
            "blocked queries are counted",
            blocked_queries_are_counted(seen),
        ),
    ]
}

/// The blocker stage's fifteen checks: the resolver's eight, then the blocker's seven.
pub fn judge_blocker_stage(resolver: &ResolverSeen, blocker: &BlockerSeen) -> Vec<Check> {
    let mut checks = judge_resolver(resolver);
    checks.extend(judge_blocker(blocker));
    checks
}

/// The middle time of `times`; the upper one of the two in the middle for an even count.
pub fn median(times: &[Duration]) -> Option<Duration> {
    let mut sorted = times.to_vec();
    sorted.sort();
    sorted.get(sorted.len() / 2).copied()
}

/// A line for each check and a count; and whether every check holds.
pub fn report(checks: &[Check]) -> (String, bool) {
    let mut text = String::new();
    for check in checks {
        if check.ok {
            text.push_str(&format!("probe: ok: {}\n", check.what));
        } else {
            text.push_str(&format!("probe: FAILED: {}: {}\n", check.what, check.found));
        }
    }
    let holding = checks.iter().filter(|c| c.ok).count();
    text.push_str(&format!(
        "probe: {holding} of {} checks hold\n",
        checks.len()
    ));
    (text, holding == checks.len())
}

fn timed_out() -> io::Error {
    io::Error::new(ErrorKind::TimedOut, "no answer within the wait")
}

/// The time left until `deadline`; a timeout error once none is.
pub(crate) fn time_left(deadline: Instant) -> io::Result<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        Err(timed_out())
    } else {
        Ok(left)
    }
}

/// One read that gives up at `deadline`, however slowly the other side sends.
fn read_by(stream: &mut TcpStream, buf: &mut [u8], deadline: Instant) -> io::Result<usize> {
    loop {
        stream.set_read_timeout(Some(time_left(deadline)?))?;
        match stream.read(buf) {
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Err(timed_out());
            }
            other => return other,
        }
    }
}

fn read_exact_by(stream: &mut TcpStream, mut buf: &mut [u8], deadline: Instant) -> io::Result<()> {
    while !buf.is_empty() {
        match read_by(stream, buf, deadline)? {
            0 => return Err(ErrorKind::UnexpectedEof.into()),
            n => buf = &mut buf[n..],
        }
    }
    Ok(())
}

/// A query ID that differs from one question to the next.
pub(crate) fn next_id() -> u16 {
    static COUNTER: AtomicU16 = AtomicU16::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.subsec_nanos());
    let seed = u16::try_from(nanos & 0xffff).unwrap_or(0);
    seed ^ COUNTER.fetch_add(0x9e37, Ordering::Relaxed)
}

/// Asks `server` over UDP and waits up to `wait` for the answer to this query; datagrams that
/// are not that answer are ignored.
pub fn ask_udp(server: SocketAddr, name: &str, qtype: u16, wait: Duration) -> io::Result<Timed> {
    let id = next_id();
    let packet = query(id, name, qtype)?;
    // Connected, so that only the server's own datagrams arrive, and a refusal is an error.
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.connect(server)?;
    let started = Instant::now();
    let deadline = started + wait;
    socket.send(&packet)?;
    let mut buf = [0u8; 4096];
    loop {
        socket.set_read_timeout(Some(time_left(deadline)?))?;
        match socket.recv(&mut buf) {
            Ok(n) => {
                if let Some(answer) = read_answer(&buf[..n], id) {
                    return Ok(Timed {
                        answer,
                        took: started.elapsed(),
                    });
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Err(timed_out());
            }
            Err(e) => return Err(e),
        }
    }
}

/// Asks `server` over TCP, connecting included in the time and in the wait.
pub fn ask_tcp(server: SocketAddr, name: &str, qtype: u16, wait: Duration) -> io::Result<Timed> {
    let id = next_id();
    let packet = query(id, name, qtype)?;
    let length = u16::try_from(packet.len())
        .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "the query is too long"))?;
    let started = Instant::now();
    let deadline = started + wait;
    let mut stream = TcpStream::connect_timeout(&server, wait)?;
    let mut framed = length.to_be_bytes().to_vec();
    framed.extend_from_slice(&packet);
    stream.set_write_timeout(Some(time_left(deadline)?))?;
    stream.write_all(&framed)?;
    let mut prefix = [0u8; 2];
    read_exact_by(&mut stream, &mut prefix, deadline)?;
    let mut reply = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
    read_exact_by(&mut stream, &mut reply, deadline)?;
    let answer = read_answer(&reply, id).ok_or_else(|| {
        io::Error::new(
            ErrorKind::InvalidData,
            "the reply is not the answer to the query",
        )
    })?;
    Ok(Timed {
        answer,
        took: started.elapsed(),
    })
}

/// The position just past the first blank line of `bytes`, if there is one.
fn head_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| at + 4)
}

/// The value of the `Content-Length` header in `head`, if it has one.
fn content_length(head: &str) -> Option<usize> {
    head.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case("content-length") {
            value.trim().parse().ok()
        } else {
            None
        }
    })
}

/// Reads `GET /api/v1/stats` from the status server at `status`, all within `wait`.
pub fn get_stats(status: SocketAddr, wait: Duration) -> Result<Value> {
    let deadline = Instant::now() + wait;
    let mut stream =
        TcpStream::connect_timeout(&status, wait).context("cannot connect to the status server")?;
    stream
        .set_write_timeout(Some(time_left(deadline)?))
        .context("cannot send to the status server")?;
    write!(
        stream,
        "GET /api/v1/stats HTTP/1.1\r\nHost: {status}\r\nConnection: close\r\n\r\n"
    )
    .context("cannot send to the status server")?;

    let mut response = Vec::new();
    let mut chunk = [0u8; 4096];
    let (head_len, body_len) = loop {
        if let Some(end) = head_end(&response) {
            let head = std::str::from_utf8(&response[..end])
                .context("the status server's headers are not text")?;
            let status_line = head.lines().next().unwrap_or_default();
            let mut parts = status_line.split(' ');
            if !parts.next().is_some_and(|v| v.starts_with("HTTP/1."))
                || parts.next() != Some("200")
            {
                bail!("the status server did not answer 200: {status_line:?}");
            }
            break (end, content_length(head));
        }
        if response.len() > MAX_HTTP {
            bail!("the status server's headers are too long");
        }
        let n = read_by(&mut stream, &mut chunk, deadline)
            .context("cannot read the status server's answer")?;
        if n == 0 {
            bail!("the status server closed the connection inside its headers");
        }
        response.extend_from_slice(&chunk[..n]);
    };
    if body_len.is_some_and(|len| len > MAX_HTTP) {
        bail!("the status server's answer is too long");
    }
    // With a length, the body ends there, whether or not the connection closes; without one, at
    // the end of the connection.
    let end = loop {
        if let Some(len) = body_len
            && response.len() >= head_len + len
        {
            break head_len + len;
        }
        if response.len() > head_len + MAX_HTTP {
            bail!("the status server's answer is too long");
        }
        let n = read_by(&mut stream, &mut chunk, deadline)
            .context("cannot read the status server's answer")?;
        if n == 0 {
            if body_len.is_some() {
                bail!("the status server closed the connection inside its body");
            }
            break response.len();
        }
        response.extend_from_slice(&chunk[..n]);
    };
    serde_json::from_slice(&response[head_len..end])
        .context("the status server's answer is not JSON")
}

/// The Pi's address: the one that was asked for, or `net.address` of `<root>/qberrypi.toml`.
fn server_address(server: Option<Ipv4Addr>, root: &Path) -> Result<Ipv4Addr> {
    if let Some(address) = server {
        return Ok(address);
    }
    configured_address(root, "--server <ipv4>")
}

/// `net.address` of `<root>/qberrypi.toml`; when the file cannot be read, the error says to give
/// the address with `flag` instead.
pub(crate) fn configured_address(root: &Path, flag: &str) -> Result<Ipv4Addr> {
    let path = root.join("qberrypi.toml");
    let text = fs::read_to_string(&path).with_context(|| {
        format!(
            "cannot read {}; give the Pi's address with {flag}",
            path.display()
        )
    })?;
    Ok(qberrypi::config::parse(&text)?.net.address.addr)
}

/// Prints why `what` failed, and turns the failure into "not seen".
fn noted<T, E: std::fmt::Display>(what: &str, result: Result<T, E>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            eprintln!("probe: {what}: {error:#}");
            None
        }
    }
}

/// Asks `name` every `every` until `accept` takes an answer, for `wait` at most.
///
/// The first accepted answer is returned. When the wait ends with some answers seen but none
/// accepted, the last one seen is returned, for the check on it to fail with what was found; with
/// none at all it is an error that says the Pi never answered.
fn wait_for_answer(
    dns: SocketAddr,
    name: &str,
    wait: Duration,
    every: Duration,
    accept: impl Fn(&Answer) -> bool,
) -> Result<Timed> {
    let start = Instant::now();
    let mut attempts = 0u32;
    let mut last_answer: Option<Timed> = None;
    let mut last_failure = None;
    loop {
        match ask_udp(dns, name, TYPE_A, WAKE_WAIT) {
            Ok(timed) if accept(&timed.answer) => return Ok(timed),
            Ok(timed) => last_answer = Some(timed),
            Err(failure) => last_failure = Some(failure),
        }
        attempts += 1;
        let next = start + every * attempts;
        if next >= start + wait {
            if let Some(timed) = last_answer {
                return Ok(timed);
            }
            let failure = last_failure.map_or_else(String::new, |e| format!(": {e}"));
            bail!(
                "the Pi never answered a DNS query within {} s{failure}",
                wait.as_secs()
            );
        }
        thread::sleep(next.saturating_duration_since(Instant::now()));
    }
}

/// Asks example.com every `every` until the Pi gives a good answer, for `wait` at most.
///
/// A good answer is NOERROR with at least one address. A Pi that is up but has no upstream yet
/// answers SERVFAIL, and a probe that took that for the Pi being ready would judge a resolver that
/// is still starting.
fn wait_for_the_pi(dns: SocketAddr, wait: Duration, every: Duration) -> Result<Timed> {
    wait_for_answer(dns, "example.com", wait, every, |answer| {
        answer.rcode == 0 && !answer.addrs.is_empty()
    })
}

/// Puts the Pi's resolver through the checks' questions, in the order the observation lists them
/// except that the statistics `before` are read ahead of `first`.
fn observe_resolver(dns: SocketAddr, status: SocketAddr, wait: Duration) -> Result<ResolverSeen> {
    let mut seen = ResolverSeen {
        forwarded: Some(wait_for_the_pi(dns, wait, WAKE_EVERY)?),
        ..ResolverSeen::default()
    };
    seen.before = noted(
        "the statistics before the queries",
        get_stats(status, ASK_WAIT),
    );
    seen.first = noted(
        "the first query",
        ask_udp(dns, "example.org", TYPE_A, ASK_WAIT),
    );
    for _ in 0..REPEATS {
        let repeat = noted(
            "a repeated query",
            ask_udp(dns, "example.org", TYPE_A, ASK_WAIT),
        );
        seen.repeats.extend(repeat);
    }
    seen.tcp = noted(
        "the query over TCP",
        ask_tcp(dns, "example.net", TYPE_A, ASK_WAIT),
    );
    seen.local = noted(
        "the single-label query",
        ask_udp(dns, "printer", TYPE_A, ASK_WAIT),
    );
    let started = Instant::now();
    loop {
        let stats = noted(
            "the statistics after the queries",
            get_stats(status, ASK_WAIT),
        );
        let set = stats.as_ref().is_some_and(|s| s["clock_set"] == true);
        if stats.is_some() {
            // Each reading comes with this machine's clock at the same time.
            seen.pc_unix_secs = crate::unix_time()?;
            seen.after = stats;
        }
        if set || started.elapsed() >= CLOCK_WAIT {
            return Ok(seen);
        }
        thread::sleep(Duration::from_secs(1));
    }
}

/// Whether `answer` to the marker, or the status server beside it, says that qberrypi is what is
/// answering.
///
/// Until the reboot takes it down, Raspberry Pi OS and its Pi-hole answer at the Pi's address, and
/// they say NXDOMAIN to the marker: that is not a snapshot that is missing. qberrypi is answering
/// when the marker is blocked, or when its status server says which list is in force. In the second
/// case the statistics read are left in `stats`, to be `at_first`.
fn qberrypi_answers(answer: &Answer, status: SocketAddr, stats: &RefCell<Option<Value>>) -> bool {
    if answer.rcode == 0 && answer.addrs == [UNSPECIFIED_V4] {
        return true;
    }
    match get_stats(status, WAKE_WAIT) {
        Ok(read) if read.get("list_source").is_some() => {
            *stats.borrow_mut() = Some(read);
            true
        }
        _ => false,
    }
}

/// Puts the Pi through the blocker stage's questions: the snapshot's, then the resolver's, then
/// the wait for the refresh and what is asked once it is over.
///
/// The probe starts when qberrypi answers the marker, which the snapshot blocks whatever the
/// network is, or its status server answers: the snapshot is loaded before the DNS server is, so
/// the marker's answer says whether it is in force, and it is asked before the network could have
/// refreshed the lists. An answer from something else, or a qberrypi that does not block the
/// marker and whose status server is not up, does not end the wait; the last answer seen is
/// `marker_at_first` when the wait ends with none that does. `refresh_wait` is how long the
/// statistics are read, `poll` apart, for `list_source` to say "fetched".
fn observe_blocker(
    dns: SocketAddr,
    status: SocketAddr,
    wait: Duration,
    listed: &str,
    refresh_wait: Duration,
    poll: Duration,
) -> Result<(ResolverSeen, BlockerSeen)> {
    let first_stats = RefCell::new(None);
    let mut seen = BlockerSeen {
        marker_at_first: Some(wait_for_answer(dns, MARKER, wait, WAKE_EVERY, |answer| {
            qberrypi_answers(answer, status, &first_stats)
        })?),
        ..BlockerSeen::default()
    };
    // The statistics that ended the wait, or else the first of the status server's now.
    seen.at_first = first_stats.into_inner().or_else(|| {
        noted(
            "the statistics when the Pi first answered",
            get_stats(status, ASK_WAIT),
        )
    });
    seen.listed_a = noted(
        "the listed name over A",
        ask_udp(dns, listed, TYPE_A, ASK_WAIT),
    );
    seen.listed_aaaa = noted(
        "the listed name over AAAA",
        ask_udp(dns, listed, TYPE_AAAA, ASK_WAIT),
    );

    let resolver = observe_resolver(dns, status, wait)?;

    let deadline = Instant::now() + refresh_wait;
    let mut last = None;
    loop {
        let stats = noted(
            "the statistics while waiting for the refresh",
            get_stats(status, ASK_WAIT),
        );
        if let Some(stats) = stats {
            if stats["list_source"] == "fetched" {
                seen.refreshed = Some(stats);
                break;
            }
            last = Some(stats);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        thread::sleep(poll.min(left));
    }
    if seen.refreshed.is_none() {
        let said = |key: &str| {
            last.as_ref()
                .map_or(Value::Null, |stats| stats[key].clone())
        };
        eprintln!(
            "probe: the lists were not refreshed within {} s; the last statistics said \
             list_source {} and list_error {}",
            refresh_wait.as_secs(),
            said("list_source"),
            said("list_error")
        );
    }
    seen.marker_after = noted(
        "the marker after the refresh",
        ask_udp(dns, MARKER, TYPE_A, ASK_WAIT),
    );
    seen.listed_after = noted(
        "the listed name after the refresh",
        ask_udp(dns, listed, TYPE_A, ASK_WAIT),
    );
    Ok((resolver, seen))
}

/// Runs one stage of the probe against the Pi, prints which checks hold, and fails unless all do.
///
/// The resolver stage is meant to run once per boot: it asks for example.org and counts the
/// repeats as cache hits, so a second run finds example.org cached from the first and its checks
/// of the first query and of the cache no longer mean what they say. The blocker stage includes
/// the resolver's eight checks, so the same holds for it; and its first checks are about the
/// snapshot before any refresh, so it has to be started with the deploy, before the Pi's lists
/// are fetched, and cannot be run twice in one boot.
///
/// `listed` is a name the Pi's lists hold, which the blocker stage asks for. It is never printed.
pub fn run(
    stage: Stage,
    server: Option<Ipv4Addr>,
    wait_secs: u64,
    listed: &str,
    root: &Path,
) -> Result<()> {
    let server = IpAddr::V4(server_address(server, root)?);
    let dns = SocketAddr::new(server, DNS_PORT);
    let status = SocketAddr::new(server, status::PORT);
    let wait = Duration::from_secs(wait_secs);
    let (checks, which) = match stage {
        Stage::Resolver => (
            judge_resolver(&observe_resolver(dns, status, wait)?),
            "resolver",
        ),
        Stage::Blocker => {
            let (resolver, blocker) = observe_blocker(
                dns,
                status,
                wait,
                listed,
                Duration::from_secs(REFRESH_WAIT_SECS),
                REFRESH_POLL,
            )?;
            (judge_blocker_stage(&resolver, &blocker), "blocker")
        }
    };
    let (text, all) = report(&checks);
    print!("{text}");
    if !all {
        bail!("not every check of the {which} stage holds");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Instant;

    use qberrypi::dns::client::Answer;

    const EXAMPLE_ADDR: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn answer(rcode: u8, ttl: Option<u32>) -> Answer {
        Answer {
            rcode,
            addrs: if rcode == 0 {
                vec![IpAddr::V4(EXAMPLE_ADDR)]
            } else {
                Vec::new()
            },
            min_ttl: ttl,
            truncated: false,
        }
    }

    fn timed(rcode: u8, ttl: Option<u32>, took_ms: u64) -> Timed {
        Timed {
            answer: answer(rcode, ttl),
            took: ms(took_ms),
        }
    }

    /// An observation in which all eight checks hold.
    fn good() -> ResolverSeen {
        let stats = |hits: u64| {
            serde_json::json!({
                "cache_hits_total": hits,
                "clock_set": true,
                "unix_secs": 1_800_000_000u64,
                "upstream_ms": 8,
            })
        };
        ResolverSeen {
            forwarded: Some(timed(0, Some(60), 25)),
            first: Some(timed(0, Some(300), 30)),
            repeats: [4, 5, 3, 6, 40]
                .into_iter()
                .map(|took| timed(0, Some(299), took))
                .collect(),
            tcp: Some(timed(0, Some(60), 12)),
            local: Some(timed(3, None, 1)),
            before: Some(stats(2)),
            after: Some(stats(7)),
            pc_unix_secs: 1_800_000_000,
        }
    }

    fn failing(seen: &ResolverSeen) -> Vec<&'static str> {
        judge_resolver(seen)
            .into_iter()
            .filter(|c| !c.ok)
            .map(|c| c.what)
            .collect()
    }

    #[test]
    fn a_good_observation_passes_all_eight() {
        assert_eq!(judge_resolver(&good()).len(), 8);
        assert!(failing(&good()).is_empty());
    }

    #[test]
    fn each_check_fails_on_its_own_evidence() {
        let mut s = good();
        s.repeats.iter_mut().for_each(|r| r.took = ms(31));
        assert_eq!(failing(&s), ["a cached repeat is faster"]);
        let mut s = good();
        s.after.as_mut().unwrap()["cache_hits_total"] = 6.into();
        assert_eq!(failing(&s), ["a repeat is answered from the cache"]);
        let mut s = good();
        s.repeats[0].answer.min_ttl = Some(301);
        assert_eq!(failing(&s), ["a repeat's TTL has not grown"]);
        let mut s = good();
        s.after.as_mut().unwrap()["unix_secs"] = 1_799_999_994u64.into();
        assert_eq!(failing(&s), ["the clock is set"]);
        let mut s = good();
        s.after.as_mut().unwrap()["clock_set"] = false.into();
        assert_eq!(failing(&s), ["the clock is set"]);
        let mut s = good();
        s.after.as_mut().unwrap()["upstream_ms"] = serde_json::Value::Null;
        assert_eq!(failing(&s), ["the upstream latency is known"]);
        let mut s = good();
        s.local.as_mut().unwrap().answer.rcode = 2;
        assert_eq!(failing(&s), ["a single-label name is answered by the Pi"]);
        let mut s = good();
        s.tcp = None;
        assert_eq!(failing(&s), ["a query over TCP is answered"]);
    }

    #[test]
    fn the_edges_of_each_check_are_where_the_table_puts_them() {
        // Five more hits is enough, a clock five seconds off is, and a TTL equal to the first's is.
        let mut s = good();
        s.after.as_mut().unwrap()["cache_hits_total"] = 7.into();
        s.after.as_mut().unwrap()["unix_secs"] = 1_800_000_005u64.into();
        s.repeats[0].answer.min_ttl = Some(300);
        assert!(failing(&s).is_empty());
        // A forwarded answer without an address, and a counter that went backwards, fail.
        let mut s = good();
        s.forwarded.as_mut().unwrap().answer.addrs.clear();
        s.after.as_mut().unwrap()["cache_hits_total"] = 1.into();
        assert_eq!(
            failing(&s),
            [
                "a forwarded name is answered",
                "a repeat is answered from the cache"
            ]
        );
    }

    #[test]
    fn an_observation_with_nothing_in_it_fails_every_check_and_says_what_is_missing() {
        let checks = judge_resolver(&ResolverSeen::default());
        assert!(checks.len() == 8 && checks.iter().all(|c| !c.ok && !c.found.is_empty()));
    }

    #[test]
    fn one_slow_repeat_does_not_move_the_median() {
        assert_eq!(median(&[ms(4), ms(5), ms(3), ms(6), ms(40)]), Some(ms(5)));
        assert_eq!(median(&[ms(4), ms(6)]), Some(ms(6)));
        assert_eq!(median(&[]), None);
    }

    #[test]
    fn the_report_names_each_check_and_counts_them() {
        let (text, all) = report(&[
            Check {
                what: "a",
                ok: true,
                found: String::new(),
            },
            Check {
                what: "b",
                ok: false,
                found: "c".into(),
            },
        ]);
        assert_eq!(
            text,
            "probe: ok: a\nprobe: FAILED: b: c\nprobe: 1 of 2 checks hold\n"
        );
        assert!(!all);
        assert!(report(&[]).1);
    }

    /// The reply to a query that has no OPT record: the same ID and question, the response flags
    /// and one A record 192.0.2.10.
    fn reply_to(query: &[u8]) -> Vec<u8> {
        let mut reply = query.to_vec();
        reply[2] = 0x81;
        reply[3] = 0x80;
        reply[6..8].copy_from_slice(&[0, 1]);
        reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4]);
        reply.extend_from_slice(&EXAMPLE_ADDR.octets());
        reply
    }

    fn loopback() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 0))
    }

    /// A UDP server on a thread that answers one datagram; the thread returns what it was sent.
    fn udp_server() -> (SocketAddr, thread::JoinHandle<Vec<u8>>) {
        let socket = UdpSocket::bind(loopback()).unwrap();
        let addr = socket.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (n, from) = socket.recv_from(&mut buf).unwrap();
            socket.send_to(&reply_to(&buf[..n]), from).unwrap();
            buf[..n].to_vec()
        });
        (addr, handle)
    }

    /// A TCP server on a thread that answers one length-prefixed query; the thread returns the
    /// length prefix and the query.
    fn tcp_server() -> (SocketAddr, thread::JoinHandle<(u16, Vec<u8>)>) {
        let listener = TcpListener::bind(loopback()).unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut len = [0u8; 2];
            stream.read_exact(&mut len).unwrap();
            let mut query = vec![0u8; usize::from(u16::from_be_bytes(len))];
            stream.read_exact(&mut query).unwrap();
            let reply = reply_to(&query);
            let mut framed = u16::try_from(reply.len()).unwrap().to_be_bytes().to_vec();
            framed.extend_from_slice(&reply);
            stream.write_all(&framed).unwrap();
            (u16::from_be_bytes(len), query)
        });
        (addr, handle)
    }

    /// An HTTP server on a thread that sends `response` and then keeps the connection open until
    /// the client closes it; the thread returns the request's head.
    fn http_server(response: &'static str) -> (SocketAddr, thread::JoinHandle<String>) {
        let listener = TcpListener::bind(loopback()).unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                head.push(byte[0]);
            }
            stream.write_all(response.as_bytes()).unwrap();
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).unwrap();
            String::from_utf8(head).unwrap()
        });
        (addr, handle)
    }

    #[test]
    fn a_server_is_asked_over_udp_and_tcp_and_for_its_statistics() {
        let wait = Duration::from_secs(5);

        let (addr, server) = udp_server();
        let got = ask_udp(addr, "example.com", 1, wait).unwrap();
        assert_eq!(got.answer.addrs, [IpAddr::V4(EXAMPLE_ADDR)]);
        assert_eq!(got.answer.rcode, 0);
        assert!(got.took > Duration::ZERO);
        let sent = server.join().unwrap();
        assert_eq!(&sent[12..], b"\x07example\x03com\0\0\x01\0\x01");

        let (addr, server) = tcp_server();
        let got = ask_tcp(addr, "example.net", 1, wait).unwrap();
        assert_eq!(got.answer.addrs, [IpAddr::V4(EXAMPLE_ADDR)]);
        assert!(got.took > Duration::ZERO);
        let (len, sent) = server.join().unwrap();
        assert_eq!(usize::from(len), sent.len());
        assert_eq!(&sent[12..], b"\x07example\x03net\0\0\x01\0\x01");

        let body = r#"{"clock_set":true}"#;
        assert_eq!(body.len(), 18);
        let (addr, server) = http_server(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 18\r\n\r\n{\"clock_set\":true}",
        );
        let stats = get_stats(addr, wait).unwrap();
        assert_eq!(stats["clock_set"], true);
        assert!(
            server
                .join()
                .unwrap()
                .starts_with("GET /api/v1/stats HTTP/1.1\r\n")
        );
    }

    #[test]
    fn a_server_that_is_not_there_is_an_error_within_the_wait() {
        let wait = Duration::from_secs(1);
        // A port that was just open and is not any longer.
        let closed = UdpSocket::bind(loopback()).unwrap().local_addr().unwrap();
        let started = Instant::now();
        assert!(ask_udp(closed, "example.com", 1, wait).is_err());
        assert!(started.elapsed() < wait + ms(500));
        let closed = TcpListener::bind(loopback()).unwrap().local_addr().unwrap();
        assert!(ask_tcp(closed, "example.com", 1, wait).is_err());
        assert!(get_stats(closed, wait).is_err());
    }

    #[test]
    fn a_server_that_says_nothing_is_an_error_after_the_wait_and_not_before() {
        let wait = ms(300);
        let silent_udp = UdpSocket::bind(loopback()).unwrap();
        let started = Instant::now();
        let err = ask_udp(silent_udp.local_addr().unwrap(), "example.com", 1, wait).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() >= wait && started.elapsed() < wait + Duration::from_secs(2));

        // A TCP server that accepts and says nothing, and an HTTP one that stops mid-header.
        let silent_tcp = TcpListener::bind(loopback()).unwrap();
        let started = Instant::now();
        assert!(ask_tcp(silent_tcp.local_addr().unwrap(), "example.com", 1, wait).is_err());
        assert!(get_stats(silent_tcp.local_addr().unwrap(), wait).is_err());
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn a_datagram_that_is_not_the_answer_is_ignored() {
        let socket = UdpSocket::bind(loopback()).unwrap();
        let addr = socket.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (n, from) = socket.recv_from(&mut buf).unwrap();
            let mut other_id = reply_to(&buf[..n]);
            other_id[0] ^= 0xff;
            socket.send_to(&other_id, from).unwrap();
            socket.send_to(b"not dns", from).unwrap();
            socket.send_to(&reply_to(&buf[..n]), from).unwrap();
        });
        let got = ask_udp(addr, "example.com", 1, Duration::from_secs(5)).unwrap();
        assert_eq!(got.answer.addrs, [IpAddr::V4(EXAMPLE_ADDR)]);
        server.join().unwrap();
    }

    #[test]
    fn statistics_that_are_not_a_json_answer_are_an_error() {
        for response in [
            "HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\n{}",
            "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nnotjson",
            "garbage\r\n\r\n",
        ] {
            let (addr, server) = http_server(response);
            assert!(
                get_stats(addr, Duration::from_secs(5)).is_err(),
                "{response}"
            );
            server.join().unwrap();
        }
    }

    /// A NOERROR answer that carries only `addr`, with TTL 2: what a blocked name gets.
    fn blocked(addr: &str) -> Timed {
        Timed {
            answer: Answer {
                rcode: 0,
                addrs: vec![addr.parse().unwrap()],
                min_ttl: Some(2),
                truncated: false,
            },
            took: ms(1),
        }
    }

    /// An observation of the blocker stage in which all seven checks hold.
    fn blocked_good() -> BlockerSeen {
        BlockerSeen {
            at_first: Some(serde_json::json!({
                "list_source": "snapshot",
                "list_names": 50_000,
                "list_error": null,
            })),
            marker_at_first: Some(blocked("0.0.0.0")),
            listed_a: Some(blocked("0.0.0.0")),
            listed_aaaa: Some(blocked("::")),
            refreshed: Some(serde_json::json!({
                "list_source": "fetched",
                "list_names": 60_000,
                "list_error": null,
                "blocked_total": 3,
            })),
            marker_after: Some(timed(3, None, 1)),
            listed_after: Some(blocked("0.0.0.0")),
        }
    }

    fn failing_b(seen: &BlockerSeen) -> Vec<&'static str> {
        judge_blocker(seen)
            .into_iter()
            .filter(|c| !c.ok)
            .map(|c| c.what)
            .collect()
    }

    #[test]
    fn a_good_blocker_observation_passes_all_seven() {
        assert_eq!(judge_blocker(&blocked_good()).len(), 7);
        assert!(failing_b(&blocked_good()).is_empty());
    }

    #[test]
    fn each_blocker_check_fails_on_its_own_evidence() {
        let mut s = blocked_good();
        s.at_first.as_mut().unwrap()["list_source"] = "config".into();
        assert_eq!(
            failing_b(&s),
            ["the snapshot is in force before any refresh"]
        );
        let mut s = blocked_good();
        s.marker_at_first.as_mut().unwrap().answer.rcode = 3;
        assert_eq!(failing_b(&s), ["the snapshot's marker is blocked"]);
        let mut s = blocked_good();
        s.listed_a.as_mut().unwrap().answer.addrs = vec!["192.0.2.10".parse().unwrap()];
        assert_eq!(failing_b(&s), ["a listed name gets 0.0.0.0"]);
        let mut s = blocked_good();
        s.listed_aaaa.as_mut().unwrap().answer.addrs = vec!["2001:db8::1".parse().unwrap()];
        assert_eq!(failing_b(&s), ["a listed name gets :: for AAAA"]);
        let mut s = blocked_good();
        s.refreshed.as_mut().unwrap()["list_error"] =
            "list 1 (lists.example.net): status 404".into();
        assert_eq!(failing_b(&s), ["the lists are refreshed over HTTPS"]);
        let mut s = blocked_good();
        s.marker_after = s.marker_at_first.clone();
        assert_eq!(
            failing_b(&s),
            ["after the refresh the marker is gone and the listed name is still blocked"]
        );
        let mut s = blocked_good();
        s.listed_after = Some(timed(3, None, 1));
        assert_eq!(
            failing_b(&s),
            ["after the refresh the marker is gone and the listed name is still blocked"]
        );
        let mut s = blocked_good();
        s.refreshed.as_mut().unwrap()["blocked_total"] = 2.into();
        assert_eq!(failing_b(&s), ["blocked queries are counted"]);
        let mut s = blocked_good();
        s.refreshed = None;
        assert_eq!(
            failing_b(&s),
            [
                "the lists are refreshed over HTTPS",
                "blocked queries are counted"
            ]
        );
    }

    #[test]
    fn the_edges_of_the_blocker_checks_are_where_the_table_puts_them() {
        // Three blocked queries are enough; the snapshot may hold one name; a TTL other than the
        // blocked answer's 2, or a list that is not there at all, is not the snapshot's marker.
        let mut s = blocked_good();
        s.refreshed.as_mut().unwrap()["blocked_total"] = 3.into();
        s.at_first.as_mut().unwrap()["list_names"] = 1.into();
        assert!(failing_b(&s).is_empty());
        let mut s = blocked_good();
        s.marker_at_first.as_mut().unwrap().answer.min_ttl = Some(3);
        assert_eq!(failing_b(&s), ["the snapshot's marker is blocked"]);
        let mut s = blocked_good();
        s.at_first.as_mut().unwrap()["list_names"] = 0.into();
        assert_eq!(
            failing_b(&s),
            ["the snapshot is in force before any refresh"]
        );
        let mut s = blocked_good();
        s.refreshed.as_mut().unwrap()["list_names"] = 0.into();
        assert_eq!(failing_b(&s), ["the lists are refreshed over HTTPS"]);
        // The AAAA answer is `::` and the A answer 0.0.0.0, not each other's.
        let mut s = blocked_good();
        std::mem::swap(&mut s.listed_a, &mut s.listed_aaaa);
        assert_eq!(
            failing_b(&s),
            [
                "a listed name gets 0.0.0.0",
                "a listed name gets :: for AAAA"
            ]
        );
    }

    #[test]
    fn the_blocker_stage_reports_the_resolvers_eight_checks_and_then_its_seven() {
        let (text, all) = report(&judge_blocker_stage(&good(), &blocked_good()));
        assert!(all, "{text}");
        assert_eq!(
            text,
            "probe: ok: a forwarded name is answered\n\
             probe: ok: a repeat is answered from the cache\n\
             probe: ok: a cached repeat is faster\n\
             probe: ok: a repeat's TTL has not grown\n\
             probe: ok: a query over TCP is answered\n\
             probe: ok: a single-label name is answered by the Pi\n\
             probe: ok: the clock is set\n\
             probe: ok: the upstream latency is known\n\
             probe: ok: the snapshot is in force before any refresh\n\
             probe: ok: the snapshot's marker is blocked\n\
             probe: ok: a listed name gets 0.0.0.0\n\
             probe: ok: a listed name gets :: for AAAA\n\
             probe: ok: the lists are refreshed over HTTPS\n\
             probe: ok: after the refresh the marker is gone and the listed name is still blocked\n\
             probe: ok: blocked queries are counted\n\
             probe: 15 of 15 checks hold\n"
        );
        // One failing check of either half fails the stage.
        let mut seen = good();
        seen.tcp = None;
        assert!(!report(&judge_blocker_stage(&seen, &blocked_good())).1);
        let mut seen = blocked_good();
        seen.refreshed = None;
        assert!(!report(&judge_blocker_stage(&good(), &seen)).1);
    }

    #[test]
    fn a_probe_that_came_after_the_refresh_says_so() {
        let mut s = blocked_good();
        s.at_first.as_mut().unwrap()["list_source"] = "fetched".into();
        let first = judge_blocker(&s).remove(0);
        assert!(!first.ok && first.found.contains("start it with the deploy"));
    }

    #[test]
    fn a_blocker_observation_with_nothing_in_it_fails_every_check_and_says_what_is_missing() {
        let checks = judge_blocker(&BlockerSeen::default());
        assert!(checks.len() == 7 && checks.iter().all(|c| !c.ok && !c.found.is_empty()));
    }

    #[test]
    fn the_server_is_the_flag_or_the_address_in_the_config() {
        let root = tempfile::tempdir().unwrap();
        let flag = Ipv4Addr::new(192, 0, 2, 7);
        // With the flag, the config is not read at all.
        assert_eq!(server_address(Some(flag), root.path()).unwrap(), flag);
        // Without it and without a config, the error says what to do.
        let err = server_address(None, root.path()).unwrap_err();
        assert!(err.to_string().contains("--server"), "{err:#}");
        std::fs::write(
            root.path().join("qberrypi.toml"),
            "[wifi]\nssid = \"example-network\"\npassphrase = \"example-passphrase\"\ncountry = \"US\"\n\
             [net]\naddress = \"192.0.2.53/24\"\ngateway = \"192.0.2.1\"\n\
             [dns]\nupstreams = [\"9.9.9.9\"]\n",
        )
        .unwrap();
        assert_eq!(
            server_address(None, root.path()).unwrap(),
            Ipv4Addr::new(192, 0, 2, 53)
        );
    }

    /// A Pi that answers everything on one thread: DNS over UDP and TCP on the same port number,
    /// and the statistics over HTTP. `events` lists what it was asked, in order; the statistics
    /// count the repeats of example.org as cache hits. `printer` is NXDOMAIN.
    struct FakePi {
        dns: SocketAddr,
        status: SocketAddr,
        events: Arc<Mutex<Vec<String>>>,
        stop: Arc<AtomicBool>,
        thread: Option<thread::JoinHandle<()>>,
    }

    /// The name of the first question in `query`, dotted.
    fn asked_name(query: &[u8]) -> String {
        let mut labels = Vec::new();
        let mut at = 12;
        while query[at] != 0 {
            let len = usize::from(query[at]);
            labels.push(String::from_utf8_lossy(&query[at + 1..at + 1 + len]).into_owned());
            at += 1 + len;
        }
        labels.join(".")
    }

    /// How a fake Pi blocks, for the blocker stage: the marker and `listed` are blocked the way the
    /// snapshot blocks them (0.0.0.0 or `::`, TTL 2) until the statistics have been read
    /// `refresh_after_stats` times; from then on the lists are "fetched", the marker is NXDOMAIN
    /// and `listed` stays blocked.
    ///
    /// For its first `stand_in_queries` DNS queries it stands in for the Raspberry Pi OS and Pi-hole
    /// that run at the Pi's address until the reboot: it answers NXDOMAIN to everything, and its
    /// port 80 says 404 to the statistics.
    #[derive(Clone, Copy)]
    struct Blocking {
        listed: &'static str,
        refresh_after_stats: usize,
        stand_in_queries: usize,
    }

    /// Whether `event` is a DNS query, as opposed to a read of the statistics.
    fn is_query(event: &str) -> bool {
        event.starts_with("udp ") || event.starts_with("tcp ")
    }

    fn stats_reads(events: &[String]) -> usize {
        events.iter().filter(|e| *e == "stats").count()
    }

    /// `query` answered NXDOMAIN.
    fn nxdomain(query: &[u8]) -> Vec<u8> {
        let mut reply = query.to_vec();
        reply[2] = 0x81;
        reply[3] = 0x83;
        reply
    }

    /// `query` answered with the all-zero address of its type and TTL 2.
    fn blocked_reply(query: &[u8]) -> Vec<u8> {
        let qtype = [query[query.len() - 4], query[query.len() - 3]];
        let size: u16 = if qtype == [0, 28] { 16 } else { 4 };
        let mut reply = query.to_vec();
        reply[2] = 0x81;
        reply[3] = 0x80;
        reply[6..8].copy_from_slice(&[0, 1]);
        reply.extend_from_slice(&[0xc0, 0x0c]);
        reply.extend_from_slice(&qtype);
        reply.extend_from_slice(&[0, 1, 0, 0, 0, 2]);
        reply.extend_from_slice(&size.to_be_bytes());
        reply.resize(reply.len() + usize::from(size), 0);
        reply
    }

    fn fake_reply(
        query: &[u8],
        events: &Mutex<Vec<String>>,
        how: &str,
        blocking: Option<Blocking>,
        blocked: &mut u64,
    ) -> Vec<u8> {
        let name = asked_name(query);
        let (refreshed, asked) = {
            let mut events = events.lock().unwrap();
            events.push(format!("{how} {name}"));
            (
                blocking.is_some_and(|b| stats_reads(&events) >= b.refresh_after_stats),
                events.iter().filter(|e| is_query(e)).count(),
            )
        };
        if let Some(blocking) = blocking {
            if asked <= blocking.stand_in_queries {
                return nxdomain(query);
            }
            if name == blocking.listed || (name == MARKER && !refreshed) {
                *blocked += 1;
                return blocked_reply(query);
            }
            if name == MARKER {
                return nxdomain(query);
            }
        }
        if name == "printer" {
            nxdomain(query)
        } else {
            reply_to(query)
        }
    }

    impl FakePi {
        fn start() -> FakePi {
            FakePi::start_with(None)
        }

        /// A fake Pi that blocks `listed` and the snapshot's marker, and refreshes its lists once
        /// its statistics have been read `refresh_after_stats` times.
        fn blocking(listed: &'static str, refresh_after_stats: usize) -> FakePi {
            FakePi::blocking_after(0, listed, refresh_after_stats)
        }

        /// The same, but for its first `stand_in_queries` DNS queries it is the old system that
        /// the Pi runs until the reboot: NXDOMAIN, and no statistics.
        fn blocking_after(
            stand_in_queries: usize,
            listed: &'static str,
            refresh_after_stats: usize,
        ) -> FakePi {
            FakePi::start_with(Some(Blocking {
                listed,
                refresh_after_stats,
                stand_in_queries,
            }))
        }

        fn start_with(blocking: Option<Blocking>) -> FakePi {
            let (udp, tcp) = (0..50)
                .find_map(|_| {
                    let udp = UdpSocket::bind(loopback()).ok()?;
                    let port = udp.local_addr().ok()?.port();
                    let tcp = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))).ok()?;
                    Some((udp, tcp))
                })
                .expect("a port free for both UDP and TCP");
            let http = TcpListener::bind(loopback()).unwrap();
            let dns = udp.local_addr().unwrap();
            let status = http.local_addr().unwrap();
            for listener in [&tcp, &http] {
                listener.set_nonblocking(true).unwrap();
            }
            udp.set_nonblocking(true).unwrap();
            let events = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let (log, flag) = (events.clone(), stop.clone());
            let thread = thread::spawn(move || {
                let mut buf = [0u8; 512];
                let mut blocked = 0u64;
                while !flag.load(Ordering::Relaxed) {
                    let mut idle = true;
                    if let Ok((n, from)) = udp.recv_from(&mut buf) {
                        idle = false;
                        let reply = fake_reply(&buf[..n], &log, "udp", blocking, &mut blocked);
                        udp.send_to(&reply, from).unwrap();
                    }
                    if let Ok((mut stream, _)) = tcp.accept() {
                        idle = false;
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut len = [0u8; 2];
                        stream.read_exact(&mut len).unwrap();
                        let mut query = vec![0u8; usize::from(u16::from_be_bytes(len))];
                        stream.read_exact(&mut query).unwrap();
                        let reply = fake_reply(&query, &log, "tcp", blocking, &mut blocked);
                        let mut framed = u16::try_from(reply.len()).unwrap().to_be_bytes().to_vec();
                        framed.extend_from_slice(&reply);
                        stream.write_all(&framed).unwrap();
                    }
                    if let Ok((mut stream, _)) = http.accept() {
                        idle = false;
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut head = Vec::new();
                        let mut byte = [0u8; 1];
                        while !head.ends_with(b"\r\n\r\n") {
                            stream.read_exact(&mut byte).unwrap();
                            head.push(byte[0]);
                        }
                        let stand_in = blocking.is_some_and(|b| {
                            log.lock().unwrap().iter().filter(|e| is_query(e)).count()
                                <= b.stand_in_queries
                        });
                        if stand_in {
                            stream
                                .write_all(
                                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                                )
                                .unwrap();
                            continue;
                        }
                        let (hits, reads) = {
                            let mut events = log.lock().unwrap();
                            events.push("stats".to_owned());
                            (
                                events.iter().filter(|e| *e == "udp example.org").count(),
                                stats_reads(&events),
                            )
                        };
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        let mut body = serde_json::json!({
                            "cache_hits_total": hits.saturating_sub(1),
                            "clock_set": true,
                            "unix_secs": now,
                            "upstream_ms": 8,
                        });
                        if let Some(blocking) = blocking {
                            body["list_source"] = if reads >= blocking.refresh_after_stats {
                                "fetched"
                            } else {
                                "snapshot"
                            }
                            .into();
                            body["list_names"] = 5.into();
                            body["list_error"] = serde_json::Value::Null;
                            body["blocked_total"] = blocked.into();
                        }
                        let body = body.to_string();
                        write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .unwrap();
                    }
                    if idle {
                        thread::sleep(Duration::from_millis(2));
                    }
                }
            });
            FakePi {
                dns,
                status,
                events,
                stop,
                thread: Some(thread),
            }
        }
    }

    impl Drop for FakePi {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(thread) = self.thread.take() {
                // A panic on the thread shows on stderr; joining must not panic in a panic.
                let _ = thread.join();
            }
        }
    }

    #[test]
    fn the_resolver_is_asked_in_the_order_of_the_checks_with_the_statistics_ahead_of_the_first() {
        let pi = FakePi::start();
        let seen = observe_resolver(pi.dns, pi.status, Duration::from_secs(5)).unwrap();
        assert_eq!(
            *pi.events.lock().unwrap(),
            [
                "udp example.com",
                "stats",
                "udp example.org",
                "udp example.org",
                "udp example.org",
                "udp example.org",
                "udp example.org",
                "udp example.org",
                "tcp example.net",
                "udp printer",
                "stats",
            ]
        );
        assert_eq!(seen.repeats.len(), 5);
        assert_eq!(seen.before.as_ref().unwrap()["cache_hits_total"], 0);
        assert_eq!(seen.after.as_ref().unwrap()["cache_hits_total"], 5);
        assert_eq!(seen.local.as_ref().unwrap().answer.rcode, 3);
        assert!(seen.forwarded.is_some() && seen.first.is_some() && seen.tcp.is_some());
        let checks = judge_resolver(&seen);
        for check in &checks {
            // The fake answers every query alike, so its speed and TTLs are not what is judged.
            if !["a cached repeat is faster", "a repeat's TTL has not grown"].contains(&check.what)
            {
                assert!(check.ok, "{}: {}", check.what, check.found);
            }
        }
    }

    /// What a scripted server answers with.
    #[derive(Clone, Copy)]
    enum Reply {
        /// NOERROR and the address 192.0.2.10.
        Address,
        /// SERVFAIL, no records.
        Servfail,
        /// NOERROR, no records.
        Nodata,
    }

    /// A DNS server over UDP on a thread that answers the n-th query with the n-th of its script,
    /// and every query after the script with its last.
    struct ScriptedDns {
        addr: SocketAddr,
        asked: Arc<AtomicUsize>,
        stop: Arc<AtomicBool>,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl ScriptedDns {
        fn start(script: &'static [Reply]) -> ScriptedDns {
            let socket = UdpSocket::bind(loopback()).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_millis(10)))
                .unwrap();
            let addr = socket.local_addr().unwrap();
            let asked = Arc::new(AtomicUsize::new(0));
            let stop = Arc::new(AtomicBool::new(false));
            let (count, flag) = (asked.clone(), stop.clone());
            let thread = thread::spawn(move || {
                let mut buf = [0u8; 512];
                while !flag.load(Ordering::Relaxed) {
                    let Ok((n, from)) = socket.recv_from(&mut buf) else {
                        continue;
                    };
                    let nth = count.fetch_add(1, Ordering::Relaxed);
                    let reply = match script[nth.min(script.len() - 1)] {
                        Reply::Address => reply_to(&buf[..n]),
                        Reply::Servfail | Reply::Nodata => {
                            let mut reply = buf[..n].to_vec();
                            reply[2] = 0x81;
                            reply[3] =
                                if matches!(script[nth.min(script.len() - 1)], Reply::Servfail) {
                                    0x82
                                } else {
                                    0x80
                                };
                            reply
                        }
                    };
                    socket.send_to(&reply, from).unwrap();
                }
            });
            ScriptedDns {
                addr,
                asked,
                stop,
                thread: Some(thread),
            }
        }

        fn asked(&self) -> usize {
            self.asked.load(Ordering::Relaxed)
        }
    }

    impl Drop for ScriptedDns {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    #[test]
    fn the_wait_for_the_pi_goes_on_past_answers_that_are_no_good_until_one_is() {
        // A Pi that is up but has no upstream yet answers SERVFAIL, then NODATA, then well.
        let pi = ScriptedDns::start(&[Reply::Servfail, Reply::Nodata, Reply::Address]);

        let timed = wait_for_the_pi(pi.addr, Duration::from_secs(5), ms(50)).unwrap();

        assert_eq!(timed.answer.rcode, 0);
        assert_eq!(timed.answer.addrs, [IpAddr::V4(EXAMPLE_ADDR)]);
        assert_eq!(pi.asked(), 3);
    }

    #[test]
    fn a_pi_that_only_ever_answers_badly_gives_the_last_answer_for_the_first_check_to_judge() {
        for (script, found) in [
            (&[Reply::Servfail][..], "the answer was SERVFAIL"),
            (&[Reply::Nodata][..], "the answer held no address"),
        ] {
            let script: &'static [Reply] = Box::leak(script.to_vec().into_boxed_slice());
            let pi = ScriptedDns::start(script);

            // 100 ms apart for 400 ms: four questions, and none of them is good.
            let timed = wait_for_the_pi(pi.addr, ms(400), ms(100)).unwrap();

            assert_eq!(pi.asked(), 4, "{found}");
            let seen = ResolverSeen {
                forwarded: Some(timed),
                ..ResolverSeen::default()
            };
            let check = &judge_resolver(&seen)[0];
            assert_eq!(check.what, "a forwarded name is answered");
            assert!(!check.ok);
            assert_eq!(check.found, found);
        }
    }

    #[test]
    fn a_pi_that_stops_answering_after_a_bad_answer_still_gives_that_answer() {
        // The Pi said SERVFAIL once and then stopped answering: "never answered" would be untrue.
        let socket = UdpSocket::bind(loopback()).unwrap();
        let addr = socket.local_addr().unwrap();
        let once = thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (n, from) = socket.recv_from(&mut buf).unwrap();
            let mut reply = buf[..n].to_vec();
            reply[2] = 0x81;
            reply[3] = 0x82;
            socket.send_to(&reply, from).unwrap();
            // The socket closes here: later questions are refused.
        });

        let timed = wait_for_the_pi(addr, ms(300), ms(100)).unwrap();

        assert_eq!(timed.answer.rcode, 2);
        once.join().unwrap();
    }

    #[test]
    fn a_pi_that_never_answers_is_an_error_that_says_so() {
        let silent = UdpSocket::bind(loopback()).unwrap();
        let started = Instant::now();
        let err = observe_resolver(
            silent.local_addr().unwrap(),
            silent.local_addr().unwrap(),
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(err.to_string().contains("never answered"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    const LISTED: &str = "ads.example.com";

    #[test]
    fn the_blocker_is_asked_snapshot_first_then_the_resolver_then_the_refresh_is_waited_for() {
        // The statistics are read six times before the lists are "fetched": as the Pi first
        // answers, twice in the resolver stage's questions, and three times while the probe waits
        // for the refresh, the third of which sees it.
        let pi = FakePi::blocking(LISTED, 6);

        let (resolver, seen) = observe_blocker(
            pi.dns,
            pi.status,
            Duration::from_secs(5),
            LISTED,
            Duration::from_secs(5),
            ms(20),
        )
        .unwrap();

        let mut expected = vec![
            format!("udp {MARKER}"),
            "stats".to_owned(),
            format!("udp {LISTED}"),
            format!("udp {LISTED}"),
            "udp example.com".to_owned(),
            "stats".to_owned(),
        ];
        expected.extend(["udp example.org"; 6].map(str::to_owned));
        expected.extend(["tcp example.net", "udp printer", "stats"].map(str::to_owned));
        expected.extend(["stats", "stats", "stats"].map(str::to_owned));
        expected.extend([format!("udp {MARKER}"), format!("udp {LISTED}")]);
        assert_eq!(*pi.events.lock().unwrap(), expected);

        assert_eq!(seen.at_first.as_ref().unwrap()["list_source"], "snapshot");
        assert_eq!(seen.refreshed.as_ref().unwrap()["list_source"], "fetched");
        assert_eq!(seen.refreshed.as_ref().unwrap()["blocked_total"], 3);
        assert_eq!(
            seen.listed_a.as_ref().unwrap().answer.summary(),
            "NOERROR 0.0.0.0"
        );
        assert_eq!(
            seen.listed_aaaa.as_ref().unwrap().answer.summary(),
            "NOERROR ::"
        );
        assert_eq!(seen.marker_after.as_ref().unwrap().answer.rcode, 3);
        assert_eq!(resolver.repeats.len(), 5);

        for check in judge_blocker(&seen) {
            assert!(check.ok, "{}: {}", check.what, check.found);
        }
        for check in judge_resolver(&resolver) {
            // The fake answers every query alike, so its speed and TTLs are not what is judged.
            if !["a cached repeat is faster", "a repeat's TTL has not grown"].contains(&check.what)
            {
                assert!(check.ok, "{}: {}", check.what, check.found);
            }
        }
    }

    #[test]
    fn a_refresh_that_never_comes_ends_the_wait_with_the_rest_of_the_observation_made() {
        let pi = FakePi::blocking(LISTED, usize::MAX);
        let started = Instant::now();

        let (_, seen) = observe_blocker(
            pi.dns,
            pi.status,
            Duration::from_secs(5),
            LISTED,
            ms(300),
            ms(50),
        )
        .unwrap();

        // The wait is the one asked for, not the resolver stage's, and it reads more than once.
        assert!(started.elapsed() >= ms(300) && started.elapsed() < Duration::from_secs(5));
        assert!(stats_reads(&pi.events.lock().unwrap()) >= 3 + 2);
        assert!(seen.refreshed.is_none());
        assert!(seen.marker_after.is_some() && seen.listed_after.is_some());
        assert_eq!(
            failing_b(&seen),
            [
                "the lists are refreshed over HTTPS",
                "after the refresh the marker is gone and the listed name is still blocked",
                "blocked queries are counted",
            ]
        );
    }

    #[test]
    fn a_pi_that_refreshed_before_the_probe_came_is_not_waited_for_and_the_first_check_says_so() {
        let pi = FakePi::blocking(LISTED, 0);

        let (_, seen) = observe_blocker(
            pi.dns,
            pi.status,
            Duration::from_secs(5),
            LISTED,
            Duration::from_secs(5),
            ms(20),
        )
        .unwrap();

        // The marker was answered at once, and it is not blocked any more; the Pi's statistics
        // said it is qberrypi that answers, which ended the wait, and they are `at_first`: the
        // next thing the Pi was asked is the listed name, not the statistics again.
        assert_eq!(seen.marker_at_first.as_ref().unwrap().answer.rcode, 3);
        assert_eq!(seen.at_first.as_ref().unwrap()["list_source"], "fetched");
        assert_eq!(
            pi.events.lock().unwrap()[..3],
            [
                format!("udp {MARKER}"),
                "stats".to_owned(),
                format!("udp {LISTED}")
            ]
        );
        let checks = judge_blocker(&seen);
        assert!(!checks[0].ok && checks[0].found.contains("start it with the deploy"));
        assert!(!checks[1].ok);
        assert!(checks[4].ok, "{}", checks[4].found);
    }

    #[test]
    fn the_system_that_runs_until_the_reboot_does_not_end_the_wait_for_qberrypi() {
        // Raspberry Pi OS and its Pi-hole answer at the Pi's address until the reboot takes them
        // down: NXDOMAIN for the marker, and no statistics. That is not the snapshot being absent;
        // the probe goes on asking until qberrypi answers.
        let pi = FakePi::blocking_after(1, LISTED, 6);

        let (_, seen) = observe_blocker(
            pi.dns,
            pi.status,
            Duration::from_secs(10),
            LISTED,
            Duration::from_secs(5),
            ms(20),
        )
        .unwrap();

        assert_eq!(
            seen.marker_at_first.as_ref().unwrap().answer.summary(),
            "NOERROR 0.0.0.0"
        );
        assert_eq!(seen.at_first.as_ref().unwrap()["list_source"], "snapshot");
        assert_eq!(
            pi.events.lock().unwrap()[..5],
            [
                format!("udp {MARKER}"),
                format!("udp {MARKER}"),
                "stats".to_owned(),
                format!("udp {LISTED}"),
                format!("udp {LISTED}"),
            ]
        );
        for check in judge_blocker(&seen) {
            assert!(check.ok, "{}: {}", check.what, check.found);
        }
    }

    #[test]
    fn a_qberrypi_without_its_snapshot_still_fails_the_marker_check_with_what_it_answered() {
        // Its statistics answer, so the wait ends; the marker is not blocked and `list_source`
        // says it is not the snapshot that is in force.
        let pi = FakePi::blocking(LISTED, 0);
        let (_, seen) = observe_blocker(
            pi.dns,
            pi.status,
            Duration::from_secs(5),
            LISTED,
            ms(100),
            ms(20),
        )
        .unwrap();
        let checks = judge_blocker(&seen);
        assert!(!checks[1].ok && checks[1].found == "the answer was NXDOMAIN");
    }

    #[test]
    fn a_pi_that_never_answers_the_blocker_stage_is_an_error_that_says_so() {
        let silent = UdpSocket::bind(loopback()).unwrap();
        let started = Instant::now();
        let err = observe_blocker(
            silent.local_addr().unwrap(),
            silent.local_addr().unwrap(),
            Duration::from_secs(1),
            LISTED,
            ms(100),
            ms(20),
        )
        .unwrap_err();
        assert!(err.to_string().contains("never answered"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}
