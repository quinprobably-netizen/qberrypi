//! `cargo xtask latency`: measures from this machine how fast the Pi answers a ping and DNS
//! questions, for comparison with the stock Pi-hole baseline in `docs/bring-up/latency-baseline.md`.
//!
//! Four rows, one after another, each with the same number of samples: the system's `ping`, and
//! DNS answers that are cached, blocked and forwarded. The Pi needs nothing but DNS on UDP port 53
//! and an answer to ping, so the same command measures stock Pi-hole and qberrypi alike.
//!
//! Plain std sockets, one query in flight at a time. Nothing here puts the Pi's address into the
//! results.

use std::collections::hash_map::RandomState;
use std::fs;
use std::hash::{BuildHasher, Hasher};
use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use hickory_proto::op::{Message, MessageType, Query};
use qberrypi::dns::DNS_PORT;
use qberrypi::dns::client::{Answer, query, read_answer};
use serde_json::{Value, json};

use crate::probe::{configured_address, next_id, time_left};

/// The record type A.
const TYPE_A: u16 = 1;
/// How long a DNS question waits for its answer before it counts as lost; and ping's `-W`.
const LOST_AFTER: Duration = Duration::from_secs(2);
/// The name of the cached row. It is asked once before the samples, so the Pi has it in its cache.
const CACHED_NAME: &str = "example.com";

/// The zones the forwarded row asks under, one after another, each time with a fresh random label.
///
/// The baseline measurement found that random names under ONE zone were answered without the
/// upstream: a resolver that holds a signed zone's NSEC or NSEC3 range can make up an NXDOMAIN
/// for any name inside it (RFC 8198), and a negative cache for the zone does the rest. So these
/// are six zones of six different operators, none of them signed (no DS record at the parent, so
/// there is no denial of existence to keep) and none with a wildcard (a random name under each
/// is a real NXDOMAIN from the operator's own servers): Google (its own servers), Amazon
/// (Route 53), Microsoft (Azure DNS), Wikimedia (its own servers), Mozilla (Akamai) and
/// kernel.org (Constellix).
///
/// Checked on 2026-11-10 from a public validating resolver: each zone had no DS record, and
/// four random names under each answered NXDOMAIN with an empty answer section. An operator
/// that later signs its zone or adds a wildcard spoils its zone for this row; check again if the
/// forwarded figures ever look too good.
pub const FORWARDED_ZONES: [&str; 6] = [
    "google.com",
    "amazon.com",
    "microsoft.com",
    "wikipedia.org",
    "mozilla.org",
    "kernel.org",
];

/// Well-known ad-serving names that the example configuration's lists hold, tried in this order
/// until one answers as blocked.
pub const BLOCKED_CANDIDATES: [&str; 3] = [
    "doubleclick.net",
    "googleadservices.com",
    "pagead2.googlesyndication.com",
];

/// The figures of a set of samples: the percentiles are nearest rank, and each is `None` without
/// a sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Figures {
    pub p50: Option<Duration>,
    pub p95: Option<Duration>,
    pub min: Option<Duration>,
    pub mean: Option<Duration>,
}

impl Figures {
    /// The figures of `samples`, in any order. A percentile is the nearest rank: the p50 of 200
    /// samples is the 100th smallest, the p95 the 190th.
    fn of(samples: &[Duration]) -> Figures {
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        let count = sorted.len();
        let nearest_rank = |percent: usize| {
            let rank = (percent * count).div_ceil(100);
            sorted.get(rank.saturating_sub(1)).copied()
        };
        let mean = (count > 0).then(|| {
            let total: u128 = sorted.iter().map(Duration::as_nanos).sum();
            let nanos = total / count as u128;
            Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
        });
        Figures {
            p50: nearest_rank(50),
            p95: nearest_rank(95),
            min: sorted.first().copied(),
            mean,
        }
    }
}

/// The figures of one row.
///
/// `p50`, `p95` and `mean` are the ones the table and the JSON's top level carry. On a DNS row a
/// lost sample is in them as `lost_as` (a client whose question gets no answer waits that long at
/// the least); on the icmp row, which has no `lost_as`, they are the received samples' own.
/// `min` is always the received minimum: a lost sample is "at least the wait", never a minimum.
/// `received` holds the received-only figures of every row, `min` among them.
///
/// `failed` is how many of the lost samples were not missing but answered SERVFAIL or REFUSED,
/// which is no answer for a client; it is a subset of `lost`, and `stats` leaves it 0 for the
/// DNS row to set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowStats {
    /// How many samples were received: answers other than SERVFAIL and REFUSED.
    pub samples: usize,
    /// How many were lost.
    pub lost: usize,
    /// How many of the lost were SERVFAIL or REFUSED answers.
    pub failed: usize,
    /// What a lost sample counts as in `p50`, `p95` and `mean`; `None` when it is left out.
    pub lost_as: Option<Duration>,
    /// The median, nearest rank; `None` without a sample to count, as are the others.
    pub p50: Option<Duration>,
    pub p95: Option<Duration>,
    pub min: Option<Duration>,
    pub mean: Option<Duration>,
    /// The figures of the received samples alone.
    pub received: Figures,
}

/// The figures of a row from the samples that were received and how many were lost. With
/// `lost_as`, each lost sample counts once as that long in the percentiles and the mean, the
/// received samples alongside it; with `None` only the received samples count. Percentiles are
/// nearest rank over what counts: the p50 of 200 samples is the 100th smallest, the p95 the 190th.
pub fn stats(received: &[Duration], lost: usize, lost_as: Option<Duration>) -> RowStats {
    let received_only = Figures::of(received);
    let counted = match lost_as {
        Some(wait) if lost > 0 => {
            let mut all = received.to_vec();
            all.resize(received.len() + lost, wait);
            Figures {
                min: received_only.min,
                ..Figures::of(&all)
            }
        }
        _ => received_only,
    };
    RowStats {
        samples: received.len(),
        lost,
        failed: 0,
        lost_as,
        p50: counted.p50,
        p95: counted.p95,
        min: counted.min,
        mean: counted.mean,
        received: received_only,
    }
}

/// A row that was measured: its figures, and the first socket error that made a sample lost, if
/// one did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Measured {
    pub stats: RowStats,
    pub first_error: Option<String>,
}

/// One row of the table: measured, or an error that says why it could not be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub name: &'static str,
    pub result: Result<Measured, String>,
}

/// What a run measured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub unix_secs: u64,
    pub samples_asked: usize,
    pub interval_ms: u64,
    /// The name the blocked row asked; `None` when none answered as blocked.
    pub blocked_name: Option<String>,
    pub rows: Vec<Row>,
}

/// What ping said: the round trips of the replies, and the counts of its summary line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingRun {
    pub times: Vec<Duration>,
    pub transmitted: usize,
    pub received: usize,
}

/// The `N packets transmitted, R received` line of iputils (also `R packets received`, as busybox
/// says it) as `(N, R)`.
fn summary_counts(line: &str) -> Option<(usize, usize)> {
    let (sent, rest) = line.trim_start().split_once(" packets transmitted,")?;
    let transmitted = sent.trim().parse().ok()?;
    let received = rest
        .split(',')
        .next()?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    Some((transmitted, received))
}

/// The `time=X ms` of a reply line.
fn reply_time(line: &str) -> Option<Duration> {
    let (_, after) = line.split_once("time=")?;
    let number: String = after
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    Duration::try_from_secs_f64(number.parse::<f64>().ok()? / 1000.0).ok()
}

/// Reads the output of `ping`: the time of each reply line, and the summary's counts. `None`
/// when there is no summary line, as when ping failed to start or was cut off. A duplicated
/// reply is not a sample.
pub fn parse_ping(output: &str) -> Option<PingRun> {
    let mut times = Vec::new();
    let mut counts = None;
    for line in output.lines() {
        if let Some(found) = summary_counts(line) {
            counts = Some(found);
        } else if !line.contains("DUP!")
            && let Some(time) = reply_time(line)
        {
            times.push(time);
        }
    }
    let (transmitted, received) = counts?;
    Some(PingRun {
        times,
        transmitted,
        received,
    })
}

/// The ping row from what `ping` printed on stdout and stderr. The error holds ping's first line
/// of complaint, with the address left out.
fn ping_measured(stdout: &str, stderr: &str, addr: Ipv4Addr) -> Result<Measured, String> {
    let Some(run) = parse_ping(stdout) else {
        let complaint = stderr
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .map(|line| line.replace(&addr.to_string(), "the Pi"));
        return Err(match complaint {
            Some(complaint) => format!("ping printed no summary ({complaint})"),
            None => "ping printed no summary".to_owned(),
        });
    };
    Ok(Measured {
        // No client waits on a ping: its lost replies are not counted as anything.
        stats: stats(
            &run.times,
            run.transmitted.saturating_sub(run.received),
            None,
        ),
        first_error: None,
    })
}

/// Runs the system's `ping` as this user, `samples` times with `interval` between, and reads it.
fn ping_row(addr: Ipv4Addr, samples: usize, interval: Duration) -> Result<Measured, String> {
    let output = Command::new("ping")
        // The same words and decimal point whatever the user's locale is.
        .env("LC_ALL", "C")
        .args(["-n", "-c"])
        .arg(samples.to_string())
        .arg("-i")
        .arg(format!("{:.3}", interval.as_secs_f64()))
        .arg("-W")
        .arg(LOST_AFTER.as_secs().to_string())
        .arg(addr.to_string())
        .stdin(Stdio::null())
        .output()
        .map_err(|error| match error.kind() {
            ErrorKind::NotFound => {
                "ping is not installed (there is no `ping` on the PATH)".to_owned()
            }
            _ => format!("cannot run ping: {error}"),
        })?;
    ping_measured(
        &String::from_utf8_lossy(&output.stdout),
        &String::from_utf8_lossy(&output.stderr),
        addr,
    )
}

/// The reply as an answer to the question `wanted` under `id`, or `None` if it is anything else:
/// bytes that are no message, a query, another ID, or a response that does not carry exactly our
/// question. The name is compared without regard to case.
fn answer_to(reply: &[u8], id: u16, wanted: &Query) -> Option<Answer> {
    let message = Message::from_vec(reply).ok()?;
    if message.metadata.message_type != MessageType::Response || message.metadata.id != id {
        return None;
    }
    let [asked] = message.queries.as_slice() else {
        return None;
    };
    if asked.name != wanted.name
        || asked.query_type != wanted.query_type
        || asked.query_class != wanted.query_class
    {
        return None;
    }
    read_answer(reply, id)
}

/// Asks `server` over UDP from a fresh socket and waits up to `wait` for the answer to this
/// question, ignoring every datagram that is not it. The time runs from the send to the
/// answer's arrival. `None` when no answer came in time.
fn ask_answer(
    server: SocketAddr,
    name: &str,
    qtype: u16,
    wait: Duration,
) -> io::Result<Option<(Duration, Answer)>> {
    let id = next_id();
    let packet = query(id, name, qtype)?;
    let wanted = Message::from_vec(&packet)
        .ok()
        .and_then(|message| message.queries.into_iter().next())
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "the query has no question"))?;
    // Connected, so that only the server's own datagrams arrive, and a refusal is an error.
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.connect(server)?;
    let started = Instant::now();
    let deadline = started + wait;
    socket.send(&packet)?;
    let mut buf = [0u8; 4096];
    loop {
        let left = match time_left(deadline) {
            Ok(left) => left,
            Err(error) if error.kind() == ErrorKind::TimedOut => return Ok(None),
            Err(error) => return Err(error),
        };
        socket.set_read_timeout(Some(left))?;
        match socket.recv(&mut buf) {
            Ok(n) => {
                let arrived = Instant::now();
                if let Some(answer) = answer_to(&buf[..n], id, &wanted) {
                    return Ok(Some((arrived - started, answer)));
                }
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        }
    }
}

/// Asks `server` for `name` and `qtype` over UDP and waits up to `wait`: how long the matching
/// answer took and its response code, or `None` if it did not come (lost). An answer matches only
/// when its ID and its question are ours and it is a response; anything else is read and ignored,
/// and the wait goes on. A socket error is an error.
pub fn ask(
    server: SocketAddr,
    name: &str,
    qtype: u16,
    wait: Duration,
) -> io::Result<Option<(Duration, u8)>> {
    Ok(ask_answer(server, name, qtype, wait)?.map(|(took, answer)| (took, answer.rcode)))
}

/// Whether an answer with this response code is no answer for a client: SERVFAIL or REFUSED. A
/// resolver that cannot resolve says so at once, but the client's question stays unanswered, and
/// a system that fails fast must not look faster than one that answers. NXDOMAIN is an answer:
/// it is the normal answer for the forwarded row's fresh labels.
fn is_failed_answer(rcode: u8) -> bool {
    matches!(rcode, 2 | 5)
}

/// A row of `samples` A questions to `server`, `interval` apart, the name of sample `i` being
/// `name(i)`. A question with no answer in `wait` is lost; so is one that failed on the socket,
/// and the first such error is kept; so is one answered SERVFAIL or REFUSED, which the row also
/// counts as `failed`. A lost question counts as `wait` in the row's p50, p95 and mean.
fn dns_row(
    server: SocketAddr,
    wait: Duration,
    samples: usize,
    interval: Duration,
    mut name: impl FnMut(usize) -> String,
) -> Measured {
    let mut received = Vec::with_capacity(samples);
    let mut lost = 0;
    let mut failed = 0;
    let mut first_error = None;
    for i in 0..samples {
        if i > 0 {
            thread::sleep(interval);
        }
        match ask(server, &name(i), TYPE_A, wait) {
            Ok(Some((_, rcode))) if is_failed_answer(rcode) => {
                lost += 1;
                failed += 1;
            }
            Ok(Some((took, _))) => received.push(took),
            Ok(None) => lost += 1,
            Err(error) => {
                lost += 1;
                first_error.get_or_insert_with(|| error.to_string());
            }
        }
    }
    Measured {
        stats: RowStats {
            failed,
            ..stats(&received, lost, Some(wait))
        },
        first_error,
    }
}

/// A random label of 16 lowercase hex digits. Each `RandomState` brings keys the system chose.
fn random_label() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    format!("{:016x}", hasher.finish())
}

/// The name asked in sample `index` of the forwarded row: a fresh label under the next zone.
fn forwarded_name(index: usize) -> String {
    format!(
        "{}.{}",
        random_label(),
        FORWARDED_ZONES[index % FORWARDED_ZONES.len()]
    )
}

/// What an answer says that a blocked name is expected to get from both stock Pi-hole and
/// qberrypi: NOERROR, and no address but 0.0.0.0.
fn is_blocked(answer: &Answer) -> bool {
    answer.rcode == 0
        && !answer.addrs.is_empty()
        && answer
            .addrs
            .iter()
            .all(|addr| *addr == IpAddr::V4(Ipv4Addr::UNSPECIFIED))
}

/// What an answer was, in words, without its addresses: the Pi's own address may be among them,
/// and the results hold no address.
fn describe(answer: &Answer) -> String {
    let code = match answer.rcode {
        0 => "NOERROR".to_owned(),
        2 => "SERVFAIL".to_owned(),
        3 => "NXDOMAIN".to_owned(),
        other => format!("RCODE {other}"),
    };
    match answer.addrs.len() {
        0 => code,
        1 => format!("{code} with an address other than 0.0.0.0"),
        count => format!("{code} with {count} addresses, not only 0.0.0.0"),
    }
}

/// The first of `candidates` that answers as blocked; or, if none does, what each answered, as
/// `name: what; name: what`.
fn find_blocked(server: SocketAddr, wait: Duration, candidates: &[&str]) -> Result<String, String> {
    let mut seen = Vec::new();
    for name in candidates {
        let what = match ask_answer(server, name, TYPE_A, wait) {
            Ok(Some((_, answer))) if is_blocked(&answer) => return Ok((*name).to_owned()),
            Ok(Some((_, answer))) => describe(&answer),
            Ok(None) => format!("no answer within {wait:?}"),
            Err(error) => error.to_string(),
        };
        seen.push(format!("{name}: {what}"));
    }
    Err(seen.join("; "))
}

/// What a run measures and how.
#[derive(Debug, Clone)]
pub struct Settings<'a> {
    /// How many samples each row takes.
    pub samples: usize,
    /// The pause between one sample's end and the next question.
    pub interval: Duration,
    /// The name for the blocked row, if the user gave one.
    pub blocked: Option<&'a str>,
    /// How long a question waits for its answer before it counts as lost.
    pub wait: Duration,
}

/// Measures the four rows in order: `ping` for the icmp row, then the DNS rows against `dns`.
/// `progress` is told the name of each row as it begins. A row that cannot be measured is an
/// error row, and the others go on.
pub fn measure(
    dns: SocketAddr,
    settings: &Settings,
    unix_secs: u64,
    ping: impl FnOnce() -> Result<Measured, String>,
    mut progress: impl FnMut(&str),
) -> Report {
    let Settings {
        samples,
        interval,
        blocked,
        wait,
    } = *settings;
    let mut rows = Vec::with_capacity(4);

    progress("icmp");
    rows.push(Row {
        name: "icmp",
        result: ping(),
    });

    progress("dns cached");
    // One warm-up question, not counted: the Pi has the answer when the samples begin.
    let _ = ask(dns, CACHED_NAME, TYPE_A, wait);
    rows.push(Row {
        name: "dns cached",
        result: Ok(dns_row(dns, wait, samples, interval, |_| {
            CACHED_NAME.to_owned()
        })),
    });

    progress("dns blocked");
    // The check of the name is the warm-up.
    let found = match blocked {
        Some(name) => find_blocked(dns, wait, &[name]).map_err(|seen| {
            format!("the name given with --blocked did not answer as blocked ({seen})")
        }),
        None => find_blocked(dns, wait, &BLOCKED_CANDIDATES).map_err(|seen| {
            format!(
                "none of the built-in names answered as blocked ({seen}); \
                 name one the Pi blocks with --blocked <name>"
            )
        }),
    };
    let (blocked_name, result) = match found {
        Ok(name) => {
            let row = dns_row(dns, wait, samples, interval, |_| name.clone());
            (Some(name), Ok(row))
        }
        Err(error) => (None, Err(error)),
    };
    rows.push(Row {
        name: "dns blocked",
        result,
    });

    progress("dns forwarded");
    rows.push(Row {
        name: "dns forwarded",
        result: Ok(dns_row(dns, wait, samples, interval, forwarded_name)),
    });

    Report {
        unix_secs,
        samples_asked: samples,
        interval_ms: u64::try_from(interval.as_millis()).unwrap_or(u64::MAX),
        blocked_name,
        rows,
    }
}

/// The IPv4 address named by the value of a `hostname` line of `ssh -G` output.
fn parse_ssh_hostname(config: &str) -> Option<String> {
    config.lines().find_map(|line| {
        let (key, value) = line.split_once(' ')?;
        (key == "hostname").then(|| value.trim().to_owned())
    })
}

/// The `hostname` that the SSH configuration has for `host`. `ssh -G` only reads the
/// configuration and prints it; it connects to nothing.
fn ssh_hostname(host: &str) -> Option<String> {
    let output = Command::new("ssh")
        .arg("-G")
        .arg(host)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_ssh_hostname(&String::from_utf8_lossy(&output.stdout))
}

/// The first IPv4 address this machine's resolver has for `name`.
fn system_lookup(name: &str) -> Option<Ipv4Addr> {
    (name, 0u16)
        .to_socket_addrs()
        .ok()?
        .find_map(|addr| match addr.ip() {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
}

/// The Pi's IPv4 address from what the user gave as `--host`: an address as it is; anything else
/// is an SSH alias or a host name. `ssh_hostname` gives the `hostname` the SSH configuration has
/// for it, which is used if it is an address, and otherwise resolved by this machine's resolver.
/// Without an answer from ssh, the name itself is resolved. No guess and no default: if none of
/// that gives an IPv4 address, it is an error.
pub fn resolve_host(host: &str, ssh_hostname: impl Fn(&str) -> Option<String>) -> Result<Ipv4Addr> {
    resolve_host_with(host, ssh_hostname, system_lookup)
}

fn resolve_host_with(
    host: &str,
    ssh_hostname: impl Fn(&str) -> Option<String>,
    lookup: impl Fn(&str) -> Option<Ipv4Addr>,
) -> Result<Ipv4Addr> {
    if let Ok(address) = host.parse::<Ipv4Addr>() {
        return Ok(address);
    }
    let unresolved = |why: &str| {
        anyhow!(
            "the host {host} could not be resolved to an IPv4 address ({why}); \
             give --host an IPv4 address"
        )
    };
    // Never let a name be taken for an option of ssh.
    if host.starts_with('-') {
        return Err(unresolved("it is not a host name"));
    }
    match ssh_hostname(host) {
        Some(name) => name
            .parse::<Ipv4Addr>()
            .ok()
            .or_else(|| lookup(&name))
            .ok_or_else(|| unresolved(&format!("the SSH configuration names it {name}"))),
        None => lookup(host).ok_or_else(|| {
            unresolved("ssh gave no host name for it and this machine's resolver does not know it")
        }),
    }
}

/// The Pi: `host` if given, else `net.address` of `<root>/qberrypi.toml`.
fn target_address(
    host: Option<&str>,
    ssh_hostname: impl Fn(&str) -> Option<String>,
    root: &Path,
) -> Result<Ipv4Addr> {
    match host {
        Some(host) => resolve_host(host, ssh_hostname),
        None => configured_address(root, "--host <ssh-alias-or-address>"),
    }
}

/// Milliseconds with two decimals, or `-` for no figure.
fn figure(time: Option<Duration>) -> String {
    match time {
        Some(time) => format!("{:.2}", time.as_secs_f64() * 1000.0),
        None => "-".to_owned(),
    }
}

fn header_line() -> String {
    format!(
        "{:<16}{:>7}{:>6}{:>7}{:>8}{:>8}{:>8}{:>8}",
        "row", "samples", "lost", "failed", "p50", "p95", "min", "mean"
    )
}

fn row_line(name: &str, stats: &RowStats) -> String {
    format!(
        "{:<16}{:>7}{:>6}{:>7}{:>8}{:>8}{:>8}{:>8}",
        name,
        stats.samples,
        stats.lost,
        stats.failed,
        figure(stats.p50),
        figure(stats.p95),
        figure(stats.min),
        figure(stats.mean),
    )
}

/// The plain text of a report: the zones, the blocked name, the table, one line when a DNS row
/// lost a sample (the table's figures count it; the line also says so when a row had SERVFAIL or
/// REFUSED answers, which count as lost), and one line for each row that lost a sample to a
/// socket error.
pub fn render_text(report: &Report) -> String {
    let mut text = format!(
        "latency: forwarded zones: {}\nlatency: blocked name: {}\n{}\n",
        FORWARDED_ZONES.join(", "),
        report.blocked_name.as_deref().unwrap_or("-"),
        header_line()
    );
    for row in &report.rows {
        match &row.result {
            Ok(measured) => text.push_str(&row_line(row.name, &measured.stats)),
            Err(error) => text.push_str(&format!("{:<16}error: {error}", row.name)),
        }
        text.push('\n');
    }
    // Every DNS row waits as long as the others, so one line says it for all.
    let counted = report.rows.iter().find_map(|row| match &row.result {
        Ok(Measured { stats, .. }) if stats.lost > 0 => stats.lost_as,
        _ => None,
    });
    if let Some(wait) = counted {
        let any_failed = report.rows.iter().any(|row| match &row.result {
            Ok(measured) => measured.stats.failed > 0,
            Err(_) => false,
        });
        let failed_note = if any_failed {
            "; a SERVFAIL or REFUSED answer counts as lost too, and is counted in failed"
        } else {
            ""
        };
        text.push_str(&format!(
            "latency: lost answers count as {} ms in p50, p95 and mean (icmp: received \
             only){failed_note}\n",
            figure_ms(wait)
        ));
    }
    for row in &report.rows {
        if let Ok(Measured {
            first_error: Some(error),
            ..
        }) = &row.result
        {
            text.push_str(&format!(
                "latency: {}: first socket error: {error}\n",
                row.name
            ));
        }
    }
    text
}

/// A duration in milliseconds as plain text: whole when it is whole, else with its decimals.
fn figure_ms(time: Duration) -> String {
    let ms = time.as_secs_f64() * 1000.0;
    if ms.fract() == 0.0 {
        format!("{ms:.0}")
    } else {
        format!("{ms}")
    }
}

/// Milliseconds rounded to two decimals as a JSON number, or null.
fn json_ms(time: Option<Duration>) -> Value {
    match time {
        Some(time) => json!((time.as_secs_f64() * 100_000.0).round() / 100.0),
        None => Value::Null,
    }
}

/// The received-only figures as a JSON object.
fn received_json(received: &Figures) -> Value {
    json!({
        "p50_ms": json_ms(received.p50),
        "p95_ms": json_ms(received.p95),
        "min_ms": json_ms(received.min),
        "mean_ms": json_ms(received.mean),
    })
}

/// A report as one JSON object. It holds no address, host name or alias.
///
/// A DNS row's `p50_ms`, `p95_ms` and `mean_ms` count a lost sample as `lost_counted_as_ms`; the
/// icmp row and an error row have `null` there and figures of the received samples alone. Every
/// row also holds those received-only figures under `received`. A file without
/// `lost_counted_as_ms` on its rows was written before lost answers were counted. `failed` is how
/// many of `lost` were SERVFAIL or REFUSED answers (0 on the icmp row); a file without it does not
/// know.
pub fn render_json(report: &Report) -> Value {
    let rows: Vec<Value> = report
        .rows
        .iter()
        .map(|row| {
            let (stats, first_error, error) = match &row.result {
                Ok(measured) => (measured.stats.clone(), measured.first_error.as_ref(), None),
                Err(error) => (stats(&[], 0, None), None, Some(error)),
            };
            let mut object = json!({
                "row": row.name,
                "samples": stats.samples,
                "lost": stats.lost,
                "failed": stats.failed,
                "p50_ms": json_ms(stats.p50),
                "p95_ms": json_ms(stats.p95),
                "min_ms": json_ms(stats.min),
                "mean_ms": json_ms(stats.mean),
                "lost_counted_as_ms": json_ms(stats.lost_as),
                "received": received_json(&stats.received),
            });
            if let Some(error) = first_error {
                object["first_socket_error"] = json!(error);
            }
            if let Some(error) = error {
                object["error"] = json!(error);
            }
            object
        })
        .collect();
    json!({
        "unix_secs": report.unix_secs,
        "samples_asked": report.samples_asked,
        "interval_ms": report.interval_ms,
        "blocked_name": report.blocked_name,
        "forwarded_zones": FORWARDED_ZONES,
        "rows": rows,
    })
}

/// How two files written with `--json` compare, as `compare_reports` finds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comparison {
    /// What to print: the files, the notes, the table and a closing line.
    pub text: String,
    /// How many figures were compared; a figure that one of the files does not have is not.
    pub compared: usize,
    /// How many of them were slower in B than in A.
    pub slower: usize,
    /// How many figures A has that B does not: a figure of a row that B has, but cannot give, or
    /// the figures of a row B lacks. A comparison that leaves one out proves nothing about it.
    pub missing: usize,
    /// How many figures B has that A does not: a figure of a row that A has, but cannot give (an
    /// error row), or the figures of a row A lacks. A baseline that is missing one is no baseline.
    pub no_baseline: usize,
    /// Whether A and B (in that order) have a DNS row written before lost answers were counted,
    /// one without `lost_counted_as_ms`. Never so under `received_only`, which reads such files on
    /// purpose.
    pub old_rule: [bool; 2],
    /// Each of `interval_ms` and `samples_asked` that is not the same in both files, with A's and
    /// B's value, `None` for a file that does not say: the passes are not like for like.
    pub pacing: Vec<(&'static str, Option<u64>, Option<u64>)>,
}

/// A count that a file may not have, as text.
fn count_cell(count: Option<u64>) -> String {
    count.map_or_else(|| "?".to_owned(), |n| n.to_string())
}

/// Why a comparison fails, in words, or `None` when it does not: a file was written under the
/// old rule, the pacing differs, some figure is slower in B, some figure of A is not known in B,
/// or some figure of B is not known in A. `a` and `b` are what the sentence calls the files.
fn failure_words(c: &Comparison, a: &str, b: &str) -> Option<String> {
    let mut reasons = Vec::new();
    for (name, old) in [(a, c.old_rule[0]), (b, c.old_rule[1])] {
        if old {
            reasons.push(format!(
                "{name} was written before lost answers were counted: re-run that pass, \
                 or pass --received-only to read it anyway"
            ));
        }
    }
    for (key, x, y) in &c.pacing {
        reasons.push(format!(
            "{key} differs ({a} {}, {b} {})",
            count_cell(*x),
            count_cell(*y)
        ));
    }
    if c.slower > 0 {
        reasons.push(format!(
            "{} of {} compared figures are slower in {b}",
            c.slower, c.compared
        ));
    }
    if c.missing > 0 {
        let (noun, verb) = if c.missing == 1 {
            ("figure", "is")
        } else {
            ("figures", "are")
        };
        reasons.push(format!(
            "{} {noun} of {a} {verb} not known in {b}",
            c.missing
        ));
    }
    if c.no_baseline > 0 {
        let (noun, verb) = if c.no_baseline == 1 {
            ("figure", "has")
        } else {
            ("figures", "have")
        };
        reasons.push(format!(
            "{} {noun} of {b} {verb} no figure in {a} (an incomplete baseline)",
            c.no_baseline
        ));
    }
    (!reasons.is_empty()).then(|| reasons.join("; "))
}

/// The two percentiles a comparison is made on: the label, and the key in a row.
const COMPARED_FIGURES: [(&str, &str); 2] = [("p50", "p50_ms"), ("p95", "p95_ms")];

/// The key that tells a row was written under the rule that counts lost answers.
const COUNTED_KEY: &str = "lost_counted_as_ms";

/// The rows that the rule on lost answers applies to; the icmp row never has it.
const DNS_ROWS: [&str; 3] = ["dns cached", "dns blocked", "dns forwarded"];

fn rows_of(report: &Value) -> &[Value] {
    report
        .get("rows")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn row_name(row: &Value) -> Option<&str> {
    row.get("row")?.as_str()
}

/// Whether the file has a DNS row that was written before lost answers were counted.
fn has_old_rule_row(report: &Value) -> bool {
    rows_of(report).iter().any(|row| {
        row_name(row).is_some_and(|name| DNS_ROWS.contains(&name)) && row.get(COUNTED_KEY).is_none()
    })
}

/// The figure `key` of a row as it stands at its top level, which holds the counted figures in a
/// file that has `lost_counted_as_ms` and the received-only ones in a file that has not.
fn top_figure(row: &Value, key: &str) -> Option<f64> {
    row.get(key)?.as_f64()
}

/// The figure `key` of a row from its received samples alone: the `received` object of a new
/// file; the top level of an old one, which always was received-only. A new file without a
/// `received` object does not know it.
fn received_figure(row: &Value, key: &str) -> Option<f64> {
    match row.get("received") {
        Some(received) if received.is_object() => received.get(key)?.as_f64(),
        _ if row.get(COUNTED_KEY).is_none() => top_figure(row, key),
        _ => None,
    }
}

/// A figure in milliseconds with two decimals, or `-` when it is not known.
fn ms_cell(figure: Option<f64>) -> String {
    figure.map_or_else(|| "-".to_owned(), |ms| format!("{ms:.2}"))
}

/// The note on a DNS row whose lost and failed counts are not the same in both files, which shows
/// how much each pass lost and how much of that was SERVFAIL or REFUSED; `None` when they are the
/// same. It carries no verdict. A file without `failed` does not know it.
fn counts_note(name: &str, a: (&str, &Value), b: (&str, &Value)) -> Option<String> {
    let counts = |row: &Value| {
        let count = |key: &str| row.get(key).and_then(Value::as_u64);
        (count("lost"), count("failed"))
    };
    let (counts_a, counts_b) = (counts(a.1), counts(b.1));
    (counts_a != counts_b).then(|| {
        format!(
            "latency: {name}: lost {} (failed {}) in {}, lost {} (failed {}) in {}\n",
            count_cell(counts_a.0),
            count_cell(counts_a.1),
            a.0,
            count_cell(counts_b.0),
            count_cell(counts_b.1),
            b.0
        )
    })
}

/// `B` against `A` over what two reports hold (`render_json`'s objects; old files too, which
/// lack `lost_counted_as_ms`, `received` and `failed`). `a_name` and `b_name` are what the text
/// calls the files. Each row that both have, in A's order, is compared on p50 and p95: `ok` when B
/// is no greater than A, `slower` when it is. When both rows have a `lost_counted_as_ms` that is
/// not null, the figures are the top-level ones, which count lost answers; otherwise the
/// received-only figures of both (the icmp row, which counts none, is always read that way), and
/// the text says which file was written before lost answers were counted. With `received_only`
/// the received-only figures are read on every row, on purpose, and old files are allowed; the
/// text then says this is not the acceptance comparison.
///
/// Where a DNS row has `lost` or `failed` counts that differ between the files, a note says so,
/// with no verdict.
///
/// The comparison fails (see `failure_words`) when a figure is slower in B; when a figure of A is
/// not known in B, or one of B is not known in A (a row that is an error row or missing on one
/// side: acceptance needs p50 and p95 on every row, from a complete baseline); when
/// `interval_ms` or `samples_asked` is not the same in both files; and, unless `received_only`,
/// when a file has a DNS row written before lost answers were counted.
pub fn compare_reports(
    a_name: &str,
    a: &Value,
    b_name: &str,
    b: &Value,
    received_only: bool,
) -> Comparison {
    let mut text = String::new();
    let number = |report: &Value, key: &str| report.get(key).and_then(Value::as_u64);
    for (label, name, report) in [("A", a_name, a), ("B", b_name, b)] {
        let shown = |key: &str, unit: &str| {
            number(report, key).map_or_else(|| "?".to_owned(), |n| format!("{n}{unit}"))
        };
        text.push_str(&format!(
            "latency: {label} = {name}: {} samples asked, interval {}\n",
            shown("samples_asked", ""),
            shown("interval_ms", " ms"),
        ));
        if rows_of(report).is_empty() {
            text.push_str(&format!(
                "latency: {name}: no rows; is it a file written with --json?\n"
            ));
        }
    }
    if received_only {
        text.push_str(
            "latency: --received-only: lost answers are left out of every figure, in both \
             files (a file without `failed` still times its SERVFAIL and REFUSED answers as \
             received); this is not the acceptance comparison\n",
        );
    }
    let pacing: Vec<_> = ["interval_ms", "samples_asked"]
        .into_iter()
        .filter_map(|key| {
            let (x, y) = (number(a, key), number(b, key));
            (x != y).then_some((key, x, y))
        })
        .collect();
    for (key, x, y) in &pacing {
        text.push_str(&format!(
            "latency: {key} differs (A {}, B {}): the passes are not like for like\n",
            count_cell(*x),
            count_cell(*y)
        ));
    }
    let old_rule = if received_only {
        [false, false]
    } else {
        [has_old_rule_row(a), has_old_rule_row(b)]
    };

    let mut table = Vec::new();
    let mut notes = Vec::new();
    let (mut compared, mut slower, mut missing, mut no_baseline, mut unknown) = (0, 0, 0, 0, 0);
    for row_a in rows_of(a) {
        let Some(name) = row_name(row_a) else {
            continue;
        };
        let Some(row_b) = rows_of(b).iter().find(|row| row_name(row) == Some(name)) else {
            // Which of A's figures count is read at the top level, which is all that is known
            // without the other row.
            let lost = COMPARED_FIGURES
                .iter()
                .filter(|(_, key)| top_figure(row_a, key).is_some())
                .count();
            missing += lost;
            notes.push(match lost {
                0 => format!("latency: {name}: not in {b_name}, skipped\n"),
                1 => format!(
                    "latency: {name}: not in {b_name}, so 1 figure of {a_name} is not known there\n"
                ),
                n => format!(
                    "latency: {name}: not in {b_name}, so {n} figures of {a_name} are not known there\n"
                ),
            });
            continue;
        };
        if DNS_ROWS.contains(&name)
            && let Some(note) = counts_note(name, (a_name, row_a), (b_name, row_b))
        {
            notes.push(note);
        }
        // One choice of figures and of its label: the top-level figures, which count lost
        // answers, when both rows have the rule; the received-only figures otherwise.
        let lost_counted = !received_only
            && [row_a, row_b]
                .iter()
                .all(|row| row.get(COUNTED_KEY).is_some_and(|rule| !rule.is_null()));
        for (figure, key) in COMPARED_FIGURES {
            let (x, y) = if lost_counted {
                (top_figure(row_a, key), top_figure(row_b, key))
            } else {
                (received_figure(row_a, key), received_figure(row_b, key))
            };
            let verdict = match (x, y) {
                (Some(x), Some(y)) => {
                    compared += 1;
                    if y <= x {
                        "ok"
                    } else {
                        slower += 1;
                        "slower"
                    }
                }
                (Some(_), None) => {
                    missing += 1;
                    "missing"
                }
                (None, Some(_)) => {
                    no_baseline += 1;
                    "unknown"
                }
                (None, None) => {
                    unknown += 1;
                    "unknown"
                }
            };
            let basis = match (x, y) {
                (Some(_), Some(_)) if lost_counted => "lost answers counted",
                (Some(_), Some(_)) => "received only",
                _ => "-",
            };
            table.push(format!(
                "{name:<16}{figure:<8}{:>10}{:>10}  {verdict:<9}{basis}\n",
                ms_cell(x),
                ms_cell(y),
            ));
        }
    }
    for row_b in rows_of(b) {
        if let Some(name) = row_name(row_b)
            && !rows_of(a).iter().any(|row| row_name(row) == Some(name))
        {
            let lost = COMPARED_FIGURES
                .iter()
                .filter(|(_, key)| top_figure(row_b, key).is_some())
                .count();
            no_baseline += lost;
            notes.push(match lost {
                0 => format!("latency: {name}: not in {a_name}, skipped\n"),
                1 => format!(
                    "latency: {name}: not in {a_name}, so 1 figure of {b_name} has no baseline\n"
                ),
                n => format!(
                    "latency: {name}: not in {a_name}, so {n} figures of {b_name} have no baseline\n"
                ),
            });
        }
    }

    for (name, is_old) in [(a_name, old_rule[0]), (b_name, old_rule[1])] {
        if is_old {
            text.push_str(&format!(
                "latency: {name}: its DNS rows lack lost_counted_as_ms, so received-only \
                 figures are compared\n"
            ));
        }
    }
    text.push_str(&format!(
        "{:<16}{:<8}{:>10}{:>10}  {:<9}basis\n",
        "row", "figure", "A (ms)", "B (ms)", "verdict"
    ));
    for line in table {
        text.push_str(&line);
    }
    for note in notes {
        text.push_str(&note);
    }
    let mut comparison = Comparison {
        text,
        compared,
        slower,
        missing,
        no_baseline,
        old_rule,
        pacing,
    };
    let not_known = match unknown {
        0 => String::new(),
        n => format!(" ({n} not known in either file, not compared)"),
    };
    let closing = match failure_words(&comparison, "A", "B") {
        Some(words) => format!("latency: {words}{not_known}\n"),
        None => format!("latency: all {compared} compared figures are ok{not_known}\n"),
    };
    comparison.text.push_str(&closing);
    comparison
}

/// What the text calls a file: its name, or its whole path when both files have the same name.
fn file_labels(a: &Path, b: &Path) -> (String, String) {
    let name = |path: &Path| {
        path.file_name()
            .map(|name| name.to_string_lossy().into_owned())
    };
    match (name(a), name(b)) {
        (Some(x), Some(y)) if x != y => (x, y),
        _ => (a.display().to_string(), b.display().to_string()),
    }
}

/// `cargo xtask latency --compare`: reads the two files written with `--json` and prints B
/// against A (see `compare_reports`). It fails once everything is printed when a figure is
/// slower in B, when a figure is known in one file and not in the other, when the pacing differs,
/// when a file was written before lost answers were counted (unless `received_only`), or when no
/// figure could be compared at all.
pub fn compare(a: &Path, b: &Path, received_only: bool) -> Result<()> {
    let read = |path: &Path| -> Result<Value> {
        let bytes = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
        serde_json::from_slice(&bytes)
            .with_context(|| format!("{} is not a JSON file", path.display()))
    };
    let (report_a, report_b) = (read(a)?, read(b)?);
    let (a_name, b_name) = file_labels(a, b);
    let comparison = compare_reports(&a_name, &report_a, &b_name, &report_b, received_only);
    print!("{}", comparison.text);
    if let Some(words) = failure_words(&comparison, &a_name, &b_name) {
        bail!("{words}");
    }
    if comparison.compared == 0 {
        bail!("no figure could be compared: the two files have no p50 or p95 for a row in common");
    }
    Ok(())
}

/// `cargo xtask latency`: measures the Pi named by `host` (or by `net.address` of the
/// configuration under `root`), prints the table and, with `json`, writes the figures there. A
/// row that could not be measured does not stop the others; it makes the command fail once
/// everything is printed.
pub fn run(
    host: Option<&str>,
    samples: usize,
    interval: Duration,
    blocked: Option<&str>,
    json: Option<&Path>,
    root: &Path,
) -> Result<()> {
    if samples == 0 {
        bail!("--samples must be at least 1");
    }
    let address = target_address(host, ssh_hostname, root)?;
    let settings = Settings {
        samples,
        interval,
        blocked,
        wait: LOST_AFTER,
    };
    let report = measure(
        SocketAddr::new(IpAddr::V4(address), DNS_PORT),
        &settings,
        crate::unix_time()?,
        || ping_row(address, samples, interval),
        |row| eprintln!("latency: measuring {row} ..."),
    );
    print!("{}", render_text(&report));
    if let Some(path) = json {
        let mut text = serde_json::to_string_pretty(&render_json(&report))?;
        text.push('\n');
        fs::write(path, text).with_context(|| format!("cannot write {}", path.display()))?;
    }
    let failed = report.rows.iter().filter(|row| row.result.is_err()).count();
    if failed > 0 {
        bail!(
            "{failed} of {} rows could not be measured",
            report.rows.len()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::UdpSocket;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Instant;

    use hickory_proto::op::Message;
    use qberrypi::dns::client::query;

    const FAKE_ADDR: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 9);

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn loopback() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 0))
    }

    /// The name of the first question in `packet`, dotted, without the final dot.
    fn asked_name(packet: &[u8]) -> String {
        let message = Message::from_vec(packet).unwrap();
        let name = message.queries[0].name.to_ascii();
        name.trim_end_matches('.').to_owned()
    }

    fn id_of(packet: &[u8]) -> u16 {
        u16::from_be_bytes([packet[0], packet[1]])
    }

    /// A response to `query`: its ID and question, the response flag, `rcode`, and one A record
    /// when `addr` is given.
    fn reply(query: &[u8], rcode: u8, addr: Option<Ipv4Addr>) -> Vec<u8> {
        let mut reply = query.to_vec();
        reply[2] = 0x81;
        reply[3] = 0x80 | rcode;
        if let Some(addr) = addr {
            reply[6..8].copy_from_slice(&[0, 1]);
            reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4]);
            reply.extend_from_slice(&addr.octets());
        }
        reply
    }

    fn with_id(mut packet: Vec<u8>, id: u16) -> Vec<u8> {
        packet[0..2].copy_from_slice(&id.to_be_bytes());
        packet
    }

    /// A UDP server on a thread. For every datagram it records the name asked, then sends what
    /// `script(query, n)` says — each packet after its delay — where `n` counts the queries
    /// from 0. An empty list drops the question.
    struct FakeDns {
        addr: SocketAddr,
        asked: Arc<Mutex<Vec<String>>>,
        stop: Arc<AtomicBool>,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl FakeDns {
        fn start(
            script: impl Fn(&[u8], usize) -> Vec<(Duration, Vec<u8>)> + Send + 'static,
        ) -> FakeDns {
            let socket = UdpSocket::bind(loopback()).unwrap();
            socket.set_read_timeout(Some(ms(10))).unwrap();
            let addr = socket.local_addr().unwrap();
            let asked = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let (log, flag) = (asked.clone(), stop.clone());
            let thread = thread::spawn(move || {
                let mut buf = [0u8; 512];
                while !flag.load(Ordering::Relaxed) {
                    let Ok((n, from)) = socket.recv_from(&mut buf) else {
                        continue;
                    };
                    let query = buf[..n].to_vec();
                    let nth = {
                        let mut log = log.lock().unwrap();
                        log.push(asked_name(&query));
                        log.len() - 1
                    };
                    for (delay, packet) in script(&query, nth) {
                        thread::sleep(delay);
                        socket.send_to(&packet, from).unwrap();
                    }
                }
            });
            FakeDns {
                addr,
                asked,
                stop,
                thread: Some(thread),
            }
        }

        fn asked(&self) -> Vec<String> {
            self.asked.lock().unwrap().clone()
        }
    }

    impl Drop for FakeDns {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(thread) = self.thread.take() {
                // A panic on the thread shows on stderr; joining must not panic in a panic.
                let _ = thread.join();
            }
        }
    }

    /// A server that answers every question NXDOMAIN at once.
    fn nxdomain_server() -> FakeDns {
        FakeDns::start(|q, _| vec![(Duration::ZERO, reply(q, 3, None))])
    }

    // ask

    #[test]
    fn ask_measures_at_least_the_servers_delay_and_returns_the_rcode() {
        let fake = FakeDns::start(|q, _| vec![(ms(40), reply(q, 3, None))]);
        let (took, rcode) = ask(fake.addr, "example.com", 1, Duration::from_secs(2))
            .unwrap()
            .unwrap();
        assert_eq!(rcode, 3);
        assert!(took >= ms(40), "{took:?}");
        assert!(took < Duration::from_secs(1), "{took:?}");
    }

    #[test]
    fn a_dropped_question_is_lost_after_the_wait_and_the_next_is_answered() {
        let fake = FakeDns::start(|q, nth| {
            if nth == 0 {
                Vec::new()
            } else {
                vec![(Duration::ZERO, reply(q, 0, Some(FAKE_ADDR)))]
            }
        });
        let started = Instant::now();
        let lost = ask(fake.addr, "example.com", 1, ms(200)).unwrap();
        assert_eq!(lost, None);
        assert!(started.elapsed() >= ms(200));
        let (_, rcode) = ask(fake.addr, "example.com", 1, ms(200)).unwrap().unwrap();
        assert_eq!(rcode, 0);
    }

    #[test]
    fn datagrams_that_are_not_the_answer_are_ignored_and_the_wait_goes_on() {
        // Every wrong datagram says SERVFAIL (2); the answer says NXDOMAIN (3).
        let fake = FakeDns::start(|q, _| {
            let id = id_of(q);
            let mut other_type = reply(q, 2, None);
            let n = other_type.len();
            other_type[n - 4..n - 2].copy_from_slice(&[0, 28]);
            let mut other_class = reply(q, 2, None);
            other_class[n - 2..n].copy_from_slice(&[0, 3]);
            let mut no_question = reply(q, 2, None)[..12].to_vec();
            no_question[4..6].copy_from_slice(&[0, 0]);
            // The same answer as the real one, but written as a server that keeps the case of
            // the name the way 0x20 randomisation expects it.
            let mut shouted = reply(q, 3, None);
            for byte in &mut shouted[12..] {
                *byte = byte.to_ascii_uppercase();
            }
            vec![
                (Duration::ZERO, vec![1, 2, 3]),
                (Duration::ZERO, with_id(reply(q, 2, None), id ^ 0xffff)),
                (
                    Duration::ZERO,
                    reply(&query(id, "other.invalid", 1).unwrap(), 2, None),
                ),
                (Duration::ZERO, other_type),
                (Duration::ZERO, other_class),
                (Duration::ZERO, no_question),
                // Our own question, echoed: not a response.
                (Duration::ZERO, q.to_vec()),
                (ms(30), shouted),
            ]
        });
        let (took, rcode) = ask(fake.addr, "example.com", 1, Duration::from_secs(2))
            .unwrap()
            .unwrap();
        assert_eq!(rcode, 3);
        assert!(took >= ms(30), "{took:?}");
    }

    #[test]
    fn a_refusing_port_is_an_error_not_a_loss() {
        let closed = {
            let socket = UdpSocket::bind(loopback()).unwrap();
            socket.local_addr().unwrap()
        };
        let err = ask(closed, "example.com", 1, ms(500)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused, "{err}");
    }

    #[test]
    fn a_name_that_cannot_be_encoded_is_an_error() {
        let server = loopback();
        let name = format!("{}.invalid", "a".repeat(64));
        assert!(ask(server, &name, 1, ms(10)).is_err());
    }

    // rows

    #[test]
    fn a_dns_row_counts_received_and_lost() {
        // Every third question is dropped: of six, questions 2 and 5 are lost.
        let fake = FakeDns::start(|q, nth| {
            if nth % 3 == 2 {
                Vec::new()
            } else {
                vec![(Duration::ZERO, reply(q, 3, None))]
            }
        });
        let row = dns_row(fake.addr, ms(100), 6, Duration::ZERO, |i| {
            format!("name{i}.invalid")
        });
        assert_eq!(row.stats.samples, 4);
        assert_eq!(row.stats.lost, 2);
        // Missing answers are lost, not failed: NXDOMAIN is an answer.
        assert_eq!(row.stats.failed, 0);
        assert_eq!(row.first_error, None);
        // Two of six are lost, so the p95 (the 6th of six) is a lost one, counted as the wait the
        // row used; the median (the 3rd) is a received answer, far below it.
        assert_eq!(row.stats.lost_as, Some(ms(100)));
        assert_eq!(row.stats.p95, Some(ms(100)));
        assert!(row.stats.p50.unwrap() < ms(100), "{:?}", row.stats.p50);
        assert!(row.stats.received.p95.unwrap() < ms(100));
        assert!(row.stats.min.unwrap() < ms(100));
        assert_eq!(
            fake.asked(),
            [
                "name0.invalid",
                "name1.invalid",
                "name2.invalid",
                "name3.invalid",
                "name4.invalid",
                "name5.invalid"
            ]
        );
    }

    #[test]
    fn a_servfail_answer_is_lost_and_failed_and_counts_as_the_wait() {
        // Every second question is answered SERVFAIL at once, the others NXDOMAIN at once.
        let fake = FakeDns::start(|q, nth| {
            let rcode = if nth % 2 == 1 { 2 } else { 3 };
            vec![(Duration::ZERO, reply(q, rcode, None))]
        });
        let row = dns_row(fake.addr, ms(100), 6, Duration::ZERO, |i| {
            format!("name{i}.invalid")
        });
        let stats = &row.stats;
        assert_eq!((stats.samples, stats.lost, stats.failed), (3, 3, 3));
        assert_eq!(row.first_error, None);
        // The SERVFAILs came at once, yet they count as the wait, like a missing answer: the p95
        // (the 6th of six) is the wait, the p50 (the 3rd) is the slowest NXDOMAIN, and the mean
        // holds three waits in six.
        assert_eq!(stats.lost_as, Some(ms(100)));
        assert_eq!(stats.p95, Some(ms(100)));
        assert!(stats.p50.unwrap() < ms(100), "{:?}", stats.p50);
        assert!(stats.mean.unwrap() >= ms(50), "{:?}", stats.mean);
        assert!(stats.received.p95.unwrap() < ms(100));
        assert!(stats.min.unwrap() < ms(100));
    }

    #[test]
    fn refused_counts_like_servfail_and_noerror_and_nxdomain_stay_answers() {
        // Per four questions: NOERROR, NXDOMAIN, REFUSED, SERVFAIL.
        let fake = FakeDns::start(|q, nth| {
            let packet = match nth % 4 {
                0 => reply(q, 0, Some(FAKE_ADDR)),
                1 => reply(q, 3, None),
                2 => reply(q, 5, None),
                _ => reply(q, 2, None),
            };
            vec![(Duration::ZERO, packet)]
        });
        let row = dns_row(fake.addr, ms(100), 8, Duration::ZERO, |i| {
            format!("name{i}.invalid")
        });
        let stats = &row.stats;
        assert_eq!((stats.samples, stats.lost, stats.failed), (4, 4, 4));
        // Half the samples count as the wait: the p95 is the wait, the p50 the slowest answer.
        assert_eq!(stats.p95, Some(ms(100)));
        assert!(stats.p50.unwrap() < ms(100), "{:?}", stats.p50);
        // With every answer SERVFAIL or REFUSED there is nothing received, and everything is the
        // wait.
        let all = FakeDns::start(|q, nth| {
            vec![(
                Duration::ZERO,
                reply(q, if nth % 2 == 0 { 5 } else { 2 }, None),
            )]
        });
        let row = dns_row(all.addr, ms(100), 4, Duration::ZERO, |i| {
            format!("name{i}.invalid")
        });
        let stats = &row.stats;
        assert_eq!((stats.samples, stats.lost, stats.failed), (0, 4, 4));
        assert_eq!(
            (stats.p50, stats.p95, stats.mean, stats.min),
            (Some(ms(100)), Some(ms(100)), Some(ms(100)), None)
        );
    }

    #[test]
    fn a_socket_error_is_lost_too_and_the_first_one_is_kept() {
        let closed = {
            let socket = UdpSocket::bind(loopback()).unwrap();
            socket.local_addr().unwrap()
        };
        let row = dns_row(closed, ms(300), 3, Duration::ZERO, |i| {
            format!("name{i}.invalid")
        });
        assert_eq!(row.stats.samples, 0);
        assert_eq!(row.stats.lost, 3);
        assert!(row.first_error.is_some());
        // Nothing was received, so there is no minimum and no received figure; the three lost
        // samples count as the wait.
        assert_eq!(row.stats.min, None);
        assert_eq!(row.stats.received.p50, None);
        assert_eq!(
            (row.stats.p50, row.stats.p95, row.stats.mean),
            (Some(ms(300)), Some(ms(300)), Some(ms(300)))
        );
    }

    #[test]
    fn the_interval_lies_between_samples_and_not_after_the_last() {
        let fake = nxdomain_server();
        let started = Instant::now();
        let row = dns_row(fake.addr, ms(200), 2, ms(400), |i| format!("n{i}.invalid"));
        let took = started.elapsed();
        assert_eq!(row.stats.samples, 2);
        // One pause between the two samples, not two: a second pause would make it 800 ms, and a
        // loaded test run has 400 ms to spare for the questions themselves.
        assert!(took >= ms(400), "{took:?}");
        assert!(took < ms(800), "{took:?}");
    }

    // measure

    fn settings(samples: usize, blocked: Option<&str>) -> Settings<'_> {
        Settings {
            samples,
            interval: Duration::ZERO,
            blocked,
            wait: ms(300),
        }
    }

    fn fake_ping() -> Result<Measured, String> {
        Ok(Measured {
            stats: stats(&[ms(5), ms(6)], 0, None),
            first_error: None,
        })
    }

    #[test]
    fn the_rows_come_in_order_and_the_blocked_name_is_the_first_candidate_that_blocks() {
        // The first candidate answers with a real address, the second is blocked.
        let (first, second) = (BLOCKED_CANDIDATES[0], BLOCKED_CANDIDATES[1]);
        let fake = FakeDns::start(move |q, _| {
            let name = asked_name(q);
            let packet = if name == CACHED_NAME || name == first {
                reply(q, 0, Some(FAKE_ADDR))
            } else if name == second {
                reply(q, 0, Some(Ipv4Addr::UNSPECIFIED))
            } else {
                reply(q, 3, None)
            };
            vec![(Duration::ZERO, packet)]
        });
        let mut progress = Vec::new();
        let report = measure(
            fake.addr,
            &settings(4, None),
            1_800_000_000,
            fake_ping,
            |what| {
                progress.push(what.to_owned());
            },
        );
        let names: Vec<&str> = report.rows.iter().map(|row| row.name).collect();
        assert_eq!(
            names,
            ["icmp", "dns cached", "dns blocked", "dns forwarded"]
        );
        assert_eq!(progress, names);
        assert_eq!(report.blocked_name.as_deref(), Some(second));
        assert_eq!(report.unix_secs, 1_800_000_000);
        for row in &report.rows[1..] {
            let measured = row.result.as_ref().unwrap();
            assert_eq!((measured.stats.samples, measured.stats.lost), (4, 0));
            // Every DNS row counts a lost answer as the wait of the settings.
            assert_eq!(measured.stats.lost_as, Some(ms(300)));
        }
        assert_eq!(report.rows[0].result.as_ref().unwrap().stats.lost_as, None);
        let asked = fake.asked();
        let mut expected: Vec<String> = Vec::new();
        expected.extend(vec!["example.com".to_owned(); 5]); // the warm-up and four samples
        expected.push(first.to_owned()); // the check that found it is not blocked
        expected.extend(vec![second.to_owned(); 5]); // the check, which is the warm-up, and four
        assert_eq!(asked[..expected.len()], expected[..]);
        let forwarded = &asked[expected.len()..];
        assert_eq!(forwarded.len(), 4);
        for (i, name) in forwarded.iter().enumerate() {
            let zone = FORWARDED_ZONES[i % FORWARDED_ZONES.len()];
            assert!(name.ends_with(&format!(".{zone}")), "{name} under {zone}");
        }
    }

    #[test]
    fn a_failed_ping_row_does_not_stop_the_dns_rows() {
        let fake = nxdomain_server();
        let report = measure(
            fake.addr,
            &settings(2, Some("ads.invalid")),
            1,
            || Err("ping is not installed".to_owned()),
            |_| {},
        );
        assert_eq!(
            report.rows[0].result.as_ref().unwrap_err(),
            "ping is not installed"
        );
        assert!(report.rows[1].result.is_ok());
        assert!(report.rows[3].result.is_ok());
    }

    #[test]
    fn with_no_candidate_blocked_the_blocked_row_is_an_error_naming_the_flag() {
        let fake = nxdomain_server();
        let report = measure(fake.addr, &settings(2, None), 1, fake_ping, |_| {});
        let error = report.rows[2].result.as_ref().unwrap_err();
        assert!(error.contains("--blocked"), "{error}");
        assert!(error.contains("NXDOMAIN"), "{error}");
        assert_eq!(report.blocked_name, None);
        // Each candidate was asked once, and the forwarded row ran after it.
        let asked = fake.asked();
        let candidates = &asked[3..3 + BLOCKED_CANDIDATES.len()];
        assert_eq!(candidates, BLOCKED_CANDIDATES);
        assert!(report.rows[3].result.is_ok());
        assert_eq!(asked.len(), 3 + BLOCKED_CANDIDATES.len() + 2);
    }

    #[test]
    fn the_blocked_flag_names_the_only_name_that_is_tried() {
        let fake = FakeDns::start(|q, _| {
            let packet = if asked_name(q) == "ads.invalid" {
                reply(q, 0, Some(Ipv4Addr::UNSPECIFIED))
            } else {
                reply(q, 3, None)
            };
            vec![(Duration::ZERO, packet)]
        });
        let report = measure(
            fake.addr,
            &settings(2, Some("ads.invalid")),
            1,
            fake_ping,
            |_| {},
        );
        assert_eq!(report.blocked_name.as_deref(), Some("ads.invalid"));
        assert!(report.rows[2].result.is_ok());
        let asked = fake.asked();
        assert!(
            asked
                .iter()
                .all(|name| !BLOCKED_CANDIDATES.contains(&name.as_str()))
        );

        // The same flag on a Pi that answers that name with an address of its own: the error
        // says so without the address.
        let open = FakeDns::start(|q, _| vec![(Duration::ZERO, reply(q, 0, Some(FAKE_ADDR)))]);
        let report = measure(
            open.addr,
            &settings(2, Some("ads.invalid")),
            1,
            fake_ping,
            |_| {},
        );
        let error = report.rows[2].result.as_ref().unwrap_err();
        assert!(
            error.contains("ads.invalid") && error.contains("--blocked"),
            "{error}"
        );
        assert!(error.contains("an address other than 0.0.0.0"), "{error}");
        assert!(!error.contains("127.0.0.9"), "{error}");
        assert_eq!(report.blocked_name, None);
    }

    // statistics

    #[test]
    fn statistics_are_nearest_rank_on_the_received_samples() {
        let mut times: Vec<Duration> = (1..=200).map(ms).collect();
        times.reverse();
        let received_only = Figures {
            p50: Some(ms(100)),
            p95: Some(ms(190)),
            min: Some(ms(1)),
            mean: Some(Duration::from_micros(100_500)),
        };
        assert_eq!(
            stats(&times, 1, None),
            RowStats {
                samples: 200,
                lost: 1,
                failed: 0,
                lost_as: None,
                p50: Some(ms(100)),
                p95: Some(ms(190)),
                min: Some(ms(1)),
                mean: Some(Duration::from_micros(100_500)),
                received: received_only,
            }
        );
        let ten: Vec<Duration> = (1..=10).map(ms).collect();
        let s = stats(&ten, 0, None);
        assert_eq!((s.p50, s.p95), (Some(ms(5)), Some(ms(10))));
        let three = [ms(30), ms(10), ms(20)];
        let s = stats(&three, 0, None);
        assert_eq!(
            (s.p50, s.p95, s.min),
            (Some(ms(20)), Some(ms(30)), Some(ms(10)))
        );
        let one = stats(&[ms(7)], 0, None);
        assert_eq!(
            (one.p50, one.p95, one.mean),
            (Some(ms(7)), Some(ms(7)), Some(ms(7)))
        );
    }

    #[test]
    fn a_lost_sample_counts_as_the_wait_in_p50_p95_and_mean_but_not_in_min() {
        let wait = ms(2000);
        // 1..=190 ms received and ten lost: the 190th of 200 is the largest received answer.
        let received: Vec<Duration> = (1..=190).map(ms).collect();
        let s = stats(&received, 10, Some(wait));
        assert_eq!((s.samples, s.lost, s.lost_as), (190, 10, Some(wait)));
        assert_eq!(s.p50, Some(ms(100)));
        assert_eq!(s.p95, Some(ms(190)));
        assert_eq!(s.min, Some(ms(1)));
        // (1 + ... + 190) ms = 18_145 ms, plus ten times 2000 ms, over 200 samples.
        assert_eq!(s.mean, Some(Duration::from_micros(190_725)));
        // The received-only figures are what the same samples gave without the lost ones.
        assert_eq!(s.received, stats(&received, 10, None).received);
        assert_eq!(s.received.p95, Some(ms(181)));
        assert_eq!(s.received.mean, Some(Duration::from_micros(95_500)));
        assert_eq!(s.received.min, Some(ms(1)));

        // One more lost and one fewer received: the 190th of 200 is a lost one.
        let received: Vec<Duration> = (1..=189).map(ms).collect();
        let s = stats(&received, 11, Some(wait));
        assert_eq!(s.p95, Some(wait));
        assert_eq!(s.p50, Some(ms(100)));
        assert_eq!(s.received.p95, Some(ms(180)));

        // Without `lost_as` nothing changes with the losses.
        let s = stats(&received, 11, None);
        assert_eq!((s.p95, s.mean), (s.received.p95, s.received.mean));
        assert_eq!(s.lost, 11);
    }

    #[test]
    fn with_every_sample_lost_the_figures_are_the_wait_and_there_is_no_minimum() {
        let wait = ms(2000);
        let s = stats(&[], 3, Some(wait));
        assert_eq!(
            s,
            RowStats {
                samples: 0,
                lost: 3,
                failed: 0,
                lost_as: Some(wait),
                p50: Some(wait),
                p95: Some(wait),
                min: None,
                mean: Some(wait),
                received: Figures {
                    p50: None,
                    p95: None,
                    min: None,
                    mean: None,
                },
            }
        );
        // No loss, no change: the rule is still named, and the figures are the received ones.
        let s = stats(&[ms(4), ms(8)], 0, Some(wait));
        assert_eq!(s.lost_as, Some(wait));
        assert_eq!(
            (s.p50, s.p95, s.mean),
            (Some(ms(4)), Some(ms(8)), Some(ms(6)))
        );
    }

    #[test]
    fn no_received_sample_leaves_the_figures_empty_and_keeps_the_lost_count() {
        assert_eq!(
            stats(&[], 3, None),
            RowStats {
                samples: 0,
                lost: 3,
                failed: 0,
                lost_as: None,
                p50: None,
                p95: None,
                min: None,
                mean: None,
                received: Figures {
                    p50: None,
                    p95: None,
                    min: None,
                    mean: None,
                },
            }
        );
    }

    #[test]
    fn the_icmp_row_stays_received_only_whatever_it_lost() {
        // IPUTILS: four replies of five sent. The lost reply is not counted as anything.
        let measured = ping_measured(IPUTILS, "", Ipv4Addr::LOCALHOST).unwrap();
        let s = &measured.stats;
        assert_eq!((s.samples, s.lost, s.lost_as), (4, 1, None));
        assert_eq!(
            (s.p50, s.p95, s.min),
            (
                Some(Duration::from_micros(2490)),
                Some(Duration::from_micros(11_800)),
                Some(Duration::from_micros(345))
            )
        );
        assert_eq!(
            s.received,
            Figures {
                p50: s.p50,
                p95: s.p95,
                min: s.min,
                mean: s.mean
            }
        );
    }

    // ping

    const IPUTILS: &str = "\
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=6.12 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=11.8 ms
64 bytes from 127.0.0.1: icmp_seq=4 ttl=64 time=2.49 ms
64 bytes from 127.0.0.1: icmp_seq=5 ttl=64 time=0.345 ms

--- 127.0.0.1 ping statistics ---
5 packets transmitted, 4 received, 20% packet loss, time 806ms
rtt min/avg/max/mdev = 0.345/5.19/11.8/4.2 ms
";

    #[test]
    fn iputils_output_gives_the_times_and_the_counts() {
        let run = parse_ping(IPUTILS).unwrap();
        assert_eq!(
            run.times,
            [
                Duration::from_micros(6120),
                Duration::from_micros(11_800),
                Duration::from_micros(2490),
                Duration::from_micros(345),
            ]
        );
        assert_eq!((run.transmitted, run.received), (5, 4));
    }

    #[test]
    fn busybox_output_is_read_too() {
        let output = "\
PING 127.0.0.1 (127.0.0.1): 56 data bytes
64 bytes from 127.0.0.1: seq=0 ttl=64 time=6.120 ms
64 bytes from 127.0.0.1: seq=1 ttl=64 time=2.490 ms

--- 127.0.0.1 ping statistics ---
3 packets transmitted, 2 packets received, 33% packet loss
round-trip min/avg/max = 2.490/4.305/6.120 ms
";
        let run = parse_ping(output).unwrap();
        assert_eq!(
            run.times,
            [Duration::from_micros(6120), Duration::from_micros(2490)]
        );
        assert_eq!((run.transmitted, run.received), (3, 2));
    }

    #[test]
    fn duplicates_and_errors_in_the_summary_do_not_confuse_the_counts() {
        let output = "\
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=1.5 ms
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=1.6 ms (DUP!)
From 127.0.0.1 icmp_seq=2 Destination Host Unreachable

--- 127.0.0.1 ping statistics ---
3 packets transmitted, 1 received, +1 duplicates, +1 errors, 66.6667% packet loss, time 405ms
";
        let run = parse_ping(output).unwrap();
        assert_eq!(run.times, [Duration::from_micros(1500)]);
        assert_eq!((run.transmitted, run.received), (3, 1));
    }

    #[test]
    fn a_ping_that_got_no_reply_has_a_summary_and_no_times() {
        let output = "\
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.

--- 127.0.0.1 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 2042ms
";
        let run = parse_ping(output).unwrap();
        assert!(run.times.is_empty());
        assert_eq!((run.transmitted, run.received), (3, 0));
    }

    #[test]
    fn output_without_a_summary_is_not_a_run() {
        assert!(parse_ping("").is_none());
        assert!(parse_ping("ping: connect: Network is unreachable\n").is_none());
        assert!(
            parse_ping("PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=6.12 ms\n")
                .is_none()
        );
    }

    #[test]
    fn a_ping_row_is_the_replies_and_the_difference_of_the_counts() {
        let measured = ping_measured(IPUTILS, "", Ipv4Addr::LOCALHOST).unwrap();
        assert_eq!(measured.stats.samples, 4);
        assert_eq!(measured.stats.lost, 1);
        assert_eq!(measured.stats.min, Some(Duration::from_micros(345)));
        // Without a summary the row is an error; ping's own complaint is in it, and the address
        // is not.
        let error = ping_measured(
            "",
            "ping: connect to 127.0.0.1: Network is unreachable\n",
            Ipv4Addr::LOCALHOST,
        )
        .unwrap_err();
        assert!(error.contains("no summary"), "{error}");
        assert!(error.contains("Network is unreachable"), "{error}");
        assert!(!error.contains("127.0.0.1"), "{error}");
    }

    // the Pi's address

    #[test]
    fn an_ipv4_address_is_used_as_it_is() {
        let ip = resolve_host("127.0.0.2", |_| panic!("ssh must not be asked")).unwrap();
        assert_eq!(ip, Ipv4Addr::new(127, 0, 0, 2));
    }

    #[test]
    fn an_alias_is_looked_up_through_ssh_for_its_hostname() {
        let ip = resolve_host("pi-alias", |host| {
            assert_eq!(host, "pi-alias");
            Some("127.0.0.3".to_owned())
        })
        .unwrap();
        assert_eq!(ip, Ipv4Addr::new(127, 0, 0, 3));
    }

    #[test]
    fn a_hostname_that_is_a_name_is_resolved_by_the_machine() {
        let ip = resolve_host("pi-alias", |_| Some("localhost".to_owned())).unwrap();
        assert_eq!(ip, Ipv4Addr::LOCALHOST);
    }

    #[test]
    fn without_ssh_the_host_itself_is_resolved() {
        let ip = resolve_host("localhost", |_| None).unwrap();
        assert_eq!(ip, Ipv4Addr::LOCALHOST);
    }

    #[test]
    fn a_name_that_resolves_nowhere_is_an_error_that_says_so() {
        let looked_up = Mutex::new(Vec::new());
        let err = resolve_host_with(
            "pi-alias",
            |_| Some("nothing.invalid".to_owned()),
            |name| {
                looked_up.lock().unwrap().push(name.to_owned());
                None
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("could not be resolved"), "{err:#}");
        // The alias itself is not tried once ssh has named the host.
        assert_eq!(*looked_up.lock().unwrap(), ["nothing.invalid"]);
        // And with no ssh, the name the user gave is the one that was tried.
        let err = resolve_host_with("also-nothing.invalid", |_| None, |_| None).unwrap_err();
        assert!(err.to_string().contains("could not be resolved"), "{err:#}");
        assert!(err.to_string().contains("also-nothing.invalid"), "{err:#}");
    }

    #[test]
    fn a_host_that_looks_like_an_option_is_refused_before_ssh_sees_it() {
        let err =
            resolve_host("-oProxyCommand=x", |_| panic!("ssh must not be asked")).unwrap_err();
        assert!(err.to_string().contains("could not be resolved"), "{err:#}");
    }

    #[test]
    fn the_hostname_is_read_from_ssh_g_output() {
        let config = "user someone\nhostname 127.0.0.4\nport 22\nidentityfile ~/.ssh/id\n";
        assert_eq!(parse_ssh_hostname(config).as_deref(), Some("127.0.0.4"));
        assert_eq!(parse_ssh_hostname("user someone\nport 22\n"), None);
        assert_eq!(parse_ssh_hostname(""), None);
    }

    #[test]
    fn without_a_host_the_address_comes_from_the_configuration() {
        let root = tempfile::tempdir().unwrap();
        // A host that is given is used without any file.
        let ip = target_address(Some("127.0.0.2"), |_| None, root.path()).unwrap();
        assert_eq!(ip, Ipv4Addr::new(127, 0, 0, 2));
        // Without it and without a configuration, the error says what to do.
        let err = target_address(None, |_| None, root.path()).unwrap_err();
        assert!(err.to_string().contains("--host"), "{err:#}");
        std::fs::write(
            root.path().join("qberrypi.toml"),
            "[wifi]\nssid = \"example-network\"\npassphrase = \"example-passphrase\"\ncountry = \"US\"\n\
             [net]\naddress = \"127.0.0.5/8\"\ngateway = \"127.0.0.1\"\n\
             [dns]\nupstreams = [\"127.0.0.1\"]\n",
        )
        .unwrap();
        let ip = target_address(None, |_| None, root.path()).unwrap();
        assert_eq!(ip, Ipv4Addr::new(127, 0, 0, 5));
    }

    // the names of the forwarded row

    #[test]
    fn forwarded_names_are_fresh_and_the_zones_rotate() {
        let mut seen = std::collections::HashSet::new();
        for i in 0..600 {
            let name = forwarded_name(i);
            let zone = FORWARDED_ZONES[i % FORWARDED_ZONES.len()];
            let label = name
                .strip_suffix(&format!(".{zone}"))
                .unwrap_or_else(|| panic!("{name} is not under {zone}"));
            assert!(label.len() >= 12, "{label}");
            assert!(
                label
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase()),
                "{label}"
            );
            assert!(seen.insert(name), "a name came twice");
        }
    }

    #[test]
    fn the_forwarded_zones_are_several_distinct_plain_names() {
        assert!(FORWARDED_ZONES.len() >= 4);
        let mut zones: Vec<&str> = FORWARDED_ZONES.to_vec();
        zones.sort();
        zones.dedup();
        assert_eq!(zones.len(), FORWARDED_ZONES.len());
        for zone in FORWARDED_ZONES {
            assert!(!zone.starts_with('.') && !zone.ends_with('.'), "{zone}");
            assert_eq!(zone, zone.to_ascii_lowercase());
            assert!(zone.contains('.'), "{zone}");
            // A name under it must still fit a DNS label plus the zone.
            assert!(zone.len() + 17 <= 253);
        }
    }

    // the output

    #[test]
    fn a_row_line_has_the_columns_of_the_header() {
        assert_eq!(
            header_line(),
            "row             samples  lost failed     p50     p95     min    mean"
        );
        let figures = Figures {
            p50: Some(Duration::from_micros(6120)),
            p95: Some(Duration::from_micros(11_800)),
            min: Some(Duration::from_micros(2490)),
            mean: Some(Duration::from_micros(6930)),
        };
        let icmp = RowStats {
            samples: 200,
            lost: 0,
            failed: 0,
            lost_as: None,
            p50: figures.p50,
            p95: figures.p95,
            min: figures.min,
            mean: figures.mean,
            received: figures,
        };
        assert_eq!(
            row_line("icmp", &icmp),
            "icmp                200     0      0    6.12   11.80    2.49    6.93"
        );
    }

    #[test]
    fn the_failed_column_holds_the_count_of_servfail_and_refused_answers() {
        let row = RowStats {
            failed: 3,
            ..stats(&[ms(5); 7], 5, Some(ms(2000)))
        };
        assert_eq!(
            row_line("dns forwarded", &row),
            "dns forwarded         7     5      3    5.00 2000.00    5.00  836.25"
        );
    }

    #[test]
    fn a_row_with_no_samples_shows_dashes() {
        assert_eq!(
            row_line("icmp", &stats(&[], 200, None)),
            "icmp                  0   200      0       -       -       -       -"
        );
    }

    #[test]
    fn a_dns_row_with_every_sample_lost_shows_the_wait_and_no_minimum() {
        assert_eq!(
            row_line("dns cached", &stats(&[], 200, Some(ms(2000)))),
            "dns cached            0   200      0 2000.00 2000.00       - 2000.00"
        );
    }

    fn sample_report() -> Report {
        let row = |name: &'static str, result| Row { name, result };
        Report {
            unix_secs: 1_800_000_000,
            samples_asked: 200,
            interval_ms: 200,
            blocked_name: Some("doubleclick.net".to_owned()),
            rows: vec![
                row(
                    "icmp",
                    Ok(Measured {
                        stats: stats(&[ms(6), ms(12)], 1, None),
                        first_error: None,
                    }),
                ),
                row(
                    "dns cached",
                    Ok(Measured {
                        stats: stats(&[], 200, Some(ms(2000))),
                        first_error: Some("Connection refused (os error 111)".to_owned()),
                    }),
                ),
                row("dns blocked", Err("no name answered as blocked".to_owned())),
                row(
                    "dns forwarded",
                    Ok(Measured {
                        // Its one lost sample was a SERVFAIL answer.
                        stats: RowStats {
                            failed: 1,
                            ..stats(&[ms(20), ms(30), ms(40)], 1, Some(ms(2000)))
                        },
                        first_error: None,
                    }),
                ),
            ],
        }
    }

    #[test]
    fn the_text_has_two_header_lines_the_table_and_the_notes() {
        let text = render_text(&sample_report());
        let lines: Vec<&str> = text.lines().collect();
        let zones = FORWARDED_ZONES.join(", ");
        assert_eq!(lines[0], format!("latency: forwarded zones: {zones}"));
        assert_eq!(lines[1], "latency: blocked name: doubleclick.net");
        assert_eq!(lines[2], header_line());
        assert_eq!(
            lines[3],
            row_line("icmp", &stats(&[ms(6), ms(12)], 1, None))
        );
        assert_eq!(
            lines[4],
            row_line("dns cached", &stats(&[], 200, Some(ms(2000))))
        );
        assert_eq!(
            lines[5],
            "dns blocked     error: no name answered as blocked"
        );
        assert_eq!(
            lines[6],
            row_line(
                "dns forwarded",
                &RowStats {
                    failed: 1,
                    ..stats(&[ms(20), ms(30), ms(40)], 1, Some(ms(2000)))
                }
            )
        );
        // Once, under the table, however many rows lost samples; it says what a failed answer is
        // because a row has one.
        assert_eq!(
            lines[7],
            "latency: lost answers count as 2000 ms in p50, p95 and mean (icmp: received only); \
             a SERVFAIL or REFUSED answer counts as lost too, and is counted in failed"
        );
        assert_eq!(
            lines[8],
            "latency: dns cached: first socket error: Connection refused (os error 111)"
        );
        assert_eq!(lines.len(), 9);
        let mut report = sample_report();
        report.blocked_name = None;
        assert_eq!(
            render_text(&report).lines().nth(1),
            Some("latency: blocked name: -")
        );
    }

    #[test]
    fn the_note_on_lost_answers_appears_only_when_a_dns_row_lost_one() {
        let note = |report: &Report| {
            render_text(report)
                .lines()
                .any(|line| line.starts_with("latency: lost answers count as"))
        };
        let measured = |stats| {
            Ok(Measured {
                stats,
                first_error: None,
            })
        };
        let row = |name, result| Row { name, result };
        let wait = Some(ms(2000));
        let mut report = Report {
            unix_secs: 1,
            samples_asked: 3,
            interval_ms: 200,
            blocked_name: None,
            rows: vec![
                // The icmp row lost samples, which does not count.
                row("icmp", measured(stats(&[ms(6)], 2, None))),
                row("dns cached", measured(stats(&[ms(3); 3], 0, wait))),
                row("dns blocked", Err("none blocked".to_owned())),
            ],
        };
        assert!(!note(&report));
        report.rows[1] = row("dns cached", measured(stats(&[ms(3); 2], 1, wait)));
        assert!(note(&report));
        // A wait that is not whole seconds is told as it is.
        report.rows[1] = row("dns cached", measured(stats(&[ms(3); 2], 1, Some(ms(300)))));
        assert!(render_text(&report).contains("count as 300 ms in"));
    }

    #[test]
    fn the_note_names_servfail_and_refused_only_when_a_row_has_failed_answers() {
        let measured = |stats| {
            Ok(Measured {
                stats,
                first_error: None,
            })
        };
        let row = |name, result| Row { name, result };
        let wait = Some(ms(2000));
        let mut report = Report {
            unix_secs: 1,
            samples_asked: 3,
            interval_ms: 200,
            blocked_name: None,
            rows: vec![
                row("icmp", measured(stats(&[ms(6)], 2, None))),
                // One lost sample that was no answer at all: nothing failed.
                row("dns cached", measured(stats(&[ms(3); 2], 1, wait))),
            ],
        };
        let note = |report: &Report| {
            render_text(report)
                .lines()
                .find(|line| line.starts_with("latency: lost answers count as"))
                .unwrap()
                .to_owned()
        };
        assert!(!note(&report).contains("SERVFAIL"), "{}", note(&report));
        report.rows[1] = row(
            "dns cached",
            measured(RowStats {
                failed: 1,
                ..stats(&[ms(3); 2], 1, wait)
            }),
        );
        let line = note(&report);
        assert!(
            line.contains("SERVFAIL or REFUSED") && line.ends_with("counted in failed"),
            "{line}"
        );
    }

    #[test]
    fn the_json_holds_the_figures_and_no_address() {
        let json = render_json(&sample_report());
        assert_eq!(json["unix_secs"], 1_800_000_000u64);
        assert_eq!(json["samples_asked"], 200);
        assert_eq!(json["interval_ms"], 200);
        assert_eq!(json["blocked_name"], "doubleclick.net");
        assert_eq!(
            json["forwarded_zones"].as_array().unwrap().len(),
            FORWARDED_ZONES.len()
        );
        let rows = json["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[0]["row"], "icmp");
        assert_eq!(rows[0]["samples"], 2);
        assert_eq!(rows[0]["lost"], 1);
        // `failed` is a subset of `lost`: none on the icmp row, one on the forwarded row.
        assert_eq!(rows[0]["failed"], 0);
        assert_eq!(rows[1]["failed"], 0);
        assert_eq!(rows[2]["failed"], 0);
        assert_eq!(rows[3]["lost"], 1);
        assert_eq!(rows[3]["failed"], 1);
        assert_eq!(rows[0]["p50_ms"], 6.0);
        assert_eq!(rows[0]["p95_ms"], 12.0);
        assert_eq!(rows[0]["min_ms"], 6.0);
        assert_eq!(rows[0]["mean_ms"], 9.0);
        assert!(rows[0].get("error").is_none());
        // The icmp row counts nothing for a lost reply: no rule, and received figures that are
        // the figures.
        assert!(rows[0]["lost_counted_as_ms"].is_null());
        assert!(rows[0].get("lost_counted_as_ms").is_some());
        assert_eq!(rows[0]["received"]["p50_ms"], 6.0);
        assert_eq!(rows[0]["received"]["p95_ms"], 12.0);
        assert_eq!(rows[0]["received"]["min_ms"], 6.0);
        assert_eq!(rows[0]["received"]["mean_ms"], 9.0);
        // Every sample of the cached row was lost: the figures are the wait, the received ones
        // and the minimum are empty.
        assert_eq!(rows[1]["samples"], 0);
        assert_eq!(rows[1]["lost"], 200);
        assert_eq!(rows[1]["lost_counted_as_ms"], 2000.0);
        for key in ["p50_ms", "p95_ms", "mean_ms"] {
            assert_eq!(rows[1][key], 2000.0, "{key}");
        }
        assert!(rows[1]["min_ms"].is_null());
        for key in ["p50_ms", "p95_ms", "min_ms", "mean_ms"] {
            assert!(rows[1]["received"][key].is_null(), "{key}");
        }
        // An error row has no rule and no figure.
        assert_eq!(rows[2]["error"], "no name answered as blocked");
        assert!(rows[2]["lost_counted_as_ms"].is_null());
        assert!(rows[2].get("lost_counted_as_ms").is_some());
        for key in ["p50_ms", "p95_ms", "min_ms", "mean_ms"] {
            assert!(rows[2][key].is_null(), "{key}");
            assert!(rows[2]["received"][key].is_null(), "{key}");
        }
        // A forwarded row with one lost of four: its p95 is the wait, its received p95 is not.
        assert_eq!(rows[3]["lost_counted_as_ms"], 2000.0);
        assert_eq!(rows[3]["p50_ms"], 30.0);
        assert_eq!(rows[3]["p95_ms"], 2000.0);
        assert_eq!(rows[3]["min_ms"], 20.0);
        assert_eq!(rows[3]["mean_ms"], 522.5);
        assert_eq!(rows[3]["received"]["p95_ms"], 40.0);
        assert_eq!(rows[3]["received"]["mean_ms"], 30.0);
        assert_eq!(rows[3]["received"]["min_ms"], 20.0);
        let mut report = sample_report();
        report.blocked_name = None;
        assert!(render_json(&report)["blocked_name"].is_null());
    }

    // comparing two files

    /// A row as `render_json` writes it now: the top-level figures count lost answers, `received`
    /// holds the received-only ones. `rule` is `lost_counted_as_ms`.
    fn new_row(name: &str, rule: Option<f64>, counted: (f64, f64), received: (f64, f64)) -> Value {
        json!({
            "row": name,
            "samples": 200,
            "lost": 2,
            "failed": 0,
            "p50_ms": counted.0,
            "p95_ms": counted.1,
            "min_ms": 1.0,
            "mean_ms": 9.0,
            "lost_counted_as_ms": rule,
            "received": {
                "p50_ms": received.0,
                "p95_ms": received.1,
                "min_ms": 1.0,
                "mean_ms": 8.0,
            },
        })
    }

    /// A row as the files of 2026-11-11 have it, written before lost answers were counted.
    fn old_row(name: &str, p50: f64, p95: f64) -> Value {
        json!({
            "row": name,
            "samples": 200,
            "lost": 2,
            "p50_ms": p50,
            "p95_ms": p95,
            "min_ms": 1.0,
            "mean_ms": 8.0,
        })
    }

    fn file(interval_ms: u64, rows: Vec<Value>) -> Value {
        json!({
            "unix_secs": 1_800_000_000u64,
            "samples_asked": 200,
            "interval_ms": interval_ms,
            "blocked_name": "ads.example.com",
            "forwarded_zones": ["example.com", "example.net"],
            "rows": rows,
        })
    }

    /// The table line of `row` and `figure` in the text of a comparison.
    fn table_line<'a>(text: &'a str, row: &str, figure: &str) -> &'a str {
        text.lines()
            .find(|line| {
                line.starts_with(row) && line[row.len()..].trim_start().starts_with(figure)
            })
            .unwrap_or_else(|| panic!("no line for {row} {figure} in\n{text}"))
    }

    const OLD_NOTE: &str =
        "its DNS rows lack lost_counted_as_ms, so received-only figures are compared";

    /// What a comparison says of a file written before lost answers were counted.
    fn old_words(name: &str) -> String {
        format!(
            "{name} was written before lost answers were counted: re-run that pass, \
             or pass --received-only to read it anyway"
        )
    }

    #[test]
    fn two_new_files_are_compared_on_their_top_level_figures() {
        let a = file(
            200,
            vec![
                new_row("icmp", None, (6.0, 8.0), (6.0, 8.0)),
                new_row("dns cached", Some(2000.0), (3.0, 5.0), (3.0, 4.0)),
                new_row("dns forwarded", Some(2000.0), (25.0, 1000.0), (25.0, 90.0)),
            ],
        );
        // B is faster everywhere, bar the forwarded p95: counting lost answers it is slower
        // (2000 against 1000 ms), received-only it would be faster (80 against 90 ms).
        let b = file(
            200,
            vec![
                new_row("icmp", None, (6.0, 8.0), (6.0, 8.0)),
                new_row("dns cached", Some(2000.0), (2.9, 4.5), (2.9, 4.0)),
                new_row("dns forwarded", Some(2000.0), (20.0, 2000.0), (20.0, 80.0)),
            ],
        );
        let result = compare_reports("stock.json", &a, "qberrypi.json", &b, false);
        assert_eq!((result.compared, result.slower), (6, 1), "{}", result.text);
        let text = &result.text;
        assert!(table_line(text, "icmp", "p50").contains("ok"));
        // The icmp row counts no lost answer, whichever files are compared.
        assert!(table_line(text, "icmp", "p50").ends_with("received only"));
        let cached_p95 = table_line(text, "dns cached", "p95");
        assert!(cached_p95.contains("5.00") && cached_p95.contains("4.50"));
        assert!(cached_p95.contains("ok") && cached_p95.contains("lost answers counted"));
        let forwarded_p95 = table_line(text, "dns forwarded", "p95");
        assert!(forwarded_p95.contains("1000.00") && forwarded_p95.contains("2000.00"));
        assert!(forwarded_p95.contains("slower"), "{forwarded_p95}");
        assert!(table_line(text, "dns forwarded", "p50").contains("ok"));
        // Neither file is old; the files' own figures are named; the order is A's.
        assert!(!text.contains(OLD_NOTE), "{text}");
        assert!(text.contains("latency: A = stock.json: 200 samples asked, interval 200 ms"));
        assert!(text.contains("latency: B = qberrypi.json: 200 samples asked, interval 200 ms"));
        assert!(!text.contains("differs"), "{text}");
        let order: Vec<&str> = ["icmp", "dns cached", "dns forwarded"]
            .into_iter()
            .map(|row| table_line(text, row, "p50"))
            .collect();
        let at = |line: &str| text.find(line).unwrap();
        assert!(at(order[0]) < at(order[1]) && at(order[1]) < at(order[2]));
        assert!(
            text.ends_with("latency: 1 of 6 compared figures are slower in B\n"),
            "{text}"
        );
        // Equal figures are not slower.
        let same = compare_reports("a", &a, "b", &a, false);
        assert_eq!((same.compared, same.slower), (6, 0));
        assert!(
            same.text
                .ends_with("latency: all 6 compared figures are ok\n"),
            "{}",
            same.text
        );
    }

    #[test]
    fn an_old_file_is_read_as_received_only_and_fails_unless_that_is_asked_for() {
        let old = file(
            200,
            vec![
                old_row("icmp", 6.0, 8.0),
                old_row("dns cached", 3.0, 5.0),
                old_row("dns forwarded", 25.0, 90.0),
            ],
        );
        // The new file's top level counts lost answers (2000 ms at p95) and would be slower than
        // anything; its `received` figures are the ones that are compared.
        let new = file(
            200,
            vec![
                new_row("icmp", None, (6.0, 8.0), (6.0, 8.0)),
                new_row("dns cached", Some(2000.0), (2.9, 2000.0), (2.9, 4.5)),
                new_row("dns forwarded", Some(2000.0), (20.0, 2000.0), (20.0, 80.0)),
            ],
        );
        let result = compare_reports("stock.json", &old, "qberrypi.json", &new, false);
        assert_eq!((result.compared, result.slower), (6, 0), "{}", result.text);
        assert_eq!(result.old_rule, [true, false]);
        let text = &result.text;
        assert!(
            text.contains(&format!("latency: stock.json: {OLD_NOTE}\n")),
            "{text}"
        );
        // Only the old file is named in a note.
        assert!(!text.contains(&format!("latency: qberrypi.json: {OLD_NOTE}")));
        assert_eq!(text.matches(OLD_NOTE).count(), 1, "{text}");
        let cached_p95 = table_line(text, "dns cached", "p95");
        assert!(cached_p95.contains("5.00") && cached_p95.contains("4.50"));
        assert!(cached_p95.contains("received only"), "{cached_p95}");
        assert!(!text.contains("2000.00"), "{text}");
        // Every figure is fine, and still the comparison fails: it names the file and the way out.
        assert_eq!(
            failure_words(&result, "stock.json", "qberrypi.json").unwrap(),
            old_words("stock.json")
        );
        assert!(
            text.ends_with(&format!("latency: {}\n", old_words("A"))),
            "{text}"
        );

        // The other way round, the new file is A and the old one B: B is named.
        let result = compare_reports("qberrypi.json", &new, "stock.json", &old, false);
        assert_eq!(result.old_rule, [false, true]);
        assert!(
            result
                .text
                .contains(&format!("latency: stock.json: {OLD_NOTE}\n"))
        );
        assert_eq!(result.text.matches(OLD_NOTE).count(), 1);
        // (A's figures are the better ones here, so B's are slower as well: both are said.)
        assert_eq!(
            failure_words(&result, "qberrypi.json", "stock.json").unwrap(),
            format!(
                "{}; 4 of 6 compared figures are slower in stock.json",
                old_words("stock.json")
            )
        );
        // And an old figure that is slower than the new one's received figure is slower.
        let slow_old = file(200, vec![old_row("dns cached", 3.0, 4.0)]);
        let result = compare_reports("stock.json", &slow_old, "qberrypi.json", &new, false);
        assert_eq!((result.compared, result.slower), (2, 1), "{}", result.text);
        assert!(table_line(&result.text, "dns cached", "p95").contains("slower"));
    }

    #[test]
    fn received_only_reads_an_old_file_on_purpose_and_says_it_is_not_the_acceptance() {
        let old = file(
            200,
            vec![
                old_row("icmp", 6.0, 8.0),
                old_row("dns cached", 3.0, 5.0),
                old_row("dns forwarded", 25.0, 90.0),
            ],
        );
        let new = file(
            200,
            vec![
                new_row("icmp", None, (6.0, 8.0), (6.0, 8.0)),
                new_row("dns cached", Some(2000.0), (2.9, 2000.0), (2.9, 4.5)),
                new_row("dns forwarded", Some(2000.0), (20.0, 2000.0), (20.0, 80.0)),
            ],
        );
        let result = compare_reports("stock.json", &old, "qberrypi.json", &new, true);
        let text = &result.text;
        assert_eq!(
            (result.compared, result.slower, result.missing),
            (6, 0, 0),
            "{text}"
        );
        assert_eq!(result.old_rule, [false, false]);
        assert!(failure_words(&result, "stock.json", "qberrypi.json").is_none());
        assert!(text.contains("latency: --received-only:"), "{text}");
        assert!(
            text.contains("this is not the acceptance comparison"),
            "{text}"
        );
        assert!(!text.contains(OLD_NOTE), "{text}");
        assert!(text.ends_with("latency: all 6 compared figures are ok\n"));
        for row in ["icmp", "dns cached", "dns forwarded"] {
            for figure in ["p50", "p95"] {
                let line = table_line(text, row, figure);
                assert!(line.ends_with("received only"), "{line}");
            }
        }
        // Two new files, too, are read received-only on purpose: the forwarded p95 that is slower
        // with lost answers counted (2000 against 1000 ms) is faster without them (80 against 90).
        let a = file(
            200,
            vec![new_row(
                "dns forwarded",
                Some(2000.0),
                (25.0, 1000.0),
                (25.0, 90.0),
            )],
        );
        let b = file(
            200,
            vec![new_row(
                "dns forwarded",
                Some(2000.0),
                (20.0, 2000.0),
                (20.0, 80.0),
            )],
        );
        let counted = compare_reports("a.json", &a, "b.json", &b, false);
        assert_eq!(counted.slower, 1, "{}", counted.text);
        assert!(!counted.text.contains("--received-only"));
        let received = compare_reports("a.json", &a, "b.json", &b, true);
        assert_eq!(
            (received.compared, received.slower),
            (2, 0),
            "{}",
            received.text
        );
        assert!(
            table_line(&received.text, "dns forwarded", "p95").ends_with("received only"),
            "{}",
            received.text
        );
        // Pacing and the incomplete baseline still fail under the flag.
        let mut other = b.clone();
        other["interval_ms"] = json!(2);
        let result = compare_reports("a.json", &a, "b.json", &other, true);
        assert_eq!(
            failure_words(&result, "a.json", "b.json").unwrap(),
            "interval_ms differs (a.json 200, b.json 2)"
        );
        let broken = file(200, vec![error_row("dns forwarded")]);
        let result = compare_reports("broken.json", &broken, "b.json", &b, true);
        assert_eq!(result.no_baseline, 2, "{}", result.text);
        assert!(failure_words(&result, "broken.json", "b.json").is_some());
    }

    #[test]
    fn two_old_files_fail_naming_both_and_are_compared_on_their_figures_with_the_flag() {
        let a = file(200, vec![old_row("dns cached", 3.0, 5.0)]);
        let b = file(200, vec![old_row("dns cached", 3.5, 5.0)]);
        let result = compare_reports("one.json", &a, "two.json", &b, false);
        assert_eq!((result.compared, result.slower), (2, 1), "{}", result.text);
        assert!(table_line(&result.text, "dns cached", "p50").contains("slower"));
        assert!(table_line(&result.text, "dns cached", "p95").contains("ok"));
        for name in ["one.json", "two.json"] {
            assert!(
                result
                    .text
                    .contains(&format!("latency: {name}: {OLD_NOTE}\n")),
                "{}",
                result.text
            );
        }
        assert_eq!(result.old_rule, [true, true]);
        assert_eq!(
            failure_words(&result, "one.json", "two.json").unwrap(),
            format!(
                "{}; {}; 1 of 2 compared figures are slower in two.json",
                old_words("one.json"),
                old_words("two.json")
            )
        );
        // Read on purpose, only the figure that is slower fails; two equal old files pass.
        let result = compare_reports("one.json", &a, "two.json", &b, true);
        assert_eq!(result.old_rule, [false, false]);
        assert_eq!(
            failure_words(&result, "one.json", "two.json").unwrap(),
            "1 of 2 compared figures are slower in two.json"
        );
        let same = compare_reports("one.json", &a, "two.json", &a, true);
        assert!(failure_words(&same, "one.json", "two.json").is_none());
        let same = compare_reports("one.json", &a, "two.json", &a, false);
        assert!(failure_words(&same, "one.json", "two.json").is_some());
    }

    #[test]
    fn a_different_interval_or_sample_count_is_said_and_fails() {
        let rows = || vec![new_row("icmp", None, (6.0, 8.0), (6.0, 8.0))];
        let a = file(200, rows());
        let mut b = file(2, rows());
        b["samples_asked"] = json!(100);
        let result = compare_reports("a.json", &a, "b.json", &b, false);
        let text = &result.text;
        assert!(text.contains("latency: A = a.json: 200 samples asked, interval 200 ms\n"));
        assert!(text.contains("latency: B = b.json: 100 samples asked, interval 2 ms\n"));
        assert!(
            text.contains("latency: interval_ms differs (A 200, B 2)"),
            "{text}"
        );
        assert!(
            text.contains("latency: samples_asked differs (A 200, B 100)"),
            "{text}"
        );
        // Every figure is fine, and still it is not like for like.
        assert_eq!(
            (result.compared, result.slower, result.missing),
            (2, 0, 0),
            "{text}"
        );
        assert_eq!(
            failure_words(&result, "a.json", "b.json").unwrap(),
            "interval_ms differs (a.json 200, b.json 2); \
             samples_asked differs (a.json 200, b.json 100)"
        );
        assert!(
            text.ends_with(
                "latency: interval_ms differs (A 200, B 2); \
                 samples_asked differs (A 200, B 100)\n"
            ),
            "{text}"
        );
        // One that differs alone fails alone.
        let mut one = a.clone();
        one["samples_asked"] = json!(50);
        let result = compare_reports("a.json", &a, "b.json", &one, false);
        assert_eq!(
            failure_words(&result, "a.json", "b.json").unwrap(),
            "samples_asked differs (a.json 200, b.json 50)"
        );
        // A file that does not say differs from one that does; two that do not say are the same.
        let bare = json!({"rows": rows()});
        let result = compare_reports("a.json", &a, "b.json", &bare, false);
        assert!(
            result
                .text
                .contains("latency: B = b.json: ? samples asked, interval ?\n"),
            "{}",
            result.text
        );
        assert!(
            result
                .text
                .contains("latency: interval_ms differs (A 200, B ?)"),
            "{}",
            result.text
        );
        let both = compare_reports("a.json", &bare, "b.json", &bare, false);
        assert!(both.pacing.is_empty(), "{}", both.text);
        assert!(failure_words(&both, "a.json", "b.json").is_none());
    }

    #[test]
    fn a_row_only_one_file_has_fails_whichever_file_it_is() {
        let a = file(
            200,
            vec![
                new_row("icmp", None, (6.0, 8.0), (6.0, 8.0)),
                new_row("dns cached", Some(2000.0), (3.0, 5.0), (3.0, 4.0)),
            ],
        );
        let b = file(
            200,
            vec![
                new_row("dns cached", Some(2000.0), (3.0, 5.0), (3.0, 4.0)),
                new_row("dns blocked", Some(2000.0), (3.0, 5.0), (3.0, 4.0)),
            ],
        );
        // B lacks the icmp row, so its p50 and p95 are two figures of A that B cannot give; A
        // lacks the blocked row, so its two are figures of B that have no baseline.
        let result = compare_reports("a.json", &a, "b.json", &b, false);
        assert_eq!(
            (
                result.compared,
                result.slower,
                result.missing,
                result.no_baseline
            ),
            (2, 0, 2, 2),
            "{}",
            result.text
        );
        assert!(result.text.contains(
            "latency: icmp: not in b.json, so 2 figures of a.json are not known there\n"
        ));
        assert!(result.text.contains(
            "latency: dns blocked: not in a.json, so 2 figures of b.json have no baseline\n"
        ));
        assert!(!result.text.lines().any(|line| line.starts_with("icmp ")));
        assert!(
            result.text.ends_with(
                "latency: 2 figures of A are not known in B; \
                 2 figures of B have no figure in A (an incomplete baseline)\n"
            ),
            "{}",
            result.text
        );
        assert_eq!(
            failure_words(&result, "a.json", "b.json").unwrap(),
            "2 figures of a.json are not known in b.json; \
             2 figures of b.json have no figure in a.json (an incomplete baseline)"
        );

        // The other way round `dns blocked` is the row only A has, and `icmp` the one only B has.
        let result = compare_reports("b.json", &b, "a.json", &a, false);
        assert_eq!(
            (
                result.compared,
                result.slower,
                result.missing,
                result.no_baseline
            ),
            (2, 0, 2, 2),
            "{}",
            result.text
        );
        // A row that only B has is no pass either: A is not a complete baseline.
        let a_only = file(
            200,
            vec![new_row("dns cached", Some(2000.0), (3.0, 5.0), (3.0, 4.0))],
        );
        let result = compare_reports("a.json", &a_only, "b.json", &b, false);
        assert_eq!(
            (
                result.compared,
                result.slower,
                result.missing,
                result.no_baseline
            ),
            (2, 0, 0, 2),
            "{}",
            result.text
        );
        assert!(result.text.contains(
            "latency: dns blocked: not in a.json, so 2 figures of b.json have no baseline\n"
        ));
        assert_eq!(
            failure_words(&result, "a.json", "b.json").unwrap(),
            "2 figures of b.json have no figure in a.json (an incomplete baseline)"
        );

        // One figure is told in the singular, and a row of A that has no figures at all (it
        // could not be measured) is skipped: B cannot lack what A never had. B's icmp row, which
        // A lacks, has two figures that have no baseline.
        let mut half = new_row("dns cached", Some(2000.0), (3.0, 5.0), (3.0, 4.0));
        half["p95_ms"] = Value::Null;
        let mut unmeasured = new_row("dns blocked", None, (0.0, 0.0), (0.0, 0.0));
        for key in ["p50_ms", "p95_ms", "min_ms", "mean_ms"] {
            unmeasured[key] = Value::Null;
            unmeasured["received"][key] = Value::Null;
        }
        let a = file(200, vec![half, unmeasured]);
        let b = file(200, vec![new_row("icmp", None, (6.0, 8.0), (6.0, 8.0))]);
        let result = compare_reports("a.json", &a, "b.json", &b, false);
        assert_eq!(
            (
                result.compared,
                result.slower,
                result.missing,
                result.no_baseline
            ),
            (0, 0, 1, 2),
            "{}",
            result.text
        );
        assert!(result.text.contains(
            "latency: dns cached: not in b.json, so 1 figure of a.json is not known there\n"
        ));
        assert!(
            result
                .text
                .contains("latency: dns blocked: not in b.json, skipped\n")
        );
        assert!(
            result.text.ends_with(
                "latency: 1 figure of A is not known in B; \
                 2 figures of B have no figure in A (an incomplete baseline)\n"
            ),
            "{}",
            result.text
        );
    }

    /// A row that could not be measured, as `render_json` writes it: no rule, no figure.
    fn error_row(name: &str) -> Value {
        let mut row = new_row(name, None, (0.0, 0.0), (0.0, 0.0));
        for key in ["p50_ms", "p95_ms", "min_ms", "mean_ms"] {
            row[key] = Value::Null;
            row["received"][key] = Value::Null;
        }
        row["error"] = json!("no name answered as blocked");
        row
    }

    #[test]
    fn a_figure_of_a_that_b_cannot_give_is_missing_and_fails() {
        let a = file(
            200,
            vec![
                new_row("dns cached", Some(2000.0), (3.0, 5.0), (3.0, 4.0)),
                new_row("dns blocked", Some(2000.0), (3.0, 5.0), (3.0, 4.0)),
            ],
        );
        // The blocked row of B could not be measured: no figures at all, and no rule.
        let b = file(
            200,
            vec![
                new_row("dns cached", Some(2000.0), (3.0, 5.0), (3.0, 4.0)),
                error_row("dns blocked"),
            ],
        );
        let result = compare_reports("a.json", &a, "b.json", &b, false);
        assert_eq!(
            (result.compared, result.slower, result.missing),
            (2, 0, 2),
            "{}",
            result.text
        );
        let line = table_line(&result.text, "dns blocked", "p50");
        assert!(line.contains("3.00") && line.contains("missing"), "{line}");
        assert!(
            line.ends_with("  -"),
            "the basis of a figure that is not known: {line}"
        );
        assert!(
            result
                .text
                .ends_with("latency: 2 figures of A are not known in B\n"),
            "{}",
            result.text
        );
        assert!(table_line(&result.text, "dns cached", "p50").ends_with("lost answers counted"));

        // With a slower figure besides, both are said.
        let mut slower = b.clone();
        slower["rows"][0]["p95_ms"] = json!(6.0);
        let result = compare_reports("a.json", &a, "b.json", &slower, false);
        assert_eq!(
            (result.compared, result.slower, result.missing),
            (2, 1, 2),
            "{}",
            result.text
        );
        assert_eq!(
            failure_words(&result, "a.json", "b.json").unwrap(),
            "1 of 2 compared figures are slower in b.json; 2 figures of a.json are not known in b.json"
        );
    }

    #[test]
    fn a_figure_that_a_lacks_is_an_incomplete_baseline_and_fails() {
        // A could not measure the blocked row, B could: B has figures that A cannot be held to.
        let a = file(
            200,
            vec![
                new_row("dns cached", Some(2000.0), (3.0, 5.0), (3.0, 4.0)),
                error_row("dns blocked"),
            ],
        );
        let b = file(
            200,
            vec![
                new_row("dns cached", Some(2000.0), (3.0, 5.0), (3.0, 4.0)),
                new_row("dns blocked", Some(2000.0), (3.0, 5.0), (3.0, 4.0)),
            ],
        );
        let result = compare_reports("a.json", &a, "b.json", &b, false);
        assert_eq!(
            (
                result.compared,
                result.slower,
                result.missing,
                result.no_baseline
            ),
            (2, 0, 0, 2),
            "{}",
            result.text
        );
        let line = table_line(&result.text, "dns blocked", "p95");
        // A's rule is null, so B is read from `received` (4.00), not its top level (5.00).
        assert!(line.contains("4.00") && !line.contains("5.00"), "{line}");
        assert!(line.contains("unknown") && line.ends_with("  -"), "{line}");
        assert!(
            result.text.ends_with(
                "latency: 2 figures of B have no figure in A (an incomplete baseline)\n"
            ),
            "{}",
            result.text
        );
        assert_eq!(
            failure_words(&result, "a.json", "b.json").unwrap(),
            "2 figures of b.json have no figure in a.json (an incomplete baseline)"
        );
        // A row that neither file could measure is nothing to compare, and fails nothing.
        let neither = compare_reports(
            "a.json",
            &file(200, vec![error_row("dns blocked")]),
            "b.json",
            &file(200, vec![error_row("dns blocked")]),
            false,
        );
        assert_eq!((neither.compared, neither.no_baseline), (0, 0));
        assert!(failure_words(&neither, "a.json", "b.json").is_none());
        assert!(
            neither
                .text
                .ends_with("latency: all 0 compared figures are ok (2 not known in either file, not compared)\n"),
            "{}",
            neither.text
        );
    }

    #[test]
    fn an_old_stock_file_against_a_new_file_with_an_error_row_fails_naming_both() {
        let old = file(
            2,
            vec![
                old_row("dns cached", 2.9, 4.13),
                old_row("dns blocked", 2.74, 4.35),
                old_row("dns forwarded", 25.66, 92.43),
            ],
        );
        let new = file(
            2,
            vec![
                new_row("dns cached", Some(2000.0), (2.8, 4.0), (2.8, 4.0)),
                error_row("dns blocked"),
                new_row("dns forwarded", Some(2000.0), (24.0, 2000.0), (24.0, 80.0)),
            ],
        );
        let result = compare_reports("stock.json", &old, "qberrypi.json", &new, false);
        assert_eq!(
            (result.compared, result.slower, result.missing),
            (4, 0, 2),
            "{}",
            result.text
        );
        assert!(
            result
                .text
                .contains(&format!("latency: stock.json: {OLD_NOTE}\n"))
        );
        assert!(
            table_line(&result.text, "dns blocked", "p95").contains("missing"),
            "{}",
            result.text
        );
        assert!(
            result.text.ends_with(&format!(
                "latency: {}; 2 figures of A are not known in B\n",
                old_words("A")
            )),
            "{}",
            result.text
        );
        // Read on purpose, the old rule is allowed and the error row still fails.
        let result = compare_reports("stock.json", &old, "qberrypi.json", &new, true);
        assert_eq!(
            failure_words(&result, "stock.json", "qberrypi.json").unwrap(),
            "2 figures of stock.json are not known in qberrypi.json"
        );
    }

    /// A DNS row of the new rule with these counts; `failed` is `None` for a file that does not
    /// know it.
    fn counted_row(name: &str, lost: u64, failed: Option<u64>) -> Value {
        let mut row = new_row(name, Some(2000.0), (3.0, 5.0), (3.0, 4.0));
        row["lost"] = json!(lost);
        match failed {
            Some(failed) => row["failed"] = json!(failed),
            None => {
                row.as_object_mut().unwrap().remove("failed");
            }
        }
        row
    }

    #[test]
    fn the_lost_and_failed_counts_are_noted_for_a_dns_row_when_they_differ_and_judge_nothing() {
        let a = file(
            200,
            vec![
                counted_row("dns cached", 2, Some(0)),
                counted_row("dns blocked", 0, Some(0)),
                counted_row("dns forwarded", 18, None),
            ],
        );
        let b = file(
            200,
            vec![
                counted_row("dns cached", 2, Some(0)),
                counted_row("dns blocked", 0, Some(0)),
                counted_row("dns forwarded", 4, Some(4)),
            ],
        );
        let result = compare_reports("stock.json", &a, "qberrypi.json", &b, false);
        let text = &result.text;
        assert!(
            text.contains(
                "latency: dns forwarded: lost 18 (failed ?) in stock.json, \
                 lost 4 (failed 4) in qberrypi.json\n"
            ),
            "{text}"
        );
        // The rows whose counts are the same have no note, and there is no verdict on any.
        assert!(!text.contains("latency: dns cached: lost"), "{text}");
        assert!(!text.contains("latency: dns blocked: lost"), "{text}");
        assert_eq!((result.compared, result.slower), (6, 0), "{text}");
        assert!(failure_words(&result, "stock.json", "qberrypi.json").is_none());
        assert!(
            text.ends_with("latency: all 6 compared figures are ok\n"),
            "{text}"
        );
        // Counts that differ only in what is known are told as well; the icmp row has none.
        let a = file(
            200,
            vec![
                new_row("icmp", None, (6.0, 8.0), (6.0, 8.0)),
                counted_row("dns cached", 2, Some(0)),
            ],
        );
        let mut icmp = new_row("icmp", None, (6.0, 8.0), (6.0, 8.0));
        icmp["lost"] = json!(9);
        let b = file(200, vec![icmp, counted_row("dns cached", 2, None)]);
        let text = compare_reports("a.json", &a, "b.json", &b, true).text;
        assert!(
            text.contains(
                "latency: dns cached: lost 2 (failed 0) in a.json, lost 2 (failed ?) in b.json\n"
            ),
            "{text}"
        );
        assert!(!text.contains("latency: icmp: lost"), "{text}");
    }

    #[test]
    fn a_file_written_by_render_json_compares_equal_to_itself() {
        let value = render_json(&sample_report());
        let result = compare_reports("a.json", &value, "b.json", &value, false);
        // icmp, the cached and the forwarded rows have figures; the blocked row is an error, in
        // A as well, so B lacks nothing of A's.
        assert_eq!(
            (result.compared, result.slower, result.missing),
            (6, 0, 0),
            "{}",
            result.text
        );
        assert!(!result.text.contains("written before"), "{}", result.text);
    }

    #[test]
    fn a_comparison_of_files_fails_after_printing_when_a_figure_is_slower_or_missing() {
        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, value: &Value| {
            let path = dir.path().join(name);
            fs::write(&path, serde_json::to_string_pretty(value).unwrap()).unwrap();
            path
        };
        let rows = |p95: f64| {
            vec![
                new_row("dns cached", Some(2000.0), (3.0, p95), (3.0, 4.0)),
                new_row("dns forwarded", Some(2000.0), (25.0, p95), (25.0, 80.0)),
            ]
        };
        let stock = write("stock.json", &file(200, rows(10.0)));
        let better = write("better.json", &file(200, rows(9.0)));
        let worse = write("worse.json", &file(200, rows(11.0)));
        compare(&stock, &better, false).unwrap();
        let error = compare(&stock, &worse, false).unwrap_err();
        assert_eq!(
            error.to_string(),
            "2 of 4 compared figures are slower in worse.json"
        );

        // A row of A that B lacks, and a row of B that A lacks: neither is a pass.
        let fewer = write("fewer.json", &file(200, rows(10.0)[..1].to_vec()));
        let error = compare(&stock, &fewer, false).unwrap_err();
        assert_eq!(
            error.to_string(),
            "2 figures of stock.json are not known in fewer.json"
        );
        let error = compare(&fewer, &stock, false).unwrap_err();
        assert_eq!(
            error.to_string(),
            "2 figures of stock.json have no figure in fewer.json (an incomplete baseline)"
        );
        // A row that could not be measured in B.
        let mut broken_rows = rows(9.0);
        broken_rows[1] = error_row("dns forwarded");
        let broken = write("broken.json", &file(200, broken_rows));
        let error = compare(&stock, &broken, false).unwrap_err();
        assert_eq!(
            error.to_string(),
            "2 figures of stock.json are not known in broken.json"
        );
        // Slower and missing together.
        let mut both_rows = rows(11.0);
        both_rows[1] = error_row("dns forwarded");
        let both = write("both.json", &file(200, both_rows));
        let error = compare(&stock, &both, false).unwrap_err();
        assert_eq!(
            error.to_string(),
            "1 of 2 compared figures are slower in both.json; \
             2 figures of stock.json are not known in both.json"
        );

        // A missing file, and a file that is no JSON.
        let missing = compare(&stock, &dir.path().join("nothing.json"), false).unwrap_err();
        assert!(missing.to_string().contains("cannot read"), "{missing:#}");
        let text = dir.path().join("text.json");
        fs::write(&text, "not json").unwrap();
        let error = compare(&text, &stock, false).unwrap_err();
        assert!(
            error.to_string().contains("is not a JSON file"),
            "{error:#}"
        );
        // JSON that holds no rows has nothing to compare, which is not a pass: as B it leaves
        // every figure of A unknown, as A it leaves nothing to compare at all.
        let empty = write("empty.json", &file(200, Vec::new()));
        let error = compare(&stock, &empty, false).unwrap_err();
        assert_eq!(
            error.to_string(),
            "4 figures of stock.json are not known in empty.json"
        );
        let error = compare(&empty, &stock, false).unwrap_err();
        assert_eq!(
            error.to_string(),
            "4 figures of stock.json have no figure in empty.json (an incomplete baseline)"
        );
        let error = compare(&empty, &empty, false).unwrap_err();
        assert!(
            error.to_string().contains("no figure could be compared"),
            "{error:#}"
        );
    }

    #[test]
    fn a_comparison_of_files_fails_on_the_old_rule_and_on_pacing_and_received_only_reads_the_old() {
        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, value: &Value| {
            let path = dir.path().join(name);
            fs::write(&path, serde_json::to_string_pretty(value).unwrap()).unwrap();
            path
        };
        // The stock pass as 2026-11-11 wrote it, and the same pass under the new rule.
        let old = write(
            "old.json",
            &file(
                200,
                vec![
                    old_row("dns cached", 3.0, 5.0),
                    old_row("dns forwarded", 25.0, 90.0),
                ],
            ),
        );
        let new_rows = |interval_ms| {
            file(
                interval_ms,
                vec![
                    new_row("dns cached", Some(2000.0), (3.0, 2000.0), (3.0, 4.0)),
                    new_row("dns forwarded", Some(2000.0), (25.0, 2000.0), (25.0, 80.0)),
                ],
            )
        };
        let new = write("new.json", &new_rows(200));
        let error = compare(&old, &new, false).unwrap_err();
        assert_eq!(error.to_string(), old_words("old.json"));
        // The old file as B: its reason comes first, then its slower figures.
        let error = compare(&new, &old, false).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "{}; 2 of 4 compared figures are slower in old.json",
                old_words("old.json")
            )
        );
        compare(&old, &new, true).unwrap();
        compare(&new, &new, false).unwrap();
        compare(&old, &old, true).unwrap();
        assert!(compare(&old, &old, false).is_err());

        // A pass at another pacing is no comparison, with the flag or without it.
        let paced = write("paced.json", &new_rows(2));
        for received_only in [false, true] {
            let error = compare(&new, &paced, received_only).unwrap_err();
            assert_eq!(
                error.to_string(),
                "interval_ms differs (new.json 200, paced.json 2)"
            );
        }
        let error = compare(&old, &paced, true).unwrap_err();
        assert_eq!(
            error.to_string(),
            "interval_ms differs (old.json 200, paced.json 2)"
        );
        let mut fewer = new_rows(200);
        fewer["samples_asked"] = json!(100);
        let fewer = write("fewer-samples.json", &fewer);
        let error = compare(&new, &fewer, false).unwrap_err();
        assert_eq!(
            error.to_string(),
            "samples_asked differs (new.json 200, fewer-samples.json 100)"
        );

        // An error row in A is an incomplete baseline, however it is read.
        let mut broken_rows = new_rows(200);
        broken_rows["rows"][1] = error_row("dns forwarded");
        let broken = write("broken-baseline.json", &broken_rows);
        for received_only in [false, true] {
            let error = compare(&broken, &new, received_only).unwrap_err();
            assert_eq!(
                error.to_string(),
                "2 figures of new.json have no figure in broken-baseline.json \
                 (an incomplete baseline)"
            );
        }
    }

    #[test]
    fn the_files_are_named_by_their_names_unless_the_names_are_the_same() {
        let (a, b) = file_labels(Path::new("out/stock.json"), Path::new("out/qberrypi.json"));
        assert_eq!((a.as_str(), b.as_str()), ("stock.json", "qberrypi.json"));
        let (a, b) = file_labels(
            Path::new("stock/latency.json"),
            Path::new("qberrypi/latency.json"),
        );
        assert_eq!(
            (a.as_str(), b.as_str()),
            ("stock/latency.json", "qberrypi/latency.json")
        );
    }

    #[test]
    fn a_whole_run_against_a_fake_leaves_no_address_in_the_json() {
        let fake = FakeDns::start(|q, _| {
            let packet = if asked_name(q) == "ads.invalid" {
                reply(q, 0, Some(Ipv4Addr::UNSPECIFIED))
            } else {
                reply(q, 3, None)
            };
            vec![(Duration::ZERO, packet)]
        });
        let report = measure(
            fake.addr,
            &settings(3, Some("ads.invalid")),
            7,
            fake_ping,
            |_| {},
        );
        let text = serde_json::to_string(&render_json(&report)).unwrap();
        assert!(!text.contains("127.0.0.1"), "{text}");
        assert!(text.contains("\"lost_counted_as_ms\":"), "{text}");
        assert!(text.contains("\"received\":"), "{text}");
        let table = render_text(&report);
        assert!(table.contains("ads.invalid"));
    }
}
