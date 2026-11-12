//! The clock: SNTP once there is a default route, then once an hour.
//!
//! The board has no battery, so it wakes up at the time of the image build. A time server is
//! asked as soon as the network can reach one, and the clock is stepped to its answer if it is
//! half a second out or more. HTTPS waits for this: with the clock wrong every certificate would
//! look not yet valid or long expired.
//!
//! The packet is that of RFC 5905, figure 8. Nothing of ours is in it but a random nonce, which
//! the server copies back and which is all that makes an answer ours.
//!
//! The only name this logs is the configured time server's.

use std::io::{self, ErrorKind};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::{Instant, sleep, timeout};

use crate::dns::Dns;
use crate::sys;

/// The port of an NTP server.
pub const NTP_PORT: u16 = 123;
/// How long a server has to answer, from the sending of the request.
pub const ANSWER_WAIT: Duration = Duration::from_secs(3);
/// The time between one successful round and the next.
pub const RESYNC_EVERY: Duration = Duration::from_secs(3600);
/// The clock is set only if it is this far from the server's time or further.
pub const STEP_AT_LEAST: Duration = Duration::from_millis(500);
/// Seconds to the next round after one that failed, by how many failed before it; the last
/// repeats.
pub const RETRY_SECS: [u64; 5] = [5, 10, 20, 40, 60];
/// Where the kernel lists the IPv4 routes.
pub const ROUTE_FILE: &str = "/proc/net/route";
/// How often the routes are looked at while there is no default route.
const ROUTE_POLL: Duration = Duration::from_secs(1);

/// The length of an NTP packet without extension fields.
const PACKET_LEN: usize = 48;
/// The room for a datagram from a server: the answer is [`PACKET_LEN`] bytes and anything after
/// that is not read.
const REPLY_BUFFER: usize = 512;
/// The first byte of a request: no leap warning, version 4, mode 3 (client).
const CLIENT_V4: u8 = 0x23;
/// The mode of an answer from a server.
const MODE_SERVER: u8 = 4;
/// The leap indicator of a server that is not synchronised.
const LEAP_UNSYNCHRONIZED: u8 = 3;
/// The highest stratum of a server that is synchronised.
const MAX_STRATUM: u8 = 15;
/// Seconds from 1900, where NTP time starts, to 1970, where Unix time does.
const NTP_TO_UNIX_SECS: u64 = 2_208_988_800;
/// Seconds that the next era of NTP time, which begins in 2036, adds to its timestamps.
const NEXT_ERA_SECS: u64 = 1 << 32;
/// A timestamp with fewer seconds than this would be a date before 1968 in the first era, which
/// no server tells, so it is taken to be in the next era: the first ends in 2036.
const NEXT_ERA_BELOW: u64 = 1 << 31;

/// Where a packet has the originate timestamp: in an answer, the transmit timestamp of the request.
const ORIGINATE: Range<usize> = 24..32;
/// Where a packet has the time at which the server received the request.
const RECEIVE: Range<usize> = 32..40;
/// Where a packet has the time at which it was sent.
const TRANSMIT: Range<usize> = 40..48;

/// The request: a client packet of version 4 that carries `nonce` as its transmit timestamp,
/// which the server copies into its originate timestamp.
pub fn request(nonce: u64) -> [u8; PACKET_LEN] {
    let mut packet = [0u8; PACKET_LEN];
    packet[0] = CLIENT_V4;
    packet[TRANSMIT].copy_from_slice(&nonce.to_be_bytes());
    packet
}

/// Why a reply was not taken for the answer to our request.
#[derive(Debug, PartialEq, Eq)]
pub enum Rejected {
    /// Fewer than 48 bytes.
    TooShort,
    /// Not mode 4: a client's packet, a broadcast, a control message.
    NotAServerReply,
    /// Stratum 0: the server tells the client to stop asking, or why it cannot answer.
    KissOfDeath,
    /// The server says that its own clock is not set: stratum above 15, or leap indicator 3.
    Unsynchronized,
    /// The originate timestamp is not our nonce: the answer to another request, or no answer.
    NotOurs,
    /// The transmit timestamp is zero: the server gave no time.
    NoTime,
    /// A time earlier than the image build, which the clock is never allowed to show.
    BeforeBuild,
}

/// The Unix time at which `reply` arrived, if it is a usable answer to the request that carried
/// `nonce`; `round_trip` is how long it took from the sending of the request to the arrival, and
/// `earliest_unix` the earliest time that is believed.
///
/// That is the server's transmit time plus half of the network delay, which is the round trip
/// less the time the server held the packet.
pub fn server_time(
    reply: &[u8],
    nonce: u64,
    round_trip: Duration,
    earliest_unix: u64,
) -> Result<Duration, Rejected> {
    if reply.len() < PACKET_LEN {
        return Err(Rejected::TooShort);
    }
    let (leap, mode) = (reply[0] >> 6, reply[0] & 7);
    let stratum = reply[1];
    if mode != MODE_SERVER {
        return Err(Rejected::NotAServerReply);
    }
    if stratum == 0 {
        return Err(Rejected::KissOfDeath);
    }
    if stratum > MAX_STRATUM || leap == LEAP_UNSYNCHRONIZED {
        return Err(Rejected::Unsynchronized);
    }
    if reply[ORIGINATE] != nonce.to_be_bytes() {
        return Err(Rejected::NotOurs);
    }
    if reply[TRANSMIT] == [0u8; 8] {
        return Err(Rejected::NoTime);
    }
    let (receive, transmit) = (timestamp(&reply[RECEIVE]), timestamp(&reply[TRANSMIT]));
    let held = transmit.saturating_sub(receive);
    let delay = round_trip.saturating_sub(held);
    // A time before 1970 is before every build.
    (transmit + delay / 2)
        .checked_sub(Duration::from_secs(NTP_TO_UNIX_SECS))
        .filter(|unix| *unix >= Duration::from_secs(earliest_unix))
        .ok_or(Rejected::BeforeBuild)
}

/// The time since 1900 that an eight-byte timestamp holds, in the era that ends after 2036.
fn timestamp(bytes: &[u8]) -> Duration {
    let secs = u64::from(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
    let fraction = u64::from(u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]));
    let secs = if secs < NEXT_ERA_BELOW {
        secs + NEXT_ERA_SECS
    } else {
        secs
    };
    // The fraction counts 2^-32 of a second; below a second, so this is under 10^9.
    let nanos = (fraction * 1_000_000_000) >> 32;
    Duration::new(secs, nanos as u32)
}

/// Whether the clock is far enough from the server's time to be set.
pub fn needs_step(clock: Duration, server: Duration) -> bool {
    clock.abs_diff(server) >= STEP_AT_LEAST
}

/// Whether the text of `/proc/net/route` holds a default route that is up.
///
/// A default route has `00000000` as its destination (the second field) and as its mask (the
/// eighth); the flags (the fourth, in hexadecimal) have the "up" bit, 1, set. The first line
/// names the columns.
pub fn has_default_route(proc_net_route: &str) -> bool {
    proc_net_route.lines().skip(1).any(|line| {
        let mut fields = line.split_ascii_whitespace();
        let destination = fields.nth(1);
        let flags = fields.nth(1);
        let mask = fields.nth(3);
        let is_up = flags
            .and_then(|flags| u32::from_str_radix(flags, 16).ok())
            .is_some_and(|flags| flags & 1 == 1);
        destination == Some("00000000") && mask == Some("00000000") && is_up
    })
}

/// Asks `server` for the time, and gives the Unix time at which its answer arrived.
///
/// The answer is the first datagram from `server` within `wait`; one that is not a usable answer
/// (see [`Rejected`]) is `ErrorKind::InvalidData`, and none at all is `ErrorKind::TimedOut`.
pub async fn ask(server: SocketAddr, wait: Duration, earliest_unix: u64) -> io::Result<Duration> {
    let nonce = sys::random_u64();
    let exchange = async {
        // Connected, so that only the server's address can answer.
        let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).await?;
        socket.connect(server).await?;
        let sent = Instant::now();
        socket.send(&request(nonce)).await?;
        let mut buf = [0u8; REPLY_BUFFER];
        let len = socket.recv(&mut buf).await?;
        Ok::<_, io::Error>((buf, len, sent.elapsed()))
    };
    let (buf, len, round_trip) = timeout(wait, exchange)
        .await
        .map_err(|_| ErrorKind::TimedOut)??;
    server_time(&buf[..len], nonce, round_trip, earliest_unix).map_err(|rejected| {
        io::Error::new(
            ErrorKind::InvalidData,
            format!("the reply was rejected: {rejected:?}"),
        )
    })
}

/// How long to wait after a round that failed, when `failed` rounds in a row failed before it.
fn retry_after(failed: usize) -> Duration {
    Duration::from_secs(RETRY_SECS[failed.min(RETRY_SECS.len() - 1)])
}

/// The clock component: it sets the clock from the configured time servers and keeps it right.
pub struct Sntp {
    /// Host names or IPv4 addresses, asked in this order.
    pub servers: Vec<String>,
    pub port: u16,
    /// How long one server has to answer.
    pub wait: Duration,
    /// The earliest Unix time that is believed.
    pub earliest_unix: u64,
    /// The file that lists the routes, and how often it is read while there is no default route.
    pub route_file: PathBuf,
    pub route_poll: Duration,
    /// What sets the system clock.
    pub set_clock: fn(Duration) -> io::Result<()>,
}

impl Sntp {
    /// The component as the board runs it: the given time servers on [`NTP_PORT`], the clock
    /// never set to a time before the build.
    pub fn for_board(servers: Vec<String>) -> Self {
        Self {
            servers,
            port: NTP_PORT,
            wait: ANSWER_WAIT,
            earliest_unix: crate::BUILD_EPOCH,
            route_file: PathBuf::from(ROUTE_FILE),
            route_poll: ROUTE_POLL,
            set_clock: sys::set_clock,
        }
    }

    /// Waits for a default route, and then sets the clock and keeps it right, for ever.
    ///
    /// `synced` is made `true` by every round that gave a time that the clock could be set from
    /// or already agreed with, and by nothing else.
    pub async fn run(self, dns: Arc<Dns>, synced: watch::Sender<bool>) -> io::Result<()> {
        log::info!("clock: waiting for a default route");
        self.wait_for_default_route().await;
        let mut failed = 0;
        let mut warned = false;
        loop {
            match self.round(&dns).await {
                Ok(()) => {
                    synced.send_replace(true);
                    (failed, warned) = (0, false);
                    sleep(RESYNC_EVERY).await;
                }
                Err(error) => {
                    // Once, until a round succeeds: the next may be in five seconds.
                    if !warned {
                        log::warn!("clock: {error}");
                        warned = true;
                    }
                    sleep(retry_after(failed)).await;
                    failed += 1;
                }
            }
        }
    }

    /// Returns once `route_file` shows a default route that is up.
    async fn wait_for_default_route(&self) {
        loop {
            // A read of a few hundred bytes from procfs takes microseconds: no blocking wait.
            let routes = std::fs::read_to_string(&self.route_file);
            if routes.is_ok_and(|routes| has_default_route(&routes)) {
                return;
            }
            sleep(self.route_poll).await;
        }
    }

    /// Tries the servers in order, and acts on the first time that one gives. The error says
    /// what stopped the round: no server gave a time, or the clock could not be set.
    async fn round(&self, dns: &Arc<Dns>) -> io::Result<()> {
        for server in &self.servers {
            match self.time_from(dns, server).await {
                Ok(time) => return self.take(dns, server, time),
                Err(error) => log::debug!("clock: {server}: {error}"),
            }
        }
        Err(io::Error::new(
            ErrorKind::TimedOut,
            "no time server answered",
        ))
    }

    /// The Unix time that the first address of `server` gives.
    async fn time_from(&self, dns: &Arc<Dns>, server: &str) -> io::Result<Duration> {
        let addr = dns
            .lookup_v4(server)
            .await?
            .first()
            .copied()
            .ok_or(ErrorKind::NotFound)?;
        ask(
            SocketAddr::from((addr, self.port)),
            self.wait,
            self.earliest_unix,
        )
        .await
    }

    /// Sets the clock to `time`, which `server` gave, if it is far enough out, and then has the
    /// resolver ask the zone for its offset from UTC again: at the new time it may be another.
    fn take(&self, dns: &Dns, server: &str, time: Duration) -> io::Result<()> {
        let clock = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        if !needs_step(clock, time) {
            return Ok(());
        }
        (self.set_clock)(time).map_err(|error| {
            io::Error::new(error.kind(), format!("the clock could not be set: {error}"))
        })?;
        dns.sync_utc_offset();
        let stepped = if time >= clock {
            (time - clock).as_secs_f64()
        } else {
            -(clock - time).as_secs_f64()
        };
        log::info!(
            "clock: set by SNTP from {server}: unix {}, stepped {stepped:+.3} s",
            time.as_secs()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::net::Ipv4Addr;
    use std::path::Path;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use qb_dns::BlockSet;
    use tokio::net::UdpSocket;
    use tokio::sync::watch;
    use tokio::time::{sleep, timeout};

    use crate::config;
    use crate::dns::testutil::{FixedOffset, closed_port, ms};
    use crate::dns::upstream::Upstreams;

    const N: u64 = 0x0123_4567_89ab_cdef;
    const T: u32 = 3_913_056_000; // 2024-01-01T00:00:00Z, Unix 1_704_067_200

    const HEAD: &str =
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n";
    const SUBNET: &str = "wlan0\t000200C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
    const DEFAULT: &str = "wlan0\t00000000\t010200C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n";

    /// A server's answer: the nonce as the originate timestamp, `first` as byte 0, and the
    /// receive and transmit timestamps, each as seconds and fraction.
    fn reply(
        nonce: u64,
        first: u8,
        stratum: u8,
        receive: (u32, u32),
        transmit: (u32, u32),
    ) -> [u8; 48] {
        let mut packet = [0u8; 48];
        packet[0] = first;
        packet[1] = stratum;
        packet[24..32].copy_from_slice(&nonce.to_be_bytes());
        for (at, (secs, fraction)) in [(32, receive), (40, transmit)] {
            packet[at..at + 4].copy_from_slice(&secs.to_be_bytes());
            packet[at + 4..at + 8].copy_from_slice(&fraction.to_be_bytes());
        }
        packet
    }

    /// The nonce that a request carries.
    fn nonce_of(request: &[u8]) -> u64 {
        u64::from_be_bytes(request[40..48].try_into().unwrap())
    }

    /// The answer of a server whose clock reads [`T`], and which held the packet no time.
    fn at_t(request: &[u8]) -> Option<[u8; 48]> {
        Some(reply(nonce_of(request), 0x24, 2, (T, 0), (T, 0)))
    }

    /// A UDP socket on `127.0.0.1` that sends what `answer` gives for each datagram, if it gives
    /// anything, until the test ends.
    async fn fake_server(
        answer: impl Fn(&[u8]) -> Option<[u8; 48]> + Send + 'static,
    ) -> SocketAddr {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((len, from)) = socket.recv_from(&mut buf).await {
                if let Some(packet) = answer(&buf[..len]) {
                    let _ = socket.send_to(&packet, from).await;
                }
            }
        });
        addr
    }

    /// A `Dns` that answers only for IPv4 literals: its one upstream is a closed port.
    fn literal_dns() -> Arc<Dns> {
        Dns::new(
            BlockSet::default(),
            Upstreams::with(vec![closed_port()], ms(1), ms(1)),
            Box::new(FixedOffset(0)),
        )
    }

    /// The clock component, asking `127.0.0.1` at the port of `server`, polling `route`.
    fn sntp(
        server: SocketAddr,
        route: &Path,
        earliest_unix: u64,
        set_clock: fn(Duration) -> io::Result<()>,
    ) -> Sntp {
        Sntp {
            servers: vec!["127.0.0.1".to_owned()],
            port: server.port(),
            wait: ms(300),
            earliest_unix,
            route_file: route.to_owned(),
            route_poll: ms(20),
            set_clock,
        }
    }

    #[test]
    fn the_request_is_a_version_4_client_packet_that_carries_only_the_nonce() {
        let r = request(N);
        assert_eq!(r[0], 0x23);
        assert!(r[1..40].iter().all(|b| *b == 0));
        assert_eq!(r[40..], [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
    }

    #[test]
    fn server_time_is_the_transmit_time_plus_half_the_network_delay() {
        // the server held the packet 100 ms (fraction 0x1999_999a); the round trip took 300 ms: 100 ms each way
        let got = server_time(&reply(N, 0x24, 2, (T, 0), (T, 0x1999_999a)), N, ms(300), 0).unwrap();
        assert!(got.abs_diff(Duration::from_millis(1_704_067_200_200)) < Duration::from_micros(10));
        // a server that says it held the packet longer than the round trip took adds nothing
        assert_eq!(
            server_time(&reply(N, 0x24, 2, (T, 0), (T + 5, 0)), N, ms(300), 0).unwrap(),
            Duration::from_secs(1_704_067_205)
        );
    }

    #[test]
    fn seconds_below_two_to_the_31_are_in_the_era_from_2036() {
        assert_eq!(
            server_time(&reply(N, 0x24, 2, (1, 0), (1, 0)), N, ms(0), 0).unwrap(),
            Duration::from_secs(2_085_978_497)
        );
    }

    #[test]
    fn a_reply_that_is_not_a_usable_answer_to_our_request_is_rejected() {
        // Review Focus 5
        let good = reply(N, 0x24, 2, (T, 0), (T, 0));
        assert_eq!(
            server_time(&good[..47], N, ms(1), 0),
            Err(Rejected::TooShort)
        );
        assert_eq!(
            server_time(&reply(N, 0x23, 2, (T, 0), (T, 0)), N, ms(1), 0),
            Err(Rejected::NotAServerReply)
        );
        assert_eq!(
            server_time(&reply(N, 0x24, 0, (T, 0), (T, 0)), N, ms(1), 0),
            Err(Rejected::KissOfDeath)
        );
        assert_eq!(
            server_time(&reply(N, 0x24, 16, (T, 0), (T, 0)), N, ms(1), 0),
            Err(Rejected::Unsynchronized)
        );
        assert_eq!(
            server_time(&reply(N, 0xe4, 2, (T, 0), (T, 0)), N, ms(1), 0),
            Err(Rejected::Unsynchronized)
        );
        assert_eq!(server_time(&good, N + 1, ms(1), 0), Err(Rejected::NotOurs));
        assert_eq!(
            server_time(&reply(N, 0x24, 2, (T, 0), (0, 0)), N, ms(1), 0),
            Err(Rejected::NoTime)
        );
        assert_eq!(
            server_time(&good, N, ms(1), 1_704_067_201),
            Err(Rejected::BeforeBuild)
        );
        assert!(server_time(&good, N, ms(1), 1_704_067_200).is_ok());
    }

    #[test]
    fn the_clock_is_stepped_only_when_it_is_half_a_second_out() {
        let at = Duration::from_millis;
        assert!(
            !needs_step(at(1_000_000), at(1_000_499)) && !needs_step(at(1_000_499), at(1_000_000))
        );
        assert!(
            needs_step(at(1_000_000), at(1_000_500)) && needs_step(at(1_000_500), at(1_000_000))
        );
    }

    #[test]
    fn a_default_route_is_a_line_with_no_destination_no_mask_and_the_up_flag() {
        assert!(
            has_default_route(&format!("{HEAD}{DEFAULT}{SUBNET}"))
                && has_default_route(&format!("{HEAD}{SUBNET}{DEFAULT}"))
        );
        for none in [
            String::new(),
            HEAD.to_owned(),
            format!("{HEAD}{SUBNET}"),
            format!("{HEAD}{}", DEFAULT.replace("0003", "0002")),
            // A route to 0.0.0.0/24 is not the default route.
            format!(
                "{HEAD}{}",
                DEFAULT.replace("\t00000000\t0\t", "\t00FFFFFF\t0\t")
            ),
        ] {
            assert!(!has_default_route(&none), "{none:?}");
        }
    }

    #[test]
    fn a_failed_round_is_retried_after_5_10_20_40_then_every_60_seconds() {
        let waits: Vec<u64> = (0..8).map(|failed| retry_after(failed).as_secs()).collect();
        assert_eq!(waits, [5, 10, 20, 40, 60, 60, 60, 60]);
    }

    #[tokio::test]
    async fn a_server_is_asked_and_its_time_taken() {
        let server = fake_server(at_t).await;
        let got = ask(server, ms(500), 0).await.unwrap();
        assert!(
            got >= Duration::from_secs(1_704_067_200) && got < Duration::from_secs(1_704_067_201)
        );
    }

    #[tokio::test]
    async fn a_server_that_answers_another_request_or_not_at_all_is_an_error() {
        // Review Focus 5
        let liar = fake_server(|_| Some(reply(N, 0x24, 2, (T, 0), (T, 0)))).await;
        assert_eq!(
            ask(liar, ms(500), 0).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let silent = fake_server(|_| None).await;
        assert_eq!(
            ask(silent, ms(100), 0).await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[tokio::test]
    async fn the_task_waits_for_a_route_then_sets_the_clock_and_says_so() {
        static SET: Mutex<Vec<Duration>> = Mutex::new(Vec::new());
        fn record(time: Duration) -> io::Result<()> {
            SET.lock().unwrap().push(time);
            Ok(())
        }

        let server = fake_server(at_t).await;
        let dir = tempfile::tempdir().unwrap();
        let route = dir.path().join("route");
        fs::write(&route, format!("{HEAD}{SUBNET}")).unwrap();
        let (tx, mut synced) = watch::channel(false);
        tokio::spawn(sntp(server, &route, 0, record).run(literal_dns(), tx));

        // No default route yet: nothing is asked, nothing is set.
        sleep(ms(200)).await;
        assert!(SET.lock().unwrap().is_empty());
        assert!(!*synced.borrow());

        fs::write(&route, format!("{HEAD}{DEFAULT}")).unwrap();
        timeout(Duration::from_secs(2), synced.changed())
            .await
            .expect("the clock was not synced within 2 s")
            .unwrap();
        assert!(*synced.borrow());
        let set = SET.lock().unwrap();
        assert_eq!(set.len(), 1);
        assert!(
            set[0] >= Duration::from_secs(1_704_067_200)
                && set[0] < Duration::from_secs(1_704_067_201)
        );
    }

    #[tokio::test]
    async fn a_time_before_the_build_never_reaches_the_clock() {
        // Review Focus 5
        static SET: Mutex<Vec<Duration>> = Mutex::new(Vec::new());
        fn record(time: Duration) -> io::Result<()> {
            SET.lock().unwrap().push(time);
            Ok(())
        }

        let asked = Arc::new(AtomicUsize::new(0));
        let count = asked.clone();
        let server = fake_server(move |request| {
            count.fetch_add(1, Ordering::SeqCst);
            at_t(request)
        })
        .await;
        let dir = tempfile::tempdir().unwrap();
        let route = dir.path().join("route");
        fs::write(&route, format!("{HEAD}{DEFAULT}")).unwrap();
        let (tx, synced) = watch::channel(false);
        tokio::spawn(sntp(server, &route, 1_704_067_300, record).run(literal_dns(), tx));

        // The server is asked, and answers with a time 100 s before the build.
        timeout(Duration::from_secs(2), async {
            while asked.load(Ordering::SeqCst) == 0 {
                sleep(ms(10)).await;
            }
        })
        .await
        .expect("the server was not asked within 2 s");
        sleep(ms(500)).await;
        assert!(SET.lock().unwrap().is_empty());
        assert!(!*synced.borrow());
        // And is not asked again at once.
        assert_eq!(asked.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_clock_that_could_not_be_set_is_not_marked_as_set() {
        // Review Focus 5: HTTPS would start against a wrong clock.
        static TRIED: AtomicUsize = AtomicUsize::new(0);
        fn refuse(_: Duration) -> io::Result<()> {
            TRIED.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::from(ErrorKind::PermissionDenied))
        }

        let asked = Arc::new(AtomicUsize::new(0));
        let count = asked.clone();
        let server = fake_server(move |request| {
            count.fetch_add(1, Ordering::SeqCst);
            at_t(request)
        })
        .await;
        let dir = tempfile::tempdir().unwrap();
        let route = dir.path().join("route");
        fs::write(&route, format!("{HEAD}{DEFAULT}")).unwrap();
        let (tx, synced) = watch::channel(false);
        // The server's time, 2024-01-01, is years from now: the clock needs a step.
        tokio::spawn(sntp(server, &route, 0, refuse).run(literal_dns(), tx));

        timeout(Duration::from_secs(2), async {
            while asked.load(Ordering::SeqCst) == 0 {
                sleep(ms(10)).await;
            }
        })
        .await
        .expect("the server was not asked within 2 s");
        sleep(ms(500)).await;
        assert_eq!(TRIED.load(Ordering::SeqCst), 1);
        assert!(!*synced.borrow());
        // And is not asked again at once: the next round is RETRY_SECS[0] later.
        assert_eq!(asked.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    #[ignore = "reaches the real internet"]
    async fn a_real_time_server_answers() {
        let config = config::parse(include_str!("../../../qberrypi.example.toml")).unwrap();
        let dns = Dns::new(
            BlockSet::default(),
            Upstreams::new(&config.dns.upstreams),
            Box::new(FixedOffset(0)),
        );
        let addrs = dns.lookup_v4("time.cloudflare.com").await.unwrap();
        let got = ask(
            SocketAddr::from((addrs[0], NTP_PORT)),
            ANSWER_WAIT,
            crate::BUILD_EPOCH,
        )
        .await
        .unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        assert!(got.abs_diff(now) < Duration::from_secs(60));
    }
}
