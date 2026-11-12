//! The self-test of the DNS and status servers, for the boot in QEMU.
//!
//! The guest there has no network card, so nothing outside can ask the servers anything. With
//! the kernel argument [`DNS_ARG`] init asks them itself, over loopback and through the sockets
//! as an outside client would, and logs what came back. A boot that goes well shows that the
//! listeners are up on the real kernel, that the block set blocks, that a plain name is
//! NXDOMAIN, that a query that cannot be forwarded is answered SERVFAIL, and that the status
//! server answers. The marker that every snapshot holds is asked for too: it is blocked only if
//! the snapshot in the initramfs was loaded before the service listened.
//!
//! The names asked for are fixed and made up for this, so the card's log holds none of the
//! household's.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{sleep, timeout};

use crate::dns::client::{Answer, query, read_answer};
use crate::dns::upstream::UDP_BUFFER;
use crate::lists::snapshot::MARKER;

/// The kernel argument that has init run the self-test.
pub const DNS_ARG: &str = "qberrypi.selftest.dns";
/// The name that the scenario's configuration denies, which the self-test asks for.
pub const DENIED: &str = "qberrypi-selftest.invalid";
/// How long each question is given: an answer that has not come by then is `no answer`.
pub const ANSWER_WAIT: Duration = Duration::from_secs(5);
/// The kernel's file of the flags of `lo`: hexadecimal, `0x9` when it is up.
pub const LO_FLAGS: &str = "/sys/class/net/lo/flags";
/// How long to wait for `lo` to come up.
pub const LO_WAIT: Duration = Duration::from_secs(60);

/// How often the flags of `lo` are read while waiting for them.
const LO_POLL: Duration = Duration::from_millis(200);
/// What is said where there is no answer to a question.
const NO_ANSWER: &str = "no answer";
/// A name of one label, which the resolver answers NXDOMAIN without asking an upstream.
const PLAIN_NAME: &str = "printer";
/// A name that only an upstream can answer, which in the QEMU guest cannot be reached.
const OUTSIDE_NAME: &str = "example.com";
/// The path that the status server is asked for.
const STATS_PATH: &str = "/api/v1/stats";
/// The type number of an A record.
const TYPE_A: u16 = 1;
/// The ID of every query: each goes out from a socket or a connection of its own.
const QUERY_ID: u16 = 0x5e1f;
/// The longest start of the status server's answer that is read: its first line is shorter.
const STATUS_HEAD: usize = 64;

/// Whether the flags of an interface, as the kernel writes them, have the bit 0 set, which is
/// "up". The file holds hexadecimal with the prefix `0x`; anything else is not up.
pub fn is_up(flags: &str) -> bool {
    flags
        .trim()
        .strip_prefix("0x")
        .and_then(|digits| u32::from_str_radix(digits, 16).ok())
        .is_some_and(|flags| flags & 1 != 0)
}

/// Waits until the file `flags` says that the interface is up, reading it every 200 ms, for at
/// most `wait`; whether it is up. A file that is not there yet is read again.
///
/// The read is of a file in `/sys`, which the kernel answers from memory, so it does not hold
/// the runtime thread.
pub async fn lo_comes_up(flags: &Path, wait: Duration) -> bool {
    let up = async {
        while !std::fs::read_to_string(flags).is_ok_and(|text| is_up(&text)) {
            sleep(LO_POLL).await;
        }
    };
    timeout(wait, up).await.is_ok()
}

/// Asks the DNS service and the status server as an outside client would, and says what came
/// back, one line for each question, in this order:
///
/// ```text
/// selftest: dns: udp qberrypi-selftest.invalid A: NOERROR 0.0.0.0
/// selftest: dns: tcp qberrypi-selftest.invalid A: NOERROR 0.0.0.0
/// selftest: dns: udp printer A: NXDOMAIN
/// selftest: dns: udp qberrypi-snapshot.invalid A: NOERROR 0.0.0.0
/// selftest: dns: udp example.com A: SERVFAIL
/// selftest: status: /api/v1/stats: 200
/// ```
///
/// A question that has no answer within [`ANSWER_WAIT`] has `no answer` in the place of one.
pub async fn dns(dns_server: SocketAddr, status_server: SocketAddr) -> Vec<String> {
    dns_within(dns_server, status_server, ANSWER_WAIT).await
}

/// [`dns`], with each question given `wait` instead of [`ANSWER_WAIT`].
pub(crate) async fn dns_within(
    dns_server: SocketAddr,
    status_server: SocketAddr,
    wait: Duration,
) -> Vec<String> {
    let summary =
        |answer: Option<Answer>| answer.map_or_else(|| NO_ANSWER.to_owned(), |a| a.summary());
    let denied_udp = udp(dns_server, DENIED, wait).await;
    let denied_tcp = tcp(dns_server, DENIED, wait).await;
    let plain = udp(dns_server, PLAIN_NAME, wait).await;
    let marker = udp(dns_server, MARKER, wait).await;
    let outside = udp(dns_server, OUTSIDE_NAME, wait).await;
    let code = status_code(status_server, wait)
        .await
        .map_or_else(|| NO_ANSWER.to_owned(), |code| code.to_string());
    vec![
        format!("selftest: dns: udp {DENIED} A: {}", summary(denied_udp)),
        format!("selftest: dns: tcp {DENIED} A: {}", summary(denied_tcp)),
        format!("selftest: dns: udp {PLAIN_NAME} A: {}", summary(plain)),
        format!("selftest: dns: udp {MARKER} A: {}", summary(marker)),
        format!("selftest: dns: udp {OUTSIDE_NAME} A: {}", summary(outside)),
        format!("selftest: status: {STATS_PATH}: {code}"),
    ]
}

/// What `server` answers over UDP to the question `name` A within `wait`. Datagrams that are not
/// the answer to this question are not taken for it; an error ends the wait.
async fn udp(server: SocketAddr, name: &str, wait: Duration) -> Option<Answer> {
    let packet = query(QUERY_ID, name, TYPE_A).ok()?;
    let exchange = async {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.ok()?;
        socket.connect(server).await.ok()?;
        socket.send(&packet).await.ok()?;
        let mut buf = vec![0u8; UDP_BUFFER];
        loop {
            let len = socket.recv(&mut buf).await.ok()?;
            if let Some(answer) = read_answer(&buf[..len], QUERY_ID) {
                return Some(answer);
            }
        }
    };
    timeout(wait, exchange).await.ok().flatten()
}

/// What `server` answers over TCP to the question `name` A within `wait`.
async fn tcp(server: SocketAddr, name: &str, wait: Duration) -> Option<Answer> {
    let packet = query(QUERY_ID, name, TYPE_A).ok()?;
    let len = u16::try_from(packet.len()).ok()?;
    let exchange = async {
        let mut stream = TcpStream::connect(server).await.ok()?;
        stream
            .write_all(&[&len.to_be_bytes()[..], &packet[..]].concat())
            .await
            .ok()?;
        let mut head = [0u8; 2];
        stream.read_exact(&mut head).await.ok()?;
        let mut reply = vec![0u8; usize::from(u16::from_be_bytes(head))];
        stream.read_exact(&mut reply).await.ok()?;
        read_answer(&reply, QUERY_ID)
    };
    timeout(wait, exchange).await.ok().flatten()
}

/// The status code that `server` answers to a request for the statistics within `wait`.
async fn status_code(server: SocketAddr, wait: Duration) -> Option<u16> {
    let request =
        format!("GET {STATS_PATH} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    let exchange = async {
        let mut stream = TcpStream::connect(server).await.ok()?;
        stream.write_all(request.as_bytes()).await.ok()?;
        let mut head = [0u8; STATUS_HEAD];
        let mut filled = 0;
        // Up to the end of the first line, which holds the code.
        while filled < head.len() && !head[..filled].contains(&b'\n') {
            let read = stream.read(&mut head[filled..]).await.ok()?;
            if read == 0 {
                break;
            }
            filled += read;
        }
        Some(String::from_utf8_lossy(&head[..filled]).into_owned())
    };
    status_code_of(&timeout(wait, exchange).await.ok()??)
}

/// The code in the first line of an HTTP response, `HTTP/1.1 200 OK` for instance.
fn status_code_of(head: &str) -> Option<u16> {
    let mut words = head.lines().next()?.split(' ');
    words
        .next()
        .filter(|version| version.starts_with("HTTP/"))?;
    words.next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    use tokio::net::TcpListener;
    use tokio::sync::watch;

    use crate::dns::Dns;
    use crate::dns::testutil::{FakeUpstream, FixedOffset, Reply, closed_port, listen, ms};
    use crate::dns::upstream::Upstreams;
    use crate::lists::{self, ListState, Lists, Source};
    use crate::logbuf::LogBuf;
    use crate::status::Status;

    /// A DNS service that denies [`DENIED`] and whose only upstream is a port where nothing
    /// listens, and a status server over it; both on `127.0.0.1` ports, with room for two clients
    /// that may take 200 ms each. Returns the addresses of the DNS service and of the server.
    async fn service() -> (SocketAddr, SocketAddr) {
        let dns = Dns::new(
            lists::from_config(&[DENIED.to_owned(), MARKER.to_owned()], &[]).build(),
            Upstreams::with(vec![closed_port()], ms(300), ms(600)),
            Box::new(FixedOffset(0)),
        );
        let dns_addr = listen(dns.clone()).await;
        let log: &'static Mutex<LogBuf> = Box::leak(Box::new(Mutex::new(LogBuf::new(4096))));
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
            link: Arc::new(crate::live::WifiStatus::default),
            board_c: Arc::new(|| None),
            update: crate::update::UpdateCtl::off(),
        };
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let status_addr = listener.local_addr().unwrap();
        tokio::spawn(status.serve_with(listener, 2, ms(200)));
        (dns_addr, status_addr)
    }

    #[tokio::test]
    async fn the_self_test_reports_what_an_outside_client_would_see() {
        let (dns_addr, status_addr) = service().await;
        assert_eq!(
            dns(dns_addr, status_addr).await,
            [
                "selftest: dns: udp qberrypi-selftest.invalid A: NOERROR 0.0.0.0",
                "selftest: dns: tcp qberrypi-selftest.invalid A: NOERROR 0.0.0.0",
                "selftest: dns: udp printer A: NXDOMAIN",
                "selftest: dns: udp qberrypi-snapshot.invalid A: NOERROR 0.0.0.0",
                "selftest: dns: udp example.com A: SERVFAIL",
                "selftest: status: /api/v1/stats: 200",
            ]
        );
    }

    #[test]
    fn lo_is_up_when_bit_0_of_its_flags_is_set() {
        assert!(is_up("0x9\n") && is_up("0x1") && !is_up("0x8\n") && !is_up("") && !is_up("up"));
    }

    #[tokio::test]
    async fn servers_that_are_not_there_are_reported_and_do_not_hang_it() {
        let lines = dns_within(closed_port(), closed_port(), ms(200)).await;
        assert_eq!(lines.len(), 6);
        assert!(
            lines.iter().all(|line| line.ends_with(": no answer")),
            "{lines:?}"
        );
    }

    #[tokio::test]
    async fn servers_that_say_nothing_are_given_their_wait_and_no_more() {
        // Takes the queries and sends nothing back, over UDP and over TCP.
        let silent = FakeUpstream::start(Reply::Silent).await;
        // A listener that never accepts: the connection is made, and nothing is said on it.
        let quiet = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();

        let started = Instant::now();
        let lines = dns_within(silent.addr, quiet.local_addr().unwrap(), ms(200)).await;

        assert!(
            lines.iter().all(|line| line.ends_with(": no answer")),
            "{lines:?}"
        );
        // Six questions, 200 ms each.
        let took = started.elapsed();
        assert!(took >= ms(1000) && took < ms(4000), "{took:?}");
    }

    #[test]
    fn the_status_code_is_the_second_word_of_the_first_line() {
        assert_eq!(
            status_code_of("HTTP/1.1 200 OK\r\nServer: x\r\n"),
            Some(200)
        );
        assert_eq!(status_code_of("HTTP/1.0 404 not found"), Some(404));
        assert_eq!(status_code_of("200 OK\r\n"), None);
        assert_eq!(status_code_of("HTTP/1.1 ok\r\n"), None);
        assert_eq!(status_code_of(""), None);
    }

    #[tokio::test(start_paused = true)]
    async fn the_wait_for_lo_ends_when_it_is_up_or_when_the_time_is_out() {
        let dir = tempfile::tempdir().unwrap();
        let flags = dir.path().join("flags");

        // The file is not there yet, and then holds what a down interface holds.
        assert!(!lo_comes_up(&flags, Duration::from_secs(1)).await);
        std::fs::write(&flags, "0x8\n").unwrap();
        assert!(!lo_comes_up(&flags, Duration::from_secs(1)).await);

        // It comes up half a second in.
        let writer = {
            let flags = flags.clone();
            tokio::spawn(async move {
                sleep(Duration::from_millis(500)).await;
                std::fs::write(&flags, "0x9\n").unwrap();
            })
        };
        let started = tokio::time::Instant::now();
        assert!(lo_comes_up(&flags, LO_WAIT).await);
        let took = started.elapsed();
        assert!(took >= ms(500) && took <= ms(500) + LO_POLL, "{took:?}");
        writer.await.unwrap();

        // And once it is, no time is spent.
        let started = tokio::time::Instant::now();
        assert!(lo_comes_up(&flags, LO_WAIT).await);
        assert_eq!(started.elapsed(), Duration::ZERO);
    }
}
