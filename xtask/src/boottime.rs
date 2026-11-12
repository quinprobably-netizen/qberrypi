//! `cargo xtask boot-time`: measures from this computer how long a Pi takes from power-on to its
//! first DNS answer.
//!
//! The board cannot see its own power-on, so the measurement is taken from outside: the owner
//! presses Enter as the Pi's power goes in, and from then on this asks the Pi's DNS port every
//! 200 ms, first for a name that every snapshot blocks (answered without an upstream) and then
//! for a name that has to be forwarded.
//!
//! Plain std sockets and no runtime. Nothing here writes the Pi's address anywhere but the
//! terminal it was run in.

use std::collections::VecDeque;
use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use qberrypi::dns::DNS_PORT;
use qberrypi::dns::client::{Answer, query, read_answer};

use crate::probe::{configured_address, next_id};

/// How often the Pi is asked again.
pub const ASK_EVERY: Duration = Duration::from_millis(200);
/// How long after Enter the Pi is asked before the measurement gives up.
pub const GIVE_UP: Duration = Duration::from_secs(120);
/// The name every snapshot blocks, which the Pi answers with no upstream to reach.
pub const BLOCKED_NAME: &str = "qberrypi-snapshot.invalid";
/// A name no list blocks, so that only a working upstream can answer it.
pub const FORWARDED_NAME: &str = "example.com";
/// The success criterion: the first answer comes under this long after power-on.
const TARGET: Duration = Duration::from_secs(15);
/// The record type A.
const TYPE_A: u16 = 1;
/// How many questions are remembered: one for every `ASK_EVERY` of `GIVE_UP`.
const MAX_SENT: usize = 600;

/// How long after Enter each step of the Pi's start was seen; `None` for one not seen.
#[derive(Debug, Default, PartialEq)]
pub struct BootTimes {
    /// The first answer to anything: the blocked name, answered by the Pi alone.
    pub first: Option<Duration>,
    /// The first answer to the forwarded name that carries an address: the upstream is reached.
    pub forwarded: Option<Duration>,
}

/// Which name to ask next, and what answers to it say about how far the Pi has come.
#[derive(Debug, Default)]
pub struct Timer {
    /// What has been seen so far.
    pub times: BootTimes,
}

impl Timer {
    /// The name to ask next: the blocked one until it is answered, then the forwarded one until
    /// that is answered with an address; `None` once both are known.
    pub fn asking(&self) -> Option<&'static str> {
        if self.times.first.is_none() {
            Some(BLOCKED_NAME)
        } else if self.times.forwarded.is_none() {
            Some(FORWARDED_NAME)
        } else {
            None
        }
    }

    /// Takes in an answer to the name [`Timer::asking`] gives, read `at` after Enter.
    ///
    /// While the blocked name is asked, any answer of any response code counts. While the
    /// forwarded name is asked, only a NOERROR answer with an address other than `0.0.0.0` does:
    /// SERVFAIL means the upstream is not there yet, and `0.0.0.0` is the blocked reply.
    pub fn answered(&mut self, at: Duration, answer: &Answer) {
        match self.asking() {
            Some(BLOCKED_NAME) => self.times.first = Some(at),
            Some(_) => {
                let blocked_reply = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
                if answer.rcode == 0 && answer.addrs.iter().any(|addr| *addr != blocked_reply) {
                    self.times.forwarded = Some(at);
                }
            }
            None => {}
        }
    }
}

/// Seconds rounded to a tenth, which is how the report shows them and what its verdict judges.
fn tenths(time: Duration) -> f64 {
    (time.as_secs_f64() * 10.0).round() / 10.0
}

/// The two figures in words, and whether the target was met.
///
/// The text has no line break at its end: its last line ends with `met` or `missed`.
pub fn report(times: &BootTimes) -> String {
    let figure = |time: Option<Duration>| match time {
        Some(time) => format!("{:.1} s", tenths(time)),
        None => format!("none within {} s", GIVE_UP.as_secs()),
    };
    let met = times
        .first
        .is_some_and(|first| tenths(first) < TARGET.as_secs_f64());
    format!(
        "boot-time: first answer {} after power-on; first forwarded answer {}\n\
         boot-time: target: first answer under {} s: {}",
        figure(times.first),
        figure(times.forwarded),
        TARGET.as_secs(),
        if met { "met" } else { "missed" },
    )
}

/// The names the questions sent lately asked, by their IDs, so that an answer is judged by what
/// was asked and not by what is asked now.
///
/// Only the last [`MAX_SENT`] questions are kept, which is every one of a whole measurement.
#[derive(Default)]
struct Sent {
    /// The oldest first.
    asked: VecDeque<(u16, &'static str)>,
}

impl Sent {
    /// An ID that none of the remembered questions has.
    fn fresh_id(&self) -> u16 {
        loop {
            let id = next_id();
            if self.name_of(id).is_none() {
                return id;
            }
        }
    }

    /// Remembers that the question under `id` asked `name`, and forgets the oldest if that is
    /// more than [`MAX_SENT`].
    fn remember(&mut self, id: u16, name: &'static str) {
        if self.asked.len() == MAX_SENT {
            self.asked.pop_front();
        }
        self.asked.push_back((id, name));
    }

    /// The name the question under `id` asked, if it is remembered.
    fn name_of(&self, id: u16) -> Option<&'static str> {
        self.asked
            .iter()
            .find(|(sent, _)| *sent == id)
            .map(|&(_, name)| name)
    }
}

/// Gives `timer` what `datagram` says, read `at` after Enter, if it answers a question that was
/// sent for the name `timer` asks for now. A late answer to an earlier name, or to a question
/// that was never sent, changes nothing.
fn take(timer: &mut Timer, sent: &Sent, at: Duration, datagram: &[u8]) {
    let [high, low, ..] = *datagram else {
        return;
    };
    let id = u16::from_be_bytes([high, low]);
    let Some(name) = sent.name_of(id) else {
        return;
    };
    if timer.asking() != Some(name) {
        return;
    }
    if let Some(answer) = read_answer(datagram, id) {
        timer.answered(at, &answer);
    }
}

/// Asks `server` every [`ASK_EVERY`] until both steps are seen or `give_up` has passed since
/// `enter`; the times are measured from `enter` to the instant each datagram was read.
///
/// Between questions it sleeps in the socket's read. An error is for a socket that cannot be
/// opened or read, and for a Pi that no question could be sent to at all.
fn ask_until_done(server: SocketAddr, enter: Instant, give_up: Duration) -> io::Result<BootTimes> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    let deadline = enter + give_up;
    let mut timer = Timer::default();
    let mut sent = Sent::default();
    let mut next_send = Instant::now();
    let mut sends = 0u32;
    let mut send_error = None;
    let mut buf = [0u8; 4096];
    while let Some(name) = timer.asking() {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        if now >= next_send {
            let id = sent.fresh_id();
            // A failed send is a lost question, as it would be on the wire: the Pi may simply not
            // be reachable yet. Only a Pi that was never reached at all is an error.
            match socket.send_to(&query(id, name, TYPE_A)?, server) {
                Ok(_) => {
                    sent.remember(id, name);
                    sends += 1;
                }
                Err(error) => send_error = Some(error),
            }
            next_send = (next_send + ASK_EVERY).max(Instant::now());
        }
        let wait = next_send
            .min(deadline)
            .saturating_duration_since(Instant::now());
        if wait.is_zero() {
            continue;
        }
        socket.set_read_timeout(Some(wait))?;
        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                let at = Instant::now().saturating_duration_since(enter);
                if from == server {
                    take(&mut timer, &sent, at, &buf[..len]);
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error),
        }
    }
    match send_error {
        Some(error) if sends == 0 => Err(error),
        _ => Ok(timer.times),
    }
}

/// The Pi: `server` if given, else `net.address` of `<root>/qberrypi.toml`.
fn server_address(server: Option<Ipv4Addr>, root: &Path) -> Result<Ipv4Addr> {
    match server {
        Some(address) => Ok(address),
        None => configured_address(root, "--server <ipv4>"),
    }
}

/// `cargo xtask boot-time`: waits for Enter, then measures the Pi at `server` (or at
/// `net.address` of `<root>/qberrypi.toml`) and prints the report.
pub fn run(server: Option<Ipv4Addr>, root: &Path) -> Result<()> {
    let address = server_address(server, root)?;
    println!("boot-time: asking {address}; press Enter at the moment you plug the Pi's power in");
    let mut line = String::new();
    let read = io::stdin()
        .read_line(&mut line)
        .context("cannot read the Enter key")?;
    let enter = Instant::now();
    if read == 0 {
        bail!("standard input ended before Enter was pressed; run this in a terminal");
    }
    let times = ask_until_done(
        SocketAddr::new(IpAddr::V4(address), DNS_PORT),
        enter,
        GIVE_UP,
    )
    .context("cannot ask the Pi's DNS port")?;
    println!("{}", report(&times));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;

    use hickory_proto::op::Message;
    use hickory_proto::rr::RData;
    use hickory_proto::rr::rdata::A;
    use qb_dns::{Action, BlockSetBuilder, Now, Resolver, Transport};

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn ans(rcode: u8, addr: [u8; 4]) -> Answer {
        Answer {
            rcode,
            addrs: vec![IpAddr::from(addr)],
            min_ttl: Some(1),
            truncated: false,
        }
    }

    // Timer and report

    #[test]
    fn the_blocked_name_gives_the_first_answer_and_then_the_forwarded_one_is_waited_for() {
        let mut t = Timer::default();
        assert_eq!(t.asking(), Some(BLOCKED_NAME));
        t.answered(ms(9_400), &ans(0, [0, 0, 0, 0]));
        assert_eq!(t.asking(), Some(FORWARDED_NAME));
        // SERVFAIL: the upstream is not there yet.
        t.answered(ms(9_600), &ans(2, [0, 0, 0, 0]));
        // The blocked reply is not a forwarded answer.
        t.answered(ms(9_800), &ans(0, [0, 0, 0, 0]));
        assert_eq!(t.times.forwarded, None);
        t.answered(ms(11_200), &ans(0, [192, 0, 2, 10]));
        assert_eq!(
            (t.asking(), t.times),
            (
                None,
                BootTimes {
                    first: Some(ms(9_400)),
                    forwarded: Some(ms(11_200))
                }
            )
        );
    }

    #[test]
    fn any_answer_to_the_blocked_name_counts_whatever_its_code() {
        let mut t = Timer::default();
        t.answered(ms(7_000), &ans(2, [0, 0, 0, 0]));
        assert_eq!(t.times.first, Some(ms(7_000)));
    }

    #[test]
    fn a_forwarded_answer_without_an_address_or_with_an_error_code_is_not_one() {
        let mut t = Timer::default();
        t.answered(ms(1), &ans(0, [0, 0, 0, 0]));
        let empty = Answer {
            rcode: 0,
            addrs: Vec::new(),
            min_ttl: None,
            truncated: false,
        };
        t.answered(ms(2), &empty);
        t.answered(ms(3), &ans(3, [192, 0, 2, 10]));
        assert_eq!(t.times.forwarded, None);
    }

    #[test]
    fn the_report_says_whether_the_target_was_met() {
        let r = report(&BootTimes {
            first: Some(ms(9_400)),
            forwarded: None,
        });
        assert!(
            r.contains("first answer 9.4 s")
                && r.contains("none within 120 s")
                && r.ends_with("met")
        );
        assert!(
            report(&BootTimes {
                first: Some(Duration::from_secs(16)),
                forwarded: None
            })
            .ends_with("missed")
        );
        assert!(report(&BootTimes::default()).ends_with("missed"));
    }

    #[test]
    fn the_report_is_two_lines_of_whole_tenths_with_the_target_last() {
        let both = report(&BootTimes {
            first: Some(ms(9_400)),
            forwarded: Some(ms(11_249)),
        });
        assert_eq!(
            both,
            "boot-time: first answer 9.4 s after power-on; first forwarded answer 11.2 s\n\
             boot-time: target: first answer under 15 s: met"
        );
        assert_eq!(
            report(&BootTimes::default()),
            "boot-time: first answer none within 120 s after power-on; \
             first forwarded answer none within 120 s\n\
             boot-time: target: first answer under 15 s: missed"
        );
    }

    #[test]
    fn the_verdict_goes_by_the_figure_shown() {
        let at = |millis| {
            report(&BootTimes {
                first: Some(ms(millis)),
                forwarded: None,
            })
        };
        // 14.96 s shows as 15.0 s, which is not under 15 s; 14.94 s shows as 14.9 s.
        assert!(at(14_960).contains("15.0 s") && at(14_960).ends_with("missed"));
        assert!(at(14_940).contains("14.9 s") && at(14_940).ends_with("met"));
        assert!(at(15_000).ends_with("missed"));
    }

    // The questions sent

    #[test]
    fn only_the_last_questions_are_remembered_and_ids_are_not_reused() {
        assert_eq!(
            MAX_SENT as u128,
            GIVE_UP.as_millis() / ASK_EVERY.as_millis()
        );
        let mut sent = Sent::default();
        let mut ids = Vec::new();
        for _ in 0..MAX_SENT {
            let id = sent.fresh_id();
            assert!(!ids.contains(&id), "{id} was given twice");
            ids.push(id);
            sent.remember(id, BLOCKED_NAME);
        }
        assert_eq!(sent.name_of(ids[0]), Some(BLOCKED_NAME));
        let newest = sent.fresh_id();
        sent.remember(newest, FORWARDED_NAME);
        assert_eq!(sent.asked.len(), MAX_SENT);
        assert_eq!(sent.name_of(ids[0]), None);
        assert_eq!(sent.name_of(ids[1]), Some(BLOCKED_NAME));
        assert_eq!(sent.name_of(newest), Some(FORWARDED_NAME));
    }

    /// The reply of the qb-dns resolver to `query`, for a name it blocks.
    fn blocked_reply(resolver: &mut Resolver, query: &[u8]) -> Vec<u8> {
        let now = Now {
            mono_secs: 1,
            unix_secs: 1_800_000_000,
        };
        match resolver.handle_query(query, Transport::Udp, now) {
            Action::Reply(reply) => reply,
            other => panic!("not a reply: {other:?}"),
        }
    }

    /// `reply` with its first A record changed to `addr`.
    fn with_address(reply: &[u8], addr: [u8; 4]) -> Vec<u8> {
        let mut message = Message::from_vec(reply).unwrap();
        message.answers[0].data = RData::A(A(Ipv4Addr::from(addr)));
        message.to_vec().unwrap()
    }

    /// A resolver that blocks both names the measurement asks for.
    fn blocking_resolver() -> Resolver {
        let mut lists = BlockSetBuilder::new();
        lists.deny(BLOCKED_NAME).unwrap();
        lists.deny(FORWARDED_NAME).unwrap();
        Resolver::new(lists.build())
    }

    #[test]
    fn an_answer_counts_only_for_the_name_its_question_was_sent_for() {
        let mut resolver = blocking_resolver();
        let mut sent = Sent::default();
        let mut timer = Timer::default();
        let mut packets = Vec::new();
        for (id, name) in [(1, BLOCKED_NAME), (2, BLOCKED_NAME), (3, FORWARDED_NAME)] {
            sent.remember(id, name);
            packets.push(blocked_reply(
                &mut resolver,
                &query(id, name, TYPE_A).unwrap(),
            ));
        }
        let address = |packet: &[u8]| with_address(packet, [192, 0, 2, 10]);

        // An ID that was never sent, and bytes that are no message, change nothing.
        take(&mut timer, &sent, ms(1), &with_id(&packets[0], 9));
        take(&mut timer, &sent, ms(1), &[1]);
        take(&mut timer, &sent, ms(1), &[]);
        assert_eq!(timer.times, BootTimes::default());
        // The answer to the forwarded name's question means nothing while the blocked name is
        // asked for.
        take(&mut timer, &sent, ms(2), &address(&packets[2]));
        assert_eq!(timer.times, BootTimes::default());
        // The blocked name's answer is the first answer.
        take(&mut timer, &sent, ms(3), &packets[0]);
        assert_eq!(timer.times.first, Some(ms(3)));
        // The second question for the blocked name is answered late, after the switch, with an
        // address: that is no forwarded answer.
        take(&mut timer, &sent, ms(4), &address(&packets[1]));
        assert_eq!(timer.times.forwarded, None);
        // The forwarded name's own answer is.
        take(&mut timer, &sent, ms(5), &address(&packets[2]));
        assert_eq!(timer.times.forwarded, Some(ms(5)));
    }

    fn with_id(packet: &[u8], id: u16) -> Vec<u8> {
        let mut packet = packet.to_vec();
        packet[0..2].copy_from_slice(&id.to_be_bytes());
        packet
    }

    // The server's address

    #[test]
    fn the_server_is_the_flag_or_the_address_in_the_config() {
        let root = tempfile::tempdir().unwrap();
        let flag = Ipv4Addr::new(192, 0, 2, 7);
        assert_eq!(server_address(Some(flag), root.path()).unwrap(), flag);

        let error = format!("{:#}", server_address(None, root.path()).unwrap_err());
        assert!(
            error.contains("qberrypi.toml") && error.contains("--server"),
            "{error}"
        );

        let file = root.path().join("qberrypi.toml");
        fs::write(
            &file,
            "[wifi]\nssid = \"example-network\"\npassphrase = \"example-passphrase\"\ncountry = \"US\"\n\
             [net]\naddress = \"192.0.2.53/24\"\ngateway = \"192.0.2.1\"\n\
             [dns]\nupstreams = [\"9.9.9.9\"]\n",
        )
        .unwrap();
        assert_eq!(
            server_address(None, root.path()).unwrap(),
            Ipv4Addr::new(192, 0, 2, 53)
        );

        // A file that does not parse is an error that quotes none of it.
        fs::write(&file, "[wifi]\npassphrase = \"example-passphrase\n").unwrap();
        let error = format!("{:#}", server_address(None, root.path()).unwrap_err());
        assert!(
            !error.contains("example-passphrase") && !error.contains("passphrase"),
            "{error}"
        );
    }

    // Over a real socket

    /// A UDP server on 127.0.0.1 on a thread. For every datagram it records the name asked and
    /// sends what `script(name, query, n, from)` says, each packet after its delay, where `n`
    /// counts the queries from 0 and `from` is the asker. An empty list drops the question. Delayed packets go from threads of their
    /// own, so that a late answer does not hold up the next question.
    struct FakeDns {
        addr: SocketAddr,
        asked: Arc<Mutex<Vec<String>>>,
        delayed_sent: Arc<AtomicUsize>,
        stop: Arc<AtomicBool>,
        thread: Option<thread::JoinHandle<()>>,
    }

    type Script = dyn FnMut(&str, &[u8], usize, SocketAddr) -> Vec<(Duration, Vec<u8>)> + Send;

    impl FakeDns {
        fn start(mut script: Box<Script>) -> FakeDns {
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            socket.set_read_timeout(Some(ms(10))).unwrap();
            let addr = socket.local_addr().unwrap();
            let asked = Arc::new(Mutex::new(Vec::new()));
            let delayed_sent = Arc::new(AtomicUsize::new(0));
            let stop = Arc::new(AtomicBool::new(false));
            let (log, counter, flag) = (asked.clone(), delayed_sent.clone(), stop.clone());
            let thread = thread::spawn(move || {
                let mut buf = [0u8; 512];
                let mut senders = Vec::new();
                while !flag.load(Ordering::Relaxed) {
                    let Ok((len, from)) = socket.recv_from(&mut buf) else {
                        continue;
                    };
                    let query = buf[..len].to_vec();
                    let message = Message::from_vec(&query).unwrap();
                    let name = message.queries[0].name.to_ascii();
                    let name = name.trim_end_matches('.').to_owned();
                    let nth = {
                        let mut log = log.lock().unwrap();
                        log.push(name.clone());
                        log.len() - 1
                    };
                    for (delay, packet) in script(&name, &query, nth, from) {
                        if delay.is_zero() {
                            socket.send_to(&packet, from).unwrap();
                        } else {
                            let socket = socket.try_clone().unwrap();
                            let counter = counter.clone();
                            senders.push(thread::spawn(move || {
                                thread::sleep(delay);
                                socket.send_to(&packet, from).unwrap();
                                counter.fetch_add(1, Ordering::SeqCst);
                            }));
                        }
                    }
                }
                for sender in senders {
                    let _ = sender.join();
                }
            });
            FakeDns {
                addr,
                asked,
                delayed_sent,
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

    /// How long this thread has run on a CPU, from the kernel's per-thread statistics; `None`
    /// where there are none.
    fn thread_cpu_time() -> Option<Duration> {
        let stats = fs::read_to_string("/proc/thread-self/schedstat").ok()?;
        let nanos: u64 = stats.split_whitespace().next()?.parse().ok()?;
        Some(Duration::from_nanos(nanos))
    }

    #[test]
    fn answers_come_back_over_a_real_socket() {
        // Every question, for either name, gets the qb-dns blocked reply under its ID.
        let mut resolver = blocking_resolver();
        let fake = FakeDns::start(Box::new(move |_, query, _, _| {
            vec![(Duration::ZERO, blocked_reply(&mut resolver, query))]
        }));
        let started = Instant::now();
        let times = ask_until_done(fake.addr, started, Duration::from_secs(1)).unwrap();
        let took = started.elapsed();
        let first = times.first.expect("the blocked name was answered");
        assert!(first < ms(500), "{first:?}");
        // 0.0.0.0 is never a forwarded answer, so the measurement ran to its give-up.
        assert_eq!(times.forwarded, None);
        assert!(
            took >= Duration::from_secs(1) && took < ms(1_500),
            "{took:?}"
        );
        let asked = fake.asked();
        assert_eq!(asked[0], BLOCKED_NAME);
        assert!(
            asked[1..].iter().all(|name| name == FORWARDED_NAME),
            "{asked:?}"
        );
    }

    #[test]
    fn both_steps_seen_ends_the_measurement_early() {
        let mut resolver = blocking_resolver();
        let fake = FakeDns::start(Box::new(move |name, query, _, _| {
            let reply = blocked_reply(&mut resolver, query);
            let reply = if name == FORWARDED_NAME {
                with_address(&reply, [192, 0, 2, 10])
            } else {
                reply
            };
            vec![(Duration::ZERO, reply)]
        }));
        let started = Instant::now();
        let times = ask_until_done(fake.addr, started, Duration::from_secs(1)).unwrap();
        let (first, forwarded) = (times.first.unwrap(), times.forwarded.unwrap());
        assert!(first <= forwarded && forwarded < ms(500), "{times:?}");
        assert!(started.elapsed() < ms(800), "{:?}", started.elapsed());
        assert_eq!(fake.asked(), [BLOCKED_NAME, FORWARDED_NAME]);
    }

    #[test]
    fn a_late_answer_to_the_blocked_name_never_sets_the_forwarded_time() {
        // The first question (blocked name) is answered 600 ms late, with an address. The second
        // (200 ms in) is answered at once, so the forwarded name is being asked for by the time
        // the late answer arrives. The forwarded name is never answered.
        let mut resolver = blocking_resolver();
        let fake = FakeDns::start(Box::new(move |name, query, nth, _| {
            let reply = blocked_reply(&mut resolver, query);
            match (name, nth) {
                (BLOCKED_NAME, 0) => vec![(ms(600), with_address(&reply, [192, 0, 2, 10]))],
                (BLOCKED_NAME, _) => vec![(Duration::ZERO, reply)],
                _ => Vec::new(),
            }
        }));
        let started = Instant::now();
        let times = ask_until_done(fake.addr, started, Duration::from_secs(1)).unwrap();
        let first = times.first.expect("the second question was answered");
        assert!(first >= ms(150) && first < ms(500), "{first:?}");
        assert_eq!(times.forwarded, None);
        // The late answer was sent, and in time to have been read before the give-up.
        assert_eq!(fake.delayed_sent.load(Ordering::SeqCst), 1);
        assert_eq!(fake.asked()[0], BLOCKED_NAME);
        assert!(fake.asked()[2..].iter().all(|name| name == FORWARDED_NAME));
    }

    #[test]
    fn a_silent_pi_is_asked_every_200_ms_without_spinning_and_the_measurement_gives_up() {
        let fake = FakeDns::start(Box::new(|_, _, _, _| Vec::new()));
        let cpu_before = thread_cpu_time();
        let started = Instant::now();
        let times = ask_until_done(fake.addr, started, Duration::from_secs(1)).unwrap();
        let took = started.elapsed();
        let cpu_after = thread_cpu_time();
        assert_eq!(times, BootTimes::default());
        assert!(
            took >= Duration::from_secs(1) && took < ms(1_500),
            "{took:?}"
        );
        // At 0, 200, 400, 600 and 800 ms.
        let asked = fake.asked();
        assert!((4..=6).contains(&asked.len()), "{asked:?}");
        assert!(asked.iter().all(|name| name == BLOCKED_NAME));
        // A loop that polled without waiting would have used this thread's whole second.
        if let (Some(before), Some(after)) = (cpu_before, cpu_after) {
            assert!(after - before < ms(100), "{:?} of CPU", after - before);
        }
    }

    #[test]
    fn datagrams_from_other_senders_are_ignored() {
        // Every question is answered, with the right ID and the blocked reply, but from another
        // port than the server's own.
        let mut resolver = blocking_resolver();
        let intruder = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let fake = FakeDns::start(Box::new(move |_, query, _, from| {
            intruder
                .send_to(&blocked_reply(&mut resolver, query), from)
                .unwrap();
            Vec::new()
        }));
        let times = ask_until_done(fake.addr, Instant::now(), ms(500)).unwrap();
        assert_eq!(times, BootTimes::default());
        assert!(fake.asked().len() >= 2);
    }
}
