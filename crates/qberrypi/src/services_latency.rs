//! The host reproduction of the cached-answer latency regression: the real DNS listener on
//! loopback with a block set of 1.2M names, the real front panel loop drawing to memory on the
//! pool, the watchdog's analysis and device watch, the alert store, a list refresh that swaps in a
//! fresh set and frees the old one on the pool, and a client asking one cached name every 200 ms.
//!
//! It records the answer times and the longest time the runtime thread went without polling a
//! 1 ms heartbeat, and the longest wait for the resolver's lock from a thread that probes it. Each
//! component can be left out, one at a time, to find what holds the runtime thread.
//!
//! `cargo test -p qberrypi --release services::latency -- --ignored --nocapture`

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use qb_dns::{BlockSet, BlockSetBuilder, ListClass};

use super::*;
use crate::dns::client;
use crate::dns::testutil::{FakeUpstream, FixedOffset, Reply, ip, ms};
use crate::panel::{Deps, Panel, Surface};

/// The ad names of the synthetic block set.
const ADS: usize = 300_000;
/// The threat names of the synthetic block set.
const THREATS: usize = 900_000;

/// What runs beside the listener in one run.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Parts {
    pub panel: bool,
    pub analysis: bool,
    pub devices: bool,
    pub refresh: bool,
    pub household: bool,
    pub lock_probe: bool,
}

impl Parts {
    pub(crate) const ALL: Self = Self {
        panel: true,
        analysis: true,
        devices: true,
        refresh: true,
        household: true,
        lock_probe: true,
    };
}

/// What one run measured.
#[derive(Debug)]
pub(crate) struct Measured {
    /// The answer times of the cached name, in the order asked; `None` for one lost.
    pub answers: Vec<Option<Duration>>,
    /// The longest gap between two heartbeats of the runtime thread.
    pub gap_max: Duration,
    /// The gaps of 5 ms or more, with when they ended, from the start of the samples.
    pub long_gaps: Vec<(Duration, Duration)>,
    /// The longest wait for the resolver's lock that the probe saw.
    pub lock_wait_max: Duration,
}

impl Measured {
    pub(crate) fn percentile(&self, p: f64) -> Duration {
        let mut times: Vec<Duration> = self
            .answers
            .iter()
            .map(|a| a.unwrap_or(Duration::from_secs(2)))
            .collect();
        times.sort();
        let at = ((times.len() as f64 - 1.0) * p).round() as usize;
        times.get(at).copied().unwrap_or_default()
    }

    pub(crate) fn lost(&self) -> usize {
        self.answers.iter().filter(|a| a.is_none()).count()
    }

    pub(crate) fn line(&self, label: &str) -> String {
        format!(
            "{label:<14} p50 {:>7.2} ms  p95 {:>7.2} ms  max {:>8.2} ms  lost {}  gap_max {:>8.2} ms  gaps>=5ms {}  lock_wait_max {:>8.2} ms",
            ms_of(self.percentile(0.5)),
            ms_of(self.percentile(0.95)),
            ms_of(self.percentile(1.0)),
            self.lost(),
            ms_of(self.gap_max),
            self.long_gaps.len(),
            ms_of(self.lock_wait_max),
        )
    }
}

fn ms_of(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// The synthetic lists: `ADS` hosts lines and `THREATS` `||name^` lines.
pub(crate) fn synthetic_set(seed: u32, ads_n: usize, threats_n: usize) -> BlockSet {
    let mut ads = String::with_capacity(ads_n * 40);
    for n in 0..ads_n {
        ads.push_str(&format!("0.0.0.0 ad{n:07}.s{seed}.adhost{}.com\n", n % 977));
    }
    let mut threats = String::with_capacity(threats_n * 40);
    for n in 0..threats_n {
        threats.push_str(&format!("||th{n:07}.s{seed}.bad{}.net^\n", n % 1499));
    }
    let mut builder = BlockSetBuilder::new();
    builder.add_list(ads.as_bytes());
    builder.add_list_as(threats.as_bytes(), ListClass::Threat);
    builder.build()
}

/// A surface that keeps the last frame in memory, as a framebuffer write copies it.
struct Memory(Vec<u8>);

impl Surface for Memory {
    fn show(&mut self, frame: &[u8]) -> io::Result<()> {
        self.0.clear();
        self.0.extend_from_slice(frame);
        Ok(())
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// One question for `name` to `server`, and how long its answer took; `None` if none came in 2 s.
fn ask(socket: &UdpSocket, server: SocketAddr, id: u16, name: &str) -> Option<Duration> {
    let packet = client::query(id, name, 1).ok()?;
    let asked = Instant::now();
    socket.send_to(&packet, server).ok()?;
    let mut buf = [0u8; 1500];
    loop {
        let (len, _) = socket.recv_from(&mut buf).ok()?;
        if asked.elapsed() > Duration::from_secs(2) {
            return None;
        }
        if len >= 2 && u16::from_be_bytes([buf[0], buf[1]]) == id {
            return Some(asked.elapsed());
        }
    }
}

/// Runs the system of `parts` for `samples` questions `every` apart, and measures.
pub(crate) fn run(parts: Parts, samples: usize, every: Duration, scale: usize) -> Measured {
    let (ads_n, threats_n) = (ADS / scale, THREATS / scale);
    // The fake upstream has a runtime of its own, so that its work is not on the thread measured.
    let (up_tx, up_rx) = std::sync::mpsc::channel();
    let stop_up = Arc::new(AtomicBool::new(false));
    let upstream_thread = {
        let stop = stop_up.clone();
        std::thread::spawn(move || {
            let rt = Builder::new_current_thread().enable_all().build().unwrap();
            rt.block_on(async move {
                let up = FakeUpstream::start(Reply::Answer(ip("192.0.2.10"))).await;
                up_tx.send(up.addr).unwrap();
                while !stop.load(Ordering::Relaxed) {
                    sleep(ms(50)).await;
                }
                drop(up);
            });
        })
    };
    let upstream: SocketAddr = up_rx.recv().unwrap();

    let (ctx, slot, _wifi) = super::tests::context();
    let cfg = ctx.cfg;
    let runtime = runtime(None).unwrap();
    runtime
        .block_on(async move {
            let set = blocking("set", move || synthetic_set(0, ads_n, threats_n))
                .await
                .unwrap();
            let dns = Dns::new(
                set,
                Upstreams::with(vec![upstream], ms(300), ms(600)),
                Box::new(FixedOffset(0)),
            );
            dns.resolver().set_prefetch(true);
            let WatchState {
                alerts,
                devices,
                analysis,
            } = make_watch(cfg, &dns);
            let lists = Lists::new(crate::lists::ListState {
                source: Source::Config,
                names: 1_200_000,
                fetched_unix_secs: None,
                last_error: None,
            });
            let (_clock_set, synced) = watch::channel(true);
            slot.fill(running(&dns, &lists, &synced, &ctx.wifi, &ctx.signal));
            slot.fill_alerts(alerts.clone());
            dns.set_lane(slot.lane());

            let listeners = listen::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .unwrap();
            let server = listeners.addr();
            let costs: Costs = Arc::default();
            spawn_timed(&costs, "listener", listen::serve(dns.clone(), listeners));

            if parts.analysis {
                let (events, behaviour) = analysis.lock().unwrap().take().unwrap();
                spawn_timed(
                    &costs,
                    "analysis",
                    analysis::run(events, behaviour, alerts.clone(), analysis::clock()),
                );
            }
            if parts.devices {
                spawn_timed(
                    &costs,
                    "devices",
                    devwatch::run(devices.clone(), alerts.clone(), "lo"),
                );
            }
            let stop = Arc::new(AtomicBool::new(false));
            if parts.panel {
                let deps = Deps {
                    source: slot.clone(),
                    control: slot.clone(),
                    calibration: cfg.panel.calibration(),
                    calibrate: false,
                    lane: slot.lane(),
                    alerts: slot.clone(),
                };
                let stop = stop.clone();
                drop(tokio::task::spawn_blocking(move || {
                    let mut panel = Panel::new(Memory(Vec::new()), deps);
                    let began = Instant::now();
                    let (mut longest, mut turns) = (Duration::ZERO, 0u64);
                    while !stop.load(Ordering::Relaxed) {
                        let now_ms = u64::try_from(began.elapsed().as_millis()).unwrap();
                        let before = thread_cpu();
                        let wait = panel.turn(now_ms, unix_now()).unwrap();
                        longest = longest.max(thread_cpu() - before);
                        turns += 1;
                        std::thread::sleep(Duration::from_millis(wait));
                    }
                    eprintln!(
                        "    panel thread: {turns} turns, longest {:.3} ms, cpu {:.3} ms/s",
                        ms_of(longest),
                        ms_of(thread_cpu()) / began.elapsed().as_secs_f64()
                    );
                }));
            }
            let lock_wait_max = Arc::new(AtomicU64::new(0));
            if parts.lock_probe {
                let (stop, max, dns) = (stop.clone(), lock_wait_max.clone(), dns.clone());
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        let asked = Instant::now();
                        drop(dns.resolver());
                        let waited = u64::try_from(asked.elapsed().as_micros()).unwrap();
                        max.fetch_max(waited, Ordering::Relaxed);
                        std::thread::sleep(Duration::from_millis(1));
                    }
                });
            }
            if parts.household {
                // Other devices: a forwarded name, an ad and a threat now and then, 20 questions a second.
                let stop = stop.clone();
                std::thread::spawn(move || {
                    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
                    socket
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut n = 0u32;
                    while !stop.load(Ordering::Relaxed) {
                        n += 1;
                        let name = match n % 4 {
                            0 => format!("h{n}.example.org"),
                            1 => format!("ad{:07}.s0.adhost{}.com", n % 1000, n % 1000 % 977),
                            2 => format!("th{:07}.s0.bad{}.net", n % 1000, n % 1000 % 1499),
                            _ => "www.example.net".to_owned(),
                        };
                        let _ = ask(&socket, server, (n % 60_000) as u16 + 1, &name);
                        std::thread::sleep(Duration::from_millis(50));
                    }
                });
            }

            // The heartbeat: the gaps between the wake-ups of a task that sleeps 1 ms.
            let beats: Arc<Mutex<Beats>> = Arc::default();
            let began = Instant::now();
            let runtime_cpu_at_start = thread_cpu();
            {
                let (beats, stop) = (beats.clone(), stop.clone());
                tokio::spawn(async move {
                    let mut last = Instant::now();
                    while !stop.load(Ordering::Relaxed) {
                        sleep(Duration::from_millis(1)).await;
                        let now = Instant::now();
                        let gap = now - last;
                        last = now;
                        let mut beats = beats.lock().unwrap();
                        beats.0 = beats.0.max(gap);
                        if gap >= Duration::from_millis(5) {
                            beats.1.push((now - began, gap));
                        }
                    }
                });
            }
            if parts.refresh {
                // The refresh of the lists, a few seconds in: a fresh set built on the pool, swapped in
                // under the lock, and the old one freed on the pool.
                let dns = dns.clone();
                tokio::spawn(async move {
                    sleep(Duration::from_secs(3)).await;
                    let set = blocking("set", move || synthetic_set(1, ads_n, threats_n))
                        .await
                        .unwrap();
                    let swapped = Instant::now();
                    let old = dns.resolver().replace_blockset(set);
                    let _ = blocking("drop", move || drop(old)).await;
                    eprintln!(
                        "latency: refresh swapped at {:.1} s, old set freed in {:.0} ms",
                        (swapped - began).as_secs_f64(),
                        ms_of(swapped.elapsed())
                    );
                });
            }

            // The client: one cached name, asked once first, then every `every`.
            let client = std::thread::spawn(move || {
                let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let _ = ask(&socket, server, 1, "example.com");
                let mut answers = Vec::with_capacity(samples);
                for n in 0..samples {
                    std::thread::sleep(every);
                    answers.push(ask(&socket, server, (n % 60_000) as u16 + 2, "example.com"));
                }
                answers
            });
            let answers = loop {
                if client.is_finished() {
                    break client.join().unwrap();
                }
                sleep(ms(20)).await;
            };
            stop.store(true, Ordering::Relaxed);
            let (gap_max, long_gaps) = beats.lock().unwrap().clone();
            let secs = began.elapsed().as_secs_f64();
            eprintln!(
                "    runtime thread cpu {:.3} ms/s",
                ms_of(thread_cpu() - runtime_cpu_at_start) / secs
            );
            report_costs(&costs, secs);
            sleep(ms(300)).await;
            Measured {
                answers,
                gap_max,
                long_gaps,
                lock_wait_max: Duration::from_micros(lock_wait_max.load(Ordering::Relaxed)),
            }
        })
        .tap(|_| {
            stop_up.store(true, Ordering::Relaxed);
            let _ = upstream_thread.join();
        })
}

/// The CPU time of the calling thread.
fn thread_cpu() -> Duration {
    let t = rustix::time::clock_gettime(rustix::time::ClockId::ThreadCPUTime);
    Duration::new(t.tv_sec as u64, t.tv_nsec as u32)
}

/// What the polls of one task cost on the runtime thread: the longest, and all of them together,
/// in the thread's CPU time.
#[derive(Default)]
pub(crate) struct PollCost {
    longest: AtomicU64,
    total: AtomicU64,
    polls: AtomicU64,
}

/// `inner`, with every poll timed into `cost`.
struct Timed<F> {
    inner: std::pin::Pin<Box<F>>,
    cost: Arc<PollCost>,
}

impl<F: Future> Future for Timed<F> {
    type Output = F::Output;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<F::Output> {
        let before = thread_cpu();
        let out = self.inner.as_mut().poll(cx);
        let took = u64::try_from((thread_cpu() - before).as_nanos()).unwrap_or(u64::MAX);
        self.cost.longest.fetch_max(took, Ordering::Relaxed);
        self.cost.total.fetch_add(took, Ordering::Relaxed);
        self.cost.polls.fetch_add(1, Ordering::Relaxed);
        out
    }
}

/// Costs by task name.
pub(crate) type Costs = Arc<Mutex<Vec<(&'static str, Arc<PollCost>)>>>;

/// Spawns `future` with its polls timed under `name` in `costs`.
fn spawn_timed<F>(costs: &Costs, name: &'static str, future: F)
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let cost = Arc::new(PollCost::default());
    costs.lock().unwrap().push((name, cost.clone()));
    tokio::spawn(Timed {
        inner: Box::pin(future),
        cost,
    });
}

fn report_costs(costs: &Costs, secs: f64) {
    for (name, cost) in costs.lock().unwrap().iter() {
        eprintln!(
            "    task {name:<10} polls {:>7}  longest {:>8.3} ms  cpu {:>7.3} ms/s",
            cost.polls.load(Ordering::Relaxed),
            cost.longest.load(Ordering::Relaxed) as f64 / 1e6,
            cost.total.load(Ordering::Relaxed) as f64 / 1e6 / secs,
        );
    }
}

/// The longest gap of the heartbeat, and the gaps of 5 ms or more with when they ended.
type Beats = (Duration, Vec<(Duration, Duration)>);

trait Tap: Sized {
    fn tap(self, f: impl FnOnce(&Self)) -> Self {
        f(&self);
        self
    }
}
impl<T> Tap for T {}

#[test]
#[ignore = "a measurement of a minute or more; run it by hand with --release"]
fn latency_of_a_cached_name_with_each_part_left_out() {
    let samples: usize = std::env::var("LAT_SAMPLES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(150);
    let every = ms(200);
    let all = Parts::ALL;
    let runs = [
        ("all", all),
        (
            "no panel",
            Parts {
                panel: false,
                ..all
            },
        ),
        (
            "no analysis",
            Parts {
                analysis: false,
                ..all
            },
        ),
        (
            "no devices",
            Parts {
                devices: false,
                ..all
            },
        ),
        (
            "no refresh",
            Parts {
                refresh: false,
                ..all
            },
        ),
        (
            "no household",
            Parts {
                household: false,
                ..all
            },
        ),
        (
            "no lock probe",
            Parts {
                lock_probe: false,
                ..all
            },
        ),
    ];
    let only = std::env::var("LAT_ONLY").ok();
    for (label, parts) in runs {
        if only.as_deref().is_some_and(|o| o != label) {
            continue;
        }
        let measured = run(parts, samples, every, 1);
        eprintln!("{}", measured.line(label));
        for (at, gap) in measured.long_gaps.iter().take(20) {
            eprintln!(
                "    gap {:>8.2} ms ending at {:>6.2} s",
                ms_of(*gap),
                at.as_secs_f64()
            );
        }
    }
}

/// The regression bound: with every part running (the listener, a block set of 120k names, the
/// panel loop, the analysis, the device watch, a refresh that swaps the set, other devices
/// asking), the runtime thread is never held for anything near a lost answer, nobody waits long
/// for the resolver's lock, and no cached answer is lost. The bounds are loose, for a loaded host
/// and a debug build: the Pi's regression was answers of 30 ms and more, and answers lost for 2 s.
#[test]
fn the_runtime_thread_and_the_resolver_lock_are_never_held_long() {
    let measured = run(Parts::ALL, 25, ms(200), 10);
    eprintln!("{}", measured.line("bound"));
    assert_eq!(measured.lost(), 0, "{}", measured.line("lost"));
    assert!(
        measured.gap_max < Duration::from_millis(250),
        "{}",
        measured.line("gap")
    );
    assert!(
        measured.lock_wait_max < Duration::from_millis(50),
        "{}",
        measured.line("lock")
    );
    assert!(
        measured.percentile(0.95) < Duration::from_millis(100),
        "{}",
        measured.line("p95")
    );
}
