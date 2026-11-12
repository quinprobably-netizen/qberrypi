//! The trial: how a build that is on trial of an update confirms itself, or gives up.
//!
//! A boot that init's rules found to be the first boot of an update's trial (`UpdateCtl::trial`)
//! runs [`run`] as one component, named `trial` and essential (a trial that cannot run is no
//! trial, and the restart that its failing brings boots the slot the trial came from), which
//! `services` makes beside the other services, as it needs their shared state; any other boot has
//! none. From then on any restart boots the slot the trial came from, so the trial build must
//! prove itself, and does so alone:
//!
//! - **Health.** It confirms only when all of [`Waiting::ALL`] are met: at least `confirm_after`
//!   (120 s unless `debug.trial_confirm_secs` says otherwise) since init started, the Wi-Fi
//!   associated, the clock set, and an upstream that has answered a forwarded question. What it
//!   still waits for is kept current in [`UpdateCtl`], for `/api/v1/stats`.
//! - **The upstream.** Households ask all the time, so an answer usually came by itself: the
//!   figure is [`upstream_answers`], read and copied out, never held. When `confirm_after - 10 s`
//!   has come with none (and the Wi-Fi and the clock are up, without which no answer could come),
//!   the trial asks its own resolver on loopback for `example.org A`, 5 s to answer, every 10 s,
//!   and takes a real answer for the proof: the answer must be NOERROR with an address that is
//!   not the all-zeros address that a block gives.
//! - **The confirm.** On the blocking pool, in one use of the card through init's claim, it selects
//!   its own slot (`slots::select`) and deletes the marker (`slots::remove_marker`). A write that
//!   fails is an ERROR line and is tried again every 30 s; both steps can be repeated, as a
//!   selection that is already made writes nothing. On success the outcome is `confirmed`, the
//!   machinery is idle, and the component waits for ever.
//! - **The limit.** At 600 s since init started without a confirm the trial writes why into the
//!   marker (`failed=`, best effort, on the pool, for at most 10 s) and asks for a plain restart
//!   ([`Restart::Plain`] with [`Cause::GaveUp`]), which boots the slot it came from. The reason is
//!   made of fixed words, and never of a value from the configuration.
//!
//! With `debug.trial_offline` the Wi-Fi, the clock and the upstream are not waited for (the QEMU
//! guest has none of them); only the time is.
//!
//! **Nothing blocks the runtime's thread.** The card is used only through
//! [`services::blocking`]. The health is read with a few loads of atomics and watches and one
//! short lock of the upstreams' own figures (never the resolver's), each time copied out before
//! the next `.await`; the one thing that waits, the self-query, is a socket of the runtime's.
//! The component looks at the health at most once a second, and sleeps until the next moment at
//! which anything is due, so that the confirm is not up to a second late.

use std::future::{self, Future};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::{Instant, sleep_until, timeout};

use crate::config::{DebugCfg, TRIAL_CONFIRM_DEFAULT_SECS};
use crate::dns::client::{query, read_answer};
use crate::dns::upstream::{TlsState, UDP_BUFFER, Upstreams};
use crate::dns::{DNS_PORT, Dns};
use crate::link;
use crate::services;
use crate::slots::{self, Select, Slot};
use crate::supervisor::Ended;
use crate::update::{BootCard, CardAccess, Cause, Outcome, Restart, UpdateCtl, Waiting};
use crate::wifi::WifiStatus;

/// How long after init started a trial that is still not confirmed gives up.
pub const GIVE_UP_AFTER: Duration = Duration::from_secs(600);

/// How long after a confirm whose write failed the next try is made.
pub const RETRY_EVERY: Duration = Duration::from_secs(30);

/// How long before the confirm is due the self-query begins, when no upstream has answered yet.
pub const SELF_QUERY_LEAD: Duration = Duration::from_secs(10);

/// How long after one self-query the next is sent, while no upstream has answered.
pub const SELF_QUERY_EVERY: Duration = Duration::from_secs(10);

/// How long a self-query is given to be answered.
pub const SELF_QUERY_WAIT: Duration = Duration::from_secs(5);

/// How long the give-up's write of the reason into the marker may take before the trial restarts
/// without it. It covers the wait for the card, which init's claim bounds at 5 s.
pub const RECORD_WAIT: Duration = Duration::from_secs(10);

/// How often the health is looked at, at the least: a status that changes is seen within this.
const POLL: Duration = Duration::from_secs(1);

/// How often the list of what the trial waits for is logged, at the most, when it changes.
const WAITING_LOG_EVERY: Duration = Duration::from_secs(10);

/// The name that the self-query asks for: fixed and public, so that no household name is asked.
const SELF_QUERY_NAME: &str = "example.org";

/// The ID of the self-query, which has a socket of its own.
const SELF_QUERY_ID: u16 = 0x7121;

/// What the component needs to be told besides the machinery and the health.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    /// How long after init started the trial may confirm.
    pub confirm_after: Duration,
    /// Whether the Wi-Fi, the clock and the upstream are not waited for.
    pub offline: bool,
}

impl Settings {
    /// The settings that the bring-up switches of the configuration give: `debug.trial_confirm_secs`
    /// (0 is [`TRIAL_CONFIRM_DEFAULT_SECS`]) and `debug.trial_offline`.
    pub fn from_debug(debug: &DebugCfg) -> Self {
        let secs = match debug.trial_confirm_secs {
            0 => TRIAL_CONFIRM_DEFAULT_SECS,
            secs => secs,
        };
        Self {
            confirm_after: Duration::from_secs(secs),
            offline: debug.trial_offline,
        }
    }
}

/// What the trial looks at. Every method is quick and never blocks, as it is called on the
/// runtime's thread; only [`Health::ask`] waits, on a socket of the runtime's.
pub trait Health: Send + Sync {
    /// Whether the Wi-Fi is associated now.
    fn wifi_associated(&self) -> bool;

    /// Whether the clock has been set.
    fn clock_set(&self) -> bool;

    /// How many answers from an upstream have been counted since the start: [`upstream_answers`].
    /// The trial needs only to know whether it is above 0.
    fn upstream_answers(&self) -> u64;

    /// Asks this board's own resolver for a name that only an upstream can answer, and says
    /// whether an upstream's real answer came back. It has no bound of its own: the caller gives
    /// it [`SELF_QUERY_WAIT`] and drops it when that has run out.
    fn ask(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>>;
}

/// The health of the board that runs: the Wi-Fi's status, the clock's flag and the resolver.
pub struct BoardHealth {
    /// The Wi-Fi's status as the Wi-Fi task reports it.
    wifi: watch::Receiver<WifiStatus>,
    /// Whether the clock is set, which the SNTP client says.
    synced: watch::Receiver<bool>,
    /// The resolver, for the upstreams' figures.
    dns: Arc<Dns>,
    /// Where the board's own resolver listens.
    resolver: SocketAddr,
}

impl BoardHealth {
    /// The health of a board whose resolver is `dns`, listening on loopback port 53.
    pub fn new(
        wifi: watch::Receiver<WifiStatus>,
        synced: watch::Receiver<bool>,
        dns: Arc<Dns>,
    ) -> Self {
        Self {
            wifi,
            synced,
            dns,
            resolver: SocketAddr::from((Ipv4Addr::LOCALHOST, DNS_PORT)),
        }
    }
}

impl Health for BoardHealth {
    fn wifi_associated(&self) -> bool {
        // The status is looked at and let go in this one statement.
        link::is_associated(&self.wifi.borrow())
    }

    fn clock_set(&self) -> bool {
        *self.synced.borrow()
    }

    fn upstream_answers(&self) -> u64 {
        upstream_answers(self.dns.upstreams())
    }

    fn ask(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(ask_resolver(self.resolver))
    }
}

/// How many answers from an upstream `upstreams` has had, as proof that the way out works.
///
/// Over UDP and TCP that is the sum of the answers that the exchanges used, of every upstream. When
/// the upstreams are asked over TLS, the answers over UDP that were counted before the switch (the
/// time servers' names) prove nothing of it, so they are not counted: the figure is the TLS
/// handshakes completed, which need the clock, the way out and a certificate that checks, and is
/// 0 while the switch waits for the clock. The upstreams' own lock is taken once, for a few
/// additions and a small copy; the resolver's is not touched.
pub fn upstream_answers(upstreams: &Upstreams) -> u64 {
    match upstreams.tls() {
        TlsState::Off => upstreams
            .servers()
            .iter()
            .map(|server| server.answered)
            .sum(),
        TlsState::WaitingForClock => 0,
        TlsState::On { counts, .. } => counts.connects,
    }
}

/// Asks the resolver at `server` over UDP for `example.org A`, and says whether its answer is a
/// real one: NOERROR and an address that is not all zeros (a block's answer is).
///
/// A datagram that is not the answer to this question is not taken for it. A failure to send or
/// to read is `false`. It waits for as long as no answer comes: the caller bounds it.
pub async fn ask_resolver(server: SocketAddr) -> bool {
    let Ok(packet) = query(SELF_QUERY_ID, SELF_QUERY_NAME, 1) else {
        return false;
    };
    let Ok(socket) = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await else {
        return false;
    };
    if socket.connect(server).await.is_err() || socket.send(&packet).await.is_err() {
        return false;
    }
    let mut buf = vec![0u8; UDP_BUFFER];
    loop {
        let Ok(len) = socket.recv(&mut buf).await else {
            return false;
        };
        if let Some(answer) = read_answer(&buf[..len], SELF_QUERY_ID) {
            return answer.rcode == 0 && answer.addrs.iter().any(|addr| !addr.is_unspecified());
        }
    }
}

/// What the trial has found about each thing it waits for, at one look.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Met {
    /// The Wi-Fi is associated (or the trial is offline).
    wifi: bool,
    /// The clock is set (or the trial is offline).
    clock: bool,
    /// An upstream has answered (or the trial is offline).
    upstream: bool,
    /// The time since init started has reached the confirm time.
    time: bool,
}

impl Met {
    /// What is not met, in the order of [`Waiting::ALL`]: empty when the trial may confirm.
    fn waiting(self) -> Vec<Waiting> {
        Waiting::ALL
            .into_iter()
            .filter(|what| !match what {
                Waiting::Wifi => self.wifi,
                Waiting::Clock => self.clock,
                Waiting::Upstream => self.upstream,
                Waiting::Time => self.time,
            })
            .collect()
    }
}

/// The words of `waiting` for a log line, `wifi, clock`.
fn words(waiting: &[Waiting]) -> String {
    let words: Vec<&str> = waiting.iter().map(|what| what.word()).collect();
    words.join(", ")
}

/// Why a trial gives up, in fixed words: what it still waited for, or that the card refused the
/// confirm. At most [`slots::FAILED_CAP`] bytes, as the marker takes at most that.
fn give_up_reason(waiting: &[Waiting]) -> String {
    let limit = GIVE_UP_AFTER.as_secs();
    if waiting.is_empty() {
        format!("gave up after {limit} s: the confirm could not be written to the card")
    } else {
        format!(
            "gave up after {limit} s: still waiting for {}",
            words(waiting)
        )
    }
}

/// What the loop remembers from one look to the next.
#[derive(Default)]
struct Progress {
    /// An upstream has answered: once seen, it stays seen.
    upstream_seen: bool,
    /// When the last self-query was sent.
    asked_at: Option<Instant>,
    /// How many self-queries were sent.
    asks: u32,
    /// Not before this time is the confirm tried again, after a write that failed.
    retry_at: Option<Instant>,
    /// What was last given to the machinery as what the trial waits for.
    shown: Option<Vec<Waiting>>,
    /// When, and as what, the waiting list was last logged.
    logged: Option<(Instant, Vec<Waiting>)>,
}

impl Progress {
    /// Whether a self-query may go out at `now`: none has, or the last was long enough ago.
    fn may_ask(&self, now: Instant) -> bool {
        self.asked_at
            .is_none_or(|at| now.saturating_duration_since(at) >= SELF_QUERY_EVERY)
    }

    /// Gives the machinery what the trial waits for when that changed, and logs it when it
    /// changed and the last line was at least [`WAITING_LOG_EVERY`] ago (a change that is held
    /// back is logged at the first look after).
    fn show(&mut self, ctl: &UpdateCtl, waiting: &[Waiting], now: Instant) {
        if self.shown.as_deref() != Some(waiting) {
            ctl.set_waiting(waiting.to_vec());
            self.shown = Some(waiting.to_vec());
        }
        let changed = self
            .logged
            .as_ref()
            .is_none_or(|(_, last)| last.as_slice() != waiting);
        let due = self
            .logged
            .as_ref()
            .is_none_or(|(at, _)| now.saturating_duration_since(*at) >= WAITING_LOG_EVERY);
        if changed && due {
            if waiting.is_empty() {
                log::info!("update: trial: nothing is waited for any more");
            } else {
                log::info!("update: trial: waiting for {}", words(waiting));
            }
            self.logged = Some((now, waiting.to_vec()));
        }
    }
}

/// Runs the trial of this boot: see the module's text. Waits for ever once it has confirmed, or
/// has asked for the restart that follows its giving up; a boot that is not on trial does nothing
/// and waits for ever at once.
pub async fn run(ctl: Arc<UpdateCtl>, health: Arc<dyn Health>, settings: Settings) -> Ended {
    let Some(trial) = ctl.trial() else {
        return future::pending().await;
    };
    let (me, from, build) = (trial.marker.slot, trial.marker.from, trial.marker.build);
    let began = trial.began;
    log::info!(
        "update: trial of build {build} on slot {me}: confirms {} s after init started{}",
        settings.confirm_after.as_secs(),
        if settings.offline {
            ", with no Wi-Fi, clock or upstream waited for"
        } else {
            ", once the Wi-Fi, the clock and an upstream are healthy"
        }
    );
    let ask_from = settings.confirm_after.saturating_sub(SELF_QUERY_LEAD);
    let mut progress = Progress::default();
    loop {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(began);

        let wifi = settings.offline || health.wifi_associated();
        let clock = settings.offline || health.clock_set();
        if !settings.offline && !progress.upstream_seen && health.upstream_answers() > 0 {
            progress.upstream_seen = true;
        }
        // No answer can come before the Wi-Fi and the clock are up, so no question is wasted.
        if !settings.offline
            && !progress.upstream_seen
            && wifi
            && clock
            && elapsed >= ask_from
            && progress.may_ask(now)
        {
            progress.asked_at = Some(now);
            progress.asks += 1;
            let answered = timeout(SELF_QUERY_WAIT, health.ask())
                .await
                .unwrap_or(false);
            log_self_query(progress.asks, answered);
            progress.upstream_seen = answered;
            // Time has passed: look again from the top.
            continue;
        }
        let met = Met {
            wifi,
            clock,
            upstream: settings.offline || progress.upstream_seen,
            time: elapsed >= settings.confirm_after,
        };
        let waiting = met.waiting();
        progress.show(&ctl, &waiting, now);

        if elapsed >= GIVE_UP_AFTER {
            let reason = give_up_reason(&waiting);
            return give_up(&ctl, from, build, reason).await;
        }

        if waiting.is_empty() && progress.retry_at.is_none_or(|at| now >= at) {
            match confirm(&ctl, me).await {
                Ok(()) => {
                    ctl.finish(Outcome::confirmed(build));
                    log::info!("update: build {build} confirmed on slot {me}");
                    return future::pending().await;
                }
                Err(error) => {
                    progress.retry_at = Some(Instant::now() + RETRY_EVERY);
                    log::error!(
                        "update: confirming build {build} on slot {me} failed: {error}; trying again in {} s",
                        RETRY_EVERY.as_secs()
                    );
                }
            }
            continue;
        }

        sleep_until(next_wake(now, began, settings, &progress)).await;
    }
}

/// Logs what a self-query came to, the first one and then one in six, so that a minute of failures
/// is one line.
fn log_self_query(asks: u32, answered: bool) {
    if answered {
        log::info!("update: trial: an upstream answered a question for {SELF_QUERY_NAME}");
    } else if asks == 1 || asks.is_multiple_of(6) {
        log::warn!(
            "update: trial: no upstream answered a question for {SELF_QUERY_NAME} (asked {asks} times)"
        );
    }
}

/// When the loop looks next: [`POLL`] from `now`, or sooner when something is due before then, so
/// that a deadline is not missed by up to a poll.
fn next_wake(now: Instant, began: Instant, settings: Settings, progress: &Progress) -> Instant {
    let ask_from = began + settings.confirm_after.saturating_sub(SELF_QUERY_LEAD);
    let next_ask = progress
        .asked_at
        .map_or(ask_from, |at| (at + SELF_QUERY_EVERY).max(ask_from));
    let due = [
        Some(began + settings.confirm_after),
        Some(began + GIVE_UP_AFTER),
        (!settings.offline && !progress.upstream_seen).then_some(next_ask),
        progress.retry_at,
    ];
    due.into_iter()
        .flatten()
        .filter(|at| *at > now)
        .fold(now + POLL, Instant::min)
}

/// One use of the card, on the boot partition writable, that runs `work` and gives what it gave.
/// A card that cannot be used is the error, and `work` has not run.
fn use_card<T>(card: &dyn BootCard, mut work: impl FnMut(&Path) -> io::Result<T>) -> io::Result<T> {
    let mut result = None;
    card.with_boot(CardAccess::Writable, &mut |boot| result = Some(work(boot)))?;
    result.unwrap_or_else(|| Err(io::Error::other("the card's use did not run")))
}

/// The confirm's two writes on a mounted boot partition: selects `me`, then deletes the marker.
///
/// A selection that is made already writes nothing, and a marker that is gone is no error, so the
/// pair can be repeated after either half failed. A slot's `config.txt` that is refused is an error
/// that names the file and never quotes it.
fn confirm_in(boot: &Path, me: Slot) -> io::Result<()> {
    match slots::select(boot, me)? {
        Select::Selected | Select::AlreadySelected => {}
        Select::Refused(reason) => {
            return Err(io::Error::other(format!(
                "slot {me} cannot be selected: {reason}"
            )));
        }
    }
    slots::remove_marker(boot)
}

/// The confirm, on the blocking pool: one writable use of the card through init's claim.
async fn confirm(ctl: &Arc<UpdateCtl>, me: Slot) -> io::Result<()> {
    let ctl = ctl.clone();
    services::blocking("trial confirm", move || {
        use_card(ctl.card(), |boot| confirm_in(boot, me))
    })
    .await?
}

/// Writes the reason for giving up into the marker, on the blocking pool; at most
/// [`RECORD_WAIT`] is waited for it. A failure is a line of the log and nothing else.
async fn record_failure(ctl: &Arc<UpdateCtl>, reason: &str) {
    let (ctl, line) = (ctl.clone(), slots::failed_line(reason));
    let written = services::blocking("trial give-up", move || {
        use_card(ctl.card(), |boot| slots::append_line(boot, &line))
    });
    match timeout(RECORD_WAIT, written).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error)) | Err(error)) => {
            log::warn!("update: the reason could not be written to the trial marker: {error}");
        }
        Err(_) => log::warn!(
            "update: writing the reason to the trial marker took longer than {} s; restarting without it",
            RECORD_WAIT.as_secs()
        ),
    }
}

/// Gives up: says so, records why in the marker as far as the card allows, asks for a plain
/// restart, which boots the slot the trial came from, and waits for the supervisor to end.
async fn give_up(ctl: &Arc<UpdateCtl>, from: Slot, build: u64, reason: String) -> Ended {
    log::error!(
        "update: build {build} did not confirm within {} s ({reason}); restarting to boot slot {from}",
        GIVE_UP_AFTER.as_secs()
    );
    record_failure(ctl, &reason).await;
    ctl.request_restart(Restart::Plain(Cause::GaveUp(reason)));
    future::pending().await
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Mutex, PoisonError};
    use std::thread::{self, ThreadId};
    use std::time::Duration;

    use tokio::task::JoinHandle;
    use tokio::time::{advance, sleep};

    use crate::config;
    use crate::dns::testutil::{Reply, ip, ms, one};
    use crate::slots::{Marker, Mode};

    /// Builds that no other test uses, so that a test finds its own lines in the shared log.
    const BUILD: u64 = 1_794_470_001;

    /// The log buffer every test of this binary shares; see `fault::tests`.
    fn log_text() -> String {
        crate::logbuf::install(Box::new(io::sink()))
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .text()
    }

    /// The health that a test sets by hand: the three inputs, and what a self-query comes to.
    struct Fake {
        wifi: AtomicBool,
        clock: AtomicBool,
        answers: AtomicU64,
        /// What the next self-queries answer; `None` never comes back, as a resolver that is silent.
        ask_answers: Mutex<Option<bool>>,
        asks: AtomicUsize,
    }

    impl Fake {
        /// A board that is healthy but for the upstream, which has not answered by itself.
        fn healthy() -> Arc<Self> {
            Arc::new(Self {
                wifi: AtomicBool::new(true),
                clock: AtomicBool::new(true),
                answers: AtomicU64::new(0),
                ask_answers: Mutex::new(Some(true)),
                asks: AtomicUsize::new(0),
            })
        }

        /// A board that is healthy including an upstream's answer of its own accord.
        fn answered() -> Arc<Self> {
            let fake = Self::healthy();
            fake.answers.store(3, Ordering::SeqCst);
            fake
        }

        fn asks(&self) -> usize {
            self.asks.load(Ordering::SeqCst)
        }

        fn set_ask(&self, to: Option<bool>) {
            *self.ask_answers.lock().unwrap() = to;
        }
    }

    impl Health for Fake {
        fn wifi_associated(&self) -> bool {
            self.wifi.load(Ordering::SeqCst)
        }
        fn clock_set(&self) -> bool {
            self.clock.load(Ordering::SeqCst)
        }
        fn upstream_answers(&self) -> u64 {
            self.answers.load(Ordering::SeqCst)
        }
        fn ask(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
            self.asks.fetch_add(1, Ordering::SeqCst);
            let answer = *self.ask_answers.lock().unwrap();
            Box::pin(async move {
                match answer {
                    Some(answer) => answer,
                    None => future::pending().await,
                }
            })
        }
    }

    /// A card that is a directory, which records how it was used: the threads, and a number of
    /// uses that fail before the first that works.
    struct Card {
        dir: tempfile::TempDir,
        uses: Mutex<Vec<(CardAccess, ThreadId)>>,
        fail: AtomicUsize,
    }

    impl Card {
        /// A card with two slots that selects `selected` and holds the marker of a trial of
        /// build `build` of slot `slot`, as the updater leaves it and init has marked it started.
        fn of_trial(slot: Slot, selected: Slot, build: u64) -> Arc<Self> {
            let dir = tempfile::tempdir().unwrap();
            for each in [Slot::A, Slot::B] {
                let folder = dir.path().join(each.dir());
                std::fs::create_dir(&folder).unwrap();
                std::fs::write(folder.join("config.txt"), config_of(each)).unwrap();
            }
            std::fs::write(dir.path().join("config.txt"), config_of(selected)).unwrap();
            let marker = Marker {
                slot,
                from: slot.other(),
                build,
                mode: Mode::Tryboot,
                started: true,
                failed: None,
            };
            slots::write_marker(dir.path(), &marker).unwrap();
            Arc::new(Self {
                dir,
                uses: Mutex::new(Vec::new()),
                fail: AtomicUsize::new(0),
            })
        }

        fn failing(self: Arc<Self>, times: usize) -> Arc<Self> {
            self.fail.store(times, Ordering::SeqCst);
            self
        }

        fn uses(&self) -> usize {
            self.uses.lock().unwrap().len()
        }

        fn selected(&self) -> Slot {
            let config = std::fs::read(self.dir.path().join("config.txt")).unwrap();
            slots::selected_slot(&config).unwrap()
        }

        fn marker(&self) -> Option<Marker> {
            slots::read_marker(self.dir.path())
                .unwrap()
                .map(|marker| marker.unwrap())
        }
    }

    /// A `config.txt` that selects `slot`.
    fn config_of(slot: Slot) -> String {
        format!("# slot\narm_64bit=1\nos_prefix={}\n", slot.os_prefix())
    }

    /// Lends a [`Card`] to the machinery, as init lends the real one.
    struct Lent(Arc<Card>);

    impl BootCard for Lent {
        fn with_boot(&self, access: CardAccess, work: &mut dyn FnMut(&Path)) -> io::Result<()> {
            self.0
                .uses
                .lock()
                .unwrap()
                .push((access, thread::current().id()));
            let failing = self.0.fail.load(Ordering::SeqCst);
            if failing > 0 {
                self.0.fail.store(failing - 1, Ordering::SeqCst);
                return Err(io::Error::other("the card is in use by another thread"));
            }
            work(self.0.dir.path());
            Ok(())
        }
    }

    /// A trial of build `build` on slot b that began now (on the paused clock), with the card that
    /// holds its marker.
    fn trial_on(card: &Arc<Card>, build: u64) -> Arc<UpdateCtl> {
        let ctl = UpdateCtl::new(Some(Slot::B), None, Arc::new(Lent(card.clone())));
        let marker = card.marker().unwrap();
        assert_eq!(marker.build, build);
        ctl.begin_trial(marker, Instant::now());
        ctl
    }

    /// The usual settings: 120 s, with the network waited for.
    fn usual() -> Settings {
        Settings {
            confirm_after: Duration::from_secs(120),
            offline: false,
        }
    }

    /// Lets the tasks and the pool's jobs that are ready run, for a millisecond of the paused clock.
    /// A job of the pool holds the clock until it is done, so this waits for one that is running.
    async fn settle() {
        sleep(ms(1)).await;
    }

    /// Starts the trial's `run`, and gives the task.
    fn start(ctl: &Arc<UpdateCtl>, health: &Arc<Fake>, settings: Settings) -> JoinHandle<Ended> {
        crate::logbuf::install(Box::new(io::sink()));
        let health: Arc<dyn Health> = health.clone();
        tokio::spawn(run(ctl.clone(), health, settings))
    }

    /// Moves the paused clock on by `total`, as time goes by: in steps of at most a second, after
    /// each of which whatever is due happens (the time `settle` takes is part of the step, so the
    /// clock is `total` further on at the end, to the millisecond). A single jump would wake the
    /// trial once, at the end, which is not how a clock runs.
    async fn pass_for(total: Duration) {
        let mut left = total;
        while !left.is_zero() {
            let step = left.min(Duration::from_secs(1));
            advance(step.saturating_sub(ms(1))).await;
            settle().await;
            left -= step;
        }
        // What falls due at the very end happens too, a millisecond after it.
        settle().await;
    }

    /// [`pass_for`] `secs` seconds.
    async fn pass(secs: u64) {
        pass_for(Duration::from_secs(secs)).await;
    }

    // ------------------------------------------------------------------ the pure parts

    #[test]
    fn what_is_waited_for_is_what_is_not_met_in_the_statistics_order() {
        let all = Met {
            wifi: true,
            clock: true,
            upstream: true,
            time: true,
        };
        assert_eq!(all.waiting(), []);
        let none = Met {
            wifi: false,
            clock: false,
            upstream: false,
            time: false,
        };
        assert_eq!(none.waiting(), Waiting::ALL);
        assert_eq!(
            Met {
                clock: false,
                time: false,
                ..all
            }
            .waiting(),
            [Waiting::Clock, Waiting::Time]
        );
        assert_eq!(
            Met {
                upstream: false,
                ..all
            }
            .waiting(),
            [Waiting::Upstream]
        );
    }

    #[test]
    fn the_reason_for_giving_up_names_what_was_waited_for_in_fixed_words() {
        assert_eq!(
            give_up_reason(&[Waiting::Wifi, Waiting::Upstream]),
            "gave up after 600 s: still waiting for wifi, upstream"
        );
        assert_eq!(
            give_up_reason(&[]),
            "gave up after 600 s: the confirm could not be written to the card"
        );
        for waiting in [&[][..], &Waiting::ALL[..]] {
            let reason = give_up_reason(waiting);
            assert!(reason.len() <= slots::FAILED_CAP, "{reason}");
            // The marker keeps it whole: one line, nothing dropped.
            assert_eq!(slots::failed_line(&reason), format!("failed={reason}"));
        }
    }

    #[test]
    fn the_settings_follow_the_bring_up_switches_with_zero_for_the_default() {
        let debug = |secs: u64, offline: bool| {
            let text = include_str!("../../../../qberrypi.example.toml")
                .replace(
                    "trial_confirm_secs = 0",
                    &format!("trial_confirm_secs = {secs}"),
                )
                .replace(
                    "trial_offline = false",
                    &format!("trial_offline = {offline}"),
                );
            config::parse(&text).unwrap().debug
        };
        assert_eq!(Settings::from_debug(&debug(0, false)), usual());
        assert_eq!(
            Settings::from_debug(&debug(5, true)),
            Settings {
                confirm_after: Duration::from_secs(5),
                offline: true
            }
        );
        assert_eq!(
            Settings::from_debug(&debug(3600, false)).confirm_after,
            Duration::from_secs(3600)
        );
    }

    #[test]
    fn the_confirm_selects_the_slot_and_deletes_the_marker_and_can_be_repeated() {
        let card = Card::of_trial(Slot::B, Slot::A, BUILD);
        confirm_in(card.dir.path(), Slot::B).unwrap();
        assert_eq!(card.selected(), Slot::B);
        assert_eq!(card.marker(), None);
        // Cut off after the first half, or run twice: the second run changes nothing and fails not.
        confirm_in(card.dir.path(), Slot::B).unwrap();
        assert_eq!(card.selected(), Slot::B);
        // The same bytes as the slot's own file, which is the selection.
        assert_eq!(
            std::fs::read(card.dir.path().join("config.txt")).unwrap(),
            std::fs::read(card.dir.path().join("qberrypi-b/config.txt")).unwrap()
        );
    }

    #[test]
    fn a_slot_config_that_cannot_be_selected_fails_the_confirm_and_keeps_the_marker() {
        let card = Card::of_trial(Slot::B, Slot::A, BUILD);
        std::fs::write(card.dir.path().join("qberrypi-b/config.txt"), "# nothing\n").unwrap();
        let error = confirm_in(card.dir.path(), Slot::B).unwrap_err();
        assert!(
            error.to_string().contains("slot b cannot be selected"),
            "{error}"
        );
        assert_eq!(card.selected(), Slot::A);
        assert!(card.marker().is_some());
    }

    #[test]
    fn a_card_that_cannot_be_used_is_an_error_and_the_work_does_not_run() {
        let card = Card::of_trial(Slot::B, Slot::A, BUILD).failing(1);
        let mut ran = false;
        let error = use_card(&Lent(card), |_| {
            ran = true;
            Ok(())
        })
        .unwrap_err();
        assert!(!ran);
        assert!(error.to_string().contains("in use"), "{error}");
        // A lend that never ran the work is an error too, not a success.
        struct Idle;
        impl BootCard for Idle {
            fn with_boot(&self, _: CardAccess, _: &mut dyn FnMut(&Path)) -> io::Result<()> {
                Ok(())
            }
        }
        assert!(use_card(&Idle, |_| Ok(())).is_err());
    }

    // ------------------------------------------------------------------ the confirm

    #[tokio::test(start_paused = true)]
    async fn the_trial_confirms_at_120_seconds_and_not_before() {
        let card = Card::of_trial(Slot::B, Slot::A, BUILD);
        let ctl = trial_on(&card, BUILD);
        let task = start(&ctl, &Fake::answered(), usual());

        pass(119).await;
        assert_eq!(card.uses(), 0, "nothing is written before the time");
        assert_eq!((card.selected(), card.marker().is_some()), (Slot::A, true));
        let view = ctl.view();
        assert_eq!(view.state, "trial");
        assert_eq!(view.trial.unwrap().waiting_for, [Waiting::Time]);

        pass(1).await;
        assert_eq!(card.uses(), 1);
        assert_eq!((card.selected(), card.marker()), (Slot::B, None));
        let view = ctl.view();
        assert_eq!((view.state, view.trial), ("idle", None));
        assert_eq!(view.last, Some(Outcome::confirmed(BUILD)));
        assert!(log_text().contains(&format!("update: build {BUILD} confirmed on slot b")));
        // It does nothing more, and does not end.
        pass(3600).await;
        assert_eq!(card.uses(), 1);
        assert!(!task.is_finished());
        assert_eq!(*ctl.restart_receiver().borrow(), None);
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn the_confirm_is_not_a_poll_late() {
        // The trial starts 0.4 s after init did, so its looks (one a second) fall at .4 of every
        // second: the confirm, due at 120 s, must not wait for the one at 120.4.
        let card = Card::of_trial(Slot::B, Slot::A, BUILD);
        let ctl = trial_on(&card, BUILD);
        pass_for(ms(400)).await;
        let task = start(&ctl, &Fake::answered(), usual());
        pass_for(ms(119_400)).await;
        assert_eq!(card.uses(), 0);
        pass_for(ms(300)).await;
        assert_eq!(card.uses(), 1);
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn the_trial_waits_while_any_one_input_is_missing_and_says_which() {
        for (missing, expected) in [
            ("wifi", Waiting::Wifi),
            ("clock", Waiting::Clock),
            ("upstream", Waiting::Upstream),
        ] {
            let card = Card::of_trial(Slot::B, Slot::A, BUILD);
            let ctl = trial_on(&card, BUILD);
            let health = Fake::answered();
            match missing {
                "wifi" => health.wifi.store(false, Ordering::SeqCst),
                "clock" => health.clock.store(false, Ordering::SeqCst),
                _ => {
                    health.answers.store(0, Ordering::SeqCst);
                    // Nor does a self-query come back.
                    health.set_ask(Some(false));
                }
            }
            let task = start(&ctl, &health, usual());

            pass(300).await;
            assert_eq!(card.uses(), 0, "{missing}");
            assert_eq!(
                ctl.view().trial.unwrap().waiting_for,
                [expected],
                "{missing}"
            );

            // The input comes: the trial confirms at the next look.
            match missing {
                "wifi" => health.wifi.store(true, Ordering::SeqCst),
                "clock" => health.clock.store(true, Ordering::SeqCst),
                _ => health.answers.store(1, Ordering::SeqCst),
            }
            pass(1).await;
            assert_eq!((card.uses(), card.selected()), (1, Slot::B), "{missing}");
            task.abort();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_waiting_list_is_everything_at_first_and_shrinks_as_inputs_come() {
        let card = Card::of_trial(Slot::B, Slot::A, BUILD);
        let ctl = trial_on(&card, BUILD);
        let health = Fake::healthy();
        health.wifi.store(false, Ordering::SeqCst);
        health.clock.store(false, Ordering::SeqCst);
        health.set_ask(Some(false));
        let task = start(&ctl, &health, usual());
        settle().await;
        assert_eq!(ctl.view().trial.unwrap().waiting_for, Waiting::ALL);
        health.wifi.store(true, Ordering::SeqCst);
        pass(2).await;
        assert_eq!(
            ctl.view().trial.unwrap().waiting_for,
            [Waiting::Clock, Waiting::Upstream, Waiting::Time]
        );
        health.clock.store(true, Ordering::SeqCst);
        health.answers.store(1, Ordering::SeqCst);
        pass(2).await;
        assert_eq!(ctl.view().trial.unwrap().waiting_for, [Waiting::Time]);
        task.abort();
    }

    // ------------------------------------------------------------------ the self-query

    #[tokio::test(start_paused = true)]
    async fn an_upstream_that_answered_by_itself_is_never_asked_for() {
        let card = Card::of_trial(Slot::B, Slot::A, BUILD);
        let ctl = trial_on(&card, BUILD);
        let health = Fake::answered();
        let task = start(&ctl, &health, usual());
        pass(200).await;
        assert_eq!(health.asks(), 0);
        assert_eq!(card.selected(), Slot::B);
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn the_self_query_begins_ten_seconds_before_the_confirm_and_confirms_on_its_answer() {
        let card = Card::of_trial(Slot::B, Slot::A, BUILD);
        let ctl = trial_on(&card, BUILD);
        let health = Fake::healthy();
        let task = start(&ctl, &health, usual());

        pass(109).await;
        assert_eq!(health.asks(), 0, "not before confirm_secs - 10");
        pass(1).await;
        assert_eq!(health.asks(), 1);
        // The answer is in: the upstream is not waited for, and the time still is.
        assert_eq!(ctl.view().trial.unwrap().waiting_for, [Waiting::Time]);
        assert_eq!(card.uses(), 0);
        pass(10).await;
        assert_eq!((card.uses(), card.selected()), (1, Slot::B));
        // Once seen, an upstream stays seen: no second question.
        assert_eq!(health.asks(), 1);
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_self_query_with_no_answer_is_sent_again_every_ten_seconds_until_one_comes() {
        let card = Card::of_trial(Slot::B, Slot::A, BUILD);
        let ctl = trial_on(&card, BUILD);
        let health = Fake::healthy();
        health.set_ask(Some(false));
        let task = start(&ctl, &health, usual());

        // Asks at 110, 120 and 130 s, and the confirm waits for the upstream.
        pass(135).await;
        assert_eq!(health.asks(), 3);
        assert_eq!(card.uses(), 0);
        assert_eq!(ctl.view().trial.unwrap().waiting_for, [Waiting::Upstream]);
        // A fourth at 140 s is answered, and the confirm follows at once.
        health.set_ask(Some(true));
        pass(6).await;
        assert_eq!(health.asks(), 4);
        assert_eq!((card.uses(), card.selected()), (1, Slot::B));
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_self_query_that_is_never_answered_is_given_up_after_five_seconds() {
        let card = Card::of_trial(Slot::B, Slot::A, BUILD);
        let ctl = trial_on(&card, BUILD);
        let health = Fake::healthy();
        health.set_ask(None);
        let task = start(&ctl, &health, usual());

        // The first at 110 s hangs and is dropped at 115 s; the next goes out at 120 s.
        pass(114).await;
        assert_eq!(health.asks(), 1);
        pass(7).await;
        assert_eq!(health.asks(), 2);
        assert_eq!(card.uses(), 0);
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn no_question_is_asked_while_the_wifi_or_the_clock_is_missing() {
        for missing in ["wifi", "clock"] {
            let card = Card::of_trial(Slot::B, Slot::A, BUILD);
            let ctl = trial_on(&card, BUILD);
            let health = Fake::healthy();
            match missing {
                "wifi" => health.wifi.store(false, Ordering::SeqCst),
                _ => health.clock.store(false, Ordering::SeqCst),
            }
            let task = start(&ctl, &health, usual());
            pass(300).await;
            assert_eq!(health.asks(), 0, "{missing}");
            task.abort();
        }
    }

    // ------------------------------------------------------------------ offline

    #[tokio::test(start_paused = true)]
    async fn an_offline_trial_waits_for_the_time_alone() {
        let card = Card::of_trial(Slot::B, Slot::A, BUILD);
        let ctl = trial_on(&card, BUILD);
        let health = Fake::healthy();
        health.wifi.store(false, Ordering::SeqCst);
        health.clock.store(false, Ordering::SeqCst);
        let settings = Settings {
            confirm_after: Duration::from_secs(5),
            offline: true,
        };
        let task = start(&ctl, &health, settings);

        pass(4).await;
        assert_eq!(card.uses(), 0);
        assert_eq!(ctl.view().trial.unwrap().waiting_for, [Waiting::Time]);
        pass(1).await;
        assert_eq!(
            (card.uses(), card.selected(), card.marker()),
            (1, Slot::B, None)
        );
        // No upstream was asked for, and none was needed.
        assert_eq!(health.asks(), 0);
        assert_eq!(ctl.view().last, Some(Outcome::confirmed(BUILD)));
        task.abort();
    }

    // ------------------------------------------------------------------ the card

    #[tokio::test(start_paused = true)]
    async fn a_confirm_whose_write_fails_is_tried_again_every_thirty_seconds() {
        let card = Card::of_trial(Slot::B, Slot::A, BUILD).failing(2);
        let ctl = trial_on(&card, BUILD);
        let task = start(&ctl, &Fake::answered(), usual());

        pass(121).await;
        assert_eq!(card.uses(), 1);
        assert!(
            log_text().contains(&format!(
                "update: confirming build {BUILD} on slot b failed: the card is in use by another thread; trying again in 30 s"
            )),
            "an error line says it"
        );
        assert_eq!(ctl.view().state, "trial");
        pass(28).await;
        assert_eq!(card.uses(), 1, "not before 30 s");
        pass(2).await;
        assert_eq!(card.uses(), 2);
        pass(28).await;
        assert_eq!(card.uses(), 2);
        pass(2).await;
        assert_eq!(card.uses(), 3);
        assert_eq!((card.selected(), card.marker()), (Slot::B, None));
        assert_eq!(ctl.view().last, Some(Outcome::confirmed(BUILD)));
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn the_card_is_used_only_on_the_blocking_pool_and_never_on_the_runtime_thread() {
        let card = Card::of_trial(Slot::B, Slot::A, BUILD);
        let ctl = trial_on(&card, BUILD);
        // The tests of the give-up use the card too, so this one covers both of its uses.
        let health = Fake::answered();
        health.wifi.store(false, Ordering::SeqCst);
        let task = start(&ctl, &health, usual());
        let runtime_thread = thread::current().id();
        pass(601).await;
        let uses = card.uses.lock().unwrap().clone();
        assert!(!uses.is_empty());
        for (access, thread) in uses {
            assert_eq!(access, CardAccess::Writable);
            assert_ne!(thread, runtime_thread);
        }
        task.abort();
    }

    // ------------------------------------------------------------------ the limit

    #[tokio::test(start_paused = true)]
    async fn the_trial_gives_up_at_600_seconds_with_the_reason_and_a_plain_restart() {
        let card = Card::of_trial(Slot::B, Slot::A, BUILD);
        let ctl = trial_on(&card, BUILD);
        let health = Fake::answered();
        health.clock.store(false, Ordering::SeqCst);
        let mut restart = ctl.restart_receiver();
        let task = start(&ctl, &health, usual());

        pass(599).await;
        assert_eq!(*restart.borrow_and_update(), None);
        assert_eq!(card.uses(), 0);
        pass(1).await;

        let reason = "gave up after 600 s: still waiting for clock".to_owned();
        assert_eq!(
            *restart.borrow_and_update(),
            Some(Restart::Plain(Cause::GaveUp(reason.clone())))
        );
        // The marker says why, and nothing else of the card changed: the slot it came from stays selected.
        let marker = card.marker().unwrap();
        assert_eq!(marker.failed, Some(reason.clone()));
        assert!(marker.started);
        assert_eq!(card.selected(), Slot::A);
        let text = log_text();
        assert!(
            text.contains(&format!(
                "update: build {BUILD} did not confirm within 600 s ({reason}); restarting to boot slot a"
            )),
            "{text}"
        );
        // A rollback boot reads it back as the reason.
        assert_eq!(marker.rollback_detail(), reason);
        assert!(!task.is_finished());
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_card_that_never_takes_the_confirm_ends_in_a_give_up_that_says_so() {
        let card = Card::of_trial(Slot::B, Slot::A, BUILD).failing(usize::MAX);
        let ctl = trial_on(&card, BUILD);
        let mut restart = ctl.restart_receiver();
        let task = start(&ctl, &Fake::answered(), usual());

        pass(601).await;
        let reason = "gave up after 600 s: the confirm could not be written to the card";
        assert_eq!(
            *restart.borrow_and_update(),
            Some(Restart::Plain(Cause::GaveUp(reason.to_owned())))
        );
        // The confirm was tried at 120, 150, ... 570 s, and the reason once: 17 uses in all.
        assert_eq!(card.uses(), 17);
        // The reason could not be written, and that is a warning and no obstacle.
        assert!(
            log_text().contains("the reason could not be written to the trial marker"),
            "{}",
            log_text()
        );
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_trial_with_a_confirm_time_past_the_limit_gives_up_waiting_for_the_time() {
        let card = Card::of_trial(Slot::B, Slot::A, BUILD);
        let ctl = trial_on(&card, BUILD);
        let settings = Settings {
            confirm_after: Duration::from_secs(3600),
            ..usual()
        };
        let mut restart = ctl.restart_receiver();
        let task = start(&ctl, &Fake::answered(), settings);
        pass(601).await;
        assert_eq!(
            *restart.borrow_and_update(),
            Some(Restart::Plain(Cause::GaveUp(
                "gave up after 600 s: still waiting for time".to_owned()
            )))
        );
        task.abort();
    }

    // ------------------------------------------------------------------ a boot that is not on trial

    #[tokio::test(start_paused = true)]
    async fn a_boot_that_is_not_on_trial_does_nothing_and_never_ends() {
        let card = Card::of_trial(Slot::B, Slot::A, BUILD);
        let idle = UpdateCtl::new(Some(Slot::B), None, Arc::new(Lent(card.clone())));
        let task = start(&idle, &Fake::healthy(), usual());
        pass(3600).await;
        assert!(!task.is_finished());
        assert_eq!(card.uses(), 0);
        assert_eq!(*idle.restart_receiver().borrow(), None);
        task.abort();
    }

    // ------------------------------------------------------------------ the board's health

    #[tokio::test]
    async fn the_board_health_reads_the_wifi_the_clock_and_the_upstreams_answers() {
        let (dns, _addr, _upstream) = one(Reply::Answer(ip("203.0.113.9"))).await;
        let (wifi_sender, wifi) = watch::channel(WifiStatus::Starting);
        let (clock_sender, clock) = watch::channel(false);
        let health = BoardHealth::new(wifi, clock, dns);

        assert!(!health.wifi_associated());
        assert!(!health.clock_set());
        assert_eq!(health.upstream_answers(), 0);
        clock_sender.send_replace(true);
        assert!(health.clock_set());
        wifi_sender.send_replace(WifiStatus::Joined {
            bssid: [2, 0, 0, 0, 0, 1],
            freq_mhz: 5180,
            signal_mbm: -5600,
        });
        assert!(health.wifi_associated());
    }

    #[tokio::test]
    async fn an_answer_from_an_upstream_is_counted_over_udp_and_not_before() {
        let (dns, addr, upstream) = one(Reply::Answer(ip("203.0.113.9"))).await;
        assert_eq!(upstream_answers(dns.upstreams()), 0);
        // A question that only the upstream can answer.
        let answer = crate::dns::testutil::ask_udp(addr, "example.org")
            .await
            .unwrap();
        assert_eq!(answer.rcode, 0);
        assert_eq!(upstream.udp_queries(), 1);
        assert_eq!(upstream_answers(dns.upstreams()), 1);
    }

    #[tokio::test]
    async fn the_self_query_is_proved_by_a_real_answer_and_by_nothing_else() {
        // An upstream that answers: the resolver forwards and the answer is real.
        let (_dns, addr, _upstream) = one(Reply::Answer(ip("203.0.113.9"))).await;
        assert!(
            timeout(Duration::from_secs(5), ask_resolver(addr))
                .await
                .unwrap()
        );

        // An upstream that does not answer: the resolver answers SERVFAIL, which proves nothing.
        let (_dns, addr, _upstream) = one(Reply::Silent).await;
        assert!(
            !timeout(Duration::from_secs(5), ask_resolver(addr))
                .await
                .unwrap()
        );

        // An upstream that answers with the address that a block gives is no proof either.
        let (_dns, addr, _upstream) = one(Reply::Answer(ip("0.0.0.0"))).await;
        assert!(
            !timeout(Duration::from_secs(5), ask_resolver(addr))
                .await
                .unwrap()
        );

        // A port where nothing listens fails to read, and is no answer.
        let closed = crate::dns::testutil::closed_port();
        let silent = timeout(Duration::from_millis(500), ask_resolver(closed)).await;
        assert!(silent.is_err() || silent == Ok(false));
    }
}
