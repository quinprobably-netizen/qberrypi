//! The supervisor: starts every component of the board, starts the failed ones again, and says
//! when the board has to restart.
//!
//! A [`Component`] is one long-running piece of the system: the DNS service, the clock, the Wi-Fi,
//! the front panel. [`run`] starts them in the order given, each as a task of the runtime it is
//! awaited on, and for as long as the board lives it does three things: it calls the hook that
//! pets the watchdog every [`TICK`], it starts a component that failed again after
//! [`RESTART_DELAY`], and it ends with a [`Reason`] when the board has to restart. Nothing in
//! `run` blocks the thread it runs on, and a component that holds the thread for a moment delays
//! one tick by that moment, no more: the tick keeps its own deadline.
//!
//! The supervisor also watches the Wi-Fi link when it is given one ([`Plan::link`]): the LED shows
//! it ([`Hooks::led`]), and a board that is not associated for [`link::NO_ASSOCIATION_LIMIT`]
//! (90 seconds, from the start and from each loss) ends with [`Reason::NoAssociation`]. The count
//! runs on the supervisor's own clock and its deadline is a timer of the same loop as the tick, so
//! a component that holds the thread delays the reason by that hold and no more.
//!
//! A component that the update machinery lends a channel to ([`Plan::restart`]) can end the run
//! itself with [`Reason::Restart`], as an update's receiver does when the new slot is staged and
//! the trial does when it gives up; the supervisor only carries the request out of the loop.
//!
//! A component that is [`Ended::Absent`] is not there to run, as the front panel on a board
//! without its screen: it is said so once and never started again. One that [`Ended::Failed`], or
//! panicked, is started again, unless it has failed [`FAILURES_TO_GIVE_UP`] times within
//! [`FAILURE_WINDOW`]: then an essential one restarts the board, and any other is left stopped
//! while the rest of the system runs on.
//!
//! A component that panics counts as one that failed, in the host tests. On the board a panic
//! anywhere, a non-essential panel included, goes through init's panic hook to `fatal`, which
//! restarts the board (the release profile aborts on a panic), so no component is started again
//! after one.
//!
//! A component is started again only after its task has ended, and `run` never aborts one to do
//! it. A component that starts work of its own on the blocking pool (the list refresh fetches
//! and parses on it) awaits that work, so a component that is started again never runs beside
//! its earlier self, and no second fetch begins while one runs. When `run` ends, the board is
//! about to restart, and the components still running go with it.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::{self, JoinSet};
use tokio::time::{Instant, MissedTickBehavior, interval_at, sleep_until};

use crate::led::LedState;
use crate::link::{self, LinkStep, LinkWatch};
use crate::services;
use crate::update::Restart;
use crate::wifi::WifiStatus;

/// How often the tick hook is called: the watchdog is petted at least this often.
pub const TICK: Duration = Duration::from_secs(5);

/// How long a component that failed waits before it is started again.
pub const RESTART_DELAY: Duration = Duration::from_secs(1);

/// How far back the failures of a component count.
pub const FAILURE_WINDOW: Duration = Duration::from_secs(60);

/// How many failures within [`FAILURE_WINDOW`] a component is given up for.
pub const FAILURES_TO_GIVE_UP: usize = 3;

/// How a component ended.
#[derive(Debug, PartialEq)]
pub enum Ended {
    /// What the component drives is not there. It is not started again.
    Absent(String),
    /// The component broke, or stopped when it should have run on.
    Failed(String),
}

/// A component that is running: the task that ends with how it ended.
pub type Running = Pin<Box<dyn Future<Output = Ended> + Send>>;

/// One long-running piece of the system.
pub struct Component {
    /// The name the log gives it.
    pub name: &'static str,
    /// Whether the board restarts when it has failed [`FAILURES_TO_GIVE_UP`] times within [`FAILURE_WINDOW`].
    pub essential: bool,
    /// Makes the task afresh. It is called at every start, the first and each after a failure.
    pub start: Box<dyn FnMut() -> Running + Send>,
}

impl Component {
    /// A component that is a task of the runtime: each start builds its future afresh from `build`.
    pub fn task<F>(
        name: &'static str,
        essential: bool,
        mut build: impl FnMut() -> F + Send + 'static,
    ) -> Self
    where
        F: Future<Output = Ended> + Send + 'static,
    {
        Self {
            name,
            essential,
            start: Box::new(move || Box::pin(build())),
        }
    }

    /// A component whose work blocks a thread of its own: each start runs `work` again on the
    /// blocking pool, when its task is first polled and not before.
    pub fn blocking(
        name: &'static str,
        essential: bool,
        work: impl Fn() -> Ended + Send + Sync + 'static,
    ) -> Self {
        let work = Arc::new(work);
        Self::task(name, essential, move || {
            let work = work.clone();
            async move {
                services::blocking(name, move || work())
                    .await
                    .unwrap_or_else(|error| Ended::Failed(error.to_string()))
            }
        })
    }
}

/// When a component failed, as far back as [`FAILURE_WINDOW`] reaches.
#[derive(Default)]
pub struct FailureLog {
    /// The times of the failures within the window of the last one, on the supervisor's own clock.
    at: Vec<Duration>,
}

impl FailureLog {
    /// Records a failure at `at` and says how many failures are in the window, this one included.
    ///
    /// A failure counts if it came less than [`FAILURE_WINDOW`] before `at`.
    pub fn record(&mut self, at: Duration) -> usize {
        self.at
            .retain(|earlier| at.saturating_sub(*earlier) < FAILURE_WINDOW);
        self.at.push(at);
        self.at.len()
    }
}

/// Why the board has to restart.
#[derive(Debug, PartialEq)]
pub enum Reason {
    /// An essential component failed [`FAILURES_TO_GIVE_UP`] times within [`FAILURE_WINDOW`].
    ComponentFailed(&'static str),
    /// The Wi-Fi was not associated for too long.
    NoAssociation,
    /// The time that the configuration gives the board to run has passed.
    ReturnAfter,
    /// A component asked for the restart through the update machinery
    /// ([`UpdateCtl::request_restart`](crate::update::UpdateCtl::request_restart)): an update was
    /// staged, or the trial gave up. The restart says how the board goes.
    Restart(Restart),
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ComponentFailed(name) => write!(
                f,
                "component {name} failed {FAILURES_TO_GIVE_UP} times in a minute"
            ),
            Self::NoAssociation => f.write_str("no Wi-Fi association for 90 s"),
            Self::ReturnAfter => f.write_str("the configured time has passed"),
            Self::Restart(restart) => restart.fmt(f),
        }
    }
}

/// What [`run`] runs.
pub struct Plan {
    /// The components, in the order they are started.
    pub components: Vec<Component>,
    /// How long from now the board runs before it returns; `None` for ever.
    pub return_after: Option<Duration>,
    /// Where the Wi-Fi stands, if the supervisor is to watch it: the link is associated while the
    /// status is `Joined`. The LED follows it and the board restarts when it has not been associated
    /// for 90 seconds, counted from the start. A sender that is gone counts as not associated.
    /// With `None` the LED shows [`LedState::Serving`] and no such rule is armed.
    pub link: Option<watch::Receiver<WifiStatus>>,
    /// Where a component asks for the board to restart, if any may: the update machinery's
    /// channel ([`UpdateCtl::restart_receiver`](crate::update::UpdateCtl::restart_receiver)).
    /// The first `Some` it holds ends [`run`] with [`Reason::Restart`]; one that is there when
    /// `run` starts counts. A sender that is gone asks for nothing. With `None` no component can.
    pub restart: Option<watch::Receiver<Option<Restart>>>,
}

/// What [`run`] calls on the board's behalf.
pub struct Hooks {
    /// Called at once and then every [`TICK`]: pets the watchdog and does what has to be done
    /// on a clock. It runs on the runtime's thread, so it must not wait for anything.
    pub tick: Box<dyn FnMut()>,
    /// Called with what the activity LED is to show: at the start, and at each change of the link.
    /// It runs on the runtime's thread, so it must not wait for anything.
    pub led: Box<dyn FnMut(LedState)>,
}

/// A component and what the supervisor keeps of it.
struct Entry {
    component: Component,
    failures: FailureLog,
    /// When the component is started again, if it failed and has tries left.
    restart_at: Option<Instant>,
}

/// The line that says a component is not there to run.
fn absent_line(name: &str, why: &str) -> String {
    format!("{name}: {why}; running without it")
}

/// The line that says a component failed.
fn failed_line(name: &str, why: &str) -> String {
    format!("supervisor: {name} failed: {why}")
}

/// Starts the component `entry`, which is number `index`, as a task of `running`.
fn start(
    entry: &mut Entry,
    index: usize,
    running: &mut JoinSet<Ended>,
    ids: &mut HashMap<task::Id, usize>,
    again: bool,
) {
    let name = entry.component.name;
    let id = running
        .spawn(crate::stall::timed(name, (entry.component.start)()))
        .id();
    ids.insert(id, index);
    if again {
        log::info!("supervisor: starting {name} again");
    } else {
        log::info!("supervisor: started {name}");
    }
}

/// What the supervisor makes of the end of `entry`'s task, at `at` on its own clock, which was `now`.
///
/// Gives the reason to restart the board when this was the last try of an essential component.
fn ended(entry: &mut Entry, how: Ended, at: Duration, now: Instant) -> Option<Reason> {
    let name = entry.component.name;
    match how {
        Ended::Absent(why) => {
            log::warn!("{}", absent_line(name, &why));
            None
        }
        Ended::Failed(why) => {
            log::error!("{}", failed_line(name, &why));
            if entry.failures.record(at) < FAILURES_TO_GIVE_UP {
                entry.restart_at = Some(now + RESTART_DELAY);
                None
            } else if entry.component.essential {
                Some(Reason::ComponentFailed(name))
            } else {
                log::error!(
                    "supervisor: {name} failed {FAILURES_TO_GIVE_UP} times in a minute; leaving it stopped"
                );
                None
            }
        }
    }
}

/// The Wi-Fi link as the supervisor follows it: the channel of statuses and the watch over it.
struct Link {
    /// Where the Wi-Fi stands.
    status: watch::Receiver<WifiStatus>,
    /// Whether the sender of `status` is still there. Once it is gone nothing more arrives.
    open: bool,
    /// Whether the link was associated at the last look.
    up: bool,
    /// The watch that says what each look means.
    watch: LinkWatch,
    /// When the supervisor began: the time of a look is counted from here.
    began: Instant,
}

impl Link {
    /// Follows `status` from `began`, when the link is taken to be down.
    fn new(status: watch::Receiver<WifiStatus>, began: Instant) -> Self {
        Self {
            status,
            open: true,
            up: false,
            watch: LinkWatch::new(Duration::ZERO),
            began,
        }
    }

    /// Whether the link is associated now, a change that is waiting for `next` taken as seen.
    fn associated_now(&mut self) -> bool {
        self.open && link::is_associated(&self.status.borrow_and_update())
    }

    /// Waits for the next change of the status and says whether the link is associated by then.
    ///
    /// A Wi-Fi task that is gone is a link that is not associated: that is said once, and after it
    /// this waits for ever, so that a closed channel does not wake the loop again and again.
    async fn next(&mut self) -> bool {
        if self.open {
            if self.status.changed().await.is_ok() {
                return link::is_associated(&self.status.borrow_and_update());
            }
            self.open = false;
            return false;
        }
        std::future::pending().await
    }

    /// What a look at `now` means when the link is `up`: remembers `up` and asks the watch.
    fn look(&mut self, now: Instant, up: bool) -> LinkStep {
        self.up = up;
        self.watch.observe(now.duration_since(self.began), up)
    }

    /// When the board is due to restart for want of an association, if it is not associated.
    fn deadline(&self) -> Option<Instant> {
        self.watch.deadline().map(|after| self.began + after)
    }
}

/// Waits for the link's next change, for ever if there is no link.
async fn link_changed(link: &mut Option<Link>) -> bool {
    match link {
        Some(link) => link.next().await,
        None => std::future::pending().await,
    }
}

/// Waits until a restart is asked for, for ever if none can be: no channel, or a sender that is
/// gone. Cancel-safe: a request that is already there is found at once, however often it is asked.
async fn restart_asked(restart: &mut Option<watch::Receiver<Option<Restart>>>) -> Restart {
    let asked = match restart {
        Some(receiver) => match receiver.wait_for(Option::is_some).await {
            Ok(asked) => asked.clone(),
            Err(_) => None,
        },
        None => None,
    };
    match asked {
        Some(restart) => restart,
        None => std::future::pending().await,
    }
}

/// Acts on what a look at the link meant: shows a change on the LED, and says when the board has
/// to restart.
fn acted_on(step: LinkStep, led: &mut dyn FnMut(LedState)) -> Option<Reason> {
    match step {
        LinkStep::Nothing => None,
        LinkStep::Led(state) => {
            led(state);
            None
        }
        LinkStep::RestartDue => Some(Reason::NoAssociation),
    }
}

/// Runs every component until the board has to be restarted, and says why.
///
/// Calls `tick` at once, starts the components in the order given, and then calls `tick` every
/// [`TICK`] whatever else happens. Calls `led` with [`LedState::Serving`] once; with a link in the
/// plan it calls it with [`LedState::Joining`] instead, and then with what each change of the
/// link asks for, and ends with [`Reason::NoAssociation`] when the link has been down for 90 s.
/// With a restart channel in the plan it ends with [`Reason::Restart`] as soon as a request is
/// there, after a tick that is due.
pub async fn run(plan: Plan, mut hooks: Hooks) -> Reason {
    let Plan {
        components,
        return_after,
        link,
        mut restart,
    } = plan;
    let began = Instant::now();
    let return_at = return_after.map(|after| began + after);
    let mut link = link.map(|status| Link::new(status, began));
    match link.as_mut() {
        None => (hooks.led)(LedState::Serving),
        Some(link) => {
            // Down until the first look says otherwise: a link that is up already shows it at once.
            (hooks.led)(LedState::Joining);
            let up = link.associated_now();
            acted_on(link.look(began, up), &mut hooks.led);
        }
    }
    (hooks.tick)();
    // A tick that came late is not made up for: the next one is a whole `TICK` after it.
    let mut ticks = interval_at(began + TICK, TICK);
    ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let mut entries: Vec<Entry> = components
        .into_iter()
        .map(|component| Entry {
            component,
            failures: FailureLog::default(),
            restart_at: None,
        })
        .collect();
    let mut running = JoinSet::new();
    let mut ids = HashMap::new();
    for (index, entry) in entries.iter_mut().enumerate() {
        start(entry, index, &mut running, &mut ids, false);
    }

    loop {
        let now = Instant::now();
        if return_at.is_some_and(|at| now >= at) {
            return Reason::ReturnAfter;
        }
        for (index, entry) in entries.iter_mut().enumerate() {
            if entry.restart_at.is_some_and(|at| now >= at) {
                entry.restart_at = None;
                start(entry, index, &mut running, &mut ids, true);
            }
        }
        if let Some(link) = link.as_mut() {
            let up = link.up;
            if let Some(reason) = acted_on(link.look(now, up), &mut hooks.led) {
                return reason;
            }
        }
        let wake = entries
            .iter()
            .filter_map(|entry| entry.restart_at)
            .chain(return_at)
            .chain(link.as_ref().and_then(Link::deadline))
            .min();
        // In this order: a tick that is due comes before anything a component's end asks for.
        tokio::select! {
            biased;
            _ = ticks.tick() => crate::stall::time("supervisor tick", &mut hooks.tick),
            up = link_changed(&mut link) => {
                if let Some(link) = link.as_mut()
                    && let Some(reason) = acted_on(link.look(Instant::now(), up), &mut hooks.led)
                {
                    return reason;
                }
            }
            restart = restart_asked(&mut restart) => return Reason::Restart(restart),
            Some(done) = running.join_next_with_id(), if !running.is_empty() => {
                let (id, how) = match done {
                    Ok((id, how)) => (id, how),
                    Err(error) => {
                        let why = if error.is_panic() { "panicked" } else { "cancelled" };
                        (error.id(), Ended::Failed(why.to_owned()))
                    }
                };
                if let Some(index) = ids.remove(&id)
                    && let Some(reason) = ended(&mut entries[index], how, began.elapsed(), Instant::now())
                {
                    return reason;
                }
            }
            () = sleep_until(wake.unwrap_or(now)), if wake.is_some() => {}
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::{Cell, RefCell};
    use std::rc::Rc;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use tokio::time::sleep;

    use crate::update::Cause;

    const HOUR: Duration = Duration::from_secs(3600);

    /// A component that counts its starts and fails `lives_for` after each of them.
    fn failing(
        name: &'static str,
        essential: bool,
        starts: Arc<AtomicUsize>,
        lives_for: Duration,
    ) -> Component {
        Component {
            name,
            essential,
            start: Box::new(move || {
                starts.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move {
                    sleep(lives_for).await;
                    Ended::Failed("gone".into())
                })
            }),
        }
    }

    /// A component that counts its starts and ends at once as absent.
    fn absent(name: &'static str, starts: Arc<AtomicUsize>) -> Component {
        Component {
            name,
            essential: false,
            start: Box::new(move || {
                starts.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Ended::Absent("not there".into()) })
            }),
        }
    }

    /// A component that never ends.
    fn forever(name: &'static str) -> Component {
        Component {
            name,
            essential: true,
            start: Box::new(|| Box::pin(std::future::pending())),
        }
    }

    /// A component that panics at each start of its task.
    fn panicking(name: &'static str, starts: Arc<AtomicUsize>) -> Component {
        Component {
            name,
            essential: true,
            start: Box::new(move || {
                starts.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { panic!("a component that breaks") })
            }),
        }
    }

    /// A plan with no return time and no link.
    fn plan(components: Vec<Component>) -> Plan {
        Plan {
            components,
            return_after: None,
            restart: None,
            link: None,
        }
    }

    /// Runs `plan` for at most `limit`, with hooks that count the ticks and keep the LED states;
    /// gives why `run` ended, if it did, the ticks and the states.
    async fn watch(plan: Plan, limit: Duration) -> (Option<Reason>, usize, Vec<LedState>) {
        let ticks = Rc::new(Cell::new(0));
        let leds = Rc::new(RefCell::new(Vec::new()));
        let hooks = Hooks {
            tick: Box::new({
                let ticks = ticks.clone();
                move || ticks.set(ticks.get() + 1)
            }),
            led: Box::new({
                let leds = leds.clone();
                move |state| leds.borrow_mut().push(state)
            }),
        };
        let reason = tokio::time::timeout(limit, run(plan, hooks)).await.ok();
        let leds = leds.borrow().clone();
        (reason, ticks.get(), leds)
    }

    #[test]
    fn failures_count_only_within_the_last_minute() {
        let secs = Duration::from_secs;
        let mut log = FailureLog::default();
        assert_eq!(
            [
                log.record(secs(0)),
                log.record(secs(30)),
                log.record(secs(59))
            ],
            [1, 2, 3]
        );
        let mut log = FailureLog::default();
        // The first is a minute old by then.
        assert_eq!(
            [
                log.record(secs(0)),
                log.record(secs(30)),
                log.record(secs(60))
            ],
            [1, 2, 2]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn three_failures_in_a_minute_of_an_essential_component_restart_the_board() {
        let starts = Arc::new(AtomicUsize::new(0));
        let began = tokio::time::Instant::now();
        let (reason, ..) = watch(
            plan(vec![failing("dns", true, starts.clone(), Duration::ZERO)]),
            HOUR,
        )
        .await;
        assert_eq!(reason, Some(Reason::ComponentFailed("dns")));
        assert_eq!(starts.load(Ordering::SeqCst), 3);
        assert!(began.elapsed() >= 2 * RESTART_DELAY && began.elapsed() < Duration::from_secs(3));
    }

    #[tokio::test(start_paused = true)]
    async fn failures_more_than_a_minute_apart_never_add_up() {
        let starts = Arc::new(AtomicUsize::new(0));
        let (reason, ..) = watch(
            plan(vec![failing(
                "dns",
                true,
                starts.clone(),
                Duration::from_secs(31),
            )]),
            HOUR,
        )
        .await;
        assert_eq!(reason, None);
        // Started again every time.
        assert!(starts.load(Ordering::SeqCst) > 100);
    }

    #[tokio::test(start_paused = true)]
    async fn a_component_that_is_not_essential_is_left_stopped_and_the_board_runs_on() {
        let starts = Arc::new(AtomicUsize::new(0));
        let (reason, ..) = watch(
            plan(vec![
                failing("panel", false, starts.clone(), Duration::ZERO),
                forever("dns"),
            ]),
            HOUR,
        )
        .await;
        assert_eq!((reason, starts.load(Ordering::SeqCst)), (None, 3));
    }

    #[tokio::test(start_paused = true)]
    async fn an_absent_component_is_not_started_again() {
        let starts = Arc::new(AtomicUsize::new(0));
        let (reason, ..) = watch(plan(vec![absent("panel", starts.clone())]), HOUR).await;
        assert_eq!((reason, starts.load(Ordering::SeqCst)), (None, 1));
    }

    #[tokio::test(start_paused = true)]
    async fn a_component_that_panics_is_a_failure_like_any_other() {
        let starts = Arc::new(AtomicUsize::new(0));
        let (reason, ..) = watch(plan(vec![panicking("dns", starts.clone())]), HOUR).await;
        assert_eq!(reason, Some(Reason::ComponentFailed("dns")));
        assert_eq!(starts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn the_tick_comes_every_five_seconds_whatever_the_components_do() {
        let busy = failing(
            "dns",
            false,
            Arc::new(AtomicUsize::new(0)),
            Duration::from_millis(1),
        );
        let (_, ticks, leds) =
            watch(plan(vec![busy, forever("wifi")]), Duration::from_secs(60)).await;
        assert!((12..=14).contains(&ticks), "{ticks} ticks");
        assert_eq!(leds, [LedState::Serving]);
    }

    #[tokio::test(start_paused = true)]
    async fn the_board_returns_when_the_configured_time_has_passed() {
        let began = tokio::time::Instant::now();
        let mut p = plan(vec![forever("dns")]);
        p.return_after = Some(Duration::from_secs(40));
        assert_eq!(watch(p, HOUR).await.0, Some(Reason::ReturnAfter));
        assert_eq!(began.elapsed().as_secs(), 40);
    }

    #[tokio::test(start_paused = true)]
    async fn a_time_that_has_passed_already_returns_at_once_after_the_first_tick() {
        let mut p = plan(vec![forever("dns")]);
        p.return_after = Some(Duration::ZERO);
        let (reason, ticks, _) = watch(p, HOUR).await;
        assert_eq!((reason, ticks), (Some(Reason::ReturnAfter), 1));
    }

    /// A component that asks for a restart `after` its start, through `sender`, and never ends.
    fn asking(
        sender: watch::Sender<Option<Restart>>,
        after: Duration,
        restart: Restart,
    ) -> Component {
        Component::task("trial", false, move || {
            let (sender, restart) = (sender.clone(), restart.clone());
            async move {
                sleep(after).await;
                sender.send_replace(Some(restart));
                std::future::pending().await
            }
        })
    }

    #[tokio::test(start_paused = true)]
    async fn a_restart_that_a_component_asks_for_ends_the_run_with_it() {
        let (tx, rx) = watch::channel(None);
        let began = tokio::time::Instant::now();
        let mut p = plan(vec![
            forever("dns"),
            asking(tx, Duration::from_secs(7), Restart::Tryboot),
        ]);
        p.restart = Some(rx);

        let (reason, _, _) = watch(p, HOUR).await;

        assert_eq!(reason, Some(Reason::Restart(Restart::Tryboot)));
        // At once: not at the next tick, which is 5 s apart.
        assert_eq!(began.elapsed(), Duration::from_secs(7));
    }

    #[tokio::test(start_paused = true)]
    async fn a_restart_that_is_there_when_the_run_starts_ends_it_after_the_first_tick() {
        let (_tx, rx) = watch::channel(Some(Restart::Plain(Cause::Update)));
        let mut p = plan(vec![forever("dns")]);
        p.restart = Some(rx);

        let (reason, ticks, _) = watch(p, HOUR).await;

        assert_eq!(
            (reason, ticks),
            (Some(Reason::Restart(Restart::Plain(Cause::Update))), 1)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_cause_of_a_restart_comes_out_of_the_run_as_it_went_in() {
        let (tx, rx) = watch::channel(None);
        let mut p = plan(vec![asking(
            tx,
            Duration::from_secs(1),
            Restart::Plain(Cause::GaveUp("no Wi-Fi".into())),
        )]);
        p.restart = Some(rx);

        let (reason, _, _) = watch(p, HOUR).await;

        let reason = reason.unwrap();
        assert_eq!(
            reason,
            Reason::Restart(Restart::Plain(Cause::GaveUp("no Wi-Fi".into())))
        );
        assert_eq!(reason.to_string(), "the trial gave up: no Wi-Fi");
    }

    #[tokio::test(start_paused = true)]
    async fn no_restart_is_asked_when_the_channel_is_idle_gone_or_absent() {
        // Idle: the sender is there and says nothing.
        let (_tx, rx) = watch::channel(None);
        let mut idle = plan(vec![forever("dns")]);
        idle.restart = Some(rx);
        assert_eq!(watch(idle, Duration::from_secs(600)).await.0, None);
        // Gone: a closed channel asks for nothing, and does not wake the loop again and again.
        let (tx, rx) = watch::channel(None);
        drop(tx);
        let mut gone = plan(vec![forever("dns")]);
        gone.restart = Some(rx);
        assert_eq!(watch(gone, Duration::from_secs(600)).await.0, None);
        // Absent: no component can ask.
        let absent = plan(vec![forever("dns")]);
        assert_eq!(watch(absent, Duration::from_secs(600)).await.0, None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_tick_that_is_due_comes_before_a_restart_that_is_asked_for_at_the_same_moment() {
        let (tx, rx) = watch::channel(None);
        let mut p = plan(vec![asking(tx, TICK, Restart::Tryboot)]);
        p.restart = Some(rx);

        let (reason, ticks, _) = watch(p, HOUR).await;

        assert_eq!(reason, Some(Reason::Restart(Restart::Tryboot)));
        assert_eq!(ticks, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn components_start_in_the_order_given() {
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let names = ["dns", "clock", "status", "panel"];
        let components = names
            .into_iter()
            .map(|name| {
                let order = order.clone();
                Component {
                    name,
                    essential: true,
                    start: Box::new(move || {
                        order.lock().unwrap().push(name);
                        Box::pin(std::future::pending())
                    }),
                }
            })
            .collect();
        watch(plan(components), Duration::from_secs(1)).await;
        assert_eq!(*order.lock().unwrap(), names);
    }

    /// What the Wi-Fi reports while it is, or is not, associated.
    fn status(associated: bool) -> WifiStatus {
        if associated {
            WifiStatus::Joined {
                bssid: [0; 6],
                freq_mhz: 5180,
                signal_mbm: -5600,
            }
        } else {
            WifiStatus::Scanning
        }
    }

    /// A component that sends each status of `script` at its time after the start, drops the sender
    /// if `then_gone`, and never ends.
    fn reporting(
        sender: watch::Sender<WifiStatus>,
        script: Vec<(Duration, WifiStatus)>,
        then_gone: bool,
    ) -> Component {
        let mut sender = Some(sender);
        Component {
            name: "wifi",
            essential: true,
            start: Box::new(move || {
                let sender = sender.take().expect("started once");
                let script = script.clone();
                Box::pin(async move {
                    let mut at = Duration::ZERO;
                    for (when, status) in script {
                        sleep(when - at).await;
                        at = when;
                        sender.send_replace(status);
                    }
                    if then_gone {
                        drop(sender);
                    }
                    std::future::pending().await
                })
            }),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn without_an_association_for_ninety_seconds_the_board_restarts() {
        let (_tx, rx) = watch::channel(status(false));
        let began = tokio::time::Instant::now();
        let mut p = plan(vec![forever("wifi")]);
        p.link = Some(rx);

        let (reason, _, leds) = watch(p, HOUR).await;

        assert_eq!(
            (reason, leds),
            (Some(Reason::NoAssociation), vec![LedState::Joining])
        );
        assert_eq!(began.elapsed().as_secs(), 90);
    }

    #[tokio::test(start_paused = true)]
    async fn an_association_stops_the_count_and_its_loss_starts_it_afresh() {
        let secs = Duration::from_secs;
        let (tx, rx) = watch::channel(status(false));
        let began = tokio::time::Instant::now();
        let mut p = plan(vec![reporting(
            tx,
            vec![(secs(30), status(true)), (secs(100), status(false))],
            false,
        )]);
        p.link = Some(rx);

        let (reason, _, leds) = watch(p, HOUR).await;

        assert_eq!(
            (reason, leds),
            (
                Some(Reason::NoAssociation),
                vec![LedState::Joining, LedState::Serving, LedState::Joining]
            )
        );
        assert_eq!(began.elapsed().as_secs(), 190);
    }

    #[tokio::test(start_paused = true)]
    async fn a_wifi_task_that_went_away_counts_as_not_associated() {
        let secs = Duration::from_secs;
        let (tx, rx) = watch::channel(status(false));
        let began = tokio::time::Instant::now();
        // Associated at 10 s, and the sender (the Wi-Fi task's) is dropped at 20 s.
        let mut p = plan(vec![reporting(tx, vec![(secs(10), status(true))], true)]);
        p.link = Some(rx);

        let (reason, _, leds) = watch(p, HOUR).await;

        assert_eq!(
            (reason, leds),
            (
                Some(Reason::NoAssociation),
                vec![LedState::Joining, LedState::Serving, LedState::Joining]
            )
        );
        assert_eq!(began.elapsed().as_secs(), 100);
    }

    #[tokio::test(start_paused = true)]
    async fn a_link_that_is_up_from_the_start_shows_serving_and_arms_nothing() {
        let (_tx, rx) = watch::channel(status(true));
        let mut p = plan(vec![forever("wifi")]);
        p.link = Some(rx);

        let (reason, ticks, leds) = watch(p, Duration::from_secs(600)).await;

        assert_eq!(reason, None);
        assert!((120..=122).contains(&ticks), "{ticks} ticks");
        assert_eq!(leds, [LedState::Joining, LedState::Serving]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_link_that_changes_but_never_associates_does_not_move_the_ninety_seconds() {
        let secs = Duration::from_secs;
        // Scanning, joining and waiting are all "not associated": no report moves the deadline.
        let (tx, rx) = watch::channel(WifiStatus::Starting);
        let began = tokio::time::Instant::now();
        let mut p = plan(vec![reporting(
            tx,
            vec![
                (secs(20), WifiStatus::Scanning),
                (
                    secs(40),
                    WifiStatus::Joining {
                        bssid: [0; 6],
                        freq_mhz: 5180,
                    },
                ),
                (secs(60), WifiStatus::Waiting { secs: 4 }),
            ],
            false,
        )]);
        p.link = Some(rx);

        let (reason, _, leds) = watch(p, HOUR).await;

        assert_eq!(
            (reason, leds),
            (Some(Reason::NoAssociation), vec![LedState::Joining])
        );
        assert_eq!(began.elapsed().as_secs(), 90);
    }

    #[tokio::test(start_paused = true)]
    async fn the_ninety_seconds_run_out_while_a_component_holds_the_thread_again_and_again() {
        // The clock here is paused, and a hold of the thread does not move it: the bound the test can
        // give is the exact 90 s of the paused clock, and that the reason still comes, after every
        // hold that fell before it. A real clock would let the hold that spans the deadline delay
        // the reason by that hold and no more: the deadline is a timer of the same loop.
        let holds = Arc::new(AtomicUsize::new(0));
        let holder = Component {
            name: "wifi",
            essential: true,
            start: Box::new({
                let holds = holds.clone();
                move || {
                    let holds = holds.clone();
                    Box::pin(async move {
                        loop {
                            sleep(Duration::from_secs(25)).await;
                            std::thread::sleep(Duration::from_millis(2_500));
                            holds.fetch_add(1, Ordering::SeqCst);
                        }
                    })
                }
            }),
        };
        let (_tx, rx) = watch::channel(status(false));
        let began = tokio::time::Instant::now();
        let real = std::time::Instant::now();
        let mut p = plan(vec![holder]);
        p.link = Some(rx);

        let (reason, ticks, _) = watch(p, HOUR).await;

        assert_eq!(reason, Some(Reason::NoAssociation));
        assert_eq!(began.elapsed().as_secs(), 90);
        // Holds at 25, 50 and 75 s; the next would be at 100 s.
        assert_eq!(holds.load(Ordering::SeqCst), 3);
        assert!(real.elapsed() >= Duration::from_millis(7_500));
        // The ticks went on between the holds: every 5 s of the paused clock, the first at once.
        assert!((18..=19).contains(&ticks), "{ticks} ticks");
    }

    #[tokio::test]
    async fn a_component_that_holds_the_thread_delays_a_tick_by_its_hold_and_no_more() {
        // Real time: a hold of the thread is real. The component holds it from 4.5 s to 6 s, across
        // the tick that is due at 5 s, which comes when the thread is let go, and the one after it
        // is a whole `TICK` later, at 11 s or later, not a burst: until 9.5 s there are two.
        let holder = Component {
            name: "wifi",
            essential: true,
            start: Box::new(|| {
                Box::pin(async {
                    sleep(Duration::from_millis(4_500)).await;
                    std::thread::sleep(Duration::from_millis(1_500));
                    std::future::pending().await
                })
            }),
        };
        let ticks = Rc::new(RefCell::new(Vec::new()));
        let hooks = Hooks {
            tick: Box::new({
                let ticks = ticks.clone();
                move || ticks.borrow_mut().push(std::time::Instant::now())
            }),
            led: Box::new(|_| {}),
        };

        let ended =
            tokio::time::timeout(Duration::from_millis(9_500), run(plan(vec![holder]), hooks))
                .await;

        assert!(ended.is_err(), "nothing here ends the board");
        let ticks = ticks.borrow();
        assert_eq!(ticks.len(), 2, "{} ticks", ticks.len());
        let gap = ticks[1] - ticks[0];
        // At the least the tick's own length, and at the most that and the hold, with slack for a loaded host.
        assert!(
            gap >= TICK && gap <= TICK + Duration::from_millis(1_500 + 3_000),
            "{gap:?} between the two ticks"
        );
    }

    #[test]
    fn the_lines_about_a_component_that_ended_read_as_the_boot_log_shows_them() {
        // The line the QEMU scenarios look for: no screen is a warning and no more.
        assert_eq!(
            absent_line("panel", "no fb_ili9486 framebuffer"),
            "panel: no fb_ili9486 framebuffer; running without it"
        );
        assert_eq!(
            failed_line("dns", "Address in use"),
            "supervisor: dns failed: Address in use"
        );
    }

    #[test]
    fn a_reason_reads_as_a_sentence() {
        assert_eq!(
            Reason::ComponentFailed("dns").to_string(),
            "component dns failed 3 times in a minute"
        );
        assert_eq!(
            Reason::NoAssociation.to_string(),
            "no Wi-Fi association for 90 s"
        );
        assert_eq!(
            Reason::ReturnAfter.to_string(),
            "the configured time has passed"
        );
    }

    #[tokio::test]
    async fn a_blocking_component_runs_its_work_on_every_start() {
        let runs = Arc::new(AtomicUsize::new(0));
        let mut c = Component::blocking("panel", false, {
            let runs = runs.clone();
            move || {
                runs.fetch_add(1, Ordering::SeqCst);
                Ended::Absent("gone".into())
            }
        });
        assert_eq!(
            ((c.start)().await, (c.start)().await),
            (Ended::Absent("gone".into()), Ended::Absent("gone".into()))
        );
        assert_eq!(runs.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_blocking_component_does_nothing_until_its_task_is_polled() {
        let runs = Arc::new(AtomicUsize::new(0));
        let mut c = Component::blocking("panel", false, {
            let runs = runs.clone();
            move || {
                runs.fetch_add(1, Ordering::SeqCst);
                Ended::Absent("gone".into())
            }
        });
        let task = (c.start)();
        sleep(Duration::from_millis(50)).await;
        assert_eq!(runs.load(Ordering::SeqCst), 0);
        task.await;
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_task_component_builds_its_future_afresh_on_every_start() {
        let builds = Arc::new(AtomicUsize::new(0));
        let mut c = Component::task("dns", true, {
            let builds = builds.clone();
            move || {
                let n = builds.fetch_add(1, Ordering::SeqCst);
                async move { Ended::Failed(format!("start {n}")) }
            }
        });
        assert_eq!(
            ((c.start)().await, (c.start)().await),
            (
                Ended::Failed("start 0".into()),
                Ended::Failed("start 1".into())
            )
        );
    }
}
