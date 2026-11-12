//! Provoked failures, for watching the recovery work.
//!
//! `debug.fault` in `qberrypi.toml` makes the board fail in a known way, so that what is meant to
//! happen next can be seen to happen: a component that fails each time it is started
//! ([`Fault::CrashLoop`]), one that panics ([`Fault::Panic`]), or a supervisor that stops
//! ([`Fault::Stall`]). The first two are a [`Component`] that `init` adds to the others; the stall
//! is not a component, because what it provokes is the supervisor itself failing: `init`'s tick
//! asks [`stall_due`] and holds the supervisor's thread, so that nothing pets the watchdog again.
//! [`Fault::NoWifi`] is a Wi-Fi link that never associates ([`link`]), for the supervisor's rule
//! about a link that stays down.
//!
//! The last two provoke what the Wi-Fi task is meant to recover from by itself, so that the owner,
//! who cannot switch the access point off, can watch it do so. Each is a component named `fault`
//! that is *not* essential, as what it provokes must not restart the board, and that waits a minute
//! and then does its one thing and never ends. [`Fault::DropLink`] has the board leave its own
//! network ([`drop_link`]): the Wi-Fi task is told nothing and hears the kernel's disconnect as it
//! would an access point's, so the path under test is the real one. [`Fault::MuteProbe`] arms
//! [`Mute`], which makes the kernel radio's liveness probe fail as if the firmware did not answer,
//! for the one hold that finds it armed.
//!
//! The two trial faults ([`Fault::TrialPanic`], [`Fault::TrialStall`]) are the panic and the stall
//! that act only on a boot that is on trial of an update, so that the rollback can be watched:
//! [`effective`] says which fault a boot acts on, and nothing else asks the configuration for one.
//! On a boot that is not on trial they are no fault at all.
//!
//! For development: `cargo xtask deploy` refuses a permanent system that has one set.

use std::future::{self, Future};
use std::io;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use tokio::sync::watch;

use crate::config::Fault;
use crate::netlink::nl80211::{self, Nl80211};
use crate::netlink::route::Route;
use crate::supervisor::{Component, Ended};
use crate::wifi::WifiStatus;
use crate::wifi::join::REASON_LEAVING;
use crate::wifi::radio::RadioError;

/// How long the board has run when a provoked failure that waits for it happens: counted from the
/// supervisor's start, so that the components have been started and the panel has had its time.
pub const FAULT_AFTER: Duration = Duration::from_secs(10);

/// How long after the supervisor starts that [`Fault::TrialPanic`] panics: short, so that a
/// trial build fails well before it could confirm itself.
pub const TRIAL_PANIC_AFTER: Duration = Duration::from_secs(3);

/// How long after the start of the component that [`Fault::DropLink`] waits before it drops the link: the
/// board has joined by then, and the log has shown it.
pub const DROP_AFTER: Duration = Duration::from_secs(60);

/// How long after the start of the component that [`Fault::MuteProbe`] waits before it arms [`Mute`].
pub const MUTE_AFTER: Duration = Duration::from_secs(60);

/// The Wi-Fi interface the link faults act on: the board's, as `init` names it.
const WLAN: &str = "wlan0";

/// The line that says the link is being dropped, and what the log must show next.
pub const DROPPING: &str = "fault: dropping the Wi-Fi link once";

/// The line that says the radio's liveness probe is being muted.
pub const MUTING: &str = "fault: muting the radio's liveness probe for one hold";

/// The error text of a probe that [`Mute`] failed, so that a log of the loss says it was provoked.
pub const MUTED: &str = "no answer (fault: mute-probe)";

/// The line that says the supervisor is stalling on purpose, and what must happen next.
pub const STALLING: &str =
    "fault: stalling the supervisor; the watchdog must restart the board within 15 s";

/// Whether the supervisor stalls now, `since_start` after it started: only the stall fault does,
/// and only once [`FAULT_AFTER`] has passed.
pub fn stall_due(fault: Fault, since_start: Duration) -> bool {
    fault == Fault::Stall && since_start >= FAULT_AFTER
}

/// The fault that a boot acts on, given the one that `debug.fault` asks for and whether the boot is
/// on trial of an update.
///
/// The two trial faults are no fault on a boot that is not on trial. On one that is, the stall is
/// the plain [`Fault::Stall`] (the supervisor's tick asks [`stall_due`] with it) and the panic is
/// [`Fault::TrialPanic`] still, which [`component`] makes a component of. Every other fault is
/// as asked for, trial or not.
pub fn effective(fault: Fault, on_trial: bool) -> Fault {
    match fault {
        Fault::TrialStall | Fault::TrialPanic if !on_trial => Fault::None,
        Fault::TrialStall => Fault::Stall,
        other => other,
    }
}

/// The component that provokes `fault`, if it is one: one named `fault`.
///
/// `fault` is what [`effective`] gave: [`Fault::TrialPanic`] is a component here without asking
/// whether the boot is on trial, because [`effective`] has already decided that.
///
/// A crash loop fails at once at every start, so the supervisor gives up after three starts and
/// the board restarts. A panic comes [`FAULT_AFTER`] after the start: on the board the panic hook
/// makes it a fatal error, which restarts the board; in a host test the supervisor sees a task
/// that panicked. Those two are essential. The two link faults are not, as nothing they provoke
/// may restart the board: [`DROP_AFTER`] after its start the first drops the Wi-Fi link
/// ([`drop_link`]) and the second arms the process's [`mute`], and each then waits for ever, so that
/// the supervisor says nothing more of it. The trial panic is essential like the panic, and comes
/// [`TRIAL_PANIC_AFTER`] after the start. The stall and the link are not components.
pub fn component(fault: Fault) -> Option<Component> {
    match fault {
        Fault::CrashLoop => Some(Component::task("fault", true, crash)),
        Fault::Panic => Some(Component::task("fault", true, panic_after_a_while)),
        Fault::TrialPanic => Some(Component::task("fault", true, trial_panic)),
        Fault::DropLink => Some(dropping_component(DROP_AFTER, || drop_link(WLAN))),
        Fault::MuteProbe => Some(muting_component(mute(), MUTE_AFTER)),
        Fault::None | Fault::Stall | Fault::TrialStall | Fault::NoWifi => None,
    }
}

/// The component of [`Fault::DropLink`]: after `after` it does what `action` makes, once, and then waits for ever.
///
/// `action` is called at each start of the component and gives the future that drops the link; the
/// board's is [`drop_link`], and a test gives one of its own.
fn dropping_component<F>(
    after: Duration,
    mut action: impl FnMut() -> F + Send + 'static,
) -> Component
where
    F: Future<Output = Result<(), RadioError>> + Send + 'static,
{
    Component::task("fault", false, move || drop_once(after, action()))
}

/// Waits `after` on the runtime's clock, logs [`DROPPING`], runs `dropping` and logs a failure of it as a warning
/// (no panic: a link that could not be dropped is a fault that did not happen), and waits for ever.
async fn drop_once(
    after: Duration,
    dropping: impl Future<Output = Result<(), RadioError>>,
) -> Ended {
    tokio::time::sleep(after).await;
    log::info!("{DROPPING}");
    if let Err(error) = dropping.await {
        log::warn!("fault: the link could not be dropped: {error}");
    }
    future::pending().await
}

/// Leaves the network on the Wi-Fi interface `ifname`, as the station that asks to (reason 3, deauthenticated
/// because the sender is leaving), over sockets of its own.
///
/// The Wi-Fi task is not told: the kernel reports the disconnect, and the task hears that as it would
/// the loss of an access point. The sockets are the offloaded kind, like the Wi-Fi task's, because the
/// driver runs the request inside the send.
pub async fn drop_link(ifname: &str) -> Result<(), RadioError> {
    let mut route = Route::open_offloaded().map_err(RadioError::Io)?;
    let link = route
        .link(ifname)
        .await
        .map_err(RadioError::Request)?
        .ok_or(RadioError::NoInterface)?;
    let mut nl = Nl80211::open_offloaded()
        .await
        .map_err(RadioError::Request)?;
    let message = nl80211::disconnect(nl.family(), link.index, REASON_LEAVING);
    nl.request(message)
        .await
        .map(drop)
        .map_err(RadioError::Request)
}

/// The component of [`Fault::MuteProbe`]: after `after` it arms `mute`, and then waits for ever.
fn muting_component(mute: &'static Mute, after: Duration) -> Component {
    Component::task("fault", false, move || arm_after(mute, after))
}

/// Waits `after` on the runtime's clock, logs [`MUTING`], arms `mute`, and waits for ever.
pub(crate) async fn arm_after(mute: &Mute, after: Duration) -> Ended {
    tokio::time::sleep(after).await;
    log::info!("{MUTING}");
    mute.arm();
    future::pending().await
}

/// The switch that [`Fault::MuteProbe`] throws, a one-shot that mutes the radio's liveness probe for one hold.
///
/// Three states. Off: probes go to the radio as usual. Armed: the next probe is the first one muted.
/// Muting: every probe fails, until the hold ends; then the switch is off again, so the next hold's
/// probes are answered. The kernel radio asks [`probe`](Self::probe) before it sends the query and
/// tells the switch with [`hold_over`](Self::hold_over) when a new join begins (every hold is
/// preceded by a connect), so a hold that ends of any cause, the three failed probes included, leaves
/// the switch off. In the usual state the check is one load of an atomic, every `PROBE_EVERY`.
pub struct Mute(AtomicU8);

/// Probes go to the radio.
const SWITCH_OFF: u8 = 0;
/// The next probe is the first one to be muted.
const SWITCH_ARMED: u8 = 1;
/// The hold that is muted is still on.
const SWITCH_MUTING: u8 = 2;

impl Mute {
    /// A switch that is off.
    pub const fn new() -> Self {
        Self(AtomicU8::new(SWITCH_OFF))
    }

    /// Arms the switch if it is off. One that is armed or muting is as it was: a one-shot is not stacked.
    pub fn arm(&self) {
        // The switch guards no other data, so no ordering with anything else is needed.
        let _ = self.0.compare_exchange(
            SWITCH_OFF,
            SWITCH_ARMED,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }

    /// What a probe may do now: `Ok` if it goes to the radio, and a failure that says it was provoked if
    /// it must not, as the radio would fail it if it did not answer. No command is sent in that case.
    ///
    /// The first probe that is muted makes the switch muting.
    pub fn probe(&self) -> Result<(), RadioError> {
        if self.0.load(Ordering::Relaxed) == SWITCH_OFF {
            return Ok(());
        }
        let _ = self.0.compare_exchange(
            SWITCH_ARMED,
            SWITCH_MUTING,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
        Err(RadioError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            MUTED,
        )))
    }

    /// Says that the hold that was muted is over: a muting switch is off again. An armed one stays armed,
    /// as no probe was muted yet; an off one is as it was.
    pub fn hold_over(&self) {
        let _ = self.0.compare_exchange(
            SWITCH_MUTING,
            SWITCH_OFF,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }
}

impl Default for Mute {
    fn default() -> Self {
        Self::new()
    }
}

/// The process's switch of [`Fault::MuteProbe`]. Only `Fault::MuteProbe` arms it, so with any other
/// fault it stays off and the kernel radio's probes are as they are.
static MUTE: Mute = Mute::new();

/// The process's [`Mute`], which the kernel radio asks.
pub fn mute() -> &'static Mute {
    &MUTE
}

/// The senders of the links that [`link`] has made, kept so that no channel of them ever closes.
static KEPT: Mutex<Vec<watch::Sender<WifiStatus>>> = Mutex::new(Vec::new());

/// The Wi-Fi link that [`Fault::NoWifi`] stands for, if it is the fault: a status that stays
/// `Starting` and so never associates, in place of the real Wi-Fi's.
///
/// Its sender lives for the life of the process, so the link is never a closed channel: what the
/// supervisor sees is a Wi-Fi that is there and never joins.
pub fn link(fault: Fault) -> Option<watch::Receiver<WifiStatus>> {
    if fault != Fault::NoWifi {
        return None;
    }
    let (sender, receiver) = watch::channel(WifiStatus::Starting);
    KEPT.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(sender);
    Some(receiver)
}

/// Ends at once, as a failure.
async fn crash() -> Ended {
    Ended::Failed("provoked".to_owned())
}

/// Waits [`FAULT_AFTER`] on the runtime's clock, and panics.
async fn panic_after_a_while() -> Ended {
    tokio::time::sleep(FAULT_AFTER).await;
    panic!("fault: panic")
}

/// Waits [`TRIAL_PANIC_AFTER`] on the runtime's clock, and panics.
async fn trial_panic() -> Ended {
    tokio::time::sleep(TRIAL_PANIC_AFTER).await;
    panic!("fault: trial panic")
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    use tokio::time::{Instant, sleep};

    use crate::supervisor::{self, Hooks, Plan, Reason};
    use crate::wifi::WifiStatus;

    /// The log buffer every test in this binary shares. The log macros do nothing until a logger is
    /// installed, so a test that reads the log calls this before the code under test runs.
    fn logging() -> &'static Mutex<crate::logbuf::LogBuf> {
        crate::logbuf::install(Box::new(std::io::sink()))
    }

    /// Everything the log holds.
    fn log_text() -> String {
        logging()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .text()
    }

    #[test]
    fn only_the_stall_fault_stalls_and_only_after_ten_seconds() {
        let secs = Duration::from_secs;
        assert!(!stall_due(Fault::Stall, secs(9)));
        assert!(!stall_due(Fault::Stall, Duration::from_millis(9_999)));
        assert!(stall_due(Fault::Stall, secs(10)));
        assert!(stall_due(Fault::Stall, secs(3600)));
        for other in [
            Fault::None,
            Fault::CrashLoop,
            Fault::Panic,
            Fault::NoWifi,
            Fault::DropLink,
            Fault::MuteProbe,
            // The trial stall stalls as `effective` turns it into `Stall`, and not as it is.
            Fault::TrialStall,
            Fault::TrialPanic,
        ] {
            assert!(!stall_due(other, secs(3600)), "{other:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_crash_loop_fails_at_once_every_time_and_is_essential() {
        let mut c = component(Fault::CrashLoop).unwrap();
        assert!(c.essential && c.name == "fault");
        assert_eq!(
            ((c.start)().await, (c.start)().await),
            (
                Ended::Failed("provoked".into()),
                Ended::Failed("provoked".into())
            )
        );
        for none in [Fault::None, Fault::Stall, Fault::NoWifi, Fault::TrialStall] {
            assert!(component(none).is_none(), "{none:?}");
        }
    }

    #[test]
    fn the_trial_faults_act_only_on_a_boot_that_is_on_trial() {
        for fault in [Fault::TrialStall, Fault::TrialPanic] {
            assert_eq!(effective(fault, false), Fault::None, "{fault:?}");
            assert!(component(effective(fault, false)).is_none(), "{fault:?}");
        }
        // On trial the stall is the plain stall, and the panic is the one that has a component.
        assert_eq!(effective(Fault::TrialStall, true), Fault::Stall);
        assert_eq!(effective(Fault::TrialPanic, true), Fault::TrialPanic);
        assert!(stall_due(
            effective(Fault::TrialStall, true),
            Duration::from_secs(10)
        ));
        assert!(!stall_due(
            effective(Fault::TrialStall, false),
            Duration::from_secs(3600)
        ));
        // Every other fault is as it was asked for, trial or not.
        for fault in [
            Fault::None,
            Fault::Stall,
            Fault::CrashLoop,
            Fault::Panic,
            Fault::NoWifi,
            Fault::DropLink,
            Fault::MuteProbe,
        ] {
            assert_eq!(effective(fault, true), fault, "{fault:?}");
            assert_eq!(effective(fault, false), fault, "{fault:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_trial_panic_runs_quietly_for_three_seconds_and_then_panics() {
        let mut c = component(effective(Fault::TrialPanic, true)).unwrap();
        assert!(c.essential && c.name == "fault");
        let task = tokio::spawn((c.start)());

        tokio::time::sleep(TRIAL_PANIC_AFTER - Duration::from_millis(1)).await;
        assert!(!task.is_finished());
        tokio::time::sleep(Duration::from_millis(2)).await;
        let error = task.await.unwrap_err();
        assert!(error.is_panic());
        assert_eq!(
            error.into_panic().downcast_ref::<&str>(),
            Some(&"fault: trial panic")
        );
        assert_eq!(TRIAL_PANIC_AFTER, Duration::from_secs(3));
    }

    #[tokio::test(start_paused = true)]
    async fn the_panic_fault_runs_quietly_for_ten_seconds_and_then_panics() {
        let mut c = component(Fault::Panic).unwrap();
        assert!(c.essential && c.name == "fault");
        let task = tokio::spawn((c.start)());

        tokio::time::sleep(FAULT_AFTER - Duration::from_millis(1)).await;
        assert!(!task.is_finished());
        tokio::time::sleep(Duration::from_millis(2)).await;
        let error = task.await.unwrap_err();
        assert!(error.is_panic());
        assert_eq!(
            error.into_panic().downcast_ref::<&str>(),
            Some(&"fault: panic")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_crash_loop_under_the_supervisor_ends_in_a_restart_after_three_failures() {
        let began = Instant::now();
        let plan = Plan {
            components: vec![component(Fault::CrashLoop).unwrap()],
            return_after: None,
            restart: None,
            link: None,
        };
        let hooks = Hooks {
            tick: Box::new(|| {}),
            led: Box::new(|_| {}),
        };

        let reason = supervisor::run(plan, hooks).await;

        assert_eq!(reason, Reason::ComponentFailed("fault"));
        assert_eq!(
            reason.to_string(),
            "component fault failed 3 times in a minute"
        );
        // Each of the first two failures waits one second before the next start.
        assert_eq!(began.elapsed(), supervisor::RESTART_DELAY * 2);
    }

    #[test]
    fn the_no_wifi_fault_is_a_status_that_never_associates() {
        let rx = link(Fault::NoWifi).unwrap();
        assert_eq!(*rx.borrow(), WifiStatus::Starting);
        assert!(!crate::link::is_associated(&rx.borrow()));
        // Its sender is alive: the channel is not closed.
        assert!(rx.has_changed().is_ok());
        for other in [
            Fault::None,
            Fault::Stall,
            Fault::CrashLoop,
            Fault::Panic,
            Fault::DropLink,
            Fault::MuteProbe,
            Fault::TrialStall,
            Fault::TrialPanic,
        ] {
            assert!(link(other).is_none(), "{other:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_no_wifi_fault_stays_open_however_long_the_board_waits() {
        let mut rx = link(Fault::NoWifi).unwrap();
        // No change comes, and the channel does not close, in ten minutes of the paused clock.
        let waited = tokio::time::timeout(Duration::from_secs(600), rx.changed()).await;
        assert!(waited.is_err(), "{waited:?}");
        assert_eq!(*rx.borrow(), WifiStatus::Starting);
    }

    #[test]
    fn the_two_link_faults_are_components_named_fault_that_are_not_essential() {
        for fault in [Fault::DropLink, Fault::MuteProbe] {
            let c = component(fault).unwrap();
            assert!(!c.essential && c.name == "fault", "{fault:?}");
        }
    }

    /// A component that drops the link after a minute with an action of its own: it counts its calls,
    /// and says `outcome`.
    fn dropping_with(
        calls: &Arc<AtomicUsize>,
        outcome: fn() -> Result<(), RadioError>,
    ) -> Component {
        let calls = calls.clone();
        dropping_component(DROP_AFTER, move || {
            let calls = calls.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                outcome()
            }
        })
    }

    #[tokio::test(start_paused = true)]
    async fn the_drop_link_component_drops_the_link_once_at_sixty_seconds_and_never_ends() {
        logging();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut c = dropping_with(&calls, || Ok(()));
        let task = tokio::spawn((c.start)());

        sleep(DROP_AFTER - Duration::from_millis(1)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        sleep(Duration::from_millis(2)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(log_text().contains("fault: dropping the Wi-Fi link once"));

        // It waits for ever: an hour later it has done nothing more and has not ended.
        sleep(Duration::from_secs(3600)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(!task.is_finished());
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_link_that_could_not_be_dropped_is_a_warning_and_the_component_goes_on() {
        logging();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut c = dropping_with(&calls, || Err(RadioError::NoInterface));
        let task = tokio::spawn((c.start)());

        sleep(DROP_AFTER + Duration::from_secs(1)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(
            log_text()
                .contains("fault: the link could not be dropped: the wireless interface is gone")
        );
        sleep(Duration::from_secs(3600)).await;
        assert!(!task.is_finished(), "a failed drop is no failed component");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        task.abort();
    }

    #[test]
    fn the_mute_switch_mutes_from_the_first_probe_after_it_is_armed_until_the_hold_is_over() {
        let mute = Mute::new();
        // Off, probes go to the radio, and the end of a hold changes nothing.
        assert!(mute.probe().is_ok());
        mute.hold_over();
        assert!(mute.probe().is_ok());

        mute.arm();
        // The end of a hold that was not muted (none was) leaves it armed.
        mute.hold_over();
        for probe in 1..=5 {
            let error = mute.probe().unwrap_err();
            assert_eq!(
                error.to_string(),
                "no answer (fault: mute-probe)",
                "{probe}"
            );
        }
        // Arming again does not stack a second one behind it.
        mute.arm();
        assert!(mute.probe().is_err());

        // The hold is over: the next one is answered, and stays so.
        mute.hold_over();
        for _ in 0..5 {
            assert!(mute.probe().is_ok());
        }
        mute.hold_over();
        assert!(mute.probe().is_ok());

        // A second arming is a second one-shot.
        mute.arm();
        assert!(mute.probe().is_err());
        mute.hold_over();
        assert!(mute.probe().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn the_mute_component_arms_the_switch_at_sixty_seconds_and_never_ends() {
        logging();
        let mute: &'static Mute = Box::leak(Box::new(Mute::new()));
        let mut c = muting_component(mute, MUTE_AFTER);
        let task = tokio::spawn((c.start)());

        sleep(MUTE_AFTER - Duration::from_millis(1)).await;
        assert!(mute.probe().is_ok());
        sleep(Duration::from_millis(2)).await;
        assert!(log_text().contains("fault: muting the radio's liveness probe for one hold"));
        assert!(mute.probe().is_err());

        sleep(Duration::from_secs(3600)).await;
        assert!(!task.is_finished());
        // It armed once: a hold that ends releases the switch, and nothing arms it again.
        mute.hold_over();
        assert!(mute.probe().is_ok());
        task.abort();
    }

    #[test]
    fn the_real_drop_of_a_link_that_is_not_there_is_an_error_and_no_panic() {
        crate::testns::run_inside("fault::tests::ns_drop_without_an_interface");
    }

    #[tokio::test]
    #[ignore = "run by the_real_drop_of_a_link_that_is_not_there_is_an_error_and_no_panic, inside a namespace"]
    async fn ns_drop_without_an_interface() {
        if !crate::testns::inside() {
            return;
        }
        // A new namespace has no `nosuch0`: the request for its index is the one that fails. The sockets
        // are the offloaded kind.
        let opened = crate::netlink::socket::offloaded_opens();
        let error = drop_link("nosuch0").await.unwrap_err();
        assert!(matches!(error, RadioError::NoInterface), "{error}");
        assert_eq!(crate::netlink::socket::offloaded_opens() - opened, 1);
    }
}
