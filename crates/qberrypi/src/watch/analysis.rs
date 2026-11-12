//! The analysis component: it takes the answers that the listener offered to the feed, a batch
//! at a time, and gives them to the behaviour detectors.
//!
//! The listener never waits for the analysis: it offers each answer to the feed, which holds
//! [`FEED_CAPACITY`] of them. Here a component future wakes every [`DRAIN_EVERY`], takes at most
//! [`DRAIN_MAX`] events from the feed in one go, and stamps all of them with one reading of the
//! monotonic clock, which is as fine as the detectors need. A drain is bounded, so that the
//! runtime thread is never held for anything near a second however full the feed is, and the
//! events that a drain leaves wait for the next one.
//!
//! Nothing here logs: the events carry names and clients, and the alerts that come of them are
//! logged by the store as kinds, never as what they are about.
//!
//! [`FEED_CAPACITY`]: super::FEED_CAPACITY

use std::sync::Arc;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::Duration;

use tokio::time::{Instant, MissedTickBehavior, interval_at};

use super::Event;
use super::behaviour::Behaviour;
use crate::alerts::AlertSink;
use crate::supervisor::Ended;

/// How long the analysis waits between two drains of the feed.
pub const DRAIN_EVERY: Duration = Duration::from_millis(250);

/// How many events one drain takes at most.
pub const DRAIN_MAX: usize = 4096;

/// What a failed run says: every [`Feed`](super::Feed) was dropped, so no event can come any more.
const FEED_GONE: &str = "the feed is gone";

/// A monotonic clock in milliseconds that reads 0 now, from the runtime's clock, which is the
/// paused one in a test. It is what the board gives [`run`] as `mono_ms`.
pub fn clock() -> impl Fn() -> u64 + Send + 'static {
    let start = Instant::now();
    move || u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Runs the analysis for as long as the feed lives: every [`DRAIN_EVERY`] it takes up to
/// [`DRAIN_MAX`] events from `rx`, reads `mono_ms` once for all of them, and gives each to
/// `behaviour`, whose alerts go to `sink`. The first drain is one [`DRAIN_EVERY`] after the start,
/// and a tick that came late because a drain took long does not make up for the ticks it missed.
///
/// It ends only when every sender of the feed is gone and the events that were left are taken,
/// and then it ends with [`Ended::Failed`] after that one drain: it does not spin on a channel
/// that is closed, and the supervisor decides whether to start it again, which would need a feed
/// to be made afresh.
pub async fn run(
    rx: Receiver<Event>,
    mut behaviour: Behaviour,
    sink: Arc<dyn AlertSink>,
    mono_ms: impl Fn() -> u64 + Send,
) -> Ended {
    let mut ticker = interval_at(Instant::now() + DRAIN_EVERY, DRAIN_EVERY);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let now = mono_ms();
        let drained = drain(&rx, |event| {
            behaviour.observe(&event, now, &mut |alert| sink.raise(alert));
        });
        if drained == Drained::FeedGone {
            return Ended::Failed(FEED_GONE.to_owned());
        }
    }
}

/// How a drain ended.
#[derive(Debug, PartialEq, Eq)]
enum Drained {
    /// The feed was empty, or [`DRAIN_MAX`] events were taken and it may hold more.
    Open,
    /// The feed was empty and every sender is gone.
    FeedGone,
}

/// Takes at most [`DRAIN_MAX`] events from `rx` without waiting and gives each to `take`.
fn drain(rx: &Receiver<Event>, mut take: impl FnMut(Event)) -> Drained {
    for _ in 0..DRAIN_MAX {
        match rx.try_recv() {
            Ok(event) => take(event),
            Err(TryRecvError::Empty) => return Drained::Open,
            Err(TryRecvError::Disconnected) => return Drained::FeedGone,
        }
    }
    Drained::Open
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::mpsc::{SyncSender, sync_channel};
    use std::sync::{Mutex, PoisonError};

    use super::super::{FEED_CAPACITY, Feed, feed, wire_of};
    use crate::alerts::{Alert, Severity};

    /// A client of the documentation range `192.0.2.0/24`.
    fn client(host: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, host))
    }

    /// The type of an A question.
    const A: u16 = 1;
    /// The response code of a name that does not exist.
    const NXDOMAIN: u8 = 3;
    /// The consonants that make a label that looks random.
    const CONSONANTS: &[u8] = b"bcdfghjklmnpqrstvwxz";

    /// An answer to a question for `name` of type `A` with the response code `rcode`, and no record.
    fn reply(name: &str, rcode: u8) -> Vec<u8> {
        let mut out = vec![0x12, 0x34, 0x81, 0x80 | rcode, 0, 1, 0, 0, 0, 0, 0, 0];
        out.extend_from_slice(&wire_of(name));
        out.extend_from_slice(&A.to_be_bytes());
        out.extend_from_slice(&[0, 1]);
        out
    }

    /// The `n`th name of a family of random-looking names under `.com`, for `n` below 400.
    fn random_name(n: usize) -> String {
        format!(
            "qxzkvbtw{}{}.com",
            char::from(CONSONANTS[n / 20]),
            char::from(CONSONANTS[n % 20])
        )
    }

    /// One alert as the tests see it: the kind, the severity as text, the client and the subject.
    type Raised = (&'static str, &'static str, Option<IpAddr>, String);

    /// A sink that keeps what it is given.
    #[derive(Default)]
    struct Kept(Mutex<Vec<Raised>>);

    impl Kept {
        /// What was raised so far, in order.
        fn alerts(&self) -> Vec<Raised> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    impl AlertSink for Kept {
        fn raise(&self, alert: Alert) {
            let severity = match alert.severity {
                Severity::Info => "info",
                Severity::Warn => "warn",
                Severity::High => "high",
            };
            self.0.lock().unwrap_or_else(PoisonError::into_inner).push((
                alert.kind,
                severity,
                alert.client,
                alert.subject,
            ));
        }
    }

    /// Lets the tasks of the paused runtime run for `by` of its clock, and then some.
    async fn pass(by: Duration) {
        tokio::time::sleep(by + Duration::from_millis(1)).await;
    }

    /// An event for `name`, asked by `client`, answered with `rcode`.
    fn event(client: IpAddr, name: &str, rcode: u8) -> Event {
        Event::for_test(client, name, A, rcode, 60)
    }

    /// The feed of the board, the analysis on it as a task, and the sink it raises into. The clock
    /// is `clock`, a number that the test sets.
    fn start(clock: Arc<AtomicU64>) -> (Feed, Arc<Kept>, tokio::task::JoinHandle<Ended>) {
        let (feed, rx) = feed();
        let kept = Arc::new(Kept::default());
        let sink: Arc<dyn AlertSink> = kept.clone();
        let task = tokio::spawn(run(rx, Behaviour::new(Vec::new()), sink, move || {
            clock.load(Ordering::SeqCst)
        }));
        (feed, kept, task)
    }

    #[test]
    fn the_analysis_is_a_send_future_as_a_component_needs() {
        /// Fails to compile unless `_future` is `Send`.
        fn send<T: Send>(_future: &T) {}
        let (_feed, rx) = feed();
        let future = run(
            rx,
            Behaviour::new(Vec::new()),
            Arc::new(crate::alerts::NullSink),
            clock(),
        );
        send(&future);
        // And it is what `Component::task` builds a task of.
        let (_feed, rx) = feed();
        let mut waiting = Some(rx);
        let component = crate::supervisor::Component::task("analysis", false, move || {
            run(
                waiting.take().expect("one start"),
                Behaviour::new(Vec::new()),
                Arc::new(crate::alerts::NullSink),
                clock(),
            )
        });
        assert!(!component.essential);
    }

    #[tokio::test(start_paused = true)]
    async fn random_names_offered_through_the_feed_reach_the_sink_as_one_dga_alert() {
        let (feed, kept, _task) = start(Arc::new(AtomicU64::new(0)));
        for n in 0..25 {
            feed.offer(client(7), &reply(&random_name(n), NXDOMAIN));
        }
        pass(DRAIN_EVERY).await;
        assert_eq!(
            kept.alerts(),
            vec![(
                "dga",
                "high",
                Some(client(7)),
                "random NXDOMAIN names".to_owned()
            )]
        );
        // Names that do exist, in the next drain, add nothing.
        for n in 0..25 {
            feed.offer(client(8), &reply(&random_name(n), 0));
        }
        pass(DRAIN_EVERY).await;
        assert_eq!(kept.alerts().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn the_events_of_a_drain_are_stamped_with_the_clock_of_that_drain() {
        let clock = Arc::new(AtomicU64::new(0));
        let (feed, kept, _task) = start(clock.clone());
        // The first question of the client, read as 0 ms: a burst only counts from 10 minutes on.
        feed.offer(client(9), &reply("one.example.org", 0));
        pass(DRAIN_EVERY).await;
        // Then 300 questions in one drain, which the clock reads as 11 minutes: a burst.
        clock.store(11 * 60_000, Ordering::SeqCst);
        for n in 0..300 {
            feed.offer(client(9), &reply(&format!("h{n}.example.org"), 0));
        }
        pass(DRAIN_EVERY).await;
        assert_eq!(
            kept.alerts(),
            vec![("burst", "warn", Some(client(9)), "question rate".to_owned())]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_is_processed_before_the_first_tick() {
        let (feed, kept, task) = start(Arc::new(AtomicU64::new(0)));
        for n in 0..25 {
            feed.offer(client(7), &reply(&random_name(n), NXDOMAIN));
        }
        tokio::time::sleep(DRAIN_EVERY - Duration::from_millis(1)).await;
        assert!(kept.alerts().is_empty());
        assert!(!task.is_finished());
        tokio::time::sleep(Duration::from_millis(2)).await;
        assert_eq!(kept.alerts().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn the_clock_is_read_once_for_a_drain_and_the_drains_are_250_ms_apart() {
        let reads = Arc::new(AtomicUsize::new(0));
        let (feed, rx) = feed();
        let counter = reads.clone();
        let _task = tokio::spawn(run(
            rx,
            Behaviour::new(Vec::new()),
            Arc::new(crate::alerts::NullSink),
            move || {
                counter.fetch_add(1, Ordering::SeqCst);
                0
            },
        ));
        for n in 0..100 {
            feed.offer(client(7), &reply(&format!("h{n}.example.org"), 0));
        }
        tokio::time::sleep(DRAIN_EVERY * 4 + Duration::from_millis(1)).await;
        // Four ticks, the first with the 100 events and three with none.
        assert_eq!(reads.load(Ordering::SeqCst), 4);
    }

    /// A raw channel of `capacity` events with `count` events of `client` in it.
    fn filled(capacity: usize, count: usize) -> (SyncSender<Event>, Receiver<Event>) {
        let (tx, rx) = sync_channel(capacity);
        for n in 0..count {
            tx.try_send(event(client(7), &format!("h{n}.example.org"), 0))
                .expect("room for the event");
        }
        (tx, rx)
    }

    /// How many more events `tx` takes before its channel is full.
    fn room(tx: &SyncSender<Event>) -> usize {
        let mut free = 0;
        while tx.try_send(event(client(7), "room.example.org", 0)).is_ok() {
            free += 1;
        }
        free
    }

    #[test]
    fn a_drain_takes_at_most_4096_events_and_leaves_the_rest() {
        let (_tx, rx) = filled(DRAIN_MAX + 10, DRAIN_MAX + 10);
        let mut taken = 0;
        assert_eq!(drain(&rx, |_| taken += 1), Drained::Open);
        assert_eq!(taken, DRAIN_MAX);
        assert_eq!(rx.try_iter().count(), 10);
        // Exactly 4096 in the channel: all taken, and the channel is only found empty next time.
        let (_tx, rx) = filled(DRAIN_MAX, DRAIN_MAX);
        let mut taken = 0;
        assert_eq!(drain(&rx, |_| taken += 1), Drained::Open);
        assert_eq!(taken, DRAIN_MAX);
    }

    #[tokio::test(start_paused = true)]
    async fn a_tick_drains_4096_of_the_events_and_the_next_tick_the_rest() {
        let (tx, rx) = filled(DRAIN_MAX + 10, DRAIN_MAX + 10);
        let _task = tokio::spawn(run(
            rx,
            Behaviour::new(Vec::new()),
            Arc::new(crate::alerts::NullSink),
            || 0,
        ));
        // A full channel has no room; one tick later exactly 4096 places are free.
        assert_eq!(room(&tx), 0);
        pass(DRAIN_EVERY).await;
        assert_eq!(room(&tx), DRAIN_MAX);
        // That filled it again with the 10 that were left and 4096 more; the next tick takes 4096
        // of them.
        pass(DRAIN_EVERY).await;
        assert_eq!(room(&tx), DRAIN_MAX);
    }

    #[test]
    fn a_drain_gives_every_event_to_take_in_the_order_of_the_feed() {
        let (feed, rx) = feed();
        for host in ["a", "b", "c"] {
            feed.offer(client(7), &reply(&format!("{host}.example.org"), 0));
        }
        let mut seen = Vec::new();
        assert_eq!(
            drain(&rx, |event| seen.push(event.name_wire().to_vec())),
            Drained::Open
        );
        assert_eq!(
            seen,
            ["a", "b", "c"]
                .map(|host| wire_of(&format!("{host}.example.org")))
                .to_vec()
        );
        // Nothing offered: nothing taken, and not an end.
        assert_eq!(
            drain(&rx, |_| panic!("an event from nowhere")),
            Drained::Open
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_dropped_feed_ends_the_analysis_with_failed_after_one_tick_and_it_does_not_spin() {
        let (feed, rx) = feed();
        drop(feed);
        let began = Instant::now();
        let ended = run(
            rx,
            Behaviour::new(Vec::new()),
            Arc::new(crate::alerts::NullSink),
            || 0,
        )
        .await;
        assert_eq!(ended, Ended::Failed("the feed is gone".to_owned()));
        assert_eq!(began.elapsed(), DRAIN_EVERY);
    }

    #[tokio::test(start_paused = true)]
    async fn events_that_were_in_the_feed_when_it_was_dropped_are_taken_before_the_end() {
        let (feed, kept, task) = start(Arc::new(AtomicU64::new(0)));
        for n in 0..25 {
            feed.offer(client(7), &reply(&random_name(n), NXDOMAIN));
        }
        drop(feed);
        assert_eq!(
            task.await.unwrap(),
            Ended::Failed("the feed is gone".into())
        );
        assert_eq!(kept.alerts().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_running_analysis_with_a_live_feed_stays_pending_for_hours() {
        let (_feed, kept, task) = start(Arc::new(AtomicU64::new(0)));
        tokio::time::sleep(Duration::from_secs(3 * 3600)).await;
        assert!(!task.is_finished());
        assert!(kept.alerts().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn the_clock_reads_the_runtimes_milliseconds_from_where_it_was_made() {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let now = clock();
        assert_eq!(now(), 0);
        tokio::time::sleep(Duration::from_millis(1234)).await;
        assert_eq!(now(), 1234);
    }

    /// The `n`th of the many clients of a flood: documentation addresses, of the IPv4 ranges and
    /// then of `2001:db8::/32`.
    fn flood_client(n: usize) -> IpAddr {
        match n % 3 {
            0 => IpAddr::V4(Ipv4Addr::new(192, 0, 2, (n % 251) as u8)),
            1 => IpAddr::V4(Ipv4Addr::new(198, 51, 100, (n % 251) as u8)),
            _ => IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, n as u16)),
        }
    }

    /// A drain of 4096 events of a mix that is rough on the detectors: random names that do not
    /// exist, long names under a few domains, TXT questions and plain names, from 300 clients that
    /// take turns so that the table of 128 evicts at nearly every event.
    fn flood() -> Vec<Event> {
        (0..DRAIN_MAX)
            .map(|n| {
                let who = flood_client(n % 300);
                match n % 4 {
                    0 => event(who, &format!("qxzkvbtw{n:05}x.com"), NXDOMAIN),
                    1 => event(who, &format!("{n:040}.example.com"), 0),
                    2 => Event::for_test(who, &format!("t{n}.example.org"), 16, 0, 60),
                    _ => event(who, &format!("www{n}.example.net"), 0),
                }
            })
            .collect()
    }

    /// Gives `events` to fresh detectors, all stamped alike, and says how long it took and how many
    /// alerts came of it.
    fn time_drain(events: &[Event]) -> (Duration, usize) {
        let mut behaviour = Behaviour::new(vec!["quiet.example.org".to_owned()]);
        let mut raised = 0usize;
        let began = std::time::Instant::now();
        for event in events {
            behaviour.observe(event, 1_000_000, &mut |_| raised += 1);
        }
        (began.elapsed(), raised)
    }

    #[test]
    fn a_full_drain_of_4096_events_takes_well_under_a_second() {
        let build = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        let events = flood();
        assert_eq!(events.len(), DRAIN_MAX);
        // One client that asks for 4096 different random names that do not exist.
        let one_client: Vec<Event> = (0..DRAIN_MAX)
            .map(|n| event(client(7), &format!("qxzkvbtw{n:05}x.com"), NXDOMAIN))
            .collect();
        for (what, trace) in [("300 clients, mixed", &events), ("one client", &one_client)] {
            let (took, raised) = time_drain(trace);
            println!(
                "drain of {DRAIN_MAX} events, {what}: {took:?} ({:?} per event), {raised} alerts, {build} build",
                took / u32::try_from(DRAIN_MAX).unwrap(),
            );
            assert!(
                took < Duration::from_millis(500),
                "a drain of {DRAIN_MAX} events, {what}, took {took:?}"
            );
        }
    }

    #[test]
    fn the_feed_holds_fewer_events_than_a_drain_takes_so_one_tick_empties_it() {
        // Not a rule of the code but what the sizes mean: with the feed at 1024 and a drain at
        // 4096, a drain that is on time never leaves events behind.
        const { assert!(FEED_CAPACITY < DRAIN_MAX) };
    }
}
