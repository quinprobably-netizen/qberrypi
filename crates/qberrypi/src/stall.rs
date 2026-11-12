//! High-water marks of the stalls that answers wait behind: how long the runtime thread went
//! without polling a heartbeat, how long anyone waited for and held the resolver's lock, how long
//! a poll of each task took, and how long a write to the console took.
//!
//! Every figure is a relaxed atomic that a `fetch_max` or a `fetch_add` updates: no lock, no
//! allocation and no log line on any path that answers a query. The marks are kept since the
//! start, with the uptime of the worst runtime gap; the counts of long gaps are there so that two
//! reads of `/api/v1/stats`, before and after a measurement, say what happened in between.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

/// How often the heartbeat wakes on the runtime thread.
pub const BEAT_EVERY: Duration = Duration::from_millis(10);

/// A gap of the heartbeat at least this much over [`BEAT_EVERY`] counts as a stall.
pub const STALL_MS: u64 = 20;

/// A gap of the heartbeat at least this long counts as a long stall.
pub const LONG_STALL_MS: u64 = 250;

/// How many tasks have a figure of their own; the rest share the last.
const TASK_SLOTS: usize = 24;

/// A high-water mark in microseconds.
#[derive(Default)]
pub struct Mark(AtomicU64);

impl Mark {
    /// A mark at zero.
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    /// Raises the mark to `took` if it is above it.
    pub fn note(&self, took: Duration) {
        self.0.fetch_max(micros(took), Ordering::Relaxed);
    }

    /// The mark, in microseconds.
    pub fn micros(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// `took` in whole microseconds, saturated.
fn micros(took: Duration) -> u64 {
    u64::try_from(took.as_micros()).unwrap_or(u64::MAX)
}

/// The longest gap of the runtime thread's heartbeat beyond its own sleep.
pub static RUNTIME_GAP: Mark = Mark::new();
/// The uptime, in milliseconds since [`start`], at which [`RUNTIME_GAP`] was set.
static RUNTIME_GAP_AT_MS: AtomicU64 = AtomicU64::new(0);
/// The gaps of [`STALL_MS`] or more.
static STALLS: AtomicU64 = AtomicU64::new(0);
/// The gaps of [`LONG_STALL_MS`] or more.
static LONG_STALLS: AtomicU64 = AtomicU64::new(0);
/// The longest wait for the resolver's lock.
pub static RESOLVER_WAIT: Mark = Mark::new();
/// The longest hold of the resolver's lock.
pub static RESOLVER_HOLD: Mark = Mark::new();
/// The longest write of one log line to the console.
pub static CONSOLE_WRITE: Mark = Mark::new();

/// A guard of the resolver's lock that notes, when it goes, how long it was held; and the wait for
/// it was noted when it was taken. Two readings of the monotonic clock per hold.
pub struct Held<'a, T> {
    guard: MutexGuard<'a, T>,
    since: Instant,
}

impl<T> std::ops::Deref for Held<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<T> std::ops::DerefMut for Held<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

impl<T> Drop for Held<'_, T> {
    fn drop(&mut self) {
        RESOLVER_HOLD.note(self.since.elapsed());
    }
}

/// Locks `resolver`, whether or not a holder panicked, with the wait and the hold noted in
/// [`RESOLVER_WAIT`] and [`RESOLVER_HOLD`].
pub fn lock_resolver<T>(resolver: &Mutex<T>) -> Held<'_, T> {
    let asked = Instant::now();
    let guard = resolver.lock().unwrap_or_else(PoisonError::into_inner);
    let since = Instant::now();
    RESOLVER_WAIT.note(since - asked);
    Held { guard, since }
}

/// One task's figures: the longest poll, and the polls of [`STALL_MS`] or more.
struct TaskFigures {
    name: &'static str,
    longest_us: AtomicU64,
    slow: AtomicU64,
}

/// The tasks that have figures, by name; a name is entered at its first spawn and stays.
static TASKS: Mutex<Vec<&'static TaskFigures>> = Mutex::new(Vec::new());

fn tasks() -> MutexGuard<'static, Vec<&'static TaskFigures>> {
    TASKS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The figures of the task `name`, entered now if they are not there. Called once per spawn of a
/// component or of a task of the DNS service, never per poll: the figures are leaked once per
/// name, and there are at most [`TASK_SLOTS`] of them.
fn figures(name: &'static str) -> &'static TaskFigures {
    let mut tasks = tasks();
    if let Some(found) = tasks.iter().find(|figures| figures.name == name) {
        return found;
    }
    if tasks.len() >= TASK_SLOTS
        && let Some(last) = tasks.last()
    {
        return last;
    }
    let made: &'static TaskFigures = Box::leak(Box::new(TaskFigures {
        name,
        longest_us: AtomicU64::new(0),
        slow: AtomicU64::new(0),
    }));
    tasks.push(made);
    made
}

/// `inner`, with each poll timed into the figures of its task.
pub struct Timed<F> {
    inner: Pin<Box<F>>,
    figures: &'static TaskFigures,
}

impl<F: Future> Future for Timed<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let began = Instant::now();
        let polled = self.inner.as_mut().poll(cx);
        let took = micros(began.elapsed());
        self.figures.longest_us.fetch_max(took, Ordering::Relaxed);
        if took >= STALL_MS * 1000 {
            self.figures.slow.fetch_add(1, Ordering::Relaxed);
        }
        polled
    }
}

/// `future`, with its polls timed under `name`.
pub fn timed<F: Future>(name: &'static str, future: F) -> Timed<F> {
    Timed {
        inner: Box::pin(future),
        figures: figures(name),
    }
}

/// Spawns `future` on the runtime with its polls timed under `name`.
pub fn spawn<F>(name: &'static str, future: F) -> tokio::task::JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio::spawn(timed(name, future))
}

/// Times `work`, a call that the runtime thread makes outside any task (the supervisor's tick),
/// under `name`.
pub fn time<R>(name: &'static str, work: impl FnOnce() -> R) -> R {
    let figures = figures(name);
    let began = Instant::now();
    let out = work();
    let took = micros(began.elapsed());
    figures.longest_us.fetch_max(took, Ordering::Relaxed);
    if took >= STALL_MS * 1000 {
        figures.slow.fetch_add(1, Ordering::Relaxed);
    }
    out
}

/// Notes one gap of the heartbeat: `gap` between two wake-ups, `at` since the heartbeat began.
fn note_gap(gap: Duration, at: Duration) {
    let over = gap.saturating_sub(BEAT_EVERY);
    if micros(over) > RUNTIME_GAP.micros() {
        RUNTIME_GAP.note(over);
        RUNTIME_GAP_AT_MS.store(
            u64::try_from(at.as_millis()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }
    let over_ms = micros(over) / 1000;
    if over_ms >= STALL_MS {
        STALLS.fetch_add(1, Ordering::Relaxed);
    }
    if over_ms >= LONG_STALL_MS {
        LONG_STALLS.fetch_add(1, Ordering::Relaxed);
    }
}

/// The heartbeat: wakes every [`BEAT_EVERY`] on the runtime thread for ever, and notes how much
/// later than asked each wake-up came. A hundred wake-ups a second, each a few atomics.
pub async fn heartbeat() {
    let began = Instant::now();
    let mut last = Instant::now();
    loop {
        tokio::time::sleep(BEAT_EVERY).await;
        let now = Instant::now();
        note_gap(now - last, now - began);
        last = now;
    }
}

/// The figures as the statistics show them.
pub fn json() -> Value {
    let tasks: Vec<Value> = tasks()
        .iter()
        .map(|figures| {
            json!({
                "name": figures.name,
                "longest_poll_us": figures.longest_us.load(Ordering::Relaxed),
                "slow_polls": figures.slow.load(Ordering::Relaxed),
            })
        })
        .collect();
    json!({
        "runtime_gap_max_ms": RUNTIME_GAP.micros() / 1000,
        "runtime_gap_max_at_ms": RUNTIME_GAP_AT_MS.load(Ordering::Relaxed),
        "runtime_stalls": STALLS.load(Ordering::Relaxed),
        "runtime_long_stalls": LONG_STALLS.load(Ordering::Relaxed),
        "resolver_lock_wait_max_us": RESOLVER_WAIT.micros(),
        "resolver_lock_hold_max_us": RESOLVER_HOLD.micros(),
        "console_write_max_us": CONSOLE_WRITE.micros(),
        "tasks": tasks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mark_only_rises() {
        let mark = Mark::new();
        mark.note(Duration::from_micros(30));
        mark.note(Duration::from_micros(10));
        assert_eq!(mark.micros(), 30);
    }

    #[test]
    fn a_task_name_has_one_entry_and_a_slow_poll_is_counted() {
        let figures = figures("stall test");
        assert!(std::ptr::eq(figures, super::figures("stall test")));
        time("stall test", || {
            std::thread::sleep(Duration::from_millis(25))
        });
        assert!(figures.longest_us.load(Ordering::Relaxed) >= 25_000);
        assert_eq!(figures.slow.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_hold_of_the_resolver_lock_is_noted_when_it_ends() {
        let resolver = Mutex::new(0u8);
        {
            let mut held = lock_resolver(&resolver);
            *held += 1;
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(RESOLVER_HOLD.micros() >= 5_000);
        assert_eq!(*lock_resolver(&resolver), 1);
    }

    #[test]
    fn a_late_heartbeat_counts_what_it_was_late_by() {
        let (stalls, long) = (
            STALLS.load(Ordering::Relaxed),
            LONG_STALLS.load(Ordering::Relaxed),
        );
        note_gap(
            BEAT_EVERY + Duration::from_millis(300),
            Duration::from_secs(9),
        );
        assert!(RUNTIME_GAP.micros() >= 300_000);
        assert!(STALLS.load(Ordering::Relaxed) > stalls);
        assert!(LONG_STALLS.load(Ordering::Relaxed) > long);
    }

    #[test]
    fn the_statistics_carry_every_figure() {
        let value = json();
        for key in [
            "runtime_gap_max_ms",
            "runtime_gap_max_at_ms",
            "runtime_stalls",
            "runtime_long_stalls",
            "resolver_lock_wait_max_us",
            "resolver_lock_hold_max_us",
            "console_write_max_us",
            "tasks",
        ] {
            assert!(value.get(key).is_some(), "{key}");
        }
    }
}
