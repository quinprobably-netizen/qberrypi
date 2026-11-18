//! When a changed state is worth a write: not while it is still changing, and not too often.
//!
//! The saver looks at the state every [`POLL`], and tells a [`Debounce`] whether its bytes differ
//! from the poll before ([`Debounce::seen`]) and when a save begins ([`Debounce::saved`]). A save
//! is [due](Debounce::due) when the bytes differ from what the newest copy holds, they have not
//! changed for [`QUIET`], and at least [`MIN_GAP`] have passed since the last save began: an owner
//! who is still editing writes nothing until they stop, and one who never stops writes once a
//! minute at most, which is as often as the card is worth. The timing is a pure state of two
//! instants, and tokio's clock so that a test moves it by hand.

use std::time::Duration;

use tokio::time::Instant;

/// How often the saver looks at the state.
pub const POLL: Duration = Duration::from_secs(5);

/// How long the state must have been unchanged before it is saved.
pub const QUIET: Duration = Duration::from_secs(30);

/// The least time between the starts of two saves.
pub const MIN_GAP: Duration = Duration::from_secs(60);

/// When the state last changed and when the last save began.
#[derive(Debug, Clone, Copy)]
pub struct Debounce {
    /// When the bytes last differed from the poll before; the start, until a change is seen.
    changed: Instant,
    /// When the last save began, if one has.
    saved: Option<Instant>,
}

impl Debounce {
    /// A debounce that starts at `now`, with no save yet. The quiet is counted from `now`, as if the
    /// state had just changed, so that a start that restores a state and finds it already differs
    /// from the copy (a configuration that changed) is not written in its first seconds.
    pub fn new(now: Instant) -> Self {
        Self {
            changed: now,
            saved: None,
        }
    }

    /// Notes a poll at `now`: when `bytes_changed`, the bytes differ from the poll before, and the
    /// quiet starts over from `now`.
    pub fn seen(&mut self, bytes_changed: bool, now: Instant) {
        if bytes_changed {
            self.changed = now;
        }
    }

    /// Notes that a save began at `now`: the next one waits [`MIN_GAP`] from it.
    pub fn saved(&mut self, now: Instant) {
        self.saved = Some(now);
    }

    /// Whether a save is due at `now`: the bytes differ from the newest copy's (`differs_from_saved`),
    /// they have not changed for [`QUIET`], and the last save began [`MIN_GAP`] ago or never.
    pub fn due(&self, now: Instant, differs_from_saved: bool) -> bool {
        differs_from_saved
            && now.saturating_duration_since(self.changed) >= QUIET
            && self
                .saved
                .is_none_or(|began| now.saturating_duration_since(began) >= MIN_GAP)
    }
}

#[cfg(test)]
mod tests {
    use tokio::time::advance;

    use super::*;

    const SECOND: Duration = Duration::from_secs(1);

    #[test]
    fn the_timings_are_the_documented_ones() {
        assert_eq!(POLL, Duration::from_secs(5));
        assert_eq!(QUIET, Duration::from_secs(30));
        assert_eq!(MIN_GAP, Duration::from_secs(60));
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_is_due_before_thirty_seconds_of_quiet() {
        let debounce = Debounce::new(Instant::now());
        assert!(!debounce.due(Instant::now(), true));
        advance(QUIET - SECOND).await;
        assert!(!debounce.due(Instant::now(), true), "29 s");
        advance(SECOND).await;
        assert!(debounce.due(Instant::now(), true), "30 s");
        advance(Duration::from_secs(600)).await;
        assert!(debounce.due(Instant::now(), true), "and it stays due");
    }

    #[tokio::test(start_paused = true)]
    async fn a_change_at_twenty_seconds_starts_the_quiet_over() {
        let mut debounce = Debounce::new(Instant::now());
        advance(Duration::from_secs(20)).await;
        debounce.seen(true, Instant::now());
        advance(Duration::from_secs(29)).await;
        assert!(
            !debounce.due(Instant::now(), true),
            "49 s in, 29 s of quiet"
        );
        advance(SECOND).await;
        assert!(debounce.due(Instant::now(), true), "50 s in, 30 s of quiet");
    }

    #[tokio::test(start_paused = true)]
    async fn a_poll_that_sees_no_change_does_not_move_the_quiet() {
        let mut debounce = Debounce::new(Instant::now());
        for _ in 0..5 {
            advance(POLL).await;
            debounce.seen(false, Instant::now());
        }
        assert!(!debounce.due(Instant::now(), true), "25 s");
        advance(POLL).await;
        debounce.seen(false, Instant::now());
        assert!(debounce.due(Instant::now(), true), "30 s");
    }

    #[tokio::test(start_paused = true)]
    async fn a_second_save_waits_sixty_seconds_from_the_start_of_the_first_even_when_quiet() {
        let mut debounce = Debounce::new(Instant::now());
        advance(QUIET).await;
        assert!(debounce.due(Instant::now(), true));
        debounce.saved(Instant::now());
        // The state changes right after the save, and is quiet again in 30 s: still not due.
        advance(SECOND).await;
        debounce.seen(true, Instant::now());
        advance(QUIET).await;
        assert!(
            !debounce.due(Instant::now(), true),
            "31 s after the first save began"
        );
        advance(Duration::from_secs(28)).await;
        assert!(!debounce.due(Instant::now(), true), "59 s");
        advance(SECOND).await;
        assert!(debounce.due(Instant::now(), true), "60 s");
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_is_due_when_the_bytes_equal_the_saved_ones() {
        let mut debounce = Debounce::new(Instant::now());
        advance(Duration::from_secs(3600)).await;
        assert!(!debounce.due(Instant::now(), false));
        debounce.saved(Instant::now());
        advance(Duration::from_secs(3600)).await;
        assert!(!debounce.due(Instant::now(), false));
        assert!(
            debounce.due(Instant::now(), true),
            "and due the moment they differ"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn steady_edits_never_go_quiet_and_so_never_save() {
        let mut debounce = Debounce::new(Instant::now());
        for _ in 0..100 {
            advance(Duration::from_secs(10)).await;
            debounce.seen(true, Instant::now());
            assert!(!debounce.due(Instant::now(), true));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_time_before_the_change_is_not_due() {
        let start = Instant::now();
        advance(Duration::from_secs(100)).await;
        let mut debounce = Debounce::new(Instant::now());
        debounce.saved(Instant::now());
        // A clock asked for an earlier instant must not panic or wrap into being due.
        assert!(!debounce.due(start, true));
    }
}
