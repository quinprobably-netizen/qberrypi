//! The wait between attempts to join a network.

use std::time::Duration;

/// The longest wait between two attempts.
pub const BACKOFF_CAP: Duration = Duration::from_secs(30);

/// How long to wait before the next attempt: none after the first failure in a row, then 1, 2, 4, 8 and 16
/// seconds, then `BACKOFF_CAP` after each one that follows.
#[derive(Debug, Default)]
pub struct Backoff {
    /// The failures since the last success; it stops counting far above what the waits need.
    failures: u8,
}

impl Backoff {
    /// Records a failure and returns the wait before the next attempt.
    pub fn failed(&mut self) -> Duration {
        let wait = match self.failures {
            0 => Duration::ZERO,
            n => Duration::from_secs(1 << (n - 1).min(5)).min(BACKOFF_CAP),
        };
        self.failures = self.failures.saturating_add(1);
        wait
    }

    /// Records that a connection was made: the next failure is the first of a new run.
    pub fn succeeded(&mut self) {
        self.failures = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waits_grow_to_thirty_seconds_and_stay() {
        let mut b = Backoff::default();
        let waits: Vec<u64> = (0..9).map(|_| b.failed().as_secs()).collect();
        assert_eq!(waits, [0, 1, 2, 4, 8, 16, 30, 30, 30]);
    }

    #[test]
    fn a_success_starts_over() {
        let mut b = Backoff::default();
        for _ in 0..5 {
            b.failed();
        }
        b.succeeded();
        assert_eq!(b.failed(), Duration::ZERO);
        assert_eq!(b.failed(), Duration::from_secs(1));
    }
}
