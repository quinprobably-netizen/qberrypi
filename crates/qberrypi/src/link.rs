//! The Wi-Fi link as the supervisor watches it: associated or not, what the LED shows for it, and
//! the rule that a board that is not associated for 90 seconds restarts.
//!
//! The link is the Wi-Fi task's own channel of statuses (`wifi::WifiStatus`): it is associated when
//! the status is `Joined`, and not in any other state, a scan, a join under way and the wait before
//! the next attempt included. [`LinkWatch`] is told what the link is at each look and answers with
//! what the LED has to show or that the board has to restart; it reads no clock and runs no timer,
//! so the supervisor, which owns both, can drive it.

use std::time::Duration;

use crate::led::LedState;
use crate::wifi::WifiStatus;

/// How long the board may go without an association, from its start and from each loss, before it
/// has to restart.
pub const NO_ASSOCIATION_LIMIT: Duration = Duration::from_secs(90);

/// The line for a link that was lost.
const LOST_LINE: &str = "wifi: association lost";

/// Whether the link is associated while the Wi-Fi is in `status`: only a join that has completed is.
pub fn is_associated(status: &WifiStatus) -> bool {
    matches!(status, WifiStatus::Joined { .. })
}

/// What a look at the link makes the supervisor do.
#[derive(Debug, PartialEq)]
pub enum LinkStep {
    /// Nothing: the link is as it was, and the time is not up.
    Nothing,
    /// The link changed: this is what the LED shows now.
    Led(LedState),
    /// The link has been down for [`NO_ASSOCIATION_LIMIT`]: the board restarts.
    RestartDue,
}

/// The line for a link that is associated: the first time it is, and after how long away when it is again.
fn associated_line(away: Option<Duration>) -> String {
    match away {
        None => "wifi: associated".to_owned(),
        Some(away) => format!("wifi: associated again after {} s", away.as_secs()),
    }
}

/// Where the link stands, and since when, on a clock that is the caller's.
///
/// Every time is a `Duration` from the same starting point on that clock.
pub struct LinkWatch {
    /// Whether the link is associated.
    associated: bool,
    /// When the link came to be as it is: associated, or not since the last loss or since `new`.
    since: Duration,
    /// Whether the link has been associated at any time since `new`.
    ever_associated: bool,
}

impl LinkWatch {
    /// A link that is not associated since `now`. The LED is meant to show [`LedState::Joining`].
    pub fn new(now: Duration) -> Self {
        Self {
            associated: false,
            since: now,
            ever_associated: false,
        }
    }

    /// How long the link has been down at `now`, or `None` while it is associated.
    fn away_for(&self, now: Duration) -> Option<Duration> {
        (!self.associated).then(|| now.saturating_sub(self.since))
    }

    /// Takes a look at `now`, when the link is `associated` or not, and says what that makes the
    /// supervisor do.
    ///
    /// A change to associated gives [`LinkStep::Led`] with [`LedState::Serving`] and logs it, a change
    /// to not associated gives the same with [`LedState::Joining`] and a warning, and no change gives
    /// [`LinkStep::RestartDue`] once [`NO_ASSOCIATION_LIMIT`] has passed since the link was lost, or
    /// since `new` if it never was associated, and [`LinkStep::Nothing`] before and while associated.
    pub fn observe(&mut self, now: Duration, associated: bool) -> LinkStep {
        match (self.associated, associated) {
            (false, true) => {
                let away = self.away_for(now).filter(|_| self.ever_associated);
                log::info!("{}", associated_line(away));
                self.associated = true;
                self.ever_associated = true;
                self.since = now;
                LinkStep::Led(LedState::Serving)
            }
            (true, false) => {
                log::warn!("{LOST_LINE}");
                self.associated = false;
                self.since = now;
                LinkStep::Led(LedState::Joining)
            }
            (_, false) if now >= self.since + NO_ASSOCIATION_LIMIT => LinkStep::RestartDue,
            _ => LinkStep::Nothing,
        }
    }

    /// When [`LinkStep::RestartDue`] falls, on the caller's clock; `None` while the link is associated.
    pub fn deadline(&self) -> Option<Duration> {
        (!self.associated).then(|| self.since + NO_ASSOCIATION_LIMIT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use crate::led::LedState;
    use crate::wifi::WifiStatus;

    #[test]
    fn ninety_seconds_without_an_association_are_due_from_boot_and_from_each_loss() {
        let secs = Duration::from_secs;
        let mut w = LinkWatch::new(secs(0));
        assert_eq!(w.deadline(), Some(secs(90)));
        assert_eq!(
            w.observe(Duration::from_millis(89_999), false),
            LinkStep::Nothing
        );
        assert_eq!(w.observe(secs(90), false), LinkStep::RestartDue);
        let mut w = LinkWatch::new(secs(0));
        assert_eq!(w.observe(secs(30), true), LinkStep::Led(LedState::Serving));
        assert_eq!(
            (w.observe(secs(500), true), w.deadline()),
            (LinkStep::Nothing, None)
        );
        assert_eq!(
            w.observe(secs(600), false),
            LinkStep::Led(LedState::Joining)
        );
        assert_eq!(w.deadline(), Some(secs(690)));
        assert_eq!(w.observe(secs(689), false), LinkStep::Nothing);
        assert_eq!(w.observe(secs(690), false), LinkStep::RestartDue);
    }

    #[test]
    fn a_watch_that_starts_late_counts_from_its_own_start() {
        let secs = Duration::from_secs;
        let mut w = LinkWatch::new(secs(12));
        assert_eq!(w.deadline(), Some(secs(102)));
        assert_eq!(w.observe(secs(101), false), LinkStep::Nothing);
        assert_eq!(w.observe(secs(102), false), LinkStep::RestartDue);
    }

    #[test]
    fn an_unchanged_state_says_nothing_again_and_a_due_restart_stays_due() {
        let secs = Duration::from_secs;
        let mut w = LinkWatch::new(secs(0));
        assert_eq!(w.observe(secs(1), false), LinkStep::Nothing);
        assert_eq!(w.observe(secs(2), true), LinkStep::Led(LedState::Serving));
        assert_eq!(w.observe(secs(3), true), LinkStep::Nothing);
        assert_eq!(w.observe(secs(4), false), LinkStep::Led(LedState::Joining));
        assert_eq!(w.observe(secs(5), false), LinkStep::Nothing);
        assert_eq!(w.observe(secs(94), false), LinkStep::RestartDue);
        assert_eq!(w.observe(secs(95), false), LinkStep::RestartDue);
    }

    #[test]
    fn the_count_starts_afresh_at_each_loss_and_not_at_the_last_look() {
        let secs = Duration::from_secs;
        let mut w = LinkWatch::new(secs(0));
        w.observe(secs(10), true);
        // Looked at again and again while associated: none of it moves the count.
        for at in [50, 100, 150] {
            assert_eq!(w.observe(secs(at), true), LinkStep::Nothing);
        }
        w.observe(secs(200), false);
        assert_eq!(w.deadline(), Some(secs(290)));
    }

    #[test]
    fn the_lines_say_associated_the_first_time_and_after_how_long_the_next() {
        assert_eq!(associated_line(None), "wifi: associated");
        assert_eq!(
            associated_line(Some(Duration::from_millis(41_900))),
            "wifi: associated again after 41 s"
        );
        assert_eq!(LOST_LINE, "wifi: association lost");
    }

    #[test]
    fn the_time_away_in_the_second_line_is_counted_from_the_loss() {
        let secs = Duration::from_secs;
        let mut w = LinkWatch::new(secs(0));
        w.observe(secs(5), true);
        w.observe(secs(100), false);
        assert_eq!(w.away_for(secs(137)), Some(secs(37)));
        w.observe(secs(137), true);
        assert_eq!(w.away_for(secs(200)), None, "associated: not away");
    }

    #[test]
    fn only_a_joined_status_is_an_association() {
        let joined = WifiStatus::Joined {
            bssid: [0; 6],
            freq_mhz: 5180,
            signal_mbm: -5600,
        };
        assert!(is_associated(&joined));
        for status in [
            WifiStatus::Starting,
            WifiStatus::Scanning,
            WifiStatus::Joining {
                bssid: [0; 6],
                freq_mhz: 5180,
            },
            WifiStatus::Waiting { secs: 4 },
        ] {
            assert!(!is_associated(&status), "{status:?}");
        }
    }
}
