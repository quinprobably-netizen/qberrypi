//! The small values the panel shares with its caller: a time of day, the pause
//! switch, the blocked share and the lane's words. The caller fills them in;
//! the panel only reads them.

/// A time on the 24-hour clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeOfDay {
    /// The hour, 0 to 23.
    pub hour: u8,
    /// The minute, 0 to 59.
    pub minute: u8,
}

/// The pause switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Blocking {
    /// Blocked names are refused.
    #[default]
    On,
    /// Every name is answered until the pause runs out.
    Paused {
        /// Seconds until blocking turns on again.
        left_secs: u16,
    },
}

/// The share of today's queries that were blocked, as the panel says it.
///
/// It never rounds its way to a claim that is not true: `Zero` only when nothing was blocked, `All`
/// only when everything was, and `UnderOne` for a share that rounds to nothing though something was
/// blocked. Anything else is a whole percent from 1 to 99.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Share {
    /// Nothing was blocked: `0%`.
    Zero,
    /// Something was blocked, but less than half a percent of the queries: `<1%`.
    UnderOne,
    /// A whole percent, rounded to the nearest, from 1 to 99: `44%`.
    Percent(u8),
    /// Everything was blocked: `ALL`, since `100%` would run into the gate.
    All,
}

impl Share {
    /// The share that `blocked` is of `total` queries; `None` for no queries, which is no share at all.
    ///
    /// More blocked than asked cannot be, and is shown as all. The sums are wide enough that counters
    /// at the end of their range cannot overflow.
    pub fn of(blocked: u64, total: u64) -> Option<Self> {
        if total == 0 {
            return None;
        }
        if blocked == 0 {
            return Some(Self::Zero);
        }
        if blocked >= total {
            return Some(Self::All);
        }
        let share = (u128::from(blocked) * 100 + u128::from(total) / 2) / u128::from(total);
        Some(match u8::try_from(share) {
            Ok(0) => Self::UnderOne,
            // 99.5 and over rounds to 100, which only `All` may say.
            Ok(percent) => Self::Percent(percent.min(99)),
            Err(_) => Self::Percent(99),
        })
    }

    /// What the left column shows: `0%`, `<1%`, `44%` or `ALL`.
    pub fn text(self) -> String {
        match self {
            Self::Zero => "0%".to_string(),
            Self::UnderOne => "<1%".to_string(),
            Self::Percent(percent) => format!("{percent}%"),
            Self::All => "ALL".to_string(),
        }
    }
}

/// The words the lane says while it has no names to carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneWords {
    /// Wi-Fi is not joined: `JOINING WI-FI`.
    Joining,
    /// Joined, and no query has come yet: `LISTENING`.
    Listening,
    /// Queries came today, and none for a while: `QUIET 47 MIN`.
    Quiet {
        /// Whole minutes since the last name went by.
        minutes: u32,
    },
}

impl LaneWords {
    /// The words, in capitals, one per lane cell: `JOINING WI-FI`, `LISTENING`, `QUIET 47 MIN`, then
    /// `QUIET 3 H` from 2 hours and `QUIET 2 D` from 2 days. They never need more than the 15 cells
    /// right of the gate.
    pub fn text(self) -> String {
        match self {
            Self::Joining => "JOINING WI-FI".to_string(),
            Self::Listening => "LISTENING".to_string(),
            Self::Quiet { minutes } if minutes < 120 => format!("QUIET {minutes} MIN"),
            Self::Quiet { minutes } if minutes < 48 * 60 => {
                format!("QUIET {} H", minutes / 60)
            }
            Self::Quiet { minutes } => format!("QUIET {} D", minutes / (24 * 60)),
        }
    }

    /// Whether the words are white rather than `G2`: only `JOINING WI-FI` is, since it says something is wrong.
    pub fn is_white(self) -> bool {
        self == Self::Joining
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_switch_nobody_touched_is_blocking() {
        assert_eq!(Blocking::default(), Blocking::On);
    }

    #[test]
    fn share_forms() {
        let text = |blocked, total| Share::of(blocked, total).map(Share::text);
        assert_eq!(text(0, 0), None, "no queries, no share");
        assert_eq!(text(5, 0), None);
        assert_eq!(text(0, 10_818), Some("0%".to_string()));
        assert_eq!(text(0, 1), Some("0%".to_string()));
        assert_eq!(text(1, 1_000), Some("<1%".to_string()));
        assert_eq!(text(1, 201), Some("<1%".to_string()), "0.497 rounds to 0");
        assert_eq!(text(1, 200), Some("1%".to_string()), "0.5 rounds up");
        assert_eq!(text(4_780, 10_818), Some("44%".to_string()));
        assert_eq!(text(1, 3), Some("33%".to_string()));
        assert_eq!(text(2, 3), Some("67%".to_string()));
        assert_eq!(text(999, 1_000), Some("99%".to_string()), "never 100%");
        assert_eq!(text(995, 1_000), Some("99%".to_string()));
        assert_eq!(text(994, 1_000), Some("99%".to_string()));
        assert_eq!(text(1_000, 1_000), Some("ALL".to_string()));
        assert_eq!(text(3, 3), Some("ALL".to_string()));
        assert_eq!(text(1, 1), Some("ALL".to_string()));
        // More blocked than asked cannot be, and is not shown as more than all.
        assert_eq!(text(9, 5), Some("ALL".to_string()));
        // Counters at the end of their range.
        assert_eq!(text(u64::MAX, u64::MAX), Some("ALL".to_string()));
        assert_eq!(text(u64::MAX - 1, u64::MAX), Some("99%".to_string()));
        assert_eq!(text(1, u64::MAX), Some("<1%".to_string()));
        assert_eq!(text(u64::MAX / 2, u64::MAX), Some("50%".to_string()));
        assert_eq!(Share::of(0, u64::MAX), Some(Share::Zero));
        assert_eq!(Share::of(7, 10), Some(Share::Percent(70)));
    }

    #[test]
    fn lane_words_text() {
        let quiet = |minutes| LaneWords::Quiet { minutes }.text();
        assert_eq!(LaneWords::Joining.text(), "JOINING WI-FI");
        assert_eq!(LaneWords::Listening.text(), "LISTENING");
        assert_eq!(quiet(2), "QUIET 2 MIN");
        assert_eq!(quiet(47), "QUIET 47 MIN");
        assert_eq!(quiet(119), "QUIET 119 MIN");
        assert_eq!(quiet(120), "QUIET 2 H");
        assert_eq!(quiet(179), "QUIET 2 H", "whole hours");
        assert_eq!(quiet(180), "QUIET 3 H");
        assert_eq!(quiet(47 * 60 + 59), "QUIET 47 H");
        assert_eq!(quiet(48 * 60), "QUIET 2 D");
        assert_eq!(quiet(3 * 24 * 60 + 5), "QUIET 3 D");
        // The longest words fit the 15 cells right of the gate.
        assert_eq!(quiet(u32::MAX).chars().count(), 15);
        for words in [LaneWords::Joining, LaneWords::Listening] {
            assert!(words.text().chars().count() <= 15);
        }
        assert!(LaneWords::Joining.is_white());
        assert!(!LaneWords::Listening.is_white());
        assert!(!LaneWords::Quiet { minutes: 47 }.is_white());
    }
}
