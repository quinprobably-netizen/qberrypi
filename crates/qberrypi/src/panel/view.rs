//! Turning what the system knows into what the panel shows.

use qb_panel::drain::Stills;
use qb_panel::format::{alert_card, gate_fill};
use qb_panel::{Blocking, LaneWords, Share, TimeOfDay};

use super::alerts::{PanelAlert, Severity};
use crate::live::Snapshot;

/// The time of day at `unix_secs` in a zone `utc_offset_secs` seconds from UTC.
pub fn time_of_day(unix_secs: u64, utc_offset_secs: i32) -> TimeOfDay {
    // Wide enough that an offset before the epoch cannot underflow.
    let local = i128::from(unix_secs) + i128::from(utc_offset_secs);
    let secs_of_day = local.rem_euclid(86_400) as u32;
    TimeOfDay {
        hour: (secs_of_day / 3_600) as u8,
        minute: (secs_of_day % 3_600 / 60) as u8,
    }
}

/// Holds a counter to what the panel can show.
fn held(count: u64) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

/// What the key shows when `paused_left` seconds of a pause are left, or blocking is on.
pub fn blocking(paused_left: Option<u16>) -> Blocking {
    paused_left.map_or(Blocking::On, |left_secs| Blocking::Paused { left_secs })
}

/// How the gate's refill shows when `paused_left` seconds of a pause are left: steps of 12 pixels, none
/// while blocking is on.
pub fn refill(paused_left: Option<u16>) -> u8 {
    paused_left.map_or(0, gate_fill)
}

/// Whether the board is associated with its access point, as far as anything knows.
fn joined(snapshot: &Snapshot) -> bool {
    snapshot.wifi.as_ref().is_some_and(|wifi| wifi.associated)
}

/// How long without a name on the lane makes the lane say it is quiet, in seconds.
pub const QUIET_AFTER_SECS: u64 = 120;

/// The minutes of quiet that the lane's words show for `idle_secs` seconds without a lane name, rounded
/// down to the unit the words are written in: whole minutes below two hours, whole hours below 48
/// hours, whole days beyond. The words (`QUIET 47 MIN`, `QUIET 3 H`, `QUIET 2 D`) then change only when
/// their text does, so a still is spent on them no more often than that.
fn quiet_minutes(idle_secs: u64) -> u32 {
    const HOUR: u32 = 60;
    const DAY: u32 = 24 * HOUR;
    // Past what a `u32` of minutes holds, the figure is held there: the text is the same.
    let minutes = u32::try_from(idle_secs / 60).unwrap_or(u32::MAX);
    match minutes {
        0..120 => minutes,
        120..2880 => minutes / HOUR * HOUR,
        _ => minutes / DAY * DAY,
    }
}

/// The words the lane says while it has nothing to carry, for a snapshot that has been `idle_secs`
/// seconds without a lane name.
///
/// `JOINING WI-FI` until the Wi-Fi is joined, again after a drop; then `LISTENING` until the resolver
/// has answered a query today; then, once queries have come, `QUIET n MIN` after two minutes without a
/// name (minutes, then hours, then days, as `LaneWords` says, and rounded down to that unit). Otherwise
/// none: names are going by.
fn words(snapshot: &Snapshot, idle_secs: u64) -> Option<LaneWords> {
    if !joined(snapshot) {
        return Some(LaneWords::Joining);
    }
    match snapshot.today {
        None => Some(LaneWords::Listening),
        Some(today) if today.queries == 0 => Some(LaneWords::Listening),
        Some(_) if idle_secs >= QUIET_AFTER_SECS => Some(LaneWords::Quiet {
            minutes: quiet_minutes(idle_secs),
        }),
        Some(_) => None,
    }
}

/// The slow figures of the panel for a snapshot: what the screen is to come to show, one region at a time.
///
/// `paused_left` is the seconds of a pause that are left, `now_unix` is the clock in Unix seconds,
/// `idle_secs` is how long ago the panel last took a name from the lane's feed, and `alert` is the
/// alert to take the screen over, if there is one.
///
/// Whatever is not known is not shown: no percentage while the resolver has not answered anything,
/// and no time of day until the clock is set. While the Wi-Fi is not joined the percentage and the
/// count are dashes whatever the counters hold, and the lane says so. The count is the snapshot's
/// figure of blocked queries; the panel's loop replaces it with the Drain's own count, which holds
/// back the names still on their way. Nothing here keeps a name or a subject past the `Stills` it
/// returns.
pub fn wanted_stills(
    snapshot: &Snapshot,
    paused_left: Option<u16>,
    now_unix: u64,
    idle_secs: u64,
    alert: Option<&PanelAlert>,
) -> Stills {
    let today = snapshot.today.filter(|_| joined(snapshot));
    Stills {
        percent: today.and_then(|today| Share::of(today.blocked, today.queries)),
        clock: snapshot
            .clock_set
            .then(|| time_of_day(now_unix, snapshot.utc_offset_secs)),
        blocking: blocking(paused_left),
        gate_fill: refill(paused_left),
        count: today.map(|today| held(today.blocked)),
        alert: alert.map(|alert| {
            alert_card(
                &alert.kind,
                alert.severity == Severity::High,
                &alert.subject,
                alert.client,
            )
        }),
        words: words(snapshot, idle_secs),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::net::{IpAddr, Ipv4Addr};

    use crate::live::{Counts, LastBlocked, WifiStatus};
    use qb_panel::Blocking;

    /// A Unix time that is midnight at UTC.
    pub(crate) const MIDNIGHT_UTC: u64 = 1_799_971_200;

    /// 10:20 in the morning at UTC, the reference clock.
    pub(crate) const TEN_TWENTY_UTC: u64 = MIDNIGHT_UTC + 37_200;

    /// A Wi-Fi link that is up.
    fn up() -> Option<WifiStatus> {
        Some(WifiStatus {
            associated: true,
            signal_dbm: Some(-63),
            ap: None,
        })
    }

    /// A snapshot of a joined board whose resolver has counted `blocked` of `queries` today.
    fn counted(blocked: u64, queries: u64) -> Snapshot {
        Snapshot {
            wifi: up(),
            today: Some(Counts {
                queries,
                blocked,
                blocked_threat: 0,
                cache_hits: 0,
                forwarded: 0,
            }),
            ..Snapshot::default()
        }
    }

    /// The readings the reference stills show: 44% refused, and 10:20.
    pub(crate) fn reference_snapshot() -> Snapshot {
        Snapshot {
            last_blocked: Some(LastBlocked {
                name: "tracking-intake.logs.example.com".into(),
                unix_secs: TEN_TWENTY_UTC,
                count_24h: 4_419,
            }),
            upstream_ms: Some(8),
            clock_set: true,
            ..counted(4_780, 10_818)
        }
    }

    fn alert(kind: &str, severity: Severity) -> PanelAlert {
        PanelAlert {
            id: 7,
            kind: kind.into(),
            severity,
            client: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 23))),
            subject: "secure-login-verify.example.org".into(),
        }
    }

    /// The stills for `snapshot` with blocking on, no alert, and a lane that has just seen a name.
    fn stills_of(snapshot: &Snapshot) -> Stills {
        wanted_stills(snapshot, None, TEN_TWENTY_UTC, 0, None)
    }

    #[test]
    fn the_reference_readings_give_44_percent_and_ten_twenty() {
        let wanted = stills_of(&reference_snapshot());
        assert_eq!(wanted.percent, Some(Share::Percent(44)));
        assert_eq!(
            wanted.clock,
            Some(TimeOfDay {
                hour: 10,
                minute: 20
            })
        );
        assert_eq!(wanted.blocking, Blocking::On);
        assert_eq!(wanted.gate_fill, 0);
        assert_eq!(wanted.count, Some(4_780));
        assert!(wanted.alert.is_none());
        assert_eq!(wanted.words, None, "names are going by");
    }

    #[test]
    fn nothing_known_gives_the_stills_of_dashes_and_the_joining_words() {
        // The Wi-Fi is the first thing to be known: until it is, every figure is a dash and the lane says why.
        assert_eq!(
            stills_of(&Snapshot::default()),
            Stills {
                words: Some(LaneWords::Joining),
                ..Stills::default()
            }
        );
    }

    #[test]
    fn nothing_counted_is_never_shown_while_the_wifi_is_not_joined() {
        // The counters of a board whose link is down or not yet up are not shown, joined or never known.
        let counters = Snapshot {
            wifi: None,
            ..reference_snapshot()
        };
        let dropped = Snapshot {
            wifi: Some(WifiStatus {
                associated: false,
                ..WifiStatus::default()
            }),
            ..reference_snapshot()
        };
        for snapshot in [counters, dropped] {
            let wanted = stills_of(&snapshot);
            assert_eq!(
                (wanted.percent, wanted.count, wanted.words),
                (None, None, Some(LaneWords::Joining))
            );
            // The clock follows its own flag.
            assert!(wanted.clock.is_some());
            // The words stay joining however long the lane has been quiet.
            assert_eq!(
                wanted_stills(&snapshot, None, TEN_TWENTY_UTC, 100_000, None).words,
                Some(LaneWords::Joining)
            );
        }
    }

    #[test]
    fn a_joined_board_with_no_query_yet_is_listening_with_a_true_zero() {
        let listening = Some(LaneWords::Listening);
        let wanted = stills_of(&counted(0, 0));
        assert_eq!(
            (wanted.percent, wanted.count, wanted.words),
            (None, Some(0), listening)
        );
        // The resolver has not said anything about today: still listening, with the count a dash.
        let unknown = stills_of(&Snapshot {
            wifi: up(),
            ..Snapshot::default()
        });
        assert_eq!(
            (unknown.percent, unknown.count, unknown.words),
            (None, None, listening)
        );
        // However long ago a name was seen: nothing has come today.
        let long = wanted_stills(&counted(0, 0), None, TEN_TWENTY_UTC, 100_000, None);
        assert_eq!(long.words, listening);
    }

    #[test]
    fn quiet_words_follow_the_idle_time_in_minutes_hours_and_days() {
        let words = |idle_secs| {
            wanted_stills(&reference_snapshot(), None, TEN_TWENTY_UTC, idle_secs, None)
                .words
                .map(LaneWords::text)
        };
        assert_eq!(words(0), None);
        assert_eq!(words(119), None, "two minutes, not one second less");
        assert_eq!(words(120).as_deref(), Some("QUIET 2 MIN"));
        assert_eq!(words(179).as_deref(), Some("QUIET 2 MIN"));
        assert_eq!(words(47 * 60 + 59).as_deref(), Some("QUIET 47 MIN"));
        assert_eq!(words(119 * 60).as_deref(), Some("QUIET 119 MIN"));
        assert_eq!(words(2 * 3_600).as_deref(), Some("QUIET 2 H"));
        assert_eq!(words(3 * 3_600 + 59).as_deref(), Some("QUIET 3 H"));
        assert_eq!(words(47 * 3_600 + 3_599).as_deref(), Some("QUIET 47 H"));
        assert_eq!(words(48 * 3_600).as_deref(), Some("QUIET 2 D"));
        assert_eq!(words(9 * 86_400 + 5).as_deref(), Some("QUIET 9 D"));
        // Idle for longer than a clock can count: no panic, and the words still fit their 15 cells.
        let longest = words(u64::MAX).unwrap();
        assert_eq!(longest.chars().count(), 15, "{longest}");
    }

    #[test]
    fn quiet_words_change_only_when_their_text_does() {
        let words = |idle_secs| {
            wanted_stills(&reference_snapshot(), None, TEN_TWENTY_UTC, idle_secs, None).words
        };
        let minutes = |idle_secs| match words(idle_secs) {
            Some(LaneWords::Quiet { minutes }) => minutes,
            other => panic!("{other:?}"),
        };
        // Whole hours, then whole days: the figure holds for the whole hour or day.
        assert_eq!(minutes(2 * 3_600), 120);
        assert_eq!(minutes(2 * 3_600 + 59 * 60 + 59), 120);
        assert_eq!(minutes(3 * 3_600), 180);
        assert_eq!(minutes(47 * 3_600 + 3_599), 47 * 60);
        assert_eq!(minutes(48 * 3_600), 2 * 24 * 60);
        assert_eq!(minutes(71 * 3_600 + 3_599), 2 * 24 * 60);
        assert_eq!(minutes(72 * 3_600), 3 * 24 * 60);
        // Whole minutes below two hours still tick over every minute.
        assert_eq!(minutes(120), 2);
        assert_eq!(minutes(179), 2);
        assert_eq!(minutes(180), 3);
        assert_eq!(minutes(119 * 60 + 59), 119);
        // Over the first four days, the still changes exactly when the text does.
        let (mut at, mut previous) = (QUIET_AFTER_SECS, words(QUIET_AFTER_SECS));
        let mut changes = 0;
        while at + 13 < 4 * 86_400 {
            at += 13;
            let now = words(at);
            let text = |words: Option<LaneWords>| words.map(LaneWords::text);
            assert_eq!(now == previous, text(now) == text(previous), "at {at} s");
            changes += usize::from(now != previous);
            previous = now;
        }
        // 2 MIN to 119 MIN is 117 changes, then 2 H (1), 3 H to 47 H (45), 2 D (1) and 3 D (1).
        assert_eq!(
            changes,
            117 + 1 + 45 + 1 + 1,
            "one still per change of text"
        );
    }

    #[test]
    fn the_percent_forms_reach_the_screen() {
        let of = |blocked, queries| stills_of(&counted(blocked, queries)).percent;
        let text = |blocked, queries| of(blocked, queries).map(Share::text);
        // No queries is no share: a dash. Nothing blocked is a true 0%.
        assert_eq!(text(0, 0), None);
        assert_eq!(text(0, 3).as_deref(), Some("0%"));
        // Something blocked that rounds to nothing is under one, not zero.
        assert_eq!(text(1, 1_000).as_deref(), Some("<1%"));
        assert_eq!(text(1, 201).as_deref(), Some("<1%"));
        assert_eq!(text(1, 200).as_deref(), Some("1%"));
        assert_eq!(text(4_780, 10_818).as_deref(), Some("44%"));
        // Never 100% unless it is all of them, and then it says ALL.
        assert_eq!(text(999, 1_000).as_deref(), Some("99%"));
        assert_eq!(text(5, 5).as_deref(), Some("ALL"));
        // More blocked than asked cannot be, but is not shown as more than all.
        assert_eq!(text(9, 5).as_deref(), Some("ALL"));
        assert_eq!(of(u64::MAX, u64::MAX), Some(Share::All));
        assert_eq!(of(0, u64::MAX), Some(Share::Zero));
        // No form of the share without the link.
        let dropped = Snapshot {
            wifi: None,
            ..counted(5, 5)
        };
        assert_eq!(stills_of(&dropped).percent, None);
    }

    #[test]
    fn the_share_rounds_to_the_nearest_and_never_says_more_than_the_truth() {
        let of = |blocked, queries| stills_of(&counted(blocked, queries)).percent;
        assert_eq!(of(0, 3), Some(Share::Zero));
        assert_eq!(of(1, 3), Some(Share::Percent(33)));
        assert_eq!(of(2, 3), Some(Share::Percent(67)));
        assert_eq!(of(1, 200), Some(Share::Percent(1)));
        assert_eq!(of(1, 201), Some(Share::UnderOne));
        assert_eq!(of(999, 1_000), Some(Share::Percent(99)));
        assert_eq!(of(5, 5), Some(Share::All));
        assert_eq!(of(9, 5), Some(Share::All));
        assert_eq!(of(u64::MAX, u64::MAX), Some(Share::All));
    }

    #[test]
    fn the_gate_refills_with_the_pause_running_out_and_not_otherwise() {
        let fill = |left| wanted_stills(&reference_snapshot(), left, 0, 0, None).gate_fill;
        assert_eq!(fill(None), 0, "blocking is on");
        assert_eq!(fill(Some(300)), 0);
        assert_eq!(fill(Some(285)), 0);
        assert_eq!(fill(Some(277)), 1, "the mockup's 4:37");
        assert_eq!(fill(Some(150)), 9);
        assert_eq!(fill(Some(1)), 18);
        assert_eq!(fill(Some(0)), 18);
        assert_eq!(fill(Some(u16::MAX)), 0);
        // The refill is the same figure the loop gives the gate between two snapshots.
        assert_eq!(refill(Some(277)), 1);
        assert_eq!(refill(None), 0);
    }

    #[test]
    fn the_time_is_local_and_unknown_until_the_clock_is_set() {
        let unset = stills_of(&Snapshot {
            clock_set: false,
            ..reference_snapshot()
        });
        assert_eq!(unset.clock, None);
        let west = stills_of(&Snapshot {
            utc_offset_secs: -18_000,
            ..reference_snapshot()
        });
        assert_eq!(
            west.clock,
            Some(TimeOfDay {
                hour: 5,
                minute: 20
            })
        );
        // No underflow at the epoch.
        assert_eq!(
            time_of_day(0, -3_600),
            TimeOfDay {
                hour: 23,
                minute: 0
            }
        );
    }

    #[test]
    fn counters_past_the_panels_range_stop_at_its_end_and_a_pause_shows_its_seconds() {
        let huge = counted(u64::MAX, u64::MAX);
        let wanted = wanted_stills(&huge, Some(299), 0, 0, None);
        assert_eq!(
            (wanted.count, wanted.percent, wanted.blocking),
            (
                Some(u32::MAX),
                Some(Share::All),
                Blocking::Paused { left_secs: 299 }
            )
        );
    }

    #[test]
    fn an_alert_is_a_white_card_only_when_it_is_high() {
        let at = |severity| {
            wanted_stills(
                &Snapshot::default(),
                None,
                0,
                0,
                Some(&alert("threat", severity)),
            )
            .alert
            .unwrap()
        };
        let high = at(Severity::High);
        assert!(high.high);
        assert_eq!(high.title, ["THREAT", "BLOCKED"]);
        // The subject breaks after a dot, on two lines of at most 26 cells.
        assert_eq!(high.subject, ["secure-login-verify.", "example.org"]);
        assert_eq!(high.who, "asked by 192.0.2.23");
        assert!(!at(Severity::Warn).high);
        assert!(!at(Severity::Info).high);
        let device = wanted_stills(
            &Snapshot::default(),
            None,
            0,
            0,
            Some(&alert("new_device", Severity::Warn)),
        )
        .alert
        .unwrap();
        assert_eq!(
            (device.title[0].as_str(), device.who.as_str()),
            ("NEW", "at 192.0.2.23")
        );
    }
}
