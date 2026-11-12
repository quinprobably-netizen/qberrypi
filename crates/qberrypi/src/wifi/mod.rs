//! Joining a Wi-Fi network: which access point to try, how long to wait
//! between attempts, scanning, joining and holding the link over a radio,
//! the loop that does all of it for ever, and the small formatters the log
//! lines share.

use std::convert::Infallible;
use std::time::Duration;

use qb_wpa2::MacAddr;
use qb_wpa2::pmk::{Pmk, PmkError};
use tokio::time::{Instant, sleep};

use crate::config::{self, WifiKey};
use backoff::Backoff;
use join::{JoinCfg, JoinError, hold, join, scan};

pub mod backoff;
pub mod choose;
pub mod eapol;
#[cfg(test)]
pub(crate) mod fake;
pub mod ies;
pub mod join;
pub mod kernel;
pub mod radio;

/// How long a link has to hold to count as a success. One that is gone sooner counts as a failed attempt: its
/// access point goes to the back of the line, and the wait before the next attempt grows.
pub const STABLE_LINK: Duration = Duration::from_secs(30);

/// Where the Wi-Fi stands, for whoever shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WifiStatus {
    /// Nothing has been tried yet.
    Starting,
    /// A scan is running.
    Scanning,
    /// Associating with an access point and running the handshake.
    Joining { bssid: MacAddr, freq_mhz: u32 },
    /// The link is up.
    Joined {
        bssid: MacAddr,
        freq_mhz: u32,
        signal_mbm: i32,
    },
    /// The attempt failed; the next one is this many seconds away.
    Waiting { secs: u64 },
}

/// The key the configuration gives: the passphrase stretched with the network's name, or the key as written.
///
/// The error names the rule that was broken and never the secret.
pub fn derive_pmk(wifi: &config::Wifi) -> Result<Pmk, PmkError> {
    match &wifi.key {
        WifiKey::Passphrase(passphrase) => {
            Pmk::from_passphrase(passphrase.expose(), wifi.ssid.as_bytes())
        }
        WifiKey::Pmk(hex) => Pmk::from_hex(hex.expose()),
    }
}

/// What `run` needs of the configuration: the network's name and its key.
pub fn join_cfg(wifi: &config::Wifi) -> Result<JoinCfg, PmkError> {
    Ok(JoinCfg {
        ssid: wifi.ssid.as_bytes().to_vec(),
        pmk: derive_pmk(wifi)?,
    })
}

/// How one pass of the loop ended, without a link to hold any more.
enum Outcome {
    /// The link came up and went away again, after this long.
    Lost { bssid: MacAddr, held: Duration },
    /// No link was made; `tried` is the access point that was asked, if any was.
    Failed { tried: Option<MacAddr> },
}

/// Scans, joins and holds for ever: a failed handshake or a lost association is never final.
///
/// Every pass rescans. The access points that failed since the last stable link are tried after the others,
/// and when every one in sight has failed the list starts over. A pass that ended without a link of
/// `STABLE_LINK` is a failure: the first after a success is retried at once, the ones after it wait 1, 2, 4,
/// 8 and 16 s, then 30 s each. `report` hears every change of status. A link whose radio stops answering
/// is lost like any other, within a minute: `hold` probes the radio while it holds.
pub async fn run<R: radio::Radio>(
    radio: &mut R,
    cfg: &JoinCfg,
    report: &mut (dyn FnMut(WifiStatus) + Send),
) -> Infallible {
    let mut backoff = Backoff::default();
    let mut failed: Vec<MacAddr> = Vec::new();
    loop {
        match pass(radio, cfg, &mut failed, report).await {
            Outcome::Lost { held, .. } if held >= STABLE_LINK => {
                backoff.succeeded();
                failed.clear();
            }
            Outcome::Lost { bssid, .. } | Outcome::Failed { tried: Some(bssid) } => {
                if !failed.contains(&bssid) {
                    failed.push(bssid);
                }
            }
            Outcome::Failed { tried: None } => {}
        }
        let wait = backoff.failed();
        if !wait.is_zero() {
            report(WifiStatus::Waiting {
                secs: wait.as_secs(),
            });
            log::info!("wifi: next attempt in {} s", wait.as_secs());
            sleep(wait).await;
        }
    }
}

/// One scan, and the join and hold that follow it if the scan finds an access point to try.
async fn pass<R: radio::Radio>(
    radio: &mut R,
    cfg: &JoinCfg,
    failed: &mut Vec<MacAddr>,
    report: &mut (dyn FnMut(WifiStatus) + Send),
) -> Outcome {
    let began = Instant::now();
    report(WifiStatus::Scanning);
    let results = match scan(radio, &cfg.ssid).await {
        Ok(results) => results,
        Err(error) => return failure(&error, None),
    };
    let found = choose::survey(&results, &cfg.ssid, failed);
    // With every candidate failed the order among them is the one a fresh list gives: no second survey.
    if !found.candidates.is_empty() && found.candidates.iter().all(|c| failed.contains(&c.bssid)) {
        failed.clear();
    }
    log::info!(
        "wifi: scan found {} networks, {} with the configured name",
        found.seen,
        found.candidates.len() + found.skipped.len()
    );
    for candidate in &found.candidates {
        log::info!(
            "wifi: candidate {} {} MHz {}",
            mac(&candidate.bssid),
            candidate.freq_mhz,
            signal_text(candidate.signal_mbm)
        );
    }
    for (bssid, freq_mhz, reason) in &found.skipped {
        log::info!("wifi: skipping {} {freq_mhz} MHz: {reason}", mac(bssid));
    }
    let Some(candidate) = found.candidates.first() else {
        return failure(
            &JoinError::NoCandidate {
                seen: found.seen,
                out_of_scope: found.skipped.len(),
            },
            None,
        );
    };
    report(WifiStatus::Joining {
        bssid: candidate.bssid,
        freq_mhz: candidate.freq_mhz,
    });
    let mut link = match join(radio, cfg, candidate).await {
        Ok(link) => link,
        Err(error) => return failure(&error, Some(candidate.bssid)),
    };
    report(WifiStatus::Joined {
        bssid: link.bssid,
        freq_mhz: link.freq_mhz,
        signal_mbm: link.signal_mbm,
    });
    log::info!(
        "wifi: joined {} on {} MHz at {}, {} ms after the scan began",
        mac(&link.bssid),
        link.freq_mhz,
        signal_text(link.signal_mbm),
        began.elapsed().as_millis()
    );
    let joined = Instant::now();
    let lost = hold(radio, &mut link).await;
    log::warn!("wifi: link lost: {lost}");
    Outcome::Lost {
        bssid: link.bssid,
        held: joined.elapsed(),
    }
}

/// Logs a failed attempt, with the passphrase as a suspect when the handshake points at it.
fn failure(error: &JoinError, tried: Option<MacAddr>) -> Outcome {
    log::warn!("wifi: attempt failed: {error}");
    if error.passphrase_suspect() {
        log::warn!("wifi: the passphrase may be wrong");
    }
    Outcome::Failed { tried }
}

/// The address in the form the log shows: six lowercase hex pairs separated by colons.
pub fn mac(address: &MacAddr) -> String {
    let [a, b, c, d, e, f] = address;
    format!("{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}")
}

/// A signal strength in dBm from the kernel's 1/100 dBm, rounded toward zero.
pub fn dbm(signal_mbm: i32) -> i32 {
    signal_mbm / 100
}

/// A signal strength as the log shows it: `-56 dBm`, or `no signal` for the `i32::MIN` that a scan
/// result has when the kernel gave none (which `dbm` would turn into a figure no radio has).
fn signal_text(signal_mbm: i32) -> String {
    if signal_mbm == i32::MIN {
        "no signal".to_owned()
    } else {
        format!("{} dBm", dbm(signal_mbm))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::PoisonError;

    use super::*;
    use crate::netlink::nl80211::{Bss, Event};
    use crate::wifi::fake::reference::{AA, M1, M3, PMK, RSNE};
    use crate::wifi::fake::{
        Call, FakeRadio, ProbeAnswer, Step, cfg, connected, from_ap, joined_calls,
    };
    use crate::wifi::radio::RadioEvent;
    use hex_literal::hex;
    use qb_wpa2::pmk::Pmk;

    #[test]
    fn addresses_and_signals_are_formatted_for_the_log() {
        assert_eq!(mac(&hex!("a0a1a1a3a4a5")), "a0:a1:a1:a3:a4:a5");
        assert_eq!((dbm(-5600), dbm(-5650), dbm(0)), (-56, -56, 0));
        for (mbm, text) in [(-5600, "-56 dBm"), (-5650, "-56 dBm"), (0, "0 dBm")] {
            assert_eq!(signal_text(mbm), text);
        }
        // The kernel's "no signal" is the smallest number, and no figure of dBm.
        assert_eq!(signal_text(i32::MIN), "no signal");
        assert_eq!(signal_text(i32::MIN + 1), "-21474836 dBm");
    }

    /// A complete configuration shaped like `qberrypi.example.toml`, with `key` as the Wi-Fi secret's line.
    fn wifi_with(key: &str) -> config::Wifi {
        let text = format!(
            r#"hostname = "qberrypi"

[wifi]
ssid = "ThisIsASSID"
{key}
country = "US"

[net]
address = "192.0.2.53/24"
gateway = "192.0.2.1"

[dns]
upstreams = ["9.9.9.9", "149.112.112.112"]
lists = ["https://example.net/hosts"]
deny = []
allow = []
"#
        );
        config::parse(&text).unwrap().wifi
    }

    /// The log buffer every test in this binary shares. The log macros do nothing until a logger is
    /// installed, so a test that reads the log calls this before the code under test runs.
    fn logging() -> &'static std::sync::Mutex<crate::logbuf::LogBuf> {
        crate::logbuf::install(Box::new(std::io::sink()))
    }

    /// Everything the log holds.
    fn log_text() -> String {
        logging()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .text()
    }

    /// A scan result for a network called `ssid` that advertises `rsne`, heard at -56 dBm.
    fn bss(bssid: MacAddr, freq_mhz: u32, ssid: &[u8], rsne: &[u8]) -> Bss {
        let name = [&[0, u8::try_from(ssid.len()).unwrap()][..], ssid].concat();
        Bss {
            bssid,
            freq_mhz,
            signal_mbm: -5600,
            ies: [name, rsne.to_vec()].concat(),
        }
    }

    /// A radio whose every scan finds `results`.
    fn radio_seeing(results: Vec<Bss>) -> FakeRadio {
        let mut radio = FakeRadio::new();
        radio.results = results;
        radio
    }

    /// The reference access point, as a scan lists it.
    fn reference_bss() -> Bss {
        bss(AA, 5180, b"ThisIsASSID", &RSNE)
    }

    /// A step that returns a kernel event at once.
    fn nl(event: Event) -> Step {
        Step::Event(RadioEvent::Nl(event))
    }

    fn scan_done() -> Step {
        nl(Event::ScanDone)
    }

    /// The access point ends the link.
    fn ap_disconnects(reason: u16) -> RadioEvent {
        RadioEvent::Nl(Event::Disconnected {
            reason,
            by_ap: true,
        })
    }

    /// The access point refuses the association.
    fn refused() -> Step {
        nl(Event::ConnectFailed {
            status: 16,
            timed_out: false,
        })
    }

    /// The scan's end, then a join that runs the reference handshake to the end.
    fn join_script() -> [Step; 4] {
        [scan_done(), connected(), from_ap(&M1), from_ap(&M3)]
    }

    fn joining(bssid: MacAddr, freq_mhz: u32) -> WifiStatus {
        WifiStatus::Joining { bssid, freq_mhz }
    }

    fn joined(bssid: MacAddr, freq_mhz: u32) -> WifiStatus {
        WifiStatus::Joined {
            bssid,
            freq_mhz,
            signal_mbm: -5600,
        }
    }

    /// Runs `run` for `until` on tokio's paused clock, then cuts it: the radio, and every status reported.
    async fn drive(
        mut radio: FakeRadio,
        cfg: &JoinCfg,
        until: Duration,
    ) -> (FakeRadio, Vec<WifiStatus>) {
        let mut statuses = Vec::new();
        {
            let mut report = |status: WifiStatus| statuses.push(status);
            tokio::select! {
                never = run(&mut radio, cfg, &mut report) => match never {},
                () = tokio::time::sleep(until) => {}
            }
        }
        (radio, statuses)
    }

    /// The seconds, on the test's clock, at which a scan was started.
    fn scan_times(radio: &FakeRadio) -> Vec<u64> {
        radio
            .calls
            .iter()
            .filter(|(_, call)| *call == Call::TriggerScan)
            .map(|(at, _)| at.as_secs())
            .collect()
    }

    /// The access points the radio was asked to connect to, in order.
    fn connects(radio: &FakeRadio) -> Vec<MacAddr> {
        radio
            .calls
            .iter()
            .filter_map(|(_, call)| match call {
                Call::Connect { bssid, .. } => Some(*bssid),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn the_key_comes_from_the_configuration() {
        let wifi = wifi_with(r#"passphrase = "ThisIsAPassword""#);
        assert_eq!(derive_pmk(&wifi).unwrap().expose(), &PMK);
        let join = join_cfg(&wifi).unwrap();
        assert_eq!(join.ssid, b"ThisIsASSID");
        assert_eq!(join.pmk.expose(), &PMK);

        let wifi = wifi_with(
            r#"pmk = "0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af""#,
        );
        assert_eq!(derive_pmk(&wifi).unwrap().expose(), &PMK);
        assert_eq!(join_cfg(&wifi).unwrap().ssid, b"ThisIsASSID");
    }

    #[tokio::test(start_paused = true)]
    async fn joins_at_the_first_attempt_and_says_so() {
        let mut radio = radio_seeing(vec![reference_bss()]);
        radio.script.extend(join_script());
        let (radio, statuses) = drive(radio, &cfg(), Duration::from_secs(5)).await;
        assert_eq!(
            statuses,
            [WifiStatus::Scanning, joining(AA, 5180), joined(AA, 5180)]
        );
        assert_eq!(scan_times(&radio), [0]);
        let mut expected = vec![Call::TriggerScan, Call::ScanResults];
        expected.extend(joined_calls());
        assert_eq!(radio.commands(), expected);
    }

    #[tokio::test(start_paused = true)]
    async fn the_log_tells_what_was_seen_and_chosen() {
        logging();
        let other = [0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5];
        let mixed = hex!("30180100000fac020200000fac04000fac020100000fac020000");
        let mut radio = radio_seeing(vec![
            reference_bss(),
            bss(other, 2437, b"ThisIsASSID", &mixed),
            bss(other, 2412, b"another-network", &RSNE),
        ]);
        // The scan takes a quarter of a second.
        radio.script.extend([
            Step::After(Duration::from_millis(250), RadioEvent::Nl(Event::ScanDone)),
            connected(),
            from_ap(&M1),
            from_ap(&M3),
        ]);
        drive(radio, &cfg(), Duration::from_secs(1)).await;
        let log = log_text();
        for line in [
            "wifi: scan found 3 networks, 2 with the configured name",
            "wifi: candidate a0:a1:a1:a3:a4:a5 5180 MHz -56 dBm",
            "wifi: skipping b0:b1:b2:b3:b4:b5 2437 MHz: group cipher is not CCMP (mixed WPA/WPA2 network)",
            "wifi: joined a0:a1:a1:a3:a4:a5 on 5180 MHz at -56 dBm, 250 ms after the scan began",
        ] {
            assert!(log.contains(line), "missing {line:?} in\n{log}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_access_point_with_no_signal_is_logged_as_having_none() {
        logging();
        // A channel of its own, so that its lines are told from those of the other tests.
        let mut radio = radio_seeing(vec![Bss {
            signal_mbm: i32::MIN,
            ..bss(AA, 5240, b"ThisIsASSID", &RSNE)
        }]);
        radio.script.extend(join_script());
        drive(radio, &cfg(), Duration::from_secs(1)).await;
        let log = log_text();
        for line in [
            "wifi: candidate a0:a1:a1:a3:a4:a5 5240 MHz no signal\n",
            "wifi: joined a0:a1:a1:a3:a4:a5 on 5240 MHz at no signal, 0 ms after the scan began\n",
        ] {
            assert!(log.contains(line), "missing {line:?} in\n{log}");
        }
        assert!(!log.contains("-21474836"), "{log}");
    }

    // Review Focus 2.
    #[tokio::test(start_paused = true)]
    async fn failures_back_off_to_thirty_seconds_and_never_stop() {
        logging();
        let mut radio = FakeRadio::new();
        radio.script.extend((0..12).map(|_| scan_done()));
        let (radio, statuses) = drive(radio, &cfg(), Duration::from_secs(200)).await;
        assert_eq!(
            scan_times(&radio),
            [0, 0, 1, 3, 7, 15, 31, 61, 91, 121, 151, 181]
        );
        assert!(statuses.contains(&WifiStatus::Waiting { secs: 30 }));
        let waits: Vec<u64> = statuses
            .iter()
            .filter_map(|status| match status {
                WifiStatus::Waiting { secs } => Some(*secs),
                _ => None,
            })
            .collect();
        // One wait follows each of the scans but the first; the last begins at 181 s and ends at 211 s.
        assert_eq!(waits, [1, 2, 4, 8, 16, 30, 30, 30, 30, 30, 30]);
        let log = log_text();
        assert!(log.contains("wifi: next attempt in 30 s"), "{log}");
        assert!(
            log.contains("wifi: attempt failed: no access point to try: the scan saw 0, 0 of them"),
            "{log}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_link_that_held_is_rejoined_at_once() {
        logging();
        let mut radio = radio_seeing(vec![reference_bss()]);
        radio.script.extend(join_script());
        radio
            .script
            .push_back(Step::After(Duration::from_secs(40), ap_disconnects(4)));
        radio.script.extend(join_script());
        let (radio, statuses) = drive(radio, &cfg(), Duration::from_secs(60)).await;
        assert_eq!(scan_times(&radio), [0, 40]);
        assert_eq!(
            statuses,
            [
                WifiStatus::Scanning,
                joining(AA, 5180),
                joined(AA, 5180),
                WifiStatus::Scanning,
                joining(AA, 5180),
                joined(AA, 5180),
            ]
        );
        let log = log_text();
        assert!(
            log.contains("wifi: link lost: the link was ended by the access point, reason 4"),
            "{log}"
        );
    }

    // A firmware that dies while the link is up says nothing: the probes are what notice, and the loop
    // then goes the way it does for any lost link.
    #[tokio::test(start_paused = true)]
    async fn a_radio_that_stops_answering_loses_the_link_and_is_scanned_again() {
        logging();
        let mut radio = radio_seeing(vec![reference_bss()]);
        radio.script.extend(join_script());
        // Nothing comes from the radio until 125 s, which the hold does not mind and the next scan waits out;
        // then the second join, as the first.
        radio.script.push_back(Step::After(
            Duration::from_secs(125),
            RadioEvent::Nl(Event::Other(36)),
        ));
        radio.script.extend(join_script());
        radio.probe_after = Some((Duration::from_secs(100), ProbeAnswer::Fail));
        let (radio, statuses) = drive(radio, &cfg(), Duration::from_secs(130)).await;
        // Probes fail at 100, 110 and 120 s: the link is lost at 120 s, held for longer than the
        // stable time, so the rescan is at once, at 120 s.
        assert_eq!(scan_times(&radio), [0, 120]);
        assert_eq!(
            statuses,
            [
                WifiStatus::Scanning,
                joining(AA, 5180),
                joined(AA, 5180),
                WifiStatus::Scanning,
                joining(AA, 5180),
                joined(AA, 5180),
            ]
        );
        // The station left the network before the rescan.
        let commands = radio.commands();
        let leaving = commands
            .iter()
            .position(|call| *call == Call::Disconnect(3))
            .expect("the station left");
        assert_eq!(commands[leaving + 1], Call::TriggerScan);
        let log = log_text();
        assert!(
            log.contains("wifi: link lost: the radio stopped answering: no answer from the kernel"),
            "{log}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_link_that_drops_early_counts_as_a_failure() {
        let mut radio = radio_seeing(vec![reference_bss()]);
        for _ in 0..3 {
            radio.script.extend(join_script());
            radio
                .script
                .push_back(Step::After(Duration::from_secs(5), ap_disconnects(2)));
        }
        let (radio, statuses) = drive(radio, &cfg(), Duration::from_secs(30)).await;
        // The first loss is at 5 s, the second at 10 s, the third at 16 s: no wait after the first, 1 s after the
        // second, 2 s after the third, whose rescan at 18 s finds the script used up.
        assert_eq!(scan_times(&radio), [0, 5, 11, 18]);
        let waits: Vec<u64> = statuses
            .iter()
            .filter_map(|status| match status {
                WifiStatus::Waiting { secs } => Some(*secs),
                _ => None,
            })
            .collect();
        assert_eq!(waits, [1, 2]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stable_link_forgives_the_failures_before_it() {
        // The reference access point is the one that works, on 2.4 GHz; the other, on 5 GHz, refuses.
        let better = [0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5];
        let mut radio = radio_seeing(vec![
            bss(AA, 2437, b"ThisIsASSID", &RSNE),
            bss(better, 5180, b"ThisIsASSID", &RSNE),
        ]);
        radio.script.extend([scan_done(), refused()]);
        radio.script.extend(join_script());
        radio
            .script
            .push_back(Step::After(Duration::from_secs(40), ap_disconnects(4)));
        radio.script.extend([scan_done(), refused(), scan_done()]);
        let (radio, _) = drive(radio, &cfg(), Duration::from_secs(45)).await;
        // The refusal of the better one sends the next attempt to the other, which holds for 40 s. That
        // forgets the refusal and the failures, so the better one is first again. The loss of the link was
        // the first failure of a new run and the refusal after it is the second, so one second passes before
        // the attempt that goes to the other again: it was 1 + 2 s, had the earlier failures counted.
        assert_eq!(connects(&radio), [better, AA, better, AA]);
        assert_eq!(scan_times(&radio), [0, 0, 40, 41]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_bss_that_failed_is_tried_after_the_other() {
        let a = AA;
        let b = [0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5];
        let mut radio = radio_seeing(vec![
            bss(a, 5180, b"ThisIsASSID", &RSNE),
            bss(b, 2437, b"ThisIsASSID", &RSNE),
        ]);
        for _ in 0..4 {
            radio.script.extend([scan_done(), refused()]);
        }
        let (radio, _) = drive(radio, &cfg(), Duration::from_secs(5)).await;
        // The attempts fall at 0, 0, 1 and 3 s. A is first on 5 GHz; B goes ahead of the failed A; with both
        // failed the list is cleared and the order is by band again, so A is first; then only A has failed
        // since the clearing, and B goes ahead of it. Without the clearing the third and fourth would both be A.
        assert_eq!(connects(&radio), [a, b, a, b]);
        assert_eq!(scan_times(&radio), [0, 0, 1, 3]);
    }

    // Review Focus 3.
    #[tokio::test(start_paused = true)]
    async fn a_network_out_of_scope_is_never_tried() {
        logging();
        let mixed = hex!("30180100000fac020200000fac04000fac020100000fac020000");
        let out_of_scope = [0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb6];
        let mut radio = radio_seeing(vec![bss(out_of_scope, 2462, b"ThisIsASSID", &mixed)]);
        radio.script.extend([scan_done(), scan_done()]);
        let (radio, statuses) = drive(radio, &cfg(), Duration::from_secs(3)).await;
        assert!(connects(&radio).is_empty());
        assert_eq!(
            statuses,
            [
                WifiStatus::Scanning,
                WifiStatus::Scanning,
                WifiStatus::Waiting { secs: 1 },
                WifiStatus::Scanning,
            ]
        );
        let log = log_text();
        for line in [
            "wifi: skipping b0:b1:b2:b3:b4:b6 2462 MHz: group cipher is not CCMP (mixed WPA/WPA2 network)",
            "wifi: attempt failed: no access point to try: the scan saw 1, 1 of them",
        ] {
            assert!(log.contains(line), "missing {line:?} in\n{log}");
        }
    }

    // Review Focus 2.
    #[tokio::test(start_paused = true)]
    async fn a_wrong_passphrase_is_said_and_retried() {
        logging();
        let wrong = JoinCfg {
            pmk: Pmk::from_bytes([0x11; 32]),
            ..cfg()
        };
        let mut radio = radio_seeing(vec![reference_bss()]);
        for _ in 0..2 {
            radio
                .script
                .extend([scan_done(), connected(), from_ap(&M1)]);
            radio.script.push_back(nl(Event::Disconnected {
                reason: 15,
                by_ap: true,
            }));
        }
        let (radio, _) = drive(radio, &wrong, Duration::from_secs(5)).await;
        assert_eq!(connects(&radio), [AA, AA]);
        let log = log_text();
        assert!(log.contains("wifi: the passphrase may be wrong"), "{log}");
    }

    /// A fake radio behind the mute switch, as the kernel radio is: a probe asks the switch first, and
    /// is not sent to the radio when the switch fails it; a connect tells the switch that the hold
    /// before it is over. The fake itself is as it was.
    struct Gated<'a> {
        radio: FakeRadio,
        mute: &'a crate::fault::Mute,
    }

    impl radio::Radio for Gated<'_> {
        fn station(&self) -> MacAddr {
            self.radio.station()
        }

        fn nonce(&mut self) -> Result<qb_wpa2::Nonce, radio::RadioError> {
            self.radio.nonce()
        }

        async fn trigger_scan(&mut self, ssid: &[u8]) -> Result<(), radio::RadioError> {
            self.radio.trigger_scan(ssid).await
        }

        async fn scan_results(&mut self) -> Result<Vec<Bss>, radio::RadioError> {
            self.radio.scan_results().await
        }

        async fn connect(
            &mut self,
            ssid: &[u8],
            candidate: &choose::Candidate,
        ) -> Result<(), radio::RadioError> {
            self.mute.hold_over();
            self.radio.connect(ssid, candidate).await
        }

        async fn probe(&mut self, peer: MacAddr) -> Result<(), radio::RadioError> {
            self.mute.probe()?;
            self.radio.probe(peer).await
        }

        async fn disconnect(&mut self, reason: u16) -> Result<(), radio::RadioError> {
            self.radio.disconnect(reason).await
        }

        async fn next_event(&mut self) -> Result<RadioEvent, radio::RadioError> {
            self.radio.next_event().await
        }

        fn send_frame(&mut self, frame: &[u8]) -> Result<(), radio::RadioError> {
            self.radio.send_frame(frame)
        }

        async fn install_pairwise(
            &mut self,
            peer: MacAddr,
            tk: &qb_wpa2::secret::SecretBytes<16>,
        ) -> Result<(), radio::RadioError> {
            self.radio.install_pairwise(peer, tk).await
        }

        async fn install_group(
            &mut self,
            key: &qb_wpa2::supplicant::GroupKey,
        ) -> Result<(), radio::RadioError> {
            self.radio.install_group(key).await
        }

        async fn authorize(&mut self, peer: MacAddr) -> Result<(), radio::RadioError> {
            self.radio.authorize(peer).await
        }
    }

    // The `mute-probe` fault: armed at 65 s into a hold, the probes at 70, 80 and 90 s fail without a command
    // being sent, the hold ends as for a radio that died, the board scans and joins again, and the probes of
    // that hold are answered: the switch was for one hold.
    #[tokio::test(start_paused = true)]
    async fn a_muted_probe_ends_one_hold_and_the_next_hold_is_probed_as_usual() {
        use crate::fault::{MUTE_AFTER, Mute, arm_after};
        logging();
        let mute = Mute::new();
        let mut radio = Gated {
            radio: radio_seeing(vec![reference_bss()]),
            mute: &mute,
        };
        radio.radio.script.extend(join_script());
        // Nothing comes until 100 s, a little after the hold ends, which the next scan waits out; then the
        // second join, as the first, and silence.
        radio.radio.script.push_back(Step::After(
            Duration::from_secs(100),
            RadioEvent::Nl(Event::Other(36)),
        ));
        radio.radio.script.extend(join_script());

        let mut statuses = Vec::new();
        {
            let mut report = |status: WifiStatus| statuses.push(status);
            let armed_at = MUTE_AFTER + Duration::from_secs(5);
            let cfg = cfg();
            tokio::select! {
                never = run(&mut radio, &cfg, &mut report) => match never {},
                ended = arm_after(&mute, armed_at) => panic!("the arming ended: {ended:?}"),
                () = tokio::time::sleep(Duration::from_secs(195)) => {}
            }
        }

        // Lost at 90 s; the second join at 100 s, probed at 110 s, 120 s and so on to 190 s.
        assert_eq!(
            statuses,
            [
                WifiStatus::Scanning,
                joining(AA, 5180),
                joined(AA, 5180),
                WifiStatus::Scanning,
                joining(AA, 5180),
                joined(AA, 5180),
            ]
        );
        let probes: Vec<u64> = radio
            .radio
            .probe_times()
            .iter()
            .map(Duration::as_secs)
            .collect();
        // The radio was asked at 10 to 60 s, not at 70, 80 and 90 s (muted: no command went out), and again
        // from 110 s on.
        assert_eq!(
            probes,
            [
                10, 20, 30, 40, 50, 60, 110, 120, 130, 140, 150, 160, 170, 180, 190
            ]
        );
        let log = log_text();
        for line in [
            "wifi: the radio did not answer a probe (1 of 3): no answer (fault: mute-probe)",
            "wifi: the radio did not answer a probe (3 of 3): no answer (fault: mute-probe)",
            "wifi: link lost: the radio stopped answering: no answer (fault: mute-probe)",
        ] {
            assert!(log.contains(line), "missing {line:?} in\n{log}");
        }
        // The one-shot is spent: nothing mutes the hold that is on.
        assert!(mute.probe().is_ok());
    }
}
