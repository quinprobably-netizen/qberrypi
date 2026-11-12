//! A scripted radio for the tests of the Wi-Fi logic, and the access point's
//! side of the IEEE reference handshake to run it against.
//!
//! The radio answers commands at once and takes its events from a script, on
//! tokio's clock: a test runs under `#[tokio::test(start_paused = true)]`, and
//! the clock moves only when every task waits. Its answer to a liveness probe is
//! `Ok` unless a test scripts another (see [`ProbeAnswer`]).

// At the top level of this file: a `#[path]` inside an inline module would resolve elsewhere.
#[path = "../../../qb-wpa2/tests/fixtures/authenticator.rs"]
pub mod authenticator;
#[path = "../../../qb-wpa2/tests/fixtures/reference.rs"]
pub mod reference;

use std::collections::VecDeque;
use std::time::Duration;

use hex_literal::hex;
use qb_wpa2::pmk::Pmk;
use qb_wpa2::rsne::SUPPLICANT_RSNE;
use qb_wpa2::secret::SecretBytes;
use qb_wpa2::supplicant::GroupKey;
use qb_wpa2::{MacAddr, Nonce};
use tokio::time::{Instant, sleep, sleep_until, timeout};

use super::choose::Candidate;
use super::eapol::{ETHERTYPE_PAE, build};
use super::join::JoinCfg;
use super::radio::{Radio, RadioError, RadioEvent};
use crate::netlink::nl80211::{Bss, Event};
use crate::netlink::{NlError, REPLY_TIMEOUT, RequestError};
use reference::{AA, GTK1, M2, M4, RSNE, SNONCE, SPA, TK};

/// What the fake's `next_event` does next.
pub enum Step {
    /// Returns the event at once.
    Event(RadioEvent),
    /// Returns the event after this long on tokio's clock; the step is used up only when it returns.
    After(Duration, RadioEvent),
    /// Used up at once; then `next_event` never returns.
    Silence,
}

/// How the fake answers a liveness probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeAnswer {
    /// The station message of the access point, at once.
    Ok,
    /// No answer from the firmware: the request times out at once (the real radio's, after its bound).
    Fail,
    /// The answer comes after this long on tokio's clock, if that is within the bound; later, it is a timeout.
    Slow(Duration),
    /// The firmware never answers: the probe returns the timeout error only when the bound, as long as the
    /// real radio's, has passed.
    Hang,
}

/// How long a command of the real radio may take at most: the send and the reply each wait up to
/// the netlink reply timeout. The fake's `Slow` and `Hang` probes are cut at the same bound.
pub const PROBE_BOUND: Duration = Duration::from_secs(2 * REPLY_TIMEOUT.as_secs());

/// A command the fake was given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    TriggerScan,
    ScanResults,
    Connect {
        bssid: MacAddr,
        freq_mhz: u32,
    },
    Disconnect(u16),
    SendFrame(Vec<u8>),
    InstallPairwise {
        peer: MacAddr,
        tk: [u8; 16],
    },
    InstallGroup {
        key_id: u8,
        key: [u8; 16],
        rsc: [u8; 6],
    },
    Authorize(MacAddr),
    /// A liveness probe of the access point. `commands` leaves these out: a hold makes them on its own
    /// clock, and a test of the handshake's commands is not about them. `probe_times` has them.
    Probe(MacAddr),
}

pub struct FakeRadio {
    pub station: MacAddr,
    pub nonce: Nonce,
    /// What `next_event` returns, in order.
    pub script: VecDeque<Step>,
    /// What `scan_results` returns: every access point of it, or only those on the channels that the last
    /// `trigger_scan` was limited to, as a radio that scans just those channels hears just those.
    pub results: Vec<Bss>,
    /// The frequencies each `trigger_scan` was limited to, in order; an empty list is a scan of every channel.
    pub scan_freqs: Vec<Vec<u32>>,
    /// Returned by the next `trigger_scan` calls, one each.
    pub trigger_errors: VecDeque<RadioError>,
    /// `connect` returns an error.
    pub fail_connect: bool,
    /// `install_pairwise` returns an error.
    pub fail_install: bool,
    /// `install_group` returns an error.
    pub fail_install_group: bool,
    /// What the next probes answer, one each, before `probe_after` and the default `Ok` apply.
    pub probe_answers: VecDeque<ProbeAnswer>,
    /// From this moment on (the time on tokio's clock since `new`), the probes that `probe_answers` does not
    /// settle answer like this.
    pub probe_after: Option<(Duration, ProbeAnswer)>,
    /// Every command, with the time on tokio's clock since `new`.
    pub calls: Vec<(Duration, Call)>,
    /// When the `After` step at the front of the script is due: set by the first wait for it, so that a wait
    /// that is dropped (the hold's probe interrupts it) does not start it over, as an event of a real radio
    /// comes at its own time whoever is listening.
    due: Option<Instant>,
    /// A `Silence` step was used up: nothing comes any more, however often the wait is started again.
    silent: bool,
    started: Instant,
}

impl FakeRadio {
    /// A radio with the reference station address and SNonce, and nothing scripted.
    pub fn new() -> Self {
        Self {
            station: SPA,
            nonce: SNONCE,
            script: VecDeque::new(),
            results: Vec::new(),
            scan_freqs: Vec::new(),
            trigger_errors: VecDeque::new(),
            fail_connect: false,
            fail_install: false,
            fail_install_group: false,
            probe_answers: VecDeque::new(),
            probe_after: None,
            calls: Vec::new(),
            due: None,
            silent: false,
            started: Instant::now(),
        }
    }

    /// The commands so far, without their times and without the probes: those are `probe_times`.
    pub fn commands(&self) -> Vec<Call> {
        self.calls
            .iter()
            .map(|(_, call)| call)
            .filter(|call| !matches!(call, Call::Probe(_)))
            .cloned()
            .collect()
    }

    /// The times, on the test's clock since `new`, at which a probe was made.
    pub fn probe_times(&self) -> Vec<Duration> {
        self.calls
            .iter()
            .filter(|(_, call)| matches!(call, Call::Probe(_)))
            .map(|(at, _)| *at)
            .collect()
    }

    /// How the probe made now is answered.
    fn probe_answer(&mut self) -> ProbeAnswer {
        if let Some(answer) = self.probe_answers.pop_front() {
            return answer;
        }
        match self.probe_after {
            Some((from, answer)) if self.started.elapsed() >= from => answer,
            _ => ProbeAnswer::Ok,
        }
    }

    fn record(&mut self, call: Call) {
        self.calls.push((self.started.elapsed(), call));
    }
}

impl Radio for FakeRadio {
    fn station(&self) -> MacAddr {
        self.station
    }

    fn nonce(&mut self) -> Result<Nonce, RadioError> {
        Ok(self.nonce)
    }

    async fn trigger_scan(&mut self, _ssid: &[u8], freqs_mhz: &[u32]) -> Result<(), RadioError> {
        self.record(Call::TriggerScan);
        self.scan_freqs.push(freqs_mhz.to_vec());
        self.trigger_errors.pop_front().map_or(Ok(()), Err)
    }

    async fn scan_results(&mut self) -> Result<Vec<Bss>, RadioError> {
        self.record(Call::ScanResults);
        let limited = self.scan_freqs.last().filter(|freqs| !freqs.is_empty());
        Ok(self
            .results
            .iter()
            .filter(|bss| limited.is_none_or(|freqs| freqs.contains(&bss.freq_mhz)))
            .cloned()
            .collect())
    }

    async fn connect(&mut self, _ssid: &[u8], candidate: &Candidate) -> Result<(), RadioError> {
        self.record(Call::Connect {
            bssid: candidate.bssid,
            freq_mhz: candidate.freq_mhz,
        });
        if self.fail_connect {
            return Err(refused());
        }
        Ok(())
    }

    async fn probe(&mut self, peer: MacAddr) -> Result<(), RadioError> {
        self.record(Call::Probe(peer));
        match self.probe_answer() {
            ProbeAnswer::Ok => Ok(()),
            ProbeAnswer::Fail => Err(unanswered()),
            ProbeAnswer::Slow(delay) => timeout(PROBE_BOUND, sleep(delay))
                .await
                .map_err(|_| unanswered()),
            ProbeAnswer::Hang => {
                let _ = timeout(PROBE_BOUND, std::future::pending::<()>()).await;
                Err(unanswered())
            }
        }
    }

    async fn disconnect(&mut self, reason: u16) -> Result<(), RadioError> {
        self.record(Call::Disconnect(reason));
        Ok(())
    }

    async fn next_event(&mut self) -> Result<RadioEvent, RadioError> {
        // The step stays in the script until it returns, and so does its due time: a cancelled wait
        // goes on where it was.
        if self.silent {
            std::future::pending::<()>().await;
        }
        if let Some(&Step::After(delay, _)) = self.script.front() {
            let due = *self.due.get_or_insert_with(|| Instant::now() + delay);
            sleep_until(due).await;
        }
        self.due = None;
        match self.script.pop_front() {
            Some(Step::Event(event) | Step::After(_, event)) => Ok(event),
            Some(Step::Silence) => {
                self.silent = true;
                std::future::pending().await
            }
            None => std::future::pending().await,
        }
    }

    fn send_frame(&mut self, frame: &[u8]) -> Result<(), RadioError> {
        self.record(Call::SendFrame(frame.to_vec()));
        Ok(())
    }

    async fn install_pairwise(
        &mut self,
        peer: MacAddr,
        tk: &SecretBytes<16>,
    ) -> Result<(), RadioError> {
        self.record(Call::InstallPairwise {
            peer,
            tk: *tk.expose(),
        });
        if self.fail_install {
            return Err(refused());
        }
        Ok(())
    }

    async fn install_group(&mut self, key: &GroupKey) -> Result<(), RadioError> {
        self.record(Call::InstallGroup {
            key_id: key.key_id,
            key: *key.key.expose(),
            rsc: key.rsc,
        });
        if self.fail_install_group {
            return Err(refused());
        }
        Ok(())
    }

    async fn authorize(&mut self, peer: MacAddr) -> Result<(), RadioError> {
        self.record(Call::Authorize(peer));
        Ok(())
    }
}

/// The error of a radio that does not answer: the netlink request times out.
fn unanswered() -> RadioError {
    RadioError::Request(RequestError::Timeout)
}

/// The error of a kernel that refuses a request.
fn refused() -> RadioError {
    RadioError::Request(RequestError::Kernel(NlError {
        errno: libc::EINVAL,
        message: None,
    }))
}

/// The configuration of the reference network: the IEEE passphrase and network name.
pub fn cfg() -> JoinCfg {
    JoinCfg {
        ssid: b"ThisIsASSID".to_vec(),
        pmk: Pmk::from_passphrase("ThisIsAPassword", b"ThisIsASSID").unwrap(),
        hint_mhz: Vec::new(),
    }
}

/// The reference access point, as a scan found it.
pub fn ap() -> Candidate {
    Candidate {
        bssid: AA,
        freq_mhz: 5180,
        signal_mbm: -5600,
        rsne: RSNE.to_vec(),
        rsnxe: None,
    }
}

/// A frame the access point sends to the station, with `body` as its 802.1X part.
pub fn from_ap(body: &[u8]) -> Step {
    Step::Event(RadioEvent::Frame(build(SPA, AA, ETHERTYPE_PAE, body)))
}

/// The command that sends `body` to the access point.
pub fn to_ap(body: &[u8]) -> Call {
    Call::SendFrame(build(AA, SPA, ETHERTYPE_PAE, body))
}

/// The kernel reports the association with the reference access point; the request carried the station's own element.
pub fn connected() -> Step {
    connected_with(SUPPLICANT_RSNE.to_vec())
}

/// The kernel reports the association with the reference access point; the request carried `req_ies`.
pub fn connected_with(req_ies: Vec<u8>) -> Step {
    Step::Event(RadioEvent::Nl(Event::Connected { bssid: AA, req_ies }))
}

/// The commands of a join that runs the reference handshake to the end.
pub fn joined_calls() -> Vec<Call> {
    vec![
        Call::Connect {
            bssid: AA,
            freq_mhz: 5180,
        },
        to_ap(&M2),
        to_ap(&M4),
        Call::InstallPairwise { peer: AA, tk: TK },
        Call::InstallGroup {
            key_id: 1,
            key: GTK1,
            rsc: hex!("112233445566"),
        },
        Call::Authorize(AA),
    ]
}
