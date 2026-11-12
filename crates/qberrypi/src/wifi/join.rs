//! Scanning for a network, joining it, and holding the link: association, the
//! four-way handshake with `qb-wpa2`, key installation, and the rekeys after.
//!
//! All of it is written against [`Radio`], so a scripted radio can stand in
//! for the kernel. Every wait has a deadline on tokio's clock, except the
//! hold, which lasts as long as the link does and as long as the radio answers
//! the probes it makes on the side.
//!
//! The frames are the handshake's and the keys are the network's: no value
//! of type `Pmk`, `SecretBytes`, `GroupKey`, `Supplicant`, `Reply` or [`Link`]
//! is ever passed to a formatting macro, no frame is ever logged, and every
//! error says its numbers and fixed text only. The supplicant's contract
//! binds the order here: a reply's frame is sent first, then its pairwise
//! key is installed, then its group key, each exactly as returned and once.

use std::collections::VecDeque;
use std::fmt;
use std::time::Duration;

use qb_wpa2::MacAddr;
use qb_wpa2::pmk::Pmk;
use qb_wpa2::rsne::SUPPLICANT_RSNE;
use qb_wpa2::supplicant::{HandshakeError, Params, Phase, Reply, ReplyKind, Supplicant, Warning};
use tokio::time::{Instant, MissedTickBehavior, interval_at, sleep, timeout_at};

use super::choose::Candidate;
use super::eapol::{self, ETHERTYPE_PAE};
use super::ies::{self, EID_RSN};
use super::mac;
use super::radio::{Radio, RadioError, RadioEvent};
use crate::netlink::nl80211::{Bss, Event};

/// How long a scan may take, from the moment it was started.
pub const SCAN_TIMEOUT: Duration = Duration::from_secs(15);

/// How many times a scan is started while the radio says it is busy, the first time included.
pub const SCAN_BUSY_TRIES: u32 = 5;

/// How long the kernel may take to report the association, from the connect request.
pub const ASSOC_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the handshake may take, from the report of the association.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How often `hold` asks the radio whether it still knows the access point, from the start of the hold, whatever
/// the traffic is.
pub const PROBE_EVERY: Duration = Duration::from_secs(10);

/// How many probes in a row may fail before `hold` gives the link up.
pub const PROBE_FAILURES: u32 = 3;

/// How long to wait before asking a busy radio again.
const SCAN_BUSY_WAIT: Duration = Duration::from_secs(1);

/// How many frames that arrive before the kernel's report of the association are kept for the handshake.
const KEPT_FRAMES: usize = 4;

/// The 802.11 reason code for leaving the network of one's own accord: deauthenticated because the sender is leaving.
pub const REASON_LEAVING: u16 = 3;

/// The 802.11 reason code for a four-way handshake that did not complete in time.
const REASON_HANDSHAKE_TIMEOUT: u16 = 15;

/// The 802.11 reason code for an RSN element that is not the one the access point advertised.
const REASON_INVALID_RSNE: u16 = 17;

/// The network to join: its name, the key its passphrase gives, and where to look for it first.
#[derive(Debug, Clone)]
pub struct JoinCfg {
    /// The network's name.
    pub ssid: Vec<u8>,
    /// The key the passphrase and the name give.
    pub pmk: Pmk,
    /// The channel centre frequencies, in MHz, that the first scan of a join covers alone; empty for no
    /// hint, and then every scan covers every channel. A hint changes which channels that scan looks at and
    /// nothing else: see [`run`](super::run).
    pub hint_mhz: Vec<u32>,
}

/// An association whose handshake is done.
///
/// It keeps the supplicant, whose state decides which later frames are answered and which keys are installed:
/// `hold` needs it, and a new association needs a new `Link`.
pub struct Link {
    /// The access point's address.
    pub bssid: MacAddr,
    /// The channel's frequency, as the scan found it.
    pub freq_mhz: u32,
    /// The signal strength in 1/100 dBm, as the scan found it.
    pub signal_mbm: i32,
    supplicant: Supplicant,
}

// By hand, to leave out the supplicant and what it keeps.
impl fmt::Debug for Link {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Link")
            .field("bssid", &self.bssid)
            .field("freq_mhz", &self.freq_mhz)
            .field("signal_mbm", &self.signal_mbm)
            .finish_non_exhaustive()
    }
}

/// Why a scan or a join did not work.
#[derive(Debug)]
pub enum JoinError {
    /// A scan could not be started or its results not read.
    Scan(RadioError),
    /// The kernel cut the scan short.
    ScanAborted,
    /// The scan did not end in time.
    ScanTimeout,
    /// The scan found no access point to try: `seen` of any name, `out_of_scope` of the right name but not WPA2-PSK with CCMP.
    NoCandidate { seen: usize, out_of_scope: usize },
    /// The kernel did not take the connect request.
    Connect(RadioError),
    /// The kernel did not report the association in time.
    AssocTimeout,
    /// The access point refused the association, or did not answer it.
    AssocRefused { status: u16, timed_out: bool },
    /// The kernel associated with another access point than the one asked for.
    WrongBss,
    /// The handshake could not start, or the access point's message 3 was refused for good.
    Handshake(HandshakeError),
    /// The handshake did not end in time, in this phase.
    HandshakeTimeout { phase: Phase },
    /// The link went away; `phase` is where the handshake stood, if it had started.
    Disconnected {
        reason: u16,
        by_ap: bool,
        phase: Option<Phase>,
    },
    /// The kernel refused a key.
    KeyInstall(RadioError),
    /// The radio failed.
    Radio(RadioError),
    /// The kernel's event queue overflowed, so the attempt can no longer be followed.
    EventsLost,
}

impl JoinError {
    /// Whether a wrong passphrase would explain the failure: the access point checks message 2 with the key the
    /// passphrase gives, and answers a wrong one with silence, then with a disconnect. So it is the handshake that
    /// sent its message 2 and waited for message 3, in vain or until the link dropped. An access point that
    /// never sent message 1 says nothing about the passphrase.
    pub fn passphrase_suspect(&self) -> bool {
        matches!(
            self,
            Self::HandshakeTimeout {
                phase: Phase::AwaitingMessage3
            } | Self::Disconnected {
                phase: Some(Phase::AwaitingMessage3),
                ..
            }
        )
    }

    /// The 802.11 reason code to leave the network with after this failure.
    pub fn leave_reason(&self) -> u16 {
        match self {
            Self::HandshakeTimeout { .. } => REASON_HANDSHAKE_TIMEOUT,
            Self::Handshake(HandshakeError::RsneMismatch) => REASON_INVALID_RSNE,
            _ => REASON_LEAVING,
        }
    }
}

/// What the handshake was waiting for, in words.
fn waiting_for(phase: Phase) -> &'static str {
    match phase {
        Phase::AwaitingMessage1 => "message 1",
        Phase::AwaitingMessage3 => "message 3",
        Phase::Established | Phase::Rekeying => "a rekey",
    }
}

impl fmt::Display for JoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scan(error) => write!(f, "the scan failed: {error}"),
            Self::ScanAborted => f.write_str("the scan was aborted"),
            Self::ScanTimeout => write!(
                f,
                "the scan did not finish within {} s",
                SCAN_TIMEOUT.as_secs()
            ),
            Self::NoCandidate { seen, out_of_scope } => write!(
                f,
                "no access point to try: the scan saw {seen}, {out_of_scope} of them with the network's name but not WPA2-PSK with CCMP"
            ),
            Self::Connect(error) => write!(f, "the connect request failed: {error}"),
            Self::AssocTimeout => write!(
                f,
                "the association did not complete within {} s",
                ASSOC_TIMEOUT.as_secs()
            ),
            Self::AssocRefused {
                status,
                timed_out: false,
            } => write!(
                f,
                "the access point refused the association, status {status}"
            ),
            Self::AssocRefused {
                status,
                timed_out: true,
            } => write!(
                f,
                "the access point did not answer the association request, status {status}"
            ),
            Self::WrongBss => f.write_str(
                "the kernel associated with another access point than the one asked for",
            ),
            Self::Handshake(error) => write!(f, "the handshake failed: {error}"),
            Self::HandshakeTimeout { phase } => write!(
                f,
                "the handshake did not finish within {} s, waiting for {}",
                HANDSHAKE_TIMEOUT.as_secs(),
                waiting_for(*phase)
            ),
            Self::Disconnected {
                reason,
                by_ap,
                phase,
            } => {
                let who = if *by_ap {
                    "the access point"
                } else {
                    "this station"
                };
                write!(f, "the link was ended by {who}, reason {reason}")?;
                match phase {
                    Some(phase) => write!(
                        f,
                        ", while the handshake waited for {}",
                        waiting_for(*phase)
                    ),
                    None => Ok(()),
                }
            }
            Self::KeyInstall(error) => write!(f, "the kernel refused a key: {error}"),
            Self::Radio(error) => write!(f, "the radio failed: {error}"),
            Self::EventsLost => f.write_str("the kernel's event queue overflowed"),
        }
    }
}

impl std::error::Error for JoinError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Scan(error)
            | Self::Connect(error)
            | Self::KeyInstall(error)
            | Self::Radio(error) => Some(error),
            Self::Handshake(error) => Some(error),
            _ => None,
        }
    }
}

/// Why a link that was held is gone.
#[derive(Debug, PartialEq, Eq)]
pub enum Lost {
    /// The kernel reports the link as ended.
    Disconnected { reason: u16, by_ap: bool },
    /// The kernel moved the station to another access point; the handshake with it is not ours.
    Roamed,
    /// The kernel's event queue overflowed, so the link can no longer be followed.
    EventsLost,
    /// The access point's message 3 of a rekey repeated another RSN element than its beacon did.
    RsneMismatch,
    /// The radio failed, or the kernel refused a key of a rekey.
    Radio(String),
    /// The radio stopped answering: `PROBE_FAILURES` probes in a row failed; the text is the last one's error.
    Silent(String),
}

impl fmt::Display for Lost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disconnected { reason, by_ap } => {
                let who = if *by_ap {
                    "the access point"
                } else {
                    "this station"
                };
                write!(f, "the link was ended by {who}, reason {reason}")
            }
            Self::Roamed => f.write_str("the kernel moved the station to another access point"),
            Self::EventsLost => f.write_str("the kernel's event queue overflowed"),
            Self::RsneMismatch => f.write_str(
                "the RSN element of a rekey's message 3 is not the one the access point advertised",
            ),
            Self::Radio(text) => write!(f, "the radio failed: {text}"),
            Self::Silent(text) => write!(f, "the radio stopped answering: {text}"),
        }
    }
}

/// Lower-case hex of public bytes, for the log.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut text, byte| {
        // Writing to a `String` cannot fail.
        let _ = write!(text, "{byte:02x}");
        text
    })
}

/// Scans for `ssid` and returns every access point the kernel found, of any name.
///
/// The scan covers every channel when `freqs_mhz` is empty, and only the channels with these centre
/// frequencies otherwise; either way the kernel drops the earlier results first. A busy radio is asked again
/// a second later, up to `SCAN_BUSY_TRIES` times in all. A scan of channels the radio refuses is the
/// error `Scan` with the radio's refusal.
pub async fn scan<R: Radio>(
    radio: &mut R,
    ssid: &[u8],
    freqs_mhz: &[u32],
) -> Result<Vec<Bss>, JoinError> {
    let mut tries = 0;
    loop {
        tries += 1;
        match radio.trigger_scan(ssid, freqs_mhz).await {
            Ok(()) => break,
            Err(RadioError::Busy) if tries < SCAN_BUSY_TRIES => sleep(SCAN_BUSY_WAIT).await,
            Err(error) => return Err(JoinError::Scan(error)),
        }
    }
    let deadline = Instant::now() + SCAN_TIMEOUT;
    loop {
        match timeout_at(deadline, radio.next_event()).await {
            Err(_) => return Err(JoinError::ScanTimeout),
            Ok(Err(error)) => return Err(JoinError::Radio(error)),
            // A late `ScanDone` from a scan that already hit `ScanTimeout` can arrive during the backoff and be
            // taken here as the end of the next scan. Harmless: the results read are recent and the wait is bounded.
            Ok(Ok(RadioEvent::Nl(Event::ScanDone))) => break,
            Ok(Ok(RadioEvent::Nl(Event::ScanAborted))) => return Err(JoinError::ScanAborted),
            // The scan's own deadline bounds the wait, lost events or not.
            Ok(Ok(_)) => {}
        }
    }
    radio.scan_results().await.map_err(JoinError::Scan)
}

/// Associates with `candidate` and runs the four-way handshake with it, installing the keys it delivers.
///
/// On a failure after the connect request was taken, the station leaves the network again before the error is
/// returned, so the radio is idle for the next attempt.
pub async fn join<R: Radio>(
    radio: &mut R,
    cfg: &JoinCfg,
    candidate: &Candidate,
) -> Result<Link, JoinError> {
    log::info!(
        "wifi: connecting to {} on {} MHz",
        mac(&candidate.bssid),
        candidate.freq_mhz
    );
    if let Err(error) = radio.connect(&cfg.ssid, candidate).await {
        // An earlier disconnect may have failed, leaving the kernel connecting or connected; leave again, or every
        // later connect is refused as already under way. Nothing more can be done if this fails too.
        let _ = radio.disconnect(REASON_LEAVING).await;
        return Err(JoinError::Connect(error));
    }
    let attempt = associate_and_handshake(radio, cfg, candidate).await;
    if let Err(error) = &attempt {
        // Nothing more can be done if this fails too.
        let _ = radio.disconnect(error.leave_reason()).await;
    }
    attempt
}

/// Steps 2 to 4 of `join`: the report of the association, then the handshake.
async fn associate_and_handshake<R: Radio>(
    radio: &mut R,
    cfg: &JoinCfg,
    candidate: &Candidate,
) -> Result<Link, JoinError> {
    let bssid = candidate.bssid;

    // Until the kernel reports the association, a frame may come first: an access point does not wait for it
    // to send message 1.
    let deadline = Instant::now() + ASSOC_TIMEOUT;
    let mut kept: VecDeque<Vec<u8>> = VecDeque::new();
    let req_ies = loop {
        match timeout_at(deadline, radio.next_event()).await {
            Err(_) => return Err(JoinError::AssocTimeout),
            Ok(Err(error)) => return Err(JoinError::Radio(error)),
            Ok(Ok(RadioEvent::Frame(frame))) => {
                if kept.len() == KEPT_FRAMES {
                    kept.pop_front();
                }
                kept.push_back(frame);
            }
            Ok(Ok(RadioEvent::Nl(Event::Connected {
                bssid: got,
                req_ies,
            }))) => {
                if got != bssid {
                    return Err(JoinError::WrongBss);
                }
                break req_ies;
            }
            Ok(Ok(RadioEvent::Nl(Event::ConnectFailed { status, timed_out }))) => {
                return Err(JoinError::AssocRefused { status, timed_out });
            }
            Ok(Ok(RadioEvent::Nl(Event::Disconnected { reason, by_ap }))) => {
                return Err(JoinError::Disconnected {
                    reason,
                    by_ap,
                    phase: None,
                });
            }
            Ok(Ok(RadioEvent::Overrun)) => return Err(JoinError::EventsLost),
            Ok(Ok(RadioEvent::Nl(_))) => {}
        }
    };

    log::info!("wifi: associated with {}", mac(&bssid));
    // What the association request carried is what the access point saw, and what message 2 must repeat.
    let own_rsne = match ies::element(&req_ies, EID_RSN) {
        Some(element) => element.to_vec(),
        None => SUPPLICANT_RSNE.to_vec(),
    };
    if own_rsne != SUPPLICANT_RSNE {
        log::info!(
            "wifi: association request carried its own RSN element {}",
            hex(&own_rsne)
        );
    }
    let mut supplicant = Supplicant::new(Params {
        pmk: cfg.pmk.clone(),
        aa: bssid,
        spa: radio.station(),
        ap_rsne: candidate.rsne.clone(),
        ap_rsnxe: candidate.rsnxe.clone(),
        own_rsne,
    })
    .map_err(JoinError::Handshake)?;

    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    loop {
        // The frames that came early are older than any event still to come.
        let event = match kept.pop_front() {
            Some(frame) => RadioEvent::Frame(frame),
            None => match timeout_at(deadline, radio.next_event()).await {
                Err(_) => {
                    return Err(JoinError::HandshakeTimeout {
                        phase: supplicant.phase(),
                    });
                }
                Ok(Err(error)) => return Err(JoinError::Radio(error)),
                Ok(Ok(event)) => event,
            },
        };
        match event {
            RadioEvent::Frame(frame) => {
                let reply = match answer(radio, &bssid, &mut supplicant, &frame) {
                    Ok(Some(reply)) => reply,
                    Ok(None) => continue,
                    Err(Stop::Radio(error)) => return Err(JoinError::Radio(error)),
                    Err(Stop::RsneMismatch) => {
                        return Err(JoinError::Handshake(HandshakeError::RsneMismatch));
                    }
                };
                send_reply(radio, bssid, &reply);
                install_tk(radio, bssid, &reply)
                    .await
                    .map_err(JoinError::KeyInstall)?;
                install_gtk(radio, &reply)
                    .await
                    .map_err(JoinError::KeyInstall)?;
                log_warning(&reply);
                if reply.kind == ReplyKind::Message4 {
                    match radio.authorize(bssid).await {
                        Ok(()) => log::info!("wifi: port authorized"),
                        Err(error) => log::warn!("wifi: authorizing the port failed: {error}"),
                    }
                    return Ok(Link {
                        bssid,
                        freq_mhz: candidate.freq_mhz,
                        signal_mbm: candidate.signal_mbm,
                        supplicant,
                    });
                }
            }
            RadioEvent::Nl(Event::Disconnected { reason, by_ap }) => {
                return Err(JoinError::Disconnected {
                    reason,
                    by_ap,
                    phase: Some(supplicant.phase()),
                });
            }
            RadioEvent::Overrun => return Err(JoinError::EventsLost),
            RadioEvent::Nl(_) => {}
        }
    }
}

/// Keeps the link: answers the access point's rekeys and installs the keys they deliver, until the link is lost.
///
/// A frame the supplicant refuses is dropped, with a warning. A key the kernel refuses, a rekey whose message 3
/// repeats another RSN element than the beacon did, a lost event queue, a failing radio and a move to another
/// access point end the hold, and the station leaves the network before it returns. A refused key ends it
/// because the supplicant hands a key out once: the access point's repeat would not carry it again, and the
/// link would stay up with its unicast or its group traffic dead.
///
/// A radio that dies without a word (a firmware that hangs sends no disconnect, no overrun and no error) would
/// leave the link held for ever, so every `PROBE_EVERY` of the hold, whatever the traffic, the radio is asked
/// about the access point: [`Radio::probe`], a query the radio answers from its own state, which a quiet and
/// healthy link passes as well as a busy one. A probe that fails (an error of any kind, a timeout, an answer
/// without the access point) is a warning; `PROBE_FAILURES` of them in a row end the hold with
/// [`Lost::Silent`], and the station leaves the network as for the other ends. One probe that works starts the
/// count again, so a single slow answer costs nothing. The probe is made between two events and the wait for
/// events is not polled meanwhile, but it loses none: the radio keeps what arrives and hands it out next.
///
/// A radio that has stopped answering is lost within 3 × (10 s + 10 s) = 60 s: a probe is due every
/// `PROBE_EVERY` after the last one ended, and takes at most the bound of a radio command, which is two reply
/// timeouts (10 s). The `leave` that follows is a command and has the same bound.
pub async fn hold<R: Radio>(radio: &mut R, link: &mut Link) -> Lost {
    // Delay: a probe that took long, or a stretch of work, moves the next one back and does not bunch two.
    let mut due = interval_at(Instant::now() + PROBE_EVERY, PROBE_EVERY);
    due.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut failures = 0;
    loop {
        // `next_event` is cancel-safe: the tick that wins the race loses no event.
        let event = tokio::select! {
            event = radio.next_event() => event,
            _ = due.tick() => {
                match radio.probe(link.bssid).await {
                    Ok(()) => failures = 0,
                    Err(error) => {
                        failures += 1;
                        log::warn!(
                            "wifi: the radio did not answer a probe ({failures} of {PROBE_FAILURES}): {error}"
                        );
                        if failures >= PROBE_FAILURES {
                            let lost = Lost::Silent(error.to_string());
                            return leave(radio, REASON_LEAVING, lost).await;
                        }
                    }
                }
                continue;
            }
        };
        let event = match event {
            Ok(event) => event,
            Err(error) => {
                return leave(radio, REASON_LEAVING, Lost::Radio(error.to_string())).await;
            }
        };
        match event {
            RadioEvent::Frame(frame) => {
                let reply = match answer(radio, &link.bssid, &mut link.supplicant, &frame) {
                    Ok(Some(reply)) => reply,
                    Ok(None) => continue,
                    Err(Stop::Radio(error)) => {
                        return leave(radio, REASON_LEAVING, Lost::Radio(error.to_string())).await;
                    }
                    Err(Stop::RsneMismatch) => {
                        return leave(radio, REASON_INVALID_RSNE, Lost::RsneMismatch).await;
                    }
                };
                send_reply(radio, link.bssid, &reply);
                if let Err(error) = install_tk(radio, link.bssid, &reply).await {
                    log::warn!("wifi: the kernel refused the pairwise key: {error}");
                    return leave(radio, REASON_LEAVING, refused_key(&error)).await;
                }
                if let Err(error) = install_gtk(radio, &reply).await {
                    log::warn!("wifi: the kernel refused the group key: {error}");
                    return leave(radio, REASON_LEAVING, refused_key(&error)).await;
                }
                log_warning(&reply);
            }
            RadioEvent::Nl(Event::Disconnected { reason, by_ap }) => {
                return Lost::Disconnected { reason, by_ap };
            }
            RadioEvent::Nl(Event::Roamed { .. }) => {
                return leave(radio, REASON_LEAVING, Lost::Roamed).await;
            }
            RadioEvent::Overrun => return leave(radio, REASON_LEAVING, Lost::EventsLost).await,
            RadioEvent::Nl(_) => {}
        }
    }
}

/// The end of a hold whose rekey the kernel refused: the error says what the kernel said, and no key.
fn refused_key(error: &RadioError) -> Lost {
    Lost::Radio(format!("the kernel refused a key: {error}"))
}

/// Leaves the network with `reason`, ignoring whether that works, and hands `lost` back.
async fn leave<R: Radio>(radio: &mut R, reason: u16, lost: Lost) -> Lost {
    let _ = radio.disconnect(reason).await;
    lost
}

/// Why a frame ends the join or the hold instead of being answered or dropped.
enum Stop {
    /// The radio could not give a nonce.
    Radio(RadioError),
    /// Message 3 repeated another RSN element than the access point advertised.
    RsneMismatch,
}

/// Hands a frame from the radio to the supplicant, if it is one for the handshake: of the access point's address
/// and the EAPOL ethertype. `Ok(None)` for another frame, and for one the supplicant dropped, with a warning.
fn answer<R: Radio>(
    radio: &mut R,
    bssid: &MacAddr,
    supplicant: &mut Supplicant,
    frame: &[u8],
) -> Result<Option<Reply>, Stop> {
    let Some(frame) = eapol::parse(frame) else {
        return Ok(None);
    };
    if frame.ethertype != ETHERTYPE_PAE || frame.src != *bssid {
        return Ok(None);
    }
    // The supplicant asks for the nonce only when it needs one; a fresh one is ready for it every time.
    let nonce = radio.nonce().map_err(Stop::Radio)?;
    match supplicant.handle(frame.body, || nonce) {
        Ok(reply) => Ok(Some(reply)),
        Err(HandshakeError::RsneMismatch) => Err(Stop::RsneMismatch),
        Err(error) => {
            log::warn!("wifi: dropped a handshake frame: {error}");
            Ok(None)
        }
    }
}

/// What a reply is, for the log.
fn what(kind: ReplyKind) -> &'static str {
    match kind {
        ReplyKind::Message2 => "handshake message 2",
        ReplyKind::Message4 => "handshake message 4",
        ReplyKind::GroupMessage2 => "handshake group message 2",
    }
}

/// Sends the frame of a reply. A frame that cannot be sent is a warning, not a failure: the access point
/// repeats its message.
fn send_reply<R: Radio>(radio: &mut R, bssid: MacAddr, reply: &Reply) {
    let frame = eapol::build(bssid, radio.station(), ETHERTYPE_PAE, &reply.frame);
    match radio.send_frame(&frame) {
        Ok(()) => log::info!("wifi: sent {}", what(reply.kind)),
        Err(error) => log::warn!("wifi: could not send {}: {error}", what(reply.kind)),
    }
}

/// Installs the pairwise key of a reply, if it has one, as returned. Call it after `send_reply`.
async fn install_tk<R: Radio>(
    radio: &mut R,
    bssid: MacAddr,
    reply: &Reply,
) -> Result<(), RadioError> {
    if let Some(tk) = &reply.tk {
        radio.install_pairwise(bssid, tk).await?;
        log::info!("wifi: pairwise key installed");
    }
    Ok(())
}

/// Installs the group key of a reply, if it has one, as returned. Call it after `install_tk`.
async fn install_gtk<R: Radio>(radio: &mut R, reply: &Reply) -> Result<(), RadioError> {
    if let Some(gtk) = &reply.gtk {
        radio.install_group(gtk).await?;
        log::info!("wifi: group key {} installed", gtk.key_id);
    }
    Ok(())
}

/// Logs what the supplicant found odd about an accepted frame.
fn log_warning(reply: &Reply) {
    match reply.warning {
        Some(Warning::RsnxeMismatch) => {
            log::warn!("wifi: RSNXE in message 3 differs from the advertised one; tolerated")
        }
        None => {}
    }
}

#[cfg(test)]
mod tests {
    use std::sync::PoisonError;

    use super::*;
    use crate::netlink::nl80211::{Bss, Event};
    use crate::wifi::fake::authenticator::{ApFrame, gtk_kde, pad};
    use crate::wifi::fake::reference::{
        AA, ANONCE, G1, G2, GTK1, GTK2, KCK, KEK, M1, M3, PMK, RSNE, SNONCE, SPA, TK,
    };
    use crate::wifi::fake::{
        Call, FakeRadio, PROBE_BOUND, ProbeAnswer, Step, ap, cfg, connected, connected_with,
        from_ap, joined_calls, to_ap,
    };
    use hex_literal::hex;
    use qb_wpa2::eapol::EapolKey;
    use qb_wpa2::ptk::Ptk;

    /// An RSN element that differs from the reference one in its capabilities.
    const OTHER_RSNE: [u8; 22] = hex!("30140100000fac040100000fac040100000fac020c00");

    fn nl(event: Event) -> Step {
        Step::Event(RadioEvent::Nl(event))
    }

    fn disconnected(reason: u16, by_ap: bool) -> Step {
        nl(Event::Disconnected { reason, by_ap })
    }

    /// A radio that has joined the reference network with the reference handshake, and its link.
    async fn joined() -> (FakeRadio, Link) {
        let mut radio = FakeRadio::new();
        radio
            .script
            .extend([connected(), from_ap(&M1), from_ap(&M3)]);
        let link = join(&mut radio, &cfg(), &ap()).await.unwrap();
        (radio, link)
    }

    /// The commands given after the join of `joined`.
    fn after_join(radio: &FakeRadio) -> Vec<Call> {
        radio.commands()[joined_calls().len()..].to_vec()
    }

    /// A join that runs the script and fails: the error and the radio.
    async fn failed_join(steps: impl IntoIterator<Item = Step>) -> (JoinError, FakeRadio) {
        let mut radio = FakeRadio::new();
        radio.script.extend(steps);
        let error = join(&mut radio, &cfg(), &ap()).await.unwrap_err();
        (error, radio)
    }

    /// A new four-way handshake from the access point, after the reference one: a message 1 with replay
    /// counter 6 and a fresh ANonce, then a message 3 with counter 7 and that ANonce, signed under the keys
    /// the ANonce gives, that repeats `rsne` and delivers the group key 2.
    fn new_handshake(rsne: &[u8]) -> [Step; 2] {
        let anonce = [0x55; 32];
        assert_ne!(anonce, ANONCE);
        let ptk = Ptk::derive(&cfg().pmk, &AA, &SPA, &anonce, &SNONCE);
        let (kck, kek) = (ptk.kck().expose(), ptk.kek().expose());
        let key_data = pad([rsne, &gtk_kde(2, &GTK2)].concat());
        [
            from_ap(&ApFrame::m1(6, anonce).build(kck, kek)),
            from_ap(&ApFrame::m3(7, anonce, key_data).build(kck, kek)),
        ]
    }

    fn sent_frames(commands: &[Call]) -> usize {
        commands
            .iter()
            .filter(|call| matches!(call, Call::SendFrame(_)))
            .count()
    }

    fn pairwise_installs(commands: &[Call]) -> usize {
        commands
            .iter()
            .filter(|call| matches!(call, Call::InstallPairwise { .. }))
            .count()
    }

    fn last(radio: &FakeRadio) -> Option<Call> {
        radio.commands().pop()
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

    #[tokio::test(start_paused = true)]
    async fn a_join_runs_the_reference_handshake() {
        // The IEEE passphrase and network name give the reference key.
        assert_eq!(cfg().pmk.expose(), &PMK);
        let mut radio = FakeRadio::new();
        radio
            .script
            .extend([connected(), from_ap(&M1), from_ap(&M3)]);
        let link = join(&mut radio, &cfg(), &ap()).await.unwrap();
        assert_eq!(
            (link.bssid, link.freq_mhz, link.signal_mbm),
            (AA, 5180, -5600)
        );
        assert_eq!(radio.commands(), joined_calls());
        // The link prints its address and channel and nothing of its keys.
        assert_eq!(
            format!("{link:?}"),
            "Link { bssid: [160, 161, 161, 163, 164, 165], freq_mhz: 5180, signal_mbm: -5600, .. }"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn message_1_before_the_connect_event_is_answered_after_it() {
        let mut radio = FakeRadio::new();
        radio
            .script
            .extend([from_ap(&M1), connected(), from_ap(&M3)]);
        join(&mut radio, &cfg(), &ap()).await.unwrap();
        assert_eq!(radio.commands(), joined_calls());
    }

    #[tokio::test(start_paused = true)]
    async fn frames_of_others_are_ignored() {
        use crate::wifi::eapol::{ETHERTYPE_PAE, build};
        let from_us = Step::Event(RadioEvent::Frame(build(AA, SPA, ETHERTYPE_PAE, &M1)));
        let not_eapol = Step::Event(RadioEvent::Frame(build(SPA, AA, 0x0800, &M1)));
        let mut radio = FakeRadio::new();
        radio
            .script
            .extend([connected(), from_us, not_eapol, from_ap(&M1), from_ap(&M3)]);
        join(&mut radio, &cfg(), &ap()).await.unwrap();
        assert_eq!(radio.commands(), joined_calls());
    }

    #[tokio::test(start_paused = true)]
    async fn the_association_requests_own_element_goes_into_message_2() {
        logging();
        let req_ies = [&hex!("0003616263")[..], &OTHER_RSNE].concat();
        let (error, radio) =
            failed_join([connected_with(req_ies), from_ap(&M1), Step::Silence]).await;
        // The reference message 3 is not sent: its MIC covers another message 2.
        assert!(matches!(
            error,
            JoinError::HandshakeTimeout {
                phase: Phase::AwaitingMessage3
            }
        ));
        let commands = radio.commands();
        let Call::SendFrame(frame) = &commands[1] else {
            panic!("the second command is not a frame: {commands:?}");
        };
        let body = crate::wifi::eapol::parse(frame).unwrap().body;
        assert_eq!(EapolKey::decode(body).unwrap().key_data, OTHER_RSNE);
        assert!(log_text().contains(&format!(
            "wifi: association request carried its own RSN element {}",
            hex(&OTHER_RSNE)
        )));
    }

    #[tokio::test(start_paused = true)]
    async fn no_connect_event_is_an_association_timeout() {
        let (error, radio) = failed_join([Step::Silence]).await;
        assert!(matches!(error, JoinError::AssocTimeout));
        assert_eq!(
            radio.commands(),
            [
                Call::Connect {
                    bssid: AA,
                    freq_mhz: 5180
                },
                Call::Disconnect(3)
            ]
        );
        assert_eq!(radio.calls[1].0, ASSOC_TIMEOUT);
        assert_eq!(
            error.to_string(),
            "the association did not complete within 10 s"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_connect_the_kernel_refuses_is_followed_by_a_disconnect() {
        let mut radio = FakeRadio::new();
        radio.fail_connect = true;
        let error = join(&mut radio, &cfg(), &ap()).await.unwrap_err();
        assert!(matches!(error, JoinError::Connect(_)));
        // The kernel may still hold an earlier attempt that a failed disconnect left behind.
        assert_eq!(
            radio.commands(),
            [
                Call::Connect {
                    bssid: AA,
                    freq_mhz: 5180
                },
                Call::Disconnect(3)
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_refused_association_carries_its_status() {
        let (error, radio) = failed_join([nl(Event::ConnectFailed {
            status: 16,
            timed_out: false,
        })])
        .await;
        assert!(matches!(
            error,
            JoinError::AssocRefused {
                status: 16,
                timed_out: false
            }
        ));
        assert_eq!(
            error.to_string(),
            "the access point refused the association, status 16"
        );
        assert_eq!(last(&radio), Some(Call::Disconnect(3)));

        let (error, radio) = failed_join([nl(Event::Connected {
            bssid: [2; 6],
            req_ies: Vec::new(),
        })])
        .await;
        assert!(matches!(error, JoinError::WrongBss));
        assert_eq!(last(&radio), Some(Call::Disconnect(3)));

        // The kernel's queue overflowed: events are lost, so the attempt is given up.
        let (error, radio) = failed_join([Step::Event(RadioEvent::Overrun)]).await;
        assert!(matches!(error, JoinError::EventsLost));
        assert_eq!(error.to_string(), "the kernel's event queue overflowed");
        assert_eq!(last(&radio), Some(Call::Disconnect(3)));

        let (error, _) = failed_join([disconnected(2, true)]).await;
        assert!(matches!(
            error,
            JoinError::Disconnected {
                reason: 2,
                by_ap: true,
                phase: None
            }
        ));
        assert!(!error.passphrase_suspect());
    }

    #[tokio::test(start_paused = true)]
    async fn a_wrong_passphrase_is_suspected_when_the_link_drops_awaiting_message_3() {
        let config = JoinCfg {
            pmk: Pmk::from_bytes([0x11; 32]),
            ..cfg()
        };
        let mut radio = FakeRadio::new();
        radio.script.extend([
            connected(),
            from_ap(&M1),
            from_ap(&M1),
            disconnected(15, true),
        ]);
        let error = join(&mut radio, &config, &ap()).await.unwrap_err();
        assert!(matches!(
            error,
            JoinError::Disconnected {
                reason: 15,
                by_ap: true,
                phase: Some(Phase::AwaitingMessage3)
            }
        ));
        assert!(error.passphrase_suspect());
        assert_eq!(sent_frames(&radio.commands()), 2);
        assert_eq!(pairwise_installs(&radio.commands()), 0);
        // Neither the error nor the configuration shows the key: [0x11; 32] would print as "17, 17".
        let shown = format!("{error} {error:?} {config:?}");
        assert!(!shown.contains("1111") && !shown.contains("17, 17"));
        assert!(!JoinError::AssocTimeout.passphrase_suspect());
        // Only a handshake that waited for message 3 points at the passphrase.
        for (phase, suspect) in [
            (Phase::AwaitingMessage1, false),
            (Phase::AwaitingMessage3, true),
        ] {
            assert_eq!(
                JoinError::HandshakeTimeout { phase }.passphrase_suspect(),
                suspect
            );
            assert_eq!(
                JoinError::Disconnected {
                    reason: 15,
                    by_ap: true,
                    phase: Some(phase)
                }
                .passphrase_suspect(),
                suspect
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn silence_after_message_2_is_a_handshake_timeout() {
        let (error, radio) = failed_join([connected(), from_ap(&M1), Step::Silence]).await;
        assert!(matches!(
            error,
            JoinError::HandshakeTimeout {
                phase: Phase::AwaitingMessage3
            }
        ));
        assert!(error.passphrase_suspect());
        assert_eq!(error.leave_reason(), 15);
        // The connect event came at once, so the deadline is that long after it.
        assert_eq!(last(&radio), Some(Call::Disconnect(15)));
        assert_eq!(radio.calls.last().unwrap().0, HANDSHAKE_TIMEOUT);

        // An access point that never sends message 1 is not a wrong passphrase.
        let (error, radio) = failed_join([connected(), Step::Silence]).await;
        assert!(matches!(
            error,
            JoinError::HandshakeTimeout {
                phase: Phase::AwaitingMessage1
            }
        ));
        assert!(!error.passphrase_suspect());
        assert_eq!(last(&radio), Some(Call::Disconnect(15)));
    }

    #[tokio::test(start_paused = true)]
    async fn a_changed_rsn_element_in_message_3_aborts() {
        let mut candidate = ap();
        candidate.rsne = OTHER_RSNE.to_vec();
        let mut radio = FakeRadio::new();
        radio
            .script
            .extend([connected(), from_ap(&M1), from_ap(&M3)]);
        let error = join(&mut radio, &cfg(), &candidate).await.unwrap_err();
        assert!(matches!(
            error,
            JoinError::Handshake(HandshakeError::RsneMismatch)
        ));
        assert_eq!(error.leave_reason(), 17);
        assert_eq!(last(&radio), Some(Call::Disconnect(17)));
        assert_eq!(pairwise_installs(&radio.commands()), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn an_rsnxe_mismatch_is_tolerated() {
        logging();
        let mut candidate = ap();
        candidate.rsnxe = Some(hex!("f40120").to_vec());
        let mut radio = FakeRadio::new();
        radio
            .script
            .extend([connected(), from_ap(&M1), from_ap(&M3)]);
        join(&mut radio, &cfg(), &candidate).await.unwrap();
        assert_eq!(radio.commands(), joined_calls());
        assert!(
            log_text()
                .contains("wifi: RSNXE in message 3 differs from the advertised one; tolerated")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_bad_frame_is_dropped_and_the_handshake_goes_on() {
        let mut bad_mic = M3;
        bad_mic[96] ^= 1;
        let mut radio = FakeRadio::new();
        radio.script.extend([
            connected(),
            from_ap(&M1),
            from_ap(&bad_mic),
            from_ap(&M3[..40]),
            from_ap(&[]),
            from_ap(&M3),
        ]);
        join(&mut radio, &cfg(), &ap()).await.unwrap();
        assert_eq!(radio.commands(), joined_calls());
    }

    #[tokio::test(start_paused = true)]
    async fn a_key_the_kernel_refuses_fails_the_attempt() {
        let mut radio = FakeRadio::new();
        radio.fail_install = true;
        radio
            .script
            .extend([connected(), from_ap(&M1), from_ap(&M3)]);
        let error = join(&mut radio, &cfg(), &ap()).await.unwrap_err();
        assert!(matches!(error, JoinError::KeyInstall(_)));
        assert_eq!(last(&radio), Some(Call::Disconnect(3)));
        assert!(!radio.commands().contains(&Call::Authorize(AA)));
    }

    #[tokio::test(start_paused = true)]
    async fn a_group_rekey_installs_the_new_key() {
        let (mut radio, mut link) = joined().await;
        // The hold has no deadline: a link that is quiet for an hour afterwards is still held.
        let an_hour = Duration::from_secs(3600);
        radio.script.extend([
            from_ap(&G1),
            Step::After(
                an_hour,
                RadioEvent::Nl(Event::Disconnected {
                    reason: 3,
                    by_ap: false,
                }),
            ),
        ]);
        let started = tokio::time::Instant::now();
        let lost = hold(&mut radio, &mut link).await;
        assert_eq!(started.elapsed(), an_hour);
        assert_eq!(
            lost,
            Lost::Disconnected {
                reason: 3,
                by_ap: false
            }
        );
        assert_eq!(
            after_join(&radio),
            [
                to_ap(&G2),
                Call::InstallGroup {
                    key_id: 2,
                    key: GTK2,
                    rsc: hex!("0a0b0c0d0e0f")
                }
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_replayed_message_3_installs_nothing() {
        let (mut radio, mut link) = joined().await;
        radio.script.extend([
            from_ap(&M3),
            from_ap(&G1),
            from_ap(&G1),
            disconnected(3, false),
        ]);
        hold(&mut radio, &mut link).await;
        let commands = radio.commands();
        assert_eq!(pairwise_installs(&commands), 1);
        let groups: Vec<u8> = commands
            .iter()
            .filter_map(|call| match call {
                Call::InstallGroup { key_id, .. } => Some(*key_id),
                _ => None,
            })
            .collect();
        assert_eq!(groups, [1, 2]);
        // Only the group message was answered: the replayed message 3 and the repeated group message were not.
        assert_eq!(sent_frames(&after_join(&radio)), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_changed_rsn_element_in_a_rekey_ends_the_hold() {
        let (mut radio, mut link) = joined().await;
        // A new four-way handshake from the access point whose message 3 repeats an RSN element that is not
        // the advertised one.
        radio.script.extend(new_handshake(&OTHER_RSNE));
        let lost = hold(&mut radio, &mut link).await;
        assert_eq!(lost, Lost::RsneMismatch);
        assert_eq!(
            lost.to_string(),
            "the RSN element of a rekey's message 3 is not the one the access point advertised"
        );
        // One frame in the hold: the message 2 that answers the new message 1. Nothing of the message 3.
        let hold_commands = after_join(&radio);
        assert_eq!(sent_frames(&hold_commands), 1);
        let Call::SendFrame(frame) = &hold_commands[0] else {
            panic!("the first command of the hold is not a frame: {hold_commands:?}");
        };
        let message_2 = EapolKey::decode(crate::wifi::eapol::parse(frame).unwrap().body).unwrap();
        assert_eq!((message_2.replay_counter, message_2.nonce), (6, SNONCE));
        assert_eq!(last(&radio), Some(Call::Disconnect(17)));
        assert_eq!(pairwise_installs(&radio.commands()), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_key_the_kernel_refuses_in_a_rekey_ends_the_hold() {
        // The supplicant hands a key out once, so a refused one would never come again: the link is given up.
        let refused = |lost: &Lost| matches!(lost, Lost::Radio(text) if text.starts_with("the kernel refused a key: "));

        let (mut radio, mut link) = joined().await;
        radio.fail_install_group = true;
        radio.script.extend([from_ap(&G1), disconnected(3, false)]);
        let lost = hold(&mut radio, &mut link).await;
        assert!(refused(&lost), "{lost:?}");
        assert_eq!(
            after_join(&radio),
            [
                to_ap(&G2),
                Call::InstallGroup {
                    key_id: 2,
                    key: GTK2,
                    rsc: hex!("0a0b0c0d0e0f")
                },
                Call::Disconnect(3)
            ]
        );

        // A pairwise key that is refused ends the hold before the group key of the same message is tried.
        let (mut radio, mut link) = joined().await;
        radio.fail_install = true;
        radio.script.extend(new_handshake(&RSNE));
        let lost = hold(&mut radio, &mut link).await;
        assert!(refused(&lost), "{lost:?}");
        let hold_commands = after_join(&radio);
        assert_eq!(sent_frames(&hold_commands), 2);
        assert!(matches!(
            hold_commands[2..],
            [Call::InstallPairwise { .. }, Call::Disconnect(3)]
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn a_roam_or_lost_events_end_the_hold() {
        let (mut radio, mut link) = joined().await;
        radio.script.push_back(nl(Event::Roamed { bssid: [2; 6] }));
        assert_eq!(hold(&mut radio, &mut link).await, Lost::Roamed);
        assert_eq!(last(&radio), Some(Call::Disconnect(3)));

        let (mut radio, mut link) = joined().await;
        radio.script.push_back(Step::Event(RadioEvent::Overrun));
        assert_eq!(hold(&mut radio, &mut link).await, Lost::EventsLost);
        assert_eq!(last(&radio), Some(Call::Disconnect(3)));
    }

    /// A time on the test's clock, in seconds.
    fn secs(seconds: u64) -> Duration {
        Duration::from_secs(seconds)
    }

    /// The access point ends the link `after` the start of the wait, with the reason 3.
    fn disconnects_after(after: Duration) -> Step {
        Step::After(
            after,
            RadioEvent::Nl(Event::Disconnected {
                reason: 3,
                by_ap: false,
            }),
        )
    }

    /// What a hold of a link whose radio is scripted by `script` returns, how long it took, and the radio.
    async fn held_for(mut radio: FakeRadio, mut link: Link) -> (Lost, Duration, FakeRadio) {
        let started = tokio::time::Instant::now();
        let lost = hold(&mut radio, &mut link).await;
        (lost, started.elapsed(), radio)
    }

    // The hold asks every 10 s whether the radio still knows the access point, with nothing else going on.
    #[tokio::test(start_paused = true)]
    async fn a_quiet_healthy_link_is_probed_every_ten_seconds_and_kept() {
        let (mut radio, link) = joined().await;
        // Ten minutes and five seconds of silence, then the end that the script brings.
        radio.script.push_back(disconnects_after(secs(605)));
        let (lost, took, radio) = held_for(radio, link).await;
        assert_eq!(
            lost,
            Lost::Disconnected {
                reason: 3,
                by_ap: false
            }
        );
        assert_eq!(took, secs(605));
        // Sixty probes, the first one period in, and each of them about the access point.
        let times: Vec<u64> = radio.probe_times().iter().map(Duration::as_secs).collect();
        assert_eq!(times, (1..=60).map(|n| n * 10).collect::<Vec<_>>());
        assert!(
            radio
                .calls
                .iter()
                .filter(|(_, call)| matches!(call, Call::Probe(_)))
                .all(|(_, call)| *call == Call::Probe(AA))
        );
        // The probes are no command of the handshake, and the radio was told nothing else.
        assert_eq!(radio.commands(), joined_calls());
    }

    // Traffic does not stand in for a probe, and a probe does not wait for the traffic to stop.
    #[tokio::test(start_paused = true)]
    async fn the_probes_go_on_whatever_the_traffic() {
        let (mut radio, link) = joined().await;
        // An event every second, none of which ends the hold, for a minute and five seconds.
        radio
            .script
            .extend((0..65).map(|_| Step::After(secs(1), RadioEvent::Nl(Event::Other(36)))));
        radio.script.push_back(disconnects_after(secs(1)));
        let (lost, took, radio) = held_for(radio, link).await;
        assert!(matches!(lost, Lost::Disconnected { .. }), "{lost:?}");
        assert_eq!(took, secs(66));
        let times: Vec<u64> = radio.probe_times().iter().map(Duration::as_secs).collect();
        assert_eq!(times, [10, 20, 30, 40, 50, 60]);
    }

    // Three probes that fail in a row end the hold; the station leaves, and the loss says why.
    #[tokio::test(start_paused = true)]
    async fn three_failed_probes_in_a_row_end_the_hold() {
        logging();
        let (mut radio, link) = joined().await;
        // The radio answers for 95 s and then never again, and nothing else comes from it.
        radio.probe_after = Some((secs(95), ProbeAnswer::Fail));
        let (lost, took, radio) = held_for(radio, link).await;
        // Failed probes at 100, 110 and 120 s: the radio has not answered for 30 s, as the probes fail at once.
        assert_eq!(took, secs(120));
        assert_eq!(
            lost,
            Lost::Silent("no answer from the kernel within 5 s".into())
        );
        assert_eq!(
            lost.to_string(),
            "the radio stopped answering: no answer from the kernel within 5 s"
        );
        assert_eq!(PROBE_FAILURES, 3);
        // The last command of the hold is the leaving, as for the other ends.
        assert_eq!(after_join(&radio), [Call::Disconnect(3)]);
        let times: Vec<u64> = radio.probe_times().iter().map(Duration::as_secs).collect();
        assert_eq!(times.len(), 12);
        assert_eq!(&times[9..], [100, 110, 120]);
        let log = log_text();
        assert!(
            log.contains(
                "wifi: the radio did not answer a probe (3 of 3): no answer from the kernel"
            ),
            "{log}"
        );
    }

    // One answer is enough to forgive the failures before it, however often they come.
    #[tokio::test(start_paused = true)]
    async fn two_failures_and_a_success_never_end_the_hold() {
        let (mut radio, link) = joined().await;
        radio
            .probe_answers
            .extend((0..30).flat_map(|_| [ProbeAnswer::Fail, ProbeAnswer::Fail, ProbeAnswer::Ok]));
        // 30 rounds of three probes take 900 s; the hold goes on past them, on the radio's answers.
        radio.script.push_back(disconnects_after(secs(905)));
        let (lost, took, radio) = held_for(radio, link).await;
        assert!(matches!(lost, Lost::Disconnected { .. }), "{lost:?}");
        assert_eq!(took, secs(905));
        assert_eq!(radio.probe_times().len(), 90);
        // The link was never left.
        assert_eq!(radio.commands(), joined_calls());
    }

    // A probe that is never answered returns at the radio's own bound, and the hold gives up within the bound
    // the docs give: three times the probe's period plus its bound.
    #[tokio::test(start_paused = true)]
    async fn a_probe_that_hangs_still_ends_the_hold_within_the_bound() {
        let (mut radio, link) = joined().await;
        radio.probe_after = Some((Duration::ZERO, ProbeAnswer::Hang));
        let (lost, took, radio) = held_for(radio, link).await;
        assert!(matches!(lost, Lost::Silent(_)), "{lost:?}");
        assert_eq!(PROBE_BOUND, secs(10));
        assert!(
            took <= 3 * (PROBE_EVERY + PROBE_BOUND),
            "the hold took {took:?}"
        );
        // Each of the three probes took its whole bound.
        assert!(took >= 3 * PROBE_BOUND, "{took:?}");
        assert_eq!(radio.probe_times().len(), 3);
        assert_eq!(last(&radio), Some(Call::Disconnect(3)));
    }

    // A slow answer is an answer: it fails nothing as long as it is within the bound, and the next probe is a
    // period after it.
    #[tokio::test(start_paused = true)]
    async fn a_slow_answer_is_no_failure() {
        let (mut radio, link) = joined().await;
        radio
            .probe_answers
            .extend((0..5).map(|_| ProbeAnswer::Slow(secs(9))));
        radio.script.push_back(disconnects_after(secs(100)));
        let (lost, took, radio) = held_for(radio, link).await;
        assert!(matches!(lost, Lost::Disconnected { .. }), "{lost:?}");
        assert_eq!(took, secs(100));
        // Each of the first five takes 9 s, so they come at 10, 20, 30, 40 and 50 s and the rest at 60 s on.
        let times: Vec<u64> = radio.probe_times().iter().map(Duration::as_secs).collect();
        assert_eq!(&times[..5], [10, 20, 30, 40, 50]);
        assert_eq!(radio.commands(), joined_calls());
    }

    // The wait for events is not polled while a probe is made, and nothing that comes then is lost: it is the
    // next thing the hold takes.
    #[tokio::test(start_paused = true)]
    async fn an_event_that_comes_while_a_probe_is_made_is_not_lost() {
        let (mut radio, link) = joined().await;
        // The probe due at 10 s is answered at 15 s; the rekey is due at 12 s, in between.
        radio.probe_answers.push_back(ProbeAnswer::Slow(secs(5)));
        radio.script.push_back(Step::After(
            secs(12),
            RadioEvent::Frame(eapol::build(SPA, AA, ETHERTYPE_PAE, &G1)),
        ));
        radio.script.push_back(disconnected(3, false));
        let (lost, took, radio) = held_for(radio, link).await;
        assert_eq!(
            lost,
            Lost::Disconnected {
                reason: 3,
                by_ap: false
            }
        );
        assert_eq!(took, secs(15));
        // The rekey was answered and its key installed, once, right after the probe.
        assert_eq!(
            after_join(&radio),
            [
                to_ap(&G2),
                Call::InstallGroup {
                    key_id: 2,
                    key: GTK2,
                    rsc: hex!("0a0b0c0d0e0f")
                }
            ]
        );
        let answered = radio
            .calls
            .iter()
            .find(|(_, call)| *call == to_ap(&G2))
            .map(|(at, _)| *at);
        assert_eq!(answered, Some(secs(15)));
        assert_eq!(radio.probe_times(), [secs(10)]);
    }

    #[test]
    fn a_silent_radio_is_told_in_words() {
        assert_eq!(
            Lost::Silent("the radio is busy".into()).to_string(),
            "the radio stopped answering: the radio is busy"
        );
    }

    fn bss() -> Bss {
        Bss {
            bssid: AA,
            freq_mhz: 5180,
            signal_mbm: -5600,
            ies: hex!("000b546869734973415353494400").to_vec(),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_busy_radio_is_asked_again() {
        let second = std::time::Duration::from_secs;
        let mut radio = FakeRadio::new();
        radio.results = vec![bss()];
        radio
            .trigger_errors
            .extend([RadioError::Busy, RadioError::Busy]);
        radio.script.push_back(nl(Event::ScanDone));
        let found = scan(&mut radio, b"ThisIsASSID", &[]).await.unwrap();
        assert_eq!(found, [bss()]);
        assert_eq!(
            radio.calls,
            [
                (second(0), Call::TriggerScan),
                (second(1), Call::TriggerScan),
                (second(2), Call::TriggerScan),
                (second(2), Call::ScanResults)
            ]
        );

        let mut radio = FakeRadio::new();
        radio
            .trigger_errors
            .extend((0..5).map(|_| RadioError::Busy));
        let error = scan(&mut radio, b"ThisIsASSID", &[]).await.unwrap_err();
        assert!(matches!(error, JoinError::Scan(RadioError::Busy)));
        assert_eq!(radio.commands(), vec![Call::TriggerScan; 5]);

        // Any other error is final at once.
        let mut radio = FakeRadio::new();
        radio.trigger_errors.push_back(RadioError::NoInterface);
        let error = scan(&mut radio, b"ThisIsASSID", &[]).await.unwrap_err();
        assert!(matches!(error, JoinError::Scan(RadioError::NoInterface)));
        assert_eq!(radio.commands(), [Call::TriggerScan]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_scan_is_limited_to_the_channels_it_is_given() {
        let mut radio = FakeRadio::new();
        radio.results = vec![
            Bss {
                freq_mhz: 5180,
                ..bss()
            },
            Bss {
                freq_mhz: 2437,
                ..bss()
            },
        ];
        radio.script.push_back(nl(Event::ScanDone));
        let found = scan(&mut radio, b"ThisIsASSID", &[2437, 2412])
            .await
            .unwrap();
        assert_eq!(radio.scan_freqs, [vec![2437, 2412]]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].freq_mhz, 2437);
    }

    #[tokio::test(start_paused = true)]
    async fn a_scan_that_is_aborted_or_never_ends_is_an_error() {
        let mut radio = FakeRadio::new();
        radio.script.push_back(nl(Event::ScanAborted));
        let error = scan(&mut radio, b"ThisIsASSID", &[]).await.unwrap_err();
        assert!(matches!(error, JoinError::ScanAborted));

        let started = tokio::time::Instant::now();
        let mut radio = FakeRadio::new();
        radio.script.push_back(Step::Silence);
        let error = scan(&mut radio, b"ThisIsASSID", &[]).await.unwrap_err();
        assert!(matches!(error, JoinError::ScanTimeout));
        assert_eq!(started.elapsed(), SCAN_TIMEOUT);
        assert_eq!(error.to_string(), "the scan did not finish within 15 s");

        // Unrelated events, lost events among them, are ignored: the scan's deadline bounds the wait.
        let mut radio = FakeRadio::new();
        radio.results = vec![bss()];
        radio.script.extend([
            from_ap(&M1),
            nl(Event::Other(36)),
            Step::Event(RadioEvent::Overrun),
            nl(Event::ScanDone),
        ]);
        assert_eq!(
            scan(&mut radio, b"ThisIsASSID", &[]).await.unwrap(),
            [bss()]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_secret_reaches_the_log() {
        logging();
        let (mut radio, mut link) = joined().await;
        radio.script.extend([from_ap(&G1), disconnected(3, false)]);
        hold(&mut radio, &mut link).await;
        // Other tests log into the same buffer at the same time, which does no harm here.
        let text = log_text();
        assert!(text.contains("wifi: pairwise key installed"));
        assert!(text.contains("wifi: group key 2 installed"));
        for secret in [&PMK[..], &KCK, &KEK, &TK, &GTK1, &GTK2] {
            assert!(!text.contains(&hex(secret)), "a key is in the log");
        }
        assert!(!text.contains("ThisIsAPassword"));
    }
}
