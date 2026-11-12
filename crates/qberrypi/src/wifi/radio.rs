//! What the Wi-Fi logic needs of a radio: the kernel commands it sends, the
//! events and frames it waits for, and the keys it installs.
//!
//! `join` is written against this trait so that a scripted radio can stand
//! in for the kernel in tests, and so that the real one is only plumbing.
//!
//! The events carry frames of the handshake, and the commands carry its keys:
//! nothing here formats either for a log or for `Debug`.

use std::fmt;
use std::io;

use qb_wpa2::secret::SecretBytes;
use qb_wpa2::supplicant::GroupKey;
use qb_wpa2::{MacAddr, Nonce};

use super::choose::Candidate;
use crate::netlink::RequestError;
use crate::netlink::nl80211::{Bss, Event};

/// Why a radio command did not work.
#[derive(Debug)]
pub enum RadioError {
    /// The kernel is busy with something else, such as another scan; try again shortly.
    Busy,
    /// The wireless interface is not there.
    NoInterface,
    /// The radio does not know the access point as a station: its answer holds no such station.
    NoStation,
    /// A netlink request failed.
    Request(RequestError),
    /// Reading or writing a socket failed.
    Io(io::Error),
}

impl fmt::Display for RadioError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy => f.write_str("the radio is busy"),
            Self::NoInterface => f.write_str("the wireless interface is gone"),
            Self::NoStation => f.write_str("the radio does not know the access point as a station"),
            Self::Request(error) => error.fmt(f),
            Self::Io(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for RadioError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Busy | Self::NoInterface | Self::NoStation => None,
            Self::Request(error) => Some(error),
            Self::Io(error) => Some(error),
        }
    }
}

/// Something that happened on the radio.
#[derive(Clone, PartialEq, Eq)]
pub enum RadioEvent {
    /// The kernel announced something about the interface.
    Nl(Event),
    /// A whole Ethernet frame arrived on the handshake's ethertype.
    Frame(Vec<u8>),
    /// Events were lost: the kernel's queue overflowed.
    Overrun,
}

// By hand, to leave out the frame: a frame of the handshake is not for a log.
impl fmt::Debug for RadioEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nl(event) => f.debug_tuple("Nl").field(event).finish(),
            Self::Frame(frame) => f
                .debug_tuple("Frame")
                .field(&format_args!("<{} bytes>", frame.len()))
                .finish(),
            Self::Overrun => f.write_str("Overrun"),
        }
    }
}

/// A Wi-Fi interface, as `join` drives it.
///
/// Every command returns within a bound: twice the netlink reply timeout (once for the send, once
/// for the reply), for the kernel radio. Only `next_event` waits as long as there is nothing to report.
#[allow(async_fn_in_trait)]
pub trait Radio {
    /// The address of this station.
    fn station(&self) -> MacAddr;

    /// A fresh handshake nonce from the kernel's random source.
    fn nonce(&mut self) -> Result<Nonce, RadioError>;

    /// Starts a scan for `ssid`, a directed one; its end arrives as an event.
    ///
    /// The scan covers every channel when `freqs_mhz` is empty, and only the channels with these centre
    /// frequencies otherwise. A radio that has no channel at one of them may refuse the request, as
    /// the kernel does (`EINVAL`): that is an error like any other the command has.
    async fn trigger_scan(&mut self, ssid: &[u8], freqs_mhz: &[u32]) -> Result<(), RadioError>;

    /// The access points the last scan found.
    async fn scan_results(&mut self) -> Result<Vec<Bss>, RadioError>;

    /// Asks the kernel to associate with `candidate`, a network called `ssid`; the outcome arrives as an event.
    async fn connect(&mut self, ssid: &[u8], candidate: &Candidate) -> Result<(), RadioError>;

    /// Asks the radio about the access point `peer` the station is joined to, which proves the radio
    /// itself still answers: `Ok` only if the answer describes `peer` as a station.
    ///
    /// The query is for the radio's own state of the association and needs no traffic on the link, so a
    /// quiet link that is healthy answers it. The error is whatever kept the radio from saying so: a
    /// refusal (an access point it has no station for is `ENOENT`), a busy radio, no answer within
    /// the bound, or [`RadioError::NoStation`] for an answer about another station or none. `hold`
    /// asks this every `PROBE_EVERY` and gives the link up after `PROBE_FAILURES` failures in a row.
    async fn probe(&mut self, peer: MacAddr) -> Result<(), RadioError>;

    /// Leaves the network, with an 802.11 reason code.
    async fn disconnect(&mut self, reason: u16) -> Result<(), RadioError>;

    /// Waits for the next event or frame. Dropping the future loses nothing.
    async fn next_event(&mut self) -> Result<RadioEvent, RadioError>;

    /// Sends a whole Ethernet frame; it does not wait.
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), RadioError>;

    /// Installs the pairwise key for the access point `peer`.
    async fn install_pairwise(
        &mut self,
        peer: MacAddr,
        tk: &SecretBytes<16>,
    ) -> Result<(), RadioError>;

    /// Installs a group key.
    async fn install_group(&mut self, key: &GroupKey) -> Result<(), RadioError>;

    /// Opens the controlled port to the access point `peer`: data frames may flow.
    async fn authorize(&mut self, peer: MacAddr) -> Result<(), RadioError>;
}
