//! The radio over the real kernel: nl80211 for the commands and the events,
//! and a packet socket for the handshake's frames.
//!
//! Every command goes through the netlink client, whose waits are bounded by
//! the netlink reply timeout (one for the send and one for the reply), so no
//! command here waits for ever. The sockets are the offloaded kind: the driver
//! runs a command inside the send, and a radio that does not answer holds the
//! sender for seconds, which must be a thread of its own and not the
//! runtime's, where DNS is answered. The keys go from the caller's `expose()`d bytes straight into the request builder,
//! which the socket wipes once the request is sent; no key is copied, logged
//! or formatted, and the frames waiting in the queue are never printed.

use std::collections::VecDeque;
use std::fmt;

use qb_wpa2::rsne::SUPPLICANT_RSNE;
use qb_wpa2::secret::SecretBytes;
use qb_wpa2::supplicant::GroupKey;
use qb_wpa2::{MacAddr, Nonce};

use super::choose::Candidate;
use super::eapol::{ETHERTYPE_PAE, LinkSocket};
use super::mac;
use super::radio::{Radio, RadioError, RadioEvent};
use crate::fault;
use crate::netlink::RequestError;
use crate::netlink::nl80211::{
    self, Bss, ConnectTarget, Nl80211, parse_bss, parse_station, set_power_save_off,
    set_station_authorized,
};
use crate::netlink::route::Route;
use crate::sys;

/// The error numbers the kernel answers a scan request with when it cannot take one now.
const BUSY: [i32; 2] = [libc::EBUSY, libc::EAGAIN];

/// The error number of a disconnect from a network the station is not on.
const NOT_CONNECTED: i32 = libc::ENOTCONN;

/// A Wi-Fi interface of this machine, driven through nl80211.
pub struct KernelRadio {
    nl: Nl80211,
    link: LinkSocket,
    ifindex: u32,
    station: MacAddr,
    /// What has been read from the sockets and not returned by `next_event` yet, in order.
    queue: VecDeque<RadioEvent>,
}

// By hand, to leave out the queue: a frame of the handshake is not for a log.
impl fmt::Debug for KernelRadio {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KernelRadio")
            .field("ifindex", &self.ifindex)
            .field("station", &self.station)
            .field("queued", &self.queue.len())
            .finish_non_exhaustive()
    }
}

impl KernelRadio {
    /// Opens the interface called `ifname`: sets it up if it is not, turns its power save off, and starts
    /// listening for its events and for the handshake's frames.
    ///
    /// The route socket that sets the link up and the nl80211 command socket are offloaded: their
    /// requests are sent by threads of their own, so that a radio that stops answering holds those
    /// and not the runtime's.
    ///
    /// `RadioError::NoInterface` if there is no such interface. A power save that cannot be turned off is
    /// a warning and no failure.
    ///
    /// # Panics
    ///
    /// Outside a tokio runtime.
    pub async fn open(ifname: &str) -> Result<Self, RadioError> {
        let mut route = Route::open_offloaded().map_err(RadioError::Io)?;
        let link = route
            .link(ifname)
            .await
            .map_err(RadioError::Request)?
            .ok_or(RadioError::NoInterface)?;
        if !link.is_up() {
            route
                .set_up(link.index)
                .await
                .map_err(RadioError::Request)?;
        }
        log::info!("wifi: {ifname} is up, station {}", mac(&link.mac));

        let mut nl = Nl80211::open_offloaded()
            .await
            .map_err(RadioError::Request)?;
        let family = nl.family();
        match nl.request(set_power_save_off(family, link.index)).await {
            Ok(_) => log::info!("wifi: power save off"),
            Err(error) => log::warn!("wifi: could not turn power save off: {error}"),
        }

        let socket = LinkSocket::open(link.index, ETHERTYPE_PAE).map_err(RadioError::Io)?;
        Ok(Self {
            nl,
            link: socket,
            ifindex: link.index,
            station: link.mac,
            queue: VecDeque::new(),
        })
    }

    /// Whether the command socket's requests are sent by a thread of its own.
    #[cfg(test)]
    pub(crate) fn is_offloaded(&self) -> bool {
        self.nl.is_offloaded()
    }

    /// Sends a request that has no reply of interest, and says how it went.
    async fn command(&mut self, message: crate::netlink::MsgBuilder) -> Result<(), RadioError> {
        self.nl
            .request(message)
            .await
            .map(drop)
            .map_err(RadioError::Request)
    }
}

/// Whether the kernel refused a request with the error number `errno`.
fn refused_with(error: &RequestError, errnos: &[i32]) -> bool {
    error.errno().is_some_and(|errno| errnos.contains(&errno))
}

impl Radio for KernelRadio {
    fn station(&self) -> MacAddr {
        self.station
    }

    fn nonce(&mut self) -> Result<Nonce, RadioError> {
        let mut nonce = [0; 32];
        sys::random_bytes(&mut nonce).map_err(RadioError::Io)?;
        Ok(nonce)
    }

    async fn trigger_scan(&mut self, ssid: &[u8]) -> Result<(), RadioError> {
        let message = nl80211::trigger_scan(self.nl.family(), self.ifindex, ssid);
        match self.nl.request(message).await {
            Ok(_) => Ok(()),
            Err(error) if refused_with(&error, &BUSY) => Err(RadioError::Busy),
            Err(error) => Err(RadioError::Request(error)),
        }
    }

    async fn scan_results(&mut self) -> Result<Vec<Bss>, RadioError> {
        let message = nl80211::get_scan(self.nl.family(), self.ifindex);
        let replies = self
            .nl
            .request(message)
            .await
            .map_err(RadioError::Request)?;
        Ok(replies
            .iter()
            .filter_map(|reply| parse_bss(reply))
            .collect())
    }

    async fn connect(&mut self, ssid: &[u8], candidate: &Candidate) -> Result<(), RadioError> {
        // A new join follows the end of every hold: a probe muted by the development fault is over.
        fault::mute().hold_over();
        let target = ConnectTarget {
            ssid,
            bssid: candidate.bssid,
            freq_mhz: candidate.freq_mhz,
            rsne: &SUPPLICANT_RSNE,
        };
        let message = nl80211::connect(self.nl.family(), self.ifindex, &target);
        self.command(message).await
    }

    async fn probe(&mut self, peer: MacAddr) -> Result<(), RadioError> {
        // The development fault `mute-probe` fails the probe as if the firmware did not answer, and sends no
        // command; in use the switch is off, and this is one load.
        fault::mute().probe()?;
        // A query the driver answers from the radio's own state of the association; for a firmware that
        // does not answer it is the send or the reply that times out, within the request's bound.
        let message = nl80211::get_station(self.nl.family(), self.ifindex, peer);
        let replies = self
            .nl
            .request(message)
            .await
            .map_err(RadioError::Request)?;
        if replies
            .iter()
            .any(|reply| parse_station(reply) == Some(peer))
        {
            Ok(())
        } else {
            Err(RadioError::NoStation)
        }
    }

    async fn disconnect(&mut self, reason: u16) -> Result<(), RadioError> {
        let message = nl80211::disconnect(self.nl.family(), self.ifindex, reason);
        match self.nl.request(message).await {
            Ok(_) => Ok(()),
            Err(error) if refused_with(&error, &[NOT_CONNECTED]) => Ok(()),
            Err(error) => Err(RadioError::Request(error)),
        }
    }

    async fn next_event(&mut self) -> Result<RadioEvent, RadioError> {
        // Both sockets keep what they have until a call returns it, so the loser of the race, and a future
        // dropped by the caller, lose nothing. What is read goes onto the queue first and comes out in order.
        loop {
            if let Some(event) = self.queue.pop_front() {
                return Ok(event);
            }
            tokio::select! {
                frame = self.link.recv() => {
                    let frame = frame.map_err(RadioError::Io)?;
                    self.queue.push_back(RadioEvent::Frame(frame));
                }
                events = self.nl.events(self.ifindex) => match events {
                    // A datagram may hold nothing about this interface: the loop reads again.
                    Ok(events) => self.queue.extend(events.into_iter().map(RadioEvent::Nl)),
                    Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => {
                        self.queue.push_back(RadioEvent::Overrun);
                    }
                    Err(error) => return Err(RadioError::Io(error)),
                },
            }
        }
    }

    fn send_frame(&mut self, frame: &[u8]) -> Result<(), RadioError> {
        self.link.send(frame).map_err(RadioError::Io)
    }

    async fn install_pairwise(
        &mut self,
        peer: MacAddr,
        tk: &SecretBytes<16>,
    ) -> Result<(), RadioError> {
        let message = nl80211::new_pairwise_key(self.nl.family(), self.ifindex, peer, tk.expose());
        self.command(message).await
    }

    async fn install_group(&mut self, key: &GroupKey) -> Result<(), RadioError> {
        let message = nl80211::new_group_key(
            self.nl.family(),
            self.ifindex,
            key.key_id,
            key.key.expose(),
            &key.rsc,
        );
        self.command(message).await
    }

    async fn authorize(&mut self, peer: MacAddr) -> Result<(), RadioError> {
        let message = set_station_authorized(self.nl.family(), self.ifindex, peer);
        self.command(message).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kernel_refuses_a_radio_that_is_not_there() {
        crate::testns::run_inside("wifi::kernel::tests::ns_no_radio");
    }

    #[tokio::test]
    #[ignore = "run by the_kernel_refuses_a_radio_that_is_not_there, inside a namespace"]
    async fn ns_no_radio() {
        if !crate::testns::inside() {
            return;
        }
        // The sockets the open asks for are offloaded ones: counted, as the open is no more than
        // its result when there is no radio to look at.
        let opened = crate::netlink::socket::offloaded_opens();
        assert!(matches!(
            KernelRadio::open("nosuch0").await,
            Err(RadioError::NoInterface)
        ));
        // The route socket, and no more: the open stopped at the lookup.
        assert_eq!(crate::netlink::socket::offloaded_opens() - opened, 1);

        // `lo` is no wireless interface. With a wireless stack the open goes through, the power save command
        // being only a warning; without one it fails at the lookup of nl80211. Either way it is no panic, and
        // `lo` was set up first.
        let opened = crate::netlink::socket::offloaded_opens();
        let radio = KernelRadio::open("lo").await;
        // The route socket and nl80211's command socket, whether or not the lookup found the family.
        assert_eq!(crate::netlink::socket::offloaded_opens() - opened, 2);
        if let Ok(radio) = &radio {
            assert!(radio.is_offloaded());
        }
        drop(radio);
        let mut route = Route::open().unwrap();
        let lo = route.link("lo").await.unwrap().unwrap();
        assert!(lo.is_up());
    }
}
