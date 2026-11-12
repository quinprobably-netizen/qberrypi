//! WPA2-PSK supplicant for qberrypi: the station's side of the four-way
//! handshake and of the group-key handshake as a pure state machine, with the
//! key derivation and the frame codecs it stands on.
//!
//! The crate does no I/O: it owns no socket, clock or random source. The
//! caller hands [`Supplicant::handle`] each EAPOL-Key frame it receives and a
//! closure that yields a nonce, and gets back a [`Reply`] — the frame to send
//! and the keys to install — or a [`HandshakeError`], after which nothing in
//! the `Supplicant` has changed. Every byte that goes in can be sent by any
//! radio in range: no input makes a decoder panic, and no error repeats a
//! byte of a frame or of a key.
//!
//! In scope is WPA2-PSK with CCMP as pairwise and as group cipher and key
//! descriptor version 2 (HMAC-SHA1 for the MIC, AES key wrap for the key
//! data). A network outside it — a group cipher other than CCMP, no CCMP as
//! pairwise cipher, no PSK, or protected management frames required — is
//! refused before the first frame, with an error that says which.
//!
//! The modules, from the bottom: [`secret`] holds key bytes; [`pmk`] and
//! [`ptk`] derive the keys; [`eapol`] reads, writes and signs the frame;
//! [`keydata`] and [`rsne`] read its key data and the RSN element;
//! [`supplicant`] is the state machine over them, and its module
//! documentation lists the rules a frame must pass, in the order they are
//! applied.
//!
//! # The caller's contract
//!
//! 1. One [`Supplicant`] per association: create it when the kernel reports
//!    the connection, drop it on disconnect. Derive the [`Pmk`] once at
//!    start-up and clone it. `Pmk`, the keys in a `Reply` and the `Supplicant`
//!    wipe their key bytes when dropped; a copy the caller makes is the
//!    caller's to wipe.
//! 2. Hand `handle` only frames of ethertype `0x888e` whose source address is
//!    the access point's, starting at the 802.1X header. Bytes after the
//!    length that header declares are ignored, so link-layer padding may stay
//!    on.
//! 3. Transmit [`Reply::frame`] first, then install [`Reply::tk`] and
//!    [`Reply::gtk`]; never install a key that was not returned. A key is
//!    returned when it differs from the one handed out last (a group key: in
//!    its key id or in its bytes), so `tk` and `gtk` are `None` on a repeated
//!    message 3 or group message 1 that carries the same key: the caller
//!    installs exactly what is returned and nothing else.
//! 4. [`Params::own_rsne`] is the element the association request really
//!    carried (what the kernel reports), [`SUPPLICANT_RSNE`] if the firmware
//!    left it alone.
//! 5. The SNonce closure returns 32 bytes from the kernel's random source,
//!    fresh on every call. It is called only when a message 1 arrives and no
//!    handshake is under way.
//! 6. An error means: log it, drop the frame, keep the link. A link that drops
//!    while the phase is [`Phase::AwaitingMessage3`] most often means a wrong
//!    passphrase.
//! 7. Timeouts are the caller's, and they apply to
//!    [`Phase::AwaitingMessage1`] and [`Phase::AwaitingMessage3`] only;
//!    [`Phase::Established`] and [`Phase::Rekeying`] never time out.
//!    `Rekeying` is not a passing state: message 1 is not signed, so a forged
//!    one puts an established link there and it may stay there, and the
//!    installed keys stay valid throughout.
//! 8. Before associating, [`Rsne::parse`] and [`Rsne::check_access_point`]
//!    tell whether a scanned network is in scope, and their error is the log
//!    line. [`Supplicant::new`] makes the same check and refuses the same
//!    networks. It also refuses an own element that does not name CCMP as
//!    group cipher, exactly one pairwise suite (CCMP) and exactly one AKM
//!    (PSK), or that sets MFPR (protected management frames required) or
//!    MFPC (capable), so firmware or integration code that sets MFPC in the
//!    element it sends makes `Supplicant::new` fail.
//!
//! [`Supplicant`]: supplicant::Supplicant
//! [`Supplicant::new`]: supplicant::Supplicant::new
//! [`Supplicant::handle`]: supplicant::Supplicant::handle
//! [`Params::own_rsne`]: supplicant::Params::own_rsne
//! [`Reply`]: supplicant::Reply
//! [`Reply::frame`]: supplicant::Reply::frame
//! [`Reply::tk`]: supplicant::Reply::tk
//! [`Reply::gtk`]: supplicant::Reply::gtk
//! [`HandshakeError`]: supplicant::HandshakeError
//! [`Phase::AwaitingMessage1`]: supplicant::Phase::AwaitingMessage1
//! [`Phase::AwaitingMessage3`]: supplicant::Phase::AwaitingMessage3
//! [`Phase::Established`]: supplicant::Phase::Established
//! [`Phase::Rekeying`]: supplicant::Phase::Rekeying
//! [`Pmk`]: pmk::Pmk
//! [`Rsne::parse`]: rsne::Rsne::parse
//! [`Rsne::check_access_point`]: rsne::Rsne::check_access_point
//! [`SUPPLICANT_RSNE`]: rsne::SUPPLICANT_RSNE

#![forbid(unsafe_code)]

pub mod eapol;
pub mod keydata;
pub mod pmk;
pub mod ptk;
pub mod rsne;
pub mod secret;
pub mod supplicant;

#[cfg(test)]
#[path = "../tests/fixtures/reference.rs"]
mod reference;

/// An IEEE 802 MAC address, in transmission order.
pub type MacAddr = [u8; 6];

/// A handshake nonce: the ANonce of the access point or the SNonce of the station.
pub type Nonce = [u8; 32];

#[cfg(test)]
mod tests {
    use super::*;

    // IEEE Std 802.11-2016 Annex J.7.2, Table J-14: the keys the reference handshake must be built on.
    #[test]
    fn reference_fixture_uses_the_published_key_hierarchy() {
        use hex_literal::hex;
        assert_eq!(reference::KCK, hex!("379f9852d0199236b94e407ce4c00ec8"));
        assert_eq!(reference::KEK, hex!("47c9edc01c2c6e5b4910caddfb3e51a7"));
        assert_eq!(reference::TK, hex!("b2360c79e9710fdd58bea93deaf06599"));
        assert_eq!(
            reference::M3[81..97],
            hex!("225de9d7066ddf9622bb3bc46ba0ce45")
        );
    }
}
