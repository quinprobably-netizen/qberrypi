//! The supplicant: the station's side of the four-way handshake and of the
//! group-key handshake (IEEE Std 802.11-2016 12.7.6 and 12.7.7) as a state
//! machine that owns no socket, clock or random source.
//!
//! The caller hands `Supplicant::handle` each EAPOL-Key frame it receives and
//! a closure that yields a fresh nonce. It gets back the frame to send and the
//! keys to install, or an error.
//!
//! Every frame comes from any radio in range. `handle` applies its rules in a
//! fixed order and returns at the first one a frame breaks, and on any error
//! nothing in the `Supplicant` has changed: the rules are checked by functions
//! that only read the state, and `handle` writes to it in one place, after the
//! last check has passed and the reply is built. Until the MIC of a frame has
//! verified, nothing the frame says is kept, with one exception the protocol
//! forces: message 1 is not signed, so its ANonce starts a pending handshake.
//! It never touches the installed keys or the replay counter.
//!
//! The rules, by the numbers the comments below use. Every frame:
//!
//! 1. It decodes as an EAPOL-Key frame with an RSN key descriptor.
//! 2. Its key descriptor version is 2.
//! 3. It has Ack and none of Request, Error and SMK: an access point sent it.
//! 4. Its flags make it message 1 (Pairwise, neither MIC nor Install),
//!    message 3 (Pairwise and MIC) or a group message (MIC without Pairwise).
//! 5. Its replay counter is greater than the one on record, if there is one.
//!
//! Every key:
//!
//! 6. It is handed to the caller only if it differs from the one handed out
//!    last. The pairwise key and the group key (key id and key) handed out
//!    last are remembered, one of each, and a reply leaves out a key equal to
//!    the remembered one. A repeated message 3 or group message is therefore
//!    answered again, without the key: a key installed twice starts its packet
//!    numbers again, which is the key reinstallation attack. A group key that
//!    the access point sends again after a different one was handed out in
//!    between is handed out again.
//!
//! Message 1, in any phase:
//!
//! 7. The SNonce is that of the pending handshake if there is one; otherwise
//!    the caller is asked for it, and at no other time.
//! 8. The PTK is derived from the frame's nonce and the SNonce. It and the two
//!    nonces are the pending handshake from now on, in place of any earlier.
//!    Established keys are not touched: they stay in use beside it.
//! 9. The reply is message 2: the frame's replay counter, the SNonce and the
//!    station's RSN element, signed with the pending KCK. No keys.
//!
//! Message 3:
//!
//! 10. It may belong to the pending handshake or, as a repeat, to the
//!     established keys: there is at least one of the two, and the frame
//!     carries the ANonce of at least one.
//! 11. The MIC of the frame verifies under the KCK of one whose ANonce it
//!     carries; the pending handshake is tried first. The rules below use
//!     the keys of that one and of no other.
//! 12. The frame has Install and Encrypted, and its key length is 16.
//! 13. Its key data unwraps under the KEK and parses.
//! 14. The key data repeats the RSN element the access point advertised, byte
//!     for byte, and holds a group key.
//! 15. The frame's replay counter goes on record. If the keys are those of
//!     the pending handshake, it becomes the established keys; if they are
//!     the established keys, a pending handshake stays as it is. The reply is
//!     message 4, signed with the KCK, with the pairwise key and the group
//!     key to install once it is sent, as far as rule 6 allows.
//!
//! Group message:
//!
//! 16. Keys are established.
//! 17. The MIC of the frame verifies under the established KCK. The keys of a
//!     pending handshake are not tried.
//! 18. The frame has Encrypted, and its key data unwraps under the established
//!     KEK, parses and holds a group key. The key length field is not looked
//!     at: access points send 0 or 16.
//! 19. The frame's replay counter goes on record, and the phase stays. The
//!     reply is message 2 of the group-key handshake, signed with the
//!     established KCK, with the group key to install, as far as rule 6
//!     allows.

use std::fmt;

use crate::eapol::{self, EapolKey, FrameError, KeyInfo};
use crate::keydata::{self, GtkKde, KeyData, KeyDataError};
use crate::pmk::Pmk;
use crate::ptk::Ptk;
use crate::rsne::{self, Rsne, RsneError};
use crate::secret::SecretBytes;
use crate::{MacAddr, Nonce};

/// The one key descriptor version this crate speaks: HMAC-SHA1 for the MIC and AES key wrap for the key data.
const DESCRIPTOR_VERSION: u8 = 2;

/// The 802.1X protocol version of the frames a station sends; `wpa_supplicant` sends the same.
const REPLY_PROTOCOL_VERSION: u8 = 1;

/// The key information of message 2, and of message 4 before its Secure bit: version 2, Pairwise and MIC, `0x010a`.
const REPLY_INFO: u16 = DESCRIPTOR_VERSION as u16 | KeyInfo::PAIRWISE | KeyInfo::MIC;

/// The key information of message 2 of the group-key handshake: version 2, MIC and Secure, `0x0302`.
const GROUP_REPLY_INFO: u16 = DESCRIPTOR_VERSION as u16 | KeyInfo::MIC | KeyInfo::SECURE;

/// The flags only a station sets, or that belong to a handshake this crate does not speak.
const NEVER_FROM_ACCESS_POINT: u16 = KeyInfo::REQUEST | KeyInfo::ERROR | KeyInfo::SMK;

/// The key length message 3 must announce: that of the CCMP temporal key.
const CCMP_KEY_LEN: u16 = 16;

/// What a handshake needs to know about the network and the station before the first frame.
#[derive(Debug, Clone)]
pub struct Params {
    /// The pairwise master key of the network.
    pub pmk: Pmk,
    /// The address of the access point (its BSSID).
    pub aa: MacAddr,
    /// The address of this station.
    pub spa: MacAddr,
    /// The RSN element of the access point's beacon or probe response, whole.
    pub ap_rsne: Vec<u8>,
    /// The RSN extension element of the same beacon or probe response, whole, if it advertised one.
    pub ap_rsnxe: Option<Vec<u8>>,
    /// The RSN element this station sent in its association request, whole.
    pub own_rsne: Vec<u8>,
}

/// The keys of one handshake and the access point's nonce they were derived from.
#[derive(Debug, Clone)]
struct Keys {
    /// The ANonce.
    anonce: Nonce,
    /// The PTK derived from the ANonce and the SNonce of the handshake.
    ptk: Ptk,
}

/// A handshake that message 1 has started and message 3 has not yet confirmed.
#[derive(Debug)]
struct Pending {
    /// The SNonce: every message 2 of this handshake carries it.
    snonce: Nonce,
    /// The keys the handshake will establish.
    keys: Keys,
}

/// A group key as rule 6 remembers it: by key id and key, since the same key under another key id is another key to install.
#[derive(Debug)]
struct HandedGtk {
    /// The key id it was handed out under.
    key_id: u8,
    /// The group temporal key.
    key: SecretBytes<16>,
}

/// The station's side of the WPA2 handshakes with one access point.
#[derive(Debug)]
pub struct Supplicant {
    /// The network and the station, as checked by `new`.
    params: Params,
    /// The handshake under way, if any.
    pending: Option<Pending>,
    /// The keys of the last completed handshake, if any.
    established: Option<Keys>,
    /// The replay counter of the last frame whose MIC verified, if any.
    replay_counter: Option<u64>,
    /// The pairwise key handed to the caller last, if any: a reply does not carry it again.
    handed_tk: Option<SecretBytes<16>>,
    /// The group key handed to the caller last, if any: a reply does not carry it again.
    handed_gtk: Option<HandedGtk>,
}

/// Where a `Supplicant` stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// No keys yet, and no handshake under way.
    AwaitingMessage1,
    /// Message 2 has been sent; no keys yet.
    AwaitingMessage3,
    /// The keys have been handed out, and no handshake is under way.
    Established,
    /// The keys have been handed out, and a second handshake is under way beside them.
    Rekeying,
}

/// Which frame a `Reply` is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyKind {
    /// Message 2 of the four-way handshake.
    Message2,
    /// Message 4 of the four-way handshake.
    Message4,
    /// Message 2 of the group-key handshake.
    GroupMessage2,
}

/// The answer to an accepted frame: what to send, then what to install.
#[derive(Debug)]
pub struct Reply {
    /// Which frame this is.
    pub kind: ReplyKind,
    /// The frame to transmit, before any key is installed.
    pub frame: Vec<u8>,
    /// The pairwise key to install once the frame is sent, if the frame completed a handshake with a key not handed out before.
    pub tk: Option<SecretBytes<16>>,
    /// The group key to install once the frame is sent, if the access point delivered one not handed out before.
    pub gtk: Option<GroupKey>,
    /// Something the caller should log although the frame was accepted.
    pub warning: Option<Warning>,
}

/// A group key and what the driver needs to install it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupKey {
    /// The key id, 0 to 3.
    pub key_id: u8,
    /// Whether the station may send under the key as well as receive.
    pub tx: bool,
    /// The packet number the key has reached, least significant byte first.
    pub rsc: [u8; 6],
    /// The group temporal key.
    pub key: SecretBytes<16>,
}

/// What was odd about a frame that was accepted all the same.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Warning {
    /// The RSN extension element of message 3 is not the one the access point advertised.
    RsnxeMismatch,
}

/// The three frames an access point sends, told apart by their key information.
enum Message {
    /// Message 1 of the four-way handshake.
    One,
    /// Message 3 of the four-way handshake.
    Three,
    /// A message of the group-key handshake.
    Group,
}

/// Whose keys verified a message 3.
enum Candidate {
    /// Those of the handshake under way: the frame completes it.
    Pending,
    /// The established ones: the frame repeats the message 3 that established them.
    Established,
}

/// What an accepted frame changes, the keys its reply hands out apart: `handle` remembers those from the reply
/// itself. The functions that check a frame return a `Transition` and `handle` applies it.
enum Transition {
    /// Message 1: a pending handshake, in place of any earlier one.
    Started(Pending),
    /// Message 3 of the pending handshake: it has become these keys, and the frame's replay counter goes on record.
    Completed {
        /// The keys now established.
        keys: Keys,
        /// The replay counter of the frame, whose MIC verified.
        replay_counter: u64,
    },
    /// A repeated message 3 or a group message, under the established keys: only the replay counter moves.
    Answered {
        /// The replay counter of the frame, whose MIC verified.
        replay_counter: u64,
    },
}

impl Supplicant {
    /// Refuses a network or an own element outside the scope of this crate, before any frame is handled.
    pub fn new(params: Params) -> Result<Self, HandshakeError> {
        Rsne::parse(&params.ap_rsne)
            .and_then(|rsne| rsne.check_access_point())
            .map_err(HandshakeError::ApRsne)?;
        Rsne::parse(&params.own_rsne)
            .and_then(|rsne| rsne.check_supplicant())
            .map_err(HandshakeError::OwnRsne)?;
        Ok(Self {
            params,
            pending: None,
            established: None,
            replay_counter: None,
            handed_tk: None,
            handed_gtk: None,
        })
    }

    /// Where the handshake stands.
    pub fn phase(&self) -> Phase {
        match (&self.pending, &self.established) {
            (None, None) => Phase::AwaitingMessage1,
            (Some(_), None) => Phase::AwaitingMessage3,
            (None, Some(_)) => Phase::Established,
            (Some(_), Some(_)) => Phase::Rekeying,
        }
    }

    /// Handles one received frame; `snonce` is called only if a new handshake needs its nonce.
    pub fn handle(
        &mut self,
        frame: &[u8],
        snonce: impl FnOnce() -> Nonce,
    ) -> Result<Reply, HandshakeError> {
        // Rule 1. Nothing in `key` is authenticated: the rules below only compare its fields until the MIC
        // has verified.
        let key = EapolKey::decode(frame)?;
        // Rule 2.
        if key.info.version() != DESCRIPTOR_VERSION {
            return Err(HandshakeError::KeyVersion);
        }
        // Rule 3.
        if key.info.0 & NEVER_FROM_ACCESS_POINT != 0 || !key.info.has(KeyInfo::ACK) {
            return Err(HandshakeError::UnexpectedFlags);
        }
        // Rule 4.
        let message = match (
            key.info.has(KeyInfo::PAIRWISE),
            key.info.has(KeyInfo::MIC),
            key.info.has(KeyInfo::INSTALL),
        ) {
            (true, false, false) => Message::One,
            (true, true, _) => Message::Three,
            (false, true, _) => Message::Group,
            (true, false, true) | (false, false, _) => return Err(HandshakeError::UnexpectedFlags),
        };
        // Rule 5. The counter on record comes from frames whose MIC verified, and from nothing else.
        if self
            .replay_counter
            .is_some_and(|recorded| key.replay_counter <= recorded)
        {
            return Err(HandshakeError::Replay);
        }
        let (reply, transition) = match message {
            Message::One => self.message_1(&key, snonce)?,
            Message::Three => self.message_3(frame, &key)?,
            Message::Group => self.group_message(frame, &key)?,
        };

        // The frame has passed every check and its reply is built. Only here, where no error can follow,
        // does `self` change.
        match transition {
            Transition::Started(pending) => self.pending = Some(pending),
            Transition::Completed {
                keys,
                replay_counter,
            } => {
                self.pending = None;
                self.established = Some(keys);
                self.replay_counter = Some(replay_counter);
            }
            Transition::Answered { replay_counter } => self.replay_counter = Some(replay_counter),
        }
        // Rule 6, the remembering half. What is remembered is read off the reply the caller is about to get,
        // so it is what was handed out and nothing else.
        if let Some(tk) = &reply.tk {
            self.handed_tk = Some(tk.clone());
        }
        if let Some(GroupKey { key_id, key, .. }) = &reply.gtk {
            self.handed_gtk = Some(HandedGtk {
                key_id: *key_id,
                key: key.clone(),
            });
        }
        Ok(reply)
    }

    /// Rule 6 for a pairwise key: `tk` for the caller, unless it is the key handed out last.
    fn tk_to_hand_out(&self, tk: &SecretBytes<16>) -> Option<SecretBytes<16>> {
        // `SecretBytes` compares in constant time.
        let handed_before = self.handed_tk.as_ref().is_some_and(|last| last == tk);
        (!handed_before).then(|| tk.clone())
    }

    /// Rule 6 for a group key: the key of `gtk` for the caller, with the first six bytes of the frame's RSC,
    /// unless key id and key are those handed out last.
    fn gtk_to_hand_out(&self, gtk: GtkKde, rsc: [u8; 8]) -> Option<GroupKey> {
        let GtkKde { key_id, tx, key } = gtk;
        // The key id is no secret: every group-addressed data frame names it. The keys are compared in
        // constant time, by `SecretBytes`.
        let handed_before = self
            .handed_gtk
            .as_ref()
            .is_some_and(|last| last.key_id == key_id && last.key == key);
        if handed_before {
            return None;
        }
        let [rsc0, rsc1, rsc2, rsc3, rsc4, rsc5, _, _] = rsc;
        Some(GroupKey {
            key_id,
            tx,
            rsc: [rsc0, rsc1, rsc2, rsc3, rsc4, rsc5],
            key,
        })
    }

    /// Rules 7 to 9: answers message 1 with message 2, and starts or restarts the pending handshake.
    fn message_1(
        &self,
        key: &EapolKey,
        snonce: impl FnOnce() -> Nonce,
    ) -> Result<(Reply, Transition), HandshakeError> {
        // Rule 7. One SNonce per handshake: a message 3 that answers an earlier message 2 still verifies.
        let snonce = match &self.pending {
            Some(pending) => pending.snonce,
            None => snonce(),
        };
        // Rule 8. Message 1 is not signed, so its ANonce is whatever the sender chose. It is believed only
        // as far as starting a handshake, which completes only if a message 3 verifies under this PTK.
        let ptk = Ptk::derive(
            &self.params.pmk,
            &self.params.aa,
            &self.params.spa,
            &key.nonce,
            &snonce,
        );
        // Rule 9.
        let frame = reply_frame(
            &ptk,
            REPLY_INFO,
            key.replay_counter,
            snonce,
            self.params.own_rsne.clone(),
        )?;
        let reply = Reply {
            kind: ReplyKind::Message2,
            frame,
            tk: None,
            gtk: None,
            warning: None,
        };
        let pending = Pending {
            snonce,
            keys: Keys {
                anonce: key.nonce,
                ptk,
            },
        };
        Ok((reply, Transition::Started(pending)))
    }

    /// Rules 10 to 15: verifies message 3, answers it with message 4 and hands out the keys not handed out before.
    fn message_3(
        &self,
        frame: &[u8],
        key: &EapolKey,
    ) -> Result<(Reply, Transition), HandshakeError> {
        // Rule 10. The candidates: the handshake under way, and the established keys for a message 3 the
        // access point repeats because message 4 did not reach it.
        let pending = self.pending.as_ref().map(|pending| &pending.keys);
        let established = self.established.as_ref();
        if pending.is_none() && established.is_none() {
            return Err(HandshakeError::WrongPhase);
        }
        // Nonces are public, so the comparison need not be constant-time.
        let carries_anonce = |keys: &&Keys| keys.anonce == key.nonce;
        let pending = pending.filter(carries_anonce);
        let established = established.filter(carries_anonce);
        if pending.is_none() && established.is_none() {
            return Err(HandshakeError::AnonceMismatch);
        }
        // Rule 11, over the bytes as received. Both candidates can be left when a message 1 has repeated the
        // established ANonce; the frame then belongs to the one whose KCK signed it.
        let verifies = |keys: &&Keys| mic_verifies(&keys.ptk, frame);
        let (keys, candidate) = if let Some(keys) = pending.filter(verifies) {
            (keys, Candidate::Pending)
        } else if let Some(keys) = established.filter(verifies) {
            (keys, Candidate::Established)
        } else {
            return Err(HandshakeError::BadMic);
        };
        // From here on the frame is known to come from a holder of the PMK, and `keys` are the ones it was
        // signed with: the KEK below and the KCK of the reply are theirs. Rule 12.
        if !key.info.has(KeyInfo::INSTALL) {
            return Err(HandshakeError::InstallNotSet);
        }
        if !key.info.has(KeyInfo::ENCRYPTED) {
            return Err(HandshakeError::NotEncrypted);
        }
        if key.key_length != CCMP_KEY_LEN {
            return Err(HandshakeError::KeyLength);
        }
        // Rule 13. The unwrapped key data is wiped when `plain` drops.
        let plain = keydata::unwrap_key_data(keys.ptk.kek().expose(), &key.key_data)?;
        let KeyData { rsne, rsnxe, gtk } = keydata::parse_key_data(&plain)?;
        // Rule 14. The downgrade check: message 3 must repeat, byte for byte, the element the choice of
        // ciphers was made from. Both elements are public, so the comparison need not be constant-time.
        if rsne.as_deref() != Some(self.params.ap_rsne.as_slice()) {
            return Err(HandshakeError::RsneMismatch);
        }
        let Some(gtk) = gtk else {
            return Err(HandshakeError::GtkMissing);
        };
        // Rule 15. The TK of the established keys is the one handed out last, so a repeated message 3 gets
        // none; so does a handshake that arrives at that same key again.
        let frame = reply_frame(
            &keys.ptk,
            REPLY_INFO | (key.info.0 & KeyInfo::SECURE),
            key.replay_counter,
            [0; 32],
            Vec::new(),
        )?;
        let rsnxe_matches = rsne::rsnxe_matches(self.params.ap_rsnxe.as_deref(), rsnxe.as_deref());
        let reply = Reply {
            kind: ReplyKind::Message4,
            frame,
            tk: self.tk_to_hand_out(keys.ptk.tk()),
            gtk: self.gtk_to_hand_out(gtk, key.rsc),
            warning: (!rsnxe_matches).then_some(Warning::RsnxeMismatch),
        };
        let transition = match candidate {
            Candidate::Pending => Transition::Completed {
                keys: keys.clone(),
                replay_counter: key.replay_counter,
            },
            Candidate::Established => Transition::Answered {
                replay_counter: key.replay_counter,
            },
        };
        Ok((reply, transition))
    }

    /// Rules 16 to 19: verifies a group message, answers it and hands out its group key if not handed out before.
    fn group_message(
        &self,
        frame: &[u8],
        key: &EapolKey,
    ) -> Result<(Reply, Transition), HandshakeError> {
        // Rule 16.
        let Some(keys) = &self.established else {
            return Err(HandshakeError::WrongPhase);
        };
        // Rule 17, over the bytes as received. Only the keys in use sign a group message: those of a pending
        // handshake stand on an ANonce nobody has vouched for yet.
        if !mic_verifies(&keys.ptk, frame) {
            return Err(HandshakeError::BadMic);
        }
        // From here on the frame is known to come from the holder of the established keys. Rule 18.
        if !key.info.has(KeyInfo::ENCRYPTED) {
            return Err(HandshakeError::NotEncrypted);
        }
        // The unwrapped key data is wiped when `plain` drops.
        let plain = keydata::unwrap_key_data(keys.ptk.kek().expose(), &key.key_data)?;
        let KeyData { gtk, .. } = keydata::parse_key_data(&plain)?;
        let Some(gtk) = gtk else {
            return Err(HandshakeError::GtkMissing);
        };
        // Rule 19.
        let frame = reply_frame(
            &keys.ptk,
            GROUP_REPLY_INFO,
            key.replay_counter,
            [0; 32],
            Vec::new(),
        )?;
        let reply = Reply {
            kind: ReplyKind::GroupMessage2,
            frame,
            tk: None,
            gtk: self.gtk_to_hand_out(gtk, key.rsc),
            warning: None,
        };
        let transition = Transition::Answered {
            replay_counter: key.replay_counter,
        };
        Ok((reply, transition))
    }
}

/// Whether the MIC `frame` carries, over its bytes as received, is the one the KCK of `ptk` gives it.
///
/// The one place this file asks: `Ok(false)` is a forged frame, and an `Err` cannot occur for a frame `decode`
/// has accepted and counts as forged alike.
fn mic_verifies(ptk: &Ptk, frame: &[u8]) -> bool {
    match eapol::verify_mic(ptk.kck().expose(), frame) {
        Ok(true) => true,
        Ok(false) | Err(_) => false,
    }
}

/// A frame of the station, signed with the KCK of `ptk`: key length 0, and zeros in every field not given.
fn reply_frame(
    ptk: &Ptk,
    info: u16,
    replay_counter: u64,
    nonce: Nonce,
    key_data: Vec<u8>,
) -> Result<Vec<u8>, FrameError> {
    let mut frame = EapolKey {
        version: REPLY_PROTOCOL_VERSION,
        info: KeyInfo(info),
        key_length: 0,
        replay_counter,
        nonce,
        iv: [0; 16],
        rsc: [0; 8],
        mic: [0; 16],
        key_data,
    }
    .encode()?;
    eapol::sign(ptk.kck().expose(), &mut frame)?;
    Ok(frame)
}

/// Why a network or a frame was refused; it names the rule broken and carries no byte of a frame or key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    /// The frame could not be read, or a reply could not be written.
    Frame(FrameError),
    /// The key data of the frame could not be unwrapped or read.
    KeyData(KeyDataError),
    /// The RSN element of the access point is malformed or advertises a network outside the scope.
    ApRsne(RsneError),
    /// The RSN element of this station is malformed or not the one kind this crate may send.
    OwnRsne(RsneError),
    /// The key descriptor version is not 2.
    KeyVersion,
    /// The key information flags are not those of a frame an access point sends in a handshake.
    UnexpectedFlags,
    /// The frame is not one the current phase expects.
    WrongPhase,
    /// The replay counter is not greater than that of the last frame whose MIC verified.
    Replay,
    /// Message 3 carries the ANonce neither of the handshake under way nor of the established keys.
    AnonceMismatch,
    /// The MIC is not the one the key confirmation key gives the frame.
    BadMic,
    /// Message 3 does not ask for the pairwise key to be installed.
    InstallNotSet,
    /// The key data of message 3 or of a group message is not encrypted.
    NotEncrypted,
    /// The pairwise key length of message 3 is not 16.
    KeyLength,
    /// The RSN element of message 3 is missing or is not the one the access point advertised.
    RsneMismatch,
    /// Message 3 or a group message delivers no group key.
    GtkMissing,
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Frame(error) => return error.fmt(f),
            Self::KeyData(error) => return error.fmt(f),
            Self::ApRsne(error) | Self::OwnRsne(error) => return error.fmt(f),
            Self::KeyVersion => "key descriptor version is not 2",
            Self::UnexpectedFlags => {
                "key information flags are not those of an access point's frame"
            }
            Self::WrongPhase => "frame is not one the current phase of the handshake expects",
            Self::Replay => "replay counter is not greater than that of the last verified frame",
            Self::AnonceMismatch => {
                "message 3 carries the ANonce of neither the pending handshake nor the established keys"
            }
            Self::BadMic => "message integrity code is wrong",
            Self::InstallNotSet => "message 3 does not ask for the pairwise key to be installed",
            Self::NotEncrypted => "key data of the frame is not encrypted",
            Self::KeyLength => "pairwise key length of message 3 is not 16",
            Self::RsneMismatch => {
                "RSN element of message 3 is missing or is not the one the access point advertised"
            }
            Self::GtkMissing => "frame delivers no group key",
        })
    }
}

impl std::error::Error for HandshakeError {}

impl From<FrameError> for HandshakeError {
    fn from(error: FrameError) -> Self {
        Self::Frame(error)
    }
}

impl From<KeyDataError> for HandshakeError {
    fn from(error: KeyDataError) -> Self {
        Self::KeyData(error)
    }
}
