//! The EAPOL-Key frame: the one frame format of the WPA2 handshakes
//! (IEEE Std 802.1X-2004 7.5 and IEEE Std 802.11-2016 12.7.2), and the MIC
//! that signs it.
//!
//! Every function here takes bytes that any radio in range can send. None
//! panics on any input, and no error repeats a byte of the frame it refused.
//!
//! Wire layout, every integer big-endian:
//!
//! | Offset | Bytes | Field |
//! |---|---|---|
//! | 0 | 1 | protocol version (any value accepted) |
//! | 1 | 1 | packet type, 3 for EAPOL-Key |
//! | 2 | 2 | body length: everything after these four bytes |
//! | 4 | 1 | descriptor type, 2 for RSN |
//! | 5 | 2 | key information |
//! | 7 | 2 | key length |
//! | 9 | 8 | replay counter |
//! | 17 | 32 | nonce |
//! | 49 | 16 | IV |
//! | 65 | 8 | RSC |
//! | 73 | 8 | reserved: ignored on decode, zero on encode |
//! | 81 | 16 | MIC |
//! | 97 | 2 | key data length |
//! | 99 | n | key data |

use std::fmt;

use hmac::Mac;
use subtle::ConstantTimeEq;

use crate::Nonce;
use crate::ptk::hmac_sha1;

/// The length in bytes of the 802.1X header: protocol version, packet type and body length.
const HEADER_LEN: usize = 4;

/// The 802.1X packet type of an EAPOL-Key frame.
const PACKET_TYPE_KEY: u8 = 3;

/// The descriptor type of an RSN (WPA2) key frame; 254 is the WPA1 descriptor, which this crate does not speak.
const DESCRIPTOR_RSN: u8 = 2;

/// The length in bytes of a body that carries no key data: every field from the descriptor type to the key data length.
const BODY_FIXED_LEN: u16 = 95;

/// The offset of the MIC field from the start of the frame.
const MIC_OFFSET: usize = 81;

/// The length in bytes of the MIC of key descriptor version 2: HMAC-SHA1 cut to its first 16 bytes.
const MIC_LEN: usize = 16;

/// The length in bytes of the key confirmation key.
const KCK_LEN: usize = 16;

/// The key information field of an EAPOL-Key frame: the descriptor version and the flags that tell the messages apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyInfo(pub u16);

impl KeyInfo {
    /// Key Type: set in the frames of the pairwise (four-way) handshake, clear in those of the group-key handshake.
    pub const PAIRWISE: u16 = 0x0008;
    /// Install: the pairwise key is to be installed once the frame is verified.
    pub const INSTALL: u16 = 0x0040;
    /// Key Ack: the access point expects an answer to the frame.
    pub const ACK: u16 = 0x0080;
    /// Key MIC: the frame is signed and its MIC field is to be checked.
    pub const MIC: u16 = 0x0100;
    /// Secure: the pairwise key exchange is complete; set from message 3 of the four-way handshake onwards.
    pub const SECURE: u16 = 0x0200;
    /// Error: the station reports a MIC failure in a data frame.
    pub const ERROR: u16 = 0x0400;
    /// Request: the station asks the access point to start a handshake.
    pub const REQUEST: u16 = 0x0800;
    /// Encrypted Key Data: the key data is wrapped under the KEK.
    pub const ENCRYPTED: u16 = 0x1000;
    /// SMK Message: the frame belongs to the station-to-station handshake.
    pub const SMK: u16 = 0x2000;

    /// The key descriptor version, the low three bits: 2 is HMAC-SHA1 for the MIC and AES key wrap for the key data.
    pub fn version(self) -> u8 {
        let [_, low] = self.0.to_be_bytes();
        low & 0x07
    }

    /// Whether every bit of `flags` is set.
    pub fn has(self, flags: u16) -> bool {
        self.0 & flags == flags
    }
}

/// One EAPOL-Key frame with an RSN key descriptor, as its fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapolKey {
    /// The 802.1X protocol version of the header: 1 or 2 in practice, and any value is accepted.
    pub version: u8,
    /// The key information field.
    pub info: KeyInfo,
    /// The pairwise key length in bytes: 16 for CCMP in messages 1 and 3, 0 in the station's replies.
    pub key_length: u16,
    /// The replay counter: the access point raises it with every frame and the station answers with the same value.
    pub replay_counter: u64,
    /// The ANonce or the SNonce, or zeros in a frame that carries neither.
    pub nonce: Nonce,
    /// The EAPOL-Key IV, zeros under key descriptor version 2.
    pub iv: [u8; 16],
    /// The receive sequence counter: the packet number the group key has reached, least significant byte first.
    pub rsc: [u8; 8],
    /// The MIC field as it stands in the frame; `decode` does not check it, `verify_mic` does.
    pub mic: [u8; MIC_LEN],
    /// The key data: an RSN element in the clear, or elements and keys wrapped under the KEK.
    pub key_data: Vec<u8>,
}

impl EapolKey {
    /// Reads a frame, ignoring any byte after its declared length and any body byte after its key data.
    pub fn decode(frame: &[u8]) -> Result<Self, FrameError> {
        let mut fields = Fields(declared(frame)?);
        let [version, _packet_type, _body_len_high, _body_len_low] = fields.take()?;
        let [descriptor] = fields.take()?;
        if descriptor != DESCRIPTOR_RSN {
            return Err(FrameError::NotRsnDescriptor);
        }
        let info = KeyInfo(u16::from_be_bytes(fields.take()?));
        let key_length = u16::from_be_bytes(fields.take()?);
        let replay_counter = u64::from_be_bytes(fields.take()?);
        let nonce = fields.take()?;
        let iv = fields.take()?;
        let rsc = fields.take()?;
        let _reserved: [u8; 8] = fields.take()?;
        let mic = fields.take()?;
        let key_data_len = usize::from(u16::from_be_bytes(fields.take()?));
        // What is left is the body after its 95 fixed bytes: the key data, then whatever the sender padded with.
        let key_data = fields
            .0
            .get(..key_data_len)
            .ok_or(FrameError::KeyDataOverrun)?
            .to_vec();
        Ok(Self {
            version,
            info,
            key_length,
            replay_counter,
            nonce,
            iv,
            rsc,
            mic,
            key_data,
        })
    }

    /// Writes the frame. The MIC field is written as stored: a frame to send is built with a zero MIC, then signed.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let too_long = FrameError::KeyDataTooLong;
        let key_data_len = u16::try_from(self.key_data.len()).map_err(|_| too_long)?;
        let body_len = key_data_len.checked_add(BODY_FIXED_LEN).ok_or(too_long)?;
        let mut frame = Vec::with_capacity(HEADER_LEN + usize::from(body_len));
        frame.extend_from_slice(&[self.version, PACKET_TYPE_KEY]);
        frame.extend_from_slice(&body_len.to_be_bytes());
        frame.push(DESCRIPTOR_RSN);
        frame.extend_from_slice(&self.info.0.to_be_bytes());
        frame.extend_from_slice(&self.key_length.to_be_bytes());
        frame.extend_from_slice(&self.replay_counter.to_be_bytes());
        frame.extend_from_slice(&self.nonce);
        frame.extend_from_slice(&self.iv);
        frame.extend_from_slice(&self.rsc);
        frame.extend_from_slice(&[0; 8]); // reserved
        frame.extend_from_slice(&self.mic);
        frame.extend_from_slice(&key_data_len.to_be_bytes());
        frame.extend_from_slice(&self.key_data);
        Ok(frame)
    }
}

/// The bytes of a frame not yet read, handed out field by field from the front.
struct Fields<'a>(&'a [u8]);

impl Fields<'_> {
    /// The next `N` bytes. `declared` has established that all 99 fixed bytes are there, so this does not fail in
    /// `decode`; it returns an error rather than index, so that no length taken from a frame can ever panic.
    fn take<const N: usize>(&mut self) -> Result<[u8; N], FrameError> {
        let (field, rest) = self.0.split_first_chunk().ok_or(FrameError::Truncated)?;
        self.0 = rest;
        Ok(*field)
    }
}

/// The frame as its header declares it — the first 4 + body length bytes, whatever follows them — after the four
/// checks every function of this module applies: a whole header, the EAPOL-Key packet type, all of the declared
/// length present, and a body long enough for every fixed field. The result is at least 99 bytes long.
fn declared(frame: &[u8]) -> Result<&[u8], FrameError> {
    let (&[_version, packet_type, body_len_high, body_len_low], _) =
        frame.split_first_chunk().ok_or(FrameError::Truncated)?;
    if packet_type != PACKET_TYPE_KEY {
        return Err(FrameError::NotKeyFrame);
    }
    let body_len = u16::from_be_bytes([body_len_high, body_len_low]);
    let declared = frame
        .get(..HEADER_LEN + usize::from(body_len))
        .ok_or(FrameError::Truncated)?;
    if body_len < BODY_FIXED_LEN {
        return Err(FrameError::BodyTooShort);
    }
    Ok(declared)
}

/// The declared bytes of a frame before its MIC field, the MIC it carries, and the declared bytes after the field.
type AroundMic<'a> = (&'a [u8; MIC_OFFSET], &'a [u8; MIC_LEN], &'a [u8]);

/// Splits a frame at its MIC field, after the checks of `declared`.
fn around_mic(frame: &[u8]) -> Result<AroundMic<'_>, FrameError> {
    let declared = declared(frame)?;
    // Neither split fails: `declared` is at least 99 bytes long and the field ends at byte 97.
    let (before, rest) = declared.split_first_chunk().ok_or(FrameError::Truncated)?;
    let (stored, after) = rest.split_first_chunk().ok_or(FrameError::Truncated)?;
    Ok((before, stored, after))
}

/// HMAC-SHA1 under the KCK over `before`, sixteen zero bytes and `after`, cut to its first 16 bytes.
///
/// The KCK is not copied: the only state made from it is the keyed hash, whose hash states `sha1` (built with its
/// `zeroize` feature) wipes when the value drops. The working copies `hmac` and `sha1` make on the stack while
/// they key the hash and finish it (the key-xor-pad block, the inner hash, a copy of the hash state) are not
/// wiped by either crate.
fn mic_over(kck: &[u8; KCK_LEN], before: &[u8; MIC_OFFSET], after: &[u8]) -> [u8; MIC_LEN] {
    let mut keyed = hmac_sha1(kck);
    keyed.update(before);
    keyed.update(&[0; MIC_LEN]);
    keyed.update(after);
    let digest = keyed.finalize().into_bytes();
    let mut mic = [0u8; MIC_LEN];
    for (to, from) in mic.iter_mut().zip(digest.iter()) {
        *to = *from;
    }
    mic
}

/// The MIC a frame should carry: HMAC-SHA1 under the KCK over its declared length with the MIC field taken as zero.
pub fn mic(kck: &[u8; KCK_LEN], frame: &[u8]) -> Result<[u8; MIC_LEN], FrameError> {
    let (before, _stored, after) = around_mic(frame)?;
    Ok(mic_over(kck, before, after))
}

/// Whether the MIC a frame carries is the one the KCK gives it, compared in constant time.
pub fn verify_mic(kck: &[u8; KCK_LEN], frame: &[u8]) -> Result<bool, FrameError> {
    let (before, stored, after) = around_mic(frame)?;
    Ok(mic_over(kck, before, after).ct_eq(stored).into())
}

/// Writes the MIC into the frame's MIC field, whatever the field held; bytes after the declared length are left alone.
pub fn sign(kck: &[u8; KCK_LEN], frame: &mut [u8]) -> Result<(), FrameError> {
    let computed = mic(kck, frame)?;
    // Cannot fail: `mic` has accepted the frame, which is then at least 99 bytes long.
    let field: &mut [u8; MIC_LEN] = frame
        .get_mut(MIC_OFFSET..)
        .and_then(<[u8]>::first_chunk_mut)
        .ok_or(FrameError::Truncated)?;
    *field = computed;
    Ok(())
}

/// Why a frame could not be read, signed or written; it names the rule broken and carries no byte of the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The frame is shorter than its four-byte header or than the length that header declares.
    Truncated,
    /// The packet type of the header is not EAPOL-Key.
    NotKeyFrame,
    /// The declared body is shorter than the fixed fields of a key descriptor.
    BodyTooShort,
    /// The key descriptor is not of the RSN type.
    NotRsnDescriptor,
    /// The key data length runs past the end of the declared body.
    KeyDataOverrun,
    /// The key data is longer than the 65 440 bytes one frame can declare.
    KeyDataTooLong,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "frame is shorter than its header or its declared length",
            Self::NotKeyFrame => "frame is not an EAPOL-Key frame",
            Self::BodyTooShort => "frame body is too short for an EAPOL-Key descriptor",
            Self::NotRsnDescriptor => "key descriptor is not of the RSN type",
            Self::KeyDataOverrun => "key data length runs past the end of the frame body",
            Self::KeyDataTooLong => "key data is too long for one frame",
        })
    }
}

impl std::error::Error for FrameError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference::{ANONCE, G1, G2, KCK, KEK, M1, M2, M3, M4};
    use hex_literal::hex;

    /// A copy of `frame` with `bytes` written over it from offset `at`.
    fn with(frame: &[u8], at: usize, bytes: &[u8]) -> Vec<u8> {
        let mut changed = frame.to_vec();
        changed[at..at + bytes.len()].copy_from_slice(bytes);
        changed
    }

    #[test]
    fn decodes_reference_message_3() {
        let k = EapolKey::decode(&M3).unwrap();
        assert_eq!(
            (k.version, k.info, k.key_length, k.replay_counter),
            (2, KeyInfo(0x13ca), 16, 2)
        );
        assert_eq!(
            (k.nonce, k.iv, k.rsc),
            (ANONCE, [0; 16], hex!("1122334455660000"))
        );
        assert_eq!(k.mic, hex!("225de9d7066ddf9622bb3bc46ba0ce45"));
        assert_eq!(k.key_data, M3[99..]);
    }

    #[test]
    fn encode_reproduces_every_reference_frame() {
        for f in [&M1[..], &M2, &M3, &M4, &G1, &G2] {
            assert_eq!(EapolKey::decode(f).unwrap().encode().unwrap(), f);
        }
    }

    #[test]
    fn mic_matches_the_reference_and_rejects_changes() {
        for f in [&M2[..], &M3, &M4, &G1, &G2] {
            assert_eq!(mic(&KCK, f).unwrap(), f[81..97]);
            assert_eq!(verify_mic(&KCK, f), Ok(true));
            assert_eq!(verify_mic(&KEK, f), Ok(false));
            let mut changed = f.to_vec();
            changed[20] ^= 1;
            assert_eq!(verify_mic(&KCK, &changed), Ok(false));
            let mut unsigned = f.to_vec();
            unsigned[81..97].fill(0);
            sign(&KCK, &mut unsigned).unwrap();
            assert_eq!(unsigned, f);
        }
        assert_eq!(mic(&KCK, &M2[..50]), Err(FrameError::Truncated));
    }

    #[test]
    fn key_info_bits() {
        let m3 = KeyInfo(0x13ca);
        assert_eq!(m3.version(), 2);
        assert!(m3.has(
            KeyInfo::PAIRWISE
                | KeyInfo::INSTALL
                | KeyInfo::ACK
                | KeyInfo::MIC
                | KeyInfo::SECURE
                | KeyInfo::ENCRYPTED
        ));
        assert!(!m3.has(KeyInfo::ERROR) && !m3.has(KeyInfo::REQUEST) && !m3.has(KeyInfo::SMK));
        assert!(
            !KeyInfo(0x1382).has(KeyInfo::PAIRWISE)
                && !KeyInfo(0x008a).has(KeyInfo::MIC | KeyInfo::ACK)
        );
    }

    // Review Focus 5: bytes after the declared length, and body bytes after the key data.
    #[test]
    fn trailing_bytes_are_ignored() {
        let padded = [&M3[..], &[0u8; 7]].concat();
        assert_eq!(EapolKey::decode(&padded), EapolKey::decode(&M3));
        assert_eq!(verify_mic(&KCK, &padded), Ok(true));
        // What follows the declared length is no part of the frame: it may be anything, and `sign` leaves it alone.
        let noise = [&M3[..], &[0xa5; 7]].concat();
        assert_eq!(EapolKey::decode(&noise), EapolKey::decode(&M3));
        assert_eq!(verify_mic(&KCK, &noise), Ok(true));
        let mut resigned = with(&noise, 81, &[0; 16]);
        sign(&KCK, &mut resigned).unwrap();
        assert_eq!(resigned, noise);

        // M1 with body length 0x0061 and two bytes appended: decodes, key_data is empty.
        let long_body = [&with(&M1, 2, &[0x00, 0x61])[..], &[0xee; 2]].concat();
        let k = EapolKey::decode(&long_body).unwrap();
        assert_eq!(k.key_data, []);
        assert_eq!(k, EapolKey::decode(&M1).unwrap());

        // The same shape signed (message 4): the two body bytes after the key data are inside the declared
        // length, so the MIC covers them; a byte after the declared length it does not cover.
        let mut long_m4 = [&with(&M4, 2, &[0x00, 0x61])[..], &[0xee; 2], &[0x77; 3]].concat();
        assert_eq!(verify_mic(&KCK, &long_m4), Ok(false));
        sign(&KCK, &mut long_m4).unwrap();
        assert_eq!(verify_mic(&KCK, &long_m4), Ok(true));
        assert_ne!(long_m4[81..97], M4[81..97]);
        assert_eq!(EapolKey::decode(&long_m4).unwrap().key_data, []);
        assert_eq!(
            verify_mic(&KCK, &with(&long_m4, 100, &[0xef])),
            Ok(false),
            "a body byte after the key data"
        );
        assert_eq!(
            verify_mic(&KCK, &with(&long_m4, 101, &[0x78])),
            Ok(true),
            "a byte after the declared length"
        );
    }

    #[test]
    fn malformed_frames_are_typed_errors() {
        // The first four checks: `decode`, `mic`, `verify_mic` and `sign` all apply them.
        let rejected_by_all: [(Vec<u8>, FrameError); 6] = [
            (vec![], FrameError::Truncated),
            (M1[..3].to_vec(), FrameError::Truncated),
            (M1[..98].to_vec(), FrameError::Truncated),
            (with(&M1, 1, &[0]), FrameError::NotKeyFrame),
            (with(&M1, 2, &[0x00, 0x5e]), FrameError::BodyTooShort),
            (with(&M1, 2, &[0x00, 0x60]), FrameError::Truncated),
        ];
        for (frame, error) in rejected_by_all {
            assert_eq!(EapolKey::decode(&frame), Err(error), "{frame:02x?}");
            assert_eq!(mic(&KCK, &frame), Err(error), "{frame:02x?}");
            assert_eq!(verify_mic(&KCK, &frame), Err(error), "{frame:02x?}");
            let mut unchanged = frame.clone();
            assert_eq!(sign(&KCK, &mut unchanged), Err(error), "{frame:02x?}");
            assert_eq!(unchanged, frame, "a refused frame is not written to");
        }

        // The last two checks are `decode`'s alone: the MIC of such a frame can still be computed.
        let rejected_by_decode: [(Vec<u8>, FrameError); 3] = [
            // 254 is the WPA1 descriptor.
            (with(&M1, 4, &[254]), FrameError::NotRsnDescriptor),
            (with(&M1, 97, &[0x00, 0x01]), FrameError::KeyDataOverrun),
            (with(&M3, 97, &[0x00, 0x39]), FrameError::KeyDataOverrun),
        ];
        for (frame, error) in rejected_by_decode {
            assert_eq!(EapolKey::decode(&frame), Err(error), "{frame:02x?}");
            assert!(mic(&KCK, &frame).is_ok(), "{frame:02x?}");
            assert_eq!(verify_mic(&KCK, &frame), Ok(false), "{frame:02x?}");
            assert_eq!(sign(&KCK, &mut frame.clone()), Ok(()), "{frame:02x?}");
        }

        // The order of the checks, where one frame breaks two rules.
        assert_eq!(
            EapolKey::decode(&[1, 0, 0xff, 0xff]),
            Err(FrameError::NotKeyFrame),
            "the packet type is checked before the length"
        );
        assert_eq!(
            EapolKey::decode(&[1, 3, 0x00, 0x5e]),
            Err(FrameError::Truncated),
            "the frame length is checked before the body length"
        );
        assert_eq!(
            EapolKey::decode(&with(&with(&M1, 2, &[0x00, 0x5e]), 4, &[254])),
            Err(FrameError::BodyTooShort),
            "the body length is checked before the descriptor type"
        );
        assert_eq!(
            EapolKey::decode(&with(&with(&M1, 4, &[254]), 97, &[0x00, 0x01])),
            Err(FrameError::NotRsnDescriptor),
            "the descriptor type is checked before the key data length"
        );

        // One fixed sentence per variant, each its own.
        let sentences = [
            FrameError::Truncated,
            FrameError::NotKeyFrame,
            FrameError::BodyTooShort,
            FrameError::NotRsnDescriptor,
            FrameError::KeyDataOverrun,
            FrameError::KeyDataTooLong,
        ]
        .map(|error| error.to_string());
        for (i, sentence) in sentences.iter().enumerate() {
            assert!(!sentence.is_empty());
            assert!(!sentences[..i].contains(sentence), "{sentence}");
        }
    }

    #[test]
    fn oversized_key_data_cannot_be_encoded() {
        let mut k = EapolKey::decode(&M1).unwrap();
        k.key_data = vec![0; 65_440];
        assert_eq!(k.encode().unwrap().len(), 65_539);
        k.key_data.push(0);
        assert_eq!(k.encode(), Err(FrameError::KeyDataTooLong));
    }
}
