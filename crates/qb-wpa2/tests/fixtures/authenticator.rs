#![allow(dead_code)]
// A test double for the access point: it builds the EAPOL-Key frames an authenticator sends, with every field
// open to a test that wants one wrong. `authenticator_reproduces_the_reference_frames` in handshake.rs checks it
// against the frames of reference.rs, which Python and OpenSSL built, before any test relies on it.

use aes_kw::{KeyInit, KwAes128};
use qb_wpa2::eapol::{EapolKey, KeyInfo, sign};

/// One frame of the access point, before it is wrapped and signed.
pub struct ApFrame {
    /// The key information field.
    pub info: u16,
    /// The pairwise key length.
    pub key_length: u16,
    /// The replay counter.
    pub counter: u64,
    /// The ANonce, or zeros.
    pub nonce: [u8; 32],
    /// The receive sequence counter of the group key.
    pub rsc: [u8; 8],
    /// The key data in the clear; `build` wraps it if the frame says it is encrypted.
    pub key_data: Vec<u8>,
}

impl ApFrame {
    /// Message 1 of the four-way handshake: Pairwise and Ack, no MIC, no key data.
    pub fn m1(counter: u64, anonce: [u8; 32]) -> Self {
        Self {
            info: 0x008a,
            key_length: 16,
            counter,
            nonce: anonce,
            rsc: [0; 8],
            key_data: Vec::new(),
        }
    }

    /// Message 3 of the four-way handshake: Pairwise, Install, Ack, MIC, Secure and Encrypted.
    pub fn m3(counter: u64, anonce: [u8; 32], key_data: Vec<u8>) -> Self {
        Self {
            info: 0x13ca,
            key_length: 16,
            counter,
            nonce: anonce,
            rsc: [0; 8],
            key_data,
        }
    }

    /// Message 1 of the group-key handshake: Ack, MIC, Secure and Encrypted, no nonce.
    pub fn g1(counter: u64, key_data: Vec<u8>) -> Self {
        Self {
            info: 0x1382,
            key_length: 0,
            counter,
            nonce: [0; 32],
            rsc: [0; 8],
            key_data,
        }
    }

    /// The frame as sent, with protocol version 2: the key data wrapped under `kek` if the Encrypted bit is set,
    /// the frame signed under `kck` if the MIC bit is set.
    pub fn build(&self, kck: &[u8; 16], kek: &[u8; 16]) -> Vec<u8> {
        let info = KeyInfo(self.info);
        let key_data = if info.has(KeyInfo::ENCRYPTED) {
            let mut wrapped = vec![0; self.key_data.len() + 8];
            KwAes128::new(kek.into())
                .wrap_key(&self.key_data, &mut wrapped)
                .unwrap();
            wrapped
        } else {
            self.key_data.clone()
        };
        let mut frame = EapolKey {
            version: 2,
            info,
            key_length: self.key_length,
            replay_counter: self.counter,
            nonce: self.nonce,
            iv: [0; 16],
            rsc: self.rsc,
            mic: [0; 16],
            key_data,
        }
        .encode()
        .unwrap();
        if info.has(KeyInfo::MIC) {
            sign(kck, &mut frame).unwrap();
        }
        frame
    }
}

/// A GTK KDE: `dd`, the length, `00 0f ac 01`, the key id, a reserved byte, the key.
pub fn gtk_kde(key_id: u8, gtk: &[u8]) -> Vec<u8> {
    let len = u8::try_from(6 + gtk.len()).unwrap();
    [
        &[0xdd, len][..],
        &[0x00, 0x0f, 0xac, 0x01],
        &[key_id, 0x00],
        gtk,
    ]
    .concat()
}

/// Pads key data for the key wrap: `dd`, then zeros up to a multiple of 8 bytes; nothing if it is one already.
pub fn pad(mut key_data: Vec<u8>) -> Vec<u8> {
    if !key_data.len().is_multiple_of(8) {
        key_data.push(0xdd);
        while !key_data.len().is_multiple_of(8) {
            key_data.push(0x00);
        }
    }
    key_data
}
