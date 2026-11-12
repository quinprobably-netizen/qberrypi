//! The robustness sweep through the public interface (Decision 11): every decoder takes every truncation and
//! every single-byte change of the frames and elements the other tests use, and a fixed-seed stream of random
//! bytes, and must not panic; the state machine takes the same and must refuse without changing, or answer
//! with the one reply an unsigned frame can earn. Everything here is deterministic: a failure names the same
//! bytes on every run.

#[path = "fixtures/authenticator.rs"]
mod authenticator;
#[path = "fixtures/captures.rs"]
mod captures;
#[path = "fixtures/reference.rs"]
mod reference;

use authenticator::{ApFrame, gtk_kde};
use captures::Captures;
use hex_literal::hex;
use qb_wpa2::eapol::{EapolKey, mic, sign, verify_mic};
use qb_wpa2::keydata::{KeyDataError, parse_key_data, unwrap_key_data};
use qb_wpa2::pmk::Pmk;
use qb_wpa2::rsne::{Rsne, SUPPLICANT_RSNE};
use qb_wpa2::supplicant::{Params, Phase, ReplyKind, Supplicant};
use reference::{ANONCE, G1, G2, KCK, KEK, M1, M2, M3, M4, PMK, RSNE, SNONCE};

/// The RSN element of a mixed WPA/WPA2 network: TKIP group cipher, CCMP and TKIP pairwise, PSK.
const MIXED_RSNE: [u8; 26] = hex!("30180100000fac020200000fac04000fac020100000fac020000");

/// A station's RSN element with the replay-counter capability bits set (capabilities 0x0028).
const STATION_RSNE: [u8; 22] = hex!("30140100000fac040100000fac040100000fac022800");

/// The number of random inputs the decoders take.
const DECODER_ROUNDS: usize = 50_000;

/// The number of random frames a `Supplicant` takes in each phase.
const SUPPLICANT_ROUNDS: usize = 20_000;

/// Every proper prefix of `frame`, then for every index the frame with that byte replaced by 0x00, 0xff,
/// b ^ 0x01 and b ^ 0x80, leaving out replacements equal to the original byte.
fn changes(frame: &[u8]) -> Vec<Vec<u8>> {
    let prefixes = (0..frame.len()).map(|len| frame[..len].to_vec());
    let replacements = frame.iter().enumerate().flat_map(|(index, &b)| {
        [0x00, 0xff, b ^ 0x01, b ^ 0x80]
            .into_iter()
            .filter(move |replacement| *replacement != b)
            .map(move |replacement| {
                let mut changed = frame.to_vec();
                changed[index] = replacement;
                changed
            })
    });
    prefixes.chain(replacements).collect()
}

/// xorshift64 from the fixed seed 0x9e37_79b9_7f4a_7c15: x ^= x << 13; x ^= x >> 7; x ^= x << 17.
struct Stream(u64);

impl Stream {
    /// The stream at its seed.
    fn new() -> Self {
        Self(0x9e37_79b9_7f4a_7c15)
    }

    /// One step of the generator.
    fn step(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// The next `len` bytes: each step gives eight, least significant first, and what the last step gives
    /// beyond `len` is dropped.
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(len + 8);
        while bytes.len() < len {
            bytes.extend_from_slice(&self.step().to_le_bytes());
        }
        bytes.truncate(len);
        bytes
    }

    /// A number below `n`, from one step.
    fn below(&mut self, n: usize) -> usize {
        let n = u64::try_from(n).unwrap();
        usize::try_from(self.step() % n).unwrap()
    }
}

/// One round of the random sweep: up to 319 bytes of the stream. Every third round, when there are 5 bytes or
/// more, they get the EAPOL-Key packet type, a body length that is exactly what follows the header, and the
/// RSN descriptor type, so that the paths past the header checks are reached. When there are 99 bytes or more
/// (the fixed part of an EAPOL-Key frame), they also get a key data length that fits in the frame (one more
/// draw from the stream, `below(len - 98)`, written big-endian to bytes 97 and 98), so that the paths past the
/// key data length check are reached too: the key information checks, the replay check, the MIC check, and
/// message 1.
fn random_frame(stream: &mut Stream, round: usize) -> Vec<u8> {
    let len = stream.below(320);
    let mut bytes = stream.bytes(len);
    if round.is_multiple_of(3) && len >= 5 {
        bytes[1] = 3;
        bytes[2..4].copy_from_slice(&u16::try_from(len - 4).unwrap().to_be_bytes());
        bytes[4] = 2;
        if len >= 99 {
            let key_data_len = u16::try_from(stream.below(len - 98)).unwrap();
            bytes[97..99].copy_from_slice(&key_data_len.to_be_bytes());
        }
    }
    bytes
}

/// What the default run sweeps: the six reference frames, three RSN elements, the unwrapped key data of the
/// reference message 3, and two shapes real networks send that the reference handshake does not have.
fn seeds() -> Vec<Vec<u8>> {
    // A message 1 that carries key data, as many access points send it: a PMKID KDE, in the clear.
    let m1_with_pmkid = ApFrame {
        key_data: [&hex!("dd14000fac04")[..], &[0x5a; 16]].concat(),
        ..ApFrame::m1(1, ANONCE)
    }
    .build(&KCK, &KEK);
    assert_eq!(EapolKey::decode(&m1_with_pmkid).unwrap().key_data.len(), 22);
    // Key data in the form a mixed WPA/WPA2 access point sends: its RSN element, a group key of the 32 bytes
    // TKIP takes under key id 2, and padding of `dd` and five zeros.
    let mixed_key_data = [
        &MIXED_RSNE[..],
        &gtk_kde(2, &[0x77; 32]),
        &hex!("dd0000000000"),
    ]
    .concat();
    assert_eq!(
        parse_key_data(&mixed_key_data).unwrap_err(),
        KeyDataError::GtkLength
    );
    vec![
        M1.to_vec(),
        M2.to_vec(),
        M3.to_vec(),
        M4.to_vec(),
        G1.to_vec(),
        G2.to_vec(),
        RSNE.to_vec(),
        MIXED_RSNE.to_vec(),
        STATION_RSNE.to_vec(),
        unwrap_key_data(&KEK, &M3[99..]).unwrap().to_vec(),
        m1_with_pmkid,
        mixed_key_data,
    ]
}

/// Every function of the crate that reads bytes a radio or an access point chose, on the same bytes. What they
/// return does not matter here: that they return does.
fn decoders(bytes: &[u8]) {
    let _ = EapolKey::decode(bytes);
    let _ = mic(&KCK, bytes);
    let _ = verify_mic(&KCK, bytes);
    let _ = sign(&KCK, &mut bytes.to_vec());
    let _ = unwrap_key_data(&KEK, bytes);
    let _ = parse_key_data(bytes);
    let _ = Rsne::parse(bytes);
}

fn params() -> Params {
    Params {
        pmk: Pmk::from_bytes(PMK),
        aa: reference::AA,
        spa: reference::SPA,
        ap_rsne: RSNE.to_vec(),
        ap_rsnxe: None,
        own_rsne: SUPPLICANT_RSNE.to_vec(),
    }
}

/// A `Supplicant` that has answered the reference message 1.
fn awaiting_message_3() -> Supplicant {
    let mut s = Supplicant::new(params()).unwrap();
    assert_eq!(s.handle(&M1, || SNONCE).unwrap().frame, M2);
    assert_eq!(s.phase(), Phase::AwaitingMessage3);
    s
}

/// Hands `s` the reference message 3 and expects message 4 of the reference handshake and an established link.
#[track_caller]
fn completes_the_reference_handshake(s: &mut Supplicant) {
    let reply = s.handle(&M3, || SNONCE).unwrap();
    assert_eq!(
        (reply.kind, &reply.frame[..]),
        (ReplyKind::Message4, &M4[..])
    );
    assert_eq!(s.phase(), Phase::Established);
}

/// Hands `s` the reference group message 1 and expects message 2 of the reference group-key handshake.
#[track_caller]
fn answers_the_reference_group_message(s: &mut Supplicant) {
    let reply = s.handle(&G1, || SNONCE).unwrap();
    assert_eq!(
        (reply.kind, &reply.frame[..]),
        (ReplyKind::GroupMessage2, &G2[..])
    );
}

/// Hands `s` every item of `changes(frame)`: each is refused and leaves `s` as it was.
#[track_caller]
fn refuses_every_change(s: &mut Supplicant, frame: &[u8]) {
    let phase = s.phase();
    // Beyond the brief: not the phase alone. `Debug` prints everything a `Supplicant` holds but its keys (the
    // replay counter on record, the nonces of a pending handshake), and the reply the caller checks next is
    // signed with those keys.
    let untouched = format!("{s:?}");
    for changed in changes(frame) {
        assert!(
            s.handle(&changed, || SNONCE).is_err(),
            "accepted: {changed:02x?}"
        );
        assert_eq!(s.phase(), phase, "{changed:02x?}");
        assert_eq!(format!("{s:?}"), untouched, "{changed:02x?}");
    }
}

/// Hands `s` `SUPPLICANT_ROUNDS` random frames and returns how many it accepted. A random frame carries no
/// valid MIC, so the one frame it can pass for is message 1, which is not signed: an accepted frame is answered
/// with message 2, and a refused one leaves `s` as it was.
#[track_caller]
fn takes_random_frames(s: &mut Supplicant, stream: &mut Stream) -> usize {
    let mut accepted = 0;
    // Beyond the brief: `Debug` is compared as well as the phase, as in `refuses_every_change`.
    let mut before = (s.phase(), format!("{s:?}"));
    for round in 0..SUPPLICANT_ROUNDS {
        let frame = random_frame(stream, round);
        match s.handle(&frame, || SNONCE) {
            Ok(reply) => {
                assert_eq!(reply.kind, ReplyKind::Message2, "{frame:02x?}");
                accepted += 1;
                before = (s.phase(), format!("{s:?}"));
            }
            Err(_) => assert_eq!((s.phase(), format!("{s:?}")), before, "{frame:02x?}"),
        }
    }
    accepted
}

#[test]
fn decoders_survive_every_truncation_and_single_byte_change() {
    for seed in seeds() {
        for bytes in changes(&seed) {
            decoders(&bytes);
        }
    }
}

#[test]
fn decoders_survive_random_bytes() {
    let mut stream = Stream::new();
    for round in 0..DECODER_ROUNDS {
        decoders(&random_frame(&mut stream, round));
    }
}

// The MIC covers every byte of the declared frame, so one changed byte fails the framing checks, the key
// information checks or the MIC, whichever comes first; a truncated frame fails the framing checks.
#[test]
fn supplicant_rejects_every_change_to_a_signed_frame() {
    let mut s = awaiting_message_3();
    refuses_every_change(&mut s, &M3);
    completes_the_reference_handshake(&mut s);
    refuses_every_change(&mut s, &G1);
    answers_the_reference_group_message(&mut s);
    assert_eq!(s.phase(), Phase::Established);
}

// Message 1 is not signed: a change either breaks a rule or yields another message 1, which is answered.
#[test]
fn supplicant_survives_every_change_to_message_1() {
    for changed in changes(&M1) {
        let mut s = Supplicant::new(params()).unwrap();
        match s.handle(&changed, || SNONCE) {
            Ok(reply) => {
                assert_eq!(reply.kind, ReplyKind::Message2, "{changed:02x?}");
                assert_eq!(s.phase(), Phase::AwaitingMessage3, "{changed:02x?}");
            }
            Err(_) => assert_eq!(s.phase(), Phase::AwaitingMessage1, "{changed:02x?}"),
        }
    }
}

// One stream runs through the three sweeps, so each phase sees frames of its own. After its sweep each
// `Supplicant` still completes the reference exchange its phase is waiting for, byte for byte: every nonce
// asked for is `SNONCE`, so a random message 1 that was answered leaves nothing behind but a pending ANonce,
// which the reference message 1 replaces.
#[test]
fn supplicant_survives_random_frames_in_every_phase() {
    let mut stream = Stream::new();

    let mut new = Supplicant::new(params()).unwrap();
    takes_random_frames(&mut new, &mut stream);
    assert_eq!(new.handle(&M1, || SNONCE).unwrap().frame, M2);
    completes_the_reference_handshake(&mut new);

    let mut after_m1 = awaiting_message_3();
    let accepted = takes_random_frames(&mut after_m1, &mut stream);
    assert_eq!(after_m1.phase(), Phase::AwaitingMessage3);
    if accepted > 0 {
        // The last random message 1 replaced the pending ANonce: the reference message 1 puts it back.
        assert_eq!(after_m1.handle(&M1, || SNONCE).unwrap().frame, M2);
    }
    completes_the_reference_handshake(&mut after_m1);

    let mut established = awaiting_message_3();
    completes_the_reference_handshake(&mut established);
    takes_random_frames(&mut established, &mut stream);
    answers_the_reference_group_message(&mut established);
}

// The same sweep as the first test, over the frames and elements of the two captured handshakes.
#[test]
#[ignore = "needs the published captures: run `python3 -I crates/qb-wpa2/tests/fixtures/fetch_captures.py`, then `cargo test -p qb-wpa2 -- --ignored`"]
fn decoders_survive_changes_to_the_captured_frames() {
    let c = Captures::load();
    for name in [
        "linksys.M1",
        "linksys.M2",
        "linksys.M3",
        "linksys.M4",
        "induction.M3",
        "linksys.AP_RSNE",
        "induction.AP_RSNE",
        "linksys.STA_RSNE",
        "induction.KEY_DATA",
    ] {
        for bytes in changes(c.bytes(name)) {
            decoders(&bytes);
        }
    }
}
