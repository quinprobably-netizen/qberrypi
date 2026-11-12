//! The first four-way handshake through the public interface: the reference handshake byte for byte, and the
//! frames the state machine must refuse without changing.

#[path = "fixtures/authenticator.rs"]
mod authenticator;
#[path = "fixtures/reference.rs"]
mod reference;

use authenticator::{ApFrame, gtk_kde, pad};
use hex_literal::hex;
use qb_wpa2::Nonce;
use qb_wpa2::eapol::{EapolKey, FrameError, sign, verify_mic};
use qb_wpa2::keydata::KeyDataError;
use qb_wpa2::pmk::Pmk;
use qb_wpa2::ptk::Ptk;
use qb_wpa2::rsne::{RsneError, SUPPLICANT_RSNE};
use qb_wpa2::secret::SecretBytes;
use qb_wpa2::supplicant::{
    GroupKey, HandshakeError, Params, Phase, ReplyKind, Supplicant, Warning,
};
use reference::{AA, ANONCE, G1, GTK1, GTK2, KCK, KEK, M1, M2, M3, M4, PMK, RSNE, SNONCE, SPA, TK};

fn params() -> Params {
    Params {
        pmk: Pmk::from_bytes(PMK),
        aa: AA,
        spa: SPA,
        ap_rsne: RSNE.to_vec(),
        ap_rsnxe: None,
        own_rsne: SUPPLICANT_RSNE.to_vec(),
    }
}

fn no_nonce() -> Nonce {
    panic!("no SNonce may be requested here")
}

fn m3_key_data() -> Vec<u8> {
    pad([&RSNE[..], &gtk_kde(1, &GTK1)].concat())
}

fn awaiting_message_3() -> Supplicant {
    let mut s = Supplicant::new(params()).unwrap();
    assert_eq!(s.handle(&M1, || SNONCE).unwrap().frame, M2);
    assert_eq!(s.phase(), Phase::AwaitingMessage3);
    s
}

fn rejects(s: &mut Supplicant, frame: &[u8], error: HandshakeError) {
    let before = s.phase();
    assert_eq!(s.handle(frame, no_nonce).unwrap_err(), error);
    assert_eq!(s.phase(), before);
}

/// A copy of `frame` with `bytes` written over it from offset `at`.
fn with(frame: &[u8], at: usize, bytes: &[u8]) -> Vec<u8> {
    let mut changed = frame.to_vec();
    changed[at..at + bytes.len()].copy_from_slice(bytes);
    changed
}

/// The group key message 3 of the reference handshake delivers.
fn reference_group_key() -> GroupKey {
    GroupKey {
        key_id: 1,
        tx: false,
        rsc: hex!("112233445566"),
        key: SecretBytes::new(GTK1),
    }
}

// The test double is itself checked against Python and OpenSSL before anything relies on it.
#[test]
fn authenticator_reproduces_the_reference_frames() {
    assert_eq!(ApFrame::m1(1, ANONCE).build(&KCK, &KEK), M1);
    let mut m3 = ApFrame::m3(2, ANONCE, m3_key_data());
    m3.rsc = hex!("1122334455660000");
    assert_eq!(m3.build(&KCK, &KEK), M3);
    let mut g1 = ApFrame::g1(5, gtk_kde(2, &GTK2));
    g1.rsc = hex!("0a0b0c0d0e0f0000");
    assert_eq!(g1.build(&KCK, &KEK), G1);
}

#[test]
fn four_way_handshake_matches_the_reference() {
    let mut s = Supplicant::new(params()).unwrap();
    assert_eq!(s.phase(), Phase::AwaitingMessage1);
    let r = s.handle(&M1, || SNONCE).unwrap();
    assert_eq!((r.kind, &r.frame[..]), (ReplyKind::Message2, &M2[..]));
    assert!(r.tk.is_none() && r.gtk.is_none() && r.warning.is_none());
    assert_eq!(s.phase(), Phase::AwaitingMessage3);
    let r = s.handle(&M3, no_nonce).unwrap();
    assert_eq!((r.kind, &r.frame[..]), (ReplyKind::Message4, &M4[..]));
    assert_eq!(r.tk.unwrap().expose(), &TK);
    assert_eq!(
        r.gtk,
        Some(GroupKey {
            key_id: 1,
            tx: false,
            rsc: hex!("112233445566"),
            key: SecretBytes::new(GTK1)
        })
    );
    assert_eq!(r.warning, None);
    assert_eq!(s.phase(), Phase::Established);
}

// One `Supplicant` goes through both tables and then completes the reference handshake: no refused frame left
// anything behind, a replay counter least of all (every refused message 3 carries counter 2, as `M3` does).
#[test]
fn first_handshake_rejections_change_nothing() {
    let mut s = Supplicant::new(params()).unwrap();
    assert_eq!(s.phase(), Phase::AwaitingMessage1);
    let untouched = format!("{s:?}");

    rejects(&mut s, &M3, HandshakeError::WrongPhase);
    rejects(&mut s, &G1, HandshakeError::WrongPhase);
    // A supplicant's frame: no Ack.
    rejects(&mut s, &M2, HandshakeError::UnexpectedFlags);
    // Key descriptor version 1.
    rejects(
        &mut s,
        &with(&M1, 5, &hex!("0089")),
        HandshakeError::KeyVersion,
    );
    // Request.
    rejects(
        &mut s,
        &with(&M1, 5, &hex!("088a")),
        HandshakeError::UnexpectedFlags,
    );
    // Install without MIC.
    rejects(
        &mut s,
        &with(&M1, 5, &hex!("00ca")),
        HandshakeError::UnexpectedFlags,
    );
    rejects(
        &mut s,
        &M1[..98],
        HandshakeError::Frame(FrameError::Truncated),
    );
    // 254 is the WPA1 descriptor.
    rejects(
        &mut s,
        &with(&M1, 4, &[254]),
        HandshakeError::Frame(FrameError::NotRsnDescriptor),
    );
    // The order of the rules, where one frame breaks two: the descriptor type before the descriptor version,
    // and the version before the flags.
    rejects(
        &mut s,
        &with(&with(&M1, 4, &[254]), 5, &hex!("0089")),
        HandshakeError::Frame(FrameError::NotRsnDescriptor),
    );
    rejects(
        &mut s,
        &with(&M1, 5, &hex!("0889")),
        HandshakeError::KeyVersion,
    );

    assert_eq!(format!("{s:?}"), untouched);
    let r = s.handle(&M1, || SNONCE).unwrap();
    assert_eq!((r.kind, &r.frame[..]), (ReplyKind::Message2, &M2[..]));
    assert!(r.tk.is_none() && r.gtk.is_none() && r.warning.is_none());
    assert_eq!(s.phase(), Phase::AwaitingMessage3);
    let untouched = format!("{s:?}");

    let m3 = || ApFrame::m3(2, ANONCE, m3_key_data());
    let m3_with = |key_data: Vec<u8>| ApFrame::m3(2, ANONCE, key_data).build(&KCK, &KEK);
    // The last byte of the MIC: a comparison of anything less than the whole field would let it pass.
    rejects(
        &mut s,
        &with(&M3, 96, &[M3[96] ^ 0x01]),
        HandshakeError::BadMic,
    );
    rejects(
        &mut s,
        &m3().build(&[0x11; 16], &KEK),
        HandshakeError::BadMic,
    );
    rejects(
        &mut s,
        &ApFrame::m3(2, [0xab; 32], m3_key_data()).build(&KCK, &KEK),
        HandshakeError::AnonceMismatch,
    );
    // No Install.
    let no_install = ApFrame {
        info: 0x138a,
        ..m3()
    };
    rejects(
        &mut s,
        &no_install.build(&KCK, &KEK),
        HandshakeError::InstallNotSet,
    );
    // Not Encrypted: the test double then leaves the key data in the clear.
    let in_clear = ApFrame {
        info: 0x03ca,
        ..m3()
    };
    rejects(
        &mut s,
        &in_clear.build(&KCK, &KEK),
        HandshakeError::NotEncrypted,
    );
    let long_key = ApFrame {
        key_length: 32,
        ..m3()
    };
    rejects(
        &mut s,
        &long_key.build(&KCK, &KEK),
        HandshakeError::KeyLength,
    );
    rejects(
        &mut s,
        &m3().build(&KCK, &[0x22; 16]),
        HandshakeError::KeyData(KeyDataError::Unwrap),
    );
    rejects(
        &mut s,
        &m3_with(pad([&RSNE[..], &gtk_kde(1, &[0x33; 32])].concat())),
        HandshakeError::KeyData(KeyDataError::GtkLength),
    );
    // Byte 20 of the element is the low byte of its capabilities: one changed byte is a downgrade attempt.
    let other_rsne = with(&RSNE, 20, &[0x0c]);
    rejects(
        &mut s,
        &m3_with(pad([&other_rsne[..], &gtk_kde(1, &GTK1)].concat())),
        HandshakeError::RsneMismatch,
    );
    // No RSN element at all.
    rejects(
        &mut s,
        &m3_with(gtk_kde(1, &GTK1)),
        HandshakeError::RsneMismatch,
    );
    rejects(
        &mut s,
        &m3_with(pad(RSNE.to_vec())),
        HandshakeError::GtkMissing,
    );
    rejects(&mut s, &G1, HandshakeError::WrongPhase);

    // The order of the rules, where one frame breaks several. The ANonce is compared before the MIC.
    rejects(
        &mut s,
        &ApFrame::m3(2, [0xab; 32], m3_key_data()).build(&[0x11; 16], &KEK),
        HandshakeError::AnonceMismatch,
    );
    // A frame whose MIC is wrong is told nothing else: not what its flags lack, not whether it unwraps.
    let nothing_right = ApFrame {
        info: 0x038a,
        key_length: 32,
        ..m3()
    };
    rejects(
        &mut s,
        &nothing_right.build(&[0x11; 16], &KEK),
        HandshakeError::BadMic,
    );
    rejects(
        &mut s,
        &m3().build(&[0x11; 16], &[0x22; 16]),
        HandshakeError::BadMic,
    );
    // Install, then Encrypted, then the key length, and all three before the key data is unwrapped.
    rejects(
        &mut s,
        &nothing_right.build(&KCK, &KEK),
        HandshakeError::InstallNotSet,
    );
    let in_clear_and_long = ApFrame {
        info: 0x03ca,
        key_length: 32,
        ..m3()
    };
    rejects(
        &mut s,
        &in_clear_and_long.build(&KCK, &KEK),
        HandshakeError::NotEncrypted,
    );
    rejects(
        &mut s,
        &long_key.build(&KCK, &[0x22; 16]),
        HandshakeError::KeyLength,
    );
    // Padding and nothing else: the RSN element is missed before the group key is.
    rejects(
        &mut s,
        &m3_with(hex!("dd000000000000000000000000000000").to_vec()),
        HandshakeError::RsneMismatch,
    );

    assert_eq!(format!("{s:?}"), untouched);
    let r = s.handle(&M3, no_nonce).unwrap();
    assert_eq!((r.kind, &r.frame[..]), (ReplyKind::Message4, &M4[..]));
    assert_eq!(r.tk.unwrap().expose(), &TK);
    assert_eq!(r.gtk, Some(reference_group_key()));
    assert_eq!(r.warning, None);
    assert_eq!(s.phase(), Phase::Established);

    // Counter 2 is on record now, put there by the message 3 whose MIC verified. An access point's frame that
    // does not exceed it is a replay; the flags are still judged first.
    rejects(&mut s, &M3, HandshakeError::Replay);
    rejects(&mut s, &M1, HandshakeError::Replay);
    rejects(&mut s, &M2, HandshakeError::UnexpectedFlags);
}

#[test]
fn repeated_message_1_reuses_the_snonce() {
    let mut s = awaiting_message_3();
    let r = s
        .handle(&ApFrame::m1(2, ANONCE).build(&KCK, &KEK), no_nonce)
        .unwrap();
    let again = EapolKey::decode(&r.frame).unwrap();
    assert_eq!((again.replay_counter, again.nonce), (2, SNONCE));
    assert_eq!(verify_mic(&KCK, &r.frame), Ok(true));
    assert_eq!(s.phase(), Phase::AwaitingMessage3);
    // Message 1 never puts a counter on record.
    assert_eq!(s.handle(&M3, no_nonce).unwrap().frame, M4);

    // A message 1 with another ANonce replaces the pending handshake: the same SNonce, and the keys of the
    // new pair of nonces.
    let other_anonce = [0x5a; 32];
    let ptk = Ptk::derive(&Pmk::from_bytes(PMK), &AA, &SPA, &other_anonce, &SNONCE);
    let (kck, kek) = (ptk.kck().expose(), ptk.kek().expose());
    let mut s = awaiting_message_3();
    let r = s
        .handle(&ApFrame::m1(2, other_anonce).build(&KCK, &KEK), no_nonce)
        .unwrap();
    assert_eq!(EapolKey::decode(&r.frame).unwrap().nonce, SNONCE);
    assert_eq!(verify_mic(kck, &r.frame), Ok(true));
    assert_eq!(verify_mic(&KCK, &r.frame), Ok(false));
    // The message 3 of the handshake it replaced fits no longer, by its ANonce or by its keys.
    rejects(&mut s, &M3, HandshakeError::AnonceMismatch);
    let m3 = ApFrame::m3(3, other_anonce, m3_key_data());
    rejects(&mut s, &m3.build(&KCK, &KEK), HandshakeError::BadMic);
    let r = s.handle(&m3.build(kck, kek), no_nonce).unwrap();
    assert_eq!(r.kind, ReplyKind::Message4);
    assert_eq!(verify_mic(kck, &r.frame), Ok(true));
    assert_eq!(r.tk.unwrap().expose(), ptk.tk().expose());
    assert_eq!(s.phase(), Phase::Established);
}

// Review Focus 1.
#[test]
fn a_wrong_passphrase_stalls_awaiting_message_3() {
    let mut s = Supplicant::new(Params {
        pmk: Pmk::from_bytes([0x11; 32]),
        ..params()
    })
    .unwrap();
    let r = s.handle(&M1, || SNONCE).unwrap();
    assert_ne!(r.frame[81..97], M2[81..97]);
    // The access point just repeats message 1.
    for counter in 2..5 {
        s.handle(&ApFrame::m1(counter, ANONCE).build(&KCK, &KEK), no_nonce)
            .unwrap();
        assert_eq!(s.phase(), Phase::AwaitingMessage3);
    }
    rejects(&mut s, &M3, HandshakeError::BadMic);
}

#[test]
fn rsnxe_mismatch_is_reported_not_fatal() {
    let x = hex!("f40120");
    let with_x =
        ApFrame::m3(2, ANONCE, pad([&RSNE[..], &x, &gtk_kde(1, &GTK1)].concat())).build(&KCK, &KEK);
    // A `Supplicant` whose access point advertised `ap_rsnxe`, after message 1.
    let advertised = |ap_rsnxe: Option<Vec<u8>>| {
        let mut s = Supplicant::new(Params {
            ap_rsnxe,
            ..params()
        })
        .unwrap();
        s.handle(&M1, || SNONCE).unwrap();
        s
    };

    // Advertised, absent from message 3.
    let mut s = advertised(Some(x.to_vec()));
    let r = s.handle(&M3, no_nonce).unwrap();
    assert_eq!(r.warning, Some(Warning::RsnxeMismatch));
    assert_eq!((r.kind, &r.frame[..]), (ReplyKind::Message4, &M4[..]));
    assert_eq!(r.tk.unwrap().expose(), &TK);
    assert_eq!(r.gtk, Some(reference_group_key()));
    assert_eq!(s.phase(), Phase::Established);

    // Not advertised, present in message 3.
    let mut s = advertised(None);
    let r = s.handle(&with_x, no_nonce).unwrap();
    assert_eq!(r.warning, Some(Warning::RsnxeMismatch));
    assert_eq!((r.kind, &r.frame[..]), (ReplyKind::Message4, &M4[..]));
    assert_eq!(r.tk.unwrap().expose(), &TK);
    assert_eq!(s.phase(), Phase::Established);

    // Advertised and repeated.
    let mut s = advertised(Some(x.to_vec()));
    let r = s.handle(&with_x, no_nonce).unwrap();
    assert_eq!(r.warning, None);
    assert_eq!((r.kind, &r.frame[..]), (ReplyKind::Message4, &M4[..]));
    assert_eq!(r.tk.unwrap().expose(), &TK);
    assert_eq!(s.phase(), Phase::Established);
}

// Review Focus 5.
#[test]
fn trailing_bytes_after_the_frame_are_ignored() {
    let mut s = Supplicant::new(params()).unwrap();
    assert_eq!(
        s.handle(&[&M1[..], &[0; 3]].concat(), || SNONCE)
            .unwrap()
            .frame,
        M2
    );
    assert_eq!(
        s.handle(&[&M3[..], &[0; 6]].concat(), no_nonce)
            .unwrap()
            .frame,
        M4
    );

    // The other half of the focus: a body two bytes longer than its key data, and link-layer padding after
    // that. The MIC covers the two body bytes, so the access point signs the frame as it is sent.
    let long_m1 = [&with(&M1, 2, &hex!("0061"))[..], &[0xee; 2], &[0; 3]].concat();
    let mut long_m3 = [&with(&M3, 2, &hex!("0099"))[..], &[0xee; 2], &[0; 3]].concat();
    assert_eq!(verify_mic(&KCK, &long_m3), Ok(false));
    sign(&KCK, &mut long_m3).unwrap();
    let mut s = Supplicant::new(params()).unwrap();
    assert_eq!(s.handle(&long_m1, || SNONCE).unwrap().frame, M2);
    assert_eq!(s.handle(&long_m3, no_nonce).unwrap().frame, M4);
    assert_eq!(s.phase(), Phase::Established);
}

// Review Focus 4.
#[test]
fn networks_outside_scope_are_refused_at_construction() {
    // A mixed WPA/WPA2 network: TKIP group cipher, CCMP and TKIP pairwise, PSK.
    let mixed = hex!("30180100000fac020200000fac04000fac020100000fac020000").to_vec();
    // CCMP, CCMP, PSK, and protected management frames required.
    let pmf = hex!("30140100000fac040100000fac040100000fac02c000").to_vec();
    // A station's element that claims to be capable of protected management frames.
    let own_pmf = hex!("30140100000fac040100000fac040100000fac028000").to_vec();
    assert_eq!(
        Supplicant::new(Params {
            ap_rsne: mixed,
            ..params()
        })
        .unwrap_err(),
        HandshakeError::ApRsne(RsneError::GroupCipherNotCcmp)
    );
    assert_eq!(
        Supplicant::new(Params {
            ap_rsne: pmf,
            ..params()
        })
        .unwrap_err(),
        HandshakeError::ApRsne(RsneError::PmfRequired)
    );
    assert_eq!(
        Supplicant::new(Params {
            ap_rsne: vec![0x30],
            ..params()
        })
        .unwrap_err(),
        HandshakeError::ApRsne(RsneError::Truncated)
    );
    assert_eq!(
        Supplicant::new(Params {
            own_rsne: own_pmf,
            ..params()
        })
        .unwrap_err(),
        HandshakeError::OwnRsne(RsneError::NotWpa2PskCcmp)
    );
}

#[test]
fn nothing_secret_is_printed() {
    /// The decimal list form of `bytes`: `{:?}` without its brackets.
    fn list(bytes: &[u8]) -> String {
        format!("{bytes:?}")
            .trim_matches(['[', ']'].as_slice())
            .to_owned()
    }
    /// `bytes` as lower-case hex digits.
    fn lower_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    let mut s = Supplicant::new(params()).unwrap();
    let message_2 = s.handle(&M1, || SNONCE).unwrap();
    let pending = format!("{s:?}");
    let message_4 = s.handle(&M3, no_nonce).unwrap();
    assert!(message_4.tk.is_some() && message_4.gtk.is_some());
    assert_eq!(s.phase(), Phase::Established);
    let text = [
        format!("{:?}", params()),
        pending,
        format!("{s:?}"),
        format!("{message_2:?}"),
        format!("{message_4:?}"),
    ]
    .join("\n");

    assert!(text.contains("<redacted>"));
    for secret in [&PMK[..], &KCK, &KEK, &TK, &GTK1] {
        assert!(!text.to_lowercase().contains(&lower_hex(secret)));
        assert!(!text.contains(&list(secret)));
    }
    // The search finds what is printed: the ANonce is public and both forms of the state hold it.
    assert!(text.contains(&list(&ANONCE)));
}

#[test]
fn every_error_has_its_own_sentence() {
    // The first four print the sentence of the error they carry.
    assert_eq!(
        HandshakeError::Frame(FrameError::Truncated).to_string(),
        FrameError::Truncated.to_string()
    );
    assert_eq!(
        HandshakeError::KeyData(KeyDataError::Unwrap).to_string(),
        KeyDataError::Unwrap.to_string()
    );
    assert_eq!(
        HandshakeError::ApRsne(RsneError::GroupCipherNotCcmp).to_string(),
        "group cipher is not CCMP (mixed WPA/WPA2 network)"
    );
    assert_eq!(
        HandshakeError::OwnRsne(RsneError::NotWpa2PskCcmp).to_string(),
        RsneError::NotWpa2PskCcmp.to_string()
    );
    assert_eq!(
        HandshakeError::from(FrameError::KeyDataOverrun),
        HandshakeError::Frame(FrameError::KeyDataOverrun)
    );
    assert_eq!(
        HandshakeError::from(KeyDataError::Duplicate),
        HandshakeError::KeyData(KeyDataError::Duplicate)
    );

    let sentences = [
        HandshakeError::KeyVersion,
        HandshakeError::UnexpectedFlags,
        HandshakeError::WrongPhase,
        HandshakeError::Replay,
        HandshakeError::AnonceMismatch,
        HandshakeError::BadMic,
        HandshakeError::InstallNotSet,
        HandshakeError::NotEncrypted,
        HandshakeError::KeyLength,
        HandshakeError::RsneMismatch,
        HandshakeError::GtkMissing,
    ]
    .map(|error| error.to_string());
    for (i, sentence) in sentences.iter().enumerate() {
        assert!(!sentence.is_empty());
        assert!(!sentences[..i].contains(sentence), "{sentence}");
    }
    let _: &dyn std::error::Error = &HandshakeError::BadMic;
}
