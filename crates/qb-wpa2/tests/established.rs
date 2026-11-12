//! An established link through the public interface: the group rekey of the reference handshake byte for byte,
//! repeated messages answered without their keys, a second four-way handshake beside the installed keys, and the
//! frames an established link must refuse without changing.

#[path = "fixtures/authenticator.rs"]
mod authenticator;
#[path = "fixtures/reference.rs"]
mod reference;

use authenticator::{ApFrame, gtk_kde, pad};
use hex_literal::hex;
use qb_wpa2::Nonce;
use qb_wpa2::eapol::{EapolKey, KeyInfo, verify_mic};
use qb_wpa2::keydata::KeyDataError;
use qb_wpa2::pmk::Pmk;
use qb_wpa2::ptk::Ptk;
use qb_wpa2::rsne::SUPPLICANT_RSNE;
use qb_wpa2::secret::SecretBytes;
use qb_wpa2::supplicant::{GroupKey, HandshakeError, Params, Phase, ReplyKind, Supplicant};
use reference::{AA, ANONCE, G1, G2, GTK1, GTK2, KCK, KEK, M1, M3, PMK, RSNE, SNONCE, SPA, TK};

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

/// A `Supplicant` after the reference handshake: the TK and GTK1 (key id 1) are handed out, counter 2 is on
/// record.
fn established() -> Supplicant {
    let mut s = Supplicant::new(params()).unwrap();
    s.handle(&M1, || SNONCE).unwrap();
    let r = s.handle(&M3, no_nonce).unwrap();
    assert!(r.tk.is_some() && r.gtk.is_some());
    assert_eq!(s.phase(), Phase::Established);
    s
}

#[track_caller]
fn rejects(s: &mut Supplicant, frame: &[u8], error: HandshakeError) {
    let before = s.phase();
    assert_eq!(s.handle(frame, no_nonce).unwrap_err(), error);
    assert_eq!(s.phase(), before);
}

#[test]
fn group_rekey_matches_the_reference() {
    let mut s = established();
    let r = s.handle(&G1, no_nonce).unwrap();
    assert_eq!((r.kind, &r.frame[..]), (ReplyKind::GroupMessage2, &G2[..]));
    assert_eq!(
        r.gtk,
        Some(GroupKey {
            key_id: 2,
            tx: false,
            rsc: hex!("0a0b0c0d0e0f"),
            key: SecretBytes::new(GTK2)
        })
    );
    assert!(r.tk.is_none() && r.warning.is_none());
    assert_eq!(s.phase(), Phase::Established);
}

// Review Focus 2.
#[test]
fn repeated_message_3_is_answered_without_handing_keys_again() {
    let mut s = established();
    let r = s
        .handle(
            &ApFrame::m3(3, ANONCE, m3_key_data()).build(&KCK, &KEK),
            no_nonce,
        )
        .unwrap();
    let m4 = EapolKey::decode(&r.frame).unwrap();
    assert_eq!(
        (r.kind, m4.replay_counter, m4.info),
        (ReplyKind::Message4, 3, KeyInfo(0x030a))
    );
    assert_eq!(verify_mic(&KCK, &r.frame), Ok(true));
    assert!(r.tk.is_none() && r.gtk.is_none());
    assert_eq!(s.phase(), Phase::Established);
    // A repeat that carries a new group key hands out that key and still no TK:
    let r = s
        .handle(
            &ApFrame::m3(4, ANONCE, pad([&RSNE[..], &gtk_kde(2, &GTK2)].concat()))
                .build(&KCK, &KEK),
            no_nonce,
        )
        .unwrap();
    assert!(r.tk.is_none());
    assert_eq!(r.gtk.unwrap().key.expose(), &GTK2);
}

#[test]
fn repeated_group_message_is_answered_without_handing_the_key_again() {
    let mut s = established();
    s.handle(&G1, no_nonce).unwrap();
    let r = s
        .handle(
            &ApFrame::g1(6, gtk_kde(2, &GTK2)).build(&KCK, &KEK),
            no_nonce,
        )
        .unwrap();
    assert_eq!(
        (r.kind, EapolKey::decode(&r.frame).unwrap().replay_counter),
        (ReplyKind::GroupMessage2, 6)
    );
    assert!(r.gtk.is_none() && r.tk.is_none());
    // The same key under another key id is a different key to install:
    let r = s
        .handle(
            &ApFrame::g1(7, gtk_kde(1, &GTK2)).build(&KCK, &KEK),
            no_nonce,
        )
        .unwrap();
    assert_eq!(r.gtk.unwrap().key_id, 1);

    // Beyond the brief. And another key under the same key id is a different key to install. The key length
    // field is not checked: this frame says 16 where the reference says 0, and access points send either.
    let sixteen = ApFrame {
        key_length: 16,
        ..ApFrame::g1(8, gtk_kde(1, &GTK1))
    };
    let r = s.handle(&sixteen.build(&KCK, &KEK), no_nonce).unwrap();
    assert_eq!(r.kind, ReplyKind::GroupMessage2);
    let gtk = r.gtk.unwrap();
    assert_eq!((gtk.key_id, gtk.key.expose()), (1, &GTK1));
}

#[test]
fn pairwise_rekey_keeps_the_old_keys_until_message_3() {
    let (anonce2, snonce2) = ([0xa2; 32], [0x52; 32]);
    let new = Ptk::derive(&Pmk::from_bytes(PMK), &AA, &SPA, &anonce2, &snonce2);
    let (kck2, kek2) = (*new.kck().expose(), *new.kek().expose());
    let mut s = established();
    let r = s
        .handle(&ApFrame::m1(10, anonce2).build(&KCK, &KEK), || snonce2)
        .unwrap();
    assert_eq!(
        (r.kind, verify_mic(&kck2, &r.frame), s.phase()),
        (ReplyKind::Message2, Ok(true), Phase::Rekeying)
    );
    // The old keys still answer; counter 5 > 2.
    assert_eq!(s.handle(&G1, no_nonce).unwrap().frame, G2);
    assert_eq!(s.phase(), Phase::Rekeying);
    // Beyond the brief (rule 17): the keys of the handshake under way sign no group message.
    rejects(
        &mut s,
        &ApFrame::g1(6, gtk_kde(3, &GTK1)).build(&kck2, &kek2),
        HandshakeError::BadMic,
    );
    let m3 =
        ApFrame::m3(11, anonce2, pad([&RSNE[..], &gtk_kde(2, &GTK2)].concat())).build(&kck2, &kek2);
    let r = s.handle(&m3, no_nonce).unwrap();
    assert_eq!(
        (r.kind, verify_mic(&kck2, &r.frame), s.phase()),
        (ReplyKind::Message4, Ok(true), Phase::Established)
    );
    assert_eq!(r.tk.as_ref(), Some(new.tk()));
    assert_ne!(new.tk().expose(), &TK);
    // GTK2 was already handed out.
    assert!(r.gtk.is_none());
    rejects(
        &mut s,
        &ApFrame::m3(12, ANONCE, m3_key_data()).build(&KCK, &KEK),
        HandshakeError::AnonceMismatch,
    );
}

#[test]
fn forged_message_1_cannot_break_an_established_link() {
    let mut s = established();
    s.handle(&ApFrame::m1(1000, [0xee; 32]).build(&KCK, &KEK), || {
        [0x99; 32]
    })
    .unwrap();
    assert_eq!(s.phase(), Phase::Rekeying);
    // The pending SNonce is reused.
    s.handle(&ApFrame::m1(3, [0xef; 32]).build(&KCK, &KEK), no_nonce)
        .unwrap();
    assert_eq!(s.handle(&G1, no_nonce).unwrap().frame, G2);
    let r = s
        .handle(
            &ApFrame::m3(6, ANONCE, m3_key_data()).build(&KCK, &KEK),
            no_nonce,
        )
        .unwrap();
    assert!(r.kind == ReplyKind::Message4 && r.tk.is_none());
    // The group key handed out last is GTK2 (via G1), so GTK1, which the repeated message 3 carries again, differs
    // from it and is handed out again: the record is one group key deep.
    let gtk = r.gtk.as_ref().unwrap();
    assert_eq!((gtk.key_id, gtk.key.expose()), (1, &GTK1));
    assert_eq!(s.phase(), Phase::Rekeying);

    // Beyond the brief. A forged message 1 that repeats the established ANonce: a message 3 with that ANonce
    // now has two candidates, and it belongs to the one whose KCK verifies it.
    let pending = Ptk::derive(&Pmk::from_bytes(PMK), &AA, &SPA, &ANONCE, &[0x99; 32]);
    let (pending_kck, pending_kek) = (*pending.kck().expose(), *pending.kek().expose());
    let r = s
        .handle(&ApFrame::m1(7, ANONCE).build(&KCK, &KEK), no_nonce)
        .unwrap();
    assert_eq!(verify_mic(&pending_kck, &r.frame), Ok(true));
    // The established keys: a repeated message 3, answered under them, and the handshake under way stays.
    let r = s
        .handle(
            &ApFrame::m3(8, ANONCE, m3_key_data()).build(&KCK, &KEK),
            no_nonce,
        )
        .unwrap();
    assert_eq!(
        (r.kind, verify_mic(&KCK, &r.frame), s.phase()),
        (ReplyKind::Message4, Ok(true), Phase::Rekeying)
    );
    assert!(r.tk.is_none() && r.gtk.is_none());
    // Neither: refused, and the key data is unwrapped only under the KEK that belongs to the KCK that verified.
    let m3 = ApFrame::m3(9, ANONCE, m3_key_data());
    rejects(&mut s, &m3.build(&[0x11; 16], &KEK), HandshakeError::BadMic);
    rejects(
        &mut s,
        &m3.build(&KCK, &pending_kek),
        HandshakeError::KeyData(KeyDataError::Unwrap),
    );
    rejects(
        &mut s,
        &m3.build(&pending_kck, &KEK),
        HandshakeError::KeyData(KeyDataError::Unwrap),
    );
    // The handshake under way: its message 3 completes it, and its TK is a new key to install.
    let r = s
        .handle(&m3.build(&pending_kck, &pending_kek), no_nonce)
        .unwrap();
    assert_eq!(
        (r.kind, verify_mic(&pending_kck, &r.frame), s.phase()),
        (ReplyKind::Message4, Ok(true), Phase::Established)
    );
    assert_eq!(r.tk.as_ref(), Some(pending.tk()));
    assert!(r.gtk.is_none());
}

// One established `Supplicant` that has already answered `G1` goes through the table: counter 5 is on record,
// and GTK2 (key id 2) is the group key handed out last.
#[test]
fn established_rejections_change_nothing() {
    let mut s = established();
    assert_eq!(s.handle(&G1, no_nonce).unwrap().frame, G2);
    assert_eq!(s.phase(), Phase::Established);
    let untouched = format!("{s:?}");

    let g1 = || ApFrame::g1(8, gtk_kde(3, &GTK1));
    // Counter 2, counter 5, and a message 1 that carries no MIC: none exceeds the counter on record.
    rejects(&mut s, &M3, HandshakeError::Replay);
    rejects(&mut s, &G1, HandshakeError::Replay);
    rejects(
        &mut s,
        &ApFrame::m1(5, ANONCE).build(&KCK, &KEK),
        HandshakeError::Replay,
    );
    rejects(
        &mut s,
        &g1().build(&[0x11; 16], &KEK),
        HandshakeError::BadMic,
    );
    // Not Encrypted: the test double then leaves the key data in the clear.
    let in_clear = ApFrame {
        info: 0x0382,
        ..g1()
    };
    rejects(
        &mut s,
        &in_clear.build(&KCK, &KEK),
        HandshakeError::NotEncrypted,
    );
    rejects(
        &mut s,
        &g1().build(&KCK, &[0x22; 16]),
        HandshakeError::KeyData(KeyDataError::Unwrap),
    );
    rejects(
        &mut s,
        &ApFrame::g1(8, pad(RSNE.to_vec())).build(&KCK, &KEK),
        HandshakeError::GtkMissing,
    );
    rejects(
        &mut s,
        &ApFrame::m3(8, [0xab; 32], m3_key_data()).build(&KCK, &KEK),
        HandshakeError::AnonceMismatch,
    );
    rejects(
        &mut s,
        &ApFrame::m3(8, ANONCE, m3_key_data()).build(&[0x11; 16], &KEK),
        HandshakeError::BadMic,
    );

    // Beyond the brief's table: the order of the rules, where one frame breaks two. A group message whose MIC
    // is wrong is told nothing else, not that its key data is in the clear nor whether it unwraps.
    rejects(
        &mut s,
        &in_clear.build(&[0x11; 16], &KEK),
        HandshakeError::BadMic,
    );
    rejects(
        &mut s,
        &g1().build(&[0x11; 16], &[0x22; 16]),
        HandshakeError::BadMic,
    );
    // A repeated message 3 is held to rules 12 to 14 like the first one: Install, and the advertised RSN
    // element.
    let no_install = ApFrame {
        info: 0x138a,
        ..ApFrame::m3(8, ANONCE, m3_key_data())
    };
    rejects(
        &mut s,
        &no_install.build(&KCK, &KEK),
        HandshakeError::InstallNotSet,
    );
    rejects(
        &mut s,
        &ApFrame::m3(8, ANONCE, gtk_kde(1, &GTK1)).build(&KCK, &KEK),
        HandshakeError::RsneMismatch,
    );

    // Nothing changed: not the phase, not the counter on record (every refused frame above carried a counter
    // of 8 or less, and 9 is still accepted), not the group key handed out last.
    assert_eq!(format!("{s:?}"), untouched);
    assert_eq!(s.phase(), Phase::Established);
    let r = s
        .handle(
            &ApFrame::g1(9, gtk_kde(3, &GTK1)).build(&KCK, &KEK),
            no_nonce,
        )
        .unwrap();
    assert_eq!(r.kind, ReplyKind::GroupMessage2);
    assert_eq!(r.gtk.unwrap().key_id, 3);
}
