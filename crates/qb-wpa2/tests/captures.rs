//! Two captured real handshakes through the public interface: one replayed byte for byte, one from a network
//! outside the scope. Nothing of the captures is in this repository, so both tests are ignored until
//! `fixtures/fetch_captures.py` has downloaded them; its doc string says what they are and where they come from.

#[path = "fixtures/captures.rs"]
mod captures;

use captures::Captures;
use hex_literal::hex;
use qb_wpa2::Nonce;
use qb_wpa2::eapol::{EapolKey, verify_mic};
use qb_wpa2::keydata::{KeyDataError, parse_key_data, unwrap_key_data};
use qb_wpa2::pmk::Pmk;
use qb_wpa2::ptk::Ptk;
use qb_wpa2::rsne::{RsneError, SUPPLICANT_RSNE};
use qb_wpa2::secret::SecretBytes;
use qb_wpa2::supplicant::{GroupKey, HandshakeError, Params, Phase, Supplicant};

// A real access point and a real station: this crate, given the station's SNonce, must send what the station sent.
#[test]
#[ignore = "needs the published captures: run `python3 -I crates/qb-wpa2/tests/fixtures/fetch_captures.py`, then `cargo test -p qb-wpa2 -- --ignored`"]
fn linksys_capture_replays_byte_for_byte() {
    let c = Captures::load();
    let pmk = Pmk::from_passphrase("dictionary", b"linksys").unwrap();
    // `wpa_passphrase linksys dictionary`
    assert_eq!(
        pmk.expose(),
        &hex!("5df920b5481ed70538dd5fd02423d7e2522205feeebb974cad08a52b5613ede2")
    );
    let mut s = Supplicant::new(Params {
        pmk,
        aa: c.array("linksys.AA"),
        spa: c.array("linksys.SPA"),
        ap_rsne: c.bytes("linksys.AP_RSNE").to_vec(),
        ap_rsnxe: None,
        own_rsne: c.bytes("linksys.STA_RSNE").to_vec(),
    })
    .unwrap();
    let (m1, m2) = (c.bytes("linksys.M1"), c.bytes("linksys.M2"));
    let (m3, m4) = (c.bytes("linksys.M3"), c.bytes("linksys.M4"));
    let snonce: Nonce = m2[17..49].try_into().unwrap();
    // Message 1 carries a PMKID KDE, which is ignored.
    assert_eq!(s.handle(m1, || snonce).unwrap().frame, m2);
    let r = s.handle(m3, || unreachable!()).unwrap();
    assert_eq!(r.frame, m4);
    assert_eq!(r.tk.unwrap().expose(), &c.array("linksys.TK"));
    assert_eq!(
        r.gtk,
        Some(GroupKey {
            key_id: 1,
            tx: false,
            rsc: [0; 6],
            key: SecretBytes::new(c.array("linksys.GTK"))
        })
    );
    assert_eq!((r.warning, s.phase()), (None, Phase::Established));
}

// A real network outside the scope: refused before association, and its message 3 would not have slipped through.
// Review Focus 4.
#[test]
#[ignore = "needs the published captures: run `python3 -I crates/qb-wpa2/tests/fixtures/fetch_captures.py`, then `cargo test -p qb-wpa2 -- --ignored`"]
fn induction_capture_is_a_mixed_mode_network_and_is_refused() {
    let c = Captures::load();
    let (aa, spa) = (c.array("induction.AA"), c.array("induction.SPA"));
    let pmk = Pmk::from_passphrase("Induction", b"Coherer").unwrap();
    // `wpa_passphrase Coherer Induction`
    assert_eq!(
        pmk.expose(),
        &hex!("a288fcf0caaacda9a9f58633ff35e8992a01d9c10ba5e02efdf8cb5d730ce7bc")
    );
    let refused = Supplicant::new(Params {
        pmk: pmk.clone(),
        aa,
        spa,
        ap_rsne: c.bytes("induction.AP_RSNE").to_vec(),
        ap_rsnxe: None,
        own_rsne: SUPPLICANT_RSNE.to_vec(),
    });
    assert_eq!(
        refused.unwrap_err(),
        HandshakeError::ApRsne(RsneError::GroupCipherNotCcmp)
    );
    let frame = c.bytes("induction.M3");
    let m3 = EapolKey::decode(frame).unwrap();
    let ptk = Ptk::derive(&pmk, &aa, &spa, &m3.nonce, &c.array("induction.SNONCE"));
    assert_eq!(verify_mic(ptk.kck().expose(), frame), Ok(true));
    let plain = unwrap_key_data(ptk.kek().expose(), &m3.key_data).unwrap();
    assert_eq!(plain.as_slice(), c.bytes("induction.KEY_DATA"));
    assert_eq!(parse_key_data(&plain).unwrap_err(), KeyDataError::GtkLength);
}
