//! Choosing which scanned access point to try.

use std::cmp::Reverse;
use std::fmt;

use qb_wpa2::MacAddr;
use qb_wpa2::rsne::{Rsne, RsneError};

use super::ies::{self, EID_RSN, EID_RSNX, EID_SSID};
use crate::netlink::nl80211::Bss;

/// The frequency band of a channel, in order of preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Band {
    Ghz5,
    Ghz2,
    Other,
}

/// The band a frequency in MHz belongs to.
pub fn band(freq_mhz: u32) -> Band {
    match freq_mhz {
        5000..=5900 => Band::Ghz5,
        2400..=2500 => Band::Ghz2,
        _ => Band::Other,
    }
}

/// An access point worth trying, with what the handshake needs from its beacon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub bssid: MacAddr,
    pub freq_mhz: u32,
    pub signal_mbm: i32,
    /// The access point's RSN element, whole: message 3 has to repeat it.
    pub rsne: Vec<u8>,
    /// The access point's RSN extension element, whole, if it sends one.
    pub rsnxe: Option<Vec<u8>>,
}

/// Why an access point with the right name is not tried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    /// The beacon has no RSN element: an open network, or WPA without WPA2.
    NoRsne,
    /// The RSN element is unreadable or advertises more or less than WPA2-PSK with CCMP.
    Rsne(RsneError),
}

impl fmt::Display for Skip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRsne => f.write_str("no RSN element (not a WPA2 network)"),
            Self::Rsne(error) => fmt::Display::fmt(error, f),
        }
    }
}

/// What a scan found for one network name.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Survey {
    /// How many access points the scan returned, of any name.
    pub seen: usize,
    /// The access points to try, the one to try first at the front.
    pub candidates: Vec<Candidate>,
    /// The access points with the right name that cannot be used, in scan order: address, frequency, reason.
    pub skipped: Vec<(MacAddr, u32, Skip)>,
}

/// Sorts the scan results for `ssid` into candidates and skipped access points.
///
/// Candidates are ordered by: not in `failed` before in `failed`; then band, 5 GHz first; then the stronger
/// signal; then the smaller address.
pub fn survey(results: &[Bss], ssid: &[u8], failed: &[MacAddr]) -> Survey {
    let mut survey = Survey {
        seen: results.len(),
        ..Survey::default()
    };
    for bss in results {
        if ies::body(&bss.ies, EID_SSID) != Some(ssid) {
            continue;
        }
        let Some(rsne) = ies::element(&bss.ies, EID_RSN) else {
            survey.skipped.push((bss.bssid, bss.freq_mhz, Skip::NoRsne));
            continue;
        };
        if let Err(error) = Rsne::parse(rsne).and_then(|rsne| rsne.check_access_point()) {
            survey
                .skipped
                .push((bss.bssid, bss.freq_mhz, Skip::Rsne(error)));
            continue;
        }
        survey.candidates.push(Candidate {
            bssid: bss.bssid,
            freq_mhz: bss.freq_mhz,
            signal_mbm: bss.signal_mbm,
            rsne: rsne.to_vec(),
            rsnxe: ies::element(&bss.ies, EID_RSNX).map(<[u8]>::to_vec),
        });
    }
    survey.candidates.sort_by_key(|candidate| {
        (
            failed.contains(&candidate.bssid),
            band(candidate.freq_mhz),
            Reverse(candidate.signal_mbm),
            candidate.bssid,
        )
    });
    survey
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use qb_wpa2::rsne::SUPPLICANT_RSNE;

    const WPA2: [u8; 22] = SUPPLICANT_RSNE;
    const NAME: &[u8] = b"example-network";

    /// A BSS with the sample prefix a0:a1:a1:a3:a4:xx.
    fn bss(mac_last_byte: u8, freq: u32, mbm: i32, ies: Vec<u8>) -> Bss {
        Bss {
            bssid: [0xa0, 0xa1, 0xa1, 0xa3, 0xa4, mac_last_byte],
            freq_mhz: freq,
            signal_mbm: mbm,
            ies,
        }
    }

    /// An SSID element followed by `rest`.
    fn ies(ssid: &[u8], rest: &[u8]) -> Vec<u8> {
        [&[0, u8::try_from(ssid.len()).unwrap()][..], ssid, rest].concat()
    }

    fn addr(last: u8) -> MacAddr {
        [0xa0, 0xa1, 0xa1, 0xa3, 0xa4, last]
    }

    fn three() -> Vec<Bss> {
        vec![
            bss(0xa1, 2437, -4000, ies(NAME, &WPA2)), // X
            bss(0xa2, 5180, -7000, ies(NAME, &WPA2)), // Y
            bss(0xa3, 5745, -6000, ies(NAME, &WPA2)), // Z
        ]
    }

    fn bssids(survey: &Survey) -> Vec<MacAddr> {
        survey.candidates.iter().map(|c| c.bssid).collect()
    }

    #[test]
    fn bands_by_frequency() {
        assert_eq!((band(2412), band(2484)), (Band::Ghz2, Band::Ghz2));
        assert_eq!((band(5180), band(5825)), (Band::Ghz5, Band::Ghz5));
        assert_eq!(
            (band(5955), band(0), band(900)),
            (Band::Other, Band::Other, Band::Other)
        );
        assert!(Band::Ghz5 < Band::Ghz2 && Band::Ghz2 < Band::Other);
    }

    #[test]
    fn five_ghz_first_then_the_stronger_signal() {
        let survey = survey(&three(), NAME, &[]);
        assert_eq!(bssids(&survey), [addr(0xa3), addr(0xa2), addr(0xa1)]);
        assert_eq!(survey.seen, 3);
        assert!(survey.skipped.is_empty());
        // The element is kept whole; these networks advertise no RSNXE.
        assert_eq!(survey.candidates[0].rsne, WPA2.to_vec());
        assert_eq!(survey.candidates[0].rsnxe, None);
    }

    #[test]
    fn a_bss_that_failed_goes_last() {
        let survey = survey(&three(), NAME, &[addr(0xa3)]);
        assert_eq!(bssids(&survey), [addr(0xa2), addr(0xa1), addr(0xa3)]);
    }

    #[test]
    fn equal_candidates_are_ordered_by_address() {
        let results = vec![
            bss(0xa9, 5180, -6000, ies(NAME, &WPA2)),
            bss(0xa4, 5180, -6000, ies(NAME, &WPA2)),
        ];
        let survey = survey(&results, NAME, &[]);
        assert_eq!(bssids(&survey), [addr(0xa4), addr(0xa9)]);
    }

    #[test]
    fn only_the_configured_name_counts() {
        let results = vec![
            bss(0xa1, 5180, -6000, ies(b"example-network2", &WPA2)),
            bss(0xa2, 5180, -6000, ies(b"Example-Network", &WPA2)),
            bss(0xa3, 5180, -6000, ies(b"", &WPA2)),
            bss(0xa4, 5180, -6000, WPA2.to_vec()),
        ];
        let survey = survey(&results, NAME, &[]);
        assert!(survey.candidates.is_empty() && survey.skipped.is_empty());
        assert_eq!(survey.seen, 4);
    }

    // Review Focus 3.
    #[test]
    fn networks_out_of_scope_are_skipped_with_the_reason() {
        let mixed = hex!("30180100000fac020200000fac04000fac020100000fac020000");
        let pmf_required = hex!("30140100000fac040100000fac040100000fac02c000");
        let wpa3_only = hex!("30140100000fac040100000fac040100000fac080000");
        let cut_short = hex!("3003010000"); // the length byte says 3
        let results = vec![
            bss(0xa1, 2437, -4000, ies(NAME, &mixed)),
            bss(0xa2, 5180, -5000, ies(NAME, &pmf_required)),
            bss(0xa3, 5745, -6000, ies(NAME, &wpa3_only)),
            bss(0xa4, 2412, -7000, ies(NAME, &[])), // an open network
            bss(0xa5, 5200, -8000, ies(NAME, &cut_short)),
        ];
        let survey = survey(&results, NAME, &[]);
        assert!(survey.candidates.is_empty());
        assert_eq!(survey.seen, 5);
        assert_eq!(
            survey.skipped,
            [
                (addr(0xa1), 2437, Skip::Rsne(RsneError::GroupCipherNotCcmp)),
                (addr(0xa2), 5180, Skip::Rsne(RsneError::PmfRequired)),
                (addr(0xa3), 5745, Skip::Rsne(RsneError::NoPskAkm)),
                (addr(0xa4), 2412, Skip::NoRsne),
                (addr(0xa5), 5200, Skip::Rsne(RsneError::Truncated)),
            ]
        );
        assert_eq!(
            survey.skipped[0].2.to_string(),
            "group cipher is not CCMP (mixed WPA/WPA2 network)"
        );
        assert_eq!(
            survey.skipped[3].2.to_string(),
            "no RSN element (not a WPA2 network)"
        );
    }

    #[test]
    fn a_transition_network_is_a_candidate_and_keeps_its_rsnxe() {
        let rsne = hex!("301e0100000fac040100000fac040200000fac02000fac0880000000000fac06");
        let rsnxe = hex!("f40120");
        let results = vec![bss(
            0xa1,
            5180,
            -6000,
            ies(NAME, &[&rsne[..], &rsnxe].concat()),
        )];
        let survey = survey(&results, NAME, &[]);
        assert!(survey.skipped.is_empty());
        assert_eq!(
            survey.candidates,
            [Candidate {
                bssid: addr(0xa1),
                freq_mhz: 5180,
                signal_mbm: -6000,
                rsne: rsne.to_vec(),
                rsnxe: Some(rsnxe.to_vec()),
            }]
        );
    }
}
