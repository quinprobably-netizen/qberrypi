//! The RSN element (IEEE Std 802.11-2016 9.4.2.25): the element in which an
//! access point advertises its ciphers and key management, and in which a
//! station names the ones it picked.
//!
//! This module decides which networks qberrypi joins at all: WPA2-PSK with
//! CCMP as pairwise and as group cipher, without protected management frames.
//! The bytes come from beacons, which any radio in range can send. `parse`
//! does not panic on any input, and no error repeats a byte of what it refused.

use std::fmt;

/// A cipher suite or AKM suite selector: an OUI and a suite type.
pub type Suite = [u8; 4];

/// The cipher suite CCMP-128 (AES), the one cipher of WPA2 that qberrypi uses.
pub const CIPHER_CCMP: Suite = [0x00, 0x0f, 0xac, 0x04];

/// The cipher suite TKIP, the cipher of WPA; as group cipher it marks a mixed WPA/WPA2 network.
pub const CIPHER_TKIP: Suite = [0x00, 0x0f, 0xac, 0x02];

/// The AKM suite PSK: a pre-shared key and the HMAC-SHA1 key derivation, which is WPA2-PSK.
pub const AKM_PSK: Suite = [0x00, 0x0f, 0xac, 0x02];

/// The capability bit MFPR: management frame protection required.
pub const CAP_MFPR: u16 = 0x0040;

/// The capability bit MFPC: management frame protection capable.
pub const CAP_MFPC: u16 = 0x0080;

/// The element qberrypi puts in its association request: CCMP, CCMP, PSK, no capabilities.
pub const SUPPLICANT_RSNE: [u8; 22] = [
    0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
    0x00, 0x0f, 0xac, 0x02, 0x00, 0x00,
];

/// The element id of the RSN element.
const ID_RSNE: u8 = 0x30;

/// The one version of the RSN element the standard defines.
const VERSION: u16 = 1;

/// The length in bytes of a suite selector.
const SUITE_LEN: usize = 4;

/// The AKM suite 802.1X (enterprise Wi-Fi), the standard's default where an element names no AKM.
const AKM_8021X: Suite = [0x00, 0x0f, 0xac, 0x01];

/// The fields of an RSN element that decide whether qberrypi can use a network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rsne {
    /// The group data cipher suite, which protects broadcast and multicast frames.
    pub group: Suite,
    /// The pairwise cipher suites, in the order of the element.
    pub pairwise: Vec<Suite>,
    /// The authentication and key management (AKM) suites, in the order of the element.
    pub akms: Vec<Suite>,
    /// The RSN capabilities field.
    pub capabilities: u16,
}

impl Rsne {
    /// Reads a whole RSN element, its two header bytes included; a field the element ends before takes its default.
    pub fn parse(element: &[u8]) -> Result<Self, RsneError> {
        let &[id, len, ref body @ ..] = element else {
            return Err(RsneError::Truncated);
        };
        if id != ID_RSNE {
            return Err(RsneError::NotRsne);
        }
        if body.len() != usize::from(len) {
            return Err(RsneError::Length);
        }
        let (version, rest) = take_u16(body).ok_or(RsneError::Truncated)?;
        if version != VERSION {
            return Err(RsneError::Version);
        }
        // From here on the element may end before any field, but not inside one.
        let (group, rest) = if rest.is_empty() {
            (CIPHER_CCMP, rest)
        } else {
            let (suite, rest) = rest
                .split_first_chunk::<SUITE_LEN>()
                .ok_or(RsneError::Truncated)?;
            (*suite, rest)
        };
        let (pairwise, rest) = suite_list(rest, CIPHER_CCMP)?;
        let (akms, rest) = suite_list(rest, AKM_8021X)?;
        // What follows the capabilities (the PMKIDs, the group management cipher) is not read.
        let capabilities = match take_u16(rest) {
            Some((capabilities, _ignored)) => capabilities,
            None if rest.is_empty() => 0,
            None => return Err(RsneError::Truncated),
        };
        Ok(Self {
            group,
            pairwise,
            akms,
            capabilities,
        })
    }

    /// Whether qberrypi can join a network that advertises this element; the error names the first reason it cannot.
    pub fn check_access_point(&self) -> Result<(), RsneError> {
        if self.group != CIPHER_CCMP {
            return Err(RsneError::GroupCipherNotCcmp);
        }
        if !self.pairwise.contains(&CIPHER_CCMP) {
            return Err(RsneError::NoCcmpPairwise);
        }
        if !self.akms.contains(&AKM_PSK) {
            return Err(RsneError::NoPskAkm);
        }
        // "Capable" alone is no obstacle: such a network (WPA2/WPA3 transition mode among them) also serves
        // stations that do not protect management frames, and qberrypi's own element says it is one.
        if self.capabilities & CAP_MFPR != 0 {
            return Err(RsneError::PmfRequired);
        }
        Ok(())
    }

    /// Whether this is an element qberrypi may send: CCMP, CCMP alone, PSK alone, no protected management frames.
    pub fn check_supplicant(&self) -> Result<(), RsneError> {
        // A station's element names the one pairwise cipher and the one AKM it picked, so each list is
        // compared whole. The capability bits other than the two below are not checked: a few of them
        // (Extended Key ID, OCVC) do change the handshake, and this crate does nothing for them, so an element
        // that sets one is accepted here and what it asks for is left unanswered.
        if self.group == CIPHER_CCMP
            && self.pairwise == [CIPHER_CCMP]
            && self.akms == [AKM_PSK]
            && self.capabilities & (CAP_MFPR | CAP_MFPC) == 0
        {
            Ok(())
        } else {
            Err(RsneError::NotWpa2PskCcmp)
        }
    }
}

/// Whether message 3 repeats the RSN extension element the access point advertised: both absent, or equal bytes.
pub fn rsnxe_matches(advertised: Option<&[u8]>, in_message_3: Option<&[u8]>) -> bool {
    // Both elements are public (one is in every beacon), so the comparison need not be constant-time.
    advertised == in_message_3
}

/// Splits a little-endian `u16` off the front of `bytes`.
fn take_u16(bytes: &[u8]) -> Option<(u16, &[u8])> {
    let (value, rest) = bytes.split_first_chunk::<2>()?;
    Some((u16::from_le_bytes(*value), rest))
}

/// Reads a suite count and that many suites off the front of `bytes`; an element that has ended yields `[default]`.
fn suite_list(bytes: &[u8], default: Suite) -> Result<(Vec<Suite>, &[u8]), RsneError> {
    if bytes.is_empty() {
        return Ok((vec![default], bytes));
    }
    let (count, rest) = take_u16(bytes).ok_or(RsneError::Truncated)?;
    if count == 0 {
        return Err(RsneError::EmptySuiteList);
    }
    // The count is the sender's claim, up to 65 535. Nothing is allocated for it until the bytes it promises
    // are known to be there, and an element holds at most 255. The product is at most 262 140: no overflow.
    let (list, rest) = rest
        .split_at_checked(SUITE_LEN * usize::from(count))
        .ok_or(RsneError::Truncated)?;
    // `list` is a whole number of suites long, so the remainder that `as_chunks` returns is empty.
    let (suites, _remainder) = list.as_chunks::<SUITE_LEN>();
    Ok((suites.to_vec(), rest))
}

/// Why an RSN element was refused; it names the rule broken and carries no byte of the element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsneError {
    /// The element ends inside a field, or before its version.
    Truncated,
    /// The element id is not that of the RSN element.
    NotRsne,
    /// The length byte of the element disagrees with the number of bytes given.
    Length,
    /// The version of the element is not 1.
    Version,
    /// A pairwise cipher or AKM suite list declares no suites.
    EmptySuiteList,
    /// The group cipher is not CCMP, as on a mixed WPA/WPA2 network, whose group cipher is TKIP.
    GroupCipherNotCcmp,
    /// The pairwise cipher list does not offer CCMP.
    NoCcmpPairwise,
    /// The AKM list does not offer PSK.
    NoPskAkm,
    /// The network requires protected management frames.
    PmfRequired,
    /// The station's own element is not exactly WPA2-PSK with CCMP and without protected management frames.
    NotWpa2PskCcmp,
}

impl fmt::Display for RsneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "RSN element ends inside a field",
            Self::NotRsne => "element is not an RSN element",
            Self::Length => "RSN element is not as long as its length byte says",
            Self::Version => "RSN element version is not 1",
            Self::EmptySuiteList => "RSN element has a suite list with no suites",
            Self::GroupCipherNotCcmp => "group cipher is not CCMP (mixed WPA/WPA2 network)",
            Self::NoCcmpPairwise => "CCMP is not offered as pairwise cipher",
            Self::NoPskAkm => "WPA2-PSK is not offered",
            Self::PmfRequired => "protected management frames are required",
            Self::NotWpa2PskCcmp => {
                "own RSN element is not WPA2-PSK with CCMP and without protected management frames"
            }
        })
    }
}

impl std::error::Error for RsneError {}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    /// The suite selector of SAE, the AKM of WPA3-Personal.
    const AKM_SAE: Suite = [0x00, 0x0f, 0xac, 0x08];

    // Decision 10: the element is a constant, and this is its test.
    #[test]
    fn supplicant_rsne_is_wpa2_psk_ccmp_without_pmf() {
        let own = Rsne::parse(&SUPPLICANT_RSNE).unwrap();
        assert_eq!(
            own,
            Rsne {
                group: CIPHER_CCMP,
                pairwise: vec![CIPHER_CCMP],
                akms: vec![AKM_PSK],
                capabilities: 0
            }
        );
        assert_eq!(
            (own.check_supplicant(), own.check_access_point()),
            (Ok(()), Ok(()))
        );
    }

    #[test]
    fn parses_elements_real_networks_advertise() {
        // A mixed WPA/WPA2 network: TKIP group cipher, CCMP and TKIP pairwise, PSK. Review Focus 4.
        let mixed = Rsne::parse(&hex!(
            "30180100000fac020200000fac04000fac020100000fac020000"
        ))
        .unwrap();
        assert_eq!(
            mixed,
            Rsne {
                group: CIPHER_TKIP,
                pairwise: vec![CIPHER_CCMP, CIPHER_TKIP],
                akms: vec![AKM_PSK],
                capabilities: 0
            }
        );
        assert_eq!(
            mixed.check_access_point(),
            Err(RsneError::GroupCipherNotCcmp)
        );
        // A station's element with the replay-counter capability bits set (capabilities 0x0028).
        let station = Rsne::parse(&hex!("30140100000fac040100000fac040100000fac022800")).unwrap();
        assert_eq!(
            (station.capabilities, station.check_supplicant()),
            (0x0028, Ok(()))
        );
    }

    #[test]
    fn transition_mode_access_point_is_usable() {
        // CCMP, CCMP, PSK + SAE, MFPC, no PMKIDs, a group management cipher.
        let ap = Rsne::parse(&hex!(
            "301e0100000fac040100000fac040200000fac02000fac0880000000000fac06"
        ))
        .unwrap();
        assert_eq!(
            (ap.akms.len(), ap.capabilities, ap.check_access_point()),
            (2, CAP_MFPC, Ok(()))
        );
        assert_eq!(ap.check_supplicant(), Err(RsneError::NotWpa2PskCcmp));
    }

    // Review Focus 4.
    #[test]
    fn networks_outside_scope_are_named() {
        for (element, error) in [
            (
                hex!("30140100000fac040100000fac040100000fac02c000"),
                RsneError::PmfRequired,
            ),
            (
                hex!("30140100000fac040100000fac040100000fac080000"),
                RsneError::NoPskAkm,
            ),
            (
                hex!("30140100000fac040100000fac020100000fac020000"),
                RsneError::NoCcmpPairwise,
            ),
        ] {
            assert_eq!(
                Rsne::parse(&element).unwrap().check_access_point(),
                Err(error)
            );
        }
        assert_eq!(
            RsneError::GroupCipherNotCcmp.to_string(),
            "group cipher is not CCMP (mixed WPA/WPA2 network)"
        );
        assert_eq!(
            RsneError::NoCcmpPairwise.to_string(),
            "CCMP is not offered as pairwise cipher"
        );
        assert_eq!(RsneError::NoPskAkm.to_string(), "WPA2-PSK is not offered");
        assert_eq!(
            RsneError::PmfRequired.to_string(),
            "protected management frames are required"
        );
    }

    #[test]
    fn absent_fields_take_the_standard_defaults() {
        let short = Rsne::parse(&hex!("30020100")).unwrap();
        assert_eq!(
            short,
            Rsne {
                group: CIPHER_CCMP,
                pairwise: vec![CIPHER_CCMP],
                akms: vec![[0x00, 0x0f, 0xac, 0x01]],
                capabilities: 0
            }
        );
        assert_eq!(short.check_access_point(), Err(RsneError::NoPskAkm));
        assert_eq!(
            Rsne::parse(&hex!("30060100000fac02")).unwrap().group,
            CIPHER_TKIP
        );
        // The element may also end after the pairwise list, and after the AKM list.
        let no_akms = Rsne::parse(&hex!("300c0100000fac040100000fac02")).unwrap();
        assert_eq!(
            (no_akms.pairwise, no_akms.akms),
            (vec![CIPHER_TKIP], vec![[0x00, 0x0f, 0xac, 0x01]])
        );
        let no_capabilities =
            Rsne::parse(&hex!("30120100000fac040100000fac040100000fac02")).unwrap();
        assert_eq!(
            (no_capabilities.akms, no_capabilities.capabilities),
            (vec![AKM_PSK], 0)
        );
    }

    #[test]
    fn malformed_elements_are_typed_errors() {
        let refused = |input: &[u8]| Rsne::parse(input).unwrap_err();
        let own = SUPPLICANT_RSNE;

        for input in [&[][..], &hex!("30"), &hex!("300101")] {
            assert_eq!(refused(input), RsneError::Truncated);
        }

        assert_eq!(
            refused(&[&hex!("dd14")[..], &own[2..]].concat()),
            RsneError::NotRsne
        );

        assert_eq!(refused(&own[..21]), RsneError::Length);
        assert_eq!(refused(&[&own[..], &[0x00]].concat()), RsneError::Length);

        assert_eq!(
            refused(&[&hex!("30140200")[..], &own[4..]].concat()),
            RsneError::Version
        );

        for input in [
            &hex!("30040100000f")[..],                     // inside the group suite
            &hex!("30070100000fac0401"),                   // inside the pairwise count
            &hex!("300a0100000fac040100000f"),             // inside the one pairwise suite
            &hex!("30080100000fac04ffff"),                 // 65 535 pairwise suites, none there
            &hex!("300d0100000fac040100000fac0401"),       // inside the AKM count
            &hex!("30100100000fac040100000fac040100000f"), // inside the one AKM suite
            &hex!("300e0100000fac040100000fac04ffff"),     // 65 535 AKM suites, none there
            &hex!("30130100000fac040100000fac040100000fac0200"), // inside the capabilities
        ] {
            assert_eq!(refused(input), RsneError::Truncated);
        }

        assert_eq!(
            refused(&hex!("30080100000fac040000")),
            RsneError::EmptySuiteList
        );
        assert_eq!(
            refused(&hex!("300e0100000fac040100000fac040000")),
            RsneError::EmptySuiteList
        );
    }

    #[test]
    fn own_element_must_be_exactly_wpa2_psk_ccmp() {
        let own = SUPPLICANT_RSNE;
        let with = |index: usize, byte: u8| {
            let mut element = own;
            element[index] = byte;
            element.to_vec()
        };
        for element in [
            with(20, 0x80), // capabilities 0x0080: management frame protection capable
            with(20, 0x40), // capabilities 0x0040: management frame protection required
            // a second pairwise suite, TKIP after CCMP
            hex!("30180100000fac040200000fac04000fac020100000fac020000").to_vec(),
            with(7, 0x02),  // group TKIP
            with(19, 0x08), // AKM SAE
            // a second AKM, SAE after PSK
            hex!("30180100000fac040100000fac040200000fac02000fac080000").to_vec(),
        ] {
            let parsed = Rsne::parse(&element).unwrap();
            assert_eq!(parsed.check_supplicant(), Err(RsneError::NotWpa2PskCcmp));
        }
        // The edits above hit the fields they name.
        assert_eq!(Rsne::parse(&with(7, 0x02)).unwrap().group, CIPHER_TKIP);
        assert_eq!(Rsne::parse(&with(19, 0x08)).unwrap().akms, [AKM_SAE]);
        assert_eq!(Rsne::parse(&with(20, 0x80)).unwrap().capabilities, CAP_MFPC);
        assert_eq!(Rsne::parse(&with(20, 0x40)).unwrap().capabilities, CAP_MFPR);
    }

    #[test]
    fn rsnxe_comparison() {
        let x = hex!("f40120");
        assert!(rsnxe_matches(None, None) && rsnxe_matches(Some(&x), Some(&x)));
        assert!(!rsnxe_matches(Some(&x), None) && !rsnxe_matches(None, Some(&x)));
        assert!(!rsnxe_matches(Some(&x), Some(&hex!("f40100"))));
    }
}
