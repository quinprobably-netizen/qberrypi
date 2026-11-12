//! The pairwise transient key (PTK): the session keys a station and an access
//! point each derive from the PMK, their two addresses and the two nonces of
//! the handshake, and the IEEE 802.11 pseudorandom function that expands them
//! (IEEE Std 802.11-2016 12.7.1.2 and 12.7.1.3).

use hmac::digest::FixedOutput;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use zeroize::Zeroizing;

use crate::pmk::Pmk;
use crate::secret::SecretBytes;
use crate::{MacAddr, Nonce};

/// The length in bytes of each of the three keys of a CCMP PTK.
const KEY_LEN: usize = 16;

/// The length in bytes of a CCMP PTK: KCK, KEK and TK.
const PTK_LEN: usize = 3 * KEY_LEN;

/// The label of the PTK derivation (IEEE Std 802.11-2016 12.7.1.3).
const PTK_LABEL: &str = "Pairwise key expansion";

/// The length in bytes of one HMAC-SHA1 output.
const BLOCK_LEN: usize = 20;

/// The number of the last block the PRF may produce. The loop of the standard computes one block more than the
/// output needs and numbers the blocks in a single byte, so the longest output it defines is 255 blocks.
const LAST_BLOCK: u8 = 254;

/// The longest output of the PRF in bytes: 5100.
const PRF_MAX_OUTPUT: usize = (LAST_BLOCK as usize + 1) * BLOCK_LEN;

/// HMAC-SHA1 keyed with `key`: the one place this crate keys a hash, shared by the PRF and the EAPOL-Key MIC.
pub(crate) fn hmac_sha1(key: &[u8]) -> Hmac<Sha1> {
    // Cannot fail: HMAC is defined for a key of any length, and `new_from_slice` of hmac 0.13 returns `Ok` for all.
    Hmac::<Sha1>::new_from_slice(key).expect("HMAC takes a key of any length")
}

/// The pseudorandom function of IEEE Std 802.11-2016 12.7.1.2: fills `out` with the first `N` bytes of
/// HMAC-SHA1(key, label ‖ 0x00 ‖ data ‖ i) for i = 0, 1, 2, …
///
/// `N` is at most 5100, the most the one-byte block number allows; a call that asks for more does not compile.
fn prf<const N: usize>(key: &[u8], label: &str, data: &[u8], out: &mut [u8; N]) {
    const {
        assert!(
            N <= PRF_MAX_OUTPUT,
            "the PRF numbers its blocks in one byte"
        )
    };
    let mut keyed = hmac_sha1(key);
    keyed.update(label.as_bytes());
    keyed.update(&[0]);
    keyed.update(data);
    let mut block = Zeroizing::new([0u8; BLOCK_LEN]);
    for (chunk, number) in out.chunks_mut(BLOCK_LEN).zip(0..=LAST_BLOCK) {
        let mut mac = keyed.clone();
        mac.update(&[number]);
        mac.finalize_into((&mut *block).into());
        for (to, from) in chunk.iter_mut().zip(block.iter()) {
            *to = *from;
        }
    }
}

/// The pairwise transient key of one handshake: KCK, KEK and TK, each wiped on drop and redacted in `Debug`.
#[derive(Clone, Debug)]
pub struct Ptk {
    kck: SecretBytes<KEY_LEN>,
    kek: SecretBytes<KEY_LEN>,
    tk: SecretBytes<KEY_LEN>,
}

impl Ptk {
    /// Derives the PTK from the PMK, the addresses of the access point and the station, and their two nonces.
    pub fn derive(pmk: &Pmk, aa: &MacAddr, spa: &MacAddr, anonce: &Nonce, snonce: &Nonce) -> Self {
        // Each pair goes in lower value first, compared as big-endian numbers: both sides build the same input.
        let data = [
            aa.min(spa).as_slice(),
            aa.max(spa),
            anonce.min(snonce),
            anonce.max(snonce),
        ]
        .concat();
        let mut ptk = Zeroizing::new([0u8; PTK_LEN]);
        prf(pmk.expose(), PTK_LABEL, &data, &mut ptk);
        let mut keys = Zeroizing::new([[0u8; KEY_LEN]; 3]);
        let (chunks, _) = ptk.as_chunks::<KEY_LEN>();
        for (key, chunk) in keys.iter_mut().zip(chunks) {
            *key = *chunk;
        }
        let [kck, kek, tk] = &*keys;
        Self {
            kck: SecretBytes::new(*kck),
            kek: SecretBytes::new(*kek),
            tk: SecretBytes::new(*tk),
        }
    }

    /// The key confirmation key, which signs the handshake frames (the MIC).
    pub fn kck(&self) -> &SecretBytes<KEY_LEN> {
        &self.kck
    }

    /// The key encryption key, which unwraps the key data of the handshake frames.
    pub fn kek(&self) -> &SecretBytes<KEY_LEN> {
        &self.kek
    }

    /// The temporal key, which encrypts the data frames once installed.
    pub fn tk(&self) -> &SecretBytes<KEY_LEN> {
        &self.tk
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference::{AA, ANONCE, PMK, SNONCE, SPA};
    use hex_literal::hex;

    /// The first `N` bytes of the PRF; `N` is the length of the vector the call is compared with.
    fn out<const N: usize>(key: &[u8], label: &str, data: &[u8]) -> [u8; N] {
        let mut out = [0u8; N];
        prf(key, label, data, &mut out);
        out
    }

    // IEEE Std 802.11-2016 Annex J.3.2, test cases 1 to 3, 512 bits each.
    #[test]
    fn annex_j3_prf_vectors() {
        assert_eq!(
            out(&[0x0b; 20], "prefix", b"Hi There"),
            hex!(
                "bcd4c650b30b9684951829e0d75f9d54b862175ed9f00606e17d8da35402ffee75df78c3d31e0f889f012120c0862beb67753e7439ae242edb8373698356cf5a"
            )
        );
        assert_eq!(
            out(b"Jefe", "prefix", b"what do ya want for nothing?"),
            hex!(
                "51f4de5b33f249adf81aeb713a3c20f4fe631446fabdfa58244759ae58ef9009a99abf4eac2ca5fa87e692c440eb40023e7babb206d61de7b92f41529092b8fc"
            )
        );
        assert_eq!(
            out(&[0xaa; 20], "prefix", &[0xdd; 50]),
            hex!(
                "e1ac546ec4cb636f9976487be5c86be17a0252ca5d8d8df12cfb0473525249ce9dd8d177ead710bc9b590547239107aef7b4abd43d87f0a68f1cbd9e2b6f7607"
            )
        );
    }

    // IEEE Std 802.11-2016 Annex J.6.5, test cases 1 to 4 (192, 256, 384 and 512 bits).
    #[test]
    fn annex_j6_prf_vectors() {
        assert_eq!(
            out(&[0x0b; 20], "prefix", b"Hi There"),
            hex!("bcd4c650b30b9684951829e0d75f9d54b862175ed9f00606")
        );
        assert_eq!(
            out(b"Jefe", "prefix-2", b"what do ya want for nothing?"),
            hex!("47c4908e30c947521ad20be9053450ecbea23d3aa604b77326d8b3825ff7475c")
        );
        assert_eq!(
            out(
                &[0xaa; 80],
                "prefix-3",
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            ),
            hex!(
                "0ab6c33ccf70d0d736f4b04c8a7373255511abc5073713163bd0b8c9eeb7e1956fa066820a73ddee3f6d3bd407e0682a"
            )
        );
        assert_eq!(
            out(&[0x0b; 20], "prefix-4", b"Hi There Again"),
            hex!(
                "248cfbc532ab38ffa483c8a2e40bf170eb542a2e0916d7bf6d97da2c4c5ca877736c53a65b03fa4b3745ce7613f6ad68e0e4a798b7cf691c96176fd634a59a49"
            )
        );
    }

    // The longest output the one-byte block counter allows: 255 blocks, the last one numbered 254.
    #[test]
    fn longest_output_numbers_its_last_block_254() {
        let longest: [u8; PRF_MAX_OUTPUT] = out(&[0x0b; 20], "prefix", b"Hi There");
        let first: [u8; 64] = out(&[0x0b; 20], "prefix", b"Hi There");
        assert_eq!(longest[..64], first);
        let mut last = Hmac::<Sha1>::new_from_slice(&[0x0b; 20]).unwrap();
        last.update(b"prefix\x00Hi There\xfe");
        assert_eq!(
            longest[PRF_MAX_OUTPUT - 20..],
            last.finalize().into_bytes()[..]
        );
    }

    // IEEE Std 802.11-2016 Annex J.7.1 (Table J-13, inputs) and J.7.2 (Table J-14, CCMP keys).
    // reference::{PMK, AA, SPA, ANONCE, SNONCE} are those inputs: PMK 0dc0…21af, AA a0a1a1a3a4a5, SPA b0b1b2b3b4b5,
    // ANonce e0e1…0405, SNonce c0c1…e4e5.
    #[test]
    fn annex_j7_key_hierarchy() {
        let ptk = Ptk::derive(&Pmk::from_bytes(PMK), &AA, &SPA, &ANONCE, &SNONCE);
        assert_eq!(
            ptk.kck().expose(),
            &hex!("379f9852d0199236b94e407ce4c00ec8")
        );
        assert_eq!(
            ptk.kek().expose(),
            &hex!("47c9edc01c2c6e5b4910caddfb3e51a7")
        );
        assert_eq!(ptk.tk().expose(), &hex!("b2360c79e9710fdd58bea93deaf06599"));
    }

    #[test]
    fn addresses_and_nonces_are_ordered_before_use() {
        let pmk = Pmk::from_bytes(PMK);
        let ptk = Ptk::derive(&pmk, &AA, &SPA, &ANONCE, &SNONCE);
        assert_eq!(
            Ptk::derive(&pmk, &SPA, &AA, &ANONCE, &SNONCE).tk(),
            ptk.tk()
        );
        assert_eq!(
            Ptk::derive(&pmk, &AA, &SPA, &SNONCE, &ANONCE).tk(),
            ptk.tk()
        );
        assert_ne!(Ptk::derive(&pmk, &AA, &AA, &ANONCE, &SNONCE).tk(), ptk.tk());
    }

    #[test]
    fn ptk_is_redacted() {
        let text = format!(
            "{:?}",
            Ptk::derive(&Pmk::from_bytes(PMK), &AA, &SPA, &ANONCE, &SNONCE)
        );
        assert!(
            text.contains("<redacted>")
                && !text.contains("55, 159")
                && !text.to_lowercase().contains("379f")
        );
    }
}
