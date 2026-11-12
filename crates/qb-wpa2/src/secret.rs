//! The container every key in this crate lives in: wiped when dropped, never
//! printed, and compared without a timing side channel.

use std::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// `N` secret bytes, wiped on drop and redacted in `Debug`.
#[derive(Clone)]
pub struct SecretBytes<const N: usize>([u8; N]);

impl<const N: usize> SecretBytes<N> {
    /// Keeps `bytes` as a secret and wipes the argument; any other copy the caller holds is the caller's to wipe.
    pub fn new(mut bytes: [u8; N]) -> Self {
        let secret = Self(bytes);
        bytes.zeroize();
        secret
    }

    /// The secret bytes, for the cryptographic operation that needs them.
    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Constant-time: how long a comparison takes says nothing about where two secrets differ.
impl<const N: usize> PartialEq for SecretBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl<const N: usize> Eq for SecretBytes<N> {}

impl<const N: usize> Zeroize for SecretBytes<N> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<const N: usize> Drop for SecretBytes<N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const N: usize> ZeroizeOnDrop for SecretBytes<N> {}

#[cfg(test)]
mod tests {
    use super::*;

    fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}

    #[test]
    fn secret_is_wiped_and_redacted() {
        wiped_on_drop::<SecretBytes<32>>();
        let mut s = SecretBytes::new([0xab; 16]);
        assert_eq!(format!("{s:?}"), "<redacted>");
        assert_eq!(s.expose(), &[0xab; 16]);
        zeroize::Zeroize::zeroize(&mut s);
        assert_eq!(s.expose(), &[0; 16]);
    }

    #[test]
    fn secrets_compare_by_value() {
        assert_eq!(SecretBytes::new([1; 16]), SecretBytes::new([1; 16]).clone());
        assert_ne!(SecretBytes::new([1; 16]), SecretBytes::new([2; 16]));
    }
}
