//! The API's TLS certificate: the key and certificate in `tls.pem` as a `rustls` server
//! configuration, and the pin that qnet is told to trust.
//!
//! The file is `qberrypi-tls.pem` on the PC, made once by `cargo xtask make-cert`, and `tls.pem`
//! on the card. It holds the PKCS#8 private key and then the certificate. The key is a secret:
//! no error here quotes the file or names a byte of the key.

use std::fmt::Write as _;
use std::sync::Arc;

use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::pem::{self, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::SigningKey;
use rustls::version;
use rustls::{Error, InconsistentKeys, ServerConfig};
use sha2::{Digest, Sha256};
use webpki::EndEntityCert;

use crate::https::provider;

/// What a file with no certificate in it is told.
const NO_CERTIFICATE: &str = "tls.pem holds no certificate";

/// What a file with no private key in it is told.
const NO_KEY: &str = "tls.pem holds no private key";

/// What a key that signs for another certificate is told.
const KEY_MISMATCH: &str = "tls.pem's key does not fit its first certificate";

/// What a file whose first certificate is not one is told.
const NOT_A_CERTIFICATE: &str = "tls.pem's first certificate is not a valid certificate";

/// What a file with a broken PEM section is told. The parser's own texts quote the line at fault,
/// which could be a line of the key.
const NOT_PEM: &str = "tls.pem is not valid PEM";

/// What the key signs in the check that it fits its certificate. It is no handshake's, so that a
/// signature made here is of no use anywhere else.
const FIT_MESSAGE: &[u8] = b"qberrypi: does this key belong to this certificate";

/// A TLS 1.3 and 1.2 server configuration from the key and the certificates in `pem`, in the
/// file's order, or the reason the file cannot serve. It asks no client for a certificate, and
/// it picks the cipher suite by the provider's order ([`crate::https::provider`]: ChaCha20 first)
/// and not by the client's.
///
/// The key must fit the first certificate. The provider's keys cannot say what their public key
/// is, so rustls's own comparison finds nothing to compare and lets a wrong key through; the check
/// here has the key sign a fixed message and the first certificate verify it. That is one
/// signature and one verification, so a caller on the runtime thread hands this to
/// [`crate::services::blocking`].
///
/// The errors are `"tls.pem holds no certificate"`, `"tls.pem holds no private key"`,
/// `"tls.pem's key does not fit its first certificate"`, `"tls.pem is not valid PEM"` and
/// `"tls.pem: {rustls error}"`. None quotes the file.
pub fn server_config(pem: &[u8]) -> Result<Arc<ServerConfig>, String> {
    let certs = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| NOT_PEM.to_owned())?;
    let Some(leaf) = certs.first() else {
        return Err(NO_CERTIFICATE.to_owned());
    };
    let key = match PrivateKeyDer::from_pem_slice(pem) {
        Ok(key) => key,
        Err(pem::Error::NoItemsFound) => return Err(NO_KEY.to_owned()),
        Err(_) => return Err(NOT_PEM.to_owned()),
    };

    let provider = Arc::new(provider());
    let signing_key = provider
        .key_provider
        .load_private_key(key.clone_key())
        .map_err(rustls_error)?;
    key_fits(
        signing_key.as_ref(),
        leaf,
        &provider.signature_verification_algorithms,
    )?;

    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&version::TLS13, &version::TLS12])
        .map_err(rustls_error)?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|error| match error {
            Error::InconsistentKeys(InconsistentKeys::KeyMismatch) => KEY_MISMATCH.to_owned(),
            other => rustls_error(other),
        })?;
    // The provider's order, ChaCha20 first, and not the client's: the board has no AES
    // instructions, and qnet's `ring` client lists AES-GCM first.
    config.ignore_client_order = true;
    Ok(Arc::new(config))
}

/// A rustls error as the text this module gives for one.
fn rustls_error(error: Error) -> String {
    format!("tls.pem: {error}")
}

/// Whether `leaf`'s public key verifies what `key` signs, which is what it means for them to fit.
fn key_fits(
    key: &dyn SigningKey,
    leaf: &CertificateDer<'_>,
    algorithms: &WebPkiSupportedAlgorithms,
) -> Result<(), String> {
    let signer = key
        .choose_scheme(&algorithms.supported_schemes())
        .ok_or("tls.pem's key signs with no scheme that this build verifies")?;
    let signature = signer.sign(FIT_MESSAGE).map_err(rustls_error)?;
    let cert = EndEntityCert::try_from(leaf).map_err(|_| NOT_A_CERTIFICATE)?;
    // As rustls verifies a TLS 1.2 signature: a scheme can name several algorithms, and the one
    // that suits the certificate's key is the one that verifies.
    let candidates = algorithms
        .mapping
        .iter()
        .find(|(scheme, _)| *scheme == signer.scheme())
        .map_or(&[][..], |(_, candidates)| *candidates);
    if candidates.iter().any(|algorithm| {
        cert.verify_signature(*algorithm, FIT_MESSAGE, &signature)
            .is_ok()
    }) {
        Ok(())
    } else {
        Err(KEY_MISMATCH.to_owned())
    }
}

/// The SHA-256 of the DER of the first certificate in `pem`; `None` if there is none.
pub fn leaf_sha256(pem: &[u8]) -> Option<[u8; 32]> {
    let leaf = CertificateDer::pem_slice_iter(pem).next()?.ok()?;
    Some(Sha256::digest(&leaf).into())
}

/// A digest as upper-case hex pairs joined by colons, `AB:CD:…`, 95 characters: the form that qnet
/// writes and accepts for a pin.
pub fn pin_text(digest: &[u8; 32]) -> String {
    let mut text = String::with_capacity(3 * digest.len() - 1);
    for (at, byte) in digest.iter().enumerate() {
        if at > 0 {
            text.push(':');
        }
        // Writing to a `String` cannot fail.
        let _ = write!(text, "{byte:02X}");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{Read, Write};

    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384};
    use rustls::pki_types::ServerName;
    use rustls::{ClientConnection, RootCertStore, ServerConnection, version};
    use sha2::{Digest, Sha256};

    /// A certificate for `example.com` and its PKCS#8 key, both as PEM, made for this test alone.
    fn pair() -> (String, String) {
        made(&PKCS_ECDSA_P256_SHA256)
    }

    fn made(algorithm: &'static rcgen::SignatureAlgorithm) -> (String, String) {
        let key = KeyPair::generate_for(algorithm).unwrap();
        let cert = CertificateParams::new(vec!["example.com".to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        (cert.pem(), key.serialize_pem())
    }

    /// The base64 lines of a PEM text, which is all of it that holds key material.
    fn body(pem: &str) -> String {
        pem.lines()
            .filter(|line| !line.starts_with("-----"))
            .collect()
    }

    #[test]
    fn a_key_and_its_certificate_load_and_give_their_pin() {
        let (cert, key) = pair();
        let pem = format!("{key}{cert}");
        assert!(server_config(pem.as_bytes()).is_ok());
        let digest = leaf_sha256(pem.as_bytes()).unwrap();
        let text = pin_text(&digest);
        assert_eq!((text.len(), text.matches(':').count()), (95, 31));
        assert_eq!(text, text.to_uppercase());
    }

    #[test]
    fn a_file_that_cannot_serve_says_why_without_quoting_itself() {
        let (cert, key) = pair();
        let (other_cert, _) = pair();
        for (pem, why) in [
            (cert.clone(), "no private key"),
            (key.clone(), "no certificate"),
            (format!("{key}{other_cert}"), "does not fit"),
            ("garbage".to_owned(), "no certificate"),
        ] {
            let error = server_config(pem.as_bytes()).unwrap_err();
            assert!(
                error.contains(why) && !error.contains("BEGIN") && !error.contains("PRIVATE"),
                "{error}"
            );
        }
    }

    #[test]
    fn the_pin_is_the_sha256_of_the_first_certificates_der() {
        let (cert, key) = pair();
        let (second, _) = pair();
        let first_der = rustls::pki_types::CertificateDer::from_pem_slice(cert.as_bytes()).unwrap();
        let expected = Sha256::digest(&first_der);
        // Whatever order the key and the certificates come in, the pin is the first certificate's.
        for pem in [
            format!("{key}{cert}{second}"),
            format!("{cert}{second}{key}"),
            format!("{cert}{key}{second}"),
        ] {
            assert!(server_config(pem.as_bytes()).is_ok());
            assert_eq!(
                leaf_sha256(pem.as_bytes()).unwrap().as_slice(),
                &expected[..]
            );
        }
        assert_eq!(leaf_sha256(key.as_bytes()), None);
        assert_eq!(leaf_sha256(b""), None);
    }

    #[test]
    fn the_pin_is_written_in_upper_case_pairs_with_colons() {
        let mut digest = [0u8; 32];
        digest[0] = 0xab;
        digest[1] = 0x01;
        digest[31] = 0xff;
        let text = pin_text(&digest);
        assert!(text.starts_with("AB:01:00:"), "{text}");
        assert!(text.ends_with(":00:FF"), "{text}");
    }

    #[test]
    fn a_key_of_another_curve_does_not_fit_either() {
        let (cert, _) = pair();
        let (_, key) = made(&PKCS_ECDSA_P384_SHA384);
        let error = server_config(format!("{key}{cert}").as_bytes()).unwrap_err();
        assert!(error.contains("does not fit"), "{error}");
    }

    #[test]
    fn a_damaged_file_never_has_its_bytes_in_the_error() {
        let (cert, key) = pair();
        let canary = "Q0FOQVJZLWtleS1ieXRlcy00MQ"; // base64 of text the file must never show
        let sections = |kind: &str, text: &str| {
            format!("-----BEGIN {kind}-----\n{text}\n-----END {kind}-----\n")
        };
        for pem in [
            // A key section that is base64 but not a key.
            format!("{cert}{}", sections("PRIVATE KEY", canary)),
            // A key section that is not base64.
            format!("{cert}{}", sections("PRIVATE KEY", "!!canary!!")),
            // A certificate section that is not a certificate, with the real key.
            format!("{key}{}", sections("CERTIFICATE", canary)),
            // A section that never ends.
            format!("{cert}-----BEGIN PRIVATE KEY-----\n{canary}\n"),
            // A start line that is not one.
            format!("{cert}-----BEGIN PRIVATE KEY canary\n{canary}\n"),
            // The right key, cut short.
            format!("{cert}{}", &key[..key.len() / 2]),
            // The key's own text, with a byte of it changed.
            format!("{cert}{}", key.replacen('A', "B", 3)),
        ] {
            let error = server_config(pem.as_bytes()).unwrap_err();
            assert!(
                !error.contains("canary") && !error.contains(canary),
                "{error}"
            );
            assert!(
                !error.contains("BEGIN") && !error.contains("PRIVATE"),
                "{error}"
            );
            for line in body(&key).as_bytes().chunks(20) {
                let line = std::str::from_utf8(line).unwrap();
                assert!(!error.contains(line), "{error}");
            }
        }
    }

    /// Runs a TLS handshake in memory between a client that trusts `cert_pem` alone and a server
    /// made from `config`, offering only `versions`; says which version was negotiated.
    fn handshake(
        config: Arc<ServerConfig>,
        cert_pem: &str,
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> rustls::ProtocolVersion {
        handshake_with(config, cert_pem, crate::https::provider(), versions).0
    }

    /// `handshake` with the client's provider given, which says which cipher suite the server chose
    /// as well.
    fn handshake_with(
        config: Arc<ServerConfig>,
        cert_pem: &str,
        client_provider: rustls::crypto::CryptoProvider,
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> (rustls::ProtocolVersion, rustls::CipherSuite) {
        let mut roots = RootCertStore::empty();
        let der = rustls::pki_types::CertificateDer::from_pem_slice(cert_pem.as_bytes()).unwrap();
        roots.add(der).unwrap();
        let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(client_provider))
            .with_protocol_versions(versions)
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = ServerName::try_from("example.com").unwrap();
        let mut client = ClientConnection::new(Arc::new(client_config), name).unwrap();
        let mut server = ServerConnection::new(config).unwrap();
        for _ in 0..20 {
            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
            let mut wire = Vec::new();
            client.write_tls(&mut wire).unwrap();
            server.read_tls(&mut wire.as_slice()).unwrap();
            server.process_new_packets().unwrap();
            let mut wire = Vec::new();
            server.write_tls(&mut wire).unwrap();
            client.read_tls(&mut wire.as_slice()).unwrap();
            client.process_new_packets().unwrap();
        }
        assert!(!client.is_handshaking() && !server.is_handshaking());
        // Data goes both ways once it is done.
        client.writer().write_all(b"ping").unwrap();
        let mut wire = Vec::new();
        client.write_tls(&mut wire).unwrap();
        server.read_tls(&mut wire.as_slice()).unwrap();
        server.process_new_packets().unwrap();
        let mut got = [0u8; 4];
        server.reader().read_exact(&mut got).unwrap();
        assert_eq!(&got, b"ping");
        (
            server.protocol_version().unwrap(),
            server.negotiated_cipher_suite().unwrap().suite(),
        )
    }

    #[test]
    fn the_configuration_serves_tls_1_3_and_tls_1_2_to_a_client_with_no_certificate() {
        let (cert, key) = pair();
        let config = server_config(format!("{key}{cert}").as_bytes()).unwrap();
        assert_eq!(
            handshake(config.clone(), &cert, &[&version::TLS13]),
            rustls::ProtocolVersion::TLSv1_3
        );
        assert_eq!(
            handshake(config, &cert, &[&version::TLS12]),
            rustls::ProtocolVersion::TLSv1_2
        );
    }

    // Ruling S9.
    #[test]
    fn the_servers_order_of_cipher_suites_wins_so_that_chacha_comes_before_aes() {
        let (cert, key) = pair();
        let config = server_config(format!("{key}{cert}").as_bytes()).unwrap();
        assert!(config.ignore_client_order);
        // A client that lists AES-GCM first, as qnet's does: the board has no AES instructions.
        let mut aes_first = crate::https::provider();
        aes_first.cipher_suites.reverse();
        assert!(!matches!(
            aes_first.cipher_suites[0].suite(),
            rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
                | rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        ));
        for (versions, chosen) in [
            (
                &[&version::TLS13][..],
                rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            ),
            (
                &[&version::TLS12][..],
                rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            ),
        ] {
            let (_, suite) = handshake_with(config.clone(), &cert, aes_first.clone(), versions);
            assert_eq!(suite, chosen);
        }
    }
}
