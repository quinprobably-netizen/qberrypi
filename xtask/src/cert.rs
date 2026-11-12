//! `cargo xtask make-cert`: qberrypi's own TLS certificate for the Pi-hole API, made once on this
//! PC.
//!
//! The file is `qberrypi-tls.pem` beside `qberrypi.toml`: the PKCS#8 key, then the certificate. It
//! holds a secret, so it is git-ignored, written with mode 0600 and never copied into `out/`; the
//! only things this command prints are the file's name and its pin, the SHA-256 of the
//! certificate, which is public. A certificate made on the Pi could not stand: the card is never
//! written by a permanent system, so a key made at boot would be a different one at the next boot
//! and break qnet's pin each time.

use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use qberrypi::api::tls;
use qberrypi::config;
use rcgen::string::Ia5String;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256, SanType,
    SerialNumber,
};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::deploy::write_private_new;

/// The file that holds the key and the certificate, in the top of the repository.
pub const CERT_FILE: &str = "qberrypi-tls.pem";

/// The configuration that names the host and its address.
const CONFIG_FILE: &str = "qberrypi.toml";

/// What the file is written under before it gets its name; `.gitignore` covers it.
const PART_FILE: &str = "qberrypi-tls.pem.part";

/// How long before it was made the certificate is already valid, in seconds: room for a PC whose
/// clock runs a little behind the Pi's.
const BACKDATE_SECS: u64 = 3600;

/// 9999-12-31 23:59:59 UTC in seconds since 1970, which is the value that RFC 5280 gives for a
/// certificate with no expiry.
const NO_EXPIRY_UNIX: i64 = 253_402_300_799;

/// The key and then the certificate, as PEM, for a Pi named `hostname` at `address`.
///
/// The key is a new ECDSA P-256 one and the certificate is signed by it. The subject is the host
/// name, and the alternative names are the host name and the address. It is valid from an hour
/// before `now_unix` to the end of 9999, and has a random serial number.
pub fn make(hostname: &str, address: Ipv4Addr, now_unix: u64) -> Result<String> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .context("cannot make a key for the certificate")?;
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, hostname);
    params.subject_alt_names = vec![
        SanType::DnsName(
            Ia5String::try_from(hostname)
                .context("the host name is not text a certificate holds")?,
        ),
        SanType::IpAddress(IpAddr::V4(address)),
    ];
    params.not_before = at_unix(now_unix.saturating_sub(BACKDATE_SECS) as i64)?;
    params.not_after = at_unix(NO_EXPIRY_UNIX)?;
    params.serial_number = Some(SerialNumber::from_slice(&random_serial()?));
    let cert = params
        .self_signed(&key)
        .context("cannot sign the certificate")?;
    let key_pem = Zeroizing::new(key.serialize_pem());
    Ok(format!("{}{}", key_pem.as_str(), cert.pem()))
}

/// The moment `secs` seconds after 1970.
fn at_unix(secs: i64) -> Result<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp(secs).context("a time the certificate cannot hold")
}

/// A serial number from the kernel: 16 bytes, positive and with no leading zero byte, so that it
/// is the 16 bytes that are written.
fn random_serial() -> Result<[u8; 16]> {
    let mut serial = [0u8; 16];
    fs::File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(&mut serial))
        .context("reading 16 random bytes from /dev/urandom")?;
    serial[0] = serial[0] & 0x7f | 0x40;
    Ok(serial)
}

/// Makes `qberrypi-tls.pem` in `root` from the host name and the address in its `qberrypi.toml`,
/// and prints its pin.
///
/// A file that is there stays, with an error, unless `replace` is set: qnet is pinned to the
/// certificate and would have to be pinned again.
pub fn run(replace: bool, root: &Path) -> Result<()> {
    run_with(replace, root, crate::unix_time()?, &mut io::stdout())
}

/// `run`, with the time and the output in the caller's hands.
fn run_with(replace: bool, root: &Path, now_unix: u64, out: &mut dyn Write) -> Result<()> {
    let config_path = root.join(CONFIG_FILE);
    // The text of this file holds the Wi-Fi passphrase: it goes into no message.
    let text = fs::read_to_string(&config_path)
        .with_context(|| format!("cannot read {}", config_path.display()))?;
    let parsed = config::parse(&text).map_err(|error| anyhow!("{error}"))?;

    let old_there = match fs::symlink_metadata(root.join(CERT_FILE)) {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error).with_context(|| format!("cannot look at {CERT_FILE}")),
    };
    if old_there && !replace {
        bail!("{CERT_FILE} exists; --replace makes a new one, and qnet must then be pinned again");
    }

    let pem = Zeroizing::new(make(&parsed.hostname, parsed.net.address.addr, now_unix)?);
    // A file that deploy would refuse is not one to write.
    tls::server_config(pem.as_bytes()).map_err(|reason| anyhow!("{reason}"))?;
    let digest = tls::leaf_sha256(pem.as_bytes())
        .ok_or_else(|| anyhow!("the certificate that was made cannot be read back"))?;
    install(root, &pem, replace)?;

    writeln!(
        out,
        "make-cert: wrote {CERT_FILE}; pin qnet to this certificate (SHA-256): {}",
        tls::pin_text(&digest)
    )?;
    if old_there {
        writeln!(
            out,
            "make-cert: the old certificate is no longer used: qnet must be pinned again"
        )?;
    }
    Ok(())
}

/// Puts the PEM in place under its name. It goes through a temporary name in the same folder, so
/// the name never stands for half a file; with `replace`, that rename is what replaces the old
/// file, and otherwise a file that is there is never touched.
fn install(root: &Path, pem: &str, replace: bool) -> Result<()> {
    let target = root.join(CERT_FILE);
    let part = root.join(PART_FILE);
    // One that an interrupted run left holds a key that nothing uses. It is removed as it is, so
    // that a link in its place is not written through.
    match fs::remove_file(&part) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => {
            return Err(error).with_context(|| format!("cannot remove {}", part.display()));
        }
        _ => {}
    }
    // Mode 0600, and a name that is not taken: it fails where a link is, and removes what it
    // wrote if the write fails.
    write_private_new(&part, pem.as_bytes())?;
    let placed = if replace {
        fs::rename(&part, &target)
    } else {
        // A link fails where a rename would replace a file that was made since the look above.
        fs::hard_link(&part, &target)
    };
    if let Err(error) = placed {
        let _ = fs::remove_file(&part);
        return Err(error).with_context(|| format!("cannot create {}", target.display()));
    }
    // After a rename there is nothing left to remove.
    match fs::remove_file(&part) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => {
            Err(error).with_context(|| format!("cannot remove {}", part.display()))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::fs::{PermissionsExt, symlink};

    use x509_parser::extensions::GeneralName;
    use x509_parser::pem::Pem;

    const EXAMPLE: &str = include_str!("../../qberrypi.example.toml");

    /// The DER of the certificate in `pem`.
    fn certificate_der(pem: &str) -> Vec<u8> {
        Pem::iter_from_buffer(pem.as_bytes())
            .map(Result::unwrap)
            .find(|section| section.label == "CERTIFICATE")
            .expect("a certificate section")
            .contents
    }

    #[test]
    fn the_made_certificate_serves_names_the_pi_and_does_not_expire() {
        let pem = make("qberrypi", Ipv4Addr::new(192, 0, 2, 53), 1_800_000_000).unwrap();
        assert!(tls::server_config(pem.as_bytes()).is_ok());

        let der = certificate_der(&pem);
        let (rest, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
        assert!(rest.is_empty());
        // The subject is the host name, and the certificate signs for itself.
        let names: Vec<_> = cert
            .subject()
            .iter_common_name()
            .map(|name| name.as_str().unwrap())
            .collect();
        assert_eq!(names, ["qberrypi"]);
        assert_eq!(cert.subject(), cert.issuer());
        // Its alternative names are the host name and the address, and nothing else.
        let alternatives = cert
            .subject_alternative_name()
            .unwrap()
            .expect("a subject alternative name")
            .value
            .general_names
            .clone();
        assert_eq!(
            alternatives,
            [
                GeneralName::DNSName("qberrypi"),
                GeneralName::IPAddress(&[192, 0, 2, 53])
            ]
        );
        // An hour before it was made, to the last second of 9999, which is written as the
        // GeneralizedTime that RFC 5280 gives for "no expiry".
        let validity = cert.validity();
        assert_eq!(validity.not_before.timestamp(), 1_799_996_400);
        assert_eq!(validity.not_after.timestamp(), 253_402_300_799);
        assert!(der.windows(15).any(|bytes| bytes == b"99991231235959Z"));
        // ECDSA P-256, signed with SHA-256.
        assert_eq!(
            cert.signature_algorithm.algorithm.to_id_string(),
            "1.2.840.10045.4.3.2"
        );
        let key = cert.public_key();
        assert_eq!(key.algorithm.algorithm.to_id_string(), "1.2.840.10045.2.1");
        let curve = key.algorithm.parameters.as_ref().unwrap().as_oid().unwrap();
        assert_eq!(curve.to_id_string(), "1.2.840.10045.3.1.7");
    }

    #[test]
    fn every_certificate_has_a_key_and_a_serial_of_its_own() {
        let address = Ipv4Addr::new(192, 0, 2, 53);
        let first = make("qberrypi", address, 1_800_000_000).unwrap();
        let second = make("qberrypi", address, 1_800_000_000).unwrap();
        assert_ne!(first, second);
        let serials: Vec<Vec<u8>> = [&first, &second]
            .iter()
            .map(|pem| {
                let der = certificate_der(pem);
                let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
                cert.raw_serial().to_vec()
            })
            .collect();
        assert_ne!(serials[0], serials[1]);
        // Positive, and no longer than RFC 5280 allows.
        for serial in &serials {
            assert!(serial.len() <= 20 && serial[0] & 0x80 == 0, "{serial:02x?}");
        }
        // The key comes first, and is a PKCS#8 one.
        assert!(first.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(first.contains("-----BEGIN CERTIFICATE-----"));
    }

    /// A repository root that has the example `qberrypi.toml`.
    fn root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("qberrypi.toml"), EXAMPLE).unwrap();
        root
    }

    fn made(replace: bool, root: &Path) -> (Result<()>, String) {
        let mut said = Vec::new();
        let result = run_with(replace, root, 1_800_000_000, &mut said);
        (result, String::from_utf8(said).unwrap())
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn an_existing_certificate_is_kept_unless_replace_is_asked() {
        let root = root();
        let file = root.path().join("qberrypi-tls.pem");

        let (result, said) = made(false, root.path());
        result.unwrap();
        let first = fs::read(&file).unwrap();
        assert_eq!(mode(&file), 0o600);
        let pem = String::from_utf8(first.clone()).unwrap();
        assert!(tls::server_config(pem.as_bytes()).is_ok());
        let pin = tls::pin_text(&tls::leaf_sha256(pem.as_bytes()).unwrap());
        assert_eq!(
            said,
            format!(
                "make-cert: wrote qberrypi-tls.pem; pin qnet to this certificate (SHA-256): {pin}\n"
            )
        );

        // Asked again without --replace, it says what to do and changes nothing.
        let (result, said) = made(false, root.path());
        let error = format!("{:#}", result.unwrap_err());
        assert_eq!(
            error,
            "qberrypi-tls.pem exists; --replace makes a new one, and qnet must then be pinned again"
        );
        assert_eq!(said, "");
        assert_eq!(fs::read(&file).unwrap(), first);

        // With --replace, a new certificate takes its place, and the old pin is said to be dead.
        let (result, said) = made(true, root.path());
        result.unwrap();
        let second = fs::read(&file).unwrap();
        assert_ne!(second, first);
        assert_eq!(mode(&file), 0o600);
        let pem = String::from_utf8(second).unwrap();
        let new_pin = tls::pin_text(&tls::leaf_sha256(pem.as_bytes()).unwrap());
        assert_ne!(new_pin, pin);
        assert_eq!(
            said,
            format!(
                "make-cert: wrote qberrypi-tls.pem; pin qnet to this certificate (SHA-256): {new_pin}\n\
                 make-cert: the old certificate is no longer used: qnet must be pinned again\n"
            )
        );

        // Nothing else is left in the folder: no temporary name.
        let mut names: Vec<_> = fs::read_dir(root.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["qberrypi-tls.pem", "qberrypi.toml"]);
    }

    #[test]
    fn replace_with_no_file_to_replace_makes_one_and_does_not_mourn_an_old_one() {
        let root = root();
        let (result, said) = made(true, root.path());
        result.unwrap();
        assert!(
            said.starts_with("make-cert: wrote qberrypi-tls.pem;"),
            "{said}"
        );
        assert_eq!(said.lines().count(), 1, "{said}");
    }

    #[test]
    fn the_certificate_names_the_host_and_the_address_of_the_configuration() {
        let root = root();
        let text = EXAMPLE
            .replace("hostname = \"qberrypi\"", "hostname = \"pihole-two\"")
            .replace("192.0.2.53", "192.0.2.77");
        assert_ne!(
            text, EXAMPLE,
            "the example has no such host name or address"
        );
        fs::write(root.path().join("qberrypi.toml"), text).unwrap();
        made(false, root.path()).0.unwrap();
        let pem = fs::read_to_string(root.path().join("qberrypi-tls.pem")).unwrap();
        let der = certificate_der(&pem);
        let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
        assert_eq!(
            cert.subject()
                .iter_common_name()
                .next()
                .unwrap()
                .as_str()
                .unwrap(),
            "pihole-two"
        );
        let names = &cert
            .subject_alternative_name()
            .unwrap()
            .unwrap()
            .value
            .general_names;
        assert_eq!(
            names[..],
            [
                GeneralName::DNSName("pihole-two"),
                GeneralName::IPAddress(&[192, 0, 2, 77])
            ]
        );
    }

    #[test]
    fn what_is_printed_and_what_goes_wrong_never_holds_the_key() {
        let root = root();
        let (result, said) = made(false, root.path());
        result.unwrap();
        let pem = fs::read_to_string(root.path().join("qberrypi-tls.pem")).unwrap();
        let key_lines: Vec<&str> = pem
            .split("-----BEGIN CERTIFICATE-----")
            .next()
            .unwrap()
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        assert!(!key_lines.is_empty());
        let shown = |text: &str| {
            assert!(
                !text.contains("PRIVATE") && !text.contains("BEGIN"),
                "{text}"
            );
            for line in &key_lines {
                assert!(!text.contains(line), "{text}");
            }
        };
        shown(&said);
        // The refusals too.
        let (result, said) = made(false, root.path());
        shown(&format!("{:#}{:?}", result.as_ref().unwrap_err(), result));
        shown(&said);
        // A configuration that does not parse is refused by the key it fails on, not quoted.
        fs::write(
            root.path().join("qberrypi.toml"),
            EXAMPLE.replace("country = \"US\"", "country = \"canary-value-41\""),
        )
        .unwrap();
        let (result, _) = made(true, root.path());
        let error = format!("{:#}", result.unwrap_err());
        assert!(!error.contains("canary-value-41"), "{error}");
        assert!(!error.contains("example-passphrase"), "{error}");
    }

    #[test]
    fn without_a_usable_configuration_nothing_is_written() {
        let root = tempfile::tempdir().unwrap();
        // No qberrypi.toml at all.
        let (result, _) = made(false, root.path());
        let error = format!("{:#}", result.unwrap_err());
        assert!(error.contains("qberrypi.toml"), "{error}");
        // One that does not parse.
        fs::write(root.path().join("qberrypi.toml"), "this is not toml").unwrap();
        assert!(made(false, root.path()).0.is_err());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[test]
    fn a_link_is_neither_followed_nor_written_through() {
        let root = root();
        let elsewhere = tempfile::tempdir().unwrap();
        let outside = elsewhere.path().join("keep");
        fs::write(&outside, "OUTSIDE").unwrap();

        // A link where the certificate goes is a file that is there: without --replace it stays.
        let file = root.path().join("qberrypi-tls.pem");
        symlink(&outside, &file).unwrap();
        assert!(made(false, root.path()).0.is_err());
        assert!(fs::symlink_metadata(&file).unwrap().is_symlink());
        // With --replace the link itself is replaced, and what it pointed at is not touched.
        made(true, root.path()).0.unwrap();
        assert!(fs::symlink_metadata(&file).unwrap().is_file());
        assert_eq!(fs::read_to_string(&outside).unwrap(), "OUTSIDE");

        // A link where the temporary name goes, as an earlier run or someone else left it, is
        // not written through either.
        fs::remove_file(&file).unwrap();
        symlink(&outside, root.path().join("qberrypi-tls.pem.part")).unwrap();
        made(false, root.path()).0.unwrap();
        assert_eq!(fs::read_to_string(&outside).unwrap(), "OUTSIDE");
        assert_eq!(mode(&file), 0o600);
        assert!(!root.path().join("qberrypi-tls.pem.part").exists());
    }

    #[test]
    fn a_failure_leaves_no_temporary_and_the_old_file_as_it_was() {
        let root = root();
        let file = root.path().join("qberrypi-tls.pem");
        // A folder where the file goes cannot be replaced by a rename.
        fs::create_dir(&file).unwrap();
        fs::write(file.join("inside"), "x").unwrap();
        let (result, _) = made(true, root.path());
        assert!(result.is_err());
        assert!(file.join("inside").exists());
        assert!(!root.path().join("qberrypi-tls.pem.part").exists());

        // An old file stays the same bytes when the new one cannot be made: a stale temporary
        // that is a folder cannot be cleared.
        fs::remove_dir_all(&file).unwrap();
        made(false, root.path()).0.unwrap();
        let old = fs::read(&file).unwrap();
        fs::create_dir(root.path().join("qberrypi-tls.pem.part")).unwrap();
        assert!(made(true, root.path()).0.is_err());
        assert_eq!(fs::read(&file).unwrap(), old);
    }
}
