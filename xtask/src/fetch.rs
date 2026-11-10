//! `cargo xtask fetch`: downloads the pinned packages, checks each against its
//! digest and extracts the files the image needs.
//!
//! Everything lands under `vendor-cache/`, which is never committed: the
//! packages in `debs/`, the files taken from them in `extracted/`.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use sha2::{Sha256, Sha512};

use crate::deb;
use crate::pins::{Digest, PACKAGES, Package};

/// How the download servers are told who is asking.
const USER_AGENT: &str = "qberrypi-xtask";

/// The longest one download may take before it is given up.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(600);

/// Something that downloads a URL into the file at the given path.
type Download<'a> = &'a dyn Fn(&str, &Path) -> Result<()>;

/// Downloads, verifies and extracts every pinned package under `root/vendor-cache/`.
///
/// A package already downloaded with the right digest is not downloaded again,
/// and nothing is extracted until every package has been verified.
pub fn run(root: &Path) -> Result<()> {
    fetch_packages(root, PACKAGES, &download)
}

/// Fails unless the file at `path` has the digest given; the error shows both digests.
pub fn verify(path: &Path, digest: &Digest) -> Result<()> {
    let mut file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let (kind, expected, actual) = match digest {
        Digest::Sha256(expected) => ("SHA-256", expected, hex_digest::<Sha256>(&mut file)),
        Digest::Sha512(expected) => ("SHA-512", expected, hex_digest::<Sha512>(&mut file)),
    };
    let actual = actual.with_context(|| format!("cannot read {}", path.display()))?;
    if !actual.eq_ignore_ascii_case(expected) {
        bail!(
            "{}: {kind} is {actual}, expected {expected}",
            path.display()
        );
    }
    Ok(())
}

/// Hashes everything left in `file` and returns the digest as lowercase hexadecimal.
fn hex_digest<D: sha2::Digest>(file: &mut File) -> io::Result<String> {
    let mut hasher = D::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// Gets every package into `vendor-cache/debs/`, then extracts their wanted files into `vendor-cache/extracted/`.
fn fetch_packages(root: &Path, packages: &[Package], download: Download) -> Result<()> {
    let cache = root.join("vendor-cache");
    let debs = cache.join("debs");
    fs::create_dir_all(&debs).with_context(|| format!("cannot create {}", debs.display()))?;
    let verified = packages
        .iter()
        .map(|package| verified_deb(package, &debs, download))
        .collect::<Result<Vec<_>>>()?;

    let extracted = cache.join("extracted");
    for (package, deb) in packages.iter().zip(verified) {
        deb::extract(&deb, package.wanted, &extracted)?;
        println!(
            "fetch: {}: {} files in {}",
            package.name,
            package.wanted.len(),
            extracted.display()
        );
    }
    Ok(())
}

/// Returns the package's verified `.deb` in `debs`, downloading it unless a verified copy is there.
///
/// A copy with the wrong digest is deleted and downloaded once more. The
/// download is verified under a temporary name, so the returned path only
/// ever names a file with the pinned digest.
fn verified_deb(package: &Package, debs: &Path, download: Download) -> Result<PathBuf> {
    let deb = debs.join(package.file);
    if deb.exists() {
        match verify(&deb, &package.digest) {
            Ok(()) => {
                println!("fetch: {} is already here and verified", package.file);
                return Ok(deb);
            }
            Err(wrong) => {
                println!("fetch: discarding {wrong:#}");
                fs::remove_file(&deb)
                    .with_context(|| format!("cannot delete {}", deb.display()))?;
            }
        }
    }

    println!("fetch: downloading {}", package.url);
    let partial = debs.join(format!("{}.partial", package.file));
    let kept = download(package.url, &partial)
        .with_context(|| format!("cannot download {}", package.url))
        .and_then(|()| {
            verify(&partial, &package.digest).with_context(|| {
                format!(
                    "{} from {} does not match its pin and was not kept",
                    package.file, package.url
                )
            })
        })
        .and_then(|()| {
            fs::rename(&partial, &deb).with_context(|| format!("cannot write {}", deb.display()))
        });
    if kept.is_err() {
        let _ = fs::remove_file(&partial);
    }
    kept.map(|()| deb)
}

/// Downloads `url` over HTTPS into the file at `dest`.
fn download(url: &str, dest: &Path) -> Result<()> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .user_agent(USER_AGENT)
        .https_only(true)
        .timeout_global(Some(DOWNLOAD_TIMEOUT))
        .build()
        .into();
    let mut response = agent.get(url).call()?;
    let mut file =
        File::create(dest).with_context(|| format!("cannot write {}", dest.display()))?;
    io::copy(&mut response.body_mut().as_reader(), &mut file)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deb::tests::{files_under, fixture_deb};
    use std::cell::Cell;
    use std::fs;

    const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const ABC_SHA512: &str = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    const ZERO_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    /// A package whose `.deb` is the three bytes "abc".
    fn abc_package() -> Package {
        Package {
            name: "abc",
            url: "https://example.invalid/pool/abc.deb",
            file: "abc.deb",
            digest: Digest::Sha256(ABC_SHA256),
            wanted: &[],
        }
    }

    fn never_download(url: &str, _dest: &Path) -> Result<()> {
        panic!("downloaded {url}");
    }

    #[test]
    fn wrong_digest_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("abc.bin");
        fs::write(&path, "abc").unwrap();

        let e = verify(&path, &Digest::Sha256(ZERO_SHA256)).unwrap_err();

        let e = e.to_string();
        assert!(e.contains("abc.bin"), "{e}");
        assert!(e.contains(ZERO_SHA256) && e.contains(ABC_SHA256), "{e}");
    }

    #[test]
    fn wrong_sha512_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("abd.bin");
        fs::write(&path, "abd").unwrap();

        let e = verify(&path, &Digest::Sha512(ABC_SHA512)).unwrap_err();

        let e = e.to_string();
        assert!(e.contains("abd.bin") && e.contains(ABC_SHA512), "{e}");
    }

    #[test]
    fn right_sha256_and_sha512_are_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("abc.bin");
        fs::write(&path, "abc").unwrap();

        verify(&path, &Digest::Sha256(ABC_SHA256)).unwrap();
        verify(&path, &Digest::Sha512(ABC_SHA512)).unwrap();
    }

    #[test]
    fn a_file_that_cannot_be_read_is_named() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.bin");

        let e = verify(&path, &Digest::Sha256(ABC_SHA256)).unwrap_err();

        assert!(e.to_string().contains("absent.bin"), "{e}");
    }

    #[test]
    fn a_verified_file_is_not_downloaded_again() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("abc.deb"), "abc").unwrap();

        let deb = verified_deb(&abc_package(), dir.path(), &never_download).unwrap();

        assert_eq!(deb, dir.path().join("abc.deb"));
        assert_eq!(fs::read_to_string(deb).unwrap(), "abc");
    }

    #[test]
    fn a_file_with_the_wrong_digest_is_replaced_by_one_download() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("abc.deb"), "stale").unwrap();
        let downloads = Cell::new(0);

        let deb = verified_deb(&abc_package(), dir.path(), &|url, dest| {
            assert_eq!(url, "https://example.invalid/pool/abc.deb");
            downloads.set(downloads.get() + 1);
            Ok(fs::write(dest, "abc")?)
        })
        .unwrap();

        assert_eq!(downloads.get(), 1);
        assert_eq!(fs::read_to_string(deb).unwrap(), "abc");
        assert_eq!(files_under(dir.path()), ["abc.deb"]);
    }

    #[test]
    fn a_download_that_is_still_wrong_fails_and_is_not_kept() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("abc.deb"), "stale").unwrap();
        let downloads = Cell::new(0);

        let e = verified_deb(&abc_package(), dir.path(), &|_, dest| {
            downloads.set(downloads.get() + 1);
            Ok(fs::write(dest, "abd")?)
        })
        .unwrap_err();

        let e = format!("{e:#}");
        assert_eq!(downloads.get(), 1);
        assert!(e.contains("abc.deb") && e.contains(ABC_SHA256), "{e}");
        assert!(
            e.contains("a52d159f262b2c6ddb724a61840befc36eb30c88877a4030b65cbe86298449c9"),
            "{e}"
        );
        assert_eq!(files_under(dir.path()), [] as [&str; 0]);
    }

    #[test]
    fn a_failed_download_leaves_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();

        let e = verified_deb(&abc_package(), dir.path(), &|_, dest| {
            fs::write(dest, "ab")?;
            anyhow::bail!("connection lost")
        })
        .unwrap_err();

        let e = format!("{e:#}");
        assert!(
            e.contains("connection lost") && e.contains("https://example.invalid/pool/abc.deb"),
            "{e}"
        );
        assert_eq!(files_under(dir.path()), [] as [&str; 0]);
    }

    #[test]
    fn fetches_into_vendor_cache_and_a_second_run_downloads_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let source = fixture_deb(dir.path());
        let digest = hex_digest::<sha2::Sha256>(&mut File::open(&source).unwrap()).unwrap();
        let packages = [Package {
            name: "fixture",
            url: "https://example.invalid/pool/fixture.deb",
            file: "fixture.deb",
            digest: Digest::Sha256(digest.leak()),
            wanted: &[("usr/lib/a.txt", "a.txt"), ("usr/lib/m.ko.xz", "m/m.ko")],
        }];
        let root = &dir.path().join("root");

        fetch_packages(root, &packages, &|_, dest| {
            fs::copy(&source, dest)?;
            Ok(())
        })
        .unwrap();
        fetch_packages(root, &packages, &never_download).unwrap();

        assert_eq!(
            files_under(root),
            [
                "vendor-cache/debs/fixture.deb",
                "vendor-cache/extracted/a.txt",
                "vendor-cache/extracted/m/m.ko",
            ]
        );
    }

    #[test]
    fn nothing_is_extracted_unless_every_package_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let source = fixture_deb(dir.path());
        let digest = hex_digest::<sha2::Sha256>(&mut File::open(&source).unwrap()).unwrap();
        let good = Package {
            name: "fixture",
            url: "https://example.invalid/pool/fixture.deb",
            file: "fixture.deb",
            digest: Digest::Sha256(digest.leak()),
            wanted: &[("usr/lib/a.txt", "a.txt")],
        };
        let bad = Package {
            name: "other",
            url: "https://example.invalid/pool/other.deb",
            file: "other.deb",
            digest: Digest::Sha256(ZERO_SHA256),
            wanted: &[],
        };
        let root = &dir.path().join("root");

        fetch_packages(root, &[good, bad], &|_, dest| {
            fs::copy(&source, dest)?;
            Ok(())
        })
        .unwrap_err();

        assert_eq!(files_under(root), ["vendor-cache/debs/fixture.deb"]);
    }
}
