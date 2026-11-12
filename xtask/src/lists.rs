//! `cargo xtask fetch-lists`, and the snapshot of the lists that `build` packs into the image.
//!
//! The lists the configuration names are downloaded into `vendor-cache/lists/`, which is never
//! committed. List N is the file `{url_key}.txt` there; the lock file says, line by line, what
//! each file must hold. A URL is never written down, in a file name or in the lock or in a
//! message: it may carry a token, so a list is named by its place in the configuration.
//!
//! A fetch is all or nothing: every list is downloaded and checked first, and only if every one
//! holds a rule are the files in the cache replaced. A fetch merges into the lock: the cache may
//! be shared by checkouts that name different lists, so what another fetch locked stays locked
//! while its file is intact. The snapshot is made from the cache alone, and reads no network.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::io::{ErrorKind, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use qb_dns::parse::{RuleKind, parse_list};
use qberrypi::lists::snapshot::{Header, MARKER};
use sha2::{Digest, Sha256};

use crate::fetch::Download;

/// The folder under the repository root that holds the downloaded lists.
pub const LIST_CACHE: &str = "vendor-cache/lists";

/// What each list in the cache must hold: one line per list, `{url_key} {sha256} {bytes} {fetched}`.
pub const LOCK_FILE: &str = "vendor-cache/lists/lock";

/// A snapshot older than this many days is said to be old when it is packed into an image.
pub const STALE_AFTER_DAYS: u64 = 7;

/// How hard zstd works on the snapshot. The Pi unpacks any level.
pub const ZSTD_LEVEL: i32 = 19;

/// What follows a list's key in the cache for the file itself and for one still being downloaded.
const LIST_SUFFIX: &str = ".txt";
const PARTIAL_SUFFIX: &str = ".txt.partial";

/// The configuration the owner keeps, which is never committed, and the example beside it.
const LOCAL_CONFIG: &str = "qberrypi.toml";
const EXAMPLE_CONFIG: &str = "qberrypi.example.toml";

/// What stands for a list's address in a message that would otherwise show it.
const ADDRESS_LEFT_OUT: &str = "[address]";

/// The name a list has in the cache: the first 16 hexadecimal digits of its URL's SHA-256.
pub fn url_key(url: &str) -> String {
    let mut key = sha256_hex(url.as_bytes());
    key.truncate(16);
    key
}

/// The SHA-256 of `data` as lowercase hexadecimal.
fn sha256_hex(data: &[u8]) -> String {
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(data) {
        // Writing to a String cannot fail.
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// The URLs of the block lists: `dns.lists` of `qberrypi.toml` under `root` if that file is
/// there, otherwise of `qberrypi.example.toml`.
///
/// A file that does not parse is an error with the parser's message, which never quotes it.
pub fn configured_lists(root: &Path) -> Result<Vec<String>> {
    let (name, text) = match fs::read_to_string(root.join(LOCAL_CONFIG)) {
        Ok(text) => (LOCAL_CONFIG, text),
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let path = root.join(EXAMPLE_CONFIG);
            let text = fs::read_to_string(&path)
                .with_context(|| format!("cannot read {}", path.display()))?;
            (EXAMPLE_CONFIG, text)
        }
        Err(e) => {
            return Err(e)
                .with_context(|| format!("cannot read {LOCAL_CONFIG} under {}", root.display()));
        }
    };
    let config = qberrypi::config::parse(&text)
        .map_err(|e| anyhow!("cannot take the lists from {name}: {e}"))?;
    Ok(config.dns.lists)
}

/// One line of the lock: what a list's file must hold.
struct Locked {
    sha256: String,
    bytes: u64,
    fetched_unix_secs: u64,
}

/// What a fetched list came to, once it was checked.
struct Checked {
    key: String,
    sha256: String,
    bytes: usize,
    exact: usize,
    suffix: usize,
}

/// Removes the half-downloaded files it was told of when it goes out of scope, whatever came to
/// pass: a failed fetch leaves none.
struct Partials(Vec<PathBuf>);

impl Drop for Partials {
    fn drop(&mut self) {
        for path in &self.0 {
            // One that is not there is one that became a list's file, or was never made.
            let _ = fs::remove_file(path);
        }
    }
}

/// Downloads every list in `urls` into `root/vendor-cache/lists/` and locks what came.
///
/// Every list is downloaded to a file of its own and checked: it must hold at least one rule,
/// which a captive portal's page or an error page does not. Only when every list is good are the
/// cached files replaced, and then the lock is written, as `now_unix_secs` says they were
/// fetched. When any fails the cache and the lock stay as they were. A list named twice is
/// fetched once.
///
/// The lock is merged, not replaced: the cache is shared by checkouts that name different lists,
/// so each line of the old lock whose list is not in `urls` is kept, with its own time, as long
/// as its file still has the hash and the size the line says; a line whose file changed or went
/// is dropped. A lock that is missing is empty, and one that is damaged is taken as empty too,
/// so this fetch is the repair that `snapshot` asks for. The lock is written in the order of the
/// keys, to a temporary file of its own name that is renamed over it. A rename that fails after
/// the first list was put in place, or the lock's write, leaves the cache half updated: a file
/// then differs from its line or has none, and `snapshot` refuses it until the next fetch.
pub fn fetch(root: &Path, urls: &[String], now_unix_secs: u64, download: Download) -> Result<()> {
    let dir = root.join(LIST_CACHE);
    fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;

    let mut partials = Partials(Vec::new());
    let mut checked: Vec<Checked> = Vec::new();
    for (index, url) in urls.iter().enumerate() {
        let number = index + 1;
        let key = url_key(url);
        if checked.iter().any(|done| done.key == key) {
            continue;
        }
        let partial = dir.join(format!("{key}{PARTIAL_SUFFIX}"));
        partials.0.push(partial.clone());
        download(url, &partial).map_err(|e| {
            anyhow!(
                "cannot download list {number}: {}",
                without_address(&format!("{e:#}"), url)
            )
        })?;
        let text = fs::read(&partial).with_context(|| format!("cannot read list {number} back"))?;
        let stats = parse_list(&text, |_, _| {});
        if stats.exact + stats.suffix == 0 {
            bail!("list {number} is not a blocklist; kept what was there");
        }
        checked.push(Checked {
            key,
            sha256: sha256_hex(&text),
            bytes: text.len(),
            exact: stats.exact,
            suffix: stats.suffix,
        });
    }

    // Every list is good: put them in place, and then the lock that says what they hold.
    for list in &checked {
        let (partial, file) = (
            dir.join(format!("{}{PARTIAL_SUFFIX}", list.key)),
            list_file(root, &list.key),
        );
        fs::rename(&partial, &file)
            .with_context(|| format!("cannot replace {}", file.display()))?;
    }
    let mut lock = kept_lock_lines(root, &checked)?;
    for list in checked.iter() {
        lock.insert(
            list.key.clone(),
            Locked {
                sha256: list.sha256.clone(),
                bytes: list.bytes as u64,
                fetched_unix_secs: now_unix_secs,
            },
        );
    }
    write_lock(root, &lock)?;

    for (index, url) in urls.iter().enumerate() {
        let key = url_key(url);
        if let Some(list) = checked.iter().find(|list| list.key == key) {
            println!(
                "fetch-lists: list {}: {} exact, {} suffix, {} bytes",
                index + 1,
                list.exact,
                list.suffix,
                list.bytes
            );
        }
    }
    Ok(())
}

/// Where the list with this key is in the cache.
fn list_file(root: &Path, key: &str) -> PathBuf {
    root.join(LIST_CACHE).join(format!("{key}{LIST_SUFFIX}"))
}

/// The lines of the lock on disk that survive a fetch of `fetched`: those of other lists whose
/// file still holds what the line says.
fn kept_lock_lines(root: &Path, fetched: &[Checked]) -> Result<BTreeMap<String, Locked>> {
    // A damaged lock is no help to anyone: start over from the lists of this fetch.
    let mut lock = parse_lock(&read_lock_text(root)?).unwrap_or_default();
    lock.retain(|key, locked| {
        !fetched.iter().any(|list| list.key == *key) && file_holds(root, key, locked)
    });
    Ok(lock)
}

/// Whether the list's file is there with the size and the hash the lock line says.
fn file_holds(root: &Path, key: &str, locked: &Locked) -> bool {
    let path = list_file(root, key);
    let Ok(meta) = fs::metadata(&path) else {
        return false;
    };
    meta.len() == locked.bytes
        && fs::read(&path).is_ok_and(|text| sha256_hex(&text) == locked.sha256)
}

/// Replaces the lock with `lock`, one line per list in the order of the keys: the new one is
/// written to a temporary file in the same folder, with a name nothing else has, and renamed
/// over it.
fn write_lock(root: &Path, lock: &BTreeMap<String, Locked>) -> Result<()> {
    let mut text = String::new();
    for (key, locked) in lock {
        let _ = writeln!(
            text,
            "{key} {} {} {}",
            locked.sha256, locked.bytes, locked.fetched_unix_secs
        );
    }
    let path = root.join(LOCK_FILE);
    let dir = root.join(LIST_CACHE);
    let mut temporary = tempfile::NamedTempFile::new_in(&dir)
        .with_context(|| format!("cannot write in {}", dir.display()))?;
    temporary
        .write_all(text.as_bytes())
        .with_context(|| format!("cannot write {}", temporary.path().display()))?;
    // A failed rename drops the temporary file, which removes it.
    temporary.persist(&path).map_err(|e| {
        anyhow::Error::new(e.error).context(format!("cannot replace {}", path.display()))
    })?;
    Ok(())
}

/// `message` with the list's URL, and the host and the credentials in it, left out. A download
/// error may say what it was asked for.
fn without_address(message: &str, url: &str) -> String {
    let authority = url
        .split_once("://")
        .map_or(url, |(_, rest)| rest)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    let host_and_port = authority.rsplit('@').next().unwrap_or_default();
    let host = host_and_port.split(':').next().unwrap_or_default();
    let mut message = message.to_owned();
    for address in [url, authority, host_and_port, host] {
        if !address.is_empty() {
            message = message.replace(address, ADDRESS_LEFT_OUT);
        }
    }
    message
}

/// Merges the rules of every text into one list text, and says what it holds.
///
/// The rules are those that `parse_list` reads, with [`MARKER`] as one more exact name. Exact
/// names and suffix names are each sorted bytewise, once each. The text is the header's line,
/// a hosts line for each exact name, then a `||name^` line for each suffix name; the header
/// counts those lines, and `lists` is the number of texts.
pub fn canonical(texts: &[&[u8]], fetched_unix_secs: u64) -> (String, Header) {
    let mut exact = BTreeSet::from([MARKER.to_owned()]);
    let mut suffix = BTreeSet::new();
    for text in texts {
        parse_list(text, |kind, name| {
            let names = match kind {
                RuleKind::Exact => &mut exact,
                RuleKind::Suffix => &mut suffix,
            };
            if !names.contains(name) {
                names.insert(name.to_owned());
            }
        });
    }
    let count = |names: &BTreeSet<String>| u32::try_from(names.len()).unwrap_or(u32::MAX);
    let header = Header {
        fetched_unix_secs,
        lists: u32::try_from(texts.len()).unwrap_or(u32::MAX),
        exact: count(&exact),
        suffix: count(&suffix),
    };
    let mut text = header.line();
    for name in &exact {
        let _ = writeln!(text, "0.0.0.0 {name}");
    }
    for name in &suffix {
        let _ = writeln!(text, "||{name}^");
    }
    (text, header)
}

/// The snapshot for an image: the canonical text of the cached lists, compressed, with its header.
///
/// Every list of `urls` must have been fetched, and its file must be the one the lock holds. The
/// snapshot is as old as the oldest of the lists, or 0 with none. The bytes are a function of
/// the cache alone: one call of zstd with no worker threads.
pub fn snapshot(root: &Path, urls: &[String]) -> Result<(Vec<u8>, Header)> {
    let lock = read_lock(root)?;
    let mut texts = Vec::new();
    let mut oldest: Option<u64> = None;
    for (index, url) in urls.iter().enumerate() {
        let number = index + 1;
        let not_fetched =
            || anyhow!("list {number} has not been fetched: run cargo xtask fetch-lists");
        let key = url_key(url);
        let locked = lock.get(&key).ok_or_else(not_fetched)?;
        let text = match fs::read(list_file(root, &key)) {
            Ok(text) => text,
            Err(e) if e.kind() == ErrorKind::NotFound => return Err(not_fetched()),
            Err(e) => {
                return Err(e).with_context(|| format!("cannot read list {number}"));
            }
        };
        if sha256_hex(&text) != locked.sha256 {
            bail!("list {number} has changed since it was fetched: run cargo xtask fetch-lists");
        }
        oldest = Some(oldest.map_or(locked.fetched_unix_secs, |t| {
            t.min(locked.fetched_unix_secs)
        }));
        texts.push(text);
    }
    let texts: Vec<&[u8]> = texts.iter().map(Vec::as_slice).collect();
    let (text, header) = canonical(&texts, oldest.unwrap_or(0));
    // One call with no worker threads: the same text gives the same bytes.
    let packed = zstd::bulk::compress(text.as_bytes(), ZSTD_LEVEL)
        .context("cannot compress the snapshot")?;
    Ok((packed, header))
}

/// The text of the lock; empty when there is none.
fn read_lock_text(root: &Path) -> Result<String> {
    let path = root.join(LOCK_FILE);
    match fs::read_to_string(&path) {
        Ok(text) => Ok(text),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
    }
}

/// The lock by key; empty when there is none.
fn read_lock(root: &Path) -> Result<BTreeMap<String, Locked>> {
    parse_lock(&read_lock_text(root)?)
        .ok_or_else(|| anyhow!("{LOCK_FILE} is damaged: run cargo xtask fetch-lists"))
}

/// The lines of a lock by key, or `None` when any line is not `{key} {sha256} {bytes} {fetched}`.
fn parse_lock(text: &str) -> Option<BTreeMap<String, Locked>> {
    let mut lock = BTreeMap::new();
    for line in text.lines() {
        let mut words = line.split(' ');
        let (Some(key), Some(sha256), Some(bytes), Some(fetched), None) = (
            words.next(),
            words.next(),
            words.next(),
            words.next(),
            words.next(),
        ) else {
            return None;
        };
        lock.insert(
            key.to_owned(),
            Locked {
                sha256: sha256.to_owned(),
                bytes: bytes.parse().ok()?,
                fetched_unix_secs: fetched.parse().ok()?,
            },
        );
    }
    Some(lock)
}

/// `cargo xtask fetch-lists`: downloads the lists the configuration names, as of `now_unix_secs`.
pub fn run(root: &Path, now_unix_secs: u64) -> Result<()> {
    let urls = configured_lists(root)?;
    fetch(root, &urls, now_unix_secs, &crate::fetch::download)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deb::tests::files_under;
    use qberrypi::lists::snapshot::{Header, MARKER, MAX_SNAPSHOT_BYTES, unpack};
    use tempfile::TempDir;

    const A: &str = "https://lists.example.net/a.txt";
    const B: &str = "https://lists.example.org/b.txt";
    const HOSTS: &[u8] = b"0.0.0.0 ads.example.com\n0.0.0.0 pixel.example.com\n";
    const ADBLOCK: &[u8] = b"||tracker.example.net^\n";
    const HTML: &[u8] = b"<!DOCTYPE html>\n<html><body><h1>Sign in to the network</h1><p>example.com</p></body></html>\n";

    /// The SHA-256 of `HOSTS`, from `sha256sum`.
    const HOSTS_SHA256: &str = "0e6381142f440a14189e4248fa31f33c5bf7093b5d61a1f7689caacc09aca03c";

    /// A configuration that parses, with `lists` as its block lists.
    fn config_with(lists: &str) -> String {
        format!(
            "[wifi]\nssid = \"example-network\"\npassphrase = \"example-passphrase\"\n\
             country = \"US\"\n\n[net]\naddress = \"192.0.2.53/24\"\ngateway = \"192.0.2.1\"\n\n\
             [dns]\nupstreams = [\"9.9.9.9\"]\nlists = [{lists}]\n"
        )
    }

    /// A download that writes the page it holds for a URL, and fails for any other URL, saying
    /// which: the way a real download may.
    fn fake<'a>(pages: &'a [(&'a str, &'a [u8])]) -> impl Fn(&str, &Path) -> Result<()> + 'a {
        move |url, dest| {
            let (_, page) = pages
                .iter()
                .find(|(known, _)| *known == url)
                .with_context(|| format!("no page at {url}"))?;
            fs::write(dest, page)?;
            Ok(())
        }
    }

    fn urls(urls: &[&str]) -> Vec<String> {
        urls.iter().map(|url| (*url).to_owned()).collect()
    }

    fn cached(root: &Path, url: &str) -> PathBuf {
        root.join(LIST_CACHE).join(format!("{}.txt", url_key(url)))
    }

    fn lock(root: &Path) -> String {
        fs::read_to_string(root.join(LOCK_FILE)).unwrap()
    }

    /// A temporary root with the lists `A` and `B` fetched at `1_800_000_000`.
    fn root_with_both_fetched() -> TempDir {
        let root = tempfile::tempdir().unwrap();
        fetch(
            root.path(),
            &urls(&[A, B]),
            1_800_000_000,
            &fake(&[(A, HOSTS), (B, ADBLOCK)]),
        )
        .unwrap();
        root
    }

    #[test]
    fn canonical_text_is_sorted_has_no_duplicates_and_carries_the_marker() {
        let (text, header) = canonical(
            &[
                b"0.0.0.0 b.example.com\n0.0.0.0 A.example.com\n",
                b"||tracker.example.net^\n||a.example.com^\n0.0.0.0 a.example.com\n",
            ],
            1_800_000_000,
        );
        assert_eq!(
            text,
            "# qberrypi-snapshot 1 fetched=1800000000 lists=2 exact=3 suffix=2\n\
             0.0.0.0 a.example.com\n0.0.0.0 b.example.com\n0.0.0.0 qberrypi-snapshot.invalid\n\
             ||a.example.com^\n||tracker.example.net^\n"
        );
        assert_eq!(
            header,
            Header {
                fetched_unix_secs: 1_800_000_000,
                lists: 2,
                exact: 3,
                suffix: 2
            }
        );
        assert_eq!(Header::parse(text.as_bytes()), Some(header));
    }

    #[test]
    fn the_canonical_text_is_itself_a_list_with_the_headers_counts() {
        let (text, header) = canonical(&[HOSTS, ADBLOCK], 1);
        let stats = qb_dns::BlockSetBuilder::new().add_list(text.as_bytes());
        assert_eq!(
            (
                stats.exact as u32,
                stats.suffix as u32,
                stats.invalid,
                stats.unsupported
            ),
            (header.exact, header.suffix, 0, 0)
        );
    }

    #[test]
    fn a_list_key_is_the_start_of_the_urls_hash() {
        assert_eq!(url_key("abc"), "ba7816bf8f01cfea");
        assert_eq!(url_key(A).len(), 16);
        assert_ne!(url_key(A), url_key(B));
    }

    #[test]
    fn fetching_records_each_list_under_its_key_with_its_hash() {
        let root = root_with_both_fetched();
        let dir = root.path().join(LIST_CACHE);

        assert_eq!(fs::read(cached(root.path(), A)).unwrap(), HOSTS);
        assert_eq!(fs::read(cached(root.path(), B)).unwrap(), ADBLOCK);
        let lock = lock(root.path());
        // One line for each list; the lock is in the order of the keys, so put A's first.
        let mut lines: Vec<Vec<&str>> =
            lock.lines().map(|line| line.split(' ').collect()).collect();
        assert_eq!(lines.len(), 2);
        lines.sort_by_key(|line| line[0] != url_key(A));
        assert_eq!(
            lines[0],
            [
                url_key(A).as_str(),
                HOSTS_SHA256,
                &HOSTS.len().to_string(),
                "1800000000"
            ]
        );
        assert_eq!(lines[1][0], url_key(B));
        assert_eq!(lines[1][1].len(), 64);
        assert!(lines[1][1].bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(
            (lines[1][2], lines[1][3]),
            (ADBLOCK.len().to_string().as_str(), "1800000000")
        );
        // No address is written down, in a name or in a file, and no half-done file is left.
        for name in files_under(&dir) {
            assert!(!name.contains("example"), "{name}");
            assert!(!name.ends_with(".partial"), "{name}");
            let text = String::from_utf8_lossy(&fs::read(dir.join(&name)).unwrap()).into_owned();
            assert!(!text.contains("lists.example"), "{name}");
        }
        assert_eq!(files_under(&dir).len(), 3);
    }

    #[test]
    fn fetching_keeps_the_old_file_when_the_new_one_is_not_a_list() {
        // Review Focus 4
        let root = tempfile::tempdir().unwrap();
        fetch(
            root.path(),
            &urls(&[A]),
            1_800_000_000,
            &fake(&[(A, HOSTS)]),
        )
        .unwrap();
        let before = lock(root.path());

        let error =
            fetch(root.path(), &urls(&[A]), 1_800_090_000, &fake(&[(A, HTML)])).unwrap_err();

        assert!(
            format!("{error:#}").contains("list 1 is not a blocklist"),
            "{error:#}"
        );
        assert_eq!(fs::read(cached(root.path(), A)).unwrap(), HOSTS);
        assert_eq!(lock(root.path()), before);
        assert_eq!(files_under(&root.path().join(LIST_CACHE)).len(), 2);
    }

    #[test]
    fn a_page_that_holds_no_rule_is_no_list_even_when_it_is_empty() {
        let root = tempfile::tempdir().unwrap();
        let error = fetch(root.path(), &urls(&[A]), 1, &fake(&[(A, b"")])).unwrap_err();
        assert!(format!("{error:#}").contains("list 1 is not a blocklist; kept what was there"));
        assert!(!cached(root.path(), A).exists());
        assert!(!root.path().join(LOCK_FILE).exists());
        assert!(files_under(&root.path().join(LIST_CACHE)).is_empty());
    }

    #[test]
    fn fetching_changes_nothing_unless_every_list_is_good() {
        let root = root_with_both_fetched();
        let dir = root.path().join(LIST_CACHE);
        let before = lock(root.path());
        let newer: Vec<u8> = [HOSTS, b"0.0.0.0 one-more.example.com\n"].concat();

        let error = fetch(
            root.path(),
            &urls(&[A, B]),
            1_800_090_000,
            &fake(&[(A, &newer), (B, HTML)]),
        )
        .unwrap_err();

        assert!(
            format!("{error:#}").contains("list 2 is not a blocklist"),
            "{error:#}"
        );
        assert_eq!(fs::read(cached(root.path(), A)).unwrap(), HOSTS);
        assert_eq!(fs::read(cached(root.path(), B)).unwrap(), ADBLOCK);
        assert_eq!(lock(root.path()), before);
        assert_eq!(files_under(&dir).len(), 3, "{:?}", files_under(&dir));
    }

    #[test]
    fn a_download_that_fails_names_the_list_and_not_its_address() {
        let root = root_with_both_fetched();
        let dir = root.path().join(LIST_CACHE);
        let before = lock(root.path());
        let newer: Vec<u8> = [HOSTS, b"0.0.0.0 one-more.example.com\n"].concat();

        // The fake says which URL it has no page for, as a real download error may.
        let error = fetch(
            root.path(),
            &urls(&[A, B]),
            1_800_090_000,
            &fake(&[(A, &newer)]),
        )
        .unwrap_err();

        let message = format!("{error:#}");
        assert!(message.contains("list 2"), "{message}");
        assert!(!message.contains("lists.example"), "{message}");
        assert!(!message.contains("b.txt"), "{message}");
        assert_eq!(fs::read(cached(root.path(), A)).unwrap(), HOSTS);
        assert_eq!(lock(root.path()), before);
        assert_eq!(files_under(&dir).len(), 3, "{:?}", files_under(&dir));
    }

    #[test]
    fn a_list_named_twice_is_fetched_once_and_locked_once() {
        let root = tempfile::tempdir().unwrap();
        fetch(
            root.path(),
            &urls(&[A, A]),
            1_800_000_000,
            &fake(&[(A, HOSTS)]),
        )
        .unwrap();
        assert_eq!(lock(root.path()).lines().count(), 1);
        let (bytes, header) = snapshot(root.path(), &urls(&[A, A])).unwrap();
        assert_eq!(header.lists, 2);
        assert_eq!(header.exact, 3);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn the_snapshot_needs_every_list_fetched_and_unchanged() {
        let root = tempfile::tempdir().unwrap();
        let error = snapshot(root.path(), &urls(&[A])).unwrap_err().to_string();
        assert!(error.contains("list 1 has not been fetched"), "{error}");
        assert!(error.contains("cargo xtask fetch-lists"), "{error}");

        fetch(
            root.path(),
            &urls(&[A]),
            1_800_000_000,
            &fake(&[(A, HOSTS)]),
        )
        .unwrap();
        let error = snapshot(root.path(), &urls(&[A, B]))
            .unwrap_err()
            .to_string();
        assert!(error.contains("list 2 has not been fetched"), "{error}");
        assert!(error.contains("cargo xtask fetch-lists"), "{error}");

        let mut text = fs::read(cached(root.path(), A)).unwrap();
        text.push(b'\n');
        fs::write(cached(root.path(), A), text).unwrap();
        let error = snapshot(root.path(), &urls(&[A])).unwrap_err().to_string();
        assert!(
            error.contains("list 1 has changed since it was fetched"),
            "{error}"
        );
        assert!(error.contains("cargo xtask fetch-lists"), "{error}");
        assert!(!error.contains("lists.example"), "{error}");
    }

    #[test]
    fn a_lock_that_is_damaged_says_to_fetch_again() {
        let root = root_with_both_fetched();
        fs::write(root.path().join(LOCK_FILE), "not a lock line\n").unwrap();
        let error = snapshot(root.path(), &urls(&[A])).unwrap_err().to_string();
        assert!(error.contains("cargo xtask fetch-lists"), "{error}");
    }

    #[test]
    fn the_same_cache_gives_the_same_bytes_and_the_pi_can_unpack_them() {
        let root = root_with_both_fetched();

        let (first, header) = snapshot(root.path(), &urls(&[A, B])).unwrap();
        let (second, _) = snapshot(root.path(), &urls(&[A, B])).unwrap();

        assert_eq!(first, second);
        let (text, expected) = canonical(&[HOSTS, ADBLOCK], 1_800_000_000);
        assert_eq!(zstd::decode_all(&first[..]).unwrap(), text.as_bytes());
        // The Pi's decoder reads what the build's encoder wrote at level 19.
        assert_eq!(
            unpack(&first, MAX_SNAPSHOT_BYTES).unwrap(),
            zstd::decode_all(&first[..]).unwrap()
        );
        assert_eq!(header, expected);

        let (empty, header) = snapshot(root.path(), &[]).unwrap();
        assert_eq!(
            String::from_utf8(zstd::decode_all(&empty[..]).unwrap()).unwrap(),
            format!("# qberrypi-snapshot 1 fetched=0 lists=0 exact=1 suffix=0\n0.0.0.0 {MARKER}\n")
        );
        assert_eq!(
            header,
            Header {
                fetched_unix_secs: 0,
                lists: 0,
                exact: 1,
                suffix: 0
            }
        );
    }

    #[test]
    fn the_snapshot_is_as_old_as_its_oldest_list() {
        let root = tempfile::tempdir().unwrap();
        fetch(
            root.path(),
            &urls(&[A]),
            1_800_000_000,
            &fake(&[(A, HOSTS)]),
        )
        .unwrap();
        // A fetch gives every line of the lock the same time; one line is made older by hand.
        let lock_path = root.path().join(LOCK_FILE);
        let mut text = lock(root.path());
        fs::write(cached(root.path(), B), ADBLOCK).unwrap();
        text.push_str(&format!(
            "{} {} {} 1799999000\n",
            url_key(B),
            sha256_hex(ADBLOCK),
            ADBLOCK.len()
        ));
        fs::write(&lock_path, text).unwrap();

        let (_, header) = snapshot(root.path(), &urls(&[A, B])).unwrap();

        assert_eq!(header.fetched_unix_secs, 1_799_999_000);
    }

    #[test]
    fn a_fetch_keeps_the_lists_another_fetch_locked() {
        // The cache is shared by checkouts that name different lists: fetching B must not make
        // the checkout that named A fail with "list 1 has not been fetched".
        let root = tempfile::tempdir().unwrap();
        fetch(
            root.path(),
            &urls(&[A]),
            1_800_000_000,
            &fake(&[(A, HOSTS)]),
        )
        .unwrap();
        fetch(
            root.path(),
            &urls(&[B]),
            1_800_090_000,
            &fake(&[(B, ADBLOCK)]),
        )
        .unwrap();

        let (_, only_a) = snapshot(root.path(), &urls(&[A])).unwrap();
        let (_, both) = snapshot(root.path(), &urls(&[A, B])).unwrap();

        assert_eq!((only_a.exact, only_a.suffix), (3, 0));
        assert_eq!((both.exact, both.suffix), (3, 1));
        // A kept line keeps its own time: the snapshot is as old as its oldest list.
        assert_eq!(both.fetched_unix_secs, 1_800_000_000);
        let lock = lock(root.path());
        let keys: Vec<&str> = lock
            .lines()
            .map(|line| line.split(' ').next().unwrap())
            .collect();
        assert_eq!(keys.len(), 2);
        assert!(keys.is_sorted(), "{keys:?}");
    }

    #[test]
    fn a_fetch_replaces_the_line_of_a_list_it_fetched_again() {
        let root = root_with_both_fetched();
        let newer: Vec<u8> = [HOSTS, b"0.0.0.0 one-more.example.com\n"].concat();

        fetch(
            root.path(),
            &urls(&[A]),
            1_800_090_000,
            &fake(&[(A, &newer)]),
        )
        .unwrap();

        let lock = lock(root.path());
        assert_eq!(lock.lines().count(), 2);
        let line_of = |url: &str| {
            lock.lines()
                .find(|line| line.starts_with(&url_key(url)))
                .unwrap()
                .to_owned()
        };
        assert_eq!(
            line_of(A),
            format!(
                "{} {} {} 1800090000",
                url_key(A),
                sha256_hex(&newer),
                newer.len()
            )
        );
        assert!(line_of(B).ends_with(" 1800000000"), "{}", line_of(B));
        snapshot(root.path(), &urls(&[A, B])).unwrap();
    }

    #[test]
    fn a_fetch_drops_the_line_of_a_list_whose_file_changed_or_is_gone() {
        let root = root_with_both_fetched();
        let c = "https://lists.example.com/c.txt";
        fetch(
            root.path(),
            &urls(&[c]),
            1_800_090_000,
            &fake(&[(c, HOSTS)]),
        )
        .unwrap();
        // Another checkout's list C is intact and kept; A was changed and B removed meanwhile.
        assert_eq!(lock(root.path()).lines().count(), 3);
        fs::write(cached(root.path(), A), b"0.0.0.0 changed.example.com\n").unwrap();
        fs::remove_file(cached(root.path(), B)).unwrap();

        fetch(
            root.path(),
            &urls(&[c]),
            1_800_180_000,
            &fake(&[(c, HOSTS)]),
        )
        .unwrap();

        let lock = lock(root.path());
        assert_eq!(lock.lines().count(), 1, "{lock}");
        assert!(lock.starts_with(&url_key(c)), "{lock}");
    }

    #[test]
    fn a_fetch_starts_over_from_a_lock_that_is_damaged_or_missing() {
        let root = root_with_both_fetched();
        fs::write(root.path().join(LOCK_FILE), "not a lock line\n").unwrap();

        // The fetch that the damaged lock asks for must be able to repair it.
        fetch(
            root.path(),
            &urls(&[A]),
            1_800_090_000,
            &fake(&[(A, HOSTS)]),
        )
        .unwrap();

        assert_eq!(lock(root.path()).lines().count(), 1);
        snapshot(root.path(), &urls(&[A])).unwrap();
        assert!(snapshot(root.path(), &urls(&[B])).is_err());

        fs::remove_file(root.path().join(LOCK_FILE)).unwrap();
        fetch(
            root.path(),
            &urls(&[B]),
            1_800_090_000,
            &fake(&[(B, ADBLOCK)]),
        )
        .unwrap();
        assert_eq!(lock(root.path()).lines().count(), 1);
    }

    #[test]
    fn writing_the_lock_leaves_no_temporary_file_and_uses_no_fixed_name() {
        let root = root_with_both_fetched();
        let dir = root.path().join(LIST_CACHE);
        // A file with the old fixed temporary name is somebody else's and is not touched.
        fs::write(dir.join("lock.new"), "theirs").unwrap();

        fetch(
            root.path(),
            &urls(&[A]),
            1_800_090_000,
            &fake(&[(A, HOSTS)]),
        )
        .unwrap();

        assert_eq!(fs::read(dir.join("lock.new")).unwrap(), b"theirs");
        let mut names = files_under(&dir);
        names.retain(|name| name != "lock.new");
        assert_eq!(names.len(), 3, "{names:?}");
    }

    #[test]
    fn the_lists_are_the_local_configurations_or_else_the_examples() {
        const EXAMPLE: &str = include_str!("../../qberrypi.example.toml");
        let example = qberrypi::config::parse(EXAMPLE).unwrap().dns.lists;
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("qberrypi.example.toml"), EXAMPLE).unwrap();

        // Only the example: its three URLs, and none of its threat lists.
        assert_eq!(configured_lists(root.path()).unwrap(), example);
        assert_eq!(example.len(), 3);

        // A local configuration beside it wins.
        fs::write(
            root.path().join("qberrypi.toml"),
            config_with(&format!("\"{A}\"")),
        )
        .unwrap();
        assert_eq!(configured_lists(root.path()).unwrap(), [A]);

        // One that does not parse is an error, and the error does not quote the file.
        fs::write(
            root.path().join("qberrypi.toml"),
            "passphrase = example-secret-passphrase\n[[[\n",
        )
        .unwrap();
        let error = format!("{:#}", configured_lists(root.path()).unwrap_err());
        assert!(!error.contains("example-secret"), "{error}");
        assert!(error.contains("qberrypi.toml"), "{error}");
    }
}
