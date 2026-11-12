//! The format of the snapshot: the block lists as they were when the image was built.
//!
//! `cargo xtask build` packs one text into the initramfs, compressed with zstd, at
//! [`SNAPSHOT_PATH`]. The text is the first line, a comment that says what the snapshot is (see
//! [`Header`]), then one hosts line (`0.0.0.0 name`) for each name to block as it stands, then
//! one `||name^` line for each name to block with its subdomains. Any list parser reads it, and
//! the line counts of the header are the counts of that text.

use std::fs;
use std::io::{self, Read as _};
use std::path::Path;
use std::str::FromStr;

use qb_dns::BlockSet;
use ruzstd::decoding::StreamingDecoder;

use super::{ListState, Source, from_config, names};

/// Where the initramfs holds the snapshot.
pub const SNAPSHOT_PATH: &str = "/blocklist.zst";

/// The most that a snapshot may unpack to: several times what the lists hold now, and a bound
/// on the memory that a file that is not one of ours can take.
pub const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
/// The window that a frame may always declare, however small the cap on its text.
const MIN_WINDOW_LIMIT: u64 = 1024 * 1024;

/// A name that every snapshot holds as an exact rule, so that a set built from a snapshot
/// blocks it whatever the lists say. It ends in `.invalid`, which no one can register.
pub const MARKER: &str = "qberrypi-snapshot.invalid";

/// The words of a header, in order, before its numbers.
const HEADER_WORDS: [&str; 3] = ["#", "qberrypi-snapshot", "1"];

/// What the first line of a snapshot says: when its lists were fetched, how many there were, and
/// how many rules of each kind the text holds, the [`MARKER`] among the exact ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// The clock of the machine that fetched the oldest of the lists, in seconds since 1970;
    /// 0 when there was no list.
    pub fetched_unix_secs: u64,
    /// How many lists were merged.
    pub lists: u32,
    /// How many hosts lines follow the header.
    pub exact: u32,
    /// How many `||name^` lines follow them.
    pub suffix: u32,
}

impl Header {
    /// The first line of the text, with its newline.
    pub fn line(&self) -> String {
        format!(
            "# qberrypi-snapshot 1 fetched={} lists={} exact={} suffix={}\n",
            self.fetched_unix_secs, self.lists, self.exact, self.suffix
        )
    }

    /// Reads the first line of a snapshot's text; `None` unless it is exactly the line that
    /// [`Header::line`] writes, version 1, newline included. Nothing after the line is looked at.
    pub fn parse(text: &[u8]) -> Option<Header> {
        let end = text.iter().position(|&byte| byte == b'\n')?;
        let line = std::str::from_utf8(&text[..end]).ok()?;
        let mut words = line.split(' ');
        for expected in HEADER_WORDS {
            if words.next()? != expected {
                return None;
            }
        }
        let header = Header {
            fetched_unix_secs: number(words.next()?, "fetched=")?,
            lists: number(words.next()?, "lists=")?,
            exact: number(words.next()?, "exact=")?,
            suffix: number(words.next()?, "suffix=")?,
        };
        words.next().is_none().then_some(header)
    }
}

/// Unpacks a zstd frame, at most `max_bytes` of it: more than that is `InvalidData`, and so is
/// anything that is not a frame, or a frame that declares a window of more than `max_bytes`, and
/// of more than 1 MiB (the decoder would reserve the window before it read a byte). The decoder takes any window that zstd's levels use, level 19's 8 MiB among them,
/// under the cap.
///
/// This holds the thread for as long as the unpacking takes: the caller is a blocking job.
pub fn unpack(zst: &[u8], max_bytes: usize) -> io::Result<Vec<u8>> {
    let invalid = |error: Box<dyn std::error::Error + Send + Sync>| {
        io::Error::new(io::ErrorKind::InvalidData, error)
    };
    // A small text may be in a frame with a bigger window: ruzstd's own encoder declares 128 KiB
    // for any input.
    let window = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .max(MIN_WINDOW_LIMIT);
    let decoder = StreamingDecoder::new_with_max_window_size(zst, window)
        .map_err(|error| invalid(error.into()))?;
    // One byte more than the cap is enough to show that the text is over it.
    let limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut text = Vec::new();
    decoder
        .take(limit)
        .read_to_end(&mut text)
        .map_err(|error| invalid(error.into()))?;
    if text.len() > max_bytes {
        return Err(invalid(
            format!("more than {max_bytes} bytes unpacked").into(),
        ));
    }
    Ok(text)
}

/// The block set that a boot starts with, and what it came from.
pub struct Loaded {
    /// The configuration's entries, and the snapshot's rules when there was one.
    pub set: BlockSet,
    /// `Snapshot` and the header's time when the snapshot was read; else `Config` and none.
    pub state: ListState,
    /// What was wrong with the snapshot, if anything. The text names no file's contents.
    pub problem: Option<String>,
}

/// Reads the snapshot at `path` into the set that starts from the configuration's `deny` and
/// `allow` entries. Never fails: a snapshot that cannot be read leaves the configuration's
/// entries alone and says why in `problem`. Rules whose counts differ from the header's are
/// used all the same, and `problem` says so.
///
/// Reading, unpacking and building take a while on the board: the caller is a blocking job.
pub fn load(path: &Path, deny: &[String], allow: &[String]) -> Loaded {
    let mut builder = from_config(deny, allow);
    let read = fs::read(path)
        .and_then(|zst| unpack(&zst, MAX_SNAPSHOT_BYTES))
        .map_err(|error| error.to_string())
        .and_then(|text| {
            Header::parse(&text)
                .map(|header| (header, text))
                .ok_or_else(|| "no snapshot header".to_owned())
        });
    let (source, fetched_unix_secs, problem) = match read {
        Ok((header, text)) => {
            let stats = builder.add_list(&text);
            let (says_exact, says_suffix) = (header.exact as usize, header.suffix as usize);
            let problem = (stats.exact != says_exact || stats.suffix != says_suffix).then(|| {
                format!(
                    "{} exact and {} suffix rules, the header says {says_exact} and {says_suffix}",
                    stats.exact, stats.suffix
                )
            });
            (Source::Snapshot, Some(header.fetched_unix_secs), problem)
        }
        Err(problem) => (Source::Config, None, Some(problem)),
    };
    let set = builder.build();
    Loaded {
        state: ListState {
            source,
            names: names(&set),
            fetched_unix_secs,
            last_error: None,
        },
        set,
        problem,
    }
}

/// What `load` gives when there is no snapshot to read: the configuration's entries, and
/// `problem` as the reason.
pub fn config_only(deny: &[String], allow: &[String], problem: String) -> Loaded {
    let set = from_config(deny, allow).build();
    Loaded {
        state: ListState {
            source: Source::Config,
            names: names(&set),
            fetched_unix_secs: None,
            last_error: None,
        },
        set,
        problem: Some(problem),
    }
}

/// The digits after `key` in `word`, as a number; no sign, no space, nothing else.
fn number<T: FromStr>(word: &str, key: &str) -> Option<T> {
    let digits = word.strip_prefix(key)?;
    if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write as _;

    use ruzstd::encoding::{CompressionLevel, compress_to_vec};

    #[test]
    fn the_header_is_one_comment_line_and_reads_back() {
        let h = Header {
            fetched_unix_secs: 1_800_000_000,
            lists: 2,
            exact: 3,
            suffix: 2,
        };
        assert_eq!(
            h.line(),
            "# qberrypi-snapshot 1 fetched=1800000000 lists=2 exact=3 suffix=2\n"
        );
        assert_eq!(
            Header::parse(format!("{}0.0.0.0 ads.example.com\n", h.line()).as_bytes()),
            Some(h)
        );
        for bad in [
            "",
            "0.0.0.0 ads.example.com\n",
            "# qberrypi-snapshot 2 fetched=1 lists=1 exact=1 suffix=1\n",
            "# qberrypi-snapshot 1 fetched=1 lists=1 exact=1\n",
            "# qberrypi-snapshot 1 fetched=x lists=1 exact=1 suffix=1\n",
        ] {
            assert_eq!(Header::parse(bad.as_bytes()), None, "{bad:?}");
        }
    }
    #[test]
    fn only_the_line_the_header_writes_is_a_header() {
        let line = "# qberrypi-snapshot 1 fetched=1 lists=1 exact=1 suffix=1";
        assert!(Header::parse(format!("{line}\n").as_bytes()).is_some());
        for bad in [
            // Cut off before its newline, so a number may be cut short too.
            line.to_owned(),
            format!("{line} extra=1\n"),
            format!("{line}  \n"),
            format!("{line}\r\n"),
            // Another order, another sign, no digits, too many digits for the field.
            "# qberrypi-snapshot 1 lists=1 fetched=1 exact=1 suffix=1\n".to_owned(),
            "# qberrypi-snapshot 1 fetched=+1 lists=1 exact=1 suffix=1\n".to_owned(),
            "# qberrypi-snapshot 1 fetched= lists=1 exact=1 suffix=1\n".to_owned(),
            "# qberrypi-snapshot 1 fetched=1 lists=4294967296 exact=1 suffix=1\n".to_owned(),
            // The header is the first line, not a line somewhere in the text.
            format!("0.0.0.0 ads.example.com\n{line}\n"),
        ] {
            assert_eq!(Header::parse(bad.as_bytes()), None, "{bad:?}");
        }
        assert_eq!(
            Header::parse(b"# qberrypi-snapshot 1 fetched=1 lists=1 exact=1 suffix=1\n\xff"),
            Some(Header {
                fetched_unix_secs: 1,
                lists: 1,
                exact: 1,
                suffix: 1
            })
        );
    }

    const TEXT: &str = "# qberrypi-snapshot 1 fetched=1800000000 lists=2 exact=2 suffix=1\n\
                        0.0.0.0 ads.example.com\n0.0.0.0 qberrypi-snapshot.invalid\n||tracker.example.net^\n";

    fn packed(text: &str) -> Vec<u8> {
        compress_to_vec(text.as_bytes(), CompressionLevel::Fastest)
    }

    fn file(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(bytes).unwrap();
        file
    }

    fn load_from(bytes: &[u8]) -> Loaded {
        load(
            file(bytes).path(),
            &["denied.example.org".into()],
            &["ok.tracker.example.net".into()],
        )
    }

    #[test]
    fn a_snapshot_is_loaded_together_with_the_configurations_names() {
        let l = load_from(&packed(TEXT));
        assert_eq!(l.problem, None);
        assert_eq!(
            l.state,
            ListState {
                source: Source::Snapshot,
                names: 4,
                fetched_unix_secs: Some(1_800_000_000),
                last_error: None
            }
        );
        for blocked in [
            "ads.example.com",
            MARKER,
            "x.tracker.example.net",
            "denied.example.org",
        ] {
            assert!(l.set.is_blocked(blocked), "{blocked}");
        }
        for open in ["ok.tracker.example.net", "example.com"] {
            assert!(!l.set.is_blocked(open), "{open}");
        }
    }

    #[test]
    fn a_snapshot_that_is_missing_or_broken_leaves_the_configurations_names_and_says_why() {
        let missing = load(
            Path::new("/nonexistent/blocklist.zst"),
            &["denied.example.org".into()],
            &[],
        );
        let not_zstd = load_from(b"this is not zstd");
        let no_header = load_from(&packed("0.0.0.0 ads.example.com\n"));
        for l in [missing, not_zstd, no_header] {
            assert!(l.problem.is_some());
            assert_eq!(
                (l.state.source, l.state.names, l.state.fetched_unix_secs),
                (Source::Config, 1, None)
            );
            assert!(l.set.is_blocked("denied.example.org") && !l.set.is_blocked("ads.example.com"));
        }
    }

    #[test]
    fn counts_that_differ_from_the_header_are_reported_and_the_names_are_used() {
        let l = load_from(&packed(&TEXT.replace("exact=2", "exact=5")));
        assert_eq!(
            l.problem.as_deref(),
            Some("2 exact and 1 suffix rules, the header says 5 and 1")
        );
        assert_eq!(l.state.source, Source::Snapshot);
        assert!(l.set.is_blocked("ads.example.com"));
    }

    // Final review T13: the decoder's own window limit is 128 MiB.
    #[test]
    fn a_frame_that_declares_a_window_over_the_cap_is_refused_before_it_is_unpacked() {
        /// An empty zstd frame: the magic, a header with a window descriptor and nothing else, and
        /// one last raw block of no bytes.
        fn empty_frame(window_descriptor: u8) -> Vec<u8> {
            vec![
                0x28,
                0xb5,
                0x2f,
                0xfd,
                0x00,
                window_descriptor,
                0x01,
                0x00,
                0x00,
            ]
        }
        // The window is 1 KiB, and the frame is fine.
        assert_eq!(unpack(&empty_frame(0x00), MAX_SNAPSHOT_BYTES).unwrap(), b"");
        // 64 MiB (exponent 16) is the cap exactly, and passes.
        assert_eq!(unpack(&empty_frame(0x80), MAX_SNAPSHOT_BYTES).unwrap(), b"");
        // 64 MiB and seven eighths of it again, 120 MiB: under the decoder's own limit, over the
        // cap, and nothing a snapshot of at most the cap needs.
        assert_eq!(
            unpack(&empty_frame(0x87), MAX_SNAPSHOT_BYTES)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        // A small cap lets a frame declare a window of up to 1 MiB (exponent 10), and no more.
        assert_eq!(unpack(&empty_frame(0x50), 24_000).unwrap(), b"");
        assert_eq!(
            unpack(&empty_frame(0x58), 24_000).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn unpacking_stops_at_the_cap() {
        let big = packed(&"0.0.0.0 ads.example.com\n".repeat(1000));
        assert_eq!(unpack(&big, 24_000).unwrap().len(), 24_000);
        assert_eq!(
            unpack(&big, 23_999).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
