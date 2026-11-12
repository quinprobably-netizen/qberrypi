#![allow(dead_code)]
// A loader for what tests/captures.rs replays: frames, elements, addresses and keys of two published handshake
// captures. The capture bytes are deliberately not in this repository. The captures are other people's files (one
// comes from a GPL-2.0 repository, the other has no clear licence), so `fetch_captures.py`, beside this file,
// downloads them, checks their pinned SHA-256 and writes the byte strings to a git-ignored file that is read
// here at run time. The command that produces it, from the repository root:
//
//     python3 -I crates/qb-wpa2/tests/fixtures/fetch_captures.py

use std::fs;

/// The command that downloads the captures and writes `frames.txt`.
pub const FETCH_COMMAND: &str = "python3 -I crates/qb-wpa2/tests/fixtures/fetch_captures.py";

/// Where `fetch_captures.py` writes: lines of a name, one space and lower-case hex, and `#` comments.
const FRAMES_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vendor-cache/captures/frames.txt"
);

/// The named byte strings of `vendor-cache/captures/frames.txt`.
pub struct Captures {
    /// Every entry of the file, in its order.
    entries: Vec<(String, Vec<u8>)>,
}

impl Captures {
    /// Reads `frames.txt`; panics with a message naming `FETCH_COMMAND` if it is absent or malformed.
    pub fn load() -> Self {
        let text = fs::read_to_string(FRAMES_PATH).unwrap_or_else(|error| {
            panic!(
                "cannot read {FRAMES_PATH} ({error}): run `{FETCH_COMMAND}` from the repository root first"
            )
        });
        let entries = text
            .lines()
            .enumerate()
            .filter(|(_, line)| !line.starts_with('#'))
            .map(|(index, line)| {
                parse_line(line).unwrap_or_else(|| {
                    panic!(
                        "line {} of {FRAMES_PATH} is malformed: run `{FETCH_COMMAND}` from the repository root again",
                        index + 1
                    )
                })
            })
            .collect();
        Self { entries }
    }

    /// The bytes recorded under `name`, for example "linksys.M1"; panics if the name is missing.
    pub fn bytes(&self, name: &str) -> &[u8] {
        self.entries
            .iter()
            .find(|(entry, _)| entry == name)
            .map(|(_, bytes)| bytes.as_slice())
            .unwrap_or_else(|| {
                panic!(
                    "{FRAMES_PATH} has no entry {name}: run `{FETCH_COMMAND}` from the repository root again"
                )
            })
    }

    /// The same as a fixed-size array; panics if the length differs.
    pub fn array<const N: usize>(&self, name: &str) -> [u8; N] {
        let bytes = self.bytes(name);
        bytes.try_into().unwrap_or_else(|_| {
            panic!(
                "{name} in {FRAMES_PATH} is {} bytes long, not {N}",
                bytes.len()
            )
        })
    }
}

/// The name and the bytes of one line, or `None` if it is not a name, one space and lower-case hex.
fn parse_line(line: &str) -> Option<(String, Vec<u8>)> {
    let (name, hex) = line.split_once(' ')?;
    // Pairs of digits, and no digit left over.
    let (pairs, []) = hex.as_bytes().as_chunks::<2>() else {
        return None;
    };
    let bytes = pairs
        .iter()
        .map(|&[high, low]| Some(nibble(high)? << 4 | nibble(low)?))
        .collect::<Option<Vec<u8>>>()?;
    (!name.is_empty()).then(|| (name.to_owned(), bytes))
}

/// The value of one lower-case hex digit.
fn nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}
