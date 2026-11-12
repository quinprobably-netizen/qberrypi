//! The update receiver: `POST /api/qbp/update` takes one build as the body of one request, writes
//! it to the slot that is not running, proves it from the card, and stages it for the next start.
//!
//! The route is behind the login and is the only one whose body is streamed: the connection
//! checks the session from the head, before a byte of the body is read, and hands the stream to
//! [`Receiver::receive`] with bounds of its own ([`crate::api::Limits`]: 64 MiB, ten minutes from
//! the head, 30 s for each read). Everything here runs on the API connection's thread of the
//! blocking pool, as every API request does, holds no lock of the resolver, and keeps clear of
//! any other use of the card through init's claim ([`crate::update::BootCard`]).
//!
//! # The body
//!
//! A 4-byte big-endian length `N`, the manifest as `N` bytes of JSON, then the eleven files'
//! bytes one after another in the manifest's order, which is [`BODY_ORDER`]: `cmdline.txt` and
//! `config.txt` first, each at most [`MAX_TEXT`] bytes and held in memory, then the other nine in
//! the order of [`slots::SLOT_FILES`]. Anything else is refused. So the slot's name and the boot
//! files' digest are judged from the two text files before one byte of the rest reaches the card.
//! The manifest ([`Manifest`], at most [`MAX_MANIFEST`] bytes):
//!
//! ```json
//! {"build": 1794470000, "slot": "b", "mode": "tryboot", "force": false, "allow_kernel": false,
//!  "files": [{"name": "cmdline.txt", "size": 97, "sha256": "<64 lower-case hex digits>"}, ...]}
//! ```
//!
//! `mode` is `"tryboot"` (the firmware's trial) or `"software"`; `force` and `allow_kernel` may be
//! left out, and are then `false`; no other key is taken. `files` is exactly the eleven names, in the
//! body's order, and the sizes add up, with the manifest and its length, to the request's
//! `Content-Length`. [`Manifest::of_files`], [`Manifest::head`] and [`Manifest::content_length`]
//! make exactly these bytes, so a sender is tested against this parser.
//!
//! # What is refused, and how
//!
//! Every refusal is Pi-hole's error shape (`{"error": {"key", "message", "hint"}}`) with nothing
//! written to the card beyond what the step it came in had begun, and nothing selected. No
//! message repeats a byte or a name from the body; the names that appear are the fixed ones of the
//! eleven files.
//!
//! | Status | Key | When |
//! | --- | --- | --- |
//! | 401 | `unauthorized` | no valid session (the connection's, before any body byte) |
//! | 405 | `method_not_allowed` | another method on the path (the API's) |
//! | 413 | `payload_too_large` | `Content-Length` over [`UPLOAD_CAP`] |
//! | 409 | `no_slots` | the card has no slots (the old layout) |
//! | 409 | `update_busy` | an update is being received or staged, or this boot is on trial |
//! | 400 | `bad_request` | the body is not the format above; a text file that does not name the slot; the body stops arriving or ends early |
//! | 409 | `wrong_slot` | `slot` is the running one |
//! | 409 | `not_newer` | `build` is not newer than the running build, and no `force` |
//! | 409 | `kernel_change` | the boot files' digest is not the running build's, and no `allow_kernel` |
//! | 422 | `hash_mismatch` | a file's SHA-256, as it arrives or as it is read back from the card, is not the manifest's |
//! | 500 | `internal` | the card cannot be used or written |
//!
//! The checks run in this order: the length in the head, the machinery (no slots, busy), the
//! manifest, the slot, the build, the two text files, the boot files' digest, and last the card.
//!
//! # The writes, in order
//!
//! 1. One writable claim of the card: refuses (409 `wrong_slot`) if the card's `config.txt` selects
//!    the slot that is to be written, which a power cut would leave unbootable; empties
//!    `qberrypi-<slot>/`, writes the eleven files into it while hashing what arrives (a file whose
//!    hash is not the manifest's stops the update there), syncs, unmounts.
//! 2. One read-only claim: a fresh mount, so the bytes come from the card and not the page cache,
//!    and each of the eleven files is read and hashed again.
//! 3. One writable claim. In `tryboot` mode: `tryboot.txt` ([`slots::stage_tryboot`]), then the
//!    marker ([`slots::write_marker`]). In `software` mode the marker first, on the card, and
//!    then `config.txt` ([`slots::select`]): a selection with no marker would boot the new slot as
//!    a normal start, with no trial and no way back, and a power cut between the two writes this
//!    way round leaves a marker naming a slot that nothing selects, which a boot reports as a
//!    rollback. If the selection fails, the old selection is put back and the marker deleted.
//!
//! Then the reply is a 200, `{"staged": true, "slot": "b", "build": N}`. It is written and
//! flushed before the restart is asked for, and the restart is asked for [`RESTART_AFTER`] later,
//! from a timer of the runtime, never from a thread that waits: [`Received::send_then_restart`].
//! The machinery stays taken from the staging on ([`crate::update::Receiving::staged`]), so no
//! second update is received in that second.
//!
//! # Logs
//!
//! One line at the start (build, slot, how many files, how many bytes) and one for the outcome or
//! the refusal's reason; never a file's bytes, a name from `qberrypi.toml`, or a client address.
//! The log is open to the network, and these lines are only made for a request that has a valid
//! session.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::api::http::{Head, Reply};
use crate::api::routes::{error_with, ok};
use crate::bootpart::ACTIVE_CONFIG;
use crate::slots::{self, Marker, Mode, Select, Slot};
use crate::update::{CardAccess, Cause, Restart, UpdateCtl};

/// The path of the route, which the connection recognises from the head.
pub const PATH: &str = "/api/qbp/update";

/// The most bytes a body may take: 64 MiB. A longer `Content-Length` is a 413 and nothing is read.
pub const UPLOAD_CAP: u64 = 64 * 1024 * 1024;

/// The most bytes the manifest may take.
pub const MAX_MANIFEST: usize = 16 * 1024;

/// The most bytes `cmdline.txt` and `config.txt` may take each; they are held in memory.
pub const MAX_TEXT: usize = 4 * 1024;

/// How long after the reply was flushed the restart is asked for.
pub const RESTART_AFTER: Duration = Duration::from_secs(1);

/// The eleven files in the order the body carries them: the two text files that name the slot, then
/// the other nine in the order of [`slots::SLOT_FILES`].
pub const BODY_ORDER: [&str; 11] = [
    "cmdline.txt",
    "config.txt",
    "kernel8.img",
    "bcm2710-rpi-3-b-plus.dtb",
    "initramfs8",
    "ov-README",
    "ov-overlay_map.dtb",
    "ov-qb-piscreen.dtbo",
    "ov-disable-bt.dtbo",
    "qberrypi.toml",
    "tls.pem",
];

/// How many of [`BODY_ORDER`]'s first files are the text files, which are held in memory.
const TEXTS: usize = 2;

/// The bytes that are read, written and hashed at a time.
const CHUNK: usize = 64 * 1024;

/// One file of the manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileEntry {
    /// The file's name: one of [`BODY_ORDER`].
    pub name: String,
    /// The file's length in bytes.
    pub size: u64,
    /// The SHA-256 of the file's bytes, as 64 lower-case hex digits.
    pub sha256: String,
}

/// The manifest at the front of an update's body: see the module's text for its JSON.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    /// The build's time in Unix seconds, which the running build is compared with.
    pub build: u64,
    /// The slot the files are for, which must be the one that is not running.
    pub slot: Slot,
    /// How the trial is started: by the firmware's `tryboot`, or by the software trial.
    pub mode: Mode,
    /// Take a build that is not newer than the running one.
    pub force: bool,
    /// Take a build whose boot files differ from the running one's.
    pub allow_kernel: bool,
    /// The eleven files, in [`BODY_ORDER`].
    pub files: Vec<FileEntry>,
}

impl Manifest {
    /// The manifest of `files`, which are all eleven of [`BODY_ORDER`] by name, once each, in any
    /// order: their sizes and SHA-256 are taken from the bytes, and the entries are put in the
    /// body's order. `force` and `allow_kernel` are `false`; a sender sets them after.
    ///
    /// An error, in words, for a name that is not one of the eleven, or given twice, or missing.
    pub fn of_files(
        build: u64,
        slot: Slot,
        mode: Mode,
        files: &[(&str, &[u8])],
    ) -> Result<Manifest, String> {
        let mut entries = Vec::with_capacity(BODY_ORDER.len());
        for name in BODY_ORDER {
            let mut named = files.iter().filter(|(given, _)| *given == name);
            let (Some((_, bytes)), None) = (named.next(), named.next()) else {
                return Err(format!("{name} must be given exactly once"));
            };
            entries.push(FileEntry {
                name: name.to_owned(),
                size: bytes.len() as u64,
                sha256: sha256_hex(bytes),
            });
        }
        if let Some((name, _)) = files.iter().find(|(name, _)| !BODY_ORDER.contains(name)) {
            return Err(format!("{name} is not a slot file"));
        }
        Ok(Manifest {
            build,
            slot,
            mode,
            force: false,
            allow_kernel: false,
            files: entries,
        })
    }

    /// The manifest as the JSON text that goes in the body.
    pub fn to_json(&self) -> Vec<u8> {
        let files: Vec<Value> = self
            .files
            .iter()
            .map(|file| json!({ "name": file.name, "size": file.size, "sha256": file.sha256 }))
            .collect();
        let manifest = json!({
            "build": self.build,
            "slot": self.slot.letter(),
            "mode": self.mode.word(),
            "force": self.force,
            "allow_kernel": self.allow_kernel,
            "files": files,
        });
        // A `Value` of strings, numbers and booleans always serialises.
        serde_json::to_vec(&manifest).unwrap_or_default()
    }

    /// The first bytes of the body: the manifest's length as 4 bytes, big-endian, and the
    /// manifest. The files' bytes follow, in [`BODY_ORDER`]. An error if the manifest is over
    /// [`MAX_MANIFEST`] bytes.
    pub fn head(&self) -> Result<Vec<u8>, String> {
        let json = self.to_json();
        if json.len() > MAX_MANIFEST {
            return Err(format!("the manifest is over {MAX_MANIFEST} bytes"));
        }
        let mut head = Vec::with_capacity(4 + json.len());
        // `json` is at most `MAX_MANIFEST`, which fits 32 bits.
        head.extend_from_slice(&(json.len() as u32).to_be_bytes());
        head.extend_from_slice(&json);
        Ok(head)
    }

    /// The `Content-Length` of the body: [`Manifest::head`] and the files' sizes. An error if the
    /// manifest is too long, or the body is over [`UPLOAD_CAP`].
    pub fn content_length(&self) -> Result<u64, String> {
        let total = self
            .files
            .iter()
            .try_fold(self.head()?.len() as u64, |sum, file| {
                sum.checked_add(file.size)
            })
            .filter(|&total| total <= UPLOAD_CAP);
        total.ok_or_else(|| format!("the body is over {UPLOAD_CAP} bytes"))
    }

    /// Reads a manifest from its JSON text, and judges its shape: an object with `build` (a whole
    /// number), `slot` (`"a"` or `"b"`), `mode`, optionally `force` and `allow_kernel` (booleans),
    /// and `files`, exactly the eleven of [`BODY_ORDER`], each with `name`, `size` (a whole number)
    /// and `sha256` (64 lower-case hex digits) and nothing else; the two text files at most
    /// [`MAX_TEXT`] bytes. Any other key, anywhere, is an error.
    ///
    /// The error is a fixed sentence that quotes nothing from the text. That the sizes add up to
    /// the body's length is for the caller, which knows the length.
    pub fn parse(json: &[u8]) -> Result<Manifest, &'static str> {
        let Ok(Value::Object(mut fields)) = serde_json::from_slice::<Value>(json) else {
            return Err("the manifest is not a JSON object");
        };
        let build = fields
            .remove("build")
            .and_then(|value| value.as_u64())
            .ok_or("the manifest has no build, as a whole number")?;
        let slot = match fields.remove("slot") {
            Some(Value::String(letter)) => Slot::from_letter(&letter),
            _ => None,
        }
        .ok_or("the manifest's slot is not a or b")?;
        let mode = match fields.remove("mode") {
            Some(Value::String(word)) => Mode::from_word(&word),
            _ => None,
        }
        .ok_or("the manifest's mode is not tryboot or software")?;
        let force = flag(
            fields.remove("force"),
            "the manifest's force is not true or false",
        )?;
        let allow_kernel = flag(
            fields.remove("allow_kernel"),
            "the manifest's allow_kernel is not true or false",
        )?;
        let Some(Value::Array(listed)) = fields.remove("files") else {
            return Err("the manifest has no list of files");
        };
        if !fields.is_empty() {
            return Err("the manifest has a key that this server does not take");
        }
        if listed.len() != BODY_ORDER.len() {
            return Err("the manifest must list the eleven slot files and no others");
        }
        let mut files = Vec::with_capacity(listed.len());
        for (value, expected) in listed.into_iter().zip(BODY_ORDER) {
            let Value::Object(mut entry) = value else {
                return Err("a file of the manifest is not an object");
            };
            let name = match entry.remove("name") {
                Some(Value::String(name)) if name == expected => name,
                _ => return Err("the manifest's files are not the slot files in the body's order"),
            };
            let size = entry
                .remove("size")
                .and_then(|value| value.as_u64())
                .ok_or("a file of the manifest has no size, as a whole number")?;
            let sha256 = match entry.remove("sha256") {
                Some(Value::String(hash)) if is_hash(&hash) => hash,
                _ => {
                    return Err(
                        "a file of the manifest has no SHA-256 of 64 lower-case hex digits",
                    );
                }
            };
            if !entry.is_empty() {
                return Err("a file of the manifest has a key that this server does not take");
            }
            if BODY_ORDER[..TEXTS].contains(&expected) && size > MAX_TEXT as u64 {
                return Err("cmdline.txt and config.txt are at most 4 KiB each");
            }
            files.push(FileEntry { name, size, sha256 });
        }
        Ok(Manifest {
            build,
            slot,
            mode,
            force,
            allow_kernel,
            files,
        })
    }
}

/// A boolean of the manifest that may be left out (`false`).
fn flag(value: Option<Value>, otherwise: &'static str) -> Result<bool, &'static str> {
    match value {
        None => Ok(false),
        Some(Value::Bool(flag)) => Ok(flag),
        Some(_) => Err(otherwise),
    }
}

/// Whether `text` is a SHA-256 as the manifest writes it: 64 lower-case hex digits.
fn is_hash(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The SHA-256 of `bytes`, as 64 lower-case hex digits.
fn sha256_hex(bytes: &[u8]) -> String {
    slots::hex(&Sha256::digest(bytes))
}

/// Why an update is refused: the status, the key and the words of the error that answers it.
#[derive(Debug, PartialEq, Eq)]
struct Refusal {
    status: u16,
    key: &'static str,
    message: String,
}

impl Refusal {
    fn new(status: u16, key: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            key,
            message: message.into(),
        }
    }

    /// A 400: the body is not what the route takes.
    fn bad(message: impl Into<String>) -> Self {
        Self::new(400, "bad_request", message)
    }

    /// A 409 with `key`.
    fn conflict(key: &'static str, message: impl Into<String>) -> Self {
        Self::new(409, key, message)
    }

    /// A 422: a file is not the one the manifest names.
    fn mismatch(name: &str, when: &str) -> Self {
        Self::new(
            422,
            "hash_mismatch",
            format!("{name} does not match its SHA-256 {when}"),
        )
    }

    /// A 500: the card could not be used.
    fn card(message: &'static str) -> Self {
        Self::new(500, "internal", message)
    }

    /// The body stopped arriving (a stall, a close or the time) or ended before the manifest's
    /// sizes were all there.
    fn stopped() -> Self {
        Self::bad("the update's body stopped arriving, or ended before its files did")
    }

    /// The line the log gets for the refusal.
    fn log_line(&self) -> String {
        format!("update: refused ({}): {}", self.key, self.message)
    }

    /// The error that answers it.
    fn reply(&self, began: Instant) -> Reply {
        error_with(self.status, self.key, &self.message, began)
    }
}

/// What a received update did: the answer for the client, and the restart to ask for once the
/// answer has been written.
#[must_use = "the reply is to be sent, and the restart asked for after it"]
pub struct Received {
    reply: Reply,
    restart: Option<(Arc<UpdateCtl>, Restart)>,
}

impl Received {
    /// The answer to the request.
    pub fn reply(&self) -> &Reply {
        &self.reply
    }

    /// Whether the update was staged and the board is going to restart.
    pub fn staged(&self) -> bool {
        self.restart.is_some()
    }

    /// Sends the reply with `send`, which writes and flushes it, and then, whether that worked
    /// or not (the update is staged either way), asks for the restart [`RESTART_AFTER`] later,
    /// from a timer of the runtime, so that no thread waits. Returns what `send` returned.
    ///
    /// With no runtime to put the timer on (which no board has), the restart is asked for at once.
    pub fn send_then_restart(self, send: impl FnOnce(&Reply) -> io::Result<()>) -> io::Result<()> {
        let sent = send(&self.reply);
        if let Some((ctl, restart)) = self.restart {
            match tokio::runtime::Handle::try_current() {
                Ok(runtime) => {
                    runtime.spawn(async move {
                        tokio::time::sleep(RESTART_AFTER).await;
                        ctl.request_restart(restart);
                    });
                }
                Err(_) => {
                    ctl.request_restart(restart);
                }
            }
        }
        sent
    }
}

/// The update receiver: the shared state of the update machinery and the running build's time.
pub struct Receiver {
    ctl: Arc<UpdateCtl>,
    running_build: u64,
}

/// An update that is on the card and staged.
struct Staged {
    slot: Slot,
    build: u64,
    mode: Mode,
}

impl Receiver {
    /// A receiver over `ctl`, whose card it writes, for a running build made at `running_build`
    /// (Unix seconds, `crate::BUILD_EPOCH` on the board).
    pub fn new(ctl: Arc<UpdateCtl>, running_build: u64) -> Self {
        Self { ctl, running_build }
    }

    /// Takes the update that `head` announces from `body`, which is the request's stream, and
    /// answers it. Blocks for as long as it takes to read and write the files, so it is called
    /// from a thread of the blocking pool; the bounds on `body`'s reads are the caller's.
    ///
    /// At most `head.length` bytes are read from `body`, and none if the length is over
    /// [`UPLOAD_CAP`]. The session was checked by the caller. Whatever happens, the machinery is
    /// given back, unless the update was staged.
    pub fn receive(&self, head: &Head, body: &mut impl Read) -> Received {
        let began = Instant::now();
        match self.take(head, body) {
            Ok(staged) => {
                log::info!("{}", staged_line(&staged));
                let restart = match staged.mode {
                    Mode::Tryboot => Restart::Tryboot,
                    Mode::Software => Restart::Plain(Cause::Update),
                };
                Received {
                    reply: ok(
                        json!({ "staged": true, "slot": staged.slot.letter(), "build": staged.build }),
                        began,
                    ),
                    restart: Some((self.ctl.clone(), restart)),
                }
            }
            Err(refusal) => {
                log::warn!("{}", refusal.log_line());
                Received {
                    reply: refusal.reply(began),
                    restart: None,
                }
            }
        }
    }

    /// The whole of an update, to the staging, or why it is refused.
    fn take(&self, head: &Head, body: &mut impl Read) -> Result<Staged, Refusal> {
        if head.length > UPLOAD_CAP {
            return Err(Refusal::new(
                413,
                "payload_too_large",
                "the update is over 64 MiB",
            ));
        }
        let receiving = self.ctl.begin_receive().map_err(|why| match why {
            crate::update::Refused::NoSlots => Refusal::conflict(
                "no_slots",
                "this card has no slots, so there is nothing to update",
            ),
            crate::update::Refused::Busy => Refusal::conflict(
                "update_busy",
                "an update is being received or staged, or a trial is under way",
            ),
        })?;
        let mut body = body.take(head.length);

        let manifest = read_manifest(&mut body, head.length)?;
        log::info!("{}", start_line(&manifest, head.length));
        let Some(running) = self.ctl.slot() else {
            // `begin_receive` refuses a boot with no slot, so this cannot be reached.
            return Err(Refusal::conflict("no_slots", "this card has no slots"));
        };
        if manifest.slot != running.other() {
            return Err(Refusal::conflict(
                "wrong_slot",
                "the update is for the slot that is running; it must be for the other",
            ));
        }
        if manifest.build <= self.running_build && !manifest.force {
            return Err(Refusal::conflict(
                "not_newer",
                "the update is not newer than the running build",
            ));
        }

        let texts = read_texts(&mut body, &manifest)?;
        if !manifest.allow_kernel {
            self.check_boot_files(&manifest, &texts)?;
        }

        self.write_slot(&manifest, &texts, &mut body)?;
        self.verify_slot(&manifest)?;
        self.stage(&manifest, running)?;

        receiving.staged();
        Ok(Staged {
            slot: manifest.slot,
            build: manifest.build,
            mode: manifest.mode,
        })
    }

    /// Refuses an update whose boot files are not the running build's: the digest of the files
    /// that the manifest names (the two text files in their slot-a form, from their bytes, which
    /// are in memory) must be the one the running build has.
    fn check_boot_files(
        &self,
        manifest: &Manifest,
        texts: &[Vec<u8>; TEXTS],
    ) -> Result<(), Refusal> {
        let mut hashes: Vec<(&str, String)> = Vec::with_capacity(manifest.files.len());
        for (index, file) in manifest.files.iter().enumerate() {
            let hash = match texts.get(index) {
                Some(bytes) => {
                    let form = slots::slot_a_form(&file.name, bytes).map_err(Refusal::bad)?;
                    sha256_hex(&form)
                }
                None => file.sha256.clone(),
            };
            hashes.push((&file.name, hash));
        }
        let digest = slots::boot_files_digest_of_hashes(
            hashes.iter().map(|(name, hash)| (*name, hash.as_str())),
        )
        .map_err(|_| Refusal::bad("the boot files' digest could not be made"))?;
        match self.ctl.boot_files() {
            Some(running) if running == digest => Ok(()),
            Some(_) => Err(Refusal::conflict(
                "kernel_change",
                "the update changes the boot files (kernel, device tree, overlays, command line or config.txt); send it with allow_kernel to take it",
            )),
            None => Err(Refusal::conflict(
                "kernel_change",
                "the running build cannot tell its boot files, so the update cannot be shown to leave them alone; send it with allow_kernel to take it",
            )),
        }
    }

    /// One use of the card as `access` says: runs `work` on the directory where the boot
    /// partition is mounted, and gives what it returns.
    fn on_card<T>(
        &self,
        access: CardAccess,
        mut work: impl FnMut(&Path) -> Result<T, Refusal>,
    ) -> Result<T, Refusal> {
        let mut done = None;
        let used = self
            .ctl
            .card()
            .with_boot(access, &mut |dir| done = Some(work(dir)));
        if let Err(error) = used {
            log::warn!("update: the card could not be used: {error}");
            return Err(Refusal::card("the card could not be used"));
        }
        done.unwrap_or_else(|| Err(Refusal::card("the card could not be used")))
    }

    /// Step 1: empties the slot's folder and writes the eleven files into it, the two text files
    /// from memory and the rest from `body`, hashing what arrives.
    fn write_slot(
        &self,
        manifest: &Manifest,
        texts: &[Vec<u8>; TEXTS],
        body: &mut impl Read,
    ) -> Result<(), Refusal> {
        let folder = manifest.slot.dir();
        let mut buffer = vec![0u8; CHUNK];
        self.on_card(CardAccess::Writable, |boot| {
            // Never empty the slot that the card would boot from: a power cut would leave it
            // broken. The running slot is the one `config.txt` selects, bar a trial.
            let config = fs::read(boot.join(ACTIVE_CONFIG));
            if config.is_ok_and(|config| slots::selected_slot(&config) == Ok(manifest.slot)) {
                return Err(Refusal::conflict(
                    "wrong_slot",
                    "the card's config.txt selects the slot that the update is for, so it is not overwritten",
                ));
            }
            let folder = boot.join(folder);
            empty_folder(&folder).map_err(|error| card_failed("emptying the slot", &error))?;
            for (index, file) in manifest.files.iter().enumerate() {
                let mut out = File::create_new(folder.join(&file.name))
                    .map_err(|error| card_failed("creating a file", &error))?;
                let written = match texts.get(index) {
                    Some(bytes) => out.write_all(bytes),
                    None => stream(body, &mut out, file, &mut buffer)?,
                };
                written
                    .and_then(|()| out.sync_all())
                    .map_err(|error| card_failed("writing a file", &error))?;
            }
            File::open(&folder)
                .and_then(|dir| dir.sync_all())
                .map_err(|error| card_failed("syncing the slot", &error))
        })
    }

    /// Step 2: mounts the card afresh, read-only, and reads and hashes every file of the slot.
    fn verify_slot(&self, manifest: &Manifest) -> Result<(), Refusal> {
        let folder = manifest.slot.dir();
        let mut buffer = vec![0u8; CHUNK];
        self.on_card(CardAccess::ReadOnly, |boot| {
            for file in &manifest.files {
                let read = File::open(boot.join(folder).join(&file.name))
                    .and_then(|mut found| hash_of(&mut found, file.size, &mut buffer))
                    .map_err(|error| card_failed("reading a file back", &error))?;
                if read != (file.size, file.sha256.clone()) {
                    return Err(Refusal::mismatch(
                        &file.name,
                        "when it is read back from the card",
                    ));
                }
            }
            Ok(())
        })
    }

    /// Step 3: stages the trial in one writable claim of the card, in the order that a power cut
    /// leaves safe.
    ///
    /// Firmware mode writes `tryboot.txt`, then the marker. The firmware reads `tryboot.txt` only
    /// after a restart that asks for `tryboot`, so a cut between the two leaves a file nobody
    /// reads and no marker. Software mode writes the marker, on the card before the next write
    /// starts, and then the selection in `config.txt`, which is what the next start boots from. A
    /// selection with no marker boots the new slot as a normal start, with no trial and no way
    /// back, so the marker comes first: a cut between the two leaves the marker naming the new slot
    /// while `config.txt` still selects the running one, which the boot rules know as a rollback
    /// (the running slot boots and the marker is deleted).
    ///
    /// A slot that is not fit to select is a refusal and a write that fails is an error of the
    /// card; in software mode either one is followed by `undo_software_stage`.
    fn stage(&self, manifest: &Manifest, running: Slot) -> Result<(), Refusal> {
        let target = manifest.slot;
        let marker = Marker {
            slot: target,
            from: running,
            build: manifest.build,
            mode: manifest.mode,
            started: false,
            failed: None,
        };
        self.on_card(CardAccess::Writable, |boot| match manifest.mode {
            Mode::Tryboot => {
                judge_selection(slots::stage_tryboot(boot, target))?;
                write_marker(boot, &marker)
            }
            Mode::Software => {
                write_marker(boot, &marker)?;
                let selected = judge_selection(slots::select(boot, target));
                if selected.is_err() {
                    undo_software_stage(boot, running);
                }
                selected
            }
        })
    }
}

/// Judges what `slots::select` or `slots::stage_tryboot` did: the slot is selected, or the
/// answer is a refusal (the slot's `config.txt` is not fit to copy) or an error of the card.
fn judge_selection(selected: io::Result<Select>) -> Result<(), Refusal> {
    match selected {
        Ok(Select::Selected | Select::AlreadySelected) => Ok(()),
        Ok(Select::Refused(reason)) => {
            log::warn!("update: the slot was not fit to select: {reason}");
            Err(Refusal::card("the slot could not be selected"))
        }
        Err(error) => Err(card_failed("selecting the slot", &error)),
    }
}

/// Writes the marker, and the error is an error of the card.
fn write_marker(boot: &Path, marker: &Marker) -> Result<(), Refusal> {
    slots::write_marker(boot, marker).map_err(|error| card_failed("writing the marker", &error))
}

/// Takes a software-mode staging back after its selection failed: puts the running slot's
/// selection back and, only when that is done, deletes the marker.
///
/// The order matters as the staging's does: a cut between the two leaves a marker naming a slot
/// that nothing selects, which a boot reports as a rollback and deletes, where the other order
/// could leave a selection with no marker. When the running slot cannot be selected again (the
/// card fails, or `config.txt` cannot be told) the marker stays, since a `config.txt` that may
/// select the new slot is safer with its marker than without. Failures are logged and nothing more:
/// the update is refused either way.
fn undo_software_stage(boot: &Path, running: Slot) {
    match slots::select(boot, running) {
        Ok(Select::Selected | Select::AlreadySelected) => {
            if let Err(error) = slots::remove_marker(boot) {
                log::warn!(
                    "update: the marker of the refused update could not be deleted: {error}"
                );
            }
        }
        Ok(Select::Refused(reason)) => log::warn!(
            "update: slot {running} could not be selected again ({reason}); the marker stays"
        ),
        Err(error) => log::warn!(
            "update: slot {running} could not be selected again ({error}); the marker stays"
        ),
    }
}

/// The line that the log gets when an update's manifest has been read: numbers and the slot's
/// letter, and no name or byte from the body.
fn start_line(manifest: &Manifest, length: u64) -> String {
    format!(
        "update: receiving build {} for slot {}: {} files, {length} bytes",
        manifest.build,
        manifest.slot,
        manifest.files.len(),
    )
}

/// The line that the log gets when an update is staged.
fn staged_line(staged: &Staged) -> String {
    format!(
        "update: staged build {} in slot {} ({} trial), and the board restarts",
        staged.build,
        staged.slot,
        staged.mode.word()
    )
}

/// Reads and judges the manifest at the front of `body`, whose whole length is `length`.
fn read_manifest(body: &mut impl Read, length: u64) -> Result<Manifest, Refusal> {
    let mut size = [0u8; 4];
    if length < size.len() as u64 {
        return Err(Refusal::bad(
            "the update's body is too short to hold a manifest",
        ));
    }
    body.read_exact(&mut size).map_err(|_| Refusal::stopped())?;
    let size = u32::from_be_bytes(size) as usize;
    if size == 0 || size > MAX_MANIFEST || 4 + size as u64 > length {
        return Err(Refusal::bad(
            "the manifest's length is 0, over 16 KiB, or more than the body holds",
        ));
    }
    let mut json = vec![0u8; size];
    body.read_exact(&mut json).map_err(|_| Refusal::stopped())?;
    let manifest = Manifest::parse(&json).map_err(Refusal::bad)?;
    let files = manifest
        .files
        .iter()
        .try_fold(4 + size as u64, |sum, file| sum.checked_add(file.size));
    if files != Some(length) {
        return Err(Refusal::bad(
            "the files' sizes and the manifest do not add up to the body's length",
        ));
    }
    Ok(manifest)
}

/// Reads the two text files from `body`, holds them in memory, and judges them: each must be the
/// manifest's hash, `cmdline.txt` must name the slot on its command line and `config.txt` must
/// select it.
fn read_texts(body: &mut impl Read, manifest: &Manifest) -> Result<[Vec<u8>; TEXTS], Refusal> {
    let mut texts = [Vec::new(), Vec::new()];
    for (text, file) in texts.iter_mut().zip(&manifest.files) {
        // The parse held each text file to `MAX_TEXT` bytes.
        *text = vec![0u8; usize::try_from(file.size).unwrap_or(0)];
        body.read_exact(text).map_err(|_| Refusal::stopped())?;
        if sha256_hex(text) != file.sha256 {
            return Err(Refusal::mismatch(&file.name, "as it arrives"));
        }
    }
    slots::check_slot_cmdline(&texts[0], manifest.slot).map_err(Refusal::bad)?;
    slots::check_slot_config(&texts[1], manifest.slot).map_err(Refusal::bad)?;
    Ok(texts)
}

/// Copies the `file.size` bytes of `file` from `body` into `out`, hashing them, and judges the
/// hash. The error of the outer `Result` is a refusal; the inner `io::Result` is a write to the
/// card that failed, which the caller names.
fn stream(
    body: &mut impl Read,
    out: &mut File,
    file: &FileEntry,
    buffer: &mut [u8],
) -> Result<io::Result<()>, Refusal> {
    let mut hasher = Sha256::new();
    let mut left = file.size;
    while left > 0 {
        let want = usize::try_from(left).map_or(buffer.len(), |left| left.min(buffer.len()));
        let got = match body.read(&mut buffer[..want]) {
            Ok(0) | Err(_) => return Err(Refusal::stopped()),
            Ok(got) => got,
        };
        hasher.update(&buffer[..got]);
        if let Err(error) = out.write_all(&buffer[..got]) {
            return Ok(Err(error));
        }
        left -= got as u64;
    }
    if slots::hex(&hasher.finalize()) != file.sha256 {
        return Err(Refusal::mismatch(&file.name, "as it arrives"));
    }
    Ok(Ok(()))
}

/// The length and the SHA-256 of what `from` holds, reading at most `limit + 1` bytes, so that a
/// file that is longer than it should be shows as such.
fn hash_of(from: &mut File, limit: u64, buffer: &mut [u8]) -> io::Result<(u64, String)> {
    let mut hasher = Sha256::new();
    let mut length = 0u64;
    let mut capped = from.take(limit.saturating_add(1));
    loop {
        let got = match capped.read(buffer) {
            Ok(0) => break,
            Ok(got) => got,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        hasher.update(&buffer[..got]);
        length += got as u64;
    }
    Ok((length, slots::hex(&hasher.finalize())))
}

/// Removes everything in `folder`, which is made if it is not there.
fn empty_folder(folder: &Path) -> io::Result<()> {
    match fs::read_dir(folder) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    fs::remove_dir_all(entry.path())?;
                } else {
                    fs::remove_file(entry.path())?;
                }
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir(folder),
        Err(error) => Err(error),
    }
}

/// A use of the card that failed at `step`: logs the system's words and refuses in ours.
fn card_failed(step: &str, error: &io::Error) -> Refusal {
    log::warn!("update: {step} failed: {error}");
    Refusal::card("the card could not be written")
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::sync::PoisonError;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, SystemTime};

    use serde_json::Value;
    use tokio::net::TcpListener;

    use super::*;
    use crate::api::live::LiveFacts;
    use crate::api::password::PasswordHash;
    use crate::api::routes::Api;
    use crate::api::testutil::{Answer, Connection, certificate, https, pem, pinned_client};
    use crate::api::tls::server_config;
    use crate::api::{Limits, places, serve};
    use crate::dns::Dns;
    use crate::dns::testutil::{FakeUpstream, Reply as Upstream, ask_udp, one};
    use crate::services::testutil::longest_gap;
    use crate::slots::{MARKER_FILE, TRYBOOT_FILE};
    use crate::update::{BootCard, NoCard};
    use crate::wiring::Extras;

    /// A change to a manifest's JSON, which makes it wrong in one way.
    type Change = Box<dyn Fn(&mut Value)>;

    /// The running build's time in these tests.
    const RUNNING: u64 = 1_794_000_000;

    /// How long the API's TLS handshake may take in these tests. A debug build's handshake on a
    /// loaded machine can take longer than the product's `HANDSHAKE_WAIT` (5 s), which stays what
    /// it is: only the fixture's own server has this room, so that the tests are about the
    /// receiver and not about the load.
    const TEST_HANDSHAKE_WAIT: Duration = Duration::from_secs(60);

    const MS: Duration = Duration::from_millis(1);

    /// The eleven files of `slot`, in the body's order: the two text files as the build makes them
    /// and eight others that are the same for both slots.
    fn files_for(slot: Slot) -> Vec<(&'static str, Vec<u8>)> {
        BODY_ORDER
            .iter()
            .map(|&name| {
                let bytes = match name {
                    "cmdline.txt" => format!("console=serial0,115200 quiet {}\n", slot.cmdline_arg()),
                    "config.txt" => format!(
                        "# a slot of the card\nos_prefix={}\nkernel=kernel8.img\ninitramfs initramfs8 followkernel\n",
                        slot.os_prefix()
                    ),
                    other => format!("the bytes of {other}, which are the same in both slots\n"),
                };
                (name, bytes.into_bytes())
            })
            .collect()
    }

    /// The digest that a running build on slot a has of its boot files.
    fn running_digest() -> String {
        let files = files_for(Slot::A);
        slots::boot_files_digest(files.iter().map(|(name, bytes)| (*name, bytes.as_slice())))
            .unwrap()
    }

    /// A body to send: the manifest, the files, and what the request says about its length.
    struct Offer {
        manifest: Manifest,
        files: Vec<(&'static str, Vec<u8>)>,
        /// The `Content-Length` to send instead of the body's own.
        length: Option<u64>,
        /// The session to send; `None` for none.
        sid: Option<String>,
    }

    impl Offer {
        /// The files of `slot`, as build `build` that is tried the way `mode` says.
        fn new(build: u64, slot: Slot, mode: Mode) -> Offer {
            let files = files_for(slot);
            let manifest = Manifest::of_files(
                build,
                slot,
                mode,
                &files
                    .iter()
                    .map(|(name, bytes)| (*name, bytes.as_slice()))
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            Offer {
                manifest,
                files,
                length: None,
                sid: None,
            }
        }

        /// A newer build for slot b, tried with the firmware: what an update is.
        fn update() -> Offer {
            Offer::new(RUNNING + 1, Slot::B, Mode::Tryboot)
        }

        /// Makes the file `name` hold `bytes`, and the manifest say so.
        fn replace(&mut self, name: &str, bytes: Vec<u8>) {
            let at = BODY_ORDER.iter().position(|&n| n == name).unwrap();
            self.manifest.files[at].size = bytes.len() as u64;
            self.manifest.files[at].sha256 = sha256_hex(&bytes);
            self.files[at].1 = bytes;
        }

        /// The bytes of the body, in pieces: the manifest's head, then each file.
        fn pieces(&self) -> Vec<Vec<u8>> {
            let mut pieces = vec![self.manifest.head().unwrap()];
            pieces.extend(self.files.iter().map(|(_, bytes)| bytes.clone()));
            pieces
        }

        /// What the request says its body's length is.
        fn content_length(&self) -> u64 {
            self.length
                .unwrap_or_else(|| self.pieces().iter().map(|piece| piece.len() as u64).sum())
        }
    }

    /// A directory that stands for the boot partition, lent as the card, which records its uses
    /// and can flip a byte of a file just before the read-only use.
    struct DirCard {
        root: PathBuf,
        uses: Mutex<Vec<CardAccess>>,
        flip: Mutex<Option<&'static str>>,
    }

    impl DirCard {
        fn uses(&self) -> Vec<CardAccess> {
            self.uses
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    impl BootCard for DirCard {
        fn with_boot(&self, access: CardAccess, work: &mut dyn FnMut(&Path)) -> io::Result<()> {
            self.uses
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(access);
            if access == CardAccess::ReadOnly {
                let flip = self
                    .flip
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take();
                if let Some(file) = flip {
                    let path = self.root.join(file);
                    let mut bytes = fs::read(&path).unwrap();
                    bytes[0] ^= 1;
                    fs::write(&path, bytes).unwrap();
                }
            }
            work(&self.root);
            Ok(())
        }
    }

    /// The API over a card that is a directory, serving on a `127.0.0.1` port, logged in.
    struct Fixture {
        addr: SocketAddr,
        dns_addr: SocketAddr,
        client: Arc<rustls::ClientConfig>,
        ctl: Arc<UpdateCtl>,
        card: Arc<DirCard>,
        sid: String,
        card_dir: tempfile::TempDir,
        _dns: Arc<Dns>,
        _upstream: FakeUpstream,
    }

    impl Fixture {
        /// A card on slot a, whose running build has the right digest, under the default limits.
        async fn new() -> Fixture {
            Fixture::with(Limits::DEFAULT, Some(Slot::A), Some(running_digest())).await
        }

        /// A card running `slot` (`None`: the old layout, with no card to lend) whose running build
        /// has the boot files' digest `digest`, served under `limits`.
        async fn with(limits: Limits, slot: Option<Slot>, digest: Option<String>) -> Fixture {
            let card_dir = tempfile::tempdir().unwrap();
            let root = card_dir.path().to_owned();
            // What a card of slot a holds: the root config.txt, slot a's folder, and the old
            // contents of slot b's folder, with a folder in it.
            let a = files_for(Slot::A);
            fs::write(root.join("config.txt"), &a[1].1).unwrap();
            fs::create_dir(root.join("qberrypi-a")).unwrap();
            for (name, bytes) in &a {
                fs::write(root.join("qberrypi-a").join(name), bytes).unwrap();
            }
            fs::create_dir_all(root.join("qberrypi-b/old")).unwrap();
            fs::write(root.join("qberrypi-b/leftover.bin"), b"an earlier build").unwrap();
            fs::write(root.join("qberrypi-b/old/deeper.bin"), b"deeper").unwrap();

            let card = Arc::new(DirCard {
                root,
                uses: Mutex::new(Vec::new()),
                flip: Mutex::new(None),
            });
            let ctl = match slot {
                Some(_) => UpdateCtl::new(slot, digest, card.clone()),
                None => UpdateCtl::off(),
            };

            let (dns, dns_addr, upstream) =
                one(Upstream::Answer("192.0.2.1".parse().unwrap())).await;
            let pem = pem();
            let cert = certificate(&pem);
            let tls = server_config(pem.as_bytes()).unwrap();
            let api = Arc::new(
                Api::new(
                    PasswordHash::new(b"right", [0; 16]),
                    Arc::new(LiveFacts {
                        dns: dns.clone(),
                        extras: Arc::new(Extras::default),
                    }),
                    {
                        let dns = dns.clone();
                        Arc::new(move || dns.now().mono_secs)
                    },
                    Arc::new(|| Some([7; 16])),
                )
                .with_update(Receiver::new(ctl.clone(), RUNNING)),
            );
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let addr = listener.local_addr().unwrap();
            let limits = Limits {
                handshake: TEST_HANDSHAKE_WAIT,
                ..limits
            };
            tokio::spawn(serve(listener, tls, api, limits, places()));
            let client = pinned_client(&cert);
            let login = https(
                addr,
                client.clone(),
                &[r#"POST /api/auth|{"password":"right"}"#],
            )
            .await;
            let sid = login[0].1["session"]["sid"].as_str().unwrap().to_owned();
            Fixture {
                addr,
                dns_addr,
                client,
                ctl,
                card,
                sid,
                card_dir,
                _dns: dns,
                _upstream: upstream,
            }
        }

        fn root(&self) -> &Path {
            &self.card.root
        }

        /// Sends `offer` with this fixture's session, unless the offer has one of its own, and
        /// reads the answer. A write that fails because the server has already answered and closed
        /// is no failure of the test: the answer is read all the same.
        async fn send(&self, mut offer: Offer) -> Answer {
            offer.sid.get_or_insert_with(|| self.sid.clone());
            self.send_as(offer).await
        }

        /// [`Fixture::send`] with `offer.sid` as it is, which may be none.
        async fn send_as(&self, offer: Offer) -> Answer {
            let (addr, client) = (self.addr, self.client.clone());
            tokio::task::spawn_blocking(move || {
                let mut connection = Connection::open(addr, client).unwrap();
                let sid = offer
                    .sid
                    .as_ref()
                    .map(|sid| format!("X-FTL-SID: {sid}\r\n"))
                    .unwrap_or_default();
                let head = format!(
                    "POST {PATH} HTTP/1.1\r\nHost: 192.0.2.53\r\nUser-Agent: test\r\n{sid}Content-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    offer.content_length()
                );
                connection.send_raw(head.as_bytes()).unwrap();
                let pieces = offer.pieces();
                connection
                    .send_pieces_and_receive(pieces.iter().map(Vec::as_slice))
                    .unwrap_or_else(|error| panic!("no reply to the update: {error}"))
            })
            .await
            .unwrap()
        }

        /// What `file` of the card holds, if it is there.
        fn read(&self, file: &str) -> Option<Vec<u8>> {
            fs::read(self.root().join(file)).ok()
        }

        /// Checks that nothing was selected and nothing is staged: the card's `config.txt` is
        /// slot a's, there is no `tryboot.txt` and no marker, nobody is asked to restart, and the
        /// machinery is free.
        fn assert_nothing_staged(&self) {
            assert_eq!(
                self.read("config.txt"),
                Some(files_for(Slot::A)[1].1.clone())
            );
            assert_eq!(self.read(TRYBOOT_FILE), None);
            assert_eq!(self.read(MARKER_FILE), None);
            assert_eq!(*self.ctl.restart_receiver().borrow(), None);
            assert_eq!(self.ctl.view().state, "idle");
        }

        /// Checks the refusal that `answer` is, and that the card was not touched: nothing was
        /// staged, the card was not used and slot b's folder holds what it did.
        fn assert_refused_before_the_card(&self, answer: &Answer, status: u16, key: &str) {
            assert_eq!(
                (answer.status, answer.json["error"]["key"].as_str()),
                (status, Some(key)),
                "{answer:?}"
            );
            assert!(self.card.uses().is_empty(), "the card was used");
            assert_eq!(
                self.read("qberrypi-b/leftover.bin"),
                Some(b"an earlier build".to_vec())
            );
            self.assert_nothing_staged();
        }
    }

    /// The error's message in an answer.
    fn message(answer: &Answer) -> &str {
        answer.json["error"]["message"].as_str().unwrap_or("")
    }

    #[test]
    fn the_body_order_is_the_two_text_files_and_then_the_slot_files_in_their_order() {
        assert_eq!(BODY_ORDER[..2], ["cmdline.txt", "config.txt"]);
        let rest: Vec<&str> = slots::SLOT_FILES
            .iter()
            .copied()
            .filter(|name| !BODY_ORDER[..2].contains(name))
            .collect();
        assert_eq!(BODY_ORDER[2..], rest[..]);
        assert_eq!(PATH, "/api/qbp/update");
        assert_eq!(
            (UPLOAD_CAP, MAX_MANIFEST, MAX_TEXT, RESTART_AFTER),
            (64 << 20, 16 << 10, 4 << 10, Duration::from_secs(1))
        );
    }

    #[test]
    fn a_manifest_is_the_specs_json_and_reads_back_as_it_was_made() {
        let mut offer = Offer::new(1_794_470_000, Slot::B, Mode::Software);
        offer.manifest.force = true;
        let json: Value = serde_json::from_slice(&offer.manifest.to_json()).unwrap();
        assert_eq!(json["build"], 1_794_470_000_u64);
        assert_eq!(json["slot"], "b");
        assert_eq!(json["mode"], "software");
        assert_eq!(json["force"], true);
        assert_eq!(json["allow_kernel"], false);
        let files = json["files"].as_array().unwrap();
        assert_eq!(files.len(), 11);
        assert_eq!(files[0]["name"], "cmdline.txt");
        assert_eq!(files[10]["name"], "tls.pem");
        assert_eq!(
            files[0]["size"],
            files_for(Slot::B)[0].1.len() as u64,
            "the size of the file"
        );
        assert_eq!(files[0]["sha256"].as_str().unwrap().len(), 64);
        // It is read back as made, and the keys that may be left out are false.
        assert_eq!(
            Manifest::parse(&offer.manifest.to_json()),
            Ok(offer.manifest.clone())
        );
        let mut bare = json.clone();
        bare.as_object_mut().unwrap().remove("force");
        bare.as_object_mut().unwrap().remove("allow_kernel");
        let bare = Manifest::parse(&serde_json::to_vec(&bare).unwrap()).unwrap();
        assert!(!bare.force && !bare.allow_kernel);
    }

    #[test]
    fn the_body_starts_with_the_manifests_length_in_four_big_endian_bytes() {
        let offer = Offer::update();
        let head = offer.manifest.head().unwrap();
        let json = offer.manifest.to_json();
        assert_eq!(head[..4], (json.len() as u32).to_be_bytes());
        assert_eq!(head[4..], json[..]);
        let files: u64 = offer
            .files
            .iter()
            .map(|(_, bytes)| bytes.len() as u64)
            .sum();
        assert_eq!(
            offer.manifest.content_length(),
            Ok(head.len() as u64 + files)
        );
    }

    #[test]
    fn a_manifest_is_made_only_of_the_ten_files_each_once_and_a_body_over_the_cap_is_not_sent() {
        let ten = files_for(Slot::B);
        let borrowed =
            |files: &[(&'static str, Vec<u8>)]| -> Vec<(&'static str, Vec<u8>)> { files.to_vec() };
        let as_slices = |files: &[(&'static str, Vec<u8>)]| -> Result<Manifest, String> {
            Manifest::of_files(
                1,
                Slot::B,
                Mode::Tryboot,
                &files
                    .iter()
                    .map(|(name, bytes)| (*name, bytes.as_slice()))
                    .collect::<Vec<_>>(),
            )
        };
        // In any order, the entries come out in the body's.
        let mut shuffled = borrowed(&ten);
        shuffled.reverse();
        let manifest = as_slices(&shuffled).unwrap();
        let names: Vec<&str> = manifest.files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, BODY_ORDER);
        // One missing, one twice, one that is no slot file.
        assert!(as_slices(&ten[1..]).unwrap_err().contains("cmdline.txt"));
        let mut twice = borrowed(&ten);
        twice.push(ten[3].clone());
        assert!(as_slices(&twice).unwrap_err().contains(ten[3].0));
        let mut other = borrowed(&ten);
        other.push(("evil.bin", Vec::new()));
        assert!(as_slices(&other).unwrap_err().contains("evil.bin"));
        // Too much: a manifest that says a file is 64 MiB has no body that fits.
        let mut big = as_slices(&ten).unwrap();
        big.files[2].size = UPLOAD_CAP;
        assert!(big.content_length().is_err());
        big.files[2].size = u64::MAX;
        assert!(big.content_length().is_err());
    }

    #[test]
    fn a_manifest_that_is_not_the_shape_is_refused_in_fixed_words_that_quote_nothing() {
        let good = Offer::update().manifest;
        let edit = |change: &dyn Fn(&mut Value)| -> Result<Manifest, &'static str> {
            let mut json: Value = serde_json::from_slice(&good.to_json()).unwrap();
            change(&mut json);
            Manifest::parse(&serde_json::to_vec(&json).unwrap())
        };
        assert_eq!(edit(&|_| {}), Ok(good.clone()));
        let refused: [(&str, Change); 22] = [
            ("build as text", Box::new(|j| j["build"] = "1".into())),
            ("build as a float", Box::new(|j| j["build"] = 1.5.into())),
            ("a negative build", Box::new(|j| j["build"] = (-1).into())),
            (
                "no build",
                Box::new(|j| drop(j.as_object_mut().unwrap().remove("build"))),
            ),
            ("slot c", Box::new(|j| j["slot"] = "c".into())),
            ("slot as a number", Box::new(|j| j["slot"] = 1.into())),
            ("mode x", Box::new(|j| j["mode"] = "x".into())),
            (
                "no mode",
                Box::new(|j| drop(j.as_object_mut().unwrap().remove("mode"))),
            ),
            ("force as text", Box::new(|j| j["force"] = "yes".into())),
            (
                "allow_kernel as a number",
                Box::new(|j| j["allow_kernel"] = 1.into()),
            ),
            ("a key of its own", Box::new(|j| j["extra"] = true.into())),
            (
                "no files",
                Box::new(|j| drop(j.as_object_mut().unwrap().remove("files"))),
            ),
            (
                "ten files",
                Box::new(|j| drop(j["files"].as_array_mut().unwrap().pop())),
            ),
            (
                "twelve files",
                Box::new(|j| {
                    let again = j["files"][0].clone();
                    j["files"].as_array_mut().unwrap().push(again);
                }),
            ),
            (
                "two files swapped",
                Box::new(|j| j["files"].as_array_mut().unwrap().swap(0, 1)),
            ),
            (
                "a name of its own",
                Box::new(|j| j["files"][4]["name"] = "evil.bin".into()),
            ),
            (
                "a size as text",
                Box::new(|j| j["files"][3]["size"] = "5".into()),
            ),
            (
                "a negative size",
                Box::new(|j| j["files"][3]["size"] = (-5).into()),
            ),
            (
                "a hash in capitals",
                Box::new(|j| {
                    let hash = j["files"][2]["sha256"].as_str().unwrap().to_uppercase();
                    j["files"][2]["sha256"] = hash.into();
                }),
            ),
            (
                "a short hash",
                Box::new(|j| j["files"][2]["sha256"] = "ab".into()),
            ),
            (
                "a key of its own in a file",
                Box::new(|j| j["files"][2]["path"] = "/etc".into()),
            ),
            (
                "a text file of 4 KiB and a byte",
                Box::new(|j| j["files"][1]["size"] = 4097.into()),
            ),
        ];
        for (what, change) in &refused {
            let why = edit(change.as_ref()).unwrap_err();
            assert!(!why.is_empty() && !why.contains("evil"), "{what}: {why}");
        }
        // The edge of the text file's size, and bytes that are not JSON at all.
        assert!(edit(&|j| j["files"][1]["size"] = 4096.into()).is_ok());
        for bad in [
            &b""[..],
            b"[]",
            b"null",
            b"{",
            b"{\"build\":1} {}",
            b"\xff\xfe",
        ] {
            assert_eq!(
                Manifest::parse(bad),
                Err("the manifest is not a JSON object")
            );
        }
    }

    #[test]
    fn the_reply_is_sent_before_the_restart_is_asked_for_and_the_restart_comes_a_second_later() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap();
        runtime.block_on(async {
            let ctl = UpdateCtl::new(Some(Slot::A), None, Arc::new(NoCard));
            let mut asked = ctl.restart_receiver();
            let received = Received {
                reply: Reply {
                    status: 200,
                    body: b"{}".to_vec(),
                },
                restart: Some((ctl.clone(), Restart::Tryboot)),
            };
            assert!(received.staged());
            let began = tokio::time::Instant::now();
            received
                .send_then_restart(|reply| {
                    // At the time of the send nobody has been asked, and the reply is the answer.
                    assert_eq!(reply.status, 200);
                    assert_eq!(*ctl.restart_receiver().borrow(), None);
                    Ok(())
                })
                .unwrap();
            // Asked for by a timer, not at once, and not by a thread that waits.
            assert_eq!(*asked.borrow(), None);
            asked.changed().await.unwrap();
            assert_eq!(began.elapsed(), RESTART_AFTER);
            assert_eq!(*asked.borrow(), Some(Restart::Tryboot));
        });
    }

    #[test]
    fn a_reply_that_could_not_be_written_still_asks_for_the_restart_and_a_refusal_never_does() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap();
        runtime.block_on(async {
            let ctl = UpdateCtl::new(Some(Slot::A), None, Arc::new(NoCard));
            let mut asked = ctl.restart_receiver();
            let reply = || Reply {
                status: 200,
                body: Vec::new(),
            };
            let gone = Received {
                reply: reply(),
                restart: Some((ctl.clone(), Restart::Plain(Cause::Update))),
            };
            let result = gone.send_then_restart(|_| Err(io::ErrorKind::BrokenPipe.into()));
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
            asked.changed().await.unwrap();
            assert_eq!(*asked.borrow(), Some(Restart::Plain(Cause::Update)));

            let other = UpdateCtl::new(Some(Slot::A), None, Arc::new(NoCard));
            let refused = Received {
                reply: reply(),
                restart: None,
            };
            assert!(!refused.staged());
            refused.send_then_restart(|_| Ok(())).unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
            assert_eq!(*other.restart_receiver().borrow(), None);
        });
    }

    #[test]
    fn with_no_runtime_to_put_a_timer_on_the_restart_is_asked_for_at_once() {
        let ctl = UpdateCtl::new(Some(Slot::A), None, Arc::new(NoCard));
        Received {
            reply: Reply {
                status: 200,
                body: Vec::new(),
            },
            restart: Some((ctl.clone(), Restart::Tryboot)),
        }
        .send_then_restart(|_| Ok(()))
        .unwrap();
        assert_eq!(*ctl.restart_receiver().borrow(), Some(Restart::Tryboot));
    }

    #[tokio::test]
    async fn an_update_for_the_firmwares_trial_is_written_verified_staged_and_answered() {
        let fixture = Fixture::new().await;
        let mut asked = fixture.ctl.restart_receiver();
        let offer = Offer::update();
        let sent = offer.files.clone();

        let answer = fixture.send(offer).await;

        assert_eq!(answer.status, 200, "{answer:?}");
        assert_eq!(answer.json["staged"], true);
        assert_eq!(answer.json["slot"], "b");
        assert_eq!(answer.json["build"], RUNNING + 1);
        // Slot b holds the eleven files byte for byte, and what was there is gone, folders too.
        for (name, bytes) in &sent {
            assert_eq!(
                fixture.read(&format!("qberrypi-b/{name}")).as_ref(),
                Some(bytes),
                "{name}"
            );
        }
        assert_eq!(
            fs::read_dir(fixture.root().join("qberrypi-b"))
                .unwrap()
                .count(),
            11
        );
        // The firmware's trial reads tryboot.txt: slot b's config. The root config.txt still
        // selects slot a, so a power cycle boots a.
        assert_eq!(fixture.read(TRYBOOT_FILE), Some(sent[1].1.clone()));
        assert_eq!(
            fixture.read("config.txt"),
            Some(files_for(Slot::A)[1].1.clone())
        );
        // The marker, last, as the updater renders it.
        let marker = Marker {
            slot: Slot::B,
            from: Slot::A,
            build: RUNNING + 1,
            mode: Mode::Tryboot,
            started: false,
            failed: None,
        };
        assert_eq!(
            fixture.read(MARKER_FILE),
            Some(marker.render().into_bytes())
        );
        // Three claims: the write, the fresh read-only mount, the staging.
        assert_eq!(
            fixture.card.uses(),
            [
                CardAccess::Writable,
                CardAccess::ReadOnly,
                CardAccess::Writable
            ]
        );
        // The machinery stays taken, and a second later the board is asked to restart for it.
        assert_eq!(fixture.ctl.view().state, "receiving");
        tokio::time::timeout(Duration::from_secs(10), asked.changed())
            .await
            .expect("the restart was asked for")
            .unwrap();
        assert_eq!(*asked.borrow(), Some(Restart::Tryboot));
    }

    #[tokio::test]
    async fn an_update_for_the_software_trial_selects_the_slot_in_config_txt_instead() {
        let fixture = Fixture::new().await;
        let mut asked = fixture.ctl.restart_receiver();
        let offer = Offer::new(RUNNING + 1, Slot::B, Mode::Software);
        let sent = offer.files.clone();

        let answer = fixture.send(offer).await;

        assert_eq!(answer.status, 200, "{answer:?}");
        assert_eq!(fixture.read("config.txt"), Some(sent[1].1.clone()));
        assert_eq!(fixture.read(TRYBOOT_FILE), None);
        let marker = String::from_utf8(fixture.read(MARKER_FILE).unwrap()).unwrap();
        assert_eq!(
            Marker::parse(&marker).unwrap(),
            Marker {
                slot: Slot::B,
                from: Slot::A,
                build: RUNNING + 1,
                mode: Mode::Software,
                started: false,
                failed: None,
            }
        );
        tokio::time::timeout(Duration::from_secs(10), asked.changed())
            .await
            .expect("the restart was asked for")
            .unwrap();
        assert_eq!(*asked.borrow(), Some(Restart::Plain(Cause::Update)));
    }

    #[tokio::test]
    async fn the_two_text_files_may_be_what_a_boot_file_digest_ignores_and_nothing_else() {
        // A command line that differs from the running one in more than the slot's letter is a
        // change of the boot files; one that differs in the letter alone is not.
        let fixture = Fixture::new().await;
        let mut changed = Offer::update();
        changed.replace(
            "cmdline.txt",
            b"console=serial0,115200 quiet debug qberrypi.slot=b\n".to_vec(),
        );
        let answer = fixture.send(changed).await;
        fixture.assert_refused_before_the_card(&answer, 409, "kernel_change");

        let mut config_changed = Offer::update();
        let mut config = files_for(Slot::B)[1].1.clone();
        config.extend_from_slice(b"gpu_mem=16\n");
        config_changed.replace("config.txt", config);
        let answer = fixture.send(config_changed).await;
        fixture.assert_refused_before_the_card(&answer, 409, "kernel_change");

        // The initramfs and the slot's own configuration are the build, and may change.
        let mut build = Offer::update();
        build.replace("initramfs8", b"a different build".to_vec());
        build.replace("qberrypi.toml", b"another configuration".to_vec());
        build.replace("tls.pem", b"another key".to_vec());
        assert_eq!(fixture.send(build).await.status, 200);
    }

    #[tokio::test]
    async fn a_changed_kernel_device_tree_or_overlay_is_refused_unless_allowed() {
        for changed in [
            "kernel8.img",
            "bcm2710-rpi-3-b-plus.dtb",
            "ov-README",
            "ov-overlay_map.dtb",
            "ov-qb-piscreen.dtbo",
            "ov-disable-bt.dtbo",
        ] {
            let fixture = Fixture::new().await;
            let mut offer = Offer::update();
            offer.replace(changed, b"not the pinned one".to_vec());
            let answer = fixture.send(offer).await;
            fixture.assert_refused_before_the_card(&answer, 409, "kernel_change");
            assert!(!message(&answer).contains("pinned"), "{changed}");

            let mut allowed = Offer::update();
            allowed.replace(changed, b"not the pinned one".to_vec());
            allowed.manifest.allow_kernel = true;
            assert_eq!(fixture.send(allowed).await.status, 200, "{changed}");
        }
    }

    #[tokio::test]
    async fn a_running_build_that_cannot_tell_its_boot_files_takes_an_update_only_when_allowed() {
        let fixture = Fixture::with(Limits::DEFAULT, Some(Slot::A), None).await;
        let answer = fixture.send(Offer::update()).await;
        fixture.assert_refused_before_the_card(&answer, 409, "kernel_change");

        let mut allowed = Offer::update();
        allowed.manifest.allow_kernel = true;
        assert_eq!(fixture.send(allowed).await.status, 200);
    }

    #[tokio::test]
    async fn a_build_that_is_not_newer_is_refused_unless_forced() {
        let fixture = Fixture::new().await;
        for build in [RUNNING, RUNNING - 1, 0] {
            let answer = fixture
                .send(Offer::new(build, Slot::B, Mode::Tryboot))
                .await;
            fixture.assert_refused_before_the_card(&answer, 409, "not_newer");
        }
        let mut forced = Offer::new(RUNNING, Slot::B, Mode::Tryboot);
        forced.manifest.force = true;
        let answer = fixture.send(forced).await;
        assert_eq!(answer.status, 200, "{answer:?}");
        assert_eq!(answer.json["build"], RUNNING);
    }

    #[tokio::test]
    async fn an_update_for_the_running_slot_is_refused_as_the_wrong_slot() {
        let fixture = Fixture::new().await;
        let answer = fixture
            .send(Offer::new(RUNNING + 1, Slot::A, Mode::Tryboot))
            .await;
        fixture.assert_refused_before_the_card(&answer, 409, "wrong_slot");
        // The same on a card that runs slot b: then a is the one to write.
        let on_b = Fixture::with(Limits::DEFAULT, Some(Slot::B), Some(running_digest())).await;
        let answer = on_b.send(Offer::update()).await;
        on_b.assert_refused_before_the_card(&answer, 409, "wrong_slot");
    }

    #[tokio::test]
    async fn a_slot_that_config_txt_selects_is_never_emptied_even_when_the_other_one_runs() {
        let fixture = Fixture::new().await;
        // As after a trial that was cut off: slot a runs and the card boots b.
        fs::write(fixture.root().join("config.txt"), &files_for(Slot::B)[1].1).unwrap();

        let answer = fixture.send(Offer::update()).await;

        assert_eq!(
            (answer.status, answer.json["error"]["key"].as_str()),
            (409, Some("wrong_slot")),
            "{answer:?}"
        );
        assert_eq!(fixture.card.uses(), [CardAccess::Writable]);
        assert_eq!(
            fixture.read("qberrypi-b/leftover.bin"),
            Some(b"an earlier build".to_vec())
        );
        assert_eq!(fixture.read(TRYBOOT_FILE), None);
        assert_eq!(fixture.read(MARKER_FILE), None);
        assert_eq!(fixture.ctl.view().state, "idle");
    }

    #[tokio::test]
    async fn a_card_with_no_slots_refuses_before_it_reads_the_manifest() {
        let fixture = Fixture::with(Limits::DEFAULT, None, None).await;
        // A body that is not even a manifest: the refusal does not look.
        let mut offer = Offer::update();
        offer.length = Some(6);
        let answer = fixture.send(offer).await;
        fixture.assert_refused_before_the_card(&answer, 409, "no_slots");
    }

    #[tokio::test]
    async fn an_update_that_is_under_way_or_staged_or_a_trial_that_is_on_is_busy() {
        let fixture = Fixture::new().await;
        // One that is being received.
        let taken = fixture.ctl.begin_receive().unwrap();
        let answer = fixture.send(Offer::update()).await;
        assert_eq!(
            (answer.status, answer.json["error"]["key"].as_str()),
            (409, Some("update_busy"))
        );
        assert!(fixture.card.uses().is_empty());
        drop(taken);
        // The refusal left the machinery as it was: the next one is taken.
        assert_eq!(fixture.send(Offer::update()).await.status, 200);
        // A second one in the second before the restart is busy: the staged one stays taken.
        let answer = fixture.send(Offer::update()).await;
        assert_eq!(answer.json["error"]["key"], "update_busy");

        // A boot that is on trial takes none.
        let on_trial = Fixture::with(Limits::DEFAULT, Some(Slot::B), Some(running_digest())).await;
        on_trial.ctl.begin_trial(
            Marker {
                slot: Slot::B,
                from: Slot::A,
                build: RUNNING,
                mode: Mode::Tryboot,
                started: true,
                failed: None,
            },
            tokio::time::Instant::now(),
        );
        let mut offer = Offer::new(RUNNING + 1, Slot::A, Mode::Tryboot);
        offer.manifest.allow_kernel = true;
        let answer = on_trial.send(offer).await;
        assert_eq!(
            (answer.status, answer.json["error"]["key"].as_str()),
            (409, Some("update_busy"))
        );
        assert_eq!(on_trial.ctl.view().state, "trial");
        assert!(on_trial.card.uses().is_empty());
    }

    #[tokio::test]
    async fn without_a_session_nothing_of_the_body_is_read_and_another_method_is_405() {
        let fixture = Fixture::new().await;
        let (addr, client) = (fixture.addr, fixture.client.clone());
        let sid = fixture.sid.clone();
        let answers = tokio::task::spawn_blocking(move || {
            let ask = |sid: Option<&str>, length: &str, method: &str| {
                let mut connection = Connection::open(addr, client.clone()).unwrap();
                let sid = sid.map(|sid| format!("X-FTL-SID: {sid}\r\n")).unwrap_or_default();
                // A body of a gigabyte is announced and none is sent: only a server that does not
                // wait for it can answer.
                let head = format!(
                    "{method} {PATH} HTTP/1.1\r\nHost: 192.0.2.53\r\n{sid}Content-Length: {length}\r\n\r\n"
                );
                connection.send_raw(head.as_bytes()).unwrap();
                connection.receive().unwrap()
            };
            (
                ask(None, "1073741824", "POST"),
                ask(Some(&"0".repeat(32)), "1073741824", "POST"),
                ask(Some("not a session"), "5", "POST"),
                ask(None, "0", "GET"),
                ask(Some(&sid), "0", "GET"),
                ask(Some(&sid), "0", "DELETE"),
            )
        })
        .await
        .unwrap();
        let shown = |answer: &Answer| {
            (
                answer.status,
                answer.json["error"]["key"].as_str().map(str::to_owned),
            )
        };
        let key = |status, key: &str| (status, Some(key.to_owned()));
        assert_eq!(shown(&answers.0), key(401, "unauthorized"));
        assert_eq!(shown(&answers.1), key(401, "unauthorized"));
        assert_eq!(shown(&answers.2), key(401, "unauthorized"));
        assert_eq!(shown(&answers.3), key(401, "unauthorized"));
        assert_eq!(shown(&answers.4), key(405, "method_not_allowed"));
        assert_eq!(shown(&answers.5), key(405, "method_not_allowed"));
        assert!(fixture.card.uses().is_empty());
        fixture.assert_nothing_staged();
    }

    #[tokio::test]
    async fn a_body_over_the_cap_is_refused_unread_and_a_session_comes_first() {
        let fixture = Fixture::new().await;
        let mut over = Offer::update();
        over.length = Some(UPLOAD_CAP + 1);
        over.sid = Some(fixture.sid.clone());
        let (addr, client) = (fixture.addr, fixture.client.clone());
        // Only the head is sent: the 413 is the answer to it.
        let answer = tokio::task::spawn_blocking(move || {
            let mut connection = Connection::open(addr, client).unwrap();
            let head = format!(
                "POST {PATH} HTTP/1.1\r\nHost: x\r\nX-FTL-SID: {}\r\nContent-Length: {}\r\n\r\n",
                over.sid.as_ref().unwrap(),
                over.length.unwrap()
            );
            connection.send_raw(head.as_bytes()).unwrap();
            connection.receive().unwrap()
        })
        .await
        .unwrap();
        fixture.assert_refused_before_the_card(&answer, 413, "payload_too_large");

        // Exactly the cap is not too large: it is a manifest that is then wrong, as a body of
        // that length has no such manifest.
        let mut at_cap = Offer::update();
        at_cap.length = Some(UPLOAD_CAP);
        let answer = fixture.send(at_cap).await;
        assert_eq!(answer.json["error"]["key"], "bad_request", "{answer:?}");
    }

    #[tokio::test]
    async fn a_refusal_is_read_when_the_server_closed_on_a_body_that_was_still_being_written() {
        let fixture = Fixture::new().await;
        let mut offer = Offer::update();
        offer.manifest.allow_kernel = true;
        offer.replace("kernel8.img", noise(8 << 20, 3));
        assert!(offer.sid.is_none());

        // No session: the server answers from the head and closes with the body unread, so the
        // client's writes fail partway and its connection is reset, and the 401 is still there to
        // be read.
        let answer = fixture.send_as(offer).await;

        fixture.assert_refused_before_the_card(&answer, 401, "unauthorized");
    }

    #[tokio::test]
    async fn a_body_that_is_not_a_manifest_and_files_is_a_400_and_writes_nothing() {
        let fixture = Fixture::new().await;
        // A manifest whose sizes do not add up to the body: too much, and too little.
        for length in [
            Offer::update().content_length() + 1,
            Offer::update().content_length() - 1,
        ] {
            let mut offer = Offer::update();
            offer.length = Some(length);
            let answer = fixture.send(offer).await;
            fixture.assert_refused_before_the_card(&answer, 400, "bad_request");
        }
        // Shorter than the length word, a manifest of length 0, a manifest longer than the cap or
        // than the body.
        for (body, length) in [
            (vec![0u8; 3], 3),
            (vec![0, 0, 0, 0, 1, 2, 3, 4], 8),
            (
                {
                    let mut body = ((MAX_MANIFEST + 1) as u32).to_be_bytes().to_vec();
                    body.extend(vec![b' '; MAX_MANIFEST + 1]);
                    body
                },
                4 + MAX_MANIFEST as u64 + 1,
            ),
            (vec![0, 0, 1, 0, b'{', b'}'], 6),
            (b"\x00\x00\x00\x02{}".to_vec(), 6),
        ] {
            let mut offer = Offer::update();
            offer.files.clear();
            offer.manifest.files.clear();
            offer.length = Some(length);
            let answer = send_raw_body(&fixture, length, body).await;
            fixture.assert_refused_before_the_card(&answer, 400, "bad_request");
        }
    }

    /// Sends a body made of `bytes` as the request's, announcing `length` of them.
    async fn send_raw_body(fixture: &Fixture, length: u64, bytes: Vec<u8>) -> Answer {
        let (addr, client, sid) = (fixture.addr, fixture.client.clone(), fixture.sid.clone());
        tokio::task::spawn_blocking(move || {
            let mut connection = Connection::open(addr, client).unwrap();
            let head = format!(
                "POST {PATH} HTTP/1.1\r\nHost: x\r\nX-FTL-SID: {sid}\r\nContent-Length: {length}\r\n\r\n"
            );
            connection.send_raw(head.as_bytes()).unwrap();
            connection
                .send_pieces_and_receive([bytes.as_slice()])
                .unwrap_or_else(|error| panic!("no reply to the body: {error}"))
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn names_that_are_not_the_ten_files_are_refused_and_never_echoed() {
        let fixture = Fixture::new().await;
        // A name of its own in place of a slot file, and the right names in the wrong order.
        let mut evil = Offer::update();
        evil.manifest.files[4].name = "../../etc/passwd".to_owned();
        let answer = fixture.send(evil).await;
        fixture.assert_refused_before_the_card(&answer, 400, "bad_request");
        assert!(!answer.json.to_string().contains("passwd"), "{answer:?}");

        let mut swapped = Offer::update();
        swapped.manifest.files.swap(2, 3);
        swapped.files.swap(2, 3);
        let answer = fixture.send(swapped).await;
        fixture.assert_refused_before_the_card(&answer, 400, "bad_request");

        let mut nine = Offer::update();
        nine.manifest.files.pop();
        nine.files.pop();
        let answer = fixture.send(nine).await;
        fixture.assert_refused_before_the_card(&answer, 400, "bad_request");
    }

    #[tokio::test]
    async fn a_command_line_or_config_that_does_not_name_the_slot_is_a_400_before_the_card() {
        let fixture = Fixture::new().await;
        let cases: [(&str, &[u8], &str); 6] = [
            (
                "cmdline.txt",
                b"quiet qberrypi.slot=a\n",
                "names the other slot",
            ),
            ("cmdline.txt", b"quiet\n", "no qberrypi.slot"),
            (
                "cmdline.txt",
                b"quiet qberrypi.slot=b\nsecond line\n",
                "more than one line",
            ),
            (
                "config.txt",
                b"os_prefix=qberrypi-a/\n",
                "selects the other slot",
            ),
            ("config.txt", b"kernel=kernel8.img\n", "no os_prefix"),
            ("config.txt", b"   \n", "is empty"),
        ];
        for (name, text, why) in cases {
            let mut offer = Offer::update();
            offer.replace(name, text.to_vec());
            offer.manifest.allow_kernel = true;
            let answer = fixture.send(offer).await;
            fixture.assert_refused_before_the_card(&answer, 400, "bad_request");
            assert!(message(&answer).contains(why), "{name}: {answer:?}");
            assert!(message(&answer).starts_with(name), "{name}: {answer:?}");
        }
    }

    #[tokio::test]
    async fn a_text_file_that_does_not_match_its_hash_is_a_422_before_the_card() {
        let fixture = Fixture::new().await;
        for at in [0, 1] {
            let mut offer = Offer::update();
            offer.manifest.files[at].sha256 = "0".repeat(64);
            let answer = fixture.send(offer).await;
            fixture.assert_refused_before_the_card(&answer, 422, "hash_mismatch");
            assert!(message(&answer).contains(BODY_ORDER[at]));
        }
    }

    #[tokio::test]
    async fn a_file_that_does_not_match_its_hash_as_it_arrives_stops_the_update_and_selects_nothing()
     {
        let fixture = Fixture::new().await;
        let mut offer = Offer::update();
        // The kernel's hash is wrong, and the files after it are right.
        offer.manifest.files[2].sha256 = "f".repeat(64);
        offer.manifest.allow_kernel = true;

        let answer = fixture.send(offer).await;

        assert_eq!(
            (answer.status, answer.json["error"]["key"].as_str()),
            (422, Some("hash_mismatch")),
            "{answer:?}"
        );
        assert!(message(&answer).contains("kernel8.img"));
        // The write stopped there, in its one claim: no verification, no staging, nothing selected.
        assert_eq!(fixture.card.uses(), [CardAccess::Writable]);
        assert_eq!(
            fixture.read("qberrypi-b/leftover.bin"),
            None,
            "emptied first"
        );
        assert_eq!(
            fixture.read("qberrypi-b/initramfs8"),
            None,
            "stopped at the kernel"
        );
        fixture.assert_nothing_staged();
    }

    #[tokio::test]
    async fn a_byte_that_is_wrong_when_the_card_is_read_back_is_a_422_and_selects_nothing() {
        for flipped in [
            "qberrypi-b/kernel8.img",
            "qberrypi-b/tls.pem",
            "qberrypi-b/config.txt",
        ] {
            let fixture = Fixture::new().await;
            *fixture.card.flip.lock().unwrap() = Some(flipped);

            let answer = fixture.send(Offer::update()).await;

            assert_eq!(
                (answer.status, answer.json["error"]["key"].as_str()),
                (422, Some("hash_mismatch")),
                "{flipped}: {answer:?}"
            );
            assert!(message(&answer).contains("read back"), "{answer:?}");
            assert_eq!(
                fixture.card.uses(),
                [CardAccess::Writable, CardAccess::ReadOnly]
            );
            fixture.assert_nothing_staged();
            // And the machinery is free for the next update, which this time is right.
            assert_eq!(fixture.send(Offer::update()).await.status, 200);
        }
    }

    #[tokio::test]
    async fn a_card_that_cannot_be_used_or_written_is_a_500_and_selects_nothing() {
        struct Broken;
        impl BootCard for Broken {
            fn with_boot(&self, _: CardAccess, _: &mut dyn FnMut(&Path)) -> io::Result<()> {
                Err(io::Error::other("the card is in use by another thread"))
            }
        }
        let fixture = Fixture::new().await;
        let ctl = UpdateCtl::new(Some(Slot::A), Some(running_digest()), Arc::new(Broken));
        // The same API, over a ctl whose card refuses: made by hand, since the fixture's is fixed.
        let receiver = Receiver::new(ctl.clone(), RUNNING);
        let offer = Offer::update();
        let pieces: Vec<u8> = offer.pieces().concat();
        let head = head_of(pieces.len() as u64);
        let received = receiver.receive(&head, &mut io::Cursor::new(pieces));
        assert_eq!(received.reply().status, 500);
        let body: Value = serde_json::from_slice(&received.reply().body).unwrap();
        assert_eq!(body["error"]["key"], "internal");
        assert!(!received.staged());
        assert_eq!(ctl.view().state, "idle");
        let _ = fixture;

        // A slot's folder that cannot be emptied: a file stands where it should be.
        let fixture = Fixture::new().await;
        fs::remove_dir_all(fixture.root().join("qberrypi-b")).unwrap();
        fs::write(fixture.root().join("qberrypi-b"), b"not a folder").unwrap();
        let answer = fixture.send(Offer::update()).await;
        assert_eq!(
            (answer.status, answer.json["error"]["key"].as_str()),
            (500, Some("internal")),
            "{answer:?}"
        );
        fixture.assert_nothing_staged();
    }

    /// A head for a `POST` to the route with `length`.
    fn head_of(length: u64) -> Head {
        Head {
            method: "POST".to_owned(),
            target: PATH.to_owned(),
            sid: None,
            length,
            close: true,
        }
    }

    /// A card of slot a on a directory of its own, as a `DirCard` the receiver can be given, with
    /// the root `config.txt` backdated so that a write to it shows in its modification time.
    fn card_of_slot_a() -> (tempfile::TempDir, Arc<DirCard>, SystemTime) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let a = files_for(Slot::A);
        fs::write(root.join("config.txt"), &a[1].1).unwrap();
        fs::create_dir(root.join("qberrypi-a")).unwrap();
        fs::write(root.join("qberrypi-a/config.txt"), &a[1].1).unwrap();
        let long_ago = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        File::options()
            .write(true)
            .open(root.join("config.txt"))
            .unwrap()
            .set_modified(long_ago)
            .unwrap();
        let card = Arc::new(DirCard {
            root: root.to_owned(),
            uses: Mutex::new(Vec::new()),
            flip: Mutex::new(None),
        });
        (dir, card, long_ago)
    }

    /// Sends the software-trial update for slot b through a receiver on `card`, whose reply is
    /// the answer.
    fn receive_software_update(card: &Arc<DirCard>) -> (Received, Arc<UpdateCtl>) {
        let ctl = UpdateCtl::new(Some(Slot::A), Some(running_digest()), card.clone());
        let receiver = Receiver::new(ctl.clone(), RUNNING);
        let offer = Offer::new(RUNNING + 1, Slot::B, Mode::Software);
        let body: Vec<u8> = offer.pieces().concat();
        let received = receiver.receive(&head_of(body.len() as u64), &mut io::Cursor::new(body));
        (received, ctl)
    }

    #[test]
    fn in_software_mode_the_marker_is_written_before_config_txt_is_touched() {
        // The marker's path is a folder, so writing it fails. If the marker came last, `config.txt`
        // would have been written by then (the new slot, and the old one back): a power cut in
        // between would leave the new slot selected with no marker, which boots as a normal start
        // with no trial and no way back. With the marker first, it is never touched.
        let (dir, card, long_ago) = card_of_slot_a();
        let root = dir.path();
        fs::create_dir(root.join(MARKER_FILE)).unwrap();

        let (received, ctl) = receive_software_update(&card);

        assert_eq!(received.reply().status, 500);
        assert!(!received.staged());
        assert!(root.join("qberrypi-b/kernel8.img").exists());
        assert_eq!(
            fs::read(root.join("config.txt")).unwrap(),
            files_for(Slot::A)[1].1
        );
        assert_eq!(
            fs::metadata(root.join("config.txt"))
                .unwrap()
                .modified()
                .unwrap(),
            long_ago,
            "config.txt was written before the marker"
        );
        assert_eq!(ctl.view().state, "idle");
    }

    /// A card that, at its second writable use (the staging, after the slot was written and
    /// proved), first replaces `file` with `bytes`: the card changing between the proof and the
    /// selection.
    struct SpoilAtStage {
        inner: Arc<DirCard>,
        file: &'static str,
        bytes: &'static [u8],
        writable: Mutex<usize>,
    }

    impl BootCard for SpoilAtStage {
        fn with_boot(&self, access: CardAccess, work: &mut dyn FnMut(&Path)) -> io::Result<()> {
            if access == CardAccess::Writable {
                let mut count = self.writable.lock().unwrap_or_else(PoisonError::into_inner);
                *count += 1;
                if *count == 2 {
                    fs::write(self.inner.root.join(self.file), self.bytes).unwrap();
                }
            }
            self.inner.with_boot(access, work)
        }
    }

    #[test]
    fn in_software_mode_a_selection_that_is_refused_after_the_marker_takes_the_marker_back() {
        // Slot b's `config.txt` stops naming slot b between the proof and the selection, so the
        // selection is refused after the marker was written. Nothing selects slot b, so no marker
        // is left naming it: a boot would otherwise report a rollback that never was.
        let (dir, inner, long_ago) = card_of_slot_a();
        let root = dir.path();
        let card = Arc::new(SpoilAtStage {
            inner,
            file: "qberrypi-b/config.txt",
            bytes: b"arm_64bit=1\n",
            writable: Mutex::new(0),
        });
        let ctl = UpdateCtl::new(Some(Slot::A), Some(running_digest()), card.clone());
        let receiver = Receiver::new(ctl.clone(), RUNNING);
        let offer = Offer::new(RUNNING + 1, Slot::B, Mode::Software);
        let body: Vec<u8> = offer.pieces().concat();

        let received = receiver.receive(&head_of(body.len() as u64), &mut io::Cursor::new(body));

        assert_eq!(received.reply().status, 500);
        assert!(!received.staged());
        assert!(!root.join(MARKER_FILE).exists(), "a marker was left behind");
        assert_eq!(
            fs::read(root.join("config.txt")).unwrap(),
            files_for(Slot::A)[1].1
        );
        let _ = long_ago;
        assert_eq!(ctl.view().state, "idle");
    }

    #[test]
    fn in_software_mode_a_selection_that_fails_and_cannot_be_put_back_leaves_the_marker() {
        // `config.txt` is a folder, so it cannot be read to select either slot: the marker stays,
        // since a selection that cannot be told is safer with a marker than without one.
        let (dir, card, _) = card_of_slot_a();
        let root = dir.path();
        fs::remove_file(root.join("config.txt")).unwrap();
        fs::create_dir(root.join("config.txt")).unwrap();

        let (received, _) = receive_software_update(&card);

        assert_eq!(received.reply().status, 500);
        assert!(root.join(MARKER_FILE).exists());
    }

    #[tokio::test]
    async fn a_client_that_stops_sending_is_answered_after_the_read_wait_and_frees_its_place() {
        let limits = Limits {
            upload_idle: 300 * MS,
            ..Limits::DEFAULT
        };
        let fixture = Fixture::with(limits, Some(Slot::A), Some(running_digest())).await;
        let offer = Offer::update();
        let pieces = offer.pieces();
        let length = offer.content_length();
        let (addr, client, sid) = (fixture.addr, fixture.client.clone(), fixture.sid.clone());

        let (answer, waited) = tokio::task::spawn_blocking(move || {
            let mut connection = Connection::open(addr, client).unwrap();
            let head = format!(
                "POST {PATH} HTTP/1.1\r\nHost: x\r\nX-FTL-SID: {sid}\r\nContent-Length: {length}\r\n\r\n"
            );
            connection.send_raw(head.as_bytes()).unwrap();
            // The manifest and the first two files, and then nothing, with the connection open.
            for piece in &pieces[..3] {
                connection.send_raw(piece).unwrap();
            }
            let began = Instant::now();
            (connection.receive().unwrap(), began.elapsed())
        })
        .await
        .unwrap();

        assert_eq!(
            (answer.status, answer.json["error"]["key"].as_str()),
            (400, Some("bad_request")),
            "{answer:?}"
        );
        assert!(message(&answer).contains("stopped arriving"));
        assert!((250 * MS..2000 * MS).contains(&waited), "{waited:?}");
        fixture.assert_nothing_staged();
        // Its place and the machinery are free: the next update, whole, goes through.
        assert_eq!(fixture.send(Offer::update()).await.status, 200);
    }

    #[tokio::test]
    async fn a_client_that_sends_a_byte_at_a_time_is_cut_off_at_the_whole_time_of_the_request() {
        let limits = Limits {
            upload: 700 * MS,
            upload_idle: 300 * MS,
            ..Limits::DEFAULT
        };
        let fixture = Fixture::with(limits, Some(Slot::A), Some(running_digest())).await;
        let offer = Offer::update();
        let head_piece = offer.pieces().remove(0);
        let length = offer.content_length();
        let (addr, client, sid) = (fixture.addr, fixture.client.clone(), fixture.sid.clone());

        let took = tokio::task::spawn_blocking(move || {
            let mut connection = Connection::open(addr, client).unwrap();
            let head = format!(
                "POST {PATH} HTTP/1.1\r\nHost: x\r\nX-FTL-SID: {sid}\r\nContent-Length: {length}\r\n\r\n"
            );
            connection.send_raw(head.as_bytes()).unwrap();
            let began = Instant::now();
            // Each byte comes inside the 300 ms that a read may wait, so only the whole time of
            // the request can end it. The client finds out that the server has closed when a
            // write fails.
            for byte in head_piece.iter().cycle().take(60) {
                if connection.send_raw(&[*byte]).is_err() {
                    return began.elapsed();
                }
                std::thread::sleep(100 * MS);
            }
            Duration::MAX
        })
        .await
        .unwrap();

        assert!((600 * MS..1500 * MS).contains(&took), "{took:?}");
        fixture.assert_nothing_staged();
        // The place and the machinery are free again.
        assert_eq!(fixture.send(Offer::update()).await.status, 200);
    }

    /// `n` bytes that no run repeats, from a fixed seed.
    fn noise(n: usize, seed: u64) -> Vec<u8> {
        let mut state = seed | 1;
        let mut bytes = Vec::with_capacity(n);
        while bytes.len() < n {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            bytes.extend_from_slice(&state.to_le_bytes());
        }
        bytes.truncate(n);
        bytes
    }

    // Review Focus: the hot path. Run with `--nocapture` for the figures.
    #[tokio::test]
    async fn a_32_mib_upload_does_not_hold_the_runtime_and_dns_answers_from_the_cache_meanwhile() {
        let fixture = Fixture::new().await;
        let mut offer = Offer::update();
        offer.manifest.allow_kernel = true;
        // 20 MiB of kernel and 12 MiB of initramfs, over the other nine files.
        offer.replace("kernel8.img", noise(20 << 20, 1));
        offer.replace("initramfs8", noise(12 << 20, 2));
        let total = offer.content_length();
        assert!((32 << 20..33 << 20).contains(&total), "{total}");

        // The name is cached by the first question, which the upstream answers.
        assert!(ask_udp(fixture.dns_addr, "example.com").await.is_some());

        let done = AtomicBool::new(false);
        let asking = async {
            let mut times = Vec::new();
            let mut lost = 0;
            while !done.load(Ordering::SeqCst) {
                let asked = Instant::now();
                match ask_udp(fixture.dns_addr, "example.com").await {
                    Some(_) => times.push(asked.elapsed()),
                    None => lost += 1,
                }
                tokio::time::sleep(5 * MS).await;
            }
            (times, lost)
        };
        let uploading = async {
            let answer = fixture.send(offer).await;
            done.store(true, Ordering::SeqCst);
            answer
        };

        let began = Instant::now();
        let (gap, (answer, (times, lost))) =
            longest_gap(async { tokio::join!(uploading, asking) }).await;
        let took = began.elapsed();

        assert_eq!(answer.status, 200, "{answer:?}");
        let mut sorted = times.clone();
        sorted.sort();
        let (median, slowest) = (sorted[sorted.len() / 2], *sorted.last().unwrap());
        println!(
            "upload of {total} bytes in {took:?} ({:.1} MiB/s): {} cached DNS answers over UDP during it, median {median:?}, slowest {slowest:?}, {lost} lost; the runtime's longest gap {gap:?}",
            total as f64 / (1 << 20) as f64 / took.as_secs_f64(),
            times.len(),
        );
        assert_eq!(lost, 0, "a DNS answer was lost during the upload");
        assert!(
            times.len() >= 10,
            "only {} answers were asked for",
            times.len()
        );
        assert!(gap < 100 * MS, "{gap:?}");
        assert!(slowest < 100 * MS, "{slowest:?}");
        // The upload itself is whole on the card.
        assert_eq!(
            fixture
                .read("qberrypi-b/kernel8.img")
                .map(|bytes| bytes.len()),
            Some(20 << 20)
        );
        let _ = &fixture.card_dir;
    }

    #[test]
    fn the_lines_that_are_logged_hold_numbers_and_the_fixed_names_and_nothing_of_the_body() {
        let offer = Offer::new(1_794_470_000, Slot::B, Mode::Software);
        assert_eq!(
            start_line(&offer.manifest, 123_456),
            "update: receiving build 1794470000 for slot b: 11 files, 123456 bytes"
        );
        let staged = Staged {
            slot: Slot::B,
            build: 1_794_470_000,
            mode: Mode::Tryboot,
        };
        assert_eq!(
            staged_line(&staged),
            "update: staged build 1794470000 in slot b (tryboot trial), and the board restarts"
        );
        let refusal = Refusal::mismatch("kernel8.img", "as it arrives");
        assert_eq!(
            refusal.log_line(),
            "update: refused (hash_mismatch): kernel8.img does not match its SHA-256 as it arrives"
        );
        assert_eq!(
            Refusal::conflict(
                "not_newer",
                "the update is not newer than the running build"
            )
            .log_line(),
            "update: refused (not_newer): the update is not newer than the running build"
        );
    }
}
