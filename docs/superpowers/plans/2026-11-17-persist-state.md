# The owner's settings survive a restart — Implementation Plan

> **For agentic workers:** one fresh implementer per task, in order; no per-task review (owner:
> lean process), one review of the whole track at the end. Steps use checkbox (`- [ ]`) syntax.

**Goal:** the owner-set state that the Pi holds in memory today (and that qnet pushes again after
a restart) is kept on the card, so that it comes back after a power cut with the desktop off, and
pulling the plug stays safe.

**Worktree:** `~/Work/qberrypi-persist`, branch `persist-state`. `export
CARGO_TARGET_DIR=$HOME/Work/qberrypi-persist/target TMPDIR=$HOME/Work/qberrypi-persist/target/tmp`.
`vendor-cache` is a link to the main checkout's: read only, never run `cargo xtask fetch` or
`fetch-lists`. Another track works in `~/Work/qberrypi-polish`: never touch it.

## Global constraints (every task)

- **Never read `qberrypi.toml`, anything under `private/`, or a secret store.** Public repo:
  tests use 192.0.2.x / 198.51.100.x / 10.x addresses, `example.org`-style names and `02:00:00:..`
  MACs; no real names, home paths, MACs, SSIDs or IPs.
- **Never** open a real block device on this PC, never run `sudo`, never contact the Pi or the
  router, no network in tests beyond loopback. No synthetic keyboard or mouse input.
- Rust only. `unsafe` only in `crates/qberrypi/src/sys.rs`. No new crates.
- **No latency regression.** Nothing new on the runtime thread costs more than a few
  microseconds; card I/O and hashing go on the blocking pool (`services::blocking`); nothing new
  takes the resolver's lock. Do not change `dns/` or `qb-dns`.
- **Privacy:** no log line names a MAC, an address, a label, an owner's name, a hash or a byte of
  the saved file: counts and copy letters only. Nothing about lookups is ever saved.
- House style: read the neighbouring code first and match it. A doc comment on every item, in
  full sentences, with bounds and failure modes; tests named as sentences.
- **Gates before every commit:** `cargo test --workspace -- --skip
  the_hint_keeps_the_log_free_of_its_frequencies` (that one is known-flaky); `cargo clippy
  --workspace --all-targets` with 0 warnings; `cargo fmt --all --check`; `grep -rln unsafe
  crates/qberrypi/src crates/qberrypi/tests` prints only `crates/qberrypi/src/sys.rs`. A commit
  touching `init.rs`, `services.rs`, `selftest.rs` or `xtask/` also runs `cargo xtask build &&
  cargo xtask qemu-test` with every scenario ok (check `pgrep -x qemu-system-aar` for leftovers
  first and after).
- Stage files by name (no `git add -A` / `.`). Commit messages end with
  `Co-Authored-By: <your model name> <noreply@anthropic.com>`. No push, no merge.
- At the end of your task append 3–6 lines to
  `.superpowers/sdd/2026-11-17-persist-state/progress.md` (commit hash, what was done, anything
  deferred or surprising). That folder is git-ignored.

## The design (binding)

### What is kept

| State | Where it lives now | Kept as |
| --- | --- | --- |
| pushed exempt list (`exempt_pushed`, ≤ 64 MACs) | `watch::devices::Devices` | sorted MACs |
| pushed block list (`block_pushed`, ≤ 64) | `Devices` | sorted MACs |
| pushed mode (`default_pushed: Option<bool>`) | `Devices` | 0 none / 1 false / 2 true |
| labels (`labels`, ≤ 64, in order) | `Devices` | MAC + label, in order |
| known set (`known`, ≤ 1024) | `Devices` | sorted MACs |
| owner's names (≤ 128 a side, in order, with `set_unix`) | `names::OwnerList` | name, side, day, in order |
| PIN, when its source is `Api` or `Panel` | `panel::lock::Lock` | source + `PasswordHash::to_text()` |
| night hours | `panel::lock::PanelState` | `Option<(u8, u8)>` |

With the PIN and the night hours goes what the configuration said when they were saved: the
SHA-256 of the configuration's `pin_hash` text (32 zero bytes when it has none) and the
configuration's night. At a start a saved PIN is put back only if the configuration's `pin_hash`
is still the one it was saved under, and the saved night only if the configuration's night is
still the one it was saved under: an owner who changes the file and updates gets the file's.
A PIN from the configuration, a lock turned off, and the counter of wrong PINs are not kept
(at a start the configuration's PIN is in force then, as today).

**Never kept:** the main pause, the per-device gates, the staged chunks of a push, alerts and
acknowledgements, counters, the devices heard, anything about lookups, `top_today`.

**The known set and qnet.** The restored known set is put in `known`, but `state` stays
`KnownList::Waiting` and the API still says `"known_list": "waiting"`: qnet treats a Pi that is
waiting (while it has a known list of its own) as one that restarted and pushes its lists, which
keeps qnet's adoption rule exactly as it is today. While waiting, a device on the restored set
is known (never held, never raised). A new change to `Devices::tick`: when the ten minutes pass
with no list from the desktop and the known set was restored from the card, the held devices are
**raised** (the restored set stands in for the desktop's list) instead of learned, and the state
becomes `Learned`; with no restored set the learning is as today.

### The file

Two copies, `qberrypi-state/a.bin` and `qberrypi-state/b.bin` on the boot partition (their own
folder, beside the slot folders). Each copy is exactly `FILE_SIZE` bytes. A copy's frame, at its
start:

```
0..8    magic  b"QBPSTATE"
8..12   format version, u32 LE (1)
12..16  payload length, u32 LE (≤ MAX_PAYLOAD)
16..24  sequence, u64 LE
24..    payload (length bytes)
then    SHA-256 of bytes 0 .. 24+length (32 bytes)
```

The rest of the file is whatever was there (the fill, or an older frame's tail). A copy is valid
when the magic, version, length bound, checksum and the payload's own decoding all pass.
`MAX_PAYLOAD` is computed in a `const` from the caps (`MAX_EXEMPT`, `MAX_BLOCK`, `MAX_LABELS`,
`LABEL_MAX`, `MAX_KNOWN`, `OWNER_NAMES_MAX`, `MAX_NAME_LEN`, the longest PIN line) and
`FILE_SIZE` is `24 + MAX_PAYLOAD + 32` rounded up to 4096; a `const` assertion keeps them in step.
An encoder that would exceed `MAX_PAYLOAD` returns an error (logged as one line by the caller),
never a truncated payload.

The payload is a hand-made, deterministic encoding (the same state is always the same bytes, so
"did it change" is a byte comparison): the sections in the order of the table, counts as u16 LE,
MACs as 6 bytes, strings as a u8 length and bytes, `Option<u64>` as a flag byte and 8 bytes. The
decoder checks every count against its cap, every label with `Label::new`, every name with
`qb_dns::name::normalize` (it must already be normal), every PIN line with
`panel::lock::parse_pin_hash`, every hour ≤ 23 and the two different, and that nothing is left
over; any failure makes the copy invalid.

**Loading:** the valid copy with the highest sequence, in serial-number order (`a` is newer than
`b` when `a.wrapping_sub(b)` as `i64` is > 0), wins; equal sequences prefer `a`. Neither valid:
start empty exactly as today, and log one line (`state: no saved settings on the card` when the
files are not there, `state: neither saved copy is whole; starting empty` when they are).

**Saving** writes the copy that is not the newest valid one (`a` when neither is valid) with the
sequence one past the newest's (wrapping; 1 when none), then that copy is the newest. A failed
write leaves the other copy as the newest.

### How the card is written: in place, through the raw partition

A save never mounts the card. A writable mount of the FAT partition itself writes the boot
sector (the "dirty" flag, at mount and again at unmount) and the FSInfo sector, and a write
through the file system updates the file's directory entry (its time); a tear of any of those is
worse than losing a save. So:

1. **Creation, once.** The first save on a card that does not have both files at `FILE_SIZE`
   mounts the partition writable once (through the card claim, as the existing writers do:
   `on_card` / `BootCard::with_boot`), makes `qberrypi-state/`, writes each missing or wrong-sized
   file whole with a fill (SHA-256 counter stream of `b"qberrypi state fill"`, the copy letter
   and the block number, so that a fresh copy is never valid and is never all zeros), `sync_all`s
   it, maps it (step 2) and unmounts. A file of the right size is never recreated.
2. **Mapping.** While a file is open on the mounted partition, its physical place is asked with
   the `FIGETBSZ` and `FIBMAP` ioctls (wrappers in `sys.rs`, the only `unsafe`), block by block,
   and merged into extents `(offset on the partition, length)`. A block that maps to 0 (a hole) is
   an error. Then the partition device itself (`bootpart::BOOT_DEV`, opened read-only) is read at
   those extents and must equal the bytes read through the file system, else the mapping is not
   trusted and saving is off for the boot (one line).
3. **Boot load** happens in init's step 3, in the read-only mount that already reads the
   configuration (`load_slot_config` / `load_config_into`): both files are read whole and mapped
   (step 2). The result travels to the services in `services::Context`.
4. **A save** claims the card (`claim_card`, without mounting: the partition is not mounted while
   the board runs), opens `BOOT_DEV` read-write, reads the target copy's whole window back and
   checks that its SHA-256 is the one that copy was last known to hold (from the boot read or the
   last write), writes the frame padded with zeros to a multiple of 512 bytes at the copy's
   extents (`pwrite`), and `sync_all`s the device. A check that fails or any I/O error turns
   saving off for the boot with one line, and the other copy is untouched. Mount options are not
   involved (and the existing read-only mounts already pass `NOATIME`).

Nothing but the frame's own sectors is written after creation: no FAT, no directory entry, no
boot sector. A power cut during a save tears at most the copy being written, and the other holds
the state before it.

### When it saves

- A poller on the runtime every `POLL` (5 s) takes a snapshot (the three structures' locks, each
  held only for a copy, never the resolver's) and encodes it. When the bytes differ from the last
  poll's, the change time is now.
- It saves when the bytes differ from what the newest copy holds (or, with no valid copy on the
  card, from the encoding of the first snapshot the saver takes when it starts, after the restore:
  it carries this boot's configuration PIN fingerprint and night, so `Saved::default()` is not
  the baseline; a boot that changes nothing, or changes and changes back, writes nothing and
  creates nothing), the bytes have been unchanged for `QUIET`
  (30 s), at least `MIN_GAP` (60 s) have passed since the last save began, and
  `UpdateCtl::when_idle` says no update is being received or staged and no trial is on. The
  write runs on the blocking pool; one at a time.
- **The owner's restart** (`Cause::Owner`, RESTART on UP) saves at once in init's way out, before
  the log save, if the bytes differ from the newest copy: debounce does not apply, the claim and
  the update rule do.
- `[state] persist = true` by default. `false` reads nothing, writes nothing and creates
  nothing: exactly today's behaviour.
- Log lines (INFO, counts only): at a start `state: settings restored from copy a (seq 12): 3
  ADS PASS, 0 blocked, 5 labels, 41 known, 7 names, lock kept, night kept` (the parts as they
  are); each save `state: saved to copy b (seq 13)`; creation `state: made the two copies on the
  card`; and the WARN lines above for a save that is turned off.

### What the owner sees

- The LOCK screen's second line: with persistence on, `from the desktop: it outlasts a restart`
  and `set here: it outlasts a restart` (off: the old texts), and `a PIN set here outlasts a
  restart` in place of `a PIN set here lasts until a restart`. The world carries one new
  `lock_kept: bool`.
- `docs/reference.md` and the README's "Hard to break" bullet say what is written now, when, and
  why a power cut cannot damage it.

---

### Task 1: `state` — the kept state, the frame, the two copies and the timing (pure)

**Files:** create `crates/qberrypi/src/state/mod.rs`, `state/format.rs`, `state/store.rs`,
`state/debounce.rs`; modify `crates/qberrypi/src/lib.rs` (the `mod` line only).

- [ ] `state/mod.rs`: the module doc (the design above, short), and the kept types: `Saved {
  devices: SavedDevices, names: Vec<SavedName>, panel: SavedPanel }`, `SavedDevices { exempt:
  Vec<Mac>, block: Vec<Mac>, exempt_default: Option<bool>, labels: Vec<(Mac, Label)>, known:
  Vec<Mac> }`, `SavedName { name: Box<str>, side: OwnerSide, set_unix: Option<u64> }`,
  `SavedPanel { pin: Option<SavedPin>, pin_config: [u8; 32], night: Option<(u8, u8)>,
  night_config: Option<(u8, u8)> }`, `SavedPin { source: lock::Source /* Api or Panel only */,
  hash: PasswordHash }`. `Default` is the empty state (and `pin_config` of no PIN: all zeros).
  No `Debug` prints a MAC, label, name or hash (counts only, as the neighbours do). A helper
  `pin_fingerprint(Option<&PasswordHash>) -> [u8; 32]` (SHA-256 of `to_text()`, zeros for none).
- [ ] `state/format.rs`: `MAX_PAYLOAD`, `FILE_SIZE`, `encode_payload(&Saved) -> Result<Vec<u8>,
  Oversize>`, `decode_payload(&[u8]) -> Option<Saved>`, `frame(seq, &payload) -> Vec<u8>`,
  `read_frame(&[u8]) -> Option<(u64 /* seq */, &[u8] /* payload */)>`, `newer(a, b) -> bool`
  (serial order). Tests: round trip of an empty and of a full state (every cap at its maximum,
  longest names and labels) and `FILE_SIZE` holds it; one more name than fits is `Oversize` (build
  the oversize `Saved` by hand, past the caps); every single-byte corruption of a frame (each
  offset, flipped) is refused; a payload with trailing bytes, a count over its cap, a bad label, a
  name that is not normal, a PIN line of other rounds, hour 24 or equal hours are refused; the
  same state encodes to the same bytes.
- [ ] `state/store.rs`: `trait Medium { fn read(&self, copy: Copy) -> io::Result<Vec<u8>>; fn
  write(&self, copy: Copy, frame: &[u8]) -> io::Result<()>; }` (`Copy::A`/`Copy::B`, name it
  `Which` if `Copy` clashes), and `Store` that remembers each copy's validity and sequence:
  `Store::load(bytes_a: Option<&[u8]>, bytes_b: Option<&[u8]>) -> (Store, Loaded)` where `Loaded`
  says which copy won (or none, and why: absent / not whole) and gives the `Saved` and its payload
  bytes; `Store::save(&mut self, medium: &dyn Medium, payload: &[u8]) -> Result<(Which, u64),
  SaveError>` (target and sequence as above; on a write error the target is marked not valid and
  the newest stays). Tests with an in-memory medium: round trip through save then load; a torn
  write (for each of a set of offsets across the frame, the target copy is cut at that offset
  over its old bytes, or one byte of it flipped) loads the other copy's state; both invalid loads
  empty; the sequence wraps (newest at `u64::MAX`, the next save is 0 and wins); saves alternate
  copies; a failed write leaves the other copy newest and the next save targets the same copy;
  equal sequences prefer `a`.
- [ ] `state/debounce.rs`: `POLL = 5 s`, `QUIET = 30 s`, `MIN_GAP = 60 s`, and a small pure
  `Debounce` on `tokio::time::Instant`: `seen(&mut self, bytes_changed: bool, now)`, `saved(&mut
  self, now)`, `due(&self, now, differs_from_saved: bool) -> bool`. Tests: nothing is due before
  30 s of quiet; a change at 20 s restarts the quiet; a second save waits for 60 s after the first
  began even when quiet; nothing is due when the bytes equal the saved ones. Use
  `#[tokio::test(start_paused = true)]` and `tokio::time::advance`, never the wall clock.
- [ ] Gates, commit (`state: the kept settings, their frame, two copies and the timing`).

### Task 2: the structures give and take their kept state; the switch; the LOCK text

**Files:** `crates/qberrypi/src/watch/devices.rs`, `names.rs`, `panel/lock.rs`, `config.rs`,
`qberrypi.example.toml`, `crates/qb-panel/src/os/world.rs`, `crates/qb-panel/src/os/screens/system.rs`,
`crates/qberrypi/src/panel/mod.rs` (where `LockView` becomes the world), and their tests.

- [ ] `Devices::kept(&self) -> SavedDevices` (sorted sets, labels in order) and
  `Devices::restore(&mut self, saved: SavedDevices)`: sets the pushed lists, the pushed mode, the
  labels and the known set (capped as the setters cap), marks the known set as restored, leaves
  `state` `Waiting`, logs nothing, and republishes exactly as a push does (`refresh_exempt`,
  `publish_mode`). The `tick` change of the design (restored set: held devices raised, not
  learned). Tests: kept→restore→kept is the same; the DNS side's exemption reflects a restored
  exempt list and a restored mode; a restored known device is never held or raised; with a
  restored set, the ten minutes raise the held newcomers; without one, they learn as today; the
  API's `known_list` is still `waiting` after a restore.
- [ ] `OwnerList::kept(&self) -> Vec<SavedName>` and `OwnerList::restore(&self, names:
  Vec<SavedName>) -> Result<(), NamesError>` (through `commit`, so the resolver gets them; an
  entry that fails is a refused whole restore, which the caller logs as one line). Tests: round
  trip; a restored refused name is blocked by the resolver; days kept.
- [ ] `PanelState`: keep the configuration's PIN fingerprint and night (from `new`), a `kept:
  bool` given by a new `with_kept(bool)` builder (persistence on), `PanelState::kept_state(&self)
  -> SavedPanel` and `PanelState::restore(&self, saved: SavedPanel)` by the rules of the design
  (no change to `Lock::new`, the configuration path stays as it is). `LockView` gets `kept:
  bool`. Tests: an API PIN and a panel PIN round trip with their sources; a configuration PIN is
  not kept; a saved PIN under another configuration PIN is not put back, nor a saved night under
  another configuration night; the wrong-PIN count starts at 0 after a restore.
- [ ] `config.rs`: a `[state]` table with `persist` (bool, default true); unknown keys refused as
  the other tables refuse them; `Config::state.persist`. `qberrypi.example.toml`: the table,
  commented as the others are, one or two lines on what it keeps and that a save writes only its
  own two files. Tests as the neighbours'.
- [ ] qb-panel: `World::lock_kept`, the LOCK texts of the design, their test extended for both
  values; `panel/mod.rs` sets it from `LockView::kept`.
- [ ] Gates, commit (`state: the inventory, the names and the lock give and take what is kept;
  [state] persist`).

### Task 3: the card and the saver, wired

**Files:** `crates/qberrypi/src/sys.rs` (the two ioctls), `state/card.rs` (new),
`state/saver.rs` (new), `init.rs`, `services.rs`, and tests.

- [ ] `sys.rs`: `fs_block_size(&File) -> io::Result<u32>` (`FIGETBSZ`, 2) and `fs_block_of(&File,
  logical: u32) -> io::Result<u32>` (`FIBMAP`, 1), through `libc::ioctl`, documented.
- [ ] `state/card.rs`: the real medium. `map(file) -> io::Result<Vec<Extent>>`; `CardCopies {
  extents per copy, digest per copy }`; `read_at_boot(boot_dir, device) -> BootRead` (both files
  read whole if they exist at `FILE_SIZE`, mapped, checked against the raw device; says what it
  found, never panics); `RawMedium` implementing `Medium` over the device path and the extents,
  with the read-back digest check before a write and `sync_all` after; `create(boot_dir, device)`
  for the one creation. Make the device a path and the mapper a trait so that host tests can use a
  plain file as the "device" and a fake mapper that places the files' bytes in it; FIBMAP itself
  is proved only in QEMU.
- [ ] `state/saver.rs`: the poller of the design as an async fn over small traits or closures
  (snapshot, the store and medium behind a blocking writer, the idle check), so that its timing is
  tested with paused time: no save before 30 s of quiet; at most one a minute under steady edits;
  none while not idle, and one once idle again; none when the state comes back to what is saved;
  a save that fails turns it off for the boot; `flush` (for the owner's restart) saves at once
  when the bytes differ and not otherwise.
- [ ] Wiring: init's step 3 reads the files in its read-only mount on both layouts (it costs two
  80 KiB reads) and keeps a `BootRead` for the services; `services::Context` carries it and the
  card handle (a small trait implemented in init over `claim_card` and `on_card`, so the saver
  shares the one claim with every other writer, and is refused while a fatal rescue has the card).
  `Lazy::make` restores into the inventory, the names and the panel state before any service
  serves, when `cfg.state.persist`, and logs the line of the design; a new essential-or-not
  component (match how the analysis is, and add it to `SERVICES` after the API) runs the saver.
  init's way out, for `Cause::Owner` only, flushes before the log save. With `persist = false`
  nothing is read, written or created.
- [ ] Gates including `cargo xtask build && cargo xtask qemu-test` (the existing scenarios must
  stay as they are: a boot that changes nothing or changes and changes back writes nothing; if a
  self-test leaves the state changed for more than 30 s, find out why before you touch a check).
  Commit (`state: kept on the card in place, two copies, saved after 30 s of quiet`).

### Task 4: a QEMU scenario, and the docs

**Files:** `xtask/src/qemu.rs`, `crates/qberrypi/src/selftest.rs` (or a new self-test argument),
`docs/reference.md`, `README.md`.

- [ ] A scenario on a slot card with two boots: the first sets a label, an exempt MAC, a refused
  name and the night through the API, then asks the owner's restart (`Cause::Owner`, which
  flushes); the second reads them back through the API and logs them, and the conditions check
  the lines, that `qberrypi-state/a.bin` and `b.bin` exist at `FILE_SIZE`, that the first boot
  logged `state: made the two copies on the card` and `state: saved to copy a (seq 1)`, and that
  nothing else on the card changed but those two files (compare with the image before).
- [ ] `docs/reference.md`: every "kept in memory only" passage for the kept state (lines around
  179, 199, 215, 226, 274–281, 304 and the "writes nothing to the card" paragraph near 121),
  the LOCK texts, the `[state]` table, the log lines, and a short "What is written to the card"
  section: the two files, when, how (in place, raw, one copy at a time) and why a power cut cannot
  damage the rest. README's "Hard to break" bullet: plain and friendly, e.g. "Pulling the plug is
  always safe: the only thing it writes while it runs is your settings, a minute or so after you
  change them, into one of two copies, so a cut mid-write leaves the other one whole."
- [ ] Gates including `cargo xtask build && cargo xtask qemu-test`, commit.
