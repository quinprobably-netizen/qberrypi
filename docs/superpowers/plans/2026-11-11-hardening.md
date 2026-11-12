# Hardening pass

Branch `harden` from `qbp-v1` at d8b9996, worktree `~/Work/qberrypi-harden`. Spec (binding):
`docs/superpowers/specs/2026-11-11-qberrypi-watchdog-design.md`, its hard rules first. Rulings:
`docs/superpowers/plans/2026-11-10-execution-order.md` (ruling 17, latency, binds every task).

Execution: one fresh Sonnet implementer per task, no per-task review; one Opus review of the whole
branch, one fix wave for Critical and Important findings; minors listed and deferred. Ledger:
`.superpowers/sdd/2026-11-11-hardening/progress.md`.

Two lanes, so that no implementer compiles another's half-finished tree:

- lane A in `~/Work/qberrypi-harden` (branch `harden`): T1, then T2, then T2b;
- lane B in `~/Work/qberrypi-harden-b` (branch `harden-b`, from d8b9996): T3, then T4;
- the lead cherry-picks lane B onto `harden`; T5 and T6 then run on `harden`, in order.

Hands off: `crates/qb-panel/` and `crates/qberrypi/src/panel/mod.rs` (track `panel-drain-r6` edits
them). `panel/fb.rs` is touched only where T3 says.

## Gates (every commit)

`TMPDIR=<worktree>/target/tmp` (made first), then:

- `cargo test --workspace`
- `cargo clippy --workspace --all-targets` with 0 warnings
- `cargo fmt --all --check`
- `cargo build -p qberrypi --release --target aarch64-unknown-linux-musl`
- `grep -rln unsafe crates/qberrypi/src crates/qberrypi/tests` prints only `crates/qberrypi/src/sys.rs`
- a commit touching `init.rs` or `xtask/`: `cargo xtask build && cargo xtask qemu-test`, every
  scenario ok (`cargo xtask fetch-lists` first if the build asks). Leftover QEMU: `pgrep -x qemu-system-aar`.

Commits stage files by name, end with a `Co-Authored-By:` trailer naming the model, and are never
pushed. Tests use 192.0.2.x / 198.51.100.x, `02:00:00:…` MACs and example.org names only. Never read
`~/Work/qberrypi/qberrypi.toml`; the worktree's `qberrypi.toml` is a dummy.

## Rulings of this plan

- **H1 Radio commands leave the runtime thread on a thread of their own.** brcmfmac answers an
  nl80211 command (and an rtnetlink one that reaches the driver: setting `wlan0` up, adding its
  address, which runs the driver's ARP-offload notifier) inside `sendmsg(2)`, up to about 2.5 s per
  firmware command when the firmware does not answer. A netlink socket can be opened *offloaded*:
  its `send(2)` runs on one dedicated OS thread per socket (named `nl send`), which does nothing but
  send the datagrams handed to it, in order, and wipe them. The reply is still read on the runtime
  through the socket's `AsyncFd` (the kernel has queued it by then; a `recv` is a copy). The runtime
  side awaits a `tokio::sync::oneshot`; the wait for the send is bounded by `REPLY_TIMEOUT`, and so
  is the wait for the reply after it, so one request is bounded by 2 × `REPLY_TIMEOUT` = 10 s. The
  thread ends when its socket is dropped. Ruling 1 holds: no second runtime, the thread polls no
  future. Ruling 8 holds: the blocking pool stays 5, because a radio command queued behind a list
  parse there would delay a rekey's key install by seconds. Offloaded: the Wi-Fi component's
  sockets only (`KernelRadio`'s nl80211 command socket and its `Route`, and the `Route` that
  `wifi_service` addresses `wlan0` with). Inline as today: the boot's `start_network` (before DNS
  serves), the device watch and the tests' sockets. The 90 s rule and the pet are untouched: the
  runtime thread is no longer held at all.
- **H2 Liveness while joined is a station query.** Every `PROBE_EVERY` = 10 s of a hold, whatever the
  traffic, `hold` asks the radio about the joined access point (`NL80211_CMD_GET_STATION`, attributes
  ifindex and MAC). A probe succeeds when the reply holds a station message for that MAC. It fails on
  any error, a timeout, `Busy`, or a reply without that station. `PROBE_FAILURES` = 3 failures in a
  row end the hold: it leaves with `Lost::Radio("the radio stopped answering: <last error>")`, which
  logs `wifi: link lost: …` and leaves `Joined`. One success resets the count. The query is answered
  by the firmware from its own association state and does not depend on traffic, so a quiet healthy
  link always passes; three in a row guard against one slow answer. Bound: a radio that dies
  silently is `link lost` within 3 × (10 s + 10 s) = 60 s; the 90 s rule then restarts the board if
  it stays dead, 150 s after the death at most (plus one `leave` disconnect, itself bounded). The
  cost on a healthy link is one firmware query every 10 s (the `signal` component already makes the
  same query through `/proc/net/wireless` every 5 s). Not chosen: a gateway ARP check (needs the
  address set, sends frames, and a quiet gateway can be slow to answer).
- **H3 The card and the LED go by one small state machine shared with the rescue.** A `static BOARD:
  Mutex<Board>` (held only for a state change, never across I/O on the card) records who holds the
  card (`None`, or the thread) and the fatal error's thread. Rules: (a) a use of the card claims it
  under the mutex, and the claim refuses if a fatal error has begun on another thread, so the
  check and the claim are one step; (b) a claim that finds the card held waits up to
  `CARD_LOCK_WAIT`, polling; when the wait runs out only the fatal error's own thread (the rescue)
  goes on without the claim; every other thread gives up with `card_under_rescue` or a new "card
  busy" error, logged as a warning; (c) `begin_fatal` sets the fatal thread under the same mutex (and
  `FATAL_THREAD`, which `may_pet` keeps reading lock-free) and writes the LED's `Fatal` before it
  lets go; `show_led` writes under the mutex only if no fatal error has begun, so "solid on fatal"
  cannot be overwritten; a `show_led` that finds the mutex held by a stuck holder gives up after
  `LOG_LOCK_WAIT` without writing (it runs on the runtime thread: 200 ms at worst, only when
  something already failed); (d) the way out (`wind_down`, `stall_save`) claims the card and keeps
  the claim through the restart, so no pool save can begin under the restart. `CARD_BUSY` goes.
- **H4 The framebuffer mapping hands out no reference.** `SharedMapping` loses `as_mut_slice`; it
  gains `len`, `changed_rows(&self, frame, row_bytes) -> Option<Range<usize>>` (the same answer as
  `qb_panel::rows::changed_rows`, read with `read_volatile`, a `u64` word at a time where both sides
  allow it) and `write(&mut self, at, bytes)` (bounds-checked, `ptr::copy_nonoverlapping`). All the
  `unsafe` stays in `sys.rs`; `panel/fb.rs` changes only its draw arm.
- **H5 Latency.** No task adds work to a cached, blocked or forwarded answer. Where a task touches a
  path a question takes (T6's alert and DoT items), its implementer reports a host timing.

## Tasks

### T1 (lane A) Radio commands off the runtime thread — scope item 2

Files: `netlink/socket.rs`, `netlink/nl80211.rs`, `netlink/route.rs`, `wifi/kernel.rs`,
`init.rs` (only `address_wlan`/`configure_over`'s `Route::open`), `sys.rs` only if a helper is needed.

- `NlSocket::open_offloaded(protocol)` per H1; `request` unchanged in signature. The sender is a
  seam for tests (an injected `send` function), so a test can make one send take 2.5 s.
- `Nl80211::open_offloaded()` and `Route::open_offloaded()`; `KernelRadio::open` and init's Wi-Fi
  route use them.
- The request bytes stay wiped: sent or not, dropped future or not, the bytes the thread got are
  zeroized (`Zeroizing`).

Tests: a 2.5 s injected send leaves the runtime thread's longest gap under 50 ms (use
`services::testutil::longest_gap`) and the request still completes; a send that never returns ends
the request with `RequestError::Timeout` within the bound and the next request on the socket still
works or fails bounded; in a test namespace (`testns::run_inside`) a real offloaded `Route` request
works and its `send` ran on a thread other than the runtime's (record the thread id through the
seam); `KernelRadio::open` asks for offloaded sockets (a small assertion or a type-level fact,
whichever is honest). Existing netlink tests unchanged.

Acceptance: gates incl. QEMU (init.rs). Report the longest-gap figures before (inline socket with
the slow seam) and after.

### T2 (lane A, after T1) Dead-radio detection — scope item 1

Files: `netlink/nl80211.rs` (builder `get_station`, parser of the reply's MAC), `wifi/radio.rs`
(`async fn probe(&mut self, peer: MacAddr) -> Result<(), RadioError>`), `wifi/kernel.rs`,
`wifi/fake.rs`, `wifi/join.rs` (`hold`), `wifi/mod.rs` tests.

- `hold` per H2: a `tokio::time::interval` (missed ticks delayed, first tick after 10 s) beside
  `next_event` in a `select!` (`next_event` is cancel-safe); on the tick, `probe`; count failures.
- `get_station` golden bytes test, like the other builders.
- The fake radio answers probes `Ok` by default and can be scripted to fail from a moment on.

Tests, on tokio's paused clock: a quiet healthy link held 10 minutes has no loss and about 60
probes; a radio whose probes fail from 100 s on is `link lost` with the new line by 100 + 30 s plus
the bounds, then rescans; two failures then a success never end the hold; a probe that hangs (a
fake that never answers, bounded by the radio's own timeout in the fake) still ends the hold within
the H2 bound; `run`'s existing tests unchanged in what they assert.

Acceptance: gates (no init.rs: no QEMU unless touched).

### T2b (lane A, after T2) Two development faults for the link checks — coordinator's addition

The owner cannot switch the access point off (the PC shares it), so the board drops its own link.
Files: `config.rs` (`Fault::DropLink` = `"drop-link"`, `Fault::MuteProbe` = `"mute-probe"`),
`fault.rs`, `init.rs` (wiring only), `wifi/kernel.rs` (the mute hook), `xtask/src/deploy.rs` (its
refusal test's word list; the refusal itself already covers every fault), `qberrypi.example.toml`
if it lists the words, `tests/hwsim.rs`.

- **H6 `drop-link`:** a non-essential component `fault` that waits `DROP_AFTER` = 60 s from its
  start (the supervisor's), logs `fault: dropping the Wi-Fi link once`, opens an nl80211 client of
  its own (offloaded) and sends `NL80211_CMD_DISCONNECT` for `wlan0` (reason 3, deauth leaving),
  then waits for ever (it never ends, so the supervisor says nothing more of it). The Wi-Fi task is
  not told: it hears the kernel's disconnect event like any other loss, so the path under test is
  the real one: `wifi: link lost: …` → `wifi: association lost` → rejoin →
  `wifi: associated again after N s`, and DNS answers again.
- **H7 `mute-probe`:** from 60 s after the supervisor starts, the kernel radio's liveness probe
  fails as if the firmware did not answer (no command is sent), for the rest of that one hold only;
  every other command works. T2's rule then ends the hold (`wifi: link lost: the radio stopped
  answering …`) within its bound, and the board rejoins; the next hold's probes answer again. The
  switch is a process-wide one-shot (an atomic set by a small component or by init's tick, cleared
  by the hold that consumed it), so no other path changes.
- Both are refused by `deploy --permanent` (the existing `debug.fault != none` rule; extend its test).

Tests: config parses both words and refuses others as before; the drop-link component on a paused
clock calls an injected disconnect exactly once at 60 s and never ends; the mute switch makes a
fake/kernel probe fail for one hold only (host test through `hold` with the fake radio); QEMU's
scenarios unchanged; an ignored hwsim test (`tests/hwsim.rs`, same harness and ignore text) joins
hostapd, calls the drop-link action and sees `link lost` then a rejoin.

### T3 (lane B) `SharedMapping` soundness — scope item 4

Files: `sys.rs`, `panel/fb.rs` (draw arm only).

Per H4. Tests in `sys.rs`: `changed_rows` agrees with `qb_panel::rows::changed_rows` on equal, one
changed row, first and last rows, rows not a multiple of 8 bytes and an unaligned length; `write`
reaches the file (the existing test, rewritten); an out-of-range `write` panics or errs (pick one,
document it). `fb.rs`'s existing tests pass unchanged. An `#[ignore]` timing test prints a full
307,200-byte compare and a full write, release, host.

Acceptance: gates. `grep -rn "as_mut_slice" crates/qberrypi/src` is empty.

### T4 (lane B, after T3) Card and LED races — scope item 3

Files: `init.rs`.

Per H3, closing: a fatal error beginning on another thread during a save's check; `show_led`
overriding the fatal LED; the stall's (and the way out's) save beside a long pool save; the way out
rebooting under a pool save that begins late. Keep `on_card_within`'s injection style so tests use
their own `Board` and do not share the global (the m4/5 ledger's 5/5 flake came from a shared lock).

Tests: a claim refused once another thread's fatal error has begun, even when the check races (a
test that begins the fatal between the two steps is impossible now; assert the one-step API); a
save holding the card for longer than the wait makes a non-fatal claimant give up and the fatal
thread go on; `show_led` after `begin_fatal` writes nothing (a temp LED dir); the way out's claim
outlives its save (a pool save started after it finds the card claimed); existing card, rescue,
stall and leave tests pass.

Acceptance: gates incl. QEMU.

### T5 (on `harden`, after the cherry-pick) Component registry — scope item 5

Files: `services.rs`, `init.rs`.

One table per file is the most this may be: in `services.rs`, `const SERVICES: &[fn(&Arc<Lazy>) ->
Option<Component>]` listing dns, utc offset, clock, status, lists, analysis, devices, api, each a
small function; in `init.rs` a table of the board's own (wifi, signal, panel, fault) over one
context struct of what they need. `prepare_from` and `serve` iterate them. Same names, order and
essential flags: a test lists `(name, essential)` of the whole board in order and equals today's.
Stop rule: if it needs more than moving code into functions and the two tables (new traits, generic
contexts, changes to `supervisor.rs`), stop, commit nothing, and report the design.

Acceptance: gates incl. QEMU; the diff is moves plus the tables.

### T6 (on `harden`, after T5) Deferred-minor triage and the small fixes — scope item 6

T6a: read every ledger (`~/Work/qberrypi*/.superpowers/sdd/*/progress.md`) and write
`docs/bring-up/deferred.md`: grouped by area (boot and card; Wi-Fi; DNS and upstreams; lists;
watchdog and alerts; API; panel; xtask and deploy; docs and tests), each minor one line: what, then
**fix now** / **fix later** / **won't fix** and one line of reason. Items this plan fixes are marked
with the task. No addresses, names, MACs or anything private. Commit the doc alone.

T6b: the named fixes, one commit each:
- API (m7 M1): an `accept` error is retried after a short pause instead of ending `serve` (with a
  bound: a persistent error still fails the component after N in a row); the connection semaphore
  lives in `ApiParts`, so a restart can never give more than 2 API threads.
- `tls.pem` (m6/m7 M6): a deploy whose configuration has no `[api]` removes a `qberrypi/tls.pem`
  left on the card (xtask; never a write by the board, hard rule 2).
- Alerts (wd-b): an acknowledged alert of a High severity kind that recurs is shown again (rule it
  in the store; Info and Warn keep the merge-into-acked behaviour). Host timing of the raise.
- DoT (wd-a): the handshake waits behind list work on the pool. Either give it a way that does not
  queue there, or write a ruling into `deferred.md` with the reason (answers fall back to UDP while
  connecting, so no question waits for it). Host timing if code changes.
- Any other fix-now item that is one small, safe change.

Acceptance: gates (QEMU for init.rs or xtask commits).

### Final

Opus review of `d8b9996..harden`; one fix wave for Critical and Important; minors into
`deferred.md` and the ledger.
