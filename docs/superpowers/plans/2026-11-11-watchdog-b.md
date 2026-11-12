# Watchdog track B: behaviour alerts, device watch, the alert store and its API

Branch `wd-b` from `qbp-v1` at 1d38a13, worktree `~/Work/qberrypi-wd-b`. Spec:
`docs/superpowers/specs/2026-11-11-qberrypi-watchdog-design.md`, sections 2, 3 and 5, and the
analysis feed of hard rule 1. Track A (threat blocking, DoT, ECS, bypass, prefetch) runs beside this
one and owns `dns/upstream.rs`; this plan does not touch that file.

Execution: one fresh Sonnet implementer per task, in order, no per-task review; one Opus review of
the whole branch at the end and one fix wave for its Critical and Important findings. Ledger:
`.superpowers/sdd/2026-11-11-watchdog-b/progress.md`.

## Gates (every commit)

`TMPDIR=$PWD/target/tmp` (made first), then:

- `cargo test --workspace`
- `cargo clippy --workspace --all-targets` with 0 warnings
- `cargo fmt --all --check`
- `cargo build -p qberrypi --release --target aarch64-unknown-linux-musl`
- `grep -rln unsafe crates/qberrypi/src crates/qberrypi/tests` prints only `crates/qberrypi/src/sys.rs`
- a commit touching `init.rs` or `xtask/`: `cargo xtask build && cargo xtask qemu-test`, all ok

Commits stage files by name, end with a `Co-Authored-By:` trailer naming the model, and are never
pushed. Tests use 192.0.2.x / 198.51.100.x addresses, `02:00:00:…` MACs and example.org names only.

## Rulings of this plan

- **R1 The shared interface.** `crates/qberrypi/src/alerts/mod.rs` holds exactly the three items the
  brief gives (no derives, no doc comments beyond a one-line module doc, which both tracks copy
  verbatim) plus `pub struct NullSink;` and its empty `raise`. Nothing else goes in that file, so
  that track A's copy merges as the same bytes. The store and everything else of this track lives
  under `crates/qberrypi/src/watch/`.
- **R2 The feed is fed by the listener.** The listener knows the client; `Dns::decide` does not.
  Each reply the listener sends (UDP receive loop, UDP forward task, TCP connection) is offered with
  `Dns::observe(client, &reply)` once it is sent (after `try_send_to`, `send_to` or `write_all`, so
  the answer goes out first; a reply that could not be sent is not offered). Our own lookups (`lookup_v4`, prefetch) are not observed. The
  event copies the question name from the reply's wire bytes into a fixed array, with the qtype, the
  rcode and the first answer's TTL; no allocation, no clock read, no lock. The channel is
  `std::sync::mpsc::sync_channel(FEED_CAPACITY = 1024)` (array-backed, allocation-free `try_send`);
  full or disconnected adds 1 to `watch_events_dropped`. With no watch set (`OnceLock` empty) observe
  is one atomic load.
- **R3 Events are stamped when drained.** The analysis is a component future that drains the channel
  every 250 ms (at most 4096 events per drain, so it never holds the runtime thread near 1 s) and
  stamps each with the drain's monotonic time. 250 ms is fine resolution for every detector.
- **R4 Rebinding is screened in `Dns::exchange`,** in the closure that hands upstream packets to the
  resolver (dns/mod.rs, not upstream.rs). If the pending name is public and not allowed and the
  packet's answer section holds an A/AAAA in a private (RFC 1918, fc00::/7), loopback or link-local
  range (IPv4-mapped included; 0.0.0.0 and :: are not private: upstreams that block send them), the
  resolver is handed a copy with every A/AAAA address zeroed (0.0.0.0 / ::), the same answer a
  blocked name gets, so the cache holds the rewritten answer too. The scan walks the wire format
  without allocating; only a match copies. The alert (`rebind`, High, subject the name, client the
  asking client or `None` for a stale renewal) is raised only when the resolver accepted the packet
  (`Reply` or `Refreshed`), so a mismatched or hostile packet raises nothing. The sink is not called
  inside `exchange`: a tiny `tokio::spawn`ed task raises it (only on a match, so the allocation is
  rare), and the reply goes out first. It applies while
  blocking is paused too. Public means: has a dot, does not end in `local`, `lan`, `home`,
  `internal`, `localdomain`, `home.arpa` or `arpa`, and is not under a `watch.rebind_allow` entry
  (default `["plex.direct"]`, which answers private addresses by design). A DNSSEC client that asked
  with DO gets RRSIGs that no longer validate; that also fails closed, which is accepted.
- **R5 Merge keys and the ack key.** Alerts merge on (kind, client, subject). Each alert carries
  `key`, 16 hex digits of FNV-1a 64 over `kind \0 client-or-empty \0 subject`, stable across boots.
  `PUT /api/qbp/alerts/acked` takes keys and **adds** them (capped at 1024, oldest out), so qnet may
  send them in several bodies under the API's 4 KiB body cap; an alert raised whose key was restored
  is created acknowledged.
- **R6 `since` is a revision.** The store has a revision counter bumped by every change (new alert,
  merge, ack). Each alert carries the revision of its last change; `GET /api/qbp/alerts?since=R`
  returns those changed after R and the current revision. A clock step never loses an alert.
- **R7 Stable subjects.** Subjects never hold a per-event detail, so repeats merge: `dga` "random
  NXDOMAIN names"; `tunnel` the registrable domain, or "TXT/NULL share"; `beacon` the name; `burst`
  "question rate"; `rebind` the name; `new_device` the MAC; `arp_spoof` the claiming MAC with client
  the gateway's address. Track A's `threat` is theirs.
- **R8 Rate limits.** At most 20 new alerts per kind in a rolling hour (`beacon` 10); a merge is not a
  new alert. A new alert over the limit is dropped and counted (`suppressed`, shown in the GET). The
  ring holds 256 alerts; when full, the oldest acknowledged goes first, then the oldest.
- **R9 Severity.** `dga` High, `tunnel` High, `rebind` High, `arp_spoof` High, `burst` Warn,
  `new_device` Warn, `beacon` Info.
- **R10 Device watch sockets.** ARP: the existing `sys::packet_socket(ifindex, 0x0806)` (no new
  unsafe). DHCP and mDNS: ordinary UDP sockets on 0.0.0.0:67 and 0.0.0.0:5353 (SO_REUSEADDR through
  rustix's safe sockopt, mDNS joined to 224.0.0.251 on wlan0's address); a client's DHCP DISCOVER
  and REQUEST are broadcasts and reach a socket on 67, and they carry `chaddr`, option 12 and option
  50. A packet socket for all of IPv4 would copy every DNS packet of the household and is not used.
  wlan0 is found through `/sys/class/net/wlan0/{ifindex,address}`. Without it (QEMU), the component
  checks every 30 s and logs once at debug level; it never ends, never WARNs in a loop, and has no
  part in the 90 s rule. A socket error logs one WARN for a run of failures, then reopens after 30 s.
- **R11 Known list.** `PUT /api/qbp/devices/known` takes `{"known": [...], "append": bool
  (default false), "complete": bool (default true)}`: `append: false` replaces the known set,
  `true` adds to it (cap 1024 still); holds are released or dropped and unlisted never-alerted
  devices raised only when `complete` is true, so a list longer than the 4 KiB body is sent as
  `{append:false, complete:false}`, `{append:true, complete:false}`…, `{append:true, complete:true}`.
  A list on its way is kept apart and replaces the set only with its last chunk (the old set stays
  in force meanwhile, so the devices of later chunks are not raised); the reply is `{"known": <size
  of the set so far>}`, and flags of a wrong type are a 400 with nothing changed. Until a list
  arrives after boot, new-device alerts are held (cap 64). When it arrives: held MACs on it are
  dropped, the rest raised, and any device in the inventory not on it that was never alerted is
  raised. With no list 600 s after the first sighting of any device (an `Option<u64>` set the first
  time a device is recorded, not at construction), every device seen is learned as known silently
  and held alerts are dropped; with nothing heard, nothing is learned and the state stays Waiting. A
  list that arrives later is applied as above. The Pi's own MAC is never a device. A new-device
  alert's client is `None`: the MAC subject alone is the merge and ack key, so the key is stable
  across boots and IP changes (the addresses are in `GET /api/qbp/devices`). A device is not alerted
  once per boot but at most once per 3600 s (`alerted_at`): a still-unknown device is raised again
  on a later sighting after the hour, so an alert that the store's rate limit dropped is delivered
  later (repeats merge in the store).
- **R12 ARP spoofing.** The gateway is `net.gateway`. The first ARP sender claiming it fixes the
  gateway MAC for the boot; any later ARP claiming the gateway's address from another MAC raises
  `arp_spoof`. The fixed MAC is never replaced by a claim.
- **R13 Logs.** Behaviour, rebinding and devices log only kinds and counts: never a client address,
  a name, a MAC or a host name. The store logs `watch: alert <kind> (<severity>)` for a new one.
- **R14 Configuration.** An optional `[watch]` section: `rebind_allow` (names, default
  `["plex.direct"]`) and `quiet` (names, default empty: the behaviour detectors skip a question
  under one of these; the owner's "marked as fine"). Kept as one small parse function in config.rs.
- **R15 Wiring last.** `services.rs` and the API component are rebuilt by m7-serve. The wiring task
  (Task 10) starts only after the session lead says m7-serve and m6-cutover are in `qbp-v1` and this
  branch has merged it; without that message the track stops and reports before Task 10.

## Detector thresholds (constants with tests, Task 4)

Per client, at most 128 clients (least recently seen evicted), each with bounded state:

- **DGA:** in a 300 s window, 25 distinct NXDOMAIN names whose registrable label looks random. Not
  counted: single-label names (Chrome's probes), `arpa`, local suffixes. Looks random: 8+ chars of
  `a-z0-9` and one of: a consonant run of 5+, vowels under 20 % of letters, 3+ letter/digit
  alternations, or for 12+ chars a Shannon entropy of at least 0.9 × log2(len).
- **Tunnelling:** in a 600 s window, 40 distinct names under one registrable domain whose part left
  of it is 40+ bytes (at most 8 domains tracked per client, 64 hashes each); or 100+ TXT/NULL
  questions that are 50 %+ of the client's questions in the window. A name with a byte that no host
  name has (iodine's Base64 `+`, Base128 bytes from 0x80) is not skipped: it counts for the burst
  and the TXT/NULL share, and for the long names when the labels of its registrable domain decode
  (taken leniently from the end), the distinct name being a hash of the raw wire bytes left of the
  domain, and it is long when that part is 40+ bytes or holds an odd byte and is 20+. DGA and
  beaconing skip such names.
- **Beaconing:** one name (32 slots per client) asked 30+ times over 3+ hours at a mean interval of
  30 s to 1 h with a coefficient of variation of 0.1 or less, and not cache-bound: per name the slot
  keeps the TTL of the previous answer, notes for each counted interval whether it lies within
  0.8–1.25 × the TTL the client was given on its previous ask (a TTL of 0 never counts), and the
  name is cache-bound when at least half its intervals did (re-asking at TTL expiry is a cache, not
  a beacon; the resolver's cache hits carry the time left and stale answers 30 s, so a min/max band
  over all answers would exempt everything). Repeats within 2 s count once (A and AAAA pairs; of
  the pair the larger TTL is the one given). Skipped: NTP pools, connectivity checks (`connectivitycheck.gstatic.com`,
  `captive.apple.com`, `msftconnecttest.com`, `detectportal.firefox.com`, …), push services
  (`mtalk.google.com`, `push.apple.com`), and `watch.quiet`.
- **Burst:** per-minute counts with an EWMA baseline (factor 1/8), armed after 10 minutes; a minute
  of at least max(300, 10 × baseline) raises.
- Registrable domain: the last two labels, or three when the second-to-last is 2–3 chars and the
  last is 2 chars (`co.uk`); an approximation, as there is no public suffix list on the board.
- A "normal household" trace (a few phones, a TV, a laptop: browsing bursts, CDN names, periodic
  cloud checks at TTL intervals, a few typos, Chrome probes, TXT for a mail check) raises nothing.

## Tasks

### Task 1: the alert interface and the store
Files: `alerts/mod.rs` (R1), `watch/mod.rs` (module doc + `pub mod store;`), `watch/store.rs`,
`lib.rs` (`pub mod alerts;`, `pub mod watch;`).
`AlertStore` (a `Mutex` inside, clock injected as `Arc<dyn Fn() -> (u64 mono, u64 unix)>`):
`raise` via `impl AlertSink`, `list(since) -> (rev, Vec<AlertView>, suppressed)`, `ack(id) -> bool`,
`restore_acked(keys) -> usize`, `AlertView` with id, key, rev, kind, severity text, client, subject
(cut to 255 bytes at a char boundary), first/last unix, count, acked. R5–R9, R13.
Tests: merge, rate limit per kind with rolling hour, ring eviction order, ack by id, restored keys
ack existing and future alerts, revision cursor, key stability (a fixed expected hex), subject cut.

### Task 2: the feed and the DNS hook
Files: `watch/mod.rs` (`Feed`, `Event`, `FEED_CAPACITY`), `watch/names.rs` (wire name → lower-case
text into a caller buffer, registrable domain, local-suffix test, `looks_random`), `dns/mod.rs`
(`watch: OnceLock<Watch>` field, `set_watch`, `observe`, `watch_events_dropped`), `dns/listen.rs`
(observe in the three reply places; TCP keeps the peer address from `accept`), `status.rs`
(`"watch_events_dropped"`, 0 with no watch). R2, R3.
`Event { client, qtype, rcode, ttl, name_len, name: [u8; 255] }` read from the reply: header rcode,
one question at offset 12 (no pointer), first answer's TTL if any; a reply that is not that shape is
not offered.
Tests: events for a cached, a blocked, a forwarded (UDP and TCP) answer carry the client and name;
`lookup_v4` offers none; a full channel counts drops and never blocks; the stats key; names helpers.
Hot path: an `#[ignore]` timing test printing ns per `observe` (watch set and unset) and a timing
assertion with a generous bound (under 20 µs mean on the host).

### Task 3: rebinding
Files: `watch/rebind.rs` (`RebindPolicy`, `is_public`, `private_answer(packet) -> bool`,
`zero_addresses(packet) -> Vec<u8>`), `dns/mod.rs` (screen in `exchange`; `client` passed through a
new `carry_for(action, client)` and `answer_for(packet, transport, client)`, with `carry` and
`answer` kept as wrappers so other callers do not change), `dns/listen.rs` (pass the client),
`config.rs` (`[watch]`: R14), `qberrypi.example.toml` (a commented `[watch]` block). R4.
Tests: a forwarded answer of 192.0.2.x passes; one of 10.0.0.1, 127.0.0.1, 169.254.1.1, fd00::1,
fe80::1, ::ffff:10.0.0.1 is answered 0.0.0.0/:: and so is the next (cached) one, with one alert
carrying the client; an allowed name and a `.lan` name pass; a mismatched packet with a private
address raises nothing; compressed names, CNAME chains and malformed packets in the scanner; config
parse and errors. Hot path: `#[ignore]` timing of `private_answer` on a 4-record answer (ns per
call) plus a generous assertion.

### Task 4: the behaviour detectors
Files: `watch/behaviour.rs`. `Behaviour::new(quiet: Vec<String>)`, `observe(&Event, now_ms, &mut
impl FnMut(Alert))`. Thresholds and bounds above, as named constants.
Tests: each detector fires on a synthetic trace and stays quiet just under its threshold; the
household trace raises nothing; client cap and eviction; per-client state stays bounded under a
flood of distinct names (assert table lengths).

### Task 5: the analysis component
Files: `watch/analysis.rs`: `run(rx, behaviour, sink) -> !`-like future (never ends) draining every
250 ms, at most 4096 events per drain (R3). Tests with tokio's paused clock: events offered through a
`Feed` reach the sink as alerts; a drain is bounded; a dropped sender does not spin.

### Task 6: device frames
Files: `watch/frames.rs`: `parse_arp(frame) -> Option<Arp { op, sender_mac, sender_ip, target_ip }>`
(Ethernet + ARP, IPv4 over Ethernet only), `parse_dhcp(payload) -> Option<Dhcp { chaddr, msg_type,
hostname, requested_ip, ciaddr }>` (BOOTREQUEST, magic cookie, options bounded, pad/end), and
`parse_mdns(payload, &mut impl FnMut(Ipv4Addr, &str))` (A records in answers and additionals, name
ending `.local`, label decoding with compression and a loop bound). Host names: printable ASCII,
63 bytes at most. Tests with crafted frames, truncated and hostile ones (pointer loops, lengths past
the end).

### Task 7: the inventory
Files: `watch/devices.rs`: `Devices::new(own_mac, gateway, clock)`, `on_arp`, `on_dhcp`, `on_mdns`
(mDNS host names attach to the MAC that ARP gave the address), `set_known(macs)`, `tick()` (the
10-minute learning), `view() -> Vec<DeviceView>` and the list state. The inventory never calls a
sink: its methods put alerts into an internal bounded `Vec<Alert>` (64; beyond that dropped and
counted, and a dropped new-device alert leaves its device unalerted), `take_alerts()` takes them, and
every caller takes them while locked and raises them through the store after the guard is dropped
(`with_devices(&Mutex<Devices>, &dyn AlertSink, call)`). Caps: 512 devices (least recently seen out),
4 IPv4 per device. R11, R12, R13.
Tests: inventory merge of the three sources; new device held, released, dropped; learning at 10 min;
late list; spoof from another MAC; first claim fixes the gateway; own MAC ignored; caps.

### Task 8: the device watch component
Files: `watch/devwatch.rs` (R10), and `sys.rs` only if something needs `unsafe` (expected not).
`run(devices, iface: &str) -> never-ending future`: waits for the interface, opens the three
sockets, reads them with `tokio::select!`, calls the `Devices` methods, calls `tick` every 30 s.
Tests: no interface → stays pending quietly (paused clock, no WARN recorded); in a `testns`
namespace (the existing helper), a frame on a veth or a datagram on 67/5353 reaches `Devices`.

### Task 9: the API endpoints
Files: `api/qbp.rs` (handlers), `api/mod.rs` (`pub mod qbp;`), `api/routes.rs` (an
`Option<Arc<qbp::Watch>>` field set by `Api::with_watch`, and one branch after the session check:
a path under `/api/qbp/` goes to `qbp::handle`, 404 when no watch is set; `ok`/`error`/`reply`
made `pub(super)`). Endpoints, all behind the login:
- `GET /api/qbp/alerts[?since=R]` → `{"rev", "suppressed", "alerts": [...], "took"}`
- `POST /api/qbp/alerts/{id}/ack` → `{"acked": true}` or 404
- `PUT /api/qbp/alerts/acked` with `{"acked": ["<16 hex>", ...]}` → `{"restored": n}`
- `GET /api/qbp/devices` → `{"known_list": "waiting"|"received"|"learned", "devices": [{"mac",
  "ipv4", "hostname", "first_unix", "last_unix", "known"}]}`
- `PUT /api/qbp/devices/known` with `{"known": ["02:00:00:00:00:01", ...], "append": false,
  "complete": true}` (the flags are optional; chunks per R11) → `{"known": n}`
Other methods 405, other paths and bad query strings 404, bad bodies 400. Tests through
`Api::handle` with a session: each endpoint, no session is 401, wrong method 405, bad bodies.

### Task 10: wiring (gated by R15)
After the lead's message and a merge of `qbp-v1`: in `services.rs` make the store, the `Feed` and
`Behaviour` from `cfg.watch`, `dns.set_watch`, the analysis component and the device watch component
(both non-essential, never ending), and `Api::with_watch`. A QEMU scenario (or an existing one's
log check) that the board starts with no wlan0 warning from the watch and the DNS stats carry
`watch_events_dropped`. Full gates including `cargo xtask build && cargo xtask qemu-test`.

## Pi checks for the session lead (after Task 10)

1. Deploy one-shot; the boot log has no `watch` WARN; `/api/v1/stats` shows `watch_events_dropped: 0`
   after normal use.
2. `GET /api/qbp/devices` with the login lists the household's devices with host names; `PUT
   /api/qbp/devices/known` with them, then a new device (a phone's guest MAC) raises `new_device`.
3. `dig @pi <a public name that answers 10.x>` (a test record the owner controls, or a rebinding test
   service) answers 0.0.0.0 and raises `rebind`.
4. `cargo xtask latency --compare` against same-evening stock: exit 0 in both pacings.
