# Watchdog track A: threat blocking, private lookups, speed — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the threat list class with its alerts, DNS-over-TLS to the upstreams (off by default), ECS stripping, the DoH bypass rules, prefetch and a CPU-placement switch to qberrypi, without slowing any cached, blocked or forwarded answer.

**Architecture:** `qb-dns` gains a one-bit class per block-set entry, a threat hit out of `Resolver`, the DoH canary and a prefetch mark on cache entries. `qberrypi` gains `alerts/mod.rs` (the trait shared with track B), a throttle that raises one threat alert per client per name per hour, `dns/dot.rs` (one warm, pipelined TLS connection per upstream, handshakes on the blocking pool) and a hedged exchange across those connections, a prefetch budget in `Dns`, config keys, and an optional pin of the runtime thread.

**Tech Stack:** Rust 2024, tokio current-thread, rustls 0.23 with `rustls-rustcrypto`, hickory-proto 0.26, rustix 1.x. No new crates (dev: `rcgen` is already there).

**Spec:** `docs/superpowers/specs/2026-11-11-qberrypi-watchdog-design.md` (§1, §4, §6; hard rules first). Rulings: `docs/superpowers/plans/2026-11-10-execution-order.md` (ruling 17 as amended). Track brief: `target/tmp/wd-common.md` in the main checkout.

## Global Constraints

- **No latency regression.** Nothing added may make a cached, blocked or forwarded answer wait. Every hot-path change carries an `#[ignore]` timing test that prints per-question cost (run in release).
- **No card writes.** Everything here lives in RAM.
- **Privacy.** No log line names a client address together with a query name; no log line names a query name at all (existing rule in `dns/`). Alerts carry client and name together in RAM only.
- **One binary.** No new C dependencies, no new crates; `unsafe` only in `crates/qberrypi/src/sys.rs`.
- **One runtime** (ruling 1): no new threads; CPU-heavy work (TLS handshakes) goes through `services::blocking`. No future holds the runtime thread for long.
- **Public repo:** tests use 192.0.2.x / 127.0.0.1, `example.org`/`example.com` names, `02:00:00:…` MACs. Never touch `~/Work/qberrypi/qberrypi.toml`; the worktree's `qberrypi.toml` is a dummy, leave it alone.
- `TMPDIR=~/Work/qberrypi-wd-a/target/tmp` (mkdir it). Do not run `cargo xtask fetch-lists` unless a build asks for it (`vendor-cache` is shared with the main checkout).
- **Gates before every commit:** `cargo test --workspace`; `cargo clippy --workspace --all-targets` with 0 warnings; `cargo fmt --all --check`; `cargo build -p qberrypi --release --target aarch64-unknown-linux-musl`; `grep -rln unsafe crates/qberrypi/src crates/qberrypi/tests` prints only `crates/qberrypi/src/sys.rs`. A commit touching `init.rs` or `xtask/` also runs `cargo xtask build && cargo xtask qemu-test` with every scenario ok.
- Stage files by name (never `git add -A` / `.`); end each commit message with `Co-Authored-By: Claude Sonnet <noreply@anthropic.com>` (or the model that wrote it). Never push.
- Match the house style: doc comments on every item, full sentences, bounds and failure modes stated.

## Rulings made by this plan

1. **Threat feeds** (in `qberrypi.example.toml`, `dns.threat_lists`): hagezi Threat Intelligence Feeds, medium (`https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.medium.txt`, 8.0 MB, 373k names on 2026-11-11) and hagezi entropy-filtered newly registered domains of the last 7 days (`https://raw.githubusercontent.com/hagezi/nrd/main/adblock/dga7.txt`, 17.0 MB, 633k names). The full TIF (31.5 MB) sits at the 32 MiB fetch cap (ruling 12) and is not used; the unfiltered NRD-7 (2.96M names) is over it.
2. **Snapshot budget: threats ship through the first refresh only.** Measured 2026-11-11 with the snapshot's own form (`||name^` lines, sorted, zstd 19): both feeds add 5.99 MB compressed, TIF medium alone 2.03 MB, TIF mini 1.09 MB. `initramfs8` was 4.14 MB against its 6 MB budget, and the Pi loads the snapshot at about 1.9 µs per name against a 3 s budget (302k names in 572 ms), so 1M more names would also break the load budget. The 6 MB budget stays, the snapshot format stays at version 1, and `xtask` keeps snapshotting `dns.lists` only. Threat names are blocked from the first successful refresh (after the clock is set).
3. **DoH resolver list** is an ordinary ads-class entry of `dns.lists` (`https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/doh.txt`, 75 KB), so it is in the snapshot; removing the line turns it off. The canary `use-application-dns.net` gets NXDOMAIN (not the blocked answer, which Firefox would take as "keep DoH") while `dns.doh_canary = true` (default true).
4. **ECS** is already stripped: `Question::upstream_query` writes a fresh OPT with no options, and `handle_upstream` drops the upstream's OPT. This plan pins both with tests; no code change.
5. **DoT config:** optional section `[upstream]`, keys `tls` (default false) and `tls_name` (required when `tls = true`). The example has `tls = false` until the session lead's Pi comparison passes.
6. **DoT before the clock:** certificates cannot be checked before SNTP has set the clock (the Pi has no RTC, and SNTP resolves its server names through us), so questions go over UDP as today until `synced` is true; then `Upstreams::start_tls` opens the connections and every later exchange uses TLS. No fallback to plain DNS after that (a downgrade an attacker could force by blocking port 853); a down DoT upstream is reported like any silent upstream.
7. **DoT exchange:** the preferred connection alone, the others after `hedge_delay` (the same clamp(2 × smoothed, 20 ms, 250 ms)), or at once when the preferred leg fails or refuses; same 2 s overall wait; **no 700 ms resend** (TCP is reliable); a connection whose oldest open question is 2 s old is closed and reopened (a silently dead path). Answers are taken with `Transport::Tcp`. Losers are dropped, not counted.
8. **Warm connections:** reconnect at once after the server closes a session that lived at least 5 s; otherwise back off 250 ms doubling to 30 s, reset only by a session that lived at least 5 s (amended in the fix wave: a completed handshake alone does not reset it). Resumption is rustls's default in-memory store on the shared `ClientConfig`.
9. **Prefetch** (off by default, `speed.prefetch`): a fresh entry hit at least 3 times since stored, whose lifetime left is within clamp(lifetime / 10, 2 s, 60 s), is renewed once per stored answer. The service sends a prefetch only when fewer than 4 questions are out with the upstreams, and at most 4 per second (token bucket, burst 4); otherwise it is skipped and counted.
10. **CPU placement** (off by default, `speed.runtime_cpu`, a core 0–3): the main (runtime) thread is pinned to that core before the runtime is built, and every blocking-pool thread is set to all other cores at its start. On the BCM2837 every peripheral interrupt (SDIO Wi-Fi, SPI) goes to core 0, so the candidates are 1–3.
11. **Threat alerts:** kind `"threat"`, severity `High`, subject the name as recorded, client the asker's address (`None` for our own lookups). At most one per (client, name) per 3,600 s; the throttle holds at most 4,096 pairs, drops expired pairs when full, and drops the alert (counted) if still full.
12. **Config sections:** `[speed]` holds `prefetch` and `runtime_cpu`; `[dns]` gains `threat_lists` and `doh_canary`.
13. **DoT idle sessions** (amends 7 and 8, after a Pi boot showed `connects` 36 in 4.5 min and a healthy upstream logged as not answering). Measured from a desktop on 2026-11-11 against 9.9.9.9:853 and 149.112.112.112:853: Quad9 closes a session that has been idle for 10.1–11.3 s, with the TLS close notice, whether or not a question was ever asked on it; a session in use lives on (90 s at a question every 3 s); it ignores edns-tcp-keepalive (the option reaches it, and its answers carry no option); questions written 10.7 s or more after the last answer get no answer, then the close notice; a full handshake took 6.4–17 ms and a resumed one 3.6–5.2 ms after a 2.5–4 ms TCP connect; a ticket of one address never resumes at the other, and each full handshake yields two resumptions. The old connection reconnected at once after every such close, so each upstream did a handshake every ~10 s forever, a question that met the close or the handshake failed, and three of those marked the upstream silent. Ruling:
    - every question over TLS carries edns-tcp-keepalive (RFC 7828); a timeout that the server advertises is kept, less 1 s and at least half of it; 0 drains the session;
    - a session with no question open is closed by us after 9 s (`IDLE_CLOSE`), or the advertised time: no question is written into Quad9's closing second, and the TIME-WAIT is ours (RFC 7766 §6.2.3);
    - after such a close, or the server's, the next session is opened at once only if the one that ended carried a question; otherwise the next forwarded question opens it (every exchange wakes the connections it may ask, and hedges at once when its preferred one has no session up). A quiet household does no handshakes at all; one that asks every few seconds has the warm session it had;
    - no keepalive question: Quad9 does not want idle sessions, and RFC 7766/7858 say to follow the server's policy; a question just inside the timeout would keep a session that nobody uses, for load and nothing else;
    - a question that was open on a session the server ended (close notice, end of stream, reset) is sent again once on the next session, which opens at once, and the exchange hedges it at once to the other upstreams; a second end fails it;
    - none of this is a failure or a WARN: a connection fails a question at once only while it is down (a connect, a handshake or a short session failed, and the backoff runs); an upstream is counted once per exchange at most;
    - each connection keeps its own ticket store, so that a reconnect resumes;
    - a leg that waited for a handshake gives no latency sample;
    - `upstream_queries` counts the questions written to the TLS sessions too; `upstream_tls` adds `idle_closes`, `server_closes` and `retried`.

## Review Focus

1. **DoT before the clock is set** — every question must still be answered (over UDP) until `synced`; Task 8 test `before_start_tls_questions_go_over_udp`.
2. **A DoT path that goes silent without a FIN/RST** (NAT state lost) — open questions must not hang past the 2 s wait, and the connection must be replaced; Task 7 test `a_stalled_connection_is_closed_and_reopened`.
3. **A name on an ads list and a threat list, or an ads exact entry under a threat suffix** — the hit is a threat (alert raised, counted); Task 1 tests.
4. **A malware loop asking one threat name every second, or thousands of distinct threat names** — one alert per client per name per hour, throttle memory bounded; Task 6 tests.
5. **Many popular names expiring in the same second** (a boot burst all stored together) — prefetches capped at 4/s and none while 4 questions are out; Task 5 test `prefetch_budget_caps_a_burst`.

---

### Task 1: One class bit per block-set entry (qb-dns)

**Files:**
- Modify: `crates/qb-dns/src/blockset.rs`, `crates/qb-dns/src/lib.rs` (re-export)
- Create: `crates/qb-dns/tests/threat_budget.rs` (ignored timing test)

**Interfaces:**
- Produces: `pub enum ListClass { Ads, Threat }` (`Clone, Copy, Debug, PartialEq, Eq`), re-exported as `qb_dns::ListClass`; `BlockSetBuilder::add_list_as(&mut self, text: &[u8], class: ListClass) -> ListStats` (`add_list` = `add_list_as(text, ListClass::Ads)`; `deny` is Ads); `BlockSet::verdict(&self, name: &str) -> Option<ListClass>` (allocates nothing; `None` = not blocked); `BlockSet::threat_len(&self) -> usize` (entries of the exact and suffix tables with the bit set); `is_blocked(name) == verdict(name).is_some()`.

- [ ] **Step 1: Write the failing tests** in `blockset.rs` tests:
  - `threat_entries_carry_their_class`: an ads list `0.0.0.0 ad.example.com` and a threat list `||bad.example.net^\n0.0.0.0 phish.example.org`; `verdict("ad.example.com") == Some(Ads)`, `verdict("x.bad.example.net") == Some(Threat)`, `verdict("phish.example.org") == Some(Threat)`, `verdict("example.org") == None`, `threat_len() == 2`.
  - `a_name_on_both_classes_is_a_threat`: same name on an ads and a threat list (either order) → `Some(Threat)`, stored once (`exact_len() == 1`).
  - `an_ads_exact_entry_under_a_threat_suffix_is_a_threat`: ads `0.0.0.0 a.bad.example.net`, threat `||bad.example.net^` → `verdict("a.bad.example.net") == Some(Threat)`; and ads suffix `||example.net^` with threat exact `0.0.0.0 bad.example.net` → `Some(Threat)` for `bad.example.net`, `Some(Ads)` for `other.example.net`.
  - `allow_beats_a_threat`: `allow("ok.bad.example.net")` → `verdict("ok.bad.example.net") == None`.
  - `class_bits_hold_past_64_entries`: 200 names `n{i}.example.com`, even `i` on a threat list, odd on an ads list; each verdict matches its parity.
  - `span_is_still_8_bytes`: `assert_eq!(size_of::<Span>(), 8)`.
  - Update `duplicates_are_stored_once_and_the_heap_is_what_the_layout_says`: each non-empty table now adds `ceil(len / 64) * 8` bytes of bits (here 3 tables → `+ 24`).
- [ ] **Step 2: Run** `cargo test -p qb-dns blockset` — expected: the new tests fail to compile.
- [ ] **Step 3: Implement.** `Span` gains `threat: bool` (still 8 bytes). `PendingNames::push(name, threat)`. `build` sorts as now and dedups with `dedup_by(|later, kept| { let same = …; if same { kept.threat |= later.threat } same })`. `NameTable` gains `threat: Vec<u64>` (bit `i` = entry `i`; the allow table's bits are all zero), `find(name) -> Option<usize>` (the existing binary search) and `is_threat(i) -> bool`. `verdict` walks the name and its parents as `is_blocked` does today, keeps the strongest class among matching exact/suffix entries (Threat > Ads), and returns `None` at the first allowed covering name. `heap_bytes` adds the bit vectors' capacity. Doc comments say the class costs one bit per entry and nothing per lookup beyond one bit test.
- [ ] **Step 4: Write `tests/threat_budget.rs`**, one `#[ignore]` test `lookup_cost_with_the_threat_feeds`: build 300,000 ads names and 1,000,000 threat names (deterministic LCG, 2–4 labels of 6–14 `a-z0-9` chars under `.com`/`.net`/`.org`), then time 1,000,000 `verdict` calls over a mix of 1/3 ads hits, 1/3 threat hits, 1/3 misses (subdomains of misses too); also time `is_blocked` on an ads-only set of the same 300,000. Print `ns per lookup` for both and assert the mean is under 5 µs (the qb-dns lookup budget).
- [ ] **Step 5: Run** `cargo test -p qb-dns` (all pass) and `cargo test -p qb-dns --release --test threat_budget -- --ignored --nocapture` — record both figures in the commit message body.
- [ ] **Step 6: Gates, then commit** `blockset.rs lib.rs tests/threat_budget.rs` — message `qb-dns: a threat class bit on every block-set entry`.

### Task 2: Threat hits, threat counts, the DoH canary and the ECS pins (qb-dns)

**Files:**
- Modify: `crates/qb-dns/src/decide.rs`, `crates/qb-dns/src/stats.rs`, `crates/qb-dns/src/query.rs` (tests only), `crates/qb-dns/src/lib.rs`
- Fix any `Counts { … }` literal in the workspace (`..Default::default()` or the new field).

**Interfaces:**
- Consumes: `BlockSet::verdict`, `ListClass` (Task 1).
- Produces: `pub struct ThreatHit { pub name: Box<str> }` (re-exported); `Resolver::handle_query_threat(&mut self, packet: &[u8], transport: Transport, now: Now) -> (Action, Option<ThreatHit>)` — `handle_query` calls it and drops the hit; `Counts.blocked_threat: u64` (today and total; not in the history buckets); `Stats::record_threat(&mut self, now: Now)` (called right after `record`, so the day has rolled already); `Resolver::set_doh_canary(&mut self, on: bool)` (default on); `pub const DOH_CANARY: &str = "use-application-dns.net"` in `decide.rs`.

- [ ] **Step 1: Write the failing tests** in `decide.rs`:
  - `a_threat_name_is_blocked_counted_and_reported`: set from a threat list `||bad.example.net^`; `handle_query_threat` for `x.bad.example.net` A gives the blocked reply, `Some(ThreatHit { name: "x.bad.example.net" })`; `stats().today(now).blocked == 1 && .blocked_threat == 1`; totals likewise.
  - `an_ads_block_reports_no_threat`: ads-listed name → hit `None`, `blocked_threat == 0`.
  - `a_paused_resolver_reports_no_threat`: pause, then a threat name → `Action::Forward`, hit `None`, `blocked_threat == 0`.
  - `the_doh_canary_gets_nxdomain`: for qtypes A, AAAA, 65 (HTTPS): reply rcode NXDOMAIN (3), echoes the question, outcome Local (queries counted, `blocked == 0`); with `deny = ["use-application-dns.net"]` still NXDOMAIN, not the blocked reply; `sub.use-application-dns.net` is not the canary (forwarded).
  - `the_canary_can_be_turned_off`: `set_doh_canary(false)` → the canary is forwarded.
  - `blocked_threat_rolls_over_with_the_day` in `stats.rs`: `record_threat` today, then a query the next local day → `today().blocked_threat == 0`, total keeps 1.
  - In `query.rs`: `upstream_query_strips_the_clients_ecs_option` — a client query whose OPT carries an EDNS Client Subnet option (code 8, e.g. 192.0.2.0/24, built with hickory) → the upstream query decodes with an OPT that has no options at all.
  - In `decide.rs`: `a_relayed_answer_carries_no_upstream_ecs` — an upstream answer with an OPT carrying ECS → the client's reply has no ECS option (no OPT options).
- [ ] **Step 2: Run** `cargo test -p qb-dns` — expected: compile failures for the new names.
- [ ] **Step 3: Implement.** `Resolver` gains `doh_canary: bool` (true in `new`). `decide` order: `local` → canary (exact name, any type: `error(question, ResponseCode::NXDomain)`, `Outcome::Local`) → `block_class` (`verdict` on `block_key`, `None` while paused) → cache → forward. `handle_query_threat` records as now, then `record_threat` and builds the hit only for a Threat block (the only allocation added, and only on a threat hit). `Counts::count` is unchanged.
- [ ] **Step 4: Run** `cargo test --workspace` — expected: pass.
- [ ] **Step 5: Gates, then commit** — message `qb-dns: threat hits and counts, the DoH canary, ECS pins`.

### Task 3: Prefetch marks in the cache (qb-dns)

**Files:**
- Modify: `crates/qb-dns/src/cache.rs`, `crates/qb-dns/src/decide.rs`

**Interfaces:**
- Produces: `Pending::is_prefetch(&self) -> bool` (a prefetch is also `is_refresh() == true`, so its answer gives `UpstreamOutcome::Refreshed`); `Resolver::set_prefetch(&mut self, on: bool)` (default off); constants in `cache.rs`: `PREFETCH_MIN_HITS: u16 = 3`, `PREFETCH_WINDOW_MIN: u32 = 2`, `PREFETCH_WINDOW_MAX: u32 = 60`. A due prefetch comes out of `handle_query` as `Action::ReplyAndRefresh(reply, pending)` with `pending.is_prefetch()`; the outcome stays `Cached`.

- [ ] **Step 1: Write the failing tests** (cache.rs and decide.rs):
  - `no_prefetch_while_off`: entry with lifetime 300, 5 hits at age 295 → never a prefetch.
  - `a_popular_entry_is_prefetched_once_inside_its_window`: lifetime 300 (window = 30 s): hits at ages 10, 20 (no), at age 271 the 3rd hit → `ReplyAndRefresh` with `is_prefetch()`; a 4th hit at 275 → plain `Reply`.
  - `no_prefetch_before_the_window`: 3 hits at age 100 of 300 → plain replies; the 4th hit at 280 → prefetch.
  - `the_window_is_clamped`: lifetime 30 → window 3 s; lifetime 86,400 → window 60 s; lifetime 10 (via a direct `Cache::insert`) → window 2 s.
  - `a_new_answer_rearms_the_prefetch`: after a prefetch, `handle_upstream` stores a new answer → hits counted from 0 again, a later 3rd hit inside the new window prefetches again.
  - `the_prefetch_answer_is_refreshed_not_relayed`: `handle_upstream(&prefetch_pending, answer)` → `UpstreamOutcome::Refreshed`.
  - `stale_hits_are_unchanged_by_prefetch`: stale behaviour (one refresh per 10 s) is as before with prefetch on.
- [ ] **Step 2: Run** `cargo test -p qb-dns` — expected: compile failures.
- [ ] **Step 3: Implement.** `Entry` gains `hits: u16` (saturating, counted on fresh hits) and `prefetch_asked: bool`; `Cache` gains `prefetch: bool` with `set_prefetch`. `Hit::Fresh` gains `prefetch: bool`, true once per stored answer when on, `hits >= PREFETCH_MIN_HITS` (this hit included) and `ttl_left <= (lifetime / 10).clamp(PREFETCH_WINDOW_MIN, PREFETCH_WINDOW_MAX)`; setting it marks `prefetch_asked`. `Pending` gains `prefetch: bool`; `Decision::ReplyAndRefresh` carries whether it is a prefetch.
- [ ] **Step 4: Run** `cargo test --workspace` — pass. Extend the existing `entry_points_never_panic_and_stay_bounded` fuzz to run with prefetch on as well.
- [ ] **Step 5: Gates, then commit** — message `qb-dns: prefetch a popular answer once before it expires`.

### Task 4: Configuration keys and the example file

**Files:**
- Modify: `crates/qberrypi/src/config.rs`, `qberrypi.example.toml`; any test that counts the example's lists (`config.rs`, `xtask/src/lists.rs`, `init.rs` tests — fix counts only, no logic).

**Interfaces:**
- Produces: `Dns.threat_lists: Vec<String>` (every entry `https://…`, error key `dns.threat_lists`); `Dns.doh_canary: bool` (default true); `Config.upstream: UpstreamCfg { pub tls: bool, pub tls_name: Option<String> }` from optional `[upstream]` (known keys `tls`, `tls_name`; `tls = true` without `tls_name` → error key `upstream.tls_name`, reason `"required when upstream.tls is true"`; a `tls_name` that is not a host name → error `upstream.tls_name`, `"must be a host name"`, using the existing `is_hostname`/`normalized` rule; `tls_name` is stored normalised); `Config.speed: SpeedCfg { pub prefetch: bool, pub runtime_cpu: Option<u8> }` from optional `[speed]` (known keys `prefetch`, `runtime_cpu`; `runtime_cpu` outside 0..=3 or not an integer → error `speed.runtime_cpu`, `"must be a core from 0 to 3"`). Defaults with the sections absent: tls false, no name, prefetch false, no pin, no threat lists, canary on.

- [ ] **Step 1: Write the failing tests** in `config.rs`: `the_watchdog_keys_take_their_defaults` (minimal file without the new keys); `threat_lists_must_be_https`; `tls_needs_a_name`; `tls_name_must_be_a_host_name`; `runtime_cpu_is_a_core_from_0_to_3` (4 and -1 and "x" refused, 3 accepted); `the_example_keeps_tls_and_speed_off` (example parses with `upstream.tls == false`, `tls_name == Some("dns.quad9.net")`, `speed.prefetch == false`, `runtime_cpu == None`, 2 threat lists, `doh_canary == true`, 3 lists); unknown keys in `[upstream]`/`[speed]` are named with their full path.
- [ ] **Step 2: Run** `cargo test -p qberrypi config` — fails.
- [ ] **Step 3: Implement** the parsing (add a `bool_or(name, default)` helper beside `bool_or_false` and an optional-integer reader beside `reading_or`). Update `qberrypi.example.toml`:
  - `[dns]`: add the DoH list as a third `lists` entry with a comment `# public DoH resolvers, so devices fall back to this resolver; remove to allow them`; add `threat_lists` with the two Ruling-1 URLs and a comment `# malware, phishing and scam names, and newly registered random-looking names; a hit also raises an alert. Not in the image's snapshot: blocked from the first refresh.`; add `doh_canary = true  # NXDOMAIN for use-application-dns.net, which turns off browsers' own DoH`.
  - New `[upstream]` after `[dns]`: `tls = false  # DNS-over-TLS on port 853; off until the latency comparison on the Pi passes` and `tls_name = "dns.quad9.net"  # the name on the upstreams' certificate`.
  - New `[speed]`: `prefetch = false  # renew popular answers shortly before they expire` and `# runtime_cpu = 1   # pin the DNS runtime to this core (0-3); core 0 takes the Wi-Fi and SPI interrupts`.
- [ ] **Step 4: Run** `cargo test --workspace` — pass (fix list-count assertions that read the example).
- [ ] **Step 5: Gates, then commit** — message `config: threat lists, the DoH canary, upstream.tls, prefetch and runtime_cpu`.

### Task 5: Threat lists in the refresh, flags into the resolver, the prefetch budget, status keys

**Files:**
- Modify: `crates/qberrypi/src/lists/refresh.rs`, `crates/qberrypi/src/lists/mod.rs` (only if `names` needs no change — leave it), `crates/qberrypi/src/dns/mod.rs`, `crates/qberrypi/src/services.rs` (small), `crates/qberrypi/src/status.rs`

**Interfaces:**
- Consumes: Task 1 `add_list_as`, `threat_len`; Task 2 `set_doh_canary`, `Counts.blocked_threat`; Task 3 `Pending::is_prefetch`, `set_prefetch`; Task 4 config fields.
- Produces: `refresh::build(fetch: &dyn Fetch, lists: &[String], threat_lists: &[String], deny: &[String], allow: &[String]) -> Result<BlockSet, RefreshError>` (keep the existing error type; threat lists are numbered after the ads lists, and their log line ends `(threat)`); in `dns/mod.rs`: `pub const PREFETCH_PER_SEC: u32 = 4`, `pub const PREFETCH_BUSY: usize = 4`, `Dns::prefetched(&self) -> u64`, `Dns::prefetches_skipped(&self) -> u64`; status keys `"blocked_threat_today"` (after `"blocked_today"`), `"blocked_threat_total"`, `"prefetched_total"`.

- [ ] **Step 1: Write the failing tests:**
  - `refresh.rs`: `threat_lists_are_fetched_after_the_lists_and_carry_their_class` (fake fetch: A ads, T threat; the built set gives `verdict` Ads/Threat; an error in the threat list names it as list 2); `the_refresh_runs_with_threat_lists_alone` (no `lists`, one threat list → refreshed, not "none configured").
  - `dns/mod.rs`: `prefetch_bucket_refills_at_its_rate` (unit test of `Bucket::take(&mut self, now: tokio::time::Instant) -> bool` with explicit instants: 4 at once, the 5th refused, 1 more after 250 ms, never more than 4 banked after a long idle); `prefetch_budget_caps_a_burst` (real clock: 10 prefetch `Pending`s, taken from `dns.resolver().handle_query(…)` at a test-chosen `Now` with prefetch on, handed to `dns.refresh` back to back → exactly 4 reach the `FakeUpstream`, `prefetches_skipped() == 6`); `no_prefetch_while_questions_are_out` (hold 4 forwards open against a silent upstream, then a prefetch → skipped); `a_stale_refresh_ignores_the_prefetch_budget` (exhaust the bucket, a stale refresh still goes).
  - `status.rs`: the stats JSON test asserts the three new keys.
  - `services.rs` (existing prepare test or a new one): after `prepare` with `doh_canary = false` and `prefetch = true` in the parsed example, the resolver behaves accordingly (canary forwarded; a resolver-level check is enough).
- [ ] **Step 2: Run** — fails.
- [ ] **Step 3: Implement.** `refresh::run` passes `cfg.dns.threat_lists` and returns early only when both list sets are empty; the "refreshed" line also says how many threat names. `services::prepare` sets `set_doh_canary` and `set_prefetch` right after the `Dns` is made (the flags live in the resolver and survive `set_blockset`). In `Dns`: a `Mutex<Bucket>` token bucket on `tokio::time::Instant` (refill `PREFETCH_PER_SEC` per second, cap `PREFETCH_PER_SEC`), never held across an `.await`; `refresh(pending)` for a prefetch first checks `forward_limit - forwards.available_permits() < PREFETCH_BUSY`, then takes a token, else counts a skip and returns; a stale refresh is unchanged. Store the forward limit in `Dns` (`with_forward_limit` already has it).
- [ ] **Step 4: Run** `cargo test --workspace` — pass.
- [ ] **Step 5: Gates, then commit** — message `services: threat lists in the refresh, canary and prefetch switches, prefetch budget, threat counts in the stats`.

### Task 6: The alerts interface and threat alerts per client

**Files:**
- Create: `crates/qberrypi/src/alerts/mod.rs`, `crates/qberrypi/src/dns/threat.rs`
- Modify: `crates/qberrypi/src/lib.rs` (`pub mod alerts;`), `crates/qberrypi/src/dns/mod.rs`, `crates/qberrypi/src/dns/listen.rs`, `crates/qberrypi/src/dns/testutil.rs` (a recording sink), `crates/qberrypi/src/services.rs` (one line)

**Interfaces:**
- Produces, `alerts/mod.rs`, **exactly** (doc comments may be added; no derives, no other items but `NullSink`) — track B codes against the same text:

```rust
pub enum Severity { Info, Warn, High }
pub struct Alert { pub kind: &'static str, pub severity: Severity, pub client: Option<std::net::IpAddr>, pub subject: String }
pub trait AlertSink: Send + Sync { fn raise(&self, alert: Alert); }
pub struct NullSink;
impl AlertSink for NullSink { fn raise(&self, _alert: Alert) {} }
```

  The module doc states the contract: `raise` is called on the DNS receive loop and must not wait (no I/O, no `.await`, any lock held only for a copy).
- `dns/threat.rs`: `pub const THREAT_KIND: &str = "threat"`; `pub const THREAT_ALERT_EVERY_SECS: u64 = 3_600`; `pub const THREAT_PAIRS: usize = 4_096`; `pub(crate) struct ThreatThrottle` with `fn should_raise(&mut self, client: Option<IpAddr>, name: &str, mono_secs: u64) -> bool` and `fn dropped(&self) -> u64`.
- `Dns::with_alerts(blockset: BlockSet, upstreams: Upstreams, zone: Box<dyn UtcOffset>, alerts: Arc<dyn AlertSink>) -> Arc<Self>` (`new` = `with_alerts(…, Arc::new(NullSink))`); `Dns::decide_from(&self, packet: &[u8], transport: Transport, client: Option<IpAddr>) -> Action` (`decide` = `decide_from(…, None)`); `Dns::answer_from(self: &Arc<Self>, packet: &[u8], transport: Transport, client: Option<IpAddr>) -> Option<Vec<u8>>` (`answer` = `answer_from(…, None)`). The UDP loop calls `decide_from(…, Some(client.ip()))`, a TCP connection `answer_from(…, Some(peer.ip()))`; `lookup_v4` keeps `answer` (`None`).

- [ ] **Step 1: Write the failing tests:**
  - `threat.rs`: `one_alert_per_client_and_name_per_hour` (same pair at 0, 10, 3,599 → true, false, false; at 3,600 → true); `other_clients_and_names_are_separate`; `a_full_throttle_drops_expired_pairs_first` (fill 4,096 pairs at t=0, a new pair at t=3,600 → true); `a_full_throttle_of_fresh_pairs_drops_the_alert` (4,096 pairs at t=0, a new pair at t=1 → false, `dropped() == 1`; memory stays at 4,096 entries).
  - `dns/mod.rs` (recording sink from `testutil`, which stores `(kind, matches!(severity, High), client, subject)`): `a_threat_hit_raises_one_high_alert_for_its_client` (two `decide_from` for `x.bad.example.net` from 192.0.2.10 → one alert `("threat", true, Some(192.0.2.10), "x.bad.example.net")`; from 192.0.2.11 → a second); `ads_blocks_and_own_lookups_raise_nothing_unexpected` (ads hit → no alert; `lookup_v4` of a threat name → an alert with client `None`, once).
  - `listen.rs`: `a_threat_asked_over_udp_and_tcp_names_the_asker` (listener on 127.0.0.1; UDP ask, then TCP ask of another threat name → two alerts, client `127.0.0.1` both).
  - Timing, `#[ignore]` in `dns/mod.rs`: `decide_cost_for_blocked_and_threat_names` — 100,000 `decide_from` each for an ads-blocked name, a repeated threat name (throttled) and fresh threat names; print ns per call.
- [ ] **Step 2: Run** — fails.
- [ ] **Step 3: Implement.** `decide_from` takes the resolver lock for `handle_query_threat` only, releases it, then (only on a hit) locks the throttle and calls `alerts.raise` when it says so. Nothing is logged. `services::prepare` builds the `Dns` with `Dns::with_alerts(…, Arc::new(NullSink))` so that track B's store is a one-line swap.
- [ ] **Step 4: Run** `cargo test --workspace` and the ignored timing test in release (`cargo test -p qberrypi --release decide_cost -- --ignored --nocapture`); put the figures in the commit body.
- [ ] **Step 5: Gates, then commit** — message `dns: threat alerts, one per client per name per hour, through the alerts interface`.

### Task 7: One warm, pipelined DNS-over-TLS connection per upstream

**Files:**
- Create: `crates/qberrypi/src/dns/dot.rs`
- Modify: `crates/qberrypi/src/dns/mod.rs` (`pub mod dot;`), `crates/qberrypi/src/dns/testutil.rs` (a TLS fake upstream)

**Interfaces:**
- Consumes: `services::blocking(what, work)`, `https::provider()`, `https::client_config(roots)`.
- Produces:
  - `pub const DOT_PORT: u16 = 853`; `pub const STALL_AFTER: Duration = UDP_WAIT` (2 s); `pub const MIN_LIVED: Duration = 5 s`; `pub const BACKOFF_MIN: Duration = 250 ms`; `pub const BACKOFF_MAX: Duration = 30 s`; `pub const HANDSHAKE_WAIT: Duration = 3 s`; `pub const CONNECT_WAIT: Duration = 2 s`.
  - `#[derive(Clone)] pub struct TlsUpstream { pub name: rustls::pki_types::ServerName<'static>, pub config: Arc<rustls::ClientConfig> }`.
  - `pub(crate) struct ConnOptions { stall: Duration, backoff_min: Duration, backoff_max: Duration, min_lived: Duration }` with `Default` = the constants (tests shorten them).
  - `pub(crate) struct Conn` — `Conn::spawn(server: SocketAddr, tls: TlsUpstream, options: ConnOptions) -> Conn` (spawns the connection's task on the current runtime; the task is aborted when the `Conn` drops); `Conn::ask(&self, query: Vec<u8>) -> impl Future<Output = io::Result<Vec<u8>>> + Send + 'static` (fails at once with `NotConnected` while no session is up, or when the queue or the in-flight table is full; the task overwrites the query's ID with one not in flight on this connection and gives back the whole answer packet, ID included); `Conn::is_up(&self) -> bool`; `Conn::connects(&self) -> u64` (completed handshakes); `Conn::resumed(&self) -> u64` (of those, resumed: `handshake_kind() == Resumed`).
  - `fn backoff(previous: Option<Duration>, options: &ConnOptions) -> Duration` (pure: `None` → `backoff_min`, else doubled, capped at `backoff_max`).

- [ ] **Step 1: Write the TLS fake upstream** in `testutil.rs`: `pub(crate) struct TlsFakeUpstream` started on 127.0.0.1:0 with an `rcgen` certificate for `dns.example.org`, served by std threads using `rustls::ServerConnection` + `StreamOwned` with `https::provider()` (the default server session cache gives TLS 1.3 resumption). Modes: answer each query at once with a fixed A answer for its question (ID echoed); `reverse_pairs` (hold the first of every two queries and answer the second first); `close_after(n)` answers; `silent` (complete the handshake, read, never answer); `delay(ms)`. Counters: `handshakes()`, `resumed()` (server side `handshake_kind()`), `queries()`. Plus `fn tls_for_fake(fake) -> TlsUpstream` (root store holding the fake's certificate, name `dns.example.org`).
- [ ] **Step 2: Write the failing tests** in `dot.rs`:
  - `an_answer_comes_back_over_tls` (ask once `is_up` → answer for its question; `connects() == 1`).
  - `questions_are_pipelined_and_matched_by_id` (reverse_pairs: two concurrent asks on one connection, each gets the answer to its own question; the server saw 1 handshake).
  - `the_connection_is_opened_before_the_first_question` (after spawn, `is_up()` becomes true within 2 s with no ask).
  - `a_closed_connection_is_reopened_and_resumed` (close_after(1) with `min_lived` 0: ask, wait for `connects() == 2`, ask again → answer; `resumed() >= 1` and the server's `resumed() >= 1`).
  - `ask_fails_at_once_while_down` (spawn against `closed_port()` → `ask` returns `NotConnected` in under 50 ms).
  - `reconnects_back_off_boundedly` (pure `backoff`: 250, 500, 1,000 … 30,000, 30,000 ms; and against a closed port with `backoff_min` 50 ms, `backoff_max` 200 ms, the number of connect attempts in 1 s is between 3 and 12 — count them via a `TcpListener` that accepts and drops, or a counter in the conn).
  - `a_stalled_connection_is_closed_and_reopened` (silent server, `stall` 300 ms: the ask errors within 1 s, then `connects()` reaches 2).
  - `a_certificate_for_another_name_never_connects` (name `other.example.org` → `is_up()` stays false for 1 s, ask errors).
  - `a_handshake_does_not_hold_the_runtime` (while connecting, a 1 ms `tokio::time::interval` on the same current-thread runtime never misses more than 20 ms between ticks).
- [ ] **Step 3: Run** `cargo test -p qberrypi dot` — fails.
- [ ] **Step 4: Implement** the task loop: connect (`TcpStream::connect` within `CONNECT_WAIT`, `set_nodelay(true)`), then the handshake on the pool — `services::blocking("tls handshake", …)` gets the std stream (blocking mode, read/write timeouts `HANDSHAKE_WAIT`), runs `ClientConnection::new` and `complete_io` until not handshaking, sets non-blocking and gives back `(ClientConnection, std::net::TcpStream)`; `tokio::net::TcpStream::from_std`. Then the session loop with `tokio::select!` over the ask queue (`mpsc`, capacity `MAX_FORWARDS`), the socket's readability, and the stall timer (the oldest open question's send time + `stall`): write `len_be16 ‖ query` frames through `conn.writer()` and flush `write_tls` to the socket; on readable, `try_read` into a 16 KiB buffer, `read_tls` + `process_new_packets` (an error ends the session), drain `conn.reader()` (stop at `WouldBlock`) into a plaintext buffer bounded at 2 × 65,537 bytes, cut frames, and send each to the in-flight entry of its ID (unknown IDs are ignored). In-flight entries are at most `MAX_FORWARDS`. Session end (EOF, error, stall) drops every open entry (their asks get an error), marks the conn down, and then: reconnect at once if the session lived `min_lived`, else sleep `backoff`. A completed handshake resets the backoff and bumps `connects` (and `resumed`). Nothing here logs a name; one WARN per minute at most when connecting fails, with the upstream's address only.
- [ ] **Step 5: Run** `cargo test --workspace` — pass.
- [ ] **Step 6: Gates, then commit** — message `dns: a warm, pipelined DNS-over-TLS connection per upstream`.

### Task 8: The hedged exchange over TLS, switched on after the clock

**Files:**
- Modify: `crates/qberrypi/src/dns/upstream.rs`, `crates/qberrypi/src/services.rs` (small), `crates/qberrypi/src/status.rs`

**Interfaces:**
- Consumes: Task 7 `Conn`, `TlsUpstream`, `DOT_PORT`; existing `hedge_delay`, `asked`, `is_refusal`, `Shared::{note, won}`, `none_answers`, `MAX_RACED`.
- Produces: `Upstreams::with_tls(self, tls: TlsUpstream, port: u16) -> Self` (builder; nothing opens yet); `Upstreams::start_tls(&self)` (idempotent; spawns one `Conn` per upstream, at most `MAX_RACED`, on `(ip, port)`; logs `dns: upstreams over TLS from now on` once; a no-op without `with_tls`); `Upstreams::tls(&self) -> TlsState` where `pub enum TlsState { Off, WaitingForClock, On { up: usize, connects: u64, resumed: u64 } }`; status key `"upstream_tls"`: `"off"`, `"waiting for the clock"`, or `{"up": n, "connects": n, "resumed": n}`.

- [ ] **Step 1: Write the failing tests** in `upstream.rs` (two `TlsFakeUpstream`s, shortened waits where needed):
  - `before_start_tls_questions_go_over_udp` (`with_tls` set, no `start_tls`: a UDP `FakeUpstream` answers, the TLS fakes see 0 queries).
  - `after_start_tls_a_question_goes_over_tls_only` (UDP fake sees 0; the preferred TLS fake 1; the outcome is the reply).
  - `a_healthy_preferred_is_asked_alone` (20 questions in turn after the first answer: the second fake sees at most 1).
  - `a_slow_preferred_is_hedged_after_the_delay` (preferred `delay(400)`, second immediate: the answer comes from the second in under 300 ms, and the second becomes preferred).
  - `a_down_preferred_is_hedged_at_once` (preferred on a closed port: answered by the second in under 100 ms after the conns settle).
  - `a_refusal_waits_for_the_other_answer` (preferred answers REFUSED, second answers NOERROR → the NOERROR reply).
  - `all_down_gives_none_within_the_wait` (both closed ports → `None` within `udp_wait` + 100 ms; `failures()` grows).
  - `tls_state_follows_the_switch` (`Off` without `with_tls`, `WaitingForClock` before `start_tls`, `On { up: 2, .. }` after).
  - `start_tls_twice_opens_one_set` (`connects` total stays 2).
  - Timing, `#[ignore]`: `tls_and_udp_round_trips_on_loopback` (200 exchanges each way against loopback fakes; print p50/p95 µs for each).
- [ ] **Step 2: Run** — fails.
- [ ] **Step 3: Implement.** `exchange` begins `if let Some(conns) = self.started_tls() { return self.exchange_tls(conns, pending, take).await; }` and the UDP path is untouched. `exchange_tls`: query = `pending.upstream_query(0)` (empty → `None`); legs are boxed `ask` futures tagged with their index and send time, polled together with `poll_fn` (no new crates); order from `asked(preferred, count)`; hedges at `hedge_delay` (if it is shorter than the wait) or at once when no leg is live; a leg error notes a failure; an answer: refusal set aside while others are live or unsent (first kept as fallback); else `take(packet, Transport::Tcp)` — `Reply`/`Refreshed` win (`won(index, Some(now - sent))`), `Mismatch`/`RetryOverTcp` count as that leg's failure; at the deadline the open legs are failures and the fallback (if any) goes to `take`; otherwise `none_answers()`. `sent` counts each ask. In `services.rs`: when `cfg.upstream.tls`, build `with_tls(TlsUpstream { name: ServerName::try_from(tls_name.clone()), config: https::client_config(https::mozilla_roots()) }, DOT_PORT)`; the DNS component spawns a small task that waits for `synced` to be true and then calls `dns.upstreams().start_tls()` (a restart of the component calls it again, which is a no-op).
- [ ] **Step 4: Run** `cargo test --workspace` and the ignored timing test in release; record the figures in the commit body.
- [ ] **Step 5: Gates, then commit** — message `dns: the hedged exchange over TLS once the clock is set (upstream.tls, off by default)`.

### Task 9: CPU placement experiment

**Files:**
- Create: `crates/qberrypi/src/cpu.rs`
- Modify: `crates/qberrypi/src/lib.rs`, `crates/qberrypi/src/services.rs` (`runtime`), `crates/qberrypi/src/init.rs` (`start_runtime`), `crates/qberrypi/Cargo.toml` (only if a rustix feature is needed, e.g. `thread`)

**Interfaces:**
- Consumes: `cfg.speed.runtime_cpu` (Task 4).
- Produces: `cpu::pin_current_thread(core: usize) -> io::Result<()>`; `cpu::all_but_current_thread(core: usize) -> io::Result<()>` (every core the process may use, minus `core`; with nothing left it changes nothing); `services::runtime(pin: Option<usize>) -> io::Result<Runtime>` (with `Some(core)`, `on_thread_start` runs `all_but_current_thread(core)` on every pool thread). `init::start_runtime(cfg)` pins the main thread first and logs `cpu: runtime pinned to core N`, or a WARN with the error and goes on unpinned.

- [ ] **Step 1: Write the failing tests** in `cpu.rs`: `a_thread_pinned_to_core_0_runs_only_there` (std thread, then read back with `sched_getaffinity`); `all_but_leaves_out_the_core` (skip with a note when the host has one CPU); `a_pinned_runtime_keeps_its_pool_off_the_core` (`services::runtime(Some(0))` built on a fresh std thread that pinned itself to 0; a `spawn_blocking` job's mask excludes 0). Use rustix's safe API only (`rustix::thread::sched_setaffinity`/`sched_getaffinity` and `CpuSet`, or wherever rustix 1.x puts them).
- [ ] **Step 2: Run** — fails.
- [ ] **Step 3: Implement**, keeping `runtime(None)` exactly today's builder.
- [ ] **Step 4: Run** `cargo test --workspace`, then the init gate: `cargo xtask build && cargo xtask qemu-test` — every scenario ok (QEMU runs with the dummy config, so the pin is off there).
- [ ] **Step 5: Gates, then commit** — message `cpu: optional pin of the runtime thread away from the interrupt core (speed.runtime_cpu, off by default)`.

---

## After the tasks

One Opus whole-branch review (`git diff 1d38a13..HEAD`), then one fix wave for Critical and Important findings only; Minors listed and deferred.

## Pi checks for the session lead (not for implementers)

1. Build with the dummy-free config: `[upstream] tls = false`, `[speed]` off, `threat_lists` as in the example. Boot one-shot; within 5 min `/api/v1/stats` shows `list_source: "fetched"`, `list_names` ≈ ads + threat (≈ 1.3M), `blocked_threat_today` present; the log has the refresh's per-list lines (`(threat)` on two) and its total time; `list_error` null. Note the refresh's seconds and the resident memory if visible.
2. Ask `use-application-dns.net` → NXDOMAIN; a TIF-medium name → `0.0.0.0` and `blocked_threat_today` +1; a DoH resolver name from `doh.txt` → blocked.
3. **Latency acceptance, baseline** (everything of this track on except TLS, prefetch and the pin): same evening, stock / qberrypi / stock, `cargo xtask latency --samples 200 --json` at 200 ms and `--interval-ms 2`; `--compare` exits 0 in both pacings.
4. **DoT comparison:** the same with `upstream.tls = true`. Check (ruling 13) that `upstream_failures` stays 0 and no `does not answer` line is logged; `server_closes` and `retried` stay at or near 0; `idle_closes` and `connects` climb only while the household is active, and stand still in a quiet stretch (`up` is then 0, which is no fault); `resumed` is about two thirds of `connects` after the first two; `upstream_queries` rises with the questions. DoT ships enabled only if `--compare` exits 0 in both pacings; record the rows in `docs/bring-up/latency-baseline.md` either way.
5. **Prefetch:** `speed.prefetch = true`; same comparison; `prefetched_total` grows. Keep it on only if no row is worse.
6. **CPU pin:** `speed.runtime_cpu = 1` (then 3); log shows `cpu: runtime pinned to core N`; same comparison; keep only with a gain.
