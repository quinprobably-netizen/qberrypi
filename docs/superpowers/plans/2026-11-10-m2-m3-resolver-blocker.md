# Milestones 2 and 3 (Resolver, Blocker) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The Pi answers DNS on UDP and TCP port 53 — forwarding to the configured upstreams, caching, and setting its clock by SNTP (milestone 2) — then blocks from a list snapshot packed into the image and refetches the lists over HTTPS once a day (milestone 3).

**Architecture:** qberrypi has one tokio runtime, current-thread, on PID 1's main thread, built by milestone 1. This plan's components are tasks on it: the `dns` module moves packets for `qb-dns`'s `Resolver`, `sntp` sets the clock, `status` serves JSON on port 80, and `lists` loads `/blocklist.zst` and refetches the lists with `rustls` and the `rustls-rustcrypto` provider. Whatever takes real processor time — unpacking the snapshot, parsing a list, building a block set, a TLS connection — is a blocking job on a pool of two threads. `xtask` gains `fetch-lists`, the snapshot in the initramfs, a seventh QEMU scenario, and `probe`, the client the Pi checks use.

**Tech Stack:** Rust stable, edition 2024. Executable, new: tokio's `io-util` feature beside milestone 1's, `qb-dns`, `hickory-proto` 0.26, `tz-rs` 0.7, `serde_json` 1, `httparse` 1, `rustls` 0.23 (`std`, `tls12`, no built-in provider), `rustls-rustcrypto` `=0.1.0-pre.0`, `webpki-roots` 1, `ruzstd` 0.9. Tests only: `rcgen` 0.14. xtask, new: `qb-dns`, `serde_json`.

**Spec:** `docs/superpowers/specs/2026-11-10-qberrypi-design.md` — sections Process model, Boot sequence, Network, DNS, Blocklists, Status, Configuration, Failure handling, Image build, Testing, Risks.

**Starts when:** as `docs/superpowers/plans/2026-11-10-execution-order.md` orders it — `qb-dns` merged into `qbp-v1` with its Task 11 green, Tasks 1–6 of the milestone 4/5 plan done, and milestone 1 merged with its Pi check passed. That file's rulings bind this plan. Read `docs/superpowers/plans/2026-11-10-qb-dns.md` first: every `qb_dns` name below is from its Interfaces blocks.

**Two milestones, one stop between them:** Tasks 1–9 are milestone 2 and end with its "done when" check on the Pi. Tasks 10–15 are milestone 3. Nothing in Tasks 1–9 refers to a later task, so the work can stop after Task 9 with a system that forwards, caches, keeps time and serves its statistics.

## Global Constraints

- `unsafe` only in `crates/qberrypi/src/sys.rs`.
- No secret in a log line, an error, `/log`, `/api/v1/stats` or a committed file. A queried name is never logged at INFO or above, except the self-test's own fixed names: the card log and the bring-up notes must not hold the household's queries.
- The repository is public: example values only. Names are `example.com`, `example.net`, `example.org`, `*.invalid`; addresses come from `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`; tests use `127.0.0.1`. Bring-up notes carry no network name, address or raw log.
- Nothing from a downloaded list is committed. `vendor-cache/`, `out/` and `qberrypi.toml` stay git-ignored.
- This plan needs no new kernel module: IPv4 UDP and TCP, epoll, eventfd and timerfd are built into the pinned kernel (see Facts). If a task finds it needs one after all, the module goes into `xtask/src/pins.rs` and `qberrypi::modules::DEFAULT_TABLE` in that same task.
- The one-shot restore stays the first write to the card. This plan adds no card write and moves none: none of its tasks or blocking jobs touches the card. A fatal error on a pool thread does, through `fatal`, which Task 2 makes safe for that.
- One executable, all Rust: `cargo tree -p qberrypi --target aarch64-unknown-linux-musl -e normal,build --prefix none | grep -E '^(ring|aws-lc-sys|cc|zstd-sys|openssl-sys) '` prints nothing (unless Task 10's fallback to `ring` was taken and recorded).
- IPv4 only. No `AF_INET6` socket is opened (the kernel would ask the module helper for `ipv6`, which the image does not have). No name is resolved through libc — no `ToSocketAddrs` on a host name: musl would ask `127.0.0.1`. Sockets connect to `SocketAddr` values that came from the configuration or from `Dns::lookup_v4`.
- Requests to outside servers do not carry the project's name: the HTTP `User-Agent` is `list-fetch`; DNS and SNTP packets carry nothing of ours.
- One runtime, milestone 1's; this plan builds none and starts no thread of its own. On the runtime thread: no blocking call and no `std::thread::sleep`; nothing holds it for more than about 50 ms of processor time on the board — unpacking the snapshot, parsing a list, building a block set and every TLS connection go through `services::blocking`, on a pool capped at 2 threads; no lock is held across an `.await`; every connect, read and wait on the network has a timeout; every pool and queue has a named bound.
- Spec values: DNS on UDP and TCP port 53; status on port 80, read-only; lists refetched once a day, a failed fetch keeps the current set and is retried in an hour; HTTPS only after SNTP has set the clock; the clock is never earlier than the image build time.
- Host tests bind `127.0.0.1` port 0 only and reach no outside network. The six existing QEMU scenarios keep passing; their conditions may gain lines, never lose one.
- Only the session lead deploys to the Pi, with the owner's agreement: each deploy takes the household's DNS away for two to four minutes.
- Clean before every commit, with no warnings: `cargo test --workspace`, `cargo clippy --workspace --all-targets`, `cargo fmt --all --check`, `cargo build -p qberrypi --release --target aarch64-unknown-linux-musl`. Dependencies are added with `cargo add`.
- Git: stage files by name (never `git add -A` or `git add .`). Every commit message ends with a `Co-Authored-By:` trailer naming the model that wrote the commit, for example `Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>`. Never push.

## Review Focus

1. An upstream stops answering while the network is up: later queries must not each wait for it again, and when none answers the client gets SERVFAIL within the waits while the listener goes on serving. (Tests in Tasks 3 and 4.)
2. A datagram arrives on an upstream socket that is not the answer — another ID, another question, a late answer to an earlier query: it is ignored, the wait goes on, the cache is untouched. (Test in Task 3.)
3. A client connects over TCP to port 53 or port 80 and then says nothing, or half a message; or many do: each is closed after its wait, and UDP clients and later TCP clients are answered meanwhile. (Tests in Tasks 4 and 6.)
4. A list URL answers with something that is not a list — a captive portal's page, an error page with status 200, an empty body — or one list of several cannot be fetched: the current set stays in force, the state says why, the retry is in an hour. The same at build time: `fetch-lists` keeps the file it had. (Tests in Tasks 11 and 12.)
5. The time is wrong: an SNTP reply that is not the answer to our request, that says the server is not synchronised, or that names a time before the build must not set the clock; and no HTTPS connection is made before the clock is set, because every certificate would look not yet valid or long expired. (Tests in Tasks 5 and 11.)

---

## Facts

Gathered on 2026-11-10, read-only, from the Pi running Raspberry Pi OS and from the development machine.

| Fact | Consequence |
|---|---|
| The Pi runs the pinned kernel, `6.18.60+rpt-rpi-v8`; `CONFIG_INET=y`, `EPOLL=y`, `EVENTFD=y`, `TIMERFD=y`, `TCP_CONG_CUBIC=y`. | No new module. |
| `CONFIG_IPV6=m`, and `ipv6.ko` is not in the image. | IPv4 only; see Global Constraints. |
| `/proc/cpuinfo` Features: `fp asimd evtstrm crc32 cpuid` — no `aes`, `pmull`, `sha1`, `sha2`. | TLS runs on software AES or ChaCha20; ChaCha20 suites are offered first. |
| 4 cores, 904 MB of memory; Pi-hole's own process uses 22 MB. | The budgets below are far inside it. |
| The configured upstreams do not answer NTP (both timed out); `time.cloudflare.com` (3 ms), `time.google.com` (39 ms) and `pool.ntp.org` (65 ms) answer SNTP over IPv4. Raspberry Pi OS itself was synchronised over IPv6. | Time comes from named time servers, not from the upstreams; IPv4 NTP leaves this network. |
| `9.9.9.9` answers DNS in 4 ms over UDP and 8 ms over TCP; ping averages 5.7 ms. | The 2-second upstream wait is generous; TCP fallback works from here. |
| `/proc/net/route` is whitespace-separated with the header `Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT`; the default route has Destination `00000000`, Mask `00000000`, Flags `0003`. | The SNTP task can see the network come up without knowing milestone 1's code. |
| The local zone has daylight saving time. | A fixed UTC offset would be wrong for half the year. |
| Pi-hole has two lists enabled, and they are the two of `qberrypi.example.toml`: 78,216 and 225,344 entries, 303,560 rows. | The example lists are the real workload. |
| `rustls` 0.23 + `rustls-rustcrypto` 0.1.0-pre.0 + `webpki-roots` 1 + `tokio` (and `tokio-rustls`, which this plan no longer uses) cross-compile to `aarch64-unknown-linux-musl` with the repository's linker settings: static, 1.30 MB stripped, no C in the tree. On the development machine the same program fetched both lists from `raw.githubusercontent.com` (TLS 1.3, HTTP/1.1, `Content-Length`, handshake 21 ms). | The "fails to build" half of the spec's risk is retired; the "fails to handshake on the board" half is Task 11's Pi check. |
| `openssl speed` on the Pi, one core, with OpenSSL's assembly: ChaCha20-Poly1305 232 MB/s, AES-128-GCM 38 MB/s, AES-256-GCM 32 MB/s on 16 KB blocks; checking a signature takes 0.21 ms (RSA-2048), 0.79 ms (RSA-4096), 0.5 ms (ECDSA P-256), 3.6 ms (P-384); a key agreement 0.4 ms (X25519, P-256). | The floor for TLS in software on this board; see "What holds the runtime thread". |
| Both lists merged: 302,176 rules, 7.33 MB as canonical text, 1.84 MB at zstd level 19. `ruzstd` 0.9 unpacks it in 20 ms on the development machine. | See Budgets. |
| QEMU's `raspi3b` has no network card of its own; a USB one needs `cdc_ether`, a module (`CONFIG_USB_NET_CDCETHER=m`). The development machine has no `qemu-aarch64` and no `dig`; `ip_unprivileged_port_start` is 1024. | See the QEMU decision. |

## Decisions the spec leaves open

| Subject | Decision | Task |
|---|---|---|
| Runtime | The one milestone 1 built: tokio, current-thread, on PID 1's main thread (ruling 1 of `2026-11-10-execution-order.md`). This plan adds no thread of its own and no second runtime; its components are tasks on that one. Current-thread suits this load on a Cortex-A53: tens of queries a second, each a few microseconds of work on one `&mut Resolver`; a second worker would add locking and cross-core wake-ups on a processor with small caches and gain nothing. What does take processor time goes to the blocking pool, capped at 2 threads, and so to another of the four cores. | 2 |
| Starting the components | `services::start`, the first statement of milestone 1's `serve`: before `start_network` and before Wi-Fi is first polled, so DNS listens before there is a network. Each component is an `async fn run(..) -> io::Result<()>` that can be started afresh; milestone 4's supervisor takes them over as they are. | 2 |
| A stalled runtime | The hardware watchdog (ruling 2): milestone 1's main loop pets it from the same thread, so a future that holds the thread stops the pets. This plan adds no detector of its own; it keeps every hold of the thread far under a second, by the argument and the tests of "What holds the runtime thread". | 2, 10, 11 |
| Several threads and `fatal` | A pool thread can panic, and the release build aborts through the panic hook into `fatal`. The behaviour is ruling 3's: the first fatal error wins, a second thread's fatal error parks, and once a fatal error has begun only its thread pets the watchdog. Task 3 of the milestone 4/5 plan implements it, because it runs first and starts the first second thread; this plan reuses it and adds what the card needs with two threads: the main loop neither returns nor restarts once another thread's fatal error has begun, card use is serialised, and a log lock held by the other thread is waited for, for 200 ms. | 2 |
| A component that ends | Logged at ERROR, not restarted. Restart and reboot policy are milestone 4's. | 2 |
| TLS and the runtime thread | A whole connection — connect, handshake, every record, the HTTP body — is one blocking job on the pool, over `std::net::TcpStream` and `rustls::StreamOwned`. Decrypting records in an async task would have been acceptable (0.3 to 2 ms a record); the handshake's one indivisible step is estimated at 10 to 45 ms, too near the 50 ms line to leave on the thread on an estimate. | 10 |
| Listening | `0.0.0.0:53`, UDP and TCP, bound before the network is up and only once the block set is built, so no query is ever answered unblocked. | 4, 13 |
| Upstream exchange | A fresh UDP socket per attempt, connected to the upstream (the kernel then drops other sources and picks a random port); ID from the kernel's random source; 2 s for UDP, 4 s for the TCP retry; the upstream that answered last is asked first. At most 256 forwards in flight; one more gets SERVFAIL at once. Identical questions in flight are not merged. | 3, 4 |
| Upstream latency | From the first send to the accepted answer, TCP retry included, smoothed by 1/8 per sample; unknown until the first answer. | 3 |
| Local midnight | New optional key `timezone`, a POSIX TZ rule such as `CET-1CEST,M3.5.0,M10.5.0/3`, default `UTC0`. It is the last line of the zone's file under `/usr/share/zoneinfo`, so it needs no zone database in the image and still follows daylight saving time. The offset is given to `qb-dns` again every minute and after a clock step. | 1, 4 |
| Time servers | New optional key `net.time_servers`, default `time.cloudflare.com` and `time.google.com`: both are offered to the public, and the NTP pool asks that its plain zone not be a built-in default. Names resolve through qberrypi's own forwarder, as the spec says. | 1, 5 |
| SNTP | Starts when a default route appears. Random transmit timestamp, checked on the reply. The clock is stepped when it is 0.5 s or more out; checked again every hour; a failed round is retried after 5, 10, 20, 40, then every 60 s. | 5 |
| Own lookups | In-process through `Dns::answer`, as a TCP client would be answered: cached and counted like any query, no loopback socket, no libc. An answer of `0.0.0.0` counts as no address. | 4 |
| Status server here | `/api/v1/stats` and `/log`. `/`, `/api/v1/queries` and the Wi-Fi fields are milestone 4's. `/log` is here because it lets a running one-shot boot be read from the development machine. | 6 |
| QEMU | No network card. A user-mode network needs a USB network module that the Pi never uses, and a hermetic upstream on ports 53 and 123, which an unprivileged host cannot bind; forwarding, caching, SNTP and HTTPS are instead tested against fake servers on the host's loopback, and end to end on the Pi. QEMU shows what only the real kernel can: the runtime as PID 1, port 53 and port 80 bound, the snapshot blocking with no network. The existing scenarios keep `-nic none` and their kernel arguments; a seventh adds the word `qberrypi.selftest.dns`. | 7, 13 |
| Pi checks | `cargo xtask probe`, not `resolvectl`, which cannot be pointed at one server without changing this machine's resolver. | 8, 14 |
| Snapshot pinning | By hash, taken when `cargo xtask fetch-lists` downloads, kept in a lock file in the git-ignored cache; `cargo xtask build` reads only the cache and refuses a file whose hash has changed. Not by a committed hash or date: the URLs are moving branches whose content changes daily, the lists are the owner's choice in an uncommitted file, and their licences keep their text out of the repository. The same cache gives the same image bytes. | 12 |
| Which lists | `dns.lists` of `./qberrypi.toml`, or of `qberrypi.example.toml` when there is none. Nothing else of that file is read by the build, and no URL goes into the image. | 12 |
| Snapshot format | One list text in canonical form — a header line, `0.0.0.0 name` lines, `\|\|name^` lines, sorted, no duplicates — compressed with zstd level 19 at `/blocklist.zst`, as the spec's boot chain shows it; unpacked on the Pi with `ruzstd`. It goes through `BlockSetBuilder::add_list` like any list. | 12, 13 |
| Snapshot marker | Every snapshot blocks `qberrypi-snapshot.invalid`; a refreshed set does not. It gives QEMU a listed name that does not depend on the lists, and lets the Pi check see the swap. | 12, 13, 14 |
| A broken snapshot | DNS starts with the configuration's own `deny` and `allow` and an ERROR line. | 13 |
| Refresh | First 60 s after the clock is set, on every boot; then every 24 h; after a failure every hour. If any list fails or holds no rule, the whole refresh fails and the set is kept. | 11 |
| HTTPS client | Hand-written HTTP/1.1 `GET` over blocking `rustls`: `Accept-Encoding: identity`, `Connection: close`; `Content-Length`, chunked or close-delimited bodies; 32 MiB cap; 120 s in all; at most 3 redirects, to `https` only. | 10 |
| `ring` | Only if `rustls-rustcrypto` fails on the board in Task 11's Pi check; the steps are in Task 10. | 10, 11 |
| `deny`, `allow` | Checked when the configuration is parsed, so a bad entry is a configuration error that names its key. | 1 |
| File names | SNTP is `sntp.rs`, beside milestone 1's `net.rs`, which sets the address and the route. The components' starting place is `services.rs`; `supervisor.rs`, the spec's name, is left for milestone 4, whose plan creates it. | 2, 5 |
| Status JSON | One flat object, with the key names of milestone 4's plan wherever the two overlap, so that plan's checks read this server unchanged. | 6, 11 |

## Budgets

| What | Budget | Basis |
|---|---|---|
| Executable, stripped | 3 MB (now 0.54 MB) | The TLS spike alone is 1.30 MB. |
| `/blocklist.zst` for the example lists | 2.5 MB | 1.84 MB measured. |
| `initramfs8` | 6 MB (now 1.13 MB) | About 3.9 MB expected; roughly 0.3 s more for the firmware to load. |
| Snapshot unpacked and built on the Pi | 3 s, on a pool thread, beside the Wi-Fi join | 20 ms + 50 ms on the development machine, taken as 13 times faster. The board's figure is logged. |
| Memory at the worst moment (a refresh) | 120 MB | Old set 7, new builder 13, one list's text 5, cache and query log at their worst 61. |

`cargo xtask build` prints the first three; Task 15 records all five from the board.

## What holds the runtime thread

Ruling 2 allows no future to hold the one runtime thread for more than about a second: the main loop on it pets the watchdog every 5 s against a timeout of 15 s, and answers the access point's handshake frames. This plan's line is lower: anything over about 50 ms of processor time on the board in one go is a blocking job, through `services::blocking`.

| Work | Where | Longest hold of the runtime thread, on the board |
|---|---|---|
| Deciding a query; relaying a cached or an upstream answer | runtime | under 1 ms: `qb-dns` budgets a lookup at 5 µs on the development machine, and no packet is over 4,096 bytes |
| Swapping the block set in and dropping the old one | runtime | a move and six buffers freed: about 1 ms |
| `/api/v1/stats`; `/log`, at most 256 KiB copied under the log's lock | runtime | about 1 ms |
| SNTP, the self-test, every wait | runtime | microseconds between two awaits |
| Unpacking the snapshot; parsing a list; `BlockSetBuilder::build` | pool | none; 0.3 to 2 s of a pool thread |
| A list fetch: TCP connect, TLS handshake, every record, the HTTP body | pool | none; seconds of a pool thread, most of them waiting |

**TLS.** The Pi's processor has no AES instructions. With OpenSSL's assembly it does 232 MB/s of ChaCha20-Poly1305 and 38 MB/s of AES-128-GCM (see Facts): 0.07 ms and 0.43 ms for a 16 KB record. The pure-Rust code is slower. How much could not be measured — the temporary volume's quota ran out before a software-only build of the prototype could be timed — so it is taken as up to five times: 0.3 ms a record with ChaCha20, which `https::provider` offers first, 2 ms with AES-GCM, and 0.2 to 1 s of processor for a whole 7.5 MB refresh. That would be acceptable in an async task with a yield after every 64 KiB. The handshake is not so clear: the server's certificates and its signature are checked in one step that cannot be cut up — two or three chain signatures and one more, 2 to 9 ms with OpenSSL's code on this board, so an estimated 10 to 45 ms in pure Rust. That is at the 50 ms line, on an estimate. So the whole connection is a blocking job, which also makes the client plain blocking code and drops `tokio-rustls`. Task 11's Pi check logs the board's real figure for every list.

Three tests hold the line where the work is: `blocking_work_does_not_hold_the_runtime_thread` (Task 2), `a_fetch_does_not_hold_the_runtime_thread` (Task 10) and `a_refresh_does_not_hold_the_runtime_thread` (Task 11); each runs a 1 ms ticker beside the work on a current-thread runtime and fails if two ticks are ever 100 ms apart. The snapshot load of Task 13 goes through the same `blocking`.

The pool's two threads: at boot one unpacks and builds the snapshot; a refresh uses one at a time, for a fetch, then a parse, then the build. Milestone 4 gives the other to the panel for good.

## The seam with milestone 1

`docs/superpowers/plans/2026-11-10-m1-wifi.md` runs before this plan. What this plan takes from it:

- The one runtime, built in `init::run` after step 9 and blocked on `async fn serve`, whose loop pets the watchdog, saves the log and runs Wi-Fi as a future beside it. Task 2 moves the building of it into `services::runtime()`, to cap the blocking pool, and makes `services::start` the first statement of `serve`. tokio is already a dependency; Task 2 adds the `io-util` feature.
- The places in `init.rs` that Task 2 edits keep their names: `init::run`, where the runtime is built; `serve`, the loop that logs `returning`; `fatal`, `rescue` and `on_card`.
- `lo` is up (`net: lo is up`), which Task 7's self-test needs. `LogBuf::text` exists; Task 6 uses it.
- Once the Pi has joined, `/proc/net/route` shows a default route, and the SNTP task waits for exactly that. The listeners bind `0.0.0.0` and need not know the address.
- The main loop saves the log to the card at the join, at most every 30 s after, and on the way out, so the components' lines reach the card without the components touching it. `deploy` refuses a collected log that holds the passphrase.
- In QEMU, milestone 1 logs `WARN wifi: wlan0 is absent, not joining` and allows it as `NO_WLAN`.

Milestone 1's own section "Seams with the other plans" describes an earlier draft of this plan, with a `services` thread and a heartbeat. The rulings replaced that draft; what is written here holds.

This plan has no radio code, so the simulated-radio ring does not apply to it.

## The seam with milestones 4 and 5

`docs/superpowers/plans/2026-11-10-m4-m5-resilience-panel.md` runs on both sides of this plan: its Tasks 1–6 before milestone 1, its Tasks 7–13 after this plan.

From its Tasks 1–6, already in the tree:

- `fatal` for several threads — `fatal_entry`, `may_pet`, `FATAL_THREAD` (its Task 3). Task 2 here reuses them and adds the card lock, the wait for the log's lock, and the main loop standing aside.
- The panel on a thread of its own, the warning `NO_PANEL` in QEMU's allowed list, five more modules in the initramfs listing, and `deploy` waiting for the Pi according to `return_after_secs`.
- `live::Source` and `live::BlockingControl`, with stand-ins. This plan does not implement them: that plan's Task 12 writes the adapters.

For its Tasks 7–13:

- Every component here is an `async fn run(..) -> io::Result<()>` that returns when it fails and can be started afresh: `dns::listen::run`, `Sntp::run`, `Status::run`, `lists::refresh::run`. `services::run` is the one place that starts them; the supervisor takes them from there. This plan creates no `supervisor.rs`.
- When that plan rebuilds the runtime in its Task 7, it must go on using `services::runtime()`, or keep its cap of 2 pool threads; and its `leave` must keep Task 2's rule that the main loop does nothing once another thread's fatal error has begun.
- What its `live::Source` wants is here as `Dns::resolver().stats()`, `Dns::upstreams().latency_ms()`, `Dns::utc_offset()`, the `synced` watch channel and `Lists::get()`; its shared resolver and clock are `Dns::shared()` and `Dns::now()`. The latency here is smoothed by 1/8; that plan's decision is a median of nine, which is its Task 12's to make of it.
- Its status page (its Task 11) is skipped when `status.rs` exists. By ruling 5 the names built first stand: the constants and JSON keys here are that plan's own, and `/`, `/api/v1/queries`, `wifi` and `board_c` remain for it to add.

## File Structure

```
crates/qberrypi/src/
  config.rs          modify: timezone, net.time_servers, checked deny and allow
  services.rs        new: the runtime's builder, the blocking pool's one door, the components in order
  init.rs            modify: start the services; the card and the log with two threads
  sys.rs             modify: random_u64, set_clock
  dns/mod.rs         new: Dns — the shared resolver, answer, lookup_v4
  dns/upstream.rs    new: one exchange with the upstreams
  dns/client.rs      new: the few client packets qberrypi and xtask make themselves
  dns/listen.rs      new: UDP and TCP listeners
  dns/testutil.rs    new, test only: fake upstream, a service on loopback, a client
  sntp.rs            new: SNTP packets, the default-route check, the clock task
  status.rs          new: HTTP on port 80
  selftest.rs        new: the checks run under qberrypi.selftest.dns
  https.rs           new: URL, blocking HTTP/1.1 GET, TLS client
  lists/mod.rs       new: from_config, ListState
  lists/refresh.rs   new: fetch all, build, swap, schedule
  lists/snapshot.rs  new: header, marker, unpack, load
xtask/src/
  lists.rs           new: fetch-lists, canonical text, the snapshot
  probe.rs           new: the Pi checks' client
  build.rs           modify: blocklist.zst in the initramfs, sizes printed
  qemu.rs            modify: seventh scenario
  fetch.rs           modify: Download and download become pub(crate)
  main.rs            modify: fetch-lists, probe
qberrypi.example.toml, README.md, the spec's Configuration section    modify
docs/bring-up/m2.md, docs/bring-up/m3.md                              new
```

Unit tests live in a `tests` module at the foot of each file. Async tests are `#[tokio::test]`, which is a current-thread runtime, as on the board.

---

# Milestone 2 — Resolver

### Task 1: Configuration — time zone, time servers, checked names

**Files:**
- Modify: `crates/qberrypi/src/config.rs`, `crates/qberrypi/Cargo.toml`, `Cargo.lock`, `qberrypi.example.toml`, `docs/superpowers/specs/2026-11-10-qberrypi-design.md` (the Configuration section's example only)

**Interfaces:**
- Consumes: `qb_dns::name::{normalize, MAX_NAME_LEN}`.
- Produces:

```rust
pub struct Config { /* as before, and: */ pub timezone: TimeZoneRule }   // root key `timezone`; absent: UTC
pub struct Net { /* as before, and: */ pub time_servers: Vec<String> }   // `net.time_servers`; absent: the default
pub const DEFAULT_TIME_SERVERS: [&str; 2] = ["time.cloudflare.com", "time.google.com"];
#[derive(Debug, Clone)]
pub struct TimeZoneRule { /* private */ }
impl TimeZoneRule {
    pub fn utc() -> Self;
    pub fn parse(rule: &str) -> Option<Self>;
    pub fn offset_at(&self, unix_secs: u64) -> i32;    // local time minus UTC, in seconds; 0 if it cannot be worked out
}
```

Rules, each with its fixed error text (no error repeats a value from the file):

| Key | Rule | Reason text |
|---|---|---|
| `timezone` | A POSIX TZ rule. Parsed with `tz::timezone::TimeZoneSettings::new(&[], \|_\| Err("no files".into())).parse_posix_tz(rule)`, which reads no file; the offset is `find_local_time_type(unix).ut_offset()`. | `must be a POSIX TZ rule such as UTC0 or CET-1CEST,M3.5.0,M10.5.0/3` |
| `net.time_servers` | 1 to 4 entries, each an IPv4 address or a name `normalize` accepts; names are stored normalised. | `must list 1 to 4 host names or IPv4 addresses` |
| `dns.deny`, `dns.allow` | Every entry passes `normalize`. | `every entry must be a domain name` |

- [ ] **Step 1: Add the dependencies** — `cargo add -p qberrypi tz-rs@0.7 --no-default-features -F std` and `cargo add -p qberrypi qb-dns --path crates/qb-dns`
- [ ] **Step 2: Write the failing tests** in `config.rs`, beside the existing ones (`MINIMAL` and `EXAMPLE` are theirs)

```rust
const JAN: u64 = 1_768_478_400;                      // 2026-01-15T12:00:00Z
const JUL: u64 = 1_784_116_800;                      // 2026-07-15T12:00:00Z
const SPRING: u64 = 1_774_746_000;                   // 2026-03-29T01:00:00Z, when CET becomes CEST
const RULE_ERROR: &str = "must be a POSIX TZ rule such as UTC0 or CET-1CEST,M3.5.0,M10.5.0/3";

#[test] fn the_time_zone_defaults_to_utc_and_follows_its_rule() {
    assert_eq!(parse(MINIMAL).unwrap().timezone.offset_at(JUL), 0);
    let cfg = parse(&format!("timezone = \"CET-1CEST,M3.5.0,M10.5.0/3\"\n{MINIMAL}")).unwrap();
    assert_eq!((cfg.timezone.offset_at(JAN), cfg.timezone.offset_at(JUL)), (3600, 7200));
    assert_eq!((cfg.timezone.offset_at(SPRING - 1), cfg.timezone.offset_at(SPRING)), (3600, 7200));
    let west = TimeZoneRule::parse("EST5EDT,M3.2.0,M11.1.0").unwrap();
    assert_eq!((west.offset_at(JAN), west.offset_at(JUL)), (-18_000, -14_400));
    assert_eq!(TimeZoneRule::parse("<+0530>-5:30").unwrap().offset_at(JAN), 19_800);
    assert_eq!(TimeZoneRule::utc().offset_at(JAN), 0);
}
#[test] fn a_time_zone_that_is_not_a_rule_is_refused_by_key() {
    for bad in ["Europe/Berlin", "", "localtime", ":UTC", "CET-1CEST", "garbage,,"] {
        let e = parse(&format!("timezone = \"{bad}\"\n{MINIMAL}")).unwrap_err();
        assert_eq!((e.key.as_str(), e.reason.as_str()), ("timezone", RULE_ERROR), "{bad:?}");
    }
}
#[test] fn time_servers_have_a_default_and_are_checked() {
    assert_eq!(parse(MINIMAL).unwrap().net.time_servers, DEFAULT_TIME_SERVERS);
    let with = |list: &str| parse(&MINIMAL.replace("gateway = \"192.0.2.1\"", &format!("gateway = \"192.0.2.1\"\ntime_servers = {list}")));
    assert_eq!(with(r#"["192.0.2.123", "Time.Example.NET."]"#).unwrap().net.time_servers, ["192.0.2.123", "time.example.net"]);
    for bad in ["[]", r#"["a.example", "b.example", "c.example", "d.example", "e.example"]"#, r#"["not a name"]"#, r#"["https://example.com"]"#] {
        let e = with(bad).unwrap_err();
        assert_eq!((e.key.as_str(), e.reason.as_str()), ("net.time_servers", "must list 1 to 4 host names or IPv4 addresses"), "{bad}");
    }
}
#[test] fn deny_and_allow_entries_must_be_names() {
    for key in ["deny", "allow"] {
        let text = MINIMAL.replace("upstreams = [\"9.9.9.9\"]", &format!("upstreams = [\"9.9.9.9\"]\n{key} = [\"ok.example.com\", \"not a name\"]"));
        let e = parse(&text).unwrap_err();
        assert_eq!((e.key, e.reason.as_str()), (format!("dns.{key}"), "every entry must be a domain name"));
    }
}
#[test] fn the_example_file_shows_the_new_keys() {
    let cfg = parse(EXAMPLE).unwrap();
    assert_eq!((cfg.timezone.offset_at(JUL), cfg.net.time_servers.len()), (0, 2));
    assert!(EXAMPLE.contains("timezone = \"UTC0\"") && EXAMPLE.contains("time_servers = [\"time.cloudflare.com\", \"time.google.com\"]"));
}
```

- [ ] **Step 3: Run** `cargo test -p qberrypi config::` — expected: compile failure (`timezone`, `TimeZoneRule` not defined).
- [ ] **Step 4: Implement** the fields, the three rules, and the two known-key lists (`timezone` at the root, `time_servers` under `net`).
- [ ] **Step 5: Edit `qberrypi.example.toml`** — under `hostname`, the line `timezone = "UTC0"          # a POSIX TZ rule; yours is the last line of your zone's file: tail -n 1 /usr/share/zoneinfo/Europe/Berlin`; under `gateway`, the line `time_servers = ["time.cloudflare.com", "time.google.com"]`. Put the same two lines into the example block of the spec's Configuration section.
- [ ] **Step 6: Run** `cargo test --workspace` — expected: all pass, the five new ones among them; the QEMU scenario tests still find each of their strings exactly once in the example.
- [ ] **Step 7: Commit** — stage the five files by name; message `"Config: time zone rule, time servers, checked deny and allow"`.

---

### Task 2: The services on the runtime

Milestone 1 built the one runtime, on PID 1's main thread. This task gives this plan's components their place on it, caps the blocking pool, and adds what a second thread needs around the card.

**Files:**
- Create: `crates/qberrypi/src/services.rs`
- Modify: `crates/qberrypi/src/init.rs`, `crates/qberrypi/src/lib.rs`, `crates/qberrypi/Cargo.toml`, `Cargo.lock`, `xtask/src/qemu.rs`

**Interfaces:**
- Consumes: milestone 1's `async fn serve` and the runtime `init::run` builds for it; `fatal_entry`, `may_pet` and `FATAL_THREAD` from Task 3 of the milestone 4/5 plan, which ran before this one.
- Produces:

```rust
// services.rs
pub const BLOCKING_THREADS: usize = 2;
pub struct Context { pub cfg: &'static Config, pub log: &'static Mutex<LogBuf>, pub started: Instant }
pub fn runtime() -> io::Result<tokio::runtime::Runtime>;      // the one runtime: current-thread, I/O and time on, a blocking pool of BLOCKING_THREADS
pub fn start(ctx: Context) -> tokio::task::JoinHandle<()>;    // called on the runtime: logs `services: started`, spawns `run`
pub fn spawn_component<F>(name: &'static str, task: F) -> tokio::task::JoinHandle<()>
    where F: Future<Output = io::Result<()>> + Send + 'static;
pub async fn blocking<T, F>(what: &'static str, work: F) -> io::Result<T>
    where F: FnOnce() -> T + Send + 'static, T: Send + 'static;
async fn run(ctx: Context);                                   // private: the components, in order
```

A component is an `async fn run(..) -> io::Result<()>` that makes its own sockets from what it is given, runs until it fails, and returns the error. It never exits the process and never loops silently on a failure; called again with the same arguments, it starts afresh. That is the shape milestone 4's `supervisor::Component` wraps. Until that supervisor exists, `spawn_component` spawns one on the runtime and logs `{name}: stopped: {error}` at ERROR when it returns `Err`, and `{name}: stopped` at ERROR when it returns `Ok`; it starts nothing again.

`blocking` is the one way off the runtime thread: `tokio::task::spawn_blocking(work)`, awaited; a job that could not be joined is an `io::Error` that names `what`. In the release build a panic in `work` does not come back at all: it reaches the panic hook, and `fatal`, on the pool's thread.

`run` in this task only waits for ever; later tasks add components to it.

Changes in `init.rs`:

1. `init::run` builds the runtime with `services::runtime()` where milestone 1 built it inline.
2. `serve`'s first statement is `services::start(Context { cfg, log, started })`, with the `'static` references init keeps in `CONFIG` and `LOG`: the components start before `start_network` and before Wi-Fi is first polled.
3. `fatal` with several threads is already there, as the rulings in `2026-11-10-execution-order.md` word it: the first fatal error wins, a second thread's fatal error parks, and once a fatal error has begun only its thread pets the watchdog. If `init.rs` has no `fatal_entry` — the plans were run in another order — add it, `may_pet`, `FATAL_THREAD` and their test exactly as Task 3 of the milestone 4/5 plan gives them, before anything below.
4. The main loop stands aside too: when `may_pet` says no for its thread, a tick does not log `returning`, save the log or restart; it awaits `std::future::pending()`. The thread in `fatal` restarts the board.
5. Inside `fatal` and `rescue`, the log is taken with `lock_within(log, LOG_LOCK_WAIT)` where it was `lock_if_free`: with two threads, a log that is locked may only be the other thread writing a line.
6. `on_card` holds a private `static CARD_BUSY: Mutex<()>` for as long as it runs, taken with `lock_within(&CARD_BUSY, CARD_LOCK_WAIT)`; when the wait runs out it goes on without the lock, since the holder is then the thread that failed. The main loop's saves and a rescue on a pool thread can no longer mount and unmount the card under each other.

```rust
// init.rs, private
const LOG_LOCK_WAIT: Duration = Duration::from_millis(200);
const CARD_LOCK_WAIT: Duration = Duration::from_secs(5);
fn lock_within<T>(mutex: &Mutex<T>, wait: Duration) -> Option<MutexGuard<'_, T>>;   // tries every 5 ms; a poisoned lock is taken
fn on_card_within<T>(card: &mut dyn Card, access: Access, lock_wait: Duration, work: impl FnOnce(&Path) -> T) -> io::Result<(T, io::Result<()>)>;   // on_card calls it with CARD_LOCK_WAIT
```

- [ ] **Step 1: Add the feature** — `cargo add -p qberrypi tokio --no-default-features -F rt,net,time,sync,io-util,macros` (milestone 1 has all of these but `io-util`)
- [ ] **Step 2: Write the failing tests**

In `services.rs`. `longest_gap(while_this: impl Future) -> (Duration, Output)` runs a second future beside the given one that sleeps 1 ms over and over, and returns the longest time between two of its wake-ups; it goes into a `#[cfg(test)] pub(crate) mod testutil` of this file, for Tasks 10 and 11 too.

```rust
#[test] fn the_runtime_has_one_thread_and_a_pool_of_two() {
    let rt = runtime().unwrap();
    let started = Instant::now();
    let main = std::thread::current().id();
    let ids = rt.block_on(async {
        let job = || blocking("test", || { std::thread::sleep(Duration::from_millis(200)); std::thread::current().id() });
        let (a, b, c) = tokio::join!(job(), job(), job());
        assert_eq!(std::thread::current().id(), main);              // the futures themselves run where block_on was called
        [a.unwrap(), b.unwrap(), c.unwrap()]
    });
    assert!(ids.iter().all(|id| *id != main));
    assert!(started.elapsed() >= Duration::from_millis(400));        // the third job waited for a place
}
#[tokio::test] async fn blocking_work_does_not_hold_the_runtime_thread() {
    let (gap, done) = longest_gap(blocking("test", || { std::thread::sleep(Duration::from_millis(300)); 7 })).await;
    assert_eq!(done.unwrap(), 7);
    assert!(gap < Duration::from_millis(100), "{gap:?}");
}
#[tokio::test] async fn a_component_that_ends_does_not_take_the_runtime_with_it() {
    spawn_component("test", async { Err(std::io::Error::other("gone")) }).await.unwrap();
    spawn_component("test", async { Ok(()) }).await.unwrap();
}
```

In `init.rs`:

```rust
#[test] fn a_lock_another_thread_holds_briefly_is_waited_for_and_one_held_on_is_given_up() {
    let mutex = Arc::new(Mutex::new(0));
    let held = mutex.clone();
    let holder = thread::spawn(move || { let _guard = held.lock().unwrap(); thread::sleep(Duration::from_millis(60)); });
    thread::sleep(Duration::from_millis(20));               // the holder has it now
    assert!(lock_within(&mutex, Duration::from_secs(5)).is_some());
    holder.join().unwrap();
    let guard = mutex.lock().unwrap();
    let started = Instant::now();
    assert!(lock_within(&mutex, Duration::from_millis(50)).is_none());
    assert!(started.elapsed() >= Duration::from_millis(50));
    drop(guard);
}
#[test] fn two_threads_never_have_the_card_at_once() {
    static INSIDE: AtomicUsize = AtomicUsize::new(0);
    let user = || thread::spawn(|| (0..50).all(|_| {
        let mut card = FakeCard::new();
        on_card(&mut card, Access::Writable, |_| { let others = INSIDE.fetch_add(1, Ordering::SeqCst); thread::yield_now(); INSIDE.fetch_sub(1, Ordering::SeqCst); others == 0 }).unwrap().0
    }));
    let (a, b) = (user(), user());
    assert!(a.join().unwrap() && b.join().unwrap());
}
#[test] fn a_card_whose_lock_is_never_given_up_is_used_all_the_same() {
    let _held = lock(&CARD_BUSY);
    let done = thread::spawn(|| {
        let mut card = FakeCard::new();
        on_card_within(&mut card, Access::Writable, Duration::from_millis(50), |boot| bootpart::restore_pios_config(boot).is_ok()).unwrap().0
    }).join().unwrap();
    assert!(done);
}
#[test] fn the_main_loop_stands_aside_for_a_fatal_error_on_another_thread() {
    let here = thread::current().id();
    let other = thread::spawn(|| thread::current().id()).join().unwrap();
    assert!(may_pet(None, here) && may_pet(Some(here), here));      // no fatal error, or its own: the loop goes on
    assert!(!may_pet(Some(other), here));                           // another thread's: no pet, no `returning`, no restart
}
```

- [ ] **Step 3: Run** `cargo test -p qberrypi -- services:: init::` — expected: compile failure.
- [ ] **Step 4: Implement** `services.rs`, the changes in `init.rs`, and `pub mod services;` in `lib.rs`.
- [ ] **Step 5: Run** `cargo test -p qberrypi` — expected: all pass, the earlier plans' tests among them.
- [ ] **Step 6: Add one condition to `one_shot_conditions` in `xtask/src/qemu.rs`** — `evidence.serial_has("INFO  services: started")` — then run `cargo xtask build && cargo xtask qemu-test`. Expected: six `ok`.
- [ ] **Step 7: Commit** — stage the six files by name; message `"Services: a place on the runtime, a blocking pool of two, the card safe from two threads"`.

---

### Task 3: One exchange with the upstreams

**Files:**
- Create: `crates/qberrypi/src/dns/mod.rs` (the module list only), `crates/qberrypi/src/dns/upstream.rs`, `crates/qberrypi/src/dns/client.rs`, `crates/qberrypi/src/dns/testutil.rs`
- Modify: `crates/qberrypi/src/sys.rs`, `crates/qberrypi/src/lib.rs`, `crates/qberrypi/Cargo.toml`, `Cargo.lock`

**Interfaces:**
- Consumes: `qb_dns::{Resolver, BlockSet, Pending, UpstreamOutcome, Now, Transport}`.
- Produces:

```rust
// sys.rs
pub fn random_u64() -> u64;                 // from the kernel's random source (rustix::rand::getrandom)

// dns/client.rs
pub fn query(id: u16, name: &str, qtype: u16) -> io::Result<Vec<u8>>;   // one question, class IN, RD set, no OPT; Err for a name that cannot be encoded
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer { pub rcode: u8, pub addrs: Vec<IpAddr>, pub min_ttl: Option<u32>, pub truncated: bool }
pub fn read_answer(reply: &[u8], id: u16) -> Option<Answer>;            // None unless it is a response with this ID
impl Answer {
    pub fn v4(&self) -> Vec<Ipv4Addr>;                                  // the IPv4 addresses among `addrs`, in order
    pub fn summary(&self) -> String;                                    // "NOERROR 0.0.0.0", "NOERROR", "NXDOMAIN", "SERVFAIL", else "RCODE n"; the first address only
}

// dns/upstream.rs
pub const UPSTREAM_PORT: u16 = 53;
pub const UDP_WAIT: Duration = Duration::from_secs(2);
pub const TCP_WAIT: Duration = Duration::from_secs(4);
pub const UDP_BUFFER: usize = 4096;
pub struct Upstreams { /* private */ }
impl Upstreams {
    pub fn new(servers: &[Ipv4Addr]) -> Self;                           // UPSTREAM_PORT, UDP_WAIT, TCP_WAIT
    pub fn with(servers: Vec<SocketAddr>, udp_wait: Duration, tcp_wait: Duration) -> Self;
    pub async fn exchange(&self, pending: &Pending, take: &mut (dyn FnMut(&[u8], Transport) -> UpstreamOutcome + Send)) -> Option<UpstreamOutcome>;
    pub fn latency_ms(&self) -> Option<u16>;                            // None before the first answer
    pub fn failures(&self) -> u64;                                      // times an upstream gave no usable answer
    pub fn preferred(&self) -> SocketAddr;
}
pub(crate) fn order(preferred: usize, len: usize) -> impl Iterator<Item = usize>;   // preferred, then the others in turn, wrapping
pub(crate) fn smoothed(old: Option<f32>, sample_ms: f32) -> f32;                    // the first sample as it is; then old + (sample − old) / 8

// dns/testutil.rs — #[cfg(test)] pub(crate) mod testutil;
pub(crate) const NOW: Now = Now { mono_secs: 1, unix_secs: 1_800_000_000 };
pub(crate) enum Reply { Answer(Ipv4Addr), Silent, WrongIdFirst(Ipv4Addr), OtherQuestionFirst(Ipv4Addr), TruncatedOverUdp(Ipv4Addr), After(Duration, Ipv4Addr) }
pub(crate) struct FakeUpstream { pub(crate) addr: SocketAddr, /* private */ }
impl FakeUpstream {
    pub(crate) async fn start(reply: Reply) -> Self;        // UDP and TCP on one 127.0.0.1 port; answers with one A record, TTL 60
    pub(crate) fn udp_queries(&self) -> usize;
    pub(crate) fn tcp_queries(&self) -> usize;
}
pub(crate) fn closed_port() -> SocketAddr;                  // a 127.0.0.1 port on which nothing listens, UDP or TCP
pub(crate) fn pending(resolver: &mut Resolver, name: &str) -> Pending;   // handle_query(query(7, name, 1)) over UDP at NOW; panics unless Forward
pub(crate) fn ip(text: &str) -> Ipv4Addr;
pub(crate) fn ms(n: u64) -> Duration;
pub(crate) fn hex(bytes: &[u8]) -> String;
pub(crate) fn unhex(text: &str) -> Vec<u8>;                 // ignores whitespace
```

`exchange`, for each upstream in `order(preferred, len)`, until one is done:

1. Bind a new UDP socket to `0.0.0.0:0` and connect it to the upstream. Take an ID from the low 16 bits of `sys::random_u64()`. Send `pending.upstream_query(id)`.
2. Until `udp_wait` after that send, receive. A packet under 12 bytes, or with another ID, is ignored. Otherwise call `take(packet, Udp)`: `Mismatch` is ignored and the wait goes on; `RetryOverTcp` goes to step 3; `Reply` and `Refreshed` are done.
3. Over TCP, all within `tcp_wait`: connect, send the query with a new ID behind its 2-byte length, read one length-prefixed message. Another ID, or `Mismatch` from `take(packet, Tcp)`, fails this upstream; anything else is done.
4. A socket error or a wait that runs out fails this upstream: `failures` + 1, and the next one is tried.

When one is done: its latency is the time from step 1's send to the accepted answer, passed through `smoothed`; it becomes the preferred upstream; the result is `Some(outcome)`. When all have failed the result is `None`. Two warnings, and no other log line: `dns: upstream {old} does not answer; now asking {new}` when the preferred one changes, and `dns: no upstream answers` at most once in 60 s.

`FakeUpstream` builds its answers with `hickory-proto`, as the qb-dns plan's "hickory-proto 0.26 facts" describe: the query's ID and question, one A record. `WrongIdFirst` sends a copy with the ID plus one before the right answer; `OtherQuestionFirst` sends an answer for `other.example.net` under the right ID first; `TruncatedOverUdp` answers UDP with TC set and no records, and TCP in full.

- [ ] **Step 1: Add the dependencies** — `cargo add -p qberrypi hickory-proto@0.26` and `cargo add -p qberrypi rustix -F rand`
- [ ] **Step 2: Write the failing tests**

In `dns/client.rs` (the second packet is the hand-checked blocked reply of the qb-dns plan's Task 6):

```rust
#[test] fn a_query_is_the_plain_packet() {
    assert_eq!(hex(&query(0x1234, "example.com", 1).unwrap()), "123401000001000000000000076578616d706c6503636f6d0000010001");
    assert!(query(1, &"a".repeat(64), 1).is_err());
}
#[test] fn an_answer_is_read_only_under_its_own_id() {
    let blocked = unhex("12348180000100010000000007 4558616d706c65 03 636f4d 00 0001 0001 c00c 0001 0001 00000002 0004 00000000");
    let a = read_answer(&blocked, 0x1234).unwrap();
    assert_eq!(a, Answer { rcode: 0, addrs: vec![IpAddr::from([0, 0, 0, 0])], min_ttl: Some(2), truncated: false });
    assert_eq!(a.summary(), "NOERROR 0.0.0.0");
    assert_eq!(read_answer(&blocked, 0x1235), None);
    assert_eq!(read_answer(&query(0x1234, "example.com", 1).unwrap(), 0x1234), None);      // a query, not a response
    assert_eq!(read_answer(&unhex("123481830000000000000000"), 0x1234).unwrap().summary(), "NXDOMAIN");
    assert_eq!(read_answer(&unhex("123481820000000000000000"), 0x1234).unwrap().summary(), "SERVFAIL");
    assert_eq!(read_answer(&[1, 2, 3], 0x0102), None);
}
```

In `dns/upstream.rs`, with `async fn run(ups: &Upstreams, name: &str) -> (Option<Answer>, Duration)` — a fresh `Resolver::new(BlockSet::default())`, `pending(&mut r, name)`, `exchange` with `take = |packet, via| r.handle_upstream(&p, packet, via, NOW)`, the `Reply` bytes read with `read_answer(.., 7)`, and the time the exchange took:

```rust
#[tokio::test] async fn an_answer_is_taken_and_its_latency_kept() {
    let up = FakeUpstream::start(Reply::Answer(ip("192.0.2.10"))).await;
    let ups = Upstreams::with(vec![up.addr], ms(300), ms(600));
    assert_eq!(ups.latency_ms(), None);
    assert_eq!(run(&ups, "example.com").await.0.unwrap().v4(), [ip("192.0.2.10")]);
    assert!(ups.latency_ms().is_some());
    assert_eq!((ups.failures(), up.udp_queries(), up.tcp_queries()), (0, 1, 0));
}
#[tokio::test] async fn a_packet_that_is_not_the_answer_is_ignored_and_the_wait_goes_on() {      // Review Focus 2
    for reply in [Reply::WrongIdFirst(ip("192.0.2.10")), Reply::OtherQuestionFirst(ip("192.0.2.10"))] {
        let up = FakeUpstream::start(reply).await;
        let ups = Upstreams::with(vec![up.addr], ms(300), ms(600));
        assert_eq!(run(&ups, "example.com").await.0.unwrap().v4(), [ip("192.0.2.10")]);
        assert_eq!((ups.failures(), up.udp_queries()), (0, 1));
    }
}
#[tokio::test] async fn a_truncated_answer_is_asked_for_again_over_tcp() {
    let up = FakeUpstream::start(Reply::TruncatedOverUdp(ip("192.0.2.10"))).await;
    let ups = Upstreams::with(vec![up.addr], ms(300), ms(600));
    assert_eq!(run(&ups, "example.com").await.0.unwrap().v4(), [ip("192.0.2.10")]);
    assert_eq!((up.udp_queries(), up.tcp_queries()), (1, 1));
}
#[tokio::test] async fn a_silent_upstream_is_left_for_the_next_and_not_asked_first_again() {      // Review Focus 1
    let dead = FakeUpstream::start(Reply::Silent).await;
    let live = FakeUpstream::start(Reply::Answer(ip("192.0.2.10"))).await;
    let ups = Upstreams::with(vec![dead.addr, live.addr], ms(150), ms(300));
    let (first, took) = run(&ups, "example.com").await;
    assert!(first.is_some() && took >= ms(150));
    assert_eq!((ups.failures(), ups.preferred()), (1, live.addr));
    let (second, took) = run(&ups, "example.org").await;
    assert!(second.is_some() && took < ms(100));
    assert_eq!(dead.udp_queries(), 1);
}
#[tokio::test] async fn a_port_that_refuses_fails_at_once() {
    let live = FakeUpstream::start(Reply::Answer(ip("192.0.2.10"))).await;
    let ups = Upstreams::with(vec![closed_port(), live.addr], ms(2000), ms(2000));
    let (answer, took) = run(&ups, "example.com").await;
    assert!(answer.is_some() && took < ms(500));
}
#[tokio::test] async fn when_no_upstream_answers_there_is_no_outcome() {
    let (a, b) = (FakeUpstream::start(Reply::Silent).await, FakeUpstream::start(Reply::Silent).await);
    let ups = Upstreams::with(vec![a.addr, b.addr], ms(100), ms(200));
    let (answer, took) = run(&ups, "example.com").await;
    assert!(answer.is_none() && took >= ms(200) && took < ms(1000));
    assert_eq!((ups.failures(), ups.latency_ms()), (2, None));
}
#[test] fn the_order_starts_at_the_preferred_and_wraps() {
    assert_eq!(order(1, 3).collect::<Vec<_>>(), [1, 2, 0]);
    assert_eq!(order(0, 1).collect::<Vec<_>>(), [0]);
}
#[test] fn latency_moves_an_eighth_of_the_way_to_each_sample() {
    assert_eq!(smoothed(None, 40.0), 40.0);
    assert_eq!(smoothed(Some(40.0), 8.0), 36.0);
}
```

- [ ] **Step 3: Run** `cargo test -p qberrypi dns::` — expected: compile failure.
- [ ] **Step 4: Implement** `sys::random_u64`, `client.rs`, `testutil.rs`, `upstream.rs`; `dns/mod.rs` declares `pub mod client; pub mod upstream;` and the test module.
- [ ] **Step 5: Run** `cargo test -p qberrypi dns::` — expected: 10 passed.
- [ ] **Step 6: Commit** — stage the eight files by name; message `"dns: one exchange with the upstreams — UDP, TCP on truncation, failover"`.

---

### Task 4: The DNS service

**Files:**
- Create: `crates/qberrypi/src/dns/listen.rs`, `crates/qberrypi/src/lists/mod.rs`
- Modify: `crates/qberrypi/src/dns/mod.rs`, `crates/qberrypi/src/dns/testutil.rs`, `crates/qberrypi/src/services.rs`, `crates/qberrypi/src/lib.rs`

**Interfaces:**
- Consumes: Task 3's `Upstreams`, `client::{query, read_answer, Answer}`, `testutil`; Task 1's `TimeZoneRule`; `qb_dns::{Resolver, Action, BlockSet, BlockSetBuilder, Now, Transport}`; `services::spawn_component`.
- Produces:

```rust
// lists/mod.rs
pub fn from_config(deny: &[String], allow: &[String]) -> BlockSetBuilder;   // the builder every block set starts from

// dns/mod.rs
pub const DNS_PORT: u16 = 53;
pub const MAX_FORWARDS: usize = 256;
pub struct Dns { /* private: Arc<Mutex<Resolver>>, Upstreams, a semaphore of forwards, when it was made, the zone */ }
impl Dns {
    pub fn new(blockset: BlockSet, upstreams: Upstreams, zone: TimeZoneRule) -> Arc<Self>;
    pub(crate) fn with_forward_limit(blockset: BlockSet, upstreams: Upstreams, zone: TimeZoneRule, forwards: usize) -> Arc<Self>;
    pub fn now(&self) -> Now;                               // mono_secs since `new`; unix_secs from the system clock
    pub fn resolver(&self) -> MutexGuard<'_, Resolver>;     // taken whether or not poisoned; never held across an await
    pub fn shared(&self) -> Arc<Mutex<Resolver>>;           // the same resolver, for milestone 4's seam
    pub fn upstreams(&self) -> &Upstreams;
    pub fn sync_utc_offset(&self);                          // gives the resolver the zone's offset at this moment
    pub fn utc_offset(&self) -> i32;
    pub async fn answer(self: &Arc<Self>, packet: &[u8], transport: Transport) -> Option<Vec<u8>>;
    pub async fn lookup_v4(self: &Arc<Self>, name: &str) -> io::Result<Vec<Ipv4Addr>>;
}

// dns/listen.rs
pub const TCP_CLIENTS: usize = 32;
pub const TCP_IDLE: Duration = Duration::from_secs(10);
pub struct Listeners { pub udp: tokio::net::UdpSocket, pub tcp: tokio::net::TcpListener }
impl Listeners { pub fn addr(&self) -> SocketAddr; }
pub async fn bind(addr: SocketAddr) -> io::Result<Listeners>;      // UDP first; TCP on the port UDP was given
pub async fn run(dns: Arc<Dns>, addr: SocketAddr) -> io::Result<()>;                         // the component: bind, log `dns: listening on {addr}`, serve
pub async fn serve(dns: Arc<Dns>, listeners: Listeners) -> io::Result<()>;                  // serve_with(.., TCP_CLIENTS, TCP_IDLE)
pub(crate) async fn serve_with(dns: Arc<Dns>, listeners: Listeners, tcp_clients: usize, tcp_idle: Duration) -> io::Result<()>;
```

`answer` carries out what `resolver().handle_query(packet, transport, now())` decides:

| `Action` | What is done |
|---|---|
| `Reply(bytes)` | `Some(bytes)`. |
| `Forward(pending)` | If no forward permit is free: `pending.servfail()`. Otherwise `upstreams.exchange`, with `take` calling `resolver().handle_upstream(&pending, packet, via, now())`: `Reply(bytes)` gives `Some(bytes)`, no outcome gives `pending.servfail()`. |
| `ReplyAndRefresh(bytes, pending)` | A spawned task does the same exchange under a permit, or nothing if none is free; `Some(bytes)` at once. |
| `Drop` | `None`. |

`lookup_v4`: an IPv4 literal is returned as it is, with no query. Otherwise `answer(query(id, name, 1), Tcp)`; the result is the A records of a NOERROR answer. No answer, another rcode, no A record, or `0.0.0.0` among them is `ErrorKind::NotFound`.

`serve`: the UDP loop receives into a buffer of `upstream::UDP_BUFFER` bytes and spawns one task per packet, which sends what `answer(.., Udp)` returns back to the sender; nothing in the loop waits for an upstream. The TCP loop gives each connection a task, at most `tcp_clients` at a time — one more is accepted and closed at once. A connection is read as 2-byte length, then message; each is answered through `answer(.., Tcp)` in order; a length of 0, a read that waits longer than `tcp_idle`, or the end of the stream closes it.

In `services::run`, in this order: `lists::from_config(&cfg.dns.deny, &cfg.dns.allow).build()`; `Dns::new(set, Upstreams::new(&cfg.dns.upstreams), cfg.timezone.clone())`; `spawn_component("dns", listen::run(dns.clone(), 0.0.0.0:53))` — a port that cannot be bound ends the component, and `spawn_component` logs it; and a task that calls `dns.sync_utc_offset()` every 60 s.

- [ ] **Step 1: Write the failing tests** in `dns/listen.rs`. Four helpers go into `dns/testutil.rs`, for this task's tests and for Tasks 6 and 7: `service(upstreams: Upstreams) -> (Arc<Dns>, SocketAddr)` makes a `Dns` that denies `ads.example.com`, in UTC, binds `127.0.0.1:0` and spawns `serve_with(.., 2, ms(200))`; `one(reply: Reply) -> (Arc<Dns>, SocketAddr, FakeUpstream)` is `service` over one fake upstream with waits of 300 and 600 ms; `ask_udp(addr, name) -> Option<Answer>` and `ask_tcp(addr, name) -> Option<Answer>` send `query(9, name, 1)` and wait 2 s.

```rust
#[tokio::test] async fn a_forwarded_name_is_answered_and_its_repeat_comes_from_the_cache() {
    let (dns, addr, up) = one(Reply::Answer(ip("192.0.2.10"))).await;
    for _ in 0..2 { assert_eq!(ask_udp(addr, "example.com").await.unwrap().v4(), [ip("192.0.2.10")]); }
    assert_eq!(up.udp_queries(), 1);
    let total = dns.resolver().stats().total();
    assert_eq!((total.queries, total.forwarded, total.cache_hits), (2, 1, 1));
}
#[tokio::test] async fn a_tcp_client_is_answered_and_may_ask_again_on_its_connection() {
    let (_dns, addr, up) = one(Reply::Answer(ip("192.0.2.10"))).await;
    // one TcpStream: two length-prefixed queries, for example.com and example.org, read back in that order,
    // each with addrs [192.0.2.10]; then a length of 0, after which read() returns 0
    assert_eq!(up.udp_queries(), 2);
}
#[tokio::test] async fn a_denied_name_is_answered_here() {
    let (_dns, addr, up) = one(Reply::Answer(ip("192.0.2.10"))).await;
    assert_eq!(ask_udp(addr, "ads.example.com").await.unwrap().summary(), "NOERROR 0.0.0.0");
    assert_eq!(ask_tcp(addr, "ADS.example.com").await.unwrap().summary(), "NOERROR 0.0.0.0");
    assert_eq!(up.udp_queries(), 0);
}
#[tokio::test] async fn when_no_upstream_answers_the_client_gets_servfail_and_the_listener_lives() {   // Review Focus 1
    let (_dns, addr) = service(Upstreams::with(vec![closed_port()], ms(300), ms(300))).await;
    for name in ["example.com", "example.org"] { assert_eq!(ask_udp(addr, name).await.unwrap().summary(), "SERVFAIL"); }
    assert_eq!(ask_udp(addr, "printer").await.unwrap().summary(), "NXDOMAIN");
}
#[tokio::test] async fn tcp_clients_that_stall_are_closed_and_hold_up_nobody() {                       // Review Focus 3
    let (_dns, addr, _up) = one(Reply::Answer(ip("192.0.2.10"))).await;
    // two TcpStreams (the limit here): one writes a single byte, one writes nothing
    assert!(ask_udp(addr, "example.com").await.is_some());
    // a third TcpStream opened now reads 0 at once: it was closed, not queued
    // 400 ms later both stalled streams read 0, and ask_tcp(addr, "example.com") is answered
}
#[tokio::test] async fn a_forward_beyond_the_limit_gets_servfail_at_once() {
    // Dns::with_forward_limit(.., 1) over FakeUpstream::start(Reply::After(ms(400), ip("192.0.2.10"))), waits of 2 s
    // ask_udp for example.com and example.org at the same moment (tokio::join!):
    // one is "NOERROR 192.0.2.10" after at least 400 ms, the other "SERVFAIL" within 200 ms
}
#[tokio::test] async fn garbage_gets_no_answer_and_the_next_query_does() {
    let (dns, addr, _up) = one(Reply::Answer(ip("192.0.2.10"))).await;
    // five bytes [1, 2, 3, 4, 5] over UDP: nothing comes back within 200 ms
    assert!(ask_udp(addr, "example.com").await.is_some());
    assert_eq!(dns.resolver().stats().total().queries, 1);
}
#[tokio::test] async fn own_lookups_go_through_the_same_resolver() {
    let (dns, _addr, up) = one(Reply::Answer(ip("192.0.2.10"))).await;
    assert_eq!(dns.lookup_v4("192.0.2.7").await.unwrap(), [ip("192.0.2.7")]);
    assert_eq!(up.udp_queries(), 0);
    for _ in 0..2 { assert_eq!(dns.lookup_v4("time.example.net").await.unwrap(), [ip("192.0.2.10")]); }
    assert_eq!((up.udp_queries(), dns.resolver().stats().total().queries), (1, 2));
    assert_eq!(dns.lookup_v4("ads.example.com").await.unwrap_err().kind(), io::ErrorKind::NotFound);   // 0.0.0.0 is no address
    assert_eq!(dns.lookup_v4("printer").await.unwrap_err().kind(), io::ErrorKind::NotFound);
}
#[test] fn the_offset_given_to_the_resolver_is_the_zones() {
    let zone = TimeZoneRule::parse("<+0530>-5:30").unwrap();
    let dns = Dns::new(BlockSet::default(), Upstreams::with(vec![closed_port()], ms(1), ms(1)), zone);
    assert_eq!(dns.utc_offset(), 19_800);
}
```

- [ ] **Step 2: Run** `cargo test -p qberrypi dns::listen` — expected: compile failure.
- [ ] **Step 3: Implement** `lists/mod.rs`, `Dns`, `listen.rs`, and the lines in `services::run`.
- [ ] **Step 4: Run** `cargo test -p qberrypi dns::` — expected: 19 passed.
- [ ] **Step 5: Run** `cargo xtask build && cargo xtask qemu-test` — expected: six `ok` (the guest logs `dns: listening on 0.0.0.0:53`; no scenario asks for it yet).
- [ ] **Step 6: Commit** — stage the five files by name; message `"dns: listeners on port 53, the shared resolver, own lookups"`.

---

### Task 5: SNTP and the clock

**Files:**
- Create: `crates/qberrypi/src/sntp.rs`
- Modify: `crates/qberrypi/src/sys.rs`, `crates/qberrypi/src/services.rs`, `crates/qberrypi/src/lib.rs`

**Interfaces:**
- Consumes: `Dns::{lookup_v4, sync_utc_offset}`, `sys::random_u64`, `crate::BUILD_EPOCH`, `cfg.net.time_servers`.
- Produces:

```rust
// sys.rs
pub fn set_clock(unix: Duration) -> io::Result<()>;          // CLOCK_REALTIME, to the nanosecond

// sntp.rs
pub const NTP_PORT: u16 = 123;
pub const ANSWER_WAIT: Duration = Duration::from_secs(3);
pub const RESYNC_EVERY: Duration = Duration::from_secs(3600);
pub const STEP_AT_LEAST: Duration = Duration::from_millis(500);
pub const RETRY_SECS: [u64; 5] = [5, 10, 20, 40, 60];        // after a failed round; the last repeats
pub const ROUTE_FILE: &str = "/proc/net/route";
pub fn request(nonce: u64) -> [u8; 48];
#[derive(Debug, PartialEq, Eq)]
pub enum Rejected { TooShort, NotAServerReply, KissOfDeath, Unsynchronized, NotOurs, NoTime, BeforeBuild }
pub fn server_time(reply: &[u8], nonce: u64, round_trip: Duration, earliest_unix: u64) -> Result<Duration, Rejected>;   // Unix time when the reply arrived
pub fn needs_step(clock: Duration, server: Duration) -> bool;
pub fn has_default_route(proc_net_route: &str) -> bool;
pub async fn ask(server: SocketAddr, wait: Duration, earliest_unix: u64) -> io::Result<Duration>;   // a Rejected reply is ErrorKind::InvalidData
pub struct Sntp {
    pub servers: Vec<String>, pub port: u16, pub wait: Duration, pub earliest_unix: u64,
    pub route_file: PathBuf, pub route_poll: Duration, pub set_clock: fn(Duration) -> io::Result<()>,
}
impl Sntp {
    pub fn for_board(cfg: &Config) -> Self;      // the configured servers, NTP_PORT, ANSWER_WAIT, BUILD_EPOCH, ROUTE_FILE, 1 s, sys::set_clock
    pub async fn run(self, dns: Arc<Dns>, synced: tokio::sync::watch::Sender<bool>) -> io::Result<()>;
}
```

The packet (RFC 5905, figure 8). Byte 0 is leap indicator (bits 7–6), version (5–3), mode (2–0). A timestamp is 4 bytes of seconds since 1900 and 4 of fraction, big-endian; seconds below 2³¹ belong to the era that begins in 2036, so 2³² is added; Unix time is that minus 2,208,988,800.

- `request`: byte 0 is `0x23` (version 4, client), bytes 40..48 are the nonce, everything else zero.
- `server_time` checks, in this order: under 48 bytes → `TooShort`; mode not 4 → `NotAServerReply`; stratum (byte 1) 0 → `KissOfDeath`; stratum above 15, or leap indicator 3 → `Unsynchronized`; originate timestamp (bytes 24..32) not the nonce → `NotOurs`; transmit timestamp (bytes 40..48) zero → `NoTime`. The result is transmit + (round trip − (transmit − receive)) / 2, with the bracket held at zero or more; receive is bytes 32..40. A result before `earliest_unix` → `BeforeBuild`.
- `has_default_route`: some line after the first has, split at whitespace, `00000000` as its second and its eighth field and an odd fourth field (hexadecimal flags, bit 0 is "up").
- `needs_step`: the two differ by `STEP_AT_LEAST` or more, either way.

`run`: log `clock: waiting for a default route`; read `route_file` every `route_poll` until `has_default_route`. Then rounds, for ever. A round tries the servers in order: `dns.lookup_v4(server)`, `ask` the first address with a nonce from `sys::random_u64()`, and stops at the first accepted time. If `needs_step`, it calls `set_clock`, then `dns.sync_utc_offset()`, and logs `clock: set by SNTP from {server}: unix {secs}, stepped {:+.3} s`. Any accepted time sends `true` on `synced`; the next round is `RESYNC_EVERY` later. A round in which no server gave a time logs `clock: no time server answered` at WARN — once, until a round succeeds again — and the next round follows after `RETRY_SECS`.

In `services::run`, after the DNS lines: `let (synced_tx, synced) = watch::channel(false);` and `spawn_component("clock", Sntp::for_board(cfg).run(dns.clone(), synced_tx))`. `synced` is kept for Tasks 6 and 11.

- [ ] **Step 1: Write the failing tests** in `sntp.rs`. `reply(nonce, first: u8, stratum: u8, receive: (u32, u32), transmit: (u32, u32)) -> [u8; 48]` puts the nonce at 24..32 and the two timestamps at 32..40 and 40..48. `fake_server(answer: impl Fn(&[u8]) -> Option<[u8; 48]>) -> SocketAddr` is a UDP socket on `127.0.0.1:0`.

```rust
const N: u64 = 0x0123_4567_89ab_cdef;
const T: u32 = 3_913_056_000;                 // 2024-01-01T00:00:00Z, Unix 1_704_067_200

#[test] fn the_request_is_a_version_4_client_packet_that_carries_only_the_nonce() {
    let r = request(N);
    assert_eq!(r[0], 0x23);
    assert!(r[1..40].iter().all(|b| *b == 0));
    assert_eq!(r[40..], [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
}
#[test] fn server_time_is_the_transmit_time_plus_half_the_network_delay() {
    // the server held the packet 100 ms (fraction 0x1999_999a); the round trip took 300 ms: 100 ms each way
    let got = server_time(&reply(N, 0x24, 2, (T, 0), (T, 0x1999_999a)), N, ms(300), 0).unwrap();
    assert!(got.abs_diff(Duration::from_millis(1_704_067_200_200)) < Duration::from_micros(10));
    // a server that says it held the packet longer than the round trip took adds nothing
    assert_eq!(server_time(&reply(N, 0x24, 2, (T, 0), (T + 5, 0)), N, ms(300), 0).unwrap(), Duration::from_secs(1_704_067_205));
}
#[test] fn seconds_below_two_to_the_31_are_in_the_era_from_2036() {
    assert_eq!(server_time(&reply(N, 0x24, 2, (1, 0), (1, 0)), N, ms(0), 0).unwrap(), Duration::from_secs(2_085_978_497));
}
#[test] fn a_reply_that_is_not_a_usable_answer_to_our_request_is_rejected() {      // Review Focus 5
    let good = reply(N, 0x24, 2, (T, 0), (T, 0));
    assert_eq!(server_time(&good[..47], N, ms(1), 0), Err(Rejected::TooShort));
    assert_eq!(server_time(&reply(N, 0x23, 2, (T, 0), (T, 0)), N, ms(1), 0), Err(Rejected::NotAServerReply));
    assert_eq!(server_time(&reply(N, 0x24, 0, (T, 0), (T, 0)), N, ms(1), 0), Err(Rejected::KissOfDeath));
    assert_eq!(server_time(&reply(N, 0x24, 16, (T, 0), (T, 0)), N, ms(1), 0), Err(Rejected::Unsynchronized));
    assert_eq!(server_time(&reply(N, 0xe4, 2, (T, 0), (T, 0)), N, ms(1), 0), Err(Rejected::Unsynchronized));
    assert_eq!(server_time(&good, N + 1, ms(1), 0), Err(Rejected::NotOurs));
    assert_eq!(server_time(&reply(N, 0x24, 2, (T, 0), (0, 0)), N, ms(1), 0), Err(Rejected::NoTime));
    assert_eq!(server_time(&good, N, ms(1), 1_704_067_201), Err(Rejected::BeforeBuild));
    assert!(server_time(&good, N, ms(1), 1_704_067_200).is_ok());
}
#[test] fn the_clock_is_stepped_only_when_it_is_half_a_second_out() {
    let at = Duration::from_millis;
    assert!(!needs_step(at(1_000_000), at(1_000_499)) && !needs_step(at(1_000_499), at(1_000_000)));
    assert!(needs_step(at(1_000_000), at(1_000_500)) && needs_step(at(1_000_500), at(1_000_000)));
}
#[test] fn a_default_route_is_a_line_with_no_destination_no_mask_and_the_up_flag() {
    const HEAD: &str = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n";
    const SUBNET: &str = "wlan0\t000200C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
    const DEFAULT: &str = "wlan0\t00000000\t010200C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n";
    assert!(has_default_route(&format!("{HEAD}{DEFAULT}{SUBNET}")) && has_default_route(&format!("{HEAD}{SUBNET}{DEFAULT}")));
    for none in [String::new(), HEAD.to_owned(), format!("{HEAD}{SUBNET}"), format!("{HEAD}{}", DEFAULT.replace("0003", "0002"))] {
        assert!(!has_default_route(&none), "{none:?}");
    }
}
#[tokio::test] async fn a_server_is_asked_and_its_time_taken() {
    let server = fake_server(|request| Some(reply(u64::from_be_bytes(request[40..48].try_into().unwrap()), 0x24, 2, (T, 0), (T, 0)))).await;
    let got = ask(server, ms(500), 0).await.unwrap();
    assert!(got >= Duration::from_secs(1_704_067_200) && got < Duration::from_secs(1_704_067_201));
}
#[tokio::test] async fn a_server_that_answers_another_request_or_not_at_all_is_an_error() {             // Review Focus 5
    let liar = fake_server(|_| Some(reply(N, 0x24, 2, (T, 0), (T, 0)))).await;
    assert_eq!(ask(liar, ms(500), 0).await.unwrap_err().kind(), io::ErrorKind::InvalidData);
    let silent = fake_server(|_| None).await;
    assert_eq!(ask(silent, ms(100), 0).await.unwrap_err().kind(), io::ErrorKind::TimedOut);
}
#[tokio::test] async fn the_task_waits_for_a_route_then_sets_the_clock_and_says_so() {
    // SET: a static Mutex<Vec<Duration>> that `set_clock` here pushes to. The fake server answers with (T, 0).
    // Sntp { servers: ["127.0.0.1"], port: the fake's, wait: ms(300), earliest_unix: 0, route_file: a temp file
    //        holding HEAD + SUBNET, route_poll: ms(20), set_clock }, spawned with a Dns as in Task 4's last test.
    // After 200 ms: SET is empty and *synced.borrow() is false.
    // The file is rewritten as HEAD + DEFAULT. Within 2 s: synced.changed() resolves, *synced.borrow() is true,
    // and SET holds exactly one time, in 1_704_067_200 s .. 1_704_067_201 s.
}
#[tokio::test] async fn a_time_before_the_build_never_reaches_the_clock() {                             // Review Focus 5
    // the same with earliest_unix: 1_704_067_300 and the route there from the start:
    // after 500 ms SET for this test is empty and *synced.borrow() is false.
}
```

The two task tests share no static: each has its own.

- [ ] **Step 2: Run** `cargo test -p qberrypi sntp::` — expected: compile failure.
- [ ] **Step 3: Implement** `sys::set_clock`, `sntp.rs`, and the lines in `services::run`.
- [ ] **Step 4: Run** `cargo test -p qberrypi sntp::` — expected: 10 passed.
- [ ] **Step 5: Run** `cargo xtask build && cargo xtask qemu-test` — expected: six `ok`. In QEMU no route ever appears, so the guest logs `clock: waiting for a default route` and no warning.
- [ ] **Step 6: Commit** — stage the four files by name; message `"Clock: SNTP once a default route is there"`.

---

### Task 6: Status server

The constants, the paths' rules and the JSON keys are those of milestone 4's plan (its Task 11), which adds the page at `/`, `/api/v1/queries`, `wifi` and `board_c` to this file. `LogBuf::text` is milestone 1's (its Task 7); if it is there, this task adds neither the method nor its test and does not touch `logbuf.rs`.

**Files:**
- Create: `crates/qberrypi/src/status.rs`
- Modify: `crates/qberrypi/src/logbuf.rs`, `crates/qberrypi/src/services.rs`, `crates/qberrypi/src/lib.rs`, `crates/qberrypi/Cargo.toml`, `Cargo.lock`

**Interfaces:**
- Consumes: `Dns`, `Upstreams::{latency_ms, failures}`, `qb_dns::{Stats, Counts}`, `LogBuf`, `VERSION`, `BUILD_EPOCH`.
- Produces:

```rust
// logbuf.rs
impl LogBuf { pub fn text(&self) -> String; }      // every line still held, oldest first, each ending in a newline; marks nothing as saved

// status.rs
pub const PORT: u16 = 80;
pub const MAX_CLIENTS: usize = 8;
pub const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_REQUEST_LINE: usize = 1024;
#[derive(Debug, PartialEq)] pub struct Response { pub status: u16, pub content_type: &'static str, pub body: Vec<u8> }
#[derive(Clone)]
pub struct Status { pub dns: Arc<Dns>, pub log: &'static Mutex<LogBuf>, pub synced: tokio::sync::watch::Receiver<bool>, pub started: Instant }
impl Status {
    pub fn stats(&self) -> serde_json::Value;
    pub fn respond(&self, request_line: &str) -> Response;
    pub async fn run(self, addr: SocketAddr) -> io::Result<()>;                             // the component: bind, log `status: listening on {addr}`, serve
    pub async fn serve(self, listener: tokio::net::TcpListener) -> io::Result<()>;          // serve_with(.., MAX_CLIENTS, CLIENT_TIMEOUT)
    pub(crate) async fn serve_with(self, listener: tokio::net::TcpListener, clients: usize, timeout: Duration) -> io::Result<()>;
}
pub(crate) fn share(part: u64, whole: u64) -> Option<f64>;     // part / whole to four decimal places; None when whole is 0
```

`stats()` is exactly this object, 19 keys; `null` stands where a value is not known yet:

```json
{"version": "0.1.0", "build": 1794329091, "uptime_secs": 87,
 "clock_set": true, "unix_secs": 1794337331, "utc_offset_secs": 3600,
 "queries_today": 12, "blocked_today": 3, "blocked_share": 0.25, "cache_hit_rate": 0.3333,
 "queries_total": 12, "blocked_total": 3, "cache_hits_total": 4, "forwarded_total": 5,
 "cache_entries": 9, "upstream_ms": 8, "upstream_failures": 0,
 "blocking": "on", "pause_left_secs": null}
```

The `_today` values and the two fractions come from `stats().today(now)`, the `_total` values from `stats().total()`. `blocked_share` is `share(blocked, queries)` and `cache_hit_rate` is `share(cache_hits, queries)`, both of today. `clock_set` is the `synced` channel's value. `blocking` is `"on"` or `"paused"`, and `pause_left_secs` is `paused_until(now)` less `now.mono_secs`.

`respond` takes the first line of a request. Not `GET <path> HTTP/1.x`: 400, unless it is another method in that shape: 405. `/api/v1/stats`: 200, `application/json`. `/log`: 200, `text/plain; charset=utf-8`, `LogBuf::text()`. Any other path, and either of those two with a query string: 404. The bodies of 400, 404 and 405 are one line of plain text.

`serve`: at most `clients` connections at a time, held by a semaphore taken before `accept`, so further ones wait in the listen queue. Per connection, all under one `timeout`: read until the first line ends, answering 400 once `MAX_REQUEST_LINE` bytes came without one; write `HTTP/1.1 {status} {reason}`, `Content-Type`, `Content-Length`, `Connection: close`, `Cache-Control: no-store`, the body; close. A connection that runs out of time is closed with no reply. An error on one connection ends that connection only; `serve` returns `Err` only when `accept` fails.

In `services::run`, after the clock lines: `spawn_component("status", status.run(0.0.0.0:80))`.

- [ ] **Step 1: Add the dependency** — `cargo add -p qberrypi serde_json@1 --no-default-features -F std`
- [ ] **Step 2: Write the failing tests.** In `logbuf.rs`:

```rust
#[test] fn the_whole_log_is_returned_and_nothing_is_marked_saved() {
    let mut buf = LogBuf::new(4096);
    buf.push("a"); buf.take_unsaved(); buf.push("b");
    assert_eq!(buf.text(), "a\nb\n");
    assert_eq!(buf.take_unsaved(), "b\n");
}
```

In `status.rs`, with `served(reply: Reply) -> (Status, SocketAddr /* status */, SocketAddr /* dns */)` built on Task 4's `one`, a leaked `Mutex<LogBuf>` holding the lines `one` and `two`, a `synced` receiver at `false`, and `serve_with(.., 2, ms(200))` on `127.0.0.1:0`; `get(addr, request: &str) -> (String /* head */, Vec<u8> /* body */)` writes the request and reads to the end:

```rust
#[tokio::test] async fn requests_are_answered_by_method_and_path() {
    let (status, _http, _dns) = served(Reply::Silent).await;
    let code = |line: &str| status.respond(line).status;
    assert_eq!((code("GET /api/v1/stats HTTP/1.1"), code("GET /log HTTP/1.0")), (200, 200));
    assert_eq!((code("GET / HTTP/1.1"), code("GET /api/v1/queries HTTP/1.1"), code("GET /api/v1/stats?x=1 HTTP/1.1"), code("GET /log?n=5 HTTP/1.1")), (404, 404, 404, 404));
    assert_eq!((code("POST /api/v1/stats HTTP/1.1"), code("DELETE /log HTTP/1.1")), (405, 405));
    assert_eq!((code("nonsense"), code(""), code("GET /log"), code("GET /log HTTP/2")), (400, 400, 400, 400));
    assert_eq!(status.respond("GET /log HTTP/1.1"), Response { status: 200, content_type: "text/plain; charset=utf-8", body: b"one\ntwo\n".to_vec() });
}
#[tokio::test] async fn the_statistics_are_served_as_json() {
    let (_status, http, dns) = served(Reply::Answer(ip("192.0.2.10"))).await;
    for name in ["example.com", "example.com", "ads.example.com"] { ask_udp(dns, name).await.unwrap(); }
    let (head, body) = get(http, "GET /api/v1/stats HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
    for line in ["Content-Type: application/json\r\n", "Connection: close\r\n", "Cache-Control: no-store\r\n", &format!("Content-Length: {}\r\n", body.len())] { assert!(head.contains(line), "{line}"); }
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!((v["version"].as_str(), v["build"].as_u64()), (Some(crate::VERSION), Some(crate::BUILD_EPOCH)));
    assert_eq!((v["queries_today"].as_u64(), v["blocked_today"].as_u64(), v["blocked_share"].as_f64(), v["cache_hit_rate"].as_f64()), (Some(3), Some(1), Some(0.3333), Some(0.3333)));
    assert_eq!((v["queries_total"].as_u64(), v["blocked_total"].as_u64(), v["cache_hits_total"].as_u64(), v["forwarded_total"].as_u64()), (Some(3), Some(1), Some(1), Some(1)));
    assert_eq!((v["clock_set"].as_bool(), v["utc_offset_secs"].as_i64(), v["cache_entries"].as_u64(), v["upstream_failures"].as_u64()), (Some(false), Some(0), Some(1), Some(0)));
    assert!(v["unix_secs"].as_u64().unwrap() > 1_700_000_000 && v["uptime_secs"].is_u64() && v["upstream_ms"].is_u64());
    assert_eq!((v["blocking"].as_str(), v["pause_left_secs"].is_null()), (Some("on"), true));
    assert_eq!(v.as_object().unwrap().len(), 19);
}
#[tokio::test] async fn what_is_not_known_yet_is_null_and_a_pause_shows_its_seconds() {
    let (status, _http, _dns) = served(Reply::Silent).await;
    let v = status.stats();
    assert!(v["upstream_ms"].is_null() && v["blocked_share"].is_null() && v["cache_hit_rate"].is_null());
    let until = status.dns.now().mono_secs + 300;
    status.dns.resolver().pause_until(until);
    let v = status.stats();
    assert_eq!(v["blocking"], "paused");
    assert!(matches!(v["pause_left_secs"].as_u64(), Some(299..=300)));
}
#[test] fn a_share_has_four_decimal_places_and_none_of_nothing() {
    assert_eq!((share(1, 3), share(4780, 10_818), share(0, 5), share(5, 5), share(0, 0)), (Some(0.3333), Some(0.4419), Some(0.0), Some(1.0), None));
}
#[tokio::test] async fn a_request_over_a_socket_gets_one_whole_answer_and_the_connection_closes() {
    let (_status, http, _dns) = served(Reply::Silent).await;
    let (head, body) = get(http, "GET /log HTTP/1.1\r\n\r\n").await;
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n") && head.contains("Content-Type: text/plain; charset=utf-8\r\n"));
    assert_eq!(body, b"one\ntwo\n");
    assert!(get(http, "GET / HTTP/1.1\r\n\r\n").await.0.starts_with("HTTP/1.1 404 "));
    assert!(get(http, "DELETE /log HTTP/1.1\r\n\r\n").await.0.starts_with("HTTP/1.1 405 "));
    assert!(get(http, "nonsense\r\n\r\n").await.0.starts_with("HTTP/1.1 400 "));
}
#[tokio::test] async fn silent_clients_do_not_keep_the_next_from_being_served() {             // Review Focus 3
    let (_status, http, _dns) = served(Reply::Silent).await;
    // two TcpStreams (the limit here): one writes "GET /log HT", one writes nothing
    // a GET /log sent now on a third is answered with 200 within 1 s: it waited for a place, about 200 ms
    // by then both silent streams read 0, with no reply
}
#[tokio::test] async fn a_line_without_an_end_is_answered_400_after_1024_bytes() {
    let (_status, http, _dns) = served(Reply::Silent).await;
    assert!(get(http, &"a".repeat(1024)).await.0.starts_with("HTTP/1.1 400 "));
}
```

- [ ] **Step 3: Run** `cargo test -p qberrypi -- status:: logbuf::` — expected: compile failure.
- [ ] **Step 4: Implement** `LogBuf::text`, `status.rs`, and the lines in `services::run`.
- [ ] **Step 5: Run** `cargo test -p qberrypi` — expected: all pass.
- [ ] **Step 6: Commit** — stage the files this task changed, by name; message `"Status: /api/v1/stats and /log on port 80"`.

---

### Task 7: QEMU — DNS on the real kernel, without a network

**Files:**
- Create: `crates/qberrypi/src/selftest.rs`
- Modify: `crates/qberrypi/src/services.rs`, `crates/qberrypi/src/lib.rs`, `xtask/src/qemu.rs`

**Interfaces:**
- Consumes: `client::{query, read_answer}`, `sys::kernel_arg`, Tasks 4 and 6's listeners; milestone 1's `lo`, which its main loop brings up.
- Produces:

```rust
// selftest.rs
pub const DNS_ARG: &str = "qberrypi.selftest.dns";
pub const DENIED: &str = "qberrypi-selftest.invalid";
pub const ANSWER_WAIT: Duration = Duration::from_secs(5);
pub const LO_FLAGS: &str = "/sys/class/net/lo/flags";
pub const LO_WAIT: Duration = Duration::from_secs(60);
pub fn is_up(flags: &str) -> bool;             // the file holds hexadecimal flags, `0x9` when up; bit 0 is "up"
pub async fn dns(dns_server: SocketAddr, status_server: SocketAddr) -> Vec<String>;      // dns_within(.., ANSWER_WAIT)
pub(crate) async fn dns_within(dns_server: SocketAddr, status_server: SocketAddr, wait: Duration) -> Vec<String>;
```

`selftest::dns` asks the listeners as an outside client would, and returns these lines, in this order; `{..}` is `Answer::summary()`, or `no answer` when nothing came within `ANSWER_WAIT`:

```
selftest: dns: udp qberrypi-selftest.invalid A: {..}
selftest: dns: tcp qberrypi-selftest.invalid A: {..}
selftest: dns: udp printer A: {..}
selftest: dns: udp example.com A: {..}
selftest: status: /api/v1/stats: {the status code, or `no answer`}
```

In `services::run`, after the DNS and status components are spawned: if `sys::kernel_arg(selftest::DNS_ARG)`, a spawned task reads `LO_FLAGS` every 200 ms until `is_up` or `LO_WAIT` has passed — the services start before `start_network` has brought `lo` up, and by then both components have bound their ports — logs `selftest: lo is not up` at ERROR if the wait ran out, then logs each line of `selftest::dns(127.0.0.1:53, 127.0.0.1:80)` at INFO, then `selftest: dns: done`. It holds up nothing.

In `xtask/src/qemu.rs`: a fifth `Machine`, `DnsSelftest`, whose kernel arguments are `KERNEL_ARGS` followed by ` qberrypi.selftest.dns`; and a seventh scenario, after the six:

```rust
Scenario {
    name: "dns without a network",
    machine: Machine::DnsSelftest,
    note: Some(NO_NETWORK),
    file_stem: "dns-without-a-network",
    system_config: /* the one-shot edits, with `deny = []` -> `deny = ["qberrypi-selftest.invalid"]`
                      and `return_after_secs = 0` -> `return_after_secs = 60` */,
    conditions: dns_selftest_conditions,
}
```

`NO_NETWORK` says: the guest has no network card, so every upstream is unreachable; this boot shows the listeners, the block set and the status server on the real kernel, and that a query that cannot be forwarded is answered SERVFAIL; forwarding, caching and the clock are tested on the development machine and on the Pi. `dns_selftest_conditions` is:

```rust
vec![
    evidence.serial_has("INFO  services: started"),
    evidence.serial_has("INFO  net: lo is up"),
    evidence.serial_has("INFO  dns: listening on 0.0.0.0:53"),
    evidence.serial_has("INFO  status: listening on 0.0.0.0:80"),
    evidence.serial_has("INFO  selftest: dns: udp qberrypi-selftest.invalid A: NOERROR 0.0.0.0"),
    evidence.serial_has("INFO  selftest: dns: tcp qberrypi-selftest.invalid A: NOERROR 0.0.0.0"),
    evidence.serial_has("INFO  selftest: dns: udp printer A: NXDOMAIN"),
    evidence.serial_has("INFO  selftest: dns: udp example.com A: SERVFAIL"),
    evidence.serial_has("INFO  selftest: status: /api/v1/stats: 200"),
    evidence.serial_has("INFO  selftest: dns: done"),
    evidence.serial_has("INFO  clock: waiting for a default route"),
    evidence.serial_lacks("clock: set by SNTP"),
    evidence.serial_has("INFO  returning"),
    evidence.restart_requested(),
    evidence.exited(),
    evidence.pios_config_is_active(),
    evidence.log_is_of_one_boot_of_this_build(),
    evidence.log_has("selftest: dns: done"),
    evidence.log_lacks(PASSPHRASE),
    evidence.serial_lacks(PASSPHRASE),
    evidence.serial_has_no_unexpected_complaint(&Allowed { errors: &[], warnings: &[NO_WATCHDOG, NO_LED, NO_PANEL, NO_WLAN, NO_UPSTREAM] }),
]
```

with `const NO_UPSTREAM: &str = "dns: no upstream answers";`; `NO_WLAN` is milestone 1's and `NO_PANEL` the panel plan's. The return is 60 s after the start because the runtime, and so the services, start only after milestone 0's wait for `wlan0`, which is 20 s in QEMU. `scenarios` returns `[Scenario; 7]`; the comments and messages that say "six" say "seven".

- [ ] **Step 1: Write the failing tests.** In `selftest.rs`, against a service as in Task 6's tests whose `Dns` denies `selftest::DENIED` and whose only upstream is `closed_port()`:

```rust
#[tokio::test] async fn the_self_test_reports_what_an_outside_client_would_see() {
    assert_eq!(dns(dns_addr, status_addr).await, [
        "selftest: dns: udp qberrypi-selftest.invalid A: NOERROR 0.0.0.0",
        "selftest: dns: tcp qberrypi-selftest.invalid A: NOERROR 0.0.0.0",
        "selftest: dns: udp printer A: NXDOMAIN",
        "selftest: dns: udp example.com A: SERVFAIL",
        "selftest: status: /api/v1/stats: 200",
    ]);
}
#[test] fn lo_is_up_when_bit_0_of_its_flags_is_set() {
    assert!(is_up("0x9\n") && is_up("0x1") && !is_up("0x8\n") && !is_up("") && !is_up("up"));
}
#[tokio::test] async fn servers_that_are_not_there_are_reported_and_do_not_hang_it() {
    let lines = dns_within(closed_port(), closed_port(), ms(200)).await;
    assert_eq!(lines.len(), 5);
    assert!(lines.iter().all(|line| line.ends_with(": no answer")), "{lines:?}");
}
```

In `xtask/src/qemu.rs`:

```rust
#[test] fn the_dns_scenario_denies_the_self_tests_name_and_gives_it_time() {
    let all = scenarios(EXAMPLE).unwrap();
    let cfg = qberrypi::config::parse(&all[6].system_config).unwrap();
    assert_eq!(cfg.dns.deny, [qberrypi::selftest::DENIED]);
    assert_eq!((cfg.debug.one_shot, cfg.debug.log_to_sd, cfg.debug.return_after_secs), (true, true, 60));
    assert_eq!(Machine::DnsSelftest.kernel_args(), format!("{KERNEL_ARGS} {}", qberrypi::selftest::DNS_ARG));
    assert!(all[..6].iter().all(|s| !s.machine.kernel_args().contains(qberrypi::selftest::DNS_ARG)));
}
```

- [ ] **Step 2: Run** `cargo test -p qberrypi selftest::` and `cargo test -p xtask qemu::` — expected: compile failures.
- [ ] **Step 3: Implement** `selftest.rs`, the lines in `services::run`, the machine and the scenario.
- [ ] **Step 4: Run** `cargo test --workspace` — expected: all pass.
- [ ] **Step 5: Run** `cargo xtask build && cargo xtask qemu-test` — expected: seven `ok`. If `dns without a network` fails on a warning milestone 1 logs in QEMU, add that warning's opening words to this scenario's allowed list, as milestone 1 did for its own. If milestone 1 added scenarios of its own, this one goes after them, and "seven", `[Scenario; 7]` and `all[6]` here and in later tasks move up by their number.
- [ ] **Step 6: Commit** — stage the four files by name; message `"QEMU: a seventh scenario asks the DNS and status servers over loopback"`.

---

### Task 8: `cargo xtask probe`, resolver stage

**Files:**
- Create: `xtask/src/probe.rs`
- Modify: `xtask/src/main.rs`, `xtask/Cargo.toml`, `Cargo.lock`, `README.md`

**Interfaces:**
- Consumes: `qberrypi::dns::client::{query, read_answer, Answer}`, `qberrypi::config::parse`, `qberrypi::dns::DNS_PORT`, `qberrypi::status::PORT`.
- Produces:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)] pub enum Stage { Resolver, Blocker }
#[derive(Debug, PartialEq, Eq)] pub struct Check { pub what: &'static str, pub ok: bool, pub found: String }
#[derive(Debug, Clone)] pub struct Timed { pub answer: Answer, pub took: Duration }
#[derive(Debug, Default)]
pub struct ResolverSeen {
    pub forwarded: Option<Timed>,         // example.com, the answer that ended the wait for the Pi
    pub first: Option<Timed>,             // example.org, asked once
    pub repeats: Vec<Timed>,              // example.org, five more times
    pub tcp: Option<Timed>,               // example.net over TCP
    pub local: Option<Timed>,             // printer
    pub before: Option<serde_json::Value>,   // /api/v1/stats before `first`
    pub after: Option<serde_json::Value>,    // /api/v1/stats once clock_set is true, or after 30 s of waiting for that
    pub pc_unix_secs: u64,                // this machine's clock when `after` was read
}
pub fn judge_resolver(seen: &ResolverSeen) -> Vec<Check>;
pub fn median(times: &[Duration]) -> Option<Duration>;                 // the upper median for an even count
pub fn ask_udp(server: SocketAddr, name: &str, qtype: u16, wait: Duration) -> io::Result<Timed>;
pub fn ask_tcp(server: SocketAddr, name: &str, qtype: u16, wait: Duration) -> io::Result<Timed>;
pub fn get_stats(status: SocketAddr, wait: Duration) -> anyhow::Result<serde_json::Value>;
pub fn report(checks: &[Check]) -> (String, bool);                     // the lines below; whether all hold
pub fn run(stage: Stage, server: Option<Ipv4Addr>, wait_secs: u64, listed: &str, root: &Path) -> anyhow::Result<()>;
```

Command: `cargo xtask probe --stage resolver [--server <ipv4>] [--wait-secs 240] [--listed doubleclick.net]`. Without `--server` the address is `net.address` of `./qberrypi.toml`. `run` asks `example.com` over UDP every 2 s, with a 1 s wait, until it is answered or `wait_secs` have passed (an error that says the Pi never answered); then it fills `ResolverSeen` in the order of its fields, prints `report`, and fails unless every check holds. `Stage::Blocker` is Task 14's; until then it is an error that says so.

`judge_resolver` returns these eight, in this order; a missing observation fails its check with `found` saying what is missing:

| `what` | Holds when |
|---|---|
| `a forwarded name is answered` | `forwarded` is NOERROR with at least one address |
| `a repeat is answered from the cache` | `after.cache_hits_total` − `before.cache_hits_total` ≥ 5 |
| `a cached repeat is faster` | `median` of the repeats' times < `first`'s time |
| `a repeat's TTL has not grown` | every repeat's `min_ttl` ≤ `first`'s |
| `a query over TCP is answered` | `tcp` is NOERROR with at least one address |
| `a single-label name is answered by the Pi` | `local` has rcode 3 |
| `the clock is set` | `after.clock_set` is true and `after.unix_secs` is within 5 of `pc_unix_secs` |
| `the upstream latency is known` | `after.upstream_ms` is a number |

`report` prints `probe: ok: {what}` or `probe: FAILED: {what}: {found}` for each, then `probe: {n} of {m} checks hold`.

- [ ] **Step 1: Add the dependency** — `cargo add -p xtask serde_json@1`
- [ ] **Step 2: Write the failing tests** in `probe.rs`. `good() -> ResolverSeen` is an observation in which all eight hold: first took 30 ms, the repeats 4, 5, 3, 6 and 40 ms, TTLs 300 then 299, `cache_hits_total` 2 before and 7 after, `clock_set` true, both clocks at 1_800_000_000, latency 8.

```rust
fn failing(seen: &ResolverSeen) -> Vec<&'static str> { judge_resolver(seen).into_iter().filter(|c| !c.ok).map(|c| c.what).collect() }

#[test] fn a_good_observation_passes_all_eight() {
    assert_eq!(judge_resolver(&good()).len(), 8);
    assert!(failing(&good()).is_empty());
}
#[test] fn each_check_fails_on_its_own_evidence() {
    let mut s = good(); s.repeats.iter_mut().for_each(|r| r.took = Duration::from_millis(31));
    assert_eq!(failing(&s), ["a cached repeat is faster"]);
    let mut s = good(); s.after.as_mut().unwrap()["cache_hits_total"] = 6.into();
    assert_eq!(failing(&s), ["a repeat is answered from the cache"]);
    let mut s = good(); s.repeats[0].answer.min_ttl = Some(301);
    assert_eq!(failing(&s), ["a repeat's TTL has not grown"]);
    let mut s = good(); s.after.as_mut().unwrap()["unix_secs"] = 1_799_999_994u64.into();
    assert_eq!(failing(&s), ["the clock is set"]);
    let mut s = good(); s.after.as_mut().unwrap()["clock_set"] = false.into();
    assert_eq!(failing(&s), ["the clock is set"]);
    let mut s = good(); s.after.as_mut().unwrap()["upstream_ms"] = serde_json::Value::Null;
    assert_eq!(failing(&s), ["the upstream latency is known"]);
    let mut s = good(); s.local.as_mut().unwrap().answer.rcode = 2;
    assert_eq!(failing(&s), ["a single-label name is answered by the Pi"]);
    let mut s = good(); s.tcp = None;
    assert_eq!(failing(&s), ["a query over TCP is answered"]);
}
#[test] fn an_observation_with_nothing_in_it_fails_every_check_and_says_what_is_missing() {
    let checks = judge_resolver(&ResolverSeen::default());
    assert!(checks.len() == 8 && checks.iter().all(|c| !c.ok && !c.found.is_empty()));
}
#[test] fn one_slow_repeat_does_not_move_the_median() {
    let ms = |n| Duration::from_millis(n);
    assert_eq!(median(&[ms(4), ms(5), ms(3), ms(6), ms(40)]), Some(ms(5)));
    assert_eq!(median(&[ms(4), ms(6)]), Some(ms(6)));
    assert_eq!(median(&[]), None);
}
#[test] fn the_report_names_each_check_and_counts_them() {
    let (text, all) = report(&[Check { what: "a", ok: true, found: String::new() }, Check { what: "b", ok: false, found: "c".into() }]);
    assert_eq!(text, "probe: ok: a\nprobe: FAILED: b: c\nprobe: 1 of 2 checks hold\n");
    assert!(!all);
}
#[test] fn a_server_is_asked_over_udp_and_tcp_and_for_its_statistics() {
    // std sockets on 127.0.0.1:0, each on a thread: a UDP socket and a TCP listener that answer any query with its
    // ID, its question and one A record 192.0.2.10; an HTTP listener that answers `{"clock_set":true}`
    // with Content-Length. ask_udp and ask_tcp return addrs [192.0.2.10] and a non-zero time;
    // get_stats returns a value whose ["clock_set"] is true.
    // ask_udp against a port where nothing listens is an Err within its wait.
}
```

- [ ] **Step 3: Run** `cargo test -p xtask probe::` — expected: compile failure.
- [ ] **Step 4: Implement** `probe.rs` with std sockets and no runtime; add the `Probe` subcommand to `main.rs`; add a row for it to the README's command table: "While a one-shot boot is running, asks the Pi's DNS and status servers what a client would and prints which of the milestone's checks hold."
- [ ] **Step 5: Run** `cargo test -p xtask` — expected: all pass. Then `cargo xtask probe --stage resolver --server 192.0.2.1 --wait-secs 3` — expected: an error within about 4 s that says the Pi never answered.
- [ ] **Step 6: Commit** — stage the five files by name; message `"xtask probe: the resolver's checks, asked as a client"`.

---

### Task 9: Milestone 2 on the Pi — "It forwards and caches DNS; the clock is set."

Run by the session lead with the owner's agreement. The household's DNS is away for about three minutes.

**Files:**
- Create: `docs/bring-up/m2.md`
- Modify: `README.md`

- [ ] **Step 1: Set `./qberrypi.toml`** — `one_shot = true`, `log_to_sd = true`, `return_after_secs = 120`; the owner adds `timezone` if they want local midnight. `git status --short` must not list the file.
- [ ] **Step 2: Rebuild and re-run the gates** — `cargo test --workspace && cargo xtask build && cargo xtask qemu-test` — expected: all pass; seven `ok`.
- [ ] **Step 3: Deploy, and probe while the Pi is in qberrypi**

```bash
cargo xtask deploy --host <alias> &      # or in a second terminal
cargo xtask probe --stage resolver
wait
```

Expected from `probe`: eight `probe: ok:` lines and `probe: 8 of 8 checks hold`. Expected from `deploy`: the collected log, exit status 0.

- [ ] **Step 4: Pi check — the collected log** (`out/logs/`) must contain, in this order: `services: started`; `dns: listening on 0.0.0.0:53`; `clock: waiting for a default route`; `clock: set by SNTP from ` followed by a server name, `unix ` and a time within the minutes of this run; `returning`. It must also contain `status: listening on 0.0.0.0:80`. It must not contain: a line with `ERROR`; `dns: no upstream answers`; `clock: no time server answered`; the Wi-Fi passphrase; or `example.org`, which the probe asked for — no name a client queried may be in the log.

If `clock: set by SNTP` is missing and `clock: waiting for a default route` is the last clock line, milestone 1 left no default route in `/proc/net/route`: read `/log` during the next boot (`curl http://<the Pi>/log`) and fix the route check, not the wait.

- [ ] **Step 5: Check Raspberry Pi OS came back** — `ssh <alias> 'cmp /boot/firmware/config.txt /boot/firmware/config.pios.txt && pihole status'` — expected: no `cmp` output; Pi-hole listening and blocking.
- [ ] **Step 6: Write `docs/bring-up/m2.md`** — date and build; the eight probe lines; from the log's timestamps, seconds from init's start to `dns: listening` and to `clock: set by SNTP`, with the size of the step; the first answer's time and the repeats' median from the probe; the upstream latency from the statistics; the size of the executable and of `initramfs8`; anything unexpected. No network name, address, server name from the owner's file, or raw log.
- [ ] **Step 7: Update `README.md`** — status: "Milestone 2 done: it joins the network, forwards and caches DNS, and sets its clock"; then commit both files — message `"Milestone 2: resolver and clock on the Pi"`.

**Milestone 2 ends here.** The tree is green, and nothing in it waits for milestone 3.

---

# Milestone 3 — Blocker

### Task 10: HTTPS client

The spec's risk — `rustls-rustcrypto` on this target — is taken first. It builds for the target (see Facts). Whether it completes a handshake on the board is Task 11's Pi check, the first moment the board makes a TLS connection.

A connection is one blocking job on the pool, from connect to the last byte (see "What holds the runtime thread"): plain `std::net::TcpStream`, `rustls::StreamOwned`, no async TLS.

**Files:**
- Create: `crates/qberrypi/src/https.rs`
- Modify: `crates/qberrypi/src/lib.rs`, `crates/qberrypi/Cargo.toml`, `Cargo.lock`

**Interfaces:**
- Consumes: `Dns::lookup_v4`, `services::blocking`, `services::testutil::longest_gap`.
- Produces:

```rust
pub const USER_AGENT: &str = "list-fetch";
pub const HTTPS_PORT: u16 = 443;
pub const MAX_BODY: usize = 32 * 1024 * 1024;
pub const MAX_HEAD: usize = 16 * 1024;
pub const CONNECT_WAIT: Duration = Duration::from_secs(10);
pub const IO_WAIT: Duration = Duration::from_secs(15);         // one read or one write
pub const TOTAL_WAIT: Duration = Duration::from_secs(120);     // a whole fetch, redirects included
pub const MAX_REDIRECTS: usize = 3;
#[derive(Debug, Clone, PartialEq, Eq)] pub struct Url { pub host: String, pub port: u16, pub path: String }
impl Url { pub fn parse(text: &str) -> Result<Url, HttpError>; }
#[derive(Debug)]
pub enum HttpError { Url(&'static str), Resolve(io::Error), Connect(io::Error), Tls(String), Timeout, Status(u16), BadResponse(&'static str), Truncated, TooLarge, Redirects }
impl std::fmt::Display for HttpError { /* lower case, no URL: "tls: …", "status 404", "timed out", … */ }
#[derive(Debug, PartialEq, Eq)] pub enum Response { Body(Vec<u8>), Redirect(String) }
pub fn get<S: Read + Write>(stream: &mut S, host: &str, path: &str, max_body: usize, deadline: Instant) -> Result<Response, HttpError>;
pub fn provider() -> rustls::crypto::CryptoProvider;                // rustls-rustcrypto's, with its ChaCha20 suites moved to the front
pub fn mozilla_roots() -> rustls::RootCertStore;                    // webpki-roots
pub fn client_config(roots: rustls::RootCertStore) -> Arc<rustls::ClientConfig>;
pub fn request(tls: &Arc<rustls::ClientConfig>, server: SocketAddr, url: &Url, deadline: Instant) -> Result<Response, HttpError>;   // blocking: one connection, one GET
pub struct Client { /* private */ }
impl Client {
    pub fn new(tls: Arc<rustls::ClientConfig>, dns: Arc<Dns>) -> Self;
    pub(crate) fn fixed(tls: Arc<rustls::ClientConfig>, server: SocketAddr, total_wait: Duration) -> Self;   // every host is at `server`
    pub async fn fetch(&self, url: &str) -> Result<Vec<u8>, HttpError>;
}
```

- `Url::parse`: `https://` then a host, an optional `:port`, an optional path that starts with `/`. What stands before the path is split at its first `:`, and the host is checked before the port. The host is an IPv4 address or a name `qb_dns::name::normalize` accepts, stored lower-case. No path means `/`. A `#` and what follows it are cut off. Anything else is `HttpError::Url` with one of the reasons in the test.
- `get` sends exactly `GET {path} HTTP/1.1`, `Host: {host}`, `User-Agent: list-fetch`, `Accept-Encoding: identity`, `Connection: close`, each ended by `\r\n`, then a blank line. It reads the head (at most `MAX_HEAD` bytes, parsed with `httparse`). Status 200: the body, by `Transfer-Encoding: chunked` if that is there, else by `Content-Length`, else to the end of the stream. Status 301, 302, 303, 307 or 308 with a `Location`: `Redirect(location)`. Any other status: `Status`. A `Content-Length` over `max_body` is `TooLarge` before a body byte is read; a body that grows past it is `TooLarge`; one that ends early is `Truncated` — and so is a TLS stream that ends without the peer's close notice (`ErrorKind::UnexpectedEof`). Before every read it looks at `deadline`: at it or past it, `Timeout`; a read that itself times out is `Timeout` too.
- `request`: TCP connect within `CONNECT_WAIT` or what is left to `deadline`, whichever is less; read and write timeouts of `IO_WAIT`, or what is left; TLS with the URL's host as the server name; `get` with `MAX_BODY`.
- `Client::fetch`: `Url::parse`; the deadline is `TOTAL_WAIT` from now. Then, at most `MAX_REDIRECTS` + 1 times: `lookup_v4(host)` on the runtime, its first address, and `services::blocking("list fetch", ..)` around `request`. A body ends it. A redirect goes on to an `https://` URL or to a path on the same host; one more than `MAX_REDIRECTS` is `Redirects`; another scheme is `BadResponse("redirect that is not https")`.

**If Task 11's Pi check shows the provider failing on the board** (a handshake error from every list host, or the boot dying inside TLS), fall back as the spec says: `cargo remove -p qberrypi rustls-rustcrypto`; `cargo add -p qberrypi rustls@0.23 --no-default-features -F std,tls12,ring`; `provider()` returns `rustls::crypto::ring::default_provider()` with the same reordering. `ring` compiles C and assembly, so the cross build needs a C compiler for the target; the development machine has clang and no cross gcc: build with `CC_aarch64_unknown_linux_musl=clang CFLAGS_aarch64_unknown_linux_musl=--target=aarch64-unknown-linux-musl cargo xtask build`. This has not been tried. Then the Global Constraint's `cargo tree` check allows `ring` and `cc`, the spec's table under "What 'all Rust' does and does not mean" gains a row, and the bring-up notes say so.

- [ ] **Step 1: Add the dependencies**

```bash
cargo add -p qberrypi rustls@0.23 --no-default-features -F std,tls12
cargo add -p qberrypi rustls-rustcrypto@=0.1.0-pre.0
cargo add -p qberrypi webpki-roots@1
cargo add -p qberrypi httparse@1
cargo add -p qberrypi --dev rcgen@0.14
```

- [ ] **Step 2: Write the failing tests** in `https.rs`. `Canned` is a stream whose reads give the bytes it was made with and then end, and whose writes are kept; `exchange(response: &[u8], max_body: usize) -> (String, Result<Response, HttpError>)` runs `get(.., "lists.example.net", "/lists/a.txt", max_body, an hour from now)` over one and returns the request it wrote with the result. `tls_server(routes: &[(&str, &[u8])], answer_after: Duration) -> (SocketAddr, rustls::RootCertStore)` serves canned responses by path on `127.0.0.1:0`, a thread per connection, with `rustls::ServerConnection`, `provider()` and a certificate for `localhost` from `rcgen::generate_simple_self_signed`; the store holds that certificate alone.

```rust
#[test] fn urls() {
    let url = |t| Url::parse(t).unwrap();
    assert_eq!(url("https://Lists.Example.NET/a/b.txt"), Url { host: "lists.example.net".into(), port: 443, path: "/a/b.txt".into() });
    assert_eq!(url("https://example.com"), Url { host: "example.com".into(), port: 443, path: "/".into() });
    assert_eq!(url("https://example.com:8443/x?y=1#frag"), Url { host: "example.com".into(), port: 8443, path: "/x?y=1".into() });
    assert_eq!(url("https://192.0.2.7/l").host, "192.0.2.7");
    for (bad, why) in [("http://example.com/", "not https"), ("https://", "no host"), ("https://user@example.com/", "not a host name"),
                       ("https://exa mple.com/", "not a host name"), ("https://[2001:db8::1]/", "not a host name"),
                       ("https://example.com:0/", "not a port"), ("https://example.com:99999/", "not a port")] {
        assert!(matches!(Url::parse(bad), Err(HttpError::Url(reason)) if reason == why), "{bad}");
    }
}
#[test] fn the_request_is_a_plain_get_that_does_not_name_the_project() {
    let (request, _) = exchange(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 100);
    assert_eq!(request, "GET /lists/a.txt HTTP/1.1\r\nHost: lists.example.net\r\nUser-Agent: list-fetch\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n");
}
#[test] fn a_body_is_read_by_length_by_chunks_or_to_the_end() {
    for response in [&b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"[..],
                     b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nhel\r\n2;x=1\r\nlo\r\n0\r\n\r\n",
                     b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\nhello"] {
        assert_eq!(exchange(response, 100).1.unwrap(), Response::Body(b"hello".to_vec()));
    }
}
#[test] fn a_body_that_ends_early_or_is_too_large_is_an_error() {
    assert!(matches!(exchange(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello", 100).1, Err(HttpError::Truncated)));
    assert!(matches!(exchange(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel", 100).1, Err(HttpError::Truncated)));
    assert!(matches!(exchange(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world", 10).1, Err(HttpError::TooLarge)));
    assert!(matches!(exchange(b"HTTP/1.1 200 OK\r\n\r\nhello world", 10).1, Err(HttpError::TooLarge)));
    assert!(matches!(exchange(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nb\r\nhello world\r\n0\r\n\r\n", 10).1, Err(HttpError::TooLarge)));
}
#[test] fn other_statuses_redirects_and_nonsense() {
    assert!(matches!(exchange(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", 100).1, Err(HttpError::Status(404))));
    assert_eq!(exchange(b"HTTP/1.1 302 Found\r\nLocation: https://other.example.net/x\r\n\r\n", 100).1.unwrap(), Response::Redirect("https://other.example.net/x".into()));
    assert!(matches!(exchange(b"HTTP/1.1 302 Found\r\n\r\n", 100).1, Err(HttpError::BadResponse(_))));
    assert!(matches!(exchange(b"garbage\r\n\r\n", 100).1, Err(HttpError::BadResponse(_))));
    let long_head = [&b"HTTP/1.1 200 OK\r\nX: "[..], &[b'a'; 17_000], b"\r\n\r\n"].concat();
    assert!(matches!(exchange(&long_head, 100).1, Err(HttpError::BadResponse(_))));
}
#[test] fn nothing_is_read_once_the_time_is_up() {
    let mut stream = Canned::new(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
    assert!(matches!(get(&mut stream, "lists.example.net", "/", 100, Instant::now()), Err(HttpError::Timeout)));
}
#[test] fn chacha20_is_offered_first_and_the_roots_are_mozillas() {
    assert_eq!(provider().cipher_suites[0].suite(), rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256);
    assert_eq!(mozilla_roots().len(), webpki_roots::TLS_SERVER_ROOTS.len());
    assert!(mozilla_roots().len() > 100);
}
#[tokio::test] async fn a_list_is_fetched_over_tls_from_a_server_the_roots_vouch_for() {
    let (addr, roots) = tls_server(&[("/list.txt", b"HTTP/1.1 200 OK\r\nContent-Length: 24\r\n\r\n0.0.0.0 ads.example.com\n")], ms(0));
    let client = Client::fixed(client_config(roots), addr, ms(5000));
    assert_eq!(client.fetch(&format!("https://localhost:{}/list.txt", addr.port())).await.unwrap(), b"0.0.0.0 ads.example.com\n");
}
#[tokio::test] async fn a_server_the_roots_do_not_vouch_for_or_under_another_name_is_refused() {
    let (addr, roots) = tls_server(&[("/list.txt", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")], ms(0));
    let strangers = Client::fixed(client_config(mozilla_roots()), addr, ms(5000));
    assert!(matches!(strangers.fetch(&format!("https://localhost:{}/list.txt", addr.port())).await, Err(HttpError::Tls(_))));
    let known = Client::fixed(client_config(roots), addr, ms(5000));
    assert!(matches!(known.fetch(&format!("https://lists.example.net:{}/list.txt", addr.port())).await, Err(HttpError::Tls(_))));
}
#[tokio::test] async fn redirects_are_followed_three_times_and_only_to_https() {
    // routes: /a -> 302 Location: /b; /b -> 200 "ok"; /loop -> 302 Location: /loop; /plain -> 301 Location: http://localhost/x
    // fetch(/a) is b"ok"; fetch(/loop) is Err(Redirects); fetch(/plain) is Err(BadResponse("redirect that is not https"))
}
#[tokio::test] async fn a_server_that_never_speaks_is_given_up_on() {
    // a plain TcpListener that accepts and holds the connection; Client::fixed(.., ms(300)):
    // fetch is Err(Timeout) within 1 s
}
#[tokio::test] async fn a_fetch_does_not_hold_the_runtime_thread() {
    let (addr, roots) = tls_server(&[("/list.txt", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")], ms(300));
    let client = Client::fixed(client_config(roots), addr, ms(5000));
    let (gap, body) = longest_gap(client.fetch(&format!("https://localhost:{}/list.txt", addr.port()))).await;
    assert_eq!(body.unwrap(), b"ok");
    assert!(gap < ms(100), "{gap:?}");             // the handshake and the 300 ms of waiting were on the pool
}
```

- [ ] **Step 3: Run** `cargo test -p qberrypi https::` — expected: compile failure.
- [ ] **Step 4: Implement `https.rs`.**
- [ ] **Step 5: Run** `cargo test -p qberrypi https::` — expected: 12 passed.
- [ ] **Step 6: Check the target and the tree**

Run: `cargo build -p qberrypi --release --target aarch64-unknown-linux-musl` — expected: builds.
Run: `cargo tree -p qberrypi --target aarch64-unknown-linux-musl -e normal,build --prefix none | grep -E '^(ring|aws-lc-sys|cc|zstd-sys|openssl-sys) '` — expected: no output.

- [ ] **Step 7: Commit** — stage the four files by name; message `"https: a blocking HTTP/1.1 GET over rustls with the RustCrypto provider"`.

---

### Task 11: Refreshing the lists

**Files:**
- Create: `crates/qberrypi/src/lists/refresh.rs`
- Modify: `crates/qberrypi/src/lists/mod.rs`, `crates/qberrypi/src/status.rs`, `crates/qberrypi/src/services.rs`

**Interfaces:**
- Consumes: `https::{Client, HttpError, Url, client_config, mozilla_roots}`, `services::blocking`, `services::testutil::longest_gap`, `Dns::{resolver, now}`, `lists::from_config`, `qb_dns::{BlockSet, ListStats}`, the `synced` receiver.
- Produces:

```rust
// lists/mod.rs
#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum Source { Config, Snapshot, Fetched }
impl Source { pub fn as_str(self) -> &'static str; }                // "config", "snapshot", "fetched"
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListState { pub source: Source, pub names: usize, pub fetched_unix_secs: Option<u64>, pub last_error: Option<String> }
pub struct Lists { /* private: Mutex<ListState> */ }
impl Lists {
    pub fn new(state: ListState) -> Arc<Self>;
    pub fn get(&self) -> ListState;
    pub fn fetched(&self, names: usize, unix_secs: u64);            // source Fetched, the error cleared
    pub fn failed(&self, error: String);                            // only last_error changes
}
pub fn names(set: &BlockSet) -> usize;                              // exact_len() + suffix_len()

// lists/refresh.rs
pub const FIRST_AFTER: Duration = Duration::from_secs(60);
pub const EVERY: Duration = Duration::from_secs(24 * 3600);
pub const RETRY_AFTER: Duration = Duration::from_secs(3600);
pub trait Fetch: Send + Sync {
    fn fetch<'a>(&'a self, url: &'a str) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, HttpError>> + Send + 'a>>;
}
impl Fetch for https::Client { /* its own fetch */ }
#[derive(Debug)]
pub enum RefreshError { Fetch { list: usize, host: String, error: HttpError }, NotAList { list: usize, host: String } }
impl std::fmt::Display for RefreshError { /* "list 2 (lists.example.net): status 404"; "list 2 (lists.example.net): not a blocklist" */ }
pub async fn build(fetch: &dyn Fetch, urls: &[String], deny: &[String], allow: &[String]) -> Result<BlockSet, RefreshError>;
pub fn next_after(last: Option<bool>) -> Duration;     // None: the clock was just set; Some(true): a refresh worked; Some(false): it failed
pub async fn run(dns: Arc<Dns>, lists: Arc<Lists>, fetch: Arc<dyn Fetch>, cfg: &'static Config, synced: tokio::sync::watch::Receiver<bool>) -> io::Result<()>;
```

`build` starts from `from_config(deny, allow)` and takes the lists in order, counted from 1. Each text is fetched, then given to `add_list` inside `services::blocking("list parse", ..)`, the builder moved in and back out; a list whose `ListStats` has `exact + suffix == 0` is `NotAList`. The last step, `builder.build()`, is a blocking job too. A blocking job that cannot be joined is `RefreshError::Fetch` with `HttpError::Connect` of its error. An error returns before anything was swapped. `host` is the URL's host, or `?` if the URL does not parse; the URL itself is in no error and no log line.

`run`: with no list configured, log `lists: none configured` and wait for ever. Otherwise log `lists: waiting for the clock`, wait until `synced` is true, sleep `next_after(None)`, then for ever: `build`; on `Ok(set)`, `dns.resolver().set_blockset(set)`, `lists.fetched(names, now.unix_secs)`, and log `lists: refreshed: {names} names from {n} lists in {secs:.1} s`; on `Err(e)`, `lists.failed(e.to_string())` and log `lists: refresh failed: {e}; keeping {names} names` at WARN; sleep `next_after(Some(ok))`. `build` also logs, at INFO, `lists: list {i} ({host}): {bytes} bytes in {ms} ms` for each list it fetched.

`Status` gains the field `pub lists: Arc<Lists>`, and `stats()` four keys, making 23:

```json
"list_source": "fetched", "list_names": 302176, "list_age_secs": 3600, "list_error": null
```

`list_source` is `Source::as_str()`. `list_age_secs` is the clock's `unix_secs` less `fetched_unix_secs`, held at zero or more; it is `null` until the clock is set, and while there is no fetch time.

In `services::run`: `Lists::new(ListState { source: Source::Config, names: names(&set), fetched_unix_secs: None, last_error: None })` where the set is made; and after the status lines, `spawn_component("lists", refresh::run(dns.clone(), lists.clone(), Arc::new(Client::new(client_config(mozilla_roots()), dns.clone())), cfg, synced.clone()))`.

- [ ] **Step 1: Write the failing tests** in `lists/refresh.rs`. `FakeFetch` maps a URL to bytes or to an `HttpError`, counts its calls, and can be changed while a test runs. `A: &str = "https://lists.example.net/a.txt"`, `B: &str = "https://lists.example.org/b.txt"`; `HOSTS: &[u8] = b"0.0.0.0 ads.example.com\n0.0.0.0 pixel.example.com\n"`, `ADBLOCK: &[u8] = b"||tracker.example.net^\n"`, `HTML: &[u8] = b"<!DOCTYPE html>\n<html><body><h1>Sign in to the network</h1><p>example.com</p></body></html>\n"`.

```rust
#[tokio::test] async fn two_lists_and_the_configuration_make_one_set() {
    let fetch = FakeFetch::new(&[(A, Ok(HOSTS)), (B, Ok(ADBLOCK))]);
    let set = build(&fetch, &[A.into(), B.into()], &["denied.example.org".into()], &["ok.tracker.example.net".into()]).await.unwrap();
    for blocked in ["ads.example.com", "pixel.example.com", "x.tracker.example.net", "denied.example.org"] { assert!(set.is_blocked(blocked), "{blocked}"); }
    for open in ["ok.tracker.example.net", "example.com"] { assert!(!set.is_blocked(open), "{open}"); }
    assert_eq!(names(&set), 4);
}
#[tokio::test] async fn a_page_that_is_not_a_list_fails_the_refresh() {                       // Review Focus 4
    for not_a_list in [HTML, &b""[..], b"# only a comment\n"] {
        let fetch = FakeFetch::new(&[(A, Ok(HOSTS)), (B, Ok(not_a_list))]);
        let error = build(&fetch, &[A.into(), B.into()], &[], &[]).await.unwrap_err();
        assert!(matches!(&error, RefreshError::NotAList { list: 2, host } if host == "lists.example.org"));
        assert_eq!(error.to_string(), "list 2 (lists.example.org): not a blocklist");
    }
}
#[tokio::test] async fn one_list_that_cannot_be_fetched_fails_the_refresh() {                 // Review Focus 4
    let fetch = FakeFetch::new(&[(A, Err(HttpError::Status(404))), (B, Ok(ADBLOCK))]);
    let error = build(&fetch, &[A.into(), B.into()], &[], &[]).await.unwrap_err();
    assert_eq!(error.to_string(), "list 1 (lists.example.net): status 404");
}
#[test] fn the_schedule() {
    assert_eq!((next_after(None), next_after(Some(true)), next_after(Some(false))), (Duration::from_secs(60), Duration::from_secs(86_400), Duration::from_secs(3600)));
}
#[tokio::test(start_paused = true)] async fn nothing_is_fetched_before_the_clock_is_set() {     // Review Focus 5
    // run() spawned with synced at false and FakeFetch [(A, Ok(HOSTS))]; cfg lists [A]
    // advance two days: fetch.calls() == 0
    // send true; advance 59 s: still 0; advance 2 s more and yield: fetch.calls() == 1
}
#[tokio::test(start_paused = true)] async fn a_failed_refresh_keeps_the_set_and_is_tried_again_in_an_hour() {   // Review Focus 4
    // dns built from_config(["old.example.com"]); lists at Source::Config with names 1; FakeFetch [(A, Ok(HTML))]; synced true
    // advance 61 s: dns still blocks old.example.com and not ads.example.com;
    //   lists.get() == ListState { source: Config, names: 1, fetched_unix_secs: None, last_error: Some("list 1 (lists.example.net): not a blocklist") }
    // the fetcher is changed to Ok(HOSTS); advance 59 min: fetch.calls() == 1; advance 2 min more: calls() == 2,
    //   ads.example.com is blocked, old.example.com still is (it is the configuration's), and
    //   lists.get() has source Fetched, names 3, fetched_unix_secs Some(_), last_error None
    // advance 23 h: calls() == 2; advance 2 h more: calls() == 3
}
#[tokio::test] async fn a_refresh_does_not_hold_the_runtime_thread() {
    let big: Vec<u8> = (0..200_000).flat_map(|i| format!("0.0.0.0 h{i}.example.com\n").into_bytes()).collect();   // about 5 MB
    let fetch = FakeFetch::new(&[(A, Ok(big.as_slice()))]);
    let (gap, set) = longest_gap(build(&fetch, &[A.into()], &[], &[])).await;
    assert_eq!(names(&set.unwrap()), 200_000);
    assert!(gap < Duration::from_millis(100), "{gap:?}");          // parsing and building were on the pool
}
#[tokio::test(start_paused = true)] async fn with_no_lists_nothing_is_ever_fetched() {
    // cfg lists []; synced true; advance 3 days: calls() == 0 and the task has not ended
}
```

`cfg` for these tests is `Box::leak` of the example configuration with its `lists` and `deny` replaced. After each `advance` the tests wait, in steps of a millisecond, until the task has settled: a build runs on the blocking pool, which the paused clock does not drive.

In `status.rs`, `served` gives its `Status` a `Lists` at `Source::Config` with 1 name; `the_statistics_are_served_as_json` now expects 23 keys, `list_source == "config"`, `list_names == 1`, and `list_age_secs` and `list_error` null; and one test more:

```rust
#[tokio::test] async fn the_lists_age_is_known_only_with_a_fetch_time_and_a_set_clock() {
    // a Status whose Lists were `fetched(302_176, now − 3600)`, with `synced` at false: list_age_secs is null
    // `synced` sent true: list_source == "fetched", list_names == 302_176, list_age_secs is 3600 or 3601
    // lists.failed("list 1 (lists.example.net): status 404".into()): list_error is that text, the other three unchanged
}
```

- [ ] **Step 2: Run** `cargo test -p qberrypi lists::` — expected: compile failure.
- [ ] **Step 3: Implement** `Lists`, `refresh.rs`, the status keys and the lines in `services::run`.
- [ ] **Step 4: Run** `cargo test -p qberrypi` — expected: all pass.
- [ ] **Step 5: Run** `cargo xtask build && cargo xtask qemu-test` — expected: seven `ok`; the guest logs `lists: waiting for the clock` and fetches nothing.
- [ ] **Step 6: Commit** — stage the four files by name; message `"lists: refetch over HTTPS a minute after the clock is set, then daily"`.
- [ ] **Step 7: Pi check — the TLS risk** (session lead). With `return_after_secs = 150`: `cargo xtask deploy --host <alias>`. The collected log must contain, in this order: `clock: set by SNTP from `; one `lists: list N (` line per configured list, each with a byte count above 100,000; `lists: refreshed: ` with a name count above 250,000 (for the two example lists). It must not contain `lists: refresh failed` or a line with `ERROR`. Note the milliseconds of each `lists: list` line: that is a TLS handshake and a download on the board's processor.

If instead it has `lists: refresh failed: list 1 (…): tls: …` for every list, or the boot ended inside the fetch, take Task 10's fallback, rebuild, re-run `cargo xtask qemu-test`, deploy again, and record it as an amendment at the foot of this plan. A `status`, `timed out` or `no address` error is the network's or the list host's, not the provider's: deploy once more before deciding.

---

### Task 12: `cargo xtask fetch-lists` and the snapshot in the image

**Files:**
- Create: `crates/qberrypi/src/lists/snapshot.rs` (the format only), `xtask/src/lists.rs`
- Modify: `crates/qberrypi/src/lists/mod.rs`, `xtask/src/build.rs`, `xtask/src/fetch.rs`, `xtask/src/main.rs`, `xtask/Cargo.toml`, `Cargo.lock`, `README.md`

**Interfaces:**
- Consumes: `qb_dns::parse::{parse_list, RuleKind}`, `qberrypi::config::parse`, `fetch::{Download, download}` (made `pub(crate)`), `zstd`, `sha2`.
- Produces:

```rust
// crates/qberrypi/src/lists/snapshot.rs
pub const SNAPSHOT_PATH: &str = "/blocklist.zst";
pub const MARKER: &str = "qberrypi-snapshot.invalid";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header { pub fetched_unix_secs: u64, pub lists: u32, pub exact: u32, pub suffix: u32 }
impl Header {
    pub fn line(&self) -> String;                       // "# qberrypi-snapshot 1 fetched={} lists={} exact={} suffix={}\n"
    pub fn parse(text: &[u8]) -> Option<Header>;        // from the first line of a snapshot's text
}

// xtask/src/lists.rs
pub const LIST_CACHE: &str = "vendor-cache/lists";
pub const LOCK_FILE: &str = "vendor-cache/lists/lock";
pub const STALE_AFTER_DAYS: u64 = 7;
pub const ZSTD_LEVEL: i32 = 19;
pub fn url_key(url: &str) -> String;                    // the first 16 hex digits of the URL's SHA-256
pub fn configured_lists(root: &Path) -> Result<Vec<String>>;
pub fn fetch(root: &Path, urls: &[String], now_unix_secs: u64, download: Download) -> Result<()>;
pub fn canonical(texts: &[&[u8]], fetched_unix_secs: u64) -> (String, Header);
pub fn snapshot(root: &Path, urls: &[String]) -> Result<(Vec<u8>, Header)>;
```

- `configured_lists`: `dns.lists` of `<root>/qberrypi.toml` if that file is there, otherwise of `<root>/qberrypi.example.toml`. A file that does not parse is an error with the parser's message, which never quotes the file.
- The cache: list N is `vendor-cache/lists/{url_key}.txt`. The lock file has one line per list, `{url_key} {sha256 of the file} {bytes} {fetched_unix_secs}`. No URL is written anywhere.
- `fetch` (`cargo xtask fetch-lists`), for each URL: download to `{url_key}.txt.partial`; run `parse_list` over it; if it emits no rule, remove the partial file and fail with `list {n} is not a blocklist; kept what was there`; otherwise rename it over `{url_key}.txt`. When all are done the lock file is written anew, through a temporary file and a rename. It prints, per list, `fetch-lists: list {n}: {exact} exact, {suffix} suffix, {bytes} bytes`.
- `canonical`: every rule `parse_list` emits from every text, and one more exact rule, `MARKER`. Exact names and suffix names are each sorted bytewise with duplicates dropped. The text is the header line, then `0.0.0.0 {name}\n` per exact name, then `||{name}^\n` per suffix name. The header counts those lines; `lists` is the number of texts.
- `snapshot`: every URL needs a lock line — otherwise `list {n} has not been fetched: run cargo xtask fetch-lists` — and its file must have the locked hash — otherwise `list {n} has changed since it was fetched: run cargo xtask fetch-lists`. `fetched_unix_secs` is the oldest of the lists' times, or 0 with no list. The result is `canonical`'s text compressed in one call at `ZSTD_LEVEL`, with its header. It reads no network.
- `build.rs`: `initramfs_entries(extracted, init, snapshot)` gains the snapshot as its last entry, `blocklist.zst`, mode `0o644`; `write_boot_folder` takes the snapshot's bytes with the rest; `run` makes the snapshot before it cross-compiles, and prints `build: snapshot: {names} names from {lists} lists, fetched {days} days ago, {bytes} bytes`, with a second line `build: the snapshot is over 7 days old; cargo xtask fetch-lists renews it` when it is, and at the end the sizes of init and of `initramfs8`.

- [ ] **Step 1: Add the dependency** — `cargo add -p xtask qb-dns --path crates/qb-dns`
- [ ] **Step 2: Write the failing tests.** In `lists/snapshot.rs`:

```rust
#[test] fn the_header_is_one_comment_line_and_reads_back() {
    let h = Header { fetched_unix_secs: 1_800_000_000, lists: 2, exact: 3, suffix: 2 };
    assert_eq!(h.line(), "# qberrypi-snapshot 1 fetched=1800000000 lists=2 exact=3 suffix=2\n");
    assert_eq!(Header::parse(format!("{}0.0.0.0 ads.example.com\n", h.line()).as_bytes()), Some(h));
    for bad in ["", "0.0.0.0 ads.example.com\n", "# qberrypi-snapshot 2 fetched=1 lists=1 exact=1 suffix=1\n",
                "# qberrypi-snapshot 1 fetched=1 lists=1 exact=1\n", "# qberrypi-snapshot 1 fetched=x lists=1 exact=1 suffix=1\n"] {
        assert_eq!(Header::parse(bad.as_bytes()), None, "{bad:?}");
    }
}
```

In `xtask/src/lists.rs`, with a temporary root, a `fake(pages: &[(&str, &[u8])])` download that writes the page for a URL, and `A`, `B`, `HOSTS`, `ADBLOCK`, `HTML` as in Task 11:

```rust
#[test] fn canonical_text_is_sorted_has_no_duplicates_and_carries_the_marker() {
    let (text, header) = canonical(&[b"0.0.0.0 b.example.com\n0.0.0.0 A.example.com\n", b"||tracker.example.net^\n||a.example.com^\n0.0.0.0 a.example.com\n"], 1_800_000_000);
    assert_eq!(text, "# qberrypi-snapshot 1 fetched=1800000000 lists=2 exact=3 suffix=2\n\
                      0.0.0.0 a.example.com\n0.0.0.0 b.example.com\n0.0.0.0 qberrypi-snapshot.invalid\n\
                      ||a.example.com^\n||tracker.example.net^\n");
    assert_eq!(header, Header { fetched_unix_secs: 1_800_000_000, lists: 2, exact: 3, suffix: 2 });
    assert_eq!(Header::parse(text.as_bytes()), Some(header));
}
#[test] fn the_canonical_text_is_itself_a_list_with_the_headers_counts() {
    let (text, header) = canonical(&[HOSTS, ADBLOCK], 1);
    let stats = qb_dns::BlockSetBuilder::new().add_list(text.as_bytes());
    assert_eq!((stats.exact as u32, stats.suffix as u32, stats.invalid, stats.unsupported), (header.exact, header.suffix, 0, 0));
}
#[test] fn fetching_records_each_list_under_its_key_with_its_hash() {
    // fetch(root, [A, B], 1_800_000_000, fake([(A, HOSTS), (B, ADBLOCK)])):
    // vendor-cache/lists/{url_key(A)}.txt holds HOSTS; the lock has two lines, each `{key} {64 hex} {bytes} 1800000000`;
    // neither URL nor its host occurs in the lock; no .partial file is left
    assert_eq!(url_key(A).len(), 16);
    assert_ne!(url_key(A), url_key(B));
}
#[test] fn fetching_keeps_the_old_file_when_the_new_one_is_not_a_list() {                    // Review Focus 4
    // after a good fetch of [A], fetch(root, [A], .., fake([(A, HTML)])) is an error that contains
    // "list 1 is not a blocklist"; the cached file still holds HOSTS; the lock is unchanged; no .partial file is left
}
#[test] fn the_snapshot_needs_every_list_fetched_and_unchanged() {
    // snapshot(root, [A]) with an empty cache: the error contains "list 1 has not been fetched" and "cargo xtask fetch-lists"
    // after fetch of [A]: snapshot(root, [A, B]) names list 2 the same way
    // after one byte is appended to A's cached file: the error contains "list 1 has changed since it was fetched"
}
#[test] fn the_same_cache_gives_the_same_bytes_and_the_pi_can_unpack_them() {
    // after fetch of [A, B] at 1_800_000_000: two calls of snapshot(root, [A, B]) return equal bytes;
    // zstd::decode_all of them is canonical(&[HOSTS, ADBLOCK], 1_800_000_000).0
    // snapshot(root, []) unpacks to "# qberrypi-snapshot 1 fetched=0 lists=0 exact=1 suffix=0\n0.0.0.0 qberrypi-snapshot.invalid\n"
}
#[test] fn the_lists_are_the_local_configurations_or_else_the_examples() {
    // a root with only qberrypi.example.toml: its two URLs
    // with a qberrypi.toml beside it whose lists are [A]: [A]
    // with a qberrypi.toml that is not TOML: an error that does not contain the file's text
}
```

In `xtask/src/build.rs`: the `INITRAMFS` listing gains one entry, its last, `"- blocklist.zst"`; every `initramfs_entries(&extracted, b"ELF")` gains a third argument, `b"SNAPSHOT"`; and one test more:

```rust
#[test] fn the_snapshot_is_the_last_entry_and_is_not_executable() {
    let extracted = fixture_extracted();
    let entries = initramfs_entries(&extracted, b"ELF", b"SNAPSHOT");
    let (path, node) = entries.last().unwrap();
    assert_eq!((path.as_str(), *node), ("blocklist.zst", Node::File { data: b"SNAPSHOT", mode: 0o644 }));
    assert_eq!(format!("/{path}"), qberrypi::lists::snapshot::SNAPSHOT_PATH);
}
```

- [ ] **Step 3: Run** `cargo test -p xtask -- lists:: build::` and `cargo test -p qberrypi lists::snapshot` — expected: compile failures.
- [ ] **Step 4: Implement** the format, `xtask/src/lists.rs`, the changes in `build.rs`, the `FetchLists` subcommand, and a README row: "Downloads the lists your configuration names into `vendor-cache/lists/`, for `build` to pack into the image as the snapshot the Pi blocks from before it has a network." Add one sentence under the table: an image holds the lists' contents, so the lists' own licences apply to anyone who passes an image on.
- [ ] **Step 5: Run** `cargo test --workspace` — expected: all pass.
- [ ] **Step 6: Run it for real** — `cargo xtask fetch-lists && cargo xtask build && ls -l out/qberrypi/initramfs8 && git status --short`. Expected: two `fetch-lists:` lines with counts near 78,000 exact and 224,000 suffix (for the example lists); a `build: snapshot:` line with about 302,000 names and under 2,500,000 bytes; `initramfs8` under 6,000,000 bytes; `git status` lists nothing under `vendor-cache/` or `out/`.
- [ ] **Step 7: Commit** — stage the nine files by name; message `"xtask: fetch-lists, and the list snapshot in the initramfs"`.

---

### Task 13: Blocking from the snapshot at boot

**Files:**
- Modify: `crates/qberrypi/src/lists/snapshot.rs`, `crates/qberrypi/src/services.rs`, `crates/qberrypi/src/selftest.rs`, `crates/qberrypi/Cargo.toml`, `Cargo.lock`, `xtask/src/qemu.rs`, `xtask/src/lists.rs` (one test)

**Interfaces:**
- Consumes: Task 12's `Header`, `MARKER`, `SNAPSHOT_PATH`; `lists::{from_config, names, ListState, Source}`.
- Produces:

```rust
// lists/snapshot.rs
pub const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
pub fn unpack(zst: &[u8], max_bytes: usize) -> io::Result<Vec<u8>>;        // ruzstd; more than max_bytes is ErrorKind::InvalidData
pub struct Loaded { pub set: BlockSet, pub state: ListState, pub problem: Option<String> }
pub fn load(path: &Path, deny: &[String], allow: &[String]) -> Loaded;
```

`load` never fails. It starts from `from_config(deny, allow)`.

| The file | `set` | `state.source`, `fetched_unix_secs` | `problem` |
|---|---|---|---|
| reads, unpacks, has a header, and `add_list` counts what the header says | configuration and snapshot | `Snapshot`, the header's time | `None` |
| the same, but the counts differ | configuration and what was parsed | `Snapshot`, the header's time | `Some("{exact} exact and {suffix} suffix rules, the header says {exact} and {suffix}")` |
| cannot be read, is not zstd, is over the cap, or has no header | configuration only | `Config`, `None` | `Some(..)`: the I/O error, or `no snapshot header` |

`state.names` is `names(&set)`; `last_error` is `None`.

In `services::run`, the block set now comes from `services::blocking("snapshot", || snapshot::load(Path::new(SNAPSHOT_PATH), deny, allow))`, awaited before the DNS component is spawned: the runtime thread stays free meanwhile, and no query is answered without the snapshot. If the job cannot be joined, the set is the configuration's, logged like a missing snapshot. It logs `lists: snapshot: {names} names, fetched unix {secs}, loaded in {ms} ms`, or with source `Config`, `lists: no snapshot: {names} names from the configuration`; a `problem` is logged at ERROR as `lists: snapshot: {problem}`. `Lists::new` takes `loaded.state`.

`selftest::dns` gains a line, fourth of six: `selftest: dns: udp qberrypi-snapshot.invalid A: {..}`. `dns_selftest_conditions` gains three conditions: `serial_has("INFO  selftest: dns: udp qberrypi-snapshot.invalid A: NOERROR 0.0.0.0")`, `serial_has("INFO  lists: snapshot: ")`, `serial_has("INFO  lists: waiting for the clock")`.

- [ ] **Step 1: Add the dependency** — `cargo add -p qberrypi ruzstd@0.9 --no-default-features -F std`
- [ ] **Step 2: Write the failing tests** in `lists/snapshot.rs`. `packed(text: &str) -> Vec<u8>` is `ruzstd::encoding::compress_to_vec(text.as_bytes(), CompressionLevel::Fastest)`; `file(bytes: &[u8]) -> tempfile::NamedTempFile`.

```rust
const TEXT: &str = "# qberrypi-snapshot 1 fetched=1800000000 lists=2 exact=2 suffix=1\n\
                    0.0.0.0 ads.example.com\n0.0.0.0 qberrypi-snapshot.invalid\n||tracker.example.net^\n";
fn load_from(bytes: &[u8]) -> Loaded { load(file(bytes).path(), &["denied.example.org".into()], &["ok.tracker.example.net".into()]) }

#[test] fn a_snapshot_is_loaded_together_with_the_configurations_names() {
    let l = load_from(&packed(TEXT));
    assert_eq!(l.problem, None);
    assert_eq!(l.state, ListState { source: Source::Snapshot, names: 4, fetched_unix_secs: Some(1_800_000_000), last_error: None });
    for blocked in ["ads.example.com", MARKER, "x.tracker.example.net", "denied.example.org"] { assert!(l.set.is_blocked(blocked), "{blocked}"); }
    for open in ["ok.tracker.example.net", "example.com"] { assert!(!l.set.is_blocked(open), "{open}"); }
}
#[test] fn a_snapshot_that_is_missing_or_broken_leaves_the_configurations_names_and_says_why() {
    let missing = load(Path::new("/nonexistent/blocklist.zst"), &["denied.example.org".into()], &[]);
    let not_zstd = load_from(b"this is not zstd");
    let no_header = load_from(&packed("0.0.0.0 ads.example.com\n"));
    for l in [missing, not_zstd, no_header] {
        assert!(l.problem.is_some());
        assert_eq!((l.state.source, l.state.names, l.state.fetched_unix_secs), (Source::Config, 1, None));
        assert!(l.set.is_blocked("denied.example.org") && !l.set.is_blocked("ads.example.com"));
    }
}
#[test] fn counts_that_differ_from_the_header_are_reported_and_the_names_are_used() {
    let l = load_from(&packed(&TEXT.replace("exact=2", "exact=5")));
    assert_eq!(l.problem.as_deref(), Some("2 exact and 1 suffix rules, the header says 5 and 1"));
    assert_eq!(l.state.source, Source::Snapshot);
    assert!(l.set.is_blocked("ads.example.com"));
}
#[test] fn unpacking_stops_at_the_cap() {
    let big = packed(&"0.0.0.0 ads.example.com\n".repeat(1000));
    assert_eq!(unpack(&big, 24_000).unwrap().len(), 24_000);
    assert_eq!(unpack(&big, 23_999).unwrap_err().kind(), io::ErrorKind::InvalidData);
}
```

In `xtask/src/lists.rs`, add to `the_same_cache_gives_the_same_bytes_and_the_pi_can_unpack_them`: `qberrypi::lists::snapshot::unpack(&bytes, MAX_SNAPSHOT_BYTES)` equals what `zstd::decode_all` gave — the Pi's decoder reads what the build's encoder wrote at level 19. In `selftest.rs`, the expected lines of the first test gain the marker line, with the test's `Dns` also denying `MARKER`.

- [ ] **Step 3: Run** `cargo test -p qberrypi -- lists::snapshot selftest::` — expected: compile failure.
- [ ] **Step 4: Implement** `unpack`, `load`, and the changes in `services::run`, `selftest.rs` and `qemu.rs`.
- [ ] **Step 5: Run** `cargo test --workspace` — expected: all pass.
- [ ] **Step 6: Run** `cargo xtask build && cargo xtask qemu-test` — expected: seven `ok`. `dns without a network` now shows the snapshot's marker blocked on the real kernel, with no network and before any clock. Read `out/qemu/dns-without-a-network.log` for the `lists: snapshot:` line: its `loaded in` figure is emulated and several times the board's.
- [ ] **Step 7: Commit** — stage the seven files by name; message `"lists: block from the snapshot before the network is up"`.

---

### Task 14: `cargo xtask probe`, blocker stage

**Files:**
- Modify: `xtask/src/probe.rs`, `README.md`

**Interfaces:**
- Consumes: Task 8's `ask_udp`, `get_stats`, `judge_resolver`, `Check`, `Timed`, `report`; `qberrypi::lists::snapshot::MARKER`.
- Produces:

```rust
pub const REFRESH_WAIT_SECS: u64 = 150;
#[derive(Debug, Default)]
pub struct BlockerSeen {
    pub at_first: Option<serde_json::Value>,      // /api/v1/stats as soon as the Pi answered
    pub marker_at_first: Option<Timed>,           // the marker, A
    pub listed_a: Option<Timed>,                  // --listed, A
    pub listed_aaaa: Option<Timed>,               // --listed, AAAA
    pub refreshed: Option<serde_json::Value>,     // /api/v1/stats once list_source is "fetched"; None if that never came
    pub marker_after: Option<Timed>,
    pub listed_after: Option<Timed>,
}
pub fn judge_blocker(seen: &BlockerSeen) -> Vec<Check>;
```

`run(Stage::Blocker, ..)`, once the Pi answers: `at_first`, `marker_at_first`, `listed_a`, `listed_aaaa`; then everything of the resolver stage; then it reads the statistics every 5 s until `list_source` is `fetched`, for at most `REFRESH_WAIT_SECS`; then `marker_after` and `listed_after`. It reports the resolver's eight checks and these seven, and fails unless all fifteen hold.

| `what` | Holds when |
|---|---|
| `the snapshot is in force before any refresh` | `at_first.list_source` is `snapshot` and `at_first.list_names` > 0 |
| `the snapshot's marker is blocked` | `marker_at_first` is NOERROR, `0.0.0.0`, TTL 2 |
| `a listed name gets 0.0.0.0` | `listed_a` is NOERROR, `0.0.0.0` |
| `a listed name gets :: for AAAA` | `listed_aaaa` is NOERROR, `::` |
| `the lists are refreshed over HTTPS` | `refreshed.list_source` is `fetched`, `list_error` is null, `list_names` > 0 |
| `after the refresh the marker is gone and the listed name is still blocked` | `marker_after` has no `0.0.0.0`, and `listed_after` is NOERROR, `0.0.0.0` |
| `blocked queries are counted` | `refreshed.blocked_total` ≥ 3 |

If `at_first.list_source` is already `fetched`, the first check's `found` says: `the lists were refreshed before the probe arrived; start it with the deploy`.

- [ ] **Step 1: Write the failing tests** in `probe.rs`, with `blocked_good() -> BlockerSeen` in which all seven hold:

```rust
fn failing_b(seen: &BlockerSeen) -> Vec<&'static str> { judge_blocker(seen).into_iter().filter(|c| !c.ok).map(|c| c.what).collect() }

#[test] fn a_good_observation_passes_all_seven() {
    assert_eq!(judge_blocker(&blocked_good()).len(), 7);
    assert!(failing_b(&blocked_good()).is_empty());
}
#[test] fn each_blocker_check_fails_on_its_own_evidence() {
    let mut s = blocked_good(); s.at_first.as_mut().unwrap()["list_source"] = "config".into();
    assert_eq!(failing_b(&s), ["the snapshot is in force before any refresh"]);
    let mut s = blocked_good(); s.marker_at_first.as_mut().unwrap().answer.rcode = 3;
    assert_eq!(failing_b(&s), ["the snapshot's marker is blocked"]);
    let mut s = blocked_good(); s.listed_aaaa.as_mut().unwrap().answer.addrs = vec!["2001:db8::1".parse().unwrap()];
    assert_eq!(failing_b(&s), ["a listed name gets :: for AAAA"]);
    let mut s = blocked_good(); s.refreshed.as_mut().unwrap()["list_error"] = "list 1 (lists.example.net): status 404".into();
    assert_eq!(failing_b(&s), ["the lists are refreshed over HTTPS"]);
    let mut s = blocked_good(); s.marker_after = s.marker_at_first.clone();
    assert_eq!(failing_b(&s), ["after the refresh the marker is gone and the listed name is still blocked"]);
    let mut s = blocked_good(); s.refreshed = None;
    assert_eq!(failing_b(&s), ["the lists are refreshed over HTTPS", "blocked queries are counted"]);
}
#[test] fn a_probe_that_came_after_the_refresh_says_so() {
    let mut s = blocked_good(); s.at_first.as_mut().unwrap()["list_source"] = "fetched".into();
    let first = judge_blocker(&s).remove(0);
    assert!(!first.ok && first.found.contains("start it with the deploy"));
}
```

- [ ] **Step 2: Run** `cargo test -p xtask probe::` — expected: compile failure.
- [ ] **Step 3: Implement** the blocker stage; the README row for `probe` names both stages.
- [ ] **Step 4: Run** `cargo test -p xtask` — expected: all pass.
- [ ] **Step 5: Commit** — stage the two files by name; message `"xtask probe: the blocker's checks — snapshot first, then the refresh"`.

---

### Task 15: Milestone 3 on the Pi — "It blocks from the snapshot and refreshes lists over HTTPS."

Run by the session lead with the owner's agreement. The household's DNS is away for about four minutes.

**Files:**
- Create: `docs/bring-up/m3.md`
- Modify: `README.md`

- [ ] **Step 1: Set `./qberrypi.toml`** — `one_shot = true`, `log_to_sd = true`, `return_after_secs = 180`. `git status --short` must not list the file.
- [ ] **Step 2: Renew the snapshot, rebuild, re-run the gates** — `cargo xtask fetch-lists && cargo test --workspace && cargo xtask build && cargo xtask qemu-test` — expected: all pass; seven `ok`; `out/qberrypi/initramfs8` under 6,000,000 bytes.
- [ ] **Step 3: Deploy, and probe from the first second**

```bash
cargo xtask deploy --host <alias> &      # or in a second terminal
cargo xtask probe --stage blocker
wait
```

Expected from `probe`: fifteen `probe: ok:` lines and `probe: 15 of 15 checks hold`. Expected from `deploy`: the collected log, exit status 0.

- [ ] **Step 4: Pi check — the collected log** must contain, in this order: `lists: snapshot: ` with a name count above 250,000 and a `loaded in` figure; `dns: listening on 0.0.0.0:53`; `lists: waiting for the clock`; `clock: set by SNTP from `; one `lists: list N (` line per configured list; `lists: refreshed: ` with a name count above 250,000; `returning`. Between `clock: set by SNTP` and the first `lists: list` line the log's timestamps must be at least 60 s apart. It must not contain: a line with `ERROR`; `lists: refresh failed`; `lists: no snapshot`; the Wi-Fi passphrase; `https://`, which would be a list's URL; or `example.org`, the listed name the probe asked for, or `qberrypi-snapshot.invalid` — no name a client queried may be in the log.
- [ ] **Step 5: Check Raspberry Pi OS came back** — `ssh <alias> 'cmp /boot/firmware/config.txt /boot/firmware/config.pios.txt && pihole status'` — expected: no `cmp` output; Pi-hole listening and blocking.
- [ ] **Step 6: Write `docs/bring-up/m3.md`** — date and build; the fifteen probe lines; the snapshot's name count and the board's `loaded in` figure against the 3 s budget; each list's bytes and milliseconds, and the refresh's total — the cost of TLS without AES instructions; which provider is in the image, `rustls-rustcrypto` or `ring`; the sizes of the executable, `/blocklist.zst` and `initramfs8` against the Budgets table; from the log's timestamps, seconds from init's start to `dns: listening`; anything unexpected. No network name, address, list URL or raw log.
- [ ] **Step 7: Update `README.md`** — status: "Milestone 3 done: it blocks from the snapshot in its image from the first query and refreshes its lists over HTTPS once a day"; the Development section says to run `cargo xtask fetch-lists` before the first `cargo xtask build`. Commit both files — message `"Milestone 3: blocking from the snapshot, lists refreshed over HTTPS, on the Pi"`.

---

## Amendments made during execution

None yet. A decision that changes a task while the plan is carried out is recorded here, as milestone 0's plan does: task, amendment, why.
