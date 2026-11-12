# Version 1 execution order and cross-plan rulings

Six plans build qberrypi version 1. Three are pure crates built in parallel, each in its own worktree;
the three integration plans then run one after another on branch `qbp-v1`, because they change the
same files (`crates/qberrypi/src/init.rs`, `sys.rs`, `xtask/src/build.rs`, `qemu.rs`, `deploy.rs`).

| Order | Plan | Branch |
|---|---|---|
| 1 (parallel) | `2026-11-10-qb-wpa2.md` | `qb-wpa2`, merged into `qbp-v1` |
| 1 (parallel) | `2026-11-10-qb-dns.md` | `qb-dns`, merged into `qbp-v1` |
| 1 (parallel) | `2026-11-10-qb-panel.md` | `qb-panel`, merged into `qbp-v1` |
| 2 | `2026-11-10-m4-m5-resilience-panel.md`, Tasks 1–6 only: panel first light, touch, calibration | `qbp-v1` |
| 3 | `2026-11-10-m1-wifi.md` | `qbp-v1` |
| 4 | `2026-11-10-m2-m3-resolver-blocker.md` | `qbp-v1` |
| 5 | `2026-11-10-m4-m5-resilience-panel.md`, Tasks 7–13 | `qbp-v1` |
| 6 | Cutover: its own short design first | `qbp-v1` |
| 7 | Pi-hole API subset: its own design first | `qbp-v1` |

The panel's first tasks go first because the owner wants to see the panel on the real screen as early
as possible, and they need neither Wi-Fi nor DNS.

## Rulings binding all integration plans

1. **One runtime.** qberrypi has one tokio current-thread runtime, on PID 1's main thread, created by
   milestone 1 (its Task 4). Milestone 2/3 components are futures on it; CPU-heavy work goes to
   `spawn_blocking` with the blocking pool capped at 2 threads. Milestone 4's `supervisor::run` becomes
   the root future on the same runtime. There is no second runtime and no services thread.
2. **Stall detection is the hardware watchdog,** petted from the main runtime; no future may hold the
   runtime thread for more than about 1 second.
3. **`fatal` is safe for several threads** (the release profile aborts on panic, so a panic on a
   blocking-pool thread reaches `fatal`): the first fatal error wins, a second thread's fatal error
   parks, and once a fatal error has begun only its thread pets the watchdog. The earliest plan in
   execution order that introduces a second thread implements it; later plans reuse it.
4. **The panel before milestone 1 runs on its own thread** (milestone 4/5 Task 3); milestone 4/5 Task 7
   moves it under the supervisor with `spawn_blocking`.
5. **Names shared across plans** (the status server's paths and JSON keys, `LogBuf::text`, the panel's
   data traits) are those of the plan that executes first; a later plan that finds a name already built
   reuses it and does not rename it.
6. **Where a plan's own seam section disagrees with this file, this file wins.** The milestone 1 plan's
   "Seams with the other plans" was written before ruling 1 and still describes a services thread, a
   heartbeat and a two-thread `fatal` from the milestone 2/3 plan; those no longer exist.
7. **Thread-safe `fatal` is implemented by milestone 4/5 Task 3** (the first second thread, the panel,
   arrives there); milestone 1 and milestone 2/3 reuse its `fatal_entry`, `may_pet` and `FATAL_THREAD`.
   Milestone 2/3's three extra rules for card access from pool threads stand, and milestone 4/5 Task 7
   keeps them when it rebuilds the runtime.
8. **The blocking pool is capped at 3,** not 2, from the moment milestone 4/5 Task 7 moves the panel onto
   it: one thread is the panel's for good, two remain for fetch, parse and build. Milestone 7 raises the cap
   to 5: two more threads for the API's TLS connections, at most two at a time.
9. **Upstream latency is milestone 2/3's smoothed figure** (exponential, factor 1/8), not milestone
   4/5's median of nine: it is built first, and the panel shows whatever it publishes.
10. **A blocking fetch cannot be cancelled;** it is bounded by its own timeouts (15 s per read, 120 s
    total). Milestone 4's supervisor must not start a new lists component while the previous one's
    fetch is still running.
11. **Single-label names (qb-dns final review I1):** only A and AAAA queries for a single-label name are
    answered locally (NXDOMAIN; `localhost` as before); every other type is forwarded, so DNSSEC
    validation of top-level domains keeps working. The spec's DNS section is amended to match.
12. **List downloads are capped by the caller:** `qb-dns`'s block set has no size cap of its own, so the
    milestone 2/3 fetcher's 32 MiB cap per list is the bound; it must stay.
13. **End-to-end DNS tests in milestone 2/3 cover** a validating client (DS and DNSKEY through the
    resolver) and a hostile upstream (wrong ID, wrong source address), as the qb-dns final review asks.
14. **Publishing `qbp-v1`:** commit f56a2e6 (the qb-wpa2 plan as first written) holds frame bytes,
    addresses and keys taken from third-party captures; the document is scrubbed at the tip, but the
    commit remains in history. `qbp-v1` and the crate branches are therefore never pushed as they are:
    version 1 reaches `main` on GitHub as a squash merge (or after the history is rewritten to drop those
    bytes), and the owner is asked before either.
15. **The screen is flipped 180 degrees** at the owner's request: `rotate=270`, not `rotate=90`, in
    qberrypi's `config.txt` and in Raspberry Pi OS's. Touch axes are not flipped by the overlay; the
    four-corner calibration supplies the inversion. Plans written before this ruling that say
    `rotate=90` follow this ruling.
16. **Owner's answers on cutover and the API (2026-11-10):** the card reader is the only way back to
    Raspberry Pi OS (no long-press, no network return); qberrypi serves a new certificate of its own and
    the owner re-pins qnet once; per-query and per-device status pages need the API login; the IPv6
    bypass is accepted (IPv6 stays on); no plain-HTTP API.
17. **Latency must not be worse than stock (owner, 2026-11-10).** Baseline and acceptance are in
    `docs/bring-up/latency-baseline.md`. Three changes follow: milestone 1's boot integration sets the
    CPU frequency governor to `performance` (`cpufreq-dt` and the governor are built into the pinned
    kernel; one write to `/sys/devices/system/cpu/cpufreq/policy0/scaling_governor`, logged, a failure
    a WARN); milestone 2/3 adds `cargo xtask latency --host <alias>` in Rust (ICMP through the system
    `ping`, DNS through its own client; cached, blocked and forwarded rows; forwarded names vary the
    zone and the label; p50, p95, min, mean, lost) and runs it in its Pi checks against the baseline;
    milestone 2/3's upstream exchange sends each forwarded question to every configured upstream at
    once and takes the first answer that passes the ID, source and question checks (the others are
    read and dropped), replacing sequential failover for UDP.
    **Amended 2026-11-11 by the session lead** (the owner's rule is the latency goal; the full race was
    the means): the full race doubled the queries to Quad9 and lost more answers than stock in a
    2 ms-paced burst, so the exchange is now **hedged**: the preferred upstream is asked alone, the
    others after clamp(2 × smoothed latency, 20 ms, 250 ms) or at once when the preferred's leg fails
    or refuses, with one resend of every open leg at 700 ms. The latency tool counts a lost, SERVFAIL
    or REFUSED answer as 2 s. Details: `docs/bring-up/latency-baseline.md` ("qberrypi's upstream
    exchange since 2026-11-11") and rulings 5–11 and 14 of the latency follow-up ledger. Do not
    restore the full race without a measurement that beats the hedge on the acceptance rule.
