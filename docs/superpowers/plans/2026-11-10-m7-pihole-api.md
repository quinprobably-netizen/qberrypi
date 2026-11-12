# Milestone 7 (Pi-hole API subset) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** qnet, pointed at qberrypi's address on port 443 with its pin renewed once to qberrypi's own certificate and the same app password, reads the statistics, the 24-hour history and the upstreams, and pauses and resumes blocking, with no change to qnet's code. The household's queries and devices are served only behind the same login.

**Architecture:** A new `api` component listens on port 443. Each accepted connection is one blocking job, at most two at a time. The job runs a `rustls` handshake with the `rustls-rustcrypto` provider and qberrypi's own certificate, which `cargo xtask make-cert` makes once on the PC and `deploy` stages onto the card, then answers up to 100 HTTP/1.1 requests. A pure router answers each request from a small `Facts` trait over the resolver, the upstreams and the client table. Logins check a PBKDF2 hash from `qberrypi.toml` and open in-memory sessions, carried in `X-FTL-SID`, behind per-address and overall rate limits. `qb-dns` gains ten-minute history buckets, so that "the last 24 hours" means what it does on Pi-hole.

**Tech Stack:** Rust stable, edition 2024. New in `crates/qberrypi`: `pbkdf2` and `sha2` (RustCrypto, pure Rust), `rustls-pki-types` with its PEM parser; already there: `rustls` 0.23, `rustls-rustcrypto`, `httparse`, `serde_json`. Tests only: `rcgen` 0.14 (already), `rustls` with `ring` (the provider qnet's client uses). New in `xtask` (the PC only): `rcgen` 0.14 and `sha2`.

**Spec:** `docs/superpowers/specs/2026-11-10-qberrypi-cutover-and-api.md`, part 2 (its endpoint table is the contract), with `docs/superpowers/specs/2026-11-10-qberrypi-design.md` (Status, Configuration, DNS). Pi-hole's own shapes: FTL's OpenAPI files `src/api/docs/content/specs/{auth,stats,history,dns}.yaml` in `github.com/pi-hole/FTL`.

**Starts when:** milestones 1–6 are merged into `qbp-v1`. Rulings 1–16 of `docs/superpowers/plans/2026-11-10-execution-order.md` bind this plan (ruling 16: the owner's answers it follows), and Task 8 amends ruling 8. Names not defined here are from the Interfaces blocks of the milestone 1, 2/3, 4/5 and 6 plans and of `2026-11-10-qb-dns.md`; by ruling 5 a name already built stands.

## Global Constraints

- `unsafe` only in `crates/qberrypi/src/sys.rs`; `qb-dns` keeps `#![forbid(unsafe_code)]`.
- No secret in a log line, an error message, `Debug` output, `/log`, any JSON or a committed file. Secrets here are the password, the password hash, every session id, the TLS key (`qberrypi-tls.pem`) and the request bodies of `/api/auth`. Types that hold them print `<redacted>` in `Debug`. Error texts name the key or the file, never its content. `qberrypi-tls.pem` is git-ignored, created with mode 0600, and never copied into `out/`. The repository is public: examples use `192.0.2.0/24`, `198.51.100.0/24` and `example.com`; no real address, name, certificate fingerprint or password is committed. Test certificates are generated at test time.
- Per-query and per-device data (`/api/v1/queries`, `/api/v1/clients`) is served only on port 443 behind a session. No log line names a client address, since `/log` is open.
- The API is served on port 443 with TLS only. Port 80's status page is not changed by this plan.
- Every endpoint but `POST /api/auth` needs a valid session, and a request without one changes nothing.
- One executable, all Rust: `cargo tree -p qberrypi --target aarch64-unknown-linux-musl -e normal,build --prefix none | grep -E '^(ring|aws-lc-sys|cc|zstd-sys|openssl-sys) '` prints nothing. `ring` appears only as a dev-dependency (to test against the client qnet uses), and through `rcgen` in `xtask`, which runs on the PC.
- One runtime (ruling 1). On its thread nothing holds for more than about 50 ms: a TLS connection, from handshake to close, and every password check run through `services::blocking`. The blocking pool grows to 5 threads in Task 8 and no further.
- The card: this plan adds no write by qberrypi. `deploy` stages the certificate as `tls.pem`, and the card gets it with the build's read-back check. init reads `qberrypi/tls.pem` in the same read-only mount as `qberrypi.toml`.
- Spec values: sessions last 1,800 s from their last use; at most 16; sids are 16 random bytes as 32 lowercase hex digits; 5 failed logins from one address within 60 s, or 30 overall, hold logins back for 60 s; PBKDF2-HMAC-SHA256, 100,000 rounds, 16-byte salt, 32-byte hash; at most 2 connections, 5 s for a handshake, 5 s idle, 100 requests and 60 s per connection; request head 8 KiB, body 4 KiB; a pause is 1 to 86,400 s; history is 144 buckets of 600 s labelled by their centre; the certificate is ECDSA P-256, self-signed, valid to 9999-12-31.
- Implementers never reach the Pi. Pi steps are the session lead's, with the owner, on a build that has passed `qemu-test`.
- Clean before every commit, with no warnings: `cargo test --workspace`, `cargo clippy --workspace --all-targets`, `cargo fmt --all --check`, `cargo build -p qberrypi --release --target aarch64-unknown-linux-musl`. A task that touches `init.rs`, `services.rs`, `bootpart.rs` or `xtask/` also runs `cargo xtask build && cargo xtask qemu-test`. Dependencies are added with `cargo add`.
- Git: stage files by name (never `git add -A` or `git add .`). Every commit message ends with a `Co-Authored-By:` trailer naming the model that wrote the commit, for example `Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>`. Never push.

## Review Focus

1. A device on the network guesses passwords, from one address or from many: one address is held back after 5 failures in a minute, everyone after 30, the right password is not even checked while held back, and the owner's address is not held back by another's failures. (Tests in Tasks 5 and 7.)
2. A client opens port 443 and says nothing, stalls mid-handshake, sends an endless head or a huge body, or keeps a connection alive for ever: it is closed within its limits, a third client is served once a place is free, DNS answers meanwhile, and no more than two pool threads are ever the API's. (Tests in Tasks 6 and 8.)
3. A request on any endpoint without a session, with an expired one, with a sid one character off, or with a sid carried in a cookie or the query string: 401 and nothing changes. Above all, `POST /api/dns/blocking` pauses nothing, and `/api/v1/queries` and `/api/v1/clients` show nothing. (Tests in Tasks 5 and 7.)
4. The wall clock steps from the image's build time to the real time, or back, with queries on both sides: the summary and the history cover only the 24 hours before the current time, with no panic and no negative or wrapped count. (Tests in Task 1.)
5. Bodies that are not what qnet sends: `blocking` as a string, `timer` negative, zero, fractional, huge or null on a pause, extra fields, invalid JSON, no body: Pi-hole's error shape with 400, and nothing changed. A fractional timer rounds up. (Tests in Task 7.)

## Decisions the spec leaves open

| Subject | Decision | Task |
|---|---|---|
| Where the history lives | In `qb-dns`'s `Stats`, because only `Resolver::handle_query` knows each query's outcome. It is a ring of 144 buckets keyed by `unix_secs / 600`. A slot that holds any other bucket is reset to the record's bucket, because `record` runs at the current time, so a slot holding a later bucket holds counts from the clock's future, which no window ending at now shows. | 1 |
| Per-upstream counts | Answers since boot, per server, kept by `Upstreams`; the 24-hour figures are the history's. | 2 |
| Hash format | `$pbkdf2-sha256$i=<rounds>$<32 hex salt>$<64 hex hash>`. Rounds of 10,000 to 10,000,000 are read, so a later change of `ROUNDS` keeps old lines valid; new lines use 100,000. | 3 |
| `hash-password` input | Standard input only, refused when it is a terminal; one trailing `\n` or `\r\n` is dropped; empty is refused; salt from `/dev/urandom`. | 3 |
| Certificate file | `qberrypi-tls.pem` in the repository root beside `qberrypi.toml`: the PKCS#8 key, then the certificate. Subject CN and a DNS name are `hostname`, plus an IP name of `net.address`; not before an hour before it was made, not after 9999-12-31 23:59:59 UTC; serial random. | 4 |
| The pin's text | The SHA-256 of the certificate's DER as upper-case hex pairs joined by colons, the form qnet writes and accepts. | 4 |
| A broken certificate | The `api` component ends `Absent` with the reason; DNS is untouched. No `[api]` section: the component is not added at all, so no line is logged. | 4, 8 |
| Session table full | The least recently used session is ended to make room. | 5 |
| Verifying | One verification at a time (a `Mutex<()>` held around `verify`), on the connection's own pool thread. | 7 |
| `took` | The seconds `handle` spent, as a JSON number. | 7 |
| Query strings | `n` on `/api/v1/queries` only; any other `?` in an API path is 404 after the session check. | 7 |
| Keep-alive | Honoured unless the request is HTTP/1.0 or says `Connection: close`; after a 400 or 413 the connection closes. | 6 |

## File Structure

```
crates/qb-dns/src/stats.rs         + HistoryBucket, Stats::history, Stats::last_24h
crates/qb-dns/src/lib.rs           + re-export HistoryBucket
crates/qberrypi/src/
  dns/upstream.rs                  + ServerStats, Upstreams::servers
  config.rs                        + [api] password_hash
  bootpart.rs                      + read_tls
  init.rs                          + read tls.pem with the configuration; the api component
  services.rs                      BLOCKING_THREADS 3 -> 5
  api/mod.rs                       the component: listener, connections
  api/password.rs                  PasswordHash
  api/tls.rs                       ServerConfig from tls.pem
  api/session.rs                   Sessions, Limiter
  api/http.rs                      read_request, write_reply
  api/routes.rs                    Facts, Api::handle
  api/live.rs                      LiveFacts over Dns and the lists
xtask/src/
  hashpw.rs                        cargo xtask hash-password
  cert.rs                          cargo xtask make-cert
  deploy.rs                        stage tls.pem when [api] is set; print the pin
  qemu.rs                          [api] and a generated tls.pem in the DNS scenario
  main.rs                          + hash-password, make-cert
.gitignore, qberrypi.example.toml, README.md, docs/superpowers/specs/2026-11-10-qberrypi-design.md,
docs/superpowers/plans/2026-11-10-execution-order.md (ruling 8)                      modify
docs/bring-up/m7.md                                                                   new
```

---

### Task 1: Ten-minute history in `qb-dns`

**Files:**
- Modify: `crates/qb-dns/src/stats.rs`, `crates/qb-dns/src/lib.rs`

**Interfaces:**
- Consumes: `Stats::record(name, qtype, outcome, now)`, `Counts` and its private `count(outcome)`, `Now`.
- Produces:

```rust
pub const BUCKET_SECS: u64 = 600;
pub const HISTORY_BUCKETS: usize = 144;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HistoryBucket { pub start_unix: u64, pub counts: Counts }
impl Stats {
    /// Exactly HISTORY_BUCKETS buckets, oldest first; the last is the one holding now.unix_secs. Empty ones are zero.
    pub fn history(&self, now: Now) -> Vec<HistoryBucket>;
    /// The sum of `history(now)`.
    pub fn last_24h(&self, now: Now) -> Counts;
}
```

`record` also counts into slot `(unix_secs / 600) % 144`. A slot holding any other bucket is reset to the record's bucket first, because `record` runs at the current time, so a slot holding a later bucket holds counts from the clock's future, which no window ending at now shows. Memory: 144 × (8 + 32) bytes. The doc comment of `Resolver` gains this line in its memory list.

- [ ] **Step 1: Write the failing tests** in `stats.rs` (`at(unix)` is a `Now` with `mono_secs` 1 and that `unix_secs`; `T = 1_800_000_000`, a multiple of 600):

```rust
#[test] fn buckets_are_ten_minutes_oldest_first_and_end_with_the_current_one() {
    let mut s = Stats::new(16, 16);
    s.record("a.example.com", 1, Outcome::Forwarded, at(T + 5));
    s.record("b.example.com", 1, Outcome::Blocked, at(T + 599));
    s.record("c.example.com", 1, Outcome::Cached, at(T + 600));
    let h = s.history(at(T + 700));
    assert_eq!(h.len(), HISTORY_BUCKETS);
    assert_eq!((h[143].start_unix, h[142].start_unix, h[0].start_unix), (T + 600, T, T + 600 - 143 * 600));
    assert_eq!(h[142].counts, Counts { queries: 2, blocked: 1, cache_hits: 0, forwarded: 1 });
    assert_eq!(h[143].counts, Counts { queries: 1, blocked: 0, cache_hits: 1, forwarded: 0 });
    assert_eq!(s.last_24h(at(T + 700)), Counts { queries: 3, blocked: 1, cache_hits: 1, forwarded: 1 });
}
#[test] fn a_bucket_leaves_the_window_after_144_more() {
    let mut s = Stats::new(16, 16);
    s.record("a.example.com", 1, Outcome::Forwarded, at(T));
    assert_eq!(s.last_24h(at(T + 143 * 600)).queries, 1);
    assert_eq!(s.last_24h(at(T + 144 * 600)).queries, 0);
}
#[test] fn the_clock_stepping_forward_or_back_never_counts_outside_the_window() {   // Review Focus 4
    let mut s = Stats::new(16, 16);
    s.record("a.example.com", 1, Outcome::Forwarded, at(T));               // at the build time
    let later = T + 365 * 86_400;                                         // SNTP stepped the clock a year on
    s.record("b.example.com", 1, Outcome::Forwarded, at(later));
    assert_eq!(s.last_24h(at(later)).queries, 1);
    s.record("c.example.com", 1, Outcome::Forwarded, at(later - 3_600));  // and back an hour
    assert_eq!(s.last_24h(at(later)).queries, 2);
    assert_eq!(s.last_24h(at(later - 7_200)).queries, 0);                  // asked from before them all: nothing from its future
    assert_eq!(s.history(at(0)).len(), HISTORY_BUCKETS);                   // a clock near zero does not underflow
}
```

- [ ] **Step 2: Run** `cargo test -p qb-dns stats` — expected: compile failure.
- [ ] **Step 3: Implement**; re-export `HistoryBucket` from `lib.rs`.
- [ ] **Step 4: Run** the four checks — expected: all pass; `qb-dns`'s fuzz and budget tests unchanged.
- [ ] **Step 5: Commit** — `git add crates/qb-dns/src/stats.rs crates/qb-dns/src/lib.rs`, message `"qb-dns: 24 hours of ten-minute buckets, for the Pi-hole API's history and summary"`.

---

### Task 2: Per-upstream figures

**Files:**
- Modify: `crates/qberrypi/src/dns/upstream.rs`

**Interfaces:**
- Consumes: `Upstreams` and its private `smoothed`, `FakeUpstream`, `run` (the test helper of milestone 2/3 Task 3).
- Produces:

```rust
#[derive(Debug, Clone, PartialEq)]
pub struct ServerStats { pub addr: SocketAddr, pub answered: u64, pub latency_ms: Option<f32> }
impl Upstreams { pub fn servers(&self) -> Vec<ServerStats>; }     // in the configuration's order
```

Each accepted answer adds one to that server's `answered` and moves its own `latency_ms` by `smoothed`; the overall `latency_ms()` stays as it is.

- [ ] **Step 1: Write the failing test** in `upstream.rs`:

```rust
#[tokio::test] async fn each_server_counts_its_own_answers_and_round_trips() {
    let dead = FakeUpstream::start(Reply::Silent).await;
    let live = FakeUpstream::start(Reply::Answer(ip("192.0.2.10"))).await;
    let ups = Upstreams::with(vec![dead.addr, live.addr], ms(150), ms(300));
    run(&ups, "example.com").await;
    run(&ups, "example.org").await;
    let s = ups.servers();
    assert_eq!((s[0].addr, s[0].answered, s[0].latency_ms), (dead.addr, 0, None));
    assert_eq!((s[1].addr, s[1].answered), (live.addr, 2));
    assert!(s[1].latency_ms.is_some_and(|ms| ms < 150.0));
}
```

- [ ] **Step 2: Run** `cargo test -p qberrypi upstream` — expected: compile failure.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the four checks — expected: all pass.
- [ ] **Step 5: Commit** — `git add crates/qberrypi/src/dns/upstream.rs`, message `"dns: answers and round trip per upstream"`.

---

### Task 3: The password: `[api]`, its hash and `cargo xtask hash-password`

**Files:**
- Create: `crates/qberrypi/src/api/mod.rs` (module list only), `crates/qberrypi/src/api/password.rs`, `xtask/src/hashpw.rs`
- Modify: `crates/qberrypi/src/config.rs`, `crates/qberrypi/src/lib.rs`, `crates/qberrypi/Cargo.toml`, `Cargo.lock`, `xtask/src/main.rs`, `qberrypi.example.toml`

**Interfaces:**
- Consumes: `config::{parse, ConfigError}` and its section reader.
- Produces:

```rust
// api/password.rs
pub const ROUNDS: u32 = 100_000;
pub struct PasswordHash { /* rounds, salt [u8; 16], hash [u8; 32] */ }   // Debug: "<redacted>"
impl PasswordHash {
    pub fn new(password: &[u8], salt: [u8; 16]) -> Self;      // ROUNDS
    pub fn parse(text: &str) -> Option<Self>;
    pub fn to_text(&self) -> String;                            // "$pbkdf2-sha256$i=100000$<salt hex>$<hash hex>"
    pub fn verify(&self, password: &[u8]) -> bool;              // derives with the stored rounds and salt; constant-time compare
}
pub(crate) fn derive(password: &[u8], salt: &[u8], rounds: u32) -> [u8; 32];   // PBKDF2-HMAC-SHA256
// config.rs
pub struct Api { pub password_hash: PasswordHash }
// Config gains: pub api: Option<Api>       — section [api], key password_hash
// xtask/src/hashpw.rs
pub fn hash_line(password: &[u8], salt: [u8; 16]) -> anyhow::Result<String>;   // `password_hash = "..."`; Err for an empty password
pub fn run() -> anyhow::Result<()>;
```

Config errors, by key: `api.password_hash` — `"must be the line that cargo xtask hash-password prints"`; any other key in `[api]` — the parser's usual unknown-key error. `run`: if standard input is a terminal (`std::io::IsTerminal`), fail with `"pipe the password in (for example from the keyring that holds it); it is not read from a terminal, so it is never shown"`. Otherwise read it all, drop one trailing `\n` or `\r\n`, take 16 bytes from `/dev/urandom`, and print `hash_line`; on standard error print `put this line under [api] in qberrypi.toml`. `qberrypi.example.toml` gains a commented `[api]` section with a `password_hash` made from the password `example` and an all-zero salt, and lines saying how to make a real one and that `cargo xtask make-cert` must have been run.

- [ ] **Step 1: Add the dependencies** — `cargo add -p qberrypi pbkdf2 --no-default-features -F hmac` and `cargo add -p qberrypi sha2 --no-default-features`, at the versions the workspace already resolves for `qb-wpa2`'s `pbkdf2` where they agree.
- [ ] **Step 2: Write the failing tests.** `password.rs`:

```rust
#[test] fn the_derivation_is_pbkdf2_hmac_sha256() {
    // RFC 7914 section 11: P "passwd", S "salt", c 1; the first 32 bytes of its 64
    assert_eq!(hex(&derive(b"passwd", b"salt", 1)), "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc");
}
#[test] fn a_hash_round_trips_through_its_text_and_checks_only_its_password() {
    let h = PasswordHash::new(b"correct horse", [7; 16]);
    let text = h.to_text();
    assert!(text.starts_with("$pbkdf2-sha256$i=100000$07070707070707070707070707070707$") && text.len() == 15 + 9 + 32 + 1 + 64);
    let back = PasswordHash::parse(&text).unwrap();
    assert!(back.verify(b"correct horse") && !back.verify(b"correct horsf") && !back.verify(b""));
    assert_eq!(format!("{back:?}"), "<redacted>");
}
#[test] fn only_the_one_shape_parses() {
    let good = PasswordHash::new(b"x", [0; 16]).to_text();
    for bad in ["", "$pbkdf2-sha256$i=100000$00$00", &good.replace("sha256", "sha1"), &good.replace("i=100000", "i=9999"),
                &good.replace("i=100000", "i=10000001"), &good.to_uppercase(), &format!("{good}0"), &good[1..]] {
        assert!(PasswordHash::parse(bad).is_none(), "{bad}");
    }
    assert!(PasswordHash::parse(&good.replace("i=100000", "i=10000")).is_some());
}
```

`config.rs`: the example without `[api]` parses with `api` `None`; with `[api]` and a good line, `Some`; with `password_hash = "nope"`, the error's key is `api.password_hash` and its text does not contain `nope`; the `Debug` of a parsed `Config` does not contain the hash's hex.

`hashpw.rs`: `hash_line(b"example", [0; 16])` is `password_hash = "` + `PasswordHash::new(b"example", [0; 16]).to_text()` + `"`, and that text parses; `hash_line(b"", ..)` is an error. The example file's `[api]` line (uncommented in the test) equals `hash_line(b"example", [0; 16])`.

- [ ] **Step 3: Run** `cargo test -p qberrypi -- api:: config:: && cargo test -p xtask hashpw` — expected: compile failure.
- [ ] **Step 4: Implement.** `verify` compares with a loop that ORs the XOR of every byte, as `qb-wpa2` compares MICs, or with that crate's helper if it exports one.
- [ ] **Step 5: Run** the four checks — expected: all pass.
- [ ] **Step 6: Commit** — the files above by name, message `"api: [api] password_hash, PBKDF2-SHA256, and cargo xtask hash-password"`.

---

### Task 4: The certificate — made once on the PC, staged by `deploy`, read by init, loaded by `rustls`

**Files:**
- Create: `crates/qberrypi/src/api/tls.rs`, `xtask/src/cert.rs`
- Modify: `crates/qberrypi/src/bootpart.rs`, `crates/qberrypi/src/init.rs`, `crates/qberrypi/Cargo.toml`, `Cargo.lock`, `xtask/src/deploy.rs`, `xtask/src/main.rs`, `xtask/Cargo.toml`, `.gitignore`

**Interfaces:**
- Consumes: `bootpart::{OWN_DIR, read_config_text}`, init's `load_config`, `with_card`, `FakeCard`; `rustls_rustcrypto::provider()` as milestone 3's `https.rs` builds it; deploy's `staged_checksums`, `private_temp_dir`, `upload`, `NOT_THE_BUILDS`, `write_private_new`; `qberrypi::config::parse` (`hostname`, `net.address`, `api`).
- Produces:

```rust
// bootpart.rs
pub const TLS_FILE: &str = "tls.pem";
pub const TLS_FILE_CAP: u64 = 16 * 1024;
pub fn read_tls(boot: &Path) -> io::Result<Option<Vec<u8>>>;    // None when absent; an error when larger than the cap
// init.rs: load_config reads both files in its one read-only mount and keeps the PEM in
//   static TLS_PEM: OnceLock<Option<Vec<u8>>>; a read error is logged as
//   `tls.pem: {error}; the API will stay off` and stored as None
// api/tls.rs
pub fn server_config(pem: &[u8]) -> Result<Arc<rustls::ServerConfig>, String>;
pub fn leaf_sha256(pem: &[u8]) -> Option<[u8; 32]>;              // of the first certificate's DER
pub fn pin_text(digest: &[u8; 32]) -> String;                    // "AB:CD:…", 95 characters
// xtask/src/cert.rs
pub const CERT_FILE: &str = "qberrypi-tls.pem";
pub fn make(hostname: &str, address: Ipv4Addr, now_unix: u64) -> anyhow::Result<String>;   // key PEM then certificate PEM
pub fn run(replace: bool, root: &Path) -> anyhow::Result<()>;
```

`server_config`: the certificates in file order (`CertificateDer::pem_slice_iter`) and the one private key (`PrivateKeyDer::from_pem_slice`). The provider is `rustls-rustcrypto`, with TLS 1.2 and 1.3, no client authentication, and the default session cache. It checks that the key fits the first certificate, with rustls's own check where the version has one, or by signing and verifying a fixed message. Errors: `"tls.pem holds no certificate"`, `"tls.pem holds no private key"`, `"tls.pem's key does not fit its first certificate"`, or `"tls.pem: {rustls error}"`. None quotes the file.

`make`: `rcgen` with `PKCS_ECDSA_P256_SHA256`; distinguished name CN `hostname`; subject alternative names DNS `hostname` and IP `address`; not before `now_unix − 3600`, not after 9999-12-31 23:59:59 UTC; a random serial; self-signed. `run`: reads `hostname` and `net.address` from `<root>/qberrypi.toml`. If `<root>/qberrypi-tls.pem` exists and `replace` is false, it fails with `"qberrypi-tls.pem exists; --replace makes a new one, and qnet must then be pinned again"`. Otherwise it writes the file with deploy's `write_private_new` (made `pub(crate)`; mode 0600, refusing a link) through a temporary name and a rename, then prints `make-cert: wrote qberrypi-tls.pem; pin qnet to this certificate (SHA-256): {pin_text}`. With `replace`, it also prints `make-cert: the old certificate is no longer used: qnet must be pinned again`. Command: `cargo xtask make-cert [--replace]`. `.gitignore` gains `/qberrypi-tls.pem`.

`deploy`: when the local `qberrypi.toml` parses with `api` set, it reads `<root>/qberrypi-tls.pem`. A missing file is an error, `"qberrypi.toml has [api] but there is no qberrypi-tls.pem: run cargo xtask make-cert"`. A file `server_config` refuses is an error with its reason. It then writes a copy named `tls.pem` into the private scratch directory beside the staged `SHA256SUMS`, adds `tls.pem` to the staged checksums the way `qberrypi.toml` is added, and uploads it with the other files. The script copies and verifies it like any staged file, and the stage is removed however the script ends. Before installing, `deploy` prints `deploy: {host}: the API's certificate pin (SHA-256): {pin_text}`. `tls.pem` joins `NOT_THE_BUILDS`.

- [ ] **Step 1: Add the dependencies** — `cargo add -p qberrypi rustls-pki-types -F std` (its PEM parser); `cargo add -p xtask rcgen@0.14 sha2`.
- [ ] **Step 2: Write the failing tests.** `tls.rs`, with `pair() -> (String /* cert PEM */, String /* PKCS#8 key PEM */)` from `rcgen` with `PKCS_ECDSA_P256_SHA256`:

```rust
#[test] fn a_key_and_its_certificate_load_and_give_their_pin() {
    let (cert, key) = pair();
    let pem = format!("{key}{cert}");
    assert!(server_config(pem.as_bytes()).is_ok());
    let digest = leaf_sha256(pem.as_bytes()).unwrap();
    let text = pin_text(&digest);
    assert_eq!((text.len(), text.matches(':').count()), (95, 31));
    assert_eq!(text, text.to_uppercase());
}
#[test] fn a_file_that_cannot_serve_says_why_without_quoting_itself() {
    let (cert, key) = pair();
    let (other_cert, _) = pair();
    for (pem, why) in [(cert.clone(), "no private key"), (key.clone(), "no certificate"),
                       (format!("{key}{other_cert}"), "does not fit"), ("garbage".to_owned(), "no certificate")] {
        let error = server_config(pem.as_bytes()).unwrap_err();
        assert!(error.contains(why) && !error.contains("BEGIN") && !error.contains("PRIVATE"), "{error}");
    }
}
```

`cert.rs`:

```rust
#[test] fn the_made_certificate_serves_names_the_pi_and_does_not_expire() {
    let pem = make("qberrypi", Ipv4Addr::new(192, 0, 2, 53), 1_800_000_000).unwrap();
    assert!(qberrypi::api::tls::server_config(pem.as_bytes()).is_ok());
    // parse the certificate (x509-parser through rcgen's dev tools, or rustls-pki-types and a DER walk):
    // CN "qberrypi", SANs DNS "qberrypi" and IP 192.0.2.53, not before 1_799_996_400, not after 9999-12-31T23:59:59Z, ECDSA P-256
}
#[test] fn an_existing_certificate_is_kept_unless_replace_is_asked() {
    // a temporary root with the example qberrypi.toml: run(false) writes qberrypi-tls.pem with mode 0600;
    // a second run(false) fails naming --replace and leaves the bytes unchanged; run(true) changes them
}
```

`bootpart.rs`: `read_tls` on a directory without the file is `Ok(None)`; with a 20-byte file, `Ok(Some(..))`; with a file of `TLS_FILE_CAP + 1` bytes, `Err`. `init.rs`: `load_config` over a `FakeCard` holding `qberrypi/tls.pem` leaves `TLS_PEM` holding it, and the card's ops are one read-only mount and one unmount, as before.

`deploy.rs`:

```rust
#[test] fn an_api_configuration_stages_the_certificate_and_none_does_not() {
    // with the deploy tests' fake runner: [api] set and qberrypi-tls.pem present: the upload lists a file named tls.pem
    // whose bytes equal qberrypi-tls.pem, the staged SHA256SUMS has a line for tls.pem, and the output has
    // "the API's certificate pin (SHA-256): " followed by 95 characters; [api] set and no file: an error naming make-cert,
    // and nothing was run on the Pi; no [api]: no tls.pem staged, no pin line
}
```

- [ ] **Step 3: Run** `cargo test -p qberrypi -- api::tls bootpart:: init:: && cargo test -p xtask -- cert deploy` — expected: failures.
- [ ] **Step 4: Implement.**
- [ ] **Step 5: Run** the four checks, then `cargo xtask build && cargo xtask qemu-test` — expected: all pass; `git status` does not show `qberrypi-tls.pem` after a `make-cert`.
- [ ] **Step 6: Commit** — the files above by name, message `"api: qberrypi's own certificate, made once by xtask, staged by deploy, served by rustls"`.

---

### Task 5: Sessions and the login limit

**Files:**
- Create: `crates/qberrypi/src/api/session.rs`

**Interfaces:**
- Produces:

```rust
pub const SESSION_SECS: u64 = 1_800;
pub const MAX_SESSIONS: usize = 16;
pub const FAILURES_PER_ADDRESS: usize = 5;
pub const FAILURES_OVERALL: usize = 30;
pub const FAILURE_WINDOW_SECS: u64 = 60;
pub const HOLD_BACK_SECS: u64 = 60;
pub const MAX_ADDRESSES: usize = 64;
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum HoldBack { None, ThisAddress, Everyone }
#[derive(Default)] pub struct Sessions { /* private; Debug shows only the count */ }
impl Sessions {
    pub fn open(&mut self, random: [u8; 16], mono_secs: u64) -> String;     // the sid; ends the least recently used at MAX_SESSIONS
    pub fn touch(&mut self, sid: &str, mono_secs: u64) -> Option<u64>;      // valid: extends to SESSION_SECS, returns it
    pub fn close(&mut self, sid: &str, mono_secs: u64) -> bool;             // only a valid session is closed
    pub fn len(&self) -> usize;
}
#[derive(Default)] pub struct Limiter { /* private */ }
impl Limiter {
    pub fn allowed(&self, addr: Ipv4Addr, mono_secs: u64) -> bool;
    pub fn failed(&mut self, addr: Ipv4Addr, mono_secs: u64) -> HoldBack;  // which hold-back this failure starts, if any
    pub fn succeeded(&mut self, addr: Ipv4Addr);
}
```

A sid is the 16 bytes as 32 lowercase hex digits. `touch` and `close` compare the given text with every stored sid in constant time, all 16 compared whatever matches, and anything not 32 hex digits is no session. A session expires `SESSION_SECS` after its last `touch` or `open`; one exactly that old is expired. Per address, a hold-back starts at the `FAILURES_PER_ADDRESS`-th failure within `FAILURE_WINDOW_SECS` and lasts `HOLD_BACK_SECS` from it. Overall, the same with `FAILURES_OVERALL` holds every address back. The table keeps `MAX_ADDRESSES` addresses, dropping the one whose last failure is oldest.

- [ ] **Step 1: Write the failing tests** in `session.rs`:

```rust
#[test] fn a_session_lasts_thirty_minutes_from_its_last_use() {
    let mut s = Sessions::default();
    let sid = s.open([0xab; 16], 100);
    assert_eq!(sid, "ab".repeat(16));
    assert_eq!(s.touch(&sid, 1_000), Some(1_800));
    assert_eq!(s.touch(&sid, 2_799), Some(1_800));
    assert_eq!(s.touch(&sid, 2_799 + 1_800), None);
}
#[test] fn only_the_exact_sid_opens_the_session() {                      // Review Focus 3
    let mut s = Sessions::default();
    let sid = s.open([1; 16], 0);
    for wrong in [&sid[..31], &format!("{sid}0"), &sid.to_uppercase(), &sid.replace("01", "02"), "", "sid=x"] {
        assert_eq!(s.touch(wrong, 1), None, "{wrong}");
    }
    assert!(s.close(&sid, 1) && s.touch(&sid, 2).is_none() && !s.close(&sid, 3));
}
#[test] fn the_seventeenth_login_ends_the_least_recently_used() {
    let mut s = Sessions::default();
    let sids: Vec<String> = (0..16u8).map(|n| s.open([n; 16], u64::from(n))).collect();
    s.touch(&sids[0], 20);                                                // the oldest is used again
    s.open([99; 16], 21);
    assert_eq!(s.len(), MAX_SESSIONS);
    assert!(s.touch(&sids[0], 22).is_some() && s.touch(&sids[1], 22).is_none());
}
#[test] fn five_failures_in_a_minute_hold_that_address_back_and_no_other() {   // Review Focus 1
    let (a, b) = (Ipv4Addr::new(192, 0, 2, 7), Ipv4Addr::new(192, 0, 2, 8));
    let mut l = Limiter::default();
    for t in 0..4 { assert_eq!(l.failed(a, t), HoldBack::None); }
    assert_eq!(l.failed(a, 10), HoldBack::ThisAddress);
    assert!(!l.allowed(a, 11) && l.allowed(b, 11));
    assert!(!l.allowed(a, 69) && l.allowed(a, 70));
    let mut l = Limiter::default();
    for t in [0, 61, 122, 183, 244] { l.failed(a, t); }                   // a minute apart: never five in one window
    assert!(l.allowed(a, 245));
    l.failed(a, 300); l.succeeded(a);
    assert!(l.allowed(a, 301));
}
#[test] fn thirty_failures_from_anywhere_hold_everyone_back() {           // Review Focus 1
    let mut l = Limiter::default();
    let starts: Vec<HoldBack> = (0..30u32).map(|n| l.failed(Ipv4Addr::from(0xc633_6400 + n), 5)).collect();   // 198.51.100.n
    assert_eq!(starts.last(), Some(&HoldBack::Everyone));
    assert!(!l.allowed(Ipv4Addr::new(192, 0, 2, 7), 6) && l.allowed(Ipv4Addr::new(192, 0, 2, 7), 65));
}
#[test] fn a_sweep_of_addresses_keeps_the_table_bounded() {
    let mut l = Limiter::default();
    for n in 0..1_000u32 { l.failed(Ipv4Addr::from(0x0a00_0000 + n), u64::from(n) * 120); }   // far apart: no overall hold
    assert!(l.len() <= MAX_ADDRESSES);
}
```

(`Limiter::len` is `pub(crate)`, for this test.)

- [ ] **Step 2: Run** `cargo test -p qberrypi api::session` — expected: compile failure.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the four checks — expected: all pass.
- [ ] **Step 5: Commit** — `git add crates/qberrypi/src/api/session.rs crates/qberrypi/src/api/mod.rs`, message `"api: sessions that expire and a limit on failed logins"`.

---

### Task 6: HTTP over the TLS stream

**Files:**
- Create: `crates/qberrypi/src/api/http.rs`

**Interfaces:**
- Consumes: `httparse` (milestone 3's).
- Produces:

```rust
pub const MAX_HEAD: usize = 8 * 1024;
pub const MAX_BODY: usize = 4 * 1024;
pub const MAX_HEADERS: usize = 32;
#[derive(PartialEq)] pub struct Request { pub method: String, pub target: String, pub sid: Option<String>, pub body: Vec<u8>, pub close: bool }   // Debug redacts sid and body
#[derive(Debug, PartialEq)] pub enum ReadError { Closed, TooLarge, Malformed(&'static str), Io(io::ErrorKind) }
pub fn read_request(r: &mut impl BufRead) -> Result<Request, ReadError>;
#[derive(Debug, PartialEq)] pub struct Reply { pub status: u16, pub body: Vec<u8> }
pub fn write_reply(w: &mut impl Write, reply: &Reply, close: bool) -> io::Result<()>;
```

`read_request`: reads the head until `\r\n\r\n`, at most `MAX_HEAD` bytes (`TooLarge` beyond), parses it with `httparse`. End of stream before the first byte is `Closed`, and within the head `Malformed("cut short")`. `sid` is the value of an `X-FTL-SID` header, matched without regard to case, when it is 1 to 512 visible ASCII bytes, and `None` otherwise. `Cookie` and query parameters are never read for it. `close` is HTTP/1.0 or a `Connection` header containing `close`. A body is read when `Content-Length` is given: more than `MAX_BODY` is `TooLarge`, two different values or a non-number is `Malformed`, and any `Transfer-Encoding` is `Malformed("no chunked requests")`.

`write_reply`: `HTTP/1.1 {status} {reason}\r\n`, then `Content-Type: application/json\r\n` (not for 204), `Content-Length: {n}\r\n`, `Cache-Control: no-store\r\n`, `Connection: keep-alive` or `close`, a blank line, the body. Reasons for 200, 204, 400, 401, 404, 405, 413, 429 and 500.

- [ ] **Step 1: Write the failing tests** in `http.rs`, reading from `std::io::Cursor`:

```rust
const QNET_GET: &str = "GET /api/stats/summary HTTP/1.1\r\nHost: 192.0.2.53\r\nUser-Agent: qnet\r\nAccept: application/json\r\nX-FTL-SID: 0123abcd\r\nConnection: keep-alive\r\n\r\n";
#[test] fn the_requests_qnet_sends_are_read_one_after_another() {
    let post = "POST /api/dns/blocking HTTP/1.1\r\nHost: 192.0.2.53\r\nx-ftl-sid: 0123abcd\r\nContent-Type: application/json\r\nContent-Length: 30\r\nConnection: close\r\n\r\n{\"blocking\":false,\"timer\":300}";
    let mut r = Cursor::new(format!("{QNET_GET}{post}"));
    let first = read_request(&mut r).unwrap();
    assert_eq!((first.method.as_str(), first.target.as_str(), first.sid.as_deref(), first.close), ("GET", "/api/stats/summary", Some("0123abcd"), false));
    let second = read_request(&mut r).unwrap();
    assert_eq!((second.body.as_slice(), second.close), (&b"{\"blocking\":false,\"timer\":300}"[..], true));
    assert_eq!(read_request(&mut r), Err(ReadError::Closed));
}
#[test] fn oversized_chunked_or_broken_requests_are_refused() {          // Review Focus 2
    let big_head = format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(MAX_HEAD));
    let big_body = "POST /api/auth HTTP/1.1\r\nContent-Length: 5000\r\n\r\n";
    let chunked = "POST /api/auth HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    let two_lengths = "POST /api/auth HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab";
    assert_eq!(read_request(&mut Cursor::new(big_head)), Err(ReadError::TooLarge));
    assert_eq!(read_request(&mut Cursor::new(big_body)), Err(ReadError::TooLarge));
    assert!(matches!(read_request(&mut Cursor::new(chunked)), Err(ReadError::Malformed(_))));
    assert!(matches!(read_request(&mut Cursor::new(two_lengths)), Err(ReadError::Malformed(_))));
    assert!(matches!(read_request(&mut Cursor::new("GET /api/auth HTTP/1.1\r\nHost")), Err(ReadError::Malformed(_))));
    assert!(matches!(read_request(&mut Cursor::new("\x16\x03\x01garbage\r\n\r\n")), Err(ReadError::Malformed(_))));
}
#[test] fn a_sid_is_taken_only_from_its_header_and_only_when_plain() {    // Review Focus 3
    let with = |h: &str| read_request(&mut Cursor::new(format!("GET /api/auth?sid=abc HTTP/1.1\r\n{h}\r\n\r\n"))).unwrap().sid;
    assert_eq!(with("Cookie: sid=abc"), None);
    assert_eq!(with("X-FTL-SID: a b"), None);
    assert_eq!(with(&format!("X-FTL-SID: {}", "a".repeat(513))), None);
    assert_eq!(with("X-FTL-SID: abc"), Some("abc".to_owned()));
}
#[test] fn a_reply_is_written_whole() {
    let mut out = Vec::new();
    write_reply(&mut out, &Reply { status: 401, body: b"{}".to_vec() }, false).unwrap();
    assert_eq!(out, b"HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: 2\r\nCache-Control: no-store\r\nConnection: keep-alive\r\n\r\n{}");
    let mut out = Vec::new();
    write_reply(&mut out, &Reply { status: 204, body: vec![] }, true).unwrap();
    assert_eq!(out, b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n");
}
```

- [ ] **Step 2: Run** `cargo test -p qberrypi api::http` — expected: compile failure.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the four checks — expected: all pass.
- [ ] **Step 5: Commit** — `git add crates/qberrypi/src/api/http.rs crates/qberrypi/src/api/mod.rs`, message `"api: read requests and write replies, within bounds"`.

---

### Task 7: The endpoints

**Files:**
- Create: `crates/qberrypi/src/api/routes.rs`

**Interfaces:**
- Consumes: Task 1's `HistoryBucket`, `qb_dns::{Counts, LogEntry, Outcome}`; Task 2's `ServerStats`; Task 3's `PasswordHash`; Task 5's `Sessions`, `Limiter`, `HoldBack`; Task 6's `Request`, `Reply`; milestone 6's `dns::clients::Client`; milestone 4/5 Task 11's JSON for one query (`unix_secs`, `name`, `qtype`, `outcome` as `blocked` / `local` / `cached` / `stale` / `forwarded`) and its `MAX_QUERIES`.
- Produces:

```rust
pub trait Facts: Send + Sync {
    fn last_24h(&self) -> Counts;
    fn history(&self) -> Vec<HistoryBucket>;
    fn upstreams(&self) -> Vec<ServerStats>;
    fn clients(&self) -> (usize, usize);                 // seen in the last 24 h, held in the table
    fn client_list(&self) -> Vec<Client>;                // most recently seen first
    fn recent(&self, n: usize) -> Vec<LogEntry>;         // newest first
    fn list(&self) -> (Option<usize>, Option<u64>);       // names in the block set, unix time of the last list fetch
    fn paused_left_secs(&self) -> Option<u64>;
    fn pause_for(&self, secs: u64);
    fn resume(&self);
}
pub struct Api {
    pub hash: PasswordHash,
    pub facts: Arc<dyn Facts>,
    pub mono_secs: Arc<dyn Fn() -> u64 + Send + Sync>,
    pub random: Arc<dyn Fn() -> [u8; 16] + Send + Sync>,
    /* private: Mutex<Sessions>, Mutex<Limiter>, Mutex<()> held while verifying */
}
impl Api {
    pub fn new(hash: PasswordHash, facts: Arc<dyn Facts>, mono_secs: .., random: ..) -> Self;
    pub fn handle(&self, request: &Request, from: Ipv4Addr) -> Reply;
}
```

`handle` answers exactly the spec's endpoint table (part 2, "The subset, endpoint by endpoint"), every JSON body with `"took"`. In order:
1. A target outside `/api/` is 404 `not_found`.
2. `POST /api/auth` needs no session.
3. Any other request with no valid `Sessions::touch` is 401 `unauthorized`, with the error object `{"error":{"key":"unauthorized","message":"Unauthorized","hint":null},"took":…}`; `/api/auth` answers in its session shape instead.
4. A known path with another method is 405.
5. Any other target is 404 `not_found`; that includes a `?` anywhere but `n` on `/api/v1/queries`.

`/api/v1/queries` takes `n` of 1 to `MAX_QUERIES`, held to the top, default 100, and answers 400 for anything else; `/api/v1/clients` takes no query string.

`POST /api/auth`: a held-back address gets 429 at once. Otherwise the body is parsed (`password` a string, or 400 `bad_request` `"Invalid request body data (no valid JSON)"`), and the hash is checked under the verification lock. Then 200 with `Sessions::open((self.random)(), now)` and `limiter.succeeded`, or 401 and `limiter.failed`. It logs at INFO `api: login accepted`, at WARN `api: login refused`, and `api: logins from one address held back for 60 s` or `api: all logins held back for 60 s` as `failed` returns. No line carries an address, and there is no other line.

- [ ] **Step 1: Write the failing tests** in `routes.rs`. `Fake` implements `Facts` from public fields and records `pause_for`/`resume` calls; `api(fake)` is an `Api` over `PasswordHash::new(b"right", [0; 16])`, a mono clock the test moves (`advance(&api, secs)`), and a `random` that counts up from `[1; 16]`; `req(method, target, sid, body)` builds a `Request`; `json(&reply)` parses the body; `login(&api) -> String` posts `{"password":"right"}` from `192.0.2.7` and returns the sid.

```rust
const ME: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 7);
#[test] fn the_right_password_opens_a_session_and_the_wrong_one_is_refused_in_pi_holes_shape() {
    let api = api(Fake::default());
    let ok = api.handle(&req("POST", "/api/auth", None, br#"{"password":"right"}"#), ME);
    let v = json(&ok);
    assert_eq!((ok.status, v["session"]["valid"].as_bool(), v["session"]["validity"].as_u64()), (200, Some(true), Some(1_800)));
    assert!(v["session"]["sid"].as_str().unwrap().len() == 32 && v["session"]["csrf"].is_null() && v["took"].is_number());
    let no = api.handle(&req("POST", "/api/auth", None, br#"{"password":"wrong"}"#), ME);
    assert_eq!((no.status, json(&no)["session"]["valid"].as_bool(), json(&no)["session"]["sid"].is_null()), (401, Some(false), true));
    for body in [&b"{}"[..], b"not json", b"{\"password\":5}", b""] {
        assert_eq!(api.handle(&req("POST", "/api/auth", None, body), ME).status, 400);
    }
}
#[test] fn after_five_failures_even_the_right_password_waits() {            // Review Focus 1
    let api = api(Fake::default());
    for _ in 0..5 { api.handle(&req("POST", "/api/auth", None, br#"{"password":"wrong"}"#), ME); }
    let held = api.handle(&req("POST", "/api/auth", None, br#"{"password":"right"}"#), ME);
    assert_eq!((held.status, json(&held)["error"]["key"].as_str()), (429, Some("rate_limiting")));
    assert_eq!(api.handle(&req("POST", "/api/auth", None, br#"{"password":"right"}"#), Ipv4Addr::new(192, 0, 2, 8)).status, 200);
}
#[test] fn nothing_but_the_login_answers_without_a_session_and_nothing_changes_or_shows() {   // Review Focus 3
    let mut fake = Fake::default();
    fake.recent = vec![LogEntry { unix_secs: 1, name: "secret.example.com".into(), qtype: 1, outcome: Outcome::Forwarded }];
    fake.client_list = vec![Client { addr: Ipv4Addr::new(198, 51, 100, 4), queries: 3, last_seen_secs_ago: 1 }];
    let api = api(fake.clone());
    let pause = br#"{"blocking":false,"timer":300}"#;
    for (method, target, body) in [("GET", "/api/stats/summary", &b""[..]), ("GET", "/api/history", b""), ("GET", "/api/stats/upstreams", b""),
                                   ("GET", "/api/dns/blocking", b""), ("POST", "/api/dns/blocking", pause), ("GET", "/api/auth", b""),
                                   ("DELETE", "/api/auth", b""), ("GET", "/api/v1/queries", b""), ("GET", "/api/v1/clients", b""),
                                   ("GET", "/api/nope", b"")] {
        for sid in [None, Some("0".repeat(32))] {
            let r = api.handle(&req(method, target, sid.as_deref(), body), ME);
            let v = json(&r);
            // /api/auth answers in its session shape, everything else with the error object
            let refused = v["error"]["key"] == "unauthorized" || v["session"]["valid"] == false;
            let text = String::from_utf8_lossy(&r.body);
            assert!(r.status == 401 && refused && !text.contains("secret.example.com") && !text.contains("198.51.100.4"), "{method} {target}");
        }
    }
    assert!(fake.calls().is_empty());
    let sid = login(&api);
    advance(&api, 1_800);
    assert_eq!(api.handle(&req("GET", "/api/dns/blocking", Some(&sid), b""), ME).status, 401);   // expired
}
#[test] fn a_session_can_be_checked_and_ended() {
    let api = api(Fake::default());
    let sid = login(&api);
    let r = api.handle(&req("GET", "/api/auth", Some(&sid), b""), ME);
    assert_eq!((r.status, json(&r)["session"]["valid"].as_bool(), json(&r)["session"]["sid"].is_null()), (200, Some(true), true));
    assert_eq!(api.handle(&req("DELETE", "/api/auth", Some(&sid), b""), ME).status, 204);
    assert_eq!(api.handle(&req("GET", "/api/auth", Some(&sid), b""), ME).status, 401);
}
#[test] fn the_summary_is_of_the_last_24_hours() {
    let mut fake = Fake::default();
    fake.last_24h = Counts { queries: 200, blocked: 50, cache_hits: 30, forwarded: 100 };
    fake.clients = (3, 5);
    fake.list = (Some(302_176), Some(1_800_000_000));
    let api = api(fake);
    let v = json(&api.handle(&req("GET", "/api/stats/summary", Some(&login(&api)), b""), ME));
    let q = &v["queries"];
    assert_eq!((q["total"].as_u64(), q["blocked"].as_u64(), q["percent_blocked"].as_f64()), (Some(200), Some(50), Some(25.0)));
    assert_eq!((q["forwarded"].as_u64(), q["cached"].as_u64()), (Some(100), Some(50)));     // 30 from the cache, 20 answered here
    assert!((q["frequency"].as_f64().unwrap() - 200.0 / 86_400.0).abs() < 1e-9);
    assert_eq!((v["clients"]["active"].as_u64(), v["clients"]["total"].as_u64()), (Some(3), Some(5)));
    assert_eq!((v["gravity"]["domains_being_blocked"].as_u64(), v["gravity"]["last_update"].as_u64()), (Some(302_176), Some(1_800_000_000)));
    // with no queries percent_blocked is 0, and with nothing known gravity's two values are 0
}
#[test] fn the_history_is_144_buckets_by_their_centres_oldest_first() {
    // fake.history: 144 buckets from T − 143 × 600 to T, the last with counts {queries 9, blocked 2, cache_hits 3, forwarded 4}:
    // "history" has 144 objects; [0].timestamp is T − 143 × 600 + 300; [143] is {"timestamp": T + 300, "total": 9, "cached": 3, "blocked": 2, "forwarded": 4}
}
#[test] fn upstreams_come_after_the_blocklist_and_the_cache() {
    // fake.last_24h as in the summary test; fake.upstreams: 9.9.9.9:53 answered 287 at 8.0 ms, 149.112.112.112:53 answered 0 with no latency:
    // upstreams[0] is {"ip":"blocklist","name":"blocklist","port":-1,"count":50,"statistics":{"response":0,"variance":0}};
    // upstreams[1] the same with "cache" and 50; upstreams[2] is {"ip":"9.9.9.9","name":"9.9.9.9","port":53,"count":287,
    // "statistics":{"response":0.008,"variance":0}}; upstreams[3] has response 0; forwarded_queries 100; total_queries 200
}
#[test] fn the_households_queries_and_devices_come_with_a_session() {
    // fake.recent: three entries; fake.client_list: two. With a session: /api/v1/queries?n=2 gives two objects newest first,
    // the first {"unix_secs":…, "name":…, "qtype":1, "outcome":"blocked"} for Outcome::Blocked; no n: the fake was asked for 100;
    // n=999999: for MAX_QUERIES; n=0, n=abc, ?m=3: 400. /api/v1/clients gives [{"address":"198.51.100.4","queries":3,"last_seen_secs":1}, …];
    // /api/v1/clients?x=1: 404
}
#[test] fn blocking_pauses_with_a_timer_and_resumes() {
    let fake = Fake::default();
    let api = api(fake.clone());
    let sid = login(&api);
    let post = |body: &[u8]| api.handle(&req("POST", "/api/dns/blocking", Some(&sid), body), ME);
    let r = post(br#"{"blocking":false,"timer":299.5}"#);
    assert_eq!((r.status, json(&r)["blocking"].as_str(), json(&r)["timer"].as_u64()), (200, Some("disabled"), Some(300)));
    assert_eq!(fake.calls(), ["pause 300"]);
    let r = post(br#"{"blocking":true,"timer":null}"#);
    assert_eq!((json(&r)["blocking"].as_str(), json(&r)["timer"].is_null()), (Some("enabled"), true));
    assert_eq!(fake.calls(), ["pause 300", "resume"]);
}
#[test] fn bodies_that_are_not_a_pause_or_a_resume_change_nothing() {      // Review Focus 5
    let fake = Fake::default();
    let api = api(fake.clone());
    let sid = login(&api);
    for (body, key) in [(&br#"{"blocking":"no"}"#[..], "body_error"), (b"{}", "body_error"), (b"nope", "bad_request"), (b"", "bad_request"),
                        (br#"{"blocking":false}"#, "bad_request"), (br#"{"blocking":false,"timer":null}"#, "bad_request"),
                        (br#"{"blocking":false,"timer":0}"#, "bad_request"), (br#"{"blocking":false,"timer":-5}"#, "bad_request"),
                        (br#"{"blocking":false,"timer":86401}"#, "bad_request"), (br#"{"blocking":false,"timer":1e300}"#, "bad_request")] {
        let r = api.handle(&req("POST", "/api/dns/blocking", Some(&sid), body), ME);
        assert_eq!((r.status, json(&r)["error"]["key"].as_str()), (400, Some(key)), "{}", String::from_utf8_lossy(body));
    }
    assert!(fake.calls().is_empty());
    assert_eq!(api.handle(&req("POST", "/api/dns/blocking", Some(&sid), br#"{"blocking":true,"extra":1}"#), ME).status, 200);
}
#[test] fn other_paths_and_methods() {
    let api = api(Fake::default());
    let sid = login(&api);
    let status = |m: &str, t: &str| api.handle(&req(m, t, Some(&sid), b""), ME).status;
    assert_eq!([status("PUT", "/api/dns/blocking"), status("POST", "/api/v1/queries"), status("GET", "/api/domains/deny/exact"),
                status("GET", "/api/stats/summary?x=1"), status("GET", "/admin/"), status("GET", "/")], [405, 405, 404, 404, 404, 404]);
}
```

- [ ] **Step 2: Run** `cargo test -p qberrypi api::routes` — expected: compile failure.
- [ ] **Step 3: Implement** with `serde_json::json!`; numbers whole where the table says so.
- [ ] **Step 4: Run** the four checks — expected: all pass.
- [ ] **Step 5: Commit** — `git add crates/qberrypi/src/api/routes.rs crates/qberrypi/src/api/mod.rs`, message `"api: login, summary, history, upstreams, blocking, and the household's queries and devices behind the login"`.

---

### Task 8: The component on port 443

**Files:**
- Create: `crates/qberrypi/src/api/live.rs`
- Modify: `crates/qberrypi/src/api/mod.rs`, `crates/qberrypi/src/services.rs`, `crates/qberrypi/src/init.rs`, `crates/qberrypi/Cargo.toml`, `Cargo.lock`, `xtask/src/qemu.rs`, `docs/superpowers/plans/2026-11-10-execution-order.md`

**Interfaces:**
- Consumes: Tasks 3–7; `Dns::{now, shared, resolver, upstreams, clients}`; milestone 4/5's `wiring::Extras` (`list_names`, `list_fetched_unix`) and the closure that makes it; `services::{blocking, BLOCKING_THREADS}`, `services::testutil::longest_gap`; `supervisor::{Component, Ended}`; `sys::random_u64`; `dns/testutil.rs`'s `service`; Task 4's `cert::make` (for QEMU).
- Produces:

```rust
// api/mod.rs
pub const PORT: u16 = 443;
pub const CONNECTIONS: usize = 2;
pub const HANDSHAKE_WAIT: Duration = Duration::from_secs(5);
pub const IDLE_WAIT: Duration = Duration::from_secs(5);
pub const CONNECTION_LIFE: Duration = Duration::from_secs(60);
pub const MAX_REQUESTS: usize = 100;
pub struct Limits { pub connections: usize, pub handshake: Duration, pub idle: Duration, pub life: Duration }   // Limits::DEFAULT from the constants
pub async fn serve(listener: tokio::net::TcpListener, tls: Arc<rustls::ServerConfig>, api: Arc<Api>, limits: Limits) -> io::Result<()>;
pub fn component(api: Arc<Api>, tls: Arc<rustls::ServerConfig>) -> Component;   // not essential; binds 0.0.0.0:443 on each start, logs `api: listening on 0.0.0.0:443`
// api/live.rs
pub struct LiveFacts { pub dns: Arc<Dns>, pub extras: Arc<dyn Fn() -> Extras + Send + Sync> }   // impl Facts
// services.rs
pub const BLOCKING_THREADS: usize = 5;
```

`serve`: a semaphore of `limits.connections`, taken before `accept`. Each accepted stream becomes a `std::net::TcpStream` in blocking mode and goes, with its permit, to `services::blocking("api connection", ..)`. The job runs the handshake under `limits.handshake`, then reads requests (`read_request` over a `BufReader` of `rustls::StreamOwned`) with `limits.idle` as the read timeout. Each request is answered with `api.handle(&request, peer)` and `write_reply`, until the client closes, asks to close, `MAX_REQUESTS` is reached, or `limits.life` has passed (then the last reply says `close`). `TooLarge` gets 413 and `Malformed` 400, both with `close`; `Closed` or `Io` ends quietly. A peer that is not IPv4 is closed at once. `serve` returns `Err` only when `accept` fails.

`LiveFacts` reads everything from `dns` at `dns.now()`:
- `last_24h`, `history` and `recent(n)`: from `dns.resolver().stats()`.
- `upstreams`: `dns.upstreams().servers()`.
- `clients`: `(dns.clients().seen_within(now, 86_400), dns.clients().len())`; `client_list`: `dns.clients().list(now)`.
- `list`: from `extras()`.
- `paused_left_secs`: `resolver.paused_until(now) − now.mono_secs`; `pause_for(s)`: `resolver.pause_until(now.mono_secs + s)`; `resume`: `resolver.resume()`. It is the same pause the panel's `SharedResolver` sets.

`init`, when `cfg.api` is `Some`: build `server_config` from `TLS_PEM`.
- On `Some(Ok)`: add `api::component(..)` to the plan, with `Api::new(hash, LiveFacts {..}, || dns.now().mono_secs, random)`, where `random` takes 16 bytes from two `sys::random_u64()`.
- On no PEM or `Err(why)`: add a component that ends at once with `Ended::Absent(why)`, which the supervisor logs once as a warning.

When `cfg.api` is `None`, add nothing. The execution-order file's ruling 8 gains the sentence: *Milestone 7 raises the cap to 5: two more threads for the API's TLS connections, at most two at a time.*

`qemu.rs`: the DNS scenario's configuration gains `[api]` with `hash_line(b"qemu", [0; 16])`. Its card image gains `qberrypi/tls.pem` from `cert::make("qberrypi", <the scenario's address>, now)`, made for the run and never kept. Its conditions gain `evidence.serial_has("INFO  api: listening on 0.0.0.0:443")`. The other scenarios have no `[api]` and so no new line.

- [ ] **Step 1: Add the dependency** — `cargo add -p qberrypi --dev rustls@0.23 -F ring,std,tls12` (the client qnet uses, for the interop test only).
- [ ] **Step 2: Write the failing tests** in `api/mod.rs`. The helpers:
  - `pinned_client(cert_der)` is a `rustls::ClientConfig` on the `ring` provider with safe default versions. Its verifier accepts exactly that leaf's SHA-256, as qnet's does, and verifies handshake signatures with the `ring` provider's algorithms.
  - `served(limits)` binds `127.0.0.1:0` and returns `(addr, dns, cert)`. It makes a `Dns` with `service`, an `Api` over `LiveFacts` and `PasswordHash::new(b"right", [0; 16])`, and a certificate from `rcgen` P-256, then spawns `serve`.
  - `https(addr, client, requests: &[&str]) -> Vec<(u16, Value)>` sends the requests on one connection, on a blocking thread, and reads each reply. A request string is `METHOD /path|sid=..|body`; the parts after the path are optional, and the helper adds qnet's headers.

```rust
#[tokio::test(flavor = "current_thread")] async fn qnets_kind_of_client_logs_in_reads_and_pauses_the_resolver() {
    let (addr, dns, cert) = served(Limits::DEFAULT).await;
    let login = https(addr, pinned_client(&cert), &[r#"POST /api/auth|{"password":"right"}"#]).await;
    let sid = login[0].1["session"]["sid"].as_str().unwrap().to_owned();
    let polled = https(addr, pinned_client(&cert), &[&format!("GET /api/stats/summary|sid={sid}"), &format!("GET /api/dns/blocking|sid={sid}"),
                                                     &format!("GET /api/history|sid={sid}"), &format!("GET /api/stats/upstreams|sid={sid}")]).await;
    assert!(polled.iter().all(|(status, _)| *status == 200));             // four requests, one kept-alive connection
    assert_eq!(polled[2].1["history"].as_array().unwrap().len(), 144);
    https(addr, pinned_client(&cert), &[&format!(r#"POST /api/dns/blocking|sid={sid}|{{"blocking":false,"timer":300}}"#)]).await;
    assert!(dns.resolver().paused_until(dns.now()).is_some());
}
#[tokio::test] async fn a_client_pinned_to_another_certificate_is_refused_in_the_handshake() {
    // pinned_client(other_cert): the handshake fails on the client's side; the server serves the next client
}
#[tokio::test] async fn two_silent_connections_do_not_keep_a_third_out_for_long_and_dns_answers_meanwhile() {   // Review Focus 2
    let limits = Limits { handshake: Duration::from_millis(300), idle: Duration::from_millis(300), ..Limits::DEFAULT };
    // two TcpStreams that connect and send nothing; a third, qnet-like, logs in: answered within 1 s;
    // meanwhile ask_udp to the same Dns's port answers; both silent streams read end-of-file by then
}
#[tokio::test] async fn a_connection_is_closed_after_its_idle_time_and_its_life() {
    // one login, then nothing: the server closes within idle + 100 ms; a client that sends a GET every 200 ms
    // under life = 1 s gets a reply with Connection: close at the latest at 1 s and then end-of-file
}
#[tokio::test] async fn a_handshake_does_not_hold_the_runtime_thread() {
    let (addr, _dns, cert) = served(Limits::DEFAULT).await;
    let (gap, _) = longest_gap(https(addr, pinned_client(&cert), &[r#"POST /api/auth|{"password":"right"}"#])).await;
    assert!(gap < Duration::from_millis(100), "{gap:?}");
}
```

In `services.rs`, rename `the_runtime_has_one_thread_and_a_pool_of_two` (or of three, as milestone 4/5 left it) for five and make it start six jobs, the sixth waiting.

- [ ] **Step 3: Run** `cargo test -p qberrypi -- api:: services::` — expected: compile failure.
- [ ] **Step 4: Implement** `serve`, `component`, `LiveFacts`, the wiring in `init`, `BLOCKING_THREADS`, the QEMU scenario, and the ruling's sentence.
- [ ] **Step 5: Run** the four checks, the `cargo tree` check of Global Constraints (it must print nothing: `ring` is a dev-dependency only), then `cargo xtask build && cargo xtask qemu-test` — expected: all pass; the DNS scenario logs `api: listening on 0.0.0.0:443`.
- [ ] **Step 6: Commit** — the files above by name, message `"api: Pi-hole's endpoints over TLS on port 443, two connections at a time"`.

---

### Task 9: qnet against qberrypi, on the Pi (session lead with the owner)

**Files:**
- Create: `docs/bring-up/m7.md`
- Modify: `README.md` (the API in the status paragraph and in the configuration notes; `hash-password` and `make-cert` in the command table; how to re-pin qnet), `docs/superpowers/specs/2026-11-10-qberrypi-design.md` (Status gains the API on 443 and a pointer to the companion spec, and says `/api/v1/queries` moved there; Non-goals' "remote login" gains "other than the Pi-hole API subset's login"; Configuration shows `[api]` and `qberrypi-tls.pem`; Milestones row 7 says done), `qberrypi.example.toml` if Task 3's comment needs the procedure

- [ ] **Step 1: Prepare.**
  1. The owner runs `cargo xtask make-cert` once.
  2. He pipes qnet's app password into `cargo xtask hash-password` and puts the line under `[api]` in his `qberrypi.toml`. The lead checks the file has `qnet-canary.invalid` in `dns.deny`.
  3. One-shot boot: `one_shot = true`, `log_to_sd = true`, `return_after_secs = 900`. `cargo xtask deploy --host <alias>` must print `the API's certificate pin (SHA-256): …`, the same value `make-cert` printed.
  4. The owner replaces the pin in the Pi-hole section of qnet's configuration with that value, and opens qnet's panel.
- [ ] **Step 2: qnet, otherwise unchanged.** Within one poll, qnet shows API status ok, the numbers, the 24-hour graph, the upstreams and blocking on, with no TLS or pin error. The lead opens a session of his own with `curl -k` and fetches `/api/stats/summary`: qnet's total equals its `queries.total`, less qnet's own probes, within one poll.
- [ ] **Step 3: Pause both ways.** The owner pauses from qnet for 5 minutes. The front panel's switch shows the countdown, and `dig @<address> <listed>` returns a real address. He resumes from the panel's switch, and qnet shows blocking on at its next poll. Then the reverse: pause on the panel, resume from qnet.
- [ ] **Step 4: Refusals and privacy.** From the PC with `curl -k`:
  - Five logins with a wrong password get 401, the sixth with the right one 429, and after 60 s the right one gets 200.
  - `GET /api/stats/summary`, `/api/v1/queries` and `/api/v1/clients` with no `X-FTL-SID` get 401; with the session, the last two get 200 and list queries and the PC.
  - `curl http://<address>/api/v1/queries` on port 80 gets 403, and `curl http://<address>/api/auth` gets 404.
  - A login timed with `curl -k -w '%{time_total}'` takes under 1.5 s.
- [ ] **Step 5: The log.** The collected log has `api: listening on 0.0.0.0:443` and `api: login accepted`. `grep -c` on it finds nothing for the session ids `curl` printed, the password, the hash's hex, or the PC's address.
- [ ] **Step 6: Permanent.** Deploy `--permanent` with the same `[api]`. After a pulled-power restart qnet keeps working: it logs in again by itself after its first 401, with the same pin, since the certificate is on the card.
- [ ] **Step 7: Write `docs/bring-up/m7.md`** in the manner of `docs/bring-up/m0.md`: date, board, build; Steps 2–6 with what was seen; the login and handshake times; anything unexpected; anything not checked, by name. No address, password, sid or fingerprint. Update the README and the spec as listed under Files.
- [ ] **Step 8: Commit** — `git add docs/bring-up/m7.md README.md docs/superpowers/specs/2026-11-10-qberrypi-design.md` (and `qberrypi.example.toml` if changed), message `"Milestone 7 done: qnet works against qberrypi; notes and spec"`.
