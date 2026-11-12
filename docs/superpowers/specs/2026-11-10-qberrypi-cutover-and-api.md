# qberrypi — cutover and the Pi-hole API subset

Date: 2026-11-10
Status: draft; the owner's answers of 2026-11-10 are applied

A companion to `2026-11-10-qberrypi-design.md`, whose milestones table asks
for a short design of its own for milestones 6 and 7. Part 1 is milestone 6,
part 2 is milestone 7. Each part ends with the owner's answers to its
questions. Both milestones start once milestones 1–5 are merged.

Facts below marked *(Pi)* were read, read-only, from the Pi running Raspberry
Pi OS on 2026-11-10. No network name, address or secret appears in this file.

---

# Part 1 — Milestone 6: Cutover

**Done when:** qberrypi stays selected across restarts and pulled power and
answers DNS for every device on the home network, and the documented way
back to Raspberry Pi OS (the card in the PC's reader) has been carried out
once on the permanent system.

## What changes, and what does not

- qberrypi is made permanent with `cargo xtask deploy --permanent` and a
  `qberrypi.toml` with every development switch off. Nothing else about the
  boot changes: the selection is the same `config.txt` swap as a one-shot
  boot, the only difference being that init no longer puts the saved one back.
- It takes over the address Raspberry Pi OS uses today *(Pi: a static IPv4
  address set by hand, not by DHCP)*, so the owner's PC, qnet and, after
  the router change, every device already point to the right place.
- The Raspberry Pi OS install stays on the card, untouched, as the fallback.

## Getting back to Raspberry Pi OS

Once qberrypi is permanent, nothing on the Pi runs SSH, so every later
update starts with a return to Raspberry Pi OS: `deploy` installs over SSH
from Raspberry Pi OS. The way back is therefore needed for every update, not
only when something has gone wrong.

| Way back | For | Against |
|---|---|---|
| Card in the PC's reader, copy `config.pios.txt` over `config.txt` | Always works; needs no network, no login, no screen; the spec's success criterion 7 already names it. | The owner must take the card out, every update. |
| Authenticated request over the network | Works from the desk. | Needs a login, and fails exactly when the network is what broke. |
| Boot count: after N failed boots, fall back | Recovers with nobody there. | The count must survive a restart without a card write; only the firmware's reset register does, and a power cut clears it. |
| Long press on the front panel | No reader needed. | Needs the panel; more code. |

**Decision (the owner's): the card reader, and nothing else.** No gesture
and no network action are built.

To make the copy safe and easy, `cargo xtask return-to-pios --boot <dir>`
does it on the PC, with the card's boot partition mounted at `<dir>`:

- It refuses, writing nothing, unless `<dir>` looks like this Pi's boot
  partition: `bootcode.bin`, `config.txt`, `config.pios.txt` and a
  `qberrypi/` folder all present. So a wrong directory, another card or the
  card's root partition is never written.
- It runs the same `bootpart::restore_pios_config` that init uses for the
  one-shot restore. That function judges the saved file in full first
  (missing, empty, not text, or itself selecting qberrypi are refusals),
  writes in place, and never writes the saved file.
- It syncs, reads `config.txt` back against `config.pios.txt`, and says
  `config.txt is Raspberry Pi OS's again: eject the card before taking it out`.

**The way back, and the update loop:**

1. Pull the Pi's power cord. This is safe on a permanent qberrypi, which
   writes nothing (criterion 3).
2. Put the card in the PC's reader and run
   `cargo xtask return-to-pios --boot <where it is mounted>`.
3. Eject the card, put it back in the Pi, and plug the power in. The Pi
   starts Raspberry Pi OS and its Pi-hole, on the same address.
4. To update: `cargo xtask deploy` (one-shot, to try the build), then
   `cargo xtask deploy --permanent`, exactly as before.

The rule the spec already has also stays: a `qberrypi.toml` that cannot be
read or parsed restores `config.txt` and returns, permanent or not.

## Card writes on a permanent system

With `debug.one_shot` and `debug.log_to_sd` off, qberrypi never mounts the
card writable (milestone 4's Task 10 tests this, and its QEMU scenario
checks that the card image stays byte-identical). This milestone adds no
write. Success criterion 3 stands as written.

`deploy --permanent` refuses a `qberrypi.toml` with any development switch
on: `one_shot`, `log_to_sd`, `return_after_secs` other than 0,
`calibrate_touch`, or a `fault` other than `none`.

## What stays of Raspberry Pi OS, and what it costs

Confirmed: the install stays, untouched, and is the fallback. Its Pi-hole
answers on the same address, so a return is also the quickest way to get
the household's DNS back if qberrypi misbehaves. What that costs:

- **Card space.** Its root partition stays. The card has room.
- **It goes stale.** It gets no updates while qberrypi is selected. After a
  return it catches up by itself: its `apt-daily` and `apt-daily-upgrade`
  timers *(Pi: both enabled)* fire soon after boot. A deploy then has to
  wait, because a restart in the middle of a package upgrade could damage
  that install. `deploy` refuses while `apt`, `apt-get`, `dpkg` or
  `unattended-upgrades` is running, and says to try again.
- **qnet's statistics.** Part 2 gives qberrypi its own certificate, which
  qnet is pinned to. During a stay on Raspberry Pi OS, qnet's statistics
  report a certificate mismatch against Pi-hole's certificate; its DNS
  checks still work.
- **Shared boot files.** The boot firmware (`bootcode.bin`, `start.elf`,
  `fixup.dat`) and the `overlays/` folder belong to Raspberry Pi OS and are
  updated by its packages. qberrypi already carries its own kernel and device
  tree. The firmware stays shared; it is the only way the board starts, and
  if it ever stops honouring `os_prefix`, it boots Raspberry Pi OS, which is
  safe. The overlays stop being shared (next section).

## Overlays: qberrypi carries its own

Milestone 4/5 left the screen's overlay shared (its Decision "Overlay files"),
loaded from Raspberry Pi OS's `overlays/piscreen.dtbo`. A Raspberry Pi OS
kernel upgrade replaces that file with one built for a newer kernel than
qberrypi's pinned one, which could leave the panel dark. So qberrypi carries
the overlay from its own pinned kernel package, which holds `piscreen.dtbo`,
`README` and `overlay_map.dtb` under `usr/lib/modules/<version>/dtb/overlays/`
(today the same bytes as the shared copy).

The firmware loads overlays from `${os_prefix}${overlay_prefix}` when
`${os_prefix}${overlay_prefix}README` exists, and from the shared folder
otherwise (Raspberry Pi documentation, `config.txt`, "os_prefix" and
"overlay_prefix"). qberrypi's `config.txt` gains `overlay_prefix=ov-`, and
the folder gains `ov-README`, `ov-overlay_map.dtb` and `ov-qb-piscreen.dtbo`.
The folder stays flat, which `deploy`'s staging needs. The overlay is renamed
`qb-piscreen` (`dtoverlay=qb-piscreen,speed=16000000,rotate=270`, the screen
being flipped, ruling 15). A lit panel then proves the firmware read
qberrypi's copy, since the shared folder has no file of that name. The
documentation calls `overlay_prefix` a "subdirectory/prefix" without showing
a plain file prefix. If the Pi check shows the firmware will not take one,
the fallback is a `qberrypi/overlays/` subfolder, with the staging changes
that needs.

## Who updates what

Nothing updates itself except the blocklists.

| What | How it is kept current |
|---|---|
| Blocklists | qberrypi refetches them over HTTPS every day (milestone 3). The snapshot in the image only covers the first minute or so after boot. |
| Kernel, Wi-Fi firmware, modules, overlays | Pinned in `xtask/src/pins.rs`. Raised by hand: a new pin, then the update loop above. Do it when Raspberry Pi publishes a kernel that fixes a network or Wi-Fi security issue, and at least every three months. |
| Root certificates (`webpki-roots`), Rust crates | With each rebuild, the same way. |
| Raspberry Pi OS and its Pi-hole | Only while it runs; it catches up after a return. |

Not running a general-purpose OS is what makes this acceptable. qberrypi
listens on DNS (53), on the status page (80) and, after milestone 7, on the
API (443). It runs no shell and no other program, and has no user accounts.
Each update's restarts take the household's DNS away for one to three
minutes.

## Seeing the other clients, without showing them

The spec's status page counts queries, not who sent them, so it cannot show
that the router change reached a device. The DNS listener now notes each
query's source address in a small table: at most 256 addresses, the least
recently seen dropped, the Pi's own lookups not counted.

The owner's rule is that per-query and per-device data needs the API login,
while the totals stay open. Port 80 therefore gains only the counts:
`clients_hour` and `clients_24h` in the status JSON, and the first on the
page. The list of addresses comes in milestone 7, behind the login, as
`/api/v1/clients` on port 443. The same rule applies to the recent-query log
milestone 4 built: from this milestone on, port 80 answers
`/api/v1/queries` with 403 and the line `this needs the API login`, so the
household's queries are never open on the network after cutover. Milestone 7
serves it again on port 443, behind the login. `/log` stays open, so no log
line may name a client address (none names a queried name already).

The front panel is not changed. Its refused count rising, and names crossing
its lane, faster than the PC alone can account for is the at-a-glance sign,
and the client counts are the proof.

## Boot time (success criterion 6)

The target is under 15 seconds from power-on to the first answered query,
against about 45 seconds today *(Pi: systemd reports 4.2 s kernel + 31.9 s
userspace = 36 s to `multi-user.target`, before the firmware's few seconds
and before Pi-hole answers)*.

The board cannot see its own power-on: its timestamps start when the kernel
does. So the measurement is taken from outside. `cargo xtask boot-time`
prints a prompt. The owner presses Enter as he plugs the Pi's power in. The
tool then asks the configured address every 200 ms over UDP, first for
`qberrypi-snapshot.invalid` (blocked by every snapshot, so answered with no
upstream), then for `example.com` (forwarded). It reports both times. The
reaction-time error is a few tenths of a second, which a 15-second target can
bear. The board adds its own half: the first answer to a client logs
`dns: first answer to a client {ms} ms after the kernel started`. The two
figures together separate the firmware's share from qberrypi's.

At cutover: three runs on the permanent system, median reported, against one
baseline run of Raspberry Pi OS measured the same way. For the baseline,
shut it down cleanly first (`sudo poweroff`), then power it on with Enter.
Both go into `docs/bring-up/m6.md`.

## The owner's network checklist

Before:

1. `qberrypi.toml`'s `net.address` is the address Raspberry Pi OS uses now,
   and the router will not lease that address to anything else. It is
   outside the DHCP range, or reserved for the Pi. qberrypi has no DHCP
   client and cannot notice a conflict.
2. `dns.deny` includes `qnet-canary.invalid`, the name qnet's health probe
   expects to be blocked (part 2).
3. qberrypi has passed the one-shot rehearsal of this milestone, and the
   permanent deploy has reported `qberrypi build N answers at <address>`.

At the router (its DNS setting, custom servers):

4. Set the IPv4 DNS server to the Pi's address. Leave no second server.
   Clients use every server they are given, so a router or public resolver
   as a second server lets ads through. The cost is that the Pi is the only
   DNS server; a return to Raspberry Pi OS keeps the same address answering.
5. Known limitation, accepted: the router also advertises its own IPv6 DNS
   server, which qberrypi (IPv4 only) cannot replace, so devices that prefer
   it bypass blocking.
6. Devices take the new server when their lease renews: reconnect each
   device's Wi-Fi, or wait a day.

Afterwards, what qberrypi itself shows:

7. `http://<address>/api/v1/stats`: `clients_hour` grows by one as each
   device is reconnected and used. A phone, a TV and the PC each count within
   a minute of being used.
8. Names keep crossing the front panel's lane while the PC is idle.
9. On the PC, `nmcli device show` (or `resolvectl dns`) shows the Pi's
   address as the IPv4 DNS server, and no other IPv4 server.
10. A device that does not add to the count after reconnecting is using
    another server: its own (some TVs and browsers use DNS over HTTPS), or
    the router's IPv6 one (step 5). Neither is within qberrypi's reach.

One note on qnet: its failover is set to fall back to the router. That works
only if the router answers DNS by itself and does not hand the query back to
the Pi. This is worth checking once, while the Pi is on Raspberry Pi OS
after a return.

## Pi checks of milestone 6

1. **Rehearsal (one-shot):** a build with the own overlay and the client
   counts. The panel lights (proving `ov-qb-piscreen` was read).
   `clients_hour` counts the PC. Port 80's `/api/v1/queries` answers 403.
2. **Permanent:** `deploy --permanent` reports the build answering. qberrypi
   is still selected after the owner pulls the power cord for 5 seconds (the
   check milestone 4 deferred). Then the way back: cord out, card in the
   reader, `cargo xtask return-to-pios`, card back. The Pi comes up as
   Raspberry Pi OS, where `config.txt` equals `config.pios.txt` and the
   kernel reports no FAT problem on the boot partition.
3. **Cutover:** permanent again, the checklist, boot time three times.

## The owner's answers (part 1)

- Way back: the card reader only; no panel gesture, no network action.
- IPv6: the bypass is accepted; nothing turns IPv6 off.

---

# Part 2 — Milestone 7: Pi-hole API subset

**Done when:** qnet, pointed at qberrypi's address on port 443 with its pin
renewed once to qberrypi's own certificate, and with the same app password
in the keyring, shows the statistics, the 24-hour graph and the upstreams,
and pauses and resumes blocking, with no change to qnet's code.

## What qnet does

Read from qnet's source, read-only. qnet is the owner's private project, so
this describes its behaviour only.

- **Transport.** HTTPS to port 443, never port 80. The server's certificate
  is trusted by a SHA-256 pin of the leaf certificate's DER, with no name or
  date check; the handshake signature is still verified. The client is
  `rustls` with its `ring` provider and its default protocol versions
  (TLS 1.2 and 1.3). One deadline of 3 s covers each request, connect and
  handshake included. GETs reuse a kept-alive connection and fall back to a
  fresh one; other methods use a fresh `Connection: close` connection.
  Response bodies over 256 KiB are refused. *(Pi: qnet's stored pin is the
  SHA-256 of Pi-hole's own leaf certificate.)*
- **The pin's home.** qnet keeps the pin as a value in the Pi-hole section
  of its own configuration file. It accepts 64 hex digits, with or without
  colons, in either case, and writes them as colon-separated upper-case
  pairs. It reads its configuration again on start, whenever its panel is
  opened, and on a refresh. Its interactive setup is where a pin is normally
  taken (it shows the certificate's fingerprint and asks for "yes" when it
  changed), but against qberrypi setup stops before it saves anything (see
  below).
- **Login.** `POST /api/auth` with `{"password": ...}` (the app password from
  the desktop keyring). It reads `session.valid` and `session.sid`; the sid
  must be visible ASCII, at most 512 bytes. The sid travels in the
  `X-FTL-SID` header. A 401 or 403 is an authentication failure; a 429 is
  "rate limiting". After a 401 on another call it logs in once more, and only
  once. It keeps the sid in a private file and, on start, checks it with
  `GET /api/auth` (`session.valid`), so a restart does not use a new
  session. It ends with `DELETE /api/auth`, ignoring the answer.
- **Polling**, only while its panel is open: every 10 s
  `GET /api/stats/summary` (reads `queries.total`, `queries.blocked`,
  `queries.percent_blocked`) and `GET /api/dns/blocking` (`blocking`,
  `timer`); every 60 s `GET /api/history` (`history[].timestamp`, `total`,
  `blocked`, oldest first; it keeps the newest 144 buckets and expects
  ten-minute buckets labelled by their centre) and `GET /api/stats/upstreams`
  (entries `ip` `blocklist` and `cache` give the split; other entries need
  a parseable `ip`, a `port` in 1–65535 and a numeric `count`, and may have
  `name` and `statistics.response` in seconds; also `forwarded_queries`). An
  upstreams failure does not fail the poll. qnet subtracts its own probe
  queries, which it tallies over a rolling 24 hours, so the summary's counts
  must cover the last 24 hours, as Pi-hole's do.
- **Pause and resume:** `POST /api/dns/blocking` with
  `{"blocking": false, "timer": <seconds>}` or `{"blocking": true, "timer": null}`;
  it reads the answer like the GET. It always pauses with a timer.
- **Liveness:** when DNS stops answering, a `GET /api/dns/blocking` with no
  session. A completed pinned handshake means "alive", whatever the HTTP
  status, so a 401 is fine.
- **The canary.** qnet's health probe asks for `qnet-canary.invalid` and
  expects `0.0.0.0` or the server's own address. If that is not blocked, it
  asks for its configured canary (a name on the blocklists), and if that is
  blocked, it uses that one, looking for the dedicated name again every
  10 minutes. Only qnet's interactive setup adds the canary, through
  `POST /api/domains/deny/exact`.
- **Setup only:** `GET /api/config/webserver/api`, `GET /api/auth/app` (makes
  an app password), `PATCH /api/config`, and the deny-list POST above.
  Setup logs in with the web password, and reading the app-password setting
  is its third step: if that fails, setup stops with "nothing was changed".

## Threat model

The API is reachable by every device on the home network, over TLS with a
certificate of qberrypi's own that qnet pins. It protects against one thing:
such a device reading statistics or the household's queries and devices,
pausing blocking, or guessing its way in without the password. It does not
protect against someone holding the SD card, which keeps the Wi-Fi
passphrase, the TLS key and the password hash in plain files.

(The milestone's brief assumed the API port has no TLS today. Pi-hole serves
the API both on port 80 in plain HTTP and on port 443 with TLS, and qnet
uses only 443.)

## Port and TLS

- The API is served on **443 only, with TLS** (the owner's answer). Port 80
  stays the read-only status page with the open totals. Its `/api/*` paths
  other than `/api/v1/stats` answer 404, or 403 for `/api/v1/queries`.
- **The certificate is qberrypi's own, made once on the PC.**
  `cargo xtask make-cert` makes an ECDSA P-256 key and a self-signed
  certificate. The subject is the configured host name; the alternative
  names are that name and `net.address`. It is valid from an hour before it
  was made to 9999-12-31, the value RFC 5280 gives for "no expiry"; qnet
  checks no dates. P-256 because its signatures are the cheapest of the
  curves the provider signs with, and qnet's client verifies them.
  - The key and the certificate go into `qberrypi-tls.pem`, beside
    `qberrypi.toml` in the working directory, created with mode 0600. Like
    `qberrypi.toml` it is git-ignored and never enters `out/`.
  - The tool refuses to replace an existing file without `--replace`, which
    warns that qnet must then be pinned again.
  - Generation on the Pi cannot work: a permanent system never writes the
    card, so a key made at boot would change at every boot and break the pin
    each time.
- **Deploy** checks that the file loads as a server certificate, stages it
  as `tls.pem` with its own line in `SHA256SUMS`, and so the card gets it
  with the same read-back check as every other file. The stage, holding the
  key as it holds the passphrase, is removed however the script ends.
  `deploy` prints `deploy: <host>: the API's certificate pin (SHA-256): AB:CD:…`
  on every deploy that carries it. The key sits on the FAT partition, as the
  Wi-Fi passphrase does. init reads `qberrypi/tls.pem` with `qberrypi.toml`,
  in the same read-only mount.
- **Re-pinning qnet, once.** The owner replaces the pin value in the Pi-hole
  section of qnet's configuration with the fingerprint `deploy` or
  `make-cert` printed (the colon form can be pasted as it is), then opens
  qnet's panel, which reads the configuration again. qnet's setup cannot do
  it: against qberrypi it stops before saving. While the Pi is on Raspberry
  Pi OS after a return, qnet's statistics report a certificate mismatch
  until it is back on qberrypi.
- TLS is `rustls` with the `rustls-rustcrypto` provider that milestone 3
  already uses for list downloads. Its key exchange groups are X25519, P-256
  and P-384, which qnet's client offers. Certificates are parsed from PEM
  with `rustls-pki-types`. A server checks no dates, so it works before SNTP
  has set the clock. The default session cache gives resumed handshakes,
  which skip the signature.
- A TLS connection is one blocking job, as milestone 3's client
  connections are. The handshake's signature is one indivisible step,
  estimated at tens of milliseconds in pure Rust on this processor. At most
  2 API connections are open at a time; more wait in the listen queue. Each
  connection has 5 s for its handshake, takes up to 100 requests, closes
  after 5 s idle, and lives at most 60 s. The blocking pool grows from
  3 threads to 5 (amending ruling 8 of the execution order): one for the
  panel, two for lists, two for the API. A missing or broken `tls.pem` leaves
  the API off, with one error line. DNS is not affected.

## Authentication

- **One password**, the app password qnet already holds. The owner pipes it
  once into `cargo xtask hash-password`, which prints
  `password_hash = "$pbkdf2-sha256$i=100000$<salt hex>$<hash hex>"` for the
  `[api]` section of `qberrypi.toml` (PBKDF2-HMAC-SHA256, 100,000 rounds,
  16-byte random salt, 32-byte hash). The tool refuses to read from a
  terminal, so the password is never echoed or left in shell history.
  qberrypi does not use Pi-hole's own hashes: they are in a Balloon-SHA256
  format, and matching FTL's implementation exactly would be its own project.
  No `[api]` section means no API: port 443 is not opened.
- **Never logged.** The hash is a `Secret` like the passphrase (redacted in
  `Debug`, never in an error message). No password, sid or request body
  appears in a log line, and, since `/log` is open, no client address does
  either. The log says `api: login accepted`, `api: login refused`,
  `api: logins from one address held back for 60 s`,
  `api: all logins held back for 60 s`.
- **Verification** is one blocking job (about 0.2 s of one core on this
  board), one at a time, with a constant-time comparison.
- **Sessions:** a sid is 16 bytes from the kernel's random source, as 32 hex
  digits. It lasts 1,800 s, and each authenticated request extends it, as
  Pi-hole's default `webserver.session.timeout` does *(Pi: 1800)*. At most
  16 sessions *(Pi: `max_sessions` 16)*; a seventeenth login ends the least
  recently used session, rather than refusing with 429, so the owner is never
  locked out by abandoned sessions. Sessions live in memory: a restart ends
  them, and qnet logs in again after its next 401. Monotonic time; a wall
  clock step changes nothing.
- **The sid is accepted only in `X-FTL-SID`.** No cookie, so no CSRF token is
  needed; `csrf` is `null` in answers. No `sid` query parameter, which would
  land in URLs.
- **Every API endpoint but the login needs a valid session**, reads
  included, as on Pi-hole. Without one: 401
  `{"error":{"key":"unauthorized","message":"Unauthorized","hint":null},"took":…}`,
  and nothing changes.
- **Rate limiting:** per source address, 5 failed logins within 60 s hold
  that address back for 60 s. Overall, 30 failures in 60 s hold back every
  address for 60 s, so many spoofed addresses cannot multiply the rate. Both
  answer 429
  `{"error":{"key":"rate_limiting","message":"Rate-limiting login attempts","hint":null}}`
  without checking the password. The per-address table holds at most 64
  addresses. With the one-at-a-time verification, a guesser gets at most
  30 tries a minute. A 44-character random app password makes that
  irrelevant; a weak one would not be.

## The subset, endpoint by endpoint

Shapes follow Pi-hole's API documentation, the OpenAPI specification shipped
in FTL (`src/api/docs/content/specs/` in `github.com/pi-hole/FTL`: `auth.yaml`,
`stats.yaml`, `history.yaml`, `dns.yaml`; served by every Pi-hole at
`/api/docs`), and the live Pi-hole v6 answers qnet's tests record *(Pi: Core
v6.5, FTL v6.8)*. Every answer is `application/json` and carries
`"took"`, the seconds spent, as Pi-hole's do.

| Endpoint | qberrypi answers |
|---|---|
| `POST /api/auth` | Body `{"password": string}` (`totp` ignored). Right: 200 `{"session":{"valid":true,"totp":false,"sid":"<32 hex>","csrf":null,"validity":1800,"message":"password correct"}}`. Wrong: 401 with the same object, `valid` false, `sid` null, `validity` −1, `message` `"password incorrect"`. Held back: 429. Body not JSON or no `password` string: 400. |
| `GET /api/auth` | Valid sid: 200 `{"session":{"valid":true,"totp":false,"sid":null,"csrf":null,"validity":<seconds left>,"message":null}}`. Otherwise 401 with `valid` false, `validity` −1. |
| `DELETE /api/auth` | Valid sid: 204, the session ended. Otherwise 401. |
| `GET /api/stats/summary` | `{"queries":{"total","blocked","percent_blocked","forwarded","cached","frequency"},"clients":{"active","total"},"gravity":{"domains_being_blocked","last_update"}}`. Counts are of the last 24 hours. `percent_blocked` is `blocked / total × 100` (0 with no queries). `cached` includes queries answered locally, as Pi-hole's "from cache or local configuration" does. `frequency` is `total / 86400`. `clients` comes from part 1's table (`active` = seen in 24 h, `total` = held). `gravity` gives the block set's size and the list fetch time (0 until known). Left out: `unique_domains`, `types`, `status`, `replies` (not counted; qnet reads none). |
| `GET /api/history` | `{"history":[{"timestamp","total","cached","blocked","forwarded"}, …]}`: 144 ten-minute buckets, oldest first, ending with the current one, `timestamp` the bucket's centre (`start + 300`), empty buckets as zeros. |
| `GET /api/stats/upstreams` | `{"upstreams":[…],"forwarded_queries","total_queries"}`. First `{"ip":"blocklist","name":"blocklist","port":-1,"count":<blocked, 24 h>,"statistics":{"response":0,"variance":0}}`, then the same for `"cache"` (cached, 24 h), then one entry per configured upstream: `ip`, `name` the same as `ip` (no reverse lookup; qnet shows no name then), `port` 53, `count` its answers since boot, `statistics.response` its smoothed round trip in seconds (0 before its first answer), `variance` 0. The two totals are of 24 h. |
| `GET /api/dns/blocking` | `{"blocking":"enabled","timer":null}`, or while paused `{"blocking":"disabled","timer":<seconds left>}`. The same pause the panel's switch makes, on the resolver's own clock. |
| `POST /api/dns/blocking` | `{"blocking": true}` resumes. `{"blocking": false, "timer": n}` pauses for n seconds, rounded up, 1 ≤ n ≤ 86,400. Answers like the GET. `blocking` missing or not a boolean: 400 `{"error":{"key":"body_error","message":"No \"blocking\" boolean in body data","hint":null}}`. Pause with `timer` null or missing, or out of range: 400 `bad_request`, `"message":"a pause needs a timer of 1 to 86400 seconds"`. There is no endless pause: the panel shows a countdown, and qnet always sends a timer. |
| `GET /api/v1/queries?n=` | qberrypi's own, moved here from port 80 by the owner's rule: the most recent queries, newest first, as milestone 4 defined them (`unix_secs`, `name`, `qtype`, `outcome`; `n` 1–1000, default 100). |
| `GET /api/v1/clients` | qberrypi's own: part 1's table, most recently seen first, `{"address","queries","last_seen_secs"}`. |
| anything else under `/api/` | Without a session 401, with one 404 `not_found`. A wrong method on a known path: 405. Outside `/api/`: 404. |

**Not implemented, and how qnet copes:**

- `POST /api/domains/deny/exact` and the rest of the domain lists. Deny and
  allow entries live in `qberrypi.toml`, on a card a permanent system never
  writes, so an API entry could only live in memory and vanish at the next
  restart. No client of the owner's needs one in normal running: qnet adds
  its canary only during setup. The canary instead goes into `dns.deny` in
  `qberrypi.toml` at cutover, so it is blocked from the first query after
  every boot. If it were missing, qnet would fall back to its configured
  canary, as described above, and stay healthy.
- `GET /api/config/webserver/api`, `GET /api/auth/app`, `PATCH /api/config`:
  setup only. Against qberrypi, qnet's setup stops at its third step having
  changed nothing (and before that, its web-password login fails: qberrypi
  knows only the app password). The pin is renewed by hand instead (above).
  To change qberrypi's password: `cargo xtask hash-password`, then a deploy.
- Two-factor login, cookie sessions, `/admin`, and every other endpoint.

## Pi checks of milestone 7

On a one-shot boot with `[api]` set, at qberrypi's usual address, after the
owner has pinned qnet to the fingerprint `deploy` printed. The owner opens
qnet's panel and sees the numbers (equal to the API's own
`/api/stats/summary`, less qnet's own probes, within one poll), the graph,
the upstreams, and `blocking` on. A pause from qnet pauses the front panel's
switch and the reverse. A `dig` of a listed name answers `0.0.0.0`, then a
real address while paused. Five wrong passwords from the PC are refused with
401; the sixth attempt, even with the right password, is held back with 429.
`/api/v1/queries` and `/api/v1/clients` answer 401 without a session and 200
with one; port 80's `/api/v1/queries` answers 403. A login's round trip,
handshake included, is under 1.5 s. The log has no sid, password, hash or
client address.

## The owner's answers (part 2)

- Certificate: a new one of qberrypi's own; Pi-hole's certificate and key
  are not copied; qnet is re-pinned once.
- Per-query and per-device data (`/api/v1/queries`, `/api/v1/clients`) need
  the API login; the totals stay open.
- No plain-HTTP API on port 80.
- No network "return to Raspberry Pi OS" (part 1).
