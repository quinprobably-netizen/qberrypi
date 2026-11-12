# qberrypi watchdog: threat blocking, behaviour alerts, device watch, private lookups

Date: 2026-11-11. Status: approved by the owner in conversation; this file records it.

## Intent

The owner wants qberrypi to be "a full security watchdog in a 3B+", with more speed and privacy, and
**nothing that causes a speed regression**. The Pi is a Wi-Fi client on the home network, not the
gateway: it sees every DNS question sent to it, plus broadcast and multicast traffic on the Wi-Fi
(ARP, DHCP, mDNS). It does not see other devices' connections. Everything below works within that.

Alerts go to the front panel and to the owner's PC through qnet. Nothing leaves the home network
except the encrypted lookups to the upstream resolver and the list downloads.

## Hard rules

1. **No latency regression.** The hot path (cached, blocked and forwarded answers) does not wait on
   any watchdog work. Each answered question is offered to the analysis side through a bounded,
   non-blocking channel; when the channel is full the event is dropped and counted
   (`watch_events_dropped` in the stats). A feature merges only after `cargo xtask latency --compare`
   against same-evening stock passes still exits 0 in both pacings (ruling 17).
2. **No card writes in permanent mode** (milestone 4/5). Watchdog state lives in RAM. State that must
   survive a reboot (known devices, acknowledged alerts) is held by qnet on the PC and pushed back.
3. **Privacy.** The PC fetches per-query and per-device data only through the API login (ruling 16).
   Logs never name a client address together with a query name. Nothing is written to the card.
4. **One binary.** All of it is in the qberrypi executable as supervisor components, with analysis
   on the blocking pool or its own component future. No new C dependencies, and `unsafe` stays only
   in `sys.rs`.

## 1. Threat blocking

- A second list class, **threat**, beside **ads**. The default configuration adds a threat
  intelligence feed (malware, phishing, scam) and a newly-registered-domains feed, chosen by the plan
  from maintained public lists. The source URLs go in `qberrypi.example.toml`.
- One block set holds both. Each entry carries its class (one bit), so a lookup costs the same.
- A blocked answer is the same for both classes. A **threat** hit also raises an alert (§5), at most
  one per client per name per hour.
- The snapshot in the image includes threat names if `initramfs8` stays under its budget. The plan
  measures this and rules on raising the 6 MB budget or shipping threats through the first refresh
  only.
- `/api/v1/stats` gains `blocked_threat_today`.

## 2. Behaviour alerts (per client, in RAM)

The analysis keeps a small bounded state per client address (cap the number of clients and the state
per client; evict the least recently seen). Thresholds are constants with tests, chosen by the plan
to be quiet on a normal household:

- **Malware-style random names (DGA):** many NXDOMAIN answers for high-entropy or unpronounceable
  labels within a few minutes.
- **DNS tunnelling:** many unique long labels under one registrable domain, or a high share of
  TXT/NULL questions.
- **Beaconing:** one name asked at near-constant intervals (low jitter) for hours. Lower severity.
  Names the owner marks as fine, and an allow list of common periodic services, are skipped.
- **Burst:** a client's question rate far above its own moving baseline.
- **DNS rebinding:** a forwarded answer for a public name that holds a private, loopback or
  link-local address is replaced with a blocked answer and raises an alert. Exception: names on a
  configurable allow list (for example the router's own name).

## 3. Device watch

- A component opens packet sockets on wlan0 for ARP and listens for DHCP (UDP 67/68) and mDNS
  (UDP 5353). It builds an inventory of MAC address → IPv4 address(es), host name (DHCP option 12 or
  mDNS), first seen and last seen.
- **New device:** a MAC address not in the known list raises an alert.
- **Router impersonation (ARP spoofing):** a MAC address other than the gateway's claiming the
  gateway's IPv4 address, or the gateway's MAC changing, raises a high-severity alert.
- **Known list:** qnet sends it with `PUT /api/qbp/devices/known` after each boot and when the owner
  marks a device as known. Until qnet has sent it after a boot, new-device alerts are held, not shown,
  and released or dropped once the list arrives. Without qnet, the Pi learns silently for its first
  10 minutes after boot.
- `GET /api/qbp/devices` (login) returns the inventory.

## 4. Private lookups

- **DNS-over-TLS to the upstreams** (port 853, with the provider's TLS name from configuration):
  - one persistent connection per upstream, kept warm, with questions pipelined under distinct IDs;
  - the hedged exchange (ruling 17, amended) applies across connections;
  - reconnects use session resumption, with a bounded backoff.
- DoT ships enabled only if the latency acceptance passes with it. Otherwise it stays in the code
  behind `upstream.tls = false`, and the result is recorded in `latency-baseline.md`.
- **No client hints upstream:** strip any EDNS Client Subnet option from forwarded questions, and send
  no ECS of our own.
- **Encrypted-DNS bypass:**
  - answer NXDOMAIN for `use-application-dns.net`, the canary browsers use to turn off their own DoH;
  - block a maintained list of public DoH resolver names, so devices fall back to the Pi;
  - each of these can be turned off in configuration.

## 5. Alerts

- An alert store in RAM: a bounded ring holding kind, severity, client, subject, first and last time,
  and count. Repeats of the same kind, client and subject merge into one alert. Every kind has a rate
  limit.
- API (login):
  - `GET /api/qbp/alerts?since=` returns alerts;
  - `POST /api/qbp/alerts/{id}/ack` acknowledges one;
  - `PUT /api/qbp/alerts/acked` restores acknowledgements after a boot (sent by qnet).
- **Panel:** an unacknowledged alert takes a band of the screen (the exact form follows the panel
  design the owner picks) until it is tapped away. A tap acknowledges it.
- **qnet** (separate repo, the owner's desktop plugin) polls the alerts endpoint, shows a desktop
  notification per new alert, keeps the known-device list and the acknowledgements, and pushes both
  back after the Pi boots.

## 6. Speed wins

- **Prefetch:** a cached name that has been asked at least N times in its TTL is refreshed upstream
  shortly before it expires, so the next question is a cache hit. The budget is bounded: at most a few
  prefetches per second, and none while forwards are queued.
- **CPU placement:** try pinning the runtime thread away from the core that takes the SDIO (Wi-Fi)
  and SPI interrupts. Keep it only if the latency comparison shows a gain.

## Order

1. Finish the running tracks (API on :443, cutover tooling) and the fault checks.
2. Two tracks in parallel worktrees:
   - **A:** threat blocking, DoT, ECS stripping, the bypass rules, prefetch;
   - **B:** device watch, behaviour analysis, the alert store and API.
3. The panel alert band (after the panel pick) and the qnet side.
4. Latency acceptance with everything on, then the cutover.

## Testing

- Unit tests for each detector with recorded-style synthetic traffic, including a "normal household"
  trace that must raise nothing.
- Device watch tests with crafted ARP, DHCP and mDNS frames.
- DoT against a local TLS test server.
- QEMU scenarios where they can run without Wi-Fi (the analysis fed from loopback DNS).
- The latency gate on the Pi for every track.
