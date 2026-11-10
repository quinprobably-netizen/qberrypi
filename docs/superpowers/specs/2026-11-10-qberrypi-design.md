# qberrypi — design

Date: 2026-11-10
Status: draft, awaiting owner review

## What it is

qberrypi is a single-purpose operating system for a Raspberry Pi 3 Model B+.
It turns the board into a network-wide DNS ad blocker, the job Pi-hole does
today. The Linux kernel is stock. Everything above the kernel is one static
Rust executable: the init process, the Wi-Fi supplicant, the network setup,
the DNS server and the status page. There is no shell, no package manager and
no other program on the system.

It is a curiosity project. It shares one SD card with an existing Raspberry
Pi OS install that runs Pi-hole: qberrypi's files sit in a `qberrypi/` folder
on the boot partition, and which system starts is decided by `config.txt`.
The existing install's root filesystem is never mounted or modified.

## Success criteria

1. Power on with qberrypi selected and no other intervention: the Pi joins
   the configured WPA2 network and answers DNS on its configured static
   address.
2. It blocks the same lists the Pi-hole card blocks, from the first query
   after boot.
3. Once made permanent, it never writes to the SD card, so cutting power at
   any moment cannot corrupt it.
4. It recovers from a lost Wi-Fi connection without a power-cycle.
5. The image contains exactly one userspace executable, written in Rust.
6. Time from power-on to the first answered query is measured and reported.
   The target is under 15 seconds; today's system takes about 45.
7. Restoring the saved `config.txt` brings the Pi-hole setup back exactly.
   During development this happens by itself: every qberrypi boot is
   one-shot, and the next restart returns to Raspberry Pi OS.

## What "all Rust" does and does not mean

Rust starts at PID 1. Below and beside it, four things are not Rust, and the
project does not pretend otherwise:

| Component | Why it stays |
|---|---|
| Raspberry Pi boot firmware (`bootcode.bin`, `start.elf`, `fixup.dat`) | Closed blobs the SoC needs to start at all. |
| Linux kernel and five kernel modules | A Rust kernel would need a USB or SDIO stack and a network driver written from scratch before it could answer one query. |
| Wi-Fi chip firmware (`cyfmac43455-sdio`) | Closed blob that runs on the radio chip itself. |
| musl libc, statically linked into the executable | Rust's standard library on Linux calls the kernel through a libc. |

Not present: BusyBox, a shell, systemd, `wpa_supplicant`, `iwd`, `dnsmasq`,
OpenSSL, any interpreter, any dynamic library.

## Non-goals for version 1

- Ethernet, IPv6 transport, DHCP client or server.
- WPA3 (SAE), protected management frames, enterprise Wi-Fi.
- A web admin UI, remote login, over-the-network updates.
- Encrypted upstream DNS (DoT/DoH), local DNSSEC validation.
- Any board other than the Pi 3 B+.
- Persisting anything across reboots.
- A flashable image for a blank card. Version 1 installs beside an existing
  Raspberry Pi OS and uses the boot firmware already on that card.

Each of these is a later project with its own design. The architecture below
leaves room for them but builds none of them.

## Architecture

### Boot chain

```
Pi boot firmware  ->  kernel8.img + device tree  ->  initramfs (cpio, zstd)
                                                        /init        the Rust executable
                                                        /dev/console, /dev/null  so init starts even with no console
                                                        /lib/modules 5 Wi-Fi modules, uncompressed
                                                        /lib/firmware Wi-Fi firmware, regulatory db
                                                        /blocklist.zst build-time list snapshot
```

The root filesystem is the initramfs, held in RAM. The card's FAT boot
partition is mounted once at boot to read the configuration, then unmounted.

### Sharing the card

The Pi firmware can load an operating system from a subfolder of the boot
partition (`os_prefix`). qberrypi uses that:

```
boot partition (FAT, shared)
  bootcode.bin, start.elf, fixup.dat   boot firmware, already there, shared
  config.txt                           the active configuration
  config.pios.txt                      saved copy of Raspberry Pi OS's config.txt
  kernel8.img, initramfs8, ...         Raspberry Pi OS's own files, untouched
  qberrypi/
    kernel8.img                        qberrypi's own pinned kernel
    bcm2710-rpi-3-b-plus.dtb
    initramfs8
    cmdline.txt
    qberrypi.toml
    config.txt                         qberrypi's config, copied over the active one to select it
    log.txt                            only when debug.log_to_sd is on
```

Selecting qberrypi means copying `qberrypi/config.txt` over `config.txt`.
That file is minimal: 64-bit mode, `os_prefix=qberrypi/`, and no graphics
overlay, so the kernel's built-in framebuffer console works without loading
a display driver. Selecting Raspberry Pi OS means copying `config.pios.txt`
back. If the kernel or device tree is missing from the folder, the firmware
ignores the prefix by design and starts Raspberry Pi OS's kernel instead.

qberrypi carries its own kernel copy, so a kernel upgrade on the Raspberry
Pi OS side cannot break the match between qberrypi's kernel and its modules.

### One-shot boots and the development loop

While `debug.one_shot` is on, init copies `config.pios.txt` back over
`config.txt` as soon as it has read its configuration, before loading any
driver. From that moment any
restart, for any reason, returns to Raspberry Pi OS. Development then runs
without touching the card:

1. `cargo xtask deploy` copies the built `qberrypi/` folder to the running
   Raspberry Pi OS over SSH, selects qberrypi, and reboots the Pi.
2. qberrypi boots once. If the network comes up, it is inspected through
   its status page. Either way it appends its log to `qberrypi/log.txt`.
3. After `debug.return_after_secs`, or on a fatal error, or when the power
   is cycled, the Pi restarts into Raspberry Pi OS.
4. `cargo xtask collect` fetches the log over SSH.

`deploy` waits for step 3 and does step 4 itself. Before it fetches the log
it checks that `config.txt` is the saved one again, which it is not if the
firmware ignored the prefix and started Raspberry Pi OS's kernel. Afterwards
it checks that the last boot in the log is of the build it sent: a boot's
entry in the log starts with one header line that names the build time.

Making qberrypi permanent is turning `debug.one_shot` and
`debug.log_to_sd` off. Only then does success criterion 3 hold.

### Process model

One process. It is PID 1 and never forks a long-lived child. Inside it, an
async runtime (tokio) runs the components as tasks under one supervisor.

The executable is multi-call. The kernel occasionally asks userspace to load
a module by running a helper program. qberrypi registers itself as that
helper, so when it is started with PID other than 1 it acts as a minimal
module loader and exits. This is what lets the Wi-Fi driver pull in its
vendor sub-module without a `modprobe` binary.

### Components

Each component has one job and a narrow interface, so it can be tested
without the others.

| Component | Job | Depends on | Tested |
|---|---|---|---|
| `init` | Mount `/proc`, `/sys`, `/dev`; console; load modules; pet the hardware watchdog; reboot. | kernel | QEMU boot test |
| `config` | Parse `qberrypi.toml` into typed settings; reject bad values with a clear message. | none | unit |
| `netlink` | Thin client for route netlink and nl80211. | kernel | namespace test |
| `wpa2` (own crate) | WPA2-PSK handshake as a pure state machine: bytes in, bytes and keys out. No sockets. | none | unit, published vectors, a captured real handshake |
| `wifi` | Scan, pick an access point, connect, run `wpa2` over a packet socket, install keys, watch for disconnects. | `netlink`, `wpa2` | simulated-radio VM, real Pi |
| `net` | Bring interfaces up, set the static address and default route, set the clock by SNTP. | `netlink` | namespace test |
| `dns` (own crate) | Answer queries: block, serve from cache, or forward. | none (sockets passed in) | unit, integration on the dev machine |
| `lists` | Load the snapshot; fetch lists over HTTPS; parse hosts and adblock formats; build the block set. | `dns` types | unit, integration |
| `status` | Read-only HTTP status page and JSON. | shared stats | integration |
| `supervisor` | Start components in order, restart failed ones, own the reboot policy and the LED. | all | unit, QEMU |
| `xtask` (dev-machine tool) | Fetch pinned kernel and firmware files, build the initramfs and the `qberrypi/` boot folder, deploy it and collect logs. | none | builds an image from small fixture packages |

`wpa2` and `dns` are separate crates because each is useful and testable
with no knowledge of the rest. The others are modules of the main crate.

## Boot sequence

1. Mount `/proc`, `/sys`, `/dev`, a tmpfs at `/run`. Open the console.
2. Set the clock to the image build time, so it is never earlier than that.
3. Wait for the kernel to find the card, for up to two minutes. Mount the
   boot partition read-only, read `qberrypi/qberrypi.toml`, unmount. In
   one-shot mode, remount it writable, restore `config.txt`, sync and
   unmount. With `debug.log_to_sd` on, the log so far is appended in that
   same writable mount (in one of its own when one-shot mode is off), so a
   boot that dies in a later step has left its first lines on the card. If
   the configuration cannot be read or parsed, the restore happens anyway,
   so a bad file cannot strand the Pi in qberrypi.
4. Open the hardware watchdog with a 15-second timeout. This comes after
   the restore on purpose: a board that misbehaved when the watchdog
   started would otherwise reset before `config.txt` was put back, on
   every boot. A missing watchdog is logged, not fatal.
5. Register as the kernel's module helper. Load `rfkill`, `cfg80211`
   (with the configured country), `brcmutil`, `brcmfmac`. The driver then
   requests the fifth module, its vendor sub-module `brcmfmac-cyw`, through
   the helper.
6. Load the blocklist snapshot and start the DNS server. It is ready before
   the network is.
7. Join Wi-Fi (next section). Set the static address and default route.
8. Set the clock by SNTP.
9. Start the status server and the list refresher.

A failure in steps 1 to 5 is fatal, the missing watchdog aside: the message
goes to the console, `config.txt` is restored where the rules below say so
(waiting up to half a minute for the card, if the failure came before the
kernel had found it), and the board restarts after five seconds. From step 6 on, failures are
handled by the supervisor.

## Wi-Fi

The Pi's radio (Broadcom/Cypress 43455, `brcmfmac` driver) is a FullMAC
device: association runs in the chip's firmware, but this firmware does not
perform the WPA2 key handshake. qberrypi therefore implements the supplicant
side itself.

Sequence:

1. Wait for `wlan0`, bring it up, turn power save off.
2. Scan. From the results, choose the strongest access point advertising
   the configured network name with WPA2-PSK and CCMP.
3. Ask the kernel to connect, supplying qberrypi's own RSN element.
4. Run the four-way handshake over a packet socket bound to the EAPOL
   ethertype:
   - derive the PMK from the passphrase and network name (PBKDF2-HMAC-SHA1,
     4096 rounds), or take it directly from the configuration;
   - derive the PTK from the PMK, both addresses and both nonces;
   - verify and produce message integrity codes (HMAC-SHA1);
   - unwrap the group key from message 3 (AES key wrap).
5. Install the pairwise and group keys through nl80211. Mark the link
   operational.
6. Keep listening: answer group-key rekeys and repeat handshakes, and react
   to disconnect events.

All cryptography comes from the RustCrypto crates (`pbkdf2`, `hmac`, `sha1`,
`aes-kw`). Nonces come from the kernel's random source.

Scope is deliberately narrow: WPA2-PSK, CCMP, no protected management
frames. That is what the target network uses. Anything else is rejected at
scan time with a clear log line.

## Network

Static IPv4 only: one address, one default route, both from the
configuration. Name resolution for qberrypi's own needs (time servers, list
hosts) goes through its own DNS forwarder, whose upstreams are IP addresses,
so there is no bootstrap problem.

The clock has no battery. Until SNTP succeeds it runs from the image build
time, and HTTPS list downloads wait for SNTP.

## DNS

Listens on UDP and TCP port 53. For each query:

1. If the name, or a parent domain covered by a subdomain rule, is in the
   block set and not in the allow set: answer `0.0.0.0` for A and `::` for
   AAAA, and an empty success for other types.
2. Otherwise, if a fresh answer is cached, serve it.
3. Otherwise, if a stale answer under one hour old is cached, serve it and
   refresh in the background.
4. Otherwise forward to an upstream over UDP, retrying over TCP when the
   answer is truncated, and fall over to the next upstream on timeout.

Also: single-label names and reverse lookups for private address ranges are
answered locally and never forwarded. Message parsing uses `hickory-proto`.

The cache is bounded (10,000 entries, least recently used evicted). Counters
and the last 50,000 queries are kept in memory for the status page and are
lost on reboot by design.

## Blocklists

Two formats are understood: hosts files, and adblock-style `||domain^`
rules, which also cover subdomains. The compiled block set is an exact-match
set plus a suffix-match set, held in memory (about 300,000 names, roughly
25 MB).

- **At build time**, `xtask` downloads the configured lists and stores the
  merged result in the image. Blocking therefore works from the first query,
  with no network.
- **At run time**, the lists are refetched over HTTPS once a day and the new
  set is swapped in atomically. A failed fetch keeps the current set.

HTTPS uses `rustls` with the pure-Rust `rustls-rustcrypto` provider and the
bundled Mozilla root certificates. That provider has not had a security
audit. The only thing it protects here is the download of public blocklists,
where the worst outcome of a broken connection is a wrong list. If it proves
unworkable on this target, the fallback is the `ring` provider, which adds
C and assembly to the executable.

## Status

A read-only HTTP server on port 80, with no authentication, reachable from
the local network:

- `/` — plain page: uptime, Wi-Fi access point and signal, queries answered,
  share blocked, cache hit rate, upstream latency, list age and size.
- `/api/v1/stats` — the same as JSON.
- `/api/v1/queries?n=` — the most recent queries.
- `/log` — the system log, kept in a fixed-size in-memory buffer.

Nothing on this server changes state in version 1.

## Configuration

One file, `qberrypi.toml`, on the SD card's FAT partition, editable from any
computer. The repository carries `qberrypi.example.toml`; the real file is
ignored by git because it holds the Wi-Fi passphrase.

```toml
hostname = "qberrypi"

[wifi]
ssid = "example-network"
passphrase = "example-passphrase"   # or: pmk = "<64 hex digits>"
country = "US"

[net]
address = "192.0.2.53/24"
gateway = "192.0.2.1"

[dns]
upstreams = ["9.9.9.9", "149.112.112.112"]
lists = [
  "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
  "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
]
deny = []
allow = []

[debug]
one_shot = false          # restore Raspberry Pi OS's config.txt at every boot
log_to_sd = false         # append the log to qberrypi/log.txt
return_after_secs = 0     # restart after this long; 0 means never
```

The passphrase sits in plain text on the card, as it does on a stock
Raspberry Pi OS card.

## Failure handling

| Failure | Response |
|---|---|
| Any fatal error or panic in PID 1 | Message to console; kernel reboots after 5 seconds. |
| Supervisor stops making progress | Hardware watchdog resets the board within 15 seconds. |
| Wi-Fi disconnects | Rejoin immediately, then with backoff. |
| No Wi-Fi association for 90 seconds | Reboot. A reboot costs seconds and writes nothing. |
| Upstream times out | Try the next upstream; serve stale if available; otherwise SERVFAIL. |
| List fetch fails | Keep the current block set; retry in an hour. |
| A component task fails | Supervisor restarts it; three failures in a minute become a reboot. |
| Bad or missing configuration | Fatal at boot, with the offending key named on the console; `config.txt` is restored first, as in one-shot mode. |

The activity LED shows state without a screen: slow heartbeat when serving,
fast blink while joining Wi-Fi, solid on a fatal error.

The two development switches are the only things that write to the card:
`debug.one_shot` rewrites `config.txt` once per boot, and `debug.log_to_sd`
appends the log to `qberrypi/log.txt` so a failed Wi-Fi bring-up can be read
back afterwards. Each write is followed by a sync and an unmount. Both are
off by default.

## Image build

`cargo xtask build` on the development machine:

1. Download pinned, checksummed versions of the official Raspberry Pi
   packages for the kernel with its modules, the Wi-Fi firmware and the
   regulatory database. Nothing from them is committed to this repository.
2. Extract the kernel, the device tree and the five modules; decompress the
   modules; generate the module dependency and alias table the loader uses.
3. Cross-compile the executable for `aarch64-unknown-linux-musl`.
4. Build the blocklist snapshot.
5. Pack the initramfs.
6. Write `out/qberrypi/`, the folder that goes onto the boot partition.

`cargo xtask deploy` and `cargo xtask collect` are the development loop
described above. The real `qberrypi.toml` is read from the working
directory at deploy time, is ignored by git, and never enters a build
output that could be shared.

## Testing

Three rings, from cheapest to most real.

1. **On the development machine, no privileges.** Unit tests for every pure
   component. The `wpa2` crate is checked against the published IEEE
   key-derivation vectors and against a publicly available capture of a
   real handshake with a known passphrase. DNS is tested end to end against
   a fake upstream. Init and network setup run inside unprivileged user,
   mount and network namespaces.
2. **In virtual machines.** An aarch64 QEMU machine boots the real Pi
   kernel and the real initramfs to prove the boot path. A second VM, with
   the kernel's simulated Wi-Fi radios, runs the Wi-Fi component against a
   reference access point (`hostapd`, used only as test equipment). Nothing
   touches the development machine's own radios.
3. **On the Pi.** One-shot boots from the shared card. The simulated radio
   is a different driver class from the Pi's chip, so the real board is the
   final word on Wi-Fi. The SD log, the HDMI console and the LED exist to
   make this ring debuggable without a network.

Every milestone below is finished only when its ring-3 check passes on the
real board.

## Repository layout

```
Cargo.toml                 workspace
crates/qberrypi/           the executable: init, config, netlink, wifi, net,
                           lists, status, supervisor
crates/qb-wpa2/            WPA2-PSK supplicant state machine, no I/O
crates/qb-dns/             DNS decision logic, cache, block set
xtask/                     image builder
qberrypi.example.toml
docs/
```

## Milestones

Each one ends with something observable on the real Pi and gets its own
implementation plan.

| # | Name | Done when |
|---|---|---|
| 0 | Boot | A deploy boots the Pi once into the Rust init, which shows a banner on HDMI, blinks the LED, writes its log and returns to Raspberry Pi OS by itself. |
| 1 | Wi-Fi | The Pi joins the network unaided and answers ping on its static address. |
| 2 | Resolver | It forwards and caches DNS; the clock is set. |
| 3 | Blocker | It blocks from the snapshot and refreshes lists over HTTPS. |
| 4 | Resilience | Status page, watchdog, rejoin and reboot policies; survives pulled power and a restarted access point. |
| 5 | Pi-hole API subset | Existing Pi-hole clients that only read statistics and toggle blocking work unchanged. Needs its own design. |

Milestone 1 carries most of the risk and is attempted first for that reason.

## Risks

| Risk | How it is retired |
|---|---|
| Key installation and event behaviour on the FullMAC chip differs from the simulated radio. | Read the reference supplicant's driver code for this path before writing ours; verify on the Pi with the SD log. |
| The Wi-Fi driver's request for its vendor sub-module does not work through our helper. | Tested in milestone 0 on the real board, before any supplicant code depends on it. Fallback: load the sub-module explicitly, first. |
| The netlink crate (`neli`) lacks something nl80211 needs. | First task of milestone 1 is a spike that sends each required command. Fallback: an in-tree encoder; the message format is simple. |
| `rustls-rustcrypto` fails to build or handshake on this target. | Checked at the start of milestone 3. Fallback: `ring`. |
| The pinned package versions cannot be fetched reproducibly. | Milestone 0 pins and checksums them; fallback is copying the same files from the running Raspberry Pi OS install. |
| A build dies before it restores `config.txt`, so the Pi keeps restarting into it. | Restoring is init's first action after mounting the card, and the boot path is proven in QEMU before any deploy. Recovery is copying `config.pios.txt` over `config.txt` with the card in another computer. |
| A power cut during one of the development-mode writes damages the shared boot partition. | Writes are tiny, synced and immediately unmounted; they stop entirely once qberrypi is made permanent. A copy of the boot partition's files is taken before the first deploy. |
| The framebuffer console does not appear without the graphics overlay. | Checked on the screen in milestone 0; the SD log and LED do not depend on it. |

## Licence

MIT.
