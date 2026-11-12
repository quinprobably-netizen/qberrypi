# qberrypi

A single-purpose operating system for the Raspberry Pi 3 B+ that turns the
board into a network-wide DNS ad blocker. The Linux kernel is stock;
everything above it is one static Rust executable: init, Wi-Fi supplicant,
network setup, DNS server and status page. No shell, no other programs.

**Status: all milestones done; it runs permanently on the Pi it was built for.** It joins the
Wi-Fi network by itself, forwards over DNS-over-TLS and caches, blocks ads and threat lists from the
snapshot in its image and refreshes them daily, survives pulled power and lost links, draws a live
front panel on a 3.5-inch touchscreen, watches the network for new devices and suspicious lookups,
and serves a Pi-hole-compatible API over HTTPS. Notes: [milestone 0](docs/bring-up/m0.md),
[milestone 1](docs/bring-up/m1.md), [milestones 2 and 3](docs/bring-up/m2-m3.md),
[milestones 4 and 5](docs/bring-up/m4-m5.md), [milestone 6](docs/bring-up/m6.md),
[latency against Pi-hole](docs/bring-up/latency-baseline.md).
Milestone 8 puts qberrypi on the card alone, in two slots, and updates it over the network
(`cargo xtask update`, with a trial boot and an automatic rollback). It is built and its trials run
under QEMU; its checks on the Pi are listed in [milestone 8](docs/bring-up/m8-only-os.md) and have not
been run yet.
The design is in
[`docs/superpowers/specs/2026-11-10-qberrypi-design.md`](docs/superpowers/specs/2026-11-10-qberrypi-design.md);
the security watchdog's is in
[`docs/superpowers/specs/2026-11-11-qberrypi-watchdog-design.md`](docs/superpowers/specs/2026-11-11-qberrypi-watchdog-design.md);
the card with two slots and the network update are in
[`docs/superpowers/specs/2026-11-11-qberrypi-only-os-design.md`](docs/superpowers/specs/2026-11-11-qberrypi-only-os-design.md).

## Install

The card holds qberrypi alone: the Pi's boot firmware and two slots, `qberrypi-a/` and `qberrypi-b/`,
each a complete copy of the kernel, the initramfs and your configuration. One card-reader trip puts
that on the card; every later update goes over the network (see Update). Everything below runs on
this PC, with the Pi switched off and its card in a USB reader. Bluetooth is absent by design: the
image has no Bluetooth module and no Bluetooth firmware, the module helper refuses every request for
one, and the device-tree node is disabled.

Copy `qberrypi.example.toml` to `qberrypi.toml` and fill it in; the file holds the Wi-Fi passphrase
and is ignored by git. A card that is to stay needs every `[debug]` switch off and an `[api]`
section, because the API is how the Pi is updated: `cargo xtask image` refuses a configuration
without it. Make the `password_hash` for that section by piping the password into
`cargo xtask hash-password`. Then:

```
cargo xtask fetch
cargo xtask fetch-lists
cargo xtask build
cargo xtask make-cert
cargo xtask image
```

Optionally, `qberrypi.toml` may say which channel the access point is on (`hint_mhz` under `[wifi]`,
see `qberrypi.example.toml`), so that the Pi's first scan after a start covers only that channel;
`cargo xtask image --wifi-hint 5180` puts it in the slots' copy, and `cargo xtask update` adds the
channel the Pi is on to the copy it uploads, when your file has none and the channel is a 5 GHz one.
The hint is meant for the 5 GHz channel, which the Pi prefers: a hinted scan whose best access point
is on 2.4 GHz is not taken, and the scan covers every channel after all. The Pi shows its channel as
`wifi.freq_mhz` in `/api/v1/stats`.

`make-cert` is needed once: it makes the API's certificate, `qberrypi-tls.pem`, which the image carries
and which qnet and `cargo xtask update` pin. `image` writes `private/qberrypi-card.img`, 256 MiB:
the boot firmware and both slots holding this build, slot a selected. It prints the image's SHA-256.
The image holds the Wi-Fi passphrase and the API's key, so `private/` is git-ignored and made with
mode 0700, and the file with mode 0600.

With the Pi's power cord pulled and its card in the reader, find the card and make sure nothing has
it mounted:

```
lsblk -o NAME,TRAN,RM,SIZE,MOUNTPOINTS
udisksctl unmount -b /dev/sdX1
```

Take a backup of the card first, because after the flash it is the only copy of what was on it (the
way back to Raspberry Pi OS and Pi-hole; it holds the Wi-Fi passphrase and keys, so it is kept in
`private/` too), then write the image:

```
cargo xtask backup-card --device /dev/sdX --yes
cargo xtask flash --image private/qberrypi-card.img --device /dev/sdX --yes
udisksctl power-off -b /dev/sdX
```

`sdX` is the card as a whole, never a partition. Both commands refuse anything but a removable USB
`/dev/sd*` disk of 1 to 512 GiB with nothing mounted, say what they will do, and do nothing without
`--yes`. If this user may not open the device they print the exact `sudo` line to run, and you run
it yourself; they never call `sudo`. A file name ending in `.zst` is compressed (backup) or
decompressed (flash) on the way; a backup without `--out` goes to
`private/card-backup-<UTC time>.img.zst`. `flash` reads the image's length back from the card, past
the page cache, and says whether the SHA-256 matches. It writes 256 MiB and leaves the rest of the
card as it was. Put the card in the Pi and switch it on: it answers about 15 s later, and
`curl -s http://<pi>/api/v1/stats` reports `"slot": "a"`.

## Update

Build, then pipe the API's password into `update`. The password comes from whatever prints it for
you, never typed at a terminal, which `update` refuses, as `hash-password` does:

```
cargo xtask build
<command that prints the API password> | cargo xtask update
```

`update` checks locally what the Pi checks, logs in over TLS to the certificate in
`qberrypi-tls.pem` (and to no other), and uploads the build and your current `qberrypi.toml` to the
slot the Pi is not running. The Pi hashes everything it wrote back from the card, then restarts into
the new slot on trial, with the firmware's one-shot `tryboot` flag. About two minutes after that the
new build confirms itself, once its Wi-Fi is up, its clock is set and an upstream has answered, and
the command says the build is confirmed on its slot. If the trial build restarts, stalls or has not
confirmed within ten minutes, or the power is pulled during the trial, the Pi boots the slot it came
from, reports why in its log and in `/api/v1/stats` (`update.last`), and the command says it rolled
back. The Pi answers no DNS for about 15 to 20 s around the restart.

- `--server <ipv4>` names the Pi's address.
- `--allow-kernel` lets the update change the kernel, device tree, overlays or command line. Without
  it the kernel and boot files stay fixed: the build carries a digest of them, and both `update` and
  the Pi refuse a build whose digest differs from the running one's. Nothing rolls back a kernel that
  stops the board before init runs, except that under the firmware trial a power cycle boots the old
  slot again.
- `--force` uploads a build that is not newer than the running one.
- `--software-trial` selects the new slot in `config.txt` instead of using `tryboot`, for a board
  whose firmware ignores the flag. It rolls back only a build that reaches init; for anything
  earlier the card must come out.
- `--rollback-drill panic|stall` uploads the same build with a fault that acts only on a trial boot,
  and succeeds when the Pi rolls back. It is how the rollback is tested.

qberrypi still writes nothing to the card while it runs, apart from an update's own writes and the
few lines of a trial boot's bookkeeping; a boot with no update under way writes nothing
([milestone 6](docs/bring-up/m6.md), amended).

## Recovery

- **A trial that fails** needs nothing from you: the Pi is back on its old slot and says why.
- **The Pi does not answer during an update's trial:** pull its power cord and plug it back. Under the
  firmware trial this boots the slot it came from.
- **A card that will not boot, or a configuration to start over from:** with the card in the reader,
  `cargo xtask flash --image private/qberrypi-card.img --device /dev/sdX --yes` writes the image
  again. It holds the build and configuration as of the day `image` made it; run `build` and
  `image` again first for a current one.
- **Back to Raspberry Pi OS and Pi-hole:** `cargo xtask flash --image <the backup that backup-card
  made> --device /dev/sdX --yes` puts the old card back as it was. `return-to-pios` is not the way
  back from a slot card; it works only on the old layout described under Development.

## Development on a card with Raspberry Pi OS

This is the development path, for a Pi whose card still has Raspberry Pi OS: it needs no card
reader, and it is not how a slot card is updated. The Pi keeps its Raspberry Pi OS install. qberrypi
lives in a folder on the same card's boot partition and is started for one boot at a time, so the
card never leaves the Pi. Copy `qberrypi.example.toml` to `qberrypi.toml` and fill
it in; the file holds the Wi-Fi passphrase and is ignored by git. For a
development boot, set three things under `[debug]`:

- `one_shot = true`, so qberrypi puts Raspberry Pi OS's `config.txt` back as
  soon as it starts and any restart returns to Raspberry Pi OS;
- `log_to_sd = true`, so it leaves a log on the card for `collect` to fetch;
- `return_after_secs = 90` or so, so it restarts by itself after that long
  and has time to join the network first.
  With 0 it stays up until the Pi is switched off and on.

To measure the touch screen, set `calibrate_touch = true` under `[debug]` for
one boot. Four crosses appear one after the other on the screen: press each for
about half a second. The log then holds the `[panel]` table for this screen as
`panel: calibration:` lines, a heading and five values; copy them into
`qberrypi.toml` without that prefix and set `calibrate_touch` back to `false`.

## Speed against Pi-hole

Measured on the same Raspberry Pi 3 B+, on the same Wi-Fi, from the same PC, with
`cargo xtask latency`, against the stock Raspberry Pi OS + Pi-hole install that
qberrypi replaced, booted from the same card. Each cell is median / 95th
percentile in milliseconds over 200 questions. A lost or failed answer counts as
the full 2-second wait. Full runs and method:
[`docs/bring-up/latency-baseline.md`](docs/bring-up/latency-baseline.md).

**As shipped** (DNS-over-TLS to the upstreams, one question every 200 ms; Pi-hole
measured just before and just after):

| Answer | Pi-hole, before | qberrypi | Pi-hole, after |
|---|---|---|---|
| Cached | 8.27 / 10.70 | **7.77 / 10.44** | 8.01 / 10.07 |
| Blocked | 7.99 / 10.83 | **7.73 / 10.28** | 7.92 / 10.00 |
| Forwarded upstream | 29.93 / 184.54 | **28.07 / 86.87** | 29.04 / 126.98 |
| Forwarded after 20 s of silence (median / max) | 36.3 / 166 | **33.6 / 106** | — |

Pi-hole sends its upstream questions as plain UDP. qberrypi encrypts them and is
still no slower, including the first question after the encrypted connection
has gone idle.

**Under load** (one question every 2 ms; three Pi-hole runs on the same day):

| Answer | Pi-hole, three runs | qberrypi |
|---|---|---|
| Cached | 3.47 / 6.67, 2.90 / 4.38, 2.98 / 4.83 | **2.82 / 5.50** |
| Blocked | 3.52 / 122.79, 2.78 / 4.69, 2.65 / 4.30 | **2.65 / 4.81** |
| Forwarded upstream | 25.76 / 2000 (11 lost), 24.52 / 118.46 (6 lost), 25.08 / 2000 (11 lost) | **23.83 / 77.51 (0 lost)** |

- **Medians:** qberrypi's median is lower than every Pi-hole run on every row.
- **Lost answers:** it lost no forwarded answer in any run, where Pi-hole lost 6
  to 29 of 200 under load.
- **Cached and blocked 95th percentiles:** these sit inside the spread between
  Pi-hole's own runs, which is mostly Wi-Fi noise.

The first DNS answer goes out 5.9 s after the kernel starts: about 2.1 s of kernel
start-up, 2.8 s scanning for the Wi-Fi network, and 0.2 s to join it and set the
address. The board's firmware runs before the kernel and is not in that figure;
`cargo xtask boot-time` measures from power-on.

## Commands

| Command | What it does |
|---|---|
| `cargo xtask fetch` | Downloads the pinned Raspberry Pi kernel, Wi-Fi firmware and boot-firmware packages, checks them and extracts what the image needs. |
| `cargo xtask fetch-lists` | Downloads the lists your configuration names into `vendor-cache/lists/`, for `build` to pack into the image as the snapshot the Pi blocks from before it has a network. |
| `cargo xtask build` | Cross-compiles qberrypi and writes the boot folder to `out/qberrypi/`. Needs `cargo xtask fetch-lists` first: the image holds the snapshot of the lists, and `build` stops where they have not been fetched. |
| `cargo xtask qemu-test` | Boots the built image in QEMU and checks that it behaves, including a card with two slots and three trial updates (one that confirms, two that roll back). |
| `cargo xtask image [--out <file>] [--firmware <dir>] [--wifi-hint <MHz>]...` | Makes a complete card image from the build in `out/qberrypi/`, `qberrypi.toml`, `qberrypi-tls.pem` and the boot firmware: both slots hold this build, slot a is selected. It goes to `private/qberrypi-card.img` unless `--out` says otherwise, and holds the Wi-Fi passphrase and the API's key. Refuses a configuration with a development switch on or with no `[api]` section. `--wifi-hint` (up to four times, a 2.4 or 5 GHz channel centre in MHz, at least one of them 5 GHz) sets `wifi.hint_mhz` in the slots' copy of `qberrypi.toml` only, and is refused if your file has a `hint_mhz` already or lists 2.4 GHz channels alone. |
| `cargo xtask backup-card --device /dev/sdX [--out <file>] --yes` | Copies the whole card in a USB reader into a file, `private/card-backup-<UTC time>.img.zst` by default (compressed when the name ends in `.zst`), and prints the SHA-256 of the bytes it read. Without `--yes` it only says what it would do; if the device needs root it prints the `sudo` line to run. |
| `cargo xtask flash --image <file> --device /dev/sdX --yes` | Writes an image (decompressed when its name ends in `.zst`) onto the card in a USB reader, reads it back past the page cache and compares the SHA-256. Without `--yes` it only says what it would do; if the device needs root it prints the `sudo` line to run. |
| `<password command> \| cargo xtask update [--server <ipv4>] [--allow-kernel] [--force] [--software-trial] [--rollback-drill panic\|stall]` | Uploads the build to the Pi's other slot over the API, with the password piped on standard input, and follows the trial boot until the new build confirms or the Pi rolls back, then says which. When your `qberrypi.toml` has no `hint_mhz`, the copy it uploads gets the channel the Pi reports (`wifi.freq_mhz`) when that is a 5 GHz one, and it says so (or says that it left a 2.4 GHz channel out). See Update. |
| `cargo xtask deploy --host <ssh-alias>` | On a card that still has Raspberry Pi OS: copies the build to the Pi over SSH, starts it for one boot, waits for Raspberry Pi OS to come back, checks that the Pi went through qberrypi, and collects the log, which must be this build's. |
| `cargo xtask collect --host <ssh-alias>` | On a card that still has Raspberry Pi OS: fetches the log qberrypi left on the card into `out/logs/`, and refuses to show it if it holds the passphrase. |
| `cargo xtask deploy --host <ssh-alias> --permanent` | On a card that still has Raspberry Pi OS: installs the build to stay: qberrypi is selected for every boot. The configuration must have every `[debug]` switch off. |
| `cargo xtask return-to-pios --boot <mount>` | With the Pi's card in this computer's reader, makes it start Raspberry Pi OS again: the way back from a permanent qberrypi on a card that still has Raspberry Pi OS. |
| `cargo xtask make-cert` | Makes qberrypi's own TLS certificate for the API, once, as `qberrypi-tls.pem` (private, git-ignored), and prints the pin a client checks. `image` and `update` use it too. |
| `cargo xtask hash-password` | Prints the `password_hash` line for the API's login from a password piped in on standard input. |
| `cargo xtask boot-time` | Measures power-on to the Pi's first DNS answer, from this computer. |
| `cargo xtask panel-preview` | Draws the front panel into a PNG, and with `--push` onto the Pi's 3.5-inch screen. |
| `cargo xtask probe --stage {resolver,blocker} [--server <ipv4>] [--listed <name>]` | While a one-shot boot is running, asks the Pi's DNS and status servers what a client would and prints which of the milestone's checks hold. `resolver` runs eight checks: forwarding, the cache, TCP, single-label names, the clock and the upstream latency. `blocker` runs those and seven more: the snapshot blocks before any refresh, the lists are then refreshed over HTTPS (it waits up to 150 s for that), and the name given with `--listed`, which must be on the lists, stays blocked. Start `blocker` together with the deploy, before the Pi has refreshed its lists. Run either stage once per boot: a second run finds `example.org` already in the Pi's cache. |
| `cargo xtask latency [--host <ssh-alias-or-address>] [--samples N] [--interval-ms M] [--blocked <name>] [--json <file>]`, or `cargo xtask latency --compare <a.json> <b.json> [--received-only]` | Measures from this PC the Pi's ping round trip and its DNS answer times — cached, blocked and forwarded — as p50, p95, min, mean, lost and failed, for comparison with `docs/bring-up/latency-baseline.md`; a DNS answer that does not come within 2 s counts as 2 s in p50, p95 and mean, and so does one with the response code SERVFAIL or REFUSED (`failed` counts those, a subset of `lost`; ping counts replies only); `--json <file>` keeps the figures. `--compare` measures nothing: it reads two such files and prints, per row, the p50 and p95 of the second against the first with a verdict, `ok` or `slower`, and a note where the two files' lost and failed counts differ. It fails, after printing, if any figure is slower, if either file lacks a figure the other has (a baseline with an error row or a missing row is incomplete), if the interval or the sample count differs between the files, or if a file has DNS rows from before lost answers were counted (re-run that pass). `--received-only` reads both files' received-only figures instead (lost answers left out), which accepts those older files; it is not the acceptance comparison, and a mismatch of pacing or samples still fails. |
| `cargo test -p qberrypi --test hwsim -- --ignored --test-threads=1` | Runs the Wi-Fi code against `hostapd` on the kernel's simulated radios (`mac80211_hwsim`), each test inside a user and network namespace of its own. Needs `sudo modprobe mac80211_hwsim radios=0` once and `hostapd` installed; it touches no real radio. |

An image holds the contents of the lists, so the lists' own licences apply to
anyone who passes an image on.

`deploy` and `collect` (the development path, for a card that still has Raspberry Pi OS) can leave
out `--host` when the environment variable `QBERRYPI_HOST` names the Pi; `probe` and `latency`
ignore that variable and, without `--server` or `--host`, use `net.address` of `qberrypi.toml`. The
first deploy saves a copy of the Pi's boot partition to `vendor-cache/bootpart-backup.tar`.

If the Pi does not come back after a deploy, put the card in another computer
and copy `config.pios.txt` over `config.txt` on its boot partition: that file
is Raspberry Pi OS's configuration, saved before qberrypi was first selected.
(That file exists only on a card that still has Raspberry Pi OS.)

## Licence

MIT. See `LICENSE`.

The image also carries the JetBrains Mono typefaces, which are under the SIL Open
Font License 1.1; its text is packed into the image as `licenses/JetBrainsMono-OFL.txt`.
