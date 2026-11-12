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
The design is in
[`docs/superpowers/specs/2026-11-10-qberrypi-design.md`](docs/superpowers/specs/2026-11-10-qberrypi-design.md);
the security watchdog's is in
[`docs/superpowers/specs/2026-11-11-qberrypi-watchdog-design.md`](docs/superpowers/specs/2026-11-11-qberrypi-watchdog-design.md).

## Development

The Pi keeps its Raspberry Pi OS install. qberrypi lives in a folder on the
same card's boot partition and is started for one boot at a time, so the card
never leaves the Pi. Copy `qberrypi.example.toml` to `qberrypi.toml` and fill
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

| Command | What it does |
|---|---|
| `cargo xtask fetch` | Downloads the pinned Raspberry Pi kernel and firmware packages, checks them and extracts what the image needs. |
| `cargo xtask fetch-lists` | Downloads the lists your configuration names into `vendor-cache/lists/`, for `build` to pack into the image as the snapshot the Pi blocks from before it has a network. |
| `cargo xtask build` | Cross-compiles qberrypi and writes the boot folder to `out/qberrypi/`. Needs `cargo xtask fetch-lists` first: the image holds the snapshot of the lists, and `build` stops where they have not been fetched. |
| `cargo xtask qemu-test` | Boots the built image in QEMU and checks that it behaves. |
| `cargo xtask deploy --host <ssh-alias>` | Copies the build to the Pi over SSH, starts it for one boot, waits for Raspberry Pi OS to come back, checks that the Pi went through qberrypi, and collects the log, which must be this build's. |
| `cargo xtask collect --host <ssh-alias>` | Fetches the log qberrypi left on the card into `out/logs/`, and refuses to show it if it holds the passphrase. |
| `cargo xtask deploy --host <ssh-alias> --permanent` | Installs the build to stay: qberrypi is selected for every boot. The configuration must have every `[debug]` switch off. |
| `cargo xtask return-to-pios --boot <mount>` | With the Pi's card in this computer's reader, makes it start Raspberry Pi OS again: the way back from a permanent qberrypi. |
| `cargo xtask make-cert` | Makes qberrypi's own TLS certificate for the API, once, as `qberrypi-tls.pem` (private, git-ignored), and prints the pin a client checks. |
| `cargo xtask hash-password` | Prints the `password_hash` line for the API's login from a password piped in on standard input. |
| `cargo xtask boot-time` | Measures power-on to the Pi's first DNS answer, from this computer. |
| `cargo xtask panel-preview` | Draws the front panel into a PNG, and with `--push` onto the Pi's 3.5-inch screen. |
| `cargo xtask probe --stage {resolver,blocker} [--server <ipv4>] [--listed <name>]` | While a one-shot boot is running, asks the Pi's DNS and status servers what a client would and prints which of the milestone's checks hold. `resolver` runs eight checks: forwarding, the cache, TCP, single-label names, the clock and the upstream latency. `blocker` runs those and seven more: the snapshot blocks before any refresh, the lists are then refreshed over HTTPS (it waits up to 150 s for that), and the name given with `--listed`, which must be on the lists, stays blocked. Start `blocker` together with the deploy, before the Pi has refreshed its lists. Run either stage once per boot: a second run finds `example.org` already in the Pi's cache. |
| `cargo xtask latency [--host <ssh-alias-or-address>] [--samples N] [--interval-ms M] [--blocked <name>] [--json <file>]`, or `cargo xtask latency --compare <a.json> <b.json> [--received-only]` | Measures from this PC the Pi's ping round trip and its DNS answer times — cached, blocked and forwarded — as p50, p95, min, mean, lost and failed, for comparison with `docs/bring-up/latency-baseline.md`; a DNS answer that does not come within 2 s counts as 2 s in p50, p95 and mean, and so does one with the response code SERVFAIL or REFUSED (`failed` counts those, a subset of `lost`; ping counts replies only); `--json <file>` keeps the figures. `--compare` measures nothing: it reads two such files and prints, per row, the p50 and p95 of the second against the first with a verdict, `ok` or `slower`, and a note where the two files' lost and failed counts differ. It fails, after printing, if any figure is slower, if either file lacks a figure the other has (a baseline with an error row or a missing row is incomplete), if the interval or the sample count differs between the files, or if a file has DNS rows from before lost answers were counted (re-run that pass). `--received-only` reads both files' received-only figures instead (lost answers left out), which accepts those older files; it is not the acceptance comparison, and a mismatch of pacing or samples still fails. |
| `cargo test -p qberrypi --test hwsim -- --ignored --test-threads=1` | Runs the Wi-Fi code against `hostapd` on the kernel's simulated radios (`mac80211_hwsim`), each test inside a user and network namespace of its own. Needs `sudo modprobe mac80211_hwsim radios=0` once and `hostapd` installed; it touches no real radio. |

An image holds the contents of the lists, so the lists' own licences apply to
anyone who passes an image on.

`deploy` and `collect` can leave out `--host` when the environment variable
`QBERRYPI_HOST` names the Pi; `probe` and `latency` ignore that variable and,
without `--server` or `--host`, use `net.address` of `qberrypi.toml`. The first
deploy saves a copy of the Pi's boot partition to
`vendor-cache/bootpart-backup.tar`.

If the Pi does not come back after a deploy, put the card in another computer
and copy `config.pios.txt` over `config.txt` on its boot partition: that file
is Raspberry Pi OS's configuration, saved before qberrypi was first selected.

## Licence

MIT. See `LICENSE`.

The image also carries the JetBrains Mono typefaces, which are under the SIL Open
Font License 1.1; its text is packed into the image as `licenses/JetBrainsMono-OFL.txt`.
