# qberrypi

A single-purpose operating system for the Raspberry Pi 3 B+ that turns the
board into a network-wide DNS ad blocker. The Linux kernel is stock;
everything above it is one static Rust executable: init, Wi-Fi supplicant,
network setup, DNS server and status page. No shell, no other programs.

**Status: Milestone 0 in progress.** It boots in a virtual machine; the first
boot on a real board is still to come. The design is in
[`docs/superpowers/specs/2026-11-10-qberrypi-design.md`](docs/superpowers/specs/2026-11-10-qberrypi-design.md).

## Development

The Pi keeps its Raspberry Pi OS install. qberrypi lives in a folder on the
same card's boot partition and is started for one boot at a time, so the card
never leaves the Pi. Copy `qberrypi.example.toml` to `qberrypi.toml` and fill
it in; the file holds the Wi-Fi passphrase and is ignored by git. For a
development boot, set three things under `[debug]`:

- `one_shot = true`, so qberrypi puts Raspberry Pi OS's `config.txt` back as
  soon as it starts and any restart returns to Raspberry Pi OS;
- `log_to_sd = true`, so it leaves a log on the card for `collect` to fetch;
- `return_after_secs = 40` or so, so it restarts by itself after that long.
  With 0 it stays up until the Pi is switched off and on.

| Command | What it does |
|---|---|
| `cargo xtask fetch` | Downloads the pinned Raspberry Pi kernel and firmware packages, checks them and extracts what the image needs. |
| `cargo xtask build` | Cross-compiles qberrypi and writes the boot folder to `out/qberrypi/`. |
| `cargo xtask qemu-test` | Boots the built image in QEMU and checks that it behaves. |
| `cargo xtask deploy --host <ssh-alias>` | Copies the build to the Pi over SSH, starts it for one boot, waits for Raspberry Pi OS to come back and collects the log. |
| `cargo xtask collect --host <ssh-alias>` | Fetches the log qberrypi left on the card into `out/logs/`. |

`--host` can be left out when the environment variable `QBERRYPI_HOST` names
the Pi. The first deploy saves a copy of the Pi's boot partition to
`vendor-cache/bootpart-backup.tar`.

If the Pi does not come back after a deploy, put the card in another computer
and copy `config.pios.txt` over `config.txt` on its boot partition: that file
is Raspberry Pi OS's configuration, saved before qberrypi was first selected.

## Licence

MIT. See `LICENSE`.
