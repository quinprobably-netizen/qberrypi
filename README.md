# qberrypi

**A Raspberry Pi ad blocker and home-network watchdog, written as its own tiny operating system.**

Put it on a Raspberry Pi 3 B+, point your router's DNS at it, and every device in the house gets
ads, trackers, malware and phishing sites blocked. There's no Linux distribution underneath to
maintain: the stock Raspberry Pi kernel boots straight into one Rust program that does everything
else, from joining your Wi-Fi to drawing the touchscreen.

- **Blocks ads and threats for the whole house**: about 1.3 million domains from well-known public
  lists, refreshed daily.
- **Fast**: 2.7–3× the lookups of Pi-hole and 10–24× AdGuard Home on the same Pi ([numbers below](#how-fast)).
- **Private**: questions to the internet go out encrypted (DNS-over-TLS to Quad9), and the Pi
  keeps no record of who looked up what.
- **Watches the network**: alerts you to new devices, devices pretending to be your router, and
  lookups that look like malware calling home.
- **Per-device control**: let ads through on a device that breaks with blocking, while threats stay
  blocked, or block everything everywhere.
- **Touchscreen**: an optional 3.5-inch screen shows what's happening and lets you pause blocking,
  manage devices and see alerts without a computer.
- **Hard to break**: updates install over the network into a spare slot, run on trial, and roll back
  by themselves if anything goes wrong. Your settings (ADS PASS devices, labels, your own allowed
  and refused names, the PIN, the night hours) come back after a restart, even with your PC off.
  Pulling the plug is still always safe: apart from updates (and a log, if you ask for one), the
  only thing it writes while it runs is those settings, half a minute to a minute after you change
  them, into one of two copies, so a cut mid-write leaves the other one whole.

## How fast

Measured on one Raspberry Pi 3 B+, each server running alone at full clock with the same
1.29-million-domain block lists and the same load generator. Figures are lookups per second
answered with nothing lost and 99% of answers back within 10 ms.

| | qberrypi | Pi-hole v6 | AdGuard Home |
|---|---|---|---|
| Cached lookups | **17,000/s** | 6,250/s | 1,625/s |
| Blocked lookups | **18,000/s** | 5,750/s | 750/s |
| CPU used | ~1 core | ~1.8 cores | up to 3 cores |
| Memory | **34 MB** total | ~92 MB | ~540 MB |

From your devices over Wi-Fi it answers in about 7.5 ms for cached and blocked lookups and 28 ms for
lookups that go to the internet. It's faster than Pi-hole's medians even though it encrypts
everything Pi-hole sends in plain text. It boots in about 9.5 seconds from power-on to the first answer.

How these were measured, and every run: [throughput](docs/bring-up/benchmark.md) and
[latency](docs/bring-up/latency-baseline.md).

## What you need

- A **Raspberry Pi 3 Model B+**. It is the only board it supports.
- A **microSD card** (256 MB is used; any size from 1 GB up) and a **USB card reader**.
- **Wi-Fi with a WPA2-Personal password**. It connects over Wi-Fi only, using IPv4.
- **A Linux PC** with [Rust](https://rustup.rs) to build and install it.
- Optional: a **3.5-inch SPI touchscreen** of the common ILI9486/ADS7846 kind (often sold as
  "3.5 inch RPi display"), and [**qnet**](https://github.com/quinprobably-netizen/qnet), a desktop panel for managing it.

## Getting started

1. **Configure.** Copy `qberrypi.example.toml` to `qberrypi.toml` and fill in your Wi-Fi name and
   password, the address the Pi should have, and an admin password. The comments in the file explain
   each setting. This file holds secrets; git ignores it.
2. **Set the admin password.** Pipe it into `cargo xtask hash-password` (for example from your
   password manager, so it's never typed on screen), then uncomment the `[api]` section at the end
   of `qberrypi.toml` and paste the `password_hash` line it prints there.
3. **Build the card image:**
   ```
   cargo xtask fetch
   cargo xtask fetch-lists
   cargo xtask build
   cargo xtask make-cert
   cargo xtask image
   ```
4. **Write it to the card.** Put the card in the reader, find it with `lsblk`, and run
   `cargo xtask flash --image private/qberrypi-card.img --device /dev/sdX --yes`.
   It refuses anything that isn't a removable USB card, and checks what it wrote. If it needs root
   it prints the exact `sudo` line to run.
5. **Boot the Pi** with the card in. About 10 seconds later it answers DNS at the address you gave
   it. Check it at `http://<pi address>/api/v1/stats`.
6. **Point your router's DNS** at the Pi's address, with no second server. Devices pick it up as
   they reconnect.

## Updating

Updates go over the network, so the card never needs to come out again:

```
cargo xtask build
<command that prints your admin password> | cargo xtask update
```

The Pi installs the new build in its spare slot and restarts into it on trial. If the new build
proves itself healthy within about two minutes it stays; otherwise the Pi goes back to the
previous one by itself. DNS is down for about 15 seconds during the restart.

## If something goes wrong

- **An update fails:** nothing to do. The Pi is already back on the previous version and says why.
- **The Pi stops answering during an update:** unplug it and plug it back in. It boots the previous
  version.
- **Anything else:** flash the card again (step 4 of Getting started).

## The touchscreen

The home screen has six tiles:

- **LIVE**: lookups flowing past, with blocked ones draining away.
- **DEVICES**: every device on the network. Tap one to see what it's been looking up, let ads pass
  on it, or block it.
- **ALERTS**: anything suspicious the watchdog spotted.
- **GATE**: pause blocking for everyone for 5, 30 or 60 minutes.
- **NAMES**: what's being blocked most.
- **SYSTEM**: version, Wi-Fi and uptime.

Everything works by tap, and it returns to the home screen after a minute idle. SYSTEM also has night
hours and an optional PIN for the strong actions ([details](docs/reference.md#the-front-panel)).

## Privacy

- Lookups to the internet are encrypted. Until the Pi's clock is set (needed to check certificates),
  only the time servers' names go out unencrypted.
- The Pi keeps counts, not a history. A device's recent lookups are shown only while you have that
  device open on the screen, and are forgotten when you close it.
- A device can ask the Pi about its own activity at `http://<pi address>/api/v1/me`; the Pi starts
  tracking it only when it asks, and forgets it 15 minutes after it stops.
- Logs never contain the names your devices look up, or their addresses.
- There's no shell, no SSH and no way to log in. Management is through the password-protected API
  only.

## Learn more

- [The full manual](docs/reference.md): every setting, screen and command, the development path,
  and recovery details.
- [Design documents](docs/superpowers/specs/) and [bring-up notes](docs/bring-up/) from building it
  on a real Pi.

## Licence

MIT. See `LICENSE`. The image also carries the JetBrains Mono typefaces (SIL Open Font License 1.1),
and the block lists keep their own licences: anyone passing an image on passes those lists on too.
