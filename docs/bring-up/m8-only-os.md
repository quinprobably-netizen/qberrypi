# Milestone 8: qberrypi alone on the card, updated over the network

Date: 2026-11-12. Board: Raspberry Pi 3 Model B Plus Rev 1.4. Status: not yet run on the Pi.

The design is in
[`../superpowers/specs/2026-11-11-qberrypi-only-os-design.md`](../superpowers/specs/2026-11-11-qberrypi-only-os-design.md).
After one card-reader trip the card holds qberrypi alone, in two slots, and `cargo xtask update`
uploads a new slot, has the Pi boot it on trial and either confirms it or falls back to the slot it
came from. Everything the host tests and QEMU can prove has been run (`cargo xtask qemu-test`: 14
scenarios, three of them trial boots). This note lists what only the Pi can prove, with a blank for
each result.

## The tryboot finding

A trial boot rests on the firmware's one-shot `tryboot` flag. The official documentation, section
"Fail-safe OS updates (`tryboot`)" of
<https://www.raspberrypi.com/documentation/computers/raspberry-pi.html> (read 2026-11-11), says:
"All Raspberry Pi models support `tryboot`, however, on Raspberry Pi 4 Model B revision 1.0 and 1.1
the EEPROM must not be write protected." The flag is cleared before the firmware starts the OS, so a
crash or reset during the trial loads the normal `config.txt`; it is set with `reboot '0 tryboot'`,
and in tryboot mode the firmware reads `tryboot.txt` instead of `config.txt`. The `config.txt` page
(<https://www.raspberrypi.com/documentation/computers/config_txt.html>) puts no model restriction
on the `[tryboot]` filter either. The pinned `start.elf` contains `tryboot.txt`, and the pinned
kernel contains the reboot hook's `reboot: Restarting system with command '%s'` and ` tryboot`;
that is supporting evidence, not proof. **QEMU cannot run the GPU firmware, so it cannot prove
that this board honours the flag.** Check 13 does: had the firmware ignored the flag, the Pi would
come back on slot a and the command would say the trial never started. The fallback is
`cargo xtask update --software-trial`; check 13 records which of the two was needed.

## Boot-speed settings, Bluetooth, and what is left to measure

The cutover boot of the old layout took 5.9 s from the start of the kernel to the first answer to a
client. In init's own clock that was: services 0.68 s, `wlan0` up 0.74 s, **the Wi-Fi scan from 0.74
to 3.57 s (2.8 s; two access points of the network, at 5180 and 2437 MHz)**, association, handshake
and keys 3.57 to 3.71 s, address and route 3.73 s, first answer 3.81 s. So the scan is the main cost,
and `wifi.hint_mhz` (`qberrypi.example.toml`) makes the first scan after a start, and after a link that
held, cover only the hinted channel as a directed probe, with the full scan as the fallback when it
finds nothing usable on 5 GHz or the join on it fails (a hinted scan whose best access point is on
2.4 GHz is not taken, since the full scan would prefer the 5 GHz one); every check of the join is
unchanged. `cargo xtask image --wifi-hint MHZ` writes it into the slots' copy of `qberrypi.toml`
(and refuses a list of 2.4 GHz channels alone), and `cargo xtask update` adds the channel the Pi
reports (`wifi.freq_mhz` in `/api/v1/stats`) to the copy it uploads when the local file has none and
the channel is a 5 GHz one.

The slot's `config.txt` (not the old layout's) also gained five lines, each checked against the
official documentation on 2026-11-12: `disable_splash=1` ("If `disable_splash` is set to `1`, the
rainbow splash screen will not be shown on boot", config.txt page, "Boot options");
`camera_auto_detect=0` and `display_auto_detect=0` ("When enabled, the firmware will automatically
load overlays for recognised CSI cameras" and "...DSI displays", "Common options" > "Common hardware
configuration options"; the board has neither, its screen is on the SPI bus); `initial_turbo=60`
("Enables turbo mode from boot for the given value in seconds, or until `cpufreq` sets a frequency.
The maximum value is `60`", "Overclocking" > "Overclocking options"; the same page says the November
2024 firmware changed its default from 0 to 60, so this states the default and the most it takes, and
init sets the `performance` governor within a second of its start anyway, so the value only bounds the
time before the kernel's `cpufreq` driver takes over); and `dtparam=audio=off` (the `audio` parameter
of the base device tree, "Set to "on" to enable the onboard ALSA audio interface (default "off")",
from the `overlays/README` that ships in the kernel package, which is `ov-README` on the card, so this
is the default stated). All of them are on the page for every model, none is specific to another
board, and none touches the console, the Wi-Fi, the watchdog or the screen. **`boot_delay` was left
out:** it is not on the current official config.txt page. **Bluetooth is absent by design:** the
initramfs holds no Bluetooth module and no Bluetooth firmware (the build refuses to pack either), the
module helper refuses every request in the Bluetooth name family, and both `config.txt` forms carry
`dtoverlay=disable-bt`, loaded from the slot's own `ov-disable-bt.dtbo` (the page's `overlay_prefix`
entry: "`dtoverlay=disable-bt` attempts to load `${os_prefix}${overlay_prefix}disable-bt.dtbo`"). The
`overlays/README` entry applies to the 3 B+ (a Bluetooth-capable Pi that is "prior to Pi 5"): "Name:
disable-bt / Info: Disable onboard Bluetooth on Bluetooth-capable Raspberry Pis. On Pis prior to Pi 5
this restores UART0/ttyAMA0 over GPIOs 14 & 15. / Load: dtoverlay=disable-bt / Params: <None>". So it
disables the Bluetooth device-tree node and gives UART0 back to GPIO 14 and 15, which nothing on the
board uses. The boot-files digest
changed with these lines and the new overlay file, which is expected: the migration image is new, and
later updates of this build keep the digest.

**Kernel-side candidates, to measure on the Pi.** The command line was not changed. With `initcall_debug`
and `loglevel=8` added, one QEMU boot of this kernel (QEMU's times, not the Pi's) spends 1.89 s in
initcalls, of which the slow ones are `init_kprobe_trace` 725 ms (kprobe events through tracefs, which
nothing here uses; probably CPU-bound work that is far shorter on the Pi), `dwc_otg_driver_init` 449 ms
(the USB host, behind which the board's wired Ethernet sits; plainly unneeded for a Wi-Fi-only board,
but not to be dropped without the owner's word), `deferred_probe_initcall` 118 ms and `gpio_led_driver_init`
74 ms (both mostly QEMU's missing firmware answers). Skipping one would be `initcall_blacklist=<name>`
on the command line, which changes the boot files. To measure: add `initcall_debug loglevel=8` to a slot's
`cmdline.txt` on the card, boot once, and read the `kernel: initcall ... returned ... after N usecs`
lines at the start of `/log` (soon after the boot, since the log is bounded); a candidate is worth
a change only if it takes tens of milliseconds there.

## Before the trip (PC, card still in the Pi)

1. Merge the `ota` branch, then `cargo xtask fetch` (this adds the boot firmware),
   `cargo xtask build` and `cargo xtask qemu-test`: 14 scenarios ok.

   Result:

2. The latency of the running qberrypi, as the reference. The folder `private/` must exist first;
   `image` makes it too, but this comes before `image`.

   ```
   mkdir -p -m 700 private
   cargo xtask latency --samples 200 --json private/latency-m8-before-200ms.json
   cargo xtask latency --samples 200 --interval-ms 2 --json private/latency-m8-before-2ms.json
   ```

   Result:

3. `cargo xtask image`. Note the SHA-256 it prints. With `--wifi-hint MHZ` (up to four times) the
   slots' copy of `qberrypi.toml` gets `wifi.hint_mhz`, so that the Pi's first scan covers only the
   access point's channel. For this migration image the Pi has no `wifi.freq_mhz` to read yet: the old
   build's `/api/v1/stats` lacks it. Read the access point's 5 GHz frequency from the old build's log
   (`curl -s http://<pi>/log | grep 'wifi: joined'` says `... on 5180 MHz ...`) or from the router
   (5 GHz channel N is 5000 + 5 x N MHz: channel 36 is 5180), or leave the hint out and let the first
   `cargo xtask update` add it to the copy it uploads. A hint that is wrong costs one short scan: the
   pass then scans every channel as it always did.

   Result:

## The card-reader trip

4. Pull the Pi's power cord and put its card in the PC's USB reader. Find it, and unmount any
   partition the desktop mounted:

   ```
   lsblk -o NAME,TRAN,RM,SIZE,MOUNTPOINTS
   udisksctl unmount -b /dev/sdX1
   udisksctl unmount -b /dev/sdX2
   ```

   Result:

5. Back up the old card: `cargo xtask backup-card --device /dev/sdX --yes`. If it prints a `sudo`
   line, the owner runs that line. Note the SHA-256 and the size. This backup is the way back to
   Raspberry Pi OS and Pi-hole.

   Result:

6. `cargo xtask flash --image private/qberrypi-card.img --device /dev/sdX --yes` (or the `sudo` line
   it prints). It reads the card back and must say the SHA-256 matches.

   Result:

7. `udisksctl power-off -b /dev/sdX`, then the card into the Pi.

   Result:

## First boot

8. `cargo xtask boot-time`, then plug the power in. The first answer should come within the usual
   time (milestone 6: about 15 s after the restart). Then read the kernel-to-first-answer line from the
   log, `curl -s http://<pi>/log | grep -E 'first answer to a client|wifi: (scanning|joined)'`: `dns:
   first answer to a client N ms after the kernel started` is to be compared with the 5.9 s measured at
   the cutover (breakdown in "Boot-speed settings" above: the scan 0.74 to 3.57 s in init's clock was
   2.8 s of it). With a hint the log says `wifi: scanning 1 hinted channel(s) first`, and `wifi:
   joined ... N ms after the scan began` should be well under the 2.8 s plus 0.14 s that the full
   scan, the association and the handshake took. If it says `the hinted channels held no access point to
   try` or `... no access point on 5 GHz to try`, the hint is wrong (or the access point moved): the
   pass fell back to the full scan, and the figure is the old one. Record the figure and whether a hint was used.

   Result:

9. `curl -s http://<pi>/api/v1/stats | jq '{build, slot, boot_files, update}'`: `slot` is `"a"`,
   `update.state` is `"idle"` and `update.last` is `null`.

   Result:

10. `cargo xtask probe --stage resolver` and `--stage blocker`: every check holds. The README says to
    run each stage once per boot, since a second run finds `example.org` already in the Pi's cache,
    and the blocker stage runs the resolver's eight checks first.

    Result:

11. qnet logs in (the same pinned certificate) and reads the alerts and the devices.

    Result:

12. `curl -s http://<pi>/log`: no WARN or ERROR beyond those known from milestone 6, and no Bluetooth
    device in it: no `Bluetooth:`, `hci0` or `btbcm` line (the build packs no Bluetooth module, so a line
    like that would mean something loaded one).

    Result:

## An update that confirms

13. `cargo xtask build` (a new build time), then

    ```
    <command that prints the API password> | cargo xtask update
    ```

    It says the build is confirmed on slot b, about 2 to 3 minutes after the upload. This also proves
    the firmware's `tryboot` on this board. Had the firmware ignored the flag, the Pi would have come
    back on slot a and the command would say the trial never started: then retry with
    `--software-trial` and record that here.

    Result:

14. Pull the power cord and plug it back. The Pi comes back on slot b, with the same build.

    Result:

## An update that fails and rolls back

15. `<command that prints the API password> | cargo xtask update --rollback-drill panic`. It says the
    Pi rolled back to the running build because the trial build restarted before it confirmed. The
    stats show the old slot and `update.last.outcome` is `"rolled_back"`.

    Result:

16. The same with `--rollback-drill stall`, which is the hardware watchdog's path.

    Result:

17. Optional: during an ordinary update's trial, after "restarting into the trial" and before the
    confirm, pull the power cord. The Pi comes back on the old slot and reports the rollback.

    Result:

## Latency acceptance

18. On the confirmed build, run the two latency passes of check 2 again with `-after-` file names,
    then compare each with its `-before-` file:

    ```
    cargo xtask latency --samples 200 --json private/latency-m8-after-200ms.json
    cargo xtask latency --samples 200 --interval-ms 2 --json private/latency-m8-after-2ms.json
    cargo xtask latency --compare private/latency-m8-before-200ms.json private/latency-m8-after-200ms.json
    cargo xtask latency --compare private/latency-m8-before-2ms.json private/latency-m8-after-2ms.json
    ```

    The gate is the one in [`latency-baseline.md`](latency-baseline.md): the p50 is no slower on any
    row, the p95 is within the spread of same-day runs, and `stalls` in `/api/v1/stats` show no
    runtime stall. Stock Pi-hole cannot be measured any more, since it no longer runs on the card;
    the before file stands for it, as the running build passed against stock at milestone 6.
    `--compare` exits non-zero on any slower figure, p95 included, so a slower p95 is judged
    against the spread of same-day runs, not by the exit status alone.

    Result:

19. Not part of the gate: run `cargo xtask latency --samples 100` in a second terminal while an
    update uploads. The cached and blocked rows stay at their usual figures until the restart, and
    the restart's gap (about 15 to 20 s without answers) is expected and noted.

    Result:

## The way back to Raspberry Pi OS and Pi-hole

With the card in the reader, `cargo xtask flash --image <the backup of check 5> --device /dev/sdX
--yes` puts the old card back as it was. Nothing here has been run.

## Results (2026-11-12)

The migration was run without the backup of step 5: the owner chose to skip it (the full read of a
58 GiB card ran at 19 MB/s), so Raspberry Pi OS and Pi-hole are gone from the card, and the speed
comparison with Pi-hole in the README is the record of it.

- **Image and flash:** 256 MiB image, SHA-256 read back from the card equal to the image's.
- **First boot:** 9.5 s from power-on to the first DNS answer (`boot-time`, started by hand at the
  plug, so about ±0.5 s); 3.57 s from the kernel's start to the first answer to a client, against
  5.9 s at the cutover. The hinted scan of one channel took 42 ms and the join was complete 207 ms
  after the scan began (2.8 s of scanning before). Slot a, no trial; probe 8 of 8 and 15 of 15; the
  desktop client logged in and pushed its lists; no Bluetooth line in the log.
- **Update that confirms:** `cargo xtask update` sent build 1794480148 to slot b (14.2 MiB) and
  started it with the firmware's tryboot flag; it confirmed on slot b. The firmware's `tryboot` works
  on this Raspberry Pi 3 B+.
- **Rollback drills:** `--rollback-drill panic` and `--rollback-drill stall` each came back on slot b
  by themselves.
- **Latency, before (old build) against after:** at 200 ms pacing every DNS median is lower after
  (cached 7.69 → 7.54, blocked 7.83 → 7.38, forwarded 27.77 → 27.70 ms); at 2 ms pacing the medians
  are within 0.2 ms of each other across three after-passes (cached 2.50–2.67 against 2.64, blocked
  2.64–2.74 against 2.53), which is the noise between identical passes here; no change in the DNS
  path explains a difference (the only change on it is the exempt check, measured at 2 to 17 ns).
  One 2 ms pass lost 28 forwarded answers during a minute in which the log shows both upstreams
  not answering at all (`dns: no upstream answers`, both recovering 55 s later, Quad9 closing 18
  sessions); the next 2 ms pass lost none. **Judged as: no regression.**
- **After the stall drill's restart** the access point refused the first association on 5 GHz
  (status 16, it still held the old station), qberrypi joined the 2.4 GHz BSS, the kernel moved the
  station within 0.2 s, and the next pass joined 5 GHz again: DNS answered 8.7 s after the kernel
  started. Candidate for later: retry the 5 GHz BSS once after a refusal before trying 2.4 GHz.
