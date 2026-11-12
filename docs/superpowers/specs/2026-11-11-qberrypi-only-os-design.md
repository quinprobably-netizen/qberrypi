# qberrypi as the only system on the card, with updates over the network

Date: 2026-11-11. Status: design for milestone 8. Binding beside
`2026-11-10-qberrypi-design.md`, `2026-11-10-qberrypi-cutover-and-api.md` and
`2026-11-11-qberrypi-watchdog-design.md`; their hard rules come first (no latency regression,
privacy, one binary). This document amends one of them: "Card writes on a permanent system"
(cutover spec) gains the update and trial writes listed below, and nothing else.

## Intent

Today the card holds Raspberry Pi OS and qberrypi side by side, and an update means a card
reader. After one card-reader trip the card holds qberrypi alone, in two slots, and every later
update goes over the network: `cargo xtask update` uploads a new slot, the Pi boots it on trial,
and the trial either confirms itself or the board falls back to the slot it came from. The card
does not come out again unless the firmware or the kernel must change and the owner chooses to.

## Card layout

One MBR partition table, one FAT32 partition of type `0x0c` from sector 2048 (the image is
256 MiB; the rest of the card is left as it was and unused). No Linux root partition.

```
bootcode.bin start.elf fixup.dat LICENCE.broadcom   the Pi 3's boot firmware (raspi-firmware)
config.txt                                          selects a slot: os_prefix=qberrypi-a/
tryboot.txt                                         only after an update: selects the trial slot
qberrypi-trial.txt                                  only during an update's trial: the marker
qberrypi-a/  qberrypi-b/                            the two slots, each complete:
    kernel8.img bcm2710-rpi-3-b-plus.dtb initramfs8
    ov-README ov-overlay_map.dtb ov-qb-piscreen.dtbo ov-disable-bt.dtbo
    cmdline.txt      the shipped command line plus qberrypi.slot=<a|b>
    config.txt       this slot's config.txt (a record: the firmware reads only the root one)
    qberrypi.toml tls.pem
```

- **Boot firmware.** `vendor-cache/extracted/firmware` holds the Wi-Fi chip's firmware, not the
  board's. The board's comes from a new pin, `raspi-firmware_1.20260915-1_all.deb` of the
  Raspberry Pi archive's trixie suite (SHA-256 `56b6f879…929b0f`, the only version listed on
  2026-11-11), from which `cargo xtask fetch` extracts `bootcode.bin`, `start.elf`, `fixup.dat`
  and `LICENCE.broadcom` into `vendor-cache/extracted/boot/`. Its `start.elf` (VC build of
  2026-09-14) contains the strings `tryboot.txt`, `[tryboot]` and `os_prefix`.
- **Bluetooth is absent by design:** no modules, no firmware, and the device-tree node disabled
  (`dtoverlay=disable-bt`, from the slot's own `ov-disable-bt.dtbo`); the build refuses to pack a
  Bluetooth module or firmware, and the module helper refuses every request for one.
- **Selecting a slot** is copying that slot's `config.txt` over the root one, in place, the way
  `bootpart::restore_pios_config` copies `config.pios.txt` (no rename, no zero-length moment; the
  two texts differ in one byte, so on FAT this rewrites one sector). A slot's `config.txt` is
  checked before it is copied: not empty, no NUL, exactly one uncommented `os_prefix=` line, and
  that line names the slot.
- **Which slot is running** is the `qberrypi.slot=` argument of the kernel command line: the
  firmware applies `os_prefix` to `cmdline.txt`, so each slot's command line names its slot. A
  boot without the argument is the old layout (`qberrypi/` beside Raspberry Pi OS), and behaves
  exactly as today. On a slot boot, init reads `qberrypi.toml` and `tls.pem` from its own slot,
  keeps `log.txt` (development only) there, and never tries the Raspberry Pi OS restore.

## Trial boot: firmware `tryboot`, with a software fallback

**What the official documentation says.** The "Fail-safe OS updates (`tryboot`)" section of
<https://www.raspberrypi.com/documentation/computers/raspberry-pi.html> (read 2026-11-11):
"All Raspberry Pi models support `tryboot`, however, on Raspberry Pi 4 Model B revision 1.0 and
1.1 the EEPROM must not be write protected." The flag is one-shot and cleared before the
firmware starts the OS, so a crash or reset during the trial loads the normal `config.txt`; it
is set with `reboot '0 tryboot'`, and in tryboot mode the firmware reads `tryboot.txt` instead of
`config.txt`. The `config.txt` page
(<https://www.raspberrypi.com/documentation/computers/config_txt.html>) adds the `[tryboot]`
filter and `/proc/device-tree/chosen/bootloader/tryboot`, and puts no model restriction on
either; `autoboot.txt` and `tryboot_a_b` are for A/B *partitions* and are not needed here.
Supporting evidence, not proof: the pinned `start.elf` contains `tryboot.txt`, and the pinned
kernel contains `reboot: Restarting system with command '%s'` and ` tryboot` (the firmware
driver's reboot hook). QEMU cannot run the GPU firmware, so the Pi check of milestone 8 is what
proves it on this board.

**Design.** The firmware trial is the default, because it alone rolls back a boot that never
reaches init. A software trial is kept as a fallback (`cargo xtask update --software-trial`) in
case the Pi check shows the firmware ignoring the flag. The two share every piece but the
updater's last write and its restart:

1. The updater (the running build, slot A) writes slot B, verifies it, writes `tryboot.txt`
   (= `qberrypi-b/config.txt`) and the marker, and restarts with `0 tryboot`. In software mode
   it instead selects slot B in `config.txt` and restarts plainly.
2. B's init, before it parses `qberrypi.toml` and before the watchdog is armed, finds the marker
   naming its slot. In software mode (`config.txt` selects B and the marker has no `started`) it
   first selects A again. Either way it appends `started` to the marker. From here on any restart
   — panic, fatal error, the supervisor giving up, the watchdog after a stall or hang, a pulled
   cord — boots A.
3. B runs normally and confirms once, at least 120 s after init started, the Wi-Fi is associated,
   the clock is set and an upstream has answered (B asks `example.org A` over loopback itself if
   no forwarded answer came by then): it selects itself in `config.txt` and deletes the marker.
4. B gives up after 10 minutes without confirming, writes the reason into the marker and
   restarts: A boots.
5. A boot that finds a marker naming the other slot reports the rollback (in the log and in
   `/api/v1/stats`) and deletes the marker.

**The rules init applies at boot**, with S its slot, C the slot `config.txt` selects and M the
marker:

| M | C | M has `started` | What init does |
|---|---|---|---|
| none | any | — | Runs. (C ≠ S means it was started from a `tryboot.txt` with no marker: a WARN.) |
| names S | M's `from` | no | Firmware trial: appends `started`, runs on trial. |
| names S | S | no | Software trial: selects `from`, appends `started`, runs on trial. |
| names S | S | yes | A confirm that selected S but was cut off before deleting M: deletes M, runs confirmed. |
| names S | M's `from` | yes | A second boot of the trial (the firmware chose `tryboot.txt` again): overwrites `tryboot.txt` with `from`'s `config.txt` (so that a firmware that keeps choosing it boots `from`), then restarts plainly, at once. |
| names the other slot | any | any | Rollback: logs which, deletes M, runs. |
| unparsable (read, but not text, over 4 KiB, or not what the updater writes) | any | — | ERROR, deletes M, runs. |
| unreadable (an I/O error opening or reading it) | any | — | ERROR, leaves M, runs with no trial: nothing is written, deleted or started. |

An unreadable marker is not an unparsable one: the I/O error says nothing of its content, and
what the boot ought to do depends on it. It may be a software trial's marker, whose slot
`config.txt` already selects, and deleting it would make that unconfirmed build permanent; it may
be a firmware trial's or a rollback's, which a guessed selection of the other slot would send back
to the build that failed. A restart to read it again would loop for ever, without DNS, if the
error lasts. So the marker is left for the first boot that can read it, which applies the table as
usual. The cost is that while the error lasts a trial is not watched (it neither confirms nor
gives up) and a software trial's build has no way back; each boot that cannot read the marker
logs an ERROR.

**What cannot be rolled back.** A kernel, device tree, overlay or command line that stops the
board before init runs: under the firmware trial a power cycle (or a restart) still boots A, as
the flag is gone; under the software trial nothing does, and the card must come out. Nothing
rolls back the boot firmware or the root `config.txt`'s other lines, which an update never
writes. So the default update ships the pinned kernel and boot files unchanged: the build packs
a digest of them into the initramfs (`boot_files` below), and `cargo xtask update` refuses a
build whose digest differs from the running one's unless `--allow-kernel` is given; the receiver
refuses it too.

## The update receiver

`POST /api/qbp/update` on port 443, behind the existing login (a valid `X-FTL-SID`; checked
before a byte of the body is read). It is the only route that streams its body: the generic
4 KiB body cap stays for every other request. Its own bounds: a body of at most 64 MiB, a manifest
of at most 16 KiB, ten minutes for the whole request counted from its head, 30 s for each read.

- **Body:** a 4-byte big-endian manifest length, the manifest as JSON, then the files'
  bytes one after another in the manifest's order. The manifest:
  `{"build": <epoch>, "slot": "b", "mode": "tryboot"|"software", "force": false,
  "allow_kernel": false, "files": [{"name": "kernel8.img", "size": N, "sha256": "<hex>"}, …]}`.
  `files` is exactly the ten slot files of the layout above, no more, no other names.
- **Refused** (with Pi-hole's error shape and nothing written): an update already running or a
  trial in progress (409 `update_busy`); a card without slots (409 `no_slots`); a `slot` that is
  not the inactive one (409 `wrong_slot`); `build` not newer than the running build without
  `force` (409 `not_newer`); boot files whose digest differs from the running build's without
  `allow_kernel` (409 `kernel_change`); a slot `config.txt` or `cmdline.txt` that does not name
  the slot (400); a bad manifest (400); a body over the cap (413).
- **Writes, in order**, in one claim of the card: empties `qberrypi-<slot>/`, streams each file
  into it while hashing what arrives, syncs and unmounts; mounts read-only again (a fresh mount,
  so the bytes come from the card, not the page cache) and hashes every file; on any mismatch
  answers 422 `hash_mismatch` and stops, with nothing selected. Then, writable, in firmware mode
  `tryboot.txt` and then the marker; in software mode the marker first (and synced) and then the
  selection in `config.txt`. The order is what a power cut between the two writes leaves: a
  selection with no marker would boot the new slot as a normal start, with no trial and no way
  back, while a marker that names a slot nothing selects is the "names the other slot" row of the
  table (the running slot boots, reports a rollback and deletes the marker). A selection that
  fails after the marker puts the old selection back, and only then deletes the marker. Answers
  200 `{"staged": true, "slot": "b", "build": N}`, and a second later asks the supervisor to end;
  init then restarts the board, with `0 tryboot` in firmware mode.
- **Where it runs:** on the API connection's thread of the blocking pool, as every API request
  does; it holds no lock of the resolver, and the card claim of init (`BOARD`) keeps it apart from
  any other use of the card. It occupies one of the API's two connection places for its length.
- **Logs** one line at the start (build, slot, file count, total bytes), one for the outcome or
  refusal reason; never a file's bytes, a name from `qberrypi.toml`, or a client address.

## What `/api/v1/stats` adds (port 80, no login, as before)

`"slot": "a"|"b"|null`, `"boot_files": "<hex>"|null`, and
`"update": {"state": "idle"|"receiving"|"trial", "trial": {"build", "from", "secs",
"waiting_for": ["wifi","clock","upstream","time"]}|null, "last": {"outcome":
"confirmed"|"rolled_back", "build", "detail"}|null}`. `last.detail` for a rollback says which
case it was: "the trial build never started" (no `started`: the firmware ignored the flag, or the
kernel never reached init), "the trial build restarted before it confirmed", or the reason it
gave up.

## The `xtask` commands

- **`cargo xtask image [--out FILE] [--firmware DIR]`**: a complete card image from `out/qberrypi/`
  (as `cargo xtask build` left it), `qberrypi.toml`, `qberrypi-tls.pem` and the boot firmware:
  both slots filled with this build, slot a selected. Refuses a configuration with a development
  switch on, as `deploy --permanent` does, and a configuration with no `[api]` section (no way to
  update). The image holds the Wi-Fi passphrase and the API's key: its default path is
  `private/qberrypi-card.img`, and `private/` is git-ignored, made with mode 0700, files 0600.
  Written in pure Rust with `fatfs` (MIT, already a dependency) and the existing MBR code.
- **`cargo xtask update [--server IPV4] [--allow-kernel] [--force] [--software-trial]
  [--rollback-drill panic|stall]`**: reads the password from standard input (refusing a terminal,
  as `hash-password` does), reads `/api/v1/stats` for the running build, slot and boot digest,
  checks locally what the receiver checks, logs in over TLS pinned to `qberrypi-tls.pem` (the
  server's certificate must be that one, byte for byte, as qnet pins it), uploads the other slot,
  then follows `/api/v1/stats` until the new build reports `confirmed` or the old one reports the
  rollback, and says which in a sentence. `--rollback-drill` uploads the same build with
  `debug.fault = "trial_panic"` or `"trial_stall"` set in the uploaded copy of `qberrypi.toml`
  (both act only on a trial boot) and succeeds when the Pi rolls back.
- **`cargo xtask backup-card --device /dev/sdX [--out FILE] --yes`** and **`cargo xtask flash
  --image FILE --device /dev/sdX --yes`**: refuse anything but a whole `/dev/sd*` disk whose
  `/sys/block/<name>/removable` is 1, whose sysfs path runs through USB, of 1 to 512 GiB, with
  none of its partitions mounted or used for swap; print what they will do and do nothing without
  `--yes`. A device node this user cannot open gives the exact `sudo` line to run (the same
  command, by the absolute path of the `xtask` executable), never a call to `sudo`. A file ending
  in `.zst` is compressed or decompressed on the way. `flash` refuses an image larger than the
  device, and after writing it reads the image's length back past the page cache and compares the
  SHA-256. Under `sudo`, an output file is given to `SUDO_UID`. Backups default to
  `private/card-backup-<UTC time>.img.zst`.

`deploy`, `collect` and `return-to-pios` stay as they are, for a card with Raspberry Pi OS.

## Card writes, amended

Permanent mode still writes nothing, with these exceptions only: the update receiver's writes;
on a trial boot, the marker's `started` line, the software trial's selection, the confirm (one
selection and one deletion) or the give-up's reason; the second boot of a trial's overwrite of
`tryboot.txt` with the `config.txt` of the slot it came from; and the rollback boot's deletion of
the marker. A boot with no marker on the card writes nothing.

## Testing

- Host: the boot rules table, the marker, the slot selection and the boot digest as pure
  functions over a directory; the receiver end to end over TLS against a directory standing for
  the card, with DNS answered on the runtime meanwhile and the runtime's longest gap bounded; the
  device checks against a fake `/sys` and regular files.
- QEMU (`cargo xtask qemu-test`): the harness learns to boot a slot image as the firmware would —
  `config.txt`, or `tryboot.txt` after a restart with `0 tryboot`, then that slot's kernel,
  initramfs, device tree and command line — and to boot again after a restart. Three scenarios:
  a firmware trial that confirms; a firmware trial whose build panics (`trial_panic`) and comes
  back on slot a; and a software trial that panics and comes back on slot a. QEMU has no network
  card, so its trials confirm with `debug.trial_offline` (Wi-Fi, clock and upstream not waited
  for) and `debug.trial_confirm_secs`; both are development switches. The receiver over a network
  is the host test above.
