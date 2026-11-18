# qberrypi reference

The full manual: installing, updating, recovering, the front panel's screens, the development path
and every command. For an overview, start with the [README](../README.md).

Notes from bringing it up on a real Pi: [milestone 0](bring-up/m0.md), [milestone 1](bring-up/m1.md),
[milestones 2 and 3](bring-up/m2-m3.md), [milestones 4 and 5](bring-up/m4-m5.md),
[milestone 6](bring-up/m6.md), [milestone 8](bring-up/m8-only-os.md),
[latency against Pi-hole](bring-up/latency-baseline.md), [throughput benchmark](bring-up/benchmark.md).
Designs: [the system](superpowers/specs/2026-11-10-qberrypi-design.md),
[the security watchdog](superpowers/specs/2026-11-11-qberrypi-watchdog-design.md),
[the card with two slots and network updates](superpowers/specs/2026-11-11-qberrypi-only-os-design.md),
[the front panel](superpowers/specs/2026-11-12-qberrypi-panel-os-design.md).

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

`/api/v1/me` on the same port needs no login and tells a device about itself alone, by the address
its request comes from: its latest DNS queries (the name, the time, whether it was blocked), its
counts of queries, blocks and threat blocks, whether blocking is on and the device is exempt, and
how many devices are not on the known list (none, until a known list has come). Reverse lookups
(names under `in-addr.arpa` and `ip6.arpa`) are left out of its queries and its counts, and no
address is in the answer. The Pi records a device's queries only while that device keeps asking
this route, and forgets it, with all it kept, after 15 minutes without a call.

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
  the Pi refuse a build whose digest differs from the running one's. The digest takes the slot's
  name and the touch screen's `xohms` (the owner's `[panel] touch_xohms`) at fixed values, so
  neither is a change of the boot files (once the running build is one that does so: the first update
  from a build older than `touch_xohms` sees the overlay line change, and needs this flag). Nothing rolls back a kernel that stops the board before
  init runs, except that under the firmware trial a power cycle boots the old slot again.
- `--force` uploads a build that is not newer than the running one.
- `--software-trial` selects the new slot in `config.txt` instead of using `tryboot`, for a board
  whose firmware ignores the flag. It rolls back only a build that reaches init; for anything
  earlier the card must come out.
- `--rollback-drill panic|stall` uploads the same build with a fault that acts only on a trial boot,
  and succeeds when the Pi rolls back. It is how the rollback is tested.

While it runs, qberrypi writes to the card only an update's own writes, the few lines of a trial
boot's bookkeeping, and your settings (see [What is written to the card](#what-is-written-to-the-card));
a boot in which none of your settings change and no update is under way writes nothing (one thing
changes them without you: with no known list from qnet, the devices heard in the first ten minutes
are learned, and that is saved) ([milestone 6](bring-up/m6.md), amended).

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
- **Your settings** are not in the image: a `flash` starts them empty, and qnet pushes its own again.
  To start them afresh without a flash, delete the folder `qberrypi-state` from the card in the
  reader. `[state] persist = false` only stops keeping them: the copies stay on the card, and come
  back when it is turned on again.

## What is written to the card

Your settings are kept on the card so that they come back after a restart or a power cut, also when
the desktop is off: the ADS PASS list and the block list the desktop pushed or the panel edited, the
mode (`exempt_default`), the labels, the known devices, your names (with the day you set each on the
panel), a PIN set from the desktop or on the panel, and the night hours. Nothing that runs out is kept
(the main gate, a device's gate), nor alerts, counters, the wrong-PIN count, or anything about
lookups: the Pi keeps no record of what any device asked.

They live in two copies, `qberrypi-state/a.bin` and `b.bin` on the boot partition, each a fixed
77,824 bytes. Each copy starts with a header (a magic word, a format version, a sequence number and
the length), then the settings, then a SHA-256 of all of it. At a start the Pi takes the whole copy
with the higher sequence number; if neither is whole it starts empty, as before, and says so in one
line.

- **When.** The Pi looks at the settings every 5 s and saves once they have been still for 30 s, at
  most once a minute, and never while an update is received or on trial. `RESTART` on UP saves at
  once, before the restart; no other restart does. So what can be lost is a change made in the last
  minute or so before a power cut, a change made while an update was received or on trial, and one
  made just before an update's own restart. A boot in which none of them change writes nothing.
- **How.** The first save on a card makes the folder and the two files at their full size, in one
  ordinary write of the partition. From then on a save never mounts the partition: it writes the
  new settings, in place, into the sectors of the copy that is not the newest, straight through the
  partition device, and waits until the card has them. No file grows, no directory entry, file
  allocation table or boot sector is written, and the save goes through the same claim on the card as
  an update and the log, so the two never meet. Before it writes, the Pi reads the copy back and
  checks that it is what it left there; if not, or if a write fails, it stops saving for that boot
  and says why in one line.
- **Why a power cut cannot damage it.** A cut during a save can spoil only the copy being written.
  Its checksum then fails, and the next start takes the other copy, which holds the settings as they
  were one save before. Nothing else on the card is touched by a save, so the slots, `config.txt`
  and the configuration stay as they were.
- **The log lines** (counts only, never a name, label or address): `state: settings restored from
  copy a (seq 12): 3 ADS PASS, 0 blocked, 5 labels, 41 known, 7 names, lock kept, night kept`,
  `state: no saved settings on the card`, `state: neither saved copy is whole; starting empty`,
  `state: made the two copies on the card` and `state: saved to copy b (seq 13)`.
- **The configuration wins.** A kept PIN is put back only while `[panel] pin_hash` is what it was
  when the PIN was kept, and a kept night only while `[panel] night` is; change either in the file
  and update, and the file's value is the one in force. The configuration's own lists
  (`watch.exempt`, `watch.block`) are never copied.
- **The known devices.** After a start the Pi knows the devices it knew before, so they raise no
  alert, and it waits for qnet's known list as before. If none comes in ten minutes, a device that
  joined meanwhile and is not on the kept list is raised as new (with nothing kept, the devices seen
  in those ten minutes are learned, as before).
- **Turning it off.** `[state] persist = false` reads, writes and makes nothing: the settings live
  in memory only, and qnet pushes its own again after a restart.

## The front panel

The 3.5-inch touchscreen is a small OS of its own, built in three milestones from
[`superpowers/specs/2026-11-12-qberrypi-panel-os-design.md`](superpowers/specs/2026-11-12-qberrypi-panel-os-design.md)
and [its plan](superpowers/plans/2026-11-12-panel-os.md). This section describes all three phases: the
status lane, HOME, LIVE, DEVICES, the gate, ALERTS, NAMES, SYSTEM with its readings, the states of the whole
system (starting, updating, night, the PIN) and the lock. It is all taps, every target is at least 48 x 48
pixels, the panel comes up on STARTING and then HOME, and returns to HOME after 60 s without a touch.

| Screen | What it shows | Taps |
|---|---|---|
| **Lane** (every screen but LIVE) | `HOME`, the section's name (on HOME: `ALL WELL`, `n ALERT(S)` or `GATE OPEN`), a white tile with the count of waiting alerts, the clock | `HOME` goes HOME; the middle goes to the section's root (on HOME: `ALL WELL` opens LIVE, `n ALERTS` opens ALERTS, `GATE OPEN` shuts the gate); the clock opens SYSTEM |
| **HOME** | Six tiles: LIVE (refused today, its share), DEVICES (how many, how many blocked, a miniature wall), ALERTS (how many wait, the newest's time), the gate (`SHUT` or the time left), NAMES, SYSTEM (version, days up) | A tile opens its screen. The gate tile opens GATE when shut and shuts the gate at once when open |
| **LIVE** | The old Drain: each name crossing the gate, the day's count and share | The key unfolds `5 MIN`, `30 MIN` and `1 HOUR` over the field when the gate is shut (a tap anywhere else, or 8 s, folds them) and shuts the gate when open; the clock column opens SYSTEM |
| **GATE** | `OPEN THE GATE`: ads pass on every device, threats stay blocked | `5 MIN`, `30 MIN`, `1 HOUR` open it and go back; `KEEP` goes back |
| **DEVICES** | A wall of up to 12 places, each a device with its name and `BLOCKED`, `ADS PASS`, `OPEN m:ss` or `ALWAYS`, and a lamp that lights while it asks. Labelled devices come first, then the others by first sighting, then the router and the Pi; with more than 12 devices the twelfth place is `MORE` and turns the page. The first empty place says what a newcomer gets | A place opens DEVICE |
| **DEVICE** | Its name, the last two names it asked and what became of them (`REFUSED`, `PASSED`, `ANSWERED`), the state key and the key of its own gate | The state key opens CONFIRM; the gate key opens ITS GATE, or shuts that device's gate when it is open. Both keys are inert on the router and the Pi, and on a device the configuration decides (`SET IN CONFIG`; its gate key says `NEVER OPENS` or `ALREADY OPEN`) |
| **CONFIRM** | `LET ADS PASS?` or `BLOCK ADS?` for that device | `ALLOW ADS` / `BLOCK ADS` does it; `KEEP ...` goes back |
| **ITS GATE** | `OPEN ITS GATE`: ads pass on that one device for a while | `5 MIN`, `30 MIN`, `1 HOUR`; `KEEP` goes back |
| **ALERTS** | The watch log, on tractor-feed paper: the newest three waiting alerts, the newest at the bottom, each as `hh:mm  URGENT` or `ROUTINE` (the weekday for one from before today), the device it is about and its title, with a white flag for `URGENT` and a blue one for the rest. Under them `hh:mm  WATCH CONTINUES`, a blinking cursor and `n ON THE LOG`. With none waiting: `NOTHING TO REPORT`, `LAST ENTRY FILED <day> hh:mm` (when the watchdog last filed an alert since the board started; left out when it never has) and `WATCH OPENED <day> hh:mm` (when the board started; left out while the clock is not set) | An entry opens its ALERT |
| **ALERT** | The entry as its slip, torn off and stamped with what the Pi did: `REFUSED` for a `threat` or a `rebind` (the answer was blocked), `ADMITTED` for a `new_device` (it joined and got the newcomer's default), `OBSERVED` for anything else (nothing was blocked because of it). `URGENT` (white) for a high alert, `ROUTINE` (blue) otherwise, and up to three lines made from the alert: for a `threat` the name, `<device> asked n times by hh:mm` and `on the threat lists, never answered`; for a `new_device` `<device> joined at hh:mm` and `no name yet, <default> by default`; for an `arp_spoof` `<device> answers as router` and `n times since hh:mm`; for the rest the subject and `n times since hh:mm` | `DISMISS` acknowledges the alert (the call `POST /api/qbp/alerts/{id}/ack` makes, so qnet sees it) and goes back to the log; `SEE DEVICE` opens that device's DEVICE (dimmed and inert when the wall does not hold it); the name line of a `threat` or `rebind` opens its NAME |
| **NAMES** | The day's three most refused names with their counts, each a pipe that is thicker the more it was refused, with a blue valve when it is refused and a white one when you let it through. `YOUR OWN n` is the door to your list | A pipe opens its NAME; `YOUR OWN` opens YOUR LIST |
| **YOUR LIST** | The newest three of the names you set, as valves: refused blue, allowed white, with the day you set it on the panel at the right (`TODAY`, or the weekday), and none for an entry pushed from qnet. Nothing yet says `nothing of your own yet` | A pipe opens its NAME; the door goes back |
| **NAME** | One name as a pipe from `THE HOUSE` through its valve to the answer, and a line saying what became of it and which list holds it: `Refused 1,204 times today` (counted only for the day's eight most refused; the Pi does not count answers), `Answered today`, `Refused by you since Mon` or `Allowed by you today`, then `on the ads list`, `on the deny list` (the configuration's `dns.deny`), `on a threat list` or `on no list` | `KEEP REFUSED`, `KEEP ANSWERED` or `KEEP ALLOWED` goes back; `ALLOW NAME` (on a refused name) or `REFUSE NAME` (on an answered one) puts it on your list; on a name you set, `REFUSE AGAIN` or `ANSWER AGAIN` takes your entry back. A name on a threat list has `BACK` and a `NEVER ALLOWED` key that does nothing |
| **SYSTEM** | The board as one line, drawn as a small mimic: the router with the Wi-Fi band under it (`5 GHZ`), the link as five dashes lit by the signal with its word (`GOOD`, `FAIR`, `WEAK`, `DOWN` or `JOINING`), and the box that is the Pi with its two slots (the one that runs, with the version, and `KEPT`), and what it feels: load, memory in use, heat, days up, and how the last update ended. `NIGHT`, `LOCK` and `ABOUT` are keys under it. A figure the Pi does not know is a dash | The link opens WI-FI, the box's slots VERSION, its readings UP; the keys open NIGHT HOURS, LOCK and ABOUT |
| **WI-FI** | The link drawn large: ten dashes lit by the signal (`(dBm + 100) / 5`, rounded, 0 to 10), its word, `5 GHz · signal -54 dBm · linked 12 days` and `upstream answers in 9 ms` (the time the Pi's own resolver measures to its upstream, not the router's). While a rejoin is under way every dash is dark and it says `JOINING` | `BACK`; `REJOIN` lets the link go and joins again (the house is without DNS for the few seconds of the join). It never asks for the PIN, is refused for a minute after the last one (the key says `WAIT`), and is inert while an update is received or on trial |
| **VERSION** | The running version, `built 2026-11-12 · slot A`, and `last update: confirmed`, `rolled back` or `none since start` (the board keeps the outcome in memory only; there is no `CHECK NOW`, since the Pi cannot fetch a build) | `BACK` |
| **UP** | `12 D 4 H` since the board started, `load 0.21 · memory 38% · 47 °C` (the minute's load, the memory in use by what is not `MemAvailable`, the processor's heat) and `last restart:` the cause as far as this boot knows (`an update`, or `an update that rolled back`; the Pi writes nothing for an ordinary restart, so it shows a dash) | `BACK`; `RESTART` restarts the board (the log is saved and the cause is logged as the owner's). It is strong, and inert while an update is received or on trial |
| **NIGHT HOURS** | `DARK FROM 23:00` and `UNTIL 07:00`, each with a `-` and a `+` key. The two hours equal are no night | `-` and `+` change the draft; `DONE` sets the hours (and goes back; they are kept on the card); `SLEEP NOW` shows the night screen at once, until a touch |
| **LOCK** | `ON` or `OFF`, the actions a PIN guards, and where the PIN lives (below) | `KEEP ON` / `KEEP OFF` goes back; `SET A PIN` (lock off) opens the pad to choose four digits; `TURN OFF` (lock on, strong) turns the lock off |
| **ABOUT** | `QBERRYPI`, `a DNS gate and watchdog for the house` and `version ... on a Pi 3B+ · panel 480x320` | `BACK` or the lane goes HOME |

**A new alert opens its slip by itself**, from whatever screen the panel is on (not over a state of
the whole system, below). If several come in the same second the newest urgent one opens
and the others wait on the log. It opens once: going back, or the minute without a touch, leaves it
waiting, with the white ALERTS tile and the count in the lane. An alert acknowledged from qnet leaves
the panel within a second, and the slip with it. The panel reads the newest three waiting alerts
every second, and the device inventory every two seconds while ALERTS or an ALERT is up, to name
their devices.

**Your names** are the names you allow or refuse from the panel (or that qnet pushes): at most 128
a side, kept on the card (see [What is written to the card](#what-is-written-to-the-card)), so they
come back after a restart. A refused name is blocked,
with its subdomains, for every device, ADS PASS ones and devices with their own gate open too, and
is counted as blocked but never raises an alert. An allowed name is answered although an ads list or
`dns.deny` blocks it; a name on a threat list can never be allowed (the panel offers no key for it,
and the Pi refuses it). The panel reads the day's most refused names and your list only while NAMES,
YOUR LIST or NAME shows, every five seconds and at once when one opens or after you edit it, and the
lock the read takes on the resolver is for a copy of eight names or one lookup. NAME shows no device:
the Pi keeps no record of which device asked which name.

`GET /api/qbp/names` answers `{"rev", "allow": [...], "refuse": [...], "top_today": [{"name",
"count"}, ...]}`, each side sorted. `PUT /api/qbp/names` takes `{"allow": [...], "refuse": [...]}`
(both keys, 4 KiB at most, names validated as `dns.deny` entries are, at most 128 a side) with the
optional `"append"` and `"complete"` to send a long list in chunks as `known` is, and `"if_rev"`:
a stale one is a 409 with `{"rev": current}`. A bad body is a 400 and changes nothing. `rev` moves
whenever the list changes, whether qnet or the panel changed it; a push that leaves it as it is
leaves `rev` alone, and a push keeps the entries it names as the panel set them, with their day.
qnet adopts the Pi's list when `rev` moved and the lists differ, as it does the devices'.

**ADS PASS** is the word, on the panel and in qnet, for a device that is let off the ads lists. The
threat lists and every alert still apply to it. (The API's JSON keeps its field names, `exempt` and
`exempt_macs`.) CONFIRM edits the list of the mode in force, which is kept on the card: the pushed exempt list when
devices are blocked by default, the pushed block list when they pass by default. A device that the
configuration's own list of that mode names says `SET IN CONFIG` and is left as the file says, and
no gate opens on it (the Pi refuses it, so the panel does not offer it); the router and the Pi are
`ALWAYS` and never change.

**Gates** (the main one and each device's) are `5 MIN`, `30 MIN` or `1 HOUR`, and they shut by
themselves: the main gate is a pause of blocking, a device's is an exemption that expires (at most 64
open at once, none longer than an hour). They are never PIN-locked: opening a gate is not a strong
action, and no gate stays open past the hour. During the main gate the threat lists and the names you
refused yourself (NAMES) stay blocked: a pause lets only the ads lists and `dns.deny` through, and
qnet's own pause (`POST /api/dns/blocking`) is the same one. The gate's bar refills against the
length that was chosen; a gate opened from elsewhere (qnet,
the API) is drawn against the smallest of the three lengths that holds what is left of it.

**Labels** are the owner's names for devices, pushed by qnet (`PUT /api/qbp/devices/labels`: at most
64, each 1 to 24 printable ASCII characters, kept on the card, and pushed again after a restart). The
wall shows a device's label, else its hostname, else its last address number. No name, label or
address is ever written to the log.

**A device's names** are kept only while its DEVICE screen is open, from the moment it opens; leaving
it forgets them. The Pi has no record of which device asked what.

**Sync with qnet.** `GET /api/qbp/devices` carries a `rev` that moves whenever the pushed exempt or
block list, the mode, a label or a gate changes, whoever changed it: the panel, the API or a gate
that ran out. `PUT devices/exempt` and `devices/policy` take an optional `if_rev` and answer 409 with
`{"rev": current}` when it is stale. qnet's side of the rule (qnet is outside this repository): read
`GET devices` on the usual poll; when `rev` moved and the pushed lists (`exempt_pushed`,
`block_pushed`) differ from its own, adopt the Pi's, because the panel was the last writer; push with
`if_rev` and, on 409, read again and merge. After a restart the Pi has the lists of its last save,
says `"known_list": "waiting"` until qnet sends its known list (as it did before the lists were kept),
and qnet takes that as a restart and pushes its own. A panel edit made in the minute or so before a
power cut may be lost (the Pi saves once the settings have been still for 30 s, at most once a minute),
and the panel says nothing of that. To draw the same wall as the panel, `GET devices` also gives `own_mac` (the Pi's own address,
or `null`) and, per device, `label_rank` (the place of its label, or `null`) and `always` (the router
and whatever claims its address or the Pi's).

**The states of the whole system** cover every screen and offer no `HOME`; they answer only their own
keys.

- **STARTING** from the panel's first frame: `PANEL ON`, `WI-FI JOINED`, `CLOCK SET`, `LISTS 212K NAMES`
  and `DNS ANSWERING` tick off as the board reports them (a line that is true is done whatever the ones
  before it say), and HOME comes 3 s after the last, or after 90 s at the longest. The lists line is done
  once the lists are loaded, though they hold no name (none may be configured), and DNS answering is the
  resolver being there and having answered a query today or an upstream having answered one, so that a quiet
  house does not hold the screen for the 90 s. A trial boot shows the trial after it.
- **UPDATE**, drawn as a changeover of the two slots with `DNS ANSWERING` drawn unbroken under both:
  `RECEIVING UPDATE` with the share of the build that has arrived (the old build answers all the while),
  `TRIAL CONFIRMS IN m:ss` counting to the trial's minimum time, and then, if the trial still waits, the word
  for what it waits for (`WI-FI`, `CLOCK` or `UPSTREAM`); `UPDATE CONFIRMED` or `UPDATE ROLLED BACK` when it
  ends, shown once, until a tap or 30 s. The boxes carry the slots' real letters, and the version is written
  only for the build that runs. It covers neither a PIN pad (that is the owner's for its minute) nor a night
  screen (it stays dark, as for an alert): an update that is received or on trial, or an outcome that has not
  been shown, waits, and shows when the pad closes or the panel wakes.
- **NIGHT**, in the night hours: the hour in the darkest blue on the paper's margins. A minute without a
  touch in the hours puts the panel to sleep; a touch wakes it to HOME and the next minute alone sleeps it
  again; in the morning it lifts by itself. `SLEEP NOW` sleeps at once, outside the hours too, until a touch
  (and it is not put to sleep again outside the hours). A waiting alert turns the caption into `n ON THE LOG`
  in white; **an arriving alert does not light the screen**, and its slip opens when a touch wakes it. This is
  drawing only: the screen's backlight is not switched.
- **PIN**, the authorisation slip beside a pad of twelve keys: `ENTER THE PIN`, `CHOOSE A PIN`, `WRONG PIN`
  or `WAIT m:ss`, four boxes and what it is signed for. `CANCEL`, or a minute without a touch, goes back to
  the screen it came from with the action not done.

**The lock.** It is built and off until a PIN is set. With a PIN set, the **strong actions** ask for it
first, and their keys wear a padlock: `ALLOW ADS` on a device (letting ads pass for good), `ALLOW NAME` and
`ANSWER AGAIN` on a name you refused, `RESTART`, and turning the lock off or setting a new PIN while one is
set. Nothing that only makes the house stricter ever asks (`BLOCK ADS`, `REFUSE NAME`, `REFUSE AGAIN`,
shutting a gate), nor does reading a screen, dismissing an alert, opening a gate, the night hours, `SLEEP NOW`
or `REJOIN`. The four digits go from the pad to the check in a buffer that is wiped, and the check runs on
the panel's own thread (10,000 rounds of PBKDF2, constant-time compare; the screen is not drawn for that
moment). Three wrong PINs in a row make the pad wait 30 s, each wrong one after that doubles the wait, up to
15 minutes, and a right PIN starts the count again; the pad shows `WAIT m:ss` and takes no digit. The log
says `panel: wrong PIN (n in a row)` at WARN, the count only: no digit and no hash is ever logged or sent.
The counter is in memory, so a power cut resets it (about three guesses a boot: a household's lock, not a
vault). Until the services have started the lock fails closed: the strong keys ask, and no PIN is accepted.

**Where the PIN lives.** A PIN is four digits, and the one that never goes away is a line in your
configuration, in `[panel]`:

```
[panel]
night = "23-07"        # the night hours, or "off"; the default is 23-07
pin_hash = "$pbkdf2-sha256$i=10000$<salt>$<hash>"
```

Make the `pin_hash` line by piping four digits into `cargo xtask hash-pin` (never typed as an argument, and it
refuses a terminal); it prints the line to paste. It survives a power cut, and changing it rides the next
`cargo xtask update`. The desktop can put a hash in force with `PUT /api/qbp/panel` (qnet keeps the hash and
pushes it again after each start), and `SET A PIN` on the panel's LOCK screen works at once. Both are kept on the
card with your other settings, so they outlast a restart: the LOCK screen's second line says where the PIN lives
(`kept in the config: it outlasts a restart`, `from the desktop: it outlasts a restart`, `set here: it outlasts
a restart`; with `[state] persist = false` the last two say `until the next restart`). The latest set wins; at
a start it is the kept one, unless the configuration's `pin_hash` changed since it was kept, and then the
configuration's (or none). `TURN OFF` on the panel lasts until the next restart when the configuration has a
hash, and a PIN from the configuration is never copied into the kept settings.

`GET /api/qbp/panel` (behind the login) answers `{"night": "23-07" or null, "lock": {"on": true,
"source": "config" | "api" | "panel" | null}}`: the hash is never in an answer. `PUT /api/qbp/panel` takes
`{"night": "HH-HH" or null, "pin_hash": "<line>" or null}`, either key or both: `night` is two different hours
of the day, `00` to `23`, from the first to the second (past midnight when the first is the later); `pin_hash`
is what `hash-pin` prints, of exactly 10,000 rounds: either the hash alone (`$pbkdf2-sha256$i=10000$<salt>$<hash>`,
taken as it is, with no white space around it) or the whole line `pin_hash = "<hash>"`, with its quotes and one
space either side of the `=` (a line ending or other white space around the line is dropped), and `null` turns
the lock off, or the night. (The configuration's `pin_hash` value is the hash alone.) It answers the state after the
change, as `GET` does. A body with neither key, a bad night, a hash of another number of rounds, a line that is
not exactly as `hash-pin` prints it or a value that is no PIN's hash is a 400 and changes nothing, and no answer
repeats a piece of the body. Pushing the hash that is in force already (qnet pushes its own again after every start)
changes nothing, and in particular keeps a wait that the lock is running. The night hours the panel's
NIGHT HOURS sets are this same state: the panel and the desktop edit one value, kept on the card; at a start it is
the kept one, unless the configuration's `night` changed since it was kept.

**Reads of the board.** The panel reads the board's load, memory and heat (four small files of `/proc` and
`/sys`, on its own thread, never the runtime's) every five seconds and only while SYSTEM, UP or WI-FI is up;
where the update machinery stands once a second, whatever shows; and the link's figures with its usual
snapshot. None of it is on the answer path.

**Preview without the Pi:** `cargo xtask panel-preview --screen <name>` writes one screen to a PNG
(`out/panel-preview.png`, or `--out`), drawn by the same code as the panel and pixel-for-pixel the
reference of the same name in `crates/qb-panel/tests/reference/os-<name>.png`. The names are `home`,
`home-alert`, `home-open`, `gate`, `live`, `live-gate`, `devices`, `device`, `confirm`, `pause`,
`alerts`, `alerts-none`, `alert`, `names`, `yours`, `name`, `name-locked`, `name-threat`, `about`, SYSTEM's
`system`, `wifi`, `version`, `uptime`, `nighthours` and `lock`, and the states `boot` (STARTING), `night`, `pin`,
`update-receiving`, `update-trial`, `update-confirmed` and `update-rolledback`.
`--state` still draws the Drain's own states, and `--push <ssh-alias>` puts either on the screen of a
Pi that runs Raspberry Pi OS.

**Memory.** A unit test adds up the panel's buffers (the two painters, the glass's kept frame, the
glyph caches and the world: about 3 MB, against a ceiling of 5 MB) and prints the total; the QEMU
self-test logs the process's resident memory in its last line (`selftest: vmrss`), and
`/api/v1/stats` reports it on the Pi as `memory.rss_kib`.

Where the panel differs from the design mockups on purpose: `ADS PASS` where the mockup says
`AD-FREE`; no `CHECK NOW` (the Pi cannot fetch a build, so an update is pushed from the desktop); a
device's names only while its screen is open (above); no device on a name, so NAME starts its pipe
at `THE HOUSE` and NAMES' rows show a name and its count only; the alert's stamp is what the Pi did,
decided from its kind; YOUR LIST shows the newest three (the rest are in qnet) and the weekday an
entry was set on the panel; the log's cursor is the only thing that moves on a screen at rest. In SYSTEM, the
box says `KEPT` for the spare slot (the Pi does not know its version) and has no dates, and the last restart is
only what this boot can know.

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

How light a touch the screen takes is set in `[panel]` too, by three keys;
lower values take a lighter, quicker touch and let more stray presses through.

- `touch_xohms` (10 to 1000 ohms; 25 when unset) is the plate resistance the
  `ads7846` touch driver is told, as `xohms=` on the `dtoverlay=qb-piscreen`
  line of the slot's `config.txt` (the overlay's own value is 100). The driver
  reckons the resistance of a touch in proportion to it, drops a touch above
  255 and reports the pressure as 255 less the resistance, so a smaller value
  takes a lighter touch; one too small rounds the firmest presses to nothing,
  which the driver does not report. The digest of the boot files counts any
  value in the range as the default, so a change goes out with a plain
  `cargo xtask update`, under the usual trial and rollback. The exception is the
  first update from a build older than these keys onto one that has them: in
  the old build's eyes the overlay line gains `xohms=`, a change of the boot
  files, so that one update needs `--allow-kernel` (and runs as a firmware trial).
- `touch_min_pressure` (0 to 254 of the driver's 0 to 255; 4 when unset): a
  report of the driver is a touch when its pressure is at least this. The
  calibration counts the same reports as touches.
- `touch_min_press_ms` (10 to 500 ms; 20 when unset): a press is a tap when it
  lasts this long.

Whatever the values, a press is a tap only if it begins on a key and never
leaves it, a press cut by lost events is none, and the strong actions still ask
for the PIN when the lock is on.

## Speed against Pi-hole

Measured on the same Raspberry Pi 3 B+, on the same Wi-Fi, from the same PC, with
`cargo xtask latency`, against the stock Raspberry Pi OS + Pi-hole install that
qberrypi replaced, booted from the same card. Each cell is median / 95th
percentile in milliseconds over 200 questions. A lost or failed answer counts as
the full 2-second wait. Full runs and method:
[`bring-up/latency-baseline.md`](bring-up/latency-baseline.md).

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
| `cargo xtask hash-pin` | Prints the `pin_hash` line for `[panel]` from four digits piped in on standard input (10,000 rounds of PBKDF2; it refuses a terminal, anything but four digits, and never takes the digits as an argument). See The front panel. |
| `cargo xtask boot-time` | Measures power-on to the Pi's first DNS answer, from this computer. |
| `cargo xtask panel-preview [--state <drain state> \| --screen <screen>] [--out <file>] [--push <ssh-alias>]` | Draws the front panel into a PNG, one of the Drain's states (`--state`, the default `normal`) or one screen of the panel's OS (`--screen home`, `devices`, `alert` and so on; see The front panel), and with `--push` onto the 3.5-inch screen of a Pi running Raspberry Pi OS. |
| `cargo xtask probe --stage {resolver,blocker} [--server <ipv4>] [--listed <name>]` | While a one-shot boot is running, asks the Pi's DNS and status servers what a client would and prints which of the milestone's checks hold. `resolver` runs eight checks: forwarding, the cache, TCP, single-label names, the clock and the upstream latency. `blocker` runs those and seven more: the snapshot blocks before any refresh, the lists are then refreshed over HTTPS (it waits up to 150 s for that), and the name given with `--listed`, which must be on the lists, stays blocked. Start `blocker` together with the deploy, before the Pi has refreshed its lists. Run either stage once per boot: a second run finds `example.org` already in the Pi's cache. |
| `cargo xtask latency [--host <ssh-alias-or-address>] [--samples N] [--interval-ms M] [--blocked <name>] [--json <file>]`, or `cargo xtask latency --compare <a.json> <b.json> [--received-only]` | Measures from this PC the Pi's ping round trip and its DNS answer times — cached, blocked and forwarded — as p50, p95, min, mean, lost and failed, for comparison with `docs/bring-up/latency-baseline.md`; a DNS answer that does not come within 2 s counts as 2 s in p50, p95 and mean, and so does one with the response code SERVFAIL or REFUSED (`failed` counts those, a subset of `lost`; ping counts replies only); `--json <file>` keeps the figures. `--compare` measures nothing: it reads two such files and prints, per row, the p50 and p95 of the second against the first with a verdict, `ok` or `slower`, and a note where the two files' lost and failed counts differ. It fails, after printing, if any figure is slower, if either file lacks a figure the other has (a baseline with an error row or a missing row is incomplete), if the interval or the sample count differs between the files, or if a file has DNS rows from before lost answers were counted (re-run that pass). `--received-only` reads both files' received-only figures instead (lost answers left out), which accepts those older files; it is not the acceptance comparison, and a mismatch of pacing or samples still fails. |
| `<password command> \| cargo xtask bench --on-pi [--server <ipv4>] [--class <class>]... [--seconds N] [--forwarded-max-qps N] [--json <file>]`, `cargo xtask bench --from-here [...]`, or `cargo xtask bench --compare <a.json> <b.json>` | Measures how many DNS answers a second the Pi sustains, per class (cached, blocked, forwarded): `--on-pi` runs `qb-bench`'s generator on the Pi against its own DNS over the loopback, through the API's `POST /api/qbp/bench` (logged in as `update` does), a ramp and then a steady load at 80% of the most it sustained; `--from-here` runs the same loads from this PC, the figure the Wi-Fi allows; `--compare` prints B against A and fails if B is worse. The forwarded class really asks Quad9 for every question, which throttles a source that sends too many fresh names, so it stops at 50 a second by default (100 at most). Figures go to `private/`. The same generator is the static `qb-bench` binary for Raspberry Pi OS; see `docs/bring-up/benchmark.md`. |
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
