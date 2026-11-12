# Milestones 4 and 5 (Resilience, Front panel) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The touchscreen shows the approved panel with live numbers and a switch that pauses and resumes blocking, and the system looks after itself: a supervisor restarts failed components, the watchdog and two reboot rules catch what it cannot, and pulled power or a restarted access point need no hand.

**Architecture:** The panel is one blocking thread: it loads the screen's drivers, finds the framebuffer and the touch device by name, and loops over "read touch events, draw `qb-panel`'s frame". What it shows and what its switch controls come through two small traits in `live.rs`, with stand-ins until milestones 1–3 exist, so the panel is on the real screen after Task 3. A supervisor on a current-thread tokio runtime then owns every component, the watchdog pet, the LED and the three reasons to restart the board. A `debug.fault` switch provokes each failure so that QEMU and the Pi can show the recovery.

**Tech Stack:** Rust stable, edition 2024. New in `crates/qberrypi`: `qb-panel`, `qb-dns` (types only), `tokio` (`rt`, `time`, `sync`, `macros`, `net`, `io-util`; dev: `test-util`), `serde_json`, and `rustix`'s `event` feature. Kernel side: `spi-bcm2835`, `fbtft`, `fb_ili9486`, `ads7846`, `backlight` and the `piscreen` overlay.

**Spec:** `docs/superpowers/specs/2026-11-10-qberrypi-design.md`, sections "Front panel", "Failure handling", "Process model", "Components", "Status", "Boot sequence" and "Testing". The code follows the "Amendments made during execution" table of `docs/superpowers/plans/2026-11-10-m0-boot.md`.

## Global Constraints

- `unsafe` only in `crates/qberrypi/src/sys.rs`. This plan needs none: device files are read and written with `std`, and `poll` comes from `rustix::event`.
- No secret in a log line, an error message, `Debug` output or a committed file. The repository is public: examples use `192.0.2.0/24` and names under `example.com`; no real network name, address, access point address, host name or SSH alias is committed (the Pi is `<alias>` below).
- Every kernel module the image gains is added to the pinned extraction (`xtask/src/pins.rs`) and to the module table (`qberrypi::modules::DEFAULT_TABLE`), which is the one list the initramfs is packed from.
- The initramfs holds exactly one executable, `/init`, and it never runs another program.
- The card is written only by `debug.one_shot` and `debug.log_to_sd`, and by a fatal error before the configuration was read. The one-shot restore stays the first write. This plan adds no write to the card and no new moment at which one happens.
- Spec values: watchdog 15 s; a failed component is restarted and three failures in a minute become a reboot; no association for 90 seconds is a reboot; the panel redraws every 5 seconds and at once after a tap; a pause lasts 5 minutes and never outlives a reboot; an unknown value is a dash, never zero; the screen is found by its driver name `fb_ili9486`, never by number, and must be 480 × 320 at 16 bpp; LED: slow heartbeat serving, fast blink joining, solid on a fatal error.
- `qb-wpa2`, `qb-dns` and `qb-panel` are used through the public interfaces their plans define and are not changed here. If one lacks something, report it; do not edit the crate.
- Dependencies are pure Rust, added with `cargo add`, and the executable must still build with `cargo xtask build` (`aarch64-unknown-linux-musl`, static).
- Clean before every commit: `cargo test --workspace`, `cargo clippy --workspace --all-targets`, `cargo fmt --all --check`. A task that touches `init.rs`, `modules.rs` or `xtask/` also runs `cargo xtask build && cargo xtask qemu-test`: the six scenarios of milestone 0 and every scenario added since must pass.
- Implementers never reach the Pi: no `ssh`, no `deploy`. Every "Pi check" step is run by the session lead, on a build that has just passed `qemu-test`, with `cargo xtask deploy --host <alias>`. Unless the step says otherwise the lead's `qberrypi.toml` has `one_shot = true` and `log_to_sd = true`, and no provoked failure. A key is put into that file only once the task that adds it is merged: before that, init refuses it as unknown.
- Git: stage files by name (never `git add -A` or `git add .`). Every commit message ends with a `Co-Authored-By:` trailer naming the model that wrote the commit, for example `Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>`. Implementers commit and never push.

## Review Focus

1. The screen is unplugged, its overlay is missing, or it comes up in another rotation: DNS must run on as if the panel had never been planned, with one warning, no restart loop and no other framebuffer written. (Tests in Tasks 2, 3 and 7; every QEMU scenario runs without a screen.)
2. The screen is the only framebuffer (no HDMI attached), so the kernel puts its text console on it and init's own log lines scroll over the panel. The console is taken off the screen in exactly that case and left on HDMI otherwise. (Tests in Tasks 2 and 3; Pi check in Task 3.)
3. Touches a resistive panel really produces: a finger resting on the switch for minutes, events lost by the kernel in mid-press, both halves of a tap read in one go because a frame was being drawn, two taps on exactly the same spot. A toggle only for a clean press of 50 ms or more. (Tests in Tasks 4 and 5.)
4. Two clocks: the wall clock steps from the image's build time to the real time in the middle of a pause, and the DNS task counts the pause on its own monotonic seconds. The pause still lasts five minutes, the switch never sets a deadline on a clock the resolver does not use, and the window shows `blocked —` until the clock is set. (Tests in Tasks 2, 5 and 12.)
5. A machine on the network opens the status port and says nothing, or sends an endless line, or eight of them do: the status server answers the ninth and holds no memory for the others, and a name or an access point's name cannot put markup into the page. (Tests in Task 11.)

## What this plan needs from milestones 1–3

Their plans did not exist when this one was written. Everything this plan takes from them goes through the seams below, which this plan defines; **their code must satisfy these, and Task 12 writes the adapters.** Tasks 1–11 need only milestone 0 and the three pure crates.

| What | The seam, defined here | Until it exists |
|---|---|---|
| Pausing and resuming blocking | `live::BlockingControl` (Task 5): `paused_left_secs`, `pause_for`, `resume`. Relative times only, so the resolver's own clock decides. | `live::StandIn` |
| Counters, last blocked name, upstream latency, list size and age, UTC offset, "clock is set" | `live::Source::snapshot() -> live::Snapshot` and `recent(n)` (Task 2), in `qb-dns`'s own types | `live::Nothing`: every value unknown |
| Wi-Fi association, signal, access point | a `tokio::sync::watch::Receiver<live::WifiStatus>` (Tasks 2 and 9) | none: the LED shows "serving" and the 90-second rule is not armed |
| Every long-running task | `supervisor::Component` (Task 7): a name and a closure that starts the task afresh and resolves to `Ended` when it stops | the panel is the only component |
| The DNS task's clock | a `Fn() -> qb_dns::Now` shared with the DNS task (Task 12) | — |

Two rules for their code, checked in Task 12: a task reports failure by returning, never by looping silently or exiting the process; and the Wi-Fi task treats a missing `wlan0` as "not associated" and keeps trying, because QEMU has no radio and three returns in a minute would restart every scenario.

If milestones 1–3 are merged before Task 7 runs and already build a tokio runtime, keep theirs. `supervisor::run` must be the future handed to `block_on` on PID 1's main thread, whatever the runtime's flavour.

## Measured on the Pi (Raspberry Pi OS, same kernel 6.18.60+rpt-rpi-v8, 2026-11-10)

- Modules and what `modules.dep` says they need: `spi-bcm2835` (nothing), `backlight` (nothing), `fbtft` (`backlight`), `fb_ili9486` (`fbtft`, `backlight`), `ads7846` (nothing). Built into the kernel: the framebuffer core, `evdev`, `hwmon`, the thermal driver, the watchdog driver, the LED triggers `timer`, `heartbeat`, `default-on`.
- In the pinned kernel package: `kernel/drivers/spi/spi-bcm2835.ko.xz`, `kernel/drivers/video/backlight/backlight.ko.xz`, `kernel/drivers/staging/fbtft/fbtft.ko.xz`, `kernel/drivers/staging/fbtft/fb_ili9486.ko.xz`, `kernel/drivers/input/touchscreen/ads7846.ko.xz`, all under `usr/lib/modules/6.18.60+rpt-rpi-v8/`.
- The screen: `/sys/class/graphics/fb0/name` is `fb_ili9486`, `virtual_size` `480,320`, `bits_per_pixel` `16`, `stride` 960. It is `fb0` there only because nothing else registered a framebuffer; under qberrypi with HDMI attached the built-in `bcm2708_fb` is `fb0`. `/sys/class/vtconsole/vtcon1` (`(M) frame buffer device`) has `bind` 1: the text console is on the panel.
- The touch device: name `ADS7846 Touchscreen`, at `/sys/class/input/event1/device/name`; `EV_KEY` `BTN_TOUCH` (0x14a), `EV_ABS` `ABS_X` (0), `ABS_Y` (1), `ABS_PRESSURE` (0x18); `ABS_X` and `ABS_Y` run 0–4095, pressure 0–255. An `input_event` is 24 bytes: `i64` seconds, `i64` microseconds, `u16` type, `u16` code, `i32` value. The device tree has `touchscreen-swapped-x-y`, so the driver already exchanges the axes.
- `/sys/class/thermal/thermal_zone0/temp` holds millidegrees (`42932`).
- `config.txt` of Raspberry Pi OS ends in `dtparam=spi=on` and `dtoverlay=piscreen,speed=16000000,rotate=90`. `overlays/piscreen.dtbo` and `overlays/README` are on the shared boot partition; `qberrypi/` has no `overlays/`. The firmware's rule: overlays come from `${os_prefix}overlays/` only if `${os_prefix}overlays/README` exists, otherwise from the shared `overlays/`.
- `/proc/net/wireless` exists and gives `wlan0`'s level in dBm (`-61.`) while associated.

## Decisions the spec leaves open

| Subject | Decision | Task |
|---|---|---|
| Overlay files | Shared: the firmware loads Raspberry Pi OS's `overlays/piscreen.dtbo`. qberrypi ships no `overlays/` folder; `deploy` says so when the file is missing. Carrying its own copy belongs to Cutover, which decides what stays on the card. | 1 |
| The panel's thread | One blocking thread of its own (file I/O and `poll`), under the supervisor through `spawn_blocking`. | 3, 7 |
| The panel is optional | No screen is not a failure. Three failures in a minute stop the panel for this boot; they do not restart the board. Every other component is essential. | 3, 7 |
| Console on the screen | Detached (`vtconsole/*/bind` ← `0`) when the screen is the only framebuffer; otherwise untouched. | 2, 3 |
| Backlight | Left to the driver, which switches it on. | — |
| Press timing | From the kernel's event timestamps, not from when the events were read. | 4 |
| Countdown | While a pause runs the panel redraws every second, so `4:59` is followed by `4:58`; otherwise every 5 seconds. | 5 |
| Wi-Fi meter | A dash whenever the board is not associated. | 2 |
| Local time | The UTC offset the resolver was given; this plan adds no setting. If that is 0, the window shows UTC. | 2, 12 |
| Calibration | Four targets 40 pixels in from the corners, each reading the median of a press; kept in `[panel]` of `qberrypi.toml`; `debug.calibrate_touch` runs it, and the same boot then uses the result. | 6 |
| Restarting a component | One second after it failed; failures are counted per component; one exactly 60 s old no longer counts. | 7 |
| Runtime | Current-thread tokio on PID 1's main thread. | 7 |
| Provoking failures | `debug.fault`: `none`, `stall`, `crash-loop`, `panic`, `no-wifi`. `deploy --permanent` refuses anything but `none`. | 8, 9 |
| 90-second rule | Counted from the supervisor's start and from each loss; armed only when there is a Wi-Fi status to watch. | 9 |
| Pulled power on a permanent system | Not checked here: without Cutover's way back it needs the card in another computer. Checked here: a one-shot boot, and in QEMU that a permanent boot leaves the card image byte-identical. | 10 |
| Status page | Built here although the dispatch for this plan did not list it: the spec's row for milestone 4 names it, and the Pi checks read the log through it. Hand-written HTTP/1.1, `GET` only. **Skip Task 11 if milestones 1–3 already built `status`.** | 11 |
| Upstream latency | Median of the last nine upstream answers. | 12 |

## File Structure

```
crates/qberrypi/src/
  modules.rs          + the five panel modules in DEFAULT_TABLE, PANEL_MODULES
  config.rs           + [panel] touch calibration, debug.calibrate_touch, debug.fault
  live.rs             what other components measure and control: the seams and their stand-ins
  thermal.rs          the board temperature
  panel/mod.rs        the component: bring-up, the loop, the switch
  panel/fb.rs         find the screen, write frames, take the console off it
  panel/view.rs       readings -> qb_panel::PanelState
  panel/touch.rs      find the touch device, decode its events
  panel/calibrate.rs  cue frames, readings, the solved calibration
  supervisor.rs       components, restart policy, reasons to restart the board
  link.rs             LED state and the 90-second rule
  fault.rs            provoked failures
  status.rs           the read-only HTTP server
  wiring.rs           Task 12: the real `live::Source` and `BlockingControl`
  logbuf.rs           + LogBuf::text
  init.rs             the panel's start, `fatal` with threads, `serve` under the supervisor
xtask/src/            pins.rs, build.rs (config.txt), deploy.rs (notes, wait, refusal), qemu.rs (scenarios)
docs/bring-up/m4-m5.md
```

---

### Task 1: The screen's drivers in the image

**Files:**
- Modify: `xtask/src/pins.rs`, `crates/qberrypi/src/modules.rs`, `xtask/src/build.rs`, `xtask/src/deploy.rs`

**Interfaces:**
- Produces: `modules::DEFAULT_TABLE` with five more lines, after the Wi-Fi ones:

```
backlight	backlight.ko	
fbtft	fbtft.ko	backlight
fb_ili9486	fb_ili9486.ko	fbtft,backlight
spi-bcm2835	spi-bcm2835.ko	
ads7846	ads7846.ko	
```

  `pub const PANEL_MODULES: [&str; 3] = ["spi-bcm2835", "fb_ili9486", "ads7846"];` (what the panel asks `modules::load` for, bus first). `build::CONFIG_TXT` ends with the two lines `dtparam=spi=on` and `dtoverlay=piscreen,speed=16000000,rotate=90`. The kernel package's `wanted` list gains the five files of "Measured on the Pi", each to `modules/<name>.ko`.

- [ ] **Step 1: Write the failing tests**

`modules.rs`:

```rust
#[test] fn the_panel_modules_load_bus_first_and_bring_what_they_need() {
    let table = ModuleTable::parse(DEFAULT_TABLE).unwrap();
    let mut files = Vec::new();
    for name in PANEL_MODULES {
        load(&table, name, "", &mut |file: &Path, _: &str| { files.push(file.to_str().unwrap().to_owned()); Ok(()) }).unwrap();
    }
    assert_eq!(files, ["/lib/modules/spi-bcm2835.ko", "/lib/modules/backlight.ko", "/lib/modules/fbtft.ko",
                       "/lib/modules/fb_ili9486.ko", "/lib/modules/ads7846.ko"]);
}
```

`pins.rs`: extend the list in the existing "files the image needs" test by `modules/ads7846.ko`, `modules/backlight.ko`, `modules/fb_ili9486.ko`, `modules/fbtft.ko`, `modules/spi-bcm2835.ko` (sorted in), rename it for its new count, and add:

```rust
#[test] fn every_module_the_table_names_is_fetched() {
    let outputs: Vec<&str> = PACKAGES.iter().flat_map(|p| p.wanted.iter().map(|(_, out)| *out)).collect();
    for file in ModuleTable::parse(DEFAULT_TABLE).unwrap().files() {
        assert!(outputs.contains(&format!("modules/{file}").as_str()), "{file}");
    }
}
```

`build.rs`: add the five `modules/*.ko` to `FETCHED` and five `- lib/modules/*.ko` lines after `brcmfmac-cyw.ko` in the `INITRAMFS` listing, in the table's order; put the new text into `config_txt_and_cmdline_txt_are_the_agreed_text`; in `config_txt_selects_the_prefix_and_loads_the_initramfs` drop the line that forbids `dtoverlay`; add:

```rust
#[test] fn config_txt_turns_the_screen_on_and_leaves_overlays_shared() {
    assert_eq!(CONFIG_TXT.lines().rev().take(2).collect::<Vec<_>>(), ["dtoverlay=piscreen,speed=16000000,rotate=90", "dtparam=spi=on"]);
    assert_eq!(CONFIG_TXT.lines().filter(|l| l.starts_with("dtoverlay=")).count(), 1);   // still no graphics overlay
    assert!(!CONFIG_TXT.contains("overlay_prefix"));
}
```

`deploy.rs`, with the fixture the script tests already use, for every shell of `shells()`:

```rust
#[test] fn the_script_says_when_the_screens_overlay_is_not_where_the_firmware_looks() {
    // boot directory without overlays/piscreen.dtbo: status 0, qberrypi selected as usual, and stdout has
    //   "qberrypi-deploy: note: overlays/piscreen.dtbo is not on the boot partition: the front panel will stay dark"
    // with overlays/piscreen.dtbo present: no line containing "note: overlays"
    // with qberrypi/overlays/README present as well: stdout has
    //   "qberrypi-deploy: note: qberrypi/overlays/README is there: the firmware takes overlays from qberrypi/overlays, not from overlays"
}
```

- [ ] **Step 2: Run** `cargo test -p qberrypi modules && cargo test -p xtask` — expected: the new tests fail (`PANEL_MODULES` not found; counts differ).
- [ ] **Step 3: Implement.** The two notes go at the end of the script's step 1, after the hardware checks, as `say` lines; they stop nothing. Update the doc comment of `DEFAULT_TABLE`: it is no longer only the Wi-Fi chip's.
- [ ] **Step 4: Run** `cargo xtask fetch && cargo xtask build && cargo xtask qemu-test`, then the three checks — expected: fetch extracts five more files without downloading (the package is cached), six scenarios `ok`, no warnings.
- [ ] **Step 5: Commit** — `git add xtask/src/pins.rs xtask/src/build.rs xtask/src/deploy.rs crates/qberrypi/src/modules.rs`, message `"Image: the touchscreen's five modules and its two config.txt lines"`.

---

### Task 2: What to show and where to show it

Four small modules with no thread and no loop; each is tested against temporary directories.

**Files:**
- Create: `crates/qberrypi/src/live.rs`, `crates/qberrypi/src/thermal.rs`, `crates/qberrypi/src/panel/mod.rs` (module lines only), `crates/qberrypi/src/panel/fb.rs`, `crates/qberrypi/src/panel/view.rs`
- Modify: `crates/qberrypi/src/lib.rs`, `crates/qberrypi/Cargo.toml`, `Cargo.lock`

**Interfaces:**
- Consumes: `qb_panel::{PanelState, LatestBlocked, TimeOfDay, Blocking}`; `qb_dns::{Counts, LastBlocked, LogEntry}`.
- Produces:

```rust
// live.rs
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WifiStatus { pub associated: bool, pub signal_dbm: Option<i8>, pub ap: Option<String> }
/// Every field is `None` until the component that measures it exists and has measured it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub wifi: Option<WifiStatus>,
    pub today: Option<Counts>, pub total: Option<Counts>, pub last_blocked: Option<LastBlocked>,
    pub upstream_ms: Option<u16>,
    pub utc_offset_secs: i32, pub clock_set: bool,
    pub list_names: Option<usize>, pub list_fetched_unix: Option<u64>,
}
pub trait Source: Send + Sync { fn snapshot(&self) -> Snapshot; fn recent(&self, n: usize) -> Vec<LogEntry>; }
pub struct Nothing;                                   // impl Source: Snapshot::default(), no queries

// thermal.rs
pub const BOARD_TEMP: &str = "/sys/class/thermal/thermal_zone0/temp";
pub fn read_c(file: &Path) -> Option<i8>;             // millidegrees -> nearest degree, held to i8; anything else None

// panel/fb.rs
pub const SCREEN_DRIVER: &str = "fb_ili9486";
pub const SYS_GRAPHICS: &str = "/sys/class/graphics";
pub const SYS_VTCONSOLE: &str = "/sys/class/vtconsole";
#[derive(Debug, PartialEq)] pub struct Screen { pub device: PathBuf, pub sole: bool }   // sole: no other framebuffer exists
#[derive(Debug, PartialEq)] pub enum ScreenError { Absent, Wrong(String) }             // Wrong: what was found, "320,480 at 16 bpp"
pub fn find_screen(sys_graphics: &Path, dev: &Path) -> Result<Screen, ScreenError>;
pub fn detach_console(sys_vtconsole: &Path) -> io::Result<bool>;   // true if a framebuffer console was bound
pub struct Framebuffer { /* the open device */ }
impl Framebuffer {
    pub fn open(device: &Path) -> io::Result<Self>;
    pub fn show(&mut self, frame: &[u8]) -> io::Result<()>;        // 307,200 bytes, written at offset 0
}

// panel/view.rs
pub fn time_of_day(unix_secs: u64, utc_offset_secs: i32) -> TimeOfDay;
pub fn panel_state(snapshot: &Snapshot, board_c: Option<i8>, paused_left_secs: Option<u16>) -> PanelState;
```

`find_screen` reads `<sys_graphics>/fb*/name` (trimmed) and takes the directory whose name is `fb_ili9486`; a directory without a `name` file (`fbcon`) is skipped. `virtual_size` must be `480,320` and `bits_per_pixel` `16`, else `Wrong`. The device is `<dev>/<directory name>`. `detach_console` writes `0` to `bind` of every `vtcon*` whose `name` contains `frame buffer` and whose `bind` reads `1`; a missing directory is `Ok(false)`.

`panel_state`: counters are `today.blocked` and `today.queries`, each held to `u32::MAX`; `wifi_dbm` is the signal only while `associated`; `latest` is the last blocked name with `count_day = count_24h` and `time = clock_set.then(|| time_of_day(unix_secs, utc_offset_secs))`; `blocking` is `Paused { left_secs }` when `paused_left_secs` is `Some`.

- [ ] **Step 1: Add the dependencies** — `cargo add -p qberrypi qb-panel --path crates/qb-panel` and `cargo add -p qberrypi qb-dns --path crates/qb-dns`.
- [ ] **Step 2: Write the failing tests**

`fb.rs`. `graphics(&[(dir, name, size, bpp)])` makes a temporary `sys_graphics` with those directories, each file ending in a newline as sysfs writes it, and an empty `fbcon/` beside them.

```rust
const HDMI: (&str, &str, &str, &str) = ("fb0", "BCM2708 FB", "1920,1080", "32");
#[test] fn the_screen_is_found_by_its_driver_whatever_its_number() {
    let dev = Path::new("/dev");
    let sys = graphics(&[HDMI, ("fb1", "fb_ili9486", "480,320", "16")]);
    assert_eq!(find_screen(sys.path(), dev), Ok(Screen { device: "/dev/fb1".into(), sole: false }));
    let sys = graphics(&[("fb0", "fb_ili9486", "480,320", "16"), ("fb1", "BCM2708 FB", "1920,1080", "32")]);
    assert_eq!(find_screen(sys.path(), dev), Ok(Screen { device: "/dev/fb0".into(), sole: false }));
    let sys = graphics(&[("fb0", "fb_ili9486", "480,320", "16")]);
    assert_eq!(find_screen(sys.path(), dev), Ok(Screen { device: "/dev/fb0".into(), sole: true }));
}
#[test] fn no_screen_and_a_screen_of_another_shape_are_told_apart_and_no_other_is_taken() {
    let dev = Path::new("/dev");
    assert_eq!(find_screen(graphics(&[("fb0", "BCM2708 FB", "480,320", "16")]).path(), dev), Err(ScreenError::Absent));
    assert_eq!(find_screen(Path::new("/nonexistent"), dev), Err(ScreenError::Absent));
    for (size, bpp, shows) in [("320,480", "16", "320,480"), ("480,320", "32", "32 bpp")] {
        match find_screen(graphics(&[HDMI, ("fb1", "fb_ili9486", size, bpp)]).path(), dev) {
            Err(ScreenError::Wrong(found)) => assert!(found.contains(shows), "{found}"),
            other => panic!("{other:?}"),
        }
    }
}
#[test] fn a_frame_replaces_the_one_before_from_the_first_byte() {
    let dir = tempfile::tempdir().unwrap();
    let device = dir.path().join("fb1");
    fs::write(&device, []).unwrap();
    let mut fb = Framebuffer::open(&device).unwrap();
    fb.show(&vec![0x11; 307_200]).unwrap();
    fb.show(&vec![0x22; 307_200]).unwrap();
    assert_eq!(fs::read(&device).unwrap(), vec![0x22; 307_200]);
    assert_eq!(fb.show(&[0; 100]).unwrap_err().kind(), ErrorKind::InvalidInput);
    assert_eq!(fs::read(&device).unwrap().len(), 307_200);
}
#[test] fn only_a_bound_framebuffer_console_is_detached() {
    // vtcon0: name "(S) dummy device\n", bind "0\n"; vtcon1: name "(M) frame buffer device\n", bind "1\n"
    assert!(detach_console(sys.path()).unwrap());
    assert_eq!((read("vtcon0/bind"), read("vtcon1/bind")), ("0\n".to_owned(), "0".to_owned()));
    assert!(!detach_console(sys.path()).unwrap());                       // nothing is bound any more
    assert!(!detach_console(Path::new("/nonexistent")).unwrap());
}
```

`thermal.rs` (`t(text)` writes a temporary file and reads it back through `read_c`):

```rust
#[test] fn the_board_temperature_is_whole_degrees_or_unknown() {
    assert_eq!((t("42932\n"), t("42499\n"), t("-4600\n"), t("200000\n")), (Some(43), Some(42), Some(-5), Some(127)));
    assert_eq!((t(""), t("warm\n"), read_c(Path::new("/nonexistent"))), (None, None, None));
}
```

`live.rs`:

```rust
#[test] fn nothing_is_known_before_the_other_components_exist() {
    assert_eq!(Nothing.snapshot(), Snapshot::default());
    assert!(Nothing.recent(10).is_empty());
}
```

`view.rs`:

```rust
const MIDNIGHT_UTC: u64 = 1_799_971_200;
fn reference_snapshot() -> Snapshot {
    Snapshot {
        wifi: Some(WifiStatus { associated: true, signal_dbm: Some(-63), ap: None }),
        today: Some(Counts { queries: 10_818, blocked: 4_780, cache_hits: 0, forwarded: 0 }),
        last_blocked: Some(LastBlocked { name: "tracking-intake.logs.example.com".into(), unix_secs: MIDNIGHT_UTC + 37_200, count_24h: 4_419 }),
        upstream_ms: Some(8), clock_set: true, ..Snapshot::default()
    }
}
#[test] fn the_reference_readings_give_the_approved_panel() {
    assert_eq!(panel_state(&reference_snapshot(), Some(51), None), PanelState::reference());
}
#[test] fn nothing_known_gives_the_panel_of_dashes() {
    assert_eq!(panel_state(&Snapshot::default(), None, None), PanelState::default());
}
#[test] fn a_resolver_that_has_answered_nothing_yet_shows_zero_not_a_dash() {
    let s = panel_state(&Snapshot { today: Some(Counts::default()), ..Snapshot::default() }, None, None);
    assert_eq!((s.blocked_today, s.total_today), (Some(0), Some(0)));
}
#[test] fn a_lost_association_shows_a_dash_not_the_last_signal() {
    let lost = Snapshot { wifi: Some(WifiStatus { associated: false, signal_dbm: Some(-63), ap: None }), ..reference_snapshot() };
    assert_eq!(panel_state(&lost, None, None).wifi_dbm, None);
}
#[test] fn the_time_is_local_and_unknown_until_the_clock_is_set() {
    let unset = panel_state(&Snapshot { clock_set: false, ..reference_snapshot() }, None, None).latest.unwrap();
    assert_eq!((unset.time, unset.count_day), (None, 4_419));
    let west = panel_state(&Snapshot { utc_offset_secs: -18_000, ..reference_snapshot() }, None, None).latest.unwrap();
    assert_eq!(west.time, Some(TimeOfDay { hour: 5, minute: 20 }));
    assert_eq!(time_of_day(0, -3_600), TimeOfDay { hour: 23, minute: 0 });          // no underflow at the epoch
}
#[test] fn counters_past_the_panels_range_stop_at_its_end_and_a_pause_shows_its_seconds() {
    let huge = Snapshot { today: Some(Counts { queries: u64::MAX, blocked: 7, cache_hits: 0, forwarded: 0 }), ..Snapshot::default() };
    let s = panel_state(&huge, None, Some(299));
    assert_eq!((s.total_today, s.blocked_today, s.blocking), (Some(u32::MAX), Some(7), Blocking::Paused { left_secs: 299 }));
}
```

`graphics`, `HDMI` and `reference_snapshot` are `pub(crate)` in their test modules: the tests of Tasks 3, 5 and 11 use them.

- [ ] **Step 3: Run** `cargo test -p qberrypi` — expected: compile failure (`find_screen` not found).
- [ ] **Step 4: Implement** the four modules; `panel/mod.rs` holds `pub mod fb; pub mod view;` for now. `Framebuffer::show` uses `std::os::unix::fs::FileExt::write_all_at(frame, 0)`.
- [ ] **Step 5: Run** the three checks — expected: 12 new tests pass, no warnings.
- [ ] **Step 6: Commit** — `git add crates/qberrypi/Cargo.toml Cargo.lock crates/qberrypi/src/lib.rs crates/qberrypi/src/live.rs crates/qberrypi/src/thermal.rs crates/qberrypi/src/panel/mod.rs crates/qberrypi/src/panel/fb.rs crates/qberrypi/src/panel/view.rs`, message `"Panel: find the screen, read the board, turn readings into the panel's state"`.

---

### Task 3: First light — the panel on the real screen

**Files:**
- Modify: `crates/qberrypi/src/panel/mod.rs`, `crates/qberrypi/src/init.rs`, `xtask/src/deploy.rs`, `xtask/src/qemu.rs`

**Interfaces:**
- Consumes: Task 1's `PANEL_MODULES`; Task 2's `find_screen`, `detach_console`, `Framebuffer`, `Source`, `Nothing`, `read_c`, `BOARD_TEMP`, `panel_state`; `qb_panel::render_rgb565`; `modules::{ModuleTable, load, Insert, MODULE_LIST}`; `sys::insert_module`.
- Produces, in `panel/mod.rs`:

```rust
pub const REDRAW_MS: u64 = 5_000;
pub const SCREEN_WAIT: Duration = Duration::from_secs(2);
pub trait Surface { fn show(&mut self, frame: &[u8]) -> io::Result<()>; }      // implemented for fb::Framebuffer
pub struct Deps { pub source: Arc<dyn Source> }                                 // Tasks 5 and 6 add fields
#[derive(Debug, PartialEq)] pub enum PanelEnd { NoScreen(String), Failed(String) }
pub struct Roots { pub module_list: PathBuf, pub sys_graphics: PathBuf, pub sys_vtconsole: PathBuf, pub dev: PathBuf }
impl Roots { pub fn real() -> Self; }
pub fn bring_up(roots: &Roots, insert: Insert, wait: Duration) -> Result<Screen, PanelEnd>;
pub struct Panel<S: Surface> { /* private */ }
impl<S: Surface> Panel<S> {
    pub fn new(surface: S, deps: Deps, board_temp: PathBuf) -> Self;
    /// Draws if a draw is due at `now_ms`; returns how many milliseconds may pass before the next call.
    pub fn turn(&mut self, now_ms: u64) -> io::Result<u64>;
}
pub fn run(deps: Deps) -> PanelEnd;       // returns only when the panel cannot go on
```

  In `xtask/src/deploy.rs`: `fn back_within(return_after_secs: u64) -> Duration`, and `wait_for_return` takes that limit instead of the constant. In `init.rs`: `fn start_panel()`, and

```rust
#[derive(Debug, PartialEq)] enum FatalEntry { First, Again, Elsewhere }
fn fatal_entry(begun_by: Option<ThreadId>, me: ThreadId) -> FatalEntry;
fn may_pet(fatal_thread: Option<ThreadId>, me: ThreadId) -> bool;
```

`bring_up`: parse the table at `module_list`; `modules::load` each of `PANEL_MODULES` (a failure is `NoScreen("loading {name}: {error}")`); log `panel: modules: inserted {names}`; ask `find_screen` every 50 ms until it stops answering `Absent` or `wait` has passed. `Absent` → `NoScreen("no fb_ili9486 framebuffer")`; `Wrong(found)` → `NoScreen("fb_ili9486 is {found}, not 480,320 at 16 bpp")`. If the screen is `sole`, `detach_console`, and log `panel: the text console was on the screen; detached` when it returns true. Log `panel: fb_ili9486 is {device}, 480 x 320, 16 bpp`.

`run`: `bring_up(&Roots::real(), &mut sys::insert_module, SCREEN_WAIT)`, open the framebuffer (an error is `Failed`), then for ever: `turn(now)`, sleep what it returned; an error from `turn` is `Failed("writing the screen: {error}")`. `now` is milliseconds since `run` began, from one `Instant`.

`start_panel` spawns a thread named `panel` that calls `panel::run(Deps { source: Arc::new(live::Nothing) })` and logs how it ended: `NoScreen(why)` as `log::warn!("panel: {why}; running without it")`, `Failed(why)` as `log::error!("panel: {why}")`. It is called in `init::run` right after `load_wifi_driver`. (Task 7 moves it under the supervisor.)

`fatal` with more than one thread: a `static FATAL_THREAD: OnceLock<ThreadId>` takes the place of `FATAL_BEGUN`. `First` goes on as today. `Again` (the rescue itself failed, on the thread that runs it) restarts at once, as today's second call does. `Elsewhere` parks for ever: the first thread restarts the board. `pet_watchdog` pets only if `may_pet`: once a fatal error has begun, only its thread pets, so a rescue that hangs is ended by the watchdog and not kept alive by a loop elsewhere.

- [ ] **Step 1: Write the failing tests**

`panel/mod.rs`. `recorder()` returns a `Surface` that keeps every frame and a handle to read them; `Broken` is a `Surface` whose `show` fails; `Fixed(Snapshot)` is a `Source`; `temp("51000\n")` is a temporary file's path; `roots(&[...])` builds temporary `Roots` whose module list is `DEFAULT_TABLE`, whose graphics directory is Task 2's `graphics(..)`, and whose `vtconsole` has `vtcon1` bound.

```rust
#[test] fn the_first_turn_draws_and_then_every_five_seconds() {
    let (surface, frames) = recorder();
    let mut panel = Panel::new(surface, Deps { source: Arc::new(Nothing) }, temp("51000\n"));
    assert_eq!(panel.turn(0).unwrap(), 5_000);
    assert_eq!(panel.turn(4_999).unwrap(), 1);
    assert_eq!(frames.count(), 1);
    assert_eq!(panel.turn(5_000).unwrap(), 5_000);
    assert_eq!(frames.count(), 2);
}
#[test] fn the_frame_is_the_panel_of_what_is_known_now() {
    let (surface, frames) = recorder();
    Panel::new(surface, Deps { source: Arc::new(Nothing) }, temp("51000\n")).turn(0).unwrap();
    assert_eq!(frames.last(), render_rgb565(&PanelState { board_c: Some(51), ..PanelState::default() }));
    let (surface, frames) = recorder();
    Panel::new(surface, Deps { source: Arc::new(Fixed(reference_snapshot())) }, temp("51000\n")).turn(0).unwrap();
    assert_eq!(frames.last(), render_rgb565(&PanelState::reference()));
}
#[test] fn a_screen_that_cannot_be_written_ends_the_turn_with_its_error() {
    assert!(Panel::new(Broken, Deps { source: Arc::new(Nothing) }, temp("51000\n")).turn(0).is_err());
}
#[test] fn a_board_without_the_screen_is_no_screen_not_a_failure() {
    let r = roots(&[HDMI]);
    assert_eq!(bring_up(&r, &mut |_, _| Ok(()), Duration::ZERO), Err(PanelEnd::NoScreen("no fb_ili9486 framebuffer".into())));
}
#[test] fn a_driver_that_does_not_load_is_no_screen_and_names_the_module() {
    let r = roots(&[HDMI, ("fb1", "fb_ili9486", "480,320", "16")]);
    let mut insert = |file: &Path, _: &str| if file.ends_with("fbtft.ko") { Err(io::Error::other("bad signature")) } else { Ok(()) };
    assert_eq!(bring_up(&r, &mut insert, Duration::ZERO), Err(PanelEnd::NoScreen("loading fb_ili9486: bad signature".into())));
}
#[test] fn a_screen_in_another_rotation_is_refused() {
    let r = roots(&[HDMI, ("fb1", "fb_ili9486", "320,480", "16")]);
    assert!(matches!(bring_up(&r, &mut |_, _| Ok(()), Duration::ZERO), Err(PanelEnd::NoScreen(why)) if why.contains("320,480")));
}
#[test] fn the_console_is_taken_off_the_screen_only_when_it_is_the_only_framebuffer() {
    let alone = roots(&[("fb0", "fb_ili9486", "480,320", "16")]);
    assert_eq!(bring_up(&alone, &mut |_, _| Ok(()), Duration::ZERO).unwrap().device, alone.dev.join("fb0"));
    assert_eq!(fs::read_to_string(alone.sys_vtconsole.join("vtcon1/bind")).unwrap(), "0");
    let beside_hdmi = roots(&[HDMI, ("fb1", "fb_ili9486", "480,320", "16")]);
    bring_up(&beside_hdmi, &mut |_, _| Ok(()), Duration::ZERO).unwrap();
    assert_eq!(fs::read_to_string(beside_hdmi.sys_vtconsole.join("vtcon1/bind")).unwrap(), "1\n");
}
```

`init.rs`:

```rust
#[test] fn a_second_fatal_error_waits_for_the_first_unless_it_is_the_first_failing_again() {
    let (a, b) = (thread::current().id(), thread::spawn(|| thread::current().id()).join().unwrap());
    assert_eq!(fatal_entry(None, a), FatalEntry::First);
    assert_eq!(fatal_entry(Some(a), a), FatalEntry::Again);
    assert_eq!(fatal_entry(Some(a), b), FatalEntry::Elsewhere);
    assert!(may_pet(None, a) && may_pet(Some(a), a) && !may_pet(Some(a), b));
}
```

`deploy.rs`:

```rust
#[test] fn the_wait_for_the_return_covers_the_configured_run() {
    let secs = Duration::from_secs;
    assert_eq!((back_within(0), back_within(40), back_within(400)), (secs(300), secs(300), secs(580)));   // at least 300 s, else the run and 180 s
}
```

- [ ] **Step 2: Run** `cargo test -p qberrypi panel && cargo test -p qberrypi init && cargo test -p xtask deploy` — expected: compile failures.
- [ ] **Step 3: Implement.** In `qemu.rs`: a constant `NO_PANEL: &str = "panel: no fb_ili9486 framebuffer"` joins the warnings of `Allowed::NO_WATCHDOG_NO_LED` and of the no-console scenario, and `one_shot_conditions` gains `evidence.serial_has("INFO  panel: modules: inserted spi-bcm2835, backlight, fbtft, fb_ili9486, ads7846")`. `deploy_with` passes `back_within(debug.return_after_secs)` and prints that number in its "waiting up to" line.
- [ ] **Step 4: Run** the three checks, then `cargo xtask build && cargo xtask qemu-test` — expected: all pass; the one-shot scenario shows the modules line; no scenario has an unexpected warning.
- [ ] **Step 5: Commit** — `git add crates/qberrypi/src/panel/mod.rs crates/qberrypi/src/init.rs xtask/src/deploy.rs xtask/src/qemu.rs`, message `"Panel: bring the screen up and draw every five seconds; fatal errors with more than one thread"`.
- [ ] **Step 6: Pi check A (session lead; the owner looks at the screen)** — `return_after_secs = 120`.
  The collected log must contain `INFO  panel: modules: inserted spi-bcm2835, backlight, fbtft, fb_ili9486, ads7846` and `INFO  panel: fb_ili9486 is /dev/fb` (any number), and no `WARN  panel:` and no `ERROR` line.
  The owner must see, for the two minutes: the panel upright and filling the screen; the dial empty with `—`; `Upstream —`, `Wi-Fi —`, and `Board` with a temperature in °C and a lit bar; `—` in the window; the switch lit and reading `on`; `—` in the footer; no console text and no cursor on it at any time. Record in the task report whether an HDMI display was attached and whether the log has `panel: the text console was on the screen; detached`.

---

### Task 4: Touch input

**Files:**
- Create: `crates/qberrypi/src/panel/touch.rs`
- Modify: `crates/qberrypi/src/panel/mod.rs` (module line), `crates/qberrypi/Cargo.toml`, `Cargo.lock`

**Interfaces:**
- Consumes: `qb_panel::{Calibration, TouchEvent, to_screen}`.
- Produces:

```rust
pub const TOUCH_NAME: &str = "ADS7846 Touchscreen";
pub const SYS_INPUT: &str = "/sys/class/input";
pub const EVENT_BYTES: usize = 24;
pub fn find_touch(sys_input: &Path, dev_input: &Path) -> Option<PathBuf>;     // <dev_input>/eventN
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawEvent { pub at_ms: u64, pub kind: u16, pub code: u16, pub value: i32 }
pub fn parse_event(bytes: &[u8; EVENT_BYTES]) -> RawEvent;
pub fn read_events(device: &mut (impl Read + AsFd), timeout: Duration) -> io::Result<Vec<RawEvent>>;
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum Decoded { Touch(TouchEvent), Lost }
#[derive(Default)] pub struct Decoder { /* private */ }
impl Decoder {
    pub fn feed(&mut self, event: RawEvent, calibration: &Calibration) -> Option<(u64, Decoded)>;
    pub fn raw(&self) -> (u16, u16);         // the last ABS_X and ABS_Y readings
    pub fn down(&self) -> bool;              // as of the last report
}
```

Rules:

- `find_touch` takes the `event*` directory of `sys_input` whose `device/name` (trimmed) is `TOUCH_NAME`, whatever its number.
- `parse_event`: native byte order; `at_ms = seconds × 1000 + microseconds / 1000` (negative parts count as 0). The kernel stamps events with the wall clock; `qb-panel`'s tracker treats a clock that went backwards as a press of 0 ms.
- `read_events` waits with `rustix::event::poll` for the device to be readable, at most `timeout`, then makes one `read` of up to 64 events. Nothing readable in time is an empty list. A read whose length is not a multiple of 24 is `ErrorKind::InvalidData`.
- `Decoder`: `EV_ABS` (3) with `ABS_X` (0) or `ABS_Y` (1) stores the value held to 0–4095; `EV_KEY` (1) with `BTN_TOUCH` (0x14a) stores whether it is pressed; everything else but the two below is ignored. `EV_SYN` (0) `SYN_REPORT` (0) compares with the report before it: released → pressed is `Touch(Down { x, y })`; pressed → pressed is `Touch(Move { x, y })` if the screen point differs from the one last given out, else nothing; pressed → released is `Touch(Up)`. The point is `to_screen(calibration, raw_x, raw_y)`; the time is the report's. `EV_SYN` `SYN_DROPPED` (3) means the kernel lost events: if pressed, the decoder becomes released and gives `Lost`; otherwise nothing.

- [ ] **Step 1: Add the feature** — `cargo add -p qberrypi rustix --features event`.
- [ ] **Step 2: Write the failing tests.** `ev(at_ms, kind, code, value)` makes a `RawEvent`; `key`, `abs_x`, `abs_y`, `pressure`, `syn`, `dropped` are shorthands for it (`key(1000, 1)` is `BTN_TOUCH` pressed at 1000 ms); `decode(&events)` feeds a fresh `Decoder` with `Calibration::NOMINAL` and collects what comes out.

```rust
use Decoded::{Lost, Touch};
use TouchEvent::{Down, Move, Up};
#[test] fn an_event_is_24_bytes_seconds_microseconds_type_code_value() {
    let mut b = [0u8; 24];
    b[..8].copy_from_slice(&3i64.to_ne_bytes());
    b[8..16].copy_from_slice(&250_000i64.to_ne_bytes());
    b[16..18].copy_from_slice(&3u16.to_ne_bytes());
    b[18..20].copy_from_slice(&1u16.to_ne_bytes());
    b[20..].copy_from_slice(&(-7i32).to_ne_bytes());
    assert_eq!(parse_event(&b), RawEvent { at_ms: 3_250, kind: 3, code: 1, value: -7 });
}
#[test] fn a_press_a_drag_and_a_release_become_down_move_up() {
    let out = decode(&[key(1000, 1), abs_x(1000, 1125), abs_y(1000, 2975), pressure(1000, 180), syn(1000),
                       abs_x(1040, 200), syn(1040), pressure(1060, 150), syn(1060),
                       key(1100, 0), pressure(1100, 0), syn(1100)]);
    assert_eq!(out, [(1000, Touch(Down { x: 120, y: 239 })), (1040, Touch(Move { x: 0, y: 239 })), (1100, Touch(Up))]);
}
#[test] fn a_second_press_on_the_same_spot_reuses_the_last_reading() {
    // the kernel sends an axis only when its value changes
    let out = decode(&[key(0, 1), abs_x(0, 1125), abs_y(0, 2975), syn(0), key(80, 0), syn(80), key(500, 1), syn(500), key(580, 0), syn(580)]);
    assert_eq!(out[2], (500, Touch(Down { x: 120, y: 239 })));
    assert_eq!(out.len(), 4);
}
#[test] fn lost_events_cancel_the_press() {
    let out = decode(&[key(0, 1), abs_x(0, 1125), abs_y(0, 2975), syn(0), dropped(40), key(90, 0), syn(90), dropped(95)]);
    assert_eq!(out, [(0, Touch(Down { x: 120, y: 239 })), (40, Lost)]);
}
#[test] fn readings_outside_twelve_bits_are_held_to_the_range() {
    let mut d = Decoder::default();
    for e in [abs_x(0, -5), abs_y(0, 70_000)] { d.feed(e, &Calibration::NOMINAL); }
    assert_eq!((d.raw(), d.down()), ((0, 4095), false));
}
#[test] fn the_touch_device_is_found_by_name_not_number() {
    // sys_input: event0/device/name "vc4-hdmi\n", event1/device/name "ADS7846 Touchscreen\n", mouse0/ without a name
    assert_eq!(find_touch(sys.path(), Path::new("/dev/input")), Some("/dev/input/event1".into()));
    // with the two names exchanged: Some("/dev/input/event0"); without the touch device: None
}
#[test] fn events_are_read_whole_and_a_quiet_device_gives_none() {
    let (mut reader, mut writer) = std::io::pipe().unwrap();
    assert!(read_events(&mut reader, Duration::from_millis(20)).unwrap().is_empty());
    writer.write_all(&[bytes_of(key(1, 1)), bytes_of(syn(1))].concat()).unwrap();      // bytes_of: the inverse of parse_event
    assert_eq!(read_events(&mut reader, Duration::from_secs(5)).unwrap(), [key(1, 1), syn(1)]);
    writer.write_all(&[0; 10]).unwrap();
    assert_eq!(read_events(&mut reader, Duration::from_secs(5)).unwrap_err().kind(), ErrorKind::InvalidData);
}
```

- [ ] **Step 3: Run** `cargo test -p qberrypi touch` — expected: compile failure.
- [ ] **Step 4: Implement `touch.rs`.**
- [ ] **Step 5: Run** the three checks — expected: 7 new tests pass, no warnings.
- [ ] **Step 6: Commit** — `git add crates/qberrypi/Cargo.toml Cargo.lock crates/qberrypi/src/panel/mod.rs crates/qberrypi/src/panel/touch.rs`, message `"Panel: find the touch device and decode its events"`.

---

### Task 5: The switch

**Files:**
- Modify: `crates/qberrypi/src/live.rs`, `crates/qberrypi/src/panel/mod.rs`, `crates/qberrypi/src/init.rs` (the `Deps` it builds)

**Interfaces:**
- Consumes: Task 4's `RawEvent`, `Decoder`, `Decoded`, `find_touch`, `read_events`; `qb_panel::{TapTracker, Control, Switch, Blocking, Calibration}`, `qb_panel::touch::PAUSE_MS`.
- Produces:

```rust
// live.rs
/// What the panel's switch controls. Times are relative, so the implementor's own clock decides.
pub trait BlockingControl: Send + Sync {
    fn paused_left_secs(&self) -> Option<u16>;      // seconds left, rounded up; None while blocking is on
    fn pause_for(&self, secs: u16);
    fn resume(&self);
}
pub struct StandIn { /* a qb_panel::Switch and a clock */ }
impl StandIn { pub fn new(mono_ms: impl Fn() -> u64 + Send + Sync + 'static) -> Self; }   // impl BlockingControl

// panel/mod.rs
pub const COUNTDOWN_MS: u64 = 1_000;
pub const PAUSE_SECS: u16 = 300;                    // qb_panel::touch::PAUSE_MS / 1000
pub struct Deps { pub source: Arc<dyn Source>, pub control: Arc<dyn BlockingControl>, pub calibration: Calibration }
impl<S: Surface> Panel<S> { pub fn touch(&mut self, events: &[RawEvent]); }
```

`Panel::touch` feeds each event to its `Decoder`. `Touch(e)` goes to its `TapTracker` with the event's time; `Lost` replaces the tracker with a new one, so the press is forgotten. When the tracker returns `Control::BlockingSwitch`: if `control.paused_left_secs()` is `Some`, call `resume()` and log `panel: switch: resumed`; otherwise `pause_for(PAUSE_SECS)` and log `panel: switch: paused for 300 s`. Either way the next `turn` draws whatever the time.

`Panel::turn` now builds the state with `control.paused_left_secs()`, and returns at most `COUNTDOWN_MS` while a pause is running. When it sees a pause gone that no tap ended, it logs `panel: switch: the pause ended`.

`run`, after the framebuffer is open: `find_touch(SYS_INPUT, "/dev/input")`, asked for up to `SCREEN_WAIT`. Without one, log `log::warn!("panel: no ADS7846 touch device; the switch will not work")` once and keep drawing. The loop becomes: `touch(&events)`, `turn(now)`, then `read_events(&mut device, wait)` (or a sleep, without a device). A read error is `Failed("reading the touch device: {error}")`. `init` builds `Deps` with `Arc::new(StandIn::new(..))` on an `Instant` of its own and `Calibration::NOMINAL`.

- [ ] **Step 1: Write the failing tests.** `tap(at, held_ms, raw)` is the events of one press: `BTN_TOUCH` 1, both axes and a report at `at`; `BTN_TOUCH` 0 and a report at `at + held_ms`. `FakeControl` implements `BlockingControl`: `pause_for(n)` records `"pause {n}"` and makes `paused_left_secs` return `Some(n)`, `resume` records `"resume"` and makes it `None`, and `set_left` lets a test set it directly. `panel()` builds a `Panel` over `recorder()`, `Nothing`, a `FakeControl`, `Calibration::NOMINAL` and `temp("51000\n")`.

```rust
const ON_SWITCH: (i32, i32) = (509, 3564);      // NOMINAL maps it to (40, 290)
const ELSEWHERE: (i32, i32) = (2054, 1360);     // (240, 100)
#[test] fn a_tap_on_the_switch_pauses_for_five_minutes_and_is_drawn_at_once() {
    let (mut panel, frames, control) = panel();
    panel.turn(0).unwrap();
    panel.touch(&tap(1_000, 60, ON_SWITCH));            // both halves in one read: timed by the events, not by the read
    assert_eq!(control.calls(), ["pause 300"]);
    assert_eq!(panel.turn(1_100).unwrap(), 1_000);      // drawn now, and every second while the pause runs
    assert_eq!(frames.last(), render_rgb565(&PanelState { board_c: Some(51), blocking: Blocking::Paused { left_secs: 300 }, ..PanelState::default() }));
}
#[test] fn a_tap_while_paused_resumes() {
    let (mut panel, _, control) = panel();
    control.set_left(Some(120));
    panel.touch(&tap(1_000, 60, ON_SWITCH));
    assert_eq!(control.calls(), ["resume"]);
    assert_eq!(panel.turn(1_100).unwrap(), 5_000);
}
#[test] fn a_brush_and_a_tap_elsewhere_change_nothing() {
    let (mut panel, frames, control) = panel();
    panel.turn(0).unwrap();
    panel.touch(&tap(1_000, 30, ON_SWITCH));
    panel.touch(&tap(2_000, 200, ELSEWHERE));
    panel.turn(2_500).unwrap();
    assert!(control.calls().is_empty());
    assert_eq!(frames.count(), 1);
}
#[test] fn a_finger_left_on_the_switch_toggles_once_when_it_lifts() {
    let (mut panel, _, control) = panel();
    panel.touch(&tap(1_000, 240_000, ON_SWITCH));
    assert_eq!(control.calls(), ["pause 300"]);
}
#[test] fn a_press_cut_off_by_lost_events_does_not_toggle() {
    let (mut panel, _, control) = panel();
    let press = tap(1_000, 200, ON_SWITCH);
    let (down, up) = press.split_at(4);                 // tap() is four events down, two up
    panel.touch(down);
    panel.touch(&[dropped(1_100)]);
    panel.touch(up);
    assert!(control.calls().is_empty());
}
#[test] fn a_pause_that_ends_by_itself_goes_back_to_five_second_draws() {
    let (mut panel, _, control) = panel();
    control.set_left(Some(1));
    assert_eq!(panel.turn(0).unwrap(), 1_000);
    control.set_left(None);
    assert_eq!(panel.turn(1_000).unwrap(), 5_000);
}
```

`live.rs`:

```rust
#[test] fn the_stand_in_pauses_for_the_time_asked_and_ends_by_itself() {
    let now = Arc::new(AtomicU64::new(10_000));
    let stand_in = StandIn::new({ let now = now.clone(); move || now.load(Ordering::SeqCst) });
    assert_eq!(stand_in.paused_left_secs(), None);
    stand_in.pause_for(300);
    assert_eq!(stand_in.paused_left_secs(), Some(300));
    now.store(309_999, Ordering::SeqCst);
    assert_eq!(stand_in.paused_left_secs(), Some(1));
    now.store(310_000, Ordering::SeqCst);
    assert_eq!(stand_in.paused_left_secs(), None);
    stand_in.pause_for(300);
    stand_in.resume();
    assert_eq!(stand_in.paused_left_secs(), None);
}
```

- [ ] **Step 2: Run** `cargo test -p qberrypi panel && cargo test -p qberrypi live` — expected: compile failures.
- [ ] **Step 3: Implement.** `StandIn` keeps a `Mutex<Switch>`: `pause_for` stores `Switch::PausedUntil(now + secs × 1000)`, and `paused_left_secs` reads `Switch::blocking(now)`.
- [ ] **Step 4: Run** the three checks, then `cargo xtask build && cargo xtask qemu-test` — expected: all pass.
- [ ] **Step 5: Commit** — `git add crates/qberrypi/src/live.rs crates/qberrypi/src/panel/mod.rs crates/qberrypi/src/init.rs`, message `"Panel: a tap on the switch pauses and resumes, on a stand-in until the resolver is there"`.

---

### Task 6: Touch calibration on the real panel

**Files:**
- Create: `crates/qberrypi/src/panel/calibrate.rs`
- Modify: `crates/qberrypi/src/config.rs`, `crates/qberrypi/src/panel/mod.rs`, `crates/qberrypi/src/init.rs`, `qberrypi.example.toml`, `README.md`

**Interfaces:**
- Consumes: Task 3's `Surface`; Task 4's `RawEvent`; `qb_panel::{Calibration, to_screen, rgba_to_rgb565}`, `qb_panel::text::draw_text`, `qb_panel::geometry::{TextSlot, Anchor, Weight, WHITE, MUTED}`.
- Produces:

```rust
// config.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PanelCfg { pub touch_left: u16, pub touch_right: u16, pub touch_top: u16, pub touch_bottom: u16, pub touch_swap_xy: bool }
impl PanelCfg { pub fn calibration(&self) -> qb_panel::Calibration; }
// Config gains `pub panel: PanelCfg`; DebugCfg gains `pub calibrate_touch: bool`

// panel/calibrate.rs
pub const TARGETS: [(u16, u16); 4] = [(40, 40), (439, 40), (439, 279), (40, 279)];
pub const TARGET_WAIT_MS: u64 = 60_000;
pub fn target_frame(index: usize) -> Vec<u8>;                    // RGB565, 307,200 bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub struct Reading { pub raw_x: u16, pub raw_y: u16 }
#[derive(Default)] pub struct Collector { /* private */ }
impl Collector { pub fn feed(&mut self, event: RawEvent) -> Option<Reading>; }
pub fn solve(readings: &[Reading; 4]) -> Result<Calibration, &'static str>;
pub fn toml_lines(calibration: &Calibration) -> [String; 6];
pub fn calibrate(surface: &mut dyn Surface, wait: &mut dyn FnMut(u64) -> io::Result<Vec<RawEvent>>, now_ms: &dyn Fn() -> u64)
    -> io::Result<Option<Calibration>>;
// panel/mod.rs: Deps gains `pub calibrate: bool`
```

Configuration: an optional `[panel]` table with `touch_left`, `touch_right`, `touch_top`, `touch_bottom` (whole numbers 0–4095; defaults 200, 3900, 200, 3900) and `touch_swap_xy` (default `false`). `touch_left` must differ from `touch_right` and `touch_top` from `touch_bottom`; the error names the second key of the pair. `[debug] calibrate_touch` is a boolean, default `false`. Unknown keys are refused as everywhere else.

`target_frame(i)`: black; at `TARGETS[i]` a white cross, two pixels thick with arms 14 pixels long; in the middle of the screen `Tap the cross` (white, bold, 22 px, baseline 156, centred on x = 240) and `{i + 1} of 4` (muted, regular, 17 px, baseline 186), drawn with `qb_panel::text::draw_text` into an RGBA buffer and converted with `rgba_to_rgb565`.

`Collector`: follows `BTN_TOUCH`, `ABS_X`, `ABS_Y` like the decoder but in raw units. Each `SYN_REPORT` while pressed records the current reading. On the report that releases: with three or more recorded readings, the result is the median of each axis (`sorted[len / 2]`); with fewer, nothing. `SYN_DROPPED` discards the press.

`solve`, in signed arithmetic:

```
swap_xy = |raw_x[1] − raw_x[0]| < |raw_y[1] − raw_y[0]|     targets 0 and 1 differ only in screen x
h, v    = (raw_y, raw_x) if swap_xy else (raw_x, raw_y)
h_l = (h[0] + h[3]) / 2    h_r = (h[1] + h[2]) / 2    v_t = (v[0] + v[1]) / 2    v_b = (v[2] + v[3]) / 2
left  = h_l − 40 × (h_r − h_l) / 399        right  = h_r + 40 × (h_r − h_l) / 399
top   = v_t − 40 × (v_b − v_t) / 239        bottom = v_b + 40 × (v_b − v_t) / 239      each rounded, held to 0..=4095
```

It is refused with `"the four readings are too close together"` if `|h_r − h_l| < 1000` or `|v_b − v_t| < 1000`, and with `"the readings do not form a rectangle"` if `|h[0] − h[3]|`, `|h[1] − h[2]|`, `|v[0] − v[1]|` or `|v[2] − v[3]|` is more than a quarter of the matching span.

`calibrate`: for each target, `show(target_frame(i))`, then call `wait(100)` and feed a `Collector` until it yields a reading, or `TARGET_WAIT_MS` has passed on `now_ms`, which ends the run with `Ok(None)` after logging `panel: calibration: no tap on target {n} of 4; keeping the configured calibration`. Each reading is logged as `panel: calibration: target {n} of 4 at ({x}, {y}): raw ({raw_x}, {raw_y})`. After the fourth, `solve`: an error is logged as `panel: calibration: {error}; keeping the configured calibration` and gives `Ok(None)`; a result is logged as one `panel: calibration: {line}` per line of `toml_lines` and returned.

`run`: when `deps.calibrate` and a touch device was found, `calibrate` runs before the loop and its result, if any, replaces `deps.calibration` for this boot. Nothing is written anywhere.

- [ ] **Step 1: Write the failing tests**

`config.rs` (`EXAMPLE` is the example file, which has no `[panel]` table):

```rust
#[test] fn without_a_panel_table_the_calibration_is_the_nominal_one_and_the_switch_is_off() {
    let cfg = parse(EXAMPLE).unwrap();
    assert_eq!(cfg.panel, PanelCfg { touch_left: 200, touch_right: 3900, touch_top: 200, touch_bottom: 3900, touch_swap_xy: false });
    assert!(!cfg.debug.calibrate_touch);
}
#[test] fn a_calibration_is_read_and_may_run_backwards() {
    let text = format!("{EXAMPLE}\n[panel]\ntouch_left = 3890\ntouch_right = 210\ntouch_top = 300\ntouch_swap_xy = true\n");
    let cfg = parse(&text.replace("calibrate_touch = false", "calibrate_touch = true")).unwrap();
    assert_eq!(cfg.panel, PanelCfg { touch_left: 3890, touch_right: 210, touch_top: 300, touch_bottom: 3900, touch_swap_xy: true });
    assert!(cfg.debug.calibrate_touch);
    let c = cfg.panel.calibration();
    assert_eq!((c.left, c.right, c.top, c.bottom, c.swap_xy), (3890, 210, 300, 3900, true));
}
#[test] fn a_calibration_no_panel_could_have_is_refused_by_key() {
    for (line, key) in [("touch_left = 4096", "panel.touch_left"), ("touch_top = -1", "panel.touch_top"),
                        ("touch_right = 200", "panel.touch_right"), ("touch_bottom = 200", "panel.touch_bottom"),
                        ("touch_swap_xy = 1", "panel.touch_swap_xy"), ("rotate = 90", "panel.rotate")] {
        assert_eq!(parse(&format!("{EXAMPLE}\n[panel]\n{line}\n")).unwrap_err().key, key);
    }
}
```

`calibrate.rs`. `raw_at(&cal, x, y)` is the reading a panel with that calibration gives at a screen point: `left + x × (right − left) / 479` and `top + y × (bottom − top) / 319`, rounded, exchanged when `swap_xy`. `press(at, raw, reports)` is the events of one press with that many reports 20 ms apart.

```rust
#[test] fn four_taps_give_back_the_calibration_that_made_them() {
    for cal in [Calibration::NOMINAL,
                Calibration { swap_xy: false, left: 3890, right: 210, top: 300, bottom: 3800 },
                Calibration { swap_xy: true, left: 250, right: 3850, top: 3900, bottom: 180 }] {
        let solved = solve(&TARGETS.map(|(x, y)| raw_at(&cal, x, y))).unwrap();
        assert_eq!(solved.swap_xy, cal.swap_xy);
        for (got, want) in [(solved.left, cal.left), (solved.right, cal.right), (solved.top, cal.top), (solved.bottom, cal.bottom)] {
            assert!(got.abs_diff(want) <= 4, "{got} for {want}");
        }
        for (x, y) in TARGETS {
            let r = raw_at(&cal, x, y);
            let (sx, sy) = to_screen(&solved, r.raw_x, r.raw_y);
            assert!(sx.abs_diff(x) <= 1 && sy.abs_diff(y) <= 1, "({sx}, {sy}) for ({x}, {y})");
        }
    }
}
#[test] fn taps_that_cannot_be_the_four_targets_are_refused() {
    assert_eq!(solve(&[Reading { raw_x: 2000, raw_y: 2000 }; 4]).unwrap_err(), "the four readings are too close together");
    let mut r = TARGETS.map(|(x, y)| raw_at(&Calibration::NOMINAL, x, y));
    r[3] = r[2];                                              // the fourth cross was not the one tapped
    assert_eq!(solve(&r).unwrap_err(), "the readings do not form a rectangle");
}
#[test] fn a_reading_is_the_median_of_a_press_and_a_short_touch_is_none() {
    // one press reporting (600, 3500), (640, 3480), (2000, 100), (620, 3490), (610, 3495), then the release
    assert_eq!(collected, Some(Reading { raw_x: 620, raw_y: 3490 }));
    // a press of two reports, and a press cut by SYN_DROPPED: None
}
#[test] fn each_cue_marks_its_own_target_in_white_on_black() {
    for (i, (x, y)) in TARGETS.into_iter().enumerate() {
        let frame = target_frame(i);
        assert_eq!(frame.len(), 307_200);
        let px = |x: u16, y: u16| { let at = (usize::from(y) * 480 + usize::from(x)) * 2; [frame[at], frame[at + 1]] };
        assert_eq!(px(x, y), [0xff, 0xff]);
        for other in TARGETS { if other != (x, y) { assert_eq!(px(other.0, other.1), [0, 0]); } }
    }
}
#[test] fn the_result_is_the_lines_to_paste_into_the_configuration() {
    assert_eq!(toml_lines(&Calibration { swap_xy: false, left: 3890, right: 210, top: 300, bottom: 3800 }),
               ["[panel]", "touch_left = 3890", "touch_right = 210", "touch_top = 300", "touch_bottom = 3800", "touch_swap_xy = false"]);
}
#[test] fn the_four_cues_come_in_order_and_the_taps_become_the_calibration() {
    // wait() hands out press(.., raw_at(&cal, TARGETS[n]), 5) on its n-th call; now_ms counts 100 per call
    // result: Some(calibration within 4 of cal); the recorder holds exactly target_frame(0..4), in order
}
#[test] fn a_cue_nobody_taps_ends_the_calibration_after_a_minute() {
    // wait() always empty: Ok(None) once now_ms passes 60_000; the recorder holds target_frame(0) only
}
```

- [ ] **Step 2: Run** `cargo test -p qberrypi calibrate && cargo test -p qberrypi config` — expected: compile failures.
- [ ] **Step 3: Implement.** Add to `qberrypi.example.toml`, under `[debug]`: `calibrate_touch = false     # show four crosses to tap and log the touch calibration`, and at the end, commented out, the `[panel]` table with its five default lines and the sentence that a calibration boot prints them. Add to the README's Development section three sentences: set `calibrate_touch = true`, tap the four crosses, copy the five `panel: calibration:` lines from the log into `[panel]`.
- [ ] **Step 4: Run** the three checks, then `cargo xtask build && cargo xtask qemu-test` — expected: all pass.
- [ ] **Step 5: Commit** — `git add crates/qberrypi/src/config.rs crates/qberrypi/src/panel/calibrate.rs crates/qberrypi/src/panel/mod.rs crates/qberrypi/src/init.rs qberrypi.example.toml README.md`, message `"Panel: measure the touch calibration on the real screen and keep it in qberrypi.toml"`.
- [ ] **Step 6: Pi check B (session lead; the owner taps)**
  **Boot 1** — `calibrate_touch = true`, `return_after_secs = 240`. The owner presses each cross for about half a second as it appears, then, when the panel is back, taps the switch, watches a few seconds, and taps it again. The log must contain four `panel: calibration: target N of 4 at` lines, the six `panel: calibration:` lines starting with `[panel]`, then `panel: switch: paused for 300 s` and `panel: switch: resumed`. The owner must have seen `Paused`, the knob on the left counting down from `5:00` second by second, and `on` again after the second tap. If the log has `keeping the configured calibration`, repeat the boot.
  **Boot 2** — the lead copies the five values into `[panel]` of the private `qberrypi.toml`; `calibrate_touch = false`, `return_after_secs = 400`. The owner taps the switch once and leaves it. The log must contain `panel: switch: paused for 300 s` and, about 300 seconds later by its timestamps, `panel: switch: the pause ended`, with no `panel: calibration` line. A tap beside the switch (the dial, the window) must leave no log line.

---

### Task 7: The supervisor

**Files:**
- Create: `crates/qberrypi/src/supervisor.rs`
- Modify: `crates/qberrypi/src/init.rs`, `crates/qberrypi/src/led.rs` (derives), `crates/qberrypi/src/lib.rs`, `crates/qberrypi/Cargo.toml`, `Cargo.lock`, `xtask/src/qemu.rs`

**Interfaces:**
- Consumes: `panel::{run, Deps, PanelEnd}`; `live::WifiStatus`; `led::LedState`; init's `pet_watchdog`, `save_log_if_asked`, `sys::{reap_children, reboot}`.
- Produces:

```rust
pub const TICK: Duration = Duration::from_secs(5);
pub const RESTART_DELAY: Duration = Duration::from_secs(1);
pub const FAILURE_WINDOW: Duration = Duration::from_secs(60);
pub const FAILURES_TO_GIVE_UP: usize = 3;

#[derive(Debug, PartialEq)] pub enum Ended { Absent(String), Failed(String) }   // Absent: what it drives is not there; not started again
pub type Running = Pin<Box<dyn Future<Output = Ended> + Send>>;
pub struct Component { pub name: &'static str, pub essential: bool, pub start: Box<dyn FnMut() -> Running + Send> }
impl Component {
    /// A component whose work blocks a thread of its own; each start runs `work` again.
    pub fn blocking(name: &'static str, essential: bool, work: impl Fn() -> Ended + Send + Sync + 'static) -> Self;
}
#[derive(Default)] pub struct FailureLog { /* private */ }
impl FailureLog { pub fn record(&mut self, at: Duration) -> usize; }    // failures less than FAILURE_WINDOW before `at`, this one included
#[derive(Debug, PartialEq)] pub enum Reason { ComponentFailed(&'static str), NoAssociation, ReturnAfter }
// Display: "component {name} failed 3 times in a minute" | "no Wi-Fi association for 90 s" | "the configured time has passed"
pub struct Plan {
    pub components: Vec<Component>,
    pub return_after: Option<Duration>,                             // from now
    pub link: Option<tokio::sync::watch::Receiver<WifiStatus>>,     // Task 9 acts on it
}
pub struct Hooks { pub tick: Box<dyn FnMut()>, pub led: Box<dyn FnMut(LedState)> }
/// Runs every component until the board has to be restarted, and says why.
pub async fn run(plan: Plan, hooks: Hooks) -> Reason;
```

What `run` does, on `tokio::time`:

- Calls `led(LedState::Serving)` once and `tick()` at once, then `tick()` every `TICK`, whatever else happens. Nothing in `run` blocks.
- Starts every component in the order given, logging `supervisor: started {name}`.
- `Ended::Absent(why)`: `log::warn!("{name}: {why}; running without it")`; never started again.
- `Ended::Failed(why)`, or a task that panicked or was cancelled: `log::error!("supervisor: {name} failed: {why}")`, recorded in that component's `FailureLog`. Below `FAILURES_TO_GIVE_UP` in the window: started again after `RESTART_DELAY`, logging `supervisor: starting {name} again`. At it: an essential component ends `run` with `Reason::ComponentFailed(name)`; any other is left stopped with `log::error!("supervisor: {name} failed 3 times in a minute; leaving it stopped")`.
- `return_after` passing ends `run` with `Reason::ReturnAfter`.

`init`: `serve` builds a current-thread runtime with `enable_all` (a build error is fatal), makes the `Plan` — the panel as `Component::blocking("panel", false, ..)`, mapping `PanelEnd::NoScreen` to `Ended::Absent` and `Failed` to `Ended::Failed`; `return_after` as `return_after_secs` less the time since boot, `None` for 0 — and the `Hooks`: `tick` reaps children and pets the watchdog; `led` calls `led::set` and logs `activity LED: {error}` as a warning when it fails. It hands `supervisor::run` to `block_on` and gives the reason to:

```rust
/// Logs why the board restarts and saves the log if the configuration keeps it on the card.
fn leave(cfg: &Config, card: &mut dyn Card, log: &Mutex<LogBuf>, reason: &Reason);
```

`leave` logs `returning` at info for `ReturnAfter` (the line the QEMU scenarios look for) and `supervisor: restarting: {reason}` at error for the others, then `save_log_if_asked`. `serve` then calls `sys::reboot()`. `start_panel`, `show_serving`, `next_tick` and the two tests of `next_tick` go; `LedState` gains `Debug, PartialEq, Eq`.

- [ ] **Step 1: Add the dependencies** — `cargo add -p qberrypi tokio --no-default-features --features rt,time,sync,macros,net,io-util` and `cargo add -p qberrypi --dev tokio --features test-util`.
- [ ] **Step 2: Write the failing tests** in `supervisor.rs`. `failing(name, essential, starts, lives_for)` is a component that counts its starts in an `Arc<AtomicUsize>` and fails `lives_for` after each; `absent(name, starts)` ends as `Absent`; `forever(name)` never ends; `plan(components)` is a `Plan` with no return time and no link; `watch(plan, limit)` runs `run` under `tokio::time::timeout(limit, ..)` with hooks that count ticks and record LED states, and returns `(Option<Reason>, ticks, leds)`.

```rust
const HOUR: Duration = Duration::from_secs(3600);
#[test] fn failures_count_only_within_the_last_minute() {
    let secs = Duration::from_secs;
    let mut log = FailureLog::default();
    assert_eq!([log.record(secs(0)), log.record(secs(30)), log.record(secs(59))], [1, 2, 3]);
    let mut log = FailureLog::default();
    assert_eq!([log.record(secs(0)), log.record(secs(30)), log.record(secs(60))], [1, 2, 2]);   // the first is a minute old
}
#[tokio::test(start_paused = true)] async fn three_failures_in_a_minute_of_an_essential_component_restart_the_board() {
    let starts = Arc::new(AtomicUsize::new(0));
    let began = tokio::time::Instant::now();
    let (reason, ..) = watch(plan(vec![failing("dns", true, starts.clone(), Duration::ZERO)]), HOUR).await;
    assert_eq!(reason, Some(Reason::ComponentFailed("dns")));
    assert_eq!(starts.load(Ordering::SeqCst), 3);
    assert!(began.elapsed() >= 2 * RESTART_DELAY && began.elapsed() < Duration::from_secs(3));
}
#[tokio::test(start_paused = true)] async fn failures_more_than_a_minute_apart_never_add_up() {
    let starts = Arc::new(AtomicUsize::new(0));
    let (reason, ..) = watch(plan(vec![failing("dns", true, starts.clone(), Duration::from_secs(31))]), HOUR).await;
    assert_eq!(reason, None);
    assert!(starts.load(Ordering::SeqCst) > 100);            // started again every time
}
#[tokio::test(start_paused = true)] async fn a_component_that_is_not_essential_is_left_stopped_and_the_board_runs_on() {
    let starts = Arc::new(AtomicUsize::new(0));
    let (reason, ..) = watch(plan(vec![failing("panel", false, starts.clone(), Duration::ZERO), forever("dns")]), HOUR).await;
    assert_eq!((reason, starts.load(Ordering::SeqCst)), (None, 3));
}
#[tokio::test(start_paused = true)] async fn an_absent_component_is_not_started_again() {
    let starts = Arc::new(AtomicUsize::new(0));
    let (reason, ..) = watch(plan(vec![absent("panel", starts.clone())]), HOUR).await;
    assert_eq!((reason, starts.load(Ordering::SeqCst)), (None, 1));
}
#[tokio::test(start_paused = true)] async fn the_tick_comes_every_five_seconds_whatever_the_components_do() {
    let busy = failing("dns", false, Arc::new(AtomicUsize::new(0)), Duration::from_millis(1));
    let (_, ticks, leds) = watch(plan(vec![busy, forever("wifi")]), Duration::from_secs(60)).await;
    assert!((12..=14).contains(&ticks), "{ticks} ticks");
    assert_eq!(leds, [LedState::Serving]);
}
#[tokio::test(start_paused = true)] async fn the_board_returns_when_the_configured_time_has_passed() {
    let began = tokio::time::Instant::now();
    let mut p = plan(vec![forever("dns")]);
    p.return_after = Some(Duration::from_secs(40));
    assert_eq!(watch(p, HOUR).await.0, Some(Reason::ReturnAfter));
    assert_eq!(began.elapsed().as_secs(), 40);
}
#[tokio::test] async fn a_blocking_component_runs_its_work_on_every_start() {
    let runs = Arc::new(AtomicUsize::new(0));
    let mut c = Component::blocking("panel", false, { let runs = runs.clone(); move || { runs.fetch_add(1, Ordering::SeqCst); Ended::Absent("gone".into()) } });
    assert_eq!(((c.start)().await, (c.start)().await), (Ended::Absent("gone".into()), Ended::Absent("gone".into())));
    assert_eq!(runs.load(Ordering::SeqCst), 2);
}
```

`init.rs` (with the existing `FakeCard`, `cfg_debug` and `log_holding`):

```rust
#[test] fn leaving_saves_the_reason_only_where_the_log_is_kept_on_the_card() {
    let mut card = FakeCard::new();
    leave(&cfg_debug(false, false), &mut card, &log_holding(&["banner"]), &Reason::ComponentFailed("dns"));
    assert!(card.ops.is_empty());
    let mut card = FakeCard::new();
    let log = log_holding(&["banner"]);
    leave(&cfg_debug(true, true), &mut card, &log, &Reason::ReturnAfter);
    assert_eq!(card.ops, WRITE_OPS);
    assert!(card.read("qberrypi/log.txt").starts_with(&header()));
}
```

- [ ] **Step 3: Run** `cargo test -p qberrypi supervisor && cargo test -p qberrypi init` — expected: compile failures.
- [ ] **Step 4: Implement.** One `select!` over the tick interval, a `JoinSet` of running components (each task resolves to its index and its `Ended`), and a `sleep_until` the earliest of the pending restarts and the return time.

  In `qemu.rs` the `one-shot` and `permanent` scenarios get `return_after_secs = 40`; the others keep 5. The components now start in `serve`, which in QEMU is reached only after init's 20-second wait for a radio the guest does not have: with 5 the board returns before the panel has looked for its screen. With 40 it has looked, so `one_shot_conditions` and `permanent_conditions` gain `evidence.serial_has("WARN  panel: no fb_ili9486 framebuffer; running without it")`, which is Review Focus 1 seen in a whole boot. The scenarios that keep 5 only allow that line.
- [ ] **Step 5: Run** the three checks, then `cargo xtask build && cargo xtask qemu-test` — expected: all pass; every scenario that reached `INFO  returning` before still does, two of them about 20 seconds later.
- [ ] **Step 6: Commit** — `git add crates/qberrypi/Cargo.toml Cargo.lock crates/qberrypi/src/lib.rs crates/qberrypi/src/supervisor.rs crates/qberrypi/src/led.rs crates/qberrypi/src/init.rs`, message `"Supervisor: start components, restart the failed, restart the board after three failures in a minute"`.

---

### Task 8: Provoked failures, and the watchdog as the last resort

**Files:**
- Create: `crates/qberrypi/src/fault.rs`
- Modify: `crates/qberrypi/src/config.rs`, `crates/qberrypi/src/init.rs`, `crates/qberrypi/src/lib.rs`, `xtask/src/qemu.rs`, `xtask/src/deploy.rs`, `qberrypi.example.toml`

**Interfaces:**
- Consumes: Task 7's `Component`, `Ended`, `Plan`, `Hooks`.
- Produces:

```rust
// config.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum Fault { None, Stall, CrashLoop, Panic, NoWifi }
// DebugCfg gains `pub fault: Fault`: key `debug.fault`, one of "none" (default), "stall", "crash-loop", "panic", "no-wifi"

// fault.rs
pub const FAULT_AFTER: Duration = Duration::from_secs(10);
pub fn stall_due(fault: Fault, since_start: Duration) -> bool;       // Stall, and FAULT_AFTER has passed
pub fn component(fault: Fault) -> Option<Component>;                  // CrashLoop and Panic: an essential component named "fault"
```

- `CrashLoop`: every start resolves at once to `Ended::Failed("provoked".into())`.
- `Panic`: sleeps `FAULT_AFTER`, then `panic!("fault: panic")`.
- `Stall` is not a component. `init`'s `tick`, before it pets: if `stall_due(cfg.debug.fault, since_start)`, it logs `log::warn!("fault: stalling the supervisor; the watchdog must restart the board within 15 s")`, saves the log if it is kept on the card, and sleeps for ever on the supervisor's own thread. Nothing pets from then on.
- `NoWifi` is Task 9's.
- `deploy`'s `check_local` refuses `--permanent` with any fault but `none`: `"qberrypi.toml has debug.fault set: a permanent qberrypi with a provoked failure would restart for ever. Set debug.fault to \"none\""`.

- [ ] **Step 1: Write the failing tests**

`config.rs`:

```rust
#[test] fn a_fault_is_one_of_five_words_and_none_by_default() {
    assert_eq!(parse(EXAMPLE).unwrap().debug.fault, Fault::None);
    for (word, fault) in [("stall", Fault::Stall), ("crash-loop", Fault::CrashLoop), ("panic", Fault::Panic), ("no-wifi", Fault::NoWifi)] {
        assert_eq!(parse(&EXAMPLE.replace("fault = \"none\"", &format!("fault = \"{word}\""))).unwrap().debug.fault, fault);
    }
    let error = parse(&EXAMPLE.replace("fault = \"none\"", "fault = \"fire\"")).unwrap_err();
    assert_eq!((error.key.as_str(), error.reason.as_str()), ("debug.fault", "must be one of none, stall, crash-loop, panic, no-wifi"));
}
```

`fault.rs`:

```rust
#[test] fn only_the_stall_fault_stalls_and_only_after_ten_seconds() {
    let secs = Duration::from_secs;
    assert!(!stall_due(Fault::Stall, secs(9)) && stall_due(Fault::Stall, secs(10)));
    for other in [Fault::None, Fault::CrashLoop, Fault::Panic, Fault::NoWifi] { assert!(!stall_due(other, secs(3600))); }
}
#[tokio::test(start_paused = true)] async fn the_crash_loop_fails_at_once_every_time_and_is_essential() {
    let mut c = fault::component(Fault::CrashLoop).unwrap();
    assert!(c.essential && c.name == "fault");
    assert_eq!(((c.start)().await, (c.start)().await), (Ended::Failed("provoked".into()), Ended::Failed("provoked".into())));
    for none in [Fault::None, Fault::Stall, Fault::NoWifi] { assert!(fault::component(none).is_none()); }
}
```

`deploy.rs`:

```rust
#[test] fn a_provoked_failure_is_never_deployed_for_good() {
    let faulty = EXAMPLE.replace("fault = \"none\"", "fault = \"crash-loop\"");      // the example configuration: debug.one_shot is off
    assert!(check_local(&faulty, true).unwrap_err().contains("debug.fault"));
    assert!(check_local(&faulty.replace("one_shot = false", "one_shot = true"), false).is_ok());
}
```

`qemu.rs`: two scenarios, both on `Machine::Usual` with `one_shot` and `log_to_sd` on and `return_after_secs = 60`, and the test that the scenarios differ from the example only under `[debug]` extended to them. `scenarios` returns a `Vec`.

```rust
fn crash_loop_conditions(evidence: &Evidence) -> Vec<Condition> {
    const RESTARTING: &str = "ERROR supervisor: restarting: component fault failed 3 times in a minute";
    let allowed = Allowed { errors: &["supervisor: fault failed: provoked", "supervisor: restarting: component fault"],
                            warnings: &[NO_WATCHDOG, NO_LED, NO_PANEL] };
    vec![evidence.serial_has(RESTARTING), evidence.serial_lacks("INFO  returning"), evidence.restart_requested(), evidence.exited(),
         evidence.pios_config_is_active(), evidence.log_has(RESTARTING), evidence.log_is_of_one_boot_of_this_build(),
         evidence.log_lacks(PASSPHRASE), evidence.serial_has_no_unexpected_complaint(&allowed)]
}
fn panic_conditions(evidence: &Evidence) -> Vec<Condition> {
    let allowed = Allowed { errors: &["panic at "], warnings: &[NO_WATCHDOG, NO_LED, NO_PANEL] };
    vec![evidence.serial_has("fault: panic"), evidence.serial_lacks("INFO  returning"), evidence.restart_requested(), evidence.exited(),
         evidence.pios_config_is_active(), evidence.log_has("ERROR panic at "), evidence.log_is_of_one_boot_of_this_build(),
         evidence.log_lacks(PASSPHRASE), evidence.serial_has_no_unexpected_complaint(&allowed)]
}
```

  Each gets host tests in the style of the existing ones: good evidence fails no condition; evidence with `INFO  returning` in place of the restart line fails.

- [ ] **Step 2: Run** `cargo test --workspace` — expected: compile failures.
- [ ] **Step 3: Implement.** Add `fault = "none"              # development only: provoke a failure to watch the recovery` under `[debug]` of `qberrypi.example.toml`. `init` appends `fault::component(cfg.debug.fault)` to the plan's components.
- [ ] **Step 4: Run** the three checks, then `cargo xtask build && cargo xtask qemu-test` — expected: eight scenarios `ok`.
- [ ] **Step 5: Commit** — `git add crates/qberrypi/src/fault.rs crates/qberrypi/src/config.rs crates/qberrypi/src/init.rs crates/qberrypi/src/lib.rs xtask/src/qemu.rs xtask/src/deploy.rs qberrypi.example.toml`, message `"debug.fault: provoke a stall, a crash loop or a panic, and two QEMU scenarios that watch the recovery"`.
- [ ] **Step 6: Pi check C (session lead alone)** — three boots, each with `return_after_secs = 300`.
  Every one of the three logs has `INFO  supervisor: started panel` and `INFO  panel: fb_ili9486 is /dev/fb`: the panel still comes up, now under the supervisor. Times below are counted from the stamp of the `supervisor: started` lines.
  `fault = "crash-loop"`: the log has three `ERROR supervisor: fault failed: provoked` lines and then `ERROR supervisor: restarting: component fault failed 3 times in a minute`, all within five seconds, and no `returning`.
  `fault = "panic"`: the log has `ERROR panic at ` with `fault: panic` 10 to 12 seconds on, and no `returning`. The LED was on without a break for the five seconds before the restart, if someone watched.
  `fault = "stall"`: the last line of the boot's log is `WARN  fault: stalling the supervisor; the watchdog must restart the board within 15 s`, 10 to 16 seconds on; no `returning` and no `supervisor: restarting`. `deploy` reported `it is back` less than 150 seconds after it printed `qberrypi is selected; restarting`: a board that had waited for `return_after_secs` would have taken more than 300. Note the measured time in the task report.

---

### Task 9: The LED and the 90-second rule

**Files:**
- Create: `crates/qberrypi/src/link.rs`
- Modify: `crates/qberrypi/src/supervisor.rs`, `crates/qberrypi/src/fault.rs`, `crates/qberrypi/src/init.rs`, `crates/qberrypi/src/lib.rs`, `xtask/src/qemu.rs`

**Interfaces:**
- Consumes: `live::WifiStatus`; `led::LedState`; Task 7's `Plan::link`, `Hooks::led`, `Reason::NoAssociation`.
- Produces:

```rust
// link.rs
pub const NO_ASSOCIATION_LIMIT: Duration = Duration::from_secs(90);
#[derive(Debug, PartialEq)] pub enum LinkStep { Nothing, Led(LedState), RestartDue }
pub struct LinkWatch { /* private */ }
impl LinkWatch {
    pub fn new(now: Duration) -> Self;                                   // not associated since `now`; the LED is `Joining`
    pub fn observe(&mut self, now: Duration, associated: bool) -> LinkStep;
    pub fn deadline(&self) -> Option<Duration>;                          // when RestartDue falls; None while associated
}
// fault.rs
pub fn link(fault: Fault) -> Option<tokio::sync::watch::Receiver<WifiStatus>>;   // NoWifi: a status that never associates
```

`LinkWatch::observe`: a change to associated gives `Led(Serving)` and logs `wifi: associated` the first time, `wifi: associated again after {n} s` later; a change to not associated gives `Led(Joining)` and logs `log::warn!("wifi: association lost")`; no change gives `RestartDue` once `NO_ASSOCIATION_LIMIT` has passed since the association was lost (or since `new`), otherwise `Nothing`.

`supervisor::run` with `plan.link` set: it makes a `LinkWatch`, calls `led(LedState::Joining)` in place of `Serving`, observes at every change of the receiver and at `deadline()`, passes each `Led` to the hook and ends with `Reason::NoAssociation` on `RestartDue`. A receiver whose sender is gone counts as not associated. With `plan.link` `None` nothing changes: the LED shows `Serving` and the rule is not armed. `fault::link` keeps its sender alive for the life of the process. `init` sets `plan.link = fault::link(cfg.debug.fault)` until Task 12 gives it the real one.

- [ ] **Step 1: Write the failing tests**

`link.rs`:

```rust
#[test] fn ninety_seconds_without_an_association_are_due_from_boot_and_from_each_loss() {
    let secs = Duration::from_secs;
    let mut w = LinkWatch::new(secs(0));
    assert_eq!(w.deadline(), Some(secs(90)));
    assert_eq!(w.observe(Duration::from_millis(89_999), false), LinkStep::Nothing);
    assert_eq!(w.observe(secs(90), false), LinkStep::RestartDue);
    let mut w = LinkWatch::new(secs(0));
    assert_eq!(w.observe(secs(30), true), LinkStep::Led(LedState::Serving));
    assert_eq!((w.observe(secs(500), true), w.deadline()), (LinkStep::Nothing, None));
    assert_eq!(w.observe(secs(600), false), LinkStep::Led(LedState::Joining));
    assert_eq!(w.deadline(), Some(secs(690)));
    assert_eq!(w.observe(secs(689), false), LinkStep::Nothing);
    assert_eq!(w.observe(secs(690), false), LinkStep::RestartDue);
}
```

`supervisor.rs` (`watch` as in Task 7; `status(associated)` is a `WifiStatus`):

```rust
#[tokio::test(start_paused = true)] async fn without_an_association_for_ninety_seconds_the_board_restarts() {
    let (_tx, rx) = tokio::sync::watch::channel(status(false));
    let began = tokio::time::Instant::now();
    let mut p = plan(vec![forever("wifi")]);
    p.link = Some(rx);
    let (reason, _, leds) = watch(p, HOUR).await;
    assert_eq!((reason, leds), (Some(Reason::NoAssociation), vec![LedState::Joining]));
    assert_eq!(began.elapsed().as_secs(), 90);
}
#[tokio::test(start_paused = true)] async fn an_association_stops_the_count_and_its_loss_starts_it_afresh() {
    // a task sends status(true) at 30 s and status(false) at 100 s
    assert_eq!((reason, leds), (Some(Reason::NoAssociation), vec![LedState::Joining, LedState::Serving, LedState::Joining]));
    assert_eq!(began.elapsed().as_secs(), 190);
}
#[tokio::test(start_paused = true)] async fn a_wifi_task_that_went_away_counts_as_not_associated() {
    // the sender sends status(true) at 10 s and is dropped at 20 s: Reason::NoAssociation at 110 s
}
```

`fault.rs`:

```rust
#[test] fn the_no_wifi_fault_is_a_status_that_never_associates() {
    let rx = fault::link(Fault::NoWifi).unwrap();
    assert_eq!(*rx.borrow(), WifiStatus::default());
    assert!(rx.has_changed().is_ok());                       // its sender is alive
    for other in [Fault::None, Fault::Stall, Fault::CrashLoop, Fault::Panic] { assert!(fault::link(other).is_none()); }
}
```

`qemu.rs`: a scenario "no association" on `Machine::Usual`: `one_shot` and `log_to_sd` on, `return_after_secs = 0`, `fault = "no-wifi"`.

```rust
fn no_association_conditions(evidence: &Evidence) -> Vec<Condition> {
    const RESTARTING: &str = "ERROR supervisor: restarting: no Wi-Fi association for 90 s";
    let allowed = Allowed { errors: &["supervisor: restarting: no Wi-Fi association"], warnings: &[NO_WATCHDOG, NO_LED, NO_PANEL] };
    vec![evidence.serial_has(RESTARTING), evidence.serial_lacks("INFO  returning"), evidence.restart_requested(), evidence.exited(),
         evidence.pios_config_is_active(), evidence.log_has(RESTARTING), evidence.log_is_of_one_boot_of_this_build(),
         evidence.serial_has_no_unexpected_complaint(&allowed)]
}
```

- [ ] **Step 2: Run** `cargo test --workspace` — expected: compile failures.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the three checks, then `cargo xtask build && cargo xtask qemu-test` — expected: nine scenarios `ok`; the new one takes about two minutes.
- [ ] **Step 5: Commit** — `git add crates/qberrypi/src/link.rs crates/qberrypi/src/supervisor.rs crates/qberrypi/src/fault.rs crates/qberrypi/src/init.rs crates/qberrypi/src/lib.rs xtask/src/qemu.rs`, message `"Supervisor: the LED follows the association, and 90 seconds without one restart the board"`.
- [ ] **Step 6: Pi check D (session lead; the owner looks at the LED)** — `fault = "no-wifi"`, `return_after_secs = 300`. The log must contain `ERROR supervisor: restarting: no Wi-Fi association for 90 s`, stamped 90 to 92 seconds after the `supervisor: started` lines, and no `returning`. The owner must have seen the green LED blink fast (five times a second) from a few seconds after the start until the restart.

---

### Task 10: Pulled power

**Files:**
- Modify: `crates/qberrypi/src/init.rs` (tests only, unless one fails), `xtask/src/qemu.rs`

**Interfaces:**
- Consumes: init's `restore_and_save_log`, `save_log_if_asked`, `leave`, `rescue`, `FakeCard`; `Evidence::image_is_unchanged`.
- Produces: one host test and one QEMU scenario that fail if any code path of this plan writes to the card without a development switch.

- [ ] **Step 1: Write the tests**

`init.rs`:

```rust
#[test] fn a_permanent_system_never_mounts_the_card_writable_from_boot_to_restart() {
    let cfg = cfg_debug(false, false);
    let log = log_holding(&["banner"]);
    let mut card = FakeCard::new();
    restore_and_save_log(&cfg, &mut card, &log);
    save_log_if_asked(&cfg, &mut card, &log);
    for reason in [Reason::ComponentFailed("dns"), Reason::NoAssociation, Reason::ReturnAfter] { leave(&cfg, &mut card, &log, &reason); }
    rescue(Some(&cfg), &mut card, Some(&log), Duration::ZERO, &mut || {});
    assert!(card.ops.is_empty(), "{:?}", card.ops);
    assert_eq!(card.read("config.txt"), QBERRYPI);
}
```

`qemu.rs`: a scenario "permanent, crash loop": the example configuration with `return_after_secs = 60` and `fault = "crash-loop"`, both card switches off.

```rust
fn permanent_crash_loop_conditions(evidence: &Evidence) -> Vec<Condition> {
    let allowed = Allowed { errors: &["supervisor: fault failed: provoked", "supervisor: restarting: component fault"],
                            warnings: &[NO_WATCHDOG, NO_LED, NO_PANEL] };
    vec![evidence.serial_has("ERROR supervisor: restarting: component fault failed 3 times in a minute"),
         evidence.restart_requested(), evidence.exited(), evidence.image_is_unchanged(),
         evidence.serial_has_no_unexpected_complaint(&allowed)]
}
```

- [ ] **Step 2: Run** `cargo test -p qberrypi init && cargo xtask build && cargo xtask qemu-test` — expected: the host test passes and ten scenarios are `ok`. If either fails, a path writes to the card without a switch: find it and gate it; that is this task's only code change.
- [ ] **Step 3: Commit** — `git add crates/qberrypi/src/init.rs xtask/src/qemu.rs`, message `"Tests: a permanent system leaves the card untouched, restart by the supervisor included"`.
- [ ] **Step 4: Pi check E (session lead; the owner pulls the power cord)** — `return_after_secs = 600`. When the panel has been showing for about a minute the owner pulls the Pi's power cord, waits five seconds and plugs it in again.
  `deploy` must end without an error: the Pi answers again as Raspberry Pi OS and `config.txt` is the saved one. The collected log must have this build's header, the banner and `INFO  config.txt: Restored`, and neither `returning` nor `supervisor: restarting`. On Raspberry Pi OS, `journalctl -k -b | grep -i 'fat-fs'` must show no line about `mmcblk0p1` being not properly unmounted or corrupt, and the DNS service the Pi runs must answer.
  What this shows: after the first second of a development boot nothing is in flight to the card until qberrypi leaves, so the cord can go at any moment. The same check on a permanent system belongs to Cutover.

---

### Task 11: The status page

Skip this task if milestones 1–3 already built `crates/qberrypi/src/status.rs`; then only add `blocking`, `pause_left_secs` and `board_c` to its JSON through `live::BlockingControl` and `thermal::read_c`, with a test.

**Files:**
- Create: `crates/qberrypi/src/status.rs`
- Modify: `crates/qberrypi/src/logbuf.rs`, `crates/qberrypi/src/init.rs`, `crates/qberrypi/src/lib.rs`, `crates/qberrypi/Cargo.toml`, `Cargo.lock`

**Interfaces:**
- Consumes: `live::{Source, Snapshot, BlockingControl}`; `thermal::read_c`; Task 7's `Component`, `Ended`; `qb_dns::{LogEntry, Outcome}`.
- Produces:

```rust
// logbuf.rs
impl LogBuf { pub fn text(&self) -> String; }             // every line held, each ending in a newline

// status.rs
pub const PORT: u16 = 80;
pub const MAX_CLIENTS: usize = 8;
pub const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_REQUEST_LINE: usize = 1024;
pub const MAX_QUERIES: usize = 1000;
pub trait Facts: Send + Sync {
    fn snapshot(&self) -> Snapshot;
    fn recent(&self, n: usize) -> Vec<LogEntry>;
    fn paused_left_secs(&self) -> Option<u16>;
    fn board_c(&self) -> Option<i8>;
    fn uptime_secs(&self) -> u64;
    fn unix_secs(&self) -> u64;
    fn log_text(&self) -> String;
}
pub struct LiveFacts { pub source: Arc<dyn Source>, pub control: Arc<dyn BlockingControl>, pub log: &'static Mutex<LogBuf>, pub started: Instant }   // impl Facts
#[derive(Debug, PartialEq)] pub struct Response { pub status: u16, pub content_type: &'static str, pub body: Vec<u8> }
pub fn respond(request_line: &str, facts: &dyn Facts) -> Response;
pub async fn serve(listener: tokio::net::TcpListener, facts: Arc<dyn Facts>) -> Ended;
pub fn component(facts: Arc<dyn Facts>) -> Component;     // essential; binds 0.0.0.0:80 on each start
```

`respond` takes the first line of a request. Not `GET <path> HTTP/1.x`: 400. A method other than `GET`: 405. Paths:

| Path | Body |
|---|---|
| `/api/v1/stats` | `application/json`, the object below |
| `/api/v1/queries` | `application/json`: an array, newest first, of `{"unix_secs", "name", "qtype", "outcome"}` with `outcome` one of `blocked`, `local`, `cached`, `stale`, `forwarded`. `?n=` is 1–`MAX_QUERIES` (a larger number is held to it), default 100; anything else in the query string is 400. |
| `/log` | `text/plain; charset=utf-8`: `log_text()` |
| `/` | `text/html; charset=utf-8`: one plain page with the spec's values (uptime, access point and signal, queries answered, share blocked, cache hit rate, upstream latency, list age and size), a dash for each unknown one, every inserted text with `&`, `<`, `>` and `"` escaped |
| anything else, and any of the other three paths with a query string | 404 |

The stats object; a value that is not known is `null`:

```json
{"version": "0.1.0", "build": 1794329091, "uptime_secs": 123,
 "wifi": {"associated": true, "signal_dbm": -61, "ap": "00:00:5e:00:53:01"},
 "queries_today": 10818, "blocked_today": 4780, "blocked_share": 0.4419, "cache_hit_rate": 0.31,
 "queries_total": 250000, "upstream_ms": 8, "board_c": 51,
 "blocking": "on", "pause_left_secs": null,
 "list_names": 302176, "list_age_secs": 3600}
```

`blocked_share` and `cache_hit_rate` are of today's queries, `null` when there were none; `blocking` is `"on"` or `"paused"`; `list_age_secs` is `unix_secs()` less `list_fetched_unix`, `null` until the clock is set.

`serve`: at most `MAX_CLIENTS` connections at a time (a semaphore; further ones wait in the listen queue). Per connection, under one `CLIENT_TIMEOUT`: read until the first line ends, giving up with 400 once `MAX_REQUEST_LINE` bytes came without one; write `HTTP/1.1 {status} {reason}`, `Content-Type`, `Content-Length`, `Connection: close`, the body; close. A connection's error ends that connection only. `serve` returns `Ended::Failed` only when `accept` fails.

- [ ] **Step 1: Add the dependency** — `cargo add -p qberrypi serde_json`.
- [ ] **Step 2: Write the failing tests.** `Fake` implements `Facts` from public fields, all unknown by default; `json(response)` parses a body with `serde_json`.

```rust
#[test] fn the_stats_say_null_for_what_is_not_known() {
    let r = respond("GET /api/v1/stats HTTP/1.1", &Fake::default());
    assert_eq!((r.status, r.content_type), (200, "application/json"));
    let v = json(&r);
    for key in ["wifi", "queries_today", "blocked_share", "cache_hit_rate", "upstream_ms", "board_c", "pause_left_secs", "list_names", "list_age_secs"] {
        assert!(v[key].is_null(), "{key}");
    }
    assert_eq!((v["blocking"].as_str(), v["uptime_secs"].as_u64()), (Some("on"), Some(0)));
}
#[test] fn the_stats_of_a_running_system() {
    // snapshot: Task 2's reference_snapshot() with cache_hits 3_354, total = today, list_names 302_176,
    // list_fetched_unix = unix_secs() − 3_600; paused_left_secs Some(299); board_c Some(51); uptime 123
    assert_eq!((v["queries_today"].as_u64(), v["blocked_today"].as_u64(), v["upstream_ms"].as_u64()), (Some(10_818), Some(4_780), Some(8)));
    assert!((v["blocked_share"].as_f64().unwrap() - 0.4419).abs() < 0.0001 && (v["cache_hit_rate"].as_f64().unwrap() - 0.31).abs() < 0.0001);
    assert_eq!((v["wifi"]["signal_dbm"].as_i64(), v["blocking"].as_str(), v["pause_left_secs"].as_u64()), (Some(-63), Some("paused"), Some(299)));
    assert_eq!((v["list_names"].as_u64(), v["list_age_secs"].as_u64(), v["board_c"].as_i64()), (Some(302_176), Some(3_600), Some(51)));
}
#[test] fn queries_come_newest_first_and_n_has_an_upper_end() {
    // three entries: n=2 gives two objects, the newest first, with "outcome": "blocked" for Outcome::Blocked
    // no n: the fake was asked for 100; n=999999: asked for 1000; n=0, n=abc, n=-1 and ?m=3: status 400
}
#[test] fn text_from_outside_cannot_put_markup_into_the_page() {
    let mut facts = Fake::default();
    facts.snapshot.wifi = Some(WifiStatus { associated: true, signal_dbm: Some(-50), ap: Some("<script>alert(1)</script>&\"".into()) });
    let page = String::from_utf8(respond("GET / HTTP/1.1", &facts).body).unwrap();
    assert!(page.contains("&lt;script&gt;alert(1)&lt;/script&gt;&amp;&quot;") && !page.contains("<script>"));
}
#[test] fn only_get_and_only_the_four_paths() {
    let status = |line: &str| respond(line, &Fake::default()).status;
    assert_eq!([status("GET /log HTTP/1.0"), status("POST / HTTP/1.1"), status("GET /nope HTTP/1.1"), status("GET /../log HTTP/1.1"),
                status("hello"), status(""), status("GET / FTP/1.0")], [200, 405, 404, 404, 400, 400, 400]);
}
#[tokio::test] async fn a_request_over_a_socket_gets_one_whole_answer_and_the_connection_closes() {
    // bind 127.0.0.1:0, spawn serve; write "GET /log HTTP/1.1\r\nHost: x\r\n\r\n", read to the end:
    // starts with "HTTP/1.1 200 OK\r\n", has "Connection: close", Content-Length equals the body's length, the body is log_text()
}
#[tokio::test(start_paused = true)] async fn eight_silent_clients_do_not_keep_a_ninth_from_being_served() {
    // eight connections that send nothing, then a ninth that sends a request:
    // the ninth has its answer within 6 s, and each silent one reads end-of-file by then
}
#[tokio::test] async fn a_line_without_an_end_is_answered_400_after_1024_bytes() {
    // a client writes 4,096 times 'A' with no line end: it reads "HTTP/1.1 400 " and end-of-file
}
```

`logbuf.rs`:

```rust
#[test] fn the_whole_log_can_be_read_without_taking_it() {
    let mut buf = LogBuf::new(4096);
    buf.push("a");
    buf.push("b");
    assert_eq!(buf.text(), "a\nb\n");
    assert_eq!(buf.take_unsaved(), "a\nb\n");            // reading took nothing
}
```

- [ ] **Step 3: Run** `cargo test -p qberrypi status && cargo test -p qberrypi logbuf` — expected: compile failures.
- [ ] **Step 4: Implement.** `init` adds `status::component(Arc::new(LiveFacts { .. }))` to the plan, with the same `source` and `control` the panel has.
- [ ] **Step 5: Run** the three checks, then `cargo xtask build && cargo xtask qemu-test` — expected: all pass; no scenario gains a warning (the guest has no network, and binding `0.0.0.0:80` needs none).
- [ ] **Step 6: Commit** — `git add crates/qberrypi/Cargo.toml Cargo.lock crates/qberrypi/src/lib.rs crates/qberrypi/src/status.rs crates/qberrypi/src/logbuf.rs crates/qberrypi/src/init.rs`, message `"Status: a read-only page, the numbers as JSON, recent queries and the log, on port 80"`.

---

### Task 12: Live numbers and the real switch (needs milestones 1–3 merged)

This task meets code this plan could not read. Its first step is to read it; its tests are fixed here because they are written against `qb-dns` and this plan's own seams.

**Files:**
- Create: `crates/qberrypi/src/wiring.rs`
- Modify: `crates/qberrypi/src/init.rs`, `crates/qberrypi/src/lib.rs`, and, only where a rule below requires it, the files of milestones 1–3 that own the DNS task, the forwarder and the Wi-Fi task

**Interfaces:**
- Consumes: `qb_dns::{Resolver, Now, Transport, Action, Counts}` as its plan defines them; every seam of "What this plan needs from milestones 1–3".
- Produces:

```rust
/// The resolver the DNS task answers from, and that task's own clock.
#[derive(Clone)]
pub struct SharedResolver { pub resolver: Arc<Mutex<Resolver>>, pub now: Arc<dyn Fn() -> Now + Send + Sync> }
// impl BlockingControl for SharedResolver:
//   pause_for(secs)    -> resolver.pause_until(now().mono_secs + secs)
//   resume()           -> resolver.resume()
//   paused_left_secs() -> resolver.paused_until(now()).map(|until| until − now().mono_secs), held to u16
#[derive(Default)] pub struct LatencyMeter { /* the last nine round trips */ }
impl LatencyMeter { pub fn record(&self, ms: u16); pub fn value(&self) -> Option<u16>; }      // the median; None before the first
#[derive(Debug, Clone, Default)]
pub struct Extras { pub utc_offset_secs: i32, pub clock_set: bool, pub list_names: Option<usize>, pub list_fetched_unix: Option<u64> }
pub struct Live {
    pub resolver: SharedResolver,
    pub wifi: tokio::sync::watch::Receiver<WifiStatus>,
    pub latency: Arc<LatencyMeter>,
    pub extras: Arc<dyn Fn() -> Extras + Send + Sync>,
}
// impl live::Source for Live: today, total and last_blocked from resolver.stats() at now(); recent(n) cloned from stats().recent(n)
```

- [ ] **Step 1: Read what milestones 1–3 built, and write into the task report where each of these is:** the `Resolver` the DNS task owns and how it is shared; the function that makes that task's `Now`; the place where an upstream answer is matched to its query (for the latency); the Wi-Fi task's knowledge of association, signal and access point; the UTC offset given to `Resolver::set_utc_offset` and the moment SNTP sets the clock; the size and fetch time of the block set; every long-running task and how it is started today; every call of `led::set`.
- [ ] **Step 2: Write the failing tests** in `wiring.rs`. `resolver()` is a `Resolver` over `BlockSetBuilder` with `add_list(b"0.0.0.0 ads.example.com\n")`; `shared(clock)` wraps it with a clock the test moves (`Now { mono_secs, unix_secs: 1_800_000_000 + mono_secs }`); `query(name)` is a DNS query packet built by hand (ID 7, RD set, one question, type A, class IN); `ask(&shared, name)` is `handle_query(&query(name), Transport::Udp, (shared.now)())` under the lock; `live(shared, wifi_status, extras)` is a `Live` over a `watch` channel that holds that status, a new `LatencyMeter` and a closure that returns those extras; `status(associated, signal_dbm)` is a `WifiStatus`.

```rust
#[test] fn a_tap_pauses_the_very_resolver_the_dns_task_answers_from() {
    let (shared, clock) = shared(100);
    assert!(matches!(ask(&shared, "ads.example.com"), Action::Reply(_)));           // blocked
    shared.pause_for(300);
    assert_eq!(shared.paused_left_secs(), Some(300));
    assert!(matches!(ask(&shared, "ads.example.com"), Action::Forward(_)));         // let through
    clock.store(399, Ordering::SeqCst);
    assert_eq!(shared.paused_left_secs(), Some(1));
    clock.store(400, Ordering::SeqCst);
    assert_eq!(shared.paused_left_secs(), None);
    assert!(matches!(ask(&shared, "ads.example.com"), Action::Reply(_)));           // blocked again, by itself
    shared.pause_for(300);
    shared.resume();
    assert_eq!(shared.paused_left_secs(), None);
}
#[test] fn the_pause_runs_on_the_dns_tasks_seconds_whatever_the_wall_clock_does() {
    // the clock closure steps unix_secs from the build time to a year later between pause_for(300) and
    // paused_left_secs(): still Some(300); mono_secs + 300 later: None
}
#[test] fn the_snapshot_is_what_the_resolver_counted() {
    let (shared, _) = shared(100);
    ask(&shared, "ads.example.com");
    ask(&shared, "example.org");
    let live = live(shared, status(true, Some(-61)), Extras { clock_set: true, list_names: Some(1), ..Extras::default() });
    live.latency.record(8);
    let s = live.snapshot();
    assert_eq!(s.today, Some(Counts { queries: 2, blocked: 1, cache_hits: 0, forwarded: 1 }));
    assert_eq!(s.last_blocked.unwrap().name, "ads.example.com");
    assert_eq!((s.upstream_ms, s.wifi.unwrap().signal_dbm, s.clock_set, s.list_names), (Some(8), Some(-61), true, Some(1)));
    assert_eq!(live.recent(1)[0].name.as_ref(), "example.org");
}
#[test] fn the_latency_is_the_median_of_the_last_nine_answers() {
    let m = LatencyMeter::default();
    assert_eq!(m.value(), None);
    for ms in [8, 300, 9] { m.record(ms); }
    assert_eq!(m.value(), Some(9));
    for ms in [20; 9] { m.record(ms); }
    assert_eq!(m.value(), Some(20));                         // the first three are forgotten
}
```

- [ ] **Step 3: Run** `cargo test -p qberrypi wiring` — expected: compile failure.
- [ ] **Step 4: Implement `wiring.rs` and wire it in `init`,** by these rules:
  - **One resolver, one clock.** The DNS task and `SharedResolver` hold the same `Arc<Mutex<Resolver>>` and call the same clock function. If the DNS task owns its `Resolver` by value, change it to the shared one.
  - **Latency.** If the forwarder already measures the round trip to the upstream, feed that into the `LatencyMeter`; otherwise take an `Instant` where the query is sent and `record` where its answer is matched.
  - **Wi-Fi.** The Wi-Fi task publishes a `WifiStatus` on a `watch` channel at every change of association and at least every 5 seconds while associated. If it does not measure the signal, read it from `/proc/net/wireless`: the third number on the line that starts with `wlan0:` (`-61.` is −61 dBm), `None` when the line is missing; add that as `wiring::proc_signal(text: &str) -> Option<i8>` with a test on the two-header-line sample from "Measured on the Pi" and on a file without `wlan0`.
  - **Components.** Every long-running task of milestones 1–3 becomes an essential `Component` whose `start` builds the task afresh and maps its error to `Ended::Failed(error.to_string())`; the spawn it had goes. `plan.link` is the Wi-Fi task's receiver (the `no-wifi` fault still replaces it). The panel's and the status page's `source` is the `Live`, and their `control` the `SharedResolver`; `Nothing` and `StandIn` stay for tests only.
  - **The LED has one owner.** Remove every `led::set` call outside `fatal` and the supervisor's hook.
  - **No radio is not a failure.** If a QEMU scenario now ends in `supervisor: restarting: component` for the Wi-Fi task, that task returns when `wlan0` is missing: make it wait and try again instead.
- [ ] **Step 5: Run** the three checks, then `cargo xtask build && cargo xtask qemu-test` — expected: every scenario `ok`, with no line allowed that was not allowed before.
- [ ] **Step 6: Commit** — `git add crates/qberrypi/src/wiring.rs crates/qberrypi/src/lib.rs crates/qberrypi/src/init.rs` and each file of milestones 1–3 that changed, by name; message `"Panel and status page show the resolver's and the radio's own numbers; the switch pauses the resolver"`.
- [ ] **Step 7: Pi check F (session lead alone)** — `return_after_secs = 300`. From the development machine, with `<address>` the Pi's static address: `dig @<address> example.com` answers; `dig @<address>` for a name on the lists answers `0.0.0.0`; `curl http://<address>/api/v1/stats`, twice, 30 seconds and a few queries apart, shows `queries_today` grown, `wifi.associated` true with `signal_dbm` between −90 and −20, `upstream_ms` and `board_c` not null, `blocking` `"on"`. The collected log has `wifi: associated` and no `ERROR` line.

---

### Task 13: Done when — milestones 4 and 5 on the real Pi

Run by the session lead with the owner at the Pi, on one build that has passed `qemu-test`. Each boot: `one_shot = true`, `log_to_sd = true`. `<address>` is the Pi's static address, `<listed>` a name on the lists.

**Files:**
- Create: `docs/bring-up/m4-m5.md`
- Modify: `README.md` (the status paragraph and the command table)

- [ ] **Step 1: Front panel (milestone 5)** — `return_after_secs = 600`, `fault = "none"`.
  1. The owner reads the panel aloud while the lead fetches `/api/v1/stats`: the dial's percentage is `blocked_share` rounded; the footer is `blocked_today of queries_today today`; `Upstream`, `Wi-Fi` and `Board` are `upstream_ms`, `wifi.signal_dbm` and `board_c`. Each agrees within what one redraw can change.
  2. The lead runs `dig @<address> <listed>`: within five seconds the window shows that name with the time of day and a count, and the footer's first number has grown.
  3. The owner taps the switch. Within five seconds `dig @<address> <listed>` returns a real address instead of `0.0.0.0`, and the stats say `"blocking": "paused"`. The panel reads `Paused` and counts down.
  4. The owner taps again. `dig @<address> <listed>` returns `0.0.0.0` within five seconds; the panel reads `on`.
  5. The log has `panel: switch: paused for 300 s` and `panel: switch: resumed`, and no `ERROR` line.
- [ ] **Step 2: Status page and a restarted access point (milestone 4)** — the same boot, or one like it.
  1. `curl` of `/`, `/api/v1/stats`, `/api/v1/queries?n=5` and `/log` each answers 200; `/log` starts with the banner.
  2. The lead notes `uptime_secs`. The owner switches the access point's Wi-Fi off, waits 20 seconds and switches it on (or restarts the access point, if it is back within a minute). The owner must see the LED change from the slow heartbeat to the fast blink and back.
  3. When `dig @<address> example.com` answers again: `uptime_secs` is larger than before by the time that passed (the board did not restart), and `/log` has `WARN  wifi: association lost` followed by `INFO  wifi: associated again after` with a number below 90.
  4. Once more with the access point left off for two minutes: the Pi restarts by itself and, being a one-shot boot, comes back as Raspberry Pi OS; the collected log ends with `WARN  wifi: association lost` and, 90 seconds later by its timestamps, `ERROR supervisor: restarting: no Wi-Fi association for 90 s`.
- [ ] **Step 3: Watchdog and reboot policies (milestone 4)** — on this build, repeat the `stall` and `crash-loop` boots of Pi check C with their conditions. In the `stall` boot the lead also runs `ping <address>` from before the tenth second: the answers stop within 15 seconds of the `fault: stalling the supervisor` line's timestamp.
- [ ] **Step 4: Pulled power (milestone 4)** — repeat Pi check E on this build, pulling the cord while `dig @<address> example.com` is being answered.
- [ ] **Step 5: Write `docs/bring-up/m4-m5.md`** in the manner of `docs/bring-up/m0.md`: date, board, build; for each of Steps 1–4 what was done and what was seen, with the log's timestamps; the touch calibration's five values; the measured time from the stall to the reset; anything unexpected; anything not checked, by name (a permanent system's pulled power is one). No network name, address or access point address goes into the file. Change the README's status paragraph to say milestones 4 and 5 are done, and add `debug.calibrate_touch` and `debug.fault` to its Development section.
- [ ] **Step 6: Commit** — `git add docs/bring-up/m4-m5.md README.md`, message `"Milestones 4 and 5: resilience and the front panel, checked on the Pi"`.
