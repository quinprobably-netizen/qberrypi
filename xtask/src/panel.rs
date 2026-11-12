//! `cargo xtask panel-preview`: draws one state of the front panel into a PNG,
//! and with `--push` onto the 3.5-inch screen of a Pi running Raspberry Pi OS.
//!
//! The frame is one of the Drain's stills, as `qb-panel` paints it:
//! `--state normal` (the default), `paused`, `alert`, `alert-low`,
//! `alert-long`, `boot`, `listening`, `quiet`, `long`, `five`, `six`, `pct0`
//! or `pct100`. They are the fixtures the goldens compare, so the PNG of a
//! bare `cargo xtask panel-preview` is the first of the references in
//! `crates/qb-panel/tests/reference`.
//!
//! `--push` sends the same frame as RGB565 to the Pi, in two commands over SSH
//! and without `sudo`: on Raspberry Pi OS the user is in the `video` group,
//! which owns the framebuffer devices.
//!
//! 1. A script on the standard input of `sh -s` finds the screen: the
//!    framebuffer whose driver names itself `fb_ili9486`, never a number that
//!    was assumed. It must be 480 × 320 at 16 bits per pixel. The script
//!    changes nothing and prints the device, or stops with the reason.
//! 2. `dd` writes the 307,200 bytes to that device.
//!
//! A search that is refused, or an answer that is not a framebuffer device,
//! ends the command: nothing is tried twice and no other device is written.
//! As in `deploy`, each command is built as data and run through a [`Runner`],
//! so the tests read the commands and none reaches a real machine.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, ensure};
use qb_panel::{Fixture, HEIGHT, Painter, WIDTH, drain_fixture, rgba_to_rgb565};

use crate::deploy::{Invocation, Runner, SystemRunner, resolve_host, run_fed_to_success, ssh};

/// Where the PNG goes when `--out` does not say, under the top of the repository.
const DEFAULT_PNG: &str = "out/panel-preview.png";

/// Where Linux lists its framebuffers.
const SYS_GRAPHICS: &str = "/sys/class/graphics";
/// What the driver of the 3.5-inch screen calls its framebuffer.
const SCREEN_DRIVER: &str = "fb_ili9486";
/// The bits per pixel of an RGB565 frame.
const DEPTH: usize = 16;
/// The bytes of one frame.
const FRAME_BYTES: usize = WIDTH * HEIGHT * DEPTH / 8;

/// Script status: no framebuffer is the 3.5-inch screen, or more than one says it is.
const NO_SCREEN: i32 = 3;
/// Script status: the screen is not 480 × 320 at 16 bits per pixel.
const WRONG_SHAPE: i32 = 4;
/// Script status: the folder to look in has a name that cannot be written into the script.
const BAD_FOLDER: i32 = 5;

/// Which still of the Drain to draw.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum State {
    /// Blocking is on and a refused name is melting at the gate.
    #[default]
    Normal,
    /// Blocking is paused, with a listed name crossing the gate outlined.
    Paused,
    /// The normal scene, with a high severity alert over its lower right.
    Alert,
    /// The normal scene, with a blue alert for a new device.
    AlertLow,
    /// The normal scene, with an alert whose subject takes two lines.
    AlertLong,
    /// Wi-Fi not joined: the lane says so and the figures are dashes.
    Boot,
    /// Joined, and no query yet.
    Listening,
    /// No traffic for 47 minutes.
    Quiet,
    /// A name longer than the lane has stopped at the gate.
    Long,
    /// The normal scene with a five-digit count.
    Five,
    /// The normal scene with a six-digit count.
    Six,
    /// Nothing refused yet: `0%`.
    Pct0,
    /// Everything refused so far: `ALL`.
    Pct100,
}

impl State {
    /// The fixture of `qb-panel` that is this still.
    fn fixture(self) -> Fixture {
        match self {
            State::Normal => Fixture::Normal,
            State::Paused => Fixture::Paused,
            State::Alert => Fixture::Alert,
            State::AlertLow => Fixture::AlertLow,
            State::AlertLong => Fixture::AlertLong,
            State::Boot => Fixture::Boot,
            State::Listening => Fixture::Listening,
            State::Quiet => Fixture::Quiet,
            State::Long => Fixture::Long,
            State::Five => Fixture::Five,
            State::Six => Fixture::Six,
            State::Pct0 => Fixture::Pct0,
            State::Pct100 => Fixture::Pct100,
        }
    }
}

/// The flags of `cargo xtask panel-preview`; each field's comment is that flag's help.
#[derive(clap::Args, Default)]
pub struct PreviewArgs {
    /// Where the PNG goes [default: out/panel-preview.png in the repository]
    #[arg(long, value_name = "path")]
    pub out: Option<PathBuf>,
    /// Also show the frame on the 3.5-inch screen of the Pi with this SSH alias, running Raspberry Pi OS
    #[arg(long, value_name = "ssh-alias")]
    pub push: Option<String>,
    /// Which still to draw
    #[arg(long, value_enum, default_value_t = State::Normal)]
    pub state: State,
}

/// Paints a still of the Drain from scratch, as the RGBA frame `qb-panel` draws it.
pub fn render(state: State) -> Vec<u8> {
    let (drain, stills) = drain_fixture(state.fixture());
    let mut painter = Painter::new();
    painter.paint(&drain, &stills);
    painter.rgba().to_vec()
}

/// Packs one frame of the panel, 480 × 320 with four bytes a pixel, as an 8-bit RGBA PNG.
pub fn encode_png(rgba: &[u8]) -> Result<Vec<u8>> {
    let mut file = Vec::new();
    let mut encoder = png::Encoder::new(&mut file, WIDTH as u32, HEIGHT as u32);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder
        .write_header()
        .context("cannot start the PNG of the frame")?;
    writer
        .write_image_data(rgba)
        .context("cannot write the frame into the PNG")?;
    writer.finish().context("cannot end the PNG of the frame")?;
    Ok(file)
}

/// The script that finds the 3.5-inch screen among the Pi's framebuffers.
pub struct FindScreen {
    /// The folder in which Linux lists its framebuffers: `/sys/class/graphics` on the Pi.
    pub sys_graphics: String,
}

impl FindScreen {
    /// Writes the script out: POSIX `sh`, for the SSH user, changing nothing.
    ///
    /// The folder goes into it between single quotes. One with a single quote in
    /// its name is not quoted some other way: the script for it only says so and
    /// stops, with a status of its own.
    pub fn render(&self) -> String {
        let sys_graphics = &self.sys_graphics;
        if sys_graphics.contains('\'') {
            return format!("{REFUSING_SCRIPT}exit {BAD_FOLDER}\n");
        }
        format!(
            "{SCRIPT_HEAD}\n\
             sys_graphics='{sys_graphics}'\n\
             driver={SCREEN_DRIVER}\n\
             size={WIDTH},{HEIGHT}\n\
             depth={DEPTH}\n\
             \n\
             no_screen={NO_SCREEN}\n\
             wrong_shape={WRONG_SHAPE}\n\
             {SCRIPT_BODY}"
        )
    }
}

/// The first lines of the script; the values of one search follow them.
const SCRIPT_HEAD: &str = r"#!/bin/sh
# Finds the framebuffer of the 3.5-inch screen. Written by
# `cargo xtask panel-preview --push`, which runs it as the SSH user:
# ssh <host> sh -s
#
# The screen is the framebuffer whose driver names itself; its number is never
# assumed. It must have the size and the depth of the frame that is about to
# be written to it. Prints the device, such as /dev/fb1, and nothing else, or
# stops with the reason. Changes nothing.
#
# The work is done by main, which the last line calls: a script that arrives
# cut short does nothing.
set -eu
LC_ALL=C
export LC_ALL
";

/// The script proper. It takes everything it needs from the variables set before it.
const SCRIPT_BODY: &str = r#"
# Stops the script with the status given first; the rest is the reason.
die() {
    status=$1
    shift
    printf 'qberrypi-panel-preview: stopped: %s\n' "$*" >&2
    exit "$status"
}

main() {
    found=
    for dir in "$sys_graphics"/fb*; do
        # The console's folder, fbcon, has no name; nor has a pattern that matched nothing.
        [ -f "$dir/name" ] || continue
        name=$(cat "$dir/name") ||
            die "$no_screen" "cannot read the name of ${dir##*/} while looking for $driver"
        [ "$name" = "$driver" ] || continue
        [ -z "$found" ] ||
            die "$no_screen" "${found##*/} and ${dir##*/} both say they are $driver; neither is chosen"
        found=$dir
    done
    [ -n "$found" ] ||
        die "$no_screen" "no framebuffer under $sys_graphics says it is $driver: is the screen's overlay loaded?"
    fb=${found##*/}

    found_size=$(cat "$found/virtual_size") ||
        die "$wrong_shape" "cannot read the size of $fb"
    [ "$found_size" = "$size" ] ||
        die "$wrong_shape" "$fb is $found_size and not $size: the frame is not made for it"
    found_depth=$(cat "$found/bits_per_pixel") ||
        die "$wrong_shape" "cannot read the bits per pixel of $fb"
    [ "$found_depth" = "$depth" ] ||
        die "$wrong_shape" "$fb has $found_depth bits per pixel and not $depth: the frame is not made for it"

    printf '/dev/%s\n' "$fb"
}

main
"#;

/// The whole script when the folder cannot be written into it, but for its last line: the status.
const REFUSING_SCRIPT: &str = r"#!/bin/sh
# Written by `cargo xtask panel-preview --push` in place of the script that
# finds the 3.5-inch screen: the folder to look in has a single quote in its
# name, and such a name is not written into a script. Looks at nothing.
set -eu
printf 'qberrypi-panel-preview: stopped: %s\n' \
    'the folder of the framebuffers has a single quote in its name; nothing was looked at' >&2
";

/// Reads the device from what the script printed; anything else is written to nowhere.
pub fn parse_device(answer: &[u8]) -> Result<String> {
    let is_framebuffer = |device: &&str| {
        device.strip_prefix("/dev/fb").is_some_and(|number| {
            !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
        })
    };
    str::from_utf8(answer)
        .ok()
        .and_then(|text| text.strip_suffix('\n'))
        .filter(is_framebuffer)
        .map(str::to_owned)
        .ok_or_else(|| {
            anyhow!(
                "the search for the screen on the Pi did not answer with a framebuffer device but \
                 with {:?}; nothing was written",
                String::from_utf8_lossy(answer)
            )
        })
}

/// Writes the frame on standard input to the screen; `device` must have passed [`parse_device`].
pub fn write_frame(host: &str, device: &str) -> Invocation {
    ssh(
        host,
        &["dd", &format!("of={device}"), "bs=64k", "status=none"],
    )
}

/// Puts an RGB565 frame on the 3.5-inch screen of the Pi with this SSH alias,
/// and returns the device it was written to.
///
/// The alias and the frame's length are checked before any command runs. Then
/// the screen is looked for once and the frame is written once: a search that
/// is refused, or that answers with anything but a framebuffer device, is the
/// end, and so is a write that fails.
fn push(runner: &mut dyn Runner, alias: &str, frame: &[u8]) -> Result<String> {
    let host = resolve_host(Some(alias.to_owned()), None)?;
    ensure!(
        frame.len() == FRAME_BYTES,
        "the frame is {} bytes and not the {FRAME_BYTES} of a {WIDTH} × {HEIGHT} screen at \
         {DEPTH} bits per pixel; nothing was sent",
        frame.len()
    );
    let script = FindScreen {
        sys_graphics: SYS_GRAPHICS.to_owned(),
    }
    .render();
    let search = run_fed_to_success(
        runner,
        &ssh(&host, &["sh", "-s"]),
        Some(script.as_bytes()),
        "the search for the screen on the Pi",
    )?;
    let device = parse_device(&search.stdout)?;
    run_fed_to_success(
        runner,
        &write_frame(&host, &device),
        Some(frame),
        &format!("writing the frame to {device} on the Pi"),
    )?;
    Ok(device)
}

/// Draws the still the flags name, writes it as a PNG and prints where;
/// with `--push`, then puts the same frame on the Pi's screen.
pub fn run(args: &PreviewArgs, root: &Path) -> Result<()> {
    let rgba = render(args.state);
    let path = match &args.out {
        Some(path) => path.clone(),
        None => root.join(DEFAULT_PNG),
    };
    if let Some(folder) = path.parent() {
        fs::create_dir_all(folder)
            .with_context(|| format!("cannot create {}", folder.display()))?;
    }
    fs::write(&path, encode_png(&rgba)?)
        .with_context(|| format!("cannot write {}", path.display()))?;
    println!("{}", path.display());
    if let Some(alias) = &args.push {
        let device = push(&mut SystemRunner, alias, &rgba_to_rgb565(&rgba))?;
        println!("panel-preview: the frame is on {device} of {alias}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;
    use std::fs;
    use std::io::{self, Write};
    use std::process::{Command, Stdio};

    use tempfile::TempDir;

    use crate::deploy::Finished;

    // ---------------------------------------------------------------- the flags

    #[derive(clap::Parser)]
    struct Line {
        #[command(flatten)]
        args: PreviewArgs,
    }

    fn parse(words: &[&str]) -> Result<PreviewArgs, clap::Error> {
        let argv = ["t"].into_iter().chain(words.iter().copied());
        <Line as clap::Parser>::try_parse_from(argv).map(|line| line.args)
    }

    #[test]
    fn no_flags_draw_the_normal_still_to_the_default_place() {
        let args = parse(&[]).unwrap();
        assert_eq!(
            (args.state, args.out, args.push),
            (State::Normal, None, None)
        );
        assert_eq!(State::default(), State::Normal);
        assert_eq!(PreviewArgs::default().state, State::Normal);
    }

    #[test]
    fn state_takes_the_mockups_stills_by_name_and_nothing_else() {
        for (word, state) in [
            ("normal", State::Normal),
            ("paused", State::Paused),
            ("alert", State::Alert),
            ("alert-low", State::AlertLow),
            ("alert-long", State::AlertLong),
            ("boot", State::Boot),
            ("listening", State::Listening),
            ("quiet", State::Quiet),
            ("long", State::Long),
            ("five", State::Five),
            ("six", State::Six),
            ("pct0", State::Pct0),
            ("pct100", State::Pct100),
        ] {
            assert_eq!(parse(&["--state", word]).unwrap().state, state, "{word}");
            assert_eq!(state.fixture().name(), word, "{word} is its fixture's name");
        }
        for bad in ["", "Normal", "dial", "unknown", "alert,paused", "alert_low"] {
            assert!(parse(&["--state", bad]).is_err(), "{bad:?}");
        }
        assert!(parse(&["--state"]).is_err());
    }

    #[test]
    fn out_and_push_come_along_with_a_state() {
        let args = parse(&["--out", "shot.png", "--push", "pi", "--state", "paused"]).unwrap();
        assert_eq!(args.out, Some(PathBuf::from("shot.png")));
        assert_eq!(args.push.as_deref(), Some("pi"));
        assert_eq!(args.state, State::Paused);
    }

    #[test]
    fn the_flags_of_the_old_design_are_gone() {
        for flag in [
            "--unknown",
            "--blocked",
            "--total",
            "--upstream-ms",
            "--wifi-dbm",
            "--board-c",
            "--name",
            "--time",
            "--day-count",
            "--paused",
        ] {
            assert!(parse(&[flag, "1"]).is_err(), "{flag}");
        }
    }

    // ---------------------------------------------------------------- the PNG

    /// Reads a PNG back: its width, height, colour type, bit depth and pixels.
    fn decode(file: &[u8]) -> (u32, u32, png::ColorType, png::BitDepth, Vec<u8>) {
        let mut reader = png::Decoder::new(io::Cursor::new(file))
            .read_info()
            .unwrap();
        let mut pixels = vec![0; reader.output_buffer_size().unwrap()];
        let frame = reader.next_frame(&mut pixels).unwrap();
        pixels.truncate(frame.buffer_size());
        (
            frame.width,
            frame.height,
            frame.color_type,
            frame.bit_depth,
            pixels,
        )
    }

    /// The reference of a still in `qb-panel`, as an RGBA frame: its 8-bit RGB PNG with the alpha added.
    fn reference(name: &str) -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../crates/qb-panel/tests/reference")
            .join(format!("drain-{name}.png"));
        let (width, height, colour, depth, rgb) = decode(&fs::read(&path).unwrap());
        assert_eq!(
            (width, height, colour, depth),
            (480, 320, png::ColorType::Rgb, png::BitDepth::Eight),
            "{}",
            path.display()
        );
        rgb.as_chunks::<3>()
            .0
            .iter()
            .flat_map(|&[r, g, b]| [r, g, b, 255])
            .collect()
    }

    #[test]
    fn the_png_holds_the_frame() {
        let (drain, stills) = drain_fixture(Fixture::Normal);
        let mut painter = Painter::new();
        painter.paint(&drain, &stills);
        let rgba = painter.rgba();
        let (width, height, colour, depth, pixels) = decode(&encode_png(rgba).unwrap());
        assert_eq!((width, height), (480, 320));
        assert_eq!(
            (colour, depth),
            (png::ColorType::Rgba, png::BitDepth::Eight)
        );
        assert!(pixels == rgba, "the PNG's pixels are not the frame's");
    }

    #[test]
    fn each_state_renders_its_fixture() {
        let root = tempfile::tempdir().unwrap();
        // The states that have a golden in `qb-panel`; the others are drawn, but not kept.
        for (state, name) in [
            (State::Normal, "normal"),
            (State::Paused, "paused"),
            (State::Alert, "alert"),
            (State::Boot, "boot"),
            (State::Listening, "listening"),
            (State::Quiet, "quiet"),
            (State::Long, "long"),
            (State::Six, "six"),
        ] {
            let out = root.path().join(format!("{name}.png"));
            let args = PreviewArgs {
                out: Some(out.clone()),
                state,
                ..PreviewArgs::default()
            };
            run(&args, root.path()).unwrap();
            let (width, height, colour, depth, pixels) = decode(&fs::read(&out).unwrap());
            assert_eq!((width, height), (480, 320), "{name}");
            assert_eq!(
                (colour, depth),
                (png::ColorType::Rgba, png::BitDepth::Eight),
                "{name}"
            );
            assert!(
                pixels == reference(name),
                "--state {name} is not the pixels of drain-{name}.png"
            );
        }
    }

    #[test]
    fn every_state_looks_different() {
        let all = [
            State::Normal,
            State::Paused,
            State::Alert,
            State::AlertLow,
            State::AlertLong,
            State::Boot,
            State::Listening,
            State::Quiet,
            State::Long,
            State::Five,
            State::Six,
            State::Pct0,
            State::Pct100,
        ];
        let frames: Vec<Vec<u8>> = all.iter().map(|&state| render(state)).collect();
        for (i, a) in frames.iter().enumerate() {
            for b in &frames[i + 1..] {
                assert!(a != b);
            }
        }
    }

    #[test]
    fn without_out_the_png_goes_to_out_under_the_root() {
        let root = tempfile::tempdir().unwrap();
        run(&PreviewArgs::default(), root.path()).unwrap();
        let file = fs::read(root.path().join("out/panel-preview.png")).unwrap();
        assert!(decode(&file).4 == reference("normal"));

        let elsewhere = root.path().join("shots/paused.png");
        let paused = PreviewArgs {
            out: Some(elsewhere.clone()),
            state: State::Paused,
            ..PreviewArgs::default()
        };
        run(&paused, root.path()).unwrap();
        assert!(decode(&fs::read(elsewhere).unwrap()).4 == reference("paused"));
        // The default place still holds the first run's frame.
        assert!(
            decode(&fs::read(root.path().join("out/panel-preview.png")).unwrap()).4
                == reference("normal")
        );
    }

    // ---------------------------------------------------------------- the script

    /// The shells the script is tried under: `sh`, and `dash` (the Pi's `sh`) where there is one.
    fn shells() -> Vec<&'static str> {
        let has_dash = Command::new("dash")
            .args(["-c", "exit 0"])
            .status()
            .is_ok_and(|status| status.success());
        if has_dash {
            vec!["sh", "dash"]
        } else {
            vec!["sh"]
        }
    }

    struct Ran {
        status: Option<i32>,
        stdout: String,
        stderr: String,
    }

    /// Runs a script as `--push` does, on the standard input of `sh -s`.
    fn run_script(shell: &str, script: &str) -> Ran {
        let mut child = Command::new(shell)
            .arg("-s")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        // A shell that stops early may not read all of it.
        let _ = input.write_all(script.as_bytes());
        drop(input);
        let output = child.wait_with_output().unwrap();
        Ran {
            status: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    /// A stand-in for `/sys/class/graphics` on the Pi.
    struct Graphics {
        dir: TempDir,
    }

    impl Graphics {
        fn empty() -> Self {
            Graphics {
                dir: tempfile::tempdir().unwrap(),
            }
        }

        /// As on the Pi: the HDMI output is `fb0` and the 3.5-inch screen is `fb1`.
        fn pi() -> Self {
            let graphics = Self::empty();
            graphics.hdmi("fb0");
            graphics.screen("fb1");
            graphics
        }

        /// Writes one file of a framebuffer, with the newline that sysfs ends it with.
        fn set(&self, fb: &str, file: &str, content: &str) {
            let folder = self.dir.path().join(fb);
            fs::create_dir_all(&folder).unwrap();
            fs::write(folder.join(file), format!("{content}\n")).unwrap();
        }

        fn hdmi(&self, fb: &str) {
            self.set(fb, "name", "BCM2708 FB");
        }

        fn screen(&self, fb: &str) {
            self.set(fb, "name", "fb_ili9486");
            self.set(fb, "virtual_size", "480,320");
            self.set(fb, "bits_per_pixel", "16");
        }

        fn script(&self) -> FindScreen {
            FindScreen {
                sys_graphics: self.dir.path().to_str().unwrap().to_owned(),
            }
        }

        fn run(&self, shell: &str) -> Ran {
            run_script(shell, &self.script().render())
        }
    }

    #[test]
    fn the_script_finds_the_screen_by_its_driver_name() {
        for shell in shells() {
            let ran = Graphics::pi().run(shell);
            assert_eq!(
                (ran.status, ran.stdout.as_str(), ran.stderr.as_str()),
                (Some(0), "/dev/fb1\n", ""),
                "{shell}"
            );

            let exchanged = Graphics::empty();
            exchanged.screen("fb0");
            exchanged.hdmi("fb1");
            let ran = exchanged.run(shell);
            assert_eq!(
                (ran.status, ran.stdout.as_str(), ran.stderr.as_str()),
                (Some(0), "/dev/fb0\n", ""),
                "{shell}"
            );
        }
    }

    #[test]
    fn the_script_refuses_when_the_screen_is_absent() {
        for shell in shells() {
            let graphics = Graphics::empty();
            graphics.hdmi("fb0");
            let ran = graphics.run(shell);
            assert_eq!((ran.status, ran.stdout.as_str()), (Some(3), ""), "{shell}");
            assert!(ran.stderr.contains("fb_ili9486"), "{shell}: {}", ran.stderr);
        }
    }

    #[test]
    fn the_script_refuses_another_rotation_or_depth() {
        for shell in shells() {
            let turned = Graphics::pi();
            turned.set("fb1", "virtual_size", "320,480");
            let ran = turned.run(shell);
            assert_eq!((ran.status, ran.stdout.as_str()), (Some(4), ""), "{shell}");
            assert!(ran.stderr.contains("320,480"), "{shell}: {}", ran.stderr);

            let deep = Graphics::pi();
            deep.set("fb1", "bits_per_pixel", "32");
            let ran = deep.run(shell);
            assert_eq!((ran.status, ran.stdout.as_str()), (Some(4), ""), "{shell}");
            assert!(
                ran.stderr.contains("fb1 has 32 bits per pixel and not 16"),
                "{shell}: {}",
                ran.stderr
            );
        }
    }

    #[test]
    fn the_script_refuses_to_choose_between_two_screens() {
        for shell in shells() {
            let graphics = Graphics::pi();
            graphics.screen("fb2");
            let ran = graphics.run(shell);
            assert_eq!((ran.status, ran.stdout.as_str()), (Some(3), ""), "{shell}");
            for word in ["fb_ili9486", "fb1", "fb2"] {
                assert!(ran.stderr.contains(word), "{shell}: {}", ran.stderr);
            }
        }
    }

    #[test]
    fn the_script_refuses_a_screen_it_cannot_measure() {
        for shell in shells() {
            let unreadable = [
                ("virtual_size", "cannot read the size of fb1"),
                ("bits_per_pixel", "cannot read the bits per pixel of fb1"),
            ];
            for (missing, reason) in unreadable {
                let graphics = Graphics::pi();
                fs::remove_file(graphics.dir.path().join("fb1").join(missing)).unwrap();
                let ran = graphics.run(shell);
                assert_eq!(
                    (ran.status, ran.stdout.as_str()),
                    (Some(4), ""),
                    "{shell}, no {missing}"
                );
                assert!(ran.stderr.contains(reason), "{shell}: {}", ran.stderr);
            }
        }
    }

    #[test]
    fn the_script_passes_over_what_is_not_a_framebuffer() {
        for shell in shells() {
            // The console's folder is there on a real Pi, and has no `name`.
            let graphics = Graphics::pi();
            graphics.set("fbcon", "cursor_blink", "1");
            let ran = graphics.run(shell);
            assert_eq!(
                (ran.status, ran.stdout.as_str()),
                (Some(0), "/dev/fb1\n"),
                "{shell}"
            );

            // Only the console: the pattern for the folders matches nothing with a name.
            let bare = Graphics::empty();
            bare.set("fbcon", "cursor_blink", "1");
            for graphics in [bare, Graphics::empty()] {
                let ran = graphics.run(shell);
                assert_eq!((ran.status, ran.stdout.as_str()), (Some(3), ""), "{shell}");
                assert!(ran.stderr.contains("fb_ili9486"), "{shell}: {}", ran.stderr);
            }
        }
    }

    #[test]
    fn a_folder_with_a_quote_in_its_name_gives_a_script_that_only_refuses() {
        let outside = tempfile::tempdir().unwrap();
        let marker = outside.path().join("marker");
        // Were the folder pasted between quotes as it is, the shell would run `touch`.
        let script = FindScreen {
            sys_graphics: format!("/nowhere'; touch {}; : '", marker.display()),
        }
        .render();
        for shell in shells() {
            let ran = run_script(shell, &script);
            assert_eq!((ran.status, ran.stdout.as_str()), (Some(5), ""), "{shell}");
            assert!(ran.stderr.contains("quote"), "{shell}: {}", ran.stderr);
        }
        assert!(!marker.exists());
        assert!(!script.contains("touch"));
    }

    // ---------------------------------------------------------------- the push

    #[test]
    fn only_a_framebuffer_device_is_accepted_as_the_answer() {
        assert_eq!(parse_device(b"/dev/fb1\n").unwrap(), "/dev/fb1");
        for bad in [
            &b"/dev/fb1"[..],
            b"/dev/sda\n",
            b"/dev/fb1 x\n",
            b"/dev/fb\n",
            b"/dev/fb1\n/dev/fb2\n",
            b"",
        ] {
            assert!(parse_device(bad).is_err());
        }
    }

    #[test]
    fn the_frame_is_written_with_one_command_and_no_shell_words() {
        let words: Vec<String> = write_frame("pi", "/dev/fb1")
            .args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            words[words.len() - 5..],
            ["pi", "dd", "of=/dev/fb1", "bs=64k", "status=none"]
        );
    }

    fn words(invocation: &Invocation) -> Vec<String> {
        invocation
            .args
            .iter()
            .map(|arg| arg.to_str().unwrap().to_owned())
            .collect()
    }

    fn finished(status: i32, stdout: &str, stderr: &str) -> Finished {
        Finished {
            status: Some(status),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    /// Stands in for `ssh`: records every command with what it was fed, and
    /// answers from a list. A command beyond the list fails the test.
    struct Recorder {
        calls: Vec<(Invocation, Option<Vec<u8>>)>,
        answers: VecDeque<Finished>,
    }

    impl Recorder {
        fn answering<const N: usize>(answers: [Finished; N]) -> Self {
            Recorder {
                calls: Vec::new(),
                answers: VecDeque::from(answers),
            }
        }
    }

    impl Runner for Recorder {
        fn reported_build(&mut self, _address: std::net::Ipv4Addr) -> Option<u64> {
            unreachable!("the panel commands never ask a status page")
        }

        fn run(&mut self, invocation: &Invocation, stdin: Option<&[u8]>) -> io::Result<Finished> {
            self.calls
                .push((invocation.clone(), stdin.map(<[u8]>::to_vec)));
            Ok(self
                .answers
                .pop_front()
                .expect("one command more than the test allows"))
        }
    }

    fn frame() -> Vec<u8> {
        rgba_to_rgb565(&render(State::Normal))
    }

    #[test]
    fn a_found_screen_gets_the_frame_in_two_commands() {
        let mut pi = Recorder::answering([finished(0, "/dev/fb1\n", ""), finished(0, "", "")]);
        let frame = frame();
        assert_eq!(push(&mut pi, "pi", &frame).unwrap(), "/dev/fb1");
        assert_eq!(pi.calls.len(), 2);

        let (find, script) = &pi.calls[0];
        assert_eq!(find.program, "ssh");
        assert_eq!(
            words(find),
            [
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                "--",
                "pi",
                "sh",
                "-s"
            ]
        );
        let on_the_pi = FindScreen {
            sys_graphics: "/sys/class/graphics".to_owned(),
        };
        assert_eq!(script.as_deref(), Some(on_the_pi.render().as_bytes()));

        let (write, fed) = &pi.calls[1];
        assert_eq!(write.program, "ssh");
        let words = words(write);
        assert_eq!(
            words[words.len() - 5..],
            ["pi", "dd", "of=/dev/fb1", "bs=64k", "status=none"]
        );
        assert_eq!(fed.as_ref().map(Vec::len), Some(307_200));
        assert!(fed.as_deref() == Some(&frame[..]));
    }

    #[test]
    fn a_refused_search_writes_nothing_and_says_why() {
        let refusals = [
            (
                3,
                "qberrypi-panel-preview: stopped: no framebuffer says it is fb_ili9486\n",
                "fb_ili9486",
            ),
            (
                4,
                "qberrypi-panel-preview: stopped: fb1 is 320,480, not 480,320\n",
                "320,480",
            ),
        ];
        for (status, stderr, reason) in refusals {
            let mut pi = Recorder::answering([finished(status, "", stderr)]);
            let error = push(&mut pi, "pi", &frame()).unwrap_err().to_string();
            assert_eq!(pi.calls.len(), 1, "{error}");
            assert!(error.contains(reason), "{error}");
            assert!(error.contains(&format!("status {status}")), "{error}");
        }
    }

    #[test]
    fn an_answer_that_is_no_framebuffer_device_writes_nothing() {
        for answer in ["/dev/sda\n", "/dev/fb1\n/dev/fb2\n", "/dev/fb1", ""] {
            let mut pi = Recorder::answering([finished(0, answer, "")]);
            let error = push(&mut pi, "pi", &frame()).unwrap_err().to_string();
            assert_eq!(pi.calls.len(), 1, "{answer:?}: {error}");
            assert!(error.contains("nothing was written"), "{error}");
        }
    }

    #[test]
    fn a_failed_write_is_an_error_with_what_dd_said() {
        let mut pi = Recorder::answering([
            finished(0, "/dev/fb1\n", ""),
            finished(1, "", "dd: failed to open '/dev/fb1': Permission denied\n"),
        ]);
        let error = push(&mut pi, "pi", &frame()).unwrap_err().to_string();
        assert_eq!(pi.calls.len(), 2);
        assert!(error.contains("Permission denied"), "{error}");
        assert!(error.contains("/dev/fb1"), "{error}");
    }

    #[test]
    fn a_bad_alias_or_a_frame_of_another_size_runs_no_command() {
        for alias in ["", "-oProxyCommand=true", "pi; reboot", "pi example"] {
            let mut pi = Recorder::answering([]);
            assert!(push(&mut pi, alias, &frame()).is_err(), "{alias:?}");
            assert!(pi.calls.is_empty(), "{alias:?}");
        }
        let mut pi = Recorder::answering([]);
        let error = push(&mut pi, "pi", &frame()[..307_198]).unwrap_err();
        assert!(error.to_string().contains("307198"), "{error}");
        assert!(pi.calls.is_empty());
    }
}
