//! The Drain's golden tests: eight of the stills as this crate paints them, compared with the committed
//! references, and the painter's frame built up compared with a fresh one.
//!
//! The comparison has three parts: the mean over the frame, the share of outlier pixels and the
//! worst tile. The references are this painter's own output, inspected beside the round 6 mockup's
//! stills; `drain_matches_the_mockup` compares regions with those stills directly when
//! `QBP_MOCKUP_DIR` names the directory that holds them.
//!
//! To write the references again after a change of look, run the tests with `QBP_BLESS=1`: each golden
//! test then writes its reference from the rendering and passes. Look at the PNGs before committing them.

use std::env;
use std::error::Error;
use std::fs::{self, File};
use std::io::{BufWriter, Cursor};
use std::ops::Range;
use std::path::{Path, PathBuf};

use qb_panel::drain::look::{TILE_DX, TILE_W, cell_x};
use qb_panel::drain::{AlertCard, Drain, Melt, NameKind, Stills, Tile, TileStyle};
use qb_panel::rows::changed_rows;
use qb_panel::{
    Blocking, Fixture, HEIGHT, LaneWords, Painter, Share, TimeOfDay, WIDTH, drain_fixture,
};

/// The side of a tile of the third part of the metric, in pixels.
const TILE: usize = 16;
/// A pixel is an outlier if a channel of it differs by more than this.
const OUTLIER_STEP: u8 = 48;
/// The tiles in a row of the frame.
const TILES_ACROSS: usize = WIDTH / TILE;
/// The pixels of a frame, as the divisor of a share or a mean.
const FRAME_PIXELS: f64 = (WIDTH * HEIGHT) as f64;
/// The pixels of a tile, as the divisor of a mean.
const TILE_PIXELS: f64 = (TILE * TILE) as f64;
/// The colour channels of a pixel that are compared: R, G and B.
const CHANNELS: f64 = 3.0;

// The tiles cover the frame exactly: 600 of them.
const _: () = assert!(WIDTH.is_multiple_of(TILE) && HEIGHT.is_multiple_of(TILE));

/// A colour as the frame stores it, without the alpha.
type Rgb = [u8; 3];
/// A rectangle of the frame: left, top, width, height.
type Rect = (usize, usize, usize, usize);

/// How far two frames are apart.
struct Diff {
    /// The mean of |a − b| over the R, G and B bytes of all pixels.
    mean_abs: f64,
    /// The share of pixels with any channel differing by more than 48.
    outliers: f64,
    /// The largest `mean_abs` of one of the 600 tiles of 16 × 16.
    worst_tile: f64,
}

/// Compares two 480 × 320 RGBA frames; the alpha is ignored.
fn diff(a: &[u8], b: &[u8]) -> Diff {
    let (a, b) = (a.as_chunks::<4>().0, b.as_chunks::<4>().0);
    assert_eq!(
        (a.len(), b.len()),
        (WIDTH * HEIGHT, WIDTH * HEIGHT),
        "two frames of 480 × 320"
    );
    // The sum of |a − b| in each tile; a whole frame of the largest steps stays within `u32`.
    let mut tiles = vec![0_u32; TILES_ACROSS * (HEIGHT / TILE)];
    let mut outliers = 0_u32;
    for (at, (p, q)) in a.iter().zip(b).enumerate() {
        let steps = [
            p[0].abs_diff(q[0]),
            p[1].abs_diff(q[1]),
            p[2].abs_diff(q[2]),
        ];
        let (x, y) = (at % WIDTH, at / WIDTH);
        tiles[y / TILE * TILES_ACROSS + x / TILE] +=
            steps.iter().copied().map(u32::from).sum::<u32>();
        outliers += u32::from(steps.iter().any(|&step| step > OUTLIER_STEP));
    }
    let worst = tiles.iter().copied().max().unwrap_or(0);
    Diff {
        mean_abs: f64::from(tiles.iter().sum::<u32>()) / (FRAME_PIXELS * CHANNELS),
        outliers: f64::from(outliers) / FRAME_PIXELS,
        worst_tile: f64::from(worst) / (TILE_PIXELS * CHANNELS),
    }
}

/// Whether a difference is within the three limits of the golden test.
fn close(d: &Diff) -> bool {
    d.mean_abs <= 0.40 && d.outliers <= 0.0003 && d.worst_tile <= 8.0
}

/// The reference PNG of a still.
fn reference_path(which: Fixture) -> String {
    format!(
        "{}/tests/reference/drain-{}.png",
        env!("CARGO_MANIFEST_DIR"),
        which.name()
    )
}

/// An 8-bit RGB or RGBA PNG of any size, as RGBA, with its width and height.
fn read_png_any(path: impl AsRef<Path>) -> (usize, usize, Vec<u8>) {
    let path = path.as_ref();
    let png = fs::read(path).unwrap_or_else(|e| panic!("{} is read: {e}", path.display()));
    let mut reader = png::Decoder::new(Cursor::new(png))
        .read_info()
        .expect("the file is a PNG");
    let mut raw = vec![0; reader.output_buffer_size().expect("the PNG fits in memory")];
    let frame = reader.next_frame(&mut raw).expect("the PNG decodes");
    let (width, height) = (
        usize::try_from(frame.width).expect("the width fits"),
        usize::try_from(frame.height).expect("the height fits"),
    );
    assert_eq!(
        frame.bit_depth,
        png::BitDepth::Eight,
        "{} is 8-bit",
        path.display()
    );
    let raw = &raw[..frame.buffer_size()];
    let rgba = match frame.color_type {
        png::ColorType::Rgb => raw
            .as_chunks::<3>()
            .0
            .iter()
            .flat_map(|&[r, g, b]| [r, g, b, u8::MAX])
            .collect(),
        png::ColorType::Rgba => raw.to_vec(),
        other => panic!("{} is {other:?}, not RGB or RGBA", path.display()),
    };
    (width, height, rgba)
}

/// An 8-bit RGB PNG as an RGBA frame of 480 × 320.
fn read_png(path: impl AsRef<Path>) -> Vec<u8> {
    let path = path.as_ref();
    let (width, height, rgba) = read_png_any(path);
    assert_eq!(
        (width, height),
        (WIDTH, HEIGHT),
        "{} has the frame's size",
        path.display()
    );
    rgba
}

/// The committed reference of a still as an RGBA frame.
fn reference(which: Fixture) -> Vec<u8> {
    read_png(reference_path(which))
}

/// The still as the painter paints it from scratch, as RGBA.
fn render(which: Fixture) -> Vec<u8> {
    let (drain, stills) = drain_fixture(which);
    let mut painter = Painter::new();
    painter.paint(&drain, &stills);
    painter.rgba().to_vec()
}

/// Writes an RGBA frame as an 8-bit RGB PNG.
fn write_png(path: &Path, rgba: &[u8]) -> Result<(), Box<dyn Error>> {
    let rgb: Vec<u8> = rgba
        .as_chunks::<4>()
        .0
        .iter()
        .flat_map(|&[r, g, b, _]| [r, g, b])
        .collect();
    let mut encoder = png::Encoder::new(
        BufWriter::new(File::create(path)?),
        u32::try_from(WIDTH)?,
        u32::try_from(HEIGHT)?,
    );
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header()?;
    writer.write_image_data(&rgb)?;
    writer.finish()?;
    Ok(())
}

/// Saves a rendering that missed its reference among the build's temporary files and says where.
fn save_actual(name: &str, rgba: &[u8]) -> Result<PathBuf, Box<dyn Error>> {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("qb-panel-drain-{name}.png"));
    write_png(&path, rgba)?;
    Ok(path)
}

/// Whether this run is to write the references: `QBP_BLESS` is set to anything.
fn blessing() -> bool {
    env::var_os("QBP_BLESS").is_some()
}

/// Checks a still against its reference, saving the rendering if it is not close. With `QBP_BLESS`
/// set, it writes the reference from the rendering instead.
fn check(which: Fixture) {
    let name = which.name();
    let ours = render(which);
    if blessing() {
        write_png(Path::new(&reference_path(which)), &ours).expect("the reference is written");
        return;
    }
    let d = diff(&ours, &reference(which));
    if !close(&d) {
        match save_actual(name, &ours) {
            Ok(path) => eprintln!("the rendering is in {}", path.display()),
            Err(error) => eprintln!("the rendering could not be saved: {error}"),
        }
    }
    assert!(
        close(&d),
        "{name}: mean_abs {:.3}, outliers {:.5}, worst_tile {:.2}",
        d.mean_abs,
        d.outliers,
        d.worst_tile
    );
}

/// Where the pixel in column `x` of row `y` starts in a frame.
fn offset(x: usize, y: usize) -> usize {
    assert!(x < WIDTH && y < HEIGHT, "({x}, {y}) is outside the frame");
    (y * WIDTH + x) * 4
}

/// The colour of the pixel in column `x` of row `y`.
fn px(frame: &[u8], x: usize, y: usize) -> Rgb {
    let at = offset(x, y);
    [frame[at], frame[at + 1], frame[at + 2]]
}

/// Gives the pixel in column `x` of row `y` a colour.
fn put(frame: &mut [u8], x: usize, y: usize, colour: Rgb) {
    let at = offset(x, y);
    frame[at..at + 3].copy_from_slice(&colour);
}

/// The frame with the rectangle filled with the background and its former
/// content pasted shifted by `(dx, dy)`; what would land outside the frame is dropped.
fn moved(frame: &[u8], rect: Rect, (dx, dy): (isize, isize), background: Rgb) -> Vec<u8> {
    let (left, top, width, height) = rect;
    let mut out = filled(frame, rect, background);
    for y in top..top + height {
        for x in left..left + width {
            let to = (x.checked_add_signed(dx), y.checked_add_signed(dy));
            if let (Some(to_x), Some(to_y)) = to
                && to_x < WIDTH
                && to_y < HEIGHT
            {
                put(&mut out, to_x, to_y, px(frame, x, y));
            }
        }
    }
    out
}

/// The frame with the rectangle painted one colour.
fn filled(frame: &[u8], (left, top, width, height): Rect, colour: Rgb) -> Vec<u8> {
    let mut out = frame.to_vec();
    for y in top..top + height {
        for x in left..left + width {
            put(&mut out, x, y, colour);
        }
    }
    out
}

/// The frame with every pixel of exactly the colour `from` in the colour `to`.
fn recoloured(frame: &[u8], from: Rgb, to: Rgb) -> Vec<u8> {
    let mut out = frame.to_vec();
    for pixel in out.as_chunks_mut::<4>().0 {
        if pixel[..3] == from {
            pixel[..3].copy_from_slice(&to);
        }
    }
    out
}

#[test]
fn drain_normal_renders_as_the_reference() {
    check(Fixture::Normal);
}

#[test]
fn drain_paused_renders_as_the_reference() {
    check(Fixture::Paused);
}

#[test]
fn drain_alert_renders_as_the_reference() {
    check(Fixture::Alert);
}

#[test]
fn drain_boot_renders_as_the_reference() {
    check(Fixture::Boot);
}

#[test]
fn drain_listening_renders_as_the_reference() {
    check(Fixture::Listening);
}

#[test]
fn drain_quiet_renders_as_the_reference() {
    check(Fixture::Quiet);
}

#[test]
fn drain_long_renders_as_the_reference() {
    check(Fixture::Long);
}

#[test]
fn drain_six_renders_as_the_reference() {
    check(Fixture::Six);
}

#[test]
fn the_metric_rejects_altered_drain_frames() {
    const BLUE: Rgb = [0x4a, 0x72, 0xff];
    const G2: Rgb = [0x8e, 0x8e, 0x8e];
    const WHITE: Rgb = [0xff, 0xff, 0xff];
    const BLACK: Rgb = [0, 0, 0];
    let ours = render(Fixture::Normal);
    let reference = reference(Fixture::Normal);
    let cases: [(&str, Vec<u8>); 6] = [
        (
            "the count two pixels down",
            moved(&ours, (128, 236, 352, 82), (0, 2), BLACK),
        ),
        ("the key missing", filled(&ours, (8, 224, 80, 80), BLACK)),
        ("the gate missing", filled(&ours, (96, 0, 24, 304), BLACK)),
        (
            "the accent in another blue",
            recoloured(&ours, BLUE, [0x5b, 0x6c, 0xf0]),
        ),
        ("REFUSED in white", recoloured(&ours, G2, WHITE)),
        ("the ground at 3, 3, 3", recoloured(&ours, BLACK, [3, 3, 3])),
    ];
    for (what, frame) in &cases {
        assert!(
            !close(&diff(frame, &reference)),
            "{what} passed the golden limits"
        );
    }
}

/// A small deterministic generator for the traffic of the build-up test.
struct Lcg(u32);

impl Lcg {
    /// The next number below `n`.
    fn below(&mut self, n: u32) -> u32 {
        self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        (self.0 >> 8) % n.max(1)
    }
}

#[test]
fn the_painter_draws_the_same_frame_whether_built_up_or_fresh() {
    const ADS: [&str; 7] = [
        "doubleclick.net",
        "googlesyndication.com",
        "adnxs.com",
        "criteo.com",
        "amazon-adsystem.com",
        "openx.net",
        // Longer than the 15 cells a refused name stops in: fitted, with a `~`.
        "pagead2.googlesyndication.com",
    ];
    let mut rng = Lcg(7);
    let mut drain = Drain::new(11);
    let mut painter = Painter::new();
    let mut shown = Stills {
        blocking: Blocking::On,
        ..Stills::default()
    };
    let mut blocked = 4000_u32;
    let mut paused_left = 0_u16;
    let mut alert_left = 0_u32;
    let mut drops = 0_u32;
    let mut refills = 0_u32;
    let mut words_shown = 0_u32;
    for tick in 0..480_u32 {
        // Traffic: a name about every third tick, an ad two times in five; none before tick 14 or from
        // tick 300, so that the lane is idle and its words show.
        if (14..300).contains(&tick) && rng.below(3) == 0 {
            if rng.below(5) < 2 {
                let ad = ADS[rng.below(7) as usize];
                drain.offer(ad, NameKind::Refused);
                blocked += 1;
            } else {
                let name = format!("site{}.example.org", rng.below(40));
                drain.offer(&name, NameKind::Plain);
            }
        }
        // A pause from tick 150 to 250, counting down so that the gate refills in steps; the time left
        // starts over every 40 ticks, so that the refill also falls while the pause lasts.
        let paused = (150..250).contains(&tick);
        if paused {
            paused_left =
                299_u16.saturating_sub(u16::try_from((tick - 150) * 3 % 120).unwrap_or(0));
        }
        // The funnel is filled in one go once, as a fixture does, over the landings.
        if tick == 200 {
            drain.prefill(5);
        }
        // Nothing is known for the first ticks, as on a cold boot.
        let known = tick >= 12;
        drain.set_blocked_today(known.then_some(blocked));
        drain.tick(paused);
        drops += u32::from(drain.spout_drop());
        let wanted = Stills {
            percent: match tick {
                0..12 => None,
                12..100 => Some(Share::Percent(
                    u8::try_from(40 + (tick / 37) % 20).unwrap_or(0),
                )),
                100..140 => Some(Share::Zero),
                140..200 => Some(Share::UnderOne),
                200..260 => Some(Share::All),
                _ => Some(Share::Percent(7)),
            },
            clock: (tick >= 4).then(|| TimeOfDay {
                hour: u8::try_from(10 + tick / 240).unwrap_or(0),
                minute: u8::try_from(tick / 20 % 60).unwrap_or(0),
            }),
            blocking: if paused {
                Blocking::Paused {
                    left_secs: paused_left,
                }
            } else {
                Blocking::On
            },
            gate_fill: if paused {
                qb_panel::format::gate_fill(paused_left)
            } else {
                0
            },
            count: drain.count(),
            // An alert over ticks 60 to 90, a blue one with a subject on two lines over 300 to 330,
            // and one that is high and has no subject over 440 to 460.
            alert: match tick {
                60..90 => Some(card(true, "doubleclick.net")),
                300..330 => Some(card(
                    false,
                    "secure-login-verify.accounts-billing.example.org",
                )),
                440..460 => Some(card(true, "")),
                _ => None,
            },
            words: match tick {
                0..12 => Some(LaneWords::Joining),
                12..30 => Some(LaneWords::Listening),
                340.. => Some(LaneWords::Quiet {
                    minutes: tick - 300,
                }),
                _ => None,
            },
        };
        alert_left += u32::from(wanted.alert.is_some());
        refills += u32::from(wanted.gate_fill > 0);
        words_shown += u32::from(wanted.words.is_some() && drain.idle());
        // The panel's schedule: a motion write, then still writes one field at a time. The frame
        // built up is checked against a fresh one every few ticks, and around every change of
        // the pause, the alert, the words and the spout's drop.
        let edge = [12, 30, 60, 90, 150, 200, 250, 300, 330, 340, 440, 460]
            .iter()
            .any(|&at| (at..at + 3).contains(&tick))
            || drain.spout_drop();
        let compare = edge || tick % 8 == 0;
        painter.paint(&drain, &shown);
        while shown.step_toward(&wanted) {
            painter.paint(&drain, &shown);
            if edge {
                let mut fresh = Painter::new();
                fresh.paint(&drain, &shown);
                assert!(
                    painter.rgba() == fresh.rgba(),
                    "tick {tick}: the rgba frames differ"
                );
            }
        }
        if compare {
            let mut fresh = Painter::new();
            let built = painter.paint(&drain, &shown).to_vec();
            assert!(
                built == fresh.paint(&drain, &shown),
                "tick {tick}: the rgb565 frames differ"
            );
            assert!(
                painter.rgba() == fresh.rgba(),
                "tick {tick}: the rgba differs"
            );
        }
    }
    // The run took in every state the comparison is for.
    assert!(alert_left > 0, "an alert was shown");
    assert!(drops > 0, "a drop left the spout");
    assert!(refills > 10, "the gate refilled");
    assert!(words_shown > 0, "the lane said its words");
}

/// An alert card with a title and a name.
fn card(high: bool, subject: &str) -> AlertCard {
    qb_panel::format::alert_card("beacon", high, subject, None)
}

/// How far two frames are apart inside some rectangles of the frame: the three parts of the metric,
/// over the pixels of the rectangles only. A tile is of the frame's grid, and counts only the pixels of
/// the rectangles that fall in it.
fn region_diff(a: &[u8], b: &[u8], rects: &[Rect]) -> Diff {
    let inside = |x: usize, y: usize| {
        rects
            .iter()
            .any(|&(l, t, w, h)| (l..l + w).contains(&x) && (t..t + h).contains(&y))
    };
    let mut tiles = vec![0_u32; TILES_ACROSS * (HEIGHT / TILE)];
    let (mut total, mut outliers, mut pixels) = (0_u64, 0_u64, 0_u64);
    for y in 0..HEIGHT {
        for x in 0..WIDTH {
            if !inside(x, y) {
                continue;
            }
            let (p, q) = (px(a, x, y), px(b, x, y));
            let steps = [
                p[0].abs_diff(q[0]),
                p[1].abs_diff(q[1]),
                p[2].abs_diff(q[2]),
            ];
            let sum = steps.iter().copied().map(u32::from).sum::<u32>();
            tiles[y / TILE * TILES_ACROSS + x / TILE] += sum;
            total += u64::from(sum);
            outliers += u64::from(steps.iter().any(|&step| step > OUTLIER_STEP));
            pixels += 1;
        }
    }
    let pixels = pixels.max(1) as f64;
    Diff {
        mean_abs: total as f64 / (pixels * CHANNELS),
        outliers: outliers as f64 / pixels,
        worst_tile: f64::from(tiles.iter().copied().max().unwrap_or(0)) / (TILE_PIXELS * CHANNELS),
    }
}

// ---------------------------------------------------------------------------------------------
// The comparison with the round 6 mockup: every still, and the refusal strip frame by frame.
//
// A frame is split into text boxes and areas of shapes. Shapes are compared pixel for pixel, because
// a rect, a rail or an outline is the mockup's exactly, and a round shape is stamped from the
// mockup's own coverage masks. Text is compared with the round 5 limits: the browser and this crate
// rasterise glyphs differently at their edges, so no letter is the same pixel for pixel.

/// How the pixels of an area are held to the mockup's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Rects, rails and outlines: every pixel is the mockup's.
    Flat,
    /// Round shapes (dots, sockets, drip tips and teardrops): the masks are the browser's own, but the
    /// browser's rasteriser is not the same at every place on the screen. In a full funnel 28 of
    /// the 146 dots, in five columns, have two pixels that are up to `ROUND_STEP_MAX` off the other
    /// dots', so an area may differ in no more than `ROUND_SHARE_MAX` of its pixels, and by no more
    /// than that.
    Round,
}

/// The most a pixel of a round shape may be off the mockup's, in any channel: the browser's own
/// variation from one place to another (see `Kind::Round`), 8 in 255.
const ROUND_STEP_MAX: u8 = 8;

/// The most of an area's pixels that may differ, by up to `ROUND_STEP_MAX`, where it has round shapes.
const ROUND_SHARE_MAX: f64 = 0.0015;

/// A part of the frame whose shapes are compared pixel for pixel.
struct Area {
    /// What it is, for the report.
    name: &'static str,
    /// Its rectangles.
    rects: Vec<Rect>,
    /// How its pixels are held.
    kind: Kind,
}

/// A box of text: compared with limits of its own, and left out of the shapes. It is skipped where the
/// mockup's text is another name than the fixture's.
struct TextBox {
    /// What it is, for the report.
    what: String,
    /// Where it is.
    rect: Rect,
    /// Whether the mockup's text here is another name than the fixture's, so it is not compared.
    skipped: bool,
}

/// A region of text compared as round 5 compared its regions: a wider piece of the frame, whose ink
/// is a small share of its pixels, held to the round 5 limits.
struct TextRegion {
    /// What it is, for the report.
    name: &'static str,
    /// Its rectangles.
    rects: Vec<Rect>,
    /// Whether it holds a name that is not the mockup's, so it is not compared.
    skipped: bool,
}

/// How to compare one frame: its text boxes and regions, and the areas of shapes round them.
struct Plan {
    /// The text boxes.
    text: Vec<TextBox>,
    /// The text regions.
    regions: Vec<TextRegion>,
    /// The areas of shapes, which do not overlap.
    areas: Vec<Area>,
}

/// The round 5 limits for a text region: the mean of the differences, the share of outliers, and the worst tile.
const TEXT_MEAN_MAX: f64 = 4.0;
/// See `TEXT_MEAN_MAX`.
const TEXT_OUTLIERS_MAX: f64 = 0.035;
/// See `TEXT_MEAN_MAX`.
const TEXT_TILE_MAX: f64 = 70.0;

/// The limits for one box of text, which is mostly ink: the mean and the share of outliers are higher
/// than a region's, whose ink is a smaller share of its pixels. A glyph in the wrong place or the wrong
/// glyph is far over them.
const BOX_MEAN_MAX: f64 = 10.0;
/// See `BOX_MEAN_MAX`.
const BOX_OUTLIERS_MAX: f64 = 0.10;

/// The box of a letter on a whole tile: the lane's letters stand on y 44, and reach from 26 to 50.
const LETTER_ROWS: (usize, usize) = (22, 32);
/// The box of a letter on a sagging tile, which stands 6 px lower.
const SAG_LETTER_ROWS: (usize, usize) = (28, 32);

/// The boxes of the letters of the tiles that still have one: whole and sagging tiles.
fn letter_boxes(tiles: &[Tile], skipped: bool) -> Vec<TextBox> {
    tiles
        .iter()
        .filter_map(|tile| {
            let (top, height) = match tile.melt {
                Melt::Whole => LETTER_ROWS,
                Melt::Sag => SAG_LETTER_ROWS,
                _ => return None,
            };
            let left = (cell_x(tile.cell) + TILE_DX) as usize;
            Some(TextBox {
                what: format!("letter, cell {}", tile.cell),
                rect: (left, top, TILE_W as usize, height),
                skipped,
            })
        })
        .collect()
}

/// What of a still the fixture does not reproduce.
#[derive(Debug, Clone, Copy, Default)]
struct Replaced {
    /// The letters of the plain names on the lane.
    plain_letters: bool,
    /// The subject and who lines of the alert card.
    card_lines: bool,
}

impl Plan {
    /// The plan for a frame: `tiles` are the lane's, `idle` says whether the lane's words show.
    fn of(tiles: &[Tile], stills: &Stills, idle: bool, replaced: Replaced) -> Self {
        let plain: Vec<Tile> = tiles
            .iter()
            .copied()
            .filter(|tile| tile.style == TileStyle::Plain)
            .collect();
        let others: Vec<Tile> = tiles
            .iter()
            .copied()
            .filter(|tile| tile.style != TileStyle::Plain)
            .collect();
        let mut text = letter_boxes(&plain, replaced.plain_letters);
        text.extend(letter_boxes(&others, false));
        let boxed = |what: &str, rect: Rect, skipped: bool| TextBox {
            what: what.to_string(),
            rect,
            skipped,
        };
        text.push(boxed("percent", (0, 72, 96, 48), false));
        text.push(boxed("REFUSED", (0, 124, 96, 18), false));
        text.push(boxed("clock", (0, 168, 96, 28), false));
        text.push(boxed("key text", (16, 236, 64, 56), false));
        let alert = stills.alert.is_some();
        if alert {
            text.push(boxed("card title", (136, 92, 336, 80), false));
            text.push(boxed(
                "card subject and who",
                (136, 176, 336, 76),
                replaced.card_lines,
            ));
            text.push(boxed("card stub text", (136, 268, 336, 28), false));
        } else {
            text.push(boxed("count", (120, 250, 360, 70), false));
        }
        if stills.words.is_some() && idle {
            text.push(boxed("lane words", (120, 22, 360, 32), false));
        }
        let melting = tiles.iter().any(|tile| {
            matches!(
                tile.melt,
                Melt::Puddle | Melt::Slump | Melt::Drop | Melt::Fall
            )
        });
        let area = |name, rects: &[Rect], kind| Area {
            name,
            rects: rects.to_vec(),
            kind,
        };
        let mut areas = vec![
            area("gate column", &[(96, 0, 24, 320)], Kind::Flat),
            area(
                "lane tiles and rails",
                &[(0, 0, 96, 56), (120, 0, 360, 56)],
                Kind::Flat,
            ),
            area(
                "drips, tips and lower rail",
                &[(0, 56, 96, 24), (120, 56, 360, 24)],
                if melting { Kind::Round } else { Kind::Flat },
            ),
            area("key", &[(8, 224, 80, 80)], Kind::Flat),
            area(
                "left column",
                &[
                    (0, 80, 96, 144),
                    (0, 224, 8, 80),
                    (88, 224, 8, 80),
                    (0, 304, 96, 16),
                ],
                Kind::Flat,
            ),
        ];
        if alert {
            areas.push(area(
                "alert card and its field",
                &[(120, 80, 360, 240)],
                Kind::Flat,
            ));
        } else {
            areas.push(area("funnel", &[(120, 80, 360, 144)], Kind::Round));
            areas.push(area("count band", &[(120, 224, 360, 96)], Kind::Flat));
        }
        let mut regions = vec![
            TextRegion {
                name: "left column text",
                rects: vec![(0, 64, 96, 256)],
                skipped: false,
            },
            TextRegion {
                name: "lane letters and words",
                rects: vec![(0, 0, 96, 64), (120, 0, 360, 64)],
                skipped: replaced.plain_letters,
            },
        ];
        if alert {
            for (name, rect) in [
                ("card title", (128, 80, 344, 96)),
                ("card stub text", (128, 252, 344, 68)),
            ] {
                regions.push(TextRegion {
                    name,
                    rects: vec![rect],
                    skipped: false,
                });
            }
        } else {
            regions.push(TextRegion {
                name: "count text",
                rects: vec![(128, 240, 352, 80)],
                skipped: false,
            });
        }
        Self {
            text,
            regions,
            areas,
        }
    }

    /// The rectangles of the text boxes, compared or not.
    fn text_rects(&self) -> Vec<Rect> {
        self.text.iter().map(|text| text.rect).collect()
    }
}

/// How many pixels of some rectangles differ, and by how much at most, leaving out some others.
#[derive(Debug, Clone, Copy, Default)]
struct Stats {
    /// The pixels looked at.
    pixels: usize,
    /// The pixels where any channel differs.
    differing: usize,
    /// The largest difference of a channel.
    max: u8,
}

/// Compares the pixels of `rects` that are in none of `except`.
fn shape_stats(a: &[u8], b: &[u8], rects: &[Rect], except: &[Rect]) -> Stats {
    let inside = |rects: &[Rect], x: usize, y: usize| {
        rects
            .iter()
            .any(|&(l, t, w, h)| (l..l + w).contains(&x) && (t..t + h).contains(&y))
    };
    let mut stats = Stats::default();
    for y in 0..HEIGHT {
        for x in 0..WIDTH {
            if !inside(rects, x, y) || inside(except, x, y) {
                continue;
            }
            let (p, q) = (px(a, x, y), px(b, x, y));
            let step = (0..3).map(|c| p[c].abs_diff(q[c])).max().unwrap_or(0);
            stats.pixels += 1;
            stats.differing += usize::from(step > 0);
            stats.max = stats.max.max(step);
        }
    }
    stats
}

/// Compares a frame with the mockup's by a plan, prints every region's figures, and says what is out of bounds.
fn compare(label: &str, ours: &[u8], theirs: &[u8], plan: &Plan) -> Vec<String> {
    let mut bad = vec![];
    let except = plan.text_rects();
    for area in &plan.areas {
        let s = shape_stats(ours, theirs, &area.rects, &except);
        eprintln!(
            "{label:11} {:30} {:5} pixels {:6} differing {:5} max {:3}",
            area.name,
            format!("{:?}", area.kind).to_lowercase(),
            s.pixels,
            s.differing,
            s.max
        );
        let fine = match area.kind {
            Kind::Flat => s.differing == 0,
            Kind::Round => {
                s.max <= ROUND_STEP_MAX && s.differing as f64 <= ROUND_SHARE_MAX * s.pixels as f64
            }
        };
        if !fine {
            bad.push(format!(
                "{label} {}: {} of {} pixels differ, by up to {}",
                area.name, s.differing, s.pixels, s.max
            ));
        }
    }
    for region in &plan.regions {
        if region.skipped {
            eprintln!(
                "{label:11} {:30} text  skipped: the names are not the mockup's",
                region.name
            );
            continue;
        }
        let d = region_diff(ours, theirs, &region.rects);
        eprintln!(
            "{label:11} {:30} text  mean_abs {:.3} outliers {:.5} worst_tile {:.2}",
            region.name, d.mean_abs, d.outliers, d.worst_tile
        );
        if d.mean_abs > TEXT_MEAN_MAX
            || d.outliers > TEXT_OUTLIERS_MAX
            || d.worst_tile > TEXT_TILE_MAX
        {
            bad.push(format!(
                "{label} {}: mean_abs {:.3}, outliers {:.5}, worst_tile {:.2}",
                region.name, d.mean_abs, d.outliers, d.worst_tile
            ));
        }
    }
    for text in &plan.text {
        if text.skipped {
            continue;
        }
        let d = region_diff(ours, theirs, &[text.rect]);
        eprintln!(
            "{label:11}   box {:26} mean_abs {:.3} outliers {:.5} worst_tile {:.2}",
            text.what, d.mean_abs, d.outliers, d.worst_tile
        );
        if d.mean_abs > BOX_MEAN_MAX
            || d.outliers > BOX_OUTLIERS_MAX
            || d.worst_tile > TEXT_TILE_MAX
        {
            bad.push(format!(
                "{label} box {}: mean_abs {:.3}, outliers {:.5}, worst_tile {:.2}",
                text.what, d.mean_abs, d.outliers, d.worst_tile
            ));
        }
    }
    bad
}

/// The mockup's directory, if `QBP_MOCKUP_DIR` names it.
fn mockup_dir() -> Option<PathBuf> {
    let dir = env::var_os("QBP_MOCKUP_DIR").map(PathBuf::from);
    if dir.is_none() {
        eprintln!("QBP_MOCKUP_DIR is not set: nothing to compare with");
    }
    dir
}

/// The mockup's still of this name as the 480 × 320 frame it is a 2× copy of: every second pixel.
fn mockup_still(dir: &Path, name: &str) -> Vec<u8> {
    let path = dir.join(format!("r6-after-{name}@2x.png"));
    let (width, height, big) = read_png_any(&path);
    assert_eq!(
        (width, height),
        (2 * WIDTH, 2 * HEIGHT),
        "{} is a 2x still",
        path.display()
    );
    let mut frame = vec![0; WIDTH * HEIGHT * 4];
    for y in 0..HEIGHT {
        for x in 0..WIDTH {
            let from = (2 * y * width + 2 * x) * 4;
            frame[offset(x, y)..offset(x, y) + 4].copy_from_slice(&big[from..from + 4]);
        }
    }
    frame
}

/// Writes the frame beside the mockup's, if `QBP_DUMP_DIR` names a directory, so a difference can be looked at.
fn dump(name: &str, rgba: &[u8]) {
    if let Some(dir) = env::var_os("QBP_DUMP_DIR") {
        let path = Path::new(&dir).join(format!("{name}.png"));
        write_png(&path, rgba).unwrap_or_else(|e| panic!("{} is written: {e}", path.display()));
    }
}

/// What a fixture does not reproduce of the mockup's still.
fn replaced(which: Fixture) -> Replaced {
    match which {
        // The mockup's plain names are other names; only a name's last letters show in these.
        Fixture::Pct0 => Replaced {
            plain_letters: true,
            card_lines: false,
        },
        Fixture::Alert | Fixture::AlertLow | Fixture::AlertLong => Replaced {
            plain_letters: false,
            card_lines: true,
        },
        _ => Replaced::default(),
    }
}

// It needs the mockup stills: set QBP_MOCKUP_DIR to their directory, and QBP_DUMP_DIR to save the frames.
#[test]
#[ignore = "needs the mockup's stills: set QBP_MOCKUP_DIR"]
fn drain_matches_the_mockup() {
    let Some(dir) = mockup_dir() else {
        return;
    };
    let mut bad = vec![];
    for which in Fixture::ALL {
        let (drain, stills) = drain_fixture(which);
        let mut painter = Painter::new();
        painter.paint(&drain, &stills);
        let ours = painter.rgba().to_vec();
        dump(which.name(), &ours);
        let theirs = mockup_still(&dir, which.name());
        let tiles: Vec<Tile> = drain.lane().collect();
        let plan = Plan::of(&tiles, &stills, drain.idle(), replaced(which));
        bad.extend(compare(which.name(), &ours, &theirs, &plan));
    }
    assert!(bad.is_empty(), "out of bounds:\n{}", bad.join("\n"));
}

// ---------------------------------------------------------------------------------------------
// One refusal, frame by frame: the mockup's refusal strip.

/// The bytes in a row of the RGB565 frame.
const ROW_BYTES: usize = WIDTH * 2;

/// The name of the mockup's refusal strip: 15 letters, so the refusal takes 17 steps.
const STRIP_NAME: &str = "doubleclick.net";

/// The most rows a write may change.
const WRITE_ROWS_MAX: usize = 80;

/// The places of the screen a step of a refusal may change, one at a time, as rows: the lane
/// with the door, the funnel, the drop at the spout, and the count.
const PLACES: [(&str, Range<usize>); 4] = [
    ("lane", 0..100),
    ("funnel", 80..224),
    ("spout drop", 228..240),
    ("count", 236..320),
];

/// One step of the strip's refusal: the frame the painter has after it, and the rows it wrote.
struct StripStep {
    /// The step, from 1.
    step: u8,
    /// The rows the write changed, as the screen's driver sends them; `None` if the step changed nothing.
    rows: Option<Range<usize>>,
    /// The frame, as RGBA.
    rgba: Vec<u8>,
    /// The lane's tiles at this step.
    tiles: Vec<Tile>,
    /// The figures this step showed.
    stills: Stills,
}

/// Drives one refusal of the strip's name through the painter as the mockup's `strip()` does: the
/// funnel is full (its dot 61 next), the count is 4,780 and 44 %, the clock 10:21. The painter writes
/// after every tick, as the panel does, and the count follows the Drain in the same write.
fn strip_refusal() -> Vec<StripStep> {
    let mut drain = Drain::new(7);
    drain.prefill(7);
    // The name is in flight when the figure comes, so the count holds back the one it will add.
    drain.offer(STRIP_NAME, NameKind::Refused);
    drain.set_blocked_today(Some(4781));
    let mut stills = Stills {
        percent: Some(Share::Percent(44)),
        clock: Some(TimeOfDay {
            hour: 10,
            minute: 21,
        }),
        blocking: Blocking::On,
        count: drain.count(),
        ..Stills::default()
    };
    let mut painter = Painter::new();
    let mut last = painter.paint(&drain, &stills).to_vec();
    let mut steps = vec![];
    for _ in 0..80 {
        drain.tick(false);
        stills.count = drain.count();
        let frame = painter.paint(&drain, &stills);
        let rows = changed_rows(&last, frame, ROW_BYTES);
        last.clear();
        last.extend_from_slice(frame);
        match drain.refusal_step() {
            Some(step) => steps.push(StripStep {
                step,
                rows,
                rgba: painter.rgba().to_vec(),
                tiles: drain.lane().collect(),
                stills: stills.clone(),
            }),
            None if !steps.is_empty() => break,
            None => {}
        }
    }
    steps
}

#[test]
fn a_refusal_of_a_fifteen_letter_name_takes_seventeen_steps_each_changing_one_place() {
    let steps = strip_refusal();
    assert_eq!(steps.len(), 17, "a 15-letter name takes 17 steps");
    for (at, step) in steps.iter().enumerate() {
        assert_eq!(usize::from(step.step), at + 1, "the steps count up from 1");
        let Some(rows) = &step.rows else {
            eprintln!("step {:2}: nothing changed", step.step);
            continue;
        };
        let place = PLACES
            .iter()
            .find(|(_, place)| place.start <= rows.start && rows.end <= place.end);
        eprintln!(
            "step {:2}: rows {:3}..{:3} ({:2} rows) in the {}",
            step.step,
            rows.start,
            rows.end,
            rows.len(),
            place.map_or("-- more than one place --", |(name, _)| name)
        );
        assert!(
            place.is_some(),
            "step {}: rows {rows:?} are in more than one place",
            step.step
        );
        assert!(
            rows.len() <= WRITE_ROWS_MAX,
            "step {}: a write of {} rows",
            step.step,
            rows.len()
        );
    }
    // The door shuts at step 1 and reopens at the last step; the count rises at step 16.
    let counts: Vec<Option<u32>> = steps.iter().map(|step| step.stills.count).collect();
    assert_eq!(counts[14], Some(4780));
    assert_eq!(counts[15], Some(4781));
}

/// The mockup's strip frame `n`, from 0: four frames to a row at 1x, 8 px apart.
fn strip_frame(strip: &(usize, usize, Vec<u8>), n: usize) -> Vec<u8> {
    const GAP: usize = 8;
    let (width, _, rgba) = strip;
    let (left, top) = (n % 4 * (WIDTH + GAP), n / 4 * (HEIGHT + GAP));
    let mut frame = vec![0; WIDTH * HEIGHT * 4];
    for y in 0..HEIGHT {
        let from = ((top + y) * width + left) * 4;
        frame[offset(0, y)..offset(0, y) + WIDTH * 4]
            .copy_from_slice(&rgba[from..from + WIDTH * 4]);
    }
    frame
}

// It needs the mockup's strip: set QBP_MOCKUP_DIR to its directory.
#[test]
#[ignore = "needs the mockup's strip: set QBP_MOCKUP_DIR"]
fn a_refusal_matches_the_mockups_strip_frame_by_frame() {
    let Some(dir) = mockup_dir() else {
        return;
    };
    let strip = read_png_any(dir.join("r6-after-refusal-strip.png"));
    let mut bad = vec![];
    for (at, step) in strip_refusal().iter().enumerate() {
        let theirs = strip_frame(&strip, at);
        dump(&format!("strip-{:02}", step.step), &step.rgba);
        let label = format!("step {:2}", step.step);
        let plan = Plan::of(&step.tiles, &step.stills, false, Replaced::default());
        bad.extend(compare(&label, &step.rgba, &theirs, &plan));
        // The drips, tips and teardrops: the lane below its tiles, down to where the lowest teardrop ends.
        let tear = shape_stats(
            &step.rgba,
            &theirs,
            &[(120, 56, 360, 34)],
            &plan.text_rects(),
        );
        eprintln!(
            "{label:11} {:30} round pixels {:6} differing {:5} max {:3}",
            "drips and teardrops, y 56-90", tear.pixels, tear.differing, tear.max
        );
        if tear.max > ROUND_STEP_MAX || tear.differing as f64 > ROUND_SHARE_MAX * tear.pixels as f64
        {
            bad.push(format!(
                "{label} drips and teardrops: {} of {} pixels differ, by up to {}",
                tear.differing, tear.pixels, tear.max
            ));
        }
    }
    assert!(bad.is_empty(), "out of bounds:\n{}", bad.join("\n"));
}
