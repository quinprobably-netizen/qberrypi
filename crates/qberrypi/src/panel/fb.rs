//! Finding the screen's framebuffer, taking the text console off it, and drawing on it.

use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use qb_panel::{HEIGHT, WIDTH};

use crate::sys::SharedMapping;

/// The name of the kernel driver of the touchscreen's display.
pub const SCREEN_DRIVER: &str = "fb_ili9486";

/// Where the kernel lists its framebuffers.
pub const SYS_GRAPHICS: &str = "/sys/class/graphics";

/// Where the kernel lists its virtual consoles.
pub const SYS_VTCONSOLE: &str = "/sys/class/vtconsole";

/// How many bytes a frame holds: two for each pixel.
const FRAME_BYTES: usize = WIDTH * HEIGHT * 2;

/// How many bytes a row holds.
const ROW_BYTES: usize = WIDTH * 2;

/// The framebuffer of the screen.
#[derive(Debug, PartialEq)]
pub struct Screen {
    /// The device file to draw on.
    pub device: PathBuf,
    /// Whether no other framebuffer exists, so that the kernel's text console is on the screen.
    pub sole: bool,
}

/// Why there is no screen to draw on.
#[derive(Debug, PartialEq)]
pub enum ScreenError {
    /// No framebuffer belongs to the screen's driver.
    Absent,
    /// The driver's framebuffer is not a 480 by 320 screen of 16 bits per pixel; holds what it is,
    /// as in "320,480 at 16 bpp", with a "?" where the kernel did not say.
    Wrong(String),
}

/// Reads a sysfs file as text without its trailing newline.
fn read_trimmed(file: &Path) -> Option<String> {
    Some(fs::read_to_string(file).ok()?.trim().to_owned())
}

/// Finds the screen's framebuffer among those in `sys_graphics` and names its device file in `dev`.
///
/// The screen is the framebuffer whose driver is `SCREEN_DRIVER`, whatever its number:
/// the HDMI output may or may not be there to take number 0. No other is ever taken.
pub fn find_screen(sys_graphics: &Path, dev: &Path) -> Result<Screen, ScreenError> {
    let entries = fs::read_dir(sys_graphics).map_err(|_| ScreenError::Absent)?;
    // A directory without a `name` file, like `fbcon`, is not a framebuffer.
    let mut framebuffers: Vec<(String, String)> = entries
        .filter_map(|entry| {
            let dir = entry.ok()?.file_name().into_string().ok()?;
            if !dir.starts_with("fb") {
                return None;
            }
            let name = read_trimmed(&sys_graphics.join(&dir).join("name"))?;
            Some((dir, name))
        })
        .collect();
    framebuffers.sort();
    let at = framebuffers
        .iter()
        .position(|(_, name)| name == SCREEN_DRIVER)
        .ok_or(ScreenError::Absent)?;
    let dir = &framebuffers[at].0;
    let size = read_trimmed(&sys_graphics.join(dir).join("virtual_size"));
    let bpp = read_trimmed(&sys_graphics.join(dir).join("bits_per_pixel"));
    if size.as_deref() != Some(&format!("{WIDTH},{HEIGHT}")) || bpp.as_deref() != Some("16") {
        return Err(ScreenError::Wrong(format!(
            "{} at {} bpp",
            size.as_deref().unwrap_or("?"),
            bpp.as_deref().unwrap_or("?")
        )));
    }
    Ok(Screen {
        device: dev.join(dir),
        sole: framebuffers.len() == 1,
    })
}

/// Unbinds the kernel's text console from its framebuffer, so that log lines stop scrolling over a picture.
///
/// Looks at every console in `sys_vtconsole` that is drawn on a framebuffer and is bound,
/// and returns whether it unbound one. A directory that is not there has nothing to unbind.
pub fn detach_console(sys_vtconsole: &Path) -> io::Result<bool> {
    let entries = match fs::read_dir(sys_vtconsole) {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    let mut detached = false;
    for entry in entries {
        let dir = entry?;
        if !dir.file_name().to_string_lossy().starts_with("vtcon") {
            continue;
        }
        let is_framebuffer = read_trimmed(&dir.path().join("name"))
            .is_some_and(|name| name.contains("frame buffer"));
        let bind = dir.path().join("bind");
        if is_framebuffer && read_trimmed(&bind).as_deref() == Some("1") {
            fs::write(&bind, "0")?;
            detached = true;
        }
    }
    Ok(detached)
}

/// The screen's framebuffer, open for drawing.
///
/// It sends to the screen only the rows that changed. Every byte sent crosses a slow bus that
/// the Wi-Fi's interrupts share, so a picture that has not changed costs nothing.
pub struct Framebuffer {
    file: File,
    drawing: Drawing,
}

/// How a framebuffer is drawn on.
enum Drawing {
    /// Through a mapping of the device's memory, which the kernel's driver watches page by page
    /// and sends only the lines of the pages that were touched. (A `write(2)` it treats as a change
    /// to the whole display, whatever the length, and sends everything.)
    ///
    /// The picture is compared with the memory itself, not with a copy of what was shown: whatever
    /// is written there from outside, such as the text console scrolling over the panel, is found
    /// and painted over at the next frame. No copy is kept.
    Mapped {
        mapping: SharedMapping,
        /// Whether a frame has been shown. The first goes out whole, whatever the memory holds,
        /// so that a screen that has just come up is sent a whole picture.
        shown: bool,
    },
    /// By whole frames written to the file, for a device that cannot be mapped.
    Whole {
        /// What the screen shows now, once a frame has been shown. A write that went wrong
        /// leaves it unknown, and the next frame is written whole.
        last: Option<Vec<u8>>,
    },
}

impl Framebuffer {
    /// Opens the device file of a framebuffer for drawing, and maps its memory.
    ///
    /// The device is mapped only if it says that it holds a whole frame in rows of the right
    /// length. A device that cannot be mapped, or says it is smaller, is drawn on a whole frame
    /// at a time, with one warning that gives the reason.
    pub fn open(device: &Path) -> io::Result<Self> {
        // A shared mapping that is written to needs the file open for reading too.
        let file = OpenOptions::new().read(true).write(true).open(device)?;
        let drawing = match SharedMapping::of_framebuffer(&file, FRAME_BYTES, ROW_BYTES) {
            Ok(mapping) => Drawing::Mapped {
                mapping,
                shown: false,
            },
            Err(error) => {
                log::warn!(
                    "panel: {}: no mapping ({error}); writing whole frames",
                    device.display()
                );
                Drawing::Whole { last: None }
            }
        };
        Ok(Self { file, drawing })
    }

    /// Replaces the picture with `frame`, which holds 307,200 bytes of RGB565.
    ///
    /// A frame of any other size is refused before a byte is written. A frame equal to what the
    /// screen holds writes nothing. Of any other, the rows from the first that differs to the
    /// last are written, and the first frame is written whole.
    pub fn show(&mut self, frame: &[u8]) -> io::Result<()> {
        self.draw(frame).map(drop)
    }

    /// Does what `show` does, and tells how many bytes it sent.
    fn draw(&mut self, frame: &[u8]) -> io::Result<usize> {
        if frame.len() != FRAME_BYTES {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("a frame is {FRAME_BYTES} bytes, not {}", frame.len()),
            ));
        }
        match &mut self.drawing {
            Drawing::Mapped { mapping, shown } => {
                let rows = if *shown {
                    mapping.changed_rows(frame, ROW_BYTES)
                } else {
                    Some(0..HEIGHT)
                };
                let Some(rows) = rows else {
                    return Ok(0);
                };
                let bytes = rows.start * ROW_BYTES..rows.end * ROW_BYTES;
                mapping.write(bytes.start, &frame[bytes.clone()])?;
                *shown = true;
                Ok(bytes.len())
            }
            Drawing::Whole { last } => {
                if last.as_deref() == Some(frame) {
                    return Ok(0);
                }
                // What the screen holds is not known again until the write has gone through.
                let mut kept = last.take().unwrap_or_default();
                self.file.write_all_at(frame, 0)?;
                kept.clear();
                kept.extend_from_slice(frame);
                *last = Some(kept);
                Ok(frame.len())
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::fs;
    use std::io::ErrorKind;
    use std::ops::Range;
    use std::path::Path;

    use tempfile::TempDir;

    /// A framebuffer's directory: its name, its driver, its size and its depth.
    pub(crate) type Graphics = (&'static str, &'static str, &'static str, &'static str);

    /// The HDMI output of a Raspberry Pi 3 B+.
    pub(crate) const HDMI: Graphics = ("fb0", "BCM2708 FB", "1920,1080", "32");

    /// A temporary `/sys/class/graphics` holding the given framebuffers, each file ending in
    /// a newline as sysfs writes it, and the empty `fbcon` directory the kernel keeps beside them.
    pub(crate) fn graphics(framebuffers: &[Graphics]) -> TempDir {
        let sys = tempfile::tempdir().unwrap();
        fs::create_dir(sys.path().join("fbcon")).unwrap();
        for (dir, name, size, bpp) in framebuffers {
            let dir = sys.path().join(dir);
            fs::create_dir(&dir).unwrap();
            fs::write(dir.join("name"), format!("{name}\n")).unwrap();
            fs::write(dir.join("virtual_size"), format!("{size}\n")).unwrap();
            fs::write(dir.join("bits_per_pixel"), format!("{bpp}\n")).unwrap();
        }
        sys
    }

    #[test]
    fn the_screen_is_found_by_its_driver_whatever_its_number() {
        let dev = Path::new("/dev");
        let sys = graphics(&[HDMI, ("fb1", "fb_ili9486", "480,320", "16")]);
        assert_eq!(
            find_screen(sys.path(), dev),
            Ok(Screen {
                device: "/dev/fb1".into(),
                sole: false
            })
        );
        let sys = graphics(&[
            ("fb0", "fb_ili9486", "480,320", "16"),
            ("fb1", "BCM2708 FB", "1920,1080", "32"),
        ]);
        assert_eq!(
            find_screen(sys.path(), dev),
            Ok(Screen {
                device: "/dev/fb0".into(),
                sole: false
            })
        );
        let sys = graphics(&[("fb0", "fb_ili9486", "480,320", "16")]);
        assert_eq!(
            find_screen(sys.path(), dev),
            Ok(Screen {
                device: "/dev/fb0".into(),
                sole: true
            })
        );
    }

    #[test]
    fn no_screen_and_a_screen_of_another_shape_are_told_apart_and_no_other_is_taken() {
        let dev = Path::new("/dev");
        assert_eq!(
            find_screen(
                graphics(&[("fb0", "BCM2708 FB", "480,320", "16")]).path(),
                dev
            ),
            Err(ScreenError::Absent)
        );
        assert_eq!(
            find_screen(Path::new("/nonexistent"), dev),
            Err(ScreenError::Absent)
        );
        for (size, bpp, shows) in [("320,480", "16", "320,480"), ("480,320", "32", "32 bpp")] {
            match find_screen(
                graphics(&[HDMI, ("fb1", "fb_ili9486", size, bpp)]).path(),
                dev,
            ) {
                Err(ScreenError::Wrong(found)) => assert!(found.contains(shows), "{found}"),
                other => panic!("{other:?}"),
            }
        }
    }

    /// A temporary file of `len` zero bytes standing in for the device file of a framebuffer.
    fn device(dir: &TempDir, len: usize) -> PathBuf {
        let device = dir.path().join("fb1");
        fs::write(&device, vec![0; len]).unwrap();
        device
    }

    /// A frame of one value, with the rows `rows` of another.
    fn frame_with(fill: u8, rows: Range<usize>, other: u8) -> Vec<u8> {
        let mut frame = vec![fill; FRAME_BYTES];
        frame[rows.start * ROW_BYTES..rows.end * ROW_BYTES].fill(other);
        frame
    }

    #[test]
    fn a_frame_replaces_the_one_before_from_the_first_byte() {
        let dir = tempfile::tempdir().unwrap();
        let device = device(&dir, FRAME_BYTES);
        let mut fb = Framebuffer::open(&device).unwrap();
        fb.show(&vec![0x11; 307_200]).unwrap();
        assert_eq!(fs::read(&device).unwrap(), vec![0x11; 307_200]);
        fb.show(&vec![0x22; 307_200]).unwrap();
        assert_eq!(fs::read(&device).unwrap(), vec![0x22; 307_200]);
        assert_eq!(
            fb.show(&[0; 100]).unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(fs::read(&device).unwrap().len(), 307_200);
    }

    impl Framebuffer {
        /// Whether the screen is drawn on through a mapping.
        fn is_mapped(&self) -> bool {
            matches!(self.drawing, Drawing::Mapped { .. })
        }
    }

    /// Changes the bytes of the device file from outside the framebuffer, as fbcon would.
    fn scribble(device: &Path, at: usize, byte: u8) {
        let other_handle = OpenOptions::new().write(true).open(device).unwrap();
        other_handle.write_all_at(&[byte], at as u64).unwrap();
    }

    #[test]
    fn a_frame_equal_to_the_screens_memory_sends_nothing_and_a_changed_one_only_its_rows() {
        let dir = tempfile::tempdir().unwrap();
        let device = device(&dir, FRAME_BYTES);
        let mut fb = Framebuffer::open(&device).unwrap();
        assert!(fb.is_mapped(), "a device of a frame's size is mapped");
        let a = vec![0x11; FRAME_BYTES];
        assert_eq!(fb.draw(&a).unwrap(), FRAME_BYTES);
        assert_eq!(fs::read(&device).unwrap(), a);

        // The same frame again sends nothing, and the memory is as it was.
        assert_eq!(fb.draw(&a).unwrap(), 0);
        assert_eq!(fs::read(&device).unwrap(), a);

        // A frame that differs in rows 5 and 6 sends those rows and no others.
        let b = frame_with(0x11, 5..7, 0x33);
        assert_eq!(fb.draw(&b).unwrap(), 2 * ROW_BYTES);
        assert_eq!(fs::read(&device).unwrap(), b);

        // Going back sends the same two rows, and then nothing again.
        assert_eq!(fb.draw(&a).unwrap(), 2 * ROW_BYTES);
        assert_eq!(fs::read(&device).unwrap(), a);
        assert_eq!(fb.draw(&a).unwrap(), 0);
    }

    #[test]
    fn the_first_frame_is_sent_whole_even_if_the_screens_memory_already_holds_it() {
        let dir = tempfile::tempdir().unwrap();
        let device = device(&dir, FRAME_BYTES);
        fs::write(&device, vec![0x11; FRAME_BYTES]).unwrap();
        let mut fb = Framebuffer::open(&device).unwrap();
        assert!(fb.is_mapped());
        assert_eq!(fb.draw(&vec![0x11; FRAME_BYTES]).unwrap(), FRAME_BYTES);
        assert_eq!(fb.draw(&vec![0x11; FRAME_BYTES]).unwrap(), 0);
    }

    #[test]
    fn what_was_written_over_the_picture_from_outside_is_repaired_on_the_next_frame() {
        let dir = tempfile::tempdir().unwrap();
        let device = device(&dir, FRAME_BYTES);
        let mut fb = Framebuffer::open(&device).unwrap();
        let a = vec![0x11; FRAME_BYTES];
        fb.draw(&a).unwrap();

        // A byte of row 100 is overwritten, as the console would when it scrolls over the panel.
        let poisoned = 100 * ROW_BYTES + 7;
        scribble(&device, poisoned, 0xee);
        assert_eq!(fs::read(&device).unwrap()[poisoned], 0xee);
        // The very same frame is shown again: row 100 is sent, and no other row.
        assert_eq!(fb.draw(&a).unwrap(), ROW_BYTES);
        assert_eq!(fs::read(&device).unwrap(), a);

        // Two rows far apart, and a frame that differs from the memory in a third row besides:
        // the rows from the first to the last that differ are sent, the ones between with them.
        scribble(&device, 3 * ROW_BYTES, 0xee);
        scribble(&device, 200 * ROW_BYTES + 959, 0xee);
        let b = frame_with(0x11, 5..7, 0x33);
        assert_eq!(fb.draw(&b).unwrap(), (201 - 3) * ROW_BYTES);
        assert_eq!(fs::read(&device).unwrap(), b);
    }

    #[test]
    fn a_screen_that_cannot_be_mapped_gets_whole_changed_frames_and_none_that_are_equal() {
        let dir = tempfile::tempdir().unwrap();
        // A file shorter than a frame is refused as a mapping, as a device that cannot be mapped is.
        let device = device(&dir, 0);
        let mut fb = Framebuffer::open(&device).unwrap();
        assert!(!fb.is_mapped());
        let a = vec![0x11; FRAME_BYTES];
        assert_eq!(fb.draw(&a).unwrap(), FRAME_BYTES);
        assert_eq!(fs::read(&device).unwrap(), a);

        let poisoned = 100 * ROW_BYTES + 7;
        scribble(&device, poisoned, 0xee);
        // An equal frame writes nothing.
        assert_eq!(fb.draw(&a).unwrap(), 0);
        assert_eq!(fs::read(&device).unwrap()[poisoned], 0xee);
        // A changed frame is written whole, the poisoned row with it.
        let b = frame_with(0x11, 5..7, 0x33);
        assert_eq!(fb.draw(&b).unwrap(), FRAME_BYTES);
        assert_eq!(fs::read(&device).unwrap(), b);
    }

    #[test]
    fn a_device_that_cannot_say_what_it_holds_is_drawn_on_a_whole_frame_at_a_time() {
        // `/dev/null` is a character device and no framebuffer: asking it fails, so it is not
        // mapped, and what is written to it goes in whole frames.
        let mut fb = Framebuffer::open(Path::new("/dev/null")).unwrap();
        assert!(!fb.is_mapped());
        let a = vec![0x11; FRAME_BYTES];
        assert_eq!(fb.draw(&a).unwrap(), FRAME_BYTES);
        assert_eq!(fb.draw(&a).unwrap(), 0);
        assert_eq!(fb.draw(&vec![0x22; FRAME_BYTES]).unwrap(), FRAME_BYTES);
    }

    #[test]
    fn only_a_bound_framebuffer_console_is_detached() {
        let sys = tempfile::tempdir().unwrap();
        for (dir, name, bind) in [
            ("vtcon0", "(S) dummy device\n", "0\n"),
            ("vtcon1", "(M) frame buffer device\n", "1\n"),
        ] {
            fs::create_dir(sys.path().join(dir)).unwrap();
            fs::write(sys.path().join(dir).join("name"), name).unwrap();
            fs::write(sys.path().join(dir).join("bind"), bind).unwrap();
        }
        let read = |file: &str| fs::read_to_string(sys.path().join(file)).unwrap();
        assert!(detach_console(sys.path()).unwrap());
        assert_eq!(
            (read("vtcon0/bind"), read("vtcon1/bind")),
            ("0\n".to_owned(), "0".to_owned())
        );
        // Nothing is bound any more.
        assert!(!detach_console(sys.path()).unwrap());
        assert!(!detach_console(Path::new("/nonexistent")).unwrap());
    }
}
