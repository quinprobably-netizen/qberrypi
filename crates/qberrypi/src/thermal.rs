//! The board's temperature, as the kernel reports it.

use std::fs;
use std::path::Path;

/// The temperature sensor of the board's processor, in thousandths of a degree Celsius.
pub const BOARD_TEMP: &str = "/sys/class/thermal/thermal_zone0/temp";

/// Reads a temperature file and returns it in whole degrees Celsius, rounded to the nearest.
///
/// A temperature outside the range of an `i8` is held to its nearest end. A file that is
/// missing or does not hold a number gives `None`.
pub fn read_c(file: &Path) -> Option<i8> {
    let millidegrees: i64 = fs::read_to_string(file).ok()?.trim().parse().ok()?;
    let degrees = millidegrees.saturating_add(500).div_euclid(1000);
    Some(degrees.clamp(i8::MIN.into(), i8::MAX.into()) as i8)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::path::Path;

    /// What `read_c` makes of a file holding `text`.
    fn t(text: &str) -> Option<i8> {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("temp");
        fs::write(&file, text).unwrap();
        read_c(&file)
    }

    #[test]
    fn the_board_temperature_is_whole_degrees_or_unknown() {
        assert_eq!(
            (t("42932\n"), t("42499\n"), t("-4600\n"), t("200000\n")),
            (Some(43), Some(42), Some(-5), Some(127))
        );
        assert_eq!(
            (t(""), t("warm\n"), read_c(Path::new("/nonexistent"))),
            (None, None, None)
        );
    }
}
