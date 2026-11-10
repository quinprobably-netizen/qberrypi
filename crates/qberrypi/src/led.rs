//! Shows the system's state on the board's activity LED.
//!
//! The kernel exposes the LED as a directory of files. Writing a trigger's
//! name to `trigger` hands the LED to that trigger, and the timer trigger
//! then adds the two files that set its blink.

use std::fs;
use std::io;
use std::path::Path;

/// The activity LED of the Raspberry Pi 3 B+.
pub const LED_DIR: &str = "/sys/class/leds/ACT";

/// What the LED can say about the system.
#[derive(Clone, Copy)]
pub enum LedState {
    /// Up and answering: a slow heartbeat.
    Serving,
    /// Joining the Wi-Fi network: a fast blink.
    Joining,
    /// Stopped by a fatal error: on without a break.
    Fatal,
}

/// Lists the files that show a state, with what to write to each, in order.
pub fn writes(state: LedState) -> &'static [(&'static str, &'static str)] {
    match state {
        LedState::Serving => &[("trigger", "heartbeat")],
        // The trigger comes first: its two files exist only once it is set.
        LedState::Joining => &[
            ("trigger", "timer"),
            ("delay_on", "100"),
            ("delay_off", "100"),
        ],
        LedState::Fatal => &[("trigger", "default-on")],
    }
}

/// Makes the LED in `dir` show a state; stops at the first file that cannot be written.
pub fn set(dir: &Path, state: LedState) -> io::Result<()> {
    for (file, value) in writes(state) {
        fs::write(dir.join(file), value)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::io::ErrorKind;

    #[test]
    fn led_writes_match_the_table() {
        assert_eq!(writes(LedState::Serving), [("trigger", "heartbeat")]);
        assert_eq!(
            writes(LedState::Joining),
            [
                ("trigger", "timer"),
                ("delay_on", "100"),
                ("delay_off", "100")
            ]
        );
        assert_eq!(writes(LedState::Fatal), [("trigger", "default-on")]);
    }

    #[test]
    fn led_set_writes_the_files() {
        let tmp = tempfile::tempdir().unwrap();
        set(tmp.path(), LedState::Joining).unwrap();
        let read = |name| fs::read_to_string(tmp.path().join(name)).unwrap();
        assert_eq!(read("trigger"), "timer");
        assert_eq!(read("delay_on"), "100");
        assert_eq!(read("delay_off"), "100");
    }

    #[test]
    fn led_set_writes_only_what_the_state_needs() {
        let tmp = tempfile::tempdir().unwrap();
        set(tmp.path(), LedState::Fatal).unwrap();
        assert_eq!(
            fs::read_to_string(tmp.path().join("trigger")).unwrap(),
            "default-on"
        );
        assert_eq!(fs::read_dir(tmp.path()).unwrap().count(), 1);
    }

    #[test]
    fn led_set_reports_a_board_without_the_led() {
        let tmp = tempfile::tempdir().unwrap();
        let error = set(&tmp.path().join("absent"), LedState::Serving).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotFound);
    }
}
