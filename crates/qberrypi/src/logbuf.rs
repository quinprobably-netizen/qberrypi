//! The system's log: a bounded in-memory buffer that backs the `log` crate.
//!
//! Every record is written to the console as it happens and kept in memory,
//! so that the boot sequence can later save the log to the SD card.

use std::collections::VecDeque;
use std::fmt;
use std::io::Write;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Instant;

use log::{Level, LevelFilter, Log, Metadata, Record};

/// How many bytes of log text the system keeps in memory.
pub const LOG_CAP_BYTES: usize = 256 * 1024;

/// The most recent log lines, held within a fixed number of bytes.
///
/// A line costs its own length plus one byte for its newline. When a new line
/// does not fit, the oldest lines are discarded to make room.
pub struct LogBuf {
    lines: VecDeque<String>,
    /// What the stored lines cost together; never more than `cap_bytes`.
    bytes: usize,
    cap_bytes: usize,
    /// How many of the newest lines `take_unsaved` has not yet returned.
    unsaved: usize,
    /// Whether `take_unsaved` has been called.
    taken: bool,
    dropped: u64,
}

impl LogBuf {
    /// Makes an empty buffer that holds at most `cap_bytes` of text.
    pub fn new(cap_bytes: usize) -> Self {
        Self {
            lines: VecDeque::new(),
            bytes: 0,
            cap_bytes,
            unsaved: 0,
            taken: false,
            dropped: 0,
        }
    }

    /// Adds a line, discarding the oldest lines if it would not fit.
    ///
    /// A line too long to fit even in an empty buffer is cut short, at a
    /// character boundary, to the longest prefix that does fit.
    pub fn push(&mut self, line: &str) {
        let Some(longest) = self.cap_bytes.checked_sub(1) else {
            // Not even a newline fits, so nothing can be kept.
            self.dropped += 1;
            return;
        };
        let line = &line[..line.floor_char_boundary(longest)];
        let cost = line.len() + 1;
        while self.bytes + cost > self.cap_bytes
            && let Some(oldest) = self.lines.pop_front()
        {
            self.bytes -= oldest.len() + 1;
            self.dropped += 1;
        }
        // A discarded line that was never taken is no longer waiting.
        self.unsaved = self.unsaved.min(self.lines.len()) + 1;
        self.bytes += cost;
        self.lines.push_back(line.to_owned());
    }

    /// Returns the lines pushed since the previous call, each ending in a newline.
    pub fn take_unsaved(&mut self) -> String {
        let first = self.lines.len() - self.unsaved;
        let mut text = String::new();
        for line in self.lines.range(first..) {
            text.push_str(line);
            text.push('\n');
        }
        self.unsaved = 0;
        self.taken = true;
        text
    }

    /// Whether `take_unsaved` has been called: what it returns next is not the start of the log.
    pub fn taken(&self) -> bool {
        self.taken
    }

    /// How many lines have been discarded to stay under the cap.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

/// Makes this module the `log` backend and returns the buffer it fills.
///
/// Every record goes to `console` and to the buffer as
/// `[{secs:>8.3}] {LEVEL:<5} {message}`, with the seconds counted from this
/// call. Do not log while holding the buffer's lock. Only the first call has
/// an effect; a later one returns the same buffer and discards its console.
pub fn install(console: Box<dyn Write + Send>) -> &'static Mutex<LogBuf> {
    static LOGGER: OnceLock<Logger> = OnceLock::new();
    let logger = LOGGER.get_or_init(|| Logger::new(console, LOG_CAP_BYTES));
    // Fails only if a logger is already set, which leaves nothing to do.
    let _ = log::set_logger(logger);
    log::set_max_level(LevelFilter::Trace);
    &logger.buf
}

/// The `log` backend: a console, the buffer, and the moment logging began.
struct Logger {
    start: Instant,
    console: Mutex<Box<dyn Write + Send>>,
    buf: Mutex<LogBuf>,
}

impl Logger {
    fn new(console: Box<dyn Write + Send>, cap_bytes: usize) -> Self {
        Self {
            start: Instant::now(),
            console: Mutex::new(console),
            buf: Mutex::new(LogBuf::new(cap_bytes)),
        }
    }
}

impl Log for Logger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let secs = self.start.elapsed().as_secs_f64();
        let mut line = format_line(secs, record.level(), record.args());
        // Holding the console across both keeps their lines in the same order.
        let mut console = lock(&self.console);
        lock(&self.buf).push(&line);
        // One write per line, so kernel messages cannot land in the middle of
        // it. A console that has gone away must not stop the system logging.
        line.push('\n');
        let _ = console.write_all(line.as_bytes());
        let _ = console.flush();
    }

    fn flush(&self) {
        let _ = lock(&self.console).flush();
    }
}

/// Lays out one log line: seconds since logging began, level, message.
fn format_line(secs: f64, level: Level, message: impl fmt::Display) -> String {
    format!("[{secs:>8.3}] {level:<5} {message}")
}

/// Locks a mutex whether or not a thread panicked while holding it.
fn lock<T: ?Sized>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io;
    use std::sync::Arc;

    use log::{Level, Log, Record};

    /// A console that keeps what was written, readable from the test.
    #[derive(Clone, Default)]
    struct SharedConsole(Arc<Mutex<Vec<u8>>>);

    impl SharedConsole {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl Write for SharedConsole {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A console that has gone away: every write and flush fails.
    struct DeadConsole;

    impl Write for DeadConsole {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            Err(io::Error::from_raw_os_error(libc::EIO))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from_raw_os_error(libc::EIO))
        }
    }

    fn emit(logger: &Logger, level: Level, message: &str) {
        logger.log(
            &Record::builder()
                .level(level)
                .args(format_args!("{message}"))
                .build(),
        );
    }

    #[test]
    fn oldest_lines_are_dropped_at_the_cap() {
        let mut b = LogBuf::new(64);
        for i in 0..10 {
            b.push(&format!("line number {i:02}"));
        }
        let text = b.take_unsaved();
        assert!(
            text.len() <= 64
                && text.ends_with("line number 09\n")
                && !text.contains("line number 00")
        );
        assert!(b.dropped() > 0);
    }

    #[test]
    fn the_buffer_knows_whether_its_lines_were_taken_before() {
        let mut b = LogBuf::new(1024);
        assert!(!b.taken());
        b.push("a");
        assert!(!b.taken());
        assert_eq!(b.take_unsaved(), "a\n");
        assert!(b.taken());
        b.push("b");
        assert!(b.taken());
    }

    #[test]
    fn take_unsaved_returns_each_line_once() {
        let mut b = LogBuf::new(1024);
        b.push("a");
        assert_eq!(b.take_unsaved(), "a\n");
        b.push("b");
        assert_eq!(b.take_unsaved(), "b\n");
        assert_eq!(b.take_unsaved(), "");
    }

    #[test]
    fn take_unsaved_returns_each_line_once_across_drops() {
        // Each line is two bytes plus its newline, so the buffer holds two.
        let mut b = LogBuf::new(6);
        b.push("l0");
        assert_eq!(b.take_unsaved(), "l0\n");

        // Dropping a line that was already taken loses nothing.
        b.push("l1");
        b.push("l2");
        assert_eq!(b.dropped(), 1);
        assert_eq!(b.take_unsaved(), "l1\nl2\n");

        // l3 is dropped before it was ever taken; it is lost, not repeated.
        b.push("l3");
        b.push("l4");
        b.push("l5");
        assert_eq!(b.dropped(), 4);
        assert_eq!(b.take_unsaved(), "l4\nl5\n");

        // One taken line dropped, one taken line kept: only the new one.
        b.push("l6");
        assert_eq!(b.dropped(), 5);
        assert_eq!(b.take_unsaved(), "l6\n");
        assert_eq!(b.take_unsaved(), "");
    }

    #[test]
    fn a_line_longer_than_the_cap_is_truncated() {
        let mut b = LogBuf::new(8);
        b.push("ab");
        b.push("0123456789");
        assert_eq!(b.take_unsaved(), "0123456\n");
        assert_eq!(b.dropped(), 1);

        // A following line still fits by dropping the truncated one.
        b.push("cd");
        assert_eq!(b.take_unsaved(), "cd\n");
        assert_eq!(b.dropped(), 2);
    }

    #[test]
    fn truncation_never_splits_a_character() {
        let mut b = LogBuf::new(8);
        // Seven bytes fit; the seventh would be the first half of "é".
        b.push("aaaaaaé");
        assert_eq!(b.take_unsaved(), "aaaaaa\n");
    }

    #[test]
    fn a_zero_cap_keeps_nothing() {
        let mut b = LogBuf::new(0);
        b.push("x");
        assert_eq!(b.take_unsaved(), "");
        assert_eq!(b.dropped(), 1);
    }

    #[test]
    fn line_format_aligns_seconds_and_level() {
        let line = |secs, level| format_line(secs, level, "msg");
        assert_eq!(line(0.0, Level::Info), "[   0.000] INFO  msg");
        assert_eq!(line(1.5, Level::Warn), "[   1.500] WARN  msg");
        assert_eq!(line(12.3456, Level::Error), "[  12.346] ERROR msg");
        assert_eq!(line(1234.5, Level::Debug), "[1234.500] DEBUG msg");
        assert_eq!(line(123456.0, Level::Trace), "[123456.000] TRACE msg");
    }

    #[test]
    fn a_record_goes_to_the_console_and_the_buffer() {
        let console = SharedConsole::default();
        let logger = Logger::new(Box::new(console.clone()), 1024);
        emit(&logger, Level::Warn, "watchdog missing");
        emit(&logger, Level::Info, "wlan0: present");

        let saved = logger.buf.lock().unwrap().take_unsaved();
        assert_eq!(console.text(), saved);
        let lines: Vec<&str> = saved.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("[   0.") && lines[0].ends_with("] WARN  watchdog missing"));
        assert!(lines[1].starts_with("[   0.") && lines[1].ends_with("] INFO  wlan0: present"));
    }

    #[test]
    fn a_console_error_is_ignored() {
        let logger = Logger::new(Box::new(DeadConsole), 1024);
        emit(&logger, Level::Error, "still recorded");
        logger.flush();
        let saved = logger.buf.lock().unwrap().take_unsaved();
        assert!(saved.ends_with("] ERROR still recorded\n"));
    }

    #[test]
    fn install_routes_the_log_macros_to_the_buffer() {
        let console = SharedConsole::default();
        let buf = install(Box::new(console.clone()));
        log::info!("installed {}", 1);

        // Other tests may log through the same global logger, so look for the
        // line rather than expecting it to be the only one.
        let is_ours = |line: &str| line.starts_with('[') && line.ends_with("] INFO  installed 1");
        assert!(buf.lock().unwrap().take_unsaved().lines().any(is_ours));
        assert!(console.text().lines().any(is_ours));
    }
}
