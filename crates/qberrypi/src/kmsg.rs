//! Reads the kernel's log from `/dev/kmsg`.
//!
//! Each `read` on `/dev/kmsg` returns one record: a header, a `;`, the message
//! line, then any number of ` KEY=value` lines describing the device.

use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Larger than any record the kernel returns; a `read` into less fails.
const RECORD_MAX_BYTES: usize = 8192;

/// One message from the kernel log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmsgLine {
    /// Severity, from 0 (emergency) to 7 (debug).
    pub level: u8,
    /// When the kernel logged it, in microseconds since boot.
    pub micros: u64,
    /// The message itself, without the device details that may follow it.
    pub text: String,
}

/// Parses one `/dev/kmsg` record, or returns `None` if `raw` is not one.
pub fn parse_record(raw: &str) -> Option<KmsgLine> {
    // The header is "priority,sequence,microseconds,flags[,...]".
    let (header, rest) = raw.split_once(';')?;
    let mut fields = header.split(',');
    let priority: u32 = fields.next()?.parse().ok()?;
    let _sequence = fields.next()?;
    let micros = fields.next()?.parse().ok()?;
    let text = rest.split_once('\n').map_or(rest, |(message, _)| message);
    Some(KmsgLine {
        // The priority is the facility times eight, plus the level.
        level: (priority & 7) as u8,
        micros,
        text: text.to_owned(),
    })
}

/// An open, non-blocking source of kernel log records, which remembers how far it has read.
pub struct Reader<S = File> {
    source: S,
}

impl Reader {
    /// Opens the log at `path`, to be read from its oldest record on.
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)?;
        Ok(Self::over(file))
    }
}

impl<S: Read> Reader<S> {
    /// A reader of the records `source` gives, one per `read`.
    fn over(source: S) -> Self {
        Self { source }
    }

    /// Returns the records logged since the last call, without waiting for more.
    pub fn read_new(&mut self) -> io::Result<Vec<KmsgLine>> {
        read_records(&mut self.source)
    }
}

/// Reads one record per `read` until the source has no more to give.
fn read_records(source: &mut impl Read) -> io::Result<Vec<KmsgLine>> {
    let mut lines = Vec::new();
    let mut record = [0u8; RECORD_MAX_BYTES];
    loop {
        match source.read(&mut record) {
            Ok(0) => break,
            Ok(len) => lines.extend(parse_record(&String::from_utf8_lossy(&record[..len]))),
            Err(err) => match err.kind() {
                // Nothing more is waiting.
                ErrorKind::WouldBlock => break,
                // The kernel overwrote records before they were read and has
                // moved on to the oldest one it still holds.
                ErrorKind::BrokenPipe => continue,
                ErrorKind::Interrupted => continue,
                _ => return Err(err),
            },
        }
    }
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use rustix::fs::{CWD, FileType, Mode, mknodat};

    /// A reader that replays a fixed list of `read` results, one per call.
    struct Script(VecDeque<io::Result<&'static str>>);

    impl Read for Script {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.0.pop_front() {
                Some(Ok(text)) => {
                    buf[..text.len()].copy_from_slice(text.as_bytes());
                    Ok(text.len())
                }
                Some(Err(err)) => Err(err),
                None => Ok(0),
            }
        }
    }

    fn os_error(code: i32) -> io::Result<&'static str> {
        Err(io::Error::from_raw_os_error(code))
    }

    /// A path for a file that only the named test of this process uses.
    fn temp_path(test: &str) -> PathBuf {
        std::env::temp_dir().join(format!("qberrypi-kmsg-{test}-{}", std::process::id()))
    }

    fn texts(lines: &[KmsgLine]) -> Vec<&str> {
        lines.iter().map(|line| line.text.as_str()).collect()
    }

    #[test]
    fn kmsg_record_is_parsed() {
        let l = parse_record("6,1234,5678901,-;brcmfmac: F1 signature read").unwrap();
        assert_eq!(
            (l.level, l.micros, l.text.as_str()),
            (6, 5678901, "brcmfmac: F1 signature read")
        );
        assert!(parse_record(" SUBSYSTEM=sdio").is_none());
        assert!(parse_record("garbage").is_none());
    }

    #[test]
    fn level_is_the_low_three_bits_of_the_first_field() {
        // 30 is facility 3 (daemon), level 6 (info).
        assert_eq!(parse_record("30,1,2,-;x").unwrap().level, 6);
        assert_eq!(parse_record("3,1,2,-;x").unwrap().level, 3);
    }

    #[test]
    fn only_the_message_line_of_a_record_is_kept() {
        let raw = "4,10,20,-,caller=T1;usb 1-1: new device; ok\n SUBSYSTEM=usb\n DEVICE=c189:1\n";
        let l = parse_record(raw).unwrap();
        assert_eq!(
            (l.level, l.micros, l.text.as_str()),
            (4, 20, "usb 1-1: new device; ok")
        );
    }

    #[test]
    fn a_record_with_a_malformed_header_is_rejected() {
        assert!(parse_record("x,1,2,-;text").is_none());
        assert!(parse_record("6,1,soon,-;text").is_none());
        assert!(parse_record("6,1;text").is_none());
        assert!(parse_record("").is_none());
    }

    #[test]
    fn reading_stops_at_would_block() {
        let mut script = Script(VecDeque::from([
            Ok("6,1,100,-;first\n"),
            Ok("5,2,200,-;second\n SUBSYSTEM=sdio\n"),
            os_error(libc::EAGAIN),
            Ok("6,3,300,-;never read\n"),
        ]));
        let lines = read_records(&mut script).unwrap();
        assert_eq!(texts(&lines), ["first", "second"]);
    }

    #[test]
    fn reading_stops_at_end_of_file() {
        let mut script = Script(VecDeque::from([Ok("6,1,100,-;only\n")]));
        assert_eq!(texts(&read_records(&mut script).unwrap()), ["only"]);
    }

    #[test]
    fn overwritten_records_are_skipped() {
        let mut script = Script(VecDeque::from([
            os_error(libc::EPIPE),
            Ok("6,7,100,-;after the gap\n"),
            os_error(libc::EINTR),
            os_error(libc::EPIPE),
            Ok("6,9,200,-;after another\n"),
            os_error(libc::EAGAIN),
        ]));
        let lines = read_records(&mut script).unwrap();
        assert_eq!(texts(&lines), ["after the gap", "after another"]);
    }

    #[test]
    fn a_reader_returns_each_record_once() {
        let mut reader = Reader::over(Script(VecDeque::from([
            Ok("6,1,10,-;a"),
            os_error(libc::EAGAIN),
            Ok("6,2,20,-;b"),
            os_error(libc::EAGAIN),
            os_error(libc::EAGAIN),
        ])));
        assert_eq!(texts(&reader.read_new().unwrap()), ["a"]);
        assert_eq!(texts(&reader.read_new().unwrap()), ["b"]);
        assert_eq!(texts(&reader.read_new().unwrap()), [""; 0]);
    }

    #[test]
    fn a_reader_opened_on_a_file_sees_what_is_appended_to_it() {
        let path = temp_path("reader");
        std::fs::write(&path, "6,1,10,-;first\n").unwrap();
        let mut reader = Reader::open(&path).unwrap();
        let first = reader.read_new().unwrap();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"6,2,20,-;second\n").unwrap();
        let second = reader.read_new().unwrap();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(texts(&first), ["first"]);
        assert_eq!(texts(&second), ["second"]);
    }

    #[test]
    fn any_other_read_error_is_returned() {
        let mut script = Script(VecDeque::from([
            Ok("6,1,100,-;first\n"),
            os_error(libc::EINVAL),
        ]));
        let err = read_records(&mut script).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
    }

    #[test]
    fn a_reader_reads_a_record_from_an_ordinary_file() {
        let path = temp_path("file");
        std::fs::write(&path, "6,1234,5678901,-;brcmfmac: F1 signature read\n").unwrap();
        let result = Reader::open(&path).unwrap().read_new();
        std::fs::remove_file(&path).unwrap();

        let lines = result.unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(
            (lines[0].level, lines[0].micros, lines[0].text.as_str()),
            (6, 5678901, "brcmfmac: F1 signature read")
        );
    }

    #[test]
    fn a_reader_does_not_wait_for_more_records() {
        // A FIFO with a writer attached behaves as `/dev/kmsg` does once it
        // has been read to the end: a blocking read would wait for more.
        let path = temp_path("fifo");
        mknodat(CWD, &path, FileType::Fifo, Mode::RUSR | Mode::WUSR, 0).unwrap();
        let mut writer = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        writer.write_all(b"6,1,100,-;only\n").unwrap();

        let (done, outcome) = mpsc::channel();
        let reader_path = path.clone();
        thread::spawn(move || done.send(Reader::open(&reader_path).and_then(|mut r| r.read_new())));
        let outcome = outcome.recv_timeout(Duration::from_secs(5));
        std::fs::remove_file(&path).unwrap();

        let lines = outcome
            .expect("the reader waited for more records")
            .unwrap();
        assert_eq!(texts(&lines), ["only"]);
    }

    #[test]
    fn a_reader_reports_a_path_it_cannot_open() {
        let path = Path::new("/nonexistent/qberrypi-kmsg-test");
        let error = Reader::open(path).err().expect("there is no such file");
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }
}
