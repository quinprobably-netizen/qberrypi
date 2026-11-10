//! Reads and writes the files qberrypi keeps on the shared boot partition.
//!
//! Every function takes the directory where the partition is already mounted.
//! Which system starts next is decided by `config.txt` there, so the restore
//! changes nothing unless it has a backup worth restoring.

use std::fs::{self, File};
use std::io::{self, ErrorKind, Write};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

/// The block device that holds the boot partition.
pub const BOOT_DEV: &str = "/dev/mmcblk0p1";

/// Where the boot partition is mounted.
pub const MOUNT_POINT: &str = "/boot";

/// The size beyond which the log file on the card is started afresh.
pub const LOG_FILE_CAP: u64 = 1024 * 1024;

/// The configuration the firmware reads; it decides which system starts.
const ACTIVE_CONFIG: &str = "config.txt";
/// The saved copy of Raspberry Pi OS's configuration.
const PIOS_CONFIG: &str = "config.pios.txt";
/// The folder that holds qberrypi's own files.
const OWN_DIR: &str = "qberrypi";
const CONFIG_TEXT: &str = "qberrypi.toml";
const LOG_FILE: &str = "log.txt";

/// What a boot's header in the log has before the build time and after it.
const BOOT_HEADER_START: &str = "==== boot, build ";
const BOOT_HEADER_END: &str = " ====";

/// The setting that makes the firmware start qberrypi.
const SELECTS_QBERRYPI: &[u8] = b"os_prefix=qberrypi/";

/// How often `wait_for_path` looks for the path.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// What `restore_pios_config` did, or why it changed nothing.
#[derive(Debug, PartialEq)]
pub enum Restore {
    /// `config.txt` now holds the saved Raspberry Pi OS configuration.
    Restored,
    /// `config.txt` already held it, so nothing was written.
    AlreadyRestored,
    /// The backup is not worth restoring, for the reason given; nothing was written.
    Refused(&'static str),
}

/// Copies `config.pios.txt` over `config.txt`, so the next start is Raspberry Pi OS.
///
/// The backup is read and judged in full before `config.txt` is touched, and
/// is itself never written. It is refused, with nothing changed, when it:
///
/// - does not exist: `"config.pios.txt is missing"`;
/// - holds nothing but whitespace: `"config.pios.txt is empty"`;
/// - contains a NUL byte: `"config.pios.txt is not text"`;
/// - has an uncommented line starting with `os_prefix=qberrypi/`:
///   `"config.pios.txt selects qberrypi"`.
///
/// An error from reading either file is returned with nothing changed.
pub fn restore_pios_config(boot: &Path) -> io::Result<Restore> {
    let backup = match fs::read(boot.join(PIOS_CONFIG)) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Ok(Restore::Refused("config.pios.txt is missing"));
        }
        Err(error) => return Err(error),
    };
    if backup.trim_ascii().is_empty() {
        return Ok(Restore::Refused("config.pios.txt is empty"));
    }
    // An interrupted write on FAT can leave a file of the right size whose
    // data reads back as NUL bytes; restoring that would blank config.txt.
    if backup.contains(&0) {
        return Ok(Restore::Refused("config.pios.txt is not text"));
    }
    if selects_qberrypi(&backup) {
        return Ok(Restore::Refused("config.pios.txt selects qberrypi"));
    }

    let active = boot.join(ACTIVE_CONFIG);
    match fs::read(&active) {
        Ok(current) if current == backup => return Ok(Restore::AlreadyRestored),
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    // The file is overwritten where it lies. Renaming a finished copy into
    // place is not atomic on FAT and would leave a moment with no config.txt.
    // Opened without truncation, so the file is never zero-length on the way:
    // the new bytes go over the old ones, and only then is any old tail cut off.
    let mut file = File::options()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&active)?;
    file.write_all(&backup)?;
    file.set_len(backup.len() as u64)?;
    file.sync_all()?;
    Ok(Restore::Restored)
}

/// Whether a configuration has an uncommented line that selects qberrypi.
fn selects_qberrypi(config: &[u8]) -> bool {
    // A comment starts with `#`, so it can never start with the setting.
    config
        .split(|&byte| byte == b'\n')
        .any(|line| line.trim_ascii_start().starts_with(SELECTS_QBERRYPI))
}

/// Reads `qberrypi/qberrypi.toml`, the system's configuration file.
pub fn read_config_text(boot: &Path) -> io::Result<String> {
    fs::read_to_string(boot.join(OWN_DIR).join(CONFIG_TEXT))
}

/// Adds text to the end of `qberrypi/log.txt` and waits until it is on the card.
///
/// A log already larger than `LOG_FILE_CAP` is emptied first, but only for
/// text that starts a boot, with `boot_header`: a boot saves its log in
/// several pieces, and none of them may be cut off from its header. The
/// `qberrypi` folder is made if it is missing; the mount point itself never is.
pub fn append_log(boot: &Path, text: &str) -> io::Result<()> {
    let dir = boot.join(OWN_DIR);
    match fs::create_dir(&dir) {
        Err(error) if error.kind() != ErrorKind::AlreadyExists => return Err(error),
        _ => {}
    }
    let mut file = File::options()
        .append(true)
        .create(true)
        .open(dir.join(LOG_FILE))?;
    if text.starts_with(BOOT_HEADER_START) && file.metadata()?.len() > LOG_FILE_CAP {
        file.set_len(0)?;
    }
    file.write_all(text.as_bytes())?;
    file.sync_all()
}

/// The line that starts a boot's entry in `qberrypi/log.txt`: it names the build that booted.
pub fn boot_header(build_epoch: u64) -> String {
    format!("{BOOT_HEADER_START}{build_epoch}{BOOT_HEADER_END}\n")
}

/// Reads from the text of `qberrypi/log.txt` which build its last boot was of.
///
/// `None` if the log has no header, or if its last header names no build.
pub fn last_boot_build(log: &str) -> Option<u64> {
    let header = log
        .lines()
        .rev()
        .find(|line| line.starts_with(BOOT_HEADER_START))?;
    let build = header
        .strip_prefix(BOOT_HEADER_START)?
        .strip_suffix(BOOT_HEADER_END)?;
    // `parse` alone would take a sign.
    if !build.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    build.parse().ok()
}

/// Waits for a path to exist, such as a device the kernel has yet to find.
///
/// Returns whether it exists. The path is looked for at once and then every
/// 50 ms, with a last look when the timeout has passed.
pub fn wait_for_path(path: &Path, timeout: Duration) -> bool {
    let start = Instant::now();
    loop {
        if path.exists() {
            return true;
        }
        let left = timeout.saturating_sub(start.elapsed());
        if left.is_zero() {
            return false;
        }
        thread::sleep(left.min(POLL_INTERVAL));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::{self, File};
    use std::io::ErrorKind;
    use std::path::Path;
    use std::thread;
    use std::time::{Duration, Instant, SystemTime};

    const ACTIVE: &str = "config.txt";
    const BACKUP: &str = "config.pios.txt";
    const LOG: &str = "qberrypi/log.txt";

    fn read(dir: &Path, name: &str) -> String {
        fs::read_to_string(dir.join(name)).unwrap()
    }

    fn write(dir: &Path, name: &str, bytes: impl AsRef<[u8]>) {
        fs::write(dir.join(name), bytes).unwrap();
    }

    /// Runs the restore and checks that it left the backup exactly as it was.
    fn restore(dir: &Path) -> Restore {
        let before = fs::read(dir.join(BACKUP)).ok();
        let outcome = restore_pios_config(dir).unwrap();
        let after = fs::read(dir.join(BACKUP)).ok();
        assert_eq!(after, before, "the restore changed config.pios.txt");
        outcome
    }

    /// Gives a file a modification time far in the past and returns that time.
    fn backdate(path: &Path) -> SystemTime {
        let long_ago = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        let file = File::options().write(true).open(path).unwrap();
        file.set_modified(long_ago).unwrap();
        long_ago
    }

    fn modified(path: &Path) -> SystemTime {
        fs::metadata(path).unwrap().modified().unwrap()
    }

    #[test]
    fn restores_and_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        write(d, ACTIVE, "os_prefix=qberrypi/\n");
        write(d, BACKUP, "arm_64bit=1\n");
        assert_eq!(restore(d), Restore::Restored);
        assert_eq!(read(d, "config.txt"), "arm_64bit=1\n");
        assert_eq!(restore(d), Restore::AlreadyRestored);
        assert_eq!(read(d, "config.txt"), "arm_64bit=1\n");
    }

    #[test]
    fn refuses_and_leaves_config_untouched() {
        for (backup, reason) in [
            (None, "config.pios.txt is missing"),
            (Some(""), "config.pios.txt is empty"),
            (
                Some("arm_64bit=1\nos_prefix=qberrypi/\n"),
                "config.pios.txt selects qberrypi",
            ),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let d = tmp.path();
            write(d, ACTIVE, "ORIGINAL\n");
            if let Some(backup) = backup {
                write(d, BACKUP, backup);
            }
            let long_ago = backdate(&d.join(ACTIVE));
            assert_eq!(restore(d), Restore::Refused(reason));
            assert_eq!(read(d, "config.txt"), "ORIGINAL\n");
            assert_eq!(modified(&d.join(ACTIVE)), long_ago, "{reason}");
        }
    }

    #[test]
    fn commented_os_prefix_in_backup_is_fine() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let backup = "#os_prefix=qberrypi/\n  # os_prefix=qberrypi/\narm_64bit=1\n";
        write(d, ACTIVE, "os_prefix=qberrypi/\n");
        write(d, BACKUP, backup);
        assert_eq!(restore(d), Restore::Restored);
        assert_eq!(read(d, "config.txt"), backup);
    }

    #[test]
    fn another_os_prefix_in_backup_is_fine() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let backup = "os_prefix=pios/\nx_os_prefix=qberrypi/\n";
        write(d, ACTIVE, "os_prefix=qberrypi/\n");
        write(d, BACKUP, backup);
        assert_eq!(restore(d), Restore::Restored);
        assert_eq!(read(d, "config.txt"), backup);
    }

    #[test]
    fn whitespace_only_backup_is_refused_as_empty() {
        for backup in ["\n", " ", " \t\r\n\n  \n"] {
            let tmp = tempfile::tempdir().unwrap();
            let d = tmp.path();
            write(d, ACTIVE, "ORIGINAL\n");
            write(d, BACKUP, backup);
            assert_eq!(restore(d), Restore::Refused("config.pios.txt is empty"));
            assert_eq!(read(d, "config.txt"), "ORIGINAL\n");
        }
    }

    #[test]
    fn indented_os_prefix_in_backup_is_refused() {
        for backup in [
            "arm_64bit=1\n \tos_prefix=qberrypi/\n",
            "  os_prefix=qberrypi/",
            "arm_64bit=1\r\nos_prefix=qberrypi/\r\n",
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let d = tmp.path();
            write(d, ACTIVE, "ORIGINAL\n");
            write(d, BACKUP, backup);
            assert_eq!(
                restore(d),
                Restore::Refused("config.pios.txt selects qberrypi"),
                "{backup:?}"
            );
            assert_eq!(read(d, "config.txt"), "ORIGINAL\n");
        }
    }

    #[test]
    fn missing_config_is_created_from_the_backup() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        write(d, BACKUP, "arm_64bit=1\n");
        assert_eq!(restore(d), Restore::Restored);
        assert_eq!(read(d, "config.txt"), "arm_64bit=1\n");
    }

    #[test]
    fn non_utf8_backup_is_restored_byte_for_byte() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let backup = b"# caf\xe9 \xff\xfe\narm_64bit=1\n";
        write(d, ACTIVE, "os_prefix=qberrypi/\n");
        write(d, BACKUP, backup);
        assert_eq!(restore(d), Restore::Restored);
        assert_eq!(fs::read(d.join(ACTIVE)).unwrap(), backup);
        assert_eq!(restore(d), Restore::AlreadyRestored);
    }

    #[test]
    fn non_utf8_backup_that_selects_qberrypi_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        write(d, ACTIVE, "ORIGINAL\n");
        write(d, BACKUP, b"# \xff\xfe\nos_prefix=qberrypi/\n");
        assert_eq!(
            restore(d),
            Restore::Refused("config.pios.txt selects qberrypi")
        );
        assert_eq!(read(d, "config.txt"), "ORIGINAL\n");
    }

    #[test]
    fn backup_with_a_nul_byte_is_refused_as_not_text() {
        for (case, backup) in [
            // What an interrupted write can leave: the right size, no data.
            ("all NULs", &[0u8; 512][..]),
            ("one NUL in text", b"arm_64bit=1\ndtparam=au\0dio=on\n"),
            // Checked before the setting is looked for.
            ("NUL and the setting", b"os_prefix=qberrypi/\n\0"),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let d = tmp.path();
            write(d, ACTIVE, "ORIGINAL\n");
            write(d, BACKUP, backup);
            let long_ago = backdate(&d.join(ACTIVE));
            assert_eq!(
                restore(d),
                Restore::Refused("config.pios.txt is not text"),
                "{case}"
            );
            assert_eq!(fs::read(d.join(ACTIVE)).unwrap(), b"ORIGINAL\n");
            assert_eq!(modified(&d.join(ACTIVE)), long_ago);
        }
    }

    #[test]
    fn already_restored_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        write(d, ACTIVE, "arm_64bit=1\n");
        write(d, BACKUP, "arm_64bit=1\n");
        let long_ago = backdate(&d.join(ACTIVE));
        assert_eq!(restore(d), Restore::AlreadyRestored);
        assert_eq!(modified(&d.join(ACTIVE)), long_ago);
    }

    #[test]
    fn an_unreadable_backup_is_an_error_and_changes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        write(d, ACTIVE, "ORIGINAL\n");
        // A directory where the backup should be can be neither read nor restored.
        fs::create_dir(d.join(BACKUP)).unwrap();
        assert!(restore_pios_config(d).is_err());
        assert_eq!(read(d, "config.txt"), "ORIGINAL\n");
        assert!(d.join(BACKUP).is_dir());
    }

    #[test]
    fn reads_the_config_text() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        fs::create_dir(d.join("qberrypi")).unwrap();
        write(d, "qberrypi/qberrypi.toml", "hostname = \"example\"\n");
        assert_eq!(read_config_text(d).unwrap(), "hostname = \"example\"\n");
    }

    #[test]
    fn a_missing_config_text_is_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let error = read_config_text(tmp.path()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotFound);
    }

    #[test]
    fn a_non_utf8_config_text_is_invalid_data() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        fs::create_dir(d.join("qberrypi")).unwrap();
        write(d, "qberrypi/qberrypi.toml", b"hostname = \"\xff\"\n");
        let error = read_config_text(d).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn log_appends_then_starts_afresh_over_the_cap() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        append_log(d, "one\n").unwrap();
        append_log(d, "two\n").unwrap();
        assert_eq!(read(d, "qberrypi/log.txt"), "one\ntwo\n");
        write(d, LOG, vec![b'x'; LOG_FILE_CAP as usize + 1]);
        let first_of_a_boot = boot_header(5) + "three\n";
        append_log(d, &first_of_a_boot).unwrap();
        assert_eq!(read(d, "qberrypi/log.txt"), first_of_a_boot);
    }

    #[test]
    fn a_log_over_the_cap_is_not_started_afresh_in_the_middle_of_a_boot() {
        // A boot saves its log several times under one header. If a later
        // save emptied the file, what is left would be the end of a boot with
        // nothing to say which build it was.
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let first_of_a_boot = boot_header(5) + "banner\n";
        append_log(d, &first_of_a_boot).unwrap();
        let grown = first_of_a_boot + &"x".repeat(LOG_FILE_CAP as usize);
        write(d, LOG, &grown);

        append_log(d, "returning\n").unwrap();

        // Compared by parts: a megabyte in a failure message helps no one.
        let after = read(d, LOG);
        assert_eq!(after.len(), grown.len() + "returning\n".len());
        assert!(after.starts_with(&boot_header(5)));
        assert!(after.ends_with("xreturning\n"));
    }

    #[test]
    fn a_boot_header_names_the_build_and_reads_back() {
        assert_eq!(
            boot_header(1_700_000_000),
            "==== boot, build 1700000000 ====\n"
        );
        assert_eq!(
            last_boot_build(&boot_header(1_700_000_000)),
            Some(1_700_000_000)
        );
        assert_eq!(last_boot_build(&boot_header(u64::MAX)), Some(u64::MAX));
    }

    #[test]
    fn the_last_boot_of_a_log_is_the_one_of_its_last_header() {
        let two_boots = format!("{}a\n{}b\nc\n", boot_header(1), boot_header(2));
        assert_eq!(last_boot_build(&two_boots), Some(2));
        // A file that lost its newlines' partners on another system still reads.
        assert_eq!(last_boot_build(&two_boots.replace('\n', "\r\n")), Some(2));
        assert_eq!(last_boot_build("a\nb\n"), None);
        assert_eq!(last_boot_build(""), None);
    }

    #[test]
    fn a_header_is_a_whole_line_and_a_damaged_last_one_is_not_passed_over() {
        // A kernel message that quotes a header is not one.
        let quoted = "[   1.000] INFO  kernel: ==== boot, build 5 ====\n";
        assert_eq!(last_boot_build(quoted), None);
        // Nor is the log then taken for the boot before.
        for damaged in [
            "==== boot, build x ====",
            "==== boot, build  ====",
            "==== boot, build 3",
            "==== boot, build 3 ==== and more",
            "==== boot, build -3 ====",
        ] {
            let log = format!("{}a\n{damaged}\nb\n", boot_header(1));
            assert_eq!(last_boot_build(&log), None, "{damaged}");
        }
    }

    #[test]
    fn log_at_exactly_the_cap_still_appends() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        fs::create_dir(d.join("qberrypi")).unwrap();
        write(d, LOG, vec![b'x'; LOG_FILE_CAP as usize]);
        append_log(d, "more\n").unwrap();
        let text = read(d, LOG);
        assert_eq!(text.len() as u64, LOG_FILE_CAP + 5);
        assert!(text.ends_with("xmore\n"));
    }

    #[test]
    fn log_does_not_create_the_mount_point() {
        let tmp = tempfile::tempdir().unwrap();
        let absent = tmp.path().join("absent");
        assert!(append_log(&absent, "one\n").is_err());
        assert!(!absent.exists());
    }

    #[test]
    fn wait_for_path_sees_a_late_file_and_times_out_on_a_missing_one() {
        let tmp = tempfile::tempdir().unwrap();
        let late = tmp.path().join("late");
        let start = Instant::now();
        let creator = thread::spawn({
            let late = late.clone();
            move || {
                thread::sleep(Duration::from_millis(150));
                File::create(late).unwrap();
            }
        });
        assert!(wait_for_path(&late, Duration::from_secs(2)));
        let waited = start.elapsed();
        assert!(waited >= Duration::from_millis(150) && waited < Duration::from_secs(2));
        creator.join().unwrap();

        let never = tmp.path().join("never");
        let start = Instant::now();
        assert!(!wait_for_path(&never, Duration::from_millis(200)));
        assert!(start.elapsed() >= Duration::from_millis(200));
    }

    #[test]
    fn wait_for_path_returns_at_once_for_an_existing_path() {
        let tmp = tempfile::tempdir().unwrap();
        let start = Instant::now();
        assert!(wait_for_path(tmp.path(), Duration::from_secs(60)));
        assert!(wait_for_path(tmp.path(), Duration::ZERO));
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn wait_for_path_with_no_timeout_checks_once() {
        let tmp = tempfile::tempdir().unwrap();
        let start = Instant::now();
        assert!(!wait_for_path(&tmp.path().join("never"), Duration::ZERO));
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
