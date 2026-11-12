//! `cargo xtask return-to-pios`: the way back to Raspberry Pi OS, run on the PC
//! with the Pi's card in its reader.
//!
//! The only file ever written is `config.txt`, and only on a directory that
//! has the Pi's boot partition's files; nothing else on the card is touched.

use std::fs::{self, File};
use std::io::ErrorKind;
use std::path::Path;

use anyhow::{Result, anyhow, bail};
use qberrypi::bootpart::{Restore, restore_pios_config};

/// The configuration the firmware reads; it decides which system starts.
const CONFIG: &str = "config.txt";
/// The saved copy of Raspberry Pi OS's configuration.
const SAVED: &str = "config.pios.txt";
/// What a boot partition holds as plain files, in the order they are looked for.
const FILES: [&str; 3] = ["bootcode.bin", CONFIG, SAVED];
/// The folder qberrypi's files are in.
const FOLDER: &str = "qberrypi";
/// What to do when the card's `config.txt` cannot be trusted.
const BY_HAND: &str = "copy config.pios.txt over config.txt by hand before the card goes back";

/// What a directory entry is, for a message.
fn describe(kind: fs::FileType) -> &'static str {
    if kind.is_symlink() {
        "a symbolic link"
    } else if kind.is_dir() {
        "a directory"
    } else if kind.is_file() {
        "a regular file"
    } else {
        "neither a file nor a directory"
    }
}

/// Why a directory is not this Pi's boot partition, or `None` when it is.
///
/// It must hold `bootcode.bin`, `config.txt` and `config.pios.txt` as regular
/// files and `qberrypi` as a directory. Links are not followed: a symbolic
/// link by one of those names is not the file, so a write can never be led
/// somewhere else. `boot` itself may be a link to the directory.
pub fn not_the_boot_partition(boot: &Path) -> Option<String> {
    let dir = boot.display();
    match fs::metadata(boot) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => return Some(format!("{dir} is not a directory")),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Some(format!("{dir} does not exist"));
        }
        Err(error) => return Some(format!("{dir} cannot be read: {error}")),
    }
    let entries = FILES
        .iter()
        .map(|name| (name, false))
        .chain([(&FOLDER, true)]);
    for (name, is_folder) in entries {
        let path = boot.join(name);
        match fs::symlink_metadata(&path) {
            Ok(meta) => {
                let kind = meta.file_type();
                if (is_folder && !kind.is_dir()) || (!is_folder && !kind.is_file()) {
                    let expected = if is_folder {
                        "a directory"
                    } else {
                        "a regular file"
                    };
                    return Some(format!(
                        "{} is {}, not {expected}: {dir} is not the Pi's boot partition",
                        path.display(),
                        describe(kind)
                    ));
                }
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Some(format!(
                    "{dir} has no {name}: it is not the Pi's boot partition"
                ));
            }
            Err(error) => return Some(format!("{} cannot be read: {error}", path.display())),
        }
    }
    None
}

/// Makes the mounted card start Raspberry Pi OS next; the text to print on success.
///
/// Stops at the first failure. Everything is judged before `config.txt` is
/// written, and nothing else on the card ever is.
pub fn return_to_pios(boot: &Path) -> Result<String> {
    // The real place, so that a link to the card is judged and written as the
    // card, and the messages say where the card really is.
    let boot = fs::canonicalize(boot).unwrap_or_else(|_| boot.to_path_buf());
    if let Some(why) = not_the_boot_partition(&boot) {
        bail!("{why}; nothing was changed");
    }
    match restore_pios_config(&boot) {
        Ok(Restore::Refused(reason)) => bail!("{reason}; nothing was changed"),
        Ok(Restore::AlreadyRestored) => {
            Ok("config.txt was Raspberry Pi OS's already; nothing was changed".to_owned())
        }
        Ok(Restore::Restored) => {
            make_durable(&boot)?;
            Ok(
                "config.txt is Raspberry Pi OS's again: eject the card before taking it \
                out; the Pi will start Raspberry Pi OS"
                    .to_owned(),
            )
        }
        Err(error) => bail!("{}: {error}", boot.display()),
    }
}

/// Waits until `config.txt` and its directory entry are on the card, then
/// reads `config.txt` back and compares it with `config.pios.txt`.
fn make_durable(boot: &Path) -> Result<()> {
    let sync = |path: &Path| {
        File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(|error| {
                anyhow!(
                    "{}: the card did not take the write ({error}): {BY_HAND}",
                    boot.display()
                )
            })
    };
    sync(&boot.join(CONFIG))?;
    sync(boot)?;
    let read = |name: &str| {
        fs::read(boot.join(name)).map_err(|error| {
            anyhow!(
                "{}: {name} could not be read back ({error}): {BY_HAND}",
                boot.display()
            )
        })
    };
    if read(CONFIG)? != read(SAVED)? {
        bail!("config.txt did not read back as config.pios.txt: {BY_HAND}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs::{self, File};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime};

    use tempfile::TempDir;

    use super::*;

    /// Fills `dir` as the Pi's boot partition looks: the firmware, Raspberry Pi
    /// OS's saved configuration, qberrypi's folder, and a `config.txt` that
    /// selects qberrypi.
    fn populate(dir: &Path) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join("bootcode.bin"), b"firmware").unwrap();
        fs::write(dir.join("config.pios.txt"), b"arm_64bit=1\n").unwrap();
        fs::write(dir.join("config.txt"), b"os_prefix=qberrypi/\n").unwrap();
        fs::create_dir(dir.join("qberrypi")).unwrap();
    }

    fn card() -> TempDir {
        let dir = tempfile::tempdir().unwrap();
        populate(dir.path());
        dir
    }

    /// Every path under the directory with its contents: a folder maps to
    /// nothing and a symbolic link to the place it points at. No link is followed.
    fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
        fn walk(dir: &Path, into: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
            for entry in fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                let kind = fs::symlink_metadata(&path).unwrap().file_type();
                if kind.is_symlink() {
                    let target = fs::read_link(&path).unwrap();
                    into.insert(path, Some(target.into_os_string().into_encoded_bytes()));
                } else if kind.is_dir() {
                    into.insert(path.clone(), None);
                    walk(&path, into);
                } else {
                    let data = fs::read(&path).unwrap();
                    into.insert(path, Some(data));
                }
            }
        }
        let mut files = BTreeMap::new();
        walk(dir, &mut files);
        files
    }

    /// Takes away the card's `name`, whatever kind it is.
    fn remove(dir: &Path, name: &str) {
        let path = dir.join(name);
        if fs::symlink_metadata(&path).unwrap().is_dir() {
            fs::remove_dir(&path).unwrap();
        } else {
            fs::remove_file(&path).unwrap();
        }
    }

    #[test]
    fn a_card_that_selects_qberrypi_is_given_back_to_raspberry_pi_os() {
        let dir = card();
        let mut expected = snapshot(dir.path());
        let said = return_to_pios(dir.path()).unwrap();
        assert!(
            said.starts_with("config.txt is Raspberry Pi OS's again"),
            "{said}"
        );
        assert_eq!(
            fs::read(dir.path().join("config.txt")).unwrap(),
            b"arm_64bit=1\n"
        );
        assert_eq!(
            fs::read(dir.path().join("config.pios.txt")).unwrap(),
            b"arm_64bit=1\n"
        );
        // Nothing but config.txt was written.
        expected.insert(
            dir.path().join("config.txt"),
            Some(b"arm_64bit=1\n".to_vec()),
        );
        assert_eq!(snapshot(dir.path()), expected);
        assert!(return_to_pios(dir.path()).unwrap().contains("already"));
    }

    #[test]
    fn a_card_that_is_already_raspberry_pi_os_is_not_written_at_all() {
        let dir = card();
        let config = dir.path().join("config.txt");
        fs::write(&config, b"arm_64bit=1\n").unwrap();
        let long_ago = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        File::options()
            .write(true)
            .open(&config)
            .unwrap()
            .set_modified(long_ago)
            .unwrap();
        let before = snapshot(dir.path());
        let said = return_to_pios(dir.path()).unwrap();
        assert!(
            said.contains("already") && said.ends_with("nothing was changed"),
            "{said}"
        );
        assert_eq!(snapshot(dir.path()), before);
        assert_eq!(fs::metadata(&config).unwrap().modified().unwrap(), long_ago);
    }

    #[test]
    fn anything_but_the_pis_boot_partition_is_refused_untouched() {
        for missing in ["bootcode.bin", "config.txt", "config.pios.txt", "qberrypi"] {
            let dir = card();
            remove(dir.path(), missing);
            let before = snapshot(dir.path());
            let error = return_to_pios(dir.path()).unwrap_err().to_string();
            assert!(
                error.contains(&format!("has no {missing}"))
                    && error.ends_with("; nothing was changed"),
                "{error}"
            );
            assert_eq!(snapshot(dir.path()), before, "{missing}");
        }
        let error = return_to_pios(Path::new("/nonexistent/card"))
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "/nonexistent/card does not exist; nothing was changed"
        );
    }

    #[test]
    fn a_root_partition_a_stick_a_folder_above_the_card_and_a_file_are_refused_untouched() {
        // The card's root partition holds the boot partition's mount point, not its files.
        let root = tempfile::tempdir().unwrap();
        populate(&root.path().join("boot/firmware"));
        fs::create_dir(root.path().join("etc")).unwrap();
        // The folder that holds a card, such as /media.
        let above = tempfile::tempdir().unwrap();
        populate(&above.path().join("card"));
        // A stick with something on it, and a path that is a file.
        let stick = tempfile::tempdir().unwrap();
        fs::write(stick.path().join("photo.jpg"), b"x").unwrap();
        let empty = tempfile::tempdir().unwrap();
        let file = stick.path().join("photo.jpg");
        for (given, whole) in [
            (root.path(), root.path()),
            (above.path(), above.path()),
            (stick.path(), stick.path()),
            (empty.path(), empty.path()),
            (file.as_path(), stick.path()),
        ] {
            let before = snapshot(whole);
            let error = return_to_pios(given).unwrap_err().to_string();
            assert!(error.ends_with("; nothing was changed"), "{error}");
            assert_eq!(snapshot(whole), before, "{given:?}");
        }
        let error = return_to_pios(&file).unwrap_err().to_string();
        assert!(error.contains("is not a directory"), "{error}");
        // The card in the folder above it is still given back, when named.
        assert!(return_to_pios(&above.path().join("card")).is_ok());
    }

    #[test]
    fn a_name_of_the_wrong_kind_is_refused_and_no_link_is_followed() {
        // Where a link could lead a write: a file that selects qberrypi and a folder.
        let elsewhere = tempfile::tempdir().unwrap();
        let file_elsewhere = elsewhere.path().join("file");
        fs::write(&file_elsewhere, b"os_prefix=qberrypi/\n").unwrap();
        let folder_elsewhere = elsewhere.path().join("folder");
        fs::create_dir(&folder_elsewhere).unwrap();
        let nowhere = elsewhere.path().join("nowhere");

        // What each name is made into: a directory, a file, or a link to one of the places above.
        enum Instead {
            Directory,
            File,
            LinkTo(PathBuf),
        }
        let mut cases = Vec::new();
        for name in ["bootcode.bin", "config.txt", "config.pios.txt"] {
            cases.push((name, "a directory", Instead::Directory));
            cases.push((
                name,
                "a symbolic link",
                Instead::LinkTo(file_elsewhere.clone()),
            ));
            cases.push((name, "a symbolic link", Instead::LinkTo(nowhere.clone())));
        }
        cases.push(("qberrypi", "a regular file", Instead::File));
        cases.push((
            "qberrypi",
            "a symbolic link",
            Instead::LinkTo(folder_elsewhere.clone()),
        ));
        cases.push((
            "qberrypi",
            "a symbolic link",
            Instead::LinkTo(nowhere.clone()),
        ));

        for (name, kind, instead) in cases {
            let dir = card();
            remove(dir.path(), name);
            let path = dir.path().join(name);
            match instead {
                Instead::Directory => fs::create_dir(&path).unwrap(),
                Instead::File => fs::write(&path, b"x").unwrap(),
                Instead::LinkTo(target) => symlink(target, &path).unwrap(),
            }
            let (card_before, elsewhere_before) =
                (snapshot(dir.path()), snapshot(elsewhere.path()));
            let error = return_to_pios(dir.path()).unwrap_err().to_string();
            assert!(
                error.contains(&format!("{name} is {kind}"))
                    && error.ends_with("; nothing was changed"),
                "{name}: {error}"
            );
            assert_eq!(snapshot(dir.path()), card_before, "{name} ({kind})");
            assert_eq!(
                snapshot(elsewhere.path()),
                elsewhere_before,
                "{name} ({kind})"
            );
        }
    }

    #[test]
    fn the_directory_may_be_given_through_a_link_and_messages_name_the_real_path() {
        let dir = card();
        let real = dir.path().canonicalize().unwrap();
        let links = tempfile::tempdir().unwrap();
        let link = links.path().join("sd-card");
        symlink(&real, &link).unwrap();

        remove(&real, "bootcode.bin");
        let error = return_to_pios(&link).unwrap_err().to_string();
        assert!(
            error.starts_with(&real.display().to_string()) && !error.contains("sd-card"),
            "{error}"
        );

        fs::write(real.join("bootcode.bin"), b"firmware").unwrap();
        assert!(return_to_pios(&link).unwrap().contains("again"));
        assert_eq!(fs::read(real.join("config.txt")).unwrap(), b"arm_64bit=1\n");
    }

    #[test]
    fn a_saved_configuration_that_cannot_be_restored_leaves_config_txt_alone() {
        for (bad, why) in [
            (&b""[..], "empty"),
            (b"a\0b\n", "not text"),
            (b"os_prefix=qberrypi/\n", "selects qberrypi"),
        ] {
            let dir = card();
            fs::write(dir.path().join("config.pios.txt"), bad).unwrap();
            let before = snapshot(dir.path());
            let error = return_to_pios(dir.path()).unwrap_err().to_string();
            assert!(
                error.contains(why) && error.ends_with("; nothing was changed"),
                "{error}"
            );
            assert_eq!(snapshot(dir.path()), before, "{why}");
            assert_eq!(
                fs::read(dir.path().join("config.txt")).unwrap(),
                b"os_prefix=qberrypi/\n"
            );
        }
    }

    /// Puts the card's permissions back when dropped, so the directory can be removed.
    struct Unlock<'a>(&'a Path);

    impl Drop for Unlock<'_> {
        fn drop(&mut self) {
            let _ = fs::set_permissions(self.0, fs::Permissions::from_mode(0o755));
            let _ =
                fs::set_permissions(self.0.join("config.txt"), fs::Permissions::from_mode(0o644));
        }
    }

    #[test]
    fn a_card_mounted_read_only_is_an_error() {
        let dir = card();
        let config = dir.path().join("config.txt");
        let _unlock = Unlock(dir.path());
        fs::set_permissions(&config, fs::Permissions::from_mode(0o444)).unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o555)).unwrap();
        if File::options().write(true).open(&config).is_ok() {
            eprintln!("skipped: this user can write to a read-only file (root?)");
            return;
        }
        let before = snapshot(dir.path());
        let error = return_to_pios(dir.path()).unwrap_err().to_string();
        let real = dir.path().canonicalize().unwrap();
        assert!(
            error.starts_with(&format!("{}: ", real.display())),
            "{error}"
        );
        assert!(!error.contains("nothing was changed"), "{error}");
        assert_eq!(snapshot(dir.path()), before);
        assert_eq!(fs::read(&config).unwrap(), b"os_prefix=qberrypi/\n");
    }

    #[test]
    fn a_config_txt_that_does_not_read_back_is_an_error_that_says_what_to_do() {
        let dir = card();
        let error = make_durable(dir.path()).unwrap_err().to_string();
        assert!(
            error.contains("config.txt did not read back as config.pios.txt")
                && error.contains("by hand"),
            "{error}"
        );
        fs::write(dir.path().join("config.txt"), b"arm_64bit=1\n").unwrap();
        make_durable(dir.path()).unwrap();
    }
}
