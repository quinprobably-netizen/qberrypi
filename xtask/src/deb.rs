//! Reads Debian packages: finds the wanted files in a `.deb` and writes them out.
//!
//! A member's own path is only ever compared with the wanted list. Where a
//! file is written comes from the caller alone, so a package cannot choose
//! where its contents land.

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, ErrorKind, Read};
use std::panic;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;

use anyhow::{Context, Result, anyhow, bail};

/// Copies the wanted members of a Debian package into `out_dir`.
///
/// Each of `wanted` is a member's path inside the package and the path under
/// `out_dir` to write it to. A member matches when its path, with a leading
/// `./` removed, equals the wanted path. A member whose path ends in `.xz` is
/// written decompressed. A wanted member that is a link, or anything else that
/// is not a regular file, is an error; so is any wanted member the package
/// does not have, and that error lists them all.
///
/// An output appears under its name only when it has been written in full,
/// and one that already has the right contents is left untouched.
pub fn extract(deb: &Path, wanted: &[(&str, &str)], out_dir: &Path) -> Result<()> {
    let file = File::open(deb).with_context(|| format!("cannot open {}", deb.display()))?;
    let mut package = ar::Archive::new(file);
    while let Some(part) = package.next_entry() {
        let mut part =
            part.with_context(|| format!("{} is not a Debian package", deb.display()))?;
        let name = String::from_utf8_lossy(part.header().identifier()).into_owned();
        if !name.starts_with("data.tar") {
            continue;
        }
        let program = match name.as_str() {
            "data.tar.xz" => "xz",
            "data.tar.zst" => "zstd",
            _ => bail!(
                "{} keeps its files in {name}, which this tool cannot unpack",
                deb.display()
            ),
        };
        let missing = decompress(program, &mut part, |tar| {
            extract_from_tar(tar, wanted, out_dir)
        })
        .with_context(|| format!("extracting from {}", deb.display()))?;
        if !missing.is_empty() {
            bail!("{} does not contain: {}", deb.display(), missing.join(", "));
        }
        return Ok(());
    }
    bail!("{} has no data archive", deb.display())
}

/// Writes out each wanted member of a tar stream and returns the wanted paths it did not hold.
fn extract_from_tar(
    tar: &mut dyn Read,
    wanted: &[(&str, &str)],
    out_dir: &Path,
) -> Result<Vec<String>> {
    let mut found = vec![false; wanted.len()];
    let mut archive = tar::Archive::new(tar);
    for entry in archive.entries().context("cannot read the data archive")? {
        let mut entry = entry.context("the data archive is damaged")?;
        let path = entry.path_bytes().into_owned();
        let path = path.strip_prefix(b"./").unwrap_or(&path);
        let Some(index) = wanted
            .iter()
            .position(|(member, _)| member.as_bytes() == path)
        else {
            continue;
        };
        let (member, output) = wanted[index];
        let problem = match entry.header().entry_type() {
            tar::EntryType::Regular | tar::EntryType::Continuous => None,
            tar::EntryType::Symlink => Some("a symbolic link"),
            tar::EntryType::Link => Some("a hard link"),
            _ => Some("not a regular file"),
        };
        if let Some(problem) = problem {
            bail!("{member} is {problem} in the package, so there is no file to take");
        }
        write_output(&out_dir.join(output), |file| {
            if member.ends_with(".xz") {
                decompress("xz", &mut entry, |plain| Ok(io::copy(plain, file)?))?;
            } else {
                io::copy(&mut entry, file)?;
            }
            Ok(())
        })
        .with_context(|| format!("extracting {member}"))?;
        found[index] = true;
    }
    Ok(wanted
        .iter()
        .zip(found)
        .filter(|(_, found)| !found)
        .map(|((member, _), _)| member.to_string())
        .collect())
}

/// Puts a file at `dest` once `fill` has written all of it; an identical file already there is kept.
///
/// The contents go to a temporary name beside `dest` first, so `dest` is
/// never a half-written file. The temporary file is gone when this returns.
fn write_output(dest: &Path, fill: impl FnOnce(&mut File) -> Result<()>) -> Result<()> {
    let partial = partial_name(dest);
    let placed = fill_and_place(&partial, dest, fill);
    if placed.is_err() {
        let _ = fs::remove_file(&partial);
    }
    placed.with_context(|| format!("writing {}", dest.display()))
}

/// Writes the file at `partial` with `fill`, then renames it to `dest` unless `dest` holds the same already.
fn fill_and_place(
    partial: &Path,
    dest: &Path,
    fill: impl FnOnce(&mut File) -> Result<()>,
) -> Result<()> {
    if let Some(dir) = dest.parent() {
        fs::create_dir_all(dir)?;
    }
    let mut file = File::create(partial)?;
    fill(&mut file)?;
    if same_contents(partial, dest)? {
        fs::remove_file(partial)?;
    } else {
        file.sync_all()?;
        fs::rename(partial, dest)?;
    }
    Ok(())
}

/// The temporary name a file is written under before it takes the name `dest`.
fn partial_name(dest: &Path) -> PathBuf {
    let mut name = OsString::from(dest);
    name.push(".partial");
    PathBuf::from(name)
}

/// Whether the file at `old` exists and holds exactly what the file at `new` holds.
fn same_contents(new: &Path, old: &Path) -> io::Result<bool> {
    match fs::read(old) {
        Ok(old) => Ok(old == fs::read(new)?),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// Runs `program -dc` over `input` and gives what it writes to `consume`.
///
/// `consume` runs on another thread while this one feeds `input` to the
/// program. A program that is not installed, or that exits unsuccessfully, is
/// an error; the second includes what it wrote to standard error.
fn decompress<T: Send>(
    program: &str,
    input: &mut dyn Read,
    consume: impl FnOnce(&mut dyn Read) -> Result<T> + Send,
) -> Result<T> {
    let mut child = Command::new(program)
        .arg("-dc")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| match e.kind() {
            ErrorKind::NotFound => anyhow!(
                "the `{program}` program is needed to unpack the packages: install it and run this again"
            ),
            _ => anyhow!(e).context(format!("cannot start `{program}`")),
        })?;
    let mut stdin = child.stdin.take().expect("stdin is piped");
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let mut stderr = child.stderr.take().expect("stderr is piped");

    let (fed, consumed, complaint) = thread::scope(|scope| {
        let consumer = scope.spawn(move || {
            let value = consume(&mut stdout)?;
            // A tar reader stops at the end marker. The program must still be
            // allowed to write the rest, or it dies of a closed pipe.
            io::copy(&mut stdout, &mut io::sink())?;
            Ok(value)
        });
        let complaint = scope.spawn(move || {
            let mut text = Vec::new();
            let _ = stderr.read_to_end(&mut text);
            String::from_utf8_lossy(&text).trim().to_owned()
        });
        let fed = io::copy(input, &mut stdin);
        drop(stdin);
        let consumed: Result<T> = consumer.join().unwrap_or_else(|e| panic::resume_unwind(e));
        let complaint = complaint.join().unwrap_or_else(|e| panic::resume_unwind(e));
        (fed, consumed, complaint)
    });
    let status = child
        .wait()
        .with_context(|| format!("cannot wait for `{program}`"))?;

    // A closed pipe only says the program stopped reading; its exit status says why.
    if let Err(e) = &fed
        && e.kind() != ErrorKind::BrokenPipe
    {
        return Err(anyhow!("cannot read the compressed data: {e}"));
    }
    let failure =
        (!status.success()).then(|| format!("`{program} -dc` failed ({status}): {complaint}"));
    match (consumed, failure) {
        (Ok(value), None) => {
            fed.with_context(|| format!("`{program}` stopped reading its input early"))?;
            Ok(value)
        }
        (Ok(_), Some(failure)) => Err(anyhow!(failure)),
        // The program ended on its own account, so its complaint explains the reader's.
        (Err(e), Some(failure)) if status.code().is_some() => Err(e.context(failure)),
        // The program was only killed by the pipe the failed reader closed.
        (Err(e), _) => Err(e),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    /// What one member of a fixture package's data archive is.
    enum Member<'a> {
        File(&'a [u8]),
        Symlink(&'a str),
        HardLink(&'a str),
    }

    /// Runs `program -c` over `data` and returns what it wrote.
    fn compress(program: &str, data: &[u8]) -> Vec<u8> {
        let mut child = Command::new(program)
            .arg("-c")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(data).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        output.stdout
    }

    /// Builds a tar archive whose member names are stored exactly as given.
    fn data_tar(members: &[(&str, Member)]) -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        for (name, member) in members {
            let mut header = tar::Header::new_gnu();
            header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
            header.set_mode(0o644);
            let data = match member {
                Member::File(data) => {
                    header.set_entry_type(tar::EntryType::Regular);
                    data
                }
                Member::Symlink(target) => {
                    header.set_entry_type(tar::EntryType::Symlink);
                    header.set_link_name(target).unwrap();
                    &[][..]
                }
                Member::HardLink(target) => {
                    header.set_entry_type(tar::EntryType::Link);
                    header.set_link_name(target).unwrap();
                    &[][..]
                }
            };
            header.set_size(data.len() as u64);
            header.set_cksum();
            tar.append(&header, data).unwrap();
        }
        tar.into_inner().unwrap()
    }

    /// Writes a `.deb` whose data archive is `data`, stored under `data_name`.
    fn write_deb(path: &Path, data_name: &str, data: &[u8]) {
        let control = compress("xz", &data_tar(&[]));
        let mut deb = ar::Builder::new(File::create(path).unwrap());
        for (name, content) in [
            ("debian-binary", &b"2.0\n"[..]),
            ("control.tar.xz", &control),
            (data_name, data),
        ] {
            let header = ar::Header::new(name.as_bytes().to_vec(), content.len() as u64);
            deb.append(&header, content).unwrap();
        }
    }

    /// Writes a package with an xz-compressed data archive holding `members`.
    fn deb_with(dir: &Path, members: &[(&str, Member)]) -> PathBuf {
        let deb = dir.join("fixture.deb");
        write_deb(&deb, "data.tar.xz", &compress("xz", &data_tar(members)));
        deb
    }

    /// Writes the package most tests read: one plain file and one xz-compressed module.
    pub(crate) fn fixture_deb(dir: &Path) -> PathBuf {
        let module = compress("xz", b"module");
        deb_with(
            dir,
            &[
                ("./usr/lib/a.txt", Member::File(b"alpha")),
                ("./usr/lib/m.ko.xz", Member::File(&module)),
            ],
        )
    }

    fn read(out: &Path, name: &str) -> String {
        fs::read_to_string(out.join(name)).unwrap()
    }

    /// Every file under `dir`, as sorted paths relative to it.
    pub(crate) fn files_under(dir: &Path) -> Vec<String> {
        fn walk(dir: &Path, base: &Path, found: &mut Vec<String>) {
            for entry in fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, base, found);
                } else {
                    found.push(path.strip_prefix(base).unwrap().display().to_string());
                }
            }
        }
        let mut found = Vec::new();
        walk(dir, dir, &mut found);
        found.sort();
        found
    }

    #[test]
    fn extracts_by_suffix_and_decompresses_xz_members() {
        let dir = tempfile::tempdir().unwrap();
        let deb = fixture_deb(dir.path());
        let out = &dir.path().join("out");

        extract(
            &deb,
            &[("usr/lib/a.txt", "x/a.txt"), ("usr/lib/m.ko.xz", "x/m.ko")],
            out,
        )
        .unwrap();

        assert_eq!(read(out, "x/a.txt"), "alpha");
        assert_eq!(read(out, "x/m.ko"), "module");
        assert_eq!(files_under(out), ["x/a.txt", "x/m.ko"]);
    }

    #[test]
    fn missing_members_are_all_named() {
        let dir = tempfile::tempdir().unwrap();
        let deb = fixture_deb(dir.path());
        let out = &dir.path().join("out");

        let e = extract(
            &deb,
            &[("usr/lib/a.txt", "a"), ("nope/b", "b"), ("nope/c", "c")],
            out,
        )
        .unwrap_err()
        .to_string();

        assert!(e.contains("nope/b") && e.contains("nope/c") && !e.contains("usr/lib/a.txt"));
    }

    #[test]
    fn member_path_matches_with_or_without_leading_dot_slash() {
        let dir = tempfile::tempdir().unwrap();
        let deb = deb_with(
            dir.path(),
            &[
                ("./usr/lib/dotted.txt", Member::File(b"dotted")),
                ("usr/lib/bare.txt", Member::File(b"bare")),
            ],
        );
        let out = &dir.path().join("out");

        extract(
            &deb,
            &[("usr/lib/dotted.txt", "d"), ("usr/lib/bare.txt", "b")],
            out,
        )
        .unwrap();

        assert_eq!(read(out, "d"), "dotted");
        assert_eq!(read(out, "b"), "bare");
    }

    #[test]
    fn a_path_must_match_in_full_not_just_at_its_end() {
        let dir = tempfile::tempdir().unwrap();
        let deb = fixture_deb(dir.path());
        let out = &dir.path().join("out");

        let e = extract(&deb, &[("lib/a.txt", "a")], out).unwrap_err();

        assert!(e.to_string().contains("lib/a.txt"));
        assert!(!out.join("a").exists());
    }

    #[test]
    fn matches_a_member_path_longer_than_100_bytes() {
        let long = format!("usr/lib/modules/{}/deep.ko", "d".repeat(120));
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(4);
        tar.append_data(&mut header, &long, &b"deep"[..]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let deb = dir.path().join("long.deb");
        write_deb(
            &deb,
            "data.tar.xz",
            &compress("xz", &tar.into_inner().unwrap()),
        );
        let out = &dir.path().join("out");

        extract(&deb, &[(&long, "deep.ko")], out).unwrap();

        assert_eq!(read(out, "deep.ko"), "deep");
    }

    #[test]
    fn a_wanted_symlink_is_refused_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let deb = deb_with(
            dir.path(),
            &[
                ("./usr/lib/real.bin", Member::File(b"real")),
                ("./usr/lib/link.bin", Member::Symlink("real.bin")),
            ],
        );
        let out = &dir.path().join("out");

        let e = extract(&deb, &[("usr/lib/link.bin", "link.bin")], out).unwrap_err();

        let e = format!("{e:#}");
        assert!(
            e.contains("usr/lib/link.bin") && e.contains("symbolic link"),
            "{e}"
        );
        assert!(!out.join("link.bin").exists());
    }

    #[test]
    fn a_wanted_hard_link_is_refused_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let deb = deb_with(
            dir.path(),
            &[
                ("./usr/lib/real.bin", Member::File(b"real")),
                ("./usr/lib/twin.bin", Member::HardLink("usr/lib/real.bin")),
            ],
        );
        let out = &dir.path().join("out");

        let e = extract(&deb, &[("usr/lib/twin.bin", "twin.bin")], out).unwrap_err();

        let e = format!("{e:#}");
        assert!(
            e.contains("usr/lib/twin.bin") && e.contains("hard link"),
            "{e}"
        );
        assert!(!out.join("twin.bin").exists());
    }

    #[test]
    fn a_member_path_never_decides_where_a_file_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let deb = deb_with(
            dir.path(),
            &[
                ("../outside.txt", Member::File(b"hostile")),
                ("/absolute.txt", Member::File(b"hostile")),
            ],
        );
        let out = &dir.path().join("out");

        extract(&deb, &[("../outside.txt", "safe.txt")], out).unwrap();

        assert_eq!(files_under(dir.path()), ["fixture.deb", "out/safe.txt"]);
    }

    #[test]
    fn reads_a_zstd_compressed_data_archive() {
        let dir = tempfile::tempdir().unwrap();
        let deb = dir.path().join("zst.deb");
        let tar = data_tar(&[("./usr/lib/a.txt", Member::File(b"alpha"))]);
        write_deb(&deb, "data.tar.zst", &compress("zstd", &tar));
        let out = &dir.path().join("out");

        extract(&deb, &[("usr/lib/a.txt", "a.txt")], out).unwrap();

        assert_eq!(read(out, "a.txt"), "alpha");
    }

    #[test]
    fn an_unsupported_data_archive_is_named() {
        let dir = tempfile::tempdir().unwrap();
        let deb = dir.path().join("gz.deb");
        write_deb(&deb, "data.tar.gz", b"irrelevant");
        let out = &dir.path().join("out");

        let e = extract(&deb, &[("usr/lib/a.txt", "a.txt")], out).unwrap_err();

        assert!(format!("{e:#}").contains("data.tar.gz"), "{e:#}");
    }

    #[test]
    fn a_damaged_xz_member_reports_xz_and_leaves_no_output() {
        let dir = tempfile::tempdir().unwrap();
        let deb = deb_with(
            dir.path(),
            &[("./usr/lib/bad.ko.xz", Member::File(b"this is not xz data"))],
        );
        let out = &dir.path().join("out");

        let e = extract(&deb, &[("usr/lib/bad.ko.xz", "bad.ko")], out).unwrap_err();

        let e = format!("{e:#}");
        assert!(e.contains("`xz -dc` failed") && e.contains("bad.ko"), "{e}");
        assert_eq!(files_under(out), [] as [&str; 0]);
    }

    #[test]
    fn a_missing_decompressor_says_what_to_install() {
        let mut input = &b"anything"[..];

        let e = decompress("qberrypi-no-such-program", &mut input, |_| Ok(())).unwrap_err();

        let e = format!("{e:#}");
        assert!(
            e.contains("qberrypi-no-such-program") && e.contains("install"),
            "{e}"
        );
    }

    #[test]
    fn an_unchanged_output_is_left_alone_and_a_changed_one_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let deb = fixture_deb(dir.path());
        let out = &dir.path().join("out");
        let wanted = [("usr/lib/a.txt", "a.txt"), ("usr/lib/m.ko.xz", "m.ko")];
        extract(&deb, &wanted, out).unwrap();
        let inode_before = fs::metadata(out.join("a.txt")).unwrap().ino();
        fs::write(out.join("m.ko"), "tampered").unwrap();

        extract(&deb, &wanted, out).unwrap();

        assert_eq!(fs::metadata(out.join("a.txt")).unwrap().ino(), inode_before);
        assert_eq!(read(out, "m.ko"), "module");
        assert_eq!(files_under(out), ["a.txt", "m.ko"]);
    }
}
