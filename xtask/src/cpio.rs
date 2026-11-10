//! Writes cpio archives in the "newc" format, the one the Linux kernel
//! unpacks an initramfs from.
//!
//! A member is a 110-byte header of ASCII digits, its name and its data. The
//! name and the data are each followed by NULs up to the next 4-byte boundary.
//! Every member belongs to root and carries the time 0, so the same members
//! always give the same bytes.

use std::collections::HashSet;
use std::io::{self, ErrorKind, Write};

/// What starts every newc header.
const MAGIC: &str = "070701";

/// The length of a header: the magic and thirteen numbers of eight digits.
const HEADER_LEN: usize = MAGIC.len() + 13 * 8;

/// The name of the member that ends an archive.
const TRAILER: &str = "TRAILER!!!";

/// The file type and permissions of a directory.
const DIR_MODE: u32 = 0o040755;

/// The file type bits of a regular file; its permissions are added to them.
const FILE_TYPE: u32 = 0o100000;

/// The file type and permissions of a symbolic link.
const SYMLINK_MODE: u32 = 0o120777;

/// The file type and permissions of a character device.
const CHAR_DEV_MODE: u32 = 0o020600;

/// What one member of an archive is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Node<'a> {
    /// A directory, mode 0755.
    Dir,
    /// A regular file with these contents and permission bits.
    File { data: &'a [u8], mode: u32 },
    /// A symbolic link to `target`.
    Symlink { target: &'a str },
    /// A character device with this device number, mode 0600.
    CharDev { major: u32, minor: u32 },
}

/// Writes a newc archive, one member at a time.
pub struct CpioWriter<W: Write> {
    out: W,
    /// The inode number the next member gets.
    next_ino: u32,
    /// The directories added so far.
    dirs: HashSet<String>,
}

/// The numbers of a header that differ from one member to the next.
struct Header {
    ino: u32,
    mode: u32,
    nlink: u32,
    rdev: (u32, u32),
}

impl<W: Write> CpioWriter<W> {
    /// Starts an empty archive that is written to `w`.
    pub fn new(w: W) -> Self {
        Self {
            out: w,
            next_ino: 1,
            dirs: HashSet::new(),
        }
    }

    /// Adds one member. `path` has no leading `/`.
    ///
    /// The kernel creates members in the order they come, so the directory a
    /// path lies in must have been added before it; if it was not, this is an
    /// error and nothing is written. Paths at the top level need no directory.
    pub fn add(&mut self, path: &str, node: Node) -> io::Result<()> {
        if path.contains('\0') || path.split('/').any(str::is_empty) {
            return Err(refused(format!(
                "{path:?} is not a path relative to the top of the archive"
            )));
        }
        if let Some((parent, _)) = path.rsplit_once('/')
            && !self.dirs.contains(parent)
        {
            return Err(refused(format!(
                "{path}: the directory {parent} must be added before it"
            )));
        }

        let (mode, nlink, rdev, data) = match node {
            Node::Dir => (DIR_MODE, 2, (0, 0), &[][..]),
            Node::File { data, mode } => (FILE_TYPE | mode, 1, (0, 0), data),
            Node::Symlink { target } => (SYMLINK_MODE, 1, (0, 0), target.as_bytes()),
            Node::CharDev { major, minor } => (CHAR_DEV_MODE, 1, (major, minor), &[][..]),
        };
        let header = Header {
            ino: self.next_ino,
            mode,
            nlink,
            rdev,
        };
        self.write_member(path, &header, data)?;

        self.next_ino += 1;
        if node == Node::Dir {
            self.dirs.insert(path.to_owned());
        }
        Ok(())
    }

    /// Ends the archive with its trailer and hands back what it was written to.
    pub fn finish(mut self) -> io::Result<W> {
        let trailer = Header {
            ino: 0,
            mode: 0,
            nlink: 1,
            rdev: (0, 0),
        };
        self.write_member(TRAILER, &trailer, &[])?;
        Ok(self.out)
    }

    /// Writes a header, the name and the data, each padded to a 4-byte boundary.
    fn write_member(&mut self, name: &str, header: &Header, data: &[u8]) -> io::Result<()> {
        // A length has eight hexadecimal digits in the header, and the name's counts its NUL.
        let name_len = u32::try_from(name.len() + 1)
            .map_err(|_| refused(format!("the name {name} is too long for a cpio archive")))?;
        let data_len = u32::try_from(data.len())
            .map_err(|_| refused(format!("{name} is too large for a cpio archive")))?;
        let fields = [
            header.ino,
            header.mode,
            0, // uid
            0, // gid
            header.nlink,
            0, // mtime
            data_len,
            0, // devmajor
            0, // devminor
            header.rdev.0,
            header.rdev.1,
            name_len,
            0, // check
        ];

        self.out.write_all(MAGIC.as_bytes())?;
        for field in fields {
            write!(self.out, "{field:08X}")?;
        }
        self.out.write_all(name.as_bytes())?;
        self.out
            .write_all(&[0; 4][..1 + padding(HEADER_LEN + name.len() + 1)])?;
        self.out.write_all(data)?;
        self.out.write_all(&[0; 3][..padding(data.len())])
    }
}

/// How many bytes take `len` to the next multiple of four.
fn padding(len: usize) -> usize {
    len.wrapping_neg() % 4
}

/// The error for a member the archive cannot take.
fn refused(why: String) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, why)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::{Command, Stdio};

    /// The position of each number in a newc header.
    const INO: usize = 0;
    const MODE: usize = 1;
    const UID: usize = 2;
    const GID: usize = 3;
    const NLINK: usize = 4;
    const MTIME: usize = 5;
    const FILESIZE: usize = 6;
    const DEVMAJOR: usize = 7;
    const DEVMINOR: usize = 8;
    const RDEVMAJOR: usize = 9;
    const RDEVMINOR: usize = 10;
    const NAMESIZE: usize = 11;
    const CHECK: usize = 12;

    /// One member of an archive, as a reader finds it.
    struct Record {
        fields: [u32; 13],
        name: String,
        data: Vec<u8>,
    }

    /// Reads an archive the strict way: every length, padding byte and the trailer are checked.
    fn records(archive: &[u8]) -> Vec<Record> {
        let mut found = Vec::new();
        let mut at = 0;
        loop {
            assert_eq!(at % 4, 0, "a header starts off a 4-byte boundary");
            assert_eq!(&archive[at..at + 6], b"070701");
            let mut fields = [0; 13];
            for (index, field) in fields.iter_mut().enumerate() {
                let start = at + 6 + index * 8;
                let digits = std::str::from_utf8(&archive[start..start + 8]).unwrap();
                assert!(digits.bytes().all(|b| b.is_ascii_hexdigit()), "{digits}");
                *field = u32::from_str_radix(digits, 16).unwrap();
            }
            at += 110;

            let name_len = fields[NAMESIZE] as usize;
            let name = &archive[at..at + name_len];
            assert_eq!(name.last(), Some(&0), "the name does not end in a NUL");
            let name = String::from_utf8(name[..name_len - 1].to_vec()).unwrap();
            assert!(!name.contains('\0'), "{name:?}");
            at += name_len;
            at = skip_padding(archive, at);

            let data_len = fields[FILESIZE] as usize;
            let data = archive[at..at + data_len].to_vec();
            at += data_len;
            at = skip_padding(archive, at);

            let last = name == "TRAILER!!!";
            found.push(Record { fields, name, data });
            if last {
                assert_eq!(at, archive.len(), "bytes after the trailer");
                return found;
            }
        }
    }

    /// Steps over the NULs that pad to the next 4-byte boundary.
    fn skip_padding(archive: &[u8], mut at: usize) -> usize {
        while !at.is_multiple_of(4) {
            assert_eq!(archive[at], 0, "padding that is not NUL at {at}");
            at += 1;
        }
        at
    }

    /// Runs the system `cpio` in `dir`, feeds it `archive` and returns what it printed.
    pub(crate) fn system_cpio(args: &[&str], archive: &[u8], dir: &Path) -> String {
        let mut child = Command::new("cpio")
            .args(args)
            .arg("--quiet")
            .current_dir(dir)
            .env("LC_ALL", "C")
            .env("TZ", "UTC")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(archive).unwrap();
        let output = child.wait_with_output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stderr}");
        assert_eq!(stderr, "", "cpio complained");
        String::from_utf8(output.stdout).unwrap()
    }

    /// The four kinds of node in one small archive.
    fn small_archive() -> Vec<u8> {
        let mut cpio = CpioWriter::new(Vec::new());
        cpio.add("dev", Node::Dir).unwrap();
        cpio.add("dev/console", Node::CharDev { major: 5, minor: 1 })
            .unwrap();
        cpio.add(
            "init",
            Node::File {
                data: b"x",
                mode: 0o755,
            },
        )
        .unwrap();
        cpio.add("l", Node::Symlink { target: "init" }).unwrap();
        cpio.finish().unwrap()
    }

    #[test]
    fn archive_is_readable_by_system_cpio() {
        let dir = tempfile::tempdir().unwrap();

        let listing = system_cpio(&["-tv"], &small_archive(), dir.path());

        let lines: Vec<&str> = listing.lines().collect();
        assert_eq!(lines.len(), 4, "{listing}");
        assert!(lines[0].starts_with("drwxr-xr-x") && lines[0].ends_with(" dev"));
        assert!(lines[1].starts_with('c') && lines[1].ends_with(" dev/console"));
        assert!(lines[1].contains("5,"), "{listing}");
        assert!(lines[2].starts_with("-rwxr-xr-x") && lines[2].ends_with(" init"));
        assert!(lines[3].starts_with("lrwxrwxrwx") && lines[3].ends_with(" l -> init"));
        for line in lines {
            assert!(line.contains(" root "), "{line}");
            assert!(line.contains("Jan  1  1970"), "{line}");
        }
    }

    #[test]
    fn output_is_reproducible() {
        assert_eq!(small_archive(), small_archive());
    }

    #[test]
    fn system_cpio_unpacks_the_files_and_links_as_they_went_in() {
        let dir = tempfile::tempdir().unwrap();
        let mut cpio = CpioWriter::new(Vec::new());
        cpio.add("lib", Node::Dir).unwrap();
        cpio.add(
            "lib/five.bin",
            Node::File {
                data: b"12345",
                mode: 0o644,
            },
        )
        .unwrap();
        cpio.add("lib/alias.bin", Node::Symlink { target: "five.bin" })
            .unwrap();
        cpio.add(
            "init",
            Node::File {
                data: b"x",
                mode: 0o755,
            },
        )
        .unwrap();
        let archive = cpio.finish().unwrap();

        system_cpio(&["-id"], &archive, dir.path());

        let five = dir.path().join("lib/five.bin");
        assert_eq!(fs::read(&five).unwrap(), b"12345");
        assert_eq!(
            fs::metadata(&five).unwrap().permissions().mode() & 0o7777,
            0o644
        );
        let alias = dir.path().join("lib/alias.bin");
        assert_eq!(fs::read_link(&alias).unwrap(), Path::new("five.bin"));
        assert_eq!(fs::read(&alias).unwrap(), b"12345");
        let init = dir.path().join("init");
        assert_eq!(
            fs::metadata(&init).unwrap().permissions().mode() & 0o7777,
            0o755
        );
    }

    #[test]
    fn a_directory_and_the_trailer_are_these_exact_bytes() {
        let mut cpio = CpioWriter::new(Vec::new());
        cpio.add("dev", Node::Dir).unwrap();
        let archive = cpio.finish().unwrap();

        let expected = concat!(
            "070701",
            "00000001",  // ino
            "000041ED",  // mode: directory, 0755
            "00000000",  // uid
            "00000000",  // gid
            "00000002",  // nlink
            "00000000",  // mtime
            "00000000",  // filesize
            "00000000",  // devmajor
            "00000000",  // devminor
            "00000000",  // rdevmajor
            "00000000",  // rdevminor
            "00000004",  // namesize, counting the NUL
            "00000000",  // check
            "dev\0\0\0", // 110 + 4 = 114, padded to 116
            "070701",
            "00000000",
            "00000000",
            "00000000",
            "00000000",
            "00000001",
            "00000000",
            "00000000",
            "00000000",
            "00000000",
            "00000000",
            "00000000",
            "0000000B",
            "00000000",
            "TRAILER!!!\0\0\0\0", // 110 + 11 = 121, padded to 124
        );
        // The digits may be in either case.
        assert_eq!(
            String::from_utf8(archive).unwrap().to_ascii_uppercase(),
            expected.to_ascii_uppercase()
        );
    }

    #[test]
    fn each_kind_of_node_gets_its_mode_link_count_and_data() {
        let records = records(&small_archive());

        let names: Vec<&str> = records.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["dev", "dev/console", "init", "l", "TRAILER!!!"]);
        let [dir, console, init, link, _] = &records[..] else {
            unreachable!()
        };

        assert_eq!(dir.fields[MODE], 0o040755);
        assert_eq!(dir.fields[NLINK], 2);
        assert_eq!(dir.data, b"");

        assert_eq!(console.fields[MODE], 0o020600);
        assert_eq!(console.fields[NLINK], 1);
        assert_eq!(console.fields[RDEVMAJOR], 5);
        assert_eq!(console.fields[RDEVMINOR], 1);
        assert_eq!(console.data, b"");

        assert_eq!(init.fields[MODE], 0o100755);
        assert_eq!(init.fields[NLINK], 1);
        assert_eq!(init.fields[NAMESIZE], 5);
        assert_eq!(init.data, b"x");

        assert_eq!(link.fields[MODE], 0o120777);
        assert_eq!(link.fields[NLINK], 1);
        assert_eq!(link.data, b"init");

        for record in [dir, init, link] {
            assert_eq!(record.fields[RDEVMAJOR], 0, "{}", record.name);
            assert_eq!(record.fields[RDEVMINOR], 0, "{}", record.name);
        }
    }

    #[test]
    fn owner_time_and_device_are_zero_and_inodes_count_up_from_one() {
        let records = records(&small_archive());

        for (index, record) in records.iter().enumerate() {
            let name = &record.name;
            let trailer = name == "TRAILER!!!";
            let ino = if trailer { 0 } else { index as u32 + 1 };
            assert_eq!(record.fields[INO], ino, "{name}");
            for field in [UID, GID, MTIME, DEVMAJOR, DEVMINOR, CHECK] {
                assert_eq!(record.fields[field], 0, "{name}, field {field}");
            }
        }
    }

    #[test]
    fn names_and_data_of_every_length_are_padded_to_four_bytes() {
        let mut cpio = CpioWriter::new(Vec::new());
        let names = ["a", "ab", "abc", "abcd", "abcde"];
        let data = b"12345";
        for (index, name) in names.iter().enumerate() {
            cpio.add(
                name,
                Node::File {
                    data: &data[..index],
                    mode: 0o644,
                },
            )
            .unwrap();
        }
        let archive = cpio.finish().unwrap();

        // `records` fails on any length or padding byte that is off.
        let records = records(&archive);

        assert_eq!(archive.len() % 4, 0);
        assert_eq!(records.len(), names.len() + 1);
        for (index, name) in names.iter().enumerate() {
            assert_eq!(records[index].name, *name);
            assert_eq!(records[index].data, &data[..index]);
        }
    }

    #[test]
    fn a_path_whose_directory_was_not_added_is_refused() {
        let mut cpio = CpioWriter::new(Vec::new());

        let e = cpio.add("dev/console", Node::CharDev { major: 5, minor: 1 });

        let e = e.unwrap_err().to_string();
        assert!(e.contains("dev/console") && e.contains("directory"), "{e}");
    }

    #[test]
    fn a_directory_two_levels_down_needs_the_one_above_it() {
        let mut cpio = CpioWriter::new(Vec::new());
        cpio.add("lib", Node::Dir).unwrap();

        cpio.add("lib/firmware/brcm", Node::Dir).unwrap_err();

        cpio.add("lib/firmware", Node::Dir).unwrap();
        cpio.add("lib/firmware/brcm", Node::Dir).unwrap();
    }

    #[test]
    fn a_file_does_not_count_as_a_directory() {
        let mut cpio = CpioWriter::new(Vec::new());
        cpio.add(
            "init",
            Node::File {
                data: b"x",
                mode: 0o755,
            },
        )
        .unwrap();

        cpio.add("init/inside", Node::Dir).unwrap_err();
    }

    #[test]
    fn a_refused_path_leaves_the_archive_as_it_was() {
        let mut cpio = CpioWriter::new(Vec::new());
        cpio.add("dev", Node::Dir).unwrap();
        cpio.add("sys/kernel", Node::Dir).unwrap_err();
        cpio.add("proc", Node::Dir).unwrap();

        let records = records(&cpio.finish().unwrap());

        let entries: Vec<(&str, u32)> = records
            .iter()
            .map(|r| (r.name.as_str(), r.fields[INO]))
            .collect();
        assert_eq!(entries, [("dev", 1), ("proc", 2), ("TRAILER!!!", 0)]);
    }

    #[test]
    fn a_name_the_kernel_would_misread_is_refused() {
        for path in ["/init", "", "dev/", "dev//console", "in\0it"] {
            let mut cpio = CpioWriter::new(Vec::new());
            cpio.add("dev", Node::Dir).unwrap();

            let e = cpio.add(
                path,
                Node::File {
                    data: b"x",
                    mode: 0o644,
                },
            );

            assert!(e.is_err(), "{path:?} was accepted");
        }
    }
}
