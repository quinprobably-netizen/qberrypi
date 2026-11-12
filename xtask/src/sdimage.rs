//! Makes and reads the SD card images of `cargo xtask`: the 64 MiB one that
//! `cargo xtask qemu-test` boots from, and the 256 MiB one that `cargo xtask image` makes for a
//! real card.
//!
//! An image is laid out like the card in the Pi as far as qberrypi can tell:
//! a partition table whose first partition is the FAT boot partition. It is
//! put together and read back in memory; the file is written once, whole.
//!
//! `fsck.fat` finds fault with a directory on such an image, before any boot:
//! version 0.3 of the `fatfs` crate gives the directory's `.` and `..` entries
//! long names. Linux reads and writes the directory all the same.

use std::fs;
use std::io::{Cursor, Read, Write};
use std::ops::Range;
use std::path::Path;

use anyhow::{Context, Result, bail};
use fatfs::{FatType, FileSystem, FormatVolumeOptions, FsOptions};

/// The size of the image that QEMU boots. QEMU's Raspberry Pi takes a card only if its size is a
/// power of two.
pub const IMAGE_BYTES: usize = 64 * 1024 * 1024;

/// The size of the image that `cargo xtask image` makes for a card: 256 MiB, the one partition
/// of the design. The rest of the card is left as it was.
pub const CARD_IMAGE_BYTES: usize = 256 * 1024 * 1024;

const SECTOR_BYTES: usize = 512;
/// Where the partition starts, as partitioning tools place the first one.
const PARTITION_START_SECTOR: u32 = 2048;
/// Where the partition table has its first entry, and where its signature.
const FIRST_ENTRY: usize = 446;
const SIGNATURE_AT: usize = 510;
const SIGNATURE: [u8; 2] = [0x55, 0xAA];
/// The fewest clusters a FAT32 volume has; with fewer, readers take the volume for FAT16.
const FAT32_MIN_CLUSTERS: u32 = 65_525;
/// The partition type of a FAT32 partition addressed by sector number.
const FAT32_LBA: u8 = 0x0c;
/// Stands in an entry where a cylinder, head and sector would not fit; the sector numbers count.
const NO_CHS: [u8; 3] = [0xFE, 0xFF, 0xFF];

/// The partition over which a mounted FAT filesystem reads and writes.
type Partition<'a> = Cursor<&'a mut [u8]>;

/// Writes a 64 MiB card image whose one partition is FAT and holds the given files.
///
/// This is the image QEMU boots from; [`build_sized`] has the rules for the image. An earlier
/// file at `path` is replaced.
pub fn build(path: &Path, files: &[(&str, &[u8])]) -> Result<()> {
    build_sized(path, IMAGE_BYTES, files)
}

/// Writes a card image of `size` bytes whose one partition is FAT and holds the given files.
///
/// The file is written once, whole, and an earlier one at `path` is replaced. See [`make`] for
/// what the image is and when it is refused.
pub fn build_sized<N: AsRef<str>, D: AsRef<[u8]>>(
    path: &Path,
    size: usize,
    files: &[(N, D)],
) -> Result<()> {
    let image = make(size, files)?;
    fs::write(path, &image).with_context(|| format!("cannot write {}", path.display()))
}

/// Puts together a card image of `size` bytes whose one partition is FAT and holds the given
/// files, and returns its bytes.
///
/// The partition has type 0x0c, starts at sector 2048 and reaches the end of the image. A file's
/// path may name one folder before the file (`qberrypi-a/kernel8.img`); the folder is made when
/// the first file goes into it. A later file at the same path replaces an earlier one. The same
/// arguments always give the same bytes.
///
/// It is an error for `size` not to be a whole number of 512-byte sectors, for the partition to
/// hold more sectors than a partition table can count, for the partition to be too small for
/// FAT32 (it needs 65,525 clusters, about 33 MiB at the cluster size this makes), for a path to be empty, to have an empty part or more than one folder,
/// or for the files not to fit. The error for a file names its path.
pub fn make<N: AsRef<str>, D: AsRef<[u8]>>(size: usize, files: &[(N, D)]) -> Result<Vec<u8>> {
    let start = PARTITION_START_SECTOR as usize * SECTOR_BYTES;
    if !size.is_multiple_of(SECTOR_BYTES) {
        bail!("an image of {size} bytes is not a whole number of {SECTOR_BYTES}-byte sectors");
    }
    if size <= start {
        bail!(
            "an image of {size} bytes has no room for a partition after sector {PARTITION_START_SECTOR}"
        );
    }
    let sectors = u32::try_from((size - start) / SECTOR_BYTES)
        .context("the partition has more sectors than a partition table can count")?;

    let mut image = vec![0u8; size];
    let entry = &mut image[FIRST_ENTRY..FIRST_ENTRY + 16];
    entry[1..4].copy_from_slice(&NO_CHS);
    entry[4] = FAT32_LBA;
    entry[5..8].copy_from_slice(&NO_CHS);
    entry[8..12].copy_from_slice(&PARTITION_START_SECTOR.to_le_bytes());
    entry[12..16].copy_from_slice(&sectors.to_le_bytes());
    image[SIGNATURE_AT..SIGNATURE_AT + 2].copy_from_slice(&SIGNATURE);

    let partition = &mut image[start..];
    fatfs::format_volume(
        Cursor::new(&mut *partition),
        FormatVolumeOptions::new().fat_type(FatType::Fat32),
    )
    .context("cannot format the partition of the card image")?;
    let fat = FileSystem::new(Cursor::new(partition), FsOptions::new())
        .context("cannot open the partition just formatted")?;
    // A volume with fewer clusters is FAT16 to any reader that tells the types apart by the
    // clusters, as the Pi's boot firmware may.
    let clusters = fat
        .stats()
        .context("cannot look at the partition just formatted")?
        .total_clusters();
    if clusters < FAT32_MIN_CLUSTERS {
        bail!(
            "a partition of {} MiB has {clusters} clusters, and FAT32 needs at least \
             {FAT32_MIN_CLUSTERS}: make the image larger",
            (size - start) >> 20
        );
    }
    for (name, data) in files {
        let name = name.as_ref();
        add_file(&fat, name, data.as_ref())
            .with_context(|| format!("cannot add {name} to the card image"))?;
    }
    fat.unmount()
        .context("cannot finish the partition of the card image")?;
    Ok(image)
}

/// Writes one file into the partition, making its folder first if it names one.
fn add_file(fat: &FileSystem<Partition>, name: &str, data: &[u8]) -> Result<()> {
    if name.split('/').any(str::is_empty) {
        bail!("the path is empty or has an empty part");
    }
    let root = fat.root_dir();
    let mut file = match name.split_once('/') {
        None => root.create_file(name)?,
        Some((_, file)) if file.contains('/') => bail!("more than one directory in the path"),
        Some((dir, file)) => root.create_dir(dir)?.create_file(file)?,
    };
    file.truncate()?;
    file.write_all(data)?;
    file.flush()?;
    Ok(())
}

/// Reads one file from the first partition of a card image.
///
/// The image file itself is only read, never written. To read several files, open the image once
/// with [`Image::open`].
pub fn read_file(path: &Path, name: &str) -> Result<Vec<u8>> {
    Image::open(path)?.read(name)
}

/// A card image read into memory, for reading files from its first partition by path.
///
/// The image file is read once, whole, when this is opened, and never written; what is read is
/// what the file held then.
pub struct Image {
    /// The image file's bytes.
    bytes: Vec<u8>,
    /// Where in `bytes` the first partition lies.
    partition: Range<usize>,
    /// The image file's name, for the errors.
    name: String,
}

impl std::fmt::Debug for Image {
    /// Names the image file and its first partition; the bytes are not printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Image")
            .field("name", &self.name)
            .field("partition", &self.partition)
            .finish_non_exhaustive()
    }
}

impl Image {
    /// Reads the image file at `path` and finds its first partition.
    ///
    /// It is an error for the file not to be readable, to have no partition table, or to have a
    /// first partition that is not there or reaches past its end; the error names the file.
    pub fn open(path: &Path) -> Result<Image> {
        let bytes = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
        let partition = first_partition(&bytes)
            .with_context(|| format!("{} is not a card image", path.display()))?;
        let mut image = Image {
            bytes,
            partition,
            name: path.display().to_string(),
        };
        // Look at the filesystem now, so that a file that only has a table fails here.
        image
            .with_fat(|_| Ok(()))
            .with_context(|| format!("cannot open the FAT partition of {}", image.name))?;
        Ok(image)
    }

    /// Reads the file at `name`, a path from the partition's root such as `config.txt` or
    /// `qberrypi-a/qberrypi.toml`.
    ///
    /// It is an error for the file not to be there, or to be a folder; the error names the file
    /// and the image.
    pub fn read(&mut self, name: &str) -> Result<Vec<u8>> {
        let image = self.name.clone();
        self.with_fat(|fat| {
            let mut data = Vec::new();
            fat.root_dir()
                .open_file(name)
                .and_then(|mut file| file.read_to_end(&mut data))?;
            Ok(data)
        })
        .with_context(|| format!("cannot read {name} from {image}"))
    }

    /// Reads the file at `name` as [`Image::read`] does, or `None` when there is no such file.
    ///
    /// Any other failure is an error.
    pub fn find(&mut self, name: &str) -> Result<Option<Vec<u8>>> {
        match self.read(name) {
            Ok(data) => Ok(Some(data)),
            Err(error) => match error.downcast_ref::<std::io::Error>() {
                Some(io) if io.kind() == std::io::ErrorKind::NotFound => Ok(None),
                _ => Err(error),
            },
        }
    }

    /// Lists the files, not the folders, of the folder at `dir` (`""` is the root), sorted by
    /// name; `.` and `..` are not listed.
    ///
    /// It is an error for the folder not to be there; the error names it and the image.
    #[allow(
        dead_code,
        reason = "the QEMU scenarios read the slot images with it; they come next"
    )]
    pub fn files_in(&mut self, dir: &str) -> Result<Vec<String>> {
        let image = self.name.clone();
        self.with_fat(|fat| {
            let root = fat.root_dir();
            let folder = if dir.is_empty() {
                root
            } else {
                root.open_dir(dir)?
            };
            let mut names = Vec::new();
            for entry in folder.iter() {
                let entry = entry?;
                if entry.is_file() {
                    names.push(entry.file_name());
                }
            }
            names.sort();
            Ok(names)
        })
        .with_context(|| format!("cannot list {dir:?} on {image}"))
    }

    /// Runs `work` on the image's filesystem. Nothing it does is written to the image file.
    fn with_fat<T>(
        &mut self,
        work: impl FnOnce(&FileSystem<Partition>) -> std::io::Result<T>,
    ) -> Result<T> {
        let partition = &mut self.bytes[self.partition.clone()];
        let fat = FileSystem::new(Cursor::new(partition), FsOptions::new())?;
        Ok(work(&fat)?)
    }
}

/// Finds where the first partition lies, going by the image's partition table.
fn first_partition(image: &[u8]) -> Result<Range<usize>> {
    if image.get(SIGNATURE_AT..SIGNATURE_AT + 2) != Some(&SIGNATURE[..]) {
        bail!("it has no partition table");
    }
    let entry = &image[FIRST_ENTRY..FIRST_ENTRY + 16];
    let sector_count = |at: usize| {
        let field: [u8; 4] = entry[at..at + 4].try_into().expect("four bytes");
        u32::from_le_bytes(field) as usize
    };
    let start = sector_count(8) * SECTOR_BYTES;
    let end = start + sector_count(12) * SECTOR_BYTES;
    if start == 0 || start >= end {
        bail!("its partition table has no first partition");
    }
    if end > image.len() {
        bail!("its first partition reaches past its end");
    }
    Ok(start..end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_round_trips_files_and_has_one_fat_partition() {
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("sd.img");

        build(
            &img,
            &[("config.txt", b"a"), ("qberrypi/qberrypi.toml", b"b")],
        )
        .unwrap();

        assert_eq!(std::fs::metadata(&img).unwrap().len(), 64 * 1024 * 1024);
        assert_eq!(read_file(&img, "config.txt").unwrap(), b"a");
        assert_eq!(read_file(&img, "qberrypi/qberrypi.toml").unwrap(), b"b");
        let mbr = &std::fs::read(&img).unwrap()[..512];
        assert_eq!((mbr[510], mbr[511], mbr[446 + 4]), (0x55, 0xAA, 0x0c));
    }

    #[test]
    fn the_one_partition_starts_at_sector_2048_and_reaches_the_end() {
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("sd.img");

        build(&img, &[]).unwrap();

        let mbr = &fs::read(&img).unwrap()[..512];
        let number = |at: usize| u32::from_le_bytes(mbr[at..at + 4].try_into().unwrap());
        assert_eq!(number(446 + 8), 2048);
        assert_eq!(number(446 + 8) + number(446 + 12), 64 * 1024 * 1024 / 512);
        // The three other entries of the table are empty.
        assert!(mbr[446 + 16..510].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn building_the_same_image_twice_gives_identical_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let (first, second) = (dir.path().join("1.img"), dir.path().join("2.img"));
        let files: [(&str, &[u8]); 2] = [("config.txt", b"a"), ("qberrypi/log.txt", b"b")];

        build(&first, &files).unwrap();
        build(&second, &files).unwrap();

        assert!(fs::read(&first).unwrap() == fs::read(&second).unwrap());
    }

    #[test]
    fn reading_leaves_the_image_file_as_it_was() {
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("sd.img");
        build(&img, &[("config.txt", b"a")]).unwrap();
        let before = fs::read(&img).unwrap();

        read_file(&img, "config.txt").unwrap();

        assert!(fs::read(&img).unwrap() == before);
    }

    #[test]
    fn a_file_that_is_not_on_the_image_is_an_error_that_names_it() {
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("sd.img");
        build(&img, &[("config.txt", b"a")]).unwrap();

        let e = read_file(&img, "qberrypi/log.txt").unwrap_err();

        assert!(format!("{e:#}").contains("qberrypi/log.txt"), "{e:#}");
    }

    #[test]
    fn a_path_with_two_directories_is_refused() {
        let dir = tempfile::tempdir().unwrap();

        let e = build(&dir.path().join("sd.img"), &[("a/b/c.txt", b"x")]).unwrap_err();

        assert!(format!("{e:#}").contains("a/b/c.txt"), "{e:#}");
    }

    #[test]
    fn a_file_that_is_not_a_card_image_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not.img");
        fs::write(&path, vec![0u8; 4096]).unwrap();

        let e = read_file(&path, "config.txt").unwrap_err();

        assert!(format!("{e:#}").contains("not a card image"), "{e:#}");
    }

    #[test]
    fn a_card_image_is_as_large_as_asked_and_its_partition_reaches_the_end() {
        let image = make(CARD_IMAGE_BYTES, &[("config.txt", b"a")]).unwrap();

        assert_eq!(image.len(), 256 * 1024 * 1024);
        let number = |at: usize| u32::from_le_bytes(image[at..at + 4].try_into().unwrap());
        assert_eq!(number(446 + 8), 2048);
        assert_eq!(
            number(446 + 8) as usize + number(446 + 12) as usize,
            256 * 1024 * 1024 / 512
        );
        assert_eq!((image[510], image[511], image[446 + 4]), (0x55, 0xAA, 0x0c));
    }

    #[test]
    fn owned_names_and_bytes_make_the_same_image_as_borrowed_ones() {
        let owned = vec![
            ("a/x.bin".to_owned(), vec![1u8, 2, 3]),
            ("b.txt".to_owned(), b"b".to_vec()),
        ];
        let borrowed: [(&str, &[u8]); 2] = [("a/x.bin", &[1, 2, 3]), ("b.txt", b"b")];

        assert!(make(IMAGE_BYTES, &owned).unwrap() == make(IMAGE_BYTES, &borrowed).unwrap());
    }

    #[test]
    fn sizes_that_cannot_make_an_image_are_refused_with_the_reason() {
        let none: [(&str, &[u8]); 0] = [];
        // Not a whole number of sectors.
        let e = make(IMAGE_BYTES + 1, &none).unwrap_err();
        assert!(format!("{e:#}").contains("sectors"), "{e:#}");
        // No room for a partition.
        let e = make(1024 * 1024, &none).unwrap_err();
        assert!(format!("{e:#}").contains("no room"), "{e:#}");
        // A partition too small to be FAT32.
        let e = make(8 * 1024 * 1024, &none).unwrap_err();
        assert!(format!("{e:#}").contains("FAT32 needs at least"), "{e:#}");
        // The smallest that is not: 40 MiB.
        make(40 * 1024 * 1024, &none).unwrap();
    }

    #[test]
    fn a_path_with_an_empty_part_is_refused() {
        for name in ["", "/a.txt", "a//b.txt", "a/"] {
            let e = make(IMAGE_BYTES, &[(name, b"x")]).unwrap_err();
            assert!(format!("{e:#}").contains("empty"), "{name:?}: {e:#}");
        }
    }

    #[test]
    fn files_that_do_not_fit_are_refused_and_the_error_names_the_file() {
        let big = vec![7u8; IMAGE_BYTES];

        let e = make(IMAGE_BYTES, &[("big.bin", &big[..])]).unwrap_err();

        assert!(format!("{e:#}").contains("big.bin"), "{e:#}");
    }

    #[test]
    fn several_files_share_a_folder_and_a_later_file_replaces_an_earlier_one() {
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("sd.img");
        build_sized(
            &img,
            IMAGE_BYTES,
            &[
                ("qberrypi-a/one.txt", &b"1"[..]),
                ("qberrypi-a/two.txt", b"2"),
                ("qberrypi-a/one.txt", b"replaced"),
            ],
        )
        .unwrap();

        let mut image = Image::open(&img).unwrap();

        assert_eq!(image.read("qberrypi-a/one.txt").unwrap(), b"replaced");
        assert_eq!(image.read("qberrypi-a/two.txt").unwrap(), b"2");
        assert_eq!(
            image.files_in("qberrypi-a").unwrap(),
            ["one.txt", "two.txt"]
        );
    }

    #[test]
    fn an_open_image_finds_a_missing_file_as_none_and_lists_the_root_without_folders() {
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("sd.img");
        build(&img, &[("config.txt", b"a"), ("qberrypi-a/x", b"x")]).unwrap();

        let mut image = Image::open(&img).unwrap();

        assert_eq!(
            image.find("config.txt").unwrap().as_deref(),
            Some(&b"a"[..])
        );
        assert_eq!(image.find("tryboot.txt").unwrap(), None);
        assert_eq!(image.find("qberrypi-b/x").unwrap(), None);
        assert_eq!(image.files_in("").unwrap(), ["config.txt"]);
        let e = image.files_in("qberrypi-b").unwrap_err();
        assert!(format!("{e:#}").contains("qberrypi-b"), "{e:#}");
    }

    #[test]
    fn an_image_whose_partition_reaches_past_its_end_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("sd.img");
        build(&img, &[]).unwrap();
        let mut bytes = fs::read(&img).unwrap();
        bytes.truncate(IMAGE_BYTES / 2);
        fs::write(&img, &bytes).unwrap();

        let e = Image::open(&img).unwrap_err();

        let e = format!("{e:#}");
        assert!(
            e.contains("not a card image") && e.contains("past its end"),
            "{e}"
        );
    }
}
