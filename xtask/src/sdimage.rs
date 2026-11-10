//! Makes and reads the SD card image that `cargo xtask qemu-test` boots from.
//!
//! The image is laid out like the card in the Pi as far as qberrypi can tell:
//! a partition table whose first partition is the FAT boot partition. It is
//! put together and read back in memory; the file is written once, whole.
//!
//! `fsck.fat` finds fault with a directory on such an image, before any boot:
//! version 0.3 of the `fatfs` crate gives the directory's `.` and `..` entries
//! long names. Linux reads and writes the directory all the same.

use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use fatfs::{FatType, FileSystem, FormatVolumeOptions, FsOptions};

/// The size of the image. QEMU's Raspberry Pi takes a card only if its size is a power of two.
pub const IMAGE_BYTES: usize = 64 * 1024 * 1024;

const SECTOR_BYTES: usize = 512;
/// Where the partition starts, as partitioning tools place the first one.
const PARTITION_START_SECTOR: u32 = 2048;
/// Where the partition table has its first entry, and where its signature.
const FIRST_ENTRY: usize = 446;
const SIGNATURE_AT: usize = 510;
const SIGNATURE: [u8; 2] = [0x55, 0xAA];
/// The partition type of a FAT32 partition addressed by sector number.
const FAT32_LBA: u8 = 0x0c;
/// Stands in an entry where a cylinder, head and sector would not fit; the sector numbers count.
const NO_CHS: [u8; 3] = [0xFE, 0xFF, 0xFF];

/// The partition over which a mounted FAT filesystem reads and writes.
type Partition<'a> = Cursor<&'a mut [u8]>;

/// Writes a 64 MiB card image whose one partition is FAT and holds the given files.
///
/// The partition has type 0x0c, starts at sector 2048 and reaches the end of
/// the image. A file's path may name one directory before the file. An
/// earlier file at `path` is replaced.
pub fn build(path: &Path, files: &[(&str, &[u8])]) -> Result<()> {
    let mut image = vec![0u8; IMAGE_BYTES];
    let start = PARTITION_START_SECTOR as usize * SECTOR_BYTES;
    let sectors = ((IMAGE_BYTES - start) / SECTOR_BYTES) as u32;

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
    for (name, data) in files {
        add_file(&fat, name, data)
            .with_context(|| format!("cannot add {name} to the card image"))?;
    }
    fat.unmount()
        .context("cannot finish the partition of the card image")?;

    fs::write(path, &image).with_context(|| format!("cannot write {}", path.display()))
}

/// Writes one file into the partition, making its directory first if it names one.
fn add_file(fat: &FileSystem<Partition>, name: &str, data: &[u8]) -> Result<()> {
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
/// The image file itself is only read, never written.
pub fn read_file(path: &Path, name: &str) -> Result<Vec<u8>> {
    let mut image = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    let partition = first_partition(&mut image)
        .with_context(|| format!("{} is not a card image", path.display()))?;
    let fat = FileSystem::new(Cursor::new(partition), FsOptions::new())
        .with_context(|| format!("cannot open the FAT partition of {}", path.display()))?;
    let mut data = Vec::new();
    fat.root_dir()
        .open_file(name)
        .and_then(|mut file| file.read_to_end(&mut data))
        .with_context(|| format!("cannot read {name} from {}", path.display()))?;
    Ok(data)
}

/// Finds the bytes of the first partition, going by the image's partition table.
fn first_partition(image: &mut [u8]) -> Result<&mut [u8]> {
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
    image
        .get_mut(start..end)
        .context("its first partition reaches past its end")
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
}
