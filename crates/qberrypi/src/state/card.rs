//! The card as the kept settings use it: two files on the boot partition, found while the partition
//! is mounted and then written in place through the raw partition device, never through a mount.
//!
//! **Why not a mount.** A writable mount of a FAT partition writes its boot sector (the "dirty"
//! flag, at the mount and again at the unmount) and its FSInfo sector, and a write through the
//! file system updates the file's directory entry (its time). A power cut that tears any of those
//! is worse than losing a save. So after the one-time creation a save never mounts the partition:
//! it overwrites the bytes of its copy where they lie on the device, and nothing else.
//!
//! **The folder** is [`DIR`] on the partition's root, beside the folders of the two slots, and
//! holds [`file_name`] `a.bin` and `b.bin`, each exactly [`FILE_SIZE`] bytes: the copies of
//! [`super::store`].
//!
//! **Creation** ([`create`], once). On a card that does not have both files at [`FILE_SIZE`], the
//! first save mounts the partition writable once (through the card claim, as every other writer
//! does), makes the folder, writes each missing or wrong-sized file whole with a fill that is no
//! frame and no run of zeros ([`fill`]), syncs it, maps it and unmounts. A file of the right size
//! is never written, valid or not.
//!
//! **Mapping.** While a file is open on the mounted partition, a [`Mapper`] says where its bytes
//! lie on the device: the real one asks the file system with the `FIGETBSZ` and `FIBMAP`
//! requests ([`crate::sys`]), block by block, and merges the answers into [`Extent`]s (an offset
//! on the partition and a length). The mapping is then checked against the device itself, and
//! trusted only if all of it holds: the device is read at those extents and holds exactly the
//! bytes that were read through the file system; every extent starts and ends on a logical block
//! of the device (the unit a direct write needs), lies inside the device, and lies past the file
//! system's own area (its boot sector, reserved sectors, tables and, on FAT12 and FAT16, its root
//! directory, read from the boot sector of the partition); and no extent of either copy overlaps
//! another (a cross-linked file system would pass the byte check, both files holding the same
//! bytes in the same place). A mapping that fails any of it makes the boot [`BootRead::trouble`],
//! and saving is off for the boot.
//!
//! **A read** ([`read_at_boot`], in the read-only mount of init's step 3) reads both files whole
//! if they are there at [`FILE_SIZE`], maps and checks them, and says what it found
//! ([`BootRead`]): the state to restore, the [`Store`] that knows the copies, and the places and
//! digests a save needs. A copy that starts with this format's magic but is of a version this
//! build does not know (a newer build wrote it, and the board was rolled back) is trouble too:
//! saving is off, so that it is never written over, and the state stays empty if no other copy
//! restores.
//!
//! **A save** is a [`RawMedium`] write: the target copy's whole window is read back from the
//! device and must still have the SHA-256 it was last known to hold (from the boot read, or the
//! last write); the frame, zero-padded to a multiple of the device's logical block size, is
//! written at the copy's extents; the device is synced. A window that is not what it was left as,
//! or any I/O error, is an error and nothing more is written: the caller turns saving off for the
//! boot.
//!
//! **Direct, aligned.** The device is opened with `O_DIRECT`, for the reads of the copies and for
//! the writes alike, so that nothing goes through the page cache: a buffered write to a block
//! device is written back in pages and may rewrite the sectors beside the copy's, and a read that
//! the cache answers may not be what a direct write left. A direct transfer needs the memory, the
//! offset and the length aligned: the memory is an [`ALIGN`]-aligned buffer ([`Aligned`], made
//! in safe code), and the offsets and lengths are multiples of the device's logical block
//! size, which every extent is checked for. Whether the medium is direct is a property of its
//! [`Device`], which a host test with a plain file for a device can turn off; the board's is
//! always on, and QEMU proves it.
//!
//! Everything that blocks is a job of the pool or of init's own thread; nothing here is called
//! from the runtime's thread. The kept settings are the owner's, so no error or line made here
//! holds a byte of a file: copy letters, counts and the operating system's own words only.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Seek, SeekFrom, Write};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use sha2::{Digest, Sha256};

use super::format::{FILE_SIZE, foreign_version};
use super::saver::{Writer, Written};
use super::store::{Loaded, Medium, SaveError, Store, Which};
use crate::sys;

/// The folder on the boot partition that holds the two copies.
pub const DIR: &str = "qberrypi-state";

/// The smallest logical block size of a device, and the unit that the frame is padded to at the
/// least: the sector of a card.
pub const SECTOR: usize = 512;

/// How the memory of a direct transfer is aligned, in bytes, and so the largest logical block size
/// of a device that a copy is written to: a device with larger blocks is refused.
pub const ALIGN: usize = 4096;

/// What the fill of a fresh copy is made from, with the copy's letter and the number of the
/// 32-byte block.
const FILL_SEED: &[u8] = b"qberrypi state fill";

/// The name of the file that holds copy `which`: `a.bin` or `b.bin`.
pub fn file_name(which: Which) -> &'static str {
    match which {
        Which::A => "a.bin",
        Which::B => "b.bin",
    }
}

/// Which place of two copy `which` is.
fn index(which: Which) -> usize {
    match which {
        Which::A => 0,
        Which::B => 1,
    }
}

/// Both copies, `a` first.
const BOTH: [Which; 2] = [Which::A, Which::B];

/// A run of a file's bytes that lie one after the other on the partition: where it starts and how
/// long it is, both in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    /// The offset of the run's first byte on the partition.
    pub offset: u64,
    /// The length of the run in bytes, more than 0.
    pub len: u64,
}

/// Where the bytes of a file lie on the partition.
pub trait Mapper {
    /// The extents of copy `which`, whose file is `file`, open on the mounted partition: in the
    /// order of the file's bytes, so that the bytes at them one after the other are the file's
    /// first [`FILE_SIZE`] bytes. An error says that the place cannot be told.
    fn map(&self, which: Which, file: &File) -> io::Result<Vec<Extent>>;
}

/// The mapper of the board: it asks the file system where each block of the file is.
pub struct Fibmap;

impl Mapper for Fibmap {
    fn map(&self, _which: Which, file: &File) -> io::Result<Vec<Extent>> {
        let block_size = sys::fs_block_size(file)?;
        map_with(FILE_SIZE as u64, block_size, |logical| {
            sys::fs_block_of(file, logical)
        })
    }
}

/// The extents of a file of `size` bytes whose blocks are `block_size` bytes each and whose block
/// number `n` is at block `block_of(n)` of the partition, with the blocks that follow one another
/// merged into one run.
///
/// An error for a block size that is 0 or does not divide `size`, for the first error `block_of`
/// gives, and for a block that `block_of` puts at 0, which is a hole: no file occupies the
/// partition's first block, so the file system does not know where that one is.
pub fn map_with(
    size: u64,
    block_size: u32,
    mut block_of: impl FnMut(u32) -> io::Result<u32>,
) -> io::Result<Vec<Extent>> {
    let bad = |what: &str| io::Error::new(ErrorKind::InvalidData, what.to_owned());
    if block_size == 0 || !size.is_multiple_of(u64::from(block_size)) {
        return Err(bad("the file system's blocks do not divide the file"));
    }
    let blocks = u32::try_from(size / u64::from(block_size))
        .map_err(|_| bad("the file has more blocks than a request can number"))?;
    let step = u64::from(block_size);
    let mut extents: Vec<Extent> = Vec::new();
    for logical in 0..blocks {
        let physical = block_of(logical)?;
        if physical == 0 {
            return Err(bad("a block of the file has no place on the card"));
        }
        let offset = u64::from(physical) * step;
        match extents.last_mut() {
            Some(last) if last.offset + last.len == offset => last.len += step,
            _ => extents.push(Extent { offset, len: step }),
        }
    }
    Ok(extents)
}

/// A zero-filled buffer whose bytes start at an address that is a multiple of [`ALIGN`], as a
/// direct transfer needs. It is made in safe code: a vector longer than wanted by `ALIGN`
/// bytes, and the part of it that starts where the address is aligned. The vector is never grown,
/// so its memory does not move.
struct Aligned {
    /// The memory.
    buf: Vec<u8>,
    /// Where the aligned part starts in `buf`, fewer than [`ALIGN`] bytes in.
    start: usize,
    /// How long the aligned part is.
    len: usize,
}

impl Aligned {
    /// `len` zero bytes, aligned. An error if `len` is more than a buffer can be, or the memory
    /// cannot be aligned (which a byte pointer always can).
    fn zeroed(len: usize) -> io::Result<Self> {
        let buf = vec![
            0u8;
            len.checked_add(ALIGN)
                .ok_or_else(|| io::Error::other("too long"))?
        ];
        let start = buf.as_ptr().align_offset(ALIGN);
        if start >= ALIGN {
            return Err(io::Error::other("the memory cannot be aligned"));
        }
        Ok(Self { buf, start, len })
    }

    /// The aligned bytes.
    fn bytes(&self) -> &[u8] {
        &self.buf[self.start..self.start + self.len]
    }

    /// The aligned bytes, to write into.
    fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.start..self.start + self.len]
    }
}

/// The partition device and how it is used: its path, and whether it is read and written
/// directly (`O_DIRECT`, past the page cache).
///
/// The board's is [`Device::block_device`]: direct, and asked for its logical block size and size.
/// A host test uses a plain file as the device ([`Device::plain_file`]), which is not direct, since
/// a test file system may refuse it, and has the block size the test gives it.
#[derive(Debug, Clone)]
pub struct Device {
    /// The partition device (`/dev/mmcblk0p1` on the board; a plain file in a test).
    path: PathBuf,
    /// The logical block size of a plain file standing in for the device; `None` for a real
    /// device, which is asked (`BLKSSZGET`).
    stand_in_block: Option<u32>,
    /// Whether every read and write of the copies bypasses the page cache.
    direct: bool,
}

/// What a device says of itself that the copies' places are checked against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Geometry {
    /// The logical block size, in bytes: a power of two from [`SECTOR`] to [`ALIGN`].
    block: usize,
    /// The size of the device, in bytes.
    size: u64,
}

impl Device {
    /// The real device at `path`: direct, with its logical block size and size asked of it.
    pub fn block_device(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            stand_in_block: None,
            direct: true,
        }
    }

    /// A plain file at `path` standing in for the device, with `block` as its logical block size,
    /// not direct; its size is the file's length.
    #[cfg(test)]
    pub(crate) fn plain_file(path: impl Into<PathBuf>, block: u32) -> Self {
        Self {
            path: path.into(),
            stand_in_block: Some(block),
            direct: false,
        }
    }

    /// This device, read and written directly or not.
    #[cfg(test)]
    pub(crate) fn with_direct(mut self, direct: bool) -> Self {
        self.direct = direct;
        self
    }

    /// Opens the device for reading, and for writing too if `writable`: with `O_DIRECT` when the
    /// medium is direct. A new open each time, so that nothing of an earlier one is held.
    fn open(&self, writable: bool) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options.read(true).write(writable);
        if self.direct {
            options.custom_flags(libc::O_DIRECT);
        }
        options.open(&self.path)
    }

    /// The logical block size and the size of the device that `file`, open on it, is. An error for
    /// a block size that is not a power of two from [`SECTOR`] to [`ALIGN`] (a copy is not written
    /// to a device whose blocks the aligned buffers do not fit).
    fn geometry(&self, file: &File) -> io::Result<Geometry> {
        let block = match self.stand_in_block {
            Some(block) => block,
            None => sys::block_logical_size(file)?,
        };
        let block = usize::try_from(block).map_err(io::Error::other)?;
        if !block.is_power_of_two() || !(SECTOR..=ALIGN).contains(&block) {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "the device's logical blocks are not a size that the copies are written in",
            ));
        }
        // A seek to the end says the size of a block device as well as of a plain file.
        let size = (&*file).seek(SeekFrom::End(0))?;
        Ok(Geometry { block, size })
    }
}

/// Where the data region of the FAT file system whose boot sector is the start of `sector` begins,
/// in bytes from the start of the partition: after the reserved sectors, the file allocation tables
/// and, on FAT12 and FAT16, the root directory. Nothing of a file lies before it.
///
/// An error for a sector that is not a FAT boot sector (the signature, a sector size, or a count
/// that is 0), or that is shorter than [`SECTOR`] bytes.
fn data_start(sector: &[u8]) -> Result<u64, &'static str> {
    const NOT_FAT: &str = "the partition's first sector is not a FAT boot sector";
    let sector = sector.get(..SECTOR).ok_or(NOT_FAT)?;
    if sector[510..512] != [0x55, 0xAA] {
        return Err(NOT_FAT);
    }
    let le16 = |at: usize| u64::from(u16::from_le_bytes([sector[at], sector[at + 1]]));
    let le32 = |at: usize| {
        u64::from(u32::from_le_bytes([
            sector[at],
            sector[at + 1],
            sector[at + 2],
            sector[at + 3],
        ]))
    };
    let bytes_per_sector = le16(11);
    let reserved = le16(14);
    let tables = u64::from(sector[16]);
    let root_entries = le16(17);
    let table_size = match le16(22) {
        0 => le32(36),
        size => size,
    };
    if !matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096)
        || reserved == 0
        || tables == 0
        || table_size == 0
    {
        return Err(NOT_FAT);
    }
    let root = (root_entries * 32).next_multiple_of(bytes_per_sector);
    Ok((reserved + tables * table_size) * bytes_per_sector + root)
}

/// Whether `places`, the extents of both copies together, overlap anywhere.
fn overlap(places: &[Extent]) -> bool {
    let mut sorted = places.to_vec();
    sorted.sort_by_key(|extent| extent.offset);
    sorted
        .windows(2)
        .any(|pair| pair[0].offset.saturating_add(pair[0].len) > pair[1].offset)
}

/// Why `places` (one copy's extents) are not places a copy may be written at on a device with this
/// `geometry` whose file system's data begins at `data_start`, or `Ok` if they are: each starts
/// and ends on a logical block of the device, lies inside the device and lies past the file
/// system's own area. Nothing is read: this is what a mapping says of itself.
fn check_places(
    places: &[Extent],
    geometry: Geometry,
    data_start: u64,
) -> Result<(), &'static str> {
    let block = geometry.block as u64;
    for extent in places {
        if extent.offset % block != 0 || extent.len % block != 0 {
            return Err("a place of the file does not start and end on a block of the device");
        }
        if extent.offset < data_start {
            return Err("a place of the file lies in the file system's own area");
        }
        if extent
            .offset
            .checked_add(extent.len)
            .is_none_or(|end| end > geometry.size)
        {
            return Err("a place of the file lies past the end of the device");
        }
    }
    Ok(())
}

/// The bytes of `extents` on `device`, one after the other, in an aligned buffer.
fn read_extents(device: &File, extents: &[Extent]) -> io::Result<Aligned> {
    let total = extents.iter().map(|extent| extent.len).sum::<u64>();
    let mut out = Aligned::zeroed(usize::try_from(total).map_err(io::Error::other)?)?;
    let mut at = 0;
    for extent in extents {
        let end = at + usize::try_from(extent.len).map_err(io::Error::other)?;
        device.read_exact_at(&mut out.bytes_mut()[at..end], extent.offset)?;
        at = end;
    }
    Ok(out)
}

/// Writes `data`, which starts at an aligned address, over the start of `extents` on `device`, run
/// by run; nothing past `data`'s length. Each run is as long as its extent, or what is left of
/// `data` (a multiple of the extents' block, which the caller makes it).
fn write_extents(device: &File, extents: &[Extent], data: &[u8]) -> io::Result<()> {
    let mut done = 0;
    for extent in extents {
        if done == data.len() {
            break;
        }
        let take = usize::try_from(extent.len)
            .map_err(io::Error::other)?
            .min(data.len() - done);
        device.write_all_at(&data[done..done + take], extent.offset)?;
        done += take;
    }
    Ok(())
}

/// The SHA-256 of `bytes`.
fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// What a copy's file holds when it is made: the SHA-256 of [`FILL_SEED`], the copy's letter and
/// the number of the 32-byte block, block after block, for [`FILE_SIZE`] bytes. It is no frame
/// (the magic is never there) and no run of zeros, and the two copies differ.
pub fn fill(which: Which) -> Vec<u8> {
    let mut out = Vec::with_capacity(FILE_SIZE);
    let mut block = 0u32;
    while out.len() < FILE_SIZE {
        let mut hash = Sha256::new();
        hash.update(FILL_SEED);
        hash.update([which.letter() as u8]);
        hash.update(block.to_le_bytes());
        out.extend_from_slice(&hash.finalize());
        block += 1;
    }
    out.truncate(FILE_SIZE);
    out
}

/// What one copy's file is as the card holds it, mapped and checked.
#[derive(Clone, PartialEq, Eq)]
struct Held {
    /// Where its bytes lie on the partition.
    extents: Vec<Extent>,
    /// The SHA-256 of its whole window, as read through the file system and found on the device.
    digest: [u8; 32],
}

/// What a read of the two copies found: what to restore, what a save needs to go on from it, and
/// whether saving can be trusted at all.
#[derive(Clone)]
pub struct BootRead {
    /// The newest whole copy and its state, or why there is none.
    loaded: Loaded,
    /// What is known of each copy's sequence.
    store: Store,
    /// Each copy that is there at [`FILE_SIZE`], mapped and checked; `None` for one that is missing,
    /// of another size, unreadable or not trusted.
    held: [Option<Held>; 2],
    /// What the device said of itself, if it was opened (it is, when there is a file to check).
    geometry: Option<Geometry>,
    /// Why saving is off for the boot, if the read found a reason: the card did not say where a
    /// file lies, or what it said was not true or not a place a copy may be written, or a file
    /// could not be read, or a copy is of a version this build does not know.
    trouble: Option<String>,
}

impl BootRead {
    /// A read of a card with no copy on it, as a boot sees a card that has never saved (or one
    /// that was not read, which a save treats the same way: it makes the copies first).
    pub fn absent() -> Self {
        let (store, loaded) = Store::load(None, None);
        Self {
            loaded,
            store,
            held: [None, None],
            geometry: None,
            trouble: None,
        }
    }

    /// The newest whole copy, with its state and payload, or why there is none: what a start
    /// restores from.
    pub fn loaded(&self) -> &Loaded {
        &self.loaded
    }

    /// What is known of the copies: which is the newest and what sequence the next save takes.
    pub fn store(&self) -> Store {
        self.store
    }

    /// Why saving is off for this boot, if the read found a reason (one line's worth, never a byte
    /// of a file).
    pub fn trouble(&self) -> Option<&str> {
        self.trouble.as_deref()
    }

    /// Whether both copies are there, mapped and checked, so that a save can write in place at
    /// once. When it is not, and there is no trouble, the first save makes the copies ([`create`]).
    pub fn complete(&self) -> bool {
        self.trouble.is_none() && self.geometry.is_some() && self.held.iter().all(Option::is_some)
    }

    /// The medium over `device` for the copies of this read, if they [are complete](Self::complete).
    pub fn medium(&self, device: &Device) -> Option<RawMedium> {
        if !self.complete() {
            return None;
        }
        let ([Some(a), Some(b)], Some(geometry)) = (&self.held, self.geometry) else {
            return None;
        };
        Some(RawMedium {
            device: device.clone(),
            block: geometry.block,
            extents: [a.extents.clone(), b.extents.clone()],
            digest: Mutex::new([a.digest, b.digest]),
        })
    }
}

#[cfg(test)]
impl BootRead {
    /// A read that found `saved` in copy `a` at sequence `seq` and nothing else on the card, for
    /// the tests of what a start makes of it. Nothing is mapped, so it is no medium.
    pub(crate) fn with_copy_a(saved: &super::Saved, seq: u64) -> Self {
        let payload = super::format::encode_payload(saved).expect("a state that fits");
        let mut bytes = super::format::frame(seq, &payload);
        bytes.resize(FILE_SIZE, 0);
        let (store, loaded) = Store::load(Some(&bytes), None);
        Self {
            loaded,
            store,
            ..Self::absent()
        }
    }

    /// A read that found trouble, which turns saving off for the boot.
    pub(crate) fn troubled(why: &str) -> Self {
        Self {
            trouble: Some(why.to_owned()),
            ..Self::absent()
        }
    }
}

impl fmt::Debug for BootRead {
    /// What was found, in counts and letters: never a byte of a copy.
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("BootRead")
            .field("loaded", &self.loaded)
            .field(
                "mapped",
                &self.held.iter().filter(|held| held.is_some()).count(),
            )
            .field("trouble", &self.trouble.is_some())
            .finish()
    }
}

/// What reading one file found.
enum Copy {
    /// There is no such file.
    Missing,
    /// There is a file of another size than [`FILE_SIZE`]: it is no copy, and the creation makes it again.
    WrongSize,
    /// The file's bytes, and the file, still open on the mounted partition.
    Whole(Vec<u8>, File),
}

/// Reads the file at `path` whole, if it is there at [`FILE_SIZE`].
fn read_copy(path: &Path) -> io::Result<Copy> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Copy::Missing),
        Err(error) => return Err(error),
    };
    if file.metadata()?.len() != FILE_SIZE as u64 {
        return Ok(Copy::WrongSize);
    }
    let mut bytes = vec![0; FILE_SIZE];
    file.read_exact_at(&mut bytes, 0)?;
    Ok(Copy::Whole(bytes, file))
}

/// The device as a boot read has it open: read directly, with what it says of itself and where the
/// file system's own area ends.
struct Raw {
    /// The device, open for reading.
    file: File,
    /// Its logical block size and size.
    geometry: Geometry,
    /// Where the data region of the file system on it begins ([`data_start`]).
    data_start: u64,
}

impl Raw {
    /// Opens `device` and reads what it says of itself and its boot sector.
    fn open(device: &Device) -> io::Result<Self> {
        let file = device.open(false)?;
        let geometry = device.geometry(&file)?;
        let mut first = Aligned::zeroed(geometry.block)?;
        file.read_exact_at(first.bytes_mut(), 0)?;
        let data_start = data_start(first.bytes())
            .map_err(|what| io::Error::new(ErrorKind::InvalidData, what))?;
        Ok(Self {
            file,
            geometry,
            data_start,
        })
    }
}

/// Maps `file`, whose bytes are `bytes`, and checks the places against the device: the extents
/// add up to the file, each is a place a copy may be written at (see [`check_places`]) and the
/// device holds `bytes` there. `raw` is opened on the first need.
fn map_and_check(
    mapper: &dyn Mapper,
    which: Which,
    file: &File,
    bytes: &[u8],
    device: &Device,
    raw: &mut Option<Raw>,
) -> io::Result<Vec<Extent>> {
    let bad = |what: &'static str| io::Error::new(ErrorKind::InvalidData, what);
    let extents = mapper.map(which, file)?;
    if extents.iter().map(|extent| extent.len).sum::<u64>() != FILE_SIZE as u64
        || extents.iter().any(|extent| extent.len == 0)
    {
        return Err(bad(
            "the places the file system gave do not add up to the file",
        ));
    }
    let raw = match raw {
        Some(raw) => raw,
        None => raw.insert(Raw::open(device)?),
    };
    check_places(&extents, raw.geometry, raw.data_start).map_err(bad)?;
    if read_extents(&raw.file, &extents)?.bytes() != bytes {
        return Err(bad(
            "the card does not hold the file's bytes where the file system said",
        ));
    }
    Ok(extents)
}

/// Reads the two copies in `boot`, where the partition is mounted, and says what it found.
///
/// Both files are read whole if they are there at [`FILE_SIZE`] and, each, mapped and checked
/// against `device`, which is opened only if there is a file to check, and read-only. When both
/// are mapped, their places must not overlap. Never panics, and writes nothing. A file that is
/// missing is no trouble (the first save makes it), nor is one of another size; a file that cannot
/// be read or mapped, or whose mapping is not true or not a place a copy may be written, two
/// copies that overlap, and a copy of a version this build does not know, are
/// [`BootRead::trouble`], and the bytes that were read still give the state to restore (but never
/// that of a copy of an unknown version).
pub fn read_at_boot(boot: &Path, device: &Device, mapper: &dyn Mapper) -> BootRead {
    let dir = boot.join(DIR);
    let mut bytes: [Option<Vec<u8>>; 2] = [None, None];
    let mut held: [Option<Held>; 2] = [None, None];
    let mut trouble: Option<String> = None;
    let mut raw: Option<Raw> = None;
    for which in BOTH {
        let at = index(which);
        let problem = |what: &dyn fmt::Display| format!("copy {}: {what}", which.letter());
        match read_copy(&dir.join(file_name(which))) {
            Ok(Copy::Missing) => {}
            // Not a copy, but there: a start that finds no whole copy says so.
            Ok(Copy::WrongSize) => bytes[at] = Some(Vec::new()),
            Ok(Copy::Whole(data, file)) => {
                if foreign_version(&data).is_some() {
                    trouble.get_or_insert_with(|| {
                        problem(&"it was written by a build of another format version")
                    });
                }
                match map_and_check(mapper, which, &file, &data, device, &mut raw) {
                    Ok(extents) => {
                        held[at] = Some(Held {
                            extents,
                            digest: digest(&data),
                        });
                    }
                    Err(error) => {
                        trouble.get_or_insert_with(|| problem(&error));
                    }
                }
                bytes[at] = Some(data);
            }
            Err(error) => {
                trouble.get_or_insert_with(|| problem(&error));
                bytes[at] = Some(Vec::new());
            }
        }
    }
    if let [Some(a), Some(b)] = &held {
        let places: Vec<Extent> = a.extents.iter().chain(&b.extents).copied().collect();
        if overlap(&places) {
            trouble.get_or_insert_with(|| {
                "the two copies' places overlap: the file system is not sound".to_owned()
            });
        }
    }
    let (store, loaded) = Store::load(bytes[0].as_deref(), bytes[1].as_deref());
    BootRead {
        loaded,
        store,
        held,
        geometry: raw.map(|raw| raw.geometry),
        trouble,
    }
}

/// Makes the two copies in `boot`, where the partition is mounted writable, and reads them as
/// [`read_at_boot`] does.
///
/// Makes the folder if it is not there. Each file that is missing or not [`FILE_SIZE`] bytes is
/// written whole with its [`fill`] and synced; a file of the right size is never opened for
/// writing, whatever it holds. Then the folder is synced, and the two files are read, mapped and
/// checked in the same mount. An error is the first thing that could not be made or written (the
/// card's, in its own words); what is on the card then is some of the files and no more.
pub fn create(boot: &Path, device: &Device, mapper: &dyn Mapper) -> io::Result<BootRead> {
    let dir = boot.join(DIR);
    fs::create_dir_all(&dir)?;
    for which in BOTH {
        let path = dir.join(file_name(which));
        match fs::metadata(&path) {
            Ok(meta) if meta.len() == FILE_SIZE as u64 => continue,
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;
        file.write_all(&fill(which))?;
        file.sync_all()?;
    }
    File::open(&dir)?.sync_all()?;
    Ok(read_at_boot(boot, device, mapper))
}

/// The copies as the partition device holds them: a [`Medium`] that reads and writes the bytes
/// where they lie, and no more than that.
///
/// It knows, for each copy, where its bytes are and the SHA-256 of the window they make as it was
/// last known: from the read that made it, then from each write it did itself. A write checks that
/// first. Its places are whole logical blocks of the device ([`check_places`]), and it reads and
/// writes them as the device's [`Device`] says (directly, on the board).
pub struct RawMedium {
    /// The partition device.
    device: Device,
    /// The device's logical block size: what the frame is padded to.
    block: usize,
    /// Where each copy's bytes lie on it.
    extents: [Vec<Extent>; 2],
    /// What each copy's window last held, as a SHA-256.
    digest: Mutex<[[u8; 32]; 2]>,
}

impl fmt::Debug for RawMedium {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("RawMedium")
            .field("extents", &[self.extents[0].len(), self.extents[1].len()])
            .finish_non_exhaustive()
    }
}

impl RawMedium {
    /// The digests, locked; a lock that a panic poisoned still holds whole digests.
    fn digests(&self) -> std::sync::MutexGuard<'_, [[u8; 32]; 2]> {
        self.digest.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Medium for RawMedium {
    /// The copy's whole window, read from the device (opened for it, and read directly on the
    /// board, so that no page the cache holds stands in for the card).
    fn read(&self, which: Which) -> io::Result<Vec<u8>> {
        let device = self.device.open(false)?;
        Ok(read_extents(&device, &self.extents[index(which)])?
            .bytes()
            .to_vec())
    }

    /// Overwrites the start of the copy with `frame`, padded with zeros to a multiple of the
    /// device's logical block size, at the copy's extents and nowhere else, and syncs the device.
    ///
    /// The copy's whole window is read back first and must be what it was last known to be (the
    /// digest of the read that mapped it, or of the last write that did): if the bytes changed
    /// under it, or the device cannot be read, nothing is written and the error says so. The
    /// window is read and written directly (on the board), in an aligned buffer, at offsets and in
    /// lengths that are whole blocks, so that not a sector beside the copy's is written. A write
    /// that fails part of the way leaves the copy torn, which is the one that is not the newest,
    /// and the digest is not updated, so that nothing more is written to it either.
    fn write(&self, which: Which, frame: &[u8]) -> io::Result<()> {
        let at = index(which);
        let padded = frame.len().next_multiple_of(self.block);
        if padded > FILE_SIZE {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "the frame is longer than a copy",
            ));
        }
        let device = self.device.open(true)?;
        let mut window = read_extents(&device, &self.extents[at])?;
        if digest(window.bytes()) != self.digests()[at] {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "the copy on the card is not what it was left as",
            ));
        }
        let bytes = window.bytes_mut();
        bytes[..frame.len()].copy_from_slice(frame);
        bytes[frame.len()..padded].fill(0);
        write_extents(&device, &self.extents[at], &bytes[..padded])?;
        device.sync_all()?;
        self.digests()[at] = digest(window.bytes());
        Ok(())
    }
}

/// Why a use of the card did not happen.
#[derive(Debug)]
pub enum CardError {
    /// The card was not given: a fatal error's rescue has it, or another use has had it for longer
    /// than a claim waits. Nothing was done, and a later try may be given it.
    Refused(io::Error),
    /// The card was given and the use failed (the mount, say). It is not tried again.
    Failed(io::Error),
}

impl fmt::Display for CardError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CardError::Refused(error) | CardError::Failed(error) => error.fmt(out),
        }
    }
}

/// The card, as init lends it to the saver: one claim for the raw writes, and one writable mount
/// for the creation. Both block, so they are called from the pool or from init's own thread.
pub trait CardUse: Send + Sync {
    /// Runs `work` while the card is claimed (the same claim every other writer goes by: refused
    /// while a fatal error's rescue has it, waiting for another use for a few seconds) and the
    /// partition is not mounted. `work` has not run if the card was not given.
    fn claimed(&self, work: &mut dyn FnMut()) -> Result<(), CardError>;

    /// Mounts the partition writable, once, through the same claim, runs `work` on the directory
    /// it is at, syncs and unmounts. `work` has not run if the card was not given or the mount failed.
    fn mounted_writable(&self, work: &mut dyn FnMut(&Path)) -> Result<(), CardError>;
}

/// The card of a board that has none to lend (a test that never saves, and any board whose card
/// was not read): every use is refused as unsupported, and the work does not run.
pub struct NoCardUse;

impl CardUse for NoCardUse {
    fn claimed(&self, _: &mut dyn FnMut()) -> Result<(), CardError> {
        Err(CardError::Failed(unsupported()))
    }

    fn mounted_writable(&self, _: &mut dyn FnMut(&Path)) -> Result<(), CardError> {
        Err(CardError::Failed(unsupported()))
    }
}

/// The error of a card that is not there to use.
fn unsupported() -> io::Error {
    io::Error::new(ErrorKind::Unsupported, "this board has no card to lend")
}

/// The saver's writer for the real card: the two copies, kept in place through [`RawMedium`], with
/// the one creation done on the first save of a card that has not both files.
pub struct CardWriter {
    /// How the card is claimed and mounted.
    card: Arc<dyn CardUse>,
    /// The partition device.
    device: Device,
    /// Where files lie, for the creation's own mapping.
    mapper: Box<dyn Mapper + Send + Sync>,
    /// What is known of the copies' sequences.
    store: Store,
    /// The copies in place; `None` until both exist and are mapped.
    medium: Option<RawMedium>,
    /// Why nothing is to be written, if the read this writer started from found a reason (see
    /// [`BootRead::trouble`]): then every write is refused, and nothing is made or written, so that
    /// a copy of a build that is newer than this one, or a file system that is not sound, is never
    /// touched. The saver knows it too and never calls; this is the writer's own guard.
    trouble: Option<String>,
}

impl CardWriter {
    /// A writer that goes on from `read` (which [`read_at_boot`] made): when the copies are
    /// complete it writes in place at once, and otherwise the first save makes them.
    pub fn new(
        card: Arc<dyn CardUse>,
        device: Device,
        mapper: Box<dyn Mapper + Send + Sync>,
        read: &BootRead,
    ) -> Self {
        Self {
            store: read.store(),
            medium: read.medium(&device),
            trouble: read.trouble().map(str::to_owned),
            card,
            device,
            mapper,
        }
    }

    /// Makes the copies in the one writable mount, and takes up the places they are mapped at.
    /// `Err` is what [`Written`] says of the failure.
    fn make_copies(&mut self) -> Result<(), Written> {
        let (device, mapper) = (&self.device, &self.mapper);
        let mut made = None;
        let used = self.card.mounted_writable(&mut |boot| {
            made = Some(create(boot, device, mapper.as_ref()));
        });
        match used {
            Ok(()) => {}
            Err(CardError::Refused(error)) => {
                return Err(Written::Later(format!("the card was not given: {error}")));
            }
            Err(CardError::Failed(error)) => {
                return Err(Written::Off(format!(
                    "the card could not be mounted to make the copies: {error}"
                )));
            }
        }
        let read = match made {
            Some(Ok(read)) => read,
            Some(Err(error)) => {
                return Err(Written::Off(format!(
                    "the copies could not be made: {error}"
                )));
            }
            None => {
                return Err(Written::Off(
                    "the copies could not be made: the card did not run the work".to_owned(),
                ));
            }
        };
        if let Some(trouble) = read.trouble() {
            return Err(Written::Off(trouble.to_owned()));
        }
        let Some(medium) = read.medium(&self.device) else {
            return Err(Written::Off(
                "the copies were made and could not be found again".to_owned(),
            ));
        };
        log::info!("state: made the two copies on the card");
        self.store = read.store();
        self.medium = Some(medium);
        Ok(())
    }
}

impl Writer for CardWriter {
    /// Saves `payload`: makes the copies first if the card has not both, then, under the card
    /// claim, writes it in place into the copy that is not the newest ([`Store::save`]).
    fn write(&mut self, payload: &[u8]) -> Written {
        if let Some(why) = &self.trouble {
            return Written::Off(why.clone());
        }
        if self.medium.is_none()
            && let Err(refusal) = self.make_copies()
        {
            return refusal;
        }
        let Some(medium) = &self.medium else {
            return Written::Off("the copies are not in place".to_owned());
        };
        let store = &mut self.store;
        let mut saved = None;
        let used = self.card.claimed(&mut || {
            saved = Some(store.save(medium, payload));
        });
        match (used, saved) {
            (Err(CardError::Refused(error)), _) => {
                Written::Later(format!("the card was not given: {error}"))
            }
            (Err(CardError::Failed(error)), _) => {
                Written::Off(format!("the card could not be used: {error}"))
            }
            (Ok(()), Some(Ok((which, seq)))) => Written::Saved(which, seq),
            (Ok(()), Some(Err(SaveError::Write(error)))) => Written::Off(format!(
                "writing the copy failed ({error}); the other copy is untouched"
            )),
            (Ok(()), Some(Err(SaveError::Refused))) => {
                Written::Off("the settings are not a payload a copy may hold".to_owned())
            }
            (Ok(()), None) => Written::Off("the card did not run the write".to_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::super::format::{encode_payload, frame};
    use super::super::store::NoCopy;
    use super::super::{Saved, SavedName};
    use super::*;
    use qb_dns::OwnerSide;

    /// The byte that a test device is filled with before anything is placed in it, so that a byte
    /// that was not meant to change is told from one that was.
    const NOISE: u8 = 0xA5;

    /// How many noise-filled file sizes the device holds.
    const DEVICE_FILES: usize = 8;

    /// The bytes per sector of the file system on the test device, and so the unit of its boot
    /// sector's counts.
    const FAT_SECTOR: usize = 512;

    /// The reserved sectors, the tables and their size (in sectors) that the test device's boot
    /// sector tells: the file system's own area is the first 12,288 bytes of the device.
    const FAT_RESERVED: u16 = 8;
    const FAT_TABLES: u8 = 2;
    const FAT_TABLE_SECTORS: u32 = 8;

    /// Where the data region of the test device begins, which is what its boot sector tells.
    const FAT_DATA: u64 =
        (FAT_RESERVED as u64 + FAT_TABLES as u64 * FAT_TABLE_SECTORS as u64) * FAT_SECTOR as u64;

    /// A FAT32 boot sector of the layout above, padded to a sector.
    fn boot_sector() -> Vec<u8> {
        fat_boot_sector(512, FAT_RESERVED, FAT_TABLES, 0, 0, FAT_TABLE_SECTORS)
    }

    /// A boot sector of a FAT file system: the sector size, the reserved sectors, the number of
    /// tables, the root directory's entries (FAT12 and FAT16), and the table size in sectors (the
    /// 16-bit field if it fits, else the FAT32 one, as the format has it).
    fn fat_boot_sector(
        bytes_per_sector: u16,
        reserved: u16,
        tables: u8,
        root_entries: u16,
        table16: u16,
        table32: u32,
    ) -> Vec<u8> {
        let mut sector = vec![0u8; 512];
        sector[11..13].copy_from_slice(&bytes_per_sector.to_le_bytes());
        sector[13] = 1;
        sector[14..16].copy_from_slice(&reserved.to_le_bytes());
        sector[16] = tables;
        sector[17..19].copy_from_slice(&root_entries.to_le_bytes());
        sector[22..24].copy_from_slice(&table16.to_le_bytes());
        sector[36..40].copy_from_slice(&table32.to_le_bytes());
        sector[510] = 0x55;
        sector[511] = 0xAA;
        sector
    }

    /// What the device holds before anything is placed in it: the boot sector, then noise.
    fn fresh_device() -> Vec<u8> {
        let mut bytes = vec![NOISE; DEVICE_FILES * FILE_SIZE];
        bytes[..512].copy_from_slice(&boot_sector());
        bytes
    }

    /// A boot partition as a folder, and the device as a plain file that holds a boot sector and
    /// then noise.
    struct Card {
        _dir: tempfile::TempDir,
        boot: PathBuf,
        device: PathBuf,
    }

    impl Card {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let boot = dir.path().join("boot");
            fs::create_dir(&boot).unwrap();
            let device = dir.path().join("device");
            fs::write(&device, fresh_device()).unwrap();
            Self {
                _dir: dir,
                boot,
                device,
            }
        }

        /// The device as the code under test is given it: a plain file with 512-byte blocks, not
        /// read or written directly.
        fn dev(&self) -> Device {
            Device::plain_file(&self.device, 512)
        }

        fn state_dir(&self) -> PathBuf {
            self.boot.join(DIR)
        }

        fn file(&self, which: Which) -> PathBuf {
            self.state_dir().join(file_name(which))
        }

        fn device_bytes(&self) -> Vec<u8> {
            fs::read(&self.device).unwrap()
        }
    }

    /// A mapper that does what the file system would: it places the file's bytes in the device at
    /// the offset it is given for the copy (as if the file system had put them there), and says
    /// where they are. With `split` the file lies in two runs with a gap between them.
    struct Placing {
        device: PathBuf,
        at: [u64; 2],
        split: bool,
    }

    impl Placing {
        fn at(card: &Card) -> Self {
            Self {
                device: card.device.clone(),
                at: [FILE_SIZE as u64, 4 * FILE_SIZE as u64],
                split: false,
            }
        }

        fn split(card: &Card) -> Self {
            Self {
                split: true,
                ..Self::at(card)
            }
        }
    }

    impl Mapper for Placing {
        fn map(&self, which: Which, file: &File) -> io::Result<Vec<Extent>> {
            let mut data = vec![0; FILE_SIZE];
            file.read_exact_at(&mut data, 0)?;
            let device = OpenOptions::new().write(true).open(&self.device)?;
            let base = self.at[index(which)];
            if !self.split {
                device.write_all_at(&data, base)?;
                return Ok(vec![Extent {
                    offset: base,
                    len: FILE_SIZE as u64,
                }]);
            }
            let half = FILE_SIZE / 2;
            let second = base + FILE_SIZE as u64;
            device.write_all_at(&data[..half], base)?;
            device.write_all_at(&data[half..], second)?;
            Ok(vec![
                Extent {
                    offset: base,
                    len: half as u64,
                },
                Extent {
                    offset: second,
                    len: half as u64,
                },
            ])
        }
    }

    /// A mapper that says the file lies `by` bytes from where it really does.
    struct Lying {
        truth: Placing,
        by: u64,
    }

    impl Mapper for Lying {
        fn map(&self, which: Which, file: &File) -> io::Result<Vec<Extent>> {
            let mut extents = self.truth.map(which, file)?;
            for extent in &mut extents {
                extent.offset += self.by;
            }
            Ok(extents)
        }
    }

    /// A mapper that cannot say where a file is.
    struct Unknowing;

    impl Mapper for Unknowing {
        fn map(&self, _: Which, _: &File) -> io::Result<Vec<Extent>> {
            Err(io::Error::from_raw_os_error(libc::EINVAL))
        }
    }

    /// A state that differs from every other `n`.
    fn state(n: u8) -> Saved {
        Saved {
            names: vec![SavedName {
                name: format!("host-{n}.example.org").into(),
                side: OwnerSide::Refuse,
                set_unix: Some(u64::from(n)),
            }],
            ..Saved::default()
        }
    }

    fn payload(n: u8) -> Vec<u8> {
        encode_payload(&state(n)).unwrap()
    }

    /// Writes copy `which` into the card's folder as a whole file holding a frame of `seq` and
    /// `payload`.
    fn put_frame(card: &Card, which: Which, seq: u64, payload: &[u8]) {
        fs::create_dir_all(card.state_dir()).unwrap();
        let mut file = frame(seq, payload);
        file.resize(FILE_SIZE, 0x33);
        fs::write(card.file(which), file).unwrap();
    }

    #[test]
    fn blocks_that_follow_each_other_are_one_extent_and_a_gap_starts_another() {
        // 16 blocks of 4096 bytes: 10, 11, 12 and then 40, 41, then 7, and on to the end.
        let places = [
            10, 11, 12, 40, 41, 7, 8, 9, 100, 101, 102, 103, 104, 105, 106, 107,
        ];
        let extents = map_with(16 * 4096, 4096, |n| Ok(places[n as usize])).unwrap();
        let run = |first: u64, blocks: u64| Extent {
            offset: first * 4096,
            len: blocks * 4096,
        };
        assert_eq!(extents, [run(10, 3), run(40, 2), run(7, 3), run(100, 8)]);
        let total: u64 = extents.iter().map(|extent| extent.len).sum();
        assert_eq!(total, 16 * 4096, "the runs are the whole file");
    }

    #[test]
    fn the_file_system_that_counts_in_sectors_gives_one_run_per_contiguous_file() {
        let extents = map_with(FILE_SIZE as u64, 512, |n| Ok(2000 + n)).unwrap();
        assert_eq!(
            extents,
            [Extent {
                offset: 2000 * 512,
                len: FILE_SIZE as u64
            }]
        );
    }

    #[test]
    fn a_block_with_no_place_is_an_error_and_so_is_one_the_file_system_cannot_tell() {
        let hole = map_with(4 * 512, 512, |n| Ok(if n == 2 { 0 } else { 50 + n })).unwrap_err();
        assert_eq!(hole.kind(), ErrorKind::InvalidData, "{hole}");
        let refused = map_with(4 * 512, 512, |n| {
            if n == 1 {
                Err(io::Error::from_raw_os_error(libc::EPERM))
            } else {
                Ok(50 + n)
            }
        })
        .unwrap_err();
        assert_eq!(refused.raw_os_error(), Some(libc::EPERM));
    }

    #[test]
    fn a_block_size_that_does_not_divide_the_file_is_an_error() {
        for size in [0, 3, 1000, 8192] {
            let error = map_with(4096, size, |n| Ok(n + 1)).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidData, "size {size}");
        }
    }

    #[test]
    fn the_fill_is_no_frame_no_zeros_and_differs_by_copy() {
        let (a, b) = (fill(Which::A), fill(Which::B));
        assert_eq!((a.len(), b.len()), (FILE_SIZE, FILE_SIZE));
        assert_ne!(a, b);
        assert_eq!(a, fill(Which::A), "the same bytes every time");
        for fill in [&a, &b] {
            assert!(fill.iter().any(|&byte| byte != 0));
            assert!(
                fill.chunks(4096)
                    .all(|block| block.iter().any(|&byte| byte != 0)),
                "no block is all zeros"
            );
            assert!(super::super::format::read_frame(fill).is_none());
            assert_ne!(&fill[..8], b"QBPSTATE");
        }
    }

    #[test]
    fn a_card_with_no_folder_has_no_copies_and_no_trouble() {
        let card = Card::new();
        let read = read_at_boot(&card.boot, &card.dev(), &Placing::at(&card));
        assert_eq!(read.loaded(), &Loaded::Empty(NoCopy::Absent));
        assert_eq!(read.trouble(), None);
        assert!(!read.complete());
        assert!(read.medium(&card.dev()).is_none());
        assert_eq!(card.device_bytes(), fresh_device(), "nothing placed");
    }

    #[test]
    fn creation_makes_the_folder_and_both_files_at_file_size_with_their_fills() {
        let card = Card::new();
        let read = create(&card.boot, &card.dev(), &Placing::at(&card)).unwrap();
        for which in BOTH {
            assert_eq!(fs::read(card.file(which)).unwrap(), fill(which));
        }
        assert_eq!(
            read.loaded(),
            &Loaded::Empty(NoCopy::NotWhole),
            "a fill is no copy"
        );
        assert!(read.complete(), "{read:?}");
        assert_eq!(read.store().newest(), None);
    }

    #[test]
    fn creation_of_a_missing_copy_keeps_a_right_sized_one_byte_for_byte() {
        let card = Card::new();
        put_frame(&card, Which::B, 7, &payload(3));
        let kept = fs::read(card.file(Which::B)).unwrap();
        let read = create(&card.boot, &card.dev(), &Placing::at(&card)).unwrap();
        assert_eq!(
            fs::read(card.file(Which::B)).unwrap(),
            kept,
            "b is untouched"
        );
        assert_eq!(fs::read(card.file(Which::A)).unwrap(), fill(Which::A));
        let Loaded::Found(found) = read.loaded() else {
            panic!("the kept copy was not found: {read:?}");
        };
        assert_eq!(
            (found.which, found.seq, &found.saved),
            (Which::B, 7, &state(3))
        );
        assert_eq!(read.store().newest(), Some((Which::B, 7)));
    }

    #[test]
    fn creation_keeps_a_right_sized_copy_that_is_not_whole_as_well() {
        let card = Card::new();
        fs::create_dir_all(card.state_dir()).unwrap();
        let odd = vec![0x77; FILE_SIZE];
        fs::write(card.file(Which::A), &odd).unwrap();
        create(&card.boot, &card.dev(), &Placing::at(&card)).unwrap();
        assert_eq!(fs::read(card.file(Which::A)).unwrap(), odd);
        assert_eq!(fs::read(card.file(Which::B)).unwrap(), fill(Which::B));
    }

    #[test]
    fn creation_makes_a_copy_of_the_wrong_size_again() {
        let card = Card::new();
        fs::create_dir_all(card.state_dir()).unwrap();
        fs::write(card.file(Which::A), b"cut short").unwrap();
        fs::write(card.file(Which::B), vec![1; FILE_SIZE + 512]).unwrap();
        let read = create(&card.boot, &card.dev(), &Placing::at(&card)).unwrap();
        assert_eq!(fs::read(card.file(Which::A)).unwrap(), fill(Which::A));
        assert_eq!(fs::read(card.file(Which::B)).unwrap(), fill(Which::B));
        assert!(read.complete());
    }

    #[test]
    fn a_boot_read_finds_the_newest_whole_copy_and_maps_both() {
        let card = Card::new();
        put_frame(&card, Which::A, 4, &payload(1));
        put_frame(&card, Which::B, 5, &payload(2));
        let read = read_at_boot(&card.boot, &card.dev(), &Placing::split(&card));
        let Loaded::Found(found) = read.loaded() else {
            panic!("nothing found: {read:?}");
        };
        assert_eq!(
            (found.which, found.seq, &found.saved),
            (Which::B, 5, &state(2))
        );
        assert_eq!(found.payload, payload(2));
        assert!(read.complete());
        assert_eq!(read.trouble(), None);
    }

    #[test]
    fn a_copy_of_the_wrong_size_is_no_copy_and_no_trouble() {
        let card = Card::new();
        put_frame(&card, Which::A, 4, &payload(1));
        fs::write(card.file(Which::B), b"short").unwrap();
        let read = read_at_boot(&card.boot, &card.dev(), &Placing::at(&card));
        let Loaded::Found(found) = read.loaded() else {
            panic!("nothing found: {read:?}");
        };
        assert_eq!(found.which, Which::A);
        assert_eq!(read.trouble(), None);
        assert!(!read.complete(), "the first save makes b again");
        // Alone, the short file is a copy that is not whole.
        fs::remove_file(card.file(Which::A)).unwrap();
        let read = read_at_boot(&card.boot, &card.dev(), &Placing::at(&card));
        assert_eq!(read.loaded(), &Loaded::Empty(NoCopy::NotWhole));
    }

    #[test]
    fn a_mapping_that_points_at_other_bytes_is_not_trusted() {
        let card = Card::new();
        put_frame(&card, Which::A, 1, &payload(1));
        put_frame(&card, Which::B, 2, &payload(2));
        let lying = Lying {
            truth: Placing::at(&card),
            by: 512,
        };
        let read = read_at_boot(&card.boot, &card.dev(), &lying);
        assert!(read.trouble().is_some(), "{read:?}");
        assert!(!read.complete());
        assert!(read.medium(&card.dev()).is_none());
        // What was read through the file system still gives the state to restore.
        let Loaded::Found(found) = read.loaded() else {
            panic!("nothing found: {read:?}");
        };
        assert_eq!((found.which, &found.saved), (Which::B, &state(2)));
    }

    #[test]
    fn places_that_do_not_add_up_to_the_file_are_not_trusted() {
        struct Short(Placing);
        impl Mapper for Short {
            fn map(&self, which: Which, file: &File) -> io::Result<Vec<Extent>> {
                let mut extents = self.0.map(which, file)?;
                extents[0].len -= 512;
                Ok(extents)
            }
        }
        let card = Card::new();
        put_frame(&card, Which::A, 1, &payload(1));
        let read = read_at_boot(&card.boot, &card.dev(), &Short(Placing::at(&card)));
        assert!(read.trouble().is_some());
    }

    #[test]
    fn a_card_that_cannot_say_where_a_file_is_is_trouble_and_still_restores() {
        let card = Card::new();
        put_frame(&card, Which::A, 3, &payload(9));
        let read = read_at_boot(&card.boot, &card.dev(), &Unknowing);
        let trouble = read.trouble().expect("trouble");
        assert!(trouble.starts_with("copy a: "), "{trouble}");
        assert!(matches!(read.loaded(), Loaded::Found(_)));
        assert!(!read.complete());
    }

    #[test]
    fn a_device_that_cannot_be_opened_is_trouble() {
        let card = Card::new();
        put_frame(&card, Which::A, 3, &payload(9));
        let read = read_at_boot(
            &card.boot,
            &Device::plain_file(card.boot.join("no-such-device"), 512),
            &Placing::at(&card),
        );
        assert!(read.trouble().is_some());
    }

    /// A card with both copies made, a medium over them, and the device as it is then.
    fn made(card: &Card, mapper: &dyn Mapper) -> (RawMedium, Vec<u8>) {
        let read = create(&card.boot, &card.dev(), mapper).unwrap();
        let medium = read.medium(&card.dev()).expect("complete");
        (medium, card.device_bytes())
    }

    #[test]
    fn a_write_lands_at_the_extents_of_its_copy_and_nowhere_else() {
        let card = Card::new();
        let (medium, before) = made(&card, &Placing::split(&card));
        let frame = frame(1, &payload(1));
        medium.write(Which::A, &frame).unwrap();
        let after = card.device_bytes();
        let [first, second] = [
            Extent {
                offset: FILE_SIZE as u64,
                len: FILE_SIZE as u64 / 2,
            },
            Extent {
                offset: 2 * FILE_SIZE as u64,
                len: FILE_SIZE as u64 / 2,
            },
        ];
        let padded = frame.len().next_multiple_of(SECTOR);
        assert!(
            padded < first.len as usize,
            "the test's frame lies in the first run"
        );
        let (start, end) = (first.offset as usize, first.offset as usize + padded);
        assert_eq!(&after[start..start + frame.len()], &frame[..]);
        assert!(
            after[start + frame.len()..end]
                .iter()
                .all(|&byte| byte == 0),
            "zero padding"
        );
        // Every other byte of the device is what it was.
        for (at, (was, is)) in before.iter().zip(&after).enumerate() {
            if !(start..end).contains(&at) {
                assert_eq!(was, is, "byte {at} changed");
            }
        }
        // Copy b's window and the second run of a are untouched, and the read gives the frame.
        let read = medium.read(Which::A).unwrap();
        assert_eq!(&read[..frame.len()], &frame[..]);
        assert!(second.len > 0);
    }

    #[test]
    fn a_frame_that_runs_into_the_second_extent_is_written_over_both() {
        let card = Card::new();
        let (medium, _) = made(&card, &Placing::split(&card));
        // A payload long enough to pass the first run: one name per ... a filler of known bytes.
        let long = vec![0xEE; FILE_SIZE / 2 + 700];
        medium.write(Which::B, &long).unwrap();
        let window = medium.read(Which::B).unwrap();
        assert_eq!(&window[..long.len()], &long[..]);
        let padded = long.len().next_multiple_of(SECTOR);
        assert!(window[long.len()..padded].iter().all(|&byte| byte == 0));
        assert_eq!(
            &window[padded..],
            &fill(Which::B)[padded..],
            "the tail is what it was"
        );
    }

    #[test]
    fn the_frame_is_padded_to_a_whole_number_of_sectors() {
        let card = Card::new();
        let (medium, before) = made(&card, &Placing::at(&card));
        medium.write(Which::A, &[0xAB; 513]).unwrap();
        let after = card.device_bytes();
        let start = FILE_SIZE;
        assert_eq!(&after[start..start + 513], &[0xAB; 513][..]);
        assert!(
            after[start + 513..start + 1024]
                .iter()
                .all(|&byte| byte == 0)
        );
        assert_eq!(
            after[start + 1024..],
            before[start + 1024..],
            "not a byte past the second sector"
        );
        assert_eq!(after[..start], before[..start]);
    }

    #[test]
    fn a_write_is_refused_when_the_card_changed_under_it_and_writes_nothing() {
        let card = Card::new();
        let (medium, _) = made(&card, &Placing::at(&card));
        // Something else wrote one byte inside the copy's window.
        let device = OpenOptions::new().write(true).open(&card.device).unwrap();
        device
            .write_all_at(&[0x42], FILE_SIZE as u64 + 30_000)
            .unwrap();
        drop(device);
        let before = card.device_bytes();
        let error = medium.write(Which::A, &frame(1, &payload(1))).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData, "{error}");
        assert_eq!(card.device_bytes(), before, "not a byte was written");
        // The other copy is still good to write.
        medium.write(Which::B, &frame(1, &payload(1))).unwrap();
    }

    #[test]
    fn a_write_that_follows_a_write_of_its_own_passes_the_check() {
        let card = Card::new();
        let (medium, _) = made(&card, &Placing::at(&card));
        medium.write(Which::A, &frame(1, &payload(1))).unwrap();
        medium.write(Which::A, &frame(2, &payload(2))).unwrap();
        let window = medium.read(Which::A).unwrap();
        assert_eq!(
            &window[..frame(2, &payload(2)).len()],
            &frame(2, &payload(2))[..]
        );
    }

    #[test]
    fn a_write_longer_than_a_copy_is_refused_before_anything_is_written() {
        let card = Card::new();
        let (medium, before) = made(&card, &Placing::at(&card));
        let error = medium.write(Which::A, &vec![1; FILE_SIZE + 1]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert_eq!(card.device_bytes(), before);
    }

    #[test]
    fn what_the_medium_wrote_is_what_a_boot_read_finds() {
        let card = Card::new();
        let placing = Placing::split(&card);
        let (medium, _) = made(&card, &placing);
        let mut store = Store::load(None, None).0;
        store.save(&medium, &payload(5)).unwrap();
        // The file system's view of the files is not changed by a raw write; a fresh boot of the
        // board reads the files through it again, so mirror the device's bytes into the files.
        for which in BOTH {
            fs::write(card.file(which), medium.read(which).unwrap()).unwrap();
        }
        let read = read_at_boot(&card.boot, &card.dev(), &placing);
        let Loaded::Found(found) = read.loaded() else {
            panic!("nothing found: {read:?}");
        };
        assert_eq!(
            (found.which, found.seq, &found.saved),
            (Which::A, 1, &state(5))
        );
    }

    /// How a lent card answers.
    #[derive(Clone, Copy, PartialEq)]
    enum Answer {
        /// It runs the work.
        Gives,
        /// It does not give the card (a rescue has it).
        Refuses,
        /// It gives the card and the mount fails.
        FailsToMount,
    }

    /// A card claim that runs the work at once on a folder, counts its uses and can be told to
    /// refuse or to fail.
    struct Lent {
        boot: PathBuf,
        claims: AtomicUsize,
        mounts: AtomicUsize,
        answer: Mutex<Answer>,
    }

    impl Lent {
        fn new(card: &Card) -> Arc<Self> {
            Arc::new(Self {
                boot: card.boot.clone(),
                claims: AtomicUsize::new(0),
                mounts: AtomicUsize::new(0),
                answer: Mutex::new(Answer::Gives),
            })
        }

        fn answer(&self, now: Answer) {
            *self.answer.lock().unwrap() = now;
        }

        fn uses(&self) -> (usize, usize) {
            (
                self.claims.load(Ordering::SeqCst),
                self.mounts.load(Ordering::SeqCst),
            )
        }
    }

    impl CardUse for Lent {
        fn claimed(&self, work: &mut dyn FnMut()) -> Result<(), CardError> {
            if *self.answer.lock().unwrap() == Answer::Refuses {
                return Err(CardError::Refused(io::Error::other(
                    "a rescue has the card",
                )));
            }
            self.claims.fetch_add(1, Ordering::SeqCst);
            work();
            Ok(())
        }

        fn mounted_writable(&self, work: &mut dyn FnMut(&Path)) -> Result<(), CardError> {
            match *self.answer.lock().unwrap() {
                Answer::Refuses => {
                    return Err(CardError::Refused(io::Error::other(
                        "a rescue has the card",
                    )));
                }
                Answer::FailsToMount => {
                    return Err(CardError::Failed(io::Error::other("no such device")));
                }
                Answer::Gives => {}
            }
            self.mounts.fetch_add(1, Ordering::SeqCst);
            work(&self.boot);
            Ok(())
        }
    }

    /// A writer over `lent` that starts from `read`, with the copies placed as `Placing::at` does.
    fn writer(card: &Card, lent: &Arc<Lent>, read: &BootRead) -> CardWriter {
        CardWriter::new(lent.clone(), card.dev(), Box::new(Placing::at(card)), read)
    }

    #[test]
    fn the_first_save_makes_the_copies_once_and_then_writes_in_place_under_the_claim() {
        let card = Card::new();
        let lent = Lent::new(&card);
        let mut writer = writer(&card, &lent, &BootRead::absent());
        assert_eq!(writer.write(&payload(1)), Written::Saved(Which::A, 1));
        assert_eq!(
            lent.uses(),
            (1, 1),
            "one mount to make them, one claim to write"
        );
        assert_eq!(writer.write(&payload(2)), Written::Saved(Which::B, 2));
        assert_eq!(writer.write(&payload(3)), Written::Saved(Which::A, 3));
        assert_eq!(lent.uses(), (3, 1), "no mount after the first");
        // The files the creation made are as it made them: a save went to the device only.
        for which in BOTH {
            assert_eq!(fs::read(card.file(which)).unwrap(), fill(which));
        }
    }

    #[test]
    fn a_card_that_has_both_copies_is_written_at_once_with_no_mount() {
        let card = Card::new();
        put_frame(&card, Which::A, 8, &payload(1));
        put_frame(&card, Which::B, 9, &payload(2));
        let read = read_at_boot(&card.boot, &card.dev(), &Placing::at(&card));
        let lent = Lent::new(&card);
        let mut writer = writer(&card, &lent, &read);
        assert_eq!(writer.write(&payload(3)), Written::Saved(Which::A, 10));
        assert_eq!(lent.uses(), (1, 0));
    }

    #[test]
    fn a_refused_card_writes_and_creates_nothing_and_is_tried_again_later() {
        let card = Card::new();
        let lent = Lent::new(&card);
        lent.answer(Answer::Refuses);
        let mut writer = writer(&card, &lent, &BootRead::absent());
        assert!(matches!(writer.write(&payload(1)), Written::Later(_)));
        assert!(!card.state_dir().exists(), "nothing was created");
        lent.answer(Answer::Gives);
        assert_eq!(writer.write(&payload(1)), Written::Saved(Which::A, 1));
        // And a refused claim for the raw write is the same.
        lent.answer(Answer::Refuses);
        let before = card.device_bytes();
        assert!(matches!(writer.write(&payload(2)), Written::Later(_)));
        assert_eq!(card.device_bytes(), before);
    }

    #[test]
    fn a_mount_that_fails_turns_saving_off() {
        let card = Card::new();
        let lent = Lent::new(&card);
        lent.answer(Answer::FailsToMount);
        let mut writer = writer(&card, &lent, &BootRead::absent());
        let Written::Off(why) = writer.write(&payload(1)) else {
            panic!("saving stayed on");
        };
        assert!(why.contains("mounted"), "{why}");
    }

    #[test]
    fn a_card_that_changed_under_a_save_turns_saving_off_and_writes_nothing() {
        let card = Card::new();
        let lent = Lent::new(&card);
        let mut writer = writer(&card, &lent, &BootRead::absent());
        assert_eq!(writer.write(&payload(1)), Written::Saved(Which::A, 1));
        let device = OpenOptions::new().write(true).open(&card.device).unwrap();
        device
            .write_all_at(&[0x42], 4 * FILE_SIZE as u64 + 9_000)
            .unwrap();
        drop(device);
        let before = card.device_bytes();
        let Written::Off(why) = writer.write(&payload(2)) else {
            panic!("saving stayed on");
        };
        assert!(why.contains("other copy is untouched"), "{why}");
        assert_eq!(card.device_bytes(), before);
    }

    #[test]
    fn a_creation_that_cannot_map_a_kept_file_turns_saving_off_and_leaves_the_file_alone() {
        let card = Card::new();
        put_frame(&card, Which::A, 1, &payload(1));
        let lent = Lent::new(&card);
        let mut writer = CardWriter::new(
            lent.clone(),
            card.dev(),
            Box::new(Unknowing),
            &BootRead::absent(),
        );
        let kept = fs::read(card.file(Which::A)).unwrap();
        let Written::Off(why) = writer.write(&payload(2)) else {
            panic!("saving stayed on");
        };
        assert!(why.starts_with("copy a: "), "{why}");
        assert_eq!(fs::read(card.file(Which::A)).unwrap(), kept);
    }

    // ---- The device's geometry, direct and aligned transfers, the places a copy may lie at.

    /// The device as the code under test is given it, with `block`-byte logical blocks.
    fn dev_with(card: &Card, block: u32) -> Device {
        Device::plain_file(&card.device, block)
    }

    /// A mapper that puts copy a at `a` and copy b at `b` on the device (whole files, one run each).
    fn placing_at(card: &Card, a: u64, b: u64) -> Placing {
        Placing {
            at: [a, b],
            ..Placing::at(card)
        }
    }

    #[test]
    fn aligned_buffers_start_at_an_aligned_address_and_are_zeroed_and_as_long_as_asked() {
        let mut held = Vec::new();
        for len in [0, 1, 511, 512, 4096, 4097, FILE_SIZE, 3 * FILE_SIZE + 1] {
            let mut buffer = Aligned::zeroed(len).unwrap();
            assert_eq!(buffer.bytes().len(), len);
            assert_eq!(buffer.bytes().as_ptr() as usize % ALIGN, 0, "{len} bytes");
            assert!(buffer.bytes().iter().all(|&byte| byte == 0));
            buffer.bytes_mut().fill(0xEE);
            assert_eq!(buffer.bytes_mut().as_ptr() as usize % ALIGN, 0);
            // Held, so that the next ones are made from other memory, with other alignments.
            held.push(buffer);
        }
        for buffer in &held {
            assert_eq!(buffer.bytes().as_ptr() as usize % ALIGN, 0);
        }
        assert!(
            Aligned::zeroed(usize::MAX).is_err(),
            "too long for a buffer"
        );
    }

    #[test]
    fn the_data_region_begins_after_the_reserved_sectors_the_tables_and_a_fat16_root() {
        // FAT32: 32 reserved sectors, two tables of 1,000 sectors, 512 bytes a sector.
        let fat32 = fat_boot_sector(512, 32, 2, 0, 0, 1000);
        assert_eq!(data_start(&fat32), Ok((32 + 2 * 1000) * 512));
        // FAT16: the table size is the 16-bit field, and the root directory (512 entries of 32
        // bytes) lies between the tables and the data.
        let fat16 = fat_boot_sector(512, 4, 2, 512, 200, 0);
        assert_eq!(data_start(&fat16), Ok((4 + 2 * 200) * 512 + 512 * 32));
        // Another sector size scales every count.
        let big = fat_boot_sector(4096, 2, 2, 0, 0, 3);
        assert_eq!(data_start(&big), Ok((2 + 2 * 3) * 4096));
        // A longer buffer is the same (the device's block may be larger than the boot sector).
        let mut long = fat32.clone();
        long.resize(4096, 0);
        assert_eq!(data_start(&long), Ok((32 + 2 * 1000) * 512));
        assert_eq!(data_start(&boot_sector()), Ok(FAT_DATA));
    }

    #[test]
    fn a_sector_that_is_no_fat_boot_sector_has_no_data_region() {
        let good = fat_boot_sector(512, 32, 2, 0, 0, 1000);
        let mut no_signature = good.clone();
        no_signature[510] = 0;
        let mut odd_sector = good.clone();
        odd_sector[11..13].copy_from_slice(&500u16.to_le_bytes());
        let mut no_reserved = good.clone();
        no_reserved[14..16].fill(0);
        let mut no_tables = good.clone();
        no_tables[16] = 0;
        let no_table_size = fat_boot_sector(512, 32, 2, 0, 0, 0);
        for (name, sector) in [
            ("signature", no_signature),
            ("sector size", odd_sector),
            ("reserved", no_reserved),
            ("tables", no_tables),
            ("table size", no_table_size),
            ("noise", vec![NOISE; 512]),
            ("zeros", vec![0; 512]),
            ("short", good[..511].to_vec()),
            ("empty", Vec::new()),
        ] {
            assert!(data_start(&sector).is_err(), "{name}");
        }
    }

    #[test]
    fn places_are_whole_blocks_of_the_device_inside_it_and_past_the_file_systems_own_area() {
        let geometry = |block, size| Geometry { block, size };
        let at = |offset, len| Extent { offset, len };
        let ok = |places: &[Extent], block, size, start| {
            check_places(places, geometry(block, size), start)
        };
        let one = [at(8192, 4096)];
        assert_eq!(ok(&one, 512, 1 << 20, 4096), Ok(()));
        assert_eq!(
            ok(&one, 4096, 1 << 20, 8192),
            Ok(()),
            "right at the data region"
        );
        assert_eq!(ok(&[], 512, 1 << 20, 4096), Ok(()));
        // The block: an offset or a length that is not a multiple of it is refused (the unit of a
        // direct write), whichever it is.
        for places in [
            [at(8192 + 512, 4096)],
            [at(8192, 4096 + 512)],
            [at(8192, 100)],
        ] {
            let refused = ok(&places, 4096, 1 << 20, 4096).unwrap_err();
            assert!(refused.contains("block"), "{refused}");
        }
        assert_eq!(ok(&[at(8192 + 512, 4096)], 512, 1 << 20, 4096), Ok(()));
        // The end of the device: the last byte may be the copy's, one more may not, and a sum that
        // overflows is past the end.
        assert_eq!(ok(&[at(4096, 4096)], 512, 8192, 4096), Ok(()));
        let past = ok(&[at(4096, 4096 + 512)], 512, 8192, 4096).unwrap_err();
        assert!(past.contains("end of the device"), "{past}");
        assert!(ok(&[at(u64::MAX - 511, 512)], 512, u64::MAX, 4096).is_err());
        // The file system's own area: the first byte before the data region is refused.
        let own = ok(&[at(4096 - 512, 512)], 512, 1 << 20, 4096).unwrap_err();
        assert!(own.contains("own area"), "{own}");
        assert!(
            ok(&[at(0, 512)], 512, 1 << 20, 4096).is_err(),
            "the boot sector"
        );
        // One bad place among good ones is enough.
        assert!(ok(&[at(8192, 512), at(0, 512)], 512, 1 << 20, 4096).is_err());
    }

    #[test]
    fn extents_that_touch_do_not_overlap_and_extents_that_share_a_byte_do() {
        let at = |offset, len| Extent { offset, len };
        assert!(!overlap(&[]));
        assert!(!overlap(&[at(0, 512)]));
        assert!(
            !overlap(&[at(512, 512), at(0, 512)]),
            "adjacent, in any order"
        );
        assert!(!overlap(&[at(4096, 512), at(0, 512), at(1024, 512)]));
        assert!(overlap(&[at(0, 513), at(512, 512)]), "one byte shared");
        assert!(
            overlap(&[at(1024, 512), at(0, 4096)]),
            "one inside the other"
        );
        assert!(overlap(&[at(0, 512), at(0, 512)]), "the same place twice");
        assert!(overlap(&[at(0, 512), at(4096, 512), at(256, 512)]));
        assert!(overlap(&[at(u64::MAX - 10, 100), at(u64::MAX - 5, 1)]));
    }

    #[test]
    fn a_device_with_blocks_the_copies_are_not_written_in_is_trouble() {
        for block in [0, 256, 511, 1000, 8192] {
            let card = Card::new();
            put_frame(&card, Which::A, 1, &payload(1));
            let read = read_at_boot(&card.boot, &dev_with(&card, block), &Placing::at(&card));
            assert!(read.trouble().is_some(), "block {block}: {read:?}");
            assert!(read.medium(&dev_with(&card, block)).is_none());
        }
        for block in [512, 1024, 2048, 4096] {
            let card = Card::new();
            put_frame(&card, Which::A, 1, &payload(1));
            put_frame(&card, Which::B, 2, &payload(2));
            let read = read_at_boot(&card.boot, &dev_with(&card, block), &Placing::at(&card));
            assert_eq!(read.trouble(), None, "block {block}");
            assert!(
                read.medium(&dev_with(&card, block)).is_some(),
                "block {block}"
            );
        }
    }

    #[test]
    fn a_place_that_is_not_a_whole_number_of_the_devices_blocks_is_refused() {
        // The extents are sectors, the device's blocks are 4096 bytes: a file that starts at a
        // sector that is not a block's would be written in pieces of blocks that are not the copy's.
        let card = Card::new();
        put_frame(&card, Which::A, 1, &payload(1));
        put_frame(&card, Which::B, 2, &payload(2));
        let mapper = placing_at(&card, FILE_SIZE as u64 + 512, 4 * FILE_SIZE as u64);
        let read = read_at_boot(&card.boot, &dev_with(&card, 4096), &mapper);
        let trouble = read.trouble().expect("trouble");
        assert!(
            trouble.starts_with("copy a: ") && trouble.contains("block"),
            "{trouble}"
        );
        assert!(!read.complete());
        assert!(read.medium(&dev_with(&card, 4096)).is_none());
        // The same places are fine for a device of sectors.
        let card = Card::new();
        put_frame(&card, Which::A, 1, &payload(1));
        put_frame(&card, Which::B, 2, &payload(2));
        let mapper = placing_at(&card, FILE_SIZE as u64 + 512, 4 * FILE_SIZE as u64);
        let read = read_at_boot(&card.boot, &dev_with(&card, 512), &mapper);
        assert_eq!(read.trouble(), None);
    }

    #[test]
    fn a_place_in_the_file_systems_own_area_or_past_the_devices_end_is_not_trusted() {
        // In the reserved sectors and the tables (the boot sector says 12,288 bytes of them).
        let card = Card::new();
        put_frame(&card, Which::A, 1, &payload(1));
        let own = placing_at(&card, 4096, 4 * FILE_SIZE as u64);
        let read = read_at_boot(&card.boot, &card.dev(), &own);
        let trouble = read.trouble().expect("trouble");
        assert!(trouble.contains("own area"), "{trouble}");
        assert!(read.medium(&card.dev()).is_none());
        // Right at the start of the data region is the first place there is.
        let card = Card::new();
        put_frame(&card, Which::A, 1, &payload(1));
        let first = placing_at(&card, FAT_DATA, 4 * FILE_SIZE as u64);
        assert_eq!(
            read_at_boot(&card.boot, &card.dev(), &first).trouble(),
            None
        );
        // Past the end: the file system says a place the device does not have. It is refused
        // before the device is read there.
        let card = Card::new();
        put_frame(&card, Which::A, 1, &payload(1));
        let lying = Lying {
            truth: Placing::at(&card),
            by: (DEVICE_FILES * FILE_SIZE) as u64,
        };
        let read = read_at_boot(&card.boot, &card.dev(), &lying);
        let trouble = read.trouble().expect("trouble");
        assert!(trouble.contains("end of the device"), "{trouble}");
    }

    #[test]
    fn a_device_without_a_fat_boot_sector_is_trouble() {
        let card = Card::new();
        put_frame(&card, Which::A, 1, &payload(1));
        let device = OpenOptions::new().write(true).open(&card.device).unwrap();
        device.write_all_at(&[NOISE; 512], 0).unwrap();
        drop(device);
        let read = read_at_boot(&card.boot, &card.dev(), &Placing::at(&card));
        let trouble = read.trouble().expect("trouble");
        assert!(trouble.contains("boot sector"), "{trouble}");
        assert!(
            matches!(read.loaded(), Loaded::Found(_)),
            "it still restores"
        );
    }

    #[test]
    fn two_copies_that_lie_in_the_same_place_are_not_trusted_though_the_bytes_agree() {
        // A cross-linked file system: both files are the same clusters, so each reads back as the
        // bytes of the file through the file system, and a write to one would be a write to both.
        let card = Card::new();
        put_frame(&card, Which::A, 5, &payload(1));
        fs::copy(card.file(Which::A), card.file(Which::B)).unwrap();
        let read = read_at_boot(
            &card.boot,
            &card.dev(),
            &placing_at(&card, FILE_SIZE as u64, FILE_SIZE as u64),
        );
        let trouble = read.trouble().expect("trouble");
        assert!(trouble.contains("overlap"), "{trouble}");
        assert!(!read.complete());
        assert!(read.medium(&card.dev()).is_none());
        // It still restores what the files say.
        assert!(matches!(read.loaded(), Loaded::Found(found) if found.seq == 5));
        // The same files, put apart, are trusted.
        let read = read_at_boot(&card.boot, &card.dev(), &Placing::at(&card));
        assert_eq!(read.trouble(), None);
        assert!(read.complete());
        // Touching is not overlapping: b starts where a ends.
        let read = read_at_boot(
            &card.boot,
            &card.dev(),
            &placing_at(&card, FILE_SIZE as u64, 2 * FILE_SIZE as u64),
        );
        assert_eq!(read.trouble(), None);
        // A little overlap is too much.
        let read = read_at_boot(
            &card.boot,
            &card.dev(),
            &placing_at(&card, FILE_SIZE as u64, 2 * FILE_SIZE as u64 - 512),
        );
        assert!(read.trouble().is_some());
    }

    #[test]
    fn a_creation_on_a_card_whose_files_overlap_turns_saving_off() {
        let card = Card::new();
        let lent = Lent::new(&card);
        let mut writer = CardWriter::new(
            lent.clone(),
            card.dev(),
            Box::new(placing_at(&card, FILE_SIZE as u64, FILE_SIZE as u64 + 4096)),
            &BootRead::absent(),
        );
        let Written::Off(why) = writer.write(&payload(1)) else {
            panic!("saving stayed on");
        };
        assert!(why.contains("overlap") || why.starts_with("copy"), "{why}");
    }

    /// A valid frame of copy contents, made to say that it is of format version `version`.
    fn of_version(version: u32, seq: u64, payload: &[u8]) -> Vec<u8> {
        let mut file = frame(seq, payload);
        file[8..12].copy_from_slice(&version.to_le_bytes());
        file.resize(FILE_SIZE, 0x44);
        file
    }

    #[test]
    fn a_copy_of_a_newer_format_is_trouble_and_never_written_over() {
        let card = Card::new();
        fs::create_dir_all(card.state_dir()).unwrap();
        fs::write(card.file(Which::A), of_version(2, 9, &payload(1))).unwrap();
        fs::write(card.file(Which::B), of_version(1, 3, &payload(2))).unwrap();
        let newer = fs::read(card.file(Which::A)).unwrap();
        let read = read_at_boot(&card.boot, &card.dev(), &Placing::at(&card));
        let trouble = read.trouble().expect("trouble");
        assert!(
            trouble.starts_with("copy a: ") && trouble.contains("format version"),
            "{trouble}"
        );
        assert!(
            !trouble.contains('2'),
            "no byte of the file is in the line: {trouble}"
        );
        assert!(!read.complete());
        assert!(read.medium(&card.dev()).is_none());
        // What this build can read still restores (the older copy).
        let Loaded::Found(found) = read.loaded() else {
            panic!("nothing found: {read:?}");
        };
        assert_eq!((found.which, found.seq), (Which::B, 3));

        // A writer that goes on from that read writes nothing, makes nothing, and says why.
        let lent = Lent::new(&card);
        let mut writer = writer(&card, &lent, &read);
        let before = card.device_bytes();
        let Written::Off(why) = writer.write(&payload(3)) else {
            panic!("saving stayed on");
        };
        assert_eq!(why, trouble);
        assert_eq!(lent.uses(), (0, 0), "the card was not even claimed");
        assert_eq!(card.device_bytes(), before);
        assert_eq!(fs::read(card.file(Which::A)).unwrap(), newer);
    }

    #[test]
    fn a_newer_copy_alone_leaves_the_state_empty_and_is_not_made_again_by_the_creation() {
        let card = Card::new();
        fs::create_dir_all(card.state_dir()).unwrap();
        fs::write(card.file(Which::A), of_version(2, 9, &payload(1))).unwrap();
        let newer = fs::read(card.file(Which::A)).unwrap();
        let read = read_at_boot(&card.boot, &card.dev(), &Placing::at(&card));
        assert!(read.trouble().is_some());
        assert_eq!(read.loaded(), &Loaded::Empty(NoCopy::NotWhole));
        // The creation does not write over a file of the right size, and reads the pair again:
        // still trouble.
        let made = create(&card.boot, &card.dev(), &Placing::at(&card)).unwrap();
        assert_eq!(fs::read(card.file(Which::A)).unwrap(), newer);
        assert!(made.trouble().is_some());
        assert_eq!(fs::read(card.file(Which::B)).unwrap(), fill(Which::B));
        // And the writer that makes the copies says it is off, whatever it started from.
        let lent = Lent::new(&card);
        let mut writer = writer(&card, &lent, &BootRead::absent());
        let Written::Off(why) = writer.write(&payload(1)) else {
            panic!("saving stayed on");
        };
        assert!(why.contains("format version"), "{why}");
        assert_eq!(fs::read(card.file(Which::A)).unwrap(), newer);
    }

    #[test]
    fn a_frame_that_is_merely_torn_or_never_written_is_no_trouble() {
        let card = Card::new();
        // A torn frame of this format's own version, and the fill.
        let mut torn = frame(4, &payload(1));
        torn.truncate(40);
        torn.resize(FILE_SIZE, 0x44);
        fs::create_dir_all(card.state_dir()).unwrap();
        fs::write(card.file(Which::A), torn).unwrap();
        fs::write(card.file(Which::B), fill(Which::B)).unwrap();
        let read = read_at_boot(&card.boot, &card.dev(), &Placing::at(&card));
        assert_eq!(read.trouble(), None);
        assert_eq!(read.loaded(), &Loaded::Empty(NoCopy::NotWhole));
        assert!(read.complete());
    }

    #[test]
    fn the_frame_is_padded_to_the_devices_blocks_and_not_a_byte_beyond() {
        let card = Card::new();
        let read = create(&card.boot, &dev_with(&card, 4096), &Placing::at(&card)).unwrap();
        let medium = read.medium(&dev_with(&card, 4096)).expect("complete");
        let before = card.device_bytes();
        medium.write(Which::A, &[0xAB; 513]).unwrap();
        let after = card.device_bytes();
        let start = FILE_SIZE;
        assert_eq!(&after[start..start + 513], &[0xAB; 513][..]);
        assert!(
            after[start + 513..start + 4096]
                .iter()
                .all(|&byte| byte == 0)
        );
        assert_eq!(
            after[start + 4096..],
            before[start + 4096..],
            "not a byte past the first block"
        );
        assert_eq!(after[..start], before[..start]);
        // And one byte over a block is two blocks.
        medium.write(Which::A, &[0xCD; 4097]).unwrap();
        let after = card.device_bytes();
        assert_eq!(&after[start..start + 4097], &[0xCD; 4097][..]);
        assert!(
            after[start + 4097..start + 8192]
                .iter()
                .all(|&byte| byte == 0)
        );
        assert_eq!(after[start + 8192..], before[start + 8192..]);
    }

    /// Whether the file system that `dir` is on does direct transfers of a 4096-byte block at all
    /// (tmpfs of an older kernel, and some others, refuse): the tests of the direct path are only as
    /// good as the host, and say so when they cannot run. The board's direct path is proved in QEMU.
    fn direct_works_in(dir: &Path) -> bool {
        let path = dir.join("direct-probe");
        let Ok(file) = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(libc::O_DIRECT)
            .open(&path)
        else {
            return false;
        };
        let block = Aligned::zeroed(4096).unwrap();
        let mut back = Aligned::zeroed(4096).unwrap();
        let works = file.write_all_at(block.bytes(), 0).is_ok()
            && file.read_exact_at(back.bytes_mut(), 0).is_ok();
        let _ = fs::remove_file(&path);
        works
    }

    #[test]
    fn a_direct_write_is_seen_by_the_next_read_and_by_a_cached_one_and_touches_only_its_blocks() {
        let card = Card::new();
        if !direct_works_in(&card.boot) {
            eprintln!("O_DIRECT does not work on this file system: the direct path is QEMU's");
            return;
        }
        let device = dev_with(&card, 4096).with_direct(true);
        let read = create(&card.boot, &device, &Placing::at(&card)).unwrap();
        assert_eq!(read.trouble(), None, "{read:?}");
        let medium = read.medium(&device).expect("complete");
        // Pages of the device are in the cache from the reads above and from this one.
        let cached = fs::read(&card.device).unwrap();
        assert_eq!(cached[FILE_SIZE..FILE_SIZE + 8], fill(Which::A)[..8]);

        let new = frame(1, &payload(1));
        medium.write(Which::A, &new).unwrap();

        // Read through the cache, a cached page does not stand in for the card.
        let after = fs::read(&card.device).unwrap();
        assert_eq!(&after[FILE_SIZE..FILE_SIZE + new.len()], &new[..]);
        // Read as the medium does, and as a start would read the device (through the files, which
        // the test's mapper places on the device again: mirror what the device holds into them).
        assert_eq!(&medium.read(Which::A).unwrap()[..new.len()], &new[..]);
        for which in BOTH {
            fs::write(card.file(which), medium.read(which).unwrap()).unwrap();
        }
        let again = read_at_boot(&card.boot, &device, &Placing::at(&card));
        assert_eq!(again.trouble(), None, "{again:?}");
        assert!(matches!(again.loaded(), Loaded::Found(found) if found.seq == 1));
        // Only the one block of the frame changed.
        assert_eq!(after[..FILE_SIZE], cached[..FILE_SIZE]);
        assert_eq!(after[FILE_SIZE + 4096..], cached[FILE_SIZE + 4096..]);
        // A second write goes on from the first (its digest check reads the card, not the cache).
        let next = frame(2, &payload(2));
        medium.write(Which::A, &next).unwrap();
        assert_eq!(&medium.read(Which::A).unwrap()[..next.len()], &next[..]);
    }
}
