//! The system calls qberrypi makes itself, each behind a safe function.
//!
//! This is the only file that may contain `unsafe`. Nearly everything here
//! changes the machine it runs on, so the tests cover only the parts that
//! decide something: the rest is proven by booting the image.

use std::ffi::{CStr, CString, c_int, c_ulong};
use std::fs::{self, File};
use std::io::{self, ErrorKind, Write};
use std::num::NonZeroU32;
use std::ops::Range;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::thread;
use std::time::Duration;

use rustix::io::Errno;
use rustix::ioctl::{self, Opcode, Updater, opcode};
use rustix::mm::{MapFlags, ProtFlags, mmap, munmap};
use rustix::mount::{MountFlags, UnmountFlags};
use rustix::net::netlink::{self, SocketAddrNetlink};
use rustix::net::{AddressFamily, Protocol, SocketFlags, SocketType};
use rustix::process::{Resource, Rlimit, WaitOptions, getrlimit, setrlimit};
use rustix::rand::{GetRandomFlags, getrandom};
use rustix::system::RebootCommand;
use rustix::time::{ClockId, Timespec};
use tokio::io::unix::AsyncFd;

/// Where the kernel lists the modules it has, loaded or still initialising.
const SYSFS_MODULES: &str = "/sys/module";
/// The file that names the program the kernel runs to load a module.
const MODULE_HELPER_SETTING: &str = "/proc/sys/kernel/modprobe";
const KERNEL_COMMAND_LINE: &str = "/proc/cmdline";
const WATCHDOG_DEV: &str = "/dev/watchdog";

/// The request that sets a watchdog's timeout: `_IOWR('W', 6, int)`.
const WDIOC_SETTIMEOUT: Opcode = opcode::read_write::<c_int>(b'W', 6);

/// The request that reads a framebuffer's fixed information (`struct fb_fix_screeninfo`). The
/// framebuffer interface predates the encoded requests: this number says nothing of the data's size.
const FBIOGET_FSCREENINFO: Opcode = 0x4602;

/// Which of the kernel's netlink families a socket talks to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetlinkProtocol {
    /// Links, addresses and routes.
    Route,
    /// Families that are looked up by name, such as `nl80211`.
    Generic,
}

/// One of the kernel's own filesystems, and where it goes.
struct PseudoMount {
    fs_type: &'static str,
    target: &'static str,
    flags: MountFlags,
    options: Option<&'static CStr>,
}

/// For a filesystem that holds neither programs to run nor device files.
const NO_PROGRAMS: MountFlags = MountFlags::NOSUID
    .union(MountFlags::NODEV)
    .union(MountFlags::NOEXEC);

const PSEUDO_MOUNTS: [PseudoMount; 4] = [
    PseudoMount {
        fs_type: "proc",
        target: "/proc",
        flags: NO_PROGRAMS,
        options: None,
    },
    PseudoMount {
        fs_type: "sysfs",
        target: "/sys",
        flags: NO_PROGRAMS,
        options: None,
    },
    PseudoMount {
        fs_type: "devtmpfs",
        target: "/dev",
        flags: MountFlags::NOSUID.union(MountFlags::NOEXEC),
        options: Some(c"mode=0755"),
    },
    PseudoMount {
        fs_type: "tmpfs",
        target: "/run",
        flags: NO_PROGRAMS,
        options: Some(c"mode=0755"),
    },
];

/// Mounts `/proc`, `/sys`, `/dev` and a tmpfs at `/run`, making the directories if needed.
///
/// All four are tried whatever becomes of the others: `/dev` is where the
/// console and the card are, and a failure elsewhere must not cost those.
/// The error is the first failure, and names what could not be mounted.
pub fn mount_pseudo() -> io::Result<()> {
    mount_each(&PSEUDO_MOUNTS, &mut mount_one)
}

/// Makes every one of the mounts with `mount`, then returns the first error, named by its mount.
fn mount_each(
    mounts: &[PseudoMount],
    mount: &mut dyn FnMut(&PseudoMount) -> io::Result<()>,
) -> io::Result<()> {
    let mut first_error = None;
    for wanted in mounts {
        if let Err(error) = mount(wanted) {
            first_error.get_or_insert_with(|| {
                io::Error::new(error.kind(), format!("mounting {}: {error}", wanted.target))
            });
        }
    }
    first_error.map_or(Ok(()), Err)
}

/// Mounts one of the kernel's filesystems, making its directory if needed.
fn mount_one(mount: &PseudoMount) -> io::Result<()> {
    fs::create_dir_all(mount.target)?;
    rustix::mount::mount(
        mount.fs_type,
        mount.target,
        mount.fs_type,
        mount.flags,
        mount.options,
    )?;
    Ok(())
}

/// Mounts a FAT partition at a directory, which is made if it is missing.
pub fn mount_vfat(dev: &str, at: &str, read_only: bool) -> io::Result<()> {
    fs::create_dir_all(at)?;
    let mut flags = NO_PROGRAMS | MountFlags::NOATIME;
    if read_only {
        flags |= MountFlags::RDONLY;
    }
    rustix::mount::mount(dev, at, "vfat", flags, None)?;
    Ok(())
}

/// Unmounts what is mounted at a directory.
pub fn unmount(at: &str) -> io::Result<()> {
    rustix::mount::unmount(at, UnmountFlags::empty())?;
    Ok(())
}

/// Has the kernel write everything it holds back to its devices, and waits for that.
pub fn sync() {
    rustix::fs::sync();
}

/// Inserts a module file into the kernel, with the given parameters.
///
/// A module the kernel already has is `ErrorKind::AlreadyExists`.
pub fn finit_module(file: &Path, params: &str) -> io::Result<()> {
    let params = CString::new(params)?;
    let file = File::open(file)?;
    // The kernel's EEXIST arrives as `ErrorKind::AlreadyExists`.
    rustix::system::finit_module(&file, &params, 0)?;
    Ok(())
}

/// Inserts a module file unless the kernel shows that it already has the module.
///
/// This is what loads modules, for init and for the module helper. A module
/// that is there, or on its way, is `ErrorKind::AlreadyExists` without the
/// kernel being asked: asked to insert a module that is still initialising,
/// it can wait for that to end. The driver that asks the helper for its
/// sub-module is in exactly that state, so the two would wait for each other.
pub fn insert_module(file: &Path, params: &str) -> io::Result<()> {
    if module_in_kernel(Path::new(SYSFS_MODULES), file) {
        return Err(ErrorKind::AlreadyExists.into());
    }
    finit_module(file, params)
}

/// Whether the kernel lists the module a file holds, given its directory of modules.
fn module_in_kernel(sysfs_modules: &Path, file: &Path) -> bool {
    module_sysfs_dir(sysfs_modules, file).is_some_and(|dir| dir.exists())
}

/// Names the directory the kernel keeps for a module once it has it.
///
/// The module is named after its file, with `_` where the file has `-`.
/// Returns `None` for a path that has no file name to go by.
fn module_sysfs_dir(sysfs_modules: &Path, file: &Path) -> Option<PathBuf> {
    let name = file.file_stem()?.to_str()?.replace('-', "_");
    Some(sysfs_modules.join(name))
}

/// Opens a netlink socket: non-blocking, closed on exec, bound to a port the kernel picks.
///
/// An error acknowledgement carries the kernel's explanation (`NETLINK_EXT_ACK`)
/// and only the header of the request it answers (`NETLINK_CAP_ACK`): a
/// request can carry a key, and the kernel must not send it back.
pub fn netlink_socket(protocol: NetlinkProtocol) -> io::Result<OwnedFd> {
    let protocol = match protocol {
        // The default protocol of a netlink socket is route netlink.
        NetlinkProtocol::Route => None,
        NetlinkProtocol::Generic => Some(netlink::GENERIC),
    };
    let socket = rustix::net::socket_with(
        AddressFamily::NETLINK,
        SocketType::RAW,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        protocol,
    )?;
    rustix::net::bind(&socket, &SocketAddrNetlink::new(0, 0))?;
    set_netlink_option(socket.as_fd(), libc::NETLINK_EXT_ACK, 1)?;
    set_netlink_option(socket.as_fd(), libc::NETLINK_CAP_ACK, 1)?;
    Ok(socket)
}

/// Has a netlink socket receive the messages the kernel sends to a multicast group.
pub fn netlink_join_group(socket: BorrowedFd<'_>, group: u32) -> io::Result<()> {
    let group = c_int::try_from(group).map_err(|_| ErrorKind::InvalidInput)?;
    set_netlink_option(socket, libc::NETLINK_ADD_MEMBERSHIP, group)
}

/// Opens a raw packet socket that sends and hears the frames of one ethertype on one interface.
///
/// The socket is non-blocking and closed on exec. It is raw: what it reads and
/// what it sends are whole Ethernet frames, header included. It hears the frames
/// that arrive, and not those that leave the interface, its own among them: only
/// a socket for every ethertype is a tap on the outgoing ones. An ethertype of
/// zero would hear nothing, and so would one on interface index zero, which
/// the kernel's bind takes to mean every interface at once: both are
/// `ErrorKind::InvalidInput`. An interface that does not exist is an error of
/// the bind.
pub fn packet_socket(ifindex: u32, ethertype: u16) -> io::Result<OwnedFd> {
    if ifindex == 0 {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "interface index 0 would bind to every interface",
        ));
    }
    let ifindex = c_int::try_from(ifindex).map_err(|_| ErrorKind::InvalidInput)?;
    // The kernel takes the ethertype in network order, here and in the address.
    let protocol = NonZeroU32::new(u32::from(ethertype.to_be())).ok_or(ErrorKind::InvalidInput)?;
    let socket = rustix::net::socket_with(
        AddressFamily::PACKET,
        SocketType::RAW,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        Some(Protocol::from_raw(protocol)),
    )?;
    bind_packet(socket.as_fd(), ifindex, ethertype)?;
    Ok(socket)
}

/// Binds a packet socket to an interface and an ethertype.
fn bind_packet(socket: BorrowedFd<'_>, ifindex: c_int, ethertype: u16) -> io::Result<()> {
    let address = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: ethertype.to_be(),
        sll_ifindex: ifindex,
        // The kernel ignores the rest of the address when it binds.
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };
    // SAFETY: the kernel reads as many bytes as the length says from the
    // pointer. That is to `address`, a `sockaddr_ll` of exactly that length
    // that outlives the call; the descriptor stays open because `socket` is
    // borrowed for the call.
    let result = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&raw const address).cast(),
            size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Fills a buffer from the kernel's random source.
///
/// This waits, as `getrandom(2)` does, until the kernel has gathered enough
/// entropy to seed it, which a nonce needs. The call is repeated until the
/// buffer is full, and after a signal.
pub fn random_bytes(buf: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        match getrandom(&mut buf[filled..], GetRandomFlags::empty()) {
            Ok(0) => return Err(ErrorKind::UnexpectedEof.into()),
            Ok(got) => filled += got,
            Err(rustix::io::Errno::INTR) => {}
            Err(errno) => return Err(errno.into()),
        }
    }
    Ok(())
}

/// Hands a descriptor to the tokio reactor, so that it can be waited on for readiness.
///
/// # Panics
///
/// Outside a tokio runtime.
pub fn async_fd(fd: OwnedFd) -> io::Result<AsyncFd<OwnedFd>> {
    // SAFETY: an `OwnedFd` is open and stays the same descriptor until it is
    // dropped, and the `AsyncFd` that takes it never gives it up.
    let registered = unsafe { AsyncFd::register(fd) };
    Ok(registered?)
}

/// Sets one of a netlink socket's options, which all take an integer.
fn set_netlink_option(socket: BorrowedFd<'_>, option: c_int, value: c_int) -> io::Result<()> {
    // SAFETY: the kernel reads as many bytes as the length says from the
    // pointer, which is to `value`, a `c_int` that outlives the call; the
    // descriptor stays open because `socket` is borrowed for the call.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_NETLINK,
            option,
            (&raw const value).cast(),
            size_of::<c_int>() as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Raises the soft limit on open files to the hard one, and says what the soft limit is now.
///
/// The kernel starts init with a soft limit of 1024 and a hard one of 4096, and every socket of
/// the DNS service counts against the soft one. The limit never goes down: a soft limit that is
/// at the hard one already is left alone, and so is one with no hard limit to go up to. An
/// unlimited soft limit shows as `u64::MAX`.
pub fn raise_open_files() -> io::Result<u64> {
    let limit = getrlimit(Resource::Nofile);
    let wanted = open_files_target(limit).unwrap_or(limit);
    if wanted != limit {
        setrlimit(Resource::Nofile, wanted)?;
    }
    Ok(wanted.current.unwrap_or(u64::MAX))
}

/// What to set the open-file limits to, given what they are: the soft limit at the hard one.
/// `None` if the soft limit is there already, or the hard limit is none that it can go up to.
fn open_files_target(limit: Rlimit) -> Option<Rlimit> {
    let hard = limit.maximum?;
    match limit.current {
        Some(soft) if soft >= hard => None,
        _ => Some(Rlimit {
            current: Some(hard),
            maximum: limit.maximum,
        }),
    }
}

/// Gives the system its name on the network.
pub fn set_hostname(name: &str) -> io::Result<()> {
    rustix::system::sethostname(name.as_bytes())?;
    Ok(())
}

/// Moves the clock forward to a time if it shows an earlier one; says whether it did.
pub fn clock_at_least(epoch_secs: u64) -> io::Result<bool> {
    let earliest = i64::try_from(epoch_secs).map_err(|_| ErrorKind::InvalidInput)?;
    if rustix::time::clock_gettime(ClockId::Realtime).tv_sec >= earliest {
        return Ok(false);
    }
    let time = Timespec {
        tv_sec: earliest,
        tv_nsec: 0,
    };
    rustix::time::clock_settime(ClockId::Realtime, time)?;
    Ok(true)
}

/// Sets the system clock to a Unix time, to the nanosecond.
///
/// What the SNTP client does once it has a time it trusts: the clock is stepped, not slewed.
pub fn set_clock(unix: Duration) -> io::Result<()> {
    let time = Timespec::try_from(unix).map_err(|_| ErrorKind::InvalidInput)?;
    rustix::time::clock_settime(ClockId::Realtime, time)?;
    Ok(())
}

/// Eight bytes from the kernel's random source, as a number.
///
/// For the IDs of the queries sent to the upstreams, which a host off the path must not be able
/// to guess. The call waits only if the kernel's pool is not yet seeded, which it is long before
/// the network is up.
pub fn random_u64() -> u64 {
    let mut bytes = [0u8; 8];
    loop {
        match rustix::rand::getrandom(&mut bytes[..], GetRandomFlags::empty()) {
            Ok(8) => return u64::from_ne_bytes(bytes),
            // A signal cut the call short, or it gave fewer bytes than asked for.
            Ok(_) | Err(Errno::INTR) => {}
            // Nothing else is possible for this call; a number that is poor is better than none.
            Err(_) => return clock_noise(),
        }
    }
}

/// A number from the clock, mixed so that nearby readings are far apart. Not a secret.
fn clock_noise() -> u64 {
    let now = rustix::time::clock_gettime(ClockId::Monotonic);
    let mut x = ((now.tv_sec as u64) << 32) ^ now.tv_nsec as u64;
    // The finaliser of splitmix64.
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// Makes a program the one the kernel runs when it wants a module loaded.
pub fn register_module_helper(path: &str) -> io::Result<()> {
    fs::write(MODULE_HELPER_SETTING, path)
}

/// Whether the kernel was started with an argument, given as a whole word.
pub fn kernel_arg(name: &str) -> bool {
    fs::read_to_string(KERNEL_COMMAND_LINE).is_ok_and(|cmdline| cmdline_has(&cmdline, name))
}

/// Whether one of the whitespace-separated words of a command line is `name`.
fn cmdline_has(cmdline: &str, name: &str) -> bool {
    cmdline.split_ascii_whitespace().any(|word| word == name)
}

/// How long the kernel has been running.
///
/// The monotonic clock starts with the kernel, and no one sets it.
pub fn uptime() -> Duration {
    let now = rustix::time::clock_gettime(ClockId::Monotonic);
    Duration::new(
        u64::try_from(now.tv_sec).unwrap_or(0),
        u32::try_from(now.tv_nsec).unwrap_or(0),
    )
}

/// Collects every child process that has exited, without waiting for one to.
pub fn reap_children() {
    while let Ok(Some(_)) = rustix::process::waitpid(None, WaitOptions::NOHANG) {}
}

/// Writes everything to the card and restarts the board.
pub fn reboot() -> ! {
    sync();
    let _ = rustix::system::reboot(RebootCommand::Restart);
    // The restart was refused. If the watchdog has been started, it is no
    // longer petted from here and restarts the board instead. Before that,
    // in the first steps of the boot, nothing does: init stays here.
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

/// The kernel's `struct fb_fix_screeninfo`, which `FBIOGET_FSCREENINFO` fills in.
///
/// Every field is there so that the struct is as large as the kernel's, which writes all of it;
/// only the two that are read have a name.
#[repr(C)]
#[derive(Default)]
struct FixScreenInfo {
    _id: [u8; 16],
    _smem_start: c_ulong,
    smem_len: u32,
    _kind: u32,
    _type_aux: u32,
    _visual: u32,
    _xpanstep: u16,
    _ypanstep: u16,
    _ywrapstep: u16,
    line_length: u32,
    _mmio_start: c_ulong,
    _mmio_len: u32,
    _accel: u32,
    _capabilities: u16,
    _reserved: [u16; 2],
}

/// What a framebuffer says about its memory.
struct Memory {
    /// How many bytes the driver holds for the picture.
    bytes: u64,
    /// How many bytes a row of the picture takes in that memory.
    row_bytes: u64,
}

/// Asks the framebuffer how much memory it has and how it lays out a row.
///
/// Fails on anything that is no framebuffer, such as a regular file or `/dev/null`, with
/// "inappropriate ioctl for device".
fn memory_of(device: &File) -> io::Result<Memory> {
    let mut info = FixScreenInfo::default();
    // SAFETY: the request takes a pointer to a `struct fb_fix_screeninfo`, which `FixScreenInfo`
    // is laid out as (a test holds it to the kernel's size), and `info` outlives the call.
    unsafe {
        ioctl::ioctl(
            device,
            Updater::<FBIOGET_FSCREENINFO, FixScreenInfo>::new(&mut info),
        )
    }?;
    Ok(Memory {
        bytes: u64::from(info.smem_len),
        row_bytes: u64::from(info.line_length),
    })
}

/// Checks that `memory` holds `len` bytes, in rows of `row_bytes`.
///
/// More memory than `len` is no harm: a driver may keep room for a second picture.
fn check_memory(memory: &Memory, len: usize, row_bytes: usize) -> io::Result<()> {
    if memory.bytes < len as u64 {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("the device holds {} bytes", memory.bytes),
        ));
    }
    if memory.row_bytes != row_bytes as u64 {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "its rows are {} bytes long, not {row_bytes}",
                memory.row_bytes
            ),
        ));
    }
    Ok(())
}

/// A writable window onto the memory of a framebuffer, shared with the driver and whoever else has it open.
///
/// What is written through the window reaches the screen's memory without a `write(2)`. For a
/// framebuffer that matters: the kernel notes which pages of the window were touched and sends
/// only those to the screen, where a `write(2)` makes it send everything. Nothing needs to be
/// flushed, as `msync(2)` would: the kernel's deferred I/O picks the touched pages up by itself.
///
/// No Rust reference to the window's bytes is ever made, and none can be had: a `&[u8]` or a
/// `&mut [u8]` promises that nothing else changes the bytes while it lives, and the kernel's
/// text console may draw on the same memory at any moment. The window is read through
/// [`changed_rows`](Self::changed_rows), which reads each byte or word once, volatile, and
/// written through [`write`](Self::write), which copies bytes in.
///
/// The window is only made over memory that the device has said it holds, and it outlives the
/// `File` it was made from. It is unmapped when it is dropped.
pub struct SharedMapping {
    /// Where the window starts: the address of the first of `len` bytes.
    start: NonNull<u8>,
    /// How many bytes the window holds.
    len: usize,
}

impl SharedMapping {
    /// Maps the first `len` bytes of the framebuffer `file`, open for reading and writing, whose
    /// rows are `row_bytes` long.
    ///
    /// A device is asked what it holds (`FBIOGET_FSCREENINFO`), and is mapped only if it says at
    /// least `len` bytes, in rows of `row_bytes`: the kernel does not check a mapping against the
    /// device's memory, and touching a page past the end of it kills the process. A device that
    /// does not answer is refused too. A regular file stands in for a device in tests; it has no
    /// such request, and its own length is checked instead. A `len` of zero is refused.
    /// The error's message is the reason, ready to go into a warning.
    pub fn of_framebuffer(file: &File, len: usize, row_bytes: usize) -> io::Result<Self> {
        let metadata = file.metadata()?;
        if len == 0 {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "a mapping of no bytes",
            ));
        }
        if metadata.is_file() {
            if metadata.len() < len as u64 {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    format!("the file holds {} bytes", metadata.len()),
                ));
            }
        } else {
            let memory = memory_of(file).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("the device would not say how much it holds: {error}"),
                )
            })?;
            check_memory(&memory, len, row_bytes)?;
        }
        // SAFETY: with a null address and no `MAP_FIXED` the kernel picks a range of its own,
        // so no memory that is in use is replaced. The result is checked, and `file` is open
        // for the call, which is all the kernel needs of it: the mapping holds its own reference.
        let start = unsafe {
            mmap(
                std::ptr::null_mut(),
                len,
                ProtFlags::READ | ProtFlags::WRITE,
                MapFlags::SHARED,
                file,
                0,
            )
        }?;
        let start = NonNull::new(start.cast::<u8>())
            .ok_or_else(|| io::Error::other("the kernel mapped the file at address zero"))?;
        Ok(Self { start, len })
    }

    /// How many bytes the window holds. It is never zero.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the window holds no bytes, which it never does: a mapping of none is refused.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The rows in which `frame` differs from the window, as the first and one past the last, or
    /// `None` if it does not; rows are `row_bytes` long, the last perhaps shorter.
    ///
    /// This gives what `qb_panel::rows::changed_rows` gives for the same bytes, and the rows
    /// between the two may be equal. A `frame` of any other length than the window's differs in
    /// all of its rows, and the window is not read. The window is read once, at most twice for
    /// a row, with volatile reads (a `u64` at a time wherever the address and the length allow),
    /// because something else may write it meanwhile: the range that comes back is then one of
    /// rows that exist, never empty or turned round, and a row that is half old and half new
    /// is found again at the next call.
    ///
    /// # Panics
    ///
    /// If `row_bytes` is zero.
    pub fn changed_rows(&self, frame: &[u8], row_bytes: usize) -> Option<Range<usize>> {
        assert!(row_bytes != 0, "rows of no bytes");
        if frame.len() != self.len {
            return Some(0..frame.len().div_ceil(row_bytes));
        }
        let rows = self.len.div_ceil(row_bytes);
        let differs = |row: usize| {
            let at = row * row_bytes;
            let end = (at + row_bytes).min(self.len);
            !self.holds(at, &frame[at..end])
        };
        let first = (0..rows).find(|&row| differs(row))?;
        // A last row that differs, as there is a first, unless the window has changed in between.
        let last = (first..rows)
            .rev()
            .find(|&row| differs(row))
            .unwrap_or(first);
        Some(first..last + 1)
    }

    /// Copies `bytes` into the window, the first to byte `at`.
    ///
    /// A range that does not lie inside the window (`at` plus the length is more than `len`) is
    /// refused with an `InvalidInput` error, and nothing is written. That is a bug of the
    /// caller's. It is an error and no panic because this runs as PID 1, where a panic aborts
    /// the whole program and restarts the board, and a caller can log an error and draw the
    /// next picture.
    pub fn write(&mut self, at: usize, bytes: &[u8]) -> io::Result<()> {
        if at > self.len || bytes.len() > self.len - at {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "{} bytes at {at} do not lie in a window of {} bytes",
                    bytes.len(),
                    self.len
                ),
            ));
        }
        // SAFETY: the destination is `bytes.len()` bytes from `at`, which the check above put
        // inside the `len` bytes of a mapping that is readable, writable and alive until `drop`
        // (and inside the device: see `of_framebuffer`). The source is a slice, valid for its
        // length, and cannot overlap the window: the kernel chose the window's range for this
        // mapping alone, and no pointer into it is handed out, so no live reference of any other
        // origin points into it. No reference into the window is made here either. Others can
        // write the same bytes from outside the program, such as the kernel's text console
        // drawing on the screen; the copy reads and writes plain bytes, so a race with one gives
        // at worst a stale or a mixed row, which the next comparison finds again.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.start.as_ptr().add(at), bytes.len());
        }
        Ok(())
    }

    /// Whether the window holds `expected` from byte `at` on, read with volatile reads: a few
    /// bytes up to an address a `u64` can be read from, then words, then the bytes that are left.
    ///
    /// # Panics
    ///
    /// If the bytes are not all inside the window.
    fn holds(&self, at: usize, expected: &[u8]) -> bool {
        assert!(
            at <= self.len && expected.len() <= self.len - at,
            "bytes past the end of the window"
        );
        // SAFETY: `at` is at most `len`, so the result is inside the mapping or just past its end.
        let base = unsafe { self.start.as_ptr().add(at) };
        // The bytes up to the next address a `u64` can be read from, which is a multiple of 8.
        let head = base.addr().wrapping_neg() & (align_of::<u64>() - 1);
        let (head, rest) = expected.split_at(head.min(expected.len()));
        let (words, tail) = rest.as_chunks::<8>();
        // The reads below are volatile because the window can change under them, by a writer
        // outside the program such as the kernel's text console: the compiler may not assume that
        // a read sees what an earlier one saw, nor drop one. The window is never made into a
        // reference, so nothing is promised about it. Any bit pattern is a valid `u8` and `u64`,
        // so bytes that change during a read give a stale or mixed value at worst.
        let byte_at = |offset: usize| {
            debug_assert!(offset < expected.len());
            // SAFETY: `offset` is below `expected.len()`, and `expected` lies inside the window
            // from `at` (checked above), so this is one of its bytes: readable, and alive until
            // `drop` because `self` is borrowed.
            unsafe { base.add(offset).read_volatile() }
        };
        let word_at = |offset: usize| {
            debug_assert!(offset + 8 <= expected.len());
            // SAFETY: the same as for `byte_at`, for the 8 bytes from `offset`; and the address
            // is a multiple of 8, as a read of a `u64` needs: there are words only if `head`
            // was not cut short, so `base` plus `head.len()` is a multiple of 8, and a word
            // starts every 8 bytes from there.
            unsafe { base.add(offset).cast::<u64>().read_volatile() }
        };
        if head.iter().enumerate().any(|(i, &want)| byte_at(i) != want) {
            return false;
        }
        for (i, want) in words.iter().enumerate() {
            if word_at(head.len() + 8 * i) != u64::from_ne_bytes(*want) {
                return false;
            }
        }
        let tail_at = head.len() + 8 * words.len();
        !tail
            .iter()
            .enumerate()
            .any(|(i, &want)| byte_at(tail_at + i) != want)
    }
}

impl Drop for SharedMapping {
    fn drop(&mut self) {
        // SAFETY: `start` and `len` are those of the mapping made by `of_framebuffer`, nothing
        // else unmaps it, and no reference into it exists, or ever did: it is only read and
        // written through raw pointers, within the calls of `&self` and `&mut self` methods that
        // have ended by now. An error leaves nothing to do but leak the window, so it is not
        // looked at.
        let _ = unsafe { munmap(self.start.as_ptr().cast(), self.len) };
    }
}

/// The hardware watchdog: it restarts the board unless it is petted in time.
pub struct Watchdog {
    /// Held open for good. Closing it would not stop the countdown, only the pets.
    device: Option<File>,
}

impl Watchdog {
    /// Starts the watchdog, to restart the board after `timeout_secs` without a pet.
    ///
    /// Once the device is open the countdown runs and cannot be stopped. If
    /// the timeout is then refused, that is logged and the watchdog is
    /// returned all the same, running with the driver's own timeout.
    pub fn open(timeout_secs: u32) -> io::Result<Self> {
        let device = File::options().write(true).open(WATCHDOG_DEV)?;
        let mut secs = c_int::try_from(timeout_secs).unwrap_or(c_int::MAX);
        // SAFETY: the request takes a pointer to one int, and `secs` is one that outlives the call.
        let set =
            unsafe { ioctl::ioctl(&device, Updater::<WDIOC_SETTIMEOUT, c_int>::new(&mut secs)) };
        if let Err(errno) = set {
            log::warn!(
                "watchdog: the {timeout_secs} s timeout was refused: {}",
                io::Error::from(errno)
            );
        }
        Ok(Self {
            device: Some(device),
        })
    }

    /// Stands in where there is no watchdog: it takes pets and does nothing.
    pub const fn absent() -> Self {
        Self { device: None }
    }

    /// Starts the countdown afresh.
    pub fn pet(&mut self) {
        if let Some(device) = &mut self.device {
            // Any byte is a pet, except `V`, which asks the driver to stop.
            let _ = device.write_all(b"\0");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::io::ErrorKind;
    use std::path::Path;

    use rustix::net::RecvFlags;

    const SELFTEST: &str = "qberrypi.selftest";

    #[test]
    fn the_soft_limit_on_open_files_goes_up_to_the_hard_one_and_never_down() {
        let limit = |soft, hard| Rlimit {
            current: soft,
            maximum: hard,
        };
        // What the kernel starts init with.
        assert_eq!(
            open_files_target(limit(Some(1024), Some(4096))),
            Some(limit(Some(4096), Some(4096)))
        );
        // Already there, or no hard limit to go up to: there is nothing to set.
        assert_eq!(open_files_target(limit(Some(4096), Some(4096))), None);
        assert_eq!(open_files_target(limit(Some(1024), None)), None);
        assert_eq!(open_files_target(limit(None, None)), None);
    }

    #[test]
    fn raising_the_open_file_limit_twice_changes_nothing_the_second_time() {
        let before = getrlimit(Resource::Nofile).current.unwrap_or(u64::MAX);
        let first = raise_open_files().unwrap();
        let second = raise_open_files().unwrap();
        assert!(first >= before, "{first} < {before}");
        assert_eq!(first, second);
        // What the process has now is what was reported, and is the hard limit.
        let now = getrlimit(Resource::Nofile);
        assert_eq!(now.current.unwrap_or(u64::MAX), second);
        assert!(now.maximum.is_none_or(|hard| second <= hard));
    }

    #[test]
    fn a_kernel_argument_is_a_whole_token() {
        let cmdline = "console=ttyAMA0,115200 panic=5 loglevel=7 qberrypi.selftest\n";
        assert!(cmdline_has(cmdline, SELFTEST));
        assert!(cmdline_has(cmdline, "panic=5"));
        assert!(cmdline_has("qberrypi.selftest", SELFTEST));
        assert!(cmdline_has(
            "panic=5\tqberrypi.selftest  loglevel=7",
            SELFTEST
        ));
    }

    #[test]
    fn part_of_a_token_is_not_the_argument() {
        assert!(!cmdline_has("panic=5 qberrypi.selftestX", SELFTEST));
        assert!(!cmdline_has("xqberrypi.selftest panic=5", SELFTEST));
        assert!(!cmdline_has("qberrypi.selftest=1", SELFTEST));
        assert!(!cmdline_has("qberrypi .selftest", SELFTEST));
        assert!(!cmdline_has("console=tty1 panic=5", SELFTEST));
        assert!(!cmdline_has("", SELFTEST));
    }

    #[test]
    fn a_module_file_maps_to_its_sysfs_directory() {
        let sysfs = Path::new("/sys/module");
        for (file, dir) in [
            ("/lib/modules/brcmfmac.ko", "/sys/module/brcmfmac"),
            ("/lib/modules/brcmfmac-cyw.ko", "/sys/module/brcmfmac_cyw"),
            ("a-b-c.ko", "/sys/module/a_b_c"),
            ("/lib/modules/snd_pcm.ko", "/sys/module/snd_pcm"),
        ] {
            assert_eq!(
                module_sysfs_dir(sysfs, Path::new(file)).as_deref(),
                Some(Path::new(dir)),
                "{file}"
            );
        }
        assert_eq!(module_sysfs_dir(sysfs, Path::new("/")), None);
    }

    #[test]
    fn a_module_is_in_the_kernel_once_sysfs_has_its_directory() {
        let sysfs = tempfile::tempdir().unwrap();
        let cyw = Path::new("/lib/modules/brcmfmac-cyw.ko");
        let core = Path::new("/lib/modules/brcmfmac.ko");
        assert!(!module_in_kernel(sysfs.path(), cyw));
        assert!(!module_in_kernel(sysfs.path(), core));

        // What the kernel shows while brcmfmac is loaded or still initialising.
        fs::create_dir(sysfs.path().join("brcmfmac")).unwrap();
        assert!(module_in_kernel(sysfs.path(), core));
        assert!(!module_in_kernel(sysfs.path(), cyw));

        fs::create_dir(sysfs.path().join("brcmfmac_cyw")).unwrap();
        assert!(module_in_kernel(sysfs.path(), cyw));
    }

    #[test]
    fn a_path_with_no_file_name_is_not_a_module_in_the_kernel() {
        let sysfs = tempfile::tempdir().unwrap();
        assert!(!module_in_kernel(sysfs.path(), Path::new("/")));
    }

    #[test]
    fn a_module_the_kernel_already_has_is_already_exists() {
        let error = std::io::Error::from(rustix::io::Errno::EXIST);
        assert_eq!(error.kind(), ErrorKind::AlreadyExists);
    }

    #[test]
    fn the_watchdog_timeout_request_is_the_kernel_one() {
        // WDIOC_SETTIMEOUT in linux/watchdog.h: _IOWR('W', 6, int).
        assert_eq!(WDIOC_SETTIMEOUT, 0xC004_5706);
    }

    #[test]
    fn an_absent_watchdog_takes_pets_and_does_nothing() {
        let mut watchdog = Watchdog::absent();
        watchdog.pet();
        watchdog.pet();
    }

    #[test]
    fn a_filesystem_that_does_not_mount_does_not_keep_the_others_from_being_mounted() {
        let mut tried = Vec::new();
        let result = mount_each(&PSEUDO_MOUNTS, &mut |mount| {
            tried.push(mount.target);
            match mount.target {
                "/proc" => Err(std::io::Error::other("no proc here")),
                "/run" => Err(std::io::Error::other("no tmpfs here")),
                _ => Ok(()),
            }
        });
        // Without `/dev` there is no console and no card to restore on.
        assert_eq!(tried, ["/proc", "/sys", "/dev", "/run"]);
        // The error is the first one, and names what could not be mounted.
        assert_eq!(
            result.unwrap_err().to_string(),
            "mounting /proc: no proc here"
        );
    }

    #[test]
    fn mounts_that_all_succeed_are_no_error() {
        let mut tried = 0;
        mount_each(&PSEUDO_MOUNTS, &mut |_| {
            tried += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(tried, 4);
    }

    #[test]
    fn a_netlink_socket_is_open_and_does_not_block() {
        for protocol in [NetlinkProtocol::Route, NetlinkProtocol::Generic] {
            let socket = netlink_socket(protocol).unwrap();
            let mut datagram = [0u8; 64];
            let error =
                rustix::net::recv(&socket, &mut datagram[..], RecvFlags::empty()).unwrap_err();
            assert_eq!(
                io::Error::from(error).kind(),
                ErrorKind::WouldBlock,
                "{protocol:?}"
            );
        }
    }

    #[test]
    fn a_netlink_socket_joins_a_multicast_group() {
        let socket = netlink_socket(NetlinkProtocol::Route).unwrap();
        // RTNLGRP_LINK: the group that hears of links coming and going.
        netlink_join_group(socket.as_fd(), 1).unwrap();
        // A group number the option cannot hold.
        let error = netlink_join_group(socket.as_fd(), u32::MAX).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn an_error_does_not_bring_the_request_back() {
        use crate::netlink::{MsgBuilder, NLM_F_ACK, NLM_F_CAPPED, NLM_F_REQUEST, ack, messages};

        let socket = netlink_socket(NetlinkProtocol::Route).unwrap();
        // Asks for a link that no machine has. The kernel answers while it takes the request.
        let request = MsgBuilder::new(18, NLM_F_REQUEST | NLM_F_ACK)
            .header(&[0; 16])
            .attr_str(3, "nosuch0")
            .finish(1);
        rustix::net::send(&socket, &request, rustix::net::SendFlags::empty()).unwrap();
        let mut datagram = [0u8; 4096];
        let (_, len) = rustix::net::recv(&socket, &mut datagram[..], RecvFlags::empty()).unwrap();
        let message = messages(&datagram[..len]).next().unwrap();
        assert_eq!(ack(&message).unwrap().unwrap_err().errno, libc::ENODEV);
        assert_ne!(message.flags & NLM_F_CAPPED, 0);
        // The header of the request, not all of it: an error code and 16 bytes.
        assert_eq!(message.payload.len(), 4 + 16);
    }

    #[test]
    fn random_bytes_fill_the_buffer() {
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        random_bytes(&mut a).unwrap();
        random_bytes(&mut b).unwrap();
        assert!(a != [0; 32] && a != b);
        // Nothing to fill is nothing to do.
        random_bytes(&mut []).unwrap();
        // A big buffer, in case a call hands over less than it was asked for.
        let mut big = vec![0u8; 1 << 20];
        random_bytes(&mut big).unwrap();
        assert!(big.chunks(4096).all(|chunk| chunk.iter().any(|&b| b != 0)));
    }

    #[test]
    fn the_uptime_is_positive_and_never_goes_back() {
        let first = uptime();
        assert!(first > Duration::ZERO);
        assert!(uptime() >= first);
    }

    #[test]
    fn the_pseudo_filesystems_are_the_four_the_boot_needs() {
        let mounts: Vec<_> = PSEUDO_MOUNTS
            .iter()
            .map(|mount| (mount.fs_type, mount.target))
            .collect();
        assert_eq!(
            mounts,
            [
                ("proc", "/proc"),
                ("sysfs", "/sys"),
                ("devtmpfs", "/dev"),
                ("tmpfs", "/run")
            ]
        );
    }

    /// A file that stands in for a framebuffer, holding `contents`, and a mapping of all of it.
    ///
    /// The directory goes with them, as the file is gone with it.
    fn device_of(contents: &[u8]) -> (tempfile::TempDir, PathBuf, SharedMapping) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device");
        fs::write(&path, contents).unwrap();
        let file = File::options().read(true).write(true).open(&path).unwrap();
        let mapping = SharedMapping::of_framebuffer(&file, contents.len(), 960).unwrap();
        (dir, path, mapping)
    }

    /// `len` bytes that repeat neither after a word nor after a row, so that a word read from the
    /// wrong place is not taken for one read from the right place.
    fn pattern(len: usize) -> Vec<u8> {
        (0..len)
            .map(|at| (at % 251) as u8 ^ ((at / 251) as u8).wrapping_mul(37))
            .collect()
    }

    /// Asserts that the mapping and `qb_panel::rows::changed_rows` give the same answer for
    /// `frame` against what the mapping holds, which is what the file at `path` holds.
    #[track_caller]
    fn assert_agrees(mapping: &SharedMapping, path: &Path, frame: &[u8], row_bytes: usize) {
        let held = fs::read(path).unwrap();
        assert_eq!(
            mapping.changed_rows(frame, row_bytes),
            qb_panel::rows::changed_rows(&held, frame, row_bytes),
            "{} bytes in rows of {row_bytes}",
            frame.len()
        );
    }

    #[test]
    fn what_is_written_through_a_mapping_reaches_its_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device");
        fs::write(&path, vec![0u8; 8192]).unwrap();
        let file = File::options().read(true).write(true).open(&path).unwrap();
        let mut mapping = SharedMapping::of_framebuffer(&file, 8192, 960).unwrap();
        assert_eq!(mapping.len(), 8192);
        mapping.write(5000, b"rows").unwrap();
        drop(mapping);
        let written = fs::read(&path).unwrap();
        assert_eq!(&written[5000..5004], b"rows");
        assert_eq!(written.iter().filter(|&&byte| byte != 0).count(), 4);
    }

    #[test]
    fn a_write_can_touch_any_byte_from_the_first_to_the_last_and_none() {
        let (_dir, path, mut mapping) = device_of(&[0u8; 100]);
        mapping.write(0, b"ab").unwrap();
        mapping.write(98, b"yz").unwrap();
        // Bytes that are no multiple of a word, at an address that is none either.
        mapping.write(3, b"odd bytes").unwrap();
        // Nothing, at the end and inside.
        mapping.write(100, &[]).unwrap();
        mapping.write(50, &[]).unwrap();
        // All of it.
        let all = pattern(100);
        mapping.write(0, &all).unwrap();
        assert_eq!(fs::read(&path).unwrap(), all);
    }

    #[test]
    fn a_write_that_does_not_lie_in_the_window_is_an_error_and_writes_nothing() {
        let (_dir, path, mut mapping) = device_of(&[7u8; 64]);
        for (at, len) in [(0, 65), (1, 64), (63, 2), (64, 1), (65, 0), (usize::MAX, 2)] {
            let error = mapping.write(at, &vec![1; len]).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidInput, "{len} bytes at {at}");
            assert!(error.to_string().contains("do not lie"), "{error}");
        }
        // The sum of the two would wrap around to a small number.
        assert!(mapping.write(usize::MAX, &[1]).is_err());
        assert_eq!(fs::read(&path).unwrap(), vec![7u8; 64]);
        // The edge itself is inside.
        mapping.write(63, &[1]).unwrap();
        mapping.write(64, &[]).unwrap();
        assert_eq!(fs::read(&path).unwrap()[63], 1);
    }

    #[test]
    fn a_mapping_says_how_many_bytes_it_holds() {
        let (_dir, _path, mapping) = device_of(&[0u8; 1001]);
        assert_eq!(mapping.len(), 1001);
        assert!(!mapping.is_empty());
    }

    #[test]
    fn a_frame_equal_to_the_window_has_no_rows_that_changed() {
        // Row lengths that are a multiple of a word, and that are not; window lengths that are
        // a multiple of a row and a word, and that are not; a single row and more rows than bytes.
        for len in [1, 7, 8, 9, 61, 960, 1001, 8191, 8192] {
            let held = pattern(len);
            let (_dir, path, mapping) = device_of(&held);
            for row_bytes in [1, 3, 7, 8, 9, 13, 16, 960, 1920, 10_000] {
                assert_eq!(mapping.changed_rows(&held, row_bytes), None);
                assert_agrees(&mapping, &path, &held, row_bytes);
            }
        }
    }

    #[test]
    fn one_changed_byte_is_found_in_its_row_wherever_it_lies() {
        // Every position of 61 bytes, for rows that are shorter than, as long as, and longer
        // than a word, which start at addresses of every kind of alignment.
        let held = pattern(61);
        let (_dir, path, mapping) = device_of(&held);
        for row_bytes in [1, 5, 7, 8, 9, 15, 16, 17, 60, 61, 62] {
            for at in 0..held.len() {
                let mut frame = held.clone();
                frame[at] ^= 0x40;
                let row = at / row_bytes;
                assert_eq!(
                    mapping.changed_rows(&frame, row_bytes),
                    Some(row..row + 1),
                    "byte {at}, rows of {row_bytes}"
                );
                assert_agrees(&mapping, &path, &frame, row_bytes);
            }
        }
    }

    #[test]
    fn the_rows_that_changed_run_from_the_first_to_the_last_that_differ_in_a_whole_frame() {
        const ROW_BYTES: usize = 960;
        const FRAME_BYTES: usize = 307_200;
        let held = pattern(FRAME_BYTES);
        let (_dir, path, mapping) = device_of(&held);
        let with = |bytes: &[usize]| {
            let mut frame = held.clone();
            for &at in bytes {
                frame[at] = !frame[at];
            }
            assert_agrees(&mapping, &path, &frame, ROW_BYTES);
            mapping.changed_rows(&frame, ROW_BYTES)
        };
        assert_eq!(with(&[]), None);
        // One pixel of row 10.
        assert_eq!(with(&[10 * ROW_BYTES + 400]), Some(10..11));
        // Rows 3 and 200, and nothing between them.
        assert_eq!(with(&[3 * ROW_BYTES, 200 * ROW_BYTES + 959]), Some(3..201));
        // The first byte, the last byte, and both.
        assert_eq!(with(&[0]), Some(0..1));
        assert_eq!(with(&[FRAME_BYTES - 1]), Some(319..320));
        assert_eq!(with(&[0, FRAME_BYTES - 1]), Some(0..320));
        // The last byte of a row and the first of the next.
        assert_eq!(with(&[ROW_BYTES - 1, ROW_BYTES]), Some(0..2));
    }

    #[test]
    fn rows_and_a_window_of_no_whole_words_have_the_rows_of_slices() {
        // 8191 bytes in rows of 13 is 631 rows, the last of 5 bytes, and none starts where the
        // one before it ended on a word.
        let held = pattern(8191);
        let (_dir, path, mapping) = device_of(&held);
        for row_bytes in [13, 7, 1001, 4095, 4096] {
            let rows = 8191usize.div_ceil(row_bytes);
            for row in [0, 1, rows / 2, rows - 2, rows - 1] {
                let mut frame = held.clone();
                let at = row * row_bytes;
                // The first byte of a row, then its last (the last row's last byte is the end).
                for byte in [at, (at + row_bytes).min(8191) - 1] {
                    frame[byte] ^= 1;
                    assert_eq!(
                        mapping.changed_rows(&frame, row_bytes),
                        Some(row..row + 1),
                        "byte {byte} in rows of {row_bytes}"
                    );
                    assert_agrees(&mapping, &path, &frame, row_bytes);
                    frame[byte] ^= 1;
                }
            }
            // The first and last rows together.
            let mut frame = held.clone();
            frame[0] ^= 1;
            frame[8190] ^= 1;
            assert_eq!(mapping.changed_rows(&frame, row_bytes), Some(0..rows));
            assert_agrees(&mapping, &path, &frame, row_bytes);
        }
    }

    #[test]
    fn a_frame_of_another_length_differs_in_all_its_rows_as_for_slices() {
        let held = pattern(1920);
        let (_dir, path, mapping) = device_of(&held);
        for len in [0, 1, 959, 960, 961, 1919, 1921, 2880, 5000] {
            let frame = pattern(len);
            assert_agrees(&mapping, &path, &frame, 960);
            assert_agrees(&mapping, &path, &frame, 7);
        }
        assert_eq!(mapping.changed_rows(&pattern(960), 960), Some(0..1));
        assert_eq!(mapping.changed_rows(&pattern(2880), 960), Some(0..3));
        assert_eq!(mapping.changed_rows(&pattern(1000), 960), Some(0..2));
        assert_eq!(mapping.changed_rows(&[], 960), Some(0..0));
    }

    #[test]
    #[should_panic(expected = "rows of no bytes")]
    fn rows_of_no_bytes_are_refused_as_for_slices() {
        let (_dir, _path, mapping) = device_of(&[0u8; 16]);
        let _ = mapping.changed_rows(&[0u8; 16], 0);
    }

    #[test]
    fn what_another_writer_puts_in_the_window_is_found() {
        // The reason the picture is compared with the memory and not with a copy: a writer
        // outside, here the file, as the kernel's console is for a screen.
        let held = pattern(8192);
        let (_dir, path, mut mapping) = device_of(&held);
        assert_eq!(mapping.changed_rows(&held, 960), None);
        let device = File::options().write(true).open(&path).unwrap();
        std::os::unix::fs::FileExt::write_all_at(&device, b"console", 4000).unwrap();
        assert_eq!(mapping.changed_rows(&held, 960), Some(4..5));
        // Painted over, it is the picture again.
        mapping.write(4000, &held[4000..4007]).unwrap();
        assert_eq!(mapping.changed_rows(&held, 960), None);
    }

    #[test]
    fn what_a_write_changes_is_what_the_comparison_finds() {
        let held = pattern(8192);
        let (_dir, path, mut mapping) = device_of(&held);
        let mut frame = held.clone();
        frame[961..1921].fill(0xee);
        assert_eq!(mapping.changed_rows(&frame, 960), Some(1..3));
        mapping.write(960, &frame[960..2880]).unwrap();
        assert_eq!(mapping.changed_rows(&frame, 960), None);
        assert_agrees(&mapping, &path, &frame, 960);
        assert_eq!(fs::read(&path).unwrap(), frame);
    }

    /// Prints what a whole picture's compare and write cost over a file, in release, for the
    /// numbers that go with the hot-path report. It asserts nothing about them.
    ///
    /// `cargo test --release -p qberrypi the_cost_of_a_whole_picture -- --ignored --nocapture`
    #[test]
    #[ignore = "prints timings; run it in release"]
    fn the_cost_of_a_whole_picture() {
        use std::hint::black_box;
        use std::time::Instant;

        const RUNS: u32 = 200;
        const ROW_BYTES: usize = 960;
        const FRAME_BYTES: usize = 307_200;
        let frame = pattern(FRAME_BYTES);
        let (_dir, _path, mut mapping) = device_of(&frame);
        // The mean of all the runs, and the quickest one: on a busy machine the mean is noisy.
        let time = |what: &str, run: &mut dyn FnMut()| {
            run();
            let mut total = Duration::ZERO;
            let mut best = Duration::MAX;
            for _ in 0..RUNS {
                let start = Instant::now();
                run();
                let took = start.elapsed();
                total += took;
                best = best.min(took);
            }
            let micros = |time: Duration| time.as_secs_f64() * 1e6;
            println!(
                "{what:<54} mean {:>7.1} us, best {:>7.1} us",
                micros(total / RUNS),
                micros(best)
            );
        };
        println!("\n{FRAME_BYTES} bytes in rows of {ROW_BYTES}, {RUNS} runs each:");
        // The worst case of a compare: all of it equal.
        time("mapping: compare, equal (volatile u64 words)", &mut || {
            assert_eq!(
                black_box(&mapping).changed_rows(black_box(&frame), ROW_BYTES),
                None
            );
        });
        let mut other = frame.clone();
        other[0] ^= 1;
        other[FRAME_BYTES - 1] ^= 1;
        time("mapping: compare, first and last rows differ", &mut || {
            assert_eq!(
                black_box(&mapping).changed_rows(black_box(&other), ROW_BYTES),
                Some(0..320)
            );
        });
        let mut middle = frame.clone();
        middle[160 * ROW_BYTES + 5] ^= 1;
        time("mapping: compare, only row 160 differs", &mut || {
            assert_eq!(
                black_box(&mapping).changed_rows(black_box(&middle), ROW_BYTES),
                Some(160..161)
            );
        });
        time("mapping: write all", &mut || {
            mapping.write(0, black_box(&frame)).unwrap();
        });
        // What this replaced, a slice over the window (only to time it: the slice is the
        // reference that `SharedMapping` no longer makes), and the same over memory of the heap.
        // SAFETY: the window is `len` bytes of a live mapping, and nothing else writes it here.
        let window = unsafe { std::slice::from_raw_parts_mut(mapping.start.as_ptr(), mapping.len) };
        time("slice over the mapping: compare, equal", &mut || {
            assert_eq!(
                qb_panel::rows::changed_rows(black_box(window), black_box(&frame), ROW_BYTES),
                None
            );
        });
        time("slice over the mapping: copy all", &mut || {
            black_box(&mut *window).copy_from_slice(black_box(&frame));
        });
        let mut heap = frame.clone();
        time("slice over the heap: compare, equal", &mut || {
            assert_eq!(
                qb_panel::rows::changed_rows(black_box(&heap), black_box(&frame), ROW_BYTES),
                None
            );
        });
        time("slice over the heap: copy all", &mut || {
            black_box(&mut heap).copy_from_slice(black_box(&frame));
        });
    }

    #[test]
    fn a_file_shorter_than_its_mapping_is_refused_not_left_to_kill_the_process() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device");
        fs::write(&path, vec![0u8; 100]).unwrap();
        let file = File::options().read(true).write(true).open(&path).unwrap();
        assert_eq!(
            SharedMapping::of_framebuffer(&file, 8192, 960)
                .err()
                .map(|e| e.kind()),
            Some(ErrorKind::InvalidInput)
        );
        assert_eq!(
            SharedMapping::of_framebuffer(&file, 0, 960)
                .err()
                .map(|e| e.kind()),
            Some(ErrorKind::InvalidInput)
        );
        // A file only open for writing cannot be shared as a window onto it.
        let write_only = File::options().write(true).open(&path).unwrap();
        assert!(SharedMapping::of_framebuffer(&write_only, 100, 960).is_err());
    }

    #[test]
    fn a_framebuffer_with_less_memory_than_the_window_or_other_rows_is_refused() {
        let memory = |bytes, row_bytes| Memory { bytes, row_bytes };
        assert!(check_memory(&memory(307_200, 960), 307_200, 960).is_ok());
        // More memory than the window needs is no harm.
        assert!(check_memory(&memory(614_400, 960), 307_200, 960).is_ok());
        let refused = |memory: Memory| {
            let error = check_memory(&memory, 307_200, 960).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidInput);
            error.to_string()
        };
        assert_eq!(
            refused(memory(153_600, 960)),
            "the device holds 153600 bytes"
        );
        assert_eq!(
            refused(memory(307_200, 1024)),
            "its rows are 1024 bytes long, not 960"
        );
    }

    #[test]
    fn a_device_that_will_not_say_what_it_holds_is_not_mapped() {
        // A character device that is no framebuffer: the question gets no answer, and
        // the mapping is not tried (it would fail differently, with "no such device").
        let null = File::options()
            .read(true)
            .write(true)
            .open("/dev/null")
            .unwrap();
        assert_eq!(
            memory_of(&null).err().and_then(|e| e.raw_os_error()),
            Some(Errno::NOTTY.raw_os_error())
        );
        let error = SharedMapping::of_framebuffer(&null, 307_200, 960)
            .err()
            .unwrap();
        assert!(
            error.to_string().contains("would not say how much"),
            "{error}"
        );
    }

    #[test]
    fn the_framebuffer_information_is_laid_out_as_the_kernel_lays_it_out() {
        // The request has no size in its number, so only the size of the struct tells
        // the kernel how much it may write: it must be the kernel's `fb_fix_screeninfo`.
        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(size_of::<FixScreenInfo>(), 80);
            assert_eq!(std::mem::offset_of!(FixScreenInfo, smem_len), 24);
            assert_eq!(std::mem::offset_of!(FixScreenInfo, line_length), 48);
        }
    }

    #[test]
    fn a_packet_socket_on_interface_index_zero_is_refused_before_anything_is_opened() {
        // The kernel takes index 0 in a bind to mean every interface: the socket would hear all of
        // them. The refusal comes before any socket is made, so it needs no privilege.
        let error = packet_socket(0, 0x0806).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(error.to_string().contains("every interface"), "{error}");
        // Index 0 is refused for any ethertype, the refused one among them.
        assert_eq!(
            packet_socket(0, 0).err().map(|e| e.kind()),
            Some(ErrorKind::InvalidInput)
        );
    }
}
