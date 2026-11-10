//! The system calls qberrypi makes itself, each behind a safe function.
//!
//! This is the only file that may contain `unsafe`. Nearly everything here
//! changes the machine it runs on, so the tests cover only the parts that
//! decide something: the rest is proven by booting the image.

use std::ffi::{CStr, CString, c_int};
use std::fs::{self, File};
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use rustix::ioctl::{self, Opcode, Updater, opcode};
use rustix::mount::{MountFlags, UnmountFlags};
use rustix::process::WaitOptions;
use rustix::system::RebootCommand;
use rustix::time::{ClockId, Timespec};

/// Where the kernel lists the modules it has, loaded or still initialising.
const SYSFS_MODULES: &str = "/sys/module";
/// The file that names the program the kernel runs to load a module.
const MODULE_HELPER_SETTING: &str = "/proc/sys/kernel/modprobe";
const KERNEL_COMMAND_LINE: &str = "/proc/cmdline";
const WATCHDOG_DEV: &str = "/dev/watchdog";

/// The request that sets a watchdog's timeout: `_IOWR('W', 6, int)`.
const WDIOC_SETTIMEOUT: Opcode = opcode::read_write::<c_int>(b'W', 6);

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
/// Stops at the first that fails; the error names it.
pub fn mount_pseudo() -> io::Result<()> {
    for mount in &PSEUDO_MOUNTS {
        let named = |error: io::Error| {
            io::Error::new(error.kind(), format!("mounting {}: {error}", mount.target))
        };
        fs::create_dir_all(mount.target).map_err(named)?;
        rustix::mount::mount(
            mount.fs_type,
            mount.target,
            mount.fs_type,
            mount.flags,
            mount.options,
        )
        .map_err(|errno| named(errno.into()))?;
    }
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

    const SELFTEST: &str = "qberrypi.selftest";

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
}
