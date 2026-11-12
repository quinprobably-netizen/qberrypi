//! Which cores the runtime's threads may run on.
//!
//! An experiment, off by default (`speed.runtime_cpu`): on the BCM2837 every peripheral
//! interrupt (the SDIO Wi-Fi, the SPI screen) is routed to core 0, so a thread that answers DNS
//! on core 0 competes with the interrupts that bring the questions in. Pinning the runtime's
//! thread to another core, and keeping the blocking pool off that core, shows whether the
//! answers get faster.
//!
//! This is the kernel's affinity call, through rustix's safe wrappers. A thread that is created
//! starts with the mask of the thread that created it, so the pool's threads begin on the
//! runtime's core and each has to leave it by itself ([`all_but_current_thread`]). So does every
//! other thread that the runtime's thread creates (the TLS handshake's, the netlink send
//! thread's): [`spawn_off_runtime_core`] is how they are made.

use rustix::io::Errno;
use rustix::thread::{CpuSet, sched_getaffinity, sched_setaffinity};
use std::io;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{Builder, JoinHandle};

/// The cores the process could use before the first of its threads was pinned. A pool thread
/// starts with its creator's mask, which is the pinned core alone, so the cores to spread over
/// are remembered here. Never written by anything but [`pin_current_thread`], and only once.
static PROCESS_CORES: OnceLock<CpuSet> = OnceLock::new();

/// The core that the runtime's thread is pinned to; unset while nothing is pinned. Init pins one
/// thread, the one that then runs the runtime, so the first thread that [`pin_current_thread`]
/// pins is the runtime's. Never written by anything else, and only once.
static RUNTIME_CORE: OnceLock<usize> = OnceLock::new();

/// Whether a thread that could not leave the runtime's core was logged already: one line is
/// enough, as every such thread fails for the same reason.
static LEAVE_LOGGED: AtomicBool = AtomicBool::new(false);

/// The error for a core that no mask can name: the kernel's own words for a bad argument.
fn no_such_core() -> io::Error {
    io::Error::from(Errno::INVAL)
}

/// Whether `core` fits in a [`CpuSet`]; the set's bit operations panic beyond it.
fn nameable(core: usize) -> io::Result<()> {
    if core < CpuSet::MAX_CPU {
        Ok(())
    } else {
        Err(no_such_core())
    }
}

/// `cores` without `core`, or `None` when nothing is left.
fn without(mut cores: CpuSet, core: usize) -> Option<CpuSet> {
    cores.unset(core);
    (cores.count() > 0).then_some(cores)
}

/// Pins the calling thread to `core` alone.
///
/// Fails, and leaves the thread as it was, when `core` is beyond what a mask can name or when
/// the process may not use it (the host's cgroup, `taskset` or an offline core). The first
/// success remembers the cores the process had, for [`all_but_current_thread`], and the core, for
/// [`leave_runtime_core`].
pub fn pin_current_thread(core: usize) -> io::Result<()> {
    nameable(core)?;
    let before = sched_getaffinity(None)?;
    let mut only = CpuSet::new();
    only.set(core);
    sched_setaffinity(None, &only)?;
    PROCESS_CORES.get_or_init(|| before);
    RUNTIME_CORE.get_or_init(|| core);
    Ok(())
}

/// Sets the calling thread to every core the process may use except `core`.
///
/// With no other core to use (a one-core host, or a process that is allowed only `core`) it
/// changes nothing and succeeds. Fails when `core` is beyond what a mask can name or when the
/// kernel refuses the mask.
pub fn all_but_current_thread(core: usize) -> io::Result<()> {
    nameable(core)?;
    let cores = match PROCESS_CORES.get() {
        Some(cores) => *cores,
        None => sched_getaffinity(None)?,
    };
    match without(cores, core) {
        Some(others) => Ok(sched_setaffinity(None, &others)?),
        None => Ok(()),
    }
}

/// What a thread does first to leave `pinned` as the runtime's core: nothing when no thread was
/// pinned, and otherwise [`all_but_current_thread`].
fn leave(pinned: Option<usize>) -> io::Result<()> {
    pinned.map_or(Ok(()), all_but_current_thread)
}

/// Takes the calling thread off the core that the runtime's thread is pinned to: it is the first
/// thing that a thread made by the runtime's thread does, as such a thread starts with the
/// runtime's one-core mask and would otherwise compete with the DNS service for it.
///
/// Changes nothing when no thread is pinned (`speed.runtime_cpu` unset, or a core that could not
/// be taken). A failure is logged, once for all the threads, and the thread goes on where it is.
/// [`spawn_off_runtime_core`] makes a thread that does this.
pub fn leave_runtime_core() {
    let pinned = RUNTIME_CORE.get().copied();
    if let Err(error) = leave(pinned)
        && !LEAVE_LOGGED.swap(true, Ordering::Relaxed)
    {
        let core = pinned.unwrap_or_default();
        log::warn!("cpu: a thread could not leave core {core}: {error}");
    }
}

/// Starts a thread called `name` that runs `work` after it has left the runtime's core
/// ([`leave_runtime_core`]). For every `std` thread that the runtime's thread creates: a plain
/// `thread::spawn` there starts on the runtime's core when the runtime is pinned.
///
/// A thread that cannot be made is the error.
pub fn spawn_off_runtime_core<T, F>(name: &str, work: F) -> io::Result<JoinHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    Builder::new().name(name.to_owned()).spawn(move || {
        leave_runtime_core();
        work()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services;

    /// The cores of `set`, lowest first.
    fn cores_of(set: &CpuSet) -> Vec<usize> {
        (0..CpuSet::MAX_CPU).filter(|c| set.is_set(*c)).collect()
    }

    /// The cores the calling thread may run on.
    fn mask_now() -> Vec<usize> {
        cores_of(&sched_getaffinity(None).unwrap())
    }

    /// Runs `work` on a thread of its own, so that no test changes the mask of a thread of the
    /// test harness: the thread ends with the test, and so does its pin.
    fn on_a_new_thread<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
        std::thread::spawn(work)
            .join()
            .expect("the thread panicked")
    }

    #[test]
    fn a_thread_pinned_to_core_0_runs_only_there() {
        // Core 0 on every host that does not restrict the process; on one that does, the lowest
        // core it may use.
        let allowed = mask_now();
        assert!(!allowed.is_empty());
        let core = allowed[0];
        let (mask, running_on) = on_a_new_thread(move || {
            pin_current_thread(core).unwrap();
            (mask_now(), rustix::thread::sched_getcpu())
        });
        assert_eq!(mask, vec![core]);
        assert_eq!(running_on, core);
        // The harness's own thread kept its mask.
        assert_eq!(mask_now(), allowed);
    }

    #[test]
    fn all_but_leaves_out_the_core() {
        let allowed = mask_now();
        if allowed.len() < 2 {
            println!(
                "skipped: the host allows {} CPU(s), the test needs 2",
                allowed.len()
            );
            return;
        }
        let core = allowed[0];
        let mask = on_a_new_thread(move || {
            all_but_current_thread(core).unwrap();
            mask_now()
        });
        assert_eq!(mask, allowed[1..].to_vec());
        assert_eq!(mask_now(), allowed);
    }

    #[test]
    fn a_pinned_runtime_keeps_its_pool_off_the_core() {
        let allowed = mask_now();
        if allowed.len() < 2 {
            println!(
                "skipped: the host allows {} CPU(s), the test needs 2",
                allowed.len()
            );
            return;
        }
        let core = allowed[0];
        let (runtime_thread, pool_thread) = on_a_new_thread(move || {
            pin_current_thread(core).unwrap();
            let runtime = services::runtime(Some(core)).unwrap();
            let pool = runtime
                .block_on(services::blocking("test", mask_now))
                .unwrap();
            (mask_now(), pool)
        });
        assert_eq!(runtime_thread, vec![core]);
        assert_eq!(pool_thread, allowed[1..].to_vec());
    }

    #[test]
    fn an_unpinned_runtime_leaves_the_pool_as_it_found_it() {
        let allowed = mask_now();
        let pool_thread = on_a_new_thread(|| {
            let runtime = services::runtime(None).unwrap();
            runtime
                .block_on(services::blocking("test", mask_now))
                .unwrap()
        });
        assert_eq!(pool_thread, allowed);
    }

    #[test]
    fn a_core_no_mask_can_name_is_an_error_not_a_panic() {
        assert!(pin_current_thread(CpuSet::MAX_CPU).is_err());
        assert!(all_but_current_thread(CpuSet::MAX_CPU).is_err());
        assert!(pin_current_thread(usize::MAX).is_err());
    }

    #[test]
    fn a_core_the_process_may_not_use_leaves_the_thread_as_it_was() {
        // The last core a mask can name is not one that any board has.
        let allowed = mask_now();
        let core = CpuSet::MAX_CPU - 1;
        assert!(!allowed.contains(&core));
        let mask = on_a_new_thread(move || {
            assert!(pin_current_thread(core).is_err());
            mask_now()
        });
        assert_eq!(mask, allowed);
    }

    #[test]
    fn a_thread_made_by_a_pinned_one_leaves_its_core() {
        let allowed = mask_now();
        if allowed.len() < 2 {
            println!(
                "skipped: the host allows {} CPU(s), the test needs 2",
                allowed.len()
            );
            return;
        }
        let core = allowed[0];
        let (parent, child) = on_a_new_thread(move || {
            pin_current_thread(core).unwrap();
            // A plain thread starts where its creator is, which is what the helper is for; this
            // shows that the test could tell the difference.
            let plain = std::thread::spawn(mask_now).join().unwrap();
            assert_eq!(plain, vec![core]);
            let child = spawn_off_runtime_core("test child", || {
                (std::thread::current().name().map(str::to_owned), mask_now())
            })
            .unwrap()
            .join()
            .unwrap();
            (mask_now(), child)
        });
        assert_eq!(parent, vec![core]);
        assert_eq!(
            child,
            (Some("test child".to_owned()), allowed[1..].to_vec())
        );
        assert_eq!(mask_now(), allowed);
    }

    #[test]
    fn with_no_core_pinned_a_thread_has_nothing_to_leave() {
        let allowed = mask_now();
        // Whatever the other tests of this process pinned, `leave` goes by what it is given.
        let mask = on_a_new_thread(|| {
            leave(None).unwrap();
            mask_now()
        });
        assert_eq!(mask, allowed);
        assert!(leave(Some(CpuSet::MAX_CPU)).is_err());
    }

    #[test]
    fn the_cores_left_after_one_is_taken_out() {
        let mut two = CpuSet::new();
        two.set(1);
        two.set(3);
        assert_eq!(cores_of(&without(two, 1).unwrap()), vec![3]);
        assert_eq!(cores_of(&without(two, 0).unwrap()), vec![1, 3]);
        let mut one = CpuSet::new();
        one.set(2);
        assert!(without(one, 2).is_none());
        assert_eq!(cores_of(&without(one, 0).unwrap()), vec![2]);
    }
}
