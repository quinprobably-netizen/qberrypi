//! The saver: looks at the kept settings every [`POLL`] and writes them when it is time.
//!
//! **What it does.** Every poll it takes a snapshot (three short lock-and-copy steps over the
//! inventory, the owner's names and the panel's state, never the resolver's lock) and encodes it
//! ([`encode_payload`]), as a job of the blocking pool: the panel's lock is held for the whole of
//! a PIN's check, and the runtime's thread may not wait for that. Because the encoding is deterministic, "did anything change" is a byte
//! comparison, and the saver needs no notion of what changed. It saves when the bytes differ from
//! what the newest copy on the card holds (the baseline), have not changed for
//! [`QUIET`](super::debounce::QUIET), at least [`MIN_GAP`](super::debounce::MIN_GAP) have passed
//! since the last save began (all of it [`Debounce`]'s) and no update is being received or staged
//! and no trial is on (the idle check). A boot that changes nothing, or changes a setting and
//! changes it back, writes nothing and creates nothing.
//!
//! **The baseline** is the payload of the newest whole copy a start found. With no whole copy on
//! the card it is the encoding of the saver's first snapshot, taken after the restore: that
//! snapshot carries this boot's configuration PIN fingerprint and night, so the empty state is not
//! the state of a boot that changed nothing.
//!
//! **The write** is a blocking job of the pool, one at a time: the poller awaits it, so it never
//! starts a second, and a runtime thread is never held for the card. What the write does is the
//! [`Writer`]'s (the card's, in [`super::card`]); this file only needs to know what came of it
//! ([`Written`]): a copy saved, the card not given just now (tried again after the gap), or saving
//! turned off for the boot, which ends the poller with the reason.
//!
//! **The owner's restart** saves at once ([`Saver::flush`]), from init's own thread after the
//! supervisor has ended, when the bytes differ and nothing is being received: debounce does not
//! apply, the card claim and the update rule do.
//!
//! The settings are the owner's, so every line made here says copy letters, sequence numbers and
//! the operating system's own words: no address, label, name or hash.

use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, TryLockError};
use std::thread;
use std::time::Duration;

use tokio::time::{Instant, sleep};

use super::Saved;
use super::debounce::{Debounce, POLL};
use super::format::{Oversize, encode_payload};
use super::store::Which;
use crate::services::blocking;

/// How the writing of one save went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Written {
    /// The payload is in copy `.0`, with sequence `.1`, and that copy is now the newest.
    Saved(Which, u64),
    /// Nothing was written, because the card was not given just now (a fatal error's rescue has
    /// it, or another use has had it for longer than a claim waits). A later try may succeed. The
    /// text says why, in words that quote no byte of any file.
    Later(String),
    /// Saving is off for the rest of the boot: the card did not say where the copies lie, said
    /// what was not true, changed under the save, or failed a write or the creation. The text says
    /// what, and no byte of any file.
    Off(String),
}

/// What turns a payload into a saved copy: the real card's [`super::card::CardWriter`], or in a
/// test a stand-in. It blocks, so it runs on the pool or on init's own thread.
pub trait Writer: Send {
    /// Writes `payload` as the next copy (making the copies first if the card has not both).
    fn write(&mut self, payload: &[u8]) -> Written;
}

/// What a look at the state gave.
pub enum Look {
    /// The state's encoding.
    Encoded(Vec<u8>),
    /// The state is more than a copy holds, so there is nothing to compare or save.
    TooBig,
    /// The look could not be made (the pool that was to make it is gone): this poll is skipped.
    Missed,
}

/// What the saver knows that changes: the newest copy's bytes and whether saving is off.
struct Book {
    /// What the newest copy on the card holds, as a payload; `None` while it is not yet known
    /// (no copy, and no snapshot has been taken).
    baseline: Option<Vec<u8>>,
    /// Why saving is off for this boot, once it is.
    off: Option<String>,
}

/// Looks at the kept settings and saves them when it is time; see the module's text.
pub struct Saver {
    /// What the three structures hold of the kept state, copied: short, and on the runtime.
    snapshot: Box<dyn Fn() -> Saved + Send + Sync>,
    /// Whether no update is being received or staged and no trial is on.
    idle: Box<dyn Fn() -> bool + Send + Sync>,
    /// The way to the card. Held for the whole of a save, so one save is made at a time, on
    /// whichever thread makes it; never taken on the runtime's thread.
    writer: Mutex<Box<dyn Writer>>,
    /// The baseline and the off switch, held for no longer than a copy of either.
    book: Mutex<Book>,
    /// Called once, when saving goes off for the boot (and at the start if it is off from the first):
    /// it tells whoever shows the owner that the settings outlast a restart that they no longer do.
    /// Quick, and never takes a lock the saver holds.
    on_off: Box<dyn Fn() + Send + Sync>,
}

impl Saver {
    /// A saver over `snapshot`, `idle` and `writer`.
    ///
    /// `baseline` is the payload of the newest whole copy a start found, or `None` when there is
    /// none: the saver then takes its first snapshot now (so after the restore, which the caller
    /// has done) and that is the baseline. `off` is why saving is off from the first, if the read
    /// of the card found trouble. `on_off` is called once when saving is off, now if `off` is set
    /// and otherwise when a write turns it off.
    pub fn new(
        snapshot: Box<dyn Fn() -> Saved + Send + Sync>,
        idle: Box<dyn Fn() -> bool + Send + Sync>,
        writer: Box<dyn Writer>,
        baseline: Option<Vec<u8>>,
        off: Option<String>,
        on_off: Box<dyn Fn() + Send + Sync>,
    ) -> Arc<Self> {
        let off_now = off.is_some();
        let saver = Arc::new(Self {
            snapshot,
            idle,
            writer: Mutex::new(writer),
            book: Mutex::new(Book { baseline, off }),
            on_off,
        });
        if let Ok(first) = saver.encode() {
            saver.adopt(&first);
        }
        if off_now {
            (saver.on_off)();
        }
        saver
    }

    /// The baseline and the switch, locked; a lock that a panic poisoned still holds a whole copy
    /// of either.
    fn book(&self) -> MutexGuard<'_, Book> {
        self.book.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The snapshot, encoded.
    fn encode(&self) -> Result<Vec<u8>, Oversize> {
        encode_payload(&(self.snapshot)())
    }

    /// Makes `bytes` the baseline if there is none yet.
    fn adopt(&self, bytes: &[u8]) {
        self.book().baseline.get_or_insert_with(|| bytes.to_vec());
    }

    /// Whether `bytes` differ from what the newest copy holds. With no baseline yet there is
    /// nothing to differ from.
    fn differs(&self, bytes: &[u8]) -> bool {
        self.book()
            .baseline
            .as_deref()
            .is_some_and(|baseline| baseline != bytes)
    }

    /// Why saving is off for this boot, if it is.
    pub fn off(&self) -> Option<String> {
        self.book().off.clone()
    }

    /// Notes what came of writing `bytes`: the copy that holds them is the newest, or saving is off
    /// (which is said to `on_off`, the first time only, with the book's lock let go of).
    fn note(&self, bytes: &[u8], written: &Written) {
        let went_off = {
            let mut book = self.book();
            match written {
                Written::Saved(..) => {
                    book.baseline = Some(bytes.to_vec());
                    false
                }
                Written::Off(why) => {
                    let first = book.off.is_none();
                    book.off.get_or_insert_with(|| why.clone());
                    first
                }
                Written::Later(_) => false,
            }
        };
        if went_off {
            (self.on_off)();
        }
    }

    /// Writes `bytes` now, on the calling thread, which blocks for as long as the write takes (and
    /// waits for another save that is under way): the job of the pool, never of the runtime.
    pub fn write_now(&self, bytes: &[u8]) -> Written {
        let written = self
            .writer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .write(bytes);
        self.note(bytes, &written);
        written
    }

    /// A look at the state now: its snapshot, encoded.
    fn look(&self) -> Look {
        match self.encode() {
            Ok(bytes) => Look::Encoded(bytes),
            Err(Oversize) => Look::TooBig,
        }
    }

    /// Looks at the state every [`POLL`], for as long as saving is on, and hands each payload that
    /// is due to `dispatch`, which writes it and is awaited, so that one save is made at a time.
    /// Returns why saving went off.
    ///
    /// `look` makes the look ([`Saver::look`]) and `dispatch` the write ([`Saver::write_now`]): in
    /// the board both are jobs of the blocking pool ([`Saver::run_on_pool`]), so that the runtime's
    /// thread never waits for a lock of the three structures (the panel's lock is held for the
    /// whole of a PIN's check) or for the card. A state that cannot be encoded (more than a copy
    /// holds) is one WARN line and no save, and the poller goes on; so is a card that was not
    /// given, which is tried again after the gap. A write that fails ends the poller.
    pub async fn run<L, LF, D, F>(&self, mut look: L, mut dispatch: D) -> String
    where
        L: FnMut() -> LF,
        LF: Future<Output = Look>,
        D: FnMut(Vec<u8>) -> F,
        F: Future<Output = Written>,
    {
        let mut debounce = Debounce::new(Instant::now());
        let mut last: Option<Vec<u8>> = None;
        let mut too_big = false;
        loop {
            if let Some(why) = self.off() {
                return why;
            }
            match look().await {
                Look::Missed => {}
                Look::TooBig => {
                    if !too_big {
                        log::warn!(
                            "state: the settings are more than a copy holds; nothing is saved until they fit"
                        );
                        too_big = true;
                    }
                }
                Look::Encoded(bytes) => {
                    too_big = false;
                    let now = Instant::now();
                    self.adopt(&bytes);
                    debounce.seen(last.as_deref() != Some(&bytes[..]), now);
                    if debounce.due(now, self.differs(&bytes)) && (self.idle)() {
                        debounce.saved(now);
                        match dispatch(bytes.clone()).await {
                            Written::Saved(which, seq) => {
                                log::info!("state: saved to copy {} (seq {seq})", which.letter());
                            }
                            Written::Later(why) => {
                                log::warn!("state: not saved now ({why}); trying again later");
                            }
                            Written::Off(why) => {
                                self.note(&bytes, &Written::Off(why.clone()));
                                return why;
                            }
                        }
                    }
                    last = Some(bytes);
                }
            }
            sleep(POLL).await;
        }
    }

    /// [`Saver::run`] with every look and every write a job of the blocking pool ([`blocking`]),
    /// which is how the board runs it. A job that cannot be joined (the runtime is going down) is a
    /// look that is missed, and a write that turns saving off.
    pub async fn run_on_pool(self: &Arc<Self>) -> String {
        let (looker, writer) = (self.clone(), self.clone());
        self.run(
            move || {
                let saver = looker.clone();
                async move {
                    blocking("state look", move || saver.look())
                        .await
                        .unwrap_or(Look::Missed)
                }
            },
            move |bytes| {
                let saver = writer.clone();
                async move {
                    match blocking("state save", move || saver.write_now(&bytes)).await {
                        Ok(written) => written,
                        Err(error) => Written::Off(error.to_string()),
                    }
                }
            },
        )
        .await
    }

    /// Saves at once if the settings differ from the newest copy and nothing is being received:
    /// the owner's restart, which is made from init's own thread once the supervisor has ended, so
    /// this blocks. Debounce does not apply; the card claim (in the writer) and the update rule do.
    ///
    /// It does nothing when saving is off, when the settings are as the newest copy holds them,
    /// when an update is being received or staged or a trial is on, and when a save of the pool
    /// still has the card after `wait` (the line says so). A write that fails is a WARN line, as it
    /// is for the poller, and turns saving off.
    pub fn flush(&self, wait: Duration) {
        if self.off().is_some() {
            return;
        }
        let Ok(bytes) = self.encode() else {
            log::warn!("state: not saved at the restart: the settings are more than a copy holds");
            return;
        };
        if !self.differs(&bytes) {
            return;
        }
        if !(self.idle)() {
            log::warn!("state: not saved at the restart: an update is under way");
            return;
        }
        let Some(mut writer) = self.writer_within(wait) else {
            log::warn!("state: not saved at the restart: a save is still under way");
            return;
        };
        // A save of the pool that was under way may have written these very bytes.
        if !self.differs(&bytes) {
            return;
        }
        let written = writer.write(&bytes);
        drop(writer);
        self.note(&bytes, &written);
        match written {
            Written::Saved(which, seq) => {
                log::info!("state: saved to copy {} (seq {seq})", which.letter());
            }
            Written::Later(why) => log::warn!("state: not saved at the restart: {why}"),
            Written::Off(why) => {
                log::warn!("state: saving the settings is off for this boot: {why}");
            }
        }
    }

    /// The writer, locked, waiting at most `wait` for a save that holds it.
    fn writer_within(&self, wait: Duration) -> Option<MutexGuard<'_, Box<dyn Writer>>> {
        let began = std::time::Instant::now();
        loop {
            match self.writer.try_lock() {
                Ok(writer) => return Some(writer),
                Err(TryLockError::Poisoned(poisoned)) => return Some(poisoned.into_inner()),
                Err(TryLockError::WouldBlock) => {}
            }
            if began.elapsed() >= wait {
                return None;
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}

/// Where the saver is put when the shared state makes it, so that init, which does not make the
/// shared state, can [flush](Flusher::flush) it on the owner's restart.
#[derive(Default)]
pub struct Flusher {
    saver: OnceLock<Arc<Saver>>,
}

impl Flusher {
    /// A flusher with no saver yet.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Hands the saver over, once; a second saver is ignored.
    pub fn set(&self, saver: Arc<Saver>) {
        let _ = self.saver.set(saver);
    }

    /// [`Saver::flush`] of the saver that was handed over, waiting at most `wait` for a save under
    /// way; nothing when there is none (the shared state was never made, or persistence is off).
    pub fn flush(&self, wait: Duration) {
        if let Some(saver) = self.saver.get() {
            saver.flush(wait);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

    use qb_dns::OwnerSide;
    use tokio::time::advance;

    use super::super::SavedName;
    use super::*;

    /// How the stand-in writer answers.
    #[derive(Clone, Copy, PartialEq)]
    enum Mode {
        Saves,
        NotGiven,
        Fails,
    }

    /// What the tests see of the stand-in writer: when each write came, with its bytes.
    type Writes = Arc<Mutex<Vec<(Duration, Vec<u8>)>>>;

    /// The threads that ran the stand-ins: the writer's and the snapshot's.
    type Threads = Arc<Mutex<Vec<thread::ThreadId>>>;

    /// A writer that records its writes and answers as told.
    struct Fake {
        writes: Writes,
        threads: Threads,
        mode: Arc<Mutex<Mode>>,
        began: Instant,
        seq: u64,
    }

    impl Writer for Fake {
        fn write(&mut self, payload: &[u8]) -> Written {
            let mode = *self.mode.lock().unwrap();
            match mode {
                Mode::NotGiven => return Written::Later("the card is in use".to_owned()),
                Mode::Fails => return Written::Off("the card said no".to_owned()),
                Mode::Saves => {}
            }
            self.threads.lock().unwrap().push(thread::current().id());
            self.seq += 1;
            self.writes
                .lock()
                .unwrap()
                .push((self.began.elapsed(), payload.to_vec()));
            let copy = if self.seq % 2 == 1 {
                Which::A
            } else {
                Which::B
            };
            Written::Saved(copy, self.seq)
        }
    }

    /// A saver over a state the test sets, an idle flag it sets and a writer that records.
    struct Rig {
        state: Arc<AtomicU8>,
        idle: Arc<AtomicBool>,
        writes: Writes,
        threads: Threads,
        mode: Arc<Mutex<Mode>>,
        saver: Arc<Saver>,
        began: Instant,
        /// How many times the saver said that it went off.
        offs: Arc<AtomicUsize>,
    }

    /// The state that number `n` stands for: 0 is the empty one, every other differs from all
    /// the rest.
    fn state(n: u8) -> Saved {
        let mut saved = Saved::default();
        if n != 0 {
            saved.names.push(SavedName {
                name: format!("host-{n}.example.org").into(),
                side: OwnerSide::Refuse,
                set_unix: None,
            });
        }
        saved
    }

    /// A state that no payload holds: more names than a copy takes.
    fn too_big() -> Saved {
        Saved {
            names: (0..300)
                .map(|n| SavedName {
                    name: format!("host-{n}.example.org").into(),
                    side: OwnerSide::Refuse,
                    set_unix: None,
                })
                .collect(),
            ..Saved::default()
        }
    }

    /// The state number that stands for the one that is too big.
    const BIG: u8 = 255;

    fn payload(n: u8) -> Vec<u8> {
        encode_payload(&state(n)).unwrap()
    }

    impl Rig {
        /// A saver that starts from state `start` with `baseline` as the newest copy's payload.
        fn new(start: u8, baseline: Option<Vec<u8>>) -> Rig {
            let state = Arc::new(AtomicU8::new(start));
            let idle = Arc::new(AtomicBool::new(true));
            let writes: Writes = Arc::default();
            let threads: Threads = Arc::default();
            let mode = Arc::new(Mutex::new(Mode::Saves));
            let began = Instant::now();
            let offs = Arc::new(AtomicUsize::new(0));
            let writer = Fake {
                writes: writes.clone(),
                threads: threads.clone(),
                mode: mode.clone(),
                began,
                seq: 0,
            };
            let saver = Saver::new(
                {
                    let state = state.clone();
                    let looked = threads.clone();
                    Box::new(move || {
                        looked.lock().unwrap().push(thread::current().id());
                        match state.load(Ordering::SeqCst) {
                            BIG => too_big(),
                            n => self::state(n),
                        }
                    })
                },
                {
                    let idle = idle.clone();
                    Box::new(move || idle.load(Ordering::SeqCst))
                },
                Box::new(writer),
                baseline,
                None,
                {
                    let offs = offs.clone();
                    Box::new(move || {
                        offs.fetch_add(1, Ordering::SeqCst);
                    })
                },
            );
            Rig {
                state,
                idle,
                writes,
                threads,
                mode,
                saver,
                began,
                offs,
            }
        }

        fn set(&self, n: u8) {
            self.state.store(n, Ordering::SeqCst);
        }

        /// How many times the saver has said that saving went off.
        fn said_off(&self) -> usize {
            self.offs.load(Ordering::SeqCst)
        }

        fn set_idle(&self, idle: bool) {
            self.idle.store(idle, Ordering::SeqCst);
        }

        fn mode(&self, mode: Mode) {
            *self.mode.lock().unwrap() = mode;
        }

        /// Starts the poller as the board does, with the stand-in as the pool, and lets it take its
        /// first look before any time passes.
        async fn start(&self) -> tokio::task::JoinHandle<String> {
            let saver = self.saver.clone();
            let poller = tokio::spawn(async move {
                let (looker, writer) = (saver.clone(), saver.clone());
                saver
                    .run(
                        move || {
                            let looker = looker.clone();
                            async move { looker.look() }
                        },
                        move |bytes| {
                            let writer = writer.clone();
                            async move { writer.write_now(&bytes) }
                        },
                    )
                    .await
            });
            tokio::task::yield_now().await;
            poller
        }

        /// Lets `seconds` pass in the steps of one poll, so that every poll looks.
        async fn pass(&self, seconds: u64) {
            for _ in 0..seconds.div_ceil(POLL.as_secs()) {
                advance(POLL).await;
                // The poller takes its turn after the clock has moved.
                tokio::task::yield_now().await;
            }
        }

        fn seconds(&self) -> u64 {
            self.began.elapsed().as_secs()
        }

        /// When each write came, in seconds from the start, and which state it holds as a number.
        fn writes(&self) -> Vec<(u64, Vec<u8>)> {
            self.writes
                .lock()
                .unwrap()
                .iter()
                .map(|(at, bytes)| (at.as_secs(), bytes.clone()))
                .collect()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_is_saved_before_thirty_seconds_of_quiet_and_then_one_save_is_made() {
        let rig = Rig::new(0, Some(payload(0)));
        rig.set(1);
        let _poller = rig.start().await;
        rig.pass(25).await;
        assert!(rig.writes().is_empty(), "at {} s", rig.seconds());
        rig.pass(5).await;
        assert_eq!(rig.writes(), [(30, payload(1))], "at {} s", rig.seconds());
        // What is saved is the baseline now: nothing more follows.
        rig.pass(600).await;
        assert_eq!(rig.writes().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_change_starts_the_quiet_over() {
        let rig = Rig::new(0, Some(payload(0)));
        rig.set(1);
        let _poller = rig.start().await;
        rig.pass(20).await;
        rig.set(2);
        rig.pass(30).await;
        assert!(rig.writes().is_empty(), "at {} s", rig.seconds());
        rig.pass(10).await;
        assert_eq!(
            rig.writes(),
            [(55, payload(2))],
            "only the last state, once"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn steady_edits_make_at_most_one_save_a_minute() {
        let rig = Rig::new(0, Some(payload(0)));
        rig.set(1);
        let _poller = rig.start().await;
        // An edit every 40 s: each is quiet long enough to save 30 s on, and the second begins
        // before the minute is over.
        for n in 2..=12 {
            rig.pass(40).await;
            rig.set(n);
        }
        rig.pass(60).await;
        let times: Vec<u64> = rig.writes().iter().map(|(at, _)| *at).collect();
        assert!(times.len() >= 3, "saves at {times:?}");
        for pair in times.windows(2) {
            assert!(pair[1] - pair[0] >= 60, "saves at {times:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_is_saved_while_an_update_is_under_way_and_one_is_once_it_is_idle() {
        let rig = Rig::new(0, Some(payload(0)));
        rig.set_idle(false);
        rig.set(1);
        let _poller = rig.start().await;
        rig.pass(300).await;
        assert!(rig.writes().is_empty());
        rig.set_idle(true);
        rig.pass(POLL.as_secs()).await;
        assert_eq!(rig.writes(), [(305, payload(1))]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_state_that_comes_back_to_the_saved_one_is_not_written() {
        let rig = Rig::new(0, Some(payload(0)));
        let _poller = rig.start().await;
        rig.pass(5).await;
        rig.set(1);
        rig.pass(20).await;
        rig.set(0);
        rig.pass(300).await;
        assert!(
            rig.writes().is_empty(),
            "changed and changed back: {:?}",
            rig.writes()
        );
        // After a save, the saved state is the one to come back to.
        rig.set(2);
        rig.pass(40).await;
        assert_eq!(rig.writes().len(), 1);
        rig.set(3);
        rig.pass(20).await;
        rig.set(2);
        rig.pass(300).await;
        assert_eq!(rig.writes().len(), 1, "{:?}", rig.writes());
    }

    #[tokio::test(start_paused = true)]
    async fn with_no_copy_the_first_snapshot_is_the_baseline_and_not_the_empty_state() {
        // A boot whose configuration gives a state that is not the empty one: nothing is saved.
        let rig = Rig::new(7, None);
        let _poller = rig.start().await;
        rig.pass(600).await;
        assert!(
            rig.writes().is_empty(),
            "a boot that changed nothing writes nothing"
        );
        // A change from there is saved, and so is one back to the empty state.
        rig.set(8);
        rig.pass(35).await;
        assert_eq!(rig.writes().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn the_newest_copys_payload_is_the_baseline_when_there_is_one() {
        // The copy holds state 1 and the boot's own state is 1: nothing to save.
        let rig = Rig::new(1, Some(payload(1)));
        let _poller = rig.start().await;
        rig.pass(300).await;
        assert!(rig.writes().is_empty());
        // A boot whose state is not what the copy holds (a configuration that changed) saves once.
        let rig = Rig::new(2, Some(payload(1)));
        let _poller = rig.start().await;
        rig.pass(40).await;
        assert_eq!(rig.writes().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_save_that_fails_turns_the_saver_off_for_the_boot() {
        let rig = Rig::new(0, Some(payload(0)));
        rig.mode(Mode::Fails);
        rig.set(1);
        let poller = rig.start().await;
        rig.pass(35).await;
        assert!(poller.is_finished(), "the poller ended");
        assert_eq!(poller.await.unwrap(), "the card said no");
        assert_eq!(rig.saver.off().as_deref(), Some("the card said no"));
        assert_eq!(rig.said_off(), 1, "the owner's screen is told once");
        // Whatever is done later, nothing is written; and the restart's flush has nothing to do.
        rig.mode(Mode::Saves);
        rig.set(2);
        rig.saver.flush(Duration::from_millis(50));
        assert!(rig.writes().is_empty());
        assert_eq!(rig.said_off(), 1, "and not told again");
    }

    #[tokio::test(start_paused = true)]
    async fn a_card_that_is_not_given_is_tried_again_after_the_gap_and_saving_stays_on() {
        let rig = Rig::new(0, Some(payload(0)));
        rig.mode(Mode::NotGiven);
        rig.set(1);
        let poller = rig.start().await;
        rig.pass(35).await;
        assert!(!poller.is_finished());
        assert!(rig.writes().is_empty());
        assert_eq!(
            rig.said_off(),
            0,
            "saving is still on, so the screen is not told"
        );
        rig.mode(Mode::Saves);
        rig.pass(20).await;
        assert!(
            rig.writes().is_empty(),
            "not before the gap: {} s",
            rig.seconds()
        );
        rig.pass(35).await;
        assert_eq!(rig.writes(), [(90, payload(1))]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_state_that_is_too_big_is_not_saved_and_the_poller_goes_on() {
        let rig = Rig::new(0, Some(payload(0)));
        rig.set(BIG);
        let poller = rig.start().await;
        rig.pass(120).await;
        assert!(rig.writes().is_empty());
        assert!(!poller.is_finished());
        rig.set(1);
        rig.pass(35).await;
        assert_eq!(rig.writes().len(), 1);
        assert_eq!(rig.writes()[0].1, payload(1));
    }

    #[tokio::test(start_paused = true)]
    async fn on_the_board_every_look_and_every_write_is_a_job_of_the_pool() {
        let rig = Rig::new(0, Some(payload(0)));
        rig.set(1);
        let runtime_thread = thread::current().id();
        // Only what is made from here on is what the poller does.
        rig.threads.lock().unwrap().clear();
        let saver = rig.saver.clone();
        let poller = tokio::spawn(async move { saver.run_on_pool().await });
        // The pool's jobs run on real threads, so each poll is given real time to come back.
        for _ in 0..16 {
            advance(POLL).await;
            for _ in 0..20 {
                tokio::task::yield_now().await;
                thread::sleep(Duration::from_millis(1));
            }
        }
        assert_eq!(rig.writes().len(), 1, "saved once, after the quiet");
        let threads = rig.threads.lock().unwrap().clone();
        assert!(
            threads.len() > 2,
            "many looks and one write: {}",
            threads.len()
        );
        assert!(
            threads.iter().all(|thread| *thread != runtime_thread),
            "the runtime's thread looked or wrote"
        );
        assert!(!poller.is_finished());
        poller.abort();
    }

    #[test]
    fn a_restart_saves_at_once_when_the_bytes_differ_and_not_otherwise() {
        let rig_time = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap();
        let _guard = rig_time.enter();
        let rig = Rig::new(0, Some(payload(0)));
        // The same: nothing.
        rig.saver.flush(Duration::from_millis(50));
        assert!(rig.writes().is_empty());
        // Different, a second after the change: at once, with no quiet.
        rig.set(1);
        rig.saver.flush(Duration::from_millis(50));
        assert_eq!(rig.writes().len(), 1);
        assert_eq!(rig.writes()[0].1, payload(1));
        // Now it is what the newest copy holds: nothing.
        rig.saver.flush(Duration::from_millis(50));
        assert_eq!(rig.writes().len(), 1);
    }

    #[test]
    fn a_restart_does_not_save_while_an_update_is_under_way() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap();
        let _guard = runtime.enter();
        let rig = Rig::new(0, Some(payload(0)));
        rig.set(1);
        rig.set_idle(false);
        rig.saver.flush(Duration::from_millis(50));
        assert!(rig.writes().is_empty());
        rig.set_idle(true);
        rig.saver.flush(Duration::from_millis(50));
        assert_eq!(rig.writes().len(), 1);
    }

    #[test]
    fn a_restart_gives_up_on_a_save_that_still_has_the_card_and_a_failed_one_is_off() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap();
        let _guard = runtime.enter();
        let rig = Rig::new(0, Some(payload(0)));
        rig.set(1);
        {
            // A save of the pool is under way: the writer is held.
            let _held = rig.saver.writer.lock().unwrap();
            rig.saver.flush(Duration::from_millis(30));
        }
        assert!(rig.writes().is_empty());
        rig.mode(Mode::Fails);
        rig.saver.flush(Duration::from_millis(30));
        assert!(rig.saver.off().is_some(), "a failed write turns it off");
        assert_eq!(rig.said_off(), 1);
        // A card that is not given at the restart is not a failure.
        let rig = Rig::new(0, Some(payload(0)));
        rig.set(1);
        rig.mode(Mode::NotGiven);
        rig.saver.flush(Duration::from_millis(30));
        assert!(rig.saver.off().is_none());
        assert_eq!(rig.said_off(), 0);
    }

    #[test]
    fn a_restart_does_not_write_what_a_save_that_was_under_way_just_wrote() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap();
        let _guard = runtime.enter();
        let rig = Rig::new(0, Some(payload(0)));
        rig.set(1);
        // The pool's save finishes while the restart waits for the writer.
        let saver = rig.saver.clone();
        let held = rig.saver.writer.lock().unwrap();
        let waiting = thread::spawn(move || saver.flush(Duration::from_secs(5)));
        thread::sleep(Duration::from_millis(50));
        rig.saver.note(&payload(1), &Written::Saved(Which::A, 1));
        drop(held);
        waiting.join().unwrap();
        assert!(rig.writes().is_empty(), "nothing written twice");
    }

    #[test]
    fn the_flusher_does_nothing_without_a_saver_and_flushes_the_one_it_is_given() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap();
        let _guard = runtime.enter();
        let flusher = Flusher::new();
        flusher.flush(Duration::from_millis(10));
        let rig = Rig::new(0, Some(payload(0)));
        rig.set(1);
        flusher.set(rig.saver.clone());
        flusher.flush(Duration::from_millis(10));
        assert_eq!(rig.writes().len(), 1);
    }

    #[test]
    fn a_saver_that_starts_off_says_why_and_never_writes() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap();
        let _guard = runtime.enter();
        let told = Arc::new(AtomicUsize::new(0));
        let saver = Saver::new(
            Box::new(|| state(1)),
            Box::new(|| true),
            Box::new(Fake {
                writes: Arc::default(),
                threads: Arc::default(),
                mode: Arc::new(Mutex::new(Mode::Saves)),
                began: Instant::now(),
                seq: 0,
            }),
            Some(payload(0)),
            Some("copy a: the card did not say".to_owned()),
            {
                let told = told.clone();
                Box::new(move || {
                    told.fetch_add(1, Ordering::SeqCst);
                })
            },
        );
        assert_eq!(
            told.load(Ordering::SeqCst),
            1,
            "a saver that is off from the first says so at once"
        );
        let why = runtime.block_on(saver.run(
            || async { unreachable!("it is off") },
            |_| async { unreachable!("it is off") },
        ));
        assert_eq!(why, "copy a: the card did not say");
        assert_eq!(told.load(Ordering::SeqCst), 1, "and once");
    }
}
