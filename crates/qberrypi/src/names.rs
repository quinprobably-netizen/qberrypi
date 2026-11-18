//! The owner's own names, as the front panel and the API edit them: the ones the owner allows and
//! the ones the owner refuses, kept in memory and, when the card keeps the state, on the card.
//!
//! [`OwnerList`] is the one place they are made. It keeps each entry (a name, the side it is on,
//! and the day the owner set it from the panel, if they did) in the order they were set, so the
//! panel can show the newest three, and it keeps the revision, `rev`, which moves with every change
//! of the list by anyone: the panel, or the API's `PUT names`. Every change builds a
//! [`qb_dns::OwnerNames`] of the whole list **before** the resolver's lock is taken, swaps it in
//! under that lock for a moment (as `replace_blockset` swaps a block set) and drops the old one after
//! the lock is let go; the resolver's answer path never waits for more than that swap.
//!
//! Locks: the list's own, and inside it, for the swap or for a copy, the resolver's. Nothing that
//! holds the resolver's lock takes the list's, so no order of the two can matter.
//!
//! The list lives in memory, like the exempt list. When the card keeps the state ([`crate::state`])
//! [`OwnerList::kept`] gives the entries as they are, in order and with their days, and
//! [`OwnerList::restore`] takes them back at the start, through the same swap as any change, so
//! that the resolver has them before the first query; with no card to keep them the list is empty
//! after a restart, and qnet pushes its own again. The days are the panel's own: a name that the
//! desktop pushed has none, and a push that leaves an entry as it is leaves its day too.
//!
//! The names are the owner's, so nothing here logs one and no type prints one: `Debug` says how many,
//! and an error carries no text. A change that took effect logs one line with the two counts.

use std::collections::HashSet;
use std::sync::{Mutex, MutexGuard, PoisonError};

use qb_dns::name::{MAX_NAME_LEN, normalize};
use qb_dns::{OWNER_NAMES_MAX, OwnerNames, OwnerNamesError, OwnerSide, TopName};

use crate::state::SavedName;
use crate::wiring::SharedResolver;

/// One entry of the owner's list, as the panel shows it.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnerEntry {
    /// The name, normalised (lower case, no trailing dot).
    pub name: Box<str>,
    /// Which list the name is on.
    pub side: OwnerSide,
    /// The Unix time at which the owner set it from the panel; `None` for an entry that the
    /// desktop pushed, or that was set before the clock was.
    pub set_unix: Option<u64>,
}

impl core::fmt::Debug for OwnerEntry {
    /// The side only: the name is the owner's.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OwnerEntry")
            .field("side", &self.side)
            .field("set_unix", &self.set_unix)
            .finish_non_exhaustive()
    }
}

/// What the owner's list says of one name, as the resolver would decide it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerHold {
    /// The list that covers the name, the entry itself or a parent of it: the refused list first.
    pub side: OwnerSide,
    /// Whether the name itself is an entry, and not only a parent of it. Only an entry of that name
    /// can be taken back ([`OwnerList::forget`]).
    pub exact: bool,
    /// When the owner set that entry from the panel, if it is one and they did.
    pub set_unix: Option<u64>,
}

/// Why the owner's list was not changed. It says nothing of the name at fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamesError {
    /// The name is not a valid domain name (as `dns.deny` entries must be).
    Invalid,
    /// The list is full: a side holds [`OWNER_NAMES_MAX`] names already.
    Full,
    /// The name is on a threat list, which no owner's entry can allow.
    Threat,
    /// There is no resolver yet to change.
    Unavailable,
}

impl NamesError {
    /// The word the panel's log says: `invalid`, `full`, `threat` or `unavailable`.
    pub fn as_str(self) -> &'static str {
        match self {
            NamesError::Invalid => "invalid",
            NamesError::Full => "full",
            NamesError::Threat => "threat",
            NamesError::Unavailable => "unavailable",
        }
    }
}

/// The owner's list as the API reads it: sorted, so that the same set is always the same answer.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnerView {
    /// The revision now.
    pub rev: u64,
    /// The names allowed, in bytewise order.
    pub allow: Vec<String>,
    /// The names refused, in bytewise order.
    pub refuse: Vec<String>,
}

impl core::fmt::Debug for OwnerView {
    /// The revision and the two lengths: the names are the owner's.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OwnerView")
            .field("rev", &self.rev)
            .field("allow", &self.allow.len())
            .field("refuse", &self.refuse.len())
            .finish()
    }
}

/// A chunk of a push of the whole list, as `PUT names` makes it. The flags are those of the known
/// list: `append` says whether the chunk is added to the list that is being sent (or to the list in
/// force if none is) or starts a new one, and `complete` whether it is the last, which is when the
/// list takes the place of the one in force.
#[derive(Clone, Copy)]
pub struct Push<'a> {
    /// The names of the chunk to allow.
    pub allow: &'a [String],
    /// The names of the chunk to refuse.
    pub refuse: &'a [String],
    /// Add to the list being sent, rather than start one.
    pub append: bool,
    /// This is the last chunk.
    pub complete: bool,
    /// Go ahead only if the list is at this revision still.
    pub if_rev: Option<u64>,
}

/// What a push left: how many names each side holds in the list it belongs to (the one being sent,
/// or the one in force), and the revision after.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Loaded {
    /// Names allowed.
    pub allow: usize,
    /// Names refused.
    pub refuse: usize,
    /// The revision now.
    pub rev: u64,
}

/// Why a push changed nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadError {
    /// `if_rev` is not the revision now, which this is.
    Stale(u64),
    /// A name is not a valid domain name.
    Invalid,
    /// A side would hold more than [`OWNER_NAMES_MAX`] different names.
    TooMany,
}

/// An entry of the list: its name, side and day.
#[derive(Clone, PartialEq, Eq)]
struct Entry {
    name: Box<str>,
    side: OwnerSide,
    set_unix: Option<u64>,
}

/// A name and its side, as a push sends them.
type Pair = (Box<str>, OwnerSide);

/// What the lock guards.
struct State {
    /// The entries in the order they were set, the newest last.
    entries: Vec<Entry>,
    /// What the resolver holds: the entries as the two sorted lists that it matches against.
    names: OwnerNames,
    /// The revision, moved by every change, from where this boot started it.
    rev: u64,
    /// A list that is being sent in chunks and has not taken effect yet.
    staged: Option<Vec<Pair>>,
}

/// The owner's list: the entries, the revision, and the resolver they are swapped into.
pub struct OwnerList {
    /// The resolver the answer path asks, and its clock.
    resolver: SharedResolver,
    state: Mutex<State>,
}

impl OwnerList {
    /// An empty list over `resolver`. It does not touch the resolver's own names: both start empty.
    pub fn new(resolver: SharedResolver) -> Self {
        Self {
            resolver,
            state: Mutex::new(State {
                entries: Vec::new(),
                names: OwnerNames::default(),
                rev: crate::sys::rev_seed(),
                staged: None,
            }),
        }
    }

    /// The state, locked; a lock that a panic poisoned still guards a whole list, since a change
    /// builds everything before it stores anything.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The revision now: it goes up by one for each change, from a number that is different on
    /// every boot ([`crate::sys::rev_seed`], never 0), so that a desktop that kept a revision from
    /// the boot before does not find it is the one now.
    pub fn rev(&self) -> u64 {
        self.lock().rev
    }

    /// Makes the revision start from `rev` in place of this boot's own number, so that a test can
    /// say what each change makes it.
    #[cfg(test)]
    pub(crate) fn starting_at(self, rev: u64) -> Self {
        self.lock().rev = rev;
        self
    }

    /// How many entries the list holds, on both sides.
    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    /// Whether the list holds no entry.
    pub fn is_empty(&self) -> bool {
        self.lock().entries.is_empty()
    }

    /// The revision and the two lists, sorted, as `GET names` gives them.
    pub fn view(&self) -> OwnerView {
        let state = self.lock();
        OwnerView {
            rev: state.rev,
            allow: state.names.allow_names().map(str::to_owned).collect(),
            refuse: state.names.refuse_names().map(str::to_owned).collect(),
        }
    }

    /// The newest `n` entries, the newest first: the order the owner set them in, a name set again on
    /// the other side counting from then.
    pub fn newest(&self, n: usize) -> Vec<OwnerEntry> {
        self.lock()
            .entries
            .iter()
            .rev()
            .take(n)
            .map(|entry| OwnerEntry {
                name: entry.name.clone(),
                side: entry.side,
                set_unix: entry.set_unix,
            })
            .collect()
    }

    /// The entries as they are kept ([`SavedName`]): in the order they were set, the newest last,
    /// each with its side and the day it was set from the panel. At most twice
    /// [`OWNER_NAMES_MAX`] of them; a copy under the list's own lock, and not the resolver's.
    pub fn kept(&self) -> Vec<SavedName> {
        self.lock()
            .entries
            .iter()
            .map(|entry| SavedName {
                name: entry.name.clone(),
                side: entry.side,
                set_unix: entry.set_unix,
            })
            .collect()
    }

    /// Makes `names`, as [`OwnerList::kept`] gave them, the list in force, at the start: through
    /// the same swap as any change, so that the resolver has them at once, with their days and in
    /// their order. A name that is saved twice on one side is the entry of its first place.
    ///
    /// It is all or nothing, and logs nothing (the caller says one line): a name that is not a
    /// valid one, or not as [`qb_dns::name::normalize`] leaves it, is [`NamesError::Invalid`], and a side of
    /// more than [`OWNER_NAMES_MAX`] names is [`NamesError::Full`]; the list stays as it was. A
    /// restore that leaves the list as it is moves no revision; any other moves it by one.
    pub fn restore(&self, names: Vec<SavedName>) -> Result<(), NamesError> {
        let mut entries: Vec<Entry> = Vec::with_capacity(names.len().min(2 * OWNER_NAMES_MAX));
        let mut buf = [0; MAX_NAME_LEN];
        for saved in names {
            let normal = normalize(saved.name.as_bytes(), &mut buf).ok_or(NamesError::Invalid)?;
            if normal != &*saved.name {
                return Err(NamesError::Invalid);
            }
            if entries
                .iter()
                .any(|entry| entry.side == saved.side && entry.name == saved.name)
            {
                continue;
            }
            if entries.len() >= 2 * OWNER_NAMES_MAX {
                return Err(NamesError::Full);
            }
            entries.push(Entry {
                name: saved.name,
                side: saved.side,
                set_unix: saved.set_unix,
            });
        }
        let mut guard = self.lock();
        let state = &mut *guard;
        if entries == state.entries {
            return Ok(());
        }
        self.commit(state, entries)
    }

    /// What the list says of `name`, as the resolver decides it, or `None` if it covers the name
    /// with no entry (or the name is not a valid one).
    pub fn hold(&self, name: &str) -> Option<OwnerHold> {
        let mut buf = [0; MAX_NAME_LEN];
        let name = normalize(name.as_bytes(), &mut buf)?;
        let state = self.lock();
        let side = state.names.side(name)?;
        let entry = state
            .entries
            .iter()
            .find(|entry| entry.side == side && &*entry.name == name);
        Some(OwnerHold {
            side,
            exact: entry.is_some(),
            set_unix: entry.and_then(|entry| entry.set_unix),
        })
    }

    /// The names blocked most often in the resolver's local day, most often first, at most eight:
    /// a copy, under the resolver's lock and no longer (`Stats::top_today`).
    pub fn top_today(&self) -> Vec<TopName> {
        let now = (self.resolver.now)();
        self.resolver.lock().stats().top_today(now)
    }

    /// Puts `name` on the list `side`, from the panel; `set_unix` is the wall time to keep with
    /// it. A name that is on that side alone is left as it is (no change, no new revision). On the
    /// other side it moves: its entry there is taken away, and it comes in as the newest. (A name
    /// that a push put on both sides is on the side that wins when the other's entry goes, so
    /// setting it moves it too.)
    ///
    /// Refused: a name that is not a valid one, and a side that holds [`OWNER_NAMES_MAX`] names
    /// already.
    pub fn set(
        &self,
        name: &str,
        side: OwnerSide,
        set_unix: Option<u64>,
    ) -> Result<(), NamesError> {
        let mut buf = [0; MAX_NAME_LEN];
        let name = normalize(name.as_bytes(), &mut buf).ok_or(NamesError::Invalid)?;
        let mut guard = self.lock();
        let state = &mut *guard;
        let mut here = state.entries.iter().filter(|entry| &*entry.name == name);
        if here.next().is_some_and(|entry| entry.side == side) && here.next().is_none() {
            return Ok(());
        }
        let mut entries: Vec<Entry> = state
            .entries
            .iter()
            .filter(|entry| &*entry.name != name)
            .cloned()
            .collect();
        if entries.iter().filter(|entry| entry.side == side).count() >= OWNER_NAMES_MAX {
            return Err(NamesError::Full);
        }
        entries.push(Entry {
            name: name.into(),
            side,
            set_unix,
        });
        self.commit(state, entries)
    }

    /// Takes the entries of exactly `name` off the list, from the panel. Whether there was one: a
    /// name that is covered by a parent only, or by nothing, changes nothing and is `false`.
    pub fn forget(&self, name: &str) -> Result<bool, NamesError> {
        let mut buf = [0; MAX_NAME_LEN];
        let name = normalize(name.as_bytes(), &mut buf).ok_or(NamesError::Invalid)?;
        let mut guard = self.lock();
        let state = &mut *guard;
        if !state.entries.iter().any(|entry| &*entry.name == name) {
            return Ok(false);
        }
        let entries = state
            .entries
            .iter()
            .filter(|entry| &*entry.name != name)
            .cloned()
            .collect();
        self.commit(state, entries).map(|()| true)
    }

    /// Takes a chunk of the desktop's push, as [`Push`] says, and says how many names each side holds
    /// in the list it belongs to and the revision after.
    ///
    /// A list that is being sent is kept apart and takes the place of the one in force only when
    /// its last chunk has come; the list in force stays until then. When it does, an entry that
    /// the list keeps stays where it is, with its day; an entry it leaves out goes; a name it adds
    /// comes in as the newest, with no day, the allowed ones first. A push that leaves the list as
    /// it is moves no revision. With `if_rev` that is not the revision now, nothing changes, the
    /// list that is being sent included.
    ///
    /// Everything is read and checked before anything is stored: a name that is not valid, or a
    /// side of more than [`OWNER_NAMES_MAX`] different names, changes nothing.
    pub fn load(&self, push: Push<'_>) -> Result<Loaded, LoadError> {
        let chunk = pairs(push.allow, push.refuse)?;
        let mut guard = self.lock();
        let state = &mut *guard;
        if let Some(wanted) = push.if_rev
            && wanted != state.rev
        {
            return Err(LoadError::Stale(state.rev));
        }
        let (mut list, staged) = match (push.append, &state.staged) {
            (false, _) => (Vec::new(), true),
            (true, Some(staged)) => (staged.clone(), true),
            (true, None) => (
                state
                    .entries
                    .iter()
                    .map(|entry| (entry.name.clone(), entry.side))
                    .collect(),
                false,
            ),
        };
        for pair in chunk {
            if !list.contains(&pair) {
                list.push(pair);
            }
        }
        let (allow, refuse) = counts(&list);
        if allow > OWNER_NAMES_MAX || refuse > OWNER_NAMES_MAX {
            return Err(LoadError::TooMany);
        }
        if staged && !push.complete {
            state.staged = Some(list);
            return Ok(Loaded {
                allow,
                refuse,
                rev: state.rev,
            });
        }
        let entries = merged(&state.entries, &list);
        if entries != state.entries {
            self.commit(state, entries).map_err(|error| match error {
                NamesError::Invalid => LoadError::Invalid,
                _ => LoadError::TooMany,
            })?;
            if push.complete {
                log::info!("names: the owner's lists received: {allow} allowed, {refuse} refused");
            }
        }
        state.staged = None;
        Ok(Loaded {
            allow,
            refuse,
            rev: state.rev,
        })
    }

    /// Makes `entries` the list in force: builds the names, takes the resolver's lock only to swap
    /// them in, and stores the entries and the new revision. Nothing is stored if the names cannot
    /// be built. The old names are dropped after the resolver's lock is let go.
    fn commit(&self, state: &mut State, entries: Vec<Entry>) -> Result<(), NamesError> {
        let side = |wanted: OwnerSide| {
            entries
                .iter()
                .filter(move |entry| entry.side == wanted)
                .map(|entry| &*entry.name)
        };
        let names =
            OwnerNames::new(side(OwnerSide::Allow), side(OwnerSide::Refuse)).map_err(|error| {
                match error {
                    OwnerNamesError::Invalid => NamesError::Invalid,
                    OwnerNamesError::TooMany => NamesError::Full,
                }
            })?;
        // The copy for `state` is made before the lock is taken: in `lock().set_owner_names(
        // names.clone())` the receiver, and so the lock, comes first and the clone of up to 256
        // names would be made while the resolver is held, which the queries wait for. The guard is
        // gone at the end of the statement, and the old names are dropped after it.
        let copy = names.clone();
        let old = self.resolver.lock().set_owner_names(names);
        drop(old);
        state.names = copy;
        state.entries = entries;
        state.rev += 1;
        Ok(())
    }
}

/// The normalised pairs of a chunk, each once: the allowed names, then the refused ones. A name that
/// is not valid, or more than [`OWNER_NAMES_MAX`] different on a side, is an error.
fn pairs(allow: &[String], refuse: &[String]) -> Result<Vec<Pair>, LoadError> {
    let mut list: Vec<Pair> = Vec::with_capacity(allow.len() + refuse.len());
    let mut buf = [0; MAX_NAME_LEN];
    for (side, names) in [(OwnerSide::Allow, allow), (OwnerSide::Refuse, refuse)] {
        for name in names {
            let name = normalize(name.as_bytes(), &mut buf).ok_or(LoadError::Invalid)?;
            let pair = (Box::<str>::from(name), side);
            if !list.contains(&pair) {
                list.push(pair);
            }
        }
    }
    let (allow, refuse) = counts(&list);
    if allow > OWNER_NAMES_MAX || refuse > OWNER_NAMES_MAX {
        return Err(LoadError::TooMany);
    }
    Ok(list)
}

/// How many pairs are on each side: allowed, refused.
fn counts(list: &[Pair]) -> (usize, usize) {
    let allow = list
        .iter()
        .filter(|(_, side)| *side == OwnerSide::Allow)
        .count();
    (allow, list.len() - allow)
}

/// The entries that `wanted` makes of `held`: those it keeps, as they are and in their order, then
/// the names it adds, in its order, with no day.
fn merged(held: &[Entry], wanted: &[Pair]) -> Vec<Entry> {
    let on = |side: OwnerSide| -> HashSet<&str> {
        wanted
            .iter()
            .filter(|(_, wanted_side)| *wanted_side == side)
            .map(|(name, _)| &**name)
            .collect()
    };
    let (allow, refuse) = (on(OwnerSide::Allow), on(OwnerSide::Refuse));
    let kept = |entry: &Entry| match entry.side {
        OwnerSide::Allow => allow.contains(&*entry.name),
        OwnerSide::Refuse => refuse.contains(&*entry.name),
    };
    let mut entries: Vec<Entry> = held.iter().filter(|entry| kept(entry)).cloned().collect();
    for (name, side) in wanted {
        if !held
            .iter()
            .any(|entry| entry.side == *side && entry.name == *name)
        {
            entries.push(Entry {
                name: name.clone(),
                side: *side,
                set_unix: None,
            });
        }
    }
    entries
}

/// The configuration's `dns.deny` names, to tell a name that the house denies itself from an ad:
/// the block set holds both as one class.
#[derive(Default)]
pub struct DenyList {
    names: HashSet<Box<str>>,
}

impl DenyList {
    /// The entries of `deny`, normalised. An entry that is not a valid name is left out: the
    /// configuration refuses one, so none comes from a file.
    pub fn new(deny: &[String]) -> Self {
        let mut buf = [0; MAX_NAME_LEN];
        Self {
            names: deny
                .iter()
                .filter_map(|entry| normalize(entry.as_bytes(), &mut buf).map(Box::<str>::from))
                .collect(),
        }
    }

    /// Whether `name` is an entry or a subdomain of one, as the block set matches a `deny` entry.
    /// `name` may be spelled as a client wrote it. Allocates nothing.
    pub fn covers(&self, name: &str) -> bool {
        if self.names.is_empty() {
            return false;
        }
        let mut buf = [0; MAX_NAME_LEN];
        let Some(mut covering) = normalize(name.as_bytes(), &mut buf) else {
            return false;
        };
        loop {
            if self.names.contains(covering) {
                return true;
            }
            match covering.split_once('.') {
                Some((_, parent)) => covering = parent,
                None => return false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use qb_dns::{Action, BlockSetBuilder, ListClass, Now, Resolver, Transport};

    use super::*;

    /// The wall time of the tests' clock, plus the monotonic seconds.
    const UNIX: u64 = 1_800_000_000;

    /// A resolver that blocks `ads.example.com` and the threat `evil.example.net`, with a clock that
    /// the test moves.
    fn resolver() -> (SharedResolver, Arc<AtomicU64>) {
        let mut builder = BlockSetBuilder::new();
        builder.add_list(b"0.0.0.0 ads.example.com\n");
        builder.add_list_as(b"0.0.0.0 evil.example.net\n", ListClass::Threat);
        let clock = Arc::new(AtomicU64::new(100));
        let shared = SharedResolver {
            resolver: Arc::new(Mutex::new(Resolver::new(builder.build()))),
            now: {
                let clock = clock.clone();
                Arc::new(move || {
                    let mono_secs = clock.load(Ordering::SeqCst);
                    Now {
                        mono_secs,
                        unix_secs: UNIX + mono_secs,
                    }
                })
            },
        };
        (shared, clock)
    }

    /// A list whose revision counts from 0, as the tests say what each change makes it.
    fn list() -> (OwnerList, SharedResolver) {
        let (shared, _) = resolver();
        (OwnerList::new(shared.clone()).starting_at(0), shared)
    }

    /// A query for `name`: ID 7, recursion desired, one question, type A, class IN.
    fn query(name: &str) -> Vec<u8> {
        let mut packet = vec![0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            packet.push(u8::try_from(label.len()).unwrap());
            packet.extend_from_slice(label.as_bytes());
        }
        packet.extend_from_slice(&[0, 0, 1, 0, 1]);
        packet
    }

    /// Whether the resolver answers `name` itself (blocks it) and does not forward it.
    fn blocked(shared: &SharedResolver, name: &str) -> bool {
        let now = (shared.now)();
        matches!(
            shared
                .resolver
                .lock()
                .unwrap()
                .handle_query(&query(name), Transport::Udp, now),
            Action::Reply(_)
        )
    }

    fn texts(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    /// A whole push in one body: the lists replace the list in force.
    fn push(list: &OwnerList, allow: &[&str], refuse: &[&str]) -> Result<Loaded, LoadError> {
        list.load(Push {
            allow: &texts(allow),
            refuse: &texts(refuse),
            append: false,
            complete: true,
            if_rev: None,
        })
    }

    fn names_of(entries: &[OwnerEntry]) -> Vec<String> {
        entries.iter().map(|entry| entry.name.to_string()).collect()
    }

    #[test]
    fn a_name_set_from_the_panel_reaches_the_resolver_and_is_taken_back() {
        let (list, shared) = list();
        assert!(list.is_empty());
        assert!(!blocked(&shared, "new.example.org"));
        assert!(blocked(&shared, "ads.example.com"));

        list.set("New.Example.ORG.", OwnerSide::Refuse, Some(UNIX))
            .unwrap();
        list.set("ads.example.com", OwnerSide::Allow, Some(UNIX + 1))
            .unwrap();
        assert!(blocked(&shared, "new.example.org"));
        assert!(blocked(&shared, "sub.new.example.org"));
        assert!(!blocked(&shared, "ads.example.com"));
        assert_eq!(list.len(), 2);
        assert_eq!(list.rev(), 2);

        // Taking the entries back puts both names as the lists had them.
        assert_eq!(list.forget("ads.example.com"), Ok(true));
        assert_eq!(list.forget("new.example.org"), Ok(true));
        assert!(blocked(&shared, "ads.example.com"));
        assert!(!blocked(&shared, "new.example.org"));
        assert_eq!(list.rev(), 4);
        assert!(list.is_empty());
        assert!(shared.resolver.lock().unwrap().owner_names().is_empty());
    }

    #[test]
    fn an_edit_that_changes_nothing_moves_no_revision() {
        let (list, _) = list();
        list.set("a.example.org", OwnerSide::Refuse, Some(UNIX))
            .unwrap();
        let rev = list.rev();
        // The same name on the same side, later: the entry and its day stay.
        list.set("A.example.org.", OwnerSide::Refuse, Some(UNIX + 500))
            .unwrap();
        assert_eq!(list.rev(), rev);
        assert_eq!(list.newest(1)[0].set_unix, Some(UNIX));
        // Taking back what is not there.
        assert_eq!(list.forget("b.example.org"), Ok(false));
        assert_eq!(list.rev(), rev);
        // A parent covers the name but is not its entry: nothing to take back.
        list.set("example.org", OwnerSide::Allow, None).unwrap();
        let rev = list.rev();
        assert_eq!(list.forget("deep.example.org"), Ok(false));
        assert_eq!(list.rev(), rev);
    }

    #[test]
    fn the_newest_entries_come_first_and_a_name_that_flips_is_the_newest_again() {
        let (list, _) = list();
        for (name, side) in [
            ("a.example.org", OwnerSide::Refuse),
            ("b.example.org", OwnerSide::Allow),
            ("c.example.org", OwnerSide::Refuse),
            ("d.example.org", OwnerSide::Allow),
        ] {
            list.set(name, side, Some(UNIX)).unwrap();
        }
        assert_eq!(
            names_of(&list.newest(3)),
            ["d.example.org", "c.example.org", "b.example.org"]
        );
        assert_eq!(list.newest(99).len(), 4);
        assert!(list.newest(0).is_empty());

        // `a` goes to the other side: one entry, the newest, with the new day.
        list.set("a.example.org", OwnerSide::Allow, Some(UNIX + 9))
            .unwrap();
        let newest = list.newest(2);
        assert_eq!(names_of(&newest), ["a.example.org", "d.example.org"]);
        assert_eq!(newest[0].side, OwnerSide::Allow);
        assert_eq!(newest[0].set_unix, Some(UNIX + 9));
        assert_eq!(list.len(), 4);
        let view = list.view();
        assert_eq!(view.refuse, ["c.example.org"]);
        assert_eq!(
            view.allow,
            ["a.example.org", "b.example.org", "d.example.org"]
        );
    }

    #[test]
    fn the_hold_on_a_name_is_the_resolvers_and_says_whether_the_entry_is_the_names_own() {
        let (list, _) = list();
        list.set("ads.example.com", OwnerSide::Allow, Some(UNIX))
            .unwrap();
        push_more(&list, "example.org");
        assert_eq!(list.hold("nothing.example.net"), None);
        assert_eq!(list.hold("not a name"), None);
        assert_eq!(
            list.hold("ADS.example.com."),
            Some(OwnerHold {
                side: OwnerSide::Allow,
                exact: true,
                set_unix: Some(UNIX)
            })
        );
        // Covered by a parent that the desktop pushed: the hold is that entry's, which is no day's.
        assert_eq!(
            list.hold("x.example.org"),
            Some(OwnerHold {
                side: OwnerSide::Refuse,
                exact: false,
                set_unix: None
            })
        );
        assert_eq!(
            list.hold("example.org"),
            Some(OwnerHold {
                side: OwnerSide::Refuse,
                exact: true,
                set_unix: None
            })
        );
    }

    /// A name as it is kept.
    fn saved(name: &str, side: OwnerSide, set_unix: Option<u64>) -> SavedName {
        SavedName {
            name: name.into(),
            side,
            set_unix,
        }
    }

    #[test]
    fn the_kept_names_restore_into_another_list_in_their_order_and_with_their_days() {
        let (first, _) = list();
        first
            .set("a.example.org", OwnerSide::Refuse, Some(UNIX))
            .unwrap();
        push_more(&first, "pushed.example.org");
        first
            .set("b.example.org", OwnerSide::Allow, Some(UNIX + 5))
            .unwrap();
        let kept = first.kept();
        assert_eq!(
            kept,
            [
                saved("a.example.org", OwnerSide::Refuse, Some(UNIX)),
                saved("pushed.example.org", OwnerSide::Refuse, None),
                saved("b.example.org", OwnerSide::Allow, Some(UNIX + 5)),
            ]
        );

        let (second, _) = list();
        assert_eq!(second.restore(kept.clone()), Ok(()));
        assert_eq!(second.kept(), kept);
        assert_eq!(
            names_of(&second.newest(3)),
            ["b.example.org", "pushed.example.org", "a.example.org"]
        );
        assert_eq!(second.newest(1)[0].set_unix, Some(UNIX + 5));
        assert_eq!(
            second.view(),
            OwnerView {
                rev: 1,
                ..first.view()
            }
        );
        // A list with nothing in it is kept as nothing.
        let (empty, _) = list();
        assert_eq!(empty.kept(), []);
    }

    #[test]
    fn a_restored_refused_name_is_blocked_by_the_resolver_and_an_allowed_one_is_not() {
        let (list, shared) = list();
        assert!(blocked(&shared, "ads.example.com"));
        assert!(!blocked(&shared, "new.example.org"));
        list.restore(vec![
            saved("new.example.org", OwnerSide::Refuse, Some(UNIX)),
            saved("ads.example.com", OwnerSide::Allow, None),
        ])
        .unwrap();
        assert!(blocked(&shared, "new.example.org"));
        assert!(blocked(&shared, "sub.new.example.org"));
        assert!(!blocked(&shared, "ads.example.com"));
        assert_eq!(
            list.hold("new.example.org"),
            Some(OwnerHold {
                side: OwnerSide::Refuse,
                exact: true,
                set_unix: Some(UNIX)
            })
        );
        // A restore replaces what was there, and the resolver follows.
        list.restore(vec![saved("other.example.org", OwnerSide::Refuse, None)])
            .unwrap();
        assert!(!blocked(&shared, "new.example.org"));
        assert!(blocked(&shared, "ads.example.com"));
        assert!(blocked(&shared, "other.example.org"));
    }

    #[test]
    fn a_name_on_both_sides_is_kept_and_restored_on_both() {
        let (first, _) = list();
        push(&first, &["both.example.org"], &["both.example.org"]).unwrap();
        let kept = first.kept();
        assert_eq!(kept.len(), 2);
        let (second, shared) = list();
        second.restore(kept.clone()).unwrap();
        assert_eq!(second.kept(), kept);
        assert!(blocked(&shared, "both.example.org"));
    }

    #[test]
    fn a_restore_that_leaves_the_list_as_it_is_moves_no_revision_and_any_other_moves_it_once() {
        let (list, _) = list();
        let one = vec![saved("a.example.org", OwnerSide::Refuse, Some(UNIX))];
        assert_eq!(list.restore(Vec::new()), Ok(()));
        assert_eq!(list.rev(), 0);
        list.restore(one.clone()).unwrap();
        assert_eq!(list.rev(), 1);
        list.restore(one).unwrap();
        assert_eq!(list.rev(), 1);
        // A day that differs is a change.
        list.restore(vec![saved("a.example.org", OwnerSide::Refuse, None)])
            .unwrap();
        assert_eq!(list.rev(), 2);
    }

    #[test]
    fn a_name_that_fails_makes_the_whole_restore_refused_and_nothing_changes() {
        let (list, shared) = list();
        list.set("keep.example.org", OwnerSide::Refuse, Some(UNIX))
            .unwrap();
        let rev = list.rev();
        let kept = list.kept();
        let good = saved("fine.example.org", OwnerSide::Refuse, None);
        for bad in [
            "",
            "not a name",
            "*.example.org",
            "a..b",
            // Valid, but not as it is kept: the decoder never lets one through.
            "Upper.example.org",
            "trailing.example.org.",
        ] {
            assert_eq!(
                list.restore(vec![good.clone(), saved(bad, OwnerSide::Refuse, None)]),
                Err(NamesError::Invalid),
                "{bad:?}"
            );
        }
        let too_many: Vec<SavedName> = (0..=OWNER_NAMES_MAX)
            .map(|n| saved(&format!("n{n}.example.org"), OwnerSide::Allow, None))
            .collect();
        assert_eq!(list.restore(too_many), Err(NamesError::Full));
        let far_too_many: Vec<SavedName> = (0..2 * OWNER_NAMES_MAX + 5)
            .map(|n| saved(&format!("n{n}.example.org"), OwnerSide::Refuse, None))
            .collect();
        assert_eq!(list.restore(far_too_many), Err(NamesError::Full));
        assert_eq!(list.rev(), rev);
        assert_eq!(list.kept(), kept);
        assert!(blocked(&shared, "keep.example.org"));
        assert!(!blocked(&shared, "fine.example.org"));
    }

    #[test]
    fn a_full_list_restores_and_a_name_kept_twice_on_one_side_is_one_entry() {
        let (first, _) = list();
        for n in 0..OWNER_NAMES_MAX {
            first
                .set(&format!("a{n}.example.org"), OwnerSide::Allow, None)
                .unwrap();
            first
                .set(&format!("r{n}.example.org"), OwnerSide::Refuse, Some(UNIX))
                .unwrap();
        }
        let kept = first.kept();
        assert_eq!(kept.len(), 2 * OWNER_NAMES_MAX);
        let (second, _) = list();
        assert_eq!(second.restore(kept.clone()), Ok(()));
        assert_eq!(second.kept(), kept);
        // The same name twice on a side comes in once, at its first place.
        let (third, _) = list();
        third
            .restore(vec![
                saved("x.example.org", OwnerSide::Refuse, Some(UNIX)),
                saved("x.example.org", OwnerSide::Refuse, Some(UNIX + 1)),
            ])
            .unwrap();
        assert_eq!(
            third.kept(),
            [saved("x.example.org", OwnerSide::Refuse, Some(UNIX))]
        );
    }

    /// Adds `name` to the refused list as the desktop would: a push of the list with it.
    fn push_more(list: &OwnerList, name: &str) {
        let view = list.view();
        let allow: Vec<&str> = view.allow.iter().map(String::as_str).collect();
        let mut refuse: Vec<&str> = view.refuse.iter().map(String::as_str).collect();
        refuse.push(name);
        push(list, &allow, &refuse).unwrap();
    }

    #[test]
    fn a_name_is_refused_for_a_bad_name_and_a_full_side_and_nothing_changes() {
        let (list, _) = list();
        let rev = list.rev();
        for bad in ["", "not a name", "*.example.org", "192.0.2.1", "a..b"] {
            assert_eq!(
                list.set(bad, OwnerSide::Refuse, None),
                Err(NamesError::Invalid)
            );
            assert_eq!(list.forget(bad), Err(NamesError::Invalid));
        }
        assert_eq!(list.rev(), rev);

        for n in 0..OWNER_NAMES_MAX {
            list.set(&format!("n{n}.example.org"), OwnerSide::Refuse, None)
                .unwrap();
        }
        assert_eq!(
            list.set("one-more.example.org", OwnerSide::Refuse, None),
            Err(NamesError::Full)
        );
        // The other side has room, and a name that flips makes room on the side it leaves.
        list.set("one-more.example.org", OwnerSide::Allow, None)
            .unwrap();
        list.set("n0.example.org", OwnerSide::Allow, None).unwrap();
        list.set("one-more.example.org", OwnerSide::Refuse, None)
            .unwrap();
        assert_eq!(list.view().refuse.len(), OWNER_NAMES_MAX);
    }

    #[test]
    fn a_push_replaces_the_list_keeps_what_it_names_and_the_days_of_those() {
        let (list, shared) = list();
        list.set("keep.example.org", OwnerSide::Refuse, Some(UNIX))
            .unwrap();
        list.set("drop.example.org", OwnerSide::Refuse, Some(UNIX + 1))
            .unwrap();
        list.set("ads.example.com", OwnerSide::Allow, Some(UNIX + 2))
            .unwrap();
        let rev = list.rev();

        let done = push(
            &list,
            &["ads.example.com", "Fresh.Example.org"],
            &["keep.example.org", "also.example.org"],
        )
        .unwrap();
        assert_eq!(
            done,
            Loaded {
                allow: 2,
                refuse: 2,
                rev: rev + 1
            }
        );
        // Kept entries are where they were, with their days; the new ones follow, allowed first.
        let all = list.newest(9);
        assert_eq!(
            names_of(&all),
            [
                "also.example.org",
                "fresh.example.org",
                "ads.example.com",
                "keep.example.org"
            ]
        );
        assert_eq!(all[3].set_unix, Some(UNIX));
        assert_eq!(all[2].set_unix, Some(UNIX + 2));
        assert_eq!((all[1].set_unix, all[0].set_unix), (None, None));
        assert!(!blocked(&shared, "drop.example.org"));
        assert!(blocked(&shared, "also.example.org"));
        assert!(!blocked(&shared, "ads.example.com"));

        // The same push again changes nothing, and the revision stays.
        let again = push(
            &list,
            &["ads.example.com", "fresh.example.org"],
            &["keep.example.org", "also.example.org"],
        )
        .unwrap();
        assert_eq!(again.rev, rev + 1);
        assert_eq!(list.newest(9), all);
        // `[]` and `[]` clears it.
        let cleared = push(&list, &[], &[]).unwrap();
        assert_eq!(
            cleared,
            Loaded {
                allow: 0,
                refuse: 0,
                rev: rev + 2
            }
        );
        assert!(list.is_empty());
        assert!(shared.resolver.lock().unwrap().owner_names().is_empty());
    }

    #[test]
    fn a_name_that_is_on_both_sides_of_a_push_is_on_both_and_the_resolver_refuses_it() {
        let (list, shared) = list();
        push(&list, &["both.example.org"], &["both.example.org"]).unwrap();
        assert_eq!(list.len(), 2);
        assert!(blocked(&shared, "both.example.org"));
        assert_eq!(
            list.hold("both.example.org").map(|hold| hold.side),
            Some(OwnerSide::Refuse)
        );
        // A name that flips from the panel leaves one entry.
        list.set("both.example.org", OwnerSide::Allow, None)
            .unwrap();
        assert_eq!(list.len(), 1);
        assert!(!blocked(&shared, "both.example.org"));
    }

    fn chunk(
        list: &OwnerList,
        allow: &[&str],
        refuse: &[&str],
        append: bool,
        complete: bool,
        if_rev: Option<u64>,
    ) -> Result<Loaded, LoadError> {
        list.load(Push {
            allow: &texts(allow),
            refuse: &texts(refuse),
            append,
            complete,
            if_rev,
        })
    }

    #[test]
    fn the_revision_starts_from_a_number_of_each_boot_and_a_stale_one_from_the_last_is_refused() {
        // Two lists stand for two boots. A desktop kept the revision of the first after two
        // changes; the second has made none, and starts its count somewhere else, never at 0.
        let (shared, _) = resolver();
        let last_boot = OwnerList::new(shared.clone());
        push(&last_boot, &[], &["a.example.org"]).unwrap();
        push(&last_boot, &[], &["b.example.org"]).unwrap();
        let kept = last_boot.rev();
        let this_boot = OwnerList::new(shared.clone());
        let start = this_boot.rev();
        assert_ne!(start, 0);
        assert_ne!(start, kept);
        let stale = chunk(&this_boot, &[], &["c.example.org"], false, true, Some(kept));
        assert_eq!(stale, Err(LoadError::Stale(start)));
        assert!(this_boot.is_empty());
        assert!(!blocked(&shared, "c.example.org"));
        // The count goes up by one a change from there.
        push(&this_boot, &[], &["c.example.org"]).unwrap();
        assert_eq!(this_boot.rev(), start + 1);
    }

    #[test]
    fn a_list_sent_in_chunks_takes_effect_with_its_last_chunk_only() {
        let (list, shared) = list();
        list.set("old.example.org", OwnerSide::Refuse, None)
            .unwrap();
        let rev = list.rev();

        let first = chunk(
            &list,
            &["a.example.org"],
            &["b.example.org"],
            false,
            false,
            None,
        );
        assert_eq!(
            first,
            Ok(Loaded {
                allow: 1,
                refuse: 1,
                rev
            })
        );
        // Nothing is in force yet: the old list stands, and the revision has not moved.
        assert!(blocked(&shared, "old.example.org"));
        assert!(!blocked(&shared, "b.example.org"));
        assert_eq!(list.view().refuse, ["old.example.org"]);

        let second = chunk(&list, &[], &["c.example.org"], true, false, None);
        assert_eq!(
            second,
            Ok(Loaded {
                allow: 1,
                refuse: 2,
                rev
            })
        );
        let last = chunk(
            &list,
            &[],
            &["d.example.org", "b.example.org"],
            true,
            true,
            None,
        );
        assert_eq!(
            last,
            Ok(Loaded {
                allow: 1,
                refuse: 3,
                rev: rev + 1
            })
        );
        assert!(!blocked(&shared, "old.example.org"));
        assert!(blocked(&shared, "b.example.org") && blocked(&shared, "d.example.org"));
        assert_eq!(
            list.view().refuse,
            ["b.example.org", "c.example.org", "d.example.org"]
        );

        // A chunk that starts again drops what was being sent.
        chunk(&list, &[], &["x.example.org"], false, false, None).unwrap();
        chunk(&list, &[], &["y.example.org"], false, false, None).unwrap();
        let done = chunk(&list, &[], &[], true, true, None).unwrap();
        assert_eq!((done.allow, done.refuse), (0, 1));
        assert_eq!(list.view().refuse, ["y.example.org"]);
    }

    #[test]
    fn a_chunk_added_to_no_list_that_is_being_sent_is_added_to_the_list_in_force() {
        let (list, shared) = list();
        list.set("old.example.org", OwnerSide::Refuse, None)
            .unwrap();
        // As the labels are: with nothing being sent, `append` adds to what is in force, at once.
        let done = chunk(&list, &[], &["more.example.org"], true, false, None).unwrap();
        assert_eq!((done.allow, done.refuse), (0, 2));
        assert!(blocked(&shared, "old.example.org") && blocked(&shared, "more.example.org"));
    }

    #[test]
    fn a_bad_chunk_changes_nothing_not_even_the_list_being_sent() {
        let (list, shared) = list();
        chunk(&list, &[], &["a.example.org"], false, false, None).unwrap();
        let rev = list.rev();
        for (allow, refuse) in [
            (&["fine.example.org"][..], &["not a name"][..]),
            (&["*.example.org"][..], &[][..]),
        ] {
            assert_eq!(
                chunk(&list, allow, refuse, true, true, None),
                Err(LoadError::Invalid)
            );
        }
        // Too many on one side, after the chunk before it: the list being sent is as it was.
        let many: Vec<String> = (0..OWNER_NAMES_MAX)
            .map(|n| format!("n{n}.example.org"))
            .collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert_eq!(
            chunk(&list, &[], &many, true, false, None),
            Err(LoadError::TooMany)
        );
        assert_eq!(list.rev(), rev);
        assert!(!blocked(&shared, "a.example.org"));
        let done = chunk(&list, &[], &[], true, true, None).unwrap();
        assert_eq!((done.allow, done.refuse), (0, 1));
        assert!(blocked(&shared, "a.example.org"));

        // A side of exactly 128 is fine, and 129 different names in one chunk are not.
        let full = chunk(&list, &many, &many, false, true, None).unwrap();
        assert_eq!(
            (full.allow, full.refuse),
            (OWNER_NAMES_MAX, OWNER_NAMES_MAX)
        );
        let mut over = many.clone();
        over.push("one-more.example.org");
        assert_eq!(
            chunk(&list, &over, &[], false, true, None),
            Err(LoadError::TooMany)
        );
        // Spellings of one name are one name.
        let spelled = ["N0.example.org", "n0.example.org.", "n0.EXAMPLE.org"];
        assert_eq!(
            chunk(&list, &[], &spelled, false, true, None)
                .unwrap()
                .refuse,
            1
        );
    }

    #[test]
    fn a_push_made_on_an_old_revision_changes_nothing_and_says_the_revision_now() {
        let (list, shared) = list();
        list.set("a.example.org", OwnerSide::Refuse, None).unwrap();
        let rev = list.rev();
        // The panel edits meanwhile.
        list.set("b.example.org", OwnerSide::Refuse, None).unwrap();

        assert_eq!(
            chunk(&list, &[], &["x.example.org"], false, true, Some(rev)),
            Err(LoadError::Stale(rev + 1))
        );
        assert!(!blocked(&shared, "x.example.org"));
        assert_eq!(list.view().refuse, ["a.example.org", "b.example.org"]);

        // A chunk that is stale does not even reach the list that is being sent.
        chunk(&list, &[], &["s.example.org"], false, false, None).unwrap();
        assert_eq!(
            chunk(&list, &[], &["t.example.org"], true, true, Some(rev)),
            Err(LoadError::Stale(rev + 1))
        );
        let done = chunk(&list, &[], &[], true, true, Some(rev + 1)).unwrap();
        assert_eq!(done.refuse, 1);
        assert_eq!(list.view().refuse, ["s.example.org"]);
    }

    #[test]
    fn a_list_swap_leaves_the_block_set_the_cache_and_the_counts_alone() {
        let (list, shared) = list();
        let before = shared.resolver.lock().unwrap().stats().total();
        list.set("a.example.org", OwnerSide::Refuse, None).unwrap();
        assert_eq!(shared.resolver.lock().unwrap().stats().total(), before);
        assert!(blocked(&shared, "ads.example.com"));
    }

    #[test]
    fn the_top_of_today_is_the_resolvers_blocked_names_most_often_first() {
        let (list, shared) = list();
        assert!(list.top_today().is_empty());
        list.set("owner.example.org", OwnerSide::Refuse, None)
            .unwrap();
        for name in [
            "ads.example.com",
            "owner.example.org",
            "ads.example.com",
            "sub.owner.example.org",
        ] {
            assert!(blocked(&shared, name));
        }
        let top = list.top_today();
        let top: Vec<(&str, u32)> = top.iter().map(|t| (&*t.name, t.count)).collect();
        assert_eq!(
            top,
            [
                ("ads.example.com", 2),
                ("owner.example.org", 1),
                ("sub.owner.example.org", 1)
            ]
        );
    }

    #[test]
    fn the_deny_list_covers_a_name_and_its_subdomains_at_label_boundaries() {
        let deny = DenyList::new(&texts(&["Denied.Example.ORG.", "bad name", "tracker.test"]));
        for (name, want) in [
            ("denied.example.org", true),
            ("x.y.denied.example.org", true),
            ("DENIED.example.org.", true),
            ("tracker.test", true),
            ("a.tracker.test", true),
            ("notdenied.example.org", false),
            ("example.org", false),
            ("test", false),
            ("not a name", false),
            ("", false),
        ] {
            assert_eq!(deny.covers(name), want, "{name:?}");
        }
        assert!(!DenyList::default().covers("denied.example.org"));
    }

    #[test]
    fn nothing_prints_a_name() {
        let (list, _) = list();
        list.set("secret.example.org", OwnerSide::Refuse, Some(UNIX))
            .unwrap();
        push_more(&list, "other-secret.example.org");
        let shown = format!(
            "{:?} {:?} {:?} {:?} {:?}",
            list.view(),
            list.newest(5),
            list.hold("secret.example.org"),
            NamesError::Invalid,
            LoadError::TooMany,
        );
        assert!(!shown.contains("secret"), "{shown}");
        assert!(shown.contains("Refuse"));
    }
}
