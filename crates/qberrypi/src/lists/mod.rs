//! The block lists: what a block set is built from, and what the set in force came from.

pub mod refresh;
pub mod snapshot;

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use qb_dns::{BlockSet, BlockSetBuilder};

/// Where the block set in force came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The `deny` and `allow` entries of the configuration alone: no list was loaded.
    Config,
    /// The lists as they were when the image was built.
    Snapshot,
    /// Lists that were fetched since this system came up.
    Fetched,
}

impl Source {
    /// The word that the statistics say.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Snapshot => "snapshot",
            Self::Fetched => "fetched",
        }
    }
}

/// What is known of the block set in force.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListState {
    pub source: Source,
    /// How many names the set blocks, of both kinds.
    pub names: usize,
    /// The system clock when the lists were fetched; `None` unless they were.
    pub fetched_unix_secs: Option<u64>,
    /// Why the last refresh failed; `None` when it worked or none has been tried. The text names
    /// a list's host at most, never its URL.
    pub last_error: Option<String>,
}

/// The state of the lists, shared by the refresh that changes it and the status that reads it.
///
/// Nothing holds the lock for longer than a copy, and never across an `.await`.
pub struct Lists {
    state: Mutex<ListState>,
}

impl Lists {
    /// The lists as they are at the start.
    pub fn new(state: ListState) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(state),
        })
    }

    /// A copy of the state.
    pub fn get(&self) -> ListState {
        self.lock().clone()
    }

    /// A refresh worked: the set in force is `names` names fetched at `unix_secs`, and the
    /// error of an earlier refresh is no more.
    pub fn fetched(&self, names: usize, unix_secs: u64) {
        *self.lock() = ListState {
            source: Source::Fetched,
            names,
            fetched_unix_secs: Some(unix_secs),
            last_error: None,
        };
    }

    /// A refresh failed, and the set in force stays: only the error changes.
    pub fn failed(&self, error: String) {
        self.lock().last_error = Some(error);
    }

    /// The state, locked, whether or not a holder panicked: a copy of it is always whole.
    fn lock(&self) -> MutexGuard<'_, ListState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// How many names `set` blocks, of both kinds.
pub fn names(set: &BlockSet) -> usize {
    set.exact_len() + set.suffix_len()
}

/// The builder that every block set starts from: the `deny` entries of the configuration as
/// names to block, and its `allow` entries as names never to block.
///
/// The entries come checked from `config::parse`, which refuses a file with an entry that is
/// no domain name by the very rule that the builder applies. So the builder refuses none, and
/// a debug build asserts as much; a release build would skip such an entry.
pub fn from_config(deny: &[String], allow: &[String]) -> BlockSetBuilder {
    let mut builder = BlockSetBuilder::new();
    for name in deny {
        let entry = builder.deny(name);
        debug_assert!(
            entry.is_ok(),
            "a deny entry is no domain name, but config::parse checks every one"
        );
    }
    for name in allow {
        let entry = builder.allow(name);
        debug_assert!(
            entry.is_ok(),
            "an allow entry is no domain name, but config::parse checks every one"
        );
    }
    builder
}

#[cfg(test)]
mod tests {
    use super::*;

    use qb_dns::BlockSet;

    #[test]
    fn the_configured_names_are_denied_and_allowed() {
        let deny = [
            "Ads.example.com".to_owned(),
            "tracker.example.net".to_owned(),
        ];
        let allow = ["ok.ads.example.com".to_owned()];
        let set = from_config(&deny, &allow).build();
        assert!(set.is_blocked("ads.example.com"));
        assert!(set.is_blocked("x.ads.example.com"));
        assert!(set.is_blocked("tracker.example.net"));
        assert!(!set.is_blocked("ok.ads.example.com"));
        assert!(!set.is_blocked("example.com"));
    }

    #[test]
    fn every_entry_the_configuration_accepts_is_kept() {
        let text = r#"
[wifi]
ssid = "example-network"
passphrase = "example-passphrase"
country = "US"

[net]
address = "192.0.2.53/24"
gateway = "192.0.2.1"

[dns]
upstreams = ["9.9.9.9"]
deny = ["Ads.Example.COM.", "tracker.example.net", "_ads.example.org"]
allow = ["OK.ads.example.com", "CDN.Tracker.Example.NET."]
"#;
        let cfg = crate::config::parse(text).unwrap();
        let set = from_config(&cfg.dns.deny, &cfg.dns.allow).build();
        assert_eq!((set.suffix_len(), set.allow_len()), (3, 2));
        for blocked in [
            "ads.example.com",
            "x.ads.example.com",
            "tracker.example.net",
            "www.tracker.example.net",
            "_ads.example.org",
        ] {
            assert!(set.is_blocked(blocked), "{blocked}");
        }
        for allowed in [
            "ok.ads.example.com",
            "cdn.tracker.example.net",
            "img.cdn.tracker.example.net",
            "example.com",
        ] {
            assert!(!set.is_blocked(allowed), "{allowed}");
        }
    }

    #[test]
    fn no_entries_give_an_empty_builder() {
        let set = from_config(&[], &[]).build();
        assert_eq!(
            (set.exact_len(), set.suffix_len(), set.allow_len()),
            (0, 0, 0)
        );
    }
    #[test]
    fn the_state_of_the_lists_follows_what_a_refresh_came_to() {
        let lists = Lists::new(ListState {
            source: Source::Snapshot,
            names: 5,
            fetched_unix_secs: None,
            last_error: None,
        });
        lists.failed("list 1 (lists.example.net): status 404".to_owned());
        assert_eq!(
            lists.get(),
            ListState {
                source: Source::Snapshot,
                names: 5,
                fetched_unix_secs: None,
                last_error: Some("list 1 (lists.example.net): status 404".to_owned()),
            }
        );
        lists.fetched(302_176, 1_800_000_000);
        assert_eq!(
            lists.get(),
            ListState {
                source: Source::Fetched,
                names: 302_176,
                fetched_unix_secs: Some(1_800_000_000),
                last_error: None,
            }
        );
        // A failure after a fetch changes the error and nothing else.
        lists.failed("list 2 (lists.example.org): timed out".to_owned());
        assert_eq!(
            lists.get(),
            ListState {
                source: Source::Fetched,
                names: 302_176,
                fetched_unix_secs: Some(1_800_000_000),
                last_error: Some("list 2 (lists.example.org): timed out".to_owned()),
            }
        );
    }

    #[test]
    fn a_source_has_its_name() {
        assert_eq!(
            (
                Source::Config.as_str(),
                Source::Snapshot.as_str(),
                Source::Fetched.as_str()
            ),
            ("config", "snapshot", "fetched")
        );
    }

    #[test]
    fn the_names_of_a_set_are_its_blocked_names_of_both_kinds() {
        let mut builder = from_config(
            &["denied.example.org".to_owned()],
            &["ok.example.org".to_owned()],
        );
        builder.add_list(b"0.0.0.0 ads.example.com\n||tracker.example.net^\n");
        assert_eq!(names(&builder.build()), 3);
        assert_eq!(names(&BlockSet::default()), 0);
    }
}
