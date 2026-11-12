//! The API's [`Facts`] from the running system: the resolver's own counts, log and pause, the
//! upstreams' figures, the devices that asked, and the lists' names and fetch time.
//!
//! Every method reads when it is called, at the resolver's own clock ([`Dns::now`]). Rule 17: a
//! method takes the resolver's lock, or the table of devices', once, copies what it needs out,
//! and lets go before anything is formatted; the longest holds are [`Facts::recent`]'s copy of at
//! most [`MAX_QUERIES`](super::seams::MAX_QUERIES) entries and [`Facts::client_list`]'s of at
//! most [`MAX_CLIENTS`](crate::dns::clients::MAX_CLIENTS). Nothing here reads a file or the
//! kernel.

use std::sync::Arc;

use qb_dns::{Counts, HistoryBucket, LogEntry};

use super::routes::Facts;
use super::seams::{Client, ServerStats};
use crate::dns::Dns;
use crate::wiring::Extras;

/// The window of a device that is active: the last 24 hours, in seconds.
const ACTIVE_SECS: u64 = 86_400;

/// What `extras` gives: the lists' figures, which are the panel's as well.
type ExtrasReader = Arc<dyn Fn() -> Extras + Send + Sync>;

/// The API's facts over `dns`.
pub struct LiveFacts {
    /// The resolver, its upstreams and its clock.
    pub dns: Arc<Dns>,
    /// The lists' figures, as the panel reads them ([`Extras::read`] in the integration).
    pub extras: ExtrasReader,
}

impl Facts for LiveFacts {
    fn last_24h(&self) -> Counts {
        let now = self.dns.now();
        self.dns.resolver().stats().last_24h(now)
    }

    fn history(&self) -> Vec<HistoryBucket> {
        let now = self.dns.now();
        self.dns.resolver().stats().history(now)
    }

    fn upstreams(&self) -> Vec<ServerStats> {
        self.dns.upstreams().servers()
    }

    /// The devices of the table that asked in the last 24 hours, and all those the table holds,
    /// counted under one hold of it. The table forgets the least recently seen device past
    /// [`MAX_CLIENTS`](crate::dns::clients::MAX_CLIENTS), so the second figure is never above that
    /// and the first never above the second.
    fn clients(&self) -> (usize, usize) {
        let now = self.dns.now().mono_secs;
        let clients = self.dns.clients();
        (clients.seen_within(now, ACTIVE_SECS), clients.len())
    }

    /// The devices of the table, the most recently seen first, with the seconds since each asked
    /// as of this moment: the table's own copy, taken under one hold of it.
    fn client_list(&self) -> Vec<Client> {
        let now = self.dns.now().mono_secs;
        self.dns.clients().list(now)
    }

    fn recent(&self, n: usize) -> Vec<LogEntry> {
        self.dns.resolver().stats().recent(n).cloned().collect()
    }

    fn list(&self) -> (Option<usize>, Option<u64>) {
        let extras = (self.extras)();
        (extras.list_names, extras.list_fetched_unix)
    }

    fn paused_left_secs(&self) -> Option<u64> {
        let now = self.dns.now();
        let until = self.dns.resolver().paused_until(now)?;
        Some(until.saturating_sub(now.mono_secs))
    }

    fn pause_for(&self, secs: u64) {
        let until = self.dns.now().mono_secs.saturating_add(secs);
        self.dns.resolver().pause_until(until);
    }

    fn resume(&self) {
        self.dns.resolver().resume();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::dns::testutil::{Reply, aged, ask_udp, one};
    use crate::live::BlockingControl as _;
    use crate::wiring::SharedResolver;

    const UPSTREAM_ADDRESS: &str = "192.0.2.1";

    /// Facts over a resolver that denies `ads.example.com` and whose upstream answers
    /// `192.0.2.1` for anything else; with where to ask it, and the upstream that must live on.
    async fn facts_over_a_resolver() -> (
        LiveFacts,
        std::net::SocketAddr,
        crate::dns::testutil::FakeUpstream,
    ) {
        let (dns, addr, upstream) = one(Reply::Answer(UPSTREAM_ADDRESS.parse().unwrap())).await;
        let extras = Arc::new(|| Extras {
            list_names: Some(7),
            list_fetched_unix: Some(1_800_000_000),
            ..Extras::default()
        });
        (LiveFacts { dns, extras }, addr, upstream)
    }

    #[tokio::test]
    async fn the_figures_are_the_resolvers_and_the_resolver_is_not_left_locked() {
        let (facts, addr, _upstream) = facts_over_a_resolver().await;
        assert!(ask_udp(addr, "ads.example.com").await.is_some());
        assert!(ask_udp(addr, "example.com").await.is_some());

        let day = facts.last_24h();
        assert_eq!((day.queries, day.blocked, day.forwarded), (2, 1, 1));
        let history = facts.history();
        assert_eq!(history.len(), 144);
        assert_eq!(history.iter().map(|b| b.counts.queries).sum::<u64>(), 2);
        let recent = facts.recent(10);
        let names: Vec<&str> = recent.iter().map(|entry| &*entry.name).collect();
        assert_eq!(names, ["example.com", "ads.example.com"]);
        assert_eq!(facts.recent(1).len(), 1);
        let upstreams = facts.upstreams();
        assert_eq!(upstreams.len(), 1);
        assert_eq!(upstreams[0].answered, 1);
        // The questions came over loopback, which is the Pi itself and no device.
        assert_eq!(facts.clients(), (0, 0));
        assert!(facts.client_list().is_empty());
        assert_eq!(facts.list(), (Some(7), Some(1_800_000_000)));
        // None of it keeps the resolver's lock past its own copy.
        assert!(facts.dns.shared().try_lock().is_ok());
    }

    #[test]
    fn the_clients_are_the_tables_devices_active_in_the_last_day_and_all_it_holds() {
        use std::net::IpAddr;

        let ip = |text: &str| text.parse::<IpAddr>().unwrap();
        // A service that has been up for 30 hours, with three devices: asking just now (twice),
        // 2 h ago, and 26 h ago. The table is told in the order that things happened.
        let dns = aged(30 * 3_600);
        let now = dns.now().mono_secs;
        {
            let mut table = dns.clients();
            table.record(ip("198.51.100.6"), now - 26 * 3_600);
            table.record(ip("198.51.100.5"), now - 2 * 3_600);
            table.record(ip("198.51.100.4"), now - 10);
            table.record(ip("198.51.100.4"), now - 5);
        }
        let extras = Arc::new(Extras::default);
        let facts = LiveFacts { dns, extras };

        // Active is seen in the last 24 hours; total is the table: the third is in it only.
        assert_eq!(facts.clients(), (2, 3));
        let list = facts.client_list();
        let listed: Vec<_> = list
            .iter()
            .map(|c| (c.addr.to_string(), c.queries))
            .collect();
        assert_eq!(
            listed,
            [
                ("198.51.100.4".to_owned(), 2),
                ("198.51.100.5".to_owned(), 1),
                ("198.51.100.6".to_owned(), 1)
            ]
        );
        // The seconds are those since each asked, at this moment; a second may turn meanwhile.
        assert!(matches!(list[0].last_seen_secs_ago, 5..=6));
        assert!(matches!(list[1].last_seen_secs_ago, 7_200..=7_201));
        assert!(matches!(list[2].last_seen_secs_ago, 93_600..=93_601));
        // Neither call keeps the table locked: a deadlock here would be the test hanging.
        facts.dns.note_client(ip("198.51.100.7"));
        assert_eq!(facts.clients(), (3, 4));
    }

    #[tokio::test]
    async fn the_list_is_read_through_the_extras_once_per_call() {
        let (dns, _addr, _upstream) = one(Reply::Answer(UPSTREAM_ADDRESS.parse().unwrap())).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let facts = LiveFacts {
            dns,
            extras: {
                let calls = calls.clone();
                Arc::new(move || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Extras::default()
                })
            },
        };

        assert_eq!(facts.list(), (None, None));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_pause_through_the_api_is_the_panels_pause_and_the_other_way_round() {
        let (facts, addr, _upstream) = facts_over_a_resolver().await;
        let panel = SharedResolver::of(&facts.dns);
        let blocked = |answer: Option<crate::dns::client::Answer>| {
            answer.unwrap().addrs == ["0.0.0.0".parse::<std::net::IpAddr>().unwrap()]
        };
        assert_eq!(facts.paused_left_secs(), None);
        assert!(blocked(ask_udp(addr, "ads.example.com").await));

        // Counted on whole seconds, and a second may turn between the calls.
        facts.pause_for(300);
        assert!(matches!(facts.paused_left_secs(), Some(299..=300)));
        assert!(matches!(panel.paused_left_secs(), Some(299..=300)));
        // While it lasts the name is forwarded, not blocked.
        assert!(!blocked(ask_udp(addr, "ads.example.com").await));

        facts.resume();
        assert_eq!(
            (facts.paused_left_secs(), panel.paused_left_secs()),
            (None, None)
        );
        assert!(blocked(ask_udp(addr, "ads.example.com").await));

        // The panel's pause is seen by the API, and ended by it.
        panel.pause_for(120);
        assert!(matches!(facts.paused_left_secs(), Some(119..=120)));
        facts.resume();
        assert_eq!(panel.paused_left_secs(), None);
        assert!(facts.dns.shared().try_lock().is_ok());
    }
}
