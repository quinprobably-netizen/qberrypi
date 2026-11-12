//! Refreshing the block lists: fetch every list, build one block set from them and the
//! configuration, and swap it into the resolver. A minute after SNTP has set the clock, and then
//! once a day.
//!
//! A refresh that goes wrong in any way — a list that cannot be fetched, a page that is no list,
//! such as a captive portal's — changes nothing but the state's error: the set in force stays and
//! the next try is in an hour.
//!
//! Nothing here logs a name that a household asked for, and nothing logs or says a list's URL:
//! it may carry a token. A list is named by its host.
//!
//! The runtime thread is held only for the swap: under the resolver's lock a few buffer handles
//! change places, which takes microseconds, whatever the size of the sets. The old set (tens of
//! megabytes of names) is taken out in the swap and freed on the blocking pool once the lock is
//! let go ([`release`]). A fetch is the job of [`Client`], and parsing a list and building the set
//! are blocking jobs here. Only one list's text is held at a time, and a list is no more than the
//! fetcher's cap in size.

use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use qb_dns::{BlockSet, ListClass};
use tokio::sync::watch;
use tokio::time::sleep;

use super::{Lists, from_config, names};
use crate::config::Config;
use crate::dns::Dns;
use crate::https::{Client, HttpError, Url};
use crate::services::blocking;

/// How long after the clock is set the first refresh is made.
pub const FIRST_AFTER: Duration = Duration::from_secs(60);
/// How long after a refresh that worked the next is made.
pub const EVERY: Duration = Duration::from_secs(24 * 3600);
/// How long after a refresh that failed the next is made.
pub const RETRY_AFTER: Duration = Duration::from_secs(3600);

/// What the lists are fetched with.
pub trait Fetch: Send + Sync {
    /// The body that `url` gives.
    fn fetch<'a>(
        &'a self,
        url: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, HttpError>> + Send + 'a>>;
}

impl Fetch for Client {
    fn fetch<'a>(
        &'a self,
        url: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, HttpError>> + Send + 'a>> {
        Box::pin(Client::fetch(self, url))
    }
}

/// Why a refresh made no set. `Display` names the list by its number and its host, and holds no
/// URL.
#[derive(Debug)]
pub enum RefreshError {
    /// List number `list`, counted from 1, could not be fetched.
    Fetch {
        list: usize,
        host: String,
        error: HttpError,
    },
    /// What list number `list` gave holds no rule at all: it is not a blocklist.
    NotAList { list: usize, host: String },
}

impl fmt::Display for RefreshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fetch { list, host, error } => write!(f, "list {list} ({host}): {error}"),
            Self::NotAList { list, host } => write!(f, "list {list} ({host}): not a blocklist"),
        }
    }
}

/// The host of `url`, or `?` if it does not parse: the one thing of a URL that is said.
fn host_of(url: &str) -> String {
    Url::parse(url).map_or_else(|_| "?".to_owned(), |url| url.host)
}

/// An error for the blocking job of list `list` that could not be joined.
fn lost(list: usize, host: String, error: io::Error) -> RefreshError {
    RefreshError::Fetch {
        list,
        host,
        error: HttpError::Connect(error),
    }
}

/// The block set that the lists at `urls` and then the threat lists at `threat_urls`, each in
/// order, and then the `deny` and `allow` entries of the configuration make: the lists are
/// numbered from 1, and the threat lists go on from the last of them. A name on a threat list is
/// a threat, whatever else lists it.
///
/// Each list is fetched, and its text is parsed on the blocking pool and dropped there before
/// the next is fetched; building the set is a blocking job too. The first list that fails ends
/// the refresh: so does one that is no list, which is one that holds no rule.
pub async fn build(
    fetch: &dyn Fetch,
    urls: &[String],
    threat_urls: &[String],
    deny: &[String],
    allow: &[String],
) -> Result<BlockSet, RefreshError> {
    let mut builder = from_config(deny, allow);
    let all = urls
        .iter()
        .map(|url| (url, ListClass::Ads))
        .chain(threat_urls.iter().map(|url| (url, ListClass::Threat)));
    for (index, (url, class)) in all.enumerate() {
        let list = index + 1;
        let host = host_of(url);
        let started = Instant::now();
        let text = fetch
            .fetch(url)
            .await
            .map_err(|error| RefreshError::Fetch {
                list,
                host: host.clone(),
                error,
            })?;
        let kind = match class {
            ListClass::Ads => "",
            ListClass::Threat => " (threat)",
        };
        log::info!(
            "lists: list {list} ({host}): {} bytes in {} ms{kind}",
            text.len(),
            started.elapsed().as_millis()
        );
        let (stats, parsed) = blocking("list parse", move || {
            let stats = builder.add_list_as(&text, class);
            (stats, builder)
        })
        .await
        .map_err(|error| lost(list, host.clone(), error))?;
        if stats.exact + stats.suffix == 0 {
            return Err(RefreshError::NotAList { list, host });
        }
        builder = parsed;
    }
    let host = threat_urls
        .last()
        .or(urls.last())
        .map_or_else(|| "?".to_owned(), |url| host_of(url));
    blocking("list build", move || builder.build())
        .await
        .map_err(|error| lost(urls.len() + threat_urls.len(), host, error))
}

/// Drops `old` on the blocking pool: for a set of names, which is tens of megabytes to give back
/// to the allocator, and which would hold the runtime thread (the thread of every query) while it
/// went. If the pool cannot take the job (the runtime is shutting down), `old` is dropped with the
/// job, wherever that happens.
async fn release<T: Send + 'static>(old: T) {
    let _ = blocking("dropping the old lists", move || drop(old)).await;
}

/// How long to wait before the next refresh: `None` if the clock was just set, `Some(true)` after
/// a refresh that worked and `Some(false)` after one that failed.
pub fn next_after(last: Option<bool>) -> Duration {
    match last {
        None => FIRST_AFTER,
        Some(true) => EVERY,
        Some(false) => RETRY_AFTER,
    }
}

/// The refresh component: waits for the clock, and then refreshes the lists of `cfg` into the
/// resolver of `dns` once a day, for ever, and records how it went in `lists`.
///
/// Nothing is fetched until `synced` is true, because no certificate would be good before. It is
/// looked at only for that: SNTP says it again every hour, and that starts nothing. With no list
/// and no threat list configured it waits for ever and does nothing.
pub async fn run(
    dns: Arc<Dns>,
    lists: Arc<Lists>,
    fetch: Arc<dyn Fetch>,
    cfg: &'static Config,
    mut synced: watch::Receiver<bool>,
) -> io::Result<()> {
    if cfg.dns.lists.is_empty() && cfg.dns.threat_lists.is_empty() {
        log::info!("lists: none configured");
        return std::future::pending().await;
    }
    log::info!("lists: waiting for the clock");
    // The value is let go of in the same statement: nothing is held across a wait.
    synced
        .wait_for(|&set| set)
        .await
        .map(|_| ())
        .map_err(|_| io::Error::other("the clock's reports have ended"))?;
    sleep(next_after(None)).await;
    loop {
        let started = Instant::now();
        let built = build(
            &*fetch,
            &cfg.dns.lists,
            &cfg.dns.threat_lists,
            &cfg.dns.deny,
            &cfg.dns.allow,
        )
        .await;
        let worked = built.is_ok();
        match built {
            Ok(set) => {
                let (count, threats) = (names(&set), set.threat_len());
                // The new set was built, and its names counted, off the thread. The swap under
                // the lock takes the old set out and drops nothing: the guard is gone at the end
                // of the statement, and the old set is freed on the pool, after the report.
                let old = dns.resolver().replace_blockset(set);
                lists.fetched(count, dns.now().unix_secs);
                log::info!(
                    "lists: refreshed: {count} names, {threats} of them threats, from {} lists in {:.1} s",
                    cfg.dns.lists.len() + cfg.dns.threat_lists.len(),
                    started.elapsed().as_secs_f64()
                );
                release(old).await;
            }
            Err(error) => {
                lists.failed(error.to_string());
                log::warn!(
                    "lists: refresh failed: {error}; keeping {} names",
                    lists.get().names
                );
            }
        }
        sleep(next_after(Some(worked))).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use qb_dns::{Action, ListClass, Transport};
    use tokio::sync::oneshot;
    use tokio::task::JoinHandle;
    use tokio::time::{advance, sleep};

    use crate::config;
    use crate::dns::client;
    use crate::dns::testutil::{FixedOffset, closed_port, ms};
    use crate::dns::upstream::Upstreams;
    use crate::lists::{ListState, Source, from_config};
    use crate::services::testutil::longest_gap;

    const A: &str = "https://lists.example.net/a.txt";
    const B: &str = "https://lists.example.org/b.txt";
    const T: &str = "https://lists.example.com/t.txt";
    const THREATS: &[u8] = b"||bad.example.net^\n0.0.0.0 phish.example.org\n";
    const HOSTS: &[u8] = b"0.0.0.0 ads.example.com\n0.0.0.0 pixel.example.com\n";
    const ADBLOCK: &[u8] = b"||tracker.example.net^\n";
    const HTML: &[u8] = b"<!DOCTYPE html>\n<html><body><h1>Sign in to the network</h1><p>example.com</p></body></html>\n";

    /// Real time that the lists task has to settle in, after any one step of a paused-clock test.
    const SETTLE_LIMIT: Duration = Duration::from_secs(20);

    /// What a fake server gives for a URL: a body, or the failure of a fetch.
    type Page<'a> = Result<&'a [u8], HttpError>;

    /// A fetcher that serves the pages it was given, counts its calls, and can be given other
    /// pages while a test runs. A URL it has no page for is a 404.
    struct FakeFetch {
        pages: Mutex<HashMap<String, Result<Vec<u8>, u16>>>,
        calls: AtomicUsize,
    }

    impl FakeFetch {
        fn new(pages: &[(&str, Page<'_>)]) -> Self {
            let fetch = Self {
                pages: Mutex::default(),
                calls: AtomicUsize::new(0),
            };
            for (url, page) in pages {
                fetch.put(url, page);
            }
            fetch
        }

        /// From now on `url` gives `page`. Only a body or `HttpError::Status` can be served.
        fn set(&self, url: &str, page: Page<'_>) {
            self.put(url, &page);
        }

        fn put(&self, url: &str, page: &Page<'_>) {
            let page = match page {
                Ok(body) => Ok(body.to_vec()),
                Err(HttpError::Status(code)) => Err(*code),
                Err(other) => panic!("a fake server gives a status, not: {other}"),
            };
            self.pages.lock().unwrap().insert(url.to_owned(), page);
        }

        /// How many fetches were asked for.
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl Fetch for FakeFetch {
        fn fetch<'a>(
            &'a self,
            url: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, HttpError>> + Send + 'a>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let page = self.pages.lock().unwrap().get(url).cloned();
            let page = page.unwrap_or(Err(404));
            Box::pin(async move { page.map_err(HttpError::Status) })
        }
    }

    /// The example configuration with `urls` as its lists, `threat_urls` as its threat lists and
    /// `old.example.com` as its one `deny` entry, which lives as long as the test binary.
    fn config(urls: &[&str], threat_urls: &[&str]) -> &'static Config {
        let mut cfg = config::parse(include_str!("../../../../qberrypi.example.toml")).unwrap();
        cfg.dns.lists = urls.iter().map(|&url| url.to_owned()).collect();
        cfg.dns.threat_lists = threat_urls.iter().map(|&url| url.to_owned()).collect();
        cfg.dns.deny = vec!["old.example.com".to_owned()];
        Box::leak(Box::new(cfg))
    }

    /// The error of a refresh that failed. (A block set has no `Debug`, so `unwrap_err` is out.)
    fn failure(built: Result<BlockSet, RefreshError>) -> RefreshError {
        match built {
            Err(error) => error,
            Ok(_) => panic!("the refresh worked"),
        }
    }

    /// Whether the resolver of `dns` answers `name` itself with the blocked address, which is what
    /// a name in its block set gets; a name that it would ask an upstream for is not blocked.
    fn blocks(dns: &Dns, name: &str) -> bool {
        let packet = client::query(7, name, 1).unwrap();
        let now = dns.now();
        let action = dns.resolver().handle_query(&packet, Transport::Udp, now);
        match action {
            Action::Reply(reply) => client::read_answer(&reply, 7)
                .is_some_and(|answer| answer.v4() == [Ipv4Addr::UNSPECIFIED]),
            Action::Forward(_) => false,
            other => panic!("neither blocked nor forwarded: {other:?}"),
        }
    }

    /// The lists task on a paused clock, with what it works on.
    struct Run {
        dns: Arc<Dns>,
        lists: Arc<Lists>,
        fetch: Arc<FakeFetch>,
        /// What SNTP does: tells that the clock is set.
        clock: watch::Sender<bool>,
        task: JoinHandle<io::Result<()>>,
        /// Gets its message when a test has run for [`SETTLE_LIMIT`] of real time.
        too_long: oneshot::Receiver<()>,
    }

    impl Run {
        /// Spawns `run` over the example configuration with `urls` as its lists and a resolver
        /// that blocks `old.example.com`, the lists' state being that of a set made from the
        /// configuration alone.
        async fn start(urls: &[&str], pages: &[(&str, Page<'_>)], clock_set: bool) -> Self {
            Self::start_with(urls, &[], pages, clock_set).await
        }

        /// [`Run::start`] with `threat_urls` as the configuration's threat lists too.
        async fn start_with(
            urls: &[&str],
            threat_urls: &[&str],
            pages: &[(&str, Page<'_>)],
            clock_set: bool,
        ) -> Self {
            let cfg = config(urls, threat_urls);
            let set = from_config(&cfg.dns.deny, &cfg.dns.allow).build();
            let lists = Lists::new(ListState {
                source: Source::Config,
                names: names(&set),
                fetched_unix_secs: None,
                last_error: None,
            });
            let dns = Dns::new(
                set,
                Upstreams::with(vec![closed_port()], ms(300), ms(600)),
                Box::new(FixedOffset(0)),
            );
            let fetch = Arc::new(FakeFetch::new(pages));
            let (clock, synced) = watch::channel(clock_set);
            let task = tokio::spawn(run(dns.clone(), lists.clone(), fetch.clone(), cfg, synced));
            let (late, too_long) = oneshot::channel();
            std::thread::spawn(move || {
                std::thread::sleep(SETTLE_LIMIT);
                let _ = late.send(());
            });
            let mut run = Self {
                dns,
                lists,
                fetch,
                clock,
                task,
                too_long,
            };
            // The task starts its wait before time moves: a minute is counted from the clock being
            // set, which for a clock that is set from the start is now.
            run.settle().await;
            run
        }

        /// Lets `by` pass on the paused clock, and returns when the task has done what that made
        /// it do and waits again.
        async fn pass(&mut self, by: Duration) {
            advance(by).await;
            self.settle().await;
        }

        /// Returns when the task waits on its timer or on the clock, and does nothing more.
        ///
        /// The paused clock moves on only when the runtime has nothing to run, and not while a job
        /// is on the blocking pool, which runs in real time: a build is waited for, a millisecond
        /// of the clock at a time. So this sleep of 1 ms, the nearest timer there is, ends only
        /// once the task is waiting for the next one. A task that never gets there fails the test
        /// after [`SETTLE_LIMIT`] of real time instead of hanging it.
        async fn settle(&mut self) {
            tokio::select! {
                () = sleep(ms(1)) => {}
                _ = &mut self.too_long => panic!("the lists task did not settle in {SETTLE_LIMIT:?}"),
            }
        }
    }

    #[tokio::test]
    async fn two_lists_and_the_configuration_make_one_set() {
        let fetch = FakeFetch::new(&[(A, Ok(HOSTS)), (B, Ok(ADBLOCK))]);
        let set = build(
            &fetch,
            &[A.into(), B.into()],
            &[],
            &["denied.example.org".into()],
            &["ok.tracker.example.net".into()],
        )
        .await
        .unwrap();
        for blocked in [
            "ads.example.com",
            "pixel.example.com",
            "x.tracker.example.net",
            "denied.example.org",
        ] {
            assert!(set.is_blocked(blocked), "{blocked}");
        }
        for open in ["ok.tracker.example.net", "example.com"] {
            assert!(!set.is_blocked(open), "{open}");
        }
        assert_eq!(names(&set), 4);
    }

    #[tokio::test]
    async fn threat_lists_are_fetched_after_the_lists_and_carry_their_class() {
        let fetch = FakeFetch::new(&[(A, Ok(HOSTS)), (T, Ok(THREATS))]);
        let set = build(&fetch, &[A.into()], &[T.into()], &[], &[])
            .await
            .unwrap();
        assert_eq!(set.verdict("ads.example.com"), Some(ListClass::Ads));
        assert_eq!(set.verdict("x.bad.example.net"), Some(ListClass::Threat));
        assert_eq!(set.verdict("phish.example.org"), Some(ListClass::Threat));
        assert_eq!(set.verdict("example.org"), None);
        assert_eq!((names(&set), set.threat_len()), (4, 2));

        // The threat lists are numbered after the lists, and are fetched after them: with both
        // missing, the first failure is list 1, and the threat list is never asked for.
        let fetch = FakeFetch::new(&[]);
        let error = failure(build(&fetch, &[A.into()], &[T.into()], &[], &[]).await);
        assert_eq!(error.to_string(), "list 1 (lists.example.net): status 404");
        assert_eq!(fetch.calls(), 1);
        // An error in the threat list names it as list 2, and by its host.
        let fetch = FakeFetch::new(&[(A, Ok(HOSTS)), (T, Err(HttpError::Status(503)))]);
        let error = failure(build(&fetch, &[A.into()], &[T.into()], &[], &[]).await);
        assert_eq!(error.to_string(), "list 2 (lists.example.com): status 503");
        // So does a threat list that is no list.
        let fetch = FakeFetch::new(&[(A, Ok(HOSTS)), (T, Ok(HTML))]);
        let error = failure(build(&fetch, &[A.into()], &[T.into()], &[], &[]).await);
        assert!(
            matches!(&error, RefreshError::NotAList { list: 2, host } if host == "lists.example.com")
        );
        // The `allow` entries of the configuration beat a threat, as they do an ad.
        let fetch = FakeFetch::new(&[(T, Ok(THREATS))]);
        let allow = ["ok.bad.example.net".to_owned()];
        let set = build(&fetch, &[], &[T.into()], &[], &allow).await.unwrap();
        assert_eq!(set.verdict("ok.bad.example.net"), None);
        assert_eq!(set.verdict("x.bad.example.net"), Some(ListClass::Threat));
    }

    // Review Focus 4
    #[tokio::test]
    async fn a_page_that_is_not_a_list_fails_the_refresh() {
        for not_a_list in [HTML, &b""[..], b"# only a comment\n"] {
            let fetch = FakeFetch::new(&[(A, Ok(HOSTS)), (B, Ok(not_a_list))]);
            let error = failure(build(&fetch, &[A.into(), B.into()], &[], &[], &[]).await);
            assert!(
                matches!(&error, RefreshError::NotAList { list: 2, host } if host == "lists.example.org")
            );
            assert_eq!(
                error.to_string(),
                "list 2 (lists.example.org): not a blocklist"
            );
        }
    }

    // Review Focus 4
    #[tokio::test]
    async fn one_list_that_cannot_be_fetched_fails_the_refresh() {
        let fetch = FakeFetch::new(&[(A, Err(HttpError::Status(404))), (B, Ok(ADBLOCK))]);
        let error = failure(build(&fetch, &[A.into(), B.into()], &[], &[], &[]).await);
        assert_eq!(error.to_string(), "list 1 (lists.example.net): status 404");
        // The list that fails stops the refresh: the next is not fetched.
        assert_eq!(fetch.calls(), 1);
    }

    #[tokio::test]
    async fn an_error_names_the_host_of_a_list_and_never_its_url() {
        let secret = "https://lists.example.net/token-0123456789/a.txt";
        let fetch = FakeFetch::new(&[(secret, Err(HttpError::Status(403)))]);
        let error = failure(build(&fetch, &[secret.into()], &[], &[], &[]).await);
        assert_eq!(error.to_string(), "list 1 (lists.example.net): status 403");
        // A URL that does not parse has no host to name.
        let fetch = FakeFetch::new(&[]);
        let error =
            failure(build(&fetch, &["http://token-0123456789".into()], &[], &[], &[]).await);
        assert_eq!(error.to_string(), "list 1 (?): status 404");
    }

    #[test]
    fn the_schedule() {
        assert_eq!(
            (
                next_after(None),
                next_after(Some(true)),
                next_after(Some(false))
            ),
            (
                Duration::from_secs(60),
                Duration::from_secs(86_400),
                Duration::from_secs(3600)
            )
        );
    }

    // Review Focus 5
    #[tokio::test(start_paused = true)]
    async fn nothing_is_fetched_before_the_clock_is_set() {
        let mut run = Run::start(&[A], &[(A, Ok(HOSTS))], false).await;
        run.pass(Duration::from_secs(2 * 24 * 3600)).await;
        assert_eq!(run.fetch.calls(), 0);
        // The task waits a minute from the moment the clock is set, not from the start.
        run.clock.send(true).unwrap();
        run.settle().await;
        run.pass(Duration::from_secs(59)).await;
        assert_eq!(run.fetch.calls(), 0);
        run.pass(Duration::from_secs(2)).await;
        assert_eq!(run.fetch.calls(), 1);
        assert!(blocks(&run.dns, "ads.example.com"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_second_report_that_the_clock_is_set_does_not_start_another_refresh() {
        // SNTP says so again every hour, whatever the lists are doing.
        let mut run = Run::start(&[A], &[(A, Ok(HOSTS))], true).await;
        run.pass(Duration::from_secs(61)).await;
        assert_eq!(run.fetch.calls(), 1);
        for _ in 0..3 {
            run.clock.send_replace(true);
            run.pass(Duration::from_secs(3600)).await;
            assert_eq!(run.fetch.calls(), 1);
        }
        run.pass(Duration::from_secs(22 * 3600)).await;
        assert_eq!(run.fetch.calls(), 2);
        // A refresh that failed is tried again in an hour, and SNTP's word changes nothing.
        run.fetch.set(A, Ok(HTML));
        run.pass(Duration::from_secs(25 * 3600)).await;
        assert_eq!(run.fetch.calls(), 3);
        run.clock.send_replace(true);
        run.pass(Duration::from_secs(30 * 60)).await;
        assert_eq!(run.fetch.calls(), 3);
        run.pass(Duration::from_secs(31 * 60)).await;
        assert_eq!(run.fetch.calls(), 4);
    }

    // Review Focus 4
    #[tokio::test(start_paused = true)]
    async fn a_failed_refresh_keeps_the_set_and_is_tried_again_in_an_hour() {
        let mut run = Run::start(&[A], &[(A, Ok(HTML))], true).await;
        run.pass(Duration::from_secs(61)).await;
        assert!(blocks(&run.dns, "old.example.com"));
        assert!(!blocks(&run.dns, "ads.example.com"));
        assert_eq!(
            run.lists.get(),
            ListState {
                source: Source::Config,
                names: 1,
                fetched_unix_secs: None,
                last_error: Some("list 1 (lists.example.net): not a blocklist".to_owned()),
            }
        );
        run.fetch.set(A, Ok(HOSTS));
        run.pass(Duration::from_secs(59 * 60)).await;
        assert_eq!(run.fetch.calls(), 1);
        run.pass(Duration::from_secs(2 * 60)).await;
        assert_eq!(run.fetch.calls(), 2);
        assert!(blocks(&run.dns, "ads.example.com"));
        assert!(blocks(&run.dns, "old.example.com"));
        let state = run.lists.get();
        assert_eq!((state.source, state.names), (Source::Fetched, 3));
        assert!(state.fetched_unix_secs.is_some());
        assert_eq!(state.last_error, None);
        // A refresh that worked is followed by the next one a day on.
        run.pass(Duration::from_secs(23 * 3600)).await;
        assert_eq!(run.fetch.calls(), 2);
        run.pass(Duration::from_secs(2 * 3600)).await;
        assert_eq!(run.fetch.calls(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn a_refresh_that_fails_after_one_that_worked_keeps_the_fetched_set() {
        let mut run = Run::start(&[A], &[(A, Ok(HOSTS))], true).await;
        run.pass(Duration::from_secs(61)).await;
        let worked = run.lists.get();
        assert_eq!((worked.source, worked.names), (Source::Fetched, 3));
        run.fetch.set(A, Err(HttpError::Status(503)));
        run.pass(Duration::from_secs(25 * 3600)).await;
        assert_eq!(run.fetch.calls(), 2);
        assert!(blocks(&run.dns, "ads.example.com"));
        assert_eq!(
            run.lists.get(),
            ListState {
                last_error: Some("list 1 (lists.example.net): status 503".to_owned()),
                ..worked
            }
        );
    }

    #[tokio::test]
    async fn a_refresh_does_not_hold_the_runtime_thread() {
        let big: Vec<u8> = (0..200_000)
            .flat_map(|i| format!("0.0.0.0 h{i}.example.com\n").into_bytes())
            .collect();
        let fetch = FakeFetch::new(&[(A, Ok(big.as_slice()))]);
        let (gap, set) = longest_gap(build(&fetch, &[A.into()], &[], &[], &[])).await;
        assert_eq!(names(&set.unwrap()), 200_000);
        assert!(gap < Duration::from_millis(100), "{gap:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn the_refresh_runs_with_threat_lists_alone() {
        // No `lists`, one threat list: a refresh is made, and it is not "none configured".
        let mut run = Run::start_with(&[], &[T], &[(T, Ok(THREATS))], true).await;
        run.pass(Duration::from_secs(61)).await;
        assert_eq!(run.fetch.calls(), 1);
        assert!(blocks(&run.dns, "phish.example.org"));
        assert!(blocks(&run.dns, "x.bad.example.net"));
        assert!(blocks(&run.dns, "old.example.com"));
        let state = run.lists.get();
        assert_eq!((state.source, state.names), (Source::Fetched, 3));
        assert_eq!(state.last_error, None);
        // The next is a day on, as ever.
        run.pass(Duration::from_secs(25 * 3600)).await;
        assert_eq!(run.fetch.calls(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_second_refresh_replaces_the_set_and_what_the_old_one_blocked_is_open() {
        let mut run = Run::start(&[A], &[(A, Ok(HOSTS))], true).await;
        run.pass(Duration::from_secs(61)).await;
        assert!(blocks(&run.dns, "ads.example.com"));
        assert!(blocks(&run.dns, "pixel.example.com"));
        // The list is another one the next day: the swap puts its set in force.
        run.fetch.set(A, Ok(ADBLOCK));
        run.pass(Duration::from_secs(25 * 3600)).await;
        assert_eq!(run.fetch.calls(), 2);
        assert!(!blocks(&run.dns, "ads.example.com"));
        assert!(!blocks(&run.dns, "pixel.example.com"));
        assert!(blocks(&run.dns, "x.tracker.example.net"));
        assert!(blocks(&run.dns, "old.example.com"));
        let state = run.lists.get();
        assert_eq!((state.source, state.names), (Source::Fetched, 2));
        assert_eq!(state.last_error, None);
        // And the task goes on to the day after, having freed the old set.
        assert!(!run.task.is_finished());
        run.pass(Duration::from_secs(25 * 3600)).await;
        assert_eq!(run.fetch.calls(), 3);
    }

    #[tokio::test]
    async fn an_old_set_is_dropped_on_the_pool_and_not_on_the_runtime_thread() {
        /// Notes the thread it is dropped on.
        struct Probe(Arc<Mutex<Option<std::thread::ThreadId>>>);

        impl Drop for Probe {
            fn drop(&mut self) {
                *self.0.lock().unwrap() = Some(std::thread::current().id());
            }
        }

        let dropped_on = Arc::new(Mutex::new(None));
        release(Probe(dropped_on.clone())).await;
        let thread = dropped_on.lock().unwrap().expect("the value was dropped");
        assert_ne!(thread, std::thread::current().id());
    }

    #[tokio::test(start_paused = true)]
    async fn with_no_lists_nothing_is_ever_fetched() {
        let mut run = Run::start(&[], &[(A, Ok(HOSTS))], true).await;
        run.pass(Duration::from_secs(3 * 24 * 3600)).await;
        assert_eq!(run.fetch.calls(), 0);
        assert!(!run.task.is_finished());
    }
}
