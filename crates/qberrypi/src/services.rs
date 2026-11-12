//! The services on the runtime: what the components are made from, the one way off the runtime
//! thread, and the pool behind it.
//!
//! Init's runtime has one thread, init's main one, and [`BLOCKING_THREADS`] more for work that
//! blocks. (The Wi-Fi component's netlink sockets each have one more thread beside these, which
//! does nothing but send what the socket hands it: see `netlink::socket`.) [`prepare`] gives the DNS service, the zone's offset, the clock, the status server,
//! the list refresh, the watchdog's analysis and device watch and, when the configuration has an
//! `[api]` section, the Pi-hole API on port 443 as components for the supervisor to run, and, on a boot
//! that is on trial of an update, the trial ([`crate::update::trial`]). What they
//! share (the resolver with its cache and counts, the lists, the clock's channel, the panel's slot,
//! the watchdog's alerts and device inventory) is made once, by
//! whichever of them starts first, so the supervisor starts the other components beside the
//! snapshot load. A service is an `async fn` that makes its own sockets from what it is given,
//! runs until it fails, and returns the error; it never exits the process and never loops
//! silently on a failure. The supervisor starts it again when it fails, with the same shared
//! state, so a restarted listener binds again and keeps the resolver's cache and counts.

use std::convert::Infallible;
use std::fs;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use rustls::ServerConfig;
use rustls::pki_types::ServerName;
use tokio::net::TcpListener;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::{OnceCell, Semaphore, watch};
use tokio::time::sleep;

use crate::api::live::LiveFacts;
use crate::api::qbp::QbpWatch;
use crate::api::routes::Api;
use crate::api::{self, Limits};
use crate::config::Config;
use crate::cpu;
use crate::dns::dot::{DOT_PORT, TlsUpstream};
use crate::dns::upstream::{TlsState, Upstreams};
use crate::dns::{DNS_PORT, Dns, listen};
use crate::https::{Client, client_config, mozilla_roots};
use crate::lists::snapshot::{self, Loaded, SNAPSHOT_PATH};
use crate::lists::{Lists, Source, refresh};
use crate::live;
use crate::logbuf::LogBuf;
use crate::selftest;
use crate::sntp::Sntp;
use crate::status::{self, Status};
use crate::supervisor::{Component, Ended};
use crate::sys;
use crate::thermal::{self, BOARD_TEMP};
use crate::update::UpdateCtl;
use crate::update::receive;
use crate::update::trial::{self, BoardHealth};
use crate::watch::behaviour::Behaviour;
use crate::watch::devices::Devices;
use crate::watch::rebind::RebindPolicy;
use crate::watch::store::AlertStore;
use crate::watch::{Event, Watch, analysis, devwatch, feed};
use crate::wifi;
use crate::wiring::{self, Extras, Live, PROC_WIRELESS, SharedResolver, SignalCache, Slot};

/// The threads of the blocking pool, beside the runtime's own: the most blocking jobs that run
/// at once. List parsing and TLS must leave the DNS service its share of the board's four cores.
///
/// One of the five is the front panel's for good: its thread blocks on the screen and the touch
/// screen for as long as the board runs. At most two are the API's connections, one each, and the
/// API's places, which a listener takes one of before it accepts a connection and which outlive
/// any one start of the listener (`ApiParts`), guarantee it.
/// The other two are for everything else: the snapshot load, the list fetch and parse, the log
/// saves and the signal reads. The watchdog's analysis and device watch use none of it: they are
/// tasks of the runtime that read a channel and sockets through its reactor, so the pool stays at
/// five. Nor are the DNS-over-TLS handshakes its: each runs on a thread of its own (`dns::dot`), so
/// that a question waiting for a session never waits behind a list parse.
pub const BLOCKING_THREADS: usize = 5;

/// What a blocking job's error says after the job's name when the job could not be joined.
const JOIN_FAILED: &str = "the blocking job could not be joined";

/// How often the resolver is given the time zone's offset from UTC again, so that the day that
/// the statistics count in starts at the right hour when daylight saving time changes.
const UTC_OFFSET_EVERY: Duration = Duration::from_secs(60);

/// What the components are made from.
pub struct Context {
    pub cfg: &'static Config,
    pub log: &'static Mutex<LogBuf>,
    /// When the system came up.
    pub started: Instant,
    /// Where the front panel finds the resolver: the first service to start fills it as soon as the
    /// resolver is made.
    pub slot: Arc<Slot>,
    /// Where the Wi-Fi stands, as the Wi-Fi task reports it.
    pub wifi: watch::Receiver<wifi::WifiStatus>,
    /// The Wi-Fi's signal, as the `signal` component reads it: the front panel and the status page
    /// show it from here, and never read it from the kernel themselves.
    pub signal: Arc<SignalCache>,
    /// The API's TLS key and certificate as the card holds them (`init::tls_pem`): `None` if there
    /// is no such file. It holds a secret, which no line of the log or error shows.
    pub tls_pem: Option<&'static [u8]>,
    /// The slot this boot runs, how an update stands and the card's use for it: init makes it in
    /// its first step and the boot rules fill it. The statistics read it; the update receiver
    /// and the trial are made from it.
    pub update: Arc<UpdateCtl>,
}

/// The one runtime: the current thread, with I/O and time, and a blocking pool of
/// [`BLOCKING_THREADS`]. The caller runs it with `block_on`, and nothing else builds a runtime.
///
/// With `pin` as `None` the threads of the pool run wherever the kernel puts them. With
/// `Some(core)` the caller is the thread that was pinned to `core` (see [`crate::cpu`]), and
/// every thread of the pool, which would start on that core with its creator's mask, moves to
/// every other core the process may use as it starts. A pool thread that cannot leave the core
/// is logged and goes on. A `std` thread that the runtime's thread makes itself is not a pool
/// thread, and leaves the core through [`cpu::spawn_off_runtime_core`].
pub fn runtime(pin: Option<usize>) -> io::Result<Runtime> {
    let mut builder = Builder::new_current_thread();
    builder
        .enable_io()
        .enable_time()
        .max_blocking_threads(BLOCKING_THREADS);
    if let Some(core) = pin {
        builder.on_thread_start(move || {
            if let Err(error) = cpu::all_but_current_thread(core) {
                log::warn!("cpu: a pool thread could not leave core {core}: {error}");
            }
        });
    }
    builder.build()
}

/// How a service ended, as the supervisor takes it: a service runs for ever, so whatever it
/// returns is a failure, an error with its text and an `Ok` as `stopped`.
fn failed(result: io::Result<()>) -> Ended {
    match result {
        Ok(()) => Ended::Failed("stopped".to_owned()),
        Err(error) => Ended::Failed(error.to_string()),
    }
}

/// An essential component that is a service: each start builds the service afresh from `build`.
fn essential<F>(name: &'static str, mut build: impl FnMut() -> F + Send + 'static) -> Component
where
    F: Future<Output = io::Result<()>> + Send + 'static,
{
    Component::task(name, true, move || {
        let service = build();
        async move { failed(service.await) }
    })
}

/// What the services share, made once by the first service that starts.
struct Shared {
    cfg: &'static Config,
    /// The resolver, with its cache and counts, that every start of the DNS service answers from.
    dns: Arc<Dns>,
    lists: Arc<Lists>,
    /// The clock's sender, kept here so that the channel never closes while the clock is down.
    clock_set: watch::Sender<bool>,
    synced: watch::Receiver<bool>,
    status: Status,
    client: Arc<Client>,
    /// The watchdog's alerts: the resolver's answer path, the analysis and the device watch raise
    /// into it, and the API reads it.
    alerts: Arc<AlertStore>,
    /// The devices that the device watch has heard, and the known list that the API sets.
    devices: Arc<Mutex<Devices>>,
    /// The receiving end of the resolver's feed and the behaviour detectors, until the analysis
    /// component's first start takes them: the feed has one receiver, so there is one analysis.
    analysis: Analysis,
}

/// What the analysis component takes at its first start: the feed's receiving end, and the
/// detectors that its events are given to.
type Analysis = Mutex<Option<(Receiver<Event>, Behaviour)>>;

/// The watchdog's state, as [`make_watch`] makes it: the parts of [`Shared`] that are the
/// watchdog's.
struct WatchState {
    /// The alert store.
    alerts: Arc<AlertStore>,
    /// The device inventory.
    devices: Arc<Mutex<Devices>>,
    /// The analysis' share.
    analysis: Analysis,
}

/// Makes [`Shared`] the first time any service asks for it, and gives the same to every later ask.
///
/// The snapshot load is the long part, and only the services wait for it: the Wi-Fi and the
/// front panel are components too, and start beside it. A service that starts again after a
/// failure finds the state made, with no second load.
struct Lazy {
    made: OnceCell<Shared>,
    /// What the API component keeps across its starts, made by the first start that gets as far
    /// as needing it.
    api: OnceCell<ApiParts>,
    ctx: Context,
    /// Where the snapshot is read from.
    snapshot: PathBuf,
}

/// What every start of the API component serves from: the one [`Api`], whose sessions and limit on
/// failed logins survive a start after a failure, the TLS configuration made from `tls.pem`, and
/// the places for connections.
///
/// The places are made once with the rest and every start serves from them: a connection holds its
/// place for as long as its job runs on the blocking pool, which can outlast the start that
/// accepted it, so places made by each start would let a start after a failure add its own two
/// threads to the old ones and go past the API's share of the pool.
struct ApiParts {
    api: Arc<Api>,
    tls: Arc<ServerConfig>,
    places: Arc<Semaphore>,
}

impl Lazy {
    fn new(ctx: Context, snapshot: PathBuf) -> Self {
        Self {
            made: OnceCell::new(),
            api: OnceCell::new(),
            ctx,
            snapshot,
        }
    }

    /// The shared state, made now if no service has made it yet. A service that asks while another
    /// is making it waits for that one.
    async fn get(&self) -> &Shared {
        self.made.get_or_init(|| self.make()).await
    }

    /// The API's state, made now if no start of the API has made it yet: the TLS configuration
    /// from the card's `tls.pem`, then the [`Api`] over the shared state, which this waits for.
    ///
    /// The configuration costs a P-256 signature and its check, so it is made on the blocking pool,
    /// and before the wait for the shared state, which it does not need: a file that is refused ends
    /// the component at once, as does a card with no file. Neither is made again by a later start,
    /// and neither is tried again, as an absent component is not started again. A job that cannot
    /// be joined is a failure, and the next start tries again.
    async fn api(&self) -> Result<&ApiParts, Ended> {
        let Some(section) = &self.ctx.cfg.api else {
            return Err(Ended::Absent("there is no [api] section".to_owned()));
        };
        let Some(pem) = self.ctx.tls_pem else {
            return Err(Ended::Absent("there is no tls.pem".to_owned()));
        };
        self.api
            .get_or_try_init(|| async {
                let tls = blocking("api tls", move || api::tls::server_config(pem))
                    .await
                    .map_err(|error| Ended::Failed(error.to_string()))?
                    .map_err(Ended::Absent)?;
                let shared = self.get().await;
                let facts = LiveFacts {
                    dns: shared.dns.clone(),
                    extras: extras_reader(&shared.dns, &shared.lists, &shared.synced),
                };
                let clock = shared.dns.clone();
                let api = Api::new(
                    section.password_hash.clone(),
                    Arc::new(facts),
                    Arc::new(move || clock.now().mono_secs),
                    Arc::new(session_random),
                )
                .with_watch(Arc::new(QbpWatch {
                    alerts: shared.alerts.clone(),
                    devices: shared.devices.clone(),
                }))
                .with_update(receive::Receiver::new(
                    self.ctx.update.clone(),
                    crate::BUILD_EPOCH,
                ));
                Ok(ApiParts {
                    api: Arc::new(api),
                    tls,
                    places: api::places(),
                })
            })
            .await
    }

    /// Loads the snapshot and makes the resolver, the lists, the clock's channel, the status server
    /// and the HTTPS client, and fills the front panel's slot with the resolver.
    async fn make(&self) -> Shared {
        let Context {
            cfg,
            log,
            started,
            slot,
            wifi,
            signal,
            tls_pem: _,
            update,
        } = &self.ctx;

        // The set that blocks at the start is the snapshot's rules and the configuration's own
        // entries, ready before the DNS service listens: no query is answered without them. The
        // refresh swaps in fresh lists once the clock is set.
        let loaded = load_snapshot(&self.snapshot, &cfg.dns.deny, &cfg.dns.allow).await;
        let upstreams = upstreams_of(cfg);
        let dns = Dns::new(loaded.set, upstreams, Box::new(cfg.timezone.clone()));
        // The switches live in the resolver, and a block set that a refresh swaps in leaves them.
        {
            let mut resolver = dns.resolver();
            resolver.set_doh_canary(cfg.dns.doh_canary);
            resolver.set_prefetch(cfg.speed.prefetch);
        }
        // The watch's sink is where the threat alerts go, as well as its own.
        let WatchState {
            alerts,
            devices,
            analysis,
        } = make_watch(cfg, &dns);
        let lists = Lists::new(loaded.state);
        let (clock_set, synced) = watch::channel(false);
        // Once, for as long as the state lives: a restart of the DNS service finds the
        // connections that it opened, and opens no more.
        if dns.upstreams().tls() == TlsState::WaitingForClock {
            tokio::spawn(start_tls_when_synced(dns.clone(), synced.clone()));
        }

        // The panel's numbers and its switch are the resolver's own, from now on, and the alert that
        // it takes its screen over for is the watchdog's.
        slot.fill(running(&dns, &lists, &synced, wifi, signal));
        slot.fill_alerts(alerts.clone());
        dns.set_lane(slot.lane());

        let status = Status {
            dns: dns.clone(),
            lists: lists.clone(),
            log,
            synced: synced.clone(),
            started: *started,
            link: link_reader(wifi.clone(), signal.clone()),
            board_c: Arc::new(|| thermal::read_c(Path::new(BOARD_TEMP))),
            update: update.clone(),
        };
        let client = Arc::new(Client::new(client_config(mozilla_roots()), dns.clone()));
        Shared {
            cfg,
            dns,
            lists,
            clock_set,
            synced,
            status,
            client,
            alerts,
            devices,
            analysis,
        }
    }
}

/// The upstreams of `cfg`, asked over UDP, with the way over TLS ready for [`Upstreams::start_tls`]
/// when `upstream.tls` is set. The configuration refuses a `tls_name` that TLS cannot check (a label
/// that starts with a hyphen, say), so none comes here from a file; if one does come (a `Config`
/// built another way), it is logged as an error and the upstreams stay on UDP, which is the
/// defensive way to fail, and not a path that a file can take.
fn upstreams_of(cfg: &Config) -> Upstreams {
    let upstreams = Upstreams::new(&cfg.dns.upstreams);
    if !cfg.upstream.tls {
        return upstreams;
    }
    let name = cfg
        .upstream
        .tls_name
        .clone()
        .and_then(|name| ServerName::try_from(name).ok());
    match name {
        Some(name) => upstreams
            .with_tls(
                TlsUpstream {
                    name,
                    config: client_config(mozilla_roots()),
                },
                DOT_PORT,
            )
            .with_clear_names(cfg.net.time_servers.iter().cloned()),
        None => {
            log::error!("dns: upstream.tls_name is not a name TLS can check; staying on UDP");
            upstreams
        }
    }
}

/// Waits for the clock, which a certificate check needs, and then switches the upstreams of `dns`
/// to TLS. Until then only the time servers' names are asked, over UDP, and every other question
/// that must be forwarded waits for the switch or fails (see [`Upstreams::with_clear_names`]), so
/// a clock that is kept from being set leaves nothing in the clear. Nothing here holds anything
/// that the questions or the clock need: the clock's value is let go of in the same statement that
/// waits for it.
async fn start_tls_when_synced(dns: Arc<Dns>, mut synced: watch::Receiver<bool>) {
    let set = synced.wait_for(|&set| set).await.is_ok();
    if set {
        dns.upstreams().start_tls();
    }
}

/// The watchdog's state, made with the resolver: the alert store, the device inventory and the
/// analysis' share (the feed's receiving end with the behaviour detectors). The feed's sending end
/// is hung on the resolver's answer path ([`Dns::set_watch`]) here, before any listener answers.
///
/// The store and the inventory read time from the resolver's clock: (monotonic seconds, unix
/// seconds). The resolver holds the store, and the store's clock holds the resolver: a cycle that
/// lives as long as the board does.
///
/// The inventory is given the configuration's exempt list, its block list and its mode, and the
/// Pi's own address, which with the gateway's is never exempt and always fully blocked, and keeps
/// the resolver's exemption ([`Dns::exempt`]) in step with the lists and with what it hears.
fn make_watch(cfg: &Config, dns: &Arc<Dns>) -> WatchState {
    let clock: Arc<dyn Fn() -> (u64, u64) + Send + Sync> = {
        let dns = dns.clone();
        Arc::new(move || {
            let now = dns.now();
            (now.mono_secs, now.unix_secs)
        })
    };
    let alerts = Arc::new(AlertStore::new(clock.clone()));
    let (feed, events) = feed();
    dns.set_watch(Watch {
        feed,
        rebind: RebindPolicy::new(cfg.watch.rebind_allow.clone()),
        sink: alerts.clone(),
    });
    let behaviour = Behaviour::new(cfg.watch.quiet.clone());
    let mut devices = Devices::new(None, cfg.net.gateway, clock)
        .with_exemption(dns.exempt().clone())
        .with_own_ip(cfg.net.address.addr);
    devices.set_exempt_config(cfg.watch.exempt.clone());
    devices.set_block_config(cfg.watch.block.clone());
    devices.set_exempt_default_config(cfg.watch.exempt_default);
    WatchState {
        alerts,
        devices: Arc::new(Mutex::new(devices)),
        analysis: Mutex::new(Some((events, behaviour))),
    }
}

/// An essential component that is a service of the shared state: each start waits for the state,
/// which the first start makes, and builds the service afresh from it with `run`.
fn service<Fut>(
    name: &'static str,
    lazy: &Arc<Lazy>,
    run: impl Fn(&Shared) -> Fut + Copy + Send + Sync + 'static,
) -> Component
where
    Fut: Future<Output = io::Result<()>> + Send + 'static,
{
    let lazy = lazy.clone();
    essential(name, move || {
        let lazy = lazy.clone();
        async move { run(lazy.get().await).await }
    })
}

/// What makes one service as a component from the shared state, or gives `None` when the
/// configuration has no such service.
type MakeService = fn(&Arc<Lazy>) -> Option<Component>;

/// Every service that the board starts, in the order that it starts them: the DNS service that
/// answers the household, the zone's offset from UTC, the clock, the status server that tells
/// both, and the refresh that waits for the clock; then the watchdog's analysis and device watch
/// and, with an `[api]` section, the API; last, on a boot that is on trial of an update, the trial.
///
/// **This table is where a service is added**: write its `fn <name>_component(lazy: &Arc<Lazy>) ->
/// Option<Component>` and put it here, in the place in the order where it starts. A function gives
/// `None` when the configuration has no such service (as the API does without an `[api]` section),
/// and then nothing is logged about it at all. [`prepare`] makes nothing but these.
const SERVICES: &[MakeService] = &[
    dns_component,
    utc_offset_component,
    clock_component,
    status_component,
    lists_component,
    analysis_component,
    devices_component,
    api_component,
    trial_component,
];

/// Gives the services as components, those of [`SERVICES`], in the order that the board starts
/// them.
///
/// Nothing is made here and nothing waits: the resolver, the lists and the clock's channel are
/// made once, by whichever service starts first, and shared by every start of every one. The
/// front panel's slot is filled when they are made. On a boot that asks for it, the self-test of
/// the servers runs beside them. Must be called on the runtime.
pub fn prepare(ctx: Context) -> Vec<Component> {
    prepare_from(ctx, PathBuf::from(SNAPSHOT_PATH))
}

/// `prepare`, with the snapshot read from `snapshot`.
fn prepare_from(ctx: Context, snapshot: PathBuf) -> Vec<Component> {
    log::info!("services: started");
    let lazy = Arc::new(Lazy::new(ctx, snapshot));

    // The self-test holds nothing up. What protects it is the order: it waits for the shared
    // state, as every service does, and then yields once before it asks. The services that
    // waited with it are woken when the state is made, and the runtime polls them before it
    // gives a task that yielded its second turn; the DNS and status services bind on their first
    // poll. If one has not bound by then, it says `no answer` and the scenario fails.
    if sys::kernel_arg(selftest::DNS_ARG) {
        let lazy = lazy.clone();
        tokio::spawn(async move {
            lazy.get().await;
            tokio::task::yield_now().await;
            dns_selftest().await;
        });
    }

    SERVICES.iter().filter_map(|make| make(&lazy)).collect()
}

/// The DNS service, which is essential: it answers the household on port 53, on every address.
fn dns_component(lazy: &Arc<Lazy>) -> Option<Component> {
    Some(service("dns", lazy, |shared: &Shared| {
        listen::run(shared.dns.clone(), on_every_address(DNS_PORT))
    }))
}

/// The component that gives the resolver the zone's offset from UTC again every
/// [`UTC_OFFSET_EVERY`], which is essential.
fn utc_offset_component(lazy: &Arc<Lazy>) -> Option<Component> {
    Some(Component::task("utc offset", true, {
        let lazy = lazy.clone();
        move || {
            let lazy = lazy.clone();
            async move { match keep_utc_offset(lazy.get().await.dns.clone()).await {} }
        }
    }))
}

/// The clock, which is essential: the SNTP client that sets it and tells the services that wait
/// for it.
fn clock_component(lazy: &Arc<Lazy>) -> Option<Component> {
    Some(service("clock", lazy, |shared: &Shared| {
        Sntp::for_board(shared.cfg.net.time_servers.clone())
            .run(shared.dns.clone(), shared.clock_set.clone())
    }))
}

/// The status server, which is essential: it tells the DNS service's numbers and the clock's.
fn status_component(lazy: &Arc<Lazy>) -> Option<Component> {
    Some(service("status", lazy, |shared: &Shared| {
        shared.status.clone().run(on_every_address(status::PORT))
    }))
}

/// The list refresh, which is essential: it waits for the clock, as a certificate check needs it.
fn lists_component(lazy: &Arc<Lazy>) -> Option<Component> {
    Some(service("lists", lazy, |shared: &Shared| {
        refresh::run(
            shared.dns.clone(),
            shared.lists.clone(),
            shared.client.clone(),
            shared.cfg,
            shared.synced.clone(),
        )
    }))
}

/// The watchdog's analysis, which is not essential: the board's job is DNS, and runs on without
/// it. It uses none of the blocking pool ([`BLOCKING_THREADS`] stays five): it is a task of the
/// runtime that waits on a timer.
///
/// It takes what the shared state keeps for it (the feed's receiving end and the behaviour
/// detectors) and drains the feed for as long as the board runs ([`analysis::run`]). The feed has
/// one receiver, so a start after the first finds it taken and ends `Absent`, and is not started
/// again.
fn analysis_component(lazy: &Arc<Lazy>) -> Option<Component> {
    let lazy = lazy.clone();
    Some(Component::task("analysis", false, move || {
        let lazy = lazy.clone();
        async move {
            let shared = lazy.get().await;
            let taken = shared
                .analysis
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            let Some((events, behaviour)) = taken else {
                return Ended::Absent("the feed was taken by an earlier start".to_owned());
            };
            analysis::run(events, behaviour, shared.alerts.clone(), analysis::clock()).await
        }
    }))
}

/// The watchdog's device watch, which is not essential, and like the analysis uses none of the
/// blocking pool: it runs on the Wi-Fi interface ([`devwatch::run`]), which it waits for, through
/// the runtime's sockets, and never ends.
fn devices_component(lazy: &Arc<Lazy>) -> Option<Component> {
    let lazy = lazy.clone();
    Some(Component::task("devices", false, move || {
        let lazy = lazy.clone();
        async move {
            let shared = lazy.get().await;
            devwatch::run(
                shared.devices.clone(),
                shared.alerts.clone(),
                wiring::INTERFACE,
            )
            .await
        }
    }))
}

/// The trial of an update, which is essential, on a boot that is on trial: confirms the build when
/// the Wi-Fi, the clock and an upstream have proved it healthy, or gives up and restarts to the slot
/// it came from (see [`trial`]). `None` on any other boot, and then nothing is logged about it.
///
/// It is a service because what it looks at is the shared state's: each start waits for that, which
/// the first service made, and takes the clock's flag and the resolver from it. The trial's time
/// counts from when init started, so the wait costs it nothing it would not have lost anyway.
fn trial_component(lazy: &Arc<Lazy>) -> Option<Component> {
    let settings = trial::Settings::from_debug(&lazy.ctx.cfg.debug);
    let ctl = lazy.ctx.update.clone();
    ctl.trial()?;
    let lazy = lazy.clone();
    Some(Component::task("trial", true, move || {
        let (lazy, ctl) = (lazy.clone(), ctl.clone());
        async move {
            let shared = lazy.get().await;
            let health = BoardHealth::new(
                lazy.ctx.wifi.clone(),
                shared.synced.clone(),
                shared.dns.clone(),
            );
            trial::run(ctl, Arc::new(health), settings).await
        }
    }))
}

/// The Pi-hole API as a component, which is not essential: the board's job is DNS, and runs on
/// without the API. `None` when the configuration has no `[api]` section, and then nothing is
/// logged about it at all.
///
/// Each start asks for the API's parts ([`Lazy::api`]), binds port 443 on every address, says so,
/// and serves until `accept` fails for good ([`api::serve`] retries the failures that pass).
fn api_component(lazy: &Arc<Lazy>) -> Option<Component> {
    lazy.ctx.cfg.api.as_ref()?;
    let lazy = lazy.clone();
    Some(Component::task("api", false, move || {
        let lazy = lazy.clone();
        async move { api_start(&lazy, on_every_address(api::PORT)).await }
    }))
}

/// One start of the API component, listening on `addr`.
///
/// Ends `Absent` with the reason when there is no `tls.pem` or it is refused, and `Failed` when the
/// port cannot be bound or `accept` keeps failing.
async fn api_start(lazy: &Lazy, addr: SocketAddr) -> Ended {
    let parts = match lazy.api().await {
        Ok(parts) => parts,
        Err(ended) => return ended,
    };
    let listener = match TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(error) => return failed(Err(error)),
    };
    match listener.local_addr() {
        Ok(bound) => log::info!("api: listening on {bound}"),
        Err(error) => return failed(Err(error)),
    }
    failed(
        api::serve(
            listener,
            parts.tls.clone(),
            parts.api.clone(),
            Limits::DEFAULT,
            parts.places.clone(),
        )
        .await,
    )
}

/// Sixteen bytes for the id of a session, from the kernel's random source: `None` when it cannot
/// be read, and then the login that was right gets a 500 and no session. Never from
/// [`sys::random_u64`], which falls back to clock noise that a session id must not be made of.
fn session_random() -> Option<[u8; 16]> {
    let mut bytes = [0u8; 16];
    sys::random_bytes(&mut bytes).ok().map(|()| bytes)
}

/// How often the `signal` component reads the Wi-Fi's signal from the kernel.
pub const SIGNAL_EVERY: Duration = Duration::from_secs(5);

/// What gives the text of the kernel's wireless file, or `None` when it cannot be read. It runs
/// on the blocking pool.
type WirelessReader = Arc<dyn Fn() -> Option<String> + Send + Sync>;

/// The `signal` component, which is essential: the one place that reads the Wi-Fi's signal from
/// the kernel, every [`SIGNAL_EVERY`], on the blocking pool, and stores it in `cache` for the
/// panel and the status page to read.
///
/// `status` is the Wi-Fi's. It never ends while the sender of `status` lives, and the Wi-Fi
/// component holds that sender in the closure the supervisor keeps across its restarts, so a
/// restart of the Wi-Fi does not end this one.
pub fn signal_component(
    status: watch::Receiver<wifi::WifiStatus>,
    cache: Arc<SignalCache>,
) -> Component {
    let read: WirelessReader = Arc::new(|| fs::read_to_string(PROC_WIRELESS).ok());
    Component::task("signal", true, move || {
        keep_signal(status.clone(), cache.clone(), SIGNAL_EVERY, read.clone())
    })
}

/// Stores the signal in `cache` at once and again every `every`, for ever: what `read` gives,
/// through [`wiring::proc_signal`], on the blocking pool while the Wi-Fi in `status` is joined,
/// and `None` without a read while it is not. A read that fails, a text without the signal and a
/// job that cannot be joined leave `None` too. Only a status without a sender ends it.
async fn keep_signal(
    status: watch::Receiver<wifi::WifiStatus>,
    cache: Arc<SignalCache>,
    every: Duration,
    read: WirelessReader,
) -> Ended {
    loop {
        if status.has_changed().is_err() {
            cache.set(None);
            return Ended::Failed("the Wi-Fi status has ended".to_owned());
        }
        // The status is looked at and let go before the read, which waits.
        let joined = matches!(*status.borrow(), wifi::WifiStatus::Joined { .. });
        cache.set(if joined {
            read_signal(&read).await
        } else {
            None
        });
        sleep(every).await;
    }
}

/// The signal that `read` gives, on a thread of the blocking pool.
async fn read_signal(read: &WirelessReader) -> Option<i8> {
    let read = read.clone();
    blocking("signal", move || read())
        .await
        .ok()
        .flatten()
        .and_then(|text| wiring::proc_signal(&text))
}

/// A reader of the Wi-Fi link as the front end shows it. The live signal is the one the `signal`
/// component last stored in `signal`, and is looked at only while the link is up: nothing here
/// reads the kernel, so the reader never waits, on whichever thread it is called.
fn link_reader(
    wifi: watch::Receiver<wifi::WifiStatus>,
    signal: Arc<SignalCache>,
) -> Arc<dyn Fn() -> live::WifiStatus + Send + Sync> {
    Arc::new(move || {
        // The status is copied out, so that no hold on the channel lasts through the rest.
        let status = wifi.borrow().clone();
        wiring::link_status(&status, || signal.get())
    })
}

/// What the panel reads of the running system: the resolver `dns` makes, the lists, the clock's
/// `synced`, and the Wi-Fi's `wifi` with its `signal`.
fn running(
    dns: &Arc<Dns>,
    lists: &Arc<Lists>,
    synced: &watch::Receiver<bool>,
    wifi: &watch::Receiver<wifi::WifiStatus>,
    signal: &Arc<SignalCache>,
) -> Live {
    Live {
        resolver: SharedResolver::of(dns),
        link: link_reader(wifi.clone(), signal.clone()),
        extras: extras_reader(dns, lists, synced),
    }
}

/// What gives the panel's and the API's extras: what `dns`, `lists` and the clock's `synced` say
/// at the moment it is called. It reads no file.
fn extras_reader(
    dns: &Arc<Dns>,
    lists: &Arc<Lists>,
    synced: &watch::Receiver<bool>,
) -> Arc<dyn Fn() -> Extras + Send + Sync> {
    let (dns, lists, synced) = (dns.clone(), lists.clone(), synced.clone());
    Arc::new(move || Extras::read(&dns, &lists, &synced))
}

/// Reads the snapshot at `path` on the blocking pool, so that the runtime thread stays free
/// meanwhile, and says in the log what came of it. A job that cannot be joined leaves the
/// configuration's entries alone, as a missing snapshot does.
async fn load_snapshot(path: &Path, deny: &'static [String], allow: &'static [String]) -> Loaded {
    let started = Instant::now();
    let path = path.to_owned();
    let job = blocking("snapshot", move || snapshot::load(&path, deny, allow)).await;
    let loaded = snapshot_outcome(job, deny, allow);
    let ms = started.elapsed().as_millis();
    match (loaded.state.source, loaded.state.fetched_unix_secs) {
        (Source::Snapshot, Some(fetched)) => log::info!(
            "lists: snapshot: {} names, fetched unix {fetched}, loaded in {ms} ms",
            loaded.state.names
        ),
        _ => log::info!(
            "lists: no snapshot: {} names from the configuration",
            loaded.state.names
        ),
    }
    if let Some(problem) = &loaded.problem {
        log::error!("lists: snapshot: {problem}");
    }
    loaded
}

/// What the snapshot job gave: its set, or the configuration's entries, with the reason, if the
/// job could not be joined. The reason is logged after `lists: snapshot:`, so it does not name
/// the job again.
fn snapshot_outcome(job: io::Result<Loaded>, deny: &[String], allow: &[String]) -> Loaded {
    job.unwrap_or_else(|_| snapshot::config_only(deny, allow, JOIN_FAILED.to_owned()))
}

/// The self-test of the DNS and status servers, for the boot in QEMU that asks for it: waits for
/// `lo`, asks the servers over it, and logs what they said. It is started once they have bound.
async fn dns_selftest() {
    let flags = Path::new(selftest::LO_FLAGS);
    if !selftest::lo_comes_up(flags, selftest::LO_WAIT).await {
        log::error!("selftest: lo is not up");
    }
    let dns = SocketAddr::from((Ipv4Addr::LOCALHOST, DNS_PORT));
    let status = SocketAddr::from((Ipv4Addr::LOCALHOST, status::PORT));
    for line in selftest::dns(dns, status).await {
        log::info!("{line}");
    }
    log::info!("selftest: dns: done");
}

/// The IPv4 address that a server listens on to be reached by every interface, at `port`.
fn on_every_address(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::UNSPECIFIED, port))
}

/// Gives the resolver the zone's offset from UTC every [`UTC_OFFSET_EVERY`], for ever.
async fn keep_utc_offset(dns: Arc<Dns>) -> Infallible {
    loop {
        sleep(UTC_OFFSET_EVERY).await;
        dns.sync_utc_offset();
    }
}

/// Runs `work` on a thread of the blocking pool and waits for it without holding the runtime
/// thread: for anything that takes more than about 50 ms of processor time or waits on a
/// socket in a blocking call.
///
/// A job that could not be joined is an error whose text names `what` and nothing of the work.
/// (In the release build a panic aborts the process through the panic hook, so the only way
/// to lose a job is the runtime shutting down under it.)
pub async fn blocking<T, F>(what: &'static str, work: F) -> io::Result<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| io::Error::other(format!("{what}: {JOIN_FAILED}")))
}

#[cfg(test)]
pub(crate) mod testutil {
    use std::cell::Cell;
    use std::future::Future;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use tokio::time::sleep;

    use super::BLOCKING_THREADS;

    /// Every thread of the blocking pool, held busy until `release` or until this is dropped: work
    /// that is started meanwhile waits in the queue, as it does behind a snapshot load, a list parse
    /// and the front panel.
    pub(crate) struct Jam {
        release: Arc<AtomicBool>,
    }

    impl Jam {
        /// Starts a job on each thread of the pool that waits for `release`, and returns once every
        /// one of them is running. Needs a runtime made by [`super::runtime`], whose pool is
        /// [`BLOCKING_THREADS`] wide.
        pub(crate) async fn fill() -> Self {
            let release = Arc::new(AtomicBool::new(false));
            let busy = Arc::new(AtomicUsize::new(0));
            let jam = Self { release };
            for _ in 0..BLOCKING_THREADS {
                let (release, busy) = (jam.release.clone(), busy.clone());
                drop(tokio::task::spawn_blocking(move || {
                    busy.fetch_add(1, Ordering::SeqCst);
                    while !release.load(Ordering::Acquire) {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }));
            }
            let waited = Instant::now();
            while busy.load(Ordering::SeqCst) < BLOCKING_THREADS {
                assert!(
                    waited.elapsed() < Duration::from_secs(5),
                    "the pool never filled"
                );
                sleep(Duration::from_millis(1)).await;
            }
            jam
        }

        /// Lets the jobs end, which lets what waited in the queue begin.
        pub(crate) fn release(&self) {
            self.release.store(true, Ordering::Release);
        }
    }

    /// A test that fails must not leave the pool jammed: the runtime waits for its jobs when it goes.
    impl Drop for Jam {
        fn drop(&mut self) {
            self.release();
        }
    }

    /// Runs `while_this` beside a ticker that sleeps 1 ms over and over, and returns the longest
    /// time between two of the ticker's wake-ups, from the first to the last, with the output of
    /// `while_this`. Work that holds the runtime thread shows as a gap that long.
    pub(crate) async fn longest_gap<F: Future>(while_this: F) -> (Duration, F::Output) {
        let longest = Cell::new(Duration::ZERO);
        let last = Cell::new(Instant::now());
        let ticker = async {
            loop {
                sleep(Duration::from_millis(1)).await;
                let now = Instant::now();
                longest.set(longest.get().max(now - last.get()));
                last.set(now);
            }
        };
        let output = tokio::select! {
            output = while_this => output,
            () = ticker => unreachable!("the ticker does not end"),
        };
        // A thread held until `while_this` is done never lets the ticker wake: that gap counts too.
        (longest.get().max(last.get().elapsed()), output)
    }
}

#[cfg(test)]
#[path = "services_latency.rs"]
mod latency;

#[cfg(test)]
mod tests {
    use super::testutil::longest_gap;
    use super::*;

    use crate::alerts::{Alert, AlertSink as _, Severity};
    use crate::live::{BlockingControl as _, Source as _};
    use crate::panel::alerts::PendingAlerts as _;
    use crate::supervisor::{Hooks, Plan};

    use std::sync::atomic::{AtomicI32, Ordering};
    use std::time::{Duration, Instant};

    use hickory_proto::op::{Message, MessageType};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{RData, Record};
    use qb_dns::{Action, BlockSetBuilder, Now, Transport, UpstreamOutcome};

    use crate::dns::{UtcOffset, client};

    /// A time zone whose offset a test can change, as daylight saving time does.
    struct Moving(Arc<AtomicI32>);

    impl UtcOffset for Moving {
        fn offset_at(&self, _unix_secs: u64) -> i32 {
            self.0.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn the_runtime_has_one_thread_and_a_pool_of_five() {
        assert_eq!(BLOCKING_THREADS, 5);
        let rt = runtime(None).unwrap();
        let started = Instant::now();
        let main = std::thread::current().id();
        let jobs = rt.block_on(async {
            let job = || {
                blocking("test", move || {
                    let began = started.elapsed();
                    std::thread::sleep(Duration::from_millis(200));
                    (std::thread::current().id(), began)
                })
            };
            let (a, b, c, d, e, f) = tokio::join!(job(), job(), job(), job(), job(), job());
            // The futures themselves run where `block_on` was called.
            assert_eq!(std::thread::current().id(), main);
            [a, b, c, d, e, f].map(Result::unwrap)
        });
        assert!(jobs.iter().all(|(id, _)| *id != main));
        let mut began: Vec<Duration> = jobs.iter().map(|(_, began)| *began).collect();
        began.sort();
        // Five began together, one on each thread of the pool; the sixth waited for a place.
        assert!(
            began[4] - began[0] < Duration::from_millis(150),
            "{began:?}"
        );
        assert!(
            began[5] - began[0] >= Duration::from_millis(190),
            "{began:?}"
        );
    }

    #[tokio::test]
    async fn blocking_work_does_not_hold_the_runtime_thread() {
        let (gap, done) = longest_gap(blocking("test", || {
            std::thread::sleep(Duration::from_millis(300));
            7
        }))
        .await;
        assert_eq!(done.unwrap(), 7);
        assert!(gap < Duration::from_millis(100), "{gap:?}");
    }

    /// Writes a snapshot of `names` names to a file in `dir`, as the board's build makes one.
    fn write_snapshot(dir: &Path, names: u32) -> std::path::PathBuf {
        use crate::lists::snapshot::Header;
        use ruzstd::encoding::{CompressionLevel, compress_to_vec};

        let mut text = Header {
            fetched_unix_secs: 1_800_000_000,
            lists: 1,
            exact: names,
            suffix: 0,
        }
        .line();
        for n in 0..names {
            text.push_str(&format!("0.0.0.0 host{n}.example.com\n"));
        }
        let path = dir.join("blocklist.zst");
        std::fs::write(
            &path,
            compress_to_vec(text.as_bytes(), CompressionLevel::Fastest),
        )
        .unwrap();
        path
    }

    #[tokio::test]
    async fn the_snapshot_is_loaded_without_holding_the_runtime_thread() {
        // Names enough that unpacking and building them is long, in a debug build.
        let names = 150_000;
        let dir = tempfile::tempdir().unwrap();
        let path = write_snapshot(dir.path(), names);

        let started = Instant::now();
        let (gap, loaded) = longest_gap(load_snapshot(&path, &[], &[])).await;
        let took = started.elapsed();

        assert_eq!(loaded.problem, None);
        assert_eq!(loaded.state.source, Source::Snapshot);
        assert_eq!(loaded.state.names, names as usize);
        assert!(loaded.set.is_blocked("host42.example.com"));
        // Held on the runtime thread, this work would leave the ticker silent for over 200 ms.
        assert!(gap < Duration::from_millis(100), "{gap:?} of {took:?}");
    }

    // Final review T13: the line read `lists: snapshot: snapshot: the blocking job ...`
    #[tokio::test]
    async fn a_snapshot_job_that_cannot_be_joined_is_reported_without_its_name_twice() {
        // A job that panics cannot be joined, as one that the runtime shutting down drops.
        let lost = blocking("snapshot", || -> Loaded { panic!("a lost job") }).await;
        assert_eq!(
            lost.as_ref().err().unwrap().to_string(),
            "snapshot: the blocking job could not be joined"
        );
        let deny = ["denied.example.org".to_owned()];
        let loaded = snapshot_outcome(lost, &deny, &[]);
        // The log line is `lists: snapshot: {problem}`.
        assert_eq!(
            loaded.problem.as_deref(),
            Some("the blocking job could not be joined")
        );
        assert_eq!(loaded.state.source, Source::Config);
        assert!(loaded.set.is_blocked("denied.example.org"));
    }

    #[tokio::test]
    async fn a_missing_snapshot_leaves_the_configurations_entries() {
        let deny: &'static [String] = Box::leak(Box::new(["denied.example.org".to_owned()]));
        let loaded = load_snapshot(Path::new("/nonexistent/blocklist.zst"), deny, &[]).await;

        assert!(loaded.problem.is_some());
        assert_eq!(loaded.state.source, Source::Config);
        assert_eq!(loaded.state.names, 1);
        assert!(loaded.set.is_blocked("denied.example.org"));
    }

    #[test]
    fn a_service_that_returns_has_failed_whatever_it_returns() {
        assert_eq!(
            failed(Err(std::io::Error::other("gone"))),
            Ended::Failed("gone".into())
        );
        assert_eq!(failed(Ok(())), Ended::Failed("stopped".into()));
    }

    /// What the services are made from, in a test: the example configuration, an empty slot, and a
    /// Wi-Fi that has not started (the sender is kept so that its channel stays open).
    pub(super) fn context() -> (Context, Arc<Slot>, watch::Sender<wifi::WifiStatus>) {
        context_with("", None)
    }

    /// `context`, with `extra` added to the configuration after the example, and `tls_pem` as the
    /// card's `tls.pem`.
    fn context_with(
        extra: &str,
        tls_pem: Option<&'static [u8]>,
    ) -> (Context, Arc<Slot>, watch::Sender<wifi::WifiStatus>) {
        context_from(extra, tls_pem, |_| {})
    }

    /// [`context`] with the example configuration as `edit` changes it.
    fn context_edited(
        edit: impl FnOnce(&mut Config),
    ) -> (Context, Arc<Slot>, watch::Sender<wifi::WifiStatus>) {
        context_from("", None, edit)
    }

    /// [`context_with`] `extra` and `tls_pem`, with the configuration as `edit` changes it.
    fn context_from(
        extra: &str,
        tls_pem: Option<&'static [u8]>,
        edit: impl FnOnce(&mut Config),
    ) -> (Context, Arc<Slot>, watch::Sender<wifi::WifiStatus>) {
        let text = format!(
            "{}\n{extra}",
            include_str!("../../../qberrypi.example.toml")
        );
        let mut cfg = crate::config::parse(&text).unwrap();
        edit(&mut cfg);
        let cfg: &'static Config = Box::leak(Box::new(cfg));
        let log: &'static Mutex<LogBuf> = Box::leak(Box::new(Mutex::new(LogBuf::new(4096))));
        let slot = Slot::new();
        let (sender, wifi) = watch::channel(wifi::WifiStatus::Starting);
        let ctx = Context {
            cfg,
            log,
            started: Instant::now(),
            slot: slot.clone(),
            wifi,
            signal: SignalCache::new(),
            tls_pem,
            update: UpdateCtl::off(),
        };
        (ctx, slot, sender)
    }

    /// The `[api]` section whose password is `right`.
    fn api_section() -> String {
        let hash = crate::api::password::PasswordHash::new(b"right", [0; 16]);
        format!("[api]\npassword_hash = \"{}\"\n", hash.to_text())
    }

    /// A key and certificate that live as long as the process, as the card's `tls.pem` does.
    fn leaked_pem() -> &'static [u8] {
        Box::leak(crate::api::testutil::pem().into_bytes().into_boxed_slice())
    }

    /// Waits until the resolver is in the slot, for at most 20 s.
    async fn until_filled(slot: &Slot) {
        let waited = Instant::now();
        while slot.snapshot() == live::Snapshot::default() {
            assert!(
                waited.elapsed() < Duration::from_secs(20),
                "the slot stayed empty"
            );
            sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn the_services_come_in_the_order_the_board_starts_them_and_nothing_is_made_yet() {
        let (ctx, slot, _sender) = context();

        let components = prepare(ctx);

        let order: Vec<_> = components.iter().map(|c| (c.name, c.essential)).collect();
        assert_eq!(
            order,
            [
                ("dns", true),
                ("utc offset", true),
                ("clock", true),
                ("status", true),
                ("lists", true),
                ("analysis", false),
                ("devices", false)
            ]
        );
        // The example has no `[api]` section, and so no component for it.
        assert!(components.iter().all(|c| c.name != "api"));
        // The first service that starts makes the resolver, and the slot is filled then.
        assert_eq!(slot.snapshot(), live::Snapshot::default());
    }

    #[tokio::test]
    async fn with_an_api_section_the_api_is_a_component_after_the_watchdog_and_not_essential() {
        let (ctx, slot, _sender) = context_with(&api_section(), None);

        let components = prepare(ctx);

        let order: Vec<_> = components.iter().map(|c| (c.name, c.essential)).collect();
        assert_eq!(
            order,
            [
                ("dns", true),
                ("utc offset", true),
                ("clock", true),
                ("status", true),
                ("lists", true),
                ("analysis", false),
                ("devices", false),
                ("api", false)
            ]
        );
        // Nothing is made yet, the key included.
        assert_eq!(slot.snapshot(), live::Snapshot::default());
    }

    #[tokio::test]
    async fn an_api_without_a_tls_file_ends_absent_at_once_and_waits_for_nothing() {
        let (ctx, slot, _sender) = context_with(&api_section(), None);
        let mut components = prepare(ctx);
        let api = components.pop().unwrap();
        assert_eq!(api.name, "api");
        let mut start = api.start;

        let ended = tokio::time::timeout(Duration::from_secs(1), start()).await;

        assert_eq!(
            ended.unwrap(),
            Ended::Absent("there is no tls.pem".to_owned())
        );
        // It did not wait for the shared state, and so did not make it.
        assert_eq!(slot.snapshot(), live::Snapshot::default());
    }

    #[tokio::test]
    async fn an_api_whose_tls_file_is_refused_ends_absent_with_the_reason_and_not_the_file() {
        let key_and_nothing: &'static [u8] =
            b"-----BEGIN PRIVATE KEY-----\nQ0FOQVJZ\n-----END PRIVATE KEY-----\n";
        for (pem, why) in [
            (&b"garbage"[..], "tls.pem holds no certificate"),
            (key_and_nothing, "tls.pem holds no certificate"),
        ] {
            let (ctx, _slot, _sender) = context_with(&api_section(), Some(pem));
            let lazy = Arc::new(Lazy::new(ctx, "/nonexistent/blocklist.zst".into()));

            let ended = api_start(&lazy, on_every_address(0)).await;

            assert_eq!(ended, Ended::Absent(why.to_owned()));
        }
    }

    #[tokio::test]
    async fn the_apis_state_is_made_once_and_its_sessions_survive_a_start_after_a_failure() {
        use crate::api::http::Request;

        let (ctx, _slot, _sender) = context_with(&api_section(), Some(leaked_pem()));
        let lazy = Lazy::new(ctx, "/nonexistent/blocklist.zst".into());
        let me = Ipv4Addr::new(192, 0, 2, 7);
        let request = |method: &str, target: &str, sid: Option<&str>, body: &[u8]| Request {
            method: method.into(),
            target: target.into(),
            sid: sid.map(Into::into),
            body: body.to_vec(),
            close: false,
        };

        let first = lazy.api().await.ok().unwrap();
        let login = first.api.handle(
            &request("POST", "/api/auth", None, br#"{"password":"right"}"#),
            me,
        );
        let body: serde_json::Value = serde_json::from_slice(&login.body).unwrap();
        let sid = body["session"]["sid"].as_str().unwrap().to_owned();
        // A start after the first one ended with a failure.
        let again = lazy.api().await.ok().unwrap();

        assert!(Arc::ptr_eq(&first.api, &again.api));
        assert!(Arc::ptr_eq(&first.tls, &again.tls));
        let check = again
            .api
            .handle(&request("GET", "/api/auth", Some(&sid), b""), me);
        assert_eq!(check.status, 200);
    }

    #[tokio::test]
    async fn the_connection_places_are_made_once_and_a_start_after_a_failure_gets_the_same() {
        let (ctx, _slot, _sender) = context_with(&api_section(), Some(leaked_pem()));
        let lazy = Lazy::new(ctx, "/nonexistent/blocklist.zst".into());

        let first = lazy.api().await.ok().unwrap();
        let again = lazy.api().await.ok().unwrap();

        assert!(Arc::ptr_eq(&first.places, &again.places));
        assert_eq!(first.places.available_permits(), api::CONNECTIONS);
    }

    #[tokio::test]
    async fn a_started_api_accepts_only_as_the_kept_places_allow_so_a_restart_adds_no_threads() {
        use crate::api::testutil::{certificate, https, pinned_client};

        let pem = leaked_pem();
        let (ctx, _slot, _sender) = context_with(&api_section(), Some(pem));
        let lazy = Arc::new(Lazy::new(ctx, "/nonexistent/blocklist.zst".into()));
        // The places are taken, as the connections of an earlier start that are still running
        // would hold them.
        let held = lazy
            .api()
            .await
            .ok()
            .unwrap()
            .places
            .clone()
            .acquire_many_owned(api::CONNECTIONS as u32)
            .await
            .unwrap();
        let addr = free_address();
        let running = tokio::spawn({
            let lazy = lazy.clone();
            async move { api_start(&lazy, addr).await }
        });
        let waited = Instant::now();
        while std::net::TcpStream::connect(addr).is_err() {
            assert!(waited.elapsed() < Duration::from_secs(20), "never bound");
            sleep(Duration::from_millis(10)).await;
        }

        let client = pinned_client(&certificate(std::str::from_utf8(pem).unwrap()));
        let asked = tokio::spawn(https(addr, client, &["GET /api/auth"]));
        // Nothing is accepted while the places are taken.
        sleep(Duration::from_millis(300)).await;
        assert!(!asked.is_finished(), "served with no place free");

        drop(held);
        let answered = asked.await.unwrap();
        assert_eq!(answered[0].0, 401);
        running.abort();
    }

    #[test]
    fn the_tls_configuration_is_made_on_a_thread_of_the_pool_and_waits_for_one() {
        use super::testutil::Jam;

        let rt = runtime(None).unwrap();
        rt.block_on(async {
            let (ctx, _slot, _sender) = context_with(&api_section(), Some(leaked_pem()));
            let lazy = Lazy::new(ctx, "/nonexistent/blocklist.zst".into());
            // The shared state is made first, which takes the pool as well; with it made, the
            // configuration is all that the API still waits on the pool for.
            lazy.get().await;
            let jam = Jam::fill().await;

            // Every thread of the pool is busy, so the configuration cannot be made: made on the
            // runtime thread, it would be done at once.
            let waiting = tokio::time::timeout(Duration::from_millis(300), lazy.api()).await;
            assert!(
                waiting.is_err(),
                "the configuration was made with the pool full"
            );

            jam.release();
            assert!(lazy.api().await.is_ok());
        });
    }

    /// A free port on `127.0.0.1`: bound and let go, for a service to bind next.
    fn free_address() -> SocketAddr {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.local_addr().unwrap()
    }

    #[tokio::test]
    async fn a_started_api_listens_and_answers_over_tls() {
        use crate::api::testutil::{certificate, https, pinned_client};

        let pem = leaked_pem();
        let (ctx, _slot, _sender) = context_with(&api_section(), Some(pem));
        let lazy = Arc::new(Lazy::new(ctx, "/nonexistent/blocklist.zst".into()));
        let addr = free_address();
        let running = tokio::spawn({
            let lazy = lazy.clone();
            async move { api_start(&lazy, addr).await }
        });
        // Bound once the state is made: the snapshot is missing, which is quick.
        let waited = Instant::now();
        while std::net::TcpStream::connect(addr).is_err() {
            assert!(waited.elapsed() < Duration::from_secs(20), "never bound");
            sleep(Duration::from_millis(10)).await;
        }

        let client = pinned_client(&certificate(std::str::from_utf8(pem).unwrap()));
        let answered = https(addr, client, &["GET /api/auth"]).await;

        assert_eq!(answered[0].0, 401);
        assert!(!running.is_finished());
        running.abort();
    }

    #[tokio::test]
    async fn a_started_api_takes_updates_through_the_update_state_the_board_made() {
        use crate::api::testutil::{certificate, https, pinned_client};

        let pem = leaked_pem();
        let held = UpdateCtl::new(
            Some(crate::slots::Slot::A),
            None,
            Arc::new(crate::update::NoCard),
        );
        let guard = held.begin_receive().unwrap();
        // The old layout has no slots; a slot card whose machinery is taken is busy: the API's
        // receiver answers from the very state that the context carries.
        for (update, key) in [
            (UpdateCtl::off(), "no_slots"),
            (held.clone(), "update_busy"),
        ] {
            let (mut ctx, _slot, _sender) = context_with(&api_section(), Some(pem));
            ctx.update = update;
            let lazy = Arc::new(Lazy::new(ctx, "/nonexistent/blocklist.zst".into()));
            let addr = free_address();
            let running = tokio::spawn({
                let lazy = lazy.clone();
                async move { api_start(&lazy, addr).await }
            });
            let waited = Instant::now();
            while std::net::TcpStream::connect(addr).is_err() {
                assert!(waited.elapsed() < Duration::from_secs(20), "never bound");
                sleep(Duration::from_millis(10)).await;
            }
            let client = pinned_client(&certificate(std::str::from_utf8(pem).unwrap()));
            let login = https(
                addr,
                client.clone(),
                &[r#"POST /api/auth|{"password":"right"}"#],
            )
            .await;
            let sid = login[0].1["session"]["sid"].as_str().unwrap().to_owned();

            let answered = https(
                addr,
                client,
                &[&format!("POST /api/qbp/update|sid={sid}|{{}}")],
            )
            .await;

            assert_eq!(answered[0].0, 409, "{key}");
            assert_eq!(answered[0].1["error"]["key"], key);
            running.abort();
        }
        drop(guard);
    }

    #[tokio::test]
    async fn an_api_whose_port_is_taken_fails_with_the_reason() {
        let (ctx, _slot, _sender) = context_with(&api_section(), Some(leaked_pem()));
        let lazy = Arc::new(Lazy::new(ctx, "/nonexistent/blocklist.zst".into()));
        let taken = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();

        let ended = api_start(&lazy, taken.local_addr().unwrap()).await;

        assert!(
            matches!(&ended, Ended::Failed(why) if why.contains("in use")),
            "{ended:?}"
        );
    }

    #[test]
    fn a_session_id_comes_from_the_kernels_random_source_and_is_never_a_fallback() {
        let (a, b) = (session_random().unwrap(), session_random().unwrap());
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 16]);
    }

    #[tokio::test]
    async fn the_first_service_to_start_makes_the_state_and_the_panels_slot_is_filled() {
        let (ctx, slot, _sender) = context();
        let mut components = prepare(ctx);
        let utc_offset = components.swap_remove(1);
        assert_eq!(utc_offset.name, "utc offset");
        let mut start = utc_offset.start;

        let running = tokio::spawn(start());
        until_filled(&slot).await;

        // Counted on the resolver's whole seconds: a second may turn between the two calls.
        assert_eq!(slot.paused_left_secs(), None);
        slot.pause_for(300);
        assert!(matches!(slot.paused_left_secs(), Some(299..=300)));
        running.abort();
    }

    /// What the resolver of `dns` does with a question for the DoH canary: its reply's response
    /// code if it answers at once, `None` if it would ask an upstream.
    fn canary_rcode(dns: &Dns) -> Option<u8> {
        let packet = client::query(3, "use-application-dns.net", 1).unwrap();
        match dns.decide(&packet, Transport::Udp) {
            Action::Reply(reply) => Some(client::read_answer(&reply, 3).unwrap().rcode),
            Action::Forward(_) => None,
            other => panic!("neither answered nor forwarded: {other:?}"),
        }
    }

    /// Whether the resolver of `dns` asks for a prefetch: `example.com` A is answered by a
    /// made-up upstream with a TTL of 60 and then asked for three times as the end nears.
    fn prefetches(dns: &Dns) -> bool {
        let packet = client::query(7, "example.com", 1).unwrap();
        let at = |mono_secs| Now {
            mono_secs,
            unix_secs: 1_800_000_000,
        };
        let mut resolver = dns.resolver();
        let Action::Forward(pending) = resolver.handle_query(&packet, Transport::Udp, at(0)) else {
            panic!("an empty cache forwards");
        };
        let mut answer = Message::from_vec(&pending.upstream_query(77)).unwrap();
        answer.metadata.message_type = MessageType::Response;
        let question = answer.queries[0].clone();
        answer.add_answer(Record::from_rdata(
            question.name,
            60,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 10))),
        ));
        let stored =
            resolver.handle_upstream(&pending, &answer.to_vec().unwrap(), Transport::Udp, at(0));
        assert!(matches!(stored, UpstreamOutcome::Reply(_)), "{stored:?}");
        let mut last = None;
        for _ in 0..3 {
            last = Some(resolver.handle_query(&packet, Transport::Udp, at(57)));
        }
        matches!(last, Some(Action::ReplyAndRefresh(_, p)) if p.is_prefetch())
    }

    #[tokio::test]
    async fn the_canary_and_prefetch_switches_of_the_configuration_reach_the_resolver() {
        // The example file: the canary on, prefetch off.
        let (ctx, _slot, _sender) = context();
        let lazy = Lazy::new(ctx, "/nonexistent/blocklist.zst".into());
        let dns = lazy.get().await.dns.clone();
        assert_eq!(canary_rcode(&dns), Some(3));
        assert!(!prefetches(&dns));

        // Both the other way round.
        let (ctx, _slot, _sender) = context_edited(|cfg| {
            cfg.dns.doh_canary = false;
            cfg.speed.prefetch = true;
        });
        let lazy = Lazy::new(ctx, "/nonexistent/blocklist.zst".into());
        let dns = lazy.get().await.dns.clone();
        assert_eq!(canary_rcode(&dns), None);
        assert!(prefetches(&dns));

        // The flags live in the resolver: a block set swapped in by a refresh leaves them be.
        dns.resolver().set_blockset(BlockSetBuilder::new().build());
        assert_eq!(canary_rcode(&dns), None);
    }

    /// The example configuration with `upstream.tls` on and `name` for `upstream.tls_name`.
    fn tls_config(name: &str) -> Config {
        let text = include_str!("../../../qberrypi.example.toml")
            .replace("tls = false", "tls = true")
            .replace("dns.quad9.net", name);
        crate::config::parse(&text).unwrap()
    }

    #[tokio::test]
    async fn the_upstreams_get_a_way_over_tls_only_when_the_configuration_says_so() {
        // The example: off.
        let off = crate::config::parse(include_str!("../../../qberrypi.example.toml")).unwrap();
        assert_eq!(upstreams_of(&off).tls(), TlsState::Off);
        // On: the way is there, and nothing is open until the clock is set.
        let on = tls_config("dns.example.org");
        assert_eq!(upstreams_of(&on).tls(), TlsState::WaitingForClock);
    }

    #[tokio::test]
    async fn a_tls_name_that_tls_cannot_check_leaves_the_upstreams_on_udp() {
        // The parser refuses a label that starts with a hyphen, as a certificate check does, so
        // the case is built by hand: a `Config` that did not come from a file.
        assert!(
            crate::config::parse(
                &include_str!("../../../qberrypi.example.toml")
                    .replace("tls = false", "tls = true")
                    .replace("dns.quad9.net", "-dns.example.org")
            )
            .is_err()
        );
        let mut cfg = tls_config("dns.example.org");
        cfg.upstream.tls_name = Some("-dns.example.org".to_owned());
        assert!(ServerName::try_from("-dns.example.org".to_owned()).is_err());
        let upstreams = upstreams_of(&cfg);
        assert_eq!(upstreams.tls(), TlsState::Off);
        // Switching on is then a no-op, and the questions go over UDP.
        upstreams.start_tls();
        assert_eq!(upstreams.tls(), TlsState::Off);
    }

    #[tokio::test]
    async fn the_clock_switches_the_upstreams_to_tls_and_a_restart_opens_no_second_set() {
        use crate::dns::dot::ConnCounts;
        use crate::dns::testutil::{Reply, TlsFakeUpstream, ip, tls_for_fake};

        let fake = TlsFakeUpstream::start(Reply::Answer(ip("192.0.2.10")));
        let upstreams =
            Upstreams::new(&[Ipv4Addr::LOCALHOST]).with_tls(tls_for_fake(&fake), fake.addr.port());
        let dns = Dns::new(
            BlockSetBuilder::new().build(),
            upstreams,
            Box::new(Moving(Arc::new(AtomicI32::new(0)))),
        );
        let (clock_set, synced) = watch::channel(false);

        let waiting = tokio::spawn(start_tls_when_synced(dns.clone(), synced.clone()));
        sleep(Duration::from_millis(100)).await;
        assert_eq!(dns.upstreams().tls(), TlsState::WaitingForClock);
        assert!(!waiting.is_finished());
        // The clock is not held up by the wait (a value that was held would block the sender, and
        // this test with it).
        clock_set.send_replace(true);
        waiting.await.unwrap();
        let until = Instant::now() + Duration::from_secs(10);
        while !matches!(dns.upstreams().tls(), TlsState::On { up: 1, .. }) {
            assert!(Instant::now() < until, "{:?}", dns.upstreams().tls());
            sleep(Duration::from_millis(5)).await;
        }
        // A second wait, as a restart of the service would make, finds the clock set at once and
        // opens nothing more.
        start_tls_when_synced(dns.clone(), synced).await;
        sleep(Duration::from_millis(200)).await;
        assert!(matches!(
            dns.upstreams().tls(),
            TlsState::On {
                up: 1,
                counts: ConnCounts {
                    connects: 1,
                    resumed: 0,
                    ..
                }
            }
        ));
        assert_eq!(fake.handshakes(), 1);
    }

    #[tokio::test]
    async fn the_state_of_a_configuration_with_tls_waits_for_the_clock_with_one_task_to_do_it() {
        // The upstream is the loopback, whose port 853 nothing answers: the connections that the
        // clock opens fail, which is no matter here.
        let (ctx, _slot, _sender) = context_edited(|cfg| {
            cfg.dns.upstreams = vec![Ipv4Addr::LOCALHOST];
            cfg.upstream.tls = true;
            cfg.upstream.tls_name = Some("dns.example.org".to_owned());
        });
        let lazy = Lazy::new(ctx, "/nonexistent/blocklist.zst".into());
        let shared = lazy.get().await;
        assert_eq!(shared.dns.upstreams().tls(), TlsState::WaitingForClock);
        // A restart of a service asks for the state again, and finds the same.
        assert!(std::ptr::eq(shared, lazy.get().await));
        shared.clock_set.send_replace(true);
        let until = Instant::now() + Duration::from_secs(10);
        while !matches!(shared.dns.upstreams().tls(), TlsState::On { .. }) {
            assert!(Instant::now() < until, "the clock did not switch TLS on");
            sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test]
    async fn the_resolver_offers_the_names_it_decides_to_the_panels_lane() {
        let (ctx, slot, _sender) = context();
        let lazy = Lazy::new(ctx, "/nonexistent/blocklist.zst".into());
        let dns = lazy.get().await.dns.clone();

        let packet = crate::dns::client::query(1, "lane.example.org", 1).unwrap();
        dns.decide(&packet, qb_dns::Transport::Udp);
        let mut names = Vec::new();
        slot.lane().take(&mut names);
        assert_eq!(
            names.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(),
            ["lane.example.org"]
        );
    }

    #[tokio::test]
    async fn the_state_is_made_once_and_every_start_after_the_first_finds_it_made() {
        let (ctx, _slot, _sender) = context();
        let lazy = Lazy::new(ctx, "/nonexistent/blocklist.zst".into());

        // Two services that start together, and a restart long after.
        let (a, b) = tokio::join!(lazy.get(), lazy.get());
        let again = lazy.get().await;

        assert!(std::ptr::eq(a, b) && std::ptr::eq(a, again));
        assert!(Arc::ptr_eq(&a.dns, &again.dns));
    }

    /// A card with two slots that is a directory: it selects slot a and holds the marker of a
    /// trial of slot b, as init has left it, and is lent to the update machinery as it is.
    struct TrialCard(tempfile::TempDir);

    impl TrialCard {
        fn new() -> Arc<Self> {
            use crate::slots::{Marker, Mode, Slot as BootSlot};

            let dir = tempfile::tempdir().unwrap();
            for slot in [BootSlot::A, BootSlot::B] {
                let folder = dir.path().join(slot.dir());
                fs::create_dir(&folder).unwrap();
                let config = format!("arm_64bit=1\nos_prefix={}\n", slot.os_prefix());
                fs::write(folder.join("config.txt"), &config).unwrap();
                if slot == BootSlot::A {
                    fs::write(dir.path().join("config.txt"), config).unwrap();
                }
            }
            let marker = Marker {
                slot: BootSlot::B,
                from: BootSlot::A,
                build: 1_794_470_002,
                mode: Mode::Tryboot,
                started: true,
                failed: None,
            };
            crate::slots::write_marker(dir.path(), &marker).unwrap();
            Arc::new(Self(dir))
        }

        /// The state of an update that is on trial, with this card to lend.
        fn on_trial(self: &Arc<Self>) -> Arc<UpdateCtl> {
            let ctl = UpdateCtl::new(
                Some(crate::slots::Slot::B),
                None,
                Arc::new(Lent(self.clone())),
            );
            let marker = crate::slots::read_marker(self.0.path())
                .unwrap()
                .unwrap()
                .unwrap();
            ctl.begin_trial(marker, tokio::time::Instant::now());
            ctl
        }
    }

    /// Lends a [`TrialCard`] as init lends the real one.
    struct Lent(Arc<TrialCard>);

    impl crate::update::BootCard for Lent {
        fn with_boot(
            &self,
            _: crate::update::CardAccess,
            work: &mut dyn FnMut(&Path),
        ) -> io::Result<()> {
            work(self.0.0.path());
            Ok(())
        }
    }

    #[tokio::test]
    async fn the_trial_is_a_service_of_a_boot_that_is_on_trial_and_of_no_other() {
        let card = TrialCard::new();
        for (update, expected) in [
            (card.on_trial(), true),
            (UpdateCtl::off(), false),
            // A slot card that runs no trial.
            (
                UpdateCtl::new(
                    Some(crate::slots::Slot::A),
                    None,
                    Arc::new(Lent(card.clone())),
                ),
                false,
            ),
        ] {
            let (mut ctx, _slot, _sender) = context();
            ctx.update = update;
            let components = prepare_from(ctx, "/nonexistent/blocklist.zst".into());
            let found = components.iter().find(|c| c.name == "trial");
            assert_eq!(found.is_some(), expected);
            // It starts after the other services, and a trial that cannot run restarts the board.
            if let Some(trial) = found {
                assert!(trial.essential);
                assert_eq!(components.last().unwrap().name, "trial");
            }
        }
    }

    #[tokio::test]
    async fn the_trial_service_confirms_from_the_shared_state_and_the_card() {
        let card = TrialCard::new();
        let (mut ctx, _slot, _sender) = context_edited(|cfg| {
            cfg.debug.trial_offline = true;
            cfg.debug.trial_confirm_secs = 1;
        });
        ctx.update = card.on_trial();
        let update = ctx.update.clone();
        let mut components = prepare_from(ctx, "/nonexistent/blocklist.zst".into());
        let mut trial = components.pop().unwrap();
        assert_eq!(trial.name, "trial");
        let task = tokio::spawn((trial.start)());

        // It confirms a second after init started, on the pool, and says so.
        let waited = Instant::now();
        while update.view().last.is_none() {
            assert!(waited.elapsed() < Duration::from_secs(20), "no confirm");
            sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(update.view().state, "idle");
        let config = fs::read(card.0.path().join("config.txt")).unwrap();
        assert_eq!(
            crate::slots::selected_slot(&config),
            Ok(crate::slots::Slot::B)
        );
        assert_eq!(crate::slots::read_marker(card.0.path()).unwrap(), None);
        assert!(!task.is_finished());
        task.abort();
    }

    #[tokio::test]
    async fn the_wifi_and_the_panel_start_while_the_snapshot_is_loading() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let dir = tempfile::tempdir().unwrap();
        let path = write_snapshot(dir.path(), 20_000);
        let (ctx, slot, _sender) = context();
        let mut components = prepare_from(ctx, path);
        let utc_offset = components.swap_remove(1);
        // The Wi-Fi's stand-in: its start says whether the resolver was in the slot yet.
        let started_with_the_slot_empty = Arc::new(AtomicUsize::new(0));
        let wifi = Component::task("wifi", true, {
            let (slot, seen) = (slot.clone(), started_with_the_slot_empty.clone());
            move || {
                if slot.snapshot() == live::Snapshot::default() {
                    seen.fetch_add(1, Ordering::SeqCst);
                }
                std::future::pending::<Ended>()
            }
        });
        let plan = Plan {
            components: vec![utc_offset, wifi],
            return_after: None,
            restart: None,
            link: None,
        };
        let hooks = Hooks {
            tick: Box::new(|| {}),
            led: Box::new(|_| {}),
        };

        tokio::select! {
            _ = crate::supervisor::run(plan, hooks) => unreachable!("nothing here ends"),
            () = until_filled(&slot) => {}
        }

        // The Wi-Fi was started beside the load, not after it.
        assert_eq!(started_with_the_slot_empty.load(Ordering::SeqCst), 1);
    }

    /// A Wi-Fi status that is joined.
    fn joined() -> wifi::WifiStatus {
        wifi::WifiStatus::Joined {
            bssid: [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01],
            freq_mhz: 5180,
            signal_mbm: -5600,
        }
    }

    /// The text of the kernel's wireless file with `dbm` as the signal of `wlan0`.
    fn wireless_with(dbm: i32) -> String {
        format!(
            "Inter-| sta-|   Quality        |   Discarded packets               | Missed | WE\n \
             face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22\n \
             wlan0: 0000   49.  {dbm}.  -256        0      0      0      0      0        0\n"
        )
    }

    /// A stand-in for the kernel's wireless file that says `-61` the first time it is read, `-62`
    /// the second, and so on; with the number of reads, and the threads that read.
    fn counting_reader() -> (
        WirelessReader,
        Arc<std::sync::atomic::AtomicUsize>,
        Arc<Mutex<Vec<std::thread::ThreadId>>>,
    ) {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let reads = Arc::new(AtomicUsize::new(0));
        let threads = Arc::new(Mutex::new(Vec::new()));
        let read: WirelessReader = {
            let (reads, threads) = (reads.clone(), threads.clone());
            Arc::new(move || {
                let nth = reads.fetch_add(1, Ordering::SeqCst) as i32;
                threads.lock().unwrap().push(std::thread::current().id());
                Some(wireless_with(-61 - nth))
            })
        };
        (read, reads, threads)
    }

    // Final fix I1
    #[tokio::test(start_paused = true)]
    async fn the_signal_is_read_on_the_pool_every_five_seconds_while_joined() {
        use std::sync::atomic::Ordering;

        let (_sender, status) = watch::channel(joined());
        let cache = SignalCache::new();
        let (read, reads, threads) = counting_reader();
        let main = std::thread::current().id();

        let keeping = tokio::spawn(keep_signal(status, cache.clone(), SIGNAL_EVERY, read));

        sleep(Duration::from_secs(1)).await;
        assert_eq!(
            reads.load(Ordering::SeqCst),
            1,
            "read at once, not after a period"
        );
        assert_eq!(cache.get(), Some(-61));
        sleep(Duration::from_secs(5)).await;
        assert_eq!(
            reads.load(Ordering::SeqCst),
            2,
            "and again after the period"
        );
        assert_eq!(cache.get(), Some(-62));
        sleep(Duration::from_secs(5)).await;
        assert_eq!(reads.load(Ordering::SeqCst), 3);
        assert_eq!(cache.get(), Some(-63));
        // Never on the runtime's thread.
        assert!(threads.lock().unwrap().iter().all(|id| *id != main));
        keeping.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn the_signal_is_not_read_and_is_none_while_the_link_is_not_joined() {
        use std::sync::atomic::Ordering;

        let (sender, status) = watch::channel(wifi::WifiStatus::Scanning);
        let cache = SignalCache::new();
        // A figure left from an earlier link must go.
        cache.set(Some(-40));
        let (read, reads, _) = counting_reader();
        let keeping = tokio::spawn(keep_signal(status, cache.clone(), SIGNAL_EVERY, read));

        for not_joined in [
            wifi::WifiStatus::Scanning,
            wifi::WifiStatus::Joining {
                bssid: [0x00, 0x00, 0x5e, 0x00, 0x53, 0x01],
                freq_mhz: 5180,
            },
            wifi::WifiStatus::Waiting { secs: 4 },
            wifi::WifiStatus::Starting,
        ] {
            sender.send_replace(not_joined.clone());
            sleep(SIGNAL_EVERY * 2 + Duration::from_secs(1)).await;
            assert_eq!(cache.get(), None, "{not_joined:?}");
            assert_eq!(reads.load(Ordering::SeqCst), 0, "{not_joined:?}");
        }

        // Joined, it is read; once the link is gone again the figure goes with it.
        sender.send_replace(joined());
        sleep(SIGNAL_EVERY + Duration::from_secs(1)).await;
        assert_eq!(cache.get(), Some(-61));
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        sender.send_replace(wifi::WifiStatus::Waiting { secs: 8 });
        sleep(SIGNAL_EVERY + Duration::from_secs(1)).await;
        assert_eq!(cache.get(), None);
        assert_eq!(reads.load(Ordering::SeqCst), 1, "no read without a link");
        keeping.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_file_that_cannot_be_read_or_has_no_signal_or_a_job_that_is_lost_leaves_none() {
        let (_sender, status) = watch::channel(joined());
        let cache = SignalCache::new();
        cache.set(Some(-40));
        let readers: [WirelessReader; 3] = [
            Arc::new(|| None),
            Arc::new(|| Some("wlan1: 0000   49.  -61.  -256\n".to_owned())),
            Arc::new(|| panic!("a lost job")),
        ];
        for read in readers {
            cache.set(Some(-40));
            let keeping = tokio::spawn(keep_signal(
                status.clone(),
                cache.clone(),
                SIGNAL_EVERY,
                read,
            ));
            sleep(Duration::from_secs(1)).await;
            assert_eq!(cache.get(), None);
            keeping.abort();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_signal_component_ends_only_when_the_status_has_no_sender_left() {
        let (sender, status) = watch::channel(joined());
        let cache = SignalCache::new();
        let (read, _, _) = counting_reader();
        let mut keeping = tokio::spawn(keep_signal(status, cache.clone(), SIGNAL_EVERY, read));

        // It runs on for as long as the sender is there.
        sleep(Duration::from_secs(60)).await;
        assert!(!keeping.is_finished());
        drop(sender);
        let ended = (&mut keeping).await.unwrap();

        assert_eq!(ended, Ended::Failed("the Wi-Fi status has ended".into()));
        assert_eq!(cache.get(), None, "no link, no figure");
    }

    #[tokio::test]
    async fn reading_the_signal_does_not_hold_the_runtime_thread() {
        let (_sender, status) = watch::channel(joined());
        let cache = SignalCache::new();
        // A read that takes as long as the firmware can take: 300 ms.
        let slow: WirelessReader = Arc::new(|| {
            std::thread::sleep(Duration::from_millis(300));
            Some(wireless_with(-61))
        });

        let (gap, ended) = longest_gap(tokio::time::timeout(
            Duration::from_millis(500),
            keep_signal(status, cache.clone(), SIGNAL_EVERY, slow),
        ))
        .await;

        assert!(ended.is_err(), "the component does not end");
        assert_eq!(cache.get(), Some(-61), "the read was done");
        assert!(gap < Duration::from_millis(100), "{gap:?}");
    }

    #[test]
    fn the_signal_is_an_essential_component_of_its_own() {
        let (_sender, status) = watch::channel(wifi::WifiStatus::Starting);

        let component = signal_component(status, SignalCache::new());

        assert_eq!((component.name, component.essential), ("signal", true));
    }

    // Final fix I1
    #[test]
    fn the_link_reader_serves_the_cached_signal_and_reads_no_file() {
        let (sender, status) = watch::channel(joined());
        let cache = SignalCache::new();
        let link = link_reader(status, cache.clone());

        // The join's own figure, -56, until the component has a better one.
        assert_eq!(link().signal_dbm, Some(-56));
        // The cached figure, whatever the kernel's file says on this machine.
        cache.set(Some(-50));
        let shown = link();
        assert!(shown.associated);
        assert_eq!(shown.signal_dbm, Some(-50));
        assert_eq!(shown.ap.as_deref(), Some("00:00:5e:00:53:01"));
        // Not joined: no signal, and no access point, whatever the cache holds.
        sender.send_replace(wifi::WifiStatus::Scanning);
        assert_eq!(link(), live::WifiStatus::default());
    }

    /// The wire form of the answer "no such name" to a question for `name`, type A.
    fn nxdomain_reply(name: &str) -> Vec<u8> {
        let mut out = vec![0x12, 0x34, 0x81, 0x83, 0, 1, 0, 0, 0, 0, 0, 0];
        out.extend_from_slice(&crate::watch::wire_of(name));
        out.extend_from_slice(&[0, 1, 0, 1]);
        out
    }

    /// The `n`th name of a family of 400 names under `.com` that look random.
    fn random_name(n: usize) -> String {
        const CONSONANTS: &[u8] = b"bcdfghjklmnpqrstvwxz";
        format!(
            "qxzkvbtw{}{}.com",
            char::from(CONSONANTS[n / 20]),
            char::from(CONSONANTS[n % 20])
        )
    }

    #[tokio::test]
    async fn the_resolver_has_a_watch_once_the_state_is_made_and_the_analysis_holds_its_feed() {
        let (ctx, _slot, _sender) = context();
        let lazy = Lazy::new(ctx, "/nonexistent/blocklist.zst".into());
        let client = std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));

        let shared = lazy.get().await;
        shared
            .dns
            .observe(client, &nxdomain_reply("one.example.org"));

        // The answer is an event in the feed that the analysis takes, and nothing was dropped.
        assert_eq!(shared.dns.watch_events_dropped(), 0);
        let (events, _behaviour) = shared.analysis.lock().unwrap().take().unwrap();
        let event = events.try_recv().unwrap();
        assert_eq!((event.client, event.rcode), (client, 3));
        assert!(events.try_recv().is_err());
        // The feed is the resolver's: with the receiver gone, the next answer is a drop.
        drop(events);
        shared
            .dns
            .observe(client, &nxdomain_reply("two.example.org"));
        assert_eq!(shared.dns.watch_events_dropped(), 1);
    }

    #[tokio::test]
    async fn the_configurations_exempt_devices_are_exempt_for_the_dns_service_once_heard() {
        use crate::watch::devices::with_devices;
        use crate::watch::frames::{Arp, Mac};

        let exempt = Mac([2, 0, 0, 0, 0, 5]);
        let (ctx, _slot, _sender) = context_edited(|cfg| cfg.watch.exempt = vec![exempt]);
        let lazy = Lazy::new(ctx, "/nonexistent/blocklist.zst".into());
        let shared = lazy.get().await;
        let addr = Ipv4Addr::new(192, 0, 2, 30);
        // Not heard yet: no address is exempt.
        assert!(shared.dns.exempt().listed().is_empty());
        assert_eq!(shared.status.stats()["exempt_clients"], 0);
        assert_eq!(shared.status.stats()["exempt_default"], false);

        let heard = |mac: Mac| Arp {
            op: 1,
            sender_mac: mac,
            sender_ip: addr,
            target_ip: Ipv4Addr::new(192, 0, 2, 1),
        };
        with_devices(&shared.devices, &*shared.alerts, |devices| {
            devices.on_arp(&heard(exempt));
        });
        assert!(shared.dns.exempt().is_exempt(addr.into()));
        assert_eq!(shared.status.stats()["exempt_clients"], 1);
        // Another device takes the address over: it is no longer exempt.
        with_devices(&shared.devices, &*shared.alerts, |devices| {
            devices.on_arp(&heard(Mac([2, 0, 0, 0, 0, 6])));
        });
        assert!(shared.dns.exempt().listed().is_empty());
        assert_eq!(shared.status.stats()["exempt_clients"], 0);
    }

    #[tokio::test]
    async fn exempt_by_default_in_the_configuration_exempts_all_but_the_block_list_and_the_router()
    {
        use crate::watch::devices::with_devices;
        use crate::watch::frames::{Arp, Mac};

        let blocked = Mac([2, 0, 0, 0, 0, 5]);
        let (ctx, _slot, _sender) = context_edited(|cfg| {
            cfg.watch.exempt_default = true;
            cfg.watch.block = vec![blocked];
            // The exempt list has no effect in this mode.
            cfg.watch.exempt = vec![Mac([2, 0, 0, 0, 0, 7])];
        });
        let lazy = Lazy::new(ctx, "/nonexistent/blocklist.zst".into());
        let shared = lazy.get().await;
        let exempt = shared.dns.exempt();
        let (gateway, own) = (shared.cfg.net.gateway, shared.cfg.net.address.addr);
        let addr = Ipv4Addr::new(192, 0, 2, 30);
        let stats = || shared.status.stats();
        assert_eq!(stats()["exempt_default"], true);
        // Nothing heard: every client is exempt but the router and the Pi, and none is counted.
        assert!(exempt.is_exempt(addr.into()));
        assert!(!exempt.is_exempt(gateway.into()) && !exempt.is_exempt(own.into()));
        assert_eq!(stats()["exempt_clients"], 0);

        let heard = |mac: Mac, ip: Ipv4Addr| Arp {
            op: 1,
            sender_mac: mac,
            sender_ip: ip,
            target_ip: gateway,
        };
        // A device that is not on the block list counts; the router that it heard does not.
        with_devices(&shared.devices, &*shared.alerts, |devices| {
            devices.on_arp(&heard(Mac([2, 0, 0, 0, 0, 6]), addr));
            devices.on_arp(&heard(Mac([2, 0, 0, 0, 0, 1]), gateway));
        });
        assert!(exempt.is_exempt(addr.into()));
        assert_eq!(stats()["exempt_clients"], 1);
        // The blocked device takes the address over: it is fully blocked at once.
        with_devices(&shared.devices, &*shared.alerts, |devices| {
            devices.on_arp(&heard(blocked, addr));
        });
        assert!(!exempt.is_exempt(addr.into()));
        assert_eq!(stats()["exempt_clients"], 0);
    }

    #[tokio::test]
    async fn the_panels_alerts_are_the_watchdogs_store_once_the_state_is_made() {
        let (ctx, slot, _sender) = context();
        // The panel is given the slot first: there is nothing to show, and an ack is dropped.
        assert!(slot.top().is_none());
        slot.ack(1);

        let lazy = Lazy::new(ctx, "/nonexistent/blocklist.zst".into());
        let shared = lazy.get().await;
        assert!(slot.top().is_none());
        shared.alerts.raise(Alert {
            kind: "dga",
            severity: Severity::Warn,
            client: None,
            subject: "qxzkvbtwab.com".to_owned(),
        });
        // The alert that the API lists is the one the panel shows, and it is acknowledged for both.
        let listed = shared.alerts.list(0).alerts;
        let top = slot.top().unwrap();
        assert_eq!((top.id, top.kind.as_str()), (listed[0].id, "dga"));
        slot.ack(top.id);
        assert!(slot.top().is_none());
        assert!(shared.alerts.list(0).alerts[0].acked);
    }

    #[tokio::test]
    async fn the_panel_reads_the_alerts_without_the_resolvers_lock() {
        let (ctx, slot, _sender) = context();
        let lazy = Lazy::new(ctx, "/nonexistent/blocklist.zst".into());
        let shared = lazy.get().await;
        shared.alerts.raise(Alert {
            kind: "dga",
            severity: Severity::High,
            client: None,
            subject: "qxzkvbtwab.com".to_owned(),
        });

        // The resolver's lock is the one the answer path takes for every query. Held here, the
        // panel's reads must still go through: they run on their own thread, which gives up the
        // wait after ten seconds and fails the test instead of hanging it.
        let resolver = shared.dns.shared();
        let held = resolver.lock().unwrap();
        let (done, finished) = std::sync::mpsc::channel();
        let panel = std::thread::spawn(move || {
            let id = slot.top().map(|alert| alert.id);
            if let Some(id) = id {
                slot.ack(id);
            }
            let _ = done.send((id, slot.top().is_none()));
        });
        let seen = finished.recv_timeout(Duration::from_secs(10));
        drop(held);
        assert_eq!(
            seen.expect("the panel's reads waited for the resolver"),
            (Some(1), true)
        );
        panel.join().unwrap();
    }

    #[tokio::test]
    async fn the_analysis_runs_on_the_first_start_and_a_second_finds_the_feed_taken() {
        let (ctx, _slot, _sender) = context();
        let lazy = Arc::new(Lazy::new(ctx, "/nonexistent/blocklist.zst".into()));
        lazy.get().await;
        let mut analysis = analysis_component(&lazy).unwrap();
        let devices = devices_component(&lazy).unwrap();
        assert_eq!((analysis.name, analysis.essential), ("analysis", false));
        assert_eq!((devices.name, devices.essential), ("devices", false));

        let first = tokio::spawn((analysis.start)());
        tokio::task::yield_now().await;
        let second = tokio::time::timeout(Duration::from_secs(1), (analysis.start)()).await;

        assert_eq!(
            second.unwrap(),
            Ended::Absent("the feed was taken by an earlier start".to_owned())
        );
        // The first goes on running.
        assert!(!first.is_finished());
        first.abort();
    }

    #[tokio::test]
    async fn answers_the_resolver_offers_come_out_as_alerts_in_the_api() {
        use crate::api::http::Request;

        let (ctx, _slot, _sender) = context_with(&api_section(), Some(leaked_pem()));
        let lazy = Arc::new(Lazy::new(ctx, "/nonexistent/blocklist.zst".into()));
        let me = Ipv4Addr::new(192, 0, 2, 7);
        let client = std::net::IpAddr::V4(me);
        let request = |method: &str, target: &str, sid: Option<&str>, body: &[u8]| Request {
            method: method.into(),
            target: target.into(),
            sid: sid.map(Into::into),
            body: body.to_vec(),
            close: false,
        };
        let json = |reply: crate::api::http::Reply| -> serde_json::Value {
            serde_json::from_slice(&reply.body).unwrap()
        };
        let analysis = analysis_component(&lazy).unwrap();
        let mut start = analysis.start;
        let running = tokio::spawn(start());

        // 25 random names that do not exist, asked by one client, as the listener offers them.
        let shared = lazy.get().await;
        for n in 0..25 {
            shared.dns.observe(client, &nxdomain_reply(&random_name(n)));
        }
        let parts = lazy.api().await.ok().unwrap();
        let login = parts.api.handle(
            &request("POST", "/api/auth", None, br#"{"password":"right"}"#),
            me,
        );
        let sid = json(login)["session"]["sid"].as_str().unwrap().to_owned();
        // The analysis drains the feed every 250 ms.
        let waited = Instant::now();
        let alerts = loop {
            let listed = json(
                parts
                    .api
                    .handle(&request("GET", "/api/qbp/alerts", Some(&sid), b""), me),
            );
            if !listed["alerts"].as_array().unwrap().is_empty() {
                break listed;
            }
            assert!(waited.elapsed() < Duration::from_secs(10), "no alert came");
            sleep(Duration::from_millis(50)).await;
        };

        assert_eq!(alerts["alerts"].as_array().unwrap().len(), 1);
        assert_eq!(alerts["alerts"][0]["kind"], "dga");
        assert_eq!(alerts["alerts"][0]["client"], "192.0.2.7");
        assert_eq!(shared.dns.watch_events_dropped(), 0);
        // The devices the API shows are the inventory that the device watch fills.
        let devices = json(
            parts
                .api
                .handle(&request("GET", "/api/qbp/devices", Some(&sid), b""), me),
        );
        assert_eq!(devices["known_list"], "waiting");
        running.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn the_resolver_is_given_the_zones_offset_again_every_minute() {
        let offset = Arc::new(AtomicI32::new(3600));
        let dns = Dns::new(
            BlockSetBuilder::new().build(),
            Upstreams::new(&[Ipv4Addr::LOCALHOST]),
            Box::new(Moving(offset.clone())),
        );
        let keeping = tokio::spawn(keep_utc_offset(dns.clone()));
        assert_eq!(dns.utc_offset(), 3600);

        offset.store(7200, Ordering::SeqCst);
        sleep(UTC_OFFSET_EVERY - Duration::from_secs(1)).await;
        assert_eq!(dns.utc_offset(), 3600, "not before the minute is out");
        sleep(Duration::from_secs(2)).await;
        assert_eq!(dns.utc_offset(), 7200);
        keeping.abort();
    }
}
