//! The simulated-radio ring: the whole Wi-Fi stack against `hostapd`, on the
//! kernel's simulated radios (`mac80211_hwsim`), inside a user and network
//! namespace of its own.
//!
//! Every radio, interface, `hostapd` and socket of a test lives in that
//! namespace, which `unshare` makes and the test binary re-enters, as
//! `testns` does for the unit tests: integration tests cannot reach it, so
//! the helper is repeated here. Nothing touches the machine's own radio.
//!
//! The tests are ignored by default. They need the module loaded, with no
//! radios of its own, and `hostapd` on the path:
//!
//! ```text
//! sudo modprobe mac80211_hwsim radios=0
//! cargo test -p qberrypi --test hwsim -- --ignored --test-threads=1
//! ```

use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use qb_wpa2::MacAddr;
use qb_wpa2::pmk::Pmk;
use qberrypi::fault;
use qberrypi::netlink::nl80211::{Nl80211, get_family, get_station, parse_family, parse_station};
use qberrypi::netlink::{MsgBuilder, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NlSocket, Route, find};
use qberrypi::sys::NetlinkProtocol;
use qberrypi::wifi::eapol::{self, LinkSocket};
use qberrypi::wifi::join::JoinCfg;
use qberrypi::wifi::kernel::KernelRadio;
use qberrypi::wifi::{self, WifiStatus};
use tokio::time::{Instant, sleep, timeout};

/// Set in the environment of the test binary that `in_namespace` starts.
const INSIDE: &str = "QBERRYPI_RING_NAMESPACE";

/// How long the whole of one test may take, outside the namespace, before it is cut off.
const TEST_LIMIT: Duration = Duration::from_secs(300);

/// The network's name, and its passphrase: example values.
const SSID: &str = "qb-hwsim";
const PASSPHRASE: &str = "example-passphrase";

/// The ethertype the data checks use: one of the IEEE ones for local experiments.
const DATA_ETHERTYPE: u16 = 0x88b5;
/// The size of the body a data check sends.
const DATA_LEN: usize = 32;
/// How long a frame may take to arrive.
const DATA_WAIT: Duration = Duration::from_secs(2);

/// How long `hostapd` may take to say the access point is up.
const AP_START: Duration = Duration::from_secs(10);

/// How often a wait looks at what it waits for.
const POLL: Duration = Duration::from_millis(50);

const BROADCAST: MacAddr = [0xff; 6];

/// The generic netlink family of the simulated radios.
const HWSIM_FAMILY: &str = "MAC80211_HWSIM";
/// Its command: make a radio.
const HWSIM_CMD_NEW_RADIO: u8 = 4;
/// Its attribute: the regulatory domain is the module's own custom one (an index; 0 is the first).
const HWSIM_ATTR_REG_CUSTOM_REG: u16 = 12;
/// Its attribute, a flag: the radio goes away when the socket that made it is closed.
const HWSIM_ATTR_DESTROY_RADIO_ON_CLOSE: u16 = 16;
/// nl80211's command: describe the interfaces.
const NL80211_CMD_GET_INTERFACE: u8 = 5;
/// nl80211's attributes: an interface's index and its name.
const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_IFNAME: u16 = 4;

// ----------------------------------------------------------------------------------------------------------------
// The namespace

/// Where scratch files go: never the shared temporary directory.
fn scratch_root() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp");
    fs::create_dir_all(&root).expect("making target/tmp");
    root
}

/// The path of the executable called `name` on `PATH`, if there is one.
fn on_path(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(name))
        .find(|path| path.is_file())
}

/// Runs `body` inside a new user and network namespace.
///
/// Outside one, this starts the test binary again under `unshare`, to run just the test called `test`; it
/// panics, showing what that run printed, unless the run passed. Without the module or `hostapd` it
/// panics at once, saying how to provide them.
fn in_namespace(test: &str, body: impl FnOnce()) {
    if std::env::var_os(INSIDE).is_some() {
        // The variable alone is no proof: a run by hand with it set would make radios and an access point
        // in the machine's own namespaces. The initial user namespace maps the whole range of ids.
        let map = fs::read_to_string("/proc/self/uid_map").unwrap_or_default();
        assert!(
            !map.is_empty() && !map.contains("4294967295"),
            "{INSIDE} is set, but this is not a user namespace of its own: the ring runs only under unshare"
        );
        body();
        return;
    }
    assert!(
        Path::new("/sys/module/mac80211_hwsim").exists(),
        "the ring needs the simulated radios: run `sudo modprobe mac80211_hwsim radios=0`, then this again"
    );
    assert!(
        on_path("hostapd").is_some(),
        "the ring needs hostapd on the path: install it (the hostapd package), then run this again"
    );

    let dir = tempfile::tempdir_in(scratch_root()).expect("a scratch directory");
    let (out_path, err_path) = (dir.path().join("stdout"), dir.path().join("stderr"));
    let mut child = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "--"])
        .arg(std::env::current_exe().expect("the path of the test binary"))
        .args(["--exact", test])
        .args(["--ignored", "--nocapture", "--test-threads=1"])
        .env(INSIDE, "1")
        .stdin(Stdio::null())
        .stdout(File::create(&out_path).expect("a file for stdout"))
        .stderr(File::create(&err_path).expect("a file for stderr"))
        .spawn()
        .expect("starting unshare");

    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("waiting for the test") {
            break Some(status);
        }
        if started.elapsed() > TEST_LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let stdout = fs::read_to_string(&out_path).unwrap_or_default();
    let stderr = fs::read_to_string(&err_path).unwrap_or_default();
    let Some(status) = status else {
        panic!(
            "{test} did not end within {} s and was killed\n--- stdout\n{stdout}\n--- stderr\n{stderr}",
            TEST_LIMIT.as_secs()
        );
    };
    assert!(
        status.success(),
        "{test} failed inside the namespace ({status}); if unshare itself was refused, this machine does not allow unprivileged user namespaces\n--- stdout\n{stdout}\n--- stderr\n{stderr}"
    );
    // A name that matches no test also exits with success, having run nothing.
    assert!(
        stdout.contains("1 passed"),
        "{test} did not run inside the namespace\n--- stdout\n{stdout}"
    );
}

/// Runs a test's steps on a runtime of its own: the production one is a later task's.
fn block_on<F: Future>(steps: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime")
        .block_on(steps)
}

// ----------------------------------------------------------------------------------------------------------------
// Radios

/// The simulated radios of one test, kept alive by the socket that made them.
struct Radios {
    /// Held so that `hwsim` does not get the port number a process's first generic netlink socket gets.
    ///
    /// The module destroys the radios a socket made when any netlink socket of any protocol that has the
    /// same port number is closed. The first socket of a protocol gets the process's id as its port number,
    /// so a route socket that opens and closes (as `KernelRadio::open` does) would take the radios with it.
    _reserve: NlSocket,
    hwsim: NlSocket,
    hwsim_family: u16,
    nl80211: Nl80211,
}

impl Radios {
    async fn open() -> Self {
        let reserve = NlSocket::open(NetlinkProtocol::Generic).expect("a netlink socket");
        let mut hwsim = NlSocket::open(NetlinkProtocol::Generic).expect("a netlink socket");
        let replies = hwsim
            .request(get_family(HWSIM_FAMILY))
            .await
            .expect("looking up the simulated radios' family");
        let hwsim_family = replies
            .iter()
            .find_map(|reply| parse_family(reply))
            .expect("the simulated radios' family")
            .id;
        Self {
            _reserve: reserve,
            hwsim,
            hwsim_family,
            nl80211: Nl80211::open().await.expect("nl80211"),
        }
    }

    /// The wireless interfaces of this namespace, by index and name.
    async fn interfaces(&mut self) -> Vec<(u32, String)> {
        let request = MsgBuilder::new(self.nl80211.family(), NLM_F_REQUEST | NLM_F_DUMP).header(&[
            NL80211_CMD_GET_INTERFACE,
            0,
            0,
            0,
        ]);
        let replies = self.nl80211.request(request).await.expect("the interfaces");
        replies
            .iter()
            .filter_map(|payload| {
                let body = payload.get(4..)?;
                let index = find(body, NL80211_ATTR_IFINDEX)?.u32()?;
                let name = find(body, NL80211_ATTR_IFNAME)?.str()?;
                Some((index, name.to_owned()))
            })
            .collect()
    }

    /// Makes a radio, and returns the name of its interface: the one that was not listed before.
    ///
    /// Every radio gets the module's first custom regulatory domain: 2.4 GHz channels 1 to 13 and the 5 GHz
    /// channels 36 to 48 and 149 to 165, with no restrictions. Under the world's domain an access point may
    /// not beacon on the 5 GHz channels, and a scan visits the 6 GHz band's channels too, which takes the
    /// simulated radio 12 s where this takes 3.
    async fn new_radio(&mut self) -> String {
        let before = self.interfaces().await;
        let request = MsgBuilder::new(self.hwsim_family, NLM_F_REQUEST | NLM_F_ACK)
            .header(&[HWSIM_CMD_NEW_RADIO, 1, 0, 0])
            .attr_flag(HWSIM_ATTR_DESTROY_RADIO_ON_CLOSE)
            .attr_u32(HWSIM_ATTR_REG_CUSTOM_REG, 0);
        // The kernel's acknowledgement carries the new radio's number, which nothing here needs.
        self.hwsim
            .request(request)
            .await
            .expect("the kernel refused a simulated radio");
        let new: Vec<_> = self
            .interfaces()
            .await
            .into_iter()
            .filter(|interface| !before.contains(interface))
            .collect();
        assert_eq!(new.len(), 1, "one new interface expected, found {new:?}");
        new.into_iter().next().expect("one interface").1
    }
}

// ----------------------------------------------------------------------------------------------------------------
// Access points

/// How an access point is set up, beyond what every test shares.
#[derive(Clone, Copy)]
struct ApConf {
    /// `g` for 2.4 GHz, `a` for 5 GHz.
    hw_mode: &'static str,
    channel: u32,
    /// Seconds between group rekeys, if the access point is to rekey at all.
    group_rekey: Option<u32>,
}

impl ApConf {
    const BAND_2_4: Self = Self {
        hw_mode: "g",
        channel: 1,
        group_rekey: None,
    };

    const BAND_5: Self = Self {
        hw_mode: "a",
        channel: 36,
        group_rekey: None,
    };

    fn with_group_rekey(self, secs: u32) -> Self {
        Self {
            group_rekey: Some(secs),
            ..self
        }
    }

    fn render(&self, ifname: &str) -> String {
        let mut text = format!(
            "interface={ifname}\ndriver=nl80211\nssid={SSID}\nhw_mode={}\nchannel={}\nwpa=2\n\
             wpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\nwpa_passphrase={PASSPHRASE}\n",
            self.hw_mode, self.channel
        );
        if let Some(secs) = self.group_rekey {
            writeln!(text, "wpa_group_rekey={secs}").expect("writing to a string");
        }
        text
    }
}

/// What every `hostapd` of a test has printed.
type Output = Arc<Mutex<String>>;

fn text_of(output: &Output) -> String {
    output
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// Copies what `reader` yields, line by line, to the end of `output`.
fn pump(reader: impl Read + Send + 'static, output: Output) {
    std::thread::spawn(move || {
        for line in BufReader::new(reader).lines().map_while(Result::ok) {
            let mut text = output.lock().unwrap_or_else(PoisonError::into_inner);
            text.push_str(&line);
            text.push('\n');
        }
    });
}

/// A `hostapd` child, killed when this is dropped.
struct Ap {
    child: Child,
    ifname: String,
    output: Output,
    /// How many times `hostapd` had said this interface's access point was up before this one started.
    enabled_before: usize,
}

impl Ap {
    /// The line with which `hostapd` says that the access point of `ifname` is up.
    fn enabled_line(ifname: &str) -> String {
        format!("{ifname}: AP-ENABLED")
    }

    /// Starts `hostapd` on `ifname`, with its configuration file in `dir`, and its output going to `output`.
    fn start(dir: &Path, ifname: &str, conf: &ApConf, output: &Output) -> Self {
        let path = dir.join(format!("{ifname}.conf"));
        fs::write(&path, conf.render(ifname)).expect("writing the hostapd configuration");
        let enabled_before = text_of(output).matches(&Self::enabled_line(ifname)).count();
        let mut child = Command::new("hostapd")
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("starting hostapd");
        pump(
            child.stdout.take().expect("hostapd's stdout"),
            output.clone(),
        );
        pump(
            child.stderr.take().expect("hostapd's stderr"),
            output.clone(),
        );
        Self {
            child,
            ifname: ifname.to_owned(),
            output: output.clone(),
            enabled_before,
        }
    }

    /// Waits until `hostapd` says the access point is up; panics if it ends first, or takes too long.
    async fn wait_enabled(&mut self) {
        let line = Self::enabled_line(&self.ifname);
        let deadline = Instant::now() + AP_START;
        loop {
            let output = text_of(&self.output);
            if output.matches(&line).count() > self.enabled_before {
                return;
            }
            if let Some(status) = self.child.try_wait().expect("asking hostapd's state") {
                panic!("hostapd ended ({status}) before the access point was up:\n{output}");
            }
            assert!(
                Instant::now() < deadline,
                "no AP-ENABLED from hostapd within {} s:\n{output}",
                AP_START.as_secs()
            );
            sleep(POLL).await;
        }
    }

    /// Ends `hostapd`, and waits for it to be gone.
    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Ap {
    fn drop(&mut self) {
        self.kill();
    }
}

// ----------------------------------------------------------------------------------------------------------------
// The station, and what the test sees of it

/// The statuses `wifi::run` has reported, in order. Shared with the report callback, which is `Send`.
#[derive(Clone, Default)]
struct Statuses(Arc<Mutex<Vec<WifiStatus>>>);

impl Statuses {
    fn list(&self) -> std::sync::MutexGuard<'_, Vec<WifiStatus>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn push(&self, status: WifiStatus) {
        self.list().push(status);
    }

    fn len(&self) -> usize {
        self.list().len()
    }

    fn all(&self) -> Vec<WifiStatus> {
        self.list().clone()
    }

    /// The first `Joined` among the statuses from the `from`th on: the access point and its frequency.
    fn joined_since(&self, from: usize) -> Option<(MacAddr, u32)> {
        self.list()
            .iter()
            .skip(from)
            .find_map(|status| match status {
                WifiStatus::Joined {
                    bssid, freq_mhz, ..
                } => Some((*bssid, *freq_mhz)),
                _ => None,
            })
    }
}

/// What a test has to show when it fails: the statuses, the log of the Wi-Fi code and what `hostapd` said.
struct Env {
    radios: Radios,
    dir: tempfile::TempDir,
    output: Output,
    statuses: Statuses,
    log: &'static Mutex<qberrypi::logbuf::LogBuf>,
}

impl Env {
    async fn new() -> Self {
        Self {
            // The log macros do nothing until a logger is installed; the buffer is what the tests read.
            log: qberrypi::logbuf::install(Box::new(std::io::sink())),
            radios: Radios::open().await,
            dir: tempfile::tempdir_in(scratch_root()).expect("a scratch directory"),
            output: Output::default(),
            statuses: Statuses::default(),
        }
    }

    /// Starts an access point on `ifname` and waits until it is up.
    async fn access_point(&self, ifname: &str, conf: &ApConf) -> Ap {
        let mut ap = Ap::start(self.dir.path(), ifname, conf, &self.output);
        ap.wait_enabled().await;
        ap
    }

    /// Everything the Wi-Fi code has logged.
    fn log_text(&self) -> String {
        self.log
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .text()
    }

    /// Panics with `what` and everything there is to see, unless `ok`.
    fn require(&self, ok: bool, what: &str) {
        assert!(
            ok,
            "{what}\n--- statuses\n{:#?}\n--- the log\n{}\n--- hostapd\n{}",
            self.statuses.all(),
            self.log_text(),
            text_of(&self.output)
        );
    }

    /// Waits up to `limit` for `done`, which is asked every `POLL`.
    async fn until(&self, limit: Duration, what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + limit;
        loop {
            if done() {
                return;
            }
            self.require(
                Instant::now() < deadline,
                &format!("not {what} within {} s", limit.as_secs()),
            );
            sleep(POLL).await;
        }
    }

    /// Waits up to `limit` for the station to be joined, with a `Joined` reported after the `from`th status;
    /// returns the access point and its frequency.
    async fn joined(&self, limit: Duration, from: usize) -> (MacAddr, u32) {
        self.until(limit, "joined", || {
            self.statuses.joined_since(from).is_some()
        })
        .await;
        self.statuses.joined_since(from).expect("joined")
    }
}

/// Runs the station, on `sta_if` with the key `passphrase` gives, alongside `session`, until `session` ends.
async fn with_station<T>(
    env: &Env,
    sta_if: &str,
    passphrase: &str,
    session: impl Future<Output = T>,
) -> T {
    let mut radio = KernelRadio::open(sta_if)
        .await
        .expect("opening the station's interface");
    let cfg = JoinCfg {
        ssid: SSID.as_bytes().to_vec(),
        pmk: Pmk::from_passphrase(passphrase, SSID.as_bytes()).expect("a key from the passphrase"),
        hint_mhz: Vec::new(),
    };
    let statuses = env.statuses.clone();
    let mut report = move |status| statuses.push(status);
    let out = tokio::select! {
        never = wifi::run(&mut radio, &cfg, &mut report) => match never {},
        out = session => out,
    };
    // Shown only when the test is run by hand or fails: the namespace's output is kept until then.
    eprintln!("--- the log\n{}", env.log_text());
    out
}

// ----------------------------------------------------------------------------------------------------------------
// Data

/// A raw socket on one interface, for the data checks, and the interface's address.
struct Port {
    socket: LinkSocket,
    mac: MacAddr,
}

impl Port {
    async fn open(ifname: &str) -> Self {
        let link = Route::open()
            .expect("a route socket")
            .link(ifname)
            .await
            .expect("asking for the link")
            .expect("the interface");
        Self {
            socket: LinkSocket::open(link.index, DATA_ETHERTYPE).expect("a packet socket"),
            mac: link.mac,
        }
    }
}

/// Whether a 32-byte body sent from `from` to the address `to_mac` arrives at `to` within 2 s.
async fn passes(from: &Port, to: &Port, to_mac: MacAddr) -> bool {
    // A body of its own, so that a frame left over from an earlier check is not taken for this one.
    static COUNTER: AtomicU8 = AtomicU8::new(1);
    let body = [COUNTER.fetch_add(1, Ordering::Relaxed); DATA_LEN];
    from.socket
        .send(&eapol::build(to_mac, from.mac, DATA_ETHERTYPE, &body))
        .expect("sending a data frame");
    timeout(DATA_WAIT, async {
        loop {
            let frame = to.socket.recv().await.expect("reading a data frame");
            if let Some(frame) = eapol::parse(&frame)
                && frame.src == from.mac
                && frame.dst == to_mac
                && frame.ethertype == DATA_ETHERTYPE
                && frame.body.starts_with(&body)
            {
                return;
            }
        }
    })
    .await
    .is_ok()
}

/// Whether nothing is waiting at `port`: it heard no frame of its own, and none twice.
async fn silent(port: &Port) -> bool {
    timeout(Duration::from_millis(200), port.socket.recv())
        .await
        .is_err()
}

// ----------------------------------------------------------------------------------------------------------------
// The tests

#[test]
#[ignore = "needs mac80211_hwsim (sudo modprobe mac80211_hwsim radios=0) and hostapd; run: cargo test -p qberrypi --test hwsim -- --ignored --test-threads=1"]
fn joins_and_passes_data_both_ways() {
    in_namespace("joins_and_passes_data_both_ways", || {
        block_on(async {
            let mut env = Env::new().await;
            let ap_if = env.radios.new_radio().await;
            let sta_if = env.radios.new_radio().await;
            let _ap = env.access_point(&ap_if, &ApConf::BAND_2_4).await;
            with_station(&env, &sta_if, PASSPHRASE, async {
                let (bssid, _) = env.joined(Duration::from_secs(20), 0).await;
                let station = Port::open(&sta_if).await;
                let access_point = Port::open(&ap_if).await;
                env.require(bssid == access_point.mac, "joined another access point");
                env.require(
                    passes(&station, &access_point, bssid).await,
                    "a frame from the station to the BSSID did not arrive",
                );
                env.require(
                    passes(&access_point, &station, station.mac).await,
                    "a frame from the access point to the station did not arrive",
                );
                env.require(
                    passes(&access_point, &station, BROADCAST).await,
                    "a broadcast from the access point did not arrive",
                );
                env.require(
                    silent(&station).await && silent(&access_point).await,
                    "a socket heard a frame of its own, or one twice",
                );
            })
            .await;
        });
    });
}

#[test]
#[ignore = "needs mac80211_hwsim (sudo modprobe mac80211_hwsim radios=0) and hostapd; run: cargo test -p qberrypi --test hwsim -- --ignored --test-threads=1"]
fn a_group_rekey_keeps_broadcast_working() {
    in_namespace("a_group_rekey_keeps_broadcast_working", || {
        block_on(async {
            let mut env = Env::new().await;
            let ap_if = env.radios.new_radio().await;
            let sta_if = env.radios.new_radio().await;
            let conf = ApConf::BAND_2_4.with_group_rekey(3);
            let _ap = env.access_point(&ap_if, &conf).await;
            with_station(&env, &sta_if, PASSPHRASE, async {
                env.joined(Duration::from_secs(20), 0).await;
                let reported = env.statuses.len();
                let station = Port::open(&sta_if).await;
                let access_point = Port::open(&ap_if).await;
                sleep(Duration::from_secs(5)).await;
                env.require(
                    passes(&access_point, &station, BROADCAST).await,
                    "a broadcast after the rekeys did not arrive",
                );
                env.require(
                    env.statuses.len() == reported,
                    "a status was reported after the join",
                );
                let installed = env.log_text().matches("wifi: group key").count();
                env.require(
                    installed >= 2,
                    &format!("the group key was installed {installed} times, not at least twice"),
                );
            })
            .await;
        });
    });
}

#[test]
#[ignore = "needs mac80211_hwsim (sudo modprobe mac80211_hwsim radios=0) and hostapd; run: cargo test -p qberrypi --test hwsim -- --ignored --test-threads=1"]
fn rejoins_when_the_access_point_comes_back() {
    in_namespace("rejoins_when_the_access_point_comes_back", || {
        block_on(async {
            let mut env = Env::new().await;
            let ap_if = env.radios.new_radio().await;
            let sta_if = env.radios.new_radio().await;
            let mut ap = env.access_point(&ap_if, &ApConf::BAND_2_4).await;
            with_station(&env, &sta_if, PASSPHRASE, async {
                env.joined(Duration::from_secs(20), 0).await;
                let reported = env.statuses.len();

                ap.kill();
                env.until(Duration::from_secs(30), "told the link was lost", || {
                    env.statuses.len() > reported
                })
                .await;

                let reported = env.statuses.len();
                let _ap = env.access_point(&ap_if, &ApConf::BAND_2_4).await;
                env.joined(Duration::from_secs(90), reported).await;
                let station = Port::open(&sta_if).await;
                let access_point = Port::open(&ap_if).await;
                env.require(
                    passes(&station, &access_point, access_point.mac).await,
                    "a frame from the station to the BSSID did not arrive after the rejoin",
                );
                env.require(
                    passes(&access_point, &station, station.mac).await,
                    "a frame from the access point to the station did not arrive after the rejoin",
                );
            })
            .await;
        });
    });
}

#[test]
#[ignore = "needs mac80211_hwsim (sudo modprobe mac80211_hwsim radios=0) and hostapd; run: cargo test -p qberrypi --test hwsim -- --ignored --test-threads=1"]
fn a_wrong_passphrase_never_joins() {
    in_namespace("a_wrong_passphrase_never_joins", || {
        block_on(async {
            let mut env = Env::new().await;
            let ap_if = env.radios.new_radio().await;
            let sta_if = env.radios.new_radio().await;
            let _ap = env.access_point(&ap_if, &ApConf::BAND_2_4).await;
            with_station(&env, &sta_if, "wrong-passphrase", async {
                sleep(Duration::from_secs(20)).await;
                env.require(
                    env.statuses.joined_since(0).is_none(),
                    "joined with the wrong passphrase",
                );
                let log = env.log_text();
                env.require(
                    log.contains("wifi: the passphrase may be wrong"),
                    "the log never suspected the passphrase",
                );
                let attempts = log.matches("wifi: connecting to").count();
                env.require(
                    attempts >= 2,
                    &format!("{attempts} attempts to connect, not at least two"),
                );
            })
            .await;
        });
    });
}

#[test]
#[ignore = "needs mac80211_hwsim (sudo modprobe mac80211_hwsim radios=0) and hostapd; run: cargo test -p qberrypi --test hwsim -- --ignored --test-threads=1"]
fn prefers_the_5_ghz_radio() {
    in_namespace("prefers_the_5_ghz_radio", || {
        block_on(async {
            let mut env = Env::new().await;
            let ap_2_4 = env.radios.new_radio().await;
            let ap_5 = env.radios.new_radio().await;
            let sta_if = env.radios.new_radio().await;
            let _ap_2_4 = env.access_point(&ap_2_4, &ApConf::BAND_2_4).await;
            let _ap_5 = env.access_point(&ap_5, &ApConf::BAND_5).await;
            with_station(&env, &sta_if, PASSPHRASE, async {
                let (_, freq_mhz) = env.joined(Duration::from_secs(20), 0).await;
                env.require(
                    freq_mhz == 5180,
                    &format!("joined on {freq_mhz} MHz, not 5180"),
                );
            })
            .await;
        });
    });
}

#[test]
#[ignore = "needs mac80211_hwsim (sudo modprobe mac80211_hwsim radios=0) and hostapd; run: cargo test -p qberrypi --test hwsim -- --ignored --test-threads=1"]
fn a_held_link_answers_the_stations_query_and_is_never_lost() {
    in_namespace(
        "a_held_link_answers_the_stations_query_and_is_never_lost",
        || {
            block_on(async {
                let mut env = Env::new().await;
                let ap_if = env.radios.new_radio().await;
                let sta_if = env.radios.new_radio().await;
                let _ap = env.access_point(&ap_if, &ApConf::BAND_2_4).await;
                with_station(&env, &sta_if, PASSPHRASE, async {
                    let (bssid, _) = env.joined(Duration::from_secs(20), 0).await;
                    let reported = env.statuses.len();

                    // The query the hold's probe makes, by hand against the real kernel: the access point the
                    // station is joined to is answered with a station message that holds its address, and an
                    // address the radio has no station for is refused.
                    let index = Route::open()
                        .expect("a route socket")
                        .link(&sta_if)
                        .await
                        .expect("asking for the link")
                        .expect("the interface")
                        .index;
                    let mut nl = Nl80211::open().await.expect("nl80211");
                    let family = nl.family();
                    let replies = nl
                        .request(get_station(family, index, bssid))
                        .await
                        .expect("the station query for the access point");
                    env.require(
                        replies.iter().any(|reply| parse_station(reply) == Some(bssid)),
                        "the answer to the station query holds no station message for the access point",
                    );
                    let stranger = [0x02, 0, 0, 0, 0, 0x99];
                    let error = nl
                        .request(get_station(family, index, stranger))
                        .await
                        .expect_err("the station query for an address that is no station");
                    env.require(
                        error.errno() == Some(libc::ENOENT),
                        &format!("an unknown station was answered with {error}, not ENOENT"),
                    );

                    // Longer than three probes (one every 10 s): had the kernel refused them, the hold would
                    // have given the link up by now.
                    sleep(Duration::from_secs(35)).await;
                    let log = env.log_text();
                    env.require(
                        env.statuses.len() == reported && !log.contains("wifi: link lost"),
                        "the link was lost while the radio was answering",
                    );
                    env.require(
                        !log.contains("did not answer a probe"),
                        "a probe of the held link failed",
                    );
                })
                .await;
            });
        },
    );
}

#[test]
#[ignore = "needs mac80211_hwsim (sudo modprobe mac80211_hwsim radios=0) and hostapd; run: cargo test -p qberrypi --test hwsim -- --ignored --test-threads=1"]
fn a_link_the_station_drops_itself_is_lost_and_joined_again() {
    in_namespace(
        "a_link_the_station_drops_itself_is_lost_and_joined_again",
        || {
            block_on(async {
                let mut env = Env::new().await;
                let ap_if = env.radios.new_radio().await;
                let sta_if = env.radios.new_radio().await;
                let _ap = env.access_point(&ap_if, &ApConf::BAND_2_4).await;
                with_station(&env, &sta_if, PASSPHRASE, async {
                    env.joined(Duration::from_secs(20), 0).await;
                    let reported = env.statuses.len();

                    // What the `drop-link` fault does, at once: the station leaves its own network, over
                    // sockets of its own, and tells the Wi-Fi task nothing. The task hears the kernel's
                    // disconnect event like the loss of an access point.
                    fault::drop_link(&sta_if)
                        .await
                        .expect("dropping the link of the station");
                    env.until(Duration::from_secs(30), "told the link was lost", || {
                        env.statuses.len() > reported
                    })
                    .await;
                    env.require(
                        !matches!(
                            env.statuses.all().get(reported),
                            Some(WifiStatus::Joined { .. })
                        ),
                        "the first status after the drop was a join",
                    );

                    // The next join is a rejoin, and the data flows again.
                    env.joined(Duration::from_secs(90), reported).await;
                    let log = env.log_text();
                    env.require(
                        log.contains("wifi: link lost"),
                        "the log never said the link was lost",
                    );
                    let station = Port::open(&sta_if).await;
                    let access_point = Port::open(&ap_if).await;
                    env.require(
                        passes(&station, &access_point, access_point.mac).await,
                        "a frame from the station to the BSSID did not arrive after the rejoin",
                    );
                    env.require(
                        passes(&access_point, &station, station.mac).await,
                        "a frame from the access point to the station did not arrive after the rejoin",
                    );
                })
                .await;
            });
        },
    );
}
