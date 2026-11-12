//! Parses and validates `qberrypi.toml`, the system's one configuration file.
//!
//! Every error names the offending key and states the rule it broke. No error
//! ever repeats a value from the file, so a mistyped passphrase cannot end up
//! in a log.

use std::fmt;
use std::net::Ipv4Addr;
use std::ops::{Range, RangeInclusive};

use qb_dns::name::{MAX_NAME_LEN, normalize};
use qb_panel::Calibration;
use rustls::pki_types::ServerName;
use toml::{Table, Value};
use tz::{TimeZone, TimeZoneSettings};

use crate::api::password::PasswordHash;
use crate::panel::touch::RAW_MAX;

const DEFAULT_HOSTNAME: &str = "qberrypi";

/// The time servers a file without `net.time_servers` gets.
pub const DEFAULT_TIME_SERVERS: [&str; 2] = ["time.cloudflare.com", "time.google.com"];

/// The most time servers a file may list.
const MAX_TIME_SERVERS: usize = 4;

/// The names that `watch.rebind_allow` holds in a file that does not set it: Plex's, whose names
/// answer private addresses by design.
pub const DEFAULT_REBIND_ALLOW: [&str; 1] = ["plex.direct"];

/// The validated contents of `qberrypi.toml`.
#[derive(Debug)]
pub struct Config {
    /// Name the system gives itself on the network.
    pub hostname: String,
    /// The zone the statistics' days are counted in; UTC when the file does not say.
    pub timezone: TimeZoneRule,
    /// Which wireless network to join, and how.
    pub wifi: Wifi,
    /// The static IPv4 address and route.
    pub net: Net,
    /// Upstream resolvers and blocking rules.
    pub dns: Dns,
    /// How the upstream resolvers are asked: the optional `[upstream]` table.
    pub upstream: UpstreamCfg,
    /// Switches that trade memory or a core for speed: the optional `[speed]` table.
    pub speed: SpeedCfg,
    /// How the touch screen's readings lie on the screen.
    pub panel: PanelCfg,
    /// Switches used while bringing the system up.
    pub debug: DebugCfg,
    /// What the watchdog is told to leave alone.
    pub watch: WatchCfg,
    /// The Pi-hole API on port 443; `None` when the file has no `[api]` section, and then there is
    /// none.
    pub api: Option<Api>,
}

/// The wireless network to join.
#[derive(Debug)]
pub struct Wifi {
    /// Network name.
    pub ssid: String,
    /// The secret that authenticates to the network.
    pub key: WifiKey,
    /// Regulatory domain, as a two-letter country code.
    pub country: String,
}

/// The Wi-Fi secret, in whichever of its two forms the file gave.
#[derive(Debug)]
pub enum WifiKey {
    /// A WPA passphrase, to be stretched into a PMK.
    Passphrase(Secret),
    /// A ready-made PMK, as 64 hex digits.
    Pmk(Secret),
}

/// A string that must never be printed; `Debug` shows `<redacted>`.
pub struct Secret(String);

impl Secret {
    /// Hands out the secret itself, for the one place that needs it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// An IPv4 address together with its subnet's prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Cidr {
    /// The address.
    pub addr: Ipv4Addr,
    /// Number of leading bits that name the subnet.
    pub prefix: u8,
}

/// The static IPv4 setup.
#[derive(Debug)]
pub struct Net {
    /// This system's address and subnet.
    pub address: Ipv4Cidr,
    /// The default route's next hop.
    pub gateway: Ipv4Addr,
    /// The servers that SNTP asks for the time, in order: IPv4 addresses as written, host names
    /// normalised.
    pub time_servers: Vec<String>,
}

/// A time zone given as a POSIX `TZ` rule, such as `UTC0` or `CET-1CEST,M3.5.0,M10.5.0/3`.
///
/// The rule is all there is: no zone file is read, here or on the board, which has none.
#[derive(Debug, Clone)]
pub struct TimeZoneRule {
    zone: TimeZone,
}

impl TimeZoneRule {
    /// Coordinated universal time: the offset is 0 at every moment.
    pub fn utc() -> Self {
        Self {
            zone: TimeZone::utc(),
        }
    }

    /// Reads a POSIX `TZ` rule; `None` if `rule` is not one.
    ///
    /// A zone's name (`Europe/Berlin`), `localtime`, a `:` form and an absolute path would each
    /// name a file, so none is a rule here: the settings below have no directory and no way
    /// to read one. A daylight-saving name without the dates that start and end it
    /// (`CET-1CEST`) is not a rule either.
    pub fn parse(rule: &str) -> Option<Self> {
        let settings = TimeZoneSettings::new(&[], |_| Err("no files".into()));
        let zone = settings.parse_posix_tz(rule).ok()?;
        Some(Self { zone })
    }

    /// Local time minus UTC, in seconds, at `unix_secs`; 0 if that cannot be worked out.
    pub fn offset_at(&self, unix_secs: u64) -> i32 {
        i64::try_from(unix_secs)
            .ok()
            .and_then(|unix| self.zone.find_local_time_type(unix).ok())
            .map_or(0, |local| local.ut_offset())
    }
}

impl crate::dns::UtcOffset for TimeZoneRule {
    fn offset_at(&self, unix_secs: u64) -> i32 {
        TimeZoneRule::offset_at(self, unix_secs)
    }
}

/// DNS forwarding and blocking settings.
#[derive(Debug)]
pub struct Dns {
    /// Resolvers that queries are forwarded to.
    pub upstreams: Vec<Ipv4Addr>,
    /// URLs of the blocklists to fetch.
    pub lists: Vec<String>,
    /// Names blocked in addition to the lists.
    pub deny: Vec<String>,
    /// Names never blocked, whatever the lists say.
    pub allow: Vec<String>,
    /// URLs of the threat lists to fetch: lists whose names are malware, phishing and the like,
    /// and whose hits raise an alert. Every entry starts with `https://`; none when unset.
    pub threat_lists: Vec<String>,
    /// Whether `use-application-dns.net` gets NXDOMAIN, which tells browsers to keep their own
    /// DNS-over-HTTPS off; true when unset.
    pub doh_canary: bool,
}

/// How the upstream resolvers are asked: the optional `[upstream]` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamCfg {
    /// Whether questions go to the upstreams over DNS-over-TLS (port 853) once the clock is set;
    /// false when unset.
    pub tls: bool,
    /// The host name on the upstreams' certificates, lower-cased and without a trailing dot.
    /// Always set when `tls` is true.
    pub tls_name: Option<String>,
}

/// Switches that spend memory or a core to answer faster: the optional `[speed]` table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpeedCfg {
    /// Whether popular answers are renewed shortly before they expire; false when unset.
    pub prefetch: bool,
    /// The core, 0 to 3, that the DNS runtime thread is pinned to; `None` leaves it to the
    /// scheduler.
    pub runtime_cpu: Option<u8>,
}

/// What the watchdog is told to leave alone: the optional `[watch]` table.
///
/// Each entry is a domain name as written in the file, and stands for that name and every name
/// below it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchCfg {
    /// Names that may answer a private address without being blocked for it:
    /// [`DEFAULT_REBIND_ALLOW`] when the key is not set, and none when it is an empty list.
    pub rebind_allow: Vec<String>,
    /// Names that the behaviour alerts do not count a question for.
    pub quiet: Vec<String>,
}

impl Default for WatchCfg {
    /// What a file without a `[watch]` table says.
    fn default() -> Self {
        Self {
            rebind_allow: DEFAULT_REBIND_ALLOW.map(str::to_owned).to_vec(),
            quiet: Vec::new(),
        }
    }
}

/// How the touch screen's readings lie on the screen: the optional `[panel]` table.
///
/// Each reading is the controller's own, 0 to 4095. A side's two readings
/// differ, and the first may be the greater, for an axis that runs backwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PanelCfg {
    /// The horizontal reading at the screen's left edge.
    pub touch_left: u16,
    /// The horizontal reading at the screen's right edge.
    pub touch_right: u16,
    /// The vertical reading at the screen's top edge.
    pub touch_top: u16,
    /// The vertical reading at the screen's bottom edge.
    pub touch_bottom: u16,
    /// Whether the two readings are exchanged before anything else.
    pub touch_swap_xy: bool,
}

impl PanelCfg {
    /// What a file without a `[panel]` table says: a typical panel, unmeasured.
    ///
    /// These are the five values of `Calibration::NOMINAL`; a test holds the two lists together.
    pub const DEFAULT: PanelCfg = PanelCfg {
        touch_left: 200,
        touch_right: 3900,
        touch_top: 200,
        touch_bottom: 3900,
        touch_swap_xy: false,
    };

    /// The calibration these settings are.
    pub fn calibration(&self) -> Calibration {
        Calibration {
            swap_xy: self.touch_swap_xy,
            left: self.touch_left,
            right: self.touch_right,
            top: self.touch_top,
            bottom: self.touch_bottom,
        }
    }
}

/// Bring-up switches; all off in normal use.
#[derive(Debug)]
pub struct DebugCfg {
    /// Restore Raspberry Pi OS's `config.txt` at every boot.
    pub one_shot: bool,
    /// Append the log to a file on the boot partition.
    pub log_to_sd: bool,
    /// Restart after this many seconds; 0 means never.
    pub return_after_secs: u64,
    /// Show four crosses on the panel, and log the touch calibration that the taps on them give.
    pub calibrate_touch: bool,
    /// The failure the board provokes in itself to show how it recovers; `Fault::None` in use.
    pub fault: Fault,
}

/// A failure that `debug.fault` makes the board provoke, for watching the recovery work.
///
/// For development only: a board that provokes a failure of its own restarts, or
/// stops serving, as the failure says, and `cargo xtask deploy` refuses it as a permanent system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// No failure.
    None,
    /// The supervisor stops, and with it the watchdog's petting: the watchdog restarts the board.
    Stall,
    /// An essential component that fails each time it is started: the board restarts.
    CrashLoop,
    /// An essential component that panics: the fatal error restarts the board.
    Panic,
    /// A Wi-Fi link that never associates: the board restarts after 90 seconds.
    NoWifi,
    /// The board drops its own Wi-Fi link once, a minute after the supervisor starts, as an access
    /// point that went away would: the board follows the loss and joins again. No restart.
    DropLink,
    /// The Wi-Fi radio's liveness probe stops being answered, from a minute after the supervisor
    /// starts and for one hold of the link: the board calls the link lost and joins again. No restart.
    MuteProbe,
}

/// The Pi-hole API's settings: the optional `[api]` table.
#[derive(Debug)]
pub struct Api {
    /// What the login password must hash to; `Debug` shows `<redacted>`.
    pub password_hash: PasswordHash,
}

/// Why `qberrypi.toml` was rejected: the key at fault and the rule it broke.
#[derive(Debug)]
pub struct ConfigError {
    /// Dotted path of the key, or `(syntax)` when the file is not TOML.
    pub key: String,
    /// The rule that was broken; never contains a value from the file.
    pub reason: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "qberrypi.toml: {}: {}", self.key, self.reason)
    }
}

impl std::error::Error for ConfigError {}

/// Turns the text of `qberrypi.toml` into a validated [`Config`].
pub fn parse(text: &str) -> Result<Config, ConfigError> {
    let table: Table = text
        .parse()
        .map_err(|e: toml::de::Error| syntax_error(text, e.span()))?;
    let root = Section::open(
        "",
        &table,
        &[
            "hostname", "timezone", "wifi", "net", "dns", "upstream", "speed", "panel", "debug",
            "watch", "api",
        ],
    )?;

    let hostname = match root.string("hostname")? {
        Some(name) if is_hostname(name) => name.to_owned(),
        Some(_) => {
            return Err(root.error("hostname", "must be 1 to 63 characters from a-z, 0-9 and -"));
        }
        None => DEFAULT_HOSTNAME.to_owned(),
    };
    let timezone = match root.string("timezone")? {
        Some(rule) => {
            TimeZoneRule::parse(rule).ok_or_else(|| root.error("timezone", TIMEZONE_RULE))?
        }
        None => TimeZoneRule::utc(),
    };
    let wifi = wifi(&root.required_section("wifi", &["ssid", "passphrase", "pmk", "country"])?)?;
    let net = net(&root.required_section("net", &["address", "gateway", "time_servers"])?)?;
    let dns = dns(&root.required_section(
        "dns",
        &[
            "upstreams",
            "lists",
            "deny",
            "allow",
            "threat_lists",
            "doh_canary",
        ],
    )?)?;
    let upstream = match root.section("upstream", &["tls", "tls_name"])? {
        Some(section) => upstream(&section)?,
        None => UpstreamCfg {
            tls: false,
            tls_name: None,
        },
    };
    let speed = match root.section("speed", &["prefetch", "runtime_cpu"])? {
        Some(section) => speed(&section)?,
        None => SpeedCfg {
            prefetch: false,
            runtime_cpu: None,
        },
    };
    let panel = match root.section(
        "panel",
        &[
            "touch_left",
            "touch_right",
            "touch_top",
            "touch_bottom",
            "touch_swap_xy",
        ],
    )? {
        Some(section) => panel(&section)?,
        None => PanelCfg::DEFAULT,
    };
    let debug = match root.section(
        "debug",
        &[
            "one_shot",
            "log_to_sd",
            "return_after_secs",
            "calibrate_touch",
            "fault",
        ],
    )? {
        Some(section) => debug(&section)?,
        None => DebugCfg {
            one_shot: false,
            log_to_sd: false,
            return_after_secs: 0,
            calibrate_touch: false,
            fault: Fault::None,
        },
    };
    let watch = match root.section("watch", &["rebind_allow", "quiet"])? {
        Some(section) => watch(&section)?,
        None => WatchCfg::default(),
    };
    let api = root
        .section("api", &["password_hash"])?
        .map(|section| api(&section))
        .transpose()?;
    Ok(Config {
        hostname,
        timezone,
        wifi,
        net,
        dns,
        upstream,
        speed,
        panel,
        debug,
        watch,
        api,
    })
}

fn wifi(section: &Section) -> Result<Wifi, ConfigError> {
    let ssid = section.required_string("ssid")?;
    if !(1..=32).contains(&ssid.len()) {
        return Err(section.error("ssid", "must be 1 to 32 bytes long"));
    }
    let key = match (section.string("passphrase")?, section.string("pmk")?) {
        (Some(passphrase), None) => {
            let printable = passphrase.bytes().all(|b| (0x20..=0x7e).contains(&b));
            if !printable || !(8..=63).contains(&passphrase.len()) {
                return Err(
                    section.error("passphrase", "must be 8 to 63 printable ASCII characters")
                );
            }
            WifiKey::Passphrase(Secret(passphrase.to_owned()))
        }
        (None, Some(pmk)) => {
            if pmk.len() != 64 || !pmk.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(section.error("pmk", "must be exactly 64 hex digits"));
            }
            WifiKey::Pmk(Secret(pmk.to_owned()))
        }
        _ => return Err(error(section.path, "set exactly one of passphrase and pmk")),
    };
    let country = section.required_string("country")?;
    if country.len() != 2 || !country.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(section.error("country", "must be two upper-case letters"));
    }
    Ok(Wifi {
        ssid: ssid.to_owned(),
        key,
        country: country.to_owned(),
    })
}

fn net(section: &Section) -> Result<Net, ConfigError> {
    let address = cidr(section.required_string("address")?).ok_or_else(|| {
        section.error(
            "address",
            "must be an IPv4 address with a prefix length, a.b.c.d/p, where p is 1 to 30",
        )
    })?;
    let gateway: Ipv4Addr = section
        .required_string("gateway")?
        .parse()
        .map_err(|_| section.error("gateway", "must be an IPv4 address"))?;
    let mask = u32::MAX << (32 - address.prefix);
    let same_subnet = u32::from(gateway) & mask == u32::from(address.addr) & mask;
    if !same_subnet || gateway == address.addr {
        return Err(section.error(
            "gateway",
            "must be inside net.address's subnet and differ from the address",
        ));
    }
    Ok(Net {
        address,
        gateway,
        time_servers: time_servers(section)?,
    })
}

/// The reason a `timezone` that is no POSIX rule gets.
const TIMEZONE_RULE: &str = "must be a POSIX TZ rule such as UTC0 or CET-1CEST,M3.5.0,M10.5.0/3";

/// Reads `net.time_servers`: 1 to 4 IPv4 addresses or host names with a dot in them; the default
/// when unset.
fn time_servers(section: &Section) -> Result<Vec<String>, ConfigError> {
    let Some(entries) = section.strings("time_servers")? else {
        return Ok(DEFAULT_TIME_SERVERS.map(str::to_owned).to_vec());
    };
    let servers: Option<Vec<String>> = entries
        .into_iter()
        .map(|entry| match entry.parse::<Ipv4Addr>() {
            Ok(_) => Some(entry.to_owned()),
            // A name of one label is a local name, which the resolver answers NXDOMAIN. The
            // digits of `192.0.2` or `999.1.1.1` are no top label, and `normalize` refuses them.
            Err(_) => normalized(entry).filter(|name| name.contains('.')),
        })
        .collect();
    servers
        .filter(|servers| (1..=MAX_TIME_SERVERS).contains(&servers.len()))
        .ok_or_else(|| {
            section.error(
                "time_servers",
                "must list 1 to 4 host names or IPv4 addresses",
            )
        })
}

/// The domain name `entry` is, lower-cased and without a trailing dot; `None` if it is none.
fn normalized(entry: &str) -> Option<String> {
    let mut buf = [0; MAX_NAME_LEN];
    normalize(entry.as_bytes(), &mut buf).map(str::to_owned)
}

/// Reads `a.b.c.d/p` with `p` in 1–30.
fn cidr(text: &str) -> Option<Ipv4Cidr> {
    let (addr, prefix) = text.split_once('/')?;
    let addr = addr.parse().ok()?;
    if !prefix.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let prefix = prefix.parse().ok()?;
    (1..=30)
        .contains(&prefix)
        .then_some(Ipv4Cidr { addr, prefix })
}

fn dns(section: &Section) -> Result<Dns, ConfigError> {
    let upstreams = section
        .strings("upstreams")?
        .ok_or_else(|| section.required("upstreams"))?
        .into_iter()
        .map(|upstream| upstream.parse::<Ipv4Addr>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| section.error("upstreams", "every entry must be an IPv4 address"))?;
    if upstreams.is_empty() {
        return Err(section.error("upstreams", "must list at least one IPv4 address"));
    }
    Ok(Dns {
        upstreams,
        lists: https_urls_or_empty(section, "lists")?,
        deny: names_or_empty(section, "deny")?,
        allow: names_or_empty(section, "allow")?,
        threat_lists: https_urls_or_empty(section, "threat_lists")?,
        doh_canary: section.bool_or("doh_canary", true)?,
    })
}

/// A list of `https://` URLs, as written, or none when unset.
fn https_urls_or_empty(section: &Section, name: &str) -> Result<Vec<String>, ConfigError> {
    let urls = section.strings_or_empty(name)?;
    if urls.iter().all(|url| url.starts_with("https://")) {
        Ok(urls)
    } else {
        Err(section.error(name, "every entry must start with https://"))
    }
}

/// Reads the `[upstream]` table. `tls_name`, when given, has to be a host name whether or not
/// `tls` is on, and `tls = true` has to have one.
///
/// A host name is what the block lists take (see [`normalized`]) and also what the certificate
/// check takes: the rule for names there is stricter (a label may not start or end with a hyphen,
/// say), and a name that it refuses would otherwise be found out only when the service is built,
/// which would leave the upstreams on plain UDP with a line in the log, when the file asked for TLS.
/// It is refused here instead, where the file is.
fn upstream(section: &Section) -> Result<UpstreamCfg, ConfigError> {
    let tls = section.bool_or_false("tls")?;
    let tls_name = match section.string("tls_name")? {
        Some(name) => {
            let name = normalized(name)
                .filter(|name| ServerName::try_from(name.clone()).is_ok())
                .ok_or_else(|| section.error("tls_name", "must be a host name"))?;
            Some(name)
        }
        None => None,
    };
    if tls && tls_name.is_none() {
        return Err(section.error("tls_name", "required when upstream.tls is true"));
    }
    Ok(UpstreamCfg { tls, tls_name })
}

/// Reads the `[speed]` table.
fn speed(section: &Section) -> Result<SpeedCfg, ConfigError> {
    Ok(SpeedCfg {
        prefetch: section.bool_or_false("prefetch")?,
        runtime_cpu: section.whole_number_in("runtime_cpu", 0..=3, "must be a core from 0 to 3")?,
    })
}

/// A list of domain names, as written, or none when unset. Each entry has to pass the check
/// that the block set applies to it, so that no entry is refused later.
fn names_or_empty(section: &Section, name: &str) -> Result<Vec<String>, ConfigError> {
    let entries = section.strings_or_empty(name)?;
    if entries.iter().all(|entry| normalized(entry).is_some()) {
        Ok(entries)
    } else {
        Err(section.error(name, "every entry must be a domain name"))
    }
}

fn panel(section: &Section) -> Result<PanelCfg, ConfigError> {
    let default = PanelCfg::DEFAULT;
    let panel = PanelCfg {
        touch_left: section.reading_or("touch_left", default.touch_left)?,
        touch_right: section.reading_or("touch_right", default.touch_right)?,
        touch_top: section.reading_or("touch_top", default.touch_top)?,
        touch_bottom: section.reading_or("touch_bottom", default.touch_bottom)?,
        touch_swap_xy: section.bool_or_false("touch_swap_xy")?,
    };
    // Two edges at the same reading leave no way to tell where along the side a touch is.
    if panel.touch_left == panel.touch_right {
        return Err(section.error("touch_right", "must differ from touch_left"));
    }
    if panel.touch_top == panel.touch_bottom {
        return Err(section.error("touch_bottom", "must differ from touch_top"));
    }
    Ok(panel)
}

fn debug(section: &Section) -> Result<DebugCfg, ConfigError> {
    let return_after_secs = match section.get("return_after_secs") {
        None => 0,
        Some(value) => value
            .as_integer()
            .and_then(|secs| u64::try_from(secs).ok())
            .ok_or_else(|| {
                section.error(
                    "return_after_secs",
                    "must be a whole number of seconds, 0 or more",
                )
            })?,
    };
    Ok(DebugCfg {
        one_shot: section.bool_or_false("one_shot")?,
        log_to_sd: section.bool_or_false("log_to_sd")?,
        return_after_secs,
        calibrate_touch: section.bool_or_false("calibrate_touch")?,
        fault: fault(section)?,
    })
}

/// The `[watch]` table: two lists of names. An unset `rebind_allow` is the default, which an
/// empty list is not, and an unset `quiet` is empty.
fn watch(section: &Section) -> Result<WatchCfg, ConfigError> {
    let rebind_allow = match section.get("rebind_allow") {
        None => WatchCfg::default().rebind_allow,
        Some(_) => names_or_empty(section, "rebind_allow")?,
    };
    Ok(WatchCfg {
        rebind_allow,
        quiet: names_or_empty(section, "quiet")?,
    })
}

/// The `fault` key: one of seven words, and `none` when unset.
fn fault(section: &Section) -> Result<Fault, ConfigError> {
    const WORDS: &str =
        "must be one of none, stall, crash-loop, panic, no-wifi, drop-link, mute-probe";
    match section.get("fault") {
        None => Ok(Fault::None),
        Some(Value::String(word)) => match word.as_str() {
            "none" => Ok(Fault::None),
            "stall" => Ok(Fault::Stall),
            "crash-loop" => Ok(Fault::CrashLoop),
            "panic" => Ok(Fault::Panic),
            "no-wifi" => Ok(Fault::NoWifi),
            "drop-link" => Ok(Fault::DropLink),
            "mute-probe" => Ok(Fault::MuteProbe),
            _ => Err(section.error("fault", WORDS)),
        },
        Some(_) => Err(section.error("fault", WORDS)),
    }
}

fn api(section: &Section) -> Result<Api, ConfigError> {
    let password_hash =
        PasswordHash::parse(section.required_string("password_hash")?).ok_or_else(|| {
            section.error(
                "password_hash",
                "must be the line that cargo xtask hash-password prints",
            )
        })?;
    Ok(Api { password_hash })
}

fn is_hostname(name: &str) -> bool {
    (1..=63).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Builds an error. The reason is a fixed text, so it cannot carry a value from the file.
fn error(key: impl Into<String>, reason: &'static str) -> ConfigError {
    ConfigError {
        key: key.into(),
        reason: reason.to_owned(),
    }
}

/// Reports where the file stops being TOML, by position only: the parser's own
/// message and excerpt are dropped because they can quote the file.
fn syntax_error(text: &str, span: Option<Range<usize>>) -> ConfigError {
    let reason = match span.and_then(|span| text.get(..span.start)) {
        Some(before) => {
            let line = before.matches('\n').count() + 1;
            let column = before
                .rsplit('\n')
                .next()
                .map_or(0, |last| last.chars().count())
                + 1;
            format!("not valid TOML at line {line}, column {column}")
        }
        None => "not valid TOML".to_owned(),
    };
    ConfigError {
        key: "(syntax)".to_owned(),
        reason,
    }
}

/// One table of the file, remembering its dotted path for error messages.
struct Section<'a> {
    path: &'a str,
    table: &'a Table,
}

impl<'a> Section<'a> {
    /// Wraps a table, rejecting any key that is not in `known`.
    fn open(path: &'a str, table: &'a Table, known: &[&str]) -> Result<Self, ConfigError> {
        let section = Section { path, table };
        match table.keys().find(|key| !known.contains(&key.as_str())) {
            Some(unknown) => Err(section.error(unknown, "unknown key")),
            None => Ok(section),
        }
    }

    fn error(&self, name: &str, reason: &'static str) -> ConfigError {
        if self.path.is_empty() {
            error(name, reason)
        } else {
            error(format!("{}.{name}", self.path), reason)
        }
    }

    fn required(&self, name: &str) -> ConfigError {
        self.error(name, "required, but not set")
    }

    fn get(&self, name: &str) -> Option<&'a Value> {
        self.table.get(name)
    }

    /// A sub-table of the root; `name` is its whole path.
    fn section(&self, name: &'a str, known: &[&str]) -> Result<Option<Section<'a>>, ConfigError> {
        match self.get(name) {
            None => Ok(None),
            Some(Value::Table(table)) => Section::open(name, table, known).map(Some),
            Some(_) => Err(self.error(name, "must be a table")),
        }
    }

    fn required_section(&self, name: &'a str, known: &[&str]) -> Result<Section<'a>, ConfigError> {
        self.section(name, known)?
            .ok_or_else(|| self.required(name))
    }

    fn string(&self, name: &str) -> Result<Option<&'a str>, ConfigError> {
        match self.get(name) {
            None => Ok(None),
            Some(Value::String(text)) => Ok(Some(text)),
            Some(_) => Err(self.error(name, "must be a string")),
        }
    }

    fn required_string(&self, name: &str) -> Result<&'a str, ConfigError> {
        self.string(name)?.ok_or_else(|| self.required(name))
    }

    fn strings(&self, name: &str) -> Result<Option<Vec<&'a str>>, ConfigError> {
        let Some(value) = self.get(name) else {
            return Ok(None);
        };
        value
            .as_array()
            .and_then(|items| items.iter().map(Value::as_str).collect::<Option<Vec<_>>>())
            .map(Some)
            .ok_or_else(|| self.error(name, "must be a list of strings"))
    }

    fn strings_or_empty(&self, name: &str) -> Result<Vec<String>, ConfigError> {
        let strings = self.strings(name)?.unwrap_or_default();
        Ok(strings.into_iter().map(str::to_owned).collect())
    }

    /// A reading of the touch controller, a whole number up to `RAW_MAX`; `default` when unset.
    fn reading_or(&self, name: &str, default: u16) -> Result<u16, ConfigError> {
        match self.get(name) {
            None => Ok(default),
            Some(value) => value
                .as_integer()
                .and_then(|reading| u16::try_from(reading).ok())
                .filter(|&reading| reading <= RAW_MAX)
                .ok_or_else(|| self.error(name, "must be a whole number from 0 to 4095")),
        }
    }

    fn bool_or_false(&self, name: &str) -> Result<bool, ConfigError> {
        self.bool_or(name, false)
    }

    /// A true or false; `default` when unset.
    fn bool_or(&self, name: &str, default: bool) -> Result<bool, ConfigError> {
        match self.get(name) {
            None => Ok(default),
            Some(Value::Boolean(flag)) => Ok(*flag),
            Some(_) => Err(self.error(name, "must be true or false")),
        }
    }

    /// A whole number within `range`, or `None` when unset. A value of another type or outside
    /// the range is an error with `reason`.
    fn whole_number_in(
        &self,
        name: &str,
        range: RangeInclusive<u8>,
        reason: &'static str,
    ) -> Result<Option<u8>, ConfigError> {
        match self.get(name) {
            None => Ok(None),
            Some(value) => value
                .as_integer()
                .and_then(|number| u8::try_from(number).ok())
                .filter(|number| range.contains(number))
                .map(Some)
                .ok_or_else(|| self.error(name, reason)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use qb_panel::Calibration;

    const EXAMPLE: &str = include_str!("../../../qberrypi.example.toml");
    const PASSPHRASE_LINE: &str = "passphrase = \"example-passphrase\"";
    const PMK: &str = "00112233445566778899aabbccddeeff00112233445566778899AABBCCDDEEFF";

    /// The smallest file that is valid: only the required keys.
    const MINIMAL: &str = r#"
[wifi]
ssid = "example-network"
passphrase = "example-passphrase"
country = "US"

[net]
address = "192.0.2.53/24"
gateway = "192.0.2.1"

[dns]
upstreams = ["9.9.9.9"]
"#;

    /// The example with one piece of text swapped; panics if the text is absent.
    fn example_with(find: &str, replace: &str) -> String {
        assert!(EXAMPLE.contains(find), "the example has no {find:?}");
        EXAMPLE.replace(find, replace)
    }

    #[test]
    fn example_parses() {
        let c = parse(EXAMPLE).unwrap();
        assert_eq!(c.hostname, "qberrypi");
        assert_eq!(c.wifi.ssid, "example-network");
        assert!(matches!(c.wifi.key, WifiKey::Passphrase(_)));
        assert_eq!(c.net.address.prefix, 24);
        assert_eq!(
            c.net.gateway,
            "192.0.2.1".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert_eq!(c.dns.upstreams.len(), 2);
        assert_eq!(c.dns.lists.len(), 3);
        assert!(!c.debug.one_shot && !c.debug.log_to_sd && c.debug.return_after_secs == 0);
    }

    #[test]
    fn each_rule_names_its_key() {
        for (find, replace, key) in [
            ("ssid = \"example-network\"", "ssid = \"\"", "wifi.ssid"),
            ("country = \"US\"", "country = \"usa\"", "wifi.country"),
            (
                "address = \"192.0.2.53/24\"",
                "address = \"192.0.2.53\"",
                "net.address",
            ),
            (
                "gateway = \"192.0.2.1\"",
                "gateway = \"198.51.100.1\"",
                "net.gateway",
            ),
            (
                "upstreams = [\"9.9.9.9\", \"149.112.112.112\"]",
                "upstreams = []",
                "dns.upstreams",
            ),
            (
                "hostname = \"qberrypi\"",
                "hostname = \"Bad Name\"",
                "hostname",
            ),
        ] {
            assert_eq!(parse(&EXAMPLE.replace(find, replace)).unwrap_err().key, key);
        }
    }

    #[test]
    fn unknown_key_is_named() {
        assert_eq!(
            parse(&format!("{EXAMPLE}\n[extra]\nx = 1\n"))
                .unwrap_err()
                .key,
            "extra"
        );
    }

    #[test]
    fn passphrase_and_pmk_together_or_neither_is_an_error() {
        let both = example_with(
            PASSPHRASE_LINE,
            &format!("{PASSPHRASE_LINE}\npmk = \"{PMK}\""),
        );
        assert_eq!(parse(&both).unwrap_err().key, "wifi");
        let neither = example_with(PASSPHRASE_LINE, "");
        assert_eq!(parse(&neither).unwrap_err().key, "wifi");
    }

    #[test]
    fn secrets_never_leak() {
        let c = parse(EXAMPLE).unwrap();
        assert!(!format!("{c:?}").contains("example-passphrase"));
        let short = EXAMPLE.replace("example-passphrase", "short77");
        let e = parse(&short).unwrap_err();
        assert_eq!(e.key, "wifi.passphrase");
        assert!(!e.to_string().contains("short77"));
    }

    #[test]
    fn nested_unknown_key_carries_its_full_path() {
        let text = example_with("country = \"US\"", "country = \"US\"\nchannel = 6");
        assert_eq!(parse(&text).unwrap_err().key, "wifi.channel");
        let text = example_with("one_shot = false", "one_shot = false\nverbose = true");
        assert_eq!(parse(&text).unwrap_err().key, "debug.verbose");
    }

    #[test]
    fn missing_required_key_is_named_and_called_required() {
        for (find, key) in [
            ("ssid = \"example-network\"", "wifi.ssid"),
            ("country = \"US\"", "wifi.country"),
            ("address = \"192.0.2.53/24\"", "net.address"),
            ("gateway = \"192.0.2.1\"", "net.gateway"),
            (
                "upstreams = [\"9.9.9.9\", \"149.112.112.112\"]",
                "dns.upstreams",
            ),
        ] {
            let e = parse(&example_with(find, "")).unwrap_err();
            assert_eq!(e.key, key);
            assert!(e.reason.contains("required"), "{e}");
        }
    }

    #[test]
    fn missing_required_section_is_named_and_called_required() {
        for section in ["wifi", "net", "dns"] {
            let header = format!("[{section}]");
            let without = MINIMAL
                .split("\n\n")
                .filter(|block| !block.trim_start().starts_with(&header))
                .collect::<Vec<_>>()
                .join("\n\n");
            assert!(!without.contains(&header));
            let e = parse(&without).unwrap_err();
            assert_eq!(e.key, section);
            assert!(e.reason.contains("required"), "{e}");
        }
    }

    #[test]
    fn optional_keys_take_their_defaults() {
        let c = parse(MINIMAL).unwrap();
        assert_eq!(c.hostname, "qberrypi");
        assert!(c.dns.lists.is_empty() && c.dns.deny.is_empty() && c.dns.allow.is_empty());
        assert!(!c.debug.one_shot && !c.debug.log_to_sd && c.debug.return_after_secs == 0);
    }

    /// The smallest valid file with `extra` lines added to its `[dns]` table.
    fn minimal_with_dns(extra: &str) -> String {
        MINIMAL.replace(
            "upstreams = [\"9.9.9.9\"]",
            &format!("upstreams = [\"9.9.9.9\"]\n{extra}"),
        )
    }

    /// The smallest valid file followed by `tables`, whole sections of their own.
    fn minimal_with(tables: &str) -> String {
        format!("{MINIMAL}\n{tables}\n")
    }

    /// The key and reason of the error `text` gives; panics if it parses.
    fn refusal(text: &str) -> (String, String) {
        let e = parse(text).unwrap_err();
        (e.key, e.reason)
    }

    #[test]
    fn the_watchdog_keys_take_their_defaults() {
        let c = parse(MINIMAL).unwrap();
        assert!(c.dns.threat_lists.is_empty());
        assert!(c.dns.doh_canary);
        assert!(!c.upstream.tls);
        assert_eq!(c.upstream.tls_name, None);
        assert!(!c.speed.prefetch);
        assert_eq!(c.speed.runtime_cpu, None);
        // Empty sections say the same as absent ones.
        let c = parse(&minimal_with("[upstream]\n[speed]")).unwrap();
        assert!(!c.upstream.tls && c.upstream.tls_name.is_none());
        assert!(!c.speed.prefetch && c.speed.runtime_cpu.is_none());
    }

    #[test]
    fn the_watchdog_keys_are_carried_into_the_config() {
        let text = minimal_with_dns(
            "threat_lists = [\"https://lists.example.net/threats.txt\"]\ndoh_canary = false",
        ) + "\n[upstream]\ntls = true\ntls_name = \"dns.example.net\"\n\n[speed]\nprefetch = true\nruntime_cpu = 2\n";
        let c = parse(&text).unwrap();
        assert_eq!(
            c.dns.threat_lists,
            ["https://lists.example.net/threats.txt"]
        );
        assert!(!c.dns.doh_canary);
        assert!(c.upstream.tls);
        assert_eq!(c.upstream.tls_name.as_deref(), Some("dns.example.net"));
        assert!(c.speed.prefetch);
        assert_eq!(c.speed.runtime_cpu, Some(2));
    }

    #[test]
    fn threat_lists_must_be_https() {
        for entry in [
            "http://lists.example.net/threats.txt",
            "ftp://lists.example.net/threats.txt",
            "lists.example.net/threats.txt",
            "",
        ] {
            let text = minimal_with_dns(&format!(
                "threat_lists = [\"https://lists.example.net/a.txt\", \"{entry}\"]"
            ));
            assert_eq!(
                refusal(&text),
                (
                    "dns.threat_lists".to_owned(),
                    "every entry must start with https://".to_owned()
                )
            );
        }
        // The two kinds of list are checked apart: a good one in `lists` does not excuse a bad
        // threat list, and the reverse.
        let text = minimal_with_dns(
            "lists = [\"https://lists.example.net/a.txt\"]\nthreat_lists = [\"http://lists.example.net/b.txt\"]",
        );
        assert_eq!(refusal(&text).0, "dns.threat_lists");
        let text = minimal_with_dns(
            "lists = [\"http://lists.example.net/a.txt\"]\nthreat_lists = [\"https://lists.example.net/b.txt\"]",
        );
        assert_eq!(refusal(&text).0, "dns.lists");
        // Wrong types are named by key too, and never echoed.
        for value in ["\"https://lists.example.net/a.txt\"", "[1]", "5"] {
            assert_eq!(
                refusal(&minimal_with_dns(&format!("threat_lists = {value}"))),
                (
                    "dns.threat_lists".to_owned(),
                    "must be a list of strings".to_owned()
                )
            );
        }
        assert_eq!(
            refusal(&minimal_with_dns("doh_canary = \"yes\"")),
            (
                "dns.doh_canary".to_owned(),
                "must be true or false".to_owned()
            )
        );
    }

    #[test]
    fn tls_needs_a_name() {
        let error = (
            "upstream.tls_name".to_owned(),
            "required when upstream.tls is true".to_owned(),
        );
        assert_eq!(refusal(&minimal_with("[upstream]\ntls = true")), error);
        // With the name it is accepted; without `tls` the name is only stored.
        let c = parse(&minimal_with(
            "[upstream]\ntls = true\ntls_name = \"dns.quad9.net\"",
        ))
        .unwrap();
        assert!(c.upstream.tls);
        assert_eq!(c.upstream.tls_name.as_deref(), Some("dns.quad9.net"));
        let c = parse(&minimal_with("[upstream]\ntls_name = \"dns.quad9.net\"")).unwrap();
        assert!(!c.upstream.tls);
        assert_eq!(c.upstream.tls_name.as_deref(), Some("dns.quad9.net"));
        // `tls = false` needs no name.
        assert!(parse(&minimal_with("[upstream]\ntls = false")).is_ok());
        // `tls` is a boolean.
        assert_eq!(
            refusal(&minimal_with("[upstream]\ntls = \"yes\"")),
            (
                "upstream.tls".to_owned(),
                "must be true or false".to_owned()
            )
        );
    }

    #[test]
    fn tls_name_must_be_a_host_name() {
        let error = (
            "upstream.tls_name".to_owned(),
            "must be a host name".to_owned(),
        );
        for name in [
            "",
            "not a name",
            "dns.quad9.net/path",
            "dns.quad9.net:853",
            "9.9.9.9",
            "dns..quad9.net",
            ".",
        ] {
            for tls in ["true", "false"] {
                let text = minimal_with(&format!("[upstream]\ntls = {tls}\ntls_name = \"{name}\""));
                assert_eq!(refusal(&text), error, "{name:?}, tls = {tls}");
            }
        }
        // A name is a string.
        assert_eq!(
            refusal(&minimal_with("[upstream]\ntls_name = 9")),
            (
                "upstream.tls_name".to_owned(),
                "must be a string".to_owned()
            )
        );
        // It is stored the way the block set stores names: lower case, no trailing dot.
        let c = parse(&minimal_with(
            "[upstream]\ntls = true\ntls_name = \"DNS.Quad9.NET.\"",
        ))
        .unwrap();
        assert_eq!(c.upstream.tls_name.as_deref(), Some("dns.quad9.net"));
    }

    #[test]
    fn a_tls_name_that_tls_cannot_check_is_refused_not_quietly_ignored() {
        // The block list's rule takes these, and a certificate check cannot: without this the
        // service would log it and stay on plain UDP, a downgrade that the file never asked for.
        let error = (
            "upstream.tls_name".to_owned(),
            "must be a host name".to_owned(),
        );
        for name in [
            "-dns.example.org",
            "dns-.example.org",
            "dns.-example.org",
            "dns.example.org-",
        ] {
            assert!(
                normalized(name).is_some(),
                "{name:?} should pass the list rule"
            );
            for tls in ["true", "false"] {
                let text = minimal_with(&format!("[upstream]\ntls = {tls}\ntls_name = \"{name}\""));
                assert_eq!(refusal(&text), error, "{name:?}, tls = {tls}");
            }
        }
    }

    #[test]
    fn runtime_cpu_is_a_core_from_0_to_3() {
        let error = (
            "speed.runtime_cpu".to_owned(),
            "must be a core from 0 to 3".to_owned(),
        );
        for value in ["4", "-1", "\"x\"", "\"1\"", "1.0", "true", "[1]", "256"] {
            let text = minimal_with(&format!("[speed]\nruntime_cpu = {value}"));
            assert_eq!(refusal(&text), error, "{value}");
        }
        for core in 0..=3 {
            let text = minimal_with(&format!("[speed]\nruntime_cpu = {core}"));
            assert_eq!(parse(&text).unwrap().speed.runtime_cpu, Some(core));
        }
        assert_eq!(
            refusal(&minimal_with("[speed]\nprefetch = 1")),
            (
                "speed.prefetch".to_owned(),
                "must be true or false".to_owned()
            )
        );
    }

    #[test]
    fn the_new_tables_name_unknown_keys_with_their_full_path() {
        for (table, key) in [
            ("[upstream]\nverify = true", "upstream.verify"),
            (
                "[upstream]\ntls = true\ntls_name = \"dns.example.net\"\nport = 853",
                "upstream.port",
            ),
            ("[speed]\nthreads = 2", "speed.threads"),
            (
                "[speed]\nprefetch = true\nruntime_cpu = 1\ngovernor = \"x\"",
                "speed.governor",
            ),
        ] {
            assert_eq!(
                refusal(&minimal_with(table)),
                (key.to_owned(), "unknown key".to_owned())
            );
        }
        assert_eq!(
            refusal(&minimal_with_dns("threads = 2")),
            ("dns.threads".to_owned(), "unknown key".to_owned())
        );
        // A table that is not a table.
        let text = format!("upstream = 1\nspeed = 2\n{MINIMAL}");
        assert_eq!(
            refusal(&text),
            ("upstream".to_owned(), "must be a table".to_owned())
        );
        let text = format!("speed = 2\n{MINIMAL}");
        assert_eq!(
            refusal(&text),
            ("speed".to_owned(), "must be a table".to_owned())
        );
    }

    #[test]
    fn the_example_keeps_tls_and_speed_off() {
        let c = parse(EXAMPLE).unwrap();
        assert!(!c.upstream.tls);
        assert_eq!(c.upstream.tls_name.as_deref(), Some("dns.quad9.net"));
        assert!(!c.speed.prefetch);
        assert_eq!(c.speed.runtime_cpu, None);
        assert_eq!(c.dns.threat_lists.len(), 2);
        assert!(c.dns.doh_canary);
        assert_eq!(c.dns.lists.len(), 3);
        // The commented-out pin is a valid one.
        let pinned = example_with("# runtime_cpu = 1 ", "runtime_cpu = 1 ");
        assert_eq!(parse(&pinned).unwrap().speed.runtime_cpu, Some(1));
    }

    #[test]
    fn a_file_saved_on_windows_parses() {
        let text = format!("\u{feff}{}", EXAMPLE.replace('\n', "\r\n"));
        assert_eq!(parse(&text).unwrap().wifi.ssid, "example-network");
    }

    #[test]
    fn values_are_carried_into_the_config() {
        let text = example_with("deny = []", "deny = [\"ads.example\"]")
            .replace("allow = []", "allow = [\"ok.example\"]")
            .replace("one_shot = false", "one_shot = true")
            .replace("log_to_sd = false", "log_to_sd = true")
            .replace("return_after_secs = 0", "return_after_secs = 90")
            .replace("hostname = \"qberrypi\"", "hostname = \"pi-3\"");
        let c = parse(&text).unwrap();
        assert_eq!(c.hostname, "pi-3");
        assert_eq!(c.wifi.country, "US");
        assert_eq!(c.net.address.addr, std::net::Ipv4Addr::new(192, 0, 2, 53));
        assert_eq!(
            c.dns.upstreams[1],
            std::net::Ipv4Addr::new(149, 112, 112, 112)
        );
        assert!(c.dns.lists[0].starts_with("https://raw.githubusercontent.com/StevenBlack/"));
        assert_eq!(c.dns.deny, ["ads.example"]);
        assert_eq!(c.dns.allow, ["ok.example"]);
        assert!(c.debug.one_shot && c.debug.log_to_sd);
        assert_eq!(c.debug.return_after_secs, 90);
    }

    #[test]
    fn pmk_alone_is_accepted_and_stays_secret() {
        let text = example_with(PASSPHRASE_LINE, &format!("pmk = \"{PMK}\""));
        let c = parse(&text).unwrap();
        let WifiKey::Pmk(pmk) = &c.wifi.key else {
            panic!("expected a pmk");
        };
        assert_eq!(pmk.expose(), PMK);
        assert!(!format!("{c:?}").contains(PMK));
        assert!(format!("{c:?}").contains("<redacted>"));
    }

    #[test]
    fn passphrase_is_exposed_only_on_request() {
        let c = parse(EXAMPLE).unwrap();
        let WifiKey::Passphrase(passphrase) = &c.wifi.key else {
            panic!("expected a passphrase");
        };
        assert_eq!(passphrase.expose(), "example-passphrase");
        assert_eq!(format!("{passphrase:?}"), "<redacted>");
    }

    #[test]
    fn rejected_values_name_their_key_and_are_never_echoed() {
        let long_host = "h".repeat(64);
        let long_ssid = "s".repeat(33);
        let long_pass = "p".repeat(64);
        let short_pmk = &PMK[..63];
        let not_hex_pmk = PMK.replace("00", "zz");
        let cases: Vec<(&str, String, &str, &str)> = vec![
            (
                "hostname = \"qberrypi\"",
                "hostname = \"\"".into(),
                "hostname",
                "\"\"",
            ),
            (
                "hostname = \"qberrypi\"",
                format!("hostname = \"{long_host}\""),
                "hostname",
                &long_host,
            ),
            (
                "hostname = \"qberrypi\"",
                "hostname = \"under_score\"".into(),
                "hostname",
                "under_score",
            ),
            (
                "ssid = \"example-network\"",
                format!("ssid = \"{long_ssid}\""),
                "wifi.ssid",
                &long_ssid,
            ),
            (
                PASSPHRASE_LINE,
                format!("passphrase = \"{long_pass}\""),
                "wifi.passphrase",
                &long_pass,
            ),
            (
                PASSPHRASE_LINE,
                "passphrase = \"caf\u{e9}-au-lait\"".into(),
                "wifi.passphrase",
                "au-lait",
            ),
            (
                PASSPHRASE_LINE,
                "passphrase = \"tab\\tseparated\"".into(),
                "wifi.passphrase",
                "separated",
            ),
            (
                PASSPHRASE_LINE,
                format!("pmk = \"{short_pmk}\""),
                "wifi.pmk",
                short_pmk,
            ),
            (
                PASSPHRASE_LINE,
                format!("pmk = \"{not_hex_pmk}\""),
                "wifi.pmk",
                &not_hex_pmk,
            ),
            (
                "country = \"US\"",
                "country = \"us\"".into(),
                "wifi.country",
                "\"us\"",
            ),
            (
                "country = \"US\"",
                "country = \"U\"".into(),
                "wifi.country",
                "\"U\"",
            ),
            (
                "192.0.2.53/24",
                "192.0.2.53/0".into(),
                "net.address",
                "192.0.2.53",
            ),
            (
                "192.0.2.53/24",
                "192.0.2.53/31".into(),
                "net.address",
                "192.0.2.53",
            ),
            (
                "192.0.2.53/24",
                "192.0.2.53/+24".into(),
                "net.address",
                "192.0.2.53",
            ),
            (
                "192.0.2.53/24",
                "192.0.2.530/24".into(),
                "net.address",
                "192.0.2.530",
            ),
            (
                "192.0.2.53/24",
                "example.net/24".into(),
                "net.address",
                "example.net",
            ),
            (
                "gateway = \"192.0.2.1\"",
                "gateway = \"192.0.2.53\"".into(),
                "net.gateway",
                "192.0.2.53",
            ),
            (
                "gateway = \"192.0.2.1\"",
                "gateway = \"198.51.100.1\"".into(),
                "net.gateway",
                "198.51.100.1",
            ),
            (
                "gateway = \"192.0.2.1\"",
                "gateway = \"router.example\"".into(),
                "net.gateway",
                "router.example",
            ),
            (
                "\"9.9.9.9\"",
                "\"dns.example\"".into(),
                "dns.upstreams",
                "dns.example",
            ),
            (
                "https://raw.githubusercontent.com/StevenBlack",
                "http://lists.example".into(),
                "dns.lists",
                "lists.example",
            ),
            (
                "return_after_secs = 0",
                "return_after_secs = -7654".into(),
                "debug.return_after_secs",
                "7654",
            ),
        ];
        for (find, replace, key, secret) in cases {
            let e = parse(&example_with(find, &replace)).unwrap_err();
            assert_eq!(e.key, key, "{replace}");
            assert!(!e.to_string().contains(secret), "{e}");
        }
    }

    #[test]
    fn wrong_value_type_names_its_key_without_echoing_the_value() {
        for (find, replace, key, value) in [
            (
                "one_shot = false",
                "one_shot = \"yes-please\"",
                "debug.one_shot",
                "yes-please",
            ),
            (
                "log_to_sd = false",
                "log_to_sd = 1234567",
                "debug.log_to_sd",
                "1234567",
            ),
            (
                "return_after_secs = 0",
                "return_after_secs = \"soon-ish\"",
                "debug.return_after_secs",
                "soon-ish",
            ),
            (
                "return_after_secs = 0",
                "return_after_secs = 2.5",
                "debug.return_after_secs",
                "2.5",
            ),
            (
                "hostname = \"qberrypi\"",
                "hostname = 4242",
                "hostname",
                "4242",
            ),
            (
                "ssid = \"example-network\"",
                "ssid = 987654",
                "wifi.ssid",
                "987654",
            ),
            (
                PASSPHRASE_LINE,
                "passphrase = 1234567890",
                "wifi.passphrase",
                "1234567890",
            ),
            (
                "deny = []",
                "deny = \"ads.example\"",
                "dns.deny",
                "ads.example",
            ),
            (
                "allow = []",
                "allow = [\"ok.example\", 31337]",
                "dns.allow",
                "31337",
            ),
            (
                "upstreams = [\"9.9.9.9\", \"149.112.112.112\"]",
                "upstreams = \"9.9.9.9\"",
                "dns.upstreams",
                "9.9.9.9",
            ),
        ] {
            let e = parse(&example_with(find, replace)).unwrap_err();
            assert_eq!(e.key, key, "{replace}");
            assert!(!e.to_string().contains(value), "{e}");
        }
        let e = parse("wifi = \"not-a-table\"\n").unwrap_err();
        assert_eq!(e.key, "wifi");
        assert!(!e.to_string().contains("not-a-table"));
    }

    #[test]
    fn syntax_error_gives_a_position_and_never_quotes_the_file() {
        let unterminated = example_with(PASSPHRASE_LINE, "passphrase = \"example-passphrase");
        let e = parse(&unterminated).unwrap_err();
        assert_eq!(e.key, "(syntax)");
        let secret_line = EXAMPLE
            .lines()
            .position(|line| line.starts_with(PASSPHRASE_LINE))
            .unwrap()
            + 1;
        assert!(e.reason.contains(&format!("line {secret_line},")), "{e}");
        for fragment in [
            "example-passphrase",
            "example-network",
            "passphrase =",
            "\n",
            "|",
            "^",
        ] {
            assert!(!e.to_string().contains(fragment), "{e}");
        }

        let duplicate = example_with(
            PASSPHRASE_LINE,
            &format!("{PASSPHRASE_LINE}\n{PASSPHRASE_LINE}"),
        );
        let e = parse(&duplicate).unwrap_err();
        assert_eq!(e.key, "(syntax)");
        assert!(!e.to_string().contains("example-passphrase"), "{e}");
    }

    #[test]
    fn a_fault_is_one_of_seven_words_and_none_by_default() {
        assert_eq!(parse(EXAMPLE).unwrap().debug.fault, Fault::None);
        assert_eq!(parse(MINIMAL).unwrap().debug.fault, Fault::None);
        for (word, fault) in [
            ("none", Fault::None),
            ("stall", Fault::Stall),
            ("crash-loop", Fault::CrashLoop),
            ("panic", Fault::Panic),
            ("no-wifi", Fault::NoWifi),
            ("drop-link", Fault::DropLink),
            ("mute-probe", Fault::MuteProbe),
        ] {
            let text = example_with("fault = \"none\"", &format!("fault = \"{word}\""));
            assert_eq!(parse(&text).unwrap().debug.fault, fault, "{word}");
        }
        // A file that never says it is as if it said none, with or without a [debug] table.
        let without = format!("{MINIMAL}\n[debug]\none_shot = true\n");
        assert_eq!(parse(&without).unwrap().debug.fault, Fault::None);
    }

    #[test]
    fn a_fault_that_is_not_one_of_the_seven_words_is_refused_without_echoing_it() {
        for bad in ["\"fire-drill\"", "\"Stall\"", "\"\"", "7654", "true"] {
            let text = example_with("fault = \"none\"", &format!("fault = {bad}"));
            let e = parse(&text).unwrap_err();
            assert_eq!(
                (e.key.as_str(), e.reason.as_str()),
                (
                    "debug.fault",
                    "must be one of none, stall, crash-loop, panic, no-wifi, drop-link, mute-probe"
                ),
                "{bad}"
            );
            assert!(!e.to_string().contains("fire-drill"), "{e}");
        }
    }

    #[test]
    fn without_a_panel_table_the_calibration_is_the_nominal_one_and_the_switch_is_off() {
        let cfg = parse(EXAMPLE).unwrap();
        assert_eq!(
            cfg.panel,
            PanelCfg {
                touch_left: 200,
                touch_right: 3900,
                touch_top: 200,
                touch_bottom: 3900,
                touch_swap_xy: false
            }
        );
        assert!(!cfg.debug.calibrate_touch);
    }

    #[test]
    fn the_defaults_of_the_panel_table_are_the_nominal_calibration() {
        assert_eq!(PanelCfg::DEFAULT.calibration(), Calibration::NOMINAL);
        assert_eq!(parse(MINIMAL).unwrap().panel, PanelCfg::DEFAULT);
    }

    #[test]
    fn a_calibration_is_read_and_may_run_backwards() {
        let text = format!(
            "{EXAMPLE}\n[panel]\ntouch_left = 3890\ntouch_right = 210\ntouch_top = 300\ntouch_swap_xy = true\n"
        );
        let text = text.replace("calibrate_touch = false", "calibrate_touch = true");
        let cfg = parse(&text).unwrap();
        assert_eq!(
            cfg.panel,
            PanelCfg {
                touch_left: 3890,
                touch_right: 210,
                touch_top: 300,
                touch_bottom: 3900,
                touch_swap_xy: true
            }
        );
        assert!(cfg.debug.calibrate_touch);
        let c = cfg.panel.calibration();
        assert_eq!(
            (c.left, c.right, c.top, c.bottom, c.swap_xy),
            (3890, 210, 300, 3900, true)
        );
    }

    #[test]
    fn the_ends_of_the_range_of_a_reading_are_accepted() {
        let text = format!("{EXAMPLE}\n[panel]\ntouch_left = 0\ntouch_right = 4095\n");
        let cfg = parse(&text).unwrap();
        assert_eq!((cfg.panel.touch_left, cfg.panel.touch_right), (0, 4095));
    }

    #[test]
    fn a_calibration_no_panel_could_have_is_refused_by_key() {
        for (line, key) in [
            ("touch_left = 4096", "panel.touch_left"),
            ("touch_top = -1", "panel.touch_top"),
            ("touch_right = 200", "panel.touch_right"),
            ("touch_bottom = 200", "panel.touch_bottom"),
            ("touch_swap_xy = 1", "panel.touch_swap_xy"),
            ("rotate = 90", "panel.rotate"),
        ] {
            let text = format!("{EXAMPLE}\n[panel]\n{line}\n");
            assert_eq!(parse(&text).unwrap_err().key, key, "{line}");
        }
    }

    #[test]
    fn a_panel_setting_of_the_wrong_type_is_refused_without_echoing_it() {
        for (text, key, value) in [
            (
                format!("{EXAMPLE}\n[panel]\ntouch_left = \"fifty-two\"\n"),
                "panel.touch_left",
                "fifty-two",
            ),
            (
                format!("{EXAMPLE}\n[panel]\ntouch_bottom = 2.5\n"),
                "panel.touch_bottom",
                "2.5",
            ),
            (
                format!("panel = \"flat-screen\"\n{EXAMPLE}"),
                "panel",
                "flat-screen",
            ),
            (
                example_with("calibrate_touch = false", "calibrate_touch = \"maybe\""),
                "debug.calibrate_touch",
                "maybe",
            ),
        ] {
            let e = parse(&text).unwrap_err();
            assert_eq!(e.key, key);
            assert!(!e.to_string().contains(value), "{e}");
        }
    }

    #[test]
    fn error_display_names_the_file_the_key_and_the_reason() {
        let e = ConfigError {
            key: "net.gateway".into(),
            reason: "some reason".into(),
        };
        assert_eq!(e.to_string(), "qberrypi.toml: net.gateway: some reason");
    }

    const JAN: u64 = 1_768_478_400; // 2026-01-15T12:00:00Z
    const JUL: u64 = 1_784_116_800; // 2026-07-15T12:00:00Z
    const SPRING: u64 = 1_774_746_000; // 2026-03-29T01:00:00Z, when CET becomes CEST
    const RULE_ERROR: &str = "must be a POSIX TZ rule such as UTC0 or CET-1CEST,M3.5.0,M10.5.0/3";

    #[test]
    fn the_time_zone_defaults_to_utc_and_follows_its_rule() {
        assert_eq!(parse(MINIMAL).unwrap().timezone.offset_at(JUL), 0);
        let cfg = parse(&format!(
            "timezone = \"CET-1CEST,M3.5.0,M10.5.0/3\"\n{MINIMAL}"
        ))
        .unwrap();
        assert_eq!(
            (cfg.timezone.offset_at(JAN), cfg.timezone.offset_at(JUL)),
            (3600, 7200)
        );
        assert_eq!(
            (
                cfg.timezone.offset_at(SPRING - 1),
                cfg.timezone.offset_at(SPRING)
            ),
            (3600, 7200)
        );
        let west = TimeZoneRule::parse("EST5EDT,M3.2.0,M11.1.0").unwrap();
        assert_eq!(
            (west.offset_at(JAN), west.offset_at(JUL)),
            (-18_000, -14_400)
        );
        assert_eq!(
            TimeZoneRule::parse("<+0530>-5:30").unwrap().offset_at(JAN),
            19_800
        );
        assert_eq!(TimeZoneRule::utc().offset_at(JAN), 0);
    }

    #[test]
    fn a_time_zone_that_is_not_a_rule_is_refused_by_key() {
        for bad in [
            "Europe/Berlin",
            "",
            "localtime",
            ":UTC",
            "CET-1CEST",
            "garbage,,",
        ] {
            let e = parse(&format!("timezone = \"{bad}\"\n{MINIMAL}")).unwrap_err();
            assert_eq!(
                (e.key.as_str(), e.reason.as_str()),
                ("timezone", RULE_ERROR),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn time_servers_have_a_default_and_are_checked() {
        assert_eq!(
            parse(MINIMAL).unwrap().net.time_servers,
            DEFAULT_TIME_SERVERS
        );
        let with = |list: &str| {
            parse(&MINIMAL.replace(
                "gateway = \"192.0.2.1\"",
                &format!("gateway = \"192.0.2.1\"\ntime_servers = {list}"),
            ))
        };
        assert_eq!(
            with(r#"["192.0.2.123", "Time.Example.NET."]"#)
                .unwrap()
                .net
                .time_servers,
            ["192.0.2.123", "time.example.net"]
        );
        for bad in [
            "[]",
            r#"["a.example", "b.example", "c.example", "d.example", "e.example"]"#,
            r#"["not a name"]"#,
            r#"["https://example.com"]"#,
            // A name with no dot is a local one, which the resolver answers NXDOMAIN.
            r#"["ntp"]"#,
            r#"["ntp."]"#,
            r#"["time.example.net", "ntp"]"#,
            // Not an address, and no host name has a top label that is all digits.
            r#"["192.0.2"]"#,
            r#"["999.1.1.1"]"#,
        ] {
            let e = with(bad).unwrap_err();
            assert_eq!(
                (e.key.as_str(), e.reason.as_str()),
                (
                    "net.time_servers",
                    "must list 1 to 4 host names or IPv4 addresses"
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn deny_and_allow_entries_must_be_names() {
        for key in ["deny", "allow"] {
            let text = MINIMAL.replace(
                "upstreams = [\"9.9.9.9\"]",
                &format!("upstreams = [\"9.9.9.9\"]\n{key} = [\"ok.example.com\", \"not a name\"]"),
            );
            let e = parse(&text).unwrap_err();
            assert_eq!(
                (e.key, e.reason.as_str()),
                (format!("dns.{key}"), "every entry must be a domain name")
            );
        }
    }

    #[test]
    fn the_example_file_shows_the_new_keys() {
        let cfg = parse(EXAMPLE).unwrap();
        assert_eq!(
            (cfg.timezone.offset_at(JUL), cfg.net.time_servers.len()),
            (0, 2)
        );
        assert!(
            EXAMPLE.contains("timezone = \"UTC0\"")
                && EXAMPLE
                    .contains("time_servers = [\"time.cloudflare.com\", \"time.google.com\"]")
        );
    }

    #[test]
    fn without_a_watch_section_the_watchdog_has_its_defaults() {
        for text in [EXAMPLE, MINIMAL] {
            let watch = parse(text).unwrap().watch;
            assert_eq!(watch, WatchCfg::default());
            assert_eq!(watch.rebind_allow, ["plex.direct"]);
            assert!(watch.quiet.is_empty());
        }
        // A section that sets neither key says the same.
        let watch = parse(&format!("{MINIMAL}\n[watch]\n")).unwrap().watch;
        assert_eq!(watch, WatchCfg::default());
    }

    #[test]
    fn the_watch_lists_are_carried_into_the_config_and_an_empty_list_is_none() {
        let both = format!(
            "{MINIMAL}\n[watch]\nrebind_allow = [\"Router.Example.org.\", \"nas.example.net\"]\nquiet = [\"cdn.example.org\"]\n"
        );
        let watch = parse(&both).unwrap().watch;
        // The entries are as written: whoever uses them normalises them.
        assert_eq!(
            watch.rebind_allow,
            ["Router.Example.org.", "nas.example.net"]
        );
        assert_eq!(watch.quiet, ["cdn.example.org"]);
        // Only the allow list has a default, and an empty list is not unset.
        let empty = format!("{MINIMAL}\n[watch]\nrebind_allow = []\n");
        let watch = parse(&empty).unwrap().watch;
        assert!(watch.rebind_allow.is_empty() && watch.quiet.is_empty());
        let only_quiet = format!("{MINIMAL}\n[watch]\nquiet = [\"cdn.example.org\"]\n");
        let watch = parse(&only_quiet).unwrap().watch;
        assert_eq!(watch.rebind_allow, ["plex.direct"]);
        assert_eq!(watch.quiet, ["cdn.example.org"]);
    }

    #[test]
    fn watch_entries_must_be_names() {
        for key in ["rebind_allow", "quiet"] {
            let text =
                format!("{MINIMAL}\n[watch]\n{key} = [\"ok.example.com\", \"not a name\"]\n");
            let e = parse(&text).unwrap_err();
            assert_eq!(
                (e.key, e.reason.as_str()),
                (format!("watch.{key}"), "every entry must be a domain name")
            );
        }
    }

    #[test]
    fn the_watch_section_is_checked_like_the_others() {
        for (body, key, reason, value) in [
            (
                "rebind_allow = \"plex.direct\"",
                "watch.rebind_allow",
                "must be a list of strings",
                "plex.direct",
            ),
            (
                "quiet = [\"cdn.example.org\", 31337]",
                "watch.quiet",
                "must be a list of strings",
                "31337",
            ),
            (
                "quiet = true",
                "watch.quiet",
                "must be a list of strings",
                "true",
            ),
            ("allow = []", "watch.allow", "unknown key", "allow"),
            (
                "rebind = [\"example.org\"]",
                "watch.rebind",
                "unknown key",
                "example.org",
            ),
        ] {
            let e = parse(&format!("{MINIMAL}\n[watch]\n{body}\n")).unwrap_err();
            assert_eq!((e.key.as_str(), e.reason.as_str()), (key, reason), "{body}");
            // The reason never repeats a value of the file.
            assert!(!e.reason.contains(value), "{e}");
        }
        let e = parse(&format!("watch = 1\n{MINIMAL}")).unwrap_err();
        assert_eq!(
            (e.key.as_str(), e.reason.as_str()),
            ("watch", "must be a table")
        );
    }

    #[test]
    fn the_commented_watch_section_of_the_example_is_a_valid_one() {
        let block = "# [watch]\n# rebind_allow = [\"plex.direct\"]\n# quiet = []";
        assert!(
            EXAMPLE.contains(block),
            "the example has no commented [watch] block"
        );
        let on = EXAMPLE.replace(
            block,
            "[watch]\nrebind_allow = [\"plex.direct\"]\nquiet = []",
        );
        assert_eq!(parse(&on).unwrap().watch, WatchCfg::default());
    }

    /// A well-formed `password_hash` value that no password was derived from.
    const SALT_HEX: &str = "0123456789abcdef0123456789abcdef";
    const HASH_HEX: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    /// The example with an `[api]` section whose `password_hash` line is `line`.
    fn example_with_api(line: &str) -> String {
        format!("{EXAMPLE}\n[api]\n{line}\n")
    }

    fn good_hash_line() -> String {
        format!("password_hash = \"$pbkdf2-sha256$i=100000${SALT_HEX}${HASH_HEX}\"")
    }

    #[test]
    fn without_an_api_section_there_is_no_api() {
        assert!(parse(EXAMPLE).unwrap().api.is_none());
        assert!(parse(MINIMAL).unwrap().api.is_none());
    }

    #[test]
    fn an_api_section_carries_the_password_hash() {
        let cfg = parse(&example_with_api(&good_hash_line())).unwrap();
        let api = cfg.api.expect("the file has an [api] section");
        assert_eq!(
            api.password_hash.to_text(),
            format!("$pbkdf2-sha256$i=100000${SALT_HEX}${HASH_HEX}")
        );
    }

    #[test]
    fn the_commented_api_section_of_the_example_is_a_valid_one() {
        let text = example_with("# [api]\n# password_hash", "[api]\npassword_hash");
        assert!(parse(&text).unwrap().api.is_some());
    }

    #[test]
    fn a_password_hash_that_is_no_hash_line_is_refused_by_key_without_echoing_it() {
        for bad in [
            "nope".to_owned(),
            String::new(),
            format!(
                "$pbkdf2-sha256$i=100000${SALT_HEX}${}",
                HASH_HEX.to_uppercase()
            ),
            format!("$pbkdf2-sha256$i=9999${SALT_HEX}${HASH_HEX}"),
            format!("password_hash = $pbkdf2-sha256$i=100000${SALT_HEX}${HASH_HEX}"),
        ] {
            let e = parse(&example_with_api(&format!("password_hash = \"{bad}\""))).unwrap_err();
            assert_eq!(e.key, "api.password_hash");
            assert_eq!(
                e.reason,
                "must be the line that cargo xtask hash-password prints"
            );
            if !bad.is_empty() {
                for shown in [e.to_string(), format!("{e:?}")] {
                    assert!(!shown.contains(&bad), "{shown}");
                }
            }
            for shown in [e.to_string(), format!("{e:?}")] {
                assert!(
                    !shown.contains("nope") && !shown.contains(SALT_HEX),
                    "{shown}"
                );
                assert!(!shown.contains(&HASH_HEX.to_uppercase()), "{shown}");
            }
        }
    }

    #[test]
    fn the_api_section_is_checked_like_the_others() {
        for (api, key, reason) in [
            (
                "password_hash = 12345",
                "api.password_hash",
                "must be a string",
            ),
            (
                "password_hash = true",
                "api.password_hash",
                "must be a string",
            ),
            ("", "api.password_hash", "required, but not set"),
            ("password = \"example\"", "api.password", "unknown key"),
        ] {
            let e = parse(&example_with_api(api)).unwrap_err();
            assert_eq!((e.key.as_str(), e.reason.as_str()), (key, reason), "{api}");
            assert!(!e.to_string().contains("12345") && !e.to_string().contains("example\""));
        }
        // The section is a table and nothing else.
        let e = parse(&format!("api = 1\n{EXAMPLE}")).unwrap_err();
        assert_eq!(
            (e.key.as_str(), e.reason.as_str()),
            ("api", "must be a table")
        );
    }

    #[test]
    fn a_config_shows_nothing_of_the_password_hash() {
        let cfg = parse(&example_with_api(&good_hash_line())).unwrap();
        assert!(cfg.api.is_some());
        for shown in [format!("{cfg:?}"), format!("{cfg:#?}")] {
            assert!(!shown.contains(HASH_HEX), "{shown}");
            assert!(!shown.contains(SALT_HEX), "{shown}");
            assert!(!shown.contains("pbkdf2"), "{shown}");
            assert!(shown.contains("<redacted>"), "{shown}");
        }
    }
}
