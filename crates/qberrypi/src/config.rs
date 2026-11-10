//! Parses and validates `qberrypi.toml`, the system's one configuration file.
//!
//! Every error names the offending key and states the rule it broke. No error
//! ever repeats a value from the file, so a mistyped passphrase cannot end up
//! in a log.

use std::fmt;
use std::net::Ipv4Addr;
use std::ops::Range;

use toml::{Table, Value};

const DEFAULT_HOSTNAME: &str = "qberrypi";

/// The validated contents of `qberrypi.toml`.
#[derive(Debug)]
pub struct Config {
    /// Name the system gives itself on the network.
    pub hostname: String,
    /// Which wireless network to join, and how.
    pub wifi: Wifi,
    /// The static IPv4 address and route.
    pub net: Net,
    /// Upstream resolvers and blocking rules.
    pub dns: Dns,
    /// Switches used while bringing the system up.
    pub debug: DebugCfg,
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
    let root = Section::open("", &table, &["hostname", "wifi", "net", "dns", "debug"])?;

    let hostname = match root.string("hostname")? {
        Some(name) if is_hostname(name) => name.to_owned(),
        Some(_) => {
            return Err(root.error("hostname", "must be 1 to 63 characters from a-z, 0-9 and -"));
        }
        None => DEFAULT_HOSTNAME.to_owned(),
    };
    let wifi = wifi(&root.required_section("wifi", &["ssid", "passphrase", "pmk", "country"])?)?;
    let net = net(&root.required_section("net", &["address", "gateway"])?)?;
    let dns = dns(&root.required_section("dns", &["upstreams", "lists", "deny", "allow"])?)?;
    let debug = match root.section("debug", &["one_shot", "log_to_sd", "return_after_secs"])? {
        Some(section) => debug(&section)?,
        None => DebugCfg {
            one_shot: false,
            log_to_sd: false,
            return_after_secs: 0,
        },
    };
    Ok(Config {
        hostname,
        wifi,
        net,
        dns,
        debug,
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
    Ok(Net { address, gateway })
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
    let lists = section.strings_or_empty("lists")?;
    if !lists.iter().all(|list| list.starts_with("https://")) {
        return Err(section.error("lists", "every entry must start with https://"));
    }
    Ok(Dns {
        upstreams,
        lists,
        deny: section.strings_or_empty("deny")?,
        allow: section.strings_or_empty("allow")?,
    })
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
    })
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

    fn bool_or_false(&self, name: &str) -> Result<bool, ConfigError> {
        match self.get(name) {
            None => Ok(false),
            Some(Value::Boolean(flag)) => Ok(*flag),
            Some(_) => Err(self.error(name, "must be true or false")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(c.dns.lists.len(), 2);
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
                "gateway = \"192.0.3.1\"".into(),
                "net.gateway",
                "192.0.3.1",
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
        assert!(e.reason.contains("line 5"), "{e}");
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
    fn error_display_names_the_file_the_key_and_the_reason() {
        let e = ConfigError {
            key: "net.gateway".into(),
            reason: "some reason".into(),
        };
        assert_eq!(e.to_string(), "qberrypi.toml: net.gateway: some reason");
    }
}
