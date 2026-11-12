//! The Wi-Fi channel hint (`wifi.hint_mhz`) in the copy of `qberrypi.toml` that goes to the Pi.
//!
//! `cargo xtask update` adds the frequency the Pi is on to the copy it uploads, and `cargo xtask
//! image` adds the one `--wifi-hint` gives to the copy in each slot, so that the Pi's first scan
//! after a start covers only that channel. The owner's own file is never written. The edit is of
//! the text, since `xtask` has no TOML writer and a rewrite would lose the owner's comments; the
//! result is proved with `qberrypi::config::parse`: it must parse, must have the hint, and must be
//! the original in everything else.
//!
//! The hint is for the 5 GHz channel. The Pi prefers 5 GHz to 2.4 GHz, so a hinted scan whose best
//! access point is on 2.4 GHz is not taken and the scan covers every channel after all: a hint of
//! 2.4 GHz channels alone only adds a scan. [`hinted_config`] refuses a hint that lists no 5 GHz
//! channel, and `cargo xtask update` leaves a 2.4 GHz channel out of the copy it uploads
//! ([`is_5ghz`]).
//!
//! Nothing here quotes the file: an error names the file and what is wrong, never what it says.

use anyhow::{Result, anyhow, ensure};
use qberrypi::config::{self, Config, WifiKey};
use qberrypi::wifi::choose::{Band, band};

use crate::slot::CONFIG_FILE;
use crate::update::table_name;

/// Whether `mhz` is on the 5 GHz band, as the Pi takes it when it ranks the access points of a scan
/// (`qberrypi::wifi::choose::band`): the band that it prefers to any other.
pub fn is_5ghz(mhz: u32) -> bool {
    band(mhz) == Band::Ghz5
}

/// Whether the `[wifi]` table of `text`, the text of `qberrypi.toml`, assigns `hint_mhz` (to a list
/// that may be empty). A file whose `[wifi]` is not written as a table with a header is not seen.
pub fn has_hint(text: &str) -> bool {
    let mut in_wifi = false;
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('[') {
            in_wifi = table_name(trimmed) == Some("wifi");
        } else if in_wifi
            && trimmed
                .strip_prefix("hint_mhz")
                .is_some_and(|rest| rest.trim_start().starts_with('='))
        {
            return true;
        }
    }
    false
}

/// `text` with `hint_mhz = [..]` as the first line of its `[wifi]` table, the line ending of the
/// header kept; `None` when the file has no `[wifi]` header to put it under. Nothing else is touched.
fn with_hint(text: &str, hint: &[u32]) -> Option<String> {
    let list: Vec<String> = hint.iter().map(u32::to_string).collect();
    let wanted = format!("hint_mhz = [{}]", list.join(", "));
    let mut edited = String::with_capacity(text.len() + wanted.len() + 2);
    let mut placed = false;
    for line in text.split_inclusive('\n') {
        edited.push_str(line);
        if !placed && table_name(line.trim_start()) == Some("wifi") {
            let ending = if line.ends_with("\r\n") { "\r\n" } else { "\n" };
            if !line.ends_with('\n') {
                edited.push_str(ending);
            }
            edited.push_str(&wanted);
            edited.push_str(ending);
            placed = true;
        }
    }
    placed.then_some(edited)
}

/// Whether two configurations are the same in everything `Debug` shows and in the secrets it hides:
/// the Wi-Fi key and the API's password hash, compared on their own.
pub fn same_configuration(before: &Config, after: &Config) -> bool {
    let same_secrets = match (&before.wifi.key, &after.wifi.key) {
        (WifiKey::Passphrase(a), WifiKey::Passphrase(b)) | (WifiKey::Pmk(a), WifiKey::Pmk(b)) => {
            a.expose() == b.expose()
        }
        _ => false,
    } && match (&before.api, &after.api) {
        (Some(a), Some(b)) => a.password_hash.to_text() == b.password_hash.to_text(),
        (None, None) => true,
        _ => false,
    };
    same_secrets && format!("{before:?}") == format!("{after:?}")
}

/// The text of `qberrypi.toml` for the Pi: `text` with `hint_mhz` set to `hint` under `[wifi]`, and
/// proved to differ from `text` in that and nothing else.
///
/// `text` must not have a hint already (see [`has_hint`]), and `hint` must list a 5 GHz channel: the
/// Pi does not take a hinted scan whose best access point is on 2.4 GHz, so a hint of 2.4 GHz channels
/// alone would only add a scan. The error says which step failed: the file is not a configuration,
/// the hint has no 5 GHz channel, the file has no `[wifi]` table written with a header, the copy does not parse
/// (the parser's reason for `wifi.hint_mhz` is passed on: it names the rule and no value), or the copy
/// is not the original but for the hint. It quotes nothing of the file.
pub fn hinted_config(text: &str, hint: &[u32]) -> Result<String> {
    let before = config::parse(text)
        .map_err(|error| anyhow!("{CONFIG_FILE} is not a valid configuration: {error}"))?;
    ensure!(
        !has_hint(text) && before.wifi.hint_mhz.is_empty(),
        "{CONFIG_FILE} already has wifi.hint_mhz"
    );
    ensure!(
        hint.iter().any(|&mhz| is_5ghz(mhz)),
        "the hint lists no 5 GHz channel, and the Pi prefers 5 GHz: it does not take a hinted scan \
         whose best access point is on 2.4 GHz and scans every channel after all, so a hint of \
         2.4 GHz channels alone only adds a scan; name the 5 GHz channel (5180 is channel 36)"
    );
    let edited = with_hint(text, hint).ok_or_else(|| {
        anyhow!("{CONFIG_FILE} has no [wifi] table with a header to put wifi.hint_mhz under")
    })?;
    let mut after = config::parse(&edited).map_err(|error| {
        anyhow!("the copy of {CONFIG_FILE} with wifi.hint_mhz does not parse ({error})")
    })?;
    ensure!(
        after.wifi.hint_mhz == hint,
        "the copy of {CONFIG_FILE} does not have the wifi.hint_mhz that was asked for"
    );
    after.wifi.hint_mhz = before.wifi.hint_mhz.clone();
    ensure!(
        same_configuration(&before, &after),
        "the copy of {CONFIG_FILE} with wifi.hint_mhz differs from the original in more than that key"
    );
    Ok(edited)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::slot::tests::CONFIG;

    /// The example configuration, with an `[api]` section so that a secret of the file is there.
    fn config_text() -> String {
        format!(
            "{CONFIG}\n[api]\npassword_hash = \"$pbkdf2-sha256$i=100000$00000000000000000000000000000000$0000000000000000000000000000000000000000000000000000000000000000\"\n"
        )
    }

    #[test]
    fn the_hint_is_the_first_line_of_the_wifi_table_and_nothing_else_changes() {
        let text = config_text();
        let edited = hinted_config(&text, &[5180]).unwrap();
        assert_eq!(config::parse(&edited).unwrap().wifi.hint_mhz, [5180]);
        // Take the one line out and the text is the original, byte for byte.
        assert_eq!(edited.replacen("hint_mhz = [5180]\n", "", 1), text);
        let header = edited.find("[wifi]\n").unwrap() + "[wifi]\n".len();
        assert!(
            edited[header..].starts_with("hint_mhz = [5180]\n"),
            "{edited}"
        );
        // Two channels are written in the order given.
        let two = hinted_config(&text, &[5180, 2437]).unwrap();
        assert!(two.contains("hint_mhz = [5180, 2437]\n"), "{two}");
        assert_eq!(config::parse(&two).unwrap().wifi.hint_mhz, [5180, 2437]);
    }

    #[test]
    fn a_header_with_spaces_a_comment_or_crlf_line_ends_is_found_and_kept() {
        let text = config_text().replace("[wifi]", "[ wifi ]  # the network");
        let edited = hinted_config(&text, &[5200]).unwrap();
        assert!(edited.contains("[ wifi ]  # the network\nhint_mhz = [5200]\n"));

        let crlf = config_text().replace('\n', "\r\n");
        let edited = hinted_config(&crlf, &[5200]).unwrap();
        assert!(edited.contains("[wifi]\r\nhint_mhz = [5200]\r\n"));
        assert_eq!(edited.replacen("hint_mhz = [5200]\r\n", "", 1), crlf);
    }

    #[test]
    fn a_file_that_has_a_hint_already_is_not_edited() {
        let with = |line: &str| config_text().replace("[wifi]\n", &format!("[wifi]\n{line}\n"));
        for line in ["hint_mhz = [5180]", "hint_mhz = []", "hint_mhz=[2437]"] {
            let text = with(line);
            assert!(has_hint(&text), "{line}");
            let error = hinted_config(&text, &[5200]).unwrap_err().to_string();
            assert!(error.contains("already has wifi.hint_mhz"), "{error}");
        }
        // A key of another table by that name is no hint of the Wi-Fi.
        assert!(!has_hint("[wifi]\nssid = \"x\"\n[other]\nhint_mhz = [1]\n"));
        assert!(!has_hint(&config_text()));
    }

    #[test]
    fn a_file_with_no_wifi_header_is_refused_without_a_word_of_it() {
        let inline = config_text()
            .replace("[wifi]\n", "")
            .replace("ssid =", "wifi.ssid =")
            .replace("passphrase =", "wifi.passphrase =")
            .replace("country =", "wifi.country =");
        // Whether this parses as it stands depends on the file; either way the edit is refused.
        let error = hinted_config(&inline, &[5180]).unwrap_err().to_string();
        assert!(!error.contains("example-passphrase"), "{error}");
    }

    #[test]
    fn a_frequency_that_is_no_channel_is_refused_naming_the_key_and_not_the_value() {
        for hint in [
            vec![5181],
            vec![5180, 5180],
            vec![5180, 5200, 5220, 5240, 5260],
        ] {
            let error = hinted_config(&config_text(), &hint)
                .unwrap_err()
                .to_string();
            assert!(error.contains("wifi.hint_mhz"), "{error}");
            assert!(
                !error.contains("5181") && !error.contains("5260"),
                "{error}"
            );
        }
    }

    #[test]
    fn a_hint_of_2_4_ghz_channels_alone_is_refused_and_one_with_a_5_ghz_channel_is_not() {
        for hint in [vec![2437], vec![2412, 2462], vec![2484]] {
            let error = hinted_config(&config_text(), &hint)
                .unwrap_err()
                .to_string();
            assert!(error.contains("no 5 GHz channel"), "{error}");
            assert!(error.contains("prefers 5 GHz"), "{error}");
            assert!(
                !error.contains("2437") && !error.contains("2462"),
                "{error}"
            );
        }
        // In either order, a 5 GHz channel is enough.
        for hint in [vec![2437, 5180], vec![5180, 2437]] {
            assert!(hinted_config(&config_text(), &hint).is_ok(), "{hint:?}");
        }
    }

    #[test]
    fn the_5_ghz_band_is_the_one_the_pi_takes_as_it() {
        assert!([5180, 5200, 5745, 5825].into_iter().all(is_5ghz));
        assert!(![2412, 2437, 2484, 0, 900, 5955].into_iter().any(is_5ghz));
    }

    #[test]
    fn a_file_that_is_no_configuration_is_refused_without_quoting_it() {
        let error = hinted_config("[wifi]\nssid = \"example-secret-name\"\n", &[5180])
            .unwrap_err()
            .to_string();
        assert!(error.contains("is not a valid configuration"), "{error}");
        assert!(!error.contains("example-secret-name"), "{error}");
    }

    #[test]
    fn the_proof_notices_a_copy_that_differs_in_another_key() {
        let before = config::parse(&config_text()).unwrap();
        let same = config::parse(&config_text()).unwrap();
        assert!(same_configuration(&before, &same));
        let other = config_text().replace("hostname = \"qberrypi\"", "hostname = \"other\"");
        assert!(!same_configuration(
            &before,
            &config::parse(&other).unwrap()
        ));
        // The passphrase is hidden from `Debug`, and is compared on its own.
        let key = config_text().replace("example-passphrase", "another-passphrase");
        assert!(!same_configuration(&before, &config::parse(&key).unwrap()));
    }
}
