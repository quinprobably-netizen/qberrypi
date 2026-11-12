//! What the executable does when the kernel starts it to load a module.
//!
//! The kernel runs its module helper as `<path> -q -- <name>`. qberrypi
//! registers itself as that helper, so this takes the place of `modprobe`.
//!
//! Bluetooth is absent from qberrypi by design: the image holds no Bluetooth module and no
//! Bluetooth firmware, and the helper refuses every request in the name family of Bluetooth
//! ([`is_bluetooth_request`]) before it looks at the module table, so that nothing could load
//! one even if a file appeared.

use std::io::{self, Write};

use crate::modules::{self, Insert, ModuleTable};

/// Picks the module names out of the helper's arguments.
///
/// Before a `--`, an argument that starts with `-` is an option and is
/// skipped. After it every argument is a name.
pub fn parse_args(args: &[String]) -> Vec<String> {
    let mut names = Vec::new();
    let mut options_ended = false;
    for arg in args {
        if options_ended {
            names.push(arg.clone());
        } else if arg == "--" {
            options_ended = true;
        } else if !arg.starts_with('-') {
            names.push(arg.clone());
        }
    }
    names
}

/// Whether `name`, a module the kernel asks for, is in the name family of Bluetooth: `bluetooth`, any
/// `bt*`, any `hci_*`, `bnep`, `rfcomm`, `hidp`, and the aliases the kernel asks for when something
/// opens a Bluetooth socket: `net-pf-31` (`PF_BLUETOOTH`, with anything after another `-`) and
/// `bt-proto-*`. A `-` and a `_` are the same, and so are capitals and small letters.
pub fn is_bluetooth_request(name: &str) -> bool {
    let name = name.to_ascii_lowercase().replace('_', "-");
    ["bluetooth", "bnep", "rfcomm", "hidp", "net-pf-31"].contains(&name.as_str())
        || name.starts_with("bt")
        || name.starts_with("hci-")
        || name.starts_with("net-pf-31-")
}

/// Runs the helper on the module table as it was read, or not, from the initramfs.
///
/// A table that could not be read gets one line on `kmsg`,
/// `qberrypi-modhelper: module table: {error}`, and the status is 1 with
/// nothing loaded. Otherwise this is [`run`].
pub fn run_with_table(
    table_text: io::Result<String>,
    args: &[String],
    insert: Insert,
    kmsg: &mut dyn Write,
) -> i32 {
    match table_text {
        Ok(table_text) => run(args, &table_text, insert, kmsg),
        Err(error) => {
            report(kmsg, &format!("module table: {error}"));
            1
        }
    }
}

/// Loads the modules named in `args` and returns the helper's exit status.
///
/// `args` is without the program name. Each name gets one line on `kmsg`:
/// `qberrypi-modhelper: {name}: loaded`, `not in table` or `failed: {error}`.
/// The status is 0 only if a module was named and every one named loaded.
///
/// A name in the family of Bluetooth ([`is_bluetooth_request`]) is refused outright, whatever the
/// table says: the one line it gets is at the kernel's debug level (`<7>`), reading `refused: Bluetooth
/// is absent by design`, nothing is looked up or loaded for it, and it fails the status like a module
/// that is not in the table.
pub fn run(args: &[String], table_text: &str, insert: Insert, kmsg: &mut dyn Write) -> i32 {
    let names = parse_args(args);
    if names.is_empty() {
        return 1;
    }
    let table = match ModuleTable::parse(table_text) {
        Ok(table) => table,
        Err(error) => {
            report(kmsg, &format!("module table: {error}"));
            return 1;
        }
    };
    let mut status = 0;
    for name in &names {
        if is_bluetooth_request(name) {
            report_debug(
                kmsg,
                &format!("{name}: refused, Bluetooth is absent by design"),
            );
            status = 1;
            continue;
        }
        // Asked of the table first: a module file that is missing is also
        // "not found", and that is a failed load, not an unknown module.
        let outcome = if table.load_order(name).is_none() {
            Err("not in table".to_owned())
        } else {
            modules::load(&table, name, "", insert)
                .map(|_| ())
                .map_err(|error| format!("failed: {error}"))
        };
        match outcome {
            Ok(()) => report(kmsg, &format!("{name}: loaded")),
            Err(reason) => {
                report(kmsg, &format!("{name}: {reason}"));
                status = 1;
            }
        }
    }
    status
}

/// Writes one line to the kernel log at its debug level, which the console's `loglevel` keeps off the
/// screen.
fn report_debug(kmsg: &mut dyn Write, message: &str) {
    let _ = kmsg.write_all(format!("<7>qberrypi-modhelper: {message}\n").as_bytes());
}

/// Writes one line to the kernel log.
fn report(kmsg: &mut dyn Write, message: &str) {
    // The kernel log takes one record per write, so the line goes in one
    // piece. Nothing can be done if it is refused: there is nowhere else to
    // say so.
    let _ = kmsg.write_all(format!("qberrypi-modhelper: {message}\n").as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{self, ErrorKind, Write};
    use std::path::{Path, PathBuf};

    use crate::modules::{DEFAULT_TABLE, ModuleTable};

    const TABLE: &str = DEFAULT_TABLE;

    fn args(args: &[&str]) -> Vec<String> {
        args.iter().map(|&arg| arg.to_owned()).collect()
    }

    /// Keeps what each `write` call was given, as the kernel log device would.
    #[derive(Default)]
    struct Records(Vec<String>);

    impl Write for Records {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.push(String::from_utf8(bytes.to_vec()).unwrap());
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Refuses every write.
    struct Broken;

    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(ErrorKind::BrokenPipe.into())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_table_that_cannot_be_read_is_reported_in_one_write_and_nothing_is_loaded() {
        let unreadable = || io::Error::from_raw_os_error(libc::ENOENT);
        let mut out = Records::default();
        let mut insert = |_: &Path, _: &str| panic!("nothing to insert");
        let requested = args(&["-q", "--", "brcmfmac-cyw", "rfkill"]);
        assert_eq!(
            run_with_table(Err(unreadable()), &requested, &mut insert, &mut out),
            1
        );
        assert_eq!(
            out.0,
            [format!(
                "qberrypi-modhelper: module table: {}\n",
                unreadable()
            )]
        );
    }

    #[test]
    fn a_table_that_cannot_be_read_fails_even_if_the_log_cannot_be_written() {
        let unreadable = Err(ErrorKind::PermissionDenied.into());
        let mut insert = |_: &Path, _: &str| panic!("nothing to insert");
        let requested = args(&["--", "rfkill"]);
        assert_eq!(
            run_with_table(unreadable, &requested, &mut insert, &mut Broken),
            1
        );
    }

    #[test]
    fn a_table_that_was_read_is_used_as_run_uses_it() {
        let mut calls: Vec<PathBuf> = vec![];
        let mut insert = |p: &Path, _: &str| {
            calls.push(p.to_owned());
            Ok(())
        };
        let mut out = Records::default();
        let requested = args(&["-q", "--", "cfg80211", "net-pf-10"]);
        let table = Ok(TABLE.to_owned());
        assert_eq!(run_with_table(table, &requested, &mut insert, &mut out), 1);
        assert_eq!(
            out.0,
            [
                "qberrypi-modhelper: cfg80211: loaded\n",
                "qberrypi-modhelper: net-pf-10: not in table\n",
            ]
        );
        assert_eq!(
            calls,
            [
                Path::new("/lib/modules/rfkill.ko"),
                Path::new("/lib/modules/cfg80211.ko"),
            ]
        );

        // An empty table is a table: the module is unknown, not the table unread.
        let mut out = Records::default();
        let requested = args(&["--", "rfkill"]);
        let status = run_with_table(Ok(String::new()), &requested, &mut |_, _| Ok(()), &mut out);
        assert_eq!(status, 1);
        assert_eq!(out.0, ["qberrypi-modhelper: rfkill: not in table\n"]);
    }

    #[test]
    fn the_names_of_the_family_of_bluetooth_are_told_from_the_others() {
        for name in [
            "bluetooth",
            "Bluetooth",
            "btbcm",
            "btusb",
            "btsdio",
            "btintel",
            "btrtl",
            "bt878",
            "hci_uart",
            "hci-uart",
            "hci_vhci",
            "bnep",
            "rfcomm",
            "hidp",
            "net-pf-31",
            "net_pf_31",
            "net-pf-31-proto-2",
            "net-pf-31-proto-2-type-1",
            "bt-proto-2",
            "bt_proto_0",
        ] {
            assert!(is_bluetooth_request(name), "{name}");
        }
        for name in [
            "rfkill",
            "cfg80211",
            "brcmfmac",
            "brcmfmac-cyw",
            "net-pf-10",
            "net-pf-3",
            "net-pf-310",
            "net-pf-1",
            "fbtft",
            "spi-bcm2835",
            "hid",
            "hidraw",
            "rfcomm2",
            "ads7846",
            "",
        ] {
            assert!(!is_bluetooth_request(name), "{name:?}");
        }
    }

    #[test]
    fn a_bluetooth_request_is_refused_with_one_debug_line_and_nothing_is_looked_up_or_loaded() {
        // Even a table that lists the module, and a loader that would load anything.
        let table = "bluetooth\tbluetooth.ko\t\nbtusb\tbtusb.ko\tbluetooth\n";
        let mut insert = |_: &Path, _: &str| panic!("a Bluetooth module is never loaded");
        let mut out = Records::default();
        let requested = args(&["-q", "--", "btusb", "net-pf-31", "hci_uart"]);
        assert_eq!(run(&requested, table, &mut insert, &mut out), 1);
        assert_eq!(
            out.0,
            [
                "<7>qberrypi-modhelper: btusb: refused, Bluetooth is absent by design\n",
                "<7>qberrypi-modhelper: net-pf-31: refused, Bluetooth is absent by design\n",
                "<7>qberrypi-modhelper: hci_uart: refused, Bluetooth is absent by design\n",
            ]
        );
    }

    #[test]
    fn a_bluetooth_request_among_others_changes_nothing_for_the_others() {
        let mut calls: Vec<PathBuf> = vec![];
        let mut insert = |p: &Path, _: &str| {
            calls.push(p.to_owned());
            Ok(())
        };
        let mut out = Records::default();
        let requested = args(&["--", "rfkill", "bnep", "brcmutil"]);
        // The status fails, as for a module that is not in the table; the others load.
        assert_eq!(run(&requested, TABLE, &mut insert, &mut out), 1);
        assert_eq!(
            out.0,
            [
                "qberrypi-modhelper: rfkill: loaded\n",
                "<7>qberrypi-modhelper: bnep: refused, Bluetooth is absent by design\n",
                "qberrypi-modhelper: brcmutil: loaded\n",
            ]
        );
        assert_eq!(
            calls,
            [
                Path::new("/lib/modules/rfkill.ko"),
                Path::new("/lib/modules/brcmutil.ko"),
            ]
        );
    }

    #[test]
    fn the_default_table_names_no_module_the_helper_refuses() {
        let table = ModuleTable::parse(TABLE).unwrap();
        for entry in table.entries() {
            assert!(!is_bluetooth_request(&entry.name), "{}", entry.name);
        }
    }

    #[test]
    fn helper_parses_the_kernel_argument_form() {
        assert_eq!(
            parse_args(&["-q".into(), "--".into(), "brcmfmac-cyw".into()]),
            ["brcmfmac-cyw"]
        );
    }

    #[test]
    fn helper_reports_unknown_modules_and_fails() {
        let mut out = Vec::new();
        assert_eq!(
            run(
                &["-q".into(), "--".into(), "net-pf-10".into()],
                TABLE,
                &mut |_, _| Ok(()),
                &mut out
            ),
            1
        );
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "qberrypi-modhelper: net-pf-10: not in table\n"
        );
    }

    #[test]
    fn options_are_skipped_only_before_the_double_dash() {
        for (given, names) in [
            (&[][..], &[][..]),
            (&["-q"], &[]),
            (&["-q", "--"], &[]),
            // With no "--", whatever does not look like an option is a name.
            (
                &["-q", "rfkill", "--verbose", "cfg80211"],
                &["rfkill", "cfg80211"],
            ),
            (&["rfkill", "--", "cfg80211"], &["rfkill", "cfg80211"]),
            // After "--" everything is a name.
            (&["--", "-odd", "rfkill"], &["-odd", "rfkill"]),
            (&["-q", "--", "--", "rfkill"], &["--", "rfkill"]),
        ] as [(&[&str], &[&str]); 7]
        {
            assert_eq!(parse_args(&args(given)), names, "{given:?}");
        }
    }

    #[test]
    fn a_loaded_module_is_reported_and_brings_its_dependencies() {
        let mut calls: Vec<(PathBuf, String)> = vec![];
        let mut insert = |p: &Path, params: &str| {
            calls.push((p.to_owned(), params.to_owned()));
            Ok(())
        };
        let mut out = Records::default();
        let status = run(
            &args(&["-q", "--", "brcmfmac_cyw"]),
            TABLE,
            &mut insert,
            &mut out,
        );
        assert_eq!(status, 0);
        assert_eq!(out.0, ["qberrypi-modhelper: brcmfmac_cyw: loaded\n"]);
        let files: Vec<_> = calls.iter().map(|(p, _)| p.to_str().unwrap()).collect();
        assert_eq!(
            files,
            [
                "/lib/modules/brcmutil.ko",
                "/lib/modules/rfkill.ko",
                "/lib/modules/cfg80211.ko",
                "/lib/modules/brcmfmac.ko",
                "/lib/modules/brcmfmac-cyw.ko",
            ]
        );
        assert!(calls.iter().all(|(_, params)| params.is_empty()));
    }

    #[test]
    fn a_module_already_in_the_kernel_counts_as_loaded() {
        let mut out = Records::default();
        let mut insert = |_: &Path, _: &str| Err(ErrorKind::AlreadyExists.into());
        assert_eq!(
            run(&args(&["--", "cfg80211"]), TABLE, &mut insert, &mut out),
            0
        );
        assert_eq!(out.0, ["qberrypi-modhelper: cfg80211: loaded\n"]);
    }

    #[test]
    fn each_request_gets_one_line_in_one_write_and_a_failure_does_not_stop_the_rest() {
        let mut insert = |p: &Path, _: &str| {
            if p.ends_with("cfg80211.ko") {
                Err(io::Error::other("bad signature"))
            } else {
                Ok(())
            }
        };
        let mut out = Records::default();
        let requested = args(&["-q", "--", "cfg80211", "net-pf-10", "brcmutil"]);
        assert_eq!(run(&requested, TABLE, &mut insert, &mut out), 1);
        assert_eq!(
            out.0,
            [
                "qberrypi-modhelper: cfg80211: failed: bad signature\n",
                "qberrypi-modhelper: net-pf-10: not in table\n",
                "qberrypi-modhelper: brcmutil: loaded\n",
            ]
        );
    }

    #[test]
    fn a_module_file_that_is_missing_is_a_failure_and_not_an_unknown_module() {
        let mut insert = |_: &Path, _: &str| Err(ErrorKind::NotFound.into());
        let mut out = Records::default();
        assert_eq!(
            run(&args(&["--", "rfkill"]), TABLE, &mut insert, &mut out),
            1
        );
        let error = io::Error::from(ErrorKind::NotFound);
        assert_eq!(
            out.0,
            [format!("qberrypi-modhelper: rfkill: failed: {error}\n")]
        );
    }

    #[test]
    fn with_no_module_named_nothing_is_written_and_it_fails() {
        for given in [&[][..], &["-q"], &["-q", "--"]] as [&[&str]; 3] {
            let mut out = Records::default();
            let mut insert = |_: &Path, _: &str| panic!("nothing to insert");
            // Not even a table that does not parse is reported.
            assert_eq!(run(&args(given), "broken\n", &mut insert, &mut out), 1);
            assert!(out.0.is_empty(), "{given:?}");
        }
    }

    #[test]
    fn a_table_that_does_not_parse_is_reported_once_and_nothing_is_loaded() {
        let text = "rfkill\trfkill.ko\nbroken\n";
        let error = ModuleTable::parse(text).unwrap_err();
        let mut out = Records::default();
        let mut insert = |_: &Path, _: &str| panic!("nothing to insert");
        let requested = args(&["-q", "--", "rfkill", "cfg80211"]);
        assert_eq!(run(&requested, text, &mut insert, &mut out), 1);
        assert_eq!(
            out.0,
            [format!("qberrypi-modhelper: module table: {error}\n")]
        );
    }

    #[test]
    fn a_log_that_cannot_be_written_changes_nothing() {
        let mut calls = 0;
        let mut insert = |_: &Path, _: &str| {
            calls += 1;
            Ok(())
        };
        let requested = args(&["--", "cfg80211", "net-pf-10"]);
        assert_eq!(run(&requested, TABLE, &mut insert, &mut Broken), 1);
        assert_eq!(calls, 2);

        let mut insert = |_: &Path, _: &str| Ok(());
        assert_eq!(
            run(&args(&["--", "rfkill"]), TABLE, &mut insert, &mut Broken),
            0
        );
    }
}
