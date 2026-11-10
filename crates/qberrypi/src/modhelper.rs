//! What the executable does when the kernel starts it to load a module.
//!
//! The kernel runs its module helper as `<path> -q -- <name>`. qberrypi
//! registers itself as that helper, so this takes the place of `modprobe`.

use std::io::Write;

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

/// Loads the modules named in `args` and returns the helper's exit status.
///
/// `args` is without the program name. Each name gets one line on `kmsg`:
/// `qberrypi-modhelper: {name}: loaded`, `not in table` or `failed: {error}`.
/// The status is 0 only if a module was named and every one named loaded.
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
