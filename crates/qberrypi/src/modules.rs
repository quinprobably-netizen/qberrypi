//! The table of kernel modules in the initramfs, and the order to load them in.
//!
//! The table is a text file with one module per line: its name, its file and
//! the modules it needs, separated by tabs. The needed modules are separated
//! by commas, and the field may be empty or left out.

use std::io::{self, ErrorKind};
use std::path::Path;

/// The directory in the initramfs that holds the module files.
pub const MODULE_DIR: &str = "/lib/modules";

/// The file in the initramfs that holds the module table.
pub const MODULE_LIST: &str = "/lib/modules/modules.list";

/// The module table of the image: the modules for the Wi-Fi chip of the
/// Raspberry Pi 3 B+, then those for the touchscreen on its SPI bus.
pub const DEFAULT_TABLE: &str = concat!(
    "rfkill\trfkill.ko\t\n",
    "cfg80211\tcfg80211.ko\trfkill\n",
    "brcmutil\tbrcmutil.ko\t\n",
    "brcmfmac\tbrcmfmac.ko\tbrcmutil,cfg80211\n",
    "brcmfmac-cyw\tbrcmfmac-cyw.ko\tbrcmfmac\n",
    "backlight\tbacklight.ko\t\n",
    "fbtft\tfbtft.ko\tbacklight\n",
    "fb_ili9486\tfb_ili9486.ko\tfbtft,backlight\n",
    "spi-bcm2835\tspi-bcm2835.ko\t\n",
    "ads7846\tads7846.ko\t\n",
);

/// The modules the front panel asks `load` for, in this order: the SPI bus
/// first, then the screen's driver, then the touch controller's.
pub const PANEL_MODULES: [&str; 3] = ["spi-bcm2835", "fb_ili9486", "ads7846"];

/// One module of the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleEntry {
    /// The name the kernel asks for it by.
    pub name: String,
    /// Its file name inside `MODULE_DIR`.
    pub file: String,
    /// The names of the modules that must be loaded before it.
    pub deps: Vec<String>,
}

/// The modules qberrypi can load, and what each of them needs.
#[derive(Debug)]
pub struct ModuleTable {
    entries: Vec<ModuleEntry>,
    /// For each entry, where in `entries` its dependencies are.
    needs: Vec<Vec<usize>>,
}

/// How far the walk over the dependencies has come with a module.
#[derive(Clone, Copy, PartialEq)]
enum Visit {
    Unseen,
    /// Reached, and its dependencies are still being walked.
    Open,
    Done,
}

impl ModuleTable {
    /// Parses the text of a module table.
    ///
    /// Lines with nothing but whitespace are skipped, and so are spaces
    /// around a field. The error says what is wrong and on which line: fewer
    /// than two fields or more than three, an empty name or file, a name the
    /// table already has, a dependency the table does not have, or modules
    /// that depend on each other.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut entries: Vec<ModuleEntry> = Vec::new();
        // The line each entry came from, for the errors found afterwards.
        let mut lines = Vec::new();
        for (index, line) in text.lines().enumerate() {
            let number = index + 1;
            if line.trim().is_empty() {
                continue;
            }
            let fields: Vec<&str> = line.split('\t').map(str::trim).collect();
            let (name, file, deps) = match fields[..] {
                [name, file] => (name, file, ""),
                [name, file, deps] => (name, file, deps),
                [_] => return Err(format!("line {number}: no file after the module name")),
                _ => return Err(format!("line {number}: more than three fields")),
            };
            if name.is_empty() {
                return Err(format!("line {number}: the module name is empty"));
            }
            if file.is_empty() {
                return Err(format!("line {number}: the file of {name} is empty"));
            }
            if entries.iter().any(|entry| same_name(&entry.name, name)) {
                return Err(format!("line {number}: {name} is in the table twice"));
            }
            entries.push(ModuleEntry {
                name: name.to_owned(),
                file: file.to_owned(),
                deps: deps
                    .split(',')
                    .map(str::trim)
                    .filter(|dep| !dep.is_empty())
                    .map(str::to_owned)
                    .collect(),
            });
            lines.push(number);
        }

        // A module may be listed before the modules it needs, so the
        // dependencies are looked up only once every line has been read.
        let mut needs = Vec::with_capacity(entries.len());
        for (entry, number) in entries.iter().zip(&lines) {
            let mut found = Vec::with_capacity(entry.deps.len());
            for dep in &entry.deps {
                match entries.iter().position(|other| same_name(&other.name, dep)) {
                    Some(index) => found.push(index),
                    None => {
                        return Err(format!(
                            "line {number}: {} needs {dep}, which is not in the table",
                            entry.name
                        ));
                    }
                }
            }
            needs.push(found);
        }

        let table = Self { entries, needs };
        let mut visits = vec![Visit::Unseen; table.entries.len()];
        for start in 0..table.entries.len() {
            if let Err((module, dep)) = table.walk(start, &mut visits, &mut Vec::new()) {
                return Err(format!(
                    "line {}: {} needs {}, which needs it in turn",
                    lines[module], table.entries[module].name, table.entries[dep].name
                ));
            }
        }
        Ok(table)
    }

    /// The modules of the table, in the table's order.
    pub fn entries(&self) -> &[ModuleEntry] {
        &self.entries
    }

    /// The file of every module in the table, in the table's order.
    pub fn files(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|entry| entry.file.as_str())
    }

    /// Lists a module and everything it needs, in the order to load them.
    ///
    /// Dependencies come first, in the order a module lists them, and each
    /// module appears once; the module asked for is last. `-` and `_` in
    /// names are the same. Returns `None` if the table does not have `name`.
    pub fn load_order(&self, name: &str) -> Option<Vec<&ModuleEntry>> {
        let start = self.position(name)?;
        let mut visits = vec![Visit::Unseen; self.entries.len()];
        let mut order = Vec::new();
        // `parse` let no cycle through, so the walk cannot fail.
        self.walk(start, &mut visits, &mut order).ok()?;
        Some(
            order
                .into_iter()
                .map(|index| &self.entries[index])
                .collect(),
        )
    }

    /// Where in `entries` the module of that name is.
    fn position(&self, name: &str) -> Option<usize> {
        self.entries
            .iter()
            .position(|entry| same_name(&entry.name, name))
    }

    /// Appends to `order` the modules `start` needs that are not `Done`, then `start`.
    ///
    /// Stops at a module that needs one whose own dependencies are still
    /// being walked, which is a cycle, and returns the two.
    fn walk(
        &self,
        start: usize,
        visits: &mut [Visit],
        order: &mut Vec<usize>,
    ) -> Result<(), (usize, usize)> {
        if visits[start] != Visit::Unseen {
            return Ok(());
        }
        visits[start] = Visit::Open;
        // Each module on the way down from `start`, with how many of its
        // dependencies have been looked at. Kept here and not on the call
        // stack, so a long chain of modules cannot exhaust it.
        let mut path = vec![(start, 0)];
        while let Some((module, looked_at)) = path.last_mut() {
            let module = *module;
            let Some(&dep) = self.needs[module].get(*looked_at) else {
                visits[module] = Visit::Done;
                order.push(module);
                path.pop();
                continue;
            };
            *looked_at += 1;
            match visits[dep] {
                Visit::Done => {}
                Visit::Open => return Err((module, dep)),
                Visit::Unseen => {
                    visits[dep] = Visit::Open;
                    path.push((dep, 0));
                }
            }
        }
        Ok(())
    }
}

/// Whether two module names are the same; the kernel treats `-` and `_` alike.
fn same_name(a: &str, b: &str) -> bool {
    let plain = |byte: u8| if byte == b'-' { b'_' } else { byte };
    a.len() == b.len() && a.bytes().zip(b.bytes()).all(|(x, y)| plain(x) == plain(y))
}

/// Inserts one module file into the kernel, with the given parameters.
pub type Insert<'a> = &'a mut dyn FnMut(&Path, &str) -> io::Result<()>;

/// Loads a module and, before it, everything it needs.
///
/// `params` goes to `name` only. A module the kernel already has counts as
/// loaded. The first other error from `insert` stops the load and is
/// returned; a `name` the table does not have is `ErrorKind::NotFound`.
/// Returns the names of the modules that were inserted.
pub fn load(
    table: &ModuleTable,
    name: &str,
    params: &str,
    insert: Insert,
) -> io::Result<Vec<String>> {
    let order = table.load_order(name).ok_or_else(|| {
        io::Error::new(
            ErrorKind::NotFound,
            format!("module {name} is not in the table"),
        )
    })?;
    let mut inserted = Vec::new();
    for (index, entry) in order.iter().enumerate() {
        // The module asked for is the last one in the order.
        let params = if index + 1 == order.len() { params } else { "" };
        match insert(&Path::new(MODULE_DIR).join(&entry.file), params) {
            Ok(()) => inserted.push(entry.name.clone()),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Ok(inserted)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{self, ErrorKind};
    use std::path::{Path, PathBuf};

    const TABLE: &str = DEFAULT_TABLE;

    fn order(table: &ModuleTable, name: &str) -> Vec<String> {
        let entries = table.load_order(name).unwrap();
        entries.iter().map(|e| e.name.clone()).collect()
    }

    #[test]
    fn load_order_puts_dependencies_first() {
        let t = ModuleTable::parse(TABLE).unwrap();
        let names: Vec<_> = t
            .load_order("brcmfmac")
            .unwrap()
            .iter()
            .map(|e| e.name.as_str())
            .collect();
        assert_eq!(names, ["brcmutil", "rfkill", "cfg80211", "brcmfmac"]);
        assert!(t.load_order("brcmfmac_cyw").is_some());
        assert!(t.load_order("net-pf-10").is_none());
    }

    #[test]
    fn the_files_of_a_table_are_listed_in_its_order() {
        let t = ModuleTable::parse(TABLE).unwrap();
        let files: Vec<&str> = t.files().collect();
        assert_eq!(
            files,
            [
                "rfkill.ko",
                "cfg80211.ko",
                "brcmutil.ko",
                "brcmfmac.ko",
                "brcmfmac-cyw.ko",
                "backlight.ko",
                "fbtft.ko",
                "fb_ili9486.ko",
                "spi-bcm2835.ko",
                "ads7846.ko"
            ]
        );
        assert_eq!(ModuleTable::parse("").unwrap().files().count(), 0);
    }

    #[test]
    fn cycles_and_unknown_deps_are_rejected() {
        assert!(ModuleTable::parse("a\ta.ko\tb\nb\tb.ko\ta\n").is_err());
        assert!(ModuleTable::parse("a\ta.ko\tzz\n").is_err());
    }

    #[test]
    fn params_go_to_the_named_module_only_and_already_loaded_is_fine() {
        let t = ModuleTable::parse(TABLE).unwrap();
        let mut calls = vec![];
        let mut insert = |p: &Path, params: &str| {
            calls.push((p.to_owned(), params.to_owned()));
            if p.ends_with("rfkill.ko") {
                Err(ErrorKind::AlreadyExists.into())
            } else {
                Ok(())
            }
        };
        load(&t, "cfg80211", "ieee80211_regdom=US", &mut insert).unwrap();
        assert_eq!(
            calls,
            [
                ("/lib/modules/rfkill.ko".into(), "".into()),
                (
                    "/lib/modules/cfg80211.ko".into(),
                    "ieee80211_regdom=US".into()
                )
            ]
        );
    }

    #[test]
    fn the_default_table_parses_and_every_module_has_a_load_order() {
        let t = ModuleTable::parse(DEFAULT_TABLE).unwrap();
        let names = [
            "rfkill",
            "cfg80211",
            "brcmutil",
            "brcmfmac",
            "brcmfmac-cyw",
            "backlight",
            "fbtft",
            "fb_ili9486",
            "spi-bcm2835",
            "ads7846",
        ];
        for name in names {
            let order = order(&t, name);
            assert_eq!(order.last().map(String::as_str), Some(name));
        }
        assert_eq!(
            order(&t, "brcmfmac-cyw"),
            ["brcmutil", "rfkill", "cfg80211", "brcmfmac", "brcmfmac-cyw"]
        );
        assert_eq!(
            order(&t, "fb_ili9486"),
            ["backlight", "fbtft", "fb_ili9486"]
        );
        // The initramfs gets this text as it is: one line per module, three
        // tab-separated fields each.
        assert_eq!(DEFAULT_TABLE.lines().count(), names.len());
        assert!(DEFAULT_TABLE.ends_with('\n'));
        for line in DEFAULT_TABLE.lines() {
            assert_eq!(line.split('\t').count(), 3, "{line:?}");
        }
    }

    #[test]
    fn the_panel_modules_load_bus_first_and_bring_what_they_need() {
        let table = ModuleTable::parse(DEFAULT_TABLE).unwrap();
        let mut files = Vec::new();
        for name in PANEL_MODULES {
            let mut insert = |file: &Path, _: &str| {
                files.push(file.to_str().unwrap().to_owned());
                Ok(())
            };
            load(&table, name, "", &mut insert).unwrap();
        }
        assert_eq!(
            files,
            [
                "/lib/modules/spi-bcm2835.ko",
                "/lib/modules/backlight.ko",
                "/lib/modules/fbtft.ko",
                "/lib/modules/fb_ili9486.ko",
                "/lib/modules/ads7846.ko"
            ]
        );
    }

    #[test]
    fn entries_keep_the_name_file_and_dependencies_as_written() {
        let t = ModuleTable::parse(TABLE).unwrap();
        let entries = t.load_order("brcmfmac_cyw").unwrap();
        let cyw = entries.last().unwrap();
        assert_eq!(cyw.name, "brcmfmac-cyw");
        assert_eq!(cyw.file, "brcmfmac-cyw.ko");
        assert_eq!(cyw.deps, ["brcmfmac"]);
        let rfkill = t.load_order("rfkill").unwrap()[0];
        assert!(rfkill.deps.is_empty());
    }

    #[test]
    fn a_module_two_others_depend_on_is_loaded_once() {
        let text =
            "top\ttop.ko\tleft,right\nleft\tleft.ko\tbase\nright\tright.ko\tbase\nbase\tbase.ko\n";
        let t = ModuleTable::parse(text).unwrap();
        assert_eq!(order(&t, "top"), ["base", "left", "right", "top"]);
    }

    #[test]
    fn dashes_and_underscores_are_the_same_in_dependencies_too() {
        let t = ModuleTable::parse("snd-pcm\tsnd-pcm.ko\nsnd_usb\tsnd-usb.ko\tsnd_pcm\n").unwrap();
        assert_eq!(order(&t, "snd-usb"), ["snd-pcm", "snd_usb"]);
    }

    #[test]
    fn the_dependency_field_may_be_missing_and_blank_lines_are_skipped() {
        let t = ModuleTable::parse("\na\ta.ko\n\n\nb\tb.ko\ta\n\n").unwrap();
        assert_eq!(order(&t, "b"), ["a", "b"]);
        assert!(ModuleTable::parse("").unwrap().load_order("a").is_none());
    }

    #[test]
    fn a_malformed_line_is_an_error_that_names_its_line() {
        for (text, line) in [
            ("a\n", "line 1"),
            ("a\ta.ko\n\nb\n", "line 3"),
            ("\ta.ko\n", "line 1"),
            ("a\ta.ko\nb\t\n", "line 2"),
            ("a\ta.ko\nb\t\ta\n", "line 2"),
            ("a\ta.ko\t\textra\n", "line 1"),
            // The same name twice, however it is spelled.
            ("a\ta.ko\na\tother.ko\n", "line 2"),
            ("snd-x\tx.ko\n\nsnd_x\ty.ko\n", "line 3"),
            // A dependency the table does not have.
            ("a\ta.ko\nb\tb.ko\ta,zz\n", "line 2"),
        ] {
            let error = ModuleTable::parse(text).unwrap_err();
            assert!(error.contains(line), "{text:?} gave {error:?}");
        }
    }

    #[test]
    fn every_kind_of_cycle_is_rejected() {
        for (text, line) in [
            ("a\ta.ko\ta\n", "line 1"),
            ("a\ta.ko\tb\nb\tb.ko\tc\nc\tc.ko\ta\n", "line 3"),
            // Reached only through a module that is itself fine.
            ("top\ttop.ko\tx\nx\tx.ko\ty\n\ny\ty.ko\tx\n", "line 4"),
            ("a-b\tab.ko\ta_b\n", "line 1"),
        ] {
            let error = ModuleTable::parse(text).unwrap_err();
            assert!(error.contains(line), "{text:?} gave {error:?}");
        }
    }

    #[test]
    fn spaces_around_a_field_and_whitespace_only_lines_are_ignored() {
        let text = " a \t a.ko \n \t \r\n\t\nb\tb.ko\t a , ,\r\n";
        let t = ModuleTable::parse(text).unwrap();
        let entries = t.load_order("b").unwrap();
        assert_eq!(entries[0].name, "a");
        assert_eq!(entries[0].file, "a.ko");
        assert_eq!(entries[1].deps, ["a"]);
    }

    #[test]
    fn loading_an_unknown_module_is_not_found_and_inserts_nothing() {
        let t = ModuleTable::parse(TABLE).unwrap();
        let mut calls = 0;
        let mut insert = |_: &Path, _: &str| {
            calls += 1;
            Ok(())
        };
        let error = load(&t, "net-pf-10", "", &mut insert).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotFound);
        assert_eq!(calls, 0);
    }

    #[test]
    fn a_failed_insert_stops_the_load_and_is_returned() {
        let t = ModuleTable::parse(TABLE).unwrap();
        let mut calls: Vec<PathBuf> = vec![];
        let mut insert = |p: &Path, _: &str| {
            calls.push(p.to_owned());
            if p.ends_with("cfg80211.ko") {
                Err(io::Error::new(ErrorKind::PermissionDenied, "bad signature"))
            } else {
                Ok(())
            }
        };
        let error = load(&t, "brcmfmac-cyw", "", &mut insert).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        assert_eq!(error.to_string(), "bad signature");
        assert_eq!(
            calls,
            [
                Path::new("/lib/modules/brcmutil.ko"),
                Path::new("/lib/modules/rfkill.ko"),
                Path::new("/lib/modules/cfg80211.ko"),
            ]
        );
    }

    #[test]
    fn load_returns_the_modules_it_inserted_and_not_those_already_there() {
        let t = ModuleTable::parse(TABLE).unwrap();
        let mut insert = |p: &Path, _: &str| {
            if p.ends_with("rfkill.ko") || p.ends_with("brcmfmac.ko") {
                Err(ErrorKind::AlreadyExists.into())
            } else {
                Ok(())
            }
        };
        let inserted = load(&t, "brcmfmac_cyw", "", &mut insert).unwrap();
        assert_eq!(inserted, ["brcmutil", "cfg80211", "brcmfmac-cyw"]);

        let mut all_there = |_: &Path, _: &str| Err(ErrorKind::AlreadyExists.into());
        assert!(load(&t, "brcmfmac", "", &mut all_there).unwrap().is_empty());
    }

    #[test]
    fn the_module_file_comes_from_the_table_and_not_from_the_name_asked_for() {
        let t = ModuleTable::parse("wifi_fw\tvendor-fw.ko\n").unwrap();
        let mut calls = vec![];
        let mut insert = |p: &Path, params: &str| {
            calls.push((p.to_owned(), params.to_owned()));
            Ok(())
        };
        assert_eq!(
            load(&t, "wifi-fw", "x=1", &mut insert).unwrap(),
            ["wifi_fw"]
        );
        assert_eq!(
            calls,
            [(Path::new(MODULE_DIR).join("vendor-fw.ko"), "x=1".to_owned())]
        );
    }
}
