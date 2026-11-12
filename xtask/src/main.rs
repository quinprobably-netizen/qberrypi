//! Development tasks for qberrypi. Run as `cargo xtask <command>`.

use std::env;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

mod boottime;
mod build;
mod card;
mod cert;
mod cpio;
mod deb;
mod deploy;
mod fetch;
mod hashpw;
mod image;
mod latency;
mod lists;
mod panel;
mod pinned;
mod pins;
mod pios;
mod probe;
mod qemu;
mod sdimage;
mod slot;
#[cfg(test)]
mod standin;
mod update;
mod wifihint;

#[derive(Parser)]
#[command(name = "xtask", about = "Development tasks for qberrypi")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Download the pinned Raspberry Pi packages and extract what the image needs
    Fetch,
    /// Download the block lists the configuration names, for `build` to pack into the image
    FetchLists,
    /// Cross-compile qberrypi and write the boot folder to out/qberrypi/
    Build,
    /// Boot the built image under QEMU and check it behaves
    QemuTest {
        /// How many scenarios to boot at once; by default as many as the cores and free memory allow
        #[arg(long, value_name = "N")]
        jobs: Option<std::num::NonZeroUsize>,
    },
    /// Copy the build to a Pi running Raspberry Pi OS and boot it once
    Deploy {
        /// SSH alias of the Pi; without it, the environment variable QBERRYPI_HOST is used
        #[arg(long)]
        host: Option<String>,
        /// Make qberrypi the system that starts: refuses development switches, waits until the build answers
        #[arg(long)]
        permanent: bool,
    },
    /// Fetch the log qberrypi left on the Pi's boot partition
    Collect {
        /// SSH alias of the Pi; without it, the environment variable QBERRYPI_HOST is used
        #[arg(long)]
        host: Option<String>,
    },
    /// Make the card in this computer's reader start Raspberry Pi OS again (the way back from a permanent qberrypi)
    ReturnToPios {
        /// Where the card's boot partition is mounted
        #[arg(long, value_name = "DIR")]
        boot: PathBuf,
    },
    /// Copy the whole card in a USB reader into a file (compressed when its name ends in .zst);
    /// refuses anything but a removable USB /dev/sd* disk of 1 to 512 GiB that nothing uses, and
    /// does nothing without --yes
    BackupCard(card::BackupArgs),
    /// Write an image (decompressed when its name ends in .zst) onto the card in a USB reader and
    /// read it back to check it; refuses anything but a removable USB /dev/sd* disk of 1 to
    /// 512 GiB that nothing uses, and does nothing without --yes
    Flash(card::FlashArgs),
    /// Make a complete card image on this computer: the boot firmware and both slots, holding this
    /// build and your qberrypi.toml, slot a selected; flash it with `flash`. Refuses a
    /// configuration with a development switch on or no [api] section; the image holds the Wi-Fi
    /// passphrase and the API's key, so it goes to the git-ignored private/ folder
    Image(image::ImageArgs),
    /// Send this build to the Pi's other slot over the network, let it try the build, and say
    /// whether the Pi kept it or rolled back. The API password is read from standard input (never
    /// from a terminal); the Pi's certificate must be the one in qberrypi-tls.pem. Refuses what the
    /// Pi would refuse, and a configuration with a development switch on
    Update(update::UpdateArgs),
    /// Draw the front panel into a PNG, and with --push onto the Pi's 3.5-inch screen
    PanelPreview(panel::PreviewArgs),
    /// While a one-shot boot is running, ask the Pi's DNS and status servers what a client would
    /// and print which of the milestone's checks hold
    Probe {
        /// Which checks to run
        #[arg(long, value_enum)]
        stage: probe::Stage,
        /// The Pi's IPv4 address; without it, `net.address` of qberrypi.toml
        #[arg(long)]
        server: Option<Ipv4Addr>,
        /// How long to wait for the Pi to answer its first query, in seconds
        #[arg(long, default_value_t = 240)]
        wait_secs: u64,
        /// A name the blocklist holds, for the blocker stage
        #[arg(long, default_value = "doubleclick.net")]
        listed: String,
    },
    /// Measure power-on to the Pi's first DNS answer, from this computer
    BootTime {
        /// The Pi's IPv4 address; without it, `net.address` of qberrypi.toml
        #[arg(long)]
        server: Option<Ipv4Addr>,
    },
    /// Print the `password_hash` line for the Pi-hole API's login, from a password piped in on
    /// standard input
    HashPassword,
    /// Make qberrypi's own TLS certificate for the Pi-hole API, once, as qberrypi-tls.pem
    MakeCert {
        /// Replace a certificate that is there; qnet must then be pinned again
        #[arg(long)]
        replace: bool,
    },
    /// Measure from this PC the Pi's ping round trip and its DNS answer times (cached, blocked
    /// and forwarded), for comparison with the stock Pi-hole baseline
    Latency {
        /// The Pi's IPv4 address, or an SSH alias or host name; without it, `net.address` of
        /// qberrypi.toml
        #[arg(long)]
        host: Option<String>,
        /// How many samples each row takes
        #[arg(long, default_value_t = 200)]
        samples: usize,
        /// The pause between one sample and the next question, and ping's interval, in
        /// milliseconds
        #[arg(long, default_value_t = 200)]
        interval_ms: u64,
        /// The name the blocked row asks; without it, the first of a few well-known ad names
        /// that the Pi answers as blocked
        #[arg(long)]
        blocked: Option<String>,
        /// Also write the figures to this file as one JSON object
        #[arg(long)]
        json: Option<PathBuf>,
        /// Measure nothing: print the p50 and p95 of each row of the second JSON file against
        /// the first, with a verdict (stock first, then qberrypi). Fails, after printing, if any
        /// figure is slower; if either file lacks a figure the other has (an incomplete
        /// baseline); if the interval or the sample count differs; or if a file was written
        /// before lost answers were counted (re-run that pass, or add --received-only)
        #[arg(
            long,
            num_args = 2,
            action = clap::ArgAction::Set,
            value_names = ["A.json", "B.json"],
            conflicts_with_all = ["host", "samples", "interval_ms", "blocked", "json"]
        )]
        compare: Option<Vec<PathBuf>>,
        /// With --compare: compare both files' received-only figures (lost answers left out),
        /// which reads files written before lost answers were counted; this is not the
        /// acceptance comparison
        #[arg(
            long,
            requires = "compare",
            conflicts_with_all = ["host", "samples", "interval_ms", "blocked", "json"]
        )]
        received_only: bool,
    },
}

/// The Pi a command is for: the `--host` it was given, or else `QBERRYPI_HOST`.
fn host(flag: Option<String>) -> Result<String> {
    deploy::resolve_host(flag, env::var(deploy::HOST_VARIABLE).ok())
}

/// The top of the repository, where `vendor-cache/` and `out/` live.
fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the xtask crate sits one level below the workspace root")
}

/// The current time in seconds since 1970, which a build takes as its build time.
fn unix_time() -> Result<u64> {
    let since_1970 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("the clock of this machine is set before 1970")?;
    Ok(since_1970.as_secs())
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Fetch => fetch::run(workspace_root()),
        Command::FetchLists => lists::run(workspace_root(), unix_time()?),
        Command::Build => build::run(workspace_root(), unix_time()?).map(drop),
        Command::QemuTest { jobs } => qemu::run_all(workspace_root(), jobs),
        Command::Deploy {
            host: flag,
            permanent,
        } => deploy::deploy(&host(flag)?, permanent, workspace_root()),
        Command::Collect { host: flag } => {
            deploy::collect(&host(flag)?, workspace_root()).map(drop)
        }
        Command::ReturnToPios { boot } => {
            println!("{}", pios::return_to_pios(&boot)?);
            Ok(())
        }
        Command::BackupCard(args) => card::backup(
            &card::Host::real(workspace_root(), unix_time()?)?,
            &args,
            &mut std::io::stdout(),
        ),
        Command::Flash(args) => card::flash(
            &card::Host::real(workspace_root(), unix_time()?)?,
            &args,
            &mut std::io::stdout(),
        ),
        Command::Image(args) => image::run(workspace_root(), &args, &mut std::io::stdout()),
        Command::Update(args) => update::run(workspace_root(), &args, &mut std::io::stdout()),
        Command::PanelPreview(args) => panel::run(&args, workspace_root()),
        Command::BootTime { server } => boottime::run(server, workspace_root()),
        Command::HashPassword => hashpw::run(),
        Command::MakeCert { replace } => cert::run(replace, workspace_root()),
        Command::Probe {
            stage,
            server,
            wait_secs,
            listed,
        } => probe::run(stage, server, wait_secs, &listed, workspace_root()),
        Command::Latency {
            host,
            samples,
            interval_ms,
            blocked,
            json,
            compare,
            received_only,
        } => match compare.as_deref() {
            Some([a, b]) => latency::compare(a, b, received_only),
            // clap takes exactly two values for the flag, once.
            Some(_) => unreachable!("--compare has exactly two files"),
            None => latency::run(
                host.as_deref(),
                samples,
                Duration::from_millis(interval_ms),
                blocked.as_deref(),
                json.as_deref(),
                workspace_root(),
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("xtask").chain(args.iter().copied()))
    }

    #[test]
    fn make_cert_replaces_only_when_asked() {
        let Command::MakeCert { replace } = parse(&["make-cert"]).unwrap().command else {
            panic!("not the make-cert command");
        };
        assert!(!replace);
        let Command::MakeCert { replace } = parse(&["make-cert", "--replace"]).unwrap().command
        else {
            panic!("not the make-cert command");
        };
        assert!(replace);
        assert!(parse(&["make-cert", "--replace=yes"]).is_err());
        assert!(parse(&["make-cert", "qberrypi-tls.pem"]).is_err());
    }

    #[test]
    fn backup_card_takes_a_device_an_optional_file_and_waits_for_yes() {
        let Command::BackupCard(args) = parse(&["backup-card", "--device", "/dev/sdb"])
            .unwrap()
            .command
        else {
            panic!("not the backup-card command");
        };
        assert_eq!(
            (args.device, args.out, args.yes),
            (PathBuf::from("/dev/sdb"), None, false)
        );
        let Command::BackupCard(args) = parse(&[
            "backup-card",
            "--device",
            "/dev/sdb",
            "--out",
            "card.img.zst",
            "--yes",
        ])
        .unwrap()
        .command
        else {
            panic!("not the backup-card command");
        };
        assert_eq!(
            (args.out, args.yes),
            (Some(PathBuf::from("card.img.zst")), true)
        );
        // The device has no default, and nothing is taken but flags.
        assert!(parse(&["backup-card"]).is_err());
        assert!(parse(&["backup-card", "--yes"]).is_err());
        assert!(parse(&["backup-card", "/dev/sdb"]).is_err());
        assert!(parse(&["backup-card", "--device", "/dev/sdb", "--yes=true"]).is_err());
    }

    #[test]
    fn flash_takes_an_image_and_a_device_and_waits_for_yes() {
        let Command::Flash(args) = parse(&["flash", "--image", "a.img", "--device", "/dev/sdb"])
            .unwrap()
            .command
        else {
            panic!("not the flash command");
        };
        assert_eq!(
            (args.image, args.device, args.yes),
            (PathBuf::from("a.img"), PathBuf::from("/dev/sdb"), false)
        );
        let Command::Flash(args) = parse(&[
            "flash",
            "--device",
            "/dev/sdb",
            "--yes",
            "--image",
            "a.img.zst",
        ])
        .unwrap()
        .command
        else {
            panic!("not the flash command");
        };
        assert!(args.yes);
        // Both the image and the device are needed, and there is no --out.
        assert!(parse(&["flash", "--image", "a.img"]).is_err());
        assert!(parse(&["flash", "--device", "/dev/sdb"]).is_err());
        assert!(
            parse(&[
                "flash", "--image", "a.img", "--device", "/dev/sdb", "--out", "x"
            ])
            .is_err()
        );
    }

    #[test]
    fn image_takes_an_optional_file_and_an_optional_firmware_folder() {
        let Command::Image(args) = parse(&["image"]).unwrap().command else {
            panic!("not the image command");
        };
        assert_eq!((args.out, args.firmware), (None, None));
        let Command::Image(args) = parse(&["image", "--out", "card.img", "--firmware", "fw"])
            .unwrap()
            .command
        else {
            panic!("not the image command");
        };
        assert_eq!(
            (args.out, args.firmware),
            (Some(PathBuf::from("card.img")), Some(PathBuf::from("fw")))
        );
        // The other order of the flags is the same command.
        let Command::Image(args) = parse(&["image", "--firmware", "fw", "--out", "card.img"])
            .unwrap()
            .command
        else {
            panic!("not the image command");
        };
        assert_eq!(args.out, Some(PathBuf::from("card.img")));
    }

    #[test]
    fn image_takes_nothing_but_those_two_flags_and_each_needs_its_value() {
        assert!(parse(&["image", "card.img"]).is_err());
        assert!(parse(&["image", "--yes"]).is_err());
        assert!(parse(&["image", "--device", "/dev/sdb"]).is_err());
        assert!(parse(&["image", "--out"]).is_err());
        assert!(parse(&["image", "--firmware"]).is_err());
        assert!(parse(&["image", "--out", "a.img", "--out", "b.img"]).is_err());
    }

    #[test]
    fn update_with_no_flags_sends_to_the_configured_pi_by_the_firmware_trial() {
        let Command::Update(args) = parse(&["update"]).unwrap().command else {
            panic!("not the update command");
        };
        assert_eq!(
            args,
            update::UpdateArgs {
                server: None,
                allow_kernel: false,
                force: false,
                software_trial: false,
                rollback_drill: None,
            }
        );
    }

    #[test]
    fn update_takes_its_flags_in_any_order_and_a_drill_of_either_kind() {
        let Command::Update(args) = parse(&[
            "update",
            "--software-trial",
            "--server",
            "192.0.2.53",
            "--force",
            "--allow-kernel",
            "--rollback-drill",
            "panic",
        ])
        .unwrap()
        .command
        else {
            panic!("not the update command");
        };
        assert_eq!(
            args,
            update::UpdateArgs {
                server: Some(Ipv4Addr::new(192, 0, 2, 53)),
                allow_kernel: true,
                force: true,
                software_trial: true,
                rollback_drill: Some(update::Drill::Panic),
            }
        );
        let Command::Update(args) = parse(&["update", "--rollback-drill=stall"])
            .unwrap()
            .command
        else {
            panic!("not the update command");
        };
        assert_eq!(args.rollback_drill, Some(update::Drill::Stall));
    }

    #[test]
    fn update_refuses_what_is_not_one_of_its_flags_and_a_drill_of_no_known_kind() {
        for bad in [
            &["update", "192.0.2.53"][..],
            &["update", "--server"],
            &["update", "--server", "not-an-address"],
            &["update", "--server", "2001:db8::1"],
            &["update", "--rollback-drill"],
            &["update", "--rollback-drill", "crash"],
            &["update", "--rollback-drill", "Panic"],
            &["update", "--force=yes"],
            &["update", "--password", "hunter2"],
            &["update", "--yes"],
            &["update", "--server", "192.0.2.1", "--server", "192.0.2.2"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn compare_takes_two_files_and_measures_nothing() {
        let cli = parse(&["latency", "--compare", "stock.json", "qberrypi.json"]).unwrap();
        let Command::Latency { compare, .. } = cli.command else {
            panic!("not the latency command");
        };
        assert_eq!(
            compare,
            Some(vec![
                PathBuf::from("stock.json"),
                PathBuf::from("qberrypi.json")
            ])
        );
        // One file is too few, three too many, and the flag cannot be given twice.
        assert!(parse(&["latency", "--compare", "a.json"]).is_err());
        assert!(parse(&["latency", "--compare", "a.json", "b.json", "c.json"]).is_err());
        assert!(
            parse(&[
                "latency",
                "--compare",
                "a.json",
                "b.json",
                "--compare",
                "c.json",
                "d.json"
            ])
            .is_err()
        );
    }

    #[test]
    fn compare_refuses_the_flags_that_measure() {
        for flags in [
            ["--host", "192.0.2.1"],
            ["--samples", "5"],
            ["--interval-ms", "2"],
            ["--blocked", "ads.example.com"],
            ["--json", "out.json"],
        ] {
            let mut args = vec!["latency", "--compare", "a.json", "b.json"];
            args.extend(flags);
            let error = parse(&args)
                .err()
                .unwrap_or_else(|| panic!("{flags:?} was accepted"));
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::ArgumentConflict,
                "{flags:?}"
            );
            // The other order of the same arguments is refused as well.
            let mut args = vec!["latency"];
            args.extend(flags);
            args.extend(["--compare", "a.json", "b.json"]);
            assert!(parse(&args).is_err(), "{flags:?}");
        }
    }

    #[test]
    fn without_compare_the_latency_defaults_stand() {
        let cli = parse(&["latency", "--host", "192.0.2.1"]).unwrap();
        let Command::Latency {
            samples,
            interval_ms,
            compare,
            ..
        } = cli.command
        else {
            panic!("not the latency command");
        };
        assert_eq!((samples, interval_ms, compare), (200, 200, None));
    }

    #[test]
    fn received_only_belongs_to_compare() {
        let cli = parse(&[
            "latency",
            "--compare",
            "stock.json",
            "qberrypi.json",
            "--received-only",
        ])
        .unwrap();
        let Command::Latency {
            compare,
            received_only,
            ..
        } = cli.command
        else {
            panic!("not the latency command");
        };
        assert!(compare.is_some() && received_only);
        // The flag has no meaning for a measurement, whichever way round it is given.
        assert!(parse(&["latency", "--received-only"]).is_err());
        assert!(parse(&["latency", "--host", "192.0.2.1", "--received-only"]).is_err());
        // Without it, --compare reads the counted figures.
        let cli = parse(&["latency", "--compare", "a.json", "b.json"]).unwrap();
        let Command::Latency { received_only, .. } = cli.command else {
            panic!("not the latency command");
        };
        assert!(!received_only);
    }
}
