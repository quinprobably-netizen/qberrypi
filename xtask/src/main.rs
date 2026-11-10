//! Development tasks for qberrypi. Run as `cargo xtask <command>`.

use std::env;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

mod build;
mod cpio;
mod deb;
mod deploy;
mod fetch;
mod pins;
mod qemu;
mod sdimage;

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
    /// Cross-compile qberrypi and write the boot folder to out/qberrypi/
    Build,
    /// Boot the built image under QEMU and check it behaves
    QemuTest,
    /// Copy the build to a Pi running Raspberry Pi OS and boot it once
    Deploy {
        /// SSH alias of the Pi; without it, the environment variable QBERRYPI_HOST is used
        #[arg(long)]
        host: Option<String>,
        /// Deploy a configuration that has debug.one_shot off and so stays on the Pi
        #[arg(long)]
        permanent: bool,
    },
    /// Fetch the log qberrypi left on the Pi's boot partition
    Collect {
        /// SSH alias of the Pi; without it, the environment variable QBERRYPI_HOST is used
        #[arg(long)]
        host: Option<String>,
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
        Command::Build => build::run(workspace_root(), unix_time()?).map(drop),
        Command::QemuTest => qemu::run_all(workspace_root()),
        Command::Deploy {
            host: flag,
            permanent,
        } => deploy::deploy(&host(flag)?, permanent, workspace_root()),
        Command::Collect { host: flag } => {
            deploy::collect(&host(flag)?, workspace_root()).map(drop)
        }
    }
}
