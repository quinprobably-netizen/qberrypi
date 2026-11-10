//! Development tasks for qberrypi. Run as `cargo xtask <command>`.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

mod build;
mod cpio;
mod deb;
mod fetch;
mod pins;

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
    Deploy,
    /// Fetch the log qberrypi left on the Pi's boot partition
    Collect,
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
        Command::QemuTest => bail!("qemu-test: not implemented"),
        Command::Deploy => bail!("deploy: not implemented"),
        Command::Collect => bail!("collect: not implemented"),
    }
}
