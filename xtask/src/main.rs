//! Development tasks for qberrypi. Run as `cargo xtask <command>`.

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};

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

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Fetch => bail!("fetch: not implemented"),
        Command::Build => bail!("build: not implemented"),
        Command::QemuTest => bail!("qemu-test: not implemented"),
        Command::Deploy => bail!("deploy: not implemented"),
        Command::Collect => bail!("collect: not implemented"),
    }
}
