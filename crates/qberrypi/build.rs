//! Bakes the build time into the executable. The Pi has no battery-backed
//! clock, so init uses this as the earliest time the clock may show.

use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    println!("cargo:rerun-if-env-changed=QBERRYPI_BUILD_EPOCH");
    let epoch = std::env::var("QBERRYPI_BUILD_EPOCH")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        });
    println!("cargo:rustc-env=QBERRYPI_BUILD_EPOCH={epoch}");
}
