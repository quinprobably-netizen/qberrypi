//! qberrypi: everything above the kernel, in one executable.

pub mod alerts;
pub mod api;
pub mod bootpart;
pub mod config;
pub mod cpu;
pub mod dns;
pub mod fault;
pub mod https;
pub mod init;
pub mod kmsg;
pub mod lane;
pub mod led;
pub mod link;
pub mod lists;
pub mod live;
pub mod logbuf;
pub mod modhelper;
pub mod modules;
pub mod net;
pub mod netlink;
pub mod panel;
pub mod selftest;
pub mod services;
pub mod slots;
pub mod sntp;
pub mod stall;
pub mod status;
pub mod supervisor;
pub mod sys;
#[cfg(test)]
pub(crate) mod testns;
pub mod thermal;
pub mod update;
pub mod watch;
pub mod wifi;
pub mod wiring;

/// Crate version, shown in the boot banner.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Unix time of the build. The clock is never allowed to be earlier.
pub const BUILD_EPOCH: u64 = parse_u64(env!("QBERRYPI_BUILD_EPOCH"));

const fn parse_u64(text: &str) -> u64 {
    let bytes = text.as_bytes();
    let mut value = 0u64;
    let mut i = 0;
    while i < bytes.len() {
        assert!(
            bytes[i].is_ascii_digit(),
            "QBERRYPI_BUILD_EPOCH must be a number"
        );
        value = value * 10 + (bytes[i] - b'0') as u64;
        i += 1;
    }
    value
}
