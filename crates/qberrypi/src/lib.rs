//! qberrypi: everything above the kernel, in one executable.

pub mod config;
pub mod kmsg;
pub mod logbuf;

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
