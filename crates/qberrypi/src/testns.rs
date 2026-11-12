//! Runs a test inside a fresh user and network namespace.
//!
//! A test that changes a link, an address or a route must never do it to the
//! machine the tests run on. It is written as an ignored test that returns at
//! once unless [`inside`] is true, and a normal test calls [`run_inside`] to run
//! just that one in its own namespace: `unshare` makes the namespace, maps the
//! user to root inside it, and starts this same test binary there.

use std::fs;
use std::process::Command;

/// Set in the environment of the test binary that `run_inside` starts.
const VARIABLE: &str = "QBERRYPI_TEST_NAMESPACE";

/// Runs the ignored test `test_path` in a new user and network namespace.
///
/// Panics, showing what the test printed, unless it ran and passed.
pub fn run_inside(test_path: &str) {
    let test_binary = std::env::current_exe().expect("the path of the test binary");
    let output = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "--"])
        .arg(test_binary)
        .args(["--exact", test_path])
        .args(["--ignored", "--nocapture", "--test-threads=1"])
        .env(VARIABLE, "1")
        .output()
        .expect("starting unshare");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "{test_path} failed inside the namespace ({}); if unshare itself was refused, this machine does not allow unprivileged user namespaces\n--- stdout\n{stdout}\n--- stderr\n{stderr}",
        output.status,
    );
    // A path that names no test also exits with success, having run nothing.
    assert!(
        stdout.contains("1 passed"),
        "{test_path} did not run inside the namespace\n--- stdout\n{stdout}"
    );
}

/// Whether this is the test binary that `run_inside` started.
pub fn inside() -> bool {
    std::env::var_os(VARIABLE).is_some()
}

/// The destination and gateway that `/proc/net/route` lists for each route of `iface`.
///
/// Both are as the kernel prints them: eight hex digits, the address's bytes
/// read as one native-endian integer.
pub fn routes_of(iface: &str) -> Vec<(String, String)> {
    let table = fs::read_to_string("/proc/net/route").expect("reading /proc/net/route");
    table
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let (name, destination, gateway) = (fields.next()?, fields.next()?, fields.next()?);
            (name == iface).then(|| (destination.to_owned(), gateway.to_owned()))
        })
        .collect()
}
