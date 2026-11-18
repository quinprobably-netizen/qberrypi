//! Runs a test inside a fresh user and network namespace.
//!
//! A test that changes a link, an address or a route must never do it to the
//! machine the tests run on. It is written as an ignored test that returns at
//! once unless [`inside`] is true, and a normal test calls [`run_inside`] to run
//! just that one in its own namespace: `unshare` makes the namespace, maps the
//! user to root inside it, and starts this same test binary there.
//!
//! Some machines refuse an unprivileged user namespace: Ubuntu from 24.04 on
//! (AppArmor's `kernel.apparmor_restrict_unprivileged_userns`), a container
//! whose seccomp filter forbids `unshare`, or `user.max_user_namespaces` at 0.
//! There the test is skipped with a note on standard error, the way the tests
//! that need root skip themselves without it, unless [`REQUIRED`] is set: CI sets
//! it, so that a runner that lost the namespaces fails instead of passing
//! without having run them.

use std::fs;
use std::process::Command;
use std::sync::OnceLock;

/// Set in the environment of the test binary that `run_inside` starts.
const VARIABLE: &str = "QBERRYPI_TEST_NAMESPACE";

/// When set, a machine that refuses the namespace fails the test instead of skipping it.
const REQUIRED: &str = "QBERRYPI_REQUIRE_NAMESPACES";

/// Runs the ignored test `test_path` in a new user and network namespace.
///
/// Panics, showing what the test printed, unless it ran and passed, or the
/// machine refuses the namespace and [`REQUIRED`] is not set.
pub fn run_inside(test_path: &str) {
    if let Some(refusal) = refusal() {
        assert!(
            std::env::var_os(REQUIRED).is_none(),
            "{test_path} cannot run: this machine refuses an unprivileged user and network namespace, and {REQUIRED} is set\n{refusal}"
        );
        eprintln!(
            "note: {test_path} skipped: this machine refuses an unprivileged user and network namespace\n{refusal}"
        );
        return;
    }
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
    // The namespace itself was made a moment ago, by the probe: a failure here is the test's.
    assert!(
        output.status.success(),
        "{test_path} failed inside the namespace ({})\n--- stdout\n{stdout}\n--- stderr\n{stderr}",
        output.status,
    );
    // A path that names no test also exits with success, having run nothing.
    assert!(
        stdout.contains("1 passed"),
        "{test_path} did not run inside the namespace\n--- stdout\n{stdout}"
    );
}

/// Why this machine will not make the namespace `run_inside` asks for, or `None` when it will.
///
/// The same `unshare` as `run_inside`'s, with `true` in place of the test, once
/// per test binary.
fn refusal() -> Option<&'static str> {
    static REFUSAL: OnceLock<Option<String>> = OnceLock::new();
    REFUSAL
        .get_or_init(|| {
            match Command::new("unshare")
                .args(["--user", "--map-root-user", "--net", "--", "true"])
                .output()
            {
                Ok(output) if output.status.success() => None,
                Ok(output) => Some(format!(
                    "`unshare --user --map-root-user --net -- true` exited with {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim_end(),
                )),
                Err(error) => Some(format!("`unshare` could not be started: {error}")),
            }
        })
        .as_deref()
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
