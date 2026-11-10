//! The one executable of the system.
//!
//! The kernel starts it twice over: once as PID 1, to boot and run the
//! system, and again each time it wants a module loaded.

use std::fs::{self, File};
use std::io::{self, Write};

use qberrypi::modules::MODULE_LIST;
use qberrypi::{init, modhelper, sys};

/// Where the module helper reports, so that its lines land in the kernel log.
const KERNEL_LOG: &str = "/dev/kmsg";

fn main() {
    if std::process::id() == 1 {
        init::run();
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let table = fs::read_to_string(MODULE_LIST);
    let mut kmsg: Box<dyn Write> = match File::options().write(true).open(KERNEL_LOG) {
        Ok(kmsg) => Box::new(kmsg),
        Err(_) => Box::new(io::sink()),
    };
    let status = modhelper::run_with_table(table, &args, &mut sys::insert_module, kmsg.as_mut());
    std::process::exit(status);
}
