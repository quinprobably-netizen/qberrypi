//! The device watch: the sockets that hear the home network's ARP, DHCP requests and mDNS
//! announcements, and the component future that feeds them to the [`Devices`] inventory.
//!
//! Three sockets are read together. ARP comes over a packet socket on the wireless interface for
//! the ethertype 0x0806 alone: a packet socket for all of IPv4 would copy every DNS packet of the
//! household and is not used. A device's DHCP DISCOVER and REQUEST are broadcasts, so a UDP socket
//! on port 67 hears them, and they carry the device's `chaddr`, its host name and the address it
//! asks for. mDNS announcements come to a UDP socket on port 5353 that has joined 224.0.0.251 on the
//! wireless interface.
//!
//! The component never ends. It waits for the interface to exist, opens the sockets, reads them and
//! hands what it hears to the inventory, and when a socket fails it closes everything, waits and
//! starts again from the wait for the interface. Without a wireless interface, as in QEMU, it
//! checks every 30 seconds and says so once, at debug level.
//!
//! Logs say what failed and never what was heard: a run of failures is one WARN line, and no line
//! holds a MAC, an address or a host name. The kernel's error text may name an operation but
//! not an address, and it is the only detail a line carries.

use std::convert::Infallible;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustix::net::{AddressFamily, RecvFlags, SocketFlags, SocketType, bind, socket_with, sockopt};
use tokio::io::unix::AsyncFd;
use tokio::net::UdpSocket;
use tokio::time::{Instant, MissedTickBehavior, interval_at, sleep};

use super::devices::{Devices, with_devices};
use super::frames::{Mac, parse_arp, parse_dhcp, parse_mdns};
use crate::alerts::AlertSink;
use crate::supervisor::Ended;
use crate::sys;

/// How long the component waits for an interface that is not there, and after a socket failed,
/// before it looks again.
pub const RETRY_EVERY: Duration = Duration::from_secs(30);

/// How often the inventory is told to check its learning deadline.
pub const TICK_EVERY: Duration = Duration::from_secs(30);

/// Where the kernel lists the interfaces.
const SYSFS_NET: &str = "/sys/class/net";

/// The Ethernet type of ARP.
const ETHERTYPE_ARP: u16 = 0x0806;

/// The port that a DHCP server listens on, which is where a client's broadcasts go.
const DHCP_PORT: u16 = 67;

/// The port of mDNS, for both the questions and the announcements.
const MDNS_PORT: u16 = 5353;

/// The mDNS group.
const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// How many bytes of an ARP frame are read; the message is 42 bytes, 46 with a VLAN tag.
const ARP_BUFFER: usize = 256;

/// How many bytes of a DHCP request or an mDNS datagram are read; a longer one is cut off.
const DATAGRAM_BUFFER: usize = 2048;

/// What the component has said already, so that a run of the same failure is one line.
#[derive(Default)]
struct Said {
    /// The interface was missing, said at debug level.
    missing: bool,
    /// The socket on port 67 would not open.
    dhcp: bool,
    /// The socket on port 5353 would not open.
    mdns: bool,
    /// The group could not be joined.
    join: bool,
    /// A socket failed, and nothing has been heard since.
    failed: bool,
}

/// Runs the device watch on the interface `iface`, which is `wlan0` on the board.
///
/// This future never completes: it only waits for the interface, opens the sockets, reads them,
/// and reopens them after a failure, and so it has no part in the 90 s rule that the supervisor
/// applies to a component that ends. Every [`TICK_EVERY`] it calls [`Devices::tick`], also while
/// it waits. Nothing but the [`Devices`] call holds the mutex, and never across a wait; the alerts
/// that a call makes are raised through `sink` after the mutex is released ([`with_devices`]).
///
/// When the interface is there, its hardware address is given to the inventory as the Pi's own.
/// A socket that fails to open for DHCP or mDNS, or an mDNS group that cannot be joined, costs one
/// WARN and the watch goes on with the sockets that opened; the group is joined on `iface` itself,
/// by its index, and not on whichever interface the default route uses. A failure of the ARP socket
/// or a failed read ends a round: one WARN for the run of failures, everything closed, a wait of
/// [`RETRY_EVERY`], and a new round from the wait for the interface.
pub async fn run(
    devices: Arc<Mutex<Devices>>,
    sink: Arc<dyn AlertSink>,
    iface: &'static str,
) -> Ended {
    run_in(devices, sink, iface, Path::new(SYSFS_NET), RETRY_EVERY).await
}

/// [`run`] with the place where the interfaces are listed, and the wait between rounds, given.
async fn run_in(
    devices: Arc<Mutex<Devices>>,
    sink: Arc<dyn AlertSink>,
    iface: &str,
    sysfs: &Path,
    retry: Duration,
) -> Ended {
    let sink = &*sink;
    let mut said = Said::default();
    loop {
        let (ifindex, mac) = loop {
            if let Some(found) = read_interface(sysfs, iface) {
                break found;
            }
            if !said.missing {
                said.missing = true;
                log::debug!("watch: the interface of the device watch is not there yet");
            }
            pause(&devices, sink, retry).await;
        };
        if let Some(mac) = mac {
            with(&devices, sink, |inventory| inventory.set_own_mac(mac));
        }
        let Err(error) = watch(&devices, sink, ifindex, &mut said).await;
        if !said.failed {
            said.failed = true;
            log::warn!("watch: a socket of the device watch failed, trying again: {error}");
        }
        pause(&devices, sink, retry).await;
    }
}

/// Waits `time`, and then tells the inventory to check its deadline.
async fn pause(devices: &Mutex<Devices>, sink: &dyn AlertSink, time: Duration) {
    sleep(time).await;
    with(devices, sink, Devices::tick);
}

/// Calls `call` with the inventory, which is locked for that call alone; what it makes alerts of
/// is raised through `sink` once the lock is released.
fn with<R>(
    devices: &Mutex<Devices>,
    sink: &dyn AlertSink,
    call: impl FnOnce(&mut Devices) -> R,
) -> R {
    with_devices(devices, sink, call)
}

/// The index and hardware address of the interface `iface` under `sysfs`; `None` if it has no
/// index there. An address that is not there or not readable is `None` inside: the watch can do
/// without it.
fn read_interface(sysfs: &Path, iface: &str) -> Option<(u32, Option<Mac>)> {
    let dir = sysfs.join(iface);
    let ifindex = fs::read_to_string(dir.join("ifindex"))
        .ok()?
        .trim()
        .parse()
        .ok()?;
    let mac = fs::read_to_string(dir.join("address"))
        .ok()
        .and_then(|text| text.trim().parse().ok());
    Some((ifindex, mac))
}

/// Opens the sockets for the interface with index `ifindex` and reads them until one fails.
///
/// Only a failure ends it: the error is that of the ARP socket's opening or of a read.
async fn watch(
    devices: &Mutex<Devices>,
    sink: &dyn AlertSink,
    ifindex: u32,
    said: &mut Said,
) -> io::Result<Infallible> {
    let arp = sys::async_fd(sys::packet_socket(ifindex, ETHERTYPE_ARP)?)?;
    let dhcp = open_udp(DHCP_PORT, None, &mut said.dhcp, &mut said.join);
    let mdns = open_udp(MDNS_PORT, Some(ifindex), &mut said.mdns, &mut said.join);

    let mut arp_buffer = [0u8; ARP_BUFFER];
    let mut dhcp_buffer = [0u8; DATAGRAM_BUFFER];
    let mut mdns_buffer = [0u8; DATAGRAM_BUFFER];
    let mut ticker = interval_at(Instant::now() + TICK_EVERY, TICK_EVERY);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            read = recv_frame(&arp, &mut arp_buffer) => {
                let len = read?;
                said.failed = false;
                if let Some(message) = parse_arp(&arp_buffer[..len]) {
                    with(devices, sink, |inventory| inventory.on_arp(&message));
                }
            }
            read = recv_datagram(dhcp.as_ref(), &mut dhcp_buffer) => {
                let len = read?;
                said.failed = false;
                if let Some(request) = parse_dhcp(&dhcp_buffer[..len]) {
                    with(devices, sink, |inventory| inventory.on_dhcp(&request));
                }
            }
            read = recv_datagram(mdns.as_ref(), &mut mdns_buffer) => {
                let len = read?;
                said.failed = false;
                with(devices, sink, |inventory| {
                    parse_mdns(&mdns_buffer[..len], &mut |addr, host| inventory.on_mdns(addr, host));
                });
            }
            _ = ticker.tick() => with(devices, sink, Devices::tick),
        }
    }
}

/// Reads one frame from a packet socket into `buffer` and says how long it is; a frame that does
/// not fit is cut off, and the length is that of what is in `buffer` (the first of the two
/// lengths that `recv` gives: the second is the size before any cutting and could index past the
/// buffer).
///
/// Dropping the future loses nothing: a frame is taken from the socket only by the call that
/// returns it.
async fn recv_frame(socket: &AsyncFd<OwnedFd>, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        let mut ready = socket.readable().await?;
        let read = ready.try_io(|fd| {
            rustix::net::recv(fd, &mut *buffer, RecvFlags::empty())
                .map(|(len, _)| len)
                .map_err(io::Error::from)
        });
        if let Ok(read) = read {
            return read;
        }
    }
}

/// Reads one datagram into `buffer` and says how long it is; with no socket it waits for ever.
///
/// Dropping the future loses nothing.
async fn recv_datagram(socket: Option<&UdpSocket>, buffer: &mut [u8]) -> io::Result<usize> {
    match socket {
        Some(socket) => socket.recv(buffer).await,
        None => std::future::pending().await,
    }
}

/// Opens a UDP socket on `0.0.0.0:port` that other sockets may share, which hears the broadcasts
/// and, when `join_on` is an interface index, the mDNS group on that interface.
///
/// A failure costs one WARN, unless `said_open` says it was said, and the result is `None`. A
/// failure of the join costs one too, unless `said_join` says so, and the socket is kept: it is
/// still bound to the port, and hears whatever reaches it.
fn open_udp(
    port: u16,
    join_on: Option<u32>,
    said_open: &mut bool,
    said_join: &mut bool,
) -> Option<UdpSocket> {
    let fd = match bound_udp(port) {
        Ok(fd) => fd,
        Err(error) => {
            if !*said_open {
                *said_open = true;
                log::warn!("watch: no socket for the device watch on UDP port {port}: {error}");
            }
            return None;
        }
    };
    if let Some(ifindex) = join_on
        && let Err(error) = sockopt::set_ip_add_membership_with_ifindex(
            &fd,
            &MDNS_GROUP,
            &Ipv4Addr::UNSPECIFIED,
            ifindex,
        )
        && !*said_join
    {
        *said_join = true;
        log::warn!("watch: the device watch could not join the mDNS group: {error}");
    }
    match into_tokio(fd) {
        Ok(socket) => Some(socket),
        Err(error) => {
            if !*said_open {
                *said_open = true;
                log::warn!("watch: no socket for the device watch on UDP port {port}: {error}");
            }
            None
        }
    }
}

/// A non-blocking UDP socket bound to `0.0.0.0:port` with `SO_REUSEADDR`.
fn bound_udp(port: u16) -> io::Result<OwnedFd> {
    let fd = socket_with(
        AddressFamily::INET,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )?;
    sockopt::set_socket_reuseaddr(&fd, true)?;
    bind(&fd, &SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))?;
    Ok(fd)
}

/// Gives a UDP socket to the runtime.
///
/// # Panics
///
/// Outside a tokio runtime.
fn into_tokio(fd: OwnedFd) -> io::Result<UdpSocket> {
    let socket = std::net::UdpSocket::from(fd);
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::UdpSocket as StdUdpSocket;
    use std::sync::PoisonError;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::time::timeout;

    use super::super::devices::KnownList;
    use crate::alerts::{Alert, NullSink};
    use crate::net::loopback_up;
    use crate::netlink::route::Route;
    use crate::wifi::eapol::{LinkSocket, build};

    /// The router of the network of the tests.
    const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

    /// An inventory that reads the clock of the runtime, which is the paused one when the test
    /// pauses it, in seconds.
    fn inventory() -> Arc<Mutex<Devices>> {
        let start = Instant::now();
        let clock = Arc::new(move || (start.elapsed().as_secs(), 1_800_000_000));
        Arc::new(Mutex::new(Devices::new(None, GATEWAY, clock)))
    }

    /// A sink that notes, for each alert it is given, whether the lock of the inventory was held
    /// at that moment, which it tries to take as any other caller would.
    struct LockProbe {
        /// The inventory whose lock is tried.
        devices: Arc<Mutex<Devices>>,
        /// How many alerts were given while the lock was held.
        while_locked: AtomicUsize,
        /// The kinds of the alerts that were given, in order.
        kinds: Mutex<Vec<&'static str>>,
    }

    impl LockProbe {
        /// A probe of `devices`.
        fn of(devices: &Arc<Mutex<Devices>>) -> Arc<Self> {
            Arc::new(LockProbe {
                devices: devices.clone(),
                while_locked: AtomicUsize::new(0),
                kinds: Mutex::new(Vec::new()),
            })
        }
    }

    impl AlertSink for LockProbe {
        fn raise(&self, alert: Alert) {
            if matches!(
                self.devices.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ) {
                self.while_locked.fetch_add(1, Ordering::Relaxed);
            }
            self.kinds
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(alert.kind);
        }
    }

    /// The address 192.0.2.`host`.
    fn ip(host: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, host)
    }

    /// The MAC `02:00:00:00:00:<last>`.
    fn mac(last: u8) -> Mac {
        Mac([2, 0, 0, 0, 0, last])
    }

    /// A made-up place for the interfaces, with `iface` in it: its index and its address.
    fn fake_sysfs(iface: &str, ifindex: u32, address: &str) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join(iface);
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("ifindex"), format!("{ifindex}\n")).unwrap();
        fs::write(dir.join("address"), format!("{address}\n")).unwrap();
        root
    }

    /// An Ethernet frame with an ARP message from `sender` with the address `sender_ip`.
    fn arp_frame(sender: Mac, sender_ip: Ipv4Addr) -> Vec<u8> {
        let mut message = vec![0, 1, 8, 0, 6, 4, 0, 1];
        message.extend_from_slice(&sender.0);
        message.extend_from_slice(&sender_ip.octets());
        message.extend_from_slice(&[0; 6]);
        message.extend_from_slice(&GATEWAY.octets());
        build([0xff; 6], sender.0, ETHERTYPE_ARP, &message)
    }

    /// A DHCP REQUEST from `chaddr` that asks for `wanted` and gives `host`.
    fn dhcp_request(chaddr: Mac, wanted: Ipv4Addr, host: &str) -> Vec<u8> {
        let mut message = vec![0u8; 236];
        message[..3].copy_from_slice(&[1, 1, 6]);
        message[28..34].copy_from_slice(&chaddr.0);
        message.extend_from_slice(&[99, 130, 83, 99]);
        message.extend_from_slice(&[53, 1, 3, 50, 4]);
        message.extend_from_slice(&wanted.octets());
        message.extend_from_slice(&[12, u8::try_from(host.len()).unwrap()]);
        message.extend_from_slice(host.as_bytes());
        message.push(255);
        message
    }

    /// An mDNS announcement that `host`.local is at `addr`.
    fn mdns_announcement(host: &str, addr: Ipv4Addr) -> Vec<u8> {
        let mut message = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        for label in [host, "local"] {
            message.push(u8::try_from(label.len()).unwrap());
            message.extend_from_slice(label.as_bytes());
        }
        // The root, an A record of the class IN with the cache-flush bit, a TTL, and 4 bytes.
        message.extend_from_slice(&[0, 0, 1, 0x80, 1, 0, 0, 0, 120, 0, 4]);
        message.extend_from_slice(&addr.octets());
        message
    }

    /// A logger that keeps what is logged, for the tests that install it. It is the only one of
    /// its process, as each of them runs in a process of its own.
    struct Capture(Mutex<Vec<String>>);

    impl Capture {
        fn lines(&self) -> Vec<String> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    impl log::Log for Capture {
        fn enabled(&self, _: &log::Metadata<'_>) -> bool {
            true
        }

        fn log(&self, record: &log::Record<'_>) {
            let mut lines = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            lines.push(format!("{} {}", record.level(), record.args()));
        }

        fn flush(&self) {}
    }

    /// Sends what the watch on `lo` hears from a printer at `.5` by ARP and mDNS and a tablet at
    /// `.6` by DHCP, once; and an ARP message from the Pi's own address first, which is no device.
    fn send_all(arp: &LinkSocket, udp: &StdUdpSocket) {
        arp.send(&arp_frame(mac(0xee), ip(9))).unwrap();
        arp.send(&arp_frame(mac(5), ip(5))).unwrap();
        // A frame that is longer than the buffer for it: it is cut, and is no message.
        arp.send(&build([0xff; 6], mac(7).0, ETHERTYPE_ARP, &[0; 400]))
            .unwrap();
        udp.send_to(&dhcp_request(mac(6), ip(6), "tablet"), "127.0.0.1:67")
            .unwrap();
        udp.send_to(&mdns_announcement("printer", ip(5)), "127.0.0.1:5353")
            .unwrap();
    }

    /// Waits up to five seconds for `done` to be true of the inventory, sending what a device
    /// sends every 50 ms meanwhile, as a datagram that came before a socket opened is lost.
    async fn feed_until(
        devices: &Mutex<Devices>,
        arp: &LinkSocket,
        udp: &StdUdpSocket,
        done: impl Fn(&Devices) -> bool,
    ) {
        let waited = timeout(Duration::from_secs(5), async {
            loop {
                send_all(arp, udp);
                sleep(Duration::from_millis(50)).await;
                if with(devices, &NullSink, |inventory| done(inventory)) {
                    return;
                }
            }
        })
        .await;
        assert!(waited.is_ok(), "the watch did not hear the messages in 5 s");
    }

    /// Whether the inventory has the two devices of `send_all`, with what the messages gave.
    fn has_both(devices: &Devices) -> bool {
        let view = devices.view();
        let find = |m: Mac| view.devices.iter().find(|device| device.mac == m).cloned();
        let (Some(printer), Some(tablet)) = (find(mac(5)), find(mac(6))) else {
            return false;
        };
        printer.ipv4 == [ip(5)]
            && printer.hostname.as_deref() == Some("printer")
            && tablet.ipv4 == [ip(6)]
            && tablet.hostname.as_deref() == Some("tablet")
    }

    #[tokio::test(start_paused = true)]
    async fn without_the_interface_the_watch_waits_for_ever_and_the_inventory_learns_nothing() {
        let devices = inventory();
        let mut watch = Box::pin(run(devices.clone(), Arc::new(NullSink), "nosuch0"));
        tokio::select! {
            ended = &mut watch => panic!("the device watch ended: {ended:?}"),
            () = sleep(Duration::from_secs(601)) => {}
        }
        // It kept the inventory's time while it waited, and nothing was heard, so nothing is
        // learned: the learning counts from the first device.
        assert_eq!(
            devices.lock().unwrap().view().known_list,
            KnownList::Waiting
        );
        // A device heard now is the one the learning counts from.
        with(&devices, &NullSink, |inventory| {
            inventory.on_arp(&crate::watch::frames::Arp {
                op: 1,
                sender_mac: mac(5),
                sender_ip: ip(5),
                target_ip: ip(5),
            });
        });
        // The inventory is told to check every 30 s, so the check after the 600 s is at 630.
        tokio::select! {
            ended = &mut watch => panic!("the device watch ended: {ended:?}"),
            () = sleep(Duration::from_secs(631)) => {}
        }
        assert_eq!(
            devices.lock().unwrap().view().known_list,
            KnownList::Learned
        );
        tokio::select! {
            ended = &mut watch => panic!("the device watch ended: {ended:?}"),
            () = sleep(Duration::from_secs(3600)) => {}
        }
    }

    #[test]
    fn an_interface_is_read_from_its_index_and_address() {
        let sysfs = fake_sysfs("wlan9", 7, "02:00:00:00:00:ee");
        assert_eq!(
            read_interface(sysfs.path(), "wlan9"),
            Some((7, Some(mac(0xee))))
        );
        assert_eq!(read_interface(sysfs.path(), "wlan8"), None);
        // An address that is no address leaves the index.
        fs::write(sysfs.path().join("wlan9/address"), "not an address\n").unwrap();
        assert_eq!(read_interface(sysfs.path(), "wlan9"), Some((7, None)));
        // An index that is no number is no interface.
        fs::write(sysfs.path().join("wlan9/ifindex"), "seven\n").unwrap();
        assert_eq!(read_interface(sysfs.path(), "wlan9"), None);
    }

    #[test]
    fn the_sockets_hear_what_the_devices_send() {
        crate::testns::run_inside("watch::devwatch::tests::ns_hearing");
    }

    #[tokio::test]
    #[ignore = "run by the_sockets_hear_what_the_devices_send, inside a namespace"]
    async fn ns_hearing() {
        if !crate::testns::inside() {
            return;
        }
        static CAPTURE: Capture = Capture(Mutex::new(Vec::new()));
        log::set_logger(&CAPTURE).unwrap();
        log::set_max_level(log::LevelFilter::Trace);
        let mut route = Route::open().unwrap();
        loopback_up(&mut route).await.unwrap();
        let lo = route.link("lo").await.unwrap().unwrap();

        // The interface's address, as the kernel lists it, is the Pi's own: here it is 02:00:..:ee,
        // and a frame from it is no device.
        let sysfs = fake_sysfs("lo", lo.index, "02:00:00:00:00:ee");
        let devices = inventory();
        let sink = LockProbe::of(&devices);
        // A known list with nobody on it: whoever the watch hears is new, and is raised.
        with(&devices, &NullSink, |inventory| {
            inventory.set_known(Vec::new())
        });
        let sysfs_path = sysfs.path().to_owned();
        let watching = tokio::spawn({
            let devices = devices.clone();
            let sink = sink.clone();
            async move { run_in(devices, sink, "lo", &sysfs_path, Duration::from_millis(50)).await }
        });

        let arp = LinkSocket::open(lo.index, ETHERTYPE_ARP).unwrap();
        let udp = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        feed_until(&devices, &arp, &udp, has_both).await;

        let view = devices.lock().unwrap().view();
        assert_eq!(view.known_list, KnownList::Received);
        // Two devices, the oldest sighting last, and not the Pi's own address.
        assert_eq!(view.devices.len(), 2, "{view:?}");
        assert!(view.devices.iter().all(|device| device.mac != mac(0xee)));
        // Each of the two was raised as new, by the watch, and never with the lock held.
        assert_eq!(*sink.kinds.lock().unwrap(), ["new_device", "new_device"]);
        assert_eq!(sink.while_locked.load(Ordering::Relaxed), 0);
        assert!(!watching.is_finished());
        // No warning, and not one line of the log holds anything that was heard.
        let lines = CAPTURE.lines();
        for line in &lines {
            assert!(!line.starts_with("WARN"), "{line}");
            for heard in ["192.0.2", "02:00:00", "printer", "tablet"] {
                assert!(!line.contains(heard), "{line}");
            }
        }
        watching.abort();
    }

    #[test]
    fn a_busy_port_is_one_warning_and_the_rest_goes_on() {
        crate::testns::run_inside("watch::devwatch::tests::ns_busy_port");
    }

    #[tokio::test]
    #[ignore = "run by a_busy_port_is_one_warning_and_the_rest_goes_on, inside a namespace"]
    async fn ns_busy_port() {
        if !crate::testns::inside() {
            return;
        }
        static CAPTURE: Capture = Capture(Mutex::new(Vec::new()));
        log::set_logger(&CAPTURE).unwrap();
        log::set_max_level(log::LevelFilter::Trace);
        let mut route = Route::open().unwrap();
        loopback_up(&mut route).await.unwrap();
        let lo = route.link("lo").await.unwrap().unwrap();
        // Somebody holds port 67 and shares it with nobody.
        let _squatter = StdUdpSocket::bind("0.0.0.0:67").unwrap();

        let sysfs = fake_sysfs("lo", lo.index, "02:00:00:00:00:ee");
        let devices = inventory();
        let sink = LockProbe::of(&devices);
        let sysfs_path = sysfs.path().to_owned();
        let watching = tokio::spawn({
            let devices = devices.clone();
            let sink = sink.clone();
            async move { run_in(devices, sink, "lo", &sysfs_path, Duration::from_millis(50)).await }
        });
        let arp = LinkSocket::open(lo.index, ETHERTYPE_ARP).unwrap();
        let udp = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        // ARP and mDNS are heard, and the device that DHCP would have given is not.
        feed_until(&devices, &arp, &udp, |inventory| {
            let view = inventory.view();
            view.devices
                .iter()
                .any(|device| device.mac == mac(5) && device.hostname.as_deref() == Some("printer"))
        })
        .await;
        assert!(
            devices
                .lock()
                .unwrap()
                .view()
                .devices
                .iter()
                .all(|device| device.mac != mac(6))
        );
        assert!(!watching.is_finished());
        let lines = CAPTURE.lines();
        let warnings: Vec<&String> = lines.iter().filter(|l| l.starts_with("WARN")).collect();
        assert_eq!(warnings.len(), 1, "{lines:?}");
        assert!(warnings[0].contains("port 67"), "{}", warnings[0]);
        watching.abort();
    }

    #[test]
    fn a_socket_that_will_not_open_is_one_warning_and_the_watch_reopens_later() {
        crate::testns::run_inside("watch::devwatch::tests::ns_reopening");
    }

    #[tokio::test]
    #[ignore = "run by a_socket_that_will_not_open_is_one_warning_and_the_watch_reopens_later, inside a namespace"]
    async fn ns_reopening() {
        if !crate::testns::inside() {
            return;
        }
        static CAPTURE: Capture = Capture(Mutex::new(Vec::new()));
        log::set_logger(&CAPTURE).unwrap();
        log::set_max_level(log::LevelFilter::Trace);
        let mut route = Route::open().unwrap();
        loopback_up(&mut route).await.unwrap();
        let lo = route.link("lo").await.unwrap().unwrap();

        // At first the interface the kernel lists has an index that no interface has.
        let sysfs = fake_sysfs("lo", 4_000_000, "02:00:00:00:00:ee");
        let devices = inventory();
        let sink = LockProbe::of(&devices);
        let sysfs_path = sysfs.path().to_owned();
        let watching = tokio::spawn({
            let devices = devices.clone();
            let sink = sink.clone();
            async move { run_in(devices, sink, "lo", &sysfs_path, Duration::from_millis(20)).await }
        });
        // Many rounds of failing, and one line.
        sleep(Duration::from_millis(500)).await;
        let lines = CAPTURE.lines();
        let warnings: Vec<&String> = lines.iter().filter(|l| l.starts_with("WARN")).collect();
        assert_eq!(warnings.len(), 1, "{lines:?}");
        assert!(!watching.is_finished());

        // Then the interface is there, and the next round opens the sockets.
        fs::write(sysfs.path().join("lo/ifindex"), format!("{}\n", lo.index)).unwrap();
        let arp = LinkSocket::open(lo.index, ETHERTYPE_ARP).unwrap();
        let udp = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        feed_until(&devices, &arp, &udp, has_both).await;
        assert_eq!(
            CAPTURE
                .lines()
                .iter()
                .filter(|line| line.starts_with("WARN"))
                .count(),
            1
        );
        watching.abort();
    }
}
