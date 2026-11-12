//! The static network: the interface's address and default route, and what is
//! reported about it.

use std::fmt;
use std::net::Ipv4Addr;

use crate::config::{self, Ipv4Cidr};
use crate::netlink::{RequestError, Route};

/// The loopback interface.
const LOOPBACK: &str = "lo";

/// Why the network could not be set up.
#[derive(Debug)]
pub enum NetError {
    /// There is no interface of this name.
    NoInterface(String),
    /// The kernel did not do what was asked.
    Request(RequestError),
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoInterface(name) => write!(f, "no network interface named {name}"),
            Self::Request(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for NetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NoInterface(_) => None,
            Self::Request(error) => Some(error),
        }
    }
}

impl From<RequestError> for NetError {
    fn from(error: RequestError) -> Self {
        Self::Request(error)
    }
}

/// The broadcast address of an address's subnet: the host bits all set.
pub fn broadcast(address: Ipv4Cidr) -> Ipv4Addr {
    // A prefix of 32 leaves no host bits, which a shift by 32 cannot say.
    let host_bits = u32::MAX.checked_shr(u32::from(address.prefix)).unwrap_or(0);
    Ipv4Addr::from(u32::from(address.addr) | host_bits)
}

/// Sets the loopback interface up.
pub async fn loopback_up(route: &mut Route) -> Result<(), NetError> {
    let lo = route
        .link(LOOPBACK)
        .await?
        .ok_or_else(|| NetError::NoInterface(LOOPBACK.to_owned()))?;
    route.set_up(lo.index).await?;
    Ok(())
}

/// Gives an interface its address, and sets the default route through its gateway.
///
/// Doing it again with the same settings is no error. The interface is not
/// set up here.
pub async fn configure(route: &mut Route, ifname: &str, net: &config::Net) -> Result<(), NetError> {
    let link = route
        .link(ifname)
        .await?
        .ok_or_else(|| NetError::NoInterface(ifname.to_owned()))?;
    route
        .set_address(link.index, net.address, broadcast(net.address))
        .await?;
    route.set_default_route(link.index, net.gateway).await?;
    Ok(())
}

/// How many echo requests the kernel has answered, from the text of `/proc/net/snmp`.
///
/// The file has two lines that start with `Icmp:`, the column names and then
/// the values; the columns are found by name. `None` if either is missing or
/// the two columns are not numbers.
pub fn icmp_echo_line(snmp: &str) -> Option<String> {
    let mut icmp = snmp
        .lines()
        .filter(|line| line.split_whitespace().next() == Some("Icmp:"));
    let (names, values) = (icmp.next()?, icmp.next()?);
    let column = |name: &str| -> Option<u64> {
        let at = names.split_whitespace().position(|column| column == name)?;
        values.split_whitespace().nth(at)?.parse().ok()
    };
    let requests = column("InEchos")?;
    let replies = column("OutEchoReps")?;
    Some(format!(
        "icmp: answered {replies} of {requests} echo requests"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::{Ipv4Cidr, Net};
    use std::net::UdpSocket;

    fn broadcast_of(addr: &str, prefix: u8) -> Ipv4Addr {
        broadcast(Ipv4Cidr {
            addr: addr.parse().unwrap(),
            prefix,
        })
    }

    #[test]
    fn the_broadcast_address_fills_the_host_bits() {
        assert_eq!(
            broadcast_of("192.0.2.53", 24),
            Ipv4Addr::new(192, 0, 2, 255)
        );
        assert_eq!(broadcast_of("192.0.2.53", 30), Ipv4Addr::new(192, 0, 2, 55));
        assert_eq!(
            broadcast_of("10.1.2.3", 8),
            Ipv4Addr::new(10, 255, 255, 255)
        );
        assert_eq!(broadcast_of("192.0.2.1", 1), Ipv4Addr::BROADCAST);
        // No host bits: the address itself. All host bits: the limited broadcast.
        assert_eq!(broadcast_of("192.0.2.53", 32), Ipv4Addr::new(192, 0, 2, 53));
        assert_eq!(broadcast_of("192.0.2.53", 0), Ipv4Addr::BROADCAST);
    }

    #[test]
    fn the_icmp_counters_are_read_by_column_name() {
        let snmp = "Ip: Forwarding DefaultTTL\nIp: 2 64\nIcmp: InMsgs InErrors InEchos InEchoReps OutMsgs OutEchos OutEchoReps\n\
                    Icmp: 9 0 7 0 7 0 6\nIcmpMsg: InType8 OutType0\nIcmpMsg: 7 6\n";
        assert_eq!(
            icmp_echo_line(snmp).as_deref(),
            Some("icmp: answered 6 of 7 echo requests")
        );
        // Columns are found by name, wherever they are.
        assert_eq!(
            icmp_echo_line("Icmp: OutEchoReps InEchos\nIcmp: 1 2\n").as_deref(),
            Some("icmp: answered 1 of 2 echo requests")
        );
        assert_eq!(icmp_echo_line("Ip: Forwarding\nIp: 2\n"), None);
        assert_eq!(icmp_echo_line("Icmp: InEchos OutEchoReps\nIcmp: 7\n"), None); // fewer values than names
        assert_eq!(icmp_echo_line("Icmp: InEchos\nIcmp: 7\n"), None); // no OutEchoReps column
        assert_eq!(
            icmp_echo_line("Icmp: InEchos OutEchoReps\nIcmp: 7 x\n"),
            None
        ); // not a number
        assert_eq!(icmp_echo_line(""), None);
    }

    #[test]
    fn the_kernel_takes_the_configuration() {
        crate::testns::run_inside("net::tests::ns_configure");
    }

    #[tokio::test]
    #[ignore = "run by the_kernel_takes_the_configuration, inside a namespace"]
    async fn ns_configure() {
        if !crate::testns::inside() {
            return;
        }
        let mut route = Route::open().unwrap();
        loopback_up(&mut route).await.unwrap();
        let net = Net {
            address: Ipv4Cidr {
                addr: "192.0.2.53".parse().unwrap(),
                prefix: 24,
            },
            gateway: "192.0.2.1".parse().unwrap(),
            time_servers: Vec::new(),
        };
        configure(&mut route, "lo", &net).await.unwrap();
        configure(&mut route, "lo", &net).await.unwrap();
        UdpSocket::bind("192.0.2.53:0").unwrap();
        let routes = crate::testns::routes_of("lo");
        assert!(
            routes.contains(&("00000000".to_owned(), "010200C0".to_owned())),
            "{routes:?}"
        );

        let missing = configure(&mut route, "nosuch0", &net).await;
        assert!(
            matches!(&missing, Err(NetError::NoInterface(name)) if name == "nosuch0"),
            "{missing:?}"
        );

        // A new namespace has answered no echo requests.
        let snmp = std::fs::read_to_string("/proc/net/snmp").unwrap();
        assert_eq!(
            icmp_echo_line(&snmp).as_deref(),
            Some("icmp: answered 0 of 0 echo requests")
        );
    }
}
