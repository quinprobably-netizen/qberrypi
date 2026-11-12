//! Route netlink: the messages that set up a link, an address and a default
//! route, and a socket that sends them.

use std::io;
use std::net::Ipv4Addr;

use super::{
    MsgBuilder, NLM_F_ACK, NLM_F_CREATE, NLM_F_REPLACE, NLM_F_REQUEST, RequestError, find,
    socket::NlSocket,
};
use crate::config::Ipv4Cidr;
use crate::sys::NetlinkProtocol;

/// Message type: a request for a link.
const RTM_GETLINK: u16 = 18;
/// Message type: a request to change a link.
const RTM_SETLINK: u16 = 19;
/// Message type: a request to add an address.
const RTM_NEWADDR: u16 = 20;
/// Message type: a request to add a route.
const RTM_NEWROUTE: u16 = 24;

/// Link attribute: the hardware address.
const IFLA_ADDRESS: u16 = 1;
/// Link attribute: the name.
const IFLA_IFNAME: u16 = 3;
/// Address attribute: the address, which on a link that is not point-to-point is the interface's own.
const IFA_ADDRESS: u16 = 1;
/// Address attribute: the interface's own address.
const IFA_LOCAL: u16 = 2;
/// Address attribute: the broadcast address.
const IFA_BROADCAST: u16 = 4;
/// Route attribute: the interface to send out of.
const RTA_OIF: u16 = 4;
/// Route attribute: the next hop.
const RTA_GATEWAY: u16 = 5;

/// Interface flag: the link is administratively up.
const IFF_UP: u32 = 0x1;
/// Interface flag: the link has a carrier.
const IFF_LOWER_UP: u32 = 0x1_0000;

/// Address family: IPv4.
const AF_INET: u8 = 2;
/// The routing table that holds the default route.
const RT_TABLE_MAIN: u8 = 254;
/// Route protocol: set by an administrator, not learned.
const RTPROT_STATIC: u8 = 4;
/// Route type: the packets go to the next hop.
const RTN_UNICAST: u8 = 1;

/// The size of the family header of a link message, `ifinfomsg`.
const IFINFOMSG_LEN: usize = 16;

/// The error number for a link that does not exist.
const ENODEV: i32 = 19;

/// What the kernel says about a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Link {
    /// The number that names the link in requests.
    pub index: u32,
    /// The `IFF_` flags.
    pub flags: u32,
    /// The hardware address; zeros if the link has none.
    pub mac: [u8; 6],
}

impl Link {
    /// Whether the link has been set up (`IFF_UP`).
    pub fn is_up(&self) -> bool {
        self.flags & IFF_UP != 0
    }

    /// Whether the link has a carrier (`IFF_LOWER_UP`).
    pub fn has_carrier(&self) -> bool {
        self.flags & IFF_LOWER_UP != 0
    }
}

/// A request for the link named `name`.
pub fn get_link(name: &str) -> MsgBuilder {
    MsgBuilder::new(RTM_GETLINK, NLM_F_REQUEST | NLM_F_ACK)
        .header(&[0; IFINFOMSG_LEN])
        .attr_str(IFLA_IFNAME, name)
}

/// Reads the payload of a message that describes a link.
///
/// `None` if it is too short to be one, or names an index that no link has.
pub fn parse_link(payload: &[u8]) -> Option<Link> {
    let ifinfomsg = payload.get(..IFINFOMSG_LEN)?;
    let index = i32::from_ne_bytes(ifinfomsg[4..8].try_into().ok()?);
    let flags = u32::from_ne_bytes(ifinfomsg[8..12].try_into().ok()?);
    let mac = find(&payload[IFINFOMSG_LEN..], IFLA_ADDRESS)
        .and_then(|attr| attr.mac())
        .unwrap_or_default();
    Some(Link {
        index: u32::try_from(index).ok()?,
        flags,
        mac,
    })
}

/// A request to set the link with index `index` up.
pub fn set_link_up(index: u32) -> MsgBuilder {
    let mut ifinfomsg = [0; IFINFOMSG_LEN];
    ifinfomsg[4..8].copy_from_slice(&index.to_ne_bytes());
    ifinfomsg[8..12].copy_from_slice(&IFF_UP.to_ne_bytes()); // flags
    ifinfomsg[12..16].copy_from_slice(&IFF_UP.to_ne_bytes()); // the ones to change
    MsgBuilder::new(RTM_SETLINK, NLM_F_REQUEST | NLM_F_ACK).header(&ifinfomsg)
}

/// A request to give a link an IPv4 address, replacing the same address if it is there.
pub fn new_address(index: u32, address: Ipv4Cidr, broadcast: Ipv4Addr) -> MsgBuilder {
    let mut ifaddrmsg = [0; 8];
    ifaddrmsg[0] = AF_INET;
    ifaddrmsg[1] = address.prefix;
    ifaddrmsg[4..8].copy_from_slice(&index.to_ne_bytes());
    MsgBuilder::new(
        RTM_NEWADDR,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
    )
    .header(&ifaddrmsg)
    .attr(IFA_LOCAL, &address.addr.octets())
    .attr(IFA_ADDRESS, &address.addr.octets())
    .attr(IFA_BROADCAST, &broadcast.octets())
}

/// A request for the default route to go through `gateway`, out of a link; it replaces the one there.
pub fn new_default_route(index: u32, gateway: Ipv4Addr) -> MsgBuilder {
    let mut rtmsg = [0; 12];
    rtmsg[0] = AF_INET;
    // The destination and source lengths and the type of service stay zero.
    rtmsg[4] = RT_TABLE_MAIN;
    rtmsg[5] = RTPROT_STATIC;
    // The scope is zero: the destination is not on the link.
    rtmsg[7] = RTN_UNICAST;
    MsgBuilder::new(
        RTM_NEWROUTE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
    )
    .header(&rtmsg)
    .attr(RTA_GATEWAY, &gateway.octets())
    .attr_u32(RTA_OIF, index)
}

/// A route netlink socket.
pub struct Route(NlSocket);

impl Route {
    /// Opens the socket.
    ///
    /// # Panics
    ///
    /// Outside a tokio runtime.
    pub fn open() -> io::Result<Self> {
        NlSocket::open(NetlinkProtocol::Route).map(Self)
    }

    /// Opens the socket with a thread of its own to send its requests, for a link that is a radio's:
    /// the kernel runs the driver's part of setting it up, or of giving it an address, inside the
    /// send, and a driver can take seconds over it. See [`NlSocket::open_offloaded`].
    ///
    /// # Panics
    ///
    /// Outside a tokio runtime.
    pub fn open_offloaded() -> io::Result<Self> {
        NlSocket::open_offloaded(NetlinkProtocol::Route).map(Self)
    }

    /// Whether the socket's requests are sent by a thread of its own.
    #[cfg(test)]
    pub(crate) fn is_offloaded(&self) -> bool {
        self.0.is_offloaded()
    }

    /// The link called `name`, or `None` if there is none.
    pub async fn link(&mut self, name: &str) -> Result<Option<Link>, RequestError> {
        match self.0.request(get_link(name)).await {
            Ok(payloads) => {
                let first = payloads.first().ok_or(RequestError::Malformed)?;
                parse_link(first).map(Some).ok_or(RequestError::Malformed)
            }
            Err(error) if error.errno() == Some(ENODEV) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Sets the link with index `index` up.
    pub async fn set_up(&mut self, index: u32) -> Result<(), RequestError> {
        self.0.request(set_link_up(index)).await.map(drop)
    }

    /// Gives the link an address; one that is there already is replaced.
    pub async fn set_address(
        &mut self,
        index: u32,
        address: Ipv4Cidr,
        broadcast: Ipv4Addr,
    ) -> Result<(), RequestError> {
        self.0
            .request(new_address(index, address, broadcast))
            .await
            .map(drop)
    }

    /// Sets the default route to go through `gateway` out of the link; one that is there is replaced.
    pub async fn set_default_route(
        &mut self,
        index: u32,
        gateway: Ipv4Addr,
    ) -> Result<(), RequestError> {
        self.0
            .request(new_default_route(index, gateway))
            .await
            .map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::Ipv4Cidr;
    use crate::netlink::socket::send_blocking;
    use crate::netlink::{NLM_F_DUMP, NLM_F_REQUEST, messages};
    use hex_literal::hex;
    use std::net::UdpSocket;
    use std::sync::{Arc, Mutex};

    #[test]
    fn route_messages_match_the_kernels_layout() {
        let cidr = Ipv4Cidr {
            addr: "192.0.2.53".parse().unwrap(),
            prefix: 24,
        };
        assert_eq!(
            get_link("wlan0").finish(7),
            hex!(
                "2c000000120005000700000000000000000000000000000000000000000000000a000300776c616e30000000"
            )
        );
        assert_eq!(
            set_link_up(3).finish(7),
            hex!("2000000013000500070000000000000000000000030000000100000001000000")
        );
        assert_eq!(
            new_address(3, cidr, "192.0.2.255".parse().unwrap()).finish(7),
            hex!(
                "30000000140005050700000000000000021800000300000008000200c000023508000100c000023508000400c00002ff"
            )
        );
        assert_eq!(
            new_default_route(3, "192.0.2.1".parse().unwrap()).finish(7),
            hex!(
                "2c00000018000505070000000000000002000000fe0400010000000008000500c00002010800040003000000"
            )
        );
    }

    /// The payload of an `RTM_NEWLINK` reply: an `ifinfomsg`, then what `attributes` adds.
    fn link_reply(
        index: i32,
        flags: u32,
        attributes: impl FnOnce(MsgBuilder) -> MsgBuilder,
    ) -> Vec<u8> {
        let mut ifinfomsg = [0u8; 16];
        ifinfomsg[2..4].copy_from_slice(&1u16.to_ne_bytes()); // ARPHRD_ETHER
        ifinfomsg[4..8].copy_from_slice(&index.to_ne_bytes());
        ifinfomsg[8..12].copy_from_slice(&flags.to_ne_bytes());
        let datagram = attributes(MsgBuilder::new(16, 0).header(&ifinfomsg)).finish(0);
        messages(&datagram).next().unwrap().payload.to_vec()
    }

    #[test]
    fn a_link_reply_is_read() {
        let mac = hex!("b0b1b2b3b4b5");
        let up = link_reply(3, 0x11043, |reply| reply.attr_str(3, "wlan0").attr(1, &mac));
        let link = parse_link(&up).unwrap();
        assert_eq!(
            link,
            Link {
                index: 3,
                flags: 0x11043,
                mac
            }
        );
        assert!(link.is_up());
        assert!(link.has_carrier());

        let down = parse_link(&link_reply(3, 0x1002, |reply| reply.attr(1, &mac))).unwrap();
        assert!(!down.is_up());
        assert!(!down.has_carrier());

        // Up without a carrier: the two flags are read separately.
        let no_carrier = parse_link(&link_reply(3, 0x1003, |reply| reply)).unwrap();
        assert!(no_carrier.is_up());
        assert!(!no_carrier.has_carrier());

        // No address, or one that is not six bytes: zeros.
        let nameless = link_reply(3, 0x1, |reply| reply.attr_str(3, "wlan0"));
        assert_eq!(parse_link(&nameless).unwrap().mac, [0; 6]);
        let odd = link_reply(3, 0x1, |reply| reply.attr(1, &mac[..4]));
        assert_eq!(parse_link(&odd).unwrap().mac, [0; 6]);

        // Too short to hold an `ifinfomsg`, or an index that no link has.
        assert_eq!(parse_link(&up[..10]), None);
        assert_eq!(parse_link(&[]), None);
        assert_eq!(parse_link(&link_reply(-1, 0x1, |reply| reply)), None);
    }

    #[test]
    fn an_offloaded_route_sends_from_its_own_thread() {
        crate::testns::run_inside("netlink::route::tests::ns_offloaded_route");
    }

    #[tokio::test]
    #[ignore = "run by an_offloaded_route_sends_from_its_own_thread, inside a namespace"]
    async fn ns_offloaded_route() {
        if !crate::testns::inside() {
            return;
        }
        // The seam records the thread of every send; the sends are the real ones.
        let ran_on = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&ran_on);
        let mut route = Route(
            NlSocket::open_offloaded_with(
                NetlinkProtocol::Route,
                Box::new(move |fd, bytes| {
                    let thread = std::thread::current();
                    record
                        .lock()
                        .unwrap()
                        .push((thread.id(), thread.name().map(str::to_owned)));
                    send_blocking(fd, bytes)
                }),
            )
            .unwrap(),
        );
        assert!(route.is_offloaded());
        let lo = route.link("lo").await.unwrap().unwrap();
        assert!(!lo.is_up());
        route.set_up(lo.index).await.unwrap();
        assert!(route.link("lo").await.unwrap().unwrap().is_up());

        let ran_on = ran_on.lock().unwrap();
        assert_eq!(ran_on.len(), 3);
        // One thread, not this one, and the one that is named for what it does.
        assert_ne!(ran_on[0].0, std::thread::current().id());
        assert!(ran_on.iter().all(|sender| sender == &ran_on[0]));
        assert_eq!(ran_on[0].1.as_deref(), Some("nl send"));

        // The socket that `open_offloaded` opens is the same kind, and an inline one is not.
        assert!(Route::open_offloaded().unwrap().is_offloaded());
        assert!(!Route::open().unwrap().is_offloaded());
    }

    #[test]
    fn the_kernel_takes_the_route_messages() {
        crate::testns::run_inside("netlink::route::tests::ns_route");
    }

    #[tokio::test]
    #[ignore = "run by the_kernel_takes_the_route_messages, inside a namespace"]
    async fn ns_route() {
        if !crate::testns::inside() {
            return;
        }
        let mut route = Route::open().unwrap();
        let lo = route.link("lo").await.unwrap().unwrap();
        assert!(!lo.is_up()); // a new namespace's lo is down
        assert!(route.link("nosuch0").await.unwrap().is_none());
        route.set_up(lo.index).await.unwrap();
        assert!(route.link("lo").await.unwrap().unwrap().is_up());

        let cidr = Ipv4Cidr {
            addr: "192.0.2.53".parse().unwrap(),
            prefix: 24,
        };
        let broadcast = "192.0.2.255".parse().unwrap();
        route.set_address(lo.index, cidr, broadcast).await.unwrap();
        route.set_address(lo.index, cidr, broadcast).await.unwrap(); // replace: twice is fine

        let off_link = route
            .set_default_route(lo.index, "198.51.100.1".parse().unwrap())
            .await
            .unwrap_err();
        assert_eq!(off_link.errno(), Some(101));
        assert!(
            off_link.to_string().contains("Nexthop has invalid gateway"),
            "{off_link}"
        );
        let gateway = "192.0.2.1".parse().unwrap();
        route.set_default_route(lo.index, gateway).await.unwrap();
        route.set_default_route(lo.index, gateway).await.unwrap();

        // A dump ends at NLMSG_DONE.
        let dump = route
            .0
            .request(MsgBuilder::new(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP).header(&[0; 16]))
            .await
            .unwrap();
        let links: Vec<Link> = dump.iter().filter_map(|p| parse_link(p)).collect();
        assert!(!links.is_empty());
        assert!(links.iter().any(|link| link.index == lo.index));

        // The route is in the kernel's table, as the kernel prints it.
        let routes = crate::testns::routes_of("lo");
        assert!(
            routes.contains(&("00000000".to_owned(), "010200C0".to_owned())),
            "{routes:?}"
        );
        // The address is there: it can be bound.
        UdpSocket::bind("192.0.2.53:0").unwrap();
    }
}
