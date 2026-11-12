//! The link the handshake travels over: Ethernet frames, and a packet socket
//! that hears one ethertype.
//!
//! The frames carry handshake messages, so nothing here logs a frame's body or
//! formats it for `Debug`.

use std::fmt;
use std::io;
use std::os::fd::OwnedFd;

use qb_wpa2::MacAddr;
use rustix::net::{RecvFlags, SendFlags};
use tokio::io::unix::AsyncFd;

use crate::sys;

/// The ethertype of EAPOL frames, the ones the handshake is made of.
pub const ETHERTYPE_PAE: u16 = 0x888e;

/// The length of an Ethernet header: two addresses and an ethertype.
const HEADER_LEN: usize = 14;

/// The most a received frame can hold; a longer one is cut off.
///
/// A handshake message is a few hundred bytes. A frame of an ordinary
/// Ethernet link is at most 1514, with room to spare here.
const MAX_FRAME: usize = 2048;

/// An Ethernet frame, taken apart.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub ethertype: u16,
    pub body: &'a [u8],
}

// By hand, to leave out the body: a frame of the handshake is not for a log.
impl fmt::Debug for Frame<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Frame")
            .field("dst", &self.dst)
            .field("src", &self.src)
            .field("ethertype", &format_args!("{:#06x}", self.ethertype))
            .field("body", &format_args!("<{} bytes>", self.body.len()))
            .finish()
    }
}

/// Takes apart a whole Ethernet frame; `None` if it is shorter than a header.
pub fn parse(frame: &[u8]) -> Option<Frame<'_>> {
    let (dst, rest) = frame.split_first_chunk()?;
    let (src, rest) = rest.split_first_chunk()?;
    let (ethertype, body) = rest.split_first_chunk()?;
    Some(Frame {
        dst: *dst,
        src: *src,
        ethertype: u16::from_be_bytes(*ethertype),
        body,
    })
}

/// Puts an Ethernet frame together.
pub fn build(dst: MacAddr, src: MacAddr, ethertype: u16, body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HEADER_LEN + body.len());
    frame.extend_from_slice(&dst);
    frame.extend_from_slice(&src);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(body);
    frame
}

/// A packet socket on one interface that sends and hears the frames of one ethertype.
///
/// The socket is raw: frames go out and come in whole, with their 14-byte
/// header, so the address a frame came from is in the frame. It hears the frames
/// that arrive, and not those that leave the interface, this one's own among them
/// (only a socket for every ethertype is a tap on the outgoing ones).
pub struct LinkSocket {
    fd: AsyncFd<OwnedFd>,
}

impl LinkSocket {
    /// Opens a socket on the interface with index `ifindex` for `ethertype`.
    ///
    /// # Panics
    ///
    /// Outside a tokio runtime.
    pub fn open(ifindex: u32, ethertype: u16) -> io::Result<Self> {
        Ok(Self {
            fd: sys::async_fd(sys::packet_socket(ifindex, ethertype)?)?,
        })
    }

    /// Reads one whole Ethernet frame, up to 2048 bytes of it.
    ///
    /// Dropping the future loses nothing: a frame is taken from the socket
    /// only by the call that returns it.
    pub async fn recv(&self) -> io::Result<Vec<u8>> {
        let mut frame = vec![0; MAX_FRAME];
        loop {
            let mut ready = self.fd.readable().await?;
            let read = ready.try_io(|fd| {
                rustix::net::recv(fd, &mut frame[..], RecvFlags::empty())
                    .map(|(_, len)| len)
                    .map_err(io::Error::from)
            });
            if let Ok(read) = read {
                frame.truncate(read?);
                frame.shrink_to_fit();
                return Ok(frame);
            }
        }
    }

    /// Sends one whole Ethernet frame, header included.
    ///
    /// It does not wait: a full send queue is `ErrorKind::WouldBlock`.
    pub fn send(&self, frame: &[u8]) -> io::Result<()> {
        // A frame goes whole or not at all.
        rustix::net::send(self.fd.get_ref(), frame, SendFlags::empty())
            .map(drop)
            .map_err(io::Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use hex_literal::hex;
    use tokio::time::timeout;

    use crate::netlink::route::Route;

    #[test]
    fn a_frame_round_trips() {
        let f = build(
            hex!("a0a1a1a3a4a5"),
            hex!("b0b1b2b3b4b5"),
            ETHERTYPE_PAE,
            &[1, 3, 0, 0],
        );
        assert_eq!(f, hex!("a0a1a1a3a4a5" "b0b1b2b3b4b5" "888e" "01030000"));
        assert_eq!(
            parse(&f),
            Some(Frame {
                dst: hex!("a0a1a1a3a4a5"),
                src: hex!("b0b1b2b3b4b5"),
                ethertype: 0x888e,
                body: &[1, 3, 0, 0]
            })
        );
        assert_eq!(parse(&f[..14]).unwrap().body, &[] as &[u8]);
        assert_eq!(parse(&f[..13]), None);
        assert_eq!(parse(&[]), None);
    }

    #[test]
    fn a_frame_does_not_show_its_body_when_formatted() {
        let f = build(
            hex!("a0a1a1a3a4a5"),
            hex!("b0b1b2b3b4b5"),
            ETHERTYPE_PAE,
            &[201, 202, 203, 204],
        );
        let shown = format!("{:?}", parse(&f).unwrap());
        for byte in ["201", "202", "203", "204", "0xc9", "c9ca"] {
            assert!(!shown.contains(byte), "{shown}");
        }
        assert!(shown.contains("4 bytes"), "{shown}");
        assert!(shown.contains("0x888e"), "{shown}");
    }

    #[test]
    fn the_kernel_carries_a_frame() {
        crate::testns::run_inside("wifi::eapol::tests::ns_loopback");
    }

    #[tokio::test]
    #[ignore = "run by the_kernel_carries_a_frame, inside a namespace"]
    async fn ns_loopback() {
        if !crate::testns::inside() {
            return;
        }
        let mut route = Route::open().unwrap();
        let lo = route.link("lo").await.unwrap().unwrap();
        route.set_up(lo.index).await.unwrap();

        let a = LinkSocket::open(lo.index, ETHERTYPE_PAE).unwrap();
        let other = LinkSocket::open(lo.index, 0x88b5).unwrap();

        let frame = build([0; 6], [0; 6], ETHERTYPE_PAE, b"hello");
        a.send(&frame).unwrap();
        let heard = timeout(Duration::from_secs(2), a.recv())
            .await
            .expect("the socket heard nothing within 2 s")
            .unwrap();
        assert_eq!(heard, frame);
        assert_eq!(parse(&heard).unwrap().body, b"hello");

        // A socket hears only its own ethertype.
        assert!(
            timeout(Duration::from_millis(200), other.recv())
                .await
                .is_err()
        );
        // And that socket is not deaf: it hears a frame of its own.
        let frame = build([0; 6], [0; 6], 0x88b5, b"other");
        other.send(&frame).unwrap();
        let heard = timeout(Duration::from_secs(2), other.recv())
            .await
            .expect("the other socket heard nothing within 2 s")
            .unwrap();
        assert_eq!(heard, frame);

        // No such interface; and no ethertype to hear is no socket.
        assert!(LinkSocket::open(9999, ETHERTYPE_PAE).is_err());
        let none = LinkSocket::open(lo.index, 0).err().unwrap();
        assert_eq!(none.kind(), std::io::ErrorKind::InvalidInput);
    }
}
