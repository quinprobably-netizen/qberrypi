//! The netlink wire format: requests are built as bytes and replies are read
//! straight from the bytes the kernel sent.
//!
//! Every integer is native-endian. An attribute's length field counts its
//! 4-byte header and its payload, not the padding that follows it.
//!
//! Reading never trusts a length field. A message or attribute that does not
//! fit in the bytes at hand ends the walk, so the readers cannot panic, loop
//! forever, or read outside their input, whatever the kernel (or a damaged
//! buffer) holds.

use std::fmt;
use std::io;

use zeroize::Zeroize;

/// Message type: an error, or with a code of zero an acknowledgement.
pub const NLMSG_ERROR: u16 = 2;
/// Message type: the end of a multipart reply.
pub const NLMSG_DONE: u16 = 3;

/// Flag: the message is a request.
pub const NLM_F_REQUEST: u16 = 0x001;
/// Flag: the message is one of a multipart reply.
pub const NLM_F_MULTI: u16 = 0x002;
/// Flag: the kernel is asked to acknowledge the request.
pub const NLM_F_ACK: u16 = 0x004;
/// Flag: the request is for the whole table.
pub const NLM_F_DUMP: u16 = 0x300;
/// Flag: an existing entry is replaced.
pub const NLM_F_REPLACE: u16 = 0x100;
/// Flag: the entry is created if it does not exist.
pub const NLM_F_CREATE: u16 = 0x400;
/// Flag, in an acknowledgement: the request is not echoed back, only its header.
pub const NLM_F_CAPPED: u16 = 0x100;
/// Flag, in an acknowledgement: attributes follow the echoed request.
pub const NLM_F_ACK_TLVS: u16 = 0x200;

/// Attribute type bit: the payload is itself a list of attributes.
pub const NLA_F_NESTED: u16 = 0x8000;
/// Attribute type bits that are the type, not a flag.
pub const NLA_TYPE_MASK: u16 = 0x3fff;

/// Size of a message header: length, type, flags, sequence, port.
const HEADER_LEN: usize = 16;
/// Size of an attribute header: length, type.
const ATTR_HEADER_LEN: usize = 4;
/// Where the kernel puts its text in an acknowledgement's attributes.
const NLMSGERR_ATTR_MSG: u16 = 1;
/// Room a new request starts with. Requests that carry keys are smaller, and
/// a buffer that never grows leaves no stale copy of them behind.
const REQUEST_CAPACITY: usize = 256;

/// Reads the `u16` at `at`, if the bytes reach that far.
fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    bytes
        .get(at..)?
        .first_chunk()
        .copied()
        .map(u16::from_ne_bytes)
}

/// Reads the `u32` at `at`, if the bytes reach that far.
fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    bytes
        .get(at..)?
        .first_chunk()
        .copied()
        .map(u32::from_ne_bytes)
}

/// A request being built, one piece at a time.
///
/// Every method returns the builder, so a request reads as one expression.
/// Headers and attributes are padded with zeros to a multiple of 4 bytes, as
/// the kernel requires.
///
/// Requests can carry keys, so `Debug` shows only the flags and the length,
/// and the buffer is wiped when the builder is dropped, whether it was used
/// or not. [`finish`](Self::finish) hands the buffer over, and with it the
/// duty to wipe it.
pub struct MsgBuilder {
    buf: Vec<u8>,
}

impl fmt::Debug for MsgBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MsgBuilder")
            .field("flags", &self.flags())
            .field("len", &self.buf.len())
            .finish_non_exhaustive()
    }
}

impl Drop for MsgBuilder {
    fn drop(&mut self) {
        // Wipes the whole allocation, not just the bytes written so far.
        self.buf.zeroize();
    }
}

impl MsgBuilder {
    /// Starts a message of `msg_type` with `flags`.
    ///
    /// The header's length and sequence are filled in by [`finish`](Self::finish).
    pub fn new(msg_type: u16, flags: u16) -> Self {
        let mut buf = Vec::with_capacity(REQUEST_CAPACITY);
        buf.extend_from_slice(&[0; 4]);
        buf.extend_from_slice(&msg_type.to_ne_bytes());
        buf.extend_from_slice(&flags.to_ne_bytes());
        buf.extend_from_slice(&[0; 8]);
        Self { buf }
    }

    /// Appends the family's fixed header, padded to a multiple of 4 bytes.
    pub fn header(mut self, bytes: &[u8]) -> Self {
        self.buf.extend_from_slice(bytes);
        self.pad();
        self
    }

    /// Appends an attribute of type `ty` holding `payload`.
    ///
    /// # Panics
    ///
    /// If the attribute would be longer than a 16-bit length can say.
    pub fn attr(mut self, ty: u16, payload: &[u8]) -> Self {
        let len = u16::try_from(ATTR_HEADER_LEN + payload.len())
            .expect("a netlink attribute is at most 65535 bytes");
        self.buf.extend_from_slice(&len.to_ne_bytes());
        self.buf.extend_from_slice(&ty.to_ne_bytes());
        self.buf.extend_from_slice(payload);
        self.pad();
        self
    }

    /// Appends a one-byte attribute.
    pub fn attr_u8(self, ty: u16, v: u8) -> Self {
        self.attr(ty, &v.to_ne_bytes())
    }

    /// Appends a 16-bit attribute.
    pub fn attr_u16(self, ty: u16, v: u16) -> Self {
        self.attr(ty, &v.to_ne_bytes())
    }

    /// Appends a 32-bit attribute.
    pub fn attr_u32(self, ty: u16, v: u32) -> Self {
        self.attr(ty, &v.to_ne_bytes())
    }

    /// Appends an attribute that is present or absent and has no payload.
    pub fn attr_flag(self, ty: u16) -> Self {
        self.attr(ty, &[])
    }

    /// Appends a string attribute, with the terminating NUL the kernel expects.
    pub fn attr_str(self, ty: u16, text: &str) -> Self {
        let mut payload = Vec::with_capacity(text.len() + 1);
        payload.extend_from_slice(text.as_bytes());
        payload.push(0);
        self.attr(ty, &payload)
    }

    /// Appends a nested attribute whose attributes are those `fill` adds.
    ///
    /// The type is marked [`NLA_F_NESTED`]; the length is filled in once
    /// `fill` is done. `fill` must return the builder it was given.
    ///
    /// # Panics
    ///
    /// If the nest would be longer than a 16-bit length can say.
    pub fn nest(mut self, ty: u16, fill: impl FnOnce(Self) -> Self) -> Self {
        let start = self.buf.len();
        self.buf.extend_from_slice(&[0; 2]);
        self.buf
            .extend_from_slice(&(ty | NLA_F_NESTED).to_ne_bytes());
        let mut done = fill(self);
        let len = u16::try_from(done.buf.len() - start)
            .expect("a netlink attribute is at most 65535 bytes");
        done.buf[start..start + 2].copy_from_slice(&len.to_ne_bytes());
        done
    }

    /// The flags the message was started with.
    pub fn flags(&self) -> u16 {
        u16_at(&self.buf, 6).unwrap_or_default()
    }

    /// Completes the message with sequence number `seq`, and returns its bytes.
    ///
    /// The bytes may hold a key: whoever receives them wipes them.
    pub fn finish(mut self, seq: u32) -> Vec<u8> {
        let len = u32::try_from(self.buf.len()).expect("a netlink message is at most 4 GiB");
        self.buf[..4].copy_from_slice(&len.to_ne_bytes());
        self.buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        // The builder cannot be taken apart, as it is wiped on drop; it is
        // left holding nothing.
        std::mem::take(&mut self.buf)
    }

    /// Appends zeros up to the next multiple of 4 bytes.
    fn pad(&mut self) {
        self.buf.resize(self.buf.len().next_multiple_of(4), 0);
    }
}

/// One attribute: its type and its payload, without padding.
#[derive(Debug, Clone, Copy)]
pub struct Attr<'a> {
    /// The type, with the flag bits removed.
    pub ty: u16,
    /// What follows the 4-byte attribute header, up to the attribute's length.
    pub payload: &'a [u8],
}

impl<'a> Attr<'a> {
    /// The payload as exactly `N` bytes, if it is that long.
    fn array<const N: usize>(&self) -> Option<[u8; N]> {
        self.payload.try_into().ok()
    }

    /// The payload as a byte, if it is exactly one byte.
    pub fn u8(&self) -> Option<u8> {
        self.array().map(u8::from_ne_bytes)
    }

    /// The payload as a 16-bit integer, if it is exactly two bytes.
    pub fn u16(&self) -> Option<u16> {
        self.array().map(u16::from_ne_bytes)
    }

    /// The payload as a 32-bit integer, if it is exactly four bytes.
    pub fn u32(&self) -> Option<u32> {
        self.array().map(u32::from_ne_bytes)
    }

    /// The payload as a signed 32-bit integer, if it is exactly four bytes.
    pub fn i32(&self) -> Option<i32> {
        self.array().map(i32::from_ne_bytes)
    }

    /// The payload as a hardware address, if it is exactly six bytes.
    pub fn mac(&self) -> Option<[u8; 6]> {
        self.array()
    }

    /// The payload as text up to its first NUL, if that is valid UTF-8.
    pub fn str(&self) -> Option<&'a str> {
        let text = self.payload.split(|&b| b == 0).next()?;
        std::str::from_utf8(text).ok()
    }

    /// The attributes the payload holds.
    pub fn nested(&self) -> Attrs<'a> {
        attrs(self.payload)
    }
}

/// The attributes in a run of bytes, in order.
///
/// Ends at the first attribute that does not fit: one that is cut short, or
/// whose length field is smaller than its own header or larger than what is
/// left.
#[derive(Debug, Clone)]
pub struct Attrs<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Attrs<'a> {
    type Item = Attr<'a>;

    fn next(&mut self) -> Option<Attr<'a>> {
        let len = usize::from(u16_at(self.rest, 0)?);
        let ty = u16_at(self.rest, 2)?;
        let payload = self.rest.get(ATTR_HEADER_LEN..len)?;
        // The last attribute may lack its padding.
        self.rest = self.rest.get(len.next_multiple_of(4)..).unwrap_or_default();
        Some(Attr {
            ty: ty & NLA_TYPE_MASK,
            payload,
        })
    }
}

/// The attributes in `bytes`, which start right after a message's family header.
pub fn attrs(bytes: &[u8]) -> Attrs<'_> {
    Attrs { rest: bytes }
}

/// The first attribute of type `ty` in `bytes`.
pub fn find<'a>(bytes: &'a [u8], ty: u16) -> Option<Attr<'a>> {
    attrs(bytes).find(|attr| attr.ty == ty)
}

/// One message of a datagram.
#[derive(Debug, Clone, Copy)]
pub struct Message<'a> {
    pub msg_type: u16,
    pub flags: u16,
    /// The sequence number of the request this message answers.
    pub seq: u32,
    /// Everything after the 16-byte header: the family header, then attributes.
    pub payload: &'a [u8],
}

/// The messages a datagram holds, in order.
///
/// Ends at the first header that does not fit: one that is cut short, or
/// whose length field is smaller than a header or larger than what is left.
pub fn messages(datagram: &[u8]) -> impl Iterator<Item = Message<'_>> {
    let mut rest = datagram;
    std::iter::from_fn(move || {
        let len = usize::try_from(u32_at(rest, 0)?).ok()?;
        let msg_type = u16_at(rest, 4)?;
        let flags = u16_at(rest, 6)?;
        let seq = u32_at(rest, 8)?;
        let payload = rest.get(HEADER_LEN..len)?;
        rest = rest.get(len.next_multiple_of(4)..).unwrap_or_default();
        Some(Message {
            msg_type,
            flags,
            seq,
            payload,
        })
    })
}

/// An error the kernel reported for a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NlError {
    /// The error number, positive as in `errno`.
    pub errno: i32,
    /// The kernel's explanation, when it gave one.
    pub message: Option<String>,
}

impl fmt::Display for NlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", io::Error::from_raw_os_error(self.errno))?;
        if let Some(message) = &self.message {
            write!(f, ": {message}")?;
        }
        Ok(())
    }
}

impl std::error::Error for NlError {}

/// Reads `message` as an acknowledgement.
///
/// `None` unless it is an `NLMSG_ERROR` message. Otherwise the kernel's answer
/// to a request: the value it returned (zero for a plain success), or the
/// error. An error message too short to hold its code is reported as
/// `EBADMSG`.
pub fn ack(message: &Message<'_>) -> Option<Result<u32, NlError>> {
    if message.msg_type != NLMSG_ERROR {
        return None;
    }
    let Some(code) = message
        .payload
        .first_chunk()
        .copied()
        .map(i32::from_ne_bytes)
    else {
        return Some(Err(NlError {
            errno: libc::EBADMSG,
            message: None,
        }));
    };
    Some(match u32::try_from(code) {
        Ok(value) => Ok(value),
        Err(_) => Err(NlError {
            errno: code.saturating_neg(),
            message: kernel_text(message),
        }),
    })
}

/// The explanation the kernel attached to an error message, if any.
///
/// After the error code comes the request, echoed back whole or, when
/// `NLM_F_CAPPED` is set, only its 16-byte header. The kernel pads the echo
/// to a multiple of 4 bytes, and its attributes follow.
fn kernel_text(message: &Message<'_>) -> Option<String> {
    if message.flags & NLM_F_ACK_TLVS == 0 {
        return None;
    }
    let echoed = if message.flags & NLM_F_CAPPED != 0 {
        HEADER_LEN
    } else {
        usize::try_from(u32_at(message.payload, 4)?).ok()?
    };
    let start = 4usize.checked_add(echoed)?.checked_next_multiple_of(4)?;
    let text = find(message.payload.get(start..)?, NLMSGERR_ATTR_MSG)?;
    text.str().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex_literal::hex;

    /// The first golden message: a 16-byte family header and one string.
    fn string_message() -> Vec<u8> {
        MsgBuilder::new(18, NLM_F_REQUEST | NLM_F_ACK)
            .header(&[0; 16])
            .attr_str(3, "wlan0")
            .finish(7)
    }

    /// The second golden message: a 4-byte family header, a nest and two integers.
    fn nested_message() -> Vec<u8> {
        MsgBuilder::new(28, 5)
            .header(&[33, 0, 0, 0])
            .attr_u32(3, 3)
            .nest(45, |n| n.attr(1, b"ThisIsASSID"))
            .attr_u32(158, 2)
            .finish(7)
    }

    /// An error message as the kernel sends it: `errno`, the echoed request,
    /// then the kernel's text as attribute 1.
    fn error_message(flags: u16, errno: i32, echoed: &[u8], text: &str) -> Vec<u8> {
        MsgBuilder::new(NLMSG_ERROR, flags)
            .header(&(-errno).to_ne_bytes())
            .header(echoed)
            .attr_str(1, text)
            .finish(9)
    }

    /// The text of the errors the tests build.
    const KERNEL_TEXT: &str = "Nexthop has invalid gateway";

    /// The first message of a datagram, which the tests build to hold exactly one.
    fn only_message(datagram: &[u8]) -> Message<'_> {
        let mut found = messages(datagram);
        let message = found.next().expect("one message");
        assert!(found.next().is_none());
        message
    }

    #[test]
    fn a_message_is_laid_out_as_the_kernel_reads_it() {
        assert_eq!(
            string_message(),
            hex!(
                "2c000000120005000700000000000000000000000000000000000000000000000a000300776c616e30000000"
            )
        );
    }

    #[test]
    fn a_nest_carries_the_flag_and_its_whole_length() {
        assert_eq!(
            nested_message(),
            hex!(
                "380000001c000500070000000000000021000000080003000300000014002d800f00010054686973497341535349440008009e0002000000"
            )
        );
    }

    #[test]
    fn attributes_are_read_back() {
        let message = nested_message();
        let body = &message[20..];
        let types: Vec<u16> = attrs(body).map(|a| a.ty).collect();
        assert_eq!(types, [3, 45, 158]);
        assert_eq!(find(body, 3).unwrap().u32(), Some(3));
        assert_eq!(find(body, 158).unwrap().u32(), Some(2));
        let nest = find(body, 45).unwrap();
        let inner: Vec<Attr<'_>> = nest.nested().collect();
        assert_eq!(inner.len(), 1);
        assert_eq!(inner[0].ty, 1);
        assert_eq!(inner[0].payload, b"ThisIsASSID");
        assert!(find(body, 9).is_none());

        // The builder's small helpers.
        let flag = MsgBuilder::new(1, 0).attr_flag(5).finish(0);
        assert_eq!(&flag[16..], hex!("04000500"));
        assert_eq!(find(&flag[16..], 5).unwrap().payload, b"");
        let byte = MsgBuilder::new(1, 0).attr_u8(2, 1).finish(0);
        assert_eq!(&byte[16..], hex!("0500020001000000"));
        assert_eq!(find(&byte[16..], 2).unwrap().u8(), Some(1));
        let short = MsgBuilder::new(1, 0).attr_u16(4, 0xabcd).finish(0);
        assert_eq!(find(&short[16..], 4).unwrap().u16(), Some(0xabcd));
        let signed = MsgBuilder::new(1, 0).attr_u32(4, 0xffff_fffe).finish(0);
        assert_eq!(find(&signed[16..], 4).unwrap().i32(), Some(-2));

        // A payload of the wrong size is not an integer or an address.
        let two = find(&short[16..], 4).unwrap();
        assert_eq!(two.u32(), None);
        assert_eq!(two.u8(), None);
        let five = MsgBuilder::new(1, 0).attr(6, &[1, 2, 3, 4, 5]).finish(0);
        assert_eq!(find(&five[16..], 6).unwrap().mac(), None);
        let six = MsgBuilder::new(1, 0)
            .attr(6, &hex!("a0a1a1a3a4a5"))
            .finish(0);
        assert_eq!(
            find(&six[16..], 6).unwrap().mac(),
            Some(hex!("a0a1a1a3a4a5"))
        );

        // A string stops at its NUL, and is also fine without one.
        let country = MsgBuilder::new(1, 0).attr(7, b"US\0").finish(0);
        assert_eq!(find(&country[16..], 7).unwrap().str(), Some("US"));
        let bare = MsgBuilder::new(1, 0).attr(7, b"US").finish(0);
        assert_eq!(find(&bare[16..], 7).unwrap().str(), Some("US"));
        let invalid = MsgBuilder::new(1, 0).attr(7, &[0xff, 0xfe]).finish(0);
        assert_eq!(find(&invalid[16..], 7).unwrap().str(), None);

        // The last attribute may lack its padding, and flag bits other than
        // the nest flag are removed from the type too.
        let unpadded = hex!("050002c001");
        let last = attrs(&unpadded).next().unwrap();
        assert_eq!((last.ty, last.payload), (2, &[1u8][..]));

        // An attribute that claims less than its own header ends the walk
        // instead of repeating forever; so does one that claims too much.
        assert_eq!(attrs(&hex!("00000100 00000000")).count(), 0);
        assert_eq!(attrs(&hex!("03000100 00000000")).count(), 0);
        assert_eq!(attrs(&hex!("10000100 00000000")).count(), 0);
        assert_eq!(attrs(&hex!("0400010004000200 0300")).count(), 2);
    }

    #[test]
    fn a_datagram_splits_into_its_messages() {
        let first = MsgBuilder::new(16, NLM_F_MULTI)
            .header(&[1, 2, 3, 4])
            .attr_u32(1, 9)
            .finish(7);
        let second = MsgBuilder::new(NLMSG_DONE, NLM_F_MULTI)
            .header(&0i32.to_ne_bytes())
            .finish(8);
        let datagram = [first.clone(), second.clone()].concat();

        let found: Vec<Message<'_>> = messages(&datagram).collect();
        assert_eq!(found.len(), 2);
        assert_eq!(
            (found[0].msg_type, found[0].flags, found[0].seq),
            (16, NLM_F_MULTI, 7)
        );
        assert_eq!(found[0].payload, &first[16..]);
        assert_eq!(
            (found[1].msg_type, found[1].flags, found[1].seq),
            (3, NLM_F_MULTI, 8)
        );
        assert_eq!(found[1].payload, &second[16..]);

        // The walk ends at a header that does not fit...
        assert_eq!(messages(&datagram[..datagram.len() - 1]).count(), 1);
        assert_eq!(messages(&datagram[..first.len() + 15]).count(), 1);
        assert_eq!(messages(&[]).count(), 0);
        // ...and at one that claims less than a header or more than is there.
        let mut small = first.clone();
        small[..4].copy_from_slice(&15u32.to_ne_bytes());
        assert_eq!(messages(&small).count(), 0);
        small[..4].copy_from_slice(&0u32.to_ne_bytes());
        assert_eq!(messages(&small).count(), 0);
        small[..4].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert_eq!(messages(&small).count(), 0);
    }

    #[test]
    fn an_acknowledgement_is_success_with_its_value() {
        let ack_of = |value: i32| {
            MsgBuilder::new(NLMSG_ERROR, 0)
                .header(&value.to_ne_bytes())
                .header(&[0; 16])
                .finish(5)
        };
        let zero = ack_of(0);
        assert_eq!(ack(&only_message(&zero)), Some(Ok(0)));
        let four = ack_of(4);
        assert_eq!(ack(&only_message(&four)), Some(Ok(4)));

        let done = MsgBuilder::new(NLMSG_DONE, NLM_F_MULTI)
            .header(&0i32.to_ne_bytes())
            .finish(5);
        assert_eq!(ack(&only_message(&done)), None);

        // An error message too short to hold its code is an error, not a success.
        let cut = MsgBuilder::new(NLMSG_ERROR, 0).finish(5);
        assert_eq!(
            ack(&only_message(&cut)),
            Some(Err(NlError {
                errno: libc::EBADMSG,
                message: None
            }))
        );
    }

    #[test]
    fn an_error_gives_the_errno_and_the_kernels_text() {
        let wanted = NlError {
            errno: 101,
            message: Some(KERNEL_TEXT.into()),
        };

        let capped = error_message(NLM_F_CAPPED | NLM_F_ACK_TLVS, 101, &[0; 16], KERNEL_TEXT);
        assert_eq!(ack(&only_message(&capped)), Some(Err(wanted.clone())));

        let request = string_message();
        assert_eq!(request.len(), 44);
        let uncapped = error_message(NLM_F_ACK_TLVS, 101, &request, KERNEL_TEXT);
        assert_eq!(ack(&only_message(&uncapped)), Some(Err(wanted.clone())));

        // A request whose length is not a multiple of 4 is padded in the echo.
        let mut odd = request.clone();
        odd.truncate(43);
        odd[..4].copy_from_slice(&43u32.to_ne_bytes());
        odd.push(0);
        let padded = error_message(NLM_F_ACK_TLVS, 101, &odd, KERNEL_TEXT);
        assert_eq!(ack(&only_message(&padded)), Some(Err(wanted.clone())));

        // Without the flag, the bytes after the request are not attributes.
        let plain = error_message(0, 101, &request, KERNEL_TEXT);
        assert_eq!(
            ack(&only_message(&plain)),
            Some(Err(NlError {
                errno: 101,
                message: None
            }))
        );
        let plain = error_message(NLM_F_CAPPED, 101, &[0; 16], KERNEL_TEXT);
        assert_eq!(
            ack(&only_message(&plain)).unwrap().unwrap_err().message,
            None
        );

        assert!(
            wanted
                .to_string()
                .ends_with(": Nexthop has invalid gateway"),
            "{wanted}"
        );
        let no_text = NlError {
            errno: 101,
            message: None,
        };
        assert_eq!(
            no_text.to_string(),
            std::io::Error::from_raw_os_error(101).to_string()
        );
    }

    #[test]
    fn a_builder_does_not_print_what_it_holds() {
        // Requests carry keys, and a key must not reach a log through `Debug`.
        let key = hex!("a0a1a1a3a4a5b0b1b2b3b4b5c0c1c2c3");
        let builder = MsgBuilder::new(18, NLM_F_REQUEST | NLM_F_ACK).attr(1, &key);
        assert_eq!(
            format!("{builder:?}"),
            "MsgBuilder { flags: 5, len: 36, .. }"
        );
    }

    /// Reads every attribute of `bytes` and, `levels` more times, of what
    /// each one holds, using every accessor.
    fn walk(bytes: &[u8], levels: u32) {
        let mut seen = 0;
        for attr in attrs(bytes) {
            seen += 1;
            assert!(seen <= bytes.len() / 4, "more attributes than fit");
            let _ = (attr.u8(), attr.u16(), attr.u32(), attr.i32());
            let _ = (attr.mac(), attr.str(), find(bytes, attr.ty));
            if levels > 0 {
                walk(attr.payload, levels - 1);
                assert_eq!(attr.nested().count(), attrs(attr.payload).count());
            }
        }
    }

    /// Reads a datagram the way a receiver does, whatever is in it.
    ///
    /// The attributes start after a family header of a size only the family
    /// knows, so they are read from every offset a header could end at.
    fn read_everything(datagram: &[u8]) {
        let mut seen = 0;
        for message in messages(datagram) {
            seen += 1;
            assert!(seen <= datagram.len() / 16, "more messages than fit");
            let _ = ack(&message);
            for start in (0..=message.payload.len()).step_by(4) {
                walk(&message.payload[start..], 2);
            }
        }
    }

    #[test]
    fn malformed_input_never_panics() {
        let capped = error_message(NLM_F_CAPPED | NLM_F_ACK_TLVS, 101, &[0; 16], KERNEL_TEXT);
        for original in [string_message(), nested_message(), capped] {
            read_everything(&original);
            for end in 0..original.len() {
                read_everything(&original[..end]);
            }
            for at in 0..original.len() {
                let byte = original[at];
                for changed in [0x00, 0xff, byte ^ 0x01, byte ^ 0x80] {
                    let mut damaged = original.clone();
                    damaged[at] = changed;
                    read_everything(&damaged);
                }
            }
        }
    }
}
