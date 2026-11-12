//! HTTP/1.1 over the TLS stream: one request read, one reply written, each within fixed bounds.
//!
//! The bytes come from any device on the network, so every limit is a constant and every step is
//! bounded by one:
//!
//! - the head (the request line and the headers, through the empty line) is at most
//!   [`MAX_HEAD`] bytes and has at most [`MAX_HEADERS`] headers;
//! - the body is at most [`MAX_BODY`] bytes, and is read only as far as its `Content-Length` says;
//! - a request that frames its body any other way (`Transfer-Encoding`) is refused.
//!
//! [`read_request`] takes from the reader exactly one request, head and body, and not a byte
//! more, so a connection kept alive carries the next request unharmed. A request is answered by
//! [`write_reply`]. Nothing here panics on what it reads, and nothing logs. A [`Request`] holds
//! secrets (the session id, the body of a login), so its `Debug` output hides both.

use std::fmt;
use std::io::{self, BufRead, Read, Write};

/// The most bytes a request head may take, its closing empty line included.
pub const MAX_HEAD: usize = 8 * 1024;
/// The most bytes a request body may take.
pub const MAX_BODY: usize = 4 * 1024;
/// The most headers a request may have.
pub const MAX_HEADERS: usize = 32;

/// The longest session id that is taken, in bytes.
const MAX_SID_LEN: usize = 512;

/// What ends a head.
const HEAD_END: &[u8; 4] = b"\r\n\r\n";

/// One request, as far as the API needs it.
#[derive(PartialEq)]
pub struct Request {
    /// The method, as sent: `GET`, `POST` and so on.
    pub method: String,
    /// The request target, as sent, a query string included.
    pub target: String,
    /// The value of the `X-FTL-SID` header, if there is exactly one and it is 1 to 512 visible
    /// ASCII bytes. Never taken from a cookie or from the query string.
    pub sid: Option<String>,
    /// The body, as long as the `Content-Length` said; empty when there was none.
    pub body: Vec<u8>,
    /// Whether the connection ends after the reply: the request is HTTP/1.0 or says
    /// `Connection: close`.
    pub close: bool,
}

/// Stands in for a value that `Debug` must not show.
struct Redacted;

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// The target with its query, if any, hidden: Pi-hole clients may send `?sid=` there.
fn path_only(target: &str) -> String {
    match target.split_once('?') {
        Some((path, _query)) => format!("{path}?<redacted>"),
        None => target.to_owned(),
    }
}

impl fmt::Debug for Request {
    /// Shows the method, the target's path and `close`. The query of the target (`?<redacted>`),
    /// the session id and the body, which may be a password, are not shown.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("target", &path_only(&self.target))
            .field("sid", &self.sid.as_ref().map(|_| Redacted))
            .field("body", &Redacted)
            .field("close", &self.close)
            .finish()
    }
}

/// Why no request came out of [`read_request`].
#[derive(Debug, PartialEq)]
pub enum ReadError {
    /// The stream ended before the first byte of a request: the peer is done.
    Closed,
    /// The head is over [`MAX_HEAD`] bytes, or the `Content-Length` is over [`MAX_BODY`].
    TooLarge,
    /// The bytes are not a request this server takes, for the reason given.
    Malformed(&'static str),
    /// The stream failed; a timeout is one of these.
    Io(io::ErrorKind),
}

/// Reads one request from `r`: its head, then its body.
///
/// Exactly the head, through its closing empty line, and the body that its `Content-Length`
/// names are taken from `r`; the bytes after them stay for the next call. No more than
/// [`MAX_HEAD`] bytes are looked at to find the end of the head, and the body is not read at all
/// if its length is over [`MAX_BODY`].
///
/// A stream that ends before any byte is [`ReadError::Closed`], and one that ends inside the head
/// or the body is `Malformed("cut short")`. Any `Transfer-Encoding` is `Malformed("no chunked
/// requests")`. A `Content-Length` is one or more digits; several are fine if they are equal.
/// An interrupted read is retried, and any other failure is [`ReadError::Io`].
pub fn read_request(r: &mut impl BufRead) -> Result<Request, ReadError> {
    let head = read_head(r)?;
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut parsed = httparse::Request::new(&mut headers);
    match parsed.parse(&head) {
        Ok(httparse::Status::Complete(used)) if used == head.len() => {}
        // Not our end of the head: httparse took a bare line feed for it.
        Ok(httparse::Status::Complete(_)) => return Err(ReadError::Malformed("bad line ending")),
        Ok(httparse::Status::Partial) => return Err(ReadError::Malformed("incomplete head")),
        Err(e) => return Err(ReadError::Malformed(parse_failure(e))),
    }
    let (Some(method), Some(target)) = (parsed.method, parsed.path) else {
        return Err(ReadError::Malformed("incomplete head"));
    };
    let headers = &*parsed.headers;
    let length = body_length(headers)?;
    let request = Request {
        method: method.to_owned(),
        target: target.to_owned(),
        sid: session_id(headers),
        body: read_body(r, length)?,
        close: wants_close(parsed.version, headers),
    };
    Ok(request)
}

/// Takes the head from `r`: the bytes up to and including the first `\r\n\r\n`, and not one
/// more. At most [`MAX_HEAD`] bytes are copied; the end may fall between two reads.
fn read_head(r: &mut impl BufRead) -> Result<Vec<u8>, ReadError> {
    // Room for the whole head at once: a `Vec` that grows by doubling could reach twice that.
    let mut head: Vec<u8> = Vec::with_capacity(MAX_HEAD);
    loop {
        let chunk = match r.fill_buf() {
            Ok(chunk) => chunk,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ReadError::Io(e.kind())),
        };
        if chunk.is_empty() {
            return Err(if head.is_empty() {
                ReadError::Closed
            } else {
                ReadError::Malformed("cut short")
            });
        }
        let before = head.len();
        let take = chunk.len().min(MAX_HEAD.saturating_sub(before));
        // `take` is at most `chunk.len()`, so this cannot go out of range.
        head.extend_from_slice(&chunk[..take]);
        // The end can begin in what was read before, up to three bytes back.
        let from = before.saturating_sub(HEAD_END.len() - 1);
        let found = head[from..]
            .windows(HEAD_END.len())
            .position(|window| window == HEAD_END);
        if let Some(at) = found {
            let end = from + at + HEAD_END.len();
            head.truncate(end);
            // The end lies past `before`, or an earlier read would have found it.
            r.consume(end.saturating_sub(before));
            return Ok(head);
        }
        r.consume(take);
        if head.len() >= MAX_HEAD {
            return Err(ReadError::TooLarge);
        }
    }
}

/// What a parse failure is called, in a few words that name no byte of the request.
fn parse_failure(error: httparse::Error) -> &'static str {
    match error {
        httparse::Error::HeaderName => "bad header name",
        httparse::Error::HeaderValue => "bad header value",
        httparse::Error::NewLine => "bad line ending",
        httparse::Error::Token => "bad request line",
        httparse::Error::TooManyHeaders => "too many headers",
        httparse::Error::Version => "bad http version",
        _ => "not an http request",
    }
}

/// `value` without the spaces and tabs at either end.
fn trim_ows(mut value: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = value {
        value = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = value {
        value = rest;
    }
    value
}

/// The headers called `name`, whatever the case.
fn named<'h, 'b>(
    headers: &'h [httparse::Header<'b>],
    name: &'static str,
) -> impl Iterator<Item = &'h httparse::Header<'b>> {
    headers
        .iter()
        .filter(move |header| header.name.eq_ignore_ascii_case(name))
}

/// The length of the body, from `Content-Length`: 0 when there is none.
///
/// Any `Transfer-Encoding` is refused first. Each `Content-Length` must be digits and nothing
/// else, and all must have the same value (`02` and `2` do). A length over [`MAX_BODY`] is
/// [`ReadError::TooLarge`], however many digits it takes.
fn body_length(headers: &[httparse::Header<'_>]) -> Result<usize, ReadError> {
    if named(headers, "transfer-encoding").next().is_some() {
        return Err(ReadError::Malformed("no chunked requests"));
    }
    // The digits of the length seen so far, without leading zeros.
    let mut seen: Option<&[u8]> = None;
    for header in named(headers, "content-length") {
        let digits = trim_ows(header.value);
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
            return Err(ReadError::Malformed("bad content-length"));
        }
        let start = digits
            .iter()
            .position(|&digit| digit != b'0')
            .unwrap_or(digits.len());
        let significant = &digits[start..];
        if seen.is_some_and(|earlier| earlier != significant) {
            return Err(ReadError::Malformed("conflicting content-length"));
        }
        seen = Some(significant);
    }
    let length = seen.unwrap_or_default().iter().fold(0usize, |sum, &digit| {
        sum.saturating_mul(10)
            .saturating_add(usize::from(digit.saturating_sub(b'0')))
    });
    if length > MAX_BODY {
        return Err(ReadError::TooLarge);
    }
    Ok(length)
}

/// Takes exactly `length` bytes from `r`.
fn read_body(r: &mut impl BufRead, length: usize) -> Result<Vec<u8>, ReadError> {
    let mut body = Vec::with_capacity(length);
    // `length` is at most MAX_BODY; `take` stops the read there, and `read_to_end` retries an
    // interrupted read.
    Read::take(&mut *r, length as u64)
        .read_to_end(&mut body)
        .map_err(|e| ReadError::Io(e.kind()))?;
    if body.len() < length {
        return Err(ReadError::Malformed("cut short"));
    }
    Ok(body)
}

/// The session id in the `X-FTL-SID` header: the value of the one header of that name, when it is
/// 1 to [`MAX_SID_LEN`] bytes, each from `!` to `~`. With two or more such headers, none.
fn session_id(headers: &[httparse::Header<'_>]) -> Option<String> {
    let mut found = named(headers, "x-ftl-sid");
    let value = trim_ows(found.next()?.value);
    if found.next().is_some()
        || value.is_empty()
        || value.len() > MAX_SID_LEN
        || !value.iter().all(|byte| (0x21..=0x7e).contains(byte))
    {
        return None;
    }
    std::str::from_utf8(value).ok().map(str::to_owned)
}

/// Whether the connection ends after this request: HTTP/1.0, or a `Connection` header with the
/// token `close`.
fn wants_close(version: Option<u8>, headers: &[httparse::Header<'_>]) -> bool {
    version == Some(0)
        || named(headers, "connection").any(|header| {
            header
                .value
                .split(|&byte| byte == b',')
                .any(|token| trim_ows(token).eq_ignore_ascii_case(b"close"))
        })
}

/// A reply: a status and a JSON body.
#[derive(PartialEq)]
pub struct Reply {
    /// The status code.
    pub status: u16,
    /// The body, JSON text; a 204 sends none.
    pub body: Vec<u8>,
}

/// A body as `Debug` shows it: its length, never its bytes.
struct BodyLen(usize);

impl fmt::Debug for BodyLen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} bytes>", self.0)
    }
}

impl fmt::Debug for Reply {
    /// Shows the status and the length of the body. The body of a login reply holds the new
    /// session id, so its bytes are never shown.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reply")
            .field("status", &self.status)
            .field("body", &BodyLen(self.body.len()))
            .finish()
    }
}

/// The reason phrase of a status the API uses, and `Unknown` for any other.
fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Content Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Unknown",
    }
}

/// Writes `reply` to `w` as an HTTP/1.1 response, then flushes.
///
/// The head is the status line, `Content-Type: application/json` (not for a 204), the
/// `Content-Length`, `Cache-Control: no-store` and `Connection: close` if `close` is set, else
/// `keep-alive`. A 204 has a `Content-Length` of 0 and sends no body, whatever `reply` holds.
pub fn write_reply(w: &mut impl Write, reply: &Reply, close: bool) -> io::Result<()> {
    let empty = reply.status == 204;
    let body: &[u8] = if empty { &[] } else { &reply.body };
    let mut out = Vec::with_capacity(192_usize.saturating_add(body.len()));
    write!(
        out,
        "HTTP/1.1 {} {}\r\n",
        reply.status,
        reason(reply.status)
    )?;
    if !empty {
        out.extend_from_slice(b"Content-Type: application/json\r\n");
    }
    write!(
        out,
        "Content-Length: {}\r\nCache-Control: no-store\r\nConnection: {}\r\n\r\n",
        body.len(),
        if close { "close" } else { "keep-alive" },
    )?;
    out.extend_from_slice(body);
    w.write_all(&out)?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io::{self, BufRead, Cursor, Read, Write};

    use super::*;

    const QNET_GET: &str = "GET /api/stats/summary HTTP/1.1\r\nHost: 192.0.2.53\r\nUser-Agent: qnet\r\nAccept: application/json\r\nX-FTL-SID: 0123abcd\r\nConnection: keep-alive\r\n\r\n";
    const QNET_POST: &str = "POST /api/dns/blocking HTTP/1.1\r\nHost: 192.0.2.53\r\nx-ftl-sid: 0123abcd\r\nContent-Type: application/json\r\nContent-Length: 30\r\nConnection: close\r\n\r\n{\"blocking\":false,\"timer\":300}";

    /// A reader that hands out its chunks one `fill_buf` at a time, interrupts first if told to,
    /// and then ends, or fails with `failure`. It counts the bytes that were consumed.
    struct Chunks {
        chunks: VecDeque<Vec<u8>>,
        pos: usize,
        consumed: usize,
        interrupts: u32,
        failure: Option<io::ErrorKind>,
    }

    impl Chunks {
        fn new(chunks: &[&[u8]]) -> Self {
            Chunks {
                chunks: chunks.iter().map(|c| c.to_vec()).collect(),
                pos: 0,
                consumed: 0,
                interrupts: 0,
                failure: None,
            }
        }

        /// One byte per `fill_buf`.
        fn one_byte_at_a_time(bytes: &[u8]) -> Self {
            Chunks {
                chunks: bytes.iter().map(|&b| vec![b]).collect(),
                pos: 0,
                consumed: 0,
                interrupts: 0,
                failure: None,
            }
        }

        fn failing(mut self, kind: io::ErrorKind) -> Self {
            self.failure = Some(kind);
            self
        }

        fn interrupted(mut self, times: u32) -> Self {
            self.interrupts = times;
            self
        }
    }

    impl Read for Chunks {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let n = {
                let buf = self.fill_buf()?;
                let n = buf.len().min(out.len());
                out[..n].copy_from_slice(&buf[..n]);
                n
            };
            self.consume(n);
            Ok(n)
        }
    }

    impl BufRead for Chunks {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            if self.interrupts > 0 {
                self.interrupts -= 1;
                return Err(io::ErrorKind::Interrupted.into());
            }
            while self.chunks.front().is_some_and(|c| self.pos >= c.len()) {
                self.chunks.pop_front();
                self.pos = 0;
            }
            match (self.chunks.front(), self.failure) {
                (Some(chunk), _) => Ok(&chunk[self.pos..]),
                (None, Some(kind)) => Err(kind.into()),
                (None, None) => Ok(&[]),
            }
        }

        fn consume(&mut self, amt: usize) {
            self.pos += amt;
            self.consumed += amt;
        }
    }

    fn read_bytes(bytes: &[u8]) -> Result<Request, ReadError> {
        read_request(&mut Cursor::new(bytes.to_vec()))
    }

    fn read_str(text: &str) -> Result<Request, ReadError> {
        read_bytes(text.as_bytes())
    }

    // ---- the brief's tests ----

    #[test]
    fn the_requests_qnet_sends_are_read_one_after_another() {
        let post = "POST /api/dns/blocking HTTP/1.1\r\nHost: 192.0.2.53\r\nx-ftl-sid: 0123abcd\r\nContent-Type: application/json\r\nContent-Length: 30\r\nConnection: close\r\n\r\n{\"blocking\":false,\"timer\":300}";
        let mut r = Cursor::new(format!("{QNET_GET}{post}"));
        let first = read_request(&mut r).unwrap();
        assert_eq!(
            (
                first.method.as_str(),
                first.target.as_str(),
                first.sid.as_deref(),
                first.close
            ),
            ("GET", "/api/stats/summary", Some("0123abcd"), false)
        );
        let second = read_request(&mut r).unwrap();
        assert_eq!(
            (second.body.as_slice(), second.close),
            (&b"{\"blocking\":false,\"timer\":300}"[..], true)
        );
        assert_eq!(read_request(&mut r), Err(ReadError::Closed));
    }

    #[test]
    fn oversized_chunked_or_broken_requests_are_refused() {
        // Review Focus 2
        let big_head = format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(MAX_HEAD));
        let big_body = "POST /api/auth HTTP/1.1\r\nContent-Length: 5000\r\n\r\n";
        let chunked = "POST /api/auth HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        let two_lengths =
            "POST /api/auth HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab";
        assert_eq!(
            read_request(&mut Cursor::new(big_head)),
            Err(ReadError::TooLarge)
        );
        assert_eq!(
            read_request(&mut Cursor::new(big_body)),
            Err(ReadError::TooLarge)
        );
        assert!(matches!(
            read_request(&mut Cursor::new(chunked)),
            Err(ReadError::Malformed(_))
        ));
        assert!(matches!(
            read_request(&mut Cursor::new(two_lengths)),
            Err(ReadError::Malformed(_))
        ));
        assert!(matches!(
            read_request(&mut Cursor::new("GET /api/auth HTTP/1.1\r\nHost")),
            Err(ReadError::Malformed(_))
        ));
        assert!(matches!(
            read_request(&mut Cursor::new("\x16\x03\x01garbage\r\n\r\n")),
            Err(ReadError::Malformed(_))
        ));
    }

    #[test]
    fn a_sid_is_taken_only_from_its_header_and_only_when_plain() {
        // Review Focus 3
        let with = |h: &str| {
            read_request(&mut Cursor::new(format!(
                "GET /api/auth?sid=abc HTTP/1.1\r\n{h}\r\n\r\n"
            )))
            .unwrap()
            .sid
        };
        assert_eq!(with("Cookie: sid=abc"), None);
        assert_eq!(with("X-FTL-SID: a b"), None);
        assert_eq!(with(&format!("X-FTL-SID: {}", "a".repeat(513))), None);
        assert_eq!(with("X-FTL-SID: abc"), Some("abc".to_owned()));
    }

    #[test]
    fn a_reply_is_written_whole() {
        let mut out = Vec::new();
        write_reply(
            &mut out,
            &Reply {
                status: 401,
                body: b"{}".to_vec(),
            },
            false,
        )
        .unwrap();
        assert_eq!(out, b"HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: 2\r\nCache-Control: no-store\r\nConnection: keep-alive\r\n\r\n{}");
        let mut out = Vec::new();
        write_reply(
            &mut out,
            &Reply {
                status: 204,
                body: vec![],
            },
            true,
        )
        .unwrap();
        assert_eq!(out, b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n");
    }

    // ---- the head ----

    /// A request whose head, terminator included, is exactly `len` bytes.
    fn head_of(len: usize) -> String {
        let fixed = "GET / HTTP/1.1\r\nX: \r\n\r\n".len();
        format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(len - fixed))
    }

    #[test]
    fn a_head_of_exactly_max_head_bytes_is_accepted_and_one_more_is_not() {
        let exact = head_of(MAX_HEAD);
        assert_eq!(exact.len(), MAX_HEAD);
        assert!(read_str(&exact).is_ok());
        let over = head_of(MAX_HEAD + 1);
        assert_eq!(read_str(&over), Err(ReadError::TooLarge));
        // The same, with the bytes arriving one at a time.
        let mut r = Chunks::one_byte_at_a_time(exact.as_bytes());
        assert!(read_request(&mut r).is_ok());
        let mut r = Chunks::one_byte_at_a_time(over.as_bytes());
        assert_eq!(read_request(&mut r), Err(ReadError::TooLarge));
    }

    #[test]
    fn a_head_with_no_end_is_refused_without_reading_on() {
        // An endless head: the reader would never end, but the call does.
        let mut r = Cursor::new(vec![b'a'; MAX_HEAD * 4]);
        assert_eq!(read_request(&mut r), Err(ReadError::TooLarge));
        assert!(r.position() <= MAX_HEAD as u64, "read {}", r.position());
    }

    #[test]
    fn the_end_of_the_head_may_fall_between_two_reads_at_any_place() {
        let both = format!("{QNET_GET}{QNET_POST}");
        for split in 0..=both.len() {
            let (a, b) = both.as_bytes().split_at(split);
            let mut r = Chunks::new(&[a, b]);
            let first = read_request(&mut r).unwrap_or_else(|e| panic!("split {split}: {e:?}"));
            assert_eq!(first.target, "/api/stats/summary", "split {split}");
            let second = read_request(&mut r).unwrap_or_else(|e| panic!("split {split}: {e:?}"));
            assert_eq!(second.body.len(), 30, "split {split}");
            assert_eq!(
                read_request(&mut r),
                Err(ReadError::Closed),
                "split {split}"
            );
        }
        let mut r = Chunks::one_byte_at_a_time(both.as_bytes());
        assert!(read_request(&mut r).is_ok());
        assert!(read_request(&mut r).is_ok());
        assert_eq!(read_request(&mut r), Err(ReadError::Closed));
    }

    #[test]
    fn exactly_the_head_and_the_body_are_consumed() {
        let both = format!("{QNET_POST}{QNET_GET}");
        let mut r = Cursor::new(both.as_bytes());
        read_request(&mut r).unwrap();
        assert_eq!(r.position() as usize, QNET_POST.len());
        read_request(&mut r).unwrap();
        assert_eq!(r.position() as usize, both.len());
    }

    #[test]
    fn a_stream_that_ends_is_closed_before_any_byte_and_cut_short_after() {
        assert_eq!(read_str(""), Err(ReadError::Closed));
        assert_eq!(read_str("G"), Err(ReadError::Malformed("cut short")));
        assert_eq!(
            read_str("GET / HTTP/1.1\r\n"),
            Err(ReadError::Malformed("cut short"))
        );
        assert_eq!(
            read_str("GET / HTTP/1.1\r\nHost: x\r\n\r"),
            Err(ReadError::Malformed("cut short"))
        );
    }

    #[test]
    fn an_io_error_is_reported_with_its_kind_and_an_interruption_is_retried() {
        let timed_out = Chunks::new(&[]).failing(io::ErrorKind::TimedOut);
        assert_eq!(
            read_request(&mut { timed_out }),
            Err(ReadError::Io(io::ErrorKind::TimedOut))
        );
        let half = Chunks::new(&[b"GET / HTT"]).failing(io::ErrorKind::WouldBlock);
        assert_eq!(
            read_request(&mut { half }),
            Err(ReadError::Io(io::ErrorKind::WouldBlock))
        );
        let mut r = Chunks::new(&[QNET_GET.as_bytes()]).interrupted(3);
        assert!(read_request(&mut r).is_ok());
        let body = Chunks::new(&[b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nab"])
            .failing(io::ErrorKind::ConnectionReset);
        assert_eq!(
            read_request(&mut { body }),
            Err(ReadError::Io(io::ErrorKind::ConnectionReset))
        );
    }

    #[test]
    fn the_head_must_be_a_whole_http_request() {
        assert!(matches!(
            read_str("GET / HTTP/2.0\r\n\r\n"),
            Err(ReadError::Malformed(_))
        ));
        assert!(matches!(
            read_str("GET\r\n\r\n"),
            Err(ReadError::Malformed(_))
        ));
        assert!(matches!(read_str("\r\n\r\n"), Err(ReadError::Malformed(_))));
        // A head that httparse ends before our terminator, on bare line feeds, with more after.
        assert!(matches!(
            read_str("GET / HTTP/1.1\n\nGET /x HTTP/1.1\r\n\r\n"),
            Err(ReadError::Malformed(_))
        ));
    }

    #[test]
    fn more_than_max_headers_are_refused_and_exactly_that_many_are_not() {
        let with = |n: usize| {
            let headers: String = (0..n).map(|i| format!("H{i}: v\r\n")).collect();
            read_str(&format!("GET / HTTP/1.1\r\n{headers}\r\n"))
        };
        assert!(with(MAX_HEADERS).is_ok());
        assert_eq!(
            with(MAX_HEADERS + 1),
            Err(ReadError::Malformed("too many headers"))
        );
    }

    // ---- the body ----

    #[test]
    fn a_content_length_is_digits_and_nothing_else() {
        for bad in ["+5", "-1", "5x", "5 5", "0x5", "", "five", "5,5", "1e1"] {
            let req = format!("POST / HTTP/1.1\r\nContent-Length: {bad}\r\n\r\n12345");
            assert!(
                matches!(read_str(&req), Err(ReadError::Malformed(_))),
                "{bad:?}"
            );
        }
        let ok = read_str("POST / HTTP/1.1\r\nContent-Length:   5  \r\n\r\n12345").unwrap();
        assert_eq!(ok.body, b"12345");
    }

    #[test]
    fn equal_content_lengths_are_one_length_and_different_ones_are_not() {
        let same = "POST / HTTP/1.1\r\nContent-Length: 2\r\ncontent-length: 2\r\n\r\nab";
        assert_eq!(read_str(same).unwrap().body, b"ab");
        let zeros = "POST / HTTP/1.1\r\nContent-Length: 02\r\nContent-Length: 2\r\n\r\nab";
        assert_eq!(read_str(zeros).unwrap().body, b"ab");
        let differ = "POST / HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nabc";
        assert!(matches!(read_str(differ), Err(ReadError::Malformed(_))));
        let one_bad = "POST / HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: x\r\n\r\nab";
        assert!(matches!(read_str(one_bad), Err(ReadError::Malformed(_))));
    }

    #[test]
    fn a_body_of_exactly_max_body_bytes_is_read_and_one_more_is_refused_unread() {
        let body = "b".repeat(MAX_BODY);
        let ok = read_str(&format!(
            "POST / HTTP/1.1\r\nContent-Length: {MAX_BODY}\r\n\r\n{body}"
        ))
        .unwrap();
        assert_eq!(ok.body.len(), MAX_BODY);
        // No body follows: it is refused for its size, not for being cut short.
        let over = format!(
            "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        assert_eq!(read_str(&over), Err(ReadError::TooLarge));
        let huge = "POST / HTTP/1.1\r\nContent-Length: 99999999999999999999999999\r\n\r\n";
        assert_eq!(read_str(huge), Err(ReadError::TooLarge));
        let mut r = Cursor::new(format!("{over}{}", "b".repeat(MAX_BODY + 1)));
        assert_eq!(read_request(&mut r), Err(ReadError::TooLarge));
        assert_eq!(r.position() as usize, over.len(), "no body byte was read");
    }

    #[test]
    fn a_body_that_ends_early_is_cut_short() {
        let req = "POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc";
        assert_eq!(read_str(req), Err(ReadError::Malformed("cut short")));
    }

    #[test]
    fn without_a_content_length_the_body_is_empty_and_what_follows_is_left_alone() {
        let mut r = Cursor::new("POST / HTTP/1.1\r\n\r\nleft over");
        assert!(read_request(&mut r).unwrap().body.is_empty());
        let mut rest = String::new();
        r.read_to_string(&mut rest).unwrap();
        assert_eq!(rest, "left over");
        let zero = read_str("POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n").unwrap();
        assert!(zero.body.is_empty());
    }

    #[test]
    fn any_transfer_encoding_is_refused() {
        for te in ["chunked", "identity", "gzip, chunked", ""] {
            let req = format!("POST / HTTP/1.1\r\ntransfer-ENCODING: {te}\r\n\r\n0\r\n\r\n");
            assert_eq!(
                read_str(&req),
                Err(ReadError::Malformed("no chunked requests")),
                "{te:?}"
            );
        }
        let both = "POST / HTTP/1.1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\nabcd";
        assert_eq!(
            read_str(both),
            Err(ReadError::Malformed("no chunked requests"))
        );
    }

    // ---- sid, close, method and target ----

    #[test]
    fn the_sid_header_is_matched_in_any_case_and_a_second_one_voids_it() {
        let with = |h: &str| {
            read_str(&format!("GET / HTTP/1.1\r\n{h}\r\n\r\n"))
                .unwrap()
                .sid
        };
        assert_eq!(with("x-FtL-sId: abc"), Some("abc".to_owned()));
        assert_eq!(with("X-FTL-SID: abc\r\nX-FTL-SID: abc"), None);
        assert_eq!(with("X-FTL-SID: abc\r\nx-ftl-sid: def"), None);
        assert_eq!(
            with("X-FTL-SID: abc\r\nCookie: sid=abc"),
            Some("abc".to_owned())
        );
        assert_eq!(with("X-FTL-SID:"), None);
        assert_eq!(with("X-FTL-SID: "), None);
        assert_eq!(with("X-FTL-SID-2: abc"), None);
    }

    #[test]
    fn a_sid_is_one_to_512_bytes_in_the_visible_range() {
        let with = |value: &[u8]| {
            let mut req = b"GET / HTTP/1.1\r\nX-FTL-SID: ".to_vec();
            req.extend_from_slice(value);
            req.extend_from_slice(b"\r\n\r\n");
            read_bytes(&req)
        };
        let exact = "a".repeat(512);
        assert_eq!(with(exact.as_bytes()).unwrap().sid, Some(exact));
        assert_eq!(with("a".repeat(513).as_bytes()).unwrap().sid, None);
        assert_eq!(with(b"!~").unwrap().sid, Some("!~".to_owned()));
        // A byte over 0x7F, or a tab inside, is no sid; the request goes on without one.
        for bad in [&b"ab\x80cd"[..], &b"\xff"[..], &b"ab\tcd"[..]] {
            assert_eq!(with(bad).unwrap().sid, None, "{bad:?}");
        }
        // Outer spaces are not part of the value; a 0x7F is one httparse refuses outright.
        assert_eq!(with(b"abc ").unwrap().sid, Some("abc".to_owned()));
        assert_eq!(
            with(b"ab\x7fcd"),
            Err(ReadError::Malformed("bad header value"))
        );
    }

    #[test]
    fn a_connection_is_closed_for_http_1_0_or_a_close_token() {
        let close = |version: &str, h: &str| {
            read_str(&format!("GET / HTTP/{version}\r\n{h}\r\n\r\n"))
                .unwrap()
                .close
        };
        assert!(!close("1.1", "Host: x"));
        assert!(close("1.0", "Host: x"));
        assert!(close("1.0", "Connection: keep-alive"));
        assert!(close("1.1", "Connection: close"));
        assert!(close("1.1", "Connection: keep-alive, Close"));
        assert!(close("1.1", "connection: CLOSE , upgrade"));
        assert!(close("1.1", "Connection: keep-alive\r\nConnection: close"));
        assert!(!close("1.1", "Connection: keep-alive"));
        assert!(!close("1.1", "Connection: closed"));
        assert!(!close("1.1", "Connection: unclose"));
        assert!(!close("1.1", "Connection: upgrade"));
        assert!(!close("1.1", "X-Connection: close"));
    }

    #[test]
    fn a_header_value_that_is_not_utf_8_harms_nothing() {
        let req = b"GET / HTTP/1.1\r\nX-Thing: \xff\xfe\xc3\x28\r\nConnection: \xff, close\r\nX-FTL-SID: abc\r\n\r\n";
        let r = read_bytes(req).unwrap();
        assert_eq!(r.sid.as_deref(), Some("abc"));
        assert!(r.close);
        let keep = read_bytes(b"GET / HTTP/1.1\r\nConnection: \xff\r\n\r\n").unwrap();
        assert!(!keep.close);
        let bad_length = b"POST / HTTP/1.1\r\nContent-Length: \xff\r\n\r\nx";
        assert!(matches!(
            read_bytes(bad_length),
            Err(ReadError::Malformed(_))
        ));
        let bad_target = b"GET /\xff\xfe HTTP/1.1\r\n\r\n";
        assert!(matches!(
            read_bytes(bad_target),
            Err(ReadError::Malformed(_))
        ));
    }

    #[test]
    fn method_and_target_are_copied_as_given() {
        let r = read_str("DELETE /api/auth?x=1&y=%20 HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(
            (r.method.as_str(), r.target.as_str()),
            ("DELETE", "/api/auth?x=1&y=%20")
        );
        let r = read_str("get /a HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(r.method, "get");
    }

    #[test]
    fn debug_shows_neither_the_sid_nor_the_body() {
        let r = read_str(
            "POST /api/auth HTTP/1.1\r\nX-FTL-SID: topsecretsid\r\nContent-Length: 14\r\n\r\npassword-hunt2",
        )
        .unwrap();
        let shown = format!("{r:?}");
        assert!(!shown.contains("topsecretsid"), "{shown}");
        assert!(!shown.contains("hunt2"), "{shown}");
        assert!(!shown.contains("password"), "{shown}");
        assert!(shown.contains("redacted"), "{shown}");
        assert!(shown.contains("/api/auth"), "{shown}");
        let none = format!("{:?}", read_str("GET / HTTP/1.1\r\n\r\n").unwrap());
        assert!(none.contains("sid: None"), "{none}");
        // The error that a refused request gives shows nothing of it either.
        assert_eq!(
            format!("{:?}", ReadError::Malformed("cut short")),
            "Malformed(\"cut short\")"
        );
    }

    #[test]
    fn debug_shows_the_path_of_a_target_and_never_its_query() {
        let r = read_str("GET /api/x?sid=topsecret HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(
            r.target, "/api/x?sid=topsecret",
            "the field itself is whole"
        );
        let shown = format!("{r:?}");
        assert!(!shown.contains("topsecret"), "{shown}");
        assert!(!shown.contains("sid="), "{shown}");
        assert!(shown.contains("/api/x?<redacted>"), "{shown}");
        // Several parameters, an empty query, and a target with no query at all.
        let many = read_str("GET /a?x=1&sid=topsecret&y=2 HTTP/1.1\r\n\r\n").unwrap();
        assert!(!format!("{many:?}").contains("topsecret"));
        let empty = read_str("GET /a? HTTP/1.1\r\n\r\n").unwrap();
        assert!(format!("{empty:?}").contains("/a?<redacted>"));
        let plain = read_str("GET /api/stats/summary HTTP/1.1\r\n\r\n").unwrap();
        let shown = format!("{plain:?}");
        assert!(shown.contains("/api/stats/summary"), "{shown}");
        assert!(!shown.contains("?<"), "{shown}");
    }

    #[test]
    fn the_head_never_holds_more_room_than_max_head() {
        let exact = head_of(MAX_HEAD);
        for step in [1, 7, 500, 1_000, MAX_HEAD] {
            let chunks: Vec<&[u8]> = exact.as_bytes().chunks(step).collect();
            let head = read_head(&mut Chunks::new(&chunks)).unwrap();
            assert_eq!(head.len(), MAX_HEAD, "step {step}");
            assert!(
                head.capacity() <= MAX_HEAD,
                "step {step}: {}",
                head.capacity()
            );
        }
        let small = read_head(&mut Cursor::new(QNET_GET)).unwrap();
        assert!(small.capacity() <= MAX_HEAD);
    }

    #[test]
    fn nothing_the_network_sends_makes_a_read_panic_or_run_on() {
        // A fixed-seed xorshift, so a failure repeats.
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let seeds = [QNET_GET.as_bytes(), QNET_POST.as_bytes()];
        for round in 0..3000 {
            let mut bytes = if round % 3 == 0 {
                (0..next() % 300).map(|_| next() as u8).collect::<Vec<u8>>()
            } else {
                seeds[(next() % 2) as usize].to_vec()
            };
            for _ in 0..next() % 6 {
                if bytes.is_empty() {
                    break;
                }
                let at = (next() % bytes.len() as u64) as usize;
                match next() % 3 {
                    0 => bytes[at] = next() as u8,
                    1 => {
                        bytes.remove(at);
                    }
                    _ => bytes.insert(at, b"\r\n: ,"[(next() % 5) as usize]),
                }
            }
            if round % 10 == 0 {
                // More than a head and a body can take, so that the bound below can be reached.
                bytes.extend(std::iter::repeat_n(b'a', MAX_HEAD + MAX_BODY));
            }
            let cut = (next() % (bytes.len() as u64 + 1)) as usize;
            let (a, b) = bytes.split_at(cut);
            // Whatever happens, it ends in a value, and at most MAX_HEAD + MAX_BODY bytes are used.
            let mut r = Chunks::new(&[a, b]);
            let _ = read_request(&mut r);
            assert!(
                r.consumed <= MAX_HEAD + MAX_BODY,
                "round {round}: {}",
                r.consumed
            );
        }
    }

    // ---- replies ----

    fn written(status: u16, body: &[u8], close: bool) -> String {
        let mut out = Vec::new();
        let reply = Reply {
            status,
            body: body.to_vec(),
        };
        write_reply(&mut out, &reply, close).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn every_status_has_its_reason_and_any_other_is_unknown() {
        for (status, reason) in [
            (200, "OK"),
            (204, "No Content"),
            (400, "Bad Request"),
            (401, "Unauthorized"),
            (404, "Not Found"),
            (405, "Method Not Allowed"),
            (413, "Content Too Large"),
            (429, "Too Many Requests"),
            (500, "Internal Server Error"),
            (418, "Unknown"),
            (0, "Unknown"),
            (u16::MAX, "Unknown"),
        ] {
            let text = written(status, b"x", false);
            let first = text.lines().next().unwrap();
            assert_eq!(first, format!("HTTP/1.1 {status} {reason}"));
        }
    }

    #[test]
    fn a_204_has_no_type_and_no_body_even_when_it_is_given_one() {
        let text = written(204, b"{\"oops\":true}", false);
        assert_eq!(
            text,
            "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nCache-Control: no-store\r\nConnection: keep-alive\r\n\r\n"
        );
    }

    #[test]
    fn the_length_is_the_bytes_of_the_body() {
        let body = "{\"name\":\"caf\u{e9}\"}";
        let text = written(200, body.as_bytes(), true);
        assert!(text.contains(&format!("Content-Length: {}\r\n", body.len())));
        assert!(text.ends_with(&format!("\r\n\r\n{body}")));
        assert!(text.contains("Connection: close\r\n"));
    }

    #[test]
    fn a_replys_debug_shows_its_status_and_the_size_of_its_body_and_nothing_of_the_body() {
        let sid = "0123456789abcdef0123456789abcdef";
        let body =
            format!("{{\"session\":{{\"valid\":true,\"sid\":\"{sid}\",\"validity\":1800}}}}");
        let reply = Reply {
            status: 200,
            body: body.clone().into_bytes(),
        };
        let shown = format!("{reply:?}");
        assert_eq!(
            shown,
            format!("Reply {{ status: 200, body: <{} bytes> }}", body.len())
        );
        assert!(!shown.contains(sid), "{shown}");
        assert!(!shown.contains("session"), "{shown}");
        // The same for the pretty form, and for a reply inside a Result, as `assert_eq!` shows it.
        let pretty = format!("{reply:#?}");
        assert!(!pretty.contains(sid), "{pretty}");
        let wrapped: Result<Reply, ()> = Ok(reply);
        assert!(!format!("{wrapped:?}").contains(sid));
        // `PartialEq` still compares the bytes.
        assert_eq!(
            Reply {
                status: 200,
                body: b"a".to_vec()
            },
            Reply {
                status: 200,
                body: b"a".to_vec()
            }
        );
        assert_ne!(
            Reply {
                status: 200,
                body: b"a".to_vec()
            },
            Reply {
                status: 200,
                body: b"b".to_vec()
            }
        );
    }

    /// A writer that notes whether it was flushed, and can be made to fail.
    struct Probe {
        bytes: Vec<u8>,
        flushed_at: Option<usize>,
        fail: bool,
    }

    impl Write for Probe {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.fail {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            // Take a few bytes at a time, as a stream may.
            let n = buf.len().min(7);
            self.bytes.extend_from_slice(&buf[..n]);
            Ok(n)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushed_at = Some(self.bytes.len());
            Ok(())
        }
    }

    #[test]
    fn a_reply_is_all_written_then_flushed_and_a_failed_write_is_reported() {
        let mut probe = Probe {
            bytes: Vec::new(),
            flushed_at: None,
            fail: false,
        };
        let reply = Reply {
            status: 200,
            body: b"{\"a\":1}".to_vec(),
        };
        write_reply(&mut probe, &reply, false).unwrap();
        assert!(probe.bytes.ends_with(b"\r\n\r\n{\"a\":1}"));
        assert_eq!(probe.flushed_at, Some(probe.bytes.len()));
        probe.fail = true;
        let err = write_reply(&mut probe, &reply, false).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }
}
