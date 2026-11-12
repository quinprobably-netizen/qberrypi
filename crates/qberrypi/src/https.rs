//! A blocking HTTP/1.1 GET over TLS, for fetching the block lists.
//!
//! A connection is one blocking job from the connect to the last byte of the body: a plain
//! `TcpStream` under `rustls::StreamOwned`, with the pure-Rust `rustls-rustcrypto` provider
//! (the board's processor has no AES instructions, and nothing here may need a C compiler).
//! [`Client::fetch`] runs it through [`blocking`], so the TLS handshake, every record
//! and every wait on the socket stay off the runtime thread.
//!
//! Every wait has an end: the connect, each read and each write wait at most what is left to the
//! fetch's deadline, and the deadline is [`TOTAL_WAIT`] from its start. Memory is bounded by
//! [`MAX_HEAD`] and [`MAX_BODY`].
//!
//! No error here holds a URL, a host name or a byte of a response: callers log them.

use std::fmt;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use qb_dns::name::{MAX_NAME_LEN, normalize};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::ServerName;
use rustls::{CertificateError, CipherSuite, ClientConfig, ClientConnection, RootCertStore};
use rustls::{StreamOwned, version};

use crate::dns::Dns;
use crate::services::blocking;

/// The `User-Agent` of every request: nothing of ours.
pub const USER_AGENT: &str = "list-fetch";
/// The port of a URL that names none.
pub const HTTPS_PORT: u16 = 443;
/// The most bytes of a body that is taken. The only bound on the size of a list.
pub const MAX_BODY: usize = 32 * 1024 * 1024;
/// The most bytes of a response head (the status line and the headers) that is taken.
pub const MAX_HEAD: usize = 16 * 1024;
/// The longest wait for a TCP connection.
pub const CONNECT_WAIT: Duration = Duration::from_secs(10);
/// The longest wait for one read or one write.
pub const IO_WAIT: Duration = Duration::from_secs(15);
/// The longest a whole fetch takes, redirects included.
pub const TOTAL_WAIT: Duration = Duration::from_secs(120);
/// The most redirects that a fetch follows.
pub const MAX_REDIRECTS: usize = 3;

/// The most headers in a response head.
const MAX_HEADERS: usize = 100;
/// The longest line of a chunked body's framing that is taken: a chunk size and its extensions.
const MAX_LINE: usize = 4 * 1024;
/// How much of a body of known length is made room for before any of it arrives.
const FIRST_ROOM: usize = 1024 * 1024;

/// Where a request goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    /// An IPv4 address or a domain name, in lower case.
    pub host: String,
    pub port: u16,
    /// Starts with `/`; the query is part of it, the fragment is not.
    pub path: String,
}

impl Url {
    /// `https://`, a host, an optional `:port` and an optional path that starts with `/`.
    ///
    /// What stands before the path is split at its first `:`, and the host is checked before the
    /// port, so a user, a bracketed IPv6 address or a space is "not a host name". Nothing that
    /// could end the request line early is let through in the path.
    pub fn parse(text: &str) -> Result<Url, HttpError> {
        let rest = without_fragment(text)
            .strip_prefix("https://")
            .ok_or(HttpError::Url("not https"))?;
        let (authority, path) = match rest.find('/') {
            Some(at) => rest.split_at(at),
            None => (rest, "/"),
        };
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        };
        if host.is_empty() {
            return Err(HttpError::Url("no host"));
        }
        let host = host_name(host)?;
        let port = port.map_or(Ok(HTTPS_PORT), port_number)?;
        Ok(Url {
            host,
            port,
            path: checked_path(path)?.to_owned(),
        })
    }
}

/// `text` up to its first `#`.
fn without_fragment(text: &str) -> &str {
    text.split_once('#').map_or(text, |(before, _)| before)
}

/// An IPv4 address, as it is written back, or a name that `qb_dns` takes, in lower case.
fn host_name(text: &str) -> Result<String, HttpError> {
    if let Ok(ip) = text.parse::<Ipv4Addr>() {
        return Ok(ip.to_string());
    }
    let mut buf = [0u8; MAX_NAME_LEN];
    normalize(text.as_bytes(), &mut buf)
        .map(str::to_owned)
        .ok_or(HttpError::Url("not a host name"))
}

/// A port from digits alone, not 0.
fn port_number(text: &str) -> Result<u16, HttpError> {
    let digits = !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
    match text.parse::<u16>() {
        Ok(port) if digits && port != 0 => Ok(port),
        _ => Err(HttpError::Url("not a port")),
    }
}

/// `path` if it is fit for a request line: visible ASCII, which has no space, no line end and
/// no byte that is not ASCII.
fn checked_path(path: &str) -> Result<&str, HttpError> {
    if path.bytes().all(|byte| byte.is_ascii_graphic()) {
        Ok(path)
    } else {
        Err(HttpError::Url("not a path"))
    }
}

/// Why a fetch failed. `Display` is lower case and holds no URL, no host name and nothing a
/// server sent.
#[derive(Debug)]
pub enum HttpError {
    /// The URL is not one that is fetched; the reason is a fixed text.
    Url(&'static str),
    /// The name of the host has no address.
    Resolve(io::Error),
    /// The TCP connection was not made, or the job that makes it was lost.
    Connect(io::Error),
    /// The handshake or the TLS stream failed; the text names the kind of failure only.
    Tls(String),
    /// A wait ran out, or the fetch's time did.
    Timeout,
    /// The server answered with a status that is no body and no redirect.
    Status(u16),
    /// The server's answer is not HTTP that this takes; the reason is a fixed text.
    BadResponse(&'static str),
    /// The stream ended, or broke, before the answer was whole.
    Truncated,
    /// The body is over the limit.
    TooLarge,
    /// More redirects than [`MAX_REDIRECTS`].
    Redirects,
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Url(reason) => write!(f, "url: {reason}"),
            Self::Resolve(error) => write!(f, "resolve: {error}"),
            Self::Connect(error) => write!(f, "connect: {error}"),
            Self::Tls(what) => write!(f, "tls: {what}"),
            Self::Timeout => f.write_str("timed out"),
            Self::Status(code) => write!(f, "status {code}"),
            Self::BadResponse(reason) => write!(f, "bad response: {reason}"),
            Self::Truncated => f.write_str("response ended early"),
            Self::TooLarge => f.write_str("body too large"),
            Self::Redirects => f.write_str("too many redirects"),
        }
    }
}

impl std::error::Error for HttpError {}

/// What a GET came to.
#[derive(Debug, PartialEq, Eq)]
pub enum Response {
    Body(Vec<u8>),
    /// The `Location` of a redirect, as the server wrote it.
    Redirect(String),
}

/// What the head of a response asks for.
enum Head {
    Body(Framing),
    Redirect(String),
}

/// Where a body ends.
#[derive(Clone, Copy)]
enum Framing {
    Chunked,
    Length(usize),
    /// At the end of the stream.
    Close,
}

/// What a read or a write on an open stream that failed means.
fn failure(error: io::Error) -> HttpError {
    if let Some(tls) = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    {
        return HttpError::Tls(describe(tls));
    }
    match error.kind() {
        ErrorKind::TimedOut | ErrorKind::WouldBlock => HttpError::Timeout,
        // An end without the peer's TLS close notice is `UnexpectedEof`; a reset is as good.
        _ => HttpError::Truncated,
    }
}

/// [`failure`] for the handshake, in which an end is the server's refusal, not a short answer.
fn handshake_failure(error: io::Error) -> HttpError {
    match failure(error) {
        HttpError::Truncated => HttpError::Tls("closed during the handshake".to_owned()),
        other => other,
    }
}

/// What a failed connect means: a wait that ran out is a [`HttpError::Timeout`] like any other.
fn connect_failure(error: io::Error) -> HttpError {
    match error.kind() {
        ErrorKind::TimedOut | ErrorKind::WouldBlock => HttpError::Timeout,
        _ => HttpError::Connect(error),
    }
}

/// What a TLS error says, without a name: rustls words a bad certificate with the host that
/// was asked for and the names the certificate holds.
fn describe(error: &rustls::Error) -> String {
    let rustls::Error::InvalidCertificate(certificate) = error else {
        return error.to_string();
    };
    let why = match certificate {
        CertificateError::Expired | CertificateError::ExpiredContext { .. } => "expired",
        CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
            "not valid yet"
        }
        CertificateError::UnknownIssuer => "unknown issuer",
        CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
            "not valid for the name"
        }
        CertificateError::BadSignature => "bad signature",
        CertificateError::Revoked => "revoked",
        _ => "rejected",
    };
    format!("invalid peer certificate: {why}")
}

/// The bytes read from a stream, with a deadline for every read.
struct Input<'a, S> {
    stream: &'a mut S,
    /// The head is read into all of it, and the body's framing is parsed out of it.
    buf: Vec<u8>,
    /// The bytes of `buf` from `start` to `end` are read and not yet used.
    start: usize,
    end: usize,
    deadline: Instant,
}

impl<'a, S: Read> Input<'a, S> {
    fn new(stream: &'a mut S, deadline: Instant) -> Self {
        Self {
            stream,
            buf: vec![0; MAX_HEAD],
            start: 0,
            end: 0,
            deadline,
        }
    }

    /// Reads once more, into the room that is left in the buffer, which is made first if all the
    /// bytes in it are used; the number of bytes, 0 at the end of the stream. The caller sees
    /// to it that there is room.
    fn fill(&mut self) -> Result<usize, HttpError> {
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
        } else if self.end == self.buf.len() {
            self.buf.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
        loop {
            if Instant::now() >= self.deadline {
                return Err(HttpError::Timeout);
            }
            match self.stream.read(&mut self.buf[self.end..]) {
                Ok(n) => {
                    self.end += n;
                    return Ok(n);
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(failure(error)),
            }
        }
    }

    /// Reads the status line and the headers, and decides what the response is.
    fn head(&mut self) -> Result<Head, HttpError> {
        loop {
            if let Some((head, used)) = parse_head(&self.buf[..self.end])? {
                self.start = used;
                return Ok(head);
            }
            if self.end == self.buf.len() {
                return Err(HttpError::BadResponse("head too large"));
            }
            if self.fill()? == 0 {
                return Err(HttpError::Truncated);
            }
        }
    }

    /// The body, to its end, never over `max_body` bytes.
    fn body(&mut self, framing: Framing, max_body: usize) -> Result<Vec<u8>, HttpError> {
        match framing {
            Framing::Length(len) => {
                if len > max_body {
                    return Err(HttpError::TooLarge);
                }
                let mut body = Vec::with_capacity(len.min(FIRST_ROOM));
                self.copy(len, &mut body)?;
                Ok(body)
            }
            Framing::Chunked => self.chunks(max_body),
            Framing::Close => self.until_close(max_body),
        }
    }

    /// Appends the next `count` bytes to `body`.
    fn copy(&mut self, count: usize, body: &mut Vec<u8>) -> Result<(), HttpError> {
        let mut left = count;
        while left > 0 {
            if self.start == self.end && self.fill()? == 0 {
                return Err(HttpError::Truncated);
            }
            let take = (self.end - self.start).min(left);
            body.extend_from_slice(&self.buf[self.start..self.start + take]);
            self.start += take;
            left -= take;
        }
        Ok(())
    }

    /// Everything up to the end of the stream.
    fn until_close(&mut self, max_body: usize) -> Result<Vec<u8>, HttpError> {
        let mut body = Vec::new();
        loop {
            if self.start == self.end && self.fill()? == 0 {
                return Ok(body);
            }
            let take = self.end - self.start;
            if take > max_body - body.len() {
                return Err(HttpError::TooLarge);
            }
            body.extend_from_slice(&self.buf[self.start..self.end]);
            self.start = self.end;
        }
    }

    /// The chunks, up to the last one and the trailers after it.
    fn chunks(&mut self, max_body: usize) -> Result<Vec<u8>, HttpError> {
        let mut body = Vec::new();
        loop {
            let size = chunk_size(&self.line()?)?;
            if size == 0 {
                break;
            }
            if size > max_body - body.len() {
                return Err(HttpError::TooLarge);
            }
            self.copy(size, &mut body)?;
            if !self.line()?.is_empty() {
                return Err(HttpError::BadResponse("bad chunk"));
            }
        }
        let mut trailers = 0;
        loop {
            let line = self.line()?;
            if line.is_empty() {
                return Ok(body);
            }
            trailers += line.len();
            if trailers > MAX_HEAD {
                return Err(HttpError::BadResponse("trailers too large"));
            }
        }
    }

    /// The next line without its end, at most [`MAX_LINE`] bytes of it.
    fn line(&mut self) -> Result<Vec<u8>, HttpError> {
        loop {
            let unused = &self.buf[self.start..self.end];
            if let Some(at) = unused.iter().position(|&byte| byte == b'\n') {
                if at >= MAX_LINE {
                    return Err(HttpError::BadResponse("chunk line too long"));
                }
                let mut line = unused[..at].to_vec();
                self.start += at + 1;
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(line);
            }
            if unused.len() >= MAX_LINE {
                return Err(HttpError::BadResponse("chunk line too long"));
            }
            if self.fill()? == 0 {
                return Err(HttpError::Truncated);
            }
        }
    }
}

/// The size on a chunk's first line, in hexadecimal, without its extensions.
fn chunk_size(line: &[u8]) -> Result<usize, HttpError> {
    let bad = || HttpError::BadResponse("bad chunk size");
    let size = line.split(|&byte| byte == b';').next().unwrap_or_default();
    let size = std::str::from_utf8(size).map_err(|_| bad())?.trim();
    if size.is_empty() || !size.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(bad());
    }
    // Digits that are valid but too many for a number: far over any limit.
    usize::from_str_radix(size, 16).map_err(|_| HttpError::TooLarge)
}

/// The response that `bytes` start with and how many bytes its head takes, or `None` if the head
/// is not whole yet.
fn parse_head(bytes: &[u8]) -> Result<Option<(Head, usize)>, HttpError> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut response = httparse::Response::new(&mut headers);
    let used = match response.parse(bytes) {
        Ok(httparse::Status::Complete(used)) => used,
        Ok(httparse::Status::Partial) => return Ok(None),
        Err(_) => return Err(HttpError::BadResponse("not an http response")),
    };
    let head = match response.code {
        Some(200) => Head::Body(framing(response.headers)?),
        Some(301 | 302 | 303 | 307 | 308) => Head::Redirect(location(response.headers)?),
        Some(code) => return Err(HttpError::Status(code)),
        None => return Err(HttpError::BadResponse("not an http response")),
    };
    Ok(Some((head, used)))
}

/// The values of the headers called `name`, whatever the case.
fn values<'h>(
    headers: &'h [httparse::Header<'h>],
    name: &'static str,
) -> impl Iterator<Item = &'h [u8]> {
    headers
        .iter()
        .filter(move |header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value)
}

/// A header value as text.
fn text(value: &[u8]) -> Result<&str, HttpError> {
    std::str::from_utf8(value).map_err(|_| HttpError::BadResponse("bad header"))
}

/// How the body of a 200 response is framed: by `Transfer-Encoding: chunked` if that is there,
/// else by `Content-Length`, else by the end of the stream.
fn framing(headers: &[httparse::Header<'_>]) -> Result<Framing, HttpError> {
    let mut coding = None;
    for value in values(headers, "transfer-encoding") {
        let last = text(value)?
            .split(',')
            .map(str::trim)
            .rfind(|c| !c.is_empty());
        coding = last.or(coding);
    }
    if let Some(coding) = coding {
        return if coding.eq_ignore_ascii_case("chunked") {
            Ok(Framing::Chunked)
        } else {
            Err(HttpError::BadResponse("unsupported transfer encoding"))
        };
    }
    let mut length = None;
    for value in values(headers, "content-length") {
        let digits = text(value)?.trim();
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(HttpError::BadResponse("bad content-length"));
        }
        // Digits that are too many for a number: far over any limit.
        let len = digits.parse::<usize>().map_err(|_| HttpError::TooLarge)?;
        if length.is_some_and(|seen| seen != len) {
            return Err(HttpError::BadResponse("conflicting content-length"));
        }
        length = Some(len);
    }
    Ok(length.map_or(Framing::Close, Framing::Length))
}

/// The `Location` of a redirect.
fn location(headers: &[httparse::Header<'_>]) -> Result<String, HttpError> {
    let value = values(headers, "location")
        .next()
        .ok_or(HttpError::BadResponse("redirect without a location"))?;
    Ok(text(value)?.trim().to_owned())
}

/// One GET of `path` over `stream`, with `host` as the `Host` header.
///
/// Status 200 gives the body; a redirect status with a `Location` gives that; any other status
/// is an error. A body over `max_body` is [`HttpError::TooLarge`], as soon as a `Content-Length`
/// says so or the bytes pass the limit, and one that ends early is [`HttpError::Truncated`], and
/// so is a TLS stream that ends without the peer's close notice. `deadline` is looked at before
/// every read: at it or past it is [`HttpError::Timeout`]; so is a read that times out.
pub fn get<S: Read + Write>(
    stream: &mut S,
    host: &str,
    path: &str,
    max_body: usize,
    deadline: Instant,
) -> Result<Response, HttpError> {
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
    );
    if Instant::now() >= deadline {
        return Err(HttpError::Timeout);
    }
    stream.write_all(request.as_bytes()).map_err(failure)?;
    stream.flush().map_err(failure)?;
    let mut input = Input::new(stream, deadline);
    match input.head()? {
        Head::Redirect(location) => Ok(Response::Redirect(location)),
        Head::Body(framing) => input.body(framing, max_body).map(Response::Body),
    }
}

/// The provider of `rustls-rustcrypto`, with its ChaCha20 suites first: the board's processor has
/// no AES instructions, and ChaCha20 is the quickest cipher without them. TLS 1.3's comes before
/// TLS 1.2's.
pub fn provider() -> CryptoProvider {
    let mut provider = rustls_rustcrypto::provider();
    provider
        .cipher_suites
        .sort_by_key(|suite| match suite.suite() {
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => 0,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            | CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => 1,
            _ => 2,
        });
    provider
}

/// Mozilla's root certificates, as `webpki-roots` carries them.
pub fn mozilla_roots() -> RootCertStore {
    webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect()
}

/// A TLS client that trusts `roots` alone and offers TLS 1.3 and 1.2 with [`provider`].
pub fn client_config(roots: RootCertStore) -> Arc<ClientConfig> {
    let config = ClientConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[&version::TLS13, &version::TLS12])
        .expect("the provider has suites for both TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(config)
}

/// A TCP stream whose every read and write waits [`IO_WAIT`] at most, or what is left to the
/// deadline if that is less: however a peer trickles bytes, TLS cannot hold a read past it.
struct Socket {
    tcp: TcpStream,
    deadline: Instant,
}

impl Socket {
    /// How long the next read or write may wait.
    fn wait(&self) -> io::Result<Duration> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(ErrorKind::TimedOut.into());
        }
        Ok(left.min(IO_WAIT))
    }
}

impl Read for Socket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.tcp.set_read_timeout(Some(self.wait()?))?;
        self.tcp.read(buf)
    }
}

impl Write for Socket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tcp.set_write_timeout(Some(self.wait()?))?;
        self.tcp.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}

/// One connection to `server` and one GET of `url` over it, with the URL's host as the server
/// name of the certificate. Blocking, and over at `deadline` at the latest.
pub fn request(
    tls: &Arc<ClientConfig>,
    server: SocketAddr,
    url: &Url,
    deadline: Instant,
) -> Result<Response, HttpError> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(HttpError::Timeout);
    }
    let tcp =
        TcpStream::connect_timeout(&server, CONNECT_WAIT.min(left)).map_err(connect_failure)?;
    let name = ServerName::try_from(url.host.clone())
        .map_err(|_| HttpError::Tls("not a server name".to_owned()))?;
    let conn = ClientConnection::new(tls.clone(), name)
        .map_err(|error| HttpError::Tls(describe(&error)))?;
    let mut stream = StreamOwned::new(conn, Socket { tcp, deadline });
    while stream.conn.is_handshaking() {
        stream
            .conn
            .complete_io(&mut stream.sock)
            .map_err(handshake_failure)?;
    }
    // The port is part of what the server is asked for unless it is the one `https` has.
    let host = match url.port {
        HTTPS_PORT => url.host.clone(),
        port => format!("{}:{port}", url.host),
    };
    get(&mut stream, &host, &url.path, MAX_BODY, deadline)
}

/// Where a [`Client`] finds the server of a host.
enum Route {
    Dns(Arc<Dns>),
    /// Test only: every host is at this address.
    #[cfg(test)]
    Fixed(SocketAddr),
}

/// Fetches lists over HTTPS.
pub struct Client {
    tls: Arc<ClientConfig>,
    route: Route,
    total_wait: Duration,
}

impl Client {
    /// A client that finds a host's address through `dns` and trusts what `tls` does.
    pub fn new(tls: Arc<ClientConfig>, dns: Arc<Dns>) -> Self {
        Self {
            tls,
            route: Route::Dns(dns),
            total_wait: TOTAL_WAIT,
        }
    }

    /// Test only: a client that sends every host to `server`, and gives up after `total_wait`.
    #[cfg(test)]
    pub(crate) fn fixed(tls: Arc<ClientConfig>, server: SocketAddr, total_wait: Duration) -> Self {
        Self {
            tls,
            route: Route::Fixed(server),
            total_wait,
        }
    }

    /// The body that `url` gives, with at most [`MAX_REDIRECTS`] redirects followed, in no more
    /// than the total wait.
    ///
    /// The host is resolved here, on the runtime and through the DNS service; each connection
    /// from the connect to the last byte is one blocking job.
    pub async fn fetch(&self, url: &str) -> Result<Vec<u8>, HttpError> {
        let mut url = Url::parse(url)?;
        let deadline = Instant::now() + self.total_wait;
        for _ in 0..=MAX_REDIRECTS {
            let server = self.server(&url, deadline).await?;
            let (tls, target) = (self.tls.clone(), url.clone());
            // A job that is lost is told with the text of `blocking`: it names the job only.
            let response = blocking("list fetch", move || {
                request(&tls, server, &target, deadline)
            })
            .await
            .map_err(HttpError::Connect)??;
            match response {
                Response::Body(body) => return Ok(body),
                Response::Redirect(location) => url = redirect_target(&url, &location)?,
            }
        }
        Err(HttpError::Redirects)
    }

    /// The address to connect to for `url`: the first IPv4 address of its host.
    async fn server(&self, url: &Url, deadline: Instant) -> Result<SocketAddr, HttpError> {
        match &self.route {
            Route::Dns(dns) => {
                let left = deadline.saturating_duration_since(Instant::now());
                let found = tokio::time::timeout(left, dns.lookup_v4(&url.host))
                    .await
                    .map_err(|_| HttpError::Timeout)?
                    .map_err(HttpError::Resolve)?;
                let ip = found
                    .first()
                    .ok_or_else(|| HttpError::Resolve(ErrorKind::NotFound.into()))?;
                Ok(SocketAddr::new(IpAddr::V4(*ip), url.port))
            }
            #[cfg(test)]
            Route::Fixed(server) => Ok(*server),
        }
    }
}

/// Where a redirect from `from` goes: to an `https://` URL, or to a path on the same host.
fn redirect_target(from: &Url, location: &str) -> Result<Url, HttpError> {
    if location.starts_with("https://") {
        return Url::parse(location);
    }
    // `//host/path` is another host, whatever the scheme: it is not a path.
    if location.starts_with('/') && !location.starts_with("//") {
        return Ok(Url {
            host: from.host.clone(),
            port: from.port,
            path: checked_path(without_fragment(location))?.to_owned(),
        });
    }
    Err(HttpError::BadResponse("redirect that is not https"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use crate::dns::Dns;
    use crate::dns::testutil::{FixedOffset, Reply, ms, one};
    use crate::dns::upstream::Upstreams;
    use crate::services::testutil::longest_gap;

    use std::collections::VecDeque;
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    use std::thread;

    use qb_dns::BlockSet;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ServerConfig, ServerConnection, StreamOwned};

    /// An hour from now: a deadline that a test does not reach.
    fn an_hour() -> Instant {
        Instant::now() + Duration::from_secs(3600)
    }

    /// A stream whose reads give the bytes it was made with and then end (or fail, if it was made
    /// to), and whose writes are kept.
    struct Canned {
        reads: io::Cursor<Vec<u8>>,
        then: Option<ErrorKind>,
        written: Vec<u8>,
    }

    impl Canned {
        fn new(bytes: &[u8]) -> Self {
            Self {
                reads: io::Cursor::new(bytes.to_vec()),
                then: None,
                written: Vec::new(),
            }
        }

        /// A stream whose reads fail with `kind` once the bytes are read, as a TLS stream does
        /// that ends without the peer's close notice, or a socket that times out.
        fn then_fails(bytes: &[u8], kind: ErrorKind) -> Self {
            Self {
                then: Some(kind),
                ..Self::new(bytes)
            }
        }
    }

    impl Read for Canned {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match (self.reads.read(buf)?, self.then) {
                (0, Some(kind)) if !buf.is_empty() => Err(kind.into()),
                (n, _) => Ok(n),
            }
        }
    }

    impl Write for Canned {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A piece of what [`Generated`] reads.
    enum Part {
        Bytes(Vec<u8>),
        /// This many filler bytes, which are not held anywhere.
        Fill(usize),
    }

    /// A stream whose reads give the parts it was made with, in order, and then end, and whose
    /// writes are dropped: a response of any size without a literal of that size.
    struct Generated(VecDeque<Part>);

    impl Read for Generated {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let (taken, done) = match self.0.front_mut() {
                None => return Ok(0),
                Some(Part::Bytes(bytes)) => {
                    let n = bytes.len().min(buf.len());
                    buf[..n].copy_from_slice(&bytes[..n]);
                    bytes.drain(..n);
                    (n, bytes.is_empty())
                }
                Some(Part::Fill(left)) => {
                    let n = (*left).min(buf.len());
                    buf[..n].fill(b'x');
                    *left -= n;
                    (n, *left == 0)
                }
            };
            if done {
                self.0.pop_front();
            }
            Ok(taken)
        }
    }

    impl Write for Generated {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// `get` over a [`Canned`] stream, with the request it wrote.
    fn exchange(response: &[u8], max_body: usize) -> (String, Result<Response, HttpError>) {
        let mut stream = Canned::new(response);
        let result = get(
            &mut stream,
            "lists.example.net",
            "/lists/a.txt",
            max_body,
            an_hour(),
        );
        (String::from_utf8(stream.written).unwrap(), result)
    }

    /// `get` with [`MAX_BODY`] over a [`Generated`] stream.
    fn generated(parts: Vec<Part>) -> Result<Response, HttpError> {
        get(
            &mut Generated(parts.into()),
            "lists.example.net",
            "/big.txt",
            MAX_BODY,
            an_hour(),
        )
    }

    /// A response with a close-delimited body of `size` filler bytes.
    fn until_close(size: usize) -> Vec<Part> {
        vec![
            Part::Bytes(b"HTTP/1.1 200 OK\r\n\r\n".to_vec()),
            Part::Fill(size),
        ]
    }

    /// A response with a chunked body of `size` filler bytes, in chunks of 1 MiB.
    fn chunked(size: usize) -> Vec<Part> {
        const CHUNK: usize = 1024 * 1024;
        let mut parts = vec![Part::Bytes(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec(),
        )];
        let mut left = size;
        while left > 0 {
            let this = left.min(CHUNK);
            parts.push(Part::Bytes(format!("{this:x}\r\n").into_bytes()));
            parts.push(Part::Fill(this));
            parts.push(Part::Bytes(b"\r\n".to_vec()));
            left -= this;
        }
        parts.push(Part::Bytes(b"0\r\n\r\n".to_vec()));
        parts
    }

    /// Whether `result` is a body of `len` bytes.
    fn is_body_of(result: &Result<Response, HttpError>, len: usize) -> bool {
        matches!(result, Ok(Response::Body(body)) if body.len() == len)
    }

    /// Serves the canned `routes` (a path and the whole response to a GET of it; any other path
    /// gets a 404) over TLS on a `127.0.0.1` port, a thread to a connection, each answering
    /// `answer_after` the request. The certificate is for `localhost`; the store holds it alone.
    fn tls_server(routes: &[(&str, &[u8])], answer_after: Duration) -> (SocketAddr, RootCertStore) {
        let made = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert = made.cert.der().clone();
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(made.signing_key.serialize_der()));
        let config = ServerConfig::builder_with_provider(Arc::new(provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();

        let config = Arc::new(config);
        let routes: Arc<Vec<(String, Vec<u8>)>> = Arc::new(
            routes
                .iter()
                .map(|(path, response)| ((*path).to_owned(), response.to_vec()))
                .collect(),
        );
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            for tcp in listener.incoming().flatten() {
                let (config, routes) = (config.clone(), routes.clone());
                thread::spawn(move || serve_one(tcp, config, &routes, answer_after));
            }
        });
        (addr, roots)
    }

    /// One connection of [`tls_server`]: reads a request, waits, answers, says goodbye.
    fn serve_one(
        tcp: TcpStream,
        config: Arc<ServerConfig>,
        routes: &[(String, Vec<u8>)],
        answer_after: Duration,
    ) {
        let Ok(conn) = ServerConnection::new(config) else {
            return;
        };
        let mut tls = StreamOwned::new(conn, tcp);
        let mut request = Vec::new();
        let mut buf = [0u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            match tls.read(&mut buf) {
                Ok(n) if n > 0 => request.extend_from_slice(&buf[..n]),
                _ => return,
            }
        }
        let request = String::from_utf8_lossy(&request);
        let path = request.split(' ').nth(1).unwrap_or("");
        let response = routes.iter().find(|(route, _)| route == path).map_or(
            &b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"[..],
            |(_, response)| response,
        );
        thread::sleep(answer_after);
        let _ = tls.write_all(response);
        tls.conn.send_close_notify();
        let _ = tls.flush();
    }

    #[test]
    fn urls() {
        let url = |t| Url::parse(t).unwrap();
        assert_eq!(
            url("https://Lists.Example.NET/a/b.txt"),
            Url {
                host: "lists.example.net".into(),
                port: 443,
                path: "/a/b.txt".into()
            }
        );
        assert_eq!(
            url("https://example.com"),
            Url {
                host: "example.com".into(),
                port: 443,
                path: "/".into()
            }
        );
        assert_eq!(
            url("https://example.com:8443/x?y=1#frag"),
            Url {
                host: "example.com".into(),
                port: 8443,
                path: "/x?y=1".into()
            }
        );
        assert_eq!(url("https://192.0.2.7/l").host, "192.0.2.7");
        for (bad, why) in [
            ("http://example.com/", "not https"),
            ("https://", "no host"),
            ("https://user@example.com/", "not a host name"),
            ("https://exa mple.com/", "not a host name"),
            ("https://[2001:db8::1]/", "not a host name"),
            ("https://example.com:0/", "not a port"),
            ("https://example.com:99999/", "not a port"),
        ] {
            assert!(
                matches!(Url::parse(bad), Err(HttpError::Url(reason)) if reason == why),
                "{bad}"
            );
        }
    }

    #[test]
    fn the_request_is_a_plain_get_that_does_not_name_the_project() {
        let (request, _) = exchange(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 100);
        assert_eq!(
            request,
            "GET /lists/a.txt HTTP/1.1\r\nHost: lists.example.net\r\nUser-Agent: list-fetch\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn a_body_is_read_by_length_by_chunks_or_to_the_end() {
        for response in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"[..],
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nhel\r\n2;x=1\r\nlo\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\nhello",
        ] {
            assert_eq!(
                exchange(response, 100).1.unwrap(),
                Response::Body(b"hello".to_vec())
            );
        }
    }

    #[test]
    fn a_body_that_ends_early_or_is_too_large_is_an_error() {
        assert!(matches!(
            exchange(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello", 100).1,
            Err(HttpError::Truncated)
        ));
        assert!(matches!(
            exchange(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel",
                100
            )
            .1,
            Err(HttpError::Truncated)
        ));
        assert!(matches!(
            exchange(
                b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world",
                10
            )
            .1,
            Err(HttpError::TooLarge)
        ));
        assert!(matches!(
            exchange(b"HTTP/1.1 200 OK\r\n\r\nhello world", 10).1,
            Err(HttpError::TooLarge)
        ));
        // A TLS stream that ends without the peer's close notice is `UnexpectedEof`: not the end
        // of a body that has no length, but a body cut short.
        for response in [
            &b"HTTP/1.1 200 OK\r\n\r\nhello"[..],
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Len",
        ] {
            let mut stream = Canned::then_fails(response, ErrorKind::UnexpectedEof);
            let result = get(&mut stream, "lists.example.net", "/", 100, an_hour());
            assert!(matches!(result, Err(HttpError::Truncated)), "{response:?}");
        }
        assert!(matches!(
            exchange(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nb\r\nhello world\r\n0\r\n\r\n",
                10
            )
            .1,
            Err(HttpError::TooLarge)
        ));
    }

    #[test]
    fn other_statuses_redirects_and_nonsense() {
        assert!(matches!(
            exchange(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", 100).1,
            Err(HttpError::Status(404))
        ));
        assert_eq!(
            exchange(
                b"HTTP/1.1 302 Found\r\nLocation: https://other.example.net/x\r\n\r\n",
                100
            )
            .1
            .unwrap(),
            Response::Redirect("https://other.example.net/x".into())
        );
        assert!(matches!(
            exchange(b"HTTP/1.1 302 Found\r\n\r\n", 100).1,
            Err(HttpError::BadResponse(_))
        ));
        assert!(matches!(
            exchange(b"garbage\r\n\r\n", 100).1,
            Err(HttpError::BadResponse(_))
        ));
        let long_head = [&b"HTTP/1.1 200 OK\r\nX: "[..], &[b'a'; 17_000], b"\r\n\r\n"].concat();
        assert!(matches!(
            exchange(&long_head, 100).1,
            Err(HttpError::BadResponse(_))
        ));
        // What a caller logs: lower case, and nothing of the URL or the server's words.
        assert_eq!(HttpError::Status(404).to_string(), "status 404");
        assert_eq!(HttpError::Timeout.to_string(), "timed out");
        assert_eq!(HttpError::Url("no host").to_string(), "url: no host");
    }

    #[test]
    fn nothing_is_read_once_the_time_is_up() {
        let mut stream = Canned::new(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
        assert!(matches!(
            get(&mut stream, "lists.example.net", "/", 100, Instant::now()),
            Err(HttpError::Timeout)
        ));
    }

    #[test]
    fn a_read_that_times_out_is_a_timeout() {
        for kind in [ErrorKind::TimedOut, ErrorKind::WouldBlock] {
            for response in [
                &b""[..],
                b"HTTP/1.1 200 OK\r\nContent-Len",
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhe",
            ] {
                let mut stream = Canned::then_fails(response, kind);
                let result = get(&mut stream, "lists.example.net", "/", 100, an_hour());
                assert!(matches!(result, Err(HttpError::Timeout)), "{kind:?}");
            }
        }
    }

    #[test]
    fn chacha20_is_offered_first_and_the_roots_are_mozillas() {
        assert_eq!(
            provider().cipher_suites[0].suite(),
            rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
        );
        assert_eq!(mozilla_roots().len(), webpki_roots::TLS_SERVER_ROOTS.len());
        assert!(mozilla_roots().len() > 100);
    }

    #[tokio::test]
    async fn a_list_is_fetched_over_tls_from_a_server_the_roots_vouch_for() {
        let (addr, roots) = tls_server(
            &[(
                "/list.txt",
                b"HTTP/1.1 200 OK\r\nContent-Length: 24\r\n\r\n0.0.0.0 ads.example.com\n",
            )],
            ms(0),
        );
        let client = Client::fixed(client_config(roots), addr, ms(5000));
        assert_eq!(
            client
                .fetch(&format!("https://localhost:{}/list.txt", addr.port()))
                .await
                .unwrap(),
            b"0.0.0.0 ads.example.com\n"
        );
    }

    #[tokio::test]
    async fn a_server_the_roots_do_not_vouch_for_or_under_another_name_is_refused() {
        let (addr, roots) = tls_server(
            &[("/list.txt", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")],
            ms(0),
        );
        let strangers = Client::fixed(client_config(mozilla_roots()), addr, ms(5000));
        let unknown = strangers
            .fetch(&format!("https://localhost:{}/list.txt", addr.port()))
            .await
            .unwrap_err();
        assert!(matches!(unknown, HttpError::Tls(_)), "{unknown}");
        let known = Client::fixed(client_config(roots), addr, ms(5000));
        let other_name = known
            .fetch(&format!(
                "https://lists.example.net:{}/list.txt",
                addr.port()
            ))
            .await
            .unwrap_err();
        assert!(matches!(other_name, HttpError::Tls(_)), "{other_name}");
        // What rustls says of these holds the name asked for and the names in the certificate;
        // what is passed on does not.
        assert_eq!(
            unknown.to_string(),
            "tls: invalid peer certificate: unknown issuer"
        );
        assert_eq!(
            other_name.to_string(),
            "tls: invalid peer certificate: not valid for the name"
        );
    }

    #[tokio::test]
    async fn a_host_is_found_through_the_dns_service() {
        let (addr, roots) = tls_server(
            &[(
                "/list.txt",
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            )],
            ms(0),
        );
        // The resolver answers for `localhost` itself, with 127.0.0.1; `ads.example.com` is denied.
        let (dns, _, _upstream) = one(Reply::Silent).await;
        let client = Client::new(client_config(roots), dns);
        assert_eq!(
            client
                .fetch(&format!("https://localhost:{}/list.txt", addr.port()))
                .await
                .unwrap(),
            b"ok"
        );
        let blocked = client
            .fetch(&format!("https://ads.example.com:{}/list.txt", addr.port()))
            .await
            .unwrap_err();
        assert!(matches!(blocked, HttpError::Resolve(_)), "{blocked}");
    }

    #[tokio::test]
    async fn redirects_are_followed_three_times_and_only_to_https() {
        let routes: [(&str, &[u8]); 9] = [
            ("/a", b"HTTP/1.1 302 Found\r\nLocation: /b\r\n\r\n"),
            ("/b", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
            ("/loop", b"HTTP/1.1 302 Found\r\nLocation: /loop\r\n\r\n"),
            (
                "/plain",
                b"HTTP/1.1 301 Moved Permanently\r\nLocation: http://localhost/x\r\n\r\n",
            ),
            // Three redirects in a row end in a body; four do not.
            (
                "/r4",
                b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /r3\r\n\r\n",
            ),
            (
                "/r3",
                b"HTTP/1.1 308 Permanent Redirect\r\nLocation: /r2\r\n\r\n",
            ),
            ("/r2", b"HTTP/1.1 303 See Other\r\nLocation: /r1\r\n\r\n"),
            ("/r1", b"HTTP/1.1 302 Found\r\nLocation: /b\r\n\r\n"),
            // To another host, over https.
            (
                "/away",
                b"HTTP/1.1 302 Found\r\nLocation: https://localhost/b\r\n\r\n",
            ),
        ];
        let (addr, roots) = tls_server(&routes, ms(0));
        let client = Client::fixed(client_config(roots), addr, ms(20_000));
        let fetch = |path: &str| {
            let url = format!("https://localhost:{}{path}", addr.port());
            let client = &client;
            async move { client.fetch(&url).await }
        };
        assert_eq!(fetch("/a").await.unwrap(), b"ok");
        assert_eq!(fetch("/away").await.unwrap(), b"ok");
        assert_eq!(fetch("/r3").await.unwrap(), b"ok");
        assert!(matches!(fetch("/r4").await, Err(HttpError::Redirects)));
        assert!(matches!(fetch("/loop").await, Err(HttpError::Redirects)));
        assert!(matches!(
            fetch("/plain").await,
            Err(HttpError::BadResponse("redirect that is not https"))
        ));
    }

    #[tokio::test]
    async fn a_server_that_never_speaks_is_given_up_on() {
        // It takes the connection into its queue and never answers.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = Client::fixed(
            client_config(mozilla_roots()),
            listener.local_addr().unwrap(),
            ms(300),
        );
        let started = Instant::now();
        assert!(matches!(
            client.fetch("https://localhost/list.txt").await,
            Err(HttpError::Timeout)
        ));
        assert!(started.elapsed() < ms(1000), "{:?}", started.elapsed());
    }

    #[tokio::test]
    async fn a_server_that_trickles_is_given_up_on_at_the_total_wait() {
        // A TLS record header for 16 KiB, then one byte of it every 50 ms: no single read waits
        // anywhere near `IO_WAIT`, and the record would be whole after 13 minutes.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut tcp, _) = listener.accept().unwrap();
            if tcp.write_all(&[0x16, 0x03, 0x03, 0x40, 0x00]).is_err() {
                return;
            }
            while tcp.write_all(&[0]).is_ok() {
                thread::sleep(ms(50));
            }
        });
        let client = Client::fixed(client_config(mozilla_roots()), addr, ms(400));
        let started = Instant::now();
        assert!(matches!(
            client.fetch("https://localhost/list.txt").await,
            Err(HttpError::Timeout)
        ));
        assert!(started.elapsed() < ms(1500), "{:?}", started.elapsed());
    }

    #[tokio::test]
    async fn a_body_over_32_mib_is_refused_over_tls() {
        let (addr, roots) = tls_server(
            &[(
                "/big.txt",
                b"HTTP/1.1 200 OK\r\nContent-Length: 33554433\r\n\r\n",
            )],
            ms(0),
        );
        let client = Client::fixed(client_config(roots), addr, ms(5000));
        assert!(matches!(
            client
                .fetch(&format!("https://localhost:{}/big.txt", addr.port()))
                .await,
            Err(HttpError::TooLarge)
        ));
    }

    #[test]
    fn get_with_max_body_takes_32_mib_and_refuses_one_byte_more() {
        assert_eq!(MAX_BODY, 32 * 1024 * 1024);
        assert!(is_body_of(&generated(until_close(MAX_BODY)), MAX_BODY));
        assert!(matches!(
            generated(until_close(MAX_BODY + 1)),
            Err(HttpError::TooLarge)
        ));
        assert!(is_body_of(&generated(chunked(MAX_BODY)), MAX_BODY));
        assert!(matches!(
            generated(chunked(MAX_BODY + 1)),
            Err(HttpError::TooLarge)
        ));
    }

    #[tokio::test]
    #[ignore = "reaches the real internet"]
    async fn the_example_lists_are_fetched_from_the_internet() {
        let cfg = config::parse(include_str!("../../../qberrypi.example.toml")).unwrap();
        let dns = Dns::new(
            BlockSet::default(),
            Upstreams::new(&cfg.dns.upstreams),
            Box::new(FixedOffset(0)),
        );
        let client = Client::new(client_config(mozilla_roots()), dns);
        for (index, url) in cfg.dns.lists.iter().enumerate() {
            let started = Instant::now();
            let body = client
                .fetch(url)
                .await
                .unwrap_or_else(|error| panic!("list {index}: {error}"));
            println!(
                "list {index}: {} bytes in {} ms",
                body.len(),
                started.elapsed().as_millis()
            );
            assert!(body.len() > 100_000, "list {index}: {} bytes", body.len());
        }
    }

    #[tokio::test]
    async fn a_fetch_does_not_hold_the_runtime_thread() {
        let (addr, roots) = tls_server(
            &[(
                "/list.txt",
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            )],
            ms(300),
        );
        let client = Client::fixed(client_config(roots), addr, ms(5000));
        let (gap, body) =
            longest_gap(client.fetch(&format!("https://localhost:{}/list.txt", addr.port()))).await;
        assert_eq!(body.unwrap(), b"ok");
        assert!(gap < ms(100), "{gap:?}");
    }
}
