//! The client that `cargo xtask update` talks to the Pi's API with: TLS that trusts one
//! certificate, and a small HTTP/1.1 over it.
//!
//! The Pi's certificate is the self-signed one that `cargo xtask make-cert` made, kept in
//! `qberrypi-tls.pem` and put on the card as `tls.pem`. A name or a date cannot vouch for it, so
//! the client trusts it the way qnet does: the certificate the server presents must be the first
//! one of that file, byte for byte, and no other is taken, whoever signed it. Only after the
//! handshake has proved it is the Pi, by that certificate and by a signature of its key over the
//! handshake (checked with the `ring` provider's algorithms), does the password leave this
//! computer; a connection to anything else fails before a byte of the login is written.
//!
//! The HTTP is what the Pi's API speaks and nothing more: one request at a time on a connection,
//! the reply read by its `Content-Length` (a reply with no length is refused, as is a chunked
//! one), every read and write bounded in time. The body of a request is given as a list of
//! slices and written one after the other, so the update's files are never joined into one
//! buffer. The connection is plain `std`, blocking; there is no runtime in `xtask`.
//!
//! **A refusal that comes before the body is taken.** The Pi answers some requests before the
//! body is read (a refused update closes the connection with the body unread). The client's
//! writes then fail with a reset or a broken pipe while the answer is already waiting in the
//! socket. [`Link::request`] therefore reads for the reply after a failed write, from the socket
//! only and without trying to flush what it still holds, and gives the reply if there is one;
//! only when there is none does the write's own error come out.
//!
//! The password and the session id are held in memory that is wiped when it is dropped, never
//! printed and never in an error. What the TLS library keeps of them in its own buffers is not
//! reachable from here and is not wiped.

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Error, Result, anyhow, bail};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::hashpw;

/// What a server that is not the pinned one is told, which a failed handshake carries.
const NOT_PINNED: &str = "not the pinned certificate";

/// The most bytes the head of a reply may take, its closing empty line included.
const MAX_REPLY_HEAD: usize = 16 * 1024;

/// The most bytes of a reply's body that are taken. The API's replies are small, and an update's
/// answer is one JSON object.
const MAX_REPLY_BODY: usize = 64 * 1024;

/// How long one write to the socket may block.
const WRITE_WAIT: Duration = Duration::from_secs(30);

/// The longest a single read may wait when more time than that is left, so that a stalled
/// connection is noticed at its pace and not at the end of its allowance.
const READ_SLICE: Duration = Duration::from_secs(30);

/// The path of the login, the session check and the logout.
const AUTH: &str = "/api/auth";

/// Accepts the server's certificate if it is the pinned one, byte for byte, and checks the
/// handshake's signatures with the provider's algorithms.
#[derive(Debug)]
struct Pin {
    /// The DER of the certificate that the server must present.
    cert: CertificateDer<'static>,
    /// The algorithms that the handshake's signatures are checked with.
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for Pin {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Neither the name nor the dates mean anything for a certificate that nobody else signed:
        // the pin is the whole of the trust.
        if end_entity.as_ref() == self.cert.as_ref() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(NOT_PINNED.into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// A client on the `ring` provider that trusts the first certificate of `pem` (the content of
/// `qberrypi-tls.pem`) and nothing else.
///
/// An error if `pem` holds no certificate or is not PEM; it quotes nothing from the file.
pub fn client_config(pem: &[u8]) -> Result<Arc<ClientConfig>> {
    let cert = CertificateDer::pem_slice_iter(pem)
        .next()
        .ok_or_else(|| anyhow!("qberrypi-tls.pem holds no certificate to pin"))?
        .map_err(|_| anyhow!("qberrypi-tls.pem is not valid PEM"))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let pin = Pin {
        cert,
        algorithms: provider.signature_verification_algorithms,
    };
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("the TLS client cannot be set up")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(pin))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// One reply, as the client reads it.
#[derive(Debug)]
pub struct Response {
    /// The status code.
    pub status: u16,
    /// The body, at most [`MAX_REPLY_BODY`] bytes.
    pub body: Vec<u8>,
}

impl Response {
    /// The body as JSON, if it is.
    pub fn json(&self) -> Option<Value> {
        serde_json::from_slice(&self.body).ok()
    }

    /// What the Pi said was wrong, in a few words: the key and the message of Pi-hole's error
    /// object (`{"error": {"key", "message"}}`) if the body is one, else the status alone. The
    /// words are the Pi's own fixed ones; control characters are dropped from them.
    pub fn refusal(&self) -> String {
        let said = self.json().and_then(|json| {
            let error = json.get("error")?;
            let key = error.get("key")?.as_str()?;
            let message = error.get("message").and_then(Value::as_str).unwrap_or("");
            Some(if message.is_empty() {
                key.to_owned()
            } else {
                format!("{key}: {message}")
            })
        });
        match said {
            Some(said) => printable(&said),
            None => format!("HTTP status {}", self.status),
        }
    }
}

/// `text` with its control characters dropped and at most 200 characters kept: for a word of the
/// Pi's that is shown on this terminal.
pub fn printable(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(200).collect()
}

/// A request: the method and path, the session if there is one, and the body as a list of slices
/// that are sent one after the other.
pub struct Request<'a> {
    /// `GET`, `POST` and so on.
    pub method: &'a str,
    /// The request target, with no query.
    pub path: &'a str,
    /// The session id, sent as `X-FTL-SID`; at most 512 visible ASCII bytes.
    pub sid: Option<&'a str>,
    /// The `Content-Type` of the body, if there is one.
    pub content_type: Option<&'a str>,
    /// The body, in pieces; their lengths added make the `Content-Length`.
    pub body: &'a [&'a [u8]],
}

/// One TLS connection to the API, and the requests and replies on it.
pub struct Link {
    conn: ClientConnection,
    sock: TcpStream,
    /// What the server's `Host` is taken to be, as a header value.
    host: String,
}

/// The error of a read or write that ran out of time.
fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "no answer within the wait")
}

/// The time left until `deadline`; a timeout error once none is.
fn time_left(deadline: Instant) -> io::Result<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        Err(timed_out())
    } else {
        Ok(left)
    }
}

impl Link {
    /// Connects to `addr` and runs the TLS handshake, all within `wait`.
    ///
    /// The error says that the Pi could not be reached, or that what answered is not the pinned
    /// certificate (nothing has been sent to it then), or that the handshake failed.
    pub fn open(addr: SocketAddr, config: Arc<ClientConfig>, wait: Duration) -> Result<Link> {
        let deadline = Instant::now() + wait;
        let mut sock = TcpStream::connect_timeout(&addr, wait)
            .context("cannot connect to the Pi's API (port 443)")?;
        sock.set_nodelay(true)
            .context("cannot set up the connection to the Pi")?;
        sock.set_write_timeout(Some(WRITE_WAIT))
            .context("cannot set up the connection to the Pi")?;
        let name = ServerName::IpAddress(addr.ip().into());
        let mut conn =
            ClientConnection::new(config, name).context("cannot start the TLS handshake")?;
        while conn.is_handshaking() {
            let left = time_left(deadline).context("the TLS handshake with the Pi timed out")?;
            sock.set_read_timeout(Some(left))
                .context("cannot set up the connection to the Pi")?;
            conn.complete_io(&mut sock).map_err(|error| {
                if error.to_string().contains(NOT_PINNED) {
                    anyhow!(
                        "the Pi presented a certificate that is not the one in qberrypi-tls.pem, \
                         so nothing was sent to it; was the card made with another certificate?"
                    )
                } else {
                    Error::new(error).context("the TLS handshake with the Pi failed")
                }
            })?;
        }
        let host = match addr.ip() {
            IpAddr::V4(address) => address.to_string(),
            IpAddr::V6(address) => format!("[{address}]"),
        };
        Ok(Link { conn, sock, host })
    }

    /// Sends `request` and reads its reply, all within `reply_within` of this call: the writes of
    /// the head and the body, and the wait for the reply after them.
    ///
    /// If a write fails, the reply is still looked for (see the module's text); the error is the
    /// write's, with a note, only when there is none.
    pub fn request(&mut self, request: &Request<'_>, reply_within: Duration) -> Result<Response> {
        let deadline = Instant::now() + reply_within;
        let sent = self.send(request, deadline);
        if let Err(error) = sent {
            return match self.read_response(deadline) {
                Ok(response) => Ok(response),
                Err(_) => Err(Error::new(error).context(
                    "the connection to the Pi broke while the request was sent, and it said nothing; \
                     its log may say why",
                )),
            };
        }
        self.read_response(deadline)
            .context("cannot read the Pi's answer")
    }

    /// Writes the request's head and body, flushing as it goes.
    fn send(&mut self, request: &Request<'_>, deadline: Instant) -> io::Result<()> {
        let length: usize = request.body.iter().map(|piece| piece.len()).sum();
        // The head holds the session id, so it is wiped.
        let mut head = Zeroizing::new(format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: qberrypi-xtask\r\nAccept: application/json\r\n",
            request.method, request.path, self.host
        ));
        if let Some(sid) = request.sid {
            head.push_str("X-FTL-SID: ");
            head.push_str(sid);
            head.push_str("\r\n");
        }
        if let Some(kind) = request.content_type {
            head.push_str("Content-Type: ");
            head.push_str(kind);
            head.push_str("\r\n");
        }
        if length > 0 || request.method == "POST" {
            head.push_str(&format!("Content-Length: {length}\r\n"));
        }
        head.push_str("Connection: keep-alive\r\n\r\n");
        self.write_all(head.as_bytes(), deadline)?;
        for piece in request.body {
            self.write_all(piece, deadline)?;
        }
        Ok(())
    }

    /// Hands `bytes` to TLS and out to the socket, as fast as the socket takes them.
    fn write_all(&mut self, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
        while !bytes.is_empty() {
            time_left(deadline)?;
            let taken = self.conn.writer().write(bytes)?;
            bytes = &bytes[taken..];
            self.flush_tls()?;
            if taken == 0 && !self.conn.wants_write() {
                return Err(io::ErrorKind::WriteZero.into());
            }
        }
        Ok(())
    }

    /// Writes what TLS has ready to the socket.
    fn flush_tls(&mut self) -> io::Result<()> {
        while self.conn.wants_write() {
            match self.conn.write_tls(&mut self.sock) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Err(timed_out()),
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Reads up to `buf.len()` bytes of the reply's plaintext, waiting no later than `deadline`;
    /// `Ok(0)` is the Pi's close notice. Only reads from the socket: nothing queued is written
    /// first, so this works on a connection whose writes have failed.
    fn read_some(&mut self, buf: &mut [u8], deadline: Instant) -> io::Result<usize> {
        loop {
            match self.conn.reader().read(buf) {
                Ok(read) => return Ok(read),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
            let wait = time_left(deadline)?.min(READ_SLICE);
            self.sock.set_read_timeout(Some(wait))?;
            match self.conn.read_tls(&mut self.sock) {
                // The peer ended the TCP stream: what the reader says next is the close notice, or
                // that there was none.
                Ok(0) => {}
                Ok(_) => {
                    self.conn.process_new_packets().map_err(io::Error::other)?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    // One slice of the wait is over; the loop checks the deadline.
                    if Instant::now() >= deadline {
                        return Err(timed_out());
                    }
                }
                Err(error) => return Err(error),
            }
            // An alert or a key update may be waiting to go out; a connection that cannot send
            // it is no worse off for the reply that has come in, so the failure is not raised.
            let _ = self.flush_tls();
        }
    }

    /// Reads one reply: the head through its empty line, then as many body bytes as its
    /// `Content-Length` says.
    fn read_response(&mut self, deadline: Instant) -> io::Result<Response> {
        let mut head = Vec::new();
        let mut chunk = [0u8; 4096];
        let end = loop {
            if let Some(end) = head
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|at| at + 4)
            {
                break end;
            }
            if head.len() > MAX_REPLY_HEAD {
                return Err(bad_reply("the reply's head is too long"));
            }
            match self.read_some(&mut chunk, deadline)? {
                0 => return Err(io::ErrorKind::UnexpectedEof.into()),
                read => head.extend_from_slice(&chunk[..read]),
            }
        };
        let mut body = head.split_off(end);
        let text = std::str::from_utf8(&head[..end - 4])
            .map_err(|_| bad_reply("the reply's head is not text"))?;
        let (status, length) = parse_reply_head(text)?;
        while body.len() < length {
            let want = chunk.len().min(length - body.len());
            match self.read_some(&mut chunk[..want], deadline)? {
                0 => return Err(io::ErrorKind::UnexpectedEof.into()),
                read => body.extend_from_slice(&chunk[..read]),
            }
        }
        body.truncate(length);
        Ok(Response { status, body })
    }

    /// Ends the connection politely: the TLS close notice, if it can be sent without waiting.
    pub fn close(mut self) {
        self.conn.send_close_notify();
        let _ = self.flush_tls();
    }
}

/// An error for a reply that is not one this client takes.
fn bad_reply(why: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, why)
}

/// The status and the body length of a reply's head (without its closing empty line).
///
/// A reply with no `Content-Length` (a 204 apart), with a chunked body, or with a body over
/// [`MAX_REPLY_BODY`] is refused: the Pi's API sends none of them.
fn parse_reply_head(head: &str) -> io::Result<(u16, usize)> {
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.splitn(3, ' ');
    let status = match (parts.next(), parts.next().map(str::parse::<u16>)) {
        (Some(version), Some(Ok(status))) if version.starts_with("HTTP/1.") => status,
        _ => return Err(bad_reply("the reply has no status line")),
    };
    let mut length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(bad_reply("the reply has a header with no colon"));
        };
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(bad_reply(
                "the reply is chunked, which the Pi's API never is",
            ));
        }
        if name.eq_ignore_ascii_case("content-length") {
            length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| bad_reply("the reply's Content-Length is not a number"))?,
            );
        }
    }
    let length = match (length, status) {
        (Some(length), _) => length,
        (None, 204) => 0,
        (None, _) => return Err(bad_reply("the reply has no Content-Length")),
    };
    if length > MAX_REPLY_BODY {
        return Err(bad_reply("the reply is longer than a reply of the Pi is"));
    }
    Ok((status, length))
}

/// A login to the Pi's API: the open connection and the session it holds.
pub struct Session {
    link: Link,
    sid: Zeroizing<String>,
    addr: SocketAddr,
    config: Arc<ClientConfig>,
}

impl Session {
    /// Connects to `addr`, checks that it is the pinned certificate, and logs in with
    /// `password`, all within `wait`. One attempt: the Pi holds logins back after failed ones,
    /// so a wrong password is not tried again.
    ///
    /// The error says that the password was refused, that logins are held back, that the
    /// password could not be sent as a login (empty, not UTF-8, too long), or what else went
    /// wrong; none holds the password or the session id.
    pub fn login(
        addr: SocketAddr,
        config: Arc<ClientConfig>,
        password: &[u8],
        wait: Duration,
    ) -> Result<Session> {
        let body = hashpw::login_body(password)?;
        let began = Instant::now();
        let mut link = Link::open(addr, config.clone(), wait)?;
        let left = wait.saturating_sub(began.elapsed());
        let response = link.request(
            &Request {
                method: "POST",
                path: AUTH,
                sid: None,
                content_type: Some("application/json"),
                body: &[&body],
            },
            left.max(Duration::from_secs(1)),
        )?;
        match response.status {
            200 => {}
            401 => bail!("the Pi refused the password"),
            429 => bail!(
                "the Pi is holding logins back after failed ones: wait a minute and try again"
            ),
            _ => bail!("the Pi's login was refused ({})", response.refusal()),
        }
        let sid = response
            .json()
            .and_then(|json| Some(json.get("session")?.get("sid")?.as_str()?.to_owned()))
            .filter(|sid| {
                (1..=512).contains(&sid.len()) && sid.bytes().all(|b| b.is_ascii_graphic())
            })
            .map(Zeroizing::new)
            .ok_or_else(|| anyhow!("the Pi's login answer holds no session id"))?;
        Ok(Session {
            link,
            sid,
            addr,
            config,
        })
    }

    /// Sends the update, `body` in pieces with the manifest first, and reads the Pi's answer,
    /// which comes after it has written and checked the slot: `within` is for all of it.
    ///
    /// The answer is returned whatever its status; a refusal that came before the body was taken
    /// is read as the module's text says. The connection is the Pi's to close after it.
    pub fn upload(&mut self, body: &[&[u8]], within: Duration) -> Result<Response> {
        self.link.request(
            &Request {
                method: "POST",
                path: "/api/qbp/update",
                sid: Some(self.sid.as_str()),
                content_type: Some("application/octet-stream"),
                body,
            },
            within,
        )
    }

    /// Logs out, on a connection of its own (the update's ends with its answer), as well as that
    /// can be done within `wait`. Nothing is raised: an update that was refused is not made worse
    /// by a logout that did not go through, and the session ends by itself.
    pub fn logout(self, wait: Duration) {
        let Session {
            link,
            sid,
            addr,
            config,
        } = self;
        drop(link);
        let Ok(mut link) = Link::open(addr, config, wait) else {
            return;
        };
        let _ = link.request(
            &Request {
                method: "DELETE",
                path: AUTH,
                sid: Some(sid.as_str()),
                content_type: None,
                body: &[],
            },
            wait,
        );
        link.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{Ipv4Addr, TcpListener};

    use qberrypi::api::http::Reply;

    use crate::cert;
    use crate::standin::{PASSWORD, SID, TlsPi, drain, error_reply, json_reply};

    /// A key and certificate for a Pi at 192.0.2.53, as `tls.pem` holds them.
    fn pem() -> String {
        cert::make("qberrypi", Ipv4Addr::new(192, 0, 2, 53), 1_800_000_000).unwrap()
    }

    /// A Pi that takes whatever body an update has and says it is staged.
    fn taking(pem: &str) -> TlsPi {
        TlsPi::start(
            pem,
            Box::new(|head, stream| {
                assert!(drain(stream, head.length), "the whole body arrives");
                json_reply(200, r#"{"staged":true,"slot":"b","build":1}"#)
            }),
        )
    }

    /// A Pi that refuses an update at once, with the body unread.
    fn refusing(pem: &str) -> TlsPi {
        TlsPi::start(
            pem,
            Box::new(|_, _| error_reply(409, "update_busy", "busy")),
        )
    }

    /// A session on `pi`, logged in with the right password.
    fn logged_in(pem: &str, pi: &TlsPi) -> Session {
        Session::login(
            pi.addr,
            client_config(pem.as_bytes()).unwrap(),
            PASSWORD,
            WAIT,
        )
        .unwrap()
    }

    const WAIT: Duration = Duration::from_secs(10);

    #[test]
    fn the_client_logs_in_to_the_pinned_certificate_and_holds_the_session() {
        let pem = pem();
        let pi = taking(&pem);

        let session = logged_in(&pem, &pi);

        assert_eq!(session.sid.as_str(), SID);
        assert_eq!(pi.seen(), ["POST auth"]);
    }

    #[test]
    fn a_server_with_another_certificate_gets_no_password_and_the_error_says_why() {
        let (pinned, other) = (pem(), pem());
        let pi = taking(&other);

        let error = Session::login(
            pi.addr,
            client_config(pinned.as_bytes()).unwrap(),
            b"secret-never-sent",
            WAIT,
        )
        .err()
        .expect("a server that is not the pinned one is refused");

        let said = format!("{error:#}");
        assert!(said.contains("not the one in qberrypi-tls.pem"), "{said}");
        assert!(said.contains("nothing was sent"), "{said}");
        assert!(!said.contains("secret-never-sent"), "{said}");
        // The handshake never finished, so no request reached the server.
        assert!(pi.seen().is_empty(), "{:?}", pi.seen());
    }

    #[test]
    fn a_wrong_password_is_one_attempt_and_the_error_holds_none_of_it() {
        let pem = pem();
        let pi = taking(&pem);

        let error = Session::login(
            pi.addr,
            client_config(pem.as_bytes()).unwrap(),
            b"not-the-password",
            WAIT,
        )
        .err()
        .expect("a wrong password is refused");

        assert_eq!(error.to_string(), "the Pi refused the password");
        assert_eq!(pi.seen(), ["POST auth"]);
    }

    #[test]
    fn a_password_that_cannot_be_a_login_is_refused_before_anything_is_sent() {
        let pem = pem();
        let pi = taking(&pem);

        let error = Session::login(pi.addr, client_config(pem.as_bytes()).unwrap(), b"", WAIT)
            .err()
            .expect("an empty password is no login");

        assert_eq!(error.to_string(), "the password is empty");
        assert_eq!(pi.connections(), 0);
    }

    #[test]
    fn an_update_is_sent_with_the_session_and_a_length_that_adds_up_and_the_answer_is_read() {
        let pem = pem();
        let pi = taking(&pem);
        let mut session = logged_in(&pem, &pi);
        let body = [&b"manifest"[..], &vec![7u8; 300_000][..], b"tail"];

        let answer = session.upload(&body, WAIT).unwrap();

        assert_eq!(answer.status, 200);
        assert_eq!(answer.json().unwrap()["staged"], true);
        assert_eq!(
            pi.seen()[1],
            format!("POST update sid={SID} len={}", 8 + 300_000 + 4)
        );
    }

    #[test]
    fn a_refusal_that_comes_before_the_body_is_taken_is_read_though_the_writes_fail() {
        let pem = pem();
        let pi = refusing(&pem);
        let mut session = logged_in(&pem, &pi);
        // More than the sockets of a loopback connection hold, so a write must fail when the
        // server closes with the body unread.
        let big = vec![1u8; 48 * 1024 * 1024];

        let answer = session.upload(&[&big], WAIT).unwrap();

        assert_eq!(answer.status, 409);
        assert_eq!(answer.json().unwrap()["error"]["key"], "update_busy");
        assert_eq!(answer.refusal(), "update_busy: busy");
    }

    #[test]
    fn a_connection_that_breaks_with_no_answer_is_an_error_that_says_so() {
        let pem = pem();
        // The server drops the connection with the body unread, and has no answer to give.
        let pi = TlsPi::start(
            &pem,
            Box::new(|_, stream| {
                let _ = stream.get_mut().sock.shutdown(std::net::Shutdown::Both);
                error_reply(409, "update_busy", "never delivered")
            }),
        );
        let mut session = logged_in(&pem, &pi);
        let big = vec![1u8; 48 * 1024 * 1024];

        let error = session
            .upload(&[&big], WAIT)
            .expect_err("no answer is an error");

        let said = format!("{error:#}");
        assert!(said.contains("broke while the request was sent"), "{said}");
        assert!(!said.contains("never delivered"), "{said}");
    }

    #[test]
    fn an_answer_with_no_body_is_returned_with_its_status() {
        let pem = pem();
        let pi = TlsPi::start(
            &pem,
            Box::new(|_, _| Reply {
                status: 204,
                body: Vec::new(),
            }),
        );
        let mut session = logged_in(&pem, &pi);

        let answer = session.upload(&[b"x"], WAIT).unwrap();

        assert_eq!((answer.status, answer.body.len()), (204, 0));
        assert!(answer.json().is_none());
    }

    #[test]
    fn a_logout_goes_on_a_connection_of_its_own_with_the_session() {
        let pem = pem();
        let pi = refusing(&pem);
        let mut session = logged_in(&pem, &pi);
        session.upload(&[b"x"], WAIT).unwrap();

        session.logout(WAIT);

        assert_eq!(pi.seen().last().unwrap(), &format!("DELETE auth sid={SID}"));
        assert_eq!(pi.connections(), 2);
    }

    #[test]
    fn a_server_that_says_nothing_is_an_error_after_the_wait_and_not_before() {
        // The kernel accepts the connection and nobody ever answers the handshake.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            listener.local_addr().unwrap().port(),
        );
        let pem = pem();
        let began = Instant::now();

        let error = Link::open(
            addr,
            client_config(pem.as_bytes()).unwrap(),
            Duration::from_millis(300),
        )
        .err()
        .expect("a handshake that nobody answers fails");

        assert!(
            began.elapsed() >= Duration::from_millis(250),
            "{:?}",
            began.elapsed()
        );
        assert!(format!("{error:#}").contains("handshake"), "{error:#}");
        drop(listener);
    }

    #[test]
    fn a_pem_with_no_certificate_cannot_be_pinned_and_the_error_quotes_none_of_it() {
        let error =
            client_config(b"-----BEGIN PRIVATE KEY-----\nc2VjcmV0\n-----END PRIVATE KEY-----\n")
                .err()
                .unwrap();
        assert!(error.to_string().contains("no certificate"), "{error}");
        assert!(!format!("{error:#}").contains("c2VjcmV0"), "{error:#}");
        assert!(client_config(b"").is_err());
    }

    #[test]
    fn a_reply_head_is_read_by_its_length_and_what_the_api_never_sends_is_refused() {
        let head = |text: &str| parse_reply_head(text).map_err(|e| e.to_string());
        assert_eq!(
            head("HTTP/1.1 200 OK\r\nContent-Length: 12\r\nX: y"),
            Ok((200, 12))
        );
        assert_eq!(
            head("HTTP/1.1 204 No Content\r\nconnection: close"),
            Ok((204, 0))
        );
        assert_eq!(
            head("HTTP/1.1 409 Conflict\r\ncontent-length: 0"),
            Ok((409, 0))
        );
        for refused in [
            "HTTP/1.1 200 OK",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked",
            "HTTP/1.1 200 OK\r\nContent-Length: twelve",
            "HTTP/1.1 200 OK\r\nContent-Length: 65537",
            "HTTP/1.1 200 OK\r\nno colon here",
            "garbage",
            "HTTP/1.1 abc OK\r\nContent-Length: 1",
        ] {
            assert!(head(refused).is_err(), "{refused:?}");
        }
    }

    #[test]
    fn the_pis_words_are_shown_without_control_characters_and_the_status_when_it_said_none() {
        let refused = |body: &str, status| Response {
            status,
            body: body.as_bytes().to_vec(),
        };
        assert_eq!(
            refused(
                r#"{"error":{"key":"not_newer","message":"too old\u001b[31m"}}"#,
                409
            )
            .refusal(),
            "not_newer: too old[31m"
        );
        assert_eq!(refused("<html>", 502).refusal(), "HTTP status 502");
        assert_eq!(refused(r#"{"error":{"key":"x"}}"#, 400).refusal(), "x");
        assert_eq!(printable(&"x".repeat(500)).len(), 200);
    }
}
