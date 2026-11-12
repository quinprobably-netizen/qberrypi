//! Test only: a certificate made for one test, the client that qnet is (a `ring` client that
//! trusts one certificate by its SHA-256 and by nothing else), and HTTP over it.
//!
//! The clients here block, and run on a thread of their own or on the pool: a test that serves on
//! the runtime and asks from the same thread would wait for itself.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error, SignatureScheme, StreamOwned,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// A key and certificate for `example.com`, as `tls.pem` holds them: the PKCS#8 key and then the
/// certificate, as PEM, made for the one test.
pub(crate) fn pem() -> String {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = CertificateParams::new(vec!["example.com".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    format!("{}{}", key.serialize_pem(), cert.pem())
}

/// The first certificate in `pem`.
pub(crate) fn certificate(pem: &str) -> CertificateDer<'static> {
    CertificateDer::from_pem_slice(pem.as_bytes()).unwrap()
}

/// Accepts a server's certificate if its SHA-256 is the pin, as qnet's does, whatever the names
/// and dates in it say, and checks the handshake's signatures with `ring`.
#[derive(Debug)]
struct Pin {
    sha256: [u8; 32],
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
    ) -> Result<ServerCertVerified, Error> {
        if Sha256::digest(end_entity).as_slice() == self.sha256 {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::General("not the pinned certificate".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// A client on the `ring` provider, with its default suites (AES-GCM first) and versions, that
/// trusts the certificate `cert` by its pin and nothing else.
pub(crate) fn pinned_client(cert: &CertificateDer<'_>) -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let pin = Pin {
        sha256: Sha256::digest(cert).into(),
        algorithms: provider.signature_verification_algorithms,
    };
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(pin))
        .with_no_client_auth();
    Arc::new(config)
}

/// One reply, as a client sees it.
#[derive(Debug)]
pub(crate) struct Answer {
    pub status: u16,
    /// Whether the reply says `Connection: close`.
    pub close: bool,
    /// The body as JSON; `Null` for none.
    pub json: Value,
}

/// How long a client waits for the server before it takes the server to be stuck.
///
/// Generous on purpose: a test that sends an update waits for a server that writes eleven files to a
/// disk and syncs each one, and on a loaded machine one sync takes seconds, so a reply can be late
/// by far more than a stuck server would be. A server that is stuck is a test that fails a minute
/// late, which costs nothing; a client that gives up early is a flake.
const CLIENT_WAIT: Duration = Duration::from_secs(60);

/// One TLS connection to the API, and the requests and replies on it.
pub(crate) struct Connection {
    stream: BufReader<StreamOwned<ClientConnection, TcpStream>>,
}

impl Connection {
    /// Connects, and runs the handshake; the error is the handshake's if it fails.
    pub fn open(addr: SocketAddr, config: Arc<ClientConfig>) -> io::Result<Self> {
        let socket = TcpStream::connect(addr)?;
        socket.set_read_timeout(Some(CLIENT_WAIT))?;
        socket.set_write_timeout(Some(CLIENT_WAIT))?;
        let name = ServerName::try_from("example.com").unwrap();
        let mut conn = ClientConnection::new(config, name).map_err(io::Error::other)?;
        let mut socket = socket;
        while conn.is_handshaking() {
            conn.complete_io(&mut socket)?;
        }
        Ok(Self {
            stream: BufReader::new(StreamOwned::new(conn, socket)),
        })
    }

    /// Sends the bytes as they are.
    pub fn send_raw(&mut self, bytes: &[u8]) -> io::Result<()> {
        let tls = self.stream.get_mut();
        tls.write_all(bytes)?;
        tls.flush()
    }

    /// Sends the request `spec` says, as qnet writes one: `METHOD /path`, then, each after a
    /// `|`, `sid=<sid>` and a body, both optional.
    pub fn send(&mut self, spec: &str) -> io::Result<()> {
        self.send_raw(request_text(spec).as_bytes())
    }

    /// Reads one reply; `UnexpectedEof` when the server has closed the connection, with a close
    /// notice or without, and `TimedOut` when it said nothing for `CLIENT_WAIT`.
    pub fn receive(&mut self) -> io::Result<Answer> {
        read_reply(&mut self.stream)
    }

    /// Sends `pieces`, one after the other, as the rest of a request, and reads the reply.
    ///
    /// A server that refuses a request from its head answers and closes with the body unread, and
    /// the client's writes then fail partway (a reset, or a broken pipe) while its connection
    /// still holds the reply, which arrived first. So a write that fails ends the sending and is
    /// no failure of the test: the reply is read all the same, by [`Connection::receive_unflushed`],
    /// which does not try to write what the failed write left queued. Only a reply that is not
    /// there is an error, and it names the write that failed as well.
    pub fn send_pieces_and_receive<'a>(
        &mut self,
        pieces: impl IntoIterator<Item = &'a [u8]>,
    ) -> io::Result<Answer> {
        for piece in pieces {
            if let Err(written) = self.send_raw(piece) {
                return self.receive_unflushed().map_err(|read| {
                    io::Error::new(
                        read.kind(),
                        format!("{read}, after a write failed with {written}"),
                    )
                });
            }
        }
        self.receive()
    }

    /// Reads one reply from what the server sent, and never writes: unlike a read of the TLS
    /// stream, it does not first try to flush what an earlier write left queued, which fails when
    /// the server has closed and hides the reply that is there to read.
    ///
    /// Nothing may have been read from this connection before.
    pub fn receive_unflushed(&mut self) -> io::Result<Answer> {
        assert!(
            self.stream.buffer().is_empty(),
            "a reply is half read already"
        );
        let tls = self.stream.get_mut();
        let mut reader = BufReader::new(Unflushed {
            conn: &mut tls.conn,
            sock: &mut tls.sock,
        });
        read_reply(&mut reader)
    }

    /// How long it takes the server to close the connection, if it does within `within`: what the
    /// next read finds is end of stream, a close notice or a reset, and `None` is for a server
    /// that has not closed by then.
    pub fn closed_within(&mut self, within: Duration) -> Option<Duration> {
        let began = Instant::now();
        let _ = self.stream.get_ref().sock.set_read_timeout(Some(within));
        let mut byte = [0u8; 1];
        match self.stream.read(&mut byte) {
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                None
            }
            // Nothing is sent that is not a reply: a byte would be a reply that was not read.
            _ => Some(began.elapsed()),
        }
    }
}

/// The plaintext that arrives on a client's TLS connection, read from the socket and decrypted
/// and never more: `read` does not write, whatever the connection has queued to send.
struct Unflushed<'a> {
    conn: &'a mut ClientConnection,
    sock: &'a mut TcpStream,
}

impl Read for Unflushed<'_> {
    /// Decrypted bytes if any are there; else reads more of the socket. End of stream is `Ok(0)`
    /// after a close notice and `UnexpectedEof` without one; a reset that comes when no plaintext
    /// is left is its own error, and `TimedOut` is a socket that said nothing for `CLIENT_WAIT`.
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut ended = false;
        loop {
            match self.conn.reader().read(out) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if ended {
                        return Err(io::ErrorKind::UnexpectedEof.into());
                    }
                }
                done => return done,
            }
            ended = self.conn.read_tls(self.sock).map_err(timed_out)? == 0;
            self.conn.process_new_packets().map_err(io::Error::other)?;
        }
    }
}

/// Reads one reply from `reader`: the head to its blank line, then the body that
/// `Content-Length` says.
fn read_reply(reader: &mut impl BufRead) -> io::Result<Answer> {
    let mut head = Vec::new();
    loop {
        let mut line = Vec::new();
        let got = reader.read_until(b'\n', &mut line).map_err(timed_out)?;
        if got == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        if line == b"\r\n" {
            break;
        }
        head.extend_from_slice(&line);
    }
    let head = String::from_utf8(head).unwrap();
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|status| status.parse().ok())
        .expect("a status line");
    let header = |name: &str| {
        lines.clone().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
    };
    let length: usize = header("content-length").map_or(0, |n| n.parse().unwrap());
    let close = header("connection").is_some_and(|value| value.eq_ignore_ascii_case("close"));
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).map_err(timed_out)?;
    let json = serde_json::from_slice(&body).unwrap_or(Value::Null);
    Ok(Answer {
        status,
        close,
        json,
    })
}

/// A read that the socket's timeout cut short says so.
fn timed_out(error: io::Error) -> io::Error {
    if error.kind() == io::ErrorKind::WouldBlock {
        io::ErrorKind::TimedOut.into()
    } else {
        error
    }
}

/// The text of the request that `Connection::send` takes.
fn request_text(spec: &str) -> String {
    let mut parts = spec.splitn(3, '|');
    let line = parts.next().unwrap();
    let (mut sid, mut body) = (None, None);
    for part in parts {
        match part.strip_prefix("sid=") {
            Some(value) => sid = Some(value),
            None => body = Some(part),
        }
    }
    let mut text = format!(
        "{line} HTTP/1.1\r\nHost: 192.0.2.53\r\nUser-Agent: qnet\r\nAccept: application/json\r\n"
    );
    if let Some(sid) = sid {
        text.push_str(&format!("X-FTL-SID: {sid}\r\n"));
    }
    if let Some(body) = body {
        text.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    text.push_str("Connection: keep-alive\r\n\r\n");
    text.push_str(body.unwrap_or(""));
    text
}

/// Sends `requests` one after the other on one connection to `addr` and reads each reply, on a
/// thread of the blocking pool. A request is as `Connection::send` takes it.
pub(crate) async fn https(
    addr: SocketAddr,
    client: Arc<ClientConfig>,
    requests: &[&str],
) -> Vec<(u16, Value)> {
    let requests: Vec<String> = requests.iter().map(|&request| request.to_owned()).collect();
    tokio::task::spawn_blocking(move || {
        let mut connection = Connection::open(addr, client).unwrap();
        requests
            .iter()
            .map(|request| {
                connection.send(request).unwrap();
                let answer = connection.receive().unwrap();
                (answer.status, answer.json)
            })
            .collect()
    })
    .await
    .unwrap()
}
