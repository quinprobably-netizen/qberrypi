//! Test only: stand-ins for the two servers of a Pi, on the loopback, for the tests of the update
//! client. No test of `xtask` contacts anything else.
//!
//! [`TlsPi`] is the API on port 443 as far as the client uses it: TLS with a certificate of the
//! test's own, `POST /api/auth` (the login, one password), `DELETE /api/auth` (the logout) and
//! `POST /api/qbp/update`, whose answer is the test's: a closure that gets the head and the
//! stream, so that it may read the body, or not. As the Pi's own connection does, it serves the
//! update as the last request of its connection and closes after it.
//!
//! [`StatusPi`] is the status server on port 80: each `GET` is answered with the next step of a
//! script, a JSON object or a connection that is closed with no answer (a Pi that is down), and
//! the last step stands for every later `GET`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use qberrypi::api::http::{Head, Reply, read_request_body, read_request_head, write_reply};
use qberrypi::api::tls::server_config;
use rustls::{ServerConnection, StreamOwned};
use serde_json::Value;

/// The password that [`TlsPi`] accepts.
pub(crate) const PASSWORD: &[u8] = b"example password";

/// The session id that [`TlsPi`] issues.
pub(crate) const SID: &str = "0123456789abcdefABCDEF==";

/// How long a stand-in waits for its client before it gives up on a connection.
const PATIENCE: Duration = Duration::from_secs(20);

/// How often a stand-in's accept loop looks at whether it is to stop.
const TICK: Duration = Duration::from_millis(2);

/// The stream of one connection to [`TlsPi`], with the request line and headers read.
pub(crate) type Stream = BufReader<StreamOwned<ServerConnection, TcpStream>>;

/// What [`TlsPi`] does with `POST /api/qbp/update`: reads what it wants of the body from the
/// stream and says what to answer; the connection closes after the answer.
pub(crate) type UpdateHandler = Box<dyn Fn(&Head, &mut Stream) -> Reply + Send + Sync>;

/// A reply with a JSON body.
pub(crate) fn json_reply(status: u16, body: &str) -> Reply {
    Reply {
        status,
        body: body.as_bytes().to_vec(),
    }
}

/// An error in Pi-hole's shape.
pub(crate) fn error_reply(status: u16, key: &str, message: &str) -> Reply {
    json_reply(
        status,
        &serde_json::json!({ "error": { "key": key, "message": message, "hint": null } })
            .to_string(),
    )
}

/// The address of `listener` as a client on the same computer reaches it.
fn loopback(listener: &TcpListener) -> SocketAddr {
    SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        listener.local_addr().map_or(0, |addr| addr.port()),
    )
}

/// A thread that accepts connections on `listener` one at a time until told to stop.
struct Acceptor {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Acceptor {
    fn start(listener: TcpListener, mut serve: impl FnMut(TcpStream) + Send + 'static) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let stop = stop.clone();
            thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((socket, _)) => {
                            if socket.set_nonblocking(false).is_ok() {
                                serve(socket);
                            }
                        }
                        Err(_) => thread::sleep(TICK),
                    }
                }
            })
        };
        Self {
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Acceptor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The Pi's API, over TLS with the certificate in `pem`.
pub(crate) struct TlsPi {
    /// Where to connect.
    pub addr: SocketAddr,
    seen: Arc<Mutex<Vec<String>>>,
    connections: Arc<AtomicUsize>,
    _acceptor: Acceptor,
}

impl TlsPi {
    /// Starts serving; `update` answers `POST /api/qbp/update` (the session is checked first: a
    /// request without [`SID`] is a 401 and the handler is not called).
    pub(crate) fn start(pem: &str, update: UpdateHandler) -> TlsPi {
        let config = server_config(pem.as_bytes()).expect("the test certificate serves");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a loopback port");
        listener
            .set_nonblocking(true)
            .expect("a non-blocking listener");
        let addr = loopback(&listener);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let acceptor = {
            let (seen, connections) = (seen.clone(), connections.clone());
            Acceptor::start(listener, move |socket| {
                connections.fetch_add(1, Ordering::SeqCst);
                let _ = socket.set_read_timeout(Some(PATIENCE));
                let Ok(conn) = ServerConnection::new(config.clone()) else {
                    return;
                };
                serve(
                    BufReader::new(StreamOwned::new(conn, socket)),
                    &update,
                    &seen,
                );
            })
        };
        TlsPi {
            addr,
            seen,
            connections,
            _acceptor: acceptor,
        }
    }

    /// What the server has seen so far, one line per request that reached a handler:
    /// `POST auth`, `DELETE auth sid=<sid>`, `POST update sid=<sid> len=<n>`.
    pub(crate) fn seen(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// How many connections were accepted, handshake or not.
    pub(crate) fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

/// Serves one connection: requests until the client is done, or the update's turn has come.
fn serve(mut stream: Stream, update: &UpdateHandler, seen: &Mutex<Vec<String>>) {
    let note = |text: String| {
        seen.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(text);
    };
    loop {
        let Ok(head) = read_request_head(&mut stream) else {
            return;
        };
        if head.method == "POST" && head.target == "/api/qbp/update" {
            note(format!(
                "POST update sid={} len={}",
                head.sid.clone().unwrap_or_default(),
                head.length
            ));
            let reply = if head.sid.as_deref() == Some(SID) {
                update(&head, &mut stream)
            } else {
                error_reply(401, "unauthorized", "Unauthorized")
            };
            let _ = write_reply(stream.get_mut(), &reply, true);
            return;
        }
        let Ok(request) = read_request_body(&mut stream, head) else {
            return;
        };
        let reply = match (request.method.as_str(), request.target.as_str()) {
            ("POST", "/api/auth") => {
                note("POST auth".to_owned());
                let right = serde_json::from_slice::<Value>(&request.body)
                    .ok()
                    .and_then(|json| json.get("password")?.as_str().map(str::to_owned))
                    .is_some_and(|password| password.as_bytes() == PASSWORD);
                if right {
                    json_reply(
                        200,
                        &format!(r#"{{"session":{{"valid":true,"sid":"{SID}","validity":1800}}}}"#),
                    )
                } else {
                    json_reply(401, r#"{"session":{"valid":false,"sid":null}}"#)
                }
            }
            ("DELETE", "/api/auth") => {
                note(format!(
                    "DELETE auth sid={}",
                    request.sid.clone().unwrap_or_default()
                ));
                Reply {
                    status: 204,
                    body: Vec::new(),
                }
            }
            _ => error_reply(404, "not_found", "Not found"),
        };
        if write_reply(stream.get_mut(), &reply, request.close).is_err() || request.close {
            return;
        }
    }
}

/// Reads and drops `length` bytes of a request's body from `stream`, as a server that takes an
/// upload does; `false` if the stream ends first.
pub(crate) fn drain(stream: &mut Stream, length: u64) -> bool {
    let mut left = length;
    let mut sink = vec![0u8; 64 * 1024];
    while left > 0 {
        let want = sink.len().min(usize::try_from(left).unwrap_or(usize::MAX));
        match stream.read(&mut sink[..want]) {
            Ok(0) | Err(_) => return false,
            Ok(got) => left -= got as u64,
        }
    }
    true
}

/// One step of a [`StatusPi`]'s script.
#[derive(Clone, Debug)]
pub(crate) enum Step {
    /// An answer: this JSON object, as `GET /api/v1/stats` gives it.
    Stats(Value),
    /// No answer: the connection is closed as soon as the request is in.
    Down,
}

/// The status server, answering from a script.
pub(crate) struct StatusPi {
    /// Where to connect.
    pub addr: SocketAddr,
    reads: Arc<AtomicUsize>,
    _acceptor: Acceptor,
}

impl StatusPi {
    /// Starts serving `script`, whose steps are used one per request, the last for all the rest.
    ///
    /// Panics if `script` is empty: a stand-in with nothing to say is a mistake of the test.
    pub(crate) fn start(script: Vec<Step>) -> StatusPi {
        assert!(!script.is_empty(), "a script has at least one step");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a loopback port");
        listener
            .set_nonblocking(true)
            .expect("a non-blocking listener");
        let addr = loopback(&listener);
        let reads = Arc::new(AtomicUsize::new(0));
        let acceptor = {
            let reads = reads.clone();
            Acceptor::start(listener, move |socket| {
                let _ = socket.set_read_timeout(Some(PATIENCE));
                let index = reads.fetch_add(1, Ordering::SeqCst).min(script.len() - 1);
                answer(socket, &script[index]);
            })
        };
        StatusPi {
            addr,
            reads,
            _acceptor: acceptor,
        }
    }

    /// How many requests have been made.
    pub(crate) fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }
}

/// Reads the request that `socket` carries and answers it as `step` says.
fn answer(socket: TcpStream, step: &Step) {
    let mut reader = BufReader::new(socket);
    let mut line = String::new();
    // The request's head ends at the empty line; a client that never finishes it is let go by the
    // read timeout.
    while reader.read_line(&mut line).is_ok_and(|read| read > 0) {
        if line == "\r\n" {
            break;
        }
        line.clear();
    }
    let Step::Stats(json) = step else {
        return;
    };
    let body = json.to_string();
    let _ = write!(
        reader.get_mut(),
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}
