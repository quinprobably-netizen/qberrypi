//! An asynchronous netlink socket: requests with their replies, and datagrams
//! as the kernel sends them.
//!
//! A request is one datagram out, and the reply is one or more datagrams in.
//! Nothing here waits on the runtime's thread: a wait is a socket readiness
//! wait, a tokio timer or a oneshot channel.
//!
//! A socket is opened in one of two modes. An *inline* socket sends its
//! requests with `send(2)` on the thread that polls it, which is fine for a
//! kernel that answers inside the call at once. An *offloaded* socket hands
//! each request's bytes to a thread of its own, named `nl send`, that does
//! nothing but send them, in order, and wipe them: a driver that runs a
//! command's handler inside `send(2)`, as brcmfmac does (about 2.5 s for a
//! firmware command that is not answered), then holds that thread and not the
//! runtime's. The reply is read on the runtime in both modes, through the
//! socket's `AsyncFd`: by the time the send has returned the kernel has queued
//! it, and a read is a copy. The thread ends when the socket is dropped. It is made by
//! [`cpu::spawn_off_runtime_core`], so that on a pinned runtime it does not share the DNS
//! service's core.

use std::fmt;
use std::io::{self, ErrorKind};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, poll};
use rustix::io::Errno;
use rustix::net::{RecvFlags, SendFlags};
use rustix::time::Timespec;
use tokio::io::unix::AsyncFd;
use tokio::sync::oneshot;
use zeroize::{Zeroize, Zeroizing};

use super::{Message, MsgBuilder, NLM_F_ACK, NLM_F_DUMP, NLMSG_DONE, NlError, ack, messages};
use crate::cpu;
use crate::sys::{self, NetlinkProtocol};

/// How long a request waits for the end of its reply, and, on an offloaded
/// socket, for its send to be done: such a request waits at most twice this.
pub const REPLY_TIMEOUT: Duration = Duration::from_secs(5);

/// Room for one datagram. The kernel fills a dump's datagrams up to what the
/// reader says it has, and never more than this.
const RECV_BUFFER: usize = 32_768;

/// Why a request did not get an answer.
#[derive(Debug)]
pub enum RequestError {
    /// The socket failed.
    Io(io::Error),
    /// The kernel refused the request.
    Kernel(NlError),
    /// The reply did not end in time, or the send of an offloaded request did not return in time.
    Timeout,
    /// The reply was not what the request should get.
    Malformed,
}

impl RequestError {
    /// The error number the kernel gave, if it was the kernel that refused.
    pub fn errno(&self) -> Option<i32> {
        match self {
            Self::Kernel(error) => Some(error.errno),
            _ => None,
        }
    }
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "netlink socket: {error}"),
            Self::Kernel(error) => write!(f, "refused by the kernel: {error}"),
            Self::Timeout => write!(
                f,
                "no answer from the kernel within {} s",
                REPLY_TIMEOUT.as_secs()
            ),
            Self::Malformed => f.write_str("the kernel's answer was not what was asked for"),
        }
    }
}

impl std::error::Error for RequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Kernel(error) => Some(error),
            Self::Timeout | Self::Malformed => None,
        }
    }
}

impl From<io::Error> for RequestError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// What sends one datagram to the kernel on an offloaded socket's thread: given the socket and the bytes.
///
/// It is a seam for the tests, which make a send slow or stuck.
type SendFn = Box<dyn FnMut(BorrowedFd<'_>, &[u8]) -> io::Result<()> + Send>;

/// One offloaded request on its way to the send thread.
struct Job {
    /// The request, wiped by whoever ends up holding it.
    bytes: Zeroizing<Vec<u8>>,
    /// Where the thread says how the send went.
    done: oneshot::Sender<io::Result<()>>,
}

/// A netlink socket, and the sequence number its next request gets.
pub struct NlSocket {
    fd: AsyncFd<OwnedFd>,
    seq: u32,
    /// The queue of the socket's send thread; `None` for an inline socket, which has no thread.
    offload: Option<mpsc::Sender<Job>>,
}

impl NlSocket {
    /// Opens a socket for `protocol`.
    ///
    /// # Panics
    ///
    /// Outside a tokio runtime.
    pub fn open(protocol: NetlinkProtocol) -> io::Result<Self> {
        Ok(Self {
            fd: sys::async_fd(sys::netlink_socket(protocol)?)?,
            seq: 0,
            offload: None,
        })
    }

    /// Opens a socket for `protocol` whose requests are sent by a thread of its own.
    ///
    /// For a kernel whose answer to a request can take seconds inside `send(2)`: the runtime's thread
    /// then never waits for it. The thread is named `nl send` and ends when the socket is dropped,
    /// once a send it is in has returned. It is given a duplicate of the descriptor, which is the
    /// same socket: that needs no sharing of one `OwnedFd`, and a send in progress still has a
    /// socket to go to after the socket here is dropped.
    ///
    /// # Panics
    ///
    /// Outside a tokio runtime.
    pub fn open_offloaded(protocol: NetlinkProtocol) -> io::Result<Self> {
        Self::open_offloaded_with(protocol, Box::new(send_blocking))
    }

    /// `open_offloaded` with the function that sends given, so that a test can make a send slow or stuck.
    pub(super) fn open_offloaded_with(protocol: NetlinkProtocol, send: SendFn) -> io::Result<Self> {
        let fd = sys::async_fd(sys::netlink_socket(protocol)?)?;
        let for_thread = fd.get_ref().try_clone()?;
        let (jobs, queue) = mpsc::channel();
        // A thread that cannot be made is the error of the open: no request is lost to it later.
        // It is made from the runtime's thread, so it leaves that thread's core as it starts.
        cpu::spawn_off_runtime_core("nl send", move || serve(&for_thread, &queue, send))?;
        #[cfg(test)]
        OFFLOADED_OPENS.with(|opens| opens.set(opens.get() + 1));
        Ok(Self {
            fd,
            seq: 0,
            offload: Some(jobs),
        })
    }

    /// Whether the requests of this socket are sent by a thread of its own.
    #[cfg(test)]
    pub(crate) fn is_offloaded(&self) -> bool {
        self.offload.is_some()
    }

    /// Has the socket receive what the kernel sends to a multicast group.
    pub fn join_group(&self, group: u32) -> io::Result<()> {
        sys::netlink_join_group(self.fd.get_ref().as_fd(), group)
    }

    /// Sends a request and returns the payloads of its reply, in order.
    ///
    /// The reply ends at the acknowledgement or, for a dump, at `NLMSG_DONE`;
    /// an error acknowledgement ends either kind. Messages that carry another
    /// request's sequence number are skipped. The request's bytes are wiped
    /// as soon as they are sent, whether or not that worked, and also if the
    /// future is dropped first.
    ///
    /// On an offloaded socket the send is the thread's and is waited for at
    /// most [`REPLY_TIMEOUT`], after which the request is a
    /// [`RequestError::Timeout`]; the reply then has the same time again. Dropping
    /// the future while a send is still queued behind a slow one cancels it: a
    /// request nobody waits for is not sent.
    ///
    /// # Panics
    ///
    /// In a debug build, if the request neither asks for an acknowledgement
    /// nor is a dump: the kernel then sends no end marker.
    pub async fn request(&mut self, message: MsgBuilder) -> Result<Vec<Vec<u8>>, RequestError> {
        let flags = message.flags();
        let dump = flags & NLM_F_DUMP == NLM_F_DUMP;
        debug_assert!(
            dump || flags & NLM_F_ACK != 0,
            "a request needs NLM_F_ACK or NLM_F_DUMP, or its reply has no end"
        );
        // Sequence 0 is what the kernel puts on its own notifications.
        self.seq = self.seq.wrapping_add(1).max(1);
        let seq = self.seq;
        // Wiped once sent, and on drop if this future is dropped first.
        let mut bytes = Zeroizing::new(message.finish(seq));
        match &self.offload {
            Some(jobs) => send_offloaded(jobs, bytes).await?,
            None => {
                let sent = self.send(&bytes).await;
                bytes.zeroize();
                sent?;
            }
        }
        self.reply(seq, dump).await
    }

    /// Reads one datagram, as the kernel sent it.
    ///
    /// Dropping the future loses nothing: a datagram is taken from the socket
    /// only by the call that returns it.
    pub async fn recv(&mut self) -> io::Result<Vec<u8>> {
        let mut datagram = vec![0; RECV_BUFFER];
        loop {
            let mut ready = self.fd.readable().await?;
            let read = ready.try_io(|fd| {
                rustix::net::recv(fd, &mut datagram[..], RecvFlags::empty())
                    .map(|(_, len)| len)
                    .map_err(io::Error::from)
            });
            if let Ok(read) = read {
                datagram.truncate(read?);
                datagram.shrink_to_fit();
                return Ok(datagram);
            }
        }
    }

    /// Sends one datagram to the kernel.
    async fn send(&self, datagram: &[u8]) -> io::Result<()> {
        loop {
            let mut ready = self.fd.writable().await?;
            let sent = ready.try_io(|fd| {
                rustix::net::send(fd, datagram, SendFlags::empty()).map_err(io::Error::from)
            });
            if let Ok(sent) = sent {
                // A datagram goes whole or not at all.
                return sent.map(drop);
            }
        }
    }

    /// Reads datagrams until the reply to request `seq` has ended.
    async fn reply(&mut self, seq: u32, dump: bool) -> Result<Vec<Vec<u8>>, RequestError> {
        let gather = async {
            let mut reply = Reply::new(seq, dump);
            loop {
                let datagram = self.recv().await?;
                if let Some(end) = reply.take(&datagram) {
                    return end;
                }
            }
        };
        tokio::time::timeout(REPLY_TIMEOUT, gather)
            .await
            .unwrap_or(Err(RequestError::Timeout))
    }
}

/// Hands `bytes` to the send thread behind `jobs` and waits, for [`REPLY_TIMEOUT`] at most, for it to say
/// how the send went.
///
/// The bytes are the thread's from here on, and are wiped there. A queue that nobody reads any more
/// (the thread has ended) is an I/O error.
async fn send_offloaded(
    jobs: &mpsc::Sender<Job>,
    bytes: Zeroizing<Vec<u8>>,
) -> Result<(), RequestError> {
    let (done, answer) = oneshot::channel();
    // The queue is unbounded and a send on it never waits; a refused job comes back inside the error, and
    // is dropped there, wiped.
    if jobs.send(Job { bytes, done }).is_err() {
        return Err(RequestError::Io(gone()));
    }
    match tokio::time::timeout(REPLY_TIMEOUT, answer).await {
        Ok(Ok(sent)) => Ok(sent?),
        Ok(Err(_)) => Err(RequestError::Io(gone())),
        Err(_) => Err(RequestError::Timeout),
    }
}

/// The error of a send thread that is no more.
fn gone() -> io::Error {
    io::Error::new(ErrorKind::BrokenPipe, "the netlink send thread has ended")
}

/// The body of a send thread: sends what comes, in order, until the socket it serves is dropped.
fn serve(fd: &OwnedFd, jobs: &mpsc::Receiver<Job>, mut send: SendFn) {
    while let Ok(Job { mut bytes, done }) = jobs.recv() {
        deliver(fd.as_fd(), &mut send, &mut bytes, done);
        // `bytes` is dropped here, and `Zeroizing` wipes it once more.
    }
}

/// Sends `bytes` with `send`, wipes them, and tells `done` how it went.
///
/// A request whose caller has gone is not sent (it would reach the kernel late, after the caller moved
/// on), but its bytes are wiped all the same.
fn deliver(
    fd: BorrowedFd<'_>,
    send: &mut SendFn,
    bytes: &mut Zeroizing<Vec<u8>>,
    done: oneshot::Sender<io::Result<()>>,
) {
    if done.is_closed() {
        bytes.zeroize();
        return;
    }
    let sent = send(fd, bytes);
    bytes.zeroize();
    // The caller may have given up while the send ran; then nobody is told.
    drop(done.send(sent));
}

/// Sends one datagram, and waits for the socket to take it if it cannot yet.
///
/// The descriptor is non-blocking, because the runtime's `AsyncFd` has it so. A wait that would last
/// longer than [`REPLY_TIMEOUT`] is `ErrorKind::TimedOut`: a netlink socket does not fill up on the way
/// to the kernel, so this is never seen in practice, and a thread is not to be stuck for ever.
pub(super) fn send_blocking(fd: BorrowedFd<'_>, datagram: &[u8]) -> io::Result<()> {
    let began = Instant::now();
    loop {
        match rustix::net::send(fd, datagram, SendFlags::empty()) {
            // A datagram goes whole or not at all.
            Ok(_) => return Ok(()),
            Err(Errno::INTR) => {}
            Err(Errno::AGAIN) => {
                let left = REPLY_TIMEOUT.saturating_sub(began.elapsed());
                let mut fds = [PollFd::new(&fd, PollFlags::OUT)];
                match poll(&mut fds, Some(&timespec(left))) {
                    Ok(0) => return Err(ErrorKind::TimedOut.into()),
                    Ok(_) | Err(Errno::INTR) => {}
                    Err(errno) => return Err(errno.into()),
                }
            }
            Err(errno) => return Err(errno.into()),
        }
    }
}

/// `duration` as the system call wants it.
fn timespec(duration: Duration) -> Timespec {
    Timespec::try_from(duration).unwrap_or(Timespec {
        tv_sec: i64::MAX,
        tv_nsec: 0,
    })
}

#[cfg(test)]
thread_local! {
    /// How many offloaded sockets this thread has opened, for a test that asks whether code opens them.
    static OFFLOADED_OPENS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// How many offloaded sockets the calling thread has opened so far.
#[cfg(test)]
pub(crate) fn offloaded_opens() -> usize {
    OFFLOADED_OPENS.with(std::cell::Cell::get)
}

/// The reply to one request, as far as it has come.
struct Reply {
    seq: u32,
    dump: bool,
    payloads: Vec<Vec<u8>>,
}

impl Reply {
    fn new(seq: u32, dump: bool) -> Self {
        Self {
            seq,
            dump,
            payloads: Vec::new(),
        }
    }

    /// Reads one datagram of the reply.
    ///
    /// `None` while the reply goes on. At its end, the payloads of
    /// everything that came before, or the error that ended it.
    fn take(&mut self, datagram: &[u8]) -> Option<Result<Vec<Vec<u8>>, RequestError>> {
        for message in messages(datagram).filter(|message| message.seq == self.seq) {
            if let Some(answer) = ack(&message) {
                match answer {
                    Err(error) => return Some(Err(RequestError::Kernel(error))),
                    // The end of a request that is not a dump.
                    Ok(_) if !self.dump => return Some(Ok(std::mem::take(&mut self.payloads))),
                    Ok(_) => {}
                }
            } else if message.msg_type == NLMSG_DONE {
                if self.dump {
                    return Some(done(&message).map(|()| std::mem::take(&mut self.payloads)));
                }
            } else {
                self.payloads.push(message.payload.to_vec());
            }
        }
        None
    }
}

/// How a dump ended: its `NLMSG_DONE` holds the error that stopped it, if one did.
fn done(message: &Message<'_>) -> Result<(), RequestError> {
    let code = message
        .payload
        .first_chunk()
        .copied()
        .map(i32::from_ne_bytes);
    match code {
        Some(code) if code < 0 => Err(RequestError::Kernel(NlError {
            errno: code.saturating_neg(),
            message: None,
        })),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::{self, ThreadId};

    use crate::netlink::route::{get_link, parse_link};
    use crate::netlink::{NLM_F_MULTI, NLM_F_REQUEST, NLMSG_ERROR};
    use crate::services::testutil::longest_gap;

    /// A message of the reply to request `seq`, holding `body` after its header.
    fn data(seq: u32, body: &[u8]) -> Vec<u8> {
        MsgBuilder::new(16, NLM_F_MULTI).header(body).finish(seq)
    }

    /// An acknowledgement of request `seq`: zero for success, an errno otherwise.
    fn acknowledgement(seq: u32, errno: i32) -> Vec<u8> {
        MsgBuilder::new(NLMSG_ERROR, 0)
            .header(&(-errno).to_ne_bytes())
            .header(&[0; 16])
            .finish(seq)
    }

    /// The end of a dump of request `seq`, with the error that stopped it (zero for none).
    fn dump_done(seq: u32, errno: i32) -> Vec<u8> {
        MsgBuilder::new(NLMSG_DONE, NLM_F_MULTI)
            .header(&(-errno).to_ne_bytes())
            .finish(seq)
    }

    fn datagram(messages: &[Vec<u8>]) -> Vec<u8> {
        messages.concat()
    }

    #[test]
    fn a_dump_ends_at_its_done_and_keeps_the_order() {
        let mut reply = Reply::new(5, true);
        assert!(
            reply
                .take(&datagram(&[data(5, b"one."), data(5, b"two.")]))
                .is_none()
        );
        let end = reply
            .take(&datagram(&[data(5, b"six."), dump_done(5, 0)]))
            .unwrap()
            .unwrap();
        assert_eq!(end, [b"one.", b"two.", b"six."]);
    }

    #[test]
    fn what_answers_another_request_is_skipped() {
        let mut reply = Reply::new(5, true);
        let datagram = datagram(&[
            data(4, b"old."),
            acknowledgement(4, 22),
            data(0, b"news"),
            dump_done(4, 0),
            data(5, b"mine"),
            dump_done(5, 0),
        ]);
        assert_eq!(reply.take(&datagram).unwrap().unwrap(), [b"mine"]);
    }

    #[test]
    fn a_request_that_is_not_a_dump_ends_at_its_acknowledgement() {
        let mut reply = Reply::new(5, false);
        assert!(reply.take(&data(5, b"data")).is_none());
        // Not the end: that is a dump's marker.
        assert!(reply.take(&dump_done(5, 0)).is_none());
        let end = reply.take(&acknowledgement(5, 0)).unwrap().unwrap();
        assert_eq!(end, [b"data"]);

        // With nothing before the acknowledgement, the payloads are none.
        let mut reply = Reply::new(6, false);
        assert!(
            reply
                .take(&acknowledgement(6, 0))
                .unwrap()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn an_acknowledgement_does_not_end_a_dump() {
        let mut reply = Reply::new(5, true);
        let datagram = datagram(&[data(5, b"data"), acknowledgement(5, 0)]);
        assert!(reply.take(&datagram).is_none());
        assert_eq!(reply.take(&dump_done(5, 0)).unwrap().unwrap(), [b"data"]);
    }

    #[test]
    fn an_error_ends_either_kind_of_request() {
        for dump in [false, true] {
            let mut reply = Reply::new(5, dump);
            let end = reply
                .take(&datagram(&[data(5, b"data"), acknowledgement(5, 19)]))
                .unwrap();
            let error = end.unwrap_err();
            assert_eq!(error.errno(), Some(19), "dump: {dump}");
        }
    }

    #[test]
    fn a_dump_that_failed_says_so() {
        let mut reply = Reply::new(5, true);
        let error = reply.take(&dump_done(5, 95)).unwrap().unwrap_err();
        assert_eq!(error.errno(), Some(95));
        // A done with no code, or a code of zero, is the end of a dump that worked.
        for end in [dump_done(5, 0), MsgBuilder::new(NLMSG_DONE, 0).finish(5)] {
            assert!(Reply::new(5, true).take(&end).unwrap().unwrap().is_empty());
        }
    }

    #[test]
    fn a_reply_cut_short_goes_on() {
        let mut reply = Reply::new(5, true);
        let whole = datagram(&[data(5, b"data"), dump_done(5, 0)]);
        // The first message is whole, the end marker is cut off.
        assert!(reply.take(&whole[..whole.len() - 4]).is_none());
        assert!(reply.take(&[1, 2, 3]).is_none());
        assert_eq!(reply.take(&dump_done(5, 0)).unwrap().unwrap(), [b"data"]);
    }

    #[test]
    fn the_errors_say_what_they_are() {
        let kernel = RequestError::Kernel(NlError {
            errno: 101,
            message: Some("Nexthop has invalid gateway".into()),
        });
        assert_eq!(kernel.errno(), Some(101));
        assert!(kernel.to_string().contains("Nexthop has invalid gateway"));
        let io = RequestError::from(io::Error::from(Errno::NOBUFS));
        assert_eq!(io.errno(), None);
        assert!(io.to_string().starts_with("netlink socket: "));
        assert_eq!(RequestError::Timeout.errno(), None);
        assert_eq!(
            RequestError::Timeout.to_string(),
            "no answer from the kernel within 5 s"
        );
        assert_eq!(RequestError::Malformed.errno(), None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_reply_that_never_ends_times_out() {
        // Nothing was asked of the kernel, so nothing comes back.
        let mut socket = NlSocket::open(NetlinkProtocol::Generic).unwrap();
        let started = tokio::time::Instant::now();
        let outcome = socket.reply(1, true).await;
        assert!(matches!(outcome, Err(RequestError::Timeout)));
        assert_eq!(started.elapsed(), REPLY_TIMEOUT);
    }

    #[tokio::test]
    async fn the_kernel_answers_a_question_that_changes_nothing() {
        // Reading a link by a name that no link has: the kernel's refusal, with its number.
        let mut socket = NlSocket::open(NetlinkProtocol::Route).unwrap();
        let ask = || {
            MsgBuilder::new(18, NLM_F_REQUEST | NLM_F_ACK)
                .header(&[0; 16])
                .attr_str(3, "nosuch0")
        };
        for _ in 0..2 {
            let error = socket.request(ask()).await.unwrap_err();
            assert_eq!(error.errno(), Some(19), "{error}");
        }
        // And a dump ends, having listed the links.
        let dump = MsgBuilder::new(18, NLM_F_REQUEST | NLM_F_DUMP).header(&[0; 16]);
        assert!(!socket.request(dump).await.unwrap().is_empty());
    }

    /// How long the injected sends of the tests below take: a firmware command that is not answered.
    const SLOW_SEND: Duration = Duration::from_millis(2500);

    /// The thread, and its name, that a send ran on.
    type SenderThread = (ThreadId, Option<String>);

    /// A send function that sleeps for `delay`, then sends for real, and records where it ran.
    fn slow_send(delay: Duration, ran_on: Arc<Mutex<Vec<SenderThread>>>) -> SendFn {
        Box::new(move |fd, bytes| {
            let thread = thread::current();
            ran_on
                .lock()
                .unwrap()
                .push((thread.id(), thread.name().map(str::to_owned)));
            thread::sleep(delay);
            send_blocking(fd, bytes)
        })
    }

    /// Asks for `lo`, which every machine has, and checks that the kernel's answer is a link.
    async fn ask_for_lo(socket: &mut NlSocket) -> Result<(), RequestError> {
        let payloads = socket.request(get_link("lo")).await?;
        assert!(parse_link(&payloads[0]).is_some());
        Ok(())
    }

    /// The longest time the runtime's thread was held while an offloaded socket made a request whose
    /// send took `SLOW_SEND`.
    async fn gap_with_an_offloaded_slow_send() -> Duration {
        let ran_on = Arc::default();
        let mut socket = NlSocket::open_offloaded_with(
            NetlinkProtocol::Route,
            slow_send(SLOW_SEND, Arc::clone(&ran_on)),
        )
        .unwrap();
        let began = Instant::now();
        let (gap, asked) = longest_gap(ask_for_lo(&mut socket)).await;
        asked.unwrap();
        assert!(began.elapsed() >= SLOW_SEND, "the send was not slow");
        assert_eq!(ran_on.lock().unwrap().len(), 1);
        gap
    }

    #[tokio::test]
    async fn a_slow_send_does_not_hold_the_runtime_and_the_request_completes() {
        let gap = gap_with_an_offloaded_slow_send().await;
        assert!(
            gap < Duration::from_millis(50),
            "the runtime was held for {gap:?}"
        );
    }

    /// Prints the longest gap the runtime's thread had while a send took `SLOW_SEND`, on an inline socket
    /// and on an offloaded one; run with `--ignored --nocapture`.
    #[tokio::test]
    #[ignore = "prints two figures"]
    async fn print_the_gap_of_a_slow_send_inline_and_offloaded() {
        // An inline socket sends on the thread that polls it, so a driver that runs the command inside
        // `send(2)` holds that thread: here the same hold is made just before the real send.
        let mut inline = NlSocket::open(NetlinkProtocol::Route).unwrap();
        let (before, asked) = longest_gap(async {
            thread::sleep(SLOW_SEND);
            ask_for_lo(&mut inline).await
        })
        .await;
        asked.unwrap();
        let after = gap_with_an_offloaded_slow_send().await;
        println!(
            "a {SLOW_SEND:?} send: longest runtime gap inline {before:?}, offloaded {after:?}"
        );
    }

    #[tokio::test]
    async fn a_send_that_never_returns_ends_the_request_in_time_and_the_next_is_bounded_too() {
        let (entered, has_entered) = mpsc::channel::<()>();
        let (release, stuck) = mpsc::channel::<()>();
        let stuck = Mutex::new(Some(stuck));
        let sent = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&sent);
        let mut socket = NlSocket::open_offloaded_with(
            NetlinkProtocol::Route,
            Box::new(move |fd, bytes| {
                // The first send is stuck until it is released, and then sends nothing.
                let first = stuck.lock().unwrap().take();
                if let Some(stuck) = first {
                    entered.send(()).unwrap();
                    let _ = stuck.recv();
                    return Ok(());
                }
                counted.fetch_add(1, Ordering::SeqCst);
                send_blocking(fd, bytes)
            }),
        )
        .unwrap();

        // The clock is frozen once the thread is in the send, so that the waits end at once, and not
        // before: a clock that ran ahead of the thread would end the request with the send not begun.
        let freeze = async {
            while has_entered.try_recv().is_err() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            tokio::time::pause();
            std::future::pending::<()>().await
        };
        let began = tokio::time::Instant::now();
        let first = tokio::select! {
            asked = ask_for_lo(&mut socket) => asked,
            () = freeze => unreachable!("the freeze does not end"),
        };
        assert!(matches!(first, Err(RequestError::Timeout)), "{first:?}");
        assert!(began.elapsed() >= REPLY_TIMEOUT);
        // The next request waits behind the stuck send, and is bounded the same.
        let second = ask_for_lo(&mut socket).await;
        assert!(matches!(second, Err(RequestError::Timeout)), "{second:?}");
        assert!(began.elapsed() >= 2 * REPLY_TIMEOUT);
        assert!(began.elapsed() < 2 * REPLY_TIMEOUT + Duration::from_secs(1));

        // Once the send returns, the second request, which nobody waits for, is not sent, and the
        // socket works again. The clock runs again, so that it does not decide the third request's
        // timeout while the thread is still to answer.
        release.send(()).unwrap();
        tokio::time::resume();
        ask_for_lo(&mut socket).await.unwrap();
        assert_eq!(sent.load(Ordering::SeqCst), 1);
    }

    /// Runs `deliver` for a request, with `send` as the sending function; returns what it told the
    /// caller (`None` if there was no caller to tell) and the bytes afterwards.
    fn deliver_with(
        send: SendFn,
        caller_waits: bool,
    ) -> (Option<io::Result<()>>, Zeroizing<Vec<u8>>) {
        let mut send = send;
        let mut bytes = Zeroizing::new(b"the key is 0123456789".to_vec());
        let (done, answer) = oneshot::channel();
        let mut answer = caller_waits.then_some(answer);
        deliver(io::stdin().as_fd(), &mut send, &mut bytes, done);
        (
            answer.as_mut().map(|answer| answer.try_recv().unwrap()),
            bytes,
        )
    }

    #[test]
    fn the_bytes_are_wiped_whether_the_send_worked_failed_or_nobody_waited() {
        let works: SendFn = Box::new(|_, bytes| {
            assert_eq!(bytes, b"the key is 0123456789");
            Ok(())
        });
        let (told, bytes) = deliver_with(works, true);
        assert!(told.unwrap().is_ok());
        assert!(bytes.is_empty(), "sent, and not wiped");

        let fails: SendFn = Box::new(|_, _| Err(io::Error::from(ErrorKind::PermissionDenied)));
        let (told, bytes) = deliver_with(fails, true);
        assert_eq!(
            told.unwrap().unwrap_err().kind(),
            ErrorKind::PermissionDenied
        );
        assert!(bytes.is_empty(), "refused, and not wiped");

        // The caller gave up first: nothing is sent, and the bytes are wiped all the same.
        let never: SendFn = Box::new(|_, _| panic!("a request nobody waits for was sent"));
        let (told, bytes) = deliver_with(never, false);
        assert!(told.is_none());
        assert!(bytes.is_empty(), "dropped, and not wiped");
    }

    #[tokio::test]
    async fn the_send_thread_ends_with_its_socket() {
        let (alive, gone) = mpsc::channel::<()>();
        let socket = NlSocket::open_offloaded_with(
            NetlinkProtocol::Route,
            Box::new(move |fd, bytes| {
                let _keeps_the_channel_open = &alive;
                send_blocking(fd, bytes)
            }),
        )
        .unwrap();
        let mut socket = socket;
        ask_for_lo(&mut socket).await.unwrap();
        assert!(socket.is_offloaded());
        assert!(
            !NlSocket::open(NetlinkProtocol::Route)
                .unwrap()
                .is_offloaded()
        );
        // The thread holds the only sender, and its closure is dropped when it ends.
        assert!(matches!(
            gone.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        drop(socket);
        assert!(matches!(
            gone.recv_timeout(Duration::from_secs(5)),
            Err(mpsc::RecvTimeoutError::Disconnected)
        ));
    }

    /// The cores that the calling thread may run on.
    fn cores_allowed() -> Vec<usize> {
        let mask = rustix::thread::sched_getaffinity(None).unwrap();
        (0..rustix::thread::CpuSet::MAX_CPU)
            .filter(|core| mask.is_set(*core))
            .collect()
    }

    #[test]
    fn the_send_thread_leaves_the_core_the_runtime_is_pinned_to() {
        let allowed = cores_allowed();
        if allowed.len() < 2 {
            println!(
                "skipped: the host allows {} CPU(s), the test needs 2",
                allowed.len()
            );
            return;
        }
        let core = allowed[0];
        // On a thread of its own, so that the pin does not outlast the test on a thread of the harness.
        let sent_from = thread::spawn(move || {
            cpu::pin_current_thread(core).unwrap();
            let runtime = crate::services::runtime(Some(core)).unwrap();
            runtime.block_on(async {
                let sent_from = Arc::new(Mutex::new(Vec::new()));
                let recorded = Arc::clone(&sent_from);
                let mut socket = NlSocket::open_offloaded_with(
                    NetlinkProtocol::Route,
                    Box::new(move |fd, bytes| {
                        recorded.lock().unwrap().push(cores_allowed());
                        send_blocking(fd, bytes)
                    }),
                )
                .unwrap();
                ask_for_lo(&mut socket).await.unwrap();
                std::mem::take(&mut *sent_from.lock().unwrap())
            })
        })
        .join()
        .unwrap();
        // Made from a thread that is pinned to `core`, the send thread started with that one core.
        assert_eq!(sent_from, vec![allowed[1..].to_vec()]);
    }
}
