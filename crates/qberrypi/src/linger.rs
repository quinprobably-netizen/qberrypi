//! The lingering close of the two HTTP servers, the API and the status page.
//!
//! A server that closes a connection while bytes of the client's request are still unread makes
//! the kernel send a reset, not an orderly end, and a reset throws away what of the answer the
//! client has not read yet (and what the server had not yet sent): the 400 or 413 that answers a
//! client that is still sending its body, or the tail of a long `/log`, can be lost. So a
//! connection that has been answered ends in three steps, which keep to the connection's own
//! deadline and never go beyond it:
//!
//! 1. the write side is shut down, which puts the end of the stream after the last byte of the
//!    answer, so that the client can read to the end of it whatever else it is doing;
//! 2. what the client goes on sending is read and thrown away, for at most [`TIME`] and
//!    [`BYTES`], until the client closes its side, which it does once it has read the answer;
//! 3. the connection is closed, with a reset only if a client that never stopped sending is still
//!    at it.
//!
//! Both bounds are small, so that a client that never stops sending holds a place for no longer
//! than that. The API's connections run on threads of the blocking pool and drain with the
//! blocking [`drain`]; the status page's run on the runtime and drain with [`drain_async`],
//! which waits on a timer and takes no thread, so DNS is never kept waiting.

use std::io::{self, Read};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use zeroize::Zeroizing;

/// The longest that a connection that has been answered goes on reading what its client sends,
/// before it is closed. Long enough for a client on a slow link to finish sending a body that
/// was refused and to read the refusal, short enough that no one holds a place for it.
pub const TIME: Duration = Duration::from_secs(2);
/// The most bytes that a connection that has been answered reads and throws away: 64 KiB, which
/// holds what a client that was refused has in flight by the time it reads the refusal, and is
/// read in a few milliseconds, so that a client that never stops is not read for long.
pub const BYTES: usize = 64 * 1024;
/// How many bytes are read at once. What is read is thrown away, and may be a password, so the
/// buffer is wiped when the drain is done; a small one is quick to wipe and costs the status
/// page's connections little.
const CHUNK: usize = 1024;

/// Reads from `reader`, which answers to a deadline of its own, and drops what it gives, until
/// the stream ends, a read fails (a deadline that has passed is a failure) or `limit` bytes have
/// been read. Returns how many were.
pub fn drain(reader: &mut impl Read, limit: usize) -> usize {
    let mut chunk = Zeroizing::new([0u8; CHUNK]);
    let mut total = 0;
    while total < limit {
        let room = chunk.len().min(limit - total);
        match chunk.get_mut(..room).map(|room| reader.read(room)) {
            Some(Ok(0)) | None => break,
            Some(Ok(read)) => total += read,
            Some(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {}
            Some(Err(_)) => break,
        }
    }
    total
}

/// [`drain`] for a reader of the runtime: the same, with no deadline of its own, which the caller
/// puts on it.
pub async fn drain_async(reader: &mut (impl AsyncRead + Unpin), limit: usize) -> usize {
    let mut chunk = Zeroizing::new([0u8; CHUNK]);
    let mut total = 0;
    while total < limit {
        let room = chunk.len().min(limit - total);
        let Some(room) = chunk.get_mut(..room) else {
            break;
        };
        match reader.read(room).await {
            Ok(0) | Err(_) => break,
            Ok(read) => total += read,
        }
    }
    total
}

/// Closes `stream`, which has been answered and flushed, as the module says: the write side is
/// shut down, and what the client sends is drained for at most [`TIME`] and [`BYTES`]. The
/// connection is closed when this returns.
///
/// The caller's own deadline is on top: this is called inside it, and if it passes the drain is
/// dropped with the rest of the connection.
pub async fn close(mut stream: TcpStream) {
    if stream.shutdown().await.is_err() {
        return;
    }
    let _ = timeout(TIME, drain_async(&mut stream, BYTES)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    /// A reader that gives `byte` for ever and counts the bytes that it gave.
    struct Endless {
        given: usize,
    }

    impl Read for Endless {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            self.given += out.len();
            out.fill(b'x');
            Ok(out.len())
        }
    }

    #[test]
    fn the_bounds_are_small() {
        assert_eq!((TIME, BYTES), (Duration::from_secs(2), 64 * 1024));
    }

    #[test]
    fn a_stream_that_never_ends_is_read_for_exactly_the_limit() {
        for limit in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, BYTES] {
            let mut endless = Endless { given: 0 };
            assert_eq!(drain(&mut endless, limit), limit);
            assert_eq!(endless.given, limit, "no more is read than the limit");
        }
    }

    #[test]
    fn a_stream_that_ends_or_fails_is_drained_as_far_as_it_goes() {
        assert_eq!(drain(&mut Cursor::new(vec![0u8; 3000]), BYTES), 3000);
        assert_eq!(drain(&mut io::empty(), BYTES), 0);
        /// Gives ten bytes at a read, is interrupted at its third, and fails at its tenth.
        struct Fails(usize);
        impl Read for Fails {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                self.0 += 1;
                match self.0 {
                    3 => Err(io::ErrorKind::Interrupted.into()),
                    1..=9 => Ok(out.len().min(10)),
                    _ => Err(io::ErrorKind::ConnectionReset.into()),
                }
            }
        }
        // Eight reads of ten bytes (the interrupted one is tried again), and then an error, which
        // ends the drain.
        assert_eq!(drain(&mut Fails(0), BYTES), 80);
    }

    #[tokio::test]
    async fn the_async_drain_is_bound_the_same_way() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let sender = tokio::spawn(async move {
            // More than the limit, and the client's side is dropped at the end.
            let chunk = [7u8; 1000];
            for _ in 0..10 {
                if client.write_all(&chunk).await.is_err() {
                    break;
                }
            }
        });
        assert_eq!(drain_async(&mut server, 2500).await, 2500);
        assert_eq!(drain_async(&mut server, BYTES).await, 7500);
        sender.await.unwrap();
    }
}
