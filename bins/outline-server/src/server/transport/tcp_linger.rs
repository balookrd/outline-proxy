//! Delivering what a relay already wrote upstream before the socket closes.
//!
//! A relay that is done with a target half-closes the upstream and drops it.
//! Dropping it right after `shutdown()` is not enough on Linux: a `close()` of a
//! socket whose receive queue still holds unread bytes — or that takes more data
//! from the target after the close — makes the kernel answer with an RST and
//! throw away whatever of its send queue is still unsent (RFC 2525 behaviour).
//! The target then sees `ECONNRESET` with the tail of the request body missing.
//! BSD-derived stacks (macOS) close such a socket gracefully.

use std::time::Duration;

use tokio::net::TcpStream;
#[cfg(target_os = "linux")]
use tracing::debug;

/// How often [`linger_until_delivered`] re-reads the upstream's send queue.
#[cfg(target_os = "linux")]
const LINGER_POLL: Duration = Duration::from_millis(10);

/// One read of downlink bytes nobody wants any more.
#[cfg(target_os = "linux")]
const LINGER_SINK: usize = 16 * 1024;

/// Absolute ceiling of [`linger_until_delivered`], in budgets. A target that
/// keeps taking a byte at a time renews the no-progress budget forever, and
/// the client that wrote the body is already gone, so the wait ends here no
/// matter what.
#[cfg(any(target_os = "linux", test))]
const LINGER_HARD_CAP_FACTOR: u32 = 8;

/// When to stop waiting for an upstream's send queue to drain: once it has not
/// shrunk for a whole budget, or [`LINGER_HARD_CAP_FACTOR`] budgets after the
/// start regardless of progress.
#[cfg(any(target_os = "linux", test))]
struct LingerPatience {
    budget: Duration,
    progress_at: tokio::time::Instant,
    deadline: tokio::time::Instant,
}

#[cfg(any(target_os = "linux", test))]
impl LingerPatience {
    fn new(budget: Duration) -> Self {
        let now = tokio::time::Instant::now();
        Self {
            budget,
            progress_at: now,
            deadline: now + budget.saturating_mul(LINGER_HARD_CAP_FACTOR),
        }
    }

    /// Records one send-queue sample, `shrank` saying it went down since the
    /// previous one, and says whether to keep waiting.
    fn keep_waiting(&mut self, shrank: bool) -> bool {
        let now = tokio::time::Instant::now();
        if now >= self.deadline {
            return false;
        }
        if shrank {
            self.progress_at = now;
        }
        now.duration_since(self.progress_at) < self.budget
    }
}

/// Keeps a half-closed upstream open until the kernel has delivered the request
/// body the relay already wrote into it.
///
/// The upstream is drained into the void until its send queue is empty, the
/// target closes, or the queue stops shrinking for a whole `budget` (a renewable
/// bound: a target that keeps taking bytes keeps renewing it), and in any case
/// for at most [`LINGER_HARD_CAP_FACTOR`] budgets. After that, an RST on drop
/// only discards downlink bytes nobody wants.
///
/// Reads go through the shared `TcpStream` (an `OwnedWriteHalf` derefs to it via
/// `as_ref`), so the caller may already have given up the read half — as long as
/// nothing else is still reading the socket.
///
/// Elsewhere this is a no-op: BSD-derived stacks close such a socket gracefully,
/// and the send queue depth is read with a Linux-only ioctl.
pub(in crate::server::transport) async fn linger_until_delivered(
    stream: &TcpStream,
    budget: Duration,
) {
    #[cfg(target_os = "linux")]
    {
        let Some(mut pending) = unsent_bytes(stream) else { return };
        let mut sink = vec![0u8; LINGER_SINK];
        let mut patience = LingerPatience::new(budget);
        while pending > 0 {
            tokio::select! {
                ready = stream.readable() => match ready {
                    Err(_) => return,
                    Ok(()) => match stream.try_read(&mut sink) {
                        // The target closed or reset: nothing will draw RST
                        // from it now, or there is nobody left to deliver to.
                        Ok(0) => return,
                        Err(error) if error.kind() != std::io::ErrorKind::WouldBlock => return,
                        Ok(_) | Err(_) => {},
                    },
                },
                () = tokio::time::sleep(LINGER_POLL) => {},
            }
            let Some(now) = unsent_bytes(stream) else { return };
            if !patience.keep_waiting(now < pending) {
                debug!(unsent = now, "giving up on delivering a request-body tail upstream");
                return;
            }
            pending = now;
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (stream, budget);
}

/// Bytes in the socket's send queue the peer has not acknowledged yet, or
/// `None` when the kernel will not say.
#[cfg(target_os = "linux")]
fn unsent_bytes(stream: &TcpStream) -> Option<usize> {
    use std::os::fd::AsRawFd;

    let fd = stream.as_raw_fd();
    let mut queued: libc::c_int = 0;
    // SAFETY: `fd` is borrowed from `stream`, which keeps the socket open for
    // the whole call. `TIOCOUTQ` (`SIOCOUTQ` on a TCP socket) writes exactly
    // one `c_int` through the pointer, and `queued` is a live, aligned `c_int`.
    let rc = unsafe { libc::ioctl(fd, libc::TIOCOUTQ, &mut queued) };
    (rc == 0).then(|| usize::try_from(queued).unwrap_or(0))
}

#[cfg(test)]
#[path = "tests/tcp_linger.rs"]
mod tests;
