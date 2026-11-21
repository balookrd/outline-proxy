//! A stream that must deliver its first bytes within a deadline.
//!
//! After the TLS handshake a connection has proven it speaks TLS and nothing
//! else. hyper then waits for the first request with no time limit of its own
//! on two paths: the HTTP/2 client preface, and the h1/h2 protocol sniff of a
//! connection that negotiated no ALPN. A peer that completes the handshake and
//! goes silent would hold its connection slot for good.
//!
//! [`FirstBytesDeadline`] wraps the stream and fails a read with
//! `ErrorKind::TimedOut` when fewer than `required` bytes have arrived by the
//! deadline. Once they have, it is a transparent pass-through.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Duration, Sleep, sleep},
};

pub(super) struct FirstBytesDeadline<S> {
    inner: S,
    /// Bytes still owed before the deadline is lifted.
    remaining: usize,
    /// `None` once the bytes arrived (or none were required).
    deadline: Option<Pin<Box<Sleep>>>,
}

impl<S> FirstBytesDeadline<S> {
    /// `required == 0` makes the wrapper a pass-through from the start.
    pub(super) fn new(inner: S, required: usize, within: Duration) -> Self {
        Self {
            inner,
            remaining: required,
            deadline: (required > 0).then(|| Box::pin(sleep(within))),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FirstBytesDeadline<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let read = buf.filled().len() - before;
                this.remaining = this.remaining.saturating_sub(read);
                if this.remaining == 0 {
                    this.deadline = None;
                }
                Poll::Ready(Ok(()))
            },
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => {
                if let Some(deadline) = this.deadline.as_mut() {
                    ready!(deadline.as_mut().poll(cx));
                    this.deadline = None;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "no request within the post-handshake deadline",
                    )));
                }
                Poll::Pending
            },
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FirstBytesDeadline<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
#[path = "tests/first_bytes_deadline.rs"]
mod tests;
