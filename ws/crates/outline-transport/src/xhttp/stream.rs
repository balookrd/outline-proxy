//! `XhttpStream` (the `Stream + Sink` adapter handed to callers) plus
//! the small `BoxedIo` enum that lets the h2 handshake hold either a
//! plain TCP or TLS stream behind a single `TokioIo`.

use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::{Error as WsError, protocol::Message};
use tokio_util::sync::PollSender;

use crate::guards::AbortOnDrop;

use super::XhttpSubmode;

/// Outbound stream returned by [`super::connect_xhttp`]. Implements the
/// same `Stream<Item = Result<Message, WsError>>` + `Sink<Message>`
/// surface as the WebSocket adapters so it slots into existing
/// dispatch without bespoke handling.
pub(crate) struct XhttpStream {
    pub(super) incoming: mpsc::Receiver<Result<Message, WsError>>,
    /// Wraps the raw `mpsc::Sender` so `Sink::poll_ready` can honor
    /// the channel's capacity instead of always reporting ready.
    /// `PollSender` reserves a permit asynchronously and stashes the
    /// waker, which is what gives bulk uploads real back-pressure
    /// rather than a `start_send` that fails-fast on `Full`.
    pub(super) outgoing: PollSender<Message>,
    pub(super) closed: bool,
    /// Submode the dialer landed on. Differs from the URL-requested
    /// submode when the inline stream-one→packet-up retry kicked in,
    /// so the uplink layer can surface the actual carrier shape on
    /// dashboards instead of the originally-requested one.
    pub(super) active_submode: XhttpSubmode,
    // The driver task owns the h2 SendRequest, the GET reader
    // sub-task and the POST fan-out sub-tasks. Dropping the stream
    // aborts the driver, which cancels every sub-task and frees the
    // h2 connection.
    pub(super) _driver: AbortOnDrop,
}

impl XhttpStream {
    /// Returns true while the underlying h2 connection is still
    /// believed healthy. Cheap proxy for `Sink` health that the
    /// uplink manager polls between sends; once the driver task
    /// has closed the outbound channel we surface that as `false`.
    pub fn is_healthy(&self) -> bool {
        !self.outgoing.is_closed()
    }

    /// The XHTTP submode this stream is actually carrying (after any
    /// inline stream-one→packet-up fallback at dial time). The h-version
    /// is reflected separately by the surrounding `TransportMode` —
    /// this method only tells you whether the carrier is `stream-one`
    /// or `packet-up`.
    pub fn active_submode(&self) -> XhttpSubmode {
        self.active_submode
    }

    /// Constructor used by the h3 sibling module: it builds the
    /// driver task and the channel pair on its own and hands the
    /// finished triple here. Keeps the field-level details of
    /// `XhttpStream` (closed flag, channel typing) private to this
    /// module while giving carrier modules a single way in.
    pub(super) fn from_channels(
        incoming: mpsc::Receiver<Result<Message, WsError>>,
        outgoing: mpsc::Sender<Message>,
        driver: AbortOnDrop,
        active_submode: XhttpSubmode,
    ) -> Self {
        Self {
            incoming,
            outgoing: PollSender::new(outgoing),
            closed: false,
            active_submode,
            _driver: driver,
        }
    }
}

impl Stream for XhttpStream {
    type Item = Result<Message, WsError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.incoming.poll_recv(cx)
    }
}

impl Sink<Message> for XhttpStream {
    type Error = WsError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.closed {
            return Poll::Ready(Err(io_ws_err("xhttp outgoing closed")));
        }
        // Reserve a permit — pending until the driver drains the
        // outbound channel. This is the back-pressure signal that
        // bulk uploads need: without it the writer above us treats
        // a full channel as a fatal Sink error and aborts.
        match self.outgoing.poll_reserve(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(_)) => {
                self.closed = true;
                Poll::Ready(Err(io_ws_err("xhttp outgoing closed")))
            },
            Poll::Pending => Poll::Pending,
        }
    }

    fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        if self.closed {
            return Err(io_ws_err("xhttp stream already closed"));
        }
        // Caller must have observed `Ready` from `poll_ready`, so a
        // permit is already reserved; `send_item` only fails if the
        // receiver was dropped between then and now.
        self.outgoing.send_item(item).map_err(|_| {
            self.closed = true;
            io_ws_err("xhttp outgoing closed")
        })
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // No application-level buffer beyond the reserved permit.
        // h2 flow control + the bounded channel itself are the
        // flushing layers and they self-drain.
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.closed = true;
        // Closes our half of the channel. The driver task observes
        // this through `outbound.recv()` returning None and exits,
        // which aborts the GET sub-task.
        self.outgoing.close();
        Poll::Ready(Ok(()))
    }
}

pub(super) fn io_ws_err(msg: &'static str) -> WsError {
    WsError::Io(std::io::Error::other(msg))
}

/// Drain a hyper response body into the inbound channel as
/// `Message::Binary` frames. Used by the h1 and h2 packet-up GET
/// handlers, both of which produce `hyper::body::Incoming`.
pub(super) async fn drain_hyper_body(
    mut body: hyper::body::Incoming,
    in_tx: &mpsc::Sender<Result<Message, WsError>>,
) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use http_body_util::BodyExt;
    while let Some(frame) = body.frame().await {
        let frame = frame.context("xhttp GET body frame error")?;
        if let Ok(data) = frame.into_data()
            && !data.is_empty()
            && in_tx.send(Ok(Message::Binary(data))).await.is_err()
        {
            // Consumer gave up — exit cleanly.
            return Ok(());
        }
    }
    Ok(())
}

// Simple AsyncRead+Write wrapper so we can hold either a plain TCP
// stream or a TLS stream behind a single `TokioIo` without an enum
// in the type signature of `spawn_h2`. Sibling modules (h1, h2)
// reuse the same wrapper for their own handshakes.
pub(super) enum BoxedIo {
    Plain(TcpStream),
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
}

impl AsyncRead for BoxedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Safety: project via `get_mut` since the inner enum holds
        // owned streams; `Pin::new` on the inner is sound because
        // both `TcpStream` and `TlsStream` are `Unpin`.
        let this = self.get_mut();
        match this {
            BoxedIo::Plain(s) => Pin::new(s).poll_read(cx, buf),
            BoxedIo::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for BoxedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match this {
            BoxedIo::Plain(s) => Pin::new(s).poll_write(cx, buf),
            BoxedIo::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this {
            BoxedIo::Plain(s) => Pin::new(s).poll_flush(cx),
            BoxedIo::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this {
            BoxedIo::Plain(s) => Pin::new(s).poll_shutdown(cx),
            BoxedIo::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}
