//! `XhttpStream` (the `Stream + Sink` adapter handed to callers) plus
//! the small `BoxedIo` enum that lets the h2 handshake hold either a
//! plain TCP or TLS stream behind a single `TokioIo`.

use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::{Error as WsError, protocol::Message};

use crate::carrier_queue::BudgetedSink;
use crate::guards::AbortOnDrop;

use super::{InboundReceiver, InboundSender, XhttpSubmode, message_bytes};

/// Outbound stream returned by [`super::connect_xhttp`]. Implements the
/// same `Stream<Item = Result<Message, WsError>>` + `Sink<Message>`
/// surface as the WebSocket adapters so it slots into existing
/// dispatch without bespoke handling.
pub(crate) struct XhttpStream {
    pub(super) incoming: InboundReceiver,
    /// Byte-budgeted uplink queue. `Sink::poll_ready` pends until the queue
    /// has room for the frame — by bytes and by slots — which is what gives
    /// bulk uploads real back-pressure rather than a `start_send` that
    /// fails-fast on `Full` (or a slot-only bound that admits 256 × 256 KiB).
    /// See [`crate::carrier_queue`].
    pub(super) outgoing: BudgetedSink<Message>,
    pub(super) closed: bool,
    /// Submode the dialer landed on. Differs from the URL-requested
    /// submode when the inline stream-one→packet-up retry kicked in,
    /// so the uplink layer can surface the actual carrier shape on
    /// dashboards instead of the originally-requested one.
    pub(super) active_submode: XhttpSubmode,
    /// Whether the carrier underneath is HTTP/3 (a QUIC stream).
    /// `true` only for `xhttp_h3`; `false` for `xhttp_h1`/`xhttp_h2`,
    /// which ride TCP. Surfaced via [`XhttpStream::carrier_is_h3`] so
    /// the liveness layer can skip the WS-level read-idle watchdog on
    /// QUIC carriers (which run their own keep-alive / `max_idle_timeout`),
    /// exactly as it does for the native `ws_h3` carrier.
    pub(super) carrier_is_h3: bool,
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

    /// Whether the carrier underneath is HTTP/3 (a QUIC stream).
    /// Lets `TransportStream::is_h3` treat `xhttp_h3` like the native
    /// `ws_h3` carrier so the read-idle watchdog / keepalive Ping are
    /// skipped on QUIC, where they are redundant and unsafe (see
    /// `TransportStream::is_h3`).
    pub fn carrier_is_h3(&self) -> bool {
        self.carrier_is_h3
    }

    /// Constructor used by the h3 sibling module: it builds the
    /// driver task and the channel pair on its own and hands the
    /// finished triple here. Keeps the field-level details of
    /// `XhttpStream` (closed flag, channel typing) private to this
    /// module while giving carrier modules a single way in.
    pub(super) fn from_channels(
        incoming: InboundReceiver,
        outgoing: BudgetedSink<Message>,
        driver: AbortOnDrop,
        active_submode: XhttpSubmode,
        carrier_is_h3: bool,
    ) -> Self {
        Self {
            incoming,
            outgoing,
            closed: false,
            active_submode,
            carrier_is_h3,
            _driver: driver,
        }
    }
}

impl Stream for XhttpStream {
    type Item = Result<Message, WsError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Handing the frame to the reader releases its budget permit: the bytes
        // are no longer queued, they are the caller's.
        self.incoming
            .poll_recv(cx)
            .map(|queued| queued.map(|q| q.into_parts().0))
    }
}

impl Sink<Message> for XhttpStream {
    type Error = WsError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.closed {
            return Poll::Ready(Err(io_ws_err("xhttp outgoing closed")));
        }
        // Drives any previously-staged frame into the queue, so the caller only
        // sees `Ready` once we can actually take another one. Pending until the
        // driver frees budget and a slot — the back-pressure signal bulk
        // uploads need; without it the writer above treats a full queue as a
        // fatal Sink error and aborts.
        self.poll_flush(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        if self.closed {
            return Err(io_ws_err("xhttp stream already closed"));
        }
        // The caller observed `Ready` from `poll_ready`, so nothing is staged.
        // The frame is admitted to the queue by the `poll_flush` that
        // `SinkExt::send` drives next, once its bytes fit the budget.
        let bytes = message_bytes(&item);
        self.outgoing.stage(item, bytes);
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.closed {
            return Poll::Ready(Err(io_ws_err("xhttp outgoing closed")));
        }
        match self.outgoing.poll_flush_queue(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(_)) => {
                self.closed = true;
                Poll::Ready(Err(io_ws_err("xhttp outgoing closed")))
            },
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.closed = true;
        // Closes our half of the queue. The driver task observes this through
        // `outbound.recv()` returning None and exits, which aborts the GET
        // sub-task.
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
    in_tx: &InboundSender,
) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use http_body_util::BodyExt;
    while let Some(frame) = body.frame().await {
        let frame = frame.context("xhttp GET body frame error")?;
        if let Ok(data) = frame.into_data()
            && !data.is_empty()
        {
            let bytes = data.len();
            if in_tx.send(Ok(Message::Binary(data)), bytes).await.is_err() {
                // Consumer gave up — exit cleanly.
                return Ok(());
            }
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
    // Boxed: the TLS state machine is an order of magnitude larger than a
    // plain TcpStream, and one connection-scoped allocation is cheaper than
    // carrying that size in every enum value.
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
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
