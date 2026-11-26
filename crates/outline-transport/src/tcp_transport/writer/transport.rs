use crate::TransportOperation;
use crate::carrier_padding;
use crate::carrier_queue::BudgetedSender;
use crate::ws_writer::{WsWriterOptions, spawn_ws_writer};
use crate::ws_writer_diag::WRITER_SS;
use crate::{AbortOnDrop, TransportStream};
use anyhow::{Context, Result, anyhow};
use futures_util::stream::SplitSink;
use outline_wire::early_shape::{EarlyShaper, ShapeDirection};
use outline_wire::padding_frames::{OutboundFramer, frame_message};
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::error::Error as WsError;
use tokio_tungstenite::tungstenite::protocol::Message;

/// How long the writer holds the SS2022 request header waiting for the first
/// data message, so both leave in one WS message instead of a lone 130-141 B
/// record ahead of the ClientHello. Server-speaks-first protocols simply see
/// the header after this delay.
pub(crate) const SS2022_HEADER_HOLD: std::time::Duration = std::time::Duration::from_millis(50);

pub(super) type WsSink = SplitSink<TransportStream, Message>;

#[allow(async_fn_in_trait)]
pub trait WriteTransport: Send + 'static {
    async fn write_frame(&mut self, frame: Vec<u8>) -> Result<()>;
    /// Writes the SS2022 request header. Transports that can coalesce it with
    /// the first data write may hold it briefly; the default writes at once.
    async fn write_frame_held(&mut self, frame: Vec<u8>) -> Result<()> {
        self.write_frame(frame).await
    }
    async fn close(&mut self) -> Result<()>;
    fn supports_half_close(&self) -> bool;
}

#[doc(hidden)]
pub struct WsWriteTransport {
    data_tx: Option<BudgetedSender<Message>>,
    /// Hand-off for the held SS2022 request header (see `write_frame_held`).
    held_tx: Option<mpsc::Sender<Vec<u8>>>,
    /// Kept alive for its `AbortOnDrop` — aborts the writer task on drop.
    _writer_task: Option<AbortOnDrop>,
    /// Outbound framer applying optional early-session shaping, HTTP/2 cap,
    /// and carrier padding.
    framer: OutboundFramer,
    /// Whether `write_frame_held` holds the SS2022 request header for the
    /// first data (h1/h2 carriers). Off on h3, where no record shape is at
    /// stake, and in uplink probes, whose measured latency the hold would skew.
    hold_header: bool,
}

impl WsWriteTransport {
    /// Build a WS write transport by spawning the multiplexing writer task and
    /// returning the control-channel sender alongside it.  The control sender
    /// must be passed to the paired reader so that Pong responses go through
    /// the priority channel.
    pub(super) fn spawn<S>(sink: S, shape: bool, hold_header: bool) -> (Self, mpsc::Sender<Message>)
    where
        S: futures_util::Sink<Message, Error = WsError> + Unpin + Send + 'static,
    {
        let padding = carrier_padding::effective_carrier_padding();
        let shaper = shape.then(|| {
            EarlyShaper::new(
                ShapeDirection::ClientToServer,
                padding.scheme.is_enabled(),
                &mut carrier_padding::draw_in(&mut rand::rng()),
            )
        });
        let framer = OutboundFramer::new(padding.scheme, shaper, None);
        // Note: an earlier iteration of this writer task fired a periodic
        // WebSocket Ping (intended as an idle keepalive against HAProxy /
        // nginx `proxy_*_timeout`).  In real deployments — HAProxy →
        // outline-ss-server, plain outline-ss-server over H3 — those Pings
        // poisoned the upstream Shadowsocks state and caused immediate
        // chunk-0 EOF on the next data frame, the exact opposite of the
        // intended effect.  Application-level keepalive that the upstream
        // Shadowsocks daemon actually sees is provided by `send_keepalive`
        // (a 0-length encrypted SS2022 chunk) driven from the SOCKS uplink
        // task; nothing here injects WebSocket control frames.
        let handles = spawn_ws_writer(
            sink,
            WsWriterOptions {
                cover: padding.cover_params(),
                hold_header: hold_header.then_some(SS2022_HEADER_HOLD),
                diag_writer: WRITER_SS,
                stop_on_data_close_frame: false,
            },
        );
        (
            Self {
                data_tx: Some(handles.data_tx),
                held_tx: handles.held_tx,
                _writer_task: Some(handles.task),
                framer,
                hold_header,
            },
            handles.ctrl_tx,
        )
    }

    /// Cuts every uplink message to one h2 DATA frame of one TLS record when
    /// `on` (the carrier is h2, see `TransportStream::caps_h2_uplink`).
    pub(super) fn set_h2_uplink_cap(&mut self, on: bool) {
        self.framer.set_h2_cap(if on {
            carrier_padding::h2_uplink_cap(self.framer.scheme())
        } else {
            None
        });
    }
}

impl WriteTransport for WsWriteTransport {
    async fn write_frame(&mut self, frame: Vec<u8>) -> Result<()> {
        let tx = self
            .data_tx
            .as_ref()
            .ok_or_else(|| anyhow!("writer already closed"))?;
        let frames = self.framer.frame(frame.into(), &mut rand::rng());
        for payload in frames {
            let bytes = payload.len();
            tx.send(Message::Binary(payload), bytes)
                .await
                .context("failed to send encrypted frame")?;
        }
        Ok(())
    }

    async fn write_frame_held(&mut self, frame: Vec<u8>) -> Result<()> {
        if !self.hold_header {
            return self.write_frame(frame).await;
        }
        let payload = frame_message(self.framer.scheme(), frame.into(), &mut rand::rng()).to_vec();
        let tx = self
            .held_tx
            .as_ref()
            .ok_or_else(|| anyhow!("writer already closed"))?;
        tx.send(payload)
            .await
            .map_err(|_| anyhow!("writer task stopped before the held header was queued"))
    }

    async fn close(&mut self) -> Result<()> {
        // Drop the sender — the writer task sees None from data_rx,
        // sends a WebSocket Close frame, and exits on its own.
        //
        // We intentionally do NOT take and await the writer task here.
        // The previous implementation called `writer_task.take()` +
        // `task.finish().await`, which moved the real JoinHandle out of
        // its AbortOnDrop wrapper.  If this future was then cancelled
        // (e.g. by a probe timeout), the handle was *detached* instead
        // of aborted — leaking the writer task, its SplitSink, the
        // underlying H2 connection, and the TCP socket.
        //
        // Leaving the AbortOnDrop in place guarantees that when this
        // TcpShadowsocksWriter is dropped, the writer task is aborted
        // regardless of how the caller exits (normal return, error, or
        // cancellation).
        drop(self.held_tx.take());
        drop(self.data_tx.take());
        Ok(())
    }

    fn supports_half_close(&self) -> bool {
        false
    }
}

#[doc(hidden)]
pub struct SocketWriteTransport {
    pub(super) writer: OwnedWriteHalf,
}

impl WriteTransport for SocketWriteTransport {
    async fn write_frame(&mut self, frame: Vec<u8>) -> Result<()> {
        self.writer
            .write_all(&frame)
            .await
            .context("failed to write encrypted frame to socket")
    }

    async fn close(&mut self) -> Result<()> {
        self.writer
            .shutdown()
            .await
            .context(TransportOperation::SocketShutdown)
    }

    fn supports_half_close(&self) -> bool {
        true
    }
}
