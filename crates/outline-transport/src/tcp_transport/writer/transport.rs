use crate::TransportOperation;
use crate::carrier_padding::{self, CarrierPadding};
use crate::{AbortOnDrop, TransportStream};
use anyhow::{Context, Result, anyhow};
use futures_util::SinkExt;
use futures_util::stream::SplitSink;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::protocol::Message;
use tracing::warn;

/// Buffer size for the WS writer's data channel. Sized to absorb
/// bursts up to ~4 MB at the 16 KB SS2022 chunk boundary so a long
/// upload doesn't stall on the per-channel cap; the underlying
/// transport (h2/h3 flow control or native WS) is the real bound.
const WS_DATA_CHANNEL_CAPACITY: usize = 256;
/// Control frames are tiny and rare (Ping/Pong/Close); a deeper
/// queue would only delay close propagation.
const WS_CTRL_CHANNEL_CAPACITY: usize = 8;
/// Far-future deadline the cover timer parks at when cover is disabled (the
/// `if cover.is_some()` select guard keeps the arm inert). One day is well
/// beyond any real session.
const COVER_DISABLED_PARK: std::time::Duration = std::time::Duration::from_secs(86_400);

pub(super) type WsSink = SplitSink<TransportStream, Message>;

#[allow(async_fn_in_trait)]
pub trait WriteTransport: Send + 'static {
    async fn write_frame(&mut self, frame: Vec<u8>) -> Result<()>;
    async fn close(&mut self) -> Result<()>;
    fn supports_half_close(&self) -> bool;
}

#[doc(hidden)]
pub struct WsWriteTransport {
    data_tx: Option<mpsc::Sender<Message>>,
    /// Kept alive for its `AbortOnDrop` — aborts the writer task on drop.
    _writer_task: Option<AbortOnDrop>,
    /// Process-wide carrier padding read at spawn. Disabled by default, in
    /// which case `write_frame` leaves the buffer untouched and the wire stays
    /// byte-for-byte identical to the unpadded carrier.
    padding: CarrierPadding,
}

impl WsWriteTransport {
    /// Build a WS write transport by spawning the multiplexing writer task and
    /// returning the control-channel sender alongside it.  The control sender
    /// must be passed to the paired reader so that Pong responses go through
    /// the priority channel.
    pub(super) fn spawn(sink: WsSink) -> (Self, mpsc::Sender<Message>) {
        let (data_tx, mut data_rx) = mpsc::channel::<Message>(WS_DATA_CHANNEL_CAPACITY);
        let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<Message>(WS_CTRL_CHANNEL_CAPACITY);
        let padding = carrier_padding::effective_carrier_padding();
        // Idle cover traffic on the uplink, when enabled. `None` keeps the
        // task on its legacy data/ctrl-only path. SS-over-WS and
        // SS-over-XHTTP (stream-one) both ride this writer, so cover covers
        // both; a cover frame is a `Binary` message (`real_len = 0`) that the
        // server's decoder drops transparently.
        let cover = padding.cover_enabled().then_some(padding);
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
        let writer_task = tokio::spawn(async move {
            let mut ws_sink = sink;
            let mut ctrl_open = true;
            // Cover timer: parked far in the future when cover is off (the
            // `if cover.is_some()` guard keeps the arm inert), armed to the
            // next jittered gap when on, and reset after every real write so
            // a cover frame fires only on a quiet uplink.
            let cover_sleep = tokio::time::sleep(COVER_DISABLED_PARK);
            tokio::pin!(cover_sleep);
            if let Some(c) = &cover {
                cover_sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + c.cover_gap());
            }
            loop {
                if ctrl_open {
                    tokio::select! {
                        biased;
                        msg = ctrl_rx.recv() => match msg {
                            Some(m) => {
                                if let Err(error) = ws_sink.send(m).await {
                                    warn!(%error, "ws writer ctrl send failed, terminating writer task");
                                    return;
                                }
                                arm_cover(cover_sleep.as_mut(), &cover);
                            }
                            None => ctrl_open = false,
                        },
                        msg = data_rx.recv() => match msg {
                            Some(m) => {
                                if let Err(error) = ws_sink.send(m).await {
                                    warn!(%error, "ws writer data send failed, terminating writer task");
                                    return;
                                }
                                arm_cover(cover_sleep.as_mut(), &cover);
                            }
                            None => { let _ = ws_sink.close().await; return; }
                        },
                        _ = cover_sleep.as_mut(), if cover.is_some() => {
                            if !send_cover(&mut ws_sink, &cover).await {
                                return;
                            }
                            arm_cover(cover_sleep.as_mut(), &cover);
                        },
                    }
                } else {
                    tokio::select! {
                        biased;
                        msg = data_rx.recv() => match msg {
                            Some(m) => {
                                if let Err(error) = ws_sink.send(m).await {
                                    warn!(%error, "ws writer data send failed, terminating writer task");
                                    return;
                                }
                                arm_cover(cover_sleep.as_mut(), &cover);
                            }
                            None => {
                                let _ = ws_sink.close().await;
                                return;
                            }
                        },
                        _ = cover_sleep.as_mut(), if cover.is_some() => {
                            if !send_cover(&mut ws_sink, &cover).await {
                                return;
                            }
                            arm_cover(cover_sleep.as_mut(), &cover);
                        },
                    }
                }
            }
        });
        (
            Self {
                data_tx: Some(data_tx),
                _writer_task: Some(AbortOnDrop::new(writer_task)),
                padding,
            },
            ctrl_tx,
        )
    }
}

/// Re-arms the cover timer to the next jittered idle gap. No-op when cover is
/// off (the timer stays parked and the select guard inert).
fn arm_cover(sleep: std::pin::Pin<&mut tokio::time::Sleep>, cover: &Option<CarrierPadding>) {
    if let Some(c) = cover {
        sleep.reset(tokio::time::Instant::now() + c.cover_gap());
    }
}

/// Sends one pad-only cover frame on the uplink. Returns `false` (signalling
/// the task to terminate) if the sink write fails, matching the data/ctrl
/// arms' error handling.
async fn send_cover(ws_sink: &mut WsSink, cover: &Option<CarrierPadding>) -> bool {
    let Some(c) = cover else {
        return true;
    };
    if let Err(error) = ws_sink.send(Message::Binary(c.cover_frame().into())).await {
        warn!(%error, "ws writer cover send failed, terminating writer task");
        return false;
    }
    true
}

impl WriteTransport for WsWriteTransport {
    async fn write_frame(&mut self, frame: Vec<u8>) -> Result<()> {
        let tx = self
            .data_tx
            .as_ref()
            .ok_or_else(|| anyhow!("writer already closed"))?;
        // When padding is on, wrap the encrypted SS bytes in length-delimited
        // padding frames so the WS/TLS record size no longer tracks the SS
        // payload size; otherwise hand the buffer through unchanged (wire stays
        // byte-for-byte identical). The server decodes symmetrically only when
        // its matching path also opted in (config-synchronised gate).
        let payload = if self.padding.scheme.is_enabled() {
            let mut out = Vec::with_capacity(frame.len() + 8);
            carrier_padding::frame_payload_into(
                self.padding.scheme,
                &frame,
                &mut rand::rng(),
                &mut out,
            );
            out
        } else {
            frame
        };
        tx.send(Message::Binary(payload.into()))
            .await
            .context("failed to send encrypted frame")
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
