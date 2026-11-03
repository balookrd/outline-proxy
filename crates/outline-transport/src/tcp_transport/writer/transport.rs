use crate::TransportOperation;
use crate::carrier_padding::{self, CarrierPadding};
use crate::carrier_queue::{self, BudgetedSender};
use crate::ws_writer_diag::{KIND_COVER, KIND_CTRL, KIND_DATA, WRITER_SS, send_or_report};
use crate::{AbortOnDrop, TransportStream};
use anyhow::{Context, Result, anyhow};
use futures_util::SinkExt;
use futures_util::stream::SplitSink;
use outline_wire::early_shape::{EarlyShaper, ShapeDirection};
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::error::Error as WsError;
use tokio_tungstenite::tungstenite::protocol::Message;

/// Control frames are tiny and rare (Ping/Pong/Close); a deeper
/// queue would only delay close propagation.
const WS_CTRL_CHANNEL_CAPACITY: usize = 8;
/// How long the writer holds the SS2022 request header waiting for the first
/// data message, so both leave in one WS message instead of a lone 130-141 B
/// record ahead of the ClientHello. Server-speaks-first protocols simply see
/// the header after this delay.
pub(crate) const SS2022_HEADER_HOLD: std::time::Duration = std::time::Duration::from_millis(50);
/// Far-future deadline the cover timer parks at when cover is disabled (the
/// `if cover.is_some()` select guard keeps the arm inert). One day is well
/// beyond any real session.
const COVER_DISABLED_PARK: std::time::Duration = std::time::Duration::from_secs(86_400);

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
    /// Process-wide carrier padding read at spawn. Disabled by default, in
    /// which case `write_frame` leaves the buffer untouched and the wire stays
    /// byte-for-byte identical to the unpadded carrier.
    padding: CarrierPadding,
    /// Early-session shaper (h1/h2 carriers, padded or not): cuts the first
    /// large frames into browser-sized messages. `None` otherwise.
    shaper: Option<EarlyShaper>,
}

impl WsWriteTransport {
    /// Build a WS write transport by spawning the multiplexing writer task and
    /// returning the control-channel sender alongside it.  The control sender
    /// must be passed to the paired reader so that Pong responses go through
    /// the priority channel.
    pub(super) fn spawn<S>(sink: S, shape: bool) -> (Self, mpsc::Sender<Message>)
    where
        S: futures_util::Sink<Message, Error = WsError> + Unpin + Send + 'static,
    {
        // Data frames are bounded by bytes (the writer coalesces up to
        // `FRAME_SOFT_CAP` per message); control frames keep their own tiny
        // unbudgeted queue so a Close never waits behind a congested uplink.
        let (data_tx, mut data_rx) = carrier_queue::channel::<Message>();
        let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<Message>(WS_CTRL_CHANNEL_CAPACITY);
        let (held_tx, mut held_rx) = mpsc::channel::<Vec<u8>>(1);
        let padding = carrier_padding::effective_carrier_padding();
        let shaper = shape.then(|| {
            EarlyShaper::new(
                ShapeDirection::ClientToServer,
                padding.scheme.is_enabled(),
                &mut carrier_padding::draw_in(&mut rand::rng()),
            )
        });
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
            let mut held_open = true;
            // SS2022 request header waiting for the first data message so both
            // leave in one WS message (see `write_frame_held`).
            let mut held: Option<Vec<u8>> = None;
            let hold_sleep = tokio::time::sleep(COVER_DISABLED_PARK);
            tokio::pin!(hold_sleep);
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
                tokio::select! {
                    biased;
                    // First, so a header queued together with a control message
                    // is always in `held` (and flushed) before that message.
                    h = held_rx.recv(), if held_open => match h {
                        Some(h) => match &mut held {
                            Some(existing) => existing.extend_from_slice(&h),
                            None => {
                                held = Some(h);
                                hold_sleep
                                    .as_mut()
                                    .reset(tokio::time::Instant::now() + SS2022_HEADER_HOLD);
                            }
                        },
                        None => held_open = false,
                    },
                    msg = ctrl_rx.recv(), if ctrl_open => match msg {
                        Some(m) => {
                            take_pending_held(&mut held_rx, &mut held);
                            if !flush_held(&mut ws_sink, &mut held).await {
                                return;
                            }
                            if !send_or_report(&mut ws_sink, m, WRITER_SS, KIND_CTRL).await {
                                return;
                            }
                            arm_cover(cover_sleep.as_mut(), &cover);
                        }
                        None => ctrl_open = false,
                    },
                    msg = data_rx.recv() => match msg {
                        Some(queued) => {
                            // The byte permit is released only once the frame
                            // has reached the sink: freeing it at dequeue would
                            // let the queue refill while these bytes are still
                            // buffered downstream.
                            let (m, permit) = queued.into_parts();
                            // Ordering invariant: the producer finishes the
                            // `held_tx` send before it sends on `data_tx`, so a
                            // header preceding this message is already buffered
                            // in `held_rx` even if the select did not see it.
                            take_pending_held(&mut held_rx, &mut held);
                            let m = match (held.take(), m) {
                                (Some(mut h), Message::Binary(p)) => {
                                    h.extend_from_slice(&p);
                                    Message::Binary(h.into())
                                }
                                (Some(h), m) => {
                                    if !send_or_report(
                                        &mut ws_sink,
                                        Message::Binary(h.into()),
                                        WRITER_SS,
                                        KIND_DATA,
                                    )
                                    .await
                                    {
                                        return;
                                    }
                                    m
                                }
                                (None, m) => m,
                            };
                            if !send_or_report(&mut ws_sink, m, WRITER_SS, KIND_DATA).await {
                                return;
                            }
                            drop(permit);
                            arm_cover(cover_sleep.as_mut(), &cover);
                        }
                        None => {
                            // Same invariant: a header sent before close is buffered.
                            take_pending_held(&mut held_rx, &mut held);
                            let _ = flush_held(&mut ws_sink, &mut held).await;
                            let _ = ws_sink.close().await;
                            return;
                        }
                    },
                    _ = hold_sleep.as_mut(), if held.is_some() => {
                        if !flush_held(&mut ws_sink, &mut held).await {
                            return;
                        }
                        arm_cover(cover_sleep.as_mut(), &cover);
                    },
                    // Never ahead of a held header: the hold timer flushes it first.
                    _ = cover_sleep.as_mut(), if cover.is_some() && held.is_none() => {
                        if !send_cover(&mut ws_sink, &cover).await {
                            return;
                        }
                        arm_cover(cover_sleep.as_mut(), &cover);
                    },
                }
            }
        });
        (
            Self {
                data_tx: Some(data_tx),
                held_tx: Some(held_tx),
                _writer_task: Some(AbortOnDrop::new(writer_task)),
                padding,
                shaper,
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

/// Moves any header already buffered in `held_rx` into `held`.
fn take_pending_held(held_rx: &mut mpsc::Receiver<Vec<u8>>, held: &mut Option<Vec<u8>>) {
    while let Ok(h) = held_rx.try_recv() {
        held.get_or_insert_with(Vec::new).extend_from_slice(&h);
    }
}

/// Sends the held SS2022 header (if any) as its own message.
async fn flush_held<S>(ws_sink: &mut S, held: &mut Option<Vec<u8>>) -> bool
where
    S: futures_util::Sink<Message, Error = WsError> + Unpin,
{
    match held.take() {
        Some(h) => send_or_report(ws_sink, Message::Binary(h.into()), WRITER_SS, KIND_DATA).await,
        None => true,
    }
}

/// Sends one pad-only cover frame on the uplink. Returns `false` (signalling
/// the task to terminate) if the sink write fails, matching the data/ctrl
/// arms' error handling.
async fn send_cover<S>(ws_sink: &mut S, cover: &Option<CarrierPadding>) -> bool
where
    S: futures_util::Sink<Message, Error = WsError> + Unpin,
{
    let Some(c) = cover else {
        return true;
    };
    let frame = Message::Binary(c.cover_frame().into());
    send_or_report(ws_sink, frame, WRITER_SS, KIND_COVER).await
}

impl WsWriteTransport {
    /// When padding is on, wraps the encrypted SS bytes in length-delimited
    /// padding frames so the WS/TLS record size no longer tracks the SS payload
    /// size; otherwise hands the buffer through unchanged (wire stays
    /// byte-for-byte identical). The server decodes symmetrically only when its
    /// matching path also opted in (config-synchronised gate).
    fn pad(&self, frame: Vec<u8>) -> Vec<u8> {
        if self.padding.scheme.is_enabled() {
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
        }
    }
}

impl WriteTransport for WsWriteTransport {
    async fn write_frame(&mut self, frame: Vec<u8>) -> Result<()> {
        let tx = self
            .data_tx
            .as_ref()
            .ok_or_else(|| anyhow!("writer already closed"))?;
        if let Some(shaper) = self.shaper.as_mut().filter(|s| s.is_active()) {
            let msgs = carrier_padding::shaped_messages(
                self.padding.scheme,
                shaper,
                &frame,
                &mut rand::rng(),
            );
            for payload in msgs {
                let bytes = payload.len();
                tx.send(Message::Binary(payload.into()), bytes)
                    .await
                    .context("failed to send encrypted frame")?;
            }
            return Ok(());
        }
        let payload = self.pad(frame);
        let bytes = payload.len();
        tx.send(Message::Binary(payload.into()), bytes)
            .await
            .context("failed to send encrypted frame")
    }

    async fn write_frame_held(&mut self, frame: Vec<u8>) -> Result<()> {
        let payload = self.pad(frame);
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
