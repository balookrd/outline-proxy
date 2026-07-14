//! WebSocket implementations of [`FrameSink`] / [`FrameSource`] /
//! [`DatagramChannel`].
//!
//! Construction is paired so the source can route inbound `Ping` payloads
//! back through the sink's writer task as `Pong` replies (the WS spec
//! requires same-payload echo). Three entry points:
//!
//!   * [`from_ws_frames`] — byte-chunk pipe (VLESS TCP).
//!   * [`from_ws_datagrams`] — packet pipe (VLESS UDP, SS UDP).
//!
//! The writer task drains a `(ctrl, data)` mpsc pair into the WS sink with
//! `biased` select on ctrl for Pong-priority scheduling. Once the data
//! channel is closed (sender dropped) the writer issues a clean Close
//! frame and exits. The reader task is implicit — we keep the
//! `SplitStream` inline in the source so `recv_frame` is just a
//! `stream.next()` poll, with timeout / Ping / Close handling baked in.

use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{
    SinkExt, StreamExt,
    stream::{SplitSink, SplitStream},
};
use outline_wire::padding::PaddingDecoder;
use tokio::sync::{Mutex, mpsc};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::protocol::{Message, frame::coding::CloseCode};
use tracing::{debug, warn};

use crate::carrier_padding::{self, CarrierPadding};
use crate::carrier_queue::{self, BudgetedSender};

/// Pings/Pongs/Close are tiny and rare; a deeper queue would only
/// delay close propagation.
const WS_CTRL_CHANNEL_CAPACITY: usize = 8;
/// Far-future deadline the cover timer parks at when cover is disabled (the
/// `if cover.is_some()` select guard keeps the arm inert). One day is well
/// beyond any real session.
const COVER_DISABLED_PARK: Duration = Duration::from_secs(86_400);

use crate::frame_io::{DatagramChannel, FrameSink, FrameSource};
use crate::{AbortOnDrop, TransportOperation, TransportStream, TryAgain, WsClosed};

/// Default idle watchdog for WS transports. If no inbound frame arrives
/// within this window the reader tears the session down — the only way
/// to detect a silently-dead peer (mobile in tunnel, NAT rebind, ISP
/// black-hole) before the underlying TCP/QUIC keepalive fires, which
/// can take minutes or never. Mirrors the value already used by the
/// VLESS WS path and the SS WS reader.
pub(crate) const WS_READ_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Carrier-aware liveness knobs `(read_idle_timeout, keepalive)` for a
/// WebSocket-over-* session.
///
/// On the H3 carrier the WS stream rides a QUIC connection that already runs
/// its own keep-alive (10 s) and `max_idle_timeout` liveness check, so both
/// the WS read-idle watchdog and the client keepalive Ping are redundant —
/// and the Ping is unsafe: the server cannot deliver a reactive Pong on a
/// quiet H3 stream without risking a connection-level `H3_INTERNAL_ERROR`
/// that tears down every multiplexed stream on the QUIC connection, so
/// proving liveness from inbound WS frames would spuriously kill a
/// healthy-but-quiet session. Both are disabled on H3 (we trust QUIC). On
/// h1/h2 there is no shared QUIC keep-alive underneath, so the configured
/// watchdog and keepalive stay. Mirrors the server, which sends no keepalive
/// Ping on H3.
pub(crate) fn carrier_liveness(
    is_h3: bool,
    keepalive_interval: Option<Duration>,
) -> (Option<Duration>, Option<Duration>) {
    if is_h3 {
        (None, None)
    } else {
        (Some(WS_READ_IDLE_TIMEOUT), keepalive_interval)
    }
}

// ── Writer task ────────────────────────────────────────────────────────────

/// Spawn the WS writer task: drains `ctrl_rx` (Pings/Pongs/Close) with
/// priority over `data_rx` (Binary frames) into `ws_stream`. Returns the
/// task handle and the data/ctrl senders.
fn spawn_ws_writer(
    ws_stream: TransportStream,
    cover: Option<CarrierPadding>,
) -> (
    AbortOnDrop,
    BudgetedSender<Message>,
    mpsc::Sender<Message>,
    SplitStream<TransportStream>,
) {
    let (sink, stream) = ws_stream.split();
    // Byte-budgeted data queue: VLESS coalesces up to `FRAME_SOFT_CAP` per
    // frame, datagram carriers put one packet per frame — bounding by bytes
    // fits both without throttling either. Control frames stay unbudgeted.
    let (data_tx, mut data_rx) = carrier_queue::channel::<Message>();
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<Message>(WS_CTRL_CHANNEL_CAPACITY);
    let task = tokio::spawn(async move {
        let mut ws_sink = sink;
        let mut ctrl_open = true;
        // Idle cover timer. Parked far in the future when cover is off (the
        // `if cover.is_some()` guard keeps the arm inert); when on, armed to
        // the next jittered gap and reset after every real write so a cover
        // frame fires only on a genuinely quiet uplink — never interleaved
        // with live traffic. A cover frame is a `Binary` message
        // (`real_len = 0`), so it is H3-safe (unlike a Ping it cannot escalate
        // to `H3_INTERNAL_ERROR`) and the server's decoder drops it. Only the
        // VLESS-TCP `from_ws_frames` path passes `Some`; the datagram path
        // passes `None` (SS-UDP / VLESS-UDP are not stream-padded here).
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
                                warn!(%error, "ws frame writer ctrl send failed, terminating writer task");
                                return;
                            }
                            arm_cover(cover_sleep.as_mut(), &cover);
                        }
                        None => ctrl_open = false,
                    },
                    msg = data_rx.recv() => match msg {
                        Some(queued) => {
                            // The byte permit lives until the frame reaches the
                            // sink — see `carrier_queue`.
                            let (m, permit) = queued.into_parts();
                            if matches!(m, Message::Close(_)) {
                                let _ = ws_sink.close().await;
                                return;
                            }
                            if let Err(error) = ws_sink.send(m).await {
                                warn!(%error, "ws frame writer data send failed, terminating writer task");
                                return;
                            }
                            drop(permit);
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
                        Some(queued) => {
                            let (m, permit) = queued.into_parts();
                            if matches!(m, Message::Close(_)) {
                                let _ = ws_sink.close().await;
                                return;
                            }
                            if let Err(error) = ws_sink.send(m).await {
                                warn!(%error, "ws frame writer data send failed, terminating writer task");
                                return;
                            }
                            drop(permit);
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
            }
        }
    });
    (AbortOnDrop::new(task), data_tx, ctrl_tx, stream)
}

/// Re-arms the cover timer to the next jittered idle gap. No-op when cover is
/// off (the timer stays parked and the select guard inert). Mirrors the SS WS
/// writer's `arm_cover`.
fn arm_cover(sleep: std::pin::Pin<&mut tokio::time::Sleep>, cover: &Option<CarrierPadding>) {
    if let Some(c) = cover {
        sleep.reset(tokio::time::Instant::now() + c.cover_gap());
    }
}

/// Sends one pad-only cover frame on the uplink. Returns `false` (signalling
/// the writer task to terminate) if the sink write fails, matching the
/// data/ctrl arms' error handling.
async fn send_cover(
    ws_sink: &mut SplitSink<TransportStream, Message>,
    cover: &Option<CarrierPadding>,
) -> bool {
    let Some(c) = cover else {
        return true;
    };
    if let Err(error) = ws_sink.send(Message::Binary(c.cover_frame().into())).await {
        warn!(%error, "ws frame writer cover send failed, terminating writer task");
        return false;
    }
    true
}

fn spawn_keepalive(ctrl_tx: mpsc::Sender<Message>, interval: Duration) -> AbortOnDrop {
    AbortOnDrop::new(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // skip the immediate tick
        loop {
            ticker.tick().await;
            if ctrl_tx.send(Message::Ping(vec![].into())).await.is_err() {
                break;
            }
        }
    }))
}

// ── Frame (byte-chunk) pipe ────────────────────────────────────────────────

/// WebSocket [`FrameSink`]. Wraps each `send_frame` payload in a single
/// `Message::Binary` so VLESS request-header / chunk boundaries survive.
pub struct WsFrameSink {
    data_tx: Option<BudgetedSender<Message>>,
    _writer_task: AbortOnDrop,
    _keepalive_task: Option<AbortOnDrop>,
    /// Process-wide carrier padding read at construction. Disabled by default,
    /// in which case `send_frame` leaves the bytes untouched and the wire stays
    /// byte-for-byte identical to the unpadded carrier.
    padding: CarrierPadding,
}

#[async_trait]
impl FrameSink for WsFrameSink {
    async fn send_frame(&mut self, data: Bytes) -> Result<()> {
        let tx = self
            .data_tx
            .as_ref()
            .ok_or_else(|| anyhow!("ws frame sink already closed"))?;
        // When padding is on, wrap the VLESS frame bytes in length-delimited
        // padding frames so the WS/TLS record size no longer tracks the VLESS
        // payload size; otherwise hand the bytes through unchanged (wire stays
        // byte-for-byte identical). The server decodes symmetrically only when
        // its matching path also opted in (config-synchronised gate).
        let payload: Bytes = if self.padding.scheme.is_enabled() {
            let mut out = Vec::with_capacity(data.len() + 8);
            carrier_padding::frame_payload_into(
                self.padding.scheme,
                &data,
                &mut rand::rng(),
                &mut out,
            );
            out.into()
        } else {
            data
        };
        let bytes = payload.len();
        tx.send(Message::Binary(payload), bytes)
            .await
            .context(TransportOperation::WebSocketSend)
    }

    async fn close(&mut self) -> Result<()> {
        // Drop the sender; the writer task observes this via `recv() == None`
        // and emits a clean Close frame before exiting.
        drop(self.data_tx.take());
        Ok(())
    }
}

/// WebSocket [`FrameSource`]. Strips Pings (auto-replied via the paired
/// sink's ctrl channel), surfaces Close as a clean EOF (`Ok(None)`), and
/// fails reads idle longer than `idle_timeout`.
pub struct WsFrameSource {
    stream: SplitStream<TransportStream>,
    ctrl_tx: mpsc::Sender<Message>,
    idle_timeout: Option<Duration>,
    closed_cleanly: bool,
    diag_uplink: String,
    diag_target: String,
    /// `Some` when carrier padding is on: each inbound binary frame is run
    /// through the streaming decoder (which strips pad and yields the original
    /// VLESS bytes) instead of surfaced verbatim. `None` keeps the plain path.
    /// State is held across frames because a padding frame may span multiple
    /// WS / h2 / h3 DATA frames.
    padding: Option<PaddingDecoder>,
    /// Reaction for a recognised carrier control signal (set by the dispatch
    /// layer). `None` keeps the source inert. Only meaningful when `padding`
    /// is `Some`, since control signals ride cover frames.
    throttle: Option<crate::ThrottleSignalHandle>,
    /// Fires the throttle handler at most once per carrier: one notice is
    /// enough to penalise the uplink, and the server rate-limits anyway.
    throttle_fired: bool,
}

impl WsFrameSource {
    pub fn with_diag(mut self, uplink: impl Into<String>, target: impl Into<String>) -> Self {
        self.diag_uplink = uplink.into();
        self.diag_target = target.into();
        self
    }

    /// Invokes the throttle handler for `signal`, once per carrier.
    fn fire_throttle(&mut self, signal: outline_wire::padding::ControlSignal) {
        if self.throttle_fired {
            return;
        }
        if let Some(handle) = &self.throttle {
            handle(signal);
            self.throttle_fired = true;
        }
    }
}

#[async_trait]
impl FrameSource for WsFrameSource {
    async fn recv_frame(&mut self) -> Result<Option<Bytes>> {
        loop {
            let next = match self.idle_timeout {
                Some(d) => match timeout(d, self.stream.next()).await {
                    Err(_) => bail!(
                        "ws upstream read idle for {}s on uplink {} target {}",
                        d.as_secs(),
                        self.diag_uplink,
                        self.diag_target,
                    ),
                    Ok(item) => item,
                },
                None => self.stream.next().await,
            };
            let msg = match next {
                None => {
                    self.closed_cleanly = true;
                    return Ok(None);
                },
                Some(Ok(m)) => m,
                Some(Err(e)) => return Err(e).context(TransportOperation::WebSocketRead),
            };
            match msg {
                Message::Binary(bytes) => match self.padding.as_mut() {
                    // Padding on: strip the framing, recover the VLESS bytes.
                    // A cover frame (real_len = 0) yields nothing — keep
                    // reading rather than surfacing an empty chunk to the
                    // VLESS parser. A padding frame may span multiple WS
                    // frames, so the decoder state lives across calls. A cover
                    // frame may also carry an out-of-band control signal, which
                    // the decoder surfaces via `take_control`.
                    Some(decoder) => {
                        let mut out = Vec::with_capacity(bytes.len());
                        decoder.push(&bytes, &mut out);
                        let signal = decoder.take_control();
                        // `decoder`'s borrow of `self.padding` ends here (NLL),
                        // freeing `self` for the throttle handler below.
                        if let Some(sig) = signal {
                            self.fire_throttle(sig);
                        }
                        if out.is_empty() {
                            continue;
                        }
                        return Ok(Some(Bytes::from(out)));
                    },
                    None => return Ok(Some(bytes)),
                },
                Message::Close(frame) => {
                    let try_again =
                        frame.as_ref().map(|f| f.code == CloseCode::Again).unwrap_or(false);
                    if !try_again {
                        self.closed_cleanly = true;
                    }
                    debug!(
                        target: "outline_ws_rust::session_death",
                        try_again,
                        frame = ?frame,
                        "ws frame source: received Close from upstream",
                    );
                    if try_again {
                        // Tag a per-target 1013 so the uplink-health classifier
                        // can retry the flow without stamping an uplink cooldown.
                        return Err(anyhow::Error::from(WsClosed).context(TryAgain));
                    }
                    return Err(anyhow::Error::from(WsClosed));
                },
                Message::Ping(payload) => {
                    let _ = self.ctrl_tx.try_send(Message::Pong(payload));
                },
                Message::Pong(_) | Message::Frame(_) => {},
                Message::Text(_) => bail!("unexpected text websocket frame"),
            }
        }
    }

    fn closed_cleanly(&self) -> bool {
        self.closed_cleanly
    }

    fn set_throttle_handle(&mut self, handle: crate::ThrottleSignalHandle) {
        self.throttle = Some(handle);
    }
}

/// Build a paired [`WsFrameSink`] / [`WsFrameSource`] from a WS stream.
/// `idle_timeout` of `None` disables the read-side idle watchdog;
/// `keepalive` of `None` disables outbound Pings.
pub fn from_ws_frames(
    ws_stream: TransportStream,
    idle_timeout: Option<Duration>,
    keepalive: Option<Duration>,
) -> (WsFrameSink, WsFrameSource) {
    // Process-wide carrier padding. Disabled by default (the wire stays
    // byte-for-byte identical); when on, the sink frames every VLESS write,
    // the source decodes inbound frames, and the writer emits idle cover
    // frames. VLESS-TCP-over-WS / -XHTTP ride this byte-chunk pipe; raw-QUIC
    // (`open_quic_frame_pair`) and the datagram pipe (`from_ws_datagrams`,
    // used by SS-UDP / VLESS-UDP) do not.
    let padding = carrier_padding::effective_carrier_padding();
    let cover = padding.cover_enabled().then_some(padding);
    let (writer_task, data_tx, ctrl_tx, stream) = spawn_ws_writer(ws_stream, cover);
    let keepalive_task = keepalive.map(|i| spawn_keepalive(ctrl_tx.clone(), i));
    let sink = WsFrameSink {
        data_tx: Some(data_tx),
        _writer_task: writer_task,
        _keepalive_task: keepalive_task,
        padding,
    };
    let source = WsFrameSource {
        stream,
        ctrl_tx,
        idle_timeout,
        closed_cleanly: false,
        diag_uplink: String::new(),
        diag_target: String::new(),
        padding: padding.scheme.is_enabled().then(PaddingDecoder::new),
        throttle: None,
        throttle_fired: false,
    };
    (sink, source)
}

// ── Datagram pipe ──────────────────────────────────────────────────────────

/// WebSocket [`DatagramChannel`]. Each datagram is one `Message::Binary`.
/// Reads run in a background task draining into a bounded mpsc so the
/// receive side is `&self`-safe and can be polled from any task.
pub struct WsDatagramChannel {
    data_tx: BudgetedSender<Message>,
    downlink_rx: Mutex<mpsc::Receiver<Result<Bytes>>>,
    _writer_task: AbortOnDrop,
    _reader_task: AbortOnDrop,
    _keepalive_task: Option<AbortOnDrop>,
}

#[async_trait]
impl DatagramChannel for WsDatagramChannel {
    async fn send_datagram(&self, data: Bytes) -> Result<()> {
        let bytes = data.len();
        self.data_tx
            .send(Message::Binary(data), bytes)
            .await
            .context(TransportOperation::WebSocketSend)
    }

    async fn recv_datagram(&self) -> Result<Option<Bytes>> {
        let mut rx = self.downlink_rx.lock().await;
        match rx.recv().await {
            None => Ok(None),
            Some(Ok(b)) => Ok(Some(b)),
            Some(Err(e)) => Err(e),
        }
    }

    async fn close(&self) {
        // Unbudgeted: a Close must propagate even when the data queue is full.
        let _ = self.data_tx.send_control(Message::Close(None)).await;
    }
}

/// Build a [`WsDatagramChannel`] from a WS stream. Spawns the writer task
/// (ctrl-priority biased select on Pings) and a reader task that forwards
/// each `Message::Binary` payload as a single datagram.
///
/// `idle_timeout` of `Some(d)` tears the session down if no inbound frame
/// (Binary, Ping, Pong, Close) arrives within `d` — silently-dead servers
/// (mobile in tunnel, NAT rebind, ISP black-hole) otherwise hold the WS
/// reader on `stream.next()` indefinitely, pinning the underlying
/// TCP/QUIC socket and 64 KiB stream buffers. `None` disables the
/// watchdog (used in tests). `keepalive` of `None` disables outbound
/// Pings.
pub fn from_ws_datagrams(
    ws_stream: TransportStream,
    idle_timeout: Option<Duration>,
    keepalive: Option<Duration>,
) -> WsDatagramChannel {
    // No cover on the datagram pipe: SS-UDP stays plain, and VLESS-UDP is
    // padded per-datagram inside `VlessUdpTransport`, not here.
    let (writer_task, data_tx, ctrl_tx, mut stream) = spawn_ws_writer(ws_stream, None);
    let keepalive_task = keepalive.map(|i| spawn_keepalive(ctrl_tx.clone(), i));
    let (downlink_tx, downlink_rx) = mpsc::channel::<Result<Bytes>>(64);
    let reader_ctrl_tx = ctrl_tx.clone();
    let reader_task = tokio::spawn(async move {
        loop {
            let next = match idle_timeout {
                Some(d) => match timeout(d, stream.next()).await {
                    Err(_) => {
                        let _ = downlink_tx
                            .send(Err(anyhow!(
                                "ws upstream read idle for {}s on datagram channel",
                                d.as_secs(),
                            )))
                            .await;
                        return;
                    },
                    Ok(item) => item,
                },
                None => stream.next().await,
            };
            let msg = match next {
                None => return,
                Some(Ok(m)) => m,
                Some(Err(e)) => {
                    let err: anyhow::Result<()> = Err(e).context(TransportOperation::WebSocketRead);
                    let _ = downlink_tx.send(Err(err.unwrap_err())).await;
                    return;
                },
            };
            match msg {
                Message::Binary(bytes) => {
                    if downlink_tx.send(Ok(bytes)).await.is_err() {
                        return;
                    }
                },
                Message::Close(_) => {
                    let _ = downlink_tx.send(Err(anyhow::Error::from(WsClosed))).await;
                    return;
                },
                Message::Ping(payload) => {
                    let _ = reader_ctrl_tx.try_send(Message::Pong(payload));
                },
                Message::Pong(_) | Message::Frame(_) => {},
                Message::Text(_) => {
                    let _ = downlink_tx
                        .send(Err(anyhow!("unexpected text websocket frame")))
                        .await;
                    return;
                },
            }
        }
    });
    WsDatagramChannel {
        data_tx,
        downlink_rx: Mutex::new(downlink_rx),
        _writer_task: writer_task,
        _reader_task: AbortOnDrop::new(reader_task),
        _keepalive_task: keepalive_task,
    }
}

#[cfg(test)]
#[path = "tests/frame_io_ws.rs"]
mod tests;
