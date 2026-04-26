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
use futures_util::{SinkExt, StreamExt, stream::SplitStream};
use tokio::sync::{Mutex, mpsc};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::protocol::{Message, frame::coding::CloseCode};
use tracing::debug;

use crate::frame_io::{DatagramChannel, FrameSink, FrameSource};
use crate::{AbortOnDrop, TransportOperation, WsClosed, WsTransportStream};

/// Default idle watchdog for WS transports. If no inbound frame arrives
/// within this window the reader tears the session down — the only way
/// to detect a silently-dead peer (mobile in tunnel, NAT rebind, ISP
/// black-hole) before the underlying TCP/QUIC keepalive fires, which
/// can take minutes or never. Mirrors the value already used by the
/// VLESS WS path and the SS WS reader.
pub(crate) const WS_READ_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

// ── Writer task ────────────────────────────────────────────────────────────

/// Spawn the WS writer task: drains `ctrl_rx` (Pings/Pongs/Close) with
/// priority over `data_rx` (Binary frames) into `ws_stream`. Returns the
/// task handle and the data/ctrl senders.
fn spawn_ws_writer(
    ws_stream: WsTransportStream,
) -> (AbortOnDrop, mpsc::Sender<Message>, mpsc::Sender<Message>, SplitStream<WsTransportStream>) {
    let (sink, stream) = ws_stream.split();
    let (data_tx, mut data_rx) = mpsc::channel::<Message>(64);
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<Message>(8);
    let task = tokio::spawn(async move {
        let mut ws_sink = sink;
        let mut ctrl_open = true;
        loop {
            if ctrl_open {
                tokio::select! {
                    biased;
                    msg = ctrl_rx.recv() => match msg {
                        Some(m) => { if ws_sink.send(m).await.is_err() { return; } }
                        None => ctrl_open = false,
                    },
                    msg = data_rx.recv() => match msg {
                        Some(Message::Close(_)) => {
                            let _ = ws_sink.close().await;
                            return;
                        }
                        Some(m) => { if ws_sink.send(m).await.is_err() { return; } }
                        None => { let _ = ws_sink.close().await; return; }
                    },
                }
            } else {
                match data_rx.recv().await {
                    Some(Message::Close(_)) => {
                        let _ = ws_sink.close().await;
                        return;
                    }
                    Some(m) => { if ws_sink.send(m).await.is_err() { return; } }
                    None => { let _ = ws_sink.close().await; return; }
                }
            }
        }
    });
    (AbortOnDrop::new(task), data_tx, ctrl_tx, stream)
}

fn spawn_keepalive(
    ctrl_tx: mpsc::Sender<Message>,
    interval: Duration,
) -> AbortOnDrop {
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
    data_tx: Option<mpsc::Sender<Message>>,
    _writer_task: AbortOnDrop,
    _keepalive_task: Option<AbortOnDrop>,
}

#[async_trait]
impl FrameSink for WsFrameSink {
    async fn send_frame(&mut self, data: Bytes) -> Result<()> {
        self.data_tx
            .as_ref()
            .ok_or_else(|| anyhow!("ws frame sink already closed"))?
            .send(Message::Binary(data))
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
    stream: SplitStream<WsTransportStream>,
    ctrl_tx: mpsc::Sender<Message>,
    idle_timeout: Option<Duration>,
    closed_cleanly: bool,
    diag_uplink: String,
    diag_target: String,
}

impl WsFrameSource {
    pub fn with_diag(mut self, uplink: impl Into<String>, target: impl Into<String>) -> Self {
        self.diag_uplink = uplink.into();
        self.diag_target = target.into();
        self
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
                }
                Some(Ok(m)) => m,
                Some(Err(e)) => return Err(e).context(TransportOperation::WebSocketRead),
            };
            match msg {
                Message::Binary(bytes) => return Ok(Some(bytes)),
                Message::Close(frame) => {
                    let try_again = frame
                        .as_ref()
                        .map(|f| f.code == CloseCode::Again)
                        .unwrap_or(false);
                    if !try_again {
                        self.closed_cleanly = true;
                    }
                    debug!(
                        target: "outline_ws_rust::session_death",
                        try_again,
                        frame = ?frame,
                        "ws frame source: received Close from upstream",
                    );
                    return Err(anyhow::Error::from(WsClosed));
                }
                Message::Ping(payload) => {
                    let _ = self.ctrl_tx.try_send(Message::Pong(payload));
                }
                Message::Pong(_) | Message::Frame(_) => {}
                Message::Text(_) => bail!("unexpected text websocket frame"),
            }
        }
    }

    fn closed_cleanly(&self) -> bool {
        self.closed_cleanly
    }
}

/// Build a paired [`WsFrameSink`] / [`WsFrameSource`] from a WS stream.
/// `idle_timeout` of `None` disables the read-side idle watchdog;
/// `keepalive` of `None` disables outbound Pings.
pub fn from_ws_frames(
    ws_stream: WsTransportStream,
    idle_timeout: Option<Duration>,
    keepalive: Option<Duration>,
) -> (WsFrameSink, WsFrameSource) {
    let (writer_task, data_tx, ctrl_tx, stream) = spawn_ws_writer(ws_stream);
    let keepalive_task = keepalive.map(|i| spawn_keepalive(ctrl_tx.clone(), i));
    let sink = WsFrameSink {
        data_tx: Some(data_tx),
        _writer_task: writer_task,
        _keepalive_task: keepalive_task,
    };
    let source = WsFrameSource {
        stream,
        ctrl_tx,
        idle_timeout,
        closed_cleanly: false,
        diag_uplink: String::new(),
        diag_target: String::new(),
    };
    (sink, source)
}

// ── Datagram pipe ──────────────────────────────────────────────────────────

/// WebSocket [`DatagramChannel`]. Each datagram is one `Message::Binary`.
/// Reads run in a background task draining into a bounded mpsc so the
/// receive side is `&self`-safe and can be polled from any task.
pub struct WsDatagramChannel {
    data_tx: mpsc::Sender<Message>,
    downlink_rx: Mutex<mpsc::Receiver<Result<Bytes>>>,
    _writer_task: AbortOnDrop,
    _reader_task: AbortOnDrop,
    _keepalive_task: Option<AbortOnDrop>,
}

#[async_trait]
impl DatagramChannel for WsDatagramChannel {
    async fn send_datagram(&self, data: Bytes) -> Result<()> {
        self.data_tx
            .send(Message::Binary(data))
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
        let _ = self.data_tx.send(Message::Close(None)).await;
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
    ws_stream: WsTransportStream,
    idle_timeout: Option<Duration>,
    keepalive: Option<Duration>,
) -> WsDatagramChannel {
    let (writer_task, data_tx, ctrl_tx, mut stream) = spawn_ws_writer(ws_stream);
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
                    }
                    Ok(item) => item,
                },
                None => stream.next().await,
            };
            let msg = match next {
                None => return,
                Some(Ok(m)) => m,
                Some(Err(e)) => {
                    let err: anyhow::Result<()> =
                        Err(e).context(TransportOperation::WebSocketRead);
                    let _ = downlink_tx.send(Err(err.unwrap_err())).await;
                    return;
                }
            };
            match msg {
                Message::Binary(bytes) => {
                    if downlink_tx.send(Ok(bytes)).await.is_err() {
                        return;
                    }
                }
                Message::Close(_) => {
                    let _ = downlink_tx.send(Err(anyhow::Error::from(WsClosed))).await;
                    return;
                }
                Message::Ping(payload) => {
                    let _ = reader_ctrl_tx.try_send(Message::Pong(payload));
                }
                Message::Pong(_) | Message::Frame(_) => {}
                Message::Text(_) => {
                    let _ = downlink_tx
                        .send(Err(anyhow!("unexpected text websocket frame")))
                        .await;
                    return;
                }
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
