//! VLESS client primitives (iteration 1: WS transport only, TCP + UDP,
//! no Mux, no flow/xtls).
//!
//! Wire format — request (client → server), emitted once on the first
//! WebSocket binary frame:
//!
//! ```text
//!   version(1) = 0x00
//!   uuid(16)
//!   addons_len(1) = 0x00
//!   command(1): TCP=0x01, UDP=0x02
//!   port(2 BE)
//!   atyp(1): 0x01=IPv4, 0x02=Domain(len+bytes), 0x03=IPv6
//!   addr(...)
//! ```
//!
//! For TCP the header may be immediately followed by the first chunk of
//! client payload in the same frame; subsequent frames carry raw bytes.
//!
//! For UDP the header is followed by `len(2 BE) || payload` repeated per
//! datagram; subsequent frames carry the same length-prefixed stream.
//!
//! Response (server → client) — first binary frame begins with
//! `[version=0x00, addons_len=0x00]`, followed by raw TCP bytes or the same
//! length-prefixed UDP stream.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bytes::{BufMut, Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use socks5_proto::TargetAddr;
use tokio::sync::{Mutex, mpsc, watch};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::protocol::{Message, frame::coding::CloseCode};
use tracing::debug;
use url::Url;

use crate::{
    AbortOnDrop, DnsCache, TransportOperation, UpstreamTransportGuard, WsClosed,
    WsTransportStream, config::WsTransportMode, connect_websocket_with_source,
};

const VLESS_VERSION: u8 = 0x00;
const VLESS_CMD_TCP: u8 = 0x01;
const VLESS_CMD_UDP: u8 = 0x02;

const VLESS_ATYP_IPV4: u8 = 0x01;
const VLESS_ATYP_DOMAIN: u8 = 0x02;
const VLESS_ATYP_IPV6: u8 = 0x03;

const MAX_VLESS_UDP_PAYLOAD: usize = 64 * 1024;

/// Mirror of the idle timeout used by the SS WebSocket reader. Matches the
/// SOCKS idle-watcher so both defences fire at the same time when the
/// upstream is truly dead.
const WS_READ_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Parse a VLESS UUID in hex/dashed form into 16 raw bytes.
pub fn parse_uuid(input: &str) -> Result<[u8; 16]> {
    let mut hex = [0_u8; 32];
    let mut len = 0;
    for byte in input.bytes() {
        if byte == b'-' {
            continue;
        }
        if len == hex.len() || !byte.is_ascii_hexdigit() {
            bail!("invalid vless uuid: {input}");
        }
        hex[len] = byte;
        len += 1;
    }
    if len != hex.len() {
        bail!("invalid vless uuid length: {input}");
    }
    let mut out = [0_u8; 16];
    for i in 0..16 {
        out[i] = (hex_val(hex[i * 2])? << 4) | hex_val(hex[i * 2 + 1])?;
    }
    Ok(out)
}

fn hex_val(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => bail!("invalid vless uuid hex: {byte}"),
    }
}

fn build_request_header(uuid: &[u8; 16], command: u8, target: &TargetAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 16 + 1 + 1 + 2 + 1 + 256);
    out.push(VLESS_VERSION);
    out.extend_from_slice(uuid);
    out.push(0x00); // addons_len
    out.push(command);
    match target {
        TargetAddr::IpV4(addr, port) => {
            out.extend_from_slice(&port.to_be_bytes());
            out.push(VLESS_ATYP_IPV4);
            out.extend_from_slice(&addr.octets());
        },
        TargetAddr::IpV6(addr, port) => {
            out.extend_from_slice(&port.to_be_bytes());
            out.push(VLESS_ATYP_IPV6);
            out.extend_from_slice(&addr.octets());
        },
        TargetAddr::Domain(host, port) => {
            out.extend_from_slice(&port.to_be_bytes());
            out.push(VLESS_ATYP_DOMAIN);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
        },
    }
    out
}

// ── TCP writer ─────────────────────────────────────────────────────────────

/// VLESS TCP writer over a WebSocket sink. Emits the request header on the
/// first `send_chunk` concatenated with the payload into a single binary
/// frame; subsequent frames are raw client bytes.
pub struct VlessTcpWriter {
    data_tx: Option<mpsc::Sender<Message>>,
    _writer_task: Option<AbortOnDrop>,
    pending_header: Option<Vec<u8>>,
    _lifetime: Arc<UpstreamTransportGuard>,
}

impl VlessTcpWriter {
    pub fn connect(
        sink: futures_util::stream::SplitSink<WsTransportStream, Message>,
        uuid: &[u8; 16],
        target: &TargetAddr,
        lifetime: Arc<UpstreamTransportGuard>,
    ) -> (Self, mpsc::Sender<Message>) {
        let (data_tx, mut data_rx) = mpsc::channel::<Message>(64);
        let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<Message>(8);
        let writer_task = tokio::spawn(async move {
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
                            Some(m) => { if ws_sink.send(m).await.is_err() { return; } }
                            None => { let _ = ws_sink.close().await; return; }
                        },
                    }
                } else {
                    match data_rx.recv().await {
                        Some(m) => { if ws_sink.send(m).await.is_err() { return; } }
                        None => { let _ = ws_sink.close().await; return; }
                    }
                }
            }
        });
        let header = build_request_header(uuid, VLESS_CMD_TCP, target);
        (
            Self {
                data_tx: Some(data_tx),
                _writer_task: Some(AbortOnDrop::new(writer_task)),
                pending_header: Some(header),
                _lifetime: lifetime,
            },
            ctrl_tx,
        )
    }

    pub fn supports_half_close(&self) -> bool {
        false
    }

    pub async fn send_chunk(&mut self, payload: &[u8]) -> Result<()> {
        let frame = if let Some(mut header) = self.pending_header.take() {
            header.extend_from_slice(payload);
            header
        } else if payload.is_empty() {
            return Ok(());
        } else {
            payload.to_vec()
        };
        self.data_tx
            .as_ref()
            .ok_or_else(|| anyhow!("vless writer already closed"))?
            .send(Message::Binary(frame.into()))
            .await
            .context(TransportOperation::WebSocketSend)
    }

    /// VLESS has no framing-layer keepalive of its own; the WS layer Ping
    /// that the paired reader forwards is the only defence. A zero-byte
    /// binary frame would be delivered to the destination TCP socket as a
    /// zero-byte write — harmless but pointless — so this is a no-op.
    pub async fn send_keepalive(&mut self) -> Result<()> {
        Ok(())
    }

    pub async fn close(&mut self) -> Result<()> {
        drop(self.data_tx.take());
        Ok(())
    }
}

// ── TCP reader ─────────────────────────────────────────────────────────────

/// VLESS TCP reader over a WebSocket stream. Strips the `[version,
/// addons_len(, addons…)]` prefix off the first response frame; subsequent
/// frames are returned as raw bytes. Buffering is only used when the first
/// frame is smaller than the response header or carries addons — the common
/// case is a single allocation-free path.
pub struct VlessTcpReader {
    stream: futures_util::stream::SplitStream<WsTransportStream>,
    ctrl_tx: mpsc::Sender<Message>,
    pending_header: bool,
    header_buf: Vec<u8>,
    diag: crate::WsReadDiag,
    _lifetime: Arc<UpstreamTransportGuard>,
    pub closed_cleanly: bool,
}

impl VlessTcpReader {
    pub fn new(
        stream: futures_util::stream::SplitStream<WsTransportStream>,
        ctrl_tx: mpsc::Sender<Message>,
        lifetime: Arc<UpstreamTransportGuard>,
    ) -> Self {
        Self {
            stream,
            ctrl_tx,
            pending_header: true,
            header_buf: Vec::new(),
            diag: crate::WsReadDiag::default(),
            _lifetime: lifetime,
            closed_cleanly: false,
        }
    }

    pub fn with_diag(mut self, diag: crate::WsReadDiag) -> Self {
        self.diag = diag;
        self
    }

    pub async fn read_chunk(&mut self) -> Result<Vec<u8>> {
        loop {
            let next = match timeout(WS_READ_IDLE_TIMEOUT, self.stream.next()).await {
                Err(_) => bail!(
                    "vless websocket upstream read idle for {}s on uplink {} target {}",
                    WS_READ_IDLE_TIMEOUT.as_secs(),
                    self.diag.uplink,
                    self.diag.target,
                ),
                Ok(None) => {
                    self.closed_cleanly = true;
                    return Err(anyhow::Error::from(WsClosed));
                },
                Ok(Some(Ok(msg))) => msg,
                Ok(Some(Err(e))) => return Err(e).context(TransportOperation::WebSocketRead),
            };
            match next {
                Message::Binary(bytes) => {
                    if self.pending_header {
                        // Accumulate until we have at least the 2-byte response
                        // header (version + addons_len); addons bytes (if any)
                        // are consumed afterwards.
                        self.header_buf.extend_from_slice(&bytes);
                        if self.header_buf.len() < 2 {
                            continue;
                        }
                        let version = self.header_buf[0];
                        if version != VLESS_VERSION {
                            bail!("vless bad response version {version:#x}");
                        }
                        let addons_len = self.header_buf[1] as usize;
                        let need = 2 + addons_len;
                        if self.header_buf.len() < need {
                            continue;
                        }
                        let tail = self.header_buf.split_off(need);
                        self.header_buf.clear();
                        self.pending_header = false;
                        if !tail.is_empty() {
                            return Ok(tail);
                        }
                        continue;
                    }
                    return Ok(bytes.into());
                },
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
                        "vless reader: websocket received Close frame from upstream"
                    );
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
}

// ── UDP transport ──────────────────────────────────────────────────────────

/// VLESS UDP datagram transport over a WebSocket stream. Parallel to
/// `UdpWsTransport` but without any Shadowsocks crypto: each outbound packet
/// is sent as `len(2 BE) || payload`, with the VLESS request header bundled
/// ahead of the first one.
pub struct VlessUdpWsTransport {
    data_tx: mpsc::Sender<Message>,
    downlink_rx: Mutex<mpsc::Receiver<Result<Bytes>>>,
    _writer_task: AbortOnDrop,
    _reader_task: AbortOnDrop,
    _keepalive_task: Option<AbortOnDrop>,
    pending_header: Mutex<Option<Vec<u8>>>,
    close_signal: watch::Sender<bool>,
    _lifetime: Arc<UpstreamTransportGuard>,
}

impl VlessUdpWsTransport {
    pub fn from_websocket(
        ws_stream: WsTransportStream,
        uuid: &[u8; 16],
        target: &TargetAddr,
        source: &'static str,
        keepalive_interval: Option<Duration>,
    ) -> Self {
        let (close_signal, _close_rx) = watch::channel(false);
        let (sink, stream) = ws_stream.split();
        let (data_tx, mut data_rx) = mpsc::channel::<Message>(64);
        let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<Message>(8);

        let writer_task = tokio::spawn(async move {
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
                            Some(Message::Close(_)) | None => {
                                let _ = ws_sink.close().await;
                                return;
                            }
                            Some(m) => { if ws_sink.send(m).await.is_err() { return; } }
                        },
                    }
                } else {
                    match data_rx.recv().await {
                        Some(Message::Close(_)) | None => {
                            let _ = ws_sink.close().await;
                            return;
                        }
                        Some(m) => { if ws_sink.send(m).await.is_err() { return; } }
                    }
                }
            }
        });

        let keepalive_task = keepalive_interval.map(|interval| {
            let keepalive_ctrl_tx = ctrl_tx.clone();
            AbortOnDrop(tokio::spawn(async move {
                let mut ticker = tokio::time::interval(interval);
                ticker.tick().await;
                loop {
                    ticker.tick().await;
                    if keepalive_ctrl_tx.send(Message::Ping(vec![].into())).await.is_err() {
                        break;
                    }
                }
            }))
        });

        let (downlink_tx, downlink_rx) = mpsc::channel::<Result<Bytes>>(64);
        let reader_ctrl_tx = ctrl_tx.clone();
        let mut close_rx = close_signal.subscribe();
        let reader_task = tokio::spawn(async move {
            let mut stream = stream;
            let mut pending_header = true;
            // Per-packet reassembly buffer: each downlink frame may contain
            // zero or more `len || payload` datagrams, possibly split across
            // WS messages.
            let mut buf: BytesMut = BytesMut::new();
            loop {
                let msg = tokio::select! {
                    _ = close_rx.changed() => {
                        if *close_rx.borrow() {
                            let _ = downlink_tx.send(Err(anyhow!("udp transport closed"))).await;
                            return;
                        }
                        continue;
                    }
                    msg = stream.next() => msg,
                };
                match msg {
                    None => return,
                    Some(Err(e)) => {
                        let err: anyhow::Result<()> = Err(e).context(TransportOperation::WebSocketRead);
                        let _ = downlink_tx.send(Err(err.unwrap_err())).await;
                        return;
                    }
                    Some(Ok(Message::Binary(bytes))) => {
                        buf.extend_from_slice(&bytes);
                        if pending_header {
                            if buf.len() < 2 {
                                continue;
                            }
                            let version = buf[0];
                            if version != VLESS_VERSION {
                                let _ = downlink_tx
                                    .send(Err(anyhow!("vless bad udp response version {version:#x}")))
                                    .await;
                                return;
                            }
                            let addons_len = buf[1] as usize;
                            if buf.len() < 2 + addons_len {
                                continue;
                            }
                            let _ = buf.split_to(2 + addons_len);
                            pending_header = false;
                        }
                        loop {
                            if buf.len() < 2 { break; }
                            let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                            if len > MAX_VLESS_UDP_PAYLOAD {
                                let _ = downlink_tx
                                    .send(Err(anyhow!("vless udp datagram too large: {len}")))
                                    .await;
                                return;
                            }
                            if buf.len() < 2 + len { break; }
                            let _ = buf.split_to(2);
                            let payload = buf.split_to(len).freeze();
                            if downlink_tx.send(Ok(payload)).await.is_err() {
                                return;
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) => {
                        let _ = downlink_tx.send(Err(anyhow::Error::from(WsClosed))).await;
                        return;
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        let _ = reader_ctrl_tx.try_send(Message::Pong(payload));
                    }
                    Some(Ok(Message::Pong(_) | Message::Frame(_))) => {}
                    Some(Ok(Message::Text(_))) => {
                        let _ = downlink_tx
                            .send(Err(anyhow!("unexpected text websocket frame")))
                            .await;
                        return;
                    }
                }
            }
        });

        let header = build_request_header(uuid, VLESS_CMD_UDP, target);
        Self {
            data_tx,
            downlink_rx: Mutex::new(downlink_rx),
            _writer_task: AbortOnDrop(writer_task),
            _reader_task: AbortOnDrop(reader_task),
            _keepalive_task: keepalive_task,
            pending_header: Mutex::new(Some(header)),
            close_signal,
            _lifetime: UpstreamTransportGuard::new(source, "udp"),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        cache: &DnsCache,
        url: &Url,
        mode: WsTransportMode,
        uuid: &[u8; 16],
        target: &TargetAddr,
        fwmark: Option<u32>,
        ipv6_first: bool,
        source: &'static str,
        keepalive_interval: Option<Duration>,
    ) -> Result<Self> {
        let ws_stream = connect_websocket_with_source(cache, url, mode, fwmark, ipv6_first, source)
            .await
            .with_context(|| TransportOperation::Connect { target: format!("to {}", url) })?;
        Ok(Self::from_websocket(ws_stream, uuid, target, source, keepalive_interval))
    }

    pub async fn send_packet(&self, payload: &[u8]) -> Result<()> {
        if payload.len() > MAX_VLESS_UDP_PAYLOAD {
            bail!("vless udp uplink datagram too large: {}", payload.len());
        }
        let mut frame: Vec<u8> = {
            let mut header = self.pending_header.lock().await;
            header.take().unwrap_or_default()
        };
        let need = 2 + payload.len();
        frame.reserve(need);
        frame.put_u16(payload.len() as u16);
        frame.extend_from_slice(payload);
        self.data_tx
            .send(Message::Binary(frame.into()))
            .await
            .context(TransportOperation::WebSocketSend)
    }

    pub async fn read_packet(&self) -> Result<Bytes> {
        let mut rx = self.downlink_rx.lock().await;
        rx.recv().await.ok_or_else(|| anyhow::Error::from(WsClosed))?
    }

    pub async fn close(&self) -> Result<()> {
        self.close_signal.send_replace(true);
        let _ = self.data_tx.send(Message::Close(None)).await;
        Ok(())
    }
}

// ── UDP session mux ────────────────────────────────────────────────────────

/// Shadowsocks UDP multiplexes all destinations through one encrypted session
/// (the target address is carried as a SOCKS-style atyp prefix in every
/// datagram). VLESS UDP has no such prefix: the target is locked into the
/// request header at session open, so each destination needs its own
/// WebSocket session. `VlessUdpSessionMux` provides an SS-shaped API
/// (`send_packet(socks5_framed_payload)` / `read_packet() -> socks5_framed`)
/// on top of a lazy map of per-target VLESS sessions.
///
/// The on-wire framing delta is absorbed by stripping the SOCKS5 UDP header
/// on send (to select/open the session and forward the raw payload) and
/// prepending it on receive (so the caller's existing `TargetAddr::from_wire_bytes`
/// parse still works).
pub struct VlessUdpSessionMux {
    dial: VlessUdpSessionDialer,
    sessions: Arc<Mutex<HashMap<TargetAddr, Arc<VlessUdpSessionEntry>>>>,
    downlink_tx: mpsc::Sender<Result<Bytes>>,
    downlink_rx: Mutex<mpsc::Receiver<Result<Bytes>>>,
    close_signal: watch::Sender<bool>,
    _lifetime: Arc<UpstreamTransportGuard>,
}

/// Captured connection parameters used to dial a new per-target VLESS UDP
/// session on demand. Everything here is cheap to clone and carries no
/// target-specific state.
#[derive(Clone)]
struct VlessUdpSessionDialer {
    dns_cache: Arc<DnsCache>,
    url: Url,
    mode: WsTransportMode,
    uuid: [u8; 16],
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
    keepalive_interval: Option<Duration>,
}

struct VlessUdpSessionEntry {
    transport: Arc<VlessUdpWsTransport>,
    _reader_task: AbortOnDrop,
}

impl VlessUdpSessionMux {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dns_cache: Arc<DnsCache>,
        url: Url,
        mode: WsTransportMode,
        uuid: [u8; 16],
        fwmark: Option<u32>,
        ipv6_first: bool,
        source: &'static str,
        keepalive_interval: Option<Duration>,
    ) -> Self {
        let (close_signal, _close_rx) = watch::channel(false);
        let (downlink_tx, downlink_rx) = mpsc::channel::<Result<Bytes>>(256);
        Self {
            dial: VlessUdpSessionDialer {
                dns_cache,
                url,
                mode,
                uuid,
                fwmark,
                ipv6_first,
                source,
                keepalive_interval,
            },
            sessions: Arc::new(Mutex::new(HashMap::new())),
            downlink_tx,
            downlink_rx: Mutex::new(downlink_rx),
            close_signal,
            _lifetime: UpstreamTransportGuard::new(source, "udp"),
        }
    }

    /// Send a SOCKS5-framed UDP payload (`atyp || addr || port || data`).
    /// The target is parsed out to select an existing VLESS session or open
    /// a new one; only the `data` portion crosses the VLESS wire, since the
    /// target is already bound into the session's request header.
    pub async fn send_packet(&self, socks5_payload: &[u8]) -> Result<()> {
        let (target, consumed) = TargetAddr::from_wire_bytes(socks5_payload)
            .context("vless udp: failed to parse SOCKS5 header from outbound payload")?;
        let inner = &socks5_payload[consumed..];
        let session = self.session_for(&target).await?;
        session.transport.send_packet(inner).await
    }

    /// Read the next downlink datagram as a SOCKS5-framed payload, with the
    /// originating session's `TargetAddr` prepended so the caller can parse
    /// it exactly like the SS UDP path.
    pub async fn read_packet(&self) -> Result<Bytes> {
        let mut rx = self.downlink_rx.lock().await;
        rx.recv().await.ok_or_else(|| anyhow::Error::from(WsClosed))?
    }

    pub async fn close(&self) -> Result<()> {
        self.close_signal.send_replace(true);
        let sessions = {
            let mut guard = self.sessions.lock().await;
            std::mem::take(&mut *guard)
        };
        for (_, entry) in sessions {
            let _ = entry.transport.close().await;
        }
        Ok(())
    }

    async fn session_for(&self, target: &TargetAddr) -> Result<Arc<VlessUdpSessionEntry>> {
        // Fast path: session exists.
        {
            let guard = self.sessions.lock().await;
            if let Some(entry) = guard.get(target) {
                return Ok(Arc::clone(entry));
            }
        }
        // Slow path: dial outside the lock, then insert — if a concurrent
        // caller won the race, discard ours and reuse theirs.
        let transport = Arc::new(
            VlessUdpWsTransport::connect(
                &self.dial.dns_cache,
                &self.dial.url,
                self.dial.mode,
                &self.dial.uuid,
                target,
                self.dial.fwmark,
                self.dial.ipv6_first,
                self.dial.source,
                self.dial.keepalive_interval,
            )
            .await
            .with_context(|| TransportOperation::Connect {
                target: format!("vless udp session to {target}"),
            })?,
        );
        let reader_task = spawn_vless_udp_session_reader(
            Arc::clone(&transport),
            target.clone(),
            self.downlink_tx.clone(),
            self.close_signal.subscribe(),
        );
        let entry = Arc::new(VlessUdpSessionEntry {
            transport,
            _reader_task: reader_task,
        });
        let mut guard = self.sessions.lock().await;
        if let Some(existing) = guard.get(target) {
            let existing = Arc::clone(existing);
            drop(guard);
            // Duplicate dial: let the loser's transport drop — its reader
            // task aborts with the Arc and its WS sink closes on Drop.
            let _ = entry.transport.close().await;
            return Ok(existing);
        }
        guard.insert(target.clone(), Arc::clone(&entry));
        Ok(entry)
    }
}

fn spawn_vless_udp_session_reader(
    transport: Arc<VlessUdpWsTransport>,
    target: TargetAddr,
    downlink_tx: mpsc::Sender<Result<Bytes>>,
    mut close_rx: watch::Receiver<bool>,
) -> AbortOnDrop {
    AbortOnDrop(tokio::spawn(async move {
        // Pre-build the SOCKS5 wire prefix for this session's target —
        // every downlink datagram carries the same one.
        let prefix = match target.to_wire_bytes() {
            Ok(bytes) => bytes,
            Err(error) => {
                let _ = downlink_tx
                    .send(Err(anyhow::Error::from(error).context(
                        "vless udp: failed to encode session target to SOCKS5 wire form",
                    )))
                    .await;
                return;
            },
        };
        loop {
            let payload = tokio::select! {
                biased;
                _ = close_rx.changed() => {
                    if *close_rx.borrow() { return; }
                    continue;
                }
                res = transport.read_packet() => match res {
                    Ok(p) => p,
                    Err(error) => {
                        // Per-session failure: surface it so the caller can
                        // treat it as a transport-level error, then exit —
                        // a replacement session will be opened on the next
                        // send to this target.
                        let _ = downlink_tx.send(Err(error)).await;
                        return;
                    }
                },
            };
            let mut framed = BytesMut::with_capacity(prefix.len() + payload.len());
            framed.extend_from_slice(&prefix);
            framed.extend_from_slice(&payload);
            if downlink_tx.send(Ok(framed.freeze())).await.is_err() {
                return;
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uuid_roundtrip() {
        let id = parse_uuid("550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert_eq!(id[0], 0x55);
        assert_eq!(id[15], 0x00);
    }

    #[test]
    fn request_header_ipv4_tcp() {
        let uuid = parse_uuid("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let target = TargetAddr::IpV4(std::net::Ipv4Addr::new(1, 2, 3, 4), 443);
        let hdr = build_request_header(&uuid, VLESS_CMD_TCP, &target);
        assert_eq!(hdr[0], 0x00);
        assert_eq!(&hdr[1..17], &uuid);
        assert_eq!(hdr[17], 0x00);
        assert_eq!(hdr[18], 0x01);
        assert_eq!(&hdr[19..21], &443u16.to_be_bytes());
        assert_eq!(hdr[21], VLESS_ATYP_IPV4);
        assert_eq!(&hdr[22..26], &[1, 2, 3, 4]);
    }

    #[test]
    fn request_header_domain_udp() {
        let uuid = parse_uuid("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let target = TargetAddr::Domain("example.com".into(), 80);
        let hdr = build_request_header(&uuid, VLESS_CMD_UDP, &target);
        assert_eq!(hdr[18], VLESS_CMD_UDP);
        assert_eq!(&hdr[19..21], &80u16.to_be_bytes());
        assert_eq!(hdr[21], VLESS_ATYP_DOMAIN);
        assert_eq!(hdr[22], 11);
        assert_eq!(&hdr[23..23 + 11], b"example.com");
    }
}
