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
use std::time::{Duration, Instant};

use parking_lot::Mutex as SyncMutex;

use anyhow::{Context, Result, anyhow, bail};
use bytes::{BufMut, Bytes, BytesMut};
use socks5_proto::TargetAddr;
use tokio::sync::{Mutex as AsyncMutex, mpsc, watch};
use tracing::debug;
use url::Url;

use crate::{
    AbortOnDrop, DnsCache, TransportOperation, UpstreamTransportGuard, WsClosed,
    WsTransportStream, config::WsTransportMode, connect_websocket_with_resume,
    connect_websocket_with_source, frame_io_ws::WS_READ_IDLE_TIMEOUT,
    resumption::SessionId,
};

const VLESS_VERSION: u8 = 0x00;
const VLESS_CMD_TCP: u8 = 0x01;
const VLESS_CMD_UDP: u8 = 0x02;

const VLESS_ATYP_IPV4: u8 = 0x01;
const VLESS_ATYP_DOMAIN: u8 = 0x02;
const VLESS_ATYP_IPV6: u8 = 0x03;

const MAX_VLESS_UDP_PAYLOAD: usize = 64 * 1024;

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

/// Build the standard VLESS UDP request header. Exposed so transports
/// that bypass the WebSocket layer (raw QUIC) can write it directly to
/// the underlying control stream.
pub fn build_vless_udp_request_header(uuid: &[u8; 16], target: &TargetAddr) -> Vec<u8> {
    build_request_header(uuid, VLESS_CMD_UDP, target)
}

/// Build the standard VLESS TCP request header. Same exposure rationale.
pub fn build_vless_tcp_request_header(uuid: &[u8; 16], target: &TargetAddr) -> Vec<u8> {
    build_request_header(uuid, VLESS_CMD_TCP, target)
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

/// VLESS TCP writer. Emits the request header on the first `send_chunk`
/// concatenated with the payload into a single frame; subsequent frames
/// are raw client bytes. Decoupled from the underlying transport via
/// [`crate::frame_io::FrameSink`] — works identically over WS or QUIC.
pub struct VlessTcpWriter {
    sink: Option<Box<dyn crate::frame_io::FrameSink>>,
    pending_header: Option<Vec<u8>>,
    _lifetime: Arc<UpstreamTransportGuard>,
}

impl VlessTcpWriter {
    /// Build over an arbitrary [`crate::frame_io::FrameSink`].
    pub fn with_sink(
        sink: Box<dyn crate::frame_io::FrameSink>,
        uuid: &[u8; 16],
        target: &TargetAddr,
        lifetime: Arc<UpstreamTransportGuard>,
    ) -> Self {
        let header = build_request_header(uuid, VLESS_CMD_TCP, target);
        Self {
            sink: Some(sink),
            pending_header: Some(header),
            _lifetime: lifetime,
        }
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
        self.sink
            .as_mut()
            .ok_or_else(|| anyhow!("vless writer already closed"))?
            .send_frame(Bytes::from(frame))
            .await
    }

    /// VLESS has no framing-layer keepalive of its own; the underlying
    /// transport (WS Ping, QUIC PING) handles this. No-op here.
    pub async fn send_keepalive(&mut self) -> Result<()> {
        Ok(())
    }

    pub async fn close(&mut self) -> Result<()> {
        if let Some(mut sink) = self.sink.take() {
            sink.close().await?;
        }
        Ok(())
    }
}

// ── TCP reader ─────────────────────────────────────────────────────────────

/// VLESS TCP reader. Strips the `[version, addons_len(, addons…)]` prefix
/// off the first response frame; subsequent frames are returned as raw
/// bytes. Buffering is only used when the first frame is smaller than the
/// response header or carries addons. Decoupled from the underlying
/// transport via [`crate::frame_io::FrameSource`].
pub struct VlessTcpReader {
    source: Box<dyn crate::frame_io::FrameSource>,
    pending_header: bool,
    header_buf: Vec<u8>,
    _lifetime: Arc<UpstreamTransportGuard>,
}

impl VlessTcpReader {
    pub fn with_source(
        source: Box<dyn crate::frame_io::FrameSource>,
        lifetime: Arc<UpstreamTransportGuard>,
    ) -> Self {
        Self {
            source,
            pending_header: true,
            header_buf: Vec::new(),
            _lifetime: lifetime,
        }
    }

    /// Whether the stream EOF / Close was a clean teardown vs runtime
    /// fault — surfaced from the underlying source.
    pub fn closed_cleanly(&self) -> bool {
        self.source.closed_cleanly()
    }

    pub async fn read_chunk(&mut self) -> Result<Vec<u8>> {
        loop {
            let bytes = match self.source.recv_frame().await? {
                None => return Err(anyhow::Error::from(WsClosed)),
                Some(b) => b,
            };
            if self.pending_header {
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
        }
    }
}

// ── WS convenience constructor ─────────────────────────────────────────────

/// Build a VLESS TCP writer/reader pair over a WebSocket stream.
/// Convenience wrapper around `frame_io_ws::from_ws_frames` +
/// [`VlessTcpWriter::with_sink`] / [`VlessTcpReader::with_source`].
///
/// `keepalive_interval` enables WS Ping frames on the active session to
/// defeat NAT/middlebox idle-timeout drops; pass `None` to disable.
pub fn vless_tcp_pair_from_ws(
    ws_stream: WsTransportStream,
    uuid: &[u8; 16],
    target: &TargetAddr,
    lifetime: Arc<UpstreamTransportGuard>,
    diag: crate::WsReadDiag,
    keepalive_interval: Option<Duration>,
) -> (VlessTcpWriter, VlessTcpReader) {
    let (sink, source) = crate::frame_io_ws::from_ws_frames(
        ws_stream,
        Some(WS_READ_IDLE_TIMEOUT),
        keepalive_interval,
    );
    let source = source.with_diag(diag.uplink, diag.target);
    let writer = VlessTcpWriter::with_sink(Box::new(sink), uuid, target, Arc::clone(&lifetime));
    let reader = VlessTcpReader::with_source(Box::new(source), lifetime);
    (writer, reader)
}

// ── UDP transport ──────────────────────────────────────────────────────────

/// VLESS UDP datagram transport. Each outbound packet is sent as
/// `len(2 BE) || payload`, with the VLESS request header bundled ahead of
/// the first one. Inbound: the first datagram begins with the response
/// header `[version, addons_len, addons…]`, followed by `len || payload`
/// records (one or more per underlying datagram).
///
/// Decoupled from the underlying transport via [`DatagramChannel`] —
/// works identically over WS Binary frames or QUIC datagrams.
pub struct VlessUdpTransport {
    chan: Arc<dyn crate::frame_io::DatagramChannel>,
    pending_header: SyncMutex<Option<Vec<u8>>>,
    /// Reader-side state. Single mutex covers both the in-progress
    /// reassembly buffer and the "saw response header yet?" flag — they
    /// are touched together and `read_packet` is serialized by the caller
    /// (one outstanding read at a time per session).
    recv_state: SyncMutex<VlessUdpRecvState>,
    _lifetime: Arc<UpstreamTransportGuard>,
}

struct VlessUdpRecvState {
    pending_header: bool,
    buf: BytesMut,
}

/// Public alias kept for backwards compatibility with the previous
/// `VlessUdpWsTransport` name. New code should use `VlessUdpTransport`.
pub type VlessUdpWsTransport = VlessUdpTransport;

impl VlessUdpTransport {
    pub fn from_websocket(
        ws_stream: WsTransportStream,
        uuid: &[u8; 16],
        target: &TargetAddr,
        source: &'static str,
        keepalive_interval: Option<Duration>,
    ) -> Self {
        let chan: Arc<dyn crate::frame_io::DatagramChannel> =
            Arc::new(crate::frame_io_ws::from_ws_datagrams(
                ws_stream,
                Some(WS_READ_IDLE_TIMEOUT),
                keepalive_interval,
            ));
        Self::from_channel(chan, uuid, target, source)
    }

    /// Build a VLESS UDP transport over an arbitrary [`DatagramChannel`].
    /// The channel is opaque to the protocol layer.
    pub fn from_channel(
        chan: Arc<dyn crate::frame_io::DatagramChannel>,
        uuid: &[u8; 16],
        target: &TargetAddr,
        source: &'static str,
    ) -> Self {
        let header = build_request_header(uuid, VLESS_CMD_UDP, target);
        Self {
            chan,
            pending_header: SyncMutex::new(Some(header)),
            recv_state: SyncMutex::new(VlessUdpRecvState {
                pending_header: true,
                buf: BytesMut::new(),
            }),
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

    /// Same as [`Self::connect`] but participates in cross-transport
    /// session resumption: presents `resume_request` (if any) as the
    /// `X-Outline-Resume` header on the WebSocket Upgrade and surfaces
    /// the Session ID the server assigned via `X-Outline-Session` so
    /// the caller can stash it for the next reconnect.
    ///
    /// Returns `(transport, Option<SessionId>)`. Today's only
    /// production caller of single-target VLESS UDP is the probe path;
    /// regular VLESS UDP traffic is multiplexed through
    /// [`VlessUdpSessionMux`], which doesn't yet participate in
    /// resumption.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_with_resume(
        cache: &DnsCache,
        url: &Url,
        mode: WsTransportMode,
        uuid: &[u8; 16],
        target: &TargetAddr,
        fwmark: Option<u32>,
        ipv6_first: bool,
        source: &'static str,
        keepalive_interval: Option<Duration>,
        resume_request: Option<SessionId>,
    ) -> Result<(Self, Option<SessionId>)> {
        let ws_stream = connect_websocket_with_resume(
            cache,
            url,
            mode,
            fwmark,
            ipv6_first,
            source,
            resume_request,
        )
        .await
        .with_context(|| TransportOperation::Connect { target: format!("to {}", url) })?;
        // Snapshot the assigned Session ID before the VLESS framing
        // layer takes ownership of the stream — the SessionId is on
        // the WS Upgrade response, not on the inner VLESS handshake.
        let issued = ws_stream.issued_session_id();
        let transport = Self::from_websocket(ws_stream, uuid, target, source, keepalive_interval);
        Ok((transport, issued))
    }

    pub async fn send_packet(&self, payload: &[u8]) -> Result<()> {
        if payload.len() > MAX_VLESS_UDP_PAYLOAD {
            outline_metrics::record_dropped_oversized_udp_packet("outgoing");
            bail!(crate::OversizedUdpDatagram {
                transport: "vless-udp",
                payload_len: payload.len(),
                limit: MAX_VLESS_UDP_PAYLOAD,
            });
        }
        let mut frame: Vec<u8> = {
            let mut header = self.pending_header.lock();
            header.take().unwrap_or_default()
        };
        let need = 2 + payload.len();
        frame.reserve(need);
        frame.put_u16(payload.len() as u16);
        frame.extend_from_slice(payload);
        self.chan.send_datagram(Bytes::from(frame)).await
    }

    pub async fn read_packet(&self) -> Result<Bytes> {
        loop {
            // First try to extract a full record from the buffer without
            // touching the wire — handles the (uncommon) case of a single
            // underlying datagram carrying multiple len-prefixed records.
            {
                let mut state = self.recv_state.lock();
                if !state.pending_header
                    && let Some(payload) = try_split_packet(&mut state.buf)?
                {
                    return Ok(payload);
                }
            }
            let next = self
                .chan
                .recv_datagram()
                .await?
                .ok_or_else(|| anyhow::Error::from(WsClosed))?;
            let mut state = self.recv_state.lock();
            state.buf.extend_from_slice(&next);
            if state.pending_header {
                if state.buf.len() < 2 {
                    continue;
                }
                let version = state.buf[0];
                if version != VLESS_VERSION {
                    bail!("vless bad udp response version {version:#x}");
                }
                let addons_len = state.buf[1] as usize;
                if state.buf.len() < 2 + addons_len {
                    continue;
                }
                let _ = state.buf.split_to(2 + addons_len);
                state.pending_header = false;
            }
            if let Some(payload) = try_split_packet(&mut state.buf)? {
                return Ok(payload);
            }
        }
    }

    pub async fn close(&self) -> Result<()> {
        self.chan.close().await;
        Ok(())
    }
}

fn try_split_packet(buf: &mut BytesMut) -> Result<Option<Bytes>> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if len > MAX_VLESS_UDP_PAYLOAD {
        bail!("vless udp datagram too large: {len}");
    }
    if buf.len() < 2 + len {
        return Ok(None);
    }
    let _ = buf.split_to(2);
    Ok(Some(buf.split_to(len).freeze()))
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
/// Tuning parameters for the per-target session map. Defaults are picked
/// for a SOCKS/TUN client handling typical desktop workloads — DNS fan-out,
/// browser UDP, occasional QUIC/P2P.
#[derive(Clone, Copy, Debug)]
pub struct VlessUdpMuxLimits {
    /// Hard cap on concurrent VLESS UDP sessions. When the map is full, the
    /// least-recently-used session is evicted on insert so new destinations
    /// always make progress. A cap also bounds FD / memory pressure when a
    /// misbehaving client scans thousands of destinations.
    pub max_sessions: usize,
    /// Evict sessions whose `last_use` is older than this. `None` disables
    /// the janitor loop entirely (useful for tests).
    pub session_idle_timeout: Option<Duration>,
    /// How often the janitor scans for idle sessions. Ignored when
    /// `session_idle_timeout` is `None`.
    pub janitor_interval: Duration,
}

impl Default for VlessUdpMuxLimits {
    fn default() -> Self {
        Self {
            max_sessions: 256,
            session_idle_timeout: Some(Duration::from_secs(60)),
            janitor_interval: Duration::from_secs(15),
        }
    }
}

pub struct VlessUdpSessionMux {
    dial: VlessUdpSessionDialer,
    limits: VlessUdpMuxLimits,
    sessions: Arc<SyncMutex<HashMap<TargetAddr, Arc<VlessUdpSessionEntry>>>>,
    downlink_tx: mpsc::Sender<Result<Bytes>>,
    downlink_rx: AsyncMutex<mpsc::Receiver<Result<Bytes>>>,
    close_signal: watch::Sender<bool>,
    _janitor_task: Option<AbortOnDrop>,
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
    /// `parking_lot::Mutex` — touched on every send/read for LRU/idle
    /// bookkeeping; a sync mutex avoids dragging the tokio scheduler into
    /// the hot path for what is literally a timestamp write.
    last_use: SyncMutex<Instant>,
    _reader_task: AbortOnDrop,
}

impl VlessUdpSessionEntry {
    fn touch(&self) {
        *self.last_use.lock() = Instant::now();
    }

    fn last_use(&self) -> Instant {
        *self.last_use.lock()
    }
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
        Self::new_with_limits(
            dns_cache,
            url,
            mode,
            uuid,
            fwmark,
            ipv6_first,
            source,
            keepalive_interval,
            VlessUdpMuxLimits::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_limits(
        dns_cache: Arc<DnsCache>,
        url: Url,
        mode: WsTransportMode,
        uuid: [u8; 16],
        fwmark: Option<u32>,
        ipv6_first: bool,
        source: &'static str,
        keepalive_interval: Option<Duration>,
        limits: VlessUdpMuxLimits,
    ) -> Self {
        let (close_signal, _close_rx) = watch::channel(false);
        let (downlink_tx, downlink_rx) = mpsc::channel::<Result<Bytes>>(256);
        let sessions: Arc<SyncMutex<HashMap<TargetAddr, Arc<VlessUdpSessionEntry>>>> =
            Arc::new(SyncMutex::new(HashMap::new()));
        let janitor_task = limits.session_idle_timeout.map(|idle_timeout| {
            spawn_vless_udp_janitor(
                Arc::clone(&sessions),
                idle_timeout,
                limits.janitor_interval,
                close_signal.subscribe(),
            )
        });
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
            limits,
            sessions,
            downlink_tx,
            downlink_rx: AsyncMutex::new(downlink_rx),
            close_signal,
            _janitor_task: janitor_task,
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
        session.touch();
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
            let mut guard = self.sessions.lock();
            std::mem::take(&mut *guard)
        };
        for (_, entry) in sessions {
            let _ = entry.transport.close().await;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn session_count(&self) -> usize {
        self.sessions.lock().len()
    }

    async fn session_for(&self, target: &TargetAddr) -> Result<Arc<VlessUdpSessionEntry>> {
        // Fast path: session exists. Refresh its last_use stamp so that a
        // hot destination is never evicted by the LRU cap.
        {
            let guard = self.sessions.lock();
            if let Some(entry) = guard.get(target) {
                entry.touch();
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
            last_use: SyncMutex::new(Instant::now()),
            _reader_task: reader_task,
        });
        enum SlowPathOutcome {
            DuplicateDial(Arc<VlessUdpSessionEntry>),
            Inserted(Option<Arc<VlessUdpSessionEntry>>),
        }
        let outcome = {
            let mut guard = self.sessions.lock();
            if let Some(existing) = guard.get(target) {
                let existing = Arc::clone(existing);
                existing.touch();
                SlowPathOutcome::DuplicateDial(existing)
            } else {
                let evicted = if guard.len() >= self.limits.max_sessions {
                    // LRU eviction: scan for the oldest last_use stamp. Linear
                    // but `max_sessions` is small (256 by default) and this
                    // only runs on session churn, not per-packet.
                    evict_lru_session(&mut guard)
                } else {
                    None
                };
                guard.insert(target.clone(), Arc::clone(&entry));
                SlowPathOutcome::Inserted(evicted)
            }
        };
        match outcome {
            SlowPathOutcome::DuplicateDial(existing) => {
                // Duplicate dial: let the loser's transport drop — its reader
                // task aborts with the Arc and its WS sink closes on Drop.
                let _ = entry.transport.close().await;
                Ok(existing)
            }
            SlowPathOutcome::Inserted(evicted) => {
                if let Some(victim) = evicted {
                    debug!(
                        target: "outline_transport::vless",
                        "vless udp mux at max_sessions, evicted LRU session to make room"
                    );
                    let _ = victim.transport.close().await;
                }
                Ok(entry)
            }
        }
    }
}

fn evict_lru_session(
    guard: &mut HashMap<TargetAddr, Arc<VlessUdpSessionEntry>>,
) -> Option<Arc<VlessUdpSessionEntry>> {
    let oldest_key = guard
        .iter()
        .min_by_key(|(_, entry)| entry.last_use())
        .map(|(k, _)| k.clone())?;
    guard.remove(&oldest_key)
}

fn spawn_vless_udp_janitor(
    sessions: Arc<SyncMutex<HashMap<TargetAddr, Arc<VlessUdpSessionEntry>>>>,
    idle_timeout: Duration,
    interval: Duration,
    mut close_rx: watch::Receiver<bool>,
) -> AbortOnDrop {
    AbortOnDrop::new(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // consume the immediate tick
        loop {
            tokio::select! {
                biased;
                _ = close_rx.changed() => {
                    if *close_rx.borrow() { return; }
                }
                _ = ticker.tick() => {}
            }
            let now = Instant::now();
            let expired: Vec<Arc<VlessUdpSessionEntry>> = {
                let mut guard = sessions.lock();
                let keys: Vec<TargetAddr> = guard
                    .iter()
                    .filter(|(_, entry)| {
                        now.saturating_duration_since(entry.last_use()) >= idle_timeout
                    })
                    .map(|(k, _)| k.clone())
                    .collect();
                keys.into_iter().filter_map(|k| guard.remove(&k)).collect()
            };
            if !expired.is_empty() {
                debug!(
                    target: "outline_transport::vless",
                    count = expired.len(),
                    idle_secs = idle_timeout.as_secs(),
                    "vless udp mux: evicting idle sessions"
                );
            }
            for entry in expired {
                let _ = entry.transport.close().await;
            }
        }
    }))
}

fn spawn_vless_udp_session_reader(
    transport: Arc<VlessUdpWsTransport>,
    target: TargetAddr,
    downlink_tx: mpsc::Sender<Result<Bytes>>,
    mut close_rx: watch::Receiver<bool>,
) -> AbortOnDrop {
    AbortOnDrop::new(tokio::spawn(async move {
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
