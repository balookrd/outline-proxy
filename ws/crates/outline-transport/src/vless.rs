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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::{Mutex as SyncMutex, RwLock as SyncRwLock};

use anyhow::{Context, Result, anyhow, bail};
use bytes::{BufMut, Bytes, BytesMut};
use socks5_proto::TargetAddr;
use tokio::sync::{Mutex as AsyncMutex, OnceCell, mpsc, oneshot, watch};
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

/// VLESS Addons opcode: client advertises resumption support.
/// Length 1, value `0x01`.
const ADDON_TAG_RESUME_CAPABLE: u8 = 0x10;
/// VLESS Addons opcode: client requests resumption of the named
/// Session ID. Length 16.
const ADDON_TAG_RESUME_ID: u8 = 0x11;
/// Server response opcode: assigned Session ID. Length 16. Tag is the
/// same as `RESUME_CAPABLE` but lives in the response Addons block,
/// per docs/SESSION-RESUMPTION.md.
const ADDON_TAG_SESSION_ID: u8 = 0x10;
/// Server response opcode: outcome of a resume attempt. Length 1.
/// Tag is the same as `RESUME_ID` but lives in the response Addons
/// block.
#[allow(dead_code)]
const ADDON_TAG_RESUME_RESULT: u8 = 0x11;

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
    build_request_header(uuid, VLESS_CMD_UDP, target, &[])
}

/// Build the standard VLESS TCP request header. Same exposure rationale.
pub fn build_vless_tcp_request_header(uuid: &[u8; 16], target: &TargetAddr) -> Vec<u8> {
    build_request_header(uuid, VLESS_CMD_TCP, target, &[])
}

/// Build a VLESS TCP request header with the resumption Addons opcodes
/// populated. `resume_capable=true` advertises support so a feature-
/// enabled server mints a Session ID; `resume_id` (when set) asks the
/// server to re-attach a parked upstream. Used by the raw-QUIC client
/// path; WS-based callers get the same result via the
/// `X-Outline-*` HTTP headers.
pub fn build_vless_tcp_request_header_with_resume(
    uuid: &[u8; 16],
    target: &TargetAddr,
    resume_capable: bool,
    resume_id: Option<&[u8; 16]>,
) -> Vec<u8> {
    let addons = encode_request_addons(resume_capable, resume_id);
    build_request_header(uuid, VLESS_CMD_TCP, target, &addons)
}

fn encode_request_addons(resume_capable: bool, resume_id: Option<&[u8; 16]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(if resume_capable { 3 } else { 0 } + if resume_id.is_some() { 18 } else { 0 });
    if resume_capable {
        out.push(ADDON_TAG_RESUME_CAPABLE);
        out.push(1);
        out.push(0x01);
    }
    if let Some(id) = resume_id {
        out.push(ADDON_TAG_RESUME_ID);
        out.push(16);
        out.extend_from_slice(id);
    }
    out
}

/// Walk a server response Addons block and pull out the assigned
/// `SESSION_ID` opcode (`0x10`, length 16). Returns `None` if the
/// block is empty / unknown tags only / a feature-disabled server
/// emitted the legacy zero-length Addons. The `RESUME_RESULT` opcode
/// is recognised but currently discarded — callers infer hit/miss
/// from observable side-effects (counter on the upstream target).
fn parse_response_addons_session_id(block: &[u8]) -> Option<SessionId> {
    let mut i = 0;
    while i + 2 <= block.len() {
        let tag = block[i];
        let len = block[i + 1] as usize;
        let value_start = i + 2;
        let value_end = value_start + len;
        if value_end > block.len() {
            return None;
        }
        let value = &block[value_start..value_end];
        if tag == ADDON_TAG_SESSION_ID
            && let Ok(arr) = <[u8; 16]>::try_from(value)
        {
            return Some(SessionId::from_bytes(arr));
        }
        i = value_end;
    }
    None
}

fn build_request_header(
    uuid: &[u8; 16],
    command: u8,
    target: &TargetAddr,
    addons: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 16 + 1 + addons.len() + 1 + 2 + 1 + 256);
    out.push(VLESS_VERSION);
    out.extend_from_slice(uuid);
    out.push(addons.len() as u8); // addons_len
    out.extend_from_slice(addons);
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
        let header = build_request_header(uuid, VLESS_CMD_TCP, target, &[]);
        Self {
            sink: Some(sink),
            pending_header: Some(header),
            _lifetime: lifetime,
        }
    }

    /// Same as [`Self::with_sink`] but emits a populated Addons block
    /// carrying `RESUME_CAPABLE` and (optionally) `RESUME_ID`. Used by
    /// raw-QUIC callers — WS callers reach the same negotiation via
    /// HTTP headers in `connect_websocket_with_resume`.
    pub fn with_sink_and_resume(
        sink: Box<dyn crate::frame_io::FrameSink>,
        uuid: &[u8; 16],
        target: &TargetAddr,
        lifetime: Arc<UpstreamTransportGuard>,
        resume_id: Option<&[u8; 16]>,
    ) -> Self {
        let header =
            build_vless_tcp_request_header_with_resume(uuid, target, true, resume_id);
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
    /// Optional one-shot sink that receives the parsed `SESSION_ID`
    /// opcode (or `None` on a feature-disabled server) the moment the
    /// VLESS response header is first read. Used by resumption-aware
    /// callers (raw-QUIC dial path) to stash the freshly issued Session
    /// ID in the global ResumeCache without blocking the dial on a
    /// server round-trip — the dial returns immediately and the sink
    /// fires lazily on the first inbound frame.
    session_id_sink: Option<oneshot::Sender<Option<SessionId>>>,
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
            session_id_sink: None,
            _lifetime: lifetime,
        }
    }

    /// Same as [`Self::with_source`] but installs a one-shot sink that
    /// fires with the server-assigned `SESSION_ID` (or `None`) the
    /// moment the response header is parsed by the first
    /// [`Self::read_chunk`] call. Lets the dial path return without
    /// waiting for the server's handshake response — saves one full
    /// RTT per VLESS-TCP-over-QUIC dial.
    pub fn with_source_and_resume_sink(
        source: Box<dyn crate::frame_io::FrameSource>,
        lifetime: Arc<UpstreamTransportGuard>,
        sink: oneshot::Sender<Option<SessionId>>,
    ) -> Self {
        Self {
            source,
            pending_header: true,
            header_buf: Vec::new(),
            session_id_sink: Some(sink),
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
                // Resumption-aware reader: pull SESSION_ID out of the
                // response Addons block and notify the dial-side sink.
                // Non-resumption readers skip this — the sink is None.
                if let Some(sink) = self.session_id_sink.take() {
                    let session_id =
                        parse_response_addons_session_id(&self.header_buf[2..need]);
                    let _ = sink.send(session_id);
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
        let header = build_request_header(uuid, VLESS_CMD_UDP, target, &[]);
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
    /// Hot map of `target → slot`. Each slot wraps a
    /// [`tokio::sync::OnceCell`] that is lazy-filled by the first
    /// `session_for` call to dial that target — concurrent callers
    /// for the same target await the same future via
    /// `OnceCell::get_or_try_init`, so a burst of UDP datagrams to a
    /// fresh CDN edge triggers exactly one WS Upgrade instead of N
    /// parallel handshakes that race and discard losers (the
    /// "thundering herd" pattern). An [`SyncRwLock`] lets concurrent
    /// senders to *different* targets run their fast-path lookups in
    /// parallel.
    sessions: Arc<SyncRwLock<HashMap<TargetAddr, Arc<VlessUdpSessionSlot>>>>,
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
    /// Wall-clock origin for `last_use_ns`. Captured once at session
    /// creation; the entry's lifespan is bounded by
    /// `VlessUdpMuxLimits::session_idle_timeout` (60 s default), so the
    /// `u64` ns counter has decades of headroom regardless of process
    /// uptime.
    created: Instant,
    /// Nanoseconds since `created` of the last send/read on this
    /// session. Updated lock-free on every `send_packet` / inbound
    /// datagram (the hot path); read by the LRU eviction scan and the
    /// idle-session janitor. Replaces a per-entry mutex that was
    /// acquired twice (set + read) on every UDP datagram.
    last_use_ns: AtomicU64,
    _reader_task: AbortOnDrop,
}

impl VlessUdpSessionEntry {
    fn new(transport: Arc<VlessUdpWsTransport>, reader_task: AbortOnDrop) -> Self {
        Self {
            transport,
            created: Instant::now(),
            last_use_ns: AtomicU64::new(0),
            _reader_task: reader_task,
        }
    }

    fn touch(&self) {
        // Saturate at u64::MAX rather than wrapping — we'd lose ordering
        // for the LRU comparator otherwise. With a 60 s idle timeout the
        // counter never gets near saturation in practice.
        let ns = u64::try_from(self.created.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.last_use_ns.store(ns, Ordering::Relaxed);
    }

    fn last_use(&self) -> Instant {
        let ns = self.last_use_ns.load(Ordering::Relaxed);
        self.created + Duration::from_nanos(ns)
    }
}

/// Wrapper that lets `OnceCell::get_or_try_init` serialize concurrent
/// dial attempts for the same `TargetAddr`. The cell is empty while
/// the first dial is in flight; subsequent callers `await` the same
/// future and re-emerge with the populated [`VlessUdpSessionEntry`].
///
/// `created` is captured at slot insertion so the LRU comparator and
/// idle-session janitor have a meaningful "age" for in-flight slots
/// whose `cell` has not been populated yet.
struct VlessUdpSessionSlot {
    cell: OnceCell<Arc<VlessUdpSessionEntry>>,
    created: Instant,
}

impl VlessUdpSessionSlot {
    fn new() -> Self {
        Self { cell: OnceCell::new(), created: Instant::now() }
    }

    fn entry(&self) -> Option<&Arc<VlessUdpSessionEntry>> {
        self.cell.get()
    }

    /// Effective LRU stamp. Falls back to slot creation time for
    /// in-flight (cell-empty) slots so the eviction scan still has a
    /// totally-ordered key over the whole map; populated slots use
    /// the entry's lock-free atomic stamp.
    fn last_use(&self) -> Instant {
        self.cell.get().map(|e| e.last_use()).unwrap_or(self.created)
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
        let sessions: Arc<SyncRwLock<HashMap<TargetAddr, Arc<VlessUdpSessionSlot>>>> =
            Arc::new(SyncRwLock::new(HashMap::new()));
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
            let mut guard = self.sessions.write();
            std::mem::take(&mut *guard)
        };
        for (_, slot) in sessions {
            // In-flight slots have no transport yet; their first
            // `read_packet` after dial sees `close_signal=true` via the
            // session-reader task and exits, and the dial future itself
            // is dropped together with the last `Arc<VlessUdpSessionSlot>`
            // reference we just released by clearing the map.
            if let Some(entry) = slot.entry() {
                let _ = entry.transport.close().await;
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn session_count(&self) -> usize {
        // Count only populated slots so test assertions match the
        // "open WS sessions" intuition; in-flight slots are visible
        // through the public API only as in-progress `session_for`
        // futures, not as completed sessions.
        self.sessions.read().values().filter(|s| s.entry().is_some()).count()
    }

    async fn session_for(&self, target: &TargetAddr) -> Result<Arc<VlessUdpSessionEntry>> {
        // Fast path: populated slot for this target. Concurrent senders
        // to *different* targets share a read guard so they don't
        // serialize, and `entry.touch()` updates the LRU timestamp
        // lock-free via a relaxed atomic store.
        {
            let guard = self.sessions.read();
            if let Some(slot) = guard.get(target)
                && let Some(entry) = slot.entry()
            {
                entry.touch();
                return Ok(Arc::clone(entry));
            }
        }
        // Slow path: get-or-create the slot, then `OnceCell::get_or_try_init`
        // serializes the dial. Only the first concurrent caller actually
        // runs the WS upgrade; the rest await the same future and emerge
        // with the same `Arc<VlessUdpSessionEntry>`. If the future errors,
        // the cell stays empty and the next call retries.
        let (slot, evicted) = {
            let mut guard = self.sessions.write();
            // Re-check (TOCTOU) before allocating a fresh slot.
            if let Some(existing) = guard.get(target) {
                (Arc::clone(existing), None)
            } else {
                let evicted = if guard.len() >= self.limits.max_sessions {
                    // LRU eviction. Skip in-flight slots — abandoning their
                    // shared dial future would force every blocked waiter
                    // to restart with a fresh handshake.
                    evict_lru_populated_session(&mut guard)
                } else {
                    None
                };
                let slot = Arc::new(VlessUdpSessionSlot::new());
                guard.insert(target.clone(), Arc::clone(&slot));
                (slot, evicted)
            }
        };
        if let Some(victim) = evicted {
            debug!(
                target: "outline_transport::vless",
                "vless udp mux at max_sessions, evicted LRU session to make room"
            );
            let _ = victim.transport.close().await;
        }
        let dial_outcome = slot
            .cell
            .get_or_try_init(|| async {
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
                Ok::<_, anyhow::Error>(Arc::new(VlessUdpSessionEntry::new(
                    transport,
                    reader_task,
                )))
            })
            .await;
        match dial_outcome {
            Ok(entry) => {
                entry.touch();
                Ok(Arc::clone(entry))
            }
            Err(error) => {
                // Best-effort cleanup: drop the failed slot from the map
                // so a fresh `session_for` allocates a new one rather
                // than retrying through this still-empty cell. If a
                // concurrent caller already replaced the slot we leave
                // theirs alone (Arc::ptr_eq guard).
                let mut guard = self.sessions.write();
                if let Some(existing) = guard.get(target)
                    && Arc::ptr_eq(existing, &slot)
                {
                    guard.remove(target);
                }
                Err(error)
            }
        }
    }
}

/// Pick the LRU populated slot. In-flight (cell-empty) slots are
/// skipped because evicting them would cancel the shared dial future
/// and force every blocked `session_for` waiter to retry from scratch.
/// In the pathological case where every slot is in-flight at once, no
/// eviction happens and the map briefly exceeds `max_sessions`; this
/// resolves on its own as soon as one of the dials completes.
fn evict_lru_populated_session(
    guard: &mut HashMap<TargetAddr, Arc<VlessUdpSessionSlot>>,
) -> Option<Arc<VlessUdpSessionEntry>> {
    let oldest_key = guard
        .iter()
        .filter(|(_, slot)| slot.entry().is_some())
        .min_by_key(|(_, slot)| slot.last_use())
        .map(|(k, _)| k.clone())?;
    let slot = guard.remove(&oldest_key)?;
    // `entry()` is `Some` here by construction (filter above).
    slot.entry().map(Arc::clone)
}

fn spawn_vless_udp_janitor(
    sessions: Arc<SyncRwLock<HashMap<TargetAddr, Arc<VlessUdpSessionSlot>>>>,
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
                // Two-phase scan: walk under a cheap read lock to find
                // candidates, then acquire the write lock briefly to
                // remove them. A single write-locked pass would block
                // every send_packet for the full O(N) scan.
                let candidates: Vec<TargetAddr> = {
                    let read_guard = sessions.read();
                    read_guard
                        .iter()
                        .filter(|(_, slot)| {
                            // Use `slot.last_use()` so the predicate is
                            // uniform: populated slots use the entry's
                            // atomic stamp, empty (in-flight) slots use
                            // `created`. An in-flight slot whose dial has
                            // been hanging for `idle_timeout` is almost
                            // certainly stuck — evicting it cancels the
                            // dial future and lets the next caller try
                            // afresh, preferable to indefinite blockage.
                            now.saturating_duration_since(slot.last_use()) >= idle_timeout
                        })
                        .map(|(k, _)| k.clone())
                        .collect()
                };
                if candidates.is_empty() {
                    Vec::new()
                } else {
                    let mut guard = sessions.write();
                    candidates
                        .into_iter()
                        .filter_map(|k| {
                            // Re-check the staleness predicate under the
                            // write lock — a sender may have touched the
                            // entry between the read-side scan and now.
                            // Skip if it has, so an active session never
                            // gets accidentally evicted by the janitor.
                            guard.get(&k).filter(|slot| {
                                now.saturating_duration_since(slot.last_use())
                                    >= idle_timeout
                            })?;
                            // `entry()` returns `None` for in-flight slots —
                            // we still want them evicted (the dial future
                            // dies with the last Arc), but there's no
                            // transport to close.
                            guard.remove(&k).and_then(|s| s.entry().map(Arc::clone))
                        })
                        .collect()
                }
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
        let hdr = build_request_header(&uuid, VLESS_CMD_TCP, &target, &[]);
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
        let hdr = build_request_header(&uuid, VLESS_CMD_UDP, &target, &[]);
        assert_eq!(hdr[18], VLESS_CMD_UDP);
        assert_eq!(&hdr[19..21], &80u16.to_be_bytes());
        assert_eq!(hdr[21], VLESS_ATYP_DOMAIN);
        assert_eq!(hdr[22], 11);
        assert_eq!(&hdr[23..23 + 11], b"example.com");
    }

    #[test]
    fn vless_udp_session_slot_empty_uses_created_for_lru() {
        // The LRU comparator and idle-session janitor both call
        // `slot.last_use()`. For in-flight (cell-empty) slots that
        // must fall back to `created` so the comparator has a totally-
        // ordered key — otherwise `min_by_key` would compare an
        // `Option<Instant>` and skip empty slots, but the predicate
        // for the janitor must still expire stuck dials.
        let slot = VlessUdpSessionSlot::new();
        assert!(slot.entry().is_none(), "freshly built slot is empty");
        assert_eq!(
            slot.last_use(),
            slot.created,
            "empty slot's LRU stamp falls back to creation time"
        );
    }

    #[test]
    fn evict_lru_populated_session_skips_in_flight_slots() {
        // Only populated slots are eligible for eviction — abandoning
        // an in-flight dial would cancel the shared OnceCell future
        // and force every blocked `session_for` waiter to restart.
        // The eviction scan must filter `entry().is_some()` first.
        let mut map: HashMap<TargetAddr, Arc<VlessUdpSessionSlot>> = HashMap::new();
        let target = TargetAddr::IpV4(std::net::Ipv4Addr::new(1, 2, 3, 4), 443);
        map.insert(target.clone(), Arc::new(VlessUdpSessionSlot::new()));

        let evicted = evict_lru_populated_session(&mut map);
        assert!(evicted.is_none(), "in-flight slot must not be evicted");
        assert_eq!(map.len(), 1, "in-flight slot stays in the map");
    }
}
