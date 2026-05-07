//! VLESS TCP writer/reader and the WS convenience constructor.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use bytes::Bytes;
use socks5_proto::TargetAddr;
use tokio::sync::oneshot;

use crate::{TransportStream, UpstreamTransportGuard, WsClosed, frame_io_ws::WS_READ_IDLE_TIMEOUT, resumption::SessionId};
use crate::ack_prefix::{FRAME_LEN_V1, ParseResult, parse_v1};

use super::header::{
    VLESS_CMD_TCP, VLESS_VERSION, build_request_header,
    build_vless_tcp_request_header_with_resume, parse_response_addons_session_id,
};

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
    /// Set by the caller when the WS upgrade negotiated the v1
    /// Ack-Prefix Protocol on the VLESS-WS path (server echoed
    /// `X-Outline-Resume-Ack-Prefix: 1`). When `true`, the very
    /// first 14 bytes received AFTER the VLESS response header are
    /// treated as the v1 control frame defined in the SS-RUST repo's
    /// `docs/SESSION-RESUMPTION.md` § Ack-Prefix Protocol; the
    /// reader transparently consumes them, parks the offset on
    /// [`Self::up_acked`], and returns the next real payload chunk.
    expect_ack_prefix: bool,
    /// Server-reported `up_acked` byte count from the v1 control
    /// frame, or `None` when the protocol was not negotiated, the
    /// prefix has not yet been parsed, or the frame was malformed.
    up_acked: Option<u64>,
    /// Bytes deferred to the *next* call of [`Self::read_chunk`].
    /// Populated by [`Self::consume_ack_prefix`] when the prefix and
    /// trailing application data arrived in the same WS frame, so
    /// the `read_chunk` immediately after `consume_ack_prefix` does
    /// not silently drop those bytes.
    pending_tail: Option<Vec<u8>>,
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
            expect_ack_prefix: false,
            up_acked: None,
            pending_tail: None,
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
            expect_ack_prefix: false,
            up_acked: None,
            pending_tail: None,
            _lifetime: lifetime,
        }
    }

    /// Whether the stream EOF / Close was a clean teardown vs runtime
    /// fault — surfaced from the underlying source.
    pub fn closed_cleanly(&self) -> bool {
        self.source.closed_cleanly()
    }

    /// Tells the reader to expect a v1 Ack-Prefix control frame as
    /// the very first 14 bytes received AFTER the VLESS response
    /// header. Set this when (and only when) the WS upgrade response
    /// carried `X-Outline-Resume-Ack-Prefix: 1` — i.e.
    /// [`crate::TransportStream::ack_prefix_advertised_by_server`]
    /// is `true`. The first call to [`Self::read_chunk`] (or the
    /// preferred [`Self::consume_ack_prefix`] fast path) consumes the
    /// 14 prefix bytes, parks the reported offset on
    /// [`Self::upstream_acked_offset`], and returns the next real
    /// payload chunk.
    pub fn with_expect_ack_prefix(mut self, expect: bool) -> Self {
        self.expect_ack_prefix = expect;
        self
    }

    /// Server-reported `up_acked` byte offset from the v1 Ack-Prefix
    /// control frame, or `None` when the protocol was not negotiated
    /// or the prefix has not yet been parsed.
    pub fn upstream_acked_offset(&self) -> Option<u64> {
        self.up_acked
    }

    /// v1.1 fast path: drives the VLESS response header parse and the
    /// 14-byte control-frame consume up-front, returning the parsed
    /// offset BEFORE the relay loop reads any real data. Pair with
    /// [`Self::consume_ack_prefix_with_timeout`] in production code so
    /// a server that negotiated the capability but never emits the
    /// frame cannot stall the orchestrator forever.
    ///
    /// Returns `Ok(None)` immediately when the protocol was not
    /// negotiated (the caller never set
    /// [`Self::with_expect_ack_prefix`]) or when the prefix has
    /// already been consumed by a previous call. Any parse failure
    /// drops the session per spec strict handling.
    pub async fn consume_ack_prefix(&mut self) -> Result<Option<u64>> {
        if !self.expect_ack_prefix {
            return Ok(self.up_acked);
        }
        self.ensure_header_parsed().await?;
        loop {
            if !self.header_buf.is_empty() {
                let buffered = std::mem::take(&mut self.header_buf);
                if let Some(extras) = self.try_consume_prefix_inline(&buffered)? {
                    if !extras.is_empty() {
                        self.pending_tail = Some(extras);
                    }
                    return Ok(self.up_acked);
                }
                self.header_buf = buffered;
            }
            let bytes = match self.source.recv_frame().await? {
                None => return Err(anyhow::Error::from(WsClosed)),
                Some(b) => b,
            };
            self.header_buf.extend_from_slice(&bytes);
        }
    }

    /// Same as [`Self::consume_ack_prefix`] but bounded by `timeout`
    /// — protects the orchestrator against a server that negotiated
    /// the capability but never emits the frame. On timeout the
    /// session is dropped (matches the SS-reader `consume_ack_prefix
    /// _with_timeout` semantics).
    pub async fn consume_ack_prefix_with_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<u64>> {
        match tokio::time::timeout(timeout, self.consume_ack_prefix()).await {
            Ok(result) => result,
            Err(_) => bail!(
                "vless ack-prefix v1 control frame did not arrive within {} ms; \
                 dropping session",
                timeout.as_millis(),
            ),
        }
    }

    pub async fn read_chunk(&mut self) -> Result<Vec<u8>> {
        // Fast path for the v1.1 orchestrator: hand back any bytes
        // that arrived bundled with a previously-consumed control
        // frame so the caller sees them as the first data chunk.
        if let Some(tail) = self.pending_tail.take() {
            return Ok(tail);
        }
        self.ensure_header_parsed().await?;
        if self.expect_ack_prefix {
            loop {
                if !self.header_buf.is_empty() {
                    let buffered = std::mem::take(&mut self.header_buf);
                    if let Some(extras) = self.try_consume_prefix_inline(&buffered)? {
                        if !extras.is_empty() {
                            return Ok(extras);
                        }
                        // Exact 14-byte prefix; drop into the data
                        // path and read the next frame.
                        break;
                    }
                    self.header_buf = buffered;
                }
                let bytes = match self.source.recv_frame().await? {
                    None => return Err(anyhow::Error::from(WsClosed)),
                    Some(b) => b,
                };
                self.header_buf.extend_from_slice(&bytes);
            }
        }
        loop {
            let bytes = match self.source.recv_frame().await? {
                None => return Err(anyhow::Error::from(WsClosed)),
                Some(b) => b,
            };
            return Ok(bytes.into());
        }
    }

    /// Drives `recv_frame` until the VLESS response header (`[version,
    /// addons_len, addons…]`) is fully decoded; any trailing bytes
    /// past the header (data bytes that arrived in the same WS frame)
    /// remain in `self.header_buf` for the caller to consume next.
    async fn ensure_header_parsed(&mut self) -> Result<()> {
        if !self.pending_header {
            return Ok(());
        }
        loop {
            let bytes = match self.source.recv_frame().await? {
                None => return Err(anyhow::Error::from(WsClosed)),
                Some(b) => b,
            };
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
                let session_id = parse_response_addons_session_id(&self.header_buf[2..need]);
                let _ = sink.send(session_id);
            }
            let tail = self.header_buf.split_off(need);
            self.header_buf.clear();
            if !tail.is_empty() {
                self.header_buf = tail;
            }
            self.pending_header = false;
            return Ok(());
        }
    }

    /// Tries to consume a v1 control frame from the front of `buf`.
    /// Returns `Ok(Some(extras))` on success — `extras` are any
    /// trailing data bytes after the 14-byte prefix (may be empty for
    /// the typical exact-14-byte case). Returns `Ok(None)` when `buf`
    /// has fewer than 14 bytes — the caller should buffer and wait
    /// for more. Any parse failure surfaces the matching bail-out
    /// error (drops the session per spec).
    fn try_consume_prefix_inline(&mut self, buf: &[u8]) -> Result<Option<Vec<u8>>> {
        if buf.len() < FRAME_LEN_V1 {
            return Ok(None);
        }
        match parse_v1(buf) {
            ParseResult::Valid { up_acked } => {
                self.up_acked = Some(up_acked);
                self.expect_ack_prefix = false;
                Ok(Some(buf[FRAME_LEN_V1..].to_vec()))
            },
            ParseResult::TooShort => Ok(None),
            ParseResult::BadMagic => bail!(
                "vless ack-prefix v1 control frame has unexpected magic; dropping session"
            ),
            ParseResult::UnsupportedVersion(v) => bail!(
                "vless ack-prefix control frame announces unsupported version {v}; \
                 dropping session"
            ),
            ParseResult::ReservedFlagsSet(f) => bail!(
                "vless ack-prefix v1 control frame has reserved flags 0x{f:02x} set; \
                 dropping session"
            ),
        }
    }
}

/// Build a VLESS TCP writer/reader pair over a WebSocket stream.
/// Convenience wrapper around `frame_io_ws::from_ws_frames` +
/// [`VlessTcpWriter::with_sink`] / [`VlessTcpReader::with_source`].
///
/// `keepalive_interval` enables WS Ping frames on the active session to
/// defeat NAT/middlebox idle-timeout drops; pass `None` to disable.
pub fn vless_tcp_pair_from_ws(
    ws_stream: TransportStream,
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
