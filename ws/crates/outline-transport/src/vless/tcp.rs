//! VLESS TCP writer/reader and the WS convenience constructor.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use bytes::Bytes;
use socks5_proto::TargetAddr;
use tokio::sync::oneshot;

use crate::{TransportStream, UpstreamTransportGuard, WsClosed, frame_io_ws::WS_READ_IDLE_TIMEOUT, resumption::SessionId};

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
