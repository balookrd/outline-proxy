//! VLESS UDP datagram transport (single-target session).

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bytes::{BufMut, Bytes, BytesMut};
use parking_lot::Mutex as SyncMutex;
use socks5_proto::TargetAddr;
use url::Url;

use crate::{
    DnsCache, TransportOperation, TransportStream, UpstreamTransportGuard, WsClosed,
    config::TransportMode, connect_websocket_with_resume, connect_websocket_with_source,
    frame_io_ws::WS_READ_IDLE_TIMEOUT, resumption::SessionId,
};

use super::header::{
    MAX_VLESS_UDP_PAYLOAD, VLESS_CMD_UDP, VLESS_VERSION, build_request_header,
};

/// VLESS UDP datagram transport. Each outbound packet is sent as
/// `len(2 BE) || payload`, with the VLESS request header bundled ahead of
/// the first one. Inbound: the first datagram begins with the response
/// header `[version, addons_len, addons…]`, followed by `len || payload`
/// records (one or more per underlying datagram).
///
/// Decoupled from the underlying transport via [`crate::frame_io::DatagramChannel`] —
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
        ws_stream: TransportStream,
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

    /// Build a VLESS UDP transport over an arbitrary
    /// [`crate::frame_io::DatagramChannel`]. The channel is opaque to
    /// the protocol layer.
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
        mode: TransportMode,
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
    /// Returns `(transport, issued_session_id, downgraded_from)`:
    /// - `issued_session_id` is `Some` iff the server's WS Upgrade response
    ///   carried `X-Outline-Session`.
    /// - `downgraded_from` is `Some(requested_mode)` iff the underlying
    ///   `connect_websocket_with_resume` produced a stream at a lower mode
    ///   than requested (clamp via `ws_mode_cache` or inline H3→H2/H1
    ///   fallback). The `VlessUdpSessionMux` reports this through its
    ///   `on_downgrade` hook so the uplink-manager mirrors the downgrade
    ///   into its per-uplink `mode_downgrade_until` window.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_with_resume(
        cache: &DnsCache,
        url: &Url,
        mode: TransportMode,
        uuid: &[u8; 16],
        target: &TargetAddr,
        fwmark: Option<u32>,
        ipv6_first: bool,
        source: &'static str,
        keepalive_interval: Option<Duration>,
        resume_request: Option<SessionId>,
    ) -> Result<(Self, Option<SessionId>, Option<TransportMode>)> {
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
        // Snapshot the assigned Session ID and downgrade marker before
        // the VLESS framing layer takes ownership of the stream — both
        // sit on the WS Upgrade response, not on the inner VLESS handshake.
        let issued = ws_stream.issued_session_id();
        let downgraded_from = ws_stream.downgraded_from();
        let transport = Self::from_websocket(ws_stream, uuid, target, source, keepalive_interval);
        Ok((transport, issued, downgraded_from))
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
