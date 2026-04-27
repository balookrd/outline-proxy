//! High-level VLESS / SS connect helpers over raw QUIC.
//!
//! Wire formats per the outline-ss-rust server:
//!
//! * VLESS-TCP — bidi stream on a connection with ALPN=`vless`. Standard
//!   VLESS request header → `[VERSION, 0x00]` response → bytes both ways.
//!   Multiple targets can share the same QUIC connection (each target =
//!   one bidi).
//!
//! * VLESS-UDP — bidi stream as control / lifetime anchor on the same
//!   ALPN=`vless` connection (shared with TCP), plus QUIC datagrams
//!   prefixed with the server-allocated 4-byte `session_id_BE`.
//!   Multiple UDP sessions share the connection-level demuxer
//!   ([`crate::quic::vless_udp::VlessUdpDemuxer`]).
//!
//! * SS-TCP — bidi stream on ALPN=`ss`, standard SS-AEAD ciphertext.
//!
//! * SS-UDP — QUIC datagrams on ALPN=`ss`, one datagram per
//!   self-contained SS-AEAD UDP packet (target inside encrypted
//!   payload).
//!
//! No fallback: dial / handshake failure is surfaced for the uplink
//! classifier to mark the uplink down.

#![cfg(feature = "quic")]

use std::sync::Arc;

use anyhow::{Context, Result};
use shadowsocks_crypto::CipherKind;
use socks5_proto::TargetAddr;
use url::Url;

use crate::frame_io_quic::{QuicDatagramChannel, open_quic_frame_pair};
use crate::quic::vless_udp::VlessUdpQuicSession;
use crate::quic::{ALPN_SS, ALPN_VLESS, SharedQuicConnection, connect_quic_uplink};
use crate::resumption::SessionId;
use crate::tcp_transport::{
    QuicTcpReader, QuicTcpWriter, TcpShadowsocksReader, TcpShadowsocksWriter,
};
use crate::udp_transport::UdpWsTransport;
use crate::vless::{VlessTcpReader, VlessTcpWriter};
use crate::{DnsCache, TransportOperation, UpstreamTransportGuard};

// ── VLESS over QUIC ──────────────────────────────────────────────────────

/// Open a VLESS TCP session: dial / reuse a `vless`-ALPN QUIC connection
/// and open a fresh bidi stream for the target.
pub async fn connect_vless_tcp_quic(
    cache: &DnsCache,
    url: &Url,
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
    uuid: &[u8; 16],
    target: &TargetAddr,
    lifetime: Arc<UpstreamTransportGuard>,
) -> Result<(VlessTcpWriter, VlessTcpReader)> {
    let conn = connect_quic_uplink(cache, url, fwmark, ipv6_first, source, ALPN_VLESS)
        .await
        .with_context(|| TransportOperation::Connect { target: format!("to {}", url) })?;
    let (sink, source_io) = open_quic_frame_pair(&conn).await?;
    let writer =
        VlessTcpWriter::with_sink(Box::new(sink), uuid, target, Arc::clone(&lifetime));
    let reader = VlessTcpReader::with_source(Box::new(source_io), lifetime);
    Ok((writer, reader))
}

/// Same as [`connect_vless_tcp_quic`] but participates in cross-transport
/// session resumption per the VLESS Addons opcodes specified in
/// `docs/SESSION-RESUMPTION.md`.
///
/// `resume_id` (when set) is encoded into the request header's Addons
/// block under tag `0x11 RESUME_ID`, asking the server to re-attach a
/// parked TCP upstream. `RESUME_CAPABLE` (tag `0x10`, value `0x01`) is
/// always emitted so a feature-enabled server mints a Session ID for
/// the next reconnect, even on a fresh dial.
///
/// Returns `(writer, reader, Option<SessionId>)`. The third element is
/// the Session ID the server assigned via the response Addons (empty
/// on a feature-disabled server). Internally the request header is
/// flushed eagerly so the server can echo a response before the
/// caller pushes any payload.
#[allow(clippy::too_many_arguments)]
pub async fn connect_vless_tcp_quic_with_resume(
    cache: &DnsCache,
    url: &Url,
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
    uuid: &[u8; 16],
    target: &TargetAddr,
    lifetime: Arc<UpstreamTransportGuard>,
    resume_id: Option<&[u8; 16]>,
) -> Result<(VlessTcpWriter, VlessTcpReader, Option<SessionId>)> {
    let conn = connect_quic_uplink(cache, url, fwmark, ipv6_first, source, ALPN_VLESS)
        .await
        .with_context(|| TransportOperation::Connect { target: format!("to {}", url) })?;
    let (sink, source_io) = open_quic_frame_pair(&conn).await?;
    let mut writer = VlessTcpWriter::with_sink_and_resume(
        Box::new(sink),
        uuid,
        target,
        Arc::clone(&lifetime),
        resume_id,
    );
    let mut reader = VlessTcpReader::with_source(Box::new(source_io), lifetime);
    // Flush the request header (with addons) immediately so the server
    // can read it, look up the parked upstream and write back a
    // response carrying the assigned Session ID. `send_chunk(&[])`
    // bundles only the pending header into the frame.
    writer
        .send_chunk(&[])
        .await
        .context("vless raw-quic resume: header flush failed")?;
    let session_id = reader
        .read_handshake_response()
        .await
        .context("vless raw-quic resume: handshake response read failed")?;
    Ok((writer, reader, session_id))
}

/// Open one VLESS UDP session to `target` over a shared `vless`-ALPN
/// QUIC connection. The connection-level demuxer is lazy-spawned on
/// first call. Multiple targets share the same connection.
///
/// Returns the opaque session handle. Caller talks to it via
/// `send_packet` / `read_packet` / `close` — same shape as the WS-side
/// `VlessUdpTransport`.
pub async fn connect_vless_udp_session_quic(
    cache: &DnsCache,
    url: &Url,
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
    uuid: &[u8; 16],
    target: &TargetAddr,
) -> Result<VlessUdpQuicSession> {
    let conn = connect_quic_uplink(cache, url, fwmark, ipv6_first, source, ALPN_VLESS)
        .await
        .with_context(|| TransportOperation::Connect { target: format!("to {}", url) })?;
    VlessUdpQuicSession::open(conn, uuid, target).await
}

// ── Shadowsocks over QUIC ────────────────────────────────────────────────

/// Open an SS TCP session: dial / reuse an `ss`-ALPN QUIC connection
/// and open a fresh bidi stream wrapped in the AEAD codec.
pub async fn connect_ss_tcp_quic(
    cache: &DnsCache,
    url: &Url,
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
    cipher: CipherKind,
    master_key: &[u8],
    lifetime: Arc<UpstreamTransportGuard>,
) -> Result<(QuicTcpWriter, QuicTcpReader)> {
    let conn = connect_quic_uplink(cache, url, fwmark, ipv6_first, source, ALPN_SS)
        .await
        .with_context(|| TransportOperation::Connect { target: format!("to {}", url) })?;
    let (send, recv) = conn.open_bidi_stream().await?;
    let writer =
        TcpShadowsocksWriter::connect_quic(send, cipher, master_key, Arc::clone(&lifetime))?;
    let reader = TcpShadowsocksReader::new_quic(recv, cipher, master_key, lifetime);
    Ok((writer, reader))
}

/// Build an SS UDP transport over an `ss`-ALPN QUIC connection. Each
/// outbound packet = one QUIC datagram = one SS-AEAD UDP packet (target
/// inside the encrypted payload).
pub async fn connect_ss_udp_quic(
    cache: &DnsCache,
    url: &Url,
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
    cipher: CipherKind,
    password: &str,
) -> Result<UdpWsTransport> {
    let conn = connect_quic_uplink(cache, url, fwmark, ipv6_first, source, ALPN_SS)
        .await
        .with_context(|| TransportOperation::Connect { target: format!("to {}", url) })?;
    let chan: Arc<dyn crate::frame_io::DatagramChannel> =
        Arc::new(QuicDatagramChannel::new(conn));
    UdpWsTransport::from_channel(chan, cipher, password, source)
}

#[allow(dead_code)]
pub(crate) fn _shared_conn_typecheck(c: Arc<SharedQuicConnection>) -> Arc<SharedQuicConnection> {
    c
}
