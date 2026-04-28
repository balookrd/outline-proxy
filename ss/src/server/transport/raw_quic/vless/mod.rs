//! Raw VLESS over QUIC (no WebSocket, no HTTP/3 framing).
//!
//! One QUIC bidirectional stream carries one VLESS request: header at the
//! start of the stream, then the TCP target's data is spliced in both
//! directions over the same stream. UDP and MUX commands are reserved for
//! Phase 2 (UDP via QUIC datagrams; MUX is intentionally not supported on raw
//! QUIC since QUIC streams *are* the multiplex).

use std::sync::Arc;

use anyhow::Result;

use crate::metrics::{Protocol, Transport};

use super::super::super::transport::{VlessWsServerCtx, sink};

mod ctx;
mod stream;
mod tcp;
mod udp;

pub(in crate::server) use ctx::{RawQuicVlessRouteCtx, VlessQuicConn};
pub(in crate::server) use udp::{serve_raw_vless_oversize_records, serve_raw_vless_quic_datagrams};

/// Handles a raw VLESS-over-QUIC stream, accepting a `prefix` of bytes
/// already read off the recv stream by the caller (typically the 8 bytes
/// peeked to disambiguate the oversize-record magic from a VLESS request
/// header). The handler treats those bytes as the first chunk of the
/// inbound stream.
pub(in crate::server) async fn handle_raw_vless_quic_stream_with_prefix(
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    prefix: Vec<u8>,
    server: Arc<VlessWsServerCtx>,
    route: Arc<RawQuicVlessRouteCtx>,
    connection: Arc<quinn::Connection>,
    conn_state: Arc<VlessQuicConn>,
) -> Result<()> {
    let session = server
        .metrics
        .open_websocket_session(Transport::Tcp, Protocol::QuicRaw);

    let outcome = stream::run_stream(
        send,
        recv,
        prefix,
        &server,
        &route,
        &connection,
        &conn_state,
    )
    .await;
    let outcome_for_metrics = match &outcome {
        Ok(()) => crate::metrics::DisconnectReason::Normal,
        Err(error) if sink::is_handshake_rejected(error) => {
            crate::metrics::DisconnectReason::HandshakeRejected
        },
        Err(_) => crate::metrics::DisconnectReason::Error,
    };
    session.finish(outcome_for_metrics);
    outcome
}
