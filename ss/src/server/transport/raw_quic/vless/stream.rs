use std::sync::Arc;

use anyhow::{Result, anyhow};
use tokio::time::{Duration, timeout};
use tracing::warn;

use crate::protocol::vless::{self, VlessCommand, mask_uuid};

use super::super::super::super::{
    constants::SS_TCP_HANDSHAKE_TIMEOUT_SECS,
    resumption::SessionId,
    transport::{ResumeContext, VlessWsServerCtx, sink},
};
use super::ctx::{MAX_VLESS_HEADER_BUFFER, RawQuicVlessRouteCtx, VlessQuicConn};
use super::tcp::handle_tcp;
use super::udp::handle_udp;

pub(super) async fn run_stream(
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    prefix: Vec<u8>,
    server: &VlessWsServerCtx,
    route: &RawQuicVlessRouteCtx,
    connection: &Arc<quinn::Connection>,
    conn_state: &Arc<VlessQuicConn>,
) -> Result<()> {
    // Read enough bytes from the stream to parse a VLESS request header.
    // We pull in chunks of up to MAX_VLESS_HEADER_BUFFER bytes; parsing is
    // tolerant of partial input and signals readiness via Ok(Some(_)).
    // `prefix` carries any bytes the caller pre-read off the recv stream
    // (e.g. the 8-byte peek used to disambiguate the oversize-record
    // magic from a VLESS request header) so they re-enter the parser.
    let mut header_buf = if prefix.is_empty() { Vec::with_capacity(128) } else { prefix };
    // Probe-resistance helper: when the parser rejects the header bytes
    // (wrong version, unsupported command, oversized buffer), sink the
    // remaining stream until the handshake-equivalent timeout (or byte
    // cap) before returning the error. The peer ends up seeing an
    // unfinished handshake instead of an instant close that would
    // fingerprint VLESS apart from a stalled SS-AEAD raw-QUIC stream.
    let request = loop {
        // Try parsing first so a `prefix` that already carries the
        // full header avoids an unnecessary read on a stream the
        // peer may not write to again until handshake completes.
        match vless::parse_request(&header_buf) {
            Ok(Some(request)) => break request,
            Ok(None) => {
                if header_buf.len() > MAX_VLESS_HEADER_BUFFER {
                    sink::sink_async_read(&mut recv).await;
                    return Err(anyhow!("vless raw-quic header too large")
                        .context(sink::HandshakeRejectedMarker));
                }
            },
            Err(vless::VlessError::UnsupportedCommand(c)) => {
                sink::sink_async_read(&mut recv).await;
                return Err(anyhow!("unsupported vless command {c:#x}")
                    .context(sink::HandshakeRejectedMarker));
            },
            Err(error) => {
                sink::sink_async_read(&mut recv).await;
                return Err(anyhow!(error).context(sink::HandshakeRejectedMarker));
            },
        }
        let mut chunk = [0_u8; 256];
        let read_fut = recv.read(&mut chunk);
        let read = match timeout(Duration::from_secs(SS_TCP_HANDSHAKE_TIMEOUT_SECS), read_fut).await
        {
            Ok(Ok(Some(n))) => n,
            Ok(Ok(None)) => return Ok(()),
            Ok(Err(error)) => {
                return Err(anyhow!(error).context("vless raw-quic stream read failed"));
            },
            Err(_) => {
                warn!(buffered = header_buf.len(), "vless raw-quic header read timed out");
                return Err(anyhow!("vless raw-quic handshake timeout"));
            },
        };
        header_buf.extend_from_slice(&chunk[..read]);
    };

    let user = match vless::find_user(route.users.as_ref(), &request.user_id).cloned() {
        Some(user) => user,
        None => {
            warn!(
                user = %mask_uuid(&request.user_id),
                candidates = ?route.candidate_users,
                "rejected vless raw-quic user"
            );
            sink::sink_async_read(&mut recv).await;
            return Err(anyhow!("unknown vless user").context(sink::HandshakeRejectedMarker));
        },
    };

    // Build the resume context from parsed Addons. `mint_session_id`
    // is a no-op when resumption is disabled, so this stays cheap on
    // the cold path.
    let issued_session_id = if server.orphan_registry.enabled()
        && (request.addons.resume_capable || request.addons.resume_id.is_some())
    {
        server.orphan_registry.mint_session_id()
    } else {
        None
    };
    let requested_resume = request.addons.resume_id.map(SessionId::from_bytes);
    // Ack-Prefix Protocol negotiation is HTTP-header-based and therefore
    // does not apply to raw-QUIC VLESS sessions (no HTTP layer to carry
    // the capability advertisement). Always disabled on this path.
    let resume_ctx =
        ResumeContext { requested_resume, issued_session_id, ack_prefix_requested: false };

    match request.command {
        VlessCommand::Tcp => {
            handle_tcp(send, recv, header_buf, request, user, server, resume_ctx).await
        },
        VlessCommand::Udp => {
            handle_udp(send, recv, header_buf, request, user, server, connection, conn_state).await
        },
        VlessCommand::Mux => Err(anyhow!(
            "VLESS MUX is not supported on raw QUIC; open separate streams"
        )),
    }
}
