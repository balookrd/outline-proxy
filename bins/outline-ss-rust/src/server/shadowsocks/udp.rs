use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use tracing::{debug, warn};

use crate::{
    crypto::{CryptoError, UserKey, decrypt_udp_packet_with_hint, diagnose_udp_packet},
    metrics::{AppProtocol, Protocol},
    protocol::parse_target_addr,
};

use super::super::{
    connect::resolve_udp_target,
    constants::MAX_UDP_PAYLOAD_SIZE,
    nat::{NatKey, UdpResponseSender},
    replay::{self, ReplayCheck},
    state::Services,
};

/// Identifies the client end of an SS-UDP relay for log/metrics purposes.
/// Raw-QUIC carriers use the QUIC connection's remote address.
#[derive(Clone)]
pub(in super::super) enum SsUdpClientId {
    QuicConnection(SocketAddr),
}

impl std::fmt::Display for SsUdpClientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QuicConnection(addr) => write!(f, "quic://{addr}"),
        }
    }
}

pub(in crate::server) struct SsUdpCtx {
    pub(in crate::server) users: Arc<[UserKey]>,
    pub(in crate::server) services: Arc<Services>,
}

/// Process one SS-AEAD UDP datagram regardless of where it came from (raw
/// UDP socket or QUIC datagram). Caller supplies a closure that builds the
/// response sender after the user has been authenticated.
pub(in super::super) async fn handle_ss_udp_packet<F>(
    ctx: &SsUdpCtx,
    data: Bytes,
    client_id: SsUdpClientId,
    protocol: Protocol,
    make_sender: F,
) -> Result<()>
where
    F: FnOnce() -> UdpResponseSender,
{
    let started_at = std::time::Instant::now();
    let packet = match decrypt_udp_packet_with_hint(
        ctx.users.as_ref(),
        &data,
        None,
        Some(ctx.services.udp_server.session_key_cache.as_ref()),
    ) {
        Ok((packet, _)) => packet,
        Err(CryptoError::UnknownUser) => {
            debug!(
                client = %client_id,
                encrypted_bytes = data.len(),
                attempts = ?diagnose_udp_packet(ctx.users.as_ref(), &data),
                "socket udp authentication failed for all configured users"
            );
            return Ok(());
        },
        Err(error) => return Err(anyhow!(error)),
    };
    let user_id = packet.user.id_arc();
    if let Some((csid, pid)) = replay::replay_key(&packet.session, packet.packet_id) {
        match ctx.services.udp_server.replay_store.check_and_mark(csid, pid) {
            ReplayCheck::Fresh => {},
            ReplayCheck::Replay => {
                ctx.services
                    .udp_server
                    .metrics
                    .record_udp_replay_dropped(Arc::clone(&user_id), protocol);
                warn!(
                    user = packet.user.id(),
                    client = %client_id,
                    packet_id = pid,
                    "dropping replayed ss-2022 udp datagram"
                );
                return Ok(());
            },
            ReplayCheck::StoreFull => {
                ctx.services
                    .udp_server
                    .metrics
                    .record_udp_replay_store_full_dropped(Arc::clone(&user_id), protocol);
                warn!(
                    user = packet.user.id(),
                    client = %client_id,
                    packet_id = pid,
                    "dropping ss-2022 udp datagram: replay store at capacity"
                );
                return Ok(());
            },
        }
    }
    let Some((target, consumed)) = parse_target_addr(&packet.payload)? else {
        return Err(anyhow!("udp packet is missing a complete target address"));
    };
    let payload = &packet.payload[consumed..];
    let target_display = target.to_string();
    ctx.services
        .udp_server
        .metrics
        .record_client_last_seen(Arc::clone(&user_id));
    debug!(
        user = packet.user.id(),
        cipher = packet.user.cipher().as_str(),
        client = %client_id,
        plaintext_bytes = payload.len(),
        "socket udp shadowsocks user authenticated"
    );

    if payload.len() > MAX_UDP_PAYLOAD_SIZE {
        ctx.services.udp_server.metrics.record_udp_oversized_datagram_dropped(
            Arc::clone(&user_id),
            protocol,
            AppProtocol::Shadowsocks,
            "client_to_target",
        );
        warn!(
            user = packet.user.id(),
            client = %client_id,
            target = %target_display,
            plaintext_bytes = payload.len(),
            max_udp_payload_bytes = MAX_UDP_PAYLOAD_SIZE,
            "dropping oversized socket udp datagram before upstream send"
        );
        ctx.services.udp_server.metrics.record_udp_request(
            Arc::clone(&user_id),
            protocol,
            AppProtocol::Shadowsocks,
            "error",
            started_at.elapsed().as_secs_f64(),
        );
        return Ok(());
    }

    let resolved = resolve_udp_target(
        ctx.services.udp_server.dns_cache.as_ref(),
        &target,
        ctx.services.udp_server.prefer_ipv4_upstream,
    )
    .await?;
    debug!(
        user = packet.user.id(),
        client = %client_id,
        target = %target_display,
        resolved = %resolved,
        plaintext_bytes = payload.len(),
        "socket udp resolved target"
    );
    debug!(
        user = packet.user.id(),
        fwmark = ?packet.user.fwmark(),
        client = %client_id,
        target = %target_display,
        resolved = %resolved,
        "socket udp datagram relay"
    );

    let nat_key = NatKey {
        user_id: Arc::clone(&user_id),
        fwmark: packet.user.fwmark(),
        target: resolved,
    };
    let entry = ctx
        .services
        .udp_server
        .nat_table
        .get_or_create(
            nat_key,
            &packet.user,
            packet.session.clone(),
            Arc::clone(&ctx.services.udp_server.metrics),
        )
        .await
        .with_context(|| format!("failed to create NAT entry for {resolved}"))?;

    // Direct SS-UDP is connectionless and out of scope for cross-
    // transport resumption (see docs/SESSION-RESUMPTION.md "Non-Goals").
    // Stream identity is irrelevant here because nothing ever calls
    // `detach_session_for_stream` against this entry; the constant
    // `0` makes that intent explicit.
    entry.register_session(make_sender(), packet.session.clone(), 0);

    entry
        .user_counters()
        .udp_in(AppProtocol::Shadowsocks, protocol)
        .increment(payload.len() as u64);
    debug!(
        user = packet.user.id(),
        client = %client_id,
        target = %resolved,
        plaintext_bytes = payload.len(),
        "socket udp relaying datagram to upstream"
    );
    if let Err(error) = entry.socket().send_to(payload, resolved).await {
        ctx.services.udp_server.metrics.record_udp_request(
            Arc::clone(&user_id),
            protocol,
            AppProtocol::Shadowsocks,
            "error",
            started_at.elapsed().as_secs_f64(),
        );
        return Err(error).with_context(|| format!("failed to send UDP datagram to {resolved}"));
    }
    entry.touch();
    ctx.services.udp_server.metrics.record_udp_request(
        user_id,
        protocol,
        AppProtocol::Shadowsocks,
        "success",
        started_at.elapsed().as_secs_f64(),
    );

    Ok(())
}
