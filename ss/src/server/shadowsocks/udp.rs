use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result, anyhow};
use bytes::{Bytes, BytesMut};
use futures_util::{FutureExt, StreamExt, future::BoxFuture, stream::FuturesUnordered};
use tokio::net::UdpSocket;
use tracing::{debug, warn};

use crate::{
    crypto::{CryptoError, UserKey, decrypt_udp_packet, diagnose_udp_packet},
    metrics::{Protocol, Transport},
    protocol::parse_target_addr,
};

use super::super::{
    connect::resolve_udp_target,
    constants::{MAX_UDP_DATAGRAM_SIZE, MAX_UDP_PAYLOAD_SIZE, UDP_MAX_CONCURRENT_RELAY_TASKS},
    nat::{NatKey, ResponseSender, UdpResponseSender},
    replay::{self, ReplayCheck},
    shutdown::ShutdownSignal,
    state::Services,
};

/// Identifies the client end of an SS-UDP relay for log/metrics purposes.
/// Plain UDP listeners use the source `SocketAddr`; raw-QUIC listeners use
/// the QUIC connection's remote address.
#[derive(Clone)]
pub(in super::super) enum SsUdpClientId {
    Datagram(SocketAddr),
    QuicConnection(SocketAddr),
}

impl std::fmt::Display for SsUdpClientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Datagram(addr) => write!(f, "{addr}"),
            Self::QuicConnection(addr) => write!(f, "quic://{addr}"),
        }
    }
}

pub(in crate::server) struct SsUdpCtx {
    pub(in crate::server) users: Arc<[UserKey]>,
    pub(in crate::server) services: Arc<Services>,
}

struct DatagramResponseSender {
    socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
}

impl ResponseSender for DatagramResponseSender {
    fn send_bytes(&self, data: Bytes) -> BoxFuture<'_, bool> {
        Box::pin(async move { self.socket.send_to(&data, self.client_addr).await.is_ok() })
    }

    fn protocol(&self) -> Protocol {
        Protocol::Socket
    }
}

pub(in super::super) async fn serve_ss_udp_socket(
    socket: Arc<UdpSocket>,
    ctx: SsUdpCtx,
    mut shutdown: ShutdownSignal,
) -> Result<()> {
    let ctx = Arc::new(ctx);
    let mut in_flight: FuturesUnordered<BoxFuture<'static, ()>> = FuturesUnordered::new();
    let mut buffer = BytesMut::with_capacity(MAX_UDP_DATAGRAM_SIZE);
    loop {
        buffer.reserve(MAX_UDP_DATAGRAM_SIZE);
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                debug!("shadowsocks udp listener stopping on shutdown signal");
                return Ok(());
            }
            Some(()) = in_flight.next(), if !in_flight.is_empty() => {}
            recv = socket.recv_buf_from(&mut buffer) => {
                let (read, client_addr) = match recv {
                    Ok(v) => v,
                    Err(error) => {
                        warn!(?error, "failed to receive shadowsocks udp packet");
                        continue;
                    }
                };
                debug!(
                    client_addr = %client_addr,
                    encrypted_bytes = read,
                    "socket udp received encrypted datagram"
                );
                if in_flight.len() >= UDP_MAX_CONCURRENT_RELAY_TASKS {
                    ctx.services.udp_server.metrics.record_udp_relay_drop(
                        Transport::Udp,
                        Protocol::Socket,
                        "concurrency_limit",
                    );
                    warn!(%client_addr, "socket udp concurrent relay limit reached, dropping datagram");
                    buffer.clear();
                    continue;
                }
                let data = buffer.split_to(read).freeze();
                let ctx = Arc::clone(&ctx);
                let socket = Arc::clone(&socket);
                in_flight.push(async move {
                    if let Err(error) = handle_ss_udp_datagram(&ctx, data, client_addr, socket).await {
                        warn!(%client_addr, ?error, "socket udp datagram relay failed");
                    }
                }.boxed());
            }
        }
    }
}

async fn handle_ss_udp_datagram(
    ctx: &SsUdpCtx,
    data: Bytes,
    client_addr: SocketAddr,
    outbound_socket: Arc<UdpSocket>,
) -> Result<()> {
    handle_ss_udp_packet(
        ctx,
        data,
        SsUdpClientId::Datagram(client_addr),
        Protocol::Socket,
        move || {
            UdpResponseSender::new(Arc::new(DatagramResponseSender {
                socket: Arc::clone(&outbound_socket),
                client_addr,
            }))
        },
    )
    .await
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
    let packet = match decrypt_udp_packet(ctx.users.as_ref(), &data) {
        Ok(packet) => packet,
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
    let target_display = target.display_host_port();
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

    entry
        .register_session(make_sender(), packet.session.clone())
        .await;

    entry
        .user_counters()
        .udp_in(protocol)
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
            "error",
            started_at.elapsed().as_secs_f64(),
        );
        return Err(error).with_context(|| format!("failed to send UDP datagram to {resolved}"));
    }
    entry.touch();
    ctx.services.udp_server.metrics.record_udp_request(
        user_id,
        protocol,
        "success",
        started_at.elapsed().as_secs_f64(),
    );

    Ok(())
}
