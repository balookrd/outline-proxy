use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result, anyhow};
use bytes::{Bytes, BytesMut};
use futures_util::{FutureExt, StreamExt, future::BoxFuture, stream::FuturesUnordered};
use tokio::net::UdpSocket;
use tracing::{debug, warn};

use crate::{
    crypto::{CryptoError, UdpSession, UserKey, decrypt_udp_packet, diagnose_udp_packet},
    metrics::{Metrics, Protocol, Transport},
    protocol::parse_target_addr,
};

use super::super::{
    connect::resolve_udp_target,
    constants::{MAX_UDP_PAYLOAD_SIZE, UDP_MAX_CONCURRENT_RELAY_TASKS},
    dns_cache::DnsCache,
    nat::{NatKey, NatTable, ResponseSender, UdpResponseSender},
    replay::ReplayStore,
    shutdown::ShutdownSignal,
};

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

fn ss_udp_replay_key(session: &UdpSession, packet_id: Option<u64>) -> Option<([u8; 8], u64)> {
    let csid = match session {
        UdpSession::Legacy => return None,
        UdpSession::Aes2022 { client_session_id }
        | UdpSession::Chacha2022 { client_session_id } => *client_session_id,
    };
    packet_id.map(|pid| (csid, pid))
}

#[allow(clippy::too_many_arguments)]
pub(in super::super) async fn serve_ss_udp_socket(
    socket: Arc<UdpSocket>,
    users: Arc<[UserKey]>,
    metrics: Arc<Metrics>,
    nat_table: Arc<NatTable>,
    replay_store: Arc<ReplayStore>,
    dns_cache: Arc<DnsCache>,
    prefer_ipv4_upstream: bool,
    mut shutdown: ShutdownSignal,
) -> Result<()> {
    let mut in_flight: FuturesUnordered<BoxFuture<'static, ()>> = FuturesUnordered::new();
    let mut buffer = BytesMut::with_capacity(65_535);
    loop {
        buffer.reserve(65_535);
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
                    metrics.record_udp_relay_drop(
                        Transport::Udp,
                        Protocol::Socket,
                        "concurrency_limit",
                    );
                    warn!(%client_addr, "socket udp concurrent relay limit reached, dropping datagram");
                    buffer.clear();
                    continue;
                }
                let data = buffer.split_to(read).freeze();
                let users = users.clone();
                let metrics = metrics.clone();
                let nat_table = Arc::clone(&nat_table);
                let replay_store = Arc::clone(&replay_store);
                let socket = Arc::clone(&socket);
                let dns_cache = Arc::clone(&dns_cache);
                in_flight.push(async move {
                    if let Err(error) = handle_ss_udp_datagram(
                        nat_table,
                        replay_store,
                        users,
                        data,
                        client_addr,
                        socket,
                        metrics,
                        dns_cache,
                        prefer_ipv4_upstream,
                    )
                    .await
                    {
                        warn!(%client_addr, ?error, "socket udp datagram relay failed");
                    }
                }.boxed());
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_ss_udp_datagram(
    nat_table: Arc<NatTable>,
    replay_store: Arc<ReplayStore>,
    users: Arc<[UserKey]>,
    data: Bytes,
    client_addr: SocketAddr,
    outbound_socket: Arc<UdpSocket>,
    metrics: Arc<Metrics>,
    dns_cache: Arc<DnsCache>,
    prefer_ipv4_upstream: bool,
) -> Result<()> {
    let started_at = std::time::Instant::now();
    let packet = match decrypt_udp_packet(users.as_ref(), &data) {
        Ok(packet) => packet,
        Err(CryptoError::UnknownUser) => {
            debug!(
                client_addr = %client_addr,
                encrypted_bytes = data.len(),
                attempts = ?diagnose_udp_packet(users.as_ref(), &data),
                "socket udp authentication failed for all configured users"
            );
            return Ok(());
        },
        Err(error) => return Err(anyhow!(error)),
    };
    let user_id = packet.user.id_arc();
    if let Some((csid, pid)) = ss_udp_replay_key(&packet.session, packet.packet_id)
        && !replay_store.check_and_mark(csid, pid)
    {
        metrics.record_udp_replay_dropped(Arc::clone(&user_id), Protocol::Socket);
        warn!(
            user = packet.user.id(),
            client_addr = %client_addr,
            packet_id = pid,
            "dropping replayed ss-2022 udp datagram"
        );
        return Ok(());
    }
    let Some((target, consumed)) = parse_target_addr(&packet.payload)? else {
        return Err(anyhow!("udp packet is missing a complete target address"));
    };
    let payload = &packet.payload[consumed..];
    let target_display = target.display_host_port();
    metrics.record_client_last_seen(Arc::clone(&user_id));
    debug!(
        user = packet.user.id(),
        cipher = packet.user.cipher().as_str(),
        client_addr = %client_addr,
        plaintext_bytes = payload.len(),
        "socket udp shadowsocks user authenticated"
    );

    let resolved =
        resolve_udp_target(dns_cache.as_ref(), &target, prefer_ipv4_upstream).await?;
    debug!(
        user = packet.user.id(),
        client_addr = %client_addr,
        target = %target_display,
        resolved = %resolved,
        plaintext_bytes = payload.len(),
        "socket udp resolved target"
    );
    debug!(
        user = packet.user.id(),
        fwmark = ?packet.user.fwmark(),
        client_addr = %client_addr,
        target = %target_display,
        resolved = %resolved,
        "socket udp datagram relay"
    );

    let nat_key = NatKey {
        user_id: Arc::clone(&user_id),
        fwmark: packet.user.fwmark(),
        target: resolved,
    };
    let entry = nat_table
        .get_or_create(nat_key, &packet.user, packet.session.clone(), Arc::clone(&metrics))
        .await
        .with_context(|| format!("failed to create NAT entry for {resolved}"))?;

    entry
        .register_session(
            UdpResponseSender::new(Arc::new(DatagramResponseSender {
                socket: outbound_socket,
                client_addr,
            })),
            packet.session.clone(),
        )
        .await;

    if payload.len() > MAX_UDP_PAYLOAD_SIZE {
        metrics.record_udp_oversized_datagram_dropped(
            Arc::clone(&user_id),
            Protocol::Socket,
            "client_to_target",
        );
        warn!(
            user = packet.user.id(),
            client_addr = %client_addr,
            target = %resolved,
            plaintext_bytes = payload.len(),
            max_udp_payload_bytes = MAX_UDP_PAYLOAD_SIZE,
            "dropping oversized socket udp datagram before upstream send"
        );
        metrics.record_udp_request(
            Arc::clone(&user_id),
            Protocol::Socket,
            "error",
            started_at.elapsed().as_secs_f64(),
        );
        return Ok(());
    }
    metrics.record_udp_payload_bytes(
        Arc::clone(&user_id),
        Protocol::Socket,
        "client_to_target",
        payload.len(),
    );
    debug!(
        user = packet.user.id(),
        client_addr = %client_addr,
        target = %resolved,
        plaintext_bytes = payload.len(),
        "socket udp relaying datagram to upstream"
    );
    if let Err(error) = entry.socket().send_to(payload, resolved).await {
        metrics.record_udp_request(
            Arc::clone(&user_id),
            Protocol::Socket,
            "error",
            started_at.elapsed().as_secs_f64(),
        );
        return Err(error).with_context(|| format!("failed to send UDP datagram to {resolved}"));
    }
    entry.touch();
    metrics.record_udp_request(
        user_id,
        Protocol::Socket,
        "success",
        started_at.elapsed().as_secs_f64(),
    );

    Ok(())
}
