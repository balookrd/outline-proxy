use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{OnceCell, mpsc};
use tracing::{debug, warn};

use crate::metrics;
use socks5_proto::{
    SOCKS_STATUS_SUCCESS, UdpFragmentReassembler, build_udp_packet, parse_udp_request,
    send_reply,
};
use crate::types::{TargetAddr, socket_addr_to_target};
use outline_uplink::UplinkRegistry;

use crate::proxy::ProxyConfig;

use super::assoc::{AssocGroupMap, UdpResponse, resolve_group_context};
use super::dispatch::{
    MAX_CLIENT_UDP_PACKET_SIZE, MAX_UDP_RELAY_PACKET_SIZE, send_tunneled_udp, send_udp_direct,
    udp_metric_payload_len,
};
use super::routing::{UdpPacketRoute, UdpRouteCache, resolve_udp_packet_route, routing_table_active};

pub(in crate::proxy) async fn handle_udp_associate(
    mut client: TcpStream,
    config: Arc<ProxyConfig>,
    registry: UplinkRegistry,
    _client_hint: TargetAddr,
) -> Result<()> {
    let session = metrics::track_session("udp");
    let result = async {
        let bind_ip = client.local_addr()?.ip();
        let client_peer_ip = client.peer_addr()?.ip();
        let udp_socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
            .await
            .with_context(|| format!("failed to bind UDP relay on {}", bind_ip))?;
        let udp_socket = Arc::new(udp_socket);
        let relay_addr = udp_socket.local_addr().context("failed to read UDP relay address")?;

        // Optional socket for direct UDP packets with fwmark to prevent
        // loopback through TUN when all traffic is captured.
        let direct_socket = if routing_table_active(&config) {
            let std_sock = outline_transport::bind_udp_socket(
                SocketAddr::new(bind_ip, 0),
                config.direct_fwmark,
            )
            .with_context(|| format!("failed to bind direct UDP socket on {}", bind_ip))?;
            Some(Arc::new(UdpSocket::from_std(std_sock)?))
        } else {
            None
        };

        let client_udp_addr: Arc<OnceCell<SocketAddr>> = Arc::new(OnceCell::new());
        let groups = AssocGroupMap::new();
        let (responses_tx, mut responses_rx) = mpsc::channel::<UdpResponse>(64);

        send_reply(&mut client, SOCKS_STATUS_SUCCESS, &socket_addr_to_target(relay_addr)).await?;

        let client_udp_addr_uplink = Arc::clone(&client_udp_addr);
        let socket_uplink = Arc::clone(&udp_socket);
        let groups_uplink = Arc::clone(&groups);
        let registry_uplink = registry.clone();
        let direct_socket_uplink = direct_socket.clone();
        let dns_cache_uplink = Arc::clone(&config.dns_cache);
        let config_uplink = Arc::clone(&config);
        let responses_tx_uplink = responses_tx.clone();
        let uplink = async move {
            let mut buf = vec![0u8; 65_535];
            let mut reassembler = UdpFragmentReassembler::default();
            let mut route_cache: UdpRouteCache = HashMap::new();
            loop {
                let (len, addr) = socket_uplink
                    .recv_from(&mut buf)
                    .await
                    .context("UDP relay receive failed")?;
                if addr.ip() != client_peer_ip {
                    debug!(%addr, expected_ip = %client_peer_ip, "dropping UDP packet from unexpected source");
                    continue;
                }
                match client_udp_addr_uplink.get() {
                    Some(locked) if *locked != addr => {
                        debug!(%addr, locked = %locked, "dropping UDP packet from unexpected port");
                        continue;
                    },
                    Some(_) => {},
                    None => {
                        let _ = client_udp_addr_uplink.set(addr);
                    },
                }

                let packet = parse_udp_request(&buf[..len])?;
                let Some(packet) = reassembler.push_fragment(packet)? else {
                    continue;
                };

                let group_name = match resolve_udp_packet_route(
                    &mut route_cache,
                    &config_uplink,
                    &registry_uplink,
                    &packet.target,
                )
                .await
                {
                    UdpPacketRoute::Drop => {
                        debug!(target = %packet.target, "UDP route: policy drop");
                        continue;
                    },
                    UdpPacketRoute::Direct => {
                        send_udp_direct(
                            &direct_socket_uplink,
                            &packet.target,
                            &packet.payload,
                            &dns_cache_uplink,
                        )
                        .await?;
                        continue;
                    },
                    UdpPacketRoute::Tunnel(name) => name,
                };

                let mut payload = packet.target.to_wire_bytes()?;
                payload.extend_from_slice(&packet.payload);
                if payload.len() > MAX_CLIENT_UDP_PACKET_SIZE {
                    warn!(
                        %addr,
                        target = %packet.target,
                        payload_len = payload.len(),
                        limit = MAX_CLIENT_UDP_PACKET_SIZE,
                        "dropping oversized incoming UDP packet"
                    );
                    metrics::record_dropped_oversized_udp_packet("incoming");
                    continue;
                }

                let ctx = resolve_group_context(
                    &groups_uplink,
                    &registry_uplink,
                    &group_name,
                    &responses_tx_uplink,
                )
                .await?;
                send_tunneled_udp(&ctx, Some(&packet.target), &payload).await?;
            }
        };

        let client_udp_addr_writer = Arc::clone(&client_udp_addr);
        let socket_writer = Arc::clone(&udp_socket);
        let writer = async move {
            while let Some(response) = responses_rx.recv().await {
                let client_addr = *client_udp_addr_writer.get().ok_or_else(|| {
                    anyhow!("received UDP response before client sent any packet")
                })?;
                let packet = build_udp_packet(&response.target, &response.payload)?;
                if packet.len() > MAX_UDP_RELAY_PACKET_SIZE {
                    warn!(
                        %client_addr,
                        target = %response.target,
                        packet_len = packet.len(),
                        limit = MAX_UDP_RELAY_PACKET_SIZE,
                        "dropping oversized outgoing UDP response"
                    );
                    metrics::record_dropped_oversized_udp_packet("outgoing");
                    continue;
                }
                metrics::add_udp_datagram(
                    "upstream_to_client",
                    &response.group_name,
                    &response.uplink_name,
                );
                metrics::add_bytes(
                    "udp",
                    "upstream_to_client",
                    &response.group_name,
                    &response.uplink_name,
                    response.payload.len(),
                );
                socket_writer
                    .send_to(&packet, client_addr)
                    .await
                    .context("UDP relay send failed")?;
            }
            Ok::<(), anyhow::Error>(())
        };

        let control = async move {
            let mut buf = [0u8; 1];
            loop {
                let read = client
                    .read(&mut buf)
                    .await
                    .context("control connection read failed")?;
                if read == 0 {
                    break;
                }
            }
            Ok::<(), anyhow::Error>(())
        };

        // Receive responses from directly-contacted servers and forward to the client.
        let client_udp_addr_direct = Arc::clone(&client_udp_addr);
        let socket_direct = Arc::clone(&udp_socket);
        let direct_downlink = async move {
            let Some(sock) = direct_socket else {
                std::future::pending::<()>().await;
                unreachable!()
            };
            let mut buf = vec![0u8; MAX_UDP_RELAY_PACKET_SIZE];
            loop {
                let (len, src_addr) =
                    sock.recv_from(&mut buf).await.context("direct UDP recv failed")?;
                let client_addr = *client_udp_addr_direct.get().ok_or_else(|| {
                    anyhow!("received direct UDP response before client sent any packet")
                })?;
                let target = socket_addr_to_target(src_addr);
                let metric_payload_len = udp_metric_payload_len(&target, len)?;
                let packet = build_udp_packet(&target, &buf[..len])?;
                if packet.len() > MAX_UDP_RELAY_PACKET_SIZE {
                    warn!(
                        %client_addr,
                        target = %target,
                        packet_len = packet.len(),
                        limit = MAX_UDP_RELAY_PACKET_SIZE,
                        "dropping oversized direct UDP response"
                    );
                    metrics::record_dropped_oversized_udp_packet("outgoing");
                    continue;
                }
                socket_direct
                    .send_to(&packet, client_addr)
                    .await
                    .context("direct UDP relay send failed")?;
                metrics::add_udp_datagram(
                    "upstream_to_client",
                    metrics::DIRECT_GROUP_LABEL,
                    metrics::DIRECT_UPLINK_LABEL,
                );
                metrics::add_bytes(
                    "udp",
                    "upstream_to_client",
                    metrics::DIRECT_GROUP_LABEL,
                    metrics::DIRECT_UPLINK_LABEL,
                    metric_payload_len,
                );
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        };

        let session_result = tokio::select! {
            result = uplink => result,
            result = writer => result,
            result = control => result,
            result = direct_downlink => result,
        };
        groups.shutdown("session_end").await;
        session_result
    }
    .await;
    session.finish(result.is_ok());
    result
}
