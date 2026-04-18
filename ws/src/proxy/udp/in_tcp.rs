use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::metrics;
use socks5_proto::{SOCKS_STATUS_SUCCESS, read_udp_tcp_packet, send_reply};
use crate::types::{TargetAddr, socket_addr_to_target};
use outline_uplink::UplinkRegistry;

use crate::proxy::ProxyConfig;

use super::assoc::{AssocGroupMap, UdpResponse, resolve_group_context};
use super::dispatch::{
    MAX_CLIENT_UDP_PACKET_SIZE, MAX_UDP_RELAY_PACKET_SIZE, send_tunneled_udp, send_udp_direct,
    udp_metric_payload_len,
};
use super::routing::{UdpPacketRoute, UdpRouteCache, resolve_udp_packet_route, routing_table_active};

pub(in crate::proxy) async fn handle_udp_in_tcp(
    mut client: TcpStream,
    config: Arc<ProxyConfig>,
    registry: UplinkRegistry,
    client_hint: TargetAddr,
) -> Result<()> {
    let session = metrics::track_session("udp");
    let result = async {
        let bind_ip = client.local_addr()?.ip();
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

        send_reply(&mut client, SOCKS_STATUS_SUCCESS, &client_hint).await?;

        let (mut client_read, mut client_write) = client.into_split();

        let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(64);

        let tcp_writer = async move {
            while let Some(frame) = write_rx.recv().await {
                client_write
                    .write_all(&frame)
                    .await
                    .context("UDP-in-TCP client write failed")?;
            }
            Ok::<(), anyhow::Error>(())
        };

        let groups = AssocGroupMap::new();
        let (responses_tx, mut responses_rx) = mpsc::channel::<UdpResponse>(64);

        let groups_uplink = Arc::clone(&groups);
        let registry_uplink = registry.clone();
        let direct_socket_uplink = direct_socket.clone();
        let dns_cache_uplink = Arc::clone(&config.dns_cache);
        let config_uplink = Arc::clone(&config);
        let responses_tx_uplink = responses_tx.clone();
        let uplink = async move {
            let mut route_cache: UdpRouteCache = HashMap::new();
            loop {
                let Some(packet) = read_udp_tcp_packet(&mut client_read).await? else {
                    break;
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
                        debug!(target = %packet.target, "UDP-in-TCP route: policy drop");
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
                        target = %packet.target,
                        payload_len = payload.len(),
                        limit = MAX_CLIENT_UDP_PACKET_SIZE,
                        "dropping oversized incoming UDP-in-TCP packet"
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
            Ok::<(), anyhow::Error>(())
        };

        let write_tx_writer = write_tx.clone();
        let writer = async move {
            while let Some(response) = responses_rx.recv().await {
                write_udp_tcp_response(
                    &write_tx_writer,
                    &response.target,
                    &response.payload,
                    "upstream UDP-in-TCP response",
                )
                .await?;
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
            }
            Ok::<(), anyhow::Error>(())
        };

        let write_tx_direct = write_tx.clone();
        let direct_downlink = async move {
            let Some(sock) = direct_socket else {
                std::future::pending::<()>().await;
                unreachable!()
            };
            let mut buf = vec![0u8; MAX_UDP_RELAY_PACKET_SIZE];
            loop {
                let (len, src_addr) =
                    sock.recv_from(&mut buf).await.context("direct UDP recv failed")?;
                let target = socket_addr_to_target(src_addr);
                let metric_payload_len = udp_metric_payload_len(&target, len)?;
                write_udp_tcp_response(
                    &write_tx_direct,
                    &target,
                    &buf[..len],
                    "direct UDP-in-TCP response",
                )
                .await?;
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
            result = direct_downlink => result,
            result = tcp_writer => result,
        };
        groups.shutdown("session_end").await;
        session_result
    }
    .await;
    session.finish(result.is_ok());
    result
}

async fn write_udp_tcp_response(
    write_tx: &mpsc::Sender<Vec<u8>>,
    target: &TargetAddr,
    payload: &[u8],
    context: &'static str,
) -> Result<()> {
    let addr_wire = target.to_wire_bytes()?;
    let header_len = 3 + addr_wire.len();
    if header_len > usize::from(u8::MAX) || payload.len() > usize::from(u16::MAX) {
        warn!(
            target = %target,
            payload_len = payload.len(),
            context,
            "dropping oversized outgoing UDP-in-TCP response"
        );
        metrics::record_dropped_oversized_udp_packet("outgoing");
        return Ok(());
    }

    let data_len = payload.len() as u16;
    let header_len = header_len as u8;

    let mut frame = Vec::with_capacity(2 + 1 + addr_wire.len() + payload.len());
    frame.extend_from_slice(&data_len.to_be_bytes());
    frame.push(header_len);
    frame.extend_from_slice(&addr_wire);
    frame.extend_from_slice(payload);

    write_tx
        .send(frame)
        .await
        .with_context(|| format!("failed to write {context}: TCP writer task exited"))
}
