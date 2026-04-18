mod assoc;
mod routing;
mod transport;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, warn};

use shadowsocks_crypto::SHADOWSOCKS_MAX_PAYLOAD;
use crate::metrics;
use socks5_proto::{
    SOCKS_STATUS_SUCCESS, UdpFragmentReassembler, build_udp_packet, parse_udp_request,
    read_udp_tcp_packet, send_reply,
};
use outline_transport::is_dropped_oversized_udp_error;
use crate::types::{TargetAddr, socket_addr_to_target};
use outline_uplink::{TransportKind, UplinkRegistry};

use crate::proxy::ProxyConfig;

use self::assoc::{AssocGroupMap, GroupUdpContext, UdpResponse, resolve_group_context};
use self::routing::{UdpPacketRoute, UdpRouteCache, resolve_udp_packet_route, routing_table_active};
use self::transport::{failover_udp_transport, reconcile_global_udp_transport};

const MAX_CLIENT_UDP_PACKET_SIZE: usize = SHADOWSOCKS_MAX_PAYLOAD;
const MAX_UDP_RELAY_PACKET_SIZE: usize = 65_507;

fn udp_metric_payload_len(target: &TargetAddr, payload_len: usize) -> Result<usize> {
    Ok(target.to_wire_bytes()?.len().saturating_add(payload_len))
}

pub(super) async fn handle_udp_associate(
    mut client: TcpStream,
    config: Arc<ProxyConfig>,
    registry: UplinkRegistry,
    _client_hint: TargetAddr,
) -> Result<()> {
    let session = metrics::track_session("udp");
    let result = async {
        let bind_ip = client.local_addr()?.ip();
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

        let client_udp_addr = Arc::new(Mutex::new(None::<SocketAddr>));
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
                *client_udp_addr_uplink.lock().await = Some(addr);

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
                let client_addr = client_udp_addr_writer.lock().await.ok_or_else(|| {
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
                let client_addr = client_udp_addr_direct.lock().await.ok_or_else(|| {
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

pub(super) async fn handle_udp_in_tcp(
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

/// Forward a datagram to a directly-contacted server via the direct socket.
/// Domain targets are resolved through the shared DNS cache, mirroring the
/// TCP direct path so SOCKS5 UDP ASSOCIATE clients that send `ATYP=03` can
/// use policy-direct routing.
async fn send_udp_direct(
    direct_socket: &Option<Arc<UdpSocket>>,
    target: &TargetAddr,
    payload: &[u8],
    cache: &outline_transport::DnsCache,
) -> Result<()> {
    let Some(sock) = direct_socket else {
        warn!(target = %target, "UDP direct route requested but direct socket not allocated; dropping");
        return Ok(());
    };
    let metric_payload_len = udp_metric_payload_len(target, payload.len())?;
    let target_addr = match target {
        TargetAddr::IpV4(ip, port) => SocketAddr::new(std::net::IpAddr::V4(*ip), *port),
        TargetAddr::IpV6(ip, port) => SocketAddr::new(std::net::IpAddr::V6(*ip), *port),
        TargetAddr::Domain(host, port) => {
            let resolved = outline_transport::resolve_host_with_preference(
                cache,
                host,
                *port,
                "UDP direct resolve",
                false,
            )
            .await
            .with_context(|| format!("UDP direct: failed to resolve {target}"))?;
            match resolved.first().copied() {
                Some(addr) => addr,
                None => {
                    warn!(target = %target, "UDP direct: DNS returned no addresses; dropping");
                    return Ok(());
                },
            }
        },
    };
    sock.send_to(payload, target_addr)
        .await
        .context("direct UDP send failed")?;
    metrics::add_udp_datagram(
        "client_to_upstream",
        metrics::DIRECT_GROUP_LABEL,
        metrics::DIRECT_UPLINK_LABEL,
    );
    metrics::add_bytes(
        "udp",
        "client_to_upstream",
        metrics::DIRECT_GROUP_LABEL,
        metrics::DIRECT_UPLINK_LABEL,
        metric_payload_len,
    );
    Ok(())
}

/// Send a pre-wrapped payload through a group's active transport, with
/// reconciliation + runtime failover mirroring the pre-refactor uplink loop.
async fn send_tunneled_udp(
    ctx: &GroupUdpContext,
    target: Option<&TargetAddr>,
    payload: &[u8],
) -> Result<()> {
    reconcile_global_udp_transport(&ctx.manager, &ctx.active, target).await?;
    let (transport, uplink_name, active_index) = {
        let active = ctx.active.lock().await;
        (Arc::clone(&active.transport), active.uplink_name.clone(), active.index)
    };
    let group = ctx.manager.group_name();
    if let Err(error) = transport.send_packet(payload).await {
        if is_dropped_oversized_udp_error(&error) {
            return Ok(());
        }
        let replacement =
            failover_udp_transport(&ctx.manager, &ctx.active, target, active_index, error).await?;
        if let Err(error) = replacement.transport.send_packet(payload).await {
            if is_dropped_oversized_udp_error(&error) {
                return Ok(());
            }
            return Err(error);
        }
        metrics::add_udp_datagram("client_to_upstream", group, &replacement.uplink_name);
        metrics::add_bytes(
            "udp",
            "client_to_upstream",
            group,
            &replacement.uplink_name,
            payload.len(),
        );
        ctx.manager.report_active_traffic(replacement.index, TransportKind::Udp).await;
    } else {
        metrics::add_udp_datagram("client_to_upstream", group, &uplink_name);
        metrics::add_bytes("udp", "client_to_upstream", group, &uplink_name, payload.len());
        ctx.manager.report_active_traffic(active_index, TransportKind::Udp).await;
    }
    Ok(())
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
