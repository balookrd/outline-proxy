use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use tokio::io::AsyncReadExt;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::config::AppConfig;
use crate::crypto::SHADOWSOCKS_MAX_PAYLOAD;
use crate::metrics;
use crate::socks5::{
    build_udp_packet, parse_udp_request, read_udp_tcp_packet, send_reply, write_udp_tcp_packet,
    UdpFragmentReassembler, SOCKS_STATUS_SUCCESS,
};
use crate::transport::{is_dropped_oversized_udp_error, UdpWsTransport};
use crate::types::{socket_addr_to_target, TargetAddr};
use crate::uplink::{TransportKind, UplinkManager};

#[derive(Clone)]
pub(super) struct ActiveUdpTransport {
    pub(super) index: usize,
    pub(super) uplink_name: String,
    pub(super) uplink_weight: f64,
    pub(super) transport: Arc<UdpWsTransport>,
}

const MAX_CLIENT_UDP_PACKET_SIZE: usize = SHADOWSOCKS_MAX_PAYLOAD;
const MAX_UDP_RELAY_PACKET_SIZE: usize = 65_507;

fn udp_metric_payload_len(target: &TargetAddr, payload_len: usize) -> Result<usize> {
    Ok(target.to_wire_bytes()?.len().saturating_add(payload_len))
}

pub(super) async fn handle_udp_associate(
    mut client: TcpStream,
    config: AppConfig,
    uplinks: UplinkManager,
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

        // Optional socket for direct (bypass) UDP packets.
        let bypass_socket = if config.bypass.is_some() {
            let sock = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
                .await
                .with_context(|| format!("failed to bind bypass UDP socket on {}", bind_ip))?;
            Some(Arc::new(sock))
        } else {
            None
        };
        let bypass = config.bypass.clone();

        let active_transport = Arc::new(Mutex::new(select_udp_transport(&uplinks, None).await?));
        let (initial_uplink_name, initial_weight) = {
            let active = active_transport.lock().await;
            (active.uplink_name.clone(), active.uplink_weight)
        };
        metrics::record_uplink_selected("udp", &initial_uplink_name);
        info!(
            uplink = %initial_uplink_name,
            weight = initial_weight,
            "selected UDP uplink"
        );
        let client_udp_addr = Arc::new(Mutex::new(None::<SocketAddr>));

        send_reply(&mut client, SOCKS_STATUS_SUCCESS, &socket_addr_to_target(relay_addr)).await?;

        let client_udp_addr_uplink = Arc::clone(&client_udp_addr);
        let socket_uplink = Arc::clone(&udp_socket);
        let active_transport_uplink = Arc::clone(&active_transport);
        let uplinks_uplink = uplinks.clone();
        let bypass_socket_uplink = bypass_socket.clone();
        let bypass_uplink = bypass.clone();
        let uplink = async move {
            let mut buf = vec![0u8; 65_535];
            let mut reassembler = UdpFragmentReassembler::default();
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

                // Bypass: send directly without going through the uplink.
                if let (Some(sock), Some(bl)) = (&bypass_socket_uplink, &bypass_uplink) {
                    if bl.read().await.is_bypassed(&packet.target) {
                        let metric_payload_len =
                            udp_metric_payload_len(&packet.target, packet.payload.len())?;
                        let target_addr = match &packet.target {
                            crate::types::TargetAddr::IpV4(ip, port) => {
                                SocketAddr::new(std::net::IpAddr::V4(*ip), *port)
                            },
                            crate::types::TargetAddr::IpV6(ip, port) => {
                                SocketAddr::new(std::net::IpAddr::V6(*ip), *port)
                            },
                            crate::types::TargetAddr::Domain(_, _) => {
                                unreachable!("domains return false from is_bypassed")
                            },
                        };
                        sock.send_to(&packet.payload, target_addr)
                            .await
                            .context("bypass UDP send failed")?;
                        metrics::add_udp_datagram(
                            "client_to_upstream",
                            metrics::BYPASS_UPLINK_LABEL,
                        );
                        metrics::add_bytes(
                            "udp",
                            "client_to_upstream",
                            metrics::BYPASS_UPLINK_LABEL,
                            metric_payload_len,
                        );
                        continue;
                    }
                }

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
                reconcile_global_udp_transport(
                    &uplinks_uplink,
                    &active_transport_uplink,
                    Some(&packet.target),
                )
                .await?;
                let (transport, uplink_name, active_index) = {
                    let active = active_transport_uplink.lock().await;
                    (Arc::clone(&active.transport), active.uplink_name.clone(), active.index)
                };
                if let Err(error) = transport.send_packet(&payload).await {
                    if is_dropped_oversized_udp_error(&error) {
                        continue;
                    }
                    let replacement = failover_udp_transport(
                        &uplinks_uplink,
                        &active_transport_uplink,
                        Some(&packet.target),
                        active_index,
                        error,
                    )
                    .await?;
                    if let Err(error) = replacement.transport.send_packet(&payload).await {
                        if is_dropped_oversized_udp_error(&error) {
                            continue;
                        }
                        return Err(error);
                    }
                    metrics::add_udp_datagram("client_to_upstream", &replacement.uplink_name);
                    metrics::add_bytes(
                        "udp",
                        "client_to_upstream",
                        &replacement.uplink_name,
                        payload.len(),
                    );
                    uplinks_uplink
                        .report_active_traffic(replacement.index, TransportKind::Udp)
                        .await;
                } else {
                    metrics::add_udp_datagram("client_to_upstream", &uplink_name);
                    metrics::add_bytes("udp", "client_to_upstream", &uplink_name, payload.len());
                    uplinks_uplink
                        .report_active_traffic(active_index, TransportKind::Udp)
                        .await;
                }
            }
        };

        let client_udp_addr_downlink = Arc::clone(&client_udp_addr);
        let socket_downlink = Arc::clone(&udp_socket);
        let active_transport_downlink = Arc::clone(&active_transport);
        let uplinks_downlink = uplinks.clone();
        let downlink = async move {
            loop {
                reconcile_global_udp_transport(&uplinks_downlink, &active_transport_downlink, None)
                    .await?;
                let active = {
                    let active = active_transport_downlink.lock().await;
                    (active.index, active.uplink_name.clone(), Arc::clone(&active.transport))
                };
                let payload = match active.2.read_packet().await {
                    Ok(payload) => payload,
                    Err(error) => {
                        let replacement = failover_udp_transport(
                            &uplinks_downlink,
                            &active_transport_downlink,
                            None,
                            active.0,
                            error,
                        )
                        .await?;
                        let payload = replacement.transport.read_packet().await?;
                        metrics::add_udp_datagram("upstream_to_client", &replacement.uplink_name);
                        metrics::add_bytes(
                            "udp",
                            "upstream_to_client",
                            &replacement.uplink_name,
                            payload.len(),
                        );
                        let (target, consumed) = TargetAddr::from_wire_bytes(&payload)?;
                        let client_addr =
                            client_udp_addr_downlink.lock().await.ok_or_else(|| {
                                anyhow!("received UDP response before client sent any packet")
                            })?;
                        let packet = build_udp_packet(&target, &payload[consumed..])?;
                        if packet.len() > MAX_UDP_RELAY_PACKET_SIZE {
                            warn!(
                                %client_addr,
                                target = %target,
                                packet_len = packet.len(),
                                limit = MAX_UDP_RELAY_PACKET_SIZE,
                                "dropping oversized outgoing UDP response"
                            );
                            metrics::record_dropped_oversized_udp_packet("outgoing");
                            continue;
                        }
                        socket_downlink
                            .send_to(&packet, client_addr)
                            .await
                            .context("UDP relay send failed")?;
                        continue;
                    },
                };
                let (target, consumed) = TargetAddr::from_wire_bytes(&payload)?;
                let client_addr = client_udp_addr_downlink.lock().await.ok_or_else(|| {
                    anyhow!("received UDP response before client sent any packet")
                })?;
                let packet = build_udp_packet(&target, &payload[consumed..])?;
                if packet.len() > MAX_UDP_RELAY_PACKET_SIZE {
                    warn!(
                        %client_addr,
                        target = %target,
                        packet_len = packet.len(),
                        limit = MAX_UDP_RELAY_PACKET_SIZE,
                        "dropping oversized outgoing UDP response"
                    );
                    metrics::record_dropped_oversized_udp_packet("outgoing");
                    continue;
                }
                metrics::add_udp_datagram("upstream_to_client", &active.1);
                metrics::add_bytes("udp", "upstream_to_client", &active.1, payload.len());
                socket_downlink
                    .send_to(&packet, client_addr)
                    .await
                    .context("UDP relay send failed")?;
            }
            #[allow(unreachable_code)]
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
            let Some(sock) = bypass_socket else {
                std::future::pending::<()>().await;
                unreachable!()
            };
            let mut buf = vec![0u8; MAX_UDP_RELAY_PACKET_SIZE];
            loop {
                let (len, src_addr) =
                    sock.recv_from(&mut buf).await.context("bypass UDP recv failed")?;
                let client_addr = client_udp_addr_direct.lock().await.ok_or_else(|| {
                    anyhow!("received bypass UDP response before client sent any packet")
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
                        "dropping oversized bypass UDP response"
                    );
                    metrics::record_dropped_oversized_udp_packet("outgoing");
                    continue;
                }
                socket_direct
                    .send_to(&packet, client_addr)
                    .await
                    .context("bypass UDP relay send failed")?;
                metrics::add_udp_datagram("upstream_to_client", metrics::BYPASS_UPLINK_LABEL);
                metrics::add_bytes(
                    "udp",
                    "upstream_to_client",
                    metrics::BYPASS_UPLINK_LABEL,
                    metric_payload_len,
                );
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        };

        let session_result = tokio::select! {
            result = uplink => result,
            result = downlink => result,
            result = control => result,
            result = direct_downlink => result,
        };
        close_active_udp_transport(&active_transport, "session_end").await;
        session_result
    }
    .await;
    session.finish(result.is_ok());
    result
}

pub(super) async fn handle_udp_in_tcp(
    mut client: TcpStream,
    config: AppConfig,
    uplinks: UplinkManager,
    client_hint: TargetAddr,
) -> Result<()> {
    let session = metrics::track_session("udp");
    let result = async {
        let bind_ip = client.local_addr()?.ip();
        let bypass_socket = if config.bypass.is_some() {
            let sock = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
                .await
                .with_context(|| format!("failed to bind bypass UDP socket on {}", bind_ip))?;
            Some(Arc::new(sock))
        } else {
            None
        };
        let bypass = config.bypass.clone();

        let active_transport = Arc::new(Mutex::new(select_udp_transport(&uplinks, None).await?));
        let (initial_uplink_name, initial_weight) = {
            let active = active_transport.lock().await;
            (active.uplink_name.clone(), active.uplink_weight)
        };
        metrics::record_uplink_selected("udp", &initial_uplink_name);
        info!(
            uplink = %initial_uplink_name,
            weight = initial_weight,
            "selected UDP uplink"
        );

        send_reply(&mut client, SOCKS_STATUS_SUCCESS, &client_hint).await?;

        let (mut client_read, client_write) = client.into_split();
        let client_write = Arc::new(Mutex::new(client_write));

        let active_transport_uplink = Arc::clone(&active_transport);
        let uplinks_uplink = uplinks.clone();
        let bypass_socket_uplink = bypass_socket.clone();
        let bypass_uplink = bypass.clone();
        let uplink = async move {
            loop {
                let Some(packet) = read_udp_tcp_packet(&mut client_read).await? else {
                    break;
                };

                if let (Some(sock), Some(bl)) = (&bypass_socket_uplink, &bypass_uplink) {
                    if bl.read().await.is_bypassed(&packet.target) {
                        let metric_payload_len =
                            udp_metric_payload_len(&packet.target, packet.payload.len())?;
                        let target_addr = match &packet.target {
                            crate::types::TargetAddr::IpV4(ip, port) => {
                                SocketAddr::new(std::net::IpAddr::V4(*ip), *port)
                            },
                            crate::types::TargetAddr::IpV6(ip, port) => {
                                SocketAddr::new(std::net::IpAddr::V6(*ip), *port)
                            },
                            crate::types::TargetAddr::Domain(_, _) => {
                                unreachable!("domains return false from is_bypassed")
                            },
                        };
                        sock.send_to(&packet.payload, target_addr)
                            .await
                            .context("bypass UDP send failed")?;
                        metrics::add_udp_datagram(
                            "client_to_upstream",
                            metrics::BYPASS_UPLINK_LABEL,
                        );
                        metrics::add_bytes(
                            "udp",
                            "client_to_upstream",
                            metrics::BYPASS_UPLINK_LABEL,
                            metric_payload_len,
                        );
                        continue;
                    }
                }

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

                reconcile_global_udp_transport(
                    &uplinks_uplink,
                    &active_transport_uplink,
                    Some(&packet.target),
                )
                .await?;
                let (transport, uplink_name, active_index) = {
                    let active = active_transport_uplink.lock().await;
                    (Arc::clone(&active.transport), active.uplink_name.clone(), active.index)
                };
                if let Err(error) = transport.send_packet(&payload).await {
                    if is_dropped_oversized_udp_error(&error) {
                        continue;
                    }
                    let replacement = failover_udp_transport(
                        &uplinks_uplink,
                        &active_transport_uplink,
                        Some(&packet.target),
                        active_index,
                        error,
                    )
                    .await?;
                    if let Err(error) = replacement.transport.send_packet(&payload).await {
                        if is_dropped_oversized_udp_error(&error) {
                            continue;
                        }
                        return Err(error);
                    }
                    metrics::add_udp_datagram("client_to_upstream", &replacement.uplink_name);
                    metrics::add_bytes(
                        "udp",
                        "client_to_upstream",
                        &replacement.uplink_name,
                        payload.len(),
                    );
                    uplinks_uplink
                        .report_active_traffic(replacement.index, TransportKind::Udp)
                        .await;
                } else {
                    metrics::add_udp_datagram("client_to_upstream", &uplink_name);
                    metrics::add_bytes("udp", "client_to_upstream", &uplink_name, payload.len());
                    uplinks_uplink
                        .report_active_traffic(active_index, TransportKind::Udp)
                        .await;
                }
            }
            Ok::<(), anyhow::Error>(())
        };

        let active_transport_downlink = Arc::clone(&active_transport);
        let uplinks_downlink = uplinks.clone();
        let client_write_downlink = Arc::clone(&client_write);
        let downlink = async move {
            loop {
                reconcile_global_udp_transport(&uplinks_downlink, &active_transport_downlink, None)
                    .await?;
                let active = {
                    let active = active_transport_downlink.lock().await;
                    (active.index, active.uplink_name.clone(), Arc::clone(&active.transport))
                };
                let payload = match active.2.read_packet().await {
                    Ok(payload) => payload,
                    Err(error) => {
                        let replacement = failover_udp_transport(
                            &uplinks_downlink,
                            &active_transport_downlink,
                            None,
                            active.0,
                            error,
                        )
                        .await?;
                        let payload = replacement.transport.read_packet().await?;
                        let (target, consumed) = TargetAddr::from_wire_bytes(&payload)?;
                        write_udp_tcp_response(
                            &client_write_downlink,
                            &target,
                            &payload[consumed..],
                            "upstream UDP-in-TCP response",
                        )
                        .await?;
                        metrics::add_udp_datagram("upstream_to_client", &replacement.uplink_name);
                        metrics::add_bytes(
                            "udp",
                            "upstream_to_client",
                            &replacement.uplink_name,
                            payload.len(),
                        );
                        continue;
                    },
                };

                let (target, consumed) = TargetAddr::from_wire_bytes(&payload)?;
                write_udp_tcp_response(
                    &client_write_downlink,
                    &target,
                    &payload[consumed..],
                    "upstream UDP-in-TCP response",
                )
                .await?;
                metrics::add_udp_datagram("upstream_to_client", &active.1);
                metrics::add_bytes("udp", "upstream_to_client", &active.1, payload.len());
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        };

        let client_write_direct = Arc::clone(&client_write);
        let direct_downlink = async move {
            let Some(sock) = bypass_socket else {
                std::future::pending::<()>().await;
                unreachable!()
            };
            let mut buf = vec![0u8; MAX_UDP_RELAY_PACKET_SIZE];
            loop {
                let (len, src_addr) =
                    sock.recv_from(&mut buf).await.context("bypass UDP recv failed")?;
                let target = socket_addr_to_target(src_addr);
                let metric_payload_len = udp_metric_payload_len(&target, len)?;
                write_udp_tcp_response(
                    &client_write_direct,
                    &target,
                    &buf[..len],
                    "bypass UDP-in-TCP response",
                )
                .await?;
                metrics::add_udp_datagram("upstream_to_client", metrics::BYPASS_UPLINK_LABEL);
                metrics::add_bytes(
                    "udp",
                    "upstream_to_client",
                    metrics::BYPASS_UPLINK_LABEL,
                    metric_payload_len,
                );
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        };

        let session_result = tokio::select! {
            result = uplink => result,
            result = downlink => result,
            result = direct_downlink => result,
        };
        close_active_udp_transport(&active_transport, "session_end").await;
        session_result
    }
    .await;
    session.finish(result.is_ok());
    result
}

pub(super) async fn select_udp_transport(
    uplinks: &UplinkManager,
    target: Option<&TargetAddr>,
) -> Result<ActiveUdpTransport> {
    let mut last_error = None;
    let strict_transport = uplinks.strict_active_uplink_for(TransportKind::Udp);
    let candidates = uplinks.udp_candidates(target).await;
    let iter = if strict_transport {
        candidates.into_iter().take(1).collect::<Vec<_>>()
    } else {
        candidates
    };
    for candidate in iter {
        match uplinks.acquire_udp_standby_or_connect(&candidate, "socks_udp").await {
            Ok(transport) => {
                uplinks
                    .confirm_selected_uplink(TransportKind::Udp, target, candidate.index)
                    .await;
                return Ok(ActiveUdpTransport {
                    index: candidate.index,
                    uplink_name: candidate.uplink.name.clone(),
                    uplink_weight: candidate.uplink.weight,
                    transport: Arc::new(transport),
                });
            },
            Err(error) => {
                uplinks
                    .report_runtime_failure(candidate.index, TransportKind::Udp, &error)
                    .await;
                last_error = Some(format!("{}: {error:#}", candidate.uplink.name));
            },
        }
    }

    Err(anyhow!(
        "all UDP uplinks failed: {}",
        last_error.unwrap_or_else(|| "no UDP-capable uplinks available".to_string())
    ))
}

async fn failover_udp_transport(
    uplinks: &UplinkManager,
    active_transport: &Arc<Mutex<ActiveUdpTransport>>,
    target: Option<&TargetAddr>,
    failed_index: usize,
    error: anyhow::Error,
) -> Result<ActiveUdpTransport> {
    let failed_uplink_name = {
        let active = active_transport.lock().await;
        if active.index != failed_index {
            return Ok(active.clone());
        }
        active.uplink_name.clone()
    };
    uplinks
        .report_runtime_failure(failed_index, TransportKind::Udp, &error)
        .await;
    let replacement = select_udp_transport(uplinks, target).await?;
    if let Some(previous_transport) = replace_active_udp_transport_if_current(
        active_transport,
        failed_index,
        ActiveUdpTransport {
            index: replacement.index,
            uplink_name: replacement.uplink_name.clone(),
            uplink_weight: replacement.uplink_weight,
            transport: Arc::clone(&replacement.transport),
        },
    )
    .await
    {
        info!(
            failed_index,
            failed_uplink = %failed_uplink_name,
            new_uplink = %replacement.uplink_name,
            error = %format!("{error:#}"),
            "runtime UDP failover activated"
        );
        metrics::record_failover("udp", &failed_uplink_name, &replacement.uplink_name);
        metrics::record_uplink_selected("udp", &replacement.uplink_name);
        close_udp_transport(previous_transport, "failover").await;
        return Ok(replacement);
    }
    Ok(active_transport.lock().await.clone())
}

async fn reconcile_global_udp_transport(
    uplinks: &UplinkManager,
    active_transport: &Arc<Mutex<ActiveUdpTransport>>,
    target: Option<&TargetAddr>,
) -> Result<()> {
    if !uplinks.strict_active_uplink_for(TransportKind::Udp) {
        return Ok(());
    }

    let current_active = uplinks.active_uplink_index_for_transport(TransportKind::Udp).await;
    let selected = active_transport.lock().await.index;
    if current_active == Some(selected) || current_active.is_none() {
        return Ok(());
    }

    let replaced_uplink_name = {
        let active = active_transport.lock().await;
        if active.index != selected {
            return Ok(());
        }
        active.uplink_name.clone()
    };
    let replacement = select_udp_transport(uplinks, target).await?;
    if let Some(previous_transport) = replace_active_udp_transport_if_current(
        active_transport,
        selected,
        ActiveUdpTransport {
            index: replacement.index,
            uplink_name: replacement.uplink_name.clone(),
            uplink_weight: replacement.uplink_weight,
            transport: Arc::clone(&replacement.transport),
        },
    )
    .await
    {
        metrics::record_failover("udp", &replaced_uplink_name, &replacement.uplink_name);
        metrics::record_uplink_selected("udp", &replacement.uplink_name);
        close_udp_transport(previous_transport, "global_switch").await;
    }
    Ok(())
}

async fn replace_active_udp_transport_if_current(
    active_transport: &Arc<Mutex<ActiveUdpTransport>>,
    expected_index: usize,
    replacement: ActiveUdpTransport,
) -> Option<Arc<UdpWsTransport>> {
    let mut active = active_transport.lock().await;
    if active.index != expected_index {
        return None;
    }
    let previous_transport = Arc::clone(&active.transport);
    *active = replacement;
    Some(previous_transport)
}

async fn close_active_udp_transport(
    active_transport: &Arc<Mutex<ActiveUdpTransport>>,
    reason: &'static str,
) {
    let transport = {
        let active = active_transport.lock().await;
        Arc::clone(&active.transport)
    };
    close_udp_transport(transport, reason).await;
}

async fn close_udp_transport(transport: Arc<UdpWsTransport>, reason: &'static str) {
    if let Err(error) = transport.close().await {
        debug!(
            reason,
            error = %format!("{error:#}"),
            "failed to close SOCKS5 UDP transport"
        );
    }
}

async fn write_udp_tcp_response(
    client_write: &Arc<Mutex<OwnedWriteHalf>>,
    target: &TargetAddr,
    payload: &[u8],
    context: &'static str,
) -> Result<()> {
    let target_wire = target.to_wire_bytes()?;
    if 3 + target_wire.len() > usize::from(u8::MAX) || payload.len() > usize::from(u16::MAX) {
        warn!(
            target = %target,
            payload_len = payload.len(),
            context,
            "dropping oversized outgoing UDP-in-TCP response"
        );
        metrics::record_dropped_oversized_udp_packet("outgoing");
        return Ok(());
    }

    let mut client_write = client_write.lock().await;
    write_udp_tcp_packet(&mut *client_write, target, payload)
        .await
        .with_context(|| format!("failed to write {context}"))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::net::UdpSocket;

    use super::*;
    use crate::types::CipherKind;

    #[tokio::test]
    async fn replacing_active_udp_transport_closes_previous_reader() {
        let old_transport = Arc::new(
            UdpWsTransport::from_socket(
                UdpSocket::bind(("127.0.0.1", 0)).await.unwrap(),
                CipherKind::Chacha20IetfPoly1305,
                "password",
                "test_old",
            )
            .unwrap(),
        );
        let new_transport = Arc::new(
            UdpWsTransport::from_socket(
                UdpSocket::bind(("127.0.0.1", 0)).await.unwrap(),
                CipherKind::Chacha20IetfPoly1305,
                "password",
                "test_new",
            )
            .unwrap(),
        );
        let active_transport = Arc::new(Mutex::new(ActiveUdpTransport {
            index: 1,
            uplink_name: "old".to_string(),
            uplink_weight: 1.0,
            transport: Arc::clone(&old_transport),
        }));

        let reader_transport = Arc::clone(&old_transport);
        let read_task = tokio::spawn(async move { reader_transport.read_packet().await });

        let previous_transport = replace_active_udp_transport_if_current(
            &active_transport,
            1,
            ActiveUdpTransport {
                index: 2,
                uplink_name: "new".to_string(),
                uplink_weight: 1.0,
                transport: Arc::clone(&new_transport),
            },
        )
        .await
        .expect("active transport should be replaced");
        close_udp_transport(previous_transport, "test_replace").await;

        let error = tokio::time::timeout(Duration::from_secs(1), async {
            read_task.await.unwrap().unwrap_err()
        })
        .await
        .unwrap();
        assert!(format!("{error:#}").contains("udp transport closed"));
        assert_eq!(active_transport.lock().await.index, 2);
    }
}
