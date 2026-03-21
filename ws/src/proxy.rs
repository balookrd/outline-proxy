use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::config::AppConfig;
use crate::crypto::SHADOWSOCKS_MAX_PAYLOAD;
use crate::metrics;
use crate::socks5::{
    SOCKS_STATUS_SUCCESS, SocksRequest, UdpFragmentReassembler, build_udp_packet, negotiate,
    parse_udp_request, send_reply,
};
use crate::transport::{
    TcpShadowsocksReader, TcpShadowsocksWriter, UdpWsTransport, UpstreamTransportGuard,
    connect_shadowsocks_tcp_with_source, is_dropped_oversized_udp_error,
};
use crate::types::{TargetAddr, UplinkTransport, socket_addr_to_target};
use crate::uplink::{TransportKind, UplinkManager};

struct ActiveUdpTransport {
    index: usize,
    uplink_name: String,
    uplink_weight: f64,
    transport: Arc<UdpWsTransport>,
}

const MAX_CLIENT_UDP_PACKET_SIZE: usize = SHADOWSOCKS_MAX_PAYLOAD;
const MAX_UDP_RELAY_PACKET_SIZE: usize = 65_507;

pub async fn handle_client(
    mut client: TcpStream,
    peer: SocketAddr,
    config: AppConfig,
    uplinks: UplinkManager,
) -> Result<()> {
    let request = negotiate(&mut client, config.socks5_auth.as_ref()).await?;
    debug!(%peer, ?request, "accepted SOCKS5 request");
    metrics::record_request(match &request {
        SocksRequest::Connect(_) => "connect",
        SocksRequest::UdpAssociate(_) => "udp_associate",
    });

    match request {
        SocksRequest::Connect(target) => handle_tcp_connect(client, config, uplinks, target).await,
        SocksRequest::UdpAssociate(client_hint) => {
            handle_udp_associate(client, config, uplinks, client_hint).await
        }
    }
}

async fn handle_tcp_connect(
    mut client: TcpStream,
    _config: AppConfig,
    uplinks: UplinkManager,
    target: TargetAddr,
) -> Result<()> {
    let session = metrics::track_session("tcp");
    let result = async {
        let mut last_error = None;
        let mut selected = None;
        let strict_transport = uplinks.strict_active_uplink_for(TransportKind::Tcp);
        let mut tried_indexes = std::collections::HashSet::new();
        loop {
            let candidates = uplinks.tcp_candidates(&target).await;
            let iter = if strict_transport {
                candidates.into_iter().take(1).collect::<Vec<_>>()
            } else {
                candidates
            };
            if iter.is_empty() {
                break;
            }
            let mut progressed = false;
            for candidate in iter {
                if strict_transport && !tried_indexes.insert(candidate.index) {
                    continue;
                }
                progressed = true;
                match connect_tcp_uplink(&uplinks, &candidate, &target).await {
                    Ok(connected) => {
                        selected = Some((candidate, connected));
                        break;
                    }
                    Err(error) => {
                        uplinks
                            .report_runtime_failure(candidate.index, TransportKind::Tcp, &error)
                            .await;
                        last_error = Some(format!("{}: {error:#}", candidate.uplink.name));
                    }
                }
            }
            if selected.is_some() || !strict_transport || !progressed {
                break;
            }
        }

        let (candidate, connected) = selected.ok_or_else(|| {
            anyhow!(
                "all TCP uplinks failed: {}",
                last_error.unwrap_or_else(|| "no uplinks available".to_string())
            )
        })?;
        let selected_uplink_name = candidate.uplink.name.clone();
        uplinks
            .confirm_selected_uplink(TransportKind::Tcp, Some(&target), candidate.index)
            .await;
        metrics::record_uplink_selected("tcp", &selected_uplink_name);
        info!(
            uplink = %selected_uplink_name,
            weight = candidate.uplink.weight,
            target = %target,
            "selected TCP uplink"
        );
        let selected_index = candidate.index;
        let (writer, reader) = connected;

        let bound_addr = socket_addr_to_target(client.local_addr()?);
        send_reply(&mut client, SOCKS_STATUS_SUCCESS, &bound_addr).await?;

        let (mut client_read, mut client_write) = client.into_split();
        let uplink_uplink_name = selected_uplink_name.clone();
        let uplinks_uplink = uplinks.clone();
        let uplink = async move {
            let mut writer = writer;
            let mut buf = vec![0u8; SHADOWSOCKS_MAX_PAYLOAD];
            loop {
                if strict_transport
                    && uplinks_uplink
                        .active_uplink_index_for_transport(TransportKind::Tcp)
                        .await
                        .is_some_and(|active| active != selected_index)
                {
                    return Err(anyhow!("active uplink switched for SOCKS TCP session"));
                }
                let read = client_read
                    .read(&mut buf)
                    .await
                    .context("client read failed")?;
                if read == 0 {
                    writer.close().await?;
                    break;
                }
                metrics::add_bytes("tcp", "client_to_upstream", &uplink_uplink_name, read);
                writer.send_chunk(&buf[..read]).await?;
                uplinks_uplink
                    .report_active_traffic(selected_index, TransportKind::Tcp)
                    .await;
            }
            Ok::<(), anyhow::Error>(())
        };

        let downlink_uplink_name = selected_uplink_name.clone();
        let uplinks_downlink = uplinks.clone();
        let downlink = async move {
            let mut reader = reader;
            loop {
                if strict_transport
                    && uplinks_downlink
                        .active_uplink_index_for_transport(TransportKind::Tcp)
                        .await
                        .is_some_and(|active| active != selected_index)
                {
                    return Err(anyhow!("active uplink switched for SOCKS TCP session"));
                }
                let chunk = reader.read_chunk().await?;
                if chunk.is_empty() {
                    continue;
                }
                metrics::add_bytes(
                    "tcp",
                    "upstream_to_client",
                    &downlink_uplink_name,
                    chunk.len(),
                );
                client_write
                    .write_all(&chunk)
                    .await
                    .context("client write failed")?;
                uplinks_downlink
                    .report_active_traffic(selected_index, TransportKind::Tcp)
                    .await;
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        };

        let result = tokio::select! {
            result = uplink => result,
            result = downlink => result,
        };
        // Report mid-stream upstream transport failures so that broken transports
        // (e.g. H3 APPLICATION_CLOSE received after session establishment) trigger
        // the H3→H2 downgrade and flush stale warm-standby connections immediately,
        // rather than waiting for the next connection attempt to fail.
        // Client-side disconnects and intentional uplink switches are excluded.
        if let Err(ref err) = result {
            let msg = format!("{err:#}");
            let is_upstream_failure = !msg.contains("client read failed")
                && !msg.contains("client write failed")
                && !msg.contains("active uplink switched")
                && !msg.contains("websocket closed");
            if is_upstream_failure {
                uplinks
                    .report_runtime_failure(selected_index, TransportKind::Tcp, err)
                    .await;
            } else if msg.contains("websocket closed") {
                // The upstream server closed the WebSocket connection
                // mid-stream (server-initiated close, not a client
                // disconnect).  We do not set a full runtime-failure
                // cooldown to avoid penalising the uplink for normal
                // per-connection lifetime limits, but we clear the
                // activity timestamp so the probe is not skipped on the
                // next cycle — this lets the probe detect a downed server
                // promptly rather than waiting for probe.interval of silence.
                uplinks
                    .report_upstream_close(selected_index, TransportKind::Tcp)
                    .await;
            }
        }
        result
    }
    .await;
    session.finish(result.is_ok());
    result
}

async fn handle_udp_associate(
    mut client: TcpStream,
    _config: AppConfig,
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
        let relay_addr = udp_socket
            .local_addr()
            .context("failed to read UDP relay address")?;

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

        send_reply(
            &mut client,
            SOCKS_STATUS_SUCCESS,
            &socket_addr_to_target(relay_addr),
        )
        .await?;

        let client_udp_addr_uplink = Arc::clone(&client_udp_addr);
        let socket_uplink = Arc::clone(&udp_socket);
        let active_transport_uplink = Arc::clone(&active_transport);
        let uplinks_uplink = uplinks.clone();
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
                let (transport, uplink_name) = {
                    let active = active_transport_uplink.lock().await;
                    (Arc::clone(&active.transport), active.uplink_name.clone())
                };
                let active_index = active_transport_uplink.lock().await.index;
                if let Err(error) = transport.send_packet(&payload).await {
                    if is_dropped_oversized_udp_error(&error) {
                        continue;
                    }
                    let replacement = failover_udp_transport(
                        &uplinks_uplink,
                        &active_transport_uplink,
                        Some(&packet.target),
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
                    (
                        active.index,
                        active.uplink_name.clone(),
                        Arc::clone(&active.transport),
                    )
                };
                let payload = match active.2.read_packet().await {
                    Ok(payload) => payload,
                    Err(error) => {
                        let replacement = failover_udp_transport(
                            &uplinks_downlink,
                            &active_transport_downlink,
                            None,
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
                    }
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

        tokio::select! {
            result = uplink => result,
            result = downlink => result,
            result = control => result,
        }
    }
    .await;
    session.finish(result.is_ok());
    result
}

async fn connect_tcp_uplink(
    uplinks: &UplinkManager,
    candidate: &crate::uplink::UplinkCandidate,
    target: &TargetAddr,
) -> Result<(TcpShadowsocksWriter, TcpShadowsocksReader)> {
    if candidate.uplink.transport == UplinkTransport::Shadowsocks {
        let stream = connect_shadowsocks_tcp_with_source(
            candidate
                .uplink
                .tcp_addr
                .as_ref()
                .ok_or_else(|| anyhow!("uplink {} missing tcp_addr", candidate.uplink.name))?,
            candidate.uplink.fwmark,
            candidate.uplink.ipv6_first,
            "socks_tcp",
        )
        .await?;
        return do_tcp_ss_setup_socket(stream, &candidate.uplink, target, "socks_tcp").await;
    }

    // Variant A: try a standby pool connection first.  If it turns out to be
    // stale (fails before any server bytes arrive), discard it silently and
    // retry with a fresh on-demand dial — without recording a runtime failure.
    if let Some(ws) = uplinks.try_take_tcp_standby(candidate).await {
        match do_tcp_ss_setup(ws, &candidate.uplink, target, "socks_tcp").await {
            Ok(v) => return Ok(v),
            Err(e) => {
                debug!(
                    uplink = %candidate.uplink.name,
                    error = %format!("{e:#}"),
                    "stale standby TCP pool connection, retrying with fresh dial"
                );
            }
        }
    }

    let ws = uplinks.connect_tcp_ws_fresh(candidate, "socks_tcp").await?;
    do_tcp_ss_setup(ws, &candidate.uplink, target, "socks_tcp").await
}

async fn do_tcp_ss_setup(
    ws_stream: crate::transport::AnyWsStream,
    uplink: &crate::config::UplinkConfig,
    target: &TargetAddr,
    source: &'static str,
) -> Result<(TcpShadowsocksWriter, TcpShadowsocksReader)> {
    let (ws_sink, ws_stream) = ws_stream.split();
    let master_key = uplink.cipher.derive_master_key(&uplink.password)?;
    let lifetime = UpstreamTransportGuard::new(source, "tcp");
    let (mut writer, ctrl_tx) =
        TcpShadowsocksWriter::connect(ws_sink, uplink.cipher, &master_key, Arc::clone(&lifetime))
            .await?;
    let request_salt = writer.request_salt().map(|salt| salt.to_vec());
    let reader =
        TcpShadowsocksReader::new(ws_stream, uplink.cipher, &master_key, lifetime, ctrl_tx)
            .with_request_salt(request_salt);
    writer
        .send_chunk(&target.to_wire_bytes()?)
        .await
        .context("failed to send target address")?;
    Ok((writer, reader))
}

async fn do_tcp_ss_setup_socket(
    stream: TcpStream,
    uplink: &crate::config::UplinkConfig,
    target: &TargetAddr,
    source: &'static str,
) -> Result<(TcpShadowsocksWriter, TcpShadowsocksReader)> {
    let (reader_half, writer_half) = stream.into_split();
    let master_key = uplink.cipher.derive_master_key(&uplink.password)?;
    let lifetime = UpstreamTransportGuard::new(source, "tcp");
    let mut writer = TcpShadowsocksWriter::connect_socket(
        writer_half,
        uplink.cipher,
        &master_key,
        Arc::clone(&lifetime),
    )?;
    let reader =
        TcpShadowsocksReader::new_socket(reader_half, uplink.cipher, &master_key, lifetime)
            .with_request_salt(writer.request_salt().map(|salt| salt.to_vec()));
    writer
        .send_chunk(&target.to_wire_bytes()?)
        .await
        .context("failed to send target address")?;
    Ok((writer, reader))
}

async fn select_udp_transport(
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
        match uplinks
            .acquire_udp_standby_or_connect(&candidate, "socks_udp")
            .await
        {
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
            }
            Err(error) => {
                uplinks
                    .report_runtime_failure(candidate.index, TransportKind::Udp, &error)
                    .await;
                last_error = Some(format!("{}: {error:#}", candidate.uplink.name));
            }
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
    error: anyhow::Error,
) -> Result<ActiveUdpTransport> {
    let failed = active_transport.lock().await.index;
    uplinks
        .report_runtime_failure(failed, TransportKind::Udp, &error)
        .await;
    let replacement = select_udp_transport(uplinks, target).await?;
    info!(
        failed_index = failed,
        new_uplink = %replacement.uplink_name,
        error = %format!("{error:#}"),
        "runtime UDP failover activated"
    );
    let mut active = active_transport.lock().await;
    metrics::record_failover("udp", &active.uplink_name, &replacement.uplink_name);
    metrics::record_uplink_selected("udp", &replacement.uplink_name);
    *active = ActiveUdpTransport {
        index: replacement.index,
        uplink_name: replacement.uplink_name.clone(),
        uplink_weight: replacement.uplink_weight,
        transport: Arc::clone(&replacement.transport),
    };
    Ok(replacement)
}

async fn reconcile_global_udp_transport(
    uplinks: &UplinkManager,
    active_transport: &Arc<Mutex<ActiveUdpTransport>>,
    target: Option<&TargetAddr>,
) -> Result<()> {
    if !uplinks.strict_active_uplink_for(TransportKind::Udp) {
        return Ok(());
    }

    let current_active = uplinks
        .active_uplink_index_for_transport(TransportKind::Udp)
        .await;
    let selected = active_transport.lock().await.index;
    if current_active == Some(selected) || current_active.is_none() {
        return Ok(());
    }

    let replacement = select_udp_transport(uplinks, target).await?;
    let mut active = active_transport.lock().await;
    metrics::record_failover("udp", &active.uplink_name, &replacement.uplink_name);
    metrics::record_uplink_selected("udp", &replacement.uplink_name);
    *active = ActiveUdpTransport {
        index: replacement.index,
        uplink_name: replacement.uplink_name.clone(),
        uplink_weight: replacement.uplink_weight,
        transport: Arc::clone(&replacement.transport),
    };
    Ok(())
}
