use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tracing::{debug, info};

use crate::config::AppConfig;
use crate::crypto::SHADOWSOCKS_MAX_PAYLOAD;
use crate::metrics;
use crate::socks5::{
    SOCKS_STATUS_SUCCESS, SocksRequest, UdpFragmentReassembler, build_udp_packet, negotiate,
    parse_udp_request, send_reply,
};
use crate::transport::{TcpShadowsocksReader, TcpShadowsocksWriter, UdpWsTransport};
use crate::types::{TargetAddr, socket_addr_to_target};
use crate::uplink::{TransportKind, UplinkManager};

struct ActiveUdpTransport {
    index: usize,
    uplink_name: String,
    transport: Arc<UdpWsTransport>,
}

pub async fn handle_client(
    mut client: TcpStream,
    peer: SocketAddr,
    config: AppConfig,
    uplinks: UplinkManager,
) -> Result<()> {
    let request = negotiate(&mut client).await?;
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
        for candidate in uplinks.tcp_candidates(&target).await {
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

        let (candidate, connected) = selected.ok_or_else(|| {
            anyhow!(
                "all TCP uplinks failed: {}",
                last_error.unwrap_or_else(|| "no uplinks available".to_string())
            )
        })?;
        metrics::record_uplink_selected("tcp", &candidate.uplink.name);
        info!(uplink = %candidate.uplink.name, target = %target, "selected TCP uplink");
        let (writer, reader) = connected;

        let bound_addr = socket_addr_to_target(client.local_addr()?);
        send_reply(&mut client, SOCKS_STATUS_SUCCESS, &bound_addr).await?;

        let (mut client_read, mut client_write) = client.into_split();
        let uplink = async {
            let mut writer = writer;
            let mut buf = vec![0u8; SHADOWSOCKS_MAX_PAYLOAD];
            loop {
                let read = client_read
                    .read(&mut buf)
                    .await
                    .context("client read failed")?;
                if read == 0 {
                    writer.close().await?;
                    break;
                }
                metrics::add_bytes("tcp", "client_to_upstream", read);
                writer.send_chunk(&buf[..read]).await?;
            }
            Ok::<(), anyhow::Error>(())
        };

        let downlink = async {
            let mut reader = reader;
            loop {
                let chunk = reader.read_chunk().await?;
                if chunk.is_empty() {
                    continue;
                }
                metrics::add_bytes("tcp", "upstream_to_client", chunk.len());
                client_write
                    .write_all(&chunk)
                    .await
                    .context("client write failed")?;
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        };

        tokio::select! {
            result = uplink => result,
            result = downlink => result,
        }
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
        let initial_uplink_name = active_transport.lock().await.uplink_name.clone();
        metrics::record_uplink_selected("udp", &initial_uplink_name);
        info!(uplink = %initial_uplink_name, "selected UDP uplink");
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
                metrics::add_udp_datagram("client_to_upstream");
                metrics::add_bytes("udp", "client_to_upstream", payload.len());

                let transport = {
                    let active = active_transport_uplink.lock().await;
                    Arc::clone(&active.transport)
                };
                if let Err(error) = transport.send_packet(&payload).await {
                    let replacement = failover_udp_transport(
                        &uplinks_uplink,
                        &active_transport_uplink,
                        Some(&packet.target),
                        error,
                    )
                    .await?;
                    replacement.transport.send_packet(&payload).await?;
                }
            }
        };

        let client_udp_addr_downlink = Arc::clone(&client_udp_addr);
        let socket_downlink = Arc::clone(&udp_socket);
        let active_transport_downlink = Arc::clone(&active_transport);
        let uplinks_downlink = uplinks.clone();
        let downlink = async move {
            loop {
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
                        replacement.transport.read_packet().await?
                    }
                };
                let (target, consumed) = TargetAddr::from_wire_bytes(&payload)?;
                let client_addr = client_udp_addr_downlink.lock().await.ok_or_else(|| {
                    anyhow!("received UDP response before client sent any packet")
                })?;
                let packet = build_udp_packet(&target, &payload[consumed..])?;
                metrics::add_udp_datagram("upstream_to_client");
                metrics::add_bytes("udp", "upstream_to_client", payload.len());
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
    let ws_stream = uplinks.acquire_tcp_standby_or_connect(candidate).await?;
    let (ws_sink, ws_stream) = ws_stream.split();

    let uplink = &candidate.uplink;
    let master_key = uplink.cipher.derive_master_key(&uplink.password);
    let mut writer = TcpShadowsocksWriter::connect(ws_sink, uplink.cipher, &master_key).await?;
    let reader = TcpShadowsocksReader::new(ws_stream, uplink.cipher, &master_key);
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
    for candidate in uplinks.udp_candidates(target).await {
        match uplinks.acquire_udp_standby_or_connect(&candidate).await {
            Ok(transport) => {
                return Ok(ActiveUdpTransport {
                    index: candidate.index,
                    uplink_name: candidate.uplink.name.clone(),
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
        transport: Arc::clone(&replacement.transport),
    };
    Ok(replacement)
}
