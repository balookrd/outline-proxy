use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

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

#[derive(Clone)]
struct ActiveUdpTransport {
    index: usize,
    uplink_name: String,
    uplink_weight: f64,
    transport: Arc<UdpWsTransport>,
}

const MAX_CLIENT_UDP_PACKET_SIZE: usize = SHADOWSOCKS_MAX_PAYLOAD;
const MAX_UDP_RELAY_PACKET_SIZE: usize = 65_507;
/// How long to wait for each upstream chunk during the early phase of a
/// session.  Guards against SS servers that accept the TCP connection but
/// stall indefinitely (conntrack exhaustion, dead target, etc.) and against
/// connections that stall mid-TLS-handshake after the first chunk.
const UPSTREAM_RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);
/// Number of upstream chunks covered by UPSTREAM_RESPONSE_TIMEOUT.
/// A TLS 1.3 handshake fits in ~4 flight records; TLS 1.2 needs up to ~6.
/// Using 10 gives a safe margin without touching long-lived idle data streams.
const UPSTREAM_RESPONSE_TIMEOUT_CHUNKS: u64 = 10;
/// Per-uplink timeout for the very first upstream chunk when failover is
/// possible.  Shorter than UPSTREAM_RESPONSE_TIMEOUT so that if the
/// primary SS server accepts the connection but can't reach the target,
/// we switch to the backup uplink before the client gives up.
/// Total client wait stays within UPSTREAM_RESPONSE_TIMEOUT across all
/// attempts.
const CHUNK0_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(6);
/// Maximum bytes of client→upstream data buffered for replay on failover.
/// Covers a full TLS 1.3 ClientHello (≤16 KB) with headroom.
/// If the client sends more before the first server response, failover is
/// disabled for that connection (buffer overflow) and the full
/// UPSTREAM_RESPONSE_TIMEOUT applies.
const MAX_CHUNK0_FAILOVER_BUF: usize = 32 * 1024;

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
    config: AppConfig,
    uplinks: UplinkManager,
    target: TargetAddr,
) -> Result<()> {
    if let Some(ref bypass) = config.bypass {
        if bypass.read().await.is_bypassed(&target) {
            info!(target = %target, "TCP bypass: direct connection");
            return handle_tcp_direct(client, target).await;
        }
    }
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
        let (mut writer, mut reader) = connected;

        let bound_addr = socket_addr_to_target(client.local_addr()?);
        send_reply(&mut client, SOCKS_STATUS_SUCCESS, &bound_addr).await?;

        let (mut client_read, mut client_write) = client.into_split();

        // ── Phase 1: wait for first upstream chunk, with failover on timeout ──
        //
        // In strict (active-passive) mode with multiple uplinks we use a shorter
        // per-attempt timeout (CHUNK0_ATTEMPT_TIMEOUT) so that if the primary SS
        // server accepts the connection but cannot reach the target we switch to
        // a backup before the client gives up.  Client data sent during the wait
        // is buffered and replayed verbatim to the new uplink.
        //
        // Invariants:
        //  • No data has been forwarded to the client yet (chunks_forwarded == 0).
        //  • Replaying the buffer is safe because the client hasn't received any
        //    server bytes, so the application-layer state is still in its initial
        //    handshake phase (e.g. TLS ClientHello).
        //  • If the buffer grows beyond MAX_CHUNK0_FAILOVER_BUF the connection is
        //    unusual and we fall back to the full UPSTREAM_RESPONSE_TIMEOUT without
        //    attempting a failover, to avoid unbounded memory use.
        let mut replay_buf: Vec<Vec<u8>> = Vec::new();
        let mut replay_overflow = false;
        let mut active_index = selected_index;
        let mut active_uplink_name = selected_uplink_name.clone();
        let mut client_half_closed = false;
        let mut deferred_phase1_failures: Vec<(usize, String, String)> = Vec::new();

        let first_upstream_chunk: Vec<u8> = 'phase1: loop {
            let can_failover = strict_transport
                && !replay_overflow
                && tried_indexes.len() < uplinks.uplinks().len();
            let attempt_timeout = if can_failover {
                CHUNK0_ATTEMPT_TIMEOUT
            } else {
                UPSTREAM_RESPONSE_TIMEOUT
            };
            let deadline = tokio::time::Instant::now() + attempt_timeout;
            let mut rbuf = vec![0u8; SHADOWSOCKS_MAX_PAYLOAD];

            // Run the attempt in an inner block so the borrow of `reader` held
            // by the select! (via read_chunk) is released before we potentially
            // replace writer/reader on failover.
            let attempt: Result<Vec<u8>> = loop {
                if client_half_closed {
                    break tokio::time::timeout_at(deadline, reader.read_chunk())
                        .await
                        .map_err(|_| {
                            anyhow!(
                                "upstream did not respond within {}s (chunk 0)",
                                attempt_timeout.as_secs(),
                            )
                        })?;
                }

                tokio::select! {
                    result = reader.read_chunk() => {
                        break result;
                    }
                    n_res = client_read.read(&mut rbuf) => {
                        match n_res {
                            Ok(0) => {
                                // Preserve TCP half-close semantics: stop sending
                                // client data upstream, but keep waiting for the
                                // response on the existing Shadowsocks session.
                                writer.close().await.context("uplink half-close failed")?;
                                client_half_closed = true;
                            }
                            Ok(n) => {
                                let chunk = rbuf[..n].to_vec();
                                writer
                                    .send_chunk(&chunk)
                                    .await
                                    .context("uplink write failed")?;
                                metrics::add_bytes(
                                    "tcp",
                                    "client_to_upstream",
                                    &active_uplink_name,
                                    n,
                                );
                                uplinks
                                    .report_active_traffic(active_index, TransportKind::Tcp, false)
                                    .await;
                                if !replay_overflow {
                                    let total: usize =
                                        replay_buf.iter().map(|c| c.len()).sum();
                                    if total + n <= MAX_CHUNK0_FAILOVER_BUF {
                                        replay_buf.push(chunk);
                                    } else {
                                        replay_overflow = true;
                                    }
                                }
                            }
                            Err(e) => break Err(e.into()),
                        }
                    }
                    _ = tokio::time::sleep_until(deadline) => {
                        break Err(anyhow!(
                            "upstream did not respond within {}s (chunk 0)",
                            attempt_timeout.as_secs(),
                        ));
                    }
                }
            };

            match attempt {
                Ok(chunk) if chunk.is_empty() => {
                    // Empty decrypted payload is not valid; treat as clean close.
                    client_write.shutdown().await.context("client shutdown failed")?;
                    return Ok(());
                }
                Ok(chunk) => {
                    // Attribute earlier chunk-0 stalls only after another uplink
                    // proves it can carry the same session. If every attempted
                    // uplink times out before sending any response bytes, the
                    // failure is ambiguous (target-specific or shared-path), so
                    // cooling down each uplink would poison the whole pool.
                    for (failed_index, failed_uplink_name, failed_error) in
                        deferred_phase1_failures.drain(..)
                    {
                        let deferred_error = anyhow!(failed_error.clone());
                        uplinks
                            .report_runtime_failure(
                                failed_index,
                                TransportKind::Tcp,
                                &deferred_error,
                            )
                            .await;
                        debug!(
                            uplink = %failed_uplink_name,
                            error = %failed_error,
                            recovered_via = %active_uplink_name,
                            "recorded deferred TCP chunk-0 runtime failure after successful failover"
                        );
                    }
                    break 'phase1 chunk;
                }
                Err(ref e) if reader.closed_cleanly => {
                    debug!(
                        uplink = %active_uplink_name,
                        error = %format!("{e:#}"),
                        "upstream closed before sending any data (phase 1)"
                    );
                    client_write.shutdown().await.context("client shutdown failed")?;
                    return Ok(());
                }
                Err(e) => {
                    let error_text = format!("{e:#}");
                    warn!(
                        uplink = %active_uplink_name,
                        error = %error_text,
                        "TCP chunk-0 failure"
                    );

                    if !can_failover {
                        if deferred_phase1_failures.is_empty() {
                            uplinks
                                .report_runtime_failure(active_index, TransportKind::Tcp, &e)
                                .await;
                        } else {
                            warn!(
                                last_uplink = %active_uplink_name,
                                attempts = deferred_phase1_failures.len() + 1,
                                error = %error_text,
                                "suppressing TCP chunk-0 runtime failure attribution because every attempted uplink stalled before the first response"
                            );
                        }
                        return Err(e);
                    }

                    deferred_phase1_failures.push((
                        active_index,
                        active_uplink_name.clone(),
                        error_text,
                    ));

                    // Find a candidate we haven't tried yet.
                    let candidates = uplinks.tcp_candidates(&target).await;
                    let next = candidates
                        .into_iter()
                        .find(|c| !tried_indexes.contains(&c.index));
                    let Some(next_candidate) = next else {
                        return Err(e.context("no alternative uplink available for chunk-0 failover"));
                    };
                    tried_indexes.insert(next_candidate.index);

                    // Connect to the new uplink.
                    let (new_writer, new_reader) =
                        match connect_tcp_uplink(&uplinks, &next_candidate, &target).await {
                            Ok(v) => v,
                            Err(connect_err) => {
                                uplinks
                                    .report_runtime_failure(
                                        next_candidate.index,
                                        TransportKind::Tcp,
                                        &connect_err,
                                    )
                                    .await;
                                return Err(connect_err.context("chunk-0 failover connect failed"));
                            }
                        };

                    uplinks
                        .confirm_selected_uplink(
                            TransportKind::Tcp,
                            Some(&target),
                            next_candidate.index,
                        )
                        .await;
                    metrics::record_failover("tcp", &active_uplink_name, &next_candidate.uplink.name);
                    metrics::record_uplink_selected("tcp", &next_candidate.uplink.name);
                    info!(
                        from = %active_uplink_name,
                        to = %next_candidate.uplink.name,
                        "TCP chunk-0 failover"
                    );
                    active_index = next_candidate.index;
                    active_uplink_name = next_candidate.uplink.name.clone();
                    writer = new_writer;
                    reader = new_reader;

                    // Replay buffered client data to the new uplink.
                    for chunk in &replay_buf {
                        writer
                            .send_chunk(chunk)
                            .await
                            .context("replay to failover uplink failed")?;
                    }
                    if client_half_closed {
                        writer
                            .close()
                            .await
                            .context("failover uplink half-close failed")?;
                    }
                    // Continue 'phase1 loop with the new uplink.
                }
            }
        };

        // ── Phase 2: bidirectional relay ──────────────────────────────────────
        //
        // `first_upstream_chunk` has already been received from the upstream.
        // Forward it to the client immediately, then run the normal relay loop
        // starting at chunks_forwarded = 1 (no chunk-0 timeout applies here).
        let uplink_uplink_name = active_uplink_name.clone();
        let uplinks_uplink = uplinks.clone();
        let uplink = async move {
            let mut buf = vec![0u8; SHADOWSOCKS_MAX_PAYLOAD];
            let mut chunks_sent: u64 = 0;
            loop {
                if strict_transport
                    && uplinks_uplink
                        .active_uplink_index_for_transport(TransportKind::Tcp)
                        .await
                        .is_some_and(|active| active != active_index)
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
                chunks_sent += 1;
                if chunks_sent == 1 {
                    debug!(uplink = %uplink_uplink_name, "first chunk sent to upstream");
                }
                // Outbound only — upstream has not responded yet; do not clear cooldown.
                uplinks_uplink
                    .report_active_traffic(active_index, TransportKind::Tcp, false)
                    .await;
            }
            Ok::<(), anyhow::Error>(())
        };

        let downlink_uplink_name = active_uplink_name.clone();
        let uplinks_downlink = uplinks.clone();
        let downlink = async move {
            // Forward the chunk obtained in phase 1.
            metrics::add_bytes(
                "tcp",
                "upstream_to_client",
                &downlink_uplink_name,
                first_upstream_chunk.len(),
            );
            client_write
                .write_all(&first_upstream_chunk)
                .await
                .context("client write failed")?;
            // Data path confirmed: upstream responded.
            uplinks_downlink
                .report_active_traffic(active_index, TransportKind::Tcp, true)
                .await;

            // Continue reading from upstream; chunk 0 is already done.
            let mut chunks_forwarded: u64 = 1;
            loop {
                if strict_transport
                    && uplinks_downlink
                        .active_uplink_index_for_transport(TransportKind::Tcp)
                        .await
                        .is_some_and(|active| active != active_index)
                {
                    return Err(anyhow!("active uplink switched for SOCKS TCP session"));
                }
                let chunk_result = if chunks_forwarded < UPSTREAM_RESPONSE_TIMEOUT_CHUNKS {
                    tokio::time::timeout(UPSTREAM_RESPONSE_TIMEOUT, reader.read_chunk())
                        .await
                        .map_err(|_| {
                            anyhow!(
                                "upstream did not respond within {}s (chunk {})",
                                UPSTREAM_RESPONSE_TIMEOUT.as_secs(),
                                chunks_forwarded,
                            )
                        })?
                } else {
                    reader.read_chunk().await
                };
                let chunk = match chunk_result {
                    Ok(chunk) => chunk,
                    Err(_err) if reader.closed_cleanly => {
                        break;
                    }
                    Err(err) => return Err(err),
                };
                if chunk.is_empty() {
                    break;
                }
                chunks_forwarded += 1;
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
                    .report_active_traffic(active_index, TransportKind::Tcp, true)
                    .await;
            }
            client_write
                .shutdown()
                .await
                .context("client shutdown failed")?;
            Ok::<(), anyhow::Error>(())
        };

        let result = tokio::try_join!(uplink, downlink).map(|_| ());
        // Report mid-stream upstream transport failures so that broken transports
        // (e.g. H3 APPLICATION_CLOSE received after session establishment) trigger
        // the H3→H2 downgrade and flush stale warm-standby connections immediately,
        // rather than waiting for the next connection attempt to fail.
        // Client-side disconnects and intentional uplink switches are excluded.
        if let Err(ref err) = result {
            if crate::error_text::is_upstream_runtime_failure(err) {
                uplinks
                    .report_runtime_failure(active_index, TransportKind::Tcp, err)
                    .await;
            } else if crate::error_text::is_websocket_closed(err) {
                // The upstream server closed the WebSocket connection
                // mid-stream (server-initiated close, not a client
                // disconnect).  We do not set a full runtime-failure
                // cooldown to avoid penalising the uplink for normal
                // per-connection lifetime limits, but we clear the
                // activity timestamp so the probe is not skipped on the
                // next cycle — this lets the probe detect a downed server
                // promptly rather than waiting for probe.interval of silence.
                uplinks
                    .report_upstream_close(active_index, TransportKind::Tcp)
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
        let relay_addr = udp_socket
            .local_addr()
            .context("failed to read UDP relay address")?;

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
                        let target_addr = match &packet.target {
                            crate::types::TargetAddr::IpV4(ip, port) => {
                                SocketAddr::new(std::net::IpAddr::V4(*ip), *port)
                            }
                            crate::types::TargetAddr::IpV6(ip, port) => {
                                SocketAddr::new(std::net::IpAddr::V6(*ip), *port)
                            }
                            crate::types::TargetAddr::Domain(_, _) => {
                                unreachable!("domains return false from is_bypassed")
                            }
                        };
                        sock.send_to(&packet.payload, target_addr)
                            .await
                            .context("bypass UDP send failed")?;
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
                        .report_active_traffic(replacement.index, TransportKind::Udp, false)
                        .await;
                } else {
                    metrics::add_udp_datagram("client_to_upstream", &uplink_name);
                    metrics::add_bytes("udp", "client_to_upstream", &uplink_name, payload.len());
                    uplinks_uplink
                        .report_active_traffic(active_index, TransportKind::Udp, false)
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
                // Response received from upstream — data path confirmed; clear cooldown.
                uplinks_downlink
                    .report_active_traffic(active.0, TransportKind::Udp, true)
                    .await;
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
                let (len, src_addr) = sock
                    .recv_from(&mut buf)
                    .await
                    .context("bypass UDP recv failed")?;
                let client_addr =
                    client_udp_addr_direct.lock().await.ok_or_else(|| {
                        anyhow!("received bypass UDP response before client sent any packet")
                    })?;
                let target = socket_addr_to_target(src_addr);
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
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        };

        tokio::select! {
            result = uplink => result,
            result = downlink => result,
            result = control => result,
            result = direct_downlink => result,
        }
    }
    .await;
    session.finish(result.is_ok());
    result
}

async fn handle_tcp_direct(mut client: TcpStream, target: TargetAddr) -> Result<()> {
    let addr = match &target {
        TargetAddr::IpV4(ip, port) => SocketAddr::new(std::net::IpAddr::V4(*ip), *port),
        TargetAddr::IpV6(ip, port) => SocketAddr::new(std::net::IpAddr::V6(*ip), *port),
        TargetAddr::Domain(host, port) => tokio::net::lookup_host(format!("{host}:{port}"))
            .await
            .with_context(|| format!("failed to resolve {target}"))?
            .next()
            .ok_or_else(|| anyhow!("no address resolved for {target}"))?,
    };

    let upstream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("direct TCP connect to {target} failed"))?;

    let bound_addr = socket_addr_to_target(client.local_addr()?);
    send_reply(&mut client, SOCKS_STATUS_SUCCESS, &bound_addr).await?;

    let (mut client_read, mut client_write) = client.into_split();
    let (mut upstream_read, mut upstream_write) = upstream.into_split();

    let c2u = async {
        tokio::io::copy(&mut client_read, &mut upstream_write).await?;
        upstream_write.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    };
    let u2c = async {
        tokio::io::copy(&mut upstream_read, &mut client_write).await?;
        client_write.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    };

    tokio::try_join!(c2u, u2c).map(|_| ())
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
    let target_wire = target.to_wire_bytes()?;
    writer
        .send_chunk(&target_wire)
        .await
        .context("failed to send target address")?;
    debug!(
        uplink = %uplink.name,
        target = %target,
        target_wire_len = target_wire.len(),
        transport = "websocket",
        ss2022 = uplink.cipher.is_ss2022(),
        "sent initial Shadowsocks target header to uplink"
    );
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
    let target_wire = target.to_wire_bytes()?;
    writer
        .send_chunk(&target_wire)
        .await
        .context("failed to send target address")?;
    debug!(
        uplink = %uplink.name,
        target = %target,
        target_wire_len = target_wire.len(),
        transport = "socket",
        ss2022 = uplink.cipher.is_ss2022(),
        "sent initial Shadowsocks target header to uplink"
    );
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
    // Guard against concurrent failovers: if another task already replaced the
    // transport while we were selecting, return whatever is current instead of
    // overwriting with a potentially different replacement.
    if active.index != failed {
        return Ok(active.clone());
    }
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
    // Guard against concurrent reconciliations: if another task already updated
    // the active transport while we were selecting, skip the overwrite.
    if active.index != selected {
        return Ok(());
    }
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
