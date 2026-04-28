use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use futures_util::StreamExt;
use tracing::{debug, info, warn};

use outline_metrics as metrics;
use outline_transport::{
    TcpReader, TcpWriter,
    TcpShadowsocksReader, TcpShadowsocksWriter, UpstreamTransportGuard,
    connect_shadowsocks_tcp_with_source,
};
use socks5_proto::TargetAddr;
use outline_uplink::UplinkTransport;
use outline_uplink::{TransportKind, UplinkCandidate, UplinkManager};

pub(super) async fn select_tcp_candidate_and_connect(
    uplinks: &UplinkManager,
    target: &TargetAddr,
) -> Result<(UplinkCandidate, TcpWriter, TcpReader)> {
    let mut last_error = None;
    let mut failed_uplink = None::<String>;
    let strict_transport = uplinks.strict_active_uplink_for(TransportKind::Tcp);
    let mut tried_indexes = std::collections::HashSet::new();
    loop {
        let candidates = uplinks.tcp_candidates(target).await;
        if candidates.is_empty() {
            let cooldowns = uplinks.tcp_cooldown_debug_summary().await;
            warn!(
                remote = %target,
                tcp_uplinks = cooldowns.join("; "),
                "dropping TUN TCP flow because all TCP uplinks are in cooldown or unavailable"
            );
            return Err(anyhow!("all TCP uplinks are in cooldown or unavailable for TUN flow"));
        }

        let iter = if strict_transport {
            candidates.into_iter().take(1).collect::<Vec<_>>()
        } else {
            candidates
        };
        let mut progressed = false;
        for candidate in iter {
            if strict_transport && !tried_indexes.insert(candidate.index) {
                continue;
            }
            progressed = true;
            match connect_tcp_uplink(uplinks, &candidate, target).await {
                Ok((writer, reader)) => {
                    if failed_uplink.is_some() {
                        uplinks
                            .confirm_runtime_failover_uplink(
                                TransportKind::Tcp,
                                Some(target),
                                candidate.index,
                            )
                            .await;
                    } else {
                        uplinks
                            .confirm_selected_uplink(
                                TransportKind::Tcp,
                                Some(target),
                                candidate.index,
                            )
                            .await;
                    }
                    if let Some(from_uplink) = failed_uplink.take() {
                        metrics::record_failover(
                            "tcp",
                            uplinks.group_name(),
                            &from_uplink,
                            &candidate.uplink.name,
                        );
                        info!(
                            from_uplink,
                            to_uplink = %candidate.uplink.name,
                            remote = %target,
                            "runtime TCP failover activated for TUN flow"
                        );
                    }
                    return Ok((candidate, writer, reader));
                },
                Err(error) => {
                    uplinks
                        .report_runtime_failure(candidate.index, TransportKind::Tcp, &error)
                        .await;
                    if failed_uplink.is_none() {
                        failed_uplink = Some(candidate.uplink.name.clone());
                    }
                    last_error = Some(format!("{}: {error:#}", candidate.uplink.name));
                },
            }
        }
        if !strict_transport || !progressed {
            break;
        }
    }

    Err(anyhow!(
        "all TCP uplinks failed for TUN flow: {}",
        last_error.unwrap_or_else(|| "no uplinks available".to_string())
    ))
}

async fn connect_tcp_uplink(
    uplinks: &UplinkManager,
    candidate: &UplinkCandidate,
    target: &TargetAddr,
) -> Result<(TcpWriter, TcpReader)> {
    let cache = uplinks.dns_cache();
    if candidate.uplink.transport == UplinkTransport::Shadowsocks {
        let stream = connect_shadowsocks_tcp_with_source(cache,
            candidate
                .uplink
                .tcp_addr
                .as_ref()
                .ok_or_else(|| anyhow!("uplink {} missing tcp_addr", candidate.uplink.name))?,
            candidate.uplink.fwmark,
            candidate.uplink.ipv6_first,
            "tun_tcp",
        )
        .await?;
        return do_tcp_ss_setup_socket(stream, &candidate.uplink, target).await;
    }

    // Raw QUIC (VLESS-over-QUIC or SS-over-QUIC) is shared via the per-ALPN
    // connection registry, not the warm-standby pool. Dispatch directly to
    // the QUIC dial helper which already returns a ready-to-use writer/reader
    // pair (with the VLESS request header / SS target prefix sent on the
    // first frame as the protocol requires).
    #[cfg(feature = "quic")]
    {
        let mode = uplinks.effective_tcp_ws_mode(candidate.index).await;
        if mode == outline_transport::WsTransportMode::Quic {
            match uplinks.connect_tcp_quic_fresh(candidate, target, "tun_tcp").await {
                Ok(pair) => return Ok(pair),
                Err(e) => {
                    warn!(
                        uplink = %candidate.uplink.name,
                        target = %target,
                        error = %format!("{e:#}"),
                        fallback = "ws/h2",
                        "raw-QUIC TCP dial failed, falling back to WS over H2"
                    );
                    uplinks.note_advanced_mode_dial_failure(
                        candidate.index,
                        TransportKind::Tcp,
                        &e,
                    );
                    // Fall through to the WS path below; effective_tcp_ws_mode
                    // will now return H2 for the rest of the downgrade window,
                    // and connect_websocket_with_source handles H2 → H1.
                }
            }
        }
    }

    let keepalive_interval = uplinks.load_balancing().tcp_ws_keepalive_interval;

    // Variant A: try a standby pool connection first.  If it turns out to be
    // stale (fails before any server bytes arrive), discard it silently and
    // retry with a fresh on-demand dial — without recording a runtime failure.
    if let Some(ws) = uplinks.try_take_tcp_standby(candidate).await {
        match do_tcp_ss_setup(ws, &candidate.uplink, target, keepalive_interval).await {
            Ok(v) => return Ok(v),
            Err(e) => {
                debug!(
                    uplink = %candidate.uplink.name,
                    error = %format!("{e:#}"),
                    "stale standby TCP pool connection, retrying with fresh dial"
                );
            },
        }
    }

    let ws = uplinks.connect_tcp_ws_fresh(candidate, "tun_tcp").await?;
    do_tcp_ss_setup(ws, &candidate.uplink, target, keepalive_interval).await
}

async fn do_tcp_ss_setup(
    ws_stream: outline_transport::WsTransportStream,
    uplink: &outline_uplink::UplinkConfig,
    target: &TargetAddr,
    keepalive_interval: Option<std::time::Duration>,
) -> Result<(TcpWriter, TcpReader)> {
    let shared_conn_info = ws_stream.shared_connection_info();
    let lifetime = UpstreamTransportGuard::new("tun_tcp", "tcp");
    let diag = outline_transport::WsReadDiag {
        conn_id: shared_conn_info.map(|(id, _)| id),
        mode: shared_conn_info.map(|(_, m)| m).unwrap_or("h1"),
        uplink: uplink.name.clone(),
        target: target.to_string(),
    };

    if uplink.transport == UplinkTransport::Vless {
        let uuid = uplink
            .vless_id
            .as_ref()
            .ok_or_else(|| anyhow!("uplink {} missing vless_id", uplink.name))?;
        let (writer, reader) = outline_transport::vless::vless_tcp_pair_from_ws(
            ws_stream,
            uuid,
            target,
            lifetime,
            diag,
            keepalive_interval,
        );
        return Ok((TcpWriter::Vless(writer), TcpReader::Vless(reader)));
    }

    let (ws_sink, ws_stream) = ws_stream.split();
    let master_key = uplink.cipher.derive_master_key(&uplink.password)?;
    let (mut writer, ctrl_tx) =
        TcpShadowsocksWriter::connect(ws_sink, uplink.cipher, &master_key, Arc::clone(&lifetime))
            .await?;
    let request_salt = writer.request_salt();
    let reader =
        TcpShadowsocksReader::new(ws_stream, uplink.cipher, &master_key, lifetime, ctrl_tx)
            .with_request_salt(request_salt)
            .with_diag(diag);
    writer
        .send_chunk(&target.to_wire_bytes()?)
        .await
        .context("failed to send target address")?;
    Ok((TcpWriter::Ws(writer), TcpReader::Ws(reader)))
}

async fn do_tcp_ss_setup_socket(
    stream: tokio::net::TcpStream,
    uplink: &outline_uplink::UplinkConfig,
    target: &TargetAddr,
) -> Result<(TcpWriter, TcpReader)> {
    let (reader_half, writer_half) = stream.into_split();
    let master_key = uplink.cipher.derive_master_key(&uplink.password)?;
    let lifetime = UpstreamTransportGuard::new("tun_tcp", "tcp");
    let mut writer = TcpShadowsocksWriter::connect_socket(
        writer_half,
        uplink.cipher,
        &master_key,
        Arc::clone(&lifetime),
    )?;
    let reader =
        TcpShadowsocksReader::new_socket(reader_half, uplink.cipher, &master_key, lifetime)
            .with_request_salt(writer.request_salt());
    writer
        .send_chunk(&target.to_wire_bytes()?)
        .await
        .context("failed to send target address")?;
    Ok((TcpWriter::Socket(writer), TcpReader::Socket(reader)))
}
