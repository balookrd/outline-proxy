use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use futures_util::StreamExt;
use tracing::{debug, info, warn};

use crate::metrics;
use crate::transport::{
    TcpShadowsocksReader, TcpShadowsocksWriter, UpstreamTransportGuard,
    connect_shadowsocks_tcp_with_source,
};
use crate::types::{TargetAddr, UplinkTransport};
use crate::uplink::{TransportKind, UplinkCandidate, UplinkManager};

pub(super) async fn select_tcp_candidate_and_connect(
    uplinks: &UplinkManager,
    target: &TargetAddr,
) -> Result<(UplinkCandidate, TcpShadowsocksWriter, TcpShadowsocksReader)> {
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
                    uplinks
                        .confirm_selected_uplink(TransportKind::Tcp, Some(target), candidate.index)
                        .await;
                    if let Some(from_uplink) = failed_uplink.take() {
                        metrics::record_failover("tcp", &from_uplink, &candidate.uplink.name);
                        info!(
                            from_uplink,
                            to_uplink = %candidate.uplink.name,
                            remote = %target,
                            "runtime TCP failover activated for TUN flow"
                        );
                    }
                    return Ok((candidate, writer, reader));
                }
                Err(error) => {
                    uplinks
                        .report_runtime_failure(candidate.index, TransportKind::Tcp, &error)
                        .await;
                    if failed_uplink.is_none() {
                        failed_uplink = Some(candidate.uplink.name.clone());
                    }
                    last_error = Some(format!("{}: {error:#}", candidate.uplink.name));
                }
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
            "tun_tcp",
        )
        .await?;
        return do_tcp_ss_setup_socket(stream, &candidate.uplink, target).await;
    }

    // Variant A: try a standby pool connection first.  If it turns out to be
    // stale (fails before any server bytes arrive), discard it silently and
    // retry with a fresh on-demand dial — without recording a runtime failure.
    if let Some(ws) = uplinks.try_take_tcp_standby(candidate).await {
        match do_tcp_ss_setup(ws, &candidate.uplink, target).await {
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

    let ws = uplinks.connect_tcp_ws_fresh(candidate, "tun_tcp").await?;
    do_tcp_ss_setup(ws, &candidate.uplink, target).await
}

async fn do_tcp_ss_setup(
    ws_stream: crate::transport::AnyWsStream,
    uplink: &crate::config::UplinkConfig,
    target: &TargetAddr,
) -> Result<(TcpShadowsocksWriter, TcpShadowsocksReader)> {
    let (ws_sink, ws_stream) = ws_stream.split();
    let master_key = uplink.cipher.derive_master_key(&uplink.password)?;
    let lifetime = UpstreamTransportGuard::new("tun_tcp", "tcp");
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
    stream: tokio::net::TcpStream,
    uplink: &crate::config::UplinkConfig,
    target: &TargetAddr,
) -> Result<(TcpShadowsocksWriter, TcpShadowsocksReader)> {
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
            .with_request_salt(writer.request_salt().map(|salt| salt.to_vec()));
    writer
        .send_chunk(&target.to_wire_bytes()?)
        .await
        .context("failed to send target address")?;
    Ok((writer, reader))
}
