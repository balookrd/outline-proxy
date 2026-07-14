use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use futures_util::StreamExt;
use tracing::{debug, info, warn};

use outline_metrics as metrics;
use outline_transport::{
    SessionId, TcpReader, TcpShadowsocksReader, TcpShadowsocksWriter, TcpWriter,
    UplinkConnectionBinding, UpstreamTransportGuard,
};
use outline_uplink::UplinkTransport;
use outline_uplink::{TransportKind, UplinkCandidate, UplinkManager};
use socks5_proto::TargetAddr;

/// A TUN TCP flow's freshly-established upstream: the uplink it landed on, the
/// transport halves, and the Session ID the server minted for **this flow**.
///
/// The id is per-flow, never per-uplink: on a resume hit the server ignores the
/// handshake target and re-attaches whatever upstream is parked under the id, so
/// one flow presenting another's id would be spliced onto that flow's
/// destination. It travels with the halves it was issued alongside so it cannot
/// drift apart from them. `None` against a server without resumption.
pub(super) struct ConnectedTunTcpUplink {
    pub(super) candidate: UplinkCandidate,
    pub(super) writer: TcpWriter,
    pub(super) reader: TcpReader,
    pub(super) session_id: Option<SessionId>,
}

pub(super) async fn select_tcp_candidate_and_connect(
    uplinks: &UplinkManager,
    target: &TargetAddr,
    client: Option<&str>,
) -> Result<ConnectedTunTcpUplink> {
    let mut last_error = None;
    let mut failed_uplink = None::<String>;
    let strict_transport = uplinks.strict_active_uplink_for(TransportKind::Tcp);
    let mut tried_indexes = std::collections::HashSet::new();
    loop {
        let candidates = uplinks.tcp_candidates_for(target, client).await;
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
                Ok((writer, reader, session_id)) => {
                    if failed_uplink.is_some() {
                        uplinks
                            .confirm_runtime_failover_uplink_for(
                                TransportKind::Tcp,
                                Some(target),
                                client,
                                candidate.index,
                            )
                            .await;
                    } else {
                        uplinks
                            .confirm_selected_uplink_for(
                                TransportKind::Tcp,
                                Some(target),
                                client,
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
                    return Ok(ConnectedTunTcpUplink { candidate, writer, reader, session_id });
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
) -> Result<(TcpWriter, TcpReader, Option<SessionId>)> {
    // Scope the per-uplink padding override over the whole dial + build. The
    // transport reads `effective_carrier_padding` when it splits/spawns the
    // writer (`do_tcp_ss_setup` / `vless_tcp_pair_from_ws`), which runs AFTER
    // the dial future returns — so the scope must wrap this entire call, not
    // just the dial (the manager's `dial_in_uplink_scope` covers only the dial:
    // enough for the TLS fingerprint, not for padding). Without this the hot
    // path falls back to the global `[padding] enabled` default, so a padded
    // per-uplink dials plain and the padded server path drops it while the
    // (correctly scoped) probe stays green. Mirrors the SOCKS path in
    // `outline-ws-rust`'s `proxy/tcp/failover.rs::connect_tcp_uplink`.
    let (writer, reader, session_id) = outline_uplink::dial::with_uplink_padding_scope(
        &candidate.uplink,
        connect_tcp_uplink_inner(uplinks, candidate, target),
    )
    .await?;
    // Install the carrier control-signal handler so a server downstream-throttle
    // notice on this carrier penalises the uplink and migrates traffic away.
    // No-op (handle is `None`) unless the client opted in; ignored by every
    // non-VLESS-over-WS reader.
    let reader =
        match outline_uplink::dial::throttle_handle(uplinks, candidate.index, TransportKind::Tcp) {
            Some(handle) => reader.with_throttle_handle(handle),
            None => reader,
        };
    Ok((writer, reader, session_id))
}

async fn connect_tcp_uplink_inner(
    uplinks: &UplinkManager,
    candidate: &UplinkCandidate,
    target: &TargetAddr,
) -> Result<(TcpWriter, TcpReader, Option<SessionId>)> {
    let keepalive_interval = uplinks.load_balancing().tcp_ws_keepalive_interval;

    // Variant A: try a standby pool connection first.  If it turns out to be
    // stale (fails before any server bytes arrive), discard it silently and
    // retry with a fresh on-demand dial — without recording a runtime failure.
    if let Some(ws) = uplinks.try_take_tcp_standby(candidate).await {
        let binding = tun_tcp_binding(uplinks, &candidate.uplink.name);
        match do_tcp_ss_setup(ws, &candidate.uplink, target, keepalive_interval, binding).await {
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
    let binding = tun_tcp_binding(uplinks, &candidate.uplink.name);
    do_tcp_ss_setup(ws, &candidate.uplink, target, keepalive_interval, binding).await
}

fn tun_tcp_binding(uplinks: &UplinkManager, uplink_name: &str) -> UplinkConnectionBinding {
    UplinkConnectionBinding::new(uplinks.group_name(), "tcp", uplink_name)
}

async fn do_tcp_ss_setup(
    ws_stream: outline_transport::TransportStream,
    uplink: &outline_uplink::UplinkConfig,
    target: &TargetAddr,
    keepalive_interval: Option<std::time::Duration>,
    binding: UplinkConnectionBinding,
) -> Result<(TcpWriter, TcpReader, Option<SessionId>)> {
    let shared_conn_info = ws_stream.shared_connection_info();
    let lifetime = UpstreamTransportGuard::new_with_uplink("tun_tcp", "tcp", binding);
    let diag = outline_transport::WsReadDiag {
        conn_id: shared_conn_info.map(|(id, _)| id),
        mode: shared_conn_info.map(|(_, m)| m).unwrap_or("h1"),
        is_h3: ws_stream.is_h3(),
        uplink: uplink.name.clone(),
        target: target.to_string(),
    };

    // Snapshot the resume negotiation outcome before any consume — both VLESS's
    // `vless_tcp_pair_from_ws` and SS-WS's `.split()` take ownership of the
    // underlying stream halves, after which the accessors on the enum are gone.
    //
    // `issued_session_id` is the id the server minted for THIS flow's stream;
    // the flow stores it (alongside its uplink replay ring and its
    // downstream-accepted offset) so a future carrier migration can present it
    // and have the parked upstream re-attached byte-exact.
    //
    // `ack_prefix_advertised_by_server` is still `false` here, and deliberately
    // so: the initial dial is a *fresh* dial (`resume_request: None`,
    // `ack_prefix_requested: false`), and the server only emits the v1 `ORSM` /
    // v2 `ORDR` control frames on a resume HIT. Advertising a capability we
    // cannot yet honour would make the server emit frames nobody consumes. The
    // flow now *records* everything a replay would need; the opt-in belongs to
    // the redial that actually performs the migration, not to this dial.
    let issued_session_id = ws_stream.issued_session_id();
    let expect_ack_prefix = ws_stream.ack_prefix_advertised_by_server();

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
        let reader = TcpReader::Vless(reader).with_expect_ack_prefix(expect_ack_prefix);
        return Ok((TcpWriter::Vless(writer), reader, issued_session_id));
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
            .with_diag(diag)
            .with_expect_ack_prefix(expect_ack_prefix);
    writer
        .send_chunk(&target.to_wire_bytes()?)
        .await
        .context("failed to send target address")?;
    Ok((TcpWriter::Ws(writer), TcpReader::Ws(Box::new(reader)), issued_session_id))
}
