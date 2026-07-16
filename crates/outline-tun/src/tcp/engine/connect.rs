use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
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

/// Re-dials `candidate` to migrate a flow whose carrier died, presenting **this
/// flow's own** Session ID so the server re-attaches the upstream it parked
/// rather than opening a fresh one to the destination.
///
/// Unlike every other dial in this file it advertises the resume replay
/// protocols — Ack-Prefix (v1) always, Symmetric Downlink Replay (v2) when the
/// group enables it — so that on a **hit** the server tells us exactly how many
/// uplink bytes it forwarded (`up_acked`) and hands back the downstream slice we
/// never saw. Those frames are also the only proof of a hit the client gets: the
/// capability echo on the upgrade response says the server *would* emit them,
/// not that it did, because it echoes the capability even on a miss. The caller
/// treats "no v1 frame" as a miss and tears the flow down.
///
/// Never served from the warm-standby pool: a pooled carrier already completed
/// its upgrade under a Session ID of its own, and resume is a property of the
/// handshake — it can only be requested by a dial we make ourselves.
pub(super) async fn redial_tcp_uplink_for_migration(
    uplinks: &UplinkManager,
    candidate: &UplinkCandidate,
    target: &TargetAddr,
    resume_request: SessionId,
    client_acked_offset: u64,
    symmetric_replay: bool,
) -> Result<(TcpWriter, TcpReader, Option<SessionId>)> {
    if !matches!(candidate.uplink.transport, UplinkTransport::Ss | UplinkTransport::Vless) {
        bail!(
            "carrier migration needs a WS-family uplink (SS-WS or VLESS-WS); uplink {} uses \
             transport {:?}",
            candidate.uplink.name,
            candidate.uplink.transport,
        );
    }
    // Padding scope wraps the dial *and* the transport build — see
    // `connect_tcp_uplink` for why the scope cannot stop at the dial.
    let (writer, reader, session_id) = outline_uplink::dial::with_uplink_padding_scope(
        &candidate.uplink,
        redial_tcp_uplink_for_migration_inner(
            uplinks,
            candidate,
            target,
            resume_request,
            client_acked_offset,
            symmetric_replay,
        ),
    )
    .await?;
    let reader = install_throttle_handle(uplinks, candidate, reader);
    Ok((writer, reader, session_id))
}

async fn redial_tcp_uplink_for_migration_inner(
    uplinks: &UplinkManager,
    candidate: &UplinkCandidate,
    target: &TargetAddr,
    resume_request: SessionId,
    client_acked_offset: u64,
    symmetric_replay: bool,
) -> Result<(TcpWriter, TcpReader, Option<SessionId>)> {
    let keepalive_interval = uplinks.load_balancing().tcp_ws_keepalive_interval;
    // The migrate-* dials ask for the configured carrier rather than the
    // capped one: the carrier death we are recovering from has just capped
    // this uplink's mode (h3 -> h2), and a flow handed the capped carrier
    // keeps it for the rest of its life. See
    // `connect_tcp_ws_migrate_with_ack_prefix`.
    let ws = if symmetric_replay {
        uplinks
            .connect_tcp_ws_migrate_with_symmetric_replay(
                candidate,
                "tun_tcp_migrate",
                Some(resume_request),
                client_acked_offset,
            )
            .await?
    } else {
        uplinks
            .connect_tcp_ws_migrate_with_ack_prefix(
                candidate,
                "tun_tcp_migrate",
                Some(resume_request),
            )
            .await?
    };
    let binding = tun_tcp_binding(uplinks, &candidate.uplink.name);
    do_tcp_ss_setup(ws, &candidate.uplink, target, keepalive_interval, binding).await
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
    let reader = install_throttle_handle(uplinks, candidate, reader);
    Ok((writer, reader, session_id))
}

/// Install the carrier control-signal handler so a server downstream-throttle
/// notice on this carrier penalises the uplink and migrates traffic away. No-op
/// (handle is `None`) unless the client opted in; ignored by every
/// non-VLESS-over-WS reader.
fn install_throttle_handle(
    uplinks: &UplinkManager,
    candidate: &UplinkCandidate,
    reader: TcpReader,
) -> TcpReader {
    match outline_uplink::dial::throttle_handle(uplinks, candidate.index, TransportKind::Tcp) {
        Some(handle) => reader.with_throttle_handle(handle),
        None => reader,
    }
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
    // `ack_prefix_advertised_by_server` is `false` on the *fresh* dial and
    // deliberately so: it dials with `resume_request: None` /
    // `ack_prefix_requested: false`, and the server only emits the v1 `ORSM` /
    // v2 `ORDR` control frames on a resume HIT. Advertising a capability the
    // dial cannot honour would make the server emit frames nobody consumes. The
    // migration redial (`redial_tcp_uplink_for_migration`) is the one that opts
    // in, and these two flags are how its reader knows to expect the frames.
    let issued_session_id = ws_stream.issued_session_id();
    let expect_ack_prefix = ws_stream.ack_prefix_advertised_by_server();
    let expect_downlink_replay = ws_stream.symmetric_replay_advertised_by_server();

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
        let reader = TcpReader::Vless(reader)
            .with_expect_ack_prefix(expect_ack_prefix)
            .with_expect_downlink_replay(expect_downlink_replay);
        // NB: the VLESS writer holds its request header back until the first
        // `send_chunk`, so a migration redial must flush it before it can expect
        // the server's control frames — see `migrate.rs`.
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
            .with_expect_ack_prefix(expect_ack_prefix)
            .with_expect_downlink_replay(expect_downlink_replay);
    // The target header goes out on a migration redial too. The server parses it
    // off every stream, then — on a resume hit — throws it away and keeps the
    // parked target (`transport/tcp.rs`: "the target sent in this handshake is
    // intentionally ignored on a hit"). It is also what makes the server reach
    // the resume take, and so emit the control frames the migration waits for.
    writer
        .send_chunk(&target.to_wire_bytes()?)
        .await
        .context("failed to send target address")?;
    Ok((TcpWriter::Ws(writer), TcpReader::Ws(Box::new(reader)), issued_session_id))
}
