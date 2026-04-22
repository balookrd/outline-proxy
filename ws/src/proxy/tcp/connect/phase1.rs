use std::collections::HashSet;

use anyhow::{Context, Result, anyhow};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tracing::{debug, info, warn};

use shadowsocks_crypto::SHADOWSOCKS_MAX_PAYLOAD;
use outline_metrics as metrics;
use socks5_proto::TargetAddr;

use outline_uplink::{TransportKind, UplinkManager};

use super::super::failover::{
    ActiveTcpUplink, TcpUplinkSource, connect_tcp_uplink, connect_tcp_uplink_fresh,
};
use super::replay::ReplayBufState;
use crate::proxy::TcpTimeouts;

/// Maximum number of transparent retries on the *same* uplink when chunk 0
/// dies with a transport-level reset (WebSocket RST / clean Close before any
/// response bytes). Transit flaps routinely RST fresh WS handshakes on
/// several uplinks within a few hundred milliseconds; silently redialing
/// once or twice avoids surfacing a brief network event to the client as a
/// user-visible disconnect, and is cheaper than a full cross-uplink failover.
const CHUNK0_RST_MAX_RETRIES: u8 = 2;

/// Delay between transparent chunk-0 retries. Short enough that the worst
/// case (two retries) stays well under a second, long enough to let a
/// transit/DPI flap clear before dialing again.
const CHUNK0_RST_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(300);

/// Waits for the first upstream response chunk while forwarding client data,
/// transparently failing over to alternative uplinks (and replaying buffered
/// client bytes) when an uplink resets or stalls before responding.
///
/// Returns `Ok(Some(chunk))` once the first upstream byte arrives.  Returns
/// `Ok(None)` when the upstream closed cleanly before sending any data; in
/// that case `client_write` has already been shut down and the caller should
/// return `Ok(())` immediately.
pub(super) async fn try_uplinks(
    uplinks: &UplinkManager,
    active: &mut ActiveTcpUplink,
    target: &TargetAddr,
    strict_transport: bool,
    tried_indexes: &mut HashSet<usize>,
    chunk0_attempt_timeout: std::time::Duration,
    timeouts: &TcpTimeouts,
    client_read: &mut OwnedReadHalf,
    client_write: &mut OwnedWriteHalf,
    replay: &mut ReplayBufState,
) -> Result<Option<Vec<u8>>> {
    let mut client_half_closed = false;
    let mut deferred_phase1_failures: Vec<(usize, String, String)> = Vec::new();
    // Counts transparent same-uplink retries after a chunk-0 WS reset.
    // Reset to 0 whenever we switch to a different uplink.
    let mut rst_retries_on_current_uplink: u8 = 0;
    // Single scratch buffer reused across every phase-1 failover attempt.
    // Allocated once here so a chunk-0 failover does not re-allocate 64 KiB
    // per retry.
    let mut rbuf = vec![0u8; SHADOWSOCKS_MAX_PAYLOAD];

    loop {
        let can_failover = strict_transport
            && !replay.overflow
            && tried_indexes.len() < uplinks.uplinks().len();
        // `attempt_timeout` is mutable because `replay.overflow` can flip to
        // true mid-iteration (when the client body exceeds
        // MAX_CHUNK0_FAILOVER_BUF).  Once replay is no longer possible,
        // cross-uplink failover is pointless, so we must switch to the
        // configured `upstream_response` window instead of continuing to
        // enforce the aggressive chunk-0 timeout.  Without this promotion,
        // a large request body (e.g. Codex `compact`) would always hit the
        // 10 s deadline as soon as the client finished sending — fail over to
        // the next uplink with a truncated replay — time out again — and
        // eventually surface a client-side "error sending request" even
        // though the upstream was simply taking longer than 10 s to produce
        // its first byte.
        let mut attempt_timeout = if can_failover {
            chunk0_attempt_timeout
        } else {
            timeouts.upstream_response
        };
        let mut deadline = tokio::time::Instant::now() + attempt_timeout;

        let attempt: Result<Vec<u8>> = loop {
            if client_half_closed {
                break tokio::time::timeout_at(deadline, active.reader.read_chunk())
                    .await
                    .map_err(|_| {
                        anyhow!(
                            "upstream did not respond within {}s (chunk 0)",
                            attempt_timeout.as_secs(),
                        )
                    })?;
            }

            tokio::select! {
                result = active.reader.read_chunk() => {
                    break result;
                }
                n_res = client_read.read(&mut rbuf) => {
                    match n_res {
                        Ok(0) => {
                            active.writer.close().await.context("uplink half-close failed")?;
                            client_half_closed = true;
                        }
                        Ok(n) => {
                            active.writer
                                .send_chunk(&rbuf[..n])
                                .await
                                .context("uplink write failed")?;
                            metrics::add_bytes(
                                "tcp",
                                "client_to_upstream",
                                uplinks.group_name(),
                                &active.name,
                                n,
                            );
                            // Do not treat client→upstream bytes during phase 1
                            // as proof that the uplink is healthy yet.  A broken
                            // uplink can still accept writes and then reset or
                            // stall before producing the first response byte.
                            if replay.push(&rbuf[..n]) {
                                // Overflow just triggered — promote to the full
                                // response window immediately so the deadline
                                // reflects the new timeout before we reset it.
                                attempt_timeout = timeouts.upstream_response;
                            }
                            // Treat the deadline as "no response after the last
                            // request activity", not "no response since the
                            // beginning of phase 1".  Computed after the
                            // possible promotion above so the longer window
                            // takes effect on the very same chunk.
                            deadline = tokio::time::Instant::now() + attempt_timeout;
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
                client_write.shutdown().await.context("client shutdown failed")?;
                return Ok(None);
            }
            Ok(chunk) => {
                // Flush deferred failure records now that we have proof the
                // session is alive via a different uplink.
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
                        recovered_via = %active.name,
                        "recorded deferred TCP chunk-0 runtime failure after successful failover"
                    );
                }
                return Ok(Some(chunk));
            }
            Err(ref e) if active.reader.closed_cleanly() => {
                debug!(
                    uplink = %active.name,
                    error = %format!("{e:#}"),
                    "upstream closed before sending any data (phase 1)"
                );
                client_write.shutdown().await.context("client shutdown failed")?;
                return Ok(None);
            }
            Err(e) => {
                let mut phase1_error = e;

                // ── Warm-standby stale-socket retry ─────────────────────────
                // If the connection came from the standby pool, try once more
                // with a fresh dial before treating the failure as real.
                if active.source == TcpUplinkSource::Standby {
                    debug!(
                        uplink = %active.name,
                        error = %format!("{phase1_error:#}"),
                        "TCP phase-1 failure on warm-standby socket; retrying same uplink with a fresh dial"
                    );
                    match connect_tcp_uplink_fresh(uplinks, &active.candidate, target).await {
                        Ok(reconnected) => {
                            active.replace_transport(reconnected);
                            replay
                                .replay_to(&mut active.writer, "replay to fresh uplink after standby failure failed")
                                .await?;
                            if client_half_closed {
                                active.writer
                                    .close()
                                    .await
                                    .context("fresh uplink half-close after standby failure failed")?;
                            }
                            continue;
                        }
                        Err(connect_err) => {
                            phase1_error = connect_err
                                .context("fresh dial retry after warm-standby phase-1 failure failed");
                        }
                    }
                }

                // ── Transparent same-uplink RST retry ────────────────────────
                // A brief transit flap at the uplink egress frequently resets
                // fresh WS handshakes on multiple uplinks within a few hundred
                // ms; jumping straight to cross-uplink failover is a worse
                // outcome than re-dialing the same endpoint once the flap
                // clears.  Bounded retries + short backoff cap the worst-case
                // recovery at well under a second.  Only applied to fresh-dial
                // sources: Standby has its own retry branch above, and
                // DirectSocket does not go through WebSocket.
                if active.source == TcpUplinkSource::FreshDial
                    && rst_retries_on_current_uplink < CHUNK0_RST_MAX_RETRIES
                    && crate::disconnect::is_ws_closed(&phase1_error)
                {
                    let attempt_num = rst_retries_on_current_uplink + 1;
                    debug!(
                        uplink = %active.name,
                        target = %target,
                        retry = attempt_num,
                        max_retries = CHUNK0_RST_MAX_RETRIES,
                        error = %format!("{phase1_error:#}"),
                        "TCP chunk-0 transport reset; silently retrying same uplink before failover"
                    );
                    tokio::time::sleep(CHUNK0_RST_RETRY_BACKOFF).await;
                    match connect_tcp_uplink_fresh(uplinks, &active.candidate, target).await {
                        Ok(reconnected) => {
                            active.replace_transport(reconnected);
                            rst_retries_on_current_uplink = attempt_num;
                            replay
                                .replay_to(&mut active.writer, "replay to retried uplink after chunk-0 reset failed")
                                .await?;
                            if client_half_closed {
                                active.writer
                                    .close()
                                    .await
                                    .context("retried uplink half-close after chunk-0 reset failed")?;
                            }
                            continue;
                        }
                        Err(connect_err) => {
                            phase1_error = connect_err
                                .context("fresh dial retry after chunk-0 transport reset failed");
                        }
                    }
                }

                let error_text = format!("{phase1_error:#}");
                let attempted_uplinks = outline_uplink::deduplicate_attempted_uplink_names(
                    deferred_phase1_failures.iter().map(|(_, name, _)| name.as_str()),
                    &active.name,
                );
                warn!(
                    uplink = %active.name,
                    attempted_uplinks = ?attempted_uplinks,
                    target = %target,
                    rst_retries_applied = rst_retries_on_current_uplink,
                    error = %error_text,
                    "TCP chunk-0 failure"
                );

                if !can_failover {
                    if deferred_phase1_failures.is_empty() {
                        // Apply the same attribution logic as phase 2: a
                        // WebSocket close (including Close 1013 "try again"
                        // from the server) means the uplink itself is healthy —
                        // the remote target was just unreachable.  Using
                        // report_runtime_failure here would put the uplink into
                        // a cooldown and degrade unrelated sessions for blocked
                        // social-media targets.  Use the lighter
                        // report_upstream_close instead so the probe cycle is
                        // not skipped but no cooldown is imposed.
                        if crate::disconnect::is_upstream_runtime_failure(&phase1_error) {
                            uplinks
                                .report_runtime_failure(
                                    active.index,
                                    TransportKind::Tcp,
                                    &phase1_error,
                                )
                                .await;
                        } else if crate::disconnect::is_ws_closed(&phase1_error) {
                            uplinks
                                .report_upstream_close(active.index, TransportKind::Tcp)
                                .await;
                        }
                    } else {
                        warn!(
                            last_uplink = %active.name,
                            attempts = attempted_uplinks.len(),
                            attempted_uplinks = ?attempted_uplinks,
                            error = %error_text,
                            "suppressing TCP chunk-0 runtime failure attribution because every attempted uplink stalled before the first response"
                        );
                    }
                    return Err(phase1_error);
                }

                // ── Cross-uplink failover ─────────────────────────────────────
                deferred_phase1_failures.push((
                    active.index,
                    active.name.to_string(),
                    error_text,
                ));

                let candidates = uplinks
                    .tcp_failover_candidates(target, active.index)
                    .await;
                let next = candidates
                    .into_iter()
                    .find(|c| !tried_indexes.contains(&c.index));
                let Some(next_candidate) = next else {
                    return Err(
                        phase1_error
                            .context("no alternative uplink available for chunk-0 failover"),
                    );
                };
                tried_indexes.insert(next_candidate.index);

                let reconnected =
                    match connect_tcp_uplink(uplinks, &next_candidate, target).await {
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
                    .confirm_runtime_failover_uplink(
                        TransportKind::Tcp,
                        Some(target),
                        next_candidate.index,
                    )
                    .await;
                metrics::record_failover(
                    "tcp",
                    uplinks.group_name(),
                    &active.name,
                    &next_candidate.uplink.name,
                );
                metrics::record_uplink_selected(
                    "tcp",
                    uplinks.group_name(),
                    &next_candidate.uplink.name,
                );
                info!(
                    from = %active.name,
                    to = %next_candidate.uplink.name,
                    "TCP chunk-0 failover"
                );

                active.switch_to(next_candidate, reconnected);
                rst_retries_on_current_uplink = 0;

                replay
                    .replay_to(&mut active.writer, "replay to failover uplink failed")
                    .await?;
                if client_half_closed {
                    active.writer
                        .close()
                        .await
                        .context("failover uplink half-close failed")?;
                }
                // Fall through → loop restarts with the new uplink.
            }
        }
    }
}
