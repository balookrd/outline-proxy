use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tracing::{debug, warn};

use shadowsocks_crypto::SHADOWSOCKS_MAX_PAYLOAD;
use socks5_proto::TargetAddr;

use outline_uplink::{TransportKind, UplinkManager};

use super::super::failover::{ActiveTcpUplink, TcpUplinkSource};
use super::attribution::attribute_terminal_chunk0_failure;
use super::failover_step::{FailoverStep, failover_to_next_candidate, replay_after_failover};
use super::first_chunk::{FirstChunkCtx, await_first_upstream_chunk};
use super::replay::ReplayBufState;
use super::retry::{
    CHUNK0_RST_MAX_RETRIES, CHUNK0_RST_RETRY_BACKOFF, redial_current_uplink_and_replay,
    should_retry_rst_on_current_uplink,
};
use crate::proxy::TcpTimeouts;

/// Static inputs for a phase-1 run.  Bundled so the retry/failover loop can
/// pass them around without swelling individual function signatures.
#[derive(Clone, Copy)]
pub(super) struct Phase1Params<'a> {
    pub uplinks: &'a UplinkManager,
    pub target: &'a TargetAddr,
    pub strict_transport: bool,
    pub chunk0_attempt_timeout: std::time::Duration,
    pub timeouts: &'a TcpTimeouts,
}

/// Records a phase-1 chunk-0 failure that has not yet been attributed,
/// pending proof (via successful failover) that the uplink — not the
/// remote target — was at fault.
pub(super) struct DeferredFailure {
    pub index: usize,
    pub uplink: Arc<str>,
    pub error: String,
}

/// Waits for the first upstream response chunk while forwarding client data,
/// transparently failing over to alternative uplinks (and replaying buffered
/// client bytes) when an uplink resets or stalls before responding.
///
/// Returns `Ok(Some(chunk))` once the first upstream byte arrives.  Returns
/// `Ok(None)` when the upstream closed cleanly before sending any data; in
/// that case `client_write` has already been shut down and the caller should
/// return `Ok(())` immediately.
pub(super) async fn try_uplinks(
    params: &Phase1Params<'_>,
    active: &mut ActiveTcpUplink,
    tried_indexes: &mut HashSet<usize>,
    client_read: &mut OwnedReadHalf,
    client_write: &mut OwnedWriteHalf,
    replay: &mut ReplayBufState,
) -> Result<Option<Vec<u8>>> {
    let Phase1Params {
        uplinks,
        target,
        strict_transport,
        chunk0_attempt_timeout,
        timeouts,
    } = *params;
    let mut client_half_closed = false;
    let mut deferred_phase1_failures: Vec<DeferredFailure> = Vec::new();
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
        let initial_attempt_timeout = if can_failover {
            chunk0_attempt_timeout
        } else {
            timeouts.upstream_response
        };

        let chunk_ctx = FirstChunkCtx {
            uplinks,
            initial_attempt_timeout,
            upstream_response_timeout: timeouts.upstream_response,
        };
        let attempt = await_first_upstream_chunk(
            &chunk_ctx,
            active,
            client_read,
            &mut rbuf,
            replay,
            &mut client_half_closed,
        )
        .await;

        match attempt {
            Ok(chunk) if chunk.is_empty() => {
                client_write.shutdown().await.context("client shutdown failed")?;
                return Ok(None);
            }
            Ok(chunk) => {
                // Flush deferred failure records now that we have proof the
                // session is alive via a different uplink.
                for DeferredFailure { index, uplink, error } in
                    deferred_phase1_failures.drain(..)
                {
                    let deferred_error = anyhow!(error.clone());
                    uplinks
                        .report_runtime_failure(index, TransportKind::Tcp, &deferred_error)
                        .await;
                    debug!(
                        uplink = %uplink,
                        error = %error,
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
                    match redial_current_uplink_and_replay(
                        uplinks,
                        active,
                        target,
                        replay,
                        client_half_closed,
                        "replay to fresh uplink after standby failure failed",
                        "fresh uplink half-close after standby failure failed",
                    )
                    .await
                    {
                        Ok(()) => continue,
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
                if should_retry_rst_on_current_uplink(
                    active.source,
                    rst_retries_on_current_uplink,
                    &phase1_error,
                ) {
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
                    match redial_current_uplink_and_replay(
                        uplinks,
                        active,
                        target,
                        replay,
                        client_half_closed,
                        "replay to retried uplink after chunk-0 reset failed",
                        "retried uplink half-close after chunk-0 reset failed",
                    )
                    .await
                    {
                        Ok(()) => {
                            rst_retries_on_current_uplink = attempt_num;
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
                    deferred_phase1_failures.iter().map(|f| f.uplink.as_ref()),
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
                    attribute_terminal_chunk0_failure(
                        uplinks,
                        active,
                        &phase1_error,
                        &deferred_phase1_failures,
                        &attempted_uplinks,
                        &error_text,
                    )
                    .await;
                    return Err(phase1_error);
                }

                // ── Cross-uplink failover ─────────────────────────────────────
                deferred_phase1_failures.push(DeferredFailure {
                    index: active.index,
                    uplink: Arc::clone(&active.name),
                    error: error_text,
                });

                match failover_to_next_candidate(uplinks, active, target, tried_indexes).await? {
                    FailoverStep::NoCandidate => {
                        return Err(phase1_error
                            .context("no alternative uplink available for chunk-0 failover"));
                    },
                    FailoverStep::Switched => {
                        rst_retries_on_current_uplink = 0;
                        replay_after_failover(active, replay, client_half_closed).await?;
                        // Fall through → loop restarts with the new uplink.
                    },
                }
            }
        }
    }
}
