use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use anyhow::{Context, Result};
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

/// Static inputs for a chunk-0 failover run.  Bundled so the retry/failover
/// loop can pass them around without swelling individual function signatures.
#[derive(Clone, Copy)]
pub(super) struct Chunk0FailoverParams<'a> {
    pub uplinks: &'a UplinkManager,
    pub target: &'a TargetAddr,
    pub strict_transport: bool,
    pub chunk0_attempt_timeout: std::time::Duration,
    pub timeouts: &'a TcpTimeouts,
}

/// Records a chunk-0 failure that has not yet been attributed,
/// pending proof (via successful failover) that the uplink — not the
/// remote target — was at fault.
pub(super) struct DeferredFailure {
    pub index: usize,
    pub uplink: Arc<str>,
    pub error: anyhow::Error,
}

/// Hard cap on the number of deferred chunk-0 failures retained per session.
/// Bounds memory in pathological deployments with hundreds of uplinks where
/// every candidate stalls before the first response byte; once exceeded the
/// oldest record is dropped (its uplink is still listed via `tried_indexes`,
/// it just won't be back-attributed if a later uplink succeeds).
pub(super) const DEFERRED_CHUNK0_FAILURES_CAP: usize = 10;

/// Waits for the first upstream response chunk while forwarding client data,
/// transparently failing over to alternative uplinks (and replaying buffered
/// client bytes) when an uplink resets or stalls before responding.
///
/// Returns `Ok(Some(chunk))` once the first upstream byte arrives.  Returns
/// `Ok(None)` when the upstream closed cleanly before sending any data; in
/// that case `client_write` has already been shut down and the caller should
/// return `Ok(())` immediately.
pub(super) async fn try_uplinks(
    params: &Chunk0FailoverParams<'_>,
    active: &mut ActiveTcpUplink,
    tried_indexes: &mut HashSet<usize>,
    client_read: &mut OwnedReadHalf,
    client_write: &mut OwnedWriteHalf,
    replay: &mut ReplayBufState,
) -> Result<Option<Vec<u8>>> {
    let Chunk0FailoverParams {
        uplinks,
        target,
        strict_transport,
        chunk0_attempt_timeout,
        timeouts,
    } = *params;
    let mut client_half_closed = false;
    let mut deferred_failures: VecDeque<DeferredFailure> =
        VecDeque::with_capacity(DEFERRED_CHUNK0_FAILURES_CAP);
    // Counts transparent same-uplink retries after a chunk-0 WS reset.
    // Reset to 0 whenever we switch to a different uplink.
    let mut rst_retries_on_current_uplink: u8 = 0;
    // Per-uplink set of wires already attempted during this session's
    // chunk-0 failover loop. Each entry seeds with the wire that just
    // failed before failover_to_next_candidate is called, so the wire-
    // handover phase doesn't immediately retry it. Survives across
    // cross-uplink jumps so re-encountering the same uplink doesn't
    // re-try wires we already exhausted on it.
    let mut tried_wires_per_uplink: HashMap<usize, HashSet<u8>> = HashMap::new();
    // Single scratch buffer reused across every chunk-0 failover attempt.
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
                    deferred_failures.drain(..)
                {
                    debug!(
                        uplink = %uplink,
                        error = %format!("{error:#}"),
                        recovered_via = %active.name,
                        "recorded deferred TCP chunk-0 runtime failure after successful failover"
                    );
                    uplinks
                        .report_runtime_failure(index, TransportKind::Tcp, &error)
                        .await;
                }
                return Ok(Some(chunk));
            }
            Err(ref e) if active.reader.closed_cleanly() => {
                debug!(
                    uplink = %active.name,
                    error = %format!("{e:#}"),
                    "upstream closed before sending any data (chunk-0 failover)"
                );
                client_write.shutdown().await.context("client shutdown failed")?;
                return Ok(None);
            }
            Err(e) => {
                let mut chunk0_error = e;

                // ── Warm-standby stale-socket retry ─────────────────────────
                // If the connection came from the standby pool, try once more
                // with a fresh dial before treating the failure as real.
                if active.source == TcpUplinkSource::Standby {
                    debug!(
                        uplink = %active.name,
                        error = %format!("{chunk0_error:#}"),
                        "TCP chunk-0 failure on warm-standby socket; retrying same uplink with a fresh dial"
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
                            chunk0_error = connect_err
                                .context("fresh dial retry after warm-standby chunk-0 failure failed");
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
                    &chunk0_error,
                ) {
                    let attempt_num = rst_retries_on_current_uplink + 1;
                    debug!(
                        uplink = %active.name,
                        target = %target,
                        retry = attempt_num,
                        max_retries = CHUNK0_RST_MAX_RETRIES,
                        error = %format!("{chunk0_error:#}"),
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
                            chunk0_error = connect_err
                                .context("fresh dial retry after chunk-0 transport reset failed");
                        }
                    }
                }

                let error_text = format!("{chunk0_error:#}");
                let attempted_uplinks = outline_uplink::deduplicate_attempted_uplink_names(
                    deferred_failures.iter().map(|f| f.uplink.as_ref()),
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
                        &chunk0_error,
                        &deferred_failures,
                        &attempted_uplinks,
                        &error_text,
                    )
                    .await;
                    return Err(chunk0_error);
                }

                // ── Cross-uplink failover ─────────────────────────────────────
                let failed_index = active.index;
                let failed_uplink = Arc::clone(&active.name);

                match failover_to_next_candidate(
                    uplinks,
                    active,
                    target,
                    tried_indexes,
                    &mut tried_wires_per_uplink,
                )
                .await?
                {
                    FailoverStep::NoCandidate => {
                        return Err(chunk0_error
                            .context("no alternative uplink available for chunk-0 failover"));
                    },
                    FailoverStep::Switched => {
                        if deferred_failures.len() == DEFERRED_CHUNK0_FAILURES_CAP {
                            deferred_failures.pop_front();
                        }
                        deferred_failures.push_back(DeferredFailure {
                            index: failed_index,
                            uplink: failed_uplink,
                            error: chunk0_error,
                        });
                        rst_retries_on_current_uplink = 0;
                        replay_after_failover(active, replay, client_half_closed).await?;
                        // Fall through → loop restarts with the new uplink.
                    },
                }
            }
        }
    }
}
