//! Cross-uplink failover step for chunk-0 failover.
//!
//! When same-uplink recovery (see `connect/retry.rs`) has been exhausted and
//! we still have not received the first upstream byte, the chunk-0-failover
//! loop switches the active connection to a different uplink candidate.  This
//! module owns the "pick next candidate → dial → confirm selection →
//! metrics/logging → switch active" sequence so the orchestration loop in
//! `chunk0_failover.rs` can focus on retry policy and replay.

use std::collections::HashSet;

use anyhow::{Context, Result};
use tracing::info;

use outline_metrics as metrics;
use outline_uplink::{TransportKind, UplinkManager};
use socks5_proto::TargetAddr;

use super::super::failover::{ActiveTcpUplink, connect_tcp_uplink};

pub(super) enum FailoverStep {
    /// `active` has been updated to a fresh uplink — the caller must now
    /// replay buffered client bytes and, if applicable, re-emit the client
    /// half-close onto the new transport.
    Switched,
    /// No untried failover candidate remains.  The caller should terminate
    /// chunk-0 failover with the original error.
    NoCandidate,
}

/// Finds the next untried failover candidate, dials it, confirms the selection
/// with the uplink manager, records metrics, and switches `active` to point at
/// the new transport.
///
/// On connect error the chosen candidate is immediately reported as a runtime
/// failure and the error is wrapped with a chunk-0-specific context before
/// being propagated; the caller does not need to attribute that failure
/// itself.
pub(super) async fn failover_to_next_candidate(
    uplinks: &UplinkManager,
    active: &mut ActiveTcpUplink,
    target: &TargetAddr,
    tried_indexes: &mut HashSet<usize>,
) -> Result<FailoverStep> {
    let candidates = uplinks
        .tcp_failover_candidates(target, active.index)
        .await;
    let Some(next_candidate) = candidates
        .into_iter()
        .find(|c| !tried_indexes.contains(&c.index))
    else {
        return Ok(FailoverStep::NoCandidate);
    };
    tried_indexes.insert(next_candidate.index);

    let reconnected = match connect_tcp_uplink(uplinks, &next_candidate, target).await {
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
    Ok(FailoverStep::Switched)
}

/// Replays buffered client bytes and, if the client has already half-closed,
/// re-emits the half-close onto the newly-switched transport.  Shared between
/// the cross-uplink failover step and any future post-switch recovery that
/// needs to reach a steady state before the chunk-0-failover loop continues.
pub(super) async fn replay_after_failover(
    active: &mut ActiveTcpUplink,
    replay: &super::replay::ReplayBufState,
    client_half_closed: bool,
) -> Result<()> {
    replay
        .replay_to(&mut active.writer, "replay to failover uplink failed")
        .await?;
    if client_half_closed {
        active
            .writer
            .close()
            .await
            .context("failover uplink half-close failed")?;
    }
    Ok(())
}
