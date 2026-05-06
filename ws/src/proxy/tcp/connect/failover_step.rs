//! Cross-uplink failover step for chunk-0 failover.
//!
//! When same-uplink recovery (see `connect/retry.rs`) has been exhausted and
//! we still have not received the first upstream byte, the chunk-0-failover
//! loop switches the active connection to a different uplink candidate.  This
//! module owns the "pick next candidate → dial → confirm selection →
//! metrics/logging → switch active" sequence so the orchestration loop in
//! `chunk0_failover.rs` can focus on retry policy and replay.

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};
use tracing::{debug, info};

use outline_metrics as metrics;
use outline_uplink::{TransportKind, UplinkManager};
use socks5_proto::TargetAddr;

use super::super::failover::{
    ActiveTcpUplink, connect_tcp_specific_wire, connect_tcp_uplink,
};

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
    tried_wires_per_uplink: &mut HashMap<usize, HashSet<u8>>,
) -> Result<FailoverStep> {
    // ── Phase A: try the next wire on the *same* uplink ────────────────────
    // Before jumping to a different uplink we try every other wire of the
    // current candidate (handover-within-uplink). This lets the resume-cache
    // token issued for the failed wire ride into the next wire's dial; the
    // server-side X-Outline-Resume mechanism re-attaches the upstream
    // session so the chunk-0 replay buffer is *all* the client-visible
    // change. Cross-uplink failover (Phase B below) only kicks in when
    // every wire on this uplink has been exhausted.
    let total_wires = 1 + active.candidate.uplink.fallbacks.len();
    let tried_on_current = tried_wires_per_uplink
        .entry(active.index)
        .or_default();
    tried_on_current.insert(active.wire_index);

    if total_wires > 1 {
        // Try wires in the manager's preferred order (active wire first,
        // wrapping). The currently-failed wire is in `tried_on_current`
        // and will be skipped.
        let order = uplinks.wire_dial_order(active.index, TransportKind::Tcp, total_wires);
        for &candidate_wire in &order {
            if tried_on_current.contains(&candidate_wire) {
                continue;
            }
            tried_on_current.insert(candidate_wire);
            match connect_tcp_specific_wire(uplinks, &active.candidate, target, candidate_wire)
                .await
            {
                Ok(reconnected) => {
                    let from_wire = active.wire_index;
                    debug!(
                        uplink = %active.name,
                        from_wire,
                        to_wire = candidate_wire,
                        "TCP chunk-0 wire handover (same uplink)",
                    );
                    metrics::record_failover(
                        "tcp_wire",
                        uplinks.group_name(),
                        &active.name,
                        &active.name,
                    );
                    active.replace_wire(reconnected);
                    // The dial-loop's record_wire_outcome accounting for
                    // this candidate_wire's success keeps the active-wire
                    // state machine consistent with the dial path.
                    uplinks.record_wire_outcome(
                        active.index,
                        TransportKind::Tcp,
                        candidate_wire,
                        true,
                        total_wires,
                    );
                    return Ok(FailoverStep::Switched);
                },
                Err(error) => {
                    debug!(
                        uplink = %active.name,
                        wire = candidate_wire,
                        error = %format!("{error:#}"),
                        "wire handover dial failed, trying next wire",
                    );
                    uplinks.record_wire_outcome(
                        active.index,
                        TransportKind::Tcp,
                        candidate_wire,
                        false,
                        total_wires,
                    );
                    // Continue to the next wire of this same uplink.
                },
            }
        }
        // Every wire of the current uplink is now in tried_on_current —
        // fall through to cross-uplink failover.
    }

    // ── Phase B: cross-uplink failover ─────────────────────────────────────
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

    // Seed tried-wires for the new candidate with the wire that just
    // succeeded so a subsequent wire-handover attempt on it doesn't retry
    // the same wire immediately.
    tried_wires_per_uplink
        .entry(next_candidate.index)
        .or_default()
        .insert(reconnected.wire_index);

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
