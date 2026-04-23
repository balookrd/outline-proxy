use std::time::{Duration, Instant};

use anyhow::Result;

use crate::config::TunTcpConfig;

use super::TCP_TIME_WAIT_TIMEOUT;
use super::state_machine::{
    TcpFlowState, TcpFlowStatus, half_close_timed_out, handshake_timed_out, idle_timed_out,
    is_half_closed_status, keepalive_probe_eligible, keepalive_probe_is_due,
    keepalive_probes_exhausted, maybe_emit_keepalive_probe, maybe_emit_zero_window_probe,
    next_keepalive_deadline, next_retransmission_deadline, note_congestion_event,
    retransmit_budget_exhausted, retransmit_due_segment, retransmit_is_due, sync_flow_metrics,
    time_wait_expired, zero_window_probe_is_due,
};

pub(super) enum FlowMaintenancePlan {
    Wait(Option<Instant>),
    SendPacket {
        packet: Vec<u8>,
        packet_metric: &'static str,
        event: &'static str,
    },
    Abort(&'static str),
    Close(&'static str),
}

pub(super) fn commit_flow_changes(state: &mut TcpFlowState, tcp: &TunTcpConfig) {
    sync_flow_metrics(state);
    reschedule_flow(state, tcp);
}

/// Recompute the flow's next maintenance deadline and push it onto the
/// scheduler.  Old heap entries are never removed — the loop re-validates
/// popped entries against `next_scheduled_deadline` and discards stale
/// ones.  To avoid unbounded heap growth we only push when the deadline
/// moves earlier (or no entry exists); later deadlines just wake the loop
/// so it can re-sleep against the updated horizon.
fn reschedule_flow(state: &mut TcpFlowState, tcp: &TunTcpConfig) {
    if state.status == TcpFlowStatus::Closed {
        state.next_scheduled_deadline = None;
        return;
    }
    let new_deadline = next_flow_deadline(state, tcp, state.signals.idle_timeout);
    match new_deadline {
        Some(new_deadline) => {
            let push = match state.next_scheduled_deadline {
                None => true,
                Some(current) => new_deadline < current,
            };
            state.next_scheduled_deadline = Some(new_deadline);
            if push {
                state
                    .signals
                    .scheduler
                    .schedule(state.key.clone(), new_deadline);
            } else {
                state.signals.scheduler.wake();
            }
        },
        None => {
            state.next_scheduled_deadline = None;
        },
    }
}

fn next_zero_window_probe_deadline(state: &TcpFlowState) -> Option<Instant> {
    if state.client_window == 0
        && !state.pending_server_data.is_empty()
        && state.unacked_server_segments.is_empty()
    {
        Some(state.next_zero_window_probe_at.unwrap_or_else(Instant::now))
    } else {
        None
    }
}

pub(super) fn next_flow_deadline(
    state: &TcpFlowState,
    tcp: &TunTcpConfig,
    idle_timeout: Duration,
) -> Option<Instant> {
    let mut deadline = next_retransmission_deadline(state)
        .into_iter()
        .chain(next_zero_window_probe_deadline(state))
        .chain(next_keepalive_deadline(
            state,
            tcp.keepalive_idle,
            tcp.keepalive_interval,
        ))
        .min();

    if state.status == TcpFlowStatus::SynReceived {
        deadline = Some(
            deadline
                .map(|current| current.min(state.timestamps.status_since + tcp.handshake_timeout))
                .unwrap_or(state.timestamps.status_since + tcp.handshake_timeout),
        );
    }

    if is_half_closed_status(state.status) {
        deadline = Some(
            deadline
                .map(|current| current.min(state.timestamps.status_since + tcp.half_close_timeout))
                .unwrap_or(state.timestamps.status_since + tcp.half_close_timeout),
        );
    }

    if state.status == TcpFlowStatus::TimeWait {
        deadline = Some(
            deadline
                .map(|current| current.min(state.timestamps.status_since + TCP_TIME_WAIT_TIMEOUT))
                .unwrap_or(state.timestamps.status_since + TCP_TIME_WAIT_TIMEOUT),
        );
    } else {
        deadline = Some(
            deadline
                .map(|current| current.min(state.timestamps.last_seen + idle_timeout))
                .unwrap_or(state.timestamps.last_seen + idle_timeout),
        );
    }

    deadline
}

pub(super) fn plan_flow_maintenance(
    state: &mut TcpFlowState,
    tcp: &TunTcpConfig,
    idle_timeout: Duration,
    now: Instant,
) -> Result<FlowMaintenancePlan> {
    if time_wait_expired(state.status, state.timestamps.status_since, now) {
        return Ok(FlowMaintenancePlan::Close("time_wait_expired"));
    }

    if handshake_timed_out(state.status, state.timestamps.status_since, tcp.handshake_timeout, now) {
        return Ok(FlowMaintenancePlan::Abort("handshake_timeout"));
    }

    if half_close_timed_out(state.status, state.timestamps.status_since, tcp.half_close_timeout, now) {
        return Ok(FlowMaintenancePlan::Abort("half_close_timeout"));
    }

    if idle_timed_out(state.status, state.timestamps.last_seen, idle_timeout, now) {
        return Ok(FlowMaintenancePlan::Abort("idle_timeout"));
    }

    if retransmit_is_due(state, now)
        && let Some(packet) = retransmit_due_segment(state)?
    {
        note_congestion_event(state, true);
        if retransmit_budget_exhausted(state, tcp) {
            return Ok(FlowMaintenancePlan::Abort("retransmit_budget_exhausted"));
        }
        commit_flow_changes(state, tcp);
        return Ok(FlowMaintenancePlan::SendPacket {
            packet,
            packet_metric: "tcp_retransmit",
            event: "timeout_retransmit",
        });
    }

    if zero_window_probe_is_due(state, now)
        && let Some(packet) = maybe_emit_zero_window_probe(state)?
    {
        commit_flow_changes(state, tcp);
        return Ok(FlowMaintenancePlan::SendPacket {
            packet,
            packet_metric: "tcp_window_probe",
            event: "zero_window_probe",
        });
    }

    if tcp.keepalive_idle.is_some()
        && keepalive_probe_eligible(state)
        && keepalive_probes_exhausted(
            state.keepalive_probes_sent,
            tcp.keepalive_max_probes,
            state.last_keepalive_probe_at,
            tcp.keepalive_interval,
            now,
        )
    {
        return Ok(FlowMaintenancePlan::Abort("keepalive_timeout"));
    }

    if keepalive_probe_is_due(state, tcp.keepalive_idle, tcp.keepalive_interval, now)
        && let Some(packet) =
            maybe_emit_keepalive_probe(state, tcp.keepalive_idle, tcp.keepalive_interval)?
    {
        commit_flow_changes(state, tcp);
        return Ok(FlowMaintenancePlan::SendPacket {
            packet,
            packet_metric: "tcp_keepalive_probe",
            event: "keepalive_probe",
        });
    }

    Ok(FlowMaintenancePlan::Wait(next_flow_deadline(state, tcp, idle_timeout)))
}
