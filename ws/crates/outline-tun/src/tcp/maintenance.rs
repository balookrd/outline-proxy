use std::time::{Duration, Instant};

use anyhow::Result;

use crate::config::TunTcpConfig;

use super::TCP_TIME_WAIT_TIMEOUT;
use super::state_machine::{
    TcpFlowState, TcpFlowStatus, half_close_timed_out, handshake_timed_out, idle_timed_out,
    is_half_closed_status, keepalive_probe_eligible, keepalive_probes_exhausted,
    maybe_emit_keepalive_probe, maybe_emit_zero_window_probe, next_keepalive_deadline,
    next_retransmission_deadline, note_congestion_event, retransmit_budget_exhausted,
    retransmit_due_segment, sync_flow_metrics, time_wait_expired,
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

pub(super) fn sync_flow_metrics_and_wake(state: &mut TcpFlowState) {
    sync_flow_metrics(state);
    state.maintenance_notify.notify_one();
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

fn next_flow_deadline(
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
                .map(|current| current.min(state.status_since + tcp.handshake_timeout))
                .unwrap_or(state.status_since + tcp.handshake_timeout),
        );
    }

    if is_half_closed_status(state.status) {
        deadline = Some(
            deadline
                .map(|current| current.min(state.status_since + tcp.half_close_timeout))
                .unwrap_or(state.status_since + tcp.half_close_timeout),
        );
    }

    if state.status == TcpFlowStatus::TimeWait {
        deadline = Some(
            deadline
                .map(|current| current.min(state.status_since + TCP_TIME_WAIT_TIMEOUT))
                .unwrap_or(state.status_since + TCP_TIME_WAIT_TIMEOUT),
        );
    } else {
        deadline = Some(
            deadline
                .map(|current| current.min(state.last_seen + idle_timeout))
                .unwrap_or(state.last_seen + idle_timeout),
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
    if time_wait_expired(state.status, state.status_since, now) {
        return Ok(FlowMaintenancePlan::Close("time_wait_expired"));
    }

    if handshake_timed_out(state.status, state.status_since, tcp.handshake_timeout, now) {
        return Ok(FlowMaintenancePlan::Abort("handshake_timeout"));
    }

    if half_close_timed_out(state.status, state.status_since, tcp.half_close_timeout, now) {
        return Ok(FlowMaintenancePlan::Abort("half_close_timeout"));
    }

    if idle_timed_out(state.status, state.last_seen, idle_timeout, now) {
        return Ok(FlowMaintenancePlan::Abort("idle_timeout"));
    }

    if let Some(packet) = retransmit_due_segment(state)? {
        note_congestion_event(state, true);
        if retransmit_budget_exhausted(state, tcp) {
            return Ok(FlowMaintenancePlan::Abort("retransmit_budget_exhausted"));
        }
        sync_flow_metrics_and_wake(state);
        return Ok(FlowMaintenancePlan::SendPacket {
            packet,
            packet_metric: "tcp_retransmit",
            event: "timeout_retransmit",
        });
    }

    if let Some(packet) = maybe_emit_zero_window_probe(state)? {
        sync_flow_metrics_and_wake(state);
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

    if let Some(packet) =
        maybe_emit_keepalive_probe(state, tcp.keepalive_idle, tcp.keepalive_interval)?
    {
        sync_flow_metrics_and_wake(state);
        return Ok(FlowMaintenancePlan::SendPacket {
            packet,
            packet_metric: "tcp_keepalive_probe",
            event: "keepalive_probe",
        });
    }

    Ok(FlowMaintenancePlan::Wait(next_flow_deadline(state, tcp, idle_timeout)))
}
