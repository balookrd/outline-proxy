use std::time::{Duration, Instant};

use anyhow::Result;

use crate::config::TunTcpConfig;

use super::TCP_TIME_WAIT_TIMEOUT;
use super::state_machine::{
    TcpFlowState, TcpFlowStatus, maybe_emit_zero_window_probe, next_retransmission_deadline,
    note_congestion_event, retransmit_budget_exhausted, retransmit_due_segment, sync_flow_metrics,
};

pub(super) enum FlowMaintenancePlan {
    Wait(Option<Instant>),
    SendPacket { packet: Vec<u8>, packet_metric: &'static str, event: &'static str },
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
        .min();

    if state.status == TcpFlowStatus::SynReceived {
        deadline = Some(
            deadline
                .map(|current| current.min(state.status_since + tcp.handshake_timeout))
                .unwrap_or(state.status_since + tcp.handshake_timeout),
        );
    }

    if matches!(
        state.status,
        TcpFlowStatus::CloseWait
            | TcpFlowStatus::FinWait1
            | TcpFlowStatus::FinWait2
            | TcpFlowStatus::Closing
            | TcpFlowStatus::LastAck
    ) {
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
    if state.status == TcpFlowStatus::TimeWait
        && now.saturating_duration_since(state.status_since) >= TCP_TIME_WAIT_TIMEOUT
    {
        return Ok(FlowMaintenancePlan::Close("time_wait_expired"));
    }

    if state.status == TcpFlowStatus::SynReceived
        && now.saturating_duration_since(state.status_since) >= tcp.handshake_timeout
    {
        return Ok(FlowMaintenancePlan::Abort("handshake_timeout"));
    }

    if matches!(
        state.status,
        TcpFlowStatus::CloseWait
            | TcpFlowStatus::FinWait1
            | TcpFlowStatus::FinWait2
            | TcpFlowStatus::Closing
            | TcpFlowStatus::LastAck
    ) && now.saturating_duration_since(state.status_since) >= tcp.half_close_timeout
    {
        return Ok(FlowMaintenancePlan::Abort("half_close_timeout"));
    }

    if state.status != TcpFlowStatus::TimeWait
        && now.saturating_duration_since(state.last_seen) >= idle_timeout
    {
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

    Ok(FlowMaintenancePlan::Wait(next_flow_deadline(state, tcp, idle_timeout)))
}
