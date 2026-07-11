use std::time::{Duration, Instant};

use anyhow::Result;

use crate::config::TunTcpConfig;

use super::state_machine::{
    ServerDataPacket, ServerFlush, TcpFlowState, TcpFlowStatus, build_flow_ack_packet,
    clear_delayed_ack, flush_server_output, half_close_timed_out, handshake_timed_out,
    idle_timed_out, is_half_closed_status, keepalive_probe_eligible, keepalive_probe_is_due,
    keepalive_probes_exhausted, maybe_emit_keepalive_probe, maybe_emit_zero_window_probe,
    next_keepalive_deadline, next_retransmission_deadline, note_congestion_event,
    retransmit_budget_exhausted, retransmit_due_segment, retransmit_is_due, sync_flow_metrics,
    time_wait_expired, zero_window_probe_is_due,
};
use super::{TCP_FLAG_ACK, TCP_TIME_WAIT_TIMEOUT};

pub(super) enum FlowMaintenancePlan {
    Wait(Option<Instant>),
    SendPacket {
        packet: Vec<u8>,
        packet_metric: &'static str,
        event: &'static str,
    },
    /// A retransmit whose payload is carried by reference (an owned `Bytes` on
    /// the scoreboard) and written vectored, so the resent segment is not copied
    /// into a packet buffer. Always a single MSS segment (`vnet: None`).
    SendDataPacket {
        packet: ServerDataPacket,
        packet_metric: &'static str,
        event: &'static str,
    },
    /// Pacing wakeup: the BBR pacer released credit for queued downlink data.
    /// The engine emits the flush packets exactly like the inbound path does.
    /// This is the timer fallback for app-limited/idle gaps; on a live flow the
    /// next ACK re-runs the flush before this fires.
    FlushServer(ServerFlush),
    Abort(&'static str),
    Close(&'static str),
}

/// Deadline at which the pacer will release more downlink data, if a paced
/// flush stopped with bytes still queued.
fn next_pacing_deadline(state: &TcpFlowState) -> Option<Instant> {
    if state.pending_server_data.is_empty() {
        None
    } else {
        state.bbr.pacing_next_at
    }
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
                state.signals.scheduler.schedule(state.key.clone(), new_deadline);
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
        .chain(next_pacing_deadline(state))
        .chain(next_keepalive_deadline(state, tcp.keepalive_idle, tcp.keepalive_interval))
        .chain(state.delayed_ack_deadline)
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

    if handshake_timed_out(state.status, state.timestamps.status_since, tcp.handshake_timeout, now)
    {
        return Ok(FlowMaintenancePlan::Abort("handshake_timeout"));
    }

    if half_close_timed_out(
        state.status,
        state.timestamps.status_since,
        tcp.half_close_timeout,
        now,
    ) {
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
        return Ok(FlowMaintenancePlan::SendDataPacket {
            packet,
            packet_metric: "tcp_retransmit",
            event: "timeout_retransmit",
        });
    }

    // Pacing wakeup: the BBR pacer's credit has refilled enough to release more
    // queued downlink data. Re-run the flush (which refills credit and emits as
    // much as pacing now allows, re-arming `bbr.pacing_next_at` if more remains).
    if next_pacing_deadline(state)
        .map(|deadline| deadline <= now)
        .unwrap_or(false)
    {
        let flush = flush_server_output(state)?;
        commit_flow_changes(state, tcp);
        return Ok(FlowMaintenancePlan::FlushServer(flush));
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

    // Delayed-ACK timer: a lone in-order segment deferred its ACK; the 2nd
    // segment never arrived within the hold window, so flush the standalone ACK
    // now. `build_flow_ack_packet` carries the current SACK blocks, so this is
    // correct even if a hole opened after the segment was accepted.
    if let Some(deadline) = state.delayed_ack_deadline
        && deadline <= now
    {
        let packet = build_flow_ack_packet(state, state.server_seq, state.rcv_nxt, TCP_FLAG_ACK)?;
        clear_delayed_ack(state);
        commit_flow_changes(state, tcp);
        return Ok(FlowMaintenancePlan::SendPacket {
            packet,
            packet_metric: "tcp_ack",
            event: "delayed_ack",
        });
    }

    Ok(FlowMaintenancePlan::Wait(next_flow_deadline(state, tcp, idle_timeout)))
}
