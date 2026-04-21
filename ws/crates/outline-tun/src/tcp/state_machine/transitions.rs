use std::time::Instant;

use super::super::TCP_ZERO_WINDOW_PROBE_BASE_INTERVAL;
use super::super::wire::ParsedTcpPacket;
use super::packets::update_client_send_window;
use super::types::{TcpFlowState, TcpFlowStatus};

pub(in crate::tcp) fn set_flow_status(state: &mut TcpFlowState, status: TcpFlowStatus) {
    if state.status != status {
        state.status = status;
        state.status_since = Instant::now();
    }
}

pub(in crate::tcp) fn client_fin_seen(status: TcpFlowStatus) -> bool {
    matches!(
        status,
        TcpFlowStatus::CloseWait
            | TcpFlowStatus::Closing
            | TcpFlowStatus::LastAck
            | TcpFlowStatus::TimeWait
            | TcpFlowStatus::Closed
    )
}

pub(in crate::tcp) fn server_fin_sent(status: TcpFlowStatus) -> bool {
    matches!(
        status,
        TcpFlowStatus::FinWait1
            | TcpFlowStatus::FinWait2
            | TcpFlowStatus::Closing
            | TcpFlowStatus::LastAck
            | TcpFlowStatus::TimeWait
            | TcpFlowStatus::Closed
    )
}

pub(in crate::tcp) fn server_fin_awaiting_ack(status: TcpFlowStatus) -> bool {
    matches!(
        status,
        TcpFlowStatus::FinWait1 | TcpFlowStatus::Closing | TcpFlowStatus::LastAck
    )
}

pub(in crate::tcp) fn transition_on_client_fin(state: &mut TcpFlowState) {
    match state.status {
        TcpFlowStatus::SynReceived | TcpFlowStatus::Established => {
            set_flow_status(state, TcpFlowStatus::CloseWait);
        },
        TcpFlowStatus::FinWait1 => {
            set_flow_status(state, TcpFlowStatus::Closing);
        },
        TcpFlowStatus::FinWait2 => {
            set_flow_status(state, TcpFlowStatus::TimeWait);
        },
        TcpFlowStatus::CloseWait
        | TcpFlowStatus::Closing
        | TcpFlowStatus::LastAck
        | TcpFlowStatus::TimeWait
        | TcpFlowStatus::Closed => {},
    }
}

pub(in crate::tcp) fn transition_on_server_fin_ack(state: &mut TcpFlowState) -> bool {
    match state.status {
        TcpFlowStatus::FinWait1 => {
            set_flow_status(state, TcpFlowStatus::FinWait2);
            false
        },
        TcpFlowStatus::Closing => {
            set_flow_status(state, TcpFlowStatus::TimeWait);
            false
        },
        TcpFlowStatus::LastAck => {
            set_flow_status(state, TcpFlowStatus::Closed);
            true
        },
        TcpFlowStatus::SynReceived
        | TcpFlowStatus::Established
        | TcpFlowStatus::CloseWait
        | TcpFlowStatus::FinWait2
        | TcpFlowStatus::TimeWait
        | TcpFlowStatus::Closed => false,
    }
}

pub(in crate::tcp) fn reset_zero_window_persist(state: &mut TcpFlowState) {
    state.zero_window_probe_backoff = TCP_ZERO_WINDOW_PROBE_BASE_INTERVAL;
    state.next_zero_window_probe_at = None;
}

pub(in crate::tcp) fn note_recent_client_timestamp(state: &mut TcpFlowState, timestamp_value: Option<u32>) {
    if state.timestamps_enabled
        && let Some(timestamp_value) = timestamp_value {
            state.recent_client_timestamp = Some(timestamp_value);
        }
}

/// Apply the bookkeeping that every accepted inbound segment triggers:
/// refresh the PAWS timestamp, bump `last_seen`, clear keepalive probe
/// counters (the segment is itself proof of liveness), absorb the advertised
/// receive window, and if the window is non-zero, reset the zero-window
/// persist backoff.
///
/// Does *not* call `sync_flow_metrics_and_wake` — the caller decides when to
/// wake the maintenance loop, since more mutations may follow in the same
/// critical section before it's worth notifying.
pub(in crate::tcp) fn absorb_accepted_client_packet(
    state: &mut TcpFlowState,
    packet: &ParsedTcpPacket,
) {
    note_recent_client_timestamp(state, packet.timestamp_value);
    state.last_seen = Instant::now();
    state.keepalive_probes_sent = 0;
    state.last_keepalive_probe_at = None;
    update_client_send_window(state, packet);
    if state.client_window > 0 {
        reset_zero_window_persist(state);
    }
}
