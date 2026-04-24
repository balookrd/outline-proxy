use std::time::Instant;

use bytes::Bytes;

use crate::config::TunTcpConfig;

use super::super::congestion::server_segment_is_sacked;
use super::super::types::{ServerBacklogPressure, TcpFlowState};

pub(super) fn pending_server_bytes(state: &TcpFlowState) -> usize {
    state.pending_server_data.iter().map(Bytes::len).sum()
}

pub(in crate::tcp) fn assess_server_backlog_pressure(
    state: &mut TcpFlowState,
    config: &TunTcpConfig,
    now: Instant,
    window_stalled: bool,
) -> ServerBacklogPressure {
    let pending_bytes = pending_server_bytes(state);
    if pending_bytes <= config.max_pending_server_bytes {
        state.backlog_limit_exceeded_since = None;
        return ServerBacklogPressure {
            pending_bytes,
            window_stalled,
            ..ServerBacklogPressure::default()
        };
    }

    let first_exceeded_at = *state.backlog_limit_exceeded_since.get_or_insert(now);
    let over_limit_for = now.saturating_duration_since(first_exceeded_at);
    let no_progress_for = now.saturating_duration_since(state.last_ack_progress_at);
    let hard_limit = config
        .max_pending_server_bytes
        .saturating_mul(config.backlog_hard_limit_multiplier);
    let should_abort = pending_bytes > hard_limit
        || over_limit_for >= config.backlog_abort_grace
        || (window_stalled && no_progress_for >= config.backlog_no_progress_abort);

    ServerBacklogPressure {
        exceeded: true,
        should_abort,
        pending_bytes,
        over_limit_ms: Some(over_limit_for.as_millis()),
        no_progress_ms: Some(no_progress_for.as_millis()),
        window_stalled,
    }
}

pub(in crate::tcp) fn retransmit_budget_exhausted(state: &TcpFlowState, config: &TunTcpConfig) -> bool {
    state
        .unacked_server_segments
        .iter()
        .filter(|segment| !server_segment_is_sacked(state, segment))
        .any(|segment| segment.retransmits >= config.max_retransmits)
}
