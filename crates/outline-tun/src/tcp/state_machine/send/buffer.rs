use std::time::Instant;

use bytes::Bytes;

use crate::config::TunTcpConfig;

use super::super::congestion::server_segment_is_sacked;
use super::super::packets::send_window_remaining;
use super::super::types::{ServerBacklogPressure, TcpFlowState};

pub(in crate::tcp) fn pending_server_bytes(state: &TcpFlowState) -> usize {
    state.pending_server_data.iter().map(Bytes::len).sum()
}

/// The client's advertised receive window is closed while data is still
/// queued for it — i.e. the client has stopped reading. Used both by the
/// flush path and by the reader's downlink-backpressure pause to tell a
/// genuinely stalled flow apart from one that is merely throttled (slow but
/// still ACKing).
pub(in crate::tcp) fn server_window_stalled(state: &TcpFlowState) -> bool {
    send_window_remaining(state) == 0 && !state.pending_server_data.is_empty()
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
    // Abort only when the flow is genuinely stuck, not merely throttled. The
    // reader now pauses draining the carrier once the buffer is over the soft
    // limit (downlink backpressure), so a slow-but-live client keeps the
    // buffer parked near the soft limit for the whole transfer while still
    // ACKing. The old `over_limit_for >= backlog_abort_grace` arm would reap
    // exactly that healthy-but-slow case after a few seconds (it is dropped),
    // and the `pending_bytes > hard_limit` arm fired on fast downloads before
    // backpressure could throttle the server (the observed large-file RST).
    //
    // What remains: a true stall (client window shut with no ACK progress for
    // `backlog_no_progress_abort`), plus `pending_bytes > hard_limit` kept
    // purely as a catastrophic out-of-memory guard for the case where
    // backpressure somehow fails to hold the buffer down.
    let should_abort = pending_bytes > hard_limit
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

pub(in crate::tcp) fn retransmit_budget_exhausted(
    state: &TcpFlowState,
    config: &TunTcpConfig,
) -> bool {
    state
        .unacked_server_segments
        .iter()
        .filter(|segment| !server_segment_is_sacked(state, segment))
        .any(|segment| segment.retransmits >= config.max_retransmits)
}
