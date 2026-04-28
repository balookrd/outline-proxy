use std::time::{Duration, Instant};

use super::super::{ParsedTcpPacket, TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_TIME_WAIT_TIMEOUT};
use super::congestion::next_retransmission_deadline;
use super::recv::{TrimmedSegment, trim_packet_to_receive_window};
use super::send::next_keepalive_deadline;
use super::seq::{seq_gt, seq_lt};
use super::types::{TcpFlowState, TcpFlowStatus};

// The engine's dispatch verdict for an in-window inbound segment. Keep
// this pure — mutation (enqueue, deliver, flush) happens in the engine
// after the match.
pub(in crate::tcp) enum InboundSegmentDisposition {
    BeyondExpectedSequence,
    OutsideReceiveWindow,
    Deliver(TrimmedSegment),
}

pub(in crate::tcp) fn classify_inbound_segment(
    state: &TcpFlowState,
    packet: &ParsedTcpPacket,
) -> InboundSegmentDisposition {
    if seq_gt(packet.sequence_number, state.rcv_nxt) {
        return InboundSegmentDisposition::BeyondExpectedSequence;
    }
    match trim_packet_to_receive_window(state, packet) {
        Some(trimmed) => InboundSegmentDisposition::Deliver(trimmed),
        None => InboundSegmentDisposition::OutsideReceiveWindow,
    }
}

// RFC 9293 §3.10.7.4: segments carrying data, a FIN, or a duplicate
// sequence must elicit an ACK; pure in-order ACKs do not.
pub(in crate::tcp) fn segment_requires_ack(
    sequence_number: u32,
    flags: u8,
    payload_len: usize,
    rcv_nxt: u32,
) -> bool {
    payload_len != 0
        || (flags & TCP_FLAG_FIN) != 0
        || seq_lt(sequence_number, rcv_nxt)
}

// Final ACK of the three-way handshake: client ACKs our SYN+ACK exactly
// and doesn't re-send stale sequence data.
pub(in crate::tcp) fn completes_syn_received_handshake(
    flags: u8,
    acknowledgement_number: u32,
    sequence_number: u32,
    expected_acknowledgement: u32,
    expected_sequence: u32,
) -> bool {
    (flags & TCP_FLAG_ACK) != 0
        && acknowledgement_number == expected_acknowledgement
        && sequence_number == expected_sequence
}

// Client ACK advances to or past our FIN byte — used only when we're
// already in a server_fin_awaiting_ack state.
pub(in crate::tcp) fn ack_covers_server_fin(
    flags: u8,
    acknowledgement_number: u32,
    server_seq: u32,
) -> bool {
    (flags & TCP_FLAG_ACK) != 0 && acknowledgement_number >= server_seq
}

// Client ACK is older than our latest server_seq while we're waiting for
// the FIN to be acknowledged — signals the client still needs a FIN retry.
pub(in crate::tcp) fn ack_is_stale_server_fin_retry(
    flags: u8,
    acknowledgement_number: u32,
    server_seq: u32,
) -> bool {
    (flags & TCP_FLAG_ACK) != 0 && seq_lt(acknowledgement_number, server_seq)
}

// Statuses in which at least one half of the connection is closed and the
// flow is waiting for the peer to finish its side.
pub(in crate::tcp) fn is_half_closed_status(status: TcpFlowStatus) -> bool {
    matches!(
        status,
        TcpFlowStatus::CloseWait
            | TcpFlowStatus::FinWait1
            | TcpFlowStatus::FinWait2
            | TcpFlowStatus::Closing
            | TcpFlowStatus::LastAck,
    )
}

pub(in crate::tcp) fn time_wait_expired(
    status: TcpFlowStatus,
    status_since: Instant,
    now: Instant,
) -> bool {
    status == TcpFlowStatus::TimeWait
        && now.saturating_duration_since(status_since) >= TCP_TIME_WAIT_TIMEOUT
}

pub(in crate::tcp) fn handshake_timed_out(
    status: TcpFlowStatus,
    status_since: Instant,
    handshake_timeout: Duration,
    now: Instant,
) -> bool {
    status == TcpFlowStatus::SynReceived
        && now.saturating_duration_since(status_since) >= handshake_timeout
}

pub(in crate::tcp) fn half_close_timed_out(
    status: TcpFlowStatus,
    status_since: Instant,
    half_close_timeout: Duration,
    now: Instant,
) -> bool {
    is_half_closed_status(status)
        && now.saturating_duration_since(status_since) >= half_close_timeout
}

// TimeWait flows are excluded: they drain on their own timer, not the
// generic idle timer.
pub(in crate::tcp) fn idle_timed_out(
    status: TcpFlowStatus,
    last_seen: Instant,
    idle_timeout: Duration,
    now: Instant,
) -> bool {
    status != TcpFlowStatus::TimeWait && now.saturating_duration_since(last_seen) >= idle_timeout
}

// A non-sacked unacked segment has passed its retransmission deadline —
// the engine should build and send a retransmission.
pub(in crate::tcp) fn retransmit_is_due(state: &TcpFlowState, now: Instant) -> bool {
    next_retransmission_deadline(state).is_some_and(|deadline| deadline <= now)
}

// Client advertised a zero send window while we have data to push and
// nothing in flight — and the backoff timer (or its initial absence) says
// it's time to poke with a one-byte probe.
pub(in crate::tcp) fn zero_window_probe_is_due(state: &TcpFlowState, now: Instant) -> bool {
    zero_window_probe_is_due_from_primitives(
        state.client_window,
        !state.pending_server_data.is_empty(),
        state.unacked_server_segments.is_empty(),
        state.next_zero_window_probe_at,
        now,
    )
}

fn zero_window_probe_is_due_from_primitives(
    client_window: u32,
    has_pending_data: bool,
    unacked_empty: bool,
    next_probe_at: Option<Instant>,
    now: Instant,
) -> bool {
    if client_window != 0 || !has_pending_data || !unacked_empty {
        return false;
    }
    next_probe_at.is_none_or(|deadline| deadline <= now)
}

// Keepalive is enabled, the flow is eligible, and the next probe deadline
// has passed — the engine should emit a probe.
pub(in crate::tcp) fn keepalive_probe_is_due(
    state: &TcpFlowState,
    keepalive_idle: Option<Duration>,
    keepalive_interval: Duration,
    now: Instant,
) -> bool {
    next_keepalive_deadline(state, keepalive_idle, keepalive_interval)
        .is_some_and(|deadline| deadline <= now)
}

// We've burned through the probe budget and the last probe is older than
// the interval — the peer is unreachable.
pub(in crate::tcp) fn keepalive_probes_exhausted(
    probes_sent: u32,
    max_probes: u32,
    last_probe_at: Option<Instant>,
    keepalive_interval: Duration,
    now: Instant,
) -> bool {
    probes_sent >= max_probes
        && last_probe_at
            .map(|last| now.saturating_duration_since(last) >= keepalive_interval)
            .unwrap_or(false)
}

#[cfg(test)]
#[path = "tests/policy.rs"]
mod tests;
