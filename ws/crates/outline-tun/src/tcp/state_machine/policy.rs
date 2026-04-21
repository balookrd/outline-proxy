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
    if seq_gt(packet.sequence_number, state.client_next_seq) {
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
    client_next_seq: u32,
) -> bool {
    payload_len != 0
        || (flags & TCP_FLAG_FIN) != 0
        || seq_lt(sequence_number, client_next_seq)
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
mod tests {
    use super::*;

    #[test]
    fn data_segment_requires_ack() {
        assert!(segment_requires_ack(100, TCP_FLAG_ACK, 3, 100));
    }

    #[test]
    fn fin_without_payload_requires_ack() {
        assert!(segment_requires_ack(100, TCP_FLAG_ACK | TCP_FLAG_FIN, 0, 100));
    }

    #[test]
    fn retransmitted_duplicate_requires_ack() {
        assert!(segment_requires_ack(90, TCP_FLAG_ACK, 0, 100));
    }

    #[test]
    fn bare_in_order_ack_does_not_require_ack() {
        assert!(!segment_requires_ack(100, TCP_FLAG_ACK, 0, 100));
    }

    #[test]
    fn future_segment_does_not_require_ack_by_this_rule() {
        // Future segments are ACKed by the queue path, not by this predicate.
        assert!(!segment_requires_ack(200, TCP_FLAG_ACK, 0, 100));
    }

    #[test]
    fn syn_received_handshake_completes_when_fields_match() {
        assert!(completes_syn_received_handshake(TCP_FLAG_ACK, 1000, 100, 1000, 100));
    }

    #[test]
    fn syn_received_handshake_rejects_missing_ack_flag() {
        assert!(!completes_syn_received_handshake(0, 1000, 100, 1000, 100));
    }

    #[test]
    fn syn_received_handshake_rejects_stale_ack_number() {
        assert!(!completes_syn_received_handshake(TCP_FLAG_ACK, 999, 100, 1000, 100));
    }

    #[test]
    fn syn_received_handshake_rejects_retransmitted_sequence() {
        assert!(!completes_syn_received_handshake(TCP_FLAG_ACK, 1000, 99, 1000, 100));
    }

    #[test]
    fn ack_covers_server_fin_when_equal_or_greater() {
        assert!(ack_covers_server_fin(TCP_FLAG_ACK, 1000, 1000));
        assert!(ack_covers_server_fin(TCP_FLAG_ACK, 1001, 1000));
    }

    #[test]
    fn ack_covers_server_fin_rejects_missing_ack_flag() {
        assert!(!ack_covers_server_fin(0, 1000, 1000));
    }

    #[test]
    fn stale_server_fin_retry_detects_older_ack() {
        assert!(ack_is_stale_server_fin_retry(TCP_FLAG_ACK, 999, 1000));
    }

    #[test]
    fn stale_server_fin_retry_rejects_current_ack() {
        assert!(!ack_is_stale_server_fin_retry(TCP_FLAG_ACK, 1000, 1000));
    }

    #[test]
    fn half_closed_statuses_cover_close_wait_and_fin_waits() {
        for status in [
            TcpFlowStatus::CloseWait,
            TcpFlowStatus::FinWait1,
            TcpFlowStatus::FinWait2,
            TcpFlowStatus::Closing,
            TcpFlowStatus::LastAck,
        ] {
            assert!(is_half_closed_status(status), "{status:?} should be half-closed");
        }
        for status in [
            TcpFlowStatus::SynReceived,
            TcpFlowStatus::Established,
            TcpFlowStatus::TimeWait,
        ] {
            assert!(!is_half_closed_status(status), "{status:?} should not be half-closed");
        }
    }

    #[test]
    fn time_wait_expired_requires_status_and_elapsed_timeout() {
        let now = Instant::now();
        assert!(time_wait_expired(
            TcpFlowStatus::TimeWait,
            now - TCP_TIME_WAIT_TIMEOUT,
            now,
        ));
        assert!(!time_wait_expired(
            TcpFlowStatus::TimeWait,
            now - TCP_TIME_WAIT_TIMEOUT + Duration::from_millis(1),
            now,
        ));
        assert!(!time_wait_expired(
            TcpFlowStatus::Established,
            now - TCP_TIME_WAIT_TIMEOUT,
            now,
        ));
    }

    #[test]
    fn handshake_timed_out_only_fires_in_syn_received() {
        let now = Instant::now();
        let timeout = Duration::from_secs(5);
        assert!(handshake_timed_out(TcpFlowStatus::SynReceived, now - timeout, timeout, now));
        assert!(!handshake_timed_out(
            TcpFlowStatus::Established,
            now - timeout,
            timeout,
            now,
        ));
        assert!(!handshake_timed_out(
            TcpFlowStatus::SynReceived,
            now - timeout + Duration::from_millis(1),
            timeout,
            now,
        ));
    }

    #[test]
    fn half_close_timed_out_respects_half_closed_statuses_only() {
        let now = Instant::now();
        let timeout = Duration::from_secs(30);
        assert!(half_close_timed_out(TcpFlowStatus::CloseWait, now - timeout, timeout, now));
        assert!(!half_close_timed_out(
            TcpFlowStatus::Established,
            now - timeout,
            timeout,
            now,
        ));
    }

    #[test]
    fn idle_timed_out_skips_time_wait() {
        let now = Instant::now();
        let timeout = Duration::from_secs(60);
        assert!(idle_timed_out(TcpFlowStatus::Established, now - timeout, timeout, now));
        assert!(!idle_timed_out(TcpFlowStatus::TimeWait, now - timeout, timeout, now));
        assert!(!idle_timed_out(
            TcpFlowStatus::Established,
            now - timeout + Duration::from_millis(1),
            timeout,
            now,
        ));
    }

    #[test]
    fn zero_window_probe_requires_zero_window_with_pending_and_no_inflight() {
        let now = Instant::now();
        assert!(zero_window_probe_is_due_from_primitives(0, true, true, None, now));
        assert!(!zero_window_probe_is_due_from_primitives(1, true, true, None, now));
        assert!(!zero_window_probe_is_due_from_primitives(0, false, true, None, now));
        assert!(!zero_window_probe_is_due_from_primitives(0, true, false, None, now));
    }

    #[test]
    fn zero_window_probe_honours_backoff_deadline() {
        let now = Instant::now();
        assert!(zero_window_probe_is_due_from_primitives(
            0,
            true,
            true,
            Some(now - Duration::from_millis(1)),
            now,
        ));
        assert!(!zero_window_probe_is_due_from_primitives(
            0,
            true,
            true,
            Some(now + Duration::from_millis(1)),
            now,
        ));
    }

    #[test]
    fn keepalive_exhausted_needs_budget_spent_and_interval_elapsed() {
        let now = Instant::now();
        let interval = Duration::from_secs(15);
        assert!(keepalive_probes_exhausted(3, 3, Some(now - interval), interval, now));
        assert!(!keepalive_probes_exhausted(2, 3, Some(now - interval), interval, now));
        assert!(!keepalive_probes_exhausted(3, 3, None, interval, now));
        assert!(!keepalive_probes_exhausted(
            3,
            3,
            Some(now - interval + Duration::from_millis(1)),
            interval,
            now,
        ));
    }
}
