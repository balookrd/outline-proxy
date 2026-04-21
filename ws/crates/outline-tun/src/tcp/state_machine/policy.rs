use super::super::{ParsedTcpPacket, TCP_FLAG_ACK, TCP_FLAG_FIN};
use super::recv::{TrimmedSegment, trim_packet_to_receive_window};
use super::seq::{seq_gt, seq_lt};
use super::types::TcpFlowState;

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
}
