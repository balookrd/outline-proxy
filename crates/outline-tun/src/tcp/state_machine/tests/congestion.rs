use std::time::Instant;

use super::*;
use crate::tcp::TCP_FLAG_ACK;
use crate::tcp::tests::tcp_flow_state_for_tests;

fn four_byte_segment(sequence_number: u32) -> ServerSegment {
    let now = Instant::now();
    ServerSegment {
        sequence_number,
        acknowledgement_number: 500,
        flags: TCP_FLAG_ACK,
        payload: b"DATA".to_vec().into(),
        last_sent: now,
        first_sent: now,
        retransmits: 0,
        rto_retransmits: 0,
        fast_retransmit_epoch: 0,
        delivered_snapshot: 0,
        delivered_at_snapshot: now,
        first_tx_snapshot: now,
        app_limited: false,
    }
}

/// Three queued 4-byte segments (1000..1012) with the running accounting
/// derived by the production rebuild, then a deliberate skew: the counters are
/// left holding one segment instead of three, as a future accounting site that
/// forgot to charge its push would leave them.
async fn state_with_a_pipe_that_under_reports() -> TcpFlowState {
    let mut state = tcp_flow_state_for_tests().await;
    state.last_client_ack = 1000;
    state.server_seq = 1012;
    for index in 0..3u32 {
        state
            .unacked_server_segments
            .push_back(four_byte_segment(1000 + index * 4));
    }
    rebuild_unacked_accounting(&mut state);
    assert_eq!((state.pipe_bytes, state.pipe_segments), (12, 3), "rebuild seeds the truth");

    state.pipe_bytes = 4;
    state.pipe_segments = 1;
    state
}

/// The cumulative-ACK pop loop discharges each un-SACKed segment from the
/// running pipe counters. Should a future accounting site ever leave those
/// counters short of what the queue holds, a release build (no overflow checks)
/// wraps `pipe_bytes` to ~2^64 instead of faulting — and every later
/// `congestion_window_remaining` is then `cap.saturating_sub(pipe)` == 0, i.e. a
/// silently wedged downlink. Clamp at zero so a drift degrades into a stale
/// count that the next SACK/rebuild corrects, never into a stalled flow.
#[tokio::test]
async fn a_cumulative_ack_past_a_drifted_pipe_clamps_the_counters_at_zero() {
    let mut state = state_with_a_pipe_that_under_reports().await;

    process_server_ack(&mut state, 1012, &[]);

    assert_eq!(state.pipe_bytes, 0, "pipe_bytes must clamp, not wrap past zero");
    assert_eq!(state.pipe_segments, 0, "pipe_segments must clamp, not wrap past zero");
}

/// The consequence the clamp exists for: with the queue drained, the flush path
/// must see room to send again. An underflowed `pipe_bytes` leaves
/// `congestion_window_remaining` pinned at 0 forever on a loss-free bulk
/// transfer — nothing rebuilds the scoreboard, so the stall never lifts.
#[tokio::test]
async fn a_drifted_pipe_does_not_wedge_the_congestion_window_once_the_queue_drains() {
    let mut state = state_with_a_pipe_that_under_reports().await;

    process_server_ack(&mut state, 1012, &[]);

    assert!(state.unacked_server_segments.is_empty(), "the ACK covers every queued segment");
    assert!(
        congestion_window_remaining(&state) > 0,
        "an empty pipe must leave the initial window free to send"
    );
}
