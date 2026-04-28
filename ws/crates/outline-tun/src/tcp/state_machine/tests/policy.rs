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
