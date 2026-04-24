use std::time::Duration;

use outline_metrics as metrics;

use super::buffer::pending_server_bytes;
use super::super::congestion::{bytes_in_pipe, count_segments_in_pipe};
use super::super::types::TcpFlowState;

pub(in crate::tcp) fn sync_flow_metrics(state: &mut TcpFlowState) {
    let inflight_segments = count_segments_in_pipe(state);
    let inflight_bytes = bytes_in_pipe(state);
    let pending_server_bytes = pending_server_bytes(state);
    let buffered_client_segments =
        state.pending_client_segments.len() + state.pending_client_data.len();
    let zero_window = state.client_window == 0 && pending_server_bytes > 0;
    let backlog_pressure = state.backlog_limit_exceeded_since.is_some();
    let backlog_pressure_us = state
        .backlog_limit_exceeded_since
        .map(|since| since.elapsed().as_micros() as u64)
        .unwrap_or(0);
    let ack_progress_stall =
        pending_server_bytes > 0 && state.last_ack_progress_at.elapsed() >= Duration::from_secs(1);
    let ack_progress_stall_us = if pending_server_bytes > 0 {
        state.last_ack_progress_at.elapsed().as_micros() as u64
    } else {
        0
    };
    let congestion_window = state.congestion_window;
    let slow_start_threshold = state.slow_start_threshold;
    let retransmission_timeout_us = state.retransmission_timeout.as_micros() as u64;
    let smoothed_rtt_us = state
        .smoothed_rtt
        .map(|duration| duration.as_micros() as u64)
        .unwrap_or(0);

    let group = state.routing.manager.group_name();
    let uplink: &str = &state.routing.uplink_name;
    if !state.reported.active {
        metrics::add_tun_tcp_flows_active(group, uplink, 1);
        state.reported.active = true;
    }
    apply_usize_gauge_delta(
        group,
        uplink,
        inflight_segments,
        &mut state.reported.inflight_segments,
        metrics::add_tun_tcp_inflight_segments,
    );
    apply_usize_gauge_delta(
        group,
        uplink,
        inflight_bytes,
        &mut state.reported.inflight_bytes,
        metrics::add_tun_tcp_inflight_bytes,
    );
    apply_usize_gauge_delta(
        group,
        uplink,
        pending_server_bytes,
        &mut state.reported.pending_server_bytes,
        metrics::add_tun_tcp_pending_server_bytes,
    );
    apply_usize_gauge_delta(
        group,
        uplink,
        buffered_client_segments,
        &mut state.reported.buffered_client_segments,
        metrics::add_tun_tcp_buffered_client_segments,
    );
    if zero_window != state.reported.zero_window {
        metrics::add_tun_tcp_zero_window_flows(group, uplink, if zero_window { 1 } else { -1 });
        state.reported.zero_window = zero_window;
    }
    if backlog_pressure != state.reported.backlog_pressure {
        metrics::add_tun_tcp_backlog_pressure_flows(
            group,
            uplink,
            if backlog_pressure { 1 } else { -1 },
        );
        state.reported.backlog_pressure = backlog_pressure;
    }
    apply_u64_seconds_gauge_delta(
        group,
        uplink,
        backlog_pressure_us,
        &mut state.reported.backlog_pressure_us,
        metrics::add_tun_tcp_backlog_pressure_seconds,
    );
    if ack_progress_stall != state.reported.ack_progress_stall {
        metrics::add_tun_tcp_ack_progress_stall_flows(
            group,
            uplink,
            if ack_progress_stall { 1 } else { -1 },
        );
        state.reported.ack_progress_stall = ack_progress_stall;
    }
    apply_u64_seconds_gauge_delta(
        group,
        uplink,
        ack_progress_stall_us,
        &mut state.reported.ack_progress_stall_us,
        metrics::add_tun_tcp_ack_progress_stall_seconds,
    );
    apply_usize_gauge_delta(
        group,
        uplink,
        congestion_window,
        &mut state.reported.congestion_window,
        metrics::add_tun_tcp_congestion_window_bytes,
    );
    apply_usize_gauge_delta(
        group,
        uplink,
        slow_start_threshold,
        &mut state.reported.slow_start_threshold,
        metrics::add_tun_tcp_slow_start_threshold_bytes,
    );
    apply_u64_seconds_gauge_delta(
        group,
        uplink,
        retransmission_timeout_us,
        &mut state.reported.retransmission_timeout_us,
        metrics::add_tun_tcp_retransmission_timeout_seconds,
    );
    apply_u64_seconds_gauge_delta(
        group,
        uplink,
        smoothed_rtt_us,
        &mut state.reported.smoothed_rtt_us,
        metrics::add_tun_tcp_smoothed_rtt_seconds,
    );
}

pub(in crate::tcp) fn clear_flow_metrics(state: &mut TcpFlowState) {
    let group = state.routing.manager.group_name();
    let uplink: &str = &state.routing.uplink_name;
    if state.reported.active {
        metrics::add_tun_tcp_flows_active(group, uplink, -1);
        state.reported.active = false;
    }
    if state.reported.inflight_segments != 0 {
        metrics::add_tun_tcp_inflight_segments(
            group,
            uplink,
            -(state.reported.inflight_segments as i64),
        );
        state.reported.inflight_segments = 0;
    }
    if state.reported.inflight_bytes != 0 {
        metrics::add_tun_tcp_inflight_bytes(
            group,
            uplink,
            -(state.reported.inflight_bytes as i64),
        );
        state.reported.inflight_bytes = 0;
    }
    if state.reported.pending_server_bytes != 0 {
        metrics::add_tun_tcp_pending_server_bytes(
            group,
            uplink,
            -(state.reported.pending_server_bytes as i64),
        );
        state.reported.pending_server_bytes = 0;
    }
    if state.reported.buffered_client_segments != 0 {
        metrics::add_tun_tcp_buffered_client_segments(
            group,
            uplink,
            -(state.reported.buffered_client_segments as i64),
        );
        state.reported.buffered_client_segments = 0;
    }
    if state.reported.zero_window {
        metrics::add_tun_tcp_zero_window_flows(group, uplink, -1);
        state.reported.zero_window = false;
    }
    if state.reported.backlog_pressure {
        metrics::add_tun_tcp_backlog_pressure_flows(group, uplink, -1);
        state.reported.backlog_pressure = false;
    }
    if state.reported.backlog_pressure_us != 0 {
        metrics::add_tun_tcp_backlog_pressure_seconds(
            group,
            uplink,
            -(state.reported.backlog_pressure_us as f64) / 1_000_000.0,
        );
        state.reported.backlog_pressure_us = 0;
    }
    if state.reported.ack_progress_stall {
        metrics::add_tun_tcp_ack_progress_stall_flows(group, uplink, -1);
        state.reported.ack_progress_stall = false;
    }
    if state.reported.ack_progress_stall_us != 0 {
        metrics::add_tun_tcp_ack_progress_stall_seconds(
            group,
            uplink,
            -(state.reported.ack_progress_stall_us as f64) / 1_000_000.0,
        );
        state.reported.ack_progress_stall_us = 0;
    }
    if state.reported.congestion_window != 0 {
        metrics::add_tun_tcp_congestion_window_bytes(
            group,
            uplink,
            -(state.reported.congestion_window as i64),
        );
        state.reported.congestion_window = 0;
    }
    if state.reported.slow_start_threshold != 0 {
        metrics::add_tun_tcp_slow_start_threshold_bytes(
            group,
            uplink,
            -(state.reported.slow_start_threshold as i64),
        );
        state.reported.slow_start_threshold = 0;
    }
    if state.reported.retransmission_timeout_us != 0 {
        metrics::add_tun_tcp_retransmission_timeout_seconds(
            group,
            uplink,
            -((state.reported.retransmission_timeout_us as f64) / 1_000_000.0),
        );
        state.reported.retransmission_timeout_us = 0;
    }
    if state.reported.smoothed_rtt_us != 0 {
        metrics::add_tun_tcp_smoothed_rtt_seconds(
            group,
            uplink,
            -((state.reported.smoothed_rtt_us as f64) / 1_000_000.0),
        );
        state.reported.smoothed_rtt_us = 0;
    }
}

fn apply_usize_gauge_delta(
    group: &str,
    uplink: &str,
    current: usize,
    reported: &mut usize,
    record: fn(&str, &str, i64),
) {
    let delta = current as i64 - *reported as i64;
    if delta != 0 {
        record(group, uplink, delta);
        *reported = current;
    }
}

fn apply_u64_seconds_gauge_delta(
    group: &str,
    uplink: &str,
    current: u64,
    reported: &mut u64,
    record: fn(&str, &str, f64),
) {
    let delta = current as f64 - *reported as f64;
    if delta != 0.0 {
        record(group, uplink, delta / 1_000_000.0);
        *reported = current;
    }
}
