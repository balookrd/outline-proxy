use std::sync::Arc;
use std::time::Duration;

use outline_metrics as metrics;

use super::super::congestion::{bytes_in_pipe, count_segments_in_pipe};
use super::super::types::{CachedFlowGauges, TcpFlowState};
use super::buffer::pending_server_bytes;

/// Ensures `state.flow_gauges` holds the pre-resolved gauge handles for the
/// flow's current `(group, uplink)`, resolving them on first use and
/// re-resolving after a runtime failover swaps `uplink_name` to a new `Arc`.
/// Cheap `Arc::ptr_eq` check on the hot path; the 14 label-hash registry probes
/// only run once per flow (or once per failover).
fn ensure_flow_gauges(state: &mut TcpFlowState) {
    let uplink = &state.routing.uplink_name;
    let fresh = match &state.flow_gauges {
        Some(cached) => Arc::ptr_eq(&cached.uplink, uplink),
        None => false,
    };
    if !fresh {
        let handles = metrics::tun_tcp_flow_gauges(&state.routing.group_name, uplink);
        state.flow_gauges = Some(CachedFlowGauges { uplink: Arc::clone(uplink), handles });
    }
}

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

    ensure_flow_gauges(state);
    // Disjoint borrows: `gauges` reads `state.flow_gauges`, the deltas below
    // mutate `state.reported.*` — different fields of `state`.
    let gauges = &state.flow_gauges.as_ref().expect("ensured above").handles;
    let reported = &mut state.reported;

    if !reported.active {
        gauges.flows_active.add(1);
        reported.active = true;
    }
    apply_usize_gauge_delta(
        &gauges.inflight_segments,
        inflight_segments,
        &mut reported.inflight_segments,
    );
    apply_usize_gauge_delta(&gauges.inflight_bytes, inflight_bytes, &mut reported.inflight_bytes);
    apply_usize_gauge_delta(
        &gauges.pending_server_bytes,
        pending_server_bytes,
        &mut reported.pending_server_bytes,
    );
    apply_usize_gauge_delta(
        &gauges.buffered_client_segments,
        buffered_client_segments,
        &mut reported.buffered_client_segments,
    );
    if zero_window != reported.zero_window {
        gauges.zero_window_flows.add(if zero_window { 1 } else { -1 });
        reported.zero_window = zero_window;
    }
    if backlog_pressure != reported.backlog_pressure {
        gauges
            .backlog_pressure_flows
            .add(if backlog_pressure { 1 } else { -1 });
        reported.backlog_pressure = backlog_pressure;
    }
    apply_u64_seconds_gauge_delta(
        &gauges.backlog_pressure_seconds,
        backlog_pressure_us,
        &mut reported.backlog_pressure_us,
    );
    if ack_progress_stall != reported.ack_progress_stall {
        gauges
            .ack_progress_stall_flows
            .add(if ack_progress_stall { 1 } else { -1 });
        reported.ack_progress_stall = ack_progress_stall;
    }
    apply_u64_seconds_gauge_delta(
        &gauges.ack_progress_stall_seconds,
        ack_progress_stall_us,
        &mut reported.ack_progress_stall_us,
    );
    apply_usize_gauge_delta(
        &gauges.congestion_window_bytes,
        congestion_window,
        &mut reported.congestion_window,
    );
    apply_usize_gauge_delta(
        &gauges.slow_start_threshold_bytes,
        slow_start_threshold,
        &mut reported.slow_start_threshold,
    );
    apply_u64_seconds_gauge_delta(
        &gauges.retransmission_timeout_seconds,
        retransmission_timeout_us,
        &mut reported.retransmission_timeout_us,
    );
    apply_u64_seconds_gauge_delta(
        &gauges.smoothed_rtt_seconds,
        smoothed_rtt_us,
        &mut reported.smoothed_rtt_us,
    );
}

pub(in crate::tcp) fn clear_flow_metrics(state: &mut TcpFlowState) {
    // No handle was ever resolved ⇒ the flow reported nothing: `reported.*` is
    // only ever set to a non-zero/true value in `sync_flow_metrics`, which
    // always resolves the handles first. So there is nothing to unwind, and
    // resolving handles here would create empty zero-valued series for a flow
    // that carried no traffic — a change the per-call path never made.
    if state.flow_gauges.is_none() {
        return;
    }
    // Re-resolve for the current uplink if the flow failed over since the last
    // sync — the per-call path always unwound against the then-current
    // `uplink_name`, so the reverting deltas must land on the same series.
    ensure_flow_gauges(state);
    let gauges = &state.flow_gauges.as_ref().expect("ensured above").handles;
    let reported = &mut state.reported;

    if reported.active {
        gauges.flows_active.add(-1);
        reported.active = false;
    }
    if reported.inflight_segments != 0 {
        gauges.inflight_segments.add(-(reported.inflight_segments as i64));
        reported.inflight_segments = 0;
    }
    if reported.inflight_bytes != 0 {
        gauges.inflight_bytes.add(-(reported.inflight_bytes as i64));
        reported.inflight_bytes = 0;
    }
    if reported.pending_server_bytes != 0 {
        gauges
            .pending_server_bytes
            .add(-(reported.pending_server_bytes as i64));
        reported.pending_server_bytes = 0;
    }
    if reported.buffered_client_segments != 0 {
        gauges
            .buffered_client_segments
            .add(-(reported.buffered_client_segments as i64));
        reported.buffered_client_segments = 0;
    }
    if reported.zero_window {
        gauges.zero_window_flows.add(-1);
        reported.zero_window = false;
    }
    if reported.backlog_pressure {
        gauges.backlog_pressure_flows.add(-1);
        reported.backlog_pressure = false;
    }
    if reported.backlog_pressure_us != 0 {
        gauges
            .backlog_pressure_seconds
            .add(-(reported.backlog_pressure_us as f64) / 1_000_000.0);
        reported.backlog_pressure_us = 0;
    }
    if reported.ack_progress_stall {
        gauges.ack_progress_stall_flows.add(-1);
        reported.ack_progress_stall = false;
    }
    if reported.ack_progress_stall_us != 0 {
        gauges
            .ack_progress_stall_seconds
            .add(-(reported.ack_progress_stall_us as f64) / 1_000_000.0);
        reported.ack_progress_stall_us = 0;
    }
    if reported.congestion_window != 0 {
        gauges
            .congestion_window_bytes
            .add(-(reported.congestion_window as i64));
        reported.congestion_window = 0;
    }
    if reported.slow_start_threshold != 0 {
        gauges
            .slow_start_threshold_bytes
            .add(-(reported.slow_start_threshold as i64));
        reported.slow_start_threshold = 0;
    }
    if reported.retransmission_timeout_us != 0 {
        gauges
            .retransmission_timeout_seconds
            .add(-((reported.retransmission_timeout_us as f64) / 1_000_000.0));
        reported.retransmission_timeout_us = 0;
    }
    if reported.smoothed_rtt_us != 0 {
        gauges
            .smoothed_rtt_seconds
            .add(-((reported.smoothed_rtt_us as f64) / 1_000_000.0));
        reported.smoothed_rtt_us = 0;
    }
}

fn apply_usize_gauge_delta(gauge: &metrics::TunFlowGaugeI64, current: usize, reported: &mut usize) {
    let delta = current as i64 - *reported as i64;
    if delta != 0 {
        gauge.add(delta);
        *reported = current;
    }
}

fn apply_u64_seconds_gauge_delta(
    gauge: &metrics::TunFlowGaugeF64,
    current: u64,
    reported: &mut u64,
) {
    let delta = current as f64 - *reported as f64;
    if delta != 0.0 {
        gauge.add(delta / 1_000_000.0);
        *reported = current;
    }
}
