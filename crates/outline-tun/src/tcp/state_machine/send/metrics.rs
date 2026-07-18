use std::sync::Arc;
use std::time::Duration;

use outline_metrics as metrics;

use super::super::bbr::pacing_rate;
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
    let retransmission_timeout_us = state.retransmission_timeout.as_micros() as u64;
    let smoothed_rtt_us = state
        .smoothed_rtt
        .map(|duration| duration.as_micros() as u64)
        .unwrap_or(0);
    let bbr_btlbw_bps = state.bbr.btlbw_bps;
    // The rate actually shaping the flush (gain × BtlBw, clamped by the
    // configured ceiling and the loss cap) — not the raw estimate above.
    let bbr_pacing_rate_bps = pacing_rate(state);
    let bbr_loss_cap_bps = state.bbr.loss_cap_bps;
    let bbr_loss_capped = bbr_loss_cap_bps > 0;
    // `inflight_hi` / `inflight_lo` use `usize::MAX` as the "unset" sentinel;
    // map it to 0 so a flow contributes nothing while its ceiling is inactive
    // (a raw `usize::MAX` would export as -1 through the i64 gauge delta).
    let bbr_inflight_hi_bytes = if state.bbr.inflight_hi == usize::MAX {
        0
    } else {
        state.bbr.inflight_hi
    };
    let bbr_inflight_lo_bytes = if state.bbr.inflight_lo == usize::MAX {
        0
    } else {
        state.bbr.inflight_lo
    };
    let bbr_min_rtt_us = state.bbr.min_rtt.as_micros() as u64;
    let bbr_loss_episodes = state.bbr.loss_episodes;

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
        &gauges.bbr_inflight_hi_bytes,
        bbr_inflight_hi_bytes,
        &mut reported.bbr_inflight_hi_bytes,
    );
    apply_usize_gauge_delta(
        &gauges.bbr_inflight_lo_bytes,
        bbr_inflight_lo_bytes,
        &mut reported.bbr_inflight_lo_bytes,
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
    apply_u64_gauge_delta(
        &gauges.bbr_btlbw_bytes_per_second,
        bbr_btlbw_bps,
        &mut reported.bbr_btlbw_bps,
    );
    apply_u64_gauge_delta(
        &gauges.bbr_pacing_rate_bytes_per_second,
        bbr_pacing_rate_bps,
        &mut reported.bbr_pacing_rate_bps,
    );
    apply_u64_gauge_delta(
        &gauges.bbr_loss_cap_bytes_per_second,
        bbr_loss_cap_bps,
        &mut reported.bbr_loss_cap_bps,
    );
    if bbr_loss_capped != reported.bbr_loss_capped {
        gauges.bbr_loss_capped_flows.add(if bbr_loss_capped { 1 } else { -1 });
        reported.bbr_loss_capped = bbr_loss_capped;
    }
    apply_u64_seconds_gauge_delta(
        &gauges.bbr_min_rtt_seconds,
        bbr_min_rtt_us,
        &mut reported.bbr_min_rtt_us,
    );
    apply_u64_counter_delta(
        &gauges.bbr_loss_episodes_total,
        bbr_loss_episodes,
        &mut reported.bbr_loss_episodes,
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
    if reported.bbr_inflight_hi_bytes != 0 {
        gauges
            .bbr_inflight_hi_bytes
            .add(-(reported.bbr_inflight_hi_bytes as i64));
        reported.bbr_inflight_hi_bytes = 0;
    }
    if reported.bbr_inflight_lo_bytes != 0 {
        gauges
            .bbr_inflight_lo_bytes
            .add(-(reported.bbr_inflight_lo_bytes as i64));
        reported.bbr_inflight_lo_bytes = 0;
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
    if reported.bbr_btlbw_bps != 0 {
        gauges
            .bbr_btlbw_bytes_per_second
            .add(-clamp_i64(reported.bbr_btlbw_bps));
        reported.bbr_btlbw_bps = 0;
    }
    if reported.bbr_pacing_rate_bps != 0 {
        gauges
            .bbr_pacing_rate_bytes_per_second
            .add(-clamp_i64(reported.bbr_pacing_rate_bps));
        reported.bbr_pacing_rate_bps = 0;
    }
    if reported.bbr_loss_cap_bps != 0 {
        gauges
            .bbr_loss_cap_bytes_per_second
            .add(-clamp_i64(reported.bbr_loss_cap_bps));
        reported.bbr_loss_cap_bps = 0;
    }
    if reported.bbr_loss_capped {
        gauges.bbr_loss_capped_flows.add(-1);
        reported.bbr_loss_capped = false;
    }
    if reported.bbr_min_rtt_us != 0 {
        gauges
            .bbr_min_rtt_seconds
            .add(-((reported.bbr_min_rtt_us as f64) / 1_000_000.0));
        reported.bbr_min_rtt_us = 0;
    }
    // `bbr_loss_episodes_total` is deliberately absent: it is a counter, and a
    // closing flow may not rewind history. `reported.bbr_loss_episodes` is left
    // at its last value too — zeroing it would re-add every episode of this flow
    // if the state were ever synced again after a clear, double-counting them.
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

/// Delta-apply a `u64` quantity (bytes/sec rates) to an `i64` gauge.
fn apply_u64_gauge_delta(gauge: &metrics::TunFlowGaugeI64, current: u64, reported: &mut u64) {
    if current == *reported {
        return;
    }
    gauge.add(clamp_i64(current) - clamp_i64(*reported));
    *reported = current;
}

/// Add the newly observed part of a monotonic counter. `current` is monotonic by
/// construction (`BbrState::loss_episodes` only ever grows), so `saturating_sub`
/// is a guard, not an expected path; the counter is never rewound.
fn apply_u64_counter_delta(counter: &metrics::TunFlowCounterU64, current: u64, reported: &mut u64) {
    let delta = current.saturating_sub(*reported);
    if delta != 0 {
        counter.inc_by(delta);
        *reported = current;
    }
}

/// Real rates never approach `i64::MAX` bytes/sec; the clamp only keeps a bogus
/// estimate from wrapping the gauge delta into a negative jump.
fn clamp_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}
