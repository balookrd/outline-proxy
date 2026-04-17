use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::Bytes;

use crate::config::TunTcpConfig;
use crate::metrics;

use super::super::{
    TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_ZERO_WINDOW_PROBE_MAX_INTERVAL,
};
use super::congestion::{
    bytes_in_pipe, congestion_window_remaining, count_segments_in_pipe,
    current_retransmission_timeout, preferred_retransmit_index, server_max_segment_payload,
    server_segment_is_sacked,
};
use super::packets::{build_flow_packet, send_window_remaining};
use super::transitions::{reset_zero_window_persist, set_flow_status};
use super::types::{ServerBacklogPressure, ServerFlush, ServerSegment, TcpFlowState, TcpFlowStatus};

fn pending_server_bytes(state: &TcpFlowState) -> usize {
    state.pending_server_data.iter().map(Bytes::len).sum()
}

pub(in crate::tun::tcp) fn assess_server_backlog_pressure(
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

pub(in crate::tun::tcp) fn retransmit_budget_exhausted(state: &TcpFlowState, config: &TunTcpConfig) -> bool {
    state
        .unacked_server_segments
        .iter()
        .filter(|segment| !server_segment_is_sacked(state, segment))
        .any(|segment| segment.retransmits >= config.max_retransmits)
}

fn flush_server_data(state: &mut TcpFlowState) -> Result<Vec<Vec<u8>>> {
    let mut packets = Vec::new();
    let mut available_window =
        send_window_remaining(state).min(congestion_window_remaining(state) as u32);
    let max_payload_per_segment = server_max_segment_payload(state);

    while available_window > 0 {
        let Some(front) = state.pending_server_data.front_mut() else {
            break;
        };
        if front.is_empty() {
            state.pending_server_data.pop_front();
            continue;
        }

        let payload_len = front
            .len()
            .min(max_payload_per_segment)
            .min(available_window as usize);
        let payload = front.split_to(payload_len);
        if front.is_empty() {
            state.pending_server_data.pop_front();
        }

        let sequence_number = state.server_seq;
        let acknowledgement_number = state.client_next_seq;
        let packet = build_flow_packet(
            state,
            sequence_number,
            acknowledgement_number,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
            &payload,
        )?;
        state.server_seq = state.server_seq.wrapping_add(payload.len() as u32);
        state.unacked_server_segments.push_back(ServerSegment {
            sequence_number,
            acknowledgement_number,
            flags: TCP_FLAG_ACK | TCP_FLAG_PSH,
            payload,
            last_sent: Instant::now(),
            first_sent: Instant::now(),
            retransmits: 0,
        });
        reset_zero_window_persist(state);
        packets.push(packet);
        available_window =
            send_window_remaining(state).min(congestion_window_remaining(state) as u32);
    }

    Ok(packets)
}

pub(in crate::tun::tcp) fn flush_server_output(state: &mut TcpFlowState) -> Result<ServerFlush> {
    if state.status == TcpFlowStatus::SynReceived {
        return Ok(ServerFlush::default());
    }
    let data_packets = flush_server_data(state)?;
    let window_stalled = send_window_remaining(state) == 0 && !state.pending_server_data.is_empty();
    let fin_packet = maybe_emit_server_fin(state)?;
    let probe_packet = maybe_emit_zero_window_probe(state)?;
    Ok(ServerFlush {
        data_packets,
        fin_packet,
        probe_packet,
        window_stalled,
    })
}

fn maybe_emit_server_fin(state: &mut TcpFlowState) -> Result<Option<Vec<u8>>> {
    if !state.server_fin_pending
        || !state.pending_server_data.is_empty()
        || !state.unacked_server_segments.is_empty()
        || matches!(state.status, TcpFlowStatus::Closed | TcpFlowStatus::TimeWait)
    {
        return Ok(None);
    }

    let packet = build_flow_packet(
        state,
        state.server_seq,
        state.client_next_seq,
        TCP_FLAG_FIN | TCP_FLAG_ACK,
        &[],
    )?;
    let sequence_number = state.server_seq;
    state.server_seq = state.server_seq.wrapping_add(1);
    state.server_fin_pending = false;
    match state.status {
        TcpFlowStatus::CloseWait => set_flow_status(state, TcpFlowStatus::LastAck),
        TcpFlowStatus::SynReceived | TcpFlowStatus::Established => {
            set_flow_status(state, TcpFlowStatus::FinWait1);
        },
        TcpFlowStatus::FinWait1
        | TcpFlowStatus::FinWait2
        | TcpFlowStatus::Closing
        | TcpFlowStatus::LastAck
        | TcpFlowStatus::TimeWait
        | TcpFlowStatus::Closed => {},
    }
    state.unacked_server_segments.push_back(ServerSegment {
        sequence_number,
        acknowledgement_number: state.client_next_seq,
        flags: TCP_FLAG_FIN | TCP_FLAG_ACK,
        payload: Bytes::new(),
        last_sent: Instant::now(),
        first_sent: Instant::now(),
        retransmits: 0,
    });
    Ok(Some(packet))
}

pub(in crate::tun::tcp) fn maybe_emit_zero_window_probe(state: &mut TcpFlowState) -> Result<Option<Vec<u8>>> {
    if send_window_remaining(state) != 0
        || state.pending_server_data.is_empty()
        || !state.unacked_server_segments.is_empty()
    {
        return Ok(None);
    }

    let now = Instant::now();
    if state
        .next_zero_window_probe_at
        .map(|deadline| deadline > now)
        .unwrap_or(false)
    {
        return Ok(None);
    }

    let Some(front) = state.pending_server_data.front() else {
        return Ok(None);
    };
    let Some(&probe_byte) = front.first() else {
        return Ok(None);
    };
    let packet = build_flow_packet(
        state,
        state.server_seq,
        state.client_next_seq,
        TCP_FLAG_ACK | TCP_FLAG_PSH,
        &[probe_byte],
    )?;
    let current = state.zero_window_probe_backoff;
    state.next_zero_window_probe_at = Some(now + current);
    state.zero_window_probe_backoff =
        (current.saturating_mul(2)).min(TCP_ZERO_WINDOW_PROBE_MAX_INTERVAL);
    Ok(Some(packet))
}

pub(in crate::tun::tcp) fn retransmit_oldest_unacked_packet(
    state: &mut TcpFlowState,
) -> Result<Option<Vec<u8>>> {
    let index = preferred_retransmit_index(state);
    let Some(index) = index else {
        return Ok(None);
    };
    let (sequence_number, acknowledgement_number, flags, payload) = {
        let segment = &mut state.unacked_server_segments[index];
        segment.last_sent = Instant::now();
        segment.retransmits = segment.retransmits.saturating_add(1);
        (
            segment.sequence_number,
            segment.acknowledgement_number,
            segment.flags,
            segment.payload.clone(),
        )
    };
    Ok(Some(build_flow_packet(
        state,
        sequence_number,
        state.client_next_seq.max(acknowledgement_number),
        flags,
        &payload,
    )?))
}

pub(in crate::tun::tcp) fn retransmit_due_segment(state: &mut TcpFlowState) -> Result<Option<Vec<u8>>> {
    let Some(index) = preferred_retransmit_index(state)
        .filter(|index| {
            state.unacked_server_segments[*index].last_sent.elapsed()
                >= current_retransmission_timeout(state)
        })
        .or_else(|| {
            let rto = current_retransmission_timeout(state);
            state.unacked_server_segments.iter().position(|segment| {
                !server_segment_is_sacked(state, segment) && segment.last_sent.elapsed() >= rto
            })
        })
    else {
        return Ok(None);
    };
    let (sequence_number, acknowledgement_number, flags, payload) = {
        let segment = &mut state.unacked_server_segments[index];
        segment.last_sent = Instant::now();
        segment.retransmits = segment.retransmits.saturating_add(1);
        (
            segment.sequence_number,
            segment.acknowledgement_number,
            segment.flags,
            segment.payload.clone(),
        )
    };
    Ok(Some(build_flow_packet(
        state,
        sequence_number,
        state.client_next_seq.max(acknowledgement_number),
        flags,
        &payload,
    )?))
}

pub(in crate::tun::tcp) fn sync_flow_metrics(state: &mut TcpFlowState) {
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

    let group = state.manager.group_name();
    let uplink: &str = &state.uplink_name;
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

pub(in crate::tun::tcp) fn clear_flow_metrics(state: &mut TcpFlowState) {
    let group = state.manager.group_name();
    let uplink: &str = &state.uplink_name;
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
