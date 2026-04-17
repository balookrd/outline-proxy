use std::time::{Duration, Instant};

use super::super::{
    MAX_SERVER_SEGMENT_PAYLOAD, TCP_FAST_RETRANSMIT_DUP_ACKS, TCP_FLAG_FIN, TCP_FLAG_SYN,
    TCP_MAX_RTO, TCP_MIN_RTO, TCP_MIN_SSTHRESH,
};
use super::seq::{seq_ge, seq_gt, seq_lt};
use super::types::{AckEffect, SequenceRange, ServerSegment, TcpFlowState};

pub(in crate::tun_tcp) fn server_segment_len(segment: &ServerSegment) -> usize {
    segment.payload.len()
        + usize::from((segment.flags & TCP_FLAG_SYN) != 0)
        + usize::from((segment.flags & TCP_FLAG_FIN) != 0)
}

fn merge_sequence_ranges(mut ranges: Vec<SequenceRange>, anchor: u32) -> Vec<SequenceRange> {
    ranges.retain(|range| seq_gt(range.end, range.start));
    ranges.sort_by_key(|range| range.start.wrapping_sub(anchor));

    let mut merged: Vec<SequenceRange> = Vec::with_capacity(ranges.len());
    for range in ranges {
        match merged.last_mut() {
            Some(last) if !seq_gt(range.start, last.end) => {
                if seq_gt(range.end, last.end) {
                    last.end = range.end;
                }
            },
            _ => merged.push(range),
        }
    }
    merged
}

fn trim_sack_scoreboard(scoreboard: &mut Vec<SequenceRange>, cumulative_ack: u32) {
    let mut ranges = Vec::with_capacity(scoreboard.len());
    for mut range in scoreboard.drain(..) {
        if !seq_gt(range.end, cumulative_ack) {
            continue;
        }
        if seq_lt(range.start, cumulative_ack) {
            range.start = cumulative_ack;
        }
        if seq_gt(range.end, range.start) {
            ranges.push(range);
        }
    }
    *scoreboard = merge_sequence_ranges(ranges, cumulative_ack);
}

fn update_sack_scoreboard(
    scoreboard: &mut Vec<SequenceRange>,
    cumulative_ack: u32,
    sack_blocks: &[(u32, u32)],
) -> bool {
    let before = scoreboard.clone();
    let mut ranges = std::mem::take(scoreboard);
    for (start, end) in sack_blocks {
        let mut range = SequenceRange { start: *start, end: *end };
        if !seq_gt(range.end, cumulative_ack) {
            continue;
        }
        if seq_lt(range.start, cumulative_ack) {
            range.start = cumulative_ack;
        }
        if seq_gt(range.end, range.start) {
            ranges.push(range);
        }
    }
    *scoreboard = merge_sequence_ranges(ranges, cumulative_ack);
    *scoreboard != before
}

fn range_fully_covered(scoreboard: &[SequenceRange], start: u32, end: u32) -> bool {
    if !seq_gt(end, start) {
        return true;
    }
    for range in scoreboard {
        if seq_gt(range.start, start) {
            return false;
        }
        if !seq_gt(range.end, start) {
            continue;
        }
        return !seq_lt(range.end, end);
    }
    false
}

pub(in crate::tun_tcp) fn server_segment_is_sacked(state: &TcpFlowState, segment: &ServerSegment) -> bool {
    let end = segment
        .sequence_number
        .wrapping_add(server_segment_len(segment) as u32);
    range_fully_covered(&state.sack_scoreboard, segment.sequence_number, end)
}

pub(in crate::tun_tcp) fn bytes_in_pipe(state: &TcpFlowState) -> usize {
    state
        .unacked_server_segments
        .iter()
        .filter(|segment| !server_segment_is_sacked(state, segment))
        .map(server_segment_len)
        .sum()
}

pub(in crate::tun_tcp) fn count_segments_in_pipe(state: &TcpFlowState) -> usize {
    state
        .unacked_server_segments
        .iter()
        .filter(|segment| !server_segment_is_sacked(state, segment))
        .count()
}

pub(in crate::tun_tcp) fn next_retransmission_deadline(state: &TcpFlowState) -> Option<Instant> {
    let rto = state.retransmission_timeout;
    state
        .unacked_server_segments
        .iter()
        .filter(|segment| !server_segment_is_sacked(state, segment))
        .map(|segment| segment.last_sent + rto)
        .min()
}

fn enter_fast_recovery(state: &mut TcpFlowState) {
    let inflight = bytes_in_pipe(state).max(server_max_segment_payload(state));
    state.slow_start_threshold = (inflight / 2).max(TCP_MIN_SSTHRESH);
    state.congestion_window = state.slow_start_threshold.saturating_add(
        server_max_segment_payload(state) * usize::from(TCP_FAST_RETRANSMIT_DUP_ACKS),
    );
    state.fast_recovery_end = Some(state.server_seq);
    state.duplicate_ack_count = TCP_FAST_RETRANSMIT_DUP_ACKS;
}

fn exit_fast_recovery(state: &mut TcpFlowState) {
    state.fast_recovery_end = None;
    state.duplicate_ack_count = 0;
    state.congestion_window = state.slow_start_threshold.max(server_max_segment_payload(state));
}

pub(in crate::tun_tcp) fn server_max_segment_payload(state: &TcpFlowState) -> usize {
    state
        .client_max_segment_size
        .map(usize::from)
        .unwrap_or(MAX_SERVER_SEGMENT_PAYLOAD)
        .clamp(1, MAX_SERVER_SEGMENT_PAYLOAD)
}

pub(in crate::tun_tcp) fn process_server_ack(
    state: &mut TcpFlowState,
    acknowledgement_number: u32,
    sack_blocks: &[(u32, u32)],
) -> AckEffect {
    let scoreboard_advanced =
        update_sack_scoreboard(&mut state.sack_scoreboard, acknowledgement_number, sack_blocks);
    trim_sack_scoreboard(&mut state.sack_scoreboard, acknowledgement_number);

    if state.unacked_server_segments.is_empty() {
        state.last_client_ack = acknowledgement_number;
        state.duplicate_ack_count = 0;
        state.fast_recovery_end = None;
        return AckEffect::none();
    }

    if seq_gt(acknowledgement_number, state.last_client_ack) {
        state.last_client_ack = acknowledgement_number;
        state.duplicate_ack_count = 0;
        let mut bytes_acked = 0usize;
        let mut rtt_sample = None;
        while let Some(segment) = state.unacked_server_segments.front() {
            let segment_end = segment
                .sequence_number
                .wrapping_add(server_segment_len(segment) as u32);
            if seq_ge(acknowledgement_number, segment_end) {
                let segment = state.unacked_server_segments.pop_front().expect("front exists");
                bytes_acked = bytes_acked.saturating_add(server_segment_len(&segment));
                if segment.retransmits == 0 {
                    rtt_sample = Some(segment.first_sent.elapsed());
                }
            } else {
                break;
            }
        }

        let mut grow_congestion_window = true;
        let mut retransmit_now = false;
        if let Some(recovery_end) = state.fast_recovery_end {
            grow_congestion_window = false;
            if seq_ge(acknowledgement_number, recovery_end)
                || state.unacked_server_segments.is_empty()
            {
                exit_fast_recovery(state);
            } else {
                state.congestion_window = state
                    .slow_start_threshold
                    .saturating_add(server_max_segment_payload(state));
                retransmit_now = preferred_retransmit_index(state).is_some();
            }
        }

        AckEffect {
            bytes_acked,
            rtt_sample,
            grow_congestion_window,
            retransmit_now,
        }
    } else if acknowledgement_number == state.last_client_ack {
        state.duplicate_ack_count = state.duplicate_ack_count.saturating_add(1);
        if state.fast_recovery_end.is_some() {
            state.congestion_window = state
                .congestion_window
                .saturating_add(server_max_segment_payload(state));
            AckEffect {
                bytes_acked: 0,
                rtt_sample: None,
                grow_congestion_window: false,
                retransmit_now: scoreboard_advanced && preferred_retransmit_index(state).is_some(),
            }
        } else if state.duplicate_ack_count >= TCP_FAST_RETRANSMIT_DUP_ACKS {
            enter_fast_recovery(state);
            AckEffect {
                bytes_acked: 0,
                rtt_sample: None,
                grow_congestion_window: false,
                retransmit_now: preferred_retransmit_index(state).is_some(),
            }
        } else {
            AckEffect::none()
        }
    } else {
        AckEffect::none()
    }
}

fn highest_sacked_end(state: &TcpFlowState) -> Option<u32> {
    state
        .sack_scoreboard
        .iter()
        .map(|range| range.end)
        .max_by_key(|end| end.wrapping_sub(state.last_client_ack))
}

pub(in crate::tun_tcp) fn preferred_retransmit_index(state: &TcpFlowState) -> Option<usize> {
    if let Some(highest_sacked_end) = highest_sacked_end(state)
        && let Some(index) = state.unacked_server_segments.iter().position(|segment| {
            !server_segment_is_sacked(state, segment)
                && seq_lt(segment.sequence_number, highest_sacked_end)
        }) {
            return Some(index);
        }

    state
        .unacked_server_segments
        .iter()
        .position(|segment| !server_segment_is_sacked(state, segment))
}

pub(in crate::tun_tcp) fn congestion_window_remaining(state: &TcpFlowState) -> usize {
    state.congestion_window.saturating_sub(bytes_in_pipe(state))
}

pub(in crate::tun_tcp) fn current_retransmission_timeout(state: &TcpFlowState) -> Duration {
    state.retransmission_timeout
}

fn update_rtt_estimator(state: &mut TcpFlowState, sample: Duration) {
    let sample_us = sample.as_micros() as f64;
    match state.smoothed_rtt {
        Some(smoothed_rtt) => {
            let srtt_us = smoothed_rtt.as_micros() as f64;
            let rttvar_us = state.rttvar.as_micros() as f64;
            let new_rttvar_us = 0.75 * rttvar_us + 0.25 * (srtt_us - sample_us).abs();
            let new_srtt_us = 0.875 * srtt_us + 0.125 * sample_us;
            state.smoothed_rtt = Some(Duration::from_micros(new_srtt_us.max(1.0) as u64));
            state.rttvar = Duration::from_micros(new_rttvar_us.max(1.0) as u64);
        },
        None => {
            state.smoothed_rtt = Some(sample);
            state.rttvar = sample / 2;
        },
    }

    let srtt = state.smoothed_rtt.unwrap_or(sample);
    let rto = srtt
        .saturating_add(state.rttvar.saturating_mul(4))
        .clamp(TCP_MIN_RTO, TCP_MAX_RTO);
    state.retransmission_timeout = rto;
}

pub(in crate::tun_tcp) fn note_ack_progress(
    state: &mut TcpFlowState,
    bytes_acked: usize,
    rtt_sample: Option<Duration>,
    grow_congestion_window: bool,
) {
    if let Some(sample) = rtt_sample {
        update_rtt_estimator(state, sample);
    }
    if bytes_acked == 0 || !grow_congestion_window {
        return;
    }

    state.last_ack_progress_at = Instant::now();

    if state.congestion_window < state.slow_start_threshold {
        state.congestion_window = state.congestion_window.saturating_add(bytes_acked);
    } else {
        let additive =
            ((MAX_SERVER_SEGMENT_PAYLOAD * bytes_acked) / state.congestion_window).max(1);
        state.congestion_window = state.congestion_window.saturating_add(additive);
    }
}

pub(in crate::tun_tcp) fn note_congestion_event(state: &mut TcpFlowState, timeout: bool) {
    let inflight = bytes_in_pipe(state);
    state.slow_start_threshold = (inflight / 2).max(TCP_MIN_SSTHRESH);
    state.fast_recovery_end = None;
    state.duplicate_ack_count = 0;
    state.congestion_window = if timeout {
        MAX_SERVER_SEGMENT_PAYLOAD
    } else {
        state.slow_start_threshold
    };
    if timeout {
        state.retransmission_timeout = current_retransmission_timeout(state)
            .saturating_mul(2)
            .clamp(TCP_MIN_RTO, TCP_MAX_RTO);
    }
}
