use std::time::{Duration, Instant};

use super::super::{
    MAX_SERVER_SEGMENT_PAYLOAD, TCP_FAST_RETRANSMIT_DUP_ACKS, TCP_FLAG_FIN, TCP_FLAG_SYN,
    TCP_MAX_PACING_RATE_BYTES_PER_SEC, TCP_MAX_RTO, TCP_MIN_RTO, TCP_MIN_SSTHRESH,
    TCP_PACING_MAX_BURST_BYTES,
};
use super::seq::{seq_ge, seq_gt, seq_lt};
use super::types::{AckEffect, SequenceRange, ServerSegment, TcpFlowState};

pub(in crate::tcp) fn server_segment_len(segment: &ServerSegment) -> usize {
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
    // Fast path: skip blocks that the existing scoreboard already fully covers
    // (or that fall entirely below the cumulative ACK). If nothing new comes in,
    // we return without touching the scoreboard at all.
    let mut new_ranges: Vec<SequenceRange> = Vec::new();
    for (start, end) in sack_blocks {
        let mut range = SequenceRange { start: *start, end: *end };
        if !seq_gt(range.end, cumulative_ack) {
            continue;
        }
        if seq_lt(range.start, cumulative_ack) {
            range.start = cumulative_ack;
        }
        if !seq_gt(range.end, range.start) {
            continue;
        }
        if !range_fully_covered(scoreboard, range.start, range.end) {
            new_ranges.push(range);
        }
    }
    if new_ranges.is_empty() {
        return false;
    }
    let mut ranges = std::mem::take(scoreboard);
    ranges.append(&mut new_ranges);
    *scoreboard = merge_sequence_ranges(ranges, cumulative_ack);
    true
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

pub(in crate::tcp) fn server_segment_is_sacked(
    state: &TcpFlowState,
    segment: &ServerSegment,
) -> bool {
    let end = segment
        .sequence_number
        .wrapping_add(server_segment_len(segment) as u32);
    range_fully_covered(&state.sack_scoreboard, segment.sequence_number, end)
}

pub(in crate::tcp) fn bytes_in_pipe(state: &TcpFlowState) -> usize {
    state
        .unacked_server_segments
        .iter()
        .filter(|segment| !server_segment_is_sacked(state, segment))
        .map(server_segment_len)
        .sum()
}

pub(in crate::tcp) fn count_segments_in_pipe(state: &TcpFlowState) -> usize {
    state
        .unacked_server_segments
        .iter()
        .filter(|segment| !server_segment_is_sacked(state, segment))
        .count()
}

pub(in crate::tcp) fn next_retransmission_deadline(state: &TcpFlowState) -> Option<Instant> {
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
    // New recovery episode: bump the epoch so holes carrying a stale
    // `fast_retransmit_epoch` are eligible for one fresh fast-retransmit.
    state.recovery_epoch = state.recovery_epoch.saturating_add(1);
}

fn exit_fast_recovery(state: &mut TcpFlowState) {
    state.fast_recovery_end = None;
    state.duplicate_ack_count = 0;
    state.congestion_window = state.slow_start_threshold.max(server_max_segment_payload(state));
}

pub(in crate::tcp) fn server_max_segment_payload(state: &TcpFlowState) -> usize {
    state
        .client_max_segment_size
        .map(usize::from)
        .unwrap_or(MAX_SERVER_SEGMENT_PAYLOAD)
        .clamp(1, MAX_SERVER_SEGMENT_PAYLOAD)
}

pub(in crate::tcp) fn process_server_ack(
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
                retransmit_now = fast_retransmit_index(state).is_some();
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
                retransmit_now: scoreboard_advanced && fast_retransmit_index(state).is_some(),
            }
        } else if state.duplicate_ack_count >= TCP_FAST_RETRANSMIT_DUP_ACKS {
            enter_fast_recovery(state);
            AckEffect {
                bytes_acked: 0,
                rtt_sample: None,
                grow_congestion_window: false,
                retransmit_now: fast_retransmit_index(state).is_some(),
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

pub(in crate::tcp) fn preferred_retransmit_index(state: &TcpFlowState) -> Option<usize> {
    if let Some(highest_sacked_end) = highest_sacked_end(state)
        && let Some(index) = state.unacked_server_segments.iter().position(|segment| {
            !server_segment_is_sacked(state, segment)
                && seq_lt(segment.sequence_number, highest_sacked_end)
        })
    {
        return Some(index);
    }

    state
        .unacked_server_segments
        .iter()
        .position(|segment| !server_segment_is_sacked(state, segment))
}

/// SACK-driven fast-retransmit candidate. Targets the first un-SACKed hole
/// below the highest SACKed block — but, unlike [`preferred_retransmit_index`],
/// it skips holes already fast-retransmitted in the *current* recovery episode
/// (`fast_retransmit_epoch == recovery_epoch`). RFC 6675 resends each hole at
/// most once per episode; a lost retransmit is recovered by the RTO path, not
/// by re-firing on every incoming partial SACK. This is what stops a burst of
/// duplicate ACKs from re-sending the same hole dozens of times.
pub(in crate::tcp) fn fast_retransmit_index(state: &TcpFlowState) -> Option<usize> {
    // A hole is fresh for this episode when it is neither SACKed nor already
    // fast-retransmitted under the current `recovery_epoch`.
    let fresh = |segment: &ServerSegment| {
        !server_segment_is_sacked(state, segment)
            && segment.fast_retransmit_epoch != state.recovery_epoch
    };
    if let Some(highest_sacked_end) = highest_sacked_end(state) {
        // SACK is present: a hole is only data still missing *below* the
        // highest SACKed block. Anything above it is the normal in-flight tail,
        // not a loss, so there is no Reno fallback here — returning None lets
        // the flow send new data instead of spuriously resending the tail.
        return state.unacked_server_segments.iter().position(|segment| {
            fresh(segment) && seq_lt(segment.sequence_number, highest_sacked_end)
        });
    }

    // No SACK info (Reno): the oldest still-fresh segment is the presumed loss.
    state.unacked_server_segments.iter().position(fresh)
}

pub(in crate::tcp) fn congestion_window_remaining(state: &TcpFlowState) -> usize {
    state.congestion_window.saturating_sub(bytes_in_pipe(state))
}

/// Downlink pacing rate in bytes/sec. Always active (from the first segment),
/// because the very first burst is what overran the path. Without an RTT
/// sample it paces at the hard ceiling; with one it paces just ahead of cwnd
/// (gain 5/4) but never above the ceiling — on a small-RTT hop `cwnd/RTT` is
/// enormous, so the ceiling is what actually shapes the micro-bursts.
pub(in crate::tcp) fn pacing_rate_bytes_per_sec(state: &TcpFlowState) -> u64 {
    let rate = match state.smoothed_rtt {
        Some(srtt) => {
            let srtt_secs = srtt.as_secs_f64().max(0.0001);
            (state.congestion_window as f64 / srtt_secs) * 1.25
        },
        None => TCP_MAX_PACING_RATE_BYTES_PER_SEC as f64,
    };
    (rate as u64).clamp(1, TCP_MAX_PACING_RATE_BYTES_PER_SEC)
}

/// Add credit for the time elapsed since the last refill at the current pacing
/// rate, capped at the burst ceiling.
pub(in crate::tcp) fn refill_pacing_credit(state: &mut TcpFlowState, now: Instant) {
    let rate = pacing_rate_bytes_per_sec(state);
    let elapsed = now.saturating_duration_since(state.pacing_refilled_at).as_secs_f64();
    let added = (rate as f64 * elapsed) as u64;
    state.pacing_credit = state
        .pacing_credit
        .saturating_add(added)
        .min(TCP_PACING_MAX_BURST_BYTES as u64);
    state.pacing_refilled_at = now;
}

/// Instant at which `byte_count` more bytes of pacing credit will be available,
/// given the current rate.
pub(in crate::tcp) fn pacing_release_at(state: &TcpFlowState, byte_count: usize) -> Instant {
    let rate = pacing_rate_bytes_per_sec(state);
    let deficit = (byte_count as u64).saturating_sub(state.pacing_credit);
    if deficit == 0 {
        return state.pacing_refilled_at;
    }
    let wait = Duration::from_secs_f64(deficit as f64 / rate.max(1) as f64);
    state.pacing_refilled_at + wait
}

pub(in crate::tcp) fn current_retransmission_timeout(state: &TcpFlowState) -> Duration {
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

pub(in crate::tcp) fn note_ack_progress(
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

pub(in crate::tcp) fn note_congestion_event(state: &mut TcpFlowState, timeout: bool) {
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
