use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::super::{
    BBR_CWND_LOSS_BETA, MAX_SERVER_SEGMENT_PAYLOAD, TCP_FAST_RETRANSMIT_DUP_ACKS, TCP_FLAG_FIN,
    TCP_FLAG_SYN, TCP_MAX_RTO, TCP_MAX_RTO_BACKOFF, TCP_MIN_RTO, TCP_MIN_SSTHRESH,
};
use super::seq::{seq_ge, seq_gt, seq_lt};
use super::types::{AckEffect, RateSample, SequenceRange, ServerSegment, TcpFlowState};

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

/// Drop scoreboard ranges at/below `cumulative_ack` and clip the left edge of a
/// range that straddles it. Returns `true` when a left edge was actually clipped
/// (`range.start < cumulative_ack`) — the only trim outcome that can flip a
/// still-queued segment's SACKed status: a segment straddling the ACK
/// (`seq < ack < end`) is not popped, so clipping the block that covered it
/// re-opens a hole and moves it back into the pipe. Dropping a range wholly at or
/// below the ACK only touches segments that were already popped, so it needs no
/// signal. The caller rebuilds the running accounting on a `true`.
fn trim_sack_scoreboard(scoreboard: &mut Vec<SequenceRange>, cumulative_ack: u32) -> bool {
    let mut ranges = Vec::with_capacity(scoreboard.len());
    let mut clipped = false;
    for mut range in scoreboard.drain(..) {
        if !seq_gt(range.end, cumulative_ack) {
            continue;
        }
        if seq_lt(range.start, cumulative_ack) {
            range.start = cumulative_ack;
            clipped = true;
        }
        if seq_gt(range.end, range.start) {
            ranges.push(range);
        }
    }
    *scoreboard = merge_sequence_ranges(ranges, cumulative_ack);
    clipped
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

/// Whether `segment` is fully covered by `scoreboard`. Split from
/// [`server_segment_is_sacked`] so the incremental accounting can probe the
/// scoreboard while holding a disjoint borrow of the segment queue.
fn segment_is_sacked_in(scoreboard: &[SequenceRange], segment: &ServerSegment) -> bool {
    let end = segment
        .sequence_number
        .wrapping_add(server_segment_len(segment) as u32);
    range_fully_covered(scoreboard, segment.sequence_number, end)
}

pub(in crate::tcp) fn server_segment_is_sacked(
    state: &TcpFlowState,
    segment: &ServerSegment,
) -> bool {
    segment_is_sacked_in(&state.sack_scoreboard, segment)
}

/// Scan the unacked queue against the current scoreboard and return the exact
/// `(pipe_bytes, pipe_segments, earliest_unsacked_sent, reordered)` tuple. This
/// is the O(N·scoreboard) reference computation; the running counters on
/// `TcpFlowState` must always equal it. Used both to rebuild the counters when
/// the scoreboard changes and, in debug builds, to cross-check them.
fn unacked_accounting_snapshot(
    segments: &VecDeque<ServerSegment>,
    scoreboard: &[SequenceRange],
) -> (usize, usize, Option<Instant>, bool) {
    let mut pipe_bytes = 0usize;
    let mut pipe_segments = 0usize;
    let mut earliest: Option<Instant> = None;
    let mut previous_sent: Option<Instant> = None;
    let mut reordered = false;
    for segment in segments {
        if let Some(previous) = previous_sent
            && segment.last_sent < previous
        {
            reordered = true;
        }
        previous_sent = Some(segment.last_sent);
        if !segment_is_sacked_in(scoreboard, segment) {
            pipe_bytes += server_segment_len(segment);
            pipe_segments += 1;
            earliest = Some(match earliest {
                Some(current) => current.min(segment.last_sent),
                None => segment.last_sent,
            });
        }
    }
    (pipe_bytes, pipe_segments, earliest, reordered)
}

/// Recompute the incremental in-flight accounting from scratch. Called when the
/// SACK scoreboard changes (a segment may have moved in or out of the pipe) and
/// after a retransmit reorders send instants — never on the per-write flush
/// path. Also usable from tests that build `unacked_server_segments` /
/// `sack_scoreboard` by hand, mirroring how `pending_server_bytes_total` is
/// re-synced there.
pub(in crate::tcp) fn rebuild_unacked_accounting(state: &mut TcpFlowState) {
    let (pipe_bytes, pipe_segments, earliest, reordered) =
        unacked_accounting_snapshot(&state.unacked_server_segments, &state.sack_scoreboard);
    state.pipe_bytes = pipe_bytes;
    state.pipe_segments = pipe_segments;
    state.earliest_unsacked_sent = earliest;
    state.unacked_reordered = reordered;
}

/// After a cumulative ACK popped a prefix of the queue, refresh the cached
/// earliest un-SACKed send instant. On the loss-free path `last_sent` is
/// non-decreasing by position, so the first remaining un-SACKed segment holds
/// the minimum (O(1)–O(sacked-prefix)); a prior retransmit that reordered send
/// instants falls back to the exact rescan (which also re-clears the flag once
/// order is restored). `pipe_bytes` / `pipe_segments` are maintained inline by
/// the pop loop, so this only touches the earliest cache.
fn refresh_earliest_after_pop(state: &mut TcpFlowState) {
    if state.unacked_server_segments.is_empty() {
        state.earliest_unsacked_sent = None;
        state.unacked_reordered = false;
        return;
    }
    if state.unacked_reordered {
        rebuild_unacked_accounting(state);
    } else {
        state.earliest_unsacked_sent = state
            .unacked_server_segments
            .iter()
            .find(|segment| !segment_is_sacked_in(&state.sack_scoreboard, segment))
            .map(|segment| segment.last_sent);
    }
}

/// Debug-only: assert the running counters equal the scan reference. Runs on
/// every hot-path read (`bytes_in_pipe` / `count_segments_in_pipe` /
/// `next_retransmission_deadline`), so a missed update site — the one way this
/// change could silently skew the congestion window — trips in debug/tests
/// immediately without costing anything in release.
#[inline]
fn debug_assert_unacked_accounting(state: &TcpFlowState) {
    #[cfg(not(debug_assertions))]
    let _ = state;
    #[cfg(debug_assertions)]
    {
        let (pipe_bytes, pipe_segments, earliest, reordered) =
            unacked_accounting_snapshot(&state.unacked_server_segments, &state.sack_scoreboard);
        debug_assert_eq!(state.pipe_bytes, pipe_bytes, "pipe_bytes drifted from the scan version");
        debug_assert_eq!(
            state.pipe_segments, pipe_segments,
            "pipe_segments drifted from the scan version"
        );
        debug_assert_eq!(
            state.earliest_unsacked_sent, earliest,
            "earliest_unsacked_sent drifted from the scan version"
        );
        // A stale-true `unacked_reordered` is safe (it only forces one extra
        // exact rescan); a stale-false would trust front ordering wrongly.
        if reordered {
            debug_assert!(
                state.unacked_reordered,
                "unacked_reordered is false but the queue is actually reordered"
            );
        }
    }
}

pub(in crate::tcp) fn bytes_in_pipe(state: &TcpFlowState) -> usize {
    debug_assert_unacked_accounting(state);
    state.pipe_bytes
}

pub(in crate::tcp) fn count_segments_in_pipe(state: &TcpFlowState) -> usize {
    debug_assert_unacked_accounting(state);
    state.pipe_segments
}

pub(in crate::tcp) fn next_retransmission_deadline(state: &TcpFlowState) -> Option<Instant> {
    debug_assert_unacked_accounting(state);
    // `rto` is constant across the queue, so `min(last_sent) + rto` equals the
    // old `min(last_sent + rto)`.
    state
        .earliest_unsacked_sent
        .map(|sent| sent + state.retransmission_timeout)
}

fn enter_fast_recovery(state: &mut TcpFlowState) {
    let inflight = bytes_in_pipe(state).max(server_max_segment_payload(state));
    // Gentle AIMD decrease (`× BBR_CWND_LOSS_BETA`) instead of Reno's `/ 2`: on a
    // radio last mile a sporadic drop must not halve the window and cost ~213 RTT
    // to climb back. See `BBR_CWND_LOSS_BETA`.
    state.slow_start_threshold =
        ((inflight as f64 * BBR_CWND_LOSS_BETA) as usize).max(TCP_MIN_SSTHRESH);
    state.congestion_window = state.slow_start_threshold.saturating_add(
        server_max_segment_payload(state) * usize::from(TCP_FAST_RETRANSMIT_DUP_ACKS),
    );
    state.fast_recovery_end = Some(state.server_seq);
    state.duplicate_ack_count = TCP_FAST_RETRANSMIT_DUP_ACKS;
    // New recovery episode: bump the epoch so holes carrying a stale
    // `fast_retransmit_epoch` are eligible for one fresh fast-retransmit.
    state.recovery_epoch = state.recovery_epoch.saturating_add(1);
    // Loss signal for the BBR pacer: back the loss-driven rate cap off so the
    // pacer stops driving the burst that overran the last hop.
    super::bbr::note_loss(&mut state.bbr);
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
    // Extend the scoreboard with any new SACK blocks now, but defer trimming
    // ranges at/below the cumulative ACK until *after* the pop loop below.
    // Trimming first would drop the range that still marks an already-SACKed
    // (already out-of-pipe) segment, so the pop loop would then see it as
    // un-SACKed and subtract it from the pipe a second time (underflow).
    let scoreboard_advanced =
        update_sack_scoreboard(&mut state.sack_scoreboard, acknowledgement_number, sack_blocks);
    // A new SACK block can move segments out of the pipe; rebuild the running
    // accounting once here (O(N)) rather than rescanning on every read. A
    // cumulative-only ACK (no new block) leaves every still-queued segment's
    // coverage unchanged, so the inline updates in the pop loop keep the
    // counters exact without a rebuild.
    if scoreboard_advanced {
        rebuild_unacked_accounting(state);
    }

    let effect = if state.unacked_server_segments.is_empty() {
        state.last_client_ack = acknowledgement_number;
        state.duplicate_ack_count = 0;
        state.fast_recovery_end = None;
        AckEffect::none()
    } else if seq_gt(acknowledgement_number, state.last_client_ack) {
        state.last_client_ack = acknowledgement_number;
        state.duplicate_ack_count = 0;
        let mut bytes_acked = 0usize;
        let mut rtt_sample = None;
        let mut rate_sample = None;
        while let Some(segment) = state.unacked_server_segments.front() {
            let segment_end = segment
                .sequence_number
                .wrapping_add(server_segment_len(segment) as u32);
            if !seq_ge(acknowledgement_number, segment_end) {
                break;
            }
            // A SACKed segment was already removed from the pipe when the
            // scoreboard covered it, so only un-SACKed segments decrement here.
            let was_sacked = segment_is_sacked_in(&state.sack_scoreboard, segment);
            let segment = state.unacked_server_segments.pop_front().expect("front exists");
            let segment_len = server_segment_len(&segment);
            if !was_sacked {
                state.pipe_bytes -= segment_len;
                state.pipe_segments -= 1;
            }
            bytes_acked = bytes_acked.saturating_add(segment_len);
            // Canonical `tcp_rate_skb_delivered`: "record send time of the most
            // recently ACKed packet". `first_tx_mstamp` is the anchor the *next*
            // segments snapshot into `first_tx_snapshot`, and their send interval
            // is measured from it — so it must track the flight the path is
            // currently returning.
            //
            // `tcp_rate_skb_sent` seeds it when the pipe is empty, and that was
            // the only site here. A bulk transfer never empties the pipe, so the
            // anchor stayed at the instant the flow's first byte went out and the
            // send interval became the flow's *age*: it grew without bound (3.3 s
            // and climbing on the field gateway, against an ACK interval of 8 ms).
            // Since the rate interval is `max(ack_interval, send_interval)`, every
            // sample was divided by seconds instead of milliseconds, reading ~10
            // KB/s on a path carrying tens of MB/s. Those samples are then
            // `pacing_limited`, so they may only raise BtlBw and never do — 66 of
            // 69 samples were dropped, leaving BtlBw pinned far below the link and
            // the pacer throttling the flow to it (pipe 93% empty, cwnd and the
            // BBR cap both idle).
            state.first_tx_mstamp = state.first_tx_mstamp.max(segment.last_sent);
            if segment.retransmits == 0 {
                rtt_sample = Some(segment.first_sent.elapsed());
                // BBR delivery-rate sample from the oldest cleanly-acked
                // segment of this ACK (longest interval = least noisy).
                if rate_sample.is_none() {
                    rate_sample = Some(RateSample {
                        prior_delivered: segment.delivered_snapshot,
                        prior_mstamp: segment.delivered_at_snapshot,
                        send_interval: segment
                            .first_sent
                            .saturating_duration_since(segment.first_tx_snapshot),
                        app_limited: segment.app_limited,
                    });
                }
            }
        }
        // The popped prefix may have held the earliest un-SACKed send instant.
        refresh_earliest_after_pop(state);

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
            rate_sample,
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
                rate_sample: None,
            }
        } else if state.duplicate_ack_count >= TCP_FAST_RETRANSMIT_DUP_ACKS {
            enter_fast_recovery(state);
            AckEffect {
                bytes_acked: 0,
                rtt_sample: None,
                grow_congestion_window: false,
                retransmit_now: fast_retransmit_index(state).is_some(),
                rate_sample: None,
            }
        } else {
            AckEffect::none()
        }
    } else {
        AckEffect::none()
    };

    // Now drop scoreboard ranges at/below the cumulative ACK. A segment that
    // straddles the ACK (`seq < ack < end`) is still queued, so if the trim
    // clips the left edge of a block that fully covered it, that segment falls
    // back out of the SACKed set and into the pipe — the running counters and
    // earliest cache computed above no longer reflect it. Rebuild once in that
    // case. (A cumulative-only ACK cannot produce this against an honest peer —
    // it would require a SACK block below the cumulative ACK — so on the honest
    // path `clipped` is false and this costs nothing; it keeps the accounting
    // exact against a malformed or reneging peer, where a release build would
    // otherwise skew the congestion window silently.)
    let clipped = trim_sack_scoreboard(&mut state.sack_scoreboard, acknowledgement_number);
    if clipped {
        rebuild_unacked_accounting(state);
    }
    effect
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
    // Effective send window is the smaller of the Reno congestion window and the
    // BBR in-flight cap (BDP), minus what is already in flight. On the sub-ms
    // hop to the client the Reno window inflates almost unbounded, so the BBR
    // BDP cap is what actually binds — and what stops the stack from piling a
    // whole segment past a hole on a slow last hop.
    let pipe = bytes_in_pipe(state);
    let reno_remaining = state.congestion_window.saturating_sub(pipe);
    let bbr_remaining = super::bbr::inflight_cap(state).saturating_sub(pipe);
    reno_remaining.min(bbr_remaining)
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
    rate_sample: Option<RateSample>,
) {
    let now = Instant::now();
    if let Some(sample) = rtt_sample {
        update_rtt_estimator(state, sample);
    }

    // BBR estimation advances on every delivery, independent of Reno's cwnd
    // growth: even in fast recovery (where `grow_congestion_window` is false)
    // the bytes acked still carry a delivery-rate/min-RTT signal.
    if bytes_acked > 0 || rate_sample.is_some() {
        super::bbr::on_ack(state, bytes_acked as u64, rate_sample, rtt_sample, now);
    }

    if bytes_acked == 0 || !grow_congestion_window {
        return;
    }

    state.last_ack_progress_at = now;

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
    // Gentle decrease, as in `enter_fast_recovery`: back the window off by
    // `BBR_CWND_LOSS_BETA`, and — crucially for an RTO — do NOT collapse it to a
    // single segment. The old collapse-to-1-MSS is what let a burst RTO strand
    // the flow at a tiny window from which it could not ACK-clock its way back,
    // and the timeouts then compounded into a storm (measured). Backing off to
    // `0.85 × inflight` keeps enough window in flight to keep ACKs coming while
    // the BBR pacer and loss cap shed the rate.
    state.slow_start_threshold =
        ((inflight as f64 * BBR_CWND_LOSS_BETA) as usize).max(TCP_MIN_SSTHRESH);
    state.fast_recovery_end = None;
    state.duplicate_ack_count = 0;
    state.congestion_window = state.slow_start_threshold;
    if timeout {
        // Cap the backoff (not at the 60 s dead-path ceiling): a lost
        // retransmit on a lossy last mile must be re-sent promptly so media
        // does not freeze for seconds. The dead-flow abort is by retransmit
        // count, not timing, so this does not weaken it.
        state.retransmission_timeout = current_retransmission_timeout(state)
            .saturating_mul(2)
            .clamp(TCP_MIN_RTO, TCP_MAX_RTO_BACKOFF);
        // RTO is the strongest loss signal — back the BBR pacer's rate cap off.
        super::bbr::note_loss(&mut state.bbr);
    }
}
