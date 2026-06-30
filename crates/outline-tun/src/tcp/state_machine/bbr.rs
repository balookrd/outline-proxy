//! BBR-style downlink rate and in-flight control for the userspace TCP stack.
//!
//! The stack terminates the client's TCP locally (≈1 ms away over the LAN/WG
//! hop), so the legacy Reno window inflates to the client's huge receive window
//! within a couple of milliseconds and the flush dumps an entire segment at
//! line rate. On a 100 Mbit last hop that burst overran the router's port
//! buffer and collapsed the flow (the client stalled after ~260 KB while the
//! stack had already pushed ~1.95 MB past the hole).
//!
//! BBR replaces "send whatever the window allows, as fast as possible" with
//! "send at the measured bottleneck bandwidth, keep no more than a BDP in
//! flight". Two estimates drive it:
//!   * **BtlBw** — windowed-max of the per-packet delivery rate (bytes acked
//!     per unit time). This is the real capacity of the last hop, measured.
//!   * **min-RTT** — windowed-min round-trip time, refreshed by PROBE_RTT.
//!
//! From those: `pacing_rate = gain × BtlBw` (token bucket, refilled on each
//! ACK-clocked flush — so timer granularity is never the ceiling, which is what
//! sank the previous fixed-rate pacer) and `inflight_cap = cwnd_gain × BtlBw ×
//! min_rtt`, which is what stops the stack from piling megabytes past a hole.
//!
//! This is layered *on top of* the existing SACK/Reno logic: loss detection and
//! retransmission are unchanged; BBR only lowers the effective send window
//! (`min(reno_cwnd, bbr_inflight_cap)`) and paces the flush.
//!
//! The pure helpers take `&BbrState` / `&mut BbrState` so the estimator is unit
//! testable without a full `TcpFlowState`; the public wrappers feed in the
//! flow's MSS and in-flight bytes.

use std::time::{Duration, Instant};

use super::super::{
    BBR_BW_WINDOW_ROUNDS, BBR_CWND_GAIN, BBR_DRAIN_GAIN, BBR_MIN_PIPE_CWND_SEGMENTS,
    BBR_MIN_RTT_WINDOW, BBR_PACING_MAX_BURST_SEGMENTS, BBR_PROBE_BW_GAINS,
    BBR_PROBE_RTT_CWND_SEGMENTS, BBR_PROBE_RTT_DURATION, BBR_STARTUP_FULL_BW_COUNT,
    BBR_STARTUP_GAIN, BBR_STARTUP_GROWTH_TARGET,
};
use super::congestion::{bytes_in_pipe, server_max_segment_payload};
use super::types::{BbrMode, BbrState, BwSample, RateSample, TcpFlowState};

// --- bandwidth filter ------------------------------------------------------

/// Recompute `btlbw_bps` as the max over the live (non-expired) filter slots.
fn refresh_btlbw(bbr: &mut BbrState) {
    let horizon = bbr.round_count.saturating_sub(BBR_BW_WINDOW_ROUNDS);
    bbr.btlbw_bps = bbr
        .bw_filter
        .iter()
        .filter(|sample| sample.bytes_per_sec > 0 && sample.round >= horizon)
        .map(|sample| sample.bytes_per_sec)
        .max()
        .unwrap_or(0);
}

/// Insert a delivery-rate sample into the 3-slot windowed-max filter: keep the
/// largest value for the current round, reuse an expired/empty slot, else evict
/// the smallest live slot if the new sample beats it.
fn update_bw_filter(bbr: &mut BbrState, bytes_per_sec: u64) {
    let round = bbr.round_count;
    if let Some(slot) = bbr
        .bw_filter
        .iter_mut()
        .find(|s| s.round == round && s.bytes_per_sec > 0)
    {
        if bytes_per_sec > slot.bytes_per_sec {
            slot.bytes_per_sec = bytes_per_sec;
        }
        refresh_btlbw(bbr);
        return;
    }
    let horizon = round.saturating_sub(BBR_BW_WINDOW_ROUNDS);
    if let Some(slot) = bbr
        .bw_filter
        .iter_mut()
        .find(|s| s.bytes_per_sec == 0 || s.round < horizon)
    {
        *slot = BwSample { bytes_per_sec, round };
        refresh_btlbw(bbr);
        return;
    }
    if let Some(slot) = bbr.bw_filter.iter_mut().min_by_key(|s| s.bytes_per_sec)
        && bytes_per_sec > slot.bytes_per_sec
    {
        *slot = BwSample { bytes_per_sec, round };
    }
    refresh_btlbw(bbr);
}

// --- derived quantities (pure on BbrState) ---------------------------------

/// BDP in bytes from the current estimates, or `None` until both BtlBw and
/// min-RTT have a sample (before that the small initial Reno window bounds the
/// burst).
fn bdp_bytes(bbr: &BbrState) -> Option<usize> {
    if bbr.btlbw_bps == 0 || bbr.min_rtt.is_zero() {
        return None;
    }
    Some((bbr.btlbw_bps as f64 * bbr.min_rtt.as_secs_f64()) as usize)
}

/// In-flight cap (bytes), given the flow's MSS. `usize::MAX` until an estimate
/// exists, so the Reno initial window governs the first flight; floored at a
/// few MSS so a sub-ms RTT still admits enough packets to keep ACKs clocking.
fn inflight_cap_from(bbr: &BbrState, mss: usize) -> usize {
    let floor = mss * BBR_MIN_PIPE_CWND_SEGMENTS;
    if bbr.mode == BbrMode::ProbeRtt {
        return floor;
    }
    match bdp_bytes(bbr) {
        Some(bdp) => ((bdp as f64 * bbr.cwnd_gain) as usize).max(floor),
        None => usize::MAX,
    }
}

/// Pacing rate in bytes/sec, or 0 while inactive (no BtlBw sample yet).
fn pacing_rate_from(bbr: &BbrState) -> u64 {
    if bbr.btlbw_bps == 0 {
        return 0;
    }
    ((bbr.btlbw_bps as f64 * bbr.pacing_gain) as u64).max(1)
}

fn pacing_burst_cap_bytes(mss: usize) -> u64 {
    (mss * BBR_PACING_MAX_BURST_SEGMENTS) as u64
}

/// Add credit for elapsed time at `rate`, capped at `cap`.
fn refill_credit_at(bbr: &mut BbrState, rate: u64, cap: u64, now: Instant) {
    if rate == 0 {
        return;
    }
    let elapsed = now.saturating_duration_since(bbr.pacing_refilled_at).as_secs_f64();
    let added = (rate as f64 * elapsed) as u64;
    bbr.pacing_credit = bbr.pacing_credit.saturating_add(added).min(cap);
    bbr.pacing_refilled_at = now;
}

fn release_at_for(bbr: &BbrState, byte_count: usize, rate: u64) -> Instant {
    let deficit = (byte_count as u64).saturating_sub(bbr.pacing_credit);
    if deficit == 0 {
        return bbr.pacing_refilled_at;
    }
    bbr.pacing_refilled_at + Duration::from_secs_f64(deficit as f64 / rate.max(1) as f64)
}

// --- public wrappers (feed in MSS / in-flight from the flow) ---------------

/// In-flight cap (bytes) BBR allows for this flow.
pub(in crate::tcp) fn inflight_cap(state: &TcpFlowState) -> usize {
    inflight_cap_from(&state.bbr, server_max_segment_payload(state))
}

/// Whether pacing is currently shaping this flow (a BtlBw sample exists).
pub(in crate::tcp) fn pacing_active(state: &TcpFlowState) -> bool {
    state.bbr.btlbw_bps > 0
}

/// Refill the pacing token bucket for elapsed time at the current rate. Driven
/// by the flush (ACK-clocked), so the refill cadence tracks ACK arrivals rather
/// than a coarse timer.
pub(in crate::tcp) fn refill_pacing_credit(state: &mut TcpFlowState, now: Instant) {
    let rate = pacing_rate_from(&state.bbr);
    let cap = pacing_burst_cap_bytes(server_max_segment_payload(state));
    refill_credit_at(&mut state.bbr, rate, cap, now);
}

/// Instant at which `byte_count` more bytes of credit will have refilled — the
/// wakeup the flush arms when it stops with data queued.
pub(in crate::tcp) fn pacing_release_at(state: &TcpFlowState, byte_count: usize) -> Instant {
    let rate = pacing_rate_from(&state.bbr).max(1);
    release_at_for(&state.bbr, byte_count, rate)
}

// --- mode / gain state machine ---------------------------------------------

fn enter_drain(bbr: &mut BbrState) {
    bbr.mode = BbrMode::Drain;
    bbr.pacing_gain = BBR_DRAIN_GAIN;
    bbr.cwnd_gain = BBR_STARTUP_GAIN;
}

fn enter_probe_bw(bbr: &mut BbrState, now: Instant) {
    bbr.mode = BbrMode::ProbeBw;
    bbr.cwnd_gain = BBR_CWND_GAIN;
    // Start on a cruise phase (gain 1.0) so entry does not immediately probe up.
    bbr.probe_bw_phase = 2;
    bbr.pacing_gain = BBR_PROBE_BW_GAINS[bbr.probe_bw_phase];
    bbr.cycle_stamp = now;
}

fn enter_probe_rtt(bbr: &mut BbrState) {
    bbr.mode = BbrMode::ProbeRtt;
    bbr.pacing_gain = 1.0;
    bbr.probe_rtt_done_at = None;
}

/// Per-round STARTUP plateau check: BtlBw must keep growing by the target
/// factor; once it fails to for `BBR_STARTUP_FULL_BW_COUNT` rounds the pipe is
/// full and we move to DRAIN.
fn check_startup_full_pipe(bbr: &mut BbrState) {
    if bbr.btlbw_bps >= (bbr.full_bw as f64 * BBR_STARTUP_GROWTH_TARGET) as u64 {
        bbr.full_bw = bbr.btlbw_bps;
        bbr.full_bw_count = 0;
    } else {
        bbr.full_bw_count = bbr.full_bw_count.saturating_add(1);
    }
}

/// Fold one ACK's worth of delivery into the estimates (delivered counter, rate
/// sample → BtlBw, round step, min-RTT). Pure on `BbrState`; the mode machine
/// (which needs in-flight bytes) runs in [`on_ack`].
fn record_delivery(
    bbr: &mut BbrState,
    bytes_delivered: u64,
    rate_sample: Option<RateSample>,
    rtt_sample: Option<Duration>,
    now: Instant,
) {
    bbr.delivered = bbr.delivered.saturating_add(bytes_delivered);
    bbr.delivered_at = now;

    // Round bookkeeping: a round elapses when this ACK covers a segment sent
    // at/after the start of the current round.
    if let Some(sample) = rate_sample
        && sample.prior_delivered >= bbr.next_round_delivered
    {
        bbr.round_count = bbr.round_count.saturating_add(1);
        bbr.next_round_delivered = bbr.delivered;
        if bbr.mode == BbrMode::Startup {
            check_startup_full_pipe(bbr);
        }
    }

    // Delivery-rate sample → BtlBw windowed-max. An app-limited sample (buffer
    // drained, so the rate reflects our supply, not the path) may only raise the
    // estimate, never lower it.
    if let Some(sample) = rate_sample {
        let interval = now.saturating_duration_since(sample.sent_at).as_secs_f64();
        if interval > 0.0 {
            let delivered = bbr.delivered.saturating_sub(sample.prior_delivered);
            let rate = (delivered as f64 / interval) as u64;
            if !sample.app_limited || rate > bbr.btlbw_bps {
                update_bw_filter(bbr, rate);
            }
        }
    }

    // min-RTT windowed-min: take a lower sample, or reseed when the window
    // expired or none has ever been recorded.
    if let Some(rtt) = rtt_sample {
        let expired = now.saturating_duration_since(bbr.min_rtt_stamp) > BBR_MIN_RTT_WINDOW;
        if bbr.min_rtt.is_zero() || rtt < bbr.min_rtt || expired {
            bbr.min_rtt = rtt;
            bbr.min_rtt_stamp = now;
        }
    }
}

/// Advance the mode/gain machine after the estimates have been updated.
fn update_mode(state: &mut TcpFlowState, now: Instant) {
    // PROBE_RTT takes priority: enter it when min-RTT has gone stale.
    if state.bbr.mode != BbrMode::ProbeRtt
        && now.saturating_duration_since(state.bbr.min_rtt_stamp) > BBR_MIN_RTT_WINDOW
    {
        enter_probe_rtt(&mut state.bbr);
    }

    match state.bbr.mode {
        BbrMode::Startup => {
            if state.bbr.full_bw_count >= BBR_STARTUP_FULL_BW_COUNT {
                enter_drain(&mut state.bbr);
            }
        },
        BbrMode::Drain => {
            // Once the standing queue has drained to a BDP, cruise.
            let drained = bdp_bytes(&state.bbr)
                .map(|bdp| bytes_in_pipe(state) <= bdp)
                .unwrap_or(true);
            if drained {
                enter_probe_bw(&mut state.bbr, now);
            }
        },
        BbrMode::ProbeBw => {
            // One pacing-gain phase per min-RTT.
            let phase_len = state.bbr.min_rtt.max(Duration::from_millis(1));
            if now.saturating_duration_since(state.bbr.cycle_stamp) >= phase_len {
                state.bbr.probe_bw_phase =
                    (state.bbr.probe_bw_phase + 1) % BBR_PROBE_BW_GAINS.len();
                state.bbr.pacing_gain = BBR_PROBE_BW_GAINS[state.bbr.probe_bw_phase];
                state.bbr.cycle_stamp = now;
            }
        },
        BbrMode::ProbeRtt => {
            // Hold the pipe near-empty for the probe window, then resume.
            let floor = server_max_segment_payload(state) * BBR_PROBE_RTT_CWND_SEGMENTS;
            match state.bbr.probe_rtt_done_at {
                None => {
                    if bytes_in_pipe(state) <= floor {
                        state.bbr.probe_rtt_done_at = Some(now + BBR_PROBE_RTT_DURATION);
                    }
                },
                Some(done_at) if now >= done_at => {
                    state.bbr.min_rtt_stamp = now;
                    enter_probe_bw(&mut state.bbr, now);
                },
                Some(_) => {},
            }
        },
    }
}

/// Fold one ACK into the BBR estimates and advance the mode/gain machine.
pub(in crate::tcp) fn on_ack(
    state: &mut TcpFlowState,
    bytes_delivered: u64,
    rate_sample: Option<RateSample>,
    rtt_sample: Option<Duration>,
    now: Instant,
) {
    record_delivery(&mut state.bbr, bytes_delivered, rate_sample, rtt_sample, now);
    update_mode(state, now);
}

#[cfg(test)]
#[path = "tests/bbr.rs"]
mod tests;
