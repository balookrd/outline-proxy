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
    BBR_BW_WINDOW_ROUNDS, BBR_CWND_GAIN, BBR_DRAIN_GAIN, BBR_LOSS_CAP_BACKOFF,
    BBR_LOSS_CAP_FLOOR_BPS, BBR_LOSS_CAP_RECOVER_FRACTION, BBR_MIN_PIPE_CWND_SEGMENTS,
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

/// BtlBw clamped to the configured downlink ceiling (`max_rate_bps`, 0 =
/// uncapped) and to the loss-driven soft cap (`loss_cap_bps`, 0 = inactive). On
/// a sub-ms hop BBR over-estimates BtlBw from line-rate burst samples; both
/// caps pull the effective rate down to what the last hop actually drains, so
/// this governs the BDP and the pacing rate alike.
fn effective_btlbw(bbr: &BbrState) -> u64 {
    let mut rate = bbr.btlbw_bps;
    if bbr.max_rate_bps > 0 {
        rate = rate.min(bbr.max_rate_bps);
    }
    if bbr.loss_cap_bps > 0 {
        rate = rate.min(bbr.loss_cap_bps);
    }
    rate
}

/// BDP in bytes from the current estimates, or `None` until both BtlBw and
/// min-RTT have a sample (before that the small initial Reno window bounds the
/// burst).
fn bdp_bytes(bbr: &BbrState) -> Option<usize> {
    if bbr.btlbw_bps == 0 || bbr.min_rtt.is_zero() {
        return None;
    }
    Some((effective_btlbw(bbr) as f64 * bbr.min_rtt.as_secs_f64()) as usize)
}

/// How much data the pacer puts on the wire in roughly one millisecond, in
/// segments — canonical BBR's `bbr_tso_segs_goal`, which derives it from the
/// pacing rate rather than from a fixed count. Floored at 2 segments (the
/// canonical `bbr_min_tso_segs`) and capped like the original.
fn tso_segs_goal(bbr: &BbrState, mss: usize) -> usize {
    let per_ms = (pacing_rate_from(bbr) / 1024) as usize;
    (per_ms / mss.max(1)).clamp(2, 127)
}

/// Canonical BBR's `bbr_quantization_budget`: head-room added on top of
/// `gain x BDP` so the pipe stays busy across ACK aggregation.
///
/// Without it the cap is exactly `gain x BDP`, which silently assumes the flight
/// comes back over `min_rtt`. It does not: it comes back over the path's actual
/// RTT. When `srtt / min_rtt` exceeds `cwnd_gain`, a cap-bound flight delivers
/// `cap / srtt < btlbw` — and since the cap is computed *from* BtlBw, the pair
/// ratchets each other down every round until the cap lands on its floor. The
/// field gateway hit exactly that: min_rtt 1.876 ms against srtt 5.021 ms (a
/// jittery Wi-Fi last mile, ping mdev 2.5 ms), ratio 2.7 against a gain of 2.0,
/// BtlBw collapsed to 1.17 MB/s on a link carrying 9 MB/s, cap parked on
/// `4 x MSS` with 2.1 MB queued behind a 167 KB client window.
///
/// The budget breaks the ratchet because it does not scale with BtlBw: the
/// steady state solves `btlbw = budget / (srtt - gain x min_rtt)` instead of
/// collapsing to zero, so the estimate climbs back to what the link carries.
/// Sizing it off the pacing rate (not a fixed segment count) keeps it
/// proportional to what this flow actually sends, so it is head-room on a slow
/// flow and negligible on a fast one — it does not hand the last hop a burst,
/// which is what the controller exists to prevent.
fn quantization_budget(bbr: &BbrState, mss: usize, cwnd: usize) -> usize {
    cwnd + 3 * tso_segs_goal(bbr, mss) * mss
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
        Some(bdp) => {
            let cwnd = (bdp as f64 * bbr.cwnd_gain) as usize;
            quantization_budget(bbr, mss, cwnd).max(floor)
        },
        None => usize::MAX,
    }
}

/// Pacing rate in bytes/sec, or 0 while inactive (no BtlBw sample yet). The
/// gain is applied to raw BtlBw, then the *final* rate is clamped to both the
/// configured ceiling and the loss-driven cap — so the pacer never emits faster
/// than the last hop can drain, STARTUP overshoot included.
fn pacing_rate_from(bbr: &BbrState) -> u64 {
    if bbr.btlbw_bps == 0 {
        return 0;
    }
    let mut rate = ((bbr.btlbw_bps as f64 * bbr.pacing_gain) as u64).max(1);
    if bbr.max_rate_bps > 0 {
        rate = rate.min(bbr.max_rate_bps);
    }
    if bbr.loss_cap_bps > 0 {
        rate = rate.min(bbr.loss_cap_bps);
    }
    rate
}

/// Additive-increase the loss cap toward BtlBw on a clean (loss-free) round,
/// clearing it once it catches up so the flow returns to full BBR speed. A
/// no-op while the cap is inactive or the round saw loss.
fn relax_loss_cap(bbr: &mut BbrState, had_loss: bool) {
    if bbr.loss_cap_bps == 0 || had_loss {
        return;
    }
    let step = ((bbr.btlbw_bps as f64) * BBR_LOSS_CAP_RECOVER_FRACTION) as u64;
    let raised = bbr.loss_cap_bps.saturating_add(step.max(1));
    // Caught up to BtlBw → drop the cap entirely (uncapped again).
    bbr.loss_cap_bps = if raised >= bbr.btlbw_bps { 0 } else { raised };
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

/// The rate (bytes/sec) the flush is currently pacing this flow at — gain
/// applied to BtlBw, then clamped by the configured ceiling and the loss cap.
/// Exported as a metric; the pacer itself uses the private form.
pub(in crate::tcp) fn pacing_rate(state: &TcpFlowState) -> u64 {
    pacing_rate_from(&state.bbr)
}

/// Record a loss episode (fast-recovery entry or RTO): back the loss-driven
/// bandwidth cap off one multiplicative step, down to a floor. Plain BBR would
/// keep pacing at the burst-inflated BtlBw straight into a lossy last hop; this
/// pulls the effective rate (pacing + in-flight) below it so the drops stop.
/// The cap relaxes back toward BtlBw on subsequent loss-free rounds. No-op for
/// the cap before BBR has a bandwidth estimate (the small initial Reno window
/// bounds the burst until then) — the episode is still counted.
pub(in crate::tcp) fn note_loss(bbr: &mut BbrState) {
    // Counted ahead of the no-estimate bail-out: the counter answers "is the
    // last hop still dropping?", which holds whether or not BBR yet has an
    // estimate for the cap to bite on.
    bbr.loss_episodes = bbr.loss_episodes.saturating_add(1);
    if bbr.btlbw_bps == 0 {
        return;
    }
    let basis = if bbr.loss_cap_bps > 0 {
        bbr.loss_cap_bps
    } else {
        effective_btlbw(bbr)
    };
    let backed_off = ((basis as f64) * BBR_LOSS_CAP_BACKOFF) as u64;
    bbr.loss_cap_bps = backed_off.max(BBR_LOSS_CAP_FLOOR_BPS);
    bbr.loss_in_round = true;
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
        // Canonical BBR skips app-limited rounds here
        // (`bbr_check_full_bw_reached()` bails on `rs->is_app_limited`). Do NOT
        // copy that rule until `RateSample::app_limited` means what it does
        // there. Ours is set from `pending_server_data.is_empty()` after a write
        // (`send/flush.rs`), and this stack drains its queue on nearly every
        // flush — so the flag is set on most segments of a *bandwidth*-limited
        // bulk transfer too. Gating on it therefore never ends STARTUP, which
        // pins pacing and cwnd at the 2.885 STARTUP gain, overruns the last hop,
        // and collapses `loss_cap_bps` onto its floor (reverted: it turned a
        // 5-10 Mbit ceiling into stalled downloads). Fixing this means teaching
        // `app_limited` to mean "the app could not fill the window", not "the
        // queue happens to be empty".
        if bbr.mode == BbrMode::Startup {
            check_startup_full_pipe(bbr);
        }
        // AIMD relax of the loss cap: grow it back toward BtlBw only on a round
        // that saw no loss; a round with loss just clears the flag (the
        // multiplicative back-off already happened in `note_loss`).
        let had_loss = bbr.loss_in_round;
        bbr.loss_in_round = false;
        relax_loss_cap(bbr, had_loss);
    }

    // Delivery-rate sample → BtlBw windowed-max. An app-limited sample (buffer
    // drained, so the rate reflects our supply, not the path) may only raise the
    // estimate, never lower it.
    //
    // The interval runs from `prior_mstamp` — when `delivered` last equalled the
    // sample's `prior_delivered` — so it spans exactly the bytes the numerator
    // counts. Measuring it from the segment's send instant instead divides the
    // whole ACKed flight by the short gap since one recent segment left, and
    // over-estimates BtlBw by the ratio between the two (worst under loss, which
    // pushes the sample onto ever fresher segments).
    //
    // Floored by the flight's send interval: bytes cannot have arrived faster
    // than we managed to put them on the wire. Without that floor, an ACK landing
    // a moment after the previous one divides a whole flight's worth of released
    // bytes by a near-zero gap — the common case in loss recovery, where the
    // sample skips the retransmitted (older) segments and lands on one sent
    // mid-recovery, while the ACK that closes the hole frees everything at once.
    if let Some(sample) = rate_sample {
        let ack_interval = now.saturating_duration_since(sample.prior_mstamp);
        // When the send interval wins that max(), the flight left the stack
        // slower than the path returned it: the quotient below is the rate *we*
        // paced at, not the rate the path can carry. Treat it like an
        // app-limited sample — it may raise BtlBw, never lower it — because
        // feeding it back closes a loop the flow cannot leave: pacing is derived
        // from BtlBw, so BtlBw = pacing = BtlBw pins the flow at whatever rate it
        // happens to be pacing at. One such sample is harmless (the windowed max
        // holds the honest peak), but a paced bulk transfer produces nothing else
        // until the peak ages out of the window, and the estimate then collapses
        // for good: the field gateway sat at BtlBw 0.3 MB/s on a link measured at
        // 300 Mbit, min-RTT correct, no loss, 2.1 MB queued behind a 130 KB
        // client window, emitting sub-MSS segments.
        //
        // A genuinely slower path does not hide here: it stretches the *ACK*
        // interval, which wins the max() instead, so those samples stay honest
        // and BtlBw still tracks a bottleneck downwards.
        let pacing_limited = sample.send_interval > ack_interval;
        let interval = ack_interval.max(sample.send_interval).as_secs_f64();
        if interval > 0.0 {
            let delivered = bbr.delivered.saturating_sub(sample.prior_delivered);
            let rate = (delivered as f64 / interval) as u64;
            if (!sample.app_limited && !pacing_limited) || rate > bbr.btlbw_bps {
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
