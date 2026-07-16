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
    BBR_BW_WINDOW_ROUNDS, BBR_CWND_GAIN, BBR_DRAIN_GAIN, BBR_EXTRA_ACKED_MAX_WINDOW,
    BBR_EXTRA_ACKED_WIN_ROUNDS, BBR_LOSS_CAP_BACKOFF, BBR_LOSS_CAP_FLOOR_BPS,
    BBR_LOSS_MIN_SAMPLE_BYTES, BBR_LOSS_THRESH, BBR_MIN_PIPE_CWND_SEGMENTS, BBR_MIN_RTT_WINDOW,
    BBR_PACING_MAX_BURST_SEGMENTS, BBR_PROBE_BW_GAINS, BBR_PROBE_RTT_CWND_SEGMENTS,
    BBR_PROBE_RTT_DURATION, BBR_STARTUP_FULL_BW_COUNT, BBR_STARTUP_GAIN, BBR_STARTUP_GROWTH_TARGET,
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
/// uncapped) and to the loss-driven soft cap (`loss_cap_bps`, 0 = inactive) —
/// canonical BBRv2's `bbr_bw() = min(max_bw, bw_lo)`. Governs the BDP and the
/// pacing rate alike, so a last hop that cannot drain what the windowed-max
/// claims still gets offered only what it does drain.
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

/// `gain x BDP` plus `head_room`, budget included; `usize::MAX` until an
/// estimate exists. The head-room is folded in *before* the quantization budget,
/// as canonical BBR does in `bbr_set_cwnd`.
fn inflight_for_gain_with_head_room(
    bbr: &BbrState,
    mss: usize,
    gain: f64,
    head_room: usize,
) -> usize {
    let floor = mss * BBR_MIN_PIPE_CWND_SEGMENTS;
    match bdp_bytes(bbr) {
        Some(bdp) => {
            let target = ((bdp as f64 * gain) as usize).saturating_add(head_room);
            quantization_budget(bbr, mss, target).max(floor)
        },
        None => usize::MAX,
    }
}

/// In-flight the pipe would hold at `gain x BDP`, budget included — canonical
/// BBR's `bbr_inflight(sk, bw, gain)`. `usize::MAX` until an estimate exists.
///
/// Deliberately *without* the ACK-aggregation head-room, which canonical BBR
/// adds in `bbr_set_cwnd` alone: this value is what a PROBE_BW gain phase is
/// retired against (`bbr_is_next_cycle_phase`, `2891fb92`). A probe ends when the
/// pipe holds the `gain x BDP` whose delivery it exists to provoke; requiring it
/// to also hold the head-room would leave the probe running — and the queue
/// inflating — for as long as the path keeps bursting.
fn inflight_for_gain(bbr: &BbrState, mss: usize, gain: f64) -> usize {
    inflight_for_gain_with_head_room(bbr, mss, gain, 0)
}

/// Windowed max of the aggregation estimate — canonical `bbr_extra_acked()`.
fn extra_acked(bbr: &BbrState) -> u64 {
    bbr.extra_acked[0].max(bbr.extra_acked[1])
}

/// Head-room the in-flight cap gets for ACK aggregation — canonical BBR's
/// `bbr_ack_aggregation_cwnd()`.
///
/// Canonical BBR applies `bbr_extra_acked_gain` (`BBR_UNIT`, i.e. 1.0) here; a
/// multiplication by one is left out rather than reproduced as a constant.
fn ack_aggregation_cwnd(bbr: &BbrState) -> usize {
    // Canonical BBR gates this on `bbr_full_bw_reached()`. STARTUP is the only
    // mode we can be in before the pipe has filled — nothing re-enters it — and
    // it does not need the head-room anyway: its 2.885 cwnd gain already clears
    // the srtt/min_rtt ratios the field shows, which is why the collapse this
    // measures only ever closed in PROBE_BW, at `BBR_CWND_GAIN`.
    if bbr.mode == BbrMode::Startup {
        return 0;
    }
    let ceiling = (effective_btlbw(bbr) as f64 * BBR_EXTRA_ACKED_MAX_WINDOW.as_secs_f64()) as u64;
    extra_acked(bbr).min(ceiling) as usize
}

/// In-flight cap (bytes), given the flow's MSS — canonical BBR's `bbr_set_cwnd`
/// target: `gain x BDP` + aggregation head-room + quantization budget.
/// `usize::MAX` until an estimate exists, so the Reno initial window governs the
/// first flight; floored at a few MSS so a sub-ms RTT still admits enough
/// packets to keep ACKs clocking.
fn inflight_cap_from(bbr: &BbrState, mss: usize) -> usize {
    if bbr.mode == BbrMode::ProbeRtt {
        return mss * BBR_MIN_PIPE_CWND_SEGMENTS;
    }
    inflight_for_gain_with_head_room(bbr, mss, bbr.cwnd_gain, ack_aggregation_cwnd(bbr))
}

/// Fold one ACK into the ACK-aggregation estimate — canonical BBR's
/// `bbr_update_ack_aggregation()`.
///
/// `extra_acked` is how much more arrived over an epoch than `BtlBw × epoch`
/// predicted. An epoch only ever spans a stretch running *ahead* of the estimate:
/// the moment deliveries fall back to what BtlBw predicts, the aggregate has been
/// paid out and a fresh epoch starts at that ACK. So a silence between aggregates
/// does not register as aggregation by itself — what registers is the burst that
/// ends it, and its size is exactly the in-flight the pipe needs to stay busy
/// across the next silence.
///
/// `cwnd_clamp` is canonical BBR's `min(extra_acked, tcp_snd_cwnd(tp))`: the
/// excess cannot exceed what was allowed in flight to begin with. Passing the cap
/// in force *before* this ACK (rather than the Reno window, which this stack
/// inflates to the client's rwnd within milliseconds) keeps that bound meaningful
/// and makes the head-room climb one cap-doubling per epoch instead of jumping
/// straight to `BBR_EXTRA_ACKED_MAX_WINDOW` of bandwidth.
///
/// Canonical BBR also resets the epoch once `ack_epoch_acked` reaches
/// `bbr_ack_epoch_acked_reset_thresh` (`1 << 20`). That is the overflow bound of
/// its `ack_epoch_acked:20` bit-field (clamped at `0xFFFFF`), not a property of
/// the algorithm; our counter is a `u64`, so the reset has nothing to protect and
/// is left out.
fn update_ack_aggregation(
    bbr: &mut BbrState,
    bytes_delivered: u64,
    round_start: bool,
    cwnd_clamp: usize,
    now: Instant,
) {
    if bytes_delivered == 0 {
        return;
    }

    // Retire the current slot every `BBR_EXTRA_ACKED_WIN_ROUNDS` rounds, so the
    // max over the two spans 5-10 round trips rather than the whole flow.
    if round_start {
        bbr.extra_acked_win_rounds = bbr.extra_acked_win_rounds.saturating_add(1);
        if bbr.extra_acked_win_rounds >= BBR_EXTRA_ACKED_WIN_ROUNDS {
            bbr.extra_acked_win_rounds = 0;
            bbr.extra_acked_win_idx ^= 1;
            bbr.extra_acked[bbr.extra_acked_win_idx] = 0;
        }
    }

    let epoch = now.saturating_duration_since(bbr.ack_epoch_stamp).as_secs_f64();
    let mut expected = (effective_btlbw(bbr) as f64 * epoch) as u64;
    if bbr.ack_epoch_acked <= expected {
        bbr.ack_epoch_acked = 0;
        bbr.ack_epoch_stamp = now;
        expected = 0;
    }

    bbr.ack_epoch_acked = bbr.ack_epoch_acked.saturating_add(bytes_delivered);
    let excess = bbr
        .ack_epoch_acked
        .saturating_sub(expected)
        .min(u64::try_from(cwnd_clamp).unwrap_or(u64::MAX));
    let slot = &mut bbr.extra_acked[bbr.extra_acked_win_idx];
    *slot = (*slot).max(excess);
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

/// Whether the flow is deliberately sending above its estimate right now —
/// canonical BBRv2's `bbr2_is_probing_bandwidth`. STARTUP ramps at 2.885 and the
/// PROBE_BW gain-up phase lifts in-flight to `1.25 × BDP`; loss provoked *by* a
/// probe is the probe locating the limit, which is what it is for, so it must
/// not be fed back as evidence that the path is congested.
fn is_probing_bandwidth(bbr: &BbrState) -> bool {
    bbr.mode == BbrMode::Startup || (bbr.mode == BbrMode::ProbeBw && bbr.pacing_gain > 1.0)
}

/// Release the cap, leaving the in-progress loss measurement intact.
///
/// The cap bounds the pacing rate, so a probe running under one paces at the cap
/// and cannot demonstrate anything above it — BtlBw would never learn the path
/// recovered, and the cap would be a one-way ratchet. Releasing it is canonical
/// BBRv2's `bbr2_reset_lower_bounds` on PROBE_REFILL.
///
/// The measurement window deliberately survives: our PROBE_BW cycle is BBRv1's
/// (8 phases × min_rtt ≈ 16 ms on this hop), where canonical PROBE_REFILL comes
/// around in *seconds*. Clearing the window on that cadence would keep it from
/// ever reaching `BBR_LOSS_MIN_SAMPLE_BYTES` on a slow link — 120 KB takes 60 ms
/// at 2 MB/s — so the cap could never engage on exactly the overrun last hop it
/// exists to protect (`6b74c03`). Loss is a property of the path, not of our
/// phase, so its measurement spans phases.
fn release_loss_cap(bbr: &mut BbrState) {
    bbr.loss_cap_bps = 0;
}

/// Release the cap *and* discard the in-progress measurement — for a transition
/// into steady state, where what was measured during STARTUP's 2.885 ramp or a
/// drain says nothing about the path at cruise.
fn reset_loss_cap(bbr: &mut BbrState) {
    release_loss_cap(bbr);
    bbr.lost_in_window = 0;
    bbr.delivered_in_window = 0;
    bbr.bw_latest_bps = 0;
}

/// Adapt the loss cap once per round — canonical BBRv2's
/// `bbr2_adapt_lower_bounds`, which maintains `bw_lo` as
/// `max(bw_latest, bw_lo × (1 - beta))`.
///
/// The predecessor of this function backed the cap off `×0.85` inside
/// `note_loss`, i.e. once per *loss episode*, from a basis of the cap itself and
/// with no reference to any measured quantity. That cannot distinguish the two
/// paths this stack actually serves, because it never asks how much was lost:
///
/// - A radio last mile drops sporadically. One dropped segment raises 3 dup-ACKs
///   → one recovery entry → one `note_loss` → −15%, whether it happened among 30
///   segments or 30_000. The field gateway logged 5 episodes across a ~100 MB
///   download — a loss rate near 0.007% — and the cap sat at 0.85^5 = 0.44 of the
///   link, pinning a 33 MB/s path at 3.49 MB/s.
/// - A Wi-Fi TV client whose last hop is genuinely overrun drops ~10%, and the
///   cap collapsing is the controller working (`6b74c03`).
///
/// Three orders of magnitude apart, identical input: `+1`. So the rate — not the
/// event count — is the signal, and `bw_latest` is the floor:
///
/// - **Gate** on a loss rate over `BBR_LOSS_THRESH` measured across a window of
///   at least `BBR_LOSS_MIN_SAMPLE_BYTES`, so sporadic loss never reaches the
///   model at all.
/// - **Floor** the result at `bw_latest_bps`, the rate this link delivered in the
///   round just ended. A link handing back 9 MB/s cannot be capped below 9 MB/s
///   no matter what the arithmetic proposes; a link whose deliveries have fallen
///   drags its own floor down, and the cap follows. This is the clamp that makes
///   "lossy" and "congested" separable, and it is what the old rule lacked —
///   which is why its cap could park at 1 Mbit on a healthy 300 Mbit path.
/// - **Skip** while probing (see [`is_probing_bandwidth`]).
///
/// There is deliberately no additive relax step (the old `btlbw/32` per clean
/// round, an order of magnitude weaker than the `×0.85` it had to undo — the
/// asymmetry the field report opened with). Canonical BBR has no such step
/// either: the cap is released wholesale by [`reset_loss_cap`] when the next
/// probe starts, and re-derived from measurement if loss is still there.
fn adapt_loss_cap(bbr: &mut BbrState) {
    // No bandwidth estimate yet → nothing to cap against; the small initial Reno
    // window bounds the burst until the first sample lands.
    if bbr.btlbw_bps == 0 {
        return;
    }
    // A probe is deliberately overshooting: hold the cap still until it ends.
    // The window keeps accumulating across the probe rather than being discarded
    // — see `release_loss_cap` for why it must span phases — and the `bw_latest`
    // floor keeps the drops a probe provokes from being read as a slow path,
    // since a probe's own deliveries are what set that floor.
    if is_probing_bandwidth(bbr) {
        return;
    }
    let window = bbr.lost_in_window.saturating_add(bbr.delivered_in_window);
    // Too few bytes to read a rate off: carry the counters into the next round
    // rather than acting on noise.
    if window < BBR_LOSS_MIN_SAMPLE_BYTES {
        return;
    }
    let loss_rate = bbr.lost_in_window as f64 / window as f64;
    let bw_latest = bbr.bw_latest_bps;
    // The window closed: restart all three together. Loss, deliveries and the
    // floor they are judged against must span the same bytes — a floor measured
    // over a shorter stretch than the loss rate is not a floor under it. (Taking
    // `bw_latest` over one round while the window spans several read 463 KB/s on
    // a link the same flow was pulling 3.5 MB/s through, which let `× 0.85` win
    // the `max()` and the clamp never bound.)
    bbr.lost_in_window = 0;
    bbr.delivered_in_window = 0;
    bbr.bw_latest_bps = 0;
    if loss_rate <= BBR_LOSS_THRESH {
        return;
    }
    // No delivery-rate sample in the window → no floor to stand on. Backing off
    // against an unknown link is how the old rule reached its floor; decline.
    if bw_latest == 0 {
        return;
    }
    let basis = if bbr.loss_cap_bps > 0 {
        bbr.loss_cap_bps
    } else {
        effective_btlbw(bbr)
    };
    let backed_off = ((basis as f64) * BBR_LOSS_CAP_BACKOFF) as u64;
    bbr.loss_cap_bps = backed_off.max(bw_latest).max(BBR_LOSS_CAP_FLOOR_BPS);
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

/// Record a loss *episode* (fast-recovery entry or RTO).
///
/// This no longer touches the loss cap. An episode says loss happened, not how
/// much — and "how much" is the whole question on a radio last mile, where a
/// single sporadic drop raises an episode indistinguishable from the one a
/// genuinely overrun buffer raises. The cap is driven by the measured loss rate
/// in [`adapt_loss_cap`] instead; what an episode still does is mark the round,
/// which cuts a PROBE_BW gain phase short (a small-buffered path may not hold
/// `gain × BDP` at all), and feed the exported counter.
pub(in crate::tcp) fn note_loss(bbr: &mut BbrState) {
    bbr.loss_episodes = bbr.loss_episodes.saturating_add(1);
    bbr.loss_in_round = true;
}

/// Add `bytes` to the current loss-measurement window — the numerator of the
/// loss rate [`adapt_loss_cap`] gates on.
///
/// Called from the two retransmission paths, so "lost" here means "we put these
/// bytes back on the wire", the same proxy Linux's `tp->lost` uses. It
/// over-counts a spurious retransmit; at the ~2% threshold that noise is far
/// below the signal.
pub(in crate::tcp) fn note_bytes_lost(bbr: &mut BbrState, bytes: usize) {
    bbr.lost_in_window = bbr.lost_in_window.saturating_add(bytes as u64);
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
    // Canonical `bbr2_reset_lower_bounds` runs on PROBE_RTT exit, which reaches
    // steady state through here — and a cap chosen before a drain/probe-RTT says
    // nothing about the path afterwards.
    reset_loss_cap(bbr);
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
///
/// Returns whether this ACK started a new round — canonical BBR's
/// `bbr->round_start`, which [`update_ack_aggregation`] ages its window on.
fn record_delivery(
    bbr: &mut BbrState,
    bytes_delivered: u64,
    rate_sample: Option<RateSample>,
    rtt_sample: Option<Duration>,
    now: Instant,
) -> bool {
    bbr.delivered = bbr.delivered.saturating_add(bytes_delivered);
    bbr.delivered_at = now;
    bbr.delivered_in_window = bbr.delivered_in_window.saturating_add(bytes_delivered);

    // Round bookkeeping: a round elapses when this ACK covers a segment sent
    // at/after the start of the current round.
    let round_start = rate_sample.is_some_and(|s| s.prior_delivered >= bbr.next_round_delivered);
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
        // Adapt the loss cap against the loss rate and the delivery rate of the
        // measurement window, which `adapt_loss_cap` restarts once it closes one
        // (`bw_latest` included — it is that window's floor, so it lives on the
        // window's clock, not the round's).
        adapt_loss_cap(bbr);
        bbr.loss_in_round = false;
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
            // `bw_latest` takes every sample, ungated — canonical BBR does the
            // same. It answers "what came back over this round", which is what
            // the loss cap needs a floor from; the max() over the round keeps one
            // low app-limited sample from lowering that floor.
            bbr.bw_latest_bps = bbr.bw_latest_bps.max(rate);
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

    round_start
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
            // Canonical `bbr_is_next_cycle_phase`. A gain phase is not a fixed
            // slice of wall clock, because what a phase is *for* differs:
            //
            // - gain > 1 probes for bandwidth by lifting in-flight to
            //   `gain x BDP`. That takes at least one RTT of ACKs to
            //   materialise, and canonical BBR says so outright: "this may take
            //   more than min_rtt if min_rtt is small (e.g. on a LAN)". Retiring
            //   the probe on the min-RTT timer alone ends it before the ACKs it
            //   provoked come back — the sample then lands in the *next* phase
            //   and is divided by that phase's interval, so the extra bandwidth
            //   the probe just demonstrated never reaches BtlBw. On a path whose
            //   ACKs return slower than its own minimum the 1.25 gain then
            //   raises the estimate exactly never, and BtlBw sits whereever it
            //   happens to be — which is what pinned a Wi-Fi client on the field
            //   gateway at 3.57 MB/s of a 33 MB/s link (min_rtt 1.98 ms against
            //   srtt 4.8 ms, pipe 90% empty, cycle spinning through all eight
            //   phases with the estimate frozen). Loss cuts the probe short: a
            //   path with small buffers may not hold `gain x BDP` at all.
            // - gain < 1 drains the queue the probe built, so it ends as soon as
            //   in-flight is back at a BDP — persisting would starve the pipe.
            // - gain == 1 is cruise: wall clock is exactly right.
            //
            // A path where srtt ~ min_rtt (the gateway's own loopback-ish
            // clients, a wired LAN) is unaffected either way: there the pipe
            // reaches `gain x BDP` within the timer anyway.
            let phase_len = state.bbr.min_rtt.max(Duration::from_millis(1));
            let is_full_length = now.saturating_duration_since(state.bbr.cycle_stamp) >= phase_len;
            let gain = state.bbr.pacing_gain;
            let mss = server_max_segment_payload(state);
            let pipe = bytes_in_pipe(state);
            let advance = if gain > 1.0 {
                is_full_length
                    && (state.bbr.loss_in_round || pipe >= inflight_for_gain(&state.bbr, mss, gain))
            } else if gain < 1.0 {
                is_full_length || bdp_bytes(&state.bbr).is_some_and(|bdp| pipe <= bdp)
            } else {
                is_full_length
            };
            if advance {
                state.bbr.probe_bw_phase =
                    (state.bbr.probe_bw_phase + 1) % BBR_PROBE_BW_GAINS.len();
                state.bbr.pacing_gain = BBR_PROBE_BW_GAINS[state.bbr.probe_bw_phase];
                state.bbr.cycle_stamp = now;
                // Entering the gain-up phase: release the cap, as canonical BBRv2
                // does on PROBE_REFILL. A probe that paces at the level a previous
                // episode chose cannot discover that the path recovered, and since
                // nothing else raises the cap, it would never lift again.
                if state.bbr.pacing_gain > 1.0 {
                    release_loss_cap(&mut state.bbr);
                }
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
    let round_start =
        record_delivery(&mut state.bbr, bytes_delivered, rate_sample, rtt_sample, now);
    // Canonical `bbr_update_model` order: aggregation is folded in after the
    // bandwidth this ACK just updated (its epoch is measured against BtlBw) and
    // before the cycle phase. The clamp is the cap as it stood *before* this
    // ACK, so it is read off the previous `extra_acked` rather than the one
    // being computed.
    let cwnd_clamp = inflight_cap(state);
    update_ack_aggregation(&mut state.bbr, bytes_delivered, round_start, cwnd_clamp, now);
    update_mode(state, now);
}

#[cfg(test)]
#[path = "tests/bbr.rs"]
mod tests;
