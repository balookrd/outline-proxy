use std::time::{Duration, Instant};

use super::super::types::{BbrMode, BbrState, RateSample};
use super::*;

/// `prior_mstamp` is the instant `delivered` last equalled `prior_delivered` —
/// i.e. the last ACK before that segment was sent, not the send instant itself.
fn sample(prior_delivered: u64, prior_mstamp: Instant, app_limited: bool) -> RateSample {
    RateSample {
        prior_delivered,
        prior_mstamp,
        // Default to an instantaneous flight, so the ACK interval governs unless
        // a test sets this explicitly.
        send_interval: Duration::ZERO,
        app_limited,
    }
}

#[test]
fn no_estimate_means_pacing_inactive_and_uncapped() {
    let bbr = BbrState::new(Instant::now(), 0);
    assert_eq!(pacing_rate_from(&bbr), 0, "no sample yet → pacing inactive");
    assert_eq!(inflight_cap_from(&bbr, 1200), usize::MAX, "no sample yet → no BBR cap");
    assert_eq!(bdp_bytes(&bbr), None);
    assert_eq!(bbr.mode, BbrMode::Startup);
}

#[test]
fn delivery_sample_sets_btlbw_min_rtt_and_activates_pacing() {
    let t0 = Instant::now();
    let mut bbr = BbrState::new(t0, 0);
    // 12_000 bytes delivered over a 10 ms interval → 1.2 MB/s.
    let now = t0 + Duration::from_millis(10);
    record_delivery(
        &mut bbr,
        12_000,
        Some(sample(0, t0, false)),
        Some(Duration::from_millis(10)),
        now,
    );

    assert!((bbr.btlbw_bps as i64 - 1_200_000).abs() < 50_000, "btlbw={}", bbr.btlbw_bps);
    assert_eq!(bbr.min_rtt, Duration::from_millis(10));
    // STARTUP gain (>1) paces above the raw bandwidth.
    assert!(pacing_rate_from(&bbr) > bbr.btlbw_bps, "STARTUP should pace above BtlBw");
}

#[test]
fn bdp_and_inflight_cap_track_the_estimates() {
    let t0 = Instant::now();
    let mut bbr = BbrState::new(t0, 0);
    // 1.2 MB/s with a 10 ms min-RTT → BDP ≈ 12_000 bytes.
    record_delivery(
        &mut bbr,
        12_000,
        Some(sample(0, t0, false)),
        Some(Duration::from_millis(10)),
        t0 + Duration::from_millis(10),
    );
    let bdp = bdp_bytes(&bbr).expect("estimate present");
    assert!((bdp as i64 - 12_000).abs() < 1_000, "bdp={bdp}");
    // The in-flight cap is gain×BDP and far below the client's huge rwnd — this
    // is what stops the stack piling a whole segment past a hole.
    let cap = inflight_cap_from(&bbr, 1200);
    assert!(cap >= bdp && cap < 1_000_000, "cap={cap}");
}

#[test]
fn app_limited_sample_only_raises_never_lowers_btlbw() {
    let t0 = Instant::now();
    let mut bbr = BbrState::new(t0, 0);
    let t1 = t0 + Duration::from_millis(10);
    record_delivery(
        &mut bbr,
        100_000,
        Some(sample(0, t0, false)),
        Some(Duration::from_millis(10)),
        t1,
    );
    let high = bbr.btlbw_bps;
    assert!(high > 0);

    // A low, app-limited sample (the buffer drained) must not pull BtlBw down.
    let t2 = t1 + Duration::from_millis(100);
    let round_mark = bbr.next_round_delivered;
    record_delivery(&mut bbr, 1_000, Some(sample(round_mark, t1, true)), None, t2);
    assert_eq!(bbr.btlbw_bps, high, "app-limited low sample lowered BtlBw");
}

/// An ACK 21 ms after the previous one releases 92 KB, so the delivery rate is
/// 92_000 / 0.021 ≈ 4.4 MB/s. Loss turned the flight's oldest segments into
/// retransmits, and only a cleanly-sent segment yields a rate sample, so the
/// sample anchors to a segment sent at t0+20ms — 1 ms before this ACK. Dividing
/// by that 1 ms reads 92 MB/s: 21x the truth, and worst exactly when loss is
/// heaviest and BBR most needs to back off. The interval must therefore run from
/// `prior_mstamp` (t0, the last ACK), which is the instant the numerator counts
/// from.
#[test]
fn delivery_rate_is_measured_from_the_last_ack_not_the_send_instant() {
    let t0 = Instant::now();
    let mut bbr = BbrState::new(t0, 0);

    let now = t0 + Duration::from_millis(21);
    record_delivery(
        &mut bbr,
        92_000,
        Some(sample(0, t0, false)),
        Some(Duration::from_millis(21)),
        now,
    );

    assert!(
        (bbr.btlbw_bps as i64 - 4_380_952).abs() < 100_000,
        "BtlBw should be the honest ~4.4 MB/s, got {} B/s",
        bbr.btlbw_bps
    );
}

/// Loss recovery: the flight's older segments are retransmits, so the sample
/// skips them and anchors to a segment sent *during* recovery, whose last-ACK
/// instant is only 1 ms old. The cumulative ACK that finally closes the hole
/// then releases 60 KB at once — bytes that had been stuck in that hole for the
/// 20 ms the flight took to go out. Dividing 60 KB by the 1 ms ACK interval
/// reads 60 MB/s (≈480 Mbit), which is what the live path reported under load.
///
/// We spent 20 ms sending those bytes, so they cannot have been delivered faster
/// than that. Canonical BBR takes `max(send_interval, ack_interval)` for exactly
/// this reason (`tcp_rate_gen`), giving an honest ~3 MB/s.
#[test]
fn a_short_ack_interval_cannot_outrun_the_time_we_spent_sending() {
    let t0 = Instant::now();
    let mut bbr = BbrState::new(t0, 0);

    let now = t0 + Duration::from_millis(21);
    let last_ack = now - Duration::from_millis(1);
    let mut sample = sample(0, last_ack, false);
    sample.send_interval = Duration::from_millis(20);

    record_delivery(&mut bbr, 60_000, Some(sample), Some(Duration::from_millis(21)), now);

    assert!(
        bbr.btlbw_bps < 6_000_000,
        "BtlBw inflated to {} B/s: the 1 ms ACK gap outran the 20 ms we spent sending",
        bbr.btlbw_bps
    );
}

#[test]
fn windowed_max_holds_btlbw_across_a_dip() {
    let t0 = Instant::now();
    let mut bbr = BbrState::new(t0, 0);
    // Round 1: a high (bandwidth-limited) sample.
    let mut now = t0 + Duration::from_millis(10);
    record_delivery(
        &mut bbr,
        120_000,
        Some(sample(0, t0, false)),
        Some(Duration::from_millis(10)),
        now,
    );
    let high = bbr.btlbw_bps;

    // Round 2: a genuine lower sample. The windowed-max keeps the recent high.
    let sent = now;
    let round_mark = bbr.next_round_delivered;
    now += Duration::from_millis(10);
    record_delivery(&mut bbr, 60_000, Some(sample(round_mark, sent, false)), None, now);
    assert_eq!(bbr.btlbw_bps, high, "windowed-max dropped on a within-window dip");
}

#[test]
fn token_bucket_refills_at_rate_and_caps_the_burst() {
    let t0 = Instant::now();
    let mut bbr = BbrState::new(t0, 0);
    bbr.btlbw_bps = 1_000_000; // 1 MB/s
    bbr.pacing_gain = 1.0;
    let rate = pacing_rate_from(&bbr);
    assert_eq!(rate, 1_000_000);
    let cap = pacing_burst_cap_bytes(1200);

    // 10 ms of refill at 1 MB/s → +10_000 bytes (below the cap).
    refill_credit_at(&mut bbr, rate, cap, t0 + Duration::from_millis(10));
    assert_eq!(bbr.pacing_credit, 10_000);

    // A long idle gap is clamped to the burst ceiling, not unbounded.
    refill_credit_at(&mut bbr, rate, cap, t0 + Duration::from_secs(10));
    assert_eq!(bbr.pacing_credit, cap);
}

#[test]
fn release_at_waits_only_for_the_deficit() {
    let t0 = Instant::now();
    let mut bbr = BbrState::new(t0, 0);
    bbr.pacing_refilled_at = t0;
    bbr.pacing_credit = 500;

    // Need 1500, have 500 → 1000-byte deficit at 1 MB/s = 1 ms.
    assert_eq!(release_at_for(&bbr, 1500, 1_000_000), t0 + Duration::from_millis(1));
    // Enough credit already → release immediately (the last refill instant).
    assert_eq!(release_at_for(&bbr, 400, 1_000_000), t0);
}

#[test]
fn startup_plateau_counts_stalled_rounds_and_resets_on_growth() {
    let mut bbr = BbrState::new(Instant::now(), 0);
    bbr.full_bw = 1_000_000;
    bbr.btlbw_bps = 1_000_000; // no growth (< 1.25×)
    check_startup_full_pipe(&mut bbr);
    assert_eq!(bbr.full_bw_count, 1);

    bbr.btlbw_bps = 2_000_000; // grew ≥ 1.25×
    check_startup_full_pipe(&mut bbr);
    assert_eq!(bbr.full_bw_count, 0);
    assert_eq!(bbr.full_bw, 2_000_000);
}

#[test]
fn probe_rtt_floors_the_inflight_cap() {
    let t0 = Instant::now();
    let mut bbr = BbrState::new(t0, 0);
    record_delivery(
        &mut bbr,
        120_000,
        Some(sample(0, t0, false)),
        Some(Duration::from_millis(10)),
        t0 + Duration::from_millis(10),
    );
    // Normally the cap is the (large) BDP-derived value...
    assert!(inflight_cap_from(&bbr, 1200) > 1200 * BBR_PROBE_RTT_CWND_SEGMENTS);
    // ...but PROBE_RTT pins it to the small floor to drain the pipe.
    bbr.mode = BbrMode::ProbeRtt;
    assert_eq!(inflight_cap_from(&bbr, 1200), 1200 * BBR_MIN_PIPE_CWND_SEGMENTS);
}

#[test]
fn downlink_ceiling_caps_pacing_and_bdp_including_startup_overshoot() {
    let t0 = Instant::now();
    // Ceiling = 1 MB/s (≈8 Mbit). BtlBw over-estimated at 10 MB/s from a
    // line-rate burst, STARTUP gain 2.885 — without the cap this would pace at
    // ~29 MB/s and overrun the port buffer.
    let mut bbr = BbrState::new(t0, 1_000_000);
    bbr.btlbw_bps = 10_000_000;
    bbr.pacing_gain = 2.885;
    bbr.min_rtt = Duration::from_millis(10);
    assert_eq!(pacing_rate_from(&bbr), 1_000_000, "pacing clamped to ceiling");
    // BDP uses the clamped bandwidth: 1 MB/s × 10 ms = 10 KB, not 100 KB.
    let bdp = bdp_bytes(&bbr).expect("estimate present");
    assert!((bdp as i64 - 10_000).abs() < 1_000, "bdp clamped: {bdp}");
}

#[test]
fn zero_ceiling_leaves_bandwidth_uncapped() {
    let t0 = Instant::now();
    let mut bbr = BbrState::new(t0, 0); // 0 = uncapped
    bbr.btlbw_bps = 10_000_000;
    bbr.pacing_gain = 1.0;
    assert_eq!(pacing_rate_from(&bbr), 10_000_000, "no ceiling → raw rate");
}

/// A flow cruising in PROBE_BW — the state a bulk download spends its life in,
/// and the only one where the loss cap may move (STARTUP and the gain-up phase
/// are probes, and a probe must not cap itself).
fn cruising(t0: Instant) -> BbrState {
    let mut bbr = BbrState::new(t0, 0);
    bbr.mode = BbrMode::ProbeBw;
    bbr.pacing_gain = 1.0;
    bbr.cwnd_gain = BBR_CWND_GAIN;
    bbr.min_rtt = Duration::from_millis(2);
    bbr
}

/// Drive one round: `lost` bytes retransmitted, then `delivered` bytes ACKed
/// `ack_interval` after the previous ACK — so the round's delivery rate reads
/// `delivered / ack_interval`.
fn drive_round(
    bbr: &mut BbrState,
    now: &mut Instant,
    delivered: u64,
    lost: usize,
    ack_interval: Duration,
) {
    if lost > 0 {
        note_loss(bbr);
        note_bytes_lost(bbr, lost);
    }
    let prior_delivered = bbr.delivered;
    let prior_mstamp = *now;
    *now += ack_interval;
    record_delivery(
        bbr,
        delivered,
        Some(sample(prior_delivered, prior_mstamp, false)),
        Some(Duration::from_millis(2)),
        *now,
    );
}

/// The field regression this rewrite exists for. A mac on Wi-Fi pulling a file
/// through the gateway: the radio drops a segment now and then, which is a
/// property of the medium, not a queue — every drop is recovered and the link
/// keeps handing back its full ~9 MB/s throughout.
///
/// The predecessor rule counted *episodes*: each of those isolated drops raised
/// 3 dup-ACKs → one fast-recovery entry → one `note_loss` → cap ×= 0.85, from a
/// basis of the cap itself. Five of them across the download compounded to
/// 0.85^5 = 0.44 and pinned a 33 MB/s path at 3.49 MB/s — measured on the box at
/// `bbr_loss_cap_bytes_per_second = 3494119` with `loss_episodes_total = 5`.
///
/// Loss this far under `BBR_LOSS_THRESH` must never reach the cap at all.
#[test]
fn sporadic_loss_on_a_healthy_link_does_not_cap() {
    let t0 = Instant::now();
    let mut bbr = cruising(t0);
    let mut now = t0;

    let round_len = Duration::from_millis(5);
    let per_round = 45_000u64; // 45 KB / 5 ms = 9 MB/s, the link's real rate.

    // 200 rounds ≈ 9 MB, one segment dropped every 40th — the field's five
    // episodes, at the same order of loss rate (~0.07%).
    for i in 0..200 {
        let lost = if i % 40 == 0 { 1_200 } else { 0 };
        drive_round(&mut bbr, &mut now, per_round, lost, round_len);
    }

    assert_eq!(bbr.loss_episodes, 5, "the episodes still happened and are still counted");
    assert_eq!(
        bbr.loss_cap_bps, 0,
        "sporadic radio loss capped a healthy link at {} B/s: the medium drops \
         packets, which is not a congestion signal, and the flow delivered its \
         full {per_round} B every round throughout",
        bbr.loss_cap_bps,
    );
    assert!(
        bbr.btlbw_bps > 8_000_000,
        "BtlBw should still see the ~9 MB/s link, got {}",
        bbr.btlbw_bps
    );
}

/// The clamp, isolated: even at a loss rate well over the threshold, a link that
/// keeps delivering its full rate cannot be capped below that rate.
///
/// This is canonical BBRv2's `max(bw_latest, bw_lo × (1 - beta))` — "we do not
/// cut our short-term estimates lower than the current rate and volume of
/// delivered data from this round trip". It is the difference between "the path
/// is lossy" and "the path is congested", and the old rule had no equivalent:
/// its cap descended on episode count alone, all the way to a 1 Mbit floor, no
/// matter what the link was demonstrably carrying.
#[test]
fn the_bw_latest_floor_stops_the_cap_descending_below_what_the_link_delivers() {
    let t0 = Instant::now();
    let mut bbr = cruising(t0);
    let mut now = t0;

    let round_len = Duration::from_millis(5);
    let per_round = 45_000u64; // Still a full 9 MB/s...
    let lost = 4_500usize; // ...while 10% of the bytes need resending.

    for _ in 0..100 {
        drive_round(&mut bbr, &mut now, per_round, lost, round_len);
    }

    assert!(
        bbr.loss_cap_bps == 0 || bbr.loss_cap_bps >= 8_500_000,
        "cap resolved to {} B/s, below the ~9 MB/s the link kept delivering",
        bbr.loss_cap_bps,
    );
    assert!(
        pacing_rate_from(&bbr) >= 8_500_000,
        "pacing fell to {} B/s on a link still carrying 9 MB/s",
        pacing_rate_from(&bbr),
    );
}

/// The floor must be measured over the same bytes as the loss rate it floors.
///
/// Caught on the live gateway. `bw_latest` was restarted every *round* (as the
/// canon does — there a round is also the loss-measurement interval), while our
/// window spans several rounds because it needs `BBR_LOSS_MIN_SAMPLE_BYTES`
/// before its ratio can be trusted. One short round's best sample does not
/// represent them: the box logged `bw_latest=463531` against `btlbw=3508047` on
/// a flow pulling 3.5 MB/s, so `× 0.85` won the `max()` and the clamp — the
/// entire point of this rewrite — never bound. Every unit test still passed,
/// because they all drove uniform rounds where the two intervals agree.
#[test]
fn the_floor_accumulates_across_the_rounds_the_window_spans() {
    let t0 = Instant::now();
    let mut bbr = cruising(t0);
    let mut now = t0;

    // A round carrying the link's full 9 MB/s...
    drive_round(&mut bbr, &mut now, 45_000, 0, Duration::from_millis(5));
    let after_fast = bbr.bw_latest_bps;
    assert!(after_fast > 8_000_000, "bw_latest={after_fast} after a full-rate round");

    // ...then a nearly idle one. The window is still far short of
    // `BBR_LOSS_MIN_SAMPLE_BYTES`, so it has not closed — and the floor must
    // still remember what the link just carried.
    drive_round(&mut bbr, &mut now, 500, 0, Duration::from_millis(5));
    assert_eq!(
        bbr.bw_latest_bps, after_fast,
        "a round boundary erased the floor mid-window: it now reads {} B/s on a \
         link that delivered {after_fast} B/s inside the very window the loss \
         rate is being read over",
        bbr.bw_latest_bps,
    );
}

/// The clamp, at the level of the rule itself: a cap already pulled low must be
/// lifted back to what the link delivered over the window, not backed off again.
#[test]
fn the_floor_lifts_a_cap_that_sits_below_what_the_link_delivered() {
    let mut bbr = cruising(Instant::now());
    bbr.btlbw_bps = 9_000_000;
    // Where the old episode-counting rule would have driven it.
    bbr.loss_cap_bps = 1_000_000;
    // 7.7% loss — over the threshold — but the link still carried 9 MB/s.
    bbr.lost_in_window = 10_000;
    bbr.delivered_in_window = 120_000;
    bbr.bw_latest_bps = 9_000_000;

    adapt_loss_cap(&mut bbr);

    assert_eq!(
        bbr.loss_cap_bps, 9_000_000,
        "the floor must lift the cap to what the link delivered, not back it off \
         to {}",
        bbr.loss_cap_bps
    );
    assert_eq!(bbr.bw_latest_bps, 0, "the floor restarts with the window it belongs to");
    assert_eq!(bbr.lost_in_window, 0, "the closed window restarts");
}

/// The protection `6b74c03` bought, which must survive this rewrite: a Wi-Fi TV
/// whose last hop is genuinely overrun. Here the drops come *with* collapsing
/// deliveries — the link stops draining what it is offered — so `bw_latest`
/// falls, the floor falls with it, and the cap follows the path down to what it
/// actually carries.
#[test]
fn a_last_hop_that_stops_draining_is_still_capped() {
    let t0 = Instant::now();
    let mut bbr = cruising(t0);
    let mut now = t0;
    let round_len = Duration::from_millis(5);

    // Seed an honest 9 MB/s estimate from a clean stretch.
    for _ in 0..20 {
        drive_round(&mut bbr, &mut now, 45_000, 0, round_len);
    }
    let healthy = bbr.btlbw_bps;
    assert!(healthy > 8_000_000, "seeded btlbw={healthy}");

    // The last hop is now overrun: ~10% of bytes need resending and only 2 MB/s
    // comes back, against the 9 MB/s the windowed-max still claims.
    for _ in 0..100 {
        drive_round(&mut bbr, &mut now, 10_000, 1_000, round_len);
    }

    assert!(bbr.loss_cap_bps > 0, "an overrun last hop must still engage the cap");
    assert!(
        bbr.loss_cap_bps < healthy,
        "cap {} did not pull below the stale {healthy} B/s estimate",
        bbr.loss_cap_bps,
    );
    // The pacer must now offer roughly what the hop drains, not what the
    // windowed-max remembers.
    assert!(
        pacing_rate_from(&bbr) < 4_000_000,
        "pacer still emitting {} B/s into a hop draining 2 MB/s",
        pacing_rate_from(&bbr),
    );
}

/// Loss under the threshold is noise on a radio link and must not move the
/// model, even when the deliveries alongside it are poor.
#[test]
fn loss_below_the_threshold_never_reaches_the_cap() {
    let t0 = Instant::now();
    let mut bbr = cruising(t0);
    let mut now = t0;
    let round_len = Duration::from_millis(5);

    // 1% loss — half the threshold.
    for _ in 0..100 {
        drive_round(&mut bbr, &mut now, 45_000, 450, round_len);
    }
    assert_eq!(bbr.loss_cap_bps, 0, "1% loss is under BBR_LOSS_THRESH and must be ignored");
}

/// Canonical `bbr2_is_probing_bandwidth`. A gain-up phase deliberately offers
/// the path more than the estimate; the loss that provokes is the probe finding
/// the limit, which is its job. Feeding it back as evidence of congestion would
/// make the flow cap itself for probing.
#[test]
fn a_bandwidth_probe_does_not_cap_itself() {
    let t0 = Instant::now();
    let mut bbr = cruising(t0);
    bbr.pacing_gain = BBR_PROBE_BW_GAINS[0]; // 1.25 — probing up.
    let mut now = t0;
    let round_len = Duration::from_millis(5);

    for _ in 0..100 {
        drive_round(&mut bbr, &mut now, 10_000, 1_000, round_len);
    }
    assert_eq!(bbr.loss_cap_bps, 0, "a probe must not back off against its own probing");

    // The same loss outside a probe does engage the cap.
    bbr.pacing_gain = 1.0;
    for _ in 0..100 {
        drive_round(&mut bbr, &mut now, 10_000, 1_000, round_len);
    }
    assert!(bbr.loss_cap_bps > 0, "outside a probe the same loss must cap");
}

/// Canonical `bbr2_reset_lower_bounds`. The cap bounds the pacing rate, so a
/// probe running under one paces at the cap and can never demonstrate anything
/// above it; nothing else raises the cap, so without this release it is a
/// one-way ratchet.
#[test]
fn a_bandwidth_probe_releases_the_cap() {
    let t0 = Instant::now();
    let mut bbr = cruising(t0);
    bbr.btlbw_bps = 10_000_000;
    bbr.loss_cap_bps = 2_000_000;

    enter_probe_bw(&mut bbr, t0);
    assert_eq!(bbr.loss_cap_bps, 0, "entering PROBE_BW must release the cap");
}

/// Releasing the cap for a probe must NOT discard the loss measurement.
///
/// Our PROBE_BW cycle is BBRv1's — 8 phases of min_rtt, so a gain-up phase comes
/// around every ~16 ms on a sub-ms hop, where canonical BBRv2 reaches
/// PROBE_REFILL in seconds. Clearing the window at that cadence would stop it
/// ever reaching `BBR_LOSS_MIN_SAMPLE_BYTES` on a slow link (120 KB is 60 ms at
/// 2 MB/s), so the cap could never engage on precisely the overrun last hop it
/// exists for — silently undoing `6b74c03` while every other test still passed.
#[test]
fn releasing_the_cap_for_a_probe_keeps_the_loss_measurement() {
    let mut bbr = cruising(Instant::now());
    bbr.loss_cap_bps = 2_000_000;
    bbr.lost_in_window = 5_000;
    bbr.delivered_in_window = 40_000;

    release_loss_cap(&mut bbr);
    assert_eq!(bbr.loss_cap_bps, 0, "the probe needs the cap off to climb");
    assert_eq!(bbr.lost_in_window, 5_000, "a probe must not erase what the path did");
    assert_eq!(bbr.delivered_in_window, 40_000);
}

/// The slow-link case the release/reset split exists for, end to end: an overrun
/// 2 MB/s hop, driven through repeated gain-up phases, must still get capped.
#[test]
fn a_slow_overrun_link_still_caps_across_repeated_probes() {
    let t0 = Instant::now();
    let mut bbr = cruising(t0);
    let mut now = t0;
    let round_len = Duration::from_millis(5);

    for _ in 0..20 {
        drive_round(&mut bbr, &mut now, 45_000, 0, round_len);
    }
    // 10% loss on a hop now draining only 2 MB/s, with a gain-up phase every 8th
    // round — the cadence our BBRv1 cycle actually runs at.
    for i in 0..200 {
        if i % 8 == 0 {
            bbr.pacing_gain = BBR_PROBE_BW_GAINS[0];
            release_loss_cap(&mut bbr);
        } else {
            bbr.pacing_gain = 1.0;
        }
        drive_round(&mut bbr, &mut now, 10_000, 1_000, round_len);
    }
    assert!(
        bbr.loss_cap_bps > 0,
        "the measurement never survived to engage the cap across probe phases"
    );
}

#[test]
fn loss_cap_shrinks_the_bdp_and_inflight() {
    let mut bbr = BbrState::new(Instant::now(), 0);
    bbr.btlbw_bps = 10_000_000; // 10 MB/s
    bbr.min_rtt = Duration::from_millis(10);
    let bdp_full = bdp_bytes(&bbr).expect("estimate present");
    bbr.loss_cap_bps = 8_500_000;
    let bdp_capped = bdp_bytes(&bbr).expect("estimate present");
    assert!(
        bdp_capped < bdp_full,
        "loss cap must shrink the BDP: {bdp_capped} vs {bdp_full}"
    );
    // 8.5 MB/s × 10 ms ≈ 85 KB.
    assert!((bdp_capped as i64 - 85_000).abs() < 5_000, "bdp={bdp_capped}");
}

/// The floor is a backstop under the `bw_latest` clamp, not the mechanism: it
/// only binds when the link itself has collapsed to near nothing.
#[test]
fn the_cap_cannot_collapse_below_the_absolute_floor() {
    let t0 = Instant::now();
    let mut bbr = cruising(t0);
    let mut now = t0;
    let round_len = Duration::from_millis(5);

    // Seed an estimate, then drop the link to a trickle with heavy loss.
    for _ in 0..20 {
        drive_round(&mut bbr, &mut now, 45_000, 0, round_len);
    }
    for _ in 0..200 {
        drive_round(&mut bbr, &mut now, 200, 200, round_len);
    }
    assert!(
        bbr.loss_cap_bps >= BBR_LOSS_CAP_FLOOR_BPS,
        "cap {} fell through the floor",
        bbr.loss_cap_bps
    );
}

/// The self-measurement loop that pinned bulk downloads to single-digit Mbit on
/// the live gateway. Once the pacer is slow, the flight takes longer to go out
/// than it takes to be ACKed, so `send_interval` — not the path — governs the
/// interval, and the sample reads back the pacing rate we chose. Feeding that
/// into BtlBw closes the loop: pacing = BtlBw = pacing, and the estimate can
/// never climb back to the real link. Field numbers: btlbw 0.3 MB/s on a link
/// measured at 300 Mbit, min_rtt 1.9 ms (correct), loss_cap 0, pipe 0-2 KB with
/// 2.1 MB queued and a 130 KB client window.
///
/// A sample the send interval floored is our own supply, not the path's
/// capacity — the same reasoning the app-limited gate already encodes — so it
/// may raise BtlBw but never lower it.
#[test]
fn a_pacing_limited_sample_cannot_lower_btlbw() {
    let t0 = Instant::now();
    let mut bbr = BbrState::new(t0, 0);

    // A real, path-limited sample: 120 KB delivered over a 10 ms ACK interval
    // that outran the 1 ms we spent sending it → 12 MB/s.
    let mut honest = sample(0, t0, false);
    honest.send_interval = Duration::from_millis(1);
    let t1 = t0 + Duration::from_millis(10);
    record_delivery(&mut bbr, 120_000, Some(honest), Some(Duration::from_millis(10)), t1);
    let path_bw = bbr.btlbw_bps;
    assert!((path_bw as i64 - 12_000_000).abs() < 1_000_000, "btlbw={path_bw}");

    // Now the pacer is slow: 4800 bytes take 16 ms to leave, while the ACK for
    // them lands 1.9 ms after the previous one. `send_interval` wins the
    // `max()`, so each rate reads 4800/0.016 = 300 KB/s — our pacing rate, not
    // the 12 MB/s path. `pending` stays huge throughout, so `app_limited` is
    // false and the existing gate lets every one of them through.
    //
    // One such sample is harmless (the windowed max still holds the honest
    // peak). A bulk download produces nothing else, round after round, until the
    // peak ages out past `BBR_BW_WINDOW_ROUNDS` — and from then on BtlBw *is*
    // the pacing rate, pacing is derived from BtlBw, and the loop is closed.
    let mut now = t1;
    for _ in 0..(BBR_BW_WINDOW_ROUNDS + 2) {
        let round_mark = bbr.next_round_delivered;
        now += Duration::from_micros(1900);
        let mut paced = sample(round_mark, now - Duration::from_micros(1900), false);
        paced.send_interval = Duration::from_millis(16);
        record_delivery(&mut bbr, 4_800, Some(paced), Some(Duration::from_micros(1900)), now);
    }

    assert_eq!(
        bbr.btlbw_bps, path_bw,
        "pacing-limited samples dragged BtlBw from {path_bw} down to {} B/s: the \
         estimate now reads back the pacer's own rate, so pacing = BtlBw = pacing \
         and the flow can never climb back to the real link",
        bbr.btlbw_bps
    );
}

/// The in-flight cap bounds a flight that is returned over the path's *actual*
/// RTT, but is computed from `min_rtt`. Canonical BBR gets away with that because
/// it assumes srtt ~ min_rtt once the queue drains. A jittery last mile breaks the
/// assumption: the field gateway measured min_rtt 1.876 ms against srtt 5.021 ms
/// (a mac over Wi-Fi; ping min/avg/max 2.3/4.3/9.9 ms, mdev 2.5), a ratio of 2.7
/// against `cwnd_gain = 2.0`.
///
/// Without the quantization budget a cap-bound flight then delivers
/// `2 x btlbw x min_rtt / srtt` = 0.75x the estimate it was computed from, and
/// since the cap comes *from* BtlBw the two ratchet each other down to the
/// in-flight floor — which is where the live flow sat (inflight_cap=4800,
/// pipe=4800, cwnd_rem=0, 2.1 MB queued, client window 167 KB, loss cap
/// inactive). The budget does not scale with BtlBw, so the steady state solves
/// `btlbw = budget / (srtt - gain x min_rtt)` rather than collapsing: the flow
/// climbs back to the link instead of ratcheting away from it.
#[test]
fn the_quantization_budget_keeps_a_jittery_last_mile_from_ratcheting_btlbw_down() {
    let t0 = Instant::now();
    let mut bbr = BbrState::new(t0, 0);
    let mss = 1200usize;
    // Measured on the field gateway.
    let min_rtt = Duration::from_micros(1_876);
    let srtt = Duration::from_micros(5_021);
    // What the link really carries — this download managed ~9 MB/s before the
    // BBR controller existed.
    let link_bps = 9_000_000f64;
    let deliverable_per_round = (link_bps * srtt.as_secs_f64()) as u64;

    // Seed an honest estimate of that link, then enter PROBE_BW: the state the
    // field flow reported (mode=ProbeBw, pacing_gain=1.0, cwnd_gain=2.0). The
    // ratchet only closes here — STARTUP's 2.885 gain clears the 2.7 ratio.
    let mut now = t0 + srtt;
    record_delivery(
        &mut bbr,
        deliverable_per_round,
        Some(sample(0, t0, false)),
        Some(min_rtt),
        now,
    );
    enter_probe_bw(&mut bbr, now);
    let seeded = bbr.btlbw_bps;
    assert!(seeded > 8_000_000, "seeded BtlBw should reflect the real link, got {seeded}");
    assert_eq!(bbr.cwnd_gain, BBR_CWND_GAIN);

    // Long enough for several windowed-max horizons: without the budget each one
    // drops the estimate another 0.75x, which is what took it to the floor.
    for _ in 0..200 {
        let cap = inflight_cap_from(&bbr, mss) as u64;
        let delivered = cap.min(deliverable_per_round);
        let prior_delivered = bbr.delivered;
        let prior_mstamp = now;
        let pacing = pacing_rate_from(&bbr).max(1);
        let send_interval = Duration::from_secs_f64(delivered as f64 / pacing as f64);
        now += srtt;
        let mut rate_sample = sample(prior_delivered, prior_mstamp, false);
        rate_sample.send_interval = send_interval;
        record_delivery(&mut bbr, delivered, Some(rate_sample), Some(min_rtt), now);
    }

    assert!(
        bbr.btlbw_bps > 7_000_000,
        "BtlBw must still see the {link_bps} B/s link, got {} B/s (ratcheted down)",
        bbr.btlbw_bps,
    );
    assert!(
        inflight_cap_from(&bbr, mss) > mss * BBR_MIN_PIPE_CWND_SEGMENTS,
        "the cap must stay off its floor",
    );
}

// --- ACK aggregation -------------------------------------------------------

/// The estimator half of [`on_ack`], in the canonical order, without needing a
/// whole `TcpFlowState`: the clamp is the cap as it stood *before* this ACK.
fn ack(
    bbr: &mut BbrState,
    mss: usize,
    delivered: u64,
    rate_sample: RateSample,
    rtt: Duration,
    now: Instant,
) {
    let round_start = record_delivery(bbr, delivered, Some(rate_sample), Some(rtt), now);
    let cwnd_clamp = inflight_cap_from(bbr, mss);
    update_ack_aggregation(bbr, delivered, round_start, cwnd_clamp, now);
}

/// Measured on the field gateway (a mac over Wi-Fi): min_rtt 1.876 ms against
/// srtt/min_rtt = 2.73.
const FIELD_MIN_RTT: Duration = Duration::from_micros(1_876);

/// The aggregation period those two imply. A packet waits a uniform 0..P for the
/// radio's TXOP, so the mean RTT runs P/2 above the minimum:
/// `srtt = min_rtt + P/2` → `P = 2 × (2.73 − 1) × min_rtt` ≈ 6.49 ms.
const FIELD_AGGREGATION_PERIOD: Duration = Duration::from_micros(6_492);

/// What the link carries — this download managed ~9 MB/s before the BBR
/// controller existed.
const FIELD_LINK_BPS: u64 = 9_000_000;

fn link_per_period() -> u64 {
    (FIELD_LINK_BPS as f64 * FIELD_AGGREGATION_PERIOD.as_secs_f64()) as u64
}

/// A flow on the field's aggregating path, seeded where the field flow sits: in
/// PROBE_BW, cruising, with an estimate well under what the link carries — which
/// is where STARTUP's exit and any transient leave it.
fn field_flow(t0: Instant) -> (BbrState, Instant) {
    let mut bbr = BbrState::new(t0, 0);
    let now = t0 + FIELD_AGGREGATION_PERIOD;
    record_delivery(&mut bbr, 17_000, Some(sample(0, t0, false)), Some(FIELD_MIN_RTT), now);
    enter_probe_bw(&mut bbr, now);
    (bbr, now)
}

/// Deliver one aggregate: the radio hands back everything the pipe holds, capped
/// by what the pacer got onto the wire and by what the link carries in a period.
/// Returns the bytes delivered.
///
/// The whole aggregate lands as one ACK here. On the wire it is a handful of ACKs
/// back-to-back, which reaches the same estimate — the first restarts the epoch,
/// the rest accumulate into it — with more moving parts and no more signal.
fn deliver_aggregate(
    bbr: &mut BbrState,
    mss: usize,
    now: &mut Instant,
    link_per_period: u64,
) -> u64 {
    let period = FIELD_AGGREGATION_PERIOD;
    let cap = inflight_cap_from(bbr, mss) as u64;
    let paced = (pacing_rate_from(bbr) as f64 * period.as_secs_f64()) as u64;
    let delivered = cap.min(paced).min(link_per_period).max(1);

    let prior_delivered = bbr.delivered;
    let prior_mstamp = *now;
    let pacing = pacing_rate_from(bbr).max(1);
    let mut rate_sample = sample(prior_delivered, prior_mstamp, false);
    rate_sample.send_interval = Duration::from_secs_f64(delivered as f64 / pacing as f64);
    *now += period;
    ack(bbr, mss, delivered, rate_sample, FIELD_MIN_RTT, *now);
    delivered
}

/// The field regression. A path that aggregates returns its flight over an RTT
/// well above its minimum, but `inflight_cap` is `cwnd_gain × BtlBw × min_rtt` —
/// derived from a min-RTT the flight never actually runs at. Where the ratio
/// exceeds `BBR_CWND_GAIN` the cap is below what one aggregation period carries,
/// and the flow cannot climb out on its own:
///
/// * cruising at `1.0 × BtlBw` delivers exactly `BtlBw`, which re-seeds the same
///   estimate — a fixed point;
/// * the `1.25` gain phase, the one mechanism that exists to raise BtlBw, paces
///   above the estimate but is bounded by the same cap, so the extra bytes never
///   reach the wire and the probe demonstrates nothing.
///
/// So BtlBw sits wherever it happens to be. The field gateway measured exactly
/// that: BtlBw 3.63 MB/s and `inflight_cap / srtt` 4.89 MB/s on a link the same
/// box pulls 32.99 MB/s through, with the PROBE_BW cycle turning throughout and
/// the loss cap inactive.
///
/// `37f47f91`'s quantization budget is what keeps this from ratcheting to zero,
/// but it is a floor, not a cure: the budget is sized off the pacing rate, and at
/// these rates `bbr_tso_segs_goal` sits on its 2-segment floor, so the budget
/// stops growing and the fixed point is stable. Raising `BBR_CWND_GAIN` is not
/// the answer either (`37f47f91`); measuring the aggregation is.
#[test]
fn ack_aggregation_lets_a_flow_climb_back_to_a_link_its_cap_cannot_see() {
    let mss = 1200usize;
    let (mut bbr, mut now) = field_flow(Instant::now());
    let seeded = bbr.btlbw_bps;
    assert!(seeded < 3_000_000, "seed must start below the link, got {seeded}");
    assert_eq!(bbr.cwnd_gain, BBR_CWND_GAIN);

    // Turn the PROBE_BW cycle for a couple of seconds of link time.
    for i in 0..300 {
        bbr.pacing_gain = BBR_PROBE_BW_GAINS[i % BBR_PROBE_BW_GAINS.len()];
        deliver_aggregate(&mut bbr, mss, &mut now, link_per_period());
    }

    assert!(
        bbr.btlbw_bps > 7_000_000,
        "BtlBw stalled at {} B/s on a {FIELD_LINK_BPS} B/s link: the in-flight cap \
         is derived from min_rtt but bounds a flight the path returns an \
         aggregation period later, so the gain phase cannot put its extra bytes on \
         the wire and the estimate has no way up",
        bbr.btlbw_bps,
    );
}

/// The mechanism, isolated: the head-room must be the size of the aggregate the
/// path hands back, so the pipe stays busy across the silence before the next one.
#[test]
fn the_head_room_matches_the_aggregate_the_path_hands_back() {
    let mss = 1200usize;
    let (mut bbr, mut now) = field_flow(Instant::now());

    let mut last = 0;
    for _ in 0..60 {
        last = deliver_aggregate(&mut bbr, mss, &mut now, link_per_period());
    }

    let head_room = ack_aggregation_cwnd(&bbr) as u64;
    assert!(
        head_room >= last / 2,
        "head-room {head_room} is far under the {last} B aggregate it must cover",
    );
    assert!(
        inflight_cap_from(&bbr, mss) > inflight_for_gain(&bbr, mss, bbr.cwnd_gain),
        "the cap must carry the head-room the aggregation earned",
    );
}

/// The other side, and the guardrail `194fa962` bought: a path that does *not*
/// aggregate must not be handed a queue. Its ACKs arrive steadily at the rate
/// BtlBw predicts, so no epoch ever runs ahead of the estimate and the excess is
/// only ever the one ACK that opened the epoch — a rounding error against the BDP,
/// not head-room. The cap stays the canonical `gain × BDP` + budget, which is
/// what keeps a 100 Mbit port buffer from being overrun.
#[test]
fn a_path_that_does_not_aggregate_earns_no_head_room() {
    let t0 = Instant::now();
    let mut bbr = cruising(t0);
    let mss = 1200usize;
    bbr.min_rtt = FIELD_MIN_RTT;
    let mut now = t0;

    // 9 MB/s delivered in an even drip: an ACK every 200 us carrying 1800 B.
    let ack_gap = Duration::from_micros(200);
    let per_ack = 1_800u64;
    for _ in 0..200 {
        let prior_delivered = bbr.delivered;
        let prior_mstamp = now;
        now += ack_gap;
        ack(
            &mut bbr,
            mss,
            per_ack,
            sample(prior_delivered, prior_mstamp, false),
            FIELD_MIN_RTT,
            now,
        );
    }

    let head_room = ack_aggregation_cwnd(&bbr) as u64;
    assert!(
        head_room <= 2 * per_ack,
        "an evenly-paced path earned {head_room} B of head-room: nothing here \
         bursts, so there is no silence to provision for and the cap must stay at \
         gain x BDP",
    );
}

/// Canonical BBR gates the head-room on `bbr_full_bw_reached()`. STARTUP does not
/// need it — its 2.885 cwnd gain already clears the ratios the field shows — and
/// letting it apply there would widen the very ramp `194fa962` exists to bound.
#[test]
fn startup_takes_no_aggregation_head_room() {
    let t0 = Instant::now();
    let mut bbr = BbrState::new(t0, 0);
    bbr.btlbw_bps = 9_000_000;
    bbr.min_rtt = FIELD_MIN_RTT;
    bbr.extra_acked = [60_000, 60_000];

    assert_eq!(bbr.mode, BbrMode::Startup);
    assert_eq!(ack_aggregation_cwnd(&bbr), 0, "STARTUP must not take the head-room");

    bbr.mode = BbrMode::ProbeBw;
    assert!(ack_aggregation_cwnd(&bbr) > 0, "steady state must take it");
}

/// `2891fb92` retires a gain phase once the pipe holds `gain × BDP` — the level
/// whose delivery the probe exists to provoke. Canonical BBR adds the head-room
/// in `bbr_set_cwnd` only, never in `bbr_inflight`, and the distinction matters
/// here: folding it into the probe's target would leave the probe running — and
/// the queue inflating — for as long as the path keeps bursting.
#[test]
fn the_probe_target_does_not_move_with_the_head_room() {
    let t0 = Instant::now();
    let mut bbr = cruising(t0);
    bbr.btlbw_bps = 9_000_000;
    bbr.min_rtt = FIELD_MIN_RTT;
    let mss = 1200usize;

    let probe_target_before = inflight_for_gain(&bbr, mss, 1.25);
    let cap_before = inflight_cap_from(&bbr, mss);
    bbr.extra_acked = [60_000, 60_000];
    assert_eq!(
        inflight_for_gain(&bbr, mss, 1.25),
        probe_target_before,
        "the probe's in-flight target must not follow the aggregation head-room",
    );
    assert!(
        inflight_cap_from(&bbr, mss) > cap_before,
        "...while the cap itself must: {} did not move off {cap_before}",
        inflight_cap_from(&bbr, mss),
    );
}

/// The head-room is bounded by `BBR_EXTRA_ACKED_MAX_WINDOW` of bandwidth. While
/// BtlBw is still under-estimated every epoch outruns it, so the raw excess has
/// no ceiling of its own — this is what stops the cap running away before the two
/// converge.
#[test]
fn the_head_room_is_bounded_by_a_window_of_bandwidth() {
    let t0 = Instant::now();
    let mut bbr = cruising(t0);
    bbr.btlbw_bps = 1_000_000; // 1 MB/s → 100 ms of it is 100 KB.
    bbr.min_rtt = FIELD_MIN_RTT;
    bbr.extra_acked = [10_000_000, 10_000_000];

    assert_eq!(
        ack_aggregation_cwnd(&bbr),
        100_000,
        "the head-room must be clamped to a window of bandwidth",
    );
}
