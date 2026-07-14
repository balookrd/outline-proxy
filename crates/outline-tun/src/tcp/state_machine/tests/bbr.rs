use std::time::{Duration, Instant};

use super::super::types::{BbrMode, BbrState, RateSample};
use super::*;

/// `prior_mstamp` is the instant `delivered` last equalled `prior_delivered` —
/// i.e. the last ACK before that segment was sent, not the send instant itself.
fn sample(prior_delivered: u64, prior_mstamp: Instant, app_limited: bool) -> RateSample {
    RateSample {
        prior_delivered,
        prior_mstamp,
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

#[test]
fn loss_backs_off_pacing_cap_and_relaxes_on_clean_rounds() {
    let mut bbr = BbrState::new(Instant::now(), 0);
    bbr.btlbw_bps = 10_000_000;
    bbr.pacing_gain = 1.0;
    assert_eq!(pacing_rate_from(&bbr), 10_000_000, "no loss → full BtlBw");

    // One loss episode backs the effective rate off ~15%.
    note_loss(&mut bbr);
    assert_eq!(bbr.loss_cap_bps, 8_500_000);
    assert_eq!(pacing_rate_from(&bbr), 8_500_000, "pacing follows the loss cap");

    // A second episode compounds the back-off.
    note_loss(&mut bbr);
    assert_eq!(bbr.loss_cap_bps, 7_225_000);

    // Loss-free rounds relax the cap back up; it catches BtlBw and clears,
    // restoring full speed once the last hop stops dropping.
    for _ in 0..200 {
        relax_loss_cap(&mut bbr, false);
        if bbr.loss_cap_bps == 0 {
            break;
        }
    }
    assert_eq!(bbr.loss_cap_bps, 0, "clean rounds restore full speed");
    assert_eq!(pacing_rate_from(&bbr), 10_000_000);
}

#[test]
fn loss_cap_is_floored_and_holds_on_a_lossy_round() {
    let mut bbr = BbrState::new(Instant::now(), 0);
    bbr.btlbw_bps = 200_000; // ~1.6 Mbit, close to the floor
    bbr.pacing_gain = 1.0;
    for _ in 0..20 {
        note_loss(&mut bbr);
    }
    assert_eq!(
        bbr.loss_cap_bps, BBR_LOSS_CAP_FLOOR_BPS,
        "back-off cannot collapse below the floor"
    );

    // A round that saw loss must not grow the cap (the flag gates the relax).
    let before = bbr.loss_cap_bps;
    relax_loss_cap(&mut bbr, true);
    assert_eq!(bbr.loss_cap_bps, before, "lossy round must not relax the cap");
}

#[test]
fn loss_cap_shrinks_the_bdp_and_inflight() {
    let mut bbr = BbrState::new(Instant::now(), 0);
    bbr.btlbw_bps = 10_000_000; // 10 MB/s
    bbr.min_rtt = Duration::from_millis(10);
    let bdp_full = bdp_bytes(&bbr).expect("estimate present");
    note_loss(&mut bbr); // cap → 8.5 MB/s
    let bdp_capped = bdp_bytes(&bbr).expect("estimate present");
    assert!(
        bdp_capped < bdp_full,
        "loss cap must shrink the BDP: {bdp_capped} vs {bdp_full}"
    );
    // 8.5 MB/s × 10 ms ≈ 85 KB.
    assert!((bdp_capped as i64 - 85_000).abs() < 5_000, "bdp={bdp_capped}");
}
