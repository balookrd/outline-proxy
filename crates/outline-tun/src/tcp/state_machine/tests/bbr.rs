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
