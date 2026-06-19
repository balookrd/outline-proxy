//! Liveness-weighted carrier-family start-rank selection.
//!
//! Exercises the pure decision core ([`descend_start_rank`]) and the penalty
//! math directly with a seeded RNG, so the behaviour is deterministic and
//! independent of the process-global weighting flag (which the WS / XHTTP cache
//! wrappers read). The legacy binary-cap path is covered by the existing
//! `xhttp_mode_cache` / `dial_plan` tests.

use std::time::Duration;
use std::time::Instant;

use rand::SeedableRng;
use rand::rngs::StdRng;

use super::{ModePenalty, WeightingParams, descend_start_rank};

fn params(floor: f64) -> WeightingParams {
    WeightingParams {
        enabled: true,
        floor,
        halflife: Duration::from_secs(60),
        scale: Duration::from_millis(500),
        max_penalty: Duration::from_secs(30),
    }
}

fn penalise(slot: &mut ModePenalty, now: Instant, p: &WeightingParams, times: usize) {
    for _ in 0..times {
        slot.add(now, p);
    }
}

#[test]
fn no_penalty_always_starts_at_top() {
    let p = params(0.05);
    let now = Instant::now();
    let penalties = [ModePenalty::default(); 3];
    let mut rng = StdRng::seed_from_u64(1);
    for _ in 0..1_000 {
        // With every weight at 1.0 the descend keeps the top rank immediately —
        // preserving the "prefer the highest carrier" default.
        assert_eq!(descend_start_rank(2, &penalties, now, &p, &mut rng), 2);
    }
}

#[test]
fn flaky_top_rank_is_usually_skipped_but_floor_keeps_it() {
    let p = params(0.05);
    let now = Instant::now();
    let mut penalties = [ModePenalty::default(); 3];
    penalise(&mut penalties[2], now, &p, 60); // H3 disconnects constantly
    let mut rng = StdRng::seed_from_u64(2);
    let trials = 5_000;
    let mut chose_h3 = 0;
    for _ in 0..trials {
        if descend_start_rank(2, &penalties, now, &p, &mut rng) == 2 {
            chose_h3 += 1;
        }
    }
    assert!(chose_h3 > 0, "the floor keeps H3 reachable: {chose_h3}/{trials}");
    assert!(chose_h3 < trials / 3, "H3 is usually skipped to H2: {chose_h3}/{trials}");
}

#[test]
fn both_high_ranks_flaky_fall_to_h1() {
    let p = params(0.05);
    let now = Instant::now();
    let mut penalties = [ModePenalty::default(); 3];
    penalise(&mut penalties[1], now, &p, 60);
    penalise(&mut penalties[2], now, &p, 60);
    let mut rng = StdRng::seed_from_u64(3);
    let trials = 5_000;
    let mut chose_h1 = 0;
    for _ in 0..trials {
        if descend_start_rank(2, &penalties, now, &p, &mut rng) == 0 {
            chose_h1 += 1;
        }
    }
    // P(skip H3) * P(skip H2) ≈ 0.95 * 0.95 ≈ 0.9.
    assert!(
        chose_h1 > trials * 3 / 4,
        "both high ranks broken → mostly H1: {chose_h1}/{trials}"
    );
}

#[test]
fn penalty_decays_and_top_is_preferred_again() {
    let p = params(0.05);
    let now = Instant::now();
    let mut penalties = [ModePenalty::default(); 3];
    penalise(&mut penalties[2], now, &p, 60);
    // Many half-lives later the H3 penalty has effectively vanished.
    let later = now + Duration::from_secs(60 * 20);
    let mut rng = StdRng::seed_from_u64(4);
    let trials = 1_000;
    let mut chose_h3 = 0;
    for _ in 0..trials {
        if descend_start_rank(2, &penalties, later, &p, &mut rng) == 2 {
            chose_h3 += 1;
        }
    }
    assert!(
        chose_h3 > trials * 9 / 10,
        "after decay H3 is preferred again: {chose_h3}/{trials}"
    );
}

#[test]
fn weight_is_full_without_penalty_and_drops_then_recovers() {
    let p = params(0.05);
    let now = Instant::now();
    let mut mp = ModePenalty::default();
    assert!((mp.weight(now, &p) - 1.0).abs() < 1e-9, "no penalty → weight 1.0");
    mp.add(now, &p);
    let w1 = mp.weight(now, &p);
    assert!(w1 < 1.0 && w1 > 0.05, "one failure: {w1}");
    let later = now + Duration::from_secs(600);
    assert!(mp.weight(later, &p) > w1, "weight recovers as the penalty decays");
}

#[test]
fn weight_never_drops_below_floor() {
    let p = params(0.2);
    let now = Instant::now();
    let mut mp = ModePenalty::default();
    penalise(&mut mp, now, &p, 200);
    assert!(mp.weight(now, &p) >= 0.2, "weight is clamped at the floor");
}

#[test]
fn requested_h2_never_starts_at_h3() {
    // When the operator only asks for H2 (top_rank = 1), the descend can never
    // pick H3 (rank 2) even with H2 penalised — the ceiling is respected.
    let p = params(0.05);
    let now = Instant::now();
    let mut penalties = [ModePenalty::default(); 3];
    penalise(&mut penalties[1], now, &p, 60);
    let mut rng = StdRng::seed_from_u64(5);
    for _ in 0..2_000 {
        let chosen = descend_start_rank(1, &penalties, now, &p, &mut rng);
        assert!(chosen <= 1, "must not exceed the requested ceiling: {chosen}");
    }
}
