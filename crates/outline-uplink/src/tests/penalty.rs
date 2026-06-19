use std::time::Duration;

use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::time::Instant;

use super::{
    add_penalty, penalty_weight, update_rtt_ewma, weighted_permutation_with_rng,
    weighted_pick_with_rng,
};
use crate::manager::status::PenaltyState;

#[test]
fn rtt_ewma_smooths_new_samples() {
    let mut current = Some(Duration::from_millis(100));
    update_rtt_ewma(&mut current, Some(Duration::from_millis(300)), 0.25);
    assert_eq!(current, Some(Duration::from_millis(150)));
}

#[test]
fn penalty_weight_is_full_without_penalty() {
    let cfg = crate::tests::lb();
    let now = Instant::now();
    let state = PenaltyState::default();
    let w = penalty_weight(&state, now, &cfg, 0.05);
    assert!((w - 1.0).abs() < 1e-9, "a never-failed candidate scores 1.0, got {w}");
}

#[test]
fn penalty_weight_drops_with_failures_and_respects_floor() {
    let cfg = crate::tests::lb();
    let now = Instant::now();
    let mut state = PenaltyState::default();
    // One failure: weight noticeably below 1.0 but well above the floor.
    add_penalty(&mut state, now, &cfg);
    let w1 = penalty_weight(&state, now, &cfg, 0.05);
    assert!(w1 < 1.0 && w1 > 0.05, "one failure leaves a usable weight: {w1}");
    // Many failures saturate toward `failure_penalty_max`; the weight bottoms
    // out at the floor rather than reaching zero (candidate stays reachable).
    for _ in 0..200 {
        add_penalty(&mut state, now, &cfg);
    }
    let w2 = penalty_weight(&state, now, &cfg, 0.05);
    assert!(w2 >= 0.05, "floor keeps a non-zero chance: {w2}");
    assert!(w2 < w1, "more failures lower the weight: {w2} < {w1}");
}

#[test]
fn penalty_weight_recovers_as_penalty_decays() {
    let cfg = crate::tests::lb();
    let now = Instant::now();
    let mut state = PenaltyState::default();
    add_penalty(&mut state, now, &cfg);
    let w_fresh = penalty_weight(&state, now, &cfg, 0.05);
    // After one half-life the penalty has halved, so the weight has climbed.
    let later = now + cfg.failure_penalty_halflife;
    let w_decayed = penalty_weight(&state, later, &cfg, 0.05);
    assert!(w_decayed > w_fresh, "weight recovers with decay: {w_decayed} > {w_fresh}");
    // Far in the future the penalty is gone and the weight is back to ~1.0.
    let much_later = now + cfg.failure_penalty_halflife * 20;
    let w_recovered = penalty_weight(&state, much_later, &cfg, 0.05);
    assert!(w_recovered > 0.99, "fully recovered after many half-lives: {w_recovered}");
}

#[test]
fn weighted_pick_favours_heavier_weight_but_still_samples_light() {
    let mut rng = StdRng::seed_from_u64(42);
    let weights = [1.0, 0.01];
    let mut hits = [0u32; 2];
    for _ in 0..10_000 {
        let idx = weighted_pick_with_rng(&weights, &mut rng).unwrap();
        hits[idx] += 1;
    }
    assert!(hits[0] > hits[1] * 10, "heavy index dominates: {hits:?}");
    assert!(hits[1] > 0, "light index is still chosen occasionally: {hits:?}");
}

#[test]
fn weighted_pick_none_for_empty_or_zero() {
    let mut rng = StdRng::seed_from_u64(1);
    assert_eq!(weighted_pick_with_rng(&[], &mut rng), None);
    assert_eq!(weighted_pick_with_rng(&[0.0, 0.0], &mut rng), None);
}

#[test]
fn weighted_permutation_contains_every_index() {
    let mut rng = StdRng::seed_from_u64(7);
    let weights = [1.0, 0.001, 0.5, 0.05];
    for _ in 0..100 {
        let perm = weighted_permutation_with_rng(&weights, &mut rng);
        assert_eq!(perm.len(), 4);
        let mut seen = perm.clone();
        seen.sort_unstable();
        assert_eq!(seen, vec![0, 1, 2, 3], "every candidate must remain reachable");
    }
}

#[test]
fn weighted_permutation_usually_leads_with_heavy_index() {
    let mut rng = StdRng::seed_from_u64(123);
    let weights = [1.0, 0.02];
    let trials = 10_000;
    let mut first_is_heavy = 0u32;
    for _ in 0..trials {
        let perm = weighted_permutation_with_rng(&weights, &mut rng);
        if perm[0] == 0 {
            first_is_heavy += 1;
        }
    }
    assert!(
        first_is_heavy > trials * 9 / 10,
        "the healthy index leads in the vast majority of rounds: {first_is_heavy}/{trials}"
    );
}
