//! EWMA RTT smoothing and exponentially-decaying failure penalty for uplinks.
//!
//! Both quantities live on `PerTransportStatus` and are updated by the probe
//! and runtime-failure paths to bias load-balancing scores away from links
//! that have been recently slow or unreliable.

use std::time::Duration;

use rand::Rng;
use tokio::time::Instant;

use crate::config::LoadBalancingConfig;
use crate::manager::status::PenaltyState;

pub(crate) fn update_rtt_ewma(
    current: &mut Option<Duration>,
    sample: Option<Duration>,
    alpha: f64,
) {
    let Some(sample) = sample else {
        return;
    };
    *current = Some(match *current {
        Some(existing) => Duration::from_secs_f64(
            existing.as_secs_f64() * (1.0 - alpha) + sample.as_secs_f64() * alpha,
        ),
        None => sample,
    });
}

pub(crate) fn current_penalty(
    state: &PenaltyState,
    now: Instant,
    config: &LoadBalancingConfig,
) -> Option<Duration> {
    let updated_at = state.updated_at?;
    if state.value_secs <= 0.0 {
        return None;
    }
    let elapsed = now.saturating_duration_since(updated_at).as_secs_f64();
    let halflife = config.failure_penalty_halflife.as_secs_f64().max(1.0);
    let value_secs = state.value_secs * 0.5_f64.powf(elapsed / halflife);
    if value_secs < 0.001 {
        None
    } else {
        Some(Duration::from_secs_f64(
            value_secs.min(config.failure_penalty_max.as_secs_f64()),
        ))
    }
}

pub(crate) fn add_penalty(state: &mut PenaltyState, now: Instant, config: &LoadBalancingConfig) {
    let current = current_penalty(state, now, config).unwrap_or_default().as_secs_f64();
    let next = (current + config.failure_penalty.as_secs_f64())
        .min(config.failure_penalty_max.as_secs_f64());
    state.value_secs = next;
    state.updated_at = Some(now);
}

/// Convert a decaying liveness penalty into a selection weight in `(0, 1]`,
/// clamped below by `floor`.
///
/// `weight = 1 / (1 + penalty_secs / scale)`, where `scale` is the
/// `failure_penalty` knob — one fresh failure's worth of penalty pulls the
/// weight to half. A candidate with no penalty (never failed, or fully
/// recovered) scores `1.0`; a candidate that keeps disconnecting decays toward
/// `floor` but never reaches `0`, so weighted selection still picks it
/// occasionally and the penalty's own `0.5^(t/halflife)` decay restores the
/// weight over time. This is the shared math behind both the per-wire and the
/// carrier-family rankings.
pub(crate) fn penalty_weight(
    state: &PenaltyState,
    now: Instant,
    config: &LoadBalancingConfig,
    floor: f64,
) -> f64 {
    let floor = floor.clamp(0.0, 1.0);
    let penalty = current_penalty(state, now, config)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    // Guard against a zero `failure_penalty` (operator disabled penalties):
    // with `scale == 0` the ratio would be NaN/Inf. A zero penalty already
    // yields weight 1.0 regardless, so the floor on `scale` is purely defensive.
    let scale = config.failure_penalty.as_secs_f64().max(0.001);
    let weight = 1.0 / (1.0 + penalty / scale);
    weight.max(floor)
}

/// Pick one index from `weights` with probability proportional to each weight.
/// Returns `None` only when `weights` is empty or no entry has positive,
/// finite weight. Generic over the RNG so callers pass `rand::rng()` in
/// production and a seeded `StdRng` in tests for reproducibility.
pub(crate) fn weighted_pick_with_rng<R: Rng + ?Sized>(
    weights: &[f64],
    rng: &mut R,
) -> Option<usize> {
    // Sum of finite, strictly-positive weights — so `total` is itself finite
    // and non-negative; an empty / all-zero input sums to `0.0`.
    let total: f64 = weights.iter().filter(|w| w.is_finite() && **w > 0.0).sum();
    if total <= 0.0 {
        return None;
    }
    let mut threshold = rng.random::<f64>() * total;
    for (i, &w) in weights.iter().enumerate() {
        if !(w.is_finite() && w > 0.0) {
            continue;
        }
        threshold -= w;
        if threshold < 0.0 {
            return Some(i);
        }
    }
    // Floating-point slack can leave `threshold` marginally positive after the
    // loop; fall back to the last positive-weight index.
    weights.iter().rposition(|w| w.is_finite() && *w > 0.0)
}

/// Return a permutation of `0..weights.len()` ordered by weighted-random
/// priority (Efraimidis–Spirakis sampling without replacement): each index
/// draws key `u^(1/w)` for a fresh uniform `u ∈ (0, 1]`, and indices are sorted
/// by descending key. Higher-weight indices are statistically first, but any
/// index can land anywhere — and crucially **every** index is present, so a
/// caller using the result as a dial order still reaches every candidate (the
/// fallback cascade never drops a wire). Indices with non-positive / non-finite
/// weight rank last (key `0`), preserving their original relative order.
pub(crate) fn weighted_permutation_with_rng<R: Rng + ?Sized>(
    weights: &[f64],
    rng: &mut R,
) -> Vec<usize> {
    let mut keyed: Vec<(usize, f64)> = weights
        .iter()
        .enumerate()
        .map(|(i, &w)| {
            let key = if w.is_finite() && w > 0.0 {
                // `1 - random()` lands in `(0, 1]`, so `powf` never sees `u == 0`.
                let u = 1.0 - rng.random::<f64>();
                u.powf(1.0 / w)
            } else {
                0.0
            };
            (i, key)
        })
        .collect();
    // Stable descending sort: equal keys (and the zero-weight tail) keep their
    // original order, matching the legacy cyclic order for all-equal weights.
    keyed.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    keyed.into_iter().map(|(i, _)| i).collect()
}

#[cfg(test)]
#[path = "tests/penalty.rs"]
mod tests;
