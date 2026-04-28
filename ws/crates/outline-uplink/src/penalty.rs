//! EWMA RTT smoothing and exponentially-decaying failure penalty for uplinks.
//!
//! Both quantities live on `PerTransportStatus` and are updated by the probe
//! and runtime-failure paths to bias load-balancing scores away from links
//! that have been recently slow or unreliable.

use std::time::Duration;

use tokio::time::Instant;

use crate::config::LoadBalancingConfig;
use crate::types::PenaltyState;

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

#[cfg(test)]
#[path = "tests/penalty.rs"]
mod tests;
