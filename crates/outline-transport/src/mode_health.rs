//! Liveness-weighted carrier-family selection shared by the WS and XHTTP
//! per-host mode caches.
//!
//! The legacy caches ([`crate::ws_mode_cache`] / [`crate::xhttp_mode_cache`])
//! enforce a binary per-host downgrade *cap*: once a higher carrier (H3) fails,
//! every dial is clamped to a lower one (H2/H1) for a TTL. This module adds the
//! opt-in (default-on in production via [`crate::init_health_weighting`])
//! weighted alternative: each rank of a family carries a decaying penalty, and
//! the starting rank is chosen probabilistically so a carrier that disconnects
//! often is preferred *less* — but still retried occasionally and fully
//! restored once its penalty decays.
//!
//! `outline-transport` does not depend on `outline-uplink`, so the
//! `0.5^(t/halflife)` penalty math from `outline_uplink::penalty` is duplicated
//! here in a small, self-contained form rather than shared as a dependency.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use rand::Rng;

/// One rank's decaying liveness penalty. Mirrors
/// `outline_uplink::manager::status::PenaltyState` but on `std::time::Instant`
/// (the caches are not on the tokio clock) and with the math inlined.
#[derive(Clone, Copy, Default, Debug)]
pub(crate) struct ModePenalty {
    value_secs: f64,
    updated_at: Option<Instant>,
}

impl ModePenalty {
    /// Penalty in seconds at `now`, after `0.5^(elapsed/halflife)` decay and the
    /// `max_penalty` cap. Returns `0.0` once it has decayed below `0.001 s`.
    fn current(&self, now: Instant, params: &WeightingParams) -> f64 {
        let Some(updated) = self.updated_at else {
            return 0.0;
        };
        if self.value_secs <= 0.0 {
            return 0.0;
        }
        let elapsed = now.saturating_duration_since(updated).as_secs_f64();
        let halflife = params.halflife.as_secs_f64().max(1.0);
        let value = self.value_secs * 0.5_f64.powf(elapsed / halflife);
        if value < 0.001 {
            0.0
        } else {
            value.min(params.max_penalty.as_secs_f64())
        }
    }

    /// Add one failure's worth of penalty (`scale`), capped at `max_penalty`.
    pub(crate) fn add(&mut self, now: Instant, params: &WeightingParams) {
        let current = self.current(now, params);
        self.value_secs =
            (current + params.scale.as_secs_f64()).min(params.max_penalty.as_secs_f64());
        self.updated_at = Some(now);
    }

    /// Clear the penalty outright (a proven success on this rank).
    pub(crate) fn reset(&mut self) {
        self.value_secs = 0.0;
        self.updated_at = None;
    }

    /// Selection weight in `(0, 1]`, clamped below by `floor`. `1.0` with no
    /// penalty; decays toward `floor` as failures accrue. Same shape as
    /// `outline_uplink::penalty::penalty_weight`.
    fn weight(&self, now: Instant, params: &WeightingParams) -> f64 {
        let penalty = self.current(now, params);
        let scale = params.scale.as_secs_f64().max(0.001);
        (1.0 / (1.0 + penalty / scale)).max(params.floor.clamp(0.0, 1.0))
    }
}

/// Process-wide weighting configuration. Set once at startup from the client
/// config via [`crate::init_health_weighting`]; the caches read it on every
/// dial through [`weighting`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct WeightingParams {
    pub(crate) enabled: bool,
    pub(crate) floor: f64,
    pub(crate) halflife: Duration,
    /// Penalty added per failure and the divisor in the weight curve (one fresh
    /// failure pulls the weight to ~half). Mirrors `failure_penalty`.
    pub(crate) scale: Duration,
    pub(crate) max_penalty: Duration,
}

/// Default when [`init_health_weighting`] is never called: **disabled**, so the
/// legacy binary-cap path runs. Production turns it on through bootstrap; the
/// disabled default keeps unrelated tests and any binary that forgets to wire
/// it on the legacy behaviour.
const DEFAULT: WeightingParams = WeightingParams {
    enabled: false,
    floor: 0.05,
    halflife: Duration::from_secs(60),
    scale: Duration::from_millis(500),
    max_penalty: Duration::from_secs(30),
};

static WEIGHTING: OnceLock<WeightingParams> = OnceLock::new();

/// Current weighting params (the [`DEFAULT`] until startup sets them).
pub(crate) fn weighting() -> WeightingParams {
    WEIGHTING.get().copied().unwrap_or(DEFAULT)
}

/// Initialise the weighting config. First call wins; later calls are ignored
/// (mirrors [`crate::ws_mode_cache::init_downgrade_ttl`]). `floor` is clamped to
/// `[0, 1]`.
pub(crate) fn init(enabled: bool, floor: f64, halflife: Duration, scale: Duration) {
    let _ = WEIGHTING.set(WeightingParams {
        enabled,
        floor: floor.clamp(0.0, 1.0),
        halflife,
        scale,
        max_penalty: DEFAULT.max_penalty,
    });
}

/// Choose a starting rank by descending from `top_rank` toward `0`, keeping each
/// rank with probability equal to its liveness weight; rank `0` (the most
/// conservative carrier) is always accepted as the last resort.
///
/// With no penalties every weight is `1.0`, so `top_rank` is chosen — preserving
/// the "prefer the highest carrier" default. A rank that fails often has a low
/// weight and is usually skipped to the next lower one, but the non-zero floor
/// keeps a small retry probability, and the penalty's decay restores the rank
/// over time. The physical fallback cascade in `dial_plan` still runs from the
/// chosen rank, so this only changes *where the cascade starts*, never whether
/// a working carrier is reached.
pub(crate) fn descend_start_rank<R: Rng + ?Sized>(
    top_rank: u8,
    penalties: &[ModePenalty],
    now: Instant,
    params: &WeightingParams,
    rng: &mut R,
) -> u8 {
    let mut chosen = 0u8;
    for rank in (0..=top_rank).rev() {
        let weight = penalties.get(rank as usize).map_or(1.0, |p| p.weight(now, params));
        if rank == 0 || rng.random::<f64>() < weight {
            chosen = rank;
            break;
        }
    }
    chosen
}

#[cfg(test)]
#[path = "tests/mode_health.rs"]
mod tests;
