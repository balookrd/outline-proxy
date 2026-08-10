//! Time-aware RTT EWMA for one wire.
//!
//! Split out of [`crate::penalty`] because the smoothed value on its own was
//! not enough: nothing in the old `update_rtt_ewma` looked at the clock, so a
//! sample taken while a carrier was broken stayed in its slot indefinitely.
//! That is not a hypothetical — a slot nothing refreshes is exactly the state a
//! stuck uplink is in: bad score → the balancer sends it no traffic → no new
//! measurement lands in the slot → the score stays bad. The age of a
//! measurement is therefore part of the measurement, and this type carries the
//! two together.
//!
//! Mirrors [`crate::loss::LossEwma`] deliberately: numbers only, `Copy`, and
//! an absent value that means "not measured" rather than "measured and fine".

use std::time::Duration;

use tokio::time::Instant;

/// Multiples of the half-life past which a slot stops counting as measured at
/// all. `0.5^4` is ~6%: below that the stale value contributes less than the
/// spread between two ordinary samples, and keeping it alive would only
/// preserve the illusion that this wire has been observed recently.
pub(crate) const EXPIRY_HALFLIVES: u32 = 4;

/// One wire's smoothed connect latency, together with the instant it last
/// moved.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RttEwma {
    value: Option<Duration>,
    updated_at: Option<Instant>,
}

impl RttEwma {
    /// A slot seeded with an already-known measurement, for tests that need a
    /// specific value at a specific age. The ordinary way a slot acquires a
    /// value is [`Self::record`].
    #[cfg(any(test, feature = "test-helpers"))]
    pub(crate) fn measured(value: Duration, at: Instant) -> Self {
        Self { value: Some(value), updated_at: Some(at) }
    }

    /// The smoothed value as measured, with no age adjustment. This is what
    /// "what did we actually observe on this wire" means, and it is what the
    /// snapshot publishes — the decay applies to *ranking*, not to the
    /// measurement itself.
    pub(crate) fn value(&self) -> Option<Duration> {
        self.value
    }

    /// How long ago this slot last moved. `None` when it has never been
    /// measured.
    pub(crate) fn age(&self, now: Instant) -> Option<Duration> {
        Some(now.saturating_duration_since(self.updated_at?))
    }

    /// Fold a fresh sample in and stamp the clock.
    ///
    /// A `None` sample is a no-op *including the timestamp*: "no measurement
    /// was taken" must not be recorded as "the existing measurement is fresh",
    /// which would defeat the whole point of tracking age. This preserves the
    /// previous `update_rtt_ewma` contract for the value itself.
    pub(crate) fn record(&mut self, sample: Option<Duration>, alpha: f64, now: Instant) {
        let Some(sample) = sample else {
            return;
        };
        self.value = Some(match self.value {
            Some(existing) => Duration::from_secs_f64(
                existing.as_secs_f64() * (1.0 - alpha) + sample.as_secs_f64() * alpha,
            ),
            None => sample,
        });
        self.updated_at = Some(now);
    }

    /// How much weight this slot still carries in ranking, in `[0, 1]`:
    /// `0.5^(age / halflife)`, and exactly `0.0` once the age reaches
    /// [`EXPIRY_HALFLIVES`] half-lives.
    ///
    /// Two escape hatches both return the full `1.0`, for opposite reasons:
    ///
    /// * `halflife == 0` is the documented off switch
    ///   ([`crate::config::LoadBalancingConfig::rtt_ewma_halflife`]) — decay
    ///   ships disable-able, and with it off the ranking arithmetic collapses
    ///   to exactly what it was before this type existed.
    /// * a value with no timestamp is a slot populated by something that did
    ///   not go through [`Self::record`]. Treating an unstamped value as
    ///   maximally stale would silently discard a real measurement, so the
    ///   conservative reading is "assume fresh" — the sampling paths all stamp,
    ///   so this is defence in depth rather than a live case.
    ///
    /// An unmeasured slot scores `0.0`: there is nothing to weight.
    pub(crate) fn confidence(&self, halflife: Duration, now: Instant) -> f64 {
        if self.value.is_none() {
            return 0.0;
        }
        if halflife.is_zero() {
            return 1.0;
        }
        let Some(updated_at) = self.updated_at else {
            return 1.0;
        };
        let age = now.saturating_duration_since(updated_at);
        if age >= halflife.saturating_mul(EXPIRY_HALFLIVES) {
            return 0.0;
        }
        0.5_f64.powf(age.as_secs_f64() / halflife.as_secs_f64())
    }

    /// The measured value, but only while the slot still carries any weight at
    /// all — i.e. `None` once it has fully expired.
    ///
    /// This is what the snapshot's active-wire EWMA field reads, and the
    /// distinction it draws is load-bearing: `None` there has always meant "no
    /// measurement exists for this wire", and a slot nobody has refreshed for
    /// [`EXPIRY_HALFLIVES`] half-lives genuinely no longer constitutes one. It
    /// stays distinct from the ranked latency the same snapshot publishes,
    /// which keeps falling back down the chain and therefore stays `Some`.
    pub(crate) fn value_if_unexpired(&self, halflife: Duration, now: Instant) -> Option<Duration> {
        (self.confidence(halflife, now) > 0.0).then_some(self.value).flatten()
    }
}

#[cfg(test)]
#[path = "tests/rtt.rs"]
mod tests;
