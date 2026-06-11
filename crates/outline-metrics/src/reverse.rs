//! Reverse-tunnel listener metrics (topology A, ws side).
//!
//! Event-driven gauge: the peer registry republishes the live count whenever
//! a peer is inserted or a dead one is reaped, so the series tracks the pool
//! without a sampler.

use super::METRICS;

/// Publish the number of currently-connected reverse-tunnel peers for `group`.
pub fn set_reverse_peers(group: &str, count: usize) {
    METRICS
        .reverse_peers
        .with_label_values(&[group])
        .set(i64::try_from(count).unwrap_or(i64::MAX));
}
