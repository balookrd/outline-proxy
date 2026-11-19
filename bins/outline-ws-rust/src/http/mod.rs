//! HTTP listeners owned by the proxy process.
//!
//! Split into two strictly separate planes, each gated by its own feature:
//! - [`metrics`] — read-only Prometheus exposition (`feature = "metrics"`).
//! - [`control`] — mutating endpoints (e.g. manual uplink switch), bound on
//!   a separate socket behind a mandatory bearer token (`feature = "control"`).

#[cfg(feature = "control")]
pub(crate) mod body;
#[cfg(feature = "control")]
pub mod control;
#[cfg(feature = "metrics")]
pub mod metrics;

#[cfg(any(feature = "control", feature = "metrics"))]
pub(crate) mod serve;

/// Secret comparison that does not leak the length or matching prefix through
/// timing. Used by the control plane's mandatory bearer token gate.
#[cfg(feature = "control")]
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let hash_a = blake3::hash(a);
    let hash_b = blake3::hash(b);
    let mut diff: u8 = 0;
    for (x, y) in hash_a.as_bytes().iter().zip(hash_b.as_bytes().iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// Raw-socket test harness for the two planes that read request bodies; a
// metrics-only build has no consumer for it.
#[cfg(all(test, feature = "control"))]
mod tests;
