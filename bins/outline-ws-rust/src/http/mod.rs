//! HTTP listeners owned by the proxy process.
//!
//! Split into two strictly separate planes, each gated by its own feature:
//! - [`metrics`] — read-only Prometheus exposition (`feature = "metrics"`).
//! - [`control`] — mutating endpoints (e.g. manual uplink switch), bound on
//!   a separate socket behind a mandatory bearer token (`feature = "control"`).

#[cfg(feature = "control")]
pub mod control;
#[cfg(feature = "dashboard")]
pub mod dashboard;
#[cfg(feature = "metrics")]
pub mod metrics;

#[cfg(any(feature = "control", feature = "dashboard", feature = "metrics"))]
pub(crate) mod serve;
