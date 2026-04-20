//! HTTP listeners owned by the proxy process.
//!
//! Split into two strictly separate planes:
//! - [`metrics`] — read-only Prometheus exposition.
//! - [`control`] — mutating endpoints (e.g. manual uplink switch), gated by
//!   a mandatory bearer token and bound on a separate socket.

pub mod control;
pub mod metrics;
