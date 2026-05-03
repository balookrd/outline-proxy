//! Public-facing types shared across the uplink crate's modules.
//!
//! Runtime state has been split out by concern:
//! - [`crate::manager::state`] — manager container & active-uplink selection
//! - [`crate::manager::status`] — per-uplink probe/runtime status
//! - [`crate::manager::standby_pool`] — warm-standby connection pool
//! - [`crate::manager::sticky`] — sticky-route entry
//! - [`crate::manager::candidates`] — load-balancing candidate state
//! - [`crate::manager::probe::outcome`] — probe result
//! - [`crate::routing_key`] — routing-key enum
//!
//! What remains here is the minimal set of types referenced from outside
//! the manager module tree (config DTOs, candidate handles, snapshot DTOs).

use std::sync::Arc;

use crate::config::UplinkConfig;

// Re-exports so internal modules can keep importing through `crate::types::*`
// for the central runtime types they routinely touch.
pub use crate::manager::state::UplinkManager;

/// Runtime handle for a configured uplink. Cheap to clone (shared `Arc`).
/// Exists to distinguish a runtime-attached uplink reference from the raw
/// [`UplinkConfig`] DTO at call sites. Field access goes through `Deref`.
#[derive(Clone, Debug)]
pub struct Uplink(Arc<UplinkConfig>);

impl Uplink {
    pub fn new(config: UplinkConfig) -> Self {
        Self(Arc::new(config))
    }
}

impl From<UplinkConfig> for Uplink {
    fn from(config: UplinkConfig) -> Self {
        Self::new(config)
    }
}

impl std::ops::Deref for Uplink {
    type Target = UplinkConfig;
    fn deref(&self) -> &UplinkConfig {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct UplinkCandidate {
    pub index: usize,
    pub uplink: Uplink,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TransportKind {
    Tcp,
    Udp,
}

// Snapshot data types live in the `outline-metrics` crate (they cross the
// producer/consumer boundary between the uplink manager here and the
// prometheus renderer); re-exported so existing `crate::uplink::*Snapshot`
// imports keep working.
pub use outline_metrics::{StickyRouteSnapshot, UplinkManagerSnapshot, UplinkSnapshot};
