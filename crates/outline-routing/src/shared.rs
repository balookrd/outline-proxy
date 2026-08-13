//! Hot-swappable holder for a [`RoutingTable`].
//!
//! The table's per-rule CIDR/domain sets are already hot-reloadable in place
//! (see [`crate::table::spawn_route_watchers`]), but the *shape* of the table
//! — how many rules, their order, their targets — is fixed at compile time.
//! Applying edited `[[route]]` config therefore means compiling a whole new
//! table and swapping the pointer. Both the SOCKS dispatcher and the TUN
//! engine hold an `Arc<SharedRoutingTable>`, so one `store` is seen by both at
//! once — unlike the pre-swap design where each held an independent
//! `Arc<RoutingTable>` clone that could not be replaced from outside.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use arc_swap::ArcSwap;
use socks5_proto::TargetAddr;

use crate::table::{RouteDecision, RoutingTable};

#[derive(Debug)]
pub struct SharedRoutingTable {
    current: ArcSwap<RoutingTable>,
}

impl SharedRoutingTable {
    pub fn new(table: RoutingTable) -> Arc<Self> {
        Arc::new(Self { current: ArcSwap::from_pointee(table) })
    }

    /// Cheap read guard for the resolve path — no lock, no await.
    pub fn load(&self) -> arc_swap::Guard<Arc<RoutingTable>> {
        self.current.load()
    }

    /// Full `Arc` clone, needed to seed [`crate::table::spawn_route_watchers`]
    /// (which takes an owned `Arc<RoutingTable>`).
    pub fn load_full(&self) -> Arc<RoutingTable> {
        self.current.load_full()
    }

    pub fn version(&self) -> u64 {
        self.current.load().version()
    }

    /// Publish `new` as the live table, continuing the `version` counter from
    /// the outgoing table instead of letting a freshly-compiled table's `0`
    /// shadow a higher live version — which would make per-association caches
    /// tagged with the old (higher) version look "current" and skip
    /// re-resolution. The version is stamped BEFORE the store so no reader can
    /// observe the new table at its temporary `0`.
    pub fn swap_preserving_version(&self, new: RoutingTable) -> Arc<RoutingTable> {
        let next = self.current.load().version() + 1;
        new.version.store(next, Ordering::Release);
        let arc = Arc::new(new);
        self.current.store(Arc::clone(&arc));
        arc
    }

    pub fn resolve(&self, target: &TargetAddr) -> RouteDecision {
        self.current.load().resolve(target)
    }

    pub fn resolve_versioned(&self, target: &TargetAddr) -> (RouteDecision, u64) {
        self.current.load().resolve_versioned(target)
    }
}

#[cfg(test)]
#[path = "tests/shared.rs"]
mod tests;
