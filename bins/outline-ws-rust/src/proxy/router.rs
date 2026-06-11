//! Routing abstraction consumed by the proxy layer.
//!
//! `ProxyConfig` holds an `Arc<dyn Router>` instead of the concrete
//! [`outline_routing::RoutingTable`] so the proxy module depends only on the
//! *behaviour* it needs (resolve a target, check table version). This keeps
//! the eventual extraction of `src/proxy/` into its own crate clean — the
//! proxy crate will depend on this trait, not on `outline-routing`.
//!
//! The concrete [`RoutingTable`] impl lives here (main crate owns the trait,
//! so the orphan rule permits it).
use async_trait::async_trait;
use outline_routing::{RouteDecision, RoutingTable};
use socks5_proto::TargetAddr;

/// Minimal surface the proxy layer needs from a routing backend.
///
/// Kept intentionally small so alternative implementations (tests, a future
/// richer policy engine) do not have to reproduce the whole
/// `RoutingTable` API.
#[async_trait]
pub trait Router: Send + Sync + std::fmt::Debug {
    /// Current table version — bumped by reload watchers. Per-association
    /// caches tag entries with the version captured at resolve time and
    /// re-resolve on mismatch.
    fn version(&self) -> u64;

    /// Resolve a target and return the version snapshot captured *before*
    /// CIDR reads (see [`RoutingTable::resolve_versioned`] for the ordering
    /// rationale).
    async fn resolve_versioned(&self, target: &TargetAddr) -> (RouteDecision, u64);

    /// Resolve without a version snapshot. Default impl delegates to
    /// [`Router::resolve_versioned`].
    async fn resolve(&self, target: &TargetAddr) -> RouteDecision {
        self.resolve_versioned(target).await.0
    }
}

#[async_trait]
impl Router for RoutingTable {
    fn version(&self) -> u64 {
        RoutingTable::version(self)
    }

    async fn resolve_versioned(&self, target: &TargetAddr) -> (RouteDecision, u64) {
        RoutingTable::resolve_versioned(self, target).await
    }

    async fn resolve(&self, target: &TargetAddr) -> RouteDecision {
        RoutingTable::resolve(self, target).await
    }
}
