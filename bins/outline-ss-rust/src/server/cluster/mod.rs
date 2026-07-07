//! Mesh-cluster edge routing.
//!
//! Every session is pinned to a **home** server identified by a shard id
//! embedded in the resumption session id. A server that receives a client
//! carrier (an **edge**) decodes that shard and decides whether it owns the
//! session (handle locally) or must relay it to the home over the mesh.
//!
//! This module currently holds only the pure routing decision. The mesh
//! transport and the relay wiring arrive in later phases; until then a
//! [`RouteDecision::Relay`] is treated as a resume-miss so a foreign-shard
//! resume degrades to a fresh local session. See `docs/CLUSTER.md`.

use std::sync::Arc;
use std::time::Duration;

use outline_wire::cluster::ShardId;

use super::resumption::{ClusterIdentity, SessionId};

use mesh::MeshIdentity;
pub(in crate::server) use mesh::{MeshEndpoint, MeshPeerPool};

/// Process-wide cluster runtime: the mesh endpoint (shared by the listener
/// accept-loop and the peer pool) and the relay progress budget. Built at
/// startup when `[cluster]` is configured; `None` otherwise.
pub(in crate::server) struct ClusterCtx {
    /// Serves the home listener and dials edge relays.
    pub(in crate::server) endpoint: MeshEndpoint,
    /// Connections to peer homes, keyed by shard.
    pub(in crate::server) pool: Arc<MeshPeerPool>,
    /// Per-uplink-write stall budget for the edge relay (health budget).
    pub(in crate::server) relay_budget: Duration,
}

/// Cap on concurrent relay streams this server dials out (bounded resources).
const MESH_MAX_RELAY_STREAMS: usize = 4096;

impl ClusterCtx {
    /// Builds the cluster runtime from resolved config: derives the mesh
    /// identity from the PSK, binds the mesh endpoint and constructs the peer
    /// pool. Fails fast (aborting startup) on a bad identity or listen bind.
    pub(in crate::server) fn build(
        cfg: &crate::config::ClusterConfig,
    ) -> anyhow::Result<Arc<Self>> {
        let identity = MeshIdentity::derive(cfg.psk.as_bytes())?;
        let endpoint = MeshEndpoint::bind(cfg.mesh_listen, &identity)?;
        let pool = Arc::new(MeshPeerPool::new(
            endpoint.clone(),
            cfg.peers.clone(),
            MESH_MAX_RELAY_STREAMS,
        ));
        Ok(Arc::new(Self {
            endpoint,
            pool,
            relay_budget: cfg.mesh_relay_budget,
        }))
    }
}

// The mesh transport is wired into both the home listener and the edge relay,
// but a few items (the health-budget close codes / progress plumbing) stay dead
// until phase 6, so keep the module-level allow. `pub(in crate::server)` so the
// transport-side carrier adapter can reach `MeshStream`.
#[allow(dead_code)]
pub(in crate::server) mod mesh;

/// Where a freshly accepted carrier's session should be served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum RouteDecision {
    /// This server owns the session (or there is nothing to route): handle it
    /// locally, exactly as a non-clustered server would.
    Local,
    /// The session belongs to another home shard and must be relayed there.
    Relay(ShardId),
}

/// Decides how to route an accepted carrier from the resume id it presented.
///
/// - No cluster identity (not clustered) → always [`RouteDecision::Local`].
/// - No resume id (a first connect) → [`RouteDecision::Local`]: this edge
///   becomes the home and mints a session id carrying its own shard.
/// - A resume id decoding to our own shard → [`RouteDecision::Local`].
/// - A resume id decoding to a foreign shard → [`RouteDecision::Relay`].
///
/// Total and side-effect-free: a forged id simply decodes to some shard, which
/// either matches (local, then resume-misses in the registry) or relays.
pub(in crate::server) fn decide(
    identity: Option<&ClusterIdentity>,
    resume_id: Option<SessionId>,
) -> RouteDecision {
    let (Some(identity), Some(id)) = (identity, resume_id) else {
        return RouteDecision::Local;
    };
    let shard = id.shard(&identity.key);
    if shard == identity.shard {
        RouteDecision::Local
    } else {
        RouteDecision::Relay(shard)
    }
}

#[cfg(test)]
#[path = "tests/routing.rs"]
mod tests;
