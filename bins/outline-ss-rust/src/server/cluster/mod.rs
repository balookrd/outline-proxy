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

use outline_wire::cluster::ShardId;

use super::resumption::{ClusterIdentity, SessionId};

// The mesh transport is built out but not yet wired into the runtime (that
// happens in phase 4c/5), so its items are dead in a non-test build until then.
#[allow(dead_code)]
mod mesh;

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
