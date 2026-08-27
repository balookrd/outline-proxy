//! Turns the startup endpoint list + the global user pools into the six
//! `RouteRegistry` maps. One place, shared by startup (`services::build`) and
//! live user mutation (`control::manager::rebuild_snapshots`).
//!
//! Because users work on every endpoint of their kind, the pool for an SS
//! endpoint is *all* SS users and for a VLESS endpoint *all* VLESS users —
//! independent of the path. The pooling that `build_transport_route_map` used
//! to do per-path (`grouped.entry(path).push(user)`) collapses to "clone the
//! whole pool into each route"; only `peer_user_cache` is fresh per route.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::config::{CipherKind, EndpointConfig, EndpointKind, UserEntry};
use crate::crypto::UserKey;
use crate::protocol::vless::VlessUser;

use super::constants::TCP_PEER_USER_CACHE_CAPACITY;
use super::peer_user_cache::PeerUserCache;
use super::state::{RouteRegistry, TransportRoute, VlessTransportRoute};

/// Shared SS pool + candidate labels, cloned into each SS route.
pub(super) fn ss_user_pool(users: &[UserKey]) -> (Arc<[UserKey]>, Arc<[Arc<str>]>) {
    let candidates: Vec<Arc<str>> = users.iter().map(|u| u.log_label()).collect();
    (
        Arc::from(users.to_vec().into_boxed_slice()),
        Arc::from(candidates.into_boxed_slice()),
    )
}

/// Shared VLESS pool + candidate labels.
pub(super) fn vless_user_pool(users: &[VlessUser]) -> (Arc<[VlessUser]>, Arc<[Arc<str>]>) {
    let candidates: Vec<Arc<str>> = users.iter().map(|u| u.label_arc()).collect();
    (
        Arc::from(users.to_vec().into_boxed_slice()),
        Arc::from(candidates.into_boxed_slice()),
    )
}

fn ss_route(pool: &Arc<[UserKey]>, candidates: &Arc<[Arc<str>]>) -> Arc<TransportRoute> {
    Arc::new(TransportRoute {
        users: Arc::clone(pool),
        candidate_users: Arc::clone(candidates),
        peer_user_cache: Arc::new(PeerUserCache::with_capacity(TCP_PEER_USER_CACHE_CAPACITY)),
    })
}

fn vless_route(pool: &Arc<[VlessUser]>, candidates: &Arc<[Arc<str>]>) -> Arc<VlessTransportRoute> {
    Arc::new(VlessTransportRoute {
        users: Arc::clone(pool),
        candidate_users: Arc::clone(candidates),
    })
}

/// Build the six route maps from the endpoint list and the global pools.
pub(super) fn build_route_registry(
    endpoints: &[EndpointConfig],
    ss_users: &[UserKey],
    vless_users: &[VlessUser],
) -> RouteRegistry {
    let (ss_pool, ss_candidates) = ss_user_pool(ss_users);
    let (vless_pool, vless_candidates) = vless_user_pool(vless_users);

    let mut tcp = BTreeMap::new();
    let mut udp = BTreeMap::new();
    let mut vless = BTreeMap::new();
    let mut xhttp_vless = BTreeMap::new();
    let mut xhttp_ss = BTreeMap::new();
    let mut xhttp_ss_udp = BTreeMap::new();

    for ep in endpoints {
        let p = ep.path.clone();
        match ep.kind {
            EndpointKind::WsSs => {
                tcp.insert(p.clone(), ss_route(&ss_pool, &ss_candidates));
                udp.insert(p, ss_route(&ss_pool, &ss_candidates));
            },
            EndpointKind::WsSsTcp => {
                tcp.insert(p, ss_route(&ss_pool, &ss_candidates));
            },
            EndpointKind::WsSsUdp => {
                udp.insert(p, ss_route(&ss_pool, &ss_candidates));
            },
            EndpointKind::WsVless => {
                vless.insert(p, vless_route(&vless_pool, &vless_candidates));
            },
            EndpointKind::XhttpSs => {
                xhttp_ss.insert(p.clone(), ss_route(&ss_pool, &ss_candidates));
                xhttp_ss_udp.insert(p, ss_route(&ss_pool, &ss_candidates));
            },
            EndpointKind::XhttpSsTcp => {
                xhttp_ss.insert(p, ss_route(&ss_pool, &ss_candidates));
            },
            EndpointKind::XhttpSsUdp => {
                xhttp_ss_udp.insert(p, ss_route(&ss_pool, &ss_candidates));
            },
            EndpointKind::XhttpVless => {
                xhttp_vless.insert(p, vless_route(&vless_pool, &vless_candidates));
            },
        }
    }

    RouteRegistry {
        tcp: Arc::new(tcp),
        udp: Arc::new(udp),
        vless: Arc::new(vless),
        xhttp_vless: Arc::new(xhttp_vless),
        xhttp_ss: Arc::new(xhttp_ss),
        xhttp_ss_udp: Arc::new(xhttp_ss_udp),
    }
}

/// Every password-bearing user as an SS `UserKey`. Shared by startup and the
/// control-plane rebuild, so the derivation lives in one place.
pub(super) fn build_ss_user_pool(
    entries: &[UserEntry],
    default_method: CipherKind,
) -> anyhow::Result<Vec<UserKey>> {
    entries
        .iter()
        .filter(|e| e.password.is_some())
        .map(|entry| {
            let method = entry.effective_method(default_method);
            let aliases = entry.build_ip_aliases()?;
            let password = entry.password.as_deref().expect("filtered to password-bearing");
            Ok(UserKey::new(entry.id.clone(), password, entry.fwmark, method, aliases)?)
        })
        .collect()
}

/// Every `vless_id` user as a `VlessUser`.
pub(super) fn build_vless_user_pool(entries: &[UserEntry]) -> anyhow::Result<Vec<VlessUser>> {
    entries
        .iter()
        .filter_map(|e| e.vless_id.clone().map(|id| (e, id)))
        .map(|(entry, vless_id)| {
            let aliases = entry.build_ip_aliases()?;
            Ok(VlessUser::new(vless_id, Arc::from(entry.id.as_str()), entry.fwmark, aliases)?)
        })
        .collect()
}

#[cfg(test)]
#[path = "tests/endpoint_routes.rs"]
mod tests;
