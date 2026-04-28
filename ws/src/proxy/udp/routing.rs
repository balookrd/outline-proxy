use std::num::NonZeroUsize;
use std::sync::Arc;

use lru::LruCache;

use crate::proxy::ProxyConfig;
use crate::proxy::dispatcher::apply_fallback_strategy;
use outline_routing::{RouteDecision, RouteTarget};
use outline_uplink::{TransportKind, UplinkRegistry};
use socks5_proto::TargetAddr;

/// Per-association route-cache cap. Bounds memory for clients with large
/// destination fan-out (DNS scans, QUIC/P2P to many peers) — without a cap,
/// the cache grows linearly with unique targets over the association lifetime.
/// 1024 entries ≈ a few hundred KB worst-case and comfortably exceeds the
/// working set of real clients.
pub(super) const UDP_ROUTE_CACHE_CAP: usize = 1024;

/// Per-packet routing decision for UDP.
///
/// `Tunnel` carries the resolved group name — the uplink loop then routes the
/// datagram through that group's transport (lazily opened on first use).
#[derive(Clone, Debug)]
pub(super) enum UdpPacketRoute {
    Direct,
    Drop,
    Tunnel(Arc<str>),
}

/// Per-association cache of route decisions keyed by destination target.
///
/// We cache the raw `(primary, fallback)` pair from the routing table — *not*
/// the final `UdpPacketRoute` — so primary↔fallback selection runs on every
/// packet and tracks live uplink-group health. The routing table's
/// [`version`](outline_routing::RoutingTable::version) invalidates entries on
/// CIDR-file reloads.
pub(super) type UdpRouteCache = LruCache<TargetAddr, (RouteDecision, u64)>;

pub(super) fn new_udp_route_cache() -> UdpRouteCache {
    LruCache::new(NonZeroUsize::new(UDP_ROUTE_CACHE_CAP).expect("cap is non-zero"))
}

pub(super) async fn resolve_udp_packet_route(
    cache: &mut UdpRouteCache,
    config: &ProxyConfig,
    registry: &UplinkRegistry,
    target: &TargetAddr,
) -> UdpPacketRoute {
    let Some(router) = config.router.as_ref() else {
        return UdpPacketRoute::Tunnel(registry.default_group_name().into());
    };
    let current_version = router.version();
    let decision = if let Some((cached, entry_version)) = cache.get(target)
        && *entry_version == current_version
    {
        cached.clone()
    } else {
        // Tag the cached entry with the version captured *before* CIDR reads,
        // not the post-resolve version — otherwise a reload that races with
        // resolution would leave a stale decision tagged with the bumped
        // version and never invalidate. See `RoutingTable::resolve_versioned`.
        let (decision, resolve_version) = router.resolve_versioned(target).await;
        cache.put(target.clone(), (decision.clone(), resolve_version));
        decision
    };
    classify_decision(registry, decision.primary, decision.fallback).await
}

pub(super) async fn classify_decision(
    registry: &UplinkRegistry,
    primary: RouteTarget,
    fallback: Option<RouteTarget>,
) -> UdpPacketRoute {
    apply_fallback_strategy(registry, primary, fallback, TransportKind::Udp, |t| match t {
        RouteTarget::Direct => UdpPacketRoute::Direct,
        RouteTarget::Drop => UdpPacketRoute::Drop,
        RouteTarget::Group(name) => UdpPacketRoute::Tunnel(name),
    })
    .await
}

/// Returns `true` when a per-association direct UDP socket must be pre-allocated.
///
/// We allocate eagerly whenever a routing table is active because any rule may
/// resolve to `Direct` at packet time. Inspecting every rule's target up-front
/// would couple this to routing internals and still require a fallback for
/// dynamically reloaded rules; a single socket bind is cheap by comparison.
pub(super) fn routing_table_active(config: &ProxyConfig) -> bool {
    config.router.is_some()
}

#[cfg(test)]
#[path = "tests/routing.rs"]
mod tests;
