use std::num::NonZeroUsize;

use lru::LruCache;
use tracing::{debug, warn};

use crate::proxy::ProxyConfig;
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
    Tunnel(String),
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
    let default_group = registry.default_group_name().to_string();
    let Some(table) = config.routing_table.as_ref() else {
        return UdpPacketRoute::Tunnel(default_group);
    };
    let current_version = table.version();
    let decision = if let Some((cached, entry_version)) = cache.get(target)
        && *entry_version == current_version
    {
        cached.clone()
    } else {
        // Tag the cached entry with the version captured *before* CIDR reads,
        // not the post-resolve version — otherwise a reload that races with
        // resolution would leave a stale decision tagged with the bumped
        // version and never invalidate. See `RoutingTable::resolve_versioned`.
        let (decision, resolve_version) = table.resolve_versioned(target).await;
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
    let as_route = |target: RouteTarget| match target {
        RouteTarget::Direct => UdpPacketRoute::Direct,
        RouteTarget::Drop => UdpPacketRoute::Drop,
        RouteTarget::Group(name) => UdpPacketRoute::Tunnel(name),
    };
    // Fallback applies when the primary is a group whose UDP pool has no
    // healthy uplinks at resolve time; Direct/Drop primaries are terminal.
    if let RouteTarget::Group(ref name) = primary {
        let manager = registry.group_by_name(name);
        if manager.is_none() {
            // Unknown group — routing table referenced a group that was not
            // found in the registry. Honour the declared fallback before
            // falling back to the default (a declared fallback is an
            // explicit escape hatch the user wrote; using it first is safer
            // than silently substituting the default).
            if let Some(fb) = fallback {
                warn!(
                    group = %name,
                    fallback = ?fb,
                    "UDP route: unknown group, using declared fallback"
                );
                return as_route(fb);
            }
            warn!(
                group = %name,
                default = registry.default_group_name(),
                "UDP route: unknown group and no fallback; dispatching to default"
            );
            return UdpPacketRoute::Tunnel(registry.default_group_name().to_string());
        }
        let manager = manager.unwrap();
        if manager.has_any_healthy(TransportKind::Udp).await {
            return as_route(primary);
        }
        if let Some(fb) = fallback {
            debug!(primary = %name, fallback = ?fb, "UDP route: primary group unhealthy, using fallback");
            return as_route(fb);
        }
    }
    as_route(primary)
}

/// Returns `true` when a per-association direct UDP socket must be pre-allocated.
///
/// We allocate eagerly whenever a routing table is active because any rule may
/// resolve to `Direct` at packet time. Inspecting every rule's target up-front
/// would couple this to routing internals and still require a fallback for
/// dynamically reloaded rules; a single socket bind is cheap by comparison.
pub(super) fn routing_table_active(config: &ProxyConfig) -> bool {
    config.routing_table.is_some()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use url::Url;

    use outline_transport::WsTransportMode;
    use outline_uplink::{
        LoadBalancingConfig, LoadBalancingMode, ProbeConfig, RoutingScope, UplinkConfig,
        UplinkManager, UplinkRegistry, UplinkTransport, WsProbeConfig,
    };

    use super::*;

    /// When the routing table references a group name that is not in the
    /// registry, `classify_decision` must fall back to the registry's default
    /// group rather than panicking or returning an error.  This is consistent
    /// with the TCP dispatch path (`resolve_single_target`).
    #[tokio::test]
    async fn classify_decision_unknown_group_falls_back_to_default() {
        let uplink = UplinkConfig {
            name: "default-uplink".to_string(),
            transport: UplinkTransport::Websocket,
            tcp_ws_url: Some(Url::parse("wss://127.0.0.1:1/tcp").unwrap()),
            tcp_ws_mode: WsTransportMode::Http1,
            udp_ws_url: None,
            udp_ws_mode: WsTransportMode::Http1,
            tcp_addr: None,
            udp_addr: None,
            cipher: shadowsocks_crypto::CipherKind::Chacha20IetfPoly1305,
            password: "s3cr3t_password".to_string(),
            weight: 1.0,
            fwmark: None,
            ipv6_first: false,
        };
        let probe = ProbeConfig {
            interval: Duration::from_secs(120),
            timeout: Duration::from_secs(10),
            max_concurrent: 4,
            max_dials: 2,
            min_failures: 3,
            attempts: 1,
            ws: WsProbeConfig { enabled: false },
            http: None,
            dns: None,
            tcp: None,
        };
        let lb = LoadBalancingConfig {
            mode: LoadBalancingMode::ActiveActive,
            routing_scope: RoutingScope::PerFlow,
            sticky_ttl: Duration::from_secs(300),
            hysteresis: Duration::from_millis(50),
            failure_cooldown: Duration::from_secs(10),
            tcp_chunk0_failover_timeout: Duration::from_secs(10),
            warm_standby_tcp: 0,
            warm_standby_udp: 0,
            rtt_ewma_alpha: 0.25,
            failure_penalty: Duration::from_millis(500),
            failure_penalty_max: Duration::from_secs(30),
            failure_penalty_halflife: Duration::from_secs(60),
            h3_downgrade_duration: Duration::from_secs(60),
            udp_ws_keepalive_interval: None,
            tcp_ws_standby_keepalive_interval: None,
            tcp_active_keepalive_interval: None,
            auto_failback: false,
        };

        let manager = UplinkManager::new_for_test("my-default", vec![uplink], probe, lb).unwrap();
        let registry = UplinkRegistry::from_single_manager(manager);

        // The routing table resolved to group "nonexistent" which is not in the registry.
        let route = classify_decision(
            &registry,
            RouteTarget::Group("nonexistent".into()),
            None,
        )
        .await;

        // Must fall back to the registry's default group name.
        match route {
            UdpPacketRoute::Tunnel(name) => {
                assert_eq!(name, registry.default_group_name(), "must fall back to default group")
            }
            other => panic!("expected Tunnel(default), got {other:?}"),
        }
    }
}
