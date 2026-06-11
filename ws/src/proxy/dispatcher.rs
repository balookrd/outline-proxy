use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use outline_metrics as metrics;
use outline_routing::RouteTarget;
use outline_uplink::{TransportKind, UplinkManager, UplinkRegistry};
use socks5_proto::{SocksRequest, TargetAddr, negotiate};

use super::ProxyConfig;

/// Outcome of resolving a connection's destination against the routing
/// table: either route *outside* any uplink, drop the traffic by policy, or
/// forward through a named uplink group. Produced by [`resolve_dispatch`]
/// and consumed by the per-protocol handlers (`tcp::serve_tcp_connect` /
/// `udp::serve_udp_associate`).
pub(crate) enum Route {
    /// Route outside any uplink (via = "direct" route).
    /// `fwmark` is applied to the outbound socket (Linux SO_MARK) so direct
    /// traffic does not loop back through TUN.
    Direct { fwmark: Option<u32> },
    /// Policy-blocked (SOCKS5 REP=0x02 for TCP; silent drop for UDP).
    Drop,
    /// Forward through this group's uplink manager.
    Group { name: Arc<str>, manager: UplinkManager },
}

/// Hard cap on how long a client may take to complete the SOCKS5 method
/// negotiation + request header. `negotiate` uses `read_exact`, which
/// blocks indefinitely on a silent peer; without this timeout a slow
/// attacker can pin every permit in the accept-loop semaphore.
const SOCKS5_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn serve_socks5_client(
    mut client: TcpStream,
    peer: SocketAddr,
    config: Arc<ProxyConfig>,
    registry: UplinkRegistry,
) -> Result<()> {
    let request = tokio::time::timeout(
        SOCKS5_HANDSHAKE_TIMEOUT,
        negotiate(&mut client, config.socks5_auth.as_ref()),
    )
    .await
    .map_err(|_| anyhow!("SOCKS5 handshake timed out after {:?}", SOCKS5_HANDSHAKE_TIMEOUT))??;
    debug!(%peer, ?request, "accepted SOCKS5 request");
    metrics::record_request(match &request {
        SocksRequest::Connect(_) => "connect",
        SocksRequest::UdpAssociate(_) => "udp_associate",
        SocksRequest::UdpInTcp(_) => "udp_in_tcp",
    });

    match request {
        SocksRequest::Connect(target) => {
            let dispatch = resolve_dispatch(&config, &registry, &target, TransportKind::Tcp).await;
            super::tcp::serve_tcp_connect(
                client,
                dispatch,
                target,
                Arc::clone(&config.dns_cache),
                config.tcp_timeouts,
            )
            .await
        },
        SocksRequest::UdpAssociate(client_hint) => {
            // UDP associate has no target yet — pick the default group. The
            // per-packet dispatch resolves each datagram's target against the
            // routing table inside the UDP loop.
            super::udp::serve_udp_associate(client, config, registry, client_hint).await
        },
        SocksRequest::UdpInTcp(client_hint) => {
            super::udp::serve_udp_in_tcp(client, config, registry, client_hint).await
        },
    }
}

/// Resolve a TCP target (destination known up-front) to a [`Route`].
/// Falls through the route's fallback one level when the primary group has
/// no healthy uplinks.
///
/// When `[[route]]` is absent, every target dispatches to the first
/// declared group. UDP per-packet routing is handled separately inside the
/// UDP associate loop and does not go through this function.
async fn resolve_dispatch(
    config: &ProxyConfig,
    registry: &UplinkRegistry,
    target: &TargetAddr,
    transport: TransportKind,
) -> Route {
    let Some(router) = config.router.as_ref() else {
        let manager = registry.default_group();
        if group_bypasses_when_down(&manager, transport).await {
            debug!(
                group = registry.default_group_name(),
                "default group has no healthy uplinks, bypassing to direct"
            );
            return Route::Direct { fwmark: config.direct_fwmark };
        }
        return Route::Group {
            name: registry.default_group_name().into(),
            manager,
        };
    };
    let decision = router.resolve(target).await;
    let direct_fwmark = config.direct_fwmark;
    apply_fallback_strategy(registry, decision.primary, decision.fallback, transport, |t| match t {
        RouteTarget::Direct => Route::Direct { fwmark: direct_fwmark },
        RouteTarget::Drop => Route::Drop,
        RouteTarget::Group(name) => {
            let manager = registry
                .group_by_name(&name)
                .unwrap_or_else(|| registry.default_group());
            Route::Group { name, manager }
        },
    })
    .await
}

/// Apply primary→fallback selection against live uplink-group health.
///
/// Shared by TCP dispatch and per-packet UDP routing.
///
/// - `Direct`/`Drop` primaries are terminal — fallback is ignored.
/// - Unknown group: prefer the *declared* fallback over silently
///   substituting the default — a declared fallback is an explicit user
///   escape hatch.
/// - Known group with no healthy uplinks of `transport`: use declared
///   fallback if present; otherwise bypass to direct when the group opted
///   into `bypass_when_down`; otherwise stay on the primary.
/// - When the substituted target is itself a group, its own
///   `bypass_when_down` is honoured one level deep — mirroring the TUN
///   path, where the fallback recurses through `materialize_target`.
pub(super) async fn apply_fallback_strategy<R, F>(
    registry: &UplinkRegistry,
    primary: RouteTarget,
    fallback: Option<RouteTarget>,
    transport: TransportKind,
    to_route: F,
) -> R
where
    F: Fn(RouteTarget) -> R,
{
    if let RouteTarget::Group(ref name) = primary {
        match registry.group_by_name(name) {
            None => {
                let substitute = if let Some(fb) = fallback {
                    warn!(group = %name, fallback = ?fb, "unknown group, using declared fallback");
                    fb
                } else {
                    warn!(
                        group = %name,
                        default = registry.default_group_name(),
                        "unknown group and no fallback; dispatching to default"
                    );
                    RouteTarget::Group(registry.default_group_name().into())
                };
                return to_route(bypass_substituted_group(registry, substitute, transport).await);
            },
            Some(manager) => {
                // Short-circuit on `fallback.is_none()` (and the group's
                // bypass opt-out) BEFORE running the health probe.
                // `has_any_healthy` walks every uplink in the group under
                // per-uplink `parking_lot::Mutex`es and clones each
                // `UplinkStatus`; when neither a fallback nor a bypass can
                // change the decision, the work is pure overhead. UDP is
                // the hot caller — this runs on *every* datagram via
                // `resolve_udp_packet_route` / `classify_decision`, even
                // after the per-association route cache hit.
                let bypass = manager.load_balancing().bypass_when_down;
                if (fallback.is_some() || bypass) && !manager.has_any_healthy(transport).await {
                    if let Some(fb) = fallback {
                        debug!(primary = %name, fallback = ?fb, "primary group unhealthy, using fallback");
                        return to_route(bypass_substituted_group(registry, fb, transport).await);
                    }
                    debug!(primary = %name, "group has no healthy uplinks, bypassing to direct");
                    return to_route(RouteTarget::Direct);
                }
            },
        }
    }
    to_route(primary)
}

/// `bypass_when_down` check for the group `manager`: true when the group
/// opted in and currently has no healthy uplink of `transport`. The flag
/// read costs nothing, so the health walk only runs for opted-in groups.
pub(super) async fn group_bypasses_when_down(
    manager: &UplinkManager,
    transport: TransportKind,
) -> bool {
    manager.load_balancing().bypass_when_down && !manager.has_any_healthy(transport).await
}

/// Honour `bypass_when_down` on a fallback-substituted target: a declared
/// `fallback_via` (or the unknown-group default substitute) may itself land
/// on a fully-down group that opted into the bypass. One level deep only —
/// the substitute's own fallback chain is never consulted, matching the
/// route-fallback "no chaining" rule.
async fn bypass_substituted_group(
    registry: &UplinkRegistry,
    substitute: RouteTarget,
    transport: TransportKind,
) -> RouteTarget {
    if let RouteTarget::Group(ref name) = substitute
        && let Some(manager) = registry.group_by_name(name)
        && group_bypasses_when_down(&manager, transport).await
    {
        debug!(group = %name, "fallback group has no healthy uplinks, bypassing to direct");
        return RouteTarget::Direct;
    }
    substitute
}

#[cfg(test)]
#[path = "tests/dispatcher.rs"]
mod tests;
