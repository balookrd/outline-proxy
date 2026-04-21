use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::net::TcpStream;
use tracing::debug;

use outline_metrics as metrics;
use outline_routing::{RouteDecision, RouteTarget};
use socks5_proto::{SocksRequest, TargetAddr, negotiate};
use outline_uplink::{TransportKind, UplinkManager, UplinkRegistry};

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
    Group {
        name: Arc<str>,
        manager: UplinkManager,
    },
}

pub async fn serve_socks5_client(
    mut client: TcpStream,
    peer: SocketAddr,
    config: Arc<ProxyConfig>,
    registry: UplinkRegistry,
) -> Result<()> {
    let request = negotiate(&mut client, config.socks5_auth.as_ref()).await?;
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
    if let Some(router) = config.router.as_ref() {
        let decision = router.resolve(target).await;
        return resolve_decision(registry, decision, transport, config.direct_fwmark).await;
    }

    Route::Group {
        name: registry.default_group_name().into(),
        manager: registry.default_group().clone(),
    }
}

async fn resolve_decision(
    registry: &UplinkRegistry,
    decision: RouteDecision,
    transport: TransportKind,
    direct_fwmark: Option<u32>,
) -> Route {
    let primary = resolve_single_target(registry, &decision.primary, direct_fwmark);
    if matches!(primary, Route::Group { ref manager, .. } if !manager.has_any_healthy(transport).await)
        && let Some(fb) = decision.fallback
    {
        debug!(primary = ?decision.primary, fallback = ?fb, "primary target unhealthy, using fallback");
        return resolve_single_target(registry, &fb, direct_fwmark);
    }
    primary
}

fn resolve_single_target(
    registry: &UplinkRegistry,
    target: &RouteTarget,
    direct_fwmark: Option<u32>,
) -> Route {
    match target {
        RouteTarget::Direct => Route::Direct { fwmark: direct_fwmark },
        RouteTarget::Drop => Route::Drop,
        RouteTarget::Group(name) => {
            let manager = registry
                .group_by_name(name)
                .cloned()
                .unwrap_or_else(|| registry.default_group().clone());
            Route::Group { name: name.clone(), manager }
        },
    }
}
