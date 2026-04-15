mod tcp;
mod udp;

use std::net::SocketAddr;

use anyhow::Result;
use tokio::net::TcpStream;
use tracing::{debug, info};

use crate::config::{AppConfig, RouteTarget};
use crate::metrics;
use crate::routing::RouteDecision;
use crate::socks5::{SocksRequest, negotiate};
use crate::types::TargetAddr;
use crate::uplink::{TransportKind, UplinkManager, UplinkRegistry};

/// Resolved dispatch plan for a single connection.
pub(super) enum Dispatch {
    /// Route outside any uplink (equivalent to the legacy bypass direct path).
    Direct,
    /// Policy-blocked (SOCKS5 REP=0x02 for TCP; silent drop for UDP).
    Drop,
    /// Dispatch via this group's uplink manager.
    Group {
        name: String,
        manager: UplinkManager,
    },
}

pub async fn handle_client(
    mut client: TcpStream,
    peer: SocketAddr,
    config: AppConfig,
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
            let dispatch = resolve_dispatch(&config, &registry, Some(&target), TransportKind::Tcp).await;
            tcp::handle_tcp_connect(client, config, dispatch, target).await
        },
        SocksRequest::UdpAssociate(client_hint) => {
            // UDP associate has no target yet — pick the default group. The
            // per-packet dispatch resolves each datagram's target against the
            // routing table inside the UDP loop.
            udp::handle_udp_associate(client, config, registry, client_hint).await
        },
        SocksRequest::UdpInTcp(client_hint) => {
            udp::handle_udp_in_tcp(client, config, registry, client_hint).await
        },
    }
}

/// Resolve a single TCP target (with destination known up-front) to a
/// [`Dispatch`]. Falls through the route's fallback (one level) if the
/// primary group has no healthy uplinks.
///
/// When `[[route]]` is not configured, the legacy `[bypass]` path is honoured
/// for direct targets and everything else dispatches to the default group.
pub(super) async fn resolve_dispatch(
    config: &AppConfig,
    registry: &UplinkRegistry,
    target: Option<&TargetAddr>,
    transport: TransportKind,
) -> Dispatch {
    if let Some(table) = config.routing_table.as_ref() {
        let decision = match target {
            Some(t) => table.resolve(t).await,
            None => RouteDecision {
                primary: RouteTarget::Group(registry.default_group_name().to_string()),
                fallback: None,
            },
        };
        return resolve_decision(registry, decision, transport).await;
    }

    // Legacy: honour [bypass] for direct match on the target.
    if let (Some(t), Some(bypass)) = (target, config.bypass.as_ref()) {
        if bypass.read().await.is_bypassed(t) {
            info!(target = %t, "legacy bypass: direct");
            return Dispatch::Direct;
        }
    }

    Dispatch::Group {
        name: registry.default_group_name().to_string(),
        manager: registry.default_group().clone(),
    }
}

async fn resolve_decision(
    registry: &UplinkRegistry,
    decision: RouteDecision,
    transport: TransportKind,
) -> Dispatch {
    let primary = resolve_single_target(registry, &decision.primary);
    if matches!(primary, Dispatch::Group { ref manager, .. } if !manager.has_any_healthy(transport).await)
        && let Some(fb) = decision.fallback
    {
        debug!(primary = ?decision.primary, fallback = ?fb, "primary target unhealthy, using fallback");
        return resolve_single_target(registry, &fb);
    }
    primary
}

fn resolve_single_target(registry: &UplinkRegistry, target: &RouteTarget) -> Dispatch {
    match target {
        RouteTarget::Direct => Dispatch::Direct,
        RouteTarget::Drop => Dispatch::Drop,
        RouteTarget::Group(name) => {
            let manager = registry
                .group_by_name(name)
                .cloned()
                .unwrap_or_else(|| registry.default_group().clone());
            Dispatch::Group { name: name.clone(), manager }
        },
    }
}

