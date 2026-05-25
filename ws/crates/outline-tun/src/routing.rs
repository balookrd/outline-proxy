//! Routing dispatch for the TUN path.
//!
//! Resolves a flow's destination against the policy routing table and
//! produces a [`TunRoute`] — which the UDP/TCP engines use to pick a group
//! uplink, escape the tunnel via a local socket, or drop the flow.

use std::sync::Arc;

use socks5_proto::TargetAddr;
use tracing::warn;

use outline_routing::{RouteTarget, RoutingTable};
use outline_uplink::{UplinkManager, UplinkRegistry};

/// Per-flow dispatch context for the TUN path.
///
/// Resolves destination targets through the policy routing table to pick a
/// group's [`UplinkManager`]. `direct` and `drop` rules on the TUN side both
/// result in the packet being dropped — TUN cannot synthesise a "host's own
/// networking stack" path without fwmark/SO_BINDTODEVICE plumbing, which is
/// OS-specific and out of scope for this module. Users that want part of
/// their traffic to go outside the tunnel should exclude those prefixes
/// from the TUN routing table on the host.
#[derive(Clone)]
pub struct TunRouting {
    registry: UplinkRegistry,
    routing: Option<Arc<RoutingTable>>,
    default_group: UplinkManager,
    direct_fwmark: Option<u32>,
    ipsec_bypass: bool,
}

/// Resolved routing decision for a new TUN flow.
#[derive(Clone)]
pub enum TunRoute {
    /// Forward this flow through the named group's uplink manager.
    Group { name: Arc<str>, manager: UplinkManager },
    /// Forward via a local socket (with optional SO_MARK to escape the TUN
    /// routing loop). The TUN engine opens a plain TCP/UDP connection to the
    /// destination, relays data bidirectionally, and synthesises IP response
    /// packets back into the TUN device — same behaviour as the SOCKS5
    /// `via = "direct"` path.
    Direct { fwmark: Option<u32> },
    /// Drop the flow silently (matches `via = "drop"`).
    Drop { reason: &'static str },
}

impl TunRouting {
    pub fn new(
        registry: UplinkRegistry,
        routing: Option<Arc<RoutingTable>>,
        direct_fwmark: Option<u32>,
        ipsec_bypass: bool,
    ) -> Self {
        let default_group = registry.default_group().clone();
        Self {
            registry,
            routing,
            default_group,
            direct_fwmark,
            ipsec_bypass,
        }
    }

    /// Test-only helper: wrap a single [`UplinkManager`] as the sole group,
    /// with no routing table. Used by TUN engine tests that pre-build an
    /// `UplinkManager` directly.
    #[cfg(test)]
    pub fn from_single_manager(manager: UplinkManager) -> Self {
        Self {
            registry: UplinkRegistry::from_single_manager(manager.clone()),
            routing: None,
            default_group: manager,
            direct_fwmark: None,
            ipsec_bypass: false,
        }
    }

    pub fn default_group(&self) -> &UplinkManager {
        &self.default_group
    }

    /// Resolve a TUN flow's destination to a group manager.
    pub async fn resolve(&self, target: &TargetAddr) -> TunRoute {
        let Some(table) = self.routing.as_ref() else {
            return TunRoute::Group {
                name: self.registry.default_group_name().into(),
                manager: self.default_group.clone(),
            };
        };
        let decision = table.resolve(target).await;
        self.materialize_target(decision.primary, decision.fallback).await
    }

    /// UDP-specific resolution that honours the IPsec bypass fast-path.
    ///
    /// When [`TunConfig::ipsec_bypass`](crate::TunConfig::ipsec_bypass) is
    /// enabled, UDP flows whose destination port is 500 or 4500 (IKE /
    /// IPsec NAT-T) short-circuit to [`TunRoute::Direct`] and skip policy
    /// routing entirely. Both ports are checked together because real-world
    /// IKEv2 stacks switch between them mid-session via NAT_DETECTION; if
    /// only 4500 were bypassed, the initial IKE_SA_INIT on 500 would still
    /// be dropped via ESP elsewhere.
    pub async fn resolve_udp(&self, target: &TargetAddr) -> TunRoute {
        if self.ipsec_bypass && is_ipsec_port(target_port(target)) {
            return TunRoute::Direct { fwmark: self.direct_fwmark };
        }
        self.resolve(target).await
    }

    async fn materialize_target(
        &self,
        primary: RouteTarget,
        fallback: Option<RouteTarget>,
    ) -> TunRoute {
        match primary {
            RouteTarget::Direct => TunRoute::Direct { fwmark: self.direct_fwmark },
            RouteTarget::Drop => TunRoute::Drop { reason: "policy_drop" },
            RouteTarget::Group(name) => {
                let Some(manager) = self.registry.group_by_name(&name) else {
                    // Config validation rejects unknown groups in `via`, but
                    // defensively honour the declared fallback before dropping
                    // — dropping silently would be a worse failure mode than
                    // using the escape hatch the user wrote.
                    warn!(group = %name, "TUN route references unknown group");
                    if let Some(fb) = fallback {
                        return Box::pin(self.materialize_target(fb, None)).await;
                    }
                    return TunRoute::Drop { reason: "unknown_group" };
                };
                // Fallback applies only when the primary group has no
                // healthy uplinks at resolve time; Direct/Drop primaries are
                // terminal decisions.
                if fallback.is_some()
                    && !manager.has_any_healthy(outline_uplink::TransportKind::Udp).await
                    && !manager.has_any_healthy(outline_uplink::TransportKind::Tcp).await
                    && let Some(fb) = fallback
                {
                    // Recurse once — fallback doesn't chain further.
                    return Box::pin(self.materialize_target(fb, None)).await;
                }
                TunRoute::Group { name, manager: manager.clone() }
            },
        }
    }
}

pub(crate) fn target_port(target: &TargetAddr) -> u16 {
    match target {
        TargetAddr::IpV4(_, port) | TargetAddr::IpV6(_, port) | TargetAddr::Domain(_, port) => {
            *port
        },
    }
}

/// Match IKE / IPsec NAT-T well-known UDP ports. Both 500 and 4500 are
/// recognised because NAT_DETECTION mid-session moves IKE_AUTH off port 500;
/// dropping either half breaks the handshake or the post-handshake ESP flow.
pub(crate) fn is_ipsec_port(port: u16) -> bool {
    matches!(port, 500 | 4500)
}
