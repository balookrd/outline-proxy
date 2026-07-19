//! Routing dispatch for the TUN path.
//!
//! Resolves a flow's destination against the policy routing table and
//! produces a [`TunRoute`] — which the UDP/TCP engines use to pick a group
//! uplink, escape the tunnel via a local socket, or drop the flow.

use std::sync::Arc;

use socks5_proto::TargetAddr;
use tracing::warn;

use outline_routing::{RouteTarget, RoutingTable};
use outline_uplink::{TransportKind, UplinkManager, UplinkRegistry};

/// Per-flow dispatch context for the TUN path.
///
/// Resolves destination targets through the policy routing table to pick a
/// group's [`UplinkManager`], escape the tunnel via a local socket
/// ([`TunRoute::Direct`], marked with `direct_fwmark` so it does not loop
/// back through the TUN device), or drop the flow by policy.
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

/// Which liveness signal gates a group's `bypass_when_down` / route-fallback
/// decision.
///
/// A flow can only ride an uplink that speaks its transport, so each flow
/// scopes the health walk to its own: a group whose UDP side has no healthy
/// uplink cannot carry a UDP flow even while its TCP side is fine. ICMP echo
/// has no transport of its own and asks for [`HealthScope::EitherTransport`],
/// which treats the group as down only when *neither* transport is healthy.
#[derive(Clone, Copy)]
enum HealthScope {
    /// Liveness of one transport — the scope every real flow uses.
    One(TransportKind),
    /// Liveness of the group as a whole: down only when both transports are.
    EitherTransport,
}

impl HealthScope {
    /// True when the group has no healthy uplink within this scope.
    async fn group_is_down(self, manager: &UplinkManager) -> bool {
        match self {
            Self::One(transport) => !manager.has_any_healthy(transport).await,
            Self::EitherTransport => {
                !manager.has_any_healthy(TransportKind::Tcp).await
                    && !manager.has_any_healthy(TransportKind::Udp).await
            },
        }
    }
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
    ///
    /// `transport` scopes the group-health walk behind `bypass_when_down` and
    /// route fallbacks: the group counts as down when it has no healthy uplink
    /// able to carry `transport`, regardless of the other transport's state.
    /// Mirrors the SOCKS5 dispatch path (`apply_fallback_strategy`), so the
    /// same config decides both ingresses the same way.
    pub async fn resolve(&self, target: &TargetAddr, transport: TransportKind) -> TunRoute {
        self.resolve_scoped(target, HealthScope::One(transport)).await
    }

    /// Resolve for traffic that has no transport of its own (ICMP echo): the
    /// group counts as down only when *neither* transport has a healthy
    /// uplink. An echo request is not carried by a group uplink, so scoping it
    /// to one transport would report a group as down while the other half is
    /// still carrying flows.
    pub async fn resolve_any_transport(&self, target: &TargetAddr) -> TunRoute {
        self.resolve_scoped(target, HealthScope::EitherTransport).await
    }

    async fn resolve_scoped(&self, target: &TargetAddr, scope: HealthScope) -> TunRoute {
        let Some(table) = self.routing.as_ref() else {
            if group_bypasses_when_down(&self.default_group, scope).await {
                return TunRoute::Direct { fwmark: self.direct_fwmark };
            }
            return TunRoute::Group {
                name: self.registry.default_group_name().into(),
                manager: self.default_group.clone(),
            };
        };
        let decision = table.resolve(target).await;
        self.materialize_target(decision.primary, decision.fallback, scope)
            .await
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
        self.resolve_udp_sni(None, target).await
    }

    /// UDP resolution that lets a sniffed SNI steer the route (two-pass:
    /// domain first, then IP), used when `[tun] route_by_sni` is on.
    ///
    /// `sni_host` is the domain recovered from the flow's QUIC Initial (or
    /// `None` — no SNI, not QUIC, or SNI-routing disabled); `ip_target` is the
    /// packet's literal destination. An explicit domain rule wins; otherwise
    /// the literal IP is matched — so a flow whose SNI hits no domain rule
    /// falls back to exactly the IP decision [`Self::resolve_udp`] would make.
    /// The IPsec bypass still short-circuits on the literal port, and with no
    /// routing table the SNI is irrelevant (no domain rules exist), collapsing
    /// to the default-group path.
    pub async fn resolve_udp_sni(&self, sni_host: Option<&str>, ip_target: &TargetAddr) -> TunRoute {
        if self.ipsec_bypass && is_ipsec_port(target_port(ip_target)) {
            return TunRoute::Direct { fwmark: self.direct_fwmark };
        }
        self.resolve_sni(sni_host, ip_target, TransportKind::Udp).await
    }

    /// Two-pass SNI-then-IP resolution for `transport`, scoping the group-health
    /// walk to it. `sni_host` is the domain sniffed from the flow's first bytes
    /// (TLS ClientHello / QUIC Initial), `ip_target` the literal destination.
    /// An explicit domain rule wins; otherwise the literal IP is matched — so a
    /// flow whose SNI hits no domain rule lands on exactly the IP decision the
    /// plain [`Self::resolve`] would make. Shared by both ingresses; the UDP
    /// wrapper [`Self::resolve_udp_sni`] layers the IPsec bypass on top.
    pub async fn resolve_sni(
        &self,
        sni_host: Option<&str>,
        ip_target: &TargetAddr,
        transport: TransportKind,
    ) -> TunRoute {
        let scope = HealthScope::One(transport);
        let Some(table) = self.routing.as_ref() else {
            if group_bypasses_when_down(&self.default_group, scope).await {
                return TunRoute::Direct { fwmark: self.direct_fwmark };
            }
            return TunRoute::Group {
                name: self.registry.default_group_name().into(),
                manager: self.default_group.clone(),
            };
        };
        let decision = table.resolve_domain_or_ip(sni_host, Some(ip_target)).await;
        self.materialize_target(decision.primary, decision.fallback, scope)
            .await
    }

    async fn materialize_target(
        &self,
        primary: RouteTarget,
        fallback: Option<RouteTarget>,
        scope: HealthScope,
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
                        return Box::pin(self.materialize_target(fb, None, scope)).await;
                    }
                    return TunRoute::Drop { reason: "unknown_group" };
                };
                // Fallback / bypass applies only when the primary group has
                // no healthy uplinks *for this scope* at resolve time;
                // Direct/Drop primaries are terminal decisions. An explicit
                // route fallback wins over the group's own `bypass_when_down`;
                // the recursion then re-evaluates the bypass on the fallback
                // group under the same scope.
                let bypass = manager.load_balancing().bypass_when_down;
                if (fallback.is_some() || bypass) && scope.group_is_down(&manager).await {
                    if let Some(fb) = fallback {
                        // Recurse once — fallback doesn't chain further.
                        return Box::pin(self.materialize_target(fb, None, scope)).await;
                    }
                    return TunRoute::Direct { fwmark: self.direct_fwmark };
                }
                TunRoute::Group { name, manager: manager.clone() }
            },
        }
    }
}

/// `bypass_when_down` check for a group on the TUN path: true when the group
/// opted in and has no healthy uplink within `scope` — the same criterion as
/// the route-fallback decision in [`TunRouting::materialize_target`]; keep the
/// two consistent. The ICMP echo health-gate
/// (`echo_reply_suppressed_for_down_group`) runs its own both-transports check
/// on the group it resolves to, matching [`HealthScope::EitherTransport`].
/// The flag read costs nothing, so the health walk only runs for opted-in
/// groups.
async fn group_bypasses_when_down(manager: &UplinkManager, scope: HealthScope) -> bool {
    manager.load_balancing().bypass_when_down && scope.group_is_down(manager).await
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

#[cfg(test)]
#[path = "tests/routing.rs"]
mod tests;
