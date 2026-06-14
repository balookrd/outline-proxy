//! Composition of [`RoutingKey`] values that drive sticky-route storage and
//! load-balancing lookups.
//!
//! A `RoutingKey` is the granularity at which sticky pinning happens: per-flow
//! (transport + target tuple), per-uplink (transport, target ignored), or
//! global (transport ignored too).  Both the sticky map and the strict-route
//! pinning use the helpers here so the semantics stay aligned.

use std::fmt;

use socks5_proto::TargetAddr;

use crate::config::RoutingScope;
use crate::types::TransportKind;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum RoutingKey {
    Global,
    TransportGlobal(TransportKind),
    Target {
        transport: TransportKind,
        target: TargetAddr,
    },
    /// Per-client affinity key (`routing_scope = "per_client"`). Carries the
    /// transport so that, like [`Self::Target`], a client can pin a different
    /// uplink for TCP vs UDP when its preferred uplink only carries one of
    /// them — without the two legs fighting over a single map entry.
    Client {
        transport: TransportKind,
        client: String,
    },
    Default(TransportKind),
}

impl fmt::Display for RoutingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Global => write!(f, "global"),
            Self::TransportGlobal(transport) => {
                write!(f, "{}:global", transport_key_prefix(*transport))
            },
            Self::Target { transport, target } => {
                write!(f, "{}:{target}", transport_key_prefix(*transport))
            },
            Self::Client { transport, client } => {
                write!(f, "{}:client:{client}", transport_key_prefix(*transport))
            },
            Self::Default(transport) => write!(f, "{}:default", transport_key_prefix(*transport)),
        }
    }
}

pub(crate) fn routing_key(
    transport: TransportKind,
    target: Option<&TargetAddr>,
    client: Option<&str>,
    scope: RoutingScope,
) -> RoutingKey {
    match scope {
        RoutingScope::Global => RoutingKey::Global,
        RoutingScope::PerUplink => RoutingKey::TransportGlobal(transport),
        // No client identity available (e.g. an ingress that cannot attribute
        // the flow to a source): fall back to a single shared key so the flow
        // is still served deterministically instead of being dropped.
        RoutingScope::PerClient => match client {
            Some(client) => RoutingKey::Client { transport, client: client.to_string() },
            None => RoutingKey::Default(transport),
        },
        RoutingScope::PerFlow => match target {
            Some(target) => RoutingKey::Target { transport, target: target.clone() },
            None => RoutingKey::Default(transport),
        },
    }
}

pub(crate) fn strict_route_key(transport: TransportKind, scope: RoutingScope) -> RoutingKey {
    match scope {
        RoutingScope::Global => RoutingKey::Global,
        RoutingScope::PerUplink => RoutingKey::TransportGlobal(transport),
        // Strict (active_passive) pinning is not defined for per-client scope —
        // per_client is an active_active concept. Use the same default key as
        // per_flow so the function stays total.
        RoutingScope::PerFlow | RoutingScope::PerClient => RoutingKey::Default(transport),
    }
}

pub(crate) fn transport_key_prefix(transport: TransportKind) -> &'static str {
    match transport {
        TransportKind::Tcp => "Tcp",
        TransportKind::Udp => "Udp",
    }
}
