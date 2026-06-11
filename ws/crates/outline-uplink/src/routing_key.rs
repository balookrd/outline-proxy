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
            Self::Default(transport) => write!(f, "{}:default", transport_key_prefix(*transport)),
        }
    }
}

pub(crate) fn routing_key(
    transport: TransportKind,
    target: Option<&TargetAddr>,
    scope: RoutingScope,
) -> RoutingKey {
    match target {
        _ if matches!(scope, RoutingScope::Global) => RoutingKey::Global,
        _ if matches!(scope, RoutingScope::PerUplink) => RoutingKey::TransportGlobal(transport),
        Some(target) => RoutingKey::Target { transport, target: target.clone() },
        None => RoutingKey::Default(transport),
    }
}

pub(crate) fn strict_route_key(transport: TransportKind, scope: RoutingScope) -> RoutingKey {
    match scope {
        RoutingScope::Global => RoutingKey::Global,
        RoutingScope::PerUplink => RoutingKey::TransportGlobal(transport),
        RoutingScope::PerFlow => RoutingKey::Default(transport),
    }
}

pub(crate) fn transport_key_prefix(transport: TransportKind) -> &'static str {
    match transport {
        TransportKind::Tcp => "Tcp",
        TransportKind::Udp => "Udp",
    }
}
