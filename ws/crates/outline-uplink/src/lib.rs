//! Uplink lifecycle management: candidate selection, health probing, failover,
//! warm-standby pools, sticky per-destination routes, and TOML-backed state
//! persistence across restarts.  The top-level entry point is
//! [`UplinkRegistry`], which holds one [`UplinkManager`] per configured group.

pub mod config;
pub mod dial;
mod error_classify;

mod manager;
mod penalty;
mod probe;
mod registry;
mod routing_key;
mod selection;
pub mod share_link;
pub mod state;
mod time;
mod types;

pub use config::{
    CipherKind, DnsProbeConfig, FallbackTransport, HttpProbeConfig, LoadBalancingConfig,
    LoadBalancingMode, ProbeConfig, RoutingScope, ServerAddr, TargetAddr, TcpProbeConfig,
    UplinkConfig, UplinkGroupConfig, UplinkTransport, VlessUdpMuxLimits, WsProbeConfig,
    TransportMode,
};
pub use share_link::VlessShareLink;
#[cfg(test)]
mod tests;

pub use manager::deduplicate_attempted_uplink_names;
pub use registry::{UplinkGroupHandle, UplinkRegistry, log_registry_summary};
pub use state::StateStore;
pub use types::{
    StickyRouteSnapshot, TransportKind, Uplink, UplinkCandidate, UplinkManager,
    UplinkManagerSnapshot, UplinkSnapshot,
};
