//! Uplink lifecycle management: candidate selection, health probing, failover,
//! warm-standby pools, sticky per-destination routes, and TOML-backed state
//! persistence across restarts.  The top-level entry point is
//! [`UplinkRegistry`], which holds one [`UplinkManager`] per configured group.

pub mod config;
mod error_text;

mod manager;
mod probe;
mod registry;
mod selection;
pub mod state;
mod types;
mod utils;

pub use config::{
    CipherKind, DnsProbeConfig, HttpProbeConfig, LoadBalancingConfig, LoadBalancingMode,
    ProbeConfig, RoutingScope, ServerAddr, TcpProbeConfig, TargetAddr, UplinkConfig,
    UplinkGroupConfig, UplinkTransport, WsProbeConfig, WsTransportMode,
};
#[cfg(test)]
mod tests;

pub use manager::{deduplicate_attempted_uplink_names, log_uplink_summary};
pub use registry::{UplinkGroupHandle, UplinkRegistry, log_registry_summary};
pub use state::StateStore;
pub use types::{
    StickyRouteSnapshot, TransportKind, UplinkCandidate, UplinkManager, UplinkManagerSnapshot,
    UplinkSnapshot,
};
