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
pub use registry::{UplinkGroup, UplinkRegistry, log_registry_summary};
pub use state::StateStore;
pub use types::{
    StickyRouteSnapshot, TransportKind, UplinkCandidate, UplinkManager, UplinkManagerSnapshot,
    UplinkSnapshot,
};
