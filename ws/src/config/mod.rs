mod args;
mod load;
mod schema;
mod types;

pub use args::Args;
pub use load::load_config;
pub use types::{
    AppConfig, DnsProbeConfig, H2Config, HttpProbeConfig, LoadBalancingConfig, LoadBalancingMode,
    MetricsConfig, ProbeConfig, RouteRule, RouteTarget, RoutingScope, RoutingTableConfig,
    Socks5AuthConfig, Socks5AuthUserConfig, TcpProbeConfig, UplinkConfig, UplinkGroupConfig,
    WsProbeConfig,
};
#[cfg(feature = "tun")]
pub use types::{TunConfig, TunTcpConfig};

#[cfg(test)]
pub(crate) use schema::{ConfigFile, resolve_outline_section};

#[cfg(test)]
mod tests;
