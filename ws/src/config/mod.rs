mod args;
mod load;
mod schema;
mod types;

pub use args::Args;
pub use load::load_config;
pub use types::{
    AppConfig, DnsProbeConfig, H2Config, HttpProbeConfig, LoadBalancingConfig, LoadBalancingMode,
    MetricsConfig, ProbeConfig, RoutingScope, Socks5AuthConfig, Socks5AuthUserConfig,
    TcpProbeConfig, TunConfig, TunTcpConfig, UplinkConfig, WsProbeConfig,
};

#[cfg(test)]
pub(crate) use schema::{ConfigFile, resolve_outline_section};

#[cfg(test)]
mod tests;
