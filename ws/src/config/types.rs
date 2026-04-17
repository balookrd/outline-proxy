use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use outline_transport::DnsCache;

use crate::routing::RoutingTable;

// Auth configs live in the `socks5-proto` workspace crate; re-exported so
// existing `crate::config::Socks5AuthConfig` imports keep working.
pub use socks5_proto::{Socks5AuthConfig, Socks5AuthUserConfig};

// Uplink config types live in the `outline-uplink` workspace crate; re-exported
// so existing `crate::config::UplinkConfig` etc. imports keep working.
pub use outline_uplink::{
    DnsProbeConfig, HttpProbeConfig, LoadBalancingConfig, LoadBalancingMode, ProbeConfig,
    RoutingScope, TcpProbeConfig, UplinkConfig, UplinkGroupConfig, WsProbeConfig,
};

// RouteTarget / RouteRule / RoutingTableConfig live in the `outline-routing`
// workspace crate; re-exported so existing `crate::config::RouteTarget`
// imports keep working.
pub use outline_routing::{RouteRule, RouteTarget, RoutingTableConfig};

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub listen: Option<SocketAddr>,
    pub socks5_auth: Option<Socks5AuthConfig>,
    /// Uplink groups — each is an isolated `UplinkManager` with its own
    /// probe loop, standby pools, sticky routes, and LB config.
    pub groups: Vec<UplinkGroupConfig>,
    /// Declarative policy routing config (parsed from `[[route]]`). `None`
    /// when no `[[route]]` is declared — traffic is then unconditionally
    /// routed through the first group.
    pub routing: Option<RoutingTableConfig>,
    /// Compiled, hot-reloadable routing table.
    ///
    /// **Two-phase init contract:** always `None` after [`load_config`] returns.
    /// [`run_with_config`] compiles `routing` into an `Arc<RoutingTable>`, stores
    /// it here, and only then starts accepting connections. Code that reads this
    /// field during request handling can therefore rely on it being `Some` whenever
    /// `routing` is `Some`. Do NOT read this field before `run_with_config` has run
    /// (e.g. in tests that call `load_config` directly) — use `routing` instead.
    pub routing_table: Option<Arc<RoutingTable>>,
    /// Shared DNS cache used by transport resolve paths.
    ///
    /// **Two-phase init contract** (same as `routing_table`): always `None`
    /// after `load_config` returns; `run_with_config` instantiates an
    /// `Arc<DnsCache>` with [`outline_transport::DEFAULT_DNS_CACHE_TTL`]
    /// and stores it here before accepting connections. Runtime paths
    /// (proxy / tun / uplink) unwrap it once per session.
    pub dns_cache: Option<Arc<DnsCache>>,
    pub metrics: Option<MetricsConfig>,
    #[cfg(feature = "tun")]
    pub tun: Option<TunConfig>,
    pub h2: H2Config,
    /// Override kernel UDP receive buffer size (SO_RCVBUF). None = kernel default.
    pub udp_recv_buf_bytes: Option<usize>,
    /// Override kernel UDP send buffer size (SO_SNDBUF). None = kernel default.
    pub udp_send_buf_bytes: Option<usize>,
    /// SO_MARK applied to sockets used by `via = "direct"` routes (both TCP
    /// connect and UDP bind). Prevents direct traffic from being routed
    /// back into the TUN device on hosts where all traffic is captured.
    /// Linux only; ignored on other platforms.
    pub direct_fwmark: Option<u32>,
    /// Path to the uplink state file used to persist active-uplink selection
    /// across restarts.  Derived from the config path at startup; `None`
    /// disables persistence (e.g. in tests).
    pub state_path: Option<PathBuf>,
}

/// HTTP/2 flow-control window sizes for WebSocket transports.
#[derive(Debug, Clone)]
pub struct H2Config {
    /// Per-stream initial window size in bytes (default: 1 MiB).
    pub initial_stream_window_size: u32,
    /// Per-connection initial window size in bytes (default: 2 MiB).
    pub initial_connection_window_size: u32,
}

#[derive(Debug, Clone)]
pub struct MetricsConfig {
    pub listen: SocketAddr,
}

// TunConfig / TunTcpConfig live in the `outline-tun` workspace crate; re-exported
// so existing `crate::config::TunConfig` etc. imports keep working.
#[cfg(feature = "tun")]
pub use outline_tun::{TunConfig, TunTcpConfig};
