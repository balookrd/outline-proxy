use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

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

#[cfg(feature = "tun")]
#[derive(Debug, Clone)]
pub struct TunConfig {
    pub path: PathBuf,
    pub name: Option<String>,
    pub mtu: usize,
    pub max_flows: usize,
    pub idle_timeout: Duration,
    pub tcp: TunTcpConfig,
    /// Max concurrent IP fragment reassembly sets (distinct flows being reassembled).
    /// Default: 1024 (VM). Reduce to 64 on routers.
    pub defrag_max_fragment_sets: usize,
    /// Max fragment chunks per reassembly set before the set is dropped.
    /// Default: 64 (VM). Reduce to 16 on routers.
    pub defrag_max_fragments_per_set: usize,
    /// Max bytes buffered across all in-progress IP fragment reassembly sets.
    /// Default: 16 MiB (VM). Reduce to 2 MiB or less on routers.
    pub defrag_max_total_bytes: usize,
    /// Max bytes buffered per individual fragment set.
    /// Default: 128 KiB. Reduce to 16 KiB on routers.
    pub defrag_max_bytes_per_set: usize,
}

#[cfg(feature = "tun")]
#[derive(Debug, Clone)]
pub struct TunTcpConfig {
    pub connect_timeout: Duration,
    pub handshake_timeout: Duration,
    pub half_close_timeout: Duration,
    pub max_pending_server_bytes: usize,
    pub backlog_abort_grace: Duration,
    pub backlog_hard_limit_multiplier: usize,
    pub backlog_no_progress_abort: Duration,
    pub max_buffered_client_segments: usize,
    pub max_buffered_client_bytes: usize,
    pub max_retransmits: u32,
}
