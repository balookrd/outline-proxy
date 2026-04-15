use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use serde::Deserialize;
use tokio::sync::RwLock;
use url::Url;

use crate::bypass::BypassList;
use crate::types::{CipherKind, UplinkTransport, WsTransportMode};

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub listen: Option<SocketAddr>,
    pub socks5_auth: Option<Socks5AuthConfig>,
    /// Legacy flat view — kept for the existing `UplinkManager`/proxy glue
    /// until the runtime migration to per-group managers (etaps 3–5).
    /// Derived from `groups` when the new config is used.
    pub uplinks: Vec<UplinkConfig>,
    /// Legacy probe config — derived from the first group.
    pub probe: ProbeConfig,
    /// Legacy LB config — derived from the first group.
    pub load_balancing: LoadBalancingConfig,
    pub metrics: Option<MetricsConfig>,
    pub tun: Option<TunConfig>,
    pub h2: H2Config,
    /// Override kernel UDP receive buffer size (SO_RCVBUF). None = kernel default.
    pub udp_recv_buf_bytes: Option<usize>,
    /// Override kernel UDP send buffer size (SO_SNDBUF). None = kernel default.
    pub udp_send_buf_bytes: Option<usize>,
    /// Optional bypass list for SOCKS5 connections. Shared + hot-reloadable.
    /// Kept until the routing-table integration in etap 5.
    pub bypass: Option<Arc<RwLock<BypassList>>>,
    /// New: explicit uplink groups, each with its own LB + probe configs.
    pub groups: Vec<UplinkGroupConfig>,
    /// New: policy routing table. `None` until the new config is wired in.
    pub routing: Option<RoutingTableConfig>,
}

/// New: a named collection of uplinks sharing a single LB + probe configuration.
#[derive(Debug, Clone)]
pub struct UplinkGroupConfig {
    pub name: String,
    pub uplinks: Vec<UplinkConfig>,
    pub probe: ProbeConfig,
    pub load_balancing: LoadBalancingConfig,
}

/// New: what a matched route should do with the traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteTarget {
    /// Forward the connection outside any uplink (equivalent to the old
    /// `[bypass]` behaviour).
    Direct,
    /// Silently drop the connection (TCP → SOCKS5 reply `REP=0x02`, UDP → drop).
    Drop,
    /// Route through the named group.
    Group(String),
}

/// New: one policy routing rule.
///
/// Prefixes come from `inline_prefixes` and/or `file`. When `file` is set,
/// a background watcher polls `file_poll` for mtime changes and swaps the
/// compiled CIDR set in place.
#[derive(Debug, Clone)]
pub struct RouteRule {
    pub inline_prefixes: Vec<String>,
    pub file: Option<PathBuf>,
    pub file_poll: Duration,
    pub target: RouteTarget,
    pub fallback: Option<RouteTarget>,
}

/// New: full routing table — ordered rules + explicit default.
#[derive(Debug, Clone)]
pub struct RoutingTableConfig {
    pub rules: Vec<RouteRule>,
    pub default_target: RouteTarget,
    pub default_fallback: Option<RouteTarget>,
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
pub struct UplinkConfig {
    pub name: String,
    pub transport: UplinkTransport,
    pub tcp_ws_url: Option<Url>,
    pub tcp_ws_mode: WsTransportMode,
    pub udp_ws_url: Option<Url>,
    pub udp_ws_mode: WsTransportMode,
    pub tcp_addr: Option<crate::types::ServerAddr>,
    pub udp_addr: Option<crate::types::ServerAddr>,
    pub cipher: CipherKind,
    pub password: String,
    pub weight: f64,
    pub fwmark: Option<u32>,
    pub ipv6_first: bool,
}

impl UplinkConfig {
    pub fn supports_udp(&self) -> bool {
        match self.transport {
            UplinkTransport::Websocket => self.udp_ws_url.is_some(),
            UplinkTransport::Shadowsocks => self.udp_addr.is_some(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5AuthUserConfig {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5AuthConfig {
    pub users: Vec<Socks5AuthUserConfig>,
}

#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub interval: Duration,
    pub timeout: Duration,
    pub max_concurrent: usize,
    pub max_dials: usize,
    pub min_failures: usize,
    /// Number of probe attempts per cycle. If any attempt succeeds the cycle is
    /// counted as a success. Retries are separated by a short pause (500 ms),
    /// so the total time per cycle can be up to
    /// `attempts × (per-transport probe timeout budget + 500 ms)`. Default: 2.
    pub attempts: usize,
    pub ws: WsProbeConfig,
    pub http: Option<HttpProbeConfig>,
    pub dns: Option<DnsProbeConfig>,
    pub tcp: Option<TcpProbeConfig>,
}

impl ProbeConfig {
    pub fn enabled(&self) -> bool {
        self.ws.enabled || self.http.is_some() || self.dns.is_some() || self.tcp.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct WsProbeConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct HttpProbeConfig {
    pub url: Url,
}

#[derive(Debug, Clone)]
pub struct DnsProbeConfig {
    pub server: String,
    pub port: u16,
    pub name: String,
}

impl DnsProbeConfig {
    pub fn target_addr(&self) -> Result<crate::types::TargetAddr> {
        if let Ok(ip) = self.server.parse::<IpAddr>() {
            Ok(match ip {
                IpAddr::V4(v4) => crate::types::TargetAddr::IpV4(v4, self.port),
                IpAddr::V6(v6) => crate::types::TargetAddr::IpV6(v6, self.port),
            })
        } else {
            Ok(crate::types::TargetAddr::Domain(self.server.clone(), self.port))
        }
    }
}

#[derive(Debug, Clone)]
pub struct TcpProbeConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct LoadBalancingConfig {
    pub mode: LoadBalancingMode,
    pub routing_scope: RoutingScope,
    pub sticky_ttl: Duration,
    pub hysteresis: Duration,
    pub failure_cooldown: Duration,
    /// Maximum silence window to wait for the first upstream response bytes
    /// before TCP chunk-0 failover is allowed.
    pub tcp_chunk0_failover_timeout: Duration,
    pub warm_standby_tcp: usize,
    pub warm_standby_udp: usize,
    pub rtt_ewma_alpha: f64,
    pub failure_penalty: Duration,
    pub failure_penalty_max: Duration,
    pub failure_penalty_halflife: Duration,
    /// How long to downgrade from H3 to H2 after an H3 runtime error.
    pub h3_downgrade_duration: Duration,
    /// Interval at which WS ping frames are sent on idle UDP data-path connections
    /// to prevent NAT/firewall timeout disconnections. None disables keepalive.
    pub udp_ws_keepalive_interval: Option<Duration>,
    /// How often to ping warm-standby TCP pool connections to keep them alive through
    /// NAT/firewall idle timeouts. Runs in addition to the 15-second validation cycle.
    /// None disables the extra keepalive loop (validation every 15 s still runs).
    pub tcp_ws_standby_keepalive_interval: Option<Duration>,
    /// How often to send a Shadowsocks keepalive frame on an idle active SOCKS TCP
    /// session (SS2022 only — SS1 uplinks treat this as a no-op). Defeats upstream
    /// proxy or NAT idle-timeout disconnections for long-lived flows like SSH.
    /// None disables per-session keepalive (relies solely on OS TCP keepalive).
    pub tcp_active_keepalive_interval: Option<Duration>,
    /// When false (default), the active uplink is only replaced when it fails.
    /// When true, traffic returns to the highest-priority healthy uplink once it
    /// has been stable for `min_failures` consecutive probe cycles.
    pub auto_failback: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancingMode {
    ActiveActive,
    ActivePassive,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RoutingScope {
    PerFlow,
    PerUplink,
    Global,
}

#[derive(Debug, Clone)]
pub struct MetricsConfig {
    pub listen: SocketAddr,
}

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
