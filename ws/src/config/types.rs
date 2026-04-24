use std::net::SocketAddr;
use std::path::PathBuf;

use outline_routing::RoutingTableConfig;
use outline_uplink::UplinkGroupConfig;
use socks5_proto::Socks5AuthConfig;
use url::Url;

use crate::proxy::TcpTimeouts;

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
    pub metrics: Option<MetricsConfig>,
    /// Control plane for mutating endpoints (e.g. manual uplink switch).
    /// Intentionally separate from `metrics` so observability access does
    /// not imply authority to flip active uplinks.
    pub control: Option<ControlConfig>,
    /// Built-in multi-instance dashboard. It serves a browser UI and proxies
    /// configured instance control APIs without exposing their bearer tokens
    /// to the browser.
    pub dashboard: Option<DashboardConfig>,
    #[cfg(feature = "tun")]
    pub tun: Option<outline_tun::TunConfig>,
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
    /// TCP session timeouts (SOCKS CONNECT and direct sessions).
    pub tcp_timeouts: TcpTimeouts,
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

/// Control-plane HTTP listener. Serves mutating endpoints gated by a
/// mandatory bearer token. Always bound on a separate socket from metrics.
#[derive(Debug, Clone)]
pub struct ControlConfig {
    pub listen: SocketAddr,
    pub token: String,
    /// Path to the TOML config file on disk. Used by `/control/uplinks` CRUD
    /// endpoints to edit `[[uplink_group.uplinks]]` in place. `None` when the
    /// binary was launched without a config file (e.g. pure CLI overrides),
    /// in which case CRUD endpoints return 409 Conflict.
    pub config_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct DashboardConfig {
    pub listen: SocketAddr,
    pub refresh_interval_secs: u64,
    pub request_timeout_secs: u64,
    pub instances: Vec<DashboardInstanceConfig>,
}

#[derive(Debug, Clone)]
pub struct DashboardInstanceConfig {
    pub name: String,
    pub control_url: Url,
    pub token: String,
}
