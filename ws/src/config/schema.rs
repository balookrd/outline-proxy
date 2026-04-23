use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;
use url::Url;

use outline_transport::{ServerAddr, WsTransportMode};
use outline_uplink::{LoadBalancingMode, RoutingScope, UplinkTransport};
use shadowsocks_crypto::CipherKind;

#[derive(Debug, Deserialize)]
pub(crate) struct ConfigFile {
    pub(super) socks5: Option<Socks5Section>,
    pub(super) transport: Option<UplinkTransport>,
    pub(super) tcp_ws_url: Option<Url>,
    pub(super) tcp_ws_mode: Option<WsTransportMode>,
    pub(super) udp_ws_url: Option<Url>,
    pub(super) udp_ws_mode: Option<WsTransportMode>,
    pub(super) tcp_addr: Option<ServerAddr>,
    pub(super) udp_addr: Option<ServerAddr>,
    pub(super) method: Option<CipherKind>,
    pub(super) password: Option<String>,
    pub(super) fwmark: Option<u32>,
    pub(super) ipv6_first: Option<bool>,
    pub(super) uplinks: Option<Vec<UplinkSection>>,
    pub(super) probe: Option<ProbeSection>,
    pub(super) load_balancing: Option<LoadBalancingSection>,
    pub(super) outline: Option<OutlineSection>,
    pub(super) metrics: Option<MetricsSection>,
    pub(super) control: Option<ControlSection>,
    pub(super) dashboard: Option<DashboardSection>,
    #[cfg(feature = "tun")]
    pub(super) tun: Option<TunSection>,
    pub(super) h2: Option<H2Section>,
    pub(super) udp_recv_buf_bytes: Option<usize>,
    pub(super) udp_send_buf_bytes: Option<usize>,
    /// SO_MARK for direct-route sockets. Linux only.
    pub(super) direct_fwmark: Option<u32>,
    /// Explicit uplink groups with per-group LB + probe config.
    pub(super) uplink_group: Option<Vec<UplinkGroupSection>>,
    /// Policy routes mapping CIDR prefixes to groups or `direct`/`drop`.
    pub(super) route: Option<Vec<RouteSection>>,
    /// Override the path where active-uplink state is persisted.
    /// Defaults to the config file path with extension replaced by
    /// `.state.toml` (e.g. `config.toml` → `config.state.toml`).
    /// Set to a writable location when the config directory is read-only
    /// (e.g. `/var/lib/outline-ws/state.toml`).
    pub(super) state_path: Option<PathBuf>,
    /// TCP session timeouts applied to SOCKS CONNECT and direct sessions.
    /// All fields optional; unset ones inherit compile-time defaults.
    pub(super) tcp_timeouts: Option<TcpTimeoutsSection>,
}

#[derive(Debug, Deserialize)]
pub(super) struct TcpTimeoutsSection {
    pub(super) post_client_eof_downstream_secs: Option<u64>,
    pub(super) upstream_response_secs: Option<u64>,
    pub(super) socks_upstream_idle_secs: Option<u64>,
    pub(super) direct_idle_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub(super) struct Socks5Section {
    pub(super) listen: Option<SocketAddr>,
    pub(super) username: Option<String>,
    pub(super) password: Option<String>,
    pub(super) users: Option<Vec<Socks5UserSection>>,
}

#[derive(Debug, Deserialize)]
pub(super) struct Socks5UserSection {
    pub(super) username: Option<String>,
    pub(super) password: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct OutlineSection {
    pub(super) transport: Option<UplinkTransport>,
    pub(super) tcp_ws_url: Option<Url>,
    pub(super) tcp_ws_mode: Option<WsTransportMode>,
    pub(super) udp_ws_url: Option<Url>,
    pub(super) udp_ws_mode: Option<WsTransportMode>,
    pub(super) tcp_addr: Option<ServerAddr>,
    pub(super) udp_addr: Option<ServerAddr>,
    pub(super) method: Option<CipherKind>,
    pub(super) password: Option<String>,
    pub(super) fwmark: Option<u32>,
    pub(super) ipv6_first: Option<bool>,
    pub(super) uplinks: Option<Vec<UplinkSection>>,
    pub(super) probe: Option<ProbeSection>,
    pub(super) load_balancing: Option<LoadBalancingSection>,
}

#[derive(Debug, Deserialize)]
pub(super) struct MetricsSection {
    pub(super) listen: Option<SocketAddr>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ControlSection {
    pub(super) listen: Option<SocketAddr>,
    pub(super) token: Option<String>,
    pub(super) token_file: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
pub(super) struct DashboardSection {
    /// Presence of [dashboard] enables the dashboard by default. Set
    /// `enabled = false` to keep the config block around without binding.
    pub(super) enabled: Option<bool>,
    pub(super) listen: Option<SocketAddr>,
    pub(super) refresh_interval_secs: Option<u64>,
    pub(super) instances: Option<Vec<DashboardInstanceSection>>,
}

#[derive(Debug, Deserialize)]
pub(super) struct DashboardInstanceSection {
    pub(super) name: Option<String>,
    pub(super) control_url: Option<Url>,
    pub(super) token: Option<String>,
    pub(super) token_file: Option<PathBuf>,
}

#[cfg(feature = "tun")]
#[derive(Debug, Deserialize)]
pub(super) struct TunSection {
    pub(super) path: Option<PathBuf>,
    pub(super) name: Option<String>,
    pub(super) mtu: Option<usize>,
    pub(super) max_flows: Option<usize>,
    pub(super) idle_timeout_secs: Option<u64>,
    pub(super) tcp: Option<TunTcpSection>,
    pub(super) defrag_max_fragment_sets: Option<usize>,
    pub(super) defrag_max_fragments_per_set: Option<usize>,
    pub(super) defrag_max_total_bytes: Option<usize>,
    pub(super) defrag_max_bytes_per_set: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(super) struct H2Section {
    pub(super) initial_stream_window_size: Option<u32>,
    pub(super) initial_connection_window_size: Option<u32>,
}

#[cfg(feature = "tun")]
#[derive(Debug, Deserialize)]
pub(super) struct TunTcpSection {
    pub(super) connect_timeout_secs: Option<u64>,
    pub(super) handshake_timeout_secs: Option<u64>,
    pub(super) half_close_timeout_secs: Option<u64>,
    pub(super) max_pending_server_bytes: Option<usize>,
    pub(super) backlog_abort_grace_secs: Option<u64>,
    pub(super) backlog_hard_limit_multiplier: Option<usize>,
    pub(super) backlog_no_progress_abort_secs: Option<u64>,
    pub(super) max_buffered_client_segments: Option<usize>,
    pub(super) max_buffered_client_bytes: Option<usize>,
    pub(super) max_retransmits: Option<u32>,
    pub(super) keepalive_idle_secs: Option<u64>,
    pub(super) keepalive_interval_secs: Option<u64>,
    pub(super) keepalive_max_probes: Option<u32>,
}

#[derive(Debug, Deserialize, Clone)]
pub(super) struct UplinkSection {
    pub(super) name: Option<String>,
    pub(super) transport: Option<UplinkTransport>,
    pub(super) tcp_ws_url: Option<Url>,
    pub(super) tcp_ws_mode: Option<WsTransportMode>,
    pub(super) udp_ws_url: Option<Url>,
    pub(super) udp_ws_mode: Option<WsTransportMode>,
    pub(super) tcp_addr: Option<ServerAddr>,
    pub(super) udp_addr: Option<ServerAddr>,
    pub(super) method: Option<CipherKind>,
    pub(super) password: Option<String>,
    pub(super) weight: Option<f64>,
    pub(super) fwmark: Option<u32>,
    pub(super) ipv6_first: Option<bool>,
    /// New: group this uplink belongs to. Required when `[[uplink_group]]` is
    /// declared; optional in legacy config (all uplinks land in `default`).
    pub(super) group: Option<String>,
}

/// New: explicit uplink group with its own LB config and probe override.
///
/// Top-level `[probe]` acts as a template; unspecified fields in
/// `[uplink_group.probe]` are inherited from it.
#[derive(Debug, Deserialize, Clone)]
pub(super) struct UplinkGroupSection {
    pub(super) name: Option<String>,
    pub(super) mode: Option<LoadBalancingMode>,
    pub(super) routing_scope: Option<RoutingScope>,
    pub(super) sticky_ttl_secs: Option<u64>,
    pub(super) hysteresis_ms: Option<u64>,
    pub(super) failure_cooldown_secs: Option<u64>,
    pub(super) tcp_chunk0_failover_timeout_secs: Option<u64>,
    pub(super) warm_standby_tcp: Option<usize>,
    pub(super) warm_standby_udp: Option<usize>,
    pub(super) rtt_ewma_alpha: Option<f64>,
    pub(super) failure_penalty_ms: Option<u64>,
    pub(super) failure_penalty_max_ms: Option<u64>,
    pub(super) failure_penalty_halflife_secs: Option<u64>,
    pub(super) h3_downgrade_secs: Option<u64>,
    pub(super) udp_ws_keepalive_secs: Option<u64>,
    pub(super) tcp_ws_standby_keepalive_secs: Option<u64>,
    pub(super) tcp_active_keepalive_secs: Option<u64>,
    pub(super) auto_failback: Option<bool>,
    /// Per-group override of top-level `[probe]`; unspecified fields inherit.
    pub(super) probe: Option<ProbeSection>,
}

/// New: policy routing rule.
///
/// Exactly one of `default = true` or non-empty `prefixes`/`file`/`files`
/// must be set.
/// `via` picks the target: either a group name or the reserved `"direct"`.
/// At most one of `fallback_via` / `fallback_direct` / `fallback_drop` is allowed.
///
/// Prefix sources are merged: inline `prefixes`, a single `file`, and any
/// additional paths in `files` all contribute to the same CIDR set.
#[derive(Debug, Deserialize, Clone)]
pub(super) struct RouteSection {
    pub(super) prefixes: Option<Vec<String>>,
    pub(super) file: Option<PathBuf>,
    pub(super) files: Option<Vec<PathBuf>>,
    pub(super) file_poll_secs: Option<u64>,
    pub(super) default: Option<bool>,
    pub(super) via: Option<String>,
    pub(super) fallback_via: Option<String>,
    pub(super) fallback_direct: Option<bool>,
    pub(super) fallback_drop: Option<bool>,
    /// If true, the rule matches addresses NOT in the prefix list.
    /// Useful for "tunnel only listed prefixes, everything else goes direct".
    pub(super) invert: Option<bool>,
}

#[derive(Debug, Deserialize, Clone)]
pub(super) struct ProbeSection {
    pub(super) interval_secs: Option<u64>,
    pub(super) timeout_secs: Option<u64>,
    pub(super) max_concurrent: Option<usize>,
    pub(super) max_dials: Option<usize>,
    pub(super) min_failures: Option<usize>,
    pub(super) attempts: Option<usize>,
    pub(super) ws: Option<WsProbeSection>,
    pub(super) http: Option<HttpProbeSection>,
    pub(super) dns: Option<DnsProbeSection>,
    pub(super) tcp: Option<TcpProbeSection>,
}

#[derive(Debug, Deserialize, Clone)]
pub(super) struct WsProbeSection {
    pub(super) enabled: Option<bool>,
}

#[derive(Debug, Deserialize, Clone)]
pub(super) struct HttpProbeSection {
    pub(super) url: Url,
}

#[derive(Debug, Deserialize, Clone)]
pub(super) struct DnsProbeSection {
    pub(super) server: String,
    pub(super) port: Option<u16>,
    pub(super) name: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub(super) struct TcpProbeSection {
    pub(super) host: String,
    pub(super) port: Option<u16>,
}

#[derive(Debug, Deserialize, Clone)]
pub(super) struct LoadBalancingSection {
    pub(super) mode: Option<LoadBalancingMode>,
    pub(super) routing_scope: Option<RoutingScope>,
    pub(super) sticky_ttl_secs: Option<u64>,
    pub(super) hysteresis_ms: Option<u64>,
    pub(super) failure_cooldown_secs: Option<u64>,
    pub(super) tcp_chunk0_failover_timeout_secs: Option<u64>,
    pub(super) warm_standby_tcp: Option<usize>,
    pub(super) warm_standby_udp: Option<usize>,
    pub(super) rtt_ewma_alpha: Option<f64>,
    pub(super) failure_penalty_ms: Option<u64>,
    pub(super) failure_penalty_max_ms: Option<u64>,
    pub(super) failure_penalty_halflife_secs: Option<u64>,
    pub(super) h3_downgrade_secs: Option<u64>,
    pub(super) udp_ws_keepalive_secs: Option<u64>,
    pub(super) tcp_ws_standby_keepalive_secs: Option<u64>,
    pub(super) tcp_active_keepalive_secs: Option<u64>,
    pub(super) auto_failback: Option<bool>,
}
