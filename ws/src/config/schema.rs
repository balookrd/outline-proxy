use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;
use url::Url;

use crate::types::{CipherKind, ServerAddr, UplinkTransport, WsTransportMode};

use super::types::{LoadBalancingMode, RoutingScope};

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
    pub(super) tun: Option<TunSection>,
    pub(super) h2: Option<H2Section>,
    pub(super) udp_recv_buf_bytes: Option<usize>,
    pub(super) udp_send_buf_bytes: Option<usize>,
    /// Explicit uplink groups with per-group LB + probe config.
    pub(super) uplink_group: Option<Vec<UplinkGroupSection>>,
    /// Policy routes mapping CIDR prefixes to groups or `direct`/`drop`.
    pub(super) route: Option<Vec<RouteSection>>,
    /// Legacy `[bypass]` section — retained only to surface a migration error
    /// instead of silently ignoring the table.
    pub(super) bypass: Option<toml::Value>,
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
/// Exactly one of `default = true` or non-empty `prefixes`/`file` must be set.
/// `via` picks the target: either a group name or the reserved `"direct"`.
/// At most one of `fallback_via` / `fallback_direct` / `fallback_drop` is allowed.
#[derive(Debug, Deserialize, Clone)]
pub(super) struct RouteSection {
    pub(super) prefixes: Option<Vec<String>>,
    pub(super) file: Option<PathBuf>,
    pub(super) file_poll_secs: Option<u64>,
    pub(super) default: Option<bool>,
    pub(super) via: Option<String>,
    pub(super) fallback_via: Option<String>,
    pub(super) fallback_direct: Option<bool>,
    pub(super) fallback_drop: Option<bool>,
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

pub(crate) fn resolve_outline_section(file: &ConfigFile) -> Option<OutlineSection> {
    let top_level_present = file.tcp_ws_url.is_some()
        || file.transport.is_some()
        || file.tcp_ws_mode.is_some()
        || file.udp_ws_url.is_some()
        || file.udp_ws_mode.is_some()
        || file.tcp_addr.is_some()
        || file.udp_addr.is_some()
        || file.method.is_some()
        || file.password.is_some()
        || file.fwmark.is_some()
        || file.ipv6_first.is_some()
        || file.uplinks.is_some()
        || file.probe.is_some()
        || file.load_balancing.is_some();

    match (top_level_present, file.outline.clone()) {
        (false, None) => None,
        (false, Some(legacy)) => Some(legacy),
        (true, None) => Some(OutlineSection {
            transport: file.transport,
            tcp_ws_url: file.tcp_ws_url.clone(),
            tcp_ws_mode: file.tcp_ws_mode,
            udp_ws_url: file.udp_ws_url.clone(),
            udp_ws_mode: file.udp_ws_mode,
            tcp_addr: file.tcp_addr.clone(),
            udp_addr: file.udp_addr.clone(),
            method: file.method,
            password: file.password.clone(),
            fwmark: file.fwmark,
            ipv6_first: file.ipv6_first,
            uplinks: file.uplinks.clone(),
            probe: file.probe.clone(),
            load_balancing: file.load_balancing.clone(),
        }),
        (true, Some(legacy)) => Some(OutlineSection {
            transport: file.transport.or(legacy.transport),
            tcp_ws_url: file.tcp_ws_url.clone().or(legacy.tcp_ws_url),
            tcp_ws_mode: file.tcp_ws_mode.or(legacy.tcp_ws_mode),
            udp_ws_url: file.udp_ws_url.clone().or(legacy.udp_ws_url),
            udp_ws_mode: file.udp_ws_mode.or(legacy.udp_ws_mode),
            tcp_addr: file.tcp_addr.clone().or(legacy.tcp_addr),
            udp_addr: file.udp_addr.clone().or(legacy.udp_addr),
            method: file.method.or(legacy.method),
            password: file.password.clone().or(legacy.password),
            fwmark: file.fwmark.or(legacy.fwmark),
            ipv6_first: file.ipv6_first.or(legacy.ipv6_first),
            uplinks: file.uplinks.clone().or(legacy.uplinks),
            probe: file.probe.clone().or(legacy.probe),
            load_balancing: file.load_balancing.clone().or(legacy.load_balancing),
        }),
    }
}
