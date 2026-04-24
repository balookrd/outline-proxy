use std::net::IpAddr;
use std::time::Duration;

use anyhow::Result;
use serde::Deserialize;
use url::Url;

pub use outline_transport::{ServerAddr, VlessUdpMuxLimits, WsTransportMode};
pub use shadowsocks_crypto::CipherKind;
pub use socks5_proto::TargetAddr;

// ── UplinkTransport ──────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum UplinkTransport {
    #[default]
    #[serde(alias = "websocket")]
    Ws,
    Shadowsocks,
    /// VLESS over WebSocket (iteration 1: TCP + UDP, no Mux, no flow/xtls,
    /// TLS supplied by the WS URL scheme `wss://` going through rustls).
    Vless,
}

impl std::str::FromStr for UplinkTransport {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "ws" | "websocket" => Ok(Self::Ws),
            "shadowsocks" => Ok(Self::Shadowsocks),
            "vless" => Ok(Self::Vless),
            _ => anyhow::bail!("unsupported uplink transport: {s}"),
        }
    }
}

impl std::fmt::Display for UplinkTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Ws => "ws",
            Self::Shadowsocks => "shadowsocks",
            Self::Vless => "vless",
        })
    }
}

// ── UplinkGroupConfig ────────────────────────────────────────────────────────

/// A named collection of uplinks sharing a single LB + probe configuration.
#[derive(Debug, Clone)]
pub struct UplinkGroupConfig {
    pub name: String,
    pub uplinks: Vec<UplinkConfig>,
    pub probe: ProbeConfig,
    pub load_balancing: LoadBalancingConfig,
}

// ── UplinkConfig ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct UplinkConfig {
    pub name: String,
    pub transport: UplinkTransport,
    pub tcp_ws_url: Option<Url>,
    pub tcp_ws_mode: WsTransportMode,
    pub udp_ws_url: Option<Url>,
    pub udp_ws_mode: WsTransportMode,
    pub tcp_addr: Option<ServerAddr>,
    pub udp_addr: Option<ServerAddr>,
    pub cipher: CipherKind,
    pub password: String,
    pub weight: f64,
    pub fwmark: Option<u32>,
    pub ipv6_first: bool,
    /// Present when `transport = "vless"`. Raw 16-byte user id; parsed from
    /// the config string via `outline_transport::vless::parse_uuid`.
    pub vless_uuid: Option<[u8; 16]>,
}

impl UplinkConfig {
    pub fn supports_udp(&self) -> bool {
        match self.transport {
            UplinkTransport::Ws | UplinkTransport::Vless => self.udp_ws_url.is_some(),
            UplinkTransport::Shadowsocks => self.udp_addr.is_some(),
        }
    }
}

// ── ProbeConfig ──────────────────────────────────────────────────────────────

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
    pub fn target_addr(&self) -> Result<TargetAddr> {
        if let Ok(ip) = self.server.parse::<IpAddr>() {
            Ok(match ip {
                IpAddr::V4(v4) => TargetAddr::IpV4(v4, self.port),
                IpAddr::V6(v6) => TargetAddr::IpV6(v6, self.port),
            })
        } else {
            Ok(TargetAddr::Domain(self.server.clone(), self.port))
        }
    }
}

#[derive(Debug, Clone)]
pub struct TcpProbeConfig {
    pub host: String,
    pub port: u16,
}

// ── LoadBalancingConfig ──────────────────────────────────────────────────────

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
    /// These keepalives preserve the transport path but do NOT reset the
    /// session-level `socks_upstream_idle` watcher; only real payload bytes do.
    /// None disables per-session keepalive (relies solely on OS TCP keepalive).
    pub tcp_active_keepalive_interval: Option<Duration>,
    /// When false (default), the active uplink is only replaced when it fails.
    /// When true, traffic returns to the highest-priority healthy uplink once it
    /// has been stable for `min_failures` consecutive probe cycles.
    pub auto_failback: bool,
    /// Bounds on the per-uplink VLESS UDP session mux: max concurrent sessions
    /// (LRU-evicted beyond the cap), per-session idle timeout, and janitor
    /// scan interval. Ignored for non-VLESS uplinks.
    pub vless_udp_mux_limits: VlessUdpMuxLimits,
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
