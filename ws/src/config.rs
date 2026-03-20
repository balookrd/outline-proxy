use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use serde::Deserialize;
use tokio::fs;
use url::Url;

use crate::types::{CipherKind, WsTransportMode};

#[derive(Debug, Clone, Parser)]
#[command(version, about = "SOCKS5 -> Outline over WebSocket proxy")]
pub struct Args {
    #[arg(long, env = "PROXY_CONFIG", default_value = "config.toml")]
    pub config: PathBuf,

    #[arg(long, env = "SOCKS5_LISTEN")]
    pub listen: Option<SocketAddr>,

    #[arg(long, env = "SOCKS5_USERNAME")]
    pub socks5_username: Option<String>,

    #[arg(long, env = "SOCKS5_PASSWORD")]
    pub socks5_password: Option<String>,

    #[arg(long, env = "OUTLINE_TCP_WS_URL")]
    pub tcp_ws_url: Option<Url>,

    #[arg(long, env = "OUTLINE_TCP_WS_MODE", help = "http1, h2, or h3")]
    pub tcp_ws_mode: Option<WsTransportMode>,

    #[arg(long, env = "OUTLINE_UDP_WS_URL")]
    pub udp_ws_url: Option<Url>,

    #[arg(long, env = "OUTLINE_UDP_WS_MODE", help = "http1, h2, or h3")]
    pub udp_ws_mode: Option<WsTransportMode>,

    #[arg(long, env = "SHADOWSOCKS_METHOD")]
    pub method: Option<CipherKind>,

    #[arg(long, env = "SHADOWSOCKS_PASSWORD")]
    pub password: Option<String>,

    #[arg(long, env = "OUTLINE_FWMARK")]
    pub fwmark: Option<u32>,

    #[arg(long, env = "METRICS_LISTEN")]
    pub metrics_listen: Option<SocketAddr>,

    #[arg(long, env = "MEMORY_TRIM_INTERVAL_SECS")]
    pub memory_trim_interval_secs: Option<u64>,

    #[arg(long, env = "TUN_PATH")]
    pub tun_path: Option<PathBuf>,

    #[arg(long, env = "TUN_NAME")]
    pub tun_name: Option<String>,

    #[arg(long, env = "TUN_MTU")]
    pub tun_mtu: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub listen: SocketAddr,
    pub socks5_auth: Option<Socks5AuthConfig>,
    pub uplinks: Vec<UplinkConfig>,
    pub probe: ProbeConfig,
    pub load_balancing: LoadBalancingConfig,
    pub metrics: Option<MetricsConfig>,
    pub memory_trim_interval: Option<Duration>,
    pub tun: Option<TunConfig>,
}

#[derive(Debug, Clone)]
pub struct UplinkConfig {
    pub name: String,
    pub tcp_ws_url: Url,
    pub tcp_ws_mode: WsTransportMode,
    pub udp_ws_url: Option<Url>,
    pub udp_ws_mode: WsTransportMode,
    pub cipher: CipherKind,
    pub password: String,
    pub weight: f64,
    pub fwmark: Option<u32>,
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
    /// Number of connection attempts per probe cycle. If any attempt succeeds the
    /// cycle is counted as a success. Retries are separated by a short pause
    /// (500 ms) so the total time per cycle can be up to
    /// `attempts × (timeout + 500 ms)`. Default: 2.
    pub attempts: usize,
    pub ws: WsProbeConfig,
    pub http: Option<HttpProbeConfig>,
    pub dns: Option<DnsProbeConfig>,
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

#[derive(Debug, Clone)]
pub struct LoadBalancingConfig {
    pub mode: LoadBalancingMode,
    pub routing_scope: RoutingScope,
    pub sticky_ttl: Duration,
    pub hysteresis: Duration,
    pub failure_cooldown: Duration,
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
}

#[derive(Debug, Clone)]
pub struct TunTcpConfig {
    pub connect_timeout: Duration,
    pub handshake_timeout: Duration,
    pub half_close_timeout: Duration,
    pub max_pending_server_bytes: usize,
    pub max_buffered_client_segments: usize,
    pub max_buffered_client_bytes: usize,
    pub max_retransmits: u32,
}

#[derive(Debug, Deserialize)]
struct ConfigFile {
    socks5: Option<Socks5Section>,
    tcp_ws_url: Option<Url>,
    tcp_ws_mode: Option<WsTransportMode>,
    udp_ws_url: Option<Url>,
    udp_ws_mode: Option<WsTransportMode>,
    method: Option<CipherKind>,
    password: Option<String>,
    fwmark: Option<u32>,
    uplinks: Option<Vec<UplinkSection>>,
    probe: Option<ProbeSection>,
    load_balancing: Option<LoadBalancingSection>,
    outline: Option<OutlineSection>,
    metrics: Option<MetricsSection>,
    memory_trim_interval_secs: Option<u64>,
    tun: Option<TunSection>,
}

#[derive(Debug, Deserialize)]
struct Socks5Section {
    listen: Option<SocketAddr>,
    username: Option<String>,
    password: Option<String>,
    users: Option<Vec<Socks5UserSection>>,
}

#[derive(Debug, Deserialize)]
struct Socks5UserSection {
    username: Option<String>,
    password: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct OutlineSection {
    tcp_ws_url: Option<Url>,
    tcp_ws_mode: Option<WsTransportMode>,
    udp_ws_url: Option<Url>,
    udp_ws_mode: Option<WsTransportMode>,
    method: Option<CipherKind>,
    password: Option<String>,
    fwmark: Option<u32>,
    uplinks: Option<Vec<UplinkSection>>,
    probe: Option<ProbeSection>,
    load_balancing: Option<LoadBalancingSection>,
}

#[derive(Debug, Deserialize)]
struct MetricsSection {
    listen: Option<SocketAddr>,
}

#[derive(Debug, Deserialize)]
struct TunSection {
    path: Option<PathBuf>,
    name: Option<String>,
    mtu: Option<usize>,
    max_flows: Option<usize>,
    idle_timeout_secs: Option<u64>,
    tcp: Option<TunTcpSection>,
}

#[derive(Debug, Deserialize)]
struct TunTcpSection {
    connect_timeout_secs: Option<u64>,
    handshake_timeout_secs: Option<u64>,
    half_close_timeout_secs: Option<u64>,
    max_pending_server_bytes: Option<usize>,
    max_buffered_client_segments: Option<usize>,
    max_buffered_client_bytes: Option<usize>,
    max_retransmits: Option<u32>,
}

#[derive(Debug, Deserialize, Clone)]
struct UplinkSection {
    name: Option<String>,
    tcp_ws_url: Option<Url>,
    tcp_ws_mode: Option<WsTransportMode>,
    udp_ws_url: Option<Url>,
    udp_ws_mode: Option<WsTransportMode>,
    method: Option<CipherKind>,
    password: Option<String>,
    weight: Option<f64>,
    fwmark: Option<u32>,
}

#[derive(Debug, Deserialize, Clone)]
struct ProbeSection {
    interval_secs: Option<u64>,
    timeout_secs: Option<u64>,
    max_concurrent: Option<usize>,
    max_dials: Option<usize>,
    min_failures: Option<usize>,
    attempts: Option<usize>,
    ws: Option<WsProbeSection>,
    http: Option<HttpProbeSection>,
    dns: Option<DnsProbeSection>,
}

#[derive(Debug, Deserialize, Clone)]
struct WsProbeSection {
    enabled: Option<bool>,
}

#[derive(Debug, Deserialize, Clone)]
struct HttpProbeSection {
    url: Url,
}

#[derive(Debug, Deserialize, Clone)]
struct DnsProbeSection {
    server: String,
    port: Option<u16>,
    name: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct LoadBalancingSection {
    mode: Option<LoadBalancingMode>,
    routing_scope: Option<RoutingScope>,
    sticky_ttl_secs: Option<u64>,
    hysteresis_ms: Option<u64>,
    failure_cooldown_secs: Option<u64>,
    warm_standby_tcp: Option<usize>,
    warm_standby_udp: Option<usize>,
    rtt_ewma_alpha: Option<f64>,
    failure_penalty_ms: Option<u64>,
    failure_penalty_max_ms: Option<u64>,
    failure_penalty_halflife_secs: Option<u64>,
    h3_downgrade_secs: Option<u64>,
    udp_ws_keepalive_secs: Option<u64>,
    tcp_ws_standby_keepalive_secs: Option<u64>,
    auto_failback: Option<bool>,
}

pub async fn load_config(path: &Path, args: &Args) -> Result<AppConfig> {
    let file = if path.exists() {
        let raw = fs::read_to_string(path)
            .await
            .with_context(|| format!("failed to read {}", path.display()))?;
        Some(
            toml::from_str::<ConfigFile>(&raw)
                .with_context(|| format!("failed to parse {}", path.display()))?,
        )
    } else {
        None
    };

    let socks5 = file.as_ref().and_then(|f| f.socks5.as_ref());
    let outline = file.as_ref().and_then(resolve_outline_section);
    let metrics_section = file.as_ref().and_then(|f| f.metrics.as_ref());
    let tun_section = file.as_ref().and_then(|f| f.tun.as_ref());

    let listen = args
        .listen
        .or_else(|| socks5.and_then(|s| s.listen))
        .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 1080)));
    let socks5_auth = load_socks5_auth_config(socks5, args)?;

    let uplinks = load_uplinks(outline.as_ref(), args)?;
    let probe = load_probe_config(outline.as_ref())?;
    let load_balancing = load_balancing_config(outline.as_ref())?;
    let metrics = args
        .metrics_listen
        .or_else(|| metrics_section.and_then(|section| section.listen))
        .map(|listen| MetricsConfig { listen });
    let memory_trim_interval = load_memory_trim_interval(file.as_ref(), args)?;
    let tun = load_tun_config(tun_section, args)?;

    Ok(AppConfig {
        listen,
        socks5_auth,
        uplinks,
        probe,
        load_balancing,
        metrics,
        memory_trim_interval,
        tun,
    })
}

fn load_socks5_auth_config(
    socks5: Option<&Socks5Section>,
    args: &Args,
) -> Result<Option<Socks5AuthConfig>> {
    let cli_username = args.socks5_username.clone();
    let cli_password = args.socks5_password.clone();

    if cli_username.is_some() || cli_password.is_some() {
        return match (cli_username, cli_password) {
            (Some(username), Some(password)) => Ok(Some(Socks5AuthConfig {
                users: vec![validate_socks5_auth_user(
                    Socks5AuthUserConfig { username, password },
                    "CLI socks5 auth user",
                )?],
            })),
            (Some(_), None) => {
                bail!(
                    "missing socks5 password: pass --socks5-password together with --socks5-username"
                )
            }
            (None, Some(_)) => {
                bail!(
                    "missing socks5 username: pass --socks5-username together with --socks5-password"
                )
            }
            (None, None) => unreachable!("checked above"),
        };
    }

    let Some(socks5) = socks5 else {
        return Ok(None);
    };

    let users = match (&socks5.users, &socks5.username, &socks5.password) {
        (Some(users), None, None) => users
            .iter()
            .enumerate()
            .map(|(index, user)| {
                let username = user.username.clone().ok_or_else(|| {
                    anyhow!(
                        "missing socks5 user username in [socks5].users entry {}",
                        index + 1
                    )
                })?;
                let password = user.password.clone().ok_or_else(|| {
                    anyhow!(
                        "missing socks5 user password in [socks5].users entry {}",
                        index + 1
                    )
                })?;
                validate_socks5_auth_user(
                    Socks5AuthUserConfig { username, password },
                    &format!("socks5 user {}", index + 1),
                )
            })
            .collect::<Result<Vec<_>>>()?,
        (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
            bail!(
                "use either [socks5].username/password for a single user or [[socks5.users]] for multiple users, not both"
            )
        }
        (None, Some(username), Some(password)) => vec![validate_socks5_auth_user(
            Socks5AuthUserConfig {
                username: username.clone(),
                password: password.clone(),
            },
            "socks5 auth user",
        )?],
        (None, Some(_), None) => {
            bail!("missing socks5 password: set [socks5].password together with [socks5].username")
        }
        (None, None, Some(_)) => {
            bail!("missing socks5 username: set [socks5].username together with [socks5].password")
        }
        (None, None, None) => Vec::new(),
    };

    if users.is_empty() {
        return Ok(None);
    }

    Ok(Some(Socks5AuthConfig { users }))
}

fn validate_socks5_auth_user(
    user: Socks5AuthUserConfig,
    context_label: &str,
) -> Result<Socks5AuthUserConfig> {
    if user.username.len() > u8::MAX as usize {
        bail!("{context_label} username is too long; maximum is 255 bytes");
    }
    if user.password.len() > u8::MAX as usize {
        bail!("{context_label} password is too long; maximum is 255 bytes");
    }
    Ok(user)
}

fn resolve_outline_section(file: &ConfigFile) -> Option<OutlineSection> {
    let top_level_present = file.tcp_ws_url.is_some()
        || file.tcp_ws_mode.is_some()
        || file.udp_ws_url.is_some()
        || file.udp_ws_mode.is_some()
        || file.method.is_some()
        || file.password.is_some()
        || file.fwmark.is_some()
        || file.uplinks.is_some()
        || file.probe.is_some()
        || file.load_balancing.is_some();

    match (top_level_present, file.outline.clone()) {
        (false, None) => None,
        (false, Some(legacy)) => Some(legacy),
        (true, None) => Some(OutlineSection {
            tcp_ws_url: file.tcp_ws_url.clone(),
            tcp_ws_mode: file.tcp_ws_mode,
            udp_ws_url: file.udp_ws_url.clone(),
            udp_ws_mode: file.udp_ws_mode,
            method: file.method,
            password: file.password.clone(),
            fwmark: file.fwmark,
            uplinks: file.uplinks.clone(),
            probe: file.probe.clone(),
            load_balancing: file.load_balancing.clone(),
        }),
        (true, Some(legacy)) => Some(OutlineSection {
            tcp_ws_url: file.tcp_ws_url.clone().or(legacy.tcp_ws_url),
            tcp_ws_mode: file.tcp_ws_mode.or(legacy.tcp_ws_mode),
            udp_ws_url: file.udp_ws_url.clone().or(legacy.udp_ws_url),
            udp_ws_mode: file.udp_ws_mode.or(legacy.udp_ws_mode),
            method: file.method.or(legacy.method),
            password: file.password.clone().or(legacy.password),
            fwmark: file.fwmark.or(legacy.fwmark),
            uplinks: file.uplinks.clone().or(legacy.uplinks),
            probe: file.probe.clone().or(legacy.probe),
            load_balancing: file.load_balancing.clone().or(legacy.load_balancing),
        }),
    }
}

impl ProbeConfig {
    pub fn enabled(&self) -> bool {
        self.ws.enabled || self.http.is_some() || self.dns.is_some()
    }
}

impl DnsProbeConfig {
    pub fn target_addr(&self) -> Result<crate::types::TargetAddr> {
        if let Ok(ip) = self.server.parse::<IpAddr>() {
            Ok(match ip {
                IpAddr::V4(v4) => crate::types::TargetAddr::IpV4(v4, self.port),
                IpAddr::V6(v6) => crate::types::TargetAddr::IpV6(v6, self.port),
            })
        } else {
            Ok(crate::types::TargetAddr::Domain(
                self.server.clone(),
                self.port,
            ))
        }
    }
}

fn load_uplinks(outline: Option<&OutlineSection>, args: &Args) -> Result<Vec<UplinkConfig>> {
    let cli_override_requested = args.tcp_ws_url.is_some()
        || args.tcp_ws_mode.is_some()
        || args.udp_ws_url.is_some()
        || args.udp_ws_mode.is_some()
        || args.method.is_some()
        || args.password.is_some()
        || args.fwmark.is_some();

    if cli_override_requested {
        return Ok(vec![build_uplink(
            "cli".to_string(),
            args.tcp_ws_url
                .clone()
                .or_else(|| outline.and_then(|o| o.tcp_ws_url.clone())),
            args.tcp_ws_mode
                .or_else(|| outline.and_then(|o| o.tcp_ws_mode)),
            args.udp_ws_url
                .clone()
                .or_else(|| outline.and_then(|o| o.udp_ws_url.clone())),
            args.udp_ws_mode
                .or_else(|| outline.and_then(|o| o.udp_ws_mode)),
            args.method.or_else(|| outline.and_then(|o| o.method)),
            args.password
                .clone()
                .or_else(|| outline.and_then(|o| o.password.clone())),
            Some(1.0),
            args.fwmark.or_else(|| outline.and_then(|o| o.fwmark)),
        )?]);
    }

    if let Some(uplinks) = outline.and_then(|o| o.uplinks.as_ref()) {
        let mut resolved = Vec::with_capacity(uplinks.len());
        for (index, uplink) in uplinks.iter().enumerate() {
            resolved.push(build_uplink(
                uplink
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("uplink-{}", index + 1)),
                uplink.tcp_ws_url.clone(),
                uplink.tcp_ws_mode,
                uplink.udp_ws_url.clone(),
                uplink.udp_ws_mode,
                uplink.method,
                uplink.password.clone(),
                uplink.weight,
                uplink.fwmark,
            )?);
        }
        if resolved.is_empty() {
            bail!("uplinks is present but empty");
        }
        return Ok(resolved);
    }

    Ok(vec![build_uplink(
        "default".to_string(),
        outline.and_then(|o| o.tcp_ws_url.clone()),
        outline.and_then(|o| o.tcp_ws_mode),
        outline.and_then(|o| o.udp_ws_url.clone()),
        outline.and_then(|o| o.udp_ws_mode),
        outline.and_then(|o| o.method),
        outline.and_then(|o| o.password.clone()),
        Some(1.0),
        outline.and_then(|o| o.fwmark),
    )?])
}

fn build_uplink(
    name: String,
    tcp_ws_url: Option<Url>,
    tcp_ws_mode: Option<WsTransportMode>,
    udp_ws_url: Option<Url>,
    udp_ws_mode: Option<WsTransportMode>,
    cipher: Option<CipherKind>,
    password: Option<String>,
    weight: Option<f64>,
    fwmark: Option<u32>,
) -> Result<UplinkConfig> {
    let weight = weight.unwrap_or(1.0);
    if !weight.is_finite() || weight <= 0.0 {
        bail!("uplink weight must be a finite positive number");
    }
    Ok(UplinkConfig {
        name,
        tcp_ws_url: tcp_ws_url.ok_or_else(|| {
            anyhow!("missing tcp_ws_url: set it in config.toml or pass --tcp-ws-url")
        })?,
        tcp_ws_mode: tcp_ws_mode.unwrap_or_default(),
        udp_ws_url,
        udp_ws_mode: udp_ws_mode.unwrap_or_default(),
        cipher: cipher.unwrap_or(CipherKind::Chacha20IetfPoly1305),
        password: password
            .ok_or_else(|| anyhow!("missing password: set it in config.toml or pass --password"))?,
        weight,
        fwmark,
    })
}

fn load_probe_config(outline: Option<&OutlineSection>) -> Result<ProbeConfig> {
    let probe = outline.and_then(|o| o.probe.as_ref());
    let http = probe
        .and_then(|p| p.http.as_ref())
        .map(|http| HttpProbeConfig {
            url: http.url.clone(),
        });
    let dns = probe
        .and_then(|p| p.dns.as_ref())
        .map(|dns| DnsProbeConfig {
            server: dns.server.clone(),
            port: dns.port.unwrap_or(53),
            name: dns
                .name
                .clone()
                .unwrap_or_else(|| "example.com".to_string()),
        });

    Ok(ProbeConfig {
        interval: Duration::from_secs(probe.and_then(|p| p.interval_secs).unwrap_or(30)),
        timeout: Duration::from_secs(probe.and_then(|p| p.timeout_secs).unwrap_or(10)),
        max_concurrent: probe.and_then(|p| p.max_concurrent).unwrap_or(4).max(1),
        max_dials: probe.and_then(|p| p.max_dials).unwrap_or(2).max(1),
        min_failures: probe.and_then(|p| p.min_failures).unwrap_or(3).max(1),
        attempts: probe.and_then(|p| p.attempts).unwrap_or(2).max(1),
        ws: WsProbeConfig {
            enabled: probe
                .and_then(|p| p.ws.as_ref())
                .and_then(|ws| ws.enabled)
                .unwrap_or(false),
        },
        http,
        dns,
    })
}

fn load_balancing_config(outline: Option<&OutlineSection>) -> Result<LoadBalancingConfig> {
    let lb = outline.and_then(|o| o.load_balancing.as_ref());
    let rtt_ewma_alpha = lb.and_then(|l| l.rtt_ewma_alpha).unwrap_or(0.3);
    if !rtt_ewma_alpha.is_finite() || !(0.0 < rtt_ewma_alpha && rtt_ewma_alpha <= 1.0) {
        bail!("load_balancing.rtt_ewma_alpha must be in the range (0, 1]");
    }
    Ok(LoadBalancingConfig {
        mode: lb
            .and_then(|l| l.mode)
            .unwrap_or(LoadBalancingMode::ActiveActive),
        routing_scope: lb
            .and_then(|l| l.routing_scope)
            .unwrap_or(RoutingScope::PerFlow),
        sticky_ttl: Duration::from_secs(lb.and_then(|l| l.sticky_ttl_secs).unwrap_or(300)),
        hysteresis: Duration::from_millis(lb.and_then(|l| l.hysteresis_ms).unwrap_or(50)),
        failure_cooldown: Duration::from_secs(
            lb.and_then(|l| l.failure_cooldown_secs).unwrap_or(10),
        ),
        warm_standby_tcp: lb.and_then(|l| l.warm_standby_tcp).unwrap_or(0),
        warm_standby_udp: lb.and_then(|l| l.warm_standby_udp).unwrap_or(0),
        rtt_ewma_alpha,
        failure_penalty: Duration::from_millis(
            lb.and_then(|l| l.failure_penalty_ms).unwrap_or(500),
        ),
        failure_penalty_max: Duration::from_millis(
            lb.and_then(|l| l.failure_penalty_max_ms).unwrap_or(30_000),
        ),
        failure_penalty_halflife: Duration::from_secs(
            lb.and_then(|l| l.failure_penalty_halflife_secs)
                .unwrap_or(60),
        ),
        h3_downgrade_duration: Duration::from_secs(
            lb.and_then(|l| l.h3_downgrade_secs).unwrap_or(60),
        ),
        udp_ws_keepalive_interval: lb
            .and_then(|l| l.udp_ws_keepalive_secs)
            .map(Duration::from_secs)
            .or(Some(Duration::from_secs(60))),
        tcp_ws_standby_keepalive_interval: lb
            .and_then(|l| l.tcp_ws_standby_keepalive_secs)
            .map(Duration::from_secs)
            .or(Some(Duration::from_secs(30))),
        auto_failback: lb.and_then(|l| l.auto_failback).unwrap_or(false),
    })
}

fn load_tun_config(tun: Option<&TunSection>, args: &Args) -> Result<Option<TunConfig>> {
    let path = args
        .tun_path
        .clone()
        .or_else(|| tun.and_then(|section| section.path.clone()));
    let name = args
        .tun_name
        .clone()
        .or_else(|| tun.and_then(|section| section.name.clone()));
    let mtu = args
        .tun_mtu
        .or_else(|| tun.and_then(|section| section.mtu))
        .unwrap_or(1500);
    let max_flows = tun.and_then(|section| section.max_flows).unwrap_or(4096);
    let idle_timeout = Duration::from_secs(
        tun.and_then(|section| section.idle_timeout_secs)
            .unwrap_or(300),
    );

    if path.is_none() && name.is_none() {
        return Ok(None);
    }

    let path =
        path.ok_or_else(|| anyhow!("missing tun.path: set it in config.toml or pass --tun-path"))?;

    if mtu < 1280 {
        bail!("tun mtu must be at least 1280");
    }
    if max_flows == 0 {
        bail!("tun max_flows must be greater than zero");
    }
    if idle_timeout < Duration::from_secs(5) {
        bail!("tun idle_timeout_secs must be at least 5");
    }

    let tcp_section = tun.and_then(|section| section.tcp.as_ref());
    let tcp = TunTcpConfig {
        connect_timeout: Duration::from_secs(
            tcp_section
                .and_then(|section| section.connect_timeout_secs)
                .unwrap_or(10),
        ),
        handshake_timeout: Duration::from_secs(
            tcp_section
                .and_then(|section| section.handshake_timeout_secs)
                .unwrap_or(15),
        ),
        half_close_timeout: Duration::from_secs(
            tcp_section
                .and_then(|section| section.half_close_timeout_secs)
                .unwrap_or(60),
        ),
        max_pending_server_bytes: tcp_section
            .and_then(|section| section.max_pending_server_bytes)
            .unwrap_or(1_048_576),
        max_buffered_client_segments: tcp_section
            .and_then(|section| section.max_buffered_client_segments)
            .unwrap_or(4096),
        max_buffered_client_bytes: tcp_section
            .and_then(|section| section.max_buffered_client_bytes)
            .unwrap_or(262_144),
        max_retransmits: tcp_section
            .and_then(|section| section.max_retransmits)
            .unwrap_or(12),
    };
    if tcp.connect_timeout < Duration::from_secs(1) {
        bail!("tun.tcp.connect_timeout_secs must be at least 1");
    }
    if tcp.handshake_timeout < Duration::from_secs(1) {
        bail!("tun.tcp.handshake_timeout_secs must be at least 1");
    }
    if tcp.half_close_timeout < Duration::from_secs(1) {
        bail!("tun.tcp.half_close_timeout_secs must be at least 1");
    }
    if tcp.max_pending_server_bytes < 16_384 {
        bail!("tun.tcp.max_pending_server_bytes must be at least 16384");
    }
    if tcp.max_buffered_client_segments == 0 {
        bail!("tun.tcp.max_buffered_client_segments must be greater than zero");
    }
    if tcp.max_buffered_client_bytes < 16_384 {
        bail!("tun.tcp.max_buffered_client_bytes must be at least 16384");
    }
    if tcp.max_buffered_client_bytes > 262_144 {
        bail!("tun.tcp.max_buffered_client_bytes must be at most 262144");
    }
    if tcp.max_retransmits == 0 {
        bail!("tun.tcp.max_retransmits must be greater than zero");
    }

    #[cfg(target_os = "linux")]
    if name.is_none() {
        bail!("missing tun.name: Linux TUN attach requires --tun-name or [tun].name");
    }

    Ok(Some(TunConfig {
        path,
        name,
        mtu,
        max_flows,
        idle_timeout,
        tcp,
    }))
}

fn load_memory_trim_interval(file: Option<&ConfigFile>, args: &Args) -> Result<Option<Duration>> {
    let interval_secs = args
        .memory_trim_interval_secs
        .or_else(|| file.and_then(|config| config.memory_trim_interval_secs))
        .or(Some(60));
    match interval_secs {
        None => Ok(None),
        Some(0) => Ok(None),
        Some(seconds) => Ok(Some(Duration::from_secs(seconds))),
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::time::Duration;

    use clap::Parser;

    use super::{
        ConfigFile, LoadBalancingMode, RoutingScope, load_config, resolve_outline_section,
    };

    #[test]
    fn config_deserializes() {
        let cfg = r#"
            tcp_ws_url = "wss://example.com/secret/tcp"
            tcp_ws_mode = "h2"
            udp_ws_url = "wss://example.com/secret/udp"
            udp_ws_mode = "h2"
            method = "chacha20-ietf-poly1305"
            password = "Secret0"

            [socks5]
            listen = "127.0.0.1:1080"
            username = "alice"
            password = "secret"
        "#;
        let parsed: ConfigFile = toml::from_str(cfg).unwrap();
        let socks5 = parsed.socks5.unwrap();
        assert_eq!(
            socks5.listen.unwrap(),
            SocketAddr::from(([127, 0, 0, 1], 1080))
        );
        assert_eq!(socks5.username.as_deref(), Some("alice"));
        assert_eq!(socks5.password.as_deref(), Some("secret"));
    }

    #[tokio::test]
    async fn load_config_enables_single_optional_socks5_auth() {
        let path = std::env::temp_dir().join("outline-ws-rust-socks5-auth.toml");
        std::fs::write(
            &path,
            r#"
            tcp_ws_url = "wss://example.com/secret/tcp"
            method = "chacha20-ietf-poly1305"
            password = "Secret0"

            [socks5]
            listen = "127.0.0.1:1080"
            username = "alice"
            password = "secret"
            "#,
        )
        .unwrap();

        let args = super::Args::parse_from(["test"]);
        let config = load_config(&path, &args).await.unwrap();
        assert_eq!(
            config.socks5_auth,
            Some(super::Socks5AuthConfig {
                users: vec![super::Socks5AuthUserConfig {
                    username: "alice".to_string(),
                    password: "secret".to_string(),
                }],
            })
        );

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn load_config_enables_multiple_socks5_users() {
        let path = std::env::temp_dir().join("outline-ws-rust-socks5-auth-users.toml");
        std::fs::write(
            &path,
            r#"
            tcp_ws_url = "wss://example.com/secret/tcp"
            method = "chacha20-ietf-poly1305"
            password = "Secret0"

            [socks5]
            listen = "127.0.0.1:1080"

            [[socks5.users]]
            username = "alice"
            password = "secret1"

            [[socks5.users]]
            username = "bob"
            password = "secret2"
            "#,
        )
        .unwrap();

        let args = super::Args::parse_from(["test"]);
        let config = load_config(&path, &args).await.unwrap();
        assert_eq!(
            config.socks5_auth,
            Some(super::Socks5AuthConfig {
                users: vec![
                    super::Socks5AuthUserConfig {
                        username: "alice".to_string(),
                        password: "secret1".to_string(),
                    },
                    super::Socks5AuthUserConfig {
                        username: "bob".to_string(),
                        password: "secret2".to_string(),
                    },
                ],
            })
        );

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn load_config_rejects_partial_socks5_auth() {
        let path = std::env::temp_dir().join("outline-ws-rust-socks5-auth-partial.toml");
        std::fs::write(
            &path,
            r#"
            tcp_ws_url = "wss://example.com/secret/tcp"
            method = "chacha20-ietf-poly1305"
            password = "Secret0"

            [socks5]
            listen = "127.0.0.1:1080"
            username = "alice"
            "#,
        )
        .unwrap();

        let args = super::Args::parse_from(["test"]);
        let err = load_config(&path, &args).await.unwrap_err();
        assert!(format!("{err:#}").contains("missing socks5 password"));

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn load_config_rejects_mixed_single_and_multi_socks5_auth() {
        let path = std::env::temp_dir().join("outline-ws-rust-socks5-auth-mixed.toml");
        std::fs::write(
            &path,
            r#"
            tcp_ws_url = "wss://example.com/secret/tcp"
            method = "chacha20-ietf-poly1305"
            password = "Secret0"

            [socks5]
            listen = "127.0.0.1:1080"
            username = "alice"
            password = "secret"

            [[socks5.users]]
            username = "bob"
            password = "secret2"
            "#,
        )
        .unwrap();

        let args = super::Args::parse_from(["test"]);
        let err = load_config(&path, &args).await.unwrap_err();
        assert!(format!("{err:#}").contains("not both"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn config_deserializes_multiple_uplinks() {
        let cfg = r#"
            [socks5]
            listen = "127.0.0.1:1080"

            [probe]
            interval_secs = 15
            timeout_secs = 5
            max_concurrent = 3
            max_dials = 1

            [probe.ws]
            enabled = true

            [probe.http]
            url = "http://example.com/"

            [probe.dns]
            server = "1.1.1.1"
            port = 53
            name = "example.com"

            [load_balancing]
            mode = "active_passive"
            routing_scope = "per_uplink"
            warm_standby_tcp = 1
            warm_standby_udp = 1
            rtt_ewma_alpha = 0.4
            failure_penalty_ms = 750
            failure_penalty_max_ms = 20000
            failure_penalty_halflife_secs = 45

            [[uplinks]]
            name = "primary"
            tcp_ws_url = "wss://primary.example.com/secret/tcp"
            tcp_ws_mode = "h3"
            weight = 1.5
            fwmark = 100
            udp_ws_url = "wss://primary.example.com/secret/udp"
            udp_ws_mode = "h3"
            method = "chacha20-ietf-poly1305"
            password = "Secret0"

            [[uplinks]]
            name = "backup"
            tcp_ws_url = "wss://backup.example.com/secret/tcp"
            tcp_ws_mode = "h2"
            udp_ws_url = "wss://backup.example.com/secret/udp"
            udp_ws_mode = "h2"
            method = "aes-128-gcm"
            password = "Secret1"
        "#;
        let parsed: ConfigFile = toml::from_str(cfg).unwrap();
        let outline = resolve_outline_section(&parsed).unwrap();
        let uplinks = outline.uplinks.unwrap();
        assert_eq!(uplinks.len(), 2);
        assert_eq!(uplinks[0].fwmark, Some(100));
        assert_eq!(uplinks[0].weight, Some(1.5));
        let probe = outline.probe.unwrap();
        assert_eq!(probe.max_concurrent, Some(3));
        assert_eq!(probe.max_dials, Some(1));
        let lb = outline.load_balancing.unwrap();
        assert_eq!(lb.mode, Some(LoadBalancingMode::ActivePassive));
        assert_eq!(lb.routing_scope, Some(RoutingScope::PerUplink));
        assert_eq!(lb.warm_standby_tcp, Some(1));
        assert_eq!(lb.warm_standby_udp, Some(1));
        assert_eq!(lb.rtt_ewma_alpha, Some(0.4));
        assert_eq!(lb.failure_penalty_ms, Some(750));
        assert_eq!(lb.failure_penalty_max_ms, Some(20000));
        assert_eq!(lb.failure_penalty_halflife_secs, Some(45));
    }

    #[test]
    fn config_deserializes_global_routing_scope() {
        let cfg = r#"
            [load_balancing]
            mode = "active_passive"
            routing_scope = "global"

            [[uplinks]]
            name = "primary"
            tcp_ws_url = "wss://primary.example.com/secret/tcp"
            tcp_ws_mode = "h2"
            method = "chacha20-ietf-poly1305"
            password = "Secret0"
        "#;
        let parsed: ConfigFile = toml::from_str(cfg).unwrap();
        let outline = resolve_outline_section(&parsed).unwrap();
        let lb = outline.load_balancing.unwrap();
        assert_eq!(lb.mode, Some(LoadBalancingMode::ActivePassive));
        assert_eq!(lb.routing_scope, Some(RoutingScope::Global));
    }

    #[test]
    fn config_deserializes_tun() {
        let cfg = r#"
            [tun]
            path = "/dev/net/tun"
            name = "tun0"
            mtu = 1500
            max_flows = 2048
            idle_timeout_secs = 120

            [tun.tcp]
            connect_timeout_secs = 8
            handshake_timeout_secs = 12
            half_close_timeout_secs = 45
            max_pending_server_bytes = 524288
            max_buffered_client_segments = 1024
            max_buffered_client_bytes = 131072
            max_retransmits = 9
        "#;
        let parsed: ConfigFile = toml::from_str(cfg).unwrap();
        let tun = parsed.tun.unwrap();
        assert_eq!(tun.path.unwrap(), PathBuf::from("/dev/net/tun"));
        assert_eq!(tun.name.unwrap(), "tun0");
        assert_eq!(tun.mtu, Some(1500));
        assert_eq!(tun.max_flows, Some(2048));
        assert_eq!(tun.idle_timeout_secs, Some(120));
        let tcp = tun.tcp.unwrap();
        assert_eq!(tcp.connect_timeout_secs, Some(8));
        assert_eq!(tcp.handshake_timeout_secs, Some(12));
        assert_eq!(tcp.half_close_timeout_secs, Some(45));
        assert_eq!(tcp.max_pending_server_bytes, Some(524288));
        assert_eq!(tcp.max_buffered_client_segments, Some(1024));
        assert_eq!(tcp.max_buffered_client_bytes, Some(131072));
        assert_eq!(tcp.max_retransmits, Some(9));
    }

    #[tokio::test]
    async fn load_config_enables_periodic_memory_trim() {
        let path = std::env::temp_dir().join("outline-ws-rust-memory-trim.toml");
        std::fs::write(
            &path,
            r#"
            tcp_ws_url = "wss://example.com/secret/tcp"
            method = "chacha20-ietf-poly1305"
            password = "Secret0"
            memory_trim_interval_secs = 45
            "#,
        )
        .unwrap();

        let args = super::Args::parse_from(["test"]);
        let config = load_config(&path, &args).await.unwrap();
        assert_eq!(config.memory_trim_interval, Some(Duration::from_secs(45)));

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn load_config_defaults_periodic_memory_trim_to_60_seconds() {
        let path = std::env::temp_dir().join("outline-ws-rust-memory-trim-default.toml");
        std::fs::write(
            &path,
            r#"
            tcp_ws_url = "wss://example.com/secret/tcp"
            method = "chacha20-ietf-poly1305"
            password = "Secret0"
            "#,
        )
        .unwrap();

        let args = super::Args::parse_from(["test"]);
        let config = load_config(&path, &args).await.unwrap();
        assert_eq!(config.memory_trim_interval, Some(Duration::from_secs(60)));

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn load_config_disables_periodic_memory_trim_when_set_to_zero() {
        let path = std::env::temp_dir().join("outline-ws-rust-memory-trim-disabled.toml");
        std::fs::write(
            &path,
            r#"
            tcp_ws_url = "wss://example.com/secret/tcp"
            method = "chacha20-ietf-poly1305"
            password = "Secret0"
            memory_trim_interval_secs = 0
            "#,
        )
        .unwrap();

        let args = super::Args::parse_from(["test"]);
        let config = load_config(&path, &args).await.unwrap();
        assert_eq!(config.memory_trim_interval, None);

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn load_config_disables_probes_when_not_configured() {
        let path = std::env::temp_dir().join("outline-ws-rust-no-probe.toml");
        std::fs::write(
            &path,
            r#"
            tcp_ws_url = "wss://example.com/secret/tcp"
            tcp_ws_mode = "h2"
            method = "chacha20-ietf-poly1305"
            password = "Secret0"

            [socks5]
            listen = "127.0.0.1:1080"
            "#,
        )
        .unwrap();

        let args = super::Args::parse_from(["test"]);
        let config = super::load_config(&path, &args).await.unwrap();
        assert!(!config.probe.enabled());

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn load_config_enables_tun_when_configured() {
        let path = std::env::temp_dir().join("outline-ws-rust-tun.toml");
        std::fs::write(
            &path,
            r#"
            tcp_ws_url = "wss://example.com/secret/tcp"
            method = "chacha20-ietf-poly1305"
            password = "Secret0"

            [tun]
            path = "/dev/tun0"
            mtu = 1500
            max_flows = 512
            idle_timeout_secs = 60

            [tun.tcp]
            connect_timeout_secs = 7
            handshake_timeout_secs = 9
            half_close_timeout_secs = 30
            max_pending_server_bytes = 262144
            max_buffered_client_segments = 2048
            max_buffered_client_bytes = 65536
            max_retransmits = 6
            "#,
        )
        .unwrap();

        let args = super::Args::parse_from(["test"]);
        let config = load_config(&path, &args).await.unwrap();
        assert_eq!(
            config.tun.as_ref().unwrap().path,
            PathBuf::from("/dev/tun0")
        );
        assert_eq!(config.tun.as_ref().unwrap().mtu, 1500);
        assert_eq!(config.tun.as_ref().unwrap().max_flows, 512);
        assert_eq!(
            config.tun.as_ref().unwrap().idle_timeout,
            Duration::from_secs(60)
        );
        assert_eq!(
            config.tun.as_ref().unwrap().tcp.connect_timeout,
            Duration::from_secs(7)
        );
        assert_eq!(
            config.tun.as_ref().unwrap().tcp.handshake_timeout,
            Duration::from_secs(9)
        );
        assert_eq!(
            config.tun.as_ref().unwrap().tcp.half_close_timeout,
            Duration::from_secs(30)
        );
        assert_eq!(
            config.tun.as_ref().unwrap().tcp.max_pending_server_bytes,
            262_144
        );
        assert_eq!(
            config
                .tun
                .as_ref()
                .unwrap()
                .tcp
                .max_buffered_client_segments,
            2048
        );
        assert_eq!(
            config.tun.as_ref().unwrap().tcp.max_buffered_client_bytes,
            65_536
        );
        assert_eq!(config.tun.as_ref().unwrap().tcp.max_retransmits, 6);
    }

    #[tokio::test]
    async fn load_config_enables_tun_from_cli_without_tun_section() {
        let path = std::env::temp_dir().join("outline-ws-rust-no-tun-section.toml");
        std::fs::write(
            &path,
            r#"
            tcp_ws_url = "wss://example.com/secret/tcp"
            method = "chacha20-ietf-poly1305"
            password = "Secret0"
            "#,
        )
        .unwrap();

        let args = super::Args::parse_from([
            "test",
            "--tun-path",
            "/dev/net/tun",
            "--tun-name",
            "tun0",
            "--tun-mtu",
            "1500",
        ]);
        let config = load_config(&path, &args).await.unwrap();
        assert_eq!(
            config.tun.as_ref().unwrap().path,
            PathBuf::from("/dev/net/tun")
        );
        assert_eq!(config.tun.as_ref().unwrap().name.as_deref(), Some("tun0"));
        assert_eq!(config.tun.as_ref().unwrap().mtu, 1500);

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn load_config_enables_metrics_from_cli_without_metrics_section() {
        let path = std::env::temp_dir().join("outline-ws-rust-no-metrics-section.toml");
        std::fs::write(
            &path,
            r#"
            tcp_ws_url = "wss://example.com/secret/tcp"
            method = "chacha20-ietf-poly1305"
            password = "Secret0"
            "#,
        )
        .unwrap();

        let args = super::Args::parse_from(["test", "--metrics-listen", "[::1]:9090"]);
        let config = load_config(&path, &args).await.unwrap();
        assert_eq!(
            config.metrics.as_ref().unwrap().listen,
            "[::1]:9090".parse().unwrap()
        );

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn load_config_disables_probes_when_probe_section_has_no_checks() {
        let path = std::env::temp_dir().join("outline-ws-rust-empty-probe.toml");
        std::fs::write(
            &path,
            r#"
            tcp_ws_url = "wss://example.com/secret/tcp"
            tcp_ws_mode = "h2"
            method = "chacha20-ietf-poly1305"
            password = "Secret0"

            [socks5]
            listen = "127.0.0.1:1080"

            [probe]
            interval_secs = 15
            timeout_secs = 5
            "#,
        )
        .unwrap();

        let args = super::Args::parse_from(["test"]);
        let config = super::load_config(&path, &args).await.unwrap();
        assert!(!config.probe.enabled());

        let _ = std::fs::remove_file(path);
    }
}
