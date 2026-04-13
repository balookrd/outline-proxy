use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use tokio::fs;
use tokio::sync::RwLock;
use url::Url;

use crate::bypass::BypassList;
use crate::types::{CipherKind, UplinkTransport, WsTransportMode};

use super::args::Args;
use super::schema::{
    BypassSection, ConfigFile, H2Section, OutlineSection, TunSection, UplinkSection,
    resolve_outline_section,
};
use super::types::{
    AppConfig, DnsProbeConfig, H2Config, HttpProbeConfig, LoadBalancingConfig, LoadBalancingMode,
    MetricsConfig, ProbeConfig, RoutingScope, Socks5AuthConfig, Socks5AuthUserConfig,
    TcpProbeConfig, TunConfig, TunTcpConfig, UplinkConfig, WsProbeConfig,
};

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
    let h2_section = file.as_ref().and_then(|f| f.h2.as_ref());
    let udp_recv_buf_bytes = file.as_ref().and_then(|f| f.udp_recv_buf_bytes);
    let udp_send_buf_bytes = file.as_ref().and_then(|f| f.udp_send_buf_bytes);

    let listen = args.listen.or_else(|| socks5.and_then(|s| s.listen));
    let socks5_auth = load_socks5_auth_config(socks5, args)?;

    let uplinks = load_uplinks(outline.as_ref(), args)?;
    let probe = load_probe_config(outline.as_ref())?;
    let load_balancing = load_balancing_config(outline.as_ref())?;
    let metrics = args
        .metrics_listen
        .or_else(|| metrics_section.and_then(|section| section.listen))
        .map(|listen| MetricsConfig { listen });
    let tun = load_tun_config(tun_section, args)?;
    let h2 = load_h2_config(h2_section);
    let bypass = load_bypass_config(file.as_ref().and_then(|f| f.bypass.as_ref())).await?;

    if listen.is_none() && tun.is_none() {
        bail!("no ingress configured: set --listen / [socks5].listen and/or configure [tun]");
    }

    Ok(AppConfig {
        listen,
        socks5_auth,
        uplinks,
        probe,
        load_balancing,
        metrics,
        tun,
        h2,
        udp_recv_buf_bytes,
        udp_send_buf_bytes,
        bypass,
    })
}

fn load_socks5_auth_config(
    socks5: Option<&super::schema::Socks5Section>,
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
                    anyhow!("missing socks5 user username in [socks5].users entry {}", index + 1)
                })?;
                let password = user.password.clone().ok_or_else(|| {
                    anyhow!("missing socks5 user password in [socks5].users entry {}", index + 1)
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
            Socks5AuthUserConfig { username: username.clone(), password: password.clone() },
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

#[derive(Debug, Clone)]
struct ResolvedUplinkInput {
    name: String,
    transport: UplinkTransport,
    tcp_ws_url: Option<Url>,
    tcp_ws_mode: Option<WsTransportMode>,
    udp_ws_url: Option<Url>,
    udp_ws_mode: Option<WsTransportMode>,
    tcp_addr: Option<crate::types::ServerAddr>,
    udp_addr: Option<crate::types::ServerAddr>,
    cipher: Option<CipherKind>,
    password: Option<String>,
    weight: Option<f64>,
    fwmark: Option<u32>,
    ipv6_first: Option<bool>,
}

impl ResolvedUplinkInput {
    fn from_cli(args: &Args, outline: Option<&OutlineSection>) -> Self {
        Self {
            name: "cli".to_string(),
            transport: args
                .transport
                .or_else(|| outline.and_then(|section| section.transport))
                .unwrap_or_default(),
            tcp_ws_url: args
                .tcp_ws_url
                .clone()
                .or_else(|| outline.and_then(|section| section.tcp_ws_url.clone())),
            tcp_ws_mode: args
                .tcp_ws_mode
                .or_else(|| outline.and_then(|section| section.tcp_ws_mode)),
            udp_ws_url: args
                .udp_ws_url
                .clone()
                .or_else(|| outline.and_then(|section| section.udp_ws_url.clone())),
            udp_ws_mode: args
                .udp_ws_mode
                .or_else(|| outline.and_then(|section| section.udp_ws_mode)),
            tcp_addr: args
                .tcp_addr
                .clone()
                .or_else(|| outline.and_then(|section| section.tcp_addr.clone())),
            udp_addr: args
                .udp_addr
                .clone()
                .or_else(|| outline.and_then(|section| section.udp_addr.clone())),
            cipher: args.method.or_else(|| outline.and_then(|section| section.method)),
            password: args
                .password
                .clone()
                .or_else(|| outline.and_then(|section| section.password.clone())),
            weight: Some(1.0),
            fwmark: args.fwmark.or_else(|| outline.and_then(|section| section.fwmark)),
            ipv6_first: args.ipv6_first.or_else(|| outline.and_then(|section| section.ipv6_first)),
        }
    }

    fn from_section(index: usize, uplink: &UplinkSection) -> Self {
        Self {
            name: uplink.name.clone().unwrap_or_else(|| format!("uplink-{}", index + 1)),
            transport: uplink.transport.unwrap_or_default(),
            tcp_ws_url: uplink.tcp_ws_url.clone(),
            tcp_ws_mode: uplink.tcp_ws_mode,
            udp_ws_url: uplink.udp_ws_url.clone(),
            udp_ws_mode: uplink.udp_ws_mode,
            tcp_addr: uplink.tcp_addr.clone(),
            udp_addr: uplink.udp_addr.clone(),
            cipher: uplink.method,
            password: uplink.password.clone(),
            weight: uplink.weight,
            fwmark: uplink.fwmark,
            ipv6_first: uplink.ipv6_first,
        }
    }

    fn from_outline_default(outline: Option<&OutlineSection>) -> Self {
        Self {
            name: "default".to_string(),
            transport: outline.and_then(|section| section.transport).unwrap_or_default(),
            tcp_ws_url: outline.and_then(|section| section.tcp_ws_url.clone()),
            tcp_ws_mode: outline.and_then(|section| section.tcp_ws_mode),
            udp_ws_url: outline.and_then(|section| section.udp_ws_url.clone()),
            udp_ws_mode: outline.and_then(|section| section.udp_ws_mode),
            tcp_addr: outline.and_then(|section| section.tcp_addr.clone()),
            udp_addr: outline.and_then(|section| section.udp_addr.clone()),
            cipher: outline.and_then(|section| section.method),
            password: outline.and_then(|section| section.password.clone()),
            weight: Some(1.0),
            fwmark: outline.and_then(|section| section.fwmark),
            ipv6_first: outline.and_then(|section| section.ipv6_first),
        }
    }
}

impl TryFrom<ResolvedUplinkInput> for UplinkConfig {
    type Error = anyhow::Error;

    fn try_from(input: ResolvedUplinkInput) -> Result<Self> {
        let ResolvedUplinkInput {
            name,
            transport,
            tcp_ws_url,
            tcp_ws_mode,
            udp_ws_url,
            udp_ws_mode,
            tcp_addr,
            udp_addr,
            cipher,
            password,
            weight,
            fwmark,
            ipv6_first,
        } = input;

        let weight = weight.unwrap_or(1.0);
        if !weight.is_finite() || weight <= 0.0 {
            bail!("uplink weight must be a finite positive number");
        }
        let cipher = cipher.unwrap_or(CipherKind::Chacha20IetfPoly1305);
        let password = password
            .ok_or_else(|| anyhow!("missing password: set it in config.toml or pass --password"))?;
        cipher
            .derive_master_key(&password)
            .with_context(|| format!("invalid password/PSK for cipher {cipher}"))?;

        Ok(UplinkConfig {
            name,
            transport,
            tcp_ws_url: match transport {
                UplinkTransport::Websocket => Some(tcp_ws_url.ok_or_else(|| {
                    anyhow!("missing tcp_ws_url: set it in config.toml or pass --tcp-ws-url")
                })?),
                UplinkTransport::Shadowsocks => {
                    if tcp_ws_url.is_some() || udp_ws_url.is_some() {
                        bail!(
                            "websocket uplink fields are not valid for transport=shadowsocks; use tcp_addr/udp_addr"
                        );
                    }
                    None
                }
            },
            tcp_ws_mode: tcp_ws_mode.unwrap_or_default(),
            udp_ws_url: match transport {
                UplinkTransport::Websocket => udp_ws_url,
                UplinkTransport::Shadowsocks => None,
            },
            udp_ws_mode: udp_ws_mode.unwrap_or_default(),
            tcp_addr: match transport {
                UplinkTransport::Websocket => {
                    if tcp_addr.is_some() || udp_addr.is_some() {
                        bail!(
                            "socket uplink fields are not valid for transport=websocket; use tcp_ws_url/udp_ws_url"
                        );
                    }
                    None
                }
                UplinkTransport::Shadowsocks => Some(tcp_addr.ok_or_else(|| {
                    anyhow!("missing tcp_addr: set it in config.toml or pass --tcp-addr")
                })?),
            },
            udp_addr: match transport {
                UplinkTransport::Websocket => None,
                UplinkTransport::Shadowsocks => udp_addr,
            },
            cipher,
            password,
            weight,
            fwmark,
            ipv6_first: ipv6_first.unwrap_or(false),
        })
    }
}

fn load_uplinks(outline: Option<&OutlineSection>, args: &Args) -> Result<Vec<UplinkConfig>> {
    let cli_override_requested = args.tcp_ws_url.is_some()
        || args.transport.is_some()
        || args.tcp_ws_mode.is_some()
        || args.udp_ws_url.is_some()
        || args.udp_ws_mode.is_some()
        || args.tcp_addr.is_some()
        || args.udp_addr.is_some()
        || args.method.is_some()
        || args.password.is_some()
        || args.fwmark.is_some()
        || args.ipv6_first.is_some();

    if cli_override_requested {
        return Ok(vec![ResolvedUplinkInput::from_cli(args, outline).try_into()?]);
    }

    if let Some(uplinks) = outline.and_then(|o| o.uplinks.as_ref()) {
        let resolved = uplinks
            .iter()
            .enumerate()
            .map(|(index, uplink)| ResolvedUplinkInput::from_section(index, uplink).try_into())
            .collect::<Result<Vec<_>>>()?;
        if resolved.is_empty() {
            bail!("uplinks is present but empty");
        }
        return Ok(resolved);
    }

    Ok(vec![ResolvedUplinkInput::from_outline_default(outline).try_into()?])
}

fn load_probe_config(outline: Option<&OutlineSection>) -> Result<ProbeConfig> {
    let probe = outline.and_then(|o| o.probe.as_ref());
    let http = probe
        .and_then(|p| p.http.as_ref())
        .map(|http| HttpProbeConfig { url: http.url.clone() });
    let dns = probe.and_then(|p| p.dns.as_ref()).map(|dns| DnsProbeConfig {
        server: dns.server.clone(),
        port: dns.port.unwrap_or(53),
        name: dns.name.clone().unwrap_or_else(|| "example.com".to_string()),
    });
    let tcp = probe
        .and_then(|p| p.tcp.as_ref())
        .map(|tcp| TcpProbeConfig { host: tcp.host.clone(), port: tcp.port.unwrap_or(80) });

    Ok(ProbeConfig {
        interval: Duration::from_secs(probe.and_then(|p| p.interval_secs).unwrap_or(30)),
        timeout: Duration::from_secs(probe.and_then(|p| p.timeout_secs).unwrap_or(10)),
        max_concurrent: probe.and_then(|p| p.max_concurrent).unwrap_or(4).max(1),
        max_dials: probe.and_then(|p| p.max_dials).unwrap_or(2).max(1),
        min_failures: probe.and_then(|p| p.min_failures).unwrap_or(3).max(1),
        attempts: probe.and_then(|p| p.attempts).unwrap_or(2).max(1),
        ws: WsProbeConfig {
            enabled: probe.and_then(|p| p.ws.as_ref()).and_then(|ws| ws.enabled).unwrap_or(false),
        },
        http,
        dns,
        tcp,
    })
}

fn load_balancing_config(outline: Option<&OutlineSection>) -> Result<LoadBalancingConfig> {
    let lb = outline.and_then(|o| o.load_balancing.as_ref());
    let rtt_ewma_alpha = lb.and_then(|l| l.rtt_ewma_alpha).unwrap_or(0.3);
    if !(rtt_ewma_alpha.is_finite() && 0.0 < rtt_ewma_alpha && rtt_ewma_alpha <= 1.0) {
        bail!("load_balancing.rtt_ewma_alpha must be in the range (0, 1]");
    }
    Ok(LoadBalancingConfig {
        mode: lb.and_then(|l| l.mode).unwrap_or(LoadBalancingMode::ActiveActive),
        routing_scope: lb.and_then(|l| l.routing_scope).unwrap_or(RoutingScope::PerFlow),
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
            lb.and_then(|l| l.failure_penalty_halflife_secs).unwrap_or(60),
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
    let path = args.tun_path.clone().or_else(|| tun.and_then(|section| section.path.clone()));
    let name = args.tun_name.clone().or_else(|| tun.and_then(|section| section.name.clone()));
    let mtu = args.tun_mtu.or_else(|| tun.and_then(|section| section.mtu)).unwrap_or(1500);
    let max_flows = tun.and_then(|section| section.max_flows).unwrap_or(4096);
    let idle_timeout =
        Duration::from_secs(tun.and_then(|section| section.idle_timeout_secs).unwrap_or(300));

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
            tcp_section.and_then(|section| section.connect_timeout_secs).unwrap_or(10),
        ),
        handshake_timeout: Duration::from_secs(
            tcp_section.and_then(|section| section.handshake_timeout_secs).unwrap_or(15),
        ),
        half_close_timeout: Duration::from_secs(
            tcp_section.and_then(|section| section.half_close_timeout_secs).unwrap_or(60),
        ),
        max_pending_server_bytes: tcp_section
            .and_then(|section| section.max_pending_server_bytes)
            .unwrap_or(4_194_304),
        backlog_abort_grace: Duration::from_secs(
            tcp_section.and_then(|section| section.backlog_abort_grace_secs).unwrap_or(3),
        ),
        backlog_hard_limit_multiplier: tcp_section
            .and_then(|section| section.backlog_hard_limit_multiplier)
            .unwrap_or(2),
        backlog_no_progress_abort: Duration::from_secs(
            tcp_section
                .and_then(|section| section.backlog_no_progress_abort_secs)
                .unwrap_or(8),
        ),
        max_buffered_client_segments: tcp_section
            .and_then(|section| section.max_buffered_client_segments)
            .unwrap_or(4096),
        max_buffered_client_bytes: tcp_section
            .and_then(|section| section.max_buffered_client_bytes)
            .unwrap_or(262_144),
        max_retransmits: tcp_section.and_then(|section| section.max_retransmits).unwrap_or(12),
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
    if tcp.backlog_abort_grace < Duration::from_secs(1) {
        bail!("tun.tcp.backlog_abort_grace_secs must be at least 1");
    }
    if tcp.backlog_hard_limit_multiplier < 2 {
        bail!("tun.tcp.backlog_hard_limit_multiplier must be at least 2");
    }
    if tcp.backlog_no_progress_abort < Duration::from_secs(1) {
        bail!("tun.tcp.backlog_no_progress_abort_secs must be at least 1");
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

    let defrag_max_fragment_sets =
        tun.and_then(|section| section.defrag_max_fragment_sets).unwrap_or(1024);
    let defrag_max_fragments_per_set =
        tun.and_then(|section| section.defrag_max_fragments_per_set).unwrap_or(64);
    let defrag_max_total_bytes = tun
        .and_then(|section| section.defrag_max_total_bytes)
        .unwrap_or(16 * 1024 * 1024);
    let defrag_max_bytes_per_set =
        tun.and_then(|section| section.defrag_max_bytes_per_set).unwrap_or(128 * 1024);
    if defrag_max_fragment_sets == 0 {
        bail!("tun.defrag_max_fragment_sets must be greater than zero");
    }
    if defrag_max_fragments_per_set == 0 {
        bail!("tun.defrag_max_fragments_per_set must be greater than zero");
    }
    if defrag_max_total_bytes < 64 * 1024 {
        bail!("tun.defrag_max_total_bytes must be at least 65536");
    }
    if defrag_max_bytes_per_set < 1500 {
        bail!("tun.defrag_max_bytes_per_set must be at least 1500");
    }
    if defrag_max_bytes_per_set > defrag_max_total_bytes {
        bail!("tun.defrag_max_bytes_per_set must not exceed tun.defrag_max_total_bytes");
    }

    Ok(Some(TunConfig {
        path,
        name,
        mtu,
        max_flows,
        idle_timeout,
        tcp,
        defrag_max_fragment_sets,
        defrag_max_fragments_per_set,
        defrag_max_total_bytes,
        defrag_max_bytes_per_set,
    }))
}

fn load_h2_config(h2: Option<&H2Section>) -> H2Config {
    H2Config {
        initial_stream_window_size: h2
            .and_then(|s| s.initial_stream_window_size)
            .unwrap_or(1024 * 1024),
        initial_connection_window_size: h2
            .and_then(|s| s.initial_connection_window_size)
            .unwrap_or(2 * 1024 * 1024),
    }
}

pub(super) async fn load_bypass_config(
    bypass: Option<&BypassSection>,
) -> Result<Option<Arc<RwLock<BypassList>>>> {
    let Some(section) = bypass else {
        return Ok(None);
    };
    let invert = section.invert.unwrap_or(false);

    let mut prefixes: Vec<String> = section.prefixes.clone().unwrap_or_default();

    if let Some(ref file) = section.file {
        let content = tokio::fs::read_to_string(file)
            .await
            .with_context(|| format!("failed to read bypass file {}", file.display()))?;
        prefixes.extend(
            content
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_string),
        );
    }

    if prefixes.is_empty() {
        return Ok(None);
    }

    let list = BypassList::parse(&prefixes, invert)?;
    let shared = Arc::new(RwLock::new(list));

    if let Some(ref file) = section.file {
        let poll = Duration::from_secs(section.file_poll_secs.unwrap_or(60));
        crate::bypass::spawn_file_watcher(file.clone(), Arc::clone(&shared), invert, poll);
    }

    Ok(Some(shared))
}
