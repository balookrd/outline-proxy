pub mod access_key;
mod cli;
mod file;
mod migrate;
mod tuning;
mod user_entry;
mod validation;

pub use migrate::migrate_config_in_place;

use std::{collections::HashSet, net::SocketAddr, path::PathBuf};

use anyhow::Result;
use clap::Parser;

use cli::ConfigArgs;
use file::{FileConfig, SessionResumptionSection, default_config_path_if_exists, load_file_config};

pub use tuning::{TuningOverrides, TuningPreset, TuningProfile};
pub use user_entry::{CipherKind, ConfigError, UserEntry};

/// ALPN protocols recognised on the HTTP/3 QUIC endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum H3Alpn {
    /// HTTP/3 (with Extended CONNECT WebSocket per RFC 9220).
    H3,
    /// Raw VLESS framed directly over QUIC bidirectional streams.
    Vless,
    /// Raw Shadowsocks AEAD framed directly over QUIC bidirectional streams.
    Ss,
}

impl H3Alpn {
    pub const fn wire_bytes(self) -> &'static [u8] {
        match self {
            Self::H3 => b"h3",
            Self::Vless => b"vless",
            Self::Ss => b"ss",
        }
    }

    /// All ALPN identifiers the server should advertise for this
    /// protocol, in preference order (MTU-aware sibling first when
    /// applicable). Newer clients negotiate the MTU-aware variant
    /// and use the oversize-record stream fallback for UDP datagrams
    /// that exceed `Connection::max_datagram_size()`; older clients
    /// negotiate the base ALPN and behave as before.
    pub const fn advertised_alpns(self) -> &'static [&'static [u8]] {
        match self {
            Self::H3 => &[b"h3"],
            Self::Vless => &[b"vless-mtu", b"vless"],
            Self::Ss => &[b"ss-mtu", b"ss"],
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::H3 => "h3",
            Self::Vless => "vless",
            Self::Ss => "ss",
        }
    }

    /// Returns `true` if the negotiated ALPN bytes denote the
    /// MTU-aware sibling for this protocol (e.g. `vless-mtu` for
    /// `Self::Vless`). Always `false` for `Self::H3`.
    pub fn is_mtu_variant(self, negotiated: &[u8]) -> bool {
        match self {
            Self::H3 => false,
            Self::Vless => negotiated == b"vless-mtu",
            Self::Ss => negotiated == b"ss-mtu",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "h3" => Some(Self::H3),
            "vless" | "vless-mtu" => Some(Self::Vless),
            "ss" | "ss-mtu" => Some(Self::Ss),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "control"), allow(dead_code))]
pub struct ControlConfig {
    pub listen: SocketAddr,
    pub token: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "control"), allow(dead_code))]
pub struct DashboardConfig {
    pub listen: SocketAddr,
    pub request_timeout_secs: u64,
    pub refresh_interval_secs: u64,
    pub instances: Vec<DashboardInstanceConfig>,
}

#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "control"), allow(dead_code))]
pub struct DashboardInstanceConfig {
    pub name: String,
    pub control_url: String,
    pub token: String,
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Path of the config file this `Config` was loaded from, if any.
    /// Preserved so the control plane can persist runtime user mutations
    /// back to the same file that seeded them.
    #[cfg_attr(not(feature = "control"), allow(dead_code))]
    pub config_path: Option<PathBuf>,
    #[cfg_attr(not(feature = "control"), allow(dead_code))]
    pub control: Option<ControlConfig>,
    #[cfg_attr(not(feature = "control"), allow(dead_code))]
    pub dashboard: Option<DashboardConfig>,
    pub listen: Option<SocketAddr>,
    pub ss_listen: Option<SocketAddr>,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
    pub h3_listen: Option<SocketAddr>,
    pub h3_cert_path: Option<PathBuf>,
    pub h3_key_path: Option<PathBuf>,
    /// ALPN protocols advertised on the HTTP/3 QUIC endpoint. Each entry
    /// selects a different transport multiplexed on the same UDP port:
    /// `"h3"` for HTTP/3 + WebSocket-over-HTTP/3 (the default), `"vless"`
    /// for raw VLESS over QUIC streams, `"ss"` for raw Shadowsocks over QUIC
    /// streams. Resolved from `[server.h3].alpn`; defaults to `["h3"]`.
    pub h3_alpn: Vec<H3Alpn>,
    pub metrics_listen: Option<SocketAddr>,
    pub metrics_path: String,
    pub prefer_ipv4_upstream: bool,
    /// If set, upstream IPv6 TCP/UDP sockets bind to a random address drawn
    /// from this prefix (e.g. `2001:db8:dead::/64`) instead of using the
    /// kernel default. See [`crate::outbound`] for details.
    pub outbound_ipv6_prefix: Option<crate::outbound::Ipv6Prefix>,
    /// Alternative to [`Self::outbound_ipv6_prefix`]: a network interface
    /// name (e.g. `eth0`). At runtime the IPv6 addresses assigned to the
    /// interface are enumerated (refreshed periodically) and upstream IPv6
    /// sockets bind to a random one. Useful for DHCPv6/SLAAC deployments
    /// where the prefix/addresses are not known statically.
    pub outbound_ipv6_interface: Option<String>,
    /// How often to re-enumerate the outbound interface's IPv6 addresses.
    pub outbound_ipv6_refresh_secs: u64,
    pub ws_path_tcp: String,
    pub ws_path_udp: String,
    pub ws_path_vless: Option<String>,
    pub http_root_auth: bool,
    pub http_root_realm: String,
    pub users: Vec<UserEntry>,
    pub method: CipherKind,
    pub access_key: AccessKeyConfig,
    /// Resolved tuning knobs (H2/H3 resource limits plus session/NAT timeouts
    /// and global UDP relay cap). Derived from the `tuning_profile` preset
    /// with any per-field overrides from `[tuning]` applied on top. Validated
    /// at config load time.
    pub tuning: TuningProfile,
    /// Resolved cross-transport session-resumption knobs. Defaults to
    /// disabled; opt in via `[session_resumption]` in the config file.
    /// See `docs/SESSION-RESUMPTION.md`.
    pub session_resumption: SessionResumptionConfig,
}

/// Public snapshot of the `[session_resumption]` config. Mirrors
/// `SessionResumptionSection` but with all fields resolved to concrete
/// values (defaults applied).
#[derive(Debug, Clone)]
pub struct SessionResumptionConfig {
    pub enabled: bool,
    pub orphan_ttl_tcp_secs: u64,
    pub orphan_ttl_udp_secs: u64,
    pub orphan_per_user_cap: usize,
    pub orphan_global_cap: usize,
    pub udp_orphan_backbuf_bytes: usize,
    pub udp_orphan_total_budget_bytes: usize,
}

impl Default for SessionResumptionConfig {
    fn default() -> Self {
        // Mirrors `docs/SESSION-RESUMPTION.md`. Disabled by default.
        Self {
            enabled: false,
            orphan_ttl_tcp_secs: 30,
            orphan_ttl_udp_secs: 30,
            orphan_per_user_cap: 4,
            orphan_global_cap: 10_000,
            udp_orphan_backbuf_bytes: 64 * 1024,
            udp_orphan_total_budget_bytes: 512 * 1024 * 1024,
        }
    }
}

impl SessionResumptionConfig {
    fn from_section(section: SessionResumptionSection) -> Self {
        let defaults = Self::default();
        Self {
            enabled: section.enabled.unwrap_or(defaults.enabled),
            orphan_ttl_tcp_secs: section
                .orphan_ttl_tcp_secs
                .unwrap_or(defaults.orphan_ttl_tcp_secs),
            orphan_ttl_udp_secs: section
                .orphan_ttl_udp_secs
                .unwrap_or(defaults.orphan_ttl_udp_secs),
            orphan_per_user_cap: section
                .orphan_per_user_cap
                .unwrap_or(defaults.orphan_per_user_cap),
            orphan_global_cap: section
                .orphan_global_cap
                .unwrap_or(defaults.orphan_global_cap),
            udp_orphan_backbuf_bytes: section
                .udp_orphan_backbuf_bytes
                .unwrap_or(defaults.udp_orphan_backbuf_bytes),
            udp_orphan_total_budget_bytes: section
                .udp_orphan_total_budget_bytes
                .unwrap_or(defaults.udp_orphan_total_budget_bytes),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AccessKeyConfig {
    pub public_host: Option<String>,
    pub public_scheme: String,
    pub access_key_url_base: Option<String>,
    pub access_key_file_extension: String,
}

impl Default for AccessKeyConfig {
    fn default() -> Self {
        Self {
            public_host: None,
            public_scheme: "wss".to_owned(),
            access_key_url_base: None,
            access_key_file_extension: ".yaml".to_owned(),
        }
    }
}

pub enum AppMode {
    Serve(Config),
    GenerateKeys {
        config: Config,
        access_key: AccessKeyConfig,
        print: bool,
        write_dir: Option<PathBuf>,
    },
    MigrateConfig {
        path: PathBuf,
    },
}

impl AppMode {
    pub fn load() -> Result<Self> {
        let args = ConfigArgs::parse();
        if let Some(path) = args.migrate_config.clone() {
            return Ok(AppMode::MigrateConfig { path });
        }
        let config_path = args.config.clone().or_else(default_config_path_if_exists);
        let file = if let Some(path) = &config_path {
            load_file_config(path)?
        } else {
            FileConfig::default()
        };

        let mut tuning = args
            .tuning_profile
            .or(file.tuning_profile)
            .unwrap_or_default()
            .preset();
        if let Some(overrides) = file.tuning.as_ref() {
            tuning.apply_overrides(overrides);
        }

        let config_dir = config_path
            .as_deref()
            .and_then(std::path::Path::parent)
            .unwrap_or_else(|| std::path::Path::new("."));
        let control = resolve_control_config(&args, &file)?;
        let dashboard = resolve_dashboard_config(&file, config_dir)?;

        let server = file.server.unwrap_or_default();
        let server_ss = server.ss.unwrap_or_default();
        let server_h3 = server.h3.unwrap_or_default();
        let metrics = file.metrics.unwrap_or_default();
        let outbound = file.outbound.unwrap_or_default();
        let websocket = file.websocket.unwrap_or_default();
        let http_root = file.http_root.unwrap_or_default();
        let access_keys_file = file.access_keys.unwrap_or_default();
        let shadowsocks = file.shadowsocks.unwrap_or_default();

        let access_key = AccessKeyConfig {
            public_host: args.public_host.or(access_keys_file.public_host),
            public_scheme: args
                .public_scheme
                .or(access_keys_file.public_scheme)
                .unwrap_or_else(|| "wss".to_owned()),
            access_key_url_base: args.access_key_url_base.or(access_keys_file.url_base),
            access_key_file_extension: normalize_access_key_file_extension(
                args.access_key_file_extension.or(access_keys_file.file_extension),
            ),
        };
        access_key.validate()?;

        let config = Config {
            config_path: config_path.clone(),
            control,
            dashboard,
            listen: args.listen.or(server.listen),
            ss_listen: args.ss_listen.or(server_ss.listen),
            tls_cert_path: args.tls_cert_path.or(server.tls_cert_path),
            tls_key_path: args.tls_key_path.or(server.tls_key_path),
            h3_listen: args.h3_listen.or(server_h3.listen),
            h3_cert_path: args.h3_cert_path.or(server_h3.cert_path),
            h3_key_path: args.h3_key_path.or(server_h3.key_path),
            h3_alpn: resolve_h3_alpn(server_h3.alpn.as_deref())?,
            metrics_listen: args.metrics_listen.or(metrics.listen),
            metrics_path: args
                .metrics_path
                .or(metrics.path)
                .unwrap_or_else(|| "/metrics".to_owned()),
            prefer_ipv4_upstream: args
                .prefer_ipv4_upstream
                .or(outbound.prefer_ipv4)
                .unwrap_or(false),
            outbound_ipv6_prefix: match args
                .outbound_ipv6_prefix
                .as_deref()
                .or(outbound.ipv6_prefix.as_deref())
            {
                Some(s) => Some(
                    s.parse::<crate::outbound::Ipv6Prefix>()
                        .map_err(|e| anyhow::anyhow!("invalid outbound.ipv6_prefix: {e}"))?,
                ),
                None => None,
            },
            outbound_ipv6_interface: args
                .outbound_ipv6_interface
                .clone()
                .or(outbound.ipv6_interface),
            outbound_ipv6_refresh_secs: args
                .outbound_ipv6_refresh_secs
                .or(outbound.ipv6_refresh_secs)
                .unwrap_or(30),
            ws_path_tcp: args
                .ws_path_tcp
                .or(websocket.tcp_path)
                .unwrap_or_else(|| "/tcp".to_owned()),
            ws_path_udp: args
                .ws_path_udp
                .or(websocket.udp_path)
                .unwrap_or_else(|| "/udp".to_owned()),
            ws_path_vless: websocket.vless_path,
            http_root_auth: args.http_root_auth.or(http_root.auth).unwrap_or(false),
            http_root_realm: args
                .http_root_realm
                .or(http_root.realm)
                .unwrap_or_else(default_http_root_realm),
            users: if args.users.is_empty() {
                file.users.unwrap_or_default()
            } else {
                args.users
            },
            method: args
                .method
                .or(shadowsocks.method)
                .unwrap_or(CipherKind::Chacha20IetfPoly1305),
            access_key: access_key.clone(),
            tuning,
            session_resumption: SessionResumptionConfig::from_section(
                file.session_resumption.unwrap_or_default(),
            ),
        };
        config.validate()?;

        let print = args.print_access_keys.or(access_keys_file.print).unwrap_or(false);
        let write_dir = args.write_access_keys_dir.or(access_keys_file.write_dir);

        if print || write_dir.is_some() {
            Ok(AppMode::GenerateKeys { config, access_key, print, write_dir })
        } else {
            Ok(AppMode::Serve(config))
        }
    }
}

impl Config {
    pub fn effective_users(&self) -> Result<Vec<UserEntry>, ConfigError> {
        let users = self.users.clone();
        if users
            .iter()
            .all(|user| user.password.is_none() && user.vless_id.is_none())
        {
            return Err(ConfigError::MissingUsers);
        }

        let mut seen = HashSet::with_capacity(users.len());
        for user in &users {
            if !seen.insert(user.id.clone()) {
                return Err(ConfigError::DuplicateUserId(user.id.clone()));
            }
        }

        Ok(users.into_iter().filter(UserEntry::is_enabled).collect())
    }

    pub fn user_entries(&self) -> Result<Vec<UserEntry>, ConfigError> {
        Ok(self
            .effective_users()?
            .into_iter()
            .filter(|user| user.password.is_some())
            .collect())
    }

    pub fn h3_enabled(&self) -> bool {
        self.h3_cert_path.is_some() && self.h3_key_path.is_some()
    }

    pub fn h3_alpn_enabled(&self, alpn: H3Alpn) -> bool {
        self.h3_alpn.contains(&alpn)
    }

    pub fn tcp_tls_enabled(&self) -> bool {
        self.tls_cert_path.is_some() && self.tls_key_path.is_some()
    }

    pub fn metrics_enabled(&self) -> bool {
        self.metrics_listen.is_some()
    }

    pub fn effective_h3_listen(&self) -> Option<SocketAddr> {
        self.h3_enabled().then_some(self.h3_listen).flatten()
    }

    pub fn data_plane_listener_enabled(&self) -> bool {
        self.listen.is_some() || self.h3_enabled() || self.ss_listen.is_some()
    }
}

fn normalize_access_key_file_extension(extension: Option<String>) -> String {
    let extension = extension.unwrap_or_else(|| ".yaml".to_owned());
    if extension.starts_with('.') {
        extension
    } else {
        format!(".{extension}")
    }
}

pub fn default_http_root_realm() -> String {
    "Authorization required".to_owned()
}

fn resolve_h3_alpn(input: Option<&[String]>) -> Result<Vec<H3Alpn>> {
    let Some(raw) = input else {
        return Ok(vec![H3Alpn::H3]);
    };
    if raw.is_empty() {
        anyhow::bail!("server.h3.alpn must list at least one protocol");
    }
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(raw.len());
    for entry in raw {
        let alpn = H3Alpn::parse(entry).ok_or_else(|| {
            anyhow::anyhow!("unknown server.h3.alpn entry {entry:?}; allowed: h3, vless, ss")
        })?;
        if !seen.insert(alpn) {
            anyhow::bail!("server.h3.alpn contains duplicate entry {entry:?}");
        }
        out.push(alpn);
    }
    Ok(out)
}

fn resolve_dashboard_config(
    file: &FileConfig,
    config_dir: &std::path::Path,
) -> Result<Option<DashboardConfig>> {
    let Some(dashboard) = file.dashboard.as_ref() else {
        return Ok(None);
    };
    if dashboard.enabled == Some(false) {
        return Ok(None);
    }

    let listen = dashboard
        .listen
        .ok_or_else(|| anyhow::anyhow!("dashboard enabled but dashboard.listen is not set"))?;
    let instances = dashboard
        .instances
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("dashboard enabled but dashboard.instances is empty"))?;
    if instances.is_empty() {
        anyhow::bail!("dashboard enabled but dashboard.instances is empty");
    }

    let mut loaded = Vec::with_capacity(instances.len());
    for (idx, server) in instances.iter().enumerate() {
        let name = server
            .name
            .clone()
            .filter(|name| !name.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("dashboard server #{idx} has no name"))?;
        let control_url = server
            .control_url
            .clone()
            .filter(|url| !url.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("dashboard server {name:?} has no control_url"))?;
        if !(control_url.starts_with("http://") || control_url.starts_with("https://")) {
            anyhow::bail!(
                "dashboard server {name:?} uses unsupported control_url {control_url:?}; \
                 only http:// and https:// control listeners are supported"
            );
        }
        control_url.parse::<hyper::Uri>().map_err(|error| {
            anyhow::anyhow!("invalid dashboard server {name:?} control_url: {error}")
        })?;

        let inline_token = server.token.clone().filter(|token| !token.is_empty());
        let file_token = match server.token_file.as_ref() {
            Some(path) => {
                let resolved = if path.is_absolute() {
                    path.clone()
                } else {
                    config_dir.join(path)
                };
                let contents = std::fs::read_to_string(&resolved).map_err(|error| {
                    anyhow::anyhow!(
                        "failed to read dashboard token file {}: {error}",
                        resolved.display()
                    )
                })?;
                let trimmed = contents.trim().to_owned();
                if trimmed.is_empty() {
                    anyhow::bail!("dashboard token file {} is empty", resolved.display());
                }
                Some(trimmed)
            },
            None => None,
        };
        if inline_token.is_some() && file_token.is_some() {
            anyhow::bail!(
                "dashboard server {name:?}: specify either token or token_file, not both"
            );
        }
        let token = inline_token
            .or(file_token)
            .ok_or_else(|| anyhow::anyhow!("dashboard server {name:?} has no token"))?;

        loaded.push(DashboardInstanceConfig { name, control_url, token });
    }

    Ok(Some(DashboardConfig {
        listen,
        request_timeout_secs: dashboard.request_timeout_secs.unwrap_or(15).max(1),
        refresh_interval_secs: dashboard.refresh_interval_secs.unwrap_or(10).max(1),
        instances: loaded,
    }))
}

fn resolve_control_config(args: &ConfigArgs, file: &FileConfig) -> Result<Option<ControlConfig>> {
    let file_control = file.control.as_ref();
    let listen = args.control_listen.or_else(|| file_control.and_then(|c| c.listen));
    let token_literal = args
        .control_token
        .clone()
        .or_else(|| file_control.and_then(|c| c.token.clone()));
    let token_file = args
        .control_token_file
        .clone()
        .or_else(|| file_control.and_then(|c| c.token_file.clone()));

    let token = match (token_literal, token_file) {
        (Some(t), None) => Some(t),
        (None, Some(path)) => {
            let contents = std::fs::read_to_string(&path).map_err(|error| {
                anyhow::anyhow!("failed to read control token file {}: {error}", path.display())
            })?;
            let trimmed = contents.trim().to_owned();
            if trimmed.is_empty() {
                anyhow::bail!("control token file {} is empty", path.display());
            }
            Some(trimmed)
        },
        (Some(_), Some(_)) => {
            anyhow::bail!("specify either control.token or control.token_file, not both")
        },
        (None, None) => None,
    };

    match (listen, token) {
        (Some(listen), Some(token)) => Ok(Some(ControlConfig { listen, token })),
        (None, None) => Ok(None),
        (Some(_), None) => {
            anyhow::bail!("control.listen requires control.token or control.token_file")
        },
        (None, Some(_)) => anyhow::bail!("control.token requires control.listen"),
    }
}
