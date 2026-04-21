mod cli;
mod file;

use std::{
    collections::{BTreeSet, HashSet},
    net::SocketAddr,
    path::PathBuf,
};

use anyhow::{Result, bail};
use clap::Parser;
use serde::Deserialize;
use thiserror::Error;

use cli::ConfigArgs;
use file::{FileConfig, default_config_path_if_exists, load_file_config};

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: Option<SocketAddr>,
    pub ss_listen: Option<SocketAddr>,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
    pub h3_listen: Option<SocketAddr>,
    pub h3_cert_path: Option<PathBuf>,
    pub h3_key_path: Option<PathBuf>,
    pub metrics_listen: Option<SocketAddr>,
    pub metrics_path: String,
    pub prefer_ipv4_upstream: bool,
    pub ws_path_tcp: String,
    pub ws_path_udp: String,
    pub http_root_auth: bool,
    pub http_root_realm: String,
    pub password: Option<String>,
    pub fwmark: Option<u32>,
    pub users: Vec<UserEntry>,
    pub method: CipherKind,
    /// Resolved tuning knobs (H2/H3 resource limits plus session/NAT timeouts
    /// and global UDP relay cap). Derived from the `tuning_profile` preset
    /// with any per-field overrides from `[tuning]` applied on top. Validated
    /// at config load time.
    pub tuning: TuningProfile,
}

/// Named bundle of HTTP/2 and HTTP/3 resource limits. Pick the smallest
/// profile that still saturates your expected bandwidth×RTT — larger
/// profiles scale memory per connection linearly.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, clap::ValueEnum, Deserialize)]
pub enum TuningProfileKind {
    #[value(name = "small")]
    #[serde(rename = "small")]
    Small,
    #[value(name = "medium")]
    #[serde(rename = "medium")]
    Medium,
    #[value(name = "large")]
    #[serde(rename = "large")]
    #[default]
    Large,
}

impl TuningProfileKind {
    pub fn preset(self) -> TuningProfile {
        match self {
            Self::Small => TuningProfile::SMALL,
            Self::Medium => TuningProfile::MEDIUM,
            Self::Large => TuningProfile::LARGE,
        }
    }
}

/// Resolved HTTP/2 and HTTP/3 resource limits used by the server transports.
///
/// Upper-bound memory per connection is roughly `h3_connection_window_bytes`
/// (flow-control) + `h3_max_backpressure_bytes` (write-side) + datagram
/// buffers, so `profile × max_expected_connections` should fit in the host's
/// available RAM with headroom.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TuningProfile {
    pub h2_stream_window_bytes: u32,
    pub h2_connection_window_bytes: u32,
    pub h2_max_send_buf_size: usize,

    pub h3_stream_window_bytes: u64,
    pub h3_connection_window_bytes: u64,
    pub h3_max_concurrent_bidi_streams: u32,
    pub h3_max_concurrent_uni_streams: u32,
    pub h3_write_buffer_bytes: usize,
    pub h3_max_backpressure_bytes: usize,
    pub h3_udp_socket_buffer_bytes: usize,

    /// TTL in seconds used to compute `client_active` / `client_up` metrics.
    pub client_active_ttl_secs: u64,
    /// How long a UDP NAT entry is kept alive after the last outbound
    /// datagram.
    pub udp_nat_idle_timeout_secs: u64,
    /// Process-wide ceiling on in-flight UDP relay tasks across all WebSocket
    /// sessions. Protects against fan-out when many sessions each try to use
    /// the per-session limit. `0` disables the global cap.
    pub udp_max_concurrent_relay_tasks: usize,
}

impl TuningProfile {
    /// Conservative profile for shared / low-memory hosts. Trades peak
    /// throughput on fat long-RTT links for predictable memory footprint when
    /// many connections are multiplexed.
    pub const SMALL: Self = Self {
        h2_stream_window_bytes: 1024 * 1024,
        h2_connection_window_bytes: 4 * 1024 * 1024,
        h2_max_send_buf_size: 1024 * 1024,
        h3_stream_window_bytes: 1024 * 1024,
        h3_connection_window_bytes: 4 * 1024 * 1024,
        h3_max_concurrent_bidi_streams: 256,
        h3_max_concurrent_uni_streams: 128,
        h3_write_buffer_bytes: 128 * 1024,
        h3_max_backpressure_bytes: 1024 * 1024,
        h3_udp_socket_buffer_bytes: 4 * 1024 * 1024,
        client_active_ttl_secs: 180,
        udp_nat_idle_timeout_secs: 120,
        udp_max_concurrent_relay_tasks: 1_024,
    };

    /// Balanced profile for typical deployments.
    pub const MEDIUM: Self = Self {
        h2_stream_window_bytes: 4 * 1024 * 1024,
        h2_connection_window_bytes: 16 * 1024 * 1024,
        h2_max_send_buf_size: 4 * 1024 * 1024,
        h3_stream_window_bytes: 4 * 1024 * 1024,
        h3_connection_window_bytes: 16 * 1024 * 1024,
        h3_max_concurrent_bidi_streams: 1_024,
        h3_max_concurrent_uni_streams: 512,
        h3_write_buffer_bytes: 256 * 1024,
        h3_max_backpressure_bytes: 4 * 1024 * 1024,
        h3_udp_socket_buffer_bytes: 8 * 1024 * 1024,
        client_active_ttl_secs: 300,
        udp_nat_idle_timeout_secs: 240,
        udp_max_concurrent_relay_tasks: 2_048,
    };

    /// Maximum-throughput profile for single-tenant, high-bandwidth-delay-
    /// product links. This is the historical default.
    pub const LARGE: Self = Self {
        h2_stream_window_bytes: 16 * 1024 * 1024,
        h2_connection_window_bytes: 64 * 1024 * 1024,
        h2_max_send_buf_size: 16 * 1024 * 1024,
        h3_stream_window_bytes: 16 * 1024 * 1024,
        h3_connection_window_bytes: 64 * 1024 * 1024,
        h3_max_concurrent_bidi_streams: 4_096,
        h3_max_concurrent_uni_streams: 1_024,
        h3_write_buffer_bytes: 512 * 1024,
        h3_max_backpressure_bytes: 16 * 1024 * 1024,
        h3_udp_socket_buffer_bytes: 32 * 1024 * 1024,
        client_active_ttl_secs: 300,
        udp_nat_idle_timeout_secs: 300,
        udp_max_concurrent_relay_tasks: 4_096,
    };

    pub(crate) fn validate(&self) -> Result<()> {
        // Guard against zeroed values that would silently stall a transport.
        if self.h2_stream_window_bytes == 0 {
            bail!("tuning.h2_stream_window_bytes must be > 0");
        }
        if self.h2_connection_window_bytes == 0 {
            bail!("tuning.h2_connection_window_bytes must be > 0");
        }
        if self.h2_max_send_buf_size == 0 {
            bail!("tuning.h2_max_send_buf_size must be > 0");
        }
        if self.h3_stream_window_bytes == 0 {
            bail!("tuning.h3_stream_window_bytes must be > 0");
        }
        if self.h3_connection_window_bytes == 0 {
            bail!("tuning.h3_connection_window_bytes must be > 0");
        }
        if self.h3_max_concurrent_bidi_streams == 0 {
            bail!("tuning.h3_max_concurrent_bidi_streams must be > 0");
        }
        if self.h3_max_concurrent_uni_streams == 0 {
            bail!("tuning.h3_max_concurrent_uni_streams must be > 0");
        }
        if self.h3_write_buffer_bytes == 0 {
            bail!("tuning.h3_write_buffer_bytes must be > 0");
        }
        if self.h3_max_backpressure_bytes == 0 {
            bail!("tuning.h3_max_backpressure_bytes must be > 0");
        }
        if self.h3_udp_socket_buffer_bytes == 0 {
            bail!("tuning.h3_udp_socket_buffer_bytes must be > 0");
        }

        // HTTP/2 and HTTP/3 both require stream ≤ connection flow-control
        // windows, otherwise a single stream can deadlock on the connection
        // window.
        if self.h2_stream_window_bytes > self.h2_connection_window_bytes {
            bail!(
                "tuning.h2_stream_window_bytes ({}) must not exceed h2_connection_window_bytes ({})",
                self.h2_stream_window_bytes,
                self.h2_connection_window_bytes,
            );
        }
        if self.h3_stream_window_bytes > self.h3_connection_window_bytes {
            bail!(
                "tuning.h3_stream_window_bytes ({}) must not exceed h3_connection_window_bytes ({})",
                self.h3_stream_window_bytes,
                self.h3_connection_window_bytes,
            );
        }

        // `quinn` encodes QUIC flow-control windows as VarInt from u32, so
        // anything wider would panic at runtime.
        if self.h3_stream_window_bytes > u32::MAX as u64 {
            bail!(
                "tuning.h3_stream_window_bytes must fit in u32 (max {})",
                u32::MAX
            );
        }
        if self.h3_connection_window_bytes > u32::MAX as u64 {
            bail!(
                "tuning.h3_connection_window_bytes must fit in u32 (max {})",
                u32::MAX
            );
        }

        // UDP receive buffer must hold at least one max-size datagram,
        // otherwise inbound QUIC packets are dropped by the kernel.
        const MIN_UDP_BUFFER: usize = 64 * 1024;
        if self.h3_udp_socket_buffer_bytes < MIN_UDP_BUFFER {
            bail!(
                "tuning.h3_udp_socket_buffer_bytes ({}) must be at least {} bytes",
                self.h3_udp_socket_buffer_bytes,
                MIN_UDP_BUFFER,
            );
        }

        if self.client_active_ttl_secs == 0 {
            bail!("tuning.client_active_ttl_secs must be > 0");
        }
        if self.udp_nat_idle_timeout_secs == 0 {
            bail!("tuning.udp_nat_idle_timeout_secs must be > 0");
        }
        // `udp_max_concurrent_relay_tasks == 0` is a valid opt-out.

        Ok(())
    }

    pub(crate) fn apply_overrides(&mut self, o: &TuningOverrides) {
        if let Some(v) = o.h2_stream_window_bytes { self.h2_stream_window_bytes = v; }
        if let Some(v) = o.h2_connection_window_bytes { self.h2_connection_window_bytes = v; }
        if let Some(v) = o.h2_max_send_buf_size { self.h2_max_send_buf_size = v; }
        if let Some(v) = o.h3_stream_window_bytes { self.h3_stream_window_bytes = v; }
        if let Some(v) = o.h3_connection_window_bytes { self.h3_connection_window_bytes = v; }
        if let Some(v) = o.h3_max_concurrent_bidi_streams {
            self.h3_max_concurrent_bidi_streams = v;
        }
        if let Some(v) = o.h3_max_concurrent_uni_streams {
            self.h3_max_concurrent_uni_streams = v;
        }
        if let Some(v) = o.h3_write_buffer_bytes { self.h3_write_buffer_bytes = v; }
        if let Some(v) = o.h3_max_backpressure_bytes { self.h3_max_backpressure_bytes = v; }
        if let Some(v) = o.h3_udp_socket_buffer_bytes { self.h3_udp_socket_buffer_bytes = v; }
        if let Some(v) = o.client_active_ttl_secs { self.client_active_ttl_secs = v; }
        if let Some(v) = o.udp_nat_idle_timeout_secs { self.udp_nat_idle_timeout_secs = v; }
        if let Some(v) = o.udp_max_concurrent_relay_tasks {
            self.udp_max_concurrent_relay_tasks = v;
        }
    }
}

impl Default for TuningProfile {
    fn default() -> Self {
        Self::LARGE
    }
}

/// Per-field overrides for [`TuningProfile`], parsed from the `[tuning]`
/// section of the config file. Any field left `None` is inherited from the
/// selected `tuning_profile` preset.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TuningOverrides {
    #[serde(default)] pub h2_stream_window_bytes: Option<u32>,
    #[serde(default)] pub h2_connection_window_bytes: Option<u32>,
    #[serde(default)] pub h2_max_send_buf_size: Option<usize>,
    #[serde(default)] pub h3_stream_window_bytes: Option<u64>,
    #[serde(default)] pub h3_connection_window_bytes: Option<u64>,
    #[serde(default)] pub h3_max_concurrent_bidi_streams: Option<u32>,
    #[serde(default)] pub h3_max_concurrent_uni_streams: Option<u32>,
    #[serde(default)] pub h3_write_buffer_bytes: Option<usize>,
    #[serde(default)] pub h3_max_backpressure_bytes: Option<usize>,
    #[serde(default)] pub h3_udp_socket_buffer_bytes: Option<usize>,
    #[serde(default)] pub client_active_ttl_secs: Option<u64>,
    #[serde(default)] pub udp_nat_idle_timeout_secs: Option<u64>,
    #[serde(default)] pub udp_max_concurrent_relay_tasks: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct AccessKeyConfig {
    pub public_host: Option<String>,
    pub public_scheme: String,
    pub access_key_url_base: Option<String>,
    pub access_key_file_extension: String,
}

pub enum AppMode {
    Serve(Config),
    GenerateKeys {
        config: Config,
        access_key: AccessKeyConfig,
        print: bool,
        write_dir: Option<PathBuf>,
    },
}

impl AppMode {
    pub fn load() -> Result<Self> {
        let args = ConfigArgs::parse();
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

        let config = Config {
            listen: args.listen.or(file.listen),
            ss_listen: args.ss_listen.or(file.ss_listen),
            tls_cert_path: args.tls_cert_path.or(file.tls_cert_path),
            tls_key_path: args.tls_key_path.or(file.tls_key_path),
            h3_listen: args.h3_listen.or(file.h3_listen),
            h3_cert_path: args.h3_cert_path.or(file.h3_cert_path),
            h3_key_path: args.h3_key_path.or(file.h3_key_path),
            metrics_listen: args.metrics_listen.or(file.metrics_listen),
            metrics_path: args
                .metrics_path
                .or(file.metrics_path)
                .unwrap_or_else(|| "/metrics".to_owned()),
            prefer_ipv4_upstream: args
                .prefer_ipv4_upstream
                .or(file.prefer_ipv4_upstream)
                .unwrap_or(false),
            ws_path_tcp: args
                .ws_path_tcp
                .or(file.ws_path_tcp)
                .unwrap_or_else(|| "/tcp".to_owned()),
            ws_path_udp: args
                .ws_path_udp
                .or(file.ws_path_udp)
                .unwrap_or_else(|| "/udp".to_owned()),
            http_root_auth: args.http_root_auth.or(file.http_root_auth).unwrap_or(false),
            http_root_realm: args
                .http_root_realm
                .or(file.http_root_realm)
                .unwrap_or_else(default_http_root_realm),
            password: args.password.or(file.password),
            fwmark: args.fwmark.or(file.fwmark),
            users: if args.users.is_empty() {
                file.users.unwrap_or_default()
            } else {
                args.users
            },
            method: args
                .method
                .or(file.method)
                .unwrap_or(CipherKind::Chacha20IetfPoly1305),
            tuning,
        };
        config.validate()?;

        let print = args.print_access_keys.or(file.print_access_keys).unwrap_or(false);
        let write_dir = args.write_access_keys_dir.or(file.write_access_keys_dir);

        if print || write_dir.is_some() {
            let access_key = AccessKeyConfig {
                public_host: args.public_host.or(file.public_host),
                public_scheme: args
                    .public_scheme
                    .or(file.public_scheme)
                    .unwrap_or_else(|| "wss".to_owned()),
                access_key_url_base: args.access_key_url_base.or(file.access_key_url_base),
                access_key_file_extension: normalize_access_key_file_extension(
                    args.access_key_file_extension.or(file.access_key_file_extension),
                ),
            };
            access_key.validate()?;
            Ok(AppMode::GenerateKeys { config, access_key, print, write_dir })
        } else {
            Ok(AppMode::Serve(config))
        }
    }
}

impl Config {
    pub fn user_entries(&self) -> Result<Vec<UserEntry>, ConfigError> {
        let mut users = self.users.clone();
        if let Some(password) = &self.password {
            users.push(UserEntry {
                id: "default".to_owned(),
                password: password.clone(),
                fwmark: self.fwmark,
                method: None,
                ws_path_tcp: None,
                ws_path_udp: None,
            });
        }

        if users.is_empty() {
            return Err(ConfigError::MissingUsers);
        }

        let mut seen = HashSet::with_capacity(users.len());
        for user in &users {
            if !seen.insert(user.id.clone()) {
                return Err(ConfigError::DuplicateUserId(user.id.clone()));
            }
        }

        Ok(users)
    }

    fn validate_cert_pair(
        cert: &Option<PathBuf>,
        key: &Option<PathBuf>,
        prefix: &str,
    ) -> Result<bool> {
        match (cert, key) {
            (Some(_), Some(_)) => Ok(true),
            (None, None) => Ok(false),
            _ => bail!("{prefix}_cert_path and {prefix}_key_path must be configured together"),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if !self.data_plane_listener_enabled() {
            bail!("configure at least one data-plane listener: listen, h3_listen, or ss_listen");
        }
        Self::validate_cert_pair(&self.tls_cert_path, &self.tls_key_path, "tls")?;
        let h3_certs_present =
            Self::validate_cert_pair(&self.h3_cert_path, &self.h3_key_path, "h3")?;
        if h3_certs_present && self.h3_listen.is_none() {
            bail!("h3_listen must be configured explicitly when HTTP/3 is enabled");
        }
        if !h3_certs_present && self.h3_listen.is_some() {
            bail!("h3_listen requires both h3_cert_path and h3_key_path");
        }
        if !self.metrics_path.starts_with('/') {
            bail!("metrics_path must start with '/'");
        }
        if self.listen.is_some() && self.listen == self.ss_listen {
            bail!("ss_listen must differ from listen");
        }
        if self.ss_listen.is_some() && self.ss_listen == self.metrics_listen {
            bail!("ss_listen must differ from metrics_listen");
        }
        if self.ss_listen.is_some() && self.ss_listen == self.effective_h3_listen() {
            bail!("ss_listen must differ from h3_listen");
        }
        if self.listen.is_some() && self.listen == self.metrics_listen {
            bail!("listen must differ from metrics_listen");
        }
        let users = self.user_entries()?;
        let mut tcp_paths = BTreeSet::new();
        let mut udp_paths = BTreeSet::new();
        for user in users {
            if let Some(path) = user.ws_path_tcp.as_deref()
                && !path.starts_with('/')
            {
                bail!("user {} ws_path_tcp must start with '/'", user.id);
            }
            if let Some(path) = user.ws_path_udp.as_deref()
                && !path.starts_with('/')
            {
                bail!("user {} ws_path_udp must start with '/'", user.id);
            }
            tcp_paths.insert(user.effective_ws_path_tcp(&self.ws_path_tcp).to_owned());
            udp_paths.insert(user.effective_ws_path_udp(&self.ws_path_udp).to_owned());
        }
        if let Some(conflict) = tcp_paths.intersection(&udp_paths).next() {
            bail!("tcp and udp websocket paths must be distinct, conflict on {}", conflict);
        }
        if self.http_root_auth && (tcp_paths.contains("/") || udp_paths.contains("/")) {
            bail!("http_root_auth requires all websocket paths to differ from '/'");
        }
        if self.http_root_realm.chars().any(char::is_control) {
            bail!("http_root_realm must not contain control characters");
        }
        self.tuning.validate()?;
        Ok(())
    }

    pub fn h3_enabled(&self) -> bool {
        self.h3_cert_path.is_some() && self.h3_key_path.is_some()
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

impl AccessKeyConfig {
    fn validate(&self) -> Result<()> {
        if !matches!(self.public_scheme.as_str(), "ws" | "wss") {
            bail!("public_scheme must be either \"ws\" or \"wss\"");
        }
        Ok(())
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, clap::ValueEnum, Deserialize)]
pub enum CipherKind {
    #[value(name = "aes-128-gcm")]
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    #[value(name = "aes-256-gcm")]
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    #[value(name = "chacha20-ietf-poly1305")]
    #[serde(rename = "chacha20-ietf-poly1305")]
    Chacha20IetfPoly1305,
    #[value(name = "2022-blake3-aes-128-gcm")]
    #[serde(rename = "2022-blake3-aes-128-gcm")]
    Aes128Gcm2022,
    #[value(name = "2022-blake3-aes-256-gcm")]
    #[serde(rename = "2022-blake3-aes-256-gcm")]
    Aes256Gcm2022,
    #[value(name = "2022-blake3-chacha20-poly1305")]
    #[serde(rename = "2022-blake3-chacha20-poly1305")]
    Chacha20Poly13052022,
}

impl CipherKind {
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aes128Gcm2022 => 16,
            Self::Aes256Gcm
            | Self::Chacha20IetfPoly1305
            | Self::Aes256Gcm2022
            | Self::Chacha20Poly13052022 => 32,
        }
    }

    pub const fn salt_len(self) -> usize {
        self.key_len()
    }

    pub const fn is_2022(self) -> bool {
        matches!(self, Self::Aes128Gcm2022 | Self::Aes256Gcm2022 | Self::Chacha20Poly13052022)
    }

    pub const fn is_2022_aes(self) -> bool {
        matches!(self, Self::Aes128Gcm2022 | Self::Aes256Gcm2022)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Aes256Gcm => "aes-256-gcm",
            Self::Chacha20IetfPoly1305 => "chacha20-ietf-poly1305",
            Self::Aes128Gcm2022 => "2022-blake3-aes-128-gcm",
            Self::Aes256Gcm2022 => "2022-blake3-aes-256-gcm",
            Self::Chacha20Poly13052022 => "2022-blake3-chacha20-poly1305",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserEntry {
    pub id: String,
    pub password: String,
    #[serde(default)]
    pub fwmark: Option<u32>,
    #[serde(default)]
    pub method: Option<CipherKind>,
    #[serde(default)]
    pub ws_path_tcp: Option<String>,
    #[serde(default)]
    pub ws_path_udp: Option<String>,
}

impl UserEntry {
    pub fn effective_method(&self, default: CipherKind) -> CipherKind {
        self.method.unwrap_or(default)
    }

    pub fn effective_ws_path_tcp<'a>(&'a self, default: &'a str) -> &'a str {
        self.ws_path_tcp.as_deref().unwrap_or(default)
    }

    pub fn effective_ws_path_udp<'a>(&'a self, default: &'a str) -> &'a str {
        self.ws_path_udp.as_deref().unwrap_or(default)
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("configure at least one key via password or [[users]]")]
    MissingUsers,
    #[error("duplicate user id: {0}")]
    DuplicateUserId(String),
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

#[cfg(test)]
mod tests {
    use super::{CipherKind, Config, default_http_root_realm};

    fn base_config() -> Config {
        Config {
            listen: Some("127.0.0.1:3000".parse().unwrap()),
            ss_listen: None,
            tls_cert_path: None,
            tls_key_path: None,
            h3_listen: None,
            h3_cert_path: None,
            h3_key_path: None,
            metrics_listen: None,
            metrics_path: "/metrics".into(),
            prefer_ipv4_upstream: false,
            ws_path_tcp: "/tcp".into(),
            ws_path_udp: "/udp".into(),
            http_root_auth: false,
            http_root_realm: default_http_root_realm(),
            password: Some("secret".into()),
            fwmark: None,
            users: vec![],
            method: CipherKind::Chacha20IetfPoly1305,
            tuning: super::TuningProfile::LARGE,
        }
    }

    #[test]
    fn requires_at_least_one_data_plane_listener() {
        let error = Config {
            listen: None,
            metrics_listen: Some("127.0.0.1:9090".parse().unwrap()),
            ..base_config()
        }
        .validate()
        .unwrap_err()
        .to_string();

        assert!(error.contains("configure at least one data-plane listener"));
    }

    #[test]
    fn requires_explicit_h3_listener_when_enabled() {
        let error = Config {
            listen: None,
            h3_cert_path: Some("cert.pem".into()),
            h3_key_path: Some("key.pem".into()),
            ..base_config()
        }
        .validate()
        .unwrap_err()
        .to_string();

        assert!(error.contains("h3_listen must be configured explicitly"));
    }

    #[test]
    fn allows_h3_listener_to_share_address_with_tcp_listener() {
        Config {
            h3_listen: Some("127.0.0.1:3000".parse().unwrap()),
            h3_cert_path: Some("cert.pem".into()),
            h3_key_path: Some("key.pem".into()),
            ..base_config()
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn rejects_http_root_auth_on_root_ws_path() {
        let error = Config {
            ws_path_tcp: "/".into(),
            http_root_auth: true,
            ..base_config()
        }
        .validate()
        .unwrap_err()
        .to_string();

        assert!(error.contains("http_root_auth requires all websocket paths to differ from '/'"));
    }

    #[test]
    fn tuning_rejects_stream_window_above_connection_window() {
        let mut tuning = super::TuningProfile::LARGE;
        tuning.h3_stream_window_bytes = tuning.h3_connection_window_bytes + 1;
        let error = Config { tuning, ..base_config() }.validate().unwrap_err().to_string();
        assert!(error.contains("h3_stream_window_bytes"));
        assert!(error.contains("must not exceed"));
    }

    #[test]
    fn tuning_rejects_zero_values() {
        let mut tuning = super::TuningProfile::LARGE;
        tuning.h3_udp_socket_buffer_bytes = 0;
        let error = Config { tuning, ..base_config() }.validate().unwrap_err().to_string();
        assert!(error.contains("h3_udp_socket_buffer_bytes"));
    }

    #[test]
    fn tuning_rejects_oversized_h3_windows() {
        let mut tuning = super::TuningProfile::LARGE;
        tuning.h3_connection_window_bytes = (u32::MAX as u64) + 1;
        let error = Config { tuning, ..base_config() }.validate().unwrap_err().to_string();
        assert!(error.contains("h3_connection_window_bytes"));
    }

    #[test]
    fn tuning_overrides_apply_on_top_of_preset() {
        use super::{TuningOverrides, TuningProfile, TuningProfileKind};
        let mut tuning = TuningProfileKind::Medium.preset();
        tuning.apply_overrides(&TuningOverrides {
            h3_udp_socket_buffer_bytes: Some(2 * 1024 * 1024),
            h3_max_concurrent_bidi_streams: Some(128),
            ..TuningOverrides::default()
        });
        // Overridden fields take the new value; others stay at the preset.
        assert_eq!(tuning.h3_udp_socket_buffer_bytes, 2 * 1024 * 1024);
        assert_eq!(tuning.h3_max_concurrent_bidi_streams, 128);
        assert_eq!(
            tuning.h3_connection_window_bytes,
            TuningProfile::MEDIUM.h3_connection_window_bytes,
        );
    }

    #[test]
    fn rejects_http_root_realm_with_control_characters() {
        let error = Config {
            http_root_auth: true,
            http_root_realm: "bad\nrealm".into(),
            ..base_config()
        }
        .validate()
        .unwrap_err()
        .to_string();

        assert!(error.contains("http_root_realm must not contain control characters"));
    }
}
