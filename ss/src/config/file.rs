use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::Deserialize;

use super::{CipherKind, TuningOverrides, TuningPreset, UserEntry};

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FileConfig {
    #[serde(default)]
    pub server: Option<ServerSection>,
    #[serde(default)]
    pub metrics: Option<MetricsSection>,
    #[serde(default)]
    pub outbound: Option<OutboundSection>,
    #[serde(default)]
    pub websocket: Option<WebsocketSection>,
    #[serde(default)]
    pub http_root: Option<HttpRootSection>,
    #[serde(default)]
    pub access_keys: Option<AccessKeysSection>,
    #[serde(default)]
    pub shadowsocks: Option<ShadowsocksSection>,
    #[serde(default)]
    pub users: Option<Vec<UserEntry>>,
    pub tuning_profile: Option<TuningPreset>,
    #[serde(default)]
    pub tuning: Option<TuningOverrides>,
    #[serde(default)]
    pub control: Option<ControlFileConfig>,
    #[serde(default)]
    pub dashboard: Option<DashboardFileConfig>,
    #[serde(default)]
    pub session_resumption: Option<SessionResumptionSection>,
    #[serde(default)]
    pub http_fallback: Option<HttpFallbackSection>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ServerSection {
    pub listen: Option<SocketAddr>,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
    #[serde(default)]
    pub ss: Option<ServerSsSection>,
    #[serde(default)]
    pub h3: Option<ServerH3Section>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ServerSsSection {
    pub listen: Option<SocketAddr>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ServerH3Section {
    pub listen: Option<SocketAddr>,
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
    /// ALPN protocols to advertise on the HTTP/3 QUIC endpoint. Allowed values
    /// are `"h3"` (HTTP/3 + WebSocket-over-HTTP/3), `"vless"` (raw VLESS over
    /// QUIC streams) and `"ss"` (raw Shadowsocks over QUIC streams). Defaults
    /// to `["h3"]` when unset.
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MetricsSection {
    pub listen: Option<SocketAddr>,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OutboundSection {
    pub prefer_ipv4: Option<bool>,
    pub ipv6_prefix: Option<String>,
    pub ipv6_interface: Option<String>,
    pub ipv6_refresh_secs: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WebsocketSection {
    pub tcp_path: Option<String>,
    pub udp_path: Option<String>,
    pub vless_path: Option<String>,
    /// Base path for VLESS-over-XHTTP packet-up. The server registers
    /// `<base>/{id}` for every advertised base, where `{id}` is an
    /// opaque per-session token chosen by the client. Absent (the
    /// default) disables XHTTP.
    pub xhttp_vless_path: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HttpRootSection {
    pub auth: Option<bool>,
    pub realm: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AccessKeysSection {
    pub public_host: Option<String>,
    pub public_scheme: Option<String>,
    pub url_base: Option<String>,
    pub file_extension: Option<String>,
    pub print: Option<bool>,
    pub write_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ShadowsocksSection {
    pub method: Option<CipherKind>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ControlFileConfig {
    pub listen: Option<SocketAddr>,
    pub token: Option<String>,
    pub token_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DashboardFileConfig {
    pub enabled: Option<bool>,
    pub listen: Option<SocketAddr>,
    pub request_timeout_secs: Option<u64>,
    pub refresh_interval_secs: Option<u64>,
    #[serde(default)]
    pub instances: Option<Vec<DashboardInstanceFileConfig>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DashboardInstanceFileConfig {
    pub name: Option<String>,
    pub control_url: Option<String>,
    pub token: Option<String>,
    pub token_file: Option<PathBuf>,
}

/// `[http_fallback]` block. When present, requests that do not match a
/// websocket / xhttp / metrics route are reverse-proxied to `backend`
/// instead of returning 404. Useful for masquerading the listener as a
/// regular web service in front of nginx / haproxy / caddy.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HttpFallbackSection {
    /// `http://host:port` of the upstream backend. HTTPS, unix sockets,
    /// and path prefixes are not supported in this MVP.
    pub backend: Option<String>,
    /// Per-request connect+response timeout in seconds. Default 30.
    pub request_timeout_secs: Option<u64>,
    /// Append the original peer IP to `X-Forwarded-For`. Default true.
    pub add_x_forwarded_for: Option<bool>,
    /// Set `X-Forwarded-Proto` to `http` / `https` based on whether the
    /// inbound listener is TLS. Default true.
    pub add_x_forwarded_proto: Option<bool>,
    /// Set `X-Forwarded-Host` to the original `Host` header. Default true.
    pub add_x_forwarded_host: Option<bool>,
    /// Wrap the upstream TCP connection in a HAProxy PROXY-protocol
    /// header (`"v1"` text or `"v2"` binary). Default: disabled. The
    /// upstream MUST be configured to expect the matching version
    /// (e.g. nginx `proxy_protocol on;` on the listen directive).
    pub proxy_protocol: Option<String>,
}

/// `[session_resumption]` block. All fields are optional; absence keeps
/// the feature disabled. See `docs/SESSION-RESUMPTION.md` for semantics
/// and recommended values.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SessionResumptionSection {
    pub enabled: Option<bool>,
    pub orphan_ttl_tcp_secs: Option<u64>,
    pub orphan_ttl_udp_secs: Option<u64>,
    pub orphan_per_user_cap: Option<usize>,
    pub orphan_global_cap: Option<usize>,
}

pub(super) fn load_file_config(path: &Path) -> Result<FileConfig> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read config file {}", path.display()))?;
    if let Some(migrated) = super::migrate::auto_migrate_if_legacy(path, &contents)? {
        return toml::from_str(&migrated)
            .with_context(|| format!("failed to parse migrated config file {}", path.display()));
    }
    toml::from_str(&contents)
        .with_context(|| format!("failed to parse config file {}", path.display()))
}

pub(super) fn default_config_path_if_exists() -> Option<PathBuf> {
    let path = PathBuf::from("config.toml");
    if path.exists() { Some(path) } else { None }
}

#[cfg(test)]
#[path = "tests/file.rs"]
mod tests;
