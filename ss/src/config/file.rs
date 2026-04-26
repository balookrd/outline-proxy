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
    pub udp_orphan_backbuf_bytes: Option<usize>,
    pub udp_orphan_total_budget_bytes: Option<usize>,
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
mod tests {
    use super::FileConfig;

    #[test]
    fn parses_sectioned_ws_paths() {
        let config: FileConfig = toml::from_str(
            r#"
[server]
listen = "0.0.0.0:3000"

[websocket]
tcp_path = "/custom-tcp"
udp_path = "/custom-udp"
vless_path = "/vless"

[http_root]
auth = true
realm = "VPN"

[[users]]
id = "alice"
password = "secret"
ws_path_tcp = "/alice-tcp"
ws_path_udp = "/alice-udp"
"#,
        )
        .unwrap();

        let ws = config.websocket.unwrap();
        assert_eq!(ws.tcp_path.as_deref(), Some("/custom-tcp"));
        assert_eq!(ws.udp_path.as_deref(), Some("/custom-udp"));
        assert_eq!(ws.vless_path.as_deref(), Some("/vless"));
        let http_root = config.http_root.unwrap();
        assert_eq!(http_root.auth, Some(true));
        assert_eq!(http_root.realm.as_deref(), Some("VPN"));
        let users = config.users.unwrap();
        assert_eq!(users[0].ws_path_tcp.as_deref(), Some("/alice-tcp"));
        assert_eq!(users[0].ws_path_udp.as_deref(), Some("/alice-udp"));
    }

    #[test]
    fn parses_server_sections() {
        let config: FileConfig = toml::from_str(
            r#"
[server]
listen = "0.0.0.0:3000"
tls_cert_path = "./cert.pem"
tls_key_path = "./key.pem"

[server.ss]
listen = "0.0.0.0:8388"

[server.h3]
listen = "0.0.0.0:3000"
cert_path = "./cert.pem"
key_path = "./key.pem"
"#,
        )
        .unwrap();

        let server = config.server.unwrap();
        assert_eq!(server.listen.unwrap().to_string(), "0.0.0.0:3000");
        assert_eq!(server.ss.unwrap().listen.unwrap().to_string(), "0.0.0.0:8388");
        let h3 = server.h3.unwrap();
        assert_eq!(h3.listen.unwrap().to_string(), "0.0.0.0:3000");
        assert!(h3.cert_path.is_some());
    }

    #[test]
    fn parses_tuning_profile_and_overrides() {
        let config: FileConfig = toml::from_str(
            r#"
tuning_profile = "medium"

[server]
listen = "0.0.0.0:3000"

[tuning]
h3_udp_socket_buffer_bytes = 2097152
h3_max_concurrent_bidi_streams = 128
"#,
        )
        .unwrap();

        assert_eq!(config.tuning_profile, Some(super::TuningPreset::Medium));
        let tuning = config.tuning.unwrap();
        assert_eq!(tuning.h3_udp_socket_buffer_bytes, Some(2_097_152));
        assert_eq!(tuning.h3_max_concurrent_bidi_streams, Some(128));
        assert_eq!(tuning.h3_connection_window_bytes, None);
    }

    #[test]
    fn parses_dashboard_instances() {
        let config: FileConfig = toml::from_str(
            r#"
[server]
listen = "0.0.0.0:3000"

[dashboard]
listen = "127.0.0.1:7002"

[[dashboard.instances]]
name = "local"
control_url = "http://127.0.0.1:7001"
token_file = "./control.token"
"#,
        )
        .unwrap();

        let dashboard = config.dashboard.unwrap();
        assert_eq!(dashboard.listen.unwrap().to_string(), "127.0.0.1:7002");
        let instances = dashboard.instances.unwrap();
        assert_eq!(instances[0].name.as_deref(), Some("local"));
        assert_eq!(instances[0].control_url.as_deref(), Some("http://127.0.0.1:7001"));
    }

    #[test]
    fn rejects_unknown_tuning_fields() {
        let error = toml::from_str::<FileConfig>(
            r#"
[server]
listen = "0.0.0.0:3000"

[tuning]
not_a_real_field = 123
"#,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("unknown field"));
        assert!(error.contains("not_a_real_field"));
    }

    #[test]
    fn rejects_legacy_top_level_keys() {
        let error = toml::from_str::<FileConfig>(
            r#"
listen = "0.0.0.0:3000"
ws_path_tcp = "/tcp"
"#,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("unknown field"));
    }
}
