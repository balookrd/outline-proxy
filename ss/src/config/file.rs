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
    pub listen: Option<SocketAddr>,
    pub ss_listen: Option<SocketAddr>,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
    pub h3_listen: Option<SocketAddr>,
    pub h3_cert_path: Option<PathBuf>,
    pub h3_key_path: Option<PathBuf>,
    pub metrics_listen: Option<SocketAddr>,
    pub metrics_path: Option<String>,
    pub prefer_ipv4_upstream: Option<bool>,
    pub outbound_ipv6_prefix: Option<String>,
    pub outbound_ipv6_interface: Option<String>,
    pub outbound_ipv6_refresh_secs: Option<u64>,
    #[serde(default)]
    pub ws_path_tcp: Option<String>,
    #[serde(default)]
    pub ws_path_udp: Option<String>,
    #[serde(default)]
    pub vless_ws_path: Option<String>,
    pub http_root_auth: Option<bool>,
    pub http_root_realm: Option<String>,
    pub public_host: Option<String>,
    pub public_scheme: Option<String>,
    pub access_key_url_base: Option<String>,
    pub access_key_file_extension: Option<String>,
    pub print_access_keys: Option<bool>,
    pub write_access_keys_dir: Option<PathBuf>,
    pub password: Option<String>,
    pub fwmark: Option<u32>,
    pub users: Option<Vec<UserEntry>>,
    pub method: Option<CipherKind>,
    pub tuning_profile: Option<TuningPreset>,
    #[serde(default)]
    pub tuning: Option<TuningOverrides>,
}

pub(super) fn load_file_config(path: &Path) -> Result<FileConfig> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read config file {}", path.display()))?;
    match path.extension().and_then(|e| e.to_str()) {
        Some("yaml" | "yml") => serde_yml::from_str(&contents)
            .with_context(|| format!("failed to parse config file {}", path.display())),
        _ => toml::from_str(&contents)
            .with_context(|| format!("failed to parse config file {}", path.display())),
    }
}

pub(super) fn default_config_path_if_exists() -> Option<PathBuf> {
    for name in ["config.yaml", "config.yml", "config.toml"] {
        let path = PathBuf::from(name);
        if path.exists() {
            return Some(path);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::FileConfig;

    #[test]
    fn parses_new_ws_path_keys() {
        let config: FileConfig = toml::from_str(
            r#"
listen = "0.0.0.0:3000"
ws_path_tcp = "/custom-tcp"
ws_path_udp = "/custom-udp"
vless_ws_path = "/vless"
http_root_auth = true
http_root_realm = "VPN"

[[users]]
id = "alice"
password = "secret"
ws_path_tcp = "/alice-tcp"
ws_path_udp = "/alice-udp"
"#,
        )
        .unwrap();

        assert_eq!(config.ws_path_tcp.as_deref(), Some("/custom-tcp"));
        assert_eq!(config.ws_path_udp.as_deref(), Some("/custom-udp"));
        assert_eq!(config.vless_ws_path.as_deref(), Some("/vless"));
        assert_eq!(config.http_root_auth, Some(true));
        assert_eq!(config.http_root_realm.as_deref(), Some("VPN"));
        let users = config.users.unwrap();
        assert_eq!(users[0].ws_path_tcp.as_deref(), Some("/alice-tcp"));
        assert_eq!(users[0].ws_path_udp.as_deref(), Some("/alice-udp"));
    }

    #[test]
    fn parses_user_vless_id() {
        let config: FileConfig = toml::from_str(
            r#"
listen = "0.0.0.0:3000"
vless_ws_path = "/vless"

[[users]]
id = "alice"
vless_id = "550e8400-e29b-41d4-a716-446655440000"
vless_ws_path = "/alice-vless"
"#,
        )
        .unwrap();

        assert_eq!(config.vless_ws_path.as_deref(), Some("/vless"));
        let users = config.users.unwrap();
        assert_eq!(users[0].id, "alice");
        assert_eq!(users[0].vless_id.as_deref(), Some("550e8400-e29b-41d4-a716-446655440000"));
        assert_eq!(users[0].vless_ws_path.as_deref(), Some("/alice-vless"));
    }

    #[test]
    fn parses_tuning_profile_and_overrides() {
        let config: FileConfig = toml::from_str(
            r#"
listen = "0.0.0.0:3000"
tuning_profile = "medium"

[tuning]
h3_udp_socket_buffer_bytes = 2097152
h3_max_concurrent_bidi_streams = 128
"#,
        )
        .unwrap();

        assert_eq!(config.tuning_profile, Some(super::TuningPreset::Medium),);
        let tuning = config.tuning.unwrap();
        assert_eq!(tuning.h3_udp_socket_buffer_bytes, Some(2_097_152));
        assert_eq!(tuning.h3_max_concurrent_bidi_streams, Some(128));
        assert_eq!(tuning.h3_connection_window_bytes, None);
    }

    #[test]
    fn rejects_unknown_tuning_fields() {
        let error = toml::from_str::<FileConfig>(
            r#"
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
    fn rejects_legacy_ws_path_keys() {
        let error = toml::from_str::<FileConfig>(
            r#"
listen = "0.0.0.0:3000"
ws_path = "/legacy-tcp"
udp_ws_path = "/legacy-udp"

[[users]]
id = "alice"
password = "secret"
ws_path = "/alice-legacy-tcp"
udp_ws_path = "/alice-legacy-udp"
"#,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("unknown field"));
        assert!(error.contains("ws_path"));
    }
}
