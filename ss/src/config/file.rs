use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::Deserialize;

use super::{CipherKind, UserEntry};

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
    pub client_active_ttl_secs: Option<u64>,
    pub udp_nat_idle_timeout_secs: Option<u64>,
    #[serde(default)]
    pub ws_path_tcp: Option<String>,
    #[serde(default)]
    pub ws_path_udp: Option<String>,
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
        assert_eq!(config.http_root_auth, Some(true));
        assert_eq!(config.http_root_realm.as_deref(), Some("VPN"));
        let users = config.users.unwrap();
        assert_eq!(users[0].ws_path_tcp.as_deref(), Some("/alice-tcp"));
        assert_eq!(users[0].ws_path_udp.as_deref(), Some("/alice-udp"));
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
