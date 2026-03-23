use std::{
    collections::{BTreeSet, HashSet},
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::{ArgAction, Parser, ValueEnum};
use serde::Deserialize;
use thiserror::Error;

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
    pub client_active_ttl_secs: u64,
    pub memory_trim_interval_secs: u64,
    pub udp_nat_idle_timeout_secs: u64,
    pub ws_path_tcp: String,
    pub ws_path_udp: String,
    pub public_host: Option<String>,
    pub public_scheme: String,
    pub access_key_url_base: Option<String>,
    pub access_key_file_extension: String,
    pub print_access_keys: bool,
    pub write_access_keys_dir: Option<PathBuf>,
    pub password: Option<String>,
    pub fwmark: Option<u32>,
    pub users: Vec<UserEntry>,
    pub method: CipherKind,
}

impl Config {
    pub fn load() -> Result<Self> {
        let args = ConfigArgs::parse();
        let config_path = args.config.clone().or_else(default_config_path_if_exists);
        let file = if let Some(path) = &config_path {
            load_file_config(path)?
        } else {
            FileConfig::default()
        };

        let config = Self {
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
            client_active_ttl_secs: args
                .client_active_ttl_secs
                .or(file.client_active_ttl_secs)
                .unwrap_or(300),
            memory_trim_interval_secs: args
                .memory_trim_interval_secs
                .or(file.memory_trim_interval_secs)
                .unwrap_or(60),
            udp_nat_idle_timeout_secs: args
                .udp_nat_idle_timeout_secs
                .or(file.udp_nat_idle_timeout_secs)
                .unwrap_or(300),
            ws_path_tcp: args
                .ws_path_tcp
                .or(file.ws_path_tcp)
                .unwrap_or_else(|| "/tcp".to_owned()),
            ws_path_udp: args
                .ws_path_udp
                .or(file.ws_path_udp)
                .unwrap_or_else(|| "/udp".to_owned()),
            public_host: args.public_host.or(file.public_host),
            public_scheme: args
                .public_scheme
                .or(file.public_scheme)
                .unwrap_or_else(|| "wss".to_owned()),
            access_key_url_base: args.access_key_url_base.or(file.access_key_url_base),
            access_key_file_extension: normalize_access_key_file_extension(
                args.access_key_file_extension
                    .or(file.access_key_file_extension),
            ),
            print_access_keys: args
                .print_access_keys
                .or(file.print_access_keys)
                .unwrap_or(false),
            write_access_keys_dir: args.write_access_keys_dir.or(file.write_access_keys_dir),
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
        };

        config.validate()?;
        Ok(config)
    }

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

    fn validate(&self) -> Result<()> {
        if !matches!(self.public_scheme.as_str(), "ws" | "wss") {
            bail!("public_scheme must be either \"ws\" or \"wss\"");
        }
        if !self.data_plane_listener_enabled() {
            bail!("configure at least one data-plane listener: listen, h3_listen, or ss_listen");
        }
        match (&self.tls_cert_path, &self.tls_key_path) {
            (Some(_), Some(_)) | (None, None) => {}
            _ => bail!("tls_cert_path and tls_key_path must be configured together"),
        }
        match (&self.h3_cert_path, &self.h3_key_path) {
            (Some(_), Some(_)) => {
                if self.h3_listen.is_none() {
                    bail!("h3_listen must be configured explicitly when HTTP/3 is enabled");
                }
            }
            (None, None) => {
                if self.h3_listen.is_some() {
                    bail!("h3_listen requires both h3_cert_path and h3_key_path");
                }
            }
            _ => bail!("h3_cert_path and h3_key_path must be configured together"),
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
        if self.listen.is_some() && self.listen == self.effective_h3_listen() {
            bail!("listen must differ from h3_listen");
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
            bail!(
                "tcp and udp websocket paths must be distinct, conflict on {}",
                conflict
            );
        }
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

#[derive(Debug, Clone, Parser)]
#[command(
    name = "outline-ss-rust",
    version,
    about = "Shadowsocks relay with WebSocket transport, UDP support and multi-user keys"
)]
struct ConfigArgs {
    #[arg(long, env = "OUTLINE_SS_CONFIG")]
    config: Option<PathBuf>,

    #[arg(long, env = "OUTLINE_SS_LISTEN")]
    listen: Option<SocketAddr>,

    #[arg(long, env = "OUTLINE_SS_SS_LISTEN")]
    ss_listen: Option<SocketAddr>,

    #[arg(long, env = "OUTLINE_SS_TLS_CERT_PATH")]
    tls_cert_path: Option<PathBuf>,

    #[arg(long, env = "OUTLINE_SS_TLS_KEY_PATH")]
    tls_key_path: Option<PathBuf>,

    #[arg(long, env = "OUTLINE_SS_H3_LISTEN")]
    h3_listen: Option<SocketAddr>,

    #[arg(long, env = "OUTLINE_SS_H3_CERT_PATH")]
    h3_cert_path: Option<PathBuf>,

    #[arg(long, env = "OUTLINE_SS_H3_KEY_PATH")]
    h3_key_path: Option<PathBuf>,

    #[arg(long, env = "OUTLINE_SS_METRICS_LISTEN")]
    metrics_listen: Option<SocketAddr>,

    #[arg(long, env = "OUTLINE_SS_METRICS_PATH")]
    metrics_path: Option<String>,

    #[arg(
        long,
        env = "OUTLINE_SS_PREFER_IPV4_UPSTREAM",
        action = ArgAction::Set,
        num_args = 0..=1,
        default_missing_value = "true",
        require_equals = true
    )]
    prefer_ipv4_upstream: Option<bool>,

    #[arg(long, env = "OUTLINE_SS_CLIENT_ACTIVE_TTL_SECS")]
    client_active_ttl_secs: Option<u64>,

    #[arg(long, env = "OUTLINE_SS_MEMORY_TRIM_INTERVAL_SECS")]
    memory_trim_interval_secs: Option<u64>,

    #[arg(long, env = "OUTLINE_SS_UDP_NAT_IDLE_TIMEOUT_SECS")]
    udp_nat_idle_timeout_secs: Option<u64>,

    #[arg(
        long = "ws-path-tcp",
        visible_alias = "ws-path",
        env = "OUTLINE_SS_WS_PATH_TCP"
    )]
    ws_path_tcp: Option<String>,

    #[arg(
        long = "ws-path-udp",
        visible_alias = "udp-ws-path",
        env = "OUTLINE_SS_WS_PATH_UDP"
    )]
    ws_path_udp: Option<String>,

    #[arg(long, env = "OUTLINE_SS_PUBLIC_HOST")]
    public_host: Option<String>,

    #[arg(long, env = "OUTLINE_SS_PUBLIC_SCHEME")]
    public_scheme: Option<String>,

    #[arg(long, env = "OUTLINE_SS_ACCESS_KEY_URL_BASE")]
    access_key_url_base: Option<String>,

    #[arg(long, env = "OUTLINE_SS_ACCESS_KEY_FILE_EXTENSION")]
    access_key_file_extension: Option<String>,

    #[arg(
        long,
        env = "OUTLINE_SS_PRINT_ACCESS_KEYS",
        action = ArgAction::Set,
        num_args = 0..=1,
        default_missing_value = "true",
        require_equals = true
    )]
    print_access_keys: Option<bool>,

    #[arg(long, env = "OUTLINE_SS_WRITE_ACCESS_KEYS_DIR")]
    write_access_keys_dir: Option<PathBuf>,

    #[arg(long, env = "OUTLINE_SS_PASSWORD")]
    password: Option<String>,

    #[arg(long, env = "OUTLINE_SS_FWMARK")]
    fwmark: Option<u32>,

    #[arg(
        long = "user",
        env = "OUTLINE_SS_USERS",
        value_delimiter = ',',
        value_parser = parse_user_entry
    )]
    users: Vec<UserEntry>,

    #[arg(long, env = "OUTLINE_SS_METHOD", value_enum)]
    method: Option<CipherKind>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    listen: Option<SocketAddr>,
    ss_listen: Option<SocketAddr>,
    tls_cert_path: Option<PathBuf>,
    tls_key_path: Option<PathBuf>,
    h3_listen: Option<SocketAddr>,
    h3_cert_path: Option<PathBuf>,
    h3_key_path: Option<PathBuf>,
    metrics_listen: Option<SocketAddr>,
    metrics_path: Option<String>,
    prefer_ipv4_upstream: Option<bool>,
    client_active_ttl_secs: Option<u64>,
    memory_trim_interval_secs: Option<u64>,
    udp_nat_idle_timeout_secs: Option<u64>,
    #[serde(default)]
    ws_path_tcp: Option<String>,
    #[serde(default)]
    ws_path_udp: Option<String>,
    public_host: Option<String>,
    public_scheme: Option<String>,
    access_key_url_base: Option<String>,
    access_key_file_extension: Option<String>,
    print_access_keys: Option<bool>,
    write_access_keys_dir: Option<PathBuf>,
    password: Option<String>,
    fwmark: Option<u32>,
    users: Option<Vec<UserEntry>>,
    method: Option<CipherKind>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum, Deserialize)]
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
        matches!(
            self,
            Self::Aes128Gcm2022 | Self::Aes256Gcm2022 | Self::Chacha20Poly13052022
        )
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

fn parse_user_entry(value: &str) -> Result<UserEntry, String> {
    let (id, password) = value
        .split_once('=')
        .ok_or_else(|| "expected format id=password".to_owned())?;
    let id = id.trim();
    let password = password.trim();

    if id.is_empty() {
        return Err("user id must not be empty".to_owned());
    }
    if password.is_empty() {
        return Err("user password must not be empty".to_owned());
    }

    Ok(UserEntry {
        id: id.to_owned(),
        password: password.to_owned(),
        fwmark: None,
        method: None,
        ws_path_tcp: None,
        ws_path_udp: None,
    })
}

fn default_config_path_if_exists() -> Option<PathBuf> {
    let path = PathBuf::from("config.toml");
    path.exists().then_some(path)
}

fn load_file_config(path: &Path) -> Result<FileConfig> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read config file {}", path.display()))?;
    toml::from_str(&contents)
        .with_context(|| format!("failed to parse config file {}", path.display()))
}

fn normalize_access_key_file_extension(extension: Option<String>) -> String {
    let extension = extension.unwrap_or_else(|| ".yaml".to_owned());
    if extension.starts_with('.') {
        extension
    } else {
        format!(".{extension}")
    }
}

#[cfg(test)]
mod tests {
    use super::{CipherKind, Config, FileConfig};

    #[test]
    fn parses_new_ws_path_keys() {
        let config: FileConfig = toml::from_str(
            r#"
listen = "0.0.0.0:3000"
ws_path_tcp = "/custom-tcp"
ws_path_udp = "/custom-udp"

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

    #[test]
    fn requires_at_least_one_data_plane_listener() {
        let error = Config {
            listen: None,
            ss_listen: None,
            tls_cert_path: None,
            tls_key_path: None,
            h3_listen: None,
            h3_cert_path: None,
            h3_key_path: None,
            metrics_listen: Some("127.0.0.1:9090".parse().unwrap()),
            metrics_path: "/metrics".into(),
            prefer_ipv4_upstream: false,
            client_active_ttl_secs: 300,
            memory_trim_interval_secs: 60,
            udp_nat_idle_timeout_secs: 300,
            ws_path_tcp: "/tcp".into(),
            ws_path_udp: "/udp".into(),
            public_host: None,
            public_scheme: "wss".into(),
            access_key_url_base: None,
            access_key_file_extension: ".yaml".into(),
            print_access_keys: false,
            write_access_keys_dir: None,
            password: Some("secret".into()),
            fwmark: None,
            users: vec![],
            method: CipherKind::Chacha20IetfPoly1305,
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
            ss_listen: None,
            tls_cert_path: None,
            tls_key_path: None,
            h3_listen: None,
            h3_cert_path: Some("cert.pem".into()),
            h3_key_path: Some("key.pem".into()),
            metrics_listen: None,
            metrics_path: "/metrics".into(),
            prefer_ipv4_upstream: false,
            client_active_ttl_secs: 300,
            memory_trim_interval_secs: 60,
            udp_nat_idle_timeout_secs: 300,
            ws_path_tcp: "/tcp".into(),
            ws_path_udp: "/udp".into(),
            public_host: None,
            public_scheme: "wss".into(),
            access_key_url_base: None,
            access_key_file_extension: ".yaml".into(),
            print_access_keys: false,
            write_access_keys_dir: None,
            password: Some("secret".into()),
            fwmark: None,
            users: vec![],
            method: CipherKind::Chacha20IetfPoly1305,
        }
        .validate()
        .unwrap_err()
        .to_string();

        assert!(error.contains("h3_listen must be configured explicitly"));
    }
}
