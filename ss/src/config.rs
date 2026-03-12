use std::{
    collections::HashSet,
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
    pub listen: SocketAddr,
    pub ws_path: String,
    pub udp_ws_path: String,
    pub public_host: Option<String>,
    pub public_scheme: String,
    pub access_key_url_base: Option<String>,
    pub print_access_keys: bool,
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
            listen: args
                .listen
                .or(file.listen)
                .unwrap_or_else(default_listen_addr),
            ws_path: args
                .ws_path
                .or(file.ws_path)
                .unwrap_or_else(|| "/tcp".to_owned()),
            udp_ws_path: args
                .udp_ws_path
                .or(file.udp_ws_path)
                .unwrap_or_else(|| "/udp".to_owned()),
            public_host: args.public_host.or(file.public_host),
            public_scheme: args
                .public_scheme
                .or(file.public_scheme)
                .unwrap_or_else(|| "wss".to_owned()),
            access_key_url_base: args.access_key_url_base.or(file.access_key_url_base),
            print_access_keys: args
                .print_access_keys
                .or(file.print_access_keys)
                .unwrap_or(false),
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
        self.user_entries()?;
        Ok(())
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

    #[arg(long = "ws-path", env = "OUTLINE_SS_WS_PATH")]
    ws_path: Option<String>,

    #[arg(long, env = "OUTLINE_SS_UDP_WS_PATH")]
    udp_ws_path: Option<String>,

    #[arg(long, env = "OUTLINE_SS_PUBLIC_HOST")]
    public_host: Option<String>,

    #[arg(long, env = "OUTLINE_SS_PUBLIC_SCHEME")]
    public_scheme: Option<String>,

    #[arg(long, env = "OUTLINE_SS_ACCESS_KEY_URL_BASE")]
    access_key_url_base: Option<String>,

    #[arg(
        long,
        env = "OUTLINE_SS_PRINT_ACCESS_KEYS",
        action = ArgAction::Set,
        num_args = 0..=1,
        default_missing_value = "true",
        require_equals = true
    )]
    print_access_keys: Option<bool>,

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
struct FileConfig {
    listen: Option<SocketAddr>,
    ws_path: Option<String>,
    udp_ws_path: Option<String>,
    public_host: Option<String>,
    public_scheme: Option<String>,
    access_key_url_base: Option<String>,
    print_access_keys: Option<bool>,
    password: Option<String>,
    fwmark: Option<u32>,
    users: Option<Vec<UserEntry>>,
    method: Option<CipherKind>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum, Deserialize)]
pub enum CipherKind {
    #[value(name = "aes-256-gcm")]
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    #[value(name = "chacha20-ietf-poly1305")]
    #[serde(rename = "chacha20-ietf-poly1305")]
    Chacha20IetfPoly1305,
}

impl CipherKind {
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes256Gcm | Self::Chacha20IetfPoly1305 => 32,
        }
    }

    pub const fn salt_len(self) -> usize {
        self.key_len()
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aes-256-gcm",
            Self::Chacha20IetfPoly1305 => "chacha20-ietf-poly1305",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserEntry {
    pub id: String,
    pub password: String,
    #[serde(default)]
    pub fwmark: Option<u32>,
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

fn default_listen_addr() -> SocketAddr {
    "0.0.0.0:3000"
        .parse()
        .expect("hardcoded listen address should parse")
}
