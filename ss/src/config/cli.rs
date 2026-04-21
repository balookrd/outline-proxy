use std::{
    net::SocketAddr,
    path::PathBuf,
};

use clap::{ArgAction, Parser};

use super::{CipherKind, TuningProfileKind, UserEntry};

#[derive(Debug, Clone, Parser)]
#[command(
    name = "outline-ss-rust",
    version,
    about = "Shadowsocks relay with WebSocket transport, UDP support and multi-user keys"
)]
pub(super) struct ConfigArgs {
    #[arg(long, env = "OUTLINE_SS_CONFIG")]
    pub config: Option<PathBuf>,

    #[arg(long, env = "OUTLINE_SS_LISTEN")]
    pub listen: Option<SocketAddr>,

    #[arg(long, env = "OUTLINE_SS_SS_LISTEN")]
    pub ss_listen: Option<SocketAddr>,

    #[arg(long, env = "OUTLINE_SS_TLS_CERT_PATH")]
    pub tls_cert_path: Option<PathBuf>,

    #[arg(long, env = "OUTLINE_SS_TLS_KEY_PATH")]
    pub tls_key_path: Option<PathBuf>,

    #[arg(long, env = "OUTLINE_SS_H3_LISTEN")]
    pub h3_listen: Option<SocketAddr>,

    #[arg(long, env = "OUTLINE_SS_H3_CERT_PATH")]
    pub h3_cert_path: Option<PathBuf>,

    #[arg(long, env = "OUTLINE_SS_H3_KEY_PATH")]
    pub h3_key_path: Option<PathBuf>,

    #[arg(long, env = "OUTLINE_SS_METRICS_LISTEN")]
    pub metrics_listen: Option<SocketAddr>,

    #[arg(long, env = "OUTLINE_SS_METRICS_PATH")]
    pub metrics_path: Option<String>,

    #[arg(
        long,
        env = "OUTLINE_SS_PREFER_IPV4_UPSTREAM",
        action = ArgAction::Set,
        num_args = 0..=1,
        default_missing_value = "true",
        require_equals = true
    )]
    pub prefer_ipv4_upstream: Option<bool>,

    #[arg(long, env = "OUTLINE_SS_CLIENT_ACTIVE_TTL_SECS")]
    pub client_active_ttl_secs: Option<u64>,

    #[arg(long, env = "OUTLINE_SS_UDP_NAT_IDLE_TIMEOUT_SECS")]
    pub udp_nat_idle_timeout_secs: Option<u64>,

    #[arg(long = "ws-path-tcp", visible_alias = "ws-path", env = "OUTLINE_SS_WS_PATH_TCP")]
    pub ws_path_tcp: Option<String>,

    #[arg(
        long = "ws-path-udp",
        visible_alias = "udp-ws-path",
        env = "OUTLINE_SS_WS_PATH_UDP"
    )]
    pub ws_path_udp: Option<String>,

    #[arg(
        long,
        env = "OUTLINE_SS_HTTP_ROOT_AUTH",
        action = ArgAction::Set,
        num_args = 0..=1,
        default_missing_value = "true",
        require_equals = true
    )]
    pub http_root_auth: Option<bool>,

    #[arg(long, env = "OUTLINE_SS_HTTP_ROOT_REALM")]
    pub http_root_realm: Option<String>,

    #[arg(long, env = "OUTLINE_SS_PUBLIC_HOST")]
    pub public_host: Option<String>,

    #[arg(long, env = "OUTLINE_SS_PUBLIC_SCHEME")]
    pub public_scheme: Option<String>,

    #[arg(long, env = "OUTLINE_SS_ACCESS_KEY_URL_BASE")]
    pub access_key_url_base: Option<String>,

    #[arg(long, env = "OUTLINE_SS_ACCESS_KEY_FILE_EXTENSION")]
    pub access_key_file_extension: Option<String>,

    #[arg(
        long,
        env = "OUTLINE_SS_PRINT_ACCESS_KEYS",
        action = ArgAction::Set,
        num_args = 0..=1,
        default_missing_value = "true",
        require_equals = true
    )]
    pub print_access_keys: Option<bool>,

    #[arg(long, env = "OUTLINE_SS_WRITE_ACCESS_KEYS_DIR")]
    pub write_access_keys_dir: Option<PathBuf>,

    #[arg(long, env = "OUTLINE_SS_PASSWORD")]
    pub password: Option<String>,

    #[arg(long, env = "OUTLINE_SS_FWMARK")]
    pub fwmark: Option<u32>,

    #[arg(
        long = "user",
        env = "OUTLINE_SS_USERS",
        value_delimiter = ',',
        value_parser = parse_user_entry
    )]
    pub users: Vec<UserEntry>,

    #[arg(long, env = "OUTLINE_SS_METHOD", value_enum)]
    pub method: Option<CipherKind>,

    #[arg(long, env = "OUTLINE_SS_TUNING_PROFILE", value_enum)]
    pub tuning_profile: Option<TuningProfileKind>,

    #[arg(long, env = "OUTLINE_SS_UDP_MAX_CONCURRENT_RELAY_TASKS")]
    pub udp_max_concurrent_relay_tasks: Option<usize>,
}

pub(super) fn parse_user_entry(value: &str) -> Result<UserEntry, String> {
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
