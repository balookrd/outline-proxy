use std::{net::SocketAddr, path::PathBuf};

use clap::{ArgAction, Parser};

use super::{CipherKind, TuningPreset, UserEntry};

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

    /// Random-source IPv6 prefix, e.g. `2001:db8:dead::/64`. When set, each
    /// outbound upstream IPv6 TCP/UDP socket binds to a random address from
    /// this prefix. Requires the prefix to be routable back to this host
    /// (typically via AnyIP `ip -6 route add local <prefix> dev lo` on Linux;
    /// `IPV6_FREEBIND` is always set on the socket as a fallback).
    #[arg(long, env = "OUTLINE_SS_OUTBOUND_IPV6_PREFIX")]
    pub outbound_ipv6_prefix: Option<String>,

    /// Network interface whose currently-assigned IPv6 addresses form the
    /// random source pool. Mutually exclusive with `--outbound-ipv6-prefix`.
    /// Useful for DHCPv6/SLAAC where the prefix is not known up-front.
    #[arg(long, env = "OUTLINE_SS_OUTBOUND_IPV6_INTERFACE")]
    pub outbound_ipv6_interface: Option<String>,

    /// Interval in seconds between re-enumerations of the outbound
    /// interface's IPv6 addresses. Ignored when `outbound_ipv6_interface`
    /// is not set. Default: 30.
    #[arg(long, env = "OUTLINE_SS_OUTBOUND_IPV6_REFRESH_SECS")]
    pub outbound_ipv6_refresh_secs: Option<u64>,

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
    pub tuning_profile: Option<TuningPreset>,

    #[arg(long, env = "OUTLINE_SS_CONTROL_LISTEN")]
    pub control_listen: Option<SocketAddr>,

    #[arg(long, env = "OUTLINE_SS_CONTROL_TOKEN")]
    pub control_token: Option<String>,

    #[arg(long, env = "OUTLINE_SS_CONTROL_TOKEN_FILE")]
    pub control_token_file: Option<PathBuf>,
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
        password: Some(password.to_owned()),
        fwmark: None,
        method: None,
        ws_path_tcp: None,
        ws_path_udp: None,
        vless_id: None,
        vless_ws_path: None,
        enabled: None,
    })
}
