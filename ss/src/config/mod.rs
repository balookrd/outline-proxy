mod cli;
mod file;
mod tuning;
mod user_entry;
mod validation;

use std::{collections::HashSet, net::SocketAddr, path::PathBuf};

use anyhow::Result;
use clap::Parser;

use cli::ConfigArgs;
use file::{FileConfig, default_config_path_if_exists, load_file_config};

pub use tuning::{TuningOverrides, TuningProfile, TuningProfileKind};
pub use user_entry::{CipherKind, ConfigError, UserEntry};

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
            outbound_ipv6_prefix: match args
                .outbound_ipv6_prefix
                .as_deref()
                .or(file.outbound_ipv6_prefix.as_deref())
            {
                Some(s) => Some(
                    s.parse::<crate::outbound::Ipv6Prefix>()
                        .map_err(|e| anyhow::anyhow!("invalid outbound_ipv6_prefix: {e}"))?,
                ),
                None => None,
            },
            outbound_ipv6_interface: args
                .outbound_ipv6_interface
                .clone()
                .or_else(|| file.outbound_ipv6_interface.clone()),
            outbound_ipv6_refresh_secs: args
                .outbound_ipv6_refresh_secs
                .or(file.outbound_ipv6_refresh_secs)
                .unwrap_or(30),
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
