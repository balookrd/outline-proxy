use std::{collections::HashSet, path::PathBuf};

use anyhow::Result;
use clap::Parser;

use super::{
    cli::ConfigArgs,
    dashboard::{resolve_control_config, resolve_dashboard_config},
    fallback::HttpFallbackConfig,
    file::{FileConfig, TlsCertSection, default_config_path_if_exists, load_file_config},
    resolved::{AccessKeyConfig, Config, H3Alpn, SessionResumptionConfig},
    sni::{SniFallbackConfig, TlsCertEntry},
    user_entry::CipherKind,
};

pub enum AppMode {
    Serve(Config),
    GenerateKeys {
        config: Config,
        access_key: AccessKeyConfig,
        print: bool,
        write_dir: Option<PathBuf>,
    },
    MigrateConfig {
        path: PathBuf,
    },
}

impl AppMode {
    pub fn load() -> Result<Self> {
        let args = ConfigArgs::parse();
        if let Some(path) = args.migrate_config.clone() {
            return Ok(AppMode::MigrateConfig { path });
        }
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

        let config_dir = config_path
            .as_deref()
            .and_then(std::path::Path::parent)
            .unwrap_or_else(|| std::path::Path::new("."));
        let control = resolve_control_config(&args, &file)?;
        let dashboard = resolve_dashboard_config(&file, config_dir)?;

        let server = file.server.unwrap_or_default();
        let server_ss = server.ss.unwrap_or_default();
        let server_h3 = server.h3.unwrap_or_default();
        let metrics = file.metrics.unwrap_or_default();
        let outbound = file.outbound.unwrap_or_default();
        let websocket = file.websocket.unwrap_or_default();
        let http_root = file.http_root.unwrap_or_default();
        let access_keys_file = file.access_keys.unwrap_or_default();
        let shadowsocks = file.shadowsocks.unwrap_or_default();

        let access_key = AccessKeyConfig {
            public_host: args.public_host.or(access_keys_file.public_host),
            public_scheme: args
                .public_scheme
                .or(access_keys_file.public_scheme)
                .unwrap_or_else(|| "wss".to_owned()),
            access_key_url_base: args.access_key_url_base.or(access_keys_file.url_base),
            access_key_file_extension: normalize_access_key_file_extension(
                args.access_key_file_extension.or(access_keys_file.file_extension),
            ),
        };
        access_key.validate()?;

        // Multi-cert arrays. The h3 array only inherits from the TCP
        // listener's array when the h3 table omits `certs` entirely —
        // an explicitly empty `certs = []` opts out of inheritance.
        let tls_certs = parse_tls_cert_array(server.certs, "server.certs")?.unwrap_or_default();
        let h3_certs = match parse_tls_cert_array(server_h3.certs, "server.h3.certs")? {
            Some(list) => list,
            None => tls_certs.clone(),
        };

        // Default cert pair. CLI flag wins over file; on the h3 side, an
        // unset h3 cert/key inherits the TCP listener's pair (via either
        // `[server].cert_path`/`tls_cert_path` or `--tls-cert-path`).
        let tls_cert_path = args.tls_cert_path.clone().or(server.cert_path);
        let tls_key_path = args.tls_key_path.clone().or(server.key_path);
        let h3_cert_path = args
            .h3_cert_path
            .or(server_h3.cert_path)
            .or_else(|| tls_cert_path.clone());
        let h3_key_path = args
            .h3_key_path
            .or(server_h3.key_path)
            .or_else(|| tls_key_path.clone());

        let config = Config {
            config_path: config_path.clone(),
            control,
            dashboard,
            listen: args.listen.or(server.listen),
            ss_listen: args.ss_listen.or(server_ss.listen),
            tls_cert_path,
            tls_key_path,
            tls_certs,
            h3_listen: args.h3_listen.or(server_h3.listen),
            h3_cert_path,
            h3_key_path,
            h3_certs,
            h3_alpn: resolve_h3_alpn(server_h3.alpn.as_deref())?,
            metrics_listen: args.metrics_listen.or(metrics.listen),
            metrics_path: args
                .metrics_path
                .or(metrics.path)
                .unwrap_or_else(|| "/metrics".to_owned()),
            prefer_ipv4_upstream: args
                .prefer_ipv4_upstream
                .or(outbound.prefer_ipv4)
                .unwrap_or(false),
            outbound_ipv6_prefix: match args
                .outbound_ipv6_prefix
                .as_deref()
                .or(outbound.ipv6_prefix.as_deref())
            {
                Some(s) => Some(
                    s.parse::<crate::outbound::Ipv6Prefix>()
                        .map_err(|e| anyhow::anyhow!("invalid outbound.ipv6_prefix: {e}"))?,
                ),
                None => None,
            },
            outbound_ipv6_interface: args
                .outbound_ipv6_interface
                .clone()
                .or(outbound.ipv6_interface),
            outbound_ipv6_refresh_secs: args
                .outbound_ipv6_refresh_secs
                .or(outbound.ipv6_refresh_secs)
                .unwrap_or(30),
            ws_path_tcp: args
                .ws_path_tcp
                .or(websocket.ws_path_tcp)
                .unwrap_or_else(|| "/tcp".to_owned()),
            ws_path_udp: args
                .ws_path_udp
                .or(websocket.ws_path_udp)
                .unwrap_or_else(|| "/udp".to_owned()),
            ws_path_vless: websocket.ws_path_vless,
            xhttp_path_vless: websocket.xhttp_path_vless,
            http_root_auth: args.http_root_auth.or(http_root.auth).unwrap_or(false),
            http_root_realm: args
                .http_root_realm
                .or(http_root.realm)
                .unwrap_or_else(default_http_root_realm),
            users: if args.users.is_empty() {
                file.users.unwrap_or_default()
            } else {
                args.users
            },
            method: args
                .method
                .or(shadowsocks.method)
                .unwrap_or(CipherKind::Chacha20IetfPoly1305),
            access_key: access_key.clone(),
            tuning,
            session_resumption: SessionResumptionConfig::from_section(
                file.session_resumption.unwrap_or_default(),
            ),
            http_fallback: HttpFallbackConfig::from_section(
                file.http_fallback.unwrap_or_default(),
            )?,
            sni_fallback: SniFallbackConfig::from_section(file.sni_fallback.unwrap_or_default())?,
        };
        config.validate()?;

        let print = args.print_access_keys.or(access_keys_file.print).unwrap_or(false);
        let write_dir = args.write_access_keys_dir.or(access_keys_file.write_dir);

        if print || write_dir.is_some() {
            Ok(AppMode::GenerateKeys { config, access_key, print, write_dir })
        } else {
            Ok(AppMode::Serve(config))
        }
    }
}

fn parse_tls_cert_array(
    raw: Option<Vec<TlsCertSection>>,
    label: &str,
) -> Result<Option<Vec<TlsCertEntry>>> {
    let Some(list) = raw else { return Ok(None) };
    let mut out = Vec::with_capacity(list.len());
    for (idx, entry) in list.into_iter().enumerate() {
        out.push(TlsCertEntry::from_section(entry, &format!("{label}[{idx}]"))?);
    }
    Ok(Some(out))
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

fn resolve_h3_alpn(input: Option<&[String]>) -> Result<Vec<H3Alpn>> {
    let Some(raw) = input else {
        return Ok(vec![H3Alpn::H3]);
    };
    if raw.is_empty() {
        anyhow::bail!("server.h3.alpn must list at least one protocol");
    }
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(raw.len());
    for entry in raw {
        let alpn = H3Alpn::parse(entry).ok_or_else(|| {
            anyhow::anyhow!("unknown server.h3.alpn entry {entry:?}; allowed: h3, vless, ss")
        })?;
        if !seen.insert(alpn) {
            anyhow::bail!("server.h3.alpn contains duplicate entry {entry:?}");
        }
        out.push(alpn);
    }
    Ok(out)
}
